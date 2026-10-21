//! The PSP's delivery of one purchase: the signatures (or the rejection) as one
//! record on the SPI's AIR server, at an address the wallet can compute and
//! nobody else can. Pure: no network; the transport helpers at the end need
//! the `air-client` feature.
//!
//! ```text
//! PSP                              AIR server                       wallet
//!  | 1. purchase = sha256(label || payload)                           | (knows it too:
//!  |    cell = sha256(label || PSP DID || reply DID || purchase)      |  it made the payload)
//!  | 2. Create(cell, seal_to(reply DID, signed record)) --->          |
//!  |                                  <--- held read on the cell ---- |
//!  |                                  --- push: the record ---------> | 3. open with the
//!  |                                                                  |    one-off key, check
//!  |                                                                  |    the PSP's signature
//! ```
//!
//! **What identifies the purchase.** `purchase` is
//! `sha256("sp-psp-purchase-v0" || payload)`, where `payload` is the payload
//! *unsealed*: the bytes the wallet builds (reply DID, outputs with their blind
//! nonces) before it seals them to the PSP for the OP_RETURN. Both sides have
//! it: the wallet made it, and the PSP opens it to settle. It is not the sealed
//! bytes (the PSP's `seal::open_payloads` hands the settlement only the opened
//! payload, and a seal is randomised, so the wallet would have to keep the sealed
//! bytes for no gain), and it is not the txid (the wallet does not know it: the
//! payment is made from any wallet). The address also contains the reply DID,
//! which only the wallet and the PSP know (it is inside the sealed payload), so
//! a third party cannot compute the address and fill the write-once cell first.
//! The reply DID is a one-off key per purchase, so two addresses of one wallet
//! share nothing.
//!
//! **The record** is the reply envelope of the other AIR calls ([`envelope`]),
//! signed by the PSP's DID key and sealed to the reply DID. It answers a question
//! that was never sent: a pseudo request of kind [`KIND_PSP_DELIVERY`] whose
//! `request_id` is the purchase and whose `R` is the reply DID. The kind is a
//! hash domain only and is never served; the signature covers the question's
//! hash, so a record cannot be moved to another purchase or another reply DID.
//! Status [`STATUS_ANSWERED`] carries [`Signed`] (the signatures and the
//! keysets to unblind them with, and a credit owed, if any); [`STATUS_REFUSED`]
//! carries [`Refused`] (the purchase was rejected, and why) or [`Held`] (the
//! payment is valid but short, so nothing was signed, with what was paid). Both
//! of those, and a credit, are **open** until `open_until`, the end of the
//! reconciliation window (Unix seconds, the PSP's clock): the purchase is not
//! closed, and after the window the PSP keeps the payment. A wallet checks a
//! record with [`open_record`].
//!
//! **No freshness check.** The record is write-once and the wallet may read it
//! days after the PSP wrote it, so [`open_record`] takes any `issued_at`; the
//! signature and the question's hash are what bind it.

use serde::{Deserialize, Serialize};

use super::AirError;
use super::addr::{self, sha256};
use super::envelope::{
    KIND_PSP_DELIVERY, STATUS_ANSWERED, STATUS_REFUSED, VerifyError, WireReply, WireRequest,
    build_reply, verify_answer,
};
use crate::ServiceDid;
use crate::psp::KeysetsResponse;
use crate::seal::{PublicKey, SecretKey};

/// Label of the delivery address (REQUEST-DESIGN.md section 18).
pub const DELIVERY_LABEL: &[u8] = b"sp-air-delivery-v0";
/// Label of the purchase id.
pub const PURCHASE_LABEL: &[u8] = b"sp-psp-purchase-v0";

/// What identifies a purchase: `sha256("sp-psp-purchase-v0" || payload)` over
/// the unsealed payload bytes.
pub fn purchase_id(payload: &[u8]) -> [u8; 32] {
    sha256(&[PURCHASE_LABEL, payload])
}

/// `sha256("sp-air-delivery-v0" || PSP DID || reply DID || purchase)`.
pub fn delivery_secret_bytes(
    psp: &ServiceDid,
    reply: &ServiceDid,
    purchase: &[u8; 32],
) -> [u8; 32] {
    sha256(&[
        DELIVERY_LABEL,
        &psp.as_bytes()[..],
        &reply.as_bytes()[..],
        &purchase[..],
    ])
}

/// The secret of the delivery cell. Only the PSP, which knows the reply DID from
/// the payload, and the wallet, which made it, can compute it.
pub fn delivery_secret(psp: &ServiceDid, reply: &ServiceDid, purchase: &[u8; 32]) -> SecretKey {
    addr::secret_from(delivery_secret_bytes(psp, reply, purchase))
}

/// The pseudo request a record answers: kind 13, the purchase as the request id
/// and the reply DID as `R`.
pub fn question(purchase: &[u8; 32], reply: &ServiceDid) -> WireRequest {
    WireRequest::new(KIND_PSP_DELIVERY, *purchase, *reply.as_bytes())
}

/// One signed output: the blind nonce the wallet asked for and the PSP's blind
/// signature of it (the pairs `describe` logs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOutput {
    pub blind_nonce: String,
    pub signature: String,
}

/// The body of an answered record: the purchase was settled and these outputs
/// were signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    /// The keyset that signed.
    pub keyset: String,
    /// One pair per signed output. A short payment drops the smallest outputs,
    /// which then have no pair (`skipped_units`).
    pub signatures: Vec<SignedOutput>,
    /// The PSP's live keysets as they were when it signed, so the wallet
    /// unblinds from this record alone, with no keys call.
    pub keysets: KeysetsResponse,
    /// Requested units that were not signed because the payment was short. The
    /// PSP keeps their value.
    #[serde(default)]
    pub skipped_units: u64,
    /// An overpayment beyond the reconciliation target, in USD cents, that the
    /// PSP owes the payer. While it is above 0 the purchase is not closed: a
    /// follow-up will settle it (not built yet).
    #[serde(default)]
    pub credit_cents: u64,
    /// When the credit stops being owed (Unix seconds, the PSP's clock): the end
    /// of the reconciliation window. After it the PSP keeps the overpayment.
    /// 0 when nothing is owed.
    #[serde(default)]
    pub open_until: u64,
}

/// The body of a record for a purchase that was rejected: nothing was signed. The
/// purchase is not closed: it stays open until `open_until`, so the payer can
/// correct it (that exchange is not built yet), and the PSP keeps the payment if
/// it is not corrected by then.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refused {
    pub reason: String,
    /// What the payment was worth, in sats.
    #[serde(default)]
    pub paid_sats: u64,
    /// The same at the price the PSP locked, in USD cents (rounded down).
    #[serde(default)]
    pub paid_cents: u64,
    /// The end of the reconciliation window (Unix seconds, the PSP's clock).
    #[serde(default)]
    pub open_until: u64,
}

/// The body of a record for a payment that is held: valid, but short by more than
/// the reconciliation target allows, so nothing was signed. Like a rejection it
/// stays open until `open_until`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Held {
    pub reason: String,
    /// What the payment was worth, in sats.
    pub paid_sats: u64,
    /// The same at the locked price, in USD cents (rounded down).
    pub paid_cents: u64,
    /// The PSP units the payload asked for.
    pub requested_units: u64,
    /// Paid against requested, in basis points (negative is short).
    pub over_under_bps: i64,
    /// The end of the reconciliation window (Unix seconds, the PSP's clock).
    pub open_until: u64,
}

/// What a record says.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Signed(Signed),
    Refused(Refused),
    Held(Held),
}

impl Outcome {
    /// The end of the reconciliation window this record opens, when it opens
    /// one: a held or rejected purchase, or a signed one that is owed a credit.
    /// `None` when the purchase is closed.
    pub fn open_until(&self) -> Option<u64> {
        let until = match self {
            Outcome::Signed(s) if s.credit_cents > 0 => s.open_until,
            Outcome::Signed(_) => 0,
            Outcome::Refused(r) => r.open_until,
            Outcome::Held(h) => h.open_until,
        };
        (until > 0).then_some(until)
    }
}

/// The body of a record that signed nothing, as written: a status of
/// `STATUS_REFUSED` and one of these.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Unsigned {
    Rejected(Refused),
    Held(Held),
}

/// A record ready to be written: the cell and the sealed bytes. The PSP keeps
/// the bytes, so that a retry writes the same record (a seal is randomised, so
/// building it again would give different bytes and a write that finds the cell
/// taken could not tell its own record from another).
#[derive(Clone, Debug)]
pub struct Built {
    pub cell: SecretKey,
    pub sealed: Vec<u8>,
}

/// Build, sign and seal the record of one purchase. `psp_key` is the PSP's DID
/// key; the record is sealed to `reply`.
pub fn build_record(
    psp_key: &SecretKey,
    reply: &ServiceDid,
    purchase: &[u8; 32],
    outcome: &Outcome,
    issued_at: u64,
) -> Result<Built, AirError> {
    let psp = addr::key_to_did(&psp_key.public_key());
    let (status, body) = match outcome {
        Outcome::Signed(signed) => (STATUS_ANSWERED, serde_json::to_vec(signed)),
        Outcome::Refused(refused) => (
            STATUS_REFUSED,
            serde_json::to_vec(&Unsigned::Rejected(refused.clone())),
        ),
        Outcome::Held(held) => (
            STATUS_REFUSED,
            serde_json::to_vec(&Unsigned::Held(held.clone())),
        ),
    };
    let body = body.map_err(|e| AirError(e.to_string()))?;
    let plain = build_reply(
        psp_key,
        &question(purchase, reply),
        status,
        issued_at,
        &body,
    );
    let sealed = addr::seal_to(&addr::did_to_key(reply)?, &plain)?;
    Ok(Built {
        cell: delivery_secret(&psp, reply, purchase),
        sealed,
    })
}

/// A record the wallet opened and checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    pub outcome: Outcome,
    /// When the PSP signed it (Unix seconds, the PSP's clock).
    pub issued_at: u64,
    /// The reply plaintext, signed by the PSP: the wallet's receipt. Anyone can
    /// check it from the PSP's DID alone (`verify_receipt` with the question's
    /// hash is not needed: the signature covers it).
    pub receipt: Vec<u8>,
}

/// Open a record with the purchase's one-off key and check it: that it opens,
/// that it names `psp`, that the PSP's signature verifies, that it answers this
/// purchase and this reply DID, and that the body is what its status says.
pub fn open_record(
    reply_key: &SecretKey,
    psp: &ServiceDid,
    purchase: &[u8; 32],
    sealed: &[u8],
) -> Result<Opened, VerifyError> {
    let plain = addr::open(reply_key, sealed)
        .map_err(|e| VerifyError::Malformed(format!("the record does not open: {e}")))?;
    let reply_did = addr::key_to_did(&reply_key.public_key());
    let reply: WireReply =
        verify_answer(&plain, psp, &question(purchase, &reply_did), 0, u64::MAX)?;
    let outcome = match reply.status {
        STATUS_ANSWERED => Outcome::Signed(
            serde_json::from_slice(&reply.body).map_err(|e| VerifyError::BadBody(e.to_string()))?,
        ),
        STATUS_REFUSED => {
            match serde_json::from_slice(&reply.body)
                .map_err(|e| VerifyError::BadBody(e.to_string()))?
            {
                Unsigned::Rejected(refused) => Outcome::Refused(refused),
                Unsigned::Held(held) => Outcome::Held(held),
            }
        }
        other => return Err(VerifyError::Refused(other)),
    };
    Ok(Opened {
        outcome,
        issued_at: reply.issued_at,
        receipt: plain,
    })
}

/// The cell's public key, which is what a read names.
pub fn delivery_address(psp: &ServiceDid, reply: &ServiceDid, purchase: &[u8; 32]) -> PublicKey {
    delivery_secret(psp, reply, purchase).public_key()
}

// ---------------------------------------------------------------- transport

#[cfg(feature = "air-client")]
pub use transport::*;

#[cfg(feature = "air-client")]
mod transport {
    use std::time::Duration;

    use tokio::sync::mpsc::unbounded_channel;

    use super::*;
    use crate::air_request::client::{self, Client, Event, Put};

    /// What a write of a record found.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Written {
        /// This call wrote the cell.
        Created,
        /// The cell already held exactly these bytes: an earlier try that was
        /// not acknowledged got through. Delivered.
        AlreadyStored,
        /// The cell holds another record. Not delivered, and not to be
        /// overwritten: the PSP reports it.
        Different,
    }

    /// `Create` the record in its write-once cell. A cell that is already taken
    /// is answered as a read (the stored record comes back), so a retry is safe:
    /// it is [`Written::AlreadyStored`] when the bytes are the same.
    pub async fn write_record(
        client: &Client,
        cell: &SecretKey,
        sealed: &[u8],
        secs: u64,
    ) -> Result<Written, AirError> {
        match client::create(client, cell, sealed.to_vec(), secs).await? {
            Put::Created(_) => Ok(Written::Created),
            Put::Taken => match client::read_once(client, cell.public_key(), secs).await? {
                Some(stored) if stored == sealed => Ok(Written::AlreadyStored),
                Some(_) => Ok(Written::Different),
                None => Err(AirError(
                    "the cell was taken, and then it read empty".to_string(),
                )),
            },
        }
    }

    /// The sealed record at `address`: read once, then (when it is not there
    /// yet) hold a read for up to `wait_secs`. `None` when it did not arrive in
    /// time. Reading changes nothing, so a second call returns the same bytes.
    pub async fn read_record(
        client: &Client,
        address: &PublicKey,
        read_secs: u64,
        wait_secs: u64,
    ) -> Result<Option<Vec<u8>>, AirError> {
        let mut found =
            read_records(client, std::slice::from_ref(address), read_secs, wait_secs).await?;
        Ok(found.remove(0))
    }

    /// [`read_record`] for several addresses at once: each is read once, and
    /// those that are not there yet are held together for up to `wait_secs` in
    /// all (not each). The result is in the order of `addresses`, `None` for a
    /// record that did not arrive in time.
    pub async fn read_records(
        client: &Client,
        addresses: &[PublicKey],
        read_secs: u64,
        wait_secs: u64,
    ) -> Result<Vec<Option<Vec<u8>>>, AirError> {
        // `PublicKey` is cloned for each call: the client takes it by value.
        let mut found: Vec<Option<Vec<u8>>> = Vec::with_capacity(addresses.len());
        for address in addresses {
            found.push(client::read_once(client, address.clone(), read_secs).await?);
        }
        let missing: Vec<usize> = (0..addresses.len())
            .filter(|&i| found[i].is_none())
            .collect();
        if wait_secs == 0 || missing.is_empty() {
            return Ok(found);
        }
        let (tx, mut rx) = unbounded_channel();
        let mut held = Vec::with_capacity(missing.len());
        for &i in &missing {
            held.push(client::hold(client, addresses[i].clone(), i as u32, tx.clone()).await);
        }
        drop(tx);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(wait_secs);
        let mut open = missing.len();
        let mut ended = None;
        while open > 0 {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(Event::Filled(i, bytes))) => {
                    found[i as usize] = Some(bytes);
                    open -= 1;
                }
                Ok(Some(Event::Lost(_))) | Ok(None) => {
                    ended = Some(AirError(
                        "the AIR session ended while waiting for the record".to_string(),
                    ));
                    break;
                }
                Err(_) => break,
            }
        }
        for handle in held {
            handle.abort();
        }
        match ended {
            // Whatever arrived before the session ended is kept.
            Some(e) if found.iter().all(Option::is_none) => Err(e),
            _ => Ok(found),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const GENERATOR: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    /// 2G, a second valid key.
    const DOUBLE: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

    fn psp() -> ServiceDid {
        ServiceDid::parse(GENERATOR).unwrap()
    }

    fn reply() -> ServiceDid {
        ServiceDid::parse(DOUBLE).unwrap()
    }

    // ---- golden values (computed independently with python hashlib)

    #[test]
    fn golden_purchase_id_address_and_question() {
        assert_eq!(
            hex::encode(purchase_id(b"payload")),
            "e675e87ea0a400e183d5c789bb924119fb236f239ca345ea6d85e8a65fee0a24"
        );
        let purchase = [0x55u8; 32];
        assert_eq!(
            hex::encode(delivery_secret_bytes(&psp(), &reply(), &purchase)),
            "66d45b21203b82d47f6041d9b05025af8e9c6ab29ac65c01f408edd219140842"
        );
        // sha256("sp-air-req-v0" || 13 || purchase || reply DID || 0u32)
        assert_eq!(
            hex::encode(question(&purchase, &reply()).hash()),
            "764dbd6dcbfb9e3f1a432ec34f985a51ccf77de80121ce3febac272c2921f8a5"
        );
    }

    #[test]
    fn every_input_moves_the_address() {
        let purchase = [0x55u8; 32];
        let base = delivery_secret_bytes(&psp(), &reply(), &purchase);
        assert_ne!(base, delivery_secret_bytes(&reply(), &reply(), &purchase));
        assert_ne!(base, delivery_secret_bytes(&psp(), &psp(), &purchase));
        assert_ne!(base, delivery_secret_bytes(&psp(), &reply(), &[0x56; 32]));
    }

    // ---- records

    fn keysets() -> KeysetsResponse {
        let key = secp256k1::PublicKey::from_slice(&hex::decode(GENERATOR).unwrap()).unwrap();
        let mut one = BTreeMap::new();
        one.insert(1u64, key);
        let mut keysets = BTreeMap::new();
        keysets.insert("aabbccddeeff0011".to_string(), one);
        KeysetsResponse {
            current: "aabbccddeeff0011".to_string(),
            previous: None,
            keysets,
        }
    }

    fn signed() -> Outcome {
        Outcome::Signed(Signed {
            keyset: "aabbccddeeff0011".to_string(),
            signatures: vec![SignedOutput {
                blind_nonce: "02aa".to_string(),
                signature: "03bb".to_string(),
            }],
            keysets: keysets(),
            skipped_units: 2,
            credit_cents: 0,
            open_until: 0,
        })
    }

    struct Parties {
        psp_key: SecretKey,
        psp: ServiceDid,
        reply_key: SecretKey,
        reply: ServiceDid,
        purchase: [u8; 32],
    }

    fn parties() -> Parties {
        let psp_key = SecretKey::new();
        let reply_key = SecretKey::new();
        Parties {
            psp: addr::key_to_did(&psp_key.public_key()),
            reply: addr::key_to_did(&reply_key.public_key()),
            psp_key,
            reply_key,
            purchase: purchase_id(b"some payload"),
        }
    }

    #[test]
    fn a_signed_record_opens_with_the_reply_key_and_checks() {
        let p = parties();
        let built =
            build_record(&p.psp_key, &p.reply, &p.purchase, &signed(), 1_700_000_000).unwrap();
        let opened = open_record(&p.reply_key, &p.psp, &p.purchase, &built.sealed).unwrap();
        assert_eq!(opened.outcome, signed());
        assert_eq!(opened.issued_at, 1_700_000_000);
        // the receipt is the signed reply: anyone can check it from the DID
        let receipt =
            crate::air_request::envelope::verify_receipt(&p.psp, &opened.receipt).unwrap();
        assert_eq!(receipt.status, STATUS_ANSWERED);
        assert_eq!(
            built.cell.public_key().to_string(),
            delivery_address(&p.psp, &p.reply, &p.purchase).to_string()
        );
    }

    #[test]
    fn a_refused_record_carries_the_reason() {
        let p = parties();
        let outcome = Outcome::Refused(Refused {
            reason: "BlindNonceAlreadyUsed".to_string(),
            paid_sats: 5_000,
            paid_cents: 500,
            open_until: 1_700_604_800,
        });
        let built = build_record(&p.psp_key, &p.reply, &p.purchase, &outcome, 5).unwrap();
        let opened = open_record(&p.reply_key, &p.psp, &p.purchase, &built.sealed).unwrap();
        assert_eq!(opened.outcome, outcome);
        assert_eq!(opened.outcome.open_until(), Some(1_700_604_800));
    }

    #[test]
    fn a_held_record_says_what_was_paid_and_for_how_long_it_stays_open() {
        let p = parties();
        let outcome = Outcome::Held(Held {
            reason: "short beyond the reconciliation target".to_string(),
            paid_sats: 300,
            paid_cents: 30,
            requested_units: 5,
            over_under_bps: -4_000,
            open_until: 1_700_604_800,
        });
        let built = build_record(&p.psp_key, &p.reply, &p.purchase, &outcome, 5).unwrap();
        // a held payment is a refusal-status record that is not a rejection
        let plain = addr::open(&p.reply_key, &built.sealed).unwrap();
        assert_eq!(
            crate::air_request::envelope::verify_receipt(&p.psp, &plain)
                .unwrap()
                .status,
            STATUS_REFUSED
        );
        let opened = open_record(&p.reply_key, &p.psp, &p.purchase, &built.sealed).unwrap();
        assert_eq!(opened.outcome, outcome);
        assert_eq!(opened.outcome.open_until(), Some(1_700_604_800));
    }

    #[test]
    fn only_an_open_purchase_has_a_window() {
        assert_eq!(signed().open_until(), None);
        let mut credit = match signed() {
            Outcome::Signed(s) => s,
            _ => unreachable!(),
        };
        credit.credit_cents = 12;
        credit.open_until = 99;
        assert_eq!(Outcome::Signed(credit.clone()).open_until(), Some(99));
        // a window with nothing owed is closed
        credit.credit_cents = 0;
        assert_eq!(Outcome::Signed(credit).open_until(), None);
        // an old refusal that names no window is closed
        assert_eq!(
            Outcome::Refused(Refused {
                reason: "x".into(),
                ..Refused::default()
            })
            .open_until(),
            None
        );
    }

    #[test]
    fn a_record_is_read_any_time_later() {
        // no freshness check: issued_at in 1970 still opens
        let p = parties();
        let built = build_record(&p.psp_key, &p.reply, &p.purchase, &signed(), 1).unwrap();
        assert!(open_record(&p.reply_key, &p.psp, &p.purchase, &built.sealed).is_ok());
    }

    #[test]
    fn a_record_for_another_key_does_not_open() {
        let p = parties();
        let other = SecretKey::new();
        let built = build_record(&p.psp_key, &p.reply, &p.purchase, &signed(), 5).unwrap();
        assert!(matches!(
            open_record(&other, &p.psp, &p.purchase, &built.sealed),
            Err(VerifyError::Malformed(_))
        ));
    }

    #[test]
    fn a_record_signed_by_another_key_is_refused() {
        let p = parties();
        let forger = SecretKey::new();
        // the forger names the real PSP but signs with its own key
        let named = *p.psp.as_bytes();
        let plain = crate::air_request::envelope::build_reply_naming(
            &forger,
            &named,
            &question(&p.purchase, &p.reply),
            STATUS_ANSWERED,
            5,
            &serde_json::to_vec(&match signed() {
                Outcome::Signed(s) => s,
                _ => unreachable!(),
            })
            .unwrap(),
        );
        let sealed = addr::seal_to(&addr::did_to_key(&p.reply).unwrap(), &plain).unwrap();
        assert_eq!(
            open_record(&p.reply_key, &p.psp, &p.purchase, &sealed).unwrap_err(),
            VerifyError::BadSignature
        );
        // and a record that names the forger is a record of another PSP
        let own = build_record(&forger, &p.reply, &p.purchase, &signed(), 5).unwrap();
        assert_eq!(
            open_record(&p.reply_key, &p.psp, &p.purchase, &own.sealed).unwrap_err(),
            VerifyError::WrongMint
        );
    }

    #[test]
    fn a_record_cannot_be_moved_to_another_purchase() {
        let p = parties();
        let built = build_record(&p.psp_key, &p.reply, &p.purchase, &signed(), 5).unwrap();
        let other = purchase_id(b"another payload");
        assert_eq!(
            open_record(&p.reply_key, &p.psp, &other, &built.sealed).unwrap_err(),
            VerifyError::WrongRequestId
        );
    }

    #[test]
    fn a_body_that_does_not_match_its_status_is_refused() {
        let p = parties();
        // answered, but with a refusal's body
        let plain = build_reply(
            &p.psp_key,
            &question(&p.purchase, &p.reply),
            STATUS_ANSWERED,
            5,
            br#"{"kind":"rejected","reason":"x"}"#,
        );
        let sealed = addr::seal_to(&addr::did_to_key(&p.reply).unwrap(), &plain).unwrap();
        assert!(matches!(
            open_record(&p.reply_key, &p.psp, &p.purchase, &sealed),
            Err(VerifyError::BadBody(_))
        ));
        // a status that is neither
        let plain = build_reply(
            &p.psp_key,
            &question(&p.purchase, &p.reply),
            crate::air_request::envelope::STATUS_UNAVAILABLE,
            5,
            b"",
        );
        let sealed = addr::seal_to(&addr::did_to_key(&p.reply).unwrap(), &plain).unwrap();
        assert!(matches!(
            open_record(&p.reply_key, &p.psp, &p.purchase, &sealed),
            Err(VerifyError::Refused(_))
        ));
    }

    #[test]
    fn the_body_reads_a_record_with_no_skipped_credit_or_window_fields() {
        let json = br#"{"keyset":"k","signatures":[],"keysets":{"current":"k","previous":null,"keysets":{}}}"#;
        let signed: Signed = serde_json::from_slice(json).unwrap();
        assert_eq!(
            (signed.skipped_units, signed.credit_cents, signed.open_until),
            (0, 0, 0)
        );
    }
}

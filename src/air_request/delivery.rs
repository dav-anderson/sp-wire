//! What the PSP owes for one purchase: an **owed record** on the SPI's AIR
//! server, at an address the wallet can compute and nobody else can. Pure: no
//! network; the transport helpers at the end need the `air-client` feature.
//!
//! ```text
//! wallet                           PSP                              AIR server
//!  | 1. makes a throwaway claim key; pays with the claim DID sealed   |
//!  |    to the PSP's DID in the OP_RETURN (payload.rs)                |
//!  |                                  | 2. price locks at 1 confirmation;
//!  |                                  |    the locked value sets the units owed
//!  |                                  |    and the confirmation tier
//!  |                                  | 3. at the tier: cell n = sha256(label ||
//!  |                                  |    PSP DID || claim DID || n)
//!  |                                  |    Create(cell, seal_to(claim DID, owed record)) -->
//!  | <--- held read on cell 0, 1, 2 ... until one is empty -----------|
//!  | 4. opens the record with the claim key, checks the PSP's signature
//!  | 5. sends ONE claim (kind 15, psp::ClaimRequest) for exactly the units owed
//! ```
//!
//! **Where the record is.** A claim key may pay more than once (a wallet that
//! reuses one, or two payments that carry the same payload), so a claim DID has
//! up to many owed records. The `n`th (counted from 0, in the order the PSP
//! writes them) is at the cell [`owed_secret`] of `(PSP DID, claim DID, n)`. The
//! wallet reads cell 0, then 1, and so on, until a cell is empty, and each record
//! says which transaction it is for (`txid`). The address contains the claim DID,
//! which only the wallet and the PSP know (it is inside the sealed payload), so a
//! third party cannot compute the address and fill the write-once cell first.
//! [`record_id`] is the claim DID and the index under another label: it is what a claim
//! names, and it is not the address, so a claim never reveals the cell.
//!
//! **The record** is the reply envelope of the other AIR calls ([`envelope`]),
//! signed by the PSP's DID key and sealed to the claim DID. It answers a question
//! that was never sent: a pseudo request of kind [`KIND_PSP_DELIVERY`] whose
//! `request_id` is the record id and whose `R` is the claim DID. The kind is a
//! hash domain only and is never served; the signature covers the question's
//! hash, so a record cannot be moved to another record id or another claim DID.
//! Its status is [`STATUS_ANSWERED`] and its body is [`Owed`]. A wallet checks a
//! record with [`open_record`].
//!
//! **The terms are in the record.** [`ClaimTerms`] says what one claim must look
//! like (the exact total of the outputs, the prepaid costs that came off it, the
//! length of the claim window, the number of attempts) and what happens if it does not. They are
//! fixed when the record is made; a later change of the PSP's settings does not
//! change them. They are a fallback for a fallback: a wallet claims
//! automatically and checks its claim against them before it sends, so it should
//! never fail. They are written out for a developer or a user who buys PSP with
//! nonstandard, self-built tooling, as one last chance to get it right before the
//! funds are lost.
//!
//! **No freshness check.** The record is write-once and the wallet may read it
//! days after the PSP wrote it, so [`open_record`] takes any `issued_at`; the
//! signature and the question's hash are what bind it.

use serde::{Deserialize, Serialize};

use super::AirError;
use super::addr::{self, sha256};
use super::envelope::{
    KIND_PSP_DELIVERY, STATUS_ANSWERED, VerifyError, WireReply, WireRequest, build_reply,
    verify_answer,
};
use crate::ServiceDid;
pub use crate::psp::SignedOutput;
use crate::seal::{PublicKey, SecretKey};

/// Label of the owed-record address (REQUEST-DESIGN.md section 18).
pub const OWED_LABEL: &[u8] = b"sp-psp-owed-v0";
/// Label of the owed-record id.
pub const RECORD_ID_LABEL: &[u8] = b"sp-psp-owed-id-v0";

/// `sha256("sp-psp-owed-id-v0" || claim DID || u32 index)`: what a claim names
/// (`psp::ClaimRequest::record_id`) and what a record answers to. The PSP's DID
/// is not in it: the record is signed by the PSP, and the id only has to tell
/// the records of one claim DID apart.
pub fn record_id(claim: &ServiceDid, index: u32) -> [u8; 32] {
    sha256(&[
        RECORD_ID_LABEL,
        &claim.as_bytes()[..],
        &index.to_be_bytes()[..],
    ])
}

/// `sha256("sp-psp-owed-v0" || PSP DID || claim DID || u32 index)`, the secret
/// of the cell of the `index`th owed record (counted from 0).
pub fn owed_secret_bytes(psp: &ServiceDid, claim: &ServiceDid, index: u32) -> [u8; 32] {
    sha256(&[
        OWED_LABEL,
        &psp.as_bytes()[..],
        &claim.as_bytes()[..],
        &index.to_be_bytes()[..],
    ])
}

/// The secret of an owed record's cell. Only the PSP, which knows the claim DID
/// from the payload, and the wallet, which made it, can compute it.
pub fn owed_secret(psp: &ServiceDid, claim: &ServiceDid, index: u32) -> SecretKey {
    addr::secret_from(owed_secret_bytes(psp, claim, index))
}

/// The cell's public key, which is what a read names.
pub fn owed_address(psp: &ServiceDid, claim: &ServiceDid, index: u32) -> PublicKey {
    owed_secret(psp, claim, index).public_key()
}

/// The pseudo request a record answers: kind 13, the record id as the request
/// id and the claim DID as `R`.
pub fn question(record_id: &[u8; 32], claim: &ServiceDid) -> WireRequest {
    WireRequest::new(KIND_PSP_DELIVERY, *record_id, *claim.as_bytes())
}

/// What one claim must be, as the owed record states it. Fixed when the record
/// is made, and kept with the payment: the PSP checks a claim against these,
/// never against its current settings.
///
/// `due_units` is an exact whole number of PSP units with no dollar or bitcoin
/// price in it: the price was locked once, when the record was made, and no
/// tolerance applies to a claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimTerms {
    /// What to send: [`SEND_PURCHASE_CLAIM`].
    pub send: String,
    /// The AIR request kind to send it as (`KIND_PSP_CLAIM`, 15).
    pub kind: u8,
    /// The exact total of the outputs the claim must carry: the units the payment
    /// buys at the locked price, less the prepaid costs, floored at 0. The PSP
    /// signs the claim whole or not at all: no partial fill.
    pub due_units: u64,
    /// The read costs the PSP prepays (the owed record and the answer), taken
    /// from the units owed.
    pub read_prepaid_units: u64,
    /// The cost of the one kind 15 write, prepaid by the SPI on the wallet's
    /// behalf and taken from the units owed. The SPI absorbs the cost of a second
    /// attempt.
    pub write_prepaid_units: u64,
    /// How long the purchase stays claimable, in seconds:
    /// [`crate::psp::CLAIM_WINDOW_SECS`], counted from when this record was
    /// stored on AIR. The record cannot state the end of the window, because the
    /// record is sealed once and its write may be retried later: the PSP's
    /// deadline is the time of the write that lands plus this. A wallet claims as
    /// soon as it reads the record and keeps the claim key at least until its
    /// first read plus this.
    pub window_secs: u64,
    /// How many claims the PSP counts: a claim signed by the right claim key,
    /// for this record, refused for its content, with a new hash.
    pub max_attempts: u32,
    /// [`EXPIRY_NOTICE`].
    pub on_expiry: String,
}

/// [`ClaimTerms::send`]: one purchase claim.
pub const SEND_PURCHASE_CLAIM: &str = "purchase_claim";
/// [`ClaimTerms::on_expiry`]: what happens if the claim is not made in time.
pub const EXPIRY_NOTICE: &str = "If the purchase is not claimed within window_secs of this record being stored on AIR, the payment is kept by the PSP and the funds are lost. A refused claim gets no reply.";

/// The body of an owed record: this payment is owed this many units, claimable
/// once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Owed {
    /// The transaction this record is for (hex), so a wallet that paid more than
    /// once with one claim key can tell its records apart.
    pub txid: String,
    /// What the payment was worth, in sats.
    pub paid_sats: u64,
    /// The whole PSP units the payment buys at the locked price, before the
    /// prepaid costs come off (the sub-unit remainder is kept by the PSP).
    pub value_units: u64,
    /// What the claim must be.
    pub terms: ClaimTerms,
}

/// What a record says. One variant today: the first record of a purchase says
/// what is owed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Owed(Owed),
}

impl Outcome {
    /// The terms of the claim this record opens.
    pub fn terms(&self) -> &ClaimTerms {
        match self {
            Outcome::Owed(owed) => &owed.terms,
        }
    }
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

/// Build, sign and seal the `index`th owed record of `claim`. `psp_key` is the
/// PSP's DID key; the record is sealed to `claim`.
pub fn build_record(
    psp_key: &SecretKey,
    claim: &ServiceDid,
    index: u32,
    outcome: &Outcome,
    issued_at: u64,
) -> Result<Built, AirError> {
    let psp = addr::key_to_did(&psp_key.public_key());
    let body = match outcome {
        Outcome::Owed(owed) => serde_json::to_vec(owed),
    }
    .map_err(|e| AirError(e.to_string()))?;
    let id = record_id(claim, index);
    let plain = build_reply(
        psp_key,
        &question(&id, claim),
        STATUS_ANSWERED,
        issued_at,
        &body,
    );
    let sealed = addr::seal_to(&addr::did_to_key(claim)?, &plain)?;
    Ok(Built {
        cell: owed_secret(&psp, claim, index),
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
    /// check it from the PSP's DID alone.
    pub receipt: Vec<u8>,
}

/// Open the `index`th record with the claim key and check it: that it opens,
/// that it names `psp`, that the PSP's signature verifies, that it answers this
/// record id and this claim DID, and that the body is what its status says.
pub fn open_record(
    claim_key: &SecretKey,
    psp: &ServiceDid,
    index: u32,
    sealed: &[u8],
) -> Result<Opened, VerifyError> {
    let plain = addr::open(claim_key, sealed)
        .map_err(|e| VerifyError::Malformed(format!("the record does not open: {e}")))?;
    let claim = addr::key_to_did(&claim_key.public_key());
    let id = record_id(&claim, index);
    let reply: WireReply = verify_answer(&plain, psp, &question(&id, &claim), 0, u64::MAX)?;
    let outcome = match reply.status {
        STATUS_ANSWERED => Outcome::Owed(
            serde_json::from_slice(&reply.body).map_err(|e| VerifyError::BadBody(e.to_string()))?,
        ),
        other => return Err(VerifyError::Refused(other)),
    };
    Ok(Opened {
        outcome,
        issued_at: reply.issued_at,
        receipt: plain,
    })
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
        // `PublicKey` is `Copy`, so each call gets its own: the client takes it by value.
        let mut found: Vec<Option<Vec<u8>>> = Vec::with_capacity(addresses.len());
        for address in addresses {
            found.push(client::read_once(client, *address, read_secs).await?);
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
            held.push(client::hold(client, addresses[i], i as u32, tx.clone()).await);
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

    const GENERATOR: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    /// 2G, a second valid key.
    const DOUBLE: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

    fn psp() -> ServiceDid {
        ServiceDid::parse(GENERATOR).unwrap()
    }

    fn claim() -> ServiceDid {
        ServiceDid::parse(DOUBLE).unwrap()
    }

    #[test]
    fn golden_record_id_address_and_question() {
        // computed independently with python hashlib
        assert_eq!(
            hex::encode(record_id(&claim(), 0)),
            "886a4d590430dc375c4b9949c7015d529754d80e97c992cc2834ca35dd4e8e85"
        );
        assert_eq!(
            hex::encode(record_id(&claim(), 1)),
            "6f080e4cf389da605b732ef9b18083d1047cd85d0d2e804c81af809f7ba057e6"
        );
        assert_eq!(
            hex::encode(owed_secret_bytes(&psp(), &claim(), 0)),
            "8ad4cba21d92eed93668542e06dfd8886119d2b0a73625922149a1cb42efffa9"
        );
        assert_eq!(
            hex::encode(owed_secret_bytes(&psp(), &claim(), 1)),
            "7f40127b3fb2e98eb2677db3145b07e89ff11d6fcf959135ba672fd89f09dce5"
        );
        // sha256("sp-air-req-v0" || 13 || id || claim DID || 0u32)
        assert_eq!(
            hex::encode(question(&[0x55u8; 32], &claim()).hash()),
            "764dbd6dcbfb9e3f1a432ec34f985a51ccf77de80121ce3febac272c2921f8a5"
        );
    }

    #[test]
    fn every_input_moves_the_address() {
        let base = owed_secret_bytes(&psp(), &claim(), 0);
        assert_ne!(base, owed_secret_bytes(&claim(), &claim(), 0));
        assert_ne!(base, owed_secret_bytes(&psp(), &psp(), 0));
        assert_ne!(base, owed_secret_bytes(&psp(), &claim(), 1));
        // the id is not the address
        assert_ne!(base, record_id(&claim(), 0));
    }

    fn owed() -> Outcome {
        Outcome::Owed(Owed {
            txid: "ab".repeat(32),
            paid_sats: 30_000,
            value_units: 30,
            terms: ClaimTerms {
                send: SEND_PURCHASE_CLAIM.to_string(),
                kind: crate::air_request::envelope::KIND_PSP_CLAIM,
                due_units: 27,
                read_prepaid_units: 2,
                write_prepaid_units: 1,
                window_secs: crate::psp::CLAIM_WINDOW_SECS,
                max_attempts: 2,
                on_expiry: EXPIRY_NOTICE.to_string(),
            },
        })
    }

    struct Parties {
        psp_key: SecretKey,
        psp: ServiceDid,
        claim_key: SecretKey,
        claim: ServiceDid,
    }

    fn parties() -> Parties {
        let psp_key = SecretKey::new();
        let claim_key = SecretKey::new();
        Parties {
            psp: addr::key_to_did(&psp_key.public_key()),
            claim: addr::key_to_did(&claim_key.public_key()),
            psp_key,
            claim_key,
        }
    }

    #[test]
    fn an_owed_record_opens_with_the_claim_key_and_checks() {
        let p = parties();
        let built = build_record(&p.psp_key, &p.claim, 3, &owed(), 1_700_000_000).unwrap();
        let opened = open_record(&p.claim_key, &p.psp, 3, &built.sealed).unwrap();
        assert_eq!(opened.outcome, owed());
        assert_eq!(opened.outcome.terms().window_secs, 2_592_000);
        assert_eq!(opened.outcome.terms().due_units, 27);
        assert_eq!(opened.issued_at, 1_700_000_000);
        // the receipt is the signed reply: anyone can check it from the DID
        let receipt =
            crate::air_request::envelope::verify_receipt(&p.psp, &opened.receipt).unwrap();
        assert_eq!(receipt.status, STATUS_ANSWERED);
        assert_eq!(
            built.cell.public_key().to_string(),
            owed_address(&p.psp, &p.claim, 3).to_string()
        );
    }

    #[test]
    fn a_record_is_read_any_time_later_by_nobody_else_and_only_where_it_was_written() {
        let p = parties();
        let built = build_record(&p.psp_key, &p.claim, 0, &owed(), 1).unwrap();
        // no freshness check: issued_at in 1970 still opens
        assert!(open_record(&p.claim_key, &p.psp, 0, &built.sealed).is_ok());
        // another key cannot open it
        assert!(matches!(
            open_record(&SecretKey::new(), &p.psp, 0, &built.sealed),
            Err(VerifyError::Malformed(_))
        ));
        // and it cannot be moved to another index of the same claim DID
        assert_eq!(
            open_record(&p.claim_key, &p.psp, 1, &built.sealed).unwrap_err(),
            VerifyError::WrongRequestId
        );
    }

    #[test]
    fn a_record_signed_by_another_key_or_with_another_status_is_refused() {
        let p = parties();
        let forger = SecretKey::new();
        let id = record_id(&p.claim, 0);
        let body = match owed() {
            Outcome::Owed(o) => serde_json::to_vec(&o).unwrap(),
        };
        // the forger names the real PSP but signs with its own key
        let plain = crate::air_request::envelope::build_reply_naming(
            &forger,
            p.psp.as_bytes(),
            &question(&id, &p.claim),
            STATUS_ANSWERED,
            5,
            &body,
        );
        let sealed = addr::seal_to(&addr::did_to_key(&p.claim).unwrap(), &plain).unwrap();
        assert_eq!(
            open_record(&p.claim_key, &p.psp, 0, &sealed).unwrap_err(),
            VerifyError::BadSignature
        );
        // a record that names the forger is a record of another PSP
        let own = build_record(&forger, &p.claim, 0, &owed(), 5).unwrap();
        assert_eq!(
            open_record(&p.claim_key, &p.psp, 0, &own.sealed).unwrap_err(),
            VerifyError::WrongMint
        );
        // a status that is not "answered" carries no owed record
        let plain = build_reply(
            &p.psp_key,
            &question(&id, &p.claim),
            crate::air_request::envelope::STATUS_REFUSED,
            5,
            b"",
        );
        let sealed = addr::seal_to(&addr::did_to_key(&p.claim).unwrap(), &plain).unwrap();
        assert!(matches!(
            open_record(&p.claim_key, &p.psp, 0, &sealed),
            Err(VerifyError::Refused(_))
        ));
    }

    #[test]
    fn the_terms_are_pinned_and_round_trip() {
        // Written by hand from the field list, not from the code.
        let json = concat!(
            r#"{"send":"purchase_claim","kind":15,"due_units":27,"#,
            r#""read_prepaid_units":2,"write_prepaid_units":1,"window_secs":2592000,"#,
            r#""max_attempts":2,"on_expiry":"If the purchase is not claimed within window_secs "#,
            r#"of this record being stored on AIR, the payment is kept by the PSP and the funds "#,
            r#"are lost. A refused claim gets no reply."}"#
        );
        let terms = owed().terms().clone();
        assert_eq!(serde_json::to_string(&terms).unwrap(), json);
        assert_eq!(serde_json::from_str::<ClaimTerms>(json).unwrap(), terms);
    }
}

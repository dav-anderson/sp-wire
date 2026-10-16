#![allow(unused_imports)]

//! `POST /redeem`: the canonical binary request, and the reply.
//!
//! Changing the encoding changes [`FORMAT_VERSION`] and the crate's
//! `WIRE_VERSION`.

use std::fmt;

use mint_types::{Amount, BlindNonce, MintInput, MintOutput, Nonce, Note};
use secp256k1::schnorr::Signature;
use secp256k1::{PublicKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::queue::{EntryView, SignedOutput};
use super::terms::Terms;
use crate::dec;
use crate::keyset::is_keyset_id;

/// The first byte of every encoded request.
pub const FORMAT_VERSION: u8 = 2;

/// Bytes of one keyset ID on the wire.
pub const KEYSET_BYTES: u64 = 8;

/// Bytes of one encoded input: service 32, day 8, keyset 8, amount 8, nonce 33,
/// note signature 33, spend signature 64.
pub const INPUT_BYTES: u64 = 186;

/// Bytes of one encoded output: service 32, day 8, amount 8, blind nonce 33.
pub const OUTPUT_BYTES: u64 = 81;

/// Bytes of an encoded request that do not depend on its contents: version 1,
/// service 32, output keyset 8, three list counts of 4, memo length 2, service
/// signature 64.
pub const FIXED_BYTES: u64 = 119;

/// The smallest possible request: one note, a memo of one byte.
pub const MIN_REQUEST_BYTES: u64 = FIXED_BYTES + INPUT_BYTES + 1;

/// The default for the longest payout memo, in bytes (`redeem.max_memo_bytes`).
pub const DEFAULT_MAX_MEMO_BYTES: usize = 256;

const DIGEST_TAG: &[u8] = b"esp-mint/redeem/v2";

const REQUEST_TAG: &[u8] = b"esp-mint/redeem-request/v2";

/// An ESP note the service presents, with the terms it claims for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedeemInput {
    pub service: XOnlyPublicKey,
    pub redeemable_after_day: u64,
    /// The keyset that signed the note (16 hex characters). The note is
    /// checked, and looked up in the spent list, of this keyset.
    #[serde(default)]
    pub keyset: String,
    /// The note, its amount, and its spend signature over the request digest.
    pub input: MintInput,
}

/// A fresh blinded output, tagged with the terms it is to be signed under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedeemOutput {
    pub service: XOnlyPublicKey,
    pub redeemable_after_day: u64,
    pub output: MintOutput,
}

#[derive(Debug, Clone)]
pub struct RedeemRequest {
    /// The service redeeming (its DID key, x-only).
    pub service: XOnlyPublicKey,
    /// The keyset to sign the refund and decline outputs with (16 hex
    /// characters). A new request must name the current keyset (the previous
    /// one is refused `keyset_not_current`). A decline signed later is signed by
    /// the current keyset whatever this says; the signatures name the keyset
    /// that signed.
    pub output_keyset: String,
    pub inputs: Vec<RedeemInput>,
    /// Where the payout goes. The service signs it, so it cannot be redirected.
    /// At most `redeem.max_memo_bytes` bytes of UTF-8.
    pub memo: String,
    /// Notes to reissue if the payout is declined: at most the accepted notes,
    /// with the same service and day, minus the fee.
    pub decline_outputs: Vec<RedeemOutput>,
    /// Notes to reissue from the rejected notes, if the accepted notes do not
    /// cover the fee.
    pub refund_outputs: Vec<RedeemOutput>,
    /// The service's signature over the digest.
    pub service_signature: Signature,
}

impl RedeemRequest {
    /// What the service and every input sign.
    pub fn digest(&self) -> [u8; 32] {
        digest(
            &self.service,
            &self.output_keyset,
            &self.inputs,
            &self.memo,
            &self.decline_outputs,
            &self.refund_outputs,
        )
    }

    /// The length of the canonical encoding, in bytes: what the fee is sized by.
    pub fn encoded_len(&self) -> u64 {
        encoded_len(
            self.inputs.len(),
            self.memo.len(),
            self.decline_outputs.len(),
            self.refund_outputs.len(),
        )
    }

    /// The canonical encoding (see `encode`).
    pub fn encode(&self) -> Vec<u8> {
        encode(self)
    }
}

/// The length of the canonical encoding of a request with this many inputs, this
/// many memo bytes and this many decline and refund outputs. Every other field
/// has a fixed size, so this is exact: `119 + 186 * inputs + memo + 81 *
/// (decline + refund)`.
pub fn encoded_len(inputs: usize, memo_bytes: usize, decline: usize, refund: usize) -> u64 {
    FIXED_BYTES
        + INPUT_BYTES * inputs as u64
        + memo_bytes as u64
        + OUTPUT_BYTES * (decline as u64 + refund as u64)
}

fn terms_bytes(service: &XOnlyPublicKey, day: u64) -> [u8; 40] {
    Terms {
        service: *service,
        redeemable_after_day: day,
    }
    .to_bytes()
}

/// A keyset ID as its 8 bytes (zeros if it is not 16 hex characters, which
/// `validate` refuses).
fn keyset_bytes(id: &str) -> [u8; 8] {
    hex::decode(id)
        .ok()
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .unwrap_or([0; 8])
}

/// Write the canonical encoding, in order, to `out`, without the service
/// signature. Spend signatures are written (each right after its note's own
/// signature) only if `spend_signatures` is true.
///
/// ```text
/// version        1   (= 2)
/// service       32   x-only key
/// output keyset  8   the keyset for the refund and decline outputs
/// input count    4   big endian
/// each input   186   service 32, day 8, keyset 8, amount 8, nonce 33,
///                    note signature 33, [spend signature 64]
/// memo length    2   big endian
/// memo           n   UTF-8
/// decline count  4
/// each output   81   service 32, day 8, amount 8, blind nonce 33
/// refund count   4
/// each output   81
/// [service signature 64]
/// ```
///
/// Integers are big endian, keys are compressed (33 bytes) or x-only (32).
#[allow(clippy::too_many_arguments)]
fn write_body(
    service: &XOnlyPublicKey,
    output_keyset: &str,
    inputs: &[RedeemInput],
    memo: &str,
    decline_outputs: &[RedeemOutput],
    refund_outputs: &[RedeemOutput],
    spend_signatures: bool,
    out: &mut dyn FnMut(&[u8]),
) {
    out(&[FORMAT_VERSION]);
    out(&service.serialize());
    out(&keyset_bytes(output_keyset));
    out(&(inputs.len() as u32).to_be_bytes());
    for i in inputs {
        out(&terms_bytes(&i.service, i.redeemable_after_day));
        out(&keyset_bytes(&i.keyset));
        out(&i.input.amount.units.to_be_bytes());
        out(&i.input.note.nonce.0.serialize());
        out(&i.input.note.signature.serialize());
        if spend_signatures {
            out(i.input.spend_signature.as_ref());
        }
    }
    out(&(memo.len() as u16).to_be_bytes());
    out(memo.as_bytes());
    for list in [decline_outputs, refund_outputs] {
        out(&(list.len() as u32).to_be_bytes());
        for o in list {
            out(&terms_bytes(&o.service, o.redeemable_after_day));
            out(&o.output.amount.units.to_be_bytes());
            out(&o.output.blind_nonce.0.serialize());
        }
    }
}

/// What the service and every input sign:
/// `SHA-256("esp-mint/redeem/v2" || the canonical encoding without any
/// signature of the spender)`. That is everything in the request except the
/// spend signatures and the service signature. The memo and the terms of every
/// input and output are in it.
pub fn digest(
    service: &XOnlyPublicKey,
    output_keyset: &str,
    inputs: &[RedeemInput],
    memo: &str,
    decline_outputs: &[RedeemOutput],
    refund_outputs: &[RedeemOutput],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_TAG);
    write_body(
        service,
        output_keyset,
        inputs,
        memo,
        decline_outputs,
        refund_outputs,
        false,
        &mut |bytes| hasher.update(bytes),
    );
    hasher.finalize().into()
}

/// The canonical encoding of a whole request, signatures included. This is the
/// body of `POST /redeem`.
pub fn encode(request: &RedeemRequest) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(request.encoded_len() as usize);
    write_body(
        &request.service,
        &request.output_keyset,
        &request.inputs,
        &request.memo,
        &request.decline_outputs,
        &request.refund_outputs,
        true,
        &mut |part| bytes.extend_from_slice(part),
    );
    bytes.extend_from_slice(request.service_signature.as_ref());
    bytes
}

/// The key a request is stored under, and the id of its queue entry:
/// `SHA-256("esp-mint/redeem-request/v1" || the canonical encoding)`. It covers
/// every byte of the encoding that is measured and, so, every signature.
pub fn request_hash(request: &RedeemRequest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_TAG);
    write_body(
        &request.service,
        &request.output_keyset,
        &request.inputs,
        &request.memo,
        &request.decline_outputs,
        &request.refund_outputs,
        true,
        &mut |bytes| hasher.update(bytes),
    );
    hasher.update(request.service_signature.as_ref());
    hex::encode(hasher.finalize())
}

/// Reads bytes in order and says what is wrong when they run out.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8], String> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| format!("the request ends inside {what}"))?;
        let part = &self.bytes[self.at..end];
        self.at = end;
        Ok(part)
    }

    fn left(&self) -> usize {
        self.bytes.len() - self.at
    }

    fn u64(&mut self, what: &str) -> Result<u64, String> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.take(8, what)?);
        Ok(u64::from_be_bytes(raw))
    }

    fn u32(&mut self, what: &str) -> Result<u32, String> {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(self.take(4, what)?);
        Ok(u32::from_be_bytes(raw))
    }

    fn service(&mut self, what: &str) -> Result<XOnlyPublicKey, String> {
        XOnlyPublicKey::from_slice(self.take(32, what)?)
            .map_err(|_| format!("{what} is not a valid x-only key"))
    }

    fn point(&mut self, what: &str) -> Result<PublicKey, String> {
        PublicKey::from_slice(self.take(33, what)?)
            .map_err(|_| format!("{what} is not a valid public key"))
    }

    fn signature(&mut self, what: &str) -> Result<Signature, String> {
        Signature::from_slice(self.take(64, what)?)
            .map_err(|_| format!("{what} is not a valid signature"))
    }

    /// A list length, checked against the bytes that are left before anything is
    /// allocated for it.
    fn count(&mut self, each: u64, what: &str) -> Result<usize, String> {
        let n = u64::from(self.u32(what)?);
        let needed = n.saturating_mul(each);
        if needed > self.left() as u64 {
            return Err(format!("{what} counts more entries than the request holds"));
        }
        Ok(n as usize)
    }

    fn output(&mut self) -> Result<RedeemOutput, String> {
        let service = self.service("an output's service")?;
        let redeemable_after_day = self.u64("an output's day")?;
        let units = self.u64("an output's amount")?;
        let blind_nonce = self.point("an output's blind nonce")?;
        Ok(RedeemOutput {
            service,
            redeemable_after_day,
            output: MintOutput {
                amount: Amount::from_units(units),
                blind_nonce: BlindNonce(blind_nonce),
            },
        })
    }
}

/// Read a request from its canonical encoding. The whole of `bytes` must be
/// exactly one request: a wrong version, a bad key, a truncated or longer body,
/// a memo that is too long or not UTF-8, or a list that counts more than the body
/// holds is an error, and nothing is guessed. This does not check signatures.
pub fn decode(bytes: &[u8]) -> Result<RedeemRequest, String> {
    decode_with(bytes, DEFAULT_MAX_MEMO_BYTES)
}

/// `decode`, with the longest memo set by the config.
pub fn decode_with(bytes: &[u8], max_memo_bytes: usize) -> Result<RedeemRequest, String> {
    let mut r = Reader { bytes, at: 0 };
    let version = r.take(1, "the version")?[0];
    if version == 1 {
        return Err("version 1 requests name no keysets; rebuild the request in version 2".into());
    }
    if version != FORMAT_VERSION {
        return Err(format!("unknown request version {version}"));
    }
    let service = r.service("the service")?;
    let output_keyset = hex::encode(r.take(8, "the output keyset")?);
    let n_inputs = r.count(INPUT_BYTES, "the input count")?;
    let mut inputs = Vec::with_capacity(n_inputs);
    for _ in 0..n_inputs {
        let note_service = r.service("a note's service")?;
        let redeemable_after_day = r.u64("a note's day")?;
        let keyset = hex::encode(r.take(8, "a note's keyset")?);
        let units = r.u64("a note's amount")?;
        let nonce = r.point("a note's nonce")?;
        let signature = r.point("a note's signature")?;
        let spend_signature = r.signature("a note's spend signature")?;
        inputs.push(RedeemInput {
            service: note_service,
            redeemable_after_day,
            keyset,
            input: MintInput {
                amount: Amount::from_units(units),
                note: Note {
                    nonce: Nonce(nonce),
                    signature,
                },
                spend_signature,
            },
        });
    }
    let mut raw = [0u8; 2];
    raw.copy_from_slice(r.take(2, "the memo length")?);
    let memo_len = usize::from(u16::from_be_bytes(raw));
    if memo_len > max_memo_bytes {
        return Err(format!("the memo is longer than {max_memo_bytes} bytes"));
    }
    let memo = std::str::from_utf8(r.take(memo_len, "the memo")?)
        .map_err(|_| "the memo is not UTF-8".to_string())?
        .to_string();
    let mut lists = Vec::with_capacity(2);
    for what in ["the decline output count", "the refund output count"] {
        let n = r.count(OUTPUT_BYTES, what)?;
        let mut list = Vec::with_capacity(n);
        for _ in 0..n {
            list.push(r.output()?);
        }
        lists.push(list);
    }
    let service_signature = r.signature("the service signature")?;
    if r.left() != 0 {
        return Err("the request has bytes after its end".into());
    }
    let refund_outputs = lists.pop().unwrap_or_default();
    let decline_outputs = lists.pop().unwrap_or_default();
    Ok(RedeemRequest {
        service,
        output_keyset,
        inputs,
        memo,
        decline_outputs,
        refund_outputs,
        service_signature,
    })
}

/// Why a note was not accepted. The first reason that applies is the one given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The note names another service than the one that signed the request.
    WrongService,
    /// The note is not genuine under the key for its amount and claimed terms,
    /// or its spend signature does not cover this request.
    BadProof,
    /// The note is spent, listed twice, or held by another unfinished request.
    AlreadySpent,
    /// The note's redeemable-after day has not come.
    Immature,
    /// The note's keyset was retired at a rotation: the note expired.
    KeysetRetired,
    /// The note names a keyset that is not this mint's.
    UnknownKeyset,
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Reason::WrongService => "wrong service",
            Reason::BadProof => "bad proof",
            Reason::AlreadySpent => "already spent",
            Reason::Immature => "immature",
            Reason::KeysetRetired => "keyset retired (expired)",
            Reason::UnknownKeyset => "unknown keyset",
        })
    }
}

/// What the mint decided about one input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteResult {
    pub accepted: bool,
    /// Why it was not accepted. `None` when it was.
    pub reason: Option<Reason>,
    /// Whether the mint burns it: every accepted note, and, when the accepted
    /// notes do not cover the fee, every genuine rejected note.
    pub burned: bool,
}

/// An amount for one service and one day.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermsTotal {
    pub service: XOnlyPublicKey,
    pub redeemable_after_day: u64,
    #[serde(with = "dec")]
    pub esp: u128,
}

/// What the mint made of a request: enough for the service to rebuild it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    /// One result per input, in the request's order.
    pub notes: Vec<NoteResult>,
    /// A: the accepted total.
    #[serde(with = "dec")]
    pub accepted_esp: u128,
    /// R: the genuine, unspent notes that were not accepted.
    #[serde(with = "dec")]
    pub rejected_esp: u128,
    /// The fee: the size of the request in bytes times the rate.
    #[serde(with = "dec")]
    pub fee_esp: u128,
    /// The size of the request's canonical encoding, in bytes.
    pub size_bytes: u64,
    /// The rate the fee was charged at: the rate in force when the request was
    /// accepted. A later change to the rate does not touch it.
    #[serde(with = "dec", default)]
    pub fee_per_byte: u128,
    pub accepted_by_terms: Vec<TermsTotal>,
    pub rejected_by_terms: Vec<TermsTotal>,
}

/// The answer to a redemption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedeemResponse {
    /// One result per input, in the request's order.
    pub notes: Vec<NoteResult>,
    #[serde(with = "dec")]
    pub accepted_esp: u128,
    #[serde(with = "dec")]
    pub rejected_esp: u128,
    #[serde(with = "dec")]
    pub fee_esp: u128,
    /// The size of the request in bytes, which the fee was sized by.
    pub size_bytes: u64,
    /// The rate the fee was charged at, in ESP units per byte: the rate in force
    /// when the request was accepted.
    #[serde(with = "dec")]
    pub fee_per_byte: u128,
    /// What the mint owes the service. Zero means there is no queue entry.
    #[serde(with = "dec")]
    pub owed_esp: u128,
    /// "payout queued" when something is owed, "nothing owed, fee taken" when the
    /// accepted notes did not exceed the fee.
    pub message: String,
    /// The signatures on `refund_outputs`. Empty if there were none.
    pub refund: Vec<SignedOutput>,
    /// The queue entry as it is now: open, completed (with the payment
    /// reference) or declined (with the reason and the signatures on the
    /// reissued notes). `None` when nothing is owed.
    pub entry: Option<EntryView>,
}

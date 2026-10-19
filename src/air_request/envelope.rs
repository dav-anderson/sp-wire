//! The request and reply envelopes, the mint's side of answering and the
//! wallet's checks on a reply. Pure: no network.
//!
//! Sign bytes, ship bytes: the verifier never re-serialises. Big-endian
//! throughout. REQUEST-DESIGN.md section 5.
//!
//! ```text
//! request   version (1) | kind (1) | request_id (32) | R (33) | body_len (2) | body
//!           sealed to the mint DID; 69 + 80 = 149 bytes for mint info
//! reply     version (1) | status (1) | mint DID (33) | request_id (32) | request_hash (32)
//!           | issued_at (8) | body_len (4) | body | signature (64)
//!           sealed to R; the fixed part is 111 bytes, the signed bytes are reply[0 .. 111+n]
//! ```
//!
//! `request_hash = sha256("sp-air-req-v0" || kind || request_id || R || body_len || body)`.
//! `digest = sha256("sp-air-reply-sig-v0" || reply[0 .. 111+n])`, and the mint
//! signs it with BIP340 using its bare DID key. The wallet keeps the reply
//! plaintext as its receipt: anyone can verify it from the DID alone.

use std::fmt;

use air::{Id, SecretKey};
use serde::{Deserialize, Serialize};

use super::AirError;
use super::addr::{self, REPLY_DIGEST_LABEL, REQUEST_HASH_LABEL, sha256};
use crate::ServiceDid;

/// The envelope's own version byte.
pub const ENVELOPE_VERSION: u8 = 0;
/// The request kind of mint info.
pub const KIND_MINT_INFO: u8 = 1;
/// The reply status of a request that was answered. Others are reserved.
pub const STATUS_ANSWERED: u8 = 0;
/// Bytes of a request with an empty body.
pub const REQUEST_FIXED: usize = 69;
/// Bytes of a reply before its body.
pub const REPLY_FIXED: usize = 111;
/// Bytes of a BIP340 signature.
pub const SIGNATURE_BYTES: usize = 64;

// ---------------------------------------------------------------- request envelope

/// A request, as the wallet writes it (sealed to the mint DID).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireRequest {
    pub kind: u8,
    pub request_id: [u8; 32],
    /// `R`, the wallet's one-off key for this request, compressed.
    pub reply_key: [u8; 33],
    pub body: Vec<u8>,
}

impl WireRequest {
    /// A mint-info request: no body.
    pub fn mint_info(request_id: [u8; 32], reply_key: [u8; 33]) -> Self {
        WireRequest {
            kind: KIND_MINT_INFO,
            request_id,
            reply_key,
            body: vec![],
        }
    }

    /// version (1) | kind (1) | request_id (32) | R (33) | body_len (2, BE) | body
    pub fn encode(&self) -> Vec<u8> {
        assert!(self.body.len() <= u16::MAX as usize, "body too long");
        let mut out = Vec::with_capacity(REQUEST_FIXED + self.body.len());
        out.push(ENVELOPE_VERSION);
        out.push(self.kind);
        out.extend_from_slice(&self.request_id);
        out.extend_from_slice(&self.reply_key);
        out.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AirError> {
        if bytes.len() < REQUEST_FIXED {
            return Err(AirError(format!(
                "request too short ({} bytes)",
                bytes.len()
            )));
        }
        if bytes[0] != ENVELOPE_VERSION {
            return Err(AirError(format!("unknown envelope version {}", bytes[0])));
        }
        let body_len = u16::from_be_bytes([bytes[67], bytes[68]]) as usize;
        if bytes.len() != REQUEST_FIXED + body_len {
            return Err(AirError(format!(
                "request length {} does not match body_len {body_len}",
                bytes.len()
            )));
        }
        Ok(Self {
            kind: bytes[1],
            request_id: bytes[2..34].try_into().unwrap(),
            reply_key: bytes[34..67].try_into().unwrap(),
            body: bytes[REQUEST_FIXED..].to_vec(),
        })
    }

    /// `sha256("sp-air-req-v0" || kind || request_id || R || body_len || body)`.
    /// Leaves out nothing that is part of the question; there is no window
    /// field in v0.
    pub fn hash(&self) -> [u8; 32] {
        sha256(&[
            REQUEST_HASH_LABEL,
            &[self.kind][..],
            &self.request_id[..],
            &self.reply_key[..],
            &(self.body.len() as u16).to_be_bytes()[..],
            &self.body[..],
        ])
    }
}

// ---------------------------------------------------------------- reply envelope

/// What `GET /health` reports: the body of a mint-info reply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintInfo {
    pub status: String,
    pub wire_version: u32,
    pub network: String,
}

/// A reply, as opened by the wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireReply {
    pub status: u8,
    pub mint_did: [u8; 33],
    pub request_id: [u8; 32],
    pub request_hash: [u8; 32],
    pub issued_at: u64,
    pub body: Vec<u8>,
    pub signature: [u8; 64],
}

/// The bytes a reply's signature covers: everything before the signature.
pub fn reply_signed_bytes(
    status: u8,
    mint_did: &[u8; 33],
    request_id: &[u8; 32],
    request_hash: &[u8; 32],
    issued_at: u64,
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(REPLY_FIXED + body.len());
    out.push(ENVELOPE_VERSION);
    out.push(status);
    out.extend_from_slice(mint_did);
    out.extend_from_slice(request_id);
    out.extend_from_slice(request_hash);
    out.extend_from_slice(&issued_at.to_be_bytes());
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// `sha256("sp-air-reply-sig-v0" || signed bytes)`; the mint signs this with BIP340.
pub fn reply_digest(signed_bytes: &[u8]) -> [u8; 32] {
    sha256(&[REPLY_DIGEST_LABEL, signed_bytes])
}

/// Build and sign a reply. Returns the plaintext (before sealing). The
/// signature is byte-identical to `SecretKey::sign(Id::from(digest))`.
pub fn build_reply(
    key: &SecretKey,
    request: &WireRequest,
    status: u8,
    issued_at: u64,
    body: &[u8],
) -> Vec<u8> {
    let did = addr::key_to_bytes(&key.public_key());
    build_reply_naming(key, &did, request, status, issued_at, body)
}

/// Like [`build_reply`], but the reply names `named_did` as the mint, whatever
/// `key` is. Only a mint that signs with its own key ever should (use
/// [`build_reply`]); this exists so that tests can forge a reply that names the
/// right mint and is signed by the wrong key.
pub fn build_reply_naming(
    key: &SecretKey,
    named_did: &[u8; 33],
    request: &WireRequest,
    status: u8,
    issued_at: u64,
    body: &[u8],
) -> Vec<u8> {
    let mut out = reply_signed_bytes(
        status,
        named_did,
        &request.request_id,
        &request.hash(),
        issued_at,
        body,
    );
    let signature = key.sign(Id::from(reply_digest(&out)));
    out.extend_from_slice(&addr::sig_to_bytes(&signature));
    out
}

impl WireReply {
    pub fn decode(bytes: &[u8]) -> Result<Self, AirError> {
        if bytes.len() < REPLY_FIXED + SIGNATURE_BYTES {
            return Err(AirError(format!("reply too short ({} bytes)", bytes.len())));
        }
        if bytes[0] != ENVELOPE_VERSION {
            return Err(AirError(format!("unknown envelope version {}", bytes[0])));
        }
        let body_len = u32::from_be_bytes(bytes[107..111].try_into().unwrap()) as usize;
        if bytes.len() != REPLY_FIXED + body_len + SIGNATURE_BYTES {
            return Err(AirError(format!(
                "reply length {} does not match body_len {body_len}",
                bytes.len()
            )));
        }
        Ok(Self {
            status: bytes[1],
            mint_did: bytes[2..35].try_into().unwrap(),
            request_id: bytes[35..67].try_into().unwrap(),
            request_hash: bytes[67..99].try_into().unwrap(),
            issued_at: u64::from_be_bytes(bytes[99..107].try_into().unwrap()),
            body: bytes[REPLY_FIXED..REPLY_FIXED + body_len].to_vec(),
            signature: bytes[REPLY_FIXED + body_len..].try_into().unwrap(),
        })
    }
}

// ---------------------------------------------------------------- the wallet's checks

/// Why a reply was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    Malformed(String),
    WrongMint,
    BadSignature,
    WrongRequestId,
    WrongRequestHash,
    Refused(u8),
    Stale { issued_at: u64, now: u64 },
    BadBody(String),
    WireVersion { theirs: u32, ours: u32 },
    Network { theirs: String, ours: String },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "malformed reply: {why}"),
            Self::WrongMint => write!(f, "reply names a different mint DID"),
            Self::BadSignature => write!(f, "signature does not verify under the mint DID"),
            Self::WrongRequestId => write!(f, "reply is for a different request id"),
            Self::WrongRequestHash => write!(f, "reply is for a different question (request hash)"),
            Self::Refused(s) => write!(f, "mint refused (status {s})"),
            Self::Stale { issued_at, now } => {
                write!(f, "issued_at {issued_at} is too far from now {now}")
            }
            Self::BadBody(why) => write!(f, "bad body: {why}"),
            Self::WireVersion { theirs, ours } => {
                write!(f, "mint speaks wire version {theirs}, this wallet {ours}")
            }
            Self::Network { theirs, ours } => {
                write!(f, "mint is on {theirs}, this wallet on {ours}")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// What the wallet expects of the reply to the request it sent.
pub struct Expect<'a> {
    pub mint_did: &'a ServiceDid,
    pub request: &'a WireRequest,
    pub wire_version: u32,
    pub network: &'a str,
    pub now: u64,
    pub max_skew_secs: u64,
}

/// The wallet's checks on an opened reply (section 5). The signature is
/// checked against the DID alone, with nothing but the 33 bytes and the reply.
pub fn verify_reply(plain: &[u8], expect: &Expect) -> Result<(WireReply, MintInfo), VerifyError> {
    let reply = WireReply::decode(plain).map_err(|e| VerifyError::Malformed(e.0))?;
    if reply.mint_did != *expect.mint_did.as_bytes() {
        return Err(VerifyError::WrongMint);
    }
    let key = addr::did_to_key(expect.mint_did).map_err(|e| VerifyError::Malformed(e.0))?;
    let signature =
        addr::sig_from_bytes(&reply.signature).map_err(|e| VerifyError::Malformed(e.0))?;
    let signed = &plain[..plain.len() - SIGNATURE_BYTES];
    key.verify(&signature, Id::from(reply_digest(signed)))
        .map_err(|_| VerifyError::BadSignature)?;
    if reply.request_id != expect.request.request_id {
        return Err(VerifyError::WrongRequestId);
    }
    if reply.request_hash != expect.request.hash() {
        return Err(VerifyError::WrongRequestHash);
    }
    if reply.status != STATUS_ANSWERED {
        return Err(VerifyError::Refused(reply.status));
    }
    if reply.issued_at.abs_diff(expect.now) > expect.max_skew_secs {
        return Err(VerifyError::Stale {
            issued_at: reply.issued_at,
            now: expect.now,
        });
    }
    let info: MintInfo =
        serde_json::from_slice(&reply.body).map_err(|e| VerifyError::BadBody(e.to_string()))?;
    if info.wire_version != expect.wire_version {
        return Err(VerifyError::WireVersion {
            theirs: info.wire_version,
            ours: expect.wire_version,
        });
    }
    if info.network != expect.network {
        return Err(VerifyError::Network {
            theirs: info.network,
            ours: expect.network.to_string(),
        });
    }
    Ok((reply, info))
}

/// Verify a saved receipt (an opened reply) from the 33-byte DID alone: no
/// server, no request, no state. It checks the DID and the signature, not the
/// question (the receipt carries `request_id` and `request_hash` to tie it to
/// one).
pub fn verify_receipt(did: &ServiceDid, receipt: &[u8]) -> Result<WireReply, AirError> {
    let reply = WireReply::decode(receipt)?;
    if reply.mint_did != *did.as_bytes() {
        return Err(AirError("the receipt names another mint".into()));
    }
    let key = addr::did_to_key(did)?;
    let signature = addr::sig_from_bytes(&reply.signature)?;
    let signed = &receipt[..receipt.len() - SIGNATURE_BYTES];
    key.verify(&signature, Id::from(reply_digest(signed)))
        .map_err(|_| AirError("signature does not verify".into()))?;
    Ok(reply)
}

// ---------------------------------------------------------------- the mint's side, pure

/// What the mint does with one sealed cell from a mailbox slot, if it can be
/// answered: the reply cell's secret and the sealed reply to write there.
pub struct Answer {
    pub request: WireRequest,
    pub reply_cell: SecretKey,
    pub sealed_reply: Vec<u8>,
}

/// Open one sealed cell from a mailbox slot and answer it with `info`, or say
/// why it is skipped (it does not open, is malformed, is of an unknown kind or
/// names a key that is not one). Mint info is read-only, so junk changes no
/// state.
pub fn answer_mint_info(
    key: &SecretKey,
    info: &MintInfo,
    sealed: &[u8],
    now: u64,
) -> Result<Answer, AirError> {
    let plain = addr::open(key, sealed)?;
    let request = WireRequest::decode(&plain)?;
    if request.kind != KIND_MINT_INFO {
        return Err(AirError(format!("unknown kind {}", request.kind)));
    }
    let r_key = addr::bytes_to_key(&request.reply_key)?;
    let shared = addr::shared_mint(key, &r_key);
    let reply_cell = addr::reply_secret(&shared, &request.request_id, 0);
    let body = serde_json::to_vec(info).map_err(|e| AirError(e.to_string()))?;
    let reply = build_reply(key, &request, STATUS_ANSWERED, now, &body);
    let sealed_reply = addr::seal_to(&r_key, &reply)?;
    Ok(Answer {
        request,
        reply_cell,
        sealed_reply,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air_request::addr::{
        key_to_bytes, random_bytes, random_id, reply_secret, seal_to, shared_wallet,
    };
    use crate::seal;

    const GENERATOR: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn test_did() -> ServiceDid {
        ServiceDid::parse(GENERATOR).unwrap()
    }

    fn test_request() -> WireRequest {
        let mut r = [0x44u8; 33];
        r[0] = 0x03;
        WireRequest::mint_info([0x33; 32], r)
    }

    fn now_secs() -> u64 {
        addr::now_secs()
    }

    fn regtest_info() -> MintInfo {
        MintInfo {
            status: "ok".into(),
            wire_version: 3,
            network: "regtest".into(),
        }
    }

    const REGTEST_BODY: &[u8] = br#"{"status":"ok","wire_version":3,"network":"regtest"}"#;

    // ---- golden values (computed independently with python hashlib)

    #[test]
    fn golden_request_hash_and_reply_digest() {
        let request = test_request();
        assert_eq!(
            hex::encode(request.hash()),
            "1342dc05d63ec8c00602ec096e32638017c066332f70f450dbfc146458d9dc06"
        );
        let signed = reply_signed_bytes(
            STATUS_ANSWERED,
            test_did().as_bytes(),
            &request.request_id,
            &request.hash(),
            1_700_000_000,
            REGTEST_BODY,
        );
        assert_eq!(signed.len(), REPLY_FIXED + REGTEST_BODY.len());
        assert_eq!(
            hex::encode(reply_digest(&signed)),
            "e867fc9107c1dd1fd2b7a2226d261695b2d382a098532d1bdad553dcfc3f70f1"
        );
    }

    // ---- envelopes

    #[test]
    fn request_round_trips_and_is_69_bytes() {
        let request = test_request();
        let bytes = request.encode();
        assert_eq!(bytes.len(), REQUEST_FIXED);
        assert_eq!(WireRequest::decode(&bytes).unwrap(), request);
        let with_body = WireRequest {
            body: vec![9, 8, 7],
            ..request
        };
        let bytes = with_body.encode();
        assert_eq!(bytes.len(), REQUEST_FIXED + 3);
        assert_eq!(WireRequest::decode(&bytes).unwrap(), with_body);
    }

    #[test]
    fn request_decode_refuses_bad_input() {
        let good = test_request().encode();
        assert!(WireRequest::decode(&good[..68]).is_err());
        let mut wrong_version = good.clone();
        wrong_version[0] = 9;
        assert!(WireRequest::decode(&wrong_version).is_err());
        let mut long = good.clone();
        long.push(0);
        assert!(WireRequest::decode(&long).is_err());
        let mut lies = good.clone();
        lies[68] = 5;
        assert!(WireRequest::decode(&lies).is_err());
    }

    // ---- the whole exchange in memory, then the wallet's checks

    struct Exchange {
        mint_key: SecretKey,
        mint_did: ServiceDid,
        request: WireRequest,
        sealed_reply: Vec<u8>,
        r: SecretKey,
    }

    fn exchange() -> Exchange {
        let mint_key = SecretKey::new();
        let mint_did = addr::key_to_did(&mint_key.public_key());
        let r = SecretKey::new();
        let request = WireRequest::mint_info(random_id(), key_to_bytes(&r.public_key()));
        let sealed_request = seal_to(&mint_key.public_key(), &request.encode()).unwrap();
        assert_eq!(sealed_request.len(), REQUEST_FIXED + seal::OVERHEAD);
        let answer =
            answer_mint_info(&mint_key, &regtest_info(), &sealed_request, now_secs()).unwrap();
        let shared = shared_wallet(&r, &mint_key.public_key());
        let wallet_reply_cell = reply_secret(&shared, &request.request_id, 0);
        assert_eq!(
            wallet_reply_cell.public_key(),
            answer.reply_cell.public_key(),
            "wallet and mint must name the same reply cell"
        );
        Exchange {
            mint_key,
            mint_did,
            request,
            sealed_reply: answer.sealed_reply,
            r,
        }
    }

    fn expect(x: &Exchange) -> Expect<'_> {
        Expect {
            mint_did: &x.mint_did,
            request: &x.request,
            wire_version: 3,
            network: "regtest",
            now: now_secs(),
            max_skew_secs: 300,
        }
    }

    fn opened(x: &Exchange) -> Vec<u8> {
        addr::open(&x.r, &x.sealed_reply).unwrap()
    }

    #[test]
    fn happy_path_in_memory() {
        let x = exchange();
        let plain = opened(&x);
        let (reply, info) = verify_reply(&plain, &expect(&x)).unwrap();
        assert_eq!(reply.mint_did, *x.mint_did.as_bytes());
        assert_eq!(info, regtest_info());
        // Only the wallet opens it; the mint's own key does not.
        assert!(addr::open(&x.mint_key, &x.sealed_reply).is_err());
    }

    #[test]
    fn the_receipt_verifies_from_the_did_and_the_bytes_alone() {
        let x = exchange();
        let plain = opened(&x);
        let reply = verify_receipt(&x.mint_did, &plain).unwrap();
        assert_eq!(reply.request_id, x.request.request_id);
        assert_eq!(reply.request_hash, x.request.hash());
        // Another DID does not accept it; a flipped bit does not verify.
        assert!(verify_receipt(&test_did(), &plain).is_err());
        let mut bad = plain.clone();
        bad[REPLY_FIXED] ^= 1;
        assert!(verify_receipt(&x.mint_did, &bad).is_err());
    }

    // ---- tamper

    #[test]
    fn a_flipped_signature_bit_is_rejected() {
        let x = exchange();
        let mut plain = opened(&x);
        let last = plain.len() - 1;
        plain[last] ^= 1;
        assert_eq!(
            verify_reply(&plain, &expect(&x)).unwrap_err(),
            VerifyError::BadSignature
        );
    }

    #[test]
    fn an_altered_body_is_rejected() {
        let x = exchange();
        let mut plain = opened(&x);
        plain[REPLY_FIXED + 5] ^= 1;
        assert_eq!(
            verify_reply(&plain, &expect(&x)).unwrap_err(),
            VerifyError::BadSignature
        );
    }

    #[test]
    fn an_altered_issued_at_is_rejected() {
        let x = exchange();
        let mut plain = opened(&x);
        plain[106] ^= 1;
        assert_eq!(
            verify_reply(&plain, &expect(&x)).unwrap_err(),
            VerifyError::BadSignature
        );
    }

    #[test]
    fn a_reply_from_another_mint_is_rejected() {
        let x = exchange();
        let other = SecretKey::new();
        let plain = build_reply(
            &other,
            &x.request,
            STATUS_ANSWERED,
            now_secs(),
            REGTEST_BODY,
        );
        // It names its own DID, which is not the one the wallet expected.
        assert_eq!(
            verify_reply(&plain, &expect(&x)).unwrap_err(),
            VerifyError::WrongMint
        );
    }

    #[test]
    fn another_mints_signature_under_the_expected_did_is_rejected() {
        let x = exchange();
        let other = SecretKey::new();
        let mut plain = build_reply(
            &other,
            &x.request,
            STATUS_ANSWERED,
            now_secs(),
            REGTEST_BODY,
        );
        // Overwrite the DID field with the expected mint's DID; the signature is not theirs.
        plain[2..35].copy_from_slice(x.mint_did.as_bytes());
        assert_eq!(
            verify_reply(&plain, &expect(&x)).unwrap_err(),
            VerifyError::BadSignature
        );
    }

    #[test]
    fn a_reply_to_another_request_is_rejected() {
        let x = exchange();
        let plain = opened(&x);
        let mut other = x.request.clone();
        other.request_id = [0x77; 32];
        let wrong_id = Expect {
            request: &other,
            ..expect(&x)
        };
        assert_eq!(
            verify_reply(&plain, &wrong_id).unwrap_err(),
            VerifyError::WrongRequestId
        );
        let mut asked_differently = x.request.clone();
        asked_differently.body = vec![1];
        let wrong_hash = Expect {
            request: &asked_differently,
            ..expect(&x)
        };
        assert_eq!(
            verify_reply(&plain, &wrong_hash).unwrap_err(),
            VerifyError::WrongRequestHash
        );
    }

    #[test]
    fn refusal_stale_version_network_and_body_are_rejected() {
        let x = exchange();
        let refused = build_reply(&x.mint_key, &x.request, 7, now_secs(), REGTEST_BODY);
        assert_eq!(
            verify_reply(&refused, &expect(&x)).unwrap_err(),
            VerifyError::Refused(7)
        );
        let old = build_reply(
            &x.mint_key,
            &x.request,
            STATUS_ANSWERED,
            now_secs() - 3600,
            REGTEST_BODY,
        );
        assert!(matches!(
            verify_reply(&old, &expect(&x)).unwrap_err(),
            VerifyError::Stale { .. }
        ));
        let plain = opened(&x);
        let other_version = Expect {
            wire_version: 4,
            ..expect(&x)
        };
        assert!(matches!(
            verify_reply(&plain, &other_version).unwrap_err(),
            VerifyError::WireVersion { .. }
        ));
        let other_network = Expect {
            network: "main",
            ..expect(&x)
        };
        assert!(matches!(
            verify_reply(&plain, &other_network).unwrap_err(),
            VerifyError::Network { .. }
        ));
        let junk = build_reply(
            &x.mint_key,
            &x.request,
            STATUS_ANSWERED,
            now_secs(),
            b"not json",
        );
        assert!(matches!(
            verify_reply(&junk, &expect(&x)).unwrap_err(),
            VerifyError::BadBody(_)
        ));
        assert!(matches!(
            verify_reply(&plain[..100], &expect(&x)).unwrap_err(),
            VerifyError::Malformed(_)
        ));
    }

    // ---- the mint skips garbage

    #[test]
    fn the_mint_skips_garbage_without_panicking() {
        let key = SecretKey::new();
        let info = regtest_info();
        assert!(answer_mint_info(&key, &info, &random_bytes(200), 0).is_err());
        assert!(answer_mint_info(&key, &info, &random_bytes(10), 0).is_err());
        assert!(answer_mint_info(&key, &info, &[], 0).is_err());
        let sealed_junk = seal_to(
            &key.public_key(),
            b"this is not an envelope at all, but it opens",
        )
        .unwrap();
        assert!(answer_mint_info(&key, &info, &sealed_junk, 0).is_err());
        let mut unknown_kind = test_request();
        unknown_kind.kind = 9;
        let sealed = seal_to(&key.public_key(), &unknown_kind.encode()).unwrap();
        assert!(answer_mint_info(&key, &info, &sealed, 0).is_err());
        let mut bad_r = test_request();
        bad_r.reply_key = [0xff; 33];
        let sealed = seal_to(&key.public_key(), &bad_r.encode()).unwrap();
        assert!(answer_mint_info(&key, &info, &sealed, 0).is_err());
    }

    #[test]
    fn two_answers_to_one_request_name_the_same_reply_cell() {
        // Retries differ in their seal (fresh sender key) but not in the reply cell.
        let mint_key = SecretKey::new();
        let r = SecretKey::new();
        let request = WireRequest::mint_info(random_id(), key_to_bytes(&r.public_key()));
        let a = seal_to(&mint_key.public_key(), &request.encode()).unwrap();
        let b = seal_to(&mint_key.public_key(), &request.encode()).unwrap();
        assert!(a != b);
        let info = regtest_info();
        let first = answer_mint_info(&mint_key, &info, &a, now_secs()).unwrap();
        let second = answer_mint_info(&mint_key, &info, &b, now_secs()).unwrap();
        assert_eq!(
            first.reply_cell.public_key(),
            second.reply_cell.public_key()
        );
    }
}

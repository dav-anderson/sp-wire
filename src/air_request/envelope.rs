//! The request and reply envelopes, the mint's side of answering and the
//! wallet's checks on a reply. Pure: no network.
//!
//! Sign bytes, ship bytes: the verifier never re-serialises. Big-endian
//! throughout. REQUEST-DESIGN.md section 5.
//!
//! ```text
//! request   version (1) | kind (1) | request_id (32) | R (33) | body_len (4) | body
//!           sealed to the mint DID; 71 + 80 = 151 bytes for any call that has no body
//! reply     version (1) | status (1) | mint DID (33) | request_id (32) | request_hash (32)
//!           | issued_at (8) | body_len (4) | body | signature (64)
//!           sealed to R; the fixed part is 111 bytes, the signed bytes are reply[0 .. 111+n]
//! ```
//!
//! A kind names a call (`GET /keysets`, `POST /rollover`), not a mint: the same
//! kind to two mints (the PSP's DID and the ESP's) gets each one's own reply, in
//! the shape its own HTTP route returns, and the body is opaque here. A mint
//! answers the kinds it serves and skips the rest.
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
/// The request kind of mint info (`GET /health`).
pub const KIND_MINT_INFO: u8 = 1;
/// The request kind of the mint's current keys (`GET /keys`).
pub const KIND_KEYS: u8 = 2;
/// The request kind of the mint's keysets (`GET /keysets`).
pub const KIND_KEYSETS: u8 = 3;
/// The request kind of the mint's rotation window (`GET /rotation`).
pub const KIND_ROTATION: u8 = 4;
/// The request kind of a rollover (`POST /rollover`): the body is the request
/// JSON the HTTP call posts. The first kind that changes the mint's state.
pub const KIND_ROLLOVER: u8 = 5;
/// The request kind of a spent check (`POST /check-state`): the body is the
/// request JSON the HTTP call posts.
pub const KIND_CHECK_STATE: u8 = 6;
/// The request kind of the mint's fees and ceilings (`GET /fees`, the ESP's).
pub const KIND_FEES: u8 = 7;
/// The request kind of an exchange (`POST /exchange`, the ESP's): the body is the
/// request JSON the HTTP call posts.
pub const KIND_EXCHANGE: u8 = 8;
/// The request kind of a transfer (`POST /transfer`, the ESP's): the body is the
/// request JSON the HTTP call posts.
pub const KIND_TRANSFER: u8 = 9;
/// The request kind of a redemption (`POST /redeem`, the ESP's): the body is the
/// request in its canonical **binary** encoding, as the HTTP call posts it, not
/// JSON.
pub const KIND_REDEEM: u8 = 10;
/// The reply status of a request that was answered. The body is what the HTTP
/// call would have returned.
pub const STATUS_ANSWERED: u8 = 0;
/// The reply status of a request the mint understood but cannot answer now (the
/// HTTP call would have failed). The body is empty. Signed like any reply.
pub const STATUS_UNAVAILABLE: u8 = 1;
/// The reply status of a request the mint understood and refuses (the HTTP call
/// would have answered 4xx). The body is what the HTTP call would have returned:
/// the same JSON `{error, code, ...}`. Signed like any reply.
pub const STATUS_REFUSED: u8 = 2;
/// Bytes of a request with an empty body.
pub const REQUEST_FIXED: usize = 71;
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
    /// A request of `kind` with no body: the plain reads.
    pub fn new(kind: u8, request_id: [u8; 32], reply_key: [u8; 33]) -> Self {
        WireRequest {
            kind,
            request_id,
            reply_key,
            body: vec![],
        }
    }

    /// A mint-info request: no body.
    pub fn mint_info(request_id: [u8; 32], reply_key: [u8; 33]) -> Self {
        Self::new(KIND_MINT_INFO, request_id, reply_key)
    }

    /// version (1) | kind (1) | request_id (32) | R (33) | body_len (4, BE) | body
    pub fn encode(&self) -> Vec<u8> {
        assert!(self.body.len() <= u32::MAX as usize, "body too long");
        let mut out = Vec::with_capacity(REQUEST_FIXED + self.body.len());
        out.push(ENVELOPE_VERSION);
        out.push(self.kind);
        out.extend_from_slice(&self.request_id);
        out.extend_from_slice(&self.reply_key);
        out.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
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
        let body_len = u32::from_be_bytes(bytes[67..71].try_into().unwrap()) as usize;
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
            &(self.body.len() as u32).to_be_bytes()[..],
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
            Self::Refused(STATUS_UNAVAILABLE) => {
                write!(f, "mint could not answer now (status {STATUS_UNAVAILABLE})")
            }
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

/// The checks on an opened reply that do not depend on what was asked (section
/// 5): the mint, the signature, the request id and hash, the status and the
/// age. The signature is checked against the DID alone, with nothing but the 33
/// bytes and the reply. The body is the caller's to read: it is as signed. A
/// reply that says [`STATUS_REFUSED`] passes these checks too (it is a signed
/// answer with a body: the refusal); the caller reads the status.
pub fn verify_answer(
    plain: &[u8],
    mint_did: &ServiceDid,
    request: &WireRequest,
    now: u64,
    max_skew_secs: u64,
) -> Result<WireReply, VerifyError> {
    let reply = WireReply::decode(plain).map_err(|e| VerifyError::Malformed(e.0))?;
    if reply.mint_did != *mint_did.as_bytes() {
        return Err(VerifyError::WrongMint);
    }
    let key = addr::did_to_key(mint_did).map_err(|e| VerifyError::Malformed(e.0))?;
    let signature =
        addr::sig_from_bytes(&reply.signature).map_err(|e| VerifyError::Malformed(e.0))?;
    let signed = &plain[..plain.len() - SIGNATURE_BYTES];
    key.verify(&signature, Id::from(reply_digest(signed)))
        .map_err(|_| VerifyError::BadSignature)?;
    if reply.request_id != request.request_id {
        return Err(VerifyError::WrongRequestId);
    }
    if reply.request_hash != request.hash() {
        return Err(VerifyError::WrongRequestHash);
    }
    if reply.status != STATUS_ANSWERED && reply.status != STATUS_REFUSED {
        return Err(VerifyError::Refused(reply.status));
    }
    if reply.issued_at.abs_diff(now) > max_skew_secs {
        return Err(VerifyError::Stale {
            issued_at: reply.issued_at,
            now,
        });
    }
    Ok(reply)
}

/// Read a mint-info body and check its wire version and network.
pub fn check_mint_info(
    body: &[u8],
    wire_version: u32,
    network: &str,
) -> Result<MintInfo, VerifyError> {
    let info: MintInfo =
        serde_json::from_slice(body).map_err(|e| VerifyError::BadBody(e.to_string()))?;
    if info.wire_version != wire_version {
        return Err(VerifyError::WireVersion {
            theirs: info.wire_version,
            ours: wire_version,
        });
    }
    if info.network != network {
        return Err(VerifyError::Network {
            theirs: info.network,
            ours: network.to_string(),
        });
    }
    Ok(info)
}

/// The wallet's checks on the opened reply to a mint-info request: those of
/// [`verify_answer`], then the body.
pub fn verify_reply(plain: &[u8], expect: &Expect) -> Result<(WireReply, MintInfo), VerifyError> {
    let reply = verify_answer(
        plain,
        expect.mint_did,
        expect.request,
        expect.now,
        expect.max_skew_secs,
    )?;
    if reply.status == STATUS_REFUSED {
        return Err(VerifyError::Refused(STATUS_REFUSED));
    }
    let info = check_mint_info(&reply.body, expect.wire_version, expect.network)?;
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

/// What the mint says to one kind of request.
pub enum Served {
    /// Answered: the reply body, which is what the HTTP call returns.
    Body(Vec<u8>),
    /// Understood, but cannot be answered now: a signed reply with status
    /// [`STATUS_UNAVAILABLE`] and no body.
    Unavailable,
    /// Understood and refused: a signed reply with status [`STATUS_REFUSED`]
    /// and this body, which is what the HTTP call would have returned with
    /// its 4xx.
    Refused(Vec<u8>),
}

/// Open one sealed cell from a mailbox slot and answer it, or say why it is
/// skipped (it does not open, is malformed, is of a kind `serve` does not know
/// or names a key that is not one). `serve` is called with the kind and the
/// body, and only once the request has opened and been decoded; it returns
/// `None` for a kind it does not know. Junk never reaches `serve`, so junk
/// changes no state; what a kind with a body does with it is the mint's.
pub fn answer_request(
    key: &SecretKey,
    sealed: &[u8],
    now: u64,
    serve: &dyn Fn(u8, &[u8]) -> Option<Served>,
) -> Result<Answer, AirError> {
    let plain = addr::open(key, sealed)?;
    let request = WireRequest::decode(&plain)?;
    let r_key = addr::bytes_to_key(&request.reply_key)?;
    let served = serve(request.kind, &request.body)
        .ok_or_else(|| AirError(format!("unknown kind {}", request.kind)))?;
    let (status, body) = match served {
        Served::Body(body) => (STATUS_ANSWERED, body),
        Served::Unavailable => (STATUS_UNAVAILABLE, Vec::new()),
        Served::Refused(body) => (STATUS_REFUSED, body),
    };
    let shared = addr::shared_mint(key, &r_key);
    let reply_cell = addr::reply_secret(&shared, &request.request_id, 0);
    let reply = build_reply(key, &request, status, now, &body);
    let sealed_reply = addr::seal_to(&r_key, &reply)?;
    Ok(Answer {
        request,
        reply_cell,
        sealed_reply,
    })
}

/// [`answer_request`] for a mint that serves only mint info.
pub fn answer_mint_info(
    key: &SecretKey,
    info: &MintInfo,
    sealed: &[u8],
    now: u64,
) -> Result<Answer, AirError> {
    let body = serde_json::to_vec(info).map_err(|e| AirError(e.to_string()))?;
    answer_request(key, sealed, now, &|kind, _| {
        (kind == KIND_MINT_INFO).then(|| Served::Body(body.clone()))
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
            "8aac00e4772fe536852f09adcca654b0e15a7818f1d8c97c85bd194208168038"
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
            "86ef1acbc7bc4b84bbbb24b37675607e9f4596672f8d2450267292a5571548fa"
        );
    }

    #[test]
    fn golden_request_hash_per_kind() {
        // The same id and R, no body, one kind each; the kind is in the hash.
        let (id, r) = (test_request().request_id, test_request().reply_key);
        for (kind, want) in [
            (
                KIND_KEYS,
                "e03fffc4c1a0853489cf06de52ff5f8b90b660cf51e9e9f05eb864b6433f8a24",
            ),
            (
                KIND_KEYSETS,
                "eabd756d7a5ee70201332a058ba47114e1314fe9d38f41271a0fb40e71309fda",
            ),
            (
                KIND_ROTATION,
                "77520ddee583d8fb9d20945a0b13dcaefbdd9b015805671f05eff3fe7c29a11c",
            ),
        ] {
            assert_eq!(hex::encode(WireRequest::new(kind, id, r).hash()), want);
        }
    }

    #[test]
    fn golden_request_hash_for_the_esp_kinds() {
        let (id, r) = (test_request().request_id, test_request().reply_key);
        // No body: fees.
        assert_eq!(
            hex::encode(WireRequest::new(KIND_FEES, id, r).hash()),
            "f7c0dfbf621e7545f70efe69ce125722b1ebc5da4f480cc80869e52e2d7f090c"
        );
        assert_eq!(
            hex::encode(WireRequest::new(KIND_EXCHANGE, id, r).hash()),
            "e682517e08d443f1f42f07f52a5b3e0b8c3e51878748824fa60d31696be3cdd0"
        );
        assert_eq!(
            hex::encode(WireRequest::new(KIND_TRANSFER, id, r).hash()),
            "ba3616d215d475829266da2582c4611841df23399e85326252371339d5f4348c"
        );
        // A redemption body is binary, and any byte value is in the hash.
        let redeem = WireRequest {
            body: vec![0, 1, 2, 3, 255, 254, 0, 128],
            ..WireRequest::new(KIND_REDEEM, id, r)
        };
        assert_eq!(
            hex::encode(redeem.hash()),
            "4489ead6f7e366d67da6dcb4a66e07ce6af26ad4df35dc040ad150b8bc0a210e"
        );
        let exchange = WireRequest {
            body: br#"{"inputs":[]}"#.to_vec(),
            ..WireRequest::new(KIND_EXCHANGE, id, r)
        };
        assert_eq!(
            hex::encode(exchange.hash()),
            "c50abd8d83063542efe34d4347993c0df1aac84bb47dcd041fb6e3673a42eaa7"
        );
    }

    #[test]
    fn golden_request_hash_with_a_body() {
        // The body and its length (4 bytes) are in the hash.
        let (id, r) = (test_request().request_id, test_request().reply_key);
        let request = WireRequest {
            body: br#"{"nonces":["aa"]}"#.to_vec(),
            ..WireRequest::new(KIND_ROLLOVER, id, r)
        };
        assert_eq!(
            hex::encode(request.hash()),
            "493452b878a2d38513a9a88d65711cf1634bdcfc653c4583f4b0e2ff41cd38f0"
        );
    }

    // ---- envelopes

    #[test]
    fn request_round_trips_and_is_71_bytes() {
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
        assert!(WireRequest::decode(&good[..70]).is_err());
        let mut wrong_version = good.clone();
        wrong_version[0] = 9;
        assert!(WireRequest::decode(&wrong_version).is_err());
        let mut long = good.clone();
        long.push(0);
        assert!(WireRequest::decode(&long).is_err());
        let mut lies = good.clone();
        lies[70] = 5;
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

    // ---- the generic request: keys, keysets, rotation

    const KEYS_BODY: &[u8] = br#"{"keys":{"1":"02aa"}}"#;

    const REFUSAL_BODY: &[u8] = br#"{"error":"no","code":"malformed_request"}"#;

    fn serve_all(kind: u8, body: &[u8]) -> Option<Served> {
        match kind {
            KIND_KEYS | KIND_KEYSETS => Some(Served::Body(KEYS_BODY.to_vec())),
            KIND_ROTATION => Some(Served::Unavailable),
            KIND_ROLLOVER => Some(Served::Body(body.to_vec())),
            KIND_CHECK_STATE => Some(Served::Refused(REFUSAL_BODY.to_vec())),
            _ => None,
        }
    }

    fn asked(kind: u8, mint: &SecretKey, r: &SecretKey) -> (WireRequest, Vec<u8>) {
        let request = WireRequest::new(kind, random_id(), key_to_bytes(&r.public_key()));
        let sealed = seal_to(&mint.public_key(), &request.encode()).unwrap();
        (request, sealed)
    }

    #[test]
    fn each_kind_is_answered_with_its_body_and_checks_out() {
        let mint = SecretKey::new();
        let did = addr::key_to_did(&mint.public_key());
        let r = SecretKey::new();
        for kind in [KIND_KEYS, KIND_KEYSETS] {
            let (request, sealed) = asked(kind, &mint, &r);
            let answer = answer_request(&mint, &sealed, now_secs(), &serve_all).unwrap();
            assert_eq!(answer.request, request);
            let plain = addr::open(&r, &answer.sealed_reply).unwrap();
            let reply = verify_answer(&plain, &did, &request, now_secs(), 300).unwrap();
            assert_eq!(
                reply.body, KEYS_BODY,
                "the body is carried as it was served"
            );
            assert_eq!(reply.status, STATUS_ANSWERED);
        }
    }

    #[test]
    fn unavailable_is_a_signed_reply_that_the_wallet_reads_as_refused() {
        let mint = SecretKey::new();
        let did = addr::key_to_did(&mint.public_key());
        let r = SecretKey::new();
        let (request, sealed) = asked(KIND_ROTATION, &mint, &r);
        let answer = answer_request(&mint, &sealed, now_secs(), &serve_all).unwrap();
        let plain = addr::open(&r, &answer.sealed_reply).unwrap();
        assert_eq!(
            verify_answer(&plain, &did, &request, now_secs(), 300).unwrap_err(),
            VerifyError::Refused(STATUS_UNAVAILABLE)
        );
        // It is signed and has no body, so it is a receipt like any other.
        let reply = verify_receipt(&did, &plain).unwrap();
        assert_eq!(reply.status, STATUS_UNAVAILABLE);
        assert!(reply.body.is_empty());
    }

    #[test]
    fn an_unknown_kind_is_skipped_and_serve_is_not_asked_for_junk() {
        let mint = SecretKey::new();
        let r = SecretKey::new();
        let (_, sealed) = asked(9, &mint, &r);
        assert!(answer_request(&mint, &sealed, 0, &serve_all).is_err());
        // Junk and a bad R never reach `serve`.
        let never = |_: u8, _: &[u8]| -> Option<Served> { panic!("serve was called for junk") };
        assert!(answer_request(&mint, &random_bytes(200), 0, &never).is_err());
        let mut bad_r = test_request();
        bad_r.kind = KIND_KEYS;
        bad_r.reply_key = [0xff; 33];
        let sealed = seal_to(&mint.public_key(), &bad_r.encode()).unwrap();
        assert!(answer_request(&mint, &sealed, 0, &never).is_err());
    }

    #[test]
    fn a_reply_to_one_kind_is_not_an_answer_to_another() {
        // Same id and R: only the kind differs, and the kind is in the hash.
        let mint = SecretKey::new();
        let did = addr::key_to_did(&mint.public_key());
        let r = SecretKey::new();
        let (keys, sealed) = asked(KIND_KEYS, &mint, &r);
        let answer = answer_request(&mint, &sealed, now_secs(), &serve_all).unwrap();
        let plain = addr::open(&r, &answer.sealed_reply).unwrap();
        let mut keysets = keys.clone();
        keysets.kind = KIND_KEYSETS;
        assert_eq!(
            verify_answer(&plain, &did, &keysets, now_secs(), 300).unwrap_err(),
            VerifyError::WrongRequestHash
        );
    }

    #[test]
    fn a_tampered_keys_body_is_rejected() {
        let mint = SecretKey::new();
        let did = addr::key_to_did(&mint.public_key());
        let r = SecretKey::new();
        let (request, sealed) = asked(KIND_KEYS, &mint, &r);
        let answer = answer_request(&mint, &sealed, now_secs(), &serve_all).unwrap();
        let mut plain = addr::open(&r, &answer.sealed_reply).unwrap();
        plain[REPLY_FIXED + 10] ^= 1;
        assert_eq!(
            verify_answer(&plain, &did, &request, now_secs(), 300).unwrap_err(),
            VerifyError::BadSignature
        );
    }

    #[test]
    fn mint_info_still_answers_only_mint_info() {
        let mint = SecretKey::new();
        let r = SecretKey::new();
        let (_, sealed) = asked(KIND_KEYS, &mint, &r);
        assert!(answer_mint_info(&mint, &regtest_info(), &sealed, 0).is_err());
    }

    // ---- a body: rollover and check-state

    fn asked_with(
        kind: u8,
        body: &[u8],
        mint: &SecretKey,
        r: &SecretKey,
    ) -> (WireRequest, Vec<u8>) {
        let request = WireRequest {
            body: body.to_vec(),
            ..WireRequest::new(kind, random_id(), key_to_bytes(&r.public_key()))
        };
        let sealed = seal_to(&mint.public_key(), &request.encode()).unwrap();
        (request, sealed)
    }

    #[test]
    fn a_request_body_can_be_a_megabyte_and_more() {
        // A full rollover chunk is about half a megabyte; the body length is 4
        // bytes, so the ceiling is the mint's setting and not the envelope's.
        let mint = SecretKey::new();
        let did = addr::key_to_did(&mint.public_key());
        let r = SecretKey::new();
        let body: Vec<u8> = (0..(1 << 20) + 4096).map(|i| (i % 251) as u8).collect();
        let (request, sealed) = asked_with(KIND_ROLLOVER, &body, &mint, &r);
        assert_eq!(request.encode().len(), REQUEST_FIXED + body.len());
        assert_eq!(WireRequest::decode(&request.encode()).unwrap(), request);
        let answer = answer_request(&mint, &sealed, now_secs(), &serve_all).unwrap();
        assert_eq!(answer.request.body, body, "the mint sees the whole body");
        let plain = addr::open(&r, &answer.sealed_reply).unwrap();
        let reply = verify_answer(&plain, &did, &request, now_secs(), 300).unwrap();
        assert_eq!(reply.body, body);
        // One flipped byte of the body is another question.
        let mut other = request.clone();
        other.body[1 << 19] ^= 1;
        assert_eq!(
            verify_answer(&plain, &did, &other, now_secs(), 300).unwrap_err(),
            VerifyError::WrongRequestHash
        );
    }

    #[test]
    fn the_esp_kinds_carry_their_bodies_both_ways_including_binary() {
        let mint = SecretKey::new();
        let did = addr::key_to_did(&mint.public_key());
        let r = SecretKey::new();
        // The mint echoes the body for three of them and refuses the fourth.
        let serve = |kind: u8, body: &[u8]| match kind {
            KIND_FEES => Some(Served::Body(br#"{"redeem":{}}"#.to_vec())),
            KIND_EXCHANGE | KIND_TRANSFER | KIND_REDEEM => Some(Served::Body(body.to_vec())),
            _ => None,
        };
        let binary: Vec<u8> = (0..=255u8).collect();
        for (kind, body) in [
            (KIND_FEES, Vec::new()),
            (KIND_EXCHANGE, br#"{"inputs":[]}"#.to_vec()),
            (KIND_TRANSFER, br#"{"inputs":[1]}"#.to_vec()),
            (KIND_REDEEM, binary.clone()),
        ] {
            let (request, sealed) = asked_with(kind, &body, &mint, &r);
            let answer = answer_request(&mint, &sealed, now_secs(), &serve).unwrap();
            assert_eq!(
                answer.request.body, body,
                "kind {kind}: the mint sees the body"
            );
            let plain = addr::open(&r, &answer.sealed_reply).unwrap();
            let reply = verify_answer(&plain, &did, &request, now_secs(), 300).unwrap();
            assert_eq!(reply.status, STATUS_ANSWERED);
            if kind != KIND_FEES {
                assert_eq!(reply.body, body, "kind {kind}: and the wallet gets it back");
            }
        }
        // A kind the mint does not serve is skipped, whatever it carries.
        let (_, sealed) = asked_with(KIND_KEYS, b"", &mint, &r);
        assert!(answer_request(&mint, &sealed, now_secs(), &serve).is_err());
    }

    #[test]
    fn a_refusal_is_a_signed_reply_with_its_body() {
        let mint = SecretKey::new();
        let did = addr::key_to_did(&mint.public_key());
        let r = SecretKey::new();
        let (request, sealed) = asked_with(KIND_CHECK_STATE, b"{}", &mint, &r);
        let answer = answer_request(&mint, &sealed, now_secs(), &serve_all).unwrap();
        let plain = addr::open(&r, &answer.sealed_reply).unwrap();
        // It passes the generic checks: the caller reads the status and the body.
        let reply = verify_answer(&plain, &did, &request, now_secs(), 300).unwrap();
        assert_eq!(reply.status, STATUS_REFUSED);
        assert_eq!(reply.body, REFUSAL_BODY);
        // And it is a receipt like any other.
        let receipt = verify_receipt(&did, &plain).unwrap();
        assert_eq!(receipt.status, STATUS_REFUSED);
        // A flipped bit in the refusal text does not verify.
        let mut bad = plain.clone();
        bad[REPLY_FIXED + 3] ^= 1;
        assert_eq!(
            verify_answer(&bad, &did, &request, now_secs(), 300).unwrap_err(),
            VerifyError::BadSignature
        );
    }

    #[test]
    fn a_refused_reply_is_not_mint_info() {
        let x = exchange();
        let refused = build_reply(
            &x.mint_key,
            &x.request,
            STATUS_REFUSED,
            now_secs(),
            REGTEST_BODY,
        );
        assert_eq!(
            verify_reply(&refused, &expect(&x)).unwrap_err(),
            VerifyError::Refused(STATUS_REFUSED)
        );
    }

    #[test]
    fn a_status_the_envelope_does_not_define_is_still_rejected() {
        let mint = SecretKey::new();
        let did = addr::key_to_did(&mint.public_key());
        let r = SecretKey::new();
        let (request, _) = asked_with(KIND_ROLLOVER, b"{}", &mint, &r);
        let odd = build_reply(&mint, &request, 3, now_secs(), b"{}");
        assert_eq!(
            verify_answer(&odd, &did, &request, now_secs(), 300).unwrap_err(),
            VerifyError::Refused(3)
        );
    }
}

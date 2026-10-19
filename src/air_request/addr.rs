//! Key forms, cell addresses, sealing and signature bytes. Pure: no network.
//!
//! Everything here has a golden or round-trip test. The labels are part of the
//! design (REQUEST-DESIGN.md sections 2, 3 and 5); changing one moves every
//! address or digest it feeds.

use air::{Id, KeySignature, PublicKey, SecretKey};
use sha2::{Digest, Sha256};

use super::AirError;
use crate::ServiceDid;
use crate::seal;

/// Label of the mailbox slot derivation (section 2).
pub const MAILBOX_LABEL: &[u8] = b"sp-air-mailbox-v0";
/// Label of the reply-cell derivation (section 3).
pub const REPLY_CELL_LABEL: &[u8] = b"sp-air-reply-cell-v0";
/// Label of the request hash (section 5).
pub const REQUEST_HASH_LABEL: &[u8] = b"sp-air-req-v0";
/// Label of the reply signature digest (section 5). Not the reply-cell label:
/// the design shared one label for both, and they are two now (finding F5).
pub const REPLY_DIGEST_LABEL: &[u8] = b"sp-air-reply-sig-v0";

/// A wallet gives up probing the mailbox after this many taken slots.
pub const MAX_SLOTS_PROBED: u32 = 100_000;

/// `sha256` over the parts, in order. Explicit bytes are used instead of AIR's
/// `Id::hash`, whose `std::hash::Hash` length prefixes depend on pointer width.
pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Unix seconds now (0 if the clock is before 1970).
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `len` random bytes, from AIR's random ids.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    while out.len() < len {
        out.extend_from_slice(&*Id::random());
    }
    out.truncate(len);
    out
}

/// 32 random bytes: a request id.
pub fn random_id() -> [u8; 32] {
    *Id::random()
}

// ---------------------------------------------------------------- key forms

/// A 33-byte compressed key to an AIR key, through AIR's compressed-hex text
/// form (`PublicKey` serialises as 64 bytes, ElligatorSwift, but prints and
/// parses as the compressed hex; the parity byte survives the round trip).
pub fn bytes_to_key(bytes: &[u8; 33]) -> Result<PublicKey, AirError> {
    hex::encode(bytes)
        .parse::<PublicKey>()
        .map_err(|e| AirError(format!("not a public key: {e}")))
}

/// A service ID (a DID) to an AIR key.
pub fn did_to_key(did: &ServiceDid) -> Result<PublicKey, AirError> {
    bytes_to_key(did.as_bytes())
}

/// An AIR key to its 33 compressed bytes.
pub fn key_to_bytes(key: &PublicKey) -> [u8; 33] {
    let bytes = hex::decode(key.to_string()).expect("AIR prints a public key as hex");
    bytes
        .try_into()
        .expect("a compressed public key is 33 bytes")
}

/// An AIR key to a service ID.
pub fn key_to_did(key: &PublicKey) -> ServiceDid {
    ServiceDid::from_slice(&key_to_bytes(key)).expect("a public key is a valid service ID")
}

/// A one-off secret key as 64 hex characters, for a wallet that keeps `r` in its
/// file until the request is answered.
pub fn secret_to_hex(key: &SecretKey) -> String {
    hex::encode(key.to_array())
}

/// The key [`secret_to_hex`] wrote.
pub fn secret_from_hex(text: &str) -> Result<SecretKey, AirError> {
    let bytes: [u8; 32] = hex::decode(text.trim())
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| AirError("a request key is 64 hex characters".into()))?;
    SecretKey::from_array(bytes).map_err(|_| AirError("not a valid secret key".into()))
}

fn secret_from(bytes: [u8; 32]) -> SecretKey {
    SecretKey::from_array(bytes).expect(
        "a sha256 output is a valid key (zero or above the order has probability about 2^-128)",
    )
}

// ---------------------------------------------------------------- cell addresses

/// Section 2: `sha256("sp-air-mailbox-v0" || mint DID || slot as big-endian u32)`.
pub fn mailbox_secret_bytes(mint: &ServiceDid, slot: u32) -> [u8; 32] {
    sha256(&[MAILBOX_LABEL, &mint.as_bytes()[..], &slot.to_be_bytes()[..]])
}

/// The secret of mailbox slot `slot` of `mint`. Anyone can compute it, so
/// anyone can `Create` in the slot; only the mint can open what is written.
pub fn mailbox_secret(mint: &ServiceDid, slot: u32) -> SecretKey {
    secret_from(mailbox_secret_bytes(mint, slot))
}

/// The shared secret as the wallet computes it: its one-off key `r` and the mint's key.
pub fn shared_wallet(r: &SecretKey, mint: &PublicKey) -> [u8; 32] {
    r.shared(mint, None).to_array()
}

/// The shared secret as the mint computes it: its DID key and the wallet's `R`.
pub fn shared_mint(mint: &SecretKey, r_public: &PublicKey) -> [u8; 32] {
    mint.shared(r_public, None).to_array()
}

/// Section 3: `sha256("sp-air-reply-cell-v0" || shared || request_id || index as big-endian u32)`.
pub fn reply_secret_bytes(shared: &[u8; 32], request_id: &[u8; 32], index: u32) -> [u8; 32] {
    sha256(&[
        REPLY_CELL_LABEL,
        &shared[..],
        &request_id[..],
        &index.to_be_bytes()[..],
    ])
}

/// The secret of the reply cell. Only the wallet and the mint can compute it.
/// `index` is 0 for mint info (room for a reply log later).
pub fn reply_secret(shared: &[u8; 32], request_id: &[u8; 32], index: u32) -> SecretKey {
    secret_from(reply_secret_bytes(shared, request_id, index))
}

// ---------------------------------------------------------------- sealing

/// Seal `plaintext` to `to` (AIR's cipher, as [`crate::seal::encrypt`]; the
/// result is `plaintext.len() + seal::OVERHEAD` bytes).
pub fn seal_to(to: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, AirError> {
    Ok(seal::encrypt(to, plaintext)?)
}

/// Open what was sealed to the public half of `key`.
pub fn open(key: &SecretKey, sealed: &[u8]) -> Result<Vec<u8>, AirError> {
    Ok(seal::decrypt(key, sealed)?)
}

// ---------------------------------------------------------------- signature bytes

/// AIR's signature type serialises as 128 hex characters in JSON; this is how
/// the raw 64 bytes are taken out of it. A serde format, not a documented API,
/// so it is a small fragility (upstream item 18).
pub fn sig_to_bytes(sig: &KeySignature) -> [u8; 64] {
    let value = serde_json::to_value(sig).expect("signature to json");
    let text = value
        .as_str()
        .expect("a signature serialises as 128 hex characters");
    hex::decode(text)
        .expect("signature hex")
        .try_into()
        .expect("signature is 64 bytes")
}

/// The reverse of [`sig_to_bytes`].
pub fn sig_from_bytes(bytes: &[u8; 64]) -> Result<KeySignature, AirError> {
    serde_json::from_value(serde_json::Value::String(hex::encode(bytes)))
        .map_err(|e| AirError(format!("not a signature: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The generator point: a valid compressed key, so a valid service ID.
    const GENERATOR: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn test_did() -> ServiceDid {
        ServiceDid::parse(GENERATOR).unwrap()
    }

    // ---- golden values (computed independently with python hashlib, after the
    // model had reproduced the prototype's values for the old reply label)

    #[test]
    fn golden_mailbox_secrets() {
        let did = test_did();
        assert_eq!(
            hex::encode(mailbox_secret_bytes(&did, 0)),
            "cba774824cc3ebc8818f0e2e91ccd901b86ad14831ea61f899713d4092c74eb6"
        );
        assert_eq!(
            hex::encode(mailbox_secret_bytes(&did, 7)),
            "cd3505620499ab0218f3d6e5dde321c1d69fa909094d8c8880bc550af433ea35"
        );
        // 258 = 0x00000102: pins the big-endian u32.
        assert_eq!(
            hex::encode(mailbox_secret_bytes(&did, 258)),
            "992c7a2dd4e6850ea227a75b3956a804211b3dd800d73e0dfee898773a9b41e8"
        );
    }

    #[test]
    fn golden_reply_secrets() {
        let shared = [0x22u8; 32];
        let id = [0x33u8; 32];
        assert_eq!(
            hex::encode(reply_secret_bytes(&shared, &id, 0)),
            "6e7fdd4ed9d5363700a3f3ca524d5b3eab1af9e522d4e91f07c81ff6899ac946"
        );
        assert_eq!(
            hex::encode(reply_secret_bytes(&shared, &id, 1)),
            "86d1395a76ed967b786470b77ba7a0d0d27ae22d8d46d4052fe3e00b793f218e"
        );
    }

    #[test]
    fn the_reply_cell_and_the_reply_digest_have_their_own_labels() {
        assert_ne!(REPLY_CELL_LABEL, REPLY_DIGEST_LABEL);
        assert_eq!(REPLY_CELL_LABEL, b"sp-air-reply-cell-v0");
        assert_eq!(REPLY_DIGEST_LABEL, b"sp-air-reply-sig-v0");
    }

    // ---- key forms

    #[test]
    fn did_and_air_key_round_trip() {
        for _ in 0..10 {
            let key = SecretKey::new().public_key();
            let did = key_to_did(&key);
            assert!(did.as_bytes()[0] == 2 || did.as_bytes()[0] == 3);
            assert_eq!(did_to_key(&did).unwrap(), key);
            assert_eq!(bytes_to_key(&key_to_bytes(&key)).unwrap(), key);
        }
        assert!(bytes_to_key(&[0xff; 33]).is_err());
    }

    // ---- the shared secret is the same on both sides

    #[test]
    fn shared_secret_is_the_same_on_both_sides() {
        for _ in 0..50 {
            let mint = SecretKey::new();
            let r = SecretKey::new();
            let wallet_side = shared_wallet(&r, &mint.public_key());
            let mint_side = shared_mint(&mint, &r.public_key());
            assert_eq!(wallet_side, mint_side);
        }
    }

    #[test]
    fn reply_cell_is_per_request_and_per_pair() {
        let mint = SecretKey::new();
        let r = SecretKey::new();
        let shared = shared_wallet(&r, &mint.public_key());
        let a = reply_secret(&shared, &[1; 32], 0).public_key();
        let b = reply_secret(&shared, &[2; 32], 0).public_key();
        let c = reply_secret(&shared, &[1; 32], 1).public_key();
        let other = reply_secret(
            &shared_wallet(&SecretKey::new(), &mint.public_key()),
            &[1; 32],
            0,
        )
        .public_key();
        assert!(a != b && a != c && a != other);
        let did = key_to_did(&mint.public_key());
        assert!(mailbox_secret(&did, 0).public_key() != mailbox_secret(&did, 1).public_key());
    }

    // ---- signature bytes and sealing

    #[test]
    fn signature_bytes_round_trip() {
        let key = SecretKey::new();
        let sig = key.sign(Id::from([5u8; 32]));
        let bytes = sig_to_bytes(&sig);
        assert_eq!(sig_from_bytes(&bytes).unwrap(), sig);
    }

    #[test]
    fn seal_round_trips_and_guards() {
        let key = SecretKey::new();
        let sealed = seal_to(&key.public_key(), b"hello").unwrap();
        assert_eq!(sealed.len(), 5 + seal::OVERHEAD);
        assert_eq!(open(&key, &sealed).unwrap(), b"hello");
        assert!(open(&SecretKey::new(), &sealed).is_err());
        assert!(open(&key, &sealed[..seal::OVERHEAD]).is_err());
        assert!(seal_to(&key.public_key(), b"").is_err());
        assert!(open(&key, &random_bytes(200)).is_err());
    }

    #[test]
    fn random_ids_differ() {
        assert_ne!(random_id(), random_id());
        assert_eq!(random_bytes(5).len(), 5);
        assert_eq!(random_bytes(70).len(), 70);
    }

    #[test]
    fn a_request_key_survives_being_kept_as_hex() {
        let key = SecretKey::new();
        let text = secret_to_hex(&key);
        assert_eq!(text.len(), 64);
        assert_eq!(secret_from_hex(&text).unwrap(), key);
        assert_eq!(secret_from_hex(&format!(" {text}\n")).unwrap(), key);
        assert!(secret_from_hex("zz").is_err());
        assert!(secret_from_hex(&text[2..]).is_err());
        assert!(secret_from_hex(&"00".repeat(32)).is_err());
    }

    #[test]
    fn host_problems_are_named() {
        use super::super::host_problem;
        for ok in ["127.0.0.1", "air.example.org", "::1", "[::1]", "localhost"] {
            assert!(host_problem(ok).is_none(), "{ok}");
        }
        for bad in [
            "ws://air.example.org",
            "air.example.org/x",
            "air.example.org:5702",
            "a b",
        ] {
            assert!(host_problem(bad).is_some(), "{bad}");
        }
    }
}

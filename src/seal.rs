//! The OP_RETURN payload is encrypted to the mint's DID key.
//!
//! The cipher is AIR's (2.0.3, and unchanged in 2.1.0 and 3.0.0), not a new scheme: `PublicKey::encrypt` seals
//! bytes to a public key and `SecretKey::decrypt` opens them with the matching
//! secret key. It does an ElligatorSwift key exchange and encrypts with
//! ChaCha20-Poly1305, and a fresh sender key is made for every message.
//!
//! On the wire the sealed payload is AIR's raw bytes, with no framing of ours:
//!
//! ```text
//! sender key   64   the one-time sender public key, ElligatorSwift encoded
//! tag          16   the Poly1305 tag
//! ciphertext    n   as long as the payload
//! ```
//!
//! so it is always [`OVERHEAD`] (80) bytes longer than the payload, whatever the
//! payload's length. (Until `WIRE_VERSION` 2 the bytes were the `postcard`
//! encoding of AIR 1.1.0's `Encrypted`, 82 or 83 bytes longer, and the sender key
//! was a different encoding. Those do not open any more.)
//!
//! The ElligatorSwift encoding looks like 64 random bytes, so nothing in a
//! sealed payload says what it is. Any 64 bytes decode to some key, so a
//! payload cannot be told from noise until the tag has failed or passed.
//!
//! The mint's own key is published as 33 bytes of compressed hex
//! ([`parse_public_key`], the same as the DID key in the payload). AIR keeps
//! that text form (`Display` and `FromStr`); its binary and serde form is the
//! 64-byte ElligatorSwift one, which this crate never writes out.
//!
//! The format is here always. [`encrypt`] and [`decrypt`] need AIR, so they are
//! behind the `seal` feature.
//!
//! The tests for [`encrypt`] and [`decrypt`] are at the bottom of this file
//! (they run with the `seal` feature). The size of a sealed payload built from
//! a real one is pinned in `tests/sizes.rs`.

use std::error::Error;
use std::fmt;

/// Bytes of the one-time sender public key (ElligatorSwift) at the front.
pub const SENDER_KEY_BYTES: usize = 64;
/// Bytes of the Poly1305 tag after it.
pub const TAG_BYTES: usize = 16;
/// Bytes a sealed payload adds to its plaintext, always.
pub const OVERHEAD: usize = SENDER_KEY_BYTES + TAG_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// Too short to be a sealed payload: AIR cannot open a message with no
    /// ciphertext (the sender key and tag alone, 80 bytes, or less).
    Malformed,
    /// It has the right length but does not open with this key. It was sealed to
    /// another key, or it was altered, or it is not a sealed payload at all.
    Undecryptable,
    /// There is nothing to seal. AIR opens only messages of at least one byte,
    /// so an empty payload would seal to bytes nobody could open.
    Empty,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::Malformed => write!(f, "not a sealed payload"),
            SealError::Undecryptable => write!(f, "not sealed to this key, or altered"),
            SealError::Empty => write!(f, "there is nothing to seal"),
        }
    }
}

impl Error for SealError {}

// AIR 3.0.0 (ff41c09) does not export `SecretKey`. The line below needs the AIR
// commit that adds it next to `PublicKey`, eae5133 on AIR's branch
// `air3-export-secretkey`, which is the pin in Cargo.toml.
#[cfg(feature = "seal")]
pub use air::{PublicKey, SecretKey};

/// Seal `plaintext` to the mint's DID public key. The result is
/// `plaintext.len() + OVERHEAD` bytes.
#[cfg(feature = "seal")]
pub fn encrypt(mint_key: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
    if plaintext.is_empty() {
        return Err(SealError::Empty);
    }
    Ok(mint_key.encrypt(plaintext.to_vec()))
}

/// Open a sealed payload with the mint's DID secret key.
#[cfg(feature = "seal")]
pub fn decrypt(secret: &SecretKey, sealed: &[u8]) -> Result<Vec<u8>, SealError> {
    if sealed.len() <= OVERHEAD {
        return Err(SealError::Malformed);
    }
    secret
        .decrypt(sealed.to_vec())
        .map_err(|_| SealError::Undecryptable)
}

/// Parse a published DID public key (33 bytes of compressed hex).
#[cfg(feature = "seal")]
pub fn parse_public_key(text: &str) -> Result<PublicKey, Box<dyn Error>> {
    text.trim()
        .parse::<PublicKey>()
        .map_err(|e| Box::<dyn Error>::from(format!("not a public key: {e}")))
}

#[cfg(all(test, feature = "seal"))]
mod tests {
    use super::*;

    /// A payload of `len` bytes that is not all the same, so a shifted or
    /// reordered copy would not compare equal.
    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn what_is_sealed_opens_to_exactly_the_same_bytes() {
        let key = SecretKey::new();
        for len in [1usize, 2, 35, 76, 10_570, 20_000] {
            let plain = payload(len);
            let sealed = encrypt(&key.public_key(), &plain).unwrap();
            assert_eq!(sealed.len(), len + OVERHEAD);
            assert_eq!(decrypt(&key, &sealed).unwrap(), plain, "length {len}");
        }
    }

    #[test]
    fn sealing_the_same_bytes_twice_gives_different_bytes_that_both_open() {
        let key = SecretKey::new();
        let plain = payload(76);
        let a = encrypt(&key.public_key(), &plain).unwrap();
        let b = encrypt(&key.public_key(), &plain).unwrap();
        assert_ne!(a, b);
        // A fresh sender key each time: the first 64 bytes differ, so two
        // purchases of the same thing cannot be matched by their bytes.
        assert_ne!(a[..SENDER_KEY_BYTES], b[..SENDER_KEY_BYTES]);
        assert_eq!(decrypt(&key, &a).unwrap(), plain);
        assert_eq!(decrypt(&key, &b).unwrap(), plain);
    }

    #[test]
    fn another_key_does_not_open_it_and_gives_an_error_not_a_panic() {
        let mint = SecretKey::new();
        let other = SecretKey::new();
        let sealed = encrypt(&mint.public_key(), &payload(76)).unwrap();
        assert_eq!(decrypt(&other, &sealed), Err(SealError::Undecryptable));
        // The right key still opens it.
        assert_eq!(decrypt(&mint, &sealed).unwrap(), payload(76));
    }

    #[test]
    fn a_changed_byte_at_any_position_is_refused() {
        let key = SecretKey::new();
        let sealed = encrypt(&key.public_key(), &payload(35)).unwrap();
        assert_eq!(sealed.len(), 35 + OVERHEAD);
        // Every position: the sender key (0..64), the tag (64..80) and the
        // ciphertext (80..).
        for i in 0..sealed.len() {
            let mut changed = sealed.clone();
            changed[i] ^= 0x01;
            assert_eq!(
                decrypt(&key, &changed),
                Err(SealError::Undecryptable),
                "byte {i} changed"
            );
        }
    }

    #[test]
    fn a_truncated_extended_or_junk_payload_is_refused() {
        let key = SecretKey::new();
        let sealed = encrypt(&key.public_key(), &payload(35)).unwrap();

        // Every truncation. Up to the 80 bytes of overhead there is no
        // ciphertext, which is `Malformed`; longer ones are the right shape
        // and fail the tag.
        for len in 0..sealed.len() {
            let want = if len <= OVERHEAD {
                SealError::Malformed
            } else {
                SealError::Undecryptable
            };
            assert_eq!(decrypt(&key, &sealed[..len]), Err(want), "cut to {len}");
        }

        // One byte more than it was sealed with.
        let mut longer = sealed.clone();
        longer.push(0);
        assert_eq!(decrypt(&key, &longer), Err(SealError::Undecryptable));

        // Junk: shorter than the overhead, exactly the overhead, and longer.
        assert_eq!(decrypt(&key, &[]), Err(SealError::Malformed));
        assert_eq!(decrypt(&key, &[7; 10]), Err(SealError::Malformed));
        assert_eq!(decrypt(&key, &[7; OVERHEAD]), Err(SealError::Malformed));
        assert_eq!(
            decrypt(&key, &[7; OVERHEAD + 1]),
            Err(SealError::Undecryptable)
        );
        assert_eq!(decrypt(&key, &[7; 500]), Err(SealError::Undecryptable));
    }

    #[test]
    fn a_public_key_that_does_not_parse_is_refused_with_its_error() {
        let key = SecretKey::new().public_key();
        let text = key.to_string();
        assert_eq!(text.len(), 66);

        // A good key parses, and the spaces around it are forgiven.
        assert_eq!(parse_public_key(&text).unwrap().to_string(), text);
        assert_eq!(
            parse_public_key(&format!("  {text}\n"))
                .unwrap()
                .to_string(),
            text
        );

        // AIR gives one error for every bad text, so the message is the same
        // whatever is wrong with it.
        let refused = "not a public key: InvalidPublicKey";
        let x_only = &text[2..];
        assert_eq!(x_only.len(), 64);
        let not_a_prefix = format!("05{}", &text[2..]);
        for (what, bad) in [
            ("empty", String::new()),
            ("only spaces", "   ".to_string()),
            ("not hex", "zz".repeat(33)),
            ("hex with a stray character", format!("{}g", &text[..65])),
            ("an odd number of digits", text[..65].to_string()),
            ("31 bytes", text[..62].to_string()),
            ("34 bytes", format!("{text}00")),
            ("x-only, 32 bytes", x_only.to_string()),
            ("a prefix that is no key", not_a_prefix),
        ] {
            let err = parse_public_key(&bad).expect_err(what);
            assert_eq!(err.to_string(), refused, "{what}: {bad:?}");
        }
    }
}

//! The OP_RETURN payload is encrypted to the mint's DID key.
//!
//! The cipher is AIR's (2.0.3), not a new scheme: `PublicKey::encrypt` seals
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
//! ([`parse_public_key`], the same as the DID key in the payload). AIR 2.0.3 keeps
//! that text form (`Display` and `FromStr`); its binary and serde form is the
//! 64-byte ElligatorSwift one, which this crate never writes out.
//!
//! The format is here always. [`encrypt`] and [`decrypt`] need AIR, so they are
//! behind the `seal` feature.

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

#[cfg(feature = "seal")]
pub use air::names::secp256k1::{PublicKey, SecretKey};

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

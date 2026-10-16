//! The OP_RETURN payload is encrypted to the mint's DID key.
//!
//! The cipher is AIR's, not a new scheme: `PublicKey::encrypt` seals bytes to a
//! public key and `SecretKey::decrypt` opens them with the matching secret key.
//! It does an ElligatorSwift key exchange and encrypts with ChaCha20-Poly1305,
//! and a fresh sender key is made for every message.
//!
//! On the wire the sealed payload is the `postcard` encoding of AIR's
//! `Encrypted`. For a payload shorter than 128 bytes that is
//! `0x40 || 64 byte sender key || 16 byte tag || length byte || ciphertext`, so
//! [`OVERHEAD_SHORT`] (82) bytes longer than the payload. From 128 bytes the
//! length takes two bytes and the overhead is [`OVERHEAD_LONG`] (83).
//!
//! The format is here always. [`encrypt`] and [`decrypt`] need AIR, so they are
//! behind the `seal` feature.

use std::error::Error;
use std::fmt;

/// Bytes a sealed payload adds to a plaintext shorter than 128 bytes.
pub const OVERHEAD_SHORT: usize = 82;
/// Bytes a sealed payload adds to a plaintext of 128 bytes or more.
pub const OVERHEAD_LONG: usize = 83;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// The bytes are not a sealed payload at all: too short, the wrong framing,
    /// or bytes left over.
    Malformed,
    /// The framing is right but it does not open with this key. It was sealed
    /// to another key, or it was altered.
    Undecryptable,
    /// The payload could not be written out. Not expected.
    Encoding,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::Malformed => write!(f, "not a sealed payload"),
            SealError::Undecryptable => write!(f, "not sealed to this key, or altered"),
            SealError::Encoding => write!(f, "could not encode the sealed payload"),
        }
    }
}

impl Error for SealError {}

#[cfg(feature = "seal")]
pub use air::names::secp256k1::{PublicKey, SecretKey};

/// Seal `plaintext` to the mint's DID public key.
#[cfg(feature = "seal")]
pub fn encrypt(mint_key: &PublicKey, plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
    let sealed = mint_key.encrypt(plaintext.to_vec());
    postcard::to_allocvec(&sealed).map_err(|_| SealError::Encoding)
}

/// Open a sealed payload with the mint's DID secret key.
#[cfg(feature = "seal")]
pub fn decrypt(secret: &SecretKey, sealed: &[u8]) -> Result<Vec<u8>, SealError> {
    let (parsed, rest) = postcard::take_from_bytes::<air::names::secp256k1::Encrypted>(sealed)
        .map_err(|_| SealError::Malformed)?;
    if !rest.is_empty() {
        return Err(SealError::Malformed);
    }
    secret.decrypt(parsed).map_err(|_| SealError::Undecryptable)
}

/// Parse a published DID public key (hex).
#[cfg(feature = "seal")]
pub fn parse_public_key(text: &str) -> Result<PublicKey, Box<dyn Error>> {
    text.trim()
        .parse::<PublicKey>()
        .map_err(|e| Box::<dyn Error>::from(format!("not a public key: {e}")))
}

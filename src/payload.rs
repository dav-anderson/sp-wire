//! The OP_RETURN payload of a PSP purchase: the **claim DID**, 33 bytes, and
//! nothing else.
//!
//! A purchase carries no notes. The payer pays bitcoin to the PSP's address with
//! one data output that holds this payload sealed to the PSP mint's DID
//! (`crate::seal`, 80 bytes of overhead, so 113 bytes on the chain). The claim
//! DID is a throwaway key the wallet made for this purchase: it is where the PSP
//! writes what it owes (`air_request::delivery`), and the wallet proves it holds
//! the private half by signing its one claim with it
//! (`psp::ClaimRequest`).
//!
//! There is no header, no version byte and no length byte: the wire version
//! ([`crate::WIRE_VERSION`], 4) already says what a payload is, and the length is
//! fixed. A payload of any other length does not decode. This is a clean break
//! from wire version 3, whose payload (a length byte, the reply DID, the notes
//! and a keyset) is longer than 33 bytes and so never decodes as a version 4
//! payload.
//!
//! The 33 bytes must be a valid compressed curve point, because the PSP seals
//! its record to the key; a payment whose payload is not one is a payment with
//! no payload the PSP can use.

use std::fmt;

use crate::service::{DidError, ServiceDid};

/// Length of the claim DID, and so of the whole payload: 33 bytes.
pub const DID_LEN: usize = 33;

/// A decoded payload.
#[derive(Debug, PartialEq, Eq)]
pub struct Payload {
    pub claim_did: ServiceDid,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DecodeError {
    /// The payload is not exactly [`DID_LEN`] bytes.
    WrongLength,
    /// The 33 bytes are not a valid compressed curve point.
    NotAKey,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::WrongLength => {
                write!(f, "payload is not exactly {DID_LEN} bytes (the claim DID)")
            }
            DecodeError::NotAKey => write!(f, "the claim DID is not a valid curve point"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Read a payload (the plaintext, after decryption).
pub fn decode(bytes: &[u8]) -> Result<Payload, DecodeError> {
    if bytes.len() != DID_LEN {
        return Err(DecodeError::WrongLength);
    }
    match ServiceDid::from_slice(bytes) {
        Ok(claim_did) => Ok(Payload { claim_did }),
        Err(DidError::NotAKey(_)) => Err(DecodeError::NotAKey),
        Err(_) => Err(DecodeError::WrongLength),
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum EncodeError {
    /// The claim DID is not exactly [`DID_LEN`] bytes.
    WrongLength,
    /// The 33 bytes are not a valid compressed curve point.
    NotAKey,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::WrongLength => {
                write!(f, "the claim DID is not exactly {DID_LEN} bytes")
            }
            EncodeError::NotAKey => write!(f, "the claim DID is not a valid curve point"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Write a payload (the plaintext, before encryption): the claim DID itself.
/// The wallet uses this, and [`decode`] reads it back.
pub fn encode(claim_did: &[u8]) -> Result<Vec<u8>, EncodeError> {
    if claim_did.len() != DID_LEN {
        return Err(EncodeError::WrongLength);
    }
    match ServiceDid::from_slice(claim_did) {
        Ok(did) => Ok(did.as_bytes().to_vec()),
        Err(_) => Err(EncodeError::NotAKey),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The generator point G: a valid claim DID.
    const GENERATOR: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn generator() -> Vec<u8> {
        hex::decode(GENERATOR).expect("valid hex")
    }

    #[test]
    fn the_payload_is_the_claim_did_and_nothing_else() {
        let bytes = encode(&generator()).unwrap();
        assert_eq!(hex::encode(&bytes), GENERATOR);
        assert_eq!(bytes.len(), DID_LEN);
        let payload = decode(&bytes).unwrap();
        assert_eq!(payload.claim_did.to_hex(), GENERATOR);
    }

    #[test]
    fn any_other_length_is_refused_both_ways() {
        for len in [0usize, 1, DID_LEN - 1, DID_LEN + 1, 64, 113] {
            let mut bytes = generator();
            bytes.resize(len, 0x11);
            assert_eq!(decode(&bytes), Err(DecodeError::WrongLength), "{len}");
            assert_eq!(encode(&bytes), Err(EncodeError::WrongLength), "{len}");
        }
    }

    #[test]
    fn bytes_that_are_not_a_curve_point_are_refused_both_ways() {
        // The right length and a valid prefix, but x = 5 is not on the curve...
        let mut off_curve = vec![0x02];
        off_curve.extend_from_slice(&[0u8; 31]);
        off_curve.push(5);
        // ...and a prefix byte that is not 2 or 3.
        let mut bad_prefix = generator();
        bad_prefix[0] = 0x07;
        for bytes in [off_curve, bad_prefix] {
            assert_eq!(decode(&bytes), Err(DecodeError::NotAKey));
            assert_eq!(encode(&bytes), Err(EncodeError::NotAKey));
        }
    }

    #[test]
    fn a_version_3_payload_does_not_decode() {
        // Version 3 began with the reply length byte (33) and then the DID, the
        // output count and the outputs: 35 bytes at the least, never 33.
        let mut v3 = vec![DID_LEN as u8];
        v3.extend_from_slice(&generator());
        v3.push(0);
        assert_eq!(decode(&v3), Err(DecodeError::WrongLength));
    }
}

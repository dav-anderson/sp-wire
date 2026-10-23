#![allow(unused_imports)]

//! `POST /transfer`: ESP notes for new ESP notes, signed by their service.

use mint_types::{MintInput, MintOutput};
use secp256k1::schnorr::Signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::exchange::ExchangeResponse;
use super::terms::Terms;
use crate::service::ServiceDid;

const DIGEST_TAG: &[u8] = b"esp-mint/transfer/v1";
const REQUEST_TAG: &[u8] = b"esp-mint/transfer-request/v3";

/// A transfer answers in the same shape as an exchange: the service, the
/// redeemable-after day, and one blind signature and key for each output.
pub type TransferResponse = ExchangeResponse;

pub mod hex_signature {
    use secp256k1::schnorr::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Signature, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v.as_ref()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Signature, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        Signature::from_slice(&bytes).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequest {
    /// The service that holds the notes and asks for the swap (its AIR DID, 33
    /// bytes). It is also the service every new note names.
    pub service: ServiceDid,
    /// The redeemable-after day of the notes. One request covers one set of
    /// terms, and the new notes keep this day.
    pub redeemable_after_day: u64,
    /// The keyset of each input, in order. Each note is checked, and looked
    /// up in the spent list, of the keyset it names.
    #[serde(default)]
    pub input_keysets: Vec<String>,
    /// The ESP notes, each with a spend signature over the digest.
    pub inputs: Vec<MintInput>,
    /// The keyset to sign the outputs with: current or previous.
    #[serde(default)]
    pub keyset: String,
    /// The new notes, blinded. Any non-zero amounts that add up to the inputs.
    pub outputs: Vec<MintOutput>,
    /// The service's signature over the digest.
    #[serde(with = "hex_signature")]
    pub service_signature: Signature,
}

impl TransferRequest {
    /// What every signature in the request covers.
    pub fn digest(&self) -> [u8; 32] {
        digest(
            &self.service,
            self.redeemable_after_day,
            &self.inputs,
            &self.outputs,
        )
    }
}

/// What the service and every input sign:
/// `SHA-256("esp-mint/transfer/v1" || terms || the inputs || the outputs)`.
/// The terms are the service's DID and the redeemable-after day (41 bytes). Each input
/// is its amount and its nonce, and each output is its amount and its blind
/// nonce, with a count in front of each list. The spend signatures themselves are
/// not part of it.
pub fn digest(
    service: &ServiceDid,
    redeemable_after_day: u64,
    inputs: &[MintInput],
    outputs: &[MintOutput],
) -> [u8; 32] {
    let terms = Terms {
        service: *service,
        redeemable_after_day,
    };
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_TAG);
    hasher.update(terms.to_bytes());
    hasher.update((inputs.len() as u64).to_be_bytes());
    for input in inputs {
        hasher.update(input.amount.units.to_be_bytes());
        hasher.update(input.note.nonce.0.serialize());
    }
    hasher.update((outputs.len() as u64).to_be_bytes());
    for output in outputs {
        hasher.update(output.amount.units.to_be_bytes());
        hasher.update(output.blind_nonce.0.serialize());
    }
    hasher.finalize().into()
}

/// The key a request is stored under. It covers the digest and every signature
/// (the service's, each input's spend signature and each note's own signature
/// from the mint) and every keyset, so a request with different signatures never
/// gets another request's stored response.
pub fn request_hash(request: &TransferRequest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_TAG);
    hasher.update(request.digest());
    hasher.update(request.service_signature.as_ref());
    for input in &request.inputs {
        hasher.update(input.spend_signature.as_ref());
    }
    for input in &request.inputs {
        hasher.update(input.note.signature.serialize());
    }
    // Every keyset field, each with its length, so two requests that differ
    // only in a keyset never share a hash.
    super::hash_keysets(&mut hasher, &request.input_keysets, &request.keyset);
    hex::encode(hasher.finalize())
}

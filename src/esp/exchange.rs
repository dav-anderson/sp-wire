#![allow(unused_imports)]

//! `POST /exchange`: PSP notes for ESP notes.

use mint_types::{MintInput, MintOutput};
use secp256k1::{PublicKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::dec;

/// The default for the most inputs, and the most outputs, in one request
/// (`exchange.max_items` and `transfer.max_items`).
pub const MAX_ITEMS: usize = 1000;

const MEMO_TAG: &[u8] = b"esp-mint/exchange/v1";
const REQUEST_TAG: &[u8] = b"esp-mint/exchange-request/v2";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangeRequest {
    /// The service that alone may redeem the new notes (its DID key, x-only).
    pub service: XOnlyPublicKey,
    /// PSP notes, each with a spend signature over the memo's melt digest.
    pub psp_inputs: Vec<MintInput>,
    /// The PSP keyset of each note, in order. Forwarded to the PSP's `/melt`,
    /// which verifies each note, and checks its spent list, by that keyset.
    #[serde(default)]
    pub psp_input_keysets: Vec<String>,
    /// The ESP keyset to sign the outputs with: current or previous, whichever
    /// is named.
    #[serde(default)]
    pub keyset: String,
    /// The ESP notes wanted, blinded. Any non-zero amount.
    pub outputs: Vec<MintOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExchangeResponse {
    /// The keyset that signed the outputs. The wallet unblinds with its keys
    /// (`keys`) and records it. Empty in a reply stored before keysets.
    #[serde(default)]
    pub keyset: String,
    pub service: XOnlyPublicKey,
    pub redeemable_after_day: u64,
    /// One blind signature per output, in the request's order.
    pub signatures: Vec<PublicKey>,
    /// The public key each output was signed with, for unblinding.
    pub keys: Vec<PublicKey>,
    /// The fee rate this request was charged at (ESP units per byte of
    /// canonical size), as it was when the request was accepted. 0 when the
    /// route has no fee, and for a reply stored before fees existed.
    #[serde(default, with = "dec")]
    pub fee_per_byte: u128,
    /// The fee taken, in ESP units: `fee_per_byte × size_bytes`. The PSP notes
    /// were worth the outputs plus this.
    #[serde(default, with = "dec")]
    pub fee_esp: u128,
    /// The canonical size the fee was worked out on.
    #[serde(default)]
    pub size_bytes: u64,
}

/// The memo the PSP burn is bound to:
/// `hex(SHA-256("esp-mint/exchange/v1" || service || each output's amount and blind nonce))`.
pub fn memo(service: &XOnlyPublicKey, outputs: &[MintOutput]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MEMO_TAG);
    hasher.update(service.serialize());
    for output in outputs {
        hasher.update(output.amount.units.to_be_bytes());
        hasher.update(output.blind_nonce.0.serialize());
    }
    hex::encode(hasher.finalize())
}

/// The key a request is stored under. It covers the memo and every input,
/// spend signatures included, so a request with different inputs never gets
/// another request's stored response.
pub fn request_hash(request: &ExchangeRequest) -> Result<String, serde_json::Error> {
    let inputs = serde_json::to_vec(&request.psp_inputs)?;
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_TAG);
    hasher.update(memo(&request.service, &request.outputs).as_bytes());
    hasher.update((inputs.len() as u64).to_be_bytes());
    hasher.update(&inputs);
    // Every keyset field (the PSP notes' and the outputs'), length-prefixed.
    super::hash_keysets(&mut hasher, &request.psp_input_keysets, &request.keyset);
    Ok(hex::encode(hasher.finalize()))
}

//! The parts of a redemption queue entry a payer sees.

use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

use crate::dec;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Open,
    Declined,
    Completed,
}

/// A blind signature on one output and the key it was made with: what a wallet
/// needs, with its blinding factor, to unblind the new note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOutput {
    pub signature: PublicKey,
    pub key: PublicKey,
    /// The keyset that signed it. Empty in an entry stored before keysets.
    #[serde(default)]
    pub keyset: String,
}

/// What a service is told about its entry when it asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryView {
    pub status: Status,
    #[serde(with = "dec")]
    pub owed_esp: u128,
    /// The rate the fee was charged at, and the fee, as stored when the request
    /// was accepted.
    #[serde(with = "dec")]
    pub fee_per_byte: u128,
    #[serde(with = "dec")]
    pub fee_esp: u128,
    pub payment_ref: Option<String>,
    pub decline_reason: Option<String>,
    pub decline_signatures: Vec<SignedOutput>,
}

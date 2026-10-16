//! The key-set ID and the `GET /rotation` body, the same on every mint.

use std::collections::BTreeMap;

use mint_types::Amount;
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

/// A key-set ID on the wire: 8 bytes.
pub const KEYSET_LEN: usize = 8;

/// A key-set ID written as hex: 16 characters.
pub const KEYSET_HEX_LEN: usize = 16;

/// Whether `id` is 16 hex characters.
pub fn is_keyset_id(id: &str) -> bool {
    id.len() == KEYSET_HEX_LEN && id.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The PSP mint's ID for a key set. ESP and FSP derive theirs from their own
/// secrets, so only the format (8 bytes, 16 hex characters) is shared.
pub fn keyset_id(pk: &BTreeMap<Amount, PublicKey>) -> String {
    use sha2::{Digest, Sha256};
    let mut data = b"psp-mint/keyset-id/v1".to_vec();
    if let Some(k) = pk.values().next() {
        data.extend_from_slice(&k.serialize());
    }
    hex::encode(&Sha256::digest(&data)[..8])
}

/// `GET /rotation`, the same shape as fsp-mint's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysetWindow {
    pub id: String,
    pub epoch: u64,
    pub starts: Option<u64>,
    pub current_until: Option<u64>,
    pub retires: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationResponse {
    pub active: bool,
    pub first_issue: Option<u64>,
    pub rotation_activation_hours: u64,
    pub activation: Option<u64>,
    pub rotation_period_hours: u64,
    pub current: KeysetWindow,
    pub previous: Option<KeysetWindow>,
    pub next_rotation: Option<u64>,
    pub now: u64,
}

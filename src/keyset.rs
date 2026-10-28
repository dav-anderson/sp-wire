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

/// The tag of the key-set ID hash. The `v2` is the second form of the ID: it
/// commits to every (amount, key) pair (the first, `v1`, hashed only the 1-unit
/// key, so a mint could give one user a key for another amount that no ID
/// showed). An ID of the first form is not accepted anywhere.
pub const KEYSET_ID_TAG: &[u8] = b"psp-mint/keyset-id/v2";

/// The ID of a key set of the PSP or an FSP mint, the same function for both and
/// for the wallet: the first 8 bytes of
/// `SHA-256(KEYSET_ID_TAG || for each (amount, key) in amount order: amount as 8
/// bytes big-endian || the key's 33 compressed bytes)`.
///
/// Every pair is hashed, so two key sets that differ in any one key have
/// different IDs. Each pair is a fixed 41 bytes after the fixed tag, so no two
/// key sets give the same hash input. The ESP mint derives its ID from its
/// master secret and names the generation only; its per-day keys are published
/// on its stream (see [`crate::air_request::stream`]).
pub fn keyset_id(pk: &BTreeMap<Amount, PublicKey>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(KEYSET_ID_TAG);
    for (amount, key) in pk {
        hasher.update(amount.units.to_be_bytes());
        hasher.update(key.serialize());
    }
    hex::encode(&hasher.finalize()[..KEYSET_LEN])
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

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, SECP256K1};

    /// The key of the secret `[n; 32]`.
    fn key(n: u8) -> PublicKey {
        Keypair::from_seckey_slice(SECP256K1, &[n; 32])
            .unwrap()
            .public_key()
    }

    /// 64 keys: the amount 2^i has the key of the secret `[i + 1; 32]`.
    fn full() -> BTreeMap<Amount, PublicKey> {
        (0..64u32)
            .map(|i| (Amount::from_units(1u64 << i), key(i as u8 + 1)))
            .collect()
    }

    /// Fails with the 1-unit-only hash: the three sets below share the 1-unit key
    /// and have three different IDs. The IDs were computed independently with
    /// Python's `hashlib` and a small secp256k1 implementation.
    #[test]
    fn a_key_set_id_commits_to_every_key() {
        let base = full();
        assert_eq!(keyset_id(&base), "e3205d54a3c48e66");

        let mut mid = base.clone();
        mid.insert(Amount::from_units(1 << 5), key(200));
        assert_eq!(mid[&Amount::from_units(1)], base[&Amount::from_units(1)]);
        assert_eq!(keyset_id(&mid), "c0f768daf657d87e");

        let mut top = base.clone();
        top.insert(Amount::from_units(1 << 63), key(201));
        assert_eq!(top[&Amount::from_units(1)], base[&Amount::from_units(1)]);
        assert_eq!(keyset_id(&top), "7a17406d9ad1fdc1");
    }

    /// Fails if the amount is left out of the hash (the same key under another
    /// amount would then give the same ID), or if the v1 tag is used.
    #[test]
    fn the_amount_is_part_of_the_id() {
        let one: BTreeMap<_, _> = [(Amount::from_units(1), key(1))].into();
        let two: BTreeMap<_, _> = [(Amount::from_units(2), key(1))].into();
        assert_eq!(keyset_id(&one), "912d9b8b1649a1a2");
        assert_eq!(keyset_id(&two), "9b042b797bbb29da");
        // The first form hashed only the 1-unit key: this was its ID for `full()`.
        assert_ne!(keyset_id(&full()), "f00d3c2acd2561fa");
    }

    #[test]
    fn the_tag_is_the_second_form() {
        assert_eq!(KEYSET_ID_TAG, b"psp-mint/keyset-id/v2");
    }
}

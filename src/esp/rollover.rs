#![allow(unused_imports)]

//! `POST /rollover` of the ESP mint: notes in, new notes of the same amounts out.

use mint_types::{MintInput, MintOutput, transaction_sighash};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

use crate::service::ServiceDid;

pub const MAX_ROLLOVER_NOTES: usize = 1000;

/// `POST /rollover`: ESP notes of one service and one redeemable-after day in,
/// fresh notes of exactly the same amounts and the same terms out, signed with
/// the key set the request names. The holder signs (each note's spend key over
/// [`RolloverRequest::digest`]); the service's signature is not needed,
/// because nothing moves to anyone and nothing is split.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloverRequest {
    pub service: ServiceDid,
    pub redeemable_after_day: u64,
    /// The keyset of each input, in order.
    #[serde(default)]
    pub input_keysets: Vec<String>,
    pub inputs: Vec<MintInput>,
    /// The keyset to sign the outputs with: the current or the previous one.
    #[serde(default)]
    pub keyset: String,
    pub outputs: Vec<MintOutput>,
}

impl RolloverRequest {
    /// What every input signs: the terms and mint-core's transaction sighash.
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"esp-mint/rollover/v1");
        h.update(self.service.serialize());
        h.update(self.redeemable_after_day.to_be_bytes());
        h.update(transaction_sighash(&self.inputs, &self.outputs));
        h.finalize().into()
    }
    pub fn hash(&self) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(
            serde_json::to_vec(self).expect("serializable"),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloverResponse {
    pub keyset: String,
    pub epoch: u64,
    pub service: ServiceDid,
    pub redeemable_after_day: u64,
    pub signatures: Vec<PublicKey>,
    pub keys: Vec<PublicKey>,
}

//! The requests and replies of fsp-mint.

use std::collections::BTreeMap;

use mint_types::{MintInput, MintOutput, Note};
use secp256k1::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use crate::keyset::{KeysetWindow, RotationResponse};
use crate::service::ServiceDid;

/// The default for the longest spend memo, in bytes. A mint's `spend.max_memo_bytes`
/// setting decides; `GET /fees` serves the value in force.
pub const MAX_MEMO_BYTES: usize = 256;

/// An ESP note handed to the service, with its spend secret (the wallet's
/// hand-over format).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandedEsp {
    pub amount: u64,
    pub note: Note,
    pub spend_secret: SecretKey,
    /// The ESP keyset that signed the note (16 hex). Required: the Issuer
    /// verifies each note by the keyset it names.
    #[serde(default)]
    pub keyset: String,
}

/// The ESP notes of one redeemable-after day, and the FSP outputs they pay
/// for. Each group is exact on its own: the notes are worth the outputs plus
/// the group's issue fee.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueGroup {
    pub redeemable_after_day: u64,
    pub notes: Vec<HandedEsp>,
    pub outputs: Vec<MintOutput>,
}

/// `POST /issue`: ESP named for this service in, FSP out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueRequest {
    /// The service: its AIR DID (33 bytes).
    pub service: ServiceDid,
    pub groups: Vec<IssueGroup>,
}

const ISSUE_TAG: &[u8] = b"fsp-mint/issue-request/v2";

impl IssueRequest {
    /// The key the request is stored under: a hash of everything in it. A
    /// retry sends the same request and gets the same stored answer.
    pub fn hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(ISSUE_TAG);
        h.update(self.service.serialize());
        h.update((self.groups.len() as u64).to_be_bytes());
        for g in &self.groups {
            h.update(g.redeemable_after_day.to_be_bytes());
            h.update((g.notes.len() as u64).to_be_bytes());
            for n in &g.notes {
                h.update(n.amount.to_be_bytes());
                h.update(n.note.nonce.0.serialize());
                h.update(n.note.signature.serialize());
                h.update(n.spend_secret.secret_bytes());
                // The keyset field too, with its length: two requests that
                // differ only in a keyset never share a hash.
                h.update((n.keyset.len() as u64).to_be_bytes());
                h.update(n.keyset.as_bytes());
            }
            h.update((g.outputs.len() as u64).to_be_bytes());
            for o in &g.outputs {
                h.update(o.amount.units.to_be_bytes());
                h.update(o.blind_nonce.0.serialize());
            }
        }
        hex::encode(h.finalize())
    }
}

/// The canonical size of one issue group, the fee is worked out on:
/// 16 bytes (day and counts), 106 a note (amount 8, nonce 33, signature 33,
/// secret 32), 41 an output (amount 8, blind nonce 33).
pub fn issue_group_size(notes: usize, outputs: usize) -> u64 {
    16 + 106 * notes as u64 + 41 * outputs as u64
}

/// What happened to one group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum GroupResult {
    /// The ESP was transferred to the service and kept, and the FSP outputs
    /// were signed: one blind signature and key per output, in order.
    Issued {
        keyset: String,
        signatures: Vec<PublicKey>,
        keys: Vec<PublicKey>,
        fee: u64,
    },
    /// The Issuer refused the ESP transfer (nothing was burned there), so no
    /// FSP was issued for this group. `code` is fsp-mint's, `why` the Issuer's.
    Refused { code: String, why: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueResponse {
    pub groups: Vec<GroupResult>,
    /// The issue fee rate the request was accepted at.
    pub fee_per_byte: u64,
}

/// An FSP note being spent: its keyset and the note with a spend signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FspInput {
    pub keyset: String,
    pub input: MintInput,
}

/// `POST /spend`: a swap with change. The inputs are worth `pay` plus the
/// outputs. `pay` goes to the service (0 for a plain swap, for example from the
/// previous keyset to the current one); the outputs are new notes for the
/// payer, in the current keyset.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendRequest {
    pub inputs: Vec<FspInput>,
    pub outputs: Vec<MintOutput>,
    pub pay: u64,
    #[serde(default)]
    pub memo: String,
}

const SPEND_DIGEST_TAG: &[u8] = b"fsp-mint/spend/v1";
const SPEND_HASH_TAG: &[u8] = b"fsp-mint/spend-request/v3";

impl SpendRequest {
    /// What every spend signature covers.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(SPEND_DIGEST_TAG);
        h.update(self.pay.to_be_bytes());
        h.update((self.memo.len() as u64).to_be_bytes());
        h.update(self.memo.as_bytes());
        h.update((self.inputs.len() as u64).to_be_bytes());
        for i in &self.inputs {
            h.update(i.keyset.as_bytes());
            h.update(i.input.amount.units.to_be_bytes());
            h.update(i.input.note.nonce.0.serialize());
        }
        h.update((self.outputs.len() as u64).to_be_bytes());
        for o in &self.outputs {
            h.update(o.amount.units.to_be_bytes());
            h.update(o.blind_nonce.0.serialize());
        }
        h.finalize().into()
    }

    /// The key the answer is stored under: the digest, every spend signature,
    /// every note's signature (the mint's, on its nonce) and every keyset. A
    /// request that differs in any of them never gets another's stored answer.
    pub fn hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(SPEND_HASH_TAG);
        h.update(self.digest());
        for i in &self.inputs {
            h.update(i.input.spend_signature.as_ref());
        }
        // The note signatures too: the digest has the nonce but not the mint's
        // signature on it, and a note with a wrong signature is refused, so a
        // request that differs only there must not share a stored answer.
        for i in &self.inputs {
            h.update(i.input.note.signature.serialize());
        }
        // Every keyset field, length-prefixed (the digest has them without
        // lengths), so no two different requests share a hash.
        for i in &self.inputs {
            h.update((i.keyset.len() as u64).to_be_bytes());
            h.update(i.keyset.as_bytes());
        }
        hex::encode(h.finalize())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendResponse {
    pub keyset: String,
    pub signatures: Vec<PublicKey>,
    pub keys: Vec<PublicKey>,
    pub paid: u64,
}

/// `GET /keys`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysResponse {
    pub service: Option<ServiceDid>,
    pub current: String,
    pub previous: Option<String>,
    /// For each live keyset, the public key for each amount.
    pub keysets: BTreeMap<String, BTreeMap<u64, PublicKey>>,
    /// When the current keyset is replaced (Unix seconds), if rotation is on.
    pub next_rotation: Option<u64>,
}

/// `GET /fees`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeesResponse {
    pub issue_fee_per_byte: u64,
    pub issue_group_fixed_bytes: u64,
    pub issue_note_bytes: u64,
    pub issue_output_bytes: u64,
    pub max_request_bytes: u64,
    /// `issue.max_items` and `spend.max_items`: the most notes or outputs in one
    /// issue group or spend. `None` from a mint that does not say.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issue_max_items: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spend_max_items: Option<u64>,
    /// `spend.max_memo_bytes`: the longest spend memo. `None` from a mint that
    /// does not say (the default is `MAX_MEMO_BYTES`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spend_max_memo_bytes: Option<u64>,
}

/// A refusal's body: `{"error", "code"}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    pub error: String,
    pub code: String,
}

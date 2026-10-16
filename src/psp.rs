//! The PSP mint's request and response bodies.

use std::collections::BTreeMap;

use mint_types::{MintInput, MintOutput, MintOutputOutcome, Nonce};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

/// `POST /melt` of mint-core: the notes to burn and a memo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeltRequest {
    pub inputs: Vec<MintInput>,
    pub memo: String,
}

/// `POST /melt`: mint-core's melt request plus the keyset of each input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PspMeltRequest {
    #[serde(flatten)]
    pub melt: MeltRequest,
    /// The keyset each input note carries, in order. Each note is verified,
    /// and looked up in the spent list, of the keyset it names.
    #[serde(default)]
    pub keysets: Vec<String>,
}

/// What the PSP says about one note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Burn {
    /// Whether the note is spent.
    pub spent: bool,
    /// The memo the note was burned under. `None` if it is not spent, or if it
    /// was spent with no memo on record.
    pub memo: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BurnsRequest {
    pub nonces: Vec<Nonce>,
}

/// In the order of the request.
#[derive(Debug, Serialize, Deserialize)]
pub struct BurnsResponse {
    pub burns: Vec<Burn>,
}

/// `GET /keysets`: every live keyset's public keys by ID, current and
/// previous, as fsp-mint's `/keys` gives them. A wallet unblinds with the
/// keys of the keyset named in a reply (or printed with claim signatures).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysetsResponse {
    pub current: String,
    pub previous: Option<String>,
    pub keysets: BTreeMap<String, BTreeMap<u64, PublicKey>>,
}

/// Most notes in one rollover.
pub const MAX_ROLLOVER_NOTES: usize = 1000;

/// `POST /rollover`: notes in, fresh notes of exactly the same amounts out,
/// signed with the current keyset. Every input signs `transaction_sighash`
/// over the inputs and outputs, as in a mint-core swap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloverRequest {
    /// The keyset of each input note, in order. Each note is verified, and
    /// looked up in the spent list, of the keyset it names.
    #[serde(default)]
    pub input_keysets: Vec<String>,
    pub inputs: Vec<MintInput>,
    /// The keyset the outputs are to be signed with: the current or the
    /// previous one (normally the current).
    #[serde(default)]
    pub keyset: String,
    pub outputs: Vec<MintOutput>,
}

impl RolloverRequest {
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
    pub outcomes: Vec<MintOutputOutcome>,
    /// The public key each output was signed with, for unblinding.
    pub keys: Vec<PublicKey>,
}

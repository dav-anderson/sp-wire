//! The bodies of `POST /melt`, which the ESP mint sends the PSP mint to burn PSP
//! in an exchange. They are the same JSON as mint-core's melt call, so there is
//! one definition for both mints.

use mint_types::{Amount, MintInput};
use serde::{Deserialize, Serialize};

/// `POST /melt`: the notes to burn and a memo. Every input signs the memo, so a
/// burn can be tied to something outside the mint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeltRequest {
    pub inputs: Vec<MintInput>,
    pub memo: String,
}

/// `POST /melt`: the total value burned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeltResponse {
    pub burned: Amount,
}

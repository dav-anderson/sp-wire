//! Bodies of the routes every mint serves: `GET /keys` and `POST /check-state`.
//! A wallet can speak to a mint without linking any mint crate. (mint-core's
//! own server crate, which defined them first, is gone: these are the
//! definitions.)

use std::collections::BTreeMap;

use mint_types::{Amount, Nonce};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

/// `GET /keys` of the PSP mint: the public key for each denomination (the
/// current key set).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysResponse {
    pub keys: BTreeMap<Amount, PublicKey>,
}

/// `POST /check-state`: which of these notes are in the spent list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckStateRequest {
    pub nonces: Vec<Nonce>,
}

/// `POST /check-state`: in the request's order, `true` for a spent note.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckStateResponse {
    pub spent: Vec<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bodies_are_the_json_the_mints_serve() {
        let r = CheckStateResponse {
            spent: vec![true, false],
        };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"spent":[true,false]}"#
        );
        let q: CheckStateRequest = serde_json::from_str(r#"{"nonces":[]}"#).unwrap();
        assert!(q.nonces.is_empty());
        let k: KeysResponse = serde_json::from_str(r#"{"keys":{}}"#).unwrap();
        assert!(k.keys.is_empty());
    }
}

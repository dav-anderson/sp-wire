//! Serde for a `u128` as a decimal string, so JSON never loses digits.
//!
//! Use it as `#[serde(with = "sp_wire::dec")]`.

use serde::{Deserialize, Deserializer, Serializer};

pub fn serialize<S: Serializer>(value: &u128, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}

pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
    let text = String::deserialize(deserializer)?;
    text.parse().map_err(serde::de::Error::custom)
}

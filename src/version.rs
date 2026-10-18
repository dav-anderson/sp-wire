//! The wire version, and what a wallet does with a mint's.
//!
//! Every mint's `GET /health` returns `"wire_version": <integer>`. The number
//! changes whenever any encoded byte or JSON field of this crate changes. A
//! wallet refuses a mint whose number is not its own.

use std::fmt;

/// The version of every encoding in this crate.
///
/// - 1: the formats of the v0.1.0 mints (sp-wire 0.1.0).
/// - 2: the sealed payload moved to AIR 2.0.3's encryption (sp-wire 0.2.0): the
///   raw sender key, tag and ciphertext, 80 bytes of overhead, in place of the
///   `postcard` encoding of AIR 1.1.0's `Encrypted`. Nothing else changed.
/// - 3: a service ID is its 33-byte AIR DID (sp-wire 0.5.0), where it was the
///   32-byte x-only key. It changes the ESP terms (41 bytes, not 40) and with
///   them the ESP key derivation, the exchange memo, the transfer, rollover and
///   redeem digests and request hashes, the redemption encoding (its format
///   version is 3 and every service is 33 bytes), the FSP issue hash, and every
///   JSON body that names a service (66 hex characters, not 64). The mint-info
///   request of the AIR integration rides this version too.
pub const WIRE_VERSION: u32 = 3;

/// A mint speaks another wire version than this build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireMismatch {
    /// `/health` carried a different number.
    Different { mint: u64, ours: u32 },
    /// `/health` carried no `wire_version`, or not an integer: a mint from
    /// before wire versions.
    Missing { ours: u32 },
}

impl fmt::Display for WireMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireMismatch::Different { mint, ours } => write!(
                f,
                "this mint speaks wire version {mint} and this wallet speaks {ours}: update whichever is older"
            ),
            WireMismatch::Missing { ours } => write!(
                f,
                "this mint does not report a wire_version in /health (this wallet speaks {ours}): it is older than wire versions, update it"
            ),
        }
    }
}

impl std::error::Error for WireMismatch {}

/// Check the `wire_version` of a `/health` body against [`WIRE_VERSION`].
pub fn check_health(health: &serde_json::Value) -> Result<(), WireMismatch> {
    check(health.get("wire_version").and_then(|v| v.as_u64()))
}

/// Check a mint's reported number (`None` if it reported none).
pub fn check(reported: Option<u64>) -> Result<(), WireMismatch> {
    match reported {
        Some(v) if v == u64::from(WIRE_VERSION) => Ok(()),
        Some(mint) => Err(WireMismatch::Different {
            mint,
            ours: WIRE_VERSION,
        }),
        None => Err(WireMismatch::Missing { ours: WIRE_VERSION }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_wire_version_is_three() {
        assert_eq!(WIRE_VERSION, 3);
    }

    #[test]
    fn the_same_version_passes() {
        assert_eq!(
            check_health(&json!({"status": "ok", "wire_version": WIRE_VERSION})),
            Ok(())
        );
    }

    #[test]
    fn another_version_is_refused_and_says_both() {
        // a mint still on version 1 (the old seal format)
        let e = check_health(&json!({"wire_version": 1})).unwrap_err();
        assert_eq!(e, WireMismatch::Different { mint: 1, ours: 3 });
        let text = e.to_string();
        assert!(
            text.contains("wire version 1") && text.contains("speaks 3"),
            "{text}"
        );
        // a mint still on version 2 (the 32-byte x-only service ID)
        let e = check_health(&json!({"wire_version": 2})).unwrap_err();
        assert_eq!(e, WireMismatch::Different { mint: 2, ours: 3 });
    }

    #[test]
    fn a_health_without_a_version_is_refused() {
        for body in [
            json!({"status": "ok"}),
            json!({"wire_version": "2"}),
            json!({"wire_version": null}),
        ] {
            assert_eq!(
                check_health(&body),
                Err(WireMismatch::Missing { ours: 3 }),
                "{body}"
            );
        }
    }
}

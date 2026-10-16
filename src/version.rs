//! The wire version, and what a wallet does with a mint's.
//!
//! Every mint's `GET /health` returns `"wire_version": <integer>`. The number
//! changes whenever any encoded byte or JSON field of this crate changes. A
//! wallet refuses a mint whose number is not its own.

use std::fmt;

/// The version of every encoding in this crate. Starts at 1.
pub const WIRE_VERSION: u32 = 1;

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
    fn the_wire_version_starts_at_one() {
        assert_eq!(WIRE_VERSION, 1);
    }

    #[test]
    fn the_same_version_passes() {
        assert_eq!(
            check_health(&json!({"status": "ok", "wire_version": 1})),
            Ok(())
        );
    }

    #[test]
    fn another_version_is_refused_and_says_both() {
        let e = check_health(&json!({"wire_version": 2})).unwrap_err();
        assert_eq!(e, WireMismatch::Different { mint: 2, ours: 1 });
        let text = e.to_string();
        assert!(
            text.contains("wire version 2") && text.contains("speaks 1"),
            "{text}"
        );
    }

    #[test]
    fn a_health_without_a_version_is_refused() {
        for body in [
            json!({"status": "ok"}),
            json!({"wire_version": "1"}),
            json!({"wire_version": null}),
        ] {
            assert_eq!(
                check_health(&body),
                Err(WireMismatch::Missing { ours: 1 }),
                "{body}"
            );
        }
    }
}

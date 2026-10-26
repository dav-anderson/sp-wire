//! The wire version, and what a wallet does with a mint's.
//!
//! Every mint reports `"wire_version": <integer>` in its mint info (what it
//! answers over AIR to the mint-info request). The number changes whenever any
//! encoded byte or JSON field of this crate changes. A wallet refuses a mint
//! whose number is not its own: [`check`] compares the number a mint reported
//! with [`WIRE_VERSION`].

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
/// - 4: the PSP purchase claim (sp-wire 0.6.0). The OP_RETURN payload is the
///   33-byte claim DID alone (it was a length byte, the reply DID, the notes and
///   an optional keyset), so a version 3 payload does not decode. Kind 15 is the
///   purchase claim (`ClaimRequest`, `ClaimResponse`, with the digest and hash
///   tags `psp-mint/claim/v1` and `psp-mint/claim-request/v1`), and the PSP
///   delivery record of kind 13 is the owed record at an address of the claim
///   DID and an index. The kind number does not change; its bodies, addresses
///   and request hashes do.
pub const WIRE_VERSION: u32 = 4;

/// A mint speaks another wire version than this build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireMismatch {
    /// The mint reported a different number.
    Different { mint: u64, ours: u32 },
    /// The mint reported no `wire_version`: a mint from before wire versions.
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
                "this mint does not report a wire_version (this wallet speaks {ours}): it is older than wire versions, update it"
            ),
        }
    }
}

impl std::error::Error for WireMismatch {}

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

    #[test]
    fn the_wire_version_is_four() {
        assert_eq!(WIRE_VERSION, 4);
    }

    #[test]
    fn the_same_version_passes() {
        assert_eq!(check(Some(4)), Ok(()));
    }

    #[test]
    fn another_version_is_refused_and_says_both() {
        // a mint still on version 1 (the old seal format)
        let e = check(Some(1)).unwrap_err();
        assert_eq!(e, WireMismatch::Different { mint: 1, ours: 4 });
        assert_eq!(
            e.to_string(),
            "this mint speaks wire version 1 and this wallet speaks 4: update whichever is older"
        );
        // a mint still on version 3 (the payload with notes in it)
        let e = check(Some(3)).unwrap_err();
        assert_eq!(e, WireMismatch::Different { mint: 3, ours: 4 });
        assert_eq!(
            e.to_string(),
            "this mint speaks wire version 3 and this wallet speaks 4: update whichever is older"
        );
        // and a mint ahead of us
        assert_eq!(
            check(Some(5)),
            Err(WireMismatch::Different { mint: 5, ours: 4 })
        );
    }

    #[test]
    fn a_mint_that_reports_no_version_is_refused_with_the_fixed_text() {
        let e = check(None).unwrap_err();
        assert_eq!(e, WireMismatch::Missing { ours: 4 });
        assert_eq!(
            e.to_string(),
            "this mint does not report a wire_version (this wallet speaks 4): it is older than wire versions, update it"
        );
    }
}

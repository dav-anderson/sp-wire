//! The `code` of an error body, as every mint and the wallet spell it.
//!
//! A refusal is `{"error": "<why>", "code": "<one of these>"}`. A wallet acts on
//! the code, never on the text.

/// The key set was rotated out and deleted with its spent list.
pub const KEYSET_RETIRED: &str = "keyset_retired";
/// The mint never had this key set.
pub const UNKNOWN_KEYSET: &str = "unknown_keyset";
/// The key set is live but not the current one: new outputs are signed by the
/// current set only.
pub const KEYSET_NOT_CURRENT: &str = "keyset_not_current";
/// A resumed rollover or transfer is finished only with proof of its burn.
pub const BURN_NOT_PROVEN: &str = "burn_not_proven";
/// Some of the request's notes were spent by a different request. The body
/// also carries `spent`, the indexes of those inputs.
pub const NOTE_SPENT_ELSEWHERE: &str = "note_spent_elsewhere";
/// A note is held by a pending request.
pub const NOTE_HELD: &str = "note_held";
/// A request names no key set where one is required.
pub const MISSING_KEYSET: &str = "missing_keyset";
/// The request is not well formed.
pub const MALFORMED_REQUEST: &str = "malformed_request";
/// The request is larger than the mint accepts.
pub const REQUEST_TOO_LARGE: &str = "request_too_large";
/// The paid and requested amounts are not equal.
pub const NOT_EXACT: &str = "not_exact";
/// The same request is still being worked on.
pub const IN_PROGRESS: &str = "in_progress";
/// A mint this one depends on cannot be reached.
pub const ISSUER_UNAVAILABLE: &str = "issuer_unavailable";
/// A mint this one depends on refused.
pub const ISSUER_REFUSED: &str = "issuer_refused";
/// The mint cannot answer now.
pub const UNAVAILABLE: &str = "unavailable";
/// Something went wrong inside the mint.
pub const INTERNAL: &str = "internal";

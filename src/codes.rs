//! The `code` of an error body, as every mint and the wallet spell it.
//!
//! A refusal is `{"error": "<why>", "code": "<one of these>"}`. A wallet acts on
//! the code, never on the text.

/// The key set was rotated out and deleted with its spent list.
pub const KEYSET_RETIRED: &str = "keyset_retired";
/// The mint never had this key set.
pub const UNKNOWN_KEYSET: &str = "unknown_keyset";
/// Reserved, and no longer sent. Mints used to refuse new outputs that named
/// the previous key set with this code; they now sign with whichever live set
/// the request names, and answer `keyset_retired` or `unknown_keyset` for a
/// set that is not live. The name stays so that existing code that spells it
/// still builds, and so that a wallet can recognise it from a mint that still
/// sends it. Removing it would change no byte on the wire, but it would break
/// every crate that names it.
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
/// A PSP spend with `pay` 0 pays nothing: it would only move notes between
/// keysets, which is a rollover.
pub const NOTHING_TO_PAY: &str = "nothing_to_pay";
/// A PSP reconciliation request was signed by the right reply key but its
/// content did not follow the rules; these are log and audit codes of the PSP
/// mint, since a refused kind 15 request gets no reply.
pub const WRONG_TOTAL: &str = "wrong_total";
/// The rules left nothing to issue (`due_units` is 0).
pub const NOTHING_TO_ISSUE: &str = "nothing_to_issue";
/// An output of a reconciliation is not a denomination of the mint.
pub const UNKNOWN_DENOMINATION: &str = "unknown_denomination";
/// A blind nonce appears twice in a request.
pub const DUPLICATE_BLIND_NONCE: &str = "duplicate_blind_nonce";
/// A blind nonce of a request was already signed.
pub const BLIND_NONCE_USED: &str = "blind_nonce_used";
/// The reconciliation's signature does not verify under its reply key.
pub const BAD_SIGNATURE: &str = "bad_signature";
/// No payment of the mint matches the reply key and purchase.
pub const UNKNOWN_PAYMENT: &str = "unknown_payment";
/// More than one payment matches the reply key and purchase.
pub const AMBIGUOUS_PAYMENT: &str = "ambiguous_payment";
/// The payment is forfeited, settled, or was never open.
pub const PAYMENT_CLOSED: &str = "payment_closed";
/// The payment has used its attempts (`max_attempts`).
pub const TOO_MANY_ATTEMPTS: &str = "too_many_attempts";
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

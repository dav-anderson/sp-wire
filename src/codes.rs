//! The `code` of an error body, as every mint and the wallet spell it.
//!
//! A refusal is `{"error": "<why>", "code": "<one of these>"}`. A wallet acts on
//! the code, never on the text.

/// The key set was rotated out and deleted with its spent list.
pub const KEYSET_RETIRED: &str = "keyset_retired";
/// The mint never had this key set.
pub const UNKNOWN_KEYSET: &str = "unknown_keyset";
/// A PSP purchase claim named the previous key set, and a claim must name the
/// current one. The only place it is used: a refused claim gets no reply, so it
/// is a log and audit code of the PSP mint. The other kinds no longer send it:
/// a rollover, a spend or a transfer is signed with whichever live set the
/// request names, and answers `keyset_retired` or `unknown_keyset` for a set
/// that is not live. A claim naming a set that is not the current one is refused
/// with this code (the previous set), `keyset_retired` (a deleted set) or
/// `unknown_keyset` (a set the mint never had), and none of the three uses up
/// an attempt.
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
/// A PSP purchase claim was signed by the right claim key but its content did
/// not follow the owed record; these claim codes are log and audit codes of the
/// PSP mint, since a refused kind 15 claim gets no reply.
pub const WRONG_TOTAL: &str = "wrong_total";
/// An output of a claim is not a denomination of the mint.
pub const UNKNOWN_DENOMINATION: &str = "unknown_denomination";
/// A blind nonce appears twice in a request.
pub const DUPLICATE_BLIND_NONCE: &str = "duplicate_blind_nonce";
/// A blind nonce of a request was already signed.
pub const BLIND_NONCE_USED: &str = "blind_nonce_used";
/// The claim's signature does not verify under its claim key.
pub const BAD_SIGNATURE: &str = "bad_signature";
/// No open owed record of the mint matches the claim key and record id. That
/// includes a record that is not stored on AIR yet, one that was claimed or
/// expired and then pruned, and one that never existed. Not counted.
pub const UNKNOWN_OWED: &str = "unknown_owed";
/// The owed record was already claimed, by another claim.
pub const ALREADY_CLAIMED: &str = "already_claimed";
/// The owed record's claim window (`window_secs`, counted from when the record
/// was stored on AIR) has closed.
pub const CLAIM_EXPIRED: &str = "claim_expired";
/// The owed record has used its attempts (`max_attempts`).
pub const TOO_MANY_ATTEMPTS: &str = "too_many_attempts";
/// The same claim is still being worked on.
pub const IN_PROGRESS: &str = "in_progress";
/// A mint this one depends on cannot be reached.
pub const ISSUER_UNAVAILABLE: &str = "issuer_unavailable";
/// A mint this one depends on refused.
pub const ISSUER_REFUSED: &str = "issuer_refused";
/// The mint cannot answer now.
pub const UNAVAILABLE: &str = "unavailable";
/// Something went wrong inside the mint.
pub const INTERNAL: &str = "internal";

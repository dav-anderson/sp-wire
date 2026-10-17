# Changelog

## Unreleased

Documentation only; no code and no wire change. The `storage` module comment and DESIGN.md describe the planned storage behaviour in place, not by a pointer to a file outside this repository.

## 0.4.0

No byte on the wire changes, and `WIRE_VERSION` stays 2.

- New module `storage`: `ServiceId` (a 32-byte x-only key, 64 hex characters; a 33-byte DID key is reduced to it), `StoragePolicy` (an ordered list of service IDs, index 0 the primary, at most 8, no duplicates, no empty entry; empty is local only, one entry has a local backup), `DataKind` (`mint_state`, `wallet`, `app`, with the setting keys `storage.<kind>`), `Redundancy` and `StorageError`. `StoragePolicy::parse` reads the comma-separated form used in the environment, and the serde form is a JSON list of hex strings. It is the one parser and validator the three mints and the wallet use for their storage settings. Config only: nothing in it reads or writes the AIR or a file.
- Tests: the unit tests in `src/storage.rs` (both ID forms, the order and primary, one and none, empty entries, duplicates written two ways, the limit, the kinds, JSON).

## 0.3.0

No byte on the wire changes, and `WIRE_VERSION` stays 2.

- New module `keys`: `KeysResponse` (`GET /keys`), `CheckStateRequest` and `CheckStateResponse` (`POST /check-state`), the same JSON as mint-core's server types, so a wallet needs no mint crate. They add no encoding of their own, so `WIRE_VERSION` stays 2.
- `payload::Payload::keyset` (already optional on the wire) is now named by the wallet, and the PSP signs with it while it is live. The doc comment says so. The format is unchanged.
- `fsp::FeesResponse` gets an optional `spend_max_memo_bytes` (`spend.max_memo_bytes`). It is left out when `None`, so the JSON of a mint that does not send it is unchanged. `fsp::MAX_MEMO_BYTES` (256) is now only the default.
- `codes::KEYSET_NOT_CURRENT` is **reserved and never sent**. Mints now sign
  new outputs with whichever live key set (current or previous) the request
  names, and answer `keyset_retired` or `unknown_keyset` only for a set that is
  not live, so no mint refuses with `keyset_not_current` any more. The constant
  stays rather than being removed: dropping it changes no wire byte, but it
  would break every crate that names it, and a wallet may still meet the code
  from a mint of an earlier release. The request docs for `output_keyset` and
  `keyset` say which sets a mint accepts.

## 0.2.0

AIR 2.0.3 (commit `8e281d5`, `master`) replaces the stale AIR 1.1.0.

- **`WIRE_VERSION` is 2.** The sealed payload changed: AIR 2.0.3's
  `PublicKey::encrypt` returns raw bytes, the 64-byte ElligatorSwift sender key,
  the 16-byte tag and the ciphertext, and `SecretKey::decrypt` takes them. They
  are no longer the `postcard` encoding of `Encrypted`. The overhead is a
  constant `seal::OVERHEAD` (80) bytes, where it was 82 (payload under 128
  bytes) or 83. `OVERHEAD_SHORT` and `OVERHEAD_LONG` are gone.
- `seal::SealError`: `Encoding` is gone (sealing cannot fail) and `Empty` is new
  (AIR cannot open a message with no bytes in it, so an empty payload is
  refused when sealing). Bytes left over after the ciphertext used to be
  `Malformed`; they are now `Undecryptable`, because the format has no length
  to disagree with.
- `postcard` is no longer a dependency.
- AIR no longer needs a local `[patch]`: its manifest has no `substance` path
  dependency.
- Only the sealed-payload golden lines moved (`seal_sealed`, `seal_sealed_len`
  and the two overheads). The DID key, its published 33-byte hex form, the
  plaintext and every other golden are unchanged.

## 0.1.0

First release. The wire types the mints and the wallet shared by copying are now
one crate: units, key-set ID, PSP payload and seal format, the PSP, ESP and FSP
request and response bodies, the request hashes, and the error codes.

- `WIRE_VERSION` is 1.
- No encoded byte changed from the mints' v0.1.0 (pinned by `tests/golden/`).

## Wire version history

| `WIRE_VERSION` | sp-wire | What it is |
| --- | --- | --- |
| 1 | 0.1.0 | The formats the v0.1.0 mints wrote. The sealed payload was the `postcard` encoding of AIR 1.1.0's `Encrypted` (82 or 83 bytes of overhead). |
| 2 | 0.2.0 | The sealed payload moved to AIR 2.0.3's encryption: the raw 64-byte ElligatorSwift sender key, the 16-byte tag and the ciphertext, a constant 80 bytes of overhead. **Nothing else changed**: every other golden is the same as in version 1. A version 1 sealed payload does not open under version 2, and the other way round, which is why this is a wire version and not a patch. |

The golden files were captured from the v0.1.0 mints before this crate existed.
The only lines that have moved since are the sealed-payload ones (`seal_sealed`,
`seal_sealed_len` and the two overheads), when AIR was upgraded (wire version 2).

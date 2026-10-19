# Changelog

## 0.5.0 (unreleased)

**`WIRE_VERSION` is 3** (it was 2). Every service ID is the 33-byte AIR DID, 66 hex characters, in place of the 32-byte x-only key, so the bytes of ESP terms, the redeem encoding and every hash that covers a service change. There is no migration and no dual format: a version 2 peer is refused by `check_health`, and a 64-character ID is refused with a message that says to use the DID. The reason is that AIR names a service by its DID, and the x-only form drops the parity byte.

- **New module `service`:** `ServiceDid` (33 bytes; `parse`, `from_slice`, `serialize`, `to_hex`, `public_key`, `x_only`; `Display`, `FromStr`, `From<PublicKey>`; serde as a 66-character hex string), and `DidError` (`NotHex`, `BadLength`, `XOnly`, `NotAKey`). `x_only()` is for signing and checking a BIP340 signature only, and is never an ID.
- **Every `XOnlyPublicKey` that meant a service is a `ServiceDid`:** `esp::terms::Terms`, `esp::exchange`, `esp::transfer`, `esp::rollover`, `esp::redeem` (inputs, outputs, totals and the request), `fsp::IssueRequest.service` and `fsp::KeysResponse.service`.
- **`storage::ServiceId` is removed** in favour of `ServiceDid`; `StoragePolicy` holds `ServiceDid`s and no longer reduces a 33-byte key to 32. `StorageError::BadId` carries a `DidError`.
- **Sizes:** `esp::terms::TERMS_BYTES` (new) is 41, not 40. The redeem encoding is `FORMAT_VERSION` 3: `FIXED_BYTES` 120, `INPUT_BYTES` 187, `OUTPUT_BYTES` 82, `MIN_REQUEST_BYTES` 308. A version 1 or version 2 request is refused with its own message.
- **Goldens:** `tests/golden/esp.txt` and `fsp.txt` are changed on exactly the lines that carry a service ID (the terms, the exchange memo and hashes, the transfer, redeem and rollover digests and hashes, the redeem encoding and its size constants, the `service` field of the JSON, the issue request hash). The new values were computed with an independent model of the hashes, which was first checked to reproduce the version 2 lines it replaces; `tests/golden/psp.txt` is unchanged. `tests/sizes.rs` is changed to the new sizes.
- Domain-separation tags (`esp-mint/transfer/v1`, `esp-mint/redeem/v2`, ...) are unchanged: the version of the whole wire is `WIRE_VERSION`.
- **New module `air_request`: one read-only request over AIR, mint info (the wallet asks, the mint answers with a signature).** Feature `air-request` (implies `seal`) holds the pure parts: the request and reply envelopes, the mailbox and reply-cell addresses, the request hash, the reply digest, sign and verify, `MintInfo`, `verify_receipt`, and the mint's `answer_mint_info`. Feature `air-client` (implies `air-request`; adds the optional dependencies `air_server`, pinned by commit `bab9ae0`, and `tokio`) holds the thin transport (`client`: connect to a configured AIR server by name and host, raw `Create` and `Read`, held reads), the wallet's whole flow (`ask::ask_mint_info`), and `local_server` (an `air_server` started in the test process, on port 5702, which the AIR client always dials). No `WIRE_VERSION` bump: the bytes ride 3. Goldens and tamper tests are in the module; `tests/air_client.rs` runs the transport against the local server.
- **The reply cell and the reply digest have two labels, not one:** `sp-air-reply-cell-v0` and `sp-air-reply-sig-v0` (the prototype shared `sp-air-reply-v0`). The goldens are recomputed independently and use the secp256k1 generator as the test DID.
- `air-client` builds only with local patches for AIR and `air_server` while `air_server` names AIR as `path = "../air"` (README, "The AIR request"). `--all-features` includes it.
- Everything in 0.4.1, below, is part of this release.

## 0.4.1

AIR 2.1.0 (commit `741b1cf`, `master`, 16 Oct 2026) replaces AIR 2.0.3. No byte on the wire changes, `WIRE_VERSION` stays 2, and the public API of `seal` is the same: `encrypt`, `decrypt`, `parse_public_key`, `OVERHEAD`, `SealError`, `PublicKey` and `SecretKey` keep their names, signatures and behaviour.

- **What moved in AIR.** Its `names` module is now private, so `air::names::secp256k1::{PublicKey, SecretKey}` no longer compiles; `seal` takes both from the crate root, `air::{PublicKey, SecretKey}`. Between 2.0.3 and 2.1.0 the cipher code (`PublicKey::encrypt`, `SecretKey::decrypt`, the ElligatorSwift exchange and ChaCha20-Poly1305) is unchanged: the only edit to AIR's `secp256k1.rs` is that `to_array` and `to_vec` take `self` instead of `&self`, which changes nothing for these Copy types. The sealed bytes are therefore the same, and the existing decrypt-only golden (`tests/golden/psp.txt`, `seal_sealed` opened with `seal_secret_json`) opens without being recaptured. `tests/` is not changed. AIR's websocket, server, client and note modules moved to a separate crate, `air_server`, and its `stream` feature is gone, so the dependency tree is smaller than with 2.0.3.
- **AIR 2.1.0 does not export `SecretKey`.** It re-exports `PublicKey` but not `SecretKey`, which appears in its public API only as the return type of `Secret::harden` and `Secret::public`, so nothing outside AIR can name it or build one from bytes. The `seal` module cannot work without it (`decrypt` takes one, and the mint's `mint_did_key.json` is a serialized one). A one-line change in AIR's `src/lib.rs` fixes it: `SecretKey` added to the existing `pub use names::secp256k1::{...}`. That change is made on a local branch of AIR (`export-secretkey`, `bdb0c85`, on top of 2.1.0) and is to be proposed upstream. No workaround type is defined here: an `air::Secret` wrapper would have changed what `sp_wire::seal::SecretKey` is, and how `psp-mint` stores and loads its key.
- **Pin.** AIR is still pinned by commit (it has no tags), now to `741b1cf`. Until the export is merged upstream, building with `seal` needs the git-ignored patch in the README ("Features and dependencies") pointing at a checkout that has it. When it is merged, the pin moves to the merged commit and the patch goes; that is a change of the `rev` in `Cargo.toml` and nothing else.
- **`rust-version` is 1.93** (it was 1.85), which is the compiler the family builds with now.
- AIR 2.1.0 pins `secp256k1` 0.31.1 in its own `Cargo.lock`; this crate uses 0.30. The two sit side by side as before, and no type crosses between them.
- Documentation: the `storage` module comment and DESIGN.md describe the planned storage behaviour in place, not by a pointer to a file outside this repository. README and DESIGN.md describe the AIR 2.1.0 pin and the export.

## 0.4.0

No byte on the wire changes, and `WIRE_VERSION` stays 2.

- New module `storage`: `ServiceId` (a 32-byte x-only key, 64 hex characters; a 33-byte DID key is reduced to it; replaced by `ServiceDid` in 0.5.0), `StoragePolicy` (an ordered list of service IDs, index 0 the primary, at most 8, no duplicates, no empty entry; empty is local only, one entry has a local backup), `DataKind` (`mint_state`, `wallet`, `app`, with the setting keys `storage.<kind>`), `Redundancy` and `StorageError`. `StoragePolicy::parse` reads the comma-separated form used in the environment, and the serde form is a JSON list of hex strings. It is the one parser and validator the three mints and the wallet use for their storage settings. Config only: nothing in it reads or writes the AIR or a file.
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

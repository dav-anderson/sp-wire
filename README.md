# sp-wire

Everything the Service Points mints and wallets exchange: the types, their
encodings and the constants. `psp-mint`, `esp-mint`, `fsp-mint` and
`ecash-wallet` all build against this one crate, so a mint and a wallet cannot
disagree about a byte.

This is the wire only. It has no storage, no HTTP server, no settlement logic and
no config files (the one exception is the storage policy's parser, `storage`, which
does no I/O), and its dependencies are small (`mint-types`, `secp256k1`, `serde`,
`sha2`, `hex`). A wallet app can use it without pulling in any mint code.

## Layout

| Module | Holds |
| --- | --- |
| `units` | `ESP_PER_PSP` (10^11), `ESP_PER_USD` (10^12), `MAX_PSP_PER_NOTE`, the PSP-to-ESP conversions |
| `keyset` | the key-set ID (8 bytes, 16 hex characters), the one shared `keyset_id` (it hashes every (amount, key) pair, tag `psp-mint/keyset-id/v2`; the PSP, every FSP mint and the wallet use it), `KeysetWindow`, `RotationResponse` (`GET /rotation`) |
| `payload` | the PSP OP_RETURN payload, the 33-byte claim DID and nothing else: `Payload`, `encode`, `decode`, `DID_LEN` (33) |
| `seal` | the sealed payload's format (a constant 80 bytes of overhead: the 64-byte sender key and the 16-byte tag) and, with the `seal` feature, `encrypt`, `decrypt`, `parse_public_key` |
| `melt` | `MeltRequest` and `MeltResponse`, the bodies of the PSP's `POST /melt` (the ESP mint calls it) |
| `psp` | `PspMeltRequest`, `Burn*`, `KeysetsResponse`, `RolloverRequest`/`Response`, `PspSpendRequest`/`Response`, `ClaimRequest`/`ClaimResponse` (the purchase claim, kind 15) with `CLAIM_WINDOW_SECS`, and the file that hands the PSP a spend paid to the SPI's wallet (`PspHandover`, `HandedPspNote`) |
| `esp` | `exchange`, `transfer`, `redeem` (the binary request and its reply), `rollover`, `queue` views, `terms`, `hash_keysets`, and `handover`, the file that hands ESP notes to a service (`Handover`, `HandedNote`) |
| `fsp` | `IssueRequest`/`Response`, `SpendRequest`/`Response`, `KeysResponse`, `FeesResponse`, `Refusal` |
| `codes` | the `code` of an error body: `keyset_retired`, `unknown_keyset`, `keyset_not_current` (reserved: no mint sends it), `burn_not_proven`, `note_spent_elsewhere`, ... |
| `dec` | a `u128` as a decimal string in JSON |
| `service` | `ServiceDid`, a service's ID: its 33-byte AIR DID (a compressed key, 66 hex characters), the one type and parser every mint and the wallet use for it |
| `version` | `WIRE_VERSION` and `check`, the check a wallet makes of the wire version a mint reports |
| `air_request` | the requests over AIR, mint info, a PSP's keys, keysets and rotation, its rollover and check-state, the PSP's owed record, and the mints' key streams (`air_request::stream`) (feature `air-request`; the transport is `air-client`): envelopes, mailbox and reply-cell addresses, request hash, reply digest, sign and verify, `MintInfo`; with `air-client` also the thin AIR client, the wallet's whole flow (`ask`) and a local `air_server` for tests. See "The AIR request" below |
| `storage` | not wire: the storage policy (an ordered list of service DIDs per kind of data, index 0 primary), its parser and its checks, shared by the three mints and the wallet. Config only; it reads and writes nothing |

The note, nonce, blinded output and mint input/output types are mint-core's
(`mint_types`). sp-wire depends on that crate at its release tag and re-exports
the types, so there is one definition of them. It does not depend on `mint-core`.

The request hashes (`request_hash`, `hash`, `digest`) live here with the types
they cover: they are part of the wire, because a retry gets its stored answer by
hash.

`esp::handover` is the file that hands ESP notes to a service: `Handover` (the
service, the redeemable-after day and the notes) and `HandedNote` (an amount, the
note, its spend secret and the keyset that signed it). fsp-mint's `export-esp`
writes it and the service's wallet reads it with `Handover::read`, which refuses
a file with no notes or with a note that names no keyset (or an empty one). The file is pinned by a
test. **Whoever holds the file holds the notes**, because each comes with its
spend secret: keep it private and delete it once the wallet has taken the notes.

`psp::PspHandover` is the same kind of file for PSP: the paid PSP of a spend that
psp-mint reissues instead of burning, one file for each spend (`revenue/<request
hash>.json`). `HandedPspNote` is an amount, the note, its spend secret and the
keyset that signed it; `PspHandover::read` refuses a file with no notes or with a
note that names no keyset. The file is pinned by a test, and **whoever holds it
holds the notes**: the SPI's ecash-wallet swaps them for notes of its own with
`receive-psp`.

## wire_version

`WIRE_VERSION` is a single integer, currently 5. Every mint reports it as
`wire_version` in its mint info (see "The AIR request" below), and a wallet
refuses a mint whose number is not its own, or that reports none, with an error
that names both (`version::check`).

**Changing any encoded byte or JSON field of this crate means bumping
`WIRE_VERSION`.** The rule and what counts as a change are in
[DESIGN.md](DESIGN.md). Two tests enforce it:

- `tests/golden_psp.rs`, `golden_esp.rs` and `golden_fsp.rs` build every wire type
  from fixed keys and compare its JSON, its hash and its bytes with
  `tests/golden/*.txt`.
- `tests/sizes.rs` pins the size of each encoded type.

If one of them fails you changed the wire. If that was meant, bump
`WIRE_VERSION`, update the golden file in the same commit and say so in
[CHANGELOG.md](CHANGELOG.md), which also has the history of each version.

`tests/hashes.rs` is not a golden: it changes one field at a time of each request
hash and digest and checks that the value changes, so that no field is missing
from a key an answer is stored under. The tests of `seal` are at the bottom of
`src/seal.rs`, and `tests/air_ask.rs` runs `ask_mint_info` against a local
`air_server`.

## Features and dependencies

`seal` (off by default) adds `encrypt`, `decrypt` and `parse_public_key`, which
need AIR. The sealed format and its sizes are available without it.
`air-request` (off by default, implies `seal`) adds the pure parts of the read-only
requests over AIR (mint info, keys, keysets, rotation, rollover, check-state, and the ESP's fees, exchange, transfer and redeem), and `air-client` (implies `air-request`) adds its transport,
which needs `air_server` and `tokio`; see "The AIR request".

Dependencies are by git tag, so a clone builds the code that was tested:
`mint-types` at mint-core `v0.2.0`. With `seal`, AIR is pinned by commit
(`eae5133` on AIR's branch `air3-export-secretkey`: 3.0.0 plus the `SecretKey` export;
AIR's only tag is `v2.1.0`, on `741b1cf`). `air_server` (for `air-client`) is pinned by
commit too (`efef621`, its tag `v1.0.1`). AIR uses `secp256k1` 0.31 and this crate
0.30; see [DESIGN.md](DESIGN.md) for why that is safe. The crate needs rustc 1.93
or later.

**`SecretKey` comes from AIR's branch `air3-export-secretkey`.** AIR 3.0.0 (`ff41c09`)
does not export it; `eae5133` adds it next to `PublicKey` in `src/lib.rs`, and nothing
else. It is on GitHub, so `seal` builds from git with no patch. The branch is not
merged into AIR's `master`; when it is, the pin can move to the merged commit.

## The AIR request

`air_request` carries the calls between a wallet and a mint. They go over AIR
only (they were HTTP routes before; the wallet no longer calls them, and the
routes the mints dropped answer 404; `GET /health` stays on each mint for
operators): the wallet asks for **mint info** (kind 1, `MintInfo`: `status`,
`wire_version`, `network`; the same document `GET /health` gives an operator) or a PSP's **keys** (kind 2,
`keys::KeysResponse`), **keysets** (kind 3, `psp::KeysetsResponse`) or
**rotation** (kind 4, `keyset::RotationResponse`) or sends its **rollover** (kind
5, `psp::RolloverRequest`) or **check-state** (kind 6, `keys::CheckStateRequest`;
the first calls with a request body, the first that change state), and verifies a
reply the mint signed with its DID key. All six are one request envelope with a
kind byte (`KIND_MINT_INFO` 1, `KIND_KEYS` 2, `KIND_KEYSETS` 3, `KIND_ROTATION` 4,
`KIND_ROLLOVER` 5, `KIND_CHECK_STATE` 6), and the body of the reply is the JSON of
the response type of that kind; a mint that cannot answer now says so in a signed
reply (`STATUS_UNAVAILABLE`, no body), and one that refuses says so in a signed
reply with the refusal's JSON body (`STATUS_REFUSED`). The request's `body_len` is 4 bytes (it
was 2 until a rollover of 1000 notes, about half a megabyte, needed more; envelope
version 0 is kept, since nothing that uses it was released). The kinds and the
status are additive: no bump.

The ESP's wallet-facing calls use the same envelope. A kind names a call, not a
mint, so the ESP mint (its own DID) answers the kinds it serves in the shape of its
own response types: mint info 1, keysets 3, rotation 4 and rollover 5 are the PSP's
kinds, and the ESP adds `KIND_FEES` 7 (its fees and ceilings; formerly `GET /fees`),
`KIND_EXCHANGE` 8 (`esp::exchange::ExchangeRequest`), `KIND_TRANSFER` 9
(`esp::transfer::TransferRequest`) and `KIND_REDEEM` 10 (`esp::redeem::RedeemRequest`;
the redeem body is the canonical binary encoding, not JSON). The ESP has no keys
call, so it skips `KIND_KEYS`. The FSP mint's wallet-facing calls are the same
envelope again: its mint info, keys (`fsp::KeysResponse`), fees (`fsp::FeesResponse`)
and rotation are kinds 1, 2, 7 and 4, and it adds `KIND_FSP_ISSUE` 11
(`fsp::IssueRequest`) and `KIND_FSP_SPEND` 12 (`fsp::SpendRequest`), JSON bodies. The PSP mint adds `KIND_PSP_SPEND` 14 (a spend with
change: notes in, change out, an amount paid that the mint burns; JSON body,
`psp::PspSpendRequest`) and `KIND_PSP_CLAIM` 15 (the one claim of a purchase, for the
units an owed record says; JSON body, `psp::ClaimRequest`, signed by the purchase's
claim key over `digest(psp)`, which covers the PSP mint's DID; the PSP answers only a claim it accepts, see `Served::Ignored`).
The envelope does not read a body.
The design and the reasons for every choice are `air-sandbox/REQUEST-DESIGN.md` in
sandbox-mint; this module is that design. In short: the wallet writes a sealed
request into a numbered mailbox of the mint's DID (anyone can write a slot, only
the mint can open it), the mint answers in a reply cell only the wallet and the
mint can compute (`r.shared(mint) == mint.shared(R)`), and the reply carries the
mint's BIP340 signature, so an untrusted AIR server can withhold a reply but not
forge one. It rides `WIRE_VERSION` 5 (kinds 13 and 15 are the owed record and the purchase claim from version 4; version 5 added the key streams, below, and the key-set ID over every key; the rest is as in version 3).

- **Feature `air-request`** (implies `seal`): the pure parts. Envelopes
  (`envelope`), addresses, sealing and signature bytes (`addr`), `MintInfo`. No
  network. The two address labels are `sp-air-mailbox-v0` and
  `sp-air-reply-cell-v0`; the request hash is `sp-air-req-v0`; the reply digest is
  `sp-air-reply-sig-v0`. Every derivation and both envelopes are pinned by goldens
  computed independently with Python's `hashlib`, and tamper tests cover each
  check a wallet makes.
- **Feature `air-client`** (implies `air-request`; adds `air_server` and `tokio`):
  the thin transport (`client`: connect to a configured server name and host, raw
  `Create` and `Read`, held reads; no `orange_me` helper), the wallet's whole flow
  (`ask::ask` for any kind, which returns a `Verified` reply whose `json::<T>()`
  reads the body; `ask::ask_mint_info` for mint info, which also checks the wire
  version and network: read the reply cell first, write a request into the first
  free slot, wait, retry with the same `request_id` and `r`, verify), and
  `local_server`, an `air_server` started in the test process.
- **The key streams (`air_request::stream`, wire version 5).** How a mint
  publishes the public keys it signs with, so that a wallet can check every key
  in every reply against what every other user can see (finding P2-04: a mint
  that signs one user with keys it uses for that user alone could recognise that
  user's notes when they come back). Every record is one write-once cell of the
  mint's AIR service, at an address anyone can compute from the mint's DID and
  the cell's name (`cell_address`: the DID key plus `SHA-256("sp-stream-cell-v0"
  || DID || path)` times G) and only the mint can write (`cell_secret`). The
  records are plain (public keys; unsealed, unsigned: signed key sets are ROADMAP
  item 34) and deterministic, so a write repeated is `Written::AlreadyStored`.
  There are three: the **key set** (kind 1) of a PSP or FSP mint, the `n`th at
  `Cell::Keyset { index: n }` (`KeysetRecord`: epoch and every (amount, key); its
  `id()` is the shared `keyset_id`); the **control record** (kind 2) of an ESP mint
  (`ControlRecord`: the maturity rule `m` and its live generations, 47 bytes); and
  the ESP's **day record** (kind 3, `DayRecord`: for one generation and one day,
  the 64 keys of each service, 2,145 bytes a service). A day is one record while
  it fits `RECORD_MAX_BYTES` or the size the operator set; past it the services
  are grouped into buckets of `BUCKET_SERVICES` (256) by `bucket_of`, a hash of the
  service DID, and a wallet reads its service's bucket. A connection that keeps
  reading the same few buckets can still be recognised, less precisely. With
  `air-client`: `write_cell`, `read_cell`, `find_end` (about 2 log2 n reads),
  `read_keyset_tail`, `read_keysets_from` and `publish_keysets`/`KeysetPublisher`
  (a restart, a crash between two writes or an unacknowledged write is repaired
  by the next call). Every address, tweak, size and record is pinned by goldens
  computed independently in Python.
- **The owed record (`air_request::delivery`).** The one call that goes the other
  way: the PSP writes, the wallet reads. The payment carries a throwaway claim key
  (`payload`, 33 bytes, sealed to the PSP). At the confirmation tier its locked USD
  value sets, the PSP writes **one record** to the SPI's AIR server saying what it
  owes (`Owed`: the `txid`, what was paid, the PSP's live keysets and the
  `ClaimTerms`), signed by its DID key and sealed to the claim DID. A claim key may
  pay more than once, so the `n`th record (from 0, in the order written) is at
  `sha256("sp-psp-owed-v0" || PSP DID || claim DID || u32 n)` (`owed_address`,
  `owed_secret`) and the claim names it by `record_id`, `sha256("sp-psp-owed-id-v0"
  || claim DID || u32 n)`; the wallet reads from 0 until a cell is empty.
  Only the wallet and the PSP can compute an address, and the cell is write-once.
  `build_record` makes the sealed record and `open_record` checks it (the PSP's
  signature, that it answers this record id and this claim DID; no freshness limit,
  since it may be read days later). With `air-client`, `write_record` (`Created`,
  `AlreadyStored` or `Different`: a write to a taken cell is answered as a read, so
  an unacknowledged write that got through is found stored), `read_record` and
  `read_records` (every address once, then the missing ones held together under one
  deadline). `KIND_PSP_DELIVERY` (13) is a hash domain only and is never served. See
  `air-sandbox/REQUEST-DESIGN.md` section 18.
  **The owed record states the terms.** `ClaimTerms`: `send` (`purchase_claim`),
  `kind` 15, the exact `due_units` the claim's outputs must add up to (the units the
  payment buys at the locked price, less the prepaid read and write costs, floored at
  0), `read_prepaid_units` and `write_prepaid_units`, `window_secs`
  (`psp::CLAIM_WINDOW_SECS`, 30 days: a constant, not a setting, counted from when
  the record is stored on AIR), `max_attempts`, and `on_expiry` (`EXPIRY_NOTICE`: if
  the purchase is not claimed within `window_secs` of the record being stored, the
  PSP keeps the payment; a refused claim gets no reply). A wallet claims as soon as
  it reads the record and keeps the claim key at least until its first read plus
  `window_secs`. The record carries no keysets: the wallet asks kind 4 for the
  current keyset before it claims, and a claim must name that one. The terms are a fallback for a
  fallback: ecash-wallet claims automatically, checks its claim against them before
  sending, and should never fail. They are written out for a developer or user who
  buys PSP with nonstandard, self-built tooling, as one last chance to get it right
  before the funds are lost. They are those in force when the record was written.
- **Port 5702.** The AIR client always dials 5702 for `ws` (upstream item 12), so a
  test server cannot take a free port: `local_server::start` needs it free and says
  so when it is not. Test binaries run one after another, so each finds it free.
- **One `air` for `air-client`.** `air_server` 1.0.1 takes `air` 3.0.0 from crates.io.
  The `[patch.crates-io]` in `Cargo.toml` points it at the AIR this crate pins, or two
  `air` crates are built and their types do not match. A crate that depends on sp-wire
  with `air-client` needs the same block in its own `Cargo.toml`:

```toml
[patch.crates-io]
air = { git = "https://github.com/ramp-stack/air", rev = "eae5133414fca493fa80ab3facf28248df9ad65d" }
```

## Build and test

    cargo test --all-features
    cargo fmt --check

`--all-features` includes `air-client`, so it needs
port 5702 free (see "The AIR request"). Without them, test the other features by
name, for example `cargo test --features seal`.

To build against local folders, put this in `.cargo/config.toml` in this folder
(it is git-ignored), or uncomment the same block at the bottom of `Cargo.toml`
and do not commit it:

```toml
[patch."https://github.com/dav-anderson/mint-core.git"]
mint-types = { path = "/path/to/mint-core-v0.2.0/crates/mint-types" }
```

The top-level README in `sandbox-mint` has the recipe across all repos and the
`local-git.sh` script, which is the simpler way to test against unpushed tags.

## Links

- [CHANGELOG.md](CHANGELOG.md): what changed in each version.
- [DESIGN.md](DESIGN.md): the rules behind the wire version and the seal.
- [../sandbox-mint/README.md](../sandbox-mint/README.md): the family of repos.

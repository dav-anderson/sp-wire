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
| `units` | `ESP_PER_PSP` (10^11), `ESP_PER_USD` (10^12), `MAX_PSP_PER_NOTE`, `MAX_PSP_DENOMINATION` (2^24, the default top note; a PSP's own top is the highest key in its `GET /keys`), the PSP-to-ESP conversions |
| `keyset` | the key-set ID (8 bytes, 16 hex characters), the PSP's `keyset_id`, `KeysetWindow`, `RotationResponse` (`GET /rotation`) |
| `payload` | the PSP OP_RETURN payload: `Payload`, `encode`, `decode`, `DID_LEN` (33) |
| `seal` | the sealed payload's format (a constant 80 bytes of overhead: the 64-byte sender key and the 16-byte tag) and, with the `seal` feature, `encrypt`, `decrypt`, `parse_public_key` |
| `psp` | `PspMeltRequest`, `Burn*`, `KeysetsResponse`, `RolloverRequest`/`Response`, `PspSpendRequest`/`Response` |
| `esp` | `exchange`, `transfer`, `redeem` (the binary request and its reply), `rollover`, `queue` views, `terms`, `hash_keysets` |
| `fsp` | `IssueRequest`/`Response`, `SpendRequest`/`Response`, `KeysResponse`, `FeesResponse`, `Refusal` |
| `codes` | the `code` of an error body: `keyset_retired`, `unknown_keyset`, `keyset_not_current` (reserved: no mint sends it), `burn_not_proven`, `note_spent_elsewhere`, ... |
| `dec` | a `u128` as a decimal string in JSON |
| `service` | `ServiceDid`, a service's ID: its 33-byte AIR DID (a compressed key, 66 hex characters), the one type and parser every mint and the wallet use for it |
| `version` | `WIRE_VERSION` and `check_health`, the check a wallet makes |
| `air_request` | the requests over AIR, mint info, a PSP's keys, keysets and rotation, its rollover and check-state, and the PSP's delivery of a purchase (feature `air-request`; the transport is `air-client`): envelopes, mailbox and reply-cell addresses, request hash, reply digest, sign and verify, `MintInfo`; with `air-client` also the thin AIR client, the wallet's whole flow (`ask`) and a local `air_server` for tests. See "The AIR request" below |
| `storage` | not wire: the storage policy (an ordered list of service DIDs per kind of data, index 0 primary), its parser and its checks, shared by the three mints and the wallet. Config only; it reads and writes nothing |

The note, nonce, blinded output and mint input/output types are mint-core's
(`mint_types`). sp-wire depends on that crate at its release tag and re-exports
the types, so there is one definition of them. It does not depend on `mint-core`
or `mint-server`.

The request hashes (`request_hash`, `hash`, `digest`) live here with the types
they cover: they are part of the wire, because a retry gets its stored answer by
hash.

## wire_version

`WIRE_VERSION` is a single integer, currently 3. Every mint's `GET /health`
returns it as `wire_version`, and a wallet refuses a mint whose number is not its
own, with an error that names both (`version::check_health`).

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

## Features and dependencies

`seal` (off by default) adds `encrypt`, `decrypt` and `parse_public_key`, which
need AIR. The sealed format and its sizes are available without it.
`air-request` (off by default, implies `seal`) adds the pure parts of the read-only
requests over AIR (mint info, keys, keysets, rotation, rollover, check-state, and the ESP's fees, exchange, transfer and redeem), and `air-client` (implies `air-request`) adds its transport,
which needs `air_server` and `tokio`; see "The AIR request".

Dependencies are by git tag, so a clone builds the code that was tested:
`mint-types` at mint-core `v0.1.3`. With `seal`, AIR is pinned by commit
(`ff41c09`, 3.0.0; AIR's only tag is `v2.1.0`, on `741b1cf`, and 3.0.0 has none). `air_server`
(for `air-client`) is pinned by commit too (`ec6ac1f`, 1.0.0; its only tag is `v0.1.0`). AIR uses `secp256k1` 0.31 and this crate
0.30; see [DESIGN.md](DESIGN.md) for why that is safe. The crate needs rustc 1.93
or later.

**AIR 3.0.0 does not export `SecretKey`, so `seal` does not build from `ff41c09`
alone.** The fix is one word in AIR's `src/lib.rs` (`SecretKey` next to
`PublicKey` in the `pub use names::secp256k1::{...}` line), made on the branch
`air3-export-secretkey` (3.0.0 plus that commit) of a local AIR checkout and not yet in upstream. Until it is, put
this in `.cargo/config.toml` in this folder (git-ignored; never commit it), with the
path of that checkout:

```toml
[patch."https://github.com/ramp-stack/air"]
air = { path = "/Users/you/air" }
```

When upstream has merged the export, the final pin is that merged commit: the
`rev` in `Cargo.toml` moves to it and the patch is no longer needed.

## The AIR request

`air_request` carries the calls between a wallet and a mint that do not go over
HTTP: the wallet asks for **mint info** (what `GET /health` reports: `status`,
`wire_version`, `network`) or a PSP's **keys**, **keysets** or **rotation** (what
`GET /keys`, `/keysets` and `/rotation` return) or sends its **rollover** or
**check-state** (`POST /rollover`, `/check-state`: the first calls with a request
body, the first that change state), and verifies a reply the mint signed with its
DID key. All six are one request envelope with a kind byte (`KIND_MINT_INFO` 1,
`KIND_KEYS` 2, `KIND_KEYSETS` 3, `KIND_ROTATION` 4, `KIND_ROLLOVER` 5,
`KIND_CHECK_STATE` 6), and the body of the reply is the exact JSON the HTTP route
returns; a mint that cannot answer now says so in a signed reply
(`STATUS_UNAVAILABLE`, no body), and one that refuses says so in a signed reply
with the HTTP `4xx` body (`STATUS_REFUSED`). The request's `body_len` is 4 bytes (it
was 2 until a rollover of 1000 notes, about half a megabyte, needed more; envelope
version 0 is kept, since nothing that uses it was released). The kinds and the
status are additive: no bump.

The ESP's wallet-facing calls use the same envelope. A kind names a call, not a
mint, so the ESP mint (its own DID) answers the kinds it serves in the shape its own
routes return: mint info 1, keysets 3, rotation 4 and rollover 5 are the PSP's
kinds, and the ESP adds `KIND_FEES` 7 (`GET /fees`), `KIND_EXCHANGE` 8,
`KIND_TRANSFER` 9 and `KIND_REDEEM` 10 (`POST /exchange`, `/transfer`, `/redeem`;
the redeem body is the canonical binary encoding, not JSON). The ESP has no keys
route, so it skips `KIND_KEYS`. The FSP mint's wallet-facing calls are the same
envelope again: its `GET /health`, `/keys`, `/fees` and `/rotation` are kinds 1, 2, 7
and 4, and it adds `KIND_FSP_ISSUE` 11 (`POST /issue`) and `KIND_FSP_SPEND` 12
(`POST /spend`), JSON bodies. The PSP mint adds `KIND_PSP_SPEND` 14 (a spend with
change: notes in, change out, an amount paid that the mint burns; JSON body,
`psp::PspSpendRequest`). The envelope does not read a body.
The design and the reasons for every choice are `air-sandbox/REQUEST-DESIGN.md` in
sandbox-mint; this module is that design. In short: the wallet writes a sealed
request into a numbered mailbox of the mint's DID (anyone can write a slot, only
the mint can open it), the mint answers in a reply cell only the wallet and the
mint can compute (`r.shared(mint) == mint.shared(R)`), and the reply carries the
mint's BIP340 signature, so an untrusted AIR server can withhold a reply but not
forge one. It rides `WIRE_VERSION` 3, with no bump.

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
- **The delivery of a purchase (`air_request::delivery`).** The one call that goes
  the other way: the PSP writes, the wallet reads. After it settles a payment the
  PSP writes **one record** to the SPI's AIR server holding the purchase's
  signatures and the PSP's live keysets, or that it holds the payment (`Held`), or
  the reason it rejected the purchase (`Refused`), the last two with what it
  received and until when it keeps the payment open (`open_until`), signed by
  its DID key and sealed to the purchase's one-off reply DID. The address is
  `sha256("sp-air-delivery-v0" || PSP DID || reply DID || purchase)`, where
  `purchase = sha256("sp-psp-purchase-v0" || the unsealed payload)` (`purchase_id`,
  `delivery_address`, `delivery_secret`); only the wallet and the PSP can compute
  it, and the cell is write-once. `build_record` makes the sealed record and
  `open_record` checks it (the PSP's signature, that it answers this purchase and
  this reply DID; no freshness limit, since it may be read days later). With
  `air-client`, `write_record` (`Created`, `AlreadyStored` or `Different`: a write to
  a taken cell is answered as a read, so an unacknowledged write that got through
  is found stored), `read_record` and `read_records` (every address once, then the
  missing ones held together under one deadline). `KIND_PSP_DELIVERY` (13) is a hash
  domain only and is never served. See `air-sandbox/REQUEST-DESIGN.md` section 18.
- **Port 5702.** The AIR client always dials 5702 for `ws` (upstream item 12), so a
  test server cannot take a free port: `local_server::start` needs it free and says
  so when it is not. Test binaries run one after another, so each finds it free.
- **`air-client` needs two local patches** while `air_server` names AIR as
  `path = "../air"` (upstream issue 3 in FINDINGS): AIR and `air_server` must be
  checkouts beside each other, and the AIR patch path must be the folder
  `<air_server>/../air`, or two `air` crates are built and their types do not match:

```toml
[patch."https://github.com/ramp-stack/air"]
air = { path = "/Users/you/sandbox-mint/air-sandbox/air" }
[patch."https://github.com/ramp-stack/air_server"]
air_server = { path = "/Users/you/sandbox-mint/air-sandbox/air_server" }
```

## Build and test

    cargo test --all-features
    cargo fmt --check

`--all-features` includes `air-client`, so it needs the two patches above and
port 5702 free (see "The AIR request"). Without them, test the other features by
name, for example `cargo test --features seal`.

To build against local folders, put this in `.cargo/config.toml` in this folder
(it is git-ignored), or uncomment the same block at the bottom of `Cargo.toml`
and do not commit it:

```toml
[patch."https://github.com/dav-anderson/mint-core.git"]
mint-types = { path = "/Users/you/mint-core-v0.1.3/crates/mint-types" }
```

(The AIR patch above goes in the same file for as long as it is needed.)

The top-level README in `sandbox-mint` has the recipe across all repos and the
`local-git.sh` script, which is the simpler way to test against unpushed tags.

## Links

- [CHANGELOG.md](CHANGELOG.md): what changed in each version.
- [DESIGN.md](DESIGN.md): the rules behind the wire version and the seal.
- [../sandbox-mint/README.md](../sandbox-mint/README.md): the family of repos.

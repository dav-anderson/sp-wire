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
| `psp` | `PspMeltRequest`, `Burn*`, `KeysetsResponse`, `RolloverRequest`/`Response` |
| `esp` | `exchange`, `transfer`, `redeem` (the binary request and its reply), `rollover`, `queue` views, `terms`, `hash_keysets` |
| `fsp` | `IssueRequest`/`Response`, `SpendRequest`/`Response`, `KeysResponse`, `FeesResponse`, `Refusal` |
| `codes` | the `code` of an error body: `keyset_retired`, `unknown_keyset`, `keyset_not_current` (reserved: no mint sends it), `burn_not_proven`, `note_spent_elsewhere`, ... |
| `dec` | a `u128` as a decimal string in JSON |
| `service` | `ServiceDid`, a service's ID: its 33-byte AIR DID (a compressed key, 66 hex characters), the one type and parser every mint and the wallet use for it |
| `version` | `WIRE_VERSION` and `check_health`, the check a wallet makes |
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

Dependencies are by git tag, so a clone builds the code that was tested:
`mint-types` at mint-core `v0.1.3`. With `seal`, AIR is pinned by commit
(`741b1cf`, 2.1.0; AIR has no tags). AIR uses `secp256k1` 0.31 and this crate
0.30; see [DESIGN.md](DESIGN.md) for why that is safe. The crate needs rustc 1.93
or later.

**AIR 2.1.0 does not export `SecretKey`, so `seal` does not build from `741b1cf`
alone.** The fix is one word in AIR's `src/lib.rs` (`SecretKey` next to
`PublicKey` in the `pub use names::secp256k1::{...}` line), made on the branch
`export-secretkey` of a local AIR checkout and not yet in upstream. Until it is, put
this in `.cargo/config.toml` in this folder (git-ignored; never commit it), with the
path of that checkout:

```toml
[patch."https://github.com/ramp-stack/air"]
air = { path = "/Users/you/air" }
```

When upstream has merged the export, the final pin is that merged commit: the
`rev` in `Cargo.toml` moves to it and the patch is no longer needed.

## Build and test

    cargo test --all-features
    cargo fmt --check

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

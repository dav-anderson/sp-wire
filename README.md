# sp-wire

Everything the Service Points mints and wallets exchange: the types, their
encodings and the constants. `psp-mint`, `esp-mint`, `fsp-mint` and
`ecash-wallet` all build against this one crate, so a mint and a wallet cannot
disagree about a byte.

This is the wire only. It has no storage, no HTTP server, no settlement logic and
no config, and its dependencies are small (`mint-types`, `secp256k1`, `serde`,
`sha2`, `hex`). A wallet app can use it without pulling in any mint code.

## Layout

| Module | Holds |
| --- | --- |
| `units` | `ESP_PER_PSP` (10^11), `ESP_PER_USD` (10^12), `MAX_PSP_PER_NOTE`, `MAX_PSP_DENOMINATION` (2^24), the PSP-to-ESP conversions |
| `keyset` | the key-set ID (8 bytes, 16 hex characters), the PSP's `keyset_id`, `KeysetWindow`, `RotationResponse` (`GET /rotation`) |
| `payload` | the PSP OP_RETURN payload: `Payload`, `encode`, `decode`, `DID_LEN` (33) |
| `seal` | the sealed payload's format (82 or 83 bytes of overhead) and, with the `seal` feature, `encrypt`, `decrypt`, `parse_public_key` |
| `psp` | `PspMeltRequest`, `Burn*`, `KeysetsResponse`, `RolloverRequest`/`Response` |
| `esp` | `exchange`, `transfer`, `redeem` (the binary request and its reply), `rollover`, `queue` views, `terms`, `hash_keysets` |
| `fsp` | `IssueRequest`/`Response`, `SpendRequest`/`Response`, `KeysResponse`, `FeesResponse`, `Refusal` |
| `codes` | the `code` of an error body: `keyset_retired`, `unknown_keyset`, `keyset_not_current`, `burn_not_proven`, `note_spent_elsewhere`, ... |
| `dec` | a `u128` as a decimal string in JSON |
| `version` | `WIRE_VERSION` and `check_health`, the check a wallet makes |

The note, nonce, blinded output and mint input/output types are mint-core's
(`mint_types`). sp-wire depends on that crate at its release tag and re-exports
the types, so there is one definition of them. It does not depend on `mint-core`
or `mint-server`.

The request hashes (`request_hash`, `hash`, `digest`) live here with the types
they cover: they are part of the wire, because a retry gets its stored answer by
hash.

## wire_version

`WIRE_VERSION` is a single integer, 1 to start. Every mint's `GET /health` returns
it as `wire_version`, and a wallet refuses a mint whose number is not its own,
with an error that names both (`version::check_health`).

**Changing any encoded byte or JSON field of this crate means bumping
`WIRE_VERSION`.** That covers a new, renamed or reordered field, a changed tag
in a hash (`esp-mint/redeem/v2`, ...), a changed size constant, a changed unit
and a changed error code. A new optional field a reader can ignore still counts:
an older wallet would sign over a different request than the mint hashes.

Two tests keep this honest.

- `tests/golden_psp.rs`, `golden_esp.rs` and `golden_fsp.rs` build every wire type
  from fixed keys and compare its JSON, its hash and its bytes with
  `tests/golden/*.txt`, which were captured from the v0.1.0 mints before this crate
  existed.
- `tests/sizes.rs` pins the size of each encoded type (payload 35 + 41 per
  output, redeem 119 + 186 per input + 81 per output + the memo, the FSP issue
  group 16 + 106 per note + 41 per output, and so on).

If one of them fails you changed the wire. If that was meant, bump
`WIRE_VERSION`, update the golden file in the same commit and say so in the
changelog.

## Features

`seal` (off by default) adds `encrypt`, `decrypt` and `parse_public_key`, which
need AIR. The sealed format and its sizes are available without it.

## Dependencies and local work

Dependencies are by git tag, so a clone builds the code that was tested:
`mint-types` at mint-core `v0.1.3`. AIR has no tags, so it is pinned by commit
(`6dd0117`, 1.1.0).

AIR's own manifest names `../substance` by path, which a build from a git checkout
cannot find. Until that changes upstream, anything that enables `seal` needs the
local `[patch]` below. See the top-level README in `sandbox-mint` for the same
recipe across all repos.

To build against local folders, put this in `.cargo/config.toml` in this folder
(it is git-ignored), or uncomment the same block at the bottom of `Cargo.toml`
and do not commit it:

```toml
[patch."https://github.com/dav-anderson/mint-core.git"]
mint-types = { path = "/Users/you/mint-core-v0.1.3/crates/mint-types" }
[patch."https://github.com/ramp-stack/air"]
air = { path = "/Users/you/air" }
```

Run the tests with every feature:

    cargo test --all-features

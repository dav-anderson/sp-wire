# Changelog

## 0.1.0

First release. The wire types the mints and the wallet shared by copying are now
one crate: units, key-set ID, PSP payload and seal format, the PSP, ESP and FSP
request and response bodies, the request hashes, and the error codes.

- `WIRE_VERSION` is 1.
- No encoded byte changed from the mints' v0.1.0 (pinned by `tests/golden/`).

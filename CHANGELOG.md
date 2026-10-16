# Changelog

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

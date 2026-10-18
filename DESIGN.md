# sp-wire: design notes

## What goes here and what does not

This crate holds types, encodings and constants only. It has no storage, no HTTP
server, no settlement logic and no config files, so a wallet app can use it without
pulling in any mint code.

The one exception is `storage`, the type and parser of the storage policy (an
ordered list of service IDs for each kind of data; index 0 is the primary). It is
here because the three mints and the wallet must read and refuse a service list in
exactly the same way, and sp-wire is the one crate all four already depend on
(mint-core is not ours to change). It is not wire: no byte of it travels, it does
no I/O, and it does not affect `WIRE_VERSION`. It is a parser and a validator
and nothing more; what a policy will do (replication, promotion, sequence numbers)
is for the mints and the wallet to build on this type: copies kept on a primary and at least one secondary, only the mint promoting a secondary, sequence numbers on writes. None of it is here. If it grows
beyond that, it should move out of this crate. The note, nonce, blinded output and mint input/output
types are mint-core's (`mint_types`); sp-wire depends on that crate at its
release tag and re-exports them, so there is one definition. It does not depend
on `mint-core` or `mint-server`.

The request hashes (`request_hash`, `hash`, `digest`) live here with the types they
cover. They are part of the wire, because a retry gets its stored answer by hash.

## The wire version

`WIRE_VERSION` is bumped for any change to an encoded byte or a JSON field. That
covers a new, renamed or reordered field, a changed tag in a hash
(`esp-mint/redeem/v2`, ...), a changed size constant, a changed unit and a changed
error code. A new optional field a reader can ignore still counts: an older
wallet would sign over a different request than the mint hashes.

The goldens in `tests/golden/*.txt` were captured from the v0.1.0 mints before
this crate existed, so that moving the types out of the mints provably changed no
byte. They are the specification. The only lines that have moved since are the
sealed-payload ones (wire version 2, below).

## The seal and AIR

The PSP payload is encrypted to the mint's DID public key with AIR's public key
encryption, so nothing in it is visible on chain. The format is AIR's, not ours:
`64-byte ElligatorSwift sender key || 16-byte tag || ciphertext`, a constant 80
bytes of overhead whatever the payload length. Anything under 81 bytes cannot be a
sealed payload, and an empty plaintext cannot be sealed (AIR cannot open a
message with no bytes in it).

AIR 1.1.0 returned an `Encrypted(Init, Message)` struct that was stored as its
`postcard` encoding (82 or 83 bytes of overhead). AIR 2.0.3 returns raw bytes. A
version 1 sealed payload does not open under version 2, and the other way round,
which is why the change is a wire version and not a patch. Nothing else moved.

AIR 2.1.0 (sp-wire 0.4.1) changed no byte of this: the encrypt and decrypt code
and the format are the same as in 2.0.3, so `WIRE_VERSION` stays 2 and the
decrypt-only golden (a fixed sealed blob, its secret key as JSON and the public key
as hex) opens as it did. What changed is where the types are: AIR's `names`
module is private, and `PublicKey` is exported from the crate root while
`SecretKey` is not. `seal` needs `SecretKey` (to open a payload, and to read the
mint's `mint_did_key.json`), and it is the same type psp-mint and the wallet use
through `sp_wire::seal`. A stand-in type would have been a different public type
with its own key-file reader, so it was not written; the export is a one-word
change in AIR (`SecretKey` next to `PublicKey` in `src/lib.rs`), made on a local
branch of AIR and to be proposed upstream. Until it is merged the build needs a
local patch (README), and the pin then moves to the merged commit.

`PublicKey` Display and FromStr are the 33-byte compressed hex (66 characters),
the same as the DID, so the published mint key and the DID in the payload did not
change. The byte-array and serde forms of AIR's public key are the 64-byte
ElligatorSwift form; sp-wire uses only Display, FromStr and `SecretKey`'s serde
(a 32-byte hex string), so existing `mint_did_key.json` files still load.

AIR (2.0.3 and 2.1.0) uses `secp256k1` 0.31 and this crate (like mint-core) uses
0.30. The two versions sit side by side and no type crosses between them: the DID
keys are AIR's own types, and the rest of the wire is `secp256k1` 0.30. AIR 2.0.3
needed its default feature `stream` to stay on; 2.1.0 has no such feature.

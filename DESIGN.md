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
sealed-payload ones (wire version 2, below) and the ones that carry a service ID
(wire version 3, below).

## The service ID (wire version 3)

A service ID is the 33-byte compressed AIR DID of the service, 66 hex characters
starting `02` or `03`: `service::ServiceDid`. It is the one type for it. Through
wire version 2 it was the 32-byte x-only key (64 hex characters), which loses the
parity byte; the DID of an AIR service has it, and the AIR name of a service is
that DID, so the ID is now the DID and nothing is reduced.

- **Where it appears.** In ESP terms (`Terms`, 41 bytes: the DID and the
  redeemable-after day), in the ESP exchange, transfer, rollover and redeem
  requests and replies, in the redeem encoding (`FORMAT_VERSION` 3), in the FSP
  issue request and the `GET /keys` reply, and in the storage policy lists. Every
  hash and digest that covers a service covers its 33 bytes. The domain-separation
  tags (`esp-mint/transfer/v1`, ...) are unchanged.
- **The parity byte is part of the ID.** `02<x>` and `03<x>` are two different
  IDs that share one x-only key. Both parse, and a mint holding one refuses the
  other as a wrong service.
- **Signing.** A BIP340 signature is made and checked against the x-only key,
  which is `ServiceDid::x_only()`. That conversion stays in the signing code and is
  never an ID.
- **No migration.** There is no dual format. A 64-character (x-only) ID is
  refused with a message that says so (`DidError::XOnly`), a version 2 redeem
  request is refused with its own message, and `check_health` refuses a mint on
  another wire version.
- **Sizes.** A redeem request grows by one byte per service in it: fixed part 119 to
  120, input 186 to 187, output 81 to 82. The fees are 0 in the family today, so no
  amount changes; the fee-sized length does, by those bytes.

## The AIR request (mint info)

`air_request` carries one read-only question from a wallet to a mint over AIR and
the mint's signed answer. The long form, with the alternatives that were rejected
and the prototype's run, is `air-sandbox/REQUEST-DESIGN.md` in sandbox-mint; what
matters for this crate:

- **Why a mailbox and a reply cell.** AIR's `Read` needs the exact key and its
  `Create` must be signed by the cell's secret. A cell derived from the mint's
  public key cannot be written by a wallet, and the mint cannot guess a
  wallet-chosen id. So the request goes into a numbered mailbox whose secrets
  anyone can compute (`sha256("sp-air-mailbox-v0" || mint DID || slot)`), and the
  reply into a cell only the two can compute (`sha256("sp-air-reply-cell-v0" ||
  shared || request_id || index)`, where `shared` is AIR's
  `r.shared(mint_pub, None)`, the same value the mint gets from `R`).
- **Write-once is the idempotence record.** The mint `Create`s the reply first and
  treats a stored record coming back as "already answered"; no read-then-write, so
  a retry that reached the mint twice or two mint processes end with one reply.
- **Sign bytes, ship bytes.** The reply's signed bytes are the reply up to its
  signature; the verifier never re-serialises. The digest is
  `sha256("sp-air-reply-sig-v0" || signed bytes)` and the signature is
  `SecretKey::sign(Id::from(digest))`, a BIP340 signature under the mint's bare DID
  key, so a saved reply (the receipt) verifies from the 33-byte DID alone.
- **Two labels, not one.** The reply cell and the reply digest first shared the
  label `sp-air-reply-v0`; they are two labels now (REQUEST-DESIGN.md F5), so the
  same bytes can never be both an address and a digest input.
- **Test DID.** The goldens use the secp256k1 generator as the mint DID. The
  prototype's `02` plus repeated bytes is probably not a curve point, which
  `ServiceDid` refuses.
- **Why the wallet's flow is here.** `ask::ask_mint_info` is the whole wallet side
  (it keeps `request_id` and `r` through a `save` callback before the first write,
  reads the reply cell before writing, retries with the same pair, verifies). It
  lives in this crate so that the wallet and the mints' integration tests run the
  same code.
- **No bump.** Nothing here is older than wire version 3. The envelope has its
  own version byte (0), and the `-v0` in each label moves every address or digest
  if a derivation changes.
- **Crates.** AIR uses `secp256k1` 0.31 and this crate 0.30; no type crosses
  (keys travel as bytes or AIR's text form), as for the seal.

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

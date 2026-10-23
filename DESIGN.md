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
is for the mints and the wallet to build on this type: a spend fsynced to the mint's local copy before it answers, then copied to the backups in batches that the mint never waits on, sequence numbers on writes. None of it is here. If it grows
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
sealed-payload ones (wire version 2, below), the ones that carry a service ID
(wire version 3, below) and the two request hashes that gained the note
signatures (`SpendRequest_hash` and `transfer_request_hash`, below). Those two
were recomputed independently with Python's `hashlib`, which first reproduced the
old values from the same inputs.

## The note signature in two request hashes

A request hash is the key an answer is stored under, and its doc says it covers
every signature. Two did not cover each input's note signature (the mint's own
signature on the note's nonce): `fsp::SpendRequest::hash` and
`esp::transfer::request_hash`. The digests leave it out on purpose (they are what
the spend signatures sign), so a request that differed only in a note's signature
had the same hash as the genuine one, and could be answered with the other's
stored answer, which might be a refusal. Both hashes now add every input's note
signature after the spend signatures, and their tags moved to
`fsp-mint/spend-request/v3` and `esp-mint/transfer-request/v3`, so a hash stored
under the old rule is never taken for one under the new. Every other request hash
already covered it. `WIRE_VERSION` stays 3: version 3 is not released.

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
  request is refused with its own message, and `version::check` refuses a mint on
  another wire version.
- **Sizes.** A redeem request grows by one byte per service in it: fixed part 119 to
  120, input 186 to 187, output 81 to 82. The fees are 0 in the family today, so no
  amount changes; the fee-sized length does, by those bytes.

## The AIR request (mint info, keys, keysets, rotation, rollover, check-state)

`air_request` carries one question from a wallet to a mint over AIR and the
mint's signed answer. The first four are reads; rollover and check-state (kinds 5
and 6) carry a request body, and rollover changes the mint's state (see the last
items of this list). The long form, with the alternatives that were rejected
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
- **One envelope, a kind byte.** Mint info, keys, keysets and rotation are one
  request envelope with a kind (`KIND_*`), not a type each: the kind is in the
  request hash, so a reply to one question is not an answer to another with the
  same id and key. The mint's side is `answer_request(key, sealed, now, serve)`,
  where `serve` maps a kind to a body or to "cannot answer now" (or to `None`, an
  unknown kind, which is skipped); `answer_mint_info` is the mint-info-only case.
  The wallet's side is `ask::ask`, which checks everything that does not depend on
  the question (`verify_answer`: mint, signature, request id and hash, status,
  age) and leaves the body to the caller. This is additive, so no `WIRE_VERSION`
  bump and no new envelope version: a mint that does not know a kind skips it, and
  the wallet waits out its tries.
- **The body is the response type's JSON.** The reply body for keys, keysets and
  rotation is the JSON of the response type of that kind (the routes they were once
  served on are gone), built by the same function in the mint, so the wallet reads
  it with the types it already uses. The signature covers those bytes.
- **Unavailable is signed.** A mint that understood the question and cannot answer
  (its lock is poisoned, a rotation step failed: the HTTP route would be a 500)
  signs a reply with `STATUS_UNAVAILABLE` and no body, so the wallet fails at once
  with the reason instead of waiting out `attempts` tries of `reply_wait_secs`. It
  is a status, not a body, because a body would have to be parsed as one of the
  types.
- **Why the wallet's flow is here.** `ask::ask` is the whole wallet side
  (it keeps `request_id` and `r` through a `save` callback before the first write,
  reads the reply cell before writing, retries with the same pair, verifies). It
  lives in this crate so that the wallet and the mints' integration tests run the
  same code.
- **No bump.** Nothing here is older than wire version 3. The envelope has its
  own version byte (0), and the `-v0` in each label moves every address or digest
  if a derivation changes.
- **Crates.** AIR uses `secp256k1` 0.31 and this crate 0.30; no type crosses
  (keys travel as bytes or AIR's text form), as for the seal.
- **A request body, and a 4-byte length (rollover, check-state).** `WireRequest` has
  always had a `body`; `body_len` was two bytes, which cannot carry a rollover of
  1000 notes (about 0.4 to 0.5 MB of JSON). It is a `u32` now, in place: envelope
  version 0 is kept and `WIRE_VERSION` does not move, because no release uses v0.
  The fixed part of a request is 71 bytes (151 sealed), the request hash covers the
  4-byte length, and the goldens (five request hashes and the reply digest) were
  recomputed with Python's `hashlib`, with a new golden for a request with a body.
  The envelope sets no ceiling of its own: the ceiling is the mint's setting
  (`server.rollover_bytes`, `server.check_state_bytes`, 1 MiB by default), applied
  to the body before it is parsed; the transport's limit is 16 MiB.
- **A refusal is signed.** `STATUS_REFUSED` (2) is a reply to a request the mint
  understood and refuses (the HTTP `4xx`); its body is the JSON the HTTP route would
  answer with. It passes `verify_answer` like an answer (mint, signature, id, hash,
  age), so it is also a receipt; `Verified::refused()` says which it is, and
  `ask_mint_info` treats it as an error. `serve` (`answer_request`) now gets the body
  too, and returns `Served::Refused(body)` beside `Body` and `Unavailable`. Any other
  status is still an error.
- **Idempotency is the mint's, not the envelope's.** A resent request has the same
  id, key, body and hash, and the reply cell is write-once, so the first reply stays;
  what makes a second delivery harmless for rollover is that the mint answers a
  body it has already answered from its store (REQUEST-DESIGN.md section 15). The
  wallet's `InFlight` carries the body (`InFlight::with_body`), fixed for the life
  of the request, so every retry has the same hash.

- **The FSP's calls are two more kinds (11 and 12).** `KIND_FSP_ISSUE` (11, `POST
  /issue`) and `KIND_FSP_SPEND` (12, `POST /spend`) are constants and nothing else, as
  for the ESP's. The FSP's reads are the kinds that already exist: `GET /health`,
  `/keys`, `/fees` and `/rotation` are 1, 2, 7 and 4, and the DID asked (the service's)
  decides whose reply it is. No `WIRE_VERSION` bump.

- **The PSP's spend is kind 14.** `KIND_PSP_SPEND` (14, a spend with change at the PSP
  mint) is a constant, as 11 and 12 are, and its body is `psp::PspSpendRequest` JSON.
  The request is fsp-mint's spend (`fsp::SpendRequest`) in a PSP rollover's shape: each
  input names its keyset (`input_keysets`, as `RolloverRequest` does), and the change is
  signed by the one live keyset `keyset` names, current or previous. Every input signs
  `PspSpendRequest::digest()` (tag `psp-mint/spend/v1`: `pay`, the memo, the change's
  keyset, every input's keyset, amount and nonce, every output's amount and blind
  nonce, every list and string length-prefixed). It differs from the FSP's digest in
  covering the change's keyset (fsp-mint always signs with its current set, so its
  digest has no such field) and in length-prefixing the input keysets, which the FSP's
  digest leaves bare. `hash()` (tag `psp-mint/spend-request/v1`: the digest, every
  spend signature and every note signature) is the key a stored answer is filed under.
  The response is the rollover's (`keyset`, `epoch`, `outcomes`, `keys`) plus `paid`.
  `pay` is the SPI's revenue and is never reissued; the amounts must add up, inputs =
  change + pay, and a `pay` of 0 is a rollover and is refused (`nothing_to_pay`). No
  `WIRE_VERSION` bump: nothing that exists is re-encoded, and a mint that does not know
  kind 14 skips it like any unknown kind.

- **The PSP's reconciliation is kind 15, and only an accepted request is answered.**
  `KIND_PSP_RECONCILE` (15) carries the corrected request (a payment that was held or a
  purchase that was rejected) and the credit claim (a purchase signed with a credit
  owed): one kind, because the mint tells them apart by its record of the payment. The
  body is `psp::ReconcileRequest` JSON (`reply_did`, `purchase`, `keyset`, `outputs`,
  `signature`); the reply is `psp::ReconcileResponse`, the follow-up record. AIR
  clients are anonymous (each connects with a one-off connection key), so the envelope
  names no sender and the proof of the right to claim is in the body: a BIP340
  signature by the purchase's reply key over `ReconcileRequest::digest()` (tag
  `psp-mint/reconcile/v1`: the reply DID, the purchase id, the length-prefixed keyset,
  and the count, amount and blind nonce of every output; lengths and counts are
  4 bytes, amounts 8 bytes, all big-endian). Only the holder of the private half may
  claim: a public key, even one only the payer and the PSP know, is never a secret.
  This matches the ESP's `service_signature` and `spend_signature`. The envelope's `R`
  is not checked; the wallet sets it to the reply key so that the answer is sealed to
  it. `hash()` (tag `psp-mint/reconcile-request/v1`: the digest and the signature) keys
  a stored answer and a counted refusal.
  **No refusal replies.** Telling an asker why a request failed is a free read for
  whoever holds the reply key, and tells a stranger nothing it should know, so a
  request that is not accepted gets no reply at all. `Served::Ignored(reason)` is the
  fourth thing a mint can say to a request, beside `Body`, `Unavailable` and
  `Refused`: `answer_request` returns an error that carries the reason (for the mint's
  log) and builds no reply, so the listener writes nothing to the reply cell. A
  transient failure of the mint is ignored too, and the asker sends the identical
  request again. The rules the request must follow are stated up front, in the first
  delivery (`ReconcileRules`, carried by `Signed`, `Refused` and `Held` when the record
  opens a window); see "The PSP's delivery of a purchase" below. The new codes
  (`wrong_total`, `nothing_to_issue`, `unknown_denomination`, `duplicate_blind_nonce`,
  `blind_nonce_used`, `bad_signature`, `unknown_payment`, `ambiguous_payment`,
  `payment_closed`, `too_many_attempts`) are the mint's log and audit codes: no
  refusal carries them to the asker. `SignedOutput` moved to `psp` so that
  `ReconcileResponse` can name it without the `air-request` feature; it is still
  exported from `air_request::delivery`. No `WIRE_VERSION` bump: nothing that exists is
  re-encoded, `rules` is `serde(default)` and is not written when absent, so the bytes
  of a record without it are as they were, and a mint that does not know kind 15 skips
  it like any unknown kind.

- **The ESP's calls are more kinds, not more envelope (7 to 10).** `KIND_FEES` (7),
  `KIND_EXCHANGE` (8), `KIND_TRANSFER` (9) and `KIND_REDEEM` (10) are constants and
  nothing else: `answer_request` hands the kind and the body to the mint's `serve`
  and the envelope never reads either, so a binary body (the redeem encoding) is
  as good as JSON, and the four-byte length already carries any ceiling the mint
  sets. The PSP's kinds 1, 3, 4 and 5 are used for the ESP too, because a kind names
  a call and the DID addressed decides whose reply it is; nothing in this crate
  looks inside a reply body for them but `check_mint_info`, and the ESP's `/health`
  has the same three fields. The goldens pin the hash of each new kind, one of them
  with a binary body.

## The PSP's delivery of a purchase (`air_request::delivery`)

Every other AIR call here is a wallet asking and a mint answering. The delivery is
the mint telling a payer something the payer never asked in a request: the
signatures for a purchase, once it settles at six confirmations, or the reason it
was rejected. The wallet knows the address in advance and reads it (held, if it
likes), so it needs no mailbox and no request.

- **The record is a reply envelope.** It answers a pseudo request that was never
  sent: kind `KIND_PSP_DELIVERY` (13), `request_id` = the purchase id, `R` = the
  reply DID, no body. The PSP signs it with its DID key (`build_reply`) and seals the
  whole reply to the reply DID. Both sides can compute the question's hash, so
  `verify_answer` binds a record to its purchase and reply DID with no new
  signature code, and the same envelope rules apply as for the other replies. The
  kind is a hash domain and is never served: a request of kind 13 in a mailbox is
  not answered.
- **What identifies the purchase.** `sha256("sp-psp-purchase-v0" || unsealed
  payload)`. The PSP only has the opened payload (`seal::open_payloads` returns the
  plaintext), a seal is randomised, and the wallet does not know the txid (any
  wallet may make the payment), so neither the sealed bytes nor the txid can be the
  id. The unsealed payload contains the reply DID, so two purchases never share an
  id.
- **The address.** `sha256("sp-air-delivery-v0" || PSP DID || reply DID ||
  purchase)` is the cell secret, from which the cell's public key is derived like
  the other reply cells. The reply DID is a one-off key made for the purchase and
  known only to the wallet and (inside the sealed payload) the PSP, so a third
  party cannot compute the address and fill the write-once cell first, and the PSP
  cannot link two purchases of one wallet.
- **Outcomes.** `STATUS_ANSWERED` carries `Signed { keyset, signatures,
  keysets, skipped_units, credit_cents, open_until }`: the blind-nonce/signature
  pairs, the PSP's live keysets (so the wallet needs no keys call, and unblinds with
  the keys of the set that signed), the units the PSP did not sign because the
  payment was short, a credit owed for an overpayment, and, when a credit is owed,
  the end of the window it stays open for. The last three are `serde(default)`.
  `STATUS_REFUSED` carries one of two bodies, told apart by a `kind` tag:
  `Refused { reason, paid_sats, paid_cents, open_until }` (`"rejected"`: the
  purchase was rejected and nothing was signed) and `Held { reason, paid_sats,
  paid_cents, requested_units, over_under_bps, open_until }` (`"held"`: the PSP has
  the payment and signed nothing, because the payment is short beyond its
  reconciliation target). Both say what the PSP received, in satoshis and in US
  cents at its price. `open_until` is Unix seconds: if the payment is not settled
  by then the PSP forfeits it and keeps the bitcoin, and the payer may delete the
  purchase and the key (0 means no window was named). `Outcome::open_until()` gives
  the end of the window, or none. Both use the one refusal status because the
  payer's reaction is the same (nothing signed, wait); `STATUS_UNAVAILABLE` is not
  used. The PSP's window is a setting of the PSP, which the wallet learns from the
  record.
- **The rules.** A record that opens a window carries `rules: Option<ReconcileRules>`
  (`serde(default)`, not written when `None`): what to send (`corrected_request` for a
  held or rejected purchase, `credit_claim` for a credit), the kind (15), the exact
  `due_units` the outputs must add up to after every fee, the reconciliation fee, the
  read and write costs the PSP prepays, the deadline, the number of attempts and
  `FORFEIT_NOTICE`. They are fixed when the window opens, so a payment that is already
  open keeps the fees it opened with, and `due_units` is a whole number of PSP units
  with no dollar or bitcoin price in it. They are a fallback for a fallback: a wallet
  that reconciles automatically and checks its request against them should never fail;
  they are spelled out for a developer or user with nonstandard tooling, as one last
  chance to get it right before the funds are lost. `Outcome::rules()` reads them.
- **No freshness check.** `open_record` calls `verify_answer` with `now` 0 and a
  maximum skew of `u64::MAX`, because the wallet may read the record days after it
  was written. The signature over the question's hash is what binds it.
- **Write-once and retries.** The AIR server answers a write to a taken cell as a
  read (ROADMAP item 11). `write_record` compares what it gets back with the bytes
  it wrote: equal is `AlreadyStored` (an unacknowledged earlier write got
  through), different is `Different` (a record is there that is not ours; the
  caller must not overwrite it, and cannot). The PSP seals once and keeps the bytes,
  so every retry writes the same bytes.
- **Goldens.** The purchase id of `b"payload"`, the address for a fixed PSP, reply
  DID and purchase, and the question's hash are pinned in the unit tests, computed
  independently with Python's `hashlib`. `tests/air_delivery.rs` runs the transport
  against a local `air_server` (a record written once and read twice, a held read, a
  read that times out, several records read together under one wait).

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

AIR (2.0.3, 2.1.0 and 3.0.0) uses `secp256k1` 0.31 and this crate (like mint-core) uses
0.30. The two versions sit side by side and no type crosses between them: the DID
keys are AIR's own types, and the rest of the wire is `secp256k1` 0.30. AIR 2.0.3
needed its default feature `stream` to stay on; 2.1.0 and 3.0.0 have no such feature. AIR 3.0.0 changed only
`channel.rs`, which this crate does not use, and air_server 1.0.0 changed only its
version and its dependency on AIR 3.0.0.

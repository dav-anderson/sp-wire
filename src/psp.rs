//! The PSP mint's request and response bodies.

use std::collections::BTreeMap;

use mint_types::{MintInput, MintOutput, MintOutputOutcome, Nonce};
use secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

/// `POST /melt` of mint-core: the notes to burn and a memo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeltRequest {
    pub inputs: Vec<MintInput>,
    pub memo: String,
}

/// `POST /melt`: mint-core's melt request plus the keyset of each input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PspMeltRequest {
    #[serde(flatten)]
    pub melt: MeltRequest,
    /// The keyset each input note carries, in order. Each note is verified,
    /// and looked up in the spent list, of the keyset it names.
    #[serde(default)]
    pub keysets: Vec<String>,
}

/// What the PSP says about one note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Burn {
    /// Whether the note is spent.
    pub spent: bool,
    /// The memo the note was burned under. `None` if it is not spent, or if it
    /// was spent with no memo on record.
    pub memo: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BurnsRequest {
    pub nonces: Vec<Nonce>,
}

/// In the order of the request.
#[derive(Debug, Serialize, Deserialize)]
pub struct BurnsResponse {
    pub burns: Vec<Burn>,
}

/// `GET /keysets`: every live keyset's public keys by ID, current and
/// previous, as fsp-mint's `/keys` gives them. A wallet unblinds with the
/// keys of the keyset named in a reply (or printed with claim signatures).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeysetsResponse {
    pub current: String,
    pub previous: Option<String>,
    pub keysets: BTreeMap<String, BTreeMap<u64, PublicKey>>,
}

/// Most notes in one rollover.
pub const MAX_ROLLOVER_NOTES: usize = 1000;

/// `POST /rollover`: notes in, fresh notes of exactly the same amounts out,
/// signed with the keyset the request names. Every input signs `transaction_sighash`
/// over the inputs and outputs, as in a mint-core swap.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloverRequest {
    /// The keyset of each input note, in order. Each note is verified, and
    /// looked up in the spent list, of the keyset it names.
    #[serde(default)]
    pub input_keysets: Vec<String>,
    pub inputs: Vec<MintInput>,
    /// The keyset the outputs are to be signed with: the current or the
    /// previous one, whichever is named (a set that is not live is refused).
    #[serde(default)]
    pub keyset: String,
    pub outputs: Vec<MintOutput>,
}

impl RolloverRequest {
    pub fn hash(&self) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(
            serde_json::to_vec(self).expect("serializable"),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloverResponse {
    pub keyset: String,
    pub epoch: u64,
    pub outcomes: Vec<MintOutputOutcome>,
    /// The public key each output was signed with, for unblinding.
    pub keys: Vec<PublicKey>,
}

/// The longest memo of a PSP spend, in bytes (the same default as fsp-mint's
/// `spend.max_memo_bytes`).
pub const MAX_SPEND_MEMO_BYTES: usize = 256;

/// A PSP spend with change (AIR kind 14, [`crate::air_request::KIND_PSP_SPEND`]):
/// notes in, change out, an amount paid, and a memo. The inputs are worth the
/// change plus `pay`, exactly. `pay` is not reissued: the PSP mint burns it,
/// and it is the SPI's revenue. With `pay` 0 this would be a rollover, and the
/// mint refuses it (`nothing_to_pay`).
///
/// It is fsp-mint's [`crate::fsp::SpendRequest`] with a PSP rollover's shape:
/// each input names its keyset in `input_keysets` (the mint verifies a note, and
/// looks it up in the spent list, of the keyset it names), and the change is
/// signed with the one live keyset `keyset` names, the current or the previous.
/// Every input signs [`PspSpendRequest::digest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PspSpendRequest {
    /// The keyset of each input note, in order.
    #[serde(default)]
    pub input_keysets: Vec<String>,
    pub inputs: Vec<MintInput>,
    /// The keyset the change is to be signed with: the current or the previous
    /// one (a set that is not live is refused).
    #[serde(default)]
    pub keyset: String,
    /// The change: new notes for the payer.
    pub outputs: Vec<MintOutput>,
    /// What is paid, in PSP units. Burned, never reissued.
    pub pay: u64,
    #[serde(default)]
    pub memo: String,
}

const SPEND_DIGEST_TAG: &[u8] = b"psp-mint/spend/v1";
const SPEND_HASH_TAG: &[u8] = b"psp-mint/spend-request/v1";

impl PspSpendRequest {
    /// What every input's spend signature covers: `pay`, the memo, the keyset the
    /// change is signed with, every input's keyset, amount and nonce, and every
    /// output's amount and blind nonce. Every variable-length field and every
    /// list carries its length, so no two different requests share a digest.
    ///
    /// It differs from fsp-mint's spend digest in covering the change's keyset
    /// (fsp-mint always signs with its current set) and in length-prefixing the
    /// input keysets.
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(SPEND_DIGEST_TAG);
        h.update(self.pay.to_be_bytes());
        h.update((self.memo.len() as u64).to_be_bytes());
        h.update(self.memo.as_bytes());
        h.update((self.keyset.len() as u64).to_be_bytes());
        h.update(self.keyset.as_bytes());
        h.update((self.input_keysets.len() as u64).to_be_bytes());
        for k in &self.input_keysets {
            h.update((k.len() as u64).to_be_bytes());
            h.update(k.as_bytes());
        }
        h.update((self.inputs.len() as u64).to_be_bytes());
        for i in &self.inputs {
            h.update(i.amount.units.to_be_bytes());
            h.update(i.note.nonce.0.serialize());
        }
        h.update((self.outputs.len() as u64).to_be_bytes());
        for o in &self.outputs {
            h.update(o.amount.units.to_be_bytes());
            h.update(o.blind_nonce.0.serialize());
        }
        h.finalize().into()
    }

    /// The key the answer is stored under: the digest, every spend signature and
    /// every note signature. A retry sends the same request and gets the same
    /// stored answer.
    pub fn hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(SPEND_HASH_TAG);
        h.update(self.digest());
        for i in &self.inputs {
            h.update(i.spend_signature.as_ref());
        }
        for i in &self.inputs {
            h.update(i.note.signature.serialize());
        }
        hex::encode(h.finalize())
    }
}

/// The answer to a [`PspSpendRequest`]: the change signed, and what was paid.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PspSpendResponse {
    /// The keyset that signed the change.
    pub keyset: String,
    pub epoch: u64,
    /// One blind signature per change output, in order.
    pub outcomes: Vec<MintOutputOutcome>,
    /// The public key each output was signed with, for unblinding.
    pub keys: Vec<PublicKey>,
    /// `pay`, burned.
    pub paid: u64,
}

/// One signed output: the blind nonce the wallet asked for and the PSP's blind
/// signature of it (the pairs `describe` logs). Used by the delivery record
/// ([`crate::air_request::delivery::Signed`]) and by [`ReconcileResponse`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOutput {
    pub blind_nonce: String,
    pub signature: String,
}

const RECONCILE_DIGEST_TAG: &[u8] = b"psp-mint/reconcile/v1";
const RECONCILE_HASH_TAG: &[u8] = b"psp-mint/reconcile-request/v1";

/// The corrected request or the credit claim of one purchase (AIR kind 15,
/// `crate::air_request::KIND_PSP_RECONCILE`): the new blinded notes for a
/// payment that is open (held, rejected, or issued with a credit). One kind
/// covers both; the mint tells them apart by its record of the payment.
///
/// The request must follow the `rules` of the purchase's first delivery
/// ([`crate::air_request::delivery::ReconcileRules`]): the outputs must add up
/// to `due_units` exactly. The mint answers only a request it accepts; a
/// refused one gets no reply.
///
/// **Who may ask.** AIR clients are anonymous (each connects with a one-off
/// connection key), so the envelope names no sender. The proof of the right to
/// claim is `signature`, a BIP340 signature by the purchase's one-off reply
/// key over [`ReconcileRequest::digest`]: only the holder of the private half
/// may claim the payment, and a public key, even one that only the payer and
/// the PSP know, is never a secret. This matches the ESP's `service_signature`.
/// The envelope's `R` is not checked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileRequest {
    /// The purchase's one-off reply key (33 bytes, 66 hex characters): the
    /// `reply_did` of the payload, `Record.payer_did` at the mint.
    pub reply_did: crate::ServiceDid,
    /// The purchase id (32 bytes, 64 hex characters): `purchase_id` of the
    /// unsealed payload, the `purchase` of the first delivery.
    #[serde(with = "hex32")]
    pub purchase: [u8; 32],
    /// The keyset that signs the outputs: the current or the previous one, as in
    /// a rollover (a set that is not live is refused).
    pub keyset: String,
    /// The new blinded notes.
    pub outputs: Vec<MintOutput>,
    /// BIP340 by `reply_did` over [`ReconcileRequest::digest`] (64 bytes, 128
    /// hex characters).
    #[serde(with = "hex_signature")]
    pub signature: secp256k1::schnorr::Signature,
}

impl ReconcileRequest {
    /// What the signature covers: `sha256("psp-mint/reconcile/v1" || reply_did
    /// (33) || purchase (32) || u32 len(keyset) || keyset || u32 count || each
    /// output: amount u64 || blind nonce (33))`, all integers big-endian.
    pub fn digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(RECONCILE_DIGEST_TAG);
        h.update(self.reply_did.as_bytes());
        h.update(self.purchase);
        h.update(
            u32::try_from(self.keyset.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        h.update(self.keyset.as_bytes());
        h.update(
            u32::try_from(self.outputs.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for o in &self.outputs {
            h.update(o.amount.units.to_be_bytes());
            h.update(o.blind_nonce.0.serialize());
        }
        h.finalize().into()
    }

    /// The key stored answers and counted refusals are kept under: the whole
    /// body, signature included, `sha256("psp-mint/reconcile-request/v1" ||
    /// digest || signature (64))`. A resend of the same request has the same
    /// hash.
    pub fn hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(RECONCILE_HASH_TAG);
        h.update(self.digest());
        h.update(self.signature.as_ref());
        hex::encode(h.finalize())
    }
}

/// The answer to an accepted [`ReconcileRequest`]: the mint's signed reply, the
/// follow-up record, written once to the request's reply cell and sealed to the
/// request's `R` (the purchase's reply key). A refused request gets no answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileResponse {
    /// The keyset that signed.
    pub keyset: String,
    /// One pair per output, in the order of the request.
    pub signatures: Vec<SignedOutput>,
    /// The live keysets, so the wallet can unblind from this reply alone.
    pub keysets: KeysetsResponse,
    /// The total signed, in PSP units.
    pub issued_units: u64,
    /// The reconciliation fee taken.
    pub fee_units: u64,
    /// The read cost prepaid for this reply.
    pub read_prepaid_units: u64,
    /// The one write prepaid for this payment.
    pub write_prepaid_units: u64,
    /// The credit rounding remainder the PSP keeps (0 to 9 cents).
    pub kept_cents: u64,
    /// The cents the PSP gives away by rounding a credit up (0 to 9).
    pub given_cents: u64,
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        let bytes = hex::decode(&text).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes of hex"))
    }
}

mod hex_signature {
    use secp256k1::schnorr::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Signature, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v.as_ref()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Signature, D::Error> {
        let text = String::deserialize(d)?;
        let bytes = hex::decode(&text).map_err(serde::de::Error::custom)?;
        Signature::from_slice(&bytes).map_err(serde::de::Error::custom)
    }
}

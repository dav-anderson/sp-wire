//! The PSP bodies and encodings, pinned to what the v0.1.0 mint wrote.
//!
//! A failure here means a byte of the wire changed: bump `WIRE_VERSION`.

use std::collections::BTreeMap;

use mint_types::{Amount, BlindNonce, MintInput, MintOutput, MintOutputOutcome, Nonce, Note};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, PublicKey, SECP256K1};
use sp_wire::keyset::{KEYSET_LEN, KeysetWindow, RotationResponse, keyset_id};
use sp_wire::payload::{self, DID_LEN, Payload};
use sp_wire::psp::{
    Burn, BurnsRequest, BurnsResponse, KeysetsResponse, MeltRequest, PspMeltRequest,
    PspSpendRequest, PspSpendResponse, RolloverRequest, RolloverResponse,
};

const GOLDEN: &str = include_str!("golden/psp.txt");

/// The captured value for `name`, from the v0.1.0 mints' own output.
fn expected(name: &str) -> &'static str {
    GOLDEN
        .lines()
        .find_map(|l| {
            l.strip_prefix("GOLDEN ")?
                .strip_prefix(name)?
                .strip_prefix(' ')
        })
        .unwrap_or_else(|| panic!("no golden line for {name}"))
}

fn line(name: &str, value: impl std::fmt::Display) {
    assert_eq!(value.to_string(), expected(name), "{name}");
}

fn json<T: serde::Serialize>(name: &str, value: &T) {
    line(name, serde_json::to_string(value).unwrap());
}

fn key(n: u8) -> PublicKey {
    Keypair::from_seckey_slice(SECP256K1, &[n; 32])
        .unwrap()
        .public_key()
}

fn sig(n: u8) -> Signature {
    Signature::from_slice(&[n; 64]).unwrap()
}

fn note(n: u8) -> Note {
    Note {
        nonce: Nonce(key(n)),
        signature: key(n + 1),
    }
}

fn input(units: u64, n: u8) -> MintInput {
    MintInput {
        amount: Amount::from_units(units),
        note: note(n),
        spend_signature: sig(n),
    }
}

fn output(units: u64, n: u8) -> MintOutput {
    MintOutput {
        amount: Amount::from_units(units),
        blind_nonce: BlindNonce(key(n)),
    }
}

#[test]
fn the_psp_wire_bytes_are_unchanged() {
    // Sizes and constants.
    line("DID_LEN", DID_LEN);
    line("KEYSET_LEN", KEYSET_LEN);
    line("MAX_ROLLOVER_NOTES", sp_wire::psp::MAX_ROLLOVER_NOTES);
    line("MAX_SPEND_MEMO_BYTES", sp_wire::psp::MAX_SPEND_MEMO_BYTES);

    // The mint-core types as they serialize.
    json("MintInput", &input(4, 30));
    json("MintOutput", &output(4, 40));
    json("MintOutputOutcome", &MintOutputOutcome(key(50)));
    json("Note", &note(30));
    line("point_hex", hex::encode(key(1).serialize()));

    // The key-set ID: 8 bytes of SHA-256 over a tag and the 1-unit key.
    let mut pk = BTreeMap::new();
    pk.insert(Amount::from_units(1), key(10));
    pk.insert(Amount::from_units(2), key(11));
    line("keyset_id", keyset_id(&pk));

    // The OP_RETURN payload, with and without a keyset.
    let outputs = vec![output(1, 20), output(1024, 21), output(16_777_216, 22)];
    let with = Payload {
        did: [7u8; DID_LEN],
        outputs: outputs.clone(),
        keyset: Some("0102030405060708".into()),
    };
    let without = Payload {
        did: [7u8; DID_LEN],
        outputs,
        keyset: None,
    };
    line(
        "payload_with_keyset",
        hex::encode(payload::encode(&with).unwrap()),
    );
    line(
        "payload_no_keyset",
        hex::encode(payload::encode(&without).unwrap()),
    );

    // The golden payload also decodes back.
    assert_eq!(
        payload::decode(&payload::encode(&with).unwrap()).unwrap(),
        with
    );
    assert_eq!(
        payload::decode(&payload::encode(&without).unwrap()).unwrap(),
        without
    );

    #[cfg(feature = "seal")]
    sealed_payload();

    // Rollover.
    let rollover = RolloverRequest {
        input_keysets: vec!["0102030405060708".into(), "1112131415161718".into()],
        inputs: vec![input(4, 60), input(2, 62)],
        keyset: "2122232425262728".into(),
        outputs: vec![output(4, 70), output(2, 71)],
    };
    json("RolloverRequest", &rollover);
    line("RolloverRequest_hash", rollover.hash());
    json(
        "RolloverResponse",
        &RolloverResponse {
            keyset: "2122232425262728".into(),
            epoch: 3,
            outcomes: vec![MintOutputOutcome(key(80)), MintOutputOutcome(key(81))],
            keys: vec![key(82), key(83)],
        },
    );

    // PSP spend with change: the request, the digest every input signs, the hash
    // a stored answer is keyed by, and the response.
    let spend = PspSpendRequest {
        input_keysets: vec!["0102030405060708".into(), "1112131415161718".into()],
        inputs: vec![input(4, 120), input(2, 122)],
        keyset: "2122232425262728".into(),
        outputs: vec![output(4, 130)],
        pay: 2,
        memo: "memo".into(),
    };
    json("PspSpendRequest", &spend);
    line("PspSpendRequest_digest", hex::encode(spend.digest()));
    line("PspSpendRequest_hash", spend.hash());
    json(
        "PspSpendResponse",
        &PspSpendResponse {
            keyset: "2122232425262728".into(),
            epoch: 3,
            outcomes: vec![MintOutputOutcome(key(140))],
            keys: vec![key(141)],
            paid: 2,
        },
    );

    // Rotation window.
    let window = |n: u8| KeysetWindow {
        id: format!("{:02x}{:02x}030405060708", n, n),
        epoch: n as u64,
        starts: Some(1_800_000_000),
        current_until: None,
        retires: Some(1_800_007_200),
    };
    json(
        "RotationResponse",
        &RotationResponse {
            active: true,
            first_issue: Some(1_800_000_000),
            rotation_activation_hours: 1,
            activation: Some(1_800_003_600),
            rotation_period_hours: 1,
            current: window(2),
            previous: Some(window(1)),
            next_rotation: Some(1_800_007_200),
            now: 1_800_003_700,
        },
    );

    // /keysets.
    let mut keysets = BTreeMap::new();
    let mut keys = BTreeMap::new();
    keys.insert(1u64, key(90));
    keys.insert(2u64, key(91));
    keysets.insert("0102030405060708".to_string(), keys);
    json(
        "KeysetsResponse",
        &KeysetsResponse {
            current: "0102030405060708".into(),
            previous: None,
            keysets,
        },
    );

    // /melt, /burns.
    json(
        "PspMeltRequest",
        &PspMeltRequest {
            melt: MeltRequest {
                inputs: vec![input(4, 100), input(1, 102)],
                memo: "memo".into(),
            },
            keysets: vec!["0102030405060708".into(), "0102030405060708".into()],
        },
    );
    json(
        "BurnsRequest",
        &BurnsRequest {
            nonces: vec![Nonce(key(110)), Nonce(key(111))],
        },
    );
    json(
        "BurnsResponse",
        &BurnsResponse {
            burns: vec![
                Burn {
                    spent: true,
                    memo: Some("m".into()),
                },
                Burn {
                    spent: false,
                    memo: None,
                },
            ],
        },
    );
}

/// A sealed payload made by the v0.1.x code (AIR 1.1.0, wire version 1): the
/// `postcard` encoding of its `Encrypted`. It opens with the key below under
/// AIR 1.1.0 and must not open any more.
#[cfg(feature = "seal")]
const SEALED_WIRE_VERSION_1: &str = "406ee6680dcc2616b63cedca37462e6b90aead2837f4e106788d85300316ed78414335cd52dcc468b302076d7f819024738777ca6e4d3c1b0963c46928f5e1df814fcf80cb9e2fb580acffbd548773a065a6016b34c8fd028ef1366d47d1406ba434cdb4e339da1b1f8ff7f02249690b2499577d05c79ee441c61d207e2dd422ef069cce944f768b019bdb607e0bbff067a7768d6ac95c888a516f27395e3f3d78dbc8420e8933e527fd62f614c83e323f74d8e9dccdae4908dfcff4f28f6894575610f3826966f08c8866248986b0c421102484601b201e0ecee479cd9cfb38c33648accaa24ff4c18d882a4bd23885b451de0bc50a5e3a51";

/// The sealed payload (wire version 2, AIR 2.0.3): a blob made by this code opens,
/// the overhead is a constant 80, and a version 1 blob does not open.
#[cfg(feature = "seal")]
fn sealed_payload() {
    use sp_wire::seal::{self, SecretKey};
    let secret: SecretKey = serde_json::from_str(expected("seal_secret_json")).unwrap();
    // The DID key is published as 33 bytes of hex, and that did not change.
    assert_eq!(secret.public_key().to_string(), expected("seal_public_hex"));
    assert_eq!(expected("seal_public_hex").len(), 66);
    let sealed = hex::decode(expected("seal_sealed")).unwrap();
    let plain = seal::decrypt(&secret, &sealed).unwrap();
    assert_eq!(hex::encode(&plain), expected("seal_plain"));
    assert_eq!(plain.len().to_string(), expected("seal_plain_len"));
    assert_eq!(sealed.len().to_string(), expected("seal_sealed_len"));
    assert_eq!(sealed.len() - plain.len(), seal::OVERHEAD);
    assert_eq!(seal::OVERHEAD.to_string(), expected("seal_overhead_20"));
    assert_eq!(seal::OVERHEAD.to_string(), expected("seal_overhead_200"));
    // A fresh seal is random, but its size is not, and it is the same for a short
    // and a long payload (there is no length byte any more).
    let short = seal::encrypt(&secret.public_key(), &[9u8; 20]).unwrap();
    let long = seal::encrypt(&secret.public_key(), &[9u8; 200]).unwrap();
    assert_eq!(short.len() - 20, seal::OVERHEAD);
    assert_eq!(long.len() - 200, seal::OVERHEAD);
    assert_eq!(seal::decrypt(&secret, &short).unwrap(), vec![9u8; 20]);
    assert_eq!(seal::decrypt(&secret, &long).unwrap(), vec![9u8; 200]);
    // Too short to hold a ciphertext is not a sealed payload.
    assert_eq!(seal::decrypt(&secret, &[]), Err(seal::SealError::Malformed));
    assert_eq!(
        seal::decrypt(&secret, &short[..seal::OVERHEAD]),
        Err(seal::SealError::Malformed)
    );
    // Anything of a plausible length that does not open is undecryptable: bytes
    // left over, a byte short, or a version 1 blob.
    let mut extra = short.clone();
    extra.push(0);
    assert_eq!(
        seal::decrypt(&secret, &extra),
        Err(seal::SealError::Undecryptable)
    );
    assert_eq!(
        seal::decrypt(&secret, &short[..short.len() - 1]),
        Err(seal::SealError::Undecryptable)
    );
    let v1 = hex::decode(SEALED_WIRE_VERSION_1).unwrap();
    assert_eq!(
        seal::decrypt(&secret, &v1),
        Err(seal::SealError::Undecryptable)
    );
    // Nothing to seal.
    assert_eq!(
        seal::encrypt(&secret.public_key(), &[]),
        Err(seal::SealError::Empty)
    );
    assert_eq!(
        seal::parse_public_key(expected("seal_public_hex"))
            .unwrap()
            .to_string(),
        expected("seal_public_hex")
    );
}

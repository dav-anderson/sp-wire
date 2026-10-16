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
    RolloverRequest, RolloverResponse,
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

/// The sealed payload: a blob made by the v0.1.0 mint code opens, and the
/// overhead of sealing is the same.
#[cfg(feature = "seal")]
fn sealed_payload() {
    use sp_wire::seal::{self, SecretKey};
    let secret: SecretKey = serde_json::from_str(expected("seal_secret_json")).unwrap();
    assert_eq!(secret.public_key().to_string(), expected("seal_public_hex"));
    let sealed = hex::decode(expected("seal_sealed")).unwrap();
    let plain = seal::decrypt(&secret, &sealed).unwrap();
    assert_eq!(hex::encode(&plain), expected("seal_plain"));
    assert_eq!(plain.len().to_string(), expected("seal_plain_len"));
    assert_eq!(sealed.len().to_string(), expected("seal_sealed_len"));
    assert_eq!(sealed.len() - plain.len(), seal::OVERHEAD_LONG);
    // A fresh seal is random, but its size is not.
    let short = seal::encrypt(&secret.public_key(), &[9u8; 20]).unwrap();
    let long = seal::encrypt(&secret.public_key(), &[9u8; 200]).unwrap();
    assert_eq!(short.len() - 20, seal::OVERHEAD_SHORT);
    assert_eq!(long.len() - 200, seal::OVERHEAD_LONG);
    assert_eq!(seal::decrypt(&secret, &short).unwrap(), vec![9u8; 20]);
    // Bytes left over, or too few, are not a sealed payload.
    let mut extra = short.clone();
    extra.push(0);
    assert_eq!(
        seal::decrypt(&secret, &extra),
        Err(seal::SealError::Malformed)
    );
    assert_eq!(
        seal::decrypt(&secret, &short[..10]),
        Err(seal::SealError::Malformed)
    );
    assert_eq!(
        seal::parse_public_key(expected("seal_public_hex"))
            .unwrap()
            .to_string(),
        expected("seal_public_hex")
    );
}

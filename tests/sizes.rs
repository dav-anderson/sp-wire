//! The size of every encoded wire type, so a change to one fails loudly.
//!
//! Each number here is part of the wire. Changing one means bumping
//! `WIRE_VERSION` (and the format byte where there is one).

use mint_types::{Amount, BlindNonce, MintInput, MintOutput, Nonce, Note};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, PublicKey, SECP256K1};
use sp_wire::esp::redeem::{
    self, FIXED_BYTES, FORMAT_VERSION, INPUT_BYTES, KEYSET_BYTES, MIN_REQUEST_BYTES, OUTPUT_BYTES,
    RedeemInput, RedeemOutput, RedeemRequest,
};
use sp_wire::esp::terms::Terms;
use sp_wire::fsp;
use sp_wire::keyset::{KEYSET_HEX_LEN, KEYSET_LEN, is_keyset_id, keyset_id};
use sp_wire::payload::{self, DID_LEN, Payload};
use sp_wire::service::ServiceDid;
use sp_wire::units::{ESP_PER_PSP, ESP_PER_USD, MAX_PSP_DENOMINATION, MAX_PSP_PER_NOTE};

fn key(n: u8) -> PublicKey {
    Keypair::from_seckey_slice(SECP256K1, &[n; 32])
        .unwrap()
        .public_key()
}

/// The DID of the key `[n; 32]`: its 33-byte compressed public key.
fn did(n: u8) -> ServiceDid {
    ServiceDid::from(key(n))
}

fn output(units: u64, n: u8) -> MintOutput {
    MintOutput {
        amount: Amount::from_units(units),
        blind_nonce: BlindNonce(key(n)),
    }
}

fn redeem_input(n: u8) -> RedeemInput {
    RedeemInput {
        service: did(1),
        redeemable_after_day: 20_500,
        keyset: "0102030405060708".into(),
        input: MintInput {
            amount: Amount::from_units(4),
            note: Note {
                nonce: Nonce(key(n)),
                signature: key(n + 1),
            },
            spend_signature: Signature::from_slice(&[n; 64]).unwrap(),
        },
    }
}

fn redeem_output(n: u8) -> RedeemOutput {
    RedeemOutput {
        service: did(1),
        redeemable_after_day: 20_500,
        output: output(2, n),
    }
}

fn request(inputs: usize, memo: &str, decline: usize, refund: usize) -> RedeemRequest {
    RedeemRequest {
        service: did(1),
        output_keyset: "2122232425262728".into(),
        inputs: (0..inputs)
            .map(|i| redeem_input(10 + 2 * i as u8))
            .collect(),
        memo: memo.into(),
        decline_outputs: (0..decline).map(|i| redeem_output(100 + i as u8)).collect(),
        refund_outputs: (0..refund).map(|i| redeem_output(120 + i as u8)).collect(),
        service_signature: Signature::from_slice(&[5; 64]).unwrap(),
    }
}

#[test]
fn the_wire_version_is_three() {
    assert_eq!(sp_wire::WIRE_VERSION, 3);
}

#[test]
fn a_point_is_33_bytes_and_so_is_a_service_id() {
    assert_eq!(key(1).serialize().len(), 33);
    assert_eq!(did(1).serialize().len(), 33);
    assert_eq!(did(1).serialize(), key(1).serialize());
    assert_eq!(DID_LEN, 33);
}

#[test]
fn the_keyset_id_is_8_bytes_or_16_hex_characters() {
    assert_eq!((KEYSET_LEN, KEYSET_HEX_LEN, KEYSET_BYTES), (8, 16, 8));
    let mut pk = std::collections::BTreeMap::new();
    pk.insert(Amount::from_units(1), key(3));
    let id = keyset_id(&pk);
    assert_eq!(id.len(), 16);
    assert!(is_keyset_id(&id));
    assert!(!is_keyset_id("0102"));
    assert!(!is_keyset_id("zz02030405060708"));
}

#[test]
fn a_payload_is_35_bytes_plus_41_for_each_output_and_8_for_a_keyset() {
    for n in 1..=4usize {
        let outputs: Vec<MintOutput> = (0..n).map(|i| output(1 << i, 20 + i as u8)).collect();
        let bare = Payload {
            did: [7; DID_LEN],
            outputs: outputs.clone(),
            keyset: None,
        };
        assert_eq!(payload::encode(&bare).unwrap().len(), 35 + 41 * n);
        let with = Payload {
            did: [7; DID_LEN],
            outputs,
            keyset: Some("0102030405060708".into()),
        };
        assert_eq!(payload::encode(&with).unwrap().len(), 35 + 41 * n + 8);
    }
}

#[test]
fn a_redeem_request_is_120_plus_187_82_and_the_memo() {
    assert_eq!(FORMAT_VERSION, 3);
    assert_eq!((FIXED_BYTES, INPUT_BYTES, OUTPUT_BYTES), (120, 187, 82));
    assert_eq!(MIN_REQUEST_BYTES, 120 + 187 + 1);
    for (inputs, memo, decline, refund) in [
        (0, "", 0, 0),
        (1, "a", 0, 0),
        (2, "payout", 1, 2),
        (5, "a longer memo, in UTF-8 é", 3, 0),
    ] {
        let r = request(inputs, memo, decline, refund);
        let bytes = redeem::encode(&r);
        let expected =
            120 + 187 * inputs as u64 + memo.len() as u64 + 82 * (decline + refund) as u64;
        assert_eq!(bytes.len() as u64, expected);
        assert_eq!(r.encoded_len(), expected);
        assert_eq!(
            redeem::encoded_len(inputs, memo.len(), decline, refund),
            expected
        );
        assert_eq!(bytes[0], FORMAT_VERSION);
    }
}

#[test]
fn one_input_adds_187_bytes_and_one_output_82() {
    let base = redeem::encode(&request(1, "m", 0, 0)).len();
    assert_eq!(redeem::encode(&request(2, "m", 0, 0)).len() - base, 187);
    assert_eq!(redeem::encode(&request(1, "m", 1, 0)).len() - base, 82);
    assert_eq!(redeem::encode(&request(1, "m", 0, 1)).len() - base, 82);
}

#[test]
fn the_redeem_encoding_reads_back_and_a_hash_is_64_hex() {
    let r = request(2, "payout", 1, 2);
    let bytes = redeem::encode(&r);
    let back = redeem::decode(&bytes).unwrap();
    assert_eq!(redeem::encode(&back), bytes);
    assert_eq!(redeem::request_hash(&r).len(), 64);
    assert_eq!(
        redeem::digest(
            &r.service,
            &r.output_keyset,
            &r.inputs,
            &r.memo,
            &r.decline_outputs,
            &r.refund_outputs
        )
        .len(),
        32
    );
}

#[test]
fn terms_are_41_bytes() {
    let t = Terms {
        service: did(1),
        redeemable_after_day: 20_500,
    };
    assert_eq!(t.to_bytes().len(), 41);
}

#[test]
fn an_fsp_issue_group_is_16_bytes_plus_106_a_note_and_41_an_output() {
    assert_eq!(fsp::issue_group_size(0, 0), 16);
    assert_eq!(fsp::issue_group_size(1, 0), 16 + 106);
    assert_eq!(fsp::issue_group_size(0, 1), 16 + 41);
    assert_eq!(fsp::issue_group_size(2, 3), 16 + 212 + 123);
}

#[test]
fn the_units_are_ten_psp_to_the_dollar() {
    assert_eq!(ESP_PER_PSP, 100_000_000_000);
    assert_eq!(ESP_PER_USD, 1_000_000_000_000);
    assert_eq!(10 * u128::from(ESP_PER_PSP), ESP_PER_USD);
    assert_eq!(MAX_PSP_DENOMINATION, 1 << 24);
    assert_eq!(MAX_PSP_PER_NOTE, 184_467_440);
}

#[test]
fn a_sealed_payload_is_80_bytes_longer_than_its_payload() {
    use sp_wire::seal::{OVERHEAD, SENDER_KEY_BYTES, TAG_BYTES};
    assert_eq!(SENDER_KEY_BYTES, 64);
    assert_eq!(TAG_BYTES, 16);
    assert_eq!(OVERHEAD, 80);
    // What goes in the OP_RETURN for n outputs without a keyset: the 35-byte
    // payload header and 41 an output, then the seal. A purchase of the largest
    // allowed 255 outputs is 35 + 41 * 255 + 80 = 10_570 bytes.
    let sealed = |n: usize| 35 + 41 * n + OVERHEAD;
    assert_eq!(sealed(1), 156);
    assert_eq!(sealed(255), 10_570);
    // With the keyset the payload carries, 8 bytes more.
    assert_eq!(sealed(1) + 8, 164);
}

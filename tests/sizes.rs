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
use sp_wire::fsp;
use sp_wire::keyset::{KEYSET_HEX_LEN, KEYSET_LEN, is_keyset_id, keyset_id};
use sp_wire::payload::{self, DID_LEN};
use sp_wire::service::ServiceDid;

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
fn a_payload_is_the_33_byte_claim_did_and_nothing_else() {
    assert_eq!(DID_LEN, 33);
    let claim = key(9).serialize();
    let bytes = payload::encode(&claim).unwrap();
    assert_eq!(bytes, claim);
    assert_eq!(payload::decode(&bytes).unwrap().claim_did, did(9));
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
fn an_fsp_issue_group_is_16_bytes_plus_106_a_note_and_41_an_output() {
    assert_eq!(fsp::issue_group_size(0, 0), 16);
    assert_eq!(fsp::issue_group_size(1, 0), 16 + 106);
    assert_eq!(fsp::issue_group_size(0, 1), 16 + 41);
    assert_eq!(fsp::issue_group_size(2, 3), 16 + 212 + 123);
}

#[cfg(feature = "seal")]
#[test]
fn a_sealed_payload_is_113_bytes_and_hides_the_claim_did() {
    use sp_wire::seal::{self, OVERHEAD, SENDER_KEY_BYTES, SecretKey, TAG_BYTES};
    assert_eq!(SENDER_KEY_BYTES, 64);
    assert_eq!(TAG_BYTES, 16);
    assert_eq!(OVERHEAD, 80);
    // What goes in the OP_RETURN: the 33-byte claim DID, then the seal.
    let claim = key(9).serialize();
    let plain = payload::encode(&claim).unwrap();
    assert_eq!(plain.len(), 33);
    // The claim DID is in the plaintext, so finding it absent below means something.
    assert!(plain.windows(DID_LEN).any(|w| w == claim));
    let mint = SecretKey::new();
    let sealed = seal::encrypt(&mint.public_key(), &plain).unwrap();
    assert_eq!(sealed.len(), 33 + OVERHEAD);
    assert_eq!(sealed.len(), 113);
    assert!(
        !sealed.windows(DID_LEN).any(|w| w == claim),
        "the claim DID shows in the sealed bytes"
    );
    assert_eq!(seal::decrypt(&mint, &sealed).unwrap(), plain);
}

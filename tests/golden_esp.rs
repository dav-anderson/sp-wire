//! The ESP bodies and encodings, pinned to what the v0.1.0 mint wrote.
//!
//! A failure here means a byte of the wire changed: bump `WIRE_VERSION`.

use mint_types::{Amount, BlindNonce, MintInput, MintOutput, Nonce, Note};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, PublicKey, SECP256K1, XOnlyPublicKey};
use sp_wire::esp::exchange::{self, ExchangeRequest, ExchangeResponse};
use sp_wire::esp::queue::{EntryView, SignedOutput, Status};
use sp_wire::esp::redeem::{
    self, NoteResult, Reason, RedeemInput, RedeemOutput, RedeemRequest, RedeemResponse, TermsTotal,
    Totals,
};
use sp_wire::esp::rollover::{self, RolloverRequest, RolloverResponse};
use sp_wire::esp::terms::Terms;
use sp_wire::esp::transfer::{self, TransferRequest};
use sp_wire::keyset::{KeysetWindow, RotationResponse};
use sp_wire::units;

const GOLDEN: &str = include_str!("golden/esp.txt");

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

fn xonly(n: u8) -> XOnlyPublicKey {
    Keypair::from_seckey_slice(SECP256K1, &[n; 32])
        .unwrap()
        .x_only_public_key()
        .0
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

const DAY: u64 = 20_500;

fn redeem_input(n: u8) -> RedeemInput {
    RedeemInput {
        service: xonly(1),
        redeemable_after_day: DAY,
        keyset: "0102030405060708".into(),
        input: input(4, n),
    }
}

fn redeem_output(n: u8) -> RedeemOutput {
    RedeemOutput {
        service: xonly(1),
        redeemable_after_day: DAY,
        output: output(2, n),
    }
}

fn redeem_request() -> RedeemRequest {
    RedeemRequest {
        service: xonly(1),
        output_keyset: "2122232425262728".into(),
        inputs: vec![redeem_input(10), redeem_input(12)],
        memo: "payout".into(),
        decline_outputs: vec![redeem_output(20)],
        refund_outputs: vec![redeem_output(22), redeem_output(24)],
        service_signature: sig(5),
    }
}

#[test]
fn the_esp_wire_bytes_are_unchanged() {
    // Constants and sizes.
    line("ESP_PER_PSP", units::ESP_PER_PSP);
    line("MAX_PSP_PER_NOTE", units::MAX_PSP_PER_NOTE);
    line("ESP_PER_USD", units::ESP_PER_USD);
    line("MAX_ITEMS", exchange::MAX_ITEMS);
    line("MAX_ROLLOVER_NOTES", rollover::MAX_ROLLOVER_NOTES);
    line("REDEEM_FORMAT_VERSION", redeem::FORMAT_VERSION);
    line("REDEEM_KEYSET_BYTES", redeem::KEYSET_BYTES);
    line("REDEEM_INPUT_BYTES", redeem::INPUT_BYTES);
    line("REDEEM_OUTPUT_BYTES", redeem::OUTPUT_BYTES);
    line("REDEEM_FIXED_BYTES", redeem::FIXED_BYTES);
    line("REDEEM_MIN_REQUEST_BYTES", redeem::MIN_REQUEST_BYTES);
    line(
        "REDEEM_encoded_len_2_6_1_2",
        redeem::encoded_len(2, 6, 1, 2),
    );
    line("SECONDS_PER_DAY", sp_wire::esp::terms::SECONDS_PER_DAY);

    // Terms: the service key and the day, 40 bytes.
    let terms = Terms {
        service: xonly(1),
        redeemable_after_day: DAY,
    };
    line("Terms_bytes", hex::encode(terms.to_bytes()));

    // Exchange.
    let exchange_request = ExchangeRequest {
        service: xonly(1),
        psp_inputs: vec![input(4, 30), input(1, 32)],
        psp_input_keysets: vec!["0102030405060708".into(), "1112131415161718".into()],
        keyset: "2122232425262728".into(),
        outputs: vec![output(5, 40), output(7, 41)],
    };
    json("ExchangeRequest", &exchange_request);
    line(
        "exchange_memo",
        exchange::memo(&exchange_request.service, &exchange_request.outputs),
    );
    line(
        "exchange_request_hash",
        exchange::request_hash(&exchange_request).unwrap(),
    );
    json(
        "ExchangeResponse",
        &ExchangeResponse {
            keyset: "2122232425262728".into(),
            service: xonly(1),
            redeemable_after_day: DAY,
            signatures: vec![key(50), key(51)],
            keys: vec![key(52), key(53)],
            fee_per_byte: 1_000_000,
            fee_esp: 123_456_789_012_345_678_901,
            size_bytes: 321,
        },
    );

    // Transfer.
    let transfer_request = TransferRequest {
        service: xonly(1),
        redeemable_after_day: DAY,
        input_keysets: vec!["0102030405060708".into()],
        inputs: vec![input(4, 60)],
        keyset: "2122232425262728".into(),
        outputs: vec![output(4, 70)],
        service_signature: sig(6),
    };
    json("TransferRequest", &transfer_request);
    line("transfer_digest", hex::encode(transfer_request.digest()));
    line(
        "transfer_request_hash",
        transfer::request_hash(&transfer_request),
    );

    // Redeem: the canonical binary body.
    let request = redeem_request();
    let encoded = redeem::encode(&request);
    line("redeem_encode", hex::encode(&encoded));
    line("redeem_encode_len", encoded.len());
    line("redeem_encoded_len_method", request.encoded_len());
    line("redeem_digest", hex::encode(request.digest()));
    line("redeem_request_hash", redeem::request_hash(&request));
    let decoded = redeem::decode(&encoded).unwrap();
    assert_eq!(redeem::encode(&decoded), encoded);
    line("redeem_decode_roundtrips", true);

    // Redeem replies.
    let results = vec![
        NoteResult {
            accepted: true,
            reason: None,
            burned: true,
        },
        NoteResult {
            accepted: false,
            reason: Some(Reason::AlreadySpent),
            burned: false,
        },
    ];
    for (name, reason) in [
        ("Reason_wrong_service", Reason::WrongService),
        ("Reason_bad_proof", Reason::BadProof),
        ("Reason_already_spent", Reason::AlreadySpent),
        ("Reason_immature", Reason::Immature),
        ("Reason_keyset_retired", Reason::KeysetRetired),
        ("Reason_unknown_keyset", Reason::UnknownKeyset),
    ] {
        json(name, &reason);
    }
    json("NoteResult", &results[1]);
    let totals = Totals {
        notes: results.clone(),
        accepted_esp: 4_000_000_000_000,
        rejected_esp: 4_000_000_000_000,
        fee_esp: 119_000_000,
        size_bytes: 119,
        fee_per_byte: 1_000_000,
        accepted_by_terms: vec![TermsTotal {
            service: xonly(1),
            redeemable_after_day: DAY,
            esp: 4_000_000_000_000,
        }],
        rejected_by_terms: vec![],
    };
    json("Totals", &totals);
    let signed = SignedOutput {
        signature: key(80),
        key: key(81),
        keyset: "2122232425262728".into(),
    };
    json("SignedOutput", &signed);
    let view = EntryView {
        status: Status::Declined,
        owed_esp: 3_999_881_000_000,
        fee_per_byte: 1_000_000,
        fee_esp: 119_000_000,
        payment_ref: Some("ref-1".into()),
        decline_reason: Some("no".into()),
        decline_signatures: vec![signed.clone()],
    };
    json("EntryView", &view);
    for (name, status) in [
        ("Status_open", Status::Open),
        ("Status_declined", Status::Declined),
        ("Status_completed", Status::Completed),
    ] {
        json(name, &status);
    }
    json(
        "RedeemResponse",
        &RedeemResponse {
            notes: results,
            accepted_esp: 4_000_000_000_000,
            rejected_esp: 4_000_000_000_000,
            fee_esp: 119_000_000,
            size_bytes: 119,
            fee_per_byte: 1_000_000,
            owed_esp: 3_999_881_000_000,
            message: "queued".into(),
            refund: vec![signed],
            entry: Some(view),
        },
    );

    // Rollover.
    let rollover = RolloverRequest {
        service: xonly(1),
        redeemable_after_day: DAY,
        input_keysets: vec!["0102030405060708".into(), "1112131415161718".into()],
        inputs: vec![input(4, 90), input(2, 92)],
        keyset: "2122232425262728".into(),
        outputs: vec![output(4, 100), output(2, 101)],
    };
    json("RolloverRequest", &rollover);
    line("RolloverRequest_digest", hex::encode(rollover.digest()));
    line("RolloverRequest_hash", rollover.hash());
    json(
        "RolloverResponse",
        &RolloverResponse {
            keyset: "2122232425262728".into(),
            epoch: 3,
            service: xonly(1),
            redeemable_after_day: DAY,
            signatures: vec![key(110), key(111)],
            keys: vec![key(112), key(113)],
        },
    );
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
}

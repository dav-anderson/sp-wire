//! The FSP bodies and encodings, pinned to what the v0.1.0 mint wrote.
//!
//! A failure here means a byte of the wire changed: bump `WIRE_VERSION`.

use std::collections::BTreeMap;

use mint_types::{Amount, BlindNonce, MintInput, MintOutput, Nonce, Note};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, PublicKey, SECP256K1, SecretKey};
use sp_wire::ServiceDid;
use sp_wire::fsp::{
    self as api, FeesResponse, FspInput, GroupResult, HandedEsp, IssueGroup, IssueRequest,
    IssueResponse, KeysResponse, KeysetWindow, Refusal, RotationResponse, SpendRequest,
    SpendResponse,
};

const GOLDEN: &str = include_str!("golden/fsp.txt");

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

fn pair(n: u8) -> Keypair {
    Keypair::from_seckey_slice(SECP256K1, &[n; 32]).unwrap()
}

fn key(n: u8) -> PublicKey {
    pair(n).public_key()
}

fn did(n: u8) -> ServiceDid {
    ServiceDid::from(key(n))
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

fn window(n: u8) -> KeysetWindow {
    KeysetWindow {
        id: format!("{:02x}{:02x}030405060708", n, n),
        epoch: n as u64,
        starts: Some(1_800_000_000),
        current_until: None,
        retires: Some(1_800_007_200),
    }
}

#[test]
fn the_fsp_wire_bytes_are_unchanged() {
    line("MAX_MEMO_BYTES", api::MAX_MEMO_BYTES);
    line("issue_group_size_0_0", api::issue_group_size(0, 0));
    line("issue_group_size_2_3", api::issue_group_size(2, 3));

    // Issue.
    let handed = |amount: u64, n: u8| HandedEsp {
        amount,
        note: note(n),
        spend_secret: SecretKey::from_slice(&[n; 32]).unwrap(),
        keyset: "0102030405060708".into(),
    };
    let issue = IssueRequest {
        service: did(1),
        groups: vec![
            IssueGroup {
                redeemable_after_day: 20_500,
                notes: vec![handed(4, 10), handed(2, 12)],
                outputs: vec![output(4, 20), output(2, 21)],
            },
            IssueGroup {
                redeemable_after_day: 20_600,
                notes: vec![handed(8, 14)],
                outputs: vec![output(8, 22)],
            },
        ],
    };
    json("IssueRequest", &issue);
    line("IssueRequest_hash", issue.hash());
    json(
        "IssueResponse",
        &IssueResponse {
            groups: vec![
                GroupResult::Issued {
                    keyset: "2122232425262728".into(),
                    signatures: vec![key(30), key(31)],
                    keys: vec![key(32), key(33)],
                    fee: 500,
                },
                GroupResult::Refused {
                    code: "keyset_retired".into(),
                    why: "gone".into(),
                },
            ],
            fee_per_byte: 7,
        },
    );

    // Spend.
    let spend = SpendRequest {
        inputs: vec![
            FspInput {
                keyset: "0102030405060708".into(),
                input: input(4, 40),
            },
            FspInput {
                keyset: "1112131415161718".into(),
                input: input(2, 42),
            },
        ],
        outputs: vec![output(4, 50)],
        pay: 2,
        memo: "memo".into(),
    };
    json("SpendRequest", &spend);
    line("SpendRequest_digest", hex::encode(spend.digest()));
    line("SpendRequest_hash", spend.hash());
    json(
        "SpendResponse",
        &SpendResponse {
            keyset: "2122232425262728".into(),
            signatures: vec![key(60)],
            keys: vec![key(61)],
            paid: 2,
        },
    );

    // Keys, fees, refusal, rotation.
    let mut keyset = BTreeMap::new();
    keyset.insert(1u64, key(70));
    keyset.insert(2u64, key(71));
    let mut keysets = BTreeMap::new();
    keysets.insert("0102030405060708".to_string(), keyset);
    json(
        "KeysResponse",
        &KeysResponse {
            service: Some(did(1)),
            current: "0102030405060708".into(),
            previous: None,
            keysets,
            next_rotation: Some(1_800_007_200),
        },
    );
    json(
        "FeesResponse",
        &FeesResponse {
            issue_fee_per_byte: 7,
            issue_group_fixed_bytes: 16,
            issue_note_bytes: 106,
            issue_output_bytes: 41,
            max_request_bytes: 1_048_576,
            issue_max_items: Some(1000),
            spend_max_items: None,
            spend_max_memo_bytes: None,
        },
    );
    json(
        "Refusal",
        &Refusal {
            error: "nope".into(),
            code: "malformed_request".into(),
        },
    );
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

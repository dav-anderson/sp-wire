//! What each request hash and digest covers.
//!
//! A hash is the key an answer is stored under, and a digest is what the
//! signatures cover. If one leaves a field out, two different requests share a
//! key (a retry gets someone else's answer) or a signature covers less than it
//! seems to. So for each: change one field at a time and the value must change,
//! and the same request must give the same value.
//!
//! These are built from the real request types. The bytes themselves are
//! pinned in `golden_*.rs`; here the point is that no field is missing.

use mint_types::{Amount, BlindNonce, MintInput, MintOutput, Nonce, Note};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, PublicKey, SECP256K1, SecretKey};
use sp_wire::ServiceDid;
use sp_wire::esp::redeem::{
    self, DEFAULT_MAX_MEMO_BYTES, FORMAT_VERSION, INPUT_BYTES, RedeemInput, RedeemOutput,
    RedeemRequest,
};
use sp_wire::esp::rollover::RolloverRequest as EspRolloverRequest;
use sp_wire::esp::transfer::{self, TransferRequest};
use sp_wire::fsp::{FspInput, HandedEsp, IssueGroup, IssueRequest, SpendRequest};
use sp_wire::psp::RolloverRequest as PspRolloverRequest;

const KEYSET_A: &str = "0102030405060708";
const KEYSET_B: &str = "1112131415161718";
const KEYSET_C: &str = "2122232425262728";
const DAY: u64 = 20_500;

fn key(n: u8) -> PublicKey {
    Keypair::from_seckey_slice(SECP256K1, &[n; 32])
        .unwrap()
        .public_key()
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

/// Change one thing in a fresh copy of a request and say the value changed.
/// `$make` builds the request, `$value` turns one into the hash or digest,
/// `$base` is the value of the unchanged request, `$what` names the change.
macro_rules! changes {
    ($make:expr, $value:expr, $base:expr, $what:expr, |$r:ident| $edit:block) => {{
        let mut $r = $make;
        $edit
        assert_ne!(($value)(&$r), $base, "unchanged when {}", $what);
    }};
}

/// Change one thing and say the value did not change.
macro_rules! ignores {
    ($make:expr, $value:expr, $base:expr, $what:expr, |$r:ident| $edit:block) => {{
        let mut $r = $make;
        $edit
        assert_eq!(($value)(&$r), $base, "changed when {}", $what);
    }};
}

// ---- fsp-mint ---------------------------------------------------------------

fn handed(units: u64, n: u8) -> HandedEsp {
    HandedEsp {
        amount: units,
        note: note(n),
        spend_secret: SecretKey::from_slice(&[n; 32]).unwrap(),
        keyset: KEYSET_A.into(),
    }
}

fn group(day: u64, n: u8) -> IssueGroup {
    IssueGroup {
        redeemable_after_day: day,
        notes: vec![handed(4, n), handed(8, n + 10)],
        outputs: vec![output(6, n + 20), output(6, n + 30)],
    }
}

fn issue_request() -> IssueRequest {
    IssueRequest {
        service: did(1),
        groups: vec![group(DAY, 40), group(DAY + 100, 80)],
    }
}

fn fsp_issue_hash_covers_every_field() {
    let base = issue_request().hash();
    let hash = IssueRequest::hash;
    assert_eq!(base, issue_request().hash(), "the same request");
    assert_eq!(base, issue_request().clone().hash(), "a copy");

    changes!(issue_request(), hash, base, "the service", |r| {
        r.service = did(2);
    });
    changes!(issue_request(), hash, base, "a group is dropped", |r| {
        r.groups.pop();
    });
    changes!(issue_request(), hash, base, "a group is added", |r| {
        r.groups.push(group(DAY + 200, 120));
    });
    changes!(issue_request(), hash, base, "the groups swap", |r| {
        r.groups.swap(0, 1);
    });
    changes!(issue_request(), hash, base, "a group's day", |r| {
        r.groups[1].redeemable_after_day += 1;
    });
    // A note moves to the next group: the counts change, the notes do not.
    changes!(issue_request(), hash, base, "a note moves group", |r| {
        let n = r.groups[0].notes.pop().unwrap();
        r.groups[1].notes.insert(0, n);
    });

    // Every field of a note.
    changes!(issue_request(), hash, base, "a note's amount", |r| {
        r.groups[0].notes[1].amount += 1;
    });
    changes!(issue_request(), hash, base, "a note's nonce", |r| {
        r.groups[1].notes[0].note.nonce = Nonce(key(200));
    });
    changes!(issue_request(), hash, base, "a note's signature", |r| {
        r.groups[1].notes[1].note.signature = key(200);
    });
    changes!(issue_request(), hash, base, "a note's spend secret", |r| {
        r.groups[0].notes[0].spend_secret = SecretKey::from_slice(&[200; 32]).unwrap()
    });
    changes!(issue_request(), hash, base, "a note's keyset", |r| {
        r.groups[1].notes[1].keyset = KEYSET_B.into();
    });
    changes!(issue_request(), hash, base, "a note is dropped", |r| {
        r.groups[0].notes.pop();
    });
    changes!(issue_request(), hash, base, "the notes swap", |r| {
        r.groups[0].notes.swap(0, 1);
    });

    // Every field of an output.
    changes!(issue_request(), hash, base, "an output's amount", |r| {
        r.groups[0].outputs[0].amount = Amount::from_units(7);
    });
    changes!(
        issue_request(),
        hash,
        base,
        "an output's blind nonce",
        |r| {
            r.groups[1].outputs[1].blind_nonce = BlindNonce(key(200));
        }
    );
    changes!(issue_request(), hash, base, "an output is dropped", |r| {
        r.groups[1].outputs.pop();
    });
    changes!(issue_request(), hash, base, "the outputs swap", |r| {
        r.groups[0].outputs.swap(0, 1);
    });

    // A keyset is length-prefixed: moving a character from one note's keyset
    // to the next one's is a different request.
    let split = |a: &str, b: &str| {
        let mut r = issue_request();
        r.groups[0].notes[0].keyset = a.into();
        r.groups[0].notes[1].keyset = b.into();
        r.hash()
    };
    assert_ne!(split("ab", "c"), split("a", "bc"));
}

fn spend_request() -> SpendRequest {
    let fsp_input = |units, n, keyset: &str| FspInput {
        keyset: keyset.into(),
        input: input(units, n),
    };
    SpendRequest {
        inputs: vec![fsp_input(4, 10, KEYSET_A), fsp_input(8, 12, KEYSET_B)],
        outputs: vec![output(5, 40), output(5, 42)],
        pay: 2,
        memo: "memo".into(),
    }
}

fn fsp_spend_hash_covers_every_field() {
    let base = spend_request().hash();
    let hash = SpendRequest::hash;
    assert_eq!(base, spend_request().hash(), "the same request");

    changes!(spend_request(), hash, base, "pay", |r| {
        r.pay += 1;
    });
    changes!(spend_request(), hash, base, "the memo", |r| {
        r.memo = "memo2".into();
    });
    changes!(spend_request(), hash, base, "an empty memo", |r| {
        r.memo = String::new();
    });

    // Every field of an input.
    changes!(spend_request(), hash, base, "an input's keyset", |r| {
        r.inputs[1].keyset = KEYSET_C.into();
    });
    changes!(spend_request(), hash, base, "an input's amount", |r| {
        r.inputs[0].input.amount = Amount::from_units(5);
    });
    changes!(spend_request(), hash, base, "an input's nonce", |r| {
        r.inputs[1].input.note.nonce = Nonce(key(200));
    });
    changes!(
        spend_request(),
        hash,
        base,
        "an input's spend signature",
        |r| {
            r.inputs[0].input.spend_signature = sig(200);
        }
    );
    changes!(spend_request(), hash, base, "an input is dropped", |r| {
        r.inputs.pop();
    });
    changes!(spend_request(), hash, base, "the inputs swap", |r| {
        r.inputs.swap(0, 1);
    });

    // Every field of an output.
    changes!(spend_request(), hash, base, "an output's amount", |r| {
        r.outputs[1].amount = Amount::from_units(6);
    });
    changes!(
        spend_request(),
        hash,
        base,
        "an output's blind nonce",
        |r| {
            r.outputs[0].blind_nonce = BlindNonce(key(200));
        }
    );
    changes!(spend_request(), hash, base, "an output is dropped", |r| {
        r.outputs.pop();
    });
    changes!(spend_request(), hash, base, "the outputs swap", |r| {
        r.outputs.swap(0, 1);
    });

    // The hash adds the spend signatures, the note signatures and the keysets to
    // the digest, which has none of the signatures. A note's signature is the
    // mint's, on its nonce: a request that differs only there is another request.
    changes!(
        spend_request(),
        hash,
        base,
        "an input's note signature",
        |r| {
            r.inputs[1].input.note.signature = key(200);
        }
    );
    let digest = spend_request().digest();
    let mut resigned = spend_request();
    resigned.inputs[0].input.spend_signature = sig(200);
    resigned.inputs[1].input.note.signature = key(200);
    assert_eq!(resigned.digest(), digest, "the digest has no signature");

    // Keysets are length-prefixed: moving a character between two inputs'
    // keysets is a different request.
    let split = |a: &str, b: &str| {
        let mut r = spend_request();
        r.inputs[0].keyset = a.into();
        r.inputs[1].keyset = b.into();
        r.hash()
    };
    assert_ne!(split("ab", "c"), split("a", "bc"));
}

#[test]
fn the_fsp_issue_and_spend_hashes_cover_every_field() {
    fsp_issue_hash_covers_every_field();
    fsp_spend_hash_covers_every_field();
}

// ---- rollover (ESP and PSP) --------------------------------------------------

fn esp_rollover() -> EspRolloverRequest {
    EspRolloverRequest {
        service: did(1),
        redeemable_after_day: DAY,
        input_keysets: vec![KEYSET_A.into(), KEYSET_B.into()],
        inputs: vec![input(4, 10), input(8, 12)],
        keyset: KEYSET_C.into(),
        outputs: vec![output(4, 40), output(8, 42)],
    }
}

fn psp_rollover() -> PspRolloverRequest {
    PspRolloverRequest {
        input_keysets: vec![KEYSET_A.into(), KEYSET_B.into()],
        inputs: vec![input(4, 10), input(8, 12)],
        keyset: KEYSET_C.into(),
        outputs: vec![output(4, 40), output(8, 42)],
    }
}

fn rollover_covers_every_field_esp() {
    let base = esp_rollover().hash();
    let hash = EspRolloverRequest::hash;
    assert_eq!(base, esp_rollover().hash(), "the same request");

    changes!(esp_rollover(), hash, base, "the service", |r| {
        r.service = did(2);
    });
    changes!(esp_rollover(), hash, base, "the day", |r| {
        r.redeemable_after_day += 1;
    });
    changes!(esp_rollover(), hash, base, "an input's keyset", |r| {
        r.input_keysets[1] = KEYSET_C.into();
    });
    changes!(
        esp_rollover(),
        hash,
        base,
        "an input keyset is dropped",
        |r| {
            r.input_keysets.pop();
        }
    );
    changes!(
        esp_rollover(),
        hash,
        base,
        "an input keyset is added",
        |r| {
            r.input_keysets.push(KEYSET_A.into());
        }
    );
    changes!(esp_rollover(), hash, base, "the output keyset", |r| {
        r.keyset = KEYSET_A.into();
    });
    changes!(esp_rollover(), hash, base, "an input's amount", |r| {
        r.inputs[0].amount = Amount::from_units(5);
    });
    changes!(esp_rollover(), hash, base, "an input's nonce", |r| {
        r.inputs[1].note.nonce = Nonce(key(200));
    });
    changes!(
        esp_rollover(),
        hash,
        base,
        "an input's note signature",
        |r| {
            r.inputs[0].note.signature = key(200);
        }
    );
    changes!(
        esp_rollover(),
        hash,
        base,
        "an input's spend signature",
        |r| {
            r.inputs[1].spend_signature = sig(200);
        }
    );
    changes!(esp_rollover(), hash, base, "an input is dropped", |r| {
        r.inputs.pop();
    });
    changes!(esp_rollover(), hash, base, "an output's amount", |r| {
        r.outputs[0].amount = Amount::from_units(5);
    });
    changes!(esp_rollover(), hash, base, "an output's blind nonce", |r| {
        r.outputs[1].blind_nonce = BlindNonce(key(200))
    });
    changes!(esp_rollover(), hash, base, "an output is dropped", |r| {
        r.outputs.pop();
    });

    // A keyset moves one character into the next field.
    let split = |last_input: &str, output_keyset: &str| {
        let mut r = esp_rollover();
        r.input_keysets = vec![last_input.into()];
        r.keyset = output_keyset.into();
        r.hash()
    };
    assert_ne!(split("ab", "c"), split("a", "bc"));
    let between_inputs = |a: &str, b: &str| {
        let mut r = esp_rollover();
        r.input_keysets = vec![a.into(), b.into()];
        r.hash()
    };
    assert_ne!(between_inputs("ab", "c"), between_inputs("a", "bc"));
}

fn rollover_covers_every_field_psp() {
    let base = psp_rollover().hash();
    let hash = PspRolloverRequest::hash;
    assert_eq!(base, psp_rollover().hash(), "the same request");

    changes!(psp_rollover(), hash, base, "an input's keyset", |r| {
        r.input_keysets[0] = KEYSET_C.into();
    });
    changes!(
        psp_rollover(),
        hash,
        base,
        "an input keyset is dropped",
        |r| {
            r.input_keysets.pop();
        }
    );
    changes!(
        psp_rollover(),
        hash,
        base,
        "an input keyset is added",
        |r| {
            r.input_keysets.push(KEYSET_A.into());
        }
    );
    changes!(psp_rollover(), hash, base, "the output keyset", |r| {
        r.keyset = KEYSET_A.into();
    });
    changes!(psp_rollover(), hash, base, "an input's amount", |r| {
        r.inputs[1].amount = Amount::from_units(9);
    });
    changes!(psp_rollover(), hash, base, "an input's nonce", |r| {
        r.inputs[0].note.nonce = Nonce(key(200));
    });
    changes!(
        psp_rollover(),
        hash,
        base,
        "an input's note signature",
        |r| {
            r.inputs[1].note.signature = key(200);
        }
    );
    changes!(
        psp_rollover(),
        hash,
        base,
        "an input's spend signature",
        |r| {
            r.inputs[0].spend_signature = sig(200);
        }
    );
    changes!(psp_rollover(), hash, base, "an input is dropped", |r| {
        r.inputs.pop();
    });
    changes!(psp_rollover(), hash, base, "an output's amount", |r| {
        r.outputs[1].amount = Amount::from_units(9);
    });
    changes!(psp_rollover(), hash, base, "an output's blind nonce", |r| {
        r.outputs[0].blind_nonce = BlindNonce(key(200))
    });
    changes!(psp_rollover(), hash, base, "an output is dropped", |r| {
        r.outputs.pop();
    });

    let split = |last_input: &str, output_keyset: &str| {
        let mut r = psp_rollover();
        r.input_keysets = vec![last_input.into()];
        r.keyset = output_keyset.into();
        r.hash()
    };
    assert_ne!(split("ab", "c"), split("a", "bc"));
    let between_inputs = |a: &str, b: &str| {
        let mut r = psp_rollover();
        r.input_keysets = vec![a.into(), b.into()];
        r.hash()
    };
    assert_ne!(between_inputs("ab", "c"), between_inputs("a", "bc"));
}

#[test]
fn both_rollover_hashes_cover_every_input_and_every_keyset_field() {
    rollover_covers_every_field_esp();
    rollover_covers_every_field_psp();
}

// ---- esp-mint: transfer -------------------------------------------------------

fn transfer_request() -> TransferRequest {
    TransferRequest {
        service: did(1),
        redeemable_after_day: DAY,
        input_keysets: vec![KEYSET_A.into(), KEYSET_B.into()],
        inputs: vec![input(4, 10), input(8, 12)],
        keyset: KEYSET_C.into(),
        outputs: vec![output(6, 40), output(6, 42)],
        service_signature: sig(5),
    }
}

#[test]
fn the_transfer_digest_and_request_hash_cover_every_field() {
    let digest = TransferRequest::digest;
    let hash = transfer::request_hash;
    let base_digest = transfer_request().digest();
    let base_hash = transfer::request_hash(&transfer_request());
    assert_eq!(base_digest, transfer_request().digest(), "the same request");
    assert_eq!(base_hash, hash(&transfer_request().clone()), "a copy");
    assert_eq!(
        transfer::digest(
            &did(1),
            DAY,
            &transfer_request().inputs,
            &transfer_request().outputs
        ),
        base_digest,
        "the free function and the method agree"
    );

    // What the signatures cover moves the digest and, with it, the hash.
    macro_rules! both {
        ($what:expr, |$r:ident| $edit:block) => {
            changes!(transfer_request(), digest, base_digest, $what, |$r| {
                $edit;
            });
            changes!(transfer_request(), hash, base_hash, $what, |$r| {
                $edit;
            });
        };
    }
    both!("the service", |r| {
        r.service = did(2);
    });
    both!("the day", |r| {
        r.redeemable_after_day += 1;
    });
    both!("an input's amount", |r| {
        r.inputs[1].amount = Amount::from_units(9);
    });
    both!("an input's nonce", |r| {
        r.inputs[0].note.nonce = Nonce(key(200));
    });
    both!("the inputs swap", |r| {
        r.inputs.swap(0, 1);
    });
    both!("an input is dropped", |r| {
        r.inputs.pop();
    });
    both!("an input is added", |r| {
        r.inputs.push(input(1, 60));
    });
    both!("an output's amount", |r| {
        r.outputs[0].amount = Amount::from_units(7);
    });
    both!("an output's blind nonce", |r| {
        r.outputs[1].blind_nonce = BlindNonce(key(200));
    });
    both!("the outputs swap", |r| {
        r.outputs.swap(0, 1);
    });
    both!("an output is dropped", |r| {
        r.outputs.pop();
    });

    // The signatures are not in the digest (they sign it) but are in the hash.
    ignores!(
        transfer_request(),
        digest,
        base_digest,
        "a spend signature",
        |r| {
            r.inputs[1].spend_signature = sig(200);
        }
    );
    ignores!(
        transfer_request(),
        digest,
        base_digest,
        "the service signature",
        |r| {
            r.service_signature = sig(200);
        }
    );
    changes!(
        transfer_request(),
        hash,
        base_hash,
        "the service signature",
        |r| {
            r.service_signature = sig(200);
        }
    );
    changes!(
        transfer_request(),
        hash,
        base_hash,
        "the first spend signature",
        |r| {
            r.inputs[0].spend_signature = sig(200);
        }
    );
    changes!(
        transfer_request(),
        hash,
        base_hash,
        "the second spend signature",
        |r| {
            r.inputs[1].spend_signature = sig(201);
        }
    );
    // A note's own signature (the mint's, on its nonce) is in the hash, in the
    // first input and in the second, and not in the digest.
    changes!(
        transfer_request(),
        hash,
        base_hash,
        "the first input's note signature",
        |r| {
            r.inputs[0].note.signature = key(200);
        }
    );
    changes!(
        transfer_request(),
        hash,
        base_hash,
        "the second input's note signature",
        |r| {
            r.inputs[1].note.signature = key(201);
        }
    );
    ignores!(
        transfer_request(),
        digest,
        base_digest,
        "a note's signature",
        |r| {
            r.inputs[0].note.signature = key(200);
        }
    );

    // Every keyset field is in the hash, with its length.
    changes!(
        transfer_request(),
        hash,
        base_hash,
        "an input's keyset",
        |r| {
            r.input_keysets[0] = KEYSET_C.into();
        }
    );
    changes!(
        transfer_request(),
        hash,
        base_hash,
        "an input keyset is dropped",
        |r| {
            r.input_keysets.pop();
        }
    );
    changes!(
        transfer_request(),
        hash,
        base_hash,
        "the output keyset",
        |r| {
            r.keyset = KEYSET_A.into();
        }
    );
    let split = |last_input: &str, output_keyset: &str| {
        let mut r = transfer_request();
        r.input_keysets = vec![last_input.into()];
        r.keyset = output_keyset.into();
        transfer::request_hash(&r)
    };
    assert_ne!(split("ab", "c"), split("a", "bc"));
    let between_inputs = |a: &str, b: &str| {
        let mut r = transfer_request();
        r.input_keysets = vec![a.into(), b.into()];
        transfer::request_hash(&r)
    };
    assert_ne!(between_inputs("ab", "c"), between_inputs("a", "bc"));
}

#[test]
fn a_transfer_request_survives_json_with_its_digest_and_request_hash() {
    let request = transfer_request();
    let text = serde_json::to_string(&request).unwrap();
    let back: TransferRequest = serde_json::from_str(&text).unwrap();
    assert_eq!(back.digest(), request.digest());
    assert_eq!(
        transfer::request_hash(&back),
        transfer::request_hash(&request)
    );
    assert_eq!(back.input_keysets, request.input_keysets);
    assert_eq!(back.keyset, request.keyset);
    assert_eq!(back.service_signature, request.service_signature);
}

// ---- esp-mint: redeem ---------------------------------------------------------

fn redeem_input(n: u8) -> RedeemInput {
    RedeemInput {
        service: did(1),
        redeemable_after_day: DAY,
        keyset: KEYSET_A.into(),
        input: input(4, n),
    }
}

fn redeem_output(n: u8) -> RedeemOutput {
    RedeemOutput {
        service: did(1),
        redeemable_after_day: DAY,
        output: output(2, n),
    }
}

fn redeem_request() -> RedeemRequest {
    RedeemRequest {
        service: did(1),
        output_keyset: KEYSET_C.into(),
        inputs: vec![redeem_input(10), redeem_input(12)],
        memo: "payout".into(),
        decline_outputs: vec![redeem_output(20)],
        refund_outputs: vec![redeem_output(22), redeem_output(24)],
        service_signature: sig(5),
    }
}

#[test]
fn the_redeem_digest_and_request_hash_cover_every_field_and_the_hash_every_byte() {
    let digest = RedeemRequest::digest;
    let hash = redeem::request_hash;
    let base_digest = redeem_request().digest();
    let base_hash = redeem::request_hash(&redeem_request());
    let r = redeem_request();
    assert_eq!(base_digest, redeem_request().digest(), "the same request");
    assert_eq!(base_hash, hash(&redeem_request()), "the same request");
    assert_eq!(
        redeem::digest(
            &r.service,
            &r.output_keyset,
            &r.inputs,
            &r.memo,
            &r.decline_outputs,
            &r.refund_outputs
        ),
        base_digest,
        "the free function and the method agree"
    );

    // What the signatures cover moves the digest and, with it, the hash.
    macro_rules! both {
        ($what:expr, |$r:ident| $edit:block) => {
            changes!(redeem_request(), digest, base_digest, $what, |$r| {
                $edit;
            });
            changes!(redeem_request(), hash, base_hash, $what, |$r| {
                $edit;
            });
        };
    }
    both!("the signing service", |r| {
        r.service = did(2);
    });
    both!("the output keyset", |r| {
        r.output_keyset = KEYSET_A.into();
    });
    both!("the memo", |r| {
        r.memo = "payout!".into();
    });
    both!("an empty memo", |r| {
        r.memo = String::new();
    });
    both!("an input's day", |r| {
        r.inputs[1].redeemable_after_day += 1;
    });
    both!("an input's service", |r| {
        r.inputs[0].service = did(2);
    });
    both!("an input's keyset", |r| {
        r.inputs[1].keyset = KEYSET_B.into();
    });
    both!("an input's amount", |r| {
        r.inputs[0].input.amount = Amount::from_units(5);
    });
    both!("an input's nonce", |r| {
        r.inputs[1].input.note.nonce = Nonce(key(200));
    });
    both!("an input's note signature", |r| {
        r.inputs[0].input.note.signature = key(200);
    });
    both!("the inputs swap", |r| {
        r.inputs.swap(0, 1);
    });
    both!("an input is dropped", |r| {
        r.inputs.pop();
    });
    both!("an output's day", |r| {
        r.decline_outputs[0].redeemable_after_day += 1;
    });
    both!("an output's service", |r| {
        r.refund_outputs[1].service = did(2);
    });
    both!("an output's amount", |r| {
        r.refund_outputs[0].output.amount = Amount::from_units(3);
    });
    both!("an output's blind nonce", |r| {
        r.decline_outputs[0].output.blind_nonce = BlindNonce(key(200));
    });
    both!("an output is dropped", |r| {
        r.refund_outputs.pop();
    });
    // The two lists are not interchangeable: the same outputs as a decline
    // list and as a refund list are different requests.
    both!("the decline and refund lists swap", |r| {
        std::mem::swap(&mut r.decline_outputs, &mut r.refund_outputs);
    });
    both!("an output moves between the lists", |r| {
        let o = r.refund_outputs.remove(0);
        r.decline_outputs.push(o);
    });

    // The digest is what the signatures sign, so it has none of them. The
    // hash covers every one.
    ignores!(
        redeem_request(),
        digest,
        base_digest,
        "a spend signature",
        |r| {
            r.inputs[0].input.spend_signature = sig(200);
        }
    );
    ignores!(
        redeem_request(),
        digest,
        base_digest,
        "the service signature",
        |r| {
            r.service_signature = sig(200);
        }
    );
    changes!(
        redeem_request(),
        hash,
        base_hash,
        "a spend signature",
        |r| {
            r.inputs[1].input.spend_signature = sig(200);
        }
    );
    changes!(
        redeem_request(),
        hash,
        base_hash,
        "the service signature",
        |r| {
            r.service_signature = sig(200);
        }
    );

    // The hash covers every byte of the encoding: any one-bit change that still
    // reads as a request gives a request with a different hash. (Changes that
    // make an invalid key, a bad version or a bad length do not read.)
    let bytes = redeem::encode(&redeem_request());
    let mut read_back = 0;
    for at in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[at] ^= 0x01;
        if let Ok(other) = redeem::decode(&changed) {
            read_back += 1;
            assert_ne!(
                redeem::request_hash(&other),
                base_hash,
                "byte {at} changed and the request hash did not"
            );
        }
    }
    assert!(
        read_back > 100,
        "only {read_back} of {} changes read as a request, so the loop proves little",
        bytes.len()
    );
}

#[test]
fn a_redeem_request_survives_its_encoding_with_every_field() {
    for request in [
        redeem_request(),
        RedeemRequest {
            memo: String::new(),
            inputs: vec![redeem_input(10)],
            decline_outputs: vec![],
            refund_outputs: vec![],
            ..redeem_request()
        },
    ] {
        let bytes = redeem::encode(&request);
        assert_eq!(request.encode(), bytes, "the method and the function");
        let back = redeem::decode(&bytes).unwrap();
        assert_eq!(redeem::encode(&back), bytes);
        assert_eq!(back.digest(), request.digest());
        assert_eq!(redeem::request_hash(&back), redeem::request_hash(&request));
        assert_eq!(back.service, request.service);
        assert_eq!(back.output_keyset, request.output_keyset);
        assert_eq!(back.inputs, request.inputs);
        assert_eq!(back.memo, request.memo);
        assert_eq!(back.decline_outputs, request.decline_outputs);
        assert_eq!(back.refund_outputs, request.refund_outputs);
        assert_eq!(back.service_signature, request.service_signature);
    }
}

#[test]
fn a_redeem_body_that_is_not_exactly_one_request_is_refused_with_its_reason() {
    let request = redeem_request();
    let bytes = redeem::encode(&request);

    // Where things are: version 1, service 33, output keyset 8, input count 4,
    // then the inputs, then the memo length and the memo.
    let first_input = 1 + 33 + 8 + 4;
    let nonce_of_first_input = first_input + 33 + 8 + 8 + 8;
    let memo_length = first_input + INPUT_BYTES as usize * request.inputs.len();
    assert_eq!(bytes[0], FORMAT_VERSION);
    assert_eq!(&bytes[memo_length + 2..memo_length + 8], b"payout");

    let refused = |changed: &[u8], needle: &str| {
        let why = redeem::decode(changed).expect_err(needle);
        assert!(why.contains(needle), "{why:?} does not say {needle:?}");
    };

    // Every truncation, down to nothing.
    for len in 0..bytes.len() {
        assert!(redeem::decode(&bytes[..len]).is_err(), "cut to {len}");
    }
    // A byte after the end, and the whole thing twice.
    let mut longer = bytes.clone();
    longer.push(0);
    refused(&longer, "after its end");
    refused(&[bytes.clone(), bytes.clone()].concat(), "after its end");

    // The version byte.
    let with_version = |v: u8| {
        let mut b = bytes.clone();
        b[0] = v;
        b
    };
    refused(&with_version(0), "version");
    refused(&with_version(4), "version");
    refused(&with_version(1), "no keysets");
    refused(&with_version(2), "x-only");

    // A service id and a nonce that are not points.
    let mut b = bytes.clone();
    b[1] = 0x05;
    refused(&b, "service");
    let mut b = bytes.clone();
    b[nonce_of_first_input] = 0x05;
    refused(&b, "nonce");

    // A count that is more than the body can hold.
    let mut b = bytes.clone();
    b[1 + 33 + 8..1 + 33 + 8 + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    refused(&b, "counts more");

    // A memo that is too long, by its length and by the limit asked for, and
    // one that is not UTF-8.
    let mut b = bytes.clone();
    b[memo_length..memo_length + 2]
        .copy_from_slice(&((DEFAULT_MAX_MEMO_BYTES + 1) as u16).to_be_bytes());
    refused(&b, "memo");
    assert!(redeem::decode_with(&bytes, 6).is_ok());
    let why = redeem::decode_with(&bytes, 5).err().unwrap();
    assert!(why.contains("memo"), "{why:?}");
    let mut b = bytes.clone();
    b[memo_length + 2] = 0xff;
    refused(&b, "UTF-8");

    // And the unchanged body reads.
    assert!(redeem::decode(&bytes).is_ok());
}

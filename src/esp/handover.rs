//! The file that hands ESP notes to a service.
//!
//! fsp-mint's `export-esp` writes one of these for each redeemable-after day of
//! the ESP it holds, and the service's wallet reads it with its `receive`
//! command. The same shape is the wallet's own record of what it handed to an
//! FSP mint. The three crates read and write it through the types here, so the
//! file is the same on both ends.
//!
//! **Whoever holds the file holds the notes.** Each note comes with its spend
//! secret, and a note is spent by whoever has the secret. Treat the file like
//! cash: keep it private, move it by a channel you trust, and delete it once
//! the wallet has taken the notes. (The notes name the service, so only the
//! service can ask the ESP mint to move or redeem them, but the file is still
//! the whole of what the service needs to do so.)
//!
//! The format is pinned by a test in this file. A change to a field name or to
//! how a field is written changes what files already written can be read, so
//! it is a change to the wire.

use mint_types::Note;
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};

use crate::service::ServiceDid;

/// ESP notes handed to a service: the service they name, the day they become
/// redeemable, and each note with its spend secret. All the notes of one file
/// share the service and the day.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handover {
    /// The service the notes name (its AIR DID, 66 hex characters).
    pub service: ServiceDid,
    /// The day the notes become redeemable (days since the Unix epoch).
    pub redeemable_after_day: u64,
    pub notes: Vec<HandedNote>,
}

/// One ESP note in a [`Handover`], with the secret that spends it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandedNote {
    pub amount: u64,
    pub note: Note,
    /// The secret key of the note's nonce. Whoever has it can spend the note.
    pub spend_secret: SecretKey,
    /// The ESP keyset that signed the note (16 hex characters), so whoever
    /// spends it can name the keyset the mint checks it under. Required and not
    /// empty: a file without it, or with an empty one, does not read.
    pub keyset: String,
}

impl Handover {
    /// Read a hand-over file. It must be JSON of the shape above, with a keyset
    /// on every note (not an empty one; the error names the note), and hold at
    /// least one note. The error says what is wrong.
    ///
    /// This reads the file; it does not check the notes. That each note's spend
    /// secret matches its nonce, that the notes are not already held and that
    /// the mint signed them are for the wallet that receives them.
    pub fn read(bytes: &[u8]) -> Result<Handover, String> {
        let handover: Handover =
            serde_json::from_slice(bytes).map_err(|e| format!("not a hand-over file: {e}"))?;
        if handover.notes.is_empty() {
            return Err("the hand-over file holds no notes".into());
        }
        if let Some(at) = handover.notes.iter().position(|n| n.keyset.is_empty()) {
            return Err(format!(
                "note {} of the hand-over file names no keyset (its keyset is empty)",
                at + 1
            ));
        }
        Ok(handover)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mint_types::Nonce;
    use secp256k1::{Keypair, PublicKey, SECP256K1};

    /// A hand-over file as the code writes it: the fields in the order of the
    /// structs, no spaces. The notes and the service are the ones of the
    /// `IssueRequest` golden in `tests/golden/fsp.txt`, which the v0.1.0 mints
    /// wrote themselves.
    const FILE: &str = r#"{"service":"031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f","redeemable_after_day":20500,"notes":[{"amount":4,"note":{"nonce":"03f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6e","signature":"02552c630b64b54bf50210c9e253d38bd4949c72e22873500f6285c2bede312a84"},"spend_secret":"0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a","keyset":"0102030405060708"},{"amount":2,"note":{"nonce":"030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d177","signature":"022f1b310f4c065331bc0d79ba4661bb9822d67d7c4a1b0a1892e1fd0cd23aa68d"},"spend_secret":"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c","keyset":"0102030405060708"}]}"#;

    /// The same file as `fsp-mint export-esp` writes it: pretty-printed from a
    /// `serde_json::Value`, which sorts the keys.
    const FSP_MINT_FILE: &str = r#"{
  "notes": [
    {
      "amount": 4,
      "keyset": "0102030405060708",
      "note": {
        "nonce": "03f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6e",
        "signature": "02552c630b64b54bf50210c9e253d38bd4949c72e22873500f6285c2bede312a84"
      },
      "spend_secret": "0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"
    },
    {
      "amount": 2,
      "keyset": "0102030405060708",
      "note": {
        "nonce": "030f0fb9a244ad31a369ee02b7abfbbb0bfa3812b9a39ed93346d03d67d412d177",
        "signature": "022f1b310f4c065331bc0d79ba4661bb9822d67d7c4a1b0a1892e1fd0cd23aa68d"
      },
      "spend_secret": "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"
    }
  ],
  "redeemable_after_day": 20500,
  "service": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
}"#;

    fn key(n: u8) -> PublicKey {
        Keypair::from_seckey_slice(SECP256K1, &[n; 32])
            .unwrap()
            .public_key()
    }

    fn handed(amount: u64, n: u8) -> HandedNote {
        HandedNote {
            amount,
            note: Note {
                nonce: Nonce(key(n)),
                signature: key(n + 1),
            },
            spend_secret: SecretKey::from_slice(&[n; 32]).unwrap(),
            keyset: "0102030405060708".into(),
        }
    }

    fn handover() -> Handover {
        Handover {
            service: ServiceDid::from(key(1)),
            redeemable_after_day: 20_500,
            notes: vec![handed(4, 10), handed(2, 12)],
        }
    }

    #[test]
    fn a_handover_file_is_pinned_and_round_trips() {
        // The file is exactly this text. If this assertion fails, the format
        // changed: files already written (by fsp-mint, by wallets) may no
        // longer read. That is a change to the wire; do not edit the literal
        // to make the test pass.
        assert_eq!(serde_json::to_string(&handover()).unwrap(), FILE);
        // It reads back to the same value, through `read` and through serde.
        assert_eq!(Handover::read(FILE.as_bytes()).unwrap(), handover());
        assert_eq!(serde_json::from_str::<Handover>(FILE).unwrap(), handover());
        // What fsp-mint writes today (the keys in another order, indented) is
        // the same file.
        assert_eq!(
            Handover::read(FSP_MINT_FILE.as_bytes()).unwrap(),
            handover()
        );
        // Writing and reading again changes nothing.
        let written = serde_json::to_vec_pretty(&handover()).unwrap();
        assert_eq!(Handover::read(&written).unwrap(), handover());
    }

    #[test]
    fn a_bad_handover_file_is_refused() {
        let read = |text: &str| Handover::read(text.as_bytes());
        let refused = |text: &str, needle: &str| {
            let why = read(text).expect_err(needle);
            assert!(why.contains(needle), "{why:?} does not say {needle:?}");
            why
        };
        // Each case below is the good file with one thing wrong, so the good
        // file reading is what shows the one thing is the cause.
        assert!(read(FILE).is_ok());
        let prefix = "not a hand-over file: ";

        // No keyset on a note (every note has one).
        let keyset = r#","keyset":"0102030405060708""#;
        assert_eq!(FILE.matches(keyset).count(), 2);
        let why = refused(&FILE.replace(keyset, ""), "missing field `keyset`");
        assert!(why.starts_with(prefix), "{why:?}");
        // An empty keyset is no keyset, and the error says which note: the
        // first, then only the second.
        let first_empty = FILE.replacen(keyset, r#","keyset":"""#, 1);
        assert_eq!(
            read(&first_empty),
            Err("note 1 of the hand-over file names no keyset (its keyset is empty)".into())
        );
        let second = FILE.rfind(keyset).unwrap();
        let mut second_empty = FILE.to_string();
        second_empty.replace_range(second..second + keyset.len(), r#","keyset":"""#);
        assert_eq!(
            read(&second_empty),
            Err("note 2 of the hand-over file names no keyset (its keyset is empty)".into())
        );
        // Only the second note lacks it.
        let mut one_missing = FILE.to_string();
        one_missing.replace_range(second..second + keyset.len(), "");
        refused(&one_missing, "missing field `keyset`");

        // A service that is not a 33-byte DID: the 32-byte x-only form, and
        // text that is not hex.
        let service = &FILE[FILE.find(r#""service":""#).unwrap() + 11..][..66];
        assert_eq!(service, ServiceDid::from(key(1)).to_hex());
        let why = refused(&FILE.replace(service, &service[2..]), "x-only");
        assert!(why.starts_with(prefix), "{why:?}");
        refused(&FILE.replace(service, &"zz".repeat(33)), "must be hex");

        // No notes.
        let empty = format!(r#"{{"service":"{service}","redeemable_after_day":20500,"notes":[]}}"#);
        assert_eq!(
            read(&empty),
            Err("the hand-over file holds no notes".into())
        );

        // A spend secret that is not 32 bytes of hex: too short, not hex.
        let secret = "0a".repeat(32);
        assert!(FILE.contains(&secret));
        let why = read(&FILE.replace(&secret, &"0a".repeat(31))).expect_err("31 bytes");
        assert!(why.starts_with(prefix), "{why:?}");
        let why = read(&FILE.replace(&secret, &"zz".repeat(32))).expect_err("not hex");
        assert!(why.starts_with(prefix), "{why:?}");

        // Not JSON at all, and JSON cut short.
        let why = refused("hello", "expected value");
        assert!(why.starts_with(prefix), "{why:?}");
        assert!(read("").unwrap_err().starts_with(prefix));
        assert!(
            read(&FILE[..FILE.len() / 2])
                .unwrap_err()
                .starts_with(prefix)
        );
        // JSON of another shape.
        assert!(read("[]").unwrap_err().starts_with(prefix));
        assert!(read("{}").unwrap_err().starts_with(prefix));
    }
}

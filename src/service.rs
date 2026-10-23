//! The service ID: an AIR DID, 33 bytes.
//!
//! A service is named by its AIR DID everywhere on the wire and in config: in the
//! terms of an ESP note, in the requests of the ESP and FSP mints, in the redemption
//! encoding, in `fsp-mint`'s `service.did`, in the wallet's `--service` and in the
//! storage lists. The ID is the DID itself, with no conversion: the 33-byte
//! compressed secp256k1 public key (a `02` or `03` byte, then the 32-byte x
//! coordinate), written as 66 lower-case hex characters in config and JSON.
//!
//! # Why 33 bytes and not the x-only key
//!
//! Until wire version 3 a service was its 32-byte x-only key, and a DID was reduced
//! to it. The AIR names a service by its DID, so an ID that is not the DID needs a
//! conversion at every boundary (and loses the parity byte, which the AIR's
//! encryption to the DID needs). The ID is now exactly the DID. The parity byte is
//! part of the ID: the same x coordinate with `02` and with `03` are two different
//! IDs (they are two different DIDs in the AIR too). A service uses the DID it
//! publishes, exactly.
//!
//! # Signing
//!
//! BIP340 signatures are checked against an x-only key. That conversion is an
//! implementation detail of the code that checks a signature, [`ServiceDid::x_only`],
//! and is never an ID. A signature made by the secret key of either parity checks
//! against the x-only half, so the parity byte does not matter to signing.
//!
//! # Refusals
//!
//! There is no second format and no migration: nothing was live. A 64-character
//! (x-only) ID is refused with [`DidError::XOnly`], which says what changed, so a
//! config or command line from wire version 2 fails with a reason.

use std::fmt;
use std::str::FromStr;

use secp256k1::{PublicKey, XOnlyPublicKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::payload::DID_LEN;

/// A service's ID: its AIR DID, a 33-byte compressed public key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceDid([u8; DID_LEN]);

impl ServiceDid {
    /// Parse 66 hex characters (upper or lower case, spaces around them
    /// forgiven). The key must be a valid curve point.
    pub fn parse(text: &str) -> Result<ServiceDid, DidError> {
        let text = text.trim();
        if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(DidError::NotHex(text.to_string()));
        }
        match text.len() {
            n if n == 2 * DID_LEN => {}
            64 => return Err(DidError::XOnly(text.to_string())),
            n => return Err(DidError::BadLength(n)),
        }
        let bytes = hex::decode(text).map_err(|_| DidError::NotHex(text.to_string()))?;
        ServiceDid::from_slice(&bytes)
    }

    /// From exactly 33 bytes (the binary encodings). The key must be a valid
    /// curve point.
    pub fn from_slice(bytes: &[u8]) -> Result<ServiceDid, DidError> {
        if bytes.len() != DID_LEN {
            return Err(DidError::BadLength(bytes.len() * 2));
        }
        PublicKey::from_slice(bytes)
            .map(ServiceDid::from)
            .map_err(|_| DidError::NotAKey(hex::encode(bytes)))
    }

    /// The 33 bytes of the compressed key, as they go on the wire and into every
    /// digest.
    pub fn serialize(&self) -> [u8; DID_LEN] {
        self.0
    }

    /// The same 33 bytes, borrowed.
    pub fn as_bytes(&self) -> &[u8; DID_LEN] {
        &self.0
    }

    /// The 66-character lower-case hex form.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from_slice(&self.0).expect("checked when the ID was made")
    }

    /// The x-only half, for checking a BIP340 signature. For signing code only:
    /// it drops the parity byte, so it is never an ID.
    pub fn x_only(&self) -> XOnlyPublicKey {
        self.public_key().x_only_public_key().0
    }
}

impl From<PublicKey> for ServiceDid {
    fn from(key: PublicKey) -> Self {
        ServiceDid(key.serialize())
    }
}

impl From<&PublicKey> for ServiceDid {
    fn from(key: &PublicKey) -> Self {
        ServiceDid(key.serialize())
    }
}

impl fmt::Display for ServiceDid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for ServiceDid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServiceDid({})", self.to_hex())
    }
}

impl FromStr for ServiceDid {
    type Err = DidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ServiceDid::parse(s)
    }
}

impl Serialize for ServiceDid {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ServiceDid {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        ServiceDid::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// Why a service ID was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DidError {
    /// Not hexadecimal.
    NotHex(String),
    /// Not 66 characters. Holds the number of characters found.
    BadLength(usize),
    /// 64 characters: a 32-byte x-only key, the form of wire version 2.
    XOnly(String),
    /// 66 characters but not a valid compressed key.
    NotAKey(String),
}

impl fmt::Display for DidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DidError::NotHex(s) => write!(f, "`{s}` is not a service ID: it must be hex"),
            DidError::BadLength(n) => write!(
                f,
                "a service ID is a 33-byte AIR DID: 66 hex characters starting 02 or 03, not {n}"
            ),
            DidError::XOnly(s) => write!(
                f,
                "`{s}` is a 32-byte x-only key (64 hex characters), the form wire version 2 used. \
                 A service ID is now the service's 33-byte AIR DID: 66 hex characters starting 02 or 03. \
                 Use the DID the service publishes; adding 02 or 03 by hand names another service if the byte is wrong"
            ),
            DidError::NotAKey(s) => write!(f, "`{s}` is not a valid public key"),
        }
    }
}

impl std::error::Error for DidError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The x coordinates of G, 2G and 3G. G and 2G have an even y, so their DIDs
    /// start `02`.
    const G: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const G2: &str = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

    #[test]
    fn a_service_id_is_a_33_byte_did() {
        let a = ServiceDid::parse(&format!("02{G}")).unwrap();
        assert_eq!(a.to_hex(), format!("02{G}"));
        assert_eq!(a.to_string(), format!("02{G}"));
        assert_eq!(a.serialize().len(), 33);
        assert_eq!(a.serialize()[0], 0x02);
        assert_eq!(hex::encode(&a.serialize()[1..]), G);
        assert_eq!(a.as_bytes(), &a.serialize());
        // Upper case and spaces are forgiven and written back normalised.
        let messy = format!("  02{}\n", G.to_uppercase());
        assert_eq!(ServiceDid::parse(&messy).unwrap(), a);
        assert_eq!(format!("02{G}").parse::<ServiceDid>().unwrap(), a);
        // It is the key, both ways.
        assert_eq!(ServiceDid::from(a.public_key()), a);
        assert_eq!(ServiceDid::from(&a.public_key()), a);
        assert_eq!(hex::encode(a.x_only().serialize()), G);
        // A point is 33 bytes, and the ID is its serialization byte for byte;
        // the payload's DID field is the same 33 bytes.
        assert_eq!(a.public_key().serialize().len(), 33);
        assert_eq!(a.serialize(), a.public_key().serialize());
        assert_eq!(crate::payload::DID_LEN, 33);
    }

    #[test]
    fn the_parity_byte_is_part_of_the_id() {
        let even = ServiceDid::parse(&format!("02{G}")).unwrap();
        let odd = ServiceDid::parse(&format!("03{G}")).unwrap();
        assert_ne!(even, odd);
        assert_ne!(even.to_hex(), odd.to_hex());
        // Signing sees only the x coordinate, so both check the same signatures.
        assert_eq!(even.x_only(), odd.x_only());
        // They order and hash as different IDs.
        assert!(even < odd);
        assert_ne!(
            ServiceDid::parse(&format!("02{G2}")).unwrap(),
            ServiceDid::parse(&format!("02{G}")).unwrap()
        );
    }

    #[test]
    fn from_slice_wants_exactly_33_valid_bytes() {
        let bytes = hex::decode(format!("02{G}")).unwrap();
        assert_eq!(
            ServiceDid::from_slice(&bytes).unwrap().to_hex(),
            format!("02{G}")
        );
        assert_eq!(
            ServiceDid::from_slice(&bytes[1..]),
            Err(DidError::BadLength(64))
        );
        assert_eq!(ServiceDid::from_slice(&[]), Err(DidError::BadLength(0)));
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(ServiceDid::from_slice(&long), Err(DidError::BadLength(68)));
        let mut bad_prefix = bytes;
        bad_prefix[0] = 0x05;
        assert!(matches!(
            ServiceDid::from_slice(&bad_prefix),
            Err(DidError::NotAKey(_))
        ));
    }

    #[test]
    fn a_bad_service_id_is_refused_with_the_reason() {
        assert_eq!(
            ServiceDid::parse("xyz"),
            Err(DidError::NotHex("xyz".into()))
        );
        assert_eq!(ServiceDid::parse(""), Err(DidError::BadLength(0)));
        // 65 characters, and 68.
        let short = format!("02{}", &G[..63]);
        assert_eq!(ServiceDid::parse(&short), Err(DidError::BadLength(65)));
        let long = format!("02{G}00");
        assert_eq!(ServiceDid::parse(&long), Err(DidError::BadLength(68)));
        // The right length but not a point on the curve.
        let off = format!("02{}", "ff".repeat(32));
        assert_eq!(ServiceDid::parse(&off), Err(DidError::NotAKey(off)));
        // A prefix that is not 02 or 03.
        let bad = format!("05{G}");
        assert_eq!(ServiceDid::parse(&bad), Err(DidError::NotAKey(bad)));
        let bad = format!("00{G}");
        assert_eq!(ServiceDid::parse(&bad), Err(DidError::NotAKey(bad)));
        for e in [
            DidError::NotHex("x".into()),
            DidError::BadLength(3),
            DidError::XOnly("x".into()),
            DidError::NotAKey("x".into()),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn an_x_only_id_is_refused_and_the_reason_says_what_changed() {
        let e = ServiceDid::parse(G).unwrap_err();
        assert_eq!(e, DidError::XOnly(G.into()));
        let text = e.to_string();
        assert!(
            text.contains("x-only") && text.contains("33-byte AIR DID") && text.contains("66 hex"),
            "{text}"
        );
        // Upper case and spaces do not get past it either.
        assert!(matches!(
            ServiceDid::parse(&format!(" {} ", G.to_uppercase())),
            Err(DidError::XOnly(_))
        ));
    }

    #[test]
    fn json_is_a_66_character_hex_string() {
        let a = ServiceDid::parse(&format!("02{G}")).unwrap();
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, format!("\"02{G}\""));
        assert_eq!(serde_json::from_str::<ServiceDid>(&json).unwrap(), a);
        // The old form fails with the reason.
        let err = serde_json::from_str::<ServiceDid>(&format!("\"{G}\"")).unwrap_err();
        assert!(err.to_string().contains("x-only"), "{err}");
        assert!(serde_json::from_str::<ServiceDid>("\"nope\"").is_err());
        assert!(serde_json::from_str::<ServiceDid>("5").is_err());
    }
}

//! The storage policy: which AIR services keep a kind of data, and in what
//! order.
//!
//! This is configuration only. Nothing in this module reads or writes the AIR,
//! opens a file or makes a request: it is the one parser and checker that the
//! three mints and the wallet share, so that a service list means the same thing
//! in all four and a bad one is refused the same way.
//!
//! # The setting
//!
//! One setting per [`DataKind`], each an ordered list of service IDs. Index 0 is
//! the **primary**; the rest are **secondaries**, in the order they would be
//! promoted. In a config file a list is a TOML array of strings or one string; in
//! the environment it is one string with the IDs separated by commas:
//!
//! ```text
//! PSP_STORAGE_MINT_STATE=79be...1798,c604...9ee5
//! ```
//!
//! - **One entry** is valid: one service holds the data, and the mint or wallet
//!   keeps a local backup copy ([`Redundancy::SingleWithLocalBackup`]).
//! - **An empty list** (the default) means local only
//!   ([`Redundancy::LocalOnly`]): nothing is sent to a service.
//! - Two or more mean the data is replicated ([`Redundancy::Replicated`]).
//!
//! # A service ID
//!
//! A service ID is the service's 32-byte x-only public key, written as 64 hex
//! characters (the same form as `fsp-mint`'s `service.did` and the wallet's
//! `--service`). A 33-byte compressed DID key (66 hex characters, starting `02`
//! or `03`) is accepted too and reduced to its x-only key, because the two name
//! the same service. IDs are stored and printed as 64 lower-case hex characters,
//! so the same service written two ways is one service (and a duplicate if listed
//! twice). The key must be a valid curve point.
//!
//! # Limits
//!
//! At most [`MAX_SERVICES`] entries, no duplicates, no empty entry (`a,,b`). The
//! limit is a sanity check and can be raised.
//!
//! The planned behaviour of a policy (replication, promotion, sequence numbers)
//! is for the mints and the wallet to build on this type (copies on a primary and
//! at least one secondary, only the mint promoting a secondary, sequence numbers
//! on writes). None of it is built here.

use std::fmt;
use std::str::FromStr;

use secp256k1::{PublicKey, XOnlyPublicKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The most services one policy may list.
pub const MAX_SERVICES: usize = 8;

/// A service's ID: its 32-byte x-only public key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceId([u8; 32]);

impl ServiceId {
    /// Parse 64 hex characters (x-only key) or 66 (compressed DID key).
    pub fn parse(text: &str) -> Result<ServiceId, StorageError> {
        let text = text.trim();
        if !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(StorageError::NotHex(text.to_string()));
        }
        if text.len() != 64 && text.len() != 66 {
            return Err(StorageError::BadLength(text.len()));
        }
        let bytes = hex::decode(text).map_err(|_| StorageError::NotHex(text.to_string()))?;
        let x_only = match bytes.len() {
            32 => XOnlyPublicKey::from_slice(&bytes)
                .map_err(|_| StorageError::NotAKey(text.to_string()))?,
            33 => {
                PublicKey::from_slice(&bytes)
                    .map_err(|_| StorageError::NotAKey(text.to_string()))?
                    .x_only_public_key()
                    .0
            }
            _ => return Err(StorageError::BadLength(text.len())),
        };
        Ok(ServiceId(x_only.serialize()))
    }

    /// The 32 bytes of the x-only key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The key itself.
    pub fn x_only(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_slice(&self.0).expect("checked when the ID was made")
    }

    /// The 64-character lower-case hex form.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl From<XOnlyPublicKey> for ServiceId {
    fn from(key: XOnlyPublicKey) -> Self {
        ServiceId(key.serialize())
    }
}

impl fmt::Display for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServiceId({})", self.to_hex())
    }
}

impl FromStr for ServiceId {
    type Err = StorageError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ServiceId::parse(s)
    }
}

impl Serialize for ServiceId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ServiceId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        ServiceId::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// Why a service ID or a list of them was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageError {
    /// Not hexadecimal.
    NotHex(String),
    /// Neither 64 nor 66 characters. Holds the length found.
    BadLength(usize),
    /// The right length but not a valid key.
    NotAKey(String),
    /// An empty entry in the list. Holds its 1-based position.
    EmptyEntry(usize),
    /// A service listed twice. Holds its ID.
    Duplicate(String),
    /// More than [`MAX_SERVICES`]. Holds the count.
    TooMany(usize),
    /// A kind of data that does not exist.
    UnknownKind(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::NotHex(s) => write!(f, "`{s}` is not a service ID: it must be hex"),
            StorageError::BadLength(n) => write!(
                f,
                "a service ID is 64 hex characters (a 32-byte x-only key) or 66 (a 33-byte DID key), not {n}"
            ),
            StorageError::NotAKey(s) => write!(f, "`{s}` is not a valid public key"),
            StorageError::EmptyEntry(n) => write!(
                f,
                "entry {n} of the service list is empty (check for a doubled or trailing comma)"
            ),
            StorageError::Duplicate(s) => write!(f, "service {s} is listed twice"),
            StorageError::TooMany(n) => write!(
                f,
                "{n} services listed, but at most {MAX_SERVICES} are allowed"
            ),
            StorageError::UnknownKind(s) => write!(
                f,
                "`{s}` is not a kind of data: use mint_state, wallet or app"
            ),
        }
    }
}

impl std::error::Error for StorageError {}

/// A kind of data a policy is set for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DataKind {
    /// A mint's state: keys, spent lists, issue records, queues.
    MintState,
    /// A wallet's notes and requests.
    Wallet,
    /// An app's own data.
    App,
}

impl DataKind {
    /// Every kind, in the order they are listed.
    pub const ALL: [DataKind; 3] = [DataKind::MintState, DataKind::Wallet, DataKind::App];

    /// The name used in a setting's key (`storage.<name>`).
    pub fn name(self) -> &'static str {
        match self {
            DataKind::MintState => "mint_state",
            DataKind::Wallet => "wallet",
            DataKind::App => "app",
        }
    }

    /// The setting's key in a config file: `storage.<name>`.
    pub fn key(self) -> &'static str {
        match self {
            DataKind::MintState => "storage.mint_state",
            DataKind::Wallet => "storage.wallet",
            DataKind::App => "storage.app",
        }
    }
}

impl FromStr for DataKind {
    type Err = StorageError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DataKind::ALL
            .into_iter()
            .find(|k| k.name() == s.trim())
            .ok_or_else(|| StorageError::UnknownKind(s.trim().to_string()))
    }
}

/// How a policy keeps the data, by how many services it lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Redundancy {
    /// No service: the data stays local.
    LocalOnly,
    /// One service, with a local backup copy.
    SingleWithLocalBackup,
    /// A primary and at least one secondary.
    Replicated,
}

impl fmt::Display for Redundancy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Redundancy::LocalOnly => "local only",
            Redundancy::SingleWithLocalBackup => "one service, with a local backup copy",
            Redundancy::Replicated => "a primary and secondaries",
        })
    }
}

/// An ordered list of service IDs for one kind of data: index 0 is the primary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoragePolicy {
    services: Vec<ServiceId>,
}

impl StoragePolicy {
    /// A policy from IDs already parsed. Refuses duplicates and too many.
    pub fn new(services: Vec<ServiceId>) -> Result<StoragePolicy, StorageError> {
        if services.len() > MAX_SERVICES {
            return Err(StorageError::TooMany(services.len()));
        }
        for (i, id) in services.iter().enumerate() {
            if services[..i].contains(id) {
                return Err(StorageError::Duplicate(id.to_hex()));
            }
        }
        Ok(StoragePolicy { services })
    }

    /// Parse the setting's text: IDs separated by commas, spaces around them
    /// allowed. Empty (or only spaces) is the empty list.
    pub fn parse(text: &str) -> Result<StoragePolicy, StorageError> {
        if text.trim().is_empty() {
            return Ok(StoragePolicy::default());
        }
        let mut services = Vec::new();
        for (i, item) in text.split(',').enumerate() {
            if item.trim().is_empty() {
                return Err(StorageError::EmptyEntry(i + 1));
            }
            services.push(ServiceId::parse(item)?);
        }
        StoragePolicy::new(services)
    }

    /// Every service, primary first.
    pub fn services(&self) -> &[ServiceId] {
        &self.services
    }

    /// The primary: index 0, if any.
    pub fn primary(&self) -> Option<&ServiceId> {
        self.services.first()
    }

    /// The secondaries, in promotion order.
    pub fn secondaries(&self) -> &[ServiceId] {
        self.services.get(1..).unwrap_or(&[])
    }

    /// No service is listed.
    pub fn is_local_only(&self) -> bool {
        self.services.is_empty()
    }

    /// Whether `id` is in the list, as primary or secondary.
    pub fn contains(&self, id: &ServiceId) -> bool {
        self.services.contains(id)
    }

    /// How the data is kept.
    pub fn redundancy(&self) -> Redundancy {
        match self.services.len() {
            0 => Redundancy::LocalOnly,
            1 => Redundancy::SingleWithLocalBackup,
            _ => Redundancy::Replicated,
        }
    }

    /// The setting as it is written: the IDs, comma-separated, in 64-character
    /// lower-case hex. Empty for local only. `parse` of this gives the same policy.
    pub fn to_config_string(&self) -> String {
        self.services
            .iter()
            .map(ServiceId::to_hex)
            .collect::<Vec<_>>()
            .join(",")
    }

    /// One line for a startup log: how the data is kept and by whom.
    pub fn describe(&self) -> String {
        match self.primary() {
            None => format!("{}", self.redundancy()),
            Some(p) if self.secondaries().is_empty() => {
                format!("{} (primary {p})", self.redundancy())
            }
            Some(p) => format!(
                "{} (primary {p}, {} secondar{})",
                self.redundancy(),
                self.secondaries().len(),
                if self.secondaries().len() == 1 {
                    "y"
                } else {
                    "ies"
                }
            ),
        }
    }
}

impl fmt::Display for StoragePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_config_string())
    }
}

impl FromStr for StoragePolicy {
    type Err = StorageError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        StoragePolicy::parse(s)
    }
}

impl Serialize for StoragePolicy {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.services.serialize(s)
    }
}

impl<'de> Deserialize<'de> for StoragePolicy {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let services = Vec::<ServiceId>::deserialize(d)?;
        StoragePolicy::new(services).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// x-only keys of G, 2G and 3G.
    const G: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const G2: &str = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const G3: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

    #[test]
    fn a_service_id_is_an_x_only_key_or_a_did_key_reduced_to_one() {
        let a = ServiceId::parse(G).unwrap();
        assert_eq!(a.to_hex(), G);
        assert_eq!(a.to_string(), G);
        // The 33-byte DID key of the same service, either parity.
        assert_eq!(ServiceId::parse(&format!("02{G}")).unwrap(), a);
        assert_eq!(ServiceId::parse(&format!("03{G}")).unwrap(), a);
        // Upper case and spaces are forgiven and written back normalised.
        assert_eq!(
            ServiceId::parse(&format!("  {}\n", G.to_uppercase())).unwrap(),
            a
        );
        assert_eq!(a.x_only().serialize(), *a.as_bytes());
        assert_eq!(ServiceId::from(a.x_only()), a);
        assert_eq!(G.parse::<ServiceId>().unwrap(), a);
    }

    #[test]
    fn a_bad_service_id_is_refused_with_the_reason() {
        assert_eq!(
            ServiceId::parse("xyz"),
            Err(StorageError::NotHex("xyz".into()))
        );
        assert_eq!(ServiceId::parse(""), Err(StorageError::BadLength(0)));
        assert_eq!(ServiceId::parse(&G[..62]), Err(StorageError::BadLength(62)));
        // 33 bytes, but the first is not a key prefix.
        let long = format!("{G}00");
        assert_eq!(ServiceId::parse(&long), Err(StorageError::NotAKey(long)));
        // The right length but not a point on the curve.
        let off = "ff".repeat(32);
        assert_eq!(ServiceId::parse(&off), Err(StorageError::NotAKey(off)));
        // A 33-byte key with a prefix that is not 02 or 03.
        let bad = format!("05{G}");
        assert_eq!(ServiceId::parse(&bad), Err(StorageError::NotAKey(bad)));
        for e in [
            StorageError::NotHex("x".into()),
            StorageError::BadLength(3),
            StorageError::NotAKey("x".into()),
            StorageError::EmptyEntry(2),
            StorageError::Duplicate("x".into()),
            StorageError::TooMany(9),
            StorageError::UnknownKind("x".into()),
        ] {
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn a_policy_keeps_the_order_and_index_0_is_the_primary() {
        let p = StoragePolicy::parse(&format!("{G2}, {G},{G3}")).unwrap();
        let hexes: Vec<String> = p.services().iter().map(ServiceId::to_hex).collect();
        assert_eq!(hexes, vec![G2, G, G3]);
        assert_eq!(p.primary().unwrap().to_hex(), G2);
        assert_eq!(p.secondaries().len(), 2);
        assert_eq!(p.secondaries()[0].to_hex(), G);
        assert!(p.contains(&ServiceId::parse(G3).unwrap()));
        assert!(!p.is_local_only());
        assert_eq!(p.redundancy(), Redundancy::Replicated);
        // Written back normalised, and that parses to the same policy.
        assert_eq!(p.to_config_string(), format!("{G2},{G},{G3}"));
        assert_eq!(StoragePolicy::parse(&p.to_config_string()).unwrap(), p);
        assert_eq!(p.to_string(), p.to_config_string());
        assert!(p.describe().contains("2 secondaries"), "{}", p.describe());
    }

    #[test]
    fn one_service_is_valid_and_empty_means_local_only() {
        let one = StoragePolicy::parse(G).unwrap();
        assert_eq!(one.primary().unwrap().to_hex(), G);
        assert!(one.secondaries().is_empty());
        assert_eq!(one.redundancy(), Redundancy::SingleWithLocalBackup);
        assert!(
            one.describe().contains("local backup"),
            "{}",
            one.describe()
        );
        assert!(one.describe().contains(G));

        for empty in ["", "   ", "\n"] {
            let p = StoragePolicy::parse(empty).unwrap();
            assert!(p.is_local_only());
            assert_eq!(p.primary(), None);
            assert!(p.secondaries().is_empty());
            assert_eq!(p.redundancy(), Redundancy::LocalOnly);
            assert_eq!(p.to_config_string(), "");
            assert_eq!(p, StoragePolicy::default());
        }
        assert_eq!(StoragePolicy::default().describe(), "local only");
    }

    #[test]
    fn empty_entries_duplicates_and_too_many_are_refused() {
        assert_eq!(
            StoragePolicy::parse(&format!("{G},,{G2}")),
            Err(StorageError::EmptyEntry(2))
        );
        assert_eq!(
            StoragePolicy::parse(&format!("{G},")),
            Err(StorageError::EmptyEntry(2))
        );
        assert_eq!(
            StoragePolicy::parse(&format!(",{G}")),
            Err(StorageError::EmptyEntry(1))
        );
        // The same service twice, even written two ways.
        assert_eq!(
            StoragePolicy::parse(&format!("{G},{G2},02{G}")),
            Err(StorageError::Duplicate(G.into()))
        );
        // A bad entry is refused, naming it.
        assert!(matches!(
            StoragePolicy::parse(&format!("{G},nope")),
            Err(StorageError::NotHex(s)) if s == "nope"
        ));
        // The limit is checked on the list. Nine entries (repeating the three
        // known keys) are too many before duplicates are looked at.
        let known = [G, G2, G3].map(|s| ServiceId::parse(s).unwrap());
        let nine: Vec<ServiceId> = (0..=MAX_SERVICES).map(|i| known[i % 3]).collect();
        assert_eq!(
            StoragePolicy::new(nine),
            Err(StorageError::TooMany(MAX_SERVICES + 1))
        );
        assert_eq!(
            StoragePolicy::parse(&format!("{G},{G2},{G3}"))
                .unwrap()
                .services()
                .len(),
            3
        );
    }

    #[test]
    fn the_kinds_have_names_and_keys() {
        assert_eq!(DataKind::MintState.key(), "storage.mint_state");
        assert_eq!(DataKind::Wallet.key(), "storage.wallet");
        assert_eq!(DataKind::App.key(), "storage.app");
        for k in DataKind::ALL {
            assert_eq!(k.name().parse::<DataKind>().unwrap(), k);
            assert_eq!(k.key(), format!("storage.{}", k.name()));
        }
        assert_eq!(
            "database".parse::<DataKind>(),
            Err(StorageError::UnknownKind("database".into()))
        );
    }

    #[test]
    fn json_is_a_list_of_hex_strings() {
        let p = StoragePolicy::parse(&format!("{G},{G2}")).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(json, format!("[\"{G}\",\"{G2}\"]"));
        assert_eq!(serde_json::from_str::<StoragePolicy>(&json).unwrap(), p);
        assert!(serde_json::from_str::<StoragePolicy>(&format!("[\"{G}\",\"{G}\"]")).is_err());
        assert!(serde_json::from_str::<StoragePolicy>("[\"nope\"]").is_err());
        assert_eq!(
            serde_json::from_str::<StoragePolicy>("[]").unwrap(),
            StoragePolicy::default()
        );
    }
}

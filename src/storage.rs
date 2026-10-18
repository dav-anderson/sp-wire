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
//! PSP_STORAGE_MINT_STATE=0279be...1798,02c604...9ee5
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
//! A service ID is the service's AIR DID: the 33-byte compressed public key,
//! written as 66 hex characters starting `02` or `03` ([`ServiceDid`], the same
//! form as `fsp-mint`'s `service.did` and the wallet's `--service`). There is one
//! form and no conversion: a 64-character (x-only) ID, the form of wire version 2,
//! is refused with a reason. IDs are stored and printed as 66 lower-case hex
//! characters, so the same DID written in upper case or with spaces is one
//! service (and a duplicate if listed twice). The key must be a valid curve
//! point. The same x coordinate with `02` and with `03` are two services.
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

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub use crate::service::DidError;
use crate::service::ServiceDid;

/// The most services one policy may list.
pub const MAX_SERVICES: usize = 8;

/// Why a service ID or a list of them was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageError {
    /// An entry is not a service ID (not hex, the wrong length, the old x-only
    /// form, or not a key). The reason is the [`DidError`].
    BadId(DidError),
    /// An empty entry in the list. Holds its 1-based position.
    EmptyEntry(usize),
    /// A service listed twice. Holds its ID.
    Duplicate(String),
    /// More than [`MAX_SERVICES`]. Holds the count.
    TooMany(usize),
    /// A kind of data that does not exist.
    UnknownKind(String),
}

impl From<DidError> for StorageError {
    fn from(e: DidError) -> Self {
        StorageError::BadId(e)
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::BadId(e) => write!(f, "{e}"),
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
    services: Vec<ServiceDid>,
}

impl StoragePolicy {
    /// A policy from IDs already parsed. Refuses duplicates and too many.
    pub fn new(services: Vec<ServiceDid>) -> Result<StoragePolicy, StorageError> {
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
            services.push(ServiceDid::parse(item)?);
        }
        StoragePolicy::new(services)
    }

    /// Every service, primary first.
    pub fn services(&self) -> &[ServiceDid] {
        &self.services
    }

    /// The primary: index 0, if any.
    pub fn primary(&self) -> Option<&ServiceDid> {
        self.services.first()
    }

    /// The secondaries, in promotion order.
    pub fn secondaries(&self) -> &[ServiceDid] {
        self.services.get(1..).unwrap_or(&[])
    }

    /// No service is listed.
    pub fn is_local_only(&self) -> bool {
        self.services.is_empty()
    }

    /// Whether `id` is in the list, as primary or secondary.
    pub fn contains(&self, id: &ServiceDid) -> bool {
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

    /// The setting as it is written: the IDs, comma-separated, in 66-character
    /// lower-case hex. Empty for local only. `parse` of this gives the same policy.
    pub fn to_config_string(&self) -> String {
        self.services
            .iter()
            .map(ServiceDid::to_hex)
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
        let services = Vec::<ServiceDid>::deserialize(d)?;
        StoragePolicy::new(services).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The DIDs of G, 2G and 3G (the x coordinate with `02`: G, 2G and 3G all
    /// have an even y).
    const G: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const G2: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    const G3: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
    /// The x-only form of G, the old ID.
    const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    #[test]
    fn an_entry_is_a_service_did() {
        let a = ServiceDid::parse(G).unwrap();
        assert_eq!(a.to_hex(), G);
        let p = StoragePolicy::parse(&format!("  {}\n", G.to_uppercase())).unwrap();
        assert_eq!(p.primary(), Some(&a));
        assert_eq!(p.to_config_string(), G);
    }

    #[test]
    fn a_bad_entry_is_refused_with_the_reason() {
        assert_eq!(
            StoragePolicy::parse("xyz"),
            Err(StorageError::BadId(DidError::NotHex("xyz".into())))
        );
        assert_eq!(
            StoragePolicy::parse(&G[..62]),
            Err(StorageError::BadId(DidError::BadLength(62)))
        );
        // The old x-only form is refused, and the message says what changed.
        let e = StoragePolicy::parse(G_X).unwrap_err();
        assert_eq!(e, StorageError::BadId(DidError::XOnly(G_X.into())));
        assert!(e.to_string().contains("x-only"), "{e}");
        // Neither is it accepted as a second entry.
        assert!(matches!(
            StoragePolicy::parse(&format!("{G},{G_X}")),
            Err(StorageError::BadId(DidError::XOnly(_)))
        ));
        assert!(StoragePolicy::parse(&format!("05{G_X}")).is_err());
        for e in [
            StorageError::BadId(DidError::NotAKey("x".into())),
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
        let hexes: Vec<String> = p.services().iter().map(ServiceDid::to_hex).collect();
        assert_eq!(hexes, vec![G2, G, G3]);
        assert_eq!(p.primary().unwrap().to_hex(), G2);
        assert_eq!(p.secondaries().len(), 2);
        assert_eq!(p.secondaries()[0].to_hex(), G);
        assert!(p.contains(&ServiceDid::parse(G3).unwrap()));
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
        // The same DID twice, even written in upper case.
        assert_eq!(
            StoragePolicy::parse(&format!("{G},{G2},{}", G.to_uppercase())),
            Err(StorageError::Duplicate(G.into()))
        );
        // The same x coordinate with the other parity byte is another service.
        let odd = format!("03{}", &G[2..]);
        assert_eq!(
            StoragePolicy::parse(&format!("{G},{odd}"))
                .unwrap()
                .services()
                .len(),
            2
        );
        // A bad entry is refused, naming it.
        assert!(matches!(
            StoragePolicy::parse(&format!("{G},nope")),
            Err(StorageError::BadId(DidError::NotHex(s))) if s == "nope"
        ));
        // The limit is checked on the list. Nine entries (repeating the three
        // known keys) are too many before duplicates are looked at.
        let known = [G, G2, G3].map(|s| ServiceDid::parse(s).unwrap());
        let nine: Vec<ServiceDid> = (0..=MAX_SERVICES).map(|i| known[i % 3]).collect();
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
        assert!(serde_json::from_str::<StoragePolicy>(&format!("[\"{G_X}\"]")).is_err());
        assert_eq!(
            serde_json::from_str::<StoragePolicy>("[]").unwrap(),
            StoragePolicy::default()
        );
    }
}

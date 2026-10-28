//! The mints' key streams: how a mint publishes its public keys on AIR, and how
//! a wallet finds and reads them (ROADMAP item 31, finding P2-04, the mint
//! fingerprinting attack). Pure: no network. The transport helpers at the end
//! need the `air-client` feature.
//!
//! **Why.** A mint that signs one user's outputs with a key it uses for that
//! user alone, or gives one user a day nobody else has, can recognise that user's
//! notes when they come back. A wallet can only see this if every user can see
//! the same keys. So each mint publishes its keys where anyone can read them,
//! and a wallet checks every key in every reply against what was published.
//!
//! **Where.** Every record is one write-once cell of the mint's AIR service. A
//! cell's address is the mint's DID key moved by a tweak that anyone can compute
//! from the mint's DID and the cell's name ([`cell_address`]); only the mint can
//! compute the matching secret ([`cell_secret`]), so only the mint can write the
//! cell, and nobody can fill it first. (The mailbox slots of `addr` are the
//! opposite: anyone can write them, only the mint can read what is written.)
//! The records are plain: they hold public keys and are neither sealed nor
//! signed (signed keysets are ROADMAP item 34).
//!
//! **The cells.**
//!
//! | cell | what | written by |
//! |---|---|---|
//! | [`Cell::Keyset`] `n` | the `n`th key set (n from 0) of a PSP or FSP mint: its epoch and every (amount, key) | psp-mint, fsp-mint |
//! | [`Cell::Control`] `n` | the `n`th change of an ESP mint's maturity rule `m` or of its live generations | esp-mint |
//! | [`Cell::Day`] | the ESP keys for one generation, one day and one bucket of services, in parts | esp-mint |
//!
//! A wallet finds the end of a sequential stream by [`find_end`] (it probes cells
//! 0, 1, 2, 4, 8, ... for the first empty one and halves back, so it takes about
//! `2 log2 n` reads), reads the last records, and holds a read on the first empty
//! cell: AIR pushes the record when the mint writes it. A restarted wallet reads
//! forward from the cell it last knew.
//!
//! **The records** start with [`RECORD_VERSION`] and a kind byte. They are
//! deterministic: no time, no randomness. A mint that writes a record again (it
//! does not know whether the first write got through) writes the same bytes, and
//! the cell answers [`Written::AlreadyStored`](delivery::Written).
//!
//! | record | bytes |
//! |---|---|
//! | keyset (kind 1) | 1 + 1 + 8 (epoch) + 2 (n) + n x 41 (amount as 8 bytes big-endian, key as 33): 2,636 for 64 keys |
//! | control (kind 2) | 47, fixed: see [`ControlRecord`] |
//! | ESP day (kind 3) | 34 + services x 2,145 (the 33-byte DID, then the 64 keys of 2^0 to 2^63, 33 bytes each) |
//!
//! **The ESP day records.** The ESP mint's key for an amount is per generation,
//! service and day, so it publishes, for each live generation and each day it
//! serves, the 64 keys of every service ([`DayRecord`]). While the day's record
//! fits [`RECORD_MAX_BYTES`] or the size the operator set, it is one record that
//! holds every service, and every wallet reads the same record. Beyond that the
//! services are grouped into buckets by [`bucket_of`], a hash of the service's
//! DID, [`BUCKET_SERVICES`] services to a bucket; a wallet reads the whole bucket
//! its service is in. A bucket is read as parts 0, 1, 2, ... until a part is
//! empty: a service that appears after a day was written is added as a new part,
//! and a part never grows past the size. Part 0 of bucket 0 says how many buckets
//! the day has ([`DayRecord::buckets`]), so a wallet reads it first. What
//! remains: a connection that keeps reading the same few buckets can still be
//! recognised, less precisely than one that reads a service's own record.

use std::collections::BTreeMap;
use std::fmt;

use secp256k1::{PublicKey as Point, SECP256K1, Scalar, SecretKey as Scalar32};

use super::AirError;
use super::addr::{self, sha256};
use crate::ServiceDid;
use crate::keyset::keyset_id;
use crate::seal::{PublicKey, SecretKey};
use mint_types::Amount;

/// Label of the cell tweak.
pub const STREAM_LABEL: &[u8] = b"sp-stream-cell-v0";
/// Label of the bucket hash.
pub const BUCKET_LABEL: &[u8] = b"sp-esp-bucket-v0";

/// The first byte of every record.
pub const RECORD_VERSION: u8 = 1;
/// The second byte of a keyset record.
pub const RECORD_KEYSET: u8 = 1;
/// The second byte of a control record.
pub const RECORD_CONTROL: u8 = 2;
/// The second byte of an ESP day record.
pub const RECORD_DAY: u8 = 3;

/// The most keys in a keyset record: 2^0 to 2^63.
pub const MAX_KEYSET_KEYS: usize = 64;
/// Keys per service in an ESP day record: 2^0 to 2^63.
pub const ESP_KEYS_PER_SERVICE: usize = 64;
/// Bytes of a compressed key.
const KEY_BYTES: usize = 33;
/// Bytes of an ESP day record before its first service.
pub const DAY_HEADER_BYTES: usize = 34;
/// Bytes of one service in an ESP day record: its DID and 64 keys (2,145).
pub const SERVICE_ENTRY_BYTES: usize = KEY_BYTES + ESP_KEYS_PER_SERVICE * KEY_BYTES;
/// Bytes of a control record.
pub const CONTROL_BYTES: usize = 47;
/// Services to a bucket, once a day is split into buckets.
pub const BUCKET_SERVICES: usize = 256;
/// The most bytes a stream record may have: AIR's 16 MiB message cap less the
/// 1 MiB esp-mint keeps free for the envelope, the seal and the framing of any
/// message it writes. The operator's size setting can not go above it.
pub const RECORD_MAX_BYTES: usize = 15 * 1024 * 1024;

// ---------------------------------------------------------------- cells

/// The name of one cell of a mint's streams.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cell {
    /// The `index`th key set of a PSP or FSP mint.
    Keyset { index: u32 },
    /// The `index`th control record of an ESP mint.
    Control { index: u32 },
    /// One part of one bucket of one day of one generation of an ESP mint.
    Day(DayCell),
}

/// Where a part of an ESP day record is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DayCell {
    /// The generation's key-set ID, 8 bytes.
    pub generation: [u8; 8],
    /// The redeemable-after day.
    pub day: u64,
    /// The bucket, 0 to the day's bucket count less 1.
    pub bucket: u32,
    /// The part of the bucket, from 0.
    pub part: u32,
}

impl Cell {
    /// The cell's name as hashed: a kind byte and the fixed-width fields.
    pub fn path(&self) -> Vec<u8> {
        match self {
            Cell::Keyset { index } => [&[1u8][..], &index.to_be_bytes()[..]].concat(),
            Cell::Control { index } => [&[2u8][..], &index.to_be_bytes()[..]].concat(),
            Cell::Day(d) => [
                &[3u8][..],
                &d.generation[..],
                &d.day.to_be_bytes()[..],
                &d.bucket.to_be_bytes()[..],
                &d.part.to_be_bytes()[..],
            ]
            .concat(),
        }
    }
}

impl fmt::Display for Cell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Cell::Keyset { index } => write!(f, "key set record {index}"),
            Cell::Control { index } => write!(f, "control record {index}"),
            Cell::Day(d) => write!(
                f,
                "day {} of generation {}, bucket {} part {}",
                d.day,
                hex::encode(d.generation),
                d.bucket,
                d.part
            ),
        }
    }
}

/// `sha256("sp-stream-cell-v0" || mint DID || the cell's path)`: the tweak that
/// moves the mint's key to the cell's key.
pub fn cell_tweak(mint: &ServiceDid, cell: &Cell) -> [u8; 32] {
    sha256(&[STREAM_LABEL, &mint.as_bytes()[..], &cell.path()])
}

fn tweak_scalar(mint: &ServiceDid, cell: &Cell) -> Result<Scalar, AirError> {
    Scalar::from_be_bytes(cell_tweak(mint, cell)).map_err(|_| {
        AirError(format!(
            "the tweak of {cell} is not a valid scalar (a chance of about 2^-128)"
        ))
    })
}

/// The cell's address (what a read names): the mint's DID key plus the tweak
/// times the generator. Anyone can compute it from the mint's DID.
pub fn cell_address(mint: &ServiceDid, cell: &Cell) -> Result<PublicKey, AirError> {
    let base = Point::from_slice(&mint.as_bytes()[..])
        .map_err(|e| AirError(format!("the mint's DID is not a public key: {e}")))?;
    let moved = base
        .add_exp_tweak(SECP256K1, &tweak_scalar(mint, cell)?)
        .map_err(|e| AirError(format!("{cell}: the cell's key is not valid: {e}")))?;
    addr::bytes_to_key(&moved.serialize())
}

/// The cell's secret (what a write is signed with): the mint's DID secret plus
/// the tweak. Only the mint can compute it, and its public key is
/// [`cell_address`].
pub fn cell_secret(mint_key: &SecretKey, cell: &Cell) -> Result<SecretKey, AirError> {
    let mint = addr::key_to_did(&mint_key.public_key());
    let base = Scalar32::from_slice(&mint_key.to_array())
        .map_err(|e| AirError(format!("the mint's key is not valid: {e}")))?;
    let moved = base
        .add_tweak(&tweak_scalar(&mint, cell)?)
        .map_err(|e| AirError(format!("{cell}: the cell's secret is not valid: {e}")))?;
    SecretKey::from_array(moved.secret_bytes())
        .map_err(|_| AirError(format!("{cell}: the cell's secret is not valid")))
}

// ---------------------------------------------------------------- errors

/// A stream record that does not decode, or does not follow the rules of its
/// kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordError(pub String);

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RecordError {}

fn bad(text: impl Into<String>) -> RecordError {
    RecordError(text.into())
}

/// A cursor over the bytes of a record.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8], RecordError> {
        let end = self.at.checked_add(n).filter(|&e| e <= self.bytes.len());
        match end {
            Some(end) => {
                let out = &self.bytes[self.at..end];
                self.at = end;
                Ok(out)
            }
            None => Err(bad(format!("the record ends inside {what}"))),
        }
    }
    fn u8(&mut self, what: &str) -> Result<u8, RecordError> {
        Ok(self.take(1, what)?[0])
    }
    fn u16(&mut self, what: &str) -> Result<u16, RecordError> {
        Ok(u16::from_be_bytes(self.take(2, what)?.try_into().unwrap()))
    }
    fn u32(&mut self, what: &str) -> Result<u32, RecordError> {
        Ok(u32::from_be_bytes(self.take(4, what)?.try_into().unwrap()))
    }
    fn u64(&mut self, what: &str) -> Result<u64, RecordError> {
        Ok(u64::from_be_bytes(self.take(8, what)?.try_into().unwrap()))
    }
    fn id(&mut self, what: &str) -> Result<[u8; 8], RecordError> {
        Ok(self.take(8, what)?.try_into().unwrap())
    }
    fn key(&mut self, what: &str) -> Result<Point, RecordError> {
        Point::from_slice(self.take(KEY_BYTES, what)?)
            .map_err(|e| bad(format!("{what} is not a public key: {e}")))
    }
    fn header(&mut self, kind: u8, name: &str) -> Result<(), RecordError> {
        let version = self.u8("the version")?;
        if version != RECORD_VERSION {
            return Err(bad(format!(
                "a {name} record of version {version}: this build reads version {RECORD_VERSION}"
            )));
        }
        let found = self.u8("the kind")?;
        if found != kind {
            return Err(bad(format!(
                "record kind {found} is not a {name} record (kind {kind})"
            )));
        }
        Ok(())
    }
    fn finish(self, name: &str) -> Result<(), RecordError> {
        if self.at != self.bytes.len() {
            return Err(bad(format!(
                "a {name} record has {} bytes after its end",
                self.bytes.len() - self.at
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- keyset record

/// One key set of a PSP or FSP mint, as the stream carries it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeysetRecord {
    /// The mint's epoch of this key set (0 for the first).
    pub epoch: u64,
    /// Every (amount, key) of the key set.
    pub keys: BTreeMap<Amount, Point>,
}

impl KeysetRecord {
    /// The key set's ID ([`keyset_id`] over every pair).
    pub fn id(&self) -> String {
        keyset_id(&self.keys)
    }

    /// `[1, 1] || epoch (8) || n (2) || n x (amount (8) || key (33))`, amounts
    /// ascending.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.keys.len() * (8 + KEY_BYTES));
        out.push(RECORD_VERSION);
        out.push(RECORD_KEYSET);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&(self.keys.len() as u16).to_be_bytes());
        for (amount, key) in &self.keys {
            out.extend_from_slice(&amount.units.to_be_bytes());
            out.extend_from_slice(&key.serialize());
        }
        out
    }

    /// Read a record. Refused: another version or kind, no key or more than
    /// [`MAX_KEYSET_KEYS`], amounts that are not strictly ascending, a key that
    /// is not a public key, bytes after the end.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut r = Reader { bytes, at: 0 };
        r.header(RECORD_KEYSET, "key set")?;
        let epoch = r.u64("the epoch")?;
        let n = usize::from(r.u16("the key count")?);
        if n == 0 || n > MAX_KEYSET_KEYS {
            return Err(bad(format!(
                "a key set record has {n} keys: 1 to {MAX_KEYSET_KEYS} are allowed"
            )));
        }
        let mut keys = BTreeMap::new();
        let mut last: Option<u64> = None;
        for _ in 0..n {
            let amount = r.u64("an amount")?;
            if last.is_some_and(|l| amount <= l) {
                return Err(bad(
                    "the amounts of a key set record are not strictly ascending",
                ));
            }
            last = Some(amount);
            keys.insert(Amount::from_units(amount), r.key("a key")?);
        }
        r.finish("key set")?;
        Ok(KeysetRecord { epoch, keys })
    }
}

// ---------------------------------------------------------------- control record

/// A generation of the ESP mint: its epoch and key-set ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenerationRef {
    pub epoch: u64,
    pub id: [u8; 8],
}

/// What the ESP mint's control stream says: its maturity rule and which
/// generations are live. A new record is written whenever one of the three
/// changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlRecord {
    /// This record's place in the stream (the `n` of its cell).
    pub index: u32,
    /// The mint's maturity rule `m` (`terms.maturity_days`): a new exchange gets
    /// the day of its issue plus this.
    pub maturity_days: u64,
    /// The generation that signs new exchanges.
    pub current: GenerationRef,
    /// The generation before it, while it is live.
    pub previous: Option<GenerationRef>,
}

impl ControlRecord {
    /// `[1, 2] || index (4) || m (8) || current epoch (8) || current id (8) ||
    /// has previous (1) || previous epoch (8) || previous id (8)`: 47 bytes, the
    /// previous's fields all zero when there is none.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CONTROL_BYTES);
        out.push(RECORD_VERSION);
        out.push(RECORD_CONTROL);
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.maturity_days.to_be_bytes());
        out.extend_from_slice(&self.current.epoch.to_be_bytes());
        out.extend_from_slice(&self.current.id);
        match self.previous {
            Some(p) => {
                out.push(1);
                out.extend_from_slice(&p.epoch.to_be_bytes());
                out.extend_from_slice(&p.id);
            }
            None => out.extend_from_slice(&[0u8; 17]),
        }
        out
    }

    /// Read a record. Refused: another version or kind, a flag that is not 0 or
    /// 1, fields set where the flag says there is no previous generation, bytes
    /// after the end.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut r = Reader { bytes, at: 0 };
        r.header(RECORD_CONTROL, "control")?;
        let index = r.u32("the index")?;
        let maturity_days = r.u64("the maturity rule")?;
        let current = GenerationRef {
            epoch: r.u64("the current epoch")?,
            id: r.id("the current key-set ID")?,
        };
        let flag = r.u8("the previous flag")?;
        let epoch = r.u64("the previous epoch")?;
        let id = r.id("the previous key-set ID")?;
        let previous = match flag {
            0 if epoch == 0 && id == [0u8; 8] => None,
            0 => {
                return Err(bad(
                    "a control record with no previous generation names one",
                ));
            }
            1 => Some(GenerationRef { epoch, id }),
            other => {
                return Err(bad(format!(
                    "a control record's flag is {other}, not 0 or 1"
                )));
            }
        };
        r.finish("control")?;
        Ok(ControlRecord {
            index,
            maturity_days,
            current,
            previous,
        })
    }
}

// ---------------------------------------------------------------- ESP day record

/// One service's 64 keys for one day, in the order 2^0 to 2^63.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceKeys {
    pub service: ServiceDid,
    pub keys: [Point; ESP_KEYS_PER_SERVICE],
}

impl ServiceKeys {
    /// The key for `amount`, which must be a power of two.
    pub fn key_for(&self, amount: Amount) -> Option<&Point> {
        let units = amount.units;
        (units.is_power_of_two()).then(|| &self.keys[units.trailing_zeros() as usize])
    }
}

/// One part of one bucket of an ESP day.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DayRecord {
    /// The generation's key-set ID.
    pub generation: [u8; 8],
    /// The redeemable-after day.
    pub day: u64,
    /// This part's bucket.
    pub bucket: u32,
    /// How many buckets the day has (at least 1). The same in every part of the day.
    pub buckets: u32,
    /// This part of the bucket, from 0.
    pub part: u32,
    /// The services of this part, each once.
    pub services: Vec<ServiceKeys>,
}

impl DayRecord {
    /// The cell this part belongs in.
    pub fn cell(&self) -> Cell {
        Cell::Day(DayCell {
            generation: self.generation,
            day: self.day,
            bucket: self.bucket,
            part: self.part,
        })
    }

    /// `[1, 3] || generation (8) || day (8) || bucket (4) || buckets (4) ||
    /// part (4) || count (4) || count x (DID (33) || 64 x key (33))`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(DAY_HEADER_BYTES + self.services.len() * SERVICE_ENTRY_BYTES);
        out.push(RECORD_VERSION);
        out.push(RECORD_DAY);
        out.extend_from_slice(&self.generation);
        out.extend_from_slice(&self.day.to_be_bytes());
        out.extend_from_slice(&self.bucket.to_be_bytes());
        out.extend_from_slice(&self.buckets.to_be_bytes());
        out.extend_from_slice(&self.part.to_be_bytes());
        out.extend_from_slice(&(self.services.len() as u32).to_be_bytes());
        for s in &self.services {
            out.extend_from_slice(s.service.as_bytes());
            for key in &s.keys {
                out.extend_from_slice(&key.serialize());
            }
        }
        out
    }

    /// Read a record. Refused: another version or kind, no buckets, a bucket
    /// not below the bucket count, a count that does not match the bytes, a
    /// service that is not in this bucket or is listed twice, a key that is not a
    /// public key, bytes after the end.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut r = Reader { bytes, at: 0 };
        r.header(RECORD_DAY, "day")?;
        let generation = r.id("the generation")?;
        let day = r.u64("the day")?;
        let bucket = r.u32("the bucket")?;
        let buckets = r.u32("the bucket count")?;
        let part = r.u32("the part")?;
        let count = r.u32("the service count")? as usize;
        if buckets == 0 || bucket >= buckets {
            return Err(bad(format!(
                "bucket {bucket} of {buckets}: a day has at least one bucket and the bucket is below the count"
            )));
        }
        let expected = DAY_HEADER_BYTES
            .checked_add(
                count
                    .checked_mul(SERVICE_ENTRY_BYTES)
                    .ok_or_else(|| bad("too many services"))?,
            )
            .ok_or_else(|| bad("too many services"))?;
        if bytes.len() != expected {
            return Err(bad(format!(
                "an ESP day record of {count} services is {expected} bytes, this one is {}",
                bytes.len()
            )));
        }
        let mut services: Vec<ServiceKeys> = Vec::with_capacity(count);
        for _ in 0..count {
            let did = ServiceDid::from_slice(r.take(KEY_BYTES, "a service ID")?)
                .map_err(|e| bad(format!("a service ID in the record is not valid: {e}")))?;
            if bucket_of(&did, buckets) != bucket {
                return Err(bad(format!(
                    "service {did} is not in bucket {bucket} of {buckets}"
                )));
            }
            if services.iter().any(|s| s.service == did) {
                return Err(bad(format!("service {did} is listed twice in one part")));
            }
            let mut keys = Vec::with_capacity(ESP_KEYS_PER_SERVICE);
            for _ in 0..ESP_KEYS_PER_SERVICE {
                keys.push(r.key("a key")?);
            }
            let keys: [Point; ESP_KEYS_PER_SERVICE] = keys
                .try_into()
                .map_err(|_| bad("a service does not have 64 keys"))?;
            services.push(ServiceKeys { service: did, keys });
        }
        r.finish("day")?;
        Ok(DayRecord {
            generation,
            day,
            bucket,
            buckets,
            part,
            services,
        })
    }
}

// ---------------------------------------------------------------- buckets

/// The bucket of `service` in a day with `buckets` buckets: the first 8 bytes of
/// `sha256("sp-esp-bucket-v0" || DID)`, big-endian, modulo `buckets`. `buckets`
/// is at least 1.
pub fn bucket_of(service: &ServiceDid, buckets: u32) -> u32 {
    let digest = sha256(&[BUCKET_LABEL, &service.as_bytes()[..]]);
    let n = u64::from_be_bytes(digest[..8].try_into().unwrap());
    (n % u64::from(buckets.max(1))) as u32
}

/// The most services one record of at most `max_bytes` holds (0 if not even
/// one fits).
pub fn services_per_record(max_bytes: usize) -> usize {
    max_bytes.saturating_sub(DAY_HEADER_BYTES) / SERVICE_ENTRY_BYTES
}

/// The bucket count of a new day with `services` services and records of at
/// most `max_bytes`: 1 while one record holds them all, else
/// `ceil(services / BUCKET_SERVICES)`.
pub fn buckets_for(services: usize, max_bytes: usize) -> u32 {
    if services <= services_per_record(max_bytes) {
        1
    } else {
        services
            .div_ceil(BUCKET_SERVICES)
            .max(1)
            .min(u32::MAX as usize) as u32
    }
}

// ---------------------------------------------------------------- transport

#[cfg(feature = "air-client")]
pub use transport::*;

#[cfg(feature = "air-client")]
mod transport {
    use super::*;
    use crate::air_request::client::{self, Client};
    use crate::air_request::delivery::{self, Written};

    /// Write `bytes` to `cell` of the mint whose DID key is `mint_key`. A cell
    /// that already holds exactly these bytes is [`Written::AlreadyStored`]; one
    /// that holds other bytes is [`Written::Different`] and is left alone.
    pub async fn write_cell(
        client: &Client,
        mint_key: &SecretKey,
        cell: &Cell,
        bytes: &[u8],
        secs: u64,
    ) -> Result<Written, AirError> {
        let secret = cell_secret(mint_key, cell)?;
        delivery::write_record(client, &secret, bytes, secs).await
    }

    /// Read `cell` of `mint` once: `None` when nothing is written there.
    pub async fn read_cell(
        client: &Client,
        mint: &ServiceDid,
        cell: &Cell,
        secs: u64,
    ) -> Result<Option<Vec<u8>>, AirError> {
        client::read_once(client, cell_address(mint, cell)?, secs).await
    }

    /// How many records a sequential stream has: the index of its first empty
    /// cell. `cell` names the `n`th cell. The stream is written in order, so the
    /// cells that hold a record are 0 up to one less than the answer; the search
    /// doubles the index until it finds an empty cell, then halves back.
    pub async fn find_end(
        client: &Client,
        mint: &ServiceDid,
        cell: impl Fn(u32) -> Cell,
        secs: u64,
    ) -> Result<u32, AirError> {
        if read_cell(client, mint, &cell(0), secs).await?.is_none() {
            return Ok(0);
        }
        let mut have = 0u32; // a cell that holds a record
        let mut empty = 1u32; // a cell that is empty, once found
        loop {
            if read_cell(client, mint, &cell(empty), secs).await?.is_none() {
                break;
            }
            have = empty;
            empty = empty.checked_mul(2).ok_or_else(|| {
                AirError("a stream with more than 2^31 records: not a stream of a mint".into())
            })?;
        }
        while empty - have > 1 {
            let mid = have + (empty - have) / 2;
            if read_cell(client, mint, &cell(mid), secs).await?.is_some() {
                have = mid;
            } else {
                empty = mid;
            }
        }
        Ok(empty)
    }

    /// The end of a PSP or FSP mint's key set stream and its last two records
    /// (the current and the previous key set), oldest first, each with its place
    /// in the stream.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct KeysetTail {
        /// How many records the stream has: the index of its first empty cell.
        pub end: u32,
        /// The last (up to) two records.
        pub last: Vec<(u32, KeysetRecord)>,
    }

    /// Read the record at `index` of the key set stream, which must exist and
    /// decode.
    pub async fn read_keyset(
        client: &Client,
        mint: &ServiceDid,
        index: u32,
        secs: u64,
    ) -> Result<KeysetRecord, AirError> {
        let cell = Cell::Keyset { index };
        let bytes = read_cell(client, mint, &cell, secs)
            .await?
            .ok_or_else(|| AirError(format!("{cell} of {mint} is empty")))?;
        KeysetRecord::decode(&bytes)
            .map_err(|e| AirError(format!("{cell} of {mint} does not decode: {e}")))
    }

    /// Find the end of the key set stream of `mint` and read its last two
    /// records.
    pub async fn read_keyset_tail(
        client: &Client,
        mint: &ServiceDid,
        secs: u64,
    ) -> Result<KeysetTail, AirError> {
        let end = find_end(client, mint, |index| Cell::Keyset { index }, secs).await?;
        let mut last = Vec::new();
        for index in end.saturating_sub(2)..end {
            last.push((index, read_keyset(client, mint, index, secs).await?));
        }
        Ok(KeysetTail { end, last })
    }

    /// The records of the key set stream from `from` on, until a cell is empty:
    /// how a wallet that was away catches up from the record it last knew.
    pub async fn read_keysets_from(
        client: &Client,
        mint: &ServiceDid,
        from: u32,
        secs: u64,
    ) -> Result<Vec<(u32, KeysetRecord)>, AirError> {
        let mut out = Vec::new();
        let mut index = from;
        while read_cell(client, mint, &Cell::Keyset { index }, secs)
            .await?
            .is_some()
        {
            out.push((index, read_keyset(client, mint, index, secs).await?));
            index = index
                .checked_add(1)
                .ok_or_else(|| AirError("a stream with more than 2^32 records".into()))?;
        }
        Ok(out)
    }

    /// What [`publish_keysets`] did.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Published {
        /// The stream's length afterwards.
        pub end: u32,
        /// The places this call wrote, in order. Empty when the stream already
        /// held every live key set.
        pub written: Vec<u32>,
    }

    /// Make the key set stream of the mint whose DID key is `mint_key` hold
    /// `live`, the mint's live key sets oldest first (the previous, then the
    /// current). A key set already among the stream's last two records (same
    /// epoch, same ID) is left alone; each other one is written after the end.
    /// Nothing is kept between calls and nothing is written twice: after a
    /// restart, a crash between two writes or a write that was not acknowledged,
    /// the next call finds what is there and writes the rest. A cell that holds
    /// another record than the one this call writes is an error (another process
    /// is writing this mint's stream), and nothing is written over it.
    pub async fn publish_keysets(
        client: &Client,
        mint_key: &SecretKey,
        live: &[KeysetRecord],
        secs: u64,
    ) -> Result<Published, AirError> {
        let did = addr::key_to_did(&mint_key.public_key());
        let tail = read_keyset_tail(client, &did, secs).await?;
        let mut end = tail.end;
        let mut present: Vec<(u64, String)> =
            tail.last.iter().map(|(_, r)| (r.epoch, r.id())).collect();
        let mut written = Vec::new();
        for record in live {
            let name = (record.epoch, record.id());
            if present.contains(&name) {
                continue;
            }
            let cell = Cell::Keyset { index: end };
            match write_cell(client, mint_key, &cell, &record.encode(), secs).await? {
                Written::Created | Written::AlreadyStored => {}
                Written::Different => {
                    return Err(AirError(format!(
                        "{cell} of {did} already holds another record: another process writes this mint's stream"
                    )));
                }
            }
            written.push(end);
            present.push(name);
            if present.len() > 2 {
                present.remove(0);
            }
            end += 1;
        }
        Ok(Published { end, written })
    }

    /// How long a mint's stream thread waits between two passes.
    pub const TICK_SECS: u64 = 5;
    /// How long it waits after a pass that failed.
    pub const RETRY_SECS: u64 = 30;

    /// Publishes a mint's live key sets to its AIR server from a thread of its
    /// own (it blocks; each pass builds a runtime for the call). The PSP mint and
    /// the FSP mint each run one.
    pub struct KeysetPublisher {
        server: client::ServerRef,
        timeout_secs: u64,
        key: [u8; 32],
        /// The (epoch, ID) of the key sets the last successful pass saw, oldest first.
        published: Option<Vec<(u64, String)>>,
    }

    impl KeysetPublisher {
        /// `key` is the mint's DID key (copied: the mint goes on to use its own).
        /// `timeout_secs` is how long the AIR server may take to answer one call
        /// (`air.timeout_secs`), and to connect.
        pub fn new(server: client::ServerRef, timeout_secs: u64, key: &SecretKey) -> Self {
            KeysetPublisher {
                server,
                timeout_secs,
                key: key.to_array(),
                published: None,
            }
        }

        /// One pass for the key sets `live` (oldest first): nothing at all, and
        /// `Ok(None)`, when they are the ones the last successful pass published;
        /// else make the stream hold them ([`publish_keysets`]) and say what was
        /// written. The mint keeps nothing between runs of the process: the first
        /// pass finds what the stream holds.
        pub fn pass(&mut self, live: &[KeysetRecord]) -> Result<Option<Published>, String> {
            let names: Vec<(u64, String)> = live.iter().map(|r| (r.epoch, r.id())).collect();
            if self.published.as_ref() == Some(&names) {
                return Ok(None);
            }
            let key = SecretKey::from_array(self.key)
                .map_err(|_| "the mint's key is not a valid secret key".to_string())?;
            let (server, timeout, key) = (&self.server, self.timeout_secs, &key);
            let done = client::block_on_new_runtime(|| async move {
                let client = tokio::time::timeout(
                    std::time::Duration::from_secs(timeout),
                    client::connect(server),
                )
                .await
                .map_err(|_| format!("no connection to the AIR server within {timeout} s"))?
                .map_err(|e| e.0)?;
                publish_keysets(&client, key, live, timeout)
                    .await
                    .map_err(|e| e.0)
            })
            .map_err(|e| e.0)??;
            self.published = Some(names);
            Ok(Some(done))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The generator's DID: the DID whose secret is 1.
    const G_DID: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn mint() -> ServiceDid {
        ServiceDid::parse(G_DID).unwrap()
    }

    /// The mint key whose DID is [`G_DID`].
    fn mint_key() -> SecretKey {
        let mut one = [0u8; 32];
        one[31] = 1;
        SecretKey::from_array(one).unwrap()
    }

    fn key(n: u8) -> Point {
        secp256k1::Keypair::from_seckey_slice(SECP256K1, &[n; 32])
            .unwrap()
            .public_key()
    }

    fn did(n: u8) -> ServiceDid {
        ServiceDid::from(key(n))
    }

    fn keys64(n: u8) -> [Point; ESP_KEYS_PER_SERVICE] {
        std::array::from_fn(|i| key(n.wrapping_add(i as u8)))
    }

    // ---- cells: tweaks, secrets and addresses, computed independently with
    // Python's hashlib and a small secp256k1 implementation. The mint's secret is
    // 1, so each cell's secret is 1 plus the tweak.

    fn gen_id() -> [u8; 8] {
        [1, 2, 3, 4, 5, 6, 7, 8]
    }

    #[test]
    fn golden_cell_tweaks_secrets_and_addresses() {
        let cells = [
            (
                Cell::Keyset { index: 0 },
                "8c2a30986ac3c0a3965c95e0d2a149f4796e04d1f25c820cf5a41d091b5718b9",
                "8c2a30986ac3c0a3965c95e0d2a149f4796e04d1f25c820cf5a41d091b5718ba",
                "03b30e4a7f4b70c7b98d04f313b7c5ed8c08002292b04695eb8468826be87b8a00",
            ),
            (
                Cell::Keyset { index: 1 },
                "44d2942c8cf4f13a6448abbd0553488ce824f886944070cb65ba60e1635f5c7d",
                "44d2942c8cf4f13a6448abbd0553488ce824f886944070cb65ba60e1635f5c7e",
                "031e5e94ead8d07a2ef7c961044748572b75048dd5112bc9c353fba4412924593c",
            ),
            (
                Cell::Control { index: 0 },
                "6e3d7179135e71effe46f2d191e45d3d1ca5872e64c351ef717a87455b93e467",
                "6e3d7179135e71effe46f2d191e45d3d1ca5872e64c351ef717a87455b93e468",
                "02a405bf83aa18b0f41ed6c40c03e882a13ef6c31abf978f463648d12230a2f7c6",
            ),
            (
                Cell::Day(DayCell {
                    generation: gen_id(),
                    day: 20_900,
                    bucket: 0,
                    part: 0,
                }),
                "69c5b604d1cbb0c023dfc670f7de105ee8fcd6e73e36aae829a2c8ab5345bdbf",
                "69c5b604d1cbb0c023dfc670f7de105ee8fcd6e73e36aae829a2c8ab5345bdc0",
                "03d31be6e86ee6667998fa2bf482dcbfa7a32cd4233c7c30923688508096dff0d5",
            ),
            (
                Cell::Day(DayCell {
                    generation: gen_id(),
                    day: 20_901,
                    bucket: 3,
                    part: 2,
                }),
                "c25b89bf6c44a86ca2ce0b0bcd1e116feaf1f4b2c5e8724ab8027bc6ebf57c0c",
                "c25b89bf6c44a86ca2ce0b0bcd1e116feaf1f4b2c5e8724ab8027bc6ebf57c0d",
                "03eae338289f2311d2d3d73cbf6e8932b8b3f7cf448b609a3e0ba84e6312db3ac3",
            ),
        ];
        for (cell, tweak, secret, address) in cells {
            assert_eq!(hex::encode(cell_tweak(&mint(), &cell)), tweak, "{cell}");
            let s = cell_secret(&mint_key(), &cell).unwrap();
            assert_eq!(hex::encode(s.to_array()), secret, "{cell}");
            assert_eq!(
                hex::encode(addr::key_to_bytes(&cell_address(&mint(), &cell).unwrap())),
                address,
                "{cell}"
            );
        }
    }

    /// Fails if the public derivation and the secret derivation ever disagree
    /// (a wrong tweak on one side): the mint would sign a cell nobody reads.
    #[test]
    fn the_address_anyone_computes_is_the_public_key_of_the_mints_secret() {
        for i in 0..20u32 {
            let key = SecretKey::new();
            let did = addr::key_to_did(&key.public_key());
            let cell = Cell::Day(DayCell {
                generation: gen_id(),
                day: 20_000 + u64::from(i),
                bucket: i % 5,
                part: i,
            });
            let secret = cell_secret(&key, &cell).unwrap();
            assert_eq!(secret.public_key(), cell_address(&did, &cell).unwrap());
            // and it is not the mint's own key, so the mint's DID key is not used
            // for any cell it publishes
            assert_ne!(secret.public_key(), key.public_key());
        }
    }

    /// Fails if a field is left out of the tweak: two cells would be one cell.
    #[test]
    fn every_part_of_a_cells_name_moves_its_address() {
        let base = Cell::Day(DayCell {
            generation: gen_id(),
            day: 20_900,
            bucket: 1,
            part: 1,
        });
        let others = [
            Cell::Keyset { index: 1 },
            Cell::Control { index: 1 },
            Cell::Day(DayCell {
                generation: [9; 8],
                day: 20_900,
                bucket: 1,
                part: 1,
            }),
            Cell::Day(DayCell {
                generation: gen_id(),
                day: 20_901,
                bucket: 1,
                part: 1,
            }),
            Cell::Day(DayCell {
                generation: gen_id(),
                day: 20_900,
                bucket: 2,
                part: 1,
            }),
            Cell::Day(DayCell {
                generation: gen_id(),
                day: 20_900,
                bucket: 1,
                part: 2,
            }),
        ];
        let at = |m: &ServiceDid, c: &Cell| cell_address(m, c).unwrap();
        for other in &others {
            assert_ne!(at(&mint(), &base), at(&mint(), other), "{other}");
        }
        assert_ne!(
            at(&mint(), &Cell::Keyset { index: 0 }),
            at(&did(2), &Cell::Keyset { index: 0 })
        );
        // a keyset cell and a control cell with the same index are two cells
        assert_ne!(
            at(&mint(), &Cell::Keyset { index: 0 }),
            at(&mint(), &Cell::Control { index: 0 })
        );
    }

    // ---- key set records

    fn keyset() -> KeysetRecord {
        KeysetRecord {
            epoch: 3,
            keys: [(1u64, key(1)), (2, key(2)), (4, key(3))]
                .into_iter()
                .map(|(a, k)| (Amount::from_units(a), k))
                .collect(),
        }
    }

    #[test]
    fn a_keyset_record_is_pinned_and_round_trips() {
        let bytes = keyset().encode();
        assert_eq!(
            hex::encode(&bytes),
            concat!(
                "0101",
                "0000000000000003",
                "0003",
                "0000000000000001",
                "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
                "0000000000000002",
                "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766",
                "0000000000000004",
                "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337"
            )
        );
        assert_eq!(bytes.len(), 12 + 3 * 41);
        assert_eq!(KeysetRecord::decode(&bytes).unwrap(), keyset());
        // 64 keys: the 2,636 bytes the module doc states
        let full = KeysetRecord {
            epoch: 0,
            keys: (0..64u32)
                .map(|i| (Amount::from_units(1u64 << i), key(i as u8 + 1)))
                .collect(),
        };
        assert_eq!(full.encode().len(), 2_636);
        assert_eq!(full.id(), "e3205d54a3c48e66");
        assert_eq!(KeysetRecord::decode(&full.encode()).unwrap(), full);
    }

    #[test]
    fn a_keyset_record_that_breaks_a_rule_is_refused() {
        let good = keyset().encode();
        let err = |bytes: &[u8]| KeysetRecord::decode(bytes).unwrap_err().to_string();
        let mut v = good.clone();
        v[0] = 2;
        assert!(err(&v).contains("version 2"), "{}", err(&v));
        let mut v = good.clone();
        v[1] = 3;
        assert!(err(&v).contains("not a key set record"), "{}", err(&v));
        // no keys
        let mut v = good[..12].to_vec();
        v[10] = 0;
        v[11] = 0;
        assert!(err(&v).contains("has 0 keys"), "{}", err(&v));
        // 65 keys
        let mut v = good.clone();
        v[10] = 0;
        v[11] = 65;
        assert!(err(&v).contains("has 65 keys"), "{}", err(&v));
        // amounts not ascending: the second amount is 1 again
        let mut v = good.clone();
        v[12 + 41 + 7] = 1;
        assert!(err(&v).contains("not strictly ascending"), "{}", err(&v));
        // a key that is not on the curve
        let mut v = good.clone();
        v[12 + 8] = 0x05;
        assert!(err(&v).contains("not a public key"), "{}", err(&v));
        // cut short, and a byte too many
        assert!(err(&good[..good.len() - 1]).contains("ends inside"));
        let mut v = good.clone();
        v.push(0);
        assert!(err(&v).contains("1 bytes after its end"), "{}", err(&v));
    }

    // ---- control records

    fn control() -> ControlRecord {
        ControlRecord {
            index: 5,
            maturity_days: 365,
            current: GenerationRef {
                epoch: 7,
                id: [1, 2, 3, 4, 5, 6, 7, 8],
            },
            previous: Some(GenerationRef {
                epoch: 6,
                id: [11, 12, 13, 14, 15, 16, 17, 18],
            }),
        }
    }

    #[test]
    fn a_control_record_is_47_bytes_pinned_and_round_trips() {
        let bytes = control().encode();
        assert_eq!(
            hex::encode(&bytes),
            "010200000005000000000000016d000000000000000701020304050607080100000000000000060b0c0d0e0f101112"
        );
        assert_eq!(bytes.len(), CONTROL_BYTES);
        assert_eq!(ControlRecord::decode(&bytes).unwrap(), control());
        let first = ControlRecord {
            index: 0,
            maturity_days: 30,
            current: GenerationRef {
                epoch: 0,
                id: [1, 2, 3, 4, 5, 6, 7, 8],
            },
            previous: None,
        };
        assert_eq!(
            hex::encode(first.encode()),
            "010200000000000000000000001e000000000000000001020304050607080000000000000000000000000000000000"
        );
        assert_eq!(ControlRecord::decode(&first.encode()).unwrap(), first);
    }

    #[test]
    fn a_control_record_that_breaks_a_rule_is_refused() {
        let good = control().encode();
        let err = |bytes: &[u8]| ControlRecord::decode(bytes).unwrap_err().to_string();
        let mut v = good.clone();
        v[30] = 2; // the previous flag
        assert!(err(&v).contains("flag is 2"), "{}", err(&v));
        // flag 0 with a previous generation's fields set
        let mut v = good.clone();
        v[30] = 0;
        assert!(err(&v).contains("names one"), "{}", err(&v));
        assert!(err(&good[..46]).contains("ends inside"));
        let mut v = good.clone();
        v.push(0);
        assert!(err(&v).contains("after its end"));
        assert!(err(&keyset().encode()).contains("not a control record"));
    }

    // ---- ESP day records

    fn day_part() -> DayRecord {
        DayRecord {
            generation: gen_id(),
            day: 20_900,
            // the bucket of key(1)'s DID among 7 (below)
            bucket: 3,
            buckets: 7,
            part: 0,
            services: vec![ServiceKeys {
                service: did(1),
                keys: keys64(10),
            }],
        }
    }

    #[test]
    fn an_esp_day_record_is_pinned_and_round_trips() {
        let bytes = day_part().encode();
        assert_eq!(bytes.len(), DAY_HEADER_BYTES + SERVICE_ENTRY_BYTES);
        assert_eq!(bytes.len(), 2_179);
        assert_eq!(
            hex::encode(&bytes[..DAY_HEADER_BYTES]),
            "0103010203040506070800000000000051a400000003000000070000000000000001"
        );
        assert_eq!(
            hex::encode(sha256(&[&bytes])),
            "5f98f9a6963ee5940b59cf45ce7b07563576682f5b0d5fb9d9c6583c0e76bf9f"
        );
        assert_eq!(DayRecord::decode(&bytes).unwrap(), day_part());
        assert_eq!(
            day_part().cell(),
            Cell::Day(DayCell {
                generation: gen_id(),
                day: 20_900,
                bucket: 3,
                part: 0
            })
        );
        // two services in the one-bucket form
        let two = DayRecord {
            generation: gen_id(),
            day: 20_900,
            bucket: 0,
            buckets: 1,
            part: 1,
            services: vec![
                ServiceKeys {
                    service: did(1),
                    keys: keys64(10),
                },
                ServiceKeys {
                    service: did(2),
                    keys: keys64(100),
                },
            ],
        };
        let bytes = two.encode();
        assert_eq!(bytes.len(), 4_324);
        assert_eq!(
            hex::encode(sha256(&[&bytes])),
            "1ca7ff76f4e689bda787559f6ad9df89ffc461e850dfec8775593c62b004109a"
        );
        assert_eq!(DayRecord::decode(&bytes).unwrap(), two);
    }

    #[test]
    fn a_service_finds_its_key_by_amount() {
        let s = ServiceKeys {
            service: did(1),
            keys: keys64(10),
        };
        assert_eq!(s.key_for(Amount::from_units(1)), Some(&key(10)));
        assert_eq!(s.key_for(Amount::from_units(8)), Some(&key(13)));
        assert_eq!(s.key_for(Amount::from_units(1 << 63)), Some(&key(73)));
        assert_eq!(s.key_for(Amount::from_units(3)), None);
        assert_eq!(s.key_for(Amount::from_units(0)), None);
    }

    #[test]
    fn an_esp_day_record_that_breaks_a_rule_is_refused() {
        let good = day_part().encode();
        let err = |bytes: &[u8]| DayRecord::decode(bytes).unwrap_err().to_string();
        // the bucket is not below the count
        let mut v = good.clone();
        v[21] = 7;
        assert!(err(&v).contains("bucket 7 of 7"), "{}", err(&v));
        // no buckets
        let mut v = good.clone();
        v[25] = 0;
        assert!(err(&v).contains("at least one bucket"), "{}", err(&v));
        // the count says 2 and the bytes hold 1
        let mut v = good.clone();
        v[33] = 2;
        assert!(
            err(&v).contains("is 4324 bytes, this one is 2179"),
            "{}",
            err(&v)
        );
        // a service that hashes to another bucket
        let mut other = day_part();
        other.bucket = 2;
        assert!(err(&other.encode()).contains("is not in bucket 2 of 7"));
        // a service twice in one part
        let mut twice = day_part();
        twice.services.push(twice.services[0].clone());
        assert!(err(&twice.encode()).contains("listed twice"));
        // a key off the curve
        let mut v = good.clone();
        v[DAY_HEADER_BYTES + 33] = 0x05;
        assert!(err(&v).contains("not a public key"), "{}", err(&v));
        // cut short
        assert!(err(&good[..good.len() - 1]).contains("is 2179 bytes"));
        assert!(err(&keyset().encode()).contains("not a day record"));
    }

    // ---- buckets and sizes

    #[test]
    fn golden_buckets() {
        // [buckets 1, 2, 7, 100] for the DIDs of key(1) to key(8)
        let expected: [(u8, [u32; 4]); 8] = [
            (1, [0, 1, 3, 61]),
            (2, [0, 1, 2, 81]),
            (3, [0, 0, 0, 92]),
            (4, [0, 0, 2, 4]),
            (5, [0, 1, 4, 75]),
            (6, [0, 1, 4, 99]),
            (7, [0, 1, 2, 1]),
            (8, [0, 0, 0, 44]),
        ];
        for (n, want) in expected {
            let got = [1, 2, 7, 100].map(|k| bucket_of(&did(n), k));
            assert_eq!(got, want, "key({n})");
        }
    }

    #[test]
    fn the_sizes_are_pinned() {
        assert_eq!(SERVICE_ENTRY_BYTES, 2_145);
        assert_eq!(DAY_HEADER_BYTES, 34);
        // 64 keys x 33 bytes + the 33-byte DID
        assert_eq!(64 * 33 + 33, SERVICE_ENTRY_BYTES);
        // AIR's 16 MiB message cap less the 1 MiB room
        assert_eq!(RECORD_MAX_BYTES, 15_728_640);
        assert_eq!(RECORD_MAX_BYTES + (1 << 20), 16 << 20);
        assert_eq!(services_per_record(4 << 20), 1_955);
        assert_eq!(services_per_record(RECORD_MAX_BYTES), 7_332);
        assert_eq!(services_per_record(65_536), 30);
        assert_eq!(services_per_record(2_178), 0);
        assert_eq!(services_per_record(2_179), 1);
    }

    /// Fails if a record could pass the size: the most services a record
    /// holds always fit it, and one more does not.
    #[test]
    fn a_record_never_passes_the_size() {
        for max in [65_536usize, 1 << 20, 4 << 20, RECORD_MAX_BYTES] {
            let n = services_per_record(max);
            assert!(DAY_HEADER_BYTES + n * SERVICE_ENTRY_BYTES <= max, "{max}");
            assert!(
                DAY_HEADER_BYTES + (n + 1) * SERVICE_ENTRY_BYTES > max,
                "{max}"
            );
        }
    }

    #[test]
    fn a_day_is_one_record_until_it_would_pass_the_size() {
        let max = 4 << 20;
        assert_eq!(buckets_for(0, max), 1);
        assert_eq!(buckets_for(1, max), 1);
        assert_eq!(buckets_for(1_955, max), 1);
        // 1,956 services would make a 4,195,654-byte record: 8 buckets of 256
        assert_eq!(buckets_for(1_956, max), 8);
        assert_eq!(buckets_for(2_048, max), 8);
        assert_eq!(buckets_for(2_049, max), 9);
        assert_eq!(buckets_for(100_000, max), 391);
    }
}

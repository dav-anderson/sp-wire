//! sp-wire: everything the Service Points mints and wallets exchange.
//!
//! Types, encodings and constants only: no storage, no HTTP, no settlement, no
//! config files. A wallet can use this crate without any mint code. The one
//! piece of configuration is [`storage`], the type and parser of the storage
//! policy, shared so that the mints and the wallet read a service list the same
//! way; it does no I/O.
//!
//! - [`units`]: PSP, ESP and FSP units and the rate between them.
//! - [`keyset`]: the key-set ID and the `GET /rotation` body.
//! - [`keys`]: `GET /keys` and `POST /check-state`, the bodies of mint-core's server.
//! - [`payload`] and [`seal`]: the PSP OP_RETURN payload and its encryption.
//! - [`psp`], [`esp`] and [`fsp`]: the request and response bodies of each mint.
//! - [`codes`]: the `code` of an error body.
//! - [`service`]: [`ServiceDid`], the service ID: an AIR DID, 33 bytes, 66 hex characters.
//! - `air_request` (feature `air-request`, with `air-client` for the transport): the first request
//!   between two parties over AIR, mint info with a mint-signed reply. Rides [`WIRE_VERSION`] 3.
//! - [`version`]: [`WIRE_VERSION`] and the check a wallet makes of the wire version a mint reports.
//! - [`storage`]: the storage policy (an ordered list of service IDs per kind of
//!   data), its parser and its checks. Not part of the wire.
//!
//! The note, nonce, blinded output and mint input/output types are mint-core's
//! (`mint_types`), re-exported here.
//!
//! Every encoding is pinned by a golden test. Changing a byte of one fails the
//! test, and the change must bump [`WIRE_VERSION`].

#[cfg(feature = "air-request")]
pub mod air_request;
pub mod codes;
pub mod dec;
pub mod esp;
pub mod fsp;
pub mod keys;
pub mod keyset;
pub mod payload;
pub mod psp;
pub mod seal;
pub mod service;
pub mod storage;
pub mod units;
pub mod version;

pub use mint_types;
pub use mint_types::{Amount, BlindNonce, MintInput, MintOutput, MintOutputOutcome, Nonce, Note};
pub use service::ServiceDid;
pub use version::WIRE_VERSION;

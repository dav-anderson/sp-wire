//! sp-wire: everything the Service Points mints and wallets exchange.
//!
//! Types, encodings and constants only: no storage, no HTTP, no settlement, no
//! config. A wallet can use this crate without any mint code.
//!
//! - [`units`]: PSP, ESP and FSP units and the rate between them.
//! - [`keyset`]: the key-set ID and the `GET /rotation` body.
//! - [`payload`] and [`seal`]: the PSP OP_RETURN payload and its encryption.
//! - [`psp`], [`esp`] and [`fsp`]: the request and response bodies of each mint.
//! - [`codes`]: the `code` of an error body.
//! - [`version`]: [`WIRE_VERSION`] and the check a wallet makes against `/health`.
//!
//! The note, nonce, blinded output and mint input/output types are mint-core's
//! (`mint_types`), re-exported here.
//!
//! Every encoding is pinned by a golden test. Changing a byte of one fails the
//! test, and the change must bump [`WIRE_VERSION`].

pub mod codes;
pub mod dec;
pub mod esp;
pub mod fsp;
pub mod keyset;
pub mod payload;
pub mod psp;
pub mod seal;
pub mod units;
pub mod version;

pub use mint_types;
pub use mint_types::{Amount, BlindNonce, MintInput, MintOutput, MintOutputOutcome, Nonce, Note};
pub use version::WIRE_VERSION;

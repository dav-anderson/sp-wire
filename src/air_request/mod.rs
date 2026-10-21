//! One read-only request from a wallet to a mint over AIR, and the mint's signed
//! reply: the calls between two parties that do not go over HTTP.
//!
//! The calls are **mint info** (what the mint's `GET /health` reports: `status`,
//! `wire_version`, `network`, which a wallet's `verify_mint` reads before it
//! sends anything else), the PSP's **keys**, **keysets** and **rotation**
//! (`GET /keys`, `/keysets`, `/rotation`) and the PSP's **rollover** and
//! **check-state** (`POST /rollover`, `/check-state`: the first calls with a
//! body, and the first that change state). They share one request envelope with
//! a kind byte, and the body of the reply is the exact JSON the HTTP call
//! returns; a refusal is a signed reply with its own status and the HTTP 4xx
//! body. REQUEST-DESIGN.md sections 14 and 15 have the reasons. The design, with the reasons for every choice, is
//! `REQUEST-DESIGN.md` in sandbox-mint (`air-sandbox/`); this module is that
//! design, ported from the throwaway prototype that ran it (`mintinfo-proto`),
//! with one change: the label of the reply cell and the label of the reply
//! signature digest, which the design shared, are two labels.
//!
//! ```text
//! wallet                        AIR server (the SPI's own)                  psp-mint
//!  | 1. request_id, one-off key r; seal the request to the mint DID             |
//!  | 2. Create mailbox slot j --- sealed request --->  push: slot filled -----> |
//!  | 3. Read reply cell(r, id): held                  reply cell <--- Create ---| open, answer, sign
//!  | <--- push: sealed, mint-signed reply ---                                   |
//!  | 4. open with r, verify the mint's signature, check the fields              |
//! ```
//!
//! # What is where
//!
//! - [`addr`] (feature `air-request`): key forms (a [`ServiceDid`](crate::ServiceDid)
//!   and AIR's `PublicKey`), the mailbox and reply-cell addresses, sealing, the
//!   signature bytes. Pure: no network.
//! - [`envelope`] (feature `air-request`): the request and reply envelopes, the
//!   mint's side of answering ([`answer_mint_info`]), the wallet's checks
//!   ([`verify_reply`]) and [`MintInfo`]. Pure.
//! - [`delivery`] (feature `air-request`): the PSP's delivery of one purchase, the
//!   signatures or the rejection as one record at an address the wallet can
//!   compute (REQUEST-DESIGN.md section 18). Pure, with transport helpers
//!   (`write_record`, `read_record`) under `air-client`.
//! - `client` (feature `air-client`): the thin transport. Connect to a
//!   configured AIR server, raw `Create` and `Read`, a held read. No AIR helper
//!   of `orange_me` is used.
//! - `ask` (feature `air-client`): the wallet's whole side of the request on top of
//!   `client`: reply cell first, mailbox probe, held read, retries, the checks.
//!   Shared by the wallet and the mint's integration tests.
//! - `local_server` (feature `air-client`): starts an `air_server` in this
//!   process, for the integration tests of the crates that use this module.
//!
//! # Wire version
//!
//! These bytes ride [`crate::WIRE_VERSION`] 3, the version in which a service ID
//! became a 33-byte DID; nothing in them is older, so there is no bump. The
//! envelope has its own version byte ([`envelope::ENVELOPE_VERSION`], 0), and the
//! `-v0` in each label moves every address and digest if a derivation changes.
//! Every derivation and both envelopes are pinned by golden tests that were
//! computed independently with Python's `hashlib`.
//!
//! # Features
//!
//! `air-request` needs AIR (it implies `seal`). `air-client` adds the transport
//! and needs `air_server` and `tokio`; `air_server` depends on `../air` by path,
//! so it can only be built with the local patches described in the README.

pub mod addr;
pub mod delivery;
pub mod envelope;

#[cfg(feature = "air-client")]
pub mod ask;
#[cfg(feature = "air-client")]
pub mod client;
#[cfg(feature = "air-client")]
pub mod local_server;

use std::error::Error;
use std::fmt;

pub use envelope::{
    Answer, Expect, KIND_CHECK_STATE, KIND_EXCHANGE, KIND_FEES, KIND_FSP_ISSUE, KIND_FSP_SPEND,
    KIND_KEYS, KIND_KEYSETS, KIND_MINT_INFO, KIND_PSP_DELIVERY, KIND_PSP_RECONCILE, KIND_PSP_SPEND,
    KIND_REDEEM, KIND_ROLLOVER, KIND_ROTATION, KIND_TRANSFER, MintInfo, STATUS_ANSWERED,
    STATUS_REFUSED, STATUS_UNAVAILABLE, Served, VerifyError, WireReply, WireRequest,
    answer_mint_info, answer_request, build_reply, build_reply_naming, check_mint_info,
    verify_answer, verify_receipt, verify_reply,
};

/// Why `host` is not a host name or IP for the AIR server setting, if it is
/// not: it is a host name or an IP with no port, no scheme and no path. (An IPv6
/// address has colons, so it is told from a `host:port` by parsing it.) Shared by
/// the mint's and the wallet's settings, so both refuse the same things.
pub fn host_problem(host: &str) -> Option<&'static str> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    if host.contains("://") || host.contains('/') {
        return Some("must be a host name or an IP, not a URL: no scheme, no path");
    }
    if host.contains(':') {
        return Some(
            "must be a host name or an IP with no port: the AIR client always uses port 5702",
        );
    }
    if host.chars().any(|c| c.is_whitespace()) {
        return Some("must not contain spaces");
    }
    None
}

/// Why a step of the request failed, in words. The checks a wallet makes on a
/// reply have their own type, [`VerifyError`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AirError(pub String);

impl fmt::Display for AirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for AirError {}

impl From<String> for AirError {
    fn from(text: String) -> Self {
        AirError(text)
    }
}

impl From<&str> for AirError {
    fn from(text: &str) -> Self {
        AirError(text.to_string())
    }
}

impl From<crate::seal::SealError> for AirError {
    fn from(e: crate::seal::SealError) -> Self {
        AirError(e.to_string())
    }
}

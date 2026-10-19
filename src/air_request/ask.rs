//! The wallet's side of a request to the mint (mint info, keys, keysets,
//! rotation): the whole flow of the design, shared so that the wallet and the
//! integration tests of the mint run the same code (REQUEST-DESIGN.md sections
//! 2, 3, 6 and 14). The flow is the same for every kind; [`ask`] returns the
//! verified reply, and the caller reads the body (for mint info,
//! [`ask_mint_info`] does).
//!
//! One request is one `request_id` and one one-off key `r`, kept by the caller
//! ([`InFlight`]) and saved through the `save` callback *before* anything is
//! sent, so a crashed or restarted wallet can retry or recover with the same
//! pair. The flow:
//!
//! 1. Read the reply cell first. A reply may already be there (a retry after a
//!    lost reply): then no request is written, and the reply is checked.
//! 2. Hold a read on the reply cell once; it stays up across the tries.
//! 3. For each try: write the request into the first free mailbox slot after the
//!    last one this request used (slots never free up), save, and wait
//!    `reply_wait_secs` for the pushed reply. The same `request_id` and `r` are
//!    used for every try, with a new seal.
//! 4. After `attempts` tries with no reply: [`AskError::Unreachable`]. The
//!    caller keeps its [`InFlight`], so the next call starts at step 1.
//!
//! A reply that arrives is opened with `r` and every check of
//! [`verify_reply`] is made. A reply that fails one is final: the cell is
//! write-once, so that request can never be answered differently, and the
//! caller should drop it (the error says so by its type).

use std::fmt;
use std::time::Duration;

use tokio::sync::mpsc;

use super::AirError;
use super::addr::{self, MAX_SLOTS_PROBED};
use super::client::{self, Client, Event, Put, ServerRef};
use super::envelope::{
    KIND_MINT_INFO, MintInfo, VerifyError, WireReply, WireRequest, check_mint_info, verify_answer,
};
use crate::ServiceDid;
use crate::seal::SecretKey;

/// What the wallet asks of which mint, and how patient it is.
#[derive(Clone, Debug)]
pub struct AskConfig {
    pub server: ServerRef,
    /// The mint's DID: where the mailbox is, and the key the reply must be signed by.
    pub mint: ServiceDid,
    /// What this wallet speaks and expects (what `verify_mint` compares).
    pub wire_version: u32,
    pub network: String,
    /// Seconds to wait for the reply on each try. The design says 30.
    pub reply_wait_secs: u64,
    /// Tries before "mint unreachable". The design says 3.
    pub attempts: u32,
    /// How far the reply's `issued_at` may be from now, in seconds.
    pub max_skew_secs: u64,
    /// How long one `Create` or `Read` may take to be answered by the server.
    pub timeout_secs: u64,
}

/// The request in flight: kept by the caller until the request is answered.
#[derive(Clone, Debug)]
pub struct InFlight {
    /// What is asked (`KIND_*`). Fixed for the life of the request: the retries
    /// are the same request.
    pub kind: u8,
    pub request_id: [u8; 32],
    /// The one-off secret key `r`; `R` is its public half.
    pub r: SecretKey,
    /// The mailbox slots this request was written to, in order.
    pub slots: Vec<u32>,
}

impl InFlight {
    /// A new mint-info request: a random id and a fresh one-off key.
    pub fn new() -> Self {
        Self::of(KIND_MINT_INFO)
    }

    /// A new request of `kind`: a random id and a fresh one-off key.
    pub fn of(kind: u8) -> Self {
        InFlight {
            kind,
            request_id: addr::random_id(),
            r: SecretKey::new(),
            slots: vec![],
        }
    }

    /// The reply cell's address is derived from these two; this is the wire
    /// request they stand for.
    pub fn request(&self) -> WireRequest {
        WireRequest::new(
            self.kind,
            self.request_id,
            addr::key_to_bytes(&self.r.public_key()),
        )
    }
}

impl Default for InFlight {
    fn default() -> Self {
        Self::new()
    }
}

/// A verified answer to a request of any kind: the mint, the signature, the
/// request id and hash, the status and the age have been checked. The body is as
/// the mint signed it; reading it is the caller's.
#[derive(Clone, Debug)]
pub struct Verified {
    pub reply: WireReply,
    /// The opened reply plaintext: the receipt. Anyone can verify it from the DID alone.
    pub receipt: Vec<u8>,
    pub request_id: [u8; 32],
    pub slots: Vec<u32>,
    /// 0 when the reply was already in its cell and no request was written.
    pub attempts_used: u32,
}

impl Verified {
    /// The signed body: the bytes the HTTP call would have returned.
    pub fn body(&self) -> &[u8] {
        &self.reply.body
    }

    /// The body read as JSON of type `T`. The error is a [`VerifyError::BadBody`]
    /// (the mint signed something that is not what was asked for).
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, VerifyError> {
        serde_json::from_slice(&self.reply.body).map_err(|e| VerifyError::BadBody(e.to_string()))
    }
}

/// A verified answer to a mint-info request.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub info: MintInfo,
    pub reply: WireReply,
    /// The opened reply plaintext: the receipt. Anyone can verify it from the DID alone.
    pub receipt: Vec<u8>,
    pub request_id: [u8; 32],
    pub slots: Vec<u32>,
    /// 0 when the reply was already in its cell and no request was written.
    pub attempts_used: u32,
}

/// Why the request did not end in a verified answer.
#[derive(Debug)]
pub enum AskError {
    /// All tries used, no reply. The request is still in flight.
    Unreachable { attempts: u32, secs: u64 },
    /// A reply arrived and failed a check. Final for this request.
    Verify(VerifyError),
    /// The reply cell held something that does not open with `r`. Final.
    NotOpenable(String),
    /// Anything else: the server, the session, the callback.
    Other(String),
}

impl fmt::Display for AskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable { attempts, secs } => write!(
                f,
                "mint unreachable: no reply after {attempts} tries of {secs} s"
            ),
            Self::Verify(e) => write!(f, "reply rejected: {e}"),
            Self::NotOpenable(e) => {
                write!(f, "the reply cell does not open with the request key: {e}")
            }
            Self::Other(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for AskError {}

impl From<AirError> for AskError {
    fn from(e: AirError) -> Self {
        AskError::Other(e.0)
    }
}

/// Write the request into the first free mailbox slot at or after `from`.
/// Returns the slot.
async fn put_in_mailbox(
    client: &Client,
    cfg: &AskConfig,
    request: &WireRequest,
    from: u32,
) -> Result<u32, AskError> {
    let mint_key = addr::did_to_key(&cfg.mint)?;
    // A new seal for every try: the same plaintext, new randomness.
    let sealed = addr::seal_to(&mint_key, &request.encode())?;
    let mut slot = from;
    loop {
        if slot >= MAX_SLOTS_PROBED {
            return Err(AskError::Other(format!(
                "no free mailbox slot below {MAX_SLOTS_PROBED}"
            )));
        }
        let key = addr::mailbox_secret(&cfg.mint, slot);
        match client::create(client, &key, sealed.clone(), cfg.timeout_secs).await? {
            Put::Created(_) => return Ok(slot),
            Put::Taken => slot += 1,
        }
    }
}

fn finish(
    cfg: &AskConfig,
    flight: &InFlight,
    request: &WireRequest,
    sealed: &[u8],
    attempts_used: u32,
) -> Result<Verified, AskError> {
    let plain = addr::open(&flight.r, sealed).map_err(|e| AskError::NotOpenable(e.0))?;
    let reply = verify_answer(
        &plain,
        &cfg.mint,
        request,
        addr::now_secs(),
        cfg.max_skew_secs,
    )
    .map_err(AskError::Verify)?;
    Ok(Verified {
        reply,
        receipt: plain,
        request_id: flight.request_id,
        slots: flight.slots.clone(),
        attempts_used,
    })
}

/// Ask the mint for its info, as described at the top of this module, and check
/// the wire version and network against `cfg`. `flight` must be a mint-info
/// request ([`InFlight::new`]).
pub async fn ask_mint_info(
    client: &Client,
    cfg: &AskConfig,
    flight: &mut InFlight,
    save: &mut dyn FnMut(&InFlight) -> Result<(), String>,
) -> Result<Outcome, AskError> {
    if flight.kind != KIND_MINT_INFO {
        return Err(AskError::Other(format!(
            "request kind {} is not mint info",
            flight.kind
        )));
    }
    let v = ask(client, cfg, flight, save).await?;
    let info =
        check_mint_info(&v.reply.body, cfg.wire_version, &cfg.network).map_err(AskError::Verify)?;
    Ok(Outcome {
        info,
        reply: v.reply,
        receipt: v.receipt,
        request_id: v.request_id,
        slots: v.slots,
        attempts_used: v.attempts_used,
    })
}

/// Ask the mint the question in `flight` (its kind), as described at the top of
/// this module. `save` is called before the first write and after each write
/// into the mailbox, with the request as it now stands; if it fails, the call
/// fails (the caller could not keep the request, so a retry would not be safe).
pub async fn ask(
    client: &Client,
    cfg: &AskConfig,
    flight: &mut InFlight,
    save: &mut dyn FnMut(&InFlight) -> Result<(), String>,
) -> Result<Verified, AskError> {
    let mint_key = addr::did_to_key(&cfg.mint)?;
    let request = flight.request();
    let shared = addr::shared_wallet(&flight.r, &mint_key);
    let cell = addr::reply_secret(&shared, &flight.request_id, 0);

    // 1. A reply may already be there (a retry after a lost reply). Read it first.
    if let Some(sealed) = client::read_once(client, cell.public_key(), cfg.timeout_secs).await? {
        return finish(cfg, flight, &request, &sealed, 0);
    }

    // Keep the request before anything is written, so a crash after a write
    // still leaves the pair that can read the reply.
    save(flight).map_err(AskError::Other)?;

    // 2. Hold the reply read once; it stays up across the tries.
    let (tx, mut rx) = mpsc::unbounded_channel();
    let held = client::hold(client, cell.public_key(), 0, tx).await;
    let result = async {
        for attempt in 1..=cfg.attempts {
            let from = flight.slots.last().map(|s| s + 1).unwrap_or(0);
            let slot = put_in_mailbox(client, cfg, &request, from).await?;
            flight.slots.push(slot);
            save(flight).map_err(AskError::Other)?;
            match tokio::time::timeout(Duration::from_secs(cfg.reply_wait_secs), rx.recv()).await {
                Ok(Some(Event::Filled(_, sealed))) => {
                    return finish(cfg, flight, &request, &sealed, attempt);
                }
                Ok(Some(Event::Lost(_))) | Ok(None) => {
                    return Err(AskError::Other(
                        "the held read on the reply cell ended (the AIR session closed)".into(),
                    ));
                }
                Err(_) => {}
            }
        }
        Err(AskError::Unreachable {
            attempts: cfg.attempts,
            secs: cfg.reply_wait_secs,
        })
    }
    .await;
    held.abort();
    result
}

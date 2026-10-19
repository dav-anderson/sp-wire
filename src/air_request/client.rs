//! The thin transport: connect to a configured AIR server, raw `Create` and
//! `Read`, and a held read that turns pushes into messages. Nothing else of AIR
//! is used (not `orange_me`, not the inbox or contract helpers).
//!
//! How the client is pointed at a server: the server is named by its public key
//! (`ServerRef::name`, AIR's compressed hex form) and reached at a host or IP
//! (`ServerRef::host`). The name is resolved through `DefaultResolver` to the
//! server's `Identity`, whose `connection` map is replaced through JSON (its
//! fields are private) with the configured host, and the result goes to
//! `Client::new(identity, "ws")`. The client verifies the server's signed
//! challenge against the name, so only the server with that key is accepted.
//! The port is fixed by the client: 5702 for `ws`, 443 for `wss` (upstream item
//! 12). Resolving a mint DID to a server DID and host is upstream item 4; for
//! now both are configuration.
//!
//! All of it is async; a blocking caller builds a runtime (see
//! [`block_on_new_runtime`]).

use std::str::FromStr;
use std::time::Duration;

use air::{DefaultResolver, KeySigned, Name, PublicKey, Request, Resolver, Response, SecretKey};
pub use air_server::Client;
use tokio::sync::mpsc::UnboundedSender;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::AirError;

/// Which AIR server to talk to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerRef {
    /// The server's name: its public key in AIR's compressed hex form (66 characters).
    pub name: String,
    /// Host or IP only, no port. `127.0.0.1` for a server on this machine.
    pub host: String,
}

/// Connect to the server. Fails with a message that names the host.
pub async fn connect(server: &ServerRef) -> Result<Client, AirError> {
    let name = Name::from_str(server.name.trim())
        .map_err(|e| AirError(format!("the AIR server's name is not a public key: {e:?}")))?;
    let mut resolver = DefaultResolver::default();
    let resolved = resolver.resolve(name, None).await;
    let mut value = serde_json::to_value(&*resolved).map_err(|e| AirError(e.to_string()))?;
    value["connection"] = serde_json::json!({ "ws": [server.host.trim()] });
    let identity: air::Identity =
        serde_json::from_value(value).map_err(|e| AirError(format!("identity: {e}")))?;
    Client::new(identity, "ws").await.map_err(|e| {
        AirError(format!(
            "cannot reach the AIR server at {}: {e}",
            server.host.trim()
        ))
    })
}

/// The result of a `Create` into a write-once cell.
#[derive(Debug, PartialEq, Eq)]
pub enum Put {
    /// This call wrote the cell (the server's time).
    Created(u64),
    /// The cell already held a record (the server returns it); nothing was written.
    Taken,
}

/// `Create` `payload` in the cell whose secret is `key`. Write-once: the first
/// `Create` wins and a later one comes back as [`Put::Taken`].
pub async fn create(
    client: &Client,
    key: &SecretKey,
    payload: Vec<u8>,
    seconds: u64,
) -> Result<Put, AirError> {
    let rx = client
        .send(Request::Create(KeySigned::new(key, payload)))
        .await;
    match timeout(Duration::from_secs(seconds), rx.recv()).await {
        Ok(Ok(Response::Created(ts))) => Ok(Put::Created(ts)),
        Ok(Ok(Response::Read(_, Some(_)))) => Ok(Put::Taken),
        Ok(Ok(other)) => Err(AirError(format!("Create returned {other:?}"))),
        Ok(Err(e)) => Err(AirError(format!("response channel closed: {e:?}"))),
        Err(_) => Err(AirError(format!("no answer to Create within {seconds} s"))),
    }
}

/// One read. `None` when the cell is empty (the server answers `Read(ts, None)`
/// at once and keeps a subscription; dropping the receiver, as happens here,
/// cancels it).
pub async fn read_once(
    client: &Client,
    key: PublicKey,
    seconds: u64,
) -> Result<Option<Vec<u8>>, AirError> {
    let rx = client.send(Request::Read(key)).await;
    match timeout(Duration::from_secs(seconds), rx.recv()).await {
        Ok(Ok(Response::Read(_, Some((_, bytes))))) => Ok(Some(bytes)),
        Ok(Ok(Response::Read(_, None))) => Ok(None),
        Ok(Ok(other)) => Err(AirError(format!("Read returned {other:?}"))),
        Ok(Err(e)) => Err(AirError(format!("response channel closed: {e:?}"))),
        Err(_) => Err(AirError(format!("no answer to Read within {seconds} s"))),
    }
}

/// What a held read reports. `tag` is whatever the caller gave (the slot
/// number, or 0).
#[derive(Debug)]
pub enum Event {
    /// The cell holds this record (it was there already, or the first `Create`
    /// just landed).
    Filled(u32, Vec<u8>),
    /// The response stream ended without a record: the session closed or was refused.
    Lost(u32),
}

/// Hold a read on `key`: the server answers `Read(ts, None)` (the
/// acknowledgement, ignored here) and later pushes the record on the same
/// receiver. Aborting the returned handle drops the receiver, which cancels the
/// subscription. A client session may hold fewer than 256 reads: the 257th is
/// refused and closes the session (upstream item 13).
pub async fn hold(
    client: &Client,
    key: PublicKey,
    tag: u32,
    events: UnboundedSender<Event>,
) -> JoinHandle<()> {
    let rx = client.send(Request::Read(key)).await;
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(Response::Read(_, Some((_, bytes)))) => {
                    let _ = events.send(Event::Filled(tag, bytes));
                    return;
                }
                Ok(Response::Read(_, None)) => continue,
                Ok(other) => {
                    eprintln!("held read {tag}: unexpected {other:?}");
                    continue;
                }
                Err(_) => {
                    let _ = events.send(Event::Lost(tag));
                    return;
                }
            }
        }
    })
}

/// Run the future `make` builds to the end on a runtime built for it, on a
/// thread of its own. For blocking callers (the wallet's library is blocking): it
/// works whether or not the calling thread is inside another runtime, which
/// `Runtime::block_on` would refuse. `make` runs on the new thread, so the
/// future need not be `Send`, and `make` may borrow from the caller (the thread
/// is scoped and joined before this returns).
pub fn block_on_new_runtime<F, T>(make: impl FnOnce() -> F + Send) -> Result<T, AirError>
where
    F: std::future::Future<Output = T>,
    T: Send,
{
    std::thread::scope(|scope| -> Result<T, AirError> {
        std::thread::Builder::new()
            .name("air-request".into())
            .spawn_scoped(scope, move || -> Result<T, AirError> {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| AirError(format!("could not start a runtime: {e}")))?;
                Ok(runtime.block_on(make()))
            })
            .map_err(|e| AirError(format!("could not start a thread: {e}")))?
            .join()
            .map_err(|_| AirError("the AIR request thread panicked".into()))?
    })
}

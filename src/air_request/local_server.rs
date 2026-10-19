//! An `air_server` in this process, for the integration tests of the crates that
//! use the transport (sp-wire, psp-mint, ecash-wallet). Not for production: it
//! listens on loopback only, with a throwaway identity and a database in the
//! temporary folder.
//!
//! The AIR client always dials port 5702 (upstream item 12), so the server must
//! listen on `127.0.0.1:5702`: there cannot be a free port. [`start`] refuses
//! with a message when something else already listens there. One server is
//! started per process however often [`start`] is called, so the tests of one
//! test binary share it (each test uses its own DIDs, so cells never mix); cargo
//! runs test binaries one after another, so a binary finds the port free when
//! the one before it has exited.
//!
//! The server reads its settings from environment variables at start
//! (`AIR_WS_ADDR`, `AIR_HEALTH_ADDR`, `AIR_STORAGE`), so they are set here
//! before it starts, once.

use std::net::{TcpListener, TcpStream};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use air::Secret;

use super::AirError;
use super::client::ServerRef;

/// The port the AIR client dials for `ws`.
pub const PORT: u16 = 5702;

static SERVER: OnceLock<Result<ServerRef, String>> = OnceLock::new();

/// Start the server (once per process) and return how to reach it.
pub fn start() -> Result<ServerRef, AirError> {
    SERVER.get_or_init(spawn).clone().map_err(AirError)
}

fn spawn() -> Result<ServerRef, String> {
    if TcpListener::bind(("127.0.0.1", PORT)).is_err() {
        return Err(format!(
            "something already listens on 127.0.0.1:{PORT}. The AIR client always dials that port, \
             so the test server needs it: stop the other air_server (or the other test run) and try again"
        ));
    }
    let dir = std::env::temp_dir().join(format!("sp-wire-air-server-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    // SAFETY: set once, before the server thread starts, and read by it at start.
    unsafe {
        std::env::set_var("AIR_WS_ADDR", format!("127.0.0.1:{PORT}"));
        std::env::set_var("AIR_HEALTH_ADDR", "127.0.0.1:0");
        std::env::set_var("AIR_STORAGE", dir.join("STORAGE.db"));
    }
    let secret = Secret::new();
    let name = secret.name().to_string();
    std::thread::Builder::new()
        .name("air-local-server".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("a runtime for the test AIR server");
            runtime.block_on(air_server::Server::start(secret));
        })
        .map_err(|e| format!("could not start the test AIR server: {e}"))?;
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], PORT));
    let until = Instant::now() + Duration::from_secs(15);
    while Instant::now() < until {
        if TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok() {
            return Ok(ServerRef {
                name,
                host: "127.0.0.1".into(),
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "the test AIR server did not start listening on 127.0.0.1:{PORT} within 15 s"
    ))
}

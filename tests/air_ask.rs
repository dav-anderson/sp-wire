//! `ask_mint_info` against an air_server started in this process (feature
//! `air-client`), with a task standing in for the mint. Port 5702 is needed, as
//! for `air_client.rs`.
//!
//! The task is the mint's side as the mints run it: it holds a read on its
//! mailbox slot, opens what arrives with [`answer_request`], and writes the
//! signed reply into the reply cell. Nothing here waits a fixed time: the task
//! wakes when the request is written, and the wallet when the reply is.

#![cfg(feature = "air-client")]

use sp_wire::ServiceDid;
use sp_wire::air_request::addr;
use sp_wire::air_request::ask::{AskConfig, AskError, InFlight, ask_mint_info};
use sp_wire::air_request::client::{self, Event, ServerRef};
use sp_wire::air_request::envelope::{
    KIND_MINT_INFO, MintInfo, STATUS_REFUSED, Served, VerifyError, answer_request,
};
use sp_wire::air_request::local_server;
use sp_wire::seal::SecretKey;
use tokio::sync::mpsc::unbounded_channel;
use tokio::task::JoinHandle;

fn config(server: &ServerRef, mint: ServiceDid) -> AskConfig {
    AskConfig {
        server: server.clone(),
        mint,
        wire_version: 3,
        network: "regtest".into(),
        // Upper bounds for a failure, not waits: the reply is pushed when written.
        reply_wait_secs: 20,
        attempts: 1,
        max_skew_secs: 300,
        timeout_secs: 10,
    }
}

fn info(wire_version: u32, network: &str) -> MintInfo {
    MintInfo {
        status: "ok".into(),
        wire_version,
        network: network.into(),
    }
}

/// What the mint says to the request: an answer with this body, or a refusal
/// with it.
#[derive(Clone)]
enum Says {
    Answer(Vec<u8>),
    Refusal(Vec<u8>),
}

fn answer(info: &MintInfo) -> Says {
    Says::Answer(serde_json::to_vec(info).unwrap())
}

/// A mint that says `says` to the first request in its mailbox and then ends.
/// Returns its DID and the task.
async fn mint(server: &ServerRef, says: Says) -> (ServiceDid, JoinHandle<()>) {
    let key = SecretKey::new();
    let did = addr::key_to_did(&key.public_key());
    let c = client::connect(server).await.unwrap();
    let (tx, mut rx) = unbounded_channel();
    // A record written before this read reaches the server is pushed at once,
    // so the wallet may write first.
    let held = client::hold(&c, addr::mailbox_secret(&did, 0).public_key(), 0, tx).await;
    let task = tokio::spawn(async move {
        let Some(Event::Filled(_, sealed)) = rx.recv().await else {
            panic!("the mint's read ended without a request");
        };
        let reply = answer_request(&key, &sealed, addr::now_secs(), &|kind, _| {
            assert_eq!(kind, KIND_MINT_INFO);
            Some(match says.clone() {
                Says::Answer(body) => Served::Body(body),
                Says::Refusal(body) => Served::Refused(body),
            })
        })
        .unwrap();
        client::create(&c, &reply.reply_cell, reply.sealed_reply, 10)
            .await
            .unwrap();
        held.abort();
    });
    (did, task)
}

#[tokio::test(flavor = "multi_thread")]
async fn ask_mint_info_passes_a_genuine_reply_and_names_what_is_wrong_with_the_others() {
    let server = local_server::start().unwrap();
    let wallet = client::connect(&server).await.unwrap();
    let mut saved = 0;

    // A genuine reply: the right wire version and network.
    let (did, task) = mint(&server, answer(&info(3, "regtest"))).await;
    let mut flight = InFlight::new();
    let outcome = ask_mint_info(&wallet, &config(&server, did), &mut flight, &mut |_| {
        saved += 1;
        Ok(())
    })
    .await
    .expect("a genuine reply passes");
    task.await.unwrap();
    assert_eq!(outcome.info, info(3, "regtest"));
    assert_eq!(outcome.request_id, flight.request_id);
    assert_eq!(outcome.reply.request_id, flight.request_id);
    assert_eq!(outcome.reply.mint_did, *did.as_bytes());
    assert_eq!(outcome.slots, vec![0]);
    assert_eq!(outcome.attempts_used, 1);
    // The request is kept before it is written and again after.
    assert_eq!(saved, 2);
    assert_eq!(flight.slots, vec![0]);

    // Another wire version: refused, and the error says both.
    let (did, task) = mint(&server, answer(&info(4, "regtest"))).await;
    let err = ask_mint_info(
        &wallet,
        &config(&server, did),
        &mut InFlight::new(),
        &mut |_| Ok(()),
    )
    .await
    .expect_err("another wire version is refused");
    task.await.unwrap();
    match err {
        AskError::Verify(e) => assert_eq!(e, VerifyError::WireVersion { theirs: 4, ours: 3 }),
        other => panic!("{other:?}"),
    }

    // Another network: refused, and the error says both.
    let (did, task) = mint(&server, answer(&info(3, "mainnet"))).await;
    let err = ask_mint_info(
        &wallet,
        &config(&server, did),
        &mut InFlight::new(),
        &mut |_| Ok(()),
    )
    .await
    .expect_err("another network is refused");
    task.await.unwrap();
    match err {
        AskError::Verify(e) => assert_eq!(
            e,
            VerifyError::Network {
                theirs: "mainnet".into(),
                ours: "regtest".into()
            }
        ),
        other => panic!("{other:?}"),
    }

    // A body that is not mint info.
    let (did, task) = mint(&server, Says::Answer(b"not json".to_vec())).await;
    let err = ask_mint_info(
        &wallet,
        &config(&server, did),
        &mut InFlight::new(),
        &mut |_| Ok(()),
    )
    .await
    .expect_err("a body that is not mint info is refused");
    task.await.unwrap();
    assert!(
        matches!(err, AskError::Verify(VerifyError::BadBody(_))),
        "{err:?}"
    );

    // A signed refusal.
    let (did, task) = mint(&server, Says::Refusal(br#"{"error":"no"}"#.to_vec())).await;
    let err = ask_mint_info(
        &wallet,
        &config(&server, did),
        &mut InFlight::new(),
        &mut |_| Ok(()),
    )
    .await
    .expect_err("a refusal is an error");
    task.await.unwrap();
    match err {
        AskError::Verify(e) => assert_eq!(e, VerifyError::Refused(STATUS_REFUSED)),
        other => panic!("{other:?}"),
    }
}

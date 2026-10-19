//! The AIR transport against an air_server started in this process (feature
//! `air-client`). Port 5702 is needed: the AIR client dials no other (see
//! `air_request::local_server`).

#![cfg(feature = "air-client")]

use std::time::Duration;

use sp_wire::air_request::addr::{self, mailbox_secret};
use sp_wire::air_request::client::{self, Event, Put};
use sp_wire::air_request::local_server;
use sp_wire::seal::SecretKey;
use tokio::sync::mpsc::unbounded_channel;

#[tokio::test(flavor = "multi_thread")]
async fn create_is_write_once_and_read_sees_it() {
    let server = local_server::start().unwrap();
    let c = client::connect(&server).await.unwrap();
    let key = SecretKey::new();
    // empty
    assert_eq!(
        client::read_once(&c, key.public_key(), 10).await.unwrap(),
        None
    );
    // the first Create wins
    assert!(matches!(
        client::create(&c, &key, b"first".to_vec(), 10)
            .await
            .unwrap(),
        Put::Created(_)
    ));
    assert_eq!(
        client::create(&c, &key, b"second".to_vec(), 10)
            .await
            .unwrap(),
        Put::Taken
    );
    assert_eq!(
        client::read_once(&c, key.public_key(), 10).await.unwrap(),
        Some(b"first".to_vec())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_held_read_is_pushed_when_the_cell_is_filled() {
    let server = local_server::start().unwrap();
    let reader = client::connect(&server).await.unwrap();
    let writer = client::connect(&server).await.unwrap();
    let key = SecretKey::new();
    let (tx, mut rx) = unbounded_channel();
    let _held = client::hold(&reader, key.public_key(), 9, tx).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err(),
        "nothing is pushed while the cell is empty"
    );
    client::create(&writer, &key, b"pushed".to_vec(), 10)
        .await
        .unwrap();
    match tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .unwrap()
        .unwrap()
    {
        Event::Filled(tag, bytes) => {
            assert_eq!(tag, 9);
            assert_eq!(bytes, b"pushed".to_vec());
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mailbox_slot_can_be_written_by_anyone_who_knows_the_mint_did() {
    let server = local_server::start().unwrap();
    let c = client::connect(&server).await.unwrap();
    let mint = addr::key_to_did(&SecretKey::new().public_key());
    let slot0 = mailbox_secret(&mint, 0);
    assert!(matches!(
        client::create(&c, &slot0, b"a".to_vec(), 10).await.unwrap(),
        Put::Created(_)
    ));
    assert_eq!(
        client::create(&c, &slot0, b"b".to_vec(), 10).await.unwrap(),
        Put::Taken
    );
    let slot1 = mailbox_secret(&mint, 1);
    assert!(matches!(
        client::create(&c, &slot1, b"b".to_vec(), 10).await.unwrap(),
        Put::Created(_)
    ));
}

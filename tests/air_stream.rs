//! The mints' key streams against an air_server started in this process
//! (feature `air-client`). Port 5702 is needed, as for `air_client.rs`.

#![cfg(feature = "air-client")]

use std::time::Duration;

use sp_wire::Amount;
use sp_wire::air_request::client::{self, Event};
use sp_wire::air_request::delivery::Written;
use sp_wire::air_request::stream::{
    Cell, ControlRecord, GenerationRef, KeysetRecord, cell_address, find_end, publish_keysets,
    read_cell, read_keyset_tail, read_keysets_from, write_cell,
};
use sp_wire::air_request::{addr, local_server};
use sp_wire::seal::SecretKey;

fn control(index: u32) -> ControlRecord {
    ControlRecord {
        index,
        maturity_days: 365,
        current: GenerationRef {
            epoch: u64::from(index),
            id: [index as u8; 8],
        },
        previous: None,
    }
}

/// Fails if a cell is not where `cell_address` says: the writer signs with the
/// mint's tweaked secret, the reader names the tweaked public key.
#[tokio::test(flavor = "multi_thread")]
async fn a_record_is_written_once_and_anyone_reads_it_from_the_dids_address() {
    let server = local_server::start().unwrap();
    let mint = client::connect(&server).await.unwrap();
    let reader = client::connect(&server).await.unwrap();
    let mint_key = SecretKey::new();
    let did = addr::key_to_did(&mint_key.public_key());
    let cell = Cell::Control { index: 0 };
    let bytes = control(0).encode();

    assert_eq!(read_cell(&reader, &did, &cell, 10).await.unwrap(), None);
    assert_eq!(
        write_cell(&mint, &mint_key, &cell, &bytes, 10)
            .await
            .unwrap(),
        Written::Created
    );
    // a write that was not acknowledged is safe to repeat
    assert_eq!(
        write_cell(&mint, &mint_key, &cell, &bytes, 10)
            .await
            .unwrap(),
        Written::AlreadyStored
    );
    // another record for the same cell is left out, not written over
    assert_eq!(
        write_cell(&mint, &mint_key, &cell, &control(1).encode(), 10)
            .await
            .unwrap(),
        Written::Different
    );
    let read = read_cell(&reader, &did, &cell, 10).await.unwrap().unwrap();
    assert_eq!(read, bytes);
    assert_eq!(ControlRecord::decode(&read).unwrap(), control(0));
    // the keyset stream and the control stream of one mint do not meet
    assert_eq!(
        read_cell(&reader, &did, &Cell::Keyset { index: 0 }, 10)
            .await
            .unwrap(),
        None
    );
}

/// Fails if the search for the end of a stream is off by one anywhere: for each
/// length, the answer is the length.
#[tokio::test(flavor = "multi_thread")]
async fn the_end_of_a_stream_is_found_for_every_length() {
    let server = local_server::start().unwrap();
    let mint = client::connect(&server).await.unwrap();
    let reader = client::connect(&server).await.unwrap();
    for length in [0u32, 1, 2, 3, 4, 5, 7, 8, 9, 16, 17] {
        let mint_key = SecretKey::new();
        let did = addr::key_to_did(&mint_key.public_key());
        for i in 0..length {
            let cell = Cell::Control { index: i };
            write_cell(&mint, &mint_key, &cell, &control(i).encode(), 10)
                .await
                .unwrap();
        }
        let end = find_end(&reader, &did, |i| Cell::Control { index: i }, 10)
            .await
            .unwrap();
        assert_eq!(end, length, "a stream of {length} records");
    }
}

/// Fails if a held read on the next cell is not answered when the mint writes
/// it: a wallet's subscription would never see a rotation.
#[tokio::test(flavor = "multi_thread")]
async fn a_held_read_on_the_next_cell_is_pushed_the_record() {
    let server = local_server::start().unwrap();
    let mint = client::connect(&server).await.unwrap();
    let wallet = client::connect(&server).await.unwrap();
    let mint_key = SecretKey::new();
    let did = addr::key_to_did(&mint_key.public_key());
    let record = KeysetRecord::decode(&{
        // one 1-unit key: the generator, as a record
        let mut v = vec![1u8, 1];
        v.extend_from_slice(&9u64.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&1u64.to_be_bytes());
        v.extend_from_slice(
            &hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
        );
        v
    })
    .unwrap();
    let cell = Cell::Keyset { index: 0 };

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let held = client::hold(&wallet, cell_address(&did, &cell).unwrap(), 7, tx).await;
    assert_eq!(
        write_cell(&mint, &mint_key, &cell, &record.encode(), 10)
            .await
            .unwrap(),
        Written::Created
    );
    match tokio::time::timeout(Duration::from_secs(20), rx.recv()).await {
        Ok(Some(Event::Filled(7, bytes))) => {
            assert_eq!(KeysetRecord::decode(&bytes).unwrap(), record)
        }
        other => panic!("the held read was not pushed the record: {other:?}"),
    }
    held.abort();
}

/// A key set with the one key of the secret `[n; 32]` for 1 unit.
fn keyset(epoch: u64, n: u8) -> KeysetRecord {
    let key = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &[n; 32])
        .unwrap()
        .public_key();
    KeysetRecord {
        epoch,
        keys: [(Amount::from_units(1), key)].into_iter().collect(),
    }
}

/// Fails if a key set is written twice, or not at all, across the calls a mint
/// makes at start, at a rotation and after a restart (the function keeps no state).
#[tokio::test(flavor = "multi_thread")]
async fn a_mint_publishes_each_key_set_once_in_epoch_order() {
    let server = local_server::start().unwrap();
    let mint = client::connect(&server).await.unwrap();
    let wallet = client::connect(&server).await.unwrap();
    let mint_key = SecretKey::new();
    let did = addr::key_to_did(&mint_key.public_key());
    let (a, b, c) = (keyset(0, 1), keyset(1, 2), keyset(2, 3));

    // first start: one live key set
    let first = publish_keysets(&mint, &mint_key, std::slice::from_ref(&a), 10)
        .await
        .unwrap();
    assert_eq!((first.end, first.written), (1, vec![0]));
    // a restart finds it and writes nothing
    let again = publish_keysets(&mint, &mint_key, std::slice::from_ref(&a), 10)
        .await
        .unwrap();
    assert_eq!((again.end, again.written), (1, vec![]));
    // a rotation: previous and current are live; only the new one is written
    let rotated = publish_keysets(&mint, &mint_key, &[a.clone(), b.clone()], 10)
        .await
        .unwrap();
    assert_eq!((rotated.end, rotated.written), (2, vec![1]));
    // the next rotation: a leaves the live pair, c is written after b
    let next = publish_keysets(&mint, &mint_key, &[b.clone(), c.clone()], 10)
        .await
        .unwrap();
    assert_eq!((next.end, next.written), (3, vec![2]));
    let restart = publish_keysets(&mint, &mint_key, &[b.clone(), c.clone()], 10)
        .await
        .unwrap();
    assert_eq!((restart.end, restart.written), (3, vec![]));

    // a wallet sees the last two, with their places, and can catch up from any record
    let tail = read_keyset_tail(&wallet, &did, 10).await.unwrap();
    assert_eq!(tail.end, 3);
    assert_eq!(tail.last, vec![(1, b.clone()), (2, c.clone())]);
    assert_eq!(
        read_keysets_from(&wallet, &did, 1, 10).await.unwrap(),
        vec![(1, b), (2, c)]
    );
    assert_eq!(
        read_keysets_from(&wallet, &did, 3, 10).await.unwrap(),
        vec![]
    );
}

/// Fails if a mint with two live key sets and an empty stream writes them in
/// the wrong order (the previous must come first), or one of them twice.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_stream_gets_the_previous_key_set_before_the_current_one() {
    let server = local_server::start().unwrap();
    let mint = client::connect(&server).await.unwrap();
    let mint_key = SecretKey::new();
    let (prev, cur) = (keyset(4, 4), keyset(5, 5));
    let done = publish_keysets(&mint, &mint_key, &[prev.clone(), cur.clone()], 10)
        .await
        .unwrap();
    assert_eq!((done.end, done.written), (2, vec![0, 1]));
    let did = addr::key_to_did(&mint_key.public_key());
    let tail = read_keyset_tail(&mint, &did, 10).await.unwrap();
    assert_eq!(tail.last, vec![(0, prev), (1, cur)]);
}

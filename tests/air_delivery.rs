//! The delivery record against an air_server started in this process (feature
//! `air-client`). Port 5702 is needed, as for `air_client.rs`.

#![cfg(feature = "air-client")]

use std::collections::BTreeMap;
use std::time::Duration;

use sp_wire::air_request::addr;
use sp_wire::air_request::client;
use sp_wire::air_request::delivery::{
    Outcome, Refused, Signed, SignedOutput, Written, build_record, delivery_address, open_record,
    purchase_id, read_record, read_records, write_record,
};
use sp_wire::air_request::local_server;
use sp_wire::psp::KeysetsResponse;
use sp_wire::seal::SecretKey;

fn signed() -> Outcome {
    Outcome::Signed(Signed {
        keyset: "k".to_string(),
        signatures: vec![SignedOutput {
            blind_nonce: "02aa".to_string(),
            signature: "03bb".to_string(),
        }],
        keysets: KeysetsResponse {
            current: "k".to_string(),
            previous: None,
            keysets: BTreeMap::new(),
        },
        skipped_units: 0,
        credit_cents: 0,
        open_until: 0,
        rules: None,
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_record_is_written_once_and_read_twice() {
    let server = local_server::start().unwrap();
    let psp_writer = client::connect(&server).await.unwrap();
    let wallet = client::connect(&server).await.unwrap();
    let psp_key = SecretKey::new();
    let reply_key = SecretKey::new();
    let psp = addr::key_to_did(&psp_key.public_key());
    let reply = addr::key_to_did(&reply_key.public_key());
    let purchase = purchase_id(b"a payload");
    let address = delivery_address(&psp, &reply, &purchase);

    // nothing there yet: a read with no wait says so
    assert_eq!(read_record(&wallet, &address, 10, 0).await.unwrap(), None);

    let built = build_record(&psp_key, &reply, &purchase, &signed(), addr::now_secs()).unwrap();
    assert_eq!(
        write_record(&psp_writer, &built.cell, &built.sealed, 10)
            .await
            .unwrap(),
        Written::Created
    );
    // the same bytes again: stored already
    assert_eq!(
        write_record(&psp_writer, &built.cell, &built.sealed, 10)
            .await
            .unwrap(),
        Written::AlreadyStored
    );
    // another record for the same purchase (a seal is randomised, so it differs)
    let other = build_record(&psp_key, &reply, &purchase, &signed(), addr::now_secs()).unwrap();
    assert_eq!(
        write_record(&psp_writer, &built.cell, &other.sealed, 10)
            .await
            .unwrap(),
        Written::Different
    );

    // read twice: the same record, and it opens
    for _ in 0..2 {
        let sealed = read_record(&wallet, &address, 10, 0)
            .await
            .unwrap()
            .expect("the record is there");
        assert_eq!(sealed, built.sealed);
        let opened = open_record(&reply_key, &psp, &purchase, &sealed).unwrap();
        assert_eq!(opened.outcome, signed());
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_held_read_gets_the_record_when_it_arrives() {
    let server = local_server::start().unwrap();
    let psp_writer = client::connect(&server).await.unwrap();
    let wallet = client::connect(&server).await.unwrap();
    let psp_key = SecretKey::new();
    let reply_key = SecretKey::new();
    let psp = addr::key_to_did(&psp_key.public_key());
    let reply = addr::key_to_did(&reply_key.public_key());
    let purchase = purchase_id(b"another payload");
    let address = delivery_address(&psp, &reply, &purchase);
    let outcome = Outcome::Refused(Refused {
        reason: "UnknownDenomination".to_string(),
        paid_sats: 5_000,
        paid_cents: 500,
        open_until: 1_000,
        rules: None,
    });
    let built = build_record(&psp_key, &reply, &purchase, &outcome, addr::now_secs()).unwrap();

    let writer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        write_record(&psp_writer, &built.cell, &built.sealed, 10)
            .await
            .unwrap()
    });
    let sealed = read_record(&wallet, &address, 10, 20)
        .await
        .unwrap()
        .expect("the held read is answered");
    assert_eq!(writer.await.unwrap(), Written::Created);
    assert_eq!(
        open_record(&reply_key, &psp, &purchase, &sealed)
            .unwrap()
            .outcome,
        outcome
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_that_times_out_says_nothing_arrived() {
    let server = local_server::start().unwrap();
    let wallet = client::connect(&server).await.unwrap();
    let psp = addr::key_to_did(&SecretKey::new().public_key());
    let reply = addr::key_to_did(&SecretKey::new().public_key());
    let address = delivery_address(&psp, &reply, &purchase_id(b"never"));
    assert_eq!(read_record(&wallet, &address, 10, 1).await.unwrap(), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn several_records_are_read_together_within_one_wait() {
    let server = local_server::start().unwrap();
    let psp_writer = client::connect(&server).await.unwrap();
    let wallet = client::connect(&server).await.unwrap();
    let psp_key = SecretKey::new();
    let psp = addr::key_to_did(&psp_key.public_key());
    let mut readers = Vec::new();
    for n in 0..3u8 {
        let reply_key = SecretKey::new();
        let reply = addr::key_to_did(&reply_key.public_key());
        let purchase = purchase_id(&[n]);
        readers.push((reply_key, reply, purchase));
    }
    let addresses: Vec<_> = readers
        .iter()
        .map(|(_, reply, purchase)| delivery_address(&psp, reply, purchase))
        .collect();

    // the first is there already, the second arrives while the wallet waits,
    // the third never does
    let first = build_record(&psp_key, &readers[0].1, &readers[0].2, &signed(), 5).unwrap();
    write_record(&psp_writer, &first.cell, &first.sealed, 10)
        .await
        .unwrap();
    let second = build_record(&psp_key, &readers[1].1, &readers[1].2, &signed(), 5).unwrap();
    let writer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        write_record(&psp_writer, &second.cell, &second.sealed, 10)
            .await
            .unwrap();
        second.sealed
    });
    let started = std::time::Instant::now();
    let found = read_records(&wallet, &addresses, 10, 3).await.unwrap();
    let second_sealed = writer.await.unwrap();
    assert_eq!(found.len(), 3);
    assert_eq!(found[0].as_deref(), Some(&first.sealed[..]));
    assert_eq!(found[1].as_deref(), Some(&second_sealed[..]));
    assert_eq!(found[2], None);
    // one wait for all, not one each
    assert!(started.elapsed() < Duration::from_secs(8));
}

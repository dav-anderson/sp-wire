//! The owed record against an air_server started in this process (feature
//! `air-client`). Port 5702 is needed, as for `air_client.rs`.

#![cfg(feature = "air-client")]

use std::time::Duration;

use sp_wire::air_request::KIND_PSP_CLAIM;
use sp_wire::air_request::addr;
use sp_wire::air_request::client;
use sp_wire::air_request::delivery::{
    ClaimTerms, EXPIRY_NOTICE, Outcome, Owed, SEND_PURCHASE_CLAIM, Written, build_record,
    open_record, owed_address, read_record, read_records, write_record,
};
use sp_wire::air_request::local_server;
use sp_wire::seal::SecretKey;

fn owed(txid: &str) -> Outcome {
    Outcome::Owed(Owed {
        txid: txid.repeat(32),
        paid_sats: 30_000,
        value_units: 30,
        terms: ClaimTerms {
            send: SEND_PURCHASE_CLAIM.to_string(),
            kind: KIND_PSP_CLAIM,
            due_units: 27,
            read_prepaid_units: 2,
            write_prepaid_units: 1,
            window_secs: sp_wire::psp::CLAIM_WINDOW_SECS,
            max_attempts: 2,
            on_expiry: EXPIRY_NOTICE.to_string(),
        },
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn a_record_is_written_once_and_read_twice() {
    let server = local_server::start().unwrap();
    let psp_writer = client::connect(&server).await.unwrap();
    let wallet = client::connect(&server).await.unwrap();
    let psp_key = SecretKey::new();
    let claim_key = SecretKey::new();
    let psp = addr::key_to_did(&psp_key.public_key());
    let claim = addr::key_to_did(&claim_key.public_key());
    let address = owed_address(&psp, &claim, 0);

    // nothing there yet: a read with no wait says so
    assert_eq!(read_record(&wallet, &address, 10, 0).await.unwrap(), None);

    let built = build_record(&psp_key, &claim, 0, &owed("ab"), addr::now_secs()).unwrap();
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
    // another record for the same cell (a seal is randomised, so it differs)
    let other = build_record(&psp_key, &claim, 0, &owed("ab"), addr::now_secs()).unwrap();
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
        let opened = open_record(&claim_key, &psp, 0, &sealed).unwrap();
        assert_eq!(opened.outcome, owed("ab"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_held_read_gets_the_record_when_it_arrives() {
    let server = local_server::start().unwrap();
    let psp_writer = client::connect(&server).await.unwrap();
    let wallet = client::connect(&server).await.unwrap();
    let psp_key = SecretKey::new();
    let claim_key = SecretKey::new();
    let psp = addr::key_to_did(&psp_key.public_key());
    let claim = addr::key_to_did(&claim_key.public_key());
    let address = owed_address(&psp, &claim, 4);
    let outcome = owed("cd");
    let built = build_record(&psp_key, &claim, 4, &outcome, addr::now_secs()).unwrap();

    let writer = tokio::spawn(async move {
        // This delay is not asserted on: it only lets the read be held first; the record arrives either way.
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
        open_record(&claim_key, &psp, 4, &sealed).unwrap().outcome,
        outcome
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_read_that_times_out_says_nothing_arrived() {
    let server = local_server::start().unwrap();
    let wallet = client::connect(&server).await.unwrap();
    let psp = addr::key_to_did(&SecretKey::new().public_key());
    let claim = addr::key_to_did(&SecretKey::new().public_key());
    let address = owed_address(&psp, &claim, 0);
    assert_eq!(read_record(&wallet, &address, 10, 1).await.unwrap(), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_wallet_reads_the_records_of_one_claim_key_until_a_cell_is_empty() {
    let server = local_server::start().unwrap();
    let psp_writer = client::connect(&server).await.unwrap();
    let wallet = client::connect(&server).await.unwrap();
    let psp_key = SecretKey::new();
    let psp = addr::key_to_did(&psp_key.public_key());
    let claim_key = SecretKey::new();
    let claim = addr::key_to_did(&claim_key.public_key());
    let addresses: Vec<_> = (0..3).map(|n| owed_address(&psp, &claim, n)).collect();

    // two payments paid with this claim key: cells 0 and 1 are written, 2 never is
    let first = build_record(&psp_key, &claim, 0, &owed("ab"), 5).unwrap();
    let second = build_record(&psp_key, &claim, 1, &owed("cd"), 5).unwrap();
    for built in [&first, &second] {
        write_record(&psp_writer, &built.cell, &built.sealed, 10)
            .await
            .unwrap();
    }
    let found = read_records(&wallet, &addresses, 10, 0).await.unwrap();
    assert_eq!(found.len(), 3);
    assert_eq!(found[0].as_deref(), Some(&first.sealed[..]));
    assert_eq!(found[1].as_deref(), Some(&second.sealed[..]));
    assert_eq!(found[2], None);
    // each opens at its own index, and says which transaction it is for
    for (n, txid) in [(0u32, "ab"), (1, "cd")] {
        let sealed = found[n as usize].as_deref().unwrap();
        let Outcome::Owed(record) = open_record(&claim_key, &psp, n, sealed).unwrap().outcome;
        assert_eq!(record.txid, txid.repeat(32));
    }
}

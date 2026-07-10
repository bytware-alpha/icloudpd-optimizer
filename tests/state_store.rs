use std::fs;
use std::path::PathBuf;
use std::thread;

use icloudpd_optimizer::manifest::{AssetRecord, Manifest, State};
use icloudpd_optimizer::state_store::{AssetStateStore, AssetStateStoreError};
use serde_json::json;

fn manifest_with_record(asset_id: &str) -> Manifest {
    let mut manifest = Manifest::new();
    manifest.upsert(AssetRecord::new(
        asset_id,
        PathBuf::from(format!("/photos/{asset_id}.dng")),
    ));
    manifest
}

#[test]
fn imports_json_once_and_reopens_durable_record_updates() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let manifest = manifest_with_record("asset-1");
    manifest.save_atomic(&manifest_path).expect("save json");

    let store = AssetStateStore::open(&manifest_path).expect("open store");
    let mut imported = store.load_or_import().expect("import json");
    imported
        .transition("asset-1", State::NasVerified, "nas", json!({"ok": true}))
        .expect("transition");
    store
        .persist_record(imported.get("asset-1").expect("asset"))
        .expect("persist record");

    let reopened = AssetStateStore::open(&manifest_path)
        .expect("reopen store")
        .load_or_import()
        .expect("reload store");
    assert_eq!(
        reopened.get("asset-1").expect("asset").state,
        State::NasVerified
    );
}

#[test]
fn merges_only_json_records_newer_than_the_database() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let manifest = manifest_with_record("asset-1");
    manifest.save_atomic(&manifest_path).expect("save json");
    let store = AssetStateStore::open(&manifest_path).expect("open store");
    store.load_or_import().expect("initial import");

    let mut database_record = manifest.get("asset-1").expect("asset").clone();
    database_record.state = State::NasVerified;
    database_record.updated_at = "200.000000000Z".to_string();
    store
        .persist_record(&database_record)
        .expect("persist db record");

    let mut older_record = AssetRecord::new("asset-1", "/photos/asset-1.dng");
    older_record.updated_at = "100.000000000Z".to_string();
    let mut older_json = Manifest::new();
    older_json.upsert(older_record);
    older_json
        .save_atomic(&manifest_path)
        .expect("save older json");
    assert_eq!(
        store
            .load_or_import()
            .expect("load newer db")
            .get("asset-1")
            .expect("asset")
            .state,
        State::NasVerified
    );

    let mut newer_record = AssetRecord::new("asset-1", "/photos/asset-1.dng");
    newer_record.state = State::Failed;
    newer_record.updated_at = "300.000000000Z".to_string();
    let mut newer_json = Manifest::new();
    newer_json.upsert(newer_record);
    newer_json
        .save_atomic(&manifest_path)
        .expect("save newer json");
    assert_eq!(
        store
            .load_or_import()
            .expect("merge newer json")
            .get("asset-1")
            .expect("asset")
            .state,
        State::Failed
    );
}

#[test]
fn concurrent_readers_observe_committed_records() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    manifest_with_record("seed")
        .save_atomic(&manifest_path)
        .expect("save json");
    let store = AssetStateStore::open(&manifest_path).expect("open store");
    store.load_or_import().expect("initial import");

    let writers = (0..16)
        .map(|index| {
            let store = store.clone();
            thread::spawn(move || {
                let record = AssetRecord::new(
                    format!("asset-{index}"),
                    PathBuf::from(format!("/photos/asset-{index}.dng")),
                );
                store
                    .persist_record(&record)
                    .expect("persist concurrent record");
            })
        })
        .collect::<Vec<_>>();
    for writer in writers {
        writer.join().expect("writer thread");
    }

    let readers = (0..8)
        .map(|_| {
            let store = store.clone();
            thread::spawn(move || {
                store
                    .load_or_import()
                    .expect("concurrent read")
                    .records()
                    .len()
            })
        })
        .collect::<Vec<_>>();
    for reader in readers {
        assert_eq!(reader.join().expect("reader thread"), 17);
    }
}

#[test]
fn corrupt_database_and_record_payload_fail_closed() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let db_path = AssetStateStore::db_path_for_manifest(&manifest_path);
    fs::write(&db_path, b"not sqlite").expect("write corrupt db");
    assert!(AssetStateStore::open(&manifest_path).is_err());

    fs::remove_file(&db_path).expect("remove corrupt db");
    let store = AssetStateStore::open(&manifest_path).expect("open clean db");
    store
        .persist_record(&AssetRecord::new("asset-1", "/photos/asset-1.dng"))
        .expect("persist record");
    let connection = rusqlite::Connection::open(&db_path).expect("open sqlite");
    connection
        .execute(
            "UPDATE assets SET record_json = 'not json' WHERE asset_id = 'asset-1'",
            [],
        )
        .expect("corrupt record");
    assert!(store.load_or_import().is_err());
}

#[test]
fn stale_record_updates_and_unknown_schema_fail_closed() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let store = AssetStateStore::open(&manifest_path).expect("open store");
    let mut current = AssetRecord::new("asset-1", "/photos/asset-1.dng");
    current.updated_at = "200.000000000Z".to_string();
    store
        .persist_record(&current)
        .expect("persist current record");

    let mut stale = current.clone();
    stale.state = State::Failed;
    stale.updated_at = "100.000000000Z".to_string();
    assert!(store.persist_record(&stale).is_err());
    assert_eq!(
        store
            .load_or_import()
            .expect("reload current record")
            .get("asset-1")
            .expect("asset")
            .state,
        State::Discovered
    );

    let connection = rusqlite::Connection::open(store.path()).expect("open sqlite");
    connection
        .pragma_update(None, "user_version", 2)
        .expect("change schema version");
    assert!(AssetStateStore::open(&manifest_path).is_err());
}

#[test]
fn authoritative_manifest_save_rejects_stale_records_but_allows_idempotent_records() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let store = AssetStateStore::open(&manifest_path).expect("open store");
    let mut current = AssetRecord::new("asset-1", "/photos/asset-1.dng");
    current.state = State::NasVerified;
    current.updated_at = "200.000000000Z".to_string();
    store
        .persist_record(&current)
        .expect("persist current record");

    let mut stale = current.clone();
    stale.state = State::Failed;
    stale.updated_at = "100.000000000Z".to_string();
    let mut stale_manifest = Manifest::new();
    stale_manifest.upsert(stale);
    assert!(store.persist_manifest_records(&stale_manifest).is_err());

    let mut current_manifest = Manifest::new();
    current_manifest.upsert(current);
    store
        .persist_manifest_records(&current_manifest)
        .expect("idempotent authoritative save");
}

#[test]
fn direct_database_load_does_not_reimport_json_checkpoint() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let store = AssetStateStore::open(&manifest_path).expect("open store");
    let mut durable = AssetRecord::new("asset-1", "/photos/asset-1.dng");
    durable.state = State::NasVerified;
    durable.updated_at = "200.000000000Z".to_string();
    store
        .persist_record(&durable)
        .expect("persist durable record");

    let mut newer_json_record = durable.clone();
    newer_json_record.state = State::Failed;
    newer_json_record.updated_at = "300.000000000Z".to_string();
    let mut json_manifest = Manifest::new();
    json_manifest.upsert(newer_json_record);
    json_manifest
        .save_atomic(&manifest_path)
        .expect("save newer JSON checkpoint");

    assert_eq!(
        store
            .load()
            .expect("load database")
            .get("asset-1")
            .unwrap()
            .state,
        State::NasVerified
    );
    assert_eq!(
        store
            .load_or_import()
            .expect("recover newer JSON")
            .get("asset-1")
            .unwrap()
            .state,
        State::Failed
    );
}

#[test]
fn single_record_snapshot_contains_only_the_requested_asset() {
    let mut manifest = manifest_with_record("asset-1");
    manifest.upsert(AssetRecord::new("asset-2", "/photos/asset-2.dng"));

    let snapshot = manifest.snapshot_record("asset-2").expect("snapshot");

    assert_eq!(snapshot.records().len(), 1);
    assert!(snapshot.get("asset-2").is_ok());
    assert!(snapshot.get("asset-1").is_err());
}

#[test]
fn atomic_record_batch_persists_every_record() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let store = AssetStateStore::open(&manifest_path).expect("open store");
    let mut first = AssetRecord::new("asset-1", "/photos/asset-1.dng");
    first.state = State::NasVerified;
    first.updated_at = "200.000000000Z".to_string();
    let mut second = AssetRecord::new("asset-2", "/photos/asset-2.dng");
    second.state = State::Failed;
    second.updated_at = "300.000000000Z".to_string();
    let records = [first, second];

    store
        .persist_records_atomic(records.iter())
        .expect("atomic batch should persist");

    let durable = store.load().expect("load durable records");
    assert_eq!(durable.records().len(), 2);
    assert_eq!(
        durable.get("asset-1").expect("first").state,
        State::NasVerified
    );
    assert_eq!(durable.get("asset-2").expect("second").state, State::Failed);
}

#[test]
fn stale_or_conflicting_batch_member_rolls_back_every_update() {
    for (case, rejected_timestamp) in [
        ("stale", "100.000000000Z"),
        ("conflicting", "200.000000000Z"),
    ] {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest_path = tempdir.path().join(format!("manifest-{case}.json"));
        let store = AssetStateStore::open(&manifest_path).expect("open store");
        let mut durable_first = AssetRecord::new("asset-1", "/photos/asset-1.dng");
        durable_first.updated_at = "100.000000000Z".to_string();
        let mut durable_second = AssetRecord::new("asset-2", "/photos/asset-2.dng");
        durable_second.state = State::NasVerified;
        durable_second.updated_at = "200.000000000Z".to_string();
        let mut durable_manifest = Manifest::new();
        durable_manifest.upsert(durable_first.clone());
        durable_manifest.upsert(durable_second.clone());
        for index in 0..2_048 {
            let mut unrelated = AssetRecord::new(
                format!("unrelated-{index:04}"),
                format!("/photos/unrelated-{index:04}.dng"),
            );
            unrelated.updated_at = "150.000000000Z".to_string();
            durable_manifest.upsert(unrelated);
        }
        store
            .persist_manifest_records(&durable_manifest)
            .expect("persist durable records");

        let mut valid_update = durable_first.clone();
        valid_update.state = State::Failed;
        valid_update.updated_at = "300.000000000Z".to_string();
        let mut rejected_update = durable_second.clone();
        rejected_update.state = State::Failed;
        rejected_update.updated_at = rejected_timestamp.to_string();

        let error = store
            .persist_records_atomic([&valid_update, &rejected_update])
            .expect_err("stale or conflicting member must reject the batch");

        assert!(matches!(
            error,
            AssetStateStoreError::StaleRecord { asset_id } if asset_id == "asset-2"
        ));
        let durable = store.load().expect("load rolled-back records");
        assert_eq!(durable.records().len(), durable_manifest.records().len());
        assert_eq!(durable.get("asset-1").expect("first"), &durable_first);
        assert_eq!(durable.get("asset-2").expect("second"), &durable_second);
        for asset_id in ["unrelated-0000", "unrelated-1024", "unrelated-2047"] {
            assert_eq!(
                durable.get(asset_id).expect("durable unrelated record"),
                durable_manifest
                    .get(asset_id)
                    .expect("expected unrelated record")
            );
        }
    }
}

#[test]
fn atomic_record_batch_validates_only_requested_asset_ids() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let store = AssetStateStore::open(&manifest_path).expect("open store");
    let mut requested = AssetRecord::new("requested", "/photos/requested.dng");
    requested.updated_at = "100.000000000Z".to_string();
    let unrelated = AssetRecord::new("unrelated", "/photos/unrelated.dng");
    store
        .persist_records_atomic([&requested, &unrelated])
        .expect("persist initial records");

    let connection = rusqlite::Connection::open(store.path()).expect("open sqlite");
    connection
        .execute(
            "UPDATE assets SET updated_at = x'80' WHERE asset_id = 'unrelated'",
            [],
        )
        .expect("make unrelated timestamp unreadable as text");

    let mut update = requested.clone();
    update.state = State::NasVerified;
    update.updated_at = "200.000000000Z".to_string();
    store
        .persist_records_atomic([&update])
        .expect("unrelated row must not be validated");

    let durable_json: String = connection
        .query_row(
            "SELECT record_json FROM assets WHERE asset_id = 'requested'",
            [],
            |row| row.get(0),
        )
        .expect("load requested record");
    let durable: AssetRecord =
        serde_json::from_str(&durable_json).expect("decode requested record");
    assert_eq!(durable, update);
    let unrelated_type: String = connection
        .query_row(
            "SELECT typeof(updated_at) FROM assets WHERE asset_id = 'unrelated'",
            [],
            |row| row.get(0),
        )
        .expect("inspect unrelated record");
    assert_eq!(unrelated_type, "blob");
}

#[test]
fn atomic_record_batch_rejects_duplicate_asset_ids_without_writes() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let store = AssetStateStore::open(&manifest_path).expect("open store");
    let first = AssetRecord::new("asset-1", "/photos/asset-1.dng");
    let mut duplicate = first.clone();
    duplicate.state = State::Failed;
    duplicate.updated_at = "300.000000000Z".to_string();

    let error = store
        .persist_records_atomic([&first, &duplicate])
        .expect_err("duplicate asset IDs must fail closed");

    assert!(matches!(
        error,
        AssetStateStoreError::DuplicateRecord { asset_id } if asset_id == "asset-1"
    ));
    assert!(store.load().expect("load empty store").records().is_empty());
}

#[test]
fn atomic_record_batch_accepts_idempotent_records() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let store = AssetStateStore::open(&manifest_path).expect("open store");
    let mut first = AssetRecord::new("asset-1", "/photos/asset-1.dng");
    first.state = State::NasVerified;
    first.updated_at = "200.000000000Z".to_string();
    let mut second = AssetRecord::new("asset-2", "/photos/asset-2.dng");
    second.state = State::Failed;
    second.updated_at = "300.000000000Z".to_string();
    let records = [first, second];
    store
        .persist_records_atomic(&records)
        .expect("initial atomic batch should persist");

    store
        .persist_records_atomic(&records)
        .expect("identical records should be idempotent");

    let durable = store.load().expect("load idempotent records");
    assert_eq!(durable.get("asset-1").expect("first"), &records[0]);
    assert_eq!(durable.get("asset-2").expect("second"), &records[1]);
}

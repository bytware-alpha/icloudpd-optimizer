use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use icloudpd_optimizer::manifest::{AssetRecord, Manifest, State};
use icloudpd_optimizer::state_store::{AssetStateStore, AssetStateStoreError};
use serde_json::json;
use sha2::{Digest, Sha256};

fn manifest_with_record(asset_id: &str) -> Manifest {
    let mut manifest = Manifest::new();
    manifest.upsert(AssetRecord::new(
        asset_id,
        PathBuf::from(format!("/photos/{asset_id}.dng")),
    ));
    manifest
}

fn open_writer(manifest_path: &std::path::Path, owner: &str) -> AssetStateStore {
    AssetStateStore::open_writer(manifest_path, owner, Duration::from_millis(200))
        .expect("open writer store")
}

fn lease_row(manifest_path: &std::path::Path) -> (String, i64, i64) {
    let connection =
        rusqlite::Connection::open(AssetStateStore::db_path_for_manifest(manifest_path))
            .expect("open state db");
    connection
        .query_row(
            "SELECT owner_id, epoch, expires_at_unix_ms FROM writer_lease WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("load lease row")
}

fn create_v1_database(manifest_path: &std::path::Path, records: &[AssetRecord]) {
    let db_path = AssetStateStore::db_path_for_manifest(manifest_path);
    let connection = rusqlite::Connection::open(db_path).expect("open v1 state db");
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             BEGIN IMMEDIATE;
             CREATE TABLE assets (
               asset_id TEXT PRIMARY KEY NOT NULL,
               state TEXT NOT NULL,
               updated_at TEXT NOT NULL,
               record_json TEXT NOT NULL
             );
             CREATE INDEX assets_state_index ON assets(state);
             PRAGMA user_version = 1;
             COMMIT;",
        )
        .expect("create v1 schema");
    for record in records {
        connection
            .execute(
                "INSERT INTO assets (asset_id, state, updated_at, record_json) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    record.asset_id,
                    record.state.as_str(),
                    record.updated_at,
                    serde_json::to_string(record).expect("encode record")
                ],
            )
            .expect("insert v1 asset record");
    }
}

fn asset_row_digest(manifest_path: &std::path::Path) -> String {
    let connection =
        rusqlite::Connection::open(AssetStateStore::db_path_for_manifest(manifest_path))
            .expect("open state db for asset digest");
    let mut statement = connection
        .prepare("SELECT asset_id, state, updated_at, record_json FROM assets ORDER BY asset_id")
        .expect("prepare asset digest query");
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .expect("query asset digest rows");
    let mut hasher = Sha256::new();
    for row in rows {
        let (asset_id, state, updated_at, record_json) = row.expect("read asset digest row");
        for value in [&asset_id, &state, &updated_at, &record_json] {
            hasher.update(value.as_bytes());
            hasher.update([0]);
        }
    }
    format!("{:x}", hasher.finalize())
}

fn create_custom_v1_database(
    manifest_path: &std::path::Path,
    assets_sql: &str,
    index_sql: &str,
    extra_sql: &str,
    records: &[AssetRecord],
) {
    let db_path = AssetStateStore::db_path_for_manifest(manifest_path);
    let connection = rusqlite::Connection::open(db_path).expect("open custom v1 state db");
    connection
        .execute_batch(&format!(
            "PRAGMA journal_mode=WAL;
             BEGIN IMMEDIATE;
             {assets_sql};
             {index_sql};
             {extra_sql}
             PRAGMA user_version = 1;
             COMMIT;"
        ))
        .expect("create custom v1 schema");
    for record in records {
        connection
            .execute(
                "INSERT INTO assets (asset_id, state, updated_at, record_json) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    record.asset_id,
                    record.state.as_str(),
                    record.updated_at,
                    serde_json::to_string(record).expect("encode record")
                ],
            )
            .expect("insert custom v1 asset record");
    }
}

fn migration_schema_digest(manifest_path: &std::path::Path) -> String {
    let connection =
        rusqlite::Connection::open(AssetStateStore::db_path_for_manifest(manifest_path))
            .expect("open state db for schema digest");
    let version: i32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read schema version for digest");
    let mut statement = connection
        .prepare(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .expect("prepare schema digest query");
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .expect("query schema digest rows");
    let mut hasher = Sha256::new();
    hasher.update(version.to_le_bytes());
    for row in rows {
        let (object_type, name, table, sql) = row.expect("read schema digest row");
        for value in [&object_type, &name, &table, &sql] {
            hasher.update(value.as_bytes());
            hasher.update([0]);
        }
    }
    format!("{:x}", hasher.finalize())
}

#[test]
fn imports_json_once_and_reopens_durable_record_updates() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let manifest = manifest_with_record("asset-1");
    manifest.save_atomic(&manifest_path).expect("save json");

    let store = open_writer(&manifest_path, "writer-a");
    let mut imported = store.load_or_import().expect("import json");
    imported
        .transition("asset-1", State::NasVerified, "nas", json!({"ok": true}))
        .expect("transition");
    store
        .persist_record(imported.get("asset-1").expect("asset"))
        .expect("persist record");
    store
        .release_writer_lease()
        .expect("release first writer before reopening");

    let reopened = AssetStateStore::open_read_only(&manifest_path)
        .expect("reopen store")
        .load()
        .expect("reload store");
    assert_eq!(
        reopened.get("asset-1").expect("asset").state,
        State::NasVerified
    );
}

#[test]
fn json_manifest_is_imported_only_once() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let manifest = manifest_with_record("asset-1");
    manifest.save_atomic(&manifest_path).expect("save json");
    let store = open_writer(&manifest_path, "writer-a");
    store.load_or_import().expect("initial import");

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
            .expect("do not reimport newer json")
            .get("asset-1")
            .expect("asset")
            .state,
        State::Discovered
    );
}

#[test]
fn imported_sqlite_state_loads_when_legacy_json_is_malformed_or_missing() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    manifest_with_record("asset-1")
        .save_atomic(&manifest_path)
        .expect("save initial json");
    let store = open_writer(&manifest_path, "writer-a");
    store.load_or_import().expect("import initial json");

    fs::write(&manifest_path, b"not json").expect("corrupt legacy json");
    assert!(
        store
            .load_or_import()
            .expect("durable state must not reread malformed imported json")
            .get("asset-1")
            .is_ok()
    );

    fs::remove_file(&manifest_path).expect("remove legacy json");
    assert!(
        store
            .load_or_import()
            .expect("durable state must not require imported json")
            .get("asset-1")
            .is_ok()
    );
}

#[test]
fn read_only_open_never_bootstraps_or_migrates_schema() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let fresh_manifest_path = tempdir.path().join("fresh/manifest.json");
    let fresh_db_path = AssetStateStore::db_path_for_manifest(&fresh_manifest_path);
    assert!(AssetStateStore::open_read_only(&fresh_manifest_path).is_err());
    assert!(
        !fresh_db_path.exists(),
        "read-only opening must not create a state database"
    );

    let v1_manifest_path = tempdir.path().join("v1/manifest.json");
    let v1_db_path = AssetStateStore::db_path_for_manifest(&v1_manifest_path);
    fs::create_dir_all(v1_db_path.parent().expect("state parent")).expect("create state parent");
    let connection = rusqlite::Connection::open(&v1_db_path).expect("open v1 database");
    connection
        .execute_batch(
            "CREATE TABLE assets (
               asset_id TEXT PRIMARY KEY NOT NULL,
               state TEXT NOT NULL,
               updated_at TEXT NOT NULL,
               record_json TEXT NOT NULL
             );
             CREATE INDEX assets_state_index ON assets(state);
             PRAGMA user_version = 1;",
        )
        .expect("create v1 schema");

    assert!(matches!(
        AssetStateStore::open_read_only(&v1_manifest_path),
        Err(AssetStateStoreError::UnsupportedSchema {
            expected: 2,
            actual: 1
        })
    ));
    let version: i32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read v1 schema version");
    assert_eq!(version, 1);
    let writer_lease_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'writer_lease'",
            [],
            |row| row.get(0),
        )
        .expect("count v2 writer lease table");
    assert_eq!(writer_lease_count, 0);
}

#[test]
fn writer_ttl_must_be_finite_and_bounded() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    for (name, ttl) in [
        ("zero", Duration::ZERO),
        ("excessive", Duration::from_secs(5 * 60 + 1)),
        ("unbounded", Duration::MAX),
    ] {
        let manifest_path = tempdir.path().join(format!("{name}.json"));
        assert!(
            AssetStateStore::open_writer(&manifest_path, "writer-a", ttl).is_err(),
            "{name} writer lease TTL must be rejected"
        );
    }
}

#[test]
fn invalid_writer_owners_do_not_bootstrap_or_share_the_sentinel_lease() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    for (name, path, owner) in [
        ("empty-first", "empty/manifest.json", String::new()),
        (
            "whitespace",
            "whitespace/manifest.json",
            " \t\n".to_string(),
        ),
        ("excessive", "excessive/manifest.json", "a".repeat(129)),
    ] {
        let manifest_path = tempdir.path().join(path);
        let db_path = AssetStateStore::db_path_for_manifest(&manifest_path);
        let error = AssetStateStore::open_writer(&manifest_path, owner, Duration::from_secs(1))
            .expect_err("invalid writer owner must be rejected before bootstrap");
        assert!(matches!(
            error,
            AssetStateStoreError::InvalidWriterOwnerId { .. }
        ));
        assert!(
            !db_path.exists(),
            "{name} owner must not create a state database"
        );
        assert!(
            !db_path.parent().expect("database parent").exists(),
            "{name} owner must not create a state directory"
        );
    }

    let manifest_path = tempdir.path().join("sentinel/manifest.json");
    let first_writer = open_writer(&manifest_path, "writer-a");
    first_writer
        .release_writer_lease()
        .expect("release the writer lease to its unowned sentinel");
    let sentinel = lease_row(&manifest_path);

    let error = AssetStateStore::open_writer(&manifest_path, "", Duration::from_secs(1))
        .expect_err("an empty owner must not acquire the unowned sentinel lease");
    assert!(matches!(
        error,
        AssetStateStoreError::InvalidWriterOwnerId { .. }
    ));
    assert_eq!(
        lease_row(&manifest_path),
        sentinel,
        "an invalid owner must leave the unowned sentinel untouched"
    );
    AssetStateStore::open_writer(&manifest_path, "writer-b", Duration::from_secs(1))
        .expect("a valid owner must be able to acquire the unowned sentinel lease");
}

#[test]
fn concurrent_fresh_openers_observe_writer_lease_held() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let first_path = manifest_path.clone();
    let first = thread::spawn(move || {
        let writer = AssetStateStore::open_writer(&first_path, "writer-a", Duration::from_secs(1))
            .expect("first fresh writer should bootstrap and acquire");
        acquired_tx.send(()).expect("signal acquired writer");
        release_rx.recv().expect("wait for release");
        drop(writer);
    });
    acquired_rx.recv().expect("wait for fresh bootstrap");

    assert!(matches!(
        AssetStateStore::open_writer(&manifest_path, "writer-b", Duration::from_secs(1)),
        Err(AssetStateStoreError::WriterLeaseHeld { .. })
    ));
    release_tx.send(()).expect("release first writer");
    first.join().expect("join first writer");
}

#[test]
fn concurrent_v1_openers_observe_writer_lease_held() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let db_path = AssetStateStore::db_path_for_manifest(&manifest_path);
    let connection = rusqlite::Connection::open(&db_path).expect("open v1 database");
    connection
        .execute_batch(
            "CREATE TABLE assets (
               asset_id TEXT PRIMARY KEY NOT NULL,
               state TEXT NOT NULL,
               updated_at TEXT NOT NULL,
               record_json TEXT NOT NULL
             );
             CREATE INDEX assets_state_index ON assets(state);
             PRAGMA user_version = 1;",
        )
        .expect("create v1 schema");

    let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let first_path = manifest_path.clone();
    let first = thread::spawn(move || {
        let writer = AssetStateStore::open_writer(&first_path, "writer-a", Duration::from_secs(1))
            .expect("first v1 writer should migrate and acquire");
        acquired_tx.send(()).expect("signal acquired writer");
        release_rx.recv().expect("wait for release");
        drop(writer);
    });
    acquired_rx.recv().expect("wait for v1 migration");

    assert!(matches!(
        AssetStateStore::open_writer(&manifest_path, "writer-b", Duration::from_secs(1)),
        Err(AssetStateStoreError::WriterLeaseHeld { .. })
    ));
    release_tx.send(()).expect("release first writer");
    first.join().expect("join first writer");
}

#[test]
fn concurrent_readers_observe_committed_records() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    manifest_with_record("seed")
        .save_atomic(&manifest_path)
        .expect("save json");
    let store = open_writer(&manifest_path, "writer-a");
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
fn read_only_loads_work_while_writer_lease_is_held() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    manifest_with_record("asset-1")
        .save_atomic(&manifest_path)
        .expect("save json");

    let writer = open_writer(&manifest_path, "writer-a");
    writer.load_or_import().expect("import");

    let reader = AssetStateStore::open_read_only(&manifest_path).expect("open reader");
    let manifest = reader.load().expect("read-only load");

    assert!(manifest.get("asset-1").is_ok());
}

#[test]
fn read_only_store_rejects_every_mutator() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    manifest_with_record("asset-1")
        .save_atomic(&manifest_path)
        .expect("save json");
    open_writer(&manifest_path, "writer-a")
        .load_or_import()
        .expect("initial import");

    let reader = AssetStateStore::open_read_only(&manifest_path).expect("open reader");
    let mut manifest = Manifest::new();
    manifest.upsert(AssetRecord::new("asset-2", "/photos/asset-2.dng"));
    let record = AssetRecord::new("asset-3", "/photos/asset-3.dng");

    for error in [
        reader
            .load_or_import()
            .expect_err("import must require writer"),
        reader
            .persist_record(&record)
            .expect_err("single-record persist must require writer"),
        reader
            .persist_records_atomic([&record])
            .expect_err("batch persist must require writer"),
        reader
            .persist_manifest_records(&manifest)
            .expect_err("manifest persist must require writer"),
        reader
            .export_json()
            .expect_err("export must require writer"),
    ] {
        assert!(matches!(error, AssetStateStoreError::WriterLeaseRequired));
    }
}

#[test]
fn live_foreign_writer_is_rejected_and_release_allows_reacquire() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let writer = open_writer(&manifest_path, "writer-a");

    let error = AssetStateStore::open_writer(&manifest_path, "writer-b", Duration::from_secs(5))
        .expect_err("live foreign writer should be rejected");
    assert!(matches!(
        error,
        AssetStateStoreError::WriterLeaseHeld { owner_id, .. } if owner_id == "writer-a"
    ));

    writer
        .release_writer_lease()
        .expect("writer should release cleanly");
    AssetStateStore::open_writer(&manifest_path, "writer-b", Duration::from_secs(5))
        .expect("new owner should acquire after release");
}

#[test]
fn same_owner_renewal_never_shortens_existing_expiry() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let first = AssetStateStore::open_writer(&manifest_path, "writer-a", Duration::from_secs(5))
        .expect("first writer");
    let (_, first_epoch, first_expiry) = lease_row(&manifest_path);

    let renewal =
        AssetStateStore::open_writer(&manifest_path, "writer-a", Duration::from_millis(1))
            .expect("same owner renewal should succeed");
    let (_, second_epoch, second_expiry) = lease_row(&manifest_path);
    assert_eq!(second_epoch, first_epoch);
    assert!(
        second_expiry >= first_expiry,
        "same-owner reopen must not shorten the lease"
    );

    renewal.renew_writer_lease().expect("renew same owner");
    let (_, renewed_epoch, renewed_expiry) = lease_row(&manifest_path);
    assert_eq!(renewed_epoch, first_epoch);
    assert!(
        renewed_expiry >= second_expiry,
        "same-owner renew must not shorten the lease"
    );

    first.release_writer_lease().expect("release lease");
}

#[test]
fn writer_drop_releases_sqlite_lease() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    {
        let writer = open_writer(&manifest_path, "writer-a");
        writer.load_or_import().expect("import");
    }

    AssetStateStore::open_writer(&manifest_path, "writer-b", Duration::from_secs(1))
        .expect("writer drop should release the sqlite lease");
}

#[test]
fn expired_takeover_increments_epoch_and_fences_stale_writer() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let writer_a =
        AssetStateStore::open_writer(&manifest_path, "writer-a", Duration::from_millis(25))
            .expect("writer a");
    let first_epoch = writer_a.writer_epoch().expect("writer epoch");

    thread::sleep(Duration::from_millis(50));

    let writer_b = open_writer(&manifest_path, "writer-b");
    assert!(
        writer_b.writer_epoch().expect("writer epoch") > first_epoch,
        "expired takeover should fence the old epoch"
    );

    let error = writer_a
        .persist_record(&AssetRecord::new("asset-1", "/photos/asset-1.dng"))
        .expect_err("stale writer should be fenced");
    assert!(matches!(
        error,
        AssetStateStoreError::WriterLeaseFenced { owner_id, epoch, .. }
            if owner_id == "writer-a" && epoch == first_epoch
    ));
}

#[test]
fn failed_v1_to_v2_migration_rolls_back_without_partial_v2_tables() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let db_path = AssetStateStore::db_path_for_manifest(&manifest_path);

    let connection = rusqlite::Connection::open(&db_path).expect("open sqlite");
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             BEGIN IMMEDIATE;
             CREATE TABLE assets (
               asset_id TEXT PRIMARY KEY NOT NULL,
               state TEXT NOT NULL,
               updated_at TEXT NOT NULL,
               record_json TEXT NOT NULL
             );
             CREATE INDEX assets_state_index ON assets(state);
             CREATE VIEW json_import_metadata AS SELECT 1 AS singleton;
             PRAGMA user_version = 1;
             COMMIT;",
        )
        .expect("create v1 schema plus conflicting view");

    let error = AssetStateStore::open_writer(&manifest_path, "writer-a", Duration::from_secs(1))
        .expect_err("migration conflict should fail closed");
    assert!(
        matches!(error, AssetStateStoreError::Database(_)),
        "expected writer-side migration error, got {error:?}"
    );

    let connection = rusqlite::Connection::open(&db_path).expect("reopen sqlite");
    let version: i32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read schema version");
    assert_eq!(version, 1);

    let writer_lease_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'writer_lease'",
            [],
            |row| row.get(0),
        )
        .expect("count writer_lease tables");
    assert_eq!(writer_lease_count, 0);

    let json_import_view_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'view' AND name = 'json_import_metadata'",
            [],
            |row| row.get(0),
        )
        .expect("count json_import_metadata views");
    assert_eq!(json_import_view_count, 1);
}

#[test]
fn migrates_v1_database_without_reimporting_json_checkpoint() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let db_path = AssetStateStore::db_path_for_manifest(&manifest_path);
    manifest_with_record("asset-1")
        .save_atomic(&manifest_path)
        .expect("save json");

    let connection = rusqlite::Connection::open(&db_path).expect("open sqlite");
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             BEGIN IMMEDIATE;
             CREATE TABLE assets (
               asset_id TEXT PRIMARY KEY NOT NULL,
               state TEXT NOT NULL,
               updated_at TEXT NOT NULL,
               record_json TEXT NOT NULL
             );
             CREATE INDEX assets_state_index ON assets(state);
             PRAGMA user_version = 1;
             COMMIT;",
        )
        .expect("create v1 schema");
    let durable = AssetRecord::new("asset-1", "/photos/asset-1.dng");
    connection
        .execute(
            "INSERT INTO assets (asset_id, state, updated_at, record_json) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                durable.asset_id,
                durable.state.as_str(),
                durable.updated_at,
                serde_json::to_string(&durable).expect("encode record")
            ],
        )
        .expect("insert durable record");

    let mut newer_json = Manifest::new();
    let mut newer = durable.clone();
    newer.state = State::Failed;
    newer.updated_at = "999.000000000Z".to_string();
    newer_json.upsert(newer);
    newer_json
        .save_atomic(&manifest_path)
        .expect("replace json checkpoint");

    let writer = open_writer(&manifest_path, "writer-a");
    let manifest = writer.load_or_import().expect("load migrated store");
    assert_eq!(
        manifest.get("asset-1").expect("asset").state,
        State::Discovered
    );

    let migrated_connection = rusqlite::Connection::open(writer.path()).expect("open migrated db");
    let version: i32 = migrated_connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read schema version");
    assert_eq!(version, 2);
}

#[test]
fn schema_only_migration_preserves_v1_assets_and_never_reads_or_writes_manifest_json() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let db_path = AssetStateStore::db_path_for_manifest(&manifest_path);
    let mut first = AssetRecord::new("asset-1", "/photos/asset-1.dng");
    first.state = State::NasVerified;
    first.updated_at = "200.000000000Z".to_string();
    let mut second = AssetRecord::new("asset-2", "/photos/asset-2.dng");
    second.state = State::Failed;
    second.updated_at = "300.000000000Z".to_string();
    create_v1_database(&manifest_path, &[first, second]);
    fs::write(&manifest_path, b"{deliberately malformed legacy json")
        .expect("write malformed manifest sentinel");
    let manifest_before = fs::read(&manifest_path).expect("read manifest sentinel");
    let assets_before = asset_row_digest(&manifest_path);

    let summary = AssetStateStore::migrate_schema_only(&manifest_path, 1, 2)
        .expect("schema-only migration should succeed");

    assert_eq!(summary.from, 1);
    assert_eq!(summary.to, 2);
    assert_eq!(summary.asset_count, 2);
    assert_eq!(summary.quick_check, "ok");
    assert!(!summary.database_id.is_empty());
    assert_eq!(
        fs::read(&manifest_path).expect("manifest sentinel should remain untouched"),
        manifest_before
    );
    assert_eq!(asset_row_digest(&manifest_path), assets_before);

    let connection = rusqlite::Connection::open(db_path).expect("open migrated state db");
    let version: i32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read migrated schema version");
    assert_eq!(version, 2);
    let lease: (String, i64, i64) = connection
        .query_row(
            "SELECT owner_id, epoch, expires_at_unix_ms FROM writer_lease WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read released migration lease");
    assert_eq!(lease.0, "");
    assert!(lease.1 > 0);
    assert_eq!(lease.2, 0);
    let import_metadata: (i64, Option<String>) = connection
        .query_row(
            "SELECT imported_once, source_path FROM json_import_metadata WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read schema-only import metadata");
    assert_eq!(import_metadata, (1, None));
}

#[test]
fn schema_only_migration_rejects_every_semantically_altered_v1_schema_without_mutation() {
    const CANONICAL_TABLE: &str = "CREATE TABLE assets (
        asset_id TEXT PRIMARY KEY NOT NULL,
        state TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        record_json TEXT NOT NULL
    )";
    const CANONICAL_INDEX: &str = "CREATE INDEX assets_state_index ON assets(state)";

    let cases = [
        (
            "wrong-index-column",
            CANONICAL_TABLE,
            "CREATE INDEX assets_state_index ON assets(asset_id)",
            "",
        ),
        (
            "unique-index",
            CANONICAL_TABLE,
            "CREATE UNIQUE INDEX assets_state_index ON assets(state)",
            "",
        ),
        (
            "partial-index",
            CANONICAL_TABLE,
            "CREATE INDEX assets_state_index ON assets(state) WHERE state <> ''",
            "",
        ),
        (
            "descending-index",
            CANONICAL_TABLE,
            "CREATE INDEX assets_state_index ON assets(state DESC)",
            "",
        ),
        (
            "column-default",
            "CREATE TABLE assets (
                asset_id TEXT PRIMARY KEY NOT NULL,
                state TEXT NOT NULL DEFAULT 'discovered',
                updated_at TEXT NOT NULL,
                record_json TEXT NOT NULL
            )",
            CANONICAL_INDEX,
            "",
        ),
        (
            "generated-column",
            "CREATE TABLE assets (
                asset_id TEXT PRIMARY KEY NOT NULL,
                state TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                record_json TEXT NOT NULL,
                state_copy TEXT GENERATED ALWAYS AS (state) STORED
            )",
            CANONICAL_INDEX,
            "",
        ),
        (
            "strict-table",
            "CREATE TABLE assets (
                asset_id TEXT PRIMARY KEY NOT NULL,
                state TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                record_json TEXT NOT NULL
            ) STRICT",
            CANONICAL_INDEX,
            "",
        ),
        (
            "without-rowid",
            "CREATE TABLE assets (
                asset_id TEXT PRIMARY KEY NOT NULL,
                state TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                record_json TEXT NOT NULL
            ) WITHOUT ROWID",
            CANONICAL_INDEX,
            "",
        ),
        (
            "table-check-constraint",
            "CREATE TABLE assets (
                asset_id TEXT PRIMARY KEY NOT NULL,
                state TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                record_json TEXT NOT NULL,
                CHECK (length(state) > 0)
            )",
            CANONICAL_INDEX,
            "",
        ),
        (
            "trigger",
            CANONICAL_TABLE,
            CANONICAL_INDEX,
            "CREATE TRIGGER assets_reject_insert BEFORE INSERT ON assets WHEN 0 BEGIN SELECT RAISE(ABORT, 'no'); END;",
        ),
        (
            "view",
            CANONICAL_TABLE,
            CANONICAL_INDEX,
            "CREATE VIEW extra_assets_view AS SELECT asset_id FROM assets;",
        ),
        (
            "extra-table",
            CANONICAL_TABLE,
            CANONICAL_INDEX,
            "CREATE TABLE extra_state (key TEXT PRIMARY KEY NOT NULL);",
        ),
    ];

    for (case, assets_sql, index_sql, extra_sql) in cases {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest_path = tempdir.path().join(format!("{case}.json"));
        let record = AssetRecord::new("asset-1", "/photos/asset-1.dng");
        create_custom_v1_database(
            &manifest_path,
            assets_sql,
            index_sql,
            extra_sql,
            std::slice::from_ref(&record),
        );
        let assets_before = asset_row_digest(&manifest_path);
        let schema_before = migration_schema_digest(&manifest_path);

        let error = AssetStateStore::migrate_schema_only(&manifest_path, 1, 2)
            .expect_err("semantically altered v1 schema must fail closed");

        assert!(matches!(
            error,
            AssetStateStoreError::MigrationSchemaInvalid { .. }
        ));
        assert_eq!(asset_row_digest(&manifest_path), assets_before, "{case}");
        assert_eq!(
            migration_schema_digest(&manifest_path),
            schema_before,
            "{case}"
        );
    }
}

#[test]
fn schema_only_migration_rejects_zero_row_v1_without_touching_json_or_schema() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    create_v1_database(&manifest_path, &[]);
    fs::write(&manifest_path, b"{legacy JSON sentinel must not be read")
        .expect("write manifest sentinel");
    let manifest_before = fs::read(&manifest_path).expect("read manifest sentinel");
    let schema_before = migration_schema_digest(&manifest_path);

    let error = AssetStateStore::migrate_schema_only(&manifest_path, 1, 2)
        .expect_err("zero-row v1 database is ambiguous and must not migrate");

    assert!(error.to_string().contains("contains no asset rows"));
    assert_eq!(
        fs::read(&manifest_path).expect("manifest sentinel should remain untouched"),
        manifest_before
    );
    assert_eq!(migration_schema_digest(&manifest_path), schema_before);
}

#[test]
fn schema_only_migration_waits_for_an_existing_immediate_writer_before_committing() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    create_v1_database(
        &manifest_path,
        &[AssetRecord::new("asset-1", "/photos/asset-1.dng")],
    );
    let db_path = AssetStateStore::db_path_for_manifest(&manifest_path);
    let lock_connection = rusqlite::Connection::open(db_path).expect("open writer lock database");
    lock_connection
        .execute_batch("BEGIN IMMEDIATE;")
        .expect("acquire existing immediate writer");
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let migration_path = manifest_path.clone();
    let migration = std::thread::spawn(move || {
        started_tx.send(()).expect("signal migration start");
        result_tx.send(AssetStateStore::migrate_schema_only(&migration_path, 1, 2))
    });
    started_rx.recv().expect("wait for migration thread start");
    assert!(
        result_rx.recv_timeout(Duration::from_millis(100)).is_err(),
        "migration must not overlap an existing IMMEDIATE writer"
    );

    lock_connection
        .execute_batch("COMMIT;")
        .expect("release existing immediate writer");
    let summary = result_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("migration should complete after writer release")
        .expect("migration should succeed after writer release");
    migration
        .join()
        .expect("migration thread should not panic")
        .expect("migration result should be sent");
    assert_eq!(summary.asset_count, 1);
}

#[test]
fn schema_only_migration_rejects_missing_wrong_or_already_migrated_databases_without_mutation() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let missing_manifest_path = tempdir.path().join("missing/manifest.json");
    let missing_db_path = AssetStateStore::db_path_for_manifest(&missing_manifest_path);
    let missing = AssetStateStore::migrate_schema_only(&missing_manifest_path, 1, 2)
        .expect_err("missing state database must fail closed");
    assert!(matches!(
        missing,
        AssetStateStoreError::MigrationDatabaseMissing { path } if path == missing_db_path
    ));
    assert!(!missing_db_path.exists());
    assert!(!missing_db_path.parent().expect("missing parent").exists());

    let manifest_path = tempdir.path().join("manifest.json");
    create_v1_database(
        &manifest_path,
        &[AssetRecord::new("asset-1", "/photos/asset-1.dng")],
    );
    let assets_before = asset_row_digest(&manifest_path);
    let wrong_request = AssetStateStore::migrate_schema_only(&manifest_path, 2, 1)
        .expect_err("only v1 to v2 should be accepted");
    assert!(matches!(
        wrong_request,
        AssetStateStoreError::InvalidSchemaMigration { from: 2, to: 1 }
    ));
    assert_eq!(asset_row_digest(&manifest_path), assets_before);

    AssetStateStore::migrate_schema_only(&manifest_path, 1, 2)
        .expect("initial migration should succeed");
    let already_migrated = AssetStateStore::migrate_schema_only(&manifest_path, 1, 2)
        .expect_err("v2 must not be accepted as an idempotent migration");
    assert!(matches!(
        already_migrated,
        AssetStateStoreError::MigrationSchemaVersion {
            expected: 1,
            actual: 2
        }
    ));
    assert_eq!(asset_row_digest(&manifest_path), assets_before);

    let empty_manifest_path = tempdir.path().join("empty.json");
    let empty_db_path = AssetStateStore::db_path_for_manifest(&empty_manifest_path);
    let empty_connection = rusqlite::Connection::open(&empty_db_path).expect("open empty state db");
    let journal_before: String = empty_connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .expect("read empty journal mode");
    let empty = AssetStateStore::migrate_schema_only(&empty_manifest_path, 1, 2)
        .expect_err("empty database must fail closed");
    assert!(matches!(
        empty,
        AssetStateStoreError::MigrationSchemaVersion {
            expected: 1,
            actual: 0
        }
    ));
    let journal_after: String = empty_connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .expect("read unchanged empty journal mode");
    assert_eq!(journal_after, journal_before);

    let unknown_manifest_path = tempdir.path().join("unknown.json");
    create_v1_database(
        &unknown_manifest_path,
        &[AssetRecord::new(
            "asset-unknown",
            "/photos/asset-unknown.dng",
        )],
    );
    let unknown_db_path = AssetStateStore::db_path_for_manifest(&unknown_manifest_path);
    let unknown_connection =
        rusqlite::Connection::open(&unknown_db_path).expect("open unknown-version state db");
    unknown_connection
        .pragma_update(None, "user_version", 3)
        .expect("set unknown schema version");
    let unknown = AssetStateStore::migrate_schema_only(&unknown_manifest_path, 1, 2)
        .expect_err("unknown schema version must fail closed");
    assert!(matches!(
        unknown,
        AssetStateStoreError::MigrationSchemaVersion {
            expected: 1,
            actual: 3
        }
    ));
}

#[test]
fn schema_only_migration_rolls_back_the_entire_transaction_on_schema_conflict() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let db_path = AssetStateStore::db_path_for_manifest(&manifest_path);
    let record = AssetRecord::new("asset-1", "/photos/asset-1.dng");
    create_v1_database(&manifest_path, std::slice::from_ref(&record));
    let connection = rusqlite::Connection::open(&db_path).expect("open v1 state db");
    connection
        .execute_batch("CREATE VIEW json_import_metadata AS SELECT 1 AS singleton;")
        .expect("install migration conflict");
    let assets_before = asset_row_digest(&manifest_path);

    assert!(AssetStateStore::migrate_schema_only(&manifest_path, 1, 2).is_err());

    assert_eq!(asset_row_digest(&manifest_path), assets_before);
    let connection = rusqlite::Connection::open(db_path).expect("reopen rolled-back state db");
    let version: i32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("read rolled-back schema version");
    assert_eq!(version, 1);
    let writer_lease_count: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'writer_lease'",
            [],
            |row| row.get(0),
        )
        .expect("count rolled-back writer lease tables");
    assert_eq!(writer_lease_count, 0);
}

#[test]
fn corrupt_database_and_record_payload_fail_closed() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let db_path = AssetStateStore::db_path_for_manifest(&manifest_path);
    fs::write(&db_path, b"not sqlite").expect("write corrupt db");
    assert!(AssetStateStore::open(&manifest_path).is_err());

    fs::remove_file(&db_path).expect("remove corrupt db");
    let store = open_writer(&manifest_path, "writer-a");
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
    let store = open_writer(&manifest_path, "writer-a");
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
        .pragma_update(None, "user_version", 3)
        .expect("change schema version");
    assert!(AssetStateStore::open(&manifest_path).is_err());
}

#[test]
fn authoritative_manifest_save_rejects_stale_records_but_allows_idempotent_records() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let manifest_path = tempdir.path().join("manifest.json");
    let store = open_writer(&manifest_path, "writer-a");
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
    let store = open_writer(&manifest_path, "writer-a");
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
    let store = open_writer(&manifest_path, "writer-a");
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
        let store = open_writer(&manifest_path, "writer-a");
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
    let store = open_writer(&manifest_path, "writer-a");
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
    let store = open_writer(&manifest_path, "writer-a");
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
    let store = open_writer(&manifest_path, "writer-a");
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

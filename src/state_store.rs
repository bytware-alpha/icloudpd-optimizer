#[cfg(test)]
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Statement, Transaction, TransactionBehavior, params,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::manifest::{AssetRecord, Manifest, ManifestError};

const SCHEMA_VERSION: i32 = 2;
const BUSY_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_WRITER_LEASE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_WRITER_OWNER_ID_BYTES: usize = 128;

#[cfg(test)]
std::thread_local! {
    static FAIL_NEXT_INTEGRITY_CHECK: Cell<bool> = const { Cell::new(false) };
}

#[cfg(test)]
fn fail_next_integrity_check_for_current_thread() {
    FAIL_NEXT_INTEGRITY_CHECK.with(|fail| fail.set(true));
}

#[derive(Clone, Debug)]
pub struct AssetStateStore {
    manifest_path: PathBuf,
    db_path: PathBuf,
    writer: Option<Arc<WriterLeaseToken>>,
}

#[derive(Debug)]
struct WriterLeaseToken {
    owner_id: String,
    epoch: u64,
    lease_ttl: Duration,
    heartbeat_failure: Mutex<Option<String>>,
}

#[derive(Debug)]
struct WriterLeaseRow {
    owner_id: String,
    epoch: u64,
    expires_at_unix_ms: i64,
    acquired_at_unix_ms: i64,
}

#[derive(Debug)]
struct JsonImportMetadata {
    imported_once: bool,
}

#[derive(Debug)]
struct JsonImportSnapshot {
    manifest: Manifest,
    source_size_bytes: Option<i64>,
    source_mtime_unix_nanos: Option<i64>,
    import_note: &'static str,
}

struct JsonImportMetadataSeed {
    imported_once: bool,
    source_path: Option<String>,
    source_size_bytes: Option<i64>,
    source_mtime_unix_nanos: Option<i64>,
    imported_at_unix_ms: Option<i64>,
    import_note: Option<&'static str>,
}

impl JsonImportMetadataSeed {
    fn schema_only() -> Self {
        Self {
            imported_once: true,
            source_path: None,
            source_size_bytes: None,
            source_mtime_unix_nanos: None,
            imported_at_unix_ms: Some(current_unix_millis()),
            import_note: Some("schema_only_v1_migration"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SchemaMigrationSummary {
    pub from: i32,
    pub to: i32,
    pub asset_count: u64,
    pub database_id: String,
    pub quick_check: String,
}

impl AssetStateStore {
    pub fn db_path_for_manifest(manifest_path: impl AsRef<Path>) -> PathBuf {
        manifest_path.as_ref().with_extension("state.sqlite3")
    }

    pub fn open(manifest_path: impl AsRef<Path>) -> Result<Self, AssetStateStoreError> {
        Self::open_read_only(manifest_path)
    }

    pub fn open_read_only(manifest_path: impl AsRef<Path>) -> Result<Self, AssetStateStoreError> {
        let manifest_path = manifest_path.as_ref().to_path_buf();
        let db_path = Self::db_path_for_manifest(&manifest_path);
        let store = Self {
            manifest_path,
            db_path,
            writer: None,
        };
        let connection = store.connect_read_only()?;
        store.verify_read_only_schema(&connection)?;
        store.verify_integrity(&connection)?;
        Ok(store)
    }

    pub fn open_writer(
        manifest_path: impl AsRef<Path>,
        owner_id: impl Into<String>,
        lease_ttl: Duration,
    ) -> Result<Self, AssetStateStoreError> {
        let owner_id = owner_id.into();
        validate_writer_owner_id(&owner_id)?;
        validate_writer_lease_ttl(lease_ttl)?;
        let manifest_path = manifest_path.as_ref().to_path_buf();
        let db_path = Self::db_path_for_manifest(&manifest_path);
        let parent = db_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|source| AssetStateStoreError::CreateDirectory {
            path: parent.to_path_buf(),
            source,
        })?;
        let mut store = Self {
            manifest_path,
            db_path,
            writer: None,
        };
        let mut connection = store.connect_writer()?;
        ensure_wal(&connection, true)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        store.initialize_writer(&transaction)?;
        let token =
            store.acquire_writer_lease_in_transaction(&transaction, &owner_id, lease_ttl)?;
        transaction.commit()?;
        if let Err(error) = store.verify_integrity(&connection) {
            store.release_writer_lease_for_token(&token)?;
            return Err(error);
        }
        store.writer = Some(Arc::new(token));
        Ok(store)
    }

    pub fn migrate_schema_only(
        manifest_path: impl AsRef<Path>,
        from: i32,
        to: i32,
    ) -> Result<SchemaMigrationSummary, AssetStateStoreError> {
        if from != 1 || to != SCHEMA_VERSION {
            return Err(AssetStateStoreError::InvalidSchemaMigration { from, to });
        }

        let manifest_path = manifest_path.as_ref().to_path_buf();
        let db_path = Self::db_path_for_manifest(&manifest_path);
        match fs::metadata(&db_path) {
            Ok(_) => {}
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return Err(AssetStateStoreError::MigrationDatabaseMissing { path: db_path });
            }
            Err(source) => {
                return Err(AssetStateStoreError::MigrationDatabaseMetadata {
                    path: db_path,
                    source,
                });
            }
        }

        let store = Self {
            manifest_path,
            db_path,
            writer: None,
        };
        let mut connection = store.connect_existing_writer()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let asset_count = validate_exact_v1_schema(&transaction)?;
        let asset_count = u64::try_from(asset_count).map_err(|_| {
            AssetStateStoreError::MigrationSchemaInvalid {
                reason: "assets count must not be negative".to_string(),
            }
        })?;
        ensure_wal_in_transaction(&transaction)?;

        // The IMMEDIATE transaction serializes legacy v1 writers until the v2 lease exists.
        // Once created, the lease token is acquired and cleared in this same transaction.
        migrate_v1_to_v2_with_import_metadata(&transaction, JsonImportMetadataSeed::schema_only())?;
        let owner_id = format!("schema-migrate-{}", Uuid::new_v4());
        let token = store.acquire_writer_lease_in_transaction(
            &transaction,
            &owner_id,
            Duration::from_secs(30),
        )?;
        release_writer_lease_in_transaction(&transaction, &token)?;
        let quick_check = quick_check_in_transaction(&transaction)?;
        transaction.commit()?;

        Ok(SchemaMigrationSummary {
            from,
            to,
            asset_count,
            database_id: database_id(&store.db_path),
            quick_check,
        })
    }

    pub fn path(&self) -> &Path {
        &self.db_path
    }

    pub fn writer_epoch(&self) -> Option<u64> {
        self.writer.as_ref().map(|token| token.epoch)
    }

    pub fn renew_writer_lease(&self) -> Result<(), AssetStateStoreError> {
        let token = self.writer_token()?;
        let mut connection = self.connect_writer()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.validate_writer_lease(&transaction, token)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn release_writer_lease(&self) -> Result<(), AssetStateStoreError> {
        let Some(token) = self.writer.as_ref() else {
            return Ok(());
        };
        self.release_writer_lease_for_token(token)
    }

    fn release_writer_lease_for_token(
        &self,
        token: &WriterLeaseToken,
    ) -> Result<(), AssetStateStoreError> {
        let mut connection = self.connect_writer()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let lease = load_writer_lease(&transaction)?;
        if lease.owner_id == token.owner_id && lease.epoch == token.epoch {
            transaction.execute(
                "UPDATE writer_lease
                 SET owner_id = '', expires_at_unix_ms = 0, renewed_at_unix_ms = ?1
                 WHERE singleton = 1",
                [current_unix_millis()],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn load_or_import(&self) -> Result<Manifest, AssetStateStoreError> {
        self.load_or_import_with_owned_lease()
    }

    pub fn load(&self) -> Result<Manifest, AssetStateStoreError> {
        self.load_database_manifest()
    }

    pub fn persist_record(&self, record: &AssetRecord) -> Result<Duration, AssetStateStoreError> {
        self.persist_record_with_owned_lease(record)
    }

    pub fn persist_records_atomic<'a>(
        &self,
        records: impl IntoIterator<Item = &'a AssetRecord>,
    ) -> Result<Duration, AssetStateStoreError> {
        self.persist_records_atomic_with_owned_lease(records)
    }

    pub fn persist_manifest_records(
        &self,
        manifest: &Manifest,
    ) -> Result<(), AssetStateStoreError> {
        self.persist_manifest_records_with_owned_lease(manifest)
    }

    pub fn export_json(&self) -> Result<Manifest, AssetStateStoreError> {
        self.export_json_with_owned_lease()
    }

    pub(crate) fn record_writer_lease_heartbeat_failure(&self, reason: String) {
        let Some(token) = self.writer.as_ref() else {
            return;
        };
        let mut failure = token
            .heartbeat_failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if failure.is_none() {
            *failure = Some(reason);
        }
    }

    fn writer_token(&self) -> Result<&Arc<WriterLeaseToken>, AssetStateStoreError> {
        let token = self
            .writer
            .as_ref()
            .ok_or(AssetStateStoreError::WriterLeaseRequired)?;
        let failure = token
            .heartbeat_failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(reason) = failure {
            return Err(AssetStateStoreError::WriterLeaseHeartbeatLost { reason });
        }
        Ok(token)
    }

    fn connect_writer(&self) -> Result<Connection, AssetStateStoreError> {
        let connection = Connection::open(&self.db_path).map_err(|source| {
            AssetStateStoreError::OpenDatabase {
                path: self.db_path.clone(),
                source,
            }
        })?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        Ok(connection)
    }

    fn connect_existing_writer(&self) -> Result<Connection, AssetStateStoreError> {
        let connection =
            Connection::open_with_flags(&self.db_path, OpenFlags::SQLITE_OPEN_READ_WRITE).map_err(
                |source| AssetStateStoreError::OpenDatabase {
                    path: self.db_path.clone(),
                    source,
                },
            )?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        Ok(connection)
    }

    fn connect_read_only(&self) -> Result<Connection, AssetStateStoreError> {
        let connection =
            Connection::open_with_flags(&self.db_path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(
                |source| AssetStateStoreError::OpenDatabase {
                    path: self.db_path.clone(),
                    source,
                },
            )?;
        connection.busy_timeout(BUSY_TIMEOUT)?;
        Ok(connection)
    }

    fn verify_read_only_schema(&self, connection: &Connection) -> Result<(), AssetStateStoreError> {
        let schema_version: i32 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        let user_table_count: i64 = connection.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;

        match (schema_version, user_table_count) {
            (0, 0) => return Err(AssetStateStoreError::MissingSchema),
            (1, _) => {
                return Err(AssetStateStoreError::UnsupportedSchema {
                    expected: SCHEMA_VERSION,
                    actual: 1,
                });
            }
            (SCHEMA_VERSION, 0) => return Err(AssetStateStoreError::MissingSchema),
            (SCHEMA_VERSION, _) => ensure_wal(connection, false)?,
            (_, 0) => return Err(AssetStateStoreError::MissingSchema),
            (actual, _) => {
                return Err(AssetStateStoreError::UnsupportedSchema {
                    expected: SCHEMA_VERSION,
                    actual,
                });
            }
        }

        Ok(())
    }

    fn initialize_writer(&self, transaction: &Transaction<'_>) -> Result<(), AssetStateStoreError> {
        let schema_version: i32 =
            transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
        let user_table_count: i64 = transaction.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;

        match (schema_version, user_table_count) {
            (0, 0) => create_v2_schema(transaction)?,
            (1, _) => self.migrate_v1_to_v2(transaction)?,
            (SCHEMA_VERSION, 0) => return Err(AssetStateStoreError::MissingSchema),
            (SCHEMA_VERSION, _) => {}
            (_, 0) => return Err(AssetStateStoreError::MissingSchema),
            (actual, _) => {
                return Err(AssetStateStoreError::UnsupportedSchema {
                    expected: SCHEMA_VERSION,
                    actual,
                });
            }
        }
        Ok(())
    }

    fn migrate_v1_to_v2(&self, transaction: &Transaction<'_>) -> Result<(), AssetStateStoreError> {
        let asset_count: i64 =
            transaction.query_row("SELECT count(*) FROM assets", [], |row| row.get(0))?;
        let (source_size_bytes, source_mtime_unix_nanos) =
            manifest_file_metadata(&self.manifest_path)?;
        let imported_once = asset_count > 0;
        migrate_v1_to_v2_with_import_metadata(
            transaction,
            JsonImportMetadataSeed {
                imported_once,
                source_path: imported_once.then(|| self.manifest_path.display().to_string()),
                source_size_bytes,
                source_mtime_unix_nanos,
                imported_at_unix_ms: imported_once.then_some(current_unix_millis()),
                import_note: imported_once.then_some("legacy_v1_migration"),
            },
        )
    }

    fn verify_integrity(&self, connection: &Connection) -> Result<(), AssetStateStoreError> {
        #[cfg(test)]
        if FAIL_NEXT_INTEGRITY_CHECK.with(|fail| fail.replace(false)) {
            return Err(AssetStateStoreError::IntegrityCheck {
                result: "forced test failure".to_string(),
            });
        }
        let result: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
        if result != "ok" {
            return Err(AssetStateStoreError::IntegrityCheck { result });
        }
        Ok(())
    }

    fn acquire_writer_lease_in_transaction(
        &self,
        transaction: &Transaction<'_>,
        owner_id: &str,
        lease_ttl: Duration,
    ) -> Result<WriterLeaseToken, AssetStateStoreError> {
        let current = load_writer_lease(transaction)?;
        let now = current_unix_millis();
        let expires_at_unix_ms = now.saturating_add(duration_millis_i64(lease_ttl));

        let (epoch, acquired_at_unix_ms, expires_at_unix_ms) =
            if current.owner_id == owner_id && current.expires_at_unix_ms > now {
                (
                    current.epoch,
                    current.acquired_at_unix_ms,
                    current.expires_at_unix_ms.max(expires_at_unix_ms),
                )
            } else if current.owner_id.is_empty() || current.expires_at_unix_ms <= now {
                (current.epoch.saturating_add(1), now, expires_at_unix_ms)
            } else {
                return Err(AssetStateStoreError::WriterLeaseHeld {
                    owner_id: current.owner_id,
                    epoch: current.epoch,
                    expires_at_unix_ms: current.expires_at_unix_ms,
                });
            };

        transaction.execute(
            "UPDATE writer_lease
             SET owner_id = ?1,
                 epoch = ?2,
                 expires_at_unix_ms = ?3,
                 acquired_at_unix_ms = ?4,
                 renewed_at_unix_ms = ?5
             WHERE singleton = 1",
            params![
                owner_id,
                i64::try_from(epoch).unwrap_or(i64::MAX),
                expires_at_unix_ms,
                acquired_at_unix_ms,
                now
            ],
        )?;
        Ok(WriterLeaseToken {
            owner_id: owner_id.to_string(),
            epoch,
            lease_ttl,
            heartbeat_failure: Mutex::new(None),
        })
    }

    fn validate_writer_lease(
        &self,
        transaction: &Transaction<'_>,
        token: &WriterLeaseToken,
    ) -> Result<(), AssetStateStoreError> {
        let current = load_writer_lease(transaction)?;
        let now = current_unix_millis();
        if current.owner_id != token.owner_id
            || current.epoch != token.epoch
            || current.expires_at_unix_ms <= now
        {
            return Err(AssetStateStoreError::WriterLeaseFenced {
                owner_id: token.owner_id.clone(),
                epoch: token.epoch,
                current_owner_id: current.owner_id,
                current_epoch: current.epoch,
            });
        }
        let renewed_until = current
            .expires_at_unix_ms
            .max(now.saturating_add(duration_millis_i64(token.lease_ttl)));
        transaction.execute(
            "UPDATE writer_lease
             SET expires_at_unix_ms = ?1, renewed_at_unix_ms = ?2
             WHERE singleton = 1",
            params![renewed_until, now],
        )?;
        Ok(())
    }

    fn load_or_import_with_owned_lease(&self) -> Result<Manifest, AssetStateStoreError> {
        let token = self.writer_token()?;
        let mut connection = self.connect_writer()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.validate_writer_lease(&transaction, token)?;
        let import_metadata = load_json_import_metadata(&transaction)?;
        if !import_metadata.imported_once {
            let snapshot = self.load_json_manifest_snapshot()?;
            for record in snapshot.manifest.records().values() {
                upsert_record(&transaction, record)?;
            }
            persist_json_import_metadata(&transaction, &self.manifest_path, &snapshot)?;
        }
        let manifest = load_database_manifest_from_transaction(&transaction)?;
        transaction.commit()?;
        Ok(manifest)
    }

    fn persist_record_with_owned_lease(
        &self,
        record: &AssetRecord,
    ) -> Result<Duration, AssetStateStoreError> {
        let token = self.writer_token()?;
        let started = Instant::now();
        let mut connection = self.connect_writer()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.validate_writer_lease(&transaction, token)?;
        let changed = upsert_record(&transaction, record)?;
        reject_stale_record(&transaction, record, changed)?;
        transaction.commit()?;
        Ok(started.elapsed())
    }

    fn persist_records_atomic_with_owned_lease<'a>(
        &self,
        records: impl IntoIterator<Item = &'a AssetRecord>,
    ) -> Result<Duration, AssetStateStoreError> {
        let token = self.writer_token()?;
        let started = Instant::now();
        let mut asset_ids = BTreeSet::new();
        let mut prepared = Vec::new();
        for record in records {
            if !asset_ids.insert(record.asset_id.clone()) {
                return Err(AssetStateStoreError::DuplicateRecord {
                    asset_id: record.asset_id.clone(),
                });
            }
            prepared.push((record, encode_record(record)?));
        }
        if prepared.is_empty() {
            return Ok(started.elapsed());
        }

        let mut connection = self.connect_writer()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.validate_writer_lease(&transaction, token)?;
        {
            let mut statement = transaction
                .prepare("SELECT updated_at, record_json FROM assets WHERE asset_id = ?1")?;
            for (record, requested_json) in &prepared {
                let persisted = statement
                    .query_row([record.asset_id.as_str()], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })
                    .optional()?;
                validate_requested_record(record, requested_json, persisted.as_ref())?;
            }
        }
        for (record, record_json) in prepared {
            upsert_encoded_record(&transaction, record, &record_json)?;
        }
        transaction.commit()?;
        Ok(started.elapsed())
    }

    fn persist_manifest_records_with_owned_lease(
        &self,
        manifest: &Manifest,
    ) -> Result<(), AssetStateStoreError> {
        let token = self.writer_token()?;
        if manifest.records().is_empty() {
            return Ok(());
        }

        let prepared = manifest
            .records()
            .values()
            .map(|record| Ok((record, encode_record(record)?)))
            .collect::<Result<Vec<_>, AssetStateStoreError>>()?;
        let mut connection = self.connect_writer()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.validate_writer_lease(&transaction, token)?;
        let persisted_records = load_persisted_records(&transaction)?;
        for (record, requested_json) in &prepared {
            validate_requested_record(
                record,
                requested_json,
                persisted_records.get(&record.asset_id),
            )?;
        }
        for (record, record_json) in prepared {
            upsert_encoded_record(&transaction, record, &record_json)?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn export_json_with_owned_lease(&self) -> Result<Manifest, AssetStateStoreError> {
        self.export_json_with_owned_lease_using(|manifest, path| manifest.save_atomic(path))
    }

    fn export_json_with_owned_lease_using<F>(
        &self,
        publish: F,
    ) -> Result<Manifest, AssetStateStoreError>
    where
        F: FnOnce(&Manifest, &Path) -> Result<(), ManifestError>,
    {
        let token = self.writer_token()?;
        let mut connection = self.connect_writer()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.validate_writer_lease(&transaction, token)?;
        let manifest = load_database_manifest_from_transaction(&transaction)?;
        publish(&manifest, &self.manifest_path).map_err(AssetStateStoreError::Manifest)?;
        transaction.commit()?;
        Ok(manifest)
    }

    fn load_json_manifest_snapshot(&self) -> Result<JsonImportSnapshot, AssetStateStoreError> {
        match Manifest::load(&self.manifest_path) {
            Ok(manifest) => {
                let (source_size_bytes, source_mtime_unix_nanos) =
                    manifest_file_metadata(&self.manifest_path)?;
                Ok(JsonImportSnapshot {
                    manifest,
                    source_size_bytes,
                    source_mtime_unix_nanos,
                    import_note: "json_bootstrap",
                })
            }
            Err(ManifestError::Io(source)) if source.kind() == io::ErrorKind::NotFound => {
                Ok(JsonImportSnapshot {
                    manifest: Manifest::new(),
                    source_size_bytes: None,
                    source_mtime_unix_nanos: None,
                    import_note: "missing_json_bootstrap",
                })
            }
            Err(source) => Err(AssetStateStoreError::Manifest(source)),
        }
    }

    fn load_database_manifest(&self) -> Result<Manifest, AssetStateStoreError> {
        if self.writer.is_some() {
            self.writer_token()?;
        }
        let connection = self.connect_read_only()?;
        let mut statement = connection.prepare(
            "SELECT asset_id, state, updated_at, record_json FROM assets ORDER BY asset_id",
        )?;
        load_database_manifest_from_statement(&mut statement)
    }
}

impl Drop for AssetStateStore {
    fn drop(&mut self) {
        if self
            .writer
            .as_ref()
            .is_some_and(|writer| Arc::strong_count(writer) == 1)
        {
            let _ = self.release_writer_lease();
        }
    }
}

fn ensure_wal(connection: &Connection, allow_enable: bool) -> Result<(), AssetStateStoreError> {
    let journal_mode: String =
        connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if journal_mode.eq_ignore_ascii_case("wal") {
        return Ok(());
    }
    if allow_enable {
        let enabled: String =
            connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
        if enabled.eq_ignore_ascii_case("wal") {
            return Ok(());
        }
        return Err(AssetStateStoreError::WalUnavailable { mode: enabled });
    }
    Err(AssetStateStoreError::WalUnavailable { mode: journal_mode })
}

fn create_v2_schema(transaction: &Transaction<'_>) -> Result<(), AssetStateStoreError> {
    transaction.execute_batch(
        "CREATE TABLE assets (
           asset_id TEXT PRIMARY KEY NOT NULL,
           state TEXT NOT NULL,
           updated_at TEXT NOT NULL,
           record_json TEXT NOT NULL
         );
         CREATE INDEX assets_state_index ON assets(state);
         CREATE TABLE writer_lease (
           singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
           owner_id TEXT NOT NULL,
           epoch INTEGER NOT NULL,
           expires_at_unix_ms INTEGER NOT NULL,
           acquired_at_unix_ms INTEGER NOT NULL,
           renewed_at_unix_ms INTEGER NOT NULL
         );
         INSERT INTO writer_lease (
           singleton, owner_id, epoch, expires_at_unix_ms, acquired_at_unix_ms, renewed_at_unix_ms
         ) VALUES (1, '', 0, 0, 0, 0);
         CREATE TABLE json_import_metadata (
           singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
           imported_once INTEGER NOT NULL,
           source_path TEXT,
           source_size_bytes INTEGER,
           source_mtime_unix_nanos INTEGER,
           imported_at_unix_ms INTEGER,
           import_note TEXT
         );
         INSERT INTO json_import_metadata (
           singleton, imported_once, source_path, source_size_bytes,
           source_mtime_unix_nanos, imported_at_unix_ms, import_note
         ) VALUES (1, 0, NULL, NULL, NULL, NULL, NULL);
         PRAGMA user_version = 2;",
    )?;
    Ok(())
}

fn migrate_v1_to_v2_with_import_metadata(
    transaction: &Transaction<'_>,
    metadata: JsonImportMetadataSeed,
) -> Result<(), AssetStateStoreError> {
    transaction.execute_batch(
        "CREATE TABLE writer_lease (
               singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
               owner_id TEXT NOT NULL,
               epoch INTEGER NOT NULL,
               expires_at_unix_ms INTEGER NOT NULL,
               acquired_at_unix_ms INTEGER NOT NULL,
               renewed_at_unix_ms INTEGER NOT NULL
             );
             INSERT INTO writer_lease (
               singleton, owner_id, epoch, expires_at_unix_ms, acquired_at_unix_ms, renewed_at_unix_ms
             ) VALUES (1, '', 0, 0, 0, 0);
             CREATE TABLE json_import_metadata (
               singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
               imported_once INTEGER NOT NULL,
               source_path TEXT,
               source_size_bytes INTEGER,
               source_mtime_unix_nanos INTEGER,
               imported_at_unix_ms INTEGER,
               import_note TEXT
             );",
    )?;
    transaction.execute(
        "INSERT INTO json_import_metadata (
               singleton, imported_once, source_path, source_size_bytes,
               source_mtime_unix_nanos, imported_at_unix_ms, import_note
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            1_i64,
            if metadata.imported_once { 1_i64 } else { 0_i64 },
            metadata.source_path,
            metadata.source_size_bytes,
            metadata.source_mtime_unix_nanos,
            metadata.imported_at_unix_ms,
            metadata.import_note,
        ],
    )?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(())
}

fn validate_exact_v1_schema(transaction: &Transaction<'_>) -> Result<i64, AssetStateStoreError> {
    let actual: i32 = transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if actual != 1 {
        return Err(AssetStateStoreError::MigrationSchemaVersion {
            expected: 1,
            actual,
        });
    }

    let mut statement = transaction.prepare(
        "SELECT type, name FROM sqlite_master
         WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    )?;
    let objects = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected_objects = vec![
        ("index".to_string(), "assets_state_index".to_string()),
        ("table".to_string(), "assets".to_string()),
    ];
    if objects != expected_objects {
        return Err(AssetStateStoreError::MigrationSchemaInvalid {
            reason: "expected only the canonical v1 assets table and assets_state_index"
                .to_string(),
        });
    }

    let mut columns = transaction.prepare("PRAGMA table_info(assets)")?;
    let columns = columns
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected_columns = vec![
        ("asset_id".to_string(), "TEXT".to_string(), 1, 1),
        ("state".to_string(), "TEXT".to_string(), 1, 0),
        ("updated_at".to_string(), "TEXT".to_string(), 1, 0),
        ("record_json".to_string(), "TEXT".to_string(), 1, 0),
    ];
    if columns != expected_columns {
        return Err(AssetStateStoreError::MigrationSchemaInvalid {
            reason: "assets table does not match the canonical v1 columns".to_string(),
        });
    }

    transaction
        .query_row("SELECT count(*) FROM assets", [], |row| row.get(0))
        .map_err(AssetStateStoreError::from)
}

fn ensure_wal_in_transaction(transaction: &Transaction<'_>) -> Result<(), AssetStateStoreError> {
    let journal_mode: String =
        transaction.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if journal_mode.eq_ignore_ascii_case("wal") {
        return Ok(());
    }
    Err(AssetStateStoreError::WalUnavailable { mode: journal_mode })
}

fn quick_check_in_transaction(
    transaction: &Transaction<'_>,
) -> Result<String, AssetStateStoreError> {
    let result: String = transaction.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    if result == "ok" {
        return Ok(result);
    }
    Err(AssetStateStoreError::IntegrityCheck { result })
}

fn release_writer_lease_in_transaction(
    transaction: &Transaction<'_>,
    token: &WriterLeaseToken,
) -> Result<(), AssetStateStoreError> {
    let changed = transaction.execute(
        "UPDATE writer_lease
         SET owner_id = '', expires_at_unix_ms = 0, renewed_at_unix_ms = ?1
         WHERE singleton = 1 AND owner_id = ?2 AND epoch = ?3",
        params![
            current_unix_millis(),
            token.owner_id,
            i64::try_from(token.epoch).unwrap_or(i64::MAX),
        ],
    )?;
    if changed == 1 {
        return Ok(());
    }
    let current = load_writer_lease(transaction)?;
    Err(AssetStateStoreError::WriterLeaseFenced {
        owner_id: token.owner_id.clone(),
        epoch: token.epoch,
        current_owner_id: current.owner_id,
        current_epoch: current.epoch,
    })
}

fn database_id(path: &Path) -> String {
    format!(
        "sha256:{:x}",
        Sha256::digest(path.to_string_lossy().as_bytes())
    )
}

fn validate_writer_owner_id(owner_id: &str) -> Result<(), AssetStateStoreError> {
    if owner_id.trim().is_empty() || owner_id.len() > MAX_WRITER_OWNER_ID_BYTES {
        return Err(AssetStateStoreError::InvalidWriterOwnerId {
            length: owner_id.len(),
            maximum: MAX_WRITER_OWNER_ID_BYTES,
        });
    }
    Ok(())
}

fn validate_writer_lease_ttl(lease_ttl: Duration) -> Result<(), AssetStateStoreError> {
    if lease_ttl.is_zero()
        || lease_ttl > MAX_WRITER_LEASE_TTL
        || i64::try_from(lease_ttl.as_millis()).is_err()
    {
        return Err(AssetStateStoreError::InvalidWriterLeaseTtl {
            ttl: lease_ttl,
            maximum: MAX_WRITER_LEASE_TTL,
        });
    }
    Ok(())
}

fn manifest_file_metadata(
    manifest_path: &Path,
) -> Result<(Option<i64>, Option<i64>), AssetStateStoreError> {
    match fs::metadata(manifest_path) {
        Ok(metadata) => {
            let size = i64::try_from(metadata.len()).unwrap_or(i64::MAX);
            let mtime = metadata
                .modified()
                .ok()
                .and_then(system_time_to_unix_nanos_i64);
            Ok((Some(size), mtime))
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok((None, None)),
        Err(source) => Err(AssetStateStoreError::ManifestMetadata {
            path: manifest_path.to_path_buf(),
            source,
        }),
    }
}

fn system_time_to_unix_nanos_i64(time: SystemTime) -> Option<i64> {
    let duration = time.duration_since(UNIX_EPOCH).ok()?;
    i64::try_from(duration.as_nanos()).ok()
}

fn current_unix_millis() -> i64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

fn duration_millis_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

fn load_writer_lease(
    transaction: &Transaction<'_>,
) -> Result<WriterLeaseRow, AssetStateStoreError> {
    let (owner_id, epoch, expires_at_unix_ms, acquired_at_unix_ms): (String, i64, i64, i64) =
        transaction.query_row(
        "SELECT owner_id, epoch, expires_at_unix_ms, acquired_at_unix_ms FROM writer_lease WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let epoch = u64::try_from(epoch)
        .map_err(|_| AssetStateStoreError::InvalidWriterLeaseEpoch { epoch })?;
    Ok(WriterLeaseRow {
        owner_id,
        epoch,
        expires_at_unix_ms,
        acquired_at_unix_ms,
    })
}

fn load_json_import_metadata(
    transaction: &Transaction<'_>,
) -> Result<JsonImportMetadata, AssetStateStoreError> {
    transaction
        .query_row(
            "SELECT imported_once FROM json_import_metadata WHERE singleton = 1",
            [],
            |row| {
                let imported_once: i64 = row.get(0)?;
                Ok(JsonImportMetadata {
                    imported_once: imported_once != 0,
                })
            },
        )
        .map_err(AssetStateStoreError::from)
}

fn persist_json_import_metadata(
    transaction: &Transaction<'_>,
    manifest_path: &Path,
    snapshot: &JsonImportSnapshot,
) -> Result<(), AssetStateStoreError> {
    transaction.execute(
        "UPDATE json_import_metadata
         SET imported_once = 1,
             source_path = ?1,
             source_size_bytes = ?2,
             source_mtime_unix_nanos = ?3,
             imported_at_unix_ms = ?4,
             import_note = ?5
         WHERE singleton = 1",
        params![
            manifest_path.display().to_string(),
            snapshot.source_size_bytes,
            snapshot.source_mtime_unix_nanos,
            current_unix_millis(),
            snapshot.import_note,
        ],
    )?;
    Ok(())
}

fn load_database_manifest_from_transaction(
    transaction: &Transaction<'_>,
) -> Result<Manifest, AssetStateStoreError> {
    let mut statement = transaction
        .prepare("SELECT asset_id, state, updated_at, record_json FROM assets ORDER BY asset_id")?;
    load_database_manifest_from_statement(&mut statement)
}

fn load_database_manifest_from_statement(
    statement: &mut Statement<'_>,
) -> Result<Manifest, AssetStateStoreError> {
    let mut rows = statement.query([])?;
    let mut manifest = Manifest::new();
    while let Some(row) = rows.next()? {
        let asset_id: String = row.get(0)?;
        let state: String = row.get(1)?;
        let updated_at: String = row.get(2)?;
        let record_json: String = row.get(3)?;
        let record: AssetRecord = serde_json::from_str(&record_json).map_err(|source| {
            AssetStateStoreError::DecodeRecord {
                asset_id: asset_id.clone(),
                source,
            }
        })?;
        if record.asset_id != asset_id
            || record.state.as_str() != state
            || record.updated_at != updated_at
        {
            return Err(AssetStateStoreError::RecordColumnMismatch { asset_id });
        }
        manifest.upsert(record);
    }
    Ok(manifest)
}

fn upsert_record(
    transaction: &Transaction<'_>,
    record: &AssetRecord,
) -> Result<usize, AssetStateStoreError> {
    let record_json = encode_record(record)?;
    upsert_encoded_record(transaction, record, &record_json)
}

fn upsert_encoded_record(
    transaction: &Transaction<'_>,
    record: &AssetRecord,
    record_json: &str,
) -> Result<usize, AssetStateStoreError> {
    let changed = transaction.execute(
        "INSERT INTO assets (asset_id, state, updated_at, record_json)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(asset_id) DO UPDATE SET
           state = excluded.state,
           updated_at = excluded.updated_at,
           record_json = excluded.record_json
         WHERE excluded.updated_at > assets.updated_at",
        params![
            record.asset_id,
            record.state.as_str(),
            record.updated_at,
            record_json
        ],
    )?;
    Ok(changed)
}

fn encode_record(record: &AssetRecord) -> Result<String, AssetStateStoreError> {
    serde_json::to_string(record).map_err(|source| AssetStateStoreError::EncodeRecord {
        asset_id: record.asset_id.clone(),
        source,
    })
}

fn load_persisted_records(
    transaction: &Transaction<'_>,
) -> Result<BTreeMap<String, (String, String)>, AssetStateStoreError> {
    let mut statement =
        transaction.prepare("SELECT asset_id, updated_at, record_json FROM assets")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut records = BTreeMap::new();
    for row in rows {
        let (asset_id, updated_at, record_json) = row?;
        records.insert(asset_id, (updated_at, record_json));
    }
    Ok(records)
}

fn validate_requested_record(
    record: &AssetRecord,
    requested_json: &str,
    persisted: Option<&(String, String)>,
) -> Result<(), AssetStateStoreError> {
    match persisted {
        Some((updated_at, _)) if updated_at > &record.updated_at => {
            Err(AssetStateStoreError::StaleRecord {
                asset_id: record.asset_id.clone(),
            })
        }
        Some((updated_at, persisted_json))
            if updated_at == &record.updated_at && persisted_json != requested_json =>
        {
            Err(AssetStateStoreError::StaleRecord {
                asset_id: record.asset_id.clone(),
            })
        }
        _ => Ok(()),
    }
}

fn reject_stale_record(
    transaction: &Transaction<'_>,
    record: &AssetRecord,
    changed: usize,
) -> Result<(), AssetStateStoreError> {
    if changed > 0 {
        return Ok(());
    }
    let persisted_json: String = transaction.query_row(
        "SELECT record_json FROM assets WHERE asset_id = ?1",
        [&record.asset_id],
        |row| row.get(0),
    )?;
    let requested_json = encode_record(record)?;
    if persisted_json != requested_json {
        return Err(AssetStateStoreError::StaleRecord {
            asset_id: record.asset_id.clone(),
        });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum AssetStateStoreError {
    #[error("failed to create state database directory {path}: {source}")]
    CreateDirectory { path: PathBuf, source: io::Error },
    #[error("failed to open state database {path}: {source}")]
    OpenDatabase {
        path: PathBuf,
        source: rusqlite::Error,
    },
    #[error("schema migration only supports from=1 to=2; received from={from} to={to}")]
    InvalidSchemaMigration { from: i32, to: i32 },
    #[error("state database for schema migration does not exist at {path}")]
    MigrationDatabaseMissing { path: PathBuf },
    #[error("failed to inspect state database for schema migration at {path}: {source}")]
    MigrationDatabaseMetadata { path: PathBuf, source: io::Error },
    #[error("schema migration expected schema version {expected}, found {actual}")]
    MigrationSchemaVersion { expected: i32, actual: i32 },
    #[error("schema migration rejected noncanonical v1 schema: {reason}")]
    MigrationSchemaInvalid { reason: String },
    #[error("state database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("manifest error: {0}")]
    Manifest(#[from] ManifestError),
    #[error("failed to read manifest metadata for {path}: {source}")]
    ManifestMetadata { path: PathBuf, source: io::Error },
    #[error("failed to encode asset {asset_id}: {source}")]
    EncodeRecord {
        asset_id: String,
        source: serde_json::Error,
    },
    #[error("failed to decode asset {asset_id}: {source}")]
    DecodeRecord {
        asset_id: String,
        source: serde_json::Error,
    },
    #[error("state database schema version {actual} is unsupported; expected {expected}")]
    UnsupportedSchema { expected: i32, actual: i32 },
    #[error("state database schema is missing")]
    MissingSchema,
    #[error("state database WAL mode is unavailable; current mode is {mode}")]
    WalUnavailable { mode: String },
    #[error("state database integrity check failed: {result}")]
    IntegrityCheck { result: String },
    #[error("state database columns do not match the stored record for {asset_id}")]
    RecordColumnMismatch { asset_id: String },
    #[error("refusing to overwrite newer durable state for {asset_id}")]
    StaleRecord { asset_id: String },
    #[error("atomic state batch contains duplicate asset ID {asset_id}")]
    DuplicateRecord { asset_id: String },
    #[error("writer lease is required for state mutation")]
    WriterLeaseRequired,
    #[error(
        "writer owner ID length {length} must be nonzero after trimming and at most {maximum} bytes"
    )]
    InvalidWriterOwnerId { length: usize, maximum: usize },
    #[error("state writer lease TTL {ttl:?} must be greater than zero and at most {maximum:?}")]
    InvalidWriterLeaseTtl { ttl: Duration, maximum: Duration },
    #[error("state writer lease is held by {owner_id} at epoch {epoch} until {expires_at_unix_ms}")]
    WriterLeaseHeld {
        owner_id: String,
        epoch: u64,
        expires_at_unix_ms: i64,
    },
    #[error("state writer lease epoch is invalid: {epoch}")]
    InvalidWriterLeaseEpoch { epoch: i64 },
    #[error(
        "state writer lease for {owner_id} at epoch {epoch} was fenced by {current_owner_id} at epoch {current_epoch}"
    )]
    WriterLeaseFenced {
        owner_id: String,
        epoch: u64,
        current_owner_id: String,
        current_epoch: u64,
    },
    #[error("state writer lease heartbeat was lost: {reason}")]
    WriterLeaseHeartbeatLost { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn export_keeps_fencing_transaction_until_publication_succeeds() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest_path = tempdir.path().join("manifest.json");
        let writer_a =
            AssetStateStore::open_writer(&manifest_path, "writer-a", Duration::from_millis(50))
                .expect("writer a");
        writer_a.load_or_import().expect("import");

        let (publish_started_tx, publish_started_rx) = mpsc::channel();
        let (release_publish_tx, release_publish_rx) = mpsc::channel();
        let export_store = writer_a.clone();
        let export_handle = thread::spawn(move || {
            export_store.export_json_with_owned_lease_using(|manifest, path| {
                publish_started_tx.send(()).expect("signal publish start");
                release_publish_rx.recv().expect("wait for release");
                manifest.save_atomic(path)
            })
        });

        publish_started_rx.recv().expect("wait for publish start");
        thread::sleep(Duration::from_millis(80));

        let (takeover_tx, takeover_rx) = mpsc::channel();
        let takeover_path = manifest_path.clone();
        thread::spawn(move || {
            let result =
                AssetStateStore::open_writer(&takeover_path, "writer-b", Duration::from_secs(1));
            takeover_tx
                .send(result.is_ok())
                .expect("send takeover result");
        });

        assert!(
            takeover_rx.recv_timeout(Duration::from_millis(30)).is_err(),
            "takeover must stay blocked until publication returns"
        );

        release_publish_tx.send(()).expect("release publish");
        export_handle
            .join()
            .expect("export thread")
            .expect("export should succeed");
        assert!(
            takeover_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("takeover result should arrive after export"),
            "takeover should proceed after publication completes"
        );
    }

    #[test]
    fn failed_post_acquisition_integrity_releases_the_writer_lease() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest_path = tempdir.path().join("manifest.json");

        fail_next_integrity_check_for_current_thread();
        let error =
            AssetStateStore::open_writer(&manifest_path, "writer-a", Duration::from_secs(1))
                .expect_err("forced integrity failure should reject the writer");
        assert!(matches!(error, AssetStateStoreError::IntegrityCheck { .. }));

        AssetStateStore::open_writer(&manifest_path, "writer-b", Duration::from_secs(1))
            .expect("failed post-acquisition integrity must not leave a held lease");
    }
}

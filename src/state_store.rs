#[cfg(test)]
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
#[cfg(unix)]
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{
    Connection, OpenFlags, OptionalExtension, Statement, Transaction, TransactionBehavior, params,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
#[cfg(unix)]
use uuid::Uuid;

use crate::manifest::{AssetRecord, Manifest, ManifestError, sanitize_untrusted_recipe_claims};
#[cfg(unix)]
use crate::manifest_lock::{ManifestLockError, acquire_existing_manifest_lock};

const SCHEMA_VERSION: i32 = 2;
const BUSY_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_WRITER_LEASE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_WRITER_OWNER_ID_BYTES: usize = 128;
const CANONICAL_V1_ASSETS_SQL: &str = "CREATE TABLE assets (
    asset_id TEXT PRIMARY KEY NOT NULL,
    state TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    record_json TEXT NOT NULL
)";
const CANONICAL_V1_ASSETS_STATE_INDEX_SQL: &str =
    "CREATE INDEX assets_state_index ON assets(state)";

#[cfg(test)]
std::thread_local! {
    static FAIL_NEXT_INTEGRITY_CHECK: Cell<bool> = const { Cell::new(false) };
    static MIGRATION_PRECOMMIT_HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}

#[cfg(test)]
fn fail_next_integrity_check_for_current_thread() {
    FAIL_NEXT_INTEGRITY_CHECK.with(|fail| fail.set(true));
}

#[cfg(test)]
fn set_migration_precommit_hook_for_current_thread(hook: impl FnOnce() + 'static) {
    MIGRATION_PRECOMMIT_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_migration_precommit_hook() {
    MIGRATION_PRECOMMIT_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_migration_precommit_hook() {}

#[derive(Clone, Debug)]
pub struct AssetStateStore {
    manifest_path: PathBuf,
    db_path: PathBuf,
    read_mode: StateStoreReadMode,
    writer: Option<Arc<WriterLeaseToken>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StateStoreReadMode {
    Normal,
    Immutable(Arc<ImmutableReadWitness>),
}

#[derive(Debug, Eq, PartialEq)]
struct ImmutableReadWitness {
    size_bytes: u64,
    modified_unix_nanos: Option<u128>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    sha256: String,
}

#[derive(Clone, Copy, Debug)]
pub struct AssetRecordExactCasUpdate<'a> {
    pub expected: &'a AssetRecord,
    pub updated: &'a AssetRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JsonCheckpointStatus {
    Current,
    Stale,
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

#[cfg(unix)]
struct VerifiedDatabasePath {
    canonical_path: PathBuf,
    identity: DatabaseIdentity,
    file: File,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DatabaseIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(unix)]
#[derive(Debug)]
struct ParentDirectoryWitness {
    path: PathBuf,
    identity: DirectoryIdentity,
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
            read_mode: StateStoreReadMode::Normal,
            writer: None,
        };
        let connection = store.connect_read_only()?;
        store.verify_read_only_schema(&connection)?;
        store.verify_integrity(&connection)?;
        Ok(store)
    }

    pub fn open_immutable_read_only(
        manifest_path: impl AsRef<Path>,
    ) -> Result<Self, AssetStateStoreError> {
        let manifest_path = manifest_path.as_ref().to_path_buf();
        let db_path = Self::db_path_for_manifest(&manifest_path);
        let witness = capture_immutable_read_witness(&db_path)?;
        let store = Self {
            manifest_path,
            db_path,
            read_mode: StateStoreReadMode::Immutable(Arc::new(witness)),
            writer: None,
        };
        let connection = store.connect_immutable_read_only()?;
        store.verify_read_only_schema(&connection)?;
        store.verify_integrity(&connection)?;
        store.revalidate_immutable_read_snapshot()?;
        Ok(store)
    }

    pub fn revalidate_immutable_read_snapshot(&self) -> Result<(), AssetStateStoreError> {
        let StateStoreReadMode::Immutable(expected) = &self.read_mode else {
            return Err(AssetStateStoreError::ImmutableReadWitnessRequired);
        };
        let actual = capture_immutable_read_witness(&self.db_path)?;
        if actual != **expected {
            return Err(AssetStateStoreError::ImmutableReadSnapshotChanged);
        }
        Ok(())
    }

    pub fn json_checkpoint_status(&self) -> Result<JsonCheckpointStatus, AssetStateStoreError> {
        self.revalidate_immutable_read_snapshot()?;
        let database_manifest = self.load()?;
        let status = self.json_checkpoint_status_for_manifest(&database_manifest)?;
        self.revalidate_immutable_read_snapshot()?;
        Ok(status)
    }

    pub(crate) fn json_checkpoint_status_for_manifest(
        &self,
        database_manifest: &Manifest,
    ) -> Result<JsonCheckpointStatus, AssetStateStoreError> {
        let json_manifest = match load_json_checkpoint_no_follow(&self.manifest_path)? {
            Some(manifest) => manifest,
            None => return Ok(JsonCheckpointStatus::Stale),
        };
        Ok(if json_manifest == *database_manifest {
            JsonCheckpointStatus::Current
        } else {
            JsonCheckpointStatus::Stale
        })
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
            read_mode: StateStoreReadMode::Normal,
            writer: None,
        };
        let mut connection = store.connect_writer()?;
        let schema_version: i32 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if schema_version == 1 {
            return Err(AssetStateStoreError::MigrationRequired {
                path: store.db_path.clone(),
            });
        }
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
        #[cfg(not(unix))]
        {
            let _ = (manifest_path, from, to);
            return Err(AssetStateStoreError::MigrationUnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            if from != 1 || to != SCHEMA_VERSION {
                return Err(AssetStateStoreError::InvalidSchemaMigration { from, to });
            }

            let manifest_path = manifest_path.as_ref().to_path_buf();
            let requested_db_path = Self::db_path_for_manifest(&manifest_path);
            preflight_existing_database_path(&requested_db_path)?;
            let owner_id = format!("schema-migrate-{}", Uuid::new_v4());
            let manifest_lock = acquire_existing_manifest_lock(&manifest_path, &owner_id)
                .map_err(migration_lock_error)?;
            manifest_lock.revalidate().map_err(migration_lock_error)?;
            let verified_database = verify_existing_database_path(&requested_db_path)?;

            let store = Self {
                manifest_path,
                db_path: verified_database.canonical_path.clone(),
                read_mode: StateStoreReadMode::Normal,
                writer: None,
            };
            let mut connection = store.connect_existing_writer()?;
            revalidate_verified_database_path(&verified_database)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let asset_count = validate_exact_v1_schema(&transaction)?;
            if asset_count == 0 {
                return Err(AssetStateStoreError::MigrationSchemaEmpty);
            }
            let asset_count = u64::try_from(asset_count).map_err(|_| {
                AssetStateStoreError::MigrationSchemaInvalid {
                    reason: "assets count must not be negative".to_string(),
                }
            })?;
            ensure_wal_in_transaction(&transaction)?;

            // The IMMEDIATE transaction serializes legacy v1 writers until the v2 lease exists.
            // Once created, the lease token is acquired and cleared in this same transaction.
            migrate_v1_to_v2_with_import_metadata(
                &transaction,
                JsonImportMetadataSeed::schema_only(),
            )?;
            let token = store.acquire_writer_lease_in_transaction(
                &transaction,
                &owner_id,
                Duration::from_secs(30),
            )?;
            release_writer_lease_in_transaction(&transaction, &token)?;
            let quick_check = quick_check_in_transaction(&transaction)?;
            // SQLite may create WAL/SHM sidecars while the DDL above runs. Capture the
            // directory only after that expected churn so a later path ABA is observable.
            let directory_witness = capture_parent_directory_witness(&verified_database)?;
            run_migration_precommit_hook();
            manifest_lock.revalidate().map_err(migration_lock_error)?;
            revalidate_verified_database_path(&verified_database)?;
            revalidate_parent_directory_witness(&directory_witness)?;
            transaction.commit()?;

            Ok(SchemaMigrationSummary {
                from,
                to,
                asset_count,
                database_id: database_id(&verified_database),
                quick_check,
            })
        }
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
        let mut sanitized = record.clone();
        sanitize_untrusted_recipe_claims(&mut sanitized);
        self.persist_record_trusted(&sanitized)
    }

    pub(crate) fn persist_record_trusted(
        &self,
        record: &AssetRecord,
    ) -> Result<Duration, AssetStateStoreError> {
        self.persist_record_with_owned_lease(record)
    }

    pub fn persist_records_atomic<'a>(
        &self,
        records: impl IntoIterator<Item = &'a AssetRecord>,
    ) -> Result<Duration, AssetStateStoreError> {
        let sanitized = records
            .into_iter()
            .map(|record| {
                let mut record = record.clone();
                sanitize_untrusted_recipe_claims(&mut record);
                record
            })
            .collect::<Vec<_>>();
        self.persist_records_atomic_trusted(sanitized.iter())
    }

    pub(crate) fn persist_records_atomic_trusted<'a>(
        &self,
        records: impl IntoIterator<Item = &'a AssetRecord>,
    ) -> Result<Duration, AssetStateStoreError> {
        self.persist_records_atomic_with_owned_lease(records)
    }

    pub fn persist_records_exact_cas_atomic<'a>(
        &self,
        updates: impl IntoIterator<Item = AssetRecordExactCasUpdate<'a>>,
    ) -> Result<Duration, AssetStateStoreError> {
        let updates = updates.into_iter().collect::<Vec<_>>();
        let sanitized_updates = updates
            .iter()
            .map(|update| {
                let mut record = update.updated.clone();
                sanitize_untrusted_recipe_claims(&mut record);
                record
            })
            .collect::<Vec<_>>();
        let sanitized = updates
            .iter()
            .zip(sanitized_updates.iter())
            .map(|(update, updated)| AssetRecordExactCasUpdate {
                expected: update.expected,
                updated,
            })
            .collect::<Vec<_>>();
        self.persist_records_exact_cas_atomic_trusted(sanitized)
    }

    pub(crate) fn persist_records_exact_cas_atomic_trusted<'a>(
        &self,
        updates: impl IntoIterator<Item = AssetRecordExactCasUpdate<'a>>,
    ) -> Result<Duration, AssetStateStoreError> {
        self.persist_records_exact_cas_atomic_with_owned_lease(updates)
    }

    pub fn persist_manifest_records(
        &self,
        manifest: &Manifest,
    ) -> Result<(), AssetStateStoreError> {
        let mut sanitized = Manifest::new();
        for record in manifest.records().values() {
            sanitized.upsert(record.clone());
        }
        self.persist_manifest_records_trusted(&sanitized)
    }

    pub(crate) fn persist_manifest_records_trusted(
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
        let connection = Connection::open_with_flags(
            &self.db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|source| AssetStateStoreError::OpenDatabase {
            path: self.db_path.clone(),
            source,
        })?;
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

    fn connect_immutable_read_only(&self) -> Result<Connection, AssetStateStoreError> {
        self.revalidate_immutable_read_snapshot()?;
        let mut uri = url::Url::from_file_path(&self.db_path)
            .map_err(|_| AssetStateStoreError::ReadOnlyUri)?;
        uri.set_query(Some("immutable=1"));
        let connection = Connection::open_with_flags(
            uri.as_str(),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
        .map_err(|source| AssetStateStoreError::OpenDatabase {
            path: self.db_path.clone(),
            source,
        })?;
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
            (1, _) => {
                return Err(AssetStateStoreError::MigrationRequired {
                    path: self.db_path.clone(),
                });
            }
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

    fn persist_records_exact_cas_atomic_with_owned_lease<'a>(
        &self,
        updates: impl IntoIterator<Item = AssetRecordExactCasUpdate<'a>>,
    ) -> Result<Duration, AssetStateStoreError> {
        let token = self.writer_token()?;
        let started = Instant::now();
        let mut asset_ids = BTreeSet::new();
        let mut prepared = Vec::new();
        for update in updates {
            if update.expected.asset_id != update.updated.asset_id {
                return Err(AssetStateStoreError::ExactCasMismatchedIds {
                    expected_asset_id: update.expected.asset_id.clone(),
                    updated_asset_id: update.updated.asset_id.clone(),
                });
            }
            if !asset_ids.insert(update.expected.asset_id.clone()) {
                return Err(AssetStateStoreError::DuplicateRecord {
                    asset_id: update.expected.asset_id.clone(),
                });
            }
            prepared.push((
                update.expected,
                update.updated,
                encode_record(update.expected)?,
                encode_record(update.updated)?,
            ));
        }
        if prepared.is_empty() {
            return Ok(started.elapsed());
        }

        let mut connection = self.connect_writer()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        self.validate_writer_lease(&transaction, token)?;
        {
            let mut statement = transaction
                .prepare("SELECT state, updated_at, record_json FROM assets WHERE asset_id = ?1")?;
            for (expected, _, expected_json, _) in &prepared {
                let persisted = statement
                    .query_row([expected.asset_id.as_str()], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    })
                    .optional()?;
                if persisted
                    .as_ref()
                    .is_none_or(|(state, updated_at, record_json)| {
                        state != expected.state.as_str()
                            || updated_at != &expected.updated_at
                            || record_json != expected_json
                    })
                {
                    return Err(AssetStateStoreError::ExactCasMismatch {
                        asset_id: expected.asset_id.clone(),
                    });
                }
            }
        }
        for (_, updated, _, updated_json) in prepared {
            let changed = transaction.execute(
                "UPDATE assets
                 SET state = ?1, updated_at = ?2, record_json = ?3
                 WHERE asset_id = ?4",
                params![
                    updated.state.as_str(),
                    updated.updated_at,
                    updated_json,
                    updated.asset_id,
                ],
            )?;
            if changed != 1 {
                return Err(AssetStateStoreError::ExactCasMismatch {
                    asset_id: updated.asset_id.clone(),
                });
            }
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
        let connection = if self.writer.is_some() {
            self.writer_token()?;
            self.connect_writer()?
        } else {
            match &self.read_mode {
                StateStoreReadMode::Normal => self.connect_read_only()?,
                StateStoreReadMode::Immutable(_) => self.connect_immutable_read_only()?,
            }
        };
        let mut statement = connection.prepare(
            "SELECT asset_id, state, updated_at, record_json FROM assets ORDER BY asset_id",
        )?;
        let manifest = load_database_manifest_from_statement(&mut statement)?;
        drop(statement);
        drop(connection);
        if matches!(self.read_mode, StateStoreReadMode::Immutable(_)) {
            self.revalidate_immutable_read_snapshot()?;
        }
        Ok(manifest)
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
        "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master
         WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    )?;
    let objects = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                normalize_schema_sql(&row.get::<_, String>(3)?),
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected_objects = vec![
        (
            "index".to_string(),
            "assets_state_index".to_string(),
            "assets".to_string(),
            normalize_schema_sql(CANONICAL_V1_ASSETS_STATE_INDEX_SQL),
        ),
        (
            "table".to_string(),
            "assets".to_string(),
            "assets".to_string(),
            normalize_schema_sql(CANONICAL_V1_ASSETS_SQL),
        ),
    ];
    if objects != expected_objects {
        return Err(AssetStateStoreError::MigrationSchemaInvalid {
            reason: "schema objects do not match the canonical v1 DDL".to_string(),
        });
    }

    let mut columns = transaction.prepare("PRAGMA table_xinfo(assets)")?;
    let columns = columns
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let expected_columns = vec![
        (0, "asset_id".to_string(), "TEXT".to_string(), 1, None, 1, 0),
        (1, "state".to_string(), "TEXT".to_string(), 1, None, 0, 0),
        (
            2,
            "updated_at".to_string(),
            "TEXT".to_string(),
            1,
            None,
            0,
            0,
        ),
        (
            3,
            "record_json".to_string(),
            "TEXT".to_string(),
            1,
            None,
            0,
            0,
        ),
    ];
    if columns != expected_columns {
        return Err(AssetStateStoreError::MigrationSchemaInvalid {
            reason: "assets columns do not match the canonical v1 definition".to_string(),
        });
    }

    let mut tables = transaction.prepare("PRAGMA table_list")?;
    let tables = tables
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let assets_tables = tables
        .into_iter()
        .filter(|(schema, name, _, _, _, _)| schema == "main" && name == "assets")
        .collect::<Vec<_>>();
    if assets_tables
        != vec![(
            "main".to_string(),
            "assets".to_string(),
            "table".to_string(),
            4,
            0,
            0,
        )]
    {
        return Err(AssetStateStoreError::MigrationSchemaInvalid {
            reason: "assets table must not be STRICT or WITHOUT ROWID".to_string(),
        });
    }

    let mut indexes = transaction.prepare("PRAGMA index_list(assets)")?;
    let indexes = indexes
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?
        .filter_map(|row| match row {
            Ok((_, name, _, _, _)) if name.starts_with("sqlite_autoindex_") => None,
            other => Some(other),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if indexes != vec![(0, "assets_state_index".to_string(), 0, "c".to_string(), 0)] {
        return Err(AssetStateStoreError::MigrationSchemaInvalid {
            reason: "assets_state_index must be the canonical non-unique non-partial index"
                .to_string(),
        });
    }

    let mut index_columns = transaction.prepare("PRAGMA index_xinfo(assets_state_index)")?;
    let index_columns = index_columns
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?
        .filter_map(|row| match row {
            Ok((_, _, _, _, _, 0)) => None,
            other => Some(other),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if index_columns != vec![(0, 1, Some("state".to_string()), 0, "BINARY".to_string(), 1)] {
        return Err(AssetStateStoreError::MigrationSchemaInvalid {
            reason: "assets_state_index must index only state with the canonical ordering"
                .to_string(),
        });
    }

    validate_v1_asset_rows(transaction)
}

fn validate_v1_asset_rows(transaction: &Transaction<'_>) -> Result<i64, AssetStateStoreError> {
    let mut statement = transaction
        .prepare("SELECT asset_id, state, updated_at, record_json FROM assets ORDER BY asset_id")?;
    let mut rows = statement.query([])?;
    let mut asset_count = 0_i64;
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
        asset_count = asset_count.saturating_add(1);
    }
    Ok(asset_count)
}

fn normalize_schema_sql(sql: &str) -> String {
    sql.chars()
        .filter(|character| !character.is_whitespace())
        .map(|character| character.to_ascii_lowercase())
        .collect()
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
    #[cfg(test)]
    if FAIL_NEXT_INTEGRITY_CHECK.with(|fail| fail.replace(false)) {
        return Err(AssetStateStoreError::IntegrityCheck {
            result: "forced test failure".to_string(),
        });
    }
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

#[cfg(unix)]
fn database_id(verified_database: &VerifiedDatabasePath) -> String {
    let mut hasher = Sha256::new();
    hasher.update(
        verified_database
            .canonical_path
            .to_string_lossy()
            .as_bytes(),
    );
    hasher.update([0]);
    hasher.update(verified_database.identity.device.to_le_bytes());
    hasher.update(verified_database.identity.inode.to_le_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(unix)]
fn verify_existing_database_path(
    path: &Path,
) -> Result<VerifiedDatabasePath, AssetStateStoreError> {
    preflight_existing_database_path(path)?;
    let canonical_path = fs::canonicalize(path).map_err(|source| {
        AssetStateStoreError::MigrationDatabaseMetadata {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let canonical_metadata = fs::symlink_metadata(&canonical_path).map_err(|source| {
        AssetStateStoreError::MigrationDatabaseMetadata {
            path: canonical_path.clone(),
            source,
        }
    })?;
    validate_database_path_metadata(&canonical_path, &canonical_metadata)?;
    let file = open_verified_database_file(&canonical_path)?;
    let identity = validate_database_identity(&canonical_path, &file)?;
    Ok(VerifiedDatabasePath {
        canonical_path,
        identity,
        file,
    })
}

#[cfg(unix)]
fn preflight_existing_database_path(path: &Path) -> Result<(), AssetStateStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(AssetStateStoreError::MigrationDatabaseMissing {
                path: path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(AssetStateStoreError::MigrationDatabaseMetadata {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    validate_database_path_metadata(path, &metadata)
}

#[cfg(unix)]
fn validate_database_path_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), AssetStateStoreError> {
    if metadata.file_type().is_symlink() {
        return Err(AssetStateStoreError::MigrationDatabaseSymlink {
            path: path.to_path_buf(),
        });
    }
    if !metadata.file_type().is_file() {
        return Err(AssetStateStoreError::MigrationDatabaseNotFile {
            path: path.to_path_buf(),
        });
    }
    if metadata.nlink() != 1 {
        return Err(AssetStateStoreError::MigrationDatabaseHardLink {
            path: path.to_path_buf(),
            links: metadata.nlink(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn open_verified_database_file(path: &Path) -> Result<File, AssetStateStoreError> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    options
        .open(path)
        .map_err(|source| AssetStateStoreError::MigrationDatabaseMetadata {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(unix)]
fn validate_database_identity(
    path: &Path,
    file: &File,
) -> Result<DatabaseIdentity, AssetStateStoreError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|source| {
        AssetStateStoreError::MigrationDatabaseMetadata {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let file_metadata =
        file.metadata()
            .map_err(|source| AssetStateStoreError::MigrationDatabaseMetadata {
                path: path.to_path_buf(),
                source,
            })?;
    for metadata in [&path_metadata, &file_metadata] {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(AssetStateStoreError::MigrationDatabaseNotFile {
                path: path.to_path_buf(),
            });
        }
        if metadata.nlink() != 1 {
            return Err(AssetStateStoreError::MigrationDatabaseHardLink {
                path: path.to_path_buf(),
                links: metadata.nlink(),
            });
        }
    }
    let path_identity = DatabaseIdentity {
        device: path_metadata.dev(),
        inode: path_metadata.ino(),
    };
    let file_identity = DatabaseIdentity {
        device: file_metadata.dev(),
        inode: file_metadata.ino(),
    };
    if path_identity != file_identity {
        return Err(AssetStateStoreError::MigrationDatabaseIdentityChanged {
            path: path.to_path_buf(),
        });
    }
    Ok(file_identity)
}

#[cfg(unix)]
fn revalidate_verified_database_path(
    verified_database: &VerifiedDatabasePath,
) -> Result<(), AssetStateStoreError> {
    let identity =
        validate_database_identity(&verified_database.canonical_path, &verified_database.file)?;
    if identity != verified_database.identity {
        return Err(AssetStateStoreError::MigrationDatabaseIdentityChanged {
            path: verified_database.canonical_path.clone(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn capture_parent_directory_witness(
    verified_database: &VerifiedDatabasePath,
) -> Result<ParentDirectoryWitness, AssetStateStoreError> {
    let path = verified_database
        .canonical_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let identity = directory_identity(&path)?;
    Ok(ParentDirectoryWitness { path, identity })
}

#[cfg(unix)]
fn revalidate_parent_directory_witness(
    witness: &ParentDirectoryWitness,
) -> Result<(), AssetStateStoreError> {
    if directory_identity(&witness.path)? != witness.identity {
        return Err(AssetStateStoreError::MigrationDatabaseDirectoryChanged {
            path: witness.path.clone(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn directory_identity(path: &Path) -> Result<DirectoryIdentity, AssetStateStoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        AssetStateStoreError::MigrationDatabaseMetadata {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(AssetStateStoreError::MigrationDatabaseDirectoryChanged {
            path: path.to_path_buf(),
        });
    }
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

#[cfg(unix)]
fn migration_lock_error(error: ManifestLockError) -> AssetStateStoreError {
    match error {
        ManifestLockError::UnsupportedPlatform => {
            AssetStateStoreError::MigrationUnsupportedPlatform
        }
        ManifestLockError::Held { lock_path } => {
            AssetStateStoreError::MigrationMonitorLockHeld { lock_path }
        }
        ManifestLockError::Missing { lock_path } => {
            AssetStateStoreError::MigrationMonitorLockMissing { lock_path }
        }
        ManifestLockError::Symlink { path } => {
            AssetStateStoreError::MigrationMonitorLockSymlink { path }
        }
        ManifestLockError::NotRegular { path } => {
            AssetStateStoreError::MigrationMonitorLockNotRegular { path }
        }
        ManifestLockError::HardLink { path, links } => {
            AssetStateStoreError::MigrationMonitorLockHardLink { path, links }
        }
        ManifestLockError::IdentityChanged { path } => {
            AssetStateStoreError::MigrationMonitorLockIdentityChanged { path }
        }
        ManifestLockError::Io { path, source } => {
            AssetStateStoreError::MigrationMonitorLockIo { path, source }
        }
    }
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

fn sqlite_wal_path(database_path: &Path) -> PathBuf {
    let mut wal_path = database_path.as_os_str().to_os_string();
    wal_path.push("-wal");
    PathBuf::from(wal_path)
}

fn capture_immutable_read_witness(
    database_path: &Path,
) -> Result<ImmutableReadWitness, AssetStateStoreError> {
    if immutable_wal_len(database_path)? > 0 {
        return Err(AssetStateStoreError::ReadOnlyWalPending);
    }

    let mut file = fs::File::open(database_path)
        .map_err(|source| AssetStateStoreError::ImmutableReadDatabaseIo { source })?;
    let before = file
        .metadata()
        .map_err(|source| AssetStateStoreError::ImmutableReadDatabaseIo { source })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|source| AssetStateStoreError::ImmutableReadDatabaseIo { source })?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    let after = file
        .metadata()
        .map_err(|source| AssetStateStoreError::ImmutableReadDatabaseIo { source })?;
    let path_metadata = fs::metadata(database_path)
        .map_err(|source| AssetStateStoreError::ImmutableReadDatabaseIo { source })?;
    if !immutable_database_metadata_matches(&before, &after)
        || !immutable_database_metadata_matches(&after, &path_metadata)
        || immutable_wal_len(database_path)? > 0
    {
        return Err(AssetStateStoreError::ImmutableReadSnapshotChanged);
    }

    Ok(ImmutableReadWitness {
        size_bytes: after.len(),
        modified_unix_nanos: after
            .modified()
            .ok()
            .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_nanos()),
        #[cfg(unix)]
        device: after.dev(),
        #[cfg(unix)]
        inode: after.ino(),
        #[cfg(unix)]
        changed_seconds: after.ctime(),
        #[cfg(unix)]
        changed_nanoseconds: after.ctime_nsec(),
        sha256: format!("{:x}", hasher.finalize()),
    })
}

#[cfg(unix)]
fn load_json_checkpoint_no_follow(path: &Path) -> Result<Option<Manifest>, AssetStateStoreError> {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(AssetStateStoreError::JsonCheckpointIo {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    validate_json_checkpoint_metadata(path, &before)?;
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|source| AssetStateStoreError::JsonCheckpointIo {
            path: path.to_path_buf(),
            source,
        })?;
    let held_before = file
        .metadata()
        .map_err(|source| AssetStateStoreError::JsonCheckpointIo {
            path: path.to_path_buf(),
            source,
        })?;
    validate_json_checkpoint_metadata(path, &held_before)?;
    if !immutable_database_metadata_matches(&before, &held_before) {
        return Err(AssetStateStoreError::JsonCheckpointChanged {
            path: path.to_path_buf(),
        });
    }
    let manifest = match Manifest::load_from_reader(&mut file) {
        Ok(manifest) => manifest,
        Err(ManifestError::Json(_)) => return Ok(None),
        Err(ManifestError::Io(source)) => {
            return Err(AssetStateStoreError::JsonCheckpointIo {
                path: path.to_path_buf(),
                source,
            });
        }
        Err(error) => return Err(AssetStateStoreError::Manifest(error)),
    };
    let held_after = file
        .metadata()
        .map_err(|source| AssetStateStoreError::JsonCheckpointIo {
            path: path.to_path_buf(),
            source,
        })?;
    let path_after =
        fs::symlink_metadata(path).map_err(|source| AssetStateStoreError::JsonCheckpointIo {
            path: path.to_path_buf(),
            source,
        })?;
    validate_json_checkpoint_metadata(path, &held_after)?;
    validate_json_checkpoint_metadata(path, &path_after)?;
    if !immutable_database_metadata_matches(&before, &held_after)
        || !immutable_database_metadata_matches(&held_after, &path_after)
    {
        return Err(AssetStateStoreError::JsonCheckpointChanged {
            path: path.to_path_buf(),
        });
    }
    Ok(Some(manifest))
}

#[cfg(unix)]
fn validate_json_checkpoint_metadata(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), AssetStateStoreError> {
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() || metadata.nlink() != 1
    {
        return Err(AssetStateStoreError::JsonCheckpointUnsafe {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn load_json_checkpoint_no_follow(_path: &Path) -> Result<Option<Manifest>, AssetStateStoreError> {
    Err(AssetStateStoreError::JsonCheckpointUnsupportedPlatform)
}

fn immutable_wal_len(database_path: &Path) -> Result<u64, AssetStateStoreError> {
    match fs::metadata(sqlite_wal_path(database_path)) {
        Ok(metadata) => Ok(metadata.len()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(source) => Err(AssetStateStoreError::ReadOnlyWalMetadata { source }),
    }
}

fn immutable_database_metadata_matches(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    if left.len() != right.len() || left.modified().ok() != right.modified().ok() {
        return false;
    }
    #[cfg(unix)]
    {
        left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        true
    }
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
        manifest.upsert_trusted(record);
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
    #[error(
        "state database at {path} requires explicit schema-only migration; stop all writers and run `icloudpd-optimizer manifest migrate --manifest <PATH> --from 1 --to 2`"
    )]
    MigrationRequired { path: PathBuf },
    #[error(
        "schema-only migration is unsupported on this platform because OS file fencing is unavailable"
    )]
    MigrationUnsupportedPlatform,
    #[error("schema migration only supports from=1 to=2; received from={from} to={to}")]
    InvalidSchemaMigration { from: i32, to: i32 },
    #[error("state database for schema migration does not exist at {path}")]
    MigrationDatabaseMissing { path: PathBuf },
    #[error("state database for schema migration must not be a symbolic link: {path}")]
    MigrationDatabaseSymlink { path: PathBuf },
    #[error("state database for schema migration must be a regular file: {path}")]
    MigrationDatabaseNotFile { path: PathBuf },
    #[error("state database for schema migration must not be hard-linked ({links} links): {path}")]
    MigrationDatabaseHardLink { path: PathBuf, links: u64 },
    #[error("state database identity changed during schema migration verification: {path}")]
    MigrationDatabaseIdentityChanged { path: PathBuf },
    #[error("state database parent directory changed during schema migration: {path}")]
    MigrationDatabaseDirectoryChanged { path: PathBuf },
    #[error("failed to inspect state database for schema migration at {path}: {source}")]
    MigrationDatabaseMetadata { path: PathBuf, source: io::Error },
    #[error(
        "schema-only migration cannot acquire manifest monitor lock at {lock_path}; stop the monitor before migrating"
    )]
    MigrationMonitorLockHeld { lock_path: PathBuf },
    #[error(
        "schema-only migration requires an existing legacy manifest monitor lock at {lock_path}; start and stop the local monitor once before migrating"
    )]
    MigrationMonitorLockMissing { lock_path: PathBuf },
    #[error("schema-only migration monitor lock must not be a symbolic link: {path}")]
    MigrationMonitorLockSymlink { path: PathBuf },
    #[error("schema-only migration monitor lock must be a regular file: {path}")]
    MigrationMonitorLockNotRegular { path: PathBuf },
    #[error("schema-only migration monitor lock must not be hard-linked ({links} links): {path}")]
    MigrationMonitorLockHardLink { path: PathBuf, links: u64 },
    #[error("schema-only migration monitor lock changed after open: {path}")]
    MigrationMonitorLockIdentityChanged { path: PathBuf },
    #[error("failed to use schema-only migration monitor lock {path}: {source}")]
    MigrationMonitorLockIo { path: PathBuf, source: io::Error },
    #[error("schema migration expected schema version {expected}, found {actual}")]
    MigrationSchemaVersion { expected: i32, actual: i32 },
    #[error("schema migration v1 assets table contains no asset rows")]
    MigrationSchemaEmpty,
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
    #[error("state database cannot be opened immutably because its WAL has unapplied changes")]
    ReadOnlyWalPending,
    #[error("failed to inspect state database WAL before immutable read-only open: {source}")]
    ReadOnlyWalMetadata { source: io::Error },
    #[error("state database path cannot be represented as an immutable SQLite URI")]
    ReadOnlyUri,
    #[error("immutable state database read requires an immutable snapshot witness")]
    ImmutableReadWitnessRequired,
    #[error("immutable state database snapshot changed during the read")]
    ImmutableReadSnapshotChanged,
    #[error("JSON checkpoint path is unsafe: {path}")]
    JsonCheckpointUnsafe { path: PathBuf },
    #[error("JSON checkpoint changed while being read: {path}")]
    JsonCheckpointChanged { path: PathBuf },
    #[error("failed to read JSON checkpoint at {path}: {source}")]
    JsonCheckpointIo { path: PathBuf, source: io::Error },
    #[error("JSON checkpoint comparison requires descriptor-safe platform support")]
    JsonCheckpointUnsupportedPlatform,
    #[error("failed to read immutable state database snapshot: {source}")]
    ImmutableReadDatabaseIo { source: io::Error },
    #[error("state database integrity check failed: {result}")]
    IntegrityCheck { result: String },
    #[error("state database columns do not match the stored record for {asset_id}")]
    RecordColumnMismatch { asset_id: String },
    #[error("refusing to overwrite newer durable state for {asset_id}")]
    StaleRecord { asset_id: String },
    #[error("atomic state batch contains duplicate asset ID {asset_id}")]
    DuplicateRecord { asset_id: String },
    #[error(
        "exact-CAS state batch expected asset ID {expected_asset_id} but update was for {updated_asset_id}"
    )]
    ExactCasMismatchedIds {
        expected_asset_id: String,
        updated_asset_id: String,
    },
    #[error("exact-CAS state batch snapshot did not match durable record {asset_id}")]
    ExactCasMismatch { asset_id: String },
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
    use sha2::{Digest, Sha256};
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    use std::sync::mpsc;
    use std::thread;

    fn checkpoint_test_store() -> (tempfile::TempDir, PathBuf, AssetStateStore) {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest_path = tempdir.path().join("manifest.json");
        let writer = AssetStateStore::open_writer(
            &manifest_path,
            "checkpoint-test",
            Duration::from_secs(30),
        )
        .expect("writer");
        writer.load_or_import().expect("import");
        writer
            .persist_record_trusted(&AssetRecord::new("asset", "/nas/asset.dng"))
            .expect("record");
        writer.export_json().expect("checkpoint");
        drop(writer);
        let reader = AssetStateStore::open_immutable_read_only(&manifest_path).expect("reader");
        (tempdir, manifest_path, reader)
    }

    #[test]
    fn json_checkpoint_status_marks_missing_and_malformed_json_stale() {
        let (_tempdir, manifest_path, reader) = checkpoint_test_store();
        assert_eq!(
            reader.json_checkpoint_status().expect("current"),
            JsonCheckpointStatus::Current
        );
        fs::remove_file(&manifest_path).expect("remove checkpoint");
        assert_eq!(
            reader.json_checkpoint_status().expect("missing"),
            JsonCheckpointStatus::Stale
        );
        fs::write(&manifest_path, b"not json").expect("malformed checkpoint");
        assert_eq!(
            reader.json_checkpoint_status().expect("malformed"),
            JsonCheckpointStatus::Stale
        );
    }

    #[cfg(unix)]
    #[test]
    fn json_checkpoint_status_rejects_symlink_nonregular_and_hardlinked_paths() {
        use std::os::unix::fs::symlink;

        let (_tempdir, manifest_path, reader) = checkpoint_test_store();
        let target = manifest_path.with_file_name("target.json");
        fs::write(&target, b"{}").expect("target");
        fs::remove_file(&manifest_path).expect("remove checkpoint");
        symlink(&target, &manifest_path).expect("symlink");
        assert!(matches!(
            reader.json_checkpoint_status(),
            Err(AssetStateStoreError::JsonCheckpointUnsafe { .. })
        ));
        fs::remove_file(&manifest_path).expect("remove symlink");
        fs::create_dir(&manifest_path).expect("directory checkpoint");
        assert!(matches!(
            reader.json_checkpoint_status(),
            Err(AssetStateStoreError::JsonCheckpointUnsafe { .. })
        ));
        fs::remove_dir(&manifest_path).expect("remove directory checkpoint");
        fs::write(&manifest_path, b"{}").expect("replacement checkpoint");
        fs::hard_link(
            &manifest_path,
            manifest_path.with_file_name("manifest-checkpoint-hardlink.json"),
        )
        .expect("hard link checkpoint");
        assert!(matches!(
            reader.json_checkpoint_status(),
            Err(AssetStateStoreError::JsonCheckpointUnsafe { .. })
        ));
    }

    #[cfg(unix)]
    fn create_migratable_v1_database(manifest_path: &Path, record: &AssetRecord) -> String {
        let db_path = AssetStateStore::db_path_for_manifest(manifest_path);
        let record_json = serde_json::to_string(record).expect("encode asset record");
        let connection = Connection::open(&db_path).expect("open v1 state db");
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
        connection
            .execute(
                "INSERT INTO assets (asset_id, state, updated_at, record_json) VALUES (?1, ?2, ?3, ?4)",
                params![
                    record.asset_id,
                    record.state.as_str(),
                    record.updated_at,
                    record_json
                ],
            )
            .expect("insert v1 asset");
        fs::write(
            manifest_path.with_extension("monitor.lock"),
            b"legacy monitor lock\n",
        )
        .expect("create legacy monitor lock");
        record_json
    }

    fn forged_recipe_record(asset_id: &str) -> AssetRecord {
        let mut record = AssetRecord::new(asset_id, format!("/raw/{asset_id}.dng"));
        for proof_name in ["conversion", "conversion_performance", "heic"] {
            record.proofs.insert(
                proof_name.to_string(),
                serde_json::json!({
                    "conversion_recipe_id": "embedded-preview-normalized-v1"
                }),
            );
        }
        record
    }

    fn assert_recipe_claims_are_sanitized(manifest: &Manifest, asset_id: &str) {
        for proof_name in ["conversion", "conversion_performance", "heic"] {
            assert_eq!(
                manifest.get(asset_id).unwrap().proofs[proof_name]["conversion_recipe_id"],
                ""
            );
        }
    }

    #[test]
    fn public_writers_sanitize_forged_recipe_claims() {
        let tempdir = tempfile::tempdir().unwrap();
        let manifest_path = tempdir.path().join("manifest.json");
        let store = AssetStateStore::open_writer(&manifest_path, "writer", Duration::from_secs(30))
            .unwrap();
        store.load_or_import().unwrap();

        let single = forged_recipe_record("single");
        store.persist_record(&single).unwrap();
        assert_recipe_claims_are_sanitized(&store.load().unwrap(), "single");

        let atomic = forged_recipe_record("atomic");
        store.persist_records_atomic([&atomic]).unwrap();
        assert_recipe_claims_are_sanitized(&store.load().unwrap(), "atomic");

        let expected = store.load().unwrap().get("single").unwrap().clone();
        let mut updated = forged_recipe_record("single");
        updated.updated_at = "9999999999.000000000Z".to_string();
        store
            .persist_records_exact_cas_atomic([AssetRecordExactCasUpdate {
                expected: &expected,
                updated: &updated,
            }])
            .unwrap();
        assert_recipe_claims_are_sanitized(&store.load().unwrap(), "single");

        let mut manifest = Manifest::new();
        manifest.upsert_trusted(forged_recipe_record("manifest"));
        store.persist_manifest_records(&manifest).unwrap();
        assert_recipe_claims_are_sanitized(&store.load().unwrap(), "manifest");
    }

    #[test]
    fn trusted_writer_preserves_current_recipe_claims_for_reloaded_state() {
        let tempdir = tempfile::tempdir().unwrap();
        let manifest_path = tempdir.path().join("manifest.json");
        let store = AssetStateStore::open_writer(&manifest_path, "writer", Duration::from_secs(30))
            .unwrap();
        store.load_or_import().unwrap();

        let trusted = forged_recipe_record("trusted");
        store.persist_record_trusted(&trusted).unwrap();
        for proof_name in ["conversion", "conversion_performance", "heic"] {
            assert_eq!(
                store.load().unwrap().get("trusted").unwrap().proofs[proof_name]["conversion_recipe_id"],
                "embedded-preview-normalized-v1"
            );
        }
    }

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

    #[cfg(unix)]
    #[test]
    fn schema_only_migration_rolls_back_when_the_locked_path_is_replaced_before_commit() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest_path = tempdir.path().join("manifest.json");
        let record = AssetRecord::new("asset-1", "/photos/asset-1.dng");
        let record_json = create_migratable_v1_database(&manifest_path, &record);
        let db_path = AssetStateStore::db_path_for_manifest(&manifest_path);
        let lock_path = manifest_path.with_extension("monitor.lock");
        let moved_lock_path = tempdir.path().join("moved-monitor.lock");
        let digest_before = format!("{:x}", Sha256::digest(record_json.as_bytes()));

        set_migration_precommit_hook_for_current_thread(move || {
            fs::rename(&lock_path, &moved_lock_path).expect("move held lock path");
            fs::write(&lock_path, b"replacement monitor lock\n").expect("replace lock path");
        });
        let error = AssetStateStore::migrate_schema_only(&manifest_path, 1, 2)
            .expect_err("replaced lock path must roll back before commit");

        assert!(matches!(
            error,
            AssetStateStoreError::MigrationMonitorLockIdentityChanged { .. }
        ));
        let connection = Connection::open(db_path).expect("reopen rolled-back state db");
        let version: i32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read rolled-back schema version");
        assert_eq!(version, 1);
        let durable_json: String = connection
            .query_row(
                "SELECT record_json FROM assets WHERE asset_id = 'asset-1'",
                [],
                |row| row.get(0),
            )
            .expect("read rolled-back asset record");
        assert_eq!(
            format!("{:x}", Sha256::digest(durable_json.as_bytes())),
            digest_before
        );
    }

    #[cfg(unix)]
    #[test]
    fn schema_only_migration_detects_database_path_aba_and_preserves_database_identity() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest_path = tempdir.path().join("manifest.json");
        let record = AssetRecord::new("asset-1", "/photos/asset-1.dng");
        let record_json = create_migratable_v1_database(&manifest_path, &record);
        let db_path = AssetStateStore::db_path_for_manifest(&manifest_path);
        let canonical_path = fs::canonicalize(&db_path).expect("canonicalize database");
        let metadata = fs::metadata(&canonical_path).expect("inspect database");
        let mut hasher = Sha256::new();
        hasher.update(canonical_path.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(metadata.dev().to_le_bytes());
        hasher.update(metadata.ino().to_le_bytes());
        let expected_database_id = format!("sha256:{:x}", hasher.finalize());
        let moved_db_path = tempdir.path().join("moved-state.sqlite3");
        let digest_before = format!("{:x}", Sha256::digest(record_json.as_bytes()));
        let db_path_for_hook = db_path.clone();

        set_migration_precommit_hook_for_current_thread(move || {
            fs::rename(&db_path_for_hook, &moved_db_path).expect("move verified database path");
            fs::rename(&moved_db_path, &db_path_for_hook).expect("restore verified database path");
        });
        let error = AssetStateStore::migrate_schema_only(&manifest_path, 1, 2)
            .expect_err("database path ABA must roll back before commit");

        assert!(matches!(
            error,
            AssetStateStoreError::MigrationDatabaseDirectoryChanged { .. }
        ));
        let connection = Connection::open(&db_path).expect("reopen rolled-back state db");
        let version: i32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read rolled-back schema version");
        assert_eq!(version, 1);
        let durable_json: String = connection
            .query_row(
                "SELECT record_json FROM assets WHERE asset_id = 'asset-1'",
                [],
                |row| row.get(0),
            )
            .expect("read rolled-back asset record");
        assert_eq!(
            format!("{:x}", Sha256::digest(durable_json.as_bytes())),
            digest_before
        );
        drop(connection);

        let summary = AssetStateStore::migrate_schema_only(&manifest_path, 1, 2)
            .expect("restored verified path should migrate normally");
        assert_eq!(summary.database_id, expected_database_id);
    }

    #[test]
    fn schema_only_migration_integrity_failure_after_ddl_rolls_back_every_change() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest_path = tempdir.path().join("manifest.json");
        let db_path = AssetStateStore::db_path_for_manifest(&manifest_path);
        let record = AssetRecord::new("asset-1", "/photos/asset-1.dng");
        let record_json = serde_json::to_string(&record).expect("encode asset record");
        let asset_digest_before = format!("{:x}", Sha256::digest(record_json.as_bytes()));
        let connection = Connection::open(&db_path).expect("open v1 state db");
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
        connection
            .execute(
                "INSERT INTO assets (asset_id, state, updated_at, record_json) VALUES (?1, ?2, ?3, ?4)",
                params![
                    record.asset_id,
                    record.state.as_str(),
                    record.updated_at,
                    record_json
                ],
            )
            .expect("insert v1 asset");
        fs::write(
            manifest_path.with_extension("monitor.lock"),
            b"legacy monitor lock\n",
        )
        .expect("create legacy monitor lock");

        fail_next_integrity_check_for_current_thread();
        let error = AssetStateStore::migrate_schema_only(&manifest_path, 1, 2)
            .expect_err("post-DDL integrity failure must roll back the migration");
        assert!(
            matches!(error, AssetStateStoreError::IntegrityCheck { .. }),
            "expected post-DDL integrity failure, got {error:?}"
        );

        let connection = Connection::open(db_path).expect("reopen rolled-back state db");
        let version: i32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .expect("read rolled-back schema version");
        assert_eq!(version, 1);
        let objects = connection
            .prepare(
                "SELECT type, name FROM sqlite_master
                 WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
            )
            .expect("prepare schema object query")
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .expect("query schema objects")
            .collect::<Result<Vec<_>, _>>()
            .expect("read schema objects");
        assert_eq!(
            objects,
            vec![
                ("index".to_string(), "assets_state_index".to_string()),
                ("table".to_string(), "assets".to_string()),
            ]
        );
        let durable_json: String = connection
            .query_row(
                "SELECT record_json FROM assets WHERE asset_id = 'asset-1'",
                [],
                |row| row.get(0),
            )
            .expect("read rolled-back asset record");
        assert_eq!(durable_json, record_json);
        assert_eq!(
            format!("{:x}", Sha256::digest(durable_json.as_bytes())),
            asset_digest_before
        );
    }

    #[test]
    fn exact_cas_batch_rolls_back_when_a_same_or_earlier_timestamp_record_changes() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest_path = tempdir.path().join("manifest.json");
        let store =
            AssetStateStore::open_writer(&manifest_path, "cas-writer", Duration::from_secs(30))
                .expect("state store should open");
        store
            .load_or_import()
            .expect("empty manifest should import");

        let mut first = AssetRecord::new("asset-first", "/nas/first.dng");
        first.updated_at = "100.000000000Z".to_string();
        let mut second = AssetRecord::new("asset-second", "/nas/second.dng");
        second.updated_at = "100.000000000Z".to_string();
        store
            .persist_records_atomic([&first, &second])
            .expect("initial records should persist");
        let expected_first = first.clone();
        let expected_second = second.clone();
        first.updated_at = "200.000000000Z".to_string();
        second.updated_at = "200.000000000Z".to_string();

        let mut out_of_band = expected_second.clone();
        out_of_band.raw_path = PathBuf::from("/secret/out-of-band.dng");
        out_of_band.updated_at = "099.000000000Z".to_string();
        let out_of_band_json = serde_json::to_string(&out_of_band).expect("record should encode");
        let connection = Connection::open(AssetStateStore::db_path_for_manifest(&manifest_path))
            .expect("out-of-band connection should open");
        connection
            .execute(
                "UPDATE assets SET state = ?1, updated_at = ?2, record_json = ?3 WHERE asset_id = ?4",
                params![
                    out_of_band.state.as_str(),
                    out_of_band.updated_at,
                    out_of_band_json,
                    out_of_band.asset_id,
                ],
            )
            .expect("out-of-band mutation should commit");
        drop(connection);

        let error = store
            .persist_records_exact_cas_atomic([
                AssetRecordExactCasUpdate {
                    expected: &expected_first,
                    updated: &first,
                },
                AssetRecordExactCasUpdate {
                    expected: &expected_second,
                    updated: &second,
                },
            ])
            .expect_err("any exact-CAS mismatch must roll back the whole batch");
        assert!(matches!(
            error,
            AssetStateStoreError::ExactCasMismatch { .. }
        ));

        let persisted = store.load().expect("persisted state should load");
        assert_eq!(
            persisted
                .get("asset-first")
                .expect("first record should exist"),
            &expected_first,
            "earlier out-of-band mutation must prevent a partial first-record write"
        );
        assert_eq!(
            persisted
                .get("asset-second")
                .expect("second record should exist"),
            &out_of_band,
            "exact CAS must reject an out-of-band change regardless of timestamp"
        );
    }

    #[test]
    fn exact_cas_batch_rejects_mismatched_and_duplicate_asset_ids() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest_path = tempdir.path().join("manifest.json");
        let store =
            AssetStateStore::open_writer(&manifest_path, "cas-writer", Duration::from_secs(30))
                .expect("state store should open");
        store
            .load_or_import()
            .expect("empty manifest should import");
        let first = AssetRecord::new("asset-first", "/nas/first.dng");
        let second = AssetRecord::new("asset-second", "/nas/second.dng");

        let mismatched = store
            .persist_records_exact_cas_atomic([AssetRecordExactCasUpdate {
                expected: &first,
                updated: &second,
            }])
            .expect_err("exact CAS must bind the expected and updated asset IDs");
        assert!(matches!(
            mismatched,
            AssetStateStoreError::ExactCasMismatchedIds { .. }
        ));

        let duplicate = store
            .persist_records_exact_cas_atomic([
                AssetRecordExactCasUpdate {
                    expected: &first,
                    updated: &first,
                },
                AssetRecordExactCasUpdate {
                    expected: &first,
                    updated: &first,
                },
            ])
            .expect_err("exact CAS must reject duplicate updates");
        assert!(matches!(
            duplicate,
            AssetStateStoreError::DuplicateRecord { .. }
        ));
    }

    #[test]
    fn exact_cas_batch_rejects_an_out_of_band_same_timestamp_change() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest_path = tempdir.path().join("manifest.json");
        let store =
            AssetStateStore::open_writer(&manifest_path, "cas-writer", Duration::from_secs(30))
                .expect("state store should open");
        store
            .load_or_import()
            .expect("empty manifest should import");
        let mut expected = AssetRecord::new("asset", "/nas/original.dng");
        expected.updated_at = "100.000000000Z".to_string();
        store
            .persist_record(&expected)
            .expect("initial record should persist");
        let mut updated = expected.clone();
        updated.updated_at = "200.000000000Z".to_string();

        let mut out_of_band = expected.clone();
        out_of_band.raw_path = PathBuf::from("/secret/same-timestamp.dng");
        let connection = Connection::open(AssetStateStore::db_path_for_manifest(&manifest_path))
            .expect("out-of-band connection should open");
        connection
            .execute(
                "UPDATE assets SET state = ?1, updated_at = ?2, record_json = ?3 WHERE asset_id = ?4",
                params![
                    out_of_band.state.as_str(),
                    out_of_band.updated_at,
                    serde_json::to_string(&out_of_band).expect("record should encode"),
                    out_of_band.asset_id,
                ],
        )
        .expect("out-of-band mutation should commit");
        drop(connection);

        let error = store
            .persist_records_exact_cas_atomic([AssetRecordExactCasUpdate {
                expected: &expected,
                updated: &updated,
            }])
            .expect_err("exact CAS must reject same-timestamp JSON changes");
        assert!(matches!(
            error,
            AssetStateStoreError::ExactCasMismatch { .. }
        ));
    }

    #[test]
    fn normal_read_only_observes_wal_while_immutable_read_fails_closed() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest_path = tempdir.path().join("manifest.json");
        let writer =
            AssetStateStore::open_writer(&manifest_path, "wal-writer", Duration::from_secs(30))
                .expect("state store should open");
        writer
            .load_or_import()
            .expect("empty manifest should import");

        let db_path = AssetStateStore::db_path_for_manifest(&manifest_path);
        let connection = Connection::open(&db_path).expect("WAL connection should open");
        connection
            .pragma_update(None, "wal_autocheckpoint", 0)
            .expect("automatic checkpointing should disable");
        let record = AssetRecord::new("wal-asset", "/nas/wal-asset.dng");
        let record_json = encode_record(&record).expect("record should encode");
        connection
            .execute(
                "INSERT INTO assets (asset_id, state, updated_at, record_json) VALUES (?1, ?2, ?3, ?4)",
                params![
                    &record.asset_id,
                    record.state.as_str(),
                    &record.updated_at,
                    record_json,
                ],
            )
            .expect("WAL record should commit");
        assert!(
            fs::metadata(sqlite_wal_path(&db_path))
                .expect("WAL should exist")
                .len()
                > 0
        );

        let read_only = AssetStateStore::open_read_only(&manifest_path)
            .expect("normal read-only access should follow the WAL");
        assert!(read_only.load().unwrap().get("wal-asset").is_ok());
        assert!(matches!(
            AssetStateStore::open_immutable_read_only(&manifest_path),
            Err(AssetStateStoreError::ReadOnlyWalPending)
        ));
    }

    #[test]
    fn exact_cas_rejects_indexed_columns_that_diverge_from_record_json() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest_path = tempdir.path().join("manifest.json");
        let store =
            AssetStateStore::open_writer(&manifest_path, "cas-writer", Duration::from_secs(30))
                .expect("state store should open");
        store
            .load_or_import()
            .expect("empty manifest should import");
        let expected = AssetRecord::new("asset", "/nas/original.dng");
        store
            .persist_record(&expected)
            .expect("initial record should persist");
        let mut updated = expected.clone();
        updated.updated_at = "999.000000000Z".to_string();

        let connection = Connection::open(AssetStateStore::db_path_for_manifest(&manifest_path))
            .expect("out-of-band connection should open");
        connection
            .execute(
                "UPDATE assets SET state = 'failed' WHERE asset_id = ?1",
                [&expected.asset_id],
            )
            .expect("indexed state should diverge");

        assert!(matches!(
            store.persist_records_exact_cas_atomic([AssetRecordExactCasUpdate {
                expected: &expected,
                updated: &updated,
            }]),
            Err(AssetStateStoreError::ExactCasMismatch { .. })
        ));
    }

    #[test]
    fn immutable_snapshot_witness_detects_a_writer_after_open() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest_path = tempdir.path().join("manifest.json");
        let writer =
            AssetStateStore::open_writer(&manifest_path, "snapshot-setup", Duration::from_secs(30))
                .expect("state store should open");
        writer
            .load_or_import()
            .expect("empty manifest should import");
        drop(writer);

        let immutable = AssetStateStore::open_immutable_read_only(&manifest_path)
            .expect("quiescent database should open immutably");
        let record = AssetRecord::new("late-writer", "/nas/late-writer.dng");
        let record_json = encode_record(&record).expect("record should encode");
        let connection = Connection::open(AssetStateStore::db_path_for_manifest(&manifest_path))
            .expect("late writer should open");
        connection
            .execute(
                "INSERT INTO assets (asset_id, state, updated_at, record_json) VALUES (?1, ?2, ?3, ?4)",
                params![
                    &record.asset_id,
                    record.state.as_str(),
                    &record.updated_at,
                    record_json,
                ],
            )
            .expect("late writer should commit");

        assert!(matches!(
            immutable.revalidate_immutable_read_snapshot(),
            Err(AssetStateStoreError::ReadOnlyWalPending)
                | Err(AssetStateStoreError::ImmutableReadSnapshotChanged)
        ));
    }
}

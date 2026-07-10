use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use thiserror::Error;

use crate::manifest::{AssetRecord, Manifest, ManifestError};

const SCHEMA_VERSION: i32 = 1;
const BUSY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct AssetStateStore {
    manifest_path: PathBuf,
    db_path: PathBuf,
}

impl AssetStateStore {
    pub fn db_path_for_manifest(manifest_path: impl AsRef<Path>) -> PathBuf {
        manifest_path.as_ref().with_extension("state.sqlite3")
    }

    pub fn open(manifest_path: impl AsRef<Path>) -> Result<Self, AssetStateStoreError> {
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

        let store = Self {
            manifest_path,
            db_path,
        };
        let connection = store.connect()?;
        store.initialize(&connection)?;
        store.verify_integrity(&connection)?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.db_path
    }

    pub fn load_or_import(&self) -> Result<Manifest, AssetStateStoreError> {
        let json_manifest = self.load_json_manifest()?;
        self.merge_manifest_records(&json_manifest)?;
        self.load()
    }

    pub fn load(&self) -> Result<Manifest, AssetStateStoreError> {
        self.load_database_manifest()
    }

    pub fn persist_record(&self, record: &AssetRecord) -> Result<Duration, AssetStateStoreError> {
        let started = Instant::now();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = upsert_record(&transaction, record)?;
        reject_stale_record(&transaction, record, changed)?;
        transaction.commit()?;
        Ok(started.elapsed())
    }

    pub fn persist_records_atomic<'a>(
        &self,
        records: impl IntoIterator<Item = &'a AssetRecord>,
    ) -> Result<Duration, AssetStateStoreError> {
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

        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
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

    pub fn persist_manifest_records(
        &self,
        manifest: &Manifest,
    ) -> Result<(), AssetStateStoreError> {
        if manifest.records().is_empty() {
            return Ok(());
        }

        let prepared = manifest
            .records()
            .values()
            .map(|record| Ok((record, encode_record(record)?)))
            .collect::<Result<Vec<_>, AssetStateStoreError>>()?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
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

    pub fn export_json(&self) -> Result<Manifest, AssetStateStoreError> {
        let manifest = self.load_database_manifest()?;
        manifest.save_atomic(&self.manifest_path)?;
        Ok(manifest)
    }

    fn connect(&self) -> Result<Connection, AssetStateStoreError> {
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

    fn merge_manifest_records(&self, manifest: &Manifest) -> Result<(), AssetStateStoreError> {
        if manifest.records().is_empty() {
            return Ok(());
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        for record in manifest.records().values() {
            upsert_record(&transaction, record)?;
        }
        transaction.commit()?;
        Ok(())
    }

    fn initialize(&self, connection: &Connection) -> Result<(), AssetStateStoreError> {
        let schema_version: i32 =
            connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        let user_table_count: i64 = connection.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;

        if schema_version == 0 && user_table_count == 0 {
            let journal_mode: String =
                connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
            if !journal_mode.eq_ignore_ascii_case("wal") {
                let enabled: String =
                    connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
                if !enabled.eq_ignore_ascii_case("wal") {
                    return Err(AssetStateStoreError::WalUnavailable { mode: enabled });
                }
            }
            connection.execute_batch(
                "BEGIN IMMEDIATE;
                 CREATE TABLE assets (
                   asset_id TEXT PRIMARY KEY NOT NULL,
                   state TEXT NOT NULL,
                   updated_at TEXT NOT NULL,
                   record_json TEXT NOT NULL
                 );
                 CREATE INDEX assets_state_index ON assets(state);
                 PRAGMA user_version = 1;
                 COMMIT;",
            )?;
            return Ok(());
        }

        if schema_version != SCHEMA_VERSION {
            return Err(AssetStateStoreError::UnsupportedSchema {
                expected: SCHEMA_VERSION,
                actual: schema_version,
            });
        }
        if user_table_count == 0 {
            return Err(AssetStateStoreError::MissingSchema);
        }
        let journal_mode: String =
            connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(AssetStateStoreError::WalUnavailable { mode: journal_mode });
        }
        Ok(())
    }

    fn verify_integrity(&self, connection: &Connection) -> Result<(), AssetStateStoreError> {
        let result: String = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
        if result != "ok" {
            return Err(AssetStateStoreError::IntegrityCheck { result });
        }
        Ok(())
    }

    fn load_json_manifest(&self) -> Result<Manifest, AssetStateStoreError> {
        match Manifest::load(&self.manifest_path) {
            Ok(manifest) => Ok(manifest),
            Err(ManifestError::Io(source)) if source.kind() == io::ErrorKind::NotFound => {
                Ok(Manifest::new())
            }
            Err(source) => Err(AssetStateStoreError::Manifest(source)),
        }
    }

    fn load_database_manifest(&self) -> Result<Manifest, AssetStateStoreError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT asset_id, state, updated_at, record_json FROM assets ORDER BY asset_id",
        )?;
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
    #[error("state database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("manifest error: {0}")]
    Manifest(#[from] ManifestError),
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
}

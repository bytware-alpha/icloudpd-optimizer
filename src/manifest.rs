use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Discovered,
    NasVerified,
    Converted,
    ConversionVerified,
    UploadVerified,
    DeleteEligible,
    DeleteApproved,
    Deleted,
    Failed,
}

impl State {
    fn allows(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Discovered, Self::NasVerified)
                | (Self::NasVerified, Self::Converted)
                | (Self::Converted, Self::ConversionVerified)
                | (Self::ConversionVerified, Self::UploadVerified)
                | (Self::UploadVerified, Self::DeleteEligible)
                | (Self::DeleteEligible, Self::DeleteApproved)
                | (Self::DeleteApproved, Self::Deleted)
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::NasVerified => "nas_verified",
            Self::Converted => "converted",
            Self::ConversionVerified => "conversion_verified",
            Self::UploadVerified => "upload_verified",
            Self::DeleteEligible => "delete_eligible",
            Self::DeleteApproved => "delete_approved",
            Self::Deleted => "deleted",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FailureRecord {
    pub stage: String,
    pub message: String,
    pub recorded_at: String,
}

impl FailureRecord {
    pub fn new(stage: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            stage: stage.into(),
            message: message.into(),
            recorded_at: current_timestamp(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AssetRecord {
    pub asset_id: String,
    pub raw_path: PathBuf,
    pub state: State,
    pub proofs: BTreeMap<String, Value>,
    pub failures: Vec<FailureRecord>,
    pub updated_at: String,
}

impl AssetRecord {
    pub fn new(asset_id: impl Into<String>, raw_path: impl Into<PathBuf>) -> Self {
        Self {
            asset_id: asset_id.into(),
            raw_path: raw_path.into(),
            state: State::Discovered,
            proofs: BTreeMap::new(),
            failures: Vec::new(),
            updated_at: current_timestamp(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Manifest {
    records: BTreeMap<String, AssetRecord>,
}

impl Manifest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert(&mut self, record: AssetRecord) {
        self.records.insert(record.asset_id.clone(), record);
    }

    pub fn get(&self, asset_id: &str) -> Result<&AssetRecord, ManifestError> {
        self.records
            .get(asset_id)
            .ok_or_else(|| ManifestError::UnknownAsset {
                asset_id: asset_id.to_string(),
            })
    }

    pub fn records(&self) -> &BTreeMap<String, AssetRecord> {
        &self.records
    }

    pub fn transition(
        &mut self,
        asset_id: &str,
        new_state: State,
        proof_name: impl Into<String>,
        proof: Value,
    ) -> Result<&AssetRecord, ManifestError> {
        let current_state = self.get(asset_id)?.state;
        if !current_state.allows(new_state) {
            return Err(ManifestError::InvalidTransition {
                asset_id: asset_id.to_string(),
                from: current_state,
                to: new_state,
            });
        }

        let updated_at = current_timestamp();
        let record = self
            .records
            .get_mut(asset_id)
            .ok_or_else(|| ManifestError::UnknownAsset {
                asset_id: asset_id.to_string(),
            })?;
        record.state = new_state;
        record.proofs.insert(proof_name.into(), proof);
        record.updated_at = updated_at;
        Ok(record)
    }

    pub fn record_failure(
        &mut self,
        asset_id: &str,
        stage: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<&AssetRecord, ManifestError> {
        let recorded_at = current_timestamp();
        let record = self
            .records
            .get_mut(asset_id)
            .ok_or_else(|| ManifestError::UnknownAsset {
                asset_id: asset_id.to_string(),
            })?;

        record.state = State::Failed;
        record.failures.push(FailureRecord {
            stage: stage.into(),
            message: message.into(),
            recorded_at: recorded_at.clone(),
        });
        record.updated_at = recorded_at;
        Ok(record)
    }

    pub(crate) fn record_proof(
        &mut self,
        asset_id: &str,
        proof_name: impl Into<String>,
        proof: Value,
    ) -> Result<&AssetRecord, ManifestError> {
        let updated_at = current_timestamp();
        let record = self
            .records
            .get_mut(asset_id)
            .ok_or_else(|| ManifestError::UnknownAsset {
                asset_id: asset_id.to_string(),
            })?;
        record.proofs.insert(proof_name.into(), proof);
        record.updated_at = updated_at;
        Ok(record)
    }

    pub fn save_atomic(&self, path: impl AsRef<Path>) -> Result<(), ManifestError> {
        let destination = path.as_ref();
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;

        let (temp_path, mut temp_file) = create_temp_file(parent, destination)?;
        let payload = ManifestFile {
            records: self.records.values().cloned().collect(),
        };

        let write_result = (|| -> Result<(), ManifestError> {
            serde_json::to_writer_pretty(&mut temp_file, &payload)?;
            writeln!(temp_file)?;
            temp_file.sync_all()?;
            Ok(())
        })();

        if let Err(error) = write_result {
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }

        drop(temp_file);
        if let Err(error) = fs::rename(&temp_path, destination) {
            let _ = fs::remove_file(&temp_path);
            return Err(ManifestError::Io(error));
        }
        sync_parent_directory(parent)?;

        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ManifestError> {
        let file = File::open(path)?;
        let payload: ManifestFile = serde_json::from_reader(file)?;
        let mut manifest = Self::new();
        for record in payload.records {
            manifest.upsert(record);
        }
        Ok(manifest)
    }
}

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("Unknown manifest asset: {asset_id}")]
    UnknownAsset { asset_id: String },
    #[error("Invalid manifest transition for {asset_id}: {from} -> {to}")]
    InvalidTransition {
        asset_id: String,
        from: State,
        to: State,
    },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Deserialize, Serialize)]
struct ManifestFile {
    records: Vec<AssetRecord>,
}

fn create_temp_file(parent: &Path, destination: &Path) -> Result<(PathBuf, File), std::io::Error> {
    let filename = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("manifest.json");
    let process_id = std::process::id();
    let timestamp = timestamp_nanos();

    for attempt in 0..100_u32 {
        let temp_path = parent.join(format!(
            ".{filename}.{process_id}.{timestamp}.{attempt}.tmp"
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => return Ok((temp_path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not create a unique manifest temp file",
    ))
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<(), std::io::Error> {
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

fn current_timestamp() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:09}Z", duration.as_secs(), duration.subsec_nanos())
}

fn timestamp_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

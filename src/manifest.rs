use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::legacy_upload_migration::{
    LegacyUploadMigrationManifestRecordAuthority, LegacyUploadMigrationManifestRegistryAuthority,
    LegacyUploadMigrationRegistry, validate_legacy_upload_migration_registry_binding,
};
use crate::state_store::{StateStoreManifestExportAuthority, StateStoreManifestRecordAuthority};

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
    NoAction,
    NeedsReview,
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
            Self::NoAction => "no_action",
            Self::NeedsReview => "needs_review",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Deleted | Self::NoAction | Self::NeedsReview)
    }
}

impl fmt::Display for State {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FailureRecord {
    pub stage: String,
    pub message: String,
    pub recorded_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<FailureKind>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    HeicVisualContent,
    HeicVisualMatch,
    HeicReferenceOrientationInvalid,
    HeicFinalOrientationRotationInvalid,
    HeicDimensionMismatch,
    ConversionTimedOut,
    RawStagingTimedOut,
    ConversionOutputUnreadable,
    ConversionOutputAlreadyExists,
    StagedRawAlreadyExists,
    ConversionMetadataFailed,
    ConversionToolUnavailable,
    EmbeddedPreviewUnavailable,
    AdjustedSourceResolveFailed,
}

impl FailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HeicVisualContent => "heic_visual_content",
            Self::HeicVisualMatch => "heic_visual_match",
            Self::HeicReferenceOrientationInvalid => "heic_reference_orientation_invalid",
            Self::HeicFinalOrientationRotationInvalid => "heic_final_orientation_rotation_invalid",
            Self::HeicDimensionMismatch => "heic_dimension_mismatch",
            Self::ConversionTimedOut => "conversion_timed_out",
            Self::RawStagingTimedOut => "raw_staging_timed_out",
            Self::ConversionOutputUnreadable => "conversion_output_unreadable",
            Self::ConversionOutputAlreadyExists => "conversion_output_already_exists",
            Self::StagedRawAlreadyExists => "staged_raw_already_exists",
            Self::ConversionMetadataFailed => "conversion_metadata_failed",
            Self::ConversionToolUnavailable => "conversion_tool_unavailable",
            Self::EmbeddedPreviewUnavailable => "embedded_preview_unavailable",
            Self::AdjustedSourceResolveFailed => "adjusted_source_resolve_failed",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "heic_visual_content" => Some(Self::HeicVisualContent),
            "heic_visual_match" => Some(Self::HeicVisualMatch),
            "heic_reference_orientation_invalid" => Some(Self::HeicReferenceOrientationInvalid),
            "heic_final_orientation_rotation_invalid" => {
                Some(Self::HeicFinalOrientationRotationInvalid)
            }
            "heic_dimension_mismatch" => Some(Self::HeicDimensionMismatch),
            "conversion_timed_out" => Some(Self::ConversionTimedOut),
            "raw_staging_timed_out" => Some(Self::RawStagingTimedOut),
            "conversion_output_unreadable" => Some(Self::ConversionOutputUnreadable),
            "conversion_output_already_exists" => Some(Self::ConversionOutputAlreadyExists),
            "staged_raw_already_exists" => Some(Self::StagedRawAlreadyExists),
            "conversion_metadata_failed" => Some(Self::ConversionMetadataFailed),
            "conversion_tool_unavailable" => Some(Self::ConversionToolUnavailable),
            "embedded_preview_unavailable" => Some(Self::EmbeddedPreviewUnavailable),
            "adjusted_source_resolve_failed" => Some(Self::AdjustedSourceResolveFailed),
            _ => None,
        }
    }
}

pub const FAILURE_QUARANTINE_PROOF_NAME: &str = "failure_quarantine";
pub const FAILURE_QUARANTINE_SCHEMA_VERSION: u64 = 1;
pub(crate) const INTERNAL_LEGACY_UPLOAD_MIGRATION_PROOF_NAME: &str = "legacy_upload_migration";
const HISTORICAL_REMOTE_SIDE_EFFECT_REASON_CODE: &str = "historical_remote_side_effect";

#[derive(Clone, Debug, Serialize)]
pub struct FailureQuarantineProof {
    schema_version: u64,
    reason_code: &'static str,
    evidence_sha256: String,
    target_set_sha256: String,
    successful_uploads: u64,
    delete_attempts: u64,
    deleted_finishes: u64,
    mirror_successes: u64,
    applied_at_unix_seconds: u64,
}

impl FailureQuarantineProof {
    pub fn historical_remote_side_effect(
        evidence_sha256: impl Into<String>,
        target_set_sha256: impl Into<String>,
        successful_uploads: u64,
        delete_attempts: u64,
        deleted_finishes: u64,
        mirror_successes: u64,
        applied_at_unix_seconds: u64,
    ) -> Self {
        Self {
            schema_version: FAILURE_QUARANTINE_SCHEMA_VERSION,
            reason_code: HISTORICAL_REMOTE_SIDE_EFFECT_REASON_CODE,
            evidence_sha256: evidence_sha256.into(),
            target_set_sha256: target_set_sha256.into(),
            successful_uploads,
            delete_attempts,
            deleted_finishes,
            mirror_successes,
            applied_at_unix_seconds,
        }
    }
}

impl FailureRecord {
    pub fn new(stage: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            stage: stage.into(),
            message: message.into(),
            recorded_at: current_timestamp(),
            kind: None,
        }
    }

    pub fn new_with_kind(
        stage: impl Into<String>,
        message: impl Into<String>,
        kind: FailureKind,
    ) -> Self {
        Self {
            stage: stage.into(),
            message: message.into(),
            recorded_at: current_timestamp(),
            kind: Some(kind),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
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
    legacy_upload_migration_registry: Option<LegacyUploadMigrationRegistry>,
}

struct CheckpointManifestRecordAuthority {
    asset_id: String,
    record_sha256: String,
}

impl CheckpointManifestRecordAuthority {
    fn for_record(record: &AssetRecord) -> Result<Self, ManifestError> {
        Ok(Self {
            asset_id: record.asset_id.clone(),
            record_sha256: asset_record_sha256(record)?,
        })
    }

    fn authorizes(&self, record: &AssetRecord) -> bool {
        self.asset_id == record.asset_id
            && asset_record_sha256(record).is_ok_and(|digest| digest == self.record_sha256)
    }
}

impl Manifest {
    pub fn new() -> Self {
        Self::default()
    }

    /// Accepts untrusted in-memory records and removes recipe claims before storage.
    /// Reserved migration records fail closed before mutation.
    #[track_caller]
    pub fn upsert(&mut self, mut record: AssetRecord) {
        if let Err(error) = self.reject_reserved_internal_proof_upsert(&record) {
            panic!("{error}");
        }
        sanitize_untrusted_recipe_claims(&mut record);
        self.records.insert(record.asset_id.clone(), record);
    }

    #[track_caller]
    pub(crate) fn upsert_trusted(&mut self, record: AssetRecord) {
        if let Err(error) = self.reject_reserved_internal_proof_upsert(&record) {
            panic!("{error}");
        }
        self.records.insert(record.asset_id.clone(), record);
    }

    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "used by the forthcoming in-module orchestrator")
    )]
    pub(crate) fn upsert_legacy_upload_migration_record(
        &mut self,
        authority: &LegacyUploadMigrationManifestRecordAuthority,
        record: AssetRecord,
    ) -> Result<(), ManifestError> {
        if !authority.authorizes(&record) {
            return Err(ManifestError::ReservedInternalProofCapabilityMismatch);
        }
        self.records.insert(record.asset_id.clone(), record);
        Ok(())
    }

    pub(crate) fn upsert_state_store_record(
        &mut self,
        authority: &StateStoreManifestRecordAuthority,
        record: AssetRecord,
    ) -> Result<(), ManifestError> {
        if !authority.authorizes(&record) {
            return Err(ManifestError::ReservedInternalProofCapabilityMismatch);
        }
        self.records.insert(record.asset_id.clone(), record);
        Ok(())
    }

    fn upsert_checkpoint_record(
        &mut self,
        authority: &CheckpointManifestRecordAuthority,
        record: AssetRecord,
    ) -> Result<(), ManifestError> {
        if !authority.authorizes(&record) {
            return Err(ManifestError::ReservedInternalProofCapabilityMismatch);
        }
        self.records.insert(record.asset_id.clone(), record);
        Ok(())
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

    #[cfg(test)]
    pub(crate) fn replace_record_unchecked_for_tamper_test(&mut self, record: AssetRecord) {
        self.records.insert(record.asset_id.clone(), record);
    }

    pub(crate) fn legacy_upload_migration_registry(
        &self,
    ) -> Option<&LegacyUploadMigrationRegistry> {
        self.legacy_upload_migration_registry.as_ref()
    }

    pub(crate) fn install_legacy_upload_migration_registry(
        &mut self,
        authority: &LegacyUploadMigrationManifestRegistryAuthority,
        registry: LegacyUploadMigrationRegistry,
    ) -> Result<(), ManifestError> {
        if !authority.authorizes(&registry)
            || self
                .legacy_upload_migration_registry
                .as_ref()
                .is_some_and(|persisted| persisted != &registry)
        {
            return Err(ManifestError::ReservedInternalProofCapabilityMismatch);
        }
        self.legacy_upload_migration_registry = Some(registry);
        Ok(())
    }

    pub fn snapshot_record(&self, asset_id: &str) -> Result<Self, ManifestError> {
        let record = self.get(asset_id)?;
        reject_reserved_internal_proof(record)?;
        let mut snapshot = Self::new();
        snapshot.upsert_trusted(record.clone());
        Ok(snapshot)
    }

    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "used by the forthcoming in-module orchestrator")
    )]
    pub(crate) fn snapshot_legacy_upload_migration_record(
        &self,
        authority: &LegacyUploadMigrationManifestRecordAuthority,
        asset_id: &str,
    ) -> Result<Self, ManifestError> {
        let record = self.get(asset_id)?;
        if !authority.authorizes(record) {
            return Err(ManifestError::ReservedInternalProofCapabilityMismatch);
        }
        let mut snapshot = Self::new();
        snapshot.upsert_legacy_upload_migration_record(authority, record.clone())?;
        Ok(snapshot)
    }

    pub fn transition(
        &mut self,
        asset_id: &str,
        new_state: State,
        proof_name: impl Into<String>,
        mut proof: Value,
    ) -> Result<&AssetRecord, ManifestError> {
        let proof_name = proof_name.into();
        reject_reserved_internal_proof_name(&proof_name)?;
        sanitize_untrusted_recipe_claim(&proof_name, &mut proof);
        self.transition_trusted(asset_id, new_state, proof_name, proof)
    }

    pub(crate) fn transition_trusted(
        &mut self,
        asset_id: &str,
        new_state: State,
        proof_name: impl Into<String>,
        proof: Value,
    ) -> Result<&AssetRecord, ManifestError> {
        let proof_name = proof_name.into();
        reject_reserved_internal_proof_name(&proof_name)?;
        reject_reserved_internal_proof(self.get(asset_id)?)?;
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
        record.proofs.insert(proof_name, proof);
        record.updated_at = updated_at;
        Ok(record)
    }

    pub fn record_failure(
        &mut self,
        asset_id: &str,
        stage: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<&AssetRecord, ManifestError> {
        self.record_failure_with_kind(asset_id, stage, message, None)
    }

    pub fn record_failure_with_kind(
        &mut self,
        asset_id: &str,
        stage: impl Into<String>,
        message: impl Into<String>,
        kind: Option<FailureKind>,
    ) -> Result<&AssetRecord, ManifestError> {
        reject_reserved_internal_proof(self.get(asset_id)?)?;
        let current_state = self.get(asset_id)?.state;
        if current_state.is_terminal() {
            return Err(ManifestError::InvalidTransition {
                asset_id: asset_id.to_string(),
                from: current_state,
                to: State::Failed,
            });
        }
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
            kind,
        });
        record.updated_at = recorded_at;
        Ok(record)
    }

    pub fn recover_failed_for_retry(
        &mut self,
        asset_id: &str,
        retry_state: State,
    ) -> Result<&AssetRecord, ManifestError> {
        reject_reserved_internal_proof(self.get(asset_id)?)?;
        let current_state = self.get(asset_id)?.state;
        if current_state != State::Failed
            || !matches!(
                retry_state,
                State::NasVerified | State::Converted | State::ConversionVerified
            )
        {
            return Err(ManifestError::InvalidTransition {
                asset_id: asset_id.to_string(),
                from: current_state,
                to: retry_state,
            });
        }

        let updated_at = current_timestamp();
        let record = self
            .records
            .get_mut(asset_id)
            .ok_or_else(|| ManifestError::UnknownAsset {
                asset_id: asset_id.to_string(),
            })?;
        record.state = retry_state;
        record.updated_at = updated_at;
        Ok(record)
    }

    pub fn quarantine_failed_for_historical_remote_side_effect(
        &mut self,
        asset_id: &str,
        proof: FailureQuarantineProof,
    ) -> Result<&AssetRecord, ManifestError> {
        reject_reserved_internal_proof(self.get(asset_id)?)?;
        let current_state = self.get(asset_id)?.state;
        if current_state != State::Failed {
            return Err(ManifestError::InvalidTransition {
                asset_id: asset_id.to_string(),
                from: current_state,
                to: State::NeedsReview,
            });
        }

        let updated_at = current_timestamp();
        let record = self
            .records
            .get_mut(asset_id)
            .ok_or_else(|| ManifestError::UnknownAsset {
                asset_id: asset_id.to_string(),
            })?;
        record.state = State::NeedsReview;
        record.proofs.insert(
            FAILURE_QUARANTINE_PROOF_NAME.to_string(),
            serde_json::to_value(proof)?,
        );
        record.updated_at = updated_at;
        Ok(record)
    }

    pub fn terminalize_failed_with_proof(
        &mut self,
        asset_id: &str,
        proof_name: impl Into<String>,
        mut proof: Value,
    ) -> Result<&AssetRecord, ManifestError> {
        let proof_name = proof_name.into();
        reject_reserved_internal_proof_name(&proof_name)?;
        reject_reserved_internal_proof(self.get(asset_id)?)?;
        sanitize_untrusted_recipe_claim(&proof_name, &mut proof);
        let current_state = self.get(asset_id)?.state;
        if current_state != State::Failed {
            return Err(ManifestError::InvalidTransition {
                asset_id: asset_id.to_string(),
                from: current_state,
                to: State::NeedsReview,
            });
        }

        let updated_at = current_timestamp();
        let record = self
            .records
            .get_mut(asset_id)
            .ok_or_else(|| ManifestError::UnknownAsset {
                asset_id: asset_id.to_string(),
            })?;
        record.state = State::NeedsReview;
        record.proofs.insert(proof_name, proof);
        record.updated_at = updated_at;
        Ok(record)
    }

    pub(crate) fn apply_original_asset_resolution_update(
        &mut self,
        asset_id: &str,
        new_state: State,
        original_asset_proof: Option<Value>,
        resolution_proof: Value,
    ) -> Result<&AssetRecord, ManifestError> {
        reject_reserved_internal_proof(self.get(asset_id)?)?;
        let updated_at = current_timestamp();
        let record = self
            .records
            .get_mut(asset_id)
            .ok_or_else(|| ManifestError::UnknownAsset {
                asset_id: asset_id.to_string(),
            })?;
        record.state = new_state;
        if let Some(proof) = original_asset_proof {
            record.proofs.insert("original_asset".to_string(), proof);
        }
        record
            .proofs
            .insert("original_asset_resolution".to_string(), resolution_proof);
        record.updated_at = updated_at;
        Ok(record)
    }

    pub(crate) fn requeue_interrupted_retries_as_failed(
        &mut self,
        mut is_interrupted_retry: impl FnMut(&AssetRecord) -> bool,
    ) -> Result<usize, ManifestError> {
        reject_reserved_internal_proofs(self.records.values())?;
        let mut requeued = 0;
        for record in self.records.values_mut() {
            if matches!(
                record.state,
                State::NasVerified | State::Converted | State::ConversionVerified
            ) && is_interrupted_retry(record)
            {
                record.state = State::Failed;
                record.updated_at = current_timestamp();
                requeued += 1;
            }
        }
        Ok(requeued)
    }

    pub(crate) fn record_proof(
        &mut self,
        asset_id: &str,
        proof_name: impl Into<String>,
        mut proof: Value,
    ) -> Result<&AssetRecord, ManifestError> {
        let proof_name = proof_name.into();
        reject_reserved_internal_proof_name(&proof_name)?;
        sanitize_untrusted_recipe_claim(&proof_name, &mut proof);
        self.record_trusted_proof(asset_id, proof_name, proof)
    }

    pub(crate) fn record_trusted_proof(
        &mut self,
        asset_id: &str,
        proof_name: impl Into<String>,
        proof: Value,
    ) -> Result<&AssetRecord, ManifestError> {
        let proof_name = proof_name.into();
        reject_reserved_internal_proof_name(&proof_name)?;
        reject_reserved_internal_proof(self.get(asset_id)?)?;
        let updated_at = current_timestamp();
        let record = self
            .records
            .get_mut(asset_id)
            .ok_or_else(|| ManifestError::UnknownAsset {
                asset_id: asset_id.to_string(),
            })?;
        record.proofs.insert(proof_name, proof);
        record.updated_at = updated_at;
        Ok(record)
    }

    pub fn save_atomic(&self, path: impl AsRef<Path>) -> Result<(), ManifestError> {
        reject_reserved_internal_proofs(self.records.values())?;
        self.save_atomic_unchecked(path.as_ref())
    }

    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "retained as a fail-closed generic trusted boundary"
        )
    )]
    pub(crate) fn save_atomic_trusted(&self, path: impl AsRef<Path>) -> Result<(), ManifestError> {
        reject_reserved_internal_proofs(self.records.values())?;
        self.save_atomic_unchecked(path.as_ref())
    }

    pub(crate) fn save_atomic_with_state_store_export_authority(
        &self,
        authority: &StateStoreManifestExportAuthority,
        path: impl AsRef<Path>,
    ) -> Result<(), ManifestError> {
        let destination = path.as_ref();
        if !authority.authorizes(self, destination) {
            return Err(ManifestError::ReservedInternalProofCapabilityMismatch);
        }
        self.save_atomic_unchecked(destination)
    }

    fn save_atomic_unchecked(&self, destination: &Path) -> Result<(), ManifestError> {
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;

        let (temp_path, mut temp_file) = create_temp_file(parent, destination)?;
        let payload = ManifestFile {
            records: self.records.values().cloned().collect(),
            legacy_upload_migration_registry: self.legacy_upload_migration_registry.clone(),
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
        Self::load_from_reader(file)
    }

    pub(crate) fn load_from_reader(reader: impl Read) -> Result<Self, ManifestError> {
        let payload: ManifestFile = crate::strict_json::from_reader(reader)?;
        let mut manifest = Self::new();
        if let Some(registry) = payload.legacy_upload_migration_registry {
            let authority = LegacyUploadMigrationManifestRegistryAuthority::for_registry(&registry)
                .map_err(|_| ManifestError::ReservedInternalProofCapabilityMismatch)?;
            manifest.install_legacy_upload_migration_registry(&authority, registry)?;
        }
        for record in payload.records {
            let authority = CheckpointManifestRecordAuthority::for_record(&record)?;
            manifest.upsert_checkpoint_record(&authority, record)?;
        }
        validate_legacy_upload_migration_registry_binding(&manifest, false)
            .map_err(|_| ManifestError::ReservedInternalProofCapabilityMismatch)?;
        Ok(manifest)
    }

    fn reject_reserved_internal_proof_upsert(
        &self,
        record: &AssetRecord,
    ) -> Result<(), ManifestError> {
        if record_has_reserved_internal_proof(record)
            || self
                .records
                .get(&record.asset_id)
                .is_some_and(record_has_reserved_internal_proof)
        {
            Err(ManifestError::ReservedInternalProofRequiresAuthority)
        } else {
            Ok(())
        }
    }
}

fn asset_record_sha256(record: &AssetRecord) -> Result<String, ManifestError> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(record)?)))
}

pub(crate) fn record_has_reserved_internal_proof(record: &AssetRecord) -> bool {
    record
        .proofs
        .contains_key(INTERNAL_LEGACY_UPLOAD_MIGRATION_PROOF_NAME)
}

fn reject_reserved_internal_proof(record: &AssetRecord) -> Result<(), ManifestError> {
    if record_has_reserved_internal_proof(record) {
        Err(ManifestError::ReservedInternalProofRequiresAuthority)
    } else {
        Ok(())
    }
}

fn reject_reserved_internal_proof_name(proof_name: &str) -> Result<(), ManifestError> {
    if proof_name == INTERNAL_LEGACY_UPLOAD_MIGRATION_PROOF_NAME {
        Err(ManifestError::ReservedInternalProofRequiresAuthority)
    } else {
        Ok(())
    }
}

fn reject_reserved_internal_proofs<'a>(
    records: impl IntoIterator<Item = &'a AssetRecord>,
) -> Result<(), ManifestError> {
    if records.into_iter().any(record_has_reserved_internal_proof) {
        Err(ManifestError::ReservedInternalProofRequiresAuthority)
    } else {
        Ok(())
    }
}

pub(crate) fn sanitize_untrusted_recipe_claims(record: &mut AssetRecord) {
    for proof_name in ["conversion", "conversion_performance", "heic"] {
        if let Some(proof) = record.proofs.get_mut(proof_name) {
            sanitize_untrusted_recipe_claim(proof_name, proof);
        }
    }
}

fn sanitize_untrusted_recipe_claim(proof_name: &str, proof: &mut Value) {
    if ["conversion", "conversion_performance", "heic"].contains(&proof_name)
        && let Value::Object(proof) = proof
    {
        proof.insert(
            "conversion_recipe_id".to_string(),
            Value::String(String::new()),
        );
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
    #[error("reserved internal proof requires an authoritative migration path")]
    ReservedInternalProofRequiresAuthority,
    #[error("sealed manifest capability does not match the exact record or checkpoint")]
    ReservedInternalProofCapabilityMismatch,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    records: Vec<AssetRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    legacy_upload_migration_registry: Option<LegacyUploadMigrationRegistry>,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn record_with_reserved_migration_proof(asset_id: &str) -> AssetRecord {
        let mut record = AssetRecord::new(asset_id, format!("/raw/{asset_id}.dng"));
        record.proofs.insert(
            INTERNAL_LEGACY_UPLOAD_MIGRATION_PROOF_NAME.to_string(),
            serde_json::json!({"forged": true}),
        );
        record
    }

    fn manifest_loaded_with_reserved_migration_proof(asset_id: &str) -> Manifest {
        let mut manifest = Manifest::new();
        let record = record_with_reserved_migration_proof(asset_id);
        manifest.records.insert(record.asset_id.clone(), record);
        manifest
    }

    #[test]
    fn failure_record_kind_is_backward_compatible_and_stable_when_present() {
        let legacy = r#"{"stage":"conversion","message":"failed","recorded_at":"100.000000000Z"}"#;
        let legacy_record: FailureRecord =
            serde_json::from_str(legacy).expect("legacy failure record should deserialize");
        assert_eq!(
            serde_json::to_string(&legacy_record).expect("legacy record should serialize"),
            legacy
        );

        let typed = r#"{"stage":"heic_verify","message":"HEIC verification failed: visual_content_ok","recorded_at":"101.000000000Z","kind":"heic_visual_content"}"#;
        let typed_record: FailureRecord =
            serde_json::from_str(typed).expect("typed failure record should deserialize");
        assert_eq!(
            serde_json::to_string(&typed_record).expect("typed record should serialize"),
            typed
        );

        let adjusted = r#"{"stage":"adjusted_source_resolve","message":"resolver failed","recorded_at":"102.000000000Z","kind":"adjusted_source_resolve_failed"}"#;
        let adjusted_record: FailureRecord =
            serde_json::from_str(adjusted).expect("adjusted resolver failure should deserialize");
        assert_eq!(
            adjusted_record.kind,
            Some(FailureKind::AdjustedSourceResolveFailed)
        );
        assert_eq!(
            adjusted_record.kind.unwrap().as_str(),
            "adjusted_source_resolve_failed"
        );

        let tool_unavailable = r#"{"stage":"conversion","message":"conversion tool not found on sanitized PATH: exiftool","recorded_at":"103.000000000Z","kind":"conversion_tool_unavailable"}"#;
        let tool_unavailable_record: FailureRecord = serde_json::from_str(tool_unavailable)
            .expect("tool-unavailable failure should deserialize");
        assert_eq!(
            tool_unavailable_record.kind,
            Some(FailureKind::ConversionToolUnavailable)
        );
        assert_eq!(
            tool_unavailable_record.kind.unwrap().as_str(),
            "conversion_tool_unavailable"
        );

        let legacy_manifest = r#"{
            "records": [{
                "asset_id": "legacy",
                "raw_path": "/raw/legacy.DNG",
                "state": "failed",
                "proofs": {},
                "failures": [{
                    "stage": "conversion",
                    "message": "legacy missing preview",
                    "recorded_at": "100.000000000Z"
                }],
                "updated_at": "100.000000000Z"
            }]
        }"#;
        let legacy_payload: ManifestFile = serde_json::from_str(legacy_manifest)
            .expect("old manifest payload should remain readable");
        assert_eq!(legacy_payload.records[0].failures[0].kind, None);
    }

    #[test]
    fn reconciliation_terminal_states_are_serialized_and_cannot_enter_lifecycle() {
        let mut manifest = Manifest::new();
        for (asset_id, state, serialized) in [
            ("no-action", State::NoAction, "no_action"),
            ("needs-review", State::NeedsReview, "needs_review"),
        ] {
            assert_eq!(state.as_str(), serialized);
            assert!(state.is_terminal());
            assert_eq!(
                serde_json::to_string(&state).unwrap(),
                format!("\"{serialized}\"")
            );

            let mut record = AssetRecord::new(asset_id, format!("/raw/{asset_id}.dng"));
            record.state = state;
            manifest.upsert(record);
            assert!(matches!(
                manifest.transition(asset_id, State::NasVerified, "test", serde_json::json!({})),
                Err(ManifestError::InvalidTransition { .. })
            ));
            let before = manifest.get(asset_id).unwrap().clone();
            assert!(matches!(
                manifest.record_failure(asset_id, "test", "terminal records are immutable"),
                Err(ManifestError::InvalidTransition { .. })
            ));
            assert_eq!(manifest.get(asset_id).unwrap(), &before);
        }
    }

    #[test]
    fn recover_failed_for_retry_only_allows_failed_assets_to_retry_states() {
        let mut manifest = Manifest::new();
        let mut failed = AssetRecord::new("failed", "/raw/failed.dng");
        failed.state = State::Failed;
        failed.updated_at = "100.000000000Z".to_string();
        manifest.upsert(failed.clone());

        let recovered = manifest
            .recover_failed_for_retry("failed", State::NasVerified)
            .expect("failed asset should recover to a retry state");
        assert_eq!(recovered.state, State::NasVerified);
        assert!(recovered.updated_at > failed.updated_at);

        let wrong_source = manifest
            .recover_failed_for_retry("failed", State::Converted)
            .expect_err("non-failed asset should not recover again");
        assert!(matches!(
            wrong_source,
            ManifestError::InvalidTransition {
                from: State::NasVerified,
                to: State::Converted,
                ..
            }
        ));

        let mut failed_again = AssetRecord::new("failed-again", "/raw/failed-again.dng");
        failed_again.state = State::Failed;
        manifest.upsert(failed_again);
        let wrong_target = manifest
            .recover_failed_for_retry("failed-again", State::UploadVerified)
            .expect_err("recovery should reject non-retry target states");
        assert!(matches!(
            wrong_target,
            ManifestError::InvalidTransition {
                from: State::Failed,
                to: State::UploadVerified,
                ..
            }
        ));
    }

    #[test]
    fn public_upsert_strips_recipe_claims_while_trusted_snapshot_and_load_preserve_them() {
        let mut record = AssetRecord::new("asset", "/raw/asset.dng");
        for proof_name in ["conversion", "conversion_performance", "heic"] {
            record.proofs.insert(
                proof_name.to_string(),
                serde_json::json!({"conversion_recipe_id": "embedded-preview-normalized-v1"}),
            );
        }

        let mut untrusted = Manifest::new();
        untrusted.upsert(record.clone());
        for proof_name in ["conversion", "conversion_performance", "heic"] {
            assert_eq!(
                untrusted.get("asset").unwrap().proofs[proof_name]["conversion_recipe_id"],
                ""
            );
        }

        let mut trusted = Manifest::new();
        trusted.upsert_trusted(record);
        let snapshot = trusted.snapshot_record("asset").unwrap();
        let path = tempfile::tempdir().unwrap().path().join("manifest.json");
        snapshot.save_atomic(&path).unwrap();
        let loaded = Manifest::load(path).unwrap();
        for proof_name in ["conversion", "conversion_performance", "heic"] {
            assert_eq!(
                loaded.get("asset").unwrap().proofs[proof_name]["conversion_recipe_id"],
                "embedded-preview-normalized-v1"
            );
        }
    }

    #[test]
    fn public_proof_mutators_strip_forged_current_recipe_claims() {
        for proof_name in ["conversion", "conversion_performance", "heic"] {
            let forged = serde_json::json!({
                "conversion_recipe_id": "embedded-preview-normalized-v1"
            });

            let mut transitioned = Manifest::new();
            transitioned.upsert(AssetRecord::new("transitioned", "/raw/transitioned.dng"));
            transitioned
                .transition(
                    "transitioned",
                    State::NasVerified,
                    proof_name,
                    forged.clone(),
                )
                .unwrap();
            assert_eq!(
                transitioned.get("transitioned").unwrap().proofs[proof_name]["conversion_recipe_id"],
                ""
            );

            let mut terminalized = Manifest::new();
            let mut failed = AssetRecord::new("terminalized", "/raw/terminalized.dng");
            failed.state = State::Failed;
            terminalized.upsert(failed);
            terminalized
                .terminalize_failed_with_proof("terminalized", proof_name, forged)
                .unwrap();
            assert_eq!(
                terminalized.get("terminalized").unwrap().proofs[proof_name]["conversion_recipe_id"],
                ""
            );
        }
    }

    #[test]
    fn public_and_generic_trusted_upsert_reject_reserved_install_and_removal_without_mutation() {
        for trusted in [false, true] {
            let mut install = Manifest::new();
            install.upsert(AssetRecord::new("ordinary", "/raw/ordinary.dng"));
            let before = install.clone();
            let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let record = record_with_reserved_migration_proof("migration");
                if trusted {
                    install.upsert_trusted(record);
                } else {
                    install.upsert(record);
                }
            }));
            assert!(rejected.is_err());
            assert_eq!(install, before);

            let mut removal = manifest_loaded_with_reserved_migration_proof("migration");
            let before = removal.clone();
            let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let record = AssetRecord::new("migration", "/raw/replacement.dng");
                if trusted {
                    removal.upsert_trusted(record);
                } else {
                    removal.upsert(record);
                }
            }));
            assert!(rejected.is_err());
            assert_eq!(removal, before);
        }
    }

    #[test]
    fn generic_trusted_transition_rejects_reserved_install_and_journal_mutation() {
        let mut install = Manifest::new();
        install.upsert(AssetRecord::new("ordinary", "/raw/ordinary.dng"));
        let before = install.clone();
        assert!(matches!(
            install.transition_trusted(
                "ordinary",
                State::NasVerified,
                INTERNAL_LEGACY_UPLOAD_MIGRATION_PROOF_NAME,
                serde_json::json!({"forged": true}),
            ),
            Err(ManifestError::ReservedInternalProofRequiresAuthority)
        ));
        assert_eq!(install, before);

        let mut detached = manifest_loaded_with_reserved_migration_proof("migration");
        let before = detached.clone();
        assert!(matches!(
            detached.transition_trusted(
                "migration",
                State::NasVerified,
                "ordinary_proof",
                serde_json::json!({"detached": true}),
            ),
            Err(ManifestError::ReservedInternalProofRequiresAuthority)
        ));
        assert_eq!(detached, before);
    }

    #[test]
    fn generic_trusted_proof_recording_rejects_reserved_install_and_journal_mutation() {
        let mut install = Manifest::new();
        install.upsert(AssetRecord::new("ordinary", "/raw/ordinary.dng"));
        let before = install.clone();
        assert!(matches!(
            install.record_trusted_proof(
                "ordinary",
                INTERNAL_LEGACY_UPLOAD_MIGRATION_PROOF_NAME,
                serde_json::json!({"forged": true}),
            ),
            Err(ManifestError::ReservedInternalProofRequiresAuthority)
        ));
        assert_eq!(install, before);

        let mut detached = manifest_loaded_with_reserved_migration_proof("migration");
        let before = detached.clone();
        assert!(matches!(
            detached.record_trusted_proof(
                "migration",
                "ordinary_proof",
                serde_json::json!({"detached": true}),
            ),
            Err(ManifestError::ReservedInternalProofRequiresAuthority)
        ));
        assert_eq!(detached, before);
    }

    #[test]
    fn generic_snapshot_and_trusted_save_reject_reserved_record_without_output() {
        let manifest = manifest_loaded_with_reserved_migration_proof("migration");
        assert!(matches!(
            manifest.snapshot_record("migration"),
            Err(ManifestError::ReservedInternalProofRequiresAuthority)
        ));

        let temp = tempfile::tempdir().unwrap();
        let destination = temp.path().join("uncreated/forged-checkpoint.json");
        assert!(matches!(
            manifest.save_atomic_trusted(&destination),
            Err(ManifestError::ReservedInternalProofRequiresAuthority)
        ));
        assert!(!destination.exists());
        assert!(!destination.parent().unwrap().exists());
    }
}

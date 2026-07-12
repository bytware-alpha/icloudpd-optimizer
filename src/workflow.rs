use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::adjusted_source::{
    AdjustedSourceError, CloudKitAdjustedSourceProof, MaterializedAdjustedSource,
    adjusted_source_proof_digest,
    materialize_adjusted_source_for_conversion as materialize_adjusted_source,
    validate_adjusted_source_proof_lineage, validate_installed_adjusted_source_proof,
};
use crate::manifest::{AssetRecord, FailureKind, Manifest, ManifestError, State};
use crate::proof::{
    MIN_RAW_AGE_SECONDS, NasRawProof, ProofError, RawFileFingerprint, prove_nas_raw,
    prove_nas_raw_with_min_age_seconds_and_fingerprint,
};
use crate::upload::{
    CloudKitDatabaseScope, CloudKitDeleteOutcome, CloudKitDeleteRequest,
    CloudKitLibraryDestination, CloudKitUploadedHeicAsset, CloudKitUploadedHeicResolveRequest,
};

const NAS_PROOF: &str = "nas";
const ORIGINAL_ASSET_PROOF: &str = "original_asset";
const ADJUSTED_SOURCE_PROOF: &str = "adjusted_source";
const CONVERSION_PROOF: &str = "conversion";
const CONVERSION_PERFORMANCE_PROOF: &str = "conversion_performance";
const HEIC_PROOF: &str = "heic";
const SOURCE_AGE_PROOF: &str = "source_age";
const UPLOAD_PROOF: &str = "upload";
const UPLOADED_HEIC_DELETE_PROOF: &str = "uploaded_heic_delete";
const ICLOUDPD_LOCAL_MIRROR_PROOF: &str = "icloudpd_local_mirror";
const DELETE_ELIGIBILITY_PROOF: &str = "delete_eligibility";
const DELETE_APPROVAL_PROOF: &str = "delete_approval";
const DELETE_EXECUTION_PROOF: &str = "delete";
const CONVERSION_PERFORMANCE_SCHEMA_VERSION: u8 = 1;
const CONVERSION_PERFORMANCE_MEASUREMENT_METHOD: &str = "monotonic_wall_clock";
pub const EMBEDDED_PREVIEW_CONVERSION_RECIPE: &str = "embedded-preview-normalized-v1";
const UNSAFE_LEGACY_RAW_SENSOR_RENDER_TOOL: &str = "dcraw_emu+magick+heif-enc";
const BASE_DELETE_PLAN_PROOFS: [&str; 10] = [
    NAS_PROOF,
    ORIGINAL_ASSET_PROOF,
    CONVERSION_PROOF,
    CONVERSION_PERFORMANCE_PROOF,
    HEIC_PROOF,
    SOURCE_AGE_PROOF,
    UPLOAD_PROOF,
    ICLOUDPD_LOCAL_MIRROR_PROOF,
    DELETE_ELIGIBILITY_PROOF,
    DELETE_APPROVAL_PROOF,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IcloudpdLocalMirrorProofDisposition {
    Current,
    Repairable,
    Blocked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConversionResultProof {
    pub heic_path: PathBuf,
    pub heic_sha256: String,
    pub size_bytes: u64,
    /// Missing values deliberately remain legacy/untrusted; do not default this to current.
    #[serde(default)]
    pub conversion_recipe_id: String,
    #[serde(default)]
    pub source_binding: ConversionSourceBinding,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversionSourceBinding {
    #[default]
    EmbeddedPreview,
    AdjustedSource {
        adjusted_source_proof_digest: String,
        adjusted_jpeg_sha256: String,
        adjusted_jpeg_path: PathBuf,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversionPerformanceInput {
    pub measured_at_unix_seconds: u64,
    pub conversion_tool: String,
    pub conversion_recipe_id: String,
    pub conversion_tool_version: Option<String>,
    pub heic_quality: u8,
    pub convert_wall_time_millis: u64,
    pub total_wall_time_millis: u64,
    pub user_cpu_time_millis: Option<u64>,
    pub system_cpu_time_millis: Option<u64>,
    pub peak_rss_kib: Option<u64>,
    pub conversion_command_timings: Vec<ConversionCommandTiming>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConversionCommandTiming {
    pub program: String,
    pub wall_time_millis: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConversionPerformanceProof {
    pub schema_version: u8,
    pub measured_at_unix_seconds: u64,
    pub measurement_method: String,
    pub conversion_tool: String,
    #[serde(default)]
    pub conversion_recipe_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversion_tool_version: Option<String>,
    pub heic_quality: u8,
    pub raw_size_bytes: u64,
    pub heic_size_bytes: u64,
    pub convert_wall_time_millis: u64,
    pub total_wall_time_millis: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_cpu_time_millis: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_cpu_time_millis: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_rss_kib: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conversion_command_timings: Vec<ConversionCommandTiming>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HeicVerificationProof {
    pub heic_path: PathBuf,
    pub heic_sha256: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub conversion_recipe_id: String,
    #[serde(alias = "vipsheader_ok")]
    pub heif_info_ok: bool,
    pub metadata_copied: bool,
    pub visual_content_ok: bool,
    pub visual_match_ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visual_rmse_ppm: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visual_mae_ppm: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UploadProof {
    pub uploaded_heic_asset_id: String,
    pub uploaded_heic_sha256: String,
    #[serde(default)]
    pub database_scope: CloudKitDatabaseScope,
    #[serde(default = "primary_sync_zone_name")]
    pub zone_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uploaded_heic_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IcloudpdLocalMirrorProof {
    pub uploaded_heic_asset_id: String,
    pub uploaded_heic_sha256: String,
    pub uploaded_heic_path: PathBuf,
    pub icloudpd_download_path: PathBuf,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OriginalAssetProof {
    pub record_name: String,
    pub record_change_tag: String,
    pub record_type: String,
    #[serde(default)]
    pub database_scope: CloudKitDatabaseScope,
    #[serde(default = "primary_sync_zone_name")]
    pub zone_name: String,
    pub filename: String,
    pub size_bytes: u64,
    pub matched_raw_sha256: String,
}

fn primary_sync_zone_name() -> String {
    "PrimarySync".to_string()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SourceAgeProof {
    pub source_captured_unix_seconds: u64,
    pub verified_at_unix_seconds: u64,
    pub min_age_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct DeleteEligibilityProof {
    upload_proof_key: String,
    original_asset_proof_key: String,
    conversion_performance_proof_key: String,
    heic_proof_key: String,
    source_age_proof_key: String,
    icloudpd_local_mirror_proof_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    adjusted_source_proof_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    adjusted_source_proof_digest: Option<String>,
    #[serde(default)]
    original_database_scope: CloudKitDatabaseScope,
    #[serde(default = "primary_sync_zone_name")]
    original_zone_name: String,
    #[serde(default)]
    uploaded_database_scope: CloudKitDatabaseScope,
    #[serde(default = "primary_sync_zone_name")]
    uploaded_zone_name: String,
    uploaded_heic_asset_id: String,
    uploaded_heic_sha256: String,
    uploaded_heic_path: PathBuf,
    verified_heic_sha256: String,
    verified_heic_path: PathBuf,
    icloudpd_download_path: PathBuf,
    mirrored_heic_sha256: String,
    mirrored_size_bytes: u64,
    source_captured_unix_seconds: u64,
    source_age_seconds: u64,
    min_source_age_seconds: u64,
    original_record_name: String,
    original_record_change_tag: String,
    original_record_type: String,
    original_filename: String,
    original_size_bytes: u64,
    matched_raw_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct DeleteApprovalProof {
    operator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    adjusted_source_proof_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    adjusted_source_proof_digest: Option<String>,
}

struct PreDeleteFacts {
    original: OriginalAssetProof,
    upload: UploadProof,
    uploaded_heic_path: PathBuf,
    heic: HeicVerificationProof,
    mirror: IcloudpdLocalMirrorProof,
    source_age: SourceAgeProof,
    source_age_seconds: u64,
    adjusted_source: Option<CloudKitAdjustedSourceProof>,
}

struct LiveDeleteFacts {
    raw_fingerprint: RawFileFingerprint,
}

struct DeleteEligibilityValidationFacts<'a> {
    original: &'a OriginalAssetProof,
    upload: &'a UploadProof,
    uploaded_heic_path: &'a Path,
    heic: &'a HeicVerificationProof,
    mirror: &'a IcloudpdLocalMirrorProof,
    source_age: &'a SourceAgeProof,
    source_age_seconds: u64,
    adjusted_source: Option<&'a CloudKitAdjustedSourceProof>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeleteExecutionProof {
    pub old_record_change_tag: String,
    pub deleted_record_name: String,
    pub confirmed_deleted_change_tag: String,
    pub uploaded_heic_asset_id: String,
}

#[must_use = "a prevalidated delete must be consumed when recording the CloudKit outcome"]
#[derive(Debug)]
pub struct PrevalidatedDelete {
    asset_id: String,
    raw_path: PathBuf,
    request: CloudKitDeleteRequest,
    uploaded_heic_asset_id: String,
    proofs: BTreeMap<String, Value>,
    raw_fingerprint: RawFileFingerprint,
    validated_at: SystemTime,
}

impl PrevalidatedDelete {
    pub fn asset_id(&self) -> &str {
        &self.asset_id
    }

    pub fn request(&self) -> &CloudKitDeleteRequest {
        &self.request
    }

    pub fn validated_at(&self) -> SystemTime {
        self.validated_at
    }

    /// Checks only token age before issuing the CloudKit delete request.
    pub fn validate_freshness(&self, max_age: Duration) -> Result<(), WorkflowError> {
        self.validate_freshness_at(max_age, SystemTime::now())
    }

    /// Checks only token age at a supplied time for deterministic tests.
    pub fn validate_freshness_at(
        &self,
        max_age: Duration,
        now: SystemTime,
    ) -> Result<(), WorkflowError> {
        validate_prevalidated_delete_freshness(&self.asset_id, self.validated_at, max_age, now)
    }

    /// Rechecks the RAW path fingerprint immediately before issuing the CloudKit delete.
    pub fn validate_live_raw(&self, max_age: Duration) -> Result<(), WorkflowError> {
        self.validate_live_raw_at(max_age, SystemTime::now())
    }

    /// Rechecks the RAW path fingerprint at a supplied time for deterministic tests.
    pub fn validate_live_raw_at(
        &self,
        max_age: Duration,
        now: SystemTime,
    ) -> Result<(), WorkflowError> {
        self.validate_freshness_at(max_age, now)?;

        let live = RawFileFingerprint::capture(&self.raw_path)?;
        if live != self.raw_fingerprint {
            return Err(WorkflowError::PrevalidatedDeleteStale {
                asset_id: self.asset_id.clone(),
                field: "raw_fingerprint".to_string(),
            });
        }
        Ok(())
    }
}

#[must_use = "a delete reconciliation token must be consumed only after read-only lookup confirms the remote delete"]
#[derive(Debug)]
pub struct DeleteReconciliation {
    asset_id: String,
    raw_path: PathBuf,
    request: CloudKitDeleteRequest,
    uploaded_heic_asset_id: String,
    proofs: BTreeMap<String, Value>,
}

impl DeleteReconciliation {
    pub fn asset_id(&self) -> &str {
        &self.asset_id
    }

    pub fn request(&self) -> &CloudKitDeleteRequest {
        &self.request
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UploadedHeicDeleteProof {
    pub uploaded_heic_asset_id: String,
    pub uploaded_heic_master_record_name: String,
    pub matched_heic_sha256: String,
    pub size_bytes: u64,
    pub old_record_change_tag: String,
    pub deleted_record_name: String,
    pub confirmed_deleted_change_tag: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeletePlan {
    pub asset_id: String,
    pub raw_path: PathBuf,
    pub required_proof_keys: Vec<String>,
    pub proofs: BTreeMap<String, Value>,
}

pub fn discover_raw_asset(
    manifest: &mut Manifest,
    asset_id: impl Into<String>,
    raw_path: impl Into<PathBuf>,
) -> Result<&AssetRecord, WorkflowError> {
    let asset_id = asset_id.into();
    let raw_path = raw_path.into();

    if let Some(record) = manifest.records().get(&asset_id) {
        if record.state != State::Discovered {
            return Err(WorkflowError::ExistingAssetNotDiscoverable {
                asset_id,
                state: record.state,
            });
        }
        if record.raw_path != raw_path {
            return Err(WorkflowError::RawPathMismatch {
                asset_id,
                existing_path: record.raw_path.clone(),
                requested_path: raw_path,
            });
        }
        return manifest.get(&asset_id).map_err(WorkflowError::Manifest);
    }

    manifest.upsert(AssetRecord::new(asset_id.clone(), raw_path));
    manifest.get(&asset_id).map_err(WorkflowError::Manifest)
}

pub fn prove_and_record_nas<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    raw_path: impl AsRef<Path>,
    nas_root: impl AsRef<Path>,
    min_age_days: u64,
    now: SystemTime,
) -> Result<&'a AssetRecord, WorkflowError> {
    let raw_path = raw_path.as_ref();
    let proof = prove_nas_raw(nas_root.as_ref(), raw_path, min_age_days, now)?;
    let canonical_path = proof.canonical_path.clone();
    discover_raw_asset(manifest, asset_id, canonical_path)?;
    record_nas_proof(manifest, asset_id, proof)
}

pub fn record_nas_proof<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    proof: NasRawProof,
) -> Result<&'a AssetRecord, WorkflowError> {
    transition_with_proof(manifest, asset_id, State::NasVerified, NAS_PROOF, &proof)
}

/// Records the exact, already-installed adjusted JPEG proof without advancing
/// lifecycle state. The next conversion is therefore forced to bind to it.
pub fn record_adjusted_source_proof<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    output_path: impl AsRef<Path>,
    proof: CloudKitAdjustedSourceProof,
) -> Result<&'a AssetRecord, WorkflowError> {
    let record = manifest.get(asset_id)?;
    if record.state != State::NasVerified {
        return Err(WorkflowError::AdjustedSourceUnavailable {
            asset_id: asset_id.to_string(),
            state: record.state,
        });
    }
    if record.proofs.contains_key(ADJUSTED_SOURCE_PROOF) {
        return Err(WorkflowError::AdjustedSourceProofAlreadyRecorded {
            asset_id: asset_id.to_string(),
        });
    }
    let original = stored_proof::<OriginalAssetProof>(manifest, asset_id, ORIGINAL_ASSET_PROOF)?;
    validate_installed_adjusted_source_proof(&proof, asset_id, &original, output_path)
        .map_err(WorkflowError::AdjustedSource)?;
    insert_workflow_proof(manifest, asset_id, ADJUSTED_SOURCE_PROOF, &proof)
}

pub fn record_conversion_result<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    proof: ConversionResultProof,
) -> Result<&'a AssetRecord, WorkflowError> {
    require_non_empty_path("heic_path", &proof.heic_path)?;
    require_non_empty("heic_sha256", &proof.heic_sha256)?;
    validate_conversion_source_binding(manifest, asset_id, &proof)?;
    transition_with_proof(
        manifest,
        asset_id,
        State::Converted,
        CONVERSION_PROOF,
        &proof,
    )
}

pub fn record_conversion_performance<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    input: ConversionPerformanceInput,
) -> Result<&'a AssetRecord, WorkflowError> {
    let state = manifest.get(asset_id)?.state;
    if state != State::Converted {
        return Err(WorkflowError::Manifest(ManifestError::InvalidTransition {
            asset_id: asset_id.to_string(),
            from: state,
            to: State::Converted,
        }));
    }

    let (nas, conversion) = load_conversion_context(manifest, asset_id)?;
    let proof = ConversionPerformanceProof {
        schema_version: CONVERSION_PERFORMANCE_SCHEMA_VERSION,
        measured_at_unix_seconds: input.measured_at_unix_seconds,
        measurement_method: CONVERSION_PERFORMANCE_MEASUREMENT_METHOD.to_string(),
        conversion_tool: input.conversion_tool,
        conversion_recipe_id: input.conversion_recipe_id,
        conversion_tool_version: input.conversion_tool_version,
        heic_quality: input.heic_quality,
        raw_size_bytes: nas.size_bytes,
        heic_size_bytes: conversion.size_bytes,
        convert_wall_time_millis: input.convert_wall_time_millis,
        total_wall_time_millis: input.total_wall_time_millis,
        user_cpu_time_millis: input.user_cpu_time_millis,
        system_cpu_time_millis: input.system_cpu_time_millis,
        peak_rss_kib: input.peak_rss_kib,
        conversion_command_timings: input.conversion_command_timings,
    };
    validate_conversion_performance_proof(&proof, &nas, &conversion)?;
    insert_workflow_proof(manifest, asset_id, CONVERSION_PERFORMANCE_PROOF, &proof)
}

pub fn record_heic_verification<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    proof: HeicVerificationProof,
) -> Result<&'a AssetRecord, WorkflowError> {
    require_non_empty_path("heic_path", &proof.heic_path)?;
    require_non_empty("heic_sha256", &proof.heic_sha256)?;
    let (_, conversion) = load_conversion_context(manifest, asset_id)?;
    require_matching_path(
        CONVERSION_PROOF,
        "heic_path",
        &conversion.heic_path,
        &proof.heic_path,
    )?;
    require_matching_str(
        CONVERSION_PROOF,
        "heic_sha256",
        &conversion.heic_sha256,
        &proof.heic_sha256,
    )?;
    require_matching_u64(
        CONVERSION_PROOF,
        "size_bytes",
        conversion.size_bytes,
        proof.size_bytes,
    )?;
    validate_heic_verification_flags_legacy(&proof)?;
    transition_with_proof(
        manifest,
        asset_id,
        State::ConversionVerified,
        HEIC_PROOF,
        &proof,
    )
}

pub fn record_upload_proof<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    proof: UploadProof,
) -> Result<&'a AssetRecord, WorkflowError> {
    require_non_empty("uploaded_heic_asset_id", &proof.uploaded_heic_asset_id)?;
    require_non_empty("uploaded_heic_sha256", &proof.uploaded_heic_sha256)?;
    let uploaded_heic_path =
        proof
            .uploaded_heic_path
            .as_ref()
            .ok_or(WorkflowError::EmptyProofField {
                field: "uploaded_heic_path",
            })?;
    require_non_empty_path("uploaded_heic_path", uploaded_heic_path)?;
    require_valid_conversion_performance(manifest, asset_id)?;
    let heic = stored_proof::<HeicVerificationProof>(manifest, asset_id, HEIC_PROOF)?;
    validate_heic_verification_flags(&heic)?;
    require_matching_str(
        HEIC_PROOF,
        "uploaded_heic_sha256",
        &heic.heic_sha256,
        &proof.uploaded_heic_sha256,
    )?;
    require_matching_path(
        HEIC_PROOF,
        "uploaded_heic_path",
        &heic.heic_path,
        uploaded_heic_path,
    )?;
    if let Some(original_value) = manifest.get(asset_id)?.proofs.get(ORIGINAL_ASSET_PROOF) {
        let original: OriginalAssetProof =
            serde_json::from_value(original_value.clone()).map_err(|source| {
                WorkflowError::ProofDecode {
                    asset_id: asset_id.to_string(),
                    proof_key: ORIGINAL_ASSET_PROOF,
                    source,
                }
            })?;
        require_matching_library_destination(UPLOAD_PROOF, &original, &proof)?;
    }
    transition_with_proof(
        manifest,
        asset_id,
        State::UploadVerified,
        UPLOAD_PROOF,
        &proof,
    )
}

pub fn uploaded_heic_delete_request(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<CloudKitUploadedHeicResolveRequest, WorkflowError> {
    let (upload, heic) = uploaded_heic_delete_inputs(manifest, asset_id)?;
    Ok(CloudKitUploadedHeicResolveRequest {
        uploaded_asset_id: upload.uploaded_heic_asset_id,
        expected_heic_sha256: upload.uploaded_heic_sha256,
        expected_size_bytes: heic.size_bytes,
        database_scope: upload.database_scope,
        zone_name: upload.zone_name,
    })
}

pub fn record_uploaded_heic_delete<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    resolved: CloudKitUploadedHeicAsset,
    outcome: CloudKitDeleteOutcome,
) -> Result<&'a AssetRecord, WorkflowError> {
    let (upload, heic) = uploaded_heic_delete_inputs(manifest, asset_id)?;
    require_matching_str(
        UPLOADED_HEIC_DELETE_PROOF,
        "uploaded_heic_asset_id",
        &upload.uploaded_heic_asset_id,
        &resolved.record_name,
    )?;
    require_matching_str(
        UPLOADED_HEIC_DELETE_PROOF,
        "matched_heic_sha256",
        &upload.uploaded_heic_sha256,
        &resolved.matched_heic_sha256,
    )?;
    require_matching_u64(
        UPLOADED_HEIC_DELETE_PROOF,
        "size_bytes",
        heic.size_bytes,
        resolved.size_bytes,
    )?;
    require_matching_str(
        UPLOADED_HEIC_DELETE_PROOF,
        "deleted_record_name",
        &resolved.record_name,
        &outcome.record_name,
    )?;
    let proof = UploadedHeicDeleteProof {
        uploaded_heic_asset_id: upload.uploaded_heic_asset_id,
        uploaded_heic_master_record_name: resolved.master_record_name,
        matched_heic_sha256: resolved.matched_heic_sha256,
        size_bytes: resolved.size_bytes,
        old_record_change_tag: resolved.record_change_tag,
        deleted_record_name: outcome.record_name,
        confirmed_deleted_change_tag: outcome.record_change_tag,
    };
    validate_uploaded_heic_delete_proof(&proof)?;
    insert_workflow_proof(manifest, asset_id, UPLOADED_HEIC_DELETE_PROOF, &proof)
}

pub fn record_icloudpd_local_mirror_proof<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    proof: IcloudpdLocalMirrorProof,
) -> Result<&'a AssetRecord, WorkflowError> {
    let state = manifest.get(asset_id)?.state;
    if !matches!(
        state,
        State::UploadVerified | State::DeleteEligible | State::DeleteApproved
    ) {
        return Err(WorkflowError::IcloudpdLocalMirrorUnavailable {
            asset_id: asset_id.to_string(),
            state,
        });
    }

    validate_candidate_icloudpd_local_mirror(manifest, asset_id, &proof)?;

    let mut staged = manifest.clone();
    insert_workflow_proof(&mut staged, asset_id, ICLOUDPD_LOCAL_MIRROR_PROOF, &proof)?;
    if matches!(state, State::DeleteEligible | State::DeleteApproved) {
        let facts = validate_pre_delete_facts(&staged, asset_id)?;
        let eligibility_proof = delete_eligibility_proof(&facts);
        insert_workflow_proof(
            &mut staged,
            asset_id,
            DELETE_ELIGIBILITY_PROOF,
            &eligibility_proof,
        )?;
        if state == State::DeleteApproved {
            validate_delete_approval_proof(&staged, asset_id, &facts)?;
        }
    }

    *manifest = staged;
    manifest.get(asset_id).map_err(WorkflowError::Manifest)
}

pub fn record_original_asset_proof<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    proof: OriginalAssetProof,
) -> Result<&'a AssetRecord, WorkflowError> {
    let nas = stored_proof::<NasRawProof>(manifest, asset_id, NAS_PROOF)?;
    validate_original_asset_proof(&proof, &nas)?;
    insert_workflow_proof(manifest, asset_id, ORIGINAL_ASSET_PROOF, &proof)
}

pub fn record_original_asset_batch_proofs(
    manifest: &mut Manifest,
    asset_ids: &[String],
    proofs: BTreeMap<String, OriginalAssetProof>,
) -> Result<(), WorkflowError> {
    let requested: std::collections::BTreeSet<&str> =
        asset_ids.iter().map(String::as_str).collect();
    for asset_id in asset_ids {
        if !proofs.contains_key(asset_id) {
            return Err(WorkflowError::MissingBatchOriginalAssetProof {
                asset_id: asset_id.clone(),
            });
        }
    }
    for asset_id in proofs.keys() {
        if !requested.contains(asset_id.as_str()) {
            return Err(WorkflowError::UnexpectedBatchOriginalAssetProof {
                asset_id: asset_id.clone(),
            });
        }
    }
    validate_batch_original_asset_unique_records(asset_ids, &proofs)?;

    let mut staged = manifest.clone();
    for asset_id in asset_ids {
        let proof =
            proofs
                .get(asset_id)
                .ok_or_else(|| WorkflowError::MissingBatchOriginalAssetProof {
                    asset_id: asset_id.clone(),
                })?;
        record_original_asset_proof(&mut staged, asset_id, proof.clone())?;
    }
    *manifest = staged;
    Ok(())
}

fn validate_batch_original_asset_unique_records(
    asset_ids: &[String],
    proofs: &BTreeMap<String, OriginalAssetProof>,
) -> Result<(), WorkflowError> {
    let mut original_record_names = BTreeSet::new();
    for asset_id in asset_ids {
        let proof =
            proofs
                .get(asset_id)
                .ok_or_else(|| WorkflowError::MissingBatchOriginalAssetProof {
                    asset_id: asset_id.clone(),
                })?;
        if !original_record_names.insert(proof.record_name.as_str()) {
            return Err(WorkflowError::DuplicateBatchOriginalAssetProof {
                original_record_name: proof.record_name.clone(),
            });
        }
    }
    Ok(())
}

pub fn upload_ready_heic_proof(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<HeicVerificationProof, WorkflowError> {
    let record = manifest.get(asset_id)?;
    if record.state != State::ConversionVerified {
        return Err(WorkflowError::UploadUnavailable {
            asset_id: asset_id.to_string(),
            state: record.state,
        });
    }
    require_valid_conversion_performance(manifest, asset_id)?;
    let proof = stored_proof::<HeicVerificationProof>(manifest, asset_id, HEIC_PROOF)?;
    validate_heic_verification_flags(&proof)?;
    Ok(proof)
}

pub fn icloudpd_local_mirror_ready_proofs(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<(UploadProof, HeicVerificationProof), WorkflowError> {
    let state = manifest.get(asset_id)?.state;
    if !matches!(
        state,
        State::UploadVerified | State::DeleteEligible | State::DeleteApproved
    ) {
        return Err(WorkflowError::IcloudpdLocalMirrorUnavailable {
            asset_id: asset_id.to_string(),
            state,
        });
    }

    let (upload, heic, _) = validate_icloudpd_local_mirror_inputs(manifest, asset_id)?;
    Ok((upload, heic))
}

/// Validates the stored local-mirror proof against the current upload and HEIC
/// lineage without reading or hashing the mirrored file.
pub fn validate_current_icloudpd_local_mirror_proof(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<(), WorkflowError> {
    let proof =
        stored_proof::<IcloudpdLocalMirrorProof>(manifest, asset_id, ICLOUDPD_LOCAL_MIRROR_PROOF)?;
    validate_candidate_icloudpd_local_mirror(manifest, asset_id, &proof)
}

/// Classifies local-mirror work from one manifest snapshot without reading or
/// hashing media. Only a complete upstream conversion/HEIC/upload lineage can
/// make an absent or invalid mirror proof repairable.
pub fn icloudpd_local_mirror_proof_disposition(
    manifest: &Manifest,
    asset_id: &str,
) -> IcloudpdLocalMirrorProofDisposition {
    let Ok((upload, heic, uploaded_heic_path)) =
        validate_icloudpd_local_mirror_inputs(manifest, asset_id)
    else {
        return IcloudpdLocalMirrorProofDisposition::Blocked;
    };
    let Ok(proof) =
        stored_proof::<IcloudpdLocalMirrorProof>(manifest, asset_id, ICLOUDPD_LOCAL_MIRROR_PROOF)
    else {
        return IcloudpdLocalMirrorProofDisposition::Repairable;
    };
    if validate_icloudpd_local_mirror_proof(&proof, &upload, &uploaded_heic_path, &heic).is_ok() {
        IcloudpdLocalMirrorProofDisposition::Current
    } else {
        IcloudpdLocalMirrorProofDisposition::Repairable
    }
}

pub fn record_source_age_proof<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    proof: SourceAgeProof,
) -> Result<&'a AssetRecord, WorkflowError> {
    let state = manifest.get(asset_id)?.state;
    if source_age_proof_is_frozen(state) {
        return Err(WorkflowError::SourceAgeProofFrozen {
            asset_id: asset_id.to_string(),
            state,
        });
    }
    require_min_age_seconds(proof.min_age_seconds)?;
    require_proof(manifest, asset_id, NAS_PROOF)?;
    insert_workflow_proof(manifest, asset_id, SOURCE_AGE_PROOF, &proof)
}

pub fn mark_delete_eligible<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
) -> Result<&'a AssetRecord, WorkflowError> {
    let record = manifest.get(asset_id)?;
    if record.state != State::UploadVerified {
        return Err(WorkflowError::DeleteEligibilityUnavailable {
            asset_id: asset_id.to_string(),
            state: record.state,
        });
    }
    require_valid_conversion_performance(manifest, asset_id)?;
    let facts = validate_pre_delete_facts(manifest, asset_id)?;
    let proof = delete_eligibility_proof(&facts);

    manifest
        .transition(
            asset_id,
            State::DeleteEligible,
            DELETE_ELIGIBILITY_PROOF,
            proof,
        )
        .map_err(WorkflowError::Manifest)
}

pub fn approve_delete<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    operator: &str,
) -> Result<&'a AssetRecord, WorkflowError> {
    require_valid_conversion_performance(manifest, asset_id)?;

    let operator = operator.trim();
    if operator.is_empty() {
        return Err(WorkflowError::EmptyOperator);
    }

    let record = manifest.get(asset_id)?;
    if record.state != State::DeleteEligible {
        return Err(WorkflowError::Manifest(ManifestError::InvalidTransition {
            asset_id: asset_id.to_string(),
            from: record.state,
            to: State::DeleteApproved,
        }));
    }

    let facts = validate_pre_delete_facts(manifest, asset_id)?;
    validate_delete_eligibility_chain(manifest, asset_id, &facts)?;

    let proof = delete_approval_proof(operator, &facts);
    transition_with_proof(
        manifest,
        asset_id,
        State::DeleteApproved,
        DELETE_APPROVAL_PROOF,
        &proof,
    )
}

pub fn record_delete_execution<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    outcome: CloudKitDeleteOutcome,
) -> Result<&'a AssetRecord, WorkflowError> {
    let record = manifest.get(asset_id)?;
    if record.state != State::DeleteApproved {
        return Err(WorkflowError::Manifest(ManifestError::InvalidTransition {
            asset_id: asset_id.to_string(),
            from: record.state,
            to: State::Deleted,
        }));
    }

    revalidate_delete_plan_proofs(manifest, asset_id)?;
    let original = stored_proof::<OriginalAssetProof>(manifest, asset_id, ORIGINAL_ASSET_PROOF)?;
    let upload = stored_proof::<UploadProof>(manifest, asset_id, UPLOAD_PROOF)?;
    let proof = delete_execution_proof(
        &original.record_name,
        &original.record_change_tag,
        &upload.uploaded_heic_asset_id,
        outcome,
    )?;
    transition_with_proof(
        manifest,
        asset_id,
        State::Deleted,
        DELETE_EXECUTION_PROOF,
        &proof,
    )
}

pub fn record_prevalidated_delete_execution(
    manifest: &mut Manifest,
    prevalidated: PrevalidatedDelete,
    outcome: CloudKitDeleteOutcome,
) -> Result<&AssetRecord, WorkflowError> {
    let record = manifest.get(prevalidated.asset_id())?;
    if record.state != State::DeleteApproved {
        return Err(WorkflowError::Manifest(ManifestError::InvalidTransition {
            asset_id: prevalidated.asset_id.clone(),
            from: record.state,
            to: State::Deleted,
        }));
    }

    validate_prevalidated_delete(record, &prevalidated)?;
    let proof = delete_execution_proof(
        &prevalidated.request.record_name,
        &prevalidated.request.record_change_tag,
        &prevalidated.uploaded_heic_asset_id,
        outcome,
    )?;
    transition_with_proof(
        manifest,
        &prevalidated.asset_id,
        State::Deleted,
        DELETE_EXECUTION_PROOF,
        &proof,
    )
}

pub fn record_reconciled_delete_execution(
    manifest: &mut Manifest,
    reconciliation: DeleteReconciliation,
    outcome: CloudKitDeleteOutcome,
) -> Result<&AssetRecord, WorkflowError> {
    let record = manifest.get(reconciliation.asset_id())?;
    if record.state != State::DeleteApproved {
        return Err(WorkflowError::Manifest(ManifestError::InvalidTransition {
            asset_id: reconciliation.asset_id.clone(),
            from: record.state,
            to: State::Deleted,
        }));
    }

    validate_delete_token_snapshot(
        record,
        &reconciliation.asset_id,
        &reconciliation.raw_path,
        &reconciliation.proofs,
        DeleteTokenKind::Reconciliation,
    )?;
    let proof = delete_execution_proof(
        &reconciliation.request.record_name,
        &reconciliation.request.record_change_tag,
        &reconciliation.uploaded_heic_asset_id,
        outcome,
    )?;
    transition_with_proof(
        manifest,
        &reconciliation.asset_id,
        State::Deleted,
        DELETE_EXECUTION_PROOF,
        &proof,
    )
}

pub fn prevalidate_approved_original_delete(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<PrevalidatedDelete, WorkflowError> {
    let record = manifest.get(asset_id)?;
    if record.state != State::DeleteApproved {
        return Err(WorkflowError::DeletePlanUnavailable {
            asset_id: asset_id.to_string(),
            state: record.state,
        });
    }

    let facts = revalidate_delete_plan_proofs(manifest, asset_id)?;
    let original = stored_proof::<OriginalAssetProof>(manifest, asset_id, ORIGINAL_ASSET_PROOF)?;
    let upload = stored_proof::<UploadProof>(manifest, asset_id, UPLOAD_PROOF)?;
    let record = manifest.get(asset_id)?;

    Ok(PrevalidatedDelete {
        asset_id: record.asset_id.clone(),
        raw_path: record.raw_path.clone(),
        request: CloudKitDeleteRequest {
            record_name: original.record_name,
            record_change_tag: original.record_change_tag,
            database_scope: original.database_scope,
            zone_name: original.zone_name,
        },
        uploaded_heic_asset_id: upload.uploaded_heic_asset_id,
        proofs: delete_plan_proof_snapshot(record)?,
        raw_fingerprint: facts.raw_fingerprint,
        validated_at: SystemTime::now(),
    })
}

pub fn prepare_delete_reconciliation(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<DeleteReconciliation, WorkflowError> {
    let record = manifest.get(asset_id)?;
    if record.state != State::DeleteApproved {
        return Err(WorkflowError::DeletePlanUnavailable {
            asset_id: asset_id.to_string(),
            state: record.state,
        });
    }

    let facts = validate_stored_delete_plan_proofs(manifest, asset_id)?;
    let record = manifest.get(asset_id)?;

    Ok(DeleteReconciliation {
        asset_id: record.asset_id.clone(),
        raw_path: record.raw_path.clone(),
        request: CloudKitDeleteRequest {
            record_name: facts.original.record_name,
            record_change_tag: facts.original.record_change_tag,
            database_scope: facts.original.database_scope,
            zone_name: facts.original.zone_name,
        },
        uploaded_heic_asset_id: facts.upload.uploaded_heic_asset_id,
        proofs: delete_plan_proof_snapshot(record)?,
    })
}

pub fn approved_original_delete_request(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<CloudKitDeleteRequest, WorkflowError> {
    Ok(prevalidate_approved_original_delete(manifest, asset_id)?.request)
}

pub fn build_delete_plan(manifest: &Manifest, asset_id: &str) -> Result<DeletePlan, WorkflowError> {
    let record = manifest.get(asset_id)?;
    if record.state != State::DeleteApproved {
        return Err(WorkflowError::DeletePlanUnavailable {
            asset_id: asset_id.to_string(),
            state: record.state,
        });
    }

    revalidate_delete_plan_proofs(manifest, asset_id)?;

    Ok(DeletePlan {
        asset_id: record.asset_id.clone(),
        raw_path: record.raw_path.clone(),
        required_proof_keys: delete_plan_proof_keys(record)?
            .into_iter()
            .map(str::to_string)
            .collect(),
        proofs: delete_plan_proof_snapshot(record)?,
    })
}

fn delete_execution_proof(
    original_record_name: &str,
    original_record_change_tag: &str,
    uploaded_heic_asset_id: &str,
    outcome: CloudKitDeleteOutcome,
) -> Result<DeleteExecutionProof, WorkflowError> {
    require_matching_str(
        ORIGINAL_ASSET_PROOF,
        "record_name",
        original_record_name,
        &outcome.record_name,
    )?;
    require_non_empty("confirmed_deleted_change_tag", &outcome.record_change_tag)?;
    if outcome.record_change_tag == original_record_change_tag {
        return Err(WorkflowError::ProofMismatch {
            proof_key: DELETE_EXECUTION_PROOF,
            field: "confirmed_deleted_change_tag",
            expected: format!("new tag different from {original_record_change_tag}"),
            actual: outcome.record_change_tag,
        });
    }

    Ok(DeleteExecutionProof {
        old_record_change_tag: original_record_change_tag.to_string(),
        deleted_record_name: outcome.record_name,
        confirmed_deleted_change_tag: outcome.record_change_tag,
        uploaded_heic_asset_id: uploaded_heic_asset_id.to_string(),
    })
}

fn delete_plan_proof_snapshot(
    record: &AssetRecord,
) -> Result<BTreeMap<String, Value>, WorkflowError> {
    let mut proofs = BTreeMap::new();
    for proof_key in delete_plan_proof_keys(record)? {
        let proof = record
            .proofs
            .get(proof_key)
            .ok_or_else(|| WorkflowError::MissingProof {
                asset_id: record.asset_id.clone(),
                proof_key: proof_key.to_string(),
            })?;
        proofs.insert(proof_key.to_string(), proof.clone());
    }
    Ok(proofs)
}

fn delete_plan_proof_keys(record: &AssetRecord) -> Result<Vec<&'static str>, WorkflowError> {
    let mut proof_keys = BASE_DELETE_PLAN_PROOFS.to_vec();
    let conversion = optional_workflow_proof::<ConversionResultProof>(record, CONVERSION_PROOF)?
        .ok_or_else(|| WorkflowError::MissingProof {
            asset_id: record.asset_id.clone(),
            proof_key: CONVERSION_PROOF.to_string(),
        })?;
    if matches!(
        conversion.source_binding,
        ConversionSourceBinding::AdjustedSource { .. }
    ) {
        proof_keys.push(ADJUSTED_SOURCE_PROOF);
    }
    Ok(proof_keys)
}

fn validate_prevalidated_delete(
    record: &AssetRecord,
    prevalidated: &PrevalidatedDelete,
) -> Result<(), WorkflowError> {
    validate_delete_token_snapshot(
        record,
        &prevalidated.asset_id,
        &prevalidated.raw_path,
        &prevalidated.proofs,
        DeleteTokenKind::Prevalidated,
    )
}

#[derive(Clone, Copy)]
enum DeleteTokenKind {
    Prevalidated,
    Reconciliation,
}

fn validate_delete_token_snapshot(
    record: &AssetRecord,
    asset_id: &str,
    raw_path: &Path,
    proofs: &BTreeMap<String, Value>,
    token_kind: DeleteTokenKind,
) -> Result<(), WorkflowError> {
    if record.raw_path != raw_path {
        return delete_token_stale(token_kind, asset_id, "raw_path");
    }

    let proof_keys = delete_plan_proof_keys(record)?;
    if proofs.len() != proof_keys.len() {
        return delete_token_stale(token_kind, asset_id, "proof_set");
    }
    for proof_key in proof_keys {
        if record.proofs.get(proof_key) != proofs.get(proof_key) {
            return delete_token_stale(token_kind, asset_id, proof_key);
        }
    }
    Ok(())
}

fn delete_token_stale(
    token_kind: DeleteTokenKind,
    asset_id: &str,
    field: &str,
) -> Result<(), WorkflowError> {
    match token_kind {
        DeleteTokenKind::Prevalidated => Err(WorkflowError::PrevalidatedDeleteStale {
            asset_id: asset_id.to_string(),
            field: field.to_string(),
        }),
        DeleteTokenKind::Reconciliation => Err(WorkflowError::DeleteReconciliationStale {
            asset_id: asset_id.to_string(),
            field: field.to_string(),
        }),
    }
}

fn validate_prevalidated_delete_freshness(
    asset_id: &str,
    validated_at: SystemTime,
    max_age: Duration,
    now: SystemTime,
) -> Result<(), WorkflowError> {
    let age = now.duration_since(validated_at).map_err(|_| {
        WorkflowError::PrevalidatedDeleteClockMovedBackwards {
            asset_id: asset_id.to_string(),
        }
    })?;
    if age > max_age {
        return Err(WorkflowError::PrevalidatedDeleteExpired {
            asset_id: asset_id.to_string(),
            age_seconds: age.as_secs(),
            max_age_seconds: max_age.as_secs(),
        });
    }
    Ok(())
}

pub fn record_stage_failure<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    stage: &str,
    message: &str,
) -> Result<&'a AssetRecord, WorkflowError> {
    manifest
        .record_failure(asset_id, stage, message)
        .map_err(WorkflowError::Manifest)
}

pub fn record_stage_failure_with_kind<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    stage: &str,
    message: &str,
    kind: FailureKind,
) -> Result<&'a AssetRecord, WorkflowError> {
    manifest
        .record_failure_with_kind(asset_id, stage, message, Some(kind))
        .map_err(WorkflowError::Manifest)
}

fn revalidate_delete_plan_proofs(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<LiveDeleteFacts, WorkflowError> {
    let facts = validate_stored_delete_plan_proofs(manifest, asset_id)?;
    let record = manifest.get(asset_id)?;
    let nas = stored_proof::<NasRawProof>(manifest, asset_id, NAS_PROOF)?;
    let raw_fingerprint = reprove_nas_proof(record, &nas, facts.source_age.min_age_seconds)?;

    Ok(LiveDeleteFacts { raw_fingerprint })
}

fn validate_stored_delete_plan_proofs(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<PreDeleteFacts, WorkflowError> {
    let facts = validate_pre_delete_facts(manifest, asset_id)?;
    validate_delete_eligibility_chain(manifest, asset_id, &facts)?;
    validate_delete_approval_proof(manifest, asset_id, &facts)?;
    Ok(facts)
}

fn validate_pre_delete_facts(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<PreDeleteFacts, WorkflowError> {
    let record = manifest.get(asset_id)?;
    let (nas, conversion) = load_conversion_context(manifest, asset_id)?;
    let adjusted_source =
        validated_adjusted_source_for_conversion(manifest, asset_id, &conversion.heic_path)?;

    let heic = stored_proof::<HeicVerificationProof>(manifest, asset_id, HEIC_PROOF)?;
    require_matching_path(
        CONVERSION_PROOF,
        "heic_path",
        &conversion.heic_path,
        &heic.heic_path,
    )?;
    require_matching_str(
        CONVERSION_PROOF,
        "heic_sha256",
        &conversion.heic_sha256,
        &heic.heic_sha256,
    )?;
    require_matching_u64(
        CONVERSION_PROOF,
        "size_bytes",
        conversion.size_bytes,
        heic.size_bytes,
    )?;
    validate_heic_verification_flags(&heic)?;

    let upload = stored_proof::<UploadProof>(manifest, asset_id, UPLOAD_PROOF)?;
    require_non_empty("uploaded_heic_asset_id", &upload.uploaded_heic_asset_id)?;
    require_non_empty("uploaded_heic_sha256", &upload.uploaded_heic_sha256)?;
    let uploaded_heic_path =
        upload
            .uploaded_heic_path
            .clone()
            .ok_or(WorkflowError::EmptyProofField {
                field: "uploaded_heic_path",
            })?;
    require_non_empty_path("uploaded_heic_path", &uploaded_heic_path)?;
    require_matching_str(
        HEIC_PROOF,
        "uploaded_heic_sha256",
        &heic.heic_sha256,
        &upload.uploaded_heic_sha256,
    )?;
    require_matching_path(
        HEIC_PROOF,
        "uploaded_heic_path",
        &heic.heic_path,
        &uploaded_heic_path,
    )?;

    let source_age = stored_proof::<SourceAgeProof>(manifest, asset_id, SOURCE_AGE_PROOF)?;
    let source_age_seconds = source_age_seconds(asset_id, &source_age)?;
    validate_nas_proof(record, &nas, source_age.min_age_seconds)?;
    validate_stored_conversion_performance(manifest, asset_id, &nas, &conversion)?;
    let original = stored_proof::<OriginalAssetProof>(manifest, asset_id, ORIGINAL_ASSET_PROOF)?;
    validate_original_asset_proof(&original, &nas)?;
    require_matching_library_destination(UPLOAD_PROOF, &original, &upload)?;
    let mirror =
        stored_proof::<IcloudpdLocalMirrorProof>(manifest, asset_id, ICLOUDPD_LOCAL_MIRROR_PROOF)?;
    validate_icloudpd_local_mirror_proof(&mirror, &upload, &uploaded_heic_path, &heic)?;

    Ok(PreDeleteFacts {
        original,
        upload,
        uploaded_heic_path,
        heic,
        mirror,
        source_age,
        source_age_seconds,
        adjusted_source,
    })
}

fn validate_delete_eligibility_chain(
    manifest: &Manifest,
    asset_id: &str,
    facts: &PreDeleteFacts,
) -> Result<(), WorkflowError> {
    let eligibility =
        stored_proof::<DeleteEligibilityProof>(manifest, asset_id, DELETE_ELIGIBILITY_PROOF)?;
    validate_delete_eligibility_proof(
        &eligibility,
        DeleteEligibilityValidationFacts {
            original: &facts.original,
            upload: &facts.upload,
            uploaded_heic_path: &facts.uploaded_heic_path,
            heic: &facts.heic,
            mirror: &facts.mirror,
            source_age: &facts.source_age,
            source_age_seconds: facts.source_age_seconds,
            adjusted_source: facts.adjusted_source.as_ref(),
        },
    )?;

    Ok(())
}

fn validate_delete_approval_proof(
    manifest: &Manifest,
    asset_id: &str,
    facts: &PreDeleteFacts,
) -> Result<(), WorkflowError> {
    let approval = stored_proof::<DeleteApprovalProof>(manifest, asset_id, DELETE_APPROVAL_PROOF)?;
    if approval.operator.trim().is_empty() {
        return Err(WorkflowError::EmptyOperator);
    }

    let eligibility =
        stored_proof::<DeleteEligibilityProof>(manifest, asset_id, DELETE_ELIGIBILITY_PROOF)?;
    match &facts.adjusted_source {
        Some(adjusted_source) => {
            let digest = adjusted_source_proof_digest(adjusted_source);
            if approval.adjusted_source_proof_key.as_deref() != Some(ADJUSTED_SOURCE_PROOF)
                || eligibility.adjusted_source_proof_key.as_deref() != Some(ADJUSTED_SOURCE_PROOF)
            {
                return Err(WorkflowError::ProofMismatch {
                    proof_key: DELETE_APPROVAL_PROOF,
                    field: "adjusted_source_proof_key",
                    expected: ADJUSTED_SOURCE_PROOF.to_string(),
                    actual: approval
                        .adjusted_source_proof_key
                        .clone()
                        .unwrap_or_else(|| "<missing>".to_string()),
                });
            }
            require_matching_str(
                DELETE_APPROVAL_PROOF,
                "adjusted_source_proof_digest",
                &digest,
                approval
                    .adjusted_source_proof_digest
                    .as_deref()
                    .unwrap_or("<missing>"),
            )?;
            require_matching_str(
                DELETE_APPROVAL_PROOF,
                "eligibility_adjusted_source_proof_digest",
                approval
                    .adjusted_source_proof_digest
                    .as_deref()
                    .unwrap_or("<missing>"),
                eligibility
                    .adjusted_source_proof_digest
                    .as_deref()
                    .unwrap_or("<missing>"),
            )?;
        }
        None => {
            if approval.adjusted_source_proof_key.is_some()
                || approval.adjusted_source_proof_digest.is_some()
            {
                return Err(WorkflowError::InvalidProofField {
                    proof_key: DELETE_APPROVAL_PROOF,
                    field: "adjusted_source",
                    reason: "embedded-preview conversion must not claim adjusted-source lineage",
                });
            }
        }
    }

    Ok(())
}

fn delete_approval_proof(operator: &str, facts: &PreDeleteFacts) -> DeleteApprovalProof {
    let (adjusted_source_proof_key, adjusted_source_proof_digest) = facts
        .adjusted_source
        .as_ref()
        .map(|proof| {
            (
                Some(ADJUSTED_SOURCE_PROOF.to_string()),
                Some(adjusted_source_proof_digest(proof)),
            )
        })
        .unwrap_or((None, None));
    DeleteApprovalProof {
        operator: operator.to_string(),
        adjusted_source_proof_key,
        adjusted_source_proof_digest,
    }
}

fn delete_eligibility_proof(facts: &PreDeleteFacts) -> Value {
    let mut proof = json!({
        "upload_proof_key": UPLOAD_PROOF,
        "original_asset_proof_key": ORIGINAL_ASSET_PROOF,
        "conversion_performance_proof_key": CONVERSION_PERFORMANCE_PROOF,
        "heic_proof_key": HEIC_PROOF,
        "source_age_proof_key": SOURCE_AGE_PROOF,
        "icloudpd_local_mirror_proof_key": ICLOUDPD_LOCAL_MIRROR_PROOF,
        "original_database_scope": facts.original.database_scope,
        "original_zone_name": &facts.original.zone_name,
        "uploaded_database_scope": facts.upload.database_scope,
        "uploaded_zone_name": &facts.upload.zone_name,
        "uploaded_heic_asset_id": &facts.upload.uploaded_heic_asset_id,
        "uploaded_heic_sha256": &facts.upload.uploaded_heic_sha256,
        "uploaded_heic_path": &facts.uploaded_heic_path,
        "verified_heic_sha256": &facts.heic.heic_sha256,
        "verified_heic_path": &facts.heic.heic_path,
        "icloudpd_download_path": &facts.mirror.icloudpd_download_path,
        "mirrored_heic_sha256": &facts.mirror.uploaded_heic_sha256,
        "mirrored_size_bytes": facts.mirror.size_bytes,
        "source_captured_unix_seconds": facts.source_age.source_captured_unix_seconds,
        "source_age_seconds": facts.source_age_seconds,
        "min_source_age_seconds": facts.source_age.min_age_seconds,
        "original_record_name": &facts.original.record_name,
        "original_record_change_tag": &facts.original.record_change_tag,
        "original_record_type": &facts.original.record_type,
        "original_filename": &facts.original.filename,
        "original_size_bytes": facts.original.size_bytes,
        "matched_raw_sha256": &facts.original.matched_raw_sha256,
    });
    if let Some(adjusted_source) = &facts.adjusted_source {
        proof["adjusted_source_proof_key"] = json!(ADJUSTED_SOURCE_PROOF);
        proof["adjusted_source_proof_digest"] =
            json!(adjusted_source_proof_digest(adjusted_source));
    }
    proof
}

fn validate_nas_proof(
    record: &AssetRecord,
    proof: &NasRawProof,
    min_age_seconds: u64,
) -> Result<(), WorkflowError> {
    require_non_empty_path("canonical_path", &proof.canonical_path)?;
    require_non_empty_path("relative_path", &proof.relative_path)?;
    require_positive_u64(NAS_PROOF, "size_bytes", proof.size_bytes)?;
    require_non_empty("sha256", &proof.sha256)?;

    if proof.age_seconds < min_age_seconds {
        return Err(WorkflowError::NasProofTooNew {
            asset_id: record.asset_id.clone(),
            age_seconds: proof.age_seconds,
            min_age_seconds,
        });
    }

    require_matching_path(
        NAS_PROOF,
        "canonical_path",
        &record.raw_path,
        &proof.canonical_path,
    )?;

    Ok(())
}

fn reprove_nas_proof(
    record: &AssetRecord,
    proof: &NasRawProof,
    min_age_seconds: u64,
) -> Result<RawFileFingerprint, WorkflowError> {
    let nas_root = derive_nas_root_from_proof(proof)?;
    let live = prove_nas_raw_with_min_age_seconds_and_fingerprint(
        &nas_root,
        &proof.canonical_path,
        min_age_seconds,
        SystemTime::now(),
    )?;
    let live_proof = &live.proof;

    require_matching_path(
        NAS_PROOF,
        "canonical_path",
        &proof.canonical_path,
        &live_proof.canonical_path,
    )?;
    require_matching_path(
        NAS_PROOF,
        "relative_path",
        &proof.relative_path,
        &live_proof.relative_path,
    )?;
    require_matching_u64(
        NAS_PROOF,
        "size_bytes",
        proof.size_bytes,
        live_proof.size_bytes,
    )?;
    require_matching_u64(
        NAS_PROOF,
        "modified_unix_seconds",
        proof.modified_unix_seconds,
        live_proof.modified_unix_seconds,
    )?;
    if live_proof.age_seconds < proof.age_seconds {
        return Err(WorkflowError::ProofMismatch {
            proof_key: NAS_PROOF,
            field: "age_seconds",
            expected: format!(">= {}", proof.age_seconds),
            actual: live_proof.age_seconds.to_string(),
        });
    }
    if live_proof.age_seconds < min_age_seconds {
        return Err(WorkflowError::NasProofTooNew {
            asset_id: record.asset_id.clone(),
            age_seconds: live_proof.age_seconds,
            min_age_seconds,
        });
    }
    require_matching_str(NAS_PROOF, "sha256", &proof.sha256, &live_proof.sha256)?;

    Ok(live.raw_fingerprint)
}

fn derive_nas_root_from_proof(proof: &NasRawProof) -> Result<PathBuf, WorkflowError> {
    if proof.relative_path.as_os_str().is_empty() {
        return Err(WorkflowError::EmptyProofField {
            field: "relative_path",
        });
    }
    if proof
        .relative_path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(WorkflowError::InvalidProofField {
            proof_key: NAS_PROOF,
            field: "relative_path",
            reason: "must be a relative path without prefix or parent components",
        });
    }

    let mut root = proof.canonical_path.clone();
    for _ in proof.relative_path.components() {
        if !root.pop() {
            return Err(WorkflowError::InvalidProofField {
                proof_key: NAS_PROOF,
                field: "relative_path",
                reason: "must be a suffix of canonical_path",
            });
        }
    }
    if root.as_os_str().is_empty() || root.join(&proof.relative_path) != proof.canonical_path {
        return Err(WorkflowError::InvalidProofField {
            proof_key: NAS_PROOF,
            field: "relative_path",
            reason: "must be a suffix of canonical_path",
        });
    }

    Ok(root)
}

fn validate_candidate_icloudpd_local_mirror(
    manifest: &Manifest,
    asset_id: &str,
    proof: &IcloudpdLocalMirrorProof,
) -> Result<(), WorkflowError> {
    let (upload, heic, uploaded_heic_path) =
        validate_icloudpd_local_mirror_inputs(manifest, asset_id)?;
    validate_icloudpd_local_mirror_proof(proof, &upload, &uploaded_heic_path, &heic)
}

fn validate_icloudpd_local_mirror_inputs(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<(UploadProof, HeicVerificationProof, PathBuf), WorkflowError> {
    let (_, conversion) = require_valid_conversion_performance(manifest, asset_id)?;
    let heic = stored_proof::<HeicVerificationProof>(manifest, asset_id, HEIC_PROOF)?;
    require_matching_path(
        CONVERSION_PROOF,
        "heic_path",
        &conversion.heic_path,
        &heic.heic_path,
    )?;
    require_matching_str(
        CONVERSION_PROOF,
        "heic_sha256",
        &conversion.heic_sha256,
        &heic.heic_sha256,
    )?;
    require_matching_u64(
        CONVERSION_PROOF,
        "size_bytes",
        conversion.size_bytes,
        heic.size_bytes,
    )?;
    validate_heic_verification_flags(&heic)?;
    let upload = stored_proof::<UploadProof>(manifest, asset_id, UPLOAD_PROOF)?;
    require_non_empty("uploaded_heic_asset_id", &upload.uploaded_heic_asset_id)?;
    require_non_empty("uploaded_heic_sha256", &upload.uploaded_heic_sha256)?;
    let uploaded_heic_path =
        upload
            .uploaded_heic_path
            .clone()
            .ok_or(WorkflowError::EmptyProofField {
                field: "uploaded_heic_path",
            })?;
    require_non_empty_path("uploaded_heic_path", &uploaded_heic_path)?;
    require_matching_str(
        HEIC_PROOF,
        "uploaded_heic_sha256",
        &heic.heic_sha256,
        &upload.uploaded_heic_sha256,
    )?;
    require_matching_path(
        HEIC_PROOF,
        "uploaded_heic_path",
        &heic.heic_path,
        &uploaded_heic_path,
    )?;

    Ok((upload, heic, uploaded_heic_path))
}

fn validate_icloudpd_local_mirror_proof(
    proof: &IcloudpdLocalMirrorProof,
    upload: &UploadProof,
    uploaded_heic_path: &Path,
    heic: &HeicVerificationProof,
) -> Result<(), WorkflowError> {
    require_non_empty("uploaded_heic_asset_id", &proof.uploaded_heic_asset_id)?;
    require_non_empty("uploaded_heic_sha256", &proof.uploaded_heic_sha256)?;
    require_non_empty_path("uploaded_heic_path", &proof.uploaded_heic_path)?;
    require_non_empty_path("icloudpd_download_path", &proof.icloudpd_download_path)?;
    require_positive_u64(ICLOUDPD_LOCAL_MIRROR_PROOF, "size_bytes", proof.size_bytes)?;
    require_matching_str(
        ICLOUDPD_LOCAL_MIRROR_PROOF,
        "uploaded_heic_asset_id",
        &upload.uploaded_heic_asset_id,
        &proof.uploaded_heic_asset_id,
    )?;
    require_matching_str(
        ICLOUDPD_LOCAL_MIRROR_PROOF,
        "uploaded_heic_sha256",
        &upload.uploaded_heic_sha256,
        &proof.uploaded_heic_sha256,
    )?;
    require_matching_str(
        ICLOUDPD_LOCAL_MIRROR_PROOF,
        "uploaded_heic_sha256",
        &heic.heic_sha256,
        &proof.uploaded_heic_sha256,
    )?;
    require_matching_path(
        ICLOUDPD_LOCAL_MIRROR_PROOF,
        "uploaded_heic_path",
        uploaded_heic_path,
        &proof.uploaded_heic_path,
    )?;
    require_matching_path(
        ICLOUDPD_LOCAL_MIRROR_PROOF,
        "uploaded_heic_path",
        &heic.heic_path,
        &proof.uploaded_heic_path,
    )?;
    require_matching_u64(
        ICLOUDPD_LOCAL_MIRROR_PROOF,
        "size_bytes",
        heic.size_bytes,
        proof.size_bytes,
    )?;

    Ok(())
}

fn validate_delete_eligibility_proof(
    eligibility: &DeleteEligibilityProof,
    facts: DeleteEligibilityValidationFacts<'_>,
) -> Result<(), WorkflowError> {
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "upload_proof_key",
        UPLOAD_PROOF,
        &eligibility.upload_proof_key,
    )?;
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "original_asset_proof_key",
        ORIGINAL_ASSET_PROOF,
        &eligibility.original_asset_proof_key,
    )?;
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "conversion_performance_proof_key",
        CONVERSION_PERFORMANCE_PROOF,
        &eligibility.conversion_performance_proof_key,
    )?;
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "heic_proof_key",
        HEIC_PROOF,
        &eligibility.heic_proof_key,
    )?;
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "source_age_proof_key",
        SOURCE_AGE_PROOF,
        &eligibility.source_age_proof_key,
    )?;
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "icloudpd_local_mirror_proof_key",
        ICLOUDPD_LOCAL_MIRROR_PROOF,
        &eligibility.icloudpd_local_mirror_proof_key,
    )?;
    match facts.adjusted_source {
        Some(adjusted_source) => {
            if eligibility.adjusted_source_proof_key.as_deref() != Some(ADJUSTED_SOURCE_PROOF) {
                return Err(WorkflowError::ProofMismatch {
                    proof_key: DELETE_ELIGIBILITY_PROOF,
                    field: "adjusted_source_proof_key",
                    expected: ADJUSTED_SOURCE_PROOF.to_string(),
                    actual: eligibility
                        .adjusted_source_proof_key
                        .clone()
                        .unwrap_or_else(|| "<missing>".to_string()),
                });
            }
            require_matching_str(
                DELETE_ELIGIBILITY_PROOF,
                "adjusted_source_proof_digest",
                &adjusted_source_proof_digest(adjusted_source),
                eligibility
                    .adjusted_source_proof_digest
                    .as_deref()
                    .unwrap_or("<missing>"),
            )?;
        }
        None => {
            if eligibility.adjusted_source_proof_key.is_some()
                || eligibility.adjusted_source_proof_digest.is_some()
            {
                return Err(WorkflowError::InvalidProofField {
                    proof_key: DELETE_ELIGIBILITY_PROOF,
                    field: "adjusted_source",
                    reason: "embedded-preview conversion must not claim adjusted-source lineage",
                });
            }
        }
    }
    if facts.original.database_scope != eligibility.original_database_scope {
        return Err(WorkflowError::ProofMismatch {
            proof_key: DELETE_ELIGIBILITY_PROOF,
            field: "original_database_scope",
            expected: facts.original.database_scope.as_str().to_string(),
            actual: eligibility.original_database_scope.as_str().to_string(),
        });
    }
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "original_zone_name",
        &facts.original.zone_name,
        &eligibility.original_zone_name,
    )?;
    if facts.upload.database_scope != eligibility.uploaded_database_scope {
        return Err(WorkflowError::ProofMismatch {
            proof_key: DELETE_ELIGIBILITY_PROOF,
            field: "uploaded_database_scope",
            expected: facts.upload.database_scope.as_str().to_string(),
            actual: eligibility.uploaded_database_scope.as_str().to_string(),
        });
    }
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "uploaded_zone_name",
        &facts.upload.zone_name,
        &eligibility.uploaded_zone_name,
    )?;
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "uploaded_heic_asset_id",
        &facts.upload.uploaded_heic_asset_id,
        &eligibility.uploaded_heic_asset_id,
    )?;
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "uploaded_heic_sha256",
        &facts.upload.uploaded_heic_sha256,
        &eligibility.uploaded_heic_sha256,
    )?;
    require_matching_path(
        DELETE_ELIGIBILITY_PROOF,
        "uploaded_heic_path",
        facts.uploaded_heic_path,
        &eligibility.uploaded_heic_path,
    )?;
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "verified_heic_sha256",
        &facts.heic.heic_sha256,
        &eligibility.verified_heic_sha256,
    )?;
    require_matching_path(
        DELETE_ELIGIBILITY_PROOF,
        "verified_heic_path",
        &facts.heic.heic_path,
        &eligibility.verified_heic_path,
    )?;
    require_matching_path(
        DELETE_ELIGIBILITY_PROOF,
        "icloudpd_download_path",
        &facts.mirror.icloudpd_download_path,
        &eligibility.icloudpd_download_path,
    )?;
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "mirrored_heic_sha256",
        &facts.mirror.uploaded_heic_sha256,
        &eligibility.mirrored_heic_sha256,
    )?;
    require_matching_u64(
        DELETE_ELIGIBILITY_PROOF,
        "mirrored_size_bytes",
        facts.mirror.size_bytes,
        eligibility.mirrored_size_bytes,
    )?;
    require_matching_u64(
        DELETE_ELIGIBILITY_PROOF,
        "source_captured_unix_seconds",
        facts.source_age.source_captured_unix_seconds,
        eligibility.source_captured_unix_seconds,
    )?;
    require_matching_u64(
        DELETE_ELIGIBILITY_PROOF,
        "source_age_seconds",
        facts.source_age_seconds,
        eligibility.source_age_seconds,
    )?;
    require_matching_u64(
        DELETE_ELIGIBILITY_PROOF,
        "min_source_age_seconds",
        facts.source_age.min_age_seconds,
        eligibility.min_source_age_seconds,
    )?;
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "original_record_name",
        &facts.original.record_name,
        &eligibility.original_record_name,
    )?;
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "original_record_change_tag",
        &facts.original.record_change_tag,
        &eligibility.original_record_change_tag,
    )?;
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "original_record_type",
        &facts.original.record_type,
        &eligibility.original_record_type,
    )?;
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "original_filename",
        &facts.original.filename,
        &eligibility.original_filename,
    )?;
    require_matching_u64(
        DELETE_ELIGIBILITY_PROOF,
        "original_size_bytes",
        facts.original.size_bytes,
        eligibility.original_size_bytes,
    )?;
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "matched_raw_sha256",
        &facts.original.matched_raw_sha256,
        &eligibility.matched_raw_sha256,
    )?;

    Ok(())
}

fn validate_original_asset_proof(
    proof: &OriginalAssetProof,
    nas: &NasRawProof,
) -> Result<(), WorkflowError> {
    require_non_empty("record_name", &proof.record_name)?;
    require_non_empty("record_change_tag", &proof.record_change_tag)?;
    require_non_empty("filename", &proof.filename)?;
    require_non_empty("zone_name", &proof.zone_name)?;
    require_matching_str(
        ORIGINAL_ASSET_PROOF,
        "record_type",
        "CPLAsset",
        &proof.record_type,
    )?;
    require_matching_u64(NAS_PROOF, "size_bytes", nas.size_bytes, proof.size_bytes)?;
    require_matching_str(
        NAS_PROOF,
        "matched_raw_sha256",
        &nas.sha256,
        &proof.matched_raw_sha256,
    )?;

    Ok(())
}

fn require_matching_library_destination(
    proof_key: &'static str,
    original: &OriginalAssetProof,
    upload: &UploadProof,
) -> Result<(), WorkflowError> {
    if original.database_scope != upload.database_scope {
        return Err(WorkflowError::ProofMismatch {
            proof_key,
            field: "database_scope",
            expected: original.database_scope.as_str().to_string(),
            actual: upload.database_scope.as_str().to_string(),
        });
    }
    require_matching_str(
        proof_key,
        "zone_name",
        &original.zone_name,
        &upload.zone_name,
    )
}

fn uploaded_heic_delete_inputs(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<(UploadProof, HeicVerificationProof), WorkflowError> {
    manifest.get(asset_id)?;
    let upload = stored_proof::<UploadProof>(manifest, asset_id, UPLOAD_PROOF)?;
    require_non_empty("uploaded_heic_asset_id", &upload.uploaded_heic_asset_id)?;
    require_non_empty("uploaded_heic_sha256", &upload.uploaded_heic_sha256)?;
    let uploaded_heic_path =
        upload
            .uploaded_heic_path
            .as_ref()
            .ok_or(WorkflowError::EmptyProofField {
                field: "uploaded_heic_path",
            })?;
    require_non_empty_path("uploaded_heic_path", uploaded_heic_path)?;
    let heic = stored_proof::<HeicVerificationProof>(manifest, asset_id, HEIC_PROOF)?;
    validate_heic_verification_flags(&heic)?;
    require_matching_str(
        HEIC_PROOF,
        "uploaded_heic_sha256",
        &heic.heic_sha256,
        &upload.uploaded_heic_sha256,
    )?;
    require_matching_path(
        HEIC_PROOF,
        "uploaded_heic_path",
        &heic.heic_path,
        uploaded_heic_path,
    )?;
    require_positive_u64(HEIC_PROOF, "size_bytes", heic.size_bytes)?;
    if let Ok(original) =
        stored_proof::<OriginalAssetProof>(manifest, asset_id, ORIGINAL_ASSET_PROOF)
        && original.record_name == upload.uploaded_heic_asset_id
    {
        return Err(WorkflowError::InvalidProofField {
            proof_key: UPLOAD_PROOF,
            field: "uploaded_heic_asset_id",
            reason: "uploaded HEIC asset id must not match the original RAW asset record",
        });
    }
    Ok((upload, heic))
}

fn validate_uploaded_heic_delete_proof(
    proof: &UploadedHeicDeleteProof,
) -> Result<(), WorkflowError> {
    require_non_empty("uploaded_heic_asset_id", &proof.uploaded_heic_asset_id)?;
    require_non_empty(
        "uploaded_heic_master_record_name",
        &proof.uploaded_heic_master_record_name,
    )?;
    require_non_empty("matched_heic_sha256", &proof.matched_heic_sha256)?;
    require_positive_u64(UPLOADED_HEIC_DELETE_PROOF, "size_bytes", proof.size_bytes)?;
    require_non_empty("old_record_change_tag", &proof.old_record_change_tag)?;
    require_non_empty("deleted_record_name", &proof.deleted_record_name)?;
    require_non_empty(
        "confirmed_deleted_change_tag",
        &proof.confirmed_deleted_change_tag,
    )?;
    require_matching_str(
        UPLOADED_HEIC_DELETE_PROOF,
        "deleted_record_name",
        &proof.uploaded_heic_asset_id,
        &proof.deleted_record_name,
    )?;
    Ok(())
}

fn validate_heic_verification_flags(proof: &HeicVerificationProof) -> Result<(), WorkflowError> {
    require_current_conversion_recipe(HEIC_PROOF, &proof.conversion_recipe_id)?;
    validate_heic_verification_flags_legacy(proof)
}

fn validate_heic_verification_flags_legacy(
    proof: &HeicVerificationProof,
) -> Result<(), WorkflowError> {
    let required = [
        ("heif_info_ok", proof.heif_info_ok),
        ("metadata_copied", proof.metadata_copied),
        ("visual_content_ok", proof.visual_content_ok),
        ("visual_match_ok", proof.visual_match_ok),
    ];

    for (field, value) in required {
        if !value {
            return Err(WorkflowError::HeicVerificationFailed { field });
        }
    }

    Ok(())
}

fn validate_conversion_performance_proof(
    proof: &ConversionPerformanceProof,
    nas: &NasRawProof,
    conversion: &ConversionResultProof,
) -> Result<(), WorkflowError> {
    require_matching_u64(
        CONVERSION_PERFORMANCE_PROOF,
        "schema_version",
        u64::from(CONVERSION_PERFORMANCE_SCHEMA_VERSION),
        u64::from(proof.schema_version),
    )?;
    require_matching_str(
        CONVERSION_PERFORMANCE_PROOF,
        "measurement_method",
        CONVERSION_PERFORMANCE_MEASUREMENT_METHOD,
        &proof.measurement_method,
    )?;
    require_non_empty("conversion_tool", &proof.conversion_tool)?;
    if proof.conversion_tool == UNSAFE_LEGACY_RAW_SENSOR_RENDER_TOOL {
        return Err(WorkflowError::InvalidProofField {
            proof_key: CONVERSION_PERFORMANCE_PROOF,
            field: "conversion_tool",
            reason: "legacy RAW sensor render is not upload-safe; rerun conversion with the embedded-preview auto-orient path",
        });
    }
    if let Some(version) = &proof.conversion_tool_version {
        require_non_empty("conversion_tool_version", version)?;
    }
    if !(1..=100).contains(&proof.heic_quality) {
        return Err(WorkflowError::InvalidProofField {
            proof_key: CONVERSION_PERFORMANCE_PROOF,
            field: "heic_quality",
            reason: "must be between 1 and 100",
        });
    }
    require_positive_u64(
        CONVERSION_PERFORMANCE_PROOF,
        "measured_at_unix_seconds",
        proof.measured_at_unix_seconds,
    )?;
    require_positive_u64(
        CONVERSION_PERFORMANCE_PROOF,
        "convert_wall_time_millis",
        proof.convert_wall_time_millis,
    )?;
    require_positive_u64(
        CONVERSION_PERFORMANCE_PROOF,
        "total_wall_time_millis",
        proof.total_wall_time_millis,
    )?;
    if proof.total_wall_time_millis < proof.convert_wall_time_millis {
        return Err(WorkflowError::InvalidProofField {
            proof_key: CONVERSION_PERFORMANCE_PROOF,
            field: "total_wall_time_millis",
            reason: "must be greater than or equal to convert_wall_time_millis",
        });
    }
    if matches!(proof.peak_rss_kib, Some(0)) {
        return Err(WorkflowError::InvalidProofField {
            proof_key: CONVERSION_PERFORMANCE_PROOF,
            field: "peak_rss_kib",
            reason: "must be greater than zero",
        });
    }
    for command_timing in &proof.conversion_command_timings {
        require_non_empty(
            "conversion_command_timings.program",
            &command_timing.program,
        )?;
        require_positive_u64(
            CONVERSION_PERFORMANCE_PROOF,
            "conversion_command_timings.wall_time_millis",
            command_timing.wall_time_millis,
        )?;
    }
    require_matching_u64(
        CONVERSION_PERFORMANCE_PROOF,
        "raw_size_bytes",
        nas.size_bytes,
        proof.raw_size_bytes,
    )?;
    require_matching_u64(
        CONVERSION_PERFORMANCE_PROOF,
        "heic_size_bytes",
        conversion.size_bytes,
        proof.heic_size_bytes,
    )?;
    if proof.heic_size_bytes >= proof.raw_size_bytes {
        return Err(WorkflowError::InvalidProofField {
            proof_key: CONVERSION_PERFORMANCE_PROOF,
            field: "heic_size_bytes",
            reason: "replacement HEIC must be smaller than the original RAW",
        });
    }

    Ok(())
}

fn load_conversion_context(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<(NasRawProof, ConversionResultProof), WorkflowError> {
    let nas = stored_proof::<NasRawProof>(manifest, asset_id, NAS_PROOF)?;
    let conversion = stored_proof::<ConversionResultProof>(manifest, asset_id, CONVERSION_PROOF)?;
    validate_conversion_source_binding(manifest, asset_id, &conversion)?;
    Ok((nas, conversion))
}

/// Returns the source proof that an imminent conversion must consume, if one
/// was durably recorded. This deliberately reuses the descriptor-safe local
/// JPEG validator immediately before command planning.
pub fn validated_adjusted_source_for_conversion(
    manifest: &Manifest,
    asset_id: &str,
    output_path: impl AsRef<Path>,
) -> Result<Option<CloudKitAdjustedSourceProof>, WorkflowError> {
    let adjusted_source = stored_adjusted_source_for_conversion(manifest, asset_id, &output_path)?;
    if let Some(proof) = &adjusted_source {
        let original =
            stored_proof::<OriginalAssetProof>(manifest, asset_id, ORIGINAL_ASSET_PROOF)?;
        validate_installed_adjusted_source_proof(proof, asset_id, &original, output_path)
            .map_err(WorkflowError::AdjustedSource)?;
    }
    Ok(adjusted_source)
}

/// Loads and validates durable adjusted-source lineage without reopening the
/// source path. Pixel consumers must materialize it separately.
pub fn stored_adjusted_source_for_conversion(
    manifest: &Manifest,
    asset_id: &str,
    output_path: impl AsRef<Path>,
) -> Result<Option<CloudKitAdjustedSourceProof>, WorkflowError> {
    let record = manifest.get(asset_id)?;
    let Some(proof) =
        optional_workflow_proof::<CloudKitAdjustedSourceProof>(record, ADJUSTED_SOURCE_PROOF)?
    else {
        return Ok(None);
    };
    let original = stored_proof::<OriginalAssetProof>(manifest, asset_id, ORIGINAL_ASSET_PROOF)?;
    validate_adjusted_source_proof_lineage(&proof, asset_id, &original, output_path)
        .map_err(WorkflowError::AdjustedSource)?;
    Ok(Some(proof))
}

/// Creates the private, RAII-owned adjusted JPEG conversion input after the
/// durable lineage has been checked. This is the only workflow path that turns
/// an adjusted proof pathname into encoder input.
pub fn materialize_adjusted_source_for_conversion(
    manifest: &Manifest,
    asset_id: &str,
    output_path: impl AsRef<Path>,
) -> Result<Option<MaterializedAdjustedSource>, WorkflowError> {
    let Some(proof) = stored_adjusted_source_for_conversion(manifest, asset_id, &output_path)?
    else {
        return Ok(None);
    };
    let original = stored_proof::<OriginalAssetProof>(manifest, asset_id, ORIGINAL_ASSET_PROOF)?;
    materialize_adjusted_source(&proof, asset_id, &original, output_path)
        .map(Some)
        .map_err(WorkflowError::AdjustedSource)
}

fn validate_conversion_source_binding(
    manifest: &Manifest,
    asset_id: &str,
    conversion: &ConversionResultProof,
) -> Result<Option<CloudKitAdjustedSourceProof>, WorkflowError> {
    let adjusted_source =
        stored_adjusted_source_for_conversion(manifest, asset_id, &conversion.heic_path)?;
    match (&adjusted_source, &conversion.source_binding) {
        (None, ConversionSourceBinding::EmbeddedPreview) => Ok(None),
        (None, ConversionSourceBinding::AdjustedSource { .. }) => {
            Err(WorkflowError::ConversionSourceBindingMismatch {
                asset_id: asset_id.to_string(),
                reason: "adjusted conversion has no adjusted-source proof",
            })
        }
        (Some(_), ConversionSourceBinding::EmbeddedPreview) => {
            Err(WorkflowError::ConversionSourceBindingMismatch {
                asset_id: asset_id.to_string(),
                reason: "adjusted-source proof requires adjusted conversion lineage",
            })
        }
        (
            Some(proof),
            ConversionSourceBinding::AdjustedSource {
                adjusted_source_proof_digest: binding_proof_digest,
                adjusted_jpeg_sha256,
                adjusted_jpeg_path,
            },
        ) => {
            if binding_proof_digest != &adjusted_source_proof_digest(proof)
                || adjusted_jpeg_sha256 != &proof.downloaded_sha256
                || adjusted_jpeg_path != &proof.local_path
            {
                return Err(WorkflowError::ConversionSourceBindingMismatch {
                    asset_id: asset_id.to_string(),
                    reason: "adjusted conversion binding differs from current adjusted-source proof",
                });
            }
            Ok(adjusted_source)
        }
    }
}

fn require_valid_conversion_performance(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<(NasRawProof, ConversionResultProof), WorkflowError> {
    let (nas, conversion) = load_conversion_context(manifest, asset_id)?;
    validate_stored_conversion_performance(manifest, asset_id, &nas, &conversion)?;
    Ok((nas, conversion))
}

pub(crate) fn reconciliation_lifecycle_state(
    manifest: &Manifest,
    asset_id: &str,
    destination: &CloudKitLibraryDestination,
) -> Result<State, WorkflowError> {
    let record = manifest.get(asset_id)?;
    let conversion = optional_workflow_proof::<ConversionResultProof>(record, CONVERSION_PROOF)?;
    let heic = optional_workflow_proof::<HeicVerificationProof>(record, HEIC_PROOF)?;
    let upload = optional_workflow_proof::<UploadProof>(record, UPLOAD_PROOF)?;

    let Some(conversion) = conversion else {
        if heic.is_some() || upload.is_some() {
            return Err(WorkflowError::InvalidProofField {
                proof_key: CONVERSION_PROOF,
                field: "lifecycle",
                reason: "HEIC or upload proof exists without conversion",
            });
        }
        return Ok(State::NasVerified);
    };
    if conversion.heic_path.as_os_str().is_empty()
        || !is_sha256(&conversion.heic_sha256)
        || conversion.size_bytes == 0
    {
        return Err(WorkflowError::InvalidProofField {
            proof_key: CONVERSION_PROOF,
            field: "conversion",
            reason: "conversion output path, SHA-256, and size are required",
        });
    }
    validate_conversion_source_binding(manifest, asset_id, &conversion)?;

    let Some(heic) = heic else {
        if upload.is_some() {
            return Err(WorkflowError::InvalidProofField {
                proof_key: UPLOAD_PROOF,
                field: "lifecycle",
                reason: "upload proof exists without HEIC verification",
            });
        }
        return Ok(State::Converted);
    };
    validate_heic_verification_flags_legacy(&heic)?;
    if heic.heic_path.as_os_str().is_empty()
        || !is_sha256(&heic.heic_sha256)
        || heic.size_bytes == 0
        || heic.heic_path != conversion.heic_path
        || heic.heic_sha256 != conversion.heic_sha256
        || heic.size_bytes != conversion.size_bytes
    {
        return Err(WorkflowError::InvalidProofField {
            proof_key: HEIC_PROOF,
            field: "conversion",
            reason: "HEIC proof must match the conversion output path, SHA-256, and size",
        });
    }
    // Existing records are classified without implicitly rewriting or upgrading
    // them; upload and delete admission independently require the current recipe.
    let _ = stored_proof::<ConversionPerformanceProof>(
        manifest,
        asset_id,
        CONVERSION_PERFORMANCE_PROOF,
    )?;

    let Some(upload) = upload else {
        return Ok(State::ConversionVerified);
    };
    let uploaded_heic_path =
        upload
            .uploaded_heic_path
            .as_ref()
            .ok_or(WorkflowError::InvalidProofField {
                proof_key: UPLOAD_PROOF,
                field: "uploaded_heic_path",
                reason: "is required",
            })?;
    if !is_safe_identity(&upload.uploaded_heic_asset_id)
        || !is_sha256(&upload.uploaded_heic_sha256)
        || uploaded_heic_path.as_os_str().is_empty()
        || uploaded_heic_path != &heic.heic_path
        || upload.uploaded_heic_sha256 != heic.heic_sha256
        || upload.database_scope != destination.database_scope
        || upload.zone_name != destination.zone_name
    {
        return Err(WorkflowError::InvalidProofField {
            proof_key: UPLOAD_PROOF,
            field: "HEIC",
            reason: "upload proof must match the verified HEIC and destination",
        });
    }
    Ok(State::UploadVerified)
}

pub(crate) fn reconciliation_exact_state_is_consistent(
    manifest: &Manifest,
    asset_id: &str,
    destination: &CloudKitLibraryDestination,
) -> Result<bool, WorkflowError> {
    let record = manifest.get(asset_id)?;
    let lifecycle_state = reconciliation_lifecycle_state(manifest, asset_id, destination)?;
    let has_eligibility = record.proofs.contains_key(DELETE_ELIGIBILITY_PROOF);
    let has_approval = record.proofs.contains_key(DELETE_APPROVAL_PROOF);
    let has_delete = record.proofs.contains_key(DELETE_EXECUTION_PROOF);

    match record.state {
        State::NasVerified
        | State::Converted
        | State::ConversionVerified
        | State::UploadVerified => {
            Ok(record.state == lifecycle_state && !has_eligibility && !has_approval && !has_delete)
        }
        State::DeleteEligible => {
            if lifecycle_state != State::UploadVerified || has_approval || has_delete {
                return Ok(false);
            }
            let facts = validate_pre_delete_facts(manifest, asset_id)?;
            validate_delete_eligibility_chain(manifest, asset_id, &facts)?;
            Ok(true)
        }
        State::DeleteApproved => {
            if lifecycle_state != State::UploadVerified || has_delete {
                return Ok(false);
            }
            validate_stored_delete_plan_proofs(manifest, asset_id)?;
            Ok(true)
        }
        State::Deleted => {
            if lifecycle_state != State::UploadVerified {
                return Ok(false);
            }
            validate_stored_delete_plan_proofs(manifest, asset_id)?;
            validate_stored_delete_execution_proof(manifest, asset_id)?;
            Ok(true)
        }
        State::Failed => {
            if has_delete
                || record
                    .failures
                    .last()
                    .is_none_or(|failure| failure.stage == "original_asset_resolve")
            {
                return Ok(false);
            }
            if has_approval {
                validate_stored_delete_plan_proofs(manifest, asset_id)?;
            } else if has_eligibility {
                let facts = validate_pre_delete_facts(manifest, asset_id)?;
                validate_delete_eligibility_chain(manifest, asset_id, &facts)?;
            }
            Ok(true)
        }
        State::Discovered | State::NoAction | State::NeedsReview => Ok(false),
    }
}

fn validate_stored_delete_execution_proof(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<(), WorkflowError> {
    let original = stored_proof::<OriginalAssetProof>(manifest, asset_id, ORIGINAL_ASSET_PROOF)?;
    let upload = stored_proof::<UploadProof>(manifest, asset_id, UPLOAD_PROOF)?;
    let delete = stored_proof::<DeleteExecutionProof>(manifest, asset_id, DELETE_EXECUTION_PROOF)?;
    let expected = delete_execution_proof(
        &original.record_name,
        &original.record_change_tag,
        &upload.uploaded_heic_asset_id,
        CloudKitDeleteOutcome {
            record_name: delete.deleted_record_name.clone(),
            record_change_tag: delete.confirmed_deleted_change_tag.clone(),
        },
    )?;
    if delete != expected {
        return Err(WorkflowError::ProofMismatch {
            proof_key: DELETE_EXECUTION_PROOF,
            field: "delete_execution",
            expected: format!("{expected:?}"),
            actual: format!("{delete:?}"),
        });
    }
    Ok(())
}

fn optional_workflow_proof<T: DeserializeOwned>(
    record: &AssetRecord,
    proof_key: &'static str,
) -> Result<Option<T>, WorkflowError> {
    record
        .proofs
        .get(proof_key)
        .map(|proof| {
            serde_json::from_value(proof.clone()).map_err(|source| WorkflowError::ProofDecode {
                asset_id: record.asset_id.clone(),
                proof_key,
                source,
            })
        })
        .transpose()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_safe_identity(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

fn validate_stored_conversion_performance(
    manifest: &Manifest,
    asset_id: &str,
    nas: &NasRawProof,
    conversion: &ConversionResultProof,
) -> Result<(), WorkflowError> {
    require_current_conversion_recipe(CONVERSION_PROOF, &conversion.conversion_recipe_id)?;
    let conversion_performance = stored_proof::<ConversionPerformanceProof>(
        manifest,
        asset_id,
        CONVERSION_PERFORMANCE_PROOF,
    )?;
    require_current_conversion_recipe(
        CONVERSION_PERFORMANCE_PROOF,
        &conversion_performance.conversion_recipe_id,
    )?;
    validate_conversion_performance_proof(&conversion_performance, nas, conversion)
}

fn transition_with_proof<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    state: State,
    proof_key: &str,
    proof: &impl Serialize,
) -> Result<&'a AssetRecord, WorkflowError> {
    let proof = serde_json::to_value(proof)?;
    manifest
        .transition(asset_id, state, proof_key, proof)
        .map_err(WorkflowError::Manifest)
}

fn insert_workflow_proof<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    proof_key: &str,
    proof: &impl Serialize,
) -> Result<&'a AssetRecord, WorkflowError> {
    let proof = serde_json::to_value(proof)?;
    manifest
        .record_proof(asset_id, proof_key, proof)
        .map_err(WorkflowError::Manifest)
}

fn require_proof<'a>(
    manifest: &'a Manifest,
    asset_id: &str,
    proof_key: &str,
) -> Result<&'a Value, WorkflowError> {
    let record = manifest.get(asset_id)?;
    record
        .proofs
        .get(proof_key)
        .ok_or_else(|| WorkflowError::MissingProof {
            asset_id: asset_id.to_string(),
            proof_key: proof_key.to_string(),
        })
}

fn source_age_proof_is_frozen(state: State) -> bool {
    state.is_terminal()
        || matches!(
            state,
            State::DeleteEligible | State::DeleteApproved | State::Failed
        )
}

fn stored_proof<T: DeserializeOwned>(
    manifest: &Manifest,
    asset_id: &str,
    proof_key: &'static str,
) -> Result<T, WorkflowError> {
    let proof = require_proof(manifest, asset_id, proof_key)?;
    serde_json::from_value(proof.clone()).map_err(|source| WorkflowError::ProofDecode {
        asset_id: asset_id.to_string(),
        proof_key,
        source,
    })
}

fn require_non_empty(field: &'static str, value: &str) -> Result<(), WorkflowError> {
    if value.trim().is_empty() {
        return Err(WorkflowError::EmptyProofField { field });
    }
    Ok(())
}

fn require_current_conversion_recipe(
    proof_key: &'static str,
    recipe_id: &str,
) -> Result<(), WorkflowError> {
    if recipe_id != EMBEDDED_PREVIEW_CONVERSION_RECIPE {
        return Err(WorkflowError::ConversionRecipeOutdated {
            proof_key,
            expected: EMBEDDED_PREVIEW_CONVERSION_RECIPE,
            actual: recipe_id.to_string(),
        });
    }
    Ok(())
}

fn require_non_empty_path(field: &'static str, path: &Path) -> Result<(), WorkflowError> {
    if path.as_os_str().is_empty() {
        return Err(WorkflowError::EmptyProofField { field });
    }
    Ok(())
}

fn require_positive_u64(
    proof_key: &'static str,
    field: &'static str,
    value: u64,
) -> Result<(), WorkflowError> {
    if value == 0 {
        return Err(WorkflowError::InvalidProofField {
            proof_key,
            field,
            reason: "must be greater than zero",
        });
    }
    Ok(())
}

fn require_matching_path(
    proof_key: &'static str,
    field: &'static str,
    expected: &Path,
    actual: &Path,
) -> Result<(), WorkflowError> {
    if expected != actual {
        return Err(WorkflowError::ProofMismatch {
            proof_key,
            field,
            expected: expected.display().to_string(),
            actual: actual.display().to_string(),
        });
    }
    Ok(())
}

fn require_matching_str(
    proof_key: &'static str,
    field: &'static str,
    expected: &str,
    actual: &str,
) -> Result<(), WorkflowError> {
    if expected != actual {
        return Err(WorkflowError::ProofMismatch {
            proof_key,
            field,
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(())
}

fn require_matching_u64(
    proof_key: &'static str,
    field: &'static str,
    expected: u64,
    actual: u64,
) -> Result<(), WorkflowError> {
    if expected != actual {
        return Err(WorkflowError::ProofMismatch {
            proof_key,
            field,
            expected: expected.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(())
}

fn source_age_seconds(asset_id: &str, proof: &SourceAgeProof) -> Result<u64, WorkflowError> {
    require_min_age_seconds(proof.min_age_seconds)?;
    let age_seconds = proof
        .verified_at_unix_seconds
        .saturating_sub(proof.source_captured_unix_seconds);
    if age_seconds < proof.min_age_seconds {
        return Err(WorkflowError::SourceAgeTooNew {
            asset_id: asset_id.to_string(),
            age_seconds,
            min_age_seconds: proof.min_age_seconds,
        });
    }
    Ok(age_seconds)
}

fn require_min_age_seconds(min_age_seconds: u64) -> Result<(), WorkflowError> {
    if min_age_seconds < MIN_RAW_AGE_SECONDS {
        return Err(WorkflowError::MinAgeBelowSafetyFloor {
            requested_seconds: min_age_seconds,
            minimum_seconds: MIN_RAW_AGE_SECONDS,
            minimum_days: crate::proof::MIN_RAW_AGE_DAYS,
        });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum WorkflowError {
    #[error("manifest error: {0}")]
    Manifest(#[from] ManifestError),
    #[error("proof error: {0}")]
    Proof(#[from] ProofError),
    #[error("adjusted source proof failed: {0}")]
    AdjustedSource(#[source] AdjustedSourceError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("asset {asset_id} is {state}; only discovered records can be reused")]
    ExistingAssetNotDiscoverable { asset_id: String, state: State },
    #[error(
        "asset {asset_id} raw path mismatch: existing {existing_path}, requested {requested_path}"
    )]
    RawPathMismatch {
        asset_id: String,
        existing_path: PathBuf,
        requested_path: PathBuf,
    },
    #[error("required proof {proof_key} is missing for {asset_id}")]
    MissingProof { asset_id: String, proof_key: String },
    #[error("batch original asset proof is missing for {asset_id}")]
    MissingBatchOriginalAssetProof { asset_id: String },
    #[error("batch original asset proof was not requested for {asset_id}")]
    UnexpectedBatchOriginalAssetProof { asset_id: String },
    #[error("batch original asset proof reused original recordName {original_record_name}")]
    DuplicateBatchOriginalAssetProof { original_record_name: String },
    #[error("stored proof {proof_key} for {asset_id} could not be decoded: {source}")]
    ProofDecode {
        asset_id: String,
        proof_key: &'static str,
        source: serde_json::Error,
    },
    #[error("proof {proof_key} field {field} mismatch: expected {expected}, got {actual}")]
    ProofMismatch {
        proof_key: &'static str,
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error(
        "source age for {asset_id} is too new: age {age_seconds}s < required {min_age_seconds}s"
    )]
    SourceAgeTooNew {
        asset_id: String,
        age_seconds: u64,
        min_age_seconds: u64,
    },
    #[error(
        "NAS proof for {asset_id} is too new: age {age_seconds}s < required {min_age_seconds}s"
    )]
    NasProofTooNew {
        asset_id: String,
        age_seconds: u64,
        min_age_seconds: u64,
    },
    #[error("source age proof for {asset_id} is frozen in state {state}")]
    SourceAgeProofFrozen { asset_id: String, state: State },
    #[error(
        "minimum age {requested_seconds}s is below safety floor {minimum_days} days ({minimum_seconds}s)"
    )]
    MinAgeBelowSafetyFloor {
        requested_seconds: u64,
        minimum_seconds: u64,
        minimum_days: u64,
    },
    #[error(
        "delete eligibility unavailable for {asset_id}: state is {state}; upload proof required"
    )]
    DeleteEligibilityUnavailable { asset_id: String, state: State },
    #[error(
        "upload unavailable for {asset_id}: state is {state}; conversion verification required"
    )]
    UploadUnavailable { asset_id: String, state: State },
    #[error("delete plan unavailable for {asset_id}: state is {state}; delete approval required")]
    DeletePlanUnavailable { asset_id: String, state: State },
    #[error("prevalidated delete for {asset_id} is stale: {field} changed after validation")]
    PrevalidatedDeleteStale { asset_id: String, field: String },
    #[error("delete reconciliation for {asset_id} is stale: {field} changed after validation")]
    DeleteReconciliationStale { asset_id: String, field: String },
    #[error(
        "prevalidated delete for {asset_id} expired: age {age_seconds}s > max {max_age_seconds}s"
    )]
    PrevalidatedDeleteExpired {
        asset_id: String,
        age_seconds: u64,
        max_age_seconds: u64,
    },
    #[error("prevalidated delete for {asset_id} is invalid: clock moved backward after validation")]
    PrevalidatedDeleteClockMovedBackwards { asset_id: String },
    #[error(
        "iCloudPD local mirror unavailable for {asset_id}: state is {state}; upload verification required"
    )]
    IcloudpdLocalMirrorUnavailable { asset_id: String, state: State },
    #[error(
        "adjusted source unavailable for {asset_id}: state is {state}; NAS verification required"
    )]
    AdjustedSourceUnavailable { asset_id: String, state: State },
    #[error("adjusted source proof already exists for {asset_id}; refusing overwrite")]
    AdjustedSourceProofAlreadyRecorded { asset_id: String },
    #[error("conversion source binding is invalid for {asset_id}: {reason}")]
    ConversionSourceBindingMismatch {
        asset_id: String,
        reason: &'static str,
    },
    #[error("delete approval operator is required")]
    EmptyOperator,
    #[error("workflow proof field {field} is required")]
    EmptyProofField { field: &'static str },
    #[error("proof {proof_key} field {field} is invalid: {reason}")]
    InvalidProofField {
        proof_key: &'static str,
        field: &'static str,
        reason: &'static str,
    },
    #[error("HEIC verification failed: {field}")]
    HeicVerificationFailed { field: &'static str },
    #[error("proof {proof_key} uses conversion recipe {actual:?}; current recipe is {expected}")]
    ConversionRecipeOutdated {
        proof_key: &'static str,
        expected: &'static str,
        actual: String,
    },
}

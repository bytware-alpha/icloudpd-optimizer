use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::manifest::{AssetRecord, Manifest, ManifestError, State};
use crate::proof::{
    MIN_RAW_AGE_SECONDS, NasRawProof, ProofError, prove_nas_raw, prove_nas_raw_with_min_age_seconds,
};

const NAS_PROOF: &str = "nas";
const CONVERSION_PROOF: &str = "conversion";
const CONVERSION_PERFORMANCE_PROOF: &str = "conversion_performance";
const HEIC_PROOF: &str = "heic";
const SOURCE_AGE_PROOF: &str = "source_age";
const UPLOAD_PROOF: &str = "upload";
const DELETE_ELIGIBILITY_PROOF: &str = "delete_eligibility";
const DELETE_APPROVAL_PROOF: &str = "delete_approval";
const CONVERSION_PERFORMANCE_SCHEMA_VERSION: u8 = 1;
const CONVERSION_PERFORMANCE_MEASUREMENT_METHOD: &str = "monotonic_wall_clock";
const DELETE_PLAN_PROOFS: [&str; 8] = [
    NAS_PROOF,
    CONVERSION_PROOF,
    CONVERSION_PERFORMANCE_PROOF,
    HEIC_PROOF,
    SOURCE_AGE_PROOF,
    UPLOAD_PROOF,
    DELETE_ELIGIBILITY_PROOF,
    DELETE_APPROVAL_PROOF,
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConversionResultProof {
    pub heic_path: PathBuf,
    pub heic_sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversionPerformanceInput {
    pub measured_at_unix_seconds: u64,
    pub conversion_tool: String,
    pub conversion_tool_version: Option<String>,
    pub heic_quality: u8,
    pub convert_wall_time_millis: u64,
    pub total_wall_time_millis: u64,
    pub user_cpu_time_millis: Option<u64>,
    pub system_cpu_time_millis: Option<u64>,
    pub peak_rss_kib: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConversionPerformanceProof {
    pub schema_version: u8,
    pub measured_at_unix_seconds: u64,
    pub measurement_method: String,
    pub conversion_tool: String,
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
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HeicVerificationProof {
    pub heic_path: PathBuf,
    pub heic_sha256: String,
    pub size_bytes: u64,
    #[serde(alias = "vipsheader_ok")]
    pub heif_info_ok: bool,
    pub metadata_copied: bool,
    pub visual_content_ok: bool,
    pub visual_match_ok: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UploadProof {
    pub uploaded_heic_asset_id: String,
    pub uploaded_heic_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uploaded_heic_path: Option<PathBuf>,
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
    conversion_performance_proof_key: String,
    heic_proof_key: String,
    source_age_proof_key: String,
    uploaded_heic_asset_id: String,
    uploaded_heic_sha256: String,
    uploaded_heic_path: PathBuf,
    verified_heic_sha256: String,
    verified_heic_path: PathBuf,
    source_captured_unix_seconds: u64,
    source_age_seconds: u64,
    min_source_age_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
struct DeleteApprovalProof {
    operator: String,
}

struct PreDeleteFacts {
    upload: UploadProof,
    uploaded_heic_path: PathBuf,
    heic: HeicVerificationProof,
    source_age: SourceAgeProof,
    source_age_seconds: u64,
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

pub fn record_conversion_result<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    proof: ConversionResultProof,
) -> Result<&'a AssetRecord, WorkflowError> {
    require_non_empty_path("heic_path", &proof.heic_path)?;
    require_non_empty("heic_sha256", &proof.heic_sha256)?;
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
        conversion_tool_version: input.conversion_tool_version,
        heic_quality: input.heic_quality,
        raw_size_bytes: nas.size_bytes,
        heic_size_bytes: conversion.size_bytes,
        convert_wall_time_millis: input.convert_wall_time_millis,
        total_wall_time_millis: input.total_wall_time_millis,
        user_cpu_time_millis: input.user_cpu_time_millis,
        system_cpu_time_millis: input.system_cpu_time_millis,
        peak_rss_kib: input.peak_rss_kib,
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
    let (_, conversion) = require_valid_conversion_performance(manifest, asset_id)?;
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
    validate_heic_verification_flags(&proof)?;
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
    transition_with_proof(
        manifest,
        asset_id,
        State::UploadVerified,
        UPLOAD_PROOF,
        &proof,
    )
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
    let proof = json!({
        "upload_proof_key": UPLOAD_PROOF,
        "conversion_performance_proof_key": CONVERSION_PERFORMANCE_PROOF,
        "heic_proof_key": HEIC_PROOF,
        "source_age_proof_key": SOURCE_AGE_PROOF,
        "uploaded_heic_asset_id": &facts.upload.uploaded_heic_asset_id,
        "uploaded_heic_sha256": &facts.upload.uploaded_heic_sha256,
        "uploaded_heic_path": &facts.uploaded_heic_path,
        "verified_heic_sha256": &facts.heic.heic_sha256,
        "verified_heic_path": &facts.heic.heic_path,
        "source_captured_unix_seconds": facts.source_age.source_captured_unix_seconds,
        "source_age_seconds": facts.source_age_seconds,
        "min_source_age_seconds": facts.source_age.min_age_seconds,
    });

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

    let proof = json!({ "operator": operator });
    manifest
        .transition(
            asset_id,
            State::DeleteApproved,
            DELETE_APPROVAL_PROOF,
            proof,
        )
        .map_err(WorkflowError::Manifest)
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

    let mut proofs = BTreeMap::new();
    for proof_key in DELETE_PLAN_PROOFS {
        let proof = record
            .proofs
            .get(proof_key)
            .ok_or_else(|| WorkflowError::MissingProof {
                asset_id: asset_id.to_string(),
                proof_key: proof_key.to_string(),
            })?;
        proofs.insert(proof_key.to_string(), proof.clone());
    }

    Ok(DeletePlan {
        asset_id: record.asset_id.clone(),
        raw_path: record.raw_path.clone(),
        required_proof_keys: DELETE_PLAN_PROOFS.into_iter().map(str::to_string).collect(),
        proofs,
    })
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

fn revalidate_delete_plan_proofs(manifest: &Manifest, asset_id: &str) -> Result<(), WorkflowError> {
    let facts = validate_pre_delete_facts(manifest, asset_id)?;
    validate_delete_eligibility_chain(manifest, asset_id, &facts)?;
    validate_delete_approval_proof(manifest, asset_id)
}

fn validate_pre_delete_facts(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<PreDeleteFacts, WorkflowError> {
    let record = manifest.get(asset_id)?;
    let (nas, conversion) = load_conversion_context(manifest, asset_id)?;

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
            .as_ref()
            .ok_or(WorkflowError::EmptyProofField {
                field: "uploaded_heic_path",
            })?;
    require_non_empty_path("uploaded_heic_path", uploaded_heic_path)?;
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
    let uploaded_heic_path = uploaded_heic_path.clone();

    let source_age = stored_proof::<SourceAgeProof>(manifest, asset_id, SOURCE_AGE_PROOF)?;
    let source_age_seconds = source_age_seconds(asset_id, &source_age)?;
    validate_nas_proof(record, &nas, source_age.min_age_seconds)?;
    reprove_nas_proof(record, &nas, source_age.min_age_seconds)?;

    validate_stored_conversion_performance(manifest, asset_id, &nas, &conversion)?;

    Ok(PreDeleteFacts {
        upload,
        uploaded_heic_path,
        heic,
        source_age,
        source_age_seconds,
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
        &facts.upload,
        &facts.uploaded_heic_path,
        &facts.heic,
        &facts.source_age,
        facts.source_age_seconds,
    )?;

    Ok(())
}

fn validate_delete_approval_proof(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<(), WorkflowError> {
    let approval = stored_proof::<DeleteApprovalProof>(manifest, asset_id, DELETE_APPROVAL_PROOF)?;
    if approval.operator.trim().is_empty() {
        return Err(WorkflowError::EmptyOperator);
    }

    Ok(())
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
) -> Result<(), WorkflowError> {
    let nas_root = derive_nas_root_from_proof(proof)?;
    let live = prove_nas_raw_with_min_age_seconds(
        &nas_root,
        &proof.canonical_path,
        min_age_seconds,
        SystemTime::now(),
    )?;

    require_matching_path(
        NAS_PROOF,
        "canonical_path",
        &proof.canonical_path,
        &live.canonical_path,
    )?;
    require_matching_path(
        NAS_PROOF,
        "relative_path",
        &proof.relative_path,
        &live.relative_path,
    )?;
    require_matching_u64(NAS_PROOF, "size_bytes", proof.size_bytes, live.size_bytes)?;
    require_matching_u64(
        NAS_PROOF,
        "modified_unix_seconds",
        proof.modified_unix_seconds,
        live.modified_unix_seconds,
    )?;
    if live.age_seconds < proof.age_seconds {
        return Err(WorkflowError::ProofMismatch {
            proof_key: NAS_PROOF,
            field: "age_seconds",
            expected: format!(">= {}", proof.age_seconds),
            actual: live.age_seconds.to_string(),
        });
    }
    if live.age_seconds < min_age_seconds {
        return Err(WorkflowError::NasProofTooNew {
            asset_id: record.asset_id.clone(),
            age_seconds: live.age_seconds,
            min_age_seconds,
        });
    }
    require_matching_str(NAS_PROOF, "sha256", &proof.sha256, &live.sha256)?;

    Ok(())
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

fn validate_delete_eligibility_proof(
    eligibility: &DeleteEligibilityProof,
    upload: &UploadProof,
    uploaded_heic_path: &Path,
    heic: &HeicVerificationProof,
    source_age: &SourceAgeProof,
    source_age_seconds: u64,
) -> Result<(), WorkflowError> {
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "upload_proof_key",
        UPLOAD_PROOF,
        &eligibility.upload_proof_key,
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
        "uploaded_heic_asset_id",
        &upload.uploaded_heic_asset_id,
        &eligibility.uploaded_heic_asset_id,
    )?;
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "uploaded_heic_sha256",
        &upload.uploaded_heic_sha256,
        &eligibility.uploaded_heic_sha256,
    )?;
    require_matching_path(
        DELETE_ELIGIBILITY_PROOF,
        "uploaded_heic_path",
        uploaded_heic_path,
        &eligibility.uploaded_heic_path,
    )?;
    require_matching_str(
        DELETE_ELIGIBILITY_PROOF,
        "verified_heic_sha256",
        &heic.heic_sha256,
        &eligibility.verified_heic_sha256,
    )?;
    require_matching_path(
        DELETE_ELIGIBILITY_PROOF,
        "verified_heic_path",
        &heic.heic_path,
        &eligibility.verified_heic_path,
    )?;
    require_matching_u64(
        DELETE_ELIGIBILITY_PROOF,
        "source_captured_unix_seconds",
        source_age.source_captured_unix_seconds,
        eligibility.source_captured_unix_seconds,
    )?;
    require_matching_u64(
        DELETE_ELIGIBILITY_PROOF,
        "source_age_seconds",
        source_age_seconds,
        eligibility.source_age_seconds,
    )?;
    require_matching_u64(
        DELETE_ELIGIBILITY_PROOF,
        "min_source_age_seconds",
        source_age.min_age_seconds,
        eligibility.min_source_age_seconds,
    )?;

    Ok(())
}

fn validate_heic_verification_flags(proof: &HeicVerificationProof) -> Result<(), WorkflowError> {
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

    Ok(())
}

fn load_conversion_context(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<(NasRawProof, ConversionResultProof), WorkflowError> {
    let nas = stored_proof::<NasRawProof>(manifest, asset_id, NAS_PROOF)?;
    let conversion = stored_proof::<ConversionResultProof>(manifest, asset_id, CONVERSION_PROOF)?;
    Ok((nas, conversion))
}

fn require_valid_conversion_performance(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<(NasRawProof, ConversionResultProof), WorkflowError> {
    let (nas, conversion) = load_conversion_context(manifest, asset_id)?;
    validate_stored_conversion_performance(manifest, asset_id, &nas, &conversion)?;
    Ok((nas, conversion))
}

fn validate_stored_conversion_performance(
    manifest: &Manifest,
    asset_id: &str,
    nas: &NasRawProof,
    conversion: &ConversionResultProof,
) -> Result<(), WorkflowError> {
    let conversion_performance = stored_proof::<ConversionPerformanceProof>(
        manifest,
        asset_id,
        CONVERSION_PERFORMANCE_PROOF,
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
    matches!(
        state,
        State::DeleteEligible | State::DeleteApproved | State::Deleted | State::Failed
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
}

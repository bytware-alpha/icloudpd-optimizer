use std::collections::{BTreeMap, BTreeSet};
use std::path::Component;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::manifest::{AssetRecord, Manifest, ManifestError, State};
use crate::proof::{MIN_RAW_AGE_SECONDS, NasRawProof};
use crate::upload::{
    CLOUDKIT_ORIGINAL_ASSET_RESOLVER_VERSION, CloudKitLibraryDestination,
    CloudKitOriginalAssetInventoryFingerprint, CloudKitOriginalAssetResolution,
    CloudKitOriginalAssetResolveDisposition, CloudKitOriginalAssetResolveObservations,
    CloudKitOriginalAssetResolveTarget, CloudKitReplacementResourceProof,
};
use crate::workflow::{
    ConversionResultProof, HeicVerificationProof, OriginalAssetProof, SourceAgeProof, UploadProof,
};

const ORIGINAL_ASSET_PROOF_KEY: &str = "original_asset";
const ORIGINAL_ASSET_RESOLUTION_SCHEMA_VERSION: u8 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalAssetResolutionBatch {
    pub targets: Vec<CloudKitOriginalAssetResolveTarget>,
    pub destination: CloudKitLibraryDestination,
    pub inventory: CloudKitOriginalAssetInventoryFingerprint,
    pub observed_at_unix_seconds: u64,
    pub resolutions: BTreeMap<String, CloudKitOriginalAssetResolution>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OriginalAssetResolutionProof {
    pub schema_version: u8,
    pub inventory: OriginalAssetResolutionInventoryProof,
    pub destination: CloudKitLibraryDestination,
    pub observed_at_unix_seconds: u64,
    pub source: OriginalAssetResolutionSourceProof,
    pub observations: OriginalAssetResolutionObservations,
    #[serde(flatten)]
    pub disposition: OriginalAssetResolutionDisposition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OriginalAssetResolutionInventoryProof {
    pub resolver_version: String,
    pub sha256: String,
    pub records_scanned: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OriginalAssetResolutionSourceProof {
    pub nas_sha256: String,
    pub nas_size_bytes: u64,
    pub source_captured_unix_seconds: u64,
    pub capture_tolerance_seconds: u64,
    pub filename: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OriginalAssetResolutionObservations {
    pub date_candidates: u64,
    pub raw_resources: u64,
    pub raw_size_matches: u64,
    pub raw_hash_matches: u64,
    pub replacement_resource_matches: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum OriginalAssetResolutionDisposition {
    ExactOriginal {
        proof: OriginalAssetProof,
    },
    ReplacementPresent {
        proof: OriginalAssetReplacementProof,
    },
    NoDateCandidate,
    NoRawResource,
    RawSizeMismatch,
    RawHashMismatch,
    Ambiguous,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OriginalAssetReplacementProof {
    pub record_name: String,
    pub record_change_tag: String,
    pub record_type: String,
    pub database_scope: crate::upload::CloudKitDatabaseScope,
    pub zone_name: String,
    pub resource_field: String,
    pub size_bytes: u64,
    pub matched_heic_sha256: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OriginalAssetResolutionBatchSummary {
    pub exact_original: u64,
    pub no_action: u64,
    pub needs_review: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginalAssetResolutionBatchApplyResult {
    pub changed_records: Vec<AssetRecord>,
    pub summary: OriginalAssetResolutionBatchSummary,
}

#[derive(Debug, Error)]
pub enum OriginalAssetResolutionError {
    #[error("original asset resolution targets must not be empty")]
    EmptyTargets,
    #[error("duplicate original asset resolution target {asset_id}")]
    DuplicateTarget { asset_id: String },
    #[error("original asset resolution target and outcome IDs must match exactly")]
    TargetOutcomeSetMismatch,
    #[error("original asset resolution inventory fingerprint is invalid: {reason}")]
    InvalidInventory { reason: &'static str },
    #[error("original asset resolution destination is invalid: {reason}")]
    InvalidDestination { reason: &'static str },
    #[error("original asset resolution observed time must be positive")]
    MissingObservedTime,
    #[error("original asset resolution target {asset_id} is invalid: {reason}")]
    InvalidTarget {
        asset_id: String,
        reason: &'static str,
    },
    #[error("original asset resolution source for {asset_id} is invalid: {reason}")]
    InvalidSource {
        asset_id: String,
        reason: &'static str,
    },
    #[error("original asset resolution source state for {asset_id} is not eligible: {state}")]
    InvalidSourceState { asset_id: String, state: State },
    #[error("original asset resolution for {asset_id} was incomplete or transient")]
    IncompleteTransient { asset_id: String },
    #[error("original asset resolution disposition is not supported for {asset_id}")]
    UnsupportedDisposition { asset_id: String },
    #[error("original asset resolution original record identity {record_name} is duplicated")]
    DuplicateOriginalRecord { record_name: String },
    #[error("original asset resolution proof for {asset_id} is invalid: {reason}")]
    InvalidResolutionProof {
        asset_id: String,
        reason: &'static str,
    },
    #[error("manifest error: {0}")]
    Manifest(#[from] ManifestError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl Manifest {
    pub fn apply_original_asset_resolution_batch(
        &mut self,
        batch: OriginalAssetResolutionBatch,
    ) -> Result<OriginalAssetResolutionBatchApplyResult, OriginalAssetResolutionError> {
        validate_batch_shape(&batch)?;

        let mut seen_remote_records = existing_original_record_names(self);
        let mut updates = Vec::with_capacity(batch.targets.len());
        let mut summary = OriginalAssetResolutionBatchSummary::default();

        for target in &batch.targets {
            let record = self.get(&target.asset_id)?;
            let source = validate_source(record, target)?;
            let resolution = batch
                .resolutions
                .get(&target.asset_id)
                .expect("validated target and outcome sets must match");
            let (new_state, original_asset_proof, disposition) = match &resolution.disposition {
                CloudKitOriginalAssetResolveDisposition::ExactOriginal { proof } => {
                    validate_exact_original_proof(
                        &target.asset_id,
                        proof,
                        target,
                        &batch.destination,
                    )?;
                    if !seen_remote_records.insert(proof.record_name.clone()) {
                        return Err(OriginalAssetResolutionError::DuplicateOriginalRecord {
                            record_name: proof.record_name.clone(),
                        });
                    }
                    summary.exact_original = summary.exact_original.saturating_add(1);
                    (
                        strongest_proof_consistent_state(record, &batch.destination)?,
                        Some(proof.clone()),
                        OriginalAssetResolutionDisposition::ExactOriginal {
                            proof: proof.clone(),
                        },
                    )
                }
                CloudKitOriginalAssetResolveDisposition::IncompleteTransient => {
                    return Err(OriginalAssetResolutionError::IncompleteTransient {
                        asset_id: target.asset_id.clone(),
                    });
                }
                CloudKitOriginalAssetResolveDisposition::ReplacementPresent { proof } => {
                    validate_replacement_proof(
                        &target.asset_id,
                        proof,
                        target,
                        &batch.destination,
                    )?;
                    if !seen_remote_records.insert(proof.record_name.clone()) {
                        return Err(OriginalAssetResolutionError::DuplicateOriginalRecord {
                            record_name: proof.record_name.clone(),
                        });
                    }
                    summary.no_action = summary.no_action.saturating_add(1);
                    (
                        State::NoAction,
                        None,
                        OriginalAssetResolutionDisposition::ReplacementPresent {
                            proof: replacement_proof(proof),
                        },
                    )
                }
                CloudKitOriginalAssetResolveDisposition::NoDateCandidate => {
                    summary.no_action = summary.no_action.saturating_add(1);
                    (
                        State::NoAction,
                        None,
                        OriginalAssetResolutionDisposition::NoDateCandidate,
                    )
                }
                CloudKitOriginalAssetResolveDisposition::NoRawResource => {
                    summary.no_action = summary.no_action.saturating_add(1);
                    (
                        State::NoAction,
                        None,
                        OriginalAssetResolutionDisposition::NoRawResource,
                    )
                }
                CloudKitOriginalAssetResolveDisposition::RawSizeMismatch => {
                    summary.needs_review = summary.needs_review.saturating_add(1);
                    (
                        State::NeedsReview,
                        None,
                        OriginalAssetResolutionDisposition::RawSizeMismatch,
                    )
                }
                CloudKitOriginalAssetResolveDisposition::RawHashMismatch => {
                    summary.needs_review = summary.needs_review.saturating_add(1);
                    (
                        State::NeedsReview,
                        None,
                        OriginalAssetResolutionDisposition::RawHashMismatch,
                    )
                }
                CloudKitOriginalAssetResolveDisposition::Ambiguous => {
                    summary.needs_review = summary.needs_review.saturating_add(1);
                    (
                        State::NeedsReview,
                        None,
                        OriginalAssetResolutionDisposition::Ambiguous,
                    )
                }
            };

            updates.push(OriginalAssetResolutionUpdate {
                asset_id: target.asset_id.clone(),
                new_state,
                original_asset_proof,
                resolution_proof: durable_proof(&batch, target, &source, resolution, disposition),
            });
        }

        let mut staged = self.clone();
        let mut changed_records = Vec::with_capacity(updates.len());
        for update in updates {
            let resolution_proof = serde_json::to_value(update.resolution_proof)?;
            let original_asset_proof = update
                .original_asset_proof
                .map(serde_json::to_value)
                .transpose()?;
            staged.apply_original_asset_resolution_update(
                &update.asset_id,
                update.new_state,
                original_asset_proof,
                resolution_proof,
            )?;
            changed_records.push(staged.get(&update.asset_id)?.clone());
        }

        *self = staged;
        Ok(OriginalAssetResolutionBatchApplyResult {
            changed_records,
            summary,
        })
    }
}

struct OriginalAssetResolutionUpdate {
    asset_id: String,
    new_state: State,
    original_asset_proof: Option<OriginalAssetProof>,
    resolution_proof: OriginalAssetResolutionProof,
}

fn validate_batch_shape(
    batch: &OriginalAssetResolutionBatch,
) -> Result<(), OriginalAssetResolutionError> {
    if batch.targets.is_empty() {
        return Err(OriginalAssetResolutionError::EmptyTargets);
    }
    if batch.observed_at_unix_seconds == 0 {
        return Err(OriginalAssetResolutionError::MissingObservedTime);
    }
    validate_inventory(&batch.inventory)?;
    validate_destination(&batch.destination)?;

    let mut target_ids = BTreeSet::new();
    for target in &batch.targets {
        validate_target(target)?;
        if !target_ids.insert(target.asset_id.as_str()) {
            return Err(OriginalAssetResolutionError::DuplicateTarget {
                asset_id: target.asset_id.clone(),
            });
        }
    }
    let outcome_ids = batch
        .resolutions
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if target_ids != outcome_ids {
        return Err(OriginalAssetResolutionError::TargetOutcomeSetMismatch);
    }
    Ok(())
}

fn validate_inventory(
    inventory: &CloudKitOriginalAssetInventoryFingerprint,
) -> Result<(), OriginalAssetResolutionError> {
    if inventory.resolver_version != CLOUDKIT_ORIGINAL_ASSET_RESOLVER_VERSION {
        return Err(OriginalAssetResolutionError::InvalidInventory {
            reason: "resolver version is not recognized",
        });
    }
    if inventory.sha256.len() != 64
        || !inventory
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(OriginalAssetResolutionError::InvalidInventory {
            reason: "SHA-256 fingerprint must be 64 hexadecimal characters",
        });
    }
    Ok(())
}

fn validate_destination(
    destination: &CloudKitLibraryDestination,
) -> Result<(), OriginalAssetResolutionError> {
    if destination.zone_name.trim().is_empty()
        || destination.zone_name.chars().any(char::is_control)
    {
        return Err(OriginalAssetResolutionError::InvalidDestination {
            reason: "zone name is required and must not contain control characters",
        });
    }
    Ok(())
}

fn validate_target(
    target: &CloudKitOriginalAssetResolveTarget,
) -> Result<(), OriginalAssetResolutionError> {
    let invalid = |reason| OriginalAssetResolutionError::InvalidTarget {
        asset_id: target.asset_id.clone(),
        reason,
    };
    if target.asset_id.trim().is_empty() {
        return Err(invalid("asset ID is required"));
    }
    if target.raw_size_bytes == 0 {
        return Err(invalid("RAW size must be positive"));
    }
    if target.filename.trim().is_empty() {
        return Err(invalid("filename is required"));
    }
    if target.matched_raw_sha256.trim().is_empty() {
        return Err(invalid("RAW SHA-256 is required"));
    }
    Ok(())
}

fn validate_source(
    record: &AssetRecord,
    target: &CloudKitOriginalAssetResolveTarget,
) -> Result<NasRawProof, OriginalAssetResolutionError> {
    if !matches!(
        record.state,
        State::NasVerified
            | State::Converted
            | State::ConversionVerified
            | State::UploadVerified
            | State::Failed
    ) {
        return Err(OriginalAssetResolutionError::InvalidSourceState {
            asset_id: record.asset_id.clone(),
            state: record.state,
        });
    }
    if record.proofs.contains_key(ORIGINAL_ASSET_PROOF_KEY)
        || record.proofs.contains_key("delete_eligibility")
        || record.proofs.contains_key("delete_approval")
    {
        return Err(OriginalAssetResolutionError::InvalidSource {
            asset_id: record.asset_id.clone(),
            reason: "already has original or delete proof",
        });
    }
    let nas = stored_source_proof::<NasRawProof>(record, "nas")?;
    let source_age = stored_source_proof::<SourceAgeProof>(record, "source_age")?;
    let file_name = record.raw_path.file_name().and_then(|name| name.to_str());
    let relative_path_is_safe = !nas.relative_path.as_os_str().is_empty()
        && nas
            .relative_path
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
    let source_is_valid = !nas.canonical_path.as_os_str().is_empty()
        && relative_path_is_safe
        && record.raw_path == nas.canonical_path
        && nas.size_bytes > 0
        && !nas.sha256.trim().is_empty()
        && nas.modified_unix_seconds == source_age.source_captured_unix_seconds
        && source_age.min_age_seconds >= MIN_RAW_AGE_SECONDS
        && nas.age_seconds >= source_age.min_age_seconds
        && source_age
            .verified_at_unix_seconds
            .saturating_sub(source_age.source_captured_unix_seconds)
            >= source_age.min_age_seconds;
    if !source_is_valid {
        return Err(OriginalAssetResolutionError::InvalidSource {
            asset_id: record.asset_id.clone(),
            reason: "NAS and source-age proofs are inconsistent",
        });
    }
    if nas.size_bytes != target.raw_size_bytes
        || nas.sha256 != target.matched_raw_sha256
        || nas.modified_unix_seconds != target.source_captured_unix_seconds
        || file_name != Some(target.filename.as_str())
    {
        return Err(OriginalAssetResolutionError::InvalidSource {
            asset_id: record.asset_id.clone(),
            reason: "target does not bind the proven source",
        });
    }
    Ok(nas)
}

fn stored_source_proof<T: for<'de> Deserialize<'de>>(
    record: &AssetRecord,
    key: &'static str,
) -> Result<T, OriginalAssetResolutionError> {
    let Some(value) = record.proofs.get(key) else {
        return Err(OriginalAssetResolutionError::InvalidSource {
            asset_id: record.asset_id.clone(),
            reason: "required source proof is missing",
        });
    };
    serde_json::from_value(value.clone()).map_err(|_| OriginalAssetResolutionError::InvalidSource {
        asset_id: record.asset_id.clone(),
        reason: "required source proof is malformed",
    })
}

fn validate_exact_original_proof(
    asset_id: &str,
    proof: &OriginalAssetProof,
    target: &CloudKitOriginalAssetResolveTarget,
    destination: &CloudKitLibraryDestination,
) -> Result<(), OriginalAssetResolutionError> {
    let invalid = |reason| OriginalAssetResolutionError::InvalidResolutionProof {
        asset_id: asset_id.to_string(),
        reason,
    };
    if proof.record_name.trim().is_empty()
        || proof.record_change_tag.trim().is_empty()
        || proof.filename != target.filename
        || proof.record_type != "CPLAsset"
        || proof.size_bytes != target.raw_size_bytes
        || proof.matched_raw_sha256 != target.matched_raw_sha256
        || proof.database_scope != destination.database_scope
        || proof.zone_name != destination.zone_name
    {
        return Err(invalid(
            "exact original proof does not bind the target and destination",
        ));
    }
    Ok(())
}

fn validate_replacement_proof(
    asset_id: &str,
    proof: &CloudKitReplacementResourceProof,
    target: &CloudKitOriginalAssetResolveTarget,
    destination: &CloudKitLibraryDestination,
) -> Result<(), OriginalAssetResolutionError> {
    let invalid = |reason| OriginalAssetResolutionError::InvalidResolutionProof {
        asset_id: asset_id.to_string(),
        reason,
    };
    let Some(candidate) = target.replacement_candidate.as_ref() else {
        return Err(invalid("replacement outcome has no replacement target"));
    };
    if proof.record_name.trim().is_empty()
        || proof.record_change_tag.trim().is_empty()
        || proof.record_type != "CPLAsset"
        || proof.resource_field.trim().is_empty()
        || proof.database_scope != destination.database_scope
        || proof.zone_name != destination.zone_name
        || proof.size_bytes != candidate.size_bytes
        || proof.matched_heic_sha256 != candidate.sha256
    {
        return Err(invalid(
            "replacement proof does not bind the target and destination",
        ));
    }
    Ok(())
}

fn existing_original_record_names(manifest: &Manifest) -> BTreeSet<String> {
    manifest
        .records()
        .values()
        .filter_map(|record| record.proofs.get(ORIGINAL_ASSET_PROOF_KEY))
        .filter_map(|proof| serde_json::from_value::<OriginalAssetProof>(proof.clone()).ok())
        .map(|proof| proof.record_name)
        .collect()
}

fn strongest_proof_consistent_state(
    record: &AssetRecord,
    destination: &CloudKitLibraryDestination,
) -> Result<State, OriginalAssetResolutionError> {
    if record.state != State::Failed {
        return Ok(record.state);
    }
    if valid_upload_proof(record, destination)
        && valid_heic_proof(record)
        && valid_conversion_proof(record)
    {
        return Ok(State::UploadVerified);
    }
    if valid_heic_proof(record) && valid_conversion_proof(record) {
        return Ok(State::ConversionVerified);
    }
    if valid_conversion_proof(record) {
        return Ok(State::Converted);
    }
    Ok(State::NasVerified)
}

fn valid_conversion_proof(record: &AssetRecord) -> bool {
    record
        .proofs
        .get("conversion")
        .and_then(|value| serde_json::from_value::<ConversionResultProof>(value.clone()).ok())
        .is_some_and(|proof| {
            !proof.heic_path.as_os_str().is_empty()
                && !proof.heic_sha256.trim().is_empty()
                && proof.size_bytes > 0
        })
}

fn valid_heic_proof(record: &AssetRecord) -> bool {
    record
        .proofs
        .get("heic")
        .and_then(|value| serde_json::from_value::<HeicVerificationProof>(value.clone()).ok())
        .is_some_and(|proof| {
            !proof.heic_path.as_os_str().is_empty()
                && !proof.heic_sha256.trim().is_empty()
                && proof.size_bytes > 0
                && proof.heif_info_ok
                && proof.metadata_copied
                && proof.visual_content_ok
                && proof.visual_match_ok
        })
}

fn valid_upload_proof(record: &AssetRecord, destination: &CloudKitLibraryDestination) -> bool {
    record
        .proofs
        .get("upload")
        .and_then(|value| serde_json::from_value::<UploadProof>(value.clone()).ok())
        .is_some_and(|proof| {
            !proof.uploaded_heic_asset_id.trim().is_empty()
                && !proof.uploaded_heic_sha256.trim().is_empty()
                && proof.database_scope == destination.database_scope
                && proof.zone_name == destination.zone_name
        })
}

fn durable_proof(
    batch: &OriginalAssetResolutionBatch,
    target: &CloudKitOriginalAssetResolveTarget,
    source: &NasRawProof,
    resolution: &CloudKitOriginalAssetResolution,
    disposition: OriginalAssetResolutionDisposition,
) -> OriginalAssetResolutionProof {
    OriginalAssetResolutionProof {
        schema_version: ORIGINAL_ASSET_RESOLUTION_SCHEMA_VERSION,
        inventory: OriginalAssetResolutionInventoryProof {
            resolver_version: batch.inventory.resolver_version.clone(),
            sha256: batch.inventory.sha256.clone(),
            records_scanned: batch.inventory.records_scanned,
        },
        destination: batch.destination.clone(),
        observed_at_unix_seconds: batch.observed_at_unix_seconds,
        source: OriginalAssetResolutionSourceProof {
            nas_sha256: source.sha256.clone(),
            nas_size_bytes: source.size_bytes,
            source_captured_unix_seconds: target.source_captured_unix_seconds,
            capture_tolerance_seconds: target.capture_tolerance_seconds,
            filename: target.filename.clone(),
        },
        observations: observations(&resolution.observations),
        disposition,
    }
}

fn observations(
    source: &CloudKitOriginalAssetResolveObservations,
) -> OriginalAssetResolutionObservations {
    OriginalAssetResolutionObservations {
        date_candidates: source.date_candidates,
        raw_resources: source.raw_resources,
        raw_size_matches: source.raw_size_matches,
        raw_hash_matches: source.raw_hash_matches,
        replacement_resource_matches: source.replacement_resource_matches,
    }
}

fn replacement_proof(proof: &CloudKitReplacementResourceProof) -> OriginalAssetReplacementProof {
    OriginalAssetReplacementProof {
        record_name: proof.record_name.clone(),
        record_change_tag: proof.record_change_tag.clone(),
        record_type: proof.record_type.clone(),
        database_scope: proof.database_scope,
        zone_name: proof.zone_name.clone(),
        resource_field: proof.resource_field.clone(),
        size_bytes: proof.size_bytes,
        matched_heic_sha256: proof.matched_heic_sha256.clone(),
    }
}

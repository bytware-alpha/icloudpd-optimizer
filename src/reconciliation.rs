use std::collections::{BTreeMap, BTreeSet};
use std::path::Component;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::manifest::{AssetRecord, Manifest, ManifestError, State};
use crate::proof::{MIN_RAW_AGE_SECONDS, NasRawProof};
use crate::upload::{
    CLOUDKIT_ORIGINAL_ASSET_RESOLVER_VERSION, CloudKitDatabaseScope, CloudKitLibraryDestination,
    CloudKitOriginalAssetInventoryFingerprint, CloudKitOriginalAssetResolution,
    CloudKitOriginalAssetResolveDisposition, CloudKitOriginalAssetResolveObservations,
    CloudKitOriginalAssetResolveTarget, CloudKitReplacementResourceProof,
    validate_library_destination,
};
use crate::workflow::{
    OriginalAssetProof, SourceAgeProof, reconciliation_exact_state_is_consistent,
    reconciliation_lifecycle_state,
};

const ORIGINAL_ASSET_PROOF_KEY: &str = "original_asset";
const ORIGINAL_ASSET_RESOLUTION_PROOF_KEY: &str = "original_asset_resolution";
const ORIGINAL_ASSET_RESOLUTION_SCHEMA_VERSION: u8 = 2;
type RemoteRecordIdentity = (CloudKitDatabaseScope, String, String);
const FAILED_RESOLUTION_DOWNSTREAM_PROOF_KEYS: [&str; 7] = [
    ORIGINAL_ASSET_PROOF_KEY,
    "icloudpd_local_mirror",
    "delete_eligibility",
    "delete_approval",
    "delete",
    "uploaded_heic_delete",
    ORIGINAL_ASSET_RESOLUTION_PROOF_KEY,
];

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
    pub download_size_mismatches: u64,
    pub ambiguity_evidence: u64,
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
    #[error("existing {proof_key} proof for {asset_id} is malformed")]
    MalformedExistingProof {
        asset_id: String,
        proof_key: &'static str,
    },
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

        let mut seen_remote_records = existing_original_record_names(self)?;
        let mut updates = Vec::with_capacity(batch.targets.len());
        let mut summary = OriginalAssetResolutionBatchSummary::default();

        for target in &batch.targets {
            let record = self.get(&target.asset_id)?;
            let source = validate_source(
                self,
                record,
                target,
                &batch.destination,
                batch.observed_at_unix_seconds,
            )?;
            let resolution = batch
                .resolutions
                .get(&target.asset_id)
                .expect("validated target and outcome sets must match");
            validate_disposition_evidence(&target.asset_id, resolution)?;
            let (new_state, original_asset_proof, disposition) = match &resolution.disposition {
                CloudKitOriginalAssetResolveDisposition::ExactOriginal { proof } => {
                    validate_exact_original_proof(
                        &target.asset_id,
                        proof,
                        target,
                        &batch.destination,
                    )?;
                    if !seen_remote_records.insert(remote_record_identity(
                        &batch.destination,
                        &proof.record_name,
                    )) {
                        return Err(OriginalAssetResolutionError::DuplicateOriginalRecord {
                            record_name: proof.record_name.clone(),
                        });
                    }
                    summary.exact_original = summary.exact_original.saturating_add(1);
                    (
                        strongest_proof_consistent_state(self, record, &batch.destination)?,
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
                    if !seen_remote_records.insert(remote_record_identity(
                        &batch.destination,
                        &proof.record_name,
                    )) {
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
    if !is_sha256(&inventory.sha256) {
        return Err(OriginalAssetResolutionError::InvalidInventory {
            reason: "SHA-256 fingerprint must be 64 hexadecimal characters",
        });
    }
    Ok(())
}

fn validate_destination(
    destination: &CloudKitLibraryDestination,
) -> Result<(), OriginalAssetResolutionError> {
    validate_library_destination(destination).map_err(|_| {
        OriginalAssetResolutionError::InvalidDestination {
            reason: "CloudKit library destination is invalid",
        }
    })
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
    if target.source_captured_unix_seconds == 0 {
        return Err(invalid("capture time must be positive"));
    }
    if !is_safe_single_filename(&target.filename) {
        return Err(invalid(
            "filename must be one safe component without control characters",
        ));
    }
    if !is_sha256(&target.matched_raw_sha256) {
        return Err(invalid("RAW SHA-256 must be 64 hexadecimal characters"));
    }
    if let Some(replacement) = &target.replacement_candidate
        && (replacement.size_bytes == 0 || !is_sha256(&replacement.sha256))
    {
        return Err(invalid(
            "replacement candidate must have a positive size and 64-character SHA-256",
        ));
    }
    Ok(())
}

fn validate_source(
    manifest: &Manifest,
    record: &AssetRecord,
    target: &CloudKitOriginalAssetResolveTarget,
    destination: &CloudKitLibraryDestination,
    observed_at_unix_seconds: u64,
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
    if record
        .proofs
        .contains_key(ORIGINAL_ASSET_RESOLUTION_PROOF_KEY)
    {
        return Err(OriginalAssetResolutionError::InvalidSource {
            asset_id: record.asset_id.clone(),
            reason: "record already carries an original asset resolution proof",
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
    if record.state == State::Failed
        && (record
            .failures
            .last()
            .is_none_or(|failure| failure.stage != "original_asset_resolve")
            || FAILED_RESOLUTION_DOWNSTREAM_PROOF_KEYS
                .iter()
                .any(|proof_key| record.proofs.contains_key(*proof_key)))
    {
        return Err(OriginalAssetResolutionError::InvalidSource {
            asset_id: record.asset_id.clone(),
            reason: "failed record is not an unresolved original asset resolver failure",
        });
    }
    let file_name = record.raw_path.file_name().and_then(|name| name.to_str());
    if !source_proofs_are_valid(record, &nas, &source_age) {
        return Err(OriginalAssetResolutionError::InvalidSource {
            asset_id: record.asset_id.clone(),
            reason: "NAS and source-age proofs are inconsistent",
        });
    }
    if observed_at_unix_seconds < source_age.verified_at_unix_seconds
        || observed_at_unix_seconds < target.source_captured_unix_seconds
    {
        return Err(OriginalAssetResolutionError::InvalidSource {
            asset_id: record.asset_id.clone(),
            reason: "resolution observation predates the source proof",
        });
    }
    let proof_strength = reconciliation_lifecycle_state(manifest, &record.asset_id, destination)
        .map_err(|_| OriginalAssetResolutionError::InvalidSource {
            asset_id: record.asset_id.clone(),
            reason: "lifecycle proof chain is invalid",
        })?;
    if record.state != State::Failed && record.state != proof_strength {
        return Err(OriginalAssetResolutionError::InvalidSource {
            asset_id: record.asset_id.clone(),
            reason: "state does not match the lifecycle proof chain",
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

fn source_proofs_are_valid(
    record: &AssetRecord,
    nas: &NasRawProof,
    source_age: &SourceAgeProof,
) -> bool {
    let relative_path_is_safe = !nas.relative_path.as_os_str().is_empty()
        && nas
            .relative_path
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
    !nas.canonical_path.as_os_str().is_empty()
        && relative_path_is_safe
        && record.raw_path == nas.canonical_path
        && nas.size_bytes > 0
        && is_sha256(&nas.sha256)
        && nas.modified_unix_seconds == source_age.source_captured_unix_seconds
        && source_age.min_age_seconds >= MIN_RAW_AGE_SECONDS
        && nas.age_seconds >= source_age.min_age_seconds
        && source_age
            .verified_at_unix_seconds
            .saturating_sub(source_age.source_captured_unix_seconds)
            >= source_age.min_age_seconds
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_safe_remote_identity(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

fn is_safe_single_filename(value: &str) -> bool {
    !value.trim().is_empty()
        && !value.chars().any(char::is_control)
        && std::path::Path::new(value)
            .components()
            .eq([Component::Normal(value.as_ref())])
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
    if !is_safe_remote_identity(&proof.record_name)
        || !is_safe_remote_identity(&proof.record_change_tag)
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
    if !is_safe_remote_identity(&proof.record_name)
        || !is_safe_remote_identity(&proof.record_change_tag)
        || proof.record_type != "CPLAsset"
        || !is_safe_remote_identity(&proof.resource_field)
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

fn validate_disposition_evidence(
    asset_id: &str,
    resolution: &CloudKitOriginalAssetResolution,
) -> Result<(), OriginalAssetResolutionError> {
    if resolution_evidence(&resolution.disposition).is_none_or(|evidence| {
        evidence_is_coherent(&observations(&resolution.observations), evidence)
    }) {
        Ok(())
    } else {
        Err(OriginalAssetResolutionError::InvalidResolutionProof {
            asset_id: asset_id.to_string(),
            reason: "disposition does not match resolver observations",
        })
    }
}

#[derive(Clone, Copy)]
enum ResolutionEvidence {
    ExactOriginal,
    ReplacementPresent,
    NoDateCandidate,
    NoRawResource,
    RawSizeMismatch,
    RawHashMismatch,
    Ambiguous,
}

fn resolution_evidence(
    disposition: &CloudKitOriginalAssetResolveDisposition,
) -> Option<ResolutionEvidence> {
    match disposition {
        CloudKitOriginalAssetResolveDisposition::ExactOriginal { .. } => {
            Some(ResolutionEvidence::ExactOriginal)
        }
        CloudKitOriginalAssetResolveDisposition::ReplacementPresent { .. } => {
            Some(ResolutionEvidence::ReplacementPresent)
        }
        CloudKitOriginalAssetResolveDisposition::NoDateCandidate => {
            Some(ResolutionEvidence::NoDateCandidate)
        }
        CloudKitOriginalAssetResolveDisposition::NoRawResource => {
            Some(ResolutionEvidence::NoRawResource)
        }
        CloudKitOriginalAssetResolveDisposition::RawSizeMismatch => {
            Some(ResolutionEvidence::RawSizeMismatch)
        }
        CloudKitOriginalAssetResolveDisposition::RawHashMismatch => {
            Some(ResolutionEvidence::RawHashMismatch)
        }
        CloudKitOriginalAssetResolveDisposition::Ambiguous => Some(ResolutionEvidence::Ambiguous),
        CloudKitOriginalAssetResolveDisposition::IncompleteTransient => None,
    }
}

fn evidence_is_coherent(
    observations: &OriginalAssetResolutionObservations,
    evidence: ResolutionEvidence,
) -> bool {
    let no_ambiguity_or_download_mismatch =
        observations.ambiguity_evidence == 0 && observations.download_size_mismatches == 0;
    let no_matches = observations.raw_size_matches == 0
        && observations.raw_hash_matches == 0
        && observations.replacement_resource_matches == 0;
    match evidence {
        ResolutionEvidence::ExactOriginal => {
            observations.date_candidates > 0
                && observations.raw_resources > 0
                && observations.raw_size_matches > 0
                && observations.raw_hash_matches == 1
                && observations.replacement_resource_matches == 0
                && no_ambiguity_or_download_mismatch
        }
        ResolutionEvidence::ReplacementPresent => {
            observations.date_candidates > 0
                && observations.raw_hash_matches == 0
                && observations.replacement_resource_matches == 1
                && no_ambiguity_or_download_mismatch
        }
        ResolutionEvidence::NoDateCandidate => {
            observations.date_candidates == 0
                && observations.raw_resources == 0
                && no_matches
                && no_ambiguity_or_download_mismatch
        }
        ResolutionEvidence::NoRawResource => {
            observations.date_candidates > 0
                && observations.raw_resources == 0
                && no_matches
                && no_ambiguity_or_download_mismatch
        }
        ResolutionEvidence::RawSizeMismatch => {
            observations.date_candidates > 0
                && observations.raw_resources > 0
                && no_matches
                && no_ambiguity_or_download_mismatch
        }
        ResolutionEvidence::RawHashMismatch => {
            observations.date_candidates > 0
                && observations.raw_resources > 0
                && observations.raw_size_matches > 0
                && observations.raw_hash_matches == 0
                && observations.replacement_resource_matches == 0
                && no_ambiguity_or_download_mismatch
        }
        ResolutionEvidence::Ambiguous => {
            observations.date_candidates > 0
                && observations.ambiguity_evidence > 0
                && (observations.raw_hash_matches > 0
                    || observations.replacement_resource_matches > 0)
                && observations.download_size_mismatches == 0
        }
    }
}

fn existing_original_record_names(
    manifest: &Manifest,
) -> Result<BTreeSet<RemoteRecordIdentity>, OriginalAssetResolutionError> {
    let mut names = BTreeMap::new();
    for record in manifest.records().values() {
        let original = record
            .proofs
            .get(ORIGINAL_ASSET_PROOF_KEY)
            .map(|value| {
                decode_existing_proof::<OriginalAssetProof>(record, ORIGINAL_ASSET_PROOF_KEY, value)
            })
            .transpose()?;
        if let Some(proof) = &original {
            validate_existing_original_asset_proof(record, proof)?;
            insert_existing_remote_identity(
                &mut names,
                record,
                remote_record_identity(
                    &CloudKitLibraryDestination {
                        database_scope: proof.database_scope,
                        zone_name: proof.zone_name.clone(),
                    },
                    &proof.record_name,
                ),
            )?;
        }

        let resolution = record
            .proofs
            .get(ORIGINAL_ASSET_RESOLUTION_PROOF_KEY)
            .map(|value| {
                decode_existing_proof::<OriginalAssetResolutionProof>(
                    record,
                    ORIGINAL_ASSET_RESOLUTION_PROOF_KEY,
                    value,
                )
            })
            .transpose()?;
        if let Some(proof) = &resolution {
            let resolution_identity =
                validate_existing_resolution_proof(manifest, record, proof, original.as_ref())?;
            if let Some(identity) = resolution_identity {
                insert_existing_remote_identity(&mut names, record, identity)?;
            }
        }
    }
    Ok(names.into_keys().collect())
}

fn decode_existing_proof<T: for<'de> Deserialize<'de>>(
    record: &AssetRecord,
    proof_key: &'static str,
    value: &serde_json::Value,
) -> Result<T, OriginalAssetResolutionError> {
    serde_json::from_value(value.clone()).map_err(|_| {
        OriginalAssetResolutionError::MalformedExistingProof {
            asset_id: record.asset_id.clone(),
            proof_key,
        }
    })
}

fn insert_existing_remote_identity(
    names: &mut BTreeMap<RemoteRecordIdentity, String>,
    record: &AssetRecord,
    identity: RemoteRecordIdentity,
) -> Result<(), OriginalAssetResolutionError> {
    let record_name = identity.2.clone();
    match names.insert(identity, record.asset_id.clone()) {
        Some(existing_asset_id) if existing_asset_id != record.asset_id => {
            Err(OriginalAssetResolutionError::DuplicateOriginalRecord { record_name })
        }
        _ => Ok(()),
    }
}

fn remote_record_identity(
    destination: &CloudKitLibraryDestination,
    record_name: &str,
) -> RemoteRecordIdentity {
    (
        destination.database_scope,
        destination.zone_name.clone(),
        record_name.to_string(),
    )
}

fn validate_existing_original_asset_proof(
    record: &AssetRecord,
    proof: &OriginalAssetProof,
) -> Result<(), OriginalAssetResolutionError> {
    let destination = CloudKitLibraryDestination {
        database_scope: proof.database_scope,
        zone_name: proof.zone_name.clone(),
    };
    if !is_safe_remote_identity(&proof.record_name)
        || !is_safe_remote_identity(&proof.record_change_tag)
        || proof.record_type != "CPLAsset"
        || !is_safe_single_filename(&proof.filename)
        || proof.size_bytes == 0
        || !is_sha256(&proof.matched_raw_sha256)
        || validate_destination(&destination).is_err()
    {
        return Err(OriginalAssetResolutionError::MalformedExistingProof {
            asset_id: record.asset_id.clone(),
            proof_key: ORIGINAL_ASSET_PROOF_KEY,
        });
    }
    Ok(())
}

fn validate_existing_resolution_proof(
    manifest: &Manifest,
    record: &AssetRecord,
    proof: &OriginalAssetResolutionProof,
    top_level_original: Option<&OriginalAssetProof>,
) -> Result<Option<RemoteRecordIdentity>, OriginalAssetResolutionError> {
    if proof.schema_version != ORIGINAL_ASSET_RESOLUTION_SCHEMA_VERSION
        || validate_inventory(&CloudKitOriginalAssetInventoryFingerprint {
            resolver_version: proof.inventory.resolver_version.clone(),
            sha256: proof.inventory.sha256.clone(),
            records_scanned: proof.inventory.records_scanned,
        })
        .is_err()
        || validate_destination(&proof.destination).is_err()
        || proof.observed_at_unix_seconds == 0
        || proof.source.nas_size_bytes == 0
        || proof.source.source_captured_unix_seconds == 0
        || !is_sha256(&proof.source.nas_sha256)
        || !is_safe_single_filename(&proof.source.filename)
    {
        return Err(malformed_existing_resolution(record));
    }

    validate_existing_resolution_source(record, proof)?;
    reconciliation_lifecycle_state(manifest, &record.asset_id, &proof.destination)
        .map_err(|_| malformed_existing_resolution(record))?;

    let (evidence, identity) = match &proof.disposition {
        OriginalAssetResolutionDisposition::ExactOriginal { proof: original } => {
            validate_existing_original_asset_proof(record, original)?;
            if top_level_original != Some(original)
                || original.database_scope != proof.destination.database_scope
                || original.zone_name != proof.destination.zone_name
                || original.filename != proof.source.filename
                || original.size_bytes != proof.source.nas_size_bytes
                || original.matched_raw_sha256 != proof.source.nas_sha256
                || !reconciliation_exact_state_is_consistent(
                    manifest,
                    &record.asset_id,
                    &proof.destination,
                )
                .map_err(|_| malformed_existing_resolution(record))?
            {
                return Err(malformed_existing_resolution(record));
            }
            (
                ResolutionEvidence::ExactOriginal,
                Some(remote_record_identity(
                    &proof.destination,
                    &original.record_name,
                )),
            )
        }
        OriginalAssetResolutionDisposition::ReplacementPresent { proof: replacement } => {
            if !is_safe_remote_identity(&replacement.record_name)
                || !is_safe_remote_identity(&replacement.record_change_tag)
                || replacement.record_type != "CPLAsset"
                || !is_safe_remote_identity(&replacement.resource_field)
                || replacement.size_bytes == 0
                || !is_sha256(&replacement.matched_heic_sha256)
                || replacement.database_scope != proof.destination.database_scope
                || replacement.zone_name != proof.destination.zone_name
            {
                return Err(malformed_existing_resolution(record));
            }
            (
                ResolutionEvidence::ReplacementPresent,
                Some(remote_record_identity(
                    &proof.destination,
                    &replacement.record_name,
                )),
            )
        }
        OriginalAssetResolutionDisposition::NoDateCandidate => {
            (ResolutionEvidence::NoDateCandidate, None)
        }
        OriginalAssetResolutionDisposition::NoRawResource => {
            (ResolutionEvidence::NoRawResource, None)
        }
        OriginalAssetResolutionDisposition::RawSizeMismatch => {
            (ResolutionEvidence::RawSizeMismatch, None)
        }
        OriginalAssetResolutionDisposition::RawHashMismatch => {
            (ResolutionEvidence::RawHashMismatch, None)
        }
        OriginalAssetResolutionDisposition::Ambiguous => (ResolutionEvidence::Ambiguous, None),
    };
    if !evidence_is_coherent(&proof.observations, evidence)
        || !persisted_disposition_state_is_consistent(record, evidence, top_level_original)
    {
        return Err(malformed_existing_resolution(record));
    }
    Ok(identity)
}

fn validate_existing_resolution_source(
    record: &AssetRecord,
    proof: &OriginalAssetResolutionProof,
) -> Result<(), OriginalAssetResolutionError> {
    let nas = stored_source_proof::<NasRawProof>(record, "nas")
        .map_err(|_| malformed_existing_resolution(record))?;
    let source_age = stored_source_proof::<SourceAgeProof>(record, "source_age")
        .map_err(|_| malformed_existing_resolution(record))?;
    let filename = record.raw_path.file_name().and_then(|name| name.to_str());

    if !source_proofs_are_valid(record, &nas, &source_age)
        || proof.source.nas_sha256 != nas.sha256
        || proof.source.nas_size_bytes != nas.size_bytes
        || proof.source.source_captured_unix_seconds != source_age.source_captured_unix_seconds
        || filename != Some(proof.source.filename.as_str())
        || proof.observed_at_unix_seconds < source_age.verified_at_unix_seconds
        || proof.observed_at_unix_seconds < proof.source.source_captured_unix_seconds
    {
        return Err(malformed_existing_resolution(record));
    }
    Ok(())
}

fn persisted_disposition_state_is_consistent(
    record: &AssetRecord,
    evidence: ResolutionEvidence,
    top_level_original: Option<&OriginalAssetProof>,
) -> bool {
    if matches!(evidence, ResolutionEvidence::ExactOriginal) {
        return top_level_original.is_some();
    }

    let expected_state = match evidence {
        ResolutionEvidence::ReplacementPresent
        | ResolutionEvidence::NoDateCandidate
        | ResolutionEvidence::NoRawResource => State::NoAction,
        ResolutionEvidence::RawSizeMismatch
        | ResolutionEvidence::RawHashMismatch
        | ResolutionEvidence::Ambiguous => State::NeedsReview,
        ResolutionEvidence::ExactOriginal => unreachable!(),
    };
    record.state == expected_state
        && top_level_original.is_none()
        && ![
            "delete_eligibility",
            "delete_approval",
            "delete",
            "uploaded_heic_delete",
        ]
        .iter()
        .any(|proof_key| record.proofs.contains_key(*proof_key))
}

fn malformed_existing_resolution(record: &AssetRecord) -> OriginalAssetResolutionError {
    OriginalAssetResolutionError::MalformedExistingProof {
        asset_id: record.asset_id.clone(),
        proof_key: ORIGINAL_ASSET_RESOLUTION_PROOF_KEY,
    }
}

fn strongest_proof_consistent_state(
    manifest: &Manifest,
    record: &AssetRecord,
    destination: &CloudKitLibraryDestination,
) -> Result<State, OriginalAssetResolutionError> {
    reconciliation_lifecycle_state(manifest, &record.asset_id, destination).map_err(|_| {
        OriginalAssetResolutionError::InvalidSource {
            asset_id: record.asset_id.clone(),
            reason: "lifecycle proof chain is invalid",
        }
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
        download_size_mismatches: source.download_size_mismatches,
        ambiguity_evidence: source.ambiguity_evidence,
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

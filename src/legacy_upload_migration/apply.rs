use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

#[cfg(test)]
type QuarantineDirectoryPreCreateHook = (usize, Box<dyn FnOnce()>);

#[cfg(test)]
thread_local! {
    static CHECKPOINT_EXPORT_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(super) fn set_checkpoint_export_hook(hook: impl FnOnce() + 'static) {
    CHECKPOINT_EXPORT_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_checkpoint_export_hook() {
    CHECKPOINT_EXPORT_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_checkpoint_export_hook() {}

#[cfg(test)]
thread_local! {
    static QUARANTINE_RENAME_CRASH_AFTER: std::cell::RefCell<Option<usize>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn set_quarantine_rename_crash_after(rename_count: usize) {
    QUARANTINE_RENAME_CRASH_AFTER.with(|slot| *slot.borrow_mut() = Some(rename_count));
}

#[cfg(test)]
fn fail_after_quarantine_rename(
    rename_count: usize,
) -> Result<(), LegacyUploadMigrationApplyError> {
    let should_fail = QUARANTINE_RENAME_CRASH_AFTER.with(|slot| {
        let mut slot = slot.borrow_mut();
        if *slot == Some(rename_count) {
            slot.take();
            true
        } else {
            false
        }
    });
    if should_fail {
        Err(LegacyUploadMigrationApplyError::Quarantine)
    } else {
        Ok(())
    }
}

#[cfg(not(test))]
fn fail_after_quarantine_rename(
    _rename_count: usize,
) -> Result<(), LegacyUploadMigrationApplyError> {
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReferenceNormalizationCrashPoint {
    AfterCreate,
    AfterCopy,
    AfterNormalize,
    BeforeRename,
    AfterRename,
}

#[cfg(test)]
thread_local! {
    static REFERENCE_NORMALIZATION_CRASH_POINT: std::cell::RefCell<Option<ReferenceNormalizationCrashPoint>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn set_reference_normalization_crash_point(point: ReferenceNormalizationCrashPoint) {
    REFERENCE_NORMALIZATION_CRASH_POINT.with(|slot| *slot.borrow_mut() = Some(point));
}

#[cfg(test)]
fn fail_at_reference_normalization_crash_point(
    point: ReferenceNormalizationCrashPoint,
) -> Result<(), LegacyUploadMigrationApplyError> {
    let should_fail = REFERENCE_NORMALIZATION_CRASH_POINT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if *slot == Some(point) {
            slot.take();
            true
        } else {
            false
        }
    });
    if should_fail {
        Err(LegacyUploadMigrationApplyError::Quarantine)
    } else {
        Ok(())
    }
}

#[cfg(not(test))]
fn fail_at_reference_normalization_crash_point(
    _point: ReferenceNormalizationCrashPoint,
) -> Result<(), LegacyUploadMigrationApplyError> {
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "test-only crash injection points")
)]
pub(super) enum QuarantineDirectoryRemovalCrashPoint {
    BeforeUnlink,
    AfterUnlink,
}

#[cfg(test)]
thread_local! {
    static QUARANTINE_DIRECTORY_CREATE_FAIL_AFTER_MKDIR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static QUARANTINE_DIRECTORY_CRASH_AFTER_MKDIR_BEFORE_RESULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static QUARANTINE_DIRECTORY_CREATE_FAIL_ROOT_ORDINAL: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static QUARANTINE_DIRECTORY_PRE_CREATE_HOOK: std::cell::RefCell<Option<QuarantineDirectoryPreCreateHook>> = const { std::cell::RefCell::new(None) };
    static QUARANTINE_DIRECTORY_REMOVAL_CRASH_POINT: std::cell::Cell<Option<QuarantineDirectoryRemovalCrashPoint>> = const { std::cell::Cell::new(None) };
    static QUARANTINE_DIRECTORY_POST_OPEN_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn set_quarantine_directory_create_fail_after_mkdir() {
    QUARANTINE_DIRECTORY_CREATE_FAIL_AFTER_MKDIR.with(|slot| slot.set(true));
}

#[cfg(test)]
pub(super) fn set_quarantine_directory_crash_after_mkdir_before_result() {
    QUARANTINE_DIRECTORY_CRASH_AFTER_MKDIR_BEFORE_RESULT.with(|slot| slot.set(true));
}

#[cfg(test)]
pub(super) fn set_quarantine_directory_create_fail_root_ordinal(root_ordinal: usize) {
    QUARANTINE_DIRECTORY_CREATE_FAIL_ROOT_ORDINAL.with(|slot| slot.set(Some(root_ordinal)));
}

#[cfg(test)]
pub(super) fn set_quarantine_directory_pre_create_hook(
    root_ordinal: usize,
    hook: impl FnOnce() + 'static,
) {
    QUARANTINE_DIRECTORY_PRE_CREATE_HOOK
        .with(|slot| *slot.borrow_mut() = Some((root_ordinal, Box::new(hook))));
}

#[cfg(test)]
pub(super) fn set_quarantine_directory_post_open_hook(hook: impl FnOnce() + 'static) {
    QUARANTINE_DIRECTORY_POST_OPEN_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_quarantine_directory_post_open_hook() {
    QUARANTINE_DIRECTORY_POST_OPEN_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_quarantine_directory_post_open_hook() {}

#[cfg(test)]
pub(super) fn set_quarantine_directory_removal_crash_point(
    point: QuarantineDirectoryRemovalCrashPoint,
) {
    QUARANTINE_DIRECTORY_REMOVAL_CRASH_POINT.with(|slot| slot.set(Some(point)));
}

#[cfg(test)]
fn fail_quarantine_directory_create_after_mkdir() -> bool {
    QUARANTINE_DIRECTORY_CREATE_FAIL_AFTER_MKDIR.with(|slot| slot.replace(false))
}

#[cfg(test)]
fn crash_quarantine_directory_after_mkdir_before_result() -> bool {
    QUARANTINE_DIRECTORY_CRASH_AFTER_MKDIR_BEFORE_RESULT.with(|slot| slot.replace(false))
}

#[cfg(test)]
fn fail_quarantine_directory_create_root(root_ordinal: usize) -> bool {
    QUARANTINE_DIRECTORY_CREATE_FAIL_ROOT_ORDINAL.with(|slot| {
        if slot.get() == Some(root_ordinal) {
            slot.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(test)]
fn run_quarantine_directory_pre_create_hook(root_ordinal: usize) {
    QUARANTINE_DIRECTORY_PRE_CREATE_HOOK.with(|slot| {
        let should_run = slot
            .borrow()
            .as_ref()
            .is_some_and(|(expected, _)| *expected == root_ordinal);
        if should_run && let Some((_, hook)) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_quarantine_directory_pre_create_hook(_root_ordinal: usize) {}

#[cfg(not(test))]
fn fail_quarantine_directory_create_root(_root_ordinal: usize) -> bool {
    false
}

#[cfg(not(test))]
fn crash_quarantine_directory_after_mkdir_before_result() -> bool {
    false
}

#[cfg(not(test))]
fn fail_quarantine_directory_create_after_mkdir() -> bool {
    false
}

#[cfg(test)]
fn fail_quarantine_directory_removal_at(point: QuarantineDirectoryRemovalCrashPoint) -> bool {
    QUARANTINE_DIRECTORY_REMOVAL_CRASH_POINT.with(|slot| {
        if slot.get() == Some(point) {
            slot.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(not(test))]
fn fail_quarantine_directory_removal_at(_point: QuarantineDirectoryRemovalCrashPoint) -> bool {
    false
}

use super::evidence::{
    EvidenceReferenceNormalization, EvidenceRetiredReplacement, LegacyUploadDeviceRecoveryRequest,
    LegacyUploadEvidenceAuditRequest, ValidatedLegacyUploadEvidence,
    is_verified_conversion_output_at_path, is_verified_conversion_source_for_quarantine,
    load_validated_legacy_uploaded_heic_evidence,
    load_validated_legacy_uploaded_heic_evidence_with_state_store,
};
use super::{
    LegacyUploadMigrationCasUpdate, LegacyUploadMigrationPhase,
    LegacyUploadMigrationQuarantinePlan, LegacyUploadMigrationRegistry,
    build_legacy_upload_migration_phase_authority, canonical_digest,
    persist_two_legacy_upload_migration_preparations_exact_cas,
    persist_two_legacy_upload_migration_records_exact_cas, prepare_legacy_upload_migration_record,
    validate_legacy_upload_migration_record,
};
use super::{LegacyUploadMigrationQuarantineFileIdentity, LegacyUploadMigrationQuarantineKind};
use crate::conversion_execution::{
    ConversionExecutionError, ConversionExecutionRequest, execute_measured_conversions,
};
use crate::local_mirror::{IcloudpdLocalMirrorRequest, ensure_icloudpd_local_mirror};
use crate::manifest::{AssetRecord, FailureKind, Manifest, State};
use crate::monitor::{HeicMetadataFailure, MonitorError};
use crate::proof::NasRawProof;
#[cfg(target_os = "macos")]
use crate::smb_noreplace::{
    SmbMountBinding, SmbNoReplaceCanaryReceipt, SmbNoReplaceError, SmbNoReplaceSession,
    SmbPathPair, SmbRenameResult, classify_smb_path_pair, prove_disposable_canary,
};
use crate::state_store::{AssetStateStore, JsonCheckpointStatus};
use crate::upload::{
    CLOUDKIT_ORIGINAL_ASSET_RESOLVER_VERSION, CloudKitActiveAssetValidation, CloudKitDatabaseScope,
    CloudKitDeleteBatchRequest, CloudKitDeleteClient, CloudKitDeleteOutcome, CloudKitDeleteRequest,
    CloudKitDeleteSession, CloudKitDeleteStateLookupResult, CloudKitLibraryDestination,
    CloudKitLocalReplacementCandidate, CloudKitOriginalAssetBatchResolveRequest,
    CloudKitOriginalAssetInventoryFingerprint, CloudKitOriginalAssetResolution,
    CloudKitOriginalAssetResolveDisposition, CloudKitOriginalAssetResolveTarget,
    CloudKitReplacementResourceProof, CloudKitUploadedHeicAsset, CloudKitUploadedHeicInitialState,
    CloudKitUploadedHeicResolveRequest, ReqwestCloudKitDeleteTransport, VerifiedUploadSource,
    build_upload_proof, load_cloudkit_delete_session, run_icloud_upload_with_verified_source,
};
use crate::workflow::{
    CONVERSION_PERFORMANCE_PROOF, CONVERSION_PROOF, HEIC_PROOF, HeicVerificationProof,
    ICLOUDPD_LOCAL_MIRROR_PROOF, IcloudpdLocalMirrorProof, SourceAgeProof, UPLOAD_PROOF,
    UploadProof, VerifiedHeic, WorkflowError, icloudpd_local_mirror_ready_proofs,
    record_current_heic_verification, record_icloudpd_local_mirror_proof, record_upload_proof,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LegacyUploadMigrationPreparationOutcome {
    pub(super) changed: bool,
    pub(super) checkpoint_exported: bool,
    pub(super) retired_replacement_delete_calls: u64,
}

/// Stable, redacted categories for failures in the conversion portion of the migration.
///
/// Keep this vocabulary closed: these values are surfaced by the CLI as the only diagnostic
/// for a conversion failure. In particular, do not add source error text, paths, asset IDs, or
/// hashes to this type or its formatting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LegacyConversionFailureCategory {
    ExecuteConversionTimedOut,
    ExecuteRawStagingTimedOut,
    ExecuteOutputUnreadable,
    ExecuteOutputAlreadyExists,
    ExecuteStagedRawAlreadyExists,
    ExecuteMetadataFailed,
    ExecuteToolUnavailable,
    ExecuteEmbeddedPreviewUnavailable,
    ExecuteRawStaging,
    ExecuteOutput,
    ExecuteCommand,
    ExecuteBatch,
    ExecutePlanning,
    ExecuteWorkflow,
    ExecuteUnsupportedBackend,
    ExecuteOther,
    VerifyVisualContent,
    VerifyVisualMatch,
    VerifyReferenceOrientation,
    VerifyFinalOrientation,
    VerifyDimension,
    VerifyCommand,
    VerifyOutput,
    VerifyWorkspace,
    VerifyWorkflow,
    VerifyOther,
    RecordManifest,
    RecordProof,
    RecordWorkflow,
    RecordOther,
}

impl LegacyConversionFailureCategory {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ExecuteConversionTimedOut => "conversion_execution_timed_out",
            Self::ExecuteRawStagingTimedOut => "conversion_execution_raw_staging_timed_out",
            Self::ExecuteOutputUnreadable => "conversion_execution_output_unreadable",
            Self::ExecuteOutputAlreadyExists => "conversion_execution_output_already_exists",
            Self::ExecuteStagedRawAlreadyExists => "conversion_execution_staged_raw_already_exists",
            Self::ExecuteMetadataFailed => "conversion_execution_metadata_failed",
            Self::ExecuteToolUnavailable => "conversion_execution_tool_unavailable",
            Self::ExecuteEmbeddedPreviewUnavailable => {
                "conversion_execution_embedded_preview_unavailable"
            }
            Self::ExecuteRawStaging => "conversion_execution_raw_staging",
            Self::ExecuteOutput => "conversion_execution_output",
            Self::ExecuteCommand => "conversion_execution_command",
            Self::ExecuteBatch => "conversion_execution_batch",
            Self::ExecutePlanning => "conversion_execution_planning",
            Self::ExecuteWorkflow => "conversion_execution_workflow",
            Self::ExecuteUnsupportedBackend => "conversion_execution_unsupported_backend",
            Self::ExecuteOther => "conversion_execution_other",
            Self::VerifyVisualContent => "conversion_verification_visual_content",
            Self::VerifyVisualMatch => "conversion_verification_visual_match",
            Self::VerifyReferenceOrientation => "conversion_verification_reference_orientation",
            Self::VerifyFinalOrientation => "conversion_verification_final_orientation",
            Self::VerifyDimension => "conversion_verification_dimension",
            Self::VerifyCommand => "conversion_verification_command",
            Self::VerifyOutput => "conversion_verification_output",
            Self::VerifyWorkspace => "conversion_verification_workspace",
            Self::VerifyWorkflow => "conversion_verification_workflow",
            Self::VerifyOther => "conversion_verification_other",
            Self::RecordManifest => "conversion_recording_manifest",
            Self::RecordProof => "conversion_recording_proof",
            Self::RecordWorkflow => "conversion_recording_workflow",
            Self::RecordOther => "conversion_recording_other",
        }
    }
}

impl fmt::Display for LegacyConversionFailureCategory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Fixed, redacted boundaries for the state-store reads and writes on the
/// Reset-to-Converted path. Keep this vocabulary closed: stage diagnostics
/// must never include the underlying state-store error or governed data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LegacyUploadMigrationStateStage {
    AuthoritativePhaseLoad,
    AuthorityRevalidationLoad,
    PreflightLoad,
    EnsureConvertedInitialLoad,
    EnsureConvertedPostLoad,
    EnsureConvertedPersist,
    EnsureConvertedCheckpoint,
}

impl LegacyUploadMigrationStateStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AuthoritativePhaseLoad => "state_authoritative_phase_load",
            Self::AuthorityRevalidationLoad => "state_authority_revalidation_load",
            Self::PreflightLoad => "state_preflight_load",
            Self::EnsureConvertedInitialLoad => "state_ensure_converted_initial_load",
            Self::EnsureConvertedPostLoad => "state_ensure_converted_post_load",
            Self::EnsureConvertedPersist => "state_ensure_converted_persist",
            Self::EnsureConvertedCheckpoint => "state_ensure_converted_checkpoint",
        }
    }
}

impl fmt::Display for LegacyUploadMigrationStateStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Fixed, redacted boundaries for the production CloudKit upload adapter.
///
/// Keep this vocabulary closed. These values are intentionally coarse enough
/// to avoid exposing governed remote responses, while still identifying which
/// side of the upload/reconciliation boundary rejected the operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LegacyUploadMigrationRemoteStage {
    AdapterInit,
    LocalReplacementTarget,
    LocalReplacementBinding,
    LocalReplacementBatchTransport,
    LocalReplacementInventory,
    LocalReplacementResolutionKeys,
    LocalReplacementDispositionIncompleteTransient,
    LocalReplacementDispositionAmbiguous,
    LocalReplacementDispositionNoRawResource,
    LocalReplacementDispositionRawSizeMismatch,
    LocalReplacementDispositionRawHashMismatch,
    LocalReplacementDispositionNoDateCandidate,
    LocalReplacementDispositionObservationInconsistent,
    LocalReplacementDispositionReplacementProofMismatch,
    LocalReplacementDispositionReplacementUniquenessMismatch,
    UploadExecution,
    UploadResponseBinding,
    UploadProofBinding,
    PostUploadVerificationResolverReadFailure,
    PostUploadVerificationExpectedIdentityMismatch,
    PostUploadVerificationRetiredAssetMasterCollision,
    PostUploadVerificationOriginalAssetCollision,
    PostUploadVerificationResolvedAssetMasterSelfCollision,
    PostUploadVerificationReplacementProofMismatch,
    PostUploadVerificationReceiptDigestFailure,
    CrossCandidateBinding,
}

impl LegacyUploadMigrationRemoteStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AdapterInit => "remote_adapter_init",
            Self::LocalReplacementTarget => "remote_local_replacement_target",
            Self::LocalReplacementBinding => "remote_local_replacement_binding",
            Self::LocalReplacementBatchTransport => "remote_local_replacement_batch_transport",
            Self::LocalReplacementInventory => "remote_local_replacement_inventory",
            Self::LocalReplacementResolutionKeys => "remote_local_replacement_resolution_keys",
            Self::LocalReplacementDispositionIncompleteTransient => {
                "remote_local_replacement_disposition_incomplete_transient"
            }
            Self::LocalReplacementDispositionAmbiguous => {
                "remote_local_replacement_disposition_ambiguous"
            }
            Self::LocalReplacementDispositionNoRawResource => {
                "remote_local_replacement_disposition_no_raw_resource"
            }
            Self::LocalReplacementDispositionRawSizeMismatch => {
                "remote_local_replacement_disposition_raw_size_mismatch"
            }
            Self::LocalReplacementDispositionRawHashMismatch => {
                "remote_local_replacement_disposition_raw_hash_mismatch"
            }
            Self::LocalReplacementDispositionNoDateCandidate => {
                "remote_local_replacement_disposition_no_date_candidate"
            }
            Self::LocalReplacementDispositionObservationInconsistent => {
                "remote_local_replacement_disposition_observation_inconsistent"
            }
            Self::LocalReplacementDispositionReplacementProofMismatch => {
                "remote_local_replacement_disposition_replacement_proof_mismatch"
            }
            Self::LocalReplacementDispositionReplacementUniquenessMismatch => {
                "remote_local_replacement_disposition_replacement_uniqueness_mismatch"
            }
            Self::UploadExecution => "remote_upload_execution",
            Self::UploadResponseBinding => "remote_upload_response_binding",
            Self::UploadProofBinding => "remote_upload_proof_binding",
            Self::PostUploadVerificationResolverReadFailure => {
                "remote_post_upload_verification_resolver_read_failure"
            }
            Self::PostUploadVerificationExpectedIdentityMismatch => {
                "remote_post_upload_verification_expected_response_identity_mismatch"
            }
            Self::PostUploadVerificationRetiredAssetMasterCollision => {
                "remote_post_upload_verification_retired_asset_master_collision"
            }
            Self::PostUploadVerificationOriginalAssetCollision => {
                "remote_post_upload_verification_original_asset_collision"
            }
            Self::PostUploadVerificationResolvedAssetMasterSelfCollision => {
                "remote_post_upload_verification_resolved_asset_master_self_collision"
            }
            Self::PostUploadVerificationReplacementProofMismatch => {
                "remote_post_upload_verification_replacement_proof_mismatch"
            }
            Self::PostUploadVerificationReceiptDigestFailure => {
                "remote_post_upload_verification_receipt_digest_failure"
            }
            Self::CrossCandidateBinding => "remote_cross_candidate_binding",
        }
    }
}

impl fmt::Display for LegacyUploadMigrationRemoteStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum LegacyUploadMigrationApplyError {
    #[error("legacy uploaded HEIC migration apply failed: category=state")]
    State,
    #[error("legacy uploaded HEIC migration apply failed: category={stage}")]
    StateStage {
        stage: LegacyUploadMigrationStateStage,
    },
    #[error("legacy uploaded HEIC migration apply failed: category={stage}")]
    RemoteStage {
        stage: LegacyUploadMigrationRemoteStage,
    },
    #[error("legacy uploaded HEIC migration apply failed: category={category}")]
    Evidence { category: &'static str },
    #[error("legacy uploaded HEIC migration apply failed: category=cohort")]
    Cohort,
    #[error("legacy uploaded HEIC migration apply failed: category=checkpoint_stale")]
    CheckpointStale,
    #[error("legacy uploaded HEIC migration apply failed: category=remote")]
    Remote,
    #[error("legacy uploaded HEIC migration apply failed: category=quarantine")]
    Quarantine,
    #[error("legacy uploaded HEIC migration apply failed: category=quarantine_rollback_ambiguous")]
    QuarantineRollbackAmbiguous,
    #[error("legacy uploaded HEIC migration apply failed: category=quarantine_rollback_incomplete")]
    QuarantineRollbackIncomplete,
    #[error("legacy uploaded HEIC migration apply failed: category=quarantine_residual")]
    QuarantineResidual,
    #[error("legacy uploaded HEIC migration apply failed: category=quarantine_residual_ambiguous")]
    QuarantineResidualAmbiguous,
    #[error("legacy uploaded HEIC migration apply failed: category={category}")]
    Conversion {
        category: LegacyConversionFailureCategory,
    },
}

impl LegacyUploadMigrationApplyError {
    pub(crate) const fn category(&self) -> &'static str {
        match self {
            Self::State => "state",
            Self::StateStage { stage } => stage.as_str(),
            Self::RemoteStage { stage } => stage.as_str(),
            Self::Evidence { category } => category,
            Self::Cohort => "cohort",
            Self::CheckpointStale => "checkpoint_stale",
            Self::Remote => "remote",
            Self::Quarantine => "quarantine",
            Self::QuarantineRollbackAmbiguous => "quarantine_rollback_ambiguous",
            Self::QuarantineRollbackIncomplete => "quarantine_rollback_incomplete",
            Self::QuarantineResidual => "quarantine_residual",
            Self::QuarantineResidualAmbiguous => "quarantine_residual_ambiguous",
            Self::Conversion { category } => category.as_str(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LegacyUploadQuarantineResidualAuditRequest {
    pub(crate) evidence: LegacyUploadEvidenceAuditRequest,
    pub(crate) quarantine_roots: Vec<PathBuf>,
    pub(crate) output_path: PathBuf,
}

#[derive(Clone, Debug)]
pub(crate) struct LegacyUploadQuarantineResidualRecoveryRequest {
    pub(crate) evidence: LegacyUploadEvidenceAuditRequest,
    pub(crate) quarantine_roots: Vec<PathBuf>,
    pub(crate) audit_path: PathBuf,
    pub(crate) expected_audit_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct LegacyUploadQuarantineResidualAuditReport {
    pub(crate) audit_sha256: String,
    pub(crate) directory_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct LegacyUploadQuarantineResidualRecoveryReport {
    pub(crate) status: &'static str,
    pub(crate) removed_directory_count: u64,
    pub(crate) remote_calls: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct LegacyUploadMigrationProductionRequest {
    pub(crate) evidence: LegacyUploadEvidenceAuditRequest,
    pub(crate) quarantine_roots: Vec<PathBuf>,
    pub(crate) heic_output_dir: PathBuf,
    pub(crate) mirror_root: PathBuf,
    pub(crate) upload_session_path: PathBuf,
    pub(crate) delete_session_path: PathBuf,
    pub(crate) jobs: usize,
    pub(crate) heic_quality: u8,
    pub(crate) conversion_tool_version: Option<String>,
    pub(crate) capture_tolerance_seconds: u64,
    pub(crate) cloudkit_start_rank: u64,
    pub(crate) cloudkit_page_size: u64,
    pub(crate) cloudkit_max_pages: u64,
    pub(crate) heic_verify_timeout_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct LegacyUploadMigrationApplyReport {
    pub(crate) status: &'static str,
    pub(crate) phase: &'static str,
    pub(crate) changed_phase_count: u64,
    pub(crate) checkpoint_exports: u64,
    pub(crate) checkpoint_recovered: bool,
    pub(crate) retired_replacement_delete_calls: u64,
    pub(crate) retired_replacements_already_deleted: u64,
    pub(crate) retired_replacements_deleted_by_migration: u64,
    pub(crate) replacement_uploads: u64,
    pub(crate) original_deletes: u64,
}

pub(super) trait RetiredReplacementDeleteAdapter {
    type Error;

    fn lookup(
        &mut self,
        replacement: &EvidenceRetiredReplacement,
    ) -> Result<CloudKitDeleteStateLookupResult, Self::Error>;

    fn resolve(
        &mut self,
        replacement: &EvidenceRetiredReplacement,
    ) -> Result<CloudKitUploadedHeicAsset, Self::Error>;

    fn delete(
        &mut self,
        replacement: &EvidenceRetiredReplacement,
        resolved: &CloudKitUploadedHeicAsset,
    ) -> Result<CloudKitDeleteOutcome, Self::Error>;

    fn validate_original_active(
        &mut self,
        replacement: &EvidenceRetiredReplacement,
    ) -> Result<CloudKitActiveAssetValidation, Self::Error>;
}

pub(super) struct ProductionRetiredReplacementDeleteAdapter {
    session: CloudKitDeleteSession,
    client: CloudKitDeleteClient<ReqwestCloudKitDeleteTransport>,
}

impl ProductionRetiredReplacementDeleteAdapter {
    pub(super) fn new(session_path: &Path) -> Result<Self, LegacyUploadMigrationApplyError> {
        let session = load_cloudkit_delete_session(session_path)
            .map_err(|_| LegacyUploadMigrationApplyError::Remote)?;
        let transport = ReqwestCloudKitDeleteTransport::new()
            .map_err(|_| LegacyUploadMigrationApplyError::Remote)?;
        Ok(Self {
            session,
            client: CloudKitDeleteClient::new(transport),
        })
    }

    fn destination_session(
        &self,
        replacement: &EvidenceRetiredReplacement,
    ) -> CloudKitDeleteSession {
        let mut session = self.session.clone();
        session.database_scope = replacement.destination.database_scope;
        session.zone = CloudKitLibraryDestination {
            database_scope: replacement.destination.database_scope,
            zone_name: replacement.destination.zone_name.clone(),
            owner_record_name: replacement.destination.owner_record_name.clone(),
        };
        session
    }
}

impl RetiredReplacementDeleteAdapter for ProductionRetiredReplacementDeleteAdapter {
    type Error = LegacyUploadMigrationApplyError;

    fn lookup(
        &mut self,
        replacement: &EvidenceRetiredReplacement,
    ) -> Result<CloudKitDeleteStateLookupResult, Self::Error> {
        let session = self.destination_session(replacement);
        self.client
            .lookup_delete_states(
                &session,
                &CloudKitDeleteBatchRequest {
                    requests: vec![CloudKitDeleteRequest {
                        record_name: replacement.uploaded_asset_id.clone(),
                        record_change_tag: replacement.old_record_change_tag.clone(),
                        database_scope: replacement.destination.database_scope,
                        zone_name: replacement.destination.zone_name.clone(),
                        owner_record_name: replacement.destination.owner_record_name.clone(),
                    }],
                },
            )
            .map_err(|_| LegacyUploadMigrationApplyError::Remote)
    }

    fn resolve(
        &mut self,
        replacement: &EvidenceRetiredReplacement,
    ) -> Result<CloudKitUploadedHeicAsset, Self::Error> {
        let session = self.destination_session(replacement);
        self.client
            .inspect_uploaded_heic_asset_initial_state_full_fields(
                &session,
                &CloudKitUploadedHeicResolveRequest {
                    uploaded_asset_id: replacement.uploaded_asset_id.clone(),
                    expected_heic_sha256: replacement.uploaded_heic_sha256.clone(),
                    expected_size_bytes: replacement.uploaded_heic_size_bytes,
                    database_scope: replacement.destination.database_scope,
                    zone_name: replacement.destination.zone_name.clone(),
                    owner_record_name: replacement.destination.owner_record_name.clone(),
                },
            )
            .map_err(|_| LegacyUploadMigrationApplyError::Remote)
    }

    fn delete(
        &mut self,
        replacement: &EvidenceRetiredReplacement,
        resolved: &CloudKitUploadedHeicAsset,
    ) -> Result<CloudKitDeleteOutcome, Self::Error> {
        let session = self.destination_session(replacement);
        self.client
            .delete_cpl_asset(
                &session,
                &CloudKitDeleteRequest {
                    record_name: resolved.record_name.clone(),
                    record_change_tag: resolved.record_change_tag.clone(),
                    database_scope: replacement.destination.database_scope,
                    zone_name: replacement.destination.zone_name.clone(),
                    owner_record_name: replacement.destination.owner_record_name.clone(),
                },
            )
            .map_err(|_| LegacyUploadMigrationApplyError::Remote)
    }

    fn validate_original_active(
        &mut self,
        replacement: &EvidenceRetiredReplacement,
    ) -> Result<CloudKitActiveAssetValidation, Self::Error> {
        let session = self.destination_session(replacement);
        let request = crate::upload::CloudKitActiveAssetReadRequest {
            record_name: replacement.original_asset_record_name.clone(),
            record_change_tag: replacement.original_record_change_tag.clone(),
            database_scope: replacement.destination.database_scope,
            zone_name: replacement.destination.zone_name.clone(),
            owner_record_name: replacement.destination.owner_record_name.clone(),
        };
        self.client
            .validate_active_asset_identity(&session, &request)
            .map_err(|_| LegacyUploadMigrationApplyError::Remote)
    }
}

struct RetiredReplacementDeleteConfirmation {
    outcomes: [CloudKitDeleteOutcome; 2],
    delete_calls: u64,
}

enum RetiredReplacementRemotePreflight {
    Confirmed(CloudKitDeleteOutcome),
    Pending(CloudKitUploadedHeicAsset),
}

#[cfg(test)]
pub(super) fn confirm_retired_replacement_deletes<T: RetiredReplacementDeleteAdapter>(
    evidence: &ValidatedLegacyUploadEvidence,
    adapter: &mut T,
) -> Result<[CloudKitDeleteOutcome; 2], LegacyUploadMigrationApplyError> {
    confirm_retired_replacement_deletes_with_stats(evidence, adapter, &mut || Ok(()))
        .map(|confirmation| confirmation.outcomes)
}

fn confirm_retired_replacement_deletes_with_stats<T: RetiredReplacementDeleteAdapter>(
    evidence: &ValidatedLegacyUploadEvidence,
    adapter: &mut T,
    before_delete: &mut impl FnMut() -> Result<(), LegacyUploadMigrationApplyError>,
) -> Result<RetiredReplacementDeleteConfirmation, LegacyUploadMigrationApplyError> {
    let replacements = evidence.retired_replacements();
    let preflights = replacements
        .iter()
        .map(|replacement| {
            let resolved = adapter
                .resolve(replacement)
                .map_err(|_| LegacyUploadMigrationApplyError::Remote)?;
            let preflight = if replacement.initial_remote_state
                == CloudKitUploadedHeicInitialState::AlreadyDeleted
            {
                require_exact_resolved(replacement, &resolved)?;
                RetiredReplacementRemotePreflight::Confirmed(CloudKitDeleteOutcome {
                    record_name: resolved.record_name,
                    record_change_tag: resolved.record_change_tag,
                })
            } else if resolved.initial_remote_state
                == CloudKitUploadedHeicInitialState::AlreadyDeleted
            {
                require_exact_recovered_delete(replacement, &resolved)?;
                RetiredReplacementRemotePreflight::Confirmed(CloudKitDeleteOutcome {
                    record_name: resolved.record_name,
                    record_change_tag: resolved.record_change_tag,
                })
            } else {
                require_exact_resolved(replacement, &resolved)?;
                RetiredReplacementRemotePreflight::Pending(resolved)
            };
            let original_remote = adapter
                .validate_original_active(replacement)
                .map_err(|_| LegacyUploadMigrationApplyError::Remote)?;
            if original_remote.remote_state != replacement.original_remote_state
                || original_remote.lookup_mode != replacement.original_state_lookup_mode
            {
                return Err(LegacyUploadMigrationApplyError::Remote);
            }
            Ok(preflight)
        })
        .collect::<Result<Vec<_>, LegacyUploadMigrationApplyError>>()?;
    let preflights: [RetiredReplacementRemotePreflight; 2] = preflights
        .try_into()
        .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;

    let mut confirmed = Vec::with_capacity(2);
    let mut delete_calls = 0_u64;
    let mut pending_after_current = preflights
        .iter()
        .filter(|preflight| matches!(preflight, RetiredReplacementRemotePreflight::Pending(_)))
        .count();
    for (replacement, preflight) in replacements.iter().zip(preflights) {
        match preflight {
            RetiredReplacementRemotePreflight::Confirmed(outcome) => {
                confirmed.push(outcome);
            }
            RetiredReplacementRemotePreflight::Pending(resolved) => {
                before_delete()?;
                pending_after_current -= 1;
                delete_calls += 1;
                match adapter.delete(replacement, &resolved) {
                    Ok(outcome) => {
                        require_exact_delete_outcome(replacement, &outcome)?;
                        confirmed.push(outcome);
                    }
                    Err(_) => {
                        let reconciled = adapter
                            .lookup(replacement)
                            .map_err(|_| LegacyUploadMigrationApplyError::Remote)?;
                        confirmed.push(
                            exact_confirmed_delete(replacement, &reconciled)
                                .ok_or(LegacyUploadMigrationApplyError::Remote)?
                                .clone(),
                        );
                        if pending_after_current != 0 {
                            return Err(LegacyUploadMigrationApplyError::Remote);
                        }
                    }
                }
            }
        }
    }
    let outcomes = confirmed
        .try_into()
        .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
    Ok(RetiredReplacementDeleteConfirmation {
        outcomes,
        delete_calls,
    })
}

#[derive(Serialize)]
pub(super) struct DeleteConfirmedReceipt {
    schema_version: u64,
    asset_id: String,
    pub(super) initial_remote_state: CloudKitUploadedHeicInitialState,
    initial_state_lookup_mode: crate::upload::CloudKitUploadedHeicInitialStateLookupMode,
    destination_sha256: String,
    retired_record_name_sha256: String,
    sealed_change_tag_sha256: String,
    confirmed_change_tag_sha256: String,
}

pub(super) fn delete_confirmed_receipt(
    replacement: &EvidenceRetiredReplacement,
    outcome: &CloudKitDeleteOutcome,
) -> Result<DeleteConfirmedReceipt, LegacyUploadMigrationApplyError> {
    Ok(DeleteConfirmedReceipt {
        schema_version: 2,
        asset_id: replacement.asset_id.clone(),
        initial_remote_state: replacement.initial_remote_state,
        initial_state_lookup_mode: replacement.initial_state_lookup_mode,
        destination_sha256: replacement.destination_sha256.clone(),
        retired_record_name_sha256: canonical_digest(&replacement.uploaded_asset_id)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
        sealed_change_tag_sha256: canonical_digest(&replacement.old_record_change_tag)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
        confirmed_change_tag_sha256: canonical_digest(&outcome.record_change_tag)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
    })
}

#[derive(Serialize)]
struct ResetReceipt {
    schema_version: u64,
    asset_id: String,
    removed_proofs_sha256: String,
    retained_original_identity_sha256: String,
    retained_delete_confirmation_entry_sha256: String,
}

#[derive(Serialize)]
struct ConvertedReceipt {
    schema_version: u64,
    asset_id: String,
    output_path_sha256: String,
    conversion_proof_sha256: String,
    performance_proof_sha256: String,
    heic_proof_sha256: String,
    output_identity: QuarantineFileIdentity,
}

#[derive(Serialize)]
struct UploadPreparedReceipt {
    schema_version: u64,
    asset_id: String,
    destination_sha256: String,
    output_path_sha256: String,
    output_identity: QuarantineFileIdentity,
}

#[derive(Serialize)]
struct UploadVerifiedPhaseReceipt<'a> {
    schema_version: u64,
    asset_id: &'a str,
    upload_proof_sha256: String,
    remote: &'a VerifiedRemoteUploadReceipt,
}

#[derive(Serialize)]
struct MirroredReceipt {
    schema_version: u64,
    asset_id: String,
    mirror_proof_sha256: String,
    upload_proof_sha256: String,
    destination_path_sha256: String,
    destination_identity: QuarantineFileIdentity,
}

#[derive(Serialize)]
struct CompleteReceipt {
    schema_version: u64,
    asset_id: String,
    destination_sha256: String,
    operational_record_sha256: String,
    prior_journal_sha256: String,
    converted: ConvertedReceipt,
    mirrored: MirroredReceipt,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct QuarantineBatchReceipt {
    pub(super) schema_version: u64,
    pub(super) cohort_sha256: String,
    pub(super) canonical_root_identity_sha256: String,
    pub(super) target_set_sha256: String,
    pub(super) target_count: u64,
    pub(super) normalized_reference_count: u64,
}

pub(super) trait LegacyArtifactQuarantineAdapter {
    type Error;

    fn quarantine_and_normalize(
        &mut self,
        evidence: &ValidatedLegacyUploadEvidence,
        manifest: &crate::manifest::Manifest,
    ) -> Result<QuarantineBatchReceipt, Self::Error>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SmbCapabilityAuthority {
    schema_version: u64,
    registry_sha256: String,
    evidence_sha256: String,
    cohort_sha256: String,
    quarantine_plan_sha256: String,
}

#[cfg(target_os = "macos")]
#[derive(Serialize)]
struct BoundSmbCapabilityDigestInput<'a> {
    schema_version: u64,
    authority: &'a SmbCapabilityAuthority,
    canary: &'a SmbNoReplaceCanaryReceipt,
}

#[cfg(target_os = "macos")]
struct BoundSmbCapability {
    authority: SmbCapabilityAuthority,
    canary: SmbNoReplaceCanaryReceipt,
    capability_sha256: String,
    session: SmbNoReplaceSession,
}

#[derive(Default)]
struct SmbQuarantineCapabilities {
    #[cfg(target_os = "macos")]
    capabilities: Vec<BoundSmbCapability>,
}

impl SmbQuarantineCapabilities {
    fn unavailable() -> Self {
        Self::default()
    }

    fn prepare(
        registry: &LegacyUploadMigrationRegistry,
    ) -> Result<Self, LegacyUploadMigrationApplyError> {
        let authority = SmbCapabilityAuthority {
            schema_version: 1,
            registry_sha256: registry.registry_sha256.clone(),
            evidence_sha256: registry.evidence_sha256.clone(),
            cohort_sha256: registry.cohort_sha256.clone(),
            quarantine_plan_sha256: registry.quarantine_plan.plan_sha256.clone(),
        };
        if !valid_sha256(&authority.registry_sha256)
            || !valid_sha256(&authority.evidence_sha256)
            || !valid_sha256(&authority.cohort_sha256)
            || !valid_sha256(&authority.quarantine_plan_sha256)
        {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }

        #[cfg(target_os = "macos")]
        {
            let bindings = smb_bindings_for_plan(&registry.quarantine_plan)?;
            let mut capabilities = Vec::with_capacity(bindings.len());
            for binding in bindings.into_values() {
                let (session, canary) = prove_disposable_canary(binding)
                    .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
                if canary.schema_version != 2
                    || !canary.missing_target_rename
                    || canary.collision_status != "STATUS_OBJECT_NAME_COLLISION"
                    || !canary.collision_preserved_both
                    || !canary.cleanup_complete
                    || canary.binding
                        != session
                            .binding()
                            .redacted_proof()
                            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?
                    || canary.session != *session.proof()
                {
                    return Err(LegacyUploadMigrationApplyError::Quarantine);
                }
                let capability_sha256 = canonical_digest(&BoundSmbCapabilityDigestInput {
                    schema_version: 1,
                    authority: &authority,
                    canary: &canary,
                })
                .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
                capabilities.push(BoundSmbCapability {
                    authority: authority.clone(),
                    canary,
                    capability_sha256,
                    session,
                });
            }
            Ok(Self { capabilities })
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = registry;
            Ok(Self::default())
        }
    }

    fn revalidate_authority(
        &self,
        evidence: &ValidatedLegacyUploadEvidence,
        manifest: &Manifest,
    ) -> Result<(), LegacyUploadMigrationApplyError> {
        #[cfg(target_os = "macos")]
        {
            let registry = manifest
                .legacy_upload_migration_registry()
                .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
            if registry.quarantine_plan != *evidence.sealed_quarantine_plan() {
                return Err(LegacyUploadMigrationApplyError::Quarantine);
            }
            let expected = SmbCapabilityAuthority {
                schema_version: 1,
                registry_sha256: registry.registry_sha256.clone(),
                evidence_sha256: evidence.audit().evidence_sha256.clone(),
                cohort_sha256: evidence.audit().cohort_sha256.clone(),
                quarantine_plan_sha256: evidence.sealed_quarantine_plan().plan_sha256.clone(),
            };
            for capability in &self.capabilities {
                if capability.authority != expected
                    || capability.canary.binding
                        != capability
                            .session
                            .binding()
                            .redacted_proof()
                            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?
                    || capability.canary.session != *capability.session.proof()
                    || canonical_digest(&BoundSmbCapabilityDigestInput {
                        schema_version: 1,
                        authority: &capability.authority,
                        canary: &capability.canary,
                    })
                    .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?
                        != capability.capability_sha256
                {
                    return Err(LegacyUploadMigrationApplyError::Quarantine);
                }
            }
            self.validate_plan_mapping(evidence.quarantine_plan())?;
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (evidence, manifest);
        }
        Ok(())
    }

    fn validate_plan_mapping(
        &self,
        plan: &LegacyUploadMigrationQuarantinePlan,
    ) -> Result<(), LegacyUploadMigrationApplyError> {
        #[cfg(target_os = "macos")]
        {
            let current = smb_bindings_for_plan(plan)?;
            if current.len() != self.capabilities.len() {
                return Err(LegacyUploadMigrationApplyError::Quarantine);
            }
            for (root, binding) in current {
                let capability = self
                    .capabilities
                    .iter()
                    .find(|candidate| candidate.session.binding().mount_root == root)
                    .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
                if !capability.session.binding().same_mount_endpoint(&binding)
                    || capability.canary.binding
                        != capability
                            .session
                            .binding()
                            .redacted_proof()
                            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?
                {
                    return Err(LegacyUploadMigrationApplyError::Quarantine);
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = plan;
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn session_for_paths(
        &mut self,
        source: &Path,
        destination: &Path,
    ) -> Result<Option<&mut SmbNoReplaceSession>, LegacyUploadMigrationApplyError> {
        let source_binding = SmbMountBinding::discover_for_path(source)
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        let destination_binding = SmbMountBinding::discover_for_path(destination)
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        match classify_smb_path_pair(source_binding, destination_binding)
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?
        {
            SmbPathPair::Local => Ok(None),
            SmbPathPair::Mounted(source_binding) => {
                let capability = self
                    .capabilities
                    .iter_mut()
                    .find(|candidate| {
                        candidate
                            .session
                            .binding()
                            .same_mount_endpoint(&source_binding)
                    })
                    .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
                if capability.canary.binding
                    != capability
                        .session
                        .binding()
                        .redacted_proof()
                        .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?
                    || capability.canary.session != *capability.session.proof()
                    || canonical_digest(&BoundSmbCapabilityDigestInput {
                        schema_version: 1,
                        authority: &capability.authority,
                        canary: &capability.canary,
                    })
                    .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?
                        != capability.capability_sha256
                {
                    return Err(LegacyUploadMigrationApplyError::Quarantine);
                }
                Ok(Some(&mut capability.session))
            }
        }
    }
}

fn after_smb_capability_gate<T>(
    gate: impl FnOnce() -> Result<(), LegacyUploadMigrationApplyError>,
    governed_access: impl FnOnce() -> Result<T, LegacyUploadMigrationApplyError>,
) -> Result<T, LegacyUploadMigrationApplyError> {
    gate()?;
    governed_access()
}

struct SmbGovernedPathGate;

fn prove_smb_governed_path_gate(
    validation: impl FnOnce() -> Result<(), LegacyUploadMigrationApplyError>,
) -> Result<SmbGovernedPathGate, LegacyUploadMigrationApplyError> {
    after_smb_capability_gate(validation, || Ok(SmbGovernedPathGate))
}

fn canonicalize_governed_path(
    _gate: &SmbGovernedPathGate,
    path: &Path,
) -> Result<PathBuf, LegacyUploadMigrationApplyError> {
    fs::canonicalize(path).map_err(|_| LegacyUploadMigrationApplyError::Quarantine)
}

#[cfg(target_os = "macos")]
fn smb_bindings_for_plan(
    plan: &LegacyUploadMigrationQuarantinePlan,
) -> Result<BTreeMap<PathBuf, SmbMountBinding>, LegacyUploadMigrationApplyError> {
    let mut bindings = BTreeMap::new();
    let mut add_path = |path: &Path| -> Result<(), LegacyUploadMigrationApplyError> {
        if let Some(binding) = SmbMountBinding::discover_for_path(path)
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?
        {
            match bindings.get(&binding.mount_root) {
                Some(existing) if existing != &binding => {
                    return Err(LegacyUploadMigrationApplyError::Quarantine);
                }
                Some(_) => {}
                None => {
                    bindings.insert(binding.mount_root.clone(), binding);
                }
            }
        }
        Ok(())
    };
    for root in &plan.roots {
        add_path(&root.canonical_path)?;
    }
    for member in &plan.members {
        let source_binding = SmbMountBinding::discover_for_path(&member.source_path)
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        let destination_binding = SmbMountBinding::discover_for_path(&member.destination_path)
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        if source_binding != destination_binding {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        add_path(&member.source_path)?;
        add_path(&member.destination_path)?;
    }
    for raw in &plan.raw_inputs {
        add_path(&raw.path)?;
    }
    Ok(bindings)
}

enum SmbCapabilityAccess<'a> {
    #[cfg(test)]
    Unavailable,
    Proven(&'a mut SmbQuarantineCapabilities),
}

impl SmbCapabilityAccess<'_> {
    fn validate_plan_mapping(
        &self,
        plan: &LegacyUploadMigrationQuarantinePlan,
    ) -> Result<(), LegacyUploadMigrationApplyError> {
        match self {
            #[cfg(test)]
            Self::Unavailable => {
                SmbQuarantineCapabilities::unavailable().validate_plan_mapping(plan)
            }
            Self::Proven(capabilities) => capabilities.validate_plan_mapping(plan),
        }
    }

    #[cfg(target_os = "macos")]
    fn session_for_paths(
        &mut self,
        source: &Path,
        destination: &Path,
    ) -> Result<Option<&mut SmbNoReplaceSession>, LegacyUploadMigrationApplyError> {
        match self {
            #[cfg(test)]
            Self::Unavailable => {
                let source_binding = SmbMountBinding::discover_for_path(source)
                    .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
                let destination_binding = SmbMountBinding::discover_for_path(destination)
                    .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
                if source_binding.is_some() || destination_binding.is_some() {
                    Err(LegacyUploadMigrationApplyError::Quarantine)
                } else {
                    Ok(None)
                }
            }
            Self::Proven(capabilities) => capabilities.session_for_paths(source, destination),
        }
    }
}

pub(super) struct ProductionLegacyArtifactQuarantineAdapter<'a> {
    quarantine_roots: Vec<PathBuf>,
    image_timeout_seconds: u64,
    smb_capabilities: SmbCapabilityAccess<'a>,
}

#[cfg(test)]
impl ProductionLegacyArtifactQuarantineAdapter<'static> {
    pub(super) fn new(quarantine_roots: Vec<PathBuf>, image_timeout_seconds: u64) -> Self {
        Self {
            quarantine_roots,
            image_timeout_seconds,
            smb_capabilities: SmbCapabilityAccess::Unavailable,
        }
    }
}

impl<'a> ProductionLegacyArtifactQuarantineAdapter<'a> {
    fn new_with_smb_capabilities(
        quarantine_roots: Vec<PathBuf>,
        image_timeout_seconds: u64,
        smb_capabilities: &'a mut SmbQuarantineCapabilities,
    ) -> Self {
        Self {
            quarantine_roots,
            image_timeout_seconds,
            smb_capabilities: SmbCapabilityAccess::Proven(smb_capabilities),
        }
    }
}

type QuarantineTargetKind = LegacyUploadMigrationQuarantineKind;

#[derive(Clone)]
struct QuarantineTargetSpec {
    asset_id: String,
    kind: QuarantineTargetKind,
    source_path: PathBuf,
    expected_sha256: String,
    expected_size_bytes: u64,
    expected_reference: Option<EvidenceReferenceNormalization>,
}

type QuarantineFileIdentity = LegacyUploadMigrationQuarantineFileIdentity;

struct AnchoredQuarantineFile {
    parent: File,
    name: CString,
    file: File,
    identity: QuarantineFileIdentity,
}

enum QuarantineLocation {
    Source(AnchoredQuarantineFile),
    Destination(QuarantineFileIdentity),
}

struct PreflightQuarantineTarget {
    spec: QuarantineTargetSpec,
    source_parent: File,
    source_name: CString,
    destination_name: CString,
    destination_path: PathBuf,
    root_index: usize,
    location: QuarantineLocation,
    normalized_source: Option<AnchoredQuarantineFile>,
    normalization_temp_name: Option<CString>,
    normalization_temp: Option<AnchoredReferenceNormalizationTemp>,
}

struct QuarantineRootContext {
    root: File,
    cohort: File,
    metadata: fs::Metadata,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct QuarantineDirectoryIdentity {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) owner: u32,
    pub(super) mode: u32,
    pub(super) link_count: u64,
}

struct HeldQuarantineRoot {
    root_path: PathBuf,
    root: File,
    root_identity: QuarantineDirectoryIdentity,
    cohort_path: PathBuf,
    cohort_name: CString,
    cohort: Option<File>,
    cohort_identity: Option<QuarantineDirectoryIdentity>,
    cohort_must_be_empty: bool,
}

pub(super) struct QuarantinePreflightGuard {
    roots: Vec<HeldQuarantineRoot>,
    files: Vec<AnchoredQuarantineFile>,
    named_files: Vec<(PathBuf, QuarantineFileIdentity)>,
    absent_files: Vec<PathBuf>,
}

const QUARANTINE_MATERIALIZATION_PROGRESS_SCHEMA_VERSION: u64 = 1;
const MAX_QUARANTINE_MATERIALIZATION_ATTEMPTS: usize = 64;
const QUARANTINE_MATERIALIZATION_GENESIS_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QuarantineMaterializationAuthority {
    schema_version: u64,
    evidence_sha256: String,
    cohort_sha256: String,
    quarantine_plan_sha256: String,
    root_count: u64,
    root_set_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QuarantineMaterializationCreateIntent {
    schema_version: u64,
    authority_sha256: String,
    root_ordinal: u64,
    attempt: u64,
    root_sha256: String,
    cohort_path_sha256: String,
    previous_removal_done_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum QuarantineMaterializationCreateDisposition {
    Created,
    AlreadyExactOwned,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QuarantineMaterializationCreated {
    schema_version: u64,
    authority_sha256: String,
    root_ordinal: u64,
    attempt: u64,
    create_intent_sha256: String,
    directory: QuarantineDirectoryIdentity,
    disposition: QuarantineMaterializationCreateDisposition,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum QuarantineDirectoryMutationDurability {
    Synced,
    RevalidatedAfterUnsupportedDirectorySync,
    RevalidatedAfterFailedDirectorySync,
    NotRequired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QuarantineMaterializationCommitted {
    schema_version: u64,
    authority_sha256: String,
    root_ordinal: u64,
    attempt: u64,
    created_sha256: String,
    directory: QuarantineDirectoryIdentity,
    durability: QuarantineDirectoryMutationDurability,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QuarantineMaterializationRemovalIntent {
    schema_version: u64,
    authority_sha256: String,
    root_ordinal: u64,
    attempt: u64,
    create_intent_sha256: String,
    created_sha256: Option<String>,
    directory: Option<QuarantineDirectoryIdentity>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum QuarantineMaterializationRemovalDisposition {
    RemovalComplete,
    AlreadyAbsent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QuarantineMaterializationRemovalDone {
    schema_version: u64,
    authority_sha256: String,
    root_ordinal: u64,
    attempt: u64,
    removal_intent_sha256: String,
    directory: Option<QuarantineDirectoryIdentity>,
    disposition: QuarantineMaterializationRemovalDisposition,
    durability: QuarantineDirectoryMutationDurability,
}

struct QuarantineMaterializationAttemptPaths {
    create_intent: PathBuf,
    created: PathBuf,
    committed: PathBuf,
    removal_intent: PathBuf,
    removal_done: PathBuf,
}

struct LoadedQuarantineMaterializationAttempt {
    intent_sha256: String,
    created: Option<(QuarantineMaterializationCreated, String)>,
    committed: Option<(QuarantineMaterializationCommitted, String)>,
    removal_intent: Option<(QuarantineMaterializationRemovalIntent, String)>,
    removal_done: Option<(QuarantineMaterializationRemovalDone, String)>,
}

impl QuarantinePreflightGuard {
    pub(super) fn revalidate(&self) -> Result<(), LegacyUploadMigrationApplyError> {
        for root in &self.roots {
            if quarantine_directory_identity(&root.root)? != root.root_identity
                || open_named_quarantine_directory_identity(&root.root_path)? != root.root_identity
            {
                return Err(LegacyUploadMigrationApplyError::Quarantine);
            }
            match (&root.cohort, root.cohort_identity) {
                (Some(cohort), Some(identity)) => {
                    if quarantine_directory_identity(cohort)? != identity
                        || open_named_quarantine_directory_identity(&root.cohort_path)? != identity
                        || root.cohort_must_be_empty && !quarantine_directory_is_empty(cohort)?
                    {
                        return Err(LegacyUploadMigrationApplyError::Quarantine);
                    }
                }
                (None, None) => {
                    if open_optional_quarantine_directory_at(
                        root.root.as_raw_fd(),
                        &root.cohort_name,
                    )?
                    .is_some()
                    {
                        return Err(LegacyUploadMigrationApplyError::Quarantine);
                    }
                }
                _ => return Err(LegacyUploadMigrationApplyError::Quarantine),
            }
        }
        revalidate_anchored_files(&self.files)?;
        for (path, identity) in &self.named_files {
            if open_optional_anchored_quarantine_file(path)?
                .is_none_or(|file| &file.identity != identity)
            {
                return Err(LegacyUploadMigrationApplyError::Quarantine);
            }
        }
        for path in &self.absent_files {
            if open_optional_anchored_quarantine_file(path)?.is_some() {
                return Err(LegacyUploadMigrationApplyError::Quarantine);
            }
        }
        Ok(())
    }
}

fn materialization_progress_bytes(
    value: &impl Serialize,
) -> Result<Vec<u8>, LegacyUploadMigrationApplyError> {
    strict_progress_bytes(value)
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)
}

fn materialization_progress_path(
    evidence: &ValidatedLegacyUploadEvidence,
    suffix: &str,
) -> Result<PathBuf, LegacyUploadMigrationApplyError> {
    if !valid_sha256(&evidence.audit().evidence_sha256)
        || suffix.is_empty()
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }
    let canonical_evidence = fs::canonicalize(evidence.evidence_path())
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?;
    let parent = canonical_evidence
        .parent()
        .ok_or(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?;
    let parent_metadata = fs::symlink_metadata(parent)
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != unsafe { libc::geteuid() }
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }
    Ok(parent.join(format!(
        ".icloudpd-quarantine-materialization-{}.{}.json",
        evidence.audit().evidence_sha256,
        suffix
    )))
}

fn materialization_attempt_paths(
    evidence: &ValidatedLegacyUploadEvidence,
    root_ordinal: usize,
    attempt: usize,
) -> Result<QuarantineMaterializationAttemptPaths, LegacyUploadMigrationApplyError> {
    let prefix = format!("r{root_ordinal:04}.a{attempt:04}");
    Ok(QuarantineMaterializationAttemptPaths {
        create_intent: materialization_progress_path(evidence, &format!("{prefix}.create.intent"))?,
        created: materialization_progress_path(evidence, &format!("{prefix}.created"))?,
        committed: materialization_progress_path(evidence, &format!("{prefix}.committed"))?,
        removal_intent: materialization_progress_path(
            evidence,
            &format!("{prefix}.remove.intent"),
        )?,
        removal_done: materialization_progress_path(evidence, &format!("{prefix}.remove.done"))?,
    })
}

fn read_materialization_progress<T>(
    path: &Path,
) -> Result<Option<(T, String)>, LegacyUploadMigrationApplyError>
where
    T: DeserializeOwned + Serialize,
{
    if !owner_only_file_exists(path)
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?
    {
        return Ok(None);
    }
    let mut sealed = read_sealed_quarantine_residual_audit(path)
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?;
    sealed
        .revalidate()
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?;
    let parsed: T = crate::strict_json::from_reader(sealed.bytes.as_slice())
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?;
    if materialization_progress_bytes(&parsed)? != sealed.bytes {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }
    Ok(Some((parsed, sealed.identity.sha256)))
}

fn ensure_materialization_progress(
    path: &Path,
    value: &impl Serialize,
) -> Result<String, LegacyUploadMigrationApplyError> {
    let bytes = materialization_progress_bytes(value)?;
    ensure_exact_owner_only_progress_file(path, &bytes)
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)
}

fn materialization_progress_artifact_exists(
    path: &Path,
) -> Result<bool, LegacyUploadMigrationApplyError> {
    owner_only_file_exists(path)
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)
}

fn directory_mutation_durability(
    directory: &File,
) -> Result<QuarantineDirectoryMutationDurability, LegacyUploadMigrationApplyError> {
    match directory.sync_all() {
        Ok(()) => Ok(QuarantineDirectoryMutationDurability::Synced),
        Err(error)
            if error.kind() == std::io::ErrorKind::Unsupported
                || error
                    .raw_os_error()
                    .is_some_and(|code| [libc::EINVAL, libc::ENOTSUP].contains(&code)) =>
        {
            Ok(QuarantineDirectoryMutationDurability::RevalidatedAfterUnsupportedDirectorySync)
        }
        Err(_) => Err(LegacyUploadMigrationApplyError::Quarantine),
    }
}

fn current_exact_empty_materialized_directory(
    root: &File,
    cohort_name: &CStr,
) -> Result<Option<(File, QuarantineDirectoryIdentity)>, LegacyUploadMigrationApplyError> {
    let current = open_optional_quarantine_directory_at(root.as_raw_fd(), cohort_name)
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?;
    let Some(current) = current else {
        return Ok(None);
    };
    let root_identity = quarantine_directory_identity(root)
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?;
    let identity = quarantine_directory_identity(&current)
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?;
    if identity.device != root_identity.device
        || !quarantine_directory_is_empty(&current)
            .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }
    Ok(Some((current, identity)))
}

fn revalidate_materialized_directory(
    root: &File,
    cohort_name: &CStr,
    held: &File,
    expected: QuarantineDirectoryIdentity,
) -> Result<(), LegacyUploadMigrationApplyError> {
    if quarantine_directory_identity(held)? != expected || !quarantine_directory_is_empty(held)? {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }
    let named = current_exact_empty_materialized_directory(root, cohort_name)?
        .ok_or(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?;
    if named.1 != expected {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }
    Ok(())
}

fn expected_quarantine_materialization_authority(
    evidence: &ValidatedLegacyUploadEvidence,
) -> Result<QuarantineMaterializationAuthority, LegacyUploadMigrationApplyError> {
    let plan = evidence.quarantine_plan();
    if plan.roots.is_empty() {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }
    Ok(QuarantineMaterializationAuthority {
        schema_version: QUARANTINE_MATERIALIZATION_PROGRESS_SCHEMA_VERSION,
        evidence_sha256: evidence.audit().evidence_sha256.clone(),
        cohort_sha256: evidence.audit().cohort_sha256.clone(),
        quarantine_plan_sha256: plan.plan_sha256.clone(),
        root_count: plan.roots.len() as u64,
        root_set_sha256: canonical_digest(&plan.roots)
            .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?,
    })
}

fn quarantine_materialization_authority(
    evidence: &ValidatedLegacyUploadEvidence,
    roots: &[(File, Option<File>)],
) -> Result<(String, PathBuf), LegacyUploadMigrationApplyError> {
    let authority = expected_quarantine_materialization_authority(evidence)?;
    if roots.len() as u64 != authority.root_count {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }
    let authority_path = materialization_progress_path(evidence, "authority")?;
    let existing: Option<(QuarantineMaterializationAuthority, String)> =
        read_materialization_progress(&authority_path)?;
    if let Some((persisted, sha256)) = existing {
        if persisted != authority {
            return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
        }
        return Ok((sha256, authority_path));
    }
    if roots.iter().any(|(_, cohort)| cohort.is_some()) {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }
    let sha256 = ensure_materialization_progress(&authority_path, &authority)?;
    Ok((sha256, authority_path))
}

fn revalidate_quarantine_materialization_authority(
    evidence: &ValidatedLegacyUploadEvidence,
    authority_sha256: &str,
) -> Result<(), LegacyUploadMigrationApplyError> {
    let path = materialization_progress_path(evidence, "authority")?;
    let (persisted, persisted_sha256): (QuarantineMaterializationAuthority, String) =
        read_materialization_progress(&path)?
            .ok_or(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?;
    if persisted != expected_quarantine_materialization_authority(evidence)?
        || persisted_sha256 != authority_sha256
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }
    Ok(())
}

fn materialization_create_intent(
    evidence: &ValidatedLegacyUploadEvidence,
    authority_sha256: &str,
    root_ordinal: usize,
    attempt: usize,
    previous_removal_done_sha256: &str,
) -> Result<QuarantineMaterializationCreateIntent, LegacyUploadMigrationApplyError> {
    let root = evidence
        .quarantine_plan()
        .roots
        .get(root_ordinal)
        .ok_or(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?;
    let cohort_path = root
        .canonical_path
        .join(evidence.audit().cohort_sha256.as_str());
    Ok(QuarantineMaterializationCreateIntent {
        schema_version: QUARANTINE_MATERIALIZATION_PROGRESS_SCHEMA_VERSION,
        authority_sha256: authority_sha256.to_string(),
        root_ordinal: root_ordinal as u64,
        attempt: attempt as u64,
        root_sha256: canonical_digest(root)
            .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?,
        cohort_path_sha256: canonical_digest(&cohort_path)
            .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?,
        previous_removal_done_sha256: previous_removal_done_sha256.to_string(),
    })
}

fn load_materialization_attempt(
    paths: &QuarantineMaterializationAttemptPaths,
    expected_intent: &QuarantineMaterializationCreateIntent,
) -> Result<Option<LoadedQuarantineMaterializationAttempt>, LegacyUploadMigrationApplyError> {
    let intent: Option<(QuarantineMaterializationCreateIntent, String)> =
        read_materialization_progress(&paths.create_intent)?;
    let created: Option<(QuarantineMaterializationCreated, String)> =
        read_materialization_progress(&paths.created)?;
    let committed: Option<(QuarantineMaterializationCommitted, String)> =
        read_materialization_progress(&paths.committed)?;
    let removal_intent: Option<(QuarantineMaterializationRemovalIntent, String)> =
        read_materialization_progress(&paths.removal_intent)?;
    let removal_done: Option<(QuarantineMaterializationRemovalDone, String)> =
        read_materialization_progress(&paths.removal_done)?;
    let Some((intent, intent_sha256)) = intent else {
        if created.is_some()
            || committed.is_some()
            || removal_intent.is_some()
            || removal_done.is_some()
        {
            return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
        }
        return Ok(None);
    };
    if &intent != expected_intent {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }
    if let Some((created, _)) = &created
        && (created.schema_version != QUARANTINE_MATERIALIZATION_PROGRESS_SCHEMA_VERSION
            || created.authority_sha256 != intent.authority_sha256
            || created.root_ordinal != intent.root_ordinal
            || created.attempt != intent.attempt
            || created.create_intent_sha256 != intent_sha256)
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }
    if let Some((committed, _)) = &committed {
        let Some((created, created_sha256)) = &created else {
            return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
        };
        if committed.schema_version != QUARANTINE_MATERIALIZATION_PROGRESS_SCHEMA_VERSION
            || committed.authority_sha256 != intent.authority_sha256
            || committed.root_ordinal != intent.root_ordinal
            || committed.attempt != intent.attempt
            || committed.created_sha256 != *created_sha256
            || committed.directory != created.directory
            || matches!(
                committed.durability,
                QuarantineDirectoryMutationDurability::NotRequired
                    | QuarantineDirectoryMutationDurability::RevalidatedAfterFailedDirectorySync
            )
        {
            return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
        }
    }
    if let Some((removal, _)) = &removal_intent
        && (removal.schema_version != QUARANTINE_MATERIALIZATION_PROGRESS_SCHEMA_VERSION
            || removal.authority_sha256 != intent.authority_sha256
            || removal.root_ordinal != intent.root_ordinal
            || removal.attempt != intent.attempt
            || removal.create_intent_sha256 != intent_sha256
            || removal.created_sha256
                != created
                    .as_ref()
                    .map(|(_, created_sha256)| created_sha256.clone())
            || created.as_ref().is_some_and(|(created, _)| {
                removal
                    .directory
                    .is_some_and(|directory| directory != created.directory)
            }))
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }
    if let Some((done, _)) = &removal_done {
        let Some((removal, removal_sha256)) = &removal_intent else {
            return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
        };
        if done.schema_version != QUARANTINE_MATERIALIZATION_PROGRESS_SCHEMA_VERSION
            || done.authority_sha256 != intent.authority_sha256
            || done.root_ordinal != intent.root_ordinal
            || done.attempt != intent.attempt
            || done.removal_intent_sha256 != *removal_sha256
            || done.directory != removal.directory
            || match done.disposition {
                QuarantineMaterializationRemovalDisposition::AlreadyAbsent => {
                    done.durability != QuarantineDirectoryMutationDurability::NotRequired
                }
                QuarantineMaterializationRemovalDisposition::RemovalComplete => {
                    done.directory.is_none()
                        || done.durability == QuarantineDirectoryMutationDurability::NotRequired
                }
            }
        {
            return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
        }
    }
    Ok(Some(LoadedQuarantineMaterializationAttempt {
        intent_sha256,
        created,
        committed,
        removal_intent,
        removal_done,
    }))
}

fn persist_materialization_created(
    paths: &QuarantineMaterializationAttemptPaths,
    expected_intent: &QuarantineMaterializationCreateIntent,
    intent_sha256: &str,
    directory: QuarantineDirectoryIdentity,
    disposition: QuarantineMaterializationCreateDisposition,
) -> Result<(QuarantineMaterializationCreated, String), LegacyUploadMigrationApplyError> {
    let created = QuarantineMaterializationCreated {
        schema_version: QUARANTINE_MATERIALIZATION_PROGRESS_SCHEMA_VERSION,
        authority_sha256: expected_intent.authority_sha256.clone(),
        root_ordinal: expected_intent.root_ordinal,
        attempt: expected_intent.attempt,
        create_intent_sha256: intent_sha256.to_string(),
        directory,
        disposition,
    };
    let sha256 = ensure_materialization_progress(&paths.created, &created)?;
    Ok((created, sha256))
}

fn persist_materialization_commit(
    paths: &QuarantineMaterializationAttemptPaths,
    expected_intent: &QuarantineMaterializationCreateIntent,
    created: &QuarantineMaterializationCreated,
    created_sha256: &str,
    durability: QuarantineDirectoryMutationDurability,
) -> Result<(), LegacyUploadMigrationApplyError> {
    let committed = QuarantineMaterializationCommitted {
        schema_version: QUARANTINE_MATERIALIZATION_PROGRESS_SCHEMA_VERSION,
        authority_sha256: expected_intent.authority_sha256.clone(),
        root_ordinal: expected_intent.root_ordinal,
        attempt: expected_intent.attempt,
        created_sha256: created_sha256.to_string(),
        directory: created.directory,
        durability,
    };
    ensure_materialization_progress(&paths.committed, &committed)?;
    Ok(())
}

fn persist_materialization_removal_done(
    paths: &QuarantineMaterializationAttemptPaths,
    intent: &QuarantineMaterializationCreateIntent,
    removal: &QuarantineMaterializationRemovalIntent,
    removal_sha256: &str,
    disposition: QuarantineMaterializationRemovalDisposition,
    durability: QuarantineDirectoryMutationDurability,
) -> Result<String, LegacyUploadMigrationApplyError> {
    let done = QuarantineMaterializationRemovalDone {
        schema_version: QUARANTINE_MATERIALIZATION_PROGRESS_SCHEMA_VERSION,
        authority_sha256: intent.authority_sha256.clone(),
        root_ordinal: intent.root_ordinal,
        attempt: intent.attempt,
        removal_intent_sha256: removal_sha256.to_string(),
        directory: removal.directory,
        disposition,
        durability,
    };
    ensure_materialization_progress(&paths.removal_done, &done)
}

fn rollback_materialization_attempt(
    evidence: &ValidatedLegacyUploadEvidence,
    root: &File,
    cohort_name: &CStr,
    paths: &QuarantineMaterializationAttemptPaths,
    intent: &QuarantineMaterializationCreateIntent,
    loaded: &LoadedQuarantineMaterializationAttempt,
) -> Result<String, LegacyUploadMigrationApplyError> {
    revalidate_quarantine_materialization_authority(evidence, &intent.authority_sha256)?;
    if let Some((_done, done_sha256)) = &loaded.removal_done {
        if current_exact_empty_materialized_directory(root, cohort_name)?.is_some() {
            return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
        }
        return Ok(done_sha256.clone());
    }
    let current = current_exact_empty_materialized_directory(root, cohort_name)?;
    let observed_identity = current.as_ref().map(|(_, identity)| *identity);
    if let Some((created, _)) = &loaded.created
        && observed_identity.is_some_and(|identity| identity != created.directory)
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }
    let (removal, removal_sha256) = if let Some((removal, removal_sha256)) = &loaded.removal_intent
    {
        if loaded.created.as_ref().is_some_and(|(created, _)| {
            removal
                .directory
                .is_some_and(|directory| directory != created.directory)
        }) {
            return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
        }
        if observed_identity.is_some_and(|identity| removal.directory != Some(identity)) {
            return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
        }
        (removal.clone(), removal_sha256.clone())
    } else {
        revalidate_quarantine_materialization_authority(evidence, &intent.authority_sha256)?;
        let removal = QuarantineMaterializationRemovalIntent {
            schema_version: QUARANTINE_MATERIALIZATION_PROGRESS_SCHEMA_VERSION,
            authority_sha256: intent.authority_sha256.clone(),
            root_ordinal: intent.root_ordinal,
            attempt: intent.attempt,
            create_intent_sha256: loaded.intent_sha256.clone(),
            created_sha256: loaded
                .created
                .as_ref()
                .map(|(_, created_sha256)| created_sha256.clone()),
            directory: observed_identity,
        };
        let sha256 = ensure_materialization_progress(&paths.removal_intent, &removal)?;
        (removal, sha256)
    };
    let Some((held, identity)) = current else {
        return persist_materialization_removal_done(
            paths,
            intent,
            &removal,
            &removal_sha256,
            QuarantineMaterializationRemovalDisposition::AlreadyAbsent,
            QuarantineDirectoryMutationDurability::NotRequired,
        );
    };
    if removal.directory != Some(identity) {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }
    revalidate_materialized_directory(root, cohort_name, &held, identity)?;
    revalidate_quarantine_materialization_authority(evidence, &intent.authority_sha256)?;
    if !fail_quarantine_directory_removal_at(QuarantineDirectoryRemovalCrashPoint::BeforeUnlink)
        && unsafe { libc::unlinkat(root.as_raw_fd(), cohort_name.as_ptr(), libc::AT_REMOVEDIR) }
            == 0
    {
        let _ =
            fail_quarantine_directory_removal_at(QuarantineDirectoryRemovalCrashPoint::AfterUnlink);
    }
    match current_exact_empty_materialized_directory(root, cohort_name) {
        Ok(None) => {
            let (durability, sync_failed) = match directory_mutation_durability(root) {
                Ok(durability) => (durability, false),
                Err(_) => (
                    QuarantineDirectoryMutationDurability::RevalidatedAfterFailedDirectorySync,
                    true,
                ),
            };
            if current_exact_empty_materialized_directory(root, cohort_name)?.is_some() {
                return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
            }
            revalidate_quarantine_materialization_authority(evidence, &intent.authority_sha256)?;
            let done_sha256 = persist_materialization_removal_done(
                paths,
                intent,
                &removal,
                &removal_sha256,
                QuarantineMaterializationRemovalDisposition::RemovalComplete,
                durability,
            )?;
            if sync_failed {
                Err(LegacyUploadMigrationApplyError::QuarantineRollbackIncomplete)
            } else {
                Ok(done_sha256)
            }
        }
        Ok(Some((current, current_identity))) => {
            if current_identity != identity || !quarantine_directory_is_empty(&current)? {
                Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)
            } else {
                Err(LegacyUploadMigrationApplyError::QuarantineRollbackIncomplete)
            }
        }
        Err(_) => Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous),
    }
}

fn materialize_quarantine_root_with_progress(
    evidence: &ValidatedLegacyUploadEvidence,
    authority_sha256: &str,
    root_ordinal: usize,
    root: &File,
    cohort_name: &CStr,
) -> Result<File, LegacyUploadMigrationApplyError> {
    let mut previous_done_sha256 = QUARANTINE_MATERIALIZATION_GENESIS_SHA256.to_string();
    for attempt in 0..MAX_QUARANTINE_MATERIALIZATION_ATTEMPTS {
        revalidate_quarantine_materialization_authority(evidence, authority_sha256)?;
        let paths = materialization_attempt_paths(evidence, root_ordinal, attempt)?;
        let expected_intent = materialization_create_intent(
            evidence,
            authority_sha256,
            root_ordinal,
            attempt,
            &previous_done_sha256,
        )?;
        let loaded = load_materialization_attempt(&paths, &expected_intent)?;
        if let Some(loaded) = loaded {
            if let Some((_, done_sha256)) = &loaded.removal_done {
                previous_done_sha256 = done_sha256.clone();
                continue;
            }
            if loaded.removal_intent.is_some() {
                match rollback_materialization_attempt(
                    evidence,
                    root,
                    cohort_name,
                    &paths,
                    &expected_intent,
                    &loaded,
                ) {
                    Ok(done_sha256) => {
                        previous_done_sha256 = done_sha256;
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }
            if let Some((created, created_sha256)) = &loaded.created {
                let Some((cohort, current_identity)) =
                    current_exact_empty_materialized_directory(root, cohort_name)?
                else {
                    let done_sha256 = rollback_materialization_attempt(
                        evidence,
                        root,
                        cohort_name,
                        &paths,
                        &expected_intent,
                        &loaded,
                    )?;
                    previous_done_sha256 = done_sha256;
                    continue;
                };
                if current_identity != created.directory {
                    return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
                }
                if loaded.committed.is_none() {
                    revalidate_quarantine_materialization_authority(evidence, authority_sha256)?;
                    let durability = match directory_mutation_durability(root) {
                        Ok(durability) => durability,
                        Err(error) => {
                            rollback_materialization_attempt(
                                evidence,
                                root,
                                cohort_name,
                                &paths,
                                &expected_intent,
                                &loaded,
                            )?;
                            return Err(error);
                        }
                    };
                    revalidate_materialized_directory(
                        root,
                        cohort_name,
                        &cohort,
                        current_identity,
                    )?;
                    persist_materialization_commit(
                        &paths,
                        &expected_intent,
                        created,
                        created_sha256,
                        durability,
                    )?;
                }
                revalidate_materialized_directory(root, cohort_name, &cohort, current_identity)?;
                return Ok(cohort);
            }
            let Some((cohort, identity)) =
                current_exact_empty_materialized_directory(root, cohort_name)?
            else {
                run_quarantine_directory_pre_create_hook(root_ordinal);
                if fail_quarantine_directory_create_root(root_ordinal) {
                    return Err(LegacyUploadMigrationApplyError::Quarantine);
                }
                revalidate_quarantine_materialization_authority(evidence, authority_sha256)?;
                if unsafe { libc::mkdirat(root.as_raw_fd(), cohort_name.as_ptr(), 0o700) } != 0 {
                    return match current_exact_empty_materialized_directory(root, cohort_name) {
                        Ok(None) => Err(LegacyUploadMigrationApplyError::Quarantine),
                        Ok(Some(_)) | Err(_) => {
                            Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)
                        }
                    };
                }
                let cohort = open_quarantine_directory_at(root.as_raw_fd(), cohort_name)
                    .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?;
                let identity = quarantine_directory_identity(&cohort)
                    .map_err(|_| LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?;
                revalidate_quarantine_materialization_authority(evidence, authority_sha256)?;
                if crash_quarantine_directory_after_mkdir_before_result() {
                    return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
                }
                let (created, created_sha256) = persist_materialization_created(
                    &paths,
                    &expected_intent,
                    &loaded.intent_sha256,
                    identity,
                    QuarantineMaterializationCreateDisposition::Created,
                )?;
                run_quarantine_directory_post_open_hook();
                if fail_quarantine_directory_create_after_mkdir() {
                    let reloaded = load_materialization_attempt(&paths, &expected_intent)?
                        .ok_or(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?;
                    rollback_materialization_attempt(
                        evidence,
                        root,
                        cohort_name,
                        &paths,
                        &expected_intent,
                        &reloaded,
                    )?;
                    return Err(LegacyUploadMigrationApplyError::Quarantine);
                }
                revalidate_materialized_directory(root, cohort_name, &cohort, identity)?;
                let durability = match directory_mutation_durability(root) {
                    Ok(durability) => durability,
                    Err(error) => {
                        let reloaded = load_materialization_attempt(&paths, &expected_intent)?
                            .ok_or(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)?;
                        rollback_materialization_attempt(
                            evidence,
                            root,
                            cohort_name,
                            &paths,
                            &expected_intent,
                            &reloaded,
                        )?;
                        return Err(error);
                    }
                };
                revalidate_materialized_directory(root, cohort_name, &cohort, identity)?;
                persist_materialization_commit(
                    &paths,
                    &expected_intent,
                    &created,
                    &created_sha256,
                    durability,
                )?;
                return Ok(cohort);
            };
            revalidate_materialized_directory(root, cohort_name, &cohort, identity)?;
            let (created, created_sha256) = persist_materialization_created(
                &paths,
                &expected_intent,
                &loaded.intent_sha256,
                identity,
                QuarantineMaterializationCreateDisposition::AlreadyExactOwned,
            )?;
            let durability = directory_mutation_durability(root)?;
            revalidate_materialized_directory(root, cohort_name, &cohort, identity)?;
            persist_materialization_commit(
                &paths,
                &expected_intent,
                &created,
                &created_sha256,
                durability,
            )?;
            return Ok(cohort);
        }

        if current_exact_empty_materialized_directory(root, cohort_name)?.is_some() {
            return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
        }
        for path in [
            &paths.created,
            &paths.committed,
            &paths.removal_intent,
            &paths.removal_done,
        ] {
            if materialization_progress_artifact_exists(path)? {
                return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
            }
        }
        ensure_materialization_progress(&paths.create_intent, &expected_intent)?;
        return materialize_quarantine_root_with_progress(
            evidence,
            authority_sha256,
            root_ordinal,
            root,
            cohort_name,
        );
    }
    Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)
}

fn rollback_materialized_quarantine_roots(
    evidence: &ValidatedLegacyUploadEvidence,
    authority_sha256: &str,
    roots: &mut [(File, Option<File>)],
    cohort_name: &CStr,
    end_exclusive: usize,
) -> Result<(), LegacyUploadMigrationApplyError> {
    if end_exclusive > roots.len() {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }
    for root_ordinal in (0..end_exclusive).rev() {
        let root = &roots[root_ordinal].0;
        let mut previous_done_sha256 = QUARANTINE_MATERIALIZATION_GENESIS_SHA256.to_string();
        for attempt in 0..MAX_QUARANTINE_MATERIALIZATION_ATTEMPTS {
            let paths = materialization_attempt_paths(evidence, root_ordinal, attempt)?;
            let expected_intent = materialization_create_intent(
                evidence,
                authority_sha256,
                root_ordinal,
                attempt,
                &previous_done_sha256,
            )?;
            let Some(loaded) = load_materialization_attempt(&paths, &expected_intent)? else {
                break;
            };
            if let Some((_, done_sha256)) = &loaded.removal_done {
                previous_done_sha256 = done_sha256.clone();
                continue;
            }
            rollback_materialization_attempt(
                evidence,
                root,
                cohort_name,
                &paths,
                &expected_intent,
                &loaded,
            )?;
            break;
        }
        roots[root_ordinal].1 = None;
    }
    Ok(())
}

fn materialize_prepared_quarantine_roots(
    evidence: &ValidatedLegacyUploadEvidence,
    roots: &mut [(File, Option<File>)],
    cohort_name: &CStr,
) -> Result<String, LegacyUploadMigrationApplyError> {
    let (authority_sha256, authority_path) = quarantine_materialization_authority(evidence, roots)?;
    let authority: Option<(QuarantineMaterializationAuthority, String)> =
        read_materialization_progress(&authority_path)?;
    if authority
        .as_ref()
        .is_none_or(|(_, sha256)| sha256 != &authority_sha256)
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }
    for root_ordinal in 0..roots.len() {
        match materialize_quarantine_root_with_progress(
            evidence,
            &authority_sha256,
            root_ordinal,
            &roots[root_ordinal].0,
            cohort_name,
        ) {
            Ok(cohort) => roots[root_ordinal].1 = Some(cohort),
            Err(error) => {
                if matches!(
                    error,
                    LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous
                        | LegacyUploadMigrationApplyError::QuarantineRollbackIncomplete
                ) {
                    rollback_materialized_quarantine_roots(
                        evidence,
                        &authority_sha256,
                        roots,
                        cohort_name,
                        root_ordinal,
                    )?;
                    return Err(error);
                }
                rollback_materialized_quarantine_roots(
                    evidence,
                    &authority_sha256,
                    roots,
                    cohort_name,
                    roots.len(),
                )?;
                return Err(error);
            }
        }
    }
    Ok(authority_sha256)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReferenceNormalizationTempState {
    Created,
    Copied,
    Normalized,
}

struct AnchoredReferenceNormalizationTemp {
    file: AnchoredQuarantineFile,
    state: ReferenceNormalizationTempState,
}

#[derive(Serialize)]
struct QuarantineTargetReceipt {
    asset_id_sha256: String,
    kind: QuarantineTargetKind,
    source_path_sha256: String,
    destination_path_sha256: String,
    before: QuarantineFileIdentity,
    quarantined_original: QuarantineFileIdentity,
    normalized_reference: Option<QuarantineFileIdentity>,
    normalized_orientation: Option<u16>,
    decoded_pixel_sha256: Option<String>,
}

#[derive(Serialize)]
struct ReferenceNormalizationTempNameInput<'a> {
    schema_version: u64,
    cohort_sha256: &'a str,
    asset_id: &'a str,
    source_path: &'a Path,
}

impl LegacyArtifactQuarantineAdapter for ProductionLegacyArtifactQuarantineAdapter<'_> {
    type Error = LegacyUploadMigrationApplyError;

    fn quarantine_and_normalize(
        &mut self,
        evidence: &ValidatedLegacyUploadEvidence,
        manifest: &Manifest,
    ) -> Result<QuarantineBatchReceipt, Self::Error> {
        quarantine_legacy_artifacts(
            &self.quarantine_roots,
            self.image_timeout_seconds,
            evidence,
            manifest,
            &mut self.smb_capabilities,
        )
    }
}

pub(super) trait LegacyConversionAdapter {
    type Error;

    fn into_apply_error(error: Self::Error) -> LegacyUploadMigrationApplyError {
        let _ = error;
        LegacyUploadMigrationApplyError::State
    }

    fn convert_and_verify(
        &mut self,
        expected: [&AssetRecord; 2],
        output_paths: [&Path; 2],
    ) -> Result<[AssetRecord; 2], Self::Error>;
}

fn classify_conversion_execution_error(
    error: &ConversionExecutionError,
) -> LegacyConversionFailureCategory {
    if let Some(kind) = error.failure_kind() {
        return match kind {
            FailureKind::ConversionTimedOut => {
                LegacyConversionFailureCategory::ExecuteConversionTimedOut
            }
            FailureKind::RawStagingTimedOut => {
                LegacyConversionFailureCategory::ExecuteRawStagingTimedOut
            }
            FailureKind::ConversionOutputUnreadable => {
                LegacyConversionFailureCategory::ExecuteOutputUnreadable
            }
            FailureKind::ConversionOutputAlreadyExists => {
                LegacyConversionFailureCategory::ExecuteOutputAlreadyExists
            }
            FailureKind::StagedRawAlreadyExists => {
                LegacyConversionFailureCategory::ExecuteStagedRawAlreadyExists
            }
            FailureKind::ConversionMetadataFailed => {
                LegacyConversionFailureCategory::ExecuteMetadataFailed
            }
            FailureKind::ConversionToolUnavailable => {
                LegacyConversionFailureCategory::ExecuteToolUnavailable
            }
            FailureKind::EmbeddedPreviewUnavailable => {
                LegacyConversionFailureCategory::ExecuteEmbeddedPreviewUnavailable
            }
            _ => LegacyConversionFailureCategory::ExecuteOther,
        };
    }

    match error {
        ConversionExecutionError::CommandFailed {
            stage: "raw_staging",
            ..
        }
        | ConversionExecutionError::StagedRawAlreadyExists { .. }
        | ConversionExecutionError::StagedRawReadFailed { .. }
        | ConversionExecutionError::StagedRawWriteFailed { .. }
        | ConversionExecutionError::StagedRawNotRegular { .. }
        | ConversionExecutionError::StagedRawSizeMismatch { .. }
        | ConversionExecutionError::StagedRawSha256Mismatch { .. }
        | ConversionExecutionError::StagingNasProofMissing { .. }
        | ConversionExecutionError::StagingNasProofMalformed { .. }
        | ConversionExecutionError::StagingNasProofInvalid { .. }
        | ConversionExecutionError::StagingNasProofPathMismatch { .. } => {
            LegacyConversionFailureCategory::ExecuteRawStaging
        }
        ConversionExecutionError::OutputChanged { .. }
        | ConversionExecutionError::OutputEmpty { .. } => {
            LegacyConversionFailureCategory::ExecuteOutput
        }
        ConversionExecutionError::CommandFailed {
            stage: "metadata", ..
        }
        | ConversionExecutionError::CommandTimedOut {
            stage: "metadata", ..
        } => LegacyConversionFailureCategory::ExecuteMetadataFailed,
        ConversionExecutionError::CommandFailed { .. }
        | ConversionExecutionError::CommandTimedOut { .. } => {
            LegacyConversionFailureCategory::ExecuteCommand
        }
        ConversionExecutionError::BatchConversionFailed { .. }
        | ConversionExecutionError::BatchWorkerPanicked { .. }
        | ConversionExecutionError::InvalidBatchJobs { .. }
        | ConversionExecutionError::EmptyBatch
        | ConversionExecutionError::DuplicateBatchAsset { .. }
        | ConversionExecutionError::DuplicateBatchOutput { .. } => {
            LegacyConversionFailureCategory::ExecuteBatch
        }
        ConversionExecutionError::Plan(_)
        | ConversionExecutionError::AdjustedSourceCommandPlan
        | ConversionExecutionError::AdjustedSourceDescriptorUnavailable => {
            LegacyConversionFailureCategory::ExecutePlanning
        }
        ConversionExecutionError::UnsupportedBackend { .. } => {
            LegacyConversionFailureCategory::ExecuteUnsupportedBackend
        }
        ConversionExecutionError::Workflow(_)
        | ConversionExecutionError::Manifest(_)
        | ConversionExecutionError::Io(_) => LegacyConversionFailureCategory::ExecuteWorkflow,
        ConversionExecutionError::PreviewProbeDecode { .. }
        | ConversionExecutionError::InvalidPreviewProbeResponse => {
            LegacyConversionFailureCategory::ExecuteCommand
        }
        ConversionExecutionError::OutputUnreadable { .. }
        | ConversionExecutionError::OutputAlreadyExists { .. }
        | ConversionExecutionError::ToolNotFound { .. }
        | ConversionExecutionError::EmbeddedPreviewUnavailable { .. } => {
            LegacyConversionFailureCategory::ExecuteOther
        }
    }
}

fn classify_conversion_verification_error(error: &MonitorError) -> LegacyConversionFailureCategory {
    match error {
        MonitorError::HeicMetadataVerification {
            kind: HeicMetadataFailure::ReferenceOrientationInvalid,
            ..
        } => LegacyConversionFailureCategory::VerifyReferenceOrientation,
        MonitorError::HeicMetadataVerification {
            kind: HeicMetadataFailure::FinalOrientationRotationInvalid,
            ..
        } => LegacyConversionFailureCategory::VerifyFinalOrientation,
        MonitorError::HeicMetadataVerification {
            kind: HeicMetadataFailure::DimensionMismatch,
            ..
        } => LegacyConversionFailureCategory::VerifyDimension,
        MonitorError::Workflow(WorkflowError::HeicVerificationFailed {
            field: "visual_content_ok",
        }) => LegacyConversionFailureCategory::VerifyVisualContent,
        MonitorError::Workflow(WorkflowError::HeicVerificationFailed {
            field: "visual_match_ok",
        }) => LegacyConversionFailureCategory::VerifyVisualMatch,
        MonitorError::CommandIo { .. }
        | MonitorError::CommandFailed { .. }
        | MonitorError::CommandTimeout { .. }
        | MonitorError::Conversion(_) => LegacyConversionFailureCategory::VerifyCommand,
        MonitorError::PreviewDecode { .. } | MonitorError::PreviewDimensionMismatch { .. } => {
            LegacyConversionFailureCategory::VerifyOutput
        }
        MonitorError::VisualVerificationWorkspace
        | MonitorError::VisualVerificationAndCleanupFailed => {
            LegacyConversionFailureCategory::VerifyWorkspace
        }
        MonitorError::Workflow(_) | MonitorError::Manifest(_) | MonitorError::StateStore(_) => {
            LegacyConversionFailureCategory::VerifyWorkflow
        }
        _ => LegacyConversionFailureCategory::VerifyOther,
    }
}

fn classify_conversion_recording_error(error: &WorkflowError) -> LegacyConversionFailureCategory {
    match error {
        WorkflowError::Manifest(_) => LegacyConversionFailureCategory::RecordManifest,
        WorkflowError::Proof(_) | WorkflowError::Json(_) => {
            LegacyConversionFailureCategory::RecordProof
        }
        WorkflowError::HeicVerificationFailed { .. } => {
            LegacyConversionFailureCategory::RecordWorkflow
        }
        _ => LegacyConversionFailureCategory::RecordOther,
    }
}

pub(super) struct ProductionLegacyConversionAdapter {
    jobs: usize,
    heic_quality: u8,
    conversion_tool_version: Option<String>,
    verify_timeout_seconds: u64,
}

impl ProductionLegacyConversionAdapter {
    pub(super) fn new(
        jobs: usize,
        heic_quality: u8,
        conversion_tool_version: Option<String>,
        verify_timeout_seconds: u64,
    ) -> Self {
        Self {
            jobs,
            heic_quality,
            conversion_tool_version,
            verify_timeout_seconds,
        }
    }
}

impl LegacyConversionAdapter for ProductionLegacyConversionAdapter {
    type Error = LegacyUploadMigrationApplyError;

    fn into_apply_error(error: Self::Error) -> LegacyUploadMigrationApplyError {
        error
    }

    fn convert_and_verify(
        &mut self,
        expected: [&AssetRecord; 2],
        output_paths: [&Path; 2],
    ) -> Result<[AssetRecord; 2], Self::Error> {
        let mut operational = Manifest::new();
        for record in expected {
            let mut unsealed = record.clone();
            unsealed
                .proofs
                .remove(super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME);
            operational.upsert_trusted(unsealed);
        }
        let requests = std::array::from_fn::<_, 2, _>(|index| ConversionExecutionRequest {
            asset_id: expected[index].asset_id.clone(),
            output_path: output_paths[index].to_path_buf(),
            heic_quality: self.heic_quality,
            conversion_tool_version: self.conversion_tool_version.clone(),
        });
        let mut converted =
            execute_measured_conversions(&operational, requests.into_iter().collect(), self.jobs)
                .map_err(|error| LegacyUploadMigrationApplyError::Conversion {
                category: classify_conversion_execution_error(&error),
            })?;
        for record in &expected {
            let verified = crate::monitor::verify_converted_heic(
                &converted,
                &record.asset_id,
                self.verify_timeout_seconds,
            )
            .map_err(|error| LegacyUploadMigrationApplyError::Conversion {
                category: classify_conversion_verification_error(&error),
            })?;
            record_current_heic_verification(&mut converted, &record.asset_id, verified.proof)
                .map_err(|error| LegacyUploadMigrationApplyError::Conversion {
                    category: classify_conversion_recording_error(&error),
                })?;
        }
        let mut candidates = [
            converted
                .get(&expected[0].asset_id)
                .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
                .clone(),
            converted
                .get(&expected[1].asset_id)
                .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
                .clone(),
        ];
        for index in 0..2 {
            candidates[index].updated_at = expected[index].updated_at.clone();
            candidates[index].proofs.insert(
                super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME.to_string(),
                expected[index].proofs[super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME].clone(),
            );
        }
        Ok(candidates)
    }
}

const fn state_stage(stage: LegacyUploadMigrationStateStage) -> LegacyUploadMigrationApplyError {
    LegacyUploadMigrationApplyError::StateStage { stage }
}

const fn remote_stage(stage: LegacyUploadMigrationRemoteStage) -> LegacyUploadMigrationApplyError {
    LegacyUploadMigrationApplyError::RemoteStage { stage }
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct VerifiedRemoteUploadReceipt {
    pub(super) asset_id: String,
    pub(super) uploaded_asset_id: String,
    pub(super) master_record_name: String,
    pub(super) uploaded_asset_id_sha256: String,
    pub(super) master_record_name_sha256: String,
    pub(super) record_change_tag_sha256: String,
    pub(super) heic_sha256: String,
    pub(super) size_bytes: u64,
    pub(super) destination_sha256: String,
    pub(super) inventory_sha256: String,
    pub(super) inventory_records_scanned: u64,
}

pub(super) struct VerifiedLegacyUpload {
    pub(super) candidate: AssetRecord,
    pub(super) receipt: VerifiedRemoteUploadReceipt,
}

pub(super) trait LegacyUploadAdapter {
    type Error;

    fn into_apply_error(error: Self::Error) -> LegacyUploadMigrationApplyError {
        let _ = error;
        LegacyUploadMigrationApplyError::Remote
    }

    fn upload_or_reconcile(
        &mut self,
        expected: [&AssetRecord; 2],
        replacements: &[EvidenceRetiredReplacement],
        sources: [&VerifiedUploadSource; 2],
    ) -> Result<[VerifiedLegacyUpload; 2], Self::Error>;

    fn verify_existing(
        &mut self,
        records: [&AssetRecord; 2],
        replacements: &[EvidenceRetiredReplacement],
    ) -> Result<[VerifiedRemoteUploadReceipt; 2], Self::Error>;
}

pub(super) trait LegacyMirrorAdapter {
    type Error;

    fn mirror_or_reconcile(
        &mut self,
        expected: [&AssetRecord; 2],
        mirror_paths: [&Path; 2],
    ) -> Result<[AssetRecord; 2], Self::Error>;
}

pub(super) struct ProductionLegacyMirrorAdapter;

impl LegacyMirrorAdapter for ProductionLegacyMirrorAdapter {
    type Error = LegacyUploadMigrationApplyError;

    fn mirror_or_reconcile(
        &mut self,
        expected: [&AssetRecord; 2],
        mirror_paths: [&Path; 2],
    ) -> Result<[AssetRecord; 2], Self::Error> {
        let mut candidates = Vec::with_capacity(2);
        for index in 0..2 {
            let mut manifest = Manifest::new();
            let mut operational = expected[index].clone();
            operational
                .proofs
                .remove(super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME);
            manifest.upsert_trusted(operational);
            let (upload, heic) =
                icloudpd_local_mirror_ready_proofs(&manifest, &expected[index].asset_id)
                    .map_err(|_| LegacyUploadMigrationApplyError::State)?;
            let uploaded_heic_path = upload
                .uploaded_heic_path
                .clone()
                .ok_or(LegacyUploadMigrationApplyError::State)?;
            let proof = ensure_icloudpd_local_mirror(IcloudpdLocalMirrorRequest {
                uploaded_heic_asset_id: upload.uploaded_heic_asset_id,
                uploaded_heic_sha256: upload.uploaded_heic_sha256,
                uploaded_heic_path,
                size_bytes: heic.size_bytes,
                icloudpd_download_path: mirror_paths[index].to_path_buf(),
            })
            .map_err(|_| LegacyUploadMigrationApplyError::State)?;
            record_icloudpd_local_mirror_proof(&mut manifest, &expected[index].asset_id, proof)
                .map_err(|_| LegacyUploadMigrationApplyError::State)?;
            let mut candidate = manifest
                .get(&expected[index].asset_id)
                .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
                .clone();
            candidate.updated_at = expected[index].updated_at.clone();
            candidate.proofs.insert(
                super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME.to_string(),
                expected[index].proofs[super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME].clone(),
            );
            candidates.push(candidate);
        }
        candidates
            .try_into()
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)
    }
}

pub(super) struct ProductionLegacyUploadAdapter {
    upload_session_path: PathBuf,
    delete_session: CloudKitDeleteSession,
    cloudkit: CloudKitDeleteClient<ReqwestCloudKitDeleteTransport>,
    capture_tolerance_seconds: u64,
    cloudkit_start_rank: u64,
    cloudkit_page_size: u64,
    cloudkit_max_pages: u64,
}

struct LegacyUploadInventoryPreflight {
    destinations: [CloudKitLibraryDestination; 2],
    replacement_proofs: [Option<CloudKitReplacementResourceProof>; 2],
    inventory: CloudKitOriginalAssetInventoryFingerprint,
}

struct LegacyUploadVerificationContext<'a> {
    heic: &'a HeicVerificationProof,
    destination: &'a CloudKitLibraryDestination,
    replacement_proof: &'a CloudKitReplacementResourceProof,
    inventory: &'a CloudKitOriginalAssetInventoryFingerprint,
}

/// Bind a legacy evidence destination to the authenticated CloudKit session.
///
/// Legacy private `PrimarySync` evidence predates owner-aware session parsing and may omit
/// `owner_record_name`.  In that one case the authenticated session owner is the effective
/// destination.  Every other destination component remains exact: explicit private owners and
/// all shared destinations must agree with the session, and shared destinations must stay
/// owner-bound.
fn effective_legacy_destination(
    evidence: &super::evidence::EvidenceDestination,
    authenticated_scope: CloudKitDatabaseScope,
    authenticated_destination: &CloudKitLibraryDestination,
) -> Option<CloudKitLibraryDestination> {
    if authenticated_scope != authenticated_destination.database_scope
        || evidence.database_scope != authenticated_scope
        || evidence.zone_name != authenticated_destination.zone_name
    {
        return None;
    }

    let owner_record_name = match evidence.database_scope {
        CloudKitDatabaseScope::Private => {
            if evidence.owner_record_name.is_none() && evidence.zone_name != "PrimarySync" {
                return None;
            }
            match (
                evidence.owner_record_name.as_deref(),
                authenticated_destination.owner_record_name.as_deref(),
            ) {
                (None, session_owner) => session_owner.map(ToOwned::to_owned),
                (Some(evidence_owner), Some(session_owner)) if evidence_owner == session_owner => {
                    Some(evidence_owner.to_string())
                }
                _ => return None,
            }
        }
        CloudKitDatabaseScope::Shared => match (
            evidence.owner_record_name.as_deref(),
            authenticated_destination.owner_record_name.as_deref(),
        ) {
            (Some(evidence_owner), Some(session_owner)) if evidence_owner == session_owner => {
                Some(evidence_owner.to_string())
            }
            _ => return None,
        },
    };

    Some(CloudKitLibraryDestination {
        database_scope: evidence.database_scope,
        zone_name: evidence.zone_name.clone(),
        owner_record_name,
    })
}

fn is_legacy_private_primary_sync_unbound(evidence: &super::evidence::EvidenceDestination) -> bool {
    evidence.database_scope == CloudKitDatabaseScope::Private
        && evidence.zone_name == "PrimarySync"
        && evidence.owner_record_name.is_none()
}

/// Keep the durable manifest proof in the sealed legacy shape after the remote result has been
/// checked against the authenticated effective destination.  The owner is only normalized for
/// private `PrimarySync` evidence that was explicitly unbound; explicit owners and shared zones
/// retain their exact bound identity.
fn durable_legacy_upload_proof(
    mut upload: UploadProof,
    evidence: &super::evidence::EvidenceDestination,
) -> UploadProof {
    if is_legacy_private_primary_sync_unbound(evidence) {
        upload.owner_record_name = None;
    }
    upload
}

fn photos_upload_transport_destination(
    effective: &CloudKitLibraryDestination,
    evidence: &super::evidence::EvidenceDestination,
) -> CloudKitLibraryDestination {
    if is_legacy_private_primary_sync_unbound(evidence) {
        CloudKitLibraryDestination {
            database_scope: effective.database_scope,
            zone_name: effective.zone_name.clone(),
            owner_record_name: None,
        }
    } else {
        effective.clone()
    }
}

fn bind_generated_upload_proof_destination(
    mut upload: UploadProof,
    effective: &CloudKitLibraryDestination,
    evidence: &super::evidence::EvidenceDestination,
) -> Option<UploadProof> {
    if upload.database_scope != effective.database_scope || upload.zone_name != effective.zone_name
    {
        return None;
    }
    if is_legacy_private_primary_sync_unbound(evidence) {
        if upload.owner_record_name.is_some() {
            return None;
        }
        upload.owner_record_name = effective.owner_record_name.clone();
    } else if upload.owner_record_name != effective.owner_record_name {
        return None;
    }
    Some(upload)
}

impl ProductionLegacyUploadAdapter {
    pub(super) fn new(
        upload_session_path: PathBuf,
        delete_session_path: &Path,
        capture_tolerance_seconds: u64,
        cloudkit_start_rank: u64,
        cloudkit_page_size: u64,
        cloudkit_max_pages: u64,
    ) -> Result<Self, LegacyUploadMigrationApplyError> {
        let delete_session = load_cloudkit_delete_session(delete_session_path)
            .map_err(|_| remote_stage(LegacyUploadMigrationRemoteStage::AdapterInit))?;
        let transport = ReqwestCloudKitDeleteTransport::new()
            .map_err(|_| remote_stage(LegacyUploadMigrationRemoteStage::AdapterInit))?;
        Ok(Self {
            upload_session_path,
            delete_session,
            cloudkit: CloudKitDeleteClient::new(transport),
            capture_tolerance_seconds,
            cloudkit_start_rank,
            cloudkit_page_size,
            cloudkit_max_pages,
        })
    }

    fn local_replacement_target(
        record: &AssetRecord,
        heic: &HeicVerificationProof,
        capture_tolerance_seconds: u64,
    ) -> Result<CloudKitOriginalAssetResolveTarget, LegacyUploadMigrationApplyError> {
        let nas: NasRawProof = serde_json::from_value(
            record
                .proofs
                .get("nas")
                .ok_or(remote_stage(
                    LegacyUploadMigrationRemoteStage::LocalReplacementTarget,
                ))?
                .clone(),
        )
        .map_err(|_| remote_stage(LegacyUploadMigrationRemoteStage::LocalReplacementTarget))?;
        let source_age: SourceAgeProof = serde_json::from_value(
            record
                .proofs
                .get("source_age")
                .ok_or(remote_stage(
                    LegacyUploadMigrationRemoteStage::LocalReplacementTarget,
                ))?
                .clone(),
        )
        .map_err(|_| remote_stage(LegacyUploadMigrationRemoteStage::LocalReplacementTarget))?;
        let original_filename = record
            .proofs
            .get("original_asset")
            .and_then(|proof| proof.get("filename"))
            .and_then(Value::as_str)
            .ok_or(remote_stage(
                LegacyUploadMigrationRemoteStage::LocalReplacementTarget,
            ))?
            .to_string();
        Ok(CloudKitOriginalAssetResolveTarget {
            asset_id: record.asset_id.clone(),
            raw_size_bytes: nas.size_bytes,
            source_captured_unix_seconds: source_age.source_captured_unix_seconds,
            capture_tolerance_seconds,
            filename: original_filename,
            matched_raw_sha256: nas.sha256,
            replacement_candidate: Some(CloudKitLocalReplacementCandidate {
                sha256: heic.heic_sha256.clone(),
                size_bytes: heic.size_bytes,
            }),
        })
    }

    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "unit fixtures exercise the target-aware variant directly"
        )
    )]
    fn validate_local_replacement_resolution(
        resolution: &CloudKitOriginalAssetResolution,
        destination: &CloudKitLibraryDestination,
        heic: &HeicVerificationProof,
    ) -> Result<Option<CloudKitReplacementResourceProof>, LegacyUploadMigrationApplyError> {
        let derived_target = match &resolution.disposition {
            CloudKitOriginalAssetResolveDisposition::Coexistence { original_proof, .. } => {
                Some(CloudKitOriginalAssetResolveTarget {
                    asset_id: String::new(),
                    raw_size_bytes: original_proof.size_bytes,
                    source_captured_unix_seconds: 1,
                    capture_tolerance_seconds: 0,
                    filename: original_proof.filename.clone(),
                    matched_raw_sha256: original_proof.matched_raw_sha256.clone(),
                    replacement_candidate: Some(CloudKitLocalReplacementCandidate {
                        sha256: heic.heic_sha256.clone(),
                        size_bytes: heic.size_bytes,
                    }),
                })
            }
            _ => None,
        };
        Self::validate_local_replacement_resolution_with_target(
            resolution,
            destination,
            derived_target.as_ref(),
            heic,
        )
    }

    fn validate_local_replacement_resolution_with_target(
        resolution: &CloudKitOriginalAssetResolution,
        destination: &CloudKitLibraryDestination,
        target: Option<&CloudKitOriginalAssetResolveTarget>,
        heic: &HeicVerificationProof,
    ) -> Result<Option<CloudKitReplacementResourceProof>, LegacyUploadMigrationApplyError> {
        let observations = &resolution.observations;
        match &resolution.disposition {
            CloudKitOriginalAssetResolveDisposition::ReplacementPresent { proof } => {
                require_unique_active_replacement(resolution).map_err(|_| {
                    remote_stage(
                        LegacyUploadMigrationRemoteStage::LocalReplacementDispositionReplacementUniquenessMismatch,
                    )
                })?;
                if observations.ambiguity_evidence != 0 || observations.raw_hash_matches != 0 {
                    return Err(remote_stage(
                        LegacyUploadMigrationRemoteStage::LocalReplacementDispositionObservationInconsistent,
                    ));
                }
                if proof.database_scope != destination.database_scope
                    || proof.zone_name != destination.zone_name
                    || proof.owner_record_name != destination.owner_record_name
                    || proof.matched_heic_sha256 != heic.heic_sha256
                    || proof.size_bytes != heic.size_bytes
                    || proof.record_type != "CPLAsset"
                    || proof.record_name.trim().is_empty()
                    || proof.record_change_tag.trim().is_empty()
                    || proof.resource_field.trim().is_empty()
                {
                    return Err(remote_stage(
                        LegacyUploadMigrationRemoteStage::LocalReplacementDispositionReplacementProofMismatch,
                    ));
                }
                Ok(Some(proof.clone()))
            }
            CloudKitOriginalAssetResolveDisposition::Coexistence {
                original_proof,
                replacement_proof,
            } => {
                if observations.date_candidates == 0
                    || observations.raw_resources == 0
                    || observations.raw_size_matches == 0
                    || observations.raw_hash_matches != 1
                    || observations.replacement_resource_matches != 1
                    || observations.download_size_mismatches != 0
                    || observations.ambiguity_evidence != 0
                {
                    return Err(remote_stage(
                        LegacyUploadMigrationRemoteStage::LocalReplacementDispositionObservationInconsistent,
                    ));
                }
                if original_proof.database_scope != destination.database_scope
                    || original_proof.zone_name != destination.zone_name
                    || original_proof.owner_record_name != destination.owner_record_name
                    || original_proof.record_type != "CPLAsset"
                    || original_proof.record_name.trim().is_empty()
                    || original_proof.record_change_tag.trim().is_empty()
                    || original_proof.filename.trim().is_empty()
                    || !valid_sha256(&original_proof.matched_raw_sha256)
                    || target.is_none_or(|target| {
                        original_proof.filename != target.filename
                            || original_proof.size_bytes != target.raw_size_bytes
                            || original_proof.matched_raw_sha256 != target.matched_raw_sha256
                    })
                {
                    return Err(remote_stage(
                        LegacyUploadMigrationRemoteStage::LocalReplacementDispositionReplacementProofMismatch,
                    ));
                }
                if replacement_proof.database_scope != destination.database_scope
                    || replacement_proof.zone_name != destination.zone_name
                    || replacement_proof.owner_record_name != destination.owner_record_name
                    || replacement_proof.matched_heic_sha256 != heic.heic_sha256
                    || replacement_proof.size_bytes != heic.size_bytes
                    || replacement_proof.record_type != "CPLAsset"
                    || replacement_proof.record_name.trim().is_empty()
                    || replacement_proof.record_change_tag.trim().is_empty()
                    || replacement_proof.resource_field.trim().is_empty()
                {
                    return Err(remote_stage(
                        LegacyUploadMigrationRemoteStage::LocalReplacementDispositionReplacementProofMismatch,
                    ));
                }
                Ok(Some(replacement_proof.clone()))
            }
            CloudKitOriginalAssetResolveDisposition::ExactOriginal { .. } => {
                if observations.date_candidates == 0
                    || observations.raw_resources == 0
                    || observations.raw_size_matches == 0
                    || observations.raw_hash_matches != 1
                    || observations.replacement_resource_matches != 0
                    || observations.download_size_mismatches != 0
                    || observations.ambiguity_evidence != 0
                {
                    return Err(remote_stage(
                        LegacyUploadMigrationRemoteStage::LocalReplacementDispositionObservationInconsistent,
                    ));
                }
                Ok(None)
            }
            CloudKitOriginalAssetResolveDisposition::NoDateCandidate => {
                if observations.date_candidates != 0
                    || observations.raw_resources != 0
                    || observations.raw_size_matches != 0
                    || observations.raw_hash_matches != 0
                    || observations.replacement_resource_matches != 0
                    || observations.download_size_mismatches != 0
                    || observations.ambiguity_evidence != 0
                {
                    return Err(remote_stage(
                        LegacyUploadMigrationRemoteStage::LocalReplacementDispositionObservationInconsistent,
                    ));
                }
                Ok(None)
            }
            CloudKitOriginalAssetResolveDisposition::IncompleteTransient => Err(remote_stage(
                LegacyUploadMigrationRemoteStage::LocalReplacementDispositionIncompleteTransient,
            )),
            CloudKitOriginalAssetResolveDisposition::Ambiguous => {
                if observations.ambiguity_evidence == 0 {
                    return Err(remote_stage(
                        LegacyUploadMigrationRemoteStage::LocalReplacementDispositionObservationInconsistent,
                    ));
                }
                Err(remote_stage(
                    LegacyUploadMigrationRemoteStage::LocalReplacementDispositionAmbiguous,
                ))
            }
            CloudKitOriginalAssetResolveDisposition::NoRawResource => {
                if observations.date_candidates == 0
                    || observations.raw_resources != 0
                    || observations.raw_size_matches != 0
                    || observations.raw_hash_matches != 0
                    || observations.replacement_resource_matches != 0
                    || observations.download_size_mismatches != 0
                    || observations.ambiguity_evidence != 0
                {
                    return Err(remote_stage(
                        LegacyUploadMigrationRemoteStage::LocalReplacementDispositionObservationInconsistent,
                    ));
                }
                Err(remote_stage(
                    LegacyUploadMigrationRemoteStage::LocalReplacementDispositionNoRawResource,
                ))
            }
            CloudKitOriginalAssetResolveDisposition::RawSizeMismatch => {
                if observations.date_candidates == 0
                    || observations.raw_resources == 0
                    || observations.raw_size_matches != 0
                    || observations.raw_hash_matches != 0
                    || observations.replacement_resource_matches != 0
                    || observations.download_size_mismatches != 0
                    || observations.ambiguity_evidence != 0
                {
                    return Err(remote_stage(
                        LegacyUploadMigrationRemoteStage::LocalReplacementDispositionObservationInconsistent,
                    ));
                }
                Err(remote_stage(
                    LegacyUploadMigrationRemoteStage::LocalReplacementDispositionRawSizeMismatch,
                ))
            }
            CloudKitOriginalAssetResolveDisposition::RawHashMismatch => {
                if observations.date_candidates == 0
                    || observations.raw_resources == 0
                    || observations.raw_size_matches == 0
                    || observations.raw_hash_matches != 0
                    || observations.replacement_resource_matches != 0
                    || observations.download_size_mismatches != 0
                    || observations.ambiguity_evidence != 0
                {
                    return Err(remote_stage(
                        LegacyUploadMigrationRemoteStage::LocalReplacementDispositionObservationInconsistent,
                    ));
                }
                Err(remote_stage(
                    LegacyUploadMigrationRemoteStage::LocalReplacementDispositionRawHashMismatch,
                ))
            }
        }
    }

    fn validate_local_replacement_inventory(
        inventory: CloudKitOriginalAssetInventoryFingerprint,
    ) -> Result<CloudKitOriginalAssetInventoryFingerprint, LegacyUploadMigrationApplyError> {
        if inventory.resolver_version != CLOUDKIT_ORIGINAL_ASSET_RESOLVER_VERSION
            || !valid_sha256(&inventory.sha256)
        {
            return Err(remote_stage(
                LegacyUploadMigrationRemoteStage::LocalReplacementInventory,
            ));
        }
        Ok(inventory)
    }

    fn preflight_local_replacements(
        &mut self,
        records: [&AssetRecord; 2],
        replacements: &[EvidenceRetiredReplacement],
        heics: [&HeicVerificationProof; 2],
    ) -> Result<LegacyUploadInventoryPreflight, LegacyUploadMigrationApplyError> {
        if replacements.len() != 2
            || records[0].asset_id == records[1].asset_id
            || records[0].asset_id != replacements[0].asset_id
            || records[1].asset_id != replacements[1].asset_id
            || replacements[0].asset_id == replacements[1].asset_id
        {
            return Err(remote_stage(
                LegacyUploadMigrationRemoteStage::LocalReplacementBinding,
            ));
        }

        let destinations = [
            effective_legacy_destination(
                &replacements[0].destination,
                self.delete_session.database_scope,
                &self.delete_session.zone,
            ),
            effective_legacy_destination(
                &replacements[1].destination,
                self.delete_session.database_scope,
                &self.delete_session.zone,
            ),
        ]
        .map(|destination| {
            destination.ok_or(remote_stage(
                LegacyUploadMigrationRemoteStage::LocalReplacementBinding,
            ))
        });
        let destinations = [destinations[0].clone()?, destinations[1].clone()?];
        if destinations[0] != destinations[1] {
            return Err(remote_stage(
                LegacyUploadMigrationRemoteStage::LocalReplacementBinding,
            ));
        }

        let targets = vec![
            Self::local_replacement_target(records[0], heics[0], self.capture_tolerance_seconds)?,
            Self::local_replacement_target(records[1], heics[1], self.capture_tolerance_seconds)?,
        ];
        let request = CloudKitOriginalAssetBatchResolveRequest {
            targets: targets.clone(),
            start_rank: self.cloudkit_start_rank,
            page_size: self.cloudkit_page_size,
            max_pages: self.cloudkit_max_pages,
        };
        let mut session = self.delete_session.clone();
        session.database_scope = destinations[0].database_scope;
        session.zone = destinations[0].clone();
        let outcome = self
            .cloudkit
            .resolve_original_assets_batch_outcome(&session, &request)
            .map_err(|_| {
                remote_stage(LegacyUploadMigrationRemoteStage::LocalReplacementBatchTransport)
            })?;
        if outcome.resolutions.len() != 2 {
            return Err(remote_stage(
                LegacyUploadMigrationRemoteStage::LocalReplacementResolutionKeys,
            ));
        }
        let inventory = Self::validate_local_replacement_inventory(outcome.inventory.ok_or(
            remote_stage(LegacyUploadMigrationRemoteStage::LocalReplacementInventory),
        )?)?;
        let replacement_proofs = [
            Self::validate_local_replacement_resolution_with_target(
                outcome
                    .resolutions
                    .get(&records[0].asset_id)
                    .ok_or(remote_stage(
                        LegacyUploadMigrationRemoteStage::LocalReplacementResolutionKeys,
                    ))?,
                &destinations[0],
                Some(&targets[0]),
                heics[0],
            )?,
            Self::validate_local_replacement_resolution_with_target(
                outcome
                    .resolutions
                    .get(&records[1].asset_id)
                    .ok_or(remote_stage(
                        LegacyUploadMigrationRemoteStage::LocalReplacementResolutionKeys,
                    ))?,
                &destinations[1],
                Some(&targets[1]),
                heics[1],
            )?,
        ];
        Ok(LegacyUploadInventoryPreflight {
            destinations,
            replacement_proofs,
            inventory,
        })
    }

    fn resolve_local_replacement(
        &mut self,
        record: &AssetRecord,
        replacement: &EvidenceRetiredReplacement,
        heic: &HeicVerificationProof,
    ) -> Result<
        (
            Option<CloudKitReplacementResourceProof>,
            CloudKitOriginalAssetInventoryFingerprint,
            bool,
        ),
        LegacyUploadMigrationApplyError,
    > {
        let destination = effective_legacy_destination(
            &replacement.destination,
            self.delete_session.database_scope,
            &self.delete_session.zone,
        )
        .ok_or(remote_stage(
            LegacyUploadMigrationRemoteStage::LocalReplacementBinding,
        ))?;
        let mut session = self.delete_session.clone();
        session.database_scope = destination.database_scope;
        session.zone = destination.clone();
        let target = Self::local_replacement_target(record, heic, self.capture_tolerance_seconds)?;
        let outcome = self
            .cloudkit
            .resolve_original_assets_batch_outcome(
                &session,
                &CloudKitOriginalAssetBatchResolveRequest {
                    targets: vec![target.clone()],
                    start_rank: self.cloudkit_start_rank,
                    page_size: self.cloudkit_page_size,
                    max_pages: self.cloudkit_max_pages,
                },
            )
            .map_err(|_| {
                remote_stage(LegacyUploadMigrationRemoteStage::LocalReplacementBatchTransport)
            })?;
        let inventory = Self::validate_local_replacement_inventory(outcome.inventory.ok_or(
            remote_stage(LegacyUploadMigrationRemoteStage::LocalReplacementInventory),
        )?)?;
        if outcome.resolutions.len() != 1 {
            return Err(remote_stage(
                LegacyUploadMigrationRemoteStage::LocalReplacementResolutionKeys,
            ));
        }
        let resolution = outcome
            .resolutions
            .get(&record.asset_id)
            .ok_or(remote_stage(
                LegacyUploadMigrationRemoteStage::LocalReplacementResolutionKeys,
            ))?;
        let no_date_candidate = matches!(
            &resolution.disposition,
            CloudKitOriginalAssetResolveDisposition::NoDateCandidate
        );
        let proof = Self::validate_local_replacement_resolution_with_target(
            resolution,
            &destination,
            Some(&target),
            heic,
        )?;
        Ok((proof, inventory, no_date_candidate))
    }

    fn candidate_with_upload_proof(
        expected: &AssetRecord,
        upload: UploadProof,
    ) -> Result<AssetRecord, LegacyUploadMigrationApplyError> {
        let mut operational = Manifest::new();
        let mut candidate = expected.clone();
        candidate
            .proofs
            .remove(super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME);
        operational.upsert_trusted(candidate);
        record_upload_proof(&mut operational, &expected.asset_id, upload)
            .map_err(|_| remote_stage(LegacyUploadMigrationRemoteStage::UploadProofBinding))?;
        let mut candidate = operational
            .get(&expected.asset_id)
            .map_err(|_| remote_stage(LegacyUploadMigrationRemoteStage::UploadProofBinding))?
            .clone();
        candidate.updated_at = expected.updated_at.clone();
        candidate.proofs.insert(
            super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME.to_string(),
            expected.proofs[super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME].clone(),
        );
        Ok(candidate)
    }

    fn verify_upload(
        &mut self,
        record: &AssetRecord,
        replacement: &EvidenceRetiredReplacement,
        expected_asset_id: Option<&str>,
        expected_master_id: Option<&str>,
    ) -> Result<VerifiedRemoteUploadReceipt, LegacyUploadMigrationApplyError> {
        let proof: UploadProof = serde_json::from_value(
            record
                .proofs
                .get(UPLOAD_PROOF)
                .ok_or(remote_stage(
                    LegacyUploadMigrationRemoteStage::UploadProofBinding,
                ))?
                .clone(),
        )
        .map_err(|_| remote_stage(LegacyUploadMigrationRemoteStage::UploadProofBinding))?;
        self.verify_upload_with_proof(
            record,
            replacement,
            &proof,
            expected_asset_id,
            expected_master_id,
        )
    }

    fn verify_upload_with_proof(
        &mut self,
        record: &AssetRecord,
        replacement: &EvidenceRetiredReplacement,
        proof: &UploadProof,
        expected_asset_id: Option<&str>,
        expected_master_id: Option<&str>,
    ) -> Result<VerifiedRemoteUploadReceipt, LegacyUploadMigrationApplyError> {
        let destination = effective_legacy_destination(
            &replacement.destination,
            self.delete_session.database_scope,
            &self.delete_session.zone,
        )
        .ok_or(remote_stage(
            LegacyUploadMigrationRemoteStage::UploadProofBinding,
        ))?;
        let heic: HeicVerificationProof = serde_json::from_value(
            record
                .proofs
                .get(HEIC_PROOF)
                .ok_or(remote_stage(
                    LegacyUploadMigrationRemoteStage::UploadProofBinding,
                ))?
                .clone(),
        )
        .map_err(|_| remote_stage(LegacyUploadMigrationRemoteStage::UploadProofBinding))?;
        let (replacement_proof, inventory, no_date_candidate) =
            self.resolve_local_replacement(record, replacement, &heic)?;
        let replacement_proof = replacement_proof.ok_or(remote_stage(if no_date_candidate {
            LegacyUploadMigrationRemoteStage::LocalReplacementDispositionNoDateCandidate
        } else {
            LegacyUploadMigrationRemoteStage::LocalReplacementDispositionReplacementProofMismatch
        }))?;
        self.verify_upload_with_known_replacement(
            record,
            replacement,
            proof,
            &LegacyUploadVerificationContext {
                heic: &heic,
                destination: &destination,
                replacement_proof: &replacement_proof,
                inventory: &inventory,
            },
            expected_asset_id,
            expected_master_id,
        )
    }

    fn verify_upload_with_known_replacement(
        &mut self,
        record: &AssetRecord,
        replacement: &EvidenceRetiredReplacement,
        proof: &UploadProof,
        context: &LegacyUploadVerificationContext<'_>,
        expected_asset_id: Option<&str>,
        expected_master_id: Option<&str>,
    ) -> Result<VerifiedRemoteUploadReceipt, LegacyUploadMigrationApplyError> {
        let heic = context.heic;
        let destination = context.destination;
        let replacement_proof = context.replacement_proof;
        let inventory = context.inventory;
        let owner_matches_effective = proof.owner_record_name == destination.owner_record_name
            || (is_legacy_private_primary_sync_unbound(&replacement.destination)
                && proof.owner_record_name.is_none());
        if proof.database_scope != destination.database_scope
            || proof.zone_name != destination.zone_name
            || !owner_matches_effective
            || replacement_proof.database_scope != destination.database_scope
            || replacement_proof.zone_name != destination.zone_name
            || replacement_proof.owner_record_name != destination.owner_record_name
            || replacement_proof.matched_heic_sha256 != heic.heic_sha256
            || replacement_proof.size_bytes != heic.size_bytes
            || replacement_proof.record_type != "CPLAsset"
            || replacement_proof.record_name.trim().is_empty()
            || replacement_proof.record_change_tag.trim().is_empty()
            || replacement_proof.resource_field.trim().is_empty()
        {
            return Err(remote_stage(
                LegacyUploadMigrationRemoteStage::UploadProofBinding,
            ));
        }
        let mut session = self.delete_session.clone();
        session.database_scope = destination.database_scope;
        session.zone = destination.clone();
        let resolved = require_active_uploaded_heic_resolution(
            self.cloudkit
                .inspect_uploaded_heic_asset_initial_state_full_fields(
                    &session,
                    &known_replacement_resolve_request(replacement_proof, destination),
                ),
        )?;
        if expected_asset_id.is_some_and(|asset_id| resolved.record_name != asset_id)
            || expected_master_id.is_some_and(|master_id| resolved.master_record_name != master_id)
        {
            return Err(remote_stage(
                LegacyUploadMigrationRemoteStage::PostUploadVerificationExpectedIdentityMismatch,
            ));
        }
        if resolved.record_name == replacement.uploaded_asset_id
            || resolved.master_record_name == replacement.uploaded_master_id
        {
            return Err(remote_stage(
                LegacyUploadMigrationRemoteStage::PostUploadVerificationRetiredAssetMasterCollision,
            ));
        }
        if resolved.record_name == replacement.original_asset_record_name
            || resolved.master_record_name == replacement.original_asset_record_name
        {
            return Err(remote_stage(
                LegacyUploadMigrationRemoteStage::PostUploadVerificationOriginalAssetCollision,
            ));
        }
        if resolved.record_name == resolved.master_record_name {
            return Err(remote_stage(
                LegacyUploadMigrationRemoteStage::PostUploadVerificationResolvedAssetMasterSelfCollision,
            ));
        }
        if resolved.record_name != replacement_proof.record_name
            || resolved.record_change_tag != replacement_proof.record_change_tag
            || resolved.matched_heic_sha256 != replacement_proof.matched_heic_sha256
            || resolved.size_bytes != replacement_proof.size_bytes
        {
            return Err(remote_stage(
                LegacyUploadMigrationRemoteStage::PostUploadVerificationReplacementProofMismatch,
            ));
        }
        Ok(VerifiedRemoteUploadReceipt {
            asset_id: record.asset_id.clone(),
            uploaded_asset_id: resolved.record_name.clone(),
            master_record_name: resolved.master_record_name.clone(),
            uploaded_asset_id_sha256: canonical_digest(&resolved.record_name).map_err(|_| {
                remote_stage(LegacyUploadMigrationRemoteStage::PostUploadVerificationReceiptDigestFailure)
            })?,
            master_record_name_sha256: canonical_digest(&resolved.master_record_name).map_err(
                |_| {
                    remote_stage(
                        LegacyUploadMigrationRemoteStage::PostUploadVerificationReceiptDigestFailure,
                    )
                },
            )?,
            record_change_tag_sha256: canonical_digest(&resolved.record_change_tag).map_err(
                |_| {
                    remote_stage(
                        LegacyUploadMigrationRemoteStage::PostUploadVerificationReceiptDigestFailure,
                    )
                },
            )?,
            heic_sha256: resolved.matched_heic_sha256,
            size_bytes: resolved.size_bytes,
            destination_sha256: replacement.destination_sha256.clone(),
            inventory_sha256: inventory.sha256.clone(),
            inventory_records_scanned: inventory.records_scanned,
        })
    }
}

fn known_replacement_resolve_request(
    replacement_proof: &CloudKitReplacementResourceProof,
    destination: &CloudKitLibraryDestination,
) -> CloudKitUploadedHeicResolveRequest {
    CloudKitUploadedHeicResolveRequest {
        uploaded_asset_id: replacement_proof.record_name.clone(),
        expected_heic_sha256: replacement_proof.matched_heic_sha256.clone(),
        expected_size_bytes: replacement_proof.size_bytes,
        database_scope: destination.database_scope,
        zone_name: destination.zone_name.clone(),
        owner_record_name: destination.owner_record_name.clone(),
    }
}

fn require_active_uploaded_heic_resolution(
    resolved: Result<CloudKitUploadedHeicAsset, crate::upload::UploadError>,
) -> Result<CloudKitUploadedHeicAsset, LegacyUploadMigrationApplyError> {
    let resolved = resolved.map_err(|_| {
        remote_stage(LegacyUploadMigrationRemoteStage::PostUploadVerificationResolverReadFailure)
    })?;
    if matches!(
        resolved.initial_remote_state,
        CloudKitUploadedHeicInitialState::Active | CloudKitUploadedHeicInitialState::ActiveUnmarked
    ) {
        Ok(resolved)
    } else {
        Err(remote_stage(
            LegacyUploadMigrationRemoteStage::PostUploadVerificationResolverReadFailure,
        ))
    }
}

pub(super) fn require_unique_active_replacement(
    resolution: &CloudKitOriginalAssetResolution,
) -> Result<(), LegacyUploadMigrationApplyError> {
    if resolution.observations.replacement_resource_matches != 1
        || resolution.observations.download_size_mismatches != 0
        || !matches!(
            resolution.disposition,
            CloudKitOriginalAssetResolveDisposition::ReplacementPresent { .. }
                | CloudKitOriginalAssetResolveDisposition::Coexistence { .. }
        )
    {
        return Err(LegacyUploadMigrationApplyError::Remote);
    }
    Ok(())
}

impl LegacyUploadAdapter for ProductionLegacyUploadAdapter {
    type Error = LegacyUploadMigrationApplyError;

    fn into_apply_error(error: Self::Error) -> LegacyUploadMigrationApplyError {
        error
    }

    fn upload_or_reconcile(
        &mut self,
        expected: [&AssetRecord; 2],
        replacements: &[EvidenceRetiredReplacement],
        sources: [&VerifiedUploadSource; 2],
    ) -> Result<[VerifiedLegacyUpload; 2], Self::Error> {
        if replacements.len() != 2 {
            return Err(remote_stage(
                LegacyUploadMigrationRemoteStage::LocalReplacementBinding,
            ));
        }
        let heic_proofs = [
            serde_json::from_value(
                expected[0]
                    .proofs
                    .get(HEIC_PROOF)
                    .ok_or(remote_stage(
                        LegacyUploadMigrationRemoteStage::UploadProofBinding,
                    ))?
                    .clone(),
            ),
            serde_json::from_value(
                expected[1]
                    .proofs
                    .get(HEIC_PROOF)
                    .ok_or(remote_stage(
                        LegacyUploadMigrationRemoteStage::UploadProofBinding,
                    ))?
                    .clone(),
            ),
        ]
        .map(|proof| {
            proof.map_err(|_| remote_stage(LegacyUploadMigrationRemoteStage::UploadProofBinding))
        });
        let heic_proofs = [heic_proofs[0].clone()?, heic_proofs[1].clone()?];
        let preflight = self.preflight_local_replacements(
            expected,
            replacements,
            [&heic_proofs[0], &heic_proofs[1]],
        )?;
        let mut verified = Vec::with_capacity(2);
        for index in 0..2 {
            let heic_proof = &heic_proofs[index];
            let verified_heic = VerifiedHeic::from(heic_proof);
            let destination = preflight.destinations[index].clone();
            if let Some(existing) = preflight.replacement_proofs[index].as_ref() {
                let upload = UploadProof {
                    uploaded_heic_asset_id: existing.record_name.clone(),
                    uploaded_heic_sha256: heic_proof.heic_sha256.clone(),
                    database_scope: destination.database_scope,
                    zone_name: destination.zone_name.clone(),
                    owner_record_name: destination.owner_record_name.clone(),
                    uploaded_heic_path: Some(heic_proof.heic_path.clone()),
                };
                let receipt = self.verify_upload_with_known_replacement(
                    expected[index],
                    &replacements[index],
                    &upload,
                    &LegacyUploadVerificationContext {
                        heic: heic_proof,
                        destination: &destination,
                        replacement_proof: existing,
                        inventory: &preflight.inventory,
                    },
                    Some(&existing.record_name),
                    None,
                )?;
                let upload = durable_legacy_upload_proof(upload, &replacements[index].destination);
                let candidate = Self::candidate_with_upload_proof(expected[index], upload)?;
                verified.push(VerifiedLegacyUpload { candidate, receipt });
                continue;
            }
            let transport_destination =
                photos_upload_transport_destination(&destination, &replacements[index].destination);
            let outcome = run_icloud_upload_with_verified_source(
                &self.upload_session_path,
                sources[index],
                &transport_destination,
            )
            .map_err(|_| remote_stage(LegacyUploadMigrationRemoteStage::UploadExecution))?;
            if outcome.response.filename.as_deref()
                != Some(replacements[index].destination.filename.as_str())
            {
                return Err(remote_stage(
                    LegacyUploadMigrationRemoteStage::UploadResponseBinding,
                ));
            }
            let expected_asset_id = outcome.response.asset_id.clone();
            let expected_master_id = outcome.response.master_id.clone().ok_or(remote_stage(
                LegacyUploadMigrationRemoteStage::UploadResponseBinding,
            ))?;
            let upload = build_upload_proof(&verified_heic, &outcome)
                .map_err(|_| remote_stage(LegacyUploadMigrationRemoteStage::UploadProofBinding))?;
            let upload = bind_generated_upload_proof_destination(
                upload,
                &destination,
                &replacements[index].destination,
            )
            .ok_or(remote_stage(
                LegacyUploadMigrationRemoteStage::UploadProofBinding,
            ))?;
            let receipt = self.verify_upload_with_proof(
                expected[index],
                &replacements[index],
                &upload,
                Some(&expected_asset_id),
                Some(&expected_master_id),
            )?;
            let upload = durable_legacy_upload_proof(upload, &replacements[index].destination);
            let candidate = Self::candidate_with_upload_proof(expected[index], upload)?;
            verified.push(VerifiedLegacyUpload { candidate, receipt });
        }
        if verified[0].receipt.uploaded_asset_id == verified[1].receipt.uploaded_asset_id
            || verified[0].receipt.master_record_name == verified[1].receipt.master_record_name
        {
            return Err(remote_stage(
                LegacyUploadMigrationRemoteStage::CrossCandidateBinding,
            ));
        }
        Ok([verified.remove(0), verified.remove(0)])
    }

    fn verify_existing(
        &mut self,
        records: [&AssetRecord; 2],
        replacements: &[EvidenceRetiredReplacement],
    ) -> Result<[VerifiedRemoteUploadReceipt; 2], Self::Error> {
        Ok([
            self.verify_upload(records[0], &replacements[0], None, None)?,
            self.verify_upload(records[1], &replacements[1], None, None)?,
        ])
    }
}

fn quarantine_legacy_artifacts(
    quarantine_roots: &[PathBuf],
    image_timeout_seconds: u64,
    evidence: &ValidatedLegacyUploadEvidence,
    manifest: &Manifest,
    smb_capabilities: &mut SmbCapabilityAccess<'_>,
) -> Result<QuarantineBatchReceipt, LegacyUploadMigrationApplyError> {
    let plan = evidence.quarantine_plan().clone();
    // This mount/session check is deliberately first: no configured root,
    // cohort path, source, or raw input is opened until the SMB canary proof
    // is present and still bound to the sealed plan.
    let governed_path_gate =
        prove_smb_governed_path_gate(|| smb_capabilities.validate_plan_mapping(&plan))?;
    let configured_roots = quarantine_roots.iter().cloned().collect::<BTreeSet<_>>();
    let sealed_roots = plan
        .roots
        .iter()
        .map(|root| root.canonical_path.clone())
        .collect::<BTreeSet<_>>();
    if configured_roots != sealed_roots || configured_roots.len() != quarantine_roots.len() {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    let cohort_name = CString::new(evidence.audit().cohort_sha256.as_bytes())
        .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
    let mut root_contexts = Vec::with_capacity(plan.roots.len());
    for sealed_root in &plan.roots {
        let canonical_root =
            canonicalize_governed_path(&governed_path_gate, &sealed_root.canonical_path)?;
        if canonical_root != sealed_root.canonical_path || !safe_quarantine_path(&canonical_root) {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        let (root_parent, root_name) = open_quarantine_parent_and_name(&canonical_root)?;
        let root = open_quarantine_directory_at(root_parent.as_raw_fd(), &root_name)?;
        let metadata = validate_quarantine_directory(&root)?;
        if metadata.dev() != sealed_root.device
            || metadata.ino() != sealed_root.inode
            || metadata.uid() != sealed_root.owner
            || metadata.mode() & 0o777 != sealed_root.mode
        {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        let cohort = open_quarantine_directory_at(root.as_raw_fd(), &cohort_name)?;
        let cohort_metadata = validate_quarantine_directory(&cohort)?;
        if cohort_metadata.dev() != metadata.dev() {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        root_contexts.push(QuarantineRootContext {
            root,
            cohort,
            metadata,
        });
    }
    let expected_destination_paths = plan
        .members
        .iter()
        .map(|member| member.destination_path.clone())
        .collect::<BTreeSet<_>>();
    let mut seen_destination_paths = BTreeSet::new();
    for root in &plan.roots {
        let cohort_path = root
            .canonical_path
            .join(evidence.audit().cohort_sha256.as_str());
        for entry in
            fs::read_dir(&cohort_path).map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?
        {
            let path = entry
                .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?
                .path();
            if !expected_destination_paths.contains(&path) || !seen_destination_paths.insert(path) {
                return Err(LegacyUploadMigrationApplyError::Quarantine);
            }
        }
    }
    let specs = quarantine_target_specs(evidence, manifest)?;
    let mut raw_paths = BTreeSet::new();
    let mut raw_identities = BTreeSet::new();
    let mut raw_files = Vec::with_capacity(10);
    for asset_id in evidence.cohort_asset_ids() {
        let raw_path = &manifest
            .get(asset_id)
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?
            .raw_path;
        if !safe_quarantine_path(raw_path) || !raw_paths.insert(raw_path.clone()) {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        let raw = open_optional_anchored_quarantine_file(raw_path)?
            .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
        let sealed_raw = plan
            .raw_inputs
            .iter()
            .find(|sealed| sealed.asset_id == asset_id && sealed.path == *raw_path)
            .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
        if raw.identity != sealed_raw.source {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        if !raw_identities.insert((raw.identity.device, raw.identity.inode)) {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        raw_files.push(raw);
    }
    if raw_files.len() != 10 {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    let mut source_paths = BTreeSet::new();
    let mut target_inodes = BTreeSet::new();
    let mut preflight = Vec::with_capacity(specs.len());
    for spec in specs {
        if !safe_quarantine_path(&spec.source_path)
            || raw_paths.contains(&spec.source_path)
            || !source_paths.insert(spec.source_path.clone())
        {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        let member = plan
            .members
            .iter()
            .find(|member| {
                member.asset_id == spec.asset_id
                    && member.kind == spec.kind
                    && member.source_path == spec.source_path
            })
            .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
        let root_index = plan
            .roots
            .iter()
            .position(|root| root.device == member.root_device)
            .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
        let context = &root_contexts[root_index];
        let destination_path = member.destination_path.clone();
        let destination_name = CString::new(
            destination_path
                .file_name()
                .ok_or(LegacyUploadMigrationApplyError::Quarantine)?
                .as_bytes(),
        )
        .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        let (source_parent, source_name) = open_quarantine_parent_and_name(&spec.source_path)?;
        let source = open_optional_quarantine_file_at(&source_parent, &source_name)?;
        let destination = open_optional_quarantine_file_at(&context.cohort, &destination_name)?;
        let normalization_temp_name = spec
            .expected_reference
            .as_ref()
            .map(|_| reference_normalization_temp_name(evidence, &spec))
            .transpose()?;
        let normalization_temp = normalization_temp_name
            .as_ref()
            .map(|name| open_optional_quarantine_file_at(&source_parent, name))
            .transpose()?
            .flatten();
        let (location, normalized_source, normalization_temp) = if let Some(reference) =
            &spec.expected_reference
        {
            match (source, destination, normalization_temp) {
                (Some(source), None, None) => {
                    validate_quarantine_source(&spec, &source.identity)?;
                    validate_reference_probe(
                        reference,
                        &spec.source_path,
                        image_timeout_seconds,
                        Some(reference.orientation),
                    )?;
                    (QuarantineLocation::Source(source), None, None)
                }
                (None, Some(destination), temp) => {
                    validate_quarantine_source(&spec, &destination.identity)?;
                    validate_reference_probe(
                        reference,
                        &destination_path,
                        image_timeout_seconds,
                        Some(reference.orientation),
                    )?;
                    let temp = temp
                        .map(|file| {
                            classify_reference_normalization_temp(
                                reference,
                                &spec.source_path,
                                &file,
                                &destination.identity,
                                image_timeout_seconds,
                            )
                            .map(|state| AnchoredReferenceNormalizationTemp { file, state })
                        })
                        .transpose()?;
                    (
                        QuarantineLocation::Destination(destination.identity),
                        None,
                        temp,
                    )
                }
                (Some(source), Some(destination), None) => {
                    validate_quarantine_source(&spec, &destination.identity)?;
                    validate_reference_probe(
                        reference,
                        &destination_path,
                        image_timeout_seconds,
                        Some(reference.orientation),
                    )?;
                    validate_normalized_reference(
                        reference,
                        &spec.source_path,
                        &source.identity,
                        &destination.identity,
                        image_timeout_seconds,
                    )?;
                    (
                        QuarantineLocation::Destination(destination.identity),
                        Some(source),
                        None,
                    )
                }
                _ => return Err(LegacyUploadMigrationApplyError::Quarantine),
            }
        } else {
            if normalization_temp.is_some() || source.is_some() == destination.is_some() {
                return Err(LegacyUploadMigrationApplyError::Quarantine);
            }
            let location = if let Some(source) = source {
                validate_quarantine_source(&spec, &source.identity)?;
                QuarantineLocation::Source(source)
            } else {
                let destination = destination.ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
                validate_quarantine_source(&spec, &destination.identity)?;
                QuarantineLocation::Destination(destination.identity)
            };
            (location, None, None)
        };
        let identity = match &location {
            QuarantineLocation::Source(source) => &source.identity,
            QuarantineLocation::Destination(identity) => identity,
        };
        if identity != &member.source
            || identity.device != context.metadata.dev()
            || raw_identities.contains(&(identity.device, identity.inode))
            || !target_inodes.insert((identity.device, identity.inode))
        {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        if let Some(normalized) = &normalized_source
            && (raw_identities.contains(&(normalized.identity.device, normalized.identity.inode))
                || !target_inodes.insert((normalized.identity.device, normalized.identity.inode)))
        {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        if let Some(temp) = &normalization_temp
            && (raw_identities.contains(&(temp.file.identity.device, temp.file.identity.inode))
                || !target_inodes.insert((temp.file.identity.device, temp.file.identity.inode)))
        {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        preflight.push(PreflightQuarantineTarget {
            spec,
            source_parent,
            source_name,
            destination_name,
            destination_path,
            root_index,
            location,
            normalized_source,
            normalization_temp_name,
            normalization_temp,
        });
    }

    // Re-open every source name against the held descriptor after all probes;
    // any mismatch aborts before the first rename.
    revalidate_anchored_files(&raw_files)?;
    let mut rename_count = 0_usize;
    for target in &preflight {
        if let QuarantineLocation::Source(source) = &target.location {
            let current = open_quarantine_file_at(&target.source_parent, &target.source_name)?;
            if current.identity != source.identity {
                return Err(LegacyUploadMigrationApplyError::Quarantine);
            }
        }
        if let Some(normalized) = &target.normalized_source {
            let current = open_quarantine_file_at(&target.source_parent, &target.source_name)?;
            if current.identity != normalized.identity {
                return Err(LegacyUploadMigrationApplyError::Quarantine);
            }
        }
        if let Some(temp) = &target.normalization_temp {
            let temp_name = target
                .normalization_temp_name
                .as_ref()
                .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
            let current = open_quarantine_file_at(&target.source_parent, temp_name)?;
            if current.identity != temp.file.identity {
                return Err(LegacyUploadMigrationApplyError::Quarantine);
            }
        }
    }
    revalidate_anchored_files(&raw_files)?;

    for target in &preflight {
        if let QuarantineLocation::Source(source) = &target.location {
            let context = &root_contexts[target.root_index];
            quarantine_rename_noreplace(
                smb_capabilities,
                &target.spec.source_path,
                &target.destination_path,
                source,
                &source.parent,
                &source.name,
                &context.cohort,
                &target.destination_name,
            )?;
            rename_count += 1;
            fail_after_quarantine_rename(rename_count)?;
        }
    }

    let mut receipts = Vec::with_capacity(preflight.len());
    let mut final_files = Vec::with_capacity(preflight.len() + 5);
    for target in preflight {
        let context = &root_contexts[target.root_index];
        let before = match &target.location {
            QuarantineLocation::Source(source) => source.identity.clone(),
            QuarantineLocation::Destination(identity) => identity.clone(),
        };
        let quarantined = open_quarantine_file_at(&context.cohort, &target.destination_name)?;
        validate_quarantine_source(&target.spec, &quarantined.identity)?;
        let mut normalized_orientation = None;
        let mut decoded_pixel_sha256 = None;
        let mut normalized_reference = None;
        if let Some(reference) = &target.spec.expected_reference {
            let normalized = if let Some(existing) = target.normalized_source {
                validate_normalized_reference(
                    reference,
                    &target.spec.source_path,
                    &existing.identity,
                    &quarantined.identity,
                    image_timeout_seconds,
                )?;
                existing.identity
            } else {
                let temp_name = target
                    .normalization_temp_name
                    .as_ref()
                    .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
                install_normalized_reference_copy(
                    reference,
                    &target.spec.source_path,
                    &target.source_parent,
                    &target.source_name,
                    &context.cohort,
                    &target.destination_name,
                    &quarantined,
                    image_timeout_seconds,
                    temp_name,
                    target.normalization_temp,
                    smb_capabilities,
                )?
            };
            normalized_orientation = Some(1);
            decoded_pixel_sha256 = Some(reference.decoded_pixel_sha256.clone());
            normalized_reference = Some(normalized);
        }
        let quarantined_original =
            open_quarantine_file_at(&context.cohort, &target.destination_name)?;
        if quarantined_original.identity != quarantined.identity
            || quarantined_original.identity.device != context.metadata.dev()
        {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        if let Some(expected) = &normalized_reference {
            let installed = open_optional_anchored_quarantine_file(&target.spec.source_path)?
                .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
            if &installed.identity != expected {
                return Err(LegacyUploadMigrationApplyError::Quarantine);
            }
            final_files.push(installed);
        }
        receipts.push(QuarantineTargetReceipt {
            asset_id_sha256: canonical_digest(&target.spec.asset_id)
                .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?,
            kind: target.spec.kind,
            source_path_sha256: canonical_digest(&target.spec.source_path)
                .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?,
            destination_path_sha256: canonical_digest(&target.destination_path)
                .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?,
            before,
            quarantined_original: quarantined_original.identity.clone(),
            normalized_reference,
            normalized_orientation,
            decoded_pixel_sha256,
        });
        final_files.push(quarantined_original);
    }
    for context in &root_contexts {
        let _ = directory_mutation_durability(&context.cohort)?;
        let _ = directory_mutation_durability(&context.root)?;
    }
    revalidate_anchored_files(&raw_files)?;
    revalidate_anchored_files(&final_files)?;
    for (index, context) in root_contexts.iter().enumerate() {
        let root_identity = quarantine_directory_identity(&context.root)?;
        let cohort_identity = quarantine_directory_identity(&context.cohort)?;
        if open_named_quarantine_directory_identity(&plan.roots[index].canonical_path)?
            != root_identity
            || open_quarantine_directory_at(context.root.as_raw_fd(), &cohort_name)
                .and_then(|directory| quarantine_directory_identity(&directory))?
                != cohort_identity
            || root_identity.device != plan.roots[index].device
            || root_identity.inode != plan.roots[index].inode
            || root_identity.owner != plan.roots[index].owner
            || root_identity.mode != plan.roots[index].mode
            || cohort_identity.device != root_identity.device
        {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
    }
    let canonical_root_identity_sha256 =
        canonical_digest(&plan.roots).map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
    let target_set_sha256 =
        canonical_digest(&receipts).map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
    Ok(QuarantineBatchReceipt {
        schema_version: 2,
        cohort_sha256: evidence.audit().cohort_sha256.clone(),
        canonical_root_identity_sha256,
        target_set_sha256,
        target_count: receipts.len() as u64,
        normalized_reference_count: receipts
            .iter()
            .filter(|receipt| receipt.kind == QuarantineTargetKind::Reference)
            .count() as u64,
    })
}

#[cfg(test)]
pub(super) fn preflight_quarantine_plan(
    evidence: &ValidatedLegacyUploadEvidence,
    configured_roots: &[PathBuf],
    phase: Option<LegacyUploadMigrationPhase>,
    image_timeout_seconds: u64,
) -> Result<QuarantinePreflightGuard, LegacyUploadMigrationApplyError> {
    preflight_quarantine_plan_with_smb_capabilities(
        evidence,
        configured_roots,
        phase,
        image_timeout_seconds,
        None,
        None,
        &SmbQuarantineCapabilities::unavailable(),
    )
}

#[cfg(test)]
pub(super) fn preflight_quarantine_plan_with_conversion_output(
    evidence: &ValidatedLegacyUploadEvidence,
    configured_roots: &[PathBuf],
    phase: LegacyUploadMigrationPhase,
    image_timeout_seconds: u64,
    authoritative_manifest: &Manifest,
    heic_output_dir: &Path,
) -> Result<QuarantinePreflightGuard, LegacyUploadMigrationApplyError> {
    preflight_quarantine_plan_with_smb_capabilities(
        evidence,
        configured_roots,
        Some(phase),
        image_timeout_seconds,
        Some(authoritative_manifest),
        Some(heic_output_dir),
        &SmbQuarantineCapabilities::unavailable(),
    )
}

fn preflight_quarantine_plan_with_smb_capabilities(
    evidence: &ValidatedLegacyUploadEvidence,
    configured_roots: &[PathBuf],
    phase: Option<LegacyUploadMigrationPhase>,
    image_timeout_seconds: u64,
    authoritative_manifest: Option<&Manifest>,
    heic_output_dir: Option<&Path>,
    smb_capabilities: &SmbQuarantineCapabilities,
) -> Result<QuarantinePreflightGuard, LegacyUploadMigrationApplyError> {
    let plan = evidence.quarantine_plan().clone();
    // Keep this before the first canonicalize/open of any governed path.
    let governed_path_gate =
        prove_smb_governed_path_gate(|| smb_capabilities.validate_plan_mapping(&plan))?;
    let configured = configured_roots.iter().cloned().collect::<BTreeSet<_>>();
    let sealed = plan
        .roots
        .iter()
        .map(|root| root.canonical_path.clone())
        .collect::<BTreeSet<_>>();
    if configured != sealed || configured.len() != configured_roots.len() {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    let cohort_name = CString::new(evidence.audit().cohort_sha256.as_bytes())
        .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
    let allow_partial_device_recovery = phase == Some(LegacyUploadMigrationPhase::DeleteConfirmed)
        && evidence.has_device_recovery_receipt();
    let mut roots = Vec::with_capacity(plan.roots.len());
    for sealed_root in &plan.roots {
        if canonicalize_governed_path(&governed_path_gate, &sealed_root.canonical_path)?
            != sealed_root.canonical_path
        {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        let (parent, name) = open_quarantine_parent_and_name(&sealed_root.canonical_path)?;
        let root = open_quarantine_directory_at(parent.as_raw_fd(), &name)?;
        let metadata = validate_quarantine_directory(&root)?;
        if metadata.dev() != sealed_root.device
            || metadata.ino() != sealed_root.inode
            || metadata.uid() != sealed_root.owner
            || metadata.mode() & 0o777 != sealed_root.mode
        {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        let cohort = match open_optional_quarantine_directory_at(root.as_raw_fd(), &cohort_name)? {
            Some(cohort) => {
                let cohort_metadata = validate_quarantine_directory(&cohort)?;
                if cohort_metadata.dev() != metadata.dev() {
                    return Err(LegacyUploadMigrationApplyError::Quarantine);
                }
                Some(cohort)
            }
            None => None,
        };
        if phase.is_none() && cohort.is_some() {
            return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
        }
        if phase.is_some_and(|phase| {
            phase.index() >= LegacyUploadMigrationPhase::DeleteConfirmed.index()
        }) && cohort.is_none()
        {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        roots.push((root, cohort));
    }

    // Every cohort entry must be one of the sealed destinations.  Once the
    // quarantine phase has committed, all destinations are required unless a
    // signed partial device-recovery receipt explicitly permits a subset.
    let expected_destinations = plan
        .members
        .iter()
        .map(|member| member.destination_path.clone())
        .collect::<BTreeSet<_>>();
    let mut seen_destinations = BTreeSet::new();
    for (index, root) in plan.roots.iter().enumerate() {
        let cohort_path = root
            .canonical_path
            .join(evidence.audit().cohort_sha256.as_str());
        if roots[index].1.is_some() {
            for entry in fs::read_dir(&cohort_path)
                .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?
            {
                let path = entry
                    .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?
                    .path();
                if !expected_destinations.contains(&path) || !seen_destinations.insert(path) {
                    // During Prepared, materialization owns only the exact empty
                    // cohort directories it created.  An unbound entry means the
                    // target may be external (or a stale race), so it cannot be
                    // removed as rollback residue; preserve it and report the
                    // recovery state as ambiguous.  Later phases do not own
                    // rollback of the cohort directory, so retain the ordinary
                    // quarantine drift classification there.
                    return Err(if phase == Some(LegacyUploadMigrationPhase::Prepared) {
                        LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous
                    } else {
                        LegacyUploadMigrationApplyError::Quarantine
                    });
                }
            }
        }
    }
    if phase.is_some_and(|phase| phase.index() >= LegacyUploadMigrationPhase::Quarantined.index())
        && !allow_partial_device_recovery
        && seen_destinations.len() != expected_destinations.len()
    {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }

    let mut held_files = Vec::new();
    let mut named_files = Vec::new();
    let mut absent_files = Vec::new();
    for raw in &plan.raw_inputs {
        let file = open_optional_anchored_quarantine_file(&raw.path)?
            .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
        if file.identity != raw.source {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        named_files.push((raw.path.clone(), file.identity.clone()));
        held_files.push(file);
    }
    let mut required_bytes = BTreeMap::<u64, u64>::new();
    for member in &plan.members {
        let root_index = plan
            .roots
            .iter()
            .position(|root| root.device == member.root_device)
            .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
        let (root, cohort) = &roots[root_index];
        let expected_parent = plan.roots[root_index]
            .canonical_path
            .join(evidence.audit().cohort_sha256.as_str());
        if member.destination_path.parent() != Some(expected_parent.as_path()) {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        let source = open_optional_anchored_quarantine_file(&member.source_path)?;
        let destination_name = CString::new(
            member
                .destination_path
                .file_name()
                .ok_or(LegacyUploadMigrationApplyError::Quarantine)?
                .as_bytes(),
        )
        .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        let destination = cohort
            .as_ref()
            .map(|cohort| open_optional_quarantine_file_at(cohort, &destination_name))
            .transpose()?
            .flatten();
        if source.is_none() && destination.is_some() {
            absent_files.push(member.source_path.clone());
        }
        if destination.is_none() && (cohort.is_some() || phase.is_some()) {
            absent_files.push(member.destination_path.clone());
        }
        if member.kind == LegacyUploadMigrationQuarantineKind::Reference
            && phase
                .is_none_or(|phase| phase.index() <= LegacyUploadMigrationPhase::Prepared.index())
        {
            let reference = evidence
                .reference_normalizations()
                .iter()
                .find(|reference| reference.asset_id == member.asset_id)
                .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
            let temp_name = reference_normalization_temp_name(
                evidence,
                &QuarantineTargetSpec {
                    asset_id: member.asset_id.clone(),
                    kind: member.kind,
                    source_path: member.source_path.clone(),
                    expected_sha256: member.source.sha256.clone(),
                    expected_size_bytes: member.source.size_bytes,
                    expected_reference: Some(reference.clone()),
                },
            )?;
            let temp_path = member
                .source_path
                .parent()
                .ok_or(LegacyUploadMigrationApplyError::Quarantine)?
                .join(OsStr::from_bytes(temp_name.to_bytes()));
            if open_optional_anchored_quarantine_file(&temp_path)?.is_some() {
                return Err(LegacyUploadMigrationApplyError::Quarantine);
            }
            absent_files.push(temp_path);
        }
        match (source, destination) {
            (Some(source), None)
                if source.identity == member.source
                    && phase.is_none_or(|phase| {
                        phase.index() <= LegacyUploadMigrationPhase::DeleteConfirmed.index()
                    }) =>
            {
                *required_bytes.entry(member.root_device).or_default() = required_bytes
                    .get(&member.root_device)
                    .copied()
                    .unwrap_or(0)
                    .checked_add(member.source.size_bytes)
                    .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
                named_files.push((member.source_path.clone(), source.identity.clone()));
                held_files.push(source);
            }
            (None, Some(destination)) if destination.identity == member.source => {
                if member.kind == LegacyUploadMigrationQuarantineKind::Final
                    && phase.is_some_and(|phase| {
                        phase.index() >= LegacyUploadMigrationPhase::Converted.index()
                    })
                {
                    let (manifest, output_dir) = authoritative_manifest
                        .zip(heic_output_dir)
                        .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
                    let replacement = evidence
                        .retired_replacements()
                        .iter()
                        .find(|replacement| replacement.asset_id == member.asset_id)
                        .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
                    let output_path =
                        migration_output_path(output_dir, &replacement.destination.filename)?;
                    if !is_verified_conversion_output_at_path(
                        manifest,
                        phase.expect("phase checked above"),
                        &member.asset_id,
                        &output_path,
                    ) {
                        return Err(LegacyUploadMigrationApplyError::Quarantine);
                    }
                    if output_path == member.source_path {
                        return Err(LegacyUploadMigrationApplyError::Quarantine);
                    }
                }
                named_files.push((
                    member.destination_path.clone(),
                    destination.identity.clone(),
                ));
                held_files.push(destination);
            }
            (Some(source), Some(destination))
                if member.kind == LegacyUploadMigrationQuarantineKind::Final
                    && phase.is_some_and(|phase| {
                        phase.index() >= LegacyUploadMigrationPhase::Converted.index()
                    }) =>
            {
                let (manifest, output_dir) = authoritative_manifest
                    .zip(heic_output_dir)
                    .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
                let replacement = evidence
                    .retired_replacements()
                    .iter()
                    .find(|replacement| replacement.asset_id == member.asset_id)
                    .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
                let output_path =
                    migration_output_path(output_dir, &replacement.destination.filename)?;
                let phase = phase.expect("phase checked above");
                if destination.identity != member.source
                    || output_path != member.source_path
                    || !is_verified_conversion_source_for_quarantine(
                        manifest,
                        phase,
                        &member.asset_id,
                        &member.source_path,
                        &source.identity,
                        &member.source,
                        member.root_device,
                    )
                {
                    return Err(LegacyUploadMigrationApplyError::Quarantine);
                }
                named_files.push((member.source_path.clone(), source.identity.clone()));
                named_files.push((
                    member.destination_path.clone(),
                    destination.identity.clone(),
                ));
                held_files.push(source);
                held_files.push(destination);
            }
            (Some(source), Some(destination))
                if member.kind == LegacyUploadMigrationQuarantineKind::Reference
                    && phase.is_some_and(|phase| {
                        phase.index() >= LegacyUploadMigrationPhase::DeleteConfirmed.index()
                    })
                    && source.identity != member.source
                    && source.identity.owner == unsafe { libc::geteuid() }
                    && source.identity.mode == 0o600
                    && source.identity.link_count == 1
                    && source.identity.device == member.root_device
                    && destination.identity == member.source =>
            {
                let reference = evidence
                    .reference_normalizations()
                    .iter()
                    .find(|reference| reference.asset_id == member.asset_id)
                    .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
                validate_reference_probe(
                    reference,
                    &member.source_path,
                    image_timeout_seconds,
                    Some(1),
                )?;
                named_files.push((member.source_path.clone(), source.identity.clone()));
                named_files.push((
                    member.destination_path.clone(),
                    destination.identity.clone(),
                ));
                held_files.push(source);
                held_files.push(destination);
            }
            _ => return Err(LegacyUploadMigrationApplyError::Quarantine),
        }
        if root
            .metadata()
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?
            .dev()
            != member.root_device
        {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
    }
    revalidate_anchored_files(&held_files)?;
    for (index, (root, _)) in roots.iter().enumerate() {
        let required = required_bytes
            .get(&plan.roots[index].device)
            .copied()
            .unwrap_or(0);
        if available_bytes(root)? < required {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
    }
    let materialization_root_count = roots.len();
    let materialization_authority = if phase == Some(LegacyUploadMigrationPhase::Prepared) {
        Some(materialize_prepared_quarantine_roots(
            evidence,
            &mut roots,
            &cohort_name,
        )?)
    } else {
        None
    };
    if let Err(error) = revalidate_anchored_files(&held_files) {
        if let Some(authority_sha256) = &materialization_authority {
            rollback_materialized_quarantine_roots(
                evidence,
                authority_sha256,
                &mut roots,
                &cohort_name,
                materialization_root_count,
            )?;
        }
        return Err(error);
    }
    let held_roots_result = roots
        .iter()
        .enumerate()
        .map(|(index, (root, cohort))| {
            let cohort_identity = cohort
                .as_ref()
                .map(quarantine_directory_identity)
                .transpose()?;
            Ok(HeldQuarantineRoot {
                root_path: plan.roots[index].canonical_path.clone(),
                root_identity: quarantine_directory_identity(root)?,
                cohort_path: plan.roots[index]
                    .canonical_path
                    .join(evidence.audit().cohort_sha256.as_str()),
                cohort_name: cohort_name.clone(),
                cohort_identity,
                cohort_must_be_empty: !allow_partial_device_recovery
                    && phase.is_none_or(|phase| {
                        phase.index() <= LegacyUploadMigrationPhase::DeleteConfirmed.index()
                    }),
                root: root
                    .try_clone()
                    .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?,
                cohort: cohort
                    .as_ref()
                    .map(File::try_clone)
                    .transpose()
                    .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?,
            })
        })
        .collect::<Result<Vec<_>, LegacyUploadMigrationApplyError>>();
    let held_roots = match held_roots_result {
        Ok(held_roots) => held_roots,
        Err(error) => {
            if let Some(authority_sha256) = &materialization_authority {
                rollback_materialized_quarantine_roots(
                    evidence,
                    authority_sha256,
                    &mut roots,
                    &cohort_name,
                    materialization_root_count,
                )?;
            }
            return Err(error);
        }
    };
    let guard = QuarantinePreflightGuard {
        roots: held_roots,
        files: held_files,
        named_files,
        absent_files,
    };
    if let Err(error) = guard.revalidate() {
        if let Some(authority_sha256) = &materialization_authority {
            rollback_materialized_quarantine_roots(
                evidence,
                authority_sha256,
                &mut roots,
                &cohort_name,
                materialization_root_count,
            )?;
        }
        return Err(error);
    }
    Ok(guard)
}

fn remove_exact_empty_quarantine_directory(
    parent: &File,
    name: &CStr,
    held: &File,
    expected: QuarantineDirectoryIdentity,
) -> Result<(), LegacyUploadMigrationApplyError> {
    if quarantine_directory_identity(held)? != expected || !quarantine_directory_is_empty(held)? {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    let named = open_optional_quarantine_directory_at(parent.as_raw_fd(), name)?
        .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
    if quarantine_directory_identity(&named)? != expected || !quarantine_directory_is_empty(&named)?
    {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    if fail_quarantine_directory_removal_at(QuarantineDirectoryRemovalCrashPoint::BeforeUnlink) {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    if fail_quarantine_directory_removal_at(QuarantineDirectoryRemovalCrashPoint::AfterUnlink) {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    parent
        .sync_all()
        .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
    if open_optional_quarantine_directory_at(parent.as_raw_fd(), name)?.is_some() {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    Ok(())
}

const QUARANTINE_RESIDUAL_AUDIT_SCHEMA_VERSION: u64 = 1;
const MAX_QUARANTINE_RESIDUAL_AUDIT_BYTES: u64 = 1_048_576;
const QUARANTINE_RESIDUAL_PROGRESS_SCHEMA_VERSION: u64 = 1;
const QUARANTINE_RESIDUAL_PROGRESS_GENESIS_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct QuarantineResidualDirectoryAudit {
    pub(super) path: PathBuf,
    pub(super) root: QuarantineResidualRootIdentity,
    pub(super) directory: QuarantineDirectoryIdentity,
    pub(super) empty: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct QuarantineResidualRootIdentity {
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) owner: u32,
    pub(super) mode: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct QuarantineResidualAuditDocument {
    pub(super) schema_version: u64,
    pub(super) evidence_sha256: String,
    pub(super) cohort_sha256: String,
    pub(super) manifest_sha256: String,
    pub(super) quarantine_plan_sha256: String,
    pub(super) directories: Vec<QuarantineResidualDirectoryAudit>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QuarantineResidualProgressAuthority {
    schema_version: u64,
    audit_sha256: String,
    evidence_sha256: String,
    cohort_sha256: String,
    manifest_sha256: String,
    quarantine_plan_sha256: String,
    directory_count: u64,
    directory_set_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QuarantineResidualRemovalIntent {
    schema_version: u64,
    authority_sha256: String,
    audit_sha256: String,
    ordinal: u64,
    path: PathBuf,
    directory: QuarantineDirectoryIdentity,
    previous_done_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct QuarantineResidualRemovalDone {
    schema_version: u64,
    authority_sha256: String,
    audit_sha256: String,
    ordinal: u64,
    path: PathBuf,
    directory: QuarantineDirectoryIdentity,
    intent_sha256: String,
    previous_done_sha256: String,
}

struct QuarantineResidualProgressStep {
    intent_path: PathBuf,
    intent_bytes: Vec<u8>,
    done_path: PathBuf,
    done_bytes: Vec<u8>,
    done_sha256: String,
}

pub(super) struct SealedQuarantineResidualAudit {
    path: PathBuf,
    parent_path: PathBuf,
    parent_device: u64,
    parent_inode: u64,
    parent: File,
    name: CString,
    file: File,
    identity: QuarantineFileIdentity,
    bytes: Vec<u8>,
}

impl SealedQuarantineResidualAudit {
    fn revalidate(&mut self) -> Result<(), LegacyUploadMigrationApplyError> {
        let (held_identity, held_bytes) = read_owner_only_audit_descriptor(&mut self.file)?;
        let mut named = open_owner_only_audit_at(&self.parent, &self.name)?;
        let (named_identity, named_bytes) = read_owner_only_audit_descriptor(&mut named)?;
        let current_parent = fs::symlink_metadata(&self.parent_path)
            .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
        if held_identity != self.identity
            || named_identity != self.identity
            || held_bytes != self.bytes
            || named_bytes != self.bytes
            || !safe_quarantine_path(&self.path)
            || !current_parent.file_type().is_dir()
            || current_parent.dev() != self.parent_device
            || current_parent.ino() != self.parent_inode
        {
            return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
        }
        Ok(())
    }
}

pub(crate) fn audit_legacy_upload_quarantine_residuals(
    request: &LegacyUploadQuarantineResidualAuditRequest,
) -> Result<LegacyUploadQuarantineResidualAuditReport, LegacyUploadMigrationApplyError> {
    let mut evidence =
        load_validated_legacy_uploaded_heic_evidence(&request.evidence).map_err(|error| {
            LegacyUploadMigrationApplyError::Evidence {
                category: error.category(),
            }
        })?;
    validate_configured_quarantine_roots(&evidence, &request.quarantine_roots)?;
    let state_store = AssetStateStore::open_immutable_read_only(&request.evidence.manifest_path)
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    let manifest = state_store
        .load()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    if state_store
        .json_checkpoint_status_for_manifest(&manifest)
        .map_err(|_| LegacyUploadMigrationApplyError::State)?
        != JsonCheckpointStatus::Current
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    evidence
        .revalidate_authoritative_manifest(&manifest)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    validate_zero_migration_journal_state(&manifest)?;
    let manifest_sha256 = migration_manifest_sha256(&manifest)?;
    let plan = evidence.quarantine_plan().clone();
    let cohort_name = CString::new(evidence.audit().cohort_sha256.as_bytes())
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
    let mut held = Vec::with_capacity(plan.roots.len());
    let mut directories = Vec::with_capacity(plan.roots.len());
    for sealed_root in &plan.roots {
        let root = open_and_validate_sealed_quarantine_root(sealed_root)?;
        let root_identity = quarantine_directory_identity(&root)?;
        let cohort = open_quarantine_directory_at(root.as_raw_fd(), &cohort_name)
            .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
        let directory_identity = quarantine_directory_identity(&cohort)
            .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
        if directory_identity.device != root_identity.device
            || !quarantine_directory_is_empty(&cohort)
                .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?
        {
            return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
        }
        directories.push(QuarantineResidualDirectoryAudit {
            path: sealed_root
                .canonical_path
                .join(evidence.audit().cohort_sha256.as_str()),
            root: quarantine_residual_root_identity(&root)?,
            directory: directory_identity,
            empty: true,
        });
        held.push((root, cohort));
    }
    if directories.is_empty() {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    revalidate_residual_directories(&held, &directories, true)?;
    evidence.revalidate_held_evidence().map_err(|error| {
        LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        }
    })?;
    state_store
        .revalidate_immutable_read_snapshot()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    let document = QuarantineResidualAuditDocument {
        schema_version: QUARANTINE_RESIDUAL_AUDIT_SCHEMA_VERSION,
        evidence_sha256: evidence.audit().evidence_sha256.clone(),
        cohort_sha256: evidence.audit().cohort_sha256.clone(),
        manifest_sha256,
        quarantine_plan_sha256: plan.plan_sha256.clone(),
        directories,
    };
    let mut bytes = serde_json::to_vec_pretty(&document)
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
    bytes.push(b'\n');
    let audit_sha256 = sha256_bytes_for_apply(&bytes);
    write_owner_only_audit_exclusive(&request.output_path, &bytes, &audit_sha256)?;
    Ok(LegacyUploadQuarantineResidualAuditReport {
        audit_sha256,
        directory_count: document.directories.len() as u64,
    })
}

pub(crate) fn recover_legacy_upload_quarantine_residuals(
    state_store: &AssetStateStore,
    request: &LegacyUploadQuarantineResidualRecoveryRequest,
) -> Result<LegacyUploadQuarantineResidualRecoveryReport, LegacyUploadMigrationApplyError> {
    if !valid_sha256(&request.expected_audit_sha256) {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    let mut evidence = load_validated_legacy_uploaded_heic_evidence_with_state_store(
        &request.evidence,
        None,
        state_store,
    )
    .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
        category: error.category(),
    })?;
    validate_configured_quarantine_roots(&evidence, &request.quarantine_roots)?;
    let manifest = state_store
        .load()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    if state_store
        .json_checkpoint_status_for_manifest(&manifest)
        .map_err(|_| LegacyUploadMigrationApplyError::State)?
        != JsonCheckpointStatus::Current
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    evidence
        .revalidate_authoritative_manifest(&manifest)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    validate_zero_migration_journal_state(&manifest)?;
    let manifest_sha256 = migration_manifest_sha256(&manifest)?;
    let mut sealed_audit = read_sealed_quarantine_residual_audit(&request.audit_path)?;
    if sealed_audit.identity.sha256 != request.expected_audit_sha256 {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    let document: QuarantineResidualAuditDocument =
        crate::strict_json::from_reader(sealed_audit.bytes.as_slice())
            .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
    let plan = evidence.quarantine_plan().clone();
    if document.schema_version != QUARANTINE_RESIDUAL_AUDIT_SCHEMA_VERSION
        || document.evidence_sha256 != evidence.audit().evidence_sha256
        || document.cohort_sha256 != evidence.audit().cohort_sha256
        || document.manifest_sha256 != manifest_sha256
        || document.quarantine_plan_sha256 != plan.plan_sha256
        || document.directories.len() != plan.roots.len()
        || document.directories.is_empty()
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    let cohort_name = CString::new(evidence.audit().cohort_sha256.as_bytes())
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
    let mut roots = Vec::with_capacity(plan.roots.len());
    for (sealed_root, audited) in plan.roots.iter().zip(&document.directories) {
        let expected_path = sealed_root
            .canonical_path
            .join(evidence.audit().cohort_sha256.as_str());
        let root = open_and_validate_sealed_quarantine_root(sealed_root)?;
        if audited.path != expected_path
            || audited.root != quarantine_residual_root_identity(&root)?
            || !audited.empty
        {
            return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
        }
        let cohort = open_optional_quarantine_directory_at(root.as_raw_fd(), &cohort_name)?;
        if let Some(cohort) = &cohort
            && (quarantine_directory_identity(cohort)? != audited.directory
                || !quarantine_directory_is_empty(cohort)?)
        {
            return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
        }
        roots.push(root);
    }
    let removed = recover_residual_directories_with_progress(
        &mut evidence,
        &mut sealed_audit,
        ResidualRecoveryProgressRequest {
            state_store,
            manifest_sha256: &manifest_sha256,
            audit_path: &request.audit_path,
            audit_sha256: &request.expected_audit_sha256,
            document: &document,
            roots: &roots,
            cohort_name: &cohort_name,
        },
    )?;
    Ok(LegacyUploadQuarantineResidualRecoveryReport {
        status: if removed == 0 {
            "already_absent"
        } else {
            "removed"
        },
        removed_directory_count: removed,
        remote_calls: 0,
    })
}

pub(super) struct ResidualRecoveryProgressRequest<'a> {
    pub(super) state_store: &'a AssetStateStore,
    pub(super) manifest_sha256: &'a str,
    pub(super) audit_path: &'a Path,
    pub(super) audit_sha256: &'a str,
    pub(super) document: &'a QuarantineResidualAuditDocument,
    pub(super) roots: &'a [File],
    pub(super) cohort_name: &'a CStr,
}

pub(super) fn recover_residual_directories_with_progress(
    evidence: &mut ValidatedLegacyUploadEvidence,
    sealed_audit: &mut SealedQuarantineResidualAudit,
    request: ResidualRecoveryProgressRequest<'_>,
) -> Result<u64, LegacyUploadMigrationApplyError> {
    let ResidualRecoveryProgressRequest {
        state_store,
        manifest_sha256,
        audit_path,
        audit_sha256,
        document,
        roots,
        cohort_name,
    } = request;
    if roots.len() != document.directories.len() || roots.is_empty() {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    let directory_set_sha256 = canonical_digest(&document.directories)
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
    let authority = QuarantineResidualProgressAuthority {
        schema_version: QUARANTINE_RESIDUAL_PROGRESS_SCHEMA_VERSION,
        audit_sha256: audit_sha256.to_string(),
        evidence_sha256: document.evidence_sha256.clone(),
        cohort_sha256: document.cohort_sha256.clone(),
        manifest_sha256: manifest_sha256.to_string(),
        quarantine_plan_sha256: document.quarantine_plan_sha256.clone(),
        directory_count: document.directories.len() as u64,
        directory_set_sha256,
    };
    let authority_bytes = strict_progress_bytes(&authority)?;
    let authority_sha256 = sha256_bytes_for_apply(&authority_bytes);
    let authority_path = residual_progress_path(audit_path, audit_sha256, "authority")?;
    let initial = roots
        .iter()
        .zip(&document.directories)
        .map(|(root, audited)| validate_current_residual_member(root, audited, cohort_name))
        .collect::<Result<Vec<_>, LegacyUploadMigrationApplyError>>()?;
    let any_absent = initial.iter().any(Option::is_none);
    let authority_exists =
        exact_owner_only_progress_file(&authority_path, &authority_bytes, false)?.is_some();
    if any_absent && !authority_exists {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous);
    }
    if any_absent {
        validate_initial_residual_progress_chain(
            audit_path,
            audit_sha256,
            &authority_sha256,
            &document.directories,
            &initial,
        )?;
    }
    revalidate_recovery_authority(state_store, evidence, manifest_sha256, sealed_audit)?;
    recovery_progress_result(
        ensure_exact_owner_only_progress_file(&authority_path, &authority_bytes),
        any_absent,
    )?;

    let mut previous_done_sha256 = QUARANTINE_RESIDUAL_PROGRESS_GENESIS_SHA256.to_string();
    let mut previous_done_proof: Option<(PathBuf, Vec<u8>)> = None;
    let mut progress_proofs = vec![(authority_path.clone(), authority_bytes.clone())];
    let mut ambiguity_boundary = any_absent;
    let mut removed = 0_u64;
    for (index, (root, audited)) in roots.iter().zip(&document.directories).enumerate() {
        recovery_progress_result(
            revalidate_recovery_authority(state_store, evidence, manifest_sha256, sealed_audit),
            ambiguity_boundary,
        )?;
        recovery_progress_result(
            exact_owner_only_progress_file(&authority_path, &authority_bytes, true),
            ambiguity_boundary,
        )?;
        if let Some((path, bytes)) = &previous_done_proof {
            recovery_progress_result(
                exact_owner_only_progress_file(path, bytes, true),
                ambiguity_boundary,
            )?;
        }
        let step = quarantine_residual_progress_step(
            audit_path,
            audit_sha256,
            &authority_sha256,
            index,
            audited,
            &previous_done_sha256,
        )?;
        let current = recovery_progress_result(
            validate_current_residual_member(root, audited, cohort_name),
            ambiguity_boundary,
        )?;
        let intent_exists = recovery_progress_result(
            exact_owner_only_progress_file(&step.intent_path, &step.intent_bytes, false),
            ambiguity_boundary,
        )?;
        let done_exists = recovery_progress_result(
            exact_owner_only_progress_file(&step.done_path, &step.done_bytes, false),
            ambiguity_boundary,
        )?;
        match current {
            Some(cohort) => {
                if done_exists.is_some() {
                    return Err(LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous);
                }
                if intent_exists.is_none() {
                    recovery_progress_result(
                        revalidate_recovery_authority(
                            state_store,
                            evidence,
                            manifest_sha256,
                            sealed_audit,
                        ),
                        ambiguity_boundary,
                    )?;
                    recovery_progress_result(
                        validate_current_residual_member(root, audited, cohort_name),
                        ambiguity_boundary,
                    )?
                    .ok_or(LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous)?;
                    recovery_progress_result(
                        ensure_exact_owner_only_progress_file(
                            &step.intent_path,
                            &step.intent_bytes,
                        ),
                        ambiguity_boundary,
                    )?;
                }
                progress_proofs.push((step.intent_path.clone(), step.intent_bytes.clone()));
                recovery_progress_result(
                    revalidate_recovery_authority(
                        state_store,
                        evidence,
                        manifest_sha256,
                        sealed_audit,
                    ),
                    ambiguity_boundary,
                )?;
                recovery_progress_result(
                    exact_owner_only_progress_file(&authority_path, &authority_bytes, true),
                    ambiguity_boundary,
                )?;
                recovery_progress_result(
                    exact_owner_only_progress_file(&step.intent_path, &step.intent_bytes, true),
                    ambiguity_boundary,
                )?;
                if let Some((path, bytes)) = &previous_done_proof {
                    recovery_progress_result(
                        exact_owner_only_progress_file(path, bytes, true),
                        ambiguity_boundary,
                    )?;
                }
                let current = recovery_progress_result(
                    validate_current_residual_member(root, audited, cohort_name),
                    ambiguity_boundary,
                )?
                .ok_or(LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous)?;
                let current_identity = recovery_progress_result(
                    quarantine_directory_identity(&current),
                    ambiguity_boundary,
                )?;
                let held_identity = recovery_progress_result(
                    quarantine_directory_identity(&cohort),
                    ambiguity_boundary,
                )?;
                if current_identity != held_identity
                    || remove_exact_empty_quarantine_directory(
                        root,
                        cohort_name,
                        &current,
                        audited.directory,
                    )
                    .is_err()
                {
                    return Err(LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous);
                }
                ambiguity_boundary = true;
                removed += 1;
            }
            None => {
                if intent_exists.is_none() {
                    return Err(LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous);
                }
                progress_proofs.push((step.intent_path.clone(), step.intent_bytes.clone()));
                ambiguity_boundary = true;
            }
        }
        recovery_progress_result(
            revalidate_recovery_authority(state_store, evidence, manifest_sha256, sealed_audit),
            ambiguity_boundary,
        )?;
        recovery_progress_result(
            exact_owner_only_progress_file(&authority_path, &authority_bytes, true),
            ambiguity_boundary,
        )?;
        recovery_progress_result(
            exact_owner_only_progress_file(&step.intent_path, &step.intent_bytes, true),
            ambiguity_boundary,
        )?;
        if let Some((path, bytes)) = &previous_done_proof {
            recovery_progress_result(
                exact_owner_only_progress_file(path, bytes, true),
                ambiguity_boundary,
            )?;
        }
        if recovery_progress_result(
            validate_current_residual_member(root, audited, cohort_name),
            ambiguity_boundary,
        )?
        .is_some()
        {
            return Err(LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous);
        }
        let persisted_done_sha256 = recovery_progress_result(
            ensure_exact_owner_only_progress_file(&step.done_path, &step.done_bytes),
            ambiguity_boundary,
        )?;
        if persisted_done_sha256 != step.done_sha256 {
            return Err(LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous);
        }
        previous_done_sha256 = step.done_sha256;
        progress_proofs.push((step.done_path.clone(), step.done_bytes.clone()));
        previous_done_proof = Some((step.done_path, step.done_bytes));
    }
    recovery_progress_result(
        revalidate_recovery_authority(state_store, evidence, manifest_sha256, sealed_audit),
        ambiguity_boundary,
    )?;
    for (root, audited) in roots.iter().zip(&document.directories) {
        if recovery_progress_result(
            validate_current_residual_member(root, audited, cohort_name),
            ambiguity_boundary,
        )?
        .is_some()
        {
            return Err(LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous);
        }
    }
    for (path, bytes) in &progress_proofs {
        recovery_progress_result(
            exact_owner_only_progress_file(path, bytes, true),
            ambiguity_boundary,
        )?;
    }
    Ok(removed)
}

fn recovery_progress_result<T>(
    result: Result<T, LegacyUploadMigrationApplyError>,
    ambiguity_boundary: bool,
) -> Result<T, LegacyUploadMigrationApplyError> {
    result.map_err(|error| {
        if ambiguity_boundary {
            LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous
        } else {
            error
        }
    })
}

fn validate_current_residual_member(
    root: &File,
    audited: &QuarantineResidualDirectoryAudit,
    cohort_name: &CStr,
) -> Result<Option<File>, LegacyUploadMigrationApplyError> {
    if quarantine_residual_root_identity(root)? != audited.root || !audited.empty {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    let audited_name = CString::new(
        audited
            .path
            .file_name()
            .ok_or(LegacyUploadMigrationApplyError::QuarantineResidual)?
            .as_bytes(),
    )
    .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
    if audited_name.as_c_str() != cohort_name {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    let current = open_optional_quarantine_directory_at(root.as_raw_fd(), cohort_name)?;
    if let Some(current) = &current
        && (quarantine_directory_identity(current)? != audited.directory
            || !quarantine_directory_is_empty(current)?)
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    Ok(current)
}

fn strict_progress_bytes(
    value: &impl Serialize,
) -> Result<Vec<u8>, LegacyUploadMigrationApplyError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn residual_progress_path(
    audit_path: &Path,
    audit_sha256: &str,
    suffix: &str,
) -> Result<PathBuf, LegacyUploadMigrationApplyError> {
    if !valid_sha256(audit_sha256)
        || suffix.is_empty()
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    Ok(audit_path
        .parent()
        .ok_or(LegacyUploadMigrationApplyError::QuarantineResidual)?
        .join(format!(
            ".icloudpd-quarantine-recovery-{audit_sha256}.{suffix}.json"
        )))
}

fn quarantine_residual_progress_step(
    audit_path: &Path,
    audit_sha256: &str,
    authority_sha256: &str,
    index: usize,
    audited: &QuarantineResidualDirectoryAudit,
    previous_done_sha256: &str,
) -> Result<QuarantineResidualProgressStep, LegacyUploadMigrationApplyError> {
    let intent = QuarantineResidualRemovalIntent {
        schema_version: QUARANTINE_RESIDUAL_PROGRESS_SCHEMA_VERSION,
        authority_sha256: authority_sha256.to_string(),
        audit_sha256: audit_sha256.to_string(),
        ordinal: index as u64,
        path: audited.path.clone(),
        directory: audited.directory,
        previous_done_sha256: previous_done_sha256.to_string(),
    };
    let intent_bytes = strict_progress_bytes(&intent)?;
    let intent_sha256 = sha256_bytes_for_apply(&intent_bytes);
    let intent_path =
        residual_progress_path(audit_path, audit_sha256, &format!("{index:04}.intent"))?;
    let done = QuarantineResidualRemovalDone {
        schema_version: QUARANTINE_RESIDUAL_PROGRESS_SCHEMA_VERSION,
        authority_sha256: authority_sha256.to_string(),
        audit_sha256: audit_sha256.to_string(),
        ordinal: index as u64,
        path: audited.path.clone(),
        directory: audited.directory,
        intent_sha256: intent_sha256.clone(),
        previous_done_sha256: previous_done_sha256.to_string(),
    };
    let done_bytes = strict_progress_bytes(&done)?;
    let done_sha256 = sha256_bytes_for_apply(&done_bytes);
    let done_path = residual_progress_path(audit_path, audit_sha256, &format!("{index:04}.done"))?;
    Ok(QuarantineResidualProgressStep {
        intent_path,
        intent_bytes,
        done_path,
        done_bytes,
        done_sha256,
    })
}

fn validate_initial_residual_progress_chain(
    audit_path: &Path,
    audit_sha256: &str,
    authority_sha256: &str,
    audited: &[QuarantineResidualDirectoryAudit],
    initial: &[Option<File>],
) -> Result<(), LegacyUploadMigrationApplyError> {
    if audited.len() != initial.len() || audited.is_empty() {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous);
    }
    let mut previous_done_sha256 = QUARANTINE_RESIDUAL_PROGRESS_GENESIS_SHA256.to_string();
    for index in 0..audited.len() {
        let step = quarantine_residual_progress_step(
            audit_path,
            audit_sha256,
            authority_sha256,
            index,
            &audited[index],
            &previous_done_sha256,
        )?;
        let intent = exact_owner_only_progress_file(&step.intent_path, &step.intent_bytes, false)?;
        let done = exact_owner_only_progress_file(&step.done_path, &step.done_bytes, false)?;
        let later_absent = initial[index + 1..].iter().any(Option::is_none);
        if initial[index].is_none() {
            if intent.is_none() || done.is_none() && later_absent {
                return Err(LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous);
            }
            if done.is_some() {
                previous_done_sha256 = step.done_sha256;
            }
        } else if done.is_some() || later_absent {
            return Err(LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous);
        }
    }
    Ok(())
}

fn exact_owner_only_progress_file(
    path: &Path,
    expected_bytes: &[u8],
    required: bool,
) -> Result<Option<String>, LegacyUploadMigrationApplyError> {
    if !owner_only_file_exists(path)? {
        return if required {
            Err(LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous)
        } else {
            Ok(None)
        };
    }
    let mut sealed = read_sealed_quarantine_residual_audit(path)?;
    sealed.revalidate()?;
    if sealed.bytes != expected_bytes {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous);
    }
    Ok(Some(sealed.identity.sha256))
}

fn ensure_exact_owner_only_progress_file(
    path: &Path,
    bytes: &[u8],
) -> Result<String, LegacyUploadMigrationApplyError> {
    if let Some(sha256) = exact_owner_only_progress_file(path, bytes, false)? {
        return Ok(sha256);
    }
    let sha256 = sha256_bytes_for_apply(bytes);
    if write_owner_only_audit_exclusive(path, bytes, &sha256).is_err() {
        return exact_owner_only_progress_file(path, bytes, true)?
            .ok_or(LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous);
    }
    exact_owner_only_progress_file(path, bytes, true)?
        .ok_or(LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous)
}

fn owner_only_file_exists(path: &Path) -> Result<bool, LegacyUploadMigrationApplyError> {
    let (parent, name) = open_quarantine_parent_and_name(path)?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if descriptor >= 0 {
        drop(unsafe { File::from_raw_fd(descriptor) });
        return Ok(true);
    }
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        Ok(false)
    } else {
        Err(LegacyUploadMigrationApplyError::QuarantineResidual)
    }
}

fn validate_configured_quarantine_roots(
    evidence: &ValidatedLegacyUploadEvidence,
    configured_roots: &[PathBuf],
) -> Result<(), LegacyUploadMigrationApplyError> {
    let configured = configured_roots.iter().cloned().collect::<BTreeSet<_>>();
    let sealed = evidence
        .quarantine_plan()
        .roots
        .iter()
        .map(|root| root.canonical_path.clone())
        .collect::<BTreeSet<_>>();
    if configured.is_empty() || configured != sealed || configured.len() != configured_roots.len() {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    Ok(())
}

fn validate_zero_migration_journal_state(
    manifest: &Manifest,
) -> Result<(), LegacyUploadMigrationApplyError> {
    if manifest.legacy_upload_migration_registry().is_some()
        || manifest.records().values().any(|record| {
            record
                .proofs
                .contains_key(super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME)
        })
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    Ok(())
}

pub(super) fn migration_manifest_sha256(
    manifest: &Manifest,
) -> Result<String, LegacyUploadMigrationApplyError> {
    canonical_digest(manifest.records())
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)
}

fn open_and_validate_sealed_quarantine_root(
    sealed: &super::LegacyUploadMigrationQuarantineRoot,
) -> Result<File, LegacyUploadMigrationApplyError> {
    if fs::canonicalize(&sealed.canonical_path)
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?
        != sealed.canonical_path
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    let (parent, name) = open_quarantine_parent_and_name(&sealed.canonical_path)?;
    let root = open_quarantine_directory_at(parent.as_raw_fd(), &name)?;
    let metadata = validate_quarantine_directory(&root)?;
    if metadata.dev() != sealed.device
        || metadata.ino() != sealed.inode
        || metadata.uid() != sealed.owner
        || metadata.mode() & 0o777 != sealed.mode
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    Ok(root)
}

pub(super) fn quarantine_residual_root_identity(
    root: &File,
) -> Result<QuarantineResidualRootIdentity, LegacyUploadMigrationApplyError> {
    let identity = quarantine_directory_identity(root)?;
    Ok(QuarantineResidualRootIdentity {
        device: identity.device,
        inode: identity.inode,
        owner: identity.owner,
        mode: identity.mode,
    })
}

fn revalidate_residual_directories(
    held: &[(File, File)],
    audited: &[QuarantineResidualDirectoryAudit],
    require_empty: bool,
) -> Result<(), LegacyUploadMigrationApplyError> {
    for ((root, cohort), audit) in held.iter().zip(audited) {
        if quarantine_residual_root_identity(root)? != audit.root
            || quarantine_directory_identity(cohort)? != audit.directory
            || require_empty && !quarantine_directory_is_empty(cohort)?
        {
            return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
        }
        let name = CString::new(
            audit
                .path
                .file_name()
                .ok_or(LegacyUploadMigrationApplyError::QuarantineResidual)?
                .as_bytes(),
        )
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
        let named = open_quarantine_directory_at(root.as_raw_fd(), &name)?;
        if quarantine_directory_identity(&named)? != audit.directory
            || require_empty && !quarantine_directory_is_empty(&named)?
        {
            return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
        }
    }
    Ok(())
}

fn revalidate_recovery_authority(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
    manifest_sha256: &str,
    audit: &mut SealedQuarantineResidualAudit,
) -> Result<(), LegacyUploadMigrationApplyError> {
    let manifest = state_store
        .load()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    if state_store
        .json_checkpoint_status_for_manifest(&manifest)
        .map_err(|_| LegacyUploadMigrationApplyError::State)?
        != JsonCheckpointStatus::Current
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    validate_zero_migration_journal_state(&manifest)?;
    if migration_manifest_sha256(&manifest)? != manifest_sha256 {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    evidence
        .revalidate_authoritative_manifest(&manifest)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    evidence.revalidate_held_evidence().map_err(|error| {
        LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        }
    })?;
    audit.revalidate()
}

pub(super) fn read_sealed_quarantine_residual_audit(
    path: &Path,
) -> Result<SealedQuarantineResidualAudit, LegacyUploadMigrationApplyError> {
    let parent_path = path
        .parent()
        .ok_or(LegacyUploadMigrationApplyError::QuarantineResidual)?
        .to_path_buf();
    let (parent, name) = open_quarantine_parent_and_name(path)?;
    let parent_metadata = parent
        .metadata()
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
    let mut file = open_owner_only_audit_at(&parent, &name)?;
    let (identity, bytes) = read_owner_only_audit_descriptor(&mut file)?;
    Ok(SealedQuarantineResidualAudit {
        path: path.to_path_buf(),
        parent_path,
        parent_device: parent_metadata.dev(),
        parent_inode: parent_metadata.ino(),
        parent,
        name,
        file,
        identity,
        bytes,
    })
}

fn open_owner_only_audit_at(
    parent: &File,
    name: &CStr,
) -> Result<File, LegacyUploadMigrationApplyError> {
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        Err(LegacyUploadMigrationApplyError::QuarantineResidual)
    } else {
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn read_owner_only_audit_descriptor(
    file: &mut File,
) -> Result<(QuarantineFileIdentity, Vec<u8>), LegacyUploadMigrationApplyError> {
    let metadata = file
        .metadata()
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > MAX_QUARANTINE_RESIDUAL_AUDIT_BYTES
    {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
    let mut bytes = Vec::new();
    file.take(MAX_QUARANTINE_RESIDUAL_AUDIT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
    if bytes.len() as u64 > MAX_QUARANTINE_RESIDUAL_AUDIT_BYTES {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
    Ok((
        QuarantineFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode() & 0o777,
            link_count: metadata.nlink(),
            size_bytes: metadata.len(),
            modified_unix_seconds: metadata.mtime(),
            modified_unix_nanoseconds: metadata.mtime_nsec(),
            sha256: sha256_bytes_for_apply(&bytes),
        },
        bytes,
    ))
}

fn write_owner_only_audit_exclusive(
    path: &Path,
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<(), LegacyUploadMigrationApplyError> {
    if !safe_quarantine_path(path) || bytes.len() as u64 > MAX_QUARANTINE_RESIDUAL_AUDIT_BYTES {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    let parent_path = path
        .parent()
        .ok_or(LegacyUploadMigrationApplyError::QuarantineResidual)?;
    let (parent, name) = open_quarantine_parent_and_name(path)?;
    let parent_metadata = parent
        .metadata()
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let initial = file
        .metadata()
        .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
    let result = (|| {
        if !initial.file_type().is_file()
            || initial.uid() != unsafe { libc::geteuid() }
            || initial.mode() & 0o777 != 0o600
            || initial.nlink() != 1
        {
            return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
        }
        file.write_all(bytes)
            .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
        file.sync_all()
            .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
        parent
            .sync_all()
            .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
        let (identity, reread) = read_owner_only_audit_descriptor(&mut file)?;
        let mut named = open_owner_only_audit_at(&parent, &name)?;
        let (named_identity, named_bytes) = read_owner_only_audit_descriptor(&mut named)?;
        let current_parent = fs::symlink_metadata(parent_path)
            .map_err(|_| LegacyUploadMigrationApplyError::QuarantineResidual)?;
        if identity.device != initial.dev()
            || identity.inode != initial.ino()
            || identity.sha256 != expected_sha256
            || reread != bytes
            || named_identity != identity
            || named_bytes != bytes
            || !current_parent.file_type().is_dir()
            || current_parent.dev() != parent_metadata.dev()
            || current_parent.ino() != parent_metadata.ino()
        {
            return Err(LegacyUploadMigrationApplyError::QuarantineResidual);
        }
        Ok(())
    })();
    if result.is_err() {
        let current = open_owner_only_audit_at(&parent, &name).ok();
        if current.as_ref().is_some_and(|current| {
            current.metadata().is_ok_and(|metadata| {
                metadata.dev() == initial.dev() && metadata.ino() == initial.ino()
            })
        }) {
            let _ = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
            let _ = parent.sync_all();
        }
    }
    result
}

fn sha256_bytes_for_apply(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn available_bytes(directory: &File) -> Result<u64, LegacyUploadMigrationApplyError> {
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(directory.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    let stats = unsafe { stats.assume_init() };
    (stats.f_bavail as u64)
        .checked_mul(stats.f_frsize)
        .ok_or(LegacyUploadMigrationApplyError::Quarantine)
}

fn quarantine_target_specs(
    evidence: &ValidatedLegacyUploadEvidence,
    manifest: &Manifest,
) -> Result<Vec<QuarantineTargetSpec>, LegacyUploadMigrationApplyError> {
    let mut targets = Vec::with_capacity(9);
    for replacement in evidence.retired_replacements() {
        let record = manifest
            .get(&replacement.asset_id)
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        let upload: UploadProof = serde_json::from_value(
            record
                .proofs
                .get(UPLOAD_PROOF)
                .ok_or(LegacyUploadMigrationApplyError::Quarantine)?
                .clone(),
        )
        .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        let mirror: IcloudpdLocalMirrorProof = serde_json::from_value(
            record
                .proofs
                .get(ICLOUDPD_LOCAL_MIRROR_PROOF)
                .ok_or(LegacyUploadMigrationApplyError::Quarantine)?
                .clone(),
        )
        .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        let final_path = upload
            .uploaded_heic_path
            .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
        if upload.uploaded_heic_sha256 != replacement.uploaded_heic_sha256
            || mirror.uploaded_heic_sha256 != replacement.uploaded_heic_sha256
            || mirror.size_bytes != replacement.uploaded_heic_size_bytes
        {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        targets.push(QuarantineTargetSpec {
            asset_id: replacement.asset_id.clone(),
            kind: QuarantineTargetKind::Final,
            expected_sha256: evidence
                .quarantine_plan()
                .members
                .iter()
                .find(|member| {
                    member.asset_id == replacement.asset_id
                        && member.kind == QuarantineTargetKind::Final
                        && member.source_path == final_path
                })
                .ok_or(LegacyUploadMigrationApplyError::Quarantine)?
                .source
                .sha256
                .clone(),
            expected_size_bytes: evidence
                .quarantine_plan()
                .members
                .iter()
                .find(|member| {
                    member.asset_id == replacement.asset_id
                        && member.kind == QuarantineTargetKind::Final
                        && member.source_path == final_path
                })
                .ok_or(LegacyUploadMigrationApplyError::Quarantine)?
                .source
                .size_bytes,
            source_path: final_path,
            expected_reference: None,
        });
        targets.push(QuarantineTargetSpec {
            asset_id: replacement.asset_id.clone(),
            kind: QuarantineTargetKind::OldMirror,
            source_path: mirror.icloudpd_download_path,
            expected_sha256: replacement.uploaded_heic_sha256.clone(),
            expected_size_bytes: replacement.uploaded_heic_size_bytes,
            expected_reference: None,
        });
    }
    targets.extend(evidence.reference_normalizations().iter().map(|reference| {
        QuarantineTargetSpec {
            asset_id: reference.asset_id.clone(),
            kind: QuarantineTargetKind::Reference,
            source_path: reference.reference_path.clone(),
            expected_sha256: reference.file_sha256.clone(),
            expected_size_bytes: reference.size_bytes,
            expected_reference: Some(reference.clone()),
        }
    }));
    if targets.len() != 9 {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    Ok(targets)
}

fn reference_normalization_temp_name(
    evidence: &ValidatedLegacyUploadEvidence,
    spec: &QuarantineTargetSpec,
) -> Result<CString, LegacyUploadMigrationApplyError> {
    if spec.kind != QuarantineTargetKind::Reference || spec.expected_reference.is_none() {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    let digest = canonical_digest(&ReferenceNormalizationTempNameInput {
        schema_version: 1,
        cohort_sha256: &evidence.audit().cohort_sha256,
        asset_id: &spec.asset_id,
        source_path: &spec.source_path,
    })
    .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
    CString::new(format!(
        ".legacy-upload-reference-normalize.{digest}.tmp.jpg"
    ))
    .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)
}

fn validate_quarantine_source(
    spec: &QuarantineTargetSpec,
    identity: &QuarantineFileIdentity,
) -> Result<(), LegacyUploadMigrationApplyError> {
    if identity.sha256 != spec.expected_sha256
        || identity.size_bytes != spec.expected_size_bytes
        || spec.expected_reference.as_ref().is_some_and(|reference| {
            identity.device != reference.device || identity.inode != reference.inode
        })
    {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    Ok(())
}

fn validate_normalized_reference(
    reference: &EvidenceReferenceNormalization,
    path: &Path,
    identity: &QuarantineFileIdentity,
    quarantined_original: &QuarantineFileIdentity,
    image_timeout_seconds: u64,
) -> Result<(), LegacyUploadMigrationApplyError> {
    let current_euid = unsafe { libc::geteuid() };
    if identity.owner != current_euid
        || identity.mode != 0o600
        || identity.link_count != 1
        || (identity.device, identity.inode)
            == (quarantined_original.device, quarantined_original.inode)
    {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    validate_reference_probe(reference, path, image_timeout_seconds, Some(1))
}

fn classify_reference_normalization_temp(
    reference: &EvidenceReferenceNormalization,
    source_path: &Path,
    temp: &AnchoredQuarantineFile,
    quarantined_original: &QuarantineFileIdentity,
    image_timeout_seconds: u64,
) -> Result<ReferenceNormalizationTempState, LegacyUploadMigrationApplyError> {
    let current_euid = unsafe { libc::geteuid() };
    if temp.identity.owner != current_euid
        || temp.identity.mode != 0o600
        || temp.identity.link_count != 1
        || temp.identity.device != quarantined_original.device
        || (temp.identity.device, temp.identity.inode)
            == (quarantined_original.device, quarantined_original.inode)
    {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    let temp_path = source_path
        .parent()
        .ok_or(LegacyUploadMigrationApplyError::Quarantine)?
        .join(OsStr::from_bytes(temp.name.to_bytes()));
    if temp.identity.size_bytes == 0 && temp.identity.sha256 == format!("{:x}", Sha256::digest([]))
    {
        Ok(ReferenceNormalizationTempState::Created)
    } else if temp.identity.sha256 == quarantined_original.sha256
        && temp.identity.size_bytes == quarantined_original.size_bytes
    {
        validate_reference_probe(
            reference,
            &temp_path,
            image_timeout_seconds,
            Some(reference.orientation),
        )?;
        Ok(ReferenceNormalizationTempState::Copied)
    } else {
        validate_normalized_reference(
            reference,
            &temp_path,
            &temp.identity,
            quarantined_original,
            image_timeout_seconds,
        )?;
        Ok(ReferenceNormalizationTempState::Normalized)
    }
}

#[allow(clippy::too_many_arguments)]
fn install_normalized_reference_copy(
    reference: &EvidenceReferenceNormalization,
    source_path: &Path,
    source_parent: &File,
    source_name: &CStr,
    cohort: &File,
    quarantine_name: &CStr,
    quarantined_original: &AnchoredQuarantineFile,
    image_timeout_seconds: u64,
    temp_name: &CStr,
    existing_temp: Option<AnchoredReferenceNormalizationTemp>,
    smb_capabilities: &mut SmbCapabilityAccess<'_>,
) -> Result<QuarantineFileIdentity, LegacyUploadMigrationApplyError> {
    let temp_path = source_path
        .parent()
        .ok_or(LegacyUploadMigrationApplyError::Quarantine)?
        .join(OsStr::from_bytes(temp_name.to_bytes()));
    let (mut temp, mut state) = if let Some(existing) = existing_temp {
        let named = open_quarantine_file_at(source_parent, temp_name)?;
        if inspect_quarantine_file(&existing.file.file)? != existing.file.identity
            || named.identity != existing.file.identity
            || classify_reference_normalization_temp(
                reference,
                source_path,
                &named,
                &quarantined_original.identity,
                image_timeout_seconds,
            )? != existing.state
        {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        (named, existing.state)
    } else {
        let fd = unsafe {
            libc::openat(
                source_parent.as_raw_fd(),
                temp_name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        let created_file = unsafe { File::from_raw_fd(fd) };
        created_file
            .sync_all()
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        drop(created_file);
        sync_directory_or_revalidate(source_parent, || {
            let created = open_quarantine_file_at(source_parent, temp_name)?;
            if created.identity.size_bytes != 0 {
                return Err(LegacyUploadMigrationApplyError::Quarantine);
            }
            Ok(())
        })?;
        let created = open_quarantine_file_at(source_parent, temp_name)?;
        let state = classify_reference_normalization_temp(
            reference,
            source_path,
            &created,
            &quarantined_original.identity,
            image_timeout_seconds,
        )?;
        if state != ReferenceNormalizationTempState::Created {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        fail_at_reference_normalization_crash_point(ReferenceNormalizationCrashPoint::AfterCreate)?;
        (created, state)
    };

    if state == ReferenceNormalizationTempState::Created {
        if inspect_quarantine_file(&quarantined_original.file)? != quarantined_original.identity
            || open_quarantine_file_at(cohort, quarantine_name)?.identity
                != quarantined_original.identity
            || open_quarantine_file_at(source_parent, temp_name)?.identity != temp.identity
        {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        let fd = unsafe {
            libc::openat(
                source_parent.as_raw_fd(),
                temp_name.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        let mut writable = unsafe { File::from_raw_fd(fd) };
        if inspect_quarantine_file(&writable)? != temp.identity {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        let mut source = quarantined_original
            .file
            .try_clone()
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        source
            .seek(SeekFrom::Start(0))
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        std::io::copy(&mut source, &mut writable)
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        writable
            .sync_all()
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        drop(writable);
        sync_directory_or_revalidate(source_parent, || {
            open_quarantine_file_at(source_parent, temp_name).map(|_| ())
        })?;
        temp = open_quarantine_file_at(source_parent, temp_name)?;
        state = classify_reference_normalization_temp(
            reference,
            source_path,
            &temp,
            &quarantined_original.identity,
            image_timeout_seconds,
        )?;
        if state != ReferenceNormalizationTempState::Copied {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        fail_at_reference_normalization_crash_point(ReferenceNormalizationCrashPoint::AfterCopy)?;
    }

    if state == ReferenceNormalizationTempState::Copied {
        if inspect_quarantine_file(&quarantined_original.file)? != quarantined_original.identity
            || open_quarantine_file_at(cohort, quarantine_name)?.identity
                != quarantined_original.identity
            || open_quarantine_file_at(source_parent, temp_name)?.identity != temp.identity
        {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        crate::monitor::normalize_private_reference_orientation_temp(
            &temp_path,
            image_timeout_seconds,
        )
        .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        temp = open_quarantine_file_at(source_parent, temp_name)?;
        state = classify_reference_normalization_temp(
            reference,
            source_path,
            &temp,
            &quarantined_original.identity,
            image_timeout_seconds,
        )?;
        if state != ReferenceNormalizationTempState::Normalized {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
        temp.file
            .sync_all()
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        sync_directory_or_revalidate(source_parent, || {
            open_quarantine_file_at(source_parent, temp_name).map(|_| ())
        })?;
        fail_at_reference_normalization_crash_point(
            ReferenceNormalizationCrashPoint::AfterNormalize,
        )?;
    }

    if inspect_quarantine_file(&quarantined_original.file)? != quarantined_original.identity
        || open_quarantine_file_at(cohort, quarantine_name)?.identity
            != quarantined_original.identity
        || open_quarantine_file_at(source_parent, temp_name)?.identity != temp.identity
    {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    fail_at_reference_normalization_crash_point(ReferenceNormalizationCrashPoint::BeforeRename)?;
    quarantine_rename_noreplace(
        smb_capabilities,
        &temp_path,
        source_path,
        &temp,
        source_parent,
        temp_name,
        source_parent,
        source_name,
    )?;
    fail_at_reference_normalization_crash_point(ReferenceNormalizationCrashPoint::AfterRename)?;
    let installed = open_quarantine_file_at(source_parent, source_name)?;
    if installed.identity != temp.identity {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    validate_normalized_reference(
        reference,
        source_path,
        &installed.identity,
        &quarantined_original.identity,
        image_timeout_seconds,
    )?;
    Ok(installed.identity)
}

fn sync_directory_or_revalidate(
    directory: &File,
    revalidate: impl FnOnce() -> Result<(), LegacyUploadMigrationApplyError>,
) -> Result<(), LegacyUploadMigrationApplyError> {
    match directory.sync_all() {
        Ok(()) => Ok(()),
        Err(error)
            if error.kind() == std::io::ErrorKind::Unsupported
                || error
                    .raw_os_error()
                    .is_some_and(|code| [libc::EINVAL, libc::ENOTSUP].contains(&code)) =>
        {
            revalidate()
        }
        Err(_) => Err(LegacyUploadMigrationApplyError::Quarantine),
    }
}

#[cfg(target_os = "macos")]
fn reconcile_smb_noreplace_result(
    result: Result<SmbRenameResult, SmbNoReplaceError>,
    exact_renamed: bool,
    exact_noop: bool,
    collision_preserved_source: bool,
    collision_has_destination: bool,
) -> Result<(), LegacyUploadMigrationApplyError> {
    match result {
        Ok(SmbRenameResult::Renamed) if exact_renamed => Ok(()),
        Err(SmbNoReplaceError::Ambiguous) if exact_renamed => Ok(()),
        Err(SmbNoReplaceError::Ambiguous) if exact_noop => {
            Err(LegacyUploadMigrationApplyError::Quarantine)
        }
        Ok(SmbRenameResult::Collision)
            if collision_preserved_source && collision_has_destination =>
        {
            Err(LegacyUploadMigrationApplyError::Quarantine)
        }
        Err(_) if exact_noop => Err(LegacyUploadMigrationApplyError::Quarantine),
        _ => Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous),
    }
}

#[allow(clippy::too_many_arguments)]
fn quarantine_rename_noreplace(
    smb_capabilities: &mut SmbCapabilityAccess<'_>,
    source_path: &Path,
    destination_path: &Path,
    held_source: &AnchoredQuarantineFile,
    source_parent: &File,
    source_name: &CStr,
    destination_parent: &File,
    destination_name: &CStr,
) -> Result<(), LegacyUploadMigrationApplyError> {
    if inspect_quarantine_file(&held_source.file)? != held_source.identity
        || open_quarantine_file_at(source_parent, source_name)?.identity != held_source.identity
        || open_optional_quarantine_file_at(destination_parent, destination_name)?.is_some()
    {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }

    #[cfg(target_os = "macos")]
    let protocol_result = match smb_capabilities.session_for_paths(source_path, destination_path)? {
        Some(session) => Some(session.rename_noreplace(source_path, destination_path)),
        None => {
            renameat_noreplace(
                source_parent,
                source_name,
                destination_parent,
                destination_name,
            )?;
            None
        }
    };
    #[cfg(not(target_os = "macos"))]
    let protocol_succeeded = {
        let _ = (smb_capabilities, source_path, destination_path);
        renameat_noreplace(
            source_parent,
            source_name,
            destination_parent,
            destination_name,
        )?;
        true
    };

    let source_after = open_optional_quarantine_file_at(source_parent, source_name)?;
    let destination_after = open_optional_quarantine_file_at(destination_parent, destination_name)?;
    let exact_renamed = source_after.is_none()
        && destination_after
            .as_ref()
            .is_some_and(|file| file.identity == held_source.identity);
    let exact_noop = source_after
        .as_ref()
        .is_some_and(|file| file.identity == held_source.identity)
        && destination_after.is_none();

    #[cfg(target_os = "macos")]
    match protocol_result {
        None if exact_renamed => {}
        Some(result) => reconcile_smb_noreplace_result(
            result,
            exact_renamed,
            exact_noop,
            source_after
                .as_ref()
                .is_some_and(|file| file.identity == held_source.identity),
            destination_after.is_some(),
        )?,
        None => return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous),
    }
    #[cfg(not(target_os = "macos"))]
    if !protocol_succeeded || !exact_renamed {
        return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
    }

    let revalidate_renamed = || {
        if open_optional_quarantine_file_at(source_parent, source_name)?.is_some()
            || open_quarantine_file_at(destination_parent, destination_name)?.identity
                != held_source.identity
            || inspect_quarantine_file(&held_source.file)? != held_source.identity
        {
            return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
        }
        Ok(())
    };
    sync_directory_or_revalidate(source_parent, revalidate_renamed)?;
    sync_directory_or_revalidate(destination_parent, || {
        if open_optional_quarantine_file_at(source_parent, source_name)?.is_some()
            || open_quarantine_file_at(destination_parent, destination_name)?.identity
                != held_source.identity
            || inspect_quarantine_file(&held_source.file)? != held_source.identity
        {
            return Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous);
        }
        Ok(())
    })?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn renameat_noreplace(
    old_parent: &File,
    old_name: &CStr,
    new_parent: &File,
    new_name: &CStr,
) -> Result<(), LegacyUploadMigrationApplyError> {
    const RENAME_EXCL: libc::c_uint = 0x0000_0004;
    unsafe extern "C" {
        fn renameatx_np(
            fromfd: libc::c_int,
            from: *const libc::c_char,
            tofd: libc::c_int,
            to: *const libc::c_char,
            flags: libc::c_uint,
        ) -> libc::c_int;
    }
    let result = unsafe {
        renameatx_np(
            old_parent.as_raw_fd(),
            old_name.as_ptr(),
            new_parent.as_raw_fd(),
            new_name.as_ptr(),
            RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(LegacyUploadMigrationApplyError::Quarantine)
    }
}

#[cfg(target_os = "linux")]
fn renameat_noreplace(
    old_parent: &File,
    old_name: &CStr,
    new_parent: &File,
    new_name: &CStr,
) -> Result<(), LegacyUploadMigrationApplyError> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            old_parent.as_raw_fd(),
            old_name.as_ptr(),
            new_parent.as_raw_fd(),
            new_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(LegacyUploadMigrationApplyError::Quarantine)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn renameat_noreplace(
    _old_parent: &File,
    _old_name: &CStr,
    _new_parent: &File,
    _new_name: &CStr,
) -> Result<(), LegacyUploadMigrationApplyError> {
    Err(LegacyUploadMigrationApplyError::Quarantine)
}

fn validate_reference_probe(
    reference: &EvidenceReferenceNormalization,
    path: &Path,
    image_timeout_seconds: u64,
    expected_orientation: Option<u16>,
) -> Result<(), LegacyUploadMigrationApplyError> {
    let probe = crate::monitor::reference_normalization_identity(path, image_timeout_seconds)
        .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
    if expected_orientation.is_some_and(|orientation| probe.orientation != orientation)
        || expected_orientation.is_none()
            && probe.orientation != reference.orientation
            && probe.orientation != 1
        || probe.width != reference.width
        || probe.height != reference.height
        || probe.decoded_pixel_sha256 != reference.decoded_pixel_sha256
    {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    Ok(())
}

fn safe_quarantine_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn open_quarantine_parent_and_name(
    path: &Path,
) -> Result<(File, CString), LegacyUploadMigrationApplyError> {
    if !safe_quarantine_path(path) {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    let components = path.components().collect::<Vec<_>>();
    let final_index = components
        .iter()
        .rposition(|component| matches!(component, Component::Normal(_)))
        .ok_or(LegacyUploadMigrationApplyError::Quarantine)?;
    if final_index != components.len() - 1 {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    let name = match components[final_index] {
        Component::Normal(name) => CString::new(name.as_bytes())
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?,
        _ => return Err(LegacyUploadMigrationApplyError::Quarantine),
    };
    let mut parent = open_quarantine_directory_at(libc::AT_FDCWD, c"/")?;
    for component in &components[1..final_index] {
        let Component::Normal(name) = component else {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        };
        let name = CString::new(name.as_bytes())
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        parent = open_quarantine_directory_at(parent.as_raw_fd(), &name)?;
    }
    Ok((parent, name))
}

fn open_quarantine_directory_at(
    dirfd: libc::c_int,
    name: &CStr,
) -> Result<File, LegacyUploadMigrationApplyError> {
    let fd = unsafe {
        libc::openat(
            dirfd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(LegacyUploadMigrationApplyError::Quarantine)
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn open_optional_quarantine_directory_at(
    dirfd: libc::c_int,
    name: &CStr,
) -> Result<Option<File>, LegacyUploadMigrationApplyError> {
    let fd = unsafe {
        libc::openat(
            dirfd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        return Ok(Some(unsafe { File::from_raw_fd(fd) }));
    }
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        Ok(None)
    } else {
        Err(LegacyUploadMigrationApplyError::Quarantine)
    }
}

fn validate_quarantine_directory(
    directory: &File,
) -> Result<fs::Metadata, LegacyUploadMigrationApplyError> {
    let metadata = directory
        .metadata()
        .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    Ok(metadata)
}

pub(super) fn quarantine_directory_identity(
    directory: &File,
) -> Result<QuarantineDirectoryIdentity, LegacyUploadMigrationApplyError> {
    let metadata = validate_quarantine_directory(directory)?;
    Ok(QuarantineDirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode() & 0o777,
        link_count: metadata.nlink(),
    })
}

fn quarantine_directory_is_empty(
    directory: &File,
) -> Result<bool, LegacyUploadMigrationApplyError> {
    let independent = open_quarantine_directory_at(directory.as_raw_fd(), c".")?;
    let descriptor = independent.as_raw_fd();
    // SAFETY: independent owns a valid directory descriptor. fdopendir takes ownership of the
    // descriptor on success, so forget prevents File from closing it a second time.
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    std::mem::forget(independent);
    let mut empty = true;
    let mut read_failed = false;
    loop {
        set_directory_read_errno(0);
        // SAFETY: stream remains live until closed below.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            read_failed = directory_read_errno() != 0;
            break;
        }
        // SAFETY: d_name is a NUL-terminated array owned by the live directory stream.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            empty = false;
            break;
        }
    }
    // SAFETY: stream was returned by fdopendir and has not been closed.
    if unsafe { libc::closedir(stream) } != 0 || read_failed {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    Ok(empty)
}

#[cfg(target_os = "macos")]
fn set_directory_read_errno(value: libc::c_int) {
    // SAFETY: __error returns the current thread's errno pointer on macOS.
    unsafe { *libc::__error() = value };
}

#[cfg(target_os = "macos")]
fn directory_read_errno() -> libc::c_int {
    // SAFETY: __error returns the current thread's errno pointer on macOS.
    unsafe { *libc::__error() }
}

#[cfg(target_os = "linux")]
fn set_directory_read_errno(value: libc::c_int) {
    // SAFETY: __errno_location returns the current thread's errno pointer on Linux.
    unsafe { *libc::__errno_location() = value };
}

#[cfg(target_os = "linux")]
fn directory_read_errno() -> libc::c_int {
    // SAFETY: __errno_location returns the current thread's errno pointer on Linux.
    unsafe { *libc::__errno_location() }
}

fn open_named_quarantine_directory_identity(
    path: &Path,
) -> Result<QuarantineDirectoryIdentity, LegacyUploadMigrationApplyError> {
    if fs::canonicalize(path).map_err(|_| LegacyUploadMigrationApplyError::Quarantine)? != path {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    let (parent, name) = open_quarantine_parent_and_name(path)?;
    let directory = open_quarantine_directory_at(parent.as_raw_fd(), &name)?;
    quarantine_directory_identity(&directory)
}

fn open_optional_anchored_quarantine_file(
    path: &Path,
) -> Result<Option<AnchoredQuarantineFile>, LegacyUploadMigrationApplyError> {
    let (parent, name) = open_quarantine_parent_and_name(path)?;
    let Some(file) = open_optional_quarantine_file_at(&parent, &name)? else {
        return Ok(None);
    };
    Ok(Some(AnchoredQuarantineFile {
        parent,
        name,
        file: file.file,
        identity: file.identity,
    }))
}

fn open_optional_quarantine_file_at(
    parent: &File,
    name: &CStr,
) -> Result<Option<AnchoredQuarantineFile>, LegacyUploadMigrationApplyError> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(LegacyUploadMigrationApplyError::Quarantine)
        };
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let identity = inspect_quarantine_file(&file)?;
    Ok(Some(AnchoredQuarantineFile {
        parent: parent
            .try_clone()
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?,
        name: name.to_owned(),
        file,
        identity,
    }))
}

fn open_quarantine_file_at(
    parent: &File,
    name: &CStr,
) -> Result<AnchoredQuarantineFile, LegacyUploadMigrationApplyError> {
    open_optional_quarantine_file_at(parent, name)?
        .ok_or(LegacyUploadMigrationApplyError::Quarantine)
}

fn inspect_quarantine_file(
    file: &File,
) -> Result<QuarantineFileIdentity, LegacyUploadMigrationApplyError> {
    let metadata = file
        .metadata()
        .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    let mut clone = file
        .try_clone()
        .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
    clone
        .seek(SeekFrom::Start(0))
        .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = clone
            .read(&mut buffer)
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(QuarantineFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode: metadata.mode() & 0o777,
        link_count: metadata.nlink(),
        size_bytes: metadata.len(),
        modified_unix_seconds: metadata.mtime(),
        modified_unix_nanoseconds: metadata.mtime_nsec(),
        sha256: format!("{:x}", hasher.finalize()),
    })
}

fn revalidate_anchored_files(
    files: &[AnchoredQuarantineFile],
) -> Result<(), LegacyUploadMigrationApplyError> {
    for held in files {
        if inspect_quarantine_file(&held.file)? != held.identity
            || open_quarantine_file_at(&held.parent, &held.name)?.identity != held.identity
        {
            return Err(LegacyUploadMigrationApplyError::Quarantine);
        }
    }
    Ok(())
}

fn exact_confirmed_delete<'a>(
    replacement: &EvidenceRetiredReplacement,
    lookup: &'a CloudKitDeleteStateLookupResult,
) -> Option<&'a CloudKitDeleteOutcome> {
    if !lookup.unconfirmed.is_empty() || lookup.confirmed_deleted.len() != 1 {
        return None;
    }
    let outcome = &lookup.confirmed_deleted[0];
    (outcome.record_name == replacement.uploaded_asset_id
        && !outcome.record_change_tag.trim().is_empty()
        && outcome.record_change_tag != replacement.old_record_change_tag)
        .then_some(outcome)
}

fn require_exact_resolved(
    replacement: &EvidenceRetiredReplacement,
    resolved: &CloudKitUploadedHeicAsset,
) -> Result<(), LegacyUploadMigrationApplyError> {
    if resolved.record_name != replacement.uploaded_asset_id
        || resolved.master_record_name != replacement.uploaded_master_id
        || resolved.record_change_tag != replacement.old_record_change_tag
        || resolved.owner_record_name_sha256 != replacement.owner_record_name_sha256
        || resolved.initial_remote_state != replacement.initial_remote_state
        || resolved.initial_state_lookup_mode != replacement.initial_state_lookup_mode
        || resolved.matched_heic_sha256 != replacement.uploaded_heic_sha256
        || resolved.size_bytes != replacement.uploaded_heic_size_bytes
    {
        return Err(LegacyUploadMigrationApplyError::Remote);
    }
    Ok(())
}

fn require_exact_recovered_delete(
    replacement: &EvidenceRetiredReplacement,
    resolved: &CloudKitUploadedHeicAsset,
) -> Result<(), LegacyUploadMigrationApplyError> {
    if resolved.record_name != replacement.uploaded_asset_id
        || resolved.master_record_name != replacement.uploaded_master_id
        || resolved.record_change_tag.trim().is_empty()
        || resolved.record_change_tag == replacement.old_record_change_tag
        || resolved.owner_record_name_sha256 != replacement.owner_record_name_sha256
        || resolved.initial_remote_state != CloudKitUploadedHeicInitialState::AlreadyDeleted
        || resolved.initial_state_lookup_mode != replacement.initial_state_lookup_mode
        || resolved.matched_heic_sha256 != replacement.uploaded_heic_sha256
        || resolved.size_bytes != replacement.uploaded_heic_size_bytes
    {
        return Err(LegacyUploadMigrationApplyError::Remote);
    }
    Ok(())
}

fn require_exact_delete_outcome(
    replacement: &EvidenceRetiredReplacement,
    outcome: &CloudKitDeleteOutcome,
) -> Result<(), LegacyUploadMigrationApplyError> {
    if outcome.record_name != replacement.uploaded_asset_id
        || outcome.record_change_tag.trim().is_empty()
        || outcome.record_change_tag == replacement.old_record_change_tag
    {
        return Err(LegacyUploadMigrationApplyError::Remote);
    }
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code, reason = "test adapter entry point"))]
pub(super) fn ensure_prepared(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
) -> Result<LegacyUploadMigrationPreparationOutcome, LegacyUploadMigrationApplyError> {
    ensure_prepared_with_pre_commit(state_store, evidence, &mut || Ok(()))
}

pub(super) fn ensure_prepared_with_quarantine_guard(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
    guard: &QuarantinePreflightGuard,
) -> Result<LegacyUploadMigrationPreparationOutcome, LegacyUploadMigrationApplyError> {
    ensure_prepared_with_pre_commit(state_store, evidence, &mut || guard.revalidate())
}

fn ensure_prepared_with_pre_commit(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
    before_commit: &mut impl FnMut() -> Result<(), LegacyUploadMigrationApplyError>,
) -> Result<LegacyUploadMigrationPreparationOutcome, LegacyUploadMigrationApplyError> {
    let manifest = state_store
        .load_or_import()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    evidence
        .revalidate_authoritative_manifest(&manifest)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    let ids = evidence.replacement_asset_ids().map(str::to_owned);
    let current = [
        manifest
            .get(&ids[0])
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
        manifest
            .get(&ids[1])
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
    ];
    let phases = current.each_ref().map(|record| {
        validate_legacy_upload_migration_record(record)
            .ok()
            .and_then(|journal| journal.entries.last().map(|entry| entry.phase))
    });

    let changed = match phases {
        [None, None] => {
            let updated = [
                prepare_legacy_upload_migration_record(
                    &current[0],
                    evidence.preparation_authority(),
                )
                .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
                prepare_legacy_upload_migration_record(
                    &current[1],
                    evidence.preparation_authority(),
                )
                .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
            ];
            before_commit()?;
            persist_two_legacy_upload_migration_preparations_exact_cas(
                state_store,
                evidence.preparation_authority(),
                [
                    LegacyUploadMigrationCasUpdate {
                        expected: &current[0],
                        updated: &updated[0],
                    },
                    LegacyUploadMigrationCasUpdate {
                        expected: &current[1],
                        updated: &updated[1],
                    },
                ],
            )
            .map_err(|_| LegacyUploadMigrationApplyError::State)?;
            true
        }
        [Some(left), Some(right)] if left == right => false,
        _ => return Err(LegacyUploadMigrationApplyError::Cohort),
    };

    let authoritative = state_store
        .load()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    evidence
        .revalidate_authoritative_manifest(&authoritative)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    let checkpoint_stale = state_store
        .json_checkpoint_status_for_manifest(&authoritative)
        .map_err(|_| LegacyUploadMigrationApplyError::State)?
        == JsonCheckpointStatus::Stale;
    if checkpoint_stale {
        state_store
            .export_json()
            .map_err(|_| LegacyUploadMigrationApplyError::CheckpointStale)?;
    }
    evidence.revalidate_held_evidence().map_err(|error| {
        LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        }
    })?;
    Ok(LegacyUploadMigrationPreparationOutcome {
        changed,
        checkpoint_exported: checkpoint_stale,
        retired_replacement_delete_calls: 0,
    })
}

#[cfg_attr(not(test), allow(dead_code, reason = "test adapter entry point"))]
pub(super) fn ensure_delete_confirmed<T: RetiredReplacementDeleteAdapter>(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
    adapter: &mut T,
) -> Result<LegacyUploadMigrationPreparationOutcome, LegacyUploadMigrationApplyError> {
    ensure_delete_confirmed_with_pre_delete(state_store, evidence, adapter, &mut || Ok(()))
}

pub(super) fn ensure_delete_confirmed_with_quarantine_guard<T: RetiredReplacementDeleteAdapter>(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
    adapter: &mut T,
    guard: &QuarantinePreflightGuard,
) -> Result<LegacyUploadMigrationPreparationOutcome, LegacyUploadMigrationApplyError> {
    ensure_delete_confirmed_with_pre_delete(state_store, evidence, adapter, &mut || {
        guard.revalidate()
    })
}

pub(super) fn ensure_delete_confirmed_with_pre_delete<T: RetiredReplacementDeleteAdapter>(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
    adapter: &mut T,
    before_delete: &mut impl FnMut() -> Result<(), LegacyUploadMigrationApplyError>,
) -> Result<LegacyUploadMigrationPreparationOutcome, LegacyUploadMigrationApplyError> {
    let manifest = state_store
        .load()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    evidence
        .revalidate_authoritative_manifest(&manifest)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    let ids = evidence.replacement_asset_ids().map(str::to_owned);
    let current = [
        manifest
            .get(&ids[0])
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
        manifest
            .get(&ids[1])
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
    ];
    let phases = current.each_ref().map(|record| {
        validate_legacy_upload_migration_record(record)
            .ok()
            .and_then(|journal| journal.entries.last().map(|entry| entry.phase))
    });

    let mut delete_calls = 0_u64;
    let changed = match phases {
        [
            Some(LegacyUploadMigrationPhase::Prepared),
            Some(LegacyUploadMigrationPhase::Prepared),
        ] => {
            let confirmation =
                confirm_retired_replacement_deletes_with_stats(evidence, adapter, before_delete)?;
            delete_calls = confirmation.delete_calls;
            let outcomes = confirmation.outcomes;
            let authoritative = state_store
                .load()
                .map_err(|_| LegacyUploadMigrationApplyError::State)?;
            evidence
                .revalidate_authoritative_manifest(&authoritative)
                .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
                    category: error.category(),
                })?;
            let expected = [
                authoritative
                    .get(&ids[0])
                    .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
                    .clone(),
                authoritative
                    .get(&ids[1])
                    .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
                    .clone(),
            ];
            if expected.each_ref().map(|record| {
                validate_legacy_upload_migration_record(record)
                    .ok()
                    .and_then(|journal| journal.entries.last().map(|entry| entry.phase))
            }) != [Some(LegacyUploadMigrationPhase::Prepared); 2]
            {
                return Err(LegacyUploadMigrationApplyError::Cohort);
            }
            let replacements = evidence.retired_replacements();
            let receipts = [
                delete_confirmed_receipt(&replacements[0], &outcomes[0])?,
                delete_confirmed_receipt(&replacements[1], &outcomes[1])?,
            ];
            evidence.revalidate_held_evidence().map_err(|error| {
                LegacyUploadMigrationApplyError::Evidence {
                    category: error.category(),
                }
            })?;
            let (authority, updated) = build_legacy_upload_migration_phase_authority(
                [&expected[0], &expected[1]],
                [&expected[0], &expected[1]],
                LegacyUploadMigrationPhase::DeleteConfirmed,
                [&receipts[0], &receipts[1]],
            )
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
            persist_two_legacy_upload_migration_records_exact_cas(
                state_store,
                &authority,
                [
                    LegacyUploadMigrationCasUpdate {
                        expected: &expected[0],
                        updated: &updated[0],
                    },
                    LegacyUploadMigrationCasUpdate {
                        expected: &expected[1],
                        updated: &updated[1],
                    },
                ],
            )
            .map_err(|_| LegacyUploadMigrationApplyError::State)?;
            true
        }
        [Some(left), Some(right)]
            if left == right
                && left.index() >= LegacyUploadMigrationPhase::DeleteConfirmed.index() =>
        {
            false
        }
        _ => return Err(LegacyUploadMigrationApplyError::Cohort),
    };

    let authoritative = state_store
        .load()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    evidence
        .revalidate_authoritative_manifest(&authoritative)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    let checkpoint_stale = state_store
        .json_checkpoint_status_for_manifest(&authoritative)
        .map_err(|_| LegacyUploadMigrationApplyError::State)?
        == JsonCheckpointStatus::Stale;
    if checkpoint_stale {
        state_store
            .export_json()
            .map_err(|_| LegacyUploadMigrationApplyError::CheckpointStale)?;
    }
    evidence.revalidate_held_evidence().map_err(|error| {
        LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        }
    })?;
    Ok(LegacyUploadMigrationPreparationOutcome {
        changed,
        checkpoint_exported: checkpoint_stale,
        retired_replacement_delete_calls: delete_calls,
    })
}

pub(super) fn ensure_quarantined<T: LegacyArtifactQuarantineAdapter>(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
    adapter: &mut T,
) -> Result<LegacyUploadMigrationPreparationOutcome, LegacyUploadMigrationApplyError> {
    let manifest = state_store
        .load()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    evidence
        .revalidate_authoritative_manifest(&manifest)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    let ids = evidence.replacement_asset_ids().map(str::to_owned);
    let current = [
        manifest
            .get(&ids[0])
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
        manifest
            .get(&ids[1])
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
    ];
    let phases = current.each_ref().map(|record| {
        validate_legacy_upload_migration_record(record)
            .ok()
            .and_then(|journal| journal.entries.last().map(|entry| entry.phase))
    });
    if !matches!(
        phases,
        [
            Some(LegacyUploadMigrationPhase::DeleteConfirmed),
            Some(LegacyUploadMigrationPhase::DeleteConfirmed)
        ] | [
            Some(LegacyUploadMigrationPhase::Quarantined),
            Some(LegacyUploadMigrationPhase::Quarantined)
        ]
    ) {
        return Err(LegacyUploadMigrationApplyError::Cohort);
    }
    if phases == [Some(LegacyUploadMigrationPhase::DeleteConfirmed); 2] {
        evidence
            .revalidate_reference_descriptors_before_quarantine()
            .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
                category: error.category(),
            })?;
    }
    let receipt = adapter
        .quarantine_and_normalize(evidence, &manifest)
        .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
    let expected_roots_sha256 = canonical_digest(&evidence.quarantine_plan().roots)
        .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
    if receipt.schema_version != 2
        || receipt.cohort_sha256 != evidence.audit().cohort_sha256
        || receipt.target_count != 9
        || receipt.normalized_reference_count != 5
        || receipt.canonical_root_identity_sha256 != expected_roots_sha256
        || !valid_sha256(&receipt.target_set_sha256)
    {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }

    let changed = if phases == [Some(LegacyUploadMigrationPhase::DeleteConfirmed); 2] {
        evidence.revalidate_held_evidence().map_err(|error| {
            LegacyUploadMigrationApplyError::Evidence {
                category: error.category(),
            }
        })?;
        let authoritative = state_store
            .load()
            .map_err(|_| LegacyUploadMigrationApplyError::State)?;
        evidence
            .revalidate_authoritative_manifest(&authoritative)
            .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
                category: error.category(),
            })?;
        let expected = [
            authoritative
                .get(&ids[0])
                .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
                .clone(),
            authoritative
                .get(&ids[1])
                .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
                .clone(),
        ];
        if expected.each_ref().map(|record| {
            validate_legacy_upload_migration_record(record)
                .ok()
                .and_then(|journal| journal.entries.last().map(|entry| entry.phase))
        }) != [Some(LegacyUploadMigrationPhase::DeleteConfirmed); 2]
        {
            return Err(LegacyUploadMigrationApplyError::Cohort);
        }
        let (authority, updated) = build_legacy_upload_migration_phase_authority(
            [&expected[0], &expected[1]],
            [&expected[0], &expected[1]],
            LegacyUploadMigrationPhase::Quarantined,
            [&receipt, &receipt],
        )
        .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
        persist_two_legacy_upload_migration_records_exact_cas(
            state_store,
            &authority,
            [
                LegacyUploadMigrationCasUpdate {
                    expected: &expected[0],
                    updated: &updated[0],
                },
                LegacyUploadMigrationCasUpdate {
                    expected: &expected[1],
                    updated: &updated[1],
                },
            ],
        )
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
        true
    } else {
        false
    };

    let authoritative = state_store
        .load()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    evidence
        .revalidate_authoritative_manifest(&authoritative)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    let checkpoint_stale = state_store
        .json_checkpoint_status_for_manifest(&authoritative)
        .map_err(|_| LegacyUploadMigrationApplyError::State)?
        == JsonCheckpointStatus::Stale;
    if checkpoint_stale {
        state_store
            .export_json()
            .map_err(|_| LegacyUploadMigrationApplyError::CheckpointStale)?;
    }
    Ok(LegacyUploadMigrationPreparationOutcome {
        changed,
        checkpoint_exported: checkpoint_stale,
        retired_replacement_delete_calls: 0,
    })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn ensure_reset(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
) -> Result<LegacyUploadMigrationPreparationOutcome, LegacyUploadMigrationApplyError> {
    let manifest = state_store
        .load()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    evidence
        .revalidate_authoritative_manifest(&manifest)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    let ids = evidence.replacement_asset_ids().map(str::to_owned);
    let expected = [
        manifest
            .get(&ids[0])
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
        manifest
            .get(&ids[1])
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
    ];
    let phases = expected.each_ref().map(|record| {
        validate_legacy_upload_migration_record(record)
            .ok()
            .and_then(|journal| journal.entries.last().map(|entry| entry.phase))
    });

    let changed = match phases {
        [
            Some(LegacyUploadMigrationPhase::Quarantined),
            Some(LegacyUploadMigrationPhase::Quarantined),
        ] => {
            let mut candidates = expected.clone();
            let replacements = evidence.retired_replacements();
            let mut receipts = Vec::with_capacity(2);
            for index in 0..2 {
                let removed = [
                    CONVERSION_PROOF,
                    CONVERSION_PERFORMANCE_PROOF,
                    HEIC_PROOF,
                    UPLOAD_PROOF,
                    ICLOUDPD_LOCAL_MIRROR_PROOF,
                ]
                .map(|name| {
                    expected[index]
                        .proofs
                        .get(name)
                        .map(|value| (name, value))
                        .ok_or(LegacyUploadMigrationApplyError::Cohort)
                });
                let [conversion, performance, heic, upload, mirror] = removed;
                let removed = [conversion?, performance?, heic?, upload?, mirror?];
                let delete_confirmation_entry_sha256 =
                    validate_legacy_upload_migration_record(&expected[index])
                        .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
                        .entries
                        .into_iter()
                        .find(|entry| entry.phase == LegacyUploadMigrationPhase::DeleteConfirmed)
                        .map(|entry| entry.entry_sha256)
                        .ok_or(LegacyUploadMigrationApplyError::Cohort)?;
                receipts.push(ResetReceipt {
                    schema_version: 1,
                    asset_id: expected[index].asset_id.clone(),
                    removed_proofs_sha256: canonical_digest(&removed)
                        .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
                    retained_original_identity_sha256: replacements[index]
                        .original_asset_identity_sha256
                        .clone(),
                    retained_delete_confirmation_entry_sha256: delete_confirmation_entry_sha256,
                });
                candidates[index].state = State::NasVerified;
                for name in [
                    CONVERSION_PROOF,
                    CONVERSION_PERFORMANCE_PROOF,
                    HEIC_PROOF,
                    UPLOAD_PROOF,
                    ICLOUDPD_LOCAL_MIRROR_PROOF,
                ] {
                    candidates[index].proofs.remove(name);
                }
            }
            evidence.revalidate_held_evidence().map_err(|error| {
                LegacyUploadMigrationApplyError::Evidence {
                    category: error.category(),
                }
            })?;
            let (authority, updated) = build_legacy_upload_migration_phase_authority(
                [&expected[0], &expected[1]],
                [&candidates[0], &candidates[1]],
                LegacyUploadMigrationPhase::Reset,
                [&receipts[0], &receipts[1]],
            )
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
            persist_two_legacy_upload_migration_records_exact_cas(
                state_store,
                &authority,
                [
                    LegacyUploadMigrationCasUpdate {
                        expected: &expected[0],
                        updated: &updated[0],
                    },
                    LegacyUploadMigrationCasUpdate {
                        expected: &expected[1],
                        updated: &updated[1],
                    },
                ],
            )
            .map_err(|_| LegacyUploadMigrationApplyError::State)?;
            true
        }
        [Some(left), Some(right)]
            if left == right && left.index() >= LegacyUploadMigrationPhase::Reset.index() =>
        {
            false
        }
        _ => return Err(LegacyUploadMigrationApplyError::Cohort),
    };

    let authoritative = state_store
        .load()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    evidence
        .revalidate_authoritative_manifest(&authoritative)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    let checkpoint_stale = state_store
        .json_checkpoint_status_for_manifest(&authoritative)
        .map_err(|_| LegacyUploadMigrationApplyError::State)?
        == JsonCheckpointStatus::Stale;
    if checkpoint_stale {
        state_store
            .export_json()
            .map_err(|_| LegacyUploadMigrationApplyError::CheckpointStale)?;
    }
    evidence.revalidate_held_evidence().map_err(|error| {
        LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        }
    })?;
    Ok(LegacyUploadMigrationPreparationOutcome {
        changed,
        checkpoint_exported: checkpoint_stale,
        retired_replacement_delete_calls: 0,
    })
}

pub(super) fn ensure_converted<T: LegacyConversionAdapter>(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
    heic_output_dir: &Path,
    adapter: &mut T,
) -> Result<LegacyUploadMigrationPreparationOutcome, LegacyUploadMigrationApplyError> {
    let manifest = state_store
        .load()
        .map_err(|_| state_stage(LegacyUploadMigrationStateStage::EnsureConvertedInitialLoad))?;
    evidence
        .revalidate_authoritative_manifest(&manifest)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    let replacements = evidence.retired_replacements();
    let output_paths = [
        migration_output_path(heic_output_dir, &replacements[0].destination.filename)?,
        migration_output_path(heic_output_dir, &replacements[1].destination.filename)?,
    ];
    let expected = [
        manifest
            .get(&replacements[0].asset_id)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
        manifest
            .get(&replacements[1].asset_id)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
    ];
    let phases = expected.each_ref().map(|record| {
        validate_legacy_upload_migration_record(record)
            .ok()
            .and_then(|journal| journal.entries.last().map(|entry| entry.phase))
    });
    let changed = match phases {
        [
            Some(LegacyUploadMigrationPhase::Reset),
            Some(LegacyUploadMigrationPhase::Reset),
        ] => {
            let candidates = adapter
                .convert_and_verify(
                    [&expected[0], &expected[1]],
                    [&output_paths[0], &output_paths[1]],
                )
                .map_err(T::into_apply_error)?;
            let receipts = [
                converted_receipt(&candidates[0], &output_paths[0])?,
                converted_receipt(&candidates[1], &output_paths[1])?,
            ];
            evidence.revalidate_held_evidence().map_err(|error| {
                LegacyUploadMigrationApplyError::Evidence {
                    category: error.category(),
                }
            })?;
            let authoritative = state_store.load().map_err(|_| {
                state_stage(LegacyUploadMigrationStateStage::EnsureConvertedPostLoad)
            })?;
            evidence
                .revalidate_authoritative_manifest(&authoritative)
                .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
                    category: error.category(),
                })?;
            for record in &expected {
                if authoritative
                    .get(&record.asset_id)
                    .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
                    != record
                {
                    return Err(LegacyUploadMigrationApplyError::Cohort);
                }
            }
            let (authority, updated) = build_legacy_upload_migration_phase_authority(
                [&expected[0], &expected[1]],
                [&candidates[0], &candidates[1]],
                LegacyUploadMigrationPhase::Converted,
                [&receipts[0], &receipts[1]],
            )
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
            persist_two_legacy_upload_migration_records_exact_cas(
                state_store,
                &authority,
                [
                    LegacyUploadMigrationCasUpdate {
                        expected: &expected[0],
                        updated: &updated[0],
                    },
                    LegacyUploadMigrationCasUpdate {
                        expected: &expected[1],
                        updated: &updated[1],
                    },
                ],
            )
            .map_err(|_| state_stage(LegacyUploadMigrationStateStage::EnsureConvertedPersist))?;
            true
        }
        [Some(left), Some(right)]
            if left == right && left.index() >= LegacyUploadMigrationPhase::Converted.index() =>
        {
            converted_receipt(&expected[0], &output_paths[0])?;
            converted_receipt(&expected[1], &output_paths[1])?;
            false
        }
        _ => return Err(LegacyUploadMigrationApplyError::Cohort),
    };
    finish_phase_checkpoint_at(
        state_store,
        evidence,
        changed,
        LegacyUploadMigrationStateStage::EnsureConvertedCheckpoint,
    )
}

pub(super) fn ensure_upload_prepared(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
    heic_output_dir: &Path,
) -> Result<LegacyUploadMigrationPreparationOutcome, LegacyUploadMigrationApplyError> {
    let manifest = state_store
        .load()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    evidence
        .revalidate_authoritative_manifest(&manifest)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    let replacements = evidence.retired_replacements();
    let output_paths = [
        migration_output_path(heic_output_dir, &replacements[0].destination.filename)?,
        migration_output_path(heic_output_dir, &replacements[1].destination.filename)?,
    ];
    let expected = [
        manifest
            .get(&replacements[0].asset_id)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
        manifest
            .get(&replacements[1].asset_id)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
    ];
    let phases = expected.each_ref().map(|record| {
        validate_legacy_upload_migration_record(record)
            .ok()
            .and_then(|journal| journal.entries.last().map(|entry| entry.phase))
    });
    let receipts = [
        upload_prepared_receipt(
            &expected[0],
            &output_paths[0],
            replacements[0].destination_sha256.clone(),
        )?,
        upload_prepared_receipt(
            &expected[1],
            &output_paths[1],
            replacements[1].destination_sha256.clone(),
        )?,
    ];
    let changed = match phases {
        [
            Some(LegacyUploadMigrationPhase::Converted),
            Some(LegacyUploadMigrationPhase::Converted),
        ] => {
            evidence.revalidate_held_evidence().map_err(|error| {
                LegacyUploadMigrationApplyError::Evidence {
                    category: error.category(),
                }
            })?;
            let (authority, updated) = build_legacy_upload_migration_phase_authority(
                [&expected[0], &expected[1]],
                [&expected[0], &expected[1]],
                LegacyUploadMigrationPhase::UploadPrepared,
                [&receipts[0], &receipts[1]],
            )
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
            persist_two_legacy_upload_migration_records_exact_cas(
                state_store,
                &authority,
                [
                    LegacyUploadMigrationCasUpdate {
                        expected: &expected[0],
                        updated: &updated[0],
                    },
                    LegacyUploadMigrationCasUpdate {
                        expected: &expected[1],
                        updated: &updated[1],
                    },
                ],
            )
            .map_err(|_| LegacyUploadMigrationApplyError::State)?;
            true
        }
        [Some(left), Some(right)]
            if left == right
                && left.index() >= LegacyUploadMigrationPhase::UploadPrepared.index() =>
        {
            false
        }
        _ => return Err(LegacyUploadMigrationApplyError::Cohort),
    };
    finish_phase_checkpoint(state_store, evidence, changed)
}

pub(super) fn ensure_upload_verified<T: LegacyUploadAdapter>(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
    adapter: &mut T,
) -> Result<LegacyUploadMigrationPreparationOutcome, LegacyUploadMigrationApplyError> {
    let manifest = state_store
        .load()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    evidence
        .revalidate_authoritative_manifest(&manifest)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    let replacements = evidence.retired_replacements();
    let expected = [
        manifest
            .get(&replacements[0].asset_id)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
        manifest
            .get(&replacements[1].asset_id)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
    ];
    let phases = expected.each_ref().map(|record| {
        validate_legacy_upload_migration_record(record)
            .ok()
            .and_then(|journal| journal.entries.last().map(|entry| entry.phase))
    });
    if let [Some(left), Some(right)] = phases
        && left == right
        && left.index() > LegacyUploadMigrationPhase::UploadVerified.index()
    {
        return finish_phase_checkpoint(state_store, evidence, false);
    }
    let (changed, candidates, remote) = match phases {
        [
            Some(LegacyUploadMigrationPhase::UploadPrepared),
            Some(LegacyUploadMigrationPhase::UploadPrepared),
        ] => {
            let sources =
                validate_upload_prepared_witness([&expected[0], &expected[1]], replacements)?;
            let uploaded = adapter
                .upload_or_reconcile(
                    [&expected[0], &expected[1]],
                    replacements,
                    [&sources[0], &sources[1]],
                )
                .map_err(T::into_apply_error)?;
            revalidate_upload_prepared_sources(
                [&expected[0], &expected[1]],
                [&sources[0], &sources[1]],
            )?;
            (
                true,
                [uploaded[0].candidate.clone(), uploaded[1].candidate.clone()],
                [uploaded[0].receipt.clone(), uploaded[1].receipt.clone()],
            )
        }
        [
            Some(LegacyUploadMigrationPhase::UploadVerified),
            Some(LegacyUploadMigrationPhase::UploadVerified),
        ] => {
            let remote = adapter
                .verify_existing([&expected[0], &expected[1]], replacements)
                .map_err(T::into_apply_error)?;
            (false, expected.clone(), remote)
        }
        _ => return Err(LegacyUploadMigrationApplyError::Cohort),
    };
    let receipts = [
        upload_verified_phase_receipt(&candidates[0], &remote[0])?,
        upload_verified_phase_receipt(&candidates[1], &remote[1])?,
    ];
    if changed {
        evidence.revalidate_held_evidence().map_err(|error| {
            LegacyUploadMigrationApplyError::Evidence {
                category: error.category(),
            }
        })?;
        let authoritative = state_store
            .load()
            .map_err(|_| LegacyUploadMigrationApplyError::State)?;
        for record in &expected {
            if authoritative
                .get(&record.asset_id)
                .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
                != record
            {
                return Err(LegacyUploadMigrationApplyError::Cohort);
            }
        }
        let (authority, updated) = build_legacy_upload_migration_phase_authority(
            [&expected[0], &expected[1]],
            [&candidates[0], &candidates[1]],
            LegacyUploadMigrationPhase::UploadVerified,
            [&receipts[0], &receipts[1]],
        )
        .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
        persist_two_legacy_upload_migration_records_exact_cas(
            state_store,
            &authority,
            [
                LegacyUploadMigrationCasUpdate {
                    expected: &expected[0],
                    updated: &updated[0],
                },
                LegacyUploadMigrationCasUpdate {
                    expected: &expected[1],
                    updated: &updated[1],
                },
            ],
        )
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    }
    finish_phase_checkpoint(state_store, evidence, changed)
}

pub(super) fn ensure_mirrored<T: LegacyMirrorAdapter>(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
    mirror_root: &Path,
    adapter: &mut T,
) -> Result<LegacyUploadMigrationPreparationOutcome, LegacyUploadMigrationApplyError> {
    let manifest = state_store
        .load()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    evidence
        .revalidate_authoritative_manifest(&manifest)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    let replacements = evidence.retired_replacements();
    let mirror_paths = [
        migration_output_path(mirror_root, &replacements[0].destination.filename)?,
        migration_output_path(mirror_root, &replacements[1].destination.filename)?,
    ];
    let expected = [
        manifest
            .get(&replacements[0].asset_id)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
        manifest
            .get(&replacements[1].asset_id)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
    ];
    let phases = expected.each_ref().map(|record| {
        validate_legacy_upload_migration_record(record)
            .ok()
            .and_then(|journal| journal.entries.last().map(|entry| entry.phase))
    });
    if let [Some(left), Some(right)] = phases
        && left == right
        && left.index() > LegacyUploadMigrationPhase::Mirrored.index()
    {
        return finish_phase_checkpoint(state_store, evidence, false);
    }
    let (changed, candidates) = match phases {
        [
            Some(LegacyUploadMigrationPhase::UploadVerified),
            Some(LegacyUploadMigrationPhase::UploadVerified),
        ] => {
            let candidates = adapter
                .mirror_or_reconcile(
                    [&expected[0], &expected[1]],
                    [&mirror_paths[0], &mirror_paths[1]],
                )
                .map_err(|_| LegacyUploadMigrationApplyError::State)?;
            (true, candidates)
        }
        [
            Some(LegacyUploadMigrationPhase::Mirrored),
            Some(LegacyUploadMigrationPhase::Mirrored),
        ] => (false, expected.clone()),
        _ => return Err(LegacyUploadMigrationApplyError::Cohort),
    };
    let receipts = [
        mirrored_receipt(&candidates[0], &mirror_paths[0])?,
        mirrored_receipt(&candidates[1], &mirror_paths[1])?,
    ];
    if changed {
        evidence.revalidate_held_evidence().map_err(|error| {
            LegacyUploadMigrationApplyError::Evidence {
                category: error.category(),
            }
        })?;
        let authoritative = state_store
            .load()
            .map_err(|_| LegacyUploadMigrationApplyError::State)?;
        for record in &expected {
            if authoritative
                .get(&record.asset_id)
                .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
                != record
            {
                return Err(LegacyUploadMigrationApplyError::Cohort);
            }
        }
        let (authority, updated) = build_legacy_upload_migration_phase_authority(
            [&expected[0], &expected[1]],
            [&candidates[0], &candidates[1]],
            LegacyUploadMigrationPhase::Mirrored,
            [&receipts[0], &receipts[1]],
        )
        .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
        persist_two_legacy_upload_migration_records_exact_cas(
            state_store,
            &authority,
            [
                LegacyUploadMigrationCasUpdate {
                    expected: &expected[0],
                    updated: &updated[0],
                },
                LegacyUploadMigrationCasUpdate {
                    expected: &expected[1],
                    updated: &updated[1],
                },
            ],
        )
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    }
    finish_phase_checkpoint(state_store, evidence, changed)
}

fn mirrored_receipt(
    record: &AssetRecord,
    expected_path: &Path,
) -> Result<MirroredReceipt, LegacyUploadMigrationApplyError> {
    let mirror_value = record
        .proofs
        .get(ICLOUDPD_LOCAL_MIRROR_PROOF)
        .ok_or(LegacyUploadMigrationApplyError::Cohort)?;
    let upload_value = record
        .proofs
        .get(UPLOAD_PROOF)
        .ok_or(LegacyUploadMigrationApplyError::Cohort)?;
    let mirror: IcloudpdLocalMirrorProof = serde_json::from_value(mirror_value.clone())
        .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
    let upload: UploadProof = serde_json::from_value(upload_value.clone())
        .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
    let heic: HeicVerificationProof = serde_json::from_value(
        record
            .proofs
            .get(HEIC_PROOF)
            .ok_or(LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
    )
    .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
    if mirror.icloudpd_download_path != expected_path
        || mirror.uploaded_heic_asset_id != upload.uploaded_heic_asset_id
        || mirror.uploaded_heic_sha256 != upload.uploaded_heic_sha256
        || mirror.uploaded_heic_path != upload.uploaded_heic_path.clone().unwrap_or_default()
        || mirror.uploaded_heic_sha256 != heic.heic_sha256
        || mirror.size_bytes != heic.size_bytes
    {
        return Err(LegacyUploadMigrationApplyError::Cohort);
    }
    let destination_identity = open_optional_anchored_quarantine_file(expected_path)?
        .ok_or(LegacyUploadMigrationApplyError::Cohort)?
        .identity;
    if destination_identity.sha256 != mirror.uploaded_heic_sha256
        || destination_identity.size_bytes != mirror.size_bytes
    {
        return Err(LegacyUploadMigrationApplyError::Cohort);
    }
    Ok(MirroredReceipt {
        schema_version: 1,
        asset_id: record.asset_id.clone(),
        mirror_proof_sha256: canonical_digest(mirror_value)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
        upload_proof_sha256: canonical_digest(upload_value)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
        destination_path_sha256: canonical_digest(&expected_path.to_path_buf())
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
        destination_identity,
    })
}

pub(super) fn ensure_complete(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
    heic_output_dir: &Path,
    mirror_root: &Path,
) -> Result<LegacyUploadMigrationPreparationOutcome, LegacyUploadMigrationApplyError> {
    let manifest = state_store
        .load()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    evidence
        .revalidate_authoritative_manifest(&manifest)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    let replacements = evidence.retired_replacements();
    let heic_paths = [
        migration_output_path(heic_output_dir, &replacements[0].destination.filename)?,
        migration_output_path(heic_output_dir, &replacements[1].destination.filename)?,
    ];
    let mirror_paths = [
        migration_output_path(mirror_root, &replacements[0].destination.filename)?,
        migration_output_path(mirror_root, &replacements[1].destination.filename)?,
    ];
    let expected = [
        manifest
            .get(&replacements[0].asset_id)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
        manifest
            .get(&replacements[1].asset_id)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
            .clone(),
    ];
    let phases = expected.each_ref().map(|record| {
        validate_legacy_upload_migration_record(record)
            .ok()
            .and_then(|journal| journal.entries.last().map(|entry| entry.phase))
    });
    match phases {
        [
            Some(LegacyUploadMigrationPhase::Complete),
            Some(LegacyUploadMigrationPhase::Complete),
        ] => finish_complete_replay_read_only(state_store, evidence),
        [
            Some(LegacyUploadMigrationPhase::Mirrored),
            Some(LegacyUploadMigrationPhase::Mirrored),
        ] => {
            let receipts = [
                complete_receipt(
                    &expected[0],
                    &heic_paths[0],
                    &mirror_paths[0],
                    replacements[0].destination_sha256.clone(),
                )?,
                complete_receipt(
                    &expected[1],
                    &heic_paths[1],
                    &mirror_paths[1],
                    replacements[1].destination_sha256.clone(),
                )?,
            ];
            evidence.revalidate_held_evidence().map_err(|error| {
                LegacyUploadMigrationApplyError::Evidence {
                    category: error.category(),
                }
            })?;
            let authoritative = state_store
                .load()
                .map_err(|_| LegacyUploadMigrationApplyError::State)?;
            for record in &expected {
                if authoritative
                    .get(&record.asset_id)
                    .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?
                    != record
                {
                    return Err(LegacyUploadMigrationApplyError::Cohort);
                }
            }
            let (authority, updated) = build_legacy_upload_migration_phase_authority(
                [&expected[0], &expected[1]],
                [&expected[0], &expected[1]],
                LegacyUploadMigrationPhase::Complete,
                [&receipts[0], &receipts[1]],
            )
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
            persist_two_legacy_upload_migration_records_exact_cas(
                state_store,
                &authority,
                [
                    LegacyUploadMigrationCasUpdate {
                        expected: &expected[0],
                        updated: &updated[0],
                    },
                    LegacyUploadMigrationCasUpdate {
                        expected: &expected[1],
                        updated: &updated[1],
                    },
                ],
            )
            .map_err(|_| LegacyUploadMigrationApplyError::State)?;
            finish_phase_checkpoint(state_store, evidence, true)
        }
        _ => Err(LegacyUploadMigrationApplyError::Cohort),
    }
}

fn complete_receipt(
    record: &AssetRecord,
    heic_path: &Path,
    mirror_path: &Path,
    destination_sha256: String,
) -> Result<CompleteReceipt, LegacyUploadMigrationApplyError> {
    let converted = converted_receipt(record, heic_path)?;
    let mirrored = mirrored_receipt(record, mirror_path)?;
    let prior_journal = record
        .proofs
        .get(super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME)
        .ok_or(LegacyUploadMigrationApplyError::Cohort)?;
    let mut operational = record.clone();
    operational
        .proofs
        .remove(super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME);
    Ok(CompleteReceipt {
        schema_version: 1,
        asset_id: record.asset_id.clone(),
        destination_sha256,
        operational_record_sha256: canonical_digest(&operational)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
        prior_journal_sha256: canonical_digest(prior_journal)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
        converted,
        mirrored,
    })
}

fn registry_cohort_phase(
    manifest: &Manifest,
    registry: &LegacyUploadMigrationRegistry,
) -> Result<LegacyUploadMigrationPhase, LegacyUploadMigrationApplyError> {
    let phases = registry.assets.each_ref().map(|asset| {
        let record = manifest
            .get(&asset.asset_id)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
        let journal = validate_legacy_upload_migration_record(record)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
        journal
            .entries
            .last()
            .map(|entry| entry.phase)
            .ok_or(LegacyUploadMigrationApplyError::Cohort)
    });
    let [left, right] = phases;
    let left = left?;
    if left != right? {
        return Err(LegacyUploadMigrationApplyError::Cohort);
    }
    Ok(left)
}

fn unregistered_evidence_mentions_smb(
    request: &LegacyUploadMigrationProductionRequest,
) -> Result<bool, LegacyUploadMigrationApplyError> {
    #[cfg(target_os = "macos")]
    {
        for root in &request.quarantine_roots {
            if SmbMountBinding::discover_for_path(root)
                .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?
                .is_some()
            {
                return Ok(true);
            }
        }
        let evidence = File::open(&request.evidence.evidence_path)
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        let document: Value = crate::strict_json::from_reader(evidence)
            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?;
        let mut pending = vec![&document];
        while let Some(value) = pending.pop() {
            match value {
                Value::String(value)
                    if Path::new(value).is_absolute()
                        && SmbMountBinding::discover_for_path(Path::new(value))
                            .map_err(|_| LegacyUploadMigrationApplyError::Quarantine)?
                            .is_some() =>
                {
                    return Ok(true);
                }
                Value::Array(values) => pending.extend(values),
                Value::Object(values) => pending.extend(values.values()),
                _ => {}
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = request;
    }
    Ok(false)
}

pub(crate) fn apply_legacy_uploaded_heic_migration(
    state_store: &AssetStateStore,
    request: &LegacyUploadMigrationProductionRequest,
) -> Result<LegacyUploadMigrationApplyReport, LegacyUploadMigrationApplyError> {
    apply_legacy_uploaded_heic_migration_with_optional_device_recovery(state_store, request, None)
}

pub(crate) fn apply_legacy_uploaded_heic_migration_with_device_recovery(
    state_store: &AssetStateStore,
    request: &LegacyUploadMigrationProductionRequest,
    recovery: &LegacyUploadDeviceRecoveryRequest,
) -> Result<LegacyUploadMigrationApplyReport, LegacyUploadMigrationApplyError> {
    apply_legacy_uploaded_heic_migration_with_optional_device_recovery(
        state_store,
        request,
        Some(recovery),
    )
}

fn apply_legacy_uploaded_heic_migration_with_optional_device_recovery(
    state_store: &AssetStateStore,
    request: &LegacyUploadMigrationProductionRequest,
    recovery: Option<&LegacyUploadDeviceRecoveryRequest>,
) -> Result<LegacyUploadMigrationApplyReport, LegacyUploadMigrationApplyError> {
    // Bootstrap from the SQLite-authoritative immutable registry. At
    // DeleteConfirmed and every later non-complete phase this proves SMB
    // capability before the evidence loader opens any governed reference.
    let bootstrap_manifest = state_store
        .load()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    let bootstrap_registry = bootstrap_manifest
        .legacy_upload_migration_registry()
        .cloned();
    let bootstrap_phase = bootstrap_registry
        .as_ref()
        .map(|registry| registry_cohort_phase(&bootstrap_manifest, registry))
        .transpose()?;
    if bootstrap_registry.is_none() && unregistered_evidence_mentions_smb(request)? {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    let mut smb_capabilities =
        if bootstrap_phase.is_some_and(|phase| phase != LegacyUploadMigrationPhase::Complete) {
            SmbQuarantineCapabilities::prepare(
                bootstrap_registry
                    .as_ref()
                    .ok_or(LegacyUploadMigrationApplyError::Quarantine)?,
            )?
        } else {
            SmbQuarantineCapabilities::unavailable()
        };

    let mut evidence = match recovery {
        Some(recovery) => load_validated_legacy_uploaded_heic_evidence_with_state_store(
            &request.evidence,
            Some(recovery),
            state_store,
        ),
        None => load_validated_legacy_uploaded_heic_evidence_with_state_store(
            &request.evidence,
            None,
            state_store,
        ),
    }
    .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
        category: error.category(),
    })?;
    let initial_remote_states = evidence.initial_remote_states();
    let mut phase = authoritative_cohort_phase(state_store, &mut evidence)?;
    if phase != bootstrap_phase {
        return Err(LegacyUploadMigrationApplyError::Cohort);
    }
    let configured_roots = request
        .quarantine_roots
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let sealed_roots = evidence
        .quarantine_plan()
        .roots
        .iter()
        .map(|root| root.canonical_path.clone())
        .collect::<BTreeSet<_>>();
    if configured_roots != sealed_roots || configured_roots.len() != request.quarantine_roots.len()
    {
        return Err(LegacyUploadMigrationApplyError::Quarantine);
    }
    if phase != Some(LegacyUploadMigrationPhase::Complete) {
        let authoritative = state_store
            .load()
            .map_err(|_| state_stage(LegacyUploadMigrationStateStage::AuthorityRevalidationLoad))?;
        if bootstrap_registry.is_some() {
            smb_capabilities.revalidate_authority(&evidence, &authoritative)?;
        } else {
            smb_capabilities.validate_plan_mapping(evidence.quarantine_plan())?;
        }
    }
    let mut changed_phase_count = 0_u64;
    let mut checkpoint_exports = 0_u64;
    let mut retired_replacement_delete_calls = 0_u64;

    // Completed cohorts deliberately do not re-open media, credentials, or remote clients.
    // Only the sealed evidence and authoritative JSON checkpoint are reconciled.
    if phase == Some(LegacyUploadMigrationPhase::Complete) {
        let authoritative = state_store
            .load()
            .map_err(|_| LegacyUploadMigrationApplyError::State)?;
        evidence
            .revalidate_authoritative_manifest(&authoritative)
            .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
                category: error.category(),
            })?;
        let checkpoint_recovered = match state_store
            .json_checkpoint_status_for_manifest(&authoritative)
            .map_err(|_| LegacyUploadMigrationApplyError::State)?
        {
            JsonCheckpointStatus::Current => false,
            JsonCheckpointStatus::Stale => {
                state_store
                    .export_json()
                    .map_err(|_| LegacyUploadMigrationApplyError::CheckpointStale)?;
                checkpoint_exports = 1;
                true
            }
        };
        evidence.revalidate_held_evidence().map_err(|error| {
            LegacyUploadMigrationApplyError::Evidence {
                category: error.category(),
            }
        })?;
        return Ok(completed_apply_report(
            changed_phase_count,
            checkpoint_exports,
            checkpoint_recovered,
            initial_remote_states,
            retired_replacement_delete_calls,
        ));
    }

    while phase != Some(LegacyUploadMigrationPhase::Complete) {
        let preflight_manifest = state_store
            .load()
            .map_err(|_| state_stage(LegacyUploadMigrationStateStage::PreflightLoad))?;
        let quarantine_guard = preflight_quarantine_plan_with_smb_capabilities(
            &evidence,
            &request.quarantine_roots,
            phase,
            request.heic_verify_timeout_seconds,
            Some(&preflight_manifest),
            Some(&request.heic_output_dir),
            &smb_capabilities,
        )?;
        let outcome = match phase {
            None => ensure_prepared_with_quarantine_guard(
                state_store,
                &mut evidence,
                &quarantine_guard,
            )?,
            Some(LegacyUploadMigrationPhase::Prepared) => {
                let mut adapter =
                    ProductionRetiredReplacementDeleteAdapter::new(&request.delete_session_path)?;
                ensure_delete_confirmed_with_quarantine_guard(
                    state_store,
                    &mut evidence,
                    &mut adapter,
                    &quarantine_guard,
                )?
            }
            Some(LegacyUploadMigrationPhase::DeleteConfirmed) => {
                let mut adapter =
                    ProductionLegacyArtifactQuarantineAdapter::new_with_smb_capabilities(
                        request.quarantine_roots.clone(),
                        request.heic_verify_timeout_seconds,
                        &mut smb_capabilities,
                    );
                ensure_quarantined(state_store, &mut evidence, &mut adapter)?
            }
            Some(LegacyUploadMigrationPhase::Quarantined) => {
                ensure_reset(state_store, &mut evidence)?
            }
            Some(LegacyUploadMigrationPhase::Reset) => {
                let mut adapter = ProductionLegacyConversionAdapter::new(
                    request.jobs,
                    request.heic_quality,
                    request.conversion_tool_version.clone(),
                    request.heic_verify_timeout_seconds,
                );
                ensure_converted(
                    state_store,
                    &mut evidence,
                    &request.heic_output_dir,
                    &mut adapter,
                )?
            }
            Some(LegacyUploadMigrationPhase::Converted) => {
                ensure_upload_prepared(state_store, &mut evidence, &request.heic_output_dir)?
            }
            Some(LegacyUploadMigrationPhase::UploadPrepared) => {
                let mut adapter = ProductionLegacyUploadAdapter::new(
                    request.upload_session_path.clone(),
                    &request.delete_session_path,
                    request.capture_tolerance_seconds,
                    request.cloudkit_start_rank,
                    request.cloudkit_page_size,
                    request.cloudkit_max_pages,
                )?;
                ensure_upload_verified(state_store, &mut evidence, &mut adapter)?
            }
            Some(LegacyUploadMigrationPhase::UploadVerified) => {
                let mut adapter = ProductionLegacyMirrorAdapter;
                ensure_mirrored(
                    state_store,
                    &mut evidence,
                    &request.mirror_root,
                    &mut adapter,
                )?
            }
            Some(LegacyUploadMigrationPhase::Mirrored) => ensure_complete(
                state_store,
                &mut evidence,
                &request.heic_output_dir,
                &request.mirror_root,
            )?,
            Some(LegacyUploadMigrationPhase::Complete) => unreachable!(),
        };
        changed_phase_count += u64::from(outcome.changed);
        checkpoint_exports += u64::from(outcome.checkpoint_exported);
        retired_replacement_delete_calls += outcome.retired_replacement_delete_calls;
        let next = authoritative_cohort_phase(state_store, &mut evidence)?;
        if next == phase {
            return Err(LegacyUploadMigrationApplyError::Cohort);
        }
        phase = next;
    }
    Ok(completed_apply_report(
        changed_phase_count,
        checkpoint_exports,
        false,
        initial_remote_states,
        retired_replacement_delete_calls,
    ))
}

fn finish_complete_replay_read_only(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
) -> Result<LegacyUploadMigrationPreparationOutcome, LegacyUploadMigrationApplyError> {
    let authoritative = state_store
        .load()
        .map_err(|_| LegacyUploadMigrationApplyError::State)?;
    evidence
        .revalidate_authoritative_manifest(&authoritative)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    if state_store
        .json_checkpoint_status_for_manifest(&authoritative)
        .map_err(|_| LegacyUploadMigrationApplyError::State)?
        != JsonCheckpointStatus::Current
    {
        return Err(LegacyUploadMigrationApplyError::CheckpointStale);
    }
    evidence.revalidate_held_evidence().map_err(|error| {
        LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        }
    })?;
    Ok(LegacyUploadMigrationPreparationOutcome {
        changed: false,
        checkpoint_exported: false,
        retired_replacement_delete_calls: 0,
    })
}

fn authoritative_cohort_phase(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
) -> Result<Option<LegacyUploadMigrationPhase>, LegacyUploadMigrationApplyError> {
    let manifest = state_store
        .load()
        .map_err(|_| state_stage(LegacyUploadMigrationStateStage::AuthoritativePhaseLoad))?;
    evidence
        .revalidate_authoritative_manifest(&manifest)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    let ids = evidence.replacement_asset_ids();
    let phases = ids.map(|asset_id| {
        let record = manifest
            .get(asset_id)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
        match record.proofs.get(super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME) {
            None => Ok(None),
            Some(_) => validate_legacy_upload_migration_record(record)
                .map_err(|_| LegacyUploadMigrationApplyError::Cohort)
                .and_then(|journal| {
                    journal
                        .entries
                        .last()
                        .map(|entry| Some(entry.phase))
                        .ok_or(LegacyUploadMigrationApplyError::Cohort)
                }),
        }
    });
    let [left, right] = phases;
    let left = left?;
    let right = right?;
    if left != right {
        return Err(LegacyUploadMigrationApplyError::Cohort);
    }
    Ok(left)
}

pub(super) fn completed_apply_report(
    changed_phase_count: u64,
    checkpoint_exports: u64,
    checkpoint_recovered: bool,
    initial_remote_states: [CloudKitUploadedHeicInitialState; 2],
    retired_replacement_delete_calls: u64,
) -> LegacyUploadMigrationApplyReport {
    let retired_replacements_already_deleted = initial_remote_states
        .iter()
        .filter(|state| **state == CloudKitUploadedHeicInitialState::AlreadyDeleted)
        .count() as u64;
    let retired_replacements_deleted_by_migration =
        2_u64.saturating_sub(retired_replacements_already_deleted);
    LegacyUploadMigrationApplyReport {
        status: "complete",
        phase: LegacyUploadMigrationPhase::Complete.as_str(),
        changed_phase_count,
        checkpoint_exports,
        checkpoint_recovered,
        retired_replacement_delete_calls,
        retired_replacements_already_deleted,
        retired_replacements_deleted_by_migration,
        replacement_uploads: 2,
        original_deletes: 0,
    }
}

fn validate_upload_prepared_witness(
    records: [&AssetRecord; 2],
    replacements: &[EvidenceRetiredReplacement],
) -> Result<[VerifiedUploadSource; 2], LegacyUploadMigrationApplyError> {
    let mut predecessors = Vec::with_capacity(2);
    let mut receipts = Vec::with_capacity(2);
    let mut sources = Vec::with_capacity(2);
    for index in 0..2 {
        let heic: HeicVerificationProof = serde_json::from_value(
            records[index]
                .proofs
                .get(HEIC_PROOF)
                .ok_or(LegacyUploadMigrationApplyError::Cohort)?
                .clone(),
        )
        .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
        if heic.heic_path.file_name().and_then(OsStr::to_str)
            != Some(replacements[index].destination.filename.as_str())
        {
            return Err(LegacyUploadMigrationApplyError::Cohort);
        }
        let source = VerifiedUploadSource::from_verified_heic(&VerifiedHeic::from(&heic))
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
        receipts.push(upload_prepared_receipt_from_source(
            records[index],
            &heic.heic_path,
            replacements[index].destination_sha256.clone(),
            &source,
        )?);
        sources.push(source);
        let mut predecessor = records[index].clone();
        let mut journal = validate_legacy_upload_migration_record(records[index])
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
        let removed = journal
            .entries
            .pop()
            .ok_or(LegacyUploadMigrationApplyError::Cohort)?;
        if removed.phase != LegacyUploadMigrationPhase::UploadPrepared
            || journal.entries.last().map(|entry| entry.phase)
                != Some(LegacyUploadMigrationPhase::Converted)
        {
            return Err(LegacyUploadMigrationApplyError::Cohort);
        }
        predecessor.proofs.insert(
            super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME.to_string(),
            serde_json::to_value(journal).map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
        );
        validate_legacy_upload_migration_record(&predecessor)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
        predecessors.push(predecessor);
    }
    let (_, rebuilt) = build_legacy_upload_migration_phase_authority(
        [&predecessors[0], &predecessors[1]],
        [&predecessors[0], &predecessors[1]],
        LegacyUploadMigrationPhase::UploadPrepared,
        [&receipts[0], &receipts[1]],
    )
    .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
    if rebuilt[0] != *records[0] || rebuilt[1] != *records[1] {
        return Err(LegacyUploadMigrationApplyError::Cohort);
    }
    sources
        .try_into()
        .map_err(|_| LegacyUploadMigrationApplyError::Cohort)
}

fn revalidate_upload_prepared_sources(
    records: [&AssetRecord; 2],
    sources: [&VerifiedUploadSource; 2],
) -> Result<(), LegacyUploadMigrationApplyError> {
    for index in 0..2 {
        let held = inspect_quarantine_file(
            &sources[index]
                .held_file()
                .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
        )?;
        let named = open_optional_anchored_quarantine_file(sources[index].sealed_path())?
            .ok_or(LegacyUploadMigrationApplyError::Cohort)?
            .identity;
        let heic: HeicVerificationProof = serde_json::from_value(
            records[index]
                .proofs
                .get(HEIC_PROOF)
                .ok_or(LegacyUploadMigrationApplyError::Cohort)?
                .clone(),
        )
        .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
        if held != named
            || sources[index].sealed_path() != heic.heic_path
            || held.sha256 != heic.heic_sha256
            || held.size_bytes != heic.size_bytes
        {
            return Err(LegacyUploadMigrationApplyError::Cohort);
        }
    }
    Ok(())
}

fn upload_verified_phase_receipt<'a>(
    record: &'a AssetRecord,
    remote: &'a VerifiedRemoteUploadReceipt,
) -> Result<UploadVerifiedPhaseReceipt<'a>, LegacyUploadMigrationApplyError> {
    let upload = record
        .proofs
        .get(UPLOAD_PROOF)
        .ok_or(LegacyUploadMigrationApplyError::Remote)?;
    if remote.asset_id != record.asset_id || !valid_sha256(&remote.uploaded_asset_id_sha256) {
        return Err(LegacyUploadMigrationApplyError::Remote);
    }
    Ok(UploadVerifiedPhaseReceipt {
        schema_version: 1,
        asset_id: &record.asset_id,
        upload_proof_sha256: canonical_digest(upload)
            .map_err(|_| LegacyUploadMigrationApplyError::Remote)?,
        remote,
    })
}

fn upload_prepared_receipt(
    record: &AssetRecord,
    output_path: &Path,
    destination_sha256: String,
) -> Result<UploadPreparedReceipt, LegacyUploadMigrationApplyError> {
    let converted = converted_receipt(record, output_path)?;
    Ok(UploadPreparedReceipt {
        schema_version: 1,
        asset_id: record.asset_id.clone(),
        destination_sha256,
        output_path_sha256: converted.output_path_sha256,
        output_identity: converted.output_identity,
    })
}

fn upload_prepared_receipt_from_source(
    record: &AssetRecord,
    output_path: &Path,
    destination_sha256: String,
    source: &VerifiedUploadSource,
) -> Result<UploadPreparedReceipt, LegacyUploadMigrationApplyError> {
    if source.sealed_path() != output_path {
        return Err(LegacyUploadMigrationApplyError::Cohort);
    }
    let identity = inspect_quarantine_file(
        &source
            .held_file()
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
    )
    .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?;
    let converted = converted_receipt_with_identity(record, output_path, identity)?;
    Ok(UploadPreparedReceipt {
        schema_version: 1,
        asset_id: record.asset_id.clone(),
        destination_sha256,
        output_path_sha256: converted.output_path_sha256,
        output_identity: converted.output_identity,
    })
}

fn migration_output_path(
    output_dir: &Path,
    filename: &str,
) -> Result<PathBuf, LegacyUploadMigrationApplyError> {
    let filename = Path::new(filename);
    if filename.components().count() != 1
        || !matches!(filename.components().next(), Some(Component::Normal(_)))
    {
        return Err(LegacyUploadMigrationApplyError::Cohort);
    }
    Ok(output_dir.join(filename))
}

fn converted_receipt(
    record: &AssetRecord,
    expected_output: &Path,
) -> Result<ConvertedReceipt, LegacyUploadMigrationApplyError> {
    let heic = record
        .proofs
        .get(HEIC_PROOF)
        .ok_or(LegacyUploadMigrationApplyError::Cohort)?;
    let heic_path = heic
        .get("heic_path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .filter(|path| path == expected_output)
        .ok_or(LegacyUploadMigrationApplyError::Cohort)?;
    let identity = open_optional_anchored_quarantine_file(&heic_path)?
        .ok_or(LegacyUploadMigrationApplyError::Cohort)?
        .identity;
    converted_receipt_with_identity(record, expected_output, identity)
}

fn converted_receipt_with_identity(
    record: &AssetRecord,
    expected_output: &Path,
    identity: QuarantineFileIdentity,
) -> Result<ConvertedReceipt, LegacyUploadMigrationApplyError> {
    let conversion = record
        .proofs
        .get(CONVERSION_PROOF)
        .ok_or(LegacyUploadMigrationApplyError::Cohort)?;
    let performance = record
        .proofs
        .get(CONVERSION_PERFORMANCE_PROOF)
        .ok_or(LegacyUploadMigrationApplyError::Cohort)?;
    let heic = record
        .proofs
        .get(HEIC_PROOF)
        .ok_or(LegacyUploadMigrationApplyError::Cohort)?;
    let _heic_path = heic
        .get("heic_path")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .filter(|path| path == expected_output)
        .ok_or(LegacyUploadMigrationApplyError::Cohort)?;
    if heic.get("heic_sha256").and_then(Value::as_str) != Some(&identity.sha256)
        || heic.get("size_bytes").and_then(Value::as_u64) != Some(identity.size_bytes)
    {
        return Err(LegacyUploadMigrationApplyError::Cohort);
    }
    Ok(ConvertedReceipt {
        schema_version: 1,
        asset_id: record.asset_id.clone(),
        output_path_sha256: canonical_digest(&expected_output.to_path_buf())
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
        conversion_proof_sha256: canonical_digest(conversion)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
        performance_proof_sha256: canonical_digest(performance)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
        heic_proof_sha256: canonical_digest(heic)
            .map_err(|_| LegacyUploadMigrationApplyError::Cohort)?,
        output_identity: identity,
    })
}

fn finish_phase_checkpoint(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
    changed: bool,
) -> Result<LegacyUploadMigrationPreparationOutcome, LegacyUploadMigrationApplyError> {
    finish_phase_checkpoint_with_state_error(
        state_store,
        evidence,
        changed,
        LegacyUploadMigrationApplyError::State,
    )
}

fn finish_phase_checkpoint_at(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
    changed: bool,
    stage: LegacyUploadMigrationStateStage,
) -> Result<LegacyUploadMigrationPreparationOutcome, LegacyUploadMigrationApplyError> {
    finish_phase_checkpoint_with_state_error(state_store, evidence, changed, state_stage(stage))
}

fn finish_phase_checkpoint_with_state_error(
    state_store: &AssetStateStore,
    evidence: &mut ValidatedLegacyUploadEvidence,
    changed: bool,
    state_error: LegacyUploadMigrationApplyError,
) -> Result<LegacyUploadMigrationPreparationOutcome, LegacyUploadMigrationApplyError> {
    let authoritative = state_store.load().map_err(|_| state_error)?;
    evidence
        .revalidate_authoritative_manifest(&authoritative)
        .map_err(|error| LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        })?;
    let checkpoint_stale = state_store
        .json_checkpoint_status_for_manifest(&authoritative)
        .map_err(|_| state_error)?
        == JsonCheckpointStatus::Stale;
    if checkpoint_stale {
        run_checkpoint_export_hook();
        state_store
            .export_json()
            .map_err(|_| LegacyUploadMigrationApplyError::CheckpointStale)?;
    }
    evidence.revalidate_held_evidence().map_err(|error| {
        LegacyUploadMigrationApplyError::Evidence {
            category: error.category(),
        }
    })?;
    Ok(LegacyUploadMigrationPreparationOutcome {
        changed,
        checkpoint_exported: checkpoint_stale,
        retired_replacement_delete_calls: 0,
    })
}

#[cfg(test)]
mod conversion_failure_tests {
    use super::*;
    use crate::upload::CloudKitOriginalAssetResolveObservations;

    const SENTINEL: &str = "sentinel-path-asset-token-hash";

    fn assert_redacted(error: LegacyUploadMigrationApplyError, expected_category: &str) -> String {
        assert_eq!(error.category(), expected_category);
        let rendered = error.to_string();
        assert_eq!(
            rendered,
            format!("legacy uploaded HEIC migration apply failed: category={expected_category}")
        );
        assert!(!rendered.contains(SENTINEL));
        rendered
    }

    #[test]
    fn execution_failure_classification_is_typed_and_redacted() {
        let error = ConversionExecutionError::BatchConversionFailed {
            asset_id: SENTINEL.to_string(),
            source: Box::new(ConversionExecutionError::OutputUnreadable {
                path: PathBuf::from(format!("/private/{SENTINEL}/output.heic")),
                source: std::io::Error::other(SENTINEL),
            }),
        };
        let category = classify_conversion_execution_error(&error);
        assert_eq!(
            category,
            LegacyConversionFailureCategory::ExecuteOutputUnreadable
        );
        assert_redacted(
            LegacyUploadMigrationApplyError::Conversion { category },
            "conversion_execution_output_unreadable",
        );
    }

    #[test]
    fn execution_command_failure_does_not_leak_program_or_status() {
        let error = ConversionExecutionError::CommandFailed {
            stage: "conversion",
            program: SENTINEL.to_string(),
            status: SENTINEL.to_string(),
        };
        let category = classify_conversion_execution_error(&error);
        assert_eq!(category, LegacyConversionFailureCategory::ExecuteCommand);
        assert_redacted(
            LegacyUploadMigrationApplyError::Conversion { category },
            "conversion_execution_command",
        );
    }

    #[test]
    fn verification_and_recording_failures_have_separate_fixed_categories() {
        let verification = MonitorError::HeicMetadataVerification {
            kind: HeicMetadataFailure::DimensionMismatch,
            metadata_probe_wall_time_millis: None,
        };
        let verification_category = classify_conversion_verification_error(&verification);
        assert_eq!(
            verification_category,
            LegacyConversionFailureCategory::VerifyDimension
        );
        assert_redacted(
            LegacyUploadMigrationApplyError::Conversion {
                category: verification_category,
            },
            "conversion_verification_dimension",
        );

        let recording = WorkflowError::Manifest(crate::manifest::ManifestError::UnknownAsset {
            asset_id: SENTINEL.to_string(),
        });
        let recording_category = classify_conversion_recording_error(&recording);
        assert_eq!(
            recording_category,
            LegacyConversionFailureCategory::RecordManifest
        );
        assert_redacted(
            LegacyUploadMigrationApplyError::Conversion {
                category: recording_category,
            },
            "conversion_recording_manifest",
        );
    }

    #[test]
    fn state_stage_categories_are_distinct_and_redacted() {
        let stages = [
            (
                LegacyUploadMigrationStateStage::AuthoritativePhaseLoad,
                "state_authoritative_phase_load",
            ),
            (
                LegacyUploadMigrationStateStage::AuthorityRevalidationLoad,
                "state_authority_revalidation_load",
            ),
            (
                LegacyUploadMigrationStateStage::PreflightLoad,
                "state_preflight_load",
            ),
            (
                LegacyUploadMigrationStateStage::EnsureConvertedInitialLoad,
                "state_ensure_converted_initial_load",
            ),
            (
                LegacyUploadMigrationStateStage::EnsureConvertedPostLoad,
                "state_ensure_converted_post_load",
            ),
            (
                LegacyUploadMigrationStateStage::EnsureConvertedPersist,
                "state_ensure_converted_persist",
            ),
            (
                LegacyUploadMigrationStateStage::EnsureConvertedCheckpoint,
                "state_ensure_converted_checkpoint",
            ),
        ];
        let mut categories = Vec::with_capacity(stages.len());
        for (stage, expected_category) in stages {
            categories.push(expected_category);
            assert_redacted(state_stage(stage), expected_category);
        }
        for (index, category) in categories.iter().enumerate() {
            assert!(
                categories[index + 1..]
                    .iter()
                    .all(|other| other != category)
            );
        }
    }

    #[test]
    fn production_remote_stage_categories_are_distinct_and_redacted() {
        let stages = [
            (
                LegacyUploadMigrationRemoteStage::AdapterInit,
                "remote_adapter_init",
            ),
            (
                LegacyUploadMigrationRemoteStage::LocalReplacementTarget,
                "remote_local_replacement_target",
            ),
            (
                LegacyUploadMigrationRemoteStage::LocalReplacementBinding,
                "remote_local_replacement_binding",
            ),
            (
                LegacyUploadMigrationRemoteStage::LocalReplacementBatchTransport,
                "remote_local_replacement_batch_transport",
            ),
            (
                LegacyUploadMigrationRemoteStage::LocalReplacementInventory,
                "remote_local_replacement_inventory",
            ),
            (
                LegacyUploadMigrationRemoteStage::LocalReplacementResolutionKeys,
                "remote_local_replacement_resolution_keys",
            ),
            (
                LegacyUploadMigrationRemoteStage::LocalReplacementDispositionIncompleteTransient,
                "remote_local_replacement_disposition_incomplete_transient",
            ),
            (
                LegacyUploadMigrationRemoteStage::LocalReplacementDispositionAmbiguous,
                "remote_local_replacement_disposition_ambiguous",
            ),
            (
                LegacyUploadMigrationRemoteStage::LocalReplacementDispositionNoRawResource,
                "remote_local_replacement_disposition_no_raw_resource",
            ),
            (
                LegacyUploadMigrationRemoteStage::LocalReplacementDispositionRawSizeMismatch,
                "remote_local_replacement_disposition_raw_size_mismatch",
            ),
            (
                LegacyUploadMigrationRemoteStage::LocalReplacementDispositionRawHashMismatch,
                "remote_local_replacement_disposition_raw_hash_mismatch",
            ),
            (
                LegacyUploadMigrationRemoteStage::LocalReplacementDispositionNoDateCandidate,
                "remote_local_replacement_disposition_no_date_candidate",
            ),
            (
                LegacyUploadMigrationRemoteStage::LocalReplacementDispositionObservationInconsistent,
                "remote_local_replacement_disposition_observation_inconsistent",
            ),
            (
                LegacyUploadMigrationRemoteStage::LocalReplacementDispositionReplacementProofMismatch,
                "remote_local_replacement_disposition_replacement_proof_mismatch",
            ),
            (
                LegacyUploadMigrationRemoteStage::LocalReplacementDispositionReplacementUniquenessMismatch,
                "remote_local_replacement_disposition_replacement_uniqueness_mismatch",
            ),
            (
                LegacyUploadMigrationRemoteStage::UploadExecution,
                "remote_upload_execution",
            ),
            (
                LegacyUploadMigrationRemoteStage::UploadResponseBinding,
                "remote_upload_response_binding",
            ),
            (
                LegacyUploadMigrationRemoteStage::UploadProofBinding,
                "remote_upload_proof_binding",
            ),
            (
                LegacyUploadMigrationRemoteStage::PostUploadVerificationResolverReadFailure,
                "remote_post_upload_verification_resolver_read_failure",
            ),
            (
                LegacyUploadMigrationRemoteStage::PostUploadVerificationExpectedIdentityMismatch,
                "remote_post_upload_verification_expected_response_identity_mismatch",
            ),
            (
                LegacyUploadMigrationRemoteStage::PostUploadVerificationRetiredAssetMasterCollision,
                "remote_post_upload_verification_retired_asset_master_collision",
            ),
            (
                LegacyUploadMigrationRemoteStage::PostUploadVerificationOriginalAssetCollision,
                "remote_post_upload_verification_original_asset_collision",
            ),
            (
                LegacyUploadMigrationRemoteStage::PostUploadVerificationResolvedAssetMasterSelfCollision,
                "remote_post_upload_verification_resolved_asset_master_self_collision",
            ),
            (
                LegacyUploadMigrationRemoteStage::PostUploadVerificationReplacementProofMismatch,
                "remote_post_upload_verification_replacement_proof_mismatch",
            ),
            (
                LegacyUploadMigrationRemoteStage::PostUploadVerificationReceiptDigestFailure,
                "remote_post_upload_verification_receipt_digest_failure",
            ),
            (
                LegacyUploadMigrationRemoteStage::CrossCandidateBinding,
                "remote_cross_candidate_binding",
            ),
        ];
        let mut categories = Vec::with_capacity(stages.len());
        for (stage, expected_category) in stages {
            categories.push(expected_category);
            assert_redacted(remote_stage(stage), expected_category);
        }
        for (index, category) in categories.iter().enumerate() {
            assert!(
                categories[index + 1..]
                    .iter()
                    .all(|other| other != category)
            );
        }
    }

    #[test]
    fn local_replacement_inventory_substages_classify_fail_closed() {
        let destination = CloudKitLibraryDestination {
            database_scope: CloudKitDatabaseScope::Private,
            zone_name: "PrimarySync".to_string(),
            owner_record_name: Some("_owner".to_string()),
        };
        let heic: HeicVerificationProof = serde_json::from_value(serde_json::json!({
            "heic_path": format!("/private/{SENTINEL}/output.heic"),
            "heic_sha256": "a".repeat(64),
            "size_bytes": 1,
            "heif_info_ok": true,
            "metadata_copied": true,
            "visual_content_ok": true,
            "visual_match_ok": true,
        }))
        .expect("test HEIC proof should decode");
        let classify = |disposition, observations| {
            ProductionLegacyUploadAdapter::validate_local_replacement_resolution(
                &CloudKitOriginalAssetResolution {
                    observations,
                    disposition,
                },
                &destination,
                &heic,
            )
            .expect_err("remote disposition must remain fail-closed")
        };
        let ambiguous_observations = CloudKitOriginalAssetResolveObservations {
            ambiguity_evidence: 1,
            ..Default::default()
        };
        assert_redacted(
            classify(
                CloudKitOriginalAssetResolveDisposition::IncompleteTransient,
                CloudKitOriginalAssetResolveObservations::default(),
            ),
            "remote_local_replacement_disposition_incomplete_transient",
        );
        assert_redacted(
            classify(
                CloudKitOriginalAssetResolveDisposition::Ambiguous,
                ambiguous_observations,
            ),
            "remote_local_replacement_disposition_ambiguous",
        );
        let no_raw_observations = CloudKitOriginalAssetResolveObservations {
            date_candidates: 1,
            ..Default::default()
        };
        assert_redacted(
            classify(
                CloudKitOriginalAssetResolveDisposition::NoRawResource,
                no_raw_observations.clone(),
            ),
            "remote_local_replacement_disposition_no_raw_resource",
        );

        let raw_size_observations = CloudKitOriginalAssetResolveObservations {
            date_candidates: 1,
            raw_resources: 1,
            ..Default::default()
        };
        assert_redacted(
            classify(
                CloudKitOriginalAssetResolveDisposition::RawSizeMismatch,
                raw_size_observations.clone(),
            ),
            "remote_local_replacement_disposition_raw_size_mismatch",
        );

        let raw_hash_observations = CloudKitOriginalAssetResolveObservations {
            date_candidates: 1,
            raw_resources: 1,
            raw_size_matches: 1,
            ..Default::default()
        };
        assert_redacted(
            classify(
                CloudKitOriginalAssetResolveDisposition::RawHashMismatch,
                raw_hash_observations,
            ),
            "remote_local_replacement_disposition_raw_hash_mismatch",
        );

        assert_redacted(
            classify(
                CloudKitOriginalAssetResolveDisposition::ExactOriginal {
                    proof: crate::workflow::OriginalAssetProof {
                        record_name: SENTINEL.to_string(),
                        record_change_tag: SENTINEL.to_string(),
                        record_type: "CPLAsset".to_string(),
                        database_scope: CloudKitDatabaseScope::Private,
                        zone_name: "PrimarySync".to_string(),
                        owner_record_name: Some("_owner".to_string()),
                        filename: "asset.raw".to_string(),
                        size_bytes: 1,
                        matched_raw_sha256: "a".repeat(64),
                    },
                },
                CloudKitOriginalAssetResolveObservations::default(),
            ),
            "remote_local_replacement_disposition_observation_inconsistent",
        );

        let replacement_proof = CloudKitReplacementResourceProof {
            record_name: SENTINEL.to_string(),
            record_change_tag: SENTINEL.to_string(),
            record_type: "CPLAsset".to_string(),
            database_scope: CloudKitDatabaseScope::Private,
            zone_name: "PrimarySync".to_string(),
            owner_record_name: Some("_wrong-owner".to_string()),
            resource_field: "resOriginalAltFingerprint".to_string(),
            size_bytes: 1,
            matched_heic_sha256: "a".repeat(64),
        };
        let replacement_observations = CloudKitOriginalAssetResolveObservations {
            replacement_resource_matches: 1,
            ..Default::default()
        };
        assert_redacted(
            classify(
                CloudKitOriginalAssetResolveDisposition::ReplacementPresent {
                    proof: replacement_proof.clone(),
                },
                replacement_observations.clone(),
            ),
            "remote_local_replacement_disposition_replacement_proof_mismatch",
        );
        let uniqueness_observations = CloudKitOriginalAssetResolveObservations {
            replacement_resource_matches: 2,
            ..Default::default()
        };
        assert_redacted(
            classify(
                CloudKitOriginalAssetResolveDisposition::ReplacementPresent {
                    proof: replacement_proof,
                },
                uniqueness_observations,
            ),
            "remote_local_replacement_disposition_replacement_uniqueness_mismatch",
        );

        let inventory_error = ProductionLegacyUploadAdapter::validate_local_replacement_inventory(
            CloudKitOriginalAssetInventoryFingerprint {
                resolver_version: "resolver".to_string(),
                sha256: SENTINEL.to_string(),
                records_scanned: 2,
            },
        )
        .expect_err("malformed inventory fingerprint must remain fail-closed");
        assert_redacted(inventory_error, "remote_local_replacement_inventory");
    }

    #[test]
    fn production_upload_errors_remain_typed_at_the_apply_boundary() {
        let error = remote_stage(
            LegacyUploadMigrationRemoteStage::PostUploadVerificationResolverReadFailure,
        );
        let mapped =
            <ProductionLegacyUploadAdapter as LegacyUploadAdapter>::into_apply_error(error);
        assert_eq!(mapped, error);
        assert_eq!(
            mapped.category(),
            "remote_post_upload_verification_resolver_read_failure"
        );
        assert!(!mapped.to_string().contains(SENTINEL));
    }

    #[test]
    fn production_conversion_errors_remain_typed_at_the_apply_boundary() {
        let error = LegacyUploadMigrationApplyError::Conversion {
            category: LegacyConversionFailureCategory::ExecuteOutputUnreadable,
        };
        let mapped =
            <ProductionLegacyConversionAdapter as LegacyConversionAdapter>::into_apply_error(error);
        assert_eq!(mapped, error);
        assert_eq!(mapped.category(), "conversion_execution_output_unreadable");
        assert!(!mapped.to_string().contains(SENTINEL));
    }
}

#[cfg(test)]
mod legacy_destination_binding_tests {
    use super::*;
    use crate::upload::CloudKitOriginalAssetResolveObservations;

    #[test]
    fn known_replacement_lookup_uses_checkpoint_identity_not_stale_upload_id() {
        let destination = CloudKitLibraryDestination {
            database_scope: CloudKitDatabaseScope::Private,
            zone_name: "PrimarySync".to_string(),
            owner_record_name: Some("_owner".to_string()),
        };
        let replacement_proof = CloudKitReplacementResourceProof {
            record_name: "replacement-record".to_string(),
            record_change_tag: "replacement-change".to_string(),
            record_type: "CPLAsset".to_string(),
            database_scope: destination.database_scope,
            zone_name: destination.zone_name.clone(),
            owner_record_name: destination.owner_record_name.clone(),
            resource_field: "resOriginalAltFingerprint".to_string(),
            size_bytes: 17,
            matched_heic_sha256: "a".repeat(64),
        };
        let request = known_replacement_resolve_request(&replacement_proof, &destination);

        assert_eq!(request.uploaded_asset_id, replacement_proof.record_name);
        assert_eq!(
            request.expected_heic_sha256,
            replacement_proof.matched_heic_sha256
        );
        assert_eq!(request.expected_size_bytes, replacement_proof.size_bytes);
        assert_ne!(request.uploaded_asset_id, "stale-upload-proof-record");
        assert_eq!(request.database_scope, destination.database_scope);
        assert_eq!(request.zone_name, destination.zone_name);
        assert_eq!(request.owner_record_name, destination.owner_record_name);
    }

    fn uploaded_heic_with_state(
        initial_remote_state: CloudKitUploadedHeicInitialState,
    ) -> CloudKitUploadedHeicAsset {
        CloudKitUploadedHeicAsset {
            record_name: "replacement-record".to_string(),
            record_change_tag: "replacement-change".to_string(),
            master_record_name: "replacement-master".to_string(),
            owner_record_name_sha256: "owner-hash".to_string(),
            initial_remote_state,
            initial_state_lookup_mode:
                crate::upload::CloudKitUploadedHeicInitialStateLookupMode::FullFields,
            matched_heic_sha256: "a".repeat(64),
            size_bytes: 17,
        }
    }

    #[test]
    fn full_fields_unmarked_active_checkpoint_is_accepted() {
        let resolved = require_active_uploaded_heic_resolution(Ok(uploaded_heic_with_state(
            CloudKitUploadedHeicInitialState::ActiveUnmarked,
        )))
        .expect("full-fields active-unmarked replacement should be accepted");
        assert_eq!(
            resolved.initial_remote_state,
            CloudKitUploadedHeicInitialState::ActiveUnmarked
        );
    }

    #[test]
    fn full_fields_deleted_checkpoint_is_rejected() {
        let error = require_active_uploaded_heic_resolution(Ok(uploaded_heic_with_state(
            CloudKitUploadedHeicInitialState::AlreadyDeleted,
        )))
        .expect_err("deleted replacement must remain fail-closed");
        assert_eq!(
            error.category(),
            "remote_post_upload_verification_resolver_read_failure"
        );
    }

    #[test]
    fn full_fields_malformed_reader_error_is_rejected_without_details() {
        let error = require_active_uploaded_heic_resolution(Err(
            crate::upload::UploadError::InvalidCloudKitUploadedHeicResponse(
                "malformed remote response",
            ),
        ))
        .expect_err("malformed full-fields response must remain fail-closed");
        assert_eq!(
            error.category(),
            "remote_post_upload_verification_resolver_read_failure"
        );
        assert!(!error.to_string().contains("malformed remote response"));
    }

    fn evidence_destination(
        database_scope: CloudKitDatabaseScope,
        zone_name: &str,
        owner_record_name: Option<&str>,
    ) -> super::super::evidence::EvidenceDestination {
        super::super::evidence::EvidenceDestination {
            database_scope,
            zone_name: zone_name.to_string(),
            owner_record_name: owner_record_name.map(ToOwned::to_owned),
            filename: "asset.heic".to_string(),
        }
    }

    fn session_destination(
        database_scope: CloudKitDatabaseScope,
        zone_name: &str,
        owner_record_name: Option<&str>,
    ) -> CloudKitLibraryDestination {
        CloudKitLibraryDestination {
            database_scope,
            zone_name: zone_name.to_string(),
            owner_record_name: owner_record_name.map(ToOwned::to_owned),
        }
    }

    #[test]
    fn private_primary_sync_inherits_authenticated_owner() {
        let evidence = evidence_destination(CloudKitDatabaseScope::Private, "PrimarySync", None);
        let session = session_destination(
            CloudKitDatabaseScope::Private,
            "PrimarySync",
            Some("_private-owner"),
        );

        let effective =
            effective_legacy_destination(&evidence, CloudKitDatabaseScope::Private, &session)
                .expect("matching private session should bind its owner");

        assert_eq!(
            effective.owner_record_name.as_deref(),
            Some("_private-owner")
        );
        assert_eq!(effective.database_scope, CloudKitDatabaseScope::Private);
        assert_eq!(effective.zone_name, "PrimarySync");
    }

    #[test]
    fn explicit_owner_requires_exact_session_agreement() {
        let evidence = evidence_destination(
            CloudKitDatabaseScope::Private,
            "PrimarySync",
            Some("_evidence-owner"),
        );
        let matching = session_destination(
            CloudKitDatabaseScope::Private,
            "PrimarySync",
            Some("_evidence-owner"),
        );
        let mismatched = session_destination(
            CloudKitDatabaseScope::Private,
            "PrimarySync",
            Some("_other-owner"),
        );
        let unbound_session =
            session_destination(CloudKitDatabaseScope::Private, "PrimarySync", None);

        assert_eq!(
            effective_legacy_destination(&evidence, CloudKitDatabaseScope::Private, &matching)
                .and_then(|destination| destination.owner_record_name),
            Some("_evidence-owner".to_string())
        );
        assert!(
            effective_legacy_destination(&evidence, CloudKitDatabaseScope::Private, &mismatched,)
                .is_none()
        );
        assert!(
            effective_legacy_destination(
                &evidence,
                CloudKitDatabaseScope::Private,
                &unbound_session,
            )
            .is_none()
        );
    }

    #[test]
    fn private_unbound_destination_remains_unbound() {
        let evidence = evidence_destination(CloudKitDatabaseScope::Private, "PrimarySync", None);
        let session = session_destination(CloudKitDatabaseScope::Private, "PrimarySync", None);

        let effective =
            effective_legacy_destination(&evidence, CloudKitDatabaseScope::Private, &session)
                .expect("matching unbound private session should remain usable");

        assert_eq!(effective, evidence_destination_to_library(&evidence));
    }

    #[test]
    fn durable_private_proof_normalization_preserves_explicit_and_shared_owners() {
        let private_unbound =
            evidence_destination(CloudKitDatabaseScope::Private, "PrimarySync", None);
        let private_upload = UploadProof {
            uploaded_heic_asset_id: "asset".to_string(),
            uploaded_heic_sha256: "a".repeat(64),
            database_scope: CloudKitDatabaseScope::Private,
            zone_name: "PrimarySync".to_string(),
            owner_record_name: Some("_session-owner".to_string()),
            uploaded_heic_path: Some(PathBuf::from("/asset.heic")),
        };
        let normalized = durable_legacy_upload_proof(private_upload, &private_unbound);
        assert!(normalized.owner_record_name.is_none());

        let explicit = evidence_destination(
            CloudKitDatabaseScope::Private,
            "PrimarySync",
            Some("_explicit-owner"),
        );
        let explicit_upload = UploadProof {
            owner_record_name: Some("_explicit-owner".to_string()),
            ..normalized.clone()
        };
        assert_eq!(
            durable_legacy_upload_proof(explicit_upload.clone(), &explicit).owner_record_name,
            explicit_upload.owner_record_name
        );

        let shared = evidence_destination(
            CloudKitDatabaseScope::Shared,
            "SharedSync-family",
            Some("_shared-owner"),
        );
        let shared_upload = UploadProof {
            database_scope: CloudKitDatabaseScope::Shared,
            zone_name: "SharedSync-family".to_string(),
            owner_record_name: Some("_shared-owner".to_string()),
            ..normalized
        };
        assert_eq!(
            durable_legacy_upload_proof(shared_upload.clone(), &shared).owner_record_name,
            shared_upload.owner_record_name
        );
    }

    #[test]
    fn legacy_private_upload_omits_transport_owner_but_binds_remote_identity() {
        let evidence = evidence_destination(CloudKitDatabaseScope::Private, "PrimarySync", None);
        let effective = session_destination(
            CloudKitDatabaseScope::Private,
            "PrimarySync",
            Some("_session-owner"),
        );
        let transport = photos_upload_transport_destination(&effective, &evidence);
        assert_eq!(transport.owner_record_name, None);

        let upload = UploadProof {
            uploaded_heic_asset_id: "asset".to_string(),
            uploaded_heic_sha256: "a".repeat(64),
            database_scope: CloudKitDatabaseScope::Private,
            zone_name: "PrimarySync".to_string(),
            owner_record_name: transport.owner_record_name.clone(),
            uploaded_heic_path: Some(PathBuf::from("/asset.heic")),
        };
        let remote = bind_generated_upload_proof_destination(upload, &effective, &evidence)
            .expect("owner-omitted upload response should bind to effective owner");
        assert_eq!(remote.owner_record_name, effective.owner_record_name);
        assert_eq!(
            durable_legacy_upload_proof(remote, &evidence).owner_record_name,
            None
        );
    }

    #[test]
    fn explicit_and_shared_upload_transport_destinations_remain_owner_bound() {
        let explicit = evidence_destination(
            CloudKitDatabaseScope::Private,
            "PrimarySync",
            Some("_explicit-owner"),
        );
        let explicit_effective = session_destination(
            CloudKitDatabaseScope::Private,
            "PrimarySync",
            Some("_explicit-owner"),
        );
        assert_eq!(
            photos_upload_transport_destination(&explicit_effective, &explicit),
            explicit_effective
        );

        let shared = evidence_destination(
            CloudKitDatabaseScope::Shared,
            "SharedSync-family",
            Some("_shared-owner"),
        );
        let shared_effective = session_destination(
            CloudKitDatabaseScope::Shared,
            "SharedSync-family",
            Some("_shared-owner"),
        );
        assert_eq!(
            photos_upload_transport_destination(&shared_effective, &shared),
            shared_effective
        );
    }

    #[test]
    fn shared_destination_remains_exact_and_owner_required() {
        let evidence = evidence_destination(
            CloudKitDatabaseScope::Shared,
            "SharedSync-family",
            Some("_shared-owner"),
        );
        let matching = session_destination(
            CloudKitDatabaseScope::Shared,
            "SharedSync-family",
            Some("_shared-owner"),
        );
        let missing_owner =
            session_destination(CloudKitDatabaseScope::Shared, "SharedSync-family", None);
        let unbound_evidence =
            evidence_destination(CloudKitDatabaseScope::Shared, "SharedSync-family", None);

        assert_eq!(
            effective_legacy_destination(&evidence, CloudKitDatabaseScope::Shared, &matching),
            Some(matching.clone())
        );
        assert!(
            effective_legacy_destination(&evidence, CloudKitDatabaseScope::Shared, &missing_owner,)
                .is_none()
        );
        assert!(
            effective_legacy_destination(
                &unbound_evidence,
                CloudKitDatabaseScope::Shared,
                &matching,
            )
            .is_none()
        );
    }

    #[test]
    fn mismatched_scope_or_zone_fails_closed() {
        let evidence = evidence_destination(CloudKitDatabaseScope::Private, "PrimarySync", None);
        let shared_session = session_destination(
            CloudKitDatabaseScope::Shared,
            "SharedSync-family",
            Some("_shared-owner"),
        );
        let wrong_zone = session_destination(
            CloudKitDatabaseScope::Private,
            "PrimarySync-other",
            Some("_private-owner"),
        );

        assert!(effective_legacy_destination(
            &evidence,
            CloudKitDatabaseScope::Shared,
            &shared_session,
        )
        .is_none());
        assert!(
            effective_legacy_destination(&evidence, CloudKitDatabaseScope::Private, &wrong_zone,)
                .is_none()
        );
    }

    #[test]
    fn batch_replacement_validation_binds_owner_hash_size_and_type() {
        let destination = session_destination(
            CloudKitDatabaseScope::Private,
            "PrimarySync",
            Some("_session-owner"),
        );
        let heic: HeicVerificationProof = serde_json::from_value(serde_json::json!({
            "heic_path": "/asset.heic",
            "heic_sha256": "a".repeat(64),
            "size_bytes": 42,
            "conversion_recipe_id": "recipe",
            "heif_info_ok": true,
            "metadata_copied": true,
            "visual_content_ok": true,
            "visual_match_ok": true
        }))
        .expect("test HEIC proof should deserialize");
        let proof = CloudKitReplacementResourceProof {
            record_name: "replacement-record".to_string(),
            record_change_tag: "change-tag".to_string(),
            record_type: "CPLAsset".to_string(),
            database_scope: destination.database_scope,
            zone_name: destination.zone_name.clone(),
            owner_record_name: destination.owner_record_name.clone(),
            resource_field: "res".to_string(),
            size_bytes: heic.size_bytes,
            matched_heic_sha256: heic.heic_sha256.clone(),
        };
        let resolution = CloudKitOriginalAssetResolution {
            observations: CloudKitOriginalAssetResolveObservations {
                replacement_resource_matches: 1,
                ..Default::default()
            },
            disposition: CloudKitOriginalAssetResolveDisposition::ReplacementPresent {
                proof: proof.clone(),
            },
        };
        assert!(
            ProductionLegacyUploadAdapter::validate_local_replacement_resolution(
                &resolution,
                &destination,
                &heic,
            )
            .expect("strict replacement result should pass")
            .is_some()
        );

        let mut ambiguous = resolution.clone();
        ambiguous.observations.ambiguity_evidence = 1;
        assert!(
            ProductionLegacyUploadAdapter::validate_local_replacement_resolution(
                &ambiguous,
                &destination,
                &heic,
            )
            .is_err()
        );

        let mut wrong_owner = resolution.clone();
        if let CloudKitOriginalAssetResolveDisposition::ReplacementPresent { proof } =
            &mut wrong_owner.disposition
        {
            proof.owner_record_name = Some("_other-owner".to_string());
        }
        assert!(
            ProductionLegacyUploadAdapter::validate_local_replacement_resolution(
                &wrong_owner,
                &destination,
                &heic,
            )
            .is_err()
        );

        let target = CloudKitOriginalAssetResolveTarget {
            asset_id: "asset-coexistence".to_string(),
            raw_size_bytes: 42,
            source_captured_unix_seconds: 1_700_000_000,
            capture_tolerance_seconds: 1,
            filename: "asset.raw".to_string(),
            matched_raw_sha256: "a".repeat(64),
            replacement_candidate: Some(CloudKitLocalReplacementCandidate {
                sha256: heic.heic_sha256.clone(),
                size_bytes: heic.size_bytes,
            }),
        };
        let coexistence = CloudKitOriginalAssetResolution {
            observations: CloudKitOriginalAssetResolveObservations {
                date_candidates: 1,
                raw_resources: 1,
                raw_size_matches: 1,
                raw_hash_matches: 1,
                replacement_resource_matches: 1,
                ..Default::default()
            },
            disposition: CloudKitOriginalAssetResolveDisposition::Coexistence {
                original_proof: crate::workflow::OriginalAssetProof {
                    record_name: "original-record".to_string(),
                    record_change_tag: "original-tag".to_string(),
                    record_type: "CPLAsset".to_string(),
                    database_scope: destination.database_scope,
                    zone_name: destination.zone_name.clone(),
                    owner_record_name: destination.owner_record_name.clone(),
                    filename: target.filename.clone(),
                    size_bytes: target.raw_size_bytes,
                    matched_raw_sha256: target.matched_raw_sha256.clone(),
                },
                replacement_proof: CloudKitReplacementResourceProof {
                    record_name: proof.record_name.clone(),
                    record_change_tag: proof.record_change_tag.clone(),
                    record_type: proof.record_type.clone(),
                    database_scope: proof.database_scope,
                    zone_name: proof.zone_name.clone(),
                    owner_record_name: proof.owner_record_name.clone(),
                    resource_field: proof.resource_field.clone(),
                    size_bytes: proof.size_bytes,
                    matched_heic_sha256: proof.matched_heic_sha256.clone(),
                },
            },
        };
        assert!(
            ProductionLegacyUploadAdapter::validate_local_replacement_resolution_with_target(
                &coexistence,
                &destination,
                Some(&target),
                &heic,
            )
            .expect("strict coexistence result should pass")
            .is_some()
        );
    }

    #[test]
    fn batch_no_replacement_validation_rejects_ambiguity_and_size_mismatch() {
        let destination = session_destination(
            CloudKitDatabaseScope::Private,
            "PrimarySync",
            Some("_session-owner"),
        );
        let heic: HeicVerificationProof = serde_json::from_value(serde_json::json!({
            "heic_path": "/asset.heic",
            "heic_sha256": "a".repeat(64),
            "size_bytes": 42,
            "conversion_recipe_id": "recipe",
            "heif_info_ok": true,
            "metadata_copied": true,
            "visual_content_ok": true,
            "visual_match_ok": true
        }))
        .expect("test HEIC proof should deserialize");
        let mut resolution = CloudKitOriginalAssetResolution {
            observations: Default::default(),
            disposition: CloudKitOriginalAssetResolveDisposition::NoDateCandidate,
        };
        assert_eq!(
            ProductionLegacyUploadAdapter::validate_local_replacement_resolution(
                &resolution,
                &destination,
                &heic,
            )
            .expect("clean no-candidate result should pass"),
            None
        );
        resolution.observations.ambiguity_evidence = 1;
        assert!(
            ProductionLegacyUploadAdapter::validate_local_replacement_resolution(
                &resolution,
                &destination,
                &heic,
            )
            .is_err()
        );
        resolution.observations.ambiguity_evidence = 0;
        resolution.observations.download_size_mismatches = 1;
        assert!(
            ProductionLegacyUploadAdapter::validate_local_replacement_resolution(
                &resolution,
                &destination,
                &heic,
            )
            .is_err()
        );
    }

    fn evidence_destination_to_library(
        evidence: &super::super::evidence::EvidenceDestination,
    ) -> CloudKitLibraryDestination {
        CloudKitLibraryDestination {
            database_scope: evidence.database_scope,
            zone_name: evidence.zone_name.clone(),
            owner_record_name: evidence.owner_record_name.clone(),
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod smb_reconciliation_tests {
    use super::*;

    #[test]
    fn capability_gate_runs_before_any_governed_path_access_or_mutation() {
        let events = std::cell::RefCell::new(Vec::new());
        let rejected: Result<(), LegacyUploadMigrationApplyError> = after_smb_capability_gate(
            || {
                events.borrow_mut().push("capability_gate");
                Err(LegacyUploadMigrationApplyError::Quarantine)
            },
            || {
                events.borrow_mut().push("governed_access");
                Ok(())
            },
        );
        assert_eq!(rejected, Err(LegacyUploadMigrationApplyError::Quarantine));
        assert_eq!(*events.borrow(), ["capability_gate"]);

        events.borrow_mut().clear();
        after_smb_capability_gate(
            || {
                events.borrow_mut().push("capability_gate");
                Ok(())
            },
            || {
                events.borrow_mut().push("governed_access");
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*events.borrow(), ["capability_gate", "governed_access"]);
    }

    #[test]
    fn disconnect_reconciliation_accepts_only_exact_renamed_state() {
        assert_eq!(
            reconcile_smb_noreplace_result(
                Err(SmbNoReplaceError::Ambiguous),
                true,
                false,
                false,
                true,
            ),
            Ok(())
        );
        assert_eq!(
            reconcile_smb_noreplace_result(
                Err(SmbNoReplaceError::Ambiguous),
                false,
                true,
                true,
                false,
            ),
            Err(LegacyUploadMigrationApplyError::Quarantine)
        );
        assert_eq!(
            reconcile_smb_noreplace_result(
                Err(SmbNoReplaceError::Ambiguous),
                false,
                false,
                false,
                true,
            ),
            Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)
        );
    }

    #[test]
    fn exact_collision_is_classified_without_accepting_a_rename() {
        assert_eq!(
            reconcile_smb_noreplace_result(
                Ok(SmbRenameResult::Collision),
                false,
                false,
                true,
                true,
            ),
            Err(LegacyUploadMigrationApplyError::Quarantine)
        );
        assert_eq!(
            reconcile_smb_noreplace_result(
                Ok(SmbRenameResult::Collision),
                false,
                false,
                false,
                true,
            ),
            Err(LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous)
        );
    }
}

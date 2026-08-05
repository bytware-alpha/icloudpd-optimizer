use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
#[cfg(all(target_os = "macos", not(test)))]
use std::process::Command;

#[cfg(test)]
use std::cell::RefCell;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::{
    LegacyUploadMigrationAuthorizedPreparation, LegacyUploadMigrationCohortAuthority,
    LegacyUploadMigrationIdentity, LegacyUploadMigrationQuarantineFileIdentity,
    LegacyUploadMigrationQuarantineKind, LegacyUploadMigrationQuarantineMember,
    LegacyUploadMigrationQuarantinePlan, LegacyUploadMigrationQuarantineRoot,
    LegacyUploadMigrationRawInput, canonical_digest,
    legacy_upload_migration_quarantine_destination_path, legacy_upload_migration_record_digest,
    seal_legacy_upload_migration_quarantine_plan, validate_legacy_upload_migration_record,
};
use crate::manifest::{AssetRecord, Manifest, State};
use crate::proof::NasRawProof;
use crate::state_store::{AssetStateStore, JsonCheckpointStatus};
use crate::upload::{
    CloudKitActiveAssetLookupMode, CloudKitActiveAssetReadRequest, CloudKitActiveAssetRemoteState,
    CloudKitActiveAssetValidation, CloudKitDatabaseScope, CloudKitDeleteSession,
    CloudKitUploadedHeicAsset, CloudKitUploadedHeicInitialState,
    CloudKitUploadedHeicInitialStateLookupMode, CloudKitUploadedHeicReadClient,
    CloudKitUploadedHeicReadTransport, CloudKitUploadedHeicResolveRequest,
};
use crate::workflow::{
    ConversionResultProof, HeicVerificationProof, IcloudpdLocalMirrorProof, OriginalAssetProof,
    UploadProof,
};

const EVIDENCE_SCHEMA_VERSION: u64 = 5;
const ASSET_COUNT: usize = 10;
const RETIRED_REPLACEMENT_COUNT: usize = 2;
const REFERENCE_COUNT: usize = 5;
const REFERENCE_ASSET_INDICES: [usize; REFERENCE_COUNT] = [2, 3, 7, 8, 9];
const REFERENCE_ORIENTATIONS: [u16; REFERENCE_COUNT] = [6, 6, 6, 6, 8];
const MAX_EVIDENCE_BYTES: u64 = 1_048_576;
const DEVICE_RECOVERY_SCHEMA_VERSION: u64 = 2;
const MAX_DEVICE_RECOVERY_BYTES: u64 = 65_536;

#[derive(Clone, Debug)]
pub(crate) struct LegacyUploadEvidenceGenerateRequest {
    pub(crate) manifest_path: PathBuf,
    pub(crate) output_path: PathBuf,
    pub(crate) image_timeout_seconds: u64,
    pub(crate) quarantine_roots: Vec<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct LegacyUploadEvidenceGenerateReport {
    pub(crate) evidence_sha256: String,
    pub(crate) cohort_sha256: String,
    pub(crate) manifest_target_sha256: String,
    pub(crate) cloudkit_target_sha256: String,
    pub(crate) asset_count: u64,
    pub(crate) retired_replacement_count: u64,
    pub(crate) reference_count: u64,
}

#[cfg(test)]
std::thread_local! {
    static EVIDENCE_POST_READ_HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    static GENERATION_PRE_OUTPUT_HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    static GENERATION_POST_OUTPUT_CREATE_HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    static DEVICE_RECOVERY_SIGNER_HOOK: RefCell<Option<DeviceRecoverySigner>> = const { RefCell::new(None) };
    static DEVICE_RECOVERY_PRE_CHECKPOINT_EXPORT_HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    static DEVICE_RECOVERY_CHECKPOINT_EXPORT_HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    static DEVICE_RECOVERY_POST_OUTPUT_HOOK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}

#[cfg(test)]
fn set_evidence_post_read_hook(hook: impl FnOnce() + 'static) {
    EVIDENCE_POST_READ_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_evidence_post_read_hook() {
    EVIDENCE_POST_READ_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
fn set_generation_pre_output_hook(hook: impl FnOnce() + 'static) {
    GENERATION_PRE_OUTPUT_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_generation_pre_output_hook() {
    GENERATION_PRE_OUTPUT_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_generation_pre_output_hook() {}

#[cfg(test)]
fn set_generation_post_output_create_hook(hook: impl FnOnce() + 'static) {
    GENERATION_POST_OUTPUT_CREATE_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_generation_post_output_create_hook() {
    GENERATION_POST_OUTPUT_CREATE_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_generation_post_output_create_hook() {}

#[cfg(not(test))]
fn run_evidence_post_read_hook() {}

#[cfg(test)]
fn set_device_recovery_signer_hook(signer: DeviceRecoverySigner) {
    DEVICE_RECOVERY_SIGNER_HOOK.with(|slot| *slot.borrow_mut() = Some(signer));
}

#[cfg(test)]
fn set_device_recovery_checkpoint_export_hook(hook: impl FnOnce() + 'static) {
    DEVICE_RECOVERY_CHECKPOINT_EXPORT_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn set_device_recovery_pre_checkpoint_export_hook(hook: impl FnOnce() + 'static) {
    DEVICE_RECOVERY_PRE_CHECKPOINT_EXPORT_HOOK
        .with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_device_recovery_pre_checkpoint_export_hook() {
    DEVICE_RECOVERY_PRE_CHECKPOINT_EXPORT_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
fn run_device_recovery_checkpoint_export_hook() {
    DEVICE_RECOVERY_CHECKPOINT_EXPORT_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_device_recovery_checkpoint_export_hook() {}

#[cfg(not(test))]
fn run_device_recovery_pre_checkpoint_export_hook() {}

#[cfg(test)]
fn set_device_recovery_post_output_hook(hook: impl FnOnce() + 'static) {
    DEVICE_RECOVERY_POST_OUTPUT_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

#[cfg(test)]
fn run_device_recovery_post_output_hook() {
    DEVICE_RECOVERY_POST_OUTPUT_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_device_recovery_post_output_hook() {}

#[derive(Clone, Debug)]
pub(crate) struct LegacyUploadEvidenceAuditRequest {
    pub(crate) manifest_path: PathBuf,
    pub(crate) evidence_path: PathBuf,
    pub(crate) expected_evidence_sha256: String,
    pub(crate) expected_asset_count: u64,
    pub(crate) expected_retired_replacement_count: u64,
    pub(crate) expected_reference_count: u64,
    pub(crate) expected_cohort_sha256: String,
}

#[derive(Clone, Debug)]
pub(crate) struct LegacyUploadDeviceRecoveryRequest {
    pub(crate) receipt_path: PathBuf,
    pub(crate) expected_receipt_sha256: String,
}

#[derive(Clone, Debug)]
pub(crate) struct LegacyUploadDeviceRecoveryGenerateRequest {
    pub(crate) evidence: LegacyUploadEvidenceAuditRequest,
    pub(crate) expected_signer_designated_requirement_sha256: String,
    /// Permit generation from an exact partially-quarantined DeleteConfirmed layout.
    ///
    /// The default remains strict empty-cohort recovery.  This capability is deliberately
    /// explicit because the resulting receipt is signer-bound and authorizes a resumed
    /// destructive workflow.
    pub(crate) allow_partial_quarantine: bool,
    pub(crate) output_path: PathBuf,
}

/// Explicit authority for rotating a post-reboot recovery receipt after the
/// signed helper is replaced.  This is deliberately separate from ordinary
/// receipt generation: the prior receipt and its sealed Service bundle must
/// both be supplied and independently validated before a new receipt is
/// written.
#[derive(Clone, Debug)]
pub(crate) struct LegacyUploadDeviceRecoveryRotateRequest {
    pub(crate) evidence: LegacyUploadEvidenceAuditRequest,
    pub(crate) prior_receipt_path: PathBuf,
    pub(crate) expected_prior_receipt_sha256: String,
    pub(crate) prior_service_bundle: PathBuf,
    pub(crate) output_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct LegacyUploadDeviceRecoveryGenerateReport {
    pub(crate) receipt_sha256: String,
    pub(crate) evidence_sha256: String,
    pub(crate) cohort_sha256: String,
    pub(crate) partial_quarantine: bool,
    pub(crate) device_mapping_count: u64,
    pub(crate) raw_input_count: u64,
    pub(crate) quarantine_member_count: u64,
    pub(crate) reference_count: u64,
    pub(crate) signer_designated_requirement_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct LegacyUploadDeviceRecoveryRotateReport {
    pub(crate) previous_receipt_sha256: String,
    pub(crate) receipt_sha256: String,
    pub(crate) evidence_sha256: String,
    pub(crate) cohort_sha256: String,
    pub(crate) migration_phase: String,
    pub(crate) device_mapping_count: u64,
    pub(crate) raw_input_count: u64,
    pub(crate) quarantine_member_count: u64,
    pub(crate) reference_count: u64,
    pub(crate) previous_signer_designated_requirement_sha256: String,
    pub(crate) signer_designated_requirement_sha256: String,
    pub(crate) checkpoint_recovered: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DeviceRecoveryMapping {
    previous_device: u64,
    current_device: u64,
    root_path_sha256: String,
    root_inode: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DeviceRecoverySigner {
    executable_sha256: String,
    designated_requirement_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DeviceRecoveryJournalAnchor {
    asset_id: String,
    entry_count: u64,
    delete_confirmed_entry_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OriginalDestinationCanonicalization {
    asset_id: String,
    original_asset_identity_sha256: String,
    destination_sha256: String,
    canonical_original_asset_sha256: String,
    delete_confirmed_entry_sha256: String,
    remote_state: CloudKitActiveAssetRemoteState,
    lookup_mode: CloudKitActiveAssetLookupMode,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DeviceRecoveryReceiptBody {
    schema_version: u64,
    evidence_sha256: String,
    cohort_sha256: String,
    authoritative_manifest_sha256: String,
    checkpoint_current: bool,
    migration_phase: String,
    mappings: Vec<DeviceRecoveryMapping>,
    journal_anchors: Vec<DeviceRecoveryJournalAnchor>,
    original_destination_canonicalizations: Vec<OriginalDestinationCanonicalization>,
    raw_input_count: u64,
    quarantine_member_count: u64,
    reference_count: u64,
    signer: DeviceRecoverySigner,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DeviceRecoveryReceipt {
    body: DeviceRecoveryReceiptBody,
    body_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct LegacyUploadEvidenceAudit {
    pub(crate) evidence_sha256: String,
    pub(crate) cohort_sha256: String,
    pub(crate) asset_count: u64,
    pub(crate) retired_replacement_count: u64,
    pub(crate) reference_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("legacy uploaded HEIC migration audit failed: category={category}")]
pub(crate) struct LegacyUploadEvidenceError {
    category: &'static str,
}

impl LegacyUploadEvidenceError {
    pub(crate) const fn category(&self) -> &'static str {
        self.category
    }
}

fn failure(category: &'static str) -> LegacyUploadEvidenceError {
    LegacyUploadEvidenceError { category }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceAsset {
    asset_id: String,
    record_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EvidenceDestination {
    pub(super) database_scope: CloudKitDatabaseScope,
    pub(super) zone_name: String,
    pub(super) owner_record_name: Option<String>,
    pub(super) filename: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EvidenceRetiredReplacement {
    pub(super) asset_id: String,
    pub(super) uploaded_asset_id: String,
    pub(super) uploaded_master_id: String,
    pub(super) owner_record_name_sha256: String,
    pub(super) initial_remote_state: CloudKitUploadedHeicInitialState,
    pub(super) initial_state_lookup_mode: CloudKitUploadedHeicInitialStateLookupMode,
    pub(super) destination: EvidenceDestination,
    pub(super) destination_sha256: String,
    pub(super) old_record_change_tag: String,
    pub(super) uploaded_heic_sha256: String,
    pub(super) uploaded_heic_size_bytes: u64,
    pub(super) original_asset_record_name: String,
    pub(super) original_record_change_tag: String,
    pub(super) original_remote_state: CloudKitActiveAssetRemoteState,
    pub(super) original_state_lookup_mode: CloudKitActiveAssetLookupMode,
    pub(super) original_asset_identity_sha256: String,
    pub(super) old_conversion_lineage_sha256: String,
    pub(super) old_upload_lineage_sha256: String,
    pub(super) old_mirror_lineage_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EvidenceReferenceNormalization {
    pub(super) asset_id: String,
    pub(super) asset_record_sha256: String,
    pub(super) reference_identity_sha256: String,
    pub(super) reference_path: PathBuf,
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) size_bytes: u64,
    pub(super) file_sha256: String,
    pub(super) orientation: u16,
    pub(super) width: u32,
    pub(super) height: u32,
    pub(super) decoded_pixel_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceQuarantineRoot {
    canonical_path: PathBuf,
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceQuarantineMember {
    asset_id: String,
    kind: LegacyUploadMigrationQuarantineKind,
    source_path: PathBuf,
    source: LegacyUploadMigrationQuarantineFileIdentity,
    root_device: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRawInput {
    asset_id: String,
    path: PathBuf,
    source: LegacyUploadMigrationQuarantineFileIdentity,
}

#[derive(Serialize)]
struct ReferenceIdentityDigestInput<'a> {
    schema_version: u64,
    asset_id: &'a str,
    reference_path: &'a Path,
    device: u64,
    inode: u64,
    size_bytes: u64,
    file_sha256: &'a str,
    orientation: u16,
    width: u32,
    height: u32,
    decoded_pixel_sha256: &'a str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceDocument {
    schema_version: u64,
    migration_id: String,
    asset_count: u64,
    retired_replacement_count: u64,
    reference_count: u64,
    cohort_sha256: String,
    assets: Vec<EvidenceAsset>,
    retired_replacements: Vec<EvidenceRetiredReplacement>,
    reference_normalizations: Vec<EvidenceReferenceNormalization>,
    quarantine_roots: Vec<EvidenceQuarantineRoot>,
    quarantine_members: Vec<EvidenceQuarantineMember>,
    raw_inputs: Vec<EvidenceRawInput>,
}

#[derive(Serialize)]
struct CohortDigestInput<'a> {
    schema_version: u64,
    migration_id: &'a str,
    asset_count: u64,
    retired_replacement_count: u64,
    reference_count: u64,
    assets: &'a [EvidenceAsset],
    retired_replacements: &'a [EvidenceRetiredReplacement],
    reference_normalizations: &'a [EvidenceReferenceNormalization],
    quarantine_roots: &'a [EvidenceQuarantineRoot],
    quarantine_members: &'a [EvidenceQuarantineMember],
    raw_inputs: &'a [EvidenceRawInput],
}

#[derive(Serialize)]
struct PreparationWitnessInput<'a> {
    schema_version: u64,
    migration_id: &'a str,
    evidence_sha256: &'a str,
    cohort_sha256: &'a str,
    asset_id: &'a str,
    quarantine_plan_sha256: &'a str,
}

struct ValidatedEvidenceDocument {
    audit: LegacyUploadEvidenceAudit,
    preparation_authority: LegacyUploadMigrationCohortAuthority,
}

pub(super) struct ValidatedLegacyUploadEvidence {
    validated: ValidatedEvidenceDocument,
    document: EvidenceDocument,
    request: LegacyUploadEvidenceAuditRequest,
    sealed_evidence: SealedEvidence,
    sealed_references: Vec<SealedReference>,
    operational_document: EvidenceDocument,
    operational_quarantine_plan: LegacyUploadMigrationQuarantinePlan,
    device_recovery: Option<SealedDeviceRecovery>,
}

struct SealedDeviceRecovery {
    request: LegacyUploadDeviceRecoveryRequest,
    receipt: DeviceRecoveryReceipt,
    sealed: SealedEvidence,
}

#[cfg(unix)]
struct SealedReference {
    path: PathBuf,
    file: fs::File,
    initial_metadata: EvidenceMetadata,
    sha256: String,
}

#[cfg(not(unix))]
struct SealedReference;

struct SealedEvidence {
    bytes: Vec<u8>,
    sha256: String,
    #[cfg(unix)]
    file: fs::File,
    #[cfg(unix)]
    initial_metadata: EvidenceMetadata,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EvidenceMetadata {
    is_regular: bool,
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

#[cfg(unix)]
impl EvidenceMetadata {
    fn capture(metadata: &fs::Metadata) -> Self {
        Self {
            is_regular: metadata.file_type().is_file(),
            dev: metadata.dev(),
            ino: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            nlink: metadata.nlink(),
            size: metadata.size(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
            ctime: metadata.ctime(),
            ctime_nsec: metadata.ctime_nsec(),
        }
    }

    fn matches_after_rename(self, expected: Self) -> bool {
        self.is_regular == expected.is_regular
            && self.dev == expected.dev
            && self.ino == expected.ino
            && self.mode == expected.mode
            && self.uid == expected.uid
            && self.gid == expected.gid
            && self.nlink == expected.nlink
            && self.size == expected.size
            && self.mtime == expected.mtime
            && self.mtime_nsec == expected.mtime_nsec
    }
}

trait LegacyUploadEvidenceResolver {
    fn resolve_uploaded_heic(
        &mut self,
        request: &CloudKitUploadedHeicResolveRequest,
    ) -> Result<CloudKitUploadedHeicAsset, LegacyUploadEvidenceError>;

    fn validate_original_active(
        &mut self,
        original: &OriginalAssetProof,
    ) -> Result<CloudKitActiveAssetValidation, LegacyUploadEvidenceError>;
}

trait LegacyUploadReferenceProbe {
    fn probe(
        &mut self,
        private_staged_path: &Path,
        timeout_seconds: u64,
    ) -> Result<crate::monitor::ReferenceNormalizationIdentity, LegacyUploadEvidenceError>;
}

struct ProductionLegacyUploadEvidenceResolver<'a, T> {
    session: &'a CloudKitDeleteSession,
    transport: &'a mut T,
}

impl<T: CloudKitUploadedHeicReadTransport> LegacyUploadEvidenceResolver
    for ProductionLegacyUploadEvidenceResolver<'_, T>
{
    fn resolve_uploaded_heic(
        &mut self,
        request: &CloudKitUploadedHeicResolveRequest,
    ) -> Result<CloudKitUploadedHeicAsset, LegacyUploadEvidenceError> {
        CloudKitUploadedHeicReadClient::new(&mut *self.transport)
            .inspect_uploaded_heic_asset_initial_state_full_fields(self.session, request)
            .map_err(|_| failure("cloudkit_read"))
    }

    fn validate_original_active(
        &mut self,
        original: &OriginalAssetProof,
    ) -> Result<CloudKitActiveAssetValidation, LegacyUploadEvidenceError> {
        CloudKitUploadedHeicReadClient::new(&mut *self.transport)
            .validate_active_asset_identity(
                self.session,
                &CloudKitActiveAssetReadRequest {
                    record_name: original.record_name.clone(),
                    record_change_tag: original.record_change_tag.clone(),
                    database_scope: original.database_scope,
                    zone_name: original.zone_name.clone(),
                    owner_record_name: original.owner_record_name.clone(),
                },
            )
            .map_err(|_| failure("original_remote_state"))
    }
}

struct ProductionLegacyUploadReferenceProbe;

impl LegacyUploadReferenceProbe for ProductionLegacyUploadReferenceProbe {
    fn probe(
        &mut self,
        private_staged_path: &Path,
        timeout_seconds: u64,
    ) -> Result<crate::monitor::ReferenceNormalizationIdentity, LegacyUploadEvidenceError> {
        crate::monitor::reference_normalization_identity(private_staged_path, timeout_seconds)
            .map_err(|_| failure("reference_image"))
    }
}

#[cfg(unix)]
struct HeldGenerationSource {
    path: PathBuf,
    file: fs::File,
    metadata: EvidenceMetadata,
    sha256: String,
}

#[cfg(unix)]
impl HeldGenerationSource {
    fn open(path: &Path) -> Result<Self, LegacyUploadEvidenceError> {
        if !safe_absolute_path(path) {
            return Err(failure("source_path"));
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        let mut file = options.open(path).map_err(|_| failure("source_open"))?;
        let metadata =
            EvidenceMetadata::capture(&file.metadata().map_err(|_| failure("source_metadata"))?);
        if !metadata.is_regular || metadata.nlink != 1 || metadata.size == 0 {
            return Err(failure("source_metadata"));
        }
        let sha256 = sha256_open_file(&mut file).map_err(|_| failure("source_read"))?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            metadata,
            sha256,
        })
    }

    fn revalidate(&mut self) -> Result<(), LegacyUploadEvidenceError> {
        let held = EvidenceMetadata::capture(
            &self
                .file
                .metadata()
                .map_err(|_| failure("source_changed"))?,
        );
        if held != self.metadata
            || sha256_open_file(&mut self.file).map_err(|_| failure("source_changed"))?
                != self.sha256
        {
            return Err(failure("source_changed"));
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        let mut named = options
            .open(&self.path)
            .map_err(|_| failure("source_changed"))?;
        if EvidenceMetadata::capture(&named.metadata().map_err(|_| failure("source_changed"))?)
            != self.metadata
            || sha256_open_file(&mut named).map_err(|_| failure("source_changed"))? != self.sha256
        {
            return Err(failure("source_changed"));
        }
        Ok(())
    }

    fn identity(&self) -> (u64, u64) {
        (self.metadata.dev, self.metadata.ino)
    }

    fn quarantine_identity(&self) -> LegacyUploadMigrationQuarantineFileIdentity {
        LegacyUploadMigrationQuarantineFileIdentity {
            device: self.metadata.dev,
            inode: self.metadata.ino,
            owner: self.metadata.uid,
            mode: self.metadata.mode & 0o777,
            link_count: self.metadata.nlink,
            size_bytes: self.metadata.size,
            modified_unix_seconds: self.metadata.mtime,
            modified_unix_nanoseconds: self.metadata.mtime_nsec,
            sha256: self.sha256.clone(),
        }
    }
}

#[cfg(unix)]
struct HeldGenerationAsset {
    raw: HeldGenerationSource,
    final_heic: HeldGenerationSource,
    mirror: HeldGenerationSource,
    reference: Option<HeldGenerationSource>,
}

#[cfg(unix)]
impl HeldGenerationAsset {
    fn revalidate(&mut self) -> Result<(), LegacyUploadEvidenceError> {
        self.raw.revalidate()?;
        self.final_heic.revalidate()?;
        self.mirror.revalidate()?;
        if let Some(reference) = &mut self.reference {
            reference.revalidate()?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn validate_generation_quarantine_roots(
    paths: &[PathBuf],
) -> Result<Vec<EvidenceQuarantineRoot>, LegacyUploadEvidenceError> {
    if paths.is_empty() {
        return Err(failure("quarantine_roots"));
    }
    let mut roots = Vec::with_capacity(paths.len());
    let mut devices = BTreeSet::new();
    let mut canonical_paths = BTreeSet::new();
    for path in paths {
        if !safe_absolute_path(path)
            || fs::canonicalize(path).map_err(|_| failure("quarantine_roots"))? != *path
            || !canonical_paths.insert(path.clone())
        {
            return Err(failure("quarantine_roots"));
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let directory = options
            .open(path)
            .map_err(|_| failure("quarantine_roots"))?;
        let metadata = directory
            .metadata()
            .map_err(|_| failure("quarantine_roots"))?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o700
            || metadata.dev() == 0
            || metadata.ino() == 0
            || !devices.insert(metadata.dev())
        {
            return Err(failure("quarantine_roots"));
        }
        roots.push(EvidenceQuarantineRoot {
            canonical_path: path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode() & 0o777,
        });
    }
    roots.sort_by_key(|root| root.device);
    Ok(roots)
}

#[cfg(unix)]
fn probe_held_reference(
    source: &mut HeldGenerationSource,
    timeout_seconds: u64,
    probe: &mut impl LegacyUploadReferenceProbe,
) -> Result<crate::monitor::ReferenceNormalizationIdentity, LegacyUploadEvidenceError> {
    let staging_root = fs::canonicalize(std::env::temp_dir())
        .map_err(|_| failure("reference_staging"))?
        .join(format!(
            "icloudpd-optimizer-evidence-{}",
            uuid::Uuid::new_v4()
        ));
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(&staging_root)
        .map_err(|_| failure("reference_staging"))?;
    let staged_path = staging_root.join("reference.jpg");
    let result = (|| {
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let mut staged = options
            .open(&staged_path)
            .map_err(|_| failure("reference_staging"))?;
        source
            .file
            .seek(SeekFrom::Start(0))
            .map_err(|_| failure("reference_staging"))?;
        std::io::copy(&mut source.file, &mut staged).map_err(|_| failure("reference_staging"))?;
        staged
            .sync_all()
            .map_err(|_| failure("reference_staging"))?;
        let staged_metadata = EvidenceMetadata::capture(
            &staged
                .metadata()
                .map_err(|_| failure("reference_staging"))?,
        );
        if !staged_metadata.is_regular
            || staged_metadata.nlink != 1
            || staged_metadata.mode & 0o777 != 0o600
            || staged_metadata.size != source.metadata.size
        {
            return Err(failure("reference_staging"));
        }
        let staged_sha256 =
            sha256_open_file(&mut staged).map_err(|_| failure("reference_staging"))?;
        if staged_sha256 != source.sha256 {
            return Err(failure("reference_staging"));
        }
        let identity = probe.probe(&staged_path, timeout_seconds)?;
        if EvidenceMetadata::capture(
            &staged
                .metadata()
                .map_err(|_| failure("reference_staging"))?,
        ) != staged_metadata
            || sha256_open_file(&mut staged).map_err(|_| failure("reference_staging"))?
                != staged_sha256
        {
            return Err(failure("reference_staging"));
        }
        source.revalidate()?;
        Ok(identity)
    })();
    let cleanup_file = fs::remove_file(&staged_path);
    let cleanup_dir = fs::remove_dir(&staging_root);
    match (result, cleanup_file, cleanup_dir) {
        (Ok(identity), Ok(()), Ok(())) => Ok(identity),
        (Err(error), _, _) => Err(error),
        (Ok(_), _, _) => Err(failure("reference_staging")),
    }
}

pub(crate) fn generate_legacy_uploaded_heic_evidence<T: CloudKitUploadedHeicReadTransport>(
    request: &LegacyUploadEvidenceGenerateRequest,
    session: &CloudKitDeleteSession,
    transport: &mut T,
) -> Result<LegacyUploadEvidenceGenerateReport, LegacyUploadEvidenceError> {
    generate_legacy_uploaded_heic_evidence_with(
        request,
        &mut ProductionLegacyUploadEvidenceResolver { session, transport },
        &mut ProductionLegacyUploadReferenceProbe,
    )
}

fn generate_legacy_uploaded_heic_evidence_with(
    request: &LegacyUploadEvidenceGenerateRequest,
    resolver: &mut impl LegacyUploadEvidenceResolver,
    reference_probe: &mut impl LegacyUploadReferenceProbe,
) -> Result<LegacyUploadEvidenceGenerateReport, LegacyUploadEvidenceError> {
    #[cfg(not(unix))]
    {
        let _ = (request, resolver, reference_probe);
        return Err(failure("unsupported_platform"));
    }
    #[cfg(unix)]
    {
        if request.image_timeout_seconds == 0 || !safe_absolute_path(&request.output_path) {
            return Err(failure("generator_request"));
        }
        let quarantine_roots = validate_generation_quarantine_roots(&request.quarantine_roots)?;
        let state_store = AssetStateStore::open_immutable_read_only(&request.manifest_path)
            .map_err(|_| failure("state_open"))?;
        let mut checkpoint_source = HeldGenerationSource::open(&request.manifest_path)
            .map_err(|_| failure("checkpoint_open"))?;
        let manifest = state_store.load().map_err(|_| failure("state_load"))?;
        if state_store
            .json_checkpoint_status_for_manifest(&manifest)
            .map_err(|_| failure("checkpoint_read"))?
            != JsonCheckpointStatus::Current
        {
            return Err(failure("checkpoint_stale"));
        }
        let records = manifest
            .records()
            .values()
            .filter(|record| record.state == State::UploadVerified)
            .collect::<Vec<_>>();
        if records.len() != ASSET_COUNT
            || records.iter().any(|record| {
                record
                    .proofs
                    .contains_key(super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME)
                    || record.proofs.contains_key("uploaded_heic_delete")
            })
        {
            return Err(failure("asset_count"));
        }

        let mut assets = Vec::with_capacity(ASSET_COUNT);
        let mut retired_replacements = Vec::new();
        let mut reference_normalizations = Vec::with_capacity(REFERENCE_COUNT);
        let mut quarantine_members = Vec::with_capacity(9);
        let mut raw_inputs = Vec::with_capacity(ASSET_COUNT);
        let mut held_assets = Vec::with_capacity(ASSET_COUNT);
        for (index, record) in records.iter().enumerate() {
            let nas: NasRawProof = generation_proof(record, "nas")?;
            let conversion: ConversionResultProof = generation_proof(record, "conversion")?;
            let heic: HeicVerificationProof = generation_proof(record, "heic")?;
            let upload: UploadProof = generation_proof(record, "upload")?;
            let mirror: IcloudpdLocalMirrorProof =
                generation_proof(record, "icloudpd_local_mirror")?;
            let original: OriginalAssetProof = generation_proof(record, "original_asset")?;
            let final_path = upload
                .uploaded_heic_path
                .clone()
                .ok_or_else(|| failure("proof_binding"))?;
            let raw_filename = record
                .raw_path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| failure("proof_binding"))?;
            if nas.canonical_path != record.raw_path
                || nas.sha256 != original.matched_raw_sha256
                || nas.size_bytes != original.size_bytes
                || original.filename != raw_filename
                || conversion.heic_path != final_path
                || conversion.heic_sha256 != heic.heic_sha256
                || conversion.size_bytes != heic.size_bytes
                || heic.heic_path != final_path
                || !heic.heif_info_ok
                || !heic.metadata_copied
                || !heic.visual_content_ok
                || !heic.visual_match_ok
                || upload.uploaded_heic_sha256 != heic.heic_sha256
                || upload.uploaded_heic_asset_id != mirror.uploaded_heic_asset_id
                || upload.uploaded_heic_sha256 != mirror.uploaded_heic_sha256
                || mirror.uploaded_heic_path != final_path
                || mirror.size_bytes != heic.size_bytes
                || upload.database_scope != original.database_scope
                || upload.zone_name != original.zone_name
                || upload.owner_record_name != original.owner_record_name
            {
                return Err(failure("proof_binding"));
            }
            let mut raw = HeldGenerationSource::open(&record.raw_path)?;
            let mut final_heic = HeldGenerationSource::open(&final_path)?;
            let mut mirror_source = HeldGenerationSource::open(&mirror.icloudpd_download_path)?;
            if raw.sha256 != nas.sha256
                || raw.metadata.size != nas.size_bytes
                || mirror_source.sha256 != upload.uploaded_heic_sha256
                || mirror_source.metadata.size != heic.size_bytes
                || [
                    raw.identity(),
                    final_heic.identity(),
                    mirror_source.identity(),
                ]
                .into_iter()
                .collect::<BTreeSet<_>>()
                .len()
                    != 3
            {
                return Err(failure("source_binding"));
            }
            let record_sha256 = legacy_upload_migration_record_digest(record)
                .map_err(|_| failure("record_digest"))?;
            assets.push(EvidenceAsset {
                asset_id: record.asset_id.clone(),
                record_sha256: record_sha256.clone(),
            });
            raw_inputs.push(EvidenceRawInput {
                asset_id: record.asset_id.clone(),
                path: record.raw_path.clone(),
                source: raw.quarantine_identity(),
            });

            let final_matches_upload = final_heic.sha256 == upload.uploaded_heic_sha256
                && final_heic.metadata.size == heic.size_bytes;
            if !final_matches_upload {
                let resolved =
                    resolver.resolve_uploaded_heic(&CloudKitUploadedHeicResolveRequest {
                        uploaded_asset_id: upload.uploaded_heic_asset_id.clone(),
                        expected_heic_sha256: upload.uploaded_heic_sha256.clone(),
                        expected_size_bytes: heic.size_bytes,
                        database_scope: upload.database_scope,
                        zone_name: upload.zone_name.clone(),
                        owner_record_name: upload.owner_record_name.clone(),
                    })?;
                if resolved.record_name != upload.uploaded_heic_asset_id
                    || resolved.matched_heic_sha256 != upload.uploaded_heic_sha256
                    || resolved.size_bytes != heic.size_bytes
                    || !valid_identity(&resolved.record_change_tag)
                    || !valid_identity(&resolved.master_record_name)
                    || resolved.master_record_name == original.record_name
                    || resolved.master_record_name == resolved.record_name
                    || resolved.record_name == original.record_name
                {
                    return Err(failure("cloudkit_binding"));
                }
                let original_remote = resolver.validate_original_active(&original)?;
                let filename = final_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| failure("proof_binding"))?
                    .to_string();
                let destination = EvidenceDestination {
                    database_scope: upload.database_scope,
                    zone_name: upload.zone_name.clone(),
                    owner_record_name: upload.owner_record_name.clone(),
                    filename,
                };
                retired_replacements.push(EvidenceRetiredReplacement {
                    asset_id: record.asset_id.clone(),
                    uploaded_asset_id: resolved.record_name,
                    uploaded_master_id: resolved.master_record_name,
                    owner_record_name_sha256: resolved.owner_record_name_sha256,
                    initial_remote_state: resolved.initial_remote_state,
                    initial_state_lookup_mode: resolved.initial_state_lookup_mode,
                    destination_sha256: digest_value(&destination)?,
                    destination,
                    old_record_change_tag: resolved.record_change_tag,
                    uploaded_heic_sha256: upload.uploaded_heic_sha256.clone(),
                    uploaded_heic_size_bytes: heic.size_bytes,
                    original_asset_record_name: original.record_name.clone(),
                    original_record_change_tag: original.record_change_tag.clone(),
                    original_remote_state: original_remote.remote_state,
                    original_state_lookup_mode: original_remote.lookup_mode,
                    original_asset_identity_sha256: digest_value(
                        record
                            .proofs
                            .get("original_asset")
                            .ok_or_else(|| failure("proof_missing"))?,
                    )?,
                    old_conversion_lineage_sha256: digest_value(
                        record
                            .proofs
                            .get("conversion")
                            .ok_or_else(|| failure("proof_missing"))?,
                    )?,
                    old_upload_lineage_sha256: digest_value(
                        record
                            .proofs
                            .get("upload")
                            .ok_or_else(|| failure("proof_missing"))?,
                    )?,
                    old_mirror_lineage_sha256: digest_value(
                        record
                            .proofs
                            .get("icloudpd_local_mirror")
                            .ok_or_else(|| failure("proof_missing"))?,
                    )?,
                });
                quarantine_members.push(EvidenceQuarantineMember {
                    asset_id: record.asset_id.clone(),
                    kind: LegacyUploadMigrationQuarantineKind::Final,
                    source_path: final_path.clone(),
                    source: final_heic.quarantine_identity(),
                    root_device: final_heic.metadata.dev,
                });
                quarantine_members.push(EvidenceQuarantineMember {
                    asset_id: record.asset_id.clone(),
                    kind: LegacyUploadMigrationQuarantineKind::OldMirror,
                    source_path: mirror.icloudpd_download_path.clone(),
                    source: mirror_source.quarantine_identity(),
                    root_device: mirror_source.metadata.dev,
                });
            }

            let reference = if let Some(reference_index) = REFERENCE_ASSET_INDICES
                .iter()
                .position(|candidate| *candidate == index)
            {
                let mut reference_path = final_path.clone();
                reference_path.set_extension("oriented-preview.jpg");
                let mut source = HeldGenerationSource::open(&reference_path)?;
                if [
                    raw.identity(),
                    final_heic.identity(),
                    mirror_source.identity(),
                ]
                .contains(&source.identity())
                    || [
                        raw.sha256.as_str(),
                        final_heic.sha256.as_str(),
                        mirror_source.sha256.as_str(),
                    ]
                    .contains(&source.sha256.as_str())
                {
                    return Err(failure("reference_distinct"));
                }
                let image = probe_held_reference(
                    &mut source,
                    request.image_timeout_seconds,
                    reference_probe,
                )?;
                if image.orientation != REFERENCE_ORIENTATIONS[reference_index]
                    || image.width == 0
                    || image.height == 0
                    || !is_digest(&image.decoded_pixel_sha256)
                {
                    return Err(failure("reference_image"));
                }
                let mut evidence = EvidenceReferenceNormalization {
                    asset_id: record.asset_id.clone(),
                    asset_record_sha256: record_sha256,
                    reference_identity_sha256: String::new(),
                    reference_path: reference_path.clone(),
                    device: source.metadata.dev,
                    inode: source.metadata.ino,
                    size_bytes: source.metadata.size,
                    file_sha256: source.sha256.clone(),
                    orientation: image.orientation,
                    width: image.width,
                    height: image.height,
                    decoded_pixel_sha256: image.decoded_pixel_sha256,
                };
                evidence.reference_identity_sha256 =
                    canonical_digest(&ReferenceIdentityDigestInput {
                        schema_version: EVIDENCE_SCHEMA_VERSION,
                        asset_id: &evidence.asset_id,
                        reference_path: &evidence.reference_path,
                        device: evidence.device,
                        inode: evidence.inode,
                        size_bytes: evidence.size_bytes,
                        file_sha256: &evidence.file_sha256,
                        orientation: evidence.orientation,
                        width: evidence.width,
                        height: evidence.height,
                        decoded_pixel_sha256: &evidence.decoded_pixel_sha256,
                    })
                    .map_err(|_| failure("reference_witness"))?;
                reference_normalizations.push(evidence);
                quarantine_members.push(EvidenceQuarantineMember {
                    asset_id: record.asset_id.clone(),
                    kind: LegacyUploadMigrationQuarantineKind::Reference,
                    source_path: reference_path,
                    source: source.quarantine_identity(),
                    root_device: source.metadata.dev,
                });
                Some(source)
            } else {
                None
            };
            raw.revalidate()?;
            final_heic.revalidate()?;
            mirror_source.revalidate()?;
            held_assets.push(HeldGenerationAsset {
                raw,
                final_heic,
                mirror: mirror_source,
                reference,
            });
        }
        if retired_replacements.len() != RETIRED_REPLACEMENT_COUNT
            || reference_normalizations.len() != REFERENCE_COUNT
            || quarantine_members.len() != 9
        {
            return Err(failure("candidate_count"));
        }
        quarantine_members.sort_by(|left, right| {
            (&left.asset_id, left.kind, &left.source_path).cmp(&(
                &right.asset_id,
                right.kind,
                &right.source_path,
            ))
        });
        let member_devices = quarantine_members
            .iter()
            .map(|member| member.source.device)
            .collect::<BTreeSet<_>>();
        let root_devices = quarantine_roots
            .iter()
            .map(|root| root.device)
            .collect::<BTreeSet<_>>();
        if member_devices != root_devices
            || quarantine_members
                .iter()
                .any(|member| member.root_device != member.source.device)
        {
            return Err(failure("quarantine_mapping"));
        }
        validate_retired_replacement_pair(&retired_replacements)?;
        let cohort_source_identities = held_assets
            .iter()
            .flat_map(|held| {
                [
                    held.raw.identity(),
                    held.final_heic.identity(),
                    held.mirror.identity(),
                ]
            })
            .collect::<BTreeSet<_>>();
        let reference_identities = held_assets
            .iter()
            .filter_map(|held| held.reference.as_ref().map(HeldGenerationSource::identity))
            .collect::<Vec<_>>();
        let cohort_source_sha256 = held_assets
            .iter()
            .flat_map(|held| {
                [
                    held.raw.sha256.as_str(),
                    held.final_heic.sha256.as_str(),
                    held.mirror.sha256.as_str(),
                ]
            })
            .collect::<BTreeSet<_>>();
        let reference_sha256 = held_assets
            .iter()
            .filter_map(|held| held.reference.as_ref().map(|source| source.sha256.as_str()))
            .collect::<Vec<_>>();
        if reference_identities.len() != REFERENCE_COUNT
            || reference_identities
                .iter()
                .any(|identity| cohort_source_identities.contains(identity))
            || reference_identities
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != REFERENCE_COUNT
            || reference_sha256
                .iter()
                .any(|sha256| cohort_source_sha256.contains(sha256))
            || reference_sha256
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != REFERENCE_COUNT
        {
            return Err(failure("reference_distinct"));
        }

        let manifest_target_sha256 =
            canonical_digest(&assets).map_err(|_| failure("manifest_target_digest"))?;
        let cloudkit_target_sha256 = canonical_digest(&retired_replacements)
            .map_err(|_| failure("cloudkit_target_digest"))?;
        let migration_id = canonical_digest(&(
            EVIDENCE_SCHEMA_VERSION,
            "legacy-uploaded-heic-evidence-generator-v1",
            &manifest_target_sha256,
            &cloudkit_target_sha256,
        ))
        .map_err(|_| failure("migration_digest"))?;
        let mut document = EvidenceDocument {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            migration_id,
            asset_count: ASSET_COUNT as u64,
            retired_replacement_count: RETIRED_REPLACEMENT_COUNT as u64,
            reference_count: REFERENCE_COUNT as u64,
            cohort_sha256: String::new(),
            assets,
            retired_replacements,
            reference_normalizations,
            quarantine_roots,
            quarantine_members,
            raw_inputs,
        };
        document.cohort_sha256 = canonical_digest(&CohortDigestInput {
            schema_version: document.schema_version,
            migration_id: &document.migration_id,
            asset_count: document.asset_count,
            retired_replacement_count: document.retired_replacement_count,
            reference_count: document.reference_count,
            assets: &document.assets,
            retired_replacements: &document.retired_replacements,
            reference_normalizations: &document.reference_normalizations,
            quarantine_roots: &document.quarantine_roots,
            quarantine_members: &document.quarantine_members,
            raw_inputs: &document.raw_inputs,
        })
        .map_err(|_| failure("cohort_digest"))?;
        let bytes = serde_json::to_vec(&document).map_err(|_| failure("evidence_encode"))?;
        let evidence_sha256 = sha256_bytes(&bytes);
        let audit_request = LegacyUploadEvidenceAuditRequest {
            manifest_path: request.manifest_path.clone(),
            evidence_path: request.output_path.clone(),
            expected_evidence_sha256: evidence_sha256.clone(),
            expected_asset_count: ASSET_COUNT as u64,
            expected_retired_replacement_count: RETIRED_REPLACEMENT_COUNT as u64,
            expected_reference_count: REFERENCE_COUNT as u64,
            expected_cohort_sha256: document.cohort_sha256.clone(),
        };
        validate_document(document, &evidence_sha256, &audit_request, &manifest, None)?;
        run_generation_pre_output_hook();
        for held in &mut held_assets {
            held.revalidate()?;
        }
        checkpoint_source.revalidate()?;
        state_store
            .revalidate_immutable_read_snapshot()
            .map_err(|_| failure("state_changed"))?;
        if state_store
            .json_checkpoint_status()
            .map_err(|_| failure("checkpoint_changed"))?
            != JsonCheckpointStatus::Current
        {
            return Err(failure("checkpoint_changed"));
        }
        write_generated_evidence(
            &audit_request,
            &bytes,
            &mut held_assets,
            &mut checkpoint_source,
            &state_store,
        )?;
        Ok(LegacyUploadEvidenceGenerateReport {
            evidence_sha256,
            cohort_sha256: audit_request.expected_cohort_sha256,
            manifest_target_sha256,
            cloudkit_target_sha256,
            asset_count: ASSET_COUNT as u64,
            retired_replacement_count: RETIRED_REPLACEMENT_COUNT as u64,
            reference_count: REFERENCE_COUNT as u64,
        })
    }
}

fn generation_proof<T: for<'de> Deserialize<'de>>(
    record: &AssetRecord,
    name: &'static str,
) -> Result<T, LegacyUploadEvidenceError> {
    serde_json::from_value(
        record
            .proofs
            .get(name)
            .cloned()
            .ok_or_else(|| failure("proof_missing"))?,
    )
    .map_err(|_| failure("proof_schema"))
}

#[cfg(unix)]
fn write_generated_evidence(
    audit_request: &LegacyUploadEvidenceAuditRequest,
    bytes: &[u8],
    held_assets: &mut [HeldGenerationAsset],
    checkpoint_source: &mut HeldGenerationSource,
    state_store: &AssetStateStore,
) -> Result<(), LegacyUploadEvidenceError> {
    let parent = audit_request
        .evidence_path
        .parent()
        .ok_or_else(|| failure("output_parent"))?;
    let file_name = audit_request
        .evidence_path
        .file_name()
        .ok_or_else(|| failure("output_parent"))?;
    let file_name = CString::new(file_name.as_bytes()).map_err(|_| failure("output_parent"))?;
    let mut parent_options = OpenOptions::new();
    parent_options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let parent_directory = parent_options
        .open(parent)
        .map_err(|_| failure("output_parent"))?;
    let parent_metadata = parent_directory
        .metadata()
        .map_err(|_| failure("output_parent"))?;
    if !parent_metadata.is_dir() {
        return Err(failure("output_parent"));
    }
    let parent_identity = EvidenceMetadata::capture(&parent_metadata);
    // SAFETY: parent_directory is a live directory descriptor, file_name is a valid C string,
    // and the returned descriptor is immediately owned by File on success.
    let descriptor = unsafe {
        libc::openat(
            parent_directory.as_raw_fd(),
            file_name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(failure("output_create"));
    }
    // SAFETY: openat returned a new owned descriptor which is transferred exactly once.
    let mut output = unsafe { fs::File::from_raw_fd(descriptor) };
    let initial_metadata =
        EvidenceMetadata::capture(&output.metadata().map_err(|_| failure("output_metadata"))?);
    run_generation_post_output_create_hook();
    let result = (|| {
        // SAFETY: geteuid has no preconditions and does not dereference pointers.
        let current_euid = unsafe { libc::geteuid() };
        validate_evidence_attributes(
            initial_metadata.is_regular,
            initial_metadata.mode,
            initial_metadata.uid,
            initial_metadata.nlink,
            current_euid,
        )
        .map_err(|_| failure("output_metadata"))?;
        std::io::Write::write_all(&mut output, bytes).map_err(|_| failure("output_write"))?;
        output.sync_all().map_err(|_| failure("output_sync"))?;
        parent_directory
            .sync_all()
            .map_err(|_| failure("output_sync"))?;
        let committed_metadata =
            EvidenceMetadata::capture(&output.metadata().map_err(|_| failure("output_verify"))?);
        if committed_metadata.dev != initial_metadata.dev
            || committed_metadata.ino != initial_metadata.ino
            || committed_metadata.size != bytes.len() as u64
        {
            return Err(failure("output_verify"));
        }
        output
            .seek(SeekFrom::Start(0))
            .map_err(|_| failure("output_verify"))?;
        let mut reread = Vec::new();
        Read::read_to_end(&mut output, &mut reread).map_err(|_| failure("output_verify"))?;
        let held_metadata =
            EvidenceMetadata::capture(&output.metadata().map_err(|_| failure("output_verify"))?);
        let named_metadata = EvidenceMetadata::capture(
            &fs::symlink_metadata(&audit_request.evidence_path)
                .map_err(|_| failure("output_verify"))?,
        );
        let current_parent = EvidenceMetadata::capture(
            &fs::symlink_metadata(parent).map_err(|_| failure("output_verify"))?,
        );
        if reread != bytes
            || sha256_bytes(&reread) != audit_request.expected_evidence_sha256
            || held_metadata != committed_metadata
            || named_metadata != held_metadata
            || current_parent.dev != parent_identity.dev
            || current_parent.ino != parent_identity.ino
        {
            return Err(failure("output_verify"));
        }
        let audit = audit_legacy_uploaded_heic_evidence(audit_request)?;
        if audit.evidence_sha256 != audit_request.expected_evidence_sha256
            || audit.cohort_sha256 != audit_request.expected_cohort_sha256
        {
            return Err(failure("output_round_trip"));
        }
        for held in held_assets {
            held.revalidate()?;
        }
        checkpoint_source.revalidate()?;
        state_store
            .revalidate_immutable_read_snapshot()
            .map_err(|_| failure("state_changed"))?;
        if state_store
            .json_checkpoint_status()
            .map_err(|_| failure("checkpoint_changed"))?
            != JsonCheckpointStatus::Current
        {
            return Err(failure("checkpoint_changed"));
        }
        Ok(())
    })();
    if let Err(error) = result {
        // SAFETY: the held directory and valid C string remain live. The returned descriptor,
        // when nonnegative, is transferred exactly once to File.
        let current_descriptor = unsafe {
            libc::openat(
                parent_directory.as_raw_fd(),
                file_name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if current_descriptor >= 0 {
            // SAFETY: openat returned a new owned descriptor.
            let current = unsafe { fs::File::from_raw_fd(current_descriptor) };
            if current.metadata().ok().is_some_and(|metadata| {
                let identity = EvidenceMetadata::capture(&metadata);
                identity.dev == initial_metadata.dev && identity.ino == initial_metadata.ino
            }) {
                // SAFETY: the immediately preceding anchored open proved this name still denotes
                // the exact file created by this invocation.
                let _ =
                    unsafe { libc::unlinkat(parent_directory.as_raw_fd(), file_name.as_ptr(), 0) };
            }
        }
        let _ = parent_directory.sync_all();
        return Err(error);
    }
    Ok(())
}

pub(crate) fn audit_legacy_uploaded_heic_evidence(
    request: &LegacyUploadEvidenceAuditRequest,
) -> Result<LegacyUploadEvidenceAudit, LegacyUploadEvidenceError> {
    Ok(load_validated_legacy_uploaded_heic_evidence(request)?
        .audit()
        .clone())
}

pub(crate) fn audit_legacy_uploaded_heic_evidence_with_device_recovery(
    request: &LegacyUploadEvidenceAuditRequest,
    recovery: &LegacyUploadDeviceRecoveryRequest,
) -> Result<LegacyUploadEvidenceAudit, LegacyUploadEvidenceError> {
    Ok(
        load_validated_legacy_uploaded_heic_evidence_with_device_recovery(request, Some(recovery))?
            .audit()
            .clone(),
    )
}

#[cfg(all(target_os = "macos", not(test)))]
fn current_recovery_signer() -> Result<DeviceRecoverySigner, LegacyUploadEvidenceError> {
    let executable = std::env::current_exe().map_err(|_| failure("recovery_signer"))?;
    recovery_signer_for_executable(&executable)
}

#[cfg(test)]
fn load_prior_recovery_service_bundle(
    bundle: &Path,
) -> Result<
    (
        crate::authorization_policy::AuthorizationPolicy,
        crate::authorization_policy::AuthorizationProvenance,
    ),
    LegacyUploadEvidenceError,
> {
    crate::authorization_policy::load_sealed_for_recovery_rotation_test(bundle, unsafe {
        libc::geteuid()
    })
    .map_err(|_| failure("recovery_signer"))
}

fn revalidate_prior_recovery_service_bundle(
    bundle: &Path,
    expected_signer: &DeviceRecoverySigner,
) -> Result<(), LegacyUploadEvidenceError> {
    let (policy, provenance) = load_prior_recovery_service_bundle(bundle)?;
    let helper_relative = policy
        .helper_relative_path
        .as_deref()
        .ok_or_else(|| failure("recovery_signer"))?;
    let helper_path = bundle.join(helper_relative);
    let signer = recovery_signer_for_executable(&helper_path)?;
    let requirement = policy
        .helper_designated_requirement
        .as_deref()
        .ok_or_else(|| failure("recovery_signer"))?;
    if signer != *expected_signer
        || provenance.helper_sha256 != expected_signer.executable_sha256
        || sha256_bytes(requirement.as_bytes()) != expected_signer.designated_requirement_sha256
    {
        return Err(failure("recovery_signer_mismatch"));
    }
    Ok(())
}

#[cfg(not(test))]
fn load_prior_recovery_service_bundle(
    bundle: &Path,
) -> Result<
    (
        crate::authorization_policy::AuthorizationPolicy,
        crate::authorization_policy::AuthorizationProvenance,
    ),
    LegacyUploadEvidenceError,
> {
    crate::authorization_policy::load_sealed_for_recovery_rotation(bundle, unsafe {
        libc::geteuid()
    })
    .map_err(|_| failure("recovery_signer"))
}

#[cfg(all(target_os = "macos", not(test)))]
fn recovery_signer_for_executable(
    executable: &Path,
) -> Result<DeviceRecoverySigner, LegacyUploadEvidenceError> {
    if !safe_absolute_path(executable)
        || fs::canonicalize(executable).map_err(|_| failure("recovery_signer"))? != executable
    {
        return Err(failure("recovery_signer"));
    }
    let verify = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--verbose=2"])
        .arg(executable)
        .output()
        .map_err(|_| failure("recovery_signer"))?;
    if !verify.status.success() {
        return Err(failure("recovery_signer"));
    }
    let requirement = Command::new("/usr/bin/codesign")
        .args(["-d", "-r-"])
        .arg(executable)
        .output()
        .map_err(|_| failure("recovery_signer"))?;
    if !requirement.status.success() {
        return Err(failure("recovery_signer"));
    }
    let designated = parse_designated_requirement(&requirement.stdout, &requirement.stderr)?;
    let mut executable_file =
        HeldGenerationSource::open(executable).map_err(|_| failure("recovery_signer"))?;
    executable_file.revalidate()?;
    if executable_file.metadata.uid != unsafe { libc::geteuid() }
        || executable_file.metadata.mode & 0o022 != 0
    {
        return Err(failure("recovery_signer"));
    }
    Ok(DeviceRecoverySigner {
        executable_sha256: executable_file.sha256,
        designated_requirement_sha256: sha256_bytes(designated.as_bytes()),
    })
}

#[cfg(test)]
fn recovery_signer_for_executable(
    executable: &Path,
) -> Result<DeviceRecoverySigner, LegacyUploadEvidenceError> {
    let mut executable_file = HeldGenerationSource::open(executable)?;
    executable_file.revalidate()?;
    Ok(DeviceRecoverySigner {
        executable_sha256: executable_file.sha256,
        designated_requirement_sha256: sha256_bytes(
            b"designated => anchor apple generic and identifier \"com.icloudpd-optimizer.helper\" and certificate leaf[subject.OU] = \"3B86NGN2ZD\"",
        ),
    })
}

#[cfg(all(not(target_os = "macos"), not(test)))]
fn recovery_signer_for_executable(
    _executable: &Path,
) -> Result<DeviceRecoverySigner, LegacyUploadEvidenceError> {
    Err(failure("recovery_unsigned"))
}

fn parse_designated_requirement(
    stdout: &[u8],
    stderr: &[u8],
) -> Result<String, LegacyUploadEvidenceError> {
    const REQUIREMENT_PREFIX: &str = "designated => anchor apple generic and identifier \"com.icloudpd-optimizer.helper\" and certificate leaf[subject.OU] = \"";
    let mut designated = None;
    for stream in [stdout, stderr] {
        let rendered = std::str::from_utf8(stream).map_err(|_| failure("recovery_signer"))?;
        for line in rendered.lines() {
            if line.starts_with("designated => ") && designated.replace(line.to_owned()).is_some() {
                return Err(failure("recovery_signer"));
            }
        }
    }
    let designated = designated.ok_or_else(|| failure("recovery_signer"))?;
    let team_id = designated
        .strip_prefix(REQUIREMENT_PREFIX)
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| {
            value.len() == 10
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        })
        .ok_or_else(|| failure("recovery_signer"))?;
    debug_assert!(!team_id.is_empty());
    Ok(designated)
}

#[cfg(test)]
fn current_recovery_signer() -> Result<DeviceRecoverySigner, LegacyUploadEvidenceError> {
    DEVICE_RECOVERY_SIGNER_HOOK
        .with(|slot| slot.borrow().clone())
        .ok_or_else(|| failure("recovery_signer"))
}

#[cfg(all(not(target_os = "macos"), not(test)))]
fn current_recovery_signer() -> Result<DeviceRecoverySigner, LegacyUploadEvidenceError> {
    Err(failure("recovery_unsigned"))
}

#[cfg(unix)]
fn device_recovery_root_mappings(
    document: &EvidenceDocument,
    require_empty_cohorts: bool,
) -> Result<Vec<DeviceRecoveryMapping>, LegacyUploadEvidenceError> {
    let mut mapping = BTreeMap::new();
    let mut current_devices = BTreeSet::new();
    let mut mappings = Vec::with_capacity(document.quarantine_roots.len());
    for root in &document.quarantine_roots {
        if fs::canonicalize(&root.canonical_path).map_err(|_| failure("recovery_root"))?
            != root.canonical_path
        {
            return Err(failure("recovery_root"));
        }
        let metadata =
            fs::symlink_metadata(&root.canonical_path).map_err(|_| failure("recovery_root"))?;
        if !metadata.is_dir()
            || metadata.ino() != root.inode
            || metadata.uid() != root.owner
            || metadata.mode() & 0o777 != root.mode
            || metadata.dev() == 0
            || mapping.insert(root.device, metadata.dev()).is_some()
            || !current_devices.insert(metadata.dev())
        {
            return Err(failure("recovery_root"));
        }
        let cohort = root.canonical_path.join(&document.cohort_sha256);
        let cohort_metadata =
            fs::symlink_metadata(&cohort).map_err(|_| failure("recovery_root"))?;
        if !cohort_metadata.is_dir()
            || cohort_metadata.dev() != metadata.dev()
            || cohort_metadata.uid() != root.owner
            || cohort_metadata.mode() & 0o777 != 0o700
            || require_empty_cohorts
                && fs::read_dir(&cohort)
                    .map_err(|_| failure("recovery_root"))?
                    .next()
                    .is_some()
        {
            return Err(failure("recovery_root"));
        }
        mappings.push(DeviceRecoveryMapping {
            previous_device: root.device,
            current_device: metadata.dev(),
            root_path_sha256: canonical_digest(&root.canonical_path)
                .map_err(|_| failure("recovery_root"))?,
            root_inode: root.inode,
        });
    }
    if mapping.len() != document.quarantine_roots.len()
        || mapping
            .iter()
            .all(|(previous, current)| previous == current)
    {
        return Err(failure("recovery_mapping"));
    }
    mappings.sort_by_key(|item| item.previous_device);
    Ok(mappings)
}

#[cfg(unix)]
fn operational_document_for_device_recovery_with_mode(
    document: &EvidenceDocument,
    manifest: &Manifest,
    allow_partial_quarantine: bool,
) -> Result<(EvidenceDocument, Vec<DeviceRecoveryMapping>), LegacyUploadEvidenceError> {
    let phase = coherent_retired_replacement_phase(document, manifest)?;
    if phase != Some(super::LegacyUploadMigrationPhase::DeleteConfirmed) {
        return Err(failure("recovery_phase"));
    }
    let mappings = device_recovery_root_mappings(document, !allow_partial_quarantine)?;
    let mut mapping = BTreeMap::new();
    for item in &mappings {
        mapping.insert(item.previous_device, item.current_device);
    }

    let mut operational = document.clone();
    for root in &mut operational.quarantine_roots {
        root.device = *mapping
            .get(&root.device)
            .ok_or_else(|| failure("recovery_mapping"))?;
    }
    operational.quarantine_roots.sort_by_key(|root| root.device);
    for member in &mut operational.quarantine_members {
        member.source.device = *mapping
            .get(&member.source.device)
            .ok_or_else(|| failure("recovery_mapping"))?;
        member.root_device = *mapping
            .get(&member.root_device)
            .ok_or_else(|| failure("recovery_mapping"))?;
        if !allow_partial_quarantine {
            let mut held = HeldGenerationSource::open(&member.source_path)?;
            if held.quarantine_identity() != member.source {
                return Err(failure("recovery_member"));
            }
            held.revalidate()?;
        }
    }
    for raw in &mut operational.raw_inputs {
        raw.source.device = *mapping
            .get(&raw.source.device)
            .ok_or_else(|| failure("recovery_mapping"))?;
        let mut held = HeldGenerationSource::open(&raw.path)?;
        if held.quarantine_identity() != raw.source {
            return Err(failure("recovery_raw"));
        }
        held.revalidate()?;
    }
    for reference in &mut operational.reference_normalizations {
        reference.device = *mapping
            .get(&reference.device)
            .ok_or_else(|| failure("recovery_mapping"))?;
    }
    if allow_partial_quarantine {
        validate_device_recovery_quarantine_layout(
            &operational,
            manifest,
            super::LegacyUploadMigrationPhase::DeleteConfirmed,
        )?;
    }
    let mut references = if allow_partial_quarantine {
        open_sealed_references_for_partial_recovery(&operational)?
    } else {
        open_sealed_references(&operational)?
    };
    revalidate_sealed_references(&mut references)?;
    let _ = quarantine_plan_from_document(&operational, manifest)?;
    Ok((operational, mappings))
}

#[cfg(unix)]
fn device_recovery_file_identity(
    path: &Path,
) -> Result<Option<LegacyUploadMigrationQuarantineFileIdentity>, LegacyUploadEvidenceError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let mut held =
                HeldGenerationSource::open(path).map_err(|_| failure("recovery_layout"))?;
            held.revalidate().map_err(|_| failure("recovery_layout"))?;
            Ok(Some(held.quarantine_identity()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(failure("recovery_layout")),
    }
}

#[cfg(unix)]
fn validate_device_recovery_normalized_reference(
    reference: &EvidenceReferenceNormalization,
    source_path: &Path,
    source: &LegacyUploadMigrationQuarantineFileIdentity,
    destination: &LegacyUploadMigrationQuarantineFileIdentity,
) -> Result<(), LegacyUploadEvidenceError> {
    let current_euid = unsafe { libc::geteuid() };
    if source.owner != current_euid
        || source.mode != 0o600
        || source.link_count != 1
        || source.device != destination.device
        || source.inode == destination.inode
        || source.size_bytes == 0
    {
        return Err(failure("recovery_layout"));
    }
    let probe = crate::monitor::reference_normalization_identity(source_path, 30)
        .map_err(|_| failure("recovery_layout"))?;
    if probe.orientation != 1
        || probe.width != reference.width
        || probe.height != reference.height
        || probe.decoded_pixel_sha256 != reference.decoded_pixel_sha256
    {
        return Err(failure("recovery_layout"));
    }
    Ok(())
}

/// Verify that a source-side Final file is the exact current conversion output
/// recorded by the authoritative manifest.  This is intentionally narrow: it
/// is only used for the exceptional source+destination layout that occurs when
/// the configured HEIC output path reuses the original source path.
#[cfg(unix)]
pub(super) fn is_verified_conversion_source_for_quarantine(
    manifest: &Manifest,
    phase: super::LegacyUploadMigrationPhase,
    asset_id: &str,
    source_path: &Path,
    source: &LegacyUploadMigrationQuarantineFileIdentity,
    original: &LegacyUploadMigrationQuarantineFileIdentity,
    root_device: u64,
) -> bool {
    if phase.index() < super::LegacyUploadMigrationPhase::Converted.index()
        || source.inode == original.inode
        || source.device != root_device
        || source.owner != unsafe { libc::geteuid() }
        || source.mode != 0o600
        || source.link_count != 1
        || source.size_bytes == 0
    {
        return false;
    }
    let Some((heic_path, heic_sha256, heic_size_bytes)) =
        manifest_verified_conversion_output(manifest, phase, asset_id)
    else {
        return false;
    };
    heic_path == source_path && source.sha256 == heic_sha256 && source.size_bytes == heic_size_bytes
}

#[cfg(unix)]
pub(super) fn is_verified_conversion_output_at_path(
    manifest: &Manifest,
    phase: super::LegacyUploadMigrationPhase,
    asset_id: &str,
    output_path: &Path,
) -> bool {
    manifest_verified_conversion_output(manifest, phase, asset_id)
        .is_some_and(|(path, _, _)| path == output_path)
}

#[cfg(unix)]
fn manifest_verified_conversion_output(
    manifest: &Manifest,
    phase: super::LegacyUploadMigrationPhase,
    asset_id: &str,
) -> Option<(PathBuf, String, u64)> {
    if phase.index() < super::LegacyUploadMigrationPhase::Converted.index() {
        return None;
    }
    let record = manifest.get(asset_id).ok()?;
    let journal = validate_legacy_upload_migration_record(record).ok()?;
    if journal
        .entries
        .last()
        .is_none_or(|entry| entry.phase != phase)
    {
        return None;
    }
    let conversion_value = record.proofs.get("conversion")?;
    let heic_value = record.proofs.get("heic")?;
    let conversion = canonical_proof::<ConversionResultProof>(conversion_value)?;
    let heic = canonical_proof::<HeicVerificationProof>(heic_value)?;
    if conversion.heic_path != heic.heic_path
        || conversion.heic_sha256 != heic.heic_sha256
        || conversion.size_bytes != heic.size_bytes
        || !heic.heif_info_ok
        || !heic.metadata_copied
        || !heic.visual_content_ok
        || !heic.visual_match_ok
    {
        return None;
    }
    Some((heic.heic_path, heic.heic_sha256, heic.size_bytes))
}

fn canonical_proof<T>(value: &Value) -> Option<T>
where
    T: DeserializeOwned + Serialize,
{
    let proof = serde_json::from_value(value.clone()).ok()?;
    (serde_json::to_value(&proof).ok()? == *value).then_some(proof)
}

#[cfg(unix)]
fn validate_device_recovery_quarantine_layout(
    document: &EvidenceDocument,
    manifest: &Manifest,
    phase: super::LegacyUploadMigrationPhase,
) -> Result<(), LegacyUploadEvidenceError> {
    let plan = quarantine_plan_from_document(document, manifest)?;
    if plan.roots.is_empty() || plan.members.len() != 9 || plan.raw_inputs.len() != ASSET_COUNT {
        return Err(failure("recovery_layout"));
    }

    let mut planned_destinations = BTreeMap::new();
    for member in &plan.members {
        let root = plan
            .roots
            .iter()
            .find(|root| root.device == member.root_device)
            .ok_or_else(|| failure("recovery_layout"))?;
        let cohort = root.canonical_path.join(&document.cohort_sha256);
        if member.destination_path.parent() != Some(cohort.as_path())
            || planned_destinations
                .insert(member.destination_path.clone(), member)
                .is_some()
        {
            return Err(failure("recovery_layout"));
        }
    }

    let mut cohort_entries = BTreeMap::new();
    for root in &plan.roots {
        if fs::canonicalize(&root.canonical_path).map_err(|_| failure("recovery_layout"))?
            != root.canonical_path
        {
            return Err(failure("recovery_layout"));
        }
        let root_metadata =
            fs::symlink_metadata(&root.canonical_path).map_err(|_| failure("recovery_layout"))?;
        if !root_metadata.is_dir()
            || root_metadata.dev() != root.device
            || root_metadata.ino() != root.inode
            || root_metadata.uid() != root.owner
            || root_metadata.mode() & 0o777 != root.mode
        {
            return Err(failure("recovery_layout"));
        }
        let cohort = root.canonical_path.join(&document.cohort_sha256);
        if fs::canonicalize(&cohort).map_err(|_| failure("recovery_layout"))? != cohort {
            return Err(failure("recovery_layout"));
        }
        let cohort_metadata =
            fs::symlink_metadata(&cohort).map_err(|_| failure("recovery_layout"))?;
        if !cohort_metadata.is_dir()
            || cohort_metadata.dev() != root.device
            || cohort_metadata.uid() != root.owner
            || cohort_metadata.mode() & 0o777 != 0o700
        {
            return Err(failure("recovery_layout"));
        }
        for entry in fs::read_dir(&cohort).map_err(|_| failure("recovery_layout"))? {
            let entry = entry.map_err(|_| failure("recovery_layout"))?;
            let path = entry.path();
            if !planned_destinations.contains_key(&path) || cohort_entries.contains_key(&path) {
                return Err(failure("recovery_layout"));
            }
            let identity =
                device_recovery_file_identity(&path)?.ok_or_else(|| failure("recovery_layout"))?;
            cohort_entries.insert(path, identity);
        }
    }

    let mut raw_paths = BTreeSet::new();
    let mut raw_identities = BTreeSet::new();
    for raw in &plan.raw_inputs {
        if !raw_paths.insert(raw.path.clone())
            || !raw_identities.insert((raw.source.device, raw.source.inode))
            || device_recovery_file_identity(&raw.path)?.as_ref() != Some(&raw.source)
        {
            return Err(failure("recovery_layout"));
        }
    }

    let mut member_paths = BTreeSet::new();
    let mut member_identities = BTreeSet::new();
    for member in &plan.members {
        if raw_paths.contains(&member.source_path)
            || !member_paths.insert(member.source_path.clone())
            || !member_identities.insert((member.source.device, member.source.inode))
        {
            return Err(failure("recovery_layout"));
        }
        let source = device_recovery_file_identity(&member.source_path)?;
        let destination = cohort_entries.get(&member.destination_path);
        if let Some(destination) = destination
            && destination != &member.source
        {
            return Err(failure("recovery_layout"));
        }
        match (source.as_ref(), destination) {
            (Some(source), None)
                if source == &member.source
                    && phase.index()
                        <= super::LegacyUploadMigrationPhase::DeleteConfirmed.index() => {}
            // Reset is the only pre-conversion phase in which a Final source may
            // be absent without a conversion proof. `ensure_reset` has already
            // removed the historical conversion/heic lineage at this point, so
            // the sealed destination identity and all gates above/below are the
            // complete recovery witness. Earlier phases must not be accepted as
            // a completed reset layout.
            (None, Some(_destination))
                if member.kind == LegacyUploadMigrationQuarantineKind::Final
                    && phase == super::LegacyUploadMigrationPhase::Reset => {}
            (None, Some(_destination))
                if member.kind == LegacyUploadMigrationQuarantineKind::Final
                    && phase.index() >= super::LegacyUploadMigrationPhase::Converted.index() =>
            {
                let Some((output_path, _, _)) =
                    manifest_verified_conversion_output(manifest, phase, &member.asset_id)
                else {
                    return Err(failure("recovery_layout"));
                };
                if output_path == member.source_path {
                    return Err(failure("recovery_layout"));
                }
            }
            (None, Some(_destination))
                if member.kind == LegacyUploadMigrationQuarantineKind::OldMirror
                    || member.kind == LegacyUploadMigrationQuarantineKind::Reference => {}
            (Some(source), Some(destination))
                if member.kind == LegacyUploadMigrationQuarantineKind::Reference =>
            {
                let reference = document
                    .reference_normalizations
                    .iter()
                    .find(|reference| reference.asset_id == member.asset_id)
                    .ok_or_else(|| failure("recovery_layout"))?;
                validate_device_recovery_normalized_reference(
                    reference,
                    &member.source_path,
                    source,
                    destination,
                )?;
            }
            (Some(source), Some(_destination))
                if member.kind == LegacyUploadMigrationQuarantineKind::Final
                    && is_verified_conversion_source_for_quarantine(
                        manifest,
                        phase,
                        &member.asset_id,
                        &member.source_path,
                        source,
                        &member.source,
                        member.root_device,
                    ) => {}
            _ => return Err(failure("recovery_layout")),
        }
        if let Some(source) = source {
            if source.device != member.root_device
                || (source != member.source
                    && !matches!(
                        member.kind,
                        LegacyUploadMigrationQuarantineKind::Reference
                            | LegacyUploadMigrationQuarantineKind::Final
                    ))
            {
                return Err(failure("recovery_layout"));
            }
            if raw_identities.contains(&(source.device, source.inode)) {
                return Err(failure("recovery_layout"));
            }
        }
        if let Some(destination) = destination
            && raw_identities.contains(&(destination.device, destination.inode))
        {
            return Err(failure("recovery_layout"));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn device_recovery_root_mappings(
    _document: &EvidenceDocument,
    _require_empty_cohorts: bool,
) -> Result<Vec<DeviceRecoveryMapping>, LegacyUploadEvidenceError> {
    Err(failure("unsupported_platform"))
}

#[cfg(not(unix))]
fn validate_device_recovery_quarantine_layout(
    _document: &EvidenceDocument,
    _manifest: &Manifest,
    _phase: super::LegacyUploadMigrationPhase,
) -> Result<(), LegacyUploadEvidenceError> {
    Err(failure("unsupported_platform"))
}

#[cfg(not(unix))]
fn operational_document_for_device_recovery_with_mode(
    _document: &EvidenceDocument,
    _manifest: &Manifest,
    _allow_partial_quarantine: bool,
) -> Result<(EvidenceDocument, Vec<DeviceRecoveryMapping>), LegacyUploadEvidenceError> {
    Err(failure("unsupported_platform"))
}

fn device_recovery_receipt_body(
    document: &EvidenceDocument,
    manifest: &Manifest,
    evidence_sha256: &str,
    expected_signer_designated_requirement_sha256: &str,
    allow_partial_quarantine: bool,
    original_destination_canonicalizations: Vec<OriginalDestinationCanonicalization>,
) -> Result<(DeviceRecoveryReceiptBody, EvidenceDocument), LegacyUploadEvidenceError> {
    let (operational, mappings) = operational_document_for_device_recovery_with_mode(
        document,
        manifest,
        allow_partial_quarantine,
    )?;
    if !is_digest(expected_signer_designated_requirement_sha256) {
        return Err(failure("recovery_signer_expected"));
    }
    let signer = current_recovery_signer()?;
    if signer.designated_requirement_sha256 != expected_signer_designated_requirement_sha256 {
        return Err(failure("recovery_signer_mismatch"));
    }
    let journal_anchors = device_recovery_journal_anchors(document, manifest)?;
    let body = DeviceRecoveryReceiptBody {
        schema_version: DEVICE_RECOVERY_SCHEMA_VERSION,
        evidence_sha256: evidence_sha256.to_string(),
        cohort_sha256: document.cohort_sha256.clone(),
        authoritative_manifest_sha256: canonical_digest(manifest.records())
            .map_err(|_| failure("recovery_manifest"))?,
        checkpoint_current: true,
        migration_phase: super::LegacyUploadMigrationPhase::DeleteConfirmed
            .as_str()
            .to_string(),
        mappings,
        journal_anchors,
        original_destination_canonicalizations,
        raw_input_count: operational.raw_inputs.len() as u64,
        quarantine_member_count: operational.quarantine_members.len() as u64,
        reference_count: operational.reference_normalizations.len() as u64,
        signer,
    };
    Ok((body, operational))
}

fn device_recovery_journal_anchors(
    document: &EvidenceDocument,
    manifest: &Manifest,
) -> Result<Vec<DeviceRecoveryJournalAnchor>, LegacyUploadEvidenceError> {
    let mut anchors = Vec::with_capacity(RETIRED_REPLACEMENT_COUNT);
    for replacement in &document.retired_replacements {
        let record = manifest
            .records()
            .get(&replacement.asset_id)
            .ok_or_else(|| failure("recovery_journal"))?;
        let journal = validate_legacy_upload_migration_record(record)
            .map_err(|_| failure("recovery_journal"))?;
        let (entry_index, entry) = journal
            .entries
            .iter()
            .enumerate()
            .rev()
            .find(|(_, entry)| entry.phase == super::LegacyUploadMigrationPhase::DeleteConfirmed)
            .ok_or_else(|| failure("recovery_phase"))?;
        anchors.push(DeviceRecoveryJournalAnchor {
            asset_id: replacement.asset_id.clone(),
            entry_count: entry_index as u64 + 1,
            delete_confirmed_entry_sha256: entry.entry_sha256.clone(),
        });
    }
    anchors.sort_by(|left, right| left.asset_id.cmp(&right.asset_id));
    Ok(anchors)
}

fn build_original_destination_canonicalizations(
    document: &EvidenceDocument,
    manifest: &Manifest,
    resolver: &mut impl LegacyUploadEvidenceResolver,
) -> Result<Vec<OriginalDestinationCanonicalization>, LegacyUploadEvidenceError> {
    if document.schema_version != EVIDENCE_SCHEMA_VERSION
        || document.retired_replacements.len() != RETIRED_REPLACEMENT_COUNT
        || document.assets.len() != ASSET_COUNT
        || document.reference_normalizations.len() != REFERENCE_COUNT
    {
        return Err(failure("evidence_count"));
    }
    if coherent_retired_replacement_phase(document, manifest)?
        != Some(super::LegacyUploadMigrationPhase::DeleteConfirmed)
    {
        return Err(failure("recovery_phase"));
    }
    let mut canonicalizations = Vec::new();
    for replacement in &document.retired_replacements {
        let record = manifest
            .records()
            .get(&replacement.asset_id)
            .ok_or_else(|| failure("original_canonicalization"))?;
        let original_value = proof(record, "original_asset")?;
        if original_asset_proof_destination_fields(original_value)? {
            continue;
        }
        if digest_value(original_value)? != replacement.original_asset_identity_sha256 {
            return Err(failure("original_canonicalization"));
        }
        let journal = validate_legacy_upload_migration_record(record)
            .map_err(|_| failure("original_canonicalization"))?;
        let identity = &journal.identity;
        if identity.asset_id != replacement.asset_id
            || identity.destination_sha256 != replacement.destination_sha256
            || identity.original_asset_identity_sha256 != replacement.original_asset_identity_sha256
            || digest_value(&replacement.destination)? != replacement.destination_sha256
        {
            return Err(failure("original_canonicalization"));
        }
        let delete_confirmed = journal
            .entries
            .last()
            .filter(|entry| entry.phase == super::LegacyUploadMigrationPhase::DeleteConfirmed)
            .ok_or_else(|| failure("original_canonicalization"))?;
        let mut canonical = original_value.clone();
        let object = canonical
            .as_object_mut()
            .ok_or_else(|| failure("original_canonicalization"))?;
        object.insert(
            "database_scope".to_string(),
            serde_json::to_value(replacement.destination.database_scope)
                .map_err(|_| failure("original_canonicalization"))?,
        );
        object.insert(
            "zone_name".to_string(),
            Value::String(replacement.destination.zone_name.clone()),
        );
        let original: OriginalAssetProof = serde_json::from_value(canonical.clone())
            .map_err(|_| failure("original_canonicalization"))?;
        if original.record_name != replacement.original_asset_record_name
            || original.record_change_tag != replacement.original_record_change_tag
            || original.database_scope != replacement.destination.database_scope
            || original.zone_name != replacement.destination.zone_name
            || original.owner_record_name != replacement.destination.owner_record_name
        {
            return Err(failure("original_canonicalization"));
        }
        let validation = resolver.validate_original_active(&original)?;
        if validation.remote_state != replacement.original_remote_state
            || validation.lookup_mode != CloudKitActiveAssetLookupMode::FullFields
        {
            return Err(failure("original_remote_state"));
        }
        canonicalizations.push(OriginalDestinationCanonicalization {
            asset_id: replacement.asset_id.clone(),
            original_asset_identity_sha256: replacement.original_asset_identity_sha256.clone(),
            destination_sha256: replacement.destination_sha256.clone(),
            canonical_original_asset_sha256: digest_value(&canonical)?,
            delete_confirmed_entry_sha256: delete_confirmed.entry_sha256.clone(),
            remote_state: validation.remote_state,
            lookup_mode: validation.lookup_mode,
        });
    }
    canonicalizations.sort_by(|left, right| left.asset_id.cmp(&right.asset_id));
    Ok(canonicalizations)
}

#[cfg(unix)]
struct CreatedRecoveryReceipt {
    sealed: SealedEvidence,
    parent: fs::File,
    name: CString,
}

#[cfg(unix)]
impl CreatedRecoveryReceipt {
    fn remove_exact(&mut self) {
        // SAFETY: parent and name remain live for the call. A successful openat returns one
        // descriptor which is transferred exactly once to File.
        let descriptor = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if descriptor < 0 {
            return;
        }
        // SAFETY: openat returned a new owned descriptor.
        let current = unsafe { fs::File::from_raw_fd(descriptor) };
        let matches = current.metadata().ok().is_some_and(|metadata| {
            EvidenceMetadata::capture(&metadata) == self.sealed.initial_metadata
        });
        drop(current);
        if matches {
            // SAFETY: the anchored open proved that this directory entry still denotes the
            // exact file created by this invocation.
            let _ = unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0) };
            let _ = self.parent.sync_all();
        }
    }
}

#[cfg(unix)]
fn write_new_owner_only_receipt(
    path: &Path,
    bytes: &[u8],
) -> Result<CreatedRecoveryReceipt, LegacyUploadEvidenceError> {
    if !safe_absolute_path(path)
        || bytes.is_empty()
        || bytes.len() as u64 > MAX_DEVICE_RECOVERY_BYTES
    {
        return Err(failure("recovery_output"));
    }
    let parent = path.parent().ok_or_else(|| failure("recovery_output"))?;
    let mut parent_options = OpenOptions::new();
    parent_options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let parent_directory = parent_options
        .open(parent)
        .map_err(|_| failure("recovery_output"))?;
    let parent_metadata = parent_directory
        .metadata()
        .map_err(|_| failure("recovery_output"))?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != unsafe { libc::geteuid() }
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(failure("recovery_output"));
    }
    let name = CString::new(
        path.file_name()
            .ok_or_else(|| failure("recovery_output"))?
            .as_bytes(),
    )
    .map_err(|_| failure("recovery_output"))?;
    // SAFETY: parent_directory and name are live. The flags forbid following links and require
    // creation of a new entry in the already-open owner-only directory.
    let descriptor = unsafe {
        libc::openat(
            parent_directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(failure("recovery_output"));
    }
    // SAFETY: openat returned a new owned descriptor.
    let mut output = unsafe { fs::File::from_raw_fd(descriptor) };
    let result = (|| {
        output
            .write_all(bytes)
            .and_then(|_| output.sync_all())
            .map_err(|_| failure("recovery_output"))?;
        output
            .seek(SeekFrom::Start(0))
            .map_err(|_| failure("recovery_output"))?;
        let mut reread = Vec::new();
        output
            .read_to_end(&mut reread)
            .map_err(|_| failure("recovery_output"))?;
        let metadata = output.metadata().map_err(|_| failure("recovery_output"))?;
        validate_evidence_metadata(&metadata).map_err(|_| failure("recovery_output"))?;
        if reread != bytes || metadata.len() != bytes.len() as u64 {
            return Err(failure("recovery_output"));
        }
        Ok(())
    })();
    if let Err(error) = result {
        let initial_metadata = output
            .metadata()
            .ok()
            .map(|metadata| EvidenceMetadata::capture(&metadata));
        if let Some(initial_metadata) = initial_metadata {
            let mut created = CreatedRecoveryReceipt {
                sealed: SealedEvidence {
                    bytes: bytes.to_vec(),
                    sha256: sha256_bytes(bytes),
                    file: output,
                    initial_metadata,
                },
                parent: parent_directory,
                name,
            };
            created.remove_exact();
        }
        return Err(error);
    }
    let initial_metadata =
        EvidenceMetadata::capture(&output.metadata().map_err(|_| failure("recovery_output"))?);
    let mut created = CreatedRecoveryReceipt {
        sealed: SealedEvidence {
            bytes: bytes.to_vec(),
            sha256: sha256_bytes(bytes),
            file: output,
            initial_metadata,
        },
        parent: parent_directory,
        name,
    };
    if created.parent.sync_all().is_err() {
        created.remove_exact();
        return Err(failure("recovery_output"));
    }
    Ok(created)
}

pub(crate) fn generate_legacy_uploaded_heic_device_recovery<
    T: CloudKitUploadedHeicReadTransport,
>(
    request: &LegacyUploadDeviceRecoveryGenerateRequest,
    session: &CloudKitDeleteSession,
    transport: &mut T,
) -> Result<LegacyUploadDeviceRecoveryGenerateReport, LegacyUploadEvidenceError> {
    let mut resolver = ProductionLegacyUploadEvidenceResolver { session, transport };
    generate_legacy_uploaded_heic_device_recovery_with_resolver(request, &mut resolver)
}

fn generate_legacy_uploaded_heic_device_recovery_with_resolver(
    request: &LegacyUploadDeviceRecoveryGenerateRequest,
    resolver: &mut impl LegacyUploadEvidenceResolver,
) -> Result<LegacyUploadDeviceRecoveryGenerateReport, LegacyUploadEvidenceError> {
    validate_public_request(&request.evidence)?;
    let mut sealed_evidence = read_sealed_evidence(&request.evidence.evidence_path)?;
    if sealed_evidence.sha256 != request.evidence.expected_evidence_sha256 {
        return Err(failure("evidence_digest"));
    }
    let document: EvidenceDocument =
        crate::strict_json::from_reader(sealed_evidence.bytes.as_slice())
            .map_err(|_| failure("evidence_schema"))?;
    let state_store = AssetStateStore::open_immutable_read_only(&request.evidence.manifest_path)
        .map_err(|_| failure("state_open"))?;
    let manifest = state_store.load().map_err(|_| failure("state_load"))?;
    let original_destination_canonicalizations =
        build_original_destination_canonicalizations(&document, &manifest, resolver)?;
    let _ = validate_document(
        document.clone(),
        &sealed_evidence.sha256,
        &request.evidence,
        &manifest,
        Some(&original_destination_canonicalizations),
    )?;
    if state_store
        .json_checkpoint_status_for_manifest(&manifest)
        .map_err(|_| failure("checkpoint_read"))?
        != JsonCheckpointStatus::Current
    {
        return Err(failure("checkpoint_stale"));
    }
    let (body, _) = device_recovery_receipt_body(
        &document,
        &manifest,
        &sealed_evidence.sha256,
        &request.expected_signer_designated_requirement_sha256,
        request.allow_partial_quarantine,
        original_destination_canonicalizations,
    )?;
    let body_sha256 = canonical_digest(&body).map_err(|_| failure("recovery_receipt"))?;
    let receipt = DeviceRecoveryReceipt { body, body_sha256 };
    let bytes = serde_json::to_vec(&receipt).map_err(|_| failure("recovery_receipt"))?;
    let receipt_sha256 = sha256_bytes(&bytes);
    let mut created = write_new_owner_only_receipt(&request.output_path, &bytes)?;
    run_device_recovery_post_output_hook();
    let result = (|| {
        state_store
            .revalidate_immutable_read_snapshot()
            .map_err(|_| failure("state_changed"))?;
        revalidate_sealed_evidence(&mut sealed_evidence, &request.evidence.evidence_path)?;
        if created.sealed.sha256 != receipt_sha256 || created.sealed.bytes != bytes {
            return Err(failure("recovery_output"));
        }
        revalidate_sealed_evidence(&mut created.sealed, &request.output_path)?;
        Ok(LegacyUploadDeviceRecoveryGenerateReport {
            receipt_sha256,
            evidence_sha256: receipt.body.evidence_sha256,
            cohort_sha256: receipt.body.cohort_sha256,
            partial_quarantine: request.allow_partial_quarantine,
            device_mapping_count: receipt.body.mappings.len() as u64,
            raw_input_count: receipt.body.raw_input_count,
            quarantine_member_count: receipt.body.quarantine_member_count,
            reference_count: receipt.body.reference_count,
            signer_designated_requirement_sha256: receipt.body.signer.designated_requirement_sha256,
        })
    })();
    if result.is_err() {
        created.remove_exact();
    }
    result
}

/// Rotate a recovery receipt across a signed-helper replacement.
///
/// The prior receipt is treated as an authorization witness, never as a
/// mutable input: its digest, body digest, sealed evidence/cohort, journal
/// anchors, device mapping, checkpoint, and exact on-disk quarantine layout
/// are all checked before the current helper signer is bound to a new
/// owner-only receipt.  The prior Service bundle is loaded through the same
/// sealed policy/provenance boundary used by normal service admission, so a
/// path or signature substitution cannot be accepted by a requirement hash
/// alone.
pub(crate) fn rotate_legacy_uploaded_heic_device_recovery(
    request: &LegacyUploadDeviceRecoveryRotateRequest,
    state_store: &AssetStateStore,
) -> Result<LegacyUploadDeviceRecoveryRotateReport, LegacyUploadEvidenceError> {
    validate_public_request(&request.evidence)?;
    if !is_digest(&request.expected_prior_receipt_sha256) {
        return Err(failure("recovery_expected_digest"));
    }

    // Rotation is an owner-authorized state transition.  An immutable reader is
    // intentionally insufficient: stale JSON may be repaired only by the
    // writer that holds the monitor lease.
    if state_store.writer_epoch().is_none() {
        return Err(failure("state_writer_required"));
    }

    let mut sealed_evidence = read_sealed_evidence(&request.evidence.evidence_path)?;
    if sealed_evidence.sha256 != request.evidence.expected_evidence_sha256 {
        return Err(failure("evidence_digest"));
    }
    let document: EvidenceDocument =
        crate::strict_json::from_reader(sealed_evidence.bytes.as_slice())
            .map_err(|_| failure("evidence_schema"))?;
    let manifest = state_store.load().map_err(|_| failure("state_load"))?;
    let checkpoint_recovered = state_store
        .json_checkpoint_status_for_manifest(&manifest)
        .map_err(|_| failure("checkpoint_read"))?
        == JsonCheckpointStatus::Stale;

    let mut sealed_prior = read_sealed_evidence(&request.prior_receipt_path)?;
    if sealed_prior.sha256 != request.expected_prior_receipt_sha256 {
        return Err(failure("recovery_digest"));
    }
    let prior_receipt: DeviceRecoveryReceipt =
        crate::strict_json::from_reader(sealed_prior.bytes.as_slice())
            .map_err(|_| failure("recovery_schema"))?;
    if canonical_digest(&prior_receipt.body).map_err(|_| failure("recovery_schema"))?
        != prior_receipt.body_sha256
    {
        return Err(failure("recovery_digest"));
    }

    let (prior_policy, prior_provenance) =
        load_prior_recovery_service_bundle(&request.prior_service_bundle)?;
    let prior_helper_relative = prior_policy
        .helper_relative_path
        .as_deref()
        .ok_or_else(|| failure("recovery_signer"))?;
    let prior_helper_path = request.prior_service_bundle.join(prior_helper_relative);
    let prior_signer = recovery_signer_for_executable(&prior_helper_path)?;
    let prior_requirement = prior_policy
        .helper_designated_requirement
        .as_deref()
        .ok_or_else(|| failure("recovery_signer"))?;
    if prior_signer.executable_sha256 != prior_receipt.body.signer.executable_sha256
        || prior_signer.designated_requirement_sha256
            != prior_receipt.body.signer.designated_requirement_sha256
        || prior_provenance.helper_sha256 != prior_receipt.body.signer.executable_sha256
        || sha256_bytes(prior_requirement.as_bytes())
            != prior_receipt.body.signer.designated_requirement_sha256
    {
        return Err(failure("recovery_signer_mismatch"));
    }

    let current_signer = current_recovery_signer()?;
    // The canonical designated requirement is deliberately kept stable across
    // helper rotations.  A different team or identifier is not a rotation.
    if current_signer.designated_requirement_sha256
        != prior_receipt.body.signer.designated_requirement_sha256
    {
        return Err(failure("recovery_signer_mismatch"));
    }
    validate_device_recovery_continuity_with_signer(
        &prior_receipt.body,
        &document,
        &manifest,
        &sealed_evidence.sha256,
        &prior_signer,
    )?;
    let phase = coherent_retired_replacement_phase(&document, &manifest)?
        .ok_or_else(|| failure("recovery_phase"))?;
    let operational = operational_document_from_recovery_receipt(&document, &prior_receipt.body)?;
    validate_device_recovery_quarantine_layout(&operational, &manifest, phase)?;
    let _ = quarantine_plan_from_document(&operational, &manifest)?;
    let _ = validate_document(
        document.clone(),
        &sealed_evidence.sha256,
        &request.evidence,
        &manifest,
        Some(&prior_receipt.body.original_destination_canonicalizations),
    )?;

    // The initial checks above deliberately happen before any checkpoint
    // mutation.  If the JSON checkpoint is stale, export exactly the manifest
    // read from the leased SQLite writer, then prove that the writer, sealed
    // inputs, and governed files are unchanged before constructing a receipt.
    if checkpoint_recovered {
        state_store
            .revalidate_legacy_upload_apply_state(&request.evidence.manifest_path, &manifest)
            .map_err(|_| failure("state_changed"))?;
        revalidate_sealed_evidence(&mut sealed_evidence, &request.evidence.evidence_path)?;
        revalidate_sealed_evidence(&mut sealed_prior, &request.prior_receipt_path)?;
        revalidate_prior_recovery_service_bundle(&request.prior_service_bundle, &prior_signer)?;
        validate_device_recovery_quarantine_layout(&operational, &manifest, phase)?;
        run_device_recovery_pre_checkpoint_export_hook();
        let _ = state_store
            .export_json()
            .map_err(|_| failure("checkpoint_export"))?;
        if state_store.load().map_err(|_| failure("state_load"))? != manifest {
            return Err(failure("state_changed"));
        }
        if state_store
            .json_checkpoint_status_for_manifest(&manifest)
            .map_err(|_| failure("checkpoint_read"))?
            != JsonCheckpointStatus::Current
        {
            return Err(failure("checkpoint_export"));
        }
        run_device_recovery_checkpoint_export_hook();
    }

    // A test-only hook models an adversarial boundary between validation and
    // the final receipt write.  Production has the same revalidation without
    // the hook, under the monitor run lock and writer lease.
    state_store
        .revalidate_legacy_upload_apply_state(&request.evidence.manifest_path, &manifest)
        .map_err(|_| failure("state_changed"))?;
    if state_store
        .json_checkpoint_status_for_manifest(&manifest)
        .map_err(|_| failure("checkpoint_read"))?
        != JsonCheckpointStatus::Current
    {
        return Err(failure("checkpoint_stale"));
    }
    revalidate_sealed_evidence(&mut sealed_evidence, &request.evidence.evidence_path)?;
    revalidate_sealed_evidence(&mut sealed_prior, &request.prior_receipt_path)?;
    revalidate_prior_recovery_service_bundle(&request.prior_service_bundle, &prior_signer)?;
    validate_device_recovery_quarantine_layout(&operational, &manifest, phase)?;
    let _ = validate_document(
        document.clone(),
        &sealed_evidence.sha256,
        &request.evidence,
        &manifest,
        Some(&prior_receipt.body.original_destination_canonicalizations),
    )?;

    let body = DeviceRecoveryReceiptBody {
        schema_version: DEVICE_RECOVERY_SCHEMA_VERSION,
        evidence_sha256: sealed_evidence.sha256.clone(),
        cohort_sha256: document.cohort_sha256.clone(),
        authoritative_manifest_sha256: canonical_digest(manifest.records())
            .map_err(|_| failure("recovery_manifest"))?,
        checkpoint_current: true,
        migration_phase: super::LegacyUploadMigrationPhase::DeleteConfirmed
            .as_str()
            .to_string(),
        mappings: prior_receipt.body.mappings.clone(),
        journal_anchors: device_recovery_journal_anchors(&document, &manifest)?,
        original_destination_canonicalizations: prior_receipt
            .body
            .original_destination_canonicalizations
            .clone(),
        raw_input_count: operational.raw_inputs.len() as u64,
        quarantine_member_count: operational.quarantine_members.len() as u64,
        reference_count: operational.reference_normalizations.len() as u64,
        signer: current_signer.clone(),
    };
    let body_sha256 = canonical_digest(&body).map_err(|_| failure("recovery_receipt"))?;
    let receipt = DeviceRecoveryReceipt { body, body_sha256 };
    let bytes = serde_json::to_vec(&receipt).map_err(|_| failure("recovery_receipt"))?;
    let receipt_sha256 = sha256_bytes(&bytes);
    let mut created = write_new_owner_only_receipt(&request.output_path, &bytes)?;
    run_device_recovery_post_output_hook();
    let result = (|| {
        state_store
            .revalidate_legacy_upload_apply_state(&request.evidence.manifest_path, &manifest)
            .map_err(|_| failure("state_changed"))?;
        if state_store
            .json_checkpoint_status_for_manifest(&manifest)
            .map_err(|_| failure("checkpoint_read"))?
            != JsonCheckpointStatus::Current
        {
            return Err(failure("checkpoint_stale"));
        }
        revalidate_sealed_evidence(&mut sealed_evidence, &request.evidence.evidence_path)?;
        revalidate_sealed_evidence(&mut sealed_prior, &request.prior_receipt_path)?;
        revalidate_prior_recovery_service_bundle(&request.prior_service_bundle, &prior_signer)?;
        validate_device_recovery_quarantine_layout(&operational, &manifest, phase)?;
        if created.sealed.sha256 != receipt_sha256 || created.sealed.bytes != bytes {
            return Err(failure("recovery_output"));
        }
        revalidate_sealed_evidence(&mut created.sealed, &request.output_path)?;
        Ok(LegacyUploadDeviceRecoveryRotateReport {
            previous_receipt_sha256: request.expected_prior_receipt_sha256.clone(),
            receipt_sha256,
            evidence_sha256: receipt.body.evidence_sha256,
            cohort_sha256: receipt.body.cohort_sha256,
            migration_phase: phase.as_str().to_string(),
            device_mapping_count: receipt.body.mappings.len() as u64,
            raw_input_count: receipt.body.raw_input_count,
            quarantine_member_count: receipt.body.quarantine_member_count,
            reference_count: receipt.body.reference_count,
            previous_signer_designated_requirement_sha256: prior_signer
                .designated_requirement_sha256,
            signer_designated_requirement_sha256: receipt.body.signer.designated_requirement_sha256,
            checkpoint_recovered,
        })
    })();
    if result.is_err() {
        created.remove_exact();
    }
    result
}

fn load_device_recovery(
    request: &LegacyUploadDeviceRecoveryRequest,
    document: &EvidenceDocument,
    manifest: &Manifest,
    evidence_sha256: &str,
) -> Result<(SealedDeviceRecovery, EvidenceDocument), LegacyUploadEvidenceError> {
    if !is_digest(&request.expected_receipt_sha256) {
        return Err(failure("recovery_expected_digest"));
    }
    let mut sealed = read_sealed_evidence(&request.receipt_path)?;
    if sealed.bytes.len() as u64 > MAX_DEVICE_RECOVERY_BYTES
        || sealed.sha256 != request.expected_receipt_sha256
    {
        return Err(failure("recovery_digest"));
    }
    let receipt: DeviceRecoveryReceipt = crate::strict_json::from_reader(sealed.bytes.as_slice())
        .map_err(|_| failure("recovery_schema"))?;
    if canonical_digest(&receipt.body).map_err(|_| failure("recovery_schema"))?
        != receipt.body_sha256
    {
        return Err(failure("recovery_digest"));
    }
    validate_device_recovery_continuity(&receipt.body, document, manifest, evidence_sha256)?;
    let phase = coherent_retired_replacement_phase(document, manifest)?
        .ok_or_else(|| failure("recovery_phase"))?;
    let operational = operational_document_from_recovery_receipt(document, &receipt.body)?;
    if phase == super::LegacyUploadMigrationPhase::DeleteConfirmed {
        let mappings = device_recovery_root_mappings(document, false)?;
        if receipt.body.mappings != mappings {
            return Err(failure("recovery_changed"));
        }
    }
    if phase.index() >= super::LegacyUploadMigrationPhase::DeleteConfirmed.index() {
        validate_device_recovery_quarantine_layout(&operational, manifest, phase)?;
    }
    let _ = quarantine_plan_from_document(&operational, manifest)?;
    revalidate_sealed_evidence(&mut sealed, &request.receipt_path)?;
    Ok((
        SealedDeviceRecovery {
            request: request.clone(),
            receipt,
            sealed,
        },
        operational,
    ))
}

fn operational_document_from_recovery_receipt(
    document: &EvidenceDocument,
    body: &DeviceRecoveryReceiptBody,
) -> Result<EvidenceDocument, LegacyUploadEvidenceError> {
    if body.mappings.len() != document.quarantine_roots.len()
        || body.mappings.is_empty()
        || body
            .mappings
            .windows(2)
            .any(|pair| pair[0].previous_device >= pair[1].previous_device)
    {
        return Err(failure("recovery_mapping"));
    }
    let mut mapping = BTreeMap::new();
    let mut current_devices = BTreeSet::new();
    for item in &body.mappings {
        let root = document
            .quarantine_roots
            .iter()
            .find(|root| root.device == item.previous_device)
            .ok_or_else(|| failure("recovery_mapping"))?;
        if item.previous_device == item.current_device
            || item.current_device == 0
            || item.root_inode != root.inode
            || item.root_path_sha256
                != canonical_digest(&root.canonical_path)
                    .map_err(|_| failure("recovery_mapping"))?
            || mapping
                .insert(item.previous_device, item.current_device)
                .is_some()
            || !current_devices.insert(item.current_device)
        {
            return Err(failure("recovery_mapping"));
        }
    }
    let mut operational = document.clone();
    for root in &mut operational.quarantine_roots {
        root.device = *mapping
            .get(&root.device)
            .ok_or_else(|| failure("recovery_mapping"))?;
    }
    operational.quarantine_roots.sort_by_key(|root| root.device);
    for member in &mut operational.quarantine_members {
        member.source.device = *mapping
            .get(&member.source.device)
            .ok_or_else(|| failure("recovery_mapping"))?;
        member.root_device = *mapping
            .get(&member.root_device)
            .ok_or_else(|| failure("recovery_mapping"))?;
    }
    for raw in &mut operational.raw_inputs {
        raw.source.device = *mapping
            .get(&raw.source.device)
            .ok_or_else(|| failure("recovery_mapping"))?;
    }
    for reference in &mut operational.reference_normalizations {
        reference.device = *mapping
            .get(&reference.device)
            .ok_or_else(|| failure("recovery_mapping"))?;
    }
    Ok(operational)
}

fn validate_device_recovery_continuity(
    body: &DeviceRecoveryReceiptBody,
    document: &EvidenceDocument,
    manifest: &Manifest,
    evidence_sha256: &str,
) -> Result<(), LegacyUploadEvidenceError> {
    let signer = current_recovery_signer()?;
    validate_device_recovery_continuity_with_signer(
        body,
        document,
        manifest,
        evidence_sha256,
        &signer,
    )
}

fn validate_device_recovery_continuity_with_signer(
    body: &DeviceRecoveryReceiptBody,
    document: &EvidenceDocument,
    manifest: &Manifest,
    evidence_sha256: &str,
    expected_signer: &DeviceRecoverySigner,
) -> Result<(), LegacyUploadEvidenceError> {
    if body.schema_version != DEVICE_RECOVERY_SCHEMA_VERSION
        || body.evidence_sha256 != evidence_sha256
        || body.cohort_sha256 != document.cohort_sha256
        || !body.checkpoint_current
        || body.migration_phase != super::LegacyUploadMigrationPhase::DeleteConfirmed.as_str()
        || body.raw_input_count != document.raw_inputs.len() as u64
        || body.quarantine_member_count != document.quarantine_members.len() as u64
        || body.reference_count != document.reference_normalizations.len() as u64
        || body.journal_anchors.len() != RETIRED_REPLACEMENT_COUNT
        || body
            .journal_anchors
            .windows(2)
            .any(|pair| pair[0].asset_id >= pair[1].asset_id)
    {
        return Err(failure("recovery_changed"));
    }
    if expected_signer != &body.signer {
        return Err(failure("recovery_signer_mismatch"));
    }
    let phase = coherent_retired_replacement_phase(document, manifest)?
        .ok_or_else(|| failure("recovery_phase"))?;
    if phase.index() < super::LegacyUploadMigrationPhase::DeleteConfirmed.index() {
        return Err(failure("recovery_phase"));
    }
    if phase == super::LegacyUploadMigrationPhase::DeleteConfirmed
        && body.authoritative_manifest_sha256
            != canonical_digest(manifest.records()).map_err(|_| failure("recovery_manifest"))?
    {
        return Err(failure("recovery_manifest"));
    }
    for replacement in &document.retired_replacements {
        let anchor = body
            .journal_anchors
            .iter()
            .find(|anchor| anchor.asset_id == replacement.asset_id)
            .ok_or_else(|| failure("recovery_journal"))?;
        let record = manifest
            .records()
            .get(&replacement.asset_id)
            .ok_or_else(|| failure("recovery_journal"))?;
        let journal = validate_legacy_upload_migration_record(record)
            .map_err(|_| failure("recovery_journal"))?;
        let anchored_index: usize = anchor
            .entry_count
            .checked_sub(1)
            .and_then(|index| index.try_into().ok())
            .ok_or_else(|| failure("recovery_journal"))?;
        let anchored = journal
            .entries
            .get(anchored_index)
            .filter(|entry| entry.phase == super::LegacyUploadMigrationPhase::DeleteConfirmed)
            .ok_or_else(|| failure("recovery_journal"))?;
        if anchored.entry_sha256 != anchor.delete_confirmed_entry_sha256 {
            return Err(failure("recovery_journal"));
        }
    }
    if body
        .original_destination_canonicalizations
        .iter()
        .any(|entry| {
            body.journal_anchors.iter().all(|anchor| {
                anchor.asset_id != entry.asset_id
                    || anchor.delete_confirmed_entry_sha256 != entry.delete_confirmed_entry_sha256
            })
        })
    {
        return Err(failure("original_canonicalization"));
    }
    validate_recovery_canonicalization_set(
        document,
        manifest,
        Some(&body.original_destination_canonicalizations),
    )
}

pub(super) fn load_validated_legacy_uploaded_heic_evidence(
    request: &LegacyUploadEvidenceAuditRequest,
) -> Result<ValidatedLegacyUploadEvidence, LegacyUploadEvidenceError> {
    load_validated_legacy_uploaded_heic_evidence_with_optional_device_recovery_and_state_store(
        request, None, None,
    )
}

pub(super) fn load_validated_legacy_uploaded_heic_evidence_with_device_recovery(
    request: &LegacyUploadEvidenceAuditRequest,
    recovery: Option<&LegacyUploadDeviceRecoveryRequest>,
) -> Result<ValidatedLegacyUploadEvidence, LegacyUploadEvidenceError> {
    load_validated_legacy_uploaded_heic_evidence_with_optional_device_recovery_and_state_store(
        request, recovery, None,
    )
}

pub(super) fn load_validated_legacy_uploaded_heic_evidence_with_state_store(
    request: &LegacyUploadEvidenceAuditRequest,
    recovery: Option<&LegacyUploadDeviceRecoveryRequest>,
    state_store: &AssetStateStore,
) -> Result<ValidatedLegacyUploadEvidence, LegacyUploadEvidenceError> {
    load_validated_legacy_uploaded_heic_evidence_with_optional_device_recovery_and_state_store(
        request,
        recovery,
        Some(state_store),
    )
}

fn load_validated_legacy_uploaded_heic_evidence_with_optional_device_recovery_and_state_store(
    request: &LegacyUploadEvidenceAuditRequest,
    recovery: Option<&LegacyUploadDeviceRecoveryRequest>,
    writer_state_store: Option<&AssetStateStore>,
) -> Result<ValidatedLegacyUploadEvidence, LegacyUploadEvidenceError> {
    validate_public_request(request)?;
    let mut sealed_evidence = read_sealed_evidence(&request.evidence_path)?;
    let actual_evidence_sha256 = sealed_evidence.sha256.clone();
    if actual_evidence_sha256 != request.expected_evidence_sha256 {
        return Err(failure("evidence_digest"));
    }
    let document: EvidenceDocument =
        crate::strict_json::from_reader(sealed_evidence.bytes.as_slice())
            .map_err(|_| failure("evidence_schema"))?;
    if document.retired_replacements.len() != RETIRED_REPLACEMENT_COUNT {
        return Err(failure("evidence_count"));
    }
    let immutable_state_store = if writer_state_store.is_none() {
        Some(
            AssetStateStore::open_immutable_read_only(&request.manifest_path)
                .map_err(|_| failure("state_open"))?,
        )
    } else {
        None
    };
    let manifest = match writer_state_store {
        Some(state_store) => state_store
            .load_for_legacy_upload_apply(&request.manifest_path)
            .map_err(|_| failure("state_load"))?,
        None => immutable_state_store
            .as_ref()
            .expect("immutable state store should exist when no writer is supplied")
            .load()
            .map_err(|_| failure("state_load"))?,
    };
    let cohort_phase = coherent_retired_replacement_phase(&document, &manifest)?;
    let (device_recovery, operational_document) = if let Some(recovery) = recovery {
        let (sealed, operational) =
            load_device_recovery(recovery, &document, &manifest, &actual_evidence_sha256)?;
        (Some(sealed), operational)
    } else {
        (None, document.clone())
    };
    let validated = validate_document(
        document.clone(),
        &actual_evidence_sha256,
        request,
        &manifest,
        device_recovery.as_ref().map(|recovery| {
            recovery
                .receipt
                .body
                .original_destination_canonicalizations
                .as_slice()
        }),
    )?;
    let operational_quarantine_plan =
        quarantine_plan_from_document(&operational_document, &manifest)?;
    let partial_device_recovery = recovery.is_some()
        && cohort_phase == Some(super::LegacyUploadMigrationPhase::DeleteConfirmed);
    let mut sealed_references = if cohort_phase.is_none_or(|phase| {
        phase.index() <= super::LegacyUploadMigrationPhase::DeleteConfirmed.index()
    }) {
        if partial_device_recovery {
            open_sealed_references_for_partial_recovery(&operational_document)?
        } else {
            open_sealed_references(&operational_document)?
        }
    } else {
        Vec::new()
    };
    if let Some(state_store) = immutable_state_store.as_ref() {
        state_store
            .revalidate_immutable_read_snapshot()
            .map_err(|_| failure("state_changed"))?;
    }
    revalidate_sealed_evidence(&mut sealed_evidence, &request.evidence_path)?;
    if partial_device_recovery {
        revalidate_held_reference_descriptors(&mut sealed_references)?;
    } else {
        revalidate_sealed_references(&mut sealed_references)?;
    }
    if let Some(state_store) = writer_state_store {
        state_store
            .revalidate_legacy_upload_apply_state(&request.manifest_path, &manifest)
            .map_err(|_| failure("state_changed"))?;
    }
    Ok(ValidatedLegacyUploadEvidence {
        validated,
        document,
        request: request.clone(),
        sealed_evidence,
        sealed_references,
        operational_document,
        operational_quarantine_plan,
        device_recovery,
    })
}

fn coherent_retired_replacement_phase(
    document: &EvidenceDocument,
    manifest: &Manifest,
) -> Result<Option<super::LegacyUploadMigrationPhase>, LegacyUploadEvidenceError> {
    let phases = std::array::from_fn::<_, RETIRED_REPLACEMENT_COUNT, _>(|index| {
        let record = manifest
            .get(&document.retired_replacements[index].asset_id)
            .map_err(|_| failure("replacement_proof"))?;
        match record.proofs.get(super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME) {
            None => Ok(None),
            Some(_) => validate_legacy_upload_migration_record(record)
                .map_err(|_| failure("replacement_proof"))
                .and_then(|journal| {
                    journal
                        .entries
                        .last()
                        .map(|entry| Some(entry.phase))
                        .ok_or_else(|| failure("replacement_proof"))
                }),
        }
    });
    let left = phases[0]?;
    let right = phases[1]?;
    if left != right {
        return Err(failure("replacement_cohort"));
    }
    Ok(left)
}

impl ValidatedLegacyUploadEvidence {
    pub(super) fn evidence_path(&self) -> &Path {
        &self.request.evidence_path
    }

    pub(super) fn audit(&self) -> &LegacyUploadEvidenceAudit {
        &self.validated.audit
    }

    pub(super) fn preparation_authority(&self) -> &LegacyUploadMigrationCohortAuthority {
        &self.validated.preparation_authority
    }

    pub(super) fn replacement_asset_ids(&self) -> [&str; RETIRED_REPLACEMENT_COUNT] {
        std::array::from_fn(|index| self.document.retired_replacements[index].asset_id.as_str())
    }

    pub(super) fn cohort_asset_ids(&self) -> Vec<&str> {
        self.document
            .assets
            .iter()
            .map(|asset| asset.asset_id.as_str())
            .collect()
    }

    pub(super) fn retired_replacements(&self) -> &[EvidenceRetiredReplacement] {
        &self.document.retired_replacements
    }

    pub(super) fn initial_remote_states(
        &self,
    ) -> [CloudKitUploadedHeicInitialState; RETIRED_REPLACEMENT_COUNT] {
        std::array::from_fn(|index| self.document.retired_replacements[index].initial_remote_state)
    }

    pub(super) fn reference_normalizations(&self) -> &[EvidenceReferenceNormalization] {
        &self.operational_document.reference_normalizations
    }

    pub(super) fn quarantine_plan(&self) -> &LegacyUploadMigrationQuarantinePlan {
        &self.operational_quarantine_plan
    }

    pub(super) fn has_device_recovery_receipt(&self) -> bool {
        self.device_recovery.is_some()
    }

    pub(super) fn sealed_quarantine_plan(&self) -> &LegacyUploadMigrationQuarantinePlan {
        &self.validated.preparation_authority.preparations[0]
            .identity
            .quarantine_plan
    }

    pub(super) fn revalidate_held_evidence(&mut self) -> Result<(), LegacyUploadEvidenceError> {
        revalidate_sealed_evidence(&mut self.sealed_evidence, &self.request.evidence_path)?;
        if let Some(recovery) = &mut self.device_recovery {
            if recovery.sealed.sha256 != recovery.request.expected_receipt_sha256
                || recovery.receipt.body_sha256
                    != canonical_digest(&recovery.receipt.body)
                        .map_err(|_| failure("recovery_changed"))?
            {
                return Err(failure("recovery_changed"));
            }
            revalidate_sealed_evidence(&mut recovery.sealed, &recovery.request.receipt_path)?;
        }
        Ok(())
    }

    pub(super) fn revalidate_reference_descriptors_before_quarantine(
        &mut self,
    ) -> Result<(), LegacyUploadEvidenceError> {
        revalidate_held_reference_descriptors(&mut self.sealed_references)
    }

    pub(super) fn revalidate_authoritative_manifest(
        &mut self,
        manifest: &Manifest,
    ) -> Result<(), LegacyUploadEvidenceError> {
        self.revalidate_held_evidence()?;
        let validated = validate_document(
            self.document.clone(),
            &self.validated.audit.evidence_sha256,
            &self.request,
            manifest,
            self.device_recovery.as_ref().map(|recovery| {
                recovery
                    .receipt
                    .body
                    .original_destination_canonicalizations
                    .as_slice()
            }),
        )?;
        if validated.audit != self.validated.audit {
            return Err(failure("evidence_changed"));
        }
        if let Some(recovery) = &self.device_recovery {
            validate_device_recovery_continuity(
                &recovery.receipt.body,
                &self.document,
                manifest,
                &self.validated.audit.evidence_sha256,
            )?;
            let operational_plan =
                quarantine_plan_from_document(&self.operational_document, manifest)?;
            if operational_plan != self.operational_quarantine_plan {
                return Err(failure("recovery_changed"));
            }
        }
        self.validated = validated;
        self.revalidate_held_evidence()
    }
}

fn validate_public_request(
    request: &LegacyUploadEvidenceAuditRequest,
) -> Result<(), LegacyUploadEvidenceError> {
    if !is_digest(&request.expected_evidence_sha256) || !is_digest(&request.expected_cohort_sha256)
    {
        return Err(failure("expected_digest"));
    }
    if request.expected_asset_count != ASSET_COUNT as u64
        || request.expected_retired_replacement_count != RETIRED_REPLACEMENT_COUNT as u64
        || request.expected_reference_count != REFERENCE_COUNT as u64
    {
        return Err(failure("expected_count"));
    }
    Ok(())
}

fn quarantine_plan_from_document(
    document: &EvidenceDocument,
    manifest: &Manifest,
) -> Result<LegacyUploadMigrationQuarantinePlan, LegacyUploadEvidenceError> {
    if document.quarantine_roots.is_empty() || document.quarantine_members.len() != 9 {
        return Err(failure("quarantine_mapping"));
    }
    let mut roots_by_device = BTreeMap::new();
    let mut prior_device = None;
    for root in &document.quarantine_roots {
        if !safe_absolute_path(&root.canonical_path)
            || root.device == 0
            || root.inode == 0
            || root.mode != 0o700
            || prior_device.is_some_and(|prior| prior >= root.device)
            || roots_by_device.insert(root.device, root).is_some()
        {
            return Err(failure("quarantine_mapping"));
        }
        prior_device = Some(root.device);
    }
    let mut expected = BTreeMap::new();
    let mut resumed_plan: Option<LegacyUploadMigrationQuarantinePlan> = None;
    for replacement in &document.retired_replacements {
        let record = manifest
            .get(&replacement.asset_id)
            .map_err(|_| failure("quarantine_mapping"))?;
        if let Ok(journal) = validate_legacy_upload_migration_record(record)
            && journal.entries.last().is_some_and(|entry| {
                entry.phase.index() >= super::LegacyUploadMigrationPhase::Reset.index()
            })
        {
            if resumed_plan
                .as_ref()
                .is_some_and(|plan| plan != &journal.identity.quarantine_plan)
            {
                return Err(failure("quarantine_mapping"));
            }
            resumed_plan = Some(journal.identity.quarantine_plan);
            continue;
        }
        let (Some(upload), Some(mirror)) = (
            record.proofs.get("upload"),
            record.proofs.get("icloudpd_local_mirror"),
        ) else {
            let journal = validate_legacy_upload_migration_record(record)
                .map_err(|_| failure("quarantine_mapping"))?;
            if journal.entries.last().is_none_or(|entry| {
                entry.phase.index() < super::LegacyUploadMigrationPhase::Reset.index()
            }) || resumed_plan
                .as_ref()
                .is_some_and(|plan| plan != &journal.identity.quarantine_plan)
            {
                return Err(failure("quarantine_mapping"));
            }
            resumed_plan = Some(journal.identity.quarantine_plan);
            continue;
        };
        let upload: UploadProof =
            serde_json::from_value(upload.clone()).map_err(|_| failure("quarantine_mapping"))?;
        let mirror: IcloudpdLocalMirrorProof =
            serde_json::from_value(mirror.clone()).map_err(|_| failure("quarantine_mapping"))?;
        expected.insert(
            (
                replacement.asset_id.clone(),
                LegacyUploadMigrationQuarantineKind::Final,
            ),
            (
                upload
                    .uploaded_heic_path
                    .ok_or_else(|| failure("quarantine_mapping"))?,
                None,
            ),
        );
        expected.insert(
            (
                replacement.asset_id.clone(),
                LegacyUploadMigrationQuarantineKind::OldMirror,
            ),
            (
                mirror.icloudpd_download_path,
                Some((
                    replacement.uploaded_heic_sha256.clone(),
                    replacement.uploaded_heic_size_bytes,
                )),
            ),
        );
    }
    for reference in &document.reference_normalizations {
        expected.insert(
            (
                reference.asset_id.clone(),
                LegacyUploadMigrationQuarantineKind::Reference,
            ),
            (
                reference.reference_path.clone(),
                Some((reference.file_sha256.clone(), reference.size_bytes)),
            ),
        );
    }
    if resumed_plan.is_some()
        && coherent_retired_replacement_phase(document, manifest)?
            .is_none_or(|phase| phase.index() < super::LegacyUploadMigrationPhase::Reset.index())
    {
        return Err(failure("replacement_cohort"));
    }
    if expected.len() != 9 && resumed_plan.is_none() {
        return Err(failure("quarantine_mapping"));
    }
    let mut prior_key = None;
    let mut source_paths = BTreeSet::new();
    let mut source_identities = BTreeSet::new();
    let mut members = Vec::with_capacity(9);
    for member in &document.quarantine_members {
        let key = (member.asset_id.clone(), member.kind);
        let (expected_path, expected_identity) = match expected.remove(&key) {
            Some(expected) => expected,
            None if resumed_plan.is_some()
                && document
                    .retired_replacements
                    .iter()
                    .any(|replacement| replacement.asset_id == member.asset_id)
                && matches!(
                    member.kind,
                    LegacyUploadMigrationQuarantineKind::Final
                        | LegacyUploadMigrationQuarantineKind::OldMirror
                ) =>
            {
                (member.source_path.clone(), None)
            }
            None => return Err(failure("quarantine_mapping")),
        };
        if prior_key.as_ref().is_some_and(|prior| prior >= &key)
            || member.source_path != expected_path
            || expected_identity.as_ref().is_some_and(|(sha256, size)| {
                member.source.sha256 != *sha256 || member.source.size_bytes != *size
            })
            || !is_digest(&member.source.sha256)
            || member.source.size_bytes == 0
            || member.source.device == 0
            || member.source.inode == 0
            || member.source.link_count != 1
            || member.root_device != member.source.device
            || !roots_by_device.contains_key(&member.root_device)
            || !source_paths.insert(member.source_path.clone())
            || !source_identities.insert((member.source.device, member.source.inode))
            || member.kind == LegacyUploadMigrationQuarantineKind::Reference
                && document.reference_normalizations.iter().any(|reference| {
                    reference.asset_id == member.asset_id
                        && (reference.device != member.source.device
                            || reference.inode != member.source.inode)
                })
        {
            return Err(failure("quarantine_mapping"));
        }
        let root = roots_by_device[&member.root_device];
        let destination_path = legacy_upload_migration_quarantine_destination_path(
            &root.canonical_path,
            &document.cohort_sha256,
            member.kind,
            &member.asset_id,
            &member.source_path,
        )
        .map_err(|_| failure("quarantine_mapping"))?;
        members.push(LegacyUploadMigrationQuarantineMember {
            asset_id: member.asset_id.clone(),
            kind: member.kind,
            source_path: member.source_path.clone(),
            destination_path,
            source: member.source.clone(),
            root_device: member.root_device,
        });
        prior_key = Some(key);
    }
    if !expected.is_empty() {
        return Err(failure("quarantine_mapping"));
    }
    if document.raw_inputs.len() != ASSET_COUNT {
        return Err(failure("raw_binding"));
    }
    let mut raw_inputs = Vec::with_capacity(ASSET_COUNT);
    let mut prior_raw_asset_id = None;
    let mut raw_paths = BTreeSet::new();
    let mut raw_identities = BTreeSet::new();
    for raw in &document.raw_inputs {
        let record = manifest
            .get(&raw.asset_id)
            .map_err(|_| failure("raw_binding"))?;
        let nas: NasRawProof = serde_json::from_value(
            record
                .proofs
                .get("nas")
                .ok_or_else(|| failure("raw_binding"))?
                .clone(),
        )
        .map_err(|_| failure("raw_binding"))?;
        if prior_raw_asset_id
            .as_ref()
            .is_some_and(|prior| prior >= &raw.asset_id)
            || raw.path != record.raw_path
            || raw.path != nas.canonical_path
            || raw.source.sha256 != nas.sha256
            || raw.source.size_bytes != nas.size_bytes
            || raw.source.device == 0
            || raw.source.inode == 0
            || raw.source.link_count != 1
            || !raw_paths.insert(raw.path.clone())
            || !raw_identities.insert((raw.source.device, raw.source.inode))
        {
            return Err(failure("raw_binding"));
        }
        raw_inputs.push(LegacyUploadMigrationRawInput {
            asset_id: raw.asset_id.clone(),
            path: raw.path.clone(),
            source: raw.source.clone(),
        });
        prior_raw_asset_id = Some(raw.asset_id.clone());
    }
    let plan = seal_legacy_upload_migration_quarantine_plan(LegacyUploadMigrationQuarantinePlan {
        schema_version: 1,
        roots: document
            .quarantine_roots
            .iter()
            .map(|root| LegacyUploadMigrationQuarantineRoot {
                canonical_path: root.canonical_path.clone(),
                device: root.device,
                inode: root.inode,
                owner: root.owner,
                mode: root.mode,
            })
            .collect(),
        members,
        raw_inputs,
        plan_sha256: String::new(),
    })
    .map_err(|_| failure("quarantine_mapping"))?;
    if let Some(sealed) = resumed_plan.as_ref() {
        let rebased = rebase_sealed_quarantine_plan_devices(sealed, document)?;
        if rebased != plan {
            return Err(failure("quarantine_mapping"));
        }
    }
    Ok(plan)
}

fn rebase_sealed_quarantine_plan_devices(
    sealed: &LegacyUploadMigrationQuarantinePlan,
    document: &EvidenceDocument,
) -> Result<LegacyUploadMigrationQuarantinePlan, LegacyUploadEvidenceError> {
    if sealed.schema_version != 1
        || sealed.roots.len() != document.quarantine_roots.len()
        || sealed.members.len() != document.quarantine_members.len()
        || sealed.raw_inputs.len() != document.raw_inputs.len()
    {
        return Err(failure("quarantine_mapping"));
    }

    let mut mapping = BTreeMap::new();
    let mut current_devices = BTreeSet::new();
    for sealed_root in &sealed.roots {
        let current_root = document
            .quarantine_roots
            .iter()
            .find(|root| {
                root.canonical_path == sealed_root.canonical_path
                    && root.inode == sealed_root.inode
                    && root.owner == sealed_root.owner
                    && root.mode == sealed_root.mode
            })
            .ok_or_else(|| failure("quarantine_mapping"))?;
        if sealed_root.device == 0
            || current_root.device == 0
            || mapping
                .insert(sealed_root.device, current_root.device)
                .is_some()
            || !current_devices.insert(current_root.device)
        {
            return Err(failure("quarantine_mapping"));
        }
    }
    if mapping.len() != sealed.roots.len() {
        return Err(failure("quarantine_mapping"));
    }

    let mut rebased = sealed.clone();
    for root in &mut rebased.roots {
        root.device = *mapping
            .get(&root.device)
            .ok_or_else(|| failure("quarantine_mapping"))?;
    }
    rebased.roots.sort_by_key(|root| root.device);
    for member in &mut rebased.members {
        member.source.device = *mapping
            .get(&member.source.device)
            .ok_or_else(|| failure("quarantine_mapping"))?;
        member.root_device = *mapping
            .get(&member.root_device)
            .ok_or_else(|| failure("quarantine_mapping"))?;
    }
    for raw in &mut rebased.raw_inputs {
        raw.source.device = *mapping
            .get(&raw.source.device)
            .ok_or_else(|| failure("quarantine_mapping"))?;
    }
    seal_legacy_upload_migration_quarantine_plan(rebased).map_err(|_| failure("quarantine_mapping"))
}

fn validate_document(
    document: EvidenceDocument,
    evidence_sha256: &str,
    request: &LegacyUploadEvidenceAuditRequest,
    manifest: &Manifest,
    canonicalizations: Option<&[OriginalDestinationCanonicalization]>,
) -> Result<ValidatedEvidenceDocument, LegacyUploadEvidenceError> {
    if document.schema_version != EVIDENCE_SCHEMA_VERSION
        || !is_digest(&document.migration_id)
        || document.asset_count != ASSET_COUNT as u64
        || document.retired_replacement_count != RETIRED_REPLACEMENT_COUNT as u64
        || document.reference_count != REFERENCE_COUNT as u64
        || document.assets.len() != ASSET_COUNT
        || document.retired_replacements.len() != RETIRED_REPLACEMENT_COUNT
        || document.reference_normalizations.len() != REFERENCE_COUNT
    {
        return Err(failure("evidence_count"));
    }
    validate_ordered_unique(document.assets.iter().map(|asset| asset.asset_id.as_str()))?;
    validate_ordered_unique(
        document
            .retired_replacements
            .iter()
            .map(|asset| asset.asset_id.as_str()),
    )?;
    validate_ordered_unique(
        document
            .reference_normalizations
            .iter()
            .map(|asset| asset.asset_id.as_str()),
    )?;
    validate_retired_replacement_pair(&document.retired_replacements)?;
    validate_recovery_canonicalization_set(&document, manifest, canonicalizations)?;
    let cohort_sha256 = canonical_digest(&CohortDigestInput {
        schema_version: document.schema_version,
        migration_id: &document.migration_id,
        asset_count: document.asset_count,
        retired_replacement_count: document.retired_replacement_count,
        reference_count: document.reference_count,
        assets: &document.assets,
        retired_replacements: &document.retired_replacements,
        reference_normalizations: &document.reference_normalizations,
        quarantine_roots: &document.quarantine_roots,
        quarantine_members: &document.quarantine_members,
        raw_inputs: &document.raw_inputs,
    })
    .map_err(|_| failure("cohort_digest"))?;
    if document.cohort_sha256 != cohort_sha256 || cohort_sha256 != request.expected_cohort_sha256 {
        return Err(failure("cohort_digest"));
    }
    let quarantine_plan = quarantine_plan_from_document(&document, manifest)?;

    let current_asset_ids = manifest
        .records()
        .values()
        .filter(|record| {
            record.state == State::UploadVerified
                || record
                    .proofs
                    .contains_key(super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME)
        })
        .map(|record| record.asset_id.as_str())
        .collect::<Vec<_>>();
    let evidence_asset_ids = document
        .assets
        .iter()
        .map(|asset| asset.asset_id.as_str())
        .collect::<Vec<_>>();
    if current_asset_ids != evidence_asset_ids {
        return Err(failure("asset_set"));
    }
    let mut record_digests = BTreeMap::new();
    for asset in &document.assets {
        if !is_digest(&asset.record_sha256) {
            return Err(failure("record_digest"));
        }
        let record = manifest
            .records()
            .get(&asset.asset_id)
            .ok_or_else(|| failure("asset_set"))?;
        let digest = if record
            .proofs
            .contains_key(super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME)
        {
            validate_legacy_upload_migration_record(record)
                .map_err(|_| failure("record_digest"))?
                .identity
                .source_record_sha256
        } else {
            legacy_upload_migration_record_digest(record).map_err(|_| failure("record_digest"))?
        };
        if digest != asset.record_sha256 {
            return Err(failure("record_digest"));
        }
        record_digests.insert(asset.asset_id.as_str(), asset.record_sha256.as_str());
    }

    for replacement in &document.retired_replacements {
        let record = manifest
            .records()
            .get(&replacement.asset_id)
            .ok_or_else(|| failure("replacement_proof"))?;
        if record
            .proofs
            .contains_key(super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME)
        {
            validate_retired_replacement_journal_identity(
                replacement,
                record,
                record_digests[replacement.asset_id.as_str()],
                canonicalizations,
            )?;
            let phase = validate_legacy_upload_migration_record(record)
                .map_err(|_| failure("replacement_proof"))?
                .entries
                .last()
                .ok_or_else(|| failure("replacement_proof"))?
                .phase;
            if matches!(
                phase,
                super::LegacyUploadMigrationPhase::Prepared
                    | super::LegacyUploadMigrationPhase::DeleteConfirmed
                    | super::LegacyUploadMigrationPhase::Quarantined
            ) {
                validate_retired_replacement(
                    replacement,
                    manifest,
                    &record_digests,
                    canonicalizations,
                )?;
            }
        } else {
            validate_retired_replacement(
                replacement,
                manifest,
                &record_digests,
                canonicalizations,
            )?;
        }
    }

    let mut protected_paths = manifest
        .records()
        .values()
        .map(|record| record.raw_path.clone())
        .collect::<BTreeSet<_>>();
    for replacement in &document.retired_replacements {
        let record = manifest
            .records()
            .get(&replacement.asset_id)
            .ok_or_else(|| failure("reference_witness"))?;
        if let Some(upload) = record
            .proofs
            .get("upload")
            .and_then(|value| serde_json::from_value::<UploadProof>(value.clone()).ok())
            && let Some(path) = upload.uploaded_heic_path
        {
            protected_paths.insert(path);
        }
        if let Some(mirror) = record
            .proofs
            .get("icloudpd_local_mirror")
            .and_then(|value| {
                serde_json::from_value::<IcloudpdLocalMirrorProof>(value.clone()).ok()
            })
        {
            protected_paths.insert(mirror.icloudpd_download_path);
        }
    }
    let mut reference_paths = BTreeSet::new();
    let mut reference_orientation_counts = BTreeMap::new();
    for (reference_index, reference) in document.reference_normalizations.iter().enumerate() {
        let expected_asset_id = &document.assets[REFERENCE_ASSET_INDICES[reference_index]].asset_id;
        let expected_orientation = REFERENCE_ORIENTATIONS[reference_index];
        let record = manifest
            .records()
            .get(&reference.asset_id)
            .ok_or_else(|| failure("reference_witness"))?;
        let path_matches_reverify_semantics = record
            .proofs
            .get("upload")
            .and_then(|value| serde_json::from_value::<UploadProof>(value.clone()).ok())
            .and_then(|upload| upload.uploaded_heic_path)
            .is_some_and(|mut path| {
                path.set_extension("oriented-preview.jpg");
                path == reference.reference_path
            });
        let reset_retired_record = document
            .retired_replacements
            .iter()
            .any(|replacement| replacement.asset_id == reference.asset_id)
            && validate_legacy_upload_migration_record(record).is_ok_and(|journal| {
                journal.entries.last().is_some_and(|entry| {
                    entry.phase.index() >= super::LegacyUploadMigrationPhase::Reset.index()
                })
            });
        let expected_identity = canonical_digest(&ReferenceIdentityDigestInput {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            asset_id: &reference.asset_id,
            reference_path: &reference.reference_path,
            device: reference.device,
            inode: reference.inode,
            size_bytes: reference.size_bytes,
            file_sha256: &reference.file_sha256,
            orientation: reference.orientation,
            width: reference.width,
            height: reference.height,
            decoded_pixel_sha256: &reference.decoded_pixel_sha256,
        })
        .map_err(|_| failure("reference_witness"))?;
        if record_digests.get(reference.asset_id.as_str()).copied()
            != Some(reference.asset_record_sha256.as_str())
            || reference.reference_identity_sha256 != expected_identity
            || !path_matches_reverify_semantics && !reset_retired_record
            || reference.asset_id != *expected_asset_id
            || !safe_absolute_path(&reference.reference_path)
            || reference.device == 0
            || reference.inode == 0
            || reference.size_bytes == 0
            || !is_digest(&reference.file_sha256)
            || !is_digest(&reference.decoded_pixel_sha256)
            || reference.orientation != expected_orientation
            || reference.width == 0
            || reference.height == 0
            || protected_paths.contains(&reference.reference_path)
            || !reference_paths.insert(reference.reference_path.clone())
        {
            return Err(failure("reference_witness"));
        }
        *reference_orientation_counts
            .entry(reference.orientation)
            .or_insert(0_u64) += 1;
    }
    if reference_orientation_counts != BTreeMap::from([(6_u16, 4_u64), (8_u16, 1_u64)]) {
        return Err(failure("reference_witness"));
    }

    // Construct the private capability only after every untrusted evidence field is validated.
    let preparations = document
        .retired_replacements
        .iter()
        .map(|replacement| {
            let prepared_witness_sha256 = canonical_digest(&PreparationWitnessInput {
                schema_version: EVIDENCE_SCHEMA_VERSION,
                migration_id: &document.migration_id,
                evidence_sha256,
                cohort_sha256: &cohort_sha256,
                asset_id: &replacement.asset_id,
                quarantine_plan_sha256: &quarantine_plan.plan_sha256,
            })
            .map_err(|_| failure("preparation_witness"))?;
            Ok(LegacyUploadMigrationAuthorizedPreparation {
                identity: LegacyUploadMigrationIdentity {
                    migration_id: document.migration_id.clone(),
                    evidence_sha256: evidence_sha256.to_string(),
                    cohort_sha256: cohort_sha256.clone(),
                    asset_id: replacement.asset_id.clone(),
                    source_record_sha256: record_digests[replacement.asset_id.as_str()].to_string(),
                    old_uploaded_asset_id: replacement.uploaded_asset_id.clone(),
                    old_uploaded_master_id: replacement.uploaded_master_id.clone(),
                    destination_sha256: replacement.destination_sha256.clone(),
                    original_asset_identity_sha256: replacement
                        .original_asset_identity_sha256
                        .clone(),
                    old_conversion_lineage_sha256: replacement
                        .old_conversion_lineage_sha256
                        .clone(),
                    old_upload_lineage_sha256: replacement.old_upload_lineage_sha256.clone(),
                    old_mirror_lineage_sha256: replacement.old_mirror_lineage_sha256.clone(),
                    quarantine_plan: quarantine_plan.clone(),
                },
                prepared_witness_sha256,
            })
        })
        .collect::<Result<Vec<_>, LegacyUploadEvidenceError>>()?
        .try_into()
        .map_err(|_| failure("evidence_count"))?;

    Ok(ValidatedEvidenceDocument {
        audit: LegacyUploadEvidenceAudit {
            evidence_sha256: request.expected_evidence_sha256.clone(),
            cohort_sha256: request.expected_cohort_sha256.clone(),
            asset_count: document.asset_count,
            retired_replacement_count: document.retired_replacement_count,
            reference_count: document.reference_count,
        },
        preparation_authority: LegacyUploadMigrationCohortAuthority { preparations },
    })
}

fn validate_retired_replacement_pair(
    replacements: &[EvidenceRetiredReplacement],
) -> Result<(), LegacyUploadEvidenceError> {
    if replacements.len() != RETIRED_REPLACEMENT_COUNT {
        return Err(failure("cloudkit_ambiguity"));
    }
    for identities in [
        replacements
            .iter()
            .map(|replacement| replacement.uploaded_asset_id.as_str())
            .collect::<BTreeSet<_>>(),
        replacements
            .iter()
            .map(|replacement| replacement.uploaded_master_id.as_str())
            .collect::<BTreeSet<_>>(),
        replacements
            .iter()
            .map(|replacement| replacement.old_record_change_tag.as_str())
            .collect::<BTreeSet<_>>(),
        replacements
            .iter()
            .map(|replacement| replacement.destination_sha256.as_str())
            .collect::<BTreeSet<_>>(),
        replacements
            .iter()
            .map(|replacement| replacement.original_asset_record_name.as_str())
            .collect::<BTreeSet<_>>(),
    ] {
        if identities.len() != RETIRED_REPLACEMENT_COUNT {
            return Err(failure("cloudkit_ambiguity"));
        }
    }
    if replacements
        .iter()
        .map(|replacement| replacement.owner_record_name_sha256.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        != 1
        || replacements.iter().any(|replacement| {
            replacement.initial_state_lookup_mode
                != CloudKitUploadedHeicInitialStateLookupMode::FullFields
        })
    {
        return Err(failure("cloudkit_ambiguity"));
    }
    Ok(())
}

fn original_asset_proof_destination_fields(
    value: &Value,
) -> Result<bool, LegacyUploadEvidenceError> {
    let object = value.as_object().ok_or_else(|| failure("proof_lineage"))?;
    match (
        object.contains_key("database_scope"),
        object.contains_key("zone_name"),
    ) {
        (true, true) => Ok(true),
        (false, false) => Ok(false),
        _ => Err(failure("proof_lineage")),
    }
}

fn validate_recovery_canonicalization_set(
    document: &EvidenceDocument,
    manifest: &Manifest,
    canonicalizations: Option<&[OriginalDestinationCanonicalization]>,
) -> Result<(), LegacyUploadEvidenceError> {
    let canonicalizations = canonicalizations.unwrap_or_default();
    if canonicalizations.len() > RETIRED_REPLACEMENT_COUNT
        || canonicalizations
            .windows(2)
            .any(|pair| pair[0].asset_id >= pair[1].asset_id)
        || canonicalizations.iter().any(|entry| {
            !is_digest(&entry.original_asset_identity_sha256)
                || !is_digest(&entry.destination_sha256)
                || !is_digest(&entry.canonical_original_asset_sha256)
                || !is_digest(&entry.delete_confirmed_entry_sha256)
                || entry.lookup_mode != CloudKitActiveAssetLookupMode::FullFields
        })
    {
        return Err(failure("original_canonicalization"));
    }
    for replacement in &document.retired_replacements {
        let record = manifest
            .records()
            .get(&replacement.asset_id)
            .ok_or_else(|| failure("original_canonicalization"))?;
        let original = proof(record, "original_asset")?;
        let has_fields = original_asset_proof_destination_fields(original)?;
        let canonicalization = canonicalizations
            .iter()
            .find(|entry| entry.asset_id == replacement.asset_id);
        if has_fields == canonicalization.is_some() {
            return Err(failure("original_canonicalization"));
        }
    }
    if canonicalizations.iter().any(|entry| {
        !document
            .retired_replacements
            .iter()
            .any(|replacement| replacement.asset_id == entry.asset_id)
    }) {
        return Err(failure("original_canonicalization"));
    }
    Ok(())
}

fn original_asset_proof_for_validation(
    evidence: &EvidenceRetiredReplacement,
    original_value: &Value,
    canonicalizations: Option<&[OriginalDestinationCanonicalization]>,
    category: &'static str,
) -> Result<OriginalAssetProof, LegacyUploadEvidenceError> {
    if digest_value(original_value)? != evidence.original_asset_identity_sha256 {
        return Err(failure(category));
    }
    if original_asset_proof_destination_fields(original_value)? {
        return serde_json::from_value(original_value.clone()).map_err(|_| failure(category));
    }
    let canonicalization = canonicalizations
        .unwrap_or_default()
        .iter()
        .find(|entry| entry.asset_id == evidence.asset_id)
        .ok_or_else(|| failure("original_canonicalization"))?;
    if canonicalization.original_asset_identity_sha256 != evidence.original_asset_identity_sha256
        || canonicalization.destination_sha256 != evidence.destination_sha256
        || canonicalization.remote_state != evidence.original_remote_state
        || canonicalization.lookup_mode != evidence.original_state_lookup_mode
    {
        return Err(failure("original_canonicalization"));
    }
    let mut canonical = original_value.clone();
    let object = canonical
        .as_object_mut()
        .ok_or_else(|| failure("original_canonicalization"))?;
    object.insert(
        "database_scope".to_string(),
        serde_json::to_value(evidence.destination.database_scope)
            .map_err(|_| failure("original_canonicalization"))?,
    );
    object.insert(
        "zone_name".to_string(),
        Value::String(evidence.destination.zone_name.clone()),
    );
    let proof: OriginalAssetProof = serde_json::from_value(canonical.clone())
        .map_err(|_| failure("original_canonicalization"))?;
    if digest_value(&canonical)? != canonicalization.canonical_original_asset_sha256 {
        return Err(failure("original_canonicalization"));
    }
    Ok(proof)
}

fn validate_retired_replacement_journal_identity(
    evidence: &EvidenceRetiredReplacement,
    record: &AssetRecord,
    source_record_sha256: &str,
    canonicalizations: Option<&[OriginalDestinationCanonicalization]>,
) -> Result<(), LegacyUploadEvidenceError> {
    let journal = validate_legacy_upload_migration_record(record)
        .map_err(|_| failure("replacement_proof"))?;
    let identity = journal.identity;
    if identity.asset_id != evidence.asset_id
        || identity.source_record_sha256 != source_record_sha256
        || identity.old_uploaded_asset_id != evidence.uploaded_asset_id
        || identity.old_uploaded_master_id != evidence.uploaded_master_id
        || identity.destination_sha256 != evidence.destination_sha256
        || identity.original_asset_identity_sha256 != evidence.original_asset_identity_sha256
        || identity.old_conversion_lineage_sha256 != evidence.old_conversion_lineage_sha256
        || identity.old_upload_lineage_sha256 != evidence.old_upload_lineage_sha256
        || identity.old_mirror_lineage_sha256 != evidence.old_mirror_lineage_sha256
    {
        return Err(failure("replacement_proof"));
    }
    if let Some(canonicalization) = canonicalizations
        .unwrap_or_default()
        .iter()
        .find(|entry| entry.asset_id == evidence.asset_id)
    {
        let delete_confirmed = journal
            .entries
            .iter()
            .find(|entry| entry.phase == super::LegacyUploadMigrationPhase::DeleteConfirmed)
            .ok_or_else(|| failure("original_canonicalization"))?;
        if delete_confirmed.entry_sha256 != canonicalization.delete_confirmed_entry_sha256 {
            return Err(failure("original_canonicalization"));
        }
    }
    if record.proofs.contains_key("uploaded_heic_delete") {
        return Err(failure("proof_conflict"));
    }
    let original_value = proof(record, "original_asset")?;
    let original = original_asset_proof_for_validation(
        evidence,
        original_value,
        canonicalizations,
        "replacement_proof",
    )?;
    if digest_value(original_value)? != evidence.original_asset_identity_sha256
        || original.record_name != evidence.original_asset_record_name
        || original.record_change_tag != evidence.original_record_change_tag
    {
        return Err(failure("replacement_proof"));
    }
    Ok(())
}

fn validate_retired_replacement(
    evidence: &EvidenceRetiredReplacement,
    manifest: &Manifest,
    record_digests: &BTreeMap<&str, &str>,
    canonicalizations: Option<&[OriginalDestinationCanonicalization]>,
) -> Result<(), LegacyUploadEvidenceError> {
    if !record_digests.contains_key(evidence.asset_id.as_str())
        || !valid_identity(&evidence.uploaded_asset_id)
        || !valid_identity(&evidence.uploaded_master_id)
        || !valid_identity(&evidence.old_record_change_tag)
        || !valid_identity(&evidence.original_asset_record_name)
        || !valid_identity(&evidence.original_record_change_tag)
        || evidence.original_state_lookup_mode != CloudKitActiveAssetLookupMode::FullFields
        || !is_digest(&evidence.owner_record_name_sha256)
        || !is_digest(&evidence.destination_sha256)
        || !is_digest(&evidence.uploaded_heic_sha256)
        || !is_digest(&evidence.original_asset_identity_sha256)
        || !is_digest(&evidence.old_conversion_lineage_sha256)
        || !is_digest(&evidence.old_upload_lineage_sha256)
        || !is_digest(&evidence.old_mirror_lineage_sha256)
        || evidence.uploaded_heic_size_bytes == 0
        || evidence.uploaded_asset_id == evidence.uploaded_master_id
        || evidence.uploaded_asset_id == evidence.original_asset_record_name
        || evidence.uploaded_master_id == evidence.original_asset_record_name
    {
        return Err(failure("retired_identity"));
    }
    let record = manifest
        .records()
        .get(&evidence.asset_id)
        .ok_or_else(|| failure("asset_set"))?;
    if record.proofs.contains_key("uploaded_heic_delete") {
        return Err(failure("proof_conflict"));
    }
    let conversion = proof(record, "conversion")?;
    let upload_value = proof(record, "upload")?;
    let mirror_value = proof(record, "icloudpd_local_mirror")?;
    let original_value = proof(record, "original_asset")?;
    let heic_value = proof(record, "heic")?;
    let upload: UploadProof =
        serde_json::from_value(upload_value.clone()).map_err(|_| failure("proof_lineage"))?;
    let mirror: IcloudpdLocalMirrorProof =
        serde_json::from_value(mirror_value.clone()).map_err(|_| failure("proof_lineage"))?;
    let original = original_asset_proof_for_validation(
        evidence,
        original_value,
        canonicalizations,
        "proof_lineage",
    )?;
    let heic: HeicVerificationProof =
        serde_json::from_value(heic_value.clone()).map_err(|_| failure("proof_lineage"))?;
    let uploaded_path = upload
        .uploaded_heic_path
        .as_ref()
        .ok_or_else(|| failure("proof_lineage"))?;
    let filename = uploaded_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| failure("proof_lineage"))?;
    if upload.uploaded_heic_asset_id != evidence.uploaded_asset_id
        || mirror.uploaded_heic_asset_id != evidence.uploaded_asset_id
        || upload.uploaded_heic_sha256 != evidence.uploaded_heic_sha256
        || mirror.uploaded_heic_sha256 != evidence.uploaded_heic_sha256
        || heic.heic_sha256 != evidence.uploaded_heic_sha256
        || mirror.size_bytes != evidence.uploaded_heic_size_bytes
        || heic.size_bytes != evidence.uploaded_heic_size_bytes
        || original.record_name != evidence.original_asset_record_name
        || original.record_change_tag != evidence.original_record_change_tag
        || original.record_name == upload.uploaded_heic_asset_id
        || evidence.destination.database_scope != upload.database_scope
        || evidence.destination.zone_name != upload.zone_name
        || evidence.destination.owner_record_name != upload.owner_record_name
        || evidence.destination.database_scope != original.database_scope
        || evidence.destination.zone_name != original.zone_name
        || evidence.destination.owner_record_name != original.owner_record_name
        || evidence.destination.filename != filename
    {
        return Err(failure("proof_binding"));
    }
    for (actual, expected) in [
        (
            digest_value(&evidence.destination)?,
            evidence.destination_sha256.as_str(),
        ),
        (
            digest_value(original_value)?,
            evidence.original_asset_identity_sha256.as_str(),
        ),
        (
            digest_value(conversion)?,
            evidence.old_conversion_lineage_sha256.as_str(),
        ),
        (
            digest_value(upload_value)?,
            evidence.old_upload_lineage_sha256.as_str(),
        ),
        (
            digest_value(mirror_value)?,
            evidence.old_mirror_lineage_sha256.as_str(),
        ),
    ] {
        if actual != expected {
            return Err(failure("proof_lineage"));
        }
    }
    Ok(())
}

fn proof<'a>(record: &'a AssetRecord, name: &str) -> Result<&'a Value, LegacyUploadEvidenceError> {
    record
        .proofs
        .get(name)
        .ok_or_else(|| failure("proof_missing"))
}

fn digest_value(value: &impl Serialize) -> Result<String, LegacyUploadEvidenceError> {
    canonical_digest(value).map_err(|_| failure("proof_lineage"))
}

fn validate_ordered_unique<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Result<(), LegacyUploadEvidenceError> {
    let values = values.into_iter().collect::<Vec<_>>();
    if values.iter().any(|value| !valid_identity(value))
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(failure("asset_order"));
    }
    Ok(())
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.len() <= 1_024
        && !value.chars().any(char::is_control)
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(unix)]
fn open_sealed_references(
    document: &EvidenceDocument,
) -> Result<Vec<SealedReference>, LegacyUploadEvidenceError> {
    document
        .reference_normalizations
        .iter()
        .map(|reference| {
            let mut options = OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
            let mut file = options
                .open(&reference.reference_path)
                .map_err(|_| failure("reference_open"))?;
            let metadata = file.metadata().map_err(|_| failure("reference_metadata"))?;
            let captured = EvidenceMetadata::capture(&metadata);
            if !captured.is_regular
                || captured.nlink != 1
                || captured.dev != reference.device
                || captured.ino != reference.inode
                || captured.size != reference.size_bytes
            {
                return Err(failure("reference_descriptor"));
            }
            let sha256 = sha256_open_file(&mut file)?;
            if sha256 != reference.file_sha256 {
                return Err(failure("reference_descriptor"));
            }
            Ok(SealedReference {
                path: reference.reference_path.clone(),
                file,
                initial_metadata: captured,
                sha256,
            })
        })
        .collect()
}

#[cfg(unix)]
fn open_sealed_references_for_partial_recovery(
    document: &EvidenceDocument,
) -> Result<Vec<SealedReference>, LegacyUploadEvidenceError> {
    let mut references = Vec::new();
    for reference in &document.reference_normalizations {
        match fs::symlink_metadata(&reference.reference_path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(failure("reference_descriptor")),
        }
        let held = HeldGenerationSource::open(&reference.reference_path)
            .map_err(|_| failure("reference_descriptor"))?;
        references.push(SealedReference {
            path: held.path,
            file: held.file,
            initial_metadata: held.metadata,
            sha256: held.sha256,
        });
    }
    Ok(references)
}

#[cfg(not(unix))]
fn open_sealed_references(
    _document: &EvidenceDocument,
) -> Result<Vec<SealedReference>, LegacyUploadEvidenceError> {
    Err(failure("reference_descriptor"))
}

#[cfg(not(unix))]
fn open_sealed_references_for_partial_recovery(
    _document: &EvidenceDocument,
) -> Result<Vec<SealedReference>, LegacyUploadEvidenceError> {
    Err(failure("reference_descriptor"))
}

#[cfg(unix)]
fn revalidate_sealed_references(
    references: &mut [SealedReference],
) -> Result<(), LegacyUploadEvidenceError> {
    for reference in references {
        let held = EvidenceMetadata::capture(
            &reference
                .file
                .metadata()
                .map_err(|_| failure("reference_metadata"))?,
        );
        if held != reference.initial_metadata
            || sha256_open_file(&mut reference.file)? != reference.sha256
        {
            return Err(failure("reference_changed"));
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        let mut named = options
            .open(&reference.path)
            .map_err(|_| failure("reference_changed"))?;
        if EvidenceMetadata::capture(
            &named
                .metadata()
                .map_err(|_| failure("reference_metadata"))?,
        ) != reference.initial_metadata
            || sha256_open_file(&mut named)? != reference.sha256
        {
            return Err(failure("reference_changed"));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn revalidate_held_reference_descriptors(
    references: &mut [SealedReference],
) -> Result<(), LegacyUploadEvidenceError> {
    for reference in references {
        let held = EvidenceMetadata::capture(
            &reference
                .file
                .metadata()
                .map_err(|_| failure("reference_metadata"))?,
        );
        if !held.matches_after_rename(reference.initial_metadata)
            || sha256_open_file(&mut reference.file)? != reference.sha256
        {
            return Err(failure("reference_changed"));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn revalidate_sealed_references(
    _references: &mut [SealedReference],
) -> Result<(), LegacyUploadEvidenceError> {
    Err(failure("reference_descriptor"))
}

#[cfg(not(unix))]
fn revalidate_held_reference_descriptors(
    _references: &mut [SealedReference],
) -> Result<(), LegacyUploadEvidenceError> {
    Err(failure("reference_descriptor"))
}

#[cfg(unix)]
fn sha256_open_file(file: &mut fs::File) -> Result<String, LegacyUploadEvidenceError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| failure("reference_read"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| failure("reference_read"))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| failure("reference_read"))?;
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(unix)]
fn read_sealed_evidence(path: &Path) -> Result<SealedEvidence, LegacyUploadEvidenceError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| failure("evidence_open"))?;
    let before = file.metadata().map_err(|_| failure("evidence_metadata"))?;
    validate_evidence_metadata(&before)?;
    let initial_metadata = EvidenceMetadata::capture(&before);
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_EVIDENCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure("evidence_read"))?;
    if bytes.len() as u64 > MAX_EVIDENCE_BYTES {
        return Err(failure("evidence_size"));
    }
    let sha256 = sha256_bytes(&bytes);
    Ok(SealedEvidence {
        bytes,
        sha256,
        file,
        initial_metadata,
    })
}

#[cfg(unix)]
fn revalidate_sealed_evidence(
    evidence: &mut SealedEvidence,
    path: &Path,
) -> Result<(), LegacyUploadEvidenceError> {
    run_evidence_post_read_hook();
    evidence
        .file
        .seek(SeekFrom::Start(0))
        .map_err(|_| failure("evidence_changed"))?;
    let mut reread = Vec::new();
    Read::by_ref(&mut evidence.file)
        .take(MAX_EVIDENCE_BYTES + 1)
        .read_to_end(&mut reread)
        .map_err(|_| failure("evidence_changed"))?;
    if reread.len() as u64 > MAX_EVIDENCE_BYTES
        || sha256_bytes(&reread) != evidence.sha256
        || reread != evidence.bytes
    {
        return Err(failure("evidence_changed"));
    }
    let held = evidence
        .file
        .metadata()
        .map_err(|_| failure("evidence_changed"))?;
    validate_evidence_metadata(&held).map_err(|_| failure("evidence_changed"))?;
    let held_metadata = EvidenceMetadata::capture(&held);
    if held_metadata != evidence.initial_metadata {
        return Err(failure("evidence_changed"));
    }

    let current_path = fs::symlink_metadata(path).map_err(|_| failure("evidence_changed"))?;
    if current_path.file_type().is_symlink() || !current_path.file_type().is_file() {
        return Err(failure("evidence_changed"));
    }
    validate_evidence_metadata(&current_path).map_err(|_| failure("evidence_changed"))?;
    if EvidenceMetadata::capture(&current_path) != held_metadata {
        return Err(failure("evidence_changed"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_evidence_metadata(metadata: &fs::Metadata) -> Result<(), LegacyUploadEvidenceError> {
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    let current_euid = unsafe { libc::geteuid() };
    validate_evidence_attributes(
        metadata.file_type().is_file(),
        metadata.mode(),
        metadata.uid(),
        metadata.nlink(),
        current_euid,
    )
}

#[cfg(unix)]
fn validate_evidence_attributes(
    is_regular: bool,
    mode: u32,
    uid: u32,
    nlink: u64,
    current_euid: u32,
) -> Result<(), LegacyUploadEvidenceError> {
    if !is_regular || mode & 0o777 != 0o600 || uid != current_euid || nlink != 1 {
        return Err(failure("evidence_permissions"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn read_sealed_evidence(_path: &Path) -> Result<SealedEvidence, LegacyUploadEvidenceError> {
    Err(failure("unsupported_platform"))
}

#[cfg(not(unix))]
fn revalidate_sealed_evidence(
    _evidence: &mut SealedEvidence,
    _path: &Path,
) -> Result<(), LegacyUploadEvidenceError> {
    Err(failure("unsupported_platform"))
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use serde_json::json;

    use super::*;
    use crate::manifest::FailureRecord;

    struct Fixture {
        _temp: tempfile::TempDir,
        manifest_path: PathBuf,
        evidence_path: PathBuf,
        artifact_root: PathBuf,
        quarantine_root: PathBuf,
        request: LegacyUploadEvidenceAuditRequest,
        document: EvidenceDocument,
    }

    fn digest(label: &str) -> String {
        sha256_bytes(label.as_bytes())
    }

    fn active_original_validation() -> CloudKitActiveAssetValidation {
        CloudKitActiveAssetValidation {
            remote_state: CloudKitActiveAssetRemoteState::Active,
            lookup_mode: CloudKitActiveAssetLookupMode::FullFields,
        }
    }

    fn original_validation_for(
        replacement: &EvidenceRetiredReplacement,
    ) -> CloudKitActiveAssetValidation {
        CloudKitActiveAssetValidation {
            remote_state: replacement.original_remote_state,
            lookup_mode: replacement.original_state_lookup_mode,
        }
    }

    fn jpeg_with_orientation(orientation: u8) -> Vec<u8> {
        let pixels = vec![
            255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 0, 0, 255, 255, 255, 0, 255, 32, 64, 96, 96,
            64, 32, 16, 48, 80, 80, 48, 16, 120, 60, 30, 30, 60, 120,
        ];
        let mut jpeg = Vec::new();
        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg, 95)
            .encode(&pixels, 4, 3, image::ExtendedColorType::Rgb8)
            .unwrap();
        let mut exif_payload = [
            b'E', b'x', b'i', b'f', 0, 0, b'I', b'I', 42, 0, 8, 0, 0, 0, 1, 0, 0x12, 0x01, 3, 0, 1,
            0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
        ];
        exif_payload[24] = orientation;
        let length = (exif_payload.len() + 2) as u16;
        let mut segment = vec![0xff, 0xe1, (length >> 8) as u8, length as u8];
        segment.extend_from_slice(&exif_payload);
        jpeg.splice(2..2, segment);
        jpeg
    }

    fn record(asset_id: &str, root: &Path) -> AssetRecord {
        let raw_path = root.join(format!("{asset_id}.dng"));
        let heic_path = root.join(format!("{asset_id}.heic"));
        let mirror_path = root.join(format!("{asset_id}.mirror.heic"));
        let reference_path = root.join(format!("{asset_id}.oriented-preview.jpg"));
        let heic_bytes = format!("heic-{asset_id}").into_bytes();
        let raw_bytes = format!("raw-{asset_id}").repeat(10).into_bytes();
        fs::write(&raw_path, &raw_bytes).unwrap();
        fs::write(&heic_path, &heic_bytes).unwrap();
        fs::write(&mirror_path, &heic_bytes).unwrap();
        fs::write(reference_path, jpeg_with_orientation(6)).unwrap();
        let heic_sha256 = sha256_bytes(&heic_bytes);
        let size_bytes = heic_bytes.len() as u64;
        let uploaded_asset_id = format!("uploaded-{asset_id}");
        let raw_sha256 = sha256_bytes(&raw_bytes);
        let mut record = AssetRecord::new(asset_id, raw_path);
        record.state = State::UploadVerified;
        record.updated_at = "2026-07-13T00:00:00Z".to_string();
        record.failures = vec![FailureRecord::new("historical", "preserved")];
        record.proofs = BTreeMap::from([
            (
                "nas".to_string(),
                json!({
                    "canonical_path": record.raw_path.clone(),
                    "relative_path": format!("{asset_id}.dng"),
                    "size_bytes": raw_bytes.len() as u64,
                    "modified_unix_seconds": 1_700_000_000_u64,
                    "age_seconds": 3_000_000_u64,
                    "sha256": raw_sha256,
                }),
            ),
            (
                "conversion".to_string(),
                json!({"heic_path": heic_path, "heic_sha256": heic_sha256, "size_bytes": size_bytes}),
            ),
            (
                "conversion_performance".to_string(),
                json!({"fixture": "sealed-old-performance-lineage"}),
            ),
            (
                "heic".to_string(),
                json!({
                    "heic_path": heic_path,
                    "heic_sha256": heic_sha256,
                    "size_bytes": size_bytes,
                    "heif_info_ok": true,
                    "metadata_copied": true,
                    "visual_content_ok": true,
                    "visual_match_ok": true
                }),
            ),
            (
                "upload".to_string(),
                json!({
                    "uploaded_heic_asset_id": uploaded_asset_id,
                    "uploaded_heic_sha256": heic_sha256,
                    "database_scope": "private",
                    "zone_name": "PrimarySync",
                    "owner_record_name": null,
                    "uploaded_heic_path": heic_path
                }),
            ),
            (
                "icloudpd_local_mirror".to_string(),
                json!({
                    "uploaded_heic_asset_id": uploaded_asset_id,
                    "uploaded_heic_sha256": heic_sha256,
                    "uploaded_heic_path": heic_path,
                    "icloudpd_download_path": mirror_path,
                    "size_bytes": size_bytes
                }),
            ),
            (
                "original_asset".to_string(),
                json!({
                    "record_name": format!("original-{asset_id}"),
                    "record_change_tag": "original-tag",
                    "record_type": "CPLMaster",
                    "database_scope": "private",
                    "zone_name": "PrimarySync",
                    "owner_record_name": null,
                    "filename": format!("{asset_id}.dng"),
                    "size_bytes": raw_bytes.len() as u64,
                    "matched_raw_sha256": raw_sha256
                }),
            ),
        ]);
        record
    }

    fn replacement(record: &AssetRecord) -> EvidenceRetiredReplacement {
        let upload = record.proofs.get("upload").unwrap();
        let mirror = record.proofs.get("icloudpd_local_mirror").unwrap();
        let original = record.proofs.get("original_asset").unwrap();
        let heic = record.proofs.get("heic").unwrap();
        let destination = EvidenceDestination {
            database_scope: CloudKitDatabaseScope::Private,
            zone_name: "PrimarySync".to_string(),
            owner_record_name: None,
            filename: format!("{}.heic", record.asset_id),
        };
        EvidenceRetiredReplacement {
            asset_id: record.asset_id.clone(),
            uploaded_asset_id: upload["uploaded_heic_asset_id"]
                .as_str()
                .unwrap()
                .to_string(),
            uploaded_master_id: format!("master-{}", record.asset_id),
            owner_record_name_sha256: digest("opaque-owner"),
            initial_remote_state: CloudKitUploadedHeicInitialState::Active,
            initial_state_lookup_mode:
                crate::upload::CloudKitUploadedHeicInitialStateLookupMode::FullFields,
            destination_sha256: digest_value(&destination).unwrap(),
            destination,
            old_record_change_tag: format!("old-tag-{}", record.asset_id),
            uploaded_heic_sha256: upload["uploaded_heic_sha256"].as_str().unwrap().to_string(),
            uploaded_heic_size_bytes: heic["size_bytes"].as_u64().unwrap(),
            original_asset_record_name: original["record_name"].as_str().unwrap().to_string(),
            original_record_change_tag: original["record_change_tag"].as_str().unwrap().to_string(),
            original_remote_state: CloudKitActiveAssetRemoteState::Active,
            original_state_lookup_mode: CloudKitActiveAssetLookupMode::FullFields,
            original_asset_identity_sha256: digest_value(original).unwrap(),
            old_conversion_lineage_sha256: digest_value(record.proofs.get("conversion").unwrap())
                .unwrap(),
            old_upload_lineage_sha256: digest_value(upload).unwrap(),
            old_mirror_lineage_sha256: digest_value(mirror).unwrap(),
        }
    }

    fn recovered_deleted_asset(
        replacement: &EvidenceRetiredReplacement,
    ) -> crate::upload::CloudKitUploadedHeicAsset {
        crate::upload::CloudKitUploadedHeicAsset {
            record_name: replacement.uploaded_asset_id.clone(),
            record_change_tag: format!("confirmed-{}", replacement.asset_id),
            master_record_name: replacement.uploaded_master_id.clone(),
            owner_record_name_sha256: replacement.owner_record_name_sha256.clone(),
            initial_remote_state: CloudKitUploadedHeicInitialState::AlreadyDeleted,
            initial_state_lookup_mode: replacement.initial_state_lookup_mode,
            matched_heic_sha256: replacement.uploaded_heic_sha256.clone(),
            size_bytes: replacement.uploaded_heic_size_bytes,
        }
    }

    fn set_cohort_digest(document: &mut EvidenceDocument) {
        document.cohort_sha256 = canonical_digest(&CohortDigestInput {
            schema_version: document.schema_version,
            migration_id: &document.migration_id,
            asset_count: document.asset_count,
            retired_replacement_count: document.retired_replacement_count,
            reference_count: document.reference_count,
            assets: &document.assets,
            retired_replacements: &document.retired_replacements,
            reference_normalizations: &document.reference_normalizations,
            quarantine_roots: &document.quarantine_roots,
            quarantine_members: &document.quarantine_members,
            raw_inputs: &document.raw_inputs,
        })
        .unwrap();
    }

    fn fixture_quarantine_identity(path: &Path) -> LegacyUploadMigrationQuarantineFileIdentity {
        let metadata = fs::metadata(path).unwrap();
        LegacyUploadMigrationQuarantineFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode() & 0o777,
            link_count: metadata.nlink(),
            size_bytes: metadata.len(),
            modified_unix_seconds: metadata.mtime(),
            modified_unix_nanoseconds: metadata.mtime_nsec(),
            sha256: sha256_bytes(&fs::read(path).unwrap()),
        }
    }

    fn write_document(fixture: &mut Fixture) {
        set_cohort_digest(&mut fixture.document);
        let bytes = serde_json::to_vec_pretty(&fixture.document).unwrap();
        fs::write(&fixture.evidence_path, &bytes).unwrap();
        fs::set_permissions(&fixture.evidence_path, fs::Permissions::from_mode(0o600)).unwrap();
        fixture.request.expected_evidence_sha256 = sha256_bytes(&bytes);
        fixture.request.expected_cohort_sha256 = fixture.document.cohort_sha256.clone();
    }

    fn append_test_quarantine_root(
        evidence: &mut ValidatedLegacyUploadEvidence,
        root: super::super::LegacyUploadMigrationQuarantineRoot,
    ) {
        let mut plan = evidence.operational_quarantine_plan.clone();
        plan.roots.push(root);
        plan.roots
            .sort_by(|left, right| left.canonical_path.cmp(&right.canonical_path));
        plan.plan_sha256 = canonical_digest(&(
            plan.schema_version,
            &plan.roots,
            &plan.members,
            &plan.raw_inputs,
        ))
        .unwrap();
        evidence.operational_quarantine_plan = plan.clone();
        for preparation in &mut evidence.validated.preparation_authority.preparations {
            preparation.identity.quarantine_plan = plan.clone();
        }
    }

    fn build_fixture() -> Fixture {
        build_fixture_with_original_destination_fields(true)
    }

    fn build_fixture_with_original_destination_fields(
        include_original_destination_fields: bool,
    ) -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let manifest_path = temp.path().join("manifest.json");
        let evidence_path = temp.path().join("evidence.json");
        let canonical_temp = fs::canonicalize(temp.path()).unwrap();
        let artifact_root = canonical_temp.join("artifacts");
        fs::create_dir(&artifact_root).unwrap();
        let quarantine_root = canonical_temp.join("quarantine");
        fs::create_dir(&quarantine_root).unwrap();
        fs::set_permissions(&quarantine_root, fs::Permissions::from_mode(0o700)).unwrap();
        let mut manifest = Manifest::new();
        let mut records = (0..ASSET_COUNT)
            .map(|index| record(&format!("asset-{index:02}"), &artifact_root))
            .collect::<Vec<_>>();
        if !include_original_destination_fields {
            for record in &mut records[..RETIRED_REPLACEMENT_COUNT] {
                let original = record
                    .proofs
                    .get_mut("original_asset")
                    .and_then(Value::as_object_mut)
                    .unwrap();
                original.remove("database_scope");
                original.remove("zone_name");
            }
        }
        for record in &records {
            manifest.upsert_trusted(record.clone());
        }
        manifest.save_atomic(&manifest_path).unwrap();
        let writer = AssetStateStore::open_writer(
            &manifest_path,
            "legacy-upload-evidence-fixture",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        writer.load_or_import().unwrap();
        writer.release_writer_lease().unwrap();
        let assets = records
            .iter()
            .map(|record| EvidenceAsset {
                asset_id: record.asset_id.clone(),
                record_sha256: legacy_upload_migration_record_digest(record).unwrap(),
            })
            .collect();
        let retired_replacements = records[..RETIRED_REPLACEMENT_COUNT]
            .iter()
            .map(replacement)
            .collect();
        let reference_normalizations = REFERENCE_ASSET_INDICES
            .iter()
            .zip(REFERENCE_ORIENTATIONS)
            .map(|(record_index, orientation)| {
                let record = &records[*record_index];
                let upload: UploadProof =
                    serde_json::from_value(record.proofs["upload"].clone()).unwrap();
                let mut reference_path = upload.uploaded_heic_path.unwrap();
                reference_path.set_extension("oriented-preview.jpg");
                fs::write(&reference_path, jpeg_with_orientation(orientation as u8)).unwrap();
                let metadata = fs::metadata(&reference_path).unwrap();
                let file_sha256 = sha256_bytes(&fs::read(&reference_path).unwrap());
                let decoded_pixel_sha256 = {
                    let rgb = image::open(&reference_path).unwrap().to_rgb8();
                    sha256_bytes(&rgb.into_raw())
                };
                let mut reference = EvidenceReferenceNormalization {
                    asset_id: record.asset_id.clone(),
                    asset_record_sha256: legacy_upload_migration_record_digest(record).unwrap(),
                    reference_identity_sha256: String::new(),
                    reference_path,
                    device: metadata.dev(),
                    inode: metadata.ino(),
                    size_bytes: metadata.len(),
                    file_sha256,
                    orientation,
                    width: 4,
                    height: 3,
                    decoded_pixel_sha256,
                };
                reference.reference_identity_sha256 =
                    canonical_digest(&ReferenceIdentityDigestInput {
                        schema_version: EVIDENCE_SCHEMA_VERSION,
                        asset_id: &reference.asset_id,
                        reference_path: &reference.reference_path,
                        device: reference.device,
                        inode: reference.inode,
                        size_bytes: reference.size_bytes,
                        file_sha256: &reference.file_sha256,
                        orientation: reference.orientation,
                        width: reference.width,
                        height: reference.height,
                        decoded_pixel_sha256: &reference.decoded_pixel_sha256,
                    })
                    .unwrap();
                reference
            })
            .collect::<Vec<_>>();
        let root_metadata = fs::metadata(&quarantine_root).unwrap();
        let quarantine_roots = vec![EvidenceQuarantineRoot {
            canonical_path: quarantine_root.clone(),
            device: root_metadata.dev(),
            inode: root_metadata.ino(),
            owner: root_metadata.uid(),
            mode: root_metadata.mode() & 0o777,
        }];
        let mut quarantine_members = Vec::with_capacity(9);
        for record in &records[..RETIRED_REPLACEMENT_COUNT] {
            let upload: UploadProof =
                serde_json::from_value(record.proofs["upload"].clone()).unwrap();
            let mirror: IcloudpdLocalMirrorProof =
                serde_json::from_value(record.proofs["icloudpd_local_mirror"].clone()).unwrap();
            for (kind, path) in [
                (
                    LegacyUploadMigrationQuarantineKind::Final,
                    upload.uploaded_heic_path.unwrap(),
                ),
                (
                    LegacyUploadMigrationQuarantineKind::OldMirror,
                    mirror.icloudpd_download_path,
                ),
            ] {
                let source = fixture_quarantine_identity(&path);
                quarantine_members.push(EvidenceQuarantineMember {
                    asset_id: record.asset_id.clone(),
                    kind,
                    source_path: path,
                    root_device: source.device,
                    source,
                });
            }
        }
        for reference in &reference_normalizations {
            let source = fixture_quarantine_identity(&reference.reference_path);
            quarantine_members.push(EvidenceQuarantineMember {
                asset_id: reference.asset_id.clone(),
                kind: LegacyUploadMigrationQuarantineKind::Reference,
                source_path: reference.reference_path.clone(),
                root_device: source.device,
                source,
            });
        }
        quarantine_members.sort_by(|left, right| {
            (&left.asset_id, left.kind, &left.source_path).cmp(&(
                &right.asset_id,
                right.kind,
                &right.source_path,
            ))
        });
        let raw_inputs = records
            .iter()
            .map(|record| EvidenceRawInput {
                asset_id: record.asset_id.clone(),
                path: record.raw_path.clone(),
                source: fixture_quarantine_identity(&record.raw_path),
            })
            .collect();
        let document = EvidenceDocument {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            migration_id: digest("migration"),
            asset_count: ASSET_COUNT as u64,
            retired_replacement_count: RETIRED_REPLACEMENT_COUNT as u64,
            reference_count: REFERENCE_COUNT as u64,
            cohort_sha256: String::new(),
            assets,
            retired_replacements,
            reference_normalizations,
            quarantine_roots,
            quarantine_members,
            raw_inputs,
        };
        let request = LegacyUploadEvidenceAuditRequest {
            manifest_path: manifest_path.clone(),
            evidence_path: evidence_path.clone(),
            expected_evidence_sha256: String::new(),
            expected_asset_count: ASSET_COUNT as u64,
            expected_retired_replacement_count: RETIRED_REPLACEMENT_COUNT as u64,
            expected_reference_count: REFERENCE_COUNT as u64,
            expected_cohort_sha256: String::new(),
        };
        let mut fixture = Fixture {
            _temp: temp,
            manifest_path,
            evidence_path,
            artifact_root,
            quarantine_root,
            request,
            document,
        };
        write_document(&mut fixture);
        fixture
    }

    #[test]
    fn apply_loader_uses_writer_state_when_wal_is_pending() {
        let fixture = build_fixture();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-apply-wal",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let connection = rusqlite::Connection::open(writer.path()).unwrap();
        connection
            .pragma_update(None, "wal_autocheckpoint", 0)
            .unwrap();
        connection
            .execute(
                "UPDATE writer_lease SET renewed_at_unix_ms = renewed_at_unix_ms + 1 WHERE singleton = 1",
                [],
            )
            .unwrap();
        assert!(matches!(
            AssetStateStore::open_immutable_read_only(&fixture.manifest_path),
            Err(crate::state_store::AssetStateStoreError::ReadOnlyWalPending)
        ));

        let validated = load_validated_legacy_uploaded_heic_evidence_with_state_store(
            &fixture.request,
            None,
            &writer,
        )
        .unwrap();
        assert_eq!(
            validated.audit().evidence_sha256,
            fixture.request.expected_evidence_sha256
        );
    }

    #[test]
    fn apply_loader_rejects_manifest_path_alias_with_same_state_database() {
        let fixture = build_fixture();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-apply-path-binding",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let mut aliased_request = fixture.request.clone();
        aliased_request.manifest_path = fixture.manifest_path.with_extension("yaml");
        let error = load_validated_legacy_uploaded_heic_evidence_with_state_store(
            &aliased_request,
            None,
            &writer,
        )
        .err()
        .expect("manifest path alias must be rejected");
        assert_eq!(error.category(), "state_load");
    }

    #[test]
    fn apply_loader_rejects_writer_state_changed_during_audit() {
        let fixture = build_fixture();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-apply-state-binding",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let mut changed_record = writer.load().unwrap().get("asset-00").unwrap().clone();
        changed_record.updated_at = "2999-01-01T00:00:00Z".to_string();
        let writer_for_hook = writer.clone();
        set_evidence_post_read_hook(move || {
            writer_for_hook
                .persist_record_trusted(&changed_record)
                .unwrap();
        });
        let error = load_validated_legacy_uploaded_heic_evidence_with_state_store(
            &fixture.request,
            None,
            &writer,
        )
        .err()
        .expect("writer state changes must be rejected");
        assert_eq!(error.category(), "state_changed");
    }

    fn persist_delete_confirmed(fixture: &Fixture) {
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-device-recovery",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let current = writer.load_or_import().unwrap();
        let validated = validate_document(
            fixture.document.clone(),
            &fixture.request.expected_evidence_sha256,
            &fixture.request,
            &current,
            None,
        )
        .unwrap();
        let ids = std::array::from_fn::<_, 2, _>(|index| {
            fixture.document.retired_replacements[index]
                .asset_id
                .clone()
        });
        let expected = [
            current.get(&ids[0]).unwrap().clone(),
            current.get(&ids[1]).unwrap().clone(),
        ];
        let prepared = [
            super::super::prepare_legacy_upload_migration_record(
                &expected[0],
                &validated.preparation_authority,
            )
            .unwrap(),
            super::super::prepare_legacy_upload_migration_record(
                &expected[1],
                &validated.preparation_authority,
            )
            .unwrap(),
        ];
        super::super::persist_two_legacy_upload_migration_preparations_exact_cas(
            &writer,
            &validated.preparation_authority,
            [
                super::super::LegacyUploadMigrationCasUpdate {
                    expected: &expected[0],
                    updated: &prepared[0],
                },
                super::super::LegacyUploadMigrationCasUpdate {
                    expected: &expected[1],
                    updated: &prepared[1],
                },
            ],
        )
        .unwrap();
        let receipt0 = json!({"asset": 0, "delete": "confirmed"});
        let receipt1 = json!({"asset": 1, "delete": "confirmed"});
        let (authority, confirmed) = super::super::build_legacy_upload_migration_phase_authority(
            [&prepared[0], &prepared[1]],
            [&prepared[0], &prepared[1]],
            super::super::LegacyUploadMigrationPhase::DeleteConfirmed,
            [&receipt0, &receipt1],
        )
        .unwrap();
        super::super::persist_two_legacy_upload_migration_records_exact_cas(
            &writer,
            &authority,
            [
                super::super::LegacyUploadMigrationCasUpdate {
                    expected: &prepared[0],
                    updated: &confirmed[0],
                },
                super::super::LegacyUploadMigrationCasUpdate {
                    expected: &prepared[1],
                    updated: &confirmed[1],
                },
            ],
        )
        .unwrap();
        writer.export_json().unwrap();
        writer.release_writer_lease().unwrap();
    }

    fn rebooted_delete_confirmed_fixture() -> (Fixture, u64, u64) {
        let mut fixture = build_fixture();
        let current_device = fixture.document.quarantine_roots[0].device;
        let previous_device = current_device.checked_add(17).unwrap();
        fixture.document.quarantine_roots[0].device = previous_device;
        for member in &mut fixture.document.quarantine_members {
            member.source.device = previous_device;
            member.root_device = previous_device;
        }
        for raw in &mut fixture.document.raw_inputs {
            raw.source.device = previous_device;
        }
        for reference in &mut fixture.document.reference_normalizations {
            reference.device = previous_device;
            reference.reference_identity_sha256 = canonical_digest(&ReferenceIdentityDigestInput {
                schema_version: EVIDENCE_SCHEMA_VERSION,
                asset_id: &reference.asset_id,
                reference_path: &reference.reference_path,
                device: reference.device,
                inode: reference.inode,
                size_bytes: reference.size_bytes,
                file_sha256: &reference.file_sha256,
                orientation: reference.orientation,
                width: reference.width,
                height: reference.height,
                decoded_pixel_sha256: &reference.decoded_pixel_sha256,
            })
            .unwrap();
        }
        write_document(&mut fixture);
        fs::create_dir(
            fixture
                .quarantine_root
                .join(&fixture.document.cohort_sha256),
        )
        .unwrap();
        fs::set_permissions(
            fixture
                .quarantine_root
                .join(&fixture.document.cohort_sha256),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        persist_delete_confirmed(&fixture);
        (fixture, previous_device, current_device)
    }

    fn fixture_recovery_signer() -> DeviceRecoverySigner {
        DeviceRecoverySigner {
            executable_sha256: digest("signed-recovery-helper"),
            designated_requirement_sha256: digest("stable-private-ca-helper-requirement"),
        }
    }

    fn signed_rotation_service_bundle(root: &Path, helper_bytes: &[u8]) -> PathBuf {
        signed_rotation_service_bundle_with_domain(
            root,
            helper_bytes,
            "com.icloudpd-optimizer.smb.v1",
        )
    }

    fn signed_rotation_service_bundle_v2(root: &Path, helper_bytes: &[u8]) -> PathBuf {
        signed_rotation_service_bundle_with_domain(
            root,
            helper_bytes,
            "com.icloudpd-optimizer.smb.v2",
        )
    }

    fn signed_rotation_service_bundle_with_domain(
        root: &Path,
        helper_bytes: &[u8],
        security_domain: &str,
    ) -> PathBuf {
        let bundle = root.join("Prior Service.app");
        let resources = bundle.join("Contents/Resources");
        fs::create_dir_all(&resources).unwrap();
        let mut policy_value: Value = serde_json::from_slice(include_bytes!(
            "../../policies/authorization-policy-production.json"
        ))
        .unwrap();
        policy_value["item"]["security_domain"] = Value::String(security_domain.to_string());
        let policy_bytes = serde_json::to_vec(&policy_value).unwrap();
        let policy: crate::authorization_policy::AuthorizationPolicy =
            serde_json::from_slice(&policy_bytes).unwrap();
        let helper_relative = policy.helper_relative_path.as_deref().unwrap();
        let helper_path = bundle.join(helper_relative);
        fs::create_dir_all(helper_path.parent().unwrap()).unwrap();
        fs::write(&helper_path, helper_bytes).unwrap();
        fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            resources.join(crate::authorization_policy::POLICY_RESOURCE),
            &policy_bytes,
        )
        .unwrap();
        let provenance = json!({
            "schema_version": 1,
            "source_commit": "0".repeat(40),
            "authority_sha256": crate::authorization_policy::authority_digest(&policy_bytes),
            "helper_sha256": sha256_bytes(helper_bytes),
            "helper_identifier": policy.helper_identifier.as_deref().unwrap(),
            "dashboard_bundle_identifier": policy.dashboard_bundle_identifier.as_deref().unwrap(),
            "service_bundle_identifier": policy.service_bundle_identifier.as_deref().unwrap(),
            "helper_relative_path": helper_relative,
            "service_install_relative_path": policy.service_install_relative_path.as_deref().unwrap(),
            "owner": "effective_user"
        });
        fs::write(
            resources.join(crate::authorization_policy::PROVENANCE_RESOURCE),
            serde_json::to_vec(&provenance).unwrap(),
        )
        .unwrap();
        bundle
    }

    #[test]
    fn prior_v1_bundle_admission_is_rotation_scoped_and_sealed() {
        let temp = tempfile::tempdir().unwrap();
        let canonical_root = fs::canonicalize(temp.path()).unwrap();
        let bundle = signed_rotation_service_bundle(&canonical_root, b"old-signed-helper");
        let loaded = load_prior_recovery_service_bundle(&bundle);
        assert!(loaded.is_ok());
        assert!(
            crate::authorization_policy::load_sealed(&bundle, unsafe { libc::geteuid() }).is_err()
        );

        let policy_path = bundle
            .join("Contents/Resources")
            .join(crate::authorization_policy::POLICY_RESOURCE);
        let original_policy = fs::read(&policy_path).unwrap();
        let mut policy: Value = serde_json::from_slice(&original_policy).unwrap();

        policy["team_id"] = Value::String("AAAAAAAAAA".to_string());
        fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
        assert_eq!(
            load_prior_recovery_service_bundle(&bundle)
                .unwrap_err()
                .category(),
            "recovery_signer"
        );
        fs::write(&policy_path, &original_policy).unwrap();

        policy["item"]["security_domain"] =
            Value::String("com.icloudpd-optimizer.smb.future".to_string());
        fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
        assert_eq!(
            load_prior_recovery_service_bundle(&bundle)
                .unwrap_err()
                .category(),
            "recovery_signer"
        );
        fs::write(&policy_path, &original_policy).unwrap();

        let helper_path = bundle.join("Contents/Resources/icloudpd-optimizer");
        fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            load_prior_recovery_service_bundle(&bundle)
                .unwrap_err()
                .category(),
            "recovery_signer"
        );
        fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o700)).unwrap();

        let provenance_path = bundle
            .join("Contents/Resources")
            .join(crate::authorization_policy::PROVENANCE_RESOURCE);
        let original_provenance = fs::read(&provenance_path).unwrap();
        let mut provenance: Value = serde_json::from_slice(&original_provenance).unwrap();
        provenance["helper_sha256"] = Value::String(digest("tampered-helper"));
        fs::write(&provenance_path, serde_json::to_vec(&provenance).unwrap()).unwrap();
        assert_eq!(
            load_prior_recovery_service_bundle(&bundle)
                .unwrap_err()
                .category(),
            "recovery_signer"
        );
        fs::write(&provenance_path, original_provenance).unwrap();

        let alias = temp.path().join("prior-service-link.app");
        symlink(&bundle, &alias).unwrap();
        assert_eq!(
            load_prior_recovery_service_bundle(&alias)
                .unwrap_err()
                .category(),
            "recovery_signer"
        );
    }

    struct NoCanonicalizationResolver;

    impl LegacyUploadEvidenceResolver for NoCanonicalizationResolver {
        fn resolve_uploaded_heic(
            &mut self,
            _request: &CloudKitUploadedHeicResolveRequest,
        ) -> Result<CloudKitUploadedHeicAsset, LegacyUploadEvidenceError> {
            Err(failure("unexpected_remote_lookup"))
        }

        fn validate_original_active(
            &mut self,
            _original: &OriginalAssetProof,
        ) -> Result<CloudKitActiveAssetValidation, LegacyUploadEvidenceError> {
            Err(failure("unexpected_remote_lookup"))
        }
    }

    #[test]
    fn designated_requirement_parser_requires_exact_canonical_apple_development_team_dr() {
        let canonical = "designated => anchor apple generic and identifier \"com.icloudpd-optimizer.helper\" and certificate leaf[subject.OU] = \"ABCDEFGHIJ\"";
        let requirement = format!("Executable=/sealed/helper\n{canonical}\n");
        assert_eq!(
            parse_designated_requirement(requirement.as_bytes(), b"").unwrap(),
            canonical
        );
        assert_eq!(
            parse_designated_requirement(b"", requirement.as_bytes()).unwrap(),
            canonical
        );
        for malformed in [
            "designated => anchor apple generic and identifier \"wrong\" and certificate leaf[subject.OU] = \"ABCDEFGHIJ\"",
            "designated => anchor apple generic and identifier \"com.icloudpd-optimizer.helper\" and certificate leaf[subject.OU] = \"abcDEFGHIJ\"",
            "designated => anchor apple generic and identifier \"com.icloudpd-optimizer.helper\" and certificate leaf[subject.OU] = \"ABCDEFGHIJ\" and certificate root = H\"abcd\"",
            "designated => certificate root = H\"abcd\" and identifier \"com.icloudpd-optimizer.helper\"",
        ] {
            assert_eq!(
                parse_designated_requirement(format!("{malformed}\n").as_bytes(), b"")
                    .unwrap_err()
                    .category(),
                "recovery_signer"
            );
        }
        assert!(
            parse_designated_requirement(format!("{canonical}\n{canonical}\n").as_bytes(), b"")
                .is_err()
        );
    }

    #[test]
    fn post_reboot_recovery_rebases_only_exact_verified_device_mapping() {
        let (fixture, previous_device, current_device) = rebooted_delete_confirmed_fixture();
        let manifest = AssetStateStore::open_immutable_read_only(&fixture.manifest_path)
            .unwrap()
            .load()
            .unwrap();

        let (operational, mappings) =
            operational_document_for_device_recovery_with_mode(&fixture.document, &manifest, false)
                .unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].previous_device, previous_device);
        assert_eq!(mappings[0].current_device, current_device);
        assert!(
            operational
                .quarantine_members
                .iter()
                .all(|member| member.source.device == current_device
                    && member.root_device == current_device)
        );
        assert!(
            operational
                .raw_inputs
                .iter()
                .all(|raw| raw.source.device == current_device)
        );
        assert!(
            operational
                .reference_normalizations
                .iter()
                .all(|reference| reference.device == current_device)
        );

        let original = fs::read(&operational.raw_inputs[0].path).unwrap();
        fs::write(&operational.raw_inputs[0].path, b"tampered").unwrap();
        assert_eq!(
            operational_document_for_device_recovery_with_mode(
                &fixture.document,
                &manifest,
                false,
            )
                .unwrap_err()
                .category(),
            "recovery_raw"
        );
        fs::write(&operational.raw_inputs[0].path, original).unwrap();
    }

    #[test]
    fn device_recovery_receipt_is_signer_pinned_sealed_and_replay_checked() {
        let (fixture, previous_device, current_device) = rebooted_delete_confirmed_fixture();
        let signer = fixture_recovery_signer();
        let output_path = fixture.artifact_root.join("device-recovery.json");
        let manifest_before = fs::read(&fixture.manifest_path).unwrap();
        let evidence_before = fs::read(&fixture.evidence_path).unwrap();
        set_device_recovery_signer_hook(signer.clone());
        let report = generate_legacy_uploaded_heic_device_recovery_with_resolver(
            &LegacyUploadDeviceRecoveryGenerateRequest {
                evidence: fixture.request.clone(),
                expected_signer_designated_requirement_sha256: signer
                    .designated_requirement_sha256
                    .clone(),
                allow_partial_quarantine: false,
                output_path: output_path.clone(),
            },
            &mut NoCanonicalizationResolver,
        )
        .unwrap();
        assert!(!report.partial_quarantine);
        assert_eq!(report.device_mapping_count, 1);
        assert_eq!(report.raw_input_count, ASSET_COUNT as u64);
        assert_eq!(report.quarantine_member_count, 9);
        assert_eq!(report.reference_count, REFERENCE_COUNT as u64);
        assert_eq!(
            report.signer_designated_requirement_sha256,
            signer.designated_requirement_sha256
        );
        let receipt: DeviceRecoveryReceipt =
            serde_json::from_slice(&fs::read(&output_path).unwrap()).unwrap();
        assert_eq!(receipt.body.mappings[0].previous_device, previous_device);
        assert_eq!(receipt.body.mappings[0].current_device, current_device);
        assert_eq!(fs::metadata(&output_path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::read(&fixture.manifest_path).unwrap(), manifest_before);
        assert_eq!(fs::read(&fixture.evidence_path).unwrap(), evidence_before);

        set_device_recovery_signer_hook(signer.clone());
        let audit = audit_legacy_uploaded_heic_evidence_with_device_recovery(
            &fixture.request,
            &LegacyUploadDeviceRecoveryRequest {
                receipt_path: output_path.clone(),
                expected_receipt_sha256: report.receipt_sha256.clone(),
            },
        )
        .unwrap();
        assert_eq!(audit.asset_count, ASSET_COUNT as u64);

        set_device_recovery_signer_hook(DeviceRecoverySigner {
            executable_sha256: digest("other-helper"),
            designated_requirement_sha256: digest("other-requirement"),
        });
        assert_eq!(
            audit_legacy_uploaded_heic_evidence_with_device_recovery(
                &fixture.request,
                &LegacyUploadDeviceRecoveryRequest {
                    receipt_path: output_path,
                    expected_receipt_sha256: report.receipt_sha256,
                },
            )
            .unwrap_err()
            .category(),
            "recovery_signer_mismatch"
        );
    }

    #[cfg(unix)]
    #[test]
    fn device_recovery_signer_rotation_accepts_reset_and_rejects_prior_helper_tamper() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (fixture, _, _) = rebooted_delete_confirmed_fixture();
        let stale_checkpoint = fs::read(&fixture.manifest_path).unwrap();
        let old_helper = b"old-signed-helper";
        let prior_bundle =
            signed_rotation_service_bundle(fixture.artifact_root.as_path(), old_helper);
        let helper_sha = sha256_bytes(old_helper);
        let requirement = "designated => anchor apple generic and identifier \"com.icloudpd-optimizer.helper\" and certificate leaf[subject.OU] = \"3B86NGN2ZD\"";
        let requirement_sha = sha256_bytes(requirement.as_bytes());
        let prior_signer = DeviceRecoverySigner {
            executable_sha256: helper_sha,
            designated_requirement_sha256: requirement_sha.clone(),
        };
        set_device_recovery_signer_hook(prior_signer.clone());
        let prior_receipt_path = fixture.artifact_root.join("prior-recovery.json");
        let prior_report = generate_legacy_uploaded_heic_device_recovery_with_resolver(
            &LegacyUploadDeviceRecoveryGenerateRequest {
                evidence: fixture.request.clone(),
                expected_signer_designated_requirement_sha256: requirement_sha.clone(),
                allow_partial_quarantine: false,
                output_path: prior_receipt_path.clone(),
            },
            &mut NoCanonicalizationResolver,
        )
        .unwrap();

        let mut validated = load_validated_legacy_uploaded_heic_evidence_with_device_recovery(
            &fixture.request,
            Some(&LegacyUploadDeviceRecoveryRequest {
                receipt_path: prior_receipt_path.clone(),
                expected_receipt_sha256: prior_report.receipt_sha256.clone(),
            }),
        )
        .unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-device-recovery-rotate",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        struct MoveAll;
        impl super::super::apply::LegacyArtifactQuarantineAdapter for MoveAll {
            type Error = ();
            fn quarantine_and_normalize(
                &mut self,
                evidence: &ValidatedLegacyUploadEvidence,
                _manifest: &Manifest,
            ) -> Result<super::super::apply::QuarantineBatchReceipt, Self::Error> {
                for member in &evidence.quarantine_plan().members {
                    fs::create_dir_all(member.destination_path.parent().unwrap()).unwrap();
                    fs::set_permissions(
                        member.destination_path.parent().unwrap(),
                        fs::Permissions::from_mode(0o700),
                    )
                    .unwrap();
                    fs::rename(&member.source_path, &member.destination_path).unwrap();
                }
                Ok(super::super::apply::QuarantineBatchReceipt {
                    schema_version: 2,
                    cohort_sha256: evidence.audit().cohort_sha256.clone(),
                    canonical_root_identity_sha256: canonical_digest(
                        &evidence.quarantine_plan().roots,
                    )
                    .unwrap(),
                    target_set_sha256: digest("rotate-targets"),
                    target_count: 9,
                    normalized_reference_count: 5,
                })
            }
        }
        super::super::apply::ensure_quarantined(&writer, &mut validated, &mut MoveAll).unwrap();
        super::super::apply::ensure_reset(&writer, &mut validated).unwrap();
        writer.release_writer_lease().unwrap();
        fs::write(&fixture.manifest_path, &stale_checkpoint).unwrap();

        let current_signer = DeviceRecoverySigner {
            executable_sha256: digest("new-signed-helper"),
            designated_requirement_sha256: requirement_sha,
        };
        set_device_recovery_signer_hook(current_signer.clone());
        let helper_path = prior_bundle.join("Contents/Resources/icloudpd-optimizer");
        assert_eq!(
            recovery_signer_for_executable(&helper_path).unwrap(),
            prior_signer
        );
        let rotation_writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-device-recovery-rotate-current",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let rotated_path = fixture.artifact_root.join("rotated-recovery.json");
        let rotated = rotate_legacy_uploaded_heic_device_recovery(
            &LegacyUploadDeviceRecoveryRotateRequest {
                evidence: fixture.request.clone(),
                prior_receipt_path: prior_receipt_path.clone(),
                expected_prior_receipt_sha256: prior_report.receipt_sha256.clone(),
                prior_service_bundle: prior_bundle.clone(),
                output_path: rotated_path.clone(),
            },
            &rotation_writer,
        )
        .unwrap();
        assert_eq!(rotated.migration_phase, "reset");
        assert!(rotated.checkpoint_recovered);
        assert_eq!(rotated.previous_receipt_sha256, prior_report.receipt_sha256);
        assert_ne!(rotated.receipt_sha256, rotated.previous_receipt_sha256);
        let new_receipt = LegacyUploadDeviceRecoveryRequest {
            receipt_path: rotated_path,
            expected_receipt_sha256: rotated.receipt_sha256,
        };
        load_validated_legacy_uploaded_heic_evidence_with_device_recovery(
            &fixture.request,
            Some(&new_receipt),
        )
        .unwrap();

        // A receipt already produced under the current v2 policy remains a
        // valid prior witness for a later signer rotation.
        let v2_prior_bundle =
            signed_rotation_service_bundle_v2(&fixture.artifact_root.join("v2-prior"), old_helper);
        let v2_rotation = rotate_legacy_uploaded_heic_device_recovery(
            &LegacyUploadDeviceRecoveryRotateRequest {
                evidence: fixture.request.clone(),
                prior_receipt_path: prior_receipt_path.clone(),
                expected_prior_receipt_sha256: prior_report.receipt_sha256.clone(),
                prior_service_bundle: v2_prior_bundle,
                output_path: fixture.artifact_root.join("rotated-recovery-v2.json"),
            },
            &rotation_writer,
        )
        .unwrap();
        assert!(!v2_rotation.checkpoint_recovered);

        let current_checkpoint_rotation = rotate_legacy_uploaded_heic_device_recovery(
            &LegacyUploadDeviceRecoveryRotateRequest {
                evidence: fixture.request.clone(),
                prior_receipt_path: prior_receipt_path.clone(),
                expected_prior_receipt_sha256: prior_report.receipt_sha256.clone(),
                prior_service_bundle: prior_bundle.clone(),
                output_path: fixture.artifact_root.join("rotated-recovery-noop.json"),
            },
            &rotation_writer,
        )
        .unwrap();
        assert!(!current_checkpoint_rotation.checkpoint_recovered);

        // A failed atomic export leaves no receipt and does not authorize a
        // retry.  The pre-export hook makes the checkpoint destination
        // unreplaceable after every governed input has passed validation.
        let current_checkpoint = fs::read(&fixture.manifest_path).unwrap();
        let rotation_output = fixture.artifact_root.join("rotation-export-failure.json");
        fs::write(&fixture.manifest_path, stale_checkpoint.clone()).unwrap();
        let manifest_path_for_failure = fixture.manifest_path.clone();
        set_device_recovery_pre_checkpoint_export_hook(move || {
            fs::remove_file(&manifest_path_for_failure).unwrap();
            fs::create_dir(&manifest_path_for_failure).unwrap();
        });
        let export_error = rotate_legacy_uploaded_heic_device_recovery(
            &LegacyUploadDeviceRecoveryRotateRequest {
                evidence: fixture.request.clone(),
                prior_receipt_path: prior_receipt_path.clone(),
                expected_prior_receipt_sha256: prior_report.receipt_sha256.clone(),
                prior_service_bundle: prior_bundle.clone(),
                output_path: rotation_output.clone(),
            },
            &rotation_writer,
        )
        .unwrap_err();
        assert_eq!(export_error.category(), "checkpoint_export");
        assert!(!rotation_output.exists());
        fs::remove_dir(&fixture.manifest_path).unwrap();
        fs::write(&fixture.manifest_path, &current_checkpoint).unwrap();

        // A governed-input change after export is rejected before the new
        // owner-only receipt can be published.
        let evidence_before = fs::read(&fixture.evidence_path).unwrap();
        fs::write(&fixture.manifest_path, &stale_checkpoint).unwrap();
        let evidence_path_for_tamper = fixture.evidence_path.clone();
        set_device_recovery_checkpoint_export_hook(move || {
            fs::write(&evidence_path_for_tamper, b"tampered-after-export").unwrap();
        });
        let tamper_error = rotate_legacy_uploaded_heic_device_recovery(
            &LegacyUploadDeviceRecoveryRotateRequest {
                evidence: fixture.request.clone(),
                prior_receipt_path: prior_receipt_path.clone(),
                expected_prior_receipt_sha256: prior_report.receipt_sha256.clone(),
                prior_service_bundle: prior_bundle.clone(),
                output_path: fixture.artifact_root.join("rotation-tampered.json"),
            },
            &rotation_writer,
        )
        .unwrap_err();
        assert_eq!(tamper_error.category(), "evidence_changed");
        fs::write(&fixture.evidence_path, evidence_before).unwrap();
        fs::write(&fixture.manifest_path, &current_checkpoint).unwrap();

        let helper_path_for_tamper = prior_bundle.join("Contents/Resources/icloudpd-optimizer");
        fs::write(&fixture.manifest_path, &stale_checkpoint).unwrap();
        let helper_path_for_race = helper_path_for_tamper.clone();
        set_device_recovery_checkpoint_export_hook(move || {
            fs::write(&helper_path_for_race, b"tampered-helper-after-export").unwrap();
        });
        let helper_race_error = rotate_legacy_uploaded_heic_device_recovery(
            &LegacyUploadDeviceRecoveryRotateRequest {
                evidence: fixture.request.clone(),
                prior_receipt_path: prior_receipt_path.clone(),
                expected_prior_receipt_sha256: prior_report.receipt_sha256.clone(),
                prior_service_bundle: prior_bundle.clone(),
                output_path: fixture.artifact_root.join("rotation-helper-race.json"),
            },
            &rotation_writer,
        )
        .unwrap_err();
        assert!(matches!(
            helper_race_error.category(),
            "recovery_signer" | "recovery_signer_mismatch"
        ));
        fs::write(&helper_path_for_tamper, old_helper).unwrap();
        rotation_writer.export_json().unwrap();

        // A writer-side manifest race after export is fenced by the exact
        // authoritative snapshot check, even though the competing write uses
        // the same lease in this deterministic test.
        let race_manifest = rotation_writer.load().unwrap();
        let race_original = race_manifest
            .records()
            .values()
            .find(|record| {
                !record
                    .proofs
                    .contains_key(super::super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME)
            })
            .cloned()
            .expect("fixture should include an ordinary manifest record");
        let mut race_updated = race_original.clone();
        race_updated.updated_at.push_str("-race");
        fs::write(&fixture.manifest_path, &stale_checkpoint).unwrap();
        let race_store = rotation_writer.clone();
        set_device_recovery_checkpoint_export_hook(move || {
            race_store.persist_record_trusted(&race_updated).unwrap();
        });
        let race_error = rotate_legacy_uploaded_heic_device_recovery(
            &LegacyUploadDeviceRecoveryRotateRequest {
                evidence: fixture.request.clone(),
                prior_receipt_path: prior_receipt_path.clone(),
                expected_prior_receipt_sha256: prior_report.receipt_sha256.clone(),
                prior_service_bundle: prior_bundle.clone(),
                output_path: fixture.artifact_root.join("rotation-race.json"),
            },
            &rotation_writer,
        )
        .unwrap_err();
        assert_eq!(race_error.category(), "state_changed");
        let restore_connection = rusqlite::Connection::open(AssetStateStore::db_path_for_manifest(
            &fixture.manifest_path,
        ))
        .unwrap();
        restore_connection
            .execute(
                "UPDATE assets SET state = ?1, updated_at = ?2, record_json = ?3 WHERE asset_id = ?4",
                rusqlite::params![
                    race_original.state.as_str(),
                    race_original.updated_at,
                    serde_json::to_string(&race_original).unwrap(),
                    race_original.asset_id,
                ],
            )
            .unwrap();
        rotation_writer.export_json().unwrap();

        fs::write(
            prior_bundle.join("Contents/Resources/icloudpd-optimizer"),
            b"tampered-helper",
        )
        .unwrap();
        set_device_recovery_signer_hook(current_signer);
        let error = rotate_legacy_uploaded_heic_device_recovery(
            &LegacyUploadDeviceRecoveryRotateRequest {
                evidence: fixture.request,
                prior_receipt_path,
                expected_prior_receipt_sha256: prior_report.receipt_sha256,
                prior_service_bundle: prior_bundle,
                output_path: fixture.artifact_root.join("tampered-rotation.json"),
            },
            &rotation_writer,
        )
        .unwrap_err();
        assert_eq!(error.category(), "recovery_signer");
        rotation_writer.release_writer_lease().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn device_recovery_accepts_exact_partial_reference_layout_after_device_remap() {
        // The production adapter probes JPEG metadata through `exiftool`, which is
        // resolved from PATH. Conversion tests replace PATH with fixture tools; use
        // the project-wide lock so this boundary test cannot observe that test-only
        // PATH while it is probing the resumed layout.
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (fixture, _, _) = rebooted_delete_confirmed_fixture();
        let signer = fixture_recovery_signer();
        let output_path = fixture.artifact_root.join("device-recovery-partial.json");
        set_device_recovery_signer_hook(signer.clone());
        let report = generate_legacy_uploaded_heic_device_recovery_with_resolver(
            &LegacyUploadDeviceRecoveryGenerateRequest {
                evidence: fixture.request.clone(),
                expected_signer_designated_requirement_sha256: signer
                    .designated_requirement_sha256
                    .clone(),
                allow_partial_quarantine: false,
                output_path: output_path.clone(),
            },
            &mut NoCanonicalizationResolver,
        )
        .unwrap();
        let initial_recovery = LegacyUploadDeviceRecoveryRequest {
            receipt_path: output_path,
            expected_receipt_sha256: report.receipt_sha256,
        };
        let receipt: DeviceRecoveryReceipt =
            serde_json::from_slice(&fs::read(&initial_recovery.receipt_path).unwrap()).unwrap();
        let manifest = AssetStateStore::open_immutable_read_only(&fixture.manifest_path)
            .unwrap()
            .load()
            .unwrap();
        let operational =
            operational_document_from_recovery_receipt(&fixture.document, &receipt.body).unwrap();
        let plan = quarantine_plan_from_document(&operational, &manifest).unwrap();
        let reference_members = plan
            .members
            .iter()
            .filter(|member| member.kind == LegacyUploadMigrationQuarantineKind::Reference)
            .collect::<Vec<_>>();
        assert_eq!(reference_members.len(), REFERENCE_COUNT);
        // Leave one reference at its source path, move one to its destination, and
        // leave one normalized at its source while retaining the original at its
        // destination.  These are the three exact partial-recovery forms.
        fs::rename(
            &reference_members[0].source_path,
            &reference_members[0].destination_path,
        )
        .unwrap();
        fs::rename(
            &reference_members[1].source_path,
            &reference_members[1].destination_path,
        )
        .unwrap();
        fs::copy(
            &reference_members[1].destination_path,
            &reference_members[1].source_path,
        )
        .unwrap();
        fs::set_permissions(
            &reference_members[1].source_path,
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        crate::monitor::normalize_private_reference_orientation_temp(
            &reference_members[1].source_path,
            30,
        )
        .unwrap();
        let rotated_output_path = fixture
            .artifact_root
            .join("device-recovery-partial-rotated.json");
        set_device_recovery_signer_hook(signer.clone());
        let rotated_report = generate_legacy_uploaded_heic_device_recovery_with_resolver(
            &LegacyUploadDeviceRecoveryGenerateRequest {
                evidence: fixture.request.clone(),
                expected_signer_designated_requirement_sha256: signer
                    .designated_requirement_sha256
                    .clone(),
                allow_partial_quarantine: true,
                output_path: rotated_output_path.clone(),
            },
            &mut NoCanonicalizationResolver,
        )
        .unwrap();
        assert!(rotated_report.partial_quarantine);
        let recovery = LegacyUploadDeviceRecoveryRequest {
            receipt_path: rotated_output_path,
            expected_receipt_sha256: rotated_report.receipt_sha256,
        };
        set_device_recovery_signer_hook(signer);
        let mut validated = load_validated_legacy_uploaded_heic_evidence_with_device_recovery(
            &fixture.request,
            Some(&recovery),
        )
        .unwrap();
        assert_eq!(validated.quarantine_plan().members.len(), 9);
        assert_eq!(validated.sealed_references.len(), REFERENCE_COUNT - 1);
        let guard = super::super::apply::preflight_quarantine_plan(
            &validated,
            std::slice::from_ref(&fixture.quarantine_root),
            Some(super::super::LegacyUploadMigrationPhase::DeleteConfirmed),
            30,
        )
        .unwrap();
        guard.revalidate().unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "device-recovery-partial-resume",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let mut quarantine = super::super::apply::ProductionLegacyArtifactQuarantineAdapter::new(
            vec![fixture.quarantine_root.clone()],
            30,
        );
        let resumed =
            super::super::apply::ensure_quarantined(&writer, &mut validated, &mut quarantine);
        assert!(
            resumed.is_ok(),
            "partial recovery resume failed: {resumed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn device_recovery_rejects_extra_wrong_and_ambiguous_partial_layouts() {
        for mutation in 0..3 {
            let (fixture, _, _) = rebooted_delete_confirmed_fixture();
            let signer = fixture_recovery_signer();
            let output_path = fixture
                .artifact_root
                .join(format!("device-recovery-invalid-{mutation}.json"));
            set_device_recovery_signer_hook(signer.clone());
            let report = generate_legacy_uploaded_heic_device_recovery_with_resolver(
                &LegacyUploadDeviceRecoveryGenerateRequest {
                    evidence: fixture.request.clone(),
                    expected_signer_designated_requirement_sha256: signer
                        .designated_requirement_sha256
                        .clone(),
                    allow_partial_quarantine: false,
                    output_path: output_path.clone(),
                },
                &mut NoCanonicalizationResolver,
            )
            .unwrap();
            let recovery = LegacyUploadDeviceRecoveryRequest {
                receipt_path: output_path,
                expected_receipt_sha256: report.receipt_sha256,
            };
            let receipt: DeviceRecoveryReceipt =
                serde_json::from_slice(&fs::read(&recovery.receipt_path).unwrap()).unwrap();
            let manifest = AssetStateStore::open_immutable_read_only(&fixture.manifest_path)
                .unwrap()
                .load()
                .unwrap();
            let operational =
                operational_document_from_recovery_receipt(&fixture.document, &receipt.body)
                    .unwrap();
            let plan = quarantine_plan_from_document(&operational, &manifest).unwrap();
            let member = plan
                .members
                .iter()
                .find(|member| member.kind == LegacyUploadMigrationQuarantineKind::Reference)
                .expect("fixture must contain a reference member");
            match mutation {
                0 => fs::write(
                    member.destination_path.parent().unwrap().join("unexpected"),
                    b"unexpected",
                )
                .unwrap(),
                1 => {
                    fs::rename(&member.source_path, &member.destination_path).unwrap();
                    fs::write(&member.destination_path, b"tampered").unwrap();
                }
                2 => {
                    fs::rename(&member.source_path, &member.destination_path).unwrap();
                    fs::copy(&member.destination_path, &member.source_path).unwrap();
                }
                _ => unreachable!(),
            }
            set_device_recovery_signer_hook(signer);
            let rotated_output_path = fixture
                .artifact_root
                .join(format!("device-recovery-invalid-rotated-{mutation}.json"));
            let explicit_error = generate_legacy_uploaded_heic_device_recovery_with_resolver(
                &LegacyUploadDeviceRecoveryGenerateRequest {
                    evidence: fixture.request.clone(),
                    expected_signer_designated_requirement_sha256: fixture_recovery_signer()
                        .designated_requirement_sha256,
                    allow_partial_quarantine: true,
                    output_path: rotated_output_path.clone(),
                },
                &mut NoCanonicalizationResolver,
            )
            .unwrap_err();
            assert_eq!(explicit_error.category(), "recovery_layout");
            assert!(!rotated_output_path.exists());
            set_device_recovery_signer_hook(fixture_recovery_signer());
            let error = load_validated_legacy_uploaded_heic_evidence_with_device_recovery(
                &fixture.request,
                Some(&recovery),
            )
            .err()
            .expect("invalid partial layout must be rejected");
            assert_eq!(error.category(), "recovery_layout");
        }
    }

    #[cfg(unix)]
    #[test]
    fn device_recovery_receipt_generation_remains_strict_about_nonempty_cohorts() {
        let (fixture, _, _) = rebooted_delete_confirmed_fixture();
        let signer = fixture_recovery_signer();
        let destination = fixture
            .quarantine_root
            .join(&fixture.document.cohort_sha256)
            .join("unexpected");
        fs::write(destination, b"unexpected").unwrap();
        set_device_recovery_signer_hook(signer.clone());
        let error = generate_legacy_uploaded_heic_device_recovery_with_resolver(
            &LegacyUploadDeviceRecoveryGenerateRequest {
                evidence: fixture.request,
                expected_signer_designated_requirement_sha256: signer.designated_requirement_sha256,
                allow_partial_quarantine: false,
                output_path: fixture.artifact_root.join("device-recovery-strict.json"),
            },
            &mut NoCanonicalizationResolver,
        )
        .unwrap_err();
        assert_eq!(error.category(), "recovery_root");
    }

    #[test]
    fn device_recovery_removes_only_its_exact_receipt_when_post_write_snapshot_changes() {
        let (fixture, _, _) = rebooted_delete_confirmed_fixture();
        let signer = fixture_recovery_signer();
        let output_path = fixture.artifact_root.join("device-recovery-raced.json");
        let evidence_path = fixture.evidence_path.clone();
        set_device_recovery_signer_hook(signer.clone());
        set_device_recovery_post_output_hook(move || {
            let mut bytes = fs::read(&evidence_path).unwrap();
            bytes.push(b'\n');
            fs::write(&evidence_path, bytes).unwrap();
        });
        let error = generate_legacy_uploaded_heic_device_recovery_with_resolver(
            &LegacyUploadDeviceRecoveryGenerateRequest {
                evidence: fixture.request,
                expected_signer_designated_requirement_sha256: signer.designated_requirement_sha256,
                allow_partial_quarantine: false,
                output_path: output_path.clone(),
            },
            &mut NoCanonicalizationResolver,
        )
        .unwrap_err();
        assert_eq!(error.category(), "evidence_changed");
        assert!(!output_path.exists());
    }

    #[test]
    fn device_recovery_revalidation_survives_exact_quarantine_rename_and_phase_advance() {
        let (fixture, _, _) = rebooted_delete_confirmed_fixture();
        let signer = fixture_recovery_signer();
        let output_path = fixture.artifact_root.join("device-recovery-phase.json");
        set_device_recovery_signer_hook(signer.clone());
        let report = generate_legacy_uploaded_heic_device_recovery_with_resolver(
            &LegacyUploadDeviceRecoveryGenerateRequest {
                evidence: fixture.request.clone(),
                expected_signer_designated_requirement_sha256: signer.designated_requirement_sha256,
                allow_partial_quarantine: false,
                output_path: output_path.clone(),
            },
            &mut NoCanonicalizationResolver,
        )
        .unwrap();
        let recovery = LegacyUploadDeviceRecoveryRequest {
            receipt_path: output_path,
            expected_receipt_sha256: report.receipt_sha256,
        };
        let mut validated = load_validated_legacy_uploaded_heic_evidence_with_device_recovery(
            &fixture.request,
            Some(&recovery),
        )
        .unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "device-recovery-quarantine-phase",
            std::time::Duration::from_secs(30),
        )
        .unwrap();

        struct MovingAdapter;
        impl super::super::apply::LegacyArtifactQuarantineAdapter for MovingAdapter {
            type Error = ();

            fn quarantine_and_normalize(
                &mut self,
                evidence: &ValidatedLegacyUploadEvidence,
                _manifest: &Manifest,
            ) -> Result<super::super::apply::QuarantineBatchReceipt, Self::Error> {
                for member in &evidence.quarantine_plan().members {
                    fs::create_dir_all(member.destination_path.parent().unwrap()).unwrap();
                    fs::rename(&member.source_path, &member.destination_path).unwrap();
                }
                Ok(super::super::apply::QuarantineBatchReceipt {
                    schema_version: 2,
                    cohort_sha256: evidence.audit().cohort_sha256.clone(),
                    canonical_root_identity_sha256: canonical_digest(
                        &evidence.quarantine_plan().roots,
                    )
                    .unwrap(),
                    target_set_sha256: digest("exact-moved-targets"),
                    target_count: 9,
                    normalized_reference_count: 5,
                })
            }
        }

        let outcome =
            super::super::apply::ensure_quarantined(&writer, &mut validated, &mut MovingAdapter)
                .unwrap();
        assert!(outcome.changed);
        assert_eq!(outcome.retired_replacement_delete_calls, 0);
        let authoritative = writer.load().unwrap();
        for asset_id in validated.replacement_asset_ids() {
            let journal = super::super::validate_legacy_upload_migration_record(
                authoritative.get(asset_id).unwrap(),
            )
            .unwrap();
            assert_eq!(
                journal.entries.last().unwrap().phase,
                super::super::LegacyUploadMigrationPhase::Quarantined
            );
        }
    }

    #[test]
    fn device_recovery_rejects_manifest_drift_and_phase_regression() {
        let (fixture, _, _) = rebooted_delete_confirmed_fixture();
        let signer = fixture_recovery_signer();
        let output_path = fixture.artifact_root.join("device-recovery-negative.json");
        set_device_recovery_signer_hook(signer.clone());
        generate_legacy_uploaded_heic_device_recovery_with_resolver(
            &LegacyUploadDeviceRecoveryGenerateRequest {
                evidence: fixture.request.clone(),
                expected_signer_designated_requirement_sha256: signer
                    .designated_requirement_sha256
                    .clone(),
                allow_partial_quarantine: false,
                output_path: output_path.clone(),
            },
            &mut NoCanonicalizationResolver,
        )
        .unwrap();
        let receipt: DeviceRecoveryReceipt =
            serde_json::from_slice(&fs::read(output_path).unwrap()).unwrap();
        let authoritative = AssetStateStore::open_immutable_read_only(&fixture.manifest_path)
            .unwrap()
            .load()
            .unwrap();
        let mut changed = authoritative.clone();
        let mut unrelated = changed.get("asset-02").unwrap().clone();
        unrelated.updated_at = "manifest-drift".to_string();
        changed.upsert_trusted(unrelated);
        assert_eq!(
            validate_device_recovery_continuity(
                &receipt.body,
                &fixture.document,
                &changed,
                &fixture.request.expected_evidence_sha256,
            )
            .unwrap_err()
            .category(),
            "recovery_manifest"
        );

        let unprepared = build_fixture();
        let unprepared_manifest = Manifest::load(&unprepared.manifest_path).unwrap();
        assert_eq!(
            validate_device_recovery_continuity(
                &receipt.body,
                &fixture.document,
                &unprepared_manifest,
                &fixture.request.expected_evidence_sha256,
            )
            .unwrap_err()
            .category(),
            "recovery_phase"
        );
    }

    #[test]
    fn original_destination_canonicalization_is_explicit_and_fully_bound() {
        let fixture = build_fixture();
        let replacement = &fixture.document.retired_replacements[0];
        let manifest = Manifest::load(&fixture.manifest_path).unwrap();
        let original = manifest
            .get(&replacement.asset_id)
            .unwrap()
            .proofs
            .get("original_asset")
            .unwrap();
        let mut missing = original.clone();
        let object = missing.as_object_mut().unwrap();
        object.remove("database_scope");
        object.remove("zone_name");
        let historical: OriginalAssetProof = serde_json::from_value(missing.clone()).unwrap();
        assert_eq!(historical.database_scope, CloudKitDatabaseScope::Private);
        assert_eq!(historical.zone_name, "PrimarySync");
        assert_eq!(historical.owner_record_name, None);

        let mut canonical = missing.clone();
        let object = canonical.as_object_mut().unwrap();
        object.insert(
            "database_scope".to_string(),
            serde_json::to_value(replacement.destination.database_scope).unwrap(),
        );
        object.insert(
            "zone_name".to_string(),
            Value::String(replacement.destination.zone_name.clone()),
        );
        let mut evidence = replacement.clone();
        evidence.original_asset_identity_sha256 = digest_value(&missing).unwrap();
        let entry = OriginalDestinationCanonicalization {
            asset_id: evidence.asset_id.clone(),
            original_asset_identity_sha256: evidence.original_asset_identity_sha256.clone(),
            destination_sha256: evidence.destination_sha256.clone(),
            canonical_original_asset_sha256: digest_value(&canonical).unwrap(),
            delete_confirmed_entry_sha256: digest("delete-confirmed-entry"),
            remote_state: evidence.original_remote_state,
            lookup_mode: CloudKitActiveAssetLookupMode::FullFields,
        };
        let parsed = original_asset_proof_for_validation(
            &evidence,
            &missing,
            Some(std::slice::from_ref(&entry)),
            "test",
        )
        .unwrap();
        assert_eq!(
            parsed.database_scope,
            replacement.destination.database_scope
        );
        assert_eq!(parsed.zone_name, replacement.destination.zone_name);
        assert_eq!(
            original_asset_proof_for_validation(&evidence, &missing, None, "test")
                .unwrap_err()
                .category(),
            "original_canonicalization"
        );
        let mut changed = entry;
        changed.destination_sha256 = digest("other-destination");
        assert_eq!(
            original_asset_proof_for_validation(&evidence, &missing, Some(&[changed]), "test")
                .unwrap_err()
                .category(),
            "original_canonicalization"
        );
        missing.as_object_mut().unwrap().insert(
            "zone_name".to_string(),
            Value::String("PrimarySync".to_string()),
        );
        assert_eq!(
            original_asset_proof_destination_fields(&missing)
                .unwrap_err()
                .category(),
            "proof_lineage"
        );
    }

    #[test]
    fn exact_evidence_audit_succeeds_without_writing_state_or_evidence() {
        let fixture = build_fixture();
        let checkpoint_before = fs::read(&fixture.manifest_path).unwrap();
        let evidence_before = fs::read(&fixture.evidence_path).unwrap();
        let state_before = AssetStateStore::open_immutable_read_only(&fixture.manifest_path)
            .unwrap()
            .load()
            .unwrap();

        let audit = audit_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        assert_eq!(audit.asset_count, 10);
        assert_eq!(audit.retired_replacement_count, 2);
        assert_eq!(audit.reference_count, 5);
        assert_eq!(
            audit.evidence_sha256,
            fixture.request.expected_evidence_sha256
        );
        assert_eq!(audit.cohort_sha256, fixture.request.expected_cohort_sha256);
        let report = serde_json::to_string(&audit).unwrap();
        for sentinel in ["asset-00", "/raw/", "uploaded-", "original-"] {
            assert!(!report.contains(sentinel));
        }
        assert_eq!(fs::read(&fixture.manifest_path).unwrap(), checkpoint_before);
        assert_eq!(fs::read(&fixture.evidence_path).unwrap(), evidence_before);
        assert_eq!(
            AssetStateStore::open_immutable_read_only(&fixture.manifest_path)
                .unwrap()
                .load()
                .unwrap(),
            state_before
        );
    }

    #[test]
    fn sealed_evidence_rejects_state_or_lookup_mode_relabeling() {
        for mutate in [
            |document: &mut EvidenceDocument| {
                document.retired_replacements[0].initial_remote_state =
                    CloudKitUploadedHeicInitialState::ActiveUnmarked;
            },
            |document: &mut EvidenceDocument| {
                document.retired_replacements[0].initial_state_lookup_mode =
                    CloudKitUploadedHeicInitialStateLookupMode::FilteredMarker;
            },
        ] {
            let fixture = build_fixture();
            let mut relabeled = fixture.document.clone();
            mutate(&mut relabeled);
            fs::write(
                &fixture.evidence_path,
                serde_json::to_vec_pretty(&relabeled).unwrap(),
            )
            .unwrap();

            assert_eq!(
                audit_legacy_uploaded_heic_evidence(&fixture.request)
                    .unwrap_err()
                    .category(),
                "evidence_digest"
            );
        }
    }

    #[test]
    fn initial_retired_replacement_rejects_preexisting_delete_proof() {
        let fixture = build_fixture();
        let state = AssetStateStore::open_immutable_read_only(&fixture.manifest_path)
            .unwrap()
            .load()
            .unwrap();
        let replacement = &fixture.document.retired_replacements[0];
        let mut record = state.get(&replacement.asset_id).unwrap().clone();
        record.proofs.insert(
            "uploaded_heic_delete".to_string(),
            json!({"preexisting": true}),
        );
        let digest = legacy_upload_migration_record_digest(&record).unwrap();
        let asset_id = record.asset_id.clone();
        let digests = BTreeMap::from([(asset_id.as_str(), digest.as_str())]);
        let mut manifest = Manifest::new();
        manifest.upsert_trusted(record);

        assert_eq!(
            validate_retired_replacement(replacement, &manifest, &digests, None)
                .unwrap_err()
                .category(),
            "proof_conflict"
        );
    }

    #[test]
    fn validated_apply_bundle_keeps_and_revalidates_the_original_evidence_descriptor() {
        let fixture = build_fixture();
        let mut validated = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        assert_eq!(validated.audit().retired_replacement_count, 2);
        assert_eq!(validated.replacement_asset_ids().len(), 2);

        fs::set_permissions(&fixture.evidence_path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(
            validated.revalidate_held_evidence().unwrap_err().category(),
            "evidence_changed"
        );
    }

    #[test]
    fn validated_evidence_resumes_against_the_exact_prepared_registry_cohort() {
        let fixture = build_fixture();
        let validated = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-evidence-prepared-resume",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let current = writer.load_or_import().unwrap();
        let ids = validated.replacement_asset_ids();
        let expected = [
            current.get(ids[0]).unwrap().clone(),
            current.get(ids[1]).unwrap().clone(),
        ];
        let updated = [
            super::super::prepare_legacy_upload_migration_record(
                &expected[0],
                validated.preparation_authority(),
            )
            .unwrap(),
            super::super::prepare_legacy_upload_migration_record(
                &expected[1],
                validated.preparation_authority(),
            )
            .unwrap(),
        ];
        super::super::persist_two_legacy_upload_migration_preparations_exact_cas(
            &writer,
            validated.preparation_authority(),
            [
                super::super::LegacyUploadMigrationCasUpdate {
                    expected: &expected[0],
                    updated: &updated[0],
                },
                super::super::LegacyUploadMigrationCasUpdate {
                    expected: &expected[1],
                    updated: &updated[1],
                },
            ],
        )
        .unwrap();
        writer.export_json().unwrap();
        writer.release_writer_lease().unwrap();

        let mut resumed = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let authoritative = AssetStateStore::open_immutable_read_only(&fixture.manifest_path)
            .unwrap()
            .load()
            .unwrap();
        resumed
            .revalidate_authoritative_manifest(&authoritative)
            .unwrap();
        resumed.revalidate_held_evidence().unwrap();
        assert_eq!(resumed.replacement_asset_ids(), ids);
    }

    #[test]
    fn apply_preparation_commits_exact_pair_and_recovers_checkpoint_idempotently() {
        let fixture = build_fixture();
        let mut validated = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-apply-prepared",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let first = super::super::apply::ensure_prepared(&writer, &mut validated).unwrap();
        assert!(first.changed);
        assert!(first.checkpoint_exported);
        let second = super::super::apply::ensure_prepared(&writer, &mut validated).unwrap();
        assert!(!second.changed);
        assert!(!second.checkpoint_exported);

        let durable = writer.load().unwrap();
        for asset_id in validated.replacement_asset_ids() {
            let journal = super::super::validate_legacy_upload_migration_record(
                durable.get(asset_id).unwrap(),
            )
            .unwrap();
            assert_eq!(
                journal.entries.last().unwrap().phase,
                super::super::LegacyUploadMigrationPhase::Prepared
            );
        }
        assert_eq!(Manifest::load(&fixture.manifest_path).unwrap(), durable);
    }

    #[test]
    fn quarantine_guard_failure_after_remote_reads_prevents_every_delete() {
        #[derive(Default)]
        struct Adapter {
            deletes: u64,
        }
        impl super::super::apply::RetiredReplacementDeleteAdapter for Adapter {
            type Error = ();

            fn lookup(
                &mut self,
                _replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitDeleteStateLookupResult, ()> {
                unreachable!()
            }

            fn resolve(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitUploadedHeicAsset, ()> {
                Ok(crate::upload::CloudKitUploadedHeicAsset {
                    record_name: replacement.uploaded_asset_id.clone(),
                    record_change_tag: replacement.old_record_change_tag.clone(),
                    master_record_name: replacement.uploaded_master_id.clone(),
                    owner_record_name_sha256: replacement.owner_record_name_sha256.clone(),
                    initial_remote_state: CloudKitUploadedHeicInitialState::Active,
                    initial_state_lookup_mode: replacement.initial_state_lookup_mode,
                    matched_heic_sha256: replacement.uploaded_heic_sha256.clone(),
                    size_bytes: replacement.uploaded_heic_size_bytes,
                })
            }

            fn delete(
                &mut self,
                _replacement: &EvidenceRetiredReplacement,
                _resolved: &crate::upload::CloudKitUploadedHeicAsset,
            ) -> Result<crate::upload::CloudKitDeleteOutcome, ()> {
                self.deletes += 1;
                unreachable!("failed local guard must run before the first delete")
            }

            fn validate_original_active(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<CloudKitActiveAssetValidation, ()> {
                Ok(original_validation_for(replacement))
            }
        }

        let fixture = build_fixture();
        let mut evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-local-guard-before-delete",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        super::super::apply::ensure_prepared(&writer, &mut evidence).unwrap();
        let mut adapter = Adapter::default();
        let error = super::super::apply::ensure_delete_confirmed_with_pre_delete(
            &writer,
            &mut evidence,
            &mut adapter,
            &mut || Err(super::super::apply::LegacyUploadMigrationApplyError::Quarantine),
        )
        .unwrap_err();
        assert_eq!(
            error,
            super::super::apply::LegacyUploadMigrationApplyError::Quarantine
        );
        assert_eq!(adapter.deletes, 0);
    }

    #[test]
    fn delete_ambiguity_reconciles_once_and_never_resends_a_confirmed_replacement() {
        #[derive(Default)]
        struct FakeDeleteAdapter {
            lookups: Vec<String>,
            resolves: Vec<String>,
            deletes: Vec<String>,
            mismatch_owner: bool,
        }

        impl super::super::apply::RetiredReplacementDeleteAdapter for FakeDeleteAdapter {
            type Error = ();

            fn lookup(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitDeleteStateLookupResult, ()> {
                self.lookups.push(replacement.asset_id.clone());
                Ok(crate::upload::CloudKitDeleteStateLookupResult {
                    confirmed_deleted: vec![crate::upload::CloudKitDeleteOutcome {
                        record_name: replacement.uploaded_asset_id.clone(),
                        record_change_tag: "confirmed-delete-tag".to_string(),
                    }],
                    unconfirmed: vec![],
                })
            }

            fn resolve(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitUploadedHeicAsset, ()> {
                self.resolves.push(replacement.asset_id.clone());
                Ok(crate::upload::CloudKitUploadedHeicAsset {
                    record_name: replacement.uploaded_asset_id.clone(),
                    record_change_tag: if replacement.asset_id == "asset-01" {
                        "confirmed-delete-tag".to_string()
                    } else {
                        replacement.old_record_change_tag.clone()
                    },
                    master_record_name: replacement.uploaded_master_id.clone(),
                    owner_record_name_sha256: if self.mismatch_owner {
                        digest("changed-owner")
                    } else {
                        replacement.owner_record_name_sha256.clone()
                    },
                    initial_remote_state: if replacement.asset_id == "asset-01" {
                        CloudKitUploadedHeicInitialState::AlreadyDeleted
                    } else {
                        replacement.initial_remote_state
                    },
                    initial_state_lookup_mode: replacement.initial_state_lookup_mode,
                    matched_heic_sha256: replacement.uploaded_heic_sha256.clone(),
                    size_bytes: replacement.uploaded_heic_size_bytes,
                })
            }

            fn delete(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
                _resolved: &crate::upload::CloudKitUploadedHeicAsset,
            ) -> Result<crate::upload::CloudKitDeleteOutcome, ()> {
                self.deletes.push(replacement.asset_id.clone());
                Err(())
            }

            fn validate_original_active(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<CloudKitActiveAssetValidation, ()> {
                Ok(original_validation_for(replacement))
            }
        }

        let fixture = build_fixture();
        let validated = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let mut adapter = FakeDeleteAdapter::default();
        let confirmed =
            super::super::apply::confirm_retired_replacement_deletes(&validated, &mut adapter)
                .unwrap();
        assert_eq!(confirmed.len(), 2);
        assert_eq!(adapter.resolves, vec!["asset-00", "asset-01"]);
        assert_eq!(adapter.deletes, vec!["asset-00"]);
        assert_eq!(adapter.lookups, vec!["asset-00"]);

        let mut changed_owner = FakeDeleteAdapter {
            mismatch_owner: true,
            ..FakeDeleteAdapter::default()
        };
        assert!(
            super::super::apply::confirm_retired_replacement_deletes(
                &validated,
                &mut changed_owner
            )
            .is_err()
        );
        assert_eq!(changed_owner.resolves, vec!["asset-00"]);
        assert!(changed_owner.deletes.is_empty());
    }

    #[test]
    fn already_deleted_initial_pair_revalidates_and_issues_zero_delete_calls() {
        #[derive(Default)]
        struct AlreadyDeletedAdapter {
            resolves: Vec<String>,
            original_checks: Vec<String>,
            delete_calls: usize,
            mismatch_tag: bool,
            mismatch_owner: bool,
            mismatch_resource: bool,
            resurrected: bool,
            fail_original: bool,
            mismatch_original_state: bool,
        }

        impl super::super::apply::RetiredReplacementDeleteAdapter for AlreadyDeletedAdapter {
            type Error = ();

            fn lookup(
                &mut self,
                _replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitDeleteStateLookupResult, ()> {
                panic!("an initially tombstoned replacement must use exact recovery inspection")
            }

            fn resolve(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitUploadedHeicAsset, ()> {
                self.resolves.push(replacement.asset_id.clone());
                Ok(crate::upload::CloudKitUploadedHeicAsset {
                    record_name: replacement.uploaded_asset_id.clone(),
                    record_change_tag: if self.mismatch_tag {
                        "changed-tombstone-tag".to_string()
                    } else {
                        replacement.old_record_change_tag.clone()
                    },
                    master_record_name: replacement.uploaded_master_id.clone(),
                    owner_record_name_sha256: if self.mismatch_owner {
                        digest("changed-owner")
                    } else {
                        replacement.owner_record_name_sha256.clone()
                    },
                    initial_remote_state: if self.resurrected {
                        CloudKitUploadedHeicInitialState::Active
                    } else {
                        CloudKitUploadedHeicInitialState::AlreadyDeleted
                    },
                    initial_state_lookup_mode: replacement.initial_state_lookup_mode,
                    matched_heic_sha256: if self.mismatch_resource {
                        digest("changed-resource")
                    } else {
                        replacement.uploaded_heic_sha256.clone()
                    },
                    size_bytes: replacement.uploaded_heic_size_bytes,
                })
            }

            fn delete(
                &mut self,
                _replacement: &EvidenceRetiredReplacement,
                _resolved: &crate::upload::CloudKitUploadedHeicAsset,
            ) -> Result<crate::upload::CloudKitDeleteOutcome, ()> {
                self.delete_calls += 1;
                panic!("already-deleted recovery must never issue a delete")
            }

            fn validate_original_active(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<CloudKitActiveAssetValidation, ()> {
                self.original_checks.push(replacement.asset_id.clone());
                if self.fail_original {
                    Err(())
                } else {
                    let mut validation = original_validation_for(replacement);
                    if self.mismatch_original_state {
                        validation.remote_state = match validation.remote_state {
                            CloudKitActiveAssetRemoteState::Active => {
                                CloudKitActiveAssetRemoteState::ActiveUnmarked
                            }
                            CloudKitActiveAssetRemoteState::ActiveUnmarked => {
                                CloudKitActiveAssetRemoteState::Active
                            }
                        };
                    }
                    Ok(validation)
                }
            }
        }

        let mut fixture = build_fixture();
        for replacement in &mut fixture.document.retired_replacements {
            replacement.initial_remote_state = CloudKitUploadedHeicInitialState::AlreadyDeleted;
        }
        write_document(&mut fixture);
        let validated = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let mut adapter = AlreadyDeletedAdapter::default();
        let confirmed =
            super::super::apply::confirm_retired_replacement_deletes(&validated, &mut adapter)
                .unwrap();

        assert_eq!(confirmed.len(), 2);
        assert_eq!(adapter.resolves, vec!["asset-00", "asset-01"]);
        assert_eq!(adapter.original_checks, vec!["asset-00", "asset-01"]);
        assert_eq!(adapter.delete_calls, 0);

        for mut changed in [
            AlreadyDeletedAdapter {
                mismatch_tag: true,
                ..AlreadyDeletedAdapter::default()
            },
            AlreadyDeletedAdapter {
                mismatch_owner: true,
                ..AlreadyDeletedAdapter::default()
            },
            AlreadyDeletedAdapter {
                mismatch_resource: true,
                ..AlreadyDeletedAdapter::default()
            },
            AlreadyDeletedAdapter {
                resurrected: true,
                ..AlreadyDeletedAdapter::default()
            },
            AlreadyDeletedAdapter {
                fail_original: true,
                ..AlreadyDeletedAdapter::default()
            },
            AlreadyDeletedAdapter {
                mismatch_original_state: true,
                ..AlreadyDeletedAdapter::default()
            },
        ] {
            assert!(
                super::super::apply::confirm_retired_replacement_deletes(&validated, &mut changed)
                    .is_err()
            );
            assert_eq!(changed.delete_calls, 0);
        }
    }

    #[test]
    fn mixed_active_unmarked_and_already_deleted_pair_reverifies_and_writes_once() {
        #[derive(Default)]
        struct MixedAdapter {
            resolves: Vec<String>,
            deletes: Vec<String>,
            original_checks: Vec<String>,
            drift_unmarked_to_explicit: bool,
            recover_confirmed_unmarked_delete: bool,
        }

        impl super::super::apply::RetiredReplacementDeleteAdapter for MixedAdapter {
            type Error = ();

            fn lookup(
                &mut self,
                _replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitDeleteStateLookupResult, ()> {
                panic!("the exact active-unmarked path must reverify with a full-fields lookup")
            }

            fn resolve(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitUploadedHeicAsset, ()> {
                self.resolves.push(replacement.asset_id.clone());
                let state = if self.recover_confirmed_unmarked_delete
                    && replacement.initial_remote_state
                        == CloudKitUploadedHeicInitialState::ActiveUnmarked
                {
                    CloudKitUploadedHeicInitialState::AlreadyDeleted
                } else if self.drift_unmarked_to_explicit
                    && replacement.initial_remote_state
                        == CloudKitUploadedHeicInitialState::ActiveUnmarked
                {
                    CloudKitUploadedHeicInitialState::Active
                } else {
                    replacement.initial_remote_state
                };
                Ok(crate::upload::CloudKitUploadedHeicAsset {
                    record_name: replacement.uploaded_asset_id.clone(),
                    record_change_tag: if self.recover_confirmed_unmarked_delete
                        && replacement.initial_remote_state
                            == CloudKitUploadedHeicInitialState::ActiveUnmarked
                    {
                        format!("recovered-delete-{}", replacement.asset_id)
                    } else {
                        replacement.old_record_change_tag.clone()
                    },
                    master_record_name: replacement.uploaded_master_id.clone(),
                    owner_record_name_sha256: replacement.owner_record_name_sha256.clone(),
                    initial_remote_state: state,
                    initial_state_lookup_mode: replacement.initial_state_lookup_mode,
                    matched_heic_sha256: replacement.uploaded_heic_sha256.clone(),
                    size_bytes: replacement.uploaded_heic_size_bytes,
                })
            }

            fn delete(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
                _resolved: &crate::upload::CloudKitUploadedHeicAsset,
            ) -> Result<crate::upload::CloudKitDeleteOutcome, ()> {
                self.deletes.push(replacement.asset_id.clone());
                Ok(crate::upload::CloudKitDeleteOutcome {
                    record_name: replacement.uploaded_asset_id.clone(),
                    record_change_tag: format!("deleted-{}", replacement.asset_id),
                })
            }

            fn validate_original_active(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<CloudKitActiveAssetValidation, ()> {
                self.original_checks.push(replacement.asset_id.clone());
                Ok(original_validation_for(replacement))
            }
        }

        let mut fixture = build_fixture();
        fixture.document.retired_replacements[0].initial_remote_state =
            CloudKitUploadedHeicInitialState::ActiveUnmarked;
        fixture.document.retired_replacements[1].initial_remote_state =
            CloudKitUploadedHeicInitialState::AlreadyDeleted;
        write_document(&mut fixture);
        let validated = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let mut adapter = MixedAdapter::default();
        let confirmed =
            super::super::apply::confirm_retired_replacement_deletes(&validated, &mut adapter)
                .unwrap();

        assert_eq!(confirmed.len(), 2);
        assert_eq!(adapter.resolves, vec!["asset-00", "asset-01"]);
        assert_eq!(adapter.deletes, vec!["asset-00"]);
        assert_eq!(adapter.original_checks, vec!["asset-00", "asset-01"]);

        let mut drifted = MixedAdapter {
            drift_unmarked_to_explicit: true,
            ..MixedAdapter::default()
        };
        assert!(
            super::super::apply::confirm_retired_replacement_deletes(&validated, &mut drifted)
                .is_err()
        );
        assert!(drifted.deletes.is_empty());

        let mut recovered = MixedAdapter {
            recover_confirmed_unmarked_delete: true,
            ..MixedAdapter::default()
        };
        let replayed =
            super::super::apply::confirm_retired_replacement_deletes(&validated, &mut recovered)
                .expect("a full-fields tombstone with a new CAS tag must recover without resend");
        assert_eq!(replayed.len(), 2);
        assert!(recovered.deletes.is_empty());
        assert_eq!(recovered.resolves, vec!["asset-00", "asset-01"]);
        assert_eq!(recovered.original_checks, vec!["asset-00", "asset-01"]);
    }

    #[test]
    fn pair_remote_preflight_completes_before_any_delete_and_failure_writes_nothing() {
        #[derive(Default)]
        struct OrderedAdapter {
            events: Vec<String>,
            delete_calls: usize,
            fail_original_asset: Option<String>,
            mismatch_resource_asset: Option<String>,
        }

        impl super::super::apply::RetiredReplacementDeleteAdapter for OrderedAdapter {
            type Error = ();

            fn lookup(
                &mut self,
                _replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitDeleteStateLookupResult, ()> {
                panic!("a successful CAS must not use ambiguity reconciliation")
            }

            fn resolve(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitUploadedHeicAsset, ()> {
                self.events
                    .push(format!("resolve:{}", replacement.asset_id));
                Ok(crate::upload::CloudKitUploadedHeicAsset {
                    record_name: replacement.uploaded_asset_id.clone(),
                    record_change_tag: replacement.old_record_change_tag.clone(),
                    master_record_name: replacement.uploaded_master_id.clone(),
                    owner_record_name_sha256: replacement.owner_record_name_sha256.clone(),
                    initial_remote_state: replacement.initial_remote_state,
                    initial_state_lookup_mode: replacement.initial_state_lookup_mode,
                    matched_heic_sha256: if self.mismatch_resource_asset.as_deref()
                        == Some(replacement.asset_id.as_str())
                    {
                        digest("wrong-remote-resource")
                    } else {
                        replacement.uploaded_heic_sha256.clone()
                    },
                    size_bytes: replacement.uploaded_heic_size_bytes,
                })
            }

            fn delete(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
                _resolved: &crate::upload::CloudKitUploadedHeicAsset,
            ) -> Result<crate::upload::CloudKitDeleteOutcome, ()> {
                self.events.push(format!("delete:{}", replacement.asset_id));
                self.delete_calls += 1;
                Ok(crate::upload::CloudKitDeleteOutcome {
                    record_name: replacement.uploaded_asset_id.clone(),
                    record_change_tag: format!("deleted-{}", replacement.asset_id),
                })
            }

            fn validate_original_active(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<CloudKitActiveAssetValidation, ()> {
                self.events
                    .push(format!("original:{}", replacement.asset_id));
                if self.fail_original_asset.as_deref() == Some(replacement.asset_id.as_str()) {
                    Err(())
                } else {
                    Ok(original_validation_for(replacement))
                }
            }
        }

        let mut fixture = build_fixture();
        fixture.document.retired_replacements[0].initial_remote_state =
            CloudKitUploadedHeicInitialState::ActiveUnmarked;
        fixture.document.retired_replacements[1].initial_remote_state =
            CloudKitUploadedHeicInitialState::AlreadyDeleted;
        write_document(&mut fixture);
        let validated = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();

        let mut successful = OrderedAdapter::default();
        super::super::apply::confirm_retired_replacement_deletes(&validated, &mut successful)
            .unwrap();
        assert_eq!(
            successful.events,
            [
                "resolve:asset-00",
                "original:asset-00",
                "resolve:asset-01",
                "original:asset-01",
                "delete:asset-00",
            ]
        );
        assert_eq!(successful.delete_calls, 1);

        let mut failed = OrderedAdapter {
            fail_original_asset: Some("asset-01".to_string()),
            ..OrderedAdapter::default()
        };
        assert!(
            super::super::apply::confirm_retired_replacement_deletes(&validated, &mut failed)
                .is_err()
        );
        assert_eq!(
            failed.events,
            [
                "resolve:asset-00",
                "original:asset-00",
                "resolve:asset-01",
                "original:asset-01",
            ]
        );
        assert_eq!(failed.delete_calls, 0);

        let mut mismatched = OrderedAdapter {
            mismatch_resource_asset: Some("asset-01".to_string()),
            ..OrderedAdapter::default()
        };
        assert!(
            super::super::apply::confirm_retired_replacement_deletes(&validated, &mut mismatched)
                .is_err()
        );
        assert_eq!(
            mismatched.events,
            ["resolve:asset-00", "original:asset-00", "resolve:asset-01",]
        );
        assert_eq!(mismatched.delete_calls, 0);
    }

    #[test]
    fn ambiguous_delete_never_mutates_a_later_member_and_replay_recovers() {
        #[derive(Default)]
        struct AmbiguityAdapter {
            recovered_first: bool,
            deletes: Vec<String>,
            lookups: Vec<String>,
        }

        impl super::super::apply::RetiredReplacementDeleteAdapter for AmbiguityAdapter {
            type Error = ();

            fn lookup(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitDeleteStateLookupResult, ()> {
                self.lookups.push(replacement.asset_id.clone());
                Ok(crate::upload::CloudKitDeleteStateLookupResult {
                    confirmed_deleted: vec![crate::upload::CloudKitDeleteOutcome {
                        record_name: replacement.uploaded_asset_id.clone(),
                        record_change_tag: format!("confirmed-{}", replacement.asset_id),
                    }],
                    unconfirmed: vec![],
                })
            }

            fn resolve(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitUploadedHeicAsset, ()> {
                if self.recovered_first && replacement.asset_id == "asset-00" {
                    Ok(recovered_deleted_asset(replacement))
                } else {
                    Ok(crate::upload::CloudKitUploadedHeicAsset {
                        record_name: replacement.uploaded_asset_id.clone(),
                        record_change_tag: replacement.old_record_change_tag.clone(),
                        master_record_name: replacement.uploaded_master_id.clone(),
                        owner_record_name_sha256: replacement.owner_record_name_sha256.clone(),
                        initial_remote_state: replacement.initial_remote_state,
                        initial_state_lookup_mode: replacement.initial_state_lookup_mode,
                        matched_heic_sha256: replacement.uploaded_heic_sha256.clone(),
                        size_bytes: replacement.uploaded_heic_size_bytes,
                    })
                }
            }

            fn delete(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
                _resolved: &crate::upload::CloudKitUploadedHeicAsset,
            ) -> Result<crate::upload::CloudKitDeleteOutcome, ()> {
                self.deletes.push(replacement.asset_id.clone());
                if replacement.asset_id == "asset-00" {
                    Err(())
                } else {
                    Ok(crate::upload::CloudKitDeleteOutcome {
                        record_name: replacement.uploaded_asset_id.clone(),
                        record_change_tag: format!("deleted-{}", replacement.asset_id),
                    })
                }
            }

            fn validate_original_active(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<CloudKitActiveAssetValidation, ()> {
                Ok(original_validation_for(replacement))
            }
        }

        let fixture = build_fixture();
        let validated = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let mut ambiguous = AmbiguityAdapter::default();
        assert!(
            super::super::apply::confirm_retired_replacement_deletes(&validated, &mut ambiguous)
                .is_err()
        );
        assert_eq!(ambiguous.deletes, ["asset-00"]);
        assert_eq!(ambiguous.lookups, ["asset-00"]);

        let mut replay = AmbiguityAdapter {
            recovered_first: true,
            ..AmbiguityAdapter::default()
        };
        super::super::apply::confirm_retired_replacement_deletes(&validated, &mut replay).unwrap();
        assert_eq!(replay.deletes, ["asset-01"]);
        assert!(replay.lookups.is_empty());
    }

    #[test]
    fn already_deleted_prepared_transition_checkpoints_and_replays_without_remote_calls() {
        #[derive(Default)]
        struct TombstoneAdapter {
            resolves: usize,
            original_checks: usize,
        }

        impl super::super::apply::RetiredReplacementDeleteAdapter for TombstoneAdapter {
            type Error = ();

            fn lookup(
                &mut self,
                _replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitDeleteStateLookupResult, ()> {
                panic!("already-deleted transition must not use delete-state lookup")
            }

            fn resolve(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitUploadedHeicAsset, ()> {
                self.resolves += 1;
                Ok(crate::upload::CloudKitUploadedHeicAsset {
                    record_name: replacement.uploaded_asset_id.clone(),
                    record_change_tag: replacement.old_record_change_tag.clone(),
                    master_record_name: replacement.uploaded_master_id.clone(),
                    owner_record_name_sha256: replacement.owner_record_name_sha256.clone(),
                    initial_remote_state: CloudKitUploadedHeicInitialState::AlreadyDeleted,
                    initial_state_lookup_mode: replacement.initial_state_lookup_mode,
                    matched_heic_sha256: replacement.uploaded_heic_sha256.clone(),
                    size_bytes: replacement.uploaded_heic_size_bytes,
                })
            }

            fn delete(
                &mut self,
                _replacement: &EvidenceRetiredReplacement,
                _resolved: &crate::upload::CloudKitUploadedHeicAsset,
            ) -> Result<crate::upload::CloudKitDeleteOutcome, ()> {
                panic!("already-deleted transition must issue zero delete calls")
            }

            fn validate_original_active(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<CloudKitActiveAssetValidation, ()> {
                self.original_checks += 1;
                Ok(original_validation_for(replacement))
            }
        }

        let mut fixture = build_fixture();
        for replacement in &mut fixture.document.retired_replacements {
            replacement.initial_remote_state = CloudKitUploadedHeicInitialState::AlreadyDeleted;
        }
        write_document(&mut fixture);
        let mut validated = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "already-deleted-checkpoint-replay",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        super::super::apply::ensure_prepared(&writer, &mut validated).unwrap();
        let mut adapter = TombstoneAdapter::default();
        let first =
            super::super::apply::ensure_delete_confirmed(&writer, &mut validated, &mut adapter)
                .unwrap();
        assert!(first.changed);
        assert!(first.checkpoint_exported);
        assert_eq!(first.retired_replacement_delete_calls, 0);
        assert_eq!(adapter.resolves, 2);
        assert_eq!(adapter.original_checks, 2);
        let checkpoint_after_first = fs::read(&fixture.manifest_path).unwrap();

        for replacement in validated.retired_replacements() {
            let receipt = super::super::apply::delete_confirmed_receipt(
                replacement,
                &crate::upload::CloudKitDeleteOutcome {
                    record_name: replacement.uploaded_asset_id.clone(),
                    record_change_tag: replacement.old_record_change_tag.clone(),
                },
            )
            .unwrap();
            assert_eq!(
                receipt.initial_remote_state,
                CloudKitUploadedHeicInitialState::AlreadyDeleted
            );
            let record = writer
                .load()
                .unwrap()
                .get(&replacement.asset_id)
                .unwrap()
                .clone();
            let journal = super::super::validate_legacy_upload_migration_record(&record).unwrap();
            assert_eq!(
                journal.entries.last().unwrap().phase,
                super::super::LegacyUploadMigrationPhase::DeleteConfirmed
            );
        }

        let second =
            super::super::apply::ensure_delete_confirmed(&writer, &mut validated, &mut adapter)
                .unwrap();
        assert!(!second.changed);
        assert!(!second.checkpoint_exported);
        assert_eq!(second.retired_replacement_delete_calls, 0);
        assert_eq!(adapter.resolves, 2);
        assert_eq!(adapter.original_checks, 2);
        assert_eq!(
            fs::read(&fixture.manifest_path).unwrap(),
            checkpoint_after_first
        );
    }

    #[test]
    fn completed_report_distinguishes_prior_tombstones_from_migration_deletes() {
        let already_deleted = super::super::apply::completed_apply_report(
            3,
            1,
            true,
            [CloudKitUploadedHeicInitialState::AlreadyDeleted; 2],
            0,
        );
        assert_eq!(already_deleted.retired_replacement_delete_calls, 0);
        assert_eq!(already_deleted.retired_replacements_already_deleted, 2);
        assert_eq!(already_deleted.retired_replacements_deleted_by_migration, 0);

        let active = super::super::apply::completed_apply_report(
            3,
            1,
            true,
            [CloudKitUploadedHeicInitialState::Active; 2],
            2,
        );
        assert_eq!(active.retired_replacement_delete_calls, 2);
        assert_eq!(active.retired_replacements_already_deleted, 0);
        assert_eq!(active.retired_replacements_deleted_by_migration, 2);

        let mixed = super::super::apply::completed_apply_report(
            3,
            1,
            true,
            [
                CloudKitUploadedHeicInitialState::ActiveUnmarked,
                CloudKitUploadedHeicInitialState::AlreadyDeleted,
            ],
            1,
        );
        assert_eq!(mixed.retired_replacement_delete_calls, 1);
        assert_eq!(mixed.retired_replacements_already_deleted, 1);
        assert_eq!(mixed.retired_replacements_deleted_by_migration, 1);
    }

    #[cfg(unix)]
    #[test]
    fn device_recovery_revalidates_reset_after_lineage_removal_and_rejects_cohort_tampering() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (fixture, _, current_device) = rebooted_delete_confirmed_fixture();
        let signer = fixture_recovery_signer();
        let receipt_path = fixture.artifact_root.join("device-recovery-reset.json");
        set_device_recovery_signer_hook(signer.clone());
        let report = generate_legacy_uploaded_heic_device_recovery_with_resolver(
            &LegacyUploadDeviceRecoveryGenerateRequest {
                evidence: fixture.request.clone(),
                expected_signer_designated_requirement_sha256: signer
                    .designated_requirement_sha256
                    .clone(),
                allow_partial_quarantine: false,
                output_path: receipt_path.clone(),
            },
            &mut NoCanonicalizationResolver,
        )
        .unwrap();
        let recovery = LegacyUploadDeviceRecoveryRequest {
            receipt_path,
            expected_receipt_sha256: report.receipt_sha256,
        };
        set_device_recovery_signer_hook(signer.clone());
        let mut validated = load_validated_legacy_uploaded_heic_evidence_with_device_recovery(
            &fixture.request,
            Some(&recovery),
        )
        .unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-device-recovery-reset",
            std::time::Duration::from_secs(30),
        )
        .unwrap();

        struct MovingAdapter;
        impl super::super::apply::LegacyArtifactQuarantineAdapter for MovingAdapter {
            type Error = ();

            fn quarantine_and_normalize(
                &mut self,
                evidence: &ValidatedLegacyUploadEvidence,
                _manifest: &Manifest,
            ) -> Result<super::super::apply::QuarantineBatchReceipt, Self::Error> {
                for member in &evidence.quarantine_plan().members {
                    fs::create_dir_all(member.destination_path.parent().unwrap()).unwrap();
                    fs::set_permissions(
                        member.destination_path.parent().unwrap(),
                        fs::Permissions::from_mode(0o700),
                    )
                    .unwrap();
                    fs::rename(&member.source_path, &member.destination_path).unwrap();
                }
                Ok(super::super::apply::QuarantineBatchReceipt {
                    schema_version: 2,
                    cohort_sha256: evidence.audit().cohort_sha256.clone(),
                    canonical_root_identity_sha256: canonical_digest(
                        &evidence.quarantine_plan().roots,
                    )
                    .unwrap(),
                    target_set_sha256: digest("reset-recovery-targets"),
                    target_count: 9,
                    normalized_reference_count: 5,
                })
            }
        }

        let quarantined =
            super::super::apply::ensure_quarantined(&writer, &mut validated, &mut MovingAdapter)
                .unwrap();
        assert!(quarantined.changed);
        let quarantined_manifest = writer.load().unwrap();
        assert_eq!(
            coherent_retired_replacement_phase(
                &validated.operational_document,
                &quarantined_manifest
            )
            .unwrap(),
            Some(super::super::LegacyUploadMigrationPhase::Quarantined)
        );
        assert_eq!(
            validate_device_recovery_quarantine_layout(
                &validated.operational_document,
                &quarantined_manifest,
                super::super::LegacyUploadMigrationPhase::Quarantined,
            )
            .unwrap_err()
            .category(),
            "recovery_layout"
        );
        let reset = super::super::apply::ensure_reset(&writer, &mut validated).unwrap();
        assert!(reset.changed);
        let reset_manifest = writer.load().unwrap();
        for replacement in &fixture.document.retired_replacements {
            let record = reset_manifest.get(&replacement.asset_id).unwrap();
            assert!(!record.proofs.contains_key("upload"));
            assert!(!record.proofs.contains_key("icloudpd_local_mirror"));
            assert_eq!(
                validate_legacy_upload_migration_record(record)
                    .unwrap()
                    .entries
                    .last()
                    .unwrap()
                    .phase,
                super::super::LegacyUploadMigrationPhase::Reset
            );
        }
        writer.release_writer_lease().unwrap();

        set_device_recovery_signer_hook(signer);
        let mut resumed = load_validated_legacy_uploaded_heic_evidence_with_device_recovery(
            &fixture.request,
            Some(&recovery),
        )
        .unwrap();
        assert!(resumed.has_device_recovery_receipt());
        assert!(
            resumed
                .quarantine_plan()
                .roots
                .iter()
                .all(|root| root.device == current_device)
        );
        let authoritative = AssetStateStore::open_immutable_read_only(&fixture.manifest_path)
            .unwrap()
            .load()
            .unwrap();
        resumed
            .revalidate_authoritative_manifest(&authoritative)
            .unwrap();
        let guard = super::super::apply::preflight_quarantine_plan(
            &resumed,
            std::slice::from_ref(&fixture.quarantine_root),
            Some(super::super::LegacyUploadMigrationPhase::Reset),
            30,
        )
        .unwrap();
        guard.revalidate().unwrap();

        let mut missing_record = authoritative
            .get(&fixture.document.retired_replacements[0].asset_id)
            .unwrap()
            .clone();
        missing_record
            .proofs
            .remove(super::super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME);
        assert!(validate_legacy_upload_migration_record(&missing_record).is_err());

        let mut invalid_record = authoritative
            .get(&fixture.document.retired_replacements[0].asset_id)
            .unwrap()
            .clone();
        let mut invalid: super::super::LegacyUploadMigrationJournal = serde_json::from_value(
            invalid_record.proofs[super::super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME].clone(),
        )
        .unwrap();
        invalid.entries[0].entry_sha256 = digest("invalid-journal");
        invalid_record.proofs.insert(
            super::super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME.to_string(),
            serde_json::to_value(invalid).unwrap(),
        );
        assert!(validate_legacy_upload_migration_record(&invalid_record).is_err());

        let mut mismatched_record = authoritative
            .get(&fixture.document.retired_replacements[0].asset_id)
            .unwrap()
            .clone();
        let mut mismatched: super::super::LegacyUploadMigrationJournal = serde_json::from_value(
            mismatched_record.proofs[super::super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME].clone(),
        )
        .unwrap();
        let mut mismatched_plan = mismatched.identity.quarantine_plan.clone();
        mismatched_plan.members[0].source.sha256 = digest("mismatched-plan");
        mismatched.identity.quarantine_plan =
            super::super::seal_legacy_upload_migration_quarantine_plan(mismatched_plan).unwrap();
        let identity_sha = super::super::canonical_digest(&mismatched.identity).unwrap();
        let mut previous = super::super::GENESIS_ENTRY_SHA256.to_string();
        for entry in &mut mismatched.entries {
            entry.previous_entry_sha256 = previous;
            entry.entry_sha256 = super::super::entry_digest(
                mismatched.schema_version,
                &identity_sha,
                entry.ordinal,
                entry.phase,
                entry.witness_kind,
                &entry.witness_sha256,
                &entry.record_body_sha256,
                &entry.previous_entry_sha256,
            )
            .unwrap();
            previous = entry.entry_sha256.clone();
        }
        mismatched_record.proofs.insert(
            super::super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME.to_string(),
            serde_json::to_value(mismatched).unwrap(),
        );
        let mismatched_authority =
            super::super::LegacyUploadMigrationManifestRecordAuthority::for_record(
                &mismatched_record,
            )
            .unwrap();
        let second_record = authoritative
            .get(&fixture.document.retired_replacements[1].asset_id)
            .unwrap()
            .clone();
        let second_authority =
            super::super::LegacyUploadMigrationManifestRecordAuthority::for_record(&second_record)
                .unwrap();
        let mut mismatched_manifest = Manifest::new();
        mismatched_manifest
            .upsert_legacy_upload_migration_record(&mismatched_authority, mismatched_record)
            .unwrap();
        mismatched_manifest
            .upsert_legacy_upload_migration_record(&second_authority, second_record)
            .unwrap();
        assert_eq!(
            quarantine_plan_from_document(&fixture.document, &mismatched_manifest)
                .unwrap_err()
                .category(),
            "quarantine_mapping"
        );

        let mut tampered_root = fixture.document.clone();
        tampered_root.quarantine_roots[0].inode += 1;
        assert_eq!(
            quarantine_plan_from_document(&tampered_root, &authoritative)
                .unwrap_err()
                .category(),
            "quarantine_mapping"
        );
        let mut tampered_member = fixture.document.clone();
        tampered_member.quarantine_members[0].source.sha256 = digest("tampered-member");
        assert_eq!(
            quarantine_plan_from_document(&tampered_member, &authoritative)
                .unwrap_err()
                .category(),
            "quarantine_mapping"
        );
    }

    #[test]
    fn sealed_evidence_revalidates_after_reset_removed_retired_downstream_proofs() {
        let fixture = build_fixture();
        let mut validated = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-evidence-reset-resume",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        super::super::apply::ensure_prepared(&writer, &mut validated).unwrap();
        let ids = validated.replacement_asset_ids().map(str::to_string);
        let phase = super::super::LegacyUploadMigrationPhase::DeleteConfirmed;
        {
            let manifest = writer.load().unwrap();
            let expected = [
                manifest.get(&ids[0]).unwrap().clone(),
                manifest.get(&ids[1]).unwrap().clone(),
            ];
            let candidates = expected.clone();
            let updated = [
                super::super::advance_legacy_upload_migration_record_with_witness(
                    &candidates[0],
                    phase,
                    &digest(&format!("phase-{phase:?}-0")),
                )
                .unwrap(),
                super::super::advance_legacy_upload_migration_record_with_witness(
                    &candidates[1],
                    phase,
                    &digest(&format!("phase-{phase:?}-1")),
                )
                .unwrap(),
            ];
            super::super::persist_two_legacy_upload_migration_records_exact_cas_internal(
                &writer,
                [
                    super::super::LegacyUploadMigrationCasUpdate {
                        expected: &expected[0],
                        updated: &updated[0],
                    },
                    super::super::LegacyUploadMigrationCasUpdate {
                        expected: &expected[1],
                        updated: &updated[1],
                    },
                ],
            )
            .unwrap_or_else(|error| panic!("phase {phase:?} failed: {error:?}"));
            for record in &updated {
                assert!(!record.proofs.contains_key("uploaded_heic_delete"));
                let journal =
                    super::super::validate_legacy_upload_migration_record(record).unwrap();
                assert_eq!(journal.entries.last().unwrap().phase, phase);
            }
        }
        struct QuarantineAdapter {
            receipt: super::super::apply::QuarantineBatchReceipt,
        }
        impl super::super::apply::LegacyArtifactQuarantineAdapter for QuarantineAdapter {
            type Error = ();

            fn quarantine_and_normalize(
                &mut self,
                evidence: &ValidatedLegacyUploadEvidence,
                _manifest: &Manifest,
            ) -> Result<super::super::apply::QuarantineBatchReceipt, ()> {
                for member in &evidence.quarantine_plan().members {
                    fs::create_dir_all(member.destination_path.parent().unwrap()).unwrap();
                    fs::set_permissions(
                        member.destination_path.parent().unwrap(),
                        fs::Permissions::from_mode(0o700),
                    )
                    .unwrap();
                    fs::rename(&member.source_path, &member.destination_path).unwrap();
                }
                Ok(self.receipt.clone())
            }
        }
        let mut quarantine = QuarantineAdapter {
            receipt: super::super::apply::QuarantineBatchReceipt {
                schema_version: 2,
                cohort_sha256: validated.audit().cohort_sha256.clone(),
                canonical_root_identity_sha256: canonical_digest(
                    &validated.quarantine_plan().roots,
                )
                .unwrap(),
                target_set_sha256: digest("quarantine-targets"),
                target_count: 9,
                normalized_reference_count: 5,
            },
        };
        let quarantined =
            super::super::apply::ensure_quarantined(&writer, &mut validated, &mut quarantine)
                .unwrap();
        assert!(quarantined.changed);
        let first = super::super::apply::ensure_reset(&writer, &mut validated).unwrap();
        assert!(first.changed);
        assert!(first.checkpoint_exported);
        let reset_manifest = writer.load().unwrap();
        for asset_id in &ids {
            let reset = reset_manifest.get(asset_id).unwrap();
            assert!(!reset.proofs.contains_key("uploaded_heic_delete"));
            let journal = super::super::validate_legacy_upload_migration_record(reset).unwrap();
            let deleted = journal
                .entries
                .iter()
                .find(|entry| {
                    entry.phase == super::super::LegacyUploadMigrationPhase::DeleteConfirmed
                })
                .unwrap();
            let reset_entry = journal.entries.last().unwrap();
            assert_eq!(
                reset_entry.phase,
                super::super::LegacyUploadMigrationPhase::Reset
            );
            assert_eq!(
                reset_entry.previous_entry_sha256,
                journal.entries[journal.entries.len() - 2].entry_sha256
            );
            assert!(
                journal
                    .entries
                    .iter()
                    .any(|entry| entry.entry_sha256 == deleted.entry_sha256)
            );
        }
        let second = super::super::apply::ensure_reset(&writer, &mut validated).unwrap();
        assert!(!second.changed);
        struct ConversionAdapter;
        impl super::super::apply::LegacyConversionAdapter for ConversionAdapter {
            type Error = ();

            fn convert_and_verify(
                &mut self,
                expected: [&AssetRecord; 2],
                output_paths: [&Path; 2],
            ) -> Result<[AssetRecord; 2], ()> {
                let mut converted = Vec::new();
                for index in 0..2 {
                    let bytes = format!("converted-{}", expected[index].asset_id).into_bytes();
                    fs::write(output_paths[index], &bytes).unwrap();
                    fs::set_permissions(output_paths[index], fs::Permissions::from_mode(0o600))
                        .unwrap();
                    let sha256 = sha256_bytes(&bytes);
                    let mut manifest = Manifest::new();
                    let mut record = expected[index].clone();
                    record
                        .proofs
                        .remove(super::super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME);
                    manifest.upsert_trusted(record);
                    crate::workflow::record_current_conversion_result(
                        &mut manifest,
                        &expected[index].asset_id,
                        crate::workflow::ConversionResultInput {
                            heic_path: output_paths[index].to_path_buf(),
                            heic_sha256: sha256.clone(),
                            size_bytes: bytes.len() as u64,
                            source_binding:
                                crate::workflow::ConversionSourceBinding::EmbeddedPreview,
                        },
                    )
                    .unwrap();
                    crate::workflow::record_current_conversion_performance(
                        &mut manifest,
                        &expected[index].asset_id,
                        crate::workflow::ConversionPerformanceInput {
                            measured_at_unix_seconds: 1_752_400_000,
                            conversion_tool: "test".to_string(),
                            conversion_tool_version: None,
                            heic_quality: 90,
                            convert_wall_time_millis: 1,
                            total_wall_time_millis: 2,
                            user_cpu_time_millis: None,
                            system_cpu_time_millis: None,
                            peak_rss_kib: None,
                            conversion_command_timings: Vec::new(),
                        },
                    )
                    .unwrap();
                    crate::workflow::record_current_heic_verification(
                        &mut manifest,
                        &expected[index].asset_id,
                        crate::workflow::HeicVerificationInput {
                            heic_path: output_paths[index].to_path_buf(),
                            heic_sha256: sha256,
                            size_bytes: bytes.len() as u64,
                            heif_info_ok: true,
                            metadata_copied: true,
                            visual_content_ok: true,
                            visual_match_ok: true,
                            visual_rmse_ppm: Some(0),
                            visual_mae_ppm: Some(0),
                        },
                    )
                    .unwrap();
                    let mut record = manifest.get(&expected[index].asset_id).unwrap().clone();
                    record.updated_at = expected[index].updated_at.clone();
                    record.proofs.insert(
                        super::super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME.to_string(),
                        expected[index].proofs[super::super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME]
                            .clone(),
                    );
                    converted.push(record);
                }
                Ok([converted.remove(0), converted.remove(0)])
            }
        }
        let converted = super::super::apply::ensure_converted(
            &writer,
            &mut validated,
            &fixture.artifact_root,
            &mut ConversionAdapter,
        )
        .unwrap();
        assert!(converted.changed);
        let converted_replay = super::super::apply::ensure_converted(
            &writer,
            &mut validated,
            &fixture.artifact_root,
            &mut ConversionAdapter,
        )
        .unwrap();
        assert!(!converted_replay.changed);
        let converted_manifest = writer.load().unwrap();
        let converted_guard =
            super::super::apply::preflight_quarantine_plan_with_conversion_output(
                &validated,
                std::slice::from_ref(&fixture.quarantine_root),
                super::super::LegacyUploadMigrationPhase::Converted,
                30,
                &converted_manifest,
                &fixture.artifact_root,
            )
            .unwrap();
        converted_guard.revalidate().unwrap();
        let final_member = validated
            .quarantine_plan()
            .members
            .iter()
            .find(|member| {
                member.kind == LegacyUploadMigrationQuarantineKind::Final
                    && member.asset_id == fixture.document.retired_replacements[0].asset_id
            })
            .unwrap();
        let original_source_bytes = fs::read(&final_member.source_path).unwrap();
        fs::write(&final_member.source_path, b"tampered converted output").unwrap();
        fs::set_permissions(&final_member.source_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            super::super::apply::preflight_quarantine_plan_with_conversion_output(
                &validated,
                std::slice::from_ref(&fixture.quarantine_root),
                super::super::LegacyUploadMigrationPhase::Converted,
                30,
                &converted_manifest,
                &fixture.artifact_root,
            )
            .is_err()
        );
        fs::write(&final_member.source_path, &original_source_bytes).unwrap();
        fs::set_permissions(&final_member.source_path, fs::Permissions::from_mode(0o600)).unwrap();
        let destination_bytes = fs::read(&final_member.destination_path).unwrap();
        fs::write(
            &final_member.destination_path,
            b"tampered quarantined original",
        )
        .unwrap();
        assert!(
            super::super::apply::preflight_quarantine_plan_with_conversion_output(
                &validated,
                std::slice::from_ref(&fixture.quarantine_root),
                super::super::LegacyUploadMigrationPhase::Converted,
                30,
                &converted_manifest,
                &fixture.artifact_root,
            )
            .is_err()
        );
        fs::write(&final_member.destination_path, &destination_bytes).unwrap();
        let upload_prepared = super::super::apply::ensure_upload_prepared(
            &writer,
            &mut validated,
            &fixture.artifact_root,
        )
        .unwrap();
        assert!(upload_prepared.changed);
        let upload_prepared_replay = super::super::apply::ensure_upload_prepared(
            &writer,
            &mut validated,
            &fixture.artifact_root,
        )
        .unwrap();
        assert!(!upload_prepared_replay.changed);
        #[derive(Clone)]
        struct RemoteUpload {
            prepared_sha256: String,
            uploaded_asset_id: String,
            master_record_name: String,
            streamed_heic_sha256: String,
        }
        struct UploadAdapter {
            upload_attempts: usize,
            create_attempts: [usize; 2],
            commits: [usize; 2],
            absence_preflights: [usize; 2],
            exact_reconciles: [usize; 2],
            fail_second_create_once: bool,
            remote: BTreeMap<String, RemoteUpload>,
            swap_first_source_path: Option<(PathBuf, PathBuf)>,
            held_source_sha256: Option<String>,
            named_source_sha256: Option<String>,
        }
        impl UploadAdapter {
            fn candidate(
                expected: &AssetRecord,
                replacement: &EvidenceRetiredReplacement,
                remote: &RemoteUpload,
            ) -> AssetRecord {
                let mut manifest = Manifest::new();
                let mut candidate = expected.clone();
                candidate
                    .proofs
                    .remove(super::super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME);
                manifest.upsert_trusted(candidate);
                let heic = &expected.proofs["heic"];
                crate::workflow::record_upload_proof(
                    &mut manifest,
                    &expected.asset_id,
                    UploadProof {
                        uploaded_heic_asset_id: remote.uploaded_asset_id.clone(),
                        uploaded_heic_sha256: remote.streamed_heic_sha256.clone(),
                        database_scope: replacement.destination.database_scope,
                        zone_name: replacement.destination.zone_name.clone(),
                        owner_record_name: replacement.destination.owner_record_name.clone(),
                        uploaded_heic_path: Some(PathBuf::from(
                            heic["heic_path"].as_str().unwrap(),
                        )),
                    },
                )
                .unwrap();
                let mut candidate = manifest.get(&expected.asset_id).unwrap().clone();
                candidate.updated_at = expected.updated_at.clone();
                candidate.proofs.insert(
                    super::super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME.to_string(),
                    expected.proofs[super::super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME].clone(),
                );
                candidate
            }

            fn receipt(
                record: &AssetRecord,
                replacement: &EvidenceRetiredReplacement,
            ) -> super::super::apply::VerifiedRemoteUploadReceipt {
                let upload: UploadProof =
                    serde_json::from_value(record.proofs["upload"].clone()).unwrap();
                let uploaded_asset_id = upload.uploaded_heic_asset_id;
                let master_record_name = format!("new-master-{}", record.asset_id);
                super::super::apply::VerifiedRemoteUploadReceipt {
                    asset_id: record.asset_id.clone(),
                    uploaded_asset_id_sha256: digest(&uploaded_asset_id),
                    master_record_name_sha256: digest(&master_record_name),
                    record_change_tag_sha256: digest("new-change-tag"),
                    heic_sha256: upload.uploaded_heic_sha256,
                    size_bytes: record.proofs["heic"]["size_bytes"].as_u64().unwrap(),
                    destination_sha256: replacement.destination_sha256.clone(),
                    inventory_sha256: digest("inventory"),
                    inventory_records_scanned: 12,
                    uploaded_asset_id,
                    master_record_name,
                }
            }
        }
        impl super::super::apply::LegacyUploadAdapter for UploadAdapter {
            type Error = ();

            fn upload_or_reconcile(
                &mut self,
                expected: [&AssetRecord; 2],
                replacements: &[EvidenceRetiredReplacement],
                sources: [&crate::upload::VerifiedUploadSource; 2],
            ) -> Result<[super::super::apply::VerifiedLegacyUpload; 2], ()> {
                self.upload_attempts += 1;
                if let Some((source_path, moved_path)) = self.swap_first_source_path.take() {
                    fs::rename(&source_path, &moved_path).map_err(|_| ())?;
                    fs::write(&source_path, b"untrusted-replacement-heic").map_err(|_| ())?;
                    let mut held = sources[0].held_file().map_err(|_| ())?;
                    let mut held_bytes = Vec::new();
                    held.read_to_end(&mut held_bytes).map_err(|_| ())?;
                    self.held_source_sha256 = Some(sha256_bytes(&held_bytes));
                    self.named_source_sha256 =
                        Some(sha256_bytes(&fs::read(&source_path).map_err(|_| ())?));
                }
                let mut uploaded = Vec::with_capacity(2);
                for index in 0..2 {
                    let mut streamed = sources[index].held_file().map_err(|_| ())?;
                    let mut streamed_bytes = Vec::new();
                    streamed.read_to_end(&mut streamed_bytes).map_err(|_| ())?;
                    let streamed_heic_sha256 = sha256_bytes(&streamed_bytes);
                    let prepared_sha256 =
                        super::super::canonical_digest(expected[index]).map_err(|_| ())?;
                    let remote = if let Some(existing) = self.remote.get(&expected[index].asset_id)
                    {
                        if existing.prepared_sha256 != prepared_sha256
                            || existing.streamed_heic_sha256 != streamed_heic_sha256
                        {
                            return Err(());
                        }
                        self.exact_reconciles[index] += 1;
                        existing.clone()
                    } else {
                        self.absence_preflights[index] += 1;
                        self.create_attempts[index] += 1;
                        if index == 1 && self.fail_second_create_once && self.upload_attempts == 1 {
                            return Err(());
                        }
                        let remote = RemoteUpload {
                            prepared_sha256,
                            uploaded_asset_id: format!("new-upload-{}", expected[index].asset_id),
                            master_record_name: format!("new-master-{}", expected[index].asset_id),
                            streamed_heic_sha256,
                        };
                        self.remote
                            .insert(expected[index].asset_id.clone(), remote.clone());
                        self.commits[index] += 1;
                        remote
                    };
                    let candidate = Self::candidate(expected[index], &replacements[index], &remote);
                    let receipt = Self::receipt(&candidate, &replacements[index]);
                    if receipt.uploaded_asset_id != remote.uploaded_asset_id
                        || receipt.master_record_name != remote.master_record_name
                    {
                        return Err(());
                    }
                    uploaded.push(super::super::apply::VerifiedLegacyUpload { candidate, receipt });
                }
                Ok([uploaded.remove(0), uploaded.remove(0)])
            }

            fn verify_existing(
                &mut self,
                records: [&AssetRecord; 2],
                replacements: &[EvidenceRetiredReplacement],
            ) -> Result<[super::super::apply::VerifiedRemoteUploadReceipt; 2], ()> {
                for record in &records {
                    let remote = self.remote.get(&record.asset_id).ok_or(())?;
                    let upload: UploadProof =
                        serde_json::from_value(record.proofs["upload"].clone()).map_err(|_| ())?;
                    if upload.uploaded_heic_asset_id != remote.uploaded_asset_id {
                        return Err(());
                    }
                }
                Ok([
                    Self::receipt(records[0], &replacements[0]),
                    Self::receipt(records[1], &replacements[1]),
                ])
            }
        }
        let prepared_manifest = writer.load().unwrap();
        let first_prepared = prepared_manifest
            .get(validated.replacement_asset_ids()[0])
            .unwrap();
        let first_heic: HeicVerificationProof =
            serde_json::from_value(first_prepared.proofs["heic"].clone()).unwrap();
        let original_output = fs::read(&first_heic.heic_path).unwrap();
        let output_metadata = fs::metadata(&first_heic.heic_path).unwrap();
        let output_mtime = filetime::FileTime::from_last_modification_time(&output_metadata);
        let mut drifted_output = original_output.clone();
        drifted_output[0] ^= 0x01;
        fs::write(&first_heic.heic_path, drifted_output).unwrap();
        filetime::set_file_mtime(&first_heic.heic_path, output_mtime).unwrap();
        let mut drift_adapter = UploadAdapter {
            upload_attempts: 0,
            create_attempts: [0; 2],
            commits: [0; 2],
            absence_preflights: [0; 2],
            exact_reconciles: [0; 2],
            fail_second_create_once: false,
            remote: BTreeMap::new(),
            swap_first_source_path: None,
            held_source_sha256: None,
            named_source_sha256: None,
        };
        assert_eq!(
            super::super::apply::ensure_upload_verified(
                &writer,
                &mut validated,
                &mut drift_adapter,
            )
            .unwrap_err(),
            super::super::apply::LegacyUploadMigrationApplyError::Cohort
        );
        assert_eq!(drift_adapter.upload_attempts, 0);
        assert!(drift_adapter.remote.is_empty());
        fs::write(&first_heic.heic_path, original_output).unwrap();
        filetime::set_file_mtime(&first_heic.heic_path, output_mtime).unwrap();
        let moved_output = first_heic.heic_path.with_extension("sealed-heic");
        let mut path_swap_adapter = UploadAdapter {
            upload_attempts: 0,
            create_attempts: [0; 2],
            commits: [0; 2],
            absence_preflights: [0; 2],
            exact_reconciles: [0; 2],
            fail_second_create_once: false,
            remote: BTreeMap::new(),
            swap_first_source_path: Some((first_heic.heic_path.clone(), moved_output.clone())),
            held_source_sha256: None,
            named_source_sha256: None,
        };
        assert_eq!(
            super::super::apply::ensure_upload_verified(
                &writer,
                &mut validated,
                &mut path_swap_adapter,
            )
            .unwrap_err(),
            super::super::apply::LegacyUploadMigrationApplyError::Cohort
        );
        assert_eq!(
            path_swap_adapter.held_source_sha256.as_deref(),
            Some(first_heic.heic_sha256.as_str()),
            "adapter/network must consume the already-held sealed descriptor bytes"
        );
        assert_ne!(
            path_swap_adapter.named_source_sha256,
            path_swap_adapter.held_source_sha256
        );
        assert_eq!(
            path_swap_adapter
                .remote
                .get(&first_prepared.asset_id)
                .unwrap()
                .streamed_heic_sha256,
            first_heic.heic_sha256
        );
        fs::remove_file(&first_heic.heic_path).unwrap();
        fs::rename(moved_output, &first_heic.heic_path).unwrap();
        let mut upload_adapter = UploadAdapter {
            upload_attempts: 0,
            create_attempts: [0; 2],
            commits: [0; 2],
            absence_preflights: [0; 2],
            exact_reconciles: [0; 2],
            fail_second_create_once: true,
            remote: BTreeMap::new(),
            swap_first_source_path: None,
            held_source_sha256: None,
            named_source_sha256: None,
        };
        assert_eq!(
            super::super::apply::ensure_upload_verified(
                &writer,
                &mut validated,
                &mut upload_adapter,
            )
            .unwrap_err(),
            super::super::apply::LegacyUploadMigrationApplyError::Remote
        );
        assert_eq!(upload_adapter.create_attempts, [1, 1]);
        assert_eq!(upload_adapter.commits, [1, 0]);
        assert_eq!(upload_adapter.absence_preflights, [1, 1]);
        assert_eq!(upload_adapter.exact_reconciles, [0, 0]);
        assert_eq!(upload_adapter.remote.len(), 1);
        let after_interruption = writer.load().unwrap();
        for asset_id in validated.replacement_asset_ids() {
            let journal = super::super::validate_legacy_upload_migration_record(
                after_interruption.get(asset_id).unwrap(),
            )
            .unwrap();
            assert_eq!(
                journal.entries.last().unwrap().phase,
                super::super::LegacyUploadMigrationPhase::UploadPrepared
            );
        }
        let upload_verified = super::super::apply::ensure_upload_verified(
            &writer,
            &mut validated,
            &mut upload_adapter,
        )
        .unwrap();
        assert!(upload_verified.changed);
        assert_eq!(upload_adapter.upload_attempts, 2);
        assert_eq!(upload_adapter.create_attempts, [1, 2]);
        assert_eq!(upload_adapter.commits, [1, 1]);
        assert_eq!(upload_adapter.absence_preflights, [1, 2]);
        assert_eq!(upload_adapter.exact_reconciles, [1, 0]);
        assert_eq!(upload_adapter.remote.len(), 2);
        let upload_verified_replay = super::super::apply::ensure_upload_verified(
            &writer,
            &mut validated,
            &mut upload_adapter,
        )
        .unwrap();
        assert!(!upload_verified_replay.changed);
        struct MirrorAdapter;
        impl super::super::apply::LegacyMirrorAdapter for MirrorAdapter {
            type Error = ();

            fn mirror_or_reconcile(
                &mut self,
                expected: [&AssetRecord; 2],
                mirror_paths: [&Path; 2],
            ) -> Result<[AssetRecord; 2], ()> {
                Ok(std::array::from_fn(|index| {
                    let upload: UploadProof =
                        serde_json::from_value(expected[index].proofs["upload"].clone()).unwrap();
                    let heic = &expected[index].proofs["heic"];
                    fs::copy(
                        Path::new(heic["heic_path"].as_str().unwrap()),
                        mirror_paths[index],
                    )
                    .unwrap();
                    let mut manifest = Manifest::new();
                    let mut candidate = expected[index].clone();
                    candidate
                        .proofs
                        .remove(super::super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME);
                    manifest.upsert_trusted(candidate);
                    crate::workflow::record_icloudpd_local_mirror_proof(
                        &mut manifest,
                        &expected[index].asset_id,
                        crate::workflow::IcloudpdLocalMirrorProof {
                            uploaded_heic_asset_id: upload.uploaded_heic_asset_id,
                            uploaded_heic_sha256: upload.uploaded_heic_sha256,
                            uploaded_heic_path: PathBuf::from(heic["heic_path"].as_str().unwrap()),
                            icloudpd_download_path: mirror_paths[index].to_path_buf(),
                            size_bytes: heic["size_bytes"].as_u64().unwrap(),
                        },
                    )
                    .unwrap();
                    let mut candidate = manifest.get(&expected[index].asset_id).unwrap().clone();
                    candidate.updated_at = expected[index].updated_at.clone();
                    candidate.proofs.insert(
                        super::super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME.to_string(),
                        expected[index].proofs[super::super::LEGACY_UPLOAD_MIGRATION_PROOF_NAME]
                            .clone(),
                    );
                    candidate
                }))
            }
        }
        let mirror_root = fixture.artifact_root.join("mirror");
        fs::create_dir(&mirror_root).unwrap();
        let mirrored = super::super::apply::ensure_mirrored(
            &writer,
            &mut validated,
            &mirror_root,
            &mut MirrorAdapter,
        )
        .unwrap();
        assert!(mirrored.changed);
        let mirrored_replay = super::super::apply::ensure_mirrored(
            &writer,
            &mut validated,
            &mirror_root,
            &mut MirrorAdapter,
        )
        .unwrap();
        assert!(!mirrored_replay.changed);
        let mirrored_checkpoint = fs::read(&fixture.manifest_path).unwrap();
        let failing_checkpoint_path = fixture.manifest_path.clone();
        super::super::apply::set_checkpoint_export_hook(move || {
            fs::remove_file(&failing_checkpoint_path).unwrap();
            fs::create_dir(&failing_checkpoint_path).unwrap();
        });
        assert_eq!(
            super::super::apply::ensure_complete(
                &writer,
                &mut validated,
                &fixture.artifact_root,
                &mirror_root,
            )
            .unwrap_err(),
            super::super::apply::LegacyUploadMigrationApplyError::CheckpointStale
        );
        fs::remove_dir(&fixture.manifest_path).unwrap();
        fs::write(&fixture.manifest_path, &mirrored_checkpoint).unwrap();
        let complete_database = writer.load().unwrap();
        for asset_id in validated.replacement_asset_ids() {
            let journal = super::super::validate_legacy_upload_migration_record(
                complete_database.get(asset_id).unwrap(),
            )
            .unwrap();
            assert_eq!(
                journal.entries.last().unwrap().phase,
                super::super::LegacyUploadMigrationPhase::Complete,
                "checkpoint export failure must not roll back the exact-two Complete CAS"
            );
        }
        assert_eq!(
            super::super::apply::ensure_complete(
                &writer,
                &mut validated,
                &fixture.artifact_root,
                &mirror_root,
            )
            .unwrap_err(),
            super::super::apply::LegacyUploadMigrationApplyError::CheckpointStale
        );
        for reference in &fixture.document.reference_normalizations {
            let _ = fs::remove_file(&reference.reference_path);
            fs::write(&reference.reference_path, b"normalized replacement").unwrap();
        }
        writer.release_writer_lease().unwrap();

        let mut resumed = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let authoritative = AssetStateStore::open_immutable_read_only(&fixture.manifest_path)
            .unwrap()
            .load()
            .unwrap();
        resumed
            .revalidate_authoritative_manifest(&authoritative)
            .unwrap();
        for replacement in &fixture.document.retired_replacements {
            fs::remove_file(
                fixture
                    .artifact_root
                    .join(&replacement.destination.filename),
            )
            .unwrap();
            fs::remove_file(mirror_root.join(&replacement.destination.filename)).unwrap();
        }
        let replay_writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-complete-production-replay",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let report = super::super::apply::apply_legacy_uploaded_heic_migration(
            &replay_writer,
            &super::super::apply::LegacyUploadMigrationProductionRequest {
                evidence: fixture.request.clone(),
                quarantine_roots: vec![fixture.quarantine_root.clone()],
                heic_output_dir: fixture.artifact_root.clone(),
                mirror_root,
                upload_session_path: PathBuf::from("/must-not-open-upload-session"),
                delete_session_path: PathBuf::from("/must-not-open-delete-session"),
                jobs: 1,
                heic_quality: 90,
                conversion_tool_version: None,
                capture_tolerance_seconds: 60,
                cloudkit_start_rank: 0,
                cloudkit_page_size: 100,
                cloudkit_max_pages: 10,
                heic_verify_timeout_seconds: 30,
            },
        )
        .unwrap();
        assert_eq!(report.phase, "complete");
        assert_eq!(report.changed_phase_count, 0);
        assert!(report.checkpoint_recovered);
        assert_eq!(report.checkpoint_exports, 1);
        assert_eq!(report.retired_replacement_delete_calls, 0);
        assert_eq!(report.retired_replacements_already_deleted, 0);
        assert_eq!(report.retired_replacements_deleted_by_migration, 2);
        assert_eq!(report.replacement_uploads, 2);
        assert_eq!(report.original_deletes, 0);
        let current_checkpoint_mtime = fs::metadata(&fixture.manifest_path)
            .unwrap()
            .modified()
            .unwrap();
        let no_op = super::super::apply::apply_legacy_uploaded_heic_migration(
            &replay_writer,
            &super::super::apply::LegacyUploadMigrationProductionRequest {
                evidence: fixture.request.clone(),
                quarantine_roots: vec![fixture.quarantine_root.clone()],
                heic_output_dir: fixture.artifact_root.clone(),
                mirror_root: fixture.artifact_root.join("mirror"),
                upload_session_path: PathBuf::from("/must-not-open-upload-session"),
                delete_session_path: PathBuf::from("/must-not-open-delete-session"),
                jobs: 1,
                heic_quality: 90,
                conversion_tool_version: None,
                capture_tolerance_seconds: 60,
                cloudkit_start_rank: 0,
                cloudkit_page_size: 100,
                cloudkit_max_pages: 10,
                heic_verify_timeout_seconds: 30,
            },
        )
        .unwrap();
        assert!(!no_op.checkpoint_recovered);
        assert_eq!(
            fs::metadata(&fixture.manifest_path)
                .unwrap()
                .modified()
                .unwrap(),
            current_checkpoint_mtime,
            "matching Complete replay must not rewrite the checkpoint"
        );

        let recovered_reader =
            AssetStateStore::open_immutable_read_only(&fixture.manifest_path).unwrap();
        assert_eq!(
            recovered_reader.json_checkpoint_status().unwrap(),
            crate::state_store::JsonCheckpointStatus::Current
        );
        replay_writer.release_writer_lease().unwrap();
    }

    #[test]
    fn delete_confirmed_phase_is_exact_two_checkpointed_and_replayed_without_network() {
        #[derive(Default)]
        struct ConfirmedAdapter {
            lookups: usize,
            resolves: usize,
            original_checks: usize,
        }
        impl super::super::apply::RetiredReplacementDeleteAdapter for ConfirmedAdapter {
            type Error = ();

            fn lookup(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitDeleteStateLookupResult, ()> {
                self.lookups += 1;
                Ok(crate::upload::CloudKitDeleteStateLookupResult {
                    confirmed_deleted: vec![crate::upload::CloudKitDeleteOutcome {
                        record_name: replacement.uploaded_asset_id.clone(),
                        record_change_tag: format!("confirmed-{}", replacement.asset_id),
                    }],
                    unconfirmed: vec![],
                })
            }

            fn resolve(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitUploadedHeicAsset, ()> {
                self.resolves += 1;
                Ok(recovered_deleted_asset(replacement))
            }

            fn delete(
                &mut self,
                _replacement: &EvidenceRetiredReplacement,
                _resolved: &crate::upload::CloudKitUploadedHeicAsset,
            ) -> Result<crate::upload::CloudKitDeleteOutcome, ()> {
                panic!("confirmed replacement must not be deleted again")
            }

            fn validate_original_active(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<CloudKitActiveAssetValidation, ()> {
                self.original_checks += 1;
                Ok(original_validation_for(replacement))
            }
        }

        let fixture = build_fixture();
        let mut validated = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-delete-confirmed",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        super::super::apply::ensure_prepared(&writer, &mut validated).unwrap();
        let mut adapter = ConfirmedAdapter::default();
        let first =
            super::super::apply::ensure_delete_confirmed(&writer, &mut validated, &mut adapter)
                .unwrap();
        assert!(first.changed);
        assert!(first.checkpoint_exported);
        assert_eq!(adapter.lookups, 0);
        assert_eq!(adapter.resolves, 2);
        assert_eq!(adapter.original_checks, 2);
        let second =
            super::super::apply::ensure_delete_confirmed(&writer, &mut validated, &mut adapter)
                .unwrap();
        assert!(!second.changed);
        assert_eq!(adapter.lookups, 0);
        assert_eq!(adapter.resolves, 2);
        assert_eq!(adapter.original_checks, 2);
        for asset_id in validated.replacement_asset_ids() {
            let record = writer.load().unwrap().get(asset_id).unwrap().clone();
            let journal = super::super::validate_legacy_upload_migration_record(&record).unwrap();
            assert_eq!(
                journal.entries.last().unwrap().phase,
                super::super::LegacyUploadMigrationPhase::DeleteConfirmed
            );
        }
    }

    #[test]
    fn upload_verification_rejects_a_second_active_replacement() {
        let resolution = crate::upload::CloudKitOriginalAssetResolution {
            observations: crate::upload::CloudKitOriginalAssetResolveObservations {
                date_candidates: 2,
                replacement_resource_matches: 2,
                ambiguity_evidence: 2,
                ..Default::default()
            },
            disposition: crate::upload::CloudKitOriginalAssetResolveDisposition::Ambiguous,
        };
        assert_eq!(
            super::super::apply::require_unique_active_replacement(&resolution).unwrap_err(),
            super::super::apply::LegacyUploadMigrationApplyError::Remote
        );

        let ambiguous_one = crate::upload::CloudKitOriginalAssetResolution {
            observations: crate::upload::CloudKitOriginalAssetResolveObservations {
                date_candidates: 1,
                replacement_resource_matches: 1,
                ..Default::default()
            },
            disposition: crate::upload::CloudKitOriginalAssetResolveDisposition::Ambiguous,
        };
        assert_eq!(
            super::super::apply::require_unique_active_replacement(&ambiguous_one).unwrap_err(),
            super::super::apply::LegacyUploadMigrationApplyError::Remote
        );
        let exact_one = crate::upload::CloudKitOriginalAssetResolution {
            observations: crate::upload::CloudKitOriginalAssetResolveObservations {
                date_candidates: 1,
                replacement_resource_matches: 1,
                ..Default::default()
            },
            disposition:
                crate::upload::CloudKitOriginalAssetResolveDisposition::ReplacementPresent {
                    proof: crate::upload::CloudKitReplacementResourceProof {
                        record_name: "new-asset".to_string(),
                        record_change_tag: "new-tag".to_string(),
                        record_type: "CPLAsset".to_string(),
                        database_scope: crate::upload::CloudKitDatabaseScope::Private,
                        zone_name: "PrimarySync".to_string(),
                        owner_record_name: None,
                        resource_field: "resJPEGFullRes".to_string(),
                        size_bytes: 10,
                        matched_heic_sha256: digest("new-heic"),
                    },
                },
        };
        super::super::apply::require_unique_active_replacement(&exact_one).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn production_quarantine_preflights_all_nine_before_atomic_moves_and_replays() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        struct ConfirmedAdapter;
        impl super::super::apply::RetiredReplacementDeleteAdapter for ConfirmedAdapter {
            type Error = ();

            fn lookup(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitDeleteStateLookupResult, ()> {
                Ok(crate::upload::CloudKitDeleteStateLookupResult {
                    confirmed_deleted: vec![crate::upload::CloudKitDeleteOutcome {
                        record_name: replacement.uploaded_asset_id.clone(),
                        record_change_tag: format!("confirmed-{}", replacement.asset_id),
                    }],
                    unconfirmed: vec![],
                })
            }

            fn resolve(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitUploadedHeicAsset, ()> {
                Ok(recovered_deleted_asset(replacement))
            }

            fn delete(
                &mut self,
                _replacement: &EvidenceRetiredReplacement,
                _resolved: &crate::upload::CloudKitUploadedHeicAsset,
            ) -> Result<crate::upload::CloudKitDeleteOutcome, ()> {
                unreachable!()
            }

            fn validate_original_active(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<CloudKitActiveAssetValidation, ()> {
                Ok(original_validation_for(replacement))
            }
        }

        let fixture = build_fixture();
        let mut evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-production-quarantine",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        super::super::apply::ensure_prepared(&writer, &mut evidence).unwrap();
        let cohort_dir = fixture
            .quarantine_root
            .join(evidence.audit().cohort_sha256.as_str());
        let guard = super::super::apply::preflight_quarantine_plan(
            &evidence,
            std::slice::from_ref(&fixture.quarantine_root),
            Some(super::super::LegacyUploadMigrationPhase::Prepared),
            30,
        )
        .unwrap();
        super::super::apply::ensure_delete_confirmed_with_quarantine_guard(
            &writer,
            &mut evidence,
            &mut ConfirmedAdapter,
            &guard,
        )
        .unwrap();

        let mut quarantine = super::super::apply::ProductionLegacyArtifactQuarantineAdapter::new(
            vec![fixture.quarantine_root.clone()],
            30,
        );
        assert!(cohort_dir.is_dir());
        assert_eq!(fs::read_dir(&cohort_dir).unwrap().count(), 0);

        super::super::apply::set_quarantine_rename_crash_after(3);
        assert_eq!(
            super::super::apply::ensure_quarantined(&writer, &mut evidence, &mut quarantine)
                .unwrap_err(),
            super::super::apply::LegacyUploadMigrationApplyError::Quarantine
        );
        assert_eq!(fs::read_dir(&cohort_dir).unwrap().count(), 3);

        let first =
            super::super::apply::ensure_quarantined(&writer, &mut evidence, &mut quarantine)
                .unwrap();
        assert!(first.changed);
        assert_eq!(fs::read_dir(&cohort_dir).unwrap().count(), 9);
        assert!(!fixture.artifact_root.join("asset-00.heic").exists());
        for reference in &fixture.document.reference_normalizations {
            let normalized =
                crate::monitor::reference_normalization_identity(&reference.reference_path, 30)
                    .unwrap();
            assert_eq!(normalized.orientation, 1);
            assert_eq!(normalized.width, reference.width);
            assert_eq!(normalized.height, reference.height);
            assert_eq!(
                normalized.decoded_pixel_sha256,
                reference.decoded_pixel_sha256
            );
            assert_ne!(
                sha256_bytes(&fs::read(&reference.reference_path).unwrap()),
                reference.file_sha256
            );
        }
        let quarantined_entries = fs::read_dir(&cohort_dir)
            .unwrap()
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        for reference in &fixture.document.reference_normalizations {
            assert_eq!(
                quarantined_entries
                    .iter()
                    .filter(|entry| {
                        let metadata = fs::metadata(entry.path()).unwrap();
                        metadata.ino() == reference.inode
                            && sha256_bytes(&fs::read(entry.path()).unwrap())
                                == reference.file_sha256
                    })
                    .count(),
                1,
                "each quarantined original must retain its exact inode and bytes"
            );
        }
        let replay =
            super::super::apply::ensure_quarantined(&writer, &mut evidence, &mut quarantine)
                .unwrap();
        assert!(!replay.changed);
        assert_eq!(fs::read_dir(cohort_dir).unwrap().count(), 9);

        let normalized_reference = &fixture.document.reference_normalizations[0].reference_path;
        fs::write(normalized_reference, b"tampered normalized reference").unwrap();
        assert!(matches!(
            super::super::apply::preflight_quarantine_plan(
                &evidence,
                std::slice::from_ref(&fixture.quarantine_root),
                Some(super::super::LegacyUploadMigrationPhase::Quarantined),
                30,
            ),
            Err(super::super::apply::LegacyUploadMigrationApplyError::Quarantine)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn missing_raw_input_fails_preflight_before_any_quarantine_move() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        let evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        fs::remove_file(&fixture.document.raw_inputs[9].path).unwrap();
        assert!(matches!(
            super::super::apply::preflight_quarantine_plan(
                &evidence,
                std::slice::from_ref(&fixture.quarantine_root),
                None,
                30,
            ),
            Err(super::super::apply::LegacyUploadMigrationApplyError::Quarantine)
        ));
        assert!(
            fixture
                .document
                .quarantine_members
                .iter()
                .all(|member| member.source_path.exists())
        );
        assert!(
            !fixture
                .quarantine_root
                .join(evidence.audit().cohort_sha256.as_str())
                .exists()
        );
    }

    #[cfg(unix)]
    #[test]
    fn pre_prepared_preflight_is_read_only_and_prepared_materialization_is_self_consistent() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        let mut evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let cohort_dir = fixture
            .quarantine_root
            .join(evidence.audit().cohort_sha256.as_str());
        let guard = super::super::apply::preflight_quarantine_plan(
            &evidence,
            std::slice::from_ref(&fixture.quarantine_root),
            None,
            30,
        )
        .unwrap();
        assert!(!cohort_dir.exists());
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-read-only-preflight",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        super::super::apply::ensure_prepared_with_quarantine_guard(&writer, &mut evidence, &guard)
            .unwrap();
        assert!(!cohort_dir.exists());
        let prepared_guard = super::super::apply::preflight_quarantine_plan(
            &evidence,
            std::slice::from_ref(&fixture.quarantine_root),
            Some(super::super::LegacyUploadMigrationPhase::Prepared),
            30,
        )
        .unwrap();
        prepared_guard.revalidate().unwrap();
        assert!(cohort_dir.is_dir());
        assert_eq!(fs::read_dir(&cohort_dir).unwrap().count(), 0);
        writer.release_writer_lease().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn prepared_materialization_replays_crash_between_mkdir_and_identity_result() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        let mut evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-materialization-mkdir-crash",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        super::super::apply::ensure_prepared(&writer, &mut evidence).unwrap();
        let cohort_dir = fixture
            .quarantine_root
            .join(evidence.audit().cohort_sha256.as_str());
        super::super::apply::set_quarantine_directory_crash_after_mkdir_before_result();
        let crash_error = match super::super::apply::preflight_quarantine_plan(
            &evidence,
            std::slice::from_ref(&fixture.quarantine_root),
            Some(super::super::LegacyUploadMigrationPhase::Prepared),
            30,
        ) {
            Ok(_) => panic!("injected mkdir/result crash must stop the attempt"),
            Err(error) => error,
        };
        assert_eq!(
            crash_error,
            super::super::apply::LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous
        );
        assert!(cohort_dir.is_dir());
        assert_eq!(fs::read_dir(&cohort_dir).unwrap().count(), 0);
        let guard = super::super::apply::preflight_quarantine_plan(
            &evidence,
            std::slice::from_ref(&fixture.quarantine_root),
            Some(super::super::LegacyUploadMigrationPhase::Prepared),
            30,
        )
        .unwrap();
        guard.revalidate().unwrap();
        assert!(cohort_dir.is_dir());
        writer.release_writer_lease().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn prepared_two_root_partial_create_rolls_back_and_replays_both_roots() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        let mut evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-materialization-two-root-replay",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        super::super::apply::ensure_prepared(&writer, &mut evidence).unwrap();
        let second_root = fs::canonicalize(fixture._temp.path())
            .unwrap()
            .join("second-materialization-root");
        fs::create_dir(&second_root).unwrap();
        fs::set_permissions(&second_root, fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(&second_root).unwrap();
        let second_sealed_root = super::super::LegacyUploadMigrationQuarantineRoot {
            canonical_path: second_root.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode() & 0o777,
        };
        append_test_quarantine_root(&mut evidence, second_sealed_root);
        let cohort = evidence.audit().cohort_sha256.clone();
        let first_cohort = fixture.quarantine_root.join(&cohort);
        let second_cohort = second_root.join(&cohort);
        let configured = vec![fixture.quarantine_root.clone(), second_root.clone()];
        super::super::apply::set_quarantine_directory_create_fail_root_ordinal(1);
        let error = match super::super::apply::preflight_quarantine_plan(
            &evidence,
            &configured,
            Some(super::super::LegacyUploadMigrationPhase::Prepared),
            30,
        ) {
            Ok(_) => panic!("second-root failure must roll back the partial materialization"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            super::super::apply::LegacyUploadMigrationApplyError::Quarantine
        );
        assert!(!first_cohort.exists());
        assert!(!second_cohort.exists());
        let replay = super::super::apply::preflight_quarantine_plan(
            &evidence,
            &configured,
            Some(super::super::LegacyUploadMigrationPhase::Prepared),
            30,
        )
        .unwrap();
        replay.revalidate().unwrap();
        assert!(first_cohort.is_dir());
        assert!(second_cohort.is_dir());
        assert_eq!(fs::read_dir(&first_cohort).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&second_cohort).unwrap().count(), 0);
        writer.release_writer_lease().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn prepared_two_root_late_unbound_target_preserves_target_and_rolls_back_owned_prefix() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        let mut evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-materialization-two-root-unbound-race",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        super::super::apply::ensure_prepared(&writer, &mut evidence).unwrap();
        let second_root = fs::canonicalize(fixture._temp.path())
            .unwrap()
            .join("second-racing-materialization-root");
        fs::create_dir(&second_root).unwrap();
        fs::set_permissions(&second_root, fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(&second_root).unwrap();
        let second_sealed_root = super::super::LegacyUploadMigrationQuarantineRoot {
            canonical_path: second_root.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode() & 0o777,
        };
        append_test_quarantine_root(&mut evidence, second_sealed_root);
        let cohort = evidence.audit().cohort_sha256.clone();
        let first_cohort = fixture.quarantine_root.join(&cohort);
        let second_cohort = second_root.join(&cohort);
        let marker = second_cohort.join("unbound-race-marker");
        let hook_cohort = second_cohort.clone();
        let hook_marker = marker.clone();
        super::super::apply::set_quarantine_directory_pre_create_hook(1, move || {
            fs::create_dir(&hook_cohort).unwrap();
            fs::set_permissions(&hook_cohort, fs::Permissions::from_mode(0o700)).unwrap();
            fs::write(&hook_marker, b"must remain").unwrap();
        });
        let source_paths = fixture
            .document
            .quarantine_members
            .iter()
            .map(|member| member.source_path.clone())
            .collect::<Vec<_>>();
        let error = match super::super::apply::preflight_quarantine_plan(
            &evidence,
            &[fixture.quarantine_root.clone(), second_root],
            Some(super::super::LegacyUploadMigrationPhase::Prepared),
            30,
        ) {
            Ok(_) => panic!("late unbound second-root target must fail closed"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            super::super::apply::LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous
        );
        assert!(!first_cohort.exists(), "owned prefix root must roll back");
        assert_eq!(fs::read(&marker).unwrap(), b"must remain");
        assert!(source_paths.iter().all(|path| path.exists()));
        writer.release_writer_lease().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn prepared_materialization_recreates_known_committed_directory_loss_without_ambiguity() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        let mut evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-materialization-known-absence",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        super::super::apply::ensure_prepared(&writer, &mut evidence).unwrap();
        let cohort_dir = fixture
            .quarantine_root
            .join(evidence.audit().cohort_sha256.as_str());
        let guard = super::super::apply::preflight_quarantine_plan(
            &evidence,
            std::slice::from_ref(&fixture.quarantine_root),
            Some(super::super::LegacyUploadMigrationPhase::Prepared),
            30,
        )
        .unwrap();
        guard.revalidate().unwrap();
        drop(guard);
        fs::remove_dir(&cohort_dir).unwrap();
        assert!(!cohort_dir.exists());
        let replay = super::super::apply::preflight_quarantine_plan(
            &evidence,
            std::slice::from_ref(&fixture.quarantine_root),
            Some(super::super::LegacyUploadMigrationPhase::Prepared),
            30,
        )
        .unwrap();
        replay.revalidate().unwrap();
        assert!(cohort_dir.is_dir());
        assert_eq!(fs::read_dir(&cohort_dir).unwrap().count(), 0);
        writer.release_writer_lease().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn prepared_materialization_rejects_unbound_and_nonempty_targets_without_removal() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        let mut evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-materialization-unbound-target",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        super::super::apply::ensure_prepared(&writer, &mut evidence).unwrap();
        let cohort_dir = fixture
            .quarantine_root
            .join(evidence.audit().cohort_sha256.as_str());
        fs::create_dir(&cohort_dir).unwrap();
        fs::set_permissions(&cohort_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let marker = cohort_dir.join("unbound-marker");
        fs::write(&marker, b"must remain").unwrap();
        let error = match super::super::apply::preflight_quarantine_plan(
            &evidence,
            std::slice::from_ref(&fixture.quarantine_root),
            Some(super::super::LegacyUploadMigrationPhase::Prepared),
            30,
        ) {
            Ok(_) => panic!("unbound nonempty target must fail closed"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            super::super::apply::LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous
        );
        assert_eq!(fs::read(&marker).unwrap(), b"must remain");
        writer.release_writer_lease().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn prepared_materialization_rejects_impossible_commit_and_removal_progress_combinations() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        {
            let fixture = build_fixture();
            let mut evidence =
                load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
            let writer = AssetStateStore::open_writer(
                &fixture.manifest_path,
                "legacy-upload-materialization-invalid-commit",
                std::time::Duration::from_secs(30),
            )
            .unwrap();
            super::super::apply::ensure_prepared(&writer, &mut evidence).unwrap();
            let guard = super::super::apply::preflight_quarantine_plan(
                &evidence,
                std::slice::from_ref(&fixture.quarantine_root),
                Some(super::super::LegacyUploadMigrationPhase::Prepared),
                30,
            )
            .unwrap();
            drop(guard);
            let progress_root = fs::canonicalize(fixture._temp.path()).unwrap();
            let committed_path = fs::read_dir(&progress_root)
                .unwrap()
                .map(Result::unwrap)
                .map(|entry| entry.path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .ends_with(".committed.json")
                })
                .unwrap();
            let committed = fs::read_to_string(&committed_path).unwrap();
            assert!(committed.contains("\"durability\": \"synced\""));
            fs::write(
                &committed_path,
                committed.replace(
                    "\"durability\": \"synced\"",
                    "\"durability\": \"not_required\"",
                ),
            )
            .unwrap();
            let error = match super::super::apply::preflight_quarantine_plan(
                &evidence,
                std::slice::from_ref(&fixture.quarantine_root),
                Some(super::super::LegacyUploadMigrationPhase::Prepared),
                30,
            ) {
                Ok(_) => panic!("impossible creation commit durability must fail closed"),
                Err(error) => error,
            };
            assert_eq!(
                error,
                super::super::apply::LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous
            );
            writer.release_writer_lease().unwrap();
        }
        {
            let fixture = build_fixture();
            let mut evidence =
                load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
            let writer = AssetStateStore::open_writer(
                &fixture.manifest_path,
                "legacy-upload-materialization-invalid-removal",
                std::time::Duration::from_secs(30),
            )
            .unwrap();
            super::super::apply::ensure_prepared(&writer, &mut evidence).unwrap();
            super::super::apply::set_quarantine_directory_create_fail_after_mkdir();
            let initial_error = match super::super::apply::preflight_quarantine_plan(
                &evidence,
                std::slice::from_ref(&fixture.quarantine_root),
                Some(super::super::LegacyUploadMigrationPhase::Prepared),
                30,
            ) {
                Ok(_) => panic!("injected creation failure must roll back"),
                Err(error) => error,
            };
            assert_eq!(
                initial_error,
                super::super::apply::LegacyUploadMigrationApplyError::Quarantine
            );
            let progress_root = fs::canonicalize(fixture._temp.path()).unwrap();
            let removal_done_path = fs::read_dir(&progress_root)
                .unwrap()
                .map(Result::unwrap)
                .map(|entry| entry.path())
                .find(|path| {
                    path.file_name()
                        .unwrap()
                        .to_string_lossy()
                        .ends_with(".remove.done.json")
                })
                .unwrap();
            let removal_done = fs::read_to_string(&removal_done_path).unwrap();
            assert!(removal_done.contains("\"durability\": \"synced\""));
            fs::write(
                &removal_done_path,
                removal_done.replace(
                    "\"durability\": \"synced\"",
                    "\"durability\": \"not_required\"",
                ),
            )
            .unwrap();
            let error = match super::super::apply::preflight_quarantine_plan(
                &evidence,
                std::slice::from_ref(&fixture.quarantine_root),
                Some(super::super::LegacyUploadMigrationPhase::Prepared),
                30,
            ) {
                Ok(_) => panic!("impossible removal completion durability must fail closed"),
                Err(error) => error,
            };
            assert_eq!(
                error,
                super::super::apply::LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous
            );
            writer.release_writer_lease().unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn prepared_directory_creation_rolls_back_or_reports_ambiguous_residue() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        let mut evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-create-rollback",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        super::super::apply::ensure_prepared(&writer, &mut evidence).unwrap();
        let cohort_dir = fixture
            .quarantine_root
            .join(evidence.audit().cohort_sha256.as_str());
        super::super::apply::set_quarantine_directory_create_fail_after_mkdir();
        let rollback_error = match super::super::apply::preflight_quarantine_plan(
            &evidence,
            std::slice::from_ref(&fixture.quarantine_root),
            Some(super::super::LegacyUploadMigrationPhase::Prepared),
            30,
        ) {
            Ok(_) => panic!("injected creation failure must fail"),
            Err(error) => error,
        };
        assert_eq!(
            rollback_error,
            super::super::apply::LegacyUploadMigrationApplyError::Quarantine
        );
        assert!(!cohort_dir.exists());
        super::super::apply::set_quarantine_directory_create_fail_after_mkdir();
        super::super::apply::set_quarantine_directory_removal_crash_point(
            super::super::apply::QuarantineDirectoryRemovalCrashPoint::BeforeUnlink,
        );
        let incomplete_error = match super::super::apply::preflight_quarantine_plan(
            &evidence,
            std::slice::from_ref(&fixture.quarantine_root),
            Some(super::super::LegacyUploadMigrationPhase::Prepared),
            30,
        ) {
            Ok(_) => panic!("injected rollback failure must fail"),
            Err(error) => error,
        };
        assert_eq!(
            incomplete_error,
            super::super::apply::LegacyUploadMigrationApplyError::QuarantineRollbackIncomplete
        );
        assert!(cohort_dir.is_dir());
        assert_eq!(fs::read_dir(&cohort_dir).unwrap().count(), 0);
        let recovered = super::super::apply::preflight_quarantine_plan(
            &evidence,
            std::slice::from_ref(&fixture.quarantine_root),
            Some(super::super::LegacyUploadMigrationPhase::Prepared),
            30,
        )
        .unwrap();
        recovered.revalidate().unwrap();
        writer.release_writer_lease().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn missing_cohort_after_delete_confirmed_is_drift_not_materialization() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        let mut evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-late-missing-cohort",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        super::super::apply::ensure_prepared(&writer, &mut evidence).unwrap();
        let cohort_dir = fixture
            .quarantine_root
            .join(evidence.audit().cohort_sha256.as_str());
        let error = match super::super::apply::preflight_quarantine_plan(
            &evidence,
            std::slice::from_ref(&fixture.quarantine_root),
            Some(super::super::LegacyUploadMigrationPhase::DeleteConfirmed),
            30,
        ) {
            Ok(_) => panic!("post-delete missing cohort must fail closed"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            super::super::apply::LegacyUploadMigrationApplyError::Quarantine
        );
        assert!(!cohort_dir.exists());
        writer.release_writer_lease().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn post_create_name_replacement_is_never_deleted_as_rollback() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        let mut evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-created-directory-race",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        super::super::apply::ensure_prepared(&writer, &mut evidence).unwrap();
        let cohort_dir = fixture
            .quarantine_root
            .join(evidence.audit().cohort_sha256.as_str());
        let moved_created = fixture.quarantine_root.join("held-created-directory");
        let hook_cohort = cohort_dir.clone();
        let hook_moved = moved_created.clone();
        super::super::apply::set_quarantine_directory_post_open_hook(move || {
            fs::rename(&hook_cohort, &hook_moved).unwrap();
            fs::create_dir(&hook_cohort).unwrap();
            fs::set_permissions(&hook_cohort, fs::Permissions::from_mode(0o700)).unwrap();
        });
        super::super::apply::set_quarantine_directory_create_fail_after_mkdir();
        let error = match super::super::apply::preflight_quarantine_plan(
            &evidence,
            std::slice::from_ref(&fixture.quarantine_root),
            Some(super::super::LegacyUploadMigrationPhase::Prepared),
            30,
        ) {
            Ok(_) => panic!("replaced post-create name must fail closed"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            super::super::apply::LegacyUploadMigrationApplyError::QuarantineRollbackAmbiguous
        );
        assert!(cohort_dir.is_dir(), "replacement must not be unlinked");
        assert!(
            moved_created.is_dir(),
            "held created directory remains inspectable"
        );
        assert_ne!(
            fs::metadata(&cohort_dir).unwrap().ino(),
            fs::metadata(&moved_created).unwrap().ino()
        );
        writer.release_writer_lease().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn exact_empty_residual_audit_and_recovery_are_sealed_strict_and_idempotent() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        let evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let cohort_dir = fixture
            .quarantine_root
            .join(evidence.audit().cohort_sha256.as_str());
        fs::create_dir(&cohort_dir).unwrap();
        fs::set_permissions(&cohort_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let private_root = fs::canonicalize(fixture._temp.path()).unwrap();
        let audit_path = private_root.join("residual-audit.json");
        let audit_request = super::super::apply::LegacyUploadQuarantineResidualAuditRequest {
            evidence: fixture.request.clone(),
            quarantine_roots: vec![fixture.quarantine_root.clone()],
            output_path: audit_path.clone(),
        };
        let report =
            super::super::apply::audit_legacy_upload_quarantine_residuals(&audit_request).unwrap();
        assert_eq!(report.directory_count, 1);
        assert_eq!(fs::metadata(&audit_path).unwrap().mode() & 0o777, 0o600);
        let audit_bytes = fs::read(&audit_path).unwrap();
        assert_eq!(sha256_bytes(&audit_bytes), report.audit_sha256);

        let unknown_path = private_root.join("unknown-audit.json");
        let mut unknown = audit_bytes.clone();
        unknown.splice(1..1, b"\"unknown\":true,".iter().copied());
        fs::write(&unknown_path, &unknown).unwrap();
        fs::set_permissions(&unknown_path, fs::Permissions::from_mode(0o600)).unwrap();
        let duplicate_path = private_root.join("duplicate-audit.json");
        let duplicate = String::from_utf8(audit_bytes.clone()).unwrap().replacen(
            "\"schema_version\": 1,",
            "\"schema_version\": 1,\n  \"schema_version\": 1,",
            1,
        );
        fs::write(&duplicate_path, duplicate.as_bytes()).unwrap();
        fs::set_permissions(&duplicate_path, fs::Permissions::from_mode(0o600)).unwrap();
        let wrong_mode_path = private_root.join("wrong-mode-audit.json");
        fs::write(&wrong_mode_path, &audit_bytes).unwrap();
        fs::set_permissions(&wrong_mode_path, fs::Permissions::from_mode(0o640)).unwrap();
        let drift_path = private_root.join("drift-audit.json");
        let mut drift: Value = serde_json::from_slice(&audit_bytes).unwrap();
        let drift_device = drift["directories"][0]["directory"]["device"]
            .as_u64()
            .unwrap()
            + 1;
        drift["directories"][0]["directory"]["device"] = json!(drift_device);
        let drift_bytes = serde_json::to_vec_pretty(&drift).unwrap();
        fs::write(&drift_path, &drift_bytes).unwrap();
        fs::set_permissions(&drift_path, fs::Permissions::from_mode(0o600)).unwrap();

        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-residual-recovery",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        for (path, bytes) in [
            (&unknown_path, unknown.as_slice()),
            (&duplicate_path, duplicate.as_bytes()),
            (&wrong_mode_path, audit_bytes.as_slice()),
            (&drift_path, drift_bytes.as_slice()),
        ] {
            let request = super::super::apply::LegacyUploadQuarantineResidualRecoveryRequest {
                evidence: fixture.request.clone(),
                quarantine_roots: vec![fixture.quarantine_root.clone()],
                audit_path: path.clone(),
                expected_audit_sha256: sha256_bytes(bytes),
            };
            assert_eq!(
                super::super::apply::recover_legacy_upload_quarantine_residuals(&writer, &request,)
                    .unwrap_err(),
                super::super::apply::LegacyUploadMigrationApplyError::QuarantineResidual
            );
            assert!(cohort_dir.is_dir());
        }
        let recovery_request = super::super::apply::LegacyUploadQuarantineResidualRecoveryRequest {
            evidence: fixture.request.clone(),
            quarantine_roots: vec![fixture.quarantine_root.clone()],
            audit_path,
            expected_audit_sha256: report.audit_sha256,
        };
        let recovered = super::super::apply::recover_legacy_upload_quarantine_residuals(
            &writer,
            &recovery_request,
        )
        .unwrap();
        assert_eq!(recovered.removed_directory_count, 1);
        assert_eq!(recovered.remote_calls, 0);
        assert!(!cohort_dir.exists());
        let replay = super::super::apply::recover_legacy_upload_quarantine_residuals(
            &writer,
            &recovery_request,
        )
        .unwrap();
        assert_eq!(replay.status, "already_absent");
        assert_eq!(replay.removed_directory_count, 0);
        assert_eq!(replay.remote_calls, 0);
        writer.release_writer_lease().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn pre_prepared_residual_stops_apply_before_state_moves_or_remote_clients() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        let evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let cohort_dir = fixture
            .quarantine_root
            .join(evidence.audit().cohort_sha256.as_str());
        fs::create_dir(&cohort_dir).unwrap();
        fs::set_permissions(&cohort_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let source_paths = fixture
            .document
            .quarantine_members
            .iter()
            .map(|member| member.source_path.clone())
            .collect::<Vec<_>>();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-residual-stops-apply",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let before = writer.load().unwrap();
        let error = super::super::apply::apply_legacy_uploaded_heic_migration(
            &writer,
            &super::super::apply::LegacyUploadMigrationProductionRequest {
                evidence: fixture.request.clone(),
                quarantine_roots: vec![fixture.quarantine_root.clone()],
                heic_output_dir: fixture.artifact_root.clone(),
                mirror_root: fixture.artifact_root.join("mirror-must-not-open"),
                upload_session_path: PathBuf::from("/must-not-open-upload-session"),
                delete_session_path: PathBuf::from("/must-not-open-delete-session"),
                jobs: 1,
                heic_quality: 90,
                conversion_tool_version: None,
                capture_tolerance_seconds: 60,
                cloudkit_start_rank: 0,
                cloudkit_page_size: 100,
                cloudkit_max_pages: 10,
                heic_verify_timeout_seconds: 30,
            },
        )
        .unwrap_err();
        assert_eq!(
            error,
            super::super::apply::LegacyUploadMigrationApplyError::QuarantineResidual
        );
        assert_eq!(writer.load().unwrap(), before);
        assert!(source_paths.iter().all(|path| path.exists()));
        assert_eq!(fs::read_dir(&cohort_dir).unwrap().count(), 0);
        writer.release_writer_lease().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn residual_removal_failure_after_unlink_reports_explicit_ambiguity() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        let evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let cohort_dir = fixture
            .quarantine_root
            .join(evidence.audit().cohort_sha256.as_str());
        fs::create_dir(&cohort_dir).unwrap();
        fs::set_permissions(&cohort_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let audit_path = fs::canonicalize(fixture._temp.path())
            .unwrap()
            .join("residual-crash-audit.json");
        let report = super::super::apply::audit_legacy_upload_quarantine_residuals(
            &super::super::apply::LegacyUploadQuarantineResidualAuditRequest {
                evidence: fixture.request.clone(),
                quarantine_roots: vec![fixture.quarantine_root.clone()],
                output_path: audit_path.clone(),
            },
        )
        .unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-residual-ambiguous",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        super::super::apply::set_quarantine_directory_removal_crash_point(
            super::super::apply::QuarantineDirectoryRemovalCrashPoint::AfterUnlink,
        );
        assert_eq!(
            super::super::apply::recover_legacy_upload_quarantine_residuals(
                &writer,
                &super::super::apply::LegacyUploadQuarantineResidualRecoveryRequest {
                    evidence: fixture.request.clone(),
                    quarantine_roots: vec![fixture.quarantine_root.clone()],
                    audit_path,
                    expected_audit_sha256: report.audit_sha256,
                },
            )
            .unwrap_err(),
            super::super::apply::LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous
        );
        assert!(!cohort_dir.exists());
        writer.release_writer_lease().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn absent_residual_without_exact_progress_is_never_inferred_as_recovered() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        let evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let cohort_dir = fixture
            .quarantine_root
            .join(evidence.audit().cohort_sha256.as_str());
        fs::create_dir(&cohort_dir).unwrap();
        fs::set_permissions(&cohort_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let audit_path = fs::canonicalize(fixture._temp.path())
            .unwrap()
            .join("absent-without-progress-audit.json");
        let report = super::super::apply::audit_legacy_upload_quarantine_residuals(
            &super::super::apply::LegacyUploadQuarantineResidualAuditRequest {
                evidence: fixture.request.clone(),
                quarantine_roots: vec![fixture.quarantine_root.clone()],
                output_path: audit_path.clone(),
            },
        )
        .unwrap();
        fs::remove_dir(&cohort_dir).unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-absent-no-progress",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(
            super::super::apply::recover_legacy_upload_quarantine_residuals(
                &writer,
                &super::super::apply::LegacyUploadQuarantineResidualRecoveryRequest {
                    evidence: fixture.request.clone(),
                    quarantine_roots: vec![fixture.quarantine_root.clone()],
                    audit_path,
                    expected_audit_sha256: report.audit_sha256,
                },
            )
            .unwrap_err(),
            super::super::apply::LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous
        );
        writer.release_writer_lease().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn two_root_residual_recovery_resumes_after_first_unlink_from_durable_progress() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        let mut evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let private_root = fs::canonicalize(fixture._temp.path()).unwrap();
        let second_root_path = private_root.join("second-progress-root");
        fs::create_dir(&second_root_path).unwrap();
        fs::set_permissions(&second_root_path, fs::Permissions::from_mode(0o700)).unwrap();
        let cohort_name = CString::new(evidence.audit().cohort_sha256.as_bytes()).unwrap();
        let cohort_paths = [
            fixture
                .quarantine_root
                .join(evidence.audit().cohort_sha256.as_str()),
            second_root_path.join(evidence.audit().cohort_sha256.as_str()),
        ];
        for path in &cohort_paths {
            fs::create_dir(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let roots = [
            fs::File::open(&fixture.quarantine_root).unwrap(),
            fs::File::open(&second_root_path).unwrap(),
        ];
        let cohorts = [
            fs::File::open(&cohort_paths[0]).unwrap(),
            fs::File::open(&cohort_paths[1]).unwrap(),
        ];
        let directories = (0..2)
            .map(
                |index| super::super::apply::QuarantineResidualDirectoryAudit {
                    path: cohort_paths[index].clone(),
                    root: super::super::apply::quarantine_residual_root_identity(&roots[index])
                        .unwrap(),
                    directory: super::super::apply::quarantine_directory_identity(&cohorts[index])
                        .unwrap(),
                    empty: true,
                },
            )
            .collect::<Vec<_>>();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "legacy-upload-two-root-progress",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        let manifest_sha256 =
            super::super::apply::migration_manifest_sha256(&writer.load().unwrap()).unwrap();
        let document = super::super::apply::QuarantineResidualAuditDocument {
            schema_version: 1,
            evidence_sha256: evidence.audit().evidence_sha256.clone(),
            cohort_sha256: evidence.audit().cohort_sha256.clone(),
            manifest_sha256: manifest_sha256.clone(),
            quarantine_plan_sha256: evidence.quarantine_plan().plan_sha256.clone(),
            directories,
        };
        let mut audit_bytes = serde_json::to_vec_pretty(&document).unwrap();
        audit_bytes.push(b'\n');
        let audit_sha256 = sha256_bytes(&audit_bytes);
        let audit_path = private_root.join("two-root-progress-audit.json");
        fs::write(&audit_path, &audit_bytes).unwrap();
        fs::set_permissions(&audit_path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut sealed_audit =
            super::super::apply::read_sealed_quarantine_residual_audit(&audit_path).unwrap();

        super::super::apply::set_quarantine_directory_removal_crash_point(
            super::super::apply::QuarantineDirectoryRemovalCrashPoint::AfterUnlink,
        );
        assert_eq!(
            super::super::apply::recover_residual_directories_with_progress(
                &mut evidence,
                &mut sealed_audit,
                super::super::apply::ResidualRecoveryProgressRequest {
                    state_store: &writer,
                    manifest_sha256: &manifest_sha256,
                    audit_path: &audit_path,
                    audit_sha256: &audit_sha256,
                    document: &document,
                    roots: &roots,
                    cohort_name: &cohort_name,
                },
            )
            .unwrap_err(),
            super::super::apply::LegacyUploadMigrationApplyError::QuarantineResidualAmbiguous
        );
        assert!(!cohort_paths[0].exists());
        assert!(cohort_paths[1].is_dir());

        let resumed = super::super::apply::recover_residual_directories_with_progress(
            &mut evidence,
            &mut sealed_audit,
            super::super::apply::ResidualRecoveryProgressRequest {
                state_store: &writer,
                manifest_sha256: &manifest_sha256,
                audit_path: &audit_path,
                audit_sha256: &audit_sha256,
                document: &document,
                roots: &roots,
                cohort_name: &cohort_name,
            },
        )
        .unwrap();
        assert_eq!(resumed, 1);
        assert!(cohort_paths.iter().all(|path| !path.exists()));
        let replay = super::super::apply::recover_residual_directories_with_progress(
            &mut evidence,
            &mut sealed_audit,
            super::super::apply::ResidualRecoveryProgressRequest {
                state_store: &writer,
                manifest_sha256: &manifest_sha256,
                audit_path: &audit_path,
                audit_sha256: &audit_sha256,
                document: &document,
                roots: &roots,
                cohort_name: &cohort_name,
            },
        )
        .unwrap();
        assert_eq!(replay, 0);
        let progress_files = fs::read_dir(&private_root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&format!(".icloudpd-quarantine-recovery-{audit_sha256}."))
            })
            .collect::<Vec<_>>();
        assert_eq!(progress_files.len(), 5);
        assert!(
            progress_files
                .iter()
                .all(|entry| { fs::metadata(entry.path()).unwrap().mode() & 0o777 == 0o600 })
        );
        writer.release_writer_lease().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn second_device_root_drift_fails_before_any_cohort_or_source_move() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut fixture = build_fixture();
        let second_root = fixture._temp.path().join("second-quarantine");
        fs::create_dir(&second_root).unwrap();
        fs::set_permissions(&second_root, fs::Permissions::from_mode(0o700)).unwrap();
        let second_metadata = fs::metadata(&second_root).unwrap();
        let fake_device = second_metadata.dev().checked_add(10_000).unwrap();
        fixture
            .document
            .quarantine_roots
            .push(EvidenceQuarantineRoot {
                canonical_path: fs::canonicalize(&second_root).unwrap(),
                device: fake_device,
                inode: second_metadata.ino(),
                owner: second_metadata.uid(),
                mode: second_metadata.mode() & 0o777,
            });
        fixture
            .document
            .quarantine_roots
            .sort_by_key(|root| root.device);
        let moved_member = fixture
            .document
            .quarantine_members
            .iter_mut()
            .find(|member| member.kind == LegacyUploadMigrationQuarantineKind::Final)
            .unwrap();
        moved_member.source.device = fake_device;
        moved_member.root_device = fake_device;
        let source_paths = fixture
            .document
            .quarantine_members
            .iter()
            .map(|member| member.source_path.clone())
            .collect::<Vec<_>>();
        write_document(&mut fixture);

        let evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        assert!(matches!(
            super::super::apply::preflight_quarantine_plan(
                &evidence,
                &[fixture.quarantine_root.clone(), second_root.clone()],
                None,
                30,
            ),
            Err(super::super::apply::LegacyUploadMigrationApplyError::Quarantine)
        ));
        assert!(source_paths.iter().all(|path| path.exists()));
        assert!(
            !fixture
                .quarantine_root
                .join(evidence.audit().cohort_sha256.as_str())
                .exists()
        );
        assert!(
            !second_root
                .join(evidence.audit().cohort_sha256.as_str())
                .exists()
        );
    }

    #[cfg(unix)]
    #[test]
    fn injected_two_device_partial_quarantine_resumes_one_aggregate_journal() {
        struct ConfirmedAdapter;
        impl super::super::apply::RetiredReplacementDeleteAdapter for ConfirmedAdapter {
            type Error = ();

            fn lookup(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitDeleteStateLookupResult, ()> {
                Ok(crate::upload::CloudKitDeleteStateLookupResult {
                    confirmed_deleted: vec![crate::upload::CloudKitDeleteOutcome {
                        record_name: replacement.uploaded_asset_id.clone(),
                        record_change_tag: format!("confirmed-{}", replacement.asset_id),
                    }],
                    unconfirmed: vec![],
                })
            }

            fn resolve(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitUploadedHeicAsset, ()> {
                Ok(recovered_deleted_asset(replacement))
            }

            fn delete(
                &mut self,
                _replacement: &EvidenceRetiredReplacement,
                _resolved: &crate::upload::CloudKitUploadedHeicAsset,
            ) -> Result<crate::upload::CloudKitDeleteOutcome, ()> {
                unreachable!()
            }

            fn validate_original_active(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<CloudKitActiveAssetValidation, ()> {
                Ok(original_validation_for(replacement))
            }
        }

        #[derive(Default)]
        struct InjectedAdapter {
            moved: BTreeSet<(String, LegacyUploadMigrationQuarantineKind)>,
            fail_once: bool,
        }
        impl super::super::apply::LegacyArtifactQuarantineAdapter for InjectedAdapter {
            type Error = ();

            fn quarantine_and_normalize(
                &mut self,
                evidence: &ValidatedLegacyUploadEvidence,
                _manifest: &Manifest,
            ) -> Result<super::super::apply::QuarantineBatchReceipt, ()> {
                let plan = evidence.quarantine_plan();
                if plan.roots.len() != 2
                    || plan.members.iter().any(|member| {
                        !plan
                            .roots
                            .iter()
                            .any(|root| root.device == member.root_device)
                    })
                {
                    return Err(());
                }
                for member in &plan.members {
                    self.moved.insert((member.asset_id.clone(), member.kind));
                    if self.fail_once && self.moved.len() == 3 {
                        self.fail_once = false;
                        return Err(());
                    }
                }
                Ok(super::super::apply::QuarantineBatchReceipt {
                    schema_version: 2,
                    cohort_sha256: evidence.audit().cohort_sha256.clone(),
                    canonical_root_identity_sha256: canonical_digest(&plan.roots).unwrap(),
                    target_set_sha256: canonical_digest(&self.moved).unwrap(),
                    target_count: self.moved.len() as u64,
                    normalized_reference_count: 5,
                })
            }
        }

        let mut fixture = build_fixture();
        let second_root = fixture._temp.path().join("injected-second-root");
        fs::create_dir(&second_root).unwrap();
        fs::set_permissions(&second_root, fs::Permissions::from_mode(0o700)).unwrap();
        let metadata = fs::metadata(&second_root).unwrap();
        let second_device = metadata.dev().checked_add(20_000).unwrap();
        fixture
            .document
            .quarantine_roots
            .push(EvidenceQuarantineRoot {
                canonical_path: fs::canonicalize(&second_root).unwrap(),
                device: second_device,
                inode: metadata.ino(),
                owner: metadata.uid(),
                mode: metadata.mode() & 0o777,
            });
        fixture
            .document
            .quarantine_roots
            .sort_by_key(|root| root.device);
        for member in fixture
            .document
            .quarantine_members
            .iter_mut()
            .filter(|member| member.kind == LegacyUploadMigrationQuarantineKind::Final)
        {
            member.source.device = second_device;
            member.root_device = second_device;
        }
        write_document(&mut fixture);

        let mut evidence = load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
        let writer = AssetStateStore::open_writer(
            &fixture.manifest_path,
            "injected-two-device-quarantine",
            std::time::Duration::from_secs(30),
        )
        .unwrap();
        super::super::apply::ensure_prepared(&writer, &mut evidence).unwrap();
        super::super::apply::ensure_delete_confirmed(&writer, &mut evidence, &mut ConfirmedAdapter)
            .unwrap();
        let mut adapter = InjectedAdapter {
            fail_once: true,
            ..InjectedAdapter::default()
        };
        assert!(
            super::super::apply::ensure_quarantined(&writer, &mut evidence, &mut adapter).is_err()
        );
        assert_eq!(adapter.moved.len(), 3);
        let after_crash = writer.load().unwrap();
        for asset_id in evidence.replacement_asset_ids() {
            let journal = super::super::validate_legacy_upload_migration_record(
                after_crash.get(asset_id).unwrap(),
            )
            .unwrap();
            assert_eq!(
                journal.entries.last().unwrap().phase,
                super::super::LegacyUploadMigrationPhase::DeleteConfirmed
            );
        }
        assert!(
            super::super::apply::ensure_quarantined(&writer, &mut evidence, &mut adapter)
                .unwrap()
                .changed
        );
        assert_eq!(adapter.moved.len(), 9);
        let recovered = writer.load().unwrap();
        for asset_id in evidence.replacement_asset_ids() {
            let journal = super::super::validate_legacy_upload_migration_record(
                recovered.get(asset_id).unwrap(),
            )
            .unwrap();
            assert_eq!(
                journal.entries.last().unwrap().phase,
                super::super::LegacyUploadMigrationPhase::Quarantined
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn production_normalization_resumes_every_deterministic_temp_crash_state() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        struct ConfirmedAdapter;
        impl super::super::apply::RetiredReplacementDeleteAdapter for ConfirmedAdapter {
            type Error = ();

            fn lookup(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitDeleteStateLookupResult, ()> {
                Ok(crate::upload::CloudKitDeleteStateLookupResult {
                    confirmed_deleted: vec![crate::upload::CloudKitDeleteOutcome {
                        record_name: replacement.uploaded_asset_id.clone(),
                        record_change_tag: format!("confirmed-{}", replacement.asset_id),
                    }],
                    unconfirmed: vec![],
                })
            }

            fn resolve(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<crate::upload::CloudKitUploadedHeicAsset, ()> {
                Ok(recovered_deleted_asset(replacement))
            }

            fn delete(
                &mut self,
                _replacement: &EvidenceRetiredReplacement,
                _resolved: &crate::upload::CloudKitUploadedHeicAsset,
            ) -> Result<crate::upload::CloudKitDeleteOutcome, ()> {
                unreachable!()
            }

            fn validate_original_active(
                &mut self,
                replacement: &EvidenceRetiredReplacement,
            ) -> Result<CloudKitActiveAssetValidation, ()> {
                Ok(original_validation_for(replacement))
            }
        }

        use super::super::apply::ReferenceNormalizationCrashPoint;
        for crash_point in [
            ReferenceNormalizationCrashPoint::AfterCreate,
            ReferenceNormalizationCrashPoint::AfterCopy,
            ReferenceNormalizationCrashPoint::AfterNormalize,
            ReferenceNormalizationCrashPoint::BeforeRename,
            ReferenceNormalizationCrashPoint::AfterRename,
        ] {
            let fixture = build_fixture();
            let reference = &fixture.document.reference_normalizations[0];
            let original_bytes = fs::read(&reference.reference_path).unwrap();
            let original_inode = fs::metadata(&reference.reference_path).unwrap().ino();
            let mut evidence =
                load_validated_legacy_uploaded_heic_evidence(&fixture.request).unwrap();
            let writer = AssetStateStore::open_writer(
                &fixture.manifest_path,
                format!("normalization-crash-{crash_point:?}"),
                std::time::Duration::from_secs(30),
            )
            .unwrap();
            super::super::apply::ensure_prepared(&writer, &mut evidence).unwrap();
            let guard = super::super::apply::preflight_quarantine_plan(
                &evidence,
                std::slice::from_ref(&fixture.quarantine_root),
                Some(super::super::LegacyUploadMigrationPhase::Prepared),
                30,
            )
            .unwrap();
            super::super::apply::ensure_delete_confirmed_with_quarantine_guard(
                &writer,
                &mut evidence,
                &mut ConfirmedAdapter,
                &guard,
            )
            .unwrap();
            let mut quarantine =
                super::super::apply::ProductionLegacyArtifactQuarantineAdapter::new(
                    vec![fixture.quarantine_root.clone()],
                    30,
                );
            super::super::apply::set_reference_normalization_crash_point(crash_point);
            assert!(
                super::super::apply::ensure_quarantined(&writer, &mut evidence, &mut quarantine,)
                    .is_err()
            );

            let reserved_temps = fs::read_dir(&fixture.artifact_root)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".legacy-upload-reference-normalize.")
                })
                .collect::<Vec<_>>();
            let after_rename = crash_point == ReferenceNormalizationCrashPoint::AfterRename;
            assert_eq!(reserved_temps.len(), usize::from(!after_rename));
            if let Some(temp) = reserved_temps.first() {
                if crash_point == ReferenceNormalizationCrashPoint::AfterCreate {
                    assert_eq!(fs::metadata(temp.path()).unwrap().len(), 0);
                    let unsafe_link = fixture.artifact_root.join("unsafe-temp-hardlink");
                    fs::hard_link(temp.path(), &unsafe_link).unwrap();
                    assert!(
                        super::super::apply::ensure_quarantined(
                            &writer,
                            &mut evidence,
                            &mut quarantine,
                        )
                        .is_err(),
                        "unsafe reserved temp metadata must fail closed"
                    );
                    assert!(
                        temp.path().exists(),
                        "unsafe temp must not be silently deleted"
                    );
                    fs::remove_file(unsafe_link).unwrap();
                } else {
                    let probe =
                        crate::monitor::reference_normalization_identity(&temp.path(), 30).unwrap();
                    assert_eq!(
                        probe.orientation,
                        if crash_point == ReferenceNormalizationCrashPoint::AfterCopy {
                            reference.orientation
                        } else {
                            1
                        }
                    );
                }
            }

            let resumed =
                super::super::apply::ensure_quarantined(&writer, &mut evidence, &mut quarantine)
                    .unwrap();
            assert!(resumed.changed);
            assert_eq!(
                crate::monitor::reference_normalization_identity(&reference.reference_path, 30)
                    .unwrap()
                    .orientation,
                1
            );
            assert_eq!(
                fs::read_dir(&fixture.artifact_root)
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter(|entry| entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".legacy-upload-reference-normalize."))
                    .count(),
                0
            );
            let cohort_dir = fixture
                .quarantine_root
                .join(evidence.audit().cohort_sha256.as_str());
            let quarantined_original = fs::read_dir(cohort_dir)
                .unwrap()
                .filter_map(Result::ok)
                .find(|entry| fs::metadata(entry.path()).unwrap().ino() == original_inode)
                .expect("the exact original inode must remain quarantined");
            assert_eq!(
                fs::read(quarantined_original.path()).unwrap(),
                original_bytes
            );
        }
    }

    fn assert_post_read_change_rejected(fixture: &Fixture, mutation: impl FnOnce() + 'static) {
        let checkpoint_before = fs::read(&fixture.manifest_path).unwrap();
        set_evidence_post_read_hook(mutation);
        assert_eq!(
            audit_legacy_uploaded_heic_evidence(&fixture.request)
                .unwrap_err()
                .category(),
            "evidence_changed"
        );
        assert_eq!(fs::read(&fixture.manifest_path).unwrap(), checkpoint_before);
    }

    #[test]
    fn descriptor_reverification_rejects_same_inode_overwrite() {
        let fixture = build_fixture();
        let path = fixture.evidence_path.clone();
        assert_post_read_change_rejected(&fixture, move || {
            let mut bytes = fs::read(&path).unwrap();
            bytes[0] ^= 1;
            OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap()
                .write_all(&bytes)
                .unwrap();
        });
    }

    #[test]
    fn descriptor_reverification_rejects_same_inode_truncate_and_rewrite() {
        let fixture = build_fixture();
        let path = fixture.evidence_path.clone();
        assert_post_read_change_rejected(&fixture, move || {
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(path)
                .unwrap()
                .write_all(b"{}")
                .unwrap();
        });
    }

    #[test]
    fn descriptor_reverification_rejects_same_inode_chmod() {
        let fixture = build_fixture();
        let path = fixture.evidence_path.clone();
        assert_post_read_change_rejected(&fixture, move || {
            fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
        });
    }

    #[test]
    fn descriptor_reverification_rejects_same_inode_link_count_change() {
        let fixture = build_fixture();
        let path = fixture.evidence_path.clone();
        let hardlink = fixture._temp.path().join("post-read-hardlink.json");
        assert_post_read_change_rejected(&fixture, move || {
            fs::hard_link(path, hardlink).unwrap();
        });
    }

    #[test]
    fn descriptor_reverification_rejects_same_inode_group_change_when_permitted() {
        let fixture = build_fixture();
        let current_gid = fs::metadata(&fixture.evidence_path).unwrap().gid();
        // SAFETY: the null query obtains the required group count; the allocated buffer has that
        // exact length for the second call.
        let group_count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        assert!(group_count >= 0);
        let mut groups = vec![0; group_count as usize];
        // SAFETY: `groups` is writable for `group_count` entries.
        let loaded = unsafe { libc::getgroups(group_count, groups.as_mut_ptr()) };
        assert_eq!(loaded, group_count);
        let Some(alternate_gid) = groups.into_iter().find(|gid| *gid != current_gid) else {
            return;
        };
        let path = CString::new(fixture.evidence_path.as_os_str().as_bytes()).unwrap();
        assert_post_read_change_rejected(&fixture, move || {
            // SAFETY: `path` is a live NUL-terminated path and `uid_t::MAX` preserves the owner.
            let result = unsafe { libc::chown(path.as_ptr(), libc::uid_t::MAX, alternate_gid) };
            assert_eq!(result, 0);
        });
    }

    #[test]
    fn schema_count_set_reference_and_proof_mismatches_fail_closed() {
        type EvidenceMutation = (&'static str, fn(&mut EvidenceDocument));
        let mutations: [EvidenceMutation; 14] = [
            ("schema", |document| document.schema_version += 1),
            ("count", |document| document.asset_count = 9),
            ("set", |document| {
                document.assets[9].asset_id = "asset-08".to_string()
            }),
            ("record", |document| {
                document.assets[9].record_sha256 = digest("wrong")
            }),
            ("proof", |document| {
                document.retired_replacements[0].old_upload_lineage_sha256 = digest("wrong")
            }),
            ("owner_digest", |document| {
                document.retired_replacements[0].owner_record_name_sha256 = "not-a-digest".into()
            }),
            ("owner_mismatch", |document| {
                document.retired_replacements[1].owner_record_name_sha256 =
                    digest("different-valid-owner")
            }),
            ("lookup_mode", |document| {
                document.retired_replacements[1].initial_state_lookup_mode =
                    crate::upload::CloudKitUploadedHeicInitialStateLookupMode::FilteredMarker
            }),
            ("colliding_uploaded_asset", |document| {
                document.retired_replacements[1].uploaded_asset_id =
                    document.retired_replacements[0].uploaded_asset_id.clone()
            }),
            ("colliding_uploaded_master", |document| {
                document.retired_replacements[1].uploaded_master_id =
                    document.retired_replacements[0].uploaded_master_id.clone()
            }),
            ("colliding_change_tag", |document| {
                document.retired_replacements[1].old_record_change_tag = document
                    .retired_replacements[0]
                    .old_record_change_tag
                    .clone()
            }),
            ("colliding_destination", |document| {
                document.retired_replacements[1].destination_sha256 =
                    document.retired_replacements[0].destination_sha256.clone()
            }),
            ("colliding_original", |document| {
                document.retired_replacements[1].original_asset_record_name = document
                    .retired_replacements[0]
                    .original_asset_record_name
                    .clone()
            }),
            ("retired_identity", |document| {
                document.retired_replacements[0].uploaded_master_id =
                    document.retired_replacements[0].uploaded_asset_id.clone()
            }),
        ];
        for (case, mutate) in mutations {
            let mut fixture = build_fixture();
            let checkpoint_before = fs::read(&fixture.manifest_path).unwrap();
            mutate(&mut fixture.document);
            write_document(&mut fixture);
            let error = audit_legacy_uploaded_heic_evidence(&fixture.request).unwrap_err();
            assert_ne!(error.category(), "evidence_open", "{case}");
            assert_eq!(fs::read(&fixture.manifest_path).unwrap(), checkpoint_before);
        }

        let mut fixture = build_fixture();
        fixture.document.reference_normalizations[0].decoded_pixel_sha256 = digest("wrong");
        fixture.document.reference_normalizations[0].width = 0;
        write_document(&mut fixture);
        assert_eq!(
            audit_legacy_uploaded_heic_evidence(&fixture.request)
                .unwrap_err()
                .category(),
            "reference_witness"
        );
    }

    #[test]
    fn audit_validator_rejects_original_destination_divergence() {
        let fixture = build_fixture();
        let state = AssetStateStore::open_immutable_read_only(&fixture.manifest_path)
            .unwrap()
            .load()
            .unwrap();
        let mut evidence = fixture.document.retired_replacements[0].clone();
        let mut record = state.get(&evidence.asset_id).unwrap().clone();
        let mut original: OriginalAssetProof =
            serde_json::from_value(record.proofs["original_asset"].clone()).unwrap();
        original.zone_name = "DivergentZone".to_string();
        let original_value = serde_json::to_value(original).unwrap();
        evidence.original_asset_identity_sha256 = digest_value(&original_value).unwrap();
        record
            .proofs
            .insert("original_asset".to_string(), original_value);
        let record_sha256 = legacy_upload_migration_record_digest(&record).unwrap();
        let asset_id = record.asset_id.clone();
        let record_digests = BTreeMap::from([(asset_id.as_str(), record_sha256.as_str())]);
        let mut manifest = Manifest::new();
        manifest.upsert_trusted(record);

        assert_eq!(
            validate_retired_replacement(&evidence, &manifest, &record_digests, None)
                .unwrap_err()
                .category(),
            "proof_binding"
        );
    }

    #[test]
    fn reference_orientation_sequence_and_distribution_are_exact() {
        fn reset_reference_identity(reference: &mut EvidenceReferenceNormalization) {
            reference.reference_identity_sha256 = canonical_digest(&ReferenceIdentityDigestInput {
                schema_version: EVIDENCE_SCHEMA_VERSION,
                asset_id: &reference.asset_id,
                reference_path: &reference.reference_path,
                device: reference.device,
                inode: reference.inode,
                size_bytes: reference.size_bytes,
                file_sha256: &reference.file_sha256,
                orientation: reference.orientation,
                width: reference.width,
                height: reference.height,
                decoded_pixel_sha256: &reference.decoded_pixel_sha256,
            })
            .unwrap();
        }

        for invalid_orientation in [1, 7] {
            let mut fixture = build_fixture();
            fixture.document.reference_normalizations[0].orientation = invalid_orientation;
            reset_reference_identity(&mut fixture.document.reference_normalizations[0]);
            write_document(&mut fixture);
            assert_eq!(
                audit_legacy_uploaded_heic_evidence(&fixture.request)
                    .unwrap_err()
                    .category(),
                "reference_witness"
            );
        }

        let mut fixture = build_fixture();
        fixture.document.reference_normalizations.swap(0, 4);
        write_document(&mut fixture);
        assert_eq!(
            audit_legacy_uploaded_heic_evidence(&fixture.request)
                .unwrap_err()
                .category(),
            "asset_order"
        );
    }

    #[test]
    fn duplicate_and_unknown_evidence_fields_fail_strict_parsing() {
        let mut fixture = build_fixture();
        let valid = fs::read_to_string(&fixture.evidence_path).unwrap();
        let duplicate = valid.replacen('{', "{\"schema_version\":1,", 1);
        fs::write(&fixture.evidence_path, duplicate.as_bytes()).unwrap();
        fixture.request.expected_evidence_sha256 = sha256_bytes(duplicate.as_bytes());
        assert_eq!(
            audit_legacy_uploaded_heic_evidence(&fixture.request)
                .unwrap_err()
                .category(),
            "evidence_schema"
        );

        let mut fixture = build_fixture();
        let mut value = serde_json::to_value(&fixture.document).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_string(), json!(true));
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(&fixture.evidence_path, &bytes).unwrap();
        fixture.request.expected_evidence_sha256 = sha256_bytes(&bytes);
        assert_eq!(
            audit_legacy_uploaded_heic_evidence(&fixture.request)
                .unwrap_err()
                .category(),
            "evidence_schema"
        );

        for (field, value) in [
            ("original_state_lookup_mode", json!("filtered_marker")),
            ("original_remote_state", json!("already_deleted")),
        ] {
            let mut fixture = build_fixture();
            let mut document = serde_json::to_value(&fixture.document).unwrap();
            document["retired_replacements"][0][field] = value;
            let bytes = serde_json::to_vec(&document).unwrap();
            fs::write(&fixture.evidence_path, &bytes).unwrap();
            fixture.request.expected_evidence_sha256 = sha256_bytes(&bytes);
            assert_eq!(
                audit_legacy_uploaded_heic_evidence(&fixture.request)
                    .unwrap_err()
                    .category(),
                "evidence_schema"
            );
        }
    }

    #[test]
    fn descriptor_rejects_mode_owner_link_symlink_and_path_swap() {
        let fixture = build_fixture();
        fs::set_permissions(&fixture.evidence_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            audit_legacy_uploaded_heic_evidence(&fixture.request)
                .unwrap_err()
                .category(),
            "evidence_permissions"
        );

        let fixture = build_fixture();
        let hardlink = fixture._temp.path().join("hardlink.json");
        fs::hard_link(&fixture.evidence_path, &hardlink).unwrap();
        assert_eq!(
            audit_legacy_uploaded_heic_evidence(&fixture.request)
                .unwrap_err()
                .category(),
            "evidence_permissions"
        );

        let mut fixture = build_fixture();
        let symlink_path = fixture._temp.path().join("symlink.json");
        symlink(&fixture.evidence_path, &symlink_path).unwrap();
        fixture.request.evidence_path = symlink_path;
        assert_eq!(
            audit_legacy_uploaded_heic_evidence(&fixture.request)
                .unwrap_err()
                .category(),
            "evidence_open"
        );

        assert_eq!(
            validate_evidence_attributes(true, 0o100600, 501, 1, 502)
                .unwrap_err()
                .category(),
            "evidence_permissions"
        );

        let fixture = build_fixture();
        let path = fixture.evidence_path.clone();
        let moved = fixture._temp.path().join("moved.json");
        set_evidence_post_read_hook(move || {
            fs::rename(&path, &moved).unwrap();
            fs::write(&path, b"{}").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        });
        assert_eq!(
            audit_legacy_uploaded_heic_evidence(&fixture.request)
                .unwrap_err()
                .category(),
            "evidence_changed"
        );
    }

    struct ExactGeneratedEvidenceResolver;

    impl LegacyUploadEvidenceResolver for ExactGeneratedEvidenceResolver {
        fn resolve_uploaded_heic(
            &mut self,
            request: &crate::upload::CloudKitUploadedHeicResolveRequest,
        ) -> Result<crate::upload::CloudKitUploadedHeicAsset, LegacyUploadEvidenceError> {
            Ok(crate::upload::CloudKitUploadedHeicAsset {
                record_name: request.uploaded_asset_id.clone(),
                record_change_tag: format!("tag-{}", request.uploaded_asset_id),
                master_record_name: format!("master-{}", request.uploaded_asset_id),
                owner_record_name_sha256: digest("opaque-owner"),
                initial_remote_state: CloudKitUploadedHeicInitialState::Active,
                initial_state_lookup_mode:
                    crate::upload::CloudKitUploadedHeicInitialStateLookupMode::FullFields,
                matched_heic_sha256: request.expected_heic_sha256.clone(),
                size_bytes: request.expected_size_bytes,
            })
        }

        fn validate_original_active(
            &mut self,
            _original: &OriginalAssetProof,
        ) -> Result<CloudKitActiveAssetValidation, LegacyUploadEvidenceError> {
            Ok(active_original_validation())
        }
    }

    #[derive(Default)]
    struct AlreadyDeletedGeneratedEvidenceResolver {
        original_checks: Vec<String>,
    }

    impl LegacyUploadEvidenceResolver for AlreadyDeletedGeneratedEvidenceResolver {
        fn resolve_uploaded_heic(
            &mut self,
            request: &CloudKitUploadedHeicResolveRequest,
        ) -> Result<CloudKitUploadedHeicAsset, LegacyUploadEvidenceError> {
            Ok(CloudKitUploadedHeicAsset {
                record_name: request.uploaded_asset_id.clone(),
                record_change_tag: format!("tombstone-{}", request.uploaded_asset_id),
                master_record_name: format!("master-{}", request.uploaded_asset_id),
                owner_record_name_sha256: digest("opaque-owner"),
                initial_remote_state: CloudKitUploadedHeicInitialState::AlreadyDeleted,
                initial_state_lookup_mode:
                    crate::upload::CloudKitUploadedHeicInitialStateLookupMode::FullFields,
                matched_heic_sha256: request.expected_heic_sha256.clone(),
                size_bytes: request.expected_size_bytes,
            })
        }

        fn validate_original_active(
            &mut self,
            original: &OriginalAssetProof,
        ) -> Result<CloudKitActiveAssetValidation, LegacyUploadEvidenceError> {
            self.original_checks.push(original.record_name.clone());
            Ok(active_original_validation())
        }
    }

    struct MixedStateResolver;

    impl LegacyUploadEvidenceResolver for MixedStateResolver {
        fn resolve_uploaded_heic(
            &mut self,
            request: &CloudKitUploadedHeicResolveRequest,
        ) -> Result<CloudKitUploadedHeicAsset, LegacyUploadEvidenceError> {
            Ok(CloudKitUploadedHeicAsset {
                record_name: request.uploaded_asset_id.clone(),
                record_change_tag: format!("tag-{}", request.uploaded_asset_id),
                master_record_name: format!("master-{}", request.uploaded_asset_id),
                owner_record_name_sha256: digest("opaque-owner"),
                initial_remote_state: if request.uploaded_asset_id.ends_with("00") {
                    CloudKitUploadedHeicInitialState::ActiveUnmarked
                } else {
                    CloudKitUploadedHeicInitialState::AlreadyDeleted
                },
                initial_state_lookup_mode:
                    crate::upload::CloudKitUploadedHeicInitialStateLookupMode::FullFields,
                matched_heic_sha256: request.expected_heic_sha256.clone(),
                size_bytes: request.expected_size_bytes,
            })
        }

        fn validate_original_active(
            &mut self,
            _original: &OriginalAssetProof,
        ) -> Result<CloudKitActiveAssetValidation, LegacyUploadEvidenceError> {
            Ok(active_original_validation())
        }
    }

    struct ProductionReferenceProbe;

    impl LegacyUploadReferenceProbe for ProductionReferenceProbe {
        fn probe(
            &mut self,
            private_staged_path: &Path,
            timeout_seconds: u64,
        ) -> Result<crate::monitor::ReferenceNormalizationIdentity, LegacyUploadEvidenceError>
        {
            crate::monitor::reference_normalization_identity(private_staged_path, timeout_seconds)
                .map_err(|_| failure("reference_image"))
        }
    }

    struct CollidingMasterResolver;

    impl LegacyUploadEvidenceResolver for CollidingMasterResolver {
        fn resolve_uploaded_heic(
            &mut self,
            request: &CloudKitUploadedHeicResolveRequest,
        ) -> Result<CloudKitUploadedHeicAsset, LegacyUploadEvidenceError> {
            Ok(CloudKitUploadedHeicAsset {
                record_name: request.uploaded_asset_id.clone(),
                record_change_tag: format!("tag-{}", request.uploaded_asset_id),
                master_record_name: "shared-master".to_string(),
                owner_record_name_sha256: digest("opaque-owner"),
                initial_remote_state: CloudKitUploadedHeicInitialState::Active,
                initial_state_lookup_mode:
                    crate::upload::CloudKitUploadedHeicInitialStateLookupMode::FullFields,
                matched_heic_sha256: request.expected_heic_sha256.clone(),
                size_bytes: request.expected_size_bytes,
            })
        }

        fn validate_original_active(
            &mut self,
            _original: &OriginalAssetProof,
        ) -> Result<CloudKitActiveAssetValidation, LegacyUploadEvidenceError> {
            Ok(active_original_validation())
        }
    }

    struct CollidingChangeTagResolver;

    impl LegacyUploadEvidenceResolver for CollidingChangeTagResolver {
        fn resolve_uploaded_heic(
            &mut self,
            request: &CloudKitUploadedHeicResolveRequest,
        ) -> Result<CloudKitUploadedHeicAsset, LegacyUploadEvidenceError> {
            Ok(CloudKitUploadedHeicAsset {
                record_name: request.uploaded_asset_id.clone(),
                record_change_tag: "shared-change-tag".to_string(),
                master_record_name: format!("master-{}", request.uploaded_asset_id),
                owner_record_name_sha256: digest("opaque-owner"),
                initial_remote_state: CloudKitUploadedHeicInitialState::Active,
                initial_state_lookup_mode:
                    crate::upload::CloudKitUploadedHeicInitialStateLookupMode::FullFields,
                matched_heic_sha256: request.expected_heic_sha256.clone(),
                size_bytes: request.expected_size_bytes,
            })
        }

        fn validate_original_active(
            &mut self,
            _original: &OriginalAssetProof,
        ) -> Result<CloudKitActiveAssetValidation, LegacyUploadEvidenceError> {
            Ok(active_original_validation())
        }
    }

    struct ChangingOwnerResolver;

    impl LegacyUploadEvidenceResolver for ChangingOwnerResolver {
        fn resolve_uploaded_heic(
            &mut self,
            request: &CloudKitUploadedHeicResolveRequest,
        ) -> Result<CloudKitUploadedHeicAsset, LegacyUploadEvidenceError> {
            Ok(CloudKitUploadedHeicAsset {
                record_name: request.uploaded_asset_id.clone(),
                record_change_tag: format!("tag-{}", request.uploaded_asset_id),
                master_record_name: format!("master-{}", request.uploaded_asset_id),
                owner_record_name_sha256: digest(&format!("owner-{}", request.uploaded_asset_id)),
                initial_remote_state: CloudKitUploadedHeicInitialState::Active,
                initial_state_lookup_mode:
                    crate::upload::CloudKitUploadedHeicInitialStateLookupMode::FullFields,
                matched_heic_sha256: request.expected_heic_sha256.clone(),
                size_bytes: request.expected_size_bytes,
            })
        }

        fn validate_original_active(
            &mut self,
            _original: &OriginalAssetProof,
        ) -> Result<CloudKitActiveAssetValidation, LegacyUploadEvidenceError> {
            Ok(active_original_validation())
        }
    }

    struct AmbiguousRemoteResolver;

    impl LegacyUploadEvidenceResolver for AmbiguousRemoteResolver {
        fn resolve_uploaded_heic(
            &mut self,
            _request: &CloudKitUploadedHeicResolveRequest,
        ) -> Result<CloudKitUploadedHeicAsset, LegacyUploadEvidenceError> {
            Err(failure("cloudkit_ambiguity"))
        }

        fn validate_original_active(
            &mut self,
            _original: &OriginalAssetProof,
        ) -> Result<CloudKitActiveAssetValidation, LegacyUploadEvidenceError> {
            Err(failure("cloudkit_ambiguity"))
        }
    }

    fn overwrite_final_for_generated_candidate(fixture: &Fixture, index: usize) -> PathBuf {
        let asset_id = format!("asset-{index:02}");
        let record = AssetStateStore::open_immutable_read_only(&fixture.manifest_path)
            .unwrap()
            .load()
            .unwrap()
            .get(&asset_id)
            .unwrap()
            .clone();
        let upload: UploadProof = serde_json::from_value(record.proofs["upload"].clone()).unwrap();
        let path = upload.uploaded_heic_path.unwrap();
        fs::write(&path, format!("replacement-final-{}", record.asset_id)).unwrap();
        path
    }

    fn prepare_generated_reference_files(fixture: &Fixture) {
        for (reference_index, asset_index) in REFERENCE_ASSET_INDICES.iter().enumerate() {
            let path = fixture
                .artifact_root
                .join(format!("asset-{asset_index:02}.oriented-preview.jpg"));
            let mut bytes = jpeg_with_orientation(REFERENCE_ORIENTATIONS[reference_index] as u8);
            bytes.push(reference_index as u8);
            fs::write(path, bytes).unwrap();
        }
    }

    #[test]
    fn generator_selects_exact_live_shaped_cohort_and_round_trips_canonical_evidence() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        prepare_generated_reference_files(&fixture);
        for index in 0..RETIRED_REPLACEMENT_COUNT {
            overwrite_final_for_generated_candidate(&fixture, index);
        }
        let output_path = fixture._temp.path().join("generated-evidence.json");
        let checkpoint_before = fs::read(&fixture.manifest_path).unwrap();
        let database_path = AssetStateStore::db_path_for_manifest(&fixture.manifest_path);
        let database_before = fs::read(&database_path).unwrap();

        let report = generate_legacy_uploaded_heic_evidence_with(
            &LegacyUploadEvidenceGenerateRequest {
                manifest_path: fixture.manifest_path.clone(),
                output_path: output_path.clone(),
                image_timeout_seconds: 30,
                quarantine_roots: vec![fixture.quarantine_root.clone()],
            },
            &mut ExactGeneratedEvidenceResolver,
            &mut ProductionReferenceProbe,
        )
        .unwrap();

        assert_eq!(report.asset_count, 10);
        assert_eq!(report.retired_replacement_count, 2);
        assert_eq!(report.reference_count, 5);
        assert_eq!(fs::read(&fixture.manifest_path).unwrap(), checkpoint_before);
        assert_eq!(fs::read(&database_path).unwrap(), database_before);
        let bytes = fs::read(&output_path).unwrap();
        let document: EvidenceDocument = crate::strict_json::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(serde_json::to_vec(&document).unwrap(), bytes);
        assert_eq!(
            document
                .assets
                .iter()
                .map(|asset| asset.asset_id.as_str())
                .collect::<Vec<_>>(),
            (0..10)
                .map(|index| format!("asset-{index:02}"))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            document
                .reference_normalizations
                .iter()
                .map(|reference| reference.orientation)
                .collect::<Vec<_>>(),
            REFERENCE_ORIENTATIONS
        );
        let audit = audit_legacy_uploaded_heic_evidence(&LegacyUploadEvidenceAuditRequest {
            manifest_path: fixture.manifest_path.clone(),
            evidence_path: output_path,
            expected_evidence_sha256: report.evidence_sha256.clone(),
            expected_asset_count: report.asset_count,
            expected_retired_replacement_count: report.retired_replacement_count,
            expected_reference_count: report.reference_count,
            expected_cohort_sha256: report.cohort_sha256.clone(),
        })
        .unwrap();
        assert_eq!(audit.evidence_sha256, report.evidence_sha256);
        assert_eq!(audit.cohort_sha256, report.cohort_sha256);
    }

    #[test]
    fn generator_seals_exact_pair_of_already_deleted_replacements_and_active_originals() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        prepare_generated_reference_files(&fixture);
        for index in 0..RETIRED_REPLACEMENT_COUNT {
            overwrite_final_for_generated_candidate(&fixture, index);
        }
        let output_path = fixture._temp.path().join("already-deleted-evidence.json");
        let mut resolver = AlreadyDeletedGeneratedEvidenceResolver::default();

        let report = generate_legacy_uploaded_heic_evidence_with(
            &LegacyUploadEvidenceGenerateRequest {
                manifest_path: fixture.manifest_path.clone(),
                output_path: output_path.clone(),
                image_timeout_seconds: 30,
                quarantine_roots: vec![fixture.quarantine_root.clone()],
            },
            &mut resolver,
            &mut ProductionReferenceProbe,
        )
        .unwrap();

        let document: EvidenceDocument =
            crate::strict_json::from_reader(fs::read(&output_path).unwrap().as_slice()).unwrap();
        assert_eq!(document.schema_version, 5);
        assert!(document.retired_replacements.iter().all(|replacement| {
            replacement.initial_remote_state == CloudKitUploadedHeicInitialState::AlreadyDeleted
                && replacement.original_remote_state == CloudKitActiveAssetRemoteState::Active
                && replacement.original_state_lookup_mode
                    == CloudKitActiveAssetLookupMode::FullFields
        }));
        assert_eq!(resolver.original_checks.len(), 2);
        audit_legacy_uploaded_heic_evidence(&LegacyUploadEvidenceAuditRequest {
            manifest_path: fixture.manifest_path.clone(),
            evidence_path: output_path,
            expected_evidence_sha256: report.evidence_sha256,
            expected_asset_count: 10,
            expected_retired_replacement_count: 2,
            expected_reference_count: 5,
            expected_cohort_sha256: report.cohort_sha256,
        })
        .unwrap();
    }

    #[test]
    fn generator_descriptor_race_emits_no_evidence() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        prepare_generated_reference_files(&fixture);
        for index in 0..RETIRED_REPLACEMENT_COUNT {
            overwrite_final_for_generated_candidate(&fixture, index);
        }
        let raced_path = fixture.artifact_root.join("asset-02.oriented-preview.jpg");
        set_generation_pre_output_hook(move || {
            fs::write(raced_path, jpeg_with_orientation(8)).unwrap();
        });
        let output_path = fixture._temp.path().join("raced-evidence.json");
        let error = generate_legacy_uploaded_heic_evidence_with(
            &LegacyUploadEvidenceGenerateRequest {
                manifest_path: fixture.manifest_path.clone(),
                output_path: output_path.clone(),
                image_timeout_seconds: 30,
                quarantine_roots: vec![fixture.quarantine_root.clone()],
            },
            &mut ExactGeneratedEvidenceResolver,
            &mut ProductionReferenceProbe,
        )
        .unwrap_err();
        assert_eq!(error.category(), "source_changed");
        assert!(!output_path.exists());
    }

    #[test]
    fn generator_rejects_zero_or_multiple_retirement_candidates_without_output() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for candidate_count in [0, 3] {
            let fixture = build_fixture();
            prepare_generated_reference_files(&fixture);
            for index in 0..candidate_count {
                overwrite_final_for_generated_candidate(&fixture, index);
            }
            let output_path = fixture
                ._temp
                .path()
                .join(format!("candidate-count-{candidate_count}.json"));
            let error = generate_legacy_uploaded_heic_evidence_with(
                &LegacyUploadEvidenceGenerateRequest {
                    manifest_path: fixture.manifest_path.clone(),
                    output_path: output_path.clone(),
                    image_timeout_seconds: 30,
                    quarantine_roots: vec![fixture.quarantine_root.clone()],
                },
                &mut ExactGeneratedEvidenceResolver,
                &mut ProductionReferenceProbe,
            )
            .unwrap_err();
            assert_eq!(error.category(), "candidate_count");
            assert!(!output_path.exists());
        }
    }

    #[test]
    fn generator_rejects_wrong_reference_orientation_without_output() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        prepare_generated_reference_files(&fixture);
        for index in 0..RETIRED_REPLACEMENT_COUNT {
            overwrite_final_for_generated_candidate(&fixture, index);
        }
        let mut wrong = jpeg_with_orientation(8);
        wrong.push(42);
        fs::write(
            fixture.artifact_root.join("asset-02.oriented-preview.jpg"),
            wrong,
        )
        .unwrap();
        let output_path = fixture._temp.path().join("wrong-orientation.json");
        let error = generate_legacy_uploaded_heic_evidence_with(
            &LegacyUploadEvidenceGenerateRequest {
                manifest_path: fixture.manifest_path.clone(),
                output_path: output_path.clone(),
                image_timeout_seconds: 30,
                quarantine_roots: vec![fixture.quarantine_root.clone()],
            },
            &mut ExactGeneratedEvidenceResolver,
            &mut ProductionReferenceProbe,
        )
        .unwrap_err();
        assert_eq!(error.category(), "reference_image");
        assert!(!output_path.exists());
    }

    #[test]
    fn generator_rejects_colliding_cloudkit_master_without_output() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        prepare_generated_reference_files(&fixture);
        for index in 0..RETIRED_REPLACEMENT_COUNT {
            overwrite_final_for_generated_candidate(&fixture, index);
        }
        let output_path = fixture._temp.path().join("cloudkit-ambiguity.json");
        let error = generate_legacy_uploaded_heic_evidence_with(
            &LegacyUploadEvidenceGenerateRequest {
                manifest_path: fixture.manifest_path.clone(),
                output_path: output_path.clone(),
                image_timeout_seconds: 30,
                quarantine_roots: vec![fixture.quarantine_root.clone()],
            },
            &mut CollidingMasterResolver,
            &mut ProductionReferenceProbe,
        )
        .unwrap_err();
        assert_eq!(error.category(), "cloudkit_ambiguity");
        assert!(!output_path.exists());

        let ambiguous_output = fixture._temp.path().join("cloudkit-remote-ambiguity.json");
        let error = generate_legacy_uploaded_heic_evidence_with(
            &LegacyUploadEvidenceGenerateRequest {
                manifest_path: fixture.manifest_path.clone(),
                output_path: ambiguous_output.clone(),
                image_timeout_seconds: 30,
                quarantine_roots: vec![fixture.quarantine_root.clone()],
            },
            &mut AmbiguousRemoteResolver,
            &mut ProductionReferenceProbe,
        )
        .unwrap_err();
        assert_eq!(error.category(), "cloudkit_ambiguity");
        assert!(!ambiguous_output.exists());
    }

    #[test]
    fn generator_rejects_colliding_cloudkit_change_tag_without_output() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        prepare_generated_reference_files(&fixture);
        for index in 0..RETIRED_REPLACEMENT_COUNT {
            overwrite_final_for_generated_candidate(&fixture, index);
        }
        let output_path = fixture
            ._temp
            .path()
            .join("cloudkit-change-tag-ambiguity.json");

        let error = generate_legacy_uploaded_heic_evidence_with(
            &LegacyUploadEvidenceGenerateRequest {
                manifest_path: fixture.manifest_path.clone(),
                output_path: output_path.clone(),
                image_timeout_seconds: 30,
                quarantine_roots: vec![fixture.quarantine_root.clone()],
            },
            &mut CollidingChangeTagResolver,
            &mut ProductionReferenceProbe,
        )
        .unwrap_err();

        assert_eq!(error.category(), "cloudkit_ambiguity");
        assert!(!output_path.exists());

        let changed_owner_output = fixture._temp.path().join("cloudkit-owner-ambiguity.json");
        let error = generate_legacy_uploaded_heic_evidence_with(
            &LegacyUploadEvidenceGenerateRequest {
                manifest_path: fixture.manifest_path.clone(),
                output_path: changed_owner_output.clone(),
                image_timeout_seconds: 30,
                quarantine_roots: vec![fixture.quarantine_root.clone()],
            },
            &mut ChangingOwnerResolver,
            &mut ProductionReferenceProbe,
        )
        .unwrap_err();
        assert_eq!(error.category(), "cloudkit_ambiguity");
        assert!(!changed_owner_output.exists());

        let mixed_state_output = fixture._temp.path().join("cloudkit-mixed-state.json");
        let report = generate_legacy_uploaded_heic_evidence_with(
            &LegacyUploadEvidenceGenerateRequest {
                manifest_path: fixture.manifest_path.clone(),
                output_path: mixed_state_output.clone(),
                image_timeout_seconds: 30,
                quarantine_roots: vec![fixture.quarantine_root.clone()],
            },
            &mut MixedStateResolver,
            &mut ProductionReferenceProbe,
        )
        .expect("an exact active-unmarked/already-deleted pair must be permitted");
        let mixed: EvidenceDocument =
            crate::strict_json::from_reader(fs::read(&mixed_state_output).unwrap().as_slice())
                .unwrap();
        assert_eq!(
            mixed
                .retired_replacements
                .iter()
                .map(|replacement| replacement.initial_remote_state)
                .collect::<Vec<_>>(),
            vec![
                CloudKitUploadedHeicInitialState::ActiveUnmarked,
                CloudKitUploadedHeicInitialState::AlreadyDeleted,
            ]
        );
        assert!(mixed.retired_replacements.iter().all(|replacement| {
            replacement.initial_state_lookup_mode
                == crate::upload::CloudKitUploadedHeicInitialStateLookupMode::FullFields
        }));
        assert_eq!(report.retired_replacement_count, 2);
    }

    #[test]
    fn generator_exclusive_output_never_overwrites_existing_file() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        prepare_generated_reference_files(&fixture);
        for index in 0..RETIRED_REPLACEMENT_COUNT {
            overwrite_final_for_generated_candidate(&fixture, index);
        }
        let output_path = fixture._temp.path().join("existing-evidence.json");
        fs::write(&output_path, b"SENTINEL_EXISTING_EVIDENCE").unwrap();
        fs::set_permissions(&output_path, fs::Permissions::from_mode(0o600)).unwrap();
        let error = generate_legacy_uploaded_heic_evidence_with(
            &LegacyUploadEvidenceGenerateRequest {
                manifest_path: fixture.manifest_path.clone(),
                output_path: output_path.clone(),
                image_timeout_seconds: 30,
                quarantine_roots: vec![fixture.quarantine_root.clone()],
            },
            &mut ExactGeneratedEvidenceResolver,
            &mut ProductionReferenceProbe,
        )
        .unwrap_err();
        assert_eq!(error.category(), "output_create");
        assert_eq!(
            fs::read(output_path).unwrap(),
            b"SENTINEL_EXISTING_EVIDENCE"
        );
    }

    #[test]
    fn generator_output_parent_race_leaves_no_file_in_either_directory() {
        let _path_lock = crate::PROCESS_PATH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = build_fixture();
        prepare_generated_reference_files(&fixture);
        for index in 0..RETIRED_REPLACEMENT_COUNT {
            overwrite_final_for_generated_candidate(&fixture, index);
        }
        let output_parent = fixture._temp.path().join("output-parent");
        let moved_parent = fixture._temp.path().join("moved-output-parent");
        fs::create_dir(&output_parent).unwrap();
        let raced_parent = output_parent.clone();
        let raced_moved = moved_parent.clone();
        set_generation_post_output_create_hook(move || {
            fs::rename(&raced_parent, &raced_moved).unwrap();
            fs::create_dir(&raced_parent).unwrap();
        });
        let output_path = output_parent.join("evidence.json");
        let error = generate_legacy_uploaded_heic_evidence_with(
            &LegacyUploadEvidenceGenerateRequest {
                manifest_path: fixture.manifest_path.clone(),
                output_path: output_path.clone(),
                image_timeout_seconds: 30,
                quarantine_roots: vec![fixture.quarantine_root.clone()],
            },
            &mut ExactGeneratedEvidenceResolver,
            &mut ProductionReferenceProbe,
        )
        .unwrap_err();
        assert_eq!(error.category(), "output_verify");
        assert!(!output_path.exists());
        assert!(!moved_parent.join("evidence.json").exists());
    }
}

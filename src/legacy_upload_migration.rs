use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::manifest::{AssetRecord, FailureRecord, Manifest, State};
use crate::state_store::{AssetRecordExactCasUpdate, AssetStateStore, AssetStateStoreError};
use crate::workflow::{
    CONVERSION_PERFORMANCE_PROOF, CONVERSION_PROOF, ConversionPerformanceInput,
    ConversionPerformanceProof, ConversionResultInput, ConversionResultProof, HEIC_PROOF,
    HeicVerificationInput, HeicVerificationProof, ICLOUDPD_LOCAL_MIRROR_PROOF,
    IcloudpdLocalMirrorProof, UPLOAD_PROOF, UploadProof, record_current_conversion_performance,
    record_current_conversion_result, record_current_heic_verification,
    record_icloudpd_local_mirror_proof, record_upload_proof, uploaded_heic_delete_request,
};

mod apply;
mod evidence;
#[cfg(test)]
mod tests;
pub(crate) use apply::{
    LegacyUploadMigrationApplyReport, LegacyUploadMigrationProductionRequest,
    LegacyUploadQuarantineResidualAuditReport, LegacyUploadQuarantineResidualAuditRequest,
    LegacyUploadQuarantineResidualRecoveryReport, LegacyUploadQuarantineResidualRecoveryRequest,
    apply_legacy_uploaded_heic_migration,
    apply_legacy_uploaded_heic_migration_with_device_recovery,
    audit_legacy_upload_quarantine_residuals, recover_legacy_upload_quarantine_residuals,
};
pub(crate) use evidence::{
    LegacyUploadDeviceRecoveryGenerateRequest, LegacyUploadDeviceRecoveryRequest,
    LegacyUploadDeviceRecoveryRotateReport, LegacyUploadDeviceRecoveryRotateRequest,
    LegacyUploadEvidenceAudit, LegacyUploadEvidenceAuditRequest,
    LegacyUploadEvidenceGenerateReport, LegacyUploadEvidenceGenerateRequest,
    audit_legacy_uploaded_heic_evidence, audit_legacy_uploaded_heic_evidence_with_device_recovery,
    generate_legacy_uploaded_heic_device_recovery, generate_legacy_uploaded_heic_evidence,
    rotate_legacy_uploaded_heic_device_recovery,
};
#[cfg(test)]
pub(crate) use tests::db_loaded_lifecycle_pair_at_phase;

pub const LEGACY_UPLOAD_MIGRATION_PROOF_NAME: &str =
    crate::manifest::INTERNAL_LEGACY_UPLOAD_MIGRATION_PROOF_NAME;
pub const LEGACY_UPLOAD_MIGRATION_SCHEMA_VERSION: u64 = 2;
pub(crate) const LEGACY_UPLOAD_MIGRATION_REGISTRY_SCHEMA_VERSION: u64 = 1;
const GENESIS_ENTRY_SHA256: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_REMOTE_IDENTITY_BYTES: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegacyUploadMigrationRecordClassification {
    ordinary_manifest: Manifest,
    sealed_asset_ids: BTreeSet<String>,
}

impl LegacyUploadMigrationRecordClassification {
    pub(crate) fn into_parts(self) -> (Manifest, BTreeSet<String>) {
        (self.ordinary_manifest, self.sealed_asset_ids)
    }
}

pub(crate) fn classify_legacy_upload_migration_records(
    manifest: &Manifest,
) -> Result<LegacyUploadMigrationRecordClassification, LegacyUploadMigrationError> {
    validate_legacy_upload_migration_registry_binding(manifest, true)?;
    let mut ordinary_manifest = Manifest::new();
    let mut sealed_asset_ids = BTreeSet::new();
    for record in manifest.records().values() {
        let Some(_) = record.proofs.get(LEGACY_UPLOAD_MIGRATION_PROOF_NAME) else {
            ordinary_manifest.upsert_trusted(record.clone());
            continue;
        };
        let journal = validate_legacy_upload_migration_record(record)?;
        let phase = journal
            .entries
            .last()
            .ok_or(LegacyUploadMigrationError::JournalEmpty)?
            .phase;
        if phase != LegacyUploadMigrationPhase::Complete {
            return Err(LegacyUploadMigrationError::IncompleteJournal { phase });
        }
        sealed_asset_ids.insert(record.asset_id.clone());
    }
    Ok(LegacyUploadMigrationRecordClassification {
        ordinary_manifest,
        sealed_asset_ids,
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyUploadMigrationPhase {
    Prepared,
    DeleteConfirmed,
    Quarantined,
    Reset,
    Converted,
    UploadPrepared,
    UploadVerified,
    Mirrored,
    Complete,
}

impl LegacyUploadMigrationPhase {
    pub const ORDER: [Self; 9] = [
        Self::Prepared,
        Self::DeleteConfirmed,
        Self::Quarantined,
        Self::Reset,
        Self::Converted,
        Self::UploadPrepared,
        Self::UploadVerified,
        Self::Mirrored,
        Self::Complete,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::DeleteConfirmed => "delete_confirmed",
            Self::Quarantined => "quarantined",
            Self::Reset => "reset",
            Self::Converted => "converted",
            Self::UploadPrepared => "upload_prepared",
            Self::UploadVerified => "upload_verified",
            Self::Mirrored => "mirrored",
            Self::Complete => "complete",
        }
    }

    const fn required_state(self) -> State {
        match self {
            Self::Prepared | Self::DeleteConfirmed | Self::Quarantined => State::UploadVerified,
            Self::Reset => State::NasVerified,
            Self::Converted | Self::UploadPrepared => State::ConversionVerified,
            Self::UploadVerified | Self::Mirrored | Self::Complete => State::UploadVerified,
        }
    }

    const fn witness_kind(self) -> LegacyUploadMigrationWitnessKind {
        match self {
            Self::Prepared => LegacyUploadMigrationWitnessKind::Preparation,
            Self::DeleteConfirmed => LegacyUploadMigrationWitnessKind::DeleteConfirmation,
            Self::Quarantined => LegacyUploadMigrationWitnessKind::Quarantine,
            Self::Reset => LegacyUploadMigrationWitnessKind::ResetSnapshot,
            Self::Converted => LegacyUploadMigrationWitnessKind::VerifiedConversion,
            Self::UploadPrepared => LegacyUploadMigrationWitnessKind::UploadIntent,
            Self::UploadVerified => LegacyUploadMigrationWitnessKind::VerifiedUpload,
            Self::Mirrored => LegacyUploadMigrationWitnessKind::VerifiedMirror,
            Self::Complete => LegacyUploadMigrationWitnessKind::Completion,
        }
    }

    fn index(self) -> usize {
        Self::ORDER
            .iter()
            .position(|candidate| *candidate == self)
            .expect("every migration phase belongs to the fixed phase order")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyUploadMigrationWitnessKind {
    Preparation,
    DeleteConfirmation,
    Quarantine,
    ResetSnapshot,
    VerifiedConversion,
    UploadIntent,
    VerifiedUpload,
    VerifiedMirror,
    Completion,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyUploadMigrationQuarantineKind {
    Final,
    Reference,
    OldMirror,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyUploadMigrationQuarantineFileIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) owner: u32,
    pub(crate) mode: u32,
    pub(crate) link_count: u64,
    pub(crate) size_bytes: u64,
    pub(crate) modified_unix_seconds: i64,
    pub(crate) modified_unix_nanoseconds: i64,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyUploadMigrationQuarantineRoot {
    pub(crate) canonical_path: PathBuf,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) owner: u32,
    pub(crate) mode: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyUploadMigrationQuarantineMember {
    pub(crate) asset_id: String,
    pub(crate) kind: LegacyUploadMigrationQuarantineKind,
    pub(crate) source_path: PathBuf,
    pub(crate) destination_path: PathBuf,
    pub(crate) source: LegacyUploadMigrationQuarantineFileIdentity,
    pub(crate) root_device: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyUploadMigrationRawInput {
    pub(crate) asset_id: String,
    pub(crate) path: PathBuf,
    pub(crate) source: LegacyUploadMigrationQuarantineFileIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyUploadMigrationQuarantinePlan {
    pub(crate) schema_version: u64,
    pub(crate) roots: Vec<LegacyUploadMigrationQuarantineRoot>,
    pub(crate) members: Vec<LegacyUploadMigrationQuarantineMember>,
    pub(crate) raw_inputs: Vec<LegacyUploadMigrationRawInput>,
    pub(crate) plan_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyUploadMigrationIdentity {
    pub migration_id: String,
    pub evidence_sha256: String,
    pub cohort_sha256: String,
    pub asset_id: String,
    pub source_record_sha256: String,
    pub old_uploaded_asset_id: String,
    pub old_uploaded_master_id: String,
    pub destination_sha256: String,
    pub original_asset_identity_sha256: String,
    pub old_conversion_lineage_sha256: String,
    pub old_upload_lineage_sha256: String,
    pub old_mirror_lineage_sha256: String,
    pub quarantine_plan: LegacyUploadMigrationQuarantinePlan,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyUploadMigrationPhaseEntry {
    pub ordinal: u64,
    pub phase: LegacyUploadMigrationPhase,
    pub witness_kind: LegacyUploadMigrationWitnessKind,
    pub witness_sha256: String,
    pub record_body_sha256: String,
    pub previous_entry_sha256: String,
    pub entry_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyUploadMigrationJournal {
    pub schema_version: u64,
    pub identity: LegacyUploadMigrationIdentity,
    pub entries: Vec<LegacyUploadMigrationPhaseEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyUploadMigrationRegistryAsset {
    pub(crate) asset_id: String,
    pub(crate) identity_sha256: String,
    pub(crate) source_record_sha256: String,
    pub(crate) original_asset_identity_sha256: String,
    pub(crate) old_conversion_lineage_sha256: String,
    pub(crate) old_upload_lineage_sha256: String,
    pub(crate) old_mirror_lineage_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyUploadMigrationRegistry {
    pub(crate) schema_version: u64,
    pub(crate) migration_id: String,
    pub(crate) evidence_sha256: String,
    pub(crate) cohort_sha256: String,
    pub(crate) quarantine_plan: LegacyUploadMigrationQuarantinePlan,
    pub(crate) assets: [LegacyUploadMigrationRegistryAsset; 2],
    pub(crate) registry_sha256: String,
}

#[derive(Serialize)]
struct LegacyUploadMigrationRegistryDigestInput<'a> {
    schema_version: u64,
    migration_id: &'a str,
    evidence_sha256: &'a str,
    cohort_sha256: &'a str,
    quarantine_plan: &'a LegacyUploadMigrationQuarantinePlan,
    assets: &'a [LegacyUploadMigrationRegistryAsset; 2],
}

pub(crate) struct LegacyUploadMigrationManifestRegistryAuthority {
    registry_sha256: String,
}

impl LegacyUploadMigrationManifestRegistryAuthority {
    pub(crate) fn for_registry(
        registry: &LegacyUploadMigrationRegistry,
    ) -> Result<Self, LegacyUploadMigrationError> {
        validate_legacy_upload_migration_registry(registry)?;
        Ok(Self {
            registry_sha256: registry.registry_sha256.clone(),
        })
    }

    pub(crate) fn authorizes(&self, registry: &LegacyUploadMigrationRegistry) -> bool {
        self.registry_sha256 == registry.registry_sha256
            && validate_legacy_upload_migration_registry(registry).is_ok()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LegacyUploadMigrationCasUpdate<'a> {
    pub expected: &'a AssetRecord,
    pub updated: &'a AssetRecord,
}

/// Opaque authority for one evidence-validated, exact-two migration cohort.
///
/// Only the future evidence loader inside this module may mint this value.
/// External callers can inspect journals, but cannot construct preparation
/// authority from self-selected evidence or lineage digests.
///
/// ```compile_fail
/// use icloudpd_optimizer::legacy_upload_migration::LegacyUploadMigrationCohortAuthority;
///
/// let _forged = LegacyUploadMigrationCohortAuthority { preparations: [] };
/// ```
///
/// ```compile_fail
/// use icloudpd_optimizer::legacy_upload_migration::LegacyUploadMigrationCohortAuthority;
///
/// let _forged = LegacyUploadMigrationCohortAuthority::new();
/// ```
pub struct LegacyUploadMigrationCohortAuthority {
    preparations: [LegacyUploadMigrationAuthorizedPreparation; 2],
}

struct LegacyUploadMigrationAuthorizedPreparation {
    identity: LegacyUploadMigrationIdentity,
    prepared_witness_sha256: String,
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "minted by the forthcoming in-module orchestrator")
)]
pub(crate) struct LegacyUploadMigrationManifestRecordAuthority {
    asset_id: String,
    record_sha256: String,
}

impl LegacyUploadMigrationManifestRecordAuthority {
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "used by the forthcoming in-module orchestrator")
    )]
    fn for_record(record: &AssetRecord) -> Result<Self, LegacyUploadMigrationError> {
        validate_journal_for_record(record, true)?;
        Ok(Self {
            asset_id: record.asset_id.clone(),
            record_sha256: legacy_upload_migration_record_digest(record)?,
        })
    }

    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "used by the forthcoming in-module orchestrator")
    )]
    pub(crate) fn authorizes(&self, record: &AssetRecord) -> bool {
        self.asset_id == record.asset_id
            && legacy_upload_migration_record_digest(record)
                .is_ok_and(|digest| digest == self.record_sha256)
    }
}

/// Opaque authority minted by the migration orchestrator after a typed phase
/// gate succeeds for one exact two-record cohort.
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "minted by the forthcoming in-module orchestrator")
)]
pub(crate) struct LegacyUploadMigrationPhaseAuthority {
    migration_id: String,
    evidence_sha256: String,
    cohort_sha256: String,
    from: LegacyUploadMigrationPhase,
    to: LegacyUploadMigrationPhase,
    transitions: [LegacyUploadMigrationAuthorizedPhaseTransition; 2],
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "minted by the forthcoming in-module orchestrator")
)]
struct LegacyUploadMigrationAuthorizedPhaseTransition {
    asset_id: String,
    expected_record_sha256: String,
    candidate_record_sha256: String,
    updated_record_sha256: String,
    payload_sha256: String,
    witness_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LegacyUploadMigrationRegistryWriteMode {
    InsertOnceOrExactReplay,
    VerifyExact,
}

pub(crate) struct LegacyUploadMigrationStateStoreWriteAuthority {
    registry: LegacyUploadMigrationRegistry,
    mode: LegacyUploadMigrationRegistryWriteMode,
}

impl LegacyUploadMigrationStateStoreWriteAuthority {
    pub(crate) fn registry(&self) -> &LegacyUploadMigrationRegistry {
        &self.registry
    }

    pub(crate) fn mode(&self) -> LegacyUploadMigrationRegistryWriteMode {
        self.mode
    }
}

impl LegacyUploadMigrationCohortAuthority {
    fn preparation_for_asset(
        &self,
        asset_id: &str,
    ) -> Option<&LegacyUploadMigrationAuthorizedPreparation> {
        let mut matches = self
            .preparations
            .iter()
            .filter(|preparation| preparation.identity.asset_id == asset_id);
        let preparation = matches.next()?;
        matches.next().is_none().then_some(preparation)
    }
}

impl LegacyUploadMigrationPhaseAuthority {
    #[cfg_attr(
        not(test),
        allow(dead_code, reason = "used by the forthcoming in-module orchestrator")
    )]
    fn transition_for_asset(
        &self,
        asset_id: &str,
    ) -> Option<&LegacyUploadMigrationAuthorizedPhaseTransition> {
        let mut matches = self
            .transitions
            .iter()
            .filter(|transition| transition.asset_id == asset_id);
        let transition = matches.next()?;
        matches.next().is_none().then_some(transition)
    }
}

/// Read-only description of a validated journal transition.
///
/// Mutation remains internal to the migration orchestrator, even though
/// callers may validate and inspect a proposed transition.
///
/// ```compile_fail
/// use icloudpd_optimizer::legacy_upload_migration::advance_legacy_upload_migration_record;
/// ```
///
/// ```compile_fail
/// use icloudpd_optimizer::legacy_upload_migration::persist_two_legacy_upload_migration_records_exact_cas;
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyUploadMigrationTransitionShape {
    Replay {
        phase: LegacyUploadMigrationPhase,
    },
    Advance {
        from: LegacyUploadMigrationPhase,
        to: LegacyUploadMigrationPhase,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LegacyUploadMigrationDeltaPolicy {
    JournalOnly,
    ResetLegacyLineage,
    InstallVerifiedConversion,
    InstallVerifiedUpload,
    InstallVerifiedMirror,
}

impl LegacyUploadMigrationDeltaPolicy {
    fn for_transition(
        from: LegacyUploadMigrationPhase,
        to: LegacyUploadMigrationPhase,
    ) -> Option<Self> {
        match (from, to) {
            (LegacyUploadMigrationPhase::Prepared, LegacyUploadMigrationPhase::DeleteConfirmed)
            | (
                LegacyUploadMigrationPhase::DeleteConfirmed,
                LegacyUploadMigrationPhase::Quarantined,
            )
            | (LegacyUploadMigrationPhase::Converted, LegacyUploadMigrationPhase::UploadPrepared)
            | (LegacyUploadMigrationPhase::Mirrored, LegacyUploadMigrationPhase::Complete) => {
                Some(Self::JournalOnly)
            }
            (LegacyUploadMigrationPhase::Quarantined, LegacyUploadMigrationPhase::Reset) => {
                Some(Self::ResetLegacyLineage)
            }
            (LegacyUploadMigrationPhase::Reset, LegacyUploadMigrationPhase::Converted) => {
                Some(Self::InstallVerifiedConversion)
            }
            (
                LegacyUploadMigrationPhase::UploadPrepared,
                LegacyUploadMigrationPhase::UploadVerified,
            ) => Some(Self::InstallVerifiedUpload),
            (LegacyUploadMigrationPhase::UploadVerified, LegacyUploadMigrationPhase::Mirrored) => {
                Some(Self::InstallVerifiedMirror)
            }
            _ => None,
        }
    }
}

struct VerifiedConversionDelta {
    conversion: ConversionResultProof,
    performance: ConversionPerformanceProof,
    heic: HeicVerificationProof,
}

struct VerifiedUploadDelta {
    upload: UploadProof,
}

struct VerifiedMirrorDelta {
    mirror: IcloudpdLocalMirrorProof,
}

#[derive(Serialize)]
struct EntryDigestInput<'a> {
    schema_version: u64,
    identity_sha256: &'a str,
    ordinal: u64,
    phase: LegacyUploadMigrationPhase,
    witness_kind: LegacyUploadMigrationWitnessKind,
    witness_sha256: &'a str,
    record_body_sha256: &'a str,
    previous_entry_sha256: &'a str,
}

#[derive(Serialize)]
struct RecordBodyDigestInput<'a> {
    asset_id: &'a str,
    raw_path: &'a std::path::Path,
    state: State,
    proofs: BTreeMap<&'a str, &'a Value>,
    failures: &'a [FailureRecord],
    updated_at: &'a str,
}

#[derive(Serialize)]
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "used by the forthcoming in-module orchestrator")
)]
struct PhaseWitnessDigestInput<'a> {
    schema_version: u64,
    migration_id: &'a str,
    evidence_sha256: &'a str,
    cohort_sha256: &'a str,
    asset_id: &'a str,
    from: LegacyUploadMigrationPhase,
    to: LegacyUploadMigrationPhase,
    expected_record_sha256: &'a str,
    candidate_record_sha256: &'a str,
    payload_sha256: &'a str,
}

pub fn legacy_upload_migration_record_digest(
    record: &AssetRecord,
) -> Result<String, LegacyUploadMigrationError> {
    canonical_digest(record)
}

pub fn prepare_legacy_upload_migration_record(
    record: &AssetRecord,
    authority: &LegacyUploadMigrationCohortAuthority,
) -> Result<AssetRecord, LegacyUploadMigrationError> {
    validate_cohort_authority(authority)?;
    let authorized = authority
        .preparation_for_asset(&record.asset_id)
        .ok_or(LegacyUploadMigrationError::CohortAuthorityMismatch)?;
    let identity = authorized.identity.clone();
    let witness_sha256 = &authorized.prepared_witness_sha256;
    if record
        .proofs
        .contains_key(LEGACY_UPLOAD_MIGRATION_PROOF_NAME)
    {
        let journal = validate_journal_for_record(record, true)?;
        if journal.identity != identity {
            return Err(LegacyUploadMigrationError::IdentityMismatch);
        }
        return advance_legacy_upload_migration_record_with_witness(
            record,
            LegacyUploadMigrationPhase::Prepared,
            witness_sha256,
        );
    }
    validate_identity(&identity)?;
    validate_digest("witness_sha256", witness_sha256)?;
    if identity.asset_id != record.asset_id {
        return Err(LegacyUploadMigrationError::IdentityMismatch);
    }
    if identity.source_record_sha256 != legacy_upload_migration_record_digest(record)? {
        return Err(LegacyUploadMigrationError::SourceRecordMismatch);
    }
    validate_state(record, LegacyUploadMigrationPhase::Prepared)?;

    let identity_sha256 = canonical_digest(&identity)?;
    let record_body_sha256 = legacy_upload_migration_record_body_digest(record)?;
    let entry = build_entry(
        LEGACY_UPLOAD_MIGRATION_SCHEMA_VERSION,
        &identity_sha256,
        0,
        LegacyUploadMigrationPhase::Prepared,
        witness_sha256,
        &record_body_sha256,
        GENESIS_ENTRY_SHA256,
    )?;
    let journal = LegacyUploadMigrationJournal {
        schema_version: LEGACY_UPLOAD_MIGRATION_SCHEMA_VERSION,
        identity,
        entries: vec![entry],
    };
    let mut updated = record.clone();
    updated.proofs.insert(
        LEGACY_UPLOAD_MIGRATION_PROOF_NAME.to_string(),
        serde_json::to_value(journal)?,
    );
    validate_legacy_upload_migration_record(&updated)?;
    Ok(updated)
}

fn advance_legacy_upload_migration_record_with_witness(
    record: &AssetRecord,
    phase: LegacyUploadMigrationPhase,
    witness_sha256: &str,
) -> Result<AssetRecord, LegacyUploadMigrationError> {
    validate_digest("witness_sha256", witness_sha256)?;
    let mut journal = validate_journal_for_record(record, false)?;
    let last = journal
        .entries
        .last()
        .ok_or(LegacyUploadMigrationError::JournalEmpty)?;

    if last.phase == phase {
        validate_state(record, phase)?;
        if last.witness_sha256 == witness_sha256 && last.witness_kind == phase.witness_kind() {
            return Ok(record.clone());
        }
        return if phase == LegacyUploadMigrationPhase::Complete {
            Err(LegacyUploadMigrationError::CompleteImmutable)
        } else {
            Err(LegacyUploadMigrationError::ReplayMismatch { phase })
        };
    }
    if last.phase == LegacyUploadMigrationPhase::Complete {
        return Err(LegacyUploadMigrationError::CompleteImmutable);
    }
    let expected = LegacyUploadMigrationPhase::ORDER
        .get(last.phase.index() + 1)
        .copied()
        .ok_or(LegacyUploadMigrationError::CompleteImmutable)?;
    if phase != expected {
        return Err(LegacyUploadMigrationError::InvalidPhaseTransition {
            from: last.phase,
            to: phase,
        });
    }
    validate_state(record, phase)?;

    let identity_sha256 = canonical_digest(&journal.identity)?;
    let record_body_sha256 = legacy_upload_migration_record_body_digest(record)?;
    let entry = build_entry(
        journal.schema_version,
        &identity_sha256,
        journal.entries.len() as u64,
        phase,
        witness_sha256,
        &record_body_sha256,
        &last.entry_sha256,
    )?;
    journal.entries.push(entry);
    let mut updated = record.clone();
    updated.proofs.insert(
        LEGACY_UPLOAD_MIGRATION_PROOF_NAME.to_string(),
        serde_json::to_value(journal)?,
    );
    validate_legacy_upload_migration_record(&updated)?;
    Ok(updated)
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "used by the forthcoming in-module orchestrator")
)]
pub(crate) fn advance_legacy_upload_migration_record(
    record: &AssetRecord,
    authority: &LegacyUploadMigrationPhaseAuthority,
) -> Result<AssetRecord, LegacyUploadMigrationError> {
    validate_phase_authority(authority)?;
    let authorized = authority
        .transition_for_asset(&record.asset_id)
        .ok_or(LegacyUploadMigrationError::PhaseAuthorityMismatch)?;
    let journal = validate_journal_for_record(record, false)?;
    if !phase_authority_matches_identity(authority, &journal.identity) {
        return Err(LegacyUploadMigrationError::PhaseAuthorityMismatch);
    }
    let phase = journal
        .entries
        .last()
        .ok_or(LegacyUploadMigrationError::JournalEmpty)?
        .phase;
    let record_sha256 = legacy_upload_migration_record_digest(record)?;
    let expected_digest = if phase == authority.from {
        &authorized.candidate_record_sha256
    } else if phase == authority.to {
        &authorized.updated_record_sha256
    } else {
        return Err(LegacyUploadMigrationError::PhaseAuthorityMismatch);
    };
    if &record_sha256 != expected_digest {
        return Err(LegacyUploadMigrationError::PhaseAuthorityMismatch);
    }
    let updated = advance_legacy_upload_migration_record_with_witness(
        record,
        authority.to,
        &authorized.witness_sha256,
    )?;
    if legacy_upload_migration_record_digest(&updated)? != authorized.updated_record_sha256 {
        return Err(LegacyUploadMigrationError::PhaseAuthorityMismatch);
    }
    Ok(updated)
}

pub fn validate_legacy_upload_migration_record(
    record: &AssetRecord,
) -> Result<LegacyUploadMigrationJournal, LegacyUploadMigrationError> {
    validate_journal_for_record(record, true)
}

pub fn validate_legacy_upload_migration_record_update(
    expected: &AssetRecord,
    updated: &AssetRecord,
) -> Result<LegacyUploadMigrationTransitionShape, LegacyUploadMigrationCommitError> {
    let expected_journal = validate_legacy_upload_migration_record(expected)
        .map_err(|_| LegacyUploadMigrationCommitError::InvalidRecordTransition)?;
    let updated_journal = validate_legacy_upload_migration_record(updated)
        .map_err(|_| LegacyUploadMigrationCommitError::InvalidRecordTransition)?;
    if expected.asset_id != updated.asset_id
        || expected_journal.identity != updated_journal.identity
    {
        return Err(LegacyUploadMigrationCommitError::InvalidRecordTransition);
    }
    let expected_phase = expected_journal
        .entries
        .last()
        .ok_or(LegacyUploadMigrationCommitError::InvalidRecordTransition)?
        .phase;
    if expected == updated {
        return Ok(LegacyUploadMigrationTransitionShape::Replay {
            phase: expected_phase,
        });
    }
    if updated_journal.entries.len() != expected_journal.entries.len() + 1
        || updated_journal.entries[..expected_journal.entries.len()] != expected_journal.entries
    {
        return Err(LegacyUploadMigrationCommitError::InvalidRecordTransition);
    }
    let updated_phase = updated_journal
        .entries
        .last()
        .ok_or(LegacyUploadMigrationCommitError::InvalidRecordTransition)?
        .phase;
    let policy = LegacyUploadMigrationDeltaPolicy::for_transition(expected_phase, updated_phase)
        .ok_or(LegacyUploadMigrationCommitError::InvalidRecordTransition)?;
    validate_transition_delta(expected, updated, policy)?;
    Ok(LegacyUploadMigrationTransitionShape::Advance {
        from: expected_phase,
        to: updated_phase,
    })
}

pub fn persist_two_legacy_upload_migration_preparations_exact_cas(
    state_store: &AssetStateStore,
    authority: &LegacyUploadMigrationCohortAuthority,
    updates: [LegacyUploadMigrationCasUpdate<'_>; 2],
) -> Result<std::time::Duration, LegacyUploadMigrationCommitError> {
    validate_cohort_authority(authority)
        .map_err(|_| LegacyUploadMigrationCommitError::CohortAuthorityMismatch)?;
    let journals = updates
        .iter()
        .map(validate_preparation_update)
        .collect::<Result<Vec<_>, _>>()?;
    validate_authorized_preparation_pair(authority, &updates, &journals)?;
    validate_exact_pair(&updates, &journals)?;
    let registry = legacy_upload_migration_registry_from_authority(authority)
        .map_err(|_| LegacyUploadMigrationCommitError::CohortAuthorityMismatch)?;
    let write_authority = LegacyUploadMigrationStateStoreWriteAuthority {
        registry,
        mode: LegacyUploadMigrationRegistryWriteMode::InsertOnceOrExactReplay,
    };
    persist_exact_pair(state_store, &write_authority, &updates)
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "used by the forthcoming in-module orchestrator")
)]
pub(crate) fn persist_two_legacy_upload_migration_records_exact_cas(
    state_store: &AssetStateStore,
    authority: &LegacyUploadMigrationPhaseAuthority,
    updates: [LegacyUploadMigrationCasUpdate<'_>; 2],
) -> Result<std::time::Duration, LegacyUploadMigrationCommitError> {
    validate_phase_authority(authority)
        .map_err(|_| LegacyUploadMigrationCommitError::PhaseAuthorityMismatch)?;
    let mut journals = Vec::with_capacity(updates.len());
    let mut shapes = Vec::with_capacity(updates.len());
    for update in &updates {
        shapes.push(validate_legacy_upload_migration_record_update(
            update.expected,
            update.updated,
        )?);
        journals.push(
            validate_legacy_upload_migration_record(update.updated)
                .map_err(|_| LegacyUploadMigrationCommitError::InvalidRecordTransition)?,
        );
    }
    validate_exact_pair(&updates, &journals)?;
    if shapes[0] != shapes[1] {
        return Err(LegacyUploadMigrationCommitError::BatchTransitionMismatch);
    }
    validate_authorized_phase_pair(authority, &updates, &journals, shapes[0])?;
    let registry = legacy_upload_migration_registry_from_journals(&journals)
        .map_err(|_| LegacyUploadMigrationCommitError::PhaseAuthorityMismatch)?;
    let write_authority = LegacyUploadMigrationStateStoreWriteAuthority {
        registry,
        mode: LegacyUploadMigrationRegistryWriteMode::VerifyExact,
    };
    persist_exact_pair(state_store, &write_authority, &updates)
}

#[cfg(test)]
fn persist_two_legacy_upload_migration_records_exact_cas_internal(
    state_store: &AssetStateStore,
    updates: [LegacyUploadMigrationCasUpdate<'_>; 2],
) -> Result<std::time::Duration, LegacyUploadMigrationCommitError> {
    let mut journals = Vec::with_capacity(updates.len());
    let mut shapes = Vec::with_capacity(updates.len());
    for update in &updates {
        shapes.push(validate_legacy_upload_migration_record_update(
            update.expected,
            update.updated,
        )?);
        journals.push(
            validate_legacy_upload_migration_record(update.updated)
                .map_err(|_| LegacyUploadMigrationCommitError::InvalidRecordTransition)?,
        );
    }
    validate_exact_pair(&updates, &journals)?;
    if shapes[0] != shapes[1] {
        return Err(LegacyUploadMigrationCommitError::BatchTransitionMismatch);
    }
    let registry = legacy_upload_migration_registry_from_journals(&journals)
        .map_err(|_| LegacyUploadMigrationCommitError::PhaseAuthorityMismatch)?;
    let write_authority = LegacyUploadMigrationStateStoreWriteAuthority {
        registry,
        mode: LegacyUploadMigrationRegistryWriteMode::VerifyExact,
    };
    persist_exact_pair(state_store, &write_authority, &updates)
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "used by the forthcoming in-module orchestrator")
)]
fn validate_authorized_phase_pair(
    authority: &LegacyUploadMigrationPhaseAuthority,
    updates: &[LegacyUploadMigrationCasUpdate<'_>; 2],
    journals: &[LegacyUploadMigrationJournal],
    shape: LegacyUploadMigrationTransitionShape,
) -> Result<(), LegacyUploadMigrationCommitError> {
    for (update, journal) in updates.iter().zip(journals) {
        let authorized = authority
            .transition_for_asset(&update.updated.asset_id)
            .ok_or(LegacyUploadMigrationCommitError::PhaseAuthorityMismatch)?;
        if !phase_authority_matches_identity(authority, &journal.identity) {
            return Err(LegacyUploadMigrationCommitError::PhaseAuthorityMismatch);
        }
        let expected_sha256 = legacy_upload_migration_record_digest(update.expected)
            .map_err(|_| LegacyUploadMigrationCommitError::PhaseAuthorityMismatch)?;
        let updated_sha256 = legacy_upload_migration_record_digest(update.updated)
            .map_err(|_| LegacyUploadMigrationCommitError::PhaseAuthorityMismatch)?;
        let digest_matches = match shape {
            LegacyUploadMigrationTransitionShape::Advance { from, to } => {
                from == authority.from
                    && to == authority.to
                    && expected_sha256 == authorized.expected_record_sha256
                    && updated_sha256 == authorized.updated_record_sha256
            }
            LegacyUploadMigrationTransitionShape::Replay { phase } => {
                phase == authority.to
                    && expected_sha256 == authorized.updated_record_sha256
                    && updated_sha256 == authorized.updated_record_sha256
            }
        };
        let witness_matches = journal.entries.last().is_some_and(|entry| {
            entry.phase == authority.to && entry.witness_sha256 == authorized.witness_sha256
        });
        if !digest_matches || !witness_matches {
            return Err(LegacyUploadMigrationCommitError::PhaseAuthorityMismatch);
        }
    }
    if authority.transitions.iter().any(|authorized| {
        !updates
            .iter()
            .any(|update| update.updated.asset_id == authorized.asset_id)
    }) {
        return Err(LegacyUploadMigrationCommitError::PhaseAuthorityMismatch);
    }
    Ok(())
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "used by the forthcoming in-module orchestrator")
)]
fn validate_phase_authority(
    authority: &LegacyUploadMigrationPhaseAuthority,
) -> Result<(), LegacyUploadMigrationError> {
    for (field, value) in [
        ("migration_id", authority.migration_id.as_str()),
        ("evidence_sha256", authority.evidence_sha256.as_str()),
        ("cohort_sha256", authority.cohort_sha256.as_str()),
    ] {
        validate_digest(field, value)?;
    }
    if LegacyUploadMigrationDeltaPolicy::for_transition(authority.from, authority.to).is_none()
        || authority.transitions[0].asset_id == authority.transitions[1].asset_id
    {
        return Err(LegacyUploadMigrationError::PhaseAuthorityMismatch);
    }
    for transition in &authority.transitions {
        validate_remote_identity("asset_id", &transition.asset_id)?;
        for (field, value) in [
            (
                "expected_record_sha256",
                transition.expected_record_sha256.as_str(),
            ),
            (
                "candidate_record_sha256",
                transition.candidate_record_sha256.as_str(),
            ),
            (
                "updated_record_sha256",
                transition.updated_record_sha256.as_str(),
            ),
            ("payload_sha256", transition.payload_sha256.as_str()),
            ("witness_sha256", transition.witness_sha256.as_str()),
        ] {
            validate_digest(field, value)?;
        }
        if transition.witness_sha256 != phase_authority_witness_sha256(authority, transition)? {
            return Err(LegacyUploadMigrationError::PhaseAuthorityMismatch);
        }
    }
    Ok(())
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "used by the forthcoming in-module orchestrator")
)]
fn phase_authority_witness_sha256(
    authority: &LegacyUploadMigrationPhaseAuthority,
    transition: &LegacyUploadMigrationAuthorizedPhaseTransition,
) -> Result<String, LegacyUploadMigrationError> {
    canonical_digest(&PhaseWitnessDigestInput {
        schema_version: LEGACY_UPLOAD_MIGRATION_SCHEMA_VERSION,
        migration_id: &authority.migration_id,
        evidence_sha256: &authority.evidence_sha256,
        cohort_sha256: &authority.cohort_sha256,
        asset_id: &transition.asset_id,
        from: authority.from,
        to: authority.to,
        expected_record_sha256: &transition.expected_record_sha256,
        candidate_record_sha256: &transition.candidate_record_sha256,
        payload_sha256: &transition.payload_sha256,
    })
}

/// Mints the only authority accepted by the exact-two phase commit path after
/// both phase-specific receipts have been validated. `expected` is the durable
/// CAS basis; `candidates` contains only the state changes permitted by the
/// target phase's delta policy.
fn build_legacy_upload_migration_phase_authority<T: Serialize>(
    expected: [&AssetRecord; 2],
    candidates: [&AssetRecord; 2],
    to: LegacyUploadMigrationPhase,
    receipts: [&T; 2],
) -> Result<(LegacyUploadMigrationPhaseAuthority, [AssetRecord; 2]), LegacyUploadMigrationError> {
    let journals = candidates
        .each_ref()
        .map(|candidate| validate_journal_for_record(candidate, false));
    let [left, right] = journals;
    let [left, right] = [left?, right?];
    let from = left
        .entries
        .last()
        .ok_or(LegacyUploadMigrationError::JournalEmpty)?
        .phase;
    if right
        .entries
        .last()
        .ok_or(LegacyUploadMigrationError::JournalEmpty)?
        .phase
        != from
        || left.identity.migration_id != right.identity.migration_id
        || left.identity.evidence_sha256 != right.identity.evidence_sha256
        || left.identity.cohort_sha256 != right.identity.cohort_sha256
        || LegacyUploadMigrationPhase::ORDER
            .get(from.index() + 1)
            .copied()
            != Some(to)
    {
        return Err(LegacyUploadMigrationError::PhaseAuthorityMismatch);
    }

    let transitions = std::array::from_fn(|index| {
        Ok(LegacyUploadMigrationAuthorizedPhaseTransition {
            asset_id: candidates[index].asset_id.clone(),
            expected_record_sha256: legacy_upload_migration_record_digest(expected[index])?,
            candidate_record_sha256: legacy_upload_migration_record_digest(candidates[index])?,
            updated_record_sha256: canonical_digest(&"pending_updated_record")?,
            payload_sha256: canonical_digest(receipts[index])?,
            witness_sha256: canonical_digest(&"pending_phase_witness")?,
        })
    });
    let [left_transition, right_transition]: [Result<
        LegacyUploadMigrationAuthorizedPhaseTransition,
        LegacyUploadMigrationError,
    >; 2] = transitions;
    let mut authority = LegacyUploadMigrationPhaseAuthority {
        migration_id: left.identity.migration_id,
        evidence_sha256: left.identity.evidence_sha256,
        cohort_sha256: left.identity.cohort_sha256,
        from,
        to,
        transitions: [left_transition?, right_transition?],
    };
    for index in 0..authority.transitions.len() {
        authority.transitions[index].witness_sha256 =
            phase_authority_witness_sha256(&authority, &authority.transitions[index])?;
    }
    let updated = std::array::from_fn(|index| {
        advance_legacy_upload_migration_record_with_witness(
            candidates[index],
            to,
            &authority.transitions[index].witness_sha256,
        )
    });
    let [left_updated, right_updated] = updated;
    let updated = [left_updated?, right_updated?];
    for (transition, record) in authority.transitions.iter_mut().zip(&updated) {
        transition.updated_record_sha256 = legacy_upload_migration_record_digest(record)?;
    }
    validate_phase_authority(&authority)?;
    Ok((authority, updated))
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "used by the forthcoming in-module orchestrator")
)]
fn phase_authority_matches_identity(
    authority: &LegacyUploadMigrationPhaseAuthority,
    identity: &LegacyUploadMigrationIdentity,
) -> bool {
    identity.migration_id == authority.migration_id
        && identity.evidence_sha256 == authority.evidence_sha256
        && identity.cohort_sha256 == authority.cohort_sha256
}

fn validate_preparation_update(
    update: &LegacyUploadMigrationCasUpdate<'_>,
) -> Result<LegacyUploadMigrationJournal, LegacyUploadMigrationCommitError> {
    let expected_is_prepared = update
        .expected
        .proofs
        .contains_key(LEGACY_UPLOAD_MIGRATION_PROOF_NAME);
    if (expected_is_prepared && update.expected != update.updated)
        || (!expected_is_prepared
            && !records_match_except_migration_journal(update.expected, update.updated))
    {
        return Err(LegacyUploadMigrationCommitError::InvalidRecordTransition);
    }
    let journal = validate_legacy_upload_migration_record(update.updated)
        .map_err(|_| LegacyUploadMigrationCommitError::InvalidRecordTransition)?;
    if journal.entries.len() != 1
        || journal.entries[0].phase != LegacyUploadMigrationPhase::Prepared
        || (!expected_is_prepared
            && journal.identity.source_record_sha256
                != legacy_upload_migration_record_digest(update.expected)
                    .map_err(|_| LegacyUploadMigrationCommitError::InvalidRecordTransition)?)
    {
        return Err(LegacyUploadMigrationCommitError::InvalidRecordTransition);
    }
    Ok(journal)
}

fn validate_authorized_preparation_pair(
    authority: &LegacyUploadMigrationCohortAuthority,
    updates: &[LegacyUploadMigrationCasUpdate<'_>; 2],
    journals: &[LegacyUploadMigrationJournal],
) -> Result<(), LegacyUploadMigrationCommitError> {
    if journals.len() != 2 {
        return Err(LegacyUploadMigrationCommitError::CohortAuthorityMismatch);
    }
    for (update, journal) in updates.iter().zip(journals) {
        let authorized = authority
            .preparation_for_asset(&update.updated.asset_id)
            .ok_or(LegacyUploadMigrationCommitError::CohortAuthorityMismatch)?;
        if journal.identity != authorized.identity
            || journal.entries.len() != 1
            || journal.entries[0].witness_sha256 != authorized.prepared_witness_sha256
        {
            return Err(LegacyUploadMigrationCommitError::CohortAuthorityMismatch);
        }
    }
    if authority.preparations.iter().any(|authorized| {
        !updates
            .iter()
            .any(|update| update.updated.asset_id == authorized.identity.asset_id)
    }) {
        return Err(LegacyUploadMigrationCommitError::CohortAuthorityMismatch);
    }
    Ok(())
}

fn validate_exact_pair(
    updates: &[LegacyUploadMigrationCasUpdate<'_>; 2],
    journals: &[LegacyUploadMigrationJournal],
) -> Result<(), LegacyUploadMigrationCommitError> {
    if updates
        .iter()
        .any(|update| update.expected.asset_id != update.updated.asset_id)
    {
        return Err(LegacyUploadMigrationCommitError::MismatchedAssetIds);
    }
    if updates[0].updated.asset_id == updates[1].updated.asset_id {
        return Err(LegacyUploadMigrationCommitError::DuplicateAsset);
    }
    let cohort = &journals[0].identity;
    if journals[1].identity.migration_id != cohort.migration_id
        || journals[1].identity.evidence_sha256 != cohort.evidence_sha256
        || journals[1].identity.cohort_sha256 != cohort.cohort_sha256
    {
        return Err(LegacyUploadMigrationCommitError::CohortMismatch);
    }
    Ok(())
}

fn persist_exact_pair(
    state_store: &AssetStateStore,
    authority: &LegacyUploadMigrationStateStoreWriteAuthority,
    updates: &[LegacyUploadMigrationCasUpdate<'_>; 2],
) -> Result<std::time::Duration, LegacyUploadMigrationCommitError> {
    state_store
        .persist_records_exact_cas_atomic_with_legacy_upload_migration_authority(
            authority,
            updates.iter().map(|update| AssetRecordExactCasUpdate {
                expected: update.expected,
                updated: update.updated,
            }),
        )
        .map_err(LegacyUploadMigrationCommitError::StateStore)
}

fn records_match_except_migration_journal(expected: &AssetRecord, updated: &AssetRecord) -> bool {
    let expected_proofs = proofs_without_migration_journal(expected);
    let updated_proofs = proofs_without_migration_journal(updated);
    expected.asset_id == updated.asset_id
        && expected.raw_path == updated.raw_path
        && expected.state == updated.state
        && expected.failures == updated.failures
        && expected.updated_at == updated.updated_at
        && expected_proofs == updated_proofs
}

fn validate_transition_delta(
    expected: &AssetRecord,
    updated: &AssetRecord,
    policy: LegacyUploadMigrationDeltaPolicy,
) -> Result<(), LegacyUploadMigrationCommitError> {
    if expected.asset_id != updated.asset_id
        || expected.raw_path != updated.raw_path
        || expected.failures != updated.failures
        || expected.updated_at != updated.updated_at
    {
        return Err(LegacyUploadMigrationCommitError::InvalidRecordTransition);
    }

    let valid = match policy {
        LegacyUploadMigrationDeltaPolicy::JournalOnly => {
            expected.state == updated.state
                && proofs_without_migration_journal(expected)
                    == proofs_without_migration_journal(updated)
        }
        LegacyUploadMigrationDeltaPolicy::ResetLegacyLineage => {
            expected.state == State::UploadVerified
                && updated.state == State::NasVerified
                && exact_proof_delta(
                    expected,
                    updated,
                    &[
                        CONVERSION_PROOF,
                        CONVERSION_PERFORMANCE_PROOF,
                        HEIC_PROOF,
                        UPLOAD_PROOF,
                        ICLOUDPD_LOCAL_MIRROR_PROOF,
                    ],
                    &[],
                )
        }
        LegacyUploadMigrationDeltaPolicy::InstallVerifiedConversion => {
            expected.state == State::NasVerified
                && updated.state == State::ConversionVerified
                && exact_proof_delta(
                    expected,
                    updated,
                    &[],
                    &[CONVERSION_PROOF, CONVERSION_PERFORMANCE_PROOF, HEIC_PROOF],
                )
                && validate_verified_conversion_delta(expected, updated)
        }
        LegacyUploadMigrationDeltaPolicy::InstallVerifiedUpload => {
            expected.state == State::ConversionVerified
                && updated.state == State::UploadVerified
                && exact_proof_delta(expected, updated, &[], &[UPLOAD_PROOF])
                && validate_verified_upload_delta(expected, updated)
        }
        LegacyUploadMigrationDeltaPolicy::InstallVerifiedMirror => {
            expected.state == State::UploadVerified
                && updated.state == State::UploadVerified
                && exact_proof_delta(expected, updated, &[], &[ICLOUDPD_LOCAL_MIRROR_PROOF])
                && validate_verified_mirror_delta(expected, updated)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(LegacyUploadMigrationCommitError::InvalidRecordTransition)
    }
}

fn proofs_without_migration_journal(record: &AssetRecord) -> BTreeMap<String, Value> {
    let mut proofs = record.proofs.clone();
    proofs.remove(LEGACY_UPLOAD_MIGRATION_PROOF_NAME);
    proofs
}

fn exact_proof_delta(
    expected: &AssetRecord,
    updated: &AssetRecord,
    removed: &[&str],
    added: &[&str],
) -> bool {
    let mut desired = proofs_without_migration_journal(expected);
    let updated_proofs = proofs_without_migration_journal(updated);
    for proof_name in removed {
        if desired.remove(*proof_name).is_none() {
            return false;
        }
    }
    for proof_name in added {
        if desired.contains_key(*proof_name) {
            return false;
        }
        let Some(value) = updated_proofs.get(*proof_name) else {
            return false;
        };
        desired.insert((*proof_name).to_string(), value.clone());
    }
    desired == updated_proofs
}

fn decode_canonical_proof<T>(record: &AssetRecord, proof_name: &str) -> Option<T>
where
    T: DeserializeOwned + Serialize,
{
    let value = record.proofs.get(proof_name)?;
    let proof: T = serde_json::from_value(value.clone()).ok()?;
    (serde_json::to_value(&proof).ok()? == *value).then_some(proof)
}

fn manifest_with_record(record: &AssetRecord) -> Option<Manifest> {
    validate_journal_for_record(record, false).ok()?;
    let mut simulated = record.clone();
    simulated
        .proofs
        .remove(LEGACY_UPLOAD_MIGRATION_PROOF_NAME)?;
    let mut manifest = Manifest::new();
    manifest.upsert_trusted(simulated);
    Some(manifest)
}

fn validate_verified_conversion_delta(expected: &AssetRecord, updated: &AssetRecord) -> bool {
    let Some(delta) = VerifiedConversionDelta::from_record(updated) else {
        return false;
    };
    if validate_digest("heic_sha256", &delta.conversion.heic_sha256).is_err() {
        return false;
    }
    let Some(mut manifest) = manifest_with_record(expected) else {
        return false;
    };
    if record_current_conversion_result(
        &mut manifest,
        &expected.asset_id,
        ConversionResultInput {
            heic_path: delta.conversion.heic_path,
            heic_sha256: delta.conversion.heic_sha256,
            size_bytes: delta.conversion.size_bytes,
            source_binding: delta.conversion.source_binding,
        },
    )
    .is_err()
        || record_current_conversion_performance(
            &mut manifest,
            &expected.asset_id,
            ConversionPerformanceInput {
                measured_at_unix_seconds: delta.performance.measured_at_unix_seconds,
                conversion_tool: delta.performance.conversion_tool,
                conversion_tool_version: delta.performance.conversion_tool_version,
                heic_quality: delta.performance.heic_quality,
                convert_wall_time_millis: delta.performance.convert_wall_time_millis,
                total_wall_time_millis: delta.performance.total_wall_time_millis,
                user_cpu_time_millis: delta.performance.user_cpu_time_millis,
                system_cpu_time_millis: delta.performance.system_cpu_time_millis,
                peak_rss_kib: delta.performance.peak_rss_kib,
                conversion_command_timings: delta.performance.conversion_command_timings,
            },
        )
        .is_err()
        || record_current_heic_verification(
            &mut manifest,
            &expected.asset_id,
            HeicVerificationInput {
                heic_path: delta.heic.heic_path,
                heic_sha256: delta.heic.heic_sha256,
                size_bytes: delta.heic.size_bytes,
                heif_info_ok: delta.heic.heif_info_ok,
                metadata_copied: delta.heic.metadata_copied,
                visual_content_ok: delta.heic.visual_content_ok,
                visual_match_ok: delta.heic.visual_match_ok,
                visual_rmse_ppm: delta.heic.visual_rmse_ppm,
                visual_mae_ppm: delta.heic.visual_mae_ppm,
            },
        )
        .is_err()
    {
        return false;
    }
    generated_proofs_match(
        &manifest,
        updated,
        &[CONVERSION_PROOF, CONVERSION_PERFORMANCE_PROOF, HEIC_PROOF],
    )
}

fn validate_verified_upload_delta(expected: &AssetRecord, updated: &AssetRecord) -> bool {
    let Some(delta) = VerifiedUploadDelta::from_record(updated) else {
        return false;
    };
    let Some(mut manifest) = manifest_with_record(expected) else {
        return false;
    };
    if record_upload_proof(&mut manifest, &expected.asset_id, delta.upload).is_err()
        || uploaded_heic_delete_request(&manifest, &expected.asset_id).is_err()
    {
        return false;
    }
    generated_proofs_match(&manifest, updated, &[UPLOAD_PROOF])
}

fn validate_verified_mirror_delta(expected: &AssetRecord, updated: &AssetRecord) -> bool {
    let Some(delta) = VerifiedMirrorDelta::from_record(updated) else {
        return false;
    };
    let Some(mut manifest) = manifest_with_record(expected) else {
        return false;
    };
    if record_icloudpd_local_mirror_proof(&mut manifest, &expected.asset_id, delta.mirror).is_err()
    {
        return false;
    }
    generated_proofs_match(&manifest, updated, &[ICLOUDPD_LOCAL_MIRROR_PROOF])
}

fn generated_proofs_match(
    generated: &Manifest,
    updated: &AssetRecord,
    proof_names: &[&str],
) -> bool {
    let Ok(generated) = generated.get(&updated.asset_id) else {
        return false;
    };
    proof_names
        .iter()
        .all(|proof_name| generated.proofs.get(*proof_name) == updated.proofs.get(*proof_name))
}

impl VerifiedConversionDelta {
    fn from_record(record: &AssetRecord) -> Option<Self> {
        Some(Self {
            conversion: decode_canonical_proof(record, CONVERSION_PROOF)?,
            performance: decode_canonical_proof(record, CONVERSION_PERFORMANCE_PROOF)?,
            heic: decode_canonical_proof(record, HEIC_PROOF)?,
        })
    }
}

impl VerifiedUploadDelta {
    fn from_record(record: &AssetRecord) -> Option<Self> {
        Some(Self {
            upload: decode_canonical_proof(record, UPLOAD_PROOF)?,
        })
    }
}

impl VerifiedMirrorDelta {
    fn from_record(record: &AssetRecord) -> Option<Self> {
        Some(Self {
            mirror: decode_canonical_proof(record, ICLOUDPD_LOCAL_MIRROR_PROOF)?,
        })
    }
}

fn validate_journal_for_record(
    record: &AssetRecord,
    validate_current_state: bool,
) -> Result<LegacyUploadMigrationJournal, LegacyUploadMigrationError> {
    let value = record
        .proofs
        .get(LEGACY_UPLOAD_MIGRATION_PROOF_NAME)
        .ok_or(LegacyUploadMigrationError::JournalMissing)?;
    let journal: LegacyUploadMigrationJournal = serde_json::from_value(value.clone())?;
    if journal.schema_version != LEGACY_UPLOAD_MIGRATION_SCHEMA_VERSION {
        return Err(LegacyUploadMigrationError::UnsupportedSchemaVersion {
            actual: journal.schema_version,
        });
    }
    validate_identity(&journal.identity)?;
    if journal.identity.asset_id != record.asset_id {
        return Err(LegacyUploadMigrationError::IdentityMismatch);
    }
    if journal.entries.is_empty() {
        return Err(LegacyUploadMigrationError::JournalEmpty);
    }

    let identity_sha256 = canonical_digest(&journal.identity)?;
    let mut previous = GENESIS_ENTRY_SHA256;
    for (index, entry) in journal.entries.iter().enumerate() {
        let expected_phase = LegacyUploadMigrationPhase::ORDER
            .get(index)
            .copied()
            .ok_or(LegacyUploadMigrationError::JournalTampered {
                field: "phase_count",
            })?;
        if entry.ordinal != index as u64 {
            return Err(LegacyUploadMigrationError::JournalTampered { field: "ordinal" });
        }
        if entry.phase != expected_phase {
            return Err(LegacyUploadMigrationError::JournalTampered { field: "phase" });
        }
        if entry.witness_kind != entry.phase.witness_kind() {
            return Err(LegacyUploadMigrationError::JournalTampered {
                field: "witness_kind",
            });
        }
        validate_digest("witness_sha256", &entry.witness_sha256)?;
        validate_digest("record_body_sha256", &entry.record_body_sha256)?;
        validate_digest("previous_entry_sha256", &entry.previous_entry_sha256)?;
        validate_digest("entry_sha256", &entry.entry_sha256)?;
        if entry.previous_entry_sha256 != previous {
            return Err(LegacyUploadMigrationError::JournalTampered {
                field: "previous_entry_sha256",
            });
        }
        let expected_digest = entry_digest(
            journal.schema_version,
            &identity_sha256,
            entry.ordinal,
            entry.phase,
            entry.witness_kind,
            &entry.witness_sha256,
            &entry.record_body_sha256,
            &entry.previous_entry_sha256,
        )?;
        if entry.entry_sha256 != expected_digest {
            return Err(LegacyUploadMigrationError::JournalTampered {
                field: "entry_sha256",
            });
        }
        previous = &entry.entry_sha256;
    }
    if validate_current_state {
        if journal
            .entries
            .last()
            .expect("nonempty journal")
            .record_body_sha256
            != legacy_upload_migration_record_body_digest(record)?
        {
            return Err(LegacyUploadMigrationError::JournalTampered {
                field: "record_body_sha256",
            });
        }
        validate_state(
            record,
            journal.entries.last().expect("nonempty journal").phase,
        )?;
    }
    Ok(journal)
}

fn build_entry(
    schema_version: u64,
    identity_sha256: &str,
    ordinal: u64,
    phase: LegacyUploadMigrationPhase,
    witness_sha256: &str,
    record_body_sha256: &str,
    previous_entry_sha256: &str,
) -> Result<LegacyUploadMigrationPhaseEntry, LegacyUploadMigrationError> {
    let witness_kind = phase.witness_kind();
    let entry_sha256 = entry_digest(
        schema_version,
        identity_sha256,
        ordinal,
        phase,
        witness_kind,
        witness_sha256,
        record_body_sha256,
        previous_entry_sha256,
    )?;
    Ok(LegacyUploadMigrationPhaseEntry {
        ordinal,
        phase,
        witness_kind,
        witness_sha256: witness_sha256.to_string(),
        record_body_sha256: record_body_sha256.to_string(),
        previous_entry_sha256: previous_entry_sha256.to_string(),
        entry_sha256,
    })
}

#[allow(clippy::too_many_arguments)]
fn entry_digest(
    schema_version: u64,
    identity_sha256: &str,
    ordinal: u64,
    phase: LegacyUploadMigrationPhase,
    witness_kind: LegacyUploadMigrationWitnessKind,
    witness_sha256: &str,
    record_body_sha256: &str,
    previous_entry_sha256: &str,
) -> Result<String, LegacyUploadMigrationError> {
    canonical_digest(&EntryDigestInput {
        schema_version,
        identity_sha256,
        ordinal,
        phase,
        witness_kind,
        witness_sha256,
        record_body_sha256,
        previous_entry_sha256,
    })
}

fn canonical_digest(value: &impl Serialize) -> Result<String, LegacyUploadMigrationError> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn legacy_upload_migration_record_body_digest(
    record: &AssetRecord,
) -> Result<String, LegacyUploadMigrationError> {
    let proofs = record
        .proofs
        .iter()
        .filter(|(name, _)| name.as_str() != LEGACY_UPLOAD_MIGRATION_PROOF_NAME)
        .map(|(name, value)| (name.as_str(), value))
        .collect::<BTreeMap<_, _>>();
    canonical_digest(&RecordBodyDigestInput {
        asset_id: &record.asset_id,
        raw_path: &record.raw_path,
        state: record.state,
        proofs,
        failures: &record.failures,
        updated_at: &record.updated_at,
    })
}

fn legacy_upload_migration_registry_from_identities(
    identities: [&LegacyUploadMigrationIdentity; 2],
) -> Result<LegacyUploadMigrationRegistry, LegacyUploadMigrationError> {
    let mut identities = identities;
    identities.sort_by(|left, right| left.asset_id.cmp(&right.asset_id));
    if identities[0].asset_id == identities[1].asset_id
        || identities[0].migration_id != identities[1].migration_id
        || identities[0].evidence_sha256 != identities[1].evidence_sha256
        || identities[0].cohort_sha256 != identities[1].cohort_sha256
        || identities[0].quarantine_plan != identities[1].quarantine_plan
    {
        return Err(LegacyUploadMigrationError::CohortAuthorityMismatch);
    }
    for identity in identities {
        validate_identity(identity)?;
    }
    let registry_asset = |identity: &LegacyUploadMigrationIdentity| {
        Ok::<_, LegacyUploadMigrationError>(LegacyUploadMigrationRegistryAsset {
            asset_id: identity.asset_id.clone(),
            identity_sha256: canonical_digest(identity)?,
            source_record_sha256: identity.source_record_sha256.clone(),
            original_asset_identity_sha256: identity.original_asset_identity_sha256.clone(),
            old_conversion_lineage_sha256: identity.old_conversion_lineage_sha256.clone(),
            old_upload_lineage_sha256: identity.old_upload_lineage_sha256.clone(),
            old_mirror_lineage_sha256: identity.old_mirror_lineage_sha256.clone(),
        })
    };
    let assets = [
        registry_asset(identities[0])?,
        registry_asset(identities[1])?,
    ];
    let mut registry = LegacyUploadMigrationRegistry {
        schema_version: LEGACY_UPLOAD_MIGRATION_REGISTRY_SCHEMA_VERSION,
        migration_id: identities[0].migration_id.clone(),
        evidence_sha256: identities[0].evidence_sha256.clone(),
        cohort_sha256: identities[0].cohort_sha256.clone(),
        quarantine_plan: identities[0].quarantine_plan.clone(),
        assets,
        registry_sha256: String::new(),
    };
    registry.registry_sha256 = legacy_upload_migration_registry_digest(&registry)?;
    validate_legacy_upload_migration_registry(&registry)?;
    Ok(registry)
}

fn legacy_upload_migration_registry_from_authority(
    authority: &LegacyUploadMigrationCohortAuthority,
) -> Result<LegacyUploadMigrationRegistry, LegacyUploadMigrationError> {
    legacy_upload_migration_registry_from_identities([
        &authority.preparations[0].identity,
        &authority.preparations[1].identity,
    ])
}

fn legacy_upload_migration_registry_from_journals(
    journals: &[LegacyUploadMigrationJournal],
) -> Result<LegacyUploadMigrationRegistry, LegacyUploadMigrationError> {
    if journals.len() != 2 {
        return Err(LegacyUploadMigrationError::RegistryCohortMismatch);
    }
    legacy_upload_migration_registry_from_identities([&journals[0].identity, &journals[1].identity])
}

fn legacy_upload_migration_registry_digest(
    registry: &LegacyUploadMigrationRegistry,
) -> Result<String, LegacyUploadMigrationError> {
    canonical_digest(&LegacyUploadMigrationRegistryDigestInput {
        schema_version: registry.schema_version,
        migration_id: &registry.migration_id,
        evidence_sha256: &registry.evidence_sha256,
        cohort_sha256: &registry.cohort_sha256,
        quarantine_plan: &registry.quarantine_plan,
        assets: &registry.assets,
    })
}

pub(crate) fn validate_legacy_upload_migration_registry(
    registry: &LegacyUploadMigrationRegistry,
) -> Result<(), LegacyUploadMigrationError> {
    if registry.schema_version != LEGACY_UPLOAD_MIGRATION_REGISTRY_SCHEMA_VERSION {
        return Err(LegacyUploadMigrationError::RegistryTampered);
    }
    for (field, value) in [
        ("migration_id", registry.migration_id.as_str()),
        ("evidence_sha256", registry.evidence_sha256.as_str()),
        ("cohort_sha256", registry.cohort_sha256.as_str()),
        ("registry_sha256", registry.registry_sha256.as_str()),
    ] {
        validate_digest(field, value)?;
    }
    validate_quarantine_plan(&registry.quarantine_plan)?;
    if registry.assets[0].asset_id >= registry.assets[1].asset_id {
        return Err(LegacyUploadMigrationError::RegistryTampered);
    }
    for asset in &registry.assets {
        validate_remote_identity("asset_id", &asset.asset_id)?;
        for (field, value) in [
            ("identity_sha256", asset.identity_sha256.as_str()),
            ("source_record_sha256", asset.source_record_sha256.as_str()),
            (
                "original_asset_identity_sha256",
                asset.original_asset_identity_sha256.as_str(),
            ),
            (
                "old_conversion_lineage_sha256",
                asset.old_conversion_lineage_sha256.as_str(),
            ),
            (
                "old_upload_lineage_sha256",
                asset.old_upload_lineage_sha256.as_str(),
            ),
            (
                "old_mirror_lineage_sha256",
                asset.old_mirror_lineage_sha256.as_str(),
            ),
        ] {
            validate_digest(field, value)?;
        }
    }
    if registry.registry_sha256 != legacy_upload_migration_registry_digest(registry)? {
        return Err(LegacyUploadMigrationError::RegistryTampered);
    }
    Ok(())
}

pub(crate) fn validate_legacy_upload_migration_registry_binding(
    manifest: &Manifest,
    require_complete: bool,
) -> Result<(), LegacyUploadMigrationError> {
    let journal_records = manifest
        .records()
        .values()
        .filter(|record| {
            record
                .proofs
                .contains_key(LEGACY_UPLOAD_MIGRATION_PROOF_NAME)
        })
        .collect::<Vec<_>>();
    let Some(registry) = manifest.legacy_upload_migration_registry() else {
        return if journal_records.is_empty() {
            Ok(())
        } else {
            Err(LegacyUploadMigrationError::RegistryMissing)
        };
    };
    validate_legacy_upload_migration_registry(registry)?;
    if journal_records.len() != 2 {
        return Err(LegacyUploadMigrationError::RegistryCohortMismatch);
    }
    let journals = journal_records
        .iter()
        .map(|record| validate_legacy_upload_migration_record(record))
        .collect::<Result<Vec<_>, _>>()?;
    if journals[0].entries.last().map(|entry| entry.phase)
        != journals[1].entries.last().map(|entry| entry.phase)
    {
        return Err(LegacyUploadMigrationError::RegistryCohortMismatch);
    }
    if require_complete {
        let phase = journals[0]
            .entries
            .last()
            .ok_or(LegacyUploadMigrationError::JournalEmpty)?
            .phase;
        if phase != LegacyUploadMigrationPhase::Complete {
            return Err(LegacyUploadMigrationError::IncompleteJournal { phase });
        }
    }
    let expected = legacy_upload_migration_registry_from_journals(&journals)?;
    if &expected != registry {
        return Err(LegacyUploadMigrationError::RegistryCohortMismatch);
    }
    Ok(())
}

fn validate_identity(
    identity: &LegacyUploadMigrationIdentity,
) -> Result<(), LegacyUploadMigrationError> {
    for (field, value) in [
        ("migration_id", identity.migration_id.as_str()),
        ("evidence_sha256", identity.evidence_sha256.as_str()),
        ("cohort_sha256", identity.cohort_sha256.as_str()),
        (
            "source_record_sha256",
            identity.source_record_sha256.as_str(),
        ),
        ("destination_sha256", identity.destination_sha256.as_str()),
        (
            "original_asset_identity_sha256",
            identity.original_asset_identity_sha256.as_str(),
        ),
        (
            "old_conversion_lineage_sha256",
            identity.old_conversion_lineage_sha256.as_str(),
        ),
        (
            "old_upload_lineage_sha256",
            identity.old_upload_lineage_sha256.as_str(),
        ),
        (
            "old_mirror_lineage_sha256",
            identity.old_mirror_lineage_sha256.as_str(),
        ),
    ] {
        validate_digest(field, value)?;
    }
    validate_quarantine_plan(&identity.quarantine_plan)?;
    for (field, value) in [
        ("asset_id", identity.asset_id.as_str()),
        (
            "old_uploaded_asset_id",
            identity.old_uploaded_asset_id.as_str(),
        ),
        (
            "old_uploaded_master_id",
            identity.old_uploaded_master_id.as_str(),
        ),
    ] {
        validate_remote_identity(field, value)?;
    }
    Ok(())
}

fn validate_cohort_authority(
    authority: &LegacyUploadMigrationCohortAuthority,
) -> Result<(), LegacyUploadMigrationError> {
    let [first, second] = &authority.preparations;
    validate_identity(&first.identity)?;
    validate_identity(&second.identity)?;
    validate_digest("prepared_witness_sha256", &first.prepared_witness_sha256)?;
    validate_digest("prepared_witness_sha256", &second.prepared_witness_sha256)?;
    if first.identity.asset_id == second.identity.asset_id
        || first.identity.migration_id != second.identity.migration_id
        || first.identity.evidence_sha256 != second.identity.evidence_sha256
        || first.identity.cohort_sha256 != second.identity.cohort_sha256
        || first.identity.quarantine_plan != second.identity.quarantine_plan
    {
        return Err(LegacyUploadMigrationError::CohortAuthorityMismatch);
    }
    Ok(())
}

pub(crate) fn seal_legacy_upload_migration_quarantine_plan(
    mut plan: LegacyUploadMigrationQuarantinePlan,
) -> Result<LegacyUploadMigrationQuarantinePlan, LegacyUploadMigrationError> {
    plan.plan_sha256.clear();
    plan.plan_sha256 = canonical_digest(&(
        plan.schema_version,
        &plan.roots,
        &plan.members,
        &plan.raw_inputs,
    ))?;
    validate_quarantine_plan(&plan)?;
    Ok(plan)
}

pub(crate) fn legacy_upload_migration_quarantine_destination_path(
    root: &std::path::Path,
    cohort_sha256: &str,
    kind: LegacyUploadMigrationQuarantineKind,
    asset_id: &str,
    source_path: &std::path::Path,
) -> Result<PathBuf, LegacyUploadMigrationError> {
    #[derive(Serialize)]
    struct Input<'a> {
        schema_version: u64,
        cohort_sha256: &'a str,
        kind: LegacyUploadMigrationQuarantineKind,
        asset_id: &'a str,
        source_path: &'a std::path::Path,
    }
    let digest = canonical_digest(&Input {
        schema_version: 1,
        cohort_sha256,
        kind,
        asset_id,
        source_path,
    })?;
    let extension = match kind {
        LegacyUploadMigrationQuarantineKind::Reference => "jpg",
        LegacyUploadMigrationQuarantineKind::Final
        | LegacyUploadMigrationQuarantineKind::OldMirror => "heic",
    };
    Ok(root
        .join(cohort_sha256)
        .join(format!("{digest}.{extension}")))
}

fn validate_quarantine_plan(
    plan: &LegacyUploadMigrationQuarantinePlan,
) -> Result<(), LegacyUploadMigrationError> {
    if plan.schema_version != 1
        || plan.roots.is_empty()
        || plan.members.len() != 9
        || plan.raw_inputs.len() != 10
    {
        return Err(LegacyUploadMigrationError::CohortAuthorityMismatch);
    }
    validate_digest("quarantine_plan_sha256", &plan.plan_sha256)?;
    let mut root_devices = BTreeSet::new();
    let mut root_paths = BTreeSet::new();
    for root in &plan.roots {
        if !safe_quarantine_plan_path(&root.canonical_path)
            || root.device == 0
            || root.inode == 0
            || root.mode != 0o700
            || !root_devices.insert(root.device)
            || !root_paths.insert(root.canonical_path.clone())
        {
            return Err(LegacyUploadMigrationError::CohortAuthorityMismatch);
        }
    }
    let mut member_keys = BTreeSet::new();
    let mut sources = BTreeSet::new();
    let mut source_identities = BTreeSet::new();
    let mut destinations = BTreeSet::new();
    let mut kind_counts = BTreeMap::new();
    for member in &plan.members {
        validate_remote_identity("quarantine_asset_id", &member.asset_id)?;
        validate_digest("quarantine_source_sha256", &member.source.sha256)?;
        if !safe_quarantine_plan_path(&member.source_path)
            || !safe_quarantine_plan_path(&member.destination_path)
            || member.source.device == 0
            || member.source.inode == 0
            || member.source.link_count != 1
            || member.source.size_bytes == 0
            || member.root_device != member.source.device
            || !root_devices.contains(&member.root_device)
            || !member_keys.insert((member.asset_id.clone(), member.kind))
            || !sources.insert(member.source_path.clone())
            || !source_identities.insert((member.source.device, member.source.inode))
            || !destinations.insert(member.destination_path.clone())
        {
            return Err(LegacyUploadMigrationError::CohortAuthorityMismatch);
        }
        let root = plan
            .roots
            .iter()
            .find(|root| root.device == member.root_device)
            .ok_or(LegacyUploadMigrationError::CohortAuthorityMismatch)?;
        if !member.destination_path.starts_with(&root.canonical_path) {
            return Err(LegacyUploadMigrationError::CohortAuthorityMismatch);
        }
        if member.source_path.starts_with(&root.canonical_path) {
            return Err(LegacyUploadMigrationError::CohortAuthorityMismatch);
        }
        *kind_counts.entry(member.kind).or_insert(0_u64) += 1;
    }
    if kind_counts
        != BTreeMap::from([
            (LegacyUploadMigrationQuarantineKind::Final, 2),
            (LegacyUploadMigrationQuarantineKind::Reference, 5),
            (LegacyUploadMigrationQuarantineKind::OldMirror, 2),
        ])
    {
        return Err(LegacyUploadMigrationError::CohortAuthorityMismatch);
    }
    let mut raw_asset_ids = BTreeSet::new();
    let mut raw_paths = BTreeSet::new();
    let mut raw_identities = BTreeSet::new();
    for raw in &plan.raw_inputs {
        validate_remote_identity("raw_asset_id", &raw.asset_id)?;
        validate_digest("raw_source_sha256", &raw.source.sha256)?;
        if !safe_quarantine_plan_path(&raw.path)
            || raw.source.device == 0
            || raw.source.inode == 0
            || raw.source.link_count != 1
            || raw.source.size_bytes == 0
            || !raw_asset_ids.insert(raw.asset_id.clone())
            || !raw_paths.insert(raw.path.clone())
            || !raw_identities.insert((raw.source.device, raw.source.inode))
            || plan
                .roots
                .iter()
                .any(|root| raw.path.starts_with(&root.canonical_path))
        {
            return Err(LegacyUploadMigrationError::CohortAuthorityMismatch);
        }
    }
    if raw_identities
        .iter()
        .any(|identity| source_identities.contains(identity))
    {
        return Err(LegacyUploadMigrationError::CohortAuthorityMismatch);
    }
    let expected = canonical_digest(&(
        plan.schema_version,
        &plan.roots,
        &plan.members,
        &plan.raw_inputs,
    ))?;
    if plan.plan_sha256 != expected {
        return Err(LegacyUploadMigrationError::CohortAuthorityMismatch);
    }
    Ok(())
}

fn safe_quarantine_plan_path(path: &std::path::Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

fn validate_digest(field: &'static str, value: &str) -> Result<(), LegacyUploadMigrationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LegacyUploadMigrationError::InvalidDigest { field });
    }
    Ok(())
}

fn validate_remote_identity(
    field: &'static str,
    value: &str,
) -> Result<(), LegacyUploadMigrationError> {
    if value.is_empty()
        || value.trim() != value
        || value.len() > MAX_REMOTE_IDENTITY_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(LegacyUploadMigrationError::InvalidRemoteIdentity { field });
    }
    Ok(())
}

fn validate_state(
    record: &AssetRecord,
    phase: LegacyUploadMigrationPhase,
) -> Result<(), LegacyUploadMigrationError> {
    let expected = phase.required_state();
    if record.state != expected {
        return Err(LegacyUploadMigrationError::StateMismatch {
            phase,
            expected,
            actual: record.state,
        });
    }
    Ok(())
}

#[derive(Error)]
pub enum LegacyUploadMigrationError {
    #[error("legacy upload migration journal is missing")]
    JournalMissing,
    #[error("legacy upload migration journal is empty")]
    JournalEmpty,
    #[error("unsupported legacy upload migration schema version {actual}")]
    UnsupportedSchemaVersion { actual: u64 },
    #[error("legacy upload migration digest field {field} is invalid")]
    InvalidDigest { field: &'static str },
    #[error("legacy upload migration remote identity field {field} is invalid")]
    InvalidRemoteIdentity { field: &'static str },
    #[error("legacy upload migration identity does not match the record")]
    IdentityMismatch,
    #[error("legacy upload migration cohort authority does not match the exact two records")]
    CohortAuthorityMismatch,
    #[error("legacy upload migration sealed cohort registry is missing")]
    RegistryMissing,
    #[error("legacy upload migration sealed cohort registry was tampered")]
    RegistryTampered,
    #[error("legacy upload migration sealed cohort registry does not match the exact two records")]
    RegistryCohortMismatch,
    #[error("legacy upload migration phase authority does not match the exact transition")]
    PhaseAuthorityMismatch,
    #[error("legacy upload migration source record digest does not match")]
    SourceRecordMismatch,
    #[error("legacy upload migration journal was tampered at {field}")]
    JournalTampered { field: &'static str },
    #[error("legacy upload migration cannot advance from {from:?} to {to:?}")]
    InvalidPhaseTransition {
        from: LegacyUploadMigrationPhase,
        to: LegacyUploadMigrationPhase,
    },
    #[error("legacy upload migration replay differs at phase {phase:?}")]
    ReplayMismatch { phase: LegacyUploadMigrationPhase },
    #[error("completed legacy upload migration journal is immutable")]
    CompleteImmutable,
    #[error("legacy upload migration journal is incomplete at phase {phase:?}")]
    IncompleteJournal { phase: LegacyUploadMigrationPhase },
    #[error(
        "legacy upload migration phase {phase:?} requires state {expected}, not state {actual}"
    )]
    StateMismatch {
        phase: LegacyUploadMigrationPhase,
        expected: State,
        actual: State,
    },
    #[error("legacy upload migration journal JSON is invalid")]
    Json(serde_json::Error),
}

impl LegacyUploadMigrationError {
    pub const fn category(&self) -> &'static str {
        match self {
            Self::JournalMissing => "journal_missing",
            Self::JournalEmpty => "journal_empty",
            Self::UnsupportedSchemaVersion { .. } => "unsupported_schema_version",
            Self::InvalidDigest { .. } => "invalid_digest",
            Self::InvalidRemoteIdentity { .. } => "invalid_remote_identity",
            Self::IdentityMismatch => "identity_mismatch",
            Self::CohortAuthorityMismatch => "cohort_authority_mismatch",
            Self::RegistryMissing => "registry_missing",
            Self::RegistryTampered => "registry_tampered",
            Self::RegistryCohortMismatch => "registry_cohort_mismatch",
            Self::PhaseAuthorityMismatch => "phase_authority_mismatch",
            Self::SourceRecordMismatch => "source_record_mismatch",
            Self::JournalTampered { .. } => "journal_tampered",
            Self::InvalidPhaseTransition { .. } => "invalid_phase_transition",
            Self::ReplayMismatch { .. } => "replay_mismatch",
            Self::CompleteImmutable => "complete_immutable",
            Self::IncompleteJournal { .. } => "incomplete_journal",
            Self::StateMismatch { .. } => "state_mismatch",
            Self::Json(_) => "invalid_json",
        }
    }

    pub fn json_error(&self) -> Option<&serde_json::Error> {
        match self {
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl fmt::Debug for LegacyUploadMigrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyUploadMigrationError")
            .field("category", &self.category())
            .finish()
    }
}

impl From<serde_json::Error> for LegacyUploadMigrationError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[derive(Error)]
pub enum LegacyUploadMigrationCommitError {
    #[error("legacy upload migration exact-CAS update changed an asset ID")]
    MismatchedAssetIds,
    #[error("legacy upload migration exact-CAS update repeated an asset ID")]
    DuplicateAsset,
    #[error("legacy upload migration exact-CAS records do not bind the same cohort")]
    CohortMismatch,
    #[error("legacy upload migration exact-CAS records do not match cohort authority")]
    CohortAuthorityMismatch,
    #[error("legacy upload migration exact-CAS records do not match phase authority")]
    PhaseAuthorityMismatch,
    #[error("legacy upload migration record transition is invalid")]
    InvalidRecordTransition,
    #[error("legacy upload migration exact-CAS records use different transition shapes")]
    BatchTransitionMismatch,
    #[error("legacy upload migration state commit failed")]
    StateStore(AssetStateStoreError),
}

impl LegacyUploadMigrationCommitError {
    pub const fn category(&self) -> &'static str {
        match self {
            Self::MismatchedAssetIds => "mismatched_asset_ids",
            Self::DuplicateAsset => "duplicate_asset",
            Self::CohortMismatch => "cohort_mismatch",
            Self::CohortAuthorityMismatch => "cohort_authority_mismatch",
            Self::PhaseAuthorityMismatch => "phase_authority_mismatch",
            Self::InvalidRecordTransition => "invalid_record_transition",
            Self::BatchTransitionMismatch => "batch_transition_mismatch",
            Self::StateStore(_) => "state_store",
        }
    }

    pub fn state_store_error(&self) -> Option<&AssetStateStoreError> {
        match self {
            Self::StateStore(error) => Some(error),
            _ => None,
        }
    }
}

impl fmt::Debug for LegacyUploadMigrationCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LegacyUploadMigrationCommitError")
            .field("category", &self.category())
            .finish()
    }
}

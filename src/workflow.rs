use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::de::{self, DeserializeOwned};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};
use thiserror::Error;

use crate::adjusted_source::{
    AdjustedSourceError, CloudKitAdjustedSourceProof, MaterializedAdjustedSource,
    adjusted_source_proof_digest,
    materialize_adjusted_source_for_conversion as materialize_adjusted_source,
    validate_adjusted_source_proof_lineage, validate_installed_adjusted_source_proof,
};
use crate::manifest::{AssetRecord, FailureKind, Manifest, ManifestError, State};
use crate::operation_hold::{self, OperationHoldError};
use crate::proof::{
    MIN_RAW_AGE_SECONDS, NasRawProof, ProofError, RawFileFingerprint, prove_nas_raw,
    prove_nas_raw_with_min_age_seconds_and_fingerprint,
};
use crate::upload::{
    CloudKitDatabaseScope, CloudKitDeleteOutcome, CloudKitDeleteRequest, CloudKitDeleteSession,
    CloudKitLibraryDestination, CloudKitUploadedHeicAsset, CloudKitUploadedHeicReadClient,
    CloudKitUploadedHeicReadTransport, CloudKitUploadedHeicResolveRequest, UploadError,
    validate_library_destination,
};

const NAS_PROOF: &str = "nas";
const ORIGINAL_ASSET_PROOF: &str = "original_asset";
const ADJUSTED_SOURCE_PROOF: &str = "adjusted_source";
pub(crate) const CONVERSION_PROOF: &str = "conversion";
pub(crate) const CONVERSION_PERFORMANCE_PROOF: &str = "conversion_performance";
pub(crate) const HEIC_PROOF: &str = "heic";
const SOURCE_AGE_PROOF: &str = "source_age";
pub(crate) const UPLOAD_PROOF: &str = "upload";
pub(crate) const REMOTE_READBACK_PROOF: &str = "remote_readback";
const UPLOADED_HEIC_DELETE_PROOF: &str = "uploaded_heic_delete";
pub(crate) const ICLOUDPD_LOCAL_MIRROR_PROOF: &str = "icloudpd_local_mirror";
const DELETE_ELIGIBILITY_PROOF: &str = "delete_eligibility";
const DELETE_APPROVAL_PROOF: &str = "delete_approval";
const DELETE_EXECUTION_PROOF: &str = "delete";
const CONVERSION_PERFORMANCE_SCHEMA_VERSION: u8 = 1;
const CONVERSION_PERFORMANCE_MEASUREMENT_METHOD: &str = "monotonic_wall_clock";
pub(crate) const EMBEDDED_PREVIEW_CONVERSION_RECIPE: &str = "embedded-preview-normalized-v1";
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
pub struct ConversionResultInput {
    pub heic_path: PathBuf,
    pub heic_sha256: String,
    pub size_bytes: u64,
    pub source_binding: ConversionSourceBinding,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ConversionResultProof {
    pub heic_path: PathBuf,
    pub heic_sha256: String,
    pub size_bytes: u64,
    #[serde(default)]
    conversion_recipe_id: String,
    #[serde(default)]
    pub source_binding: ConversionSourceBinding,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum ConversionSourceBinding {
    #[default]
    EmbeddedPreview,
    AdjustedSource {
        adjusted_source_proof_digest: String,
        adjusted_jpeg_sha256: String,
        adjusted_jpeg_path: PathBuf,
    },
    /// Historical claim that the conversion consumed the camera-native RAW.
    /// A bare string and a historical object are both preserved. Neither is an
    /// embedded-preview or adjusted-source verification.
    NativeRaw(NativeRawSource),
}

/// Provenance stored with a historical `native_raw` conversion source.
///
/// `object_fields` is `None` for the string token `"native_raw"` and `Some`
/// for the externally tagged object `{"native_raw": { ... }}`. Every field in
/// that object is retained and none of them grants a current quality pass.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NativeRawSource {
    object_fields: Option<serde_json::Map<String, Value>>,
}

impl NativeRawSource {
    pub fn token() -> Self {
        Self {
            object_fields: None,
        }
    }

    pub fn object(fields: serde_json::Map<String, Value>) -> Self {
        Self {
            object_fields: Some(fields),
        }
    }

    pub fn object_fields(&self) -> Option<&serde_json::Map<String, Value>> {
        self.object_fields.as_ref()
    }
}

impl ConversionSourceBinding {
    pub fn historical_native_raw_token() -> Self {
        Self::NativeRaw(NativeRawSource::token())
    }
}

#[derive(Deserialize, Serialize)]
struct AdjustedSourceWire {
    adjusted_source_proof_digest: String,
    adjusted_jpeg_sha256: String,
    adjusted_jpeg_path: PathBuf,
}

impl Serialize for ConversionSourceBinding {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::EmbeddedPreview => serializer.serialize_str("embedded_preview"),
            Self::AdjustedSource {
                adjusted_source_proof_digest,
                adjusted_jpeg_sha256,
                adjusted_jpeg_path,
            } => {
                let wire = AdjustedSourceWire {
                    adjusted_source_proof_digest: adjusted_source_proof_digest.clone(),
                    adjusted_jpeg_sha256: adjusted_jpeg_sha256.clone(),
                    adjusted_jpeg_path: adjusted_jpeg_path.clone(),
                };
                serde_json::json!({ "adjusted_source": wire }).serialize(serializer)
            }
            Self::NativeRaw(source) => match &source.object_fields {
                None => serializer.serialize_str("native_raw"),
                Some(fields) => serde_json::json!({ "native_raw": fields }).serialize(serializer),
            },
        }
    }
}

impl<'de> Deserialize<'de> for ConversionSourceBinding {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        conversion_source_binding_from_value(value).map_err(de::Error::custom)
    }
}

fn conversion_source_binding_from_value(value: Value) -> Result<ConversionSourceBinding, String> {
    match value {
        Value::String(token) if token == "embedded_preview" => {
            Ok(ConversionSourceBinding::EmbeddedPreview)
        }
        Value::String(token) if token == "native_raw" => {
            Ok(ConversionSourceBinding::historical_native_raw_token())
        }
        Value::String(token) => Err(format!("unknown conversion source binding {token}")),
        Value::Object(map) if map.len() == 1 && map.contains_key("adjusted_source") => {
            let wire: AdjustedSourceWire = serde_json::from_value(
                map.get("adjusted_source").cloned().unwrap_or(Value::Null),
            )
            .map_err(|error| error.to_string())?;
            Ok(ConversionSourceBinding::AdjustedSource {
                adjusted_source_proof_digest: wire.adjusted_source_proof_digest,
                adjusted_jpeg_sha256: wire.adjusted_jpeg_sha256,
                adjusted_jpeg_path: wire.adjusted_jpeg_path,
            })
        }
        Value::Object(map) if map.len() == 1 && map.contains_key("native_raw") => {
            match map.get("native_raw") {
                Some(Value::Object(fields)) => Ok(ConversionSourceBinding::NativeRaw(
                    NativeRawSource::object(fields.clone()),
                )),
                _ => Err(
                    "historical native_raw conversion source must be a string or an object"
                        .to_string(),
                ),
            }
        }
        Value::Object(_) => Err(
            "conversion source binding object is not a supported historical native_raw or adjusted source"
                .to_string(),
        ),
        _ => Err("conversion source binding must be a string or object".to_string()),
    }
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
    pub conversion_command_timings: Vec<ConversionCommandTiming>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConversionCommandTiming {
    pub program: String,
    pub wall_time_millis: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ConversionPerformanceProof {
    pub schema_version: u8,
    pub measured_at_unix_seconds: u64,
    pub measurement_method: String,
    pub conversion_tool: String,
    #[serde(default)]
    conversion_recipe_id: String,
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
pub struct HeicVerificationInput {
    pub heic_path: PathBuf,
    pub heic_sha256: String,
    pub size_bytes: u64,
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
pub(crate) struct HeicVerificationProof {
    pub heic_path: PathBuf,
    pub heic_sha256: String,
    pub size_bytes: u64,
    #[serde(default)]
    conversion_recipe_id: String,
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

impl From<HeicVerificationProof> for HeicVerificationInput {
    fn from(proof: HeicVerificationProof) -> Self {
        Self {
            heic_path: proof.heic_path,
            heic_sha256: proof.heic_sha256,
            size_bytes: proof.size_bytes,
            heif_info_ok: proof.heif_info_ok,
            metadata_copied: proof.metadata_copied,
            visual_content_ok: proof.visual_content_ok,
            visual_match_ok: proof.visual_match_ok,
            visual_rmse_ppm: proof.visual_rmse_ppm,
            visual_mae_ppm: proof.visual_mae_ppm,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct VerifiedHeic {
    pub heic_path: PathBuf,
    pub heic_sha256: String,
    pub size_bytes: u64,
}

impl From<&HeicVerificationProof> for VerifiedHeic {
    fn from(proof: &HeicVerificationProof) -> Self {
        Self {
            heic_path: proof.heic_path.clone(),
            heic_sha256: proof.heic_sha256.clone(),
            size_bytes: proof.size_bytes,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UploadProof {
    pub uploaded_heic_asset_id: String,
    pub uploaded_heic_sha256: String,
    #[serde(default)]
    pub database_scope: CloudKitDatabaseScope,
    #[serde(default = "primary_sync_zone_name")]
    pub zone_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_record_name: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_record_name: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_owner_record_name: Option<String>,
    #[serde(default)]
    uploaded_database_scope: CloudKitDatabaseScope,
    #[serde(default = "primary_sync_zone_name")]
    uploaded_zone_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uploaded_owner_record_name: Option<String>,
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
    input: ConversionResultInput,
) -> Result<&'a AssetRecord, WorkflowError> {
    record_conversion_result_with_recipe(manifest, asset_id, input, String::new(), false)
}

pub(crate) fn record_current_conversion_result<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    input: ConversionResultInput,
) -> Result<&'a AssetRecord, WorkflowError> {
    record_conversion_result_with_recipe(
        manifest,
        asset_id,
        input,
        EMBEDDED_PREVIEW_CONVERSION_RECIPE.to_string(),
        true,
    )
}

fn record_conversion_result_with_recipe<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    input: ConversionResultInput,
    conversion_recipe_id: String,
    trusted: bool,
) -> Result<&'a AssetRecord, WorkflowError> {
    let proof = ConversionResultProof {
        heic_path: input.heic_path,
        heic_sha256: input.heic_sha256,
        size_bytes: input.size_bytes,
        conversion_recipe_id,
        source_binding: input.source_binding,
    };
    require_non_empty_path("heic_path", &proof.heic_path)?;
    require_non_empty("heic_sha256", &proof.heic_sha256)?;
    validate_conversion_source_binding(manifest, asset_id, &proof)?;
    if trusted {
        transition_with_trusted_proof(
            manifest,
            asset_id,
            State::Converted,
            CONVERSION_PROOF,
            &proof,
        )
    } else {
        transition_with_proof(
            manifest,
            asset_id,
            State::Converted,
            CONVERSION_PROOF,
            &proof,
        )
    }
}

pub fn record_conversion_performance<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    input: ConversionPerformanceInput,
) -> Result<&'a AssetRecord, WorkflowError> {
    record_conversion_performance_with_recipe(manifest, asset_id, input, String::new(), false)
}

pub(crate) fn record_current_conversion_performance<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    input: ConversionPerformanceInput,
) -> Result<&'a AssetRecord, WorkflowError> {
    record_conversion_performance_with_recipe(
        manifest,
        asset_id,
        input,
        EMBEDDED_PREVIEW_CONVERSION_RECIPE.to_string(),
        true,
    )
}

fn record_conversion_performance_with_recipe<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    input: ConversionPerformanceInput,
    conversion_recipe_id: String,
    trusted: bool,
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
        conversion_recipe_id,
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
    if trusted {
        insert_trusted_workflow_proof(manifest, asset_id, CONVERSION_PERFORMANCE_PROOF, &proof)
    } else {
        insert_workflow_proof(manifest, asset_id, CONVERSION_PERFORMANCE_PROOF, &proof)
    }
}

pub fn record_heic_verification<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    input: HeicVerificationInput,
) -> Result<&'a AssetRecord, WorkflowError> {
    record_heic_verification_with_recipe(manifest, asset_id, input, String::new(), false)
}

pub(crate) fn record_current_heic_verification<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    input: HeicVerificationInput,
) -> Result<&'a AssetRecord, WorkflowError> {
    record_heic_verification_with_recipe(
        manifest,
        asset_id,
        input,
        EMBEDDED_PREVIEW_CONVERSION_RECIPE.to_string(),
        true,
    )
}

fn record_heic_verification_with_recipe<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    input: HeicVerificationInput,
    conversion_recipe_id: String,
    trusted: bool,
) -> Result<&'a AssetRecord, WorkflowError> {
    let proof = HeicVerificationProof {
        heic_path: input.heic_path,
        heic_sha256: input.heic_sha256,
        size_bytes: input.size_bytes,
        conversion_recipe_id,
        heif_info_ok: input.heif_info_ok,
        metadata_copied: input.metadata_copied,
        visual_content_ok: input.visual_content_ok,
        visual_match_ok: input.visual_match_ok,
        visual_rmse_ppm: input.visual_rmse_ppm,
        visual_mae_ppm: input.visual_mae_ppm,
    };
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
    require_valid_conversion_performance(manifest, asset_id)?;
    if trusted {
        transition_with_trusted_proof(
            manifest,
            asset_id,
            State::ConversionVerified,
            HEIC_PROOF,
            &proof,
        )
    } else {
        transition_with_proof(
            manifest,
            asset_id,
            State::ConversionVerified,
            HEIC_PROOF,
            &proof,
        )
    }
}

pub fn record_upload_proof<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    proof: UploadProof,
) -> Result<&'a AssetRecord, WorkflowError> {
    ensure_remote_mutation_allowed(manifest, asset_id)?;
    require_non_empty("uploaded_heic_asset_id", &proof.uploaded_heic_asset_id)?;
    require_non_empty("uploaded_heic_sha256", &proof.uploaded_heic_sha256)?;
    require_valid_library_destination(
        UPLOAD_PROOF,
        proof.database_scope,
        &proof.zone_name,
        proof.owner_record_name.as_deref(),
    )?;
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
        owner_record_name: upload.owner_record_name,
    })
}

/// Builds a replacement record with only the current conversion recipe claims
/// and HEIC verification measurements refreshed.  The caller is responsible
/// for proving the files and remote resource before persisting this record.
pub fn reverify_upload_verified_record(
    manifest: &Manifest,
    asset_id: &str,
    heic_input: HeicVerificationInput,
) -> Result<AssetRecord, WorkflowError> {
    if manifest.get(asset_id)?.state != State::UploadVerified {
        return Err(WorkflowError::UploadUnavailable {
            asset_id: asset_id.to_string(),
            state: manifest.get(asset_id)?.state,
        });
    }

    let conversion = stored_proof::<ConversionResultProof>(manifest, asset_id, CONVERSION_PROOF)?;
    require_matching_path(
        CONVERSION_PROOF,
        "heic_path",
        &conversion.heic_path,
        &heic_input.heic_path,
    )?;
    require_matching_str(
        CONVERSION_PROOF,
        "heic_sha256",
        &conversion.heic_sha256,
        &heic_input.heic_sha256,
    )?;
    require_matching_u64(
        CONVERSION_PROOF,
        "size_bytes",
        conversion.size_bytes,
        heic_input.size_bytes,
    )?;
    validate_heic_verification_flags_legacy(&HeicVerificationProof {
        heic_path: heic_input.heic_path.clone(),
        heic_sha256: heic_input.heic_sha256.clone(),
        size_bytes: heic_input.size_bytes,
        conversion_recipe_id: EMBEDDED_PREVIEW_CONVERSION_RECIPE.to_string(),
        heif_info_ok: heic_input.heif_info_ok,
        metadata_copied: heic_input.metadata_copied,
        visual_content_ok: heic_input.visual_content_ok,
        visual_match_ok: heic_input.visual_match_ok,
        visual_rmse_ppm: heic_input.visual_rmse_ppm,
        visual_mae_ppm: heic_input.visual_mae_ppm,
    })?;

    let mut candidate = manifest.snapshot_record(asset_id)?;
    for proof_key in [CONVERSION_PROOF, CONVERSION_PERFORMANCE_PROOF] {
        let mut proof = candidate
            .get(asset_id)?
            .proofs
            .get(proof_key)
            .cloned()
            .ok_or_else(|| WorkflowError::MissingProof {
                asset_id: asset_id.to_string(),
                proof_key: proof_key.to_string(),
            })?;
        proof["conversion_recipe_id"] =
            Value::String(EMBEDDED_PREVIEW_CONVERSION_RECIPE.to_string());
        candidate.record_trusted_proof(asset_id, proof_key, proof)?;
    }
    candidate.record_trusted_proof(
        asset_id,
        HEIC_PROOF,
        serde_json::to_value(HeicVerificationProof {
            heic_path: heic_input.heic_path,
            heic_sha256: heic_input.heic_sha256,
            size_bytes: heic_input.size_bytes,
            conversion_recipe_id: EMBEDDED_PREVIEW_CONVERSION_RECIPE.to_string(),
            heif_info_ok: heic_input.heif_info_ok,
            metadata_copied: heic_input.metadata_copied,
            visual_content_ok: heic_input.visual_content_ok,
            visual_match_ok: heic_input.visual_match_ok,
            visual_rmse_ppm: heic_input.visual_rmse_ppm,
            visual_mae_ppm: heic_input.visual_mae_ppm,
        })?,
    )?;
    // This validates the complete NAS/original/conversion/performance/HEIC/
    // upload/mirror lineage, including distinct original/replacement identity.
    validate_pre_delete_facts(&candidate, asset_id)?;
    let current = manifest.get(asset_id)?;
    let desired = candidate.get(asset_id)?;
    if reverify_owned_proofs_are_current(current, desired) {
        return Ok(current.clone());
    }
    Ok(desired.clone())
}

fn reverify_owned_proofs_are_current(current: &AssetRecord, desired: &AssetRecord) -> bool {
    [CONVERSION_PROOF, CONVERSION_PERFORMANCE_PROOF, HEIC_PROOF]
        .iter()
        .all(|proof_key| current.proofs.get(*proof_key) == desired.proofs.get(*proof_key))
}

pub fn record_uploaded_heic_delete<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    resolved: CloudKitUploadedHeicAsset,
    outcome: CloudKitDeleteOutcome,
) -> Result<&'a AssetRecord, WorkflowError> {
    ensure_remote_mutation_allowed(manifest, asset_id)?;
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
    ensure_remote_mutation_allowed(manifest, asset_id)?;
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

/// Dispatch gate for one photo upload. A durable hold or an existing upload
/// proof refuses the send. Upload proof alone is not remote readback.
pub fn ensure_upload_dispatch_allowed(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<VerifiedHeic, WorkflowError> {
    let record = manifest.get(asset_id)?;
    ensure_remote_mutation_allowed_record(record)?;
    if record.proofs.contains_key(UPLOAD_PROOF) {
        return Err(WorkflowError::UploadAlreadyRecorded {
            asset_id: asset_id.to_string(),
        });
    }
    upload_ready_heic_proof(manifest, asset_id)
}

pub fn upload_ready_heic_proof(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<VerifiedHeic, WorkflowError> {
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
    Ok(VerifiedHeic::from(&proof))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalConversionSource {
    pub source_binding: ConversionSourceBinding,
    /// True only when the stored token is a current embedded-preview or
    /// adjusted-source claim. `native_raw` stays false and is not rewritten.
    pub current_policy_source: bool,
}

/// Decodes a stored conversion proof, including historical `native_raw`.
/// This does not admit the proof to upload, delete, or quality verification.
pub fn decode_historical_conversion_source(
    asset_id: &str,
    proof: &Value,
) -> Result<HistoricalConversionSource, WorkflowError> {
    let parsed: ConversionResultProof =
        serde_json::from_value(proof.clone()).map_err(|source| WorkflowError::ProofDecode {
            asset_id: asset_id.to_string(),
            proof_key: CONVERSION_PROOF,
            source,
        })?;
    Ok(HistoricalConversionSource {
        current_policy_source: !matches!(
            parsed.source_binding,
            ConversionSourceBinding::NativeRaw(_)
        ),
        source_binding: parsed.source_binding,
    })
}

/// Confirms a historical conversion proof decodes and returns it unchanged.
/// `native_raw` is not upgraded to `embedded_preview` or `adjusted_source`.
pub fn identity_migrate_historical_conversion_proof(
    asset_id: &str,
    proof: &Value,
) -> Result<Value, WorkflowError> {
    let decoded = decode_historical_conversion_source(asset_id, proof)?;
    let encoded = serde_json::to_value(&decoded.source_binding)?;
    match proof.get("source_binding") {
        Some(stored) if stored == &encoded => Ok(proof.clone()),
        Some(_) => Err(WorkflowError::InvalidProofField {
            proof_key: CONVERSION_PROOF,
            field: "source_binding",
            reason: "stored conversion source does not round-trip",
        }),
        None => Ok(proof.clone()),
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteReadbackProof {
    schema_version: u8,
    uploaded_heic_asset_id: String,
    matched_heic_sha256: String,
    size_bytes: u64,
    database_scope: CloudKitDatabaseScope,
    zone_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    owner_record_name: Option<String>,
    record_change_tag: String,
    master_record_name: String,
}

/// True only when a downloaded remote hash was recorded and still matches the
/// upload and HEIC proofs. Upload proof and session metadata are not enough.
pub fn remote_readback_is_verified(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<bool, WorkflowError> {
    let record = manifest.get(asset_id)?;
    let Some(value) = record.proofs.get(REMOTE_READBACK_PROOF) else {
        return Ok(false);
    };
    let readback: RemoteReadbackProof =
        serde_json::from_value(value.clone()).map_err(|source| WorkflowError::ProofDecode {
            asset_id: asset_id.to_string(),
            proof_key: REMOTE_READBACK_PROOF,
            source,
        })?;
    let upload = stored_proof::<UploadProof>(manifest, asset_id, UPLOAD_PROOF)?;
    let heic = stored_proof::<HeicVerificationProof>(manifest, asset_id, HEIC_PROOF)?;
    Ok(remote_readback_matches(&readback, &upload, &heic))
}

/// Downloads the uploaded HEIC for one asset and records readback only when the
/// bytes match. A hold is left in place. Nothing is deleted.
pub fn verify_remote_readback<T: CloudKitUploadedHeicReadTransport>(
    manifest: &mut Manifest,
    asset_id: &str,
    session: &CloudKitDeleteSession,
    transport: &mut T,
) -> Result<(), WorkflowError> {
    let request = uploaded_heic_delete_request(manifest, asset_id)?;
    let resolved = CloudKitUploadedHeicReadClient::new(&mut *transport)
        .resolve_uploaded_heic_asset(session, &request)
        .map_err(WorkflowError::RemoteReadback)?;
    record_remote_readback(manifest, asset_id, &resolved)
}

fn record_remote_readback(
    manifest: &mut Manifest,
    asset_id: &str,
    resolved: &CloudKitUploadedHeicAsset,
) -> Result<(), WorkflowError> {
    let upload = stored_proof::<UploadProof>(manifest, asset_id, UPLOAD_PROOF)?;
    let heic = stored_proof::<HeicVerificationProof>(manifest, asset_id, HEIC_PROOF)?;
    if manifest.get(asset_id)?.state != State::UploadVerified {
        return Err(WorkflowError::UploadUnavailable {
            asset_id: asset_id.to_string(),
            state: manifest.get(asset_id)?.state,
        });
    }
    if resolved.record_name != upload.uploaded_heic_asset_id
        || resolved.matched_heic_sha256 != upload.uploaded_heic_sha256
        || resolved.matched_heic_sha256 != heic.heic_sha256
        || resolved.size_bytes != heic.size_bytes
        || resolved.record_change_tag.trim().is_empty()
        || resolved.master_record_name.trim().is_empty()
    {
        return Err(WorkflowError::RemoteReadback(
            UploadError::CloudKitUploadedHeicDownloadHashMismatch {
                expected: upload.uploaded_heic_sha256,
                actual: resolved.matched_heic_sha256.clone(),
            },
        ));
    }
    let proof = RemoteReadbackProof {
        schema_version: 1,
        uploaded_heic_asset_id: upload.uploaded_heic_asset_id.clone(),
        matched_heic_sha256: resolved.matched_heic_sha256.clone(),
        size_bytes: resolved.size_bytes,
        database_scope: upload.database_scope,
        zone_name: upload.zone_name.clone(),
        owner_record_name: upload.owner_record_name.clone(),
        record_change_tag: resolved.record_change_tag.clone(),
        master_record_name: resolved.master_record_name.clone(),
    };
    if let Some(value) = manifest.get(asset_id)?.proofs.get(REMOTE_READBACK_PROOF) {
        let existing: RemoteReadbackProof =
            serde_json::from_value(value.clone()).map_err(|source| WorkflowError::ProofDecode {
                asset_id: asset_id.to_string(),
                proof_key: REMOTE_READBACK_PROOF,
                source,
            })?;
        if existing == proof {
            return Ok(());
        }
        return Err(WorkflowError::ProofMismatch {
            proof_key: REMOTE_READBACK_PROOF,
            field: "remote_readback",
            expected: "the recorded remote readback".to_string(),
            actual: "a different remote readback".to_string(),
        });
    }
    insert_workflow_proof(manifest, asset_id, REMOTE_READBACK_PROOF, &proof)?;
    if manifest.get(asset_id)?.state != State::UploadVerified {
        return Err(WorkflowError::UploadUnavailable {
            asset_id: asset_id.to_string(),
            state: manifest.get(asset_id)?.state,
        });
    }
    Ok(())
}

fn remote_readback_matches(
    readback: &RemoteReadbackProof,
    upload: &UploadProof,
    heic: &HeicVerificationProof,
) -> bool {
    readback.schema_version == 1
        && readback.uploaded_heic_asset_id == upload.uploaded_heic_asset_id
        && readback.matched_heic_sha256 == upload.uploaded_heic_sha256
        && readback.matched_heic_sha256 == heic.heic_sha256
        && readback.size_bytes == heic.size_bytes
        && readback.database_scope == upload.database_scope
        && readback.zone_name == upload.zone_name
        && readback.owner_record_name == upload.owner_record_name
        && !readback.record_change_tag.trim().is_empty()
        && !readback.master_record_name.trim().is_empty()
}

pub fn icloudpd_local_mirror_ready_proofs(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<(UploadProof, VerifiedHeic), WorkflowError> {
    ensure_remote_mutation_allowed(manifest, asset_id)?;
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
    Ok((upload, VerifiedHeic::from(&heic)))
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
    ensure_remote_mutation_allowed(manifest, asset_id)?;
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
    ensure_remote_mutation_allowed(manifest, asset_id)?;
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
    ensure_remote_mutation_allowed(manifest, asset_id)?;
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
    ensure_remote_mutation_allowed(manifest, prevalidated.asset_id())?;
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
    ensure_remote_mutation_allowed(manifest, reconciliation.asset_id())?;
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
    ensure_remote_mutation_allowed(manifest, asset_id)?;
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
            owner_record_name: original.owner_record_name,
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
            owner_record_name: facts.original.owner_record_name,
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
        "original_owner_record_name": &facts.original.owner_record_name,
        "uploaded_database_scope": facts.upload.database_scope,
        "uploaded_zone_name": &facts.upload.zone_name,
        "uploaded_owner_record_name": &facts.upload.owner_record_name,
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
    require_matching_owner_identity(
        DELETE_ELIGIBILITY_PROOF,
        "original_owner_record_name",
        facts.original.owner_record_name.as_deref(),
        eligibility.original_owner_record_name.as_deref(),
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
    require_matching_owner_identity(
        DELETE_ELIGIBILITY_PROOF,
        "uploaded_owner_record_name",
        facts.upload.owner_record_name.as_deref(),
        eligibility.uploaded_owner_record_name.as_deref(),
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
    require_valid_library_destination(
        ORIGINAL_ASSET_PROOF,
        proof.database_scope,
        &proof.zone_name,
        proof.owner_record_name.as_deref(),
    )?;
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

fn require_valid_library_destination(
    proof_key: &'static str,
    database_scope: CloudKitDatabaseScope,
    zone_name: &str,
    owner_record_name: Option<&str>,
) -> Result<(), WorkflowError> {
    validate_library_destination(&CloudKitLibraryDestination {
        database_scope,
        zone_name: zone_name.to_string(),
        owner_record_name: owner_record_name.map(ToString::to_string),
    })
    .map_err(|_| WorkflowError::InvalidProofField {
        proof_key,
        field: "library_destination",
        reason: "CloudKit library destination is invalid",
    })
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
    )?;
    require_matching_owner_identity(
        proof_key,
        "owner_record_name",
        original.owner_record_name.as_deref(),
        upload.owner_record_name.as_deref(),
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
    if matches!(
        conversion.source_binding,
        ConversionSourceBinding::NativeRaw(_)
    ) {
        return Err(WorkflowError::HistoricalNativeRawUnverified {
            asset_id: asset_id.to_string(),
        });
    }
    let adjusted_source =
        stored_adjusted_source_for_conversion(manifest, asset_id, &conversion.heic_path)?;
    match (&adjusted_source, &conversion.source_binding) {
        (_, ConversionSourceBinding::NativeRaw(_)) => {
            Err(WorkflowError::HistoricalNativeRawUnverified {
                asset_id: asset_id.to_string(),
            })
        }
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

fn transition_with_trusted_proof<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    state: State,
    proof_key: &str,
    proof: &impl Serialize,
) -> Result<&'a AssetRecord, WorkflowError> {
    let proof = serde_json::to_value(proof)?;
    manifest
        .transition_trusted(asset_id, state, proof_key, proof)
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

fn insert_trusted_workflow_proof<'a>(
    manifest: &'a mut Manifest,
    asset_id: &str,
    proof_key: &str,
    proof: &impl Serialize,
) -> Result<&'a AssetRecord, WorkflowError> {
    let proof = serde_json::to_value(proof)?;
    manifest
        .record_trusted_proof(asset_id, proof_key, proof)
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

#[cfg(test)]
mod provenance_tests {
    use super::*;
    use crate::state_store::AssetStateStore;

    #[test]
    fn reverify_owned_proofs_exactly_identifies_current_record() {
        let mut current = AssetRecord::new("asset", PathBuf::from("/nas/asset.dng"));
        current.proofs.insert(
            CONVERSION_PROOF.to_string(),
            serde_json::json!({"conversion_recipe_id": EMBEDDED_PREVIEW_CONVERSION_RECIPE}),
        );
        current.proofs.insert(
            CONVERSION_PERFORMANCE_PROOF.to_string(),
            serde_json::json!({"conversion_recipe_id": EMBEDDED_PREVIEW_CONVERSION_RECIPE}),
        );
        current.proofs.insert(
            HEIC_PROOF.to_string(),
            serde_json::json!({"visual_rmse_ppm": 1, "visual_mae_ppm": 2}),
        );
        let desired = current.clone();
        assert!(reverify_owned_proofs_are_current(&current, &desired));

        let mut changed = desired;
        changed.proofs.get_mut(HEIC_PROOF).unwrap()["visual_rmse_ppm"] = serde_json::json!(3);
        assert!(!reverify_owned_proofs_are_current(&current, &changed));
    }

    fn nas_proof() -> NasRawProof {
        NasRawProof {
            canonical_path: PathBuf::from("/nas/IMG_0001.dng"),
            relative_path: PathBuf::from("IMG_0001.dng"),
            size_bytes: 42,
            modified_unix_seconds: 1_700_000_000,
            age_seconds: 40 * 24 * 60 * 60,
            sha256: "raw-sha256".to_string(),
        }
    }

    fn historical_original_asset_proof_value() -> serde_json::Value {
        serde_json::json!({
            "record_name": "raw-record",
            "record_change_tag": "raw-tag",
            "record_type": "CPLAsset",
            "filename": "IMG_0001.dng",
            "size_bytes": 42,
            "matched_raw_sha256": "raw-sha256",
        })
    }

    #[test]
    fn historical_original_asset_proof_defaults_only_missing_destination_fields() {
        let proof: OriginalAssetProof =
            serde_json::from_value(historical_original_asset_proof_value())
                .expect("the historical six-field proof should decode");

        assert_eq!(proof.database_scope, CloudKitDatabaseScope::Private);
        assert_eq!(proof.zone_name, "PrimarySync");
        assert_eq!(proof.owner_record_name, None);
        validate_original_asset_proof(&proof, &nas_proof())
            .expect("the historical proof should retain private primary-sync validation");
    }

    #[test]
    fn original_asset_destination_validation_rejects_present_malformed_values() {
        let mut malformed_zone = historical_original_asset_proof_value();
        malformed_zone["zone_name"] = serde_json::json!("NotPrimary");
        let malformed_zone: OriginalAssetProof =
            serde_json::from_value(malformed_zone).expect("zone value should decode");
        assert!(matches!(
            validate_original_asset_proof(&malformed_zone, &nas_proof()),
            Err(WorkflowError::InvalidProofField {
                proof_key: ORIGINAL_ASSET_PROOF,
                field: "library_destination",
                ..
            })
        ));

        let mut shared_without_owner = historical_original_asset_proof_value();
        shared_without_owner["database_scope"] = serde_json::json!("shared");
        shared_without_owner["zone_name"] = serde_json::json!("SharedSync-owner");
        let shared_without_owner: OriginalAssetProof =
            serde_json::from_value(shared_without_owner).expect("shared destination should decode");
        assert!(matches!(
            validate_original_asset_proof(&shared_without_owner, &nas_proof()),
            Err(WorkflowError::InvalidProofField {
                proof_key: ORIGINAL_ASSET_PROOF,
                field: "library_destination",
                ..
            })
        ));
    }

    #[test]
    fn owner_bound_original_asset_proof_roundtrips_without_legacy_defaults() {
        let mut value = historical_original_asset_proof_value();
        value["database_scope"] = serde_json::json!("shared");
        value["zone_name"] = serde_json::json!("SharedSync-owner");
        value["owner_record_name"] = serde_json::json!("owner-record");
        let proof: OriginalAssetProof =
            serde_json::from_value(value).expect("owner-bound proof should decode");

        assert_eq!(proof.database_scope, CloudKitDatabaseScope::Shared);
        assert_eq!(proof.zone_name, "SharedSync-owner");
        assert_eq!(proof.owner_record_name.as_deref(), Some("owner-record"));
        validate_original_asset_proof(&proof, &nas_proof())
            .expect("owner-bound proof should retain shared-zone validation");

        let encoded = serde_json::to_value(&proof).expect("owner-bound proof should serialize");
        assert_eq!(encoded["database_scope"], serde_json::json!("shared"));
        assert_eq!(encoded["zone_name"], serde_json::json!("SharedSync-owner"));
        assert_eq!(
            encoded["owner_record_name"],
            serde_json::json!("owner-record")
        );
    }

    fn conversion_input() -> ConversionResultInput {
        ConversionResultInput {
            heic_path: PathBuf::from("/staging/IMG_0001.heic"),
            heic_sha256: "heic-sha256".to_string(),
            size_bytes: 24,
            source_binding: ConversionSourceBinding::EmbeddedPreview,
        }
    }

    fn performance_input() -> ConversionPerformanceInput {
        ConversionPerformanceInput {
            measured_at_unix_seconds: 1_800_000_000,
            conversion_tool: "sips".to_string(),
            conversion_tool_version: Some("1.0".to_string()),
            heic_quality: 90,
            convert_wall_time_millis: 10,
            total_wall_time_millis: 20,
            user_cpu_time_millis: Some(5),
            system_cpu_time_millis: Some(2),
            peak_rss_kib: Some(1_024),
            conversion_command_timings: Vec::new(),
        }
    }

    fn heic_input() -> HeicVerificationInput {
        HeicVerificationInput {
            heic_path: PathBuf::from("/staging/IMG_0001.heic"),
            heic_sha256: "heic-sha256".to_string(),
            size_bytes: 24,
            heif_info_ok: true,
            metadata_copied: true,
            visual_content_ok: true,
            visual_match_ok: true,
            visual_rmse_ppm: Some(0),
            visual_mae_ppm: Some(0),
        }
    }

    fn nas_verified_manifest() -> Manifest {
        let mut manifest = Manifest::new();
        discover_raw_asset(&mut manifest, "asset", "/nas/IMG_0001.dng").unwrap();
        record_nas_proof(&mut manifest, "asset", nas_proof()).unwrap();
        manifest
    }

    #[test]
    fn manual_conversion_recorder_stamps_untrusted_recipe() {
        let mut manifest = nas_verified_manifest();
        record_conversion_result(&mut manifest, "asset", conversion_input()).unwrap();

        assert_eq!(
            manifest.get("asset").unwrap().proofs[CONVERSION_PROOF]["conversion_recipe_id"],
            ""
        );
    }

    #[test]
    fn current_heic_recorder_requires_conversion_performance_without_mutation() {
        let mut manifest = nas_verified_manifest();
        record_current_conversion_result(&mut manifest, "asset", conversion_input()).unwrap();
        let before = manifest.clone();

        let error = record_current_heic_verification(&mut manifest, "asset", heic_input())
            .expect_err("current HEIC verification must require conversion performance");

        assert!(matches!(error, WorkflowError::MissingProof { .. }));
        assert_eq!(manifest, before);
    }

    #[test]
    fn production_current_recorders_roundtrip_through_trusted_state_storage() {
        let mut manifest = nas_verified_manifest();
        record_current_conversion_result(&mut manifest, "asset", conversion_input()).unwrap();
        record_current_conversion_performance(&mut manifest, "asset", performance_input()).unwrap();
        record_current_heic_verification(&mut manifest, "asset", heic_input()).unwrap();
        let tempdir = tempfile::tempdir().unwrap();
        let path = tempdir.path().join("manifest.json");
        let store =
            AssetStateStore::open_writer(&path, "workflow-test", Duration::from_secs(30)).unwrap();
        store.load_or_import().unwrap();
        store.persist_manifest_records_trusted(&manifest).unwrap();
        let loaded = store.load().unwrap();

        assert!(upload_ready_heic_proof(&loaded, "asset").is_ok());
        assert_eq!(
            loaded.get("asset").unwrap().proofs[HEIC_PROOF]["conversion_recipe_id"],
            EMBEDDED_PREVIEW_CONVERSION_RECIPE
        );
    }
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

fn require_matching_owner_identity(
    proof_key: &'static str,
    field: &'static str,
    expected: Option<&str>,
    actual: Option<&str>,
) -> Result<(), WorkflowError> {
    if expected != actual {
        let status = match (expected, actual) {
            (Some(_), None) => "missing",
            (None, Some(_)) => "present",
            (Some(_), Some(_)) => "mismatch",
            (None, None) => unreachable!("equal owner identities return before classification"),
        };
        return Err(WorkflowError::OwnerIdentityMismatch {
            proof_key,
            field,
            status,
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
    #[error("proof {proof_key} field {field} owner identity {status}")]
    OwnerIdentityMismatch {
        proof_key: &'static str,
        field: &'static str,
        status: &'static str,
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
    #[error(
        "historical conversion source native_raw for {asset_id} is not a current quality verification"
    )]
    HistoricalNativeRawUnverified { asset_id: String },
    #[error("remote upload or move for {asset_id} is held until explicit reconciliation")]
    RemoteOperationHeld { asset_id: String },
    #[error("upload for {asset_id} is already recorded; refusing a duplicate upload")]
    UploadAlreadyRecorded { asset_id: String },
    #[error("operation hold for {asset_id} could not be changed: {reason}")]
    OperationHold {
        asset_id: String,
        reason: &'static str,
    },
    #[error("remote readback failed")]
    RemoteReadback(#[source] UploadError),
}

pub(crate) fn ensure_remote_mutation_allowed(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<(), WorkflowError> {
    let record = manifest.get(asset_id)?;
    ensure_remote_mutation_allowed_record(record)
}

fn ensure_remote_mutation_allowed_record(record: &AssetRecord) -> Result<(), WorkflowError> {
    operation_hold::ensure_remote_mutation_allowed(record).map_err(|error| match error {
        OperationHoldError::Held { asset_id } => WorkflowError::RemoteOperationHeld { asset_id },
        OperationHoldError::Malformed { asset_id } => WorkflowError::OperationHold {
            asset_id,
            reason: "malformed hold remains in force",
        },
        OperationHoldError::Conflict { asset_id } => WorkflowError::OperationHold {
            asset_id,
            reason: "a different hold is already recorded",
        },
        OperationHoldError::UnknownAsset { asset_id } => WorkflowError::OperationHold {
            asset_id,
            reason: "asset was not found",
        },
        OperationHoldError::InvalidHold { .. } => WorkflowError::OperationHold {
            asset_id: record.asset_id.clone(),
            reason: "hold is invalid",
        },
        OperationHoldError::Manifest(source) => WorkflowError::Manifest(source),
    })
}

#[cfg(test)]
mod per_photo_lifecycle_tests {
    use super::*;
    use crate::operation_hold::{HeldRemoteOperation, OperationHold, apply_operation_hold};
    use crate::state_store::AssetStateStore;
    use crate::upload::{
        CloudKitDatabaseScope, CloudKitDeleteSession, CloudKitResourceDownload,
        CloudKitUploadedHeicReadTransport,
    };
    use sha2::Digest;
    use std::time::Duration;

    fn raw_sha() -> String {
        "cd".repeat(32)
    }

    fn heic_bytes() -> &'static [u8] {
        b"verified-heic-bytes-24b!"
    }

    fn heic_sha() -> String {
        format!("{:x}", sha2::Sha256::digest(heic_bytes()))
    }

    fn nas() -> NasRawProof {
        NasRawProof {
            canonical_path: PathBuf::from("/nas/IMG_0001.dng"),
            relative_path: PathBuf::from("IMG_0001.dng"),
            size_bytes: 42,
            modified_unix_seconds: 1_700_000_000,
            age_seconds: 40 * 24 * 60 * 60,
            sha256: raw_sha(),
        }
    }

    fn conversion_input(binding: ConversionSourceBinding) -> ConversionResultInput {
        ConversionResultInput {
            heic_path: PathBuf::from("/staging/IMG_0001.heic"),
            heic_sha256: heic_sha(),
            size_bytes: 24,
            source_binding: binding,
        }
    }

    fn performance() -> ConversionPerformanceInput {
        ConversionPerformanceInput {
            measured_at_unix_seconds: 1_800_000_000,
            conversion_tool: "sips".to_string(),
            conversion_tool_version: Some("test".to_string()),
            heic_quality: 90,
            convert_wall_time_millis: 10,
            total_wall_time_millis: 20,
            user_cpu_time_millis: None,
            system_cpu_time_millis: None,
            peak_rss_kib: None,
            conversion_command_timings: Vec::new(),
        }
    }

    fn heic() -> HeicVerificationInput {
        HeicVerificationInput {
            heic_path: PathBuf::from("/staging/IMG_0001.heic"),
            heic_sha256: heic_sha(),
            size_bytes: 24,
            heif_info_ok: true,
            metadata_copied: true,
            visual_content_ok: true,
            visual_match_ok: true,
            visual_rmse_ppm: Some(1),
            visual_mae_ppm: Some(1),
        }
    }

    fn original() -> OriginalAssetProof {
        OriginalAssetProof {
            record_name: "CPLAsset-original".to_string(),
            record_change_tag: "tag-1".to_string(),
            record_type: "CPLAsset".to_string(),
            database_scope: CloudKitDatabaseScope::Private,
            zone_name: "PrimarySync".to_string(),
            owner_record_name: None,
            filename: "IMG_0001.dng".to_string(),
            size_bytes: 42,
            matched_raw_sha256: raw_sha(),
        }
    }

    fn upload_proof() -> UploadProof {
        UploadProof {
            uploaded_heic_asset_id: "CPLAsset-heic".to_string(),
            uploaded_heic_sha256: heic_sha(),
            database_scope: CloudKitDatabaseScope::Private,
            zone_name: "PrimarySync".to_string(),
            owner_record_name: None,
            uploaded_heic_path: Some(PathBuf::from("/staging/IMG_0001.heic")),
        }
    }

    fn current_conversion_verified(asset_id: &str) -> Manifest {
        let mut manifest = Manifest::new();
        discover_raw_asset(&mut manifest, asset_id, "/nas/IMG_0001.dng").unwrap();
        record_nas_proof(&mut manifest, asset_id, nas()).unwrap();
        record_current_conversion_result(
            &mut manifest,
            asset_id,
            conversion_input(ConversionSourceBinding::EmbeddedPreview),
        )
        .unwrap();
        record_current_conversion_performance(&mut manifest, asset_id, performance()).unwrap();
        record_current_heic_verification(&mut manifest, asset_id, heic()).unwrap();
        record_original_asset_proof(&mut manifest, asset_id, original()).unwrap();
        manifest
    }

    fn hold_for(record_name_scope: CloudKitDatabaseScope) -> OperationHold {
        let destination = if record_name_scope == CloudKitDatabaseScope::Shared {
            CloudKitLibraryDestination {
                database_scope: CloudKitDatabaseScope::Shared,
                zone_name: "SharedSync-LIBRARY".to_string(),
                owner_record_name: Some("_shared-owner".to_string()),
            }
        } else {
            CloudKitLibraryDestination::primary_sync()
        };
        OperationHold::uncertain(HeldRemoteOperation::Upload, destination, 1_800_000_000).unwrap()
    }

    #[test]
    fn native_raw_round_trip_preserves_meaning_and_stays_fail_closed() {
        let mut manifest = current_conversion_verified("asset");
        assert!(upload_ready_heic_proof(&manifest, "asset").is_ok());
        let before = manifest.get("asset").unwrap().clone();
        let mut historical = before.clone();
        historical.proofs.get_mut(CONVERSION_PROOF).unwrap()["source_binding"] =
            serde_json::json!("native_raw");
        manifest.upsert_trusted(historical.clone());

        let proof = &manifest.get("asset").unwrap().proofs[CONVERSION_PROOF];
        let decoded = decode_historical_conversion_source("asset", proof).unwrap();
        assert_eq!(
            decoded.source_binding,
            ConversionSourceBinding::historical_native_raw_token()
        );
        assert!(!decoded.current_policy_source);
        assert!(
            decoded.source_binding == ConversionSourceBinding::NativeRaw(NativeRawSource::token())
        );
        assert_eq!(
            identity_migrate_historical_conversion_proof("asset", proof).unwrap(),
            *proof
        );
        assert_eq!(proof["source_binding"], "native_raw");
        assert_eq!(
            manifest.get("asset").unwrap().proofs[HEIC_PROOF],
            before.proofs[HEIC_PROOF]
        );
        assert_eq!(
            manifest.get("asset").unwrap().state,
            State::ConversionVerified
        );

        let error = upload_ready_heic_proof(&manifest, "asset")
            .expect_err("native_raw must not pass the quality gate");
        assert!(matches!(
            error,
            WorkflowError::HistoricalNativeRawUnverified { .. }
        ));
        assert!(!remote_readback_is_verified(&manifest, "asset").unwrap());

        let invalid = serde_json::json!({"source_binding": "native_raw"});
        assert!(decode_historical_conversion_source("asset", &invalid).is_err());
        let unknown = proof.clone();
        let mut unknown = unknown;
        unknown["source_binding"] = serde_json::json!("sensor_render");
        assert!(decode_historical_conversion_source("asset", &unknown).is_err());

        let mut fresh = Manifest::new();
        discover_raw_asset(&mut fresh, "asset", "/nas/IMG_0001.dng").unwrap();
        record_nas_proof(&mut fresh, "asset", nas()).unwrap();
        let untouched = fresh.clone();
        let error = record_current_conversion_result(
            &mut fresh,
            "asset",
            conversion_input(ConversionSourceBinding::historical_native_raw_token()),
        )
        .expect_err("new native_raw proof must not be recorded");
        assert!(matches!(
            error,
            WorkflowError::HistoricalNativeRawUnverified { .. }
        ));
        assert_eq!(fresh, untouched);

        let mut object_fields = BTreeMap::new();
        object_fields.insert("raw_sha256".to_string(), serde_json::json!("cd".repeat(32)));
        object_fields.insert(
            "raw_path".to_string(),
            serde_json::json!("/nas/PrimarySync/IMG_0001.DNG"),
        );
        object_fields.insert(
            "converter".to_string(),
            serde_json::json!("dcraw_emu+magick+heif-enc"),
        );
        object_fields.insert("quality_verified".to_string(), serde_json::json!(true));
        object_fields.insert(
            "provenance".to_string(),
            serde_json::json!({
                "library": "primary",
                "asset_ref": "raw-122ae80b2d2fb76c"
            }),
        );
        let historical_object = serde_json::json!({ "native_raw": object_fields.clone() });
        let mut object_record = before.clone();
        object_record.proofs.get_mut(CONVERSION_PROOF).unwrap()["source_binding"] =
            historical_object.clone();
        let mut object_manifest = Manifest::new();
        object_manifest.upsert_trusted(object_record);
        let stored = &object_manifest.get("asset").unwrap().proofs[CONVERSION_PROOF];
        let decoded = decode_historical_conversion_source("asset", stored).unwrap();
        assert!(!decoded.current_policy_source);
        assert_eq!(
            serde_json::to_value(&decoded.source_binding).unwrap(),
            historical_object
        );
        let ConversionSourceBinding::NativeRaw(source) = &decoded.source_binding else {
            panic!("object native_raw must stay native_raw");
        };
        assert_eq!(
            source
                .object_fields()
                .and_then(|fields| fields.get("provenance")),
            Some(&serde_json::json!({
                "library": "primary",
                "asset_ref": "raw-122ae80b2d2fb76c"
            }))
        );
        assert_eq!(
            source
                .object_fields()
                .and_then(|fields| fields.get("quality_verified")),
            Some(&serde_json::json!(true))
        );
        assert_eq!(
            identity_migrate_historical_conversion_proof("asset", stored).unwrap()["source_binding"],
            historical_object
        );
        let error = upload_ready_heic_proof(&object_manifest, "asset")
            .expect_err("object native_raw must not gain a quality pass");
        assert!(matches!(
            error,
            WorkflowError::HistoricalNativeRawUnverified { .. }
        ));
        for malformed in [
            serde_json::json!({"native_raw": "not-an-object"}),
            serde_json::json!({"sensor_render": {}}),
            serde_json::json!("not_a_source"),
            serde_json::json!({"native_raw": {"raw_sha256": "abc"}, "extra": true}),
        ] {
            let mut broken = before.clone();
            broken.proofs.get_mut(CONVERSION_PROOF).unwrap()["source_binding"] = malformed;
            let mut manifest = Manifest::new();
            manifest.upsert_trusted(broken);
            let proof = &manifest.get("asset").unwrap().proofs[CONVERSION_PROOF];
            assert!(
                decode_historical_conversion_source("asset", proof).is_err(),
                "malformed historical source must fail closed"
            );
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("manifest.json");
        let store =
            AssetStateStore::open_writer(&path, "native-raw-object", Duration::from_secs(30))
                .unwrap();
        store
            .persist_manifest_records_trusted(&object_manifest)
            .unwrap();
        drop(store);
        let loaded = AssetStateStore::open_read_only(&path)
            .unwrap()
            .load()
            .unwrap();
        assert_eq!(
            loaded.get("asset").unwrap().proofs[CONVERSION_PROOF]["source_binding"],
            historical_object
        );
        assert!(matches!(
            upload_ready_heic_proof(&loaded, "asset"),
            Err(WorkflowError::HistoricalNativeRawUnverified { .. })
        ));
    }

    struct ReadbackTransport {
        responses: Vec<Value>,
        bytes: Vec<u8>,
        lookups: usize,
        downloads: usize,
    }

    impl CloudKitUploadedHeicReadTransport for ReadbackTransport {
        fn post_records_lookup(
            &mut self,
            _session: &CloudKitDeleteSession,
            _payload: Value,
        ) -> Result<Value, UploadError> {
            self.lookups += 1;
            Ok(self.responses.remove(0))
        }

        fn download_resource(
            &mut self,
            _session: &CloudKitDeleteSession,
            _download_url: &url::Url,
            expected_size_bytes: u64,
        ) -> Result<CloudKitResourceDownload, UploadError> {
            self.downloads += 1;
            let size_bytes = self.bytes.len() as u64;
            if size_bytes != expected_size_bytes {
                return Err(UploadError::CloudKitOriginalAssetDownloadSizeMismatch {
                    expected: expected_size_bytes,
                    actual: size_bytes,
                });
            }
            Ok(CloudKitResourceDownload {
                sha256: format!("{:x}", sha2::Sha256::digest(&self.bytes)),
                size_bytes,
            })
        }
    }

    fn delete_session_json(scope: &str, zone: &str, owner: Option<&str>) -> String {
        let mut value = serde_json::json!({
            "dsid": "123456789",
            "ckdatabasews_url": "https://p140-ckdatabasews.icloud.com",
            "database_scope": scope,
            "zone_name": zone,
            "cloudkit_query_params": [
                {"name": "clientBuildNumber", "value": "2522Project44"},
                {"name": "clientMasteringNumber", "value": "2522B2"},
                {"name": "clientId", "value": "4f0b58d4-ff9d-4dc5-8f0b-9c4efc4fdb27"},
                {"name": "dsid", "value": "123456789"},
                {"name": "remapEnums", "value": "True"},
                {"name": "getCurrentSyncToken", "value": "True"}
            ],
            "cookies": [
                {"name": "X-APPLE-WEBAUTH-TOKEN", "value": "SENTINEL_COOKIE"},
                {"name": "session", "value": "abc123"}
            ]
        });
        if let Some(owner) = owner {
            value["owner_record_name"] = serde_json::json!(owner);
        }
        value.to_string()
    }

    fn asset_lookup(asset: &str, master: &str) -> Value {
        serde_json::json!({
            "records": [{
                "recordName": asset,
                "recordType": "CPLAsset",
                "recordChangeTag": "heic-change",
                "fields": {
                    "masterRef": {
                        "type": "REFERENCE",
                        "value": {
                            "recordName": master,
                            "zoneID": {
                                "zoneName": "PrimarySync",
                                "ownerRecordName": "opaque-private-owner"
                            },
                            "action": "DELETE_SELF"
                        }
                    },
                    "isDeleted": {"value": 0}
                }
            }]
        })
    }

    fn master_lookup(master: &str, size: u64) -> Value {
        serde_json::json!({
            "records": [{
                "recordName": master,
                "recordType": "CPLMaster",
                "recordChangeTag": "master-change",
                "fields": {
                    "resOriginalRes": {"value": {
                        "size": size,
                        "downloadURL": "https://p140-icloud-content.icloud.com/heic"
                    }},
                    "resOriginalFileType": {"value": "public.heic"}
                }
            }]
        })
    }

    #[test]
    fn remote_readback_requires_downloaded_bytes_and_leaves_a_sibling_alone() {
        let mut good = current_conversion_verified("good");
        record_upload_proof(&mut good, "good", upload_proof()).unwrap();
        assert!(!remote_readback_is_verified(&good, "good").unwrap());
        assert!(
            !good
                .get("good")
                .unwrap()
                .proofs
                .contains_key(REMOTE_READBACK_PROOF)
        );

        let mut other = current_conversion_verified("other");
        let mut other_upload = upload_proof();
        other_upload.uploaded_heic_asset_id = "CPLAsset-other".to_string();
        record_upload_proof(&mut other, "other", other_upload).unwrap();
        let other_before = other.get("other").unwrap().clone();

        let session =
            CloudKitDeleteSession::from_json(&delete_session_json("private", "PrimarySync", None))
                .unwrap();
        let bytes = heic_bytes();
        assert_eq!(bytes.len(), 24);
        let mut wrong = ReadbackTransport {
            responses: vec![
                asset_lookup("CPLAsset-heic", "CPLMaster-heic"),
                master_lookup("CPLMaster-heic", 24),
            ],
            bytes: b"0123456789abcdefghijklmn".to_vec(),
            lookups: 0,
            downloads: 0,
        };
        let error = verify_remote_readback(&mut good, "good", &session, &mut wrong)
            .expect_err("mismatched download must not record readback");
        assert!(matches!(error, WorkflowError::RemoteReadback(_)));
        assert!(!remote_readback_is_verified(&good, "good").unwrap());
        assert_eq!(good.get("good").unwrap().state, State::UploadVerified);

        let mut transport = ReadbackTransport {
            responses: vec![
                asset_lookup("CPLAsset-heic", "CPLMaster-heic"),
                master_lookup("CPLMaster-heic", 24),
            ],
            bytes: bytes.to_vec(),
            lookups: 0,
            downloads: 0,
        };
        let downloaded = heic_sha();
        verify_remote_readback(&mut good, "good", &session, &mut transport).unwrap();
        assert_eq!(transport.downloads, 1);
        assert!(remote_readback_is_verified(&good, "good").unwrap());
        assert_eq!(good.get("good").unwrap().state, State::UploadVerified);
        assert!(!good.get("good").unwrap().proofs.contains_key("delete"));
        let readback = &good.get("good").unwrap().proofs[REMOTE_READBACK_PROOF];
        assert_eq!(readback["matched_heic_sha256"], downloaded);
        assert_eq!(readback["database_scope"], "private");
        assert!(readback.get("cookie").is_none());

        assert_eq!(other.get("other").unwrap(), &other_before);
        assert!(!remote_readback_is_verified(&other, "other").unwrap());

        let shared = CloudKitDeleteSession::from_json(&delete_session_json(
            "shared",
            "SharedSync-LIBRARY",
            Some("_shared-owner"),
        ))
        .unwrap();
        let mut scoped = ReadbackTransport {
            responses: vec![
                asset_lookup("CPLAsset-heic", "CPLMaster-heic"),
                master_lookup("CPLMaster-heic", 24),
            ],
            bytes: bytes.to_vec(),
            lookups: 0,
            downloads: 0,
        };
        assert!(verify_remote_readback(&mut good, "good", &shared, &mut scoped).is_err());
        assert_eq!(scoped.lookups, 0);
        assert_eq!(scoped.downloads, 0);
    }

    #[test]
    fn held_asset_stays_blocked_across_restart_while_eligible_upload_is_not_repeated() {
        let mut held_manifest = current_conversion_verified("held");
        let before = held_manifest.get("held").unwrap().clone();
        let hold = hold_for(CloudKitDatabaseScope::Private);
        assert!(apply_operation_hold(&mut held_manifest, "held", hold.clone()).unwrap());
        assert!(!apply_operation_hold(&mut held_manifest, "held", hold.clone()).unwrap());
        let held_record = held_manifest.get("held").unwrap().clone();
        assert_eq!(held_record.state, before.state);
        assert_eq!(held_record.state, State::ConversionVerified);
        assert_eq!(held_record.failures, before.failures);
        assert_eq!(held_record.raw_path, before.raw_path);
        assert!(!held_record.proofs.contains_key("failure_quarantine"));
        for (key, value) in &before.proofs {
            assert_eq!(held_record.proofs.get(key), Some(value));
        }

        let mut manifest = current_conversion_verified("eligible");
        manifest.upsert_trusted(held_record);
        let held_error = ensure_upload_dispatch_allowed(&manifest, "held")
            .expect_err("held asset must not dispatch");
        assert!(matches!(
            held_error,
            WorkflowError::RemoteOperationHeld { .. }
        ));
        let before_dispatch = manifest.clone();
        assert!(matches!(
            record_upload_proof(&mut manifest, "held", upload_proof()),
            Err(WorkflowError::RemoteOperationHeld { .. })
        ));
        assert_eq!(manifest, before_dispatch);

        assert!(ensure_upload_dispatch_allowed(&manifest, "eligible").is_ok());
        record_upload_proof(&mut manifest, "eligible", upload_proof()).unwrap();
        assert!(!remote_readback_is_verified(&manifest, "eligible").unwrap());
        assert!(
            !manifest
                .get("held")
                .unwrap()
                .proofs
                .contains_key(UPLOAD_PROOF)
        );
        let uploaded = manifest.get("eligible").unwrap().proofs[UPLOAD_PROOF].clone();

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("manifest.json");
        let store =
            AssetStateStore::open_writer(&path, "per-photo-test", Duration::from_secs(30)).unwrap();
        store.persist_manifest_records_trusted(&manifest).unwrap();
        drop(store);
        let loaded = AssetStateStore::open_read_only(&path)
            .unwrap()
            .load()
            .unwrap();
        assert!(matches!(
            ensure_upload_dispatch_allowed(&loaded, "held"),
            Err(WorkflowError::RemoteOperationHeld { .. })
        ));
        assert!(matches!(
            ensure_upload_dispatch_allowed(&loaded, "eligible"),
            Err(WorkflowError::UploadAlreadyRecorded { .. })
        ));
        assert_eq!(
            loaded.get("eligible").unwrap().proofs[UPLOAD_PROOF],
            uploaded
        );
        assert!(!remote_readback_is_verified(&loaded, "eligible").unwrap());

        let mut retry = loaded;
        assert!(record_upload_proof(&mut retry, "eligible", upload_proof()).is_err());
        assert_eq!(
            retry.get("eligible").unwrap().proofs[UPLOAD_PROOF],
            uploaded
        );
        crate::operation_hold::release_operation_hold(&mut retry, "held", &hold).unwrap();
        assert_eq!(retry.get("held").unwrap().state, State::ConversionVerified);
        assert!(ensure_upload_dispatch_allowed(&retry, "held").is_ok());
    }
}

#[cfg(test)]
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::adjusted_source::{
    AdjustedSourceError, CloudKitAdjustedSourceResolveRequest, CloudKitAdjustedSourceResolver,
    CloudKitAdjustedSourceTransport, adjusted_source_path_for_output,
};
use crate::conversion_execution::{
    ConversionExecutionError, ConversionExecutionRequest, execute_measured_conversion,
};
use crate::local_mirror::{IcloudpdLocalMirrorRequest, LocalMirrorError};
use crate::manifest::{
    AssetRecord, FAILURE_QUARANTINE_PROOF_NAME, FailureKind, FailureRecord, Manifest,
    ManifestError, State,
};
use crate::manifest_lock::{
    ManifestLockError, ManifestLockGuard, acquire_manifest_lock, manifest_lock_path,
};
use crate::metrics::VerifiedMetrics;
use crate::proof::{MIN_RAW_AGE_DAYS, NasRawProof, ProofError};
use crate::reconciliation::{
    OriginalAssetResolutionBatch, OriginalAssetResolutionBatchSummary, OriginalAssetResolutionError,
};
use crate::state_store::{AssetRecordExactCasUpdate, AssetStateStore, AssetStateStoreError};
use crate::upload::{
    CLOUDKIT_RECORDS_MODIFY_MAX_OPERATIONS, CloudKitDatabaseScope, CloudKitDeleteBatchRequest,
    CloudKitDeleteBatchSendError, CloudKitDeleteClient, CloudKitDeleteOutcome,
    CloudKitDeleteSession, CloudKitDeleteTransport, CloudKitLibraryDestination,
    CloudKitOriginalAssetBatchResolveOutcome, CloudKitOriginalAssetBatchResolveRequest,
    CloudKitOriginalAssetResolveTarget, ReqwestCloudKitDeleteTransport,
    ReqwestCloudKitReadTransport, UploadError, UploadTimings, load_cloudkit_delete_session,
};
use crate::workflow::{
    ConversionResultProof, DeleteReconciliation, HeicVerificationProof, IcloudpdLocalMirrorProof,
    OriginalAssetProof, PrevalidatedDelete, SourceAgeProof, UploadProof, WorkflowError,
    approve_delete, icloudpd_local_mirror_ready_proofs, mark_delete_eligible,
    prepare_delete_reconciliation, prevalidate_approved_original_delete, prove_and_record_nas,
    reconciliation_exact_state_is_consistent, record_adjusted_source_proof,
    record_heic_verification, record_icloudpd_local_mirror_proof,
    record_prevalidated_delete_execution, record_reconciled_delete_execution,
    record_source_age_proof, record_stage_failure, record_stage_failure_with_kind,
    record_upload_proof, upload_ready_heic_proof, validated_adjusted_source_for_conversion,
};

static MONITOR_FAILURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
thread_local! {
    static PENDING_MONITOR_FAILURE_CORRELATION: RefCell<Option<MonitorFailureCorrelation>> =
        const { RefCell::new(None) };
}
#[cfg(test)]
thread_local! {
    static ADJUSTED_SOURCE_RESOLUTION_FAIL_BEFORE_CAS: Cell<bool> = const { Cell::new(false) };
}

const MONITOR_CONFIG_SCHEMA_VERSION: u64 = 1;
const MONITOR_STATS_SCHEMA_VERSION: u64 = 2;
const DEFAULT_CAPTURE_TOLERANCE_SECONDS: u64 = 2;
const DEFAULT_CLOUDKIT_PAGE_SIZE: u64 = 200;
const DEFAULT_CLOUDKIT_MAX_PAGES: u64 = 2000;
const DEFAULT_SCAN_ROOT_PREFLIGHT_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_LOCAL_MIRROR_TIMEOUT_SECONDS: u64 = 60;
const DEFAULT_UPLOAD_TIMEOUT_SECONDS: u64 = 600;
const DEFAULT_HEIC_VERIFY_TIMEOUT_SECONDS: u64 = 60;
const DEFAULT_MAX_ORIGINAL_RESOLVER_RETRIES_PER_SCAN: usize = 16;
const DEFAULT_ORIGINAL_RESOLVER_RETRY_MIN_AGE_SECONDS: u64 = 24 * 60 * 60;
const DEFAULT_MAX_FAILED_RETRY_ADMISSIONS_PER_SCAN: usize = 16;
const DEFAULT_FAILED_RETRY_MIN_AGE_SECONDS: u64 = 300;
const FAILED_RETRY_POLICY_SCHEMA_VERSION: u64 = 2;
const FAILED_RETRY_POLICY_GENERATION: &str = "codec_normalized_v1";
const FAILURE_RETRY_PROOF: &str = "failure_retry";
const FAILURE_REVIEW_PROOF: &str = "failure_review";
pub const ADJUSTED_SOURCE_REQUIRED_PROOF: &str = "adjusted_source_required";
pub const ADJUSTED_SOURCE_REQUIRED_SCHEMA_VERSION: u64 = 1;
pub const ADJUSTED_SOURCE_REQUIRED_POLICY_GENERATION: &str = "adjusted_source_required_v1";
const ADJUSTED_SOURCE_RESOLVE_RETRY_MIN_AGE_SECONDS: u64 = 300;
const ADJUSTED_SOURCE_RESOLVE_MAX_ATTEMPTS: u64 = 3;
const LEGACY_OUTPUT_UNREADABLE_SUFFIX: &str = ": No such file or directory (os error 2)";
#[cfg(not(test))]
const MONITOR_STATE_LEASE_TTL: Duration = Duration::from_secs(5 * 60);
#[cfg(test)]
const MONITOR_STATE_LEASE_TTL: Duration = Duration::from_millis(40);
const DELETE_LIVE_RAW_MAX_AGE: Duration = Duration::from_secs(30);
const ORIGINAL_ASSET_RESOLVE_BATCH_WINDOW_SECONDS: u64 = 60 * 60;
const DEFAULT_ROLLING_ORIGINAL_RESOLVE_ACTIVE_WINDOW_MULTIPLIER: usize = 2;
const DEFAULT_ROLLING_ORIGINAL_RESOLVE_BATCH_MULTIPLIER: usize = 2;
const MONITOR_VERIFY_PREVIEW_MAX_EDGE: &str = "512";
const MONITOR_VISUAL_RMSE_MAX: f64 = 0.03;
const MONITOR_VISUAL_MAE_MAX: f64 = 0.02;
const MONITOR_HEIC_STDEV_MIN: f64 = 0.001;
const DEFAULT_LAUNCHD_PATH: &str = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";
const RAW_EXTENSIONS: &[&str] = &[
    "dng", "cr2", "cr3", "nef", "arw", "raf", "rw2", "orf", "pef", "srw", "raw",
];
fn default_delete_operator() -> String {
    "icloudpd-optimizer-monitor".to_string()
}

fn default_max_lifecycle_per_scan() -> usize {
    5
}

fn default_max_original_resolver_retries_per_scan() -> usize {
    DEFAULT_MAX_ORIGINAL_RESOLVER_RETRIES_PER_SCAN
}

fn default_original_resolver_retry_min_age_seconds() -> u64 {
    DEFAULT_ORIGINAL_RESOLVER_RETRY_MIN_AGE_SECONDS
}

fn default_max_failed_retry_admissions_per_scan() -> usize {
    DEFAULT_MAX_FAILED_RETRY_ADMISSIONS_PER_SCAN
}

fn default_failed_retry_min_age_seconds() -> u64 {
    DEFAULT_FAILED_RETRY_MIN_AGE_SECONDS
}

fn default_capture_tolerance_seconds() -> u64 {
    DEFAULT_CAPTURE_TOLERANCE_SECONDS
}

fn default_cloudkit_page_size() -> u64 {
    DEFAULT_CLOUDKIT_PAGE_SIZE
}

fn default_cloudkit_max_pages() -> u64 {
    DEFAULT_CLOUDKIT_MAX_PAGES
}

fn default_scan_root_preflight_timeout_seconds() -> u64 {
    DEFAULT_SCAN_ROOT_PREFLIGHT_TIMEOUT_SECONDS
}

fn default_local_mirror_timeout_seconds() -> u64 {
    DEFAULT_LOCAL_MIRROR_TIMEOUT_SECONDS
}

fn default_upload_timeout_seconds() -> u64 {
    DEFAULT_UPLOAD_TIMEOUT_SECONDS
}

fn default_heic_verify_timeout_seconds() -> u64 {
    DEFAULT_HEIC_VERIFY_TIMEOUT_SECONDS
}

fn default_rolling_original_resolve_active_window_multiplier() -> usize {
    DEFAULT_ROLLING_ORIGINAL_RESOLVE_ACTIVE_WINDOW_MULTIPLIER
}

fn default_rolling_original_resolve_batch_multiplier() -> usize {
    DEFAULT_ROLLING_ORIGINAL_RESOLVE_BATCH_MULTIPLIER
}

fn default_scan_recursive() -> bool {
    true
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MonitorConfig {
    pub schema_version: u64,
    pub download_root: PathBuf,
    pub nas_root: PathBuf,
    pub manifest_path: PathBuf,
    pub heic_output_dir: PathBuf,
    pub stats_path: PathBuf,
    pub min_age_days: u64,
    pub scan_interval_seconds: u64,
    pub jobs: usize,
    #[serde(default)]
    pub rolling_worker_count: Option<usize>,
    #[serde(default)]
    pub rolling_cpu_stage_count: Option<usize>,
    #[serde(default)]
    pub rolling_convert_stage_count: Option<usize>,
    pub heic_quality: u8,
    pub max_conversions_per_scan: usize,
    #[serde(default = "default_scan_recursive")]
    pub scan_recursive: bool,
    pub conversion_tool_version: Option<String>,
    #[serde(default)]
    pub full_lifecycle: bool,
    #[serde(default)]
    pub rolling_lifecycle: bool,
    #[serde(default)]
    pub auto_delete: bool,
    #[serde(default)]
    pub upload_session_path: Option<PathBuf>,
    #[serde(default)]
    pub delete_session_path: Option<PathBuf>,
    #[serde(default)]
    pub mirror_root: Option<PathBuf>,
    #[serde(default = "default_delete_operator")]
    pub delete_operator: String,
    #[serde(default = "default_max_lifecycle_per_scan")]
    pub max_lifecycle_per_scan: usize,
    #[serde(default = "default_max_original_resolver_retries_per_scan")]
    pub max_original_resolver_retries_per_scan: usize,
    #[serde(default = "default_original_resolver_retry_min_age_seconds")]
    pub original_resolver_retry_min_age_seconds: u64,
    #[serde(default = "default_max_failed_retry_admissions_per_scan")]
    pub max_failed_retry_admissions_per_scan: usize,
    #[serde(default = "default_failed_retry_min_age_seconds")]
    pub failed_retry_min_age_seconds: u64,
    #[serde(default = "default_capture_tolerance_seconds")]
    pub capture_tolerance_seconds: u64,
    #[serde(default)]
    pub cloudkit_start_rank: u64,
    #[serde(default = "default_cloudkit_page_size")]
    pub cloudkit_page_size: u64,
    #[serde(default = "default_cloudkit_max_pages")]
    pub cloudkit_max_pages: u64,
    #[serde(default = "default_scan_root_preflight_timeout_seconds")]
    pub scan_root_preflight_timeout_seconds: u64,
    #[serde(default = "default_local_mirror_timeout_seconds")]
    pub local_mirror_timeout_seconds: u64,
    #[serde(default = "default_upload_timeout_seconds")]
    pub upload_timeout_seconds: u64,
    #[serde(default = "default_heic_verify_timeout_seconds")]
    pub heic_verify_timeout_seconds: u64,
    #[serde(default = "default_rolling_original_resolve_active_window_multiplier")]
    pub rolling_original_resolve_active_window_multiplier: usize,
    #[serde(default = "default_rolling_original_resolve_batch_multiplier")]
    pub rolling_original_resolve_batch_multiplier: usize,
}

impl MonitorConfig {
    pub fn new(
        download_root: impl Into<PathBuf>,
        manifest_path: impl Into<PathBuf>,
        heic_output_dir: impl Into<PathBuf>,
    ) -> Self {
        let download_root = download_root.into();
        let manifest_path = manifest_path.into();
        Self {
            schema_version: MONITOR_CONFIG_SCHEMA_VERSION,
            nas_root: download_root.clone(),
            download_root,
            stats_path: manifest_path.with_extension("monitor-stats.json"),
            manifest_path,
            heic_output_dir: heic_output_dir.into(),
            min_age_days: MIN_RAW_AGE_DAYS,
            scan_interval_seconds: 300,
            jobs: 1,
            rolling_worker_count: None,
            rolling_cpu_stage_count: None,
            rolling_convert_stage_count: None,
            heic_quality: 90,
            max_conversions_per_scan: 25,
            scan_recursive: true,
            conversion_tool_version: None,
            full_lifecycle: false,
            rolling_lifecycle: false,
            auto_delete: false,
            upload_session_path: None,
            delete_session_path: None,
            mirror_root: None,
            delete_operator: default_delete_operator(),
            max_lifecycle_per_scan: default_max_lifecycle_per_scan(),
            max_original_resolver_retries_per_scan: default_max_original_resolver_retries_per_scan(
            ),
            original_resolver_retry_min_age_seconds:
                default_original_resolver_retry_min_age_seconds(),
            max_failed_retry_admissions_per_scan: default_max_failed_retry_admissions_per_scan(),
            failed_retry_min_age_seconds: default_failed_retry_min_age_seconds(),
            capture_tolerance_seconds: default_capture_tolerance_seconds(),
            cloudkit_start_rank: 0,
            cloudkit_page_size: default_cloudkit_page_size(),
            cloudkit_max_pages: default_cloudkit_max_pages(),
            scan_root_preflight_timeout_seconds: default_scan_root_preflight_timeout_seconds(),
            local_mirror_timeout_seconds: default_local_mirror_timeout_seconds(),
            upload_timeout_seconds: default_upload_timeout_seconds(),
            heic_verify_timeout_seconds: default_heic_verify_timeout_seconds(),
            rolling_original_resolve_active_window_multiplier:
                default_rolling_original_resolve_active_window_multiplier(),
            rolling_original_resolve_batch_multiplier:
                default_rolling_original_resolve_batch_multiplier(),
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, MonitorError> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|source| MonitorError::ReadConfig {
            path: path.to_path_buf(),
            source,
        })?;
        let config = serde_json::from_reader(file).map_err(|source| MonitorError::ParseConfig {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(config)
    }

    pub fn save_atomic(&self, path: impl AsRef<Path>) -> Result<(), MonitorError> {
        write_json_atomic(path.as_ref(), self).map_err(|source| MonitorError::WriteConfig {
            path: path.as_ref().to_path_buf(),
            source,
        })
    }

    pub fn validate(&self) -> Result<(), MonitorError> {
        if self.schema_version != MONITOR_CONFIG_SCHEMA_VERSION {
            return Err(MonitorError::InvalidConfig {
                message: format!(
                    "unsupported monitor config schema version {}",
                    self.schema_version
                ),
            });
        }
        let state_db_path = AssetStateStore::db_path_for_manifest(&self.manifest_path);
        let state_paths = [&self.manifest_path, &state_db_path];
        let mut media_roots = vec![&self.download_root, &self.nas_root];
        if let Some(mirror_root) = &self.mirror_root {
            media_roots.push(mirror_root);
        }
        if state_paths.iter().any(|state_path| {
            media_roots
                .iter()
                .any(|media_root| state_path.starts_with(media_root))
        }) {
            return Err(MonitorError::InvalidConfig {
                message:
                    "manifest and state database must be outside download, NAS, and mirror roots"
                        .to_string(),
            });
        }
        if self.min_age_days < MIN_RAW_AGE_DAYS {
            return Err(MonitorError::InvalidConfig {
                message: format!("min_age_days must be at least {}", MIN_RAW_AGE_DAYS),
            });
        }
        if self.scan_interval_seconds == 0 {
            return Err(MonitorError::InvalidConfig {
                message: "scan_interval_seconds must be greater than 0".to_string(),
            });
        }
        if self.jobs == 0 {
            return Err(MonitorError::InvalidConfig {
                message: "jobs must be greater than 0".to_string(),
            });
        }
        if self.rolling_worker_count == Some(0) {
            return Err(MonitorError::InvalidConfig {
                message: "rolling_worker_count must be greater than 0 when set".to_string(),
            });
        }
        if self.rolling_cpu_stage_count == Some(0) {
            return Err(MonitorError::InvalidConfig {
                message: "rolling_cpu_stage_count must be greater than 0 when set".to_string(),
            });
        }
        if self.rolling_convert_stage_count == Some(0) {
            return Err(MonitorError::InvalidConfig {
                message: "rolling_convert_stage_count must be greater than 0 when set".to_string(),
            });
        }
        if !(1..=100).contains(&self.heic_quality) {
            return Err(MonitorError::InvalidConfig {
                message: "heic_quality must be between 1 and 100".to_string(),
            });
        }
        if self.max_conversions_per_scan == 0 {
            return Err(MonitorError::InvalidConfig {
                message: "max_conversions_per_scan must be greater than 0".to_string(),
            });
        }
        if self.max_lifecycle_per_scan == 0 {
            return Err(MonitorError::InvalidConfig {
                message: "max_lifecycle_per_scan must be greater than 0".to_string(),
            });
        }
        if self.max_original_resolver_retries_per_scan == 0 {
            return Err(MonitorError::InvalidConfig {
                message: "max_original_resolver_retries_per_scan must be greater than 0"
                    .to_string(),
            });
        }
        if self.original_resolver_retry_min_age_seconds == 0 {
            return Err(MonitorError::InvalidConfig {
                message: "original_resolver_retry_min_age_seconds must be greater than 0"
                    .to_string(),
            });
        }
        if self.full_lifecycle && self.upload_session_path.is_none() {
            return Err(MonitorError::InvalidConfig {
                message: "full_lifecycle requires upload_session_path".to_string(),
            });
        }
        if self.full_lifecycle && self.delete_session_path.is_none() {
            return Err(MonitorError::InvalidConfig {
                message: "full_lifecycle requires delete_session_path".to_string(),
            });
        }
        if self.auto_delete && !self.full_lifecycle {
            return Err(MonitorError::InvalidConfig {
                message: "auto_delete requires full_lifecycle".to_string(),
            });
        }
        if self.rolling_lifecycle && !self.full_lifecycle {
            return Err(MonitorError::InvalidConfig {
                message: "rolling_lifecycle requires full_lifecycle".to_string(),
            });
        }
        if self.auto_delete && self.delete_operator.trim().is_empty() {
            return Err(MonitorError::InvalidConfig {
                message: "delete_operator must be non-empty when auto_delete is enabled"
                    .to_string(),
            });
        }
        if self.cloudkit_page_size == 0 {
            return Err(MonitorError::InvalidConfig {
                message: "cloudkit_page_size must be greater than 0".to_string(),
            });
        }
        if self.cloudkit_max_pages == 0 {
            return Err(MonitorError::InvalidConfig {
                message: "cloudkit_max_pages must be greater than 0".to_string(),
            });
        }
        if self.scan_root_preflight_timeout_seconds == 0 {
            return Err(MonitorError::InvalidConfig {
                message: "scan_root_preflight_timeout_seconds must be greater than 0".to_string(),
            });
        }
        if self.local_mirror_timeout_seconds == 0 {
            return Err(MonitorError::InvalidConfig {
                message: "local_mirror_timeout_seconds must be greater than 0".to_string(),
            });
        }
        if self.upload_timeout_seconds == 0 {
            return Err(MonitorError::InvalidConfig {
                message: "upload_timeout_seconds must be greater than 0".to_string(),
            });
        }
        if self.heic_verify_timeout_seconds == 0 {
            return Err(MonitorError::InvalidConfig {
                message: "heic_verify_timeout_seconds must be greater than 0".to_string(),
            });
        }
        if self.max_failed_retry_admissions_per_scan == 0 {
            return Err(MonitorError::InvalidConfig {
                message: "max_failed_retry_admissions_per_scan must be greater than 0".to_string(),
            });
        }
        if self.failed_retry_min_age_seconds == 0 {
            return Err(MonitorError::InvalidConfig {
                message: "failed_retry_min_age_seconds must be greater than 0".to_string(),
            });
        }
        if self.rolling_original_resolve_active_window_multiplier == 0 {
            return Err(MonitorError::InvalidConfig {
                message: "rolling_original_resolve_active_window_multiplier must be greater than 0"
                    .to_string(),
            });
        }
        if self.rolling_original_resolve_batch_multiplier == 0 {
            return Err(MonitorError::InvalidConfig {
                message: "rolling_original_resolve_batch_multiplier must be greater than 0"
                    .to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MonitorStats {
    pub schema_version: u64,
    pub scans_started: u64,
    pub scans_completed: u64,
    pub raw_files_seen: u64,
    pub candidates_verified: u64,
    pub conversions_attempted: u64,
    pub conversions_completed: u64,
    pub heics_verified: u64,
    pub originals_resolved: u64,
    pub uploads_attempted: u64,
    pub uploads_completed: u64,
    pub mirrors_recorded: u64,
    pub originals_deleted: u64,
    pub uploaded_heic_bytes: u64,
    pub deleted_raw_bytes: u64,
    pub bytes_saved: u64,
    pub skipped_known: u64,
    pub skipped_not_ready: u64,
    pub failures: u64,
    pub last_scan_started_unix_seconds: Option<u64>,
    pub last_scan_finished_unix_seconds: Option<u64>,
    pub last_error: Option<String>,
    pub state_counts: BTreeMap<String, u64>,
    #[serde(default)]
    pub terminal_records: u64,
    #[serde(default)]
    pub no_action_records: u64,
    #[serde(default)]
    pub needs_review_records: u64,
    #[serde(default)]
    pub failed_records: u64,
    #[serde(default)]
    pub pending_records: u64,
}

impl MonitorStats {
    pub fn new() -> Self {
        Self {
            schema_version: MONITOR_STATS_SCHEMA_VERSION,
            ..Self::default()
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, MonitorError> {
        let path = path.as_ref();
        match File::open(path) {
            Ok(file) => serde_json::from_reader(file).map_err(|source| MonitorError::ParseStats {
                path: path.to_path_buf(),
                source,
            }),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(Self::new()),
            Err(source) => Err(MonitorError::ReadStats {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    pub fn save_atomic(&self, path: impl AsRef<Path>) -> Result<(), MonitorError> {
        write_json_atomic(path.as_ref(), self).map_err(|source| MonitorError::WriteStats {
            path: path.as_ref().to_path_buf(),
            source,
        })
    }

    fn apply_scan(&mut self, summary: &MonitorScanSummary) {
        self.scans_completed = self.scans_completed.saturating_add(1);
        self.raw_files_seen = self.raw_files_seen.saturating_add(summary.raw_files_seen);
        self.candidates_verified = self
            .candidates_verified
            .saturating_add(summary.candidates_verified);
        self.conversions_attempted = self
            .conversions_attempted
            .saturating_add(summary.conversions_attempted);
        self.conversions_completed = self
            .conversions_completed
            .saturating_add(summary.conversions_completed);
        self.heics_verified = self.heics_verified.saturating_add(summary.heics_verified);
        self.originals_resolved = self
            .originals_resolved
            .saturating_add(summary.originals_resolved);
        self.uploads_attempted = self
            .uploads_attempted
            .saturating_add(summary.uploads_attempted);
        self.uploads_completed = self
            .uploads_completed
            .saturating_add(summary.uploads_completed);
        self.mirrors_recorded = self
            .mirrors_recorded
            .saturating_add(summary.mirrors_recorded);
        self.originals_deleted = self
            .originals_deleted
            .saturating_add(summary.originals_deleted);
        self.uploaded_heic_bytes = self
            .uploaded_heic_bytes
            .saturating_add(summary.uploaded_heic_bytes);
        self.deleted_raw_bytes = self
            .deleted_raw_bytes
            .saturating_add(summary.deleted_raw_bytes);
        self.bytes_saved = self.bytes_saved.saturating_add(summary.bytes_saved);
        self.skipped_known = self.skipped_known.saturating_add(summary.skipped_known);
        self.skipped_not_ready = self
            .skipped_not_ready
            .saturating_add(summary.skipped_not_ready);
        self.failures = self.failures.saturating_add(summary.failures);
        self.last_scan_finished_unix_seconds = Some(summary.finished_unix_seconds);
        self.last_error = summary.last_error.clone();
        self.state_counts = summary.state_counts.clone();
        self.terminal_records = summary.terminal_records;
        self.no_action_records = summary.no_action_records;
        self.needs_review_records = summary.needs_review_records;
        self.failed_records = summary.failed_records;
        self.pending_records = summary.pending_records;
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct MonitorScanSummary {
    pub raw_files_seen: u64,
    pub candidates_verified: u64,
    pub conversions_attempted: u64,
    pub conversions_completed: u64,
    pub heics_verified: u64,
    pub originals_resolved: u64,
    pub adjusted_sources_resolved: u64,
    pub adjusted_source_resolution_failures: u64,
    pub uploads_attempted: u64,
    pub uploads_completed: u64,
    pub mirrors_recorded: u64,
    pub originals_deleted: u64,
    pub uploaded_heic_bytes: u64,
    pub deleted_raw_bytes: u64,
    pub bytes_saved: u64,
    pub skipped_known: u64,
    pub skipped_not_ready: u64,
    pub failures: u64,
    pub started_unix_seconds: u64,
    pub finished_unix_seconds: u64,
    pub last_error: Option<String>,
    pub state_counts: BTreeMap<String, u64>,
    pub terminal_records: u64,
    pub no_action_records: u64,
    pub needs_review_records: u64,
    pub failed_records: u64,
    pub pending_records: u64,
}

pub fn run_monitor_once(
    config: &MonitorConfig,
    guard: &mut MonitorRunGuard,
) -> Result<MonitorScanSummary, MonitorError> {
    clear_pending_monitor_failure_correlation();
    config.validate()?;
    fs::create_dir_all(&config.heic_output_dir).map_err(|source| MonitorError::CreateDir {
        path: config.heic_output_dir.clone(),
        source,
    })?;

    let started = current_unix_seconds();
    let mut stats = MonitorStats::load(&config.stats_path)?;
    stats.scans_started = stats.scans_started.saturating_add(1);
    stats.last_scan_started_unix_seconds = Some(started);

    let download_root = fs::canonicalize(&config.download_root).map_err(|source| {
        MonitorError::CanonicalizeRoot {
            path: config.download_root.clone(),
            source,
        }
    })?;
    ensure_scan_root_access(&download_root, config.scan_root_preflight_timeout_seconds)?;

    let state_store = Arc::new(guard.state_store(&config.manifest_path)?.clone());
    let mut manifest = state_store.load_or_import()?;
    let mut summary = MonitorScanSummary {
        started_unix_seconds: started,
        ..MonitorScanSummary::default()
    };
    let retry_admissions = admit_scan_retry_policies(
        &mut manifest,
        if config.full_lifecycle {
            config.max_lifecycle_per_scan
        } else {
            0
        },
        config.max_failed_retry_admissions_per_scan,
        config.failed_retry_min_age_seconds,
        config.max_original_resolver_retries_per_scan,
        config.original_resolver_retry_min_age_seconds,
        started,
    )?;
    let failed_retry_admission = retry_admissions.failed_retry;
    let adjusted_source_required_admission = retry_admissions.adjusted_source_required;
    let original_asset_resolver_retry_admission = retry_admissions.original_asset_resolver;
    if failed_retry_admission.manifest_changed()
        || adjusted_source_required_admission.manifest_changed()
        || original_asset_resolver_retry_admission.manifest_changed()
    {
        checkpoint_manifest_state(&state_store, &manifest)?;
    }
    log_monitor_event(
        "failed_retry_policy_admission",
        started,
        failed_retry_policy_admission_fields(&failed_retry_admission),
    );
    log_monitor_event(
        "adjusted_source_required_admission",
        started,
        adjusted_source_required_admission_fields(&adjusted_source_required_admission),
    );
    log_monitor_event(
        "original_asset_resolver_retry_admission",
        started,
        original_asset_resolver_retry_admission_fields(&original_asset_resolver_retry_admission),
    );
    let mut active_lifecycle_ids = if config.full_lifecycle {
        active_lifecycle_asset_ids_for_config(config, &manifest)
    } else {
        Vec::new()
    };
    let had_lifecycle_pending_at_start = config.full_lifecycle && !active_lifecycle_ids.is_empty();
    log_monitor_event(
        "scan_started",
        started,
        json!({
            "full_lifecycle": config.full_lifecycle,
            "rolling_lifecycle": config.rolling_lifecycle,
            "active_lifecycle": active_lifecycle_ids.len(),
            "had_lifecycle_pending_at_start": had_lifecycle_pending_at_start,
            "max_conversions_per_scan": config.max_conversions_per_scan,
            "max_lifecycle_per_scan": config.max_lifecycle_per_scan,
            "max_original_resolver_retries_per_scan": config.max_original_resolver_retries_per_scan,
            "original_resolver_retry_min_age_seconds": config.original_resolver_retry_min_age_seconds,
            "scan_recursive": config.scan_recursive,
        }),
    );

    if config.full_lifecycle {
        let audit = startup_delete_audit(&manifest);
        log_monitor_event(
            "startup_delete_audit",
            started,
            startup_delete_audit_fields(&audit, config.max_lifecycle_per_scan),
        );
    }

    if config.full_lifecycle && !config.rolling_lifecycle {
        log_monitor_event(
            "lifecycle_started",
            started,
            json!({
                "pending_lifecycle": pending_lifecycle_count(&manifest),
                "position": "before_discovery",
            }),
        );
        run_lifecycle_stages(
            config,
            &state_store,
            &mut manifest,
            &mut summary,
            &active_lifecycle_ids,
        )?;
    }

    let new_work_skip_reason = new_monitor_work_skip_reason(
        had_lifecycle_pending_at_start,
        config.rolling_lifecycle,
        active_lifecycle_ids.len(),
        config.max_lifecycle_per_scan,
    );
    if new_work_skip_reason.is_none() {
        let now = SystemTime::now();
        let mut pending_capacity = config
            .max_conversions_per_scan
            .saturating_sub(pending_conversion_count(&manifest, config));
        if pending_capacity > 0 {
            log_monitor_event(
                "discovery_started",
                started,
                json!({
                    "pending_capacity": pending_capacity,
                    "scan_recursive": config.scan_recursive,
                }),
            );
            visit_raw_paths(&download_root, config.scan_recursive, &mut |raw_path| {
                if pending_capacity == 0 {
                    return Ok(VisitDecision::Stop);
                }
                summary.raw_files_seen = summary.raw_files_seen.saturating_add(1);
                let asset_id = monitor_asset_id(&download_root, &raw_path)?;
                match manifest.records().get(&asset_id).map(|record| record.state) {
                    Some(State::Converted)
                    | Some(State::ConversionVerified)
                    | Some(State::UploadVerified)
                    | Some(State::DeleteEligible)
                    | Some(State::DeleteApproved)
                    | Some(State::Deleted)
                    | Some(State::Failed)
                    | Some(State::NoAction)
                    | Some(State::NeedsReview) => {
                        summary.skipped_known = summary.skipped_known.saturating_add(1);
                        return Ok(VisitDecision::Continue);
                    }
                    Some(State::NasVerified) => return Ok(VisitDecision::Continue),
                    Some(State::Discovered) | None => {}
                }

                match prove_and_record_nas(
                    &mut manifest,
                    &asset_id,
                    &raw_path,
                    &config.nas_root,
                    config.min_age_days,
                    now,
                ) {
                    Ok(record) => {
                        let nas = decode_monitor_proof::<NasRawProof>(record, "nas")?;
                        record_source_age_proof(
                            &mut manifest,
                            &asset_id,
                            SourceAgeProof {
                                source_captured_unix_seconds: nas.modified_unix_seconds,
                                verified_at_unix_seconds: started,
                                min_age_seconds: config.min_age_days.saturating_mul(24 * 60 * 60),
                            },
                        )?;
                        summary.candidates_verified = summary.candidates_verified.saturating_add(1);
                        pending_capacity = pending_capacity.saturating_sub(1);
                    }
                    Err(error) if workflow_error_is_not_ready(&error) => {
                        summary.skipped_not_ready = summary.skipped_not_ready.saturating_add(1);
                    }
                    Err(error) => {
                        summary.failures = summary.failures.saturating_add(1);
                        summary.last_error = Some(error.to_string());
                    }
                }
                Ok(VisitDecision::Continue)
            })?;
            log_monitor_event(
                "discovery_finished",
                started,
                json!({
                    "raw_files_seen": summary.raw_files_seen,
                    "candidates_verified": summary.candidates_verified,
                    "skipped_known": summary.skipped_known,
                    "skipped_not_ready": summary.skipped_not_ready,
                    "failures": summary.failures,
                }),
            );
        }

        checkpoint_manifest_state(&state_store, &manifest)?;
    } else {
        log_monitor_event(
            "new_work_skipped",
            started,
            json!({
                "reason": new_work_skip_reason.unwrap_or("unknown"),
                "active_lifecycle": active_lifecycle_ids.len(),
                "max_lifecycle_per_scan": config.max_lifecycle_per_scan,
                "pending_lifecycle_after_lifecycle": pending_lifecycle_count(&manifest),
            }),
        );
    }

    refresh_active_lifecycle_ids_after_discovery(config, &manifest, &mut active_lifecycle_ids);

    if config.full_lifecycle {
        log_monitor_event(
            "lifecycle_started",
            started,
            json!({
                "active_lifecycle": active_lifecycle_ids.len(),
                "pending_lifecycle": pending_lifecycle_count(&manifest),
                "position": "before_conversions",
            }),
        );
        if config.rolling_lifecycle {
            run_rolling_lifecycle_passes(
                config,
                &state_store,
                &mut manifest,
                &mut summary,
                &active_lifecycle_ids,
            )?;
        } else {
            resolve_original_assets(
                config,
                &state_store,
                &mut manifest,
                &mut summary,
                &active_lifecycle_ids,
            )?;
            checkpoint_manifest_state(&state_store, &manifest)?;
        }
    }

    if !config.rolling_lifecycle {
        let requests = conversion_requests(
            &manifest,
            config,
            config
                .full_lifecycle
                .then_some(active_lifecycle_ids.as_slice()),
        );
        summary.conversions_attempted = requests.len() as u64;
        if !requests.is_empty() {
            log_monitor_event(
                "conversions_started",
                started,
                json!({
                    "requests": requests.len(),
                    "jobs": config.jobs,
                }),
            );
            execute_monitor_conversions(
                config,
                &state_store,
                &mut manifest,
                &mut summary,
                requests,
            )?;
        }

        if config.full_lifecycle {
            log_monitor_event(
                "lifecycle_started",
                started,
                json!({
                    "active_lifecycle": active_lifecycle_ids.len(),
                    "pending_lifecycle": pending_lifecycle_count(&manifest),
                    "position": "after_conversions",
                }),
            );
            run_lifecycle_stages(
                config,
                &state_store,
                &mut manifest,
                &mut summary,
                &active_lifecycle_ids,
            )?;
        }
    }

    checkpoint_manifest_state(&state_store, &manifest)?;

    summary.finished_unix_seconds = current_unix_seconds();
    let metrics = VerifiedMetrics::from_manifest(&manifest);
    summary.state_counts = metrics.state_counts;
    summary.terminal_records = metrics.terminal_records;
    summary.no_action_records = metrics.no_action_records;
    summary.needs_review_records = metrics.needs_review_records;
    summary.failed_records = metrics.failed_records;
    summary.pending_records = metrics.pending_records;
    stats.apply_scan(&summary);
    stats.save_atomic(&config.stats_path)?;
    log_monitor_event(
        "scan_finished",
        started,
        json!({
            "finished_unix_seconds": summary.finished_unix_seconds,
            "raw_files_seen": summary.raw_files_seen,
            "candidates_verified": summary.candidates_verified,
            "conversions_attempted": summary.conversions_attempted,
            "conversions_completed": summary.conversions_completed,
            "uploads_completed": summary.uploads_completed,
            "originals_deleted": summary.originals_deleted,
            "failures": summary.failures,
        }),
    );

    Ok(summary)
}

#[derive(Debug)]
pub struct MonitorRunGuard {
    lock: ManifestLockGuard,
    owner_id: String,
    state_store: Option<AssetStateStore>,
    heartbeat: Option<MonitorLeaseHeartbeat>,
}

#[derive(Debug)]
struct MonitorLeaseHeartbeat {
    stop_tx: Option<mpsc::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl MonitorLeaseHeartbeat {
    fn start(state_store: AssetStateStore) -> Self {
        let (stop_tx, stop_rx) = mpsc::channel();
        let interval = Duration::from_millis(
            u64::try_from((MONITOR_STATE_LEASE_TTL.as_millis() / 3).max(1))
                .expect("monitor lease heartbeat interval should fit u64"),
        );
        let thread = thread::spawn(move || {
            loop {
                match stop_rx.recv_timeout(interval) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if let Err(error) = state_store.renew_writer_lease() {
                            state_store.record_writer_lease_heartbeat_failure(error.to_string());
                            break;
                        }
                    }
                }
            }
        });

        Self {
            stop_tx: Some(stop_tx),
            thread: Some(thread),
        }
    }

    fn stop_and_join(&mut self) {
        self.stop_tx.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for MonitorLeaseHeartbeat {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

pub fn monitor_run_lock_path(config: &MonitorConfig) -> PathBuf {
    manifest_lock_path(&config.manifest_path)
}

pub fn acquire_monitor_run_guard(config: &MonitorConfig) -> Result<MonitorRunGuard, MonitorError> {
    let owner_id = Uuid::new_v4().to_string();
    let lock = acquire_manifest_lock(&config.manifest_path, &owner_id, true)
        .map_err(monitor_lock_error)?;

    Ok(MonitorRunGuard {
        lock,
        owner_id,
        state_store: None,
        heartbeat: None,
    })
}

impl MonitorRunGuard {
    pub(crate) fn state_store(
        &mut self,
        manifest_path: &Path,
    ) -> Result<&AssetStateStore, MonitorError> {
        self.lock.revalidate().map_err(monitor_lock_error)?;
        match self.state_store.as_ref() {
            Some(store) => store.renew_writer_lease()?,
            None => {
                let state_store = AssetStateStore::open_writer(
                    manifest_path,
                    self.owner_id.clone(),
                    MONITOR_STATE_LEASE_TTL,
                )?;
                self.heartbeat = Some(MonitorLeaseHeartbeat::start(state_store.clone()));
                self.state_store = Some(state_store);
            }
        }
        Ok(self.state_store.as_ref().expect("state store should exist"))
    }
}

impl Drop for MonitorRunGuard {
    fn drop(&mut self) {
        if let Some(mut heartbeat) = self.heartbeat.take() {
            heartbeat.stop_and_join();
        }
        if let Some(state_store) = self.state_store.as_ref() {
            let _ = state_store.release_writer_lease();
        }
    }
}

fn monitor_lock_error(error: ManifestLockError) -> MonitorError {
    match error {
        ManifestLockError::UnsupportedPlatform => MonitorError::MonitorLockUnsupported,
        ManifestLockError::Held { lock_path } => MonitorError::MonitorAlreadyRunning { lock_path },
        ManifestLockError::Missing { lock_path } => MonitorError::MonitorLockIo {
            path: lock_path,
            source: io::Error::other("monitor lock disappeared before it could be opened"),
        },
        ManifestLockError::Symlink { path } => MonitorError::MonitorLockIo {
            path,
            source: io::Error::other("monitor lock must not be a symbolic link"),
        },
        ManifestLockError::NotRegular { path } => MonitorError::MonitorLockIo {
            path,
            source: io::Error::other("monitor lock must be a regular file"),
        },
        ManifestLockError::HardLink { path, .. } => MonitorError::MonitorLockIo {
            path,
            source: io::Error::other("monitor lock must not be hard-linked"),
        },
        ManifestLockError::IdentityChanged { path } => MonitorError::MonitorLockIo {
            path,
            source: io::Error::other("monitor lock changed after open"),
        },
        ManifestLockError::Io { path, source } => MonitorError::MonitorLockIo { path, source },
    }
}

pub fn render_tui(config: &MonitorConfig, stats: &MonitorStats) -> String {
    let last_error = stats.last_error.as_deref().unwrap_or("none");
    let state_counts = if stats.state_counts.is_empty() {
        "none".to_string()
    } else {
        stats
            .state_counts
            .iter()
            .map(|(state, count)| format!("{state}: {count}"))
            .collect::<Vec<_>>()
            .join("  ")
    };

    format!(
        concat!(
            "icloudpd-optimizer monitor\n",
            "download root: {download_root}\n",
            "manifest: {manifest}\n",
            "output dir: {output_dir}\n",
            "\n",
            "scans: {scans_completed}/{scans_started}  raw seen: {raw_seen}  ",
            "verified: {verified}  converted: {converted}/{attempted}\n",
            "heic verified: {heics_verified}  original proofs: {originals_resolved}  ",
            "uploaded: {uploads_completed}/{uploads_attempted}  deleted originals: {originals_deleted}\n",
            "uploaded bytes: {uploaded_heic_bytes}  deleted RAW bytes: {deleted_raw_bytes}  ",
            "saved: {saved_gib} GiB\n",
            "skipped known: {skipped_known}  skipped not ready: {skipped_not_ready}  ",
            "failures: {failures}\n",
            "terminal: {terminal_records}  no action: {no_action_records}  ",
            "needs review: {needs_review_records}  pending: {pending_records}  ",
            "failed: {failed_records}\n",
            "last scan: {last_scan}  interval: {interval}s  jobs: {jobs}\n",
            "states: {state_counts}\n",
            "last error: {last_error}\n",
            "\n",
            "Press Ctrl-C to stop.\n"
        ),
        download_root = config.download_root.display(),
        manifest = config.manifest_path.display(),
        output_dir = config.heic_output_dir.display(),
        scans_completed = stats.scans_completed,
        scans_started = stats.scans_started,
        raw_seen = stats.raw_files_seen,
        verified = stats.candidates_verified,
        converted = stats.conversions_completed,
        attempted = stats.conversions_attempted,
        heics_verified = stats.heics_verified,
        originals_resolved = stats.originals_resolved,
        uploads_completed = stats.uploads_completed,
        uploads_attempted = stats.uploads_attempted,
        originals_deleted = stats.originals_deleted,
        uploaded_heic_bytes = stats.uploaded_heic_bytes,
        deleted_raw_bytes = stats.deleted_raw_bytes,
        saved_gib = format_gib(stats.bytes_saved),
        skipped_known = stats.skipped_known,
        skipped_not_ready = stats.skipped_not_ready,
        failures = stats.failures,
        terminal_records = stats.terminal_records,
        no_action_records = stats.no_action_records,
        needs_review_records = stats.needs_review_records,
        pending_records = stats.pending_records,
        failed_records = stats.failed_records,
        last_scan = stats
            .last_scan_finished_unix_seconds
            .map(|value| value.to_string())
            .unwrap_or_else(|| "never".to_string()),
        interval = config.scan_interval_seconds,
        jobs = config.jobs,
        state_counts = state_counts,
        last_error = last_error,
    )
}

pub fn launchd_plist(
    label: &str,
    binary: &Path,
    config: &Path,
    stdout_path: &Path,
    stderr_path: &Path,
    associated_bundle_id: Option<&str>,
) -> Result<String, MonitorError> {
    validate_launchd_label(label)?;
    let associated_bundle_identifiers = match associated_bundle_id {
        Some(bundle_id) => {
            validate_bundle_identifier(bundle_id)?;
            format!(
                concat!(
                    "  <key>AssociatedBundleIdentifiers</key>\n",
                    "  <array>\n",
                    "    <string>{bundle_id}</string>\n",
                    "  </array>\n"
                ),
                bundle_id = escape_xml(bundle_id),
            )
        }
        None => String::new(),
    };
    Ok(format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
            "<plist version=\"1.0\">\n",
            "<dict>\n",
            "  <key>Label</key>\n",
            "  <string>{label}</string>\n",
            "  <key>ProgramArguments</key>\n",
            "  <array>\n",
            "    <string>{binary}</string>\n",
            "    <string>monitor</string>\n",
            "    <string>run</string>\n",
            "    <string>--config</string>\n",
            "    <string>{config}</string>\n",
            "  </array>\n",
            "{associated_bundle_identifiers}",
            "  <key>RunAtLoad</key>\n",
            "  <true/>\n",
            "  <key>KeepAlive</key>\n",
            "  <true/>\n",
            "  <key>EnvironmentVariables</key>\n",
            "  <dict>\n",
            "    <key>PATH</key>\n",
            "    <string>{launchd_path}</string>\n",
            "  </dict>\n",
            "  <key>StandardOutPath</key>\n",
            "  <string>{stdout_path}</string>\n",
            "  <key>StandardErrorPath</key>\n",
            "  <string>{stderr_path}</string>\n",
            "</dict>\n",
            "</plist>\n"
        ),
        label = escape_xml(label),
        binary = escape_xml(&binary.display().to_string()),
        config = escape_xml(&config.display().to_string()),
        associated_bundle_identifiers = associated_bundle_identifiers,
        launchd_path = escape_xml(DEFAULT_LAUNCHD_PATH),
        stdout_path = escape_xml(&stdout_path.display().to_string()),
        stderr_path = escape_xml(&stderr_path.display().to_string()),
    ))
}

pub fn write_launchd_plist(
    label: &str,
    binary: &Path,
    config: &Path,
    stdout_path: &Path,
    stderr_path: &Path,
    output: &Path,
    associated_bundle_id: Option<&str>,
) -> Result<(), MonitorError> {
    let plist = launchd_plist(
        label,
        binary,
        config,
        stdout_path,
        stderr_path,
        associated_bundle_id,
    )?;
    write_text_atomic(output, &plist).map_err(|source| MonitorError::WriteLaunchdPlist {
        path: output.to_path_buf(),
        source,
    })
}

fn conversion_requests(
    manifest: &Manifest,
    config: &MonitorConfig,
    active_lifecycle_asset_ids: Option<&[String]>,
) -> Vec<ConversionExecutionRequest> {
    conversion_requests_with_limit(
        manifest,
        config,
        active_lifecycle_asset_ids,
        config.max_conversions_per_scan,
    )
}

fn conversion_requests_with_limit(
    manifest: &Manifest,
    config: &MonitorConfig,
    active_lifecycle_asset_ids: Option<&[String]>,
    limit: usize,
) -> Vec<ConversionExecutionRequest> {
    let mut records = manifest
        .records()
        .values()
        .filter(|record| record.state == State::NasVerified)
        .filter(|record| active_lifecycle_allows(active_lifecycle_asset_ids, &record.asset_id))
        .filter(|record| !config.full_lifecycle || record.proofs.contains_key("original_asset"))
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        raw_size_bytes_from_record(right)
            .cmp(&raw_size_bytes_from_record(left))
            .then_with(|| left.asset_id.cmp(&right.asset_id))
    });
    records
        .into_iter()
        .take(limit.min(config.max_conversions_per_scan))
        .map(|record| ConversionExecutionRequest {
            asset_id: record.asset_id.clone(),
            output_path: config
                .heic_output_dir
                .join(format!("{}.heic", record.asset_id)),
            heic_quality: config.heic_quality,
            conversion_tool_version: config.conversion_tool_version.clone(),
        })
        .collect()
}

fn raw_size_bytes_from_record(record: &AssetRecord) -> u64 {
    record
        .proofs
        .get("nas")
        .and_then(|proof| proof.get("size_bytes"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

fn execute_monitor_conversions(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    requests: Vec<ConversionExecutionRequest>,
) -> Result<(), MonitorError> {
    for chunk in requests.chunks(config.jobs) {
        let mut handles = Vec::with_capacity(chunk.len());
        for request in chunk {
            let manifest_snapshot = manifest.clone();
            let request = request.clone();
            let asset_id = request.asset_id.clone();
            handles.push((
                asset_id.clone(),
                thread::spawn(move || {
                    execute_measured_conversion(&manifest_snapshot, request)
                        .map(|updated| (asset_id, updated))
                }),
            ));
        }

        for (asset_id, handle) in handles {
            match handle.join() {
                Ok(Ok((asset_id, updated))) => {
                    let record = updated.get(&asset_id)?.clone();
                    let heic_size_bytes = record
                        .proofs
                        .get("conversion")
                        .and_then(|proof| proof.get("size_bytes"))
                        .and_then(serde_json::Value::as_u64);
                    manifest.upsert(record);
                    summary.conversions_completed = summary.conversions_completed.saturating_add(1);
                    log_monitor_event(
                        "conversion_finished",
                        summary.started_unix_seconds,
                        json!({
                            "asset_id": asset_id,
                            "converted": true,
                            "heic_size_bytes": heic_size_bytes,
                        }),
                    );
                }
                Ok(Err(error)) => {
                    let kind = error.failure_kind();
                    let message = error.to_string();
                    record_conversion_execution_failure(manifest, &asset_id, &message, kind)?;
                    summary.failures = summary.failures.saturating_add(1);
                    summary.last_error =
                        Some(format!("conversion failed for {asset_id}: {message}"));
                    log_monitor_event(
                        "conversion_finished",
                        summary.started_unix_seconds,
                        json!({
                            "asset_id": asset_id,
                            "converted": false,
                            "error": message,
                        }),
                    );
                }
                Err(_) => {
                    let message = "batch conversion worker panicked";
                    record_stage_failure(manifest, &asset_id, "conversion", message)?;
                    summary.failures = summary.failures.saturating_add(1);
                    summary.last_error =
                        Some(format!("conversion failed for {asset_id}: {message}"));
                    log_monitor_event(
                        "conversion_finished",
                        summary.started_unix_seconds,
                        json!({
                            "asset_id": asset_id,
                            "converted": false,
                            "error": message,
                        }),
                    );
                }
            }
        }

        checkpoint_manifest_state(state_store, manifest)?;
    }

    Ok(())
}

struct ParallelAssetJobOutcome<T> {
    asset_id: String,
    result: Result<T, MonitorError>,
}

fn run_parallel_asset_job_chunk<T, F>(
    asset_ids: &[String],
    worker: F,
) -> Vec<ParallelAssetJobOutcome<T>>
where
    T: Send + 'static,
    F: Fn(String) -> Result<T, MonitorError> + Clone + Send + 'static,
{
    let mut handles = Vec::with_capacity(asset_ids.len());
    for asset_id in asset_ids {
        let asset_id = asset_id.clone();
        let worker = worker.clone();
        handles.push((
            asset_id.clone(),
            thread::spawn(move || {
                let result = worker(asset_id.clone());
                ParallelAssetJobOutcome { asset_id, result }
            }),
        ));
    }

    handles
        .into_iter()
        .map(|(asset_id, handle)| match handle.join() {
            Ok(outcome) => outcome,
            Err(_) => ParallelAssetJobOutcome {
                asset_id,
                result: Err(MonitorError::CommandFailed {
                    program: "icloudpd-optimizer",
                    message: "parallel lifecycle worker panicked".to_string(),
                }),
            },
        })
        .collect()
}

fn run_lifecycle_stages(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    active_lifecycle_asset_ids: &[String],
) -> Result<(), MonitorError> {
    for stage in lifecycle_stage_sequence(config.auto_delete) {
        run_lifecycle_stage(
            config,
            state_store,
            manifest,
            summary,
            active_lifecycle_asset_ids,
            stage,
        )?;
    }
    Ok(())
}

fn run_lifecycle_stage(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    active_lifecycle_asset_ids: &[String],
    stage: LifecycleStage,
) -> Result<(), MonitorError> {
    let stage_started = Instant::now();
    log_monitor_event(
        "lifecycle_stage_started",
        summary.started_unix_seconds,
        json!({
            "stage": stage.name(),
            "active_lifecycle": active_lifecycle_asset_ids.len(),
        }),
    );
    match stage {
        LifecycleStage::DeleteOriginalAssets => {
            delete_original_assets(
                config,
                state_store,
                manifest,
                summary,
                active_lifecycle_asset_ids,
            )?;
        }
        LifecycleStage::RecordLocalMirrors => {
            record_local_mirrors(
                config,
                state_store,
                manifest,
                summary,
                active_lifecycle_asset_ids,
            )?;
        }
        LifecycleStage::UploadVerifiedHeics => {
            upload_verified_heics(
                config,
                state_store,
                manifest,
                summary,
                active_lifecycle_asset_ids,
            )?;
        }
        LifecycleStage::VerifyConvertedHeics => {
            verify_converted_heics(
                config,
                state_store,
                manifest,
                summary,
                active_lifecycle_asset_ids,
            )?;
        }
        LifecycleStage::ResolveOriginalAssets => {
            resolve_original_assets(
                config,
                state_store,
                manifest,
                summary,
                active_lifecycle_asset_ids,
            )?;
        }
    }
    log_monitor_event(
        "lifecycle_stage_finished",
        summary.started_unix_seconds,
        lifecycle_stage_finished_fields(stage, summary, stage_started.elapsed().as_secs()),
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleStage {
    DeleteOriginalAssets,
    RecordLocalMirrors,
    UploadVerifiedHeics,
    VerifyConvertedHeics,
    ResolveOriginalAssets,
}

impl LifecycleStage {
    fn name(self) -> &'static str {
        match self {
            Self::DeleteOriginalAssets => "delete_original_assets",
            Self::RecordLocalMirrors => "record_local_mirrors",
            Self::UploadVerifiedHeics => "upload_verified_heics",
            Self::VerifyConvertedHeics => "verify_converted_heics",
            Self::ResolveOriginalAssets => "resolve_original_assets",
        }
    }
}

fn lifecycle_stage_sequence(auto_delete: bool) -> Vec<LifecycleStage> {
    let mut stages = Vec::new();
    if auto_delete {
        stages.push(LifecycleStage::DeleteOriginalAssets);
    }
    stages.extend([
        LifecycleStage::RecordLocalMirrors,
        LifecycleStage::UploadVerifiedHeics,
        LifecycleStage::VerifyConvertedHeics,
        LifecycleStage::ResolveOriginalAssets,
    ]);
    stages
}

fn run_rolling_lifecycle_passes(
    config: &MonitorConfig,
    state_store: &Arc<AssetStateStore>,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    initial_active_lifecycle_asset_ids: &[String],
) -> Result<(), MonitorError> {
    if initial_active_lifecycle_asset_ids.is_empty() {
        return Ok(());
    }

    let max_passes = config
        .max_lifecycle_per_scan
        .saturating_add(config.max_conversions_per_scan)
        .max(1);
    let mut active_ids = initial_active_lifecycle_asset_ids.to_vec();
    let mut deferred_worker_asset_ids = BTreeSet::new();
    for pass_index in 0..max_passes {
        if active_ids.is_empty() {
            break;
        }
        let before = summary.clone();
        log_monitor_event(
            "rolling_lifecycle_pass_started",
            summary.started_unix_seconds,
            json!({
                "pass": pass_index + 1,
                "active_lifecycle": active_ids.len(),
                "deferred_worker_assets": deferred_worker_asset_ids.len(),
                "remaining_conversion_capacity": remaining_conversion_capacity(config, summary),
            }),
        );
        run_rolling_lifecycle_pass(
            config,
            state_store,
            manifest,
            summary,
            &active_ids,
            &mut deferred_worker_asset_ids,
        )?;
        let refreshed_active_ids = active_lifecycle_asset_ids_for_config(config, manifest);
        let active_set_changed = refreshed_active_ids != active_ids;
        log_monitor_event(
            "rolling_lifecycle_pass_finished",
            summary.started_unix_seconds,
            json!({
                "pass": pass_index + 1,
                "made_forward_progress": rolling_lifecycle_made_forward_progress(&before, summary),
                "active_set_changed": active_set_changed,
                "next_active_lifecycle": refreshed_active_ids.len(),
                "deferred_worker_assets": deferred_worker_asset_ids.len(),
                "remaining_conversion_capacity": remaining_conversion_capacity(config, summary),
            }),
        );
        if !rolling_lifecycle_should_continue(
            config,
            &before,
            summary,
            &active_ids,
            &refreshed_active_ids,
        ) {
            break;
        }
        if active_set_changed {
            log_monitor_event(
                "rolling_lifecycle_active_set_refilled",
                summary.started_unix_seconds,
                json!({
                    "pass": pass_index + 1,
                    "previous_active_lifecycle": active_ids.len(),
                    "next_active_lifecycle": refreshed_active_ids.len(),
                }),
            );
        }
        active_ids = refreshed_active_ids;
    }
    Ok(())
}

fn run_rolling_lifecycle_pass(
    config: &MonitorConfig,
    state_store: &Arc<AssetStateStore>,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    active_lifecycle_asset_ids: &[String],
    deferred_worker_asset_ids: &mut BTreeSet<String>,
) -> Result<(), MonitorError> {
    if active_lifecycle_asset_ids.is_empty() {
        return Ok(());
    }

    run_rolling_lifecycle_delete_batch(
        config,
        state_store,
        manifest,
        summary,
        active_lifecycle_asset_ids,
    )?;

    let mut worker_asset_ids = rolling_lifecycle_worker_asset_ids(
        manifest,
        config,
        active_lifecycle_asset_ids,
        config.max_lifecycle_per_scan,
        remaining_conversion_capacity(config, summary),
        deferred_worker_asset_ids,
    );
    if rolling_lifecycle_should_resolve_before_workers(
        manifest,
        config,
        active_lifecycle_asset_ids,
        worker_asset_ids.len(),
    ) {
        log_monitor_event(
            "rolling_lifecycle_preworker_resolver_started",
            summary.started_unix_seconds,
            json!({
                "queued_worker_assets_before": worker_asset_ids.len(),
                "worker_slots": config.jobs.max(1),
                "active_lifecycle": active_lifecycle_asset_ids.len(),
                "remaining_conversion_capacity": remaining_conversion_capacity(config, summary),
            }),
        );
        resolve_rolling_lifecycle_original_assets(
            config,
            state_store,
            manifest,
            summary,
            active_lifecycle_asset_ids,
            "before_workers",
        )?;
        let refreshed_worker_asset_ids = rolling_lifecycle_worker_asset_ids(
            manifest,
            config,
            active_lifecycle_asset_ids,
            config.max_lifecycle_per_scan,
            remaining_conversion_capacity(config, summary),
            deferred_worker_asset_ids,
        );
        log_monitor_event(
            "rolling_lifecycle_preworker_resolver_finished",
            summary.started_unix_seconds,
            json!({
                "queued_worker_assets_before": worker_asset_ids.len(),
                "queued_worker_assets_after": refreshed_worker_asset_ids.len(),
                "worker_slots": config.jobs.max(1),
                "active_lifecycle": active_lifecycle_asset_ids.len(),
                "remaining_conversion_capacity": remaining_conversion_capacity(config, summary),
            }),
        );
        worker_asset_ids = refreshed_worker_asset_ids;
    }
    if worker_asset_ids.is_empty() {
        log_monitor_event(
            "rolling_lifecycle_worker_pool_skipped",
            summary.started_unix_seconds,
            json!({
                "queued_assets": 0,
                "active_lifecycle": active_lifecycle_asset_ids.len(),
                "deferred_worker_assets": deferred_worker_asset_ids.len(),
                "reason": "no_progressable_assets",
                "remaining_conversion_capacity": remaining_conversion_capacity(config, summary),
            }),
        );
    } else {
        run_rolling_lifecycle_worker_pool(
            config,
            state_store,
            manifest,
            summary,
            active_lifecycle_asset_ids.len(),
            worker_asset_ids,
            deferred_worker_asset_ids,
        )?;
    }

    run_rolling_lifecycle_delete_batch(
        config,
        state_store,
        manifest,
        summary,
        active_lifecycle_asset_ids,
    )?;

    resolve_rolling_lifecycle_original_assets(
        config,
        state_store,
        manifest,
        summary,
        active_lifecycle_asset_ids,
        "after_workers",
    )?;
    Ok(())
}

fn resolve_rolling_lifecycle_original_assets(
    config: &MonitorConfig,
    state_store: &Arc<AssetStateStore>,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    active_lifecycle_asset_ids: &[String],
    position: &'static str,
) -> Result<(), MonitorError> {
    let resolver_asset_ids =
        rolling_lifecycle_resolver_asset_ids(manifest, config, active_lifecycle_asset_ids);
    if resolver_asset_ids.len() > active_lifecycle_asset_ids.len() {
        log_monitor_event(
            "rolling_lifecycle_resolver_window_expanded",
            summary.started_unix_seconds,
            json!({
                "active_lifecycle": active_lifecycle_asset_ids.len(),
                "resolver_lifecycle": resolver_asset_ids.len(),
                "max_batches": rolling_lifecycle_resolve_batch_limit(
                    config,
                    resolver_asset_ids.len(),
                ),
                "position": position,
            }),
        );
    }

    resolve_original_asset_batches(
        config,
        state_store,
        manifest,
        summary,
        &resolver_asset_ids,
        Some(rolling_lifecycle_resolve_batch_limit(
            config,
            resolver_asset_ids.len(),
        )),
    )?;
    Ok(())
}

fn run_rolling_lifecycle_delete_batch(
    config: &MonitorConfig,
    state_store: &Arc<AssetStateStore>,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    active_lifecycle_asset_ids: &[String],
) -> Result<(), MonitorError> {
    if !config.auto_delete {
        return Ok(());
    }
    delete_original_assets(
        config,
        state_store,
        manifest,
        summary,
        active_lifecycle_asset_ids,
    )
}

struct RollingLifecycleWorkerPoolInput<'a> {
    active_lifecycle_count: usize,
    worker_asset_ids: Vec<String>,
    deferred_worker_asset_ids: &'a mut BTreeSet<String>,
}

fn run_rolling_lifecycle_worker_pool(
    config: &MonitorConfig,
    state_store: &Arc<AssetStateStore>,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    active_lifecycle_count: usize,
    worker_asset_ids: Vec<String>,
    deferred_worker_asset_ids: &mut BTreeSet<String>,
) -> Result<(), MonitorError> {
    run_rolling_lifecycle_worker_pool_with_transport_factory(
        config,
        state_store,
        manifest,
        summary,
        RollingLifecycleWorkerPoolInput {
            active_lifecycle_count,
            worker_asset_ids,
            deferred_worker_asset_ids,
        },
        || ReqwestCloudKitReadTransport::new().map_err(MonitorError::Upload),
    )
}

fn run_rolling_lifecycle_worker_pool_with_transport_factory<T, F>(
    config: &MonitorConfig,
    state_store: &Arc<AssetStateStore>,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    input: RollingLifecycleWorkerPoolInput<'_>,
    adjusted_source_transport_factory: F,
) -> Result<(), MonitorError>
where
    T: CloudKitAdjustedSourceTransport + Send + 'static,
    F: Fn() -> Result<T, MonitorError> + Clone + Send + 'static,
{
    let RollingLifecycleWorkerPoolInput {
        active_lifecycle_count,
        worker_asset_ids,
        deferred_worker_asset_ids,
    } = input;
    let worker_asset_ids = dedupe_worker_asset_ids(worker_asset_ids);
    let worker_count = rolling_lifecycle_worker_count(config, worker_asset_ids.len());
    let mut resolver_capacity = remaining_conversion_capacity(config, summary);
    let mut resolver_asset_ids = Vec::new();
    for asset_id in &worker_asset_ids {
        let Some(record) = manifest.records().get(asset_id) else {
            continue;
        };
        if rolling_lifecycle_next_worker_step(record, config, true)
            == Some(RollingAssetStep::ResolveAdjustedSource)
            && resolver_capacity > 0
        {
            resolver_capacity -= 1;
            resolver_asset_ids.push(record.asset_id.clone());
        }
    }
    let base_read_session = if !resolver_asset_ids.is_empty() {
        let read_session_path = required_path(&config.delete_session_path, "delete_session_path")?;
        Some(Arc::new(load_cloudkit_delete_session(read_session_path)?))
    } else {
        None
    };
    let available_parallelism = thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(1);
    let cpu_stage_jobs = rolling_lifecycle_cpu_stage_jobs(config, available_parallelism);
    let convert_stage_jobs = rolling_lifecycle_convert_stage_jobs(config, cpu_stage_jobs);
    let mirror_stage_jobs = rolling_lifecycle_mirror_stage_jobs(config);
    let stage_permits = Arc::new(RollingStagePermits::new(
        cpu_stage_jobs,
        convert_stage_jobs,
        mirror_stage_jobs,
    ));
    let conversion_reservations = Arc::new(RollingConversionReservations::new(resolver_asset_ids));
    let queue = Arc::new(Mutex::new(
        worker_asset_ids.iter().cloned().collect::<VecDeque<_>>(),
    ));
    let shared_manifest = Arc::new(Mutex::new(manifest.clone()));
    let shared_summary = Arc::new(Mutex::new(summary.clone()));
    let shared_deferred_worker_asset_ids = Arc::new(Mutex::new(BTreeSet::new()));
    log_monitor_event(
        "rolling_lifecycle_worker_pool_started",
        summary.started_unix_seconds,
        json!({
            "worker_slots": worker_count,
            "cpu_stage_slots": cpu_stage_jobs,
            "convert_stage_slots": convert_stage_jobs,
            "mirror_stage_slots": mirror_stage_jobs,
            "queued_assets": worker_asset_ids.len(),
            "active_lifecycle": active_lifecycle_count,
            "deferred_worker_assets": deferred_worker_asset_ids.len(),
            "remaining_conversion_capacity": remaining_conversion_capacity(config, summary),
        }),
    );

    let mut handles = Vec::with_capacity(worker_count);
    for worker_index in 0..worker_count {
        let config = config.clone();
        let queue = Arc::clone(&queue);
        let shared_manifest = Arc::clone(&shared_manifest);
        let shared_summary = Arc::clone(&shared_summary);
        let shared_deferred_worker_asset_ids = Arc::clone(&shared_deferred_worker_asset_ids);
        let stage_permits = Arc::clone(&stage_permits);
        let conversion_reservations = Arc::clone(&conversion_reservations);
        let state_store = Arc::clone(state_store);
        let base_read_session = base_read_session.as_ref().map(Arc::clone);
        let adjusted_source_transport_factory = adjusted_source_transport_factory.clone();
        let worker_id = worker_index + 1;
        handles.push(thread::spawn(move || {
            run_rolling_lifecycle_worker(
                worker_id,
                RollingLifecycleWorkerContext {
                    config,
                    queue,
                    manifest: shared_manifest,
                    summary: shared_summary,
                    deferred_worker_asset_ids: shared_deferred_worker_asset_ids,
                    stage_permits,
                    conversion_reservations,
                    state_store,
                    base_read_session,
                    adjusted_source_transport_factory,
                    _transport: std::marker::PhantomData,
                },
            )
        }));
    }

    let mut first_error = None;
    for handle in handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            Err(_) => {
                if first_error.is_none() {
                    first_error = Some(MonitorError::CommandFailed {
                        program: "icloudpd-optimizer",
                        message: "rolling lifecycle worker panicked".to_string(),
                    });
                }
            }
        }
    }

    if let Some(error) = first_error {
        return Err(error);
    }

    *manifest = lock_shared(&shared_manifest, "rolling lifecycle manifest")?.clone();
    checkpoint_manifest_state(state_store, manifest)?;
    *summary = lock_shared(&shared_summary, "rolling lifecycle summary")?.clone();
    deferred_worker_asset_ids.extend(
        lock_shared(
            &shared_deferred_worker_asset_ids,
            "rolling lifecycle deferred assets",
        )?
        .iter()
        .cloned(),
    );
    log_monitor_event(
        "rolling_lifecycle_worker_pool_finished",
        summary.started_unix_seconds,
        json!({
            "worker_slots": worker_count,
            "adjusted_sources_resolved": summary.adjusted_sources_resolved,
            "adjusted_source_resolution_failures": summary.adjusted_source_resolution_failures,
            "conversions_attempted": summary.conversions_attempted,
            "conversions_completed": summary.conversions_completed,
            "heics_verified": summary.heics_verified,
            "uploads_completed": summary.uploads_completed,
            "mirrors_recorded": summary.mirrors_recorded,
            "originals_deleted": summary.originals_deleted,
            "failures": summary.failures,
            "deferred_worker_assets": deferred_worker_asset_ids.len(),
        }),
    );

    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RollingAssetStepOutcome {
    attempted: bool,
    changed: bool,
    completed: bool,
    failed: bool,
}

impl RollingAssetStepOutcome {
    fn skipped() -> Self {
        Self {
            attempted: false,
            changed: false,
            completed: false,
            failed: false,
        }
    }

    fn attempted(changed: bool) -> Self {
        Self {
            attempted: true,
            changed,
            completed: false,
            failed: false,
        }
    }

    fn completed() -> Self {
        Self {
            attempted: true,
            changed: true,
            completed: true,
            failed: false,
        }
    }

    fn failed(changed: bool) -> Self {
        Self {
            attempted: true,
            changed,
            completed: false,
            failed: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RollingAssetLifecycleDelta {
    adjusted_sources_resolved: u64,
    adjusted_source_resolution_failures: u64,
    conversions_completed: u64,
    heics_verified: u64,
    uploads_completed: u64,
    mirrors_recorded: u64,
    failures: u64,
}

impl RollingAssetLifecycleDelta {
    fn record(&mut self, step: RollingAssetStep, outcome: &RollingAssetStepOutcome) {
        if outcome.completed {
            match step {
                RollingAssetStep::ResolveAdjustedSource => self.adjusted_sources_resolved = 1,
                RollingAssetStep::ConvertHeic => self.conversions_completed = 1,
                RollingAssetStep::VerifyConvertedHeics => self.heics_verified = 1,
                RollingAssetStep::UploadVerifiedHeics => self.uploads_completed = 1,
                RollingAssetStep::RecordLocalMirrors => self.mirrors_recorded = 1,
            }
        }
        if outcome.failed {
            self.failures = 1;
            if step == RollingAssetStep::ResolveAdjustedSource {
                self.adjusted_source_resolution_failures = 1;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RollingAssetStep {
    ResolveAdjustedSource,
    ConvertHeic,
    VerifyConvertedHeics,
    UploadVerifiedHeics,
    RecordLocalMirrors,
}

impl RollingAssetStep {
    fn name(self) -> &'static str {
        match self {
            Self::ResolveAdjustedSource => "adjusted_source_resolve",
            Self::ConvertHeic => "convert_heic",
            Self::VerifyConvertedHeics => "verify_converted_heics",
            Self::UploadVerifiedHeics => "upload_verified_heics",
            Self::RecordLocalMirrors => "record_local_mirrors",
        }
    }
}

fn rolling_lifecycle_worker_stage_sequence(
    record: &AssetRecord,
    config: &MonitorConfig,
) -> Vec<RollingAssetStep> {
    let Some(first_step) = rolling_lifecycle_next_worker_step(record, config, true) else {
        return Vec::new();
    };
    rolling_lifecycle_worker_stage_sequence_from(first_step, config.auto_delete)
}

fn rolling_lifecycle_worker_stage_sequence_from(
    first_step: RollingAssetStep,
    _auto_delete: bool,
) -> Vec<RollingAssetStep> {
    let full_sequence = [
        RollingAssetStep::ResolveAdjustedSource,
        RollingAssetStep::ConvertHeic,
        RollingAssetStep::VerifyConvertedHeics,
        RollingAssetStep::UploadVerifiedHeics,
        RollingAssetStep::RecordLocalMirrors,
    ];
    full_sequence
        .iter()
        .position(|step| *step == first_step)
        .map(|index| full_sequence[index..].to_vec())
        .unwrap_or_else(|| vec![first_step])
}

fn rolling_lifecycle_worker_count(config: &MonitorConfig, queued_assets: usize) -> usize {
    rolling_lifecycle_configured_worker_count(config).min(queued_assets)
}

pub(crate) fn rolling_lifecycle_configured_worker_count(config: &MonitorConfig) -> usize {
    config.rolling_worker_count.unwrap_or(config.jobs).max(1)
}

fn dedupe_worker_asset_ids(asset_ids: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    asset_ids
        .into_iter()
        .filter(|asset_id| seen.insert(asset_id.clone()))
        .collect()
}

pub(crate) fn rolling_lifecycle_cpu_stage_jobs(
    config: &MonitorConfig,
    available_parallelism: usize,
) -> usize {
    config
        .rolling_cpu_stage_count
        .unwrap_or_else(|| config.jobs.max(1).min(available_parallelism.max(1)))
        .max(1)
}

pub(crate) fn rolling_lifecycle_convert_stage_jobs(
    config: &MonitorConfig,
    cpu_stage_jobs: usize,
) -> usize {
    let default_slots = cpu_stage_jobs.max(1).div_ceil(2).max(1);
    config
        .rolling_convert_stage_count
        .unwrap_or(default_slots)
        .max(1)
        .min(cpu_stage_jobs.max(1))
}

fn rolling_lifecycle_mirror_stage_jobs(config: &MonitorConfig) -> usize {
    config.jobs.max(1)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RollingStagePermitPolicy {
    None,
    Cpu,
    CpuAndConvert,
    Mirror,
}

fn rolling_asset_step_permit_policy(step: RollingAssetStep) -> RollingStagePermitPolicy {
    match step {
        RollingAssetStep::ResolveAdjustedSource => RollingStagePermitPolicy::None,
        RollingAssetStep::ConvertHeic => RollingStagePermitPolicy::CpuAndConvert,
        RollingAssetStep::VerifyConvertedHeics => RollingStagePermitPolicy::Cpu,
        RollingAssetStep::UploadVerifiedHeics => RollingStagePermitPolicy::None,
        RollingAssetStep::RecordLocalMirrors => RollingStagePermitPolicy::Mirror,
    }
}

fn rolling_asset_step_uses_stage_permit(step: RollingAssetStep) -> bool {
    rolling_asset_step_permit_policy(step) != RollingStagePermitPolicy::None
}

#[derive(Debug)]
struct RollingStagePermits {
    cpu_stage_slots: usize,
    convert_stage_slots: usize,
    mirror_stage_slots: usize,
    state: Mutex<RollingStagePermitState>,
    available: Condvar,
}

#[derive(Debug)]
struct RollingStagePermitState {
    available_cpu_stage_slots: usize,
    available_convert_stage_slots: usize,
    available_mirror_stage_slots: usize,
    waiting_cpu_only_slots: usize,
}

impl RollingStagePermits {
    fn new(cpu_stage_slots: usize, convert_stage_slots: usize, mirror_stage_slots: usize) -> Self {
        let cpu_stage_slots = cpu_stage_slots.max(1);
        let convert_stage_slots = convert_stage_slots.max(1).min(cpu_stage_slots);
        let mirror_stage_slots = mirror_stage_slots.max(1);
        Self {
            cpu_stage_slots,
            convert_stage_slots,
            mirror_stage_slots,
            state: Mutex::new(RollingStagePermitState {
                available_cpu_stage_slots: cpu_stage_slots,
                available_convert_stage_slots: convert_stage_slots,
                available_mirror_stage_slots: mirror_stage_slots,
                waiting_cpu_only_slots: 0,
            }),
            available: Condvar::new(),
        }
    }

    fn cpu_stage_slots(&self) -> usize {
        self.cpu_stage_slots
    }

    fn convert_stage_slots(&self) -> usize {
        self.convert_stage_slots
    }

    fn mirror_stage_slots(&self) -> usize {
        self.mirror_stage_slots
    }

    fn acquire(
        self: &Arc<Self>,
        step: RollingAssetStep,
    ) -> Result<Option<RollingStagePermitGuard>, MonitorError> {
        match rolling_asset_step_permit_policy(step) {
            RollingStagePermitPolicy::None => Ok(None),
            RollingStagePermitPolicy::Cpu => {
                self.acquire_cpu_slots(false)?;
                Ok(Some(RollingStagePermitGuard {
                    permits: Arc::clone(self),
                    policy: RollingStagePermitPolicy::Cpu,
                }))
            }
            RollingStagePermitPolicy::CpuAndConvert => {
                self.acquire_cpu_slots(true)?;
                Ok(Some(RollingStagePermitGuard {
                    permits: Arc::clone(self),
                    policy: RollingStagePermitPolicy::CpuAndConvert,
                }))
            }
            RollingStagePermitPolicy::Mirror => {
                self.acquire_mirror_slot()?;
                Ok(Some(RollingStagePermitGuard {
                    permits: Arc::clone(self),
                    policy: RollingStagePermitPolicy::Mirror,
                }))
            }
        }
    }

    fn acquire_cpu_slots(&self, convert_slot: bool) -> Result<(), MonitorError> {
        let mut state = self.state.lock().map_err(|_| MonitorError::CommandFailed {
            program: "icloudpd-optimizer",
            message: "rolling lifecycle permit lock poisoned".to_string(),
        })?;
        if !convert_slot {
            state.waiting_cpu_only_slots = state.waiting_cpu_only_slots.saturating_add(1);
        }
        while state.should_wait_for(convert_slot) {
            state = match self.available.wait(state) {
                Ok(state) => state,
                Err(_) => {
                    return Err(MonitorError::CommandFailed {
                        program: "icloudpd-optimizer",
                        message: "rolling lifecycle permit wait failed".to_string(),
                    });
                }
            };
        }
        if !convert_slot {
            state.waiting_cpu_only_slots = state.waiting_cpu_only_slots.saturating_sub(1);
        }
        state.available_cpu_stage_slots -= 1;
        if convert_slot {
            state.available_convert_stage_slots -= 1;
        }
        Ok(())
    }

    fn acquire_mirror_slot(&self) -> Result<(), MonitorError> {
        let mut state = self.state.lock().map_err(|_| MonitorError::CommandFailed {
            program: "icloudpd-optimizer",
            message: "rolling lifecycle permit lock poisoned".to_string(),
        })?;
        while state.available_mirror_stage_slots == 0 {
            state = self
                .available
                .wait(state)
                .map_err(|_| MonitorError::CommandFailed {
                    program: "icloudpd-optimizer",
                    message: "rolling lifecycle permit wait failed".to_string(),
                })?;
        }
        state.available_mirror_stage_slots -= 1;
        Ok(())
    }

    fn release_cpu_slots(&self, convert_slot: bool) {
        if let Ok(mut state) = self.state.lock() {
            state.available_cpu_stage_slots =
                (state.available_cpu_stage_slots + 1).min(self.cpu_stage_slots);
            if convert_slot {
                state.available_convert_stage_slots =
                    (state.available_convert_stage_slots + 1).min(self.convert_stage_slots);
            }
            self.available.notify_all();
        }
    }

    fn release_mirror_slot(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.available_mirror_stage_slots =
                (state.available_mirror_stage_slots + 1).min(self.mirror_stage_slots);
            self.available.notify_all();
        }
    }
}

impl RollingStagePermitState {
    fn should_wait_for(&self, convert_slot: bool) -> bool {
        self.available_cpu_stage_slots == 0
            || (convert_slot
                && (self.available_convert_stage_slots == 0 || self.waiting_cpu_only_slots > 0))
    }
}

struct RollingStagePermitGuard {
    permits: Arc<RollingStagePermits>,
    policy: RollingStagePermitPolicy,
}

impl Drop for RollingStagePermitGuard {
    fn drop(&mut self) {
        match self.policy {
            RollingStagePermitPolicy::Cpu => self.permits.release_cpu_slots(false),
            RollingStagePermitPolicy::CpuAndConvert => self.permits.release_cpu_slots(true),
            RollingStagePermitPolicy::Mirror => self.permits.release_mirror_slot(),
            RollingStagePermitPolicy::None => {}
        }
    }
}

#[derive(Debug)]
struct RollingConversionReservations {
    resolver_asset_ids: Mutex<BTreeSet<String>>,
}

impl RollingConversionReservations {
    fn new(asset_ids: impl IntoIterator<Item = String>) -> Self {
        Self {
            resolver_asset_ids: Mutex::new(asset_ids.into_iter().collect()),
        }
    }

    fn is_reserved(&self, asset_id: &str) -> Result<bool, MonitorError> {
        self.resolver_asset_ids
            .lock()
            .map(|asset_ids| asset_ids.contains(asset_id))
            .map_err(|_| MonitorError::CommandFailed {
                program: "icloudpd-optimizer",
                message: "rolling conversion reservation lock poisoned".to_string(),
            })
    }

    fn release(&self, asset_id: &str) -> Result<(), MonitorError> {
        self.resolver_asset_ids
            .lock()
            .map(|mut asset_ids| {
                asset_ids.remove(asset_id);
            })
            .map_err(|_| MonitorError::CommandFailed {
                program: "icloudpd-optimizer",
                message: "rolling conversion reservation lock poisoned".to_string(),
            })
    }

    fn release_on_drop(&self, asset_id: &str) {
        if let Ok(mut asset_ids) = self.resolver_asset_ids.lock() {
            asset_ids.remove(asset_id);
        }
    }

    fn claim_conversion_attempt(
        &self,
        asset_id: &str,
        config: &MonitorConfig,
        summary: &Arc<Mutex<MonitorScanSummary>>,
    ) -> Result<bool, MonitorError> {
        let mut reserved =
            self.resolver_asset_ids
                .lock()
                .map_err(|_| MonitorError::CommandFailed {
                    program: "icloudpd-optimizer",
                    message: "rolling conversion reservation lock poisoned".to_string(),
                })?;
        let was_reserved = reserved.remove(asset_id);
        let mut summary = lock_shared(summary, "rolling lifecycle summary")?;
        let attempted = summary.conversions_attempted as usize;
        if was_reserved {
            if attempted >= config.max_conversions_per_scan {
                return Err(MonitorError::InvalidConfig {
                    message: "rolling conversion reservation exceeded conversion capacity"
                        .to_string(),
                });
            }
        } else if attempted.saturating_add(reserved.len()) >= config.max_conversions_per_scan {
            return Ok(false);
        }
        summary.conversions_attempted = summary.conversions_attempted.saturating_add(1);
        Ok(true)
    }
}

struct RollingAdjustedSourceReservationGuard<'a> {
    reservations: &'a RollingConversionReservations,
    asset_id: &'a str,
    release_on_drop: bool,
}

impl<'a> RollingAdjustedSourceReservationGuard<'a> {
    fn new(reservations: &'a RollingConversionReservations, asset_id: &'a str) -> Self {
        Self {
            reservations,
            asset_id,
            release_on_drop: true,
        }
    }

    fn retain_for_conversion(&mut self) {
        self.release_on_drop = false;
    }
}

impl Drop for RollingAdjustedSourceReservationGuard<'_> {
    fn drop(&mut self) {
        if self.release_on_drop {
            self.reservations.release_on_drop(self.asset_id);
        }
    }
}

fn rolling_lifecycle_resolve_batch_limit(config: &MonitorConfig, active_assets: usize) -> usize {
    config
        .jobs
        .max(1)
        .saturating_mul(config.rolling_original_resolve_batch_multiplier)
        .min(active_assets)
        .max(1)
}

fn rolling_lifecycle_resolver_active_limit(config: &MonitorConfig) -> usize {
    config
        .max_lifecycle_per_scan
        .saturating_mul(config.rolling_original_resolve_active_window_multiplier)
        .max(config.max_lifecycle_per_scan)
}

fn rolling_lifecycle_resolver_asset_ids(
    manifest: &Manifest,
    config: &MonitorConfig,
    active_lifecycle_asset_ids: &[String],
) -> Vec<String> {
    let mut resolver_asset_ids = active_lifecycle_asset_ids.to_vec();
    let resolver_limit = rolling_lifecycle_resolver_active_limit(config);
    let remaining = resolver_limit.saturating_sub(resolver_asset_ids.len());
    if remaining > 0 {
        resolver_asset_ids.extend(densest_original_asset_resolution_windows(
            manifest,
            remaining,
            &resolver_asset_ids,
        ));
    }
    resolver_asset_ids
}

fn rolling_lifecycle_worker_asset_ids(
    manifest: &Manifest,
    config: &MonitorConfig,
    active_lifecycle_asset_ids: &[String],
    limit: usize,
    remaining_conversion_capacity: usize,
    deferred_worker_asset_ids: &BTreeSet<String>,
) -> Vec<String> {
    let active_set = Some(active_lifecycle_asset_ids);
    let mut candidates = active_lifecycle_asset_ids
        .iter()
        .filter(|asset_id| !deferred_worker_asset_ids.contains(asset_id.as_str()))
        .filter_map(|asset_id| manifest.records().get(asset_id))
        .filter(|record| active_lifecycle_allows(active_set, &record.asset_id))
        .filter(|record| rolling_lifecycle_record_can_run_worker_stage(record, config, true))
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        lifecycle_continuation_priority(left)
            .cmp(&lifecycle_continuation_priority(right))
            .then_with(|| raw_size_bytes_from_record(right).cmp(&raw_size_bytes_from_record(left)))
            .then_with(|| left.asset_id.cmp(&right.asset_id))
    });
    let mut conversion_capacity = remaining_conversion_capacity;
    let mut selected = Vec::with_capacity(limit);
    for record in candidates {
        let Some(step) = rolling_lifecycle_next_worker_step(record, config, true) else {
            continue;
        };
        if matches!(
            step,
            RollingAssetStep::ResolveAdjustedSource | RollingAssetStep::ConvertHeic
        ) {
            if conversion_capacity == 0 {
                continue;
            }
            conversion_capacity -= 1;
        }
        selected.push(record.asset_id.clone());
        if selected.len() == limit {
            break;
        }
    }
    selected
}

fn rolling_lifecycle_record_can_run_worker_stage(
    record: &AssetRecord,
    config: &MonitorConfig,
    conversion_capacity_available: bool,
) -> bool {
    rolling_lifecycle_next_worker_step(record, config, conversion_capacity_available).is_some()
}

fn rolling_lifecycle_should_resolve_before_workers(
    manifest: &Manifest,
    _config: &MonitorConfig,
    active_lifecycle_asset_ids: &[String],
    queued_worker_assets: usize,
) -> bool {
    queued_worker_assets == 0
        && manifest.records().values().any(|record| {
            active_lifecycle_allows(Some(active_lifecycle_asset_ids), &record.asset_id)
                && matches!(
                    record.state,
                    State::NasVerified | State::Converted | State::ConversionVerified
                )
                && !record.proofs.contains_key("original_asset")
                && original_asset_resolution_candidate(record).is_some()
        })
}

fn rolling_lifecycle_next_worker_step(
    record: &AssetRecord,
    config: &MonitorConfig,
    conversion_capacity_available: bool,
) -> Option<RollingAssetStep> {
    match record.state {
        State::Failed
            if config.full_lifecycle
                && config.rolling_lifecycle
                && conversion_capacity_available
                && adjusted_source_required_proof(record).is_ok() =>
        {
            Some(RollingAssetStep::ResolveAdjustedSource)
        }
        State::NasVerified
            if conversion_capacity_available
                && (!config.full_lifecycle || record.proofs.contains_key("original_asset")) =>
        {
            Some(RollingAssetStep::ConvertHeic)
        }
        State::Converted if !record.proofs.contains_key("heic") => {
            Some(RollingAssetStep::VerifyConvertedHeics)
        }
        State::Converted
            if record.proofs.contains_key("heic")
                && record.proofs.contains_key("original_asset") =>
        {
            Some(RollingAssetStep::UploadVerifiedHeics)
        }
        State::ConversionVerified if record.proofs.contains_key("original_asset") => {
            Some(RollingAssetStep::UploadVerifiedHeics)
        }
        State::UploadVerified if !record.proofs.contains_key("icloudpd_local_mirror") => {
            Some(RollingAssetStep::RecordLocalMirrors)
        }
        _ => None,
    }
}

struct RollingLifecycleWorkerContext<T, F> {
    config: MonitorConfig,
    queue: Arc<Mutex<VecDeque<String>>>,
    manifest: Arc<Mutex<Manifest>>,
    summary: Arc<Mutex<MonitorScanSummary>>,
    deferred_worker_asset_ids: Arc<Mutex<BTreeSet<String>>>,
    stage_permits: Arc<RollingStagePermits>,
    conversion_reservations: Arc<RollingConversionReservations>,
    state_store: Arc<AssetStateStore>,
    base_read_session: Option<Arc<CloudKitDeleteSession>>,
    adjusted_source_transport_factory: F,
    _transport: std::marker::PhantomData<T>,
}

fn run_rolling_lifecycle_worker<T, F>(
    worker_id: usize,
    context: RollingLifecycleWorkerContext<T, F>,
) -> Result<(), MonitorError>
where
    T: CloudKitAdjustedSourceTransport,
    F: Fn() -> Result<T, MonitorError>,
{
    let RollingLifecycleWorkerContext {
        config,
        queue,
        manifest,
        summary,
        deferred_worker_asset_ids,
        stage_permits,
        conversion_reservations,
        state_store,
        base_read_session,
        adjusted_source_transport_factory,
        _transport: _,
    } = context;
    let mut adjusted_source_resolver = base_read_session
        .is_some()
        .then(|| adjusted_source_transport_factory().map(CloudKitAdjustedSourceResolver::new))
        .transpose()?;
    loop {
        let asset_id = {
            let mut queue = lock_shared(&queue, "rolling lifecycle queue")?;
            queue.pop_front()
        };
        let Some(asset_id) = asset_id else {
            break;
        };

        let started = Instant::now();
        let scan_started = shared_scan_started(&summary)?;
        let state_before = shared_asset_state_name(&manifest, &asset_id)?;
        log_monitor_event(
            "rolling_lifecycle_worker_asset_started",
            scan_started,
            json!({
                "worker_id": worker_id,
                "asset_id": asset_id,
                "state_before": state_before,
            }),
        );
        let delta = {
            let mut execution = RollingAssetExecutionContext {
                config: &config,
                state_store: &state_store,
                worker_id,
                manifest: &manifest,
                summary: &summary,
                conversion_reservations: &conversion_reservations,
                base_read_session: base_read_session.as_deref(),
                adjusted_source_resolver: adjusted_source_resolver.as_mut(),
            };
            run_rolling_asset_lifecycle(&asset_id, &stage_permits, &mut execution)?
        };
        let state_after = shared_asset_state_name(&manifest, &asset_id)?;
        let no_forward_movement = delta.conversions_completed == 0
            && delta.adjusted_sources_resolved == 0
            && delta.heics_verified == 0
            && delta.uploads_completed == 0
            && delta.mirrors_recorded == 0;
        let deferred_for_scan = state_after == state_before && no_forward_movement;
        if deferred_for_scan {
            lock_shared(
                &deferred_worker_asset_ids,
                "rolling lifecycle deferred assets",
            )?
            .insert(asset_id.clone());
        }
        log_monitor_event(
            "rolling_lifecycle_worker_asset_finished",
            scan_started,
            json!({
                "worker_id": worker_id,
                "asset_id": asset_id,
                "state_after": state_after,
                "originals_resolved_delta": 0,
                "adjusted_sources_resolved_delta": delta.adjusted_sources_resolved,
                "adjusted_source_resolution_failures_delta": delta.adjusted_source_resolution_failures,
                "conversions_completed_delta": delta.conversions_completed,
                "heics_verified_delta": delta.heics_verified,
                "uploads_completed_delta": delta.uploads_completed,
                "mirrors_recorded_delta": delta.mirrors_recorded,
                "originals_deleted_delta": 0,
                "failures_delta": delta.failures,
                "deferred_for_scan": deferred_for_scan,
                "wall_time_seconds": started.elapsed().as_secs(),
            }),
        );
    }
    Ok(())
}

struct RollingAssetExecutionContext<'a, T: CloudKitAdjustedSourceTransport> {
    config: &'a MonitorConfig,
    state_store: &'a AssetStateStore,
    worker_id: usize,
    manifest: &'a Arc<Mutex<Manifest>>,
    summary: &'a Arc<Mutex<MonitorScanSummary>>,
    conversion_reservations: &'a Arc<RollingConversionReservations>,
    base_read_session: Option<&'a CloudKitDeleteSession>,
    adjusted_source_resolver: Option<&'a mut CloudKitAdjustedSourceResolver<T>>,
}

fn run_rolling_asset_lifecycle<T: CloudKitAdjustedSourceTransport>(
    asset_id: &str,
    stage_permits: &Arc<RollingStagePermits>,
    execution: &mut RollingAssetExecutionContext<'_, T>,
) -> Result<RollingAssetLifecycleDelta, MonitorError> {
    let mut delta = RollingAssetLifecycleDelta::default();
    let steps = {
        let snapshot = lock_shared(execution.manifest, "rolling lifecycle manifest")?;
        let record = snapshot.get(asset_id)?;
        rolling_lifecycle_worker_stage_sequence(record, execution.config)
    };
    for step in steps {
        let resolver_reservations = (step == RollingAssetStep::ResolveAdjustedSource)
            .then(|| Arc::clone(execution.conversion_reservations));
        let mut resolver_reservation = resolver_reservations
            .as_deref()
            .map(|reservations| RollingAdjustedSourceReservationGuard::new(reservations, asset_id));
        if rolling_asset_terminal_state(execution.manifest, asset_id)? {
            break;
        }

        let scan_started = shared_scan_started(execution.summary)?;
        let state_before = shared_asset_state_name(execution.manifest, asset_id)?;
        if rolling_asset_step_uses_stage_permit(step) {
            log_monitor_event(
                "rolling_lifecycle_worker_stage_waiting",
                scan_started,
                json!({
                    "worker_id": execution.worker_id,
                    "asset_id": asset_id,
                    "stage": step.name(),
                    "state_before": state_before,
                    "cpu_stage_slots": stage_permits.cpu_stage_slots(),
                    "convert_stage_slots": stage_permits.convert_stage_slots(),
                    "mirror_stage_slots": stage_permits.mirror_stage_slots(),
                }),
            );
        }
        let _stage_permit = stage_permits.acquire(step)?;
        let started = Instant::now();
        log_monitor_event(
            "rolling_lifecycle_worker_stage_started",
            scan_started,
            json!({
                "worker_id": execution.worker_id,
                "asset_id": asset_id,
                "stage": step.name(),
                "state_before": state_before,
            }),
        );
        let outcome = run_rolling_asset_step(asset_id, step, execution)?;
        if outcome.completed
            && let Some(reservation) = resolver_reservation.as_mut()
        {
            reservation.retain_for_conversion();
        }
        delta.record(step, &outcome);
        let state_after = shared_asset_state_name(execution.manifest, asset_id)?;
        log_monitor_event(
            "rolling_lifecycle_worker_stage_finished",
            scan_started,
            json!({
                "worker_id": execution.worker_id,
                "asset_id": asset_id,
                "stage": step.name(),
                "attempted": outcome.attempted,
                "changed": outcome.changed,
                "state_after": state_after,
                "wall_time_millis": started.elapsed().as_millis() as u64,
            }),
        );
        if rolling_asset_step_stops_lifecycle(&outcome) {
            break;
        }
    }
    Ok(delta)
}

fn rolling_asset_step_stops_lifecycle(outcome: &RollingAssetStepOutcome) -> bool {
    !outcome.changed
}

fn run_rolling_asset_step<T: CloudKitAdjustedSourceTransport>(
    asset_id: &str,
    step: RollingAssetStep,
    execution: &mut RollingAssetExecutionContext<'_, T>,
) -> Result<RollingAssetStepOutcome, MonitorError> {
    match step {
        RollingAssetStep::ResolveAdjustedSource => {
            if !execution.conversion_reservations.is_reserved(asset_id)? {
                return Ok(RollingAssetStepOutcome::skipped());
            }
            let base_read_session =
                execution
                    .base_read_session
                    .ok_or(MonitorError::InvalidConfig {
                        message: "rolling adjusted-source worker is missing its read session"
                            .to_string(),
                    })?;
            let adjusted_source_resolver =
                execution
                    .adjusted_source_resolver
                    .take()
                    .ok_or(MonitorError::InvalidConfig {
                        message: "rolling adjusted-source worker is missing its read transport"
                            .to_string(),
                    })?;
            let outcome = run_rolling_adjusted_source_resolution(
                asset_id,
                execution,
                base_read_session,
                adjusted_source_resolver,
            );
            execution.adjusted_source_resolver = Some(adjusted_source_resolver);
            outcome
        }
        RollingAssetStep::ConvertHeic => run_rolling_asset_conversion(
            execution.config,
            execution.state_store,
            asset_id,
            execution.manifest,
            execution.summary,
            execution.conversion_reservations,
        ),
        RollingAssetStep::VerifyConvertedHeics => run_rolling_asset_verify(
            execution.config,
            execution.state_store,
            asset_id,
            execution.manifest,
            execution.summary,
        ),
        RollingAssetStep::UploadVerifiedHeics => run_rolling_asset_upload(
            execution.config,
            execution.state_store,
            asset_id,
            execution.manifest,
            execution.summary,
        ),
        RollingAssetStep::RecordLocalMirrors => run_rolling_asset_local_mirror(
            execution.config,
            execution.state_store,
            asset_id,
            execution.manifest,
            execution.summary,
        ),
    }
}

fn run_rolling_adjusted_source_resolution<T: CloudKitAdjustedSourceTransport>(
    asset_id: &str,
    execution: &mut RollingAssetExecutionContext<'_, T>,
    base_read_session: &CloudKitDeleteSession,
    resolver: &mut CloudKitAdjustedSourceResolver<T>,
) -> Result<RollingAssetStepOutcome, MonitorError> {
    if !execution.config.full_lifecycle || !execution.config.rolling_lifecycle {
        return Ok(RollingAssetStepOutcome::skipped());
    }

    let (expected, marker, original, conversion_output_path, output_path) = {
        let snapshot = lock_shared(execution.manifest, "rolling lifecycle manifest")?;
        let expected = snapshot.get(asset_id)?.clone();
        let marker = match adjusted_source_required_proof(&expected) {
            Ok(marker) => marker,
            Err(_) => return Ok(RollingAssetStepOutcome::skipped()),
        };
        let original = adjusted_source_recovery_original_proof(&expected).map_err(|_| {
            MonitorError::InvalidConfig {
                message: "adjusted-source marker passed validation without an original proof"
                    .to_string(),
            }
        })?;
        let output_path =
            adjusted_source_output_path_for_marker(execution.config, asset_id, &marker)?;
        let conversion_output_path = execution
            .config
            .heic_output_dir
            .join(format!("{asset_id}.heic"));
        (
            expected,
            marker,
            original,
            conversion_output_path,
            output_path,
        )
    };

    let mut session = base_read_session.clone();
    session.database_scope = original.database_scope;
    session.zone = CloudKitLibraryDestination {
        database_scope: original.database_scope,
        zone_name: original.zone_name.clone(),
    };
    let scan_started = shared_scan_started(execution.summary)?;
    let started = Instant::now();
    log_monitor_event(
        "adjusted_source_resolve_started",
        scan_started,
        json!({
            "worker_id": execution.worker_id,
            "asset_id": asset_id,
            "attempt": marker.attempt(),
            "database_scope": original.database_scope.as_str(),
            "zone_category": "original_asset_proof",
        }),
    );

    let request = CloudKitAdjustedSourceResolveRequest {
        asset_id: asset_id.to_string(),
        original_asset: original,
        output_path,
    };
    match resolver.resolve(&session, &request) {
        Ok(proof) => {
            if take_adjusted_source_resolution_fail_before_cas() {
                return Err(MonitorError::CommandFailed {
                    program: "icloudpd-optimizer",
                    message: "injected adjusted-source post-download fault".to_string(),
                });
            }
            let updated = stage_adjusted_source_resolution_success(
                &expected,
                asset_id,
                &conversion_output_path,
                proof,
            )?;
            match persist_rolling_adjusted_source_exact_cas(
                execution.config,
                execution.state_store,
                execution.manifest,
                &expected,
                &updated,
            )? {
                Some(commit_elapsed) => {
                    {
                        let mut summary =
                            lock_shared(execution.summary, "rolling lifecycle summary")?;
                        summary.adjusted_sources_resolved =
                            summary.adjusted_sources_resolved.saturating_add(1);
                    }
                    log_monitor_event(
                        "asset_state_committed",
                        scan_started,
                        json!({
                            "asset_id": asset_id,
                            "proof_stage": "adjusted_source_resolve",
                            "state": State::NasVerified.as_str(),
                            "commit_wall_time_micros": commit_elapsed.as_micros() as u64,
                        }),
                    );
                    log_adjusted_source_resolution_finished(
                        scan_started,
                        execution.worker_id,
                        asset_id,
                        marker.attempt(),
                        session.database_scope,
                        "completed",
                        started.elapsed(),
                    );
                    Ok(RollingAssetStepOutcome::completed())
                }
                None => {
                    log_adjusted_source_resolution_finished(
                        scan_started,
                        execution.worker_id,
                        asset_id,
                        marker.attempt(),
                        session.database_scope,
                        "cas_conflict",
                        started.elapsed(),
                    );
                    Ok(RollingAssetStepOutcome::attempted(false))
                }
            }
        }
        Err(error) => {
            let updated = stage_adjusted_source_resolution_failure(&expected, asset_id, &error)?;
            match persist_rolling_adjusted_source_exact_cas(
                execution.config,
                execution.state_store,
                execution.manifest,
                &expected,
                &updated,
            )? {
                Some(commit_elapsed) => {
                    {
                        let mut summary =
                            lock_shared(execution.summary, "rolling lifecycle summary")?;
                        summary.adjusted_source_resolution_failures = summary
                            .adjusted_source_resolution_failures
                            .saturating_add(1);
                        summary.failures = summary.failures.saturating_add(1);
                        summary.last_error = Some(format!(
                            "adjusted source resolution failed for {asset_id}: {}",
                            error
                        ));
                    }
                    log_monitor_event(
                        "asset_state_committed",
                        scan_started,
                        json!({
                            "asset_id": asset_id,
                            "proof_stage": "adjusted_source_resolve_failure",
                            "state": State::Failed.as_str(),
                            "commit_wall_time_micros": commit_elapsed.as_micros() as u64,
                        }),
                    );
                    log_adjusted_source_resolution_finished(
                        scan_started,
                        execution.worker_id,
                        asset_id,
                        marker.attempt(),
                        session.database_scope,
                        "failed",
                        started.elapsed(),
                    );
                    Ok(RollingAssetStepOutcome::failed(true))
                }
                None => {
                    log_adjusted_source_resolution_finished(
                        scan_started,
                        execution.worker_id,
                        asset_id,
                        marker.attempt(),
                        session.database_scope,
                        "cas_conflict",
                        started.elapsed(),
                    );
                    Ok(RollingAssetStepOutcome::attempted(false))
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn run_rolling_adjusted_source_resolution_with<T: CloudKitAdjustedSourceTransport>(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    worker_id: usize,
    asset_id: &str,
    manifest: &Arc<Mutex<Manifest>>,
    summary: &Arc<Mutex<MonitorScanSummary>>,
    base_read_session: &CloudKitDeleteSession,
    resolver: &mut CloudKitAdjustedSourceResolver<T>,
) -> Result<RollingAssetStepOutcome, MonitorError> {
    let conversion_reservations =
        Arc::new(RollingConversionReservations::new([asset_id.to_string()]));
    let mut execution = RollingAssetExecutionContext {
        config,
        state_store,
        worker_id,
        manifest,
        summary,
        conversion_reservations: &conversion_reservations,
        base_read_session: Some(base_read_session),
        adjusted_source_resolver: None,
    };
    run_rolling_adjusted_source_resolution(asset_id, &mut execution, base_read_session, resolver)
}

#[cfg(test)]
fn fail_next_adjusted_source_resolution_before_cas() {
    ADJUSTED_SOURCE_RESOLUTION_FAIL_BEFORE_CAS.with(|fail| fail.set(true));
}

#[cfg(test)]
fn take_adjusted_source_resolution_fail_before_cas() -> bool {
    ADJUSTED_SOURCE_RESOLUTION_FAIL_BEFORE_CAS.with(|fail| fail.replace(false))
}

#[cfg(not(test))]
fn take_adjusted_source_resolution_fail_before_cas() -> bool {
    false
}

fn adjusted_source_output_path_for_marker(
    config: &MonitorConfig,
    asset_id: &str,
    marker: &AdjustedSourceRequiredProof,
) -> Result<PathBuf, MonitorError> {
    let conversion_output = config.heic_output_dir.join(format!("{asset_id}.heic"));
    let expected = adjusted_source_path_for_output(&conversion_output);
    let marker_relative = marker.adjusted_source_relative_path();
    let relative_is_safe = !marker_relative.as_os_str().is_empty()
        && marker_relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
    let marker_path = config.heic_output_dir.join(marker_relative);
    if !relative_is_safe
        || marker_path != expected
        || !marker_path.starts_with(&config.heic_output_dir)
        || marker_path.strip_prefix(&config.heic_output_dir).is_err()
    {
        return Err(MonitorError::InvalidConfig {
            message: "adjusted-source marker output path escaped the HEIC output root".to_string(),
        });
    }
    Ok(marker_path)
}

fn stage_adjusted_source_resolution_success(
    expected: &AssetRecord,
    asset_id: &str,
    conversion_output_path: &Path,
    proof: crate::adjusted_source::CloudKitAdjustedSourceProof,
) -> Result<AssetRecord, MonitorError> {
    let mut staged = Manifest::new();
    staged.upsert(expected.clone());
    staged.recover_failed_for_retry(asset_id, State::NasVerified)?;
    record_adjusted_source_proof(&mut staged, asset_id, conversion_output_path, proof)?;
    Ok(staged.get(asset_id)?.clone())
}

fn stage_adjusted_source_resolution_failure(
    expected: &AssetRecord,
    asset_id: &str,
    error: &AdjustedSourceError,
) -> Result<AssetRecord, MonitorError> {
    let mut staged = Manifest::new();
    staged.upsert(expected.clone());
    record_stage_failure_with_kind(
        &mut staged,
        asset_id,
        "adjusted_source_resolve",
        &error.to_string(),
        FailureKind::AdjustedSourceResolveFailed,
    )?;
    Ok(staged.get(asset_id)?.clone())
}

fn persist_rolling_adjusted_source_exact_cas(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    manifest: &Arc<Mutex<Manifest>>,
    expected: &AssetRecord,
    updated: &AssetRecord,
) -> Result<Option<Duration>, MonitorError> {
    match state_store
        .persist_records_exact_cas_atomic([AssetRecordExactCasUpdate { expected, updated }])
    {
        Ok(elapsed) => {
            lock_shared(manifest, "rolling lifecycle manifest")?.upsert(updated.clone());
            Ok(Some(elapsed))
        }
        Err(AssetStateStoreError::ExactCasMismatch { .. }) => {
            let durable_manifest = state_store.load()?;
            let durable_record = durable_manifest.get(&expected.asset_id)?.clone();
            validate_authoritative_adjusted_source_conflict_record(
                config,
                expected,
                &durable_manifest,
                &durable_record,
            )?;
            lock_shared(manifest, "rolling lifecycle manifest")?.upsert(durable_record);
            Ok(None)
        }
        Err(error) => Err(MonitorError::StateStore(error)),
    }
}

fn validate_authoritative_adjusted_source_conflict_record(
    config: &MonitorConfig,
    expected: &AssetRecord,
    durable_manifest: &Manifest,
    durable_record: &AssetRecord,
) -> Result<(), MonitorError> {
    let expected_original = adjusted_source_recovery_original_proof(expected).map_err(|_| {
        MonitorError::InvalidConfig {
            message: "stale adjusted-source worker expected an invalid source identity".to_string(),
        }
    })?;
    let durable_original = durable_record
        .proofs
        .get("original_asset")
        .ok_or_else(|| MonitorError::InvalidConfig {
            message: "durable adjusted-source conflict record is missing original proof"
                .to_string(),
        })
        .and_then(|proof| {
            serde_json::from_value::<OriginalAssetProof>(proof.clone()).map_err(|_| {
                MonitorError::InvalidConfig {
                    message: "durable adjusted-source conflict record has malformed original proof"
                        .to_string(),
                }
            })
        })?;
    if durable_original != expected_original {
        return Err(MonitorError::InvalidConfig {
            message: "durable adjusted-source conflict record changed source identity".to_string(),
        });
    }
    let destination = CloudKitLibraryDestination {
        database_scope: durable_original.database_scope,
        zone_name: durable_original.zone_name,
    };
    match durable_record.state {
        State::NasVerified => {
            if !reconciliation_exact_state_is_consistent(
                durable_manifest,
                &durable_record.asset_id,
                &destination,
            )? {
                return Err(MonitorError::InvalidConfig {
                    message: "durable adjusted-source conflict record is not lifecycle-consistent"
                        .to_string(),
                });
            }
            if ADJUSTED_SOURCE_RECOVERY_BLOCKING_PROOFS
                .iter()
                .any(|proof_key| {
                    *proof_key != "adjusted_source"
                        && durable_record.proofs.contains_key(*proof_key)
                })
            {
                return Err(MonitorError::InvalidConfig {
                    message: "durable adjusted-source conflict record has stale downstream proof"
                        .to_string(),
                });
            }
            let conversion_output = config
                .heic_output_dir
                .join(format!("{}.heic", durable_record.asset_id));
            if validated_adjusted_source_for_conversion(
                durable_manifest,
                &durable_record.asset_id,
                conversion_output,
            )?
            .is_none()
            {
                return Err(MonitorError::InvalidConfig {
                    message: "durable adjusted-source conflict record is missing adjusted proof"
                        .to_string(),
                });
            }
        }
        State::Converted
        | State::ConversionVerified
        | State::UploadVerified
        | State::DeleteEligible
        | State::DeleteApproved
        | State::Deleted => {
            if !reconciliation_exact_state_is_consistent(
                durable_manifest,
                &durable_record.asset_id,
                &destination,
            )? {
                return Err(MonitorError::InvalidConfig {
                    message: "durable adjusted-source conflict record is not lifecycle-consistent"
                        .to_string(),
                });
            }
        }
        _ => {
            return Err(MonitorError::InvalidConfig {
                message: "durable adjusted-source conflict record is not a safe continuation"
                    .to_string(),
            });
        }
    }
    Ok(())
}

fn log_adjusted_source_resolution_finished(
    scan_started: u64,
    worker_id: usize,
    asset_id: &str,
    attempt: u64,
    database_scope: CloudKitDatabaseScope,
    outcome: &'static str,
    elapsed: Duration,
) {
    log_monitor_event(
        "adjusted_source_resolve_finished",
        scan_started,
        json!({
            "worker_id": worker_id,
            "asset_id": asset_id,
            "attempt": attempt,
            "database_scope": database_scope.as_str(),
            "zone_category": "original_asset_proof",
            "outcome": outcome,
            "wall_time_millis": elapsed.as_millis() as u64,
        }),
    );
}

fn run_rolling_asset_conversion(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    asset_id: &str,
    manifest: &Arc<Mutex<Manifest>>,
    summary: &Arc<Mutex<MonitorScanSummary>>,
    conversion_reservations: &Arc<RollingConversionReservations>,
) -> Result<RollingAssetStepOutcome, MonitorError> {
    let (manifest_snapshot, request) = {
        let snapshot =
            lock_shared(manifest, "rolling lifecycle manifest")?.snapshot_record(asset_id)?;
        let requests =
            conversion_requests_with_limit(&snapshot, config, Some(&[asset_id.to_string()]), 1);
        let Some(request) = requests.into_iter().next() else {
            conversion_reservations.release(asset_id)?;
            return Ok(RollingAssetStepOutcome::skipped());
        };
        (snapshot, request)
    };
    if !conversion_reservations.claim_conversion_attempt(asset_id, config, summary)? {
        return Ok(RollingAssetStepOutcome::skipped());
    }
    let removed_stale_artifacts =
        remove_stale_monitor_conversion_artifacts(config, &manifest_snapshot, &request)?;
    if removed_stale_artifacts > 0 {
        log_monitor_event(
            "stale_conversion_artifacts_removed",
            shared_scan_started(summary)?,
            json!({
                "asset_id": asset_id,
                "removed": removed_stale_artifacts,
                "output_path": request.output_path.display().to_string(),
                "mode": "rolling_asset_queue",
            }),
        );
    }

    log_monitor_event(
        "conversions_started",
        shared_scan_started(summary)?,
        json!({
            "requests": 1,
            "jobs": config.jobs,
            "mode": "rolling_asset_queue",
            "asset_id": asset_id,
        }),
    );

    match execute_measured_conversion(&manifest_snapshot, request) {
        Ok(updated) => {
            let record = updated.get(asset_id)?.clone();
            let heic_size_bytes = record
                .proofs
                .get("conversion")
                .and_then(|proof| proof.get("size_bytes"))
                .and_then(serde_json::Value::as_u64);
            {
                let mut manifest = lock_shared(manifest, "rolling lifecycle manifest")?;
                if !rolling_conversion_request_is_current(&manifest, config, asset_id) {
                    log_monitor_event(
                        "stale_conversion_result_ignored",
                        shared_scan_started(summary)?,
                        json!({
                            "asset_id": asset_id,
                            "converted": true,
                            "mode": "rolling_asset_queue",
                        }),
                    );
                    return Ok(RollingAssetStepOutcome::attempted(false));
                }
                let previous = manifest.get(asset_id)?.clone();
                manifest.upsert(record);
                persist_asset_record(
                    state_store,
                    &mut manifest,
                    previous,
                    asset_id,
                    shared_scan_started(summary)?,
                    "conversion",
                )?;
            }
            let scan_started = {
                let mut summary = lock_shared(summary, "rolling lifecycle summary")?;
                summary.conversions_completed = summary.conversions_completed.saturating_add(1);
                summary.started_unix_seconds
            };
            log_monitor_event(
                "conversion_finished",
                scan_started,
                json!({
                    "asset_id": asset_id,
                    "converted": true,
                    "heic_size_bytes": heic_size_bytes,
                    "mode": "rolling_asset_queue",
                }),
            );
            Ok(RollingAssetStepOutcome::completed())
        }
        Err(error) => {
            let kind = error.failure_kind();
            let message = error.to_string();
            {
                let mut manifest = lock_shared(manifest, "rolling lifecycle manifest")?;
                if !rolling_conversion_request_is_current(&manifest, config, asset_id) {
                    log_monitor_event(
                        "stale_conversion_result_ignored",
                        shared_scan_started(summary)?,
                        json!({
                            "asset_id": asset_id,
                            "converted": false,
                            "error": message,
                            "mode": "rolling_asset_queue",
                        }),
                    );
                    return Ok(RollingAssetStepOutcome::attempted(false));
                }
                let previous = manifest.get(asset_id)?.clone();
                record_conversion_execution_failure(&mut manifest, asset_id, &message, kind)?;
                persist_asset_record(
                    state_store,
                    &mut manifest,
                    previous,
                    asset_id,
                    shared_scan_started(summary)?,
                    "conversion_failure",
                )?;
            }
            let scan_started = {
                let mut summary = lock_shared(summary, "rolling lifecycle summary")?;
                summary.failures = summary.failures.saturating_add(1);
                summary.last_error = Some(format!("conversion failed for {asset_id}: {message}"));
                summary.started_unix_seconds
            };
            log_monitor_event(
                "conversion_finished",
                scan_started,
                json!({
                    "asset_id": asset_id,
                    "converted": false,
                    "error": message,
                    "mode": "rolling_asset_queue",
                }),
            );
            Ok(RollingAssetStepOutcome::failed(true))
        }
    }
}

fn rolling_conversion_request_is_current(
    manifest: &Manifest,
    config: &MonitorConfig,
    asset_id: &str,
) -> bool {
    conversion_requests_with_limit(manifest, config, Some(&[asset_id.to_string()]), 1)
        .into_iter()
        .any(|request| request.asset_id == asset_id)
}

fn run_rolling_asset_verify(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    asset_id: &str,
    manifest: &Arc<Mutex<Manifest>>,
    summary: &Arc<Mutex<MonitorScanSummary>>,
) -> Result<RollingAssetStepOutcome, MonitorError> {
    let manifest_snapshot = {
        let snapshot =
            lock_shared(manifest, "rolling lifecycle manifest")?.snapshot_record(asset_id)?;
        let record = snapshot.get(asset_id)?;
        if record.state != State::Converted || record.proofs.contains_key("heic") {
            return Ok(RollingAssetStepOutcome::skipped());
        }
        snapshot
    };
    let scan_started = shared_scan_started(summary)?;
    log_monitor_event(
        "heic_verify_started",
        scan_started,
        json!({
            "asset_id": asset_id,
            "timeout_seconds": config.heic_verify_timeout_seconds,
            "mode": "rolling_asset_queue",
        }),
    );

    match verify_converted_heic(
        &manifest_snapshot,
        asset_id,
        config.heic_verify_timeout_seconds,
    ) {
        Ok(verification) => {
            let visual_metrics = verification.visual_metrics;
            let result = {
                let mut manifest = lock_shared(manifest, "rolling lifecycle manifest")?;
                let mut summary = lock_shared(summary, "rolling lifecycle summary")?;
                let previous = manifest.get(asset_id)?.clone();
                let result = record_heic_verification_or_failure(
                    &mut manifest,
                    &mut summary,
                    asset_id,
                    verification.proof,
                );
                persist_asset_record(
                    state_store,
                    &mut manifest,
                    previous,
                    asset_id,
                    scan_started,
                    "heic_verification",
                )?;
                result
            };
            match result {
                Ok(()) => {
                    let mut fields = json!({
                        "asset_id": asset_id,
                        "verified": true,
                        "mode": "rolling_asset_queue",
                    });
                    append_visual_verification_event_fields(&mut fields, visual_metrics);
                    log_monitor_event("heic_verify_finished", scan_started, fields);
                    Ok(RollingAssetStepOutcome::completed())
                }
                Err(message) => {
                    let mut fields = json!({
                        "asset_id": asset_id,
                        "verified": false,
                        "error": message,
                        "mode": "rolling_asset_queue",
                    });
                    append_visual_verification_event_fields(&mut fields, visual_metrics);
                    log_monitor_event("heic_verify_finished", scan_started, fields);
                    Ok(RollingAssetStepOutcome::failed(false))
                }
            }
        }
        Err(error) => {
            let message = error.to_string();
            {
                let mut summary = lock_shared(summary, "rolling lifecycle summary")?;
                record_monitor_failure(&mut summary, error);
            }
            log_monitor_event(
                "heic_verify_finished",
                scan_started,
                json!({
                    "asset_id": asset_id,
                    "verified": false,
                    "error": message,
                    "mode": "rolling_asset_queue",
                }),
            );
            Ok(RollingAssetStepOutcome::failed(false))
        }
    }
}

fn run_rolling_asset_upload(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    asset_id: &str,
    manifest: &Arc<Mutex<Manifest>>,
    summary: &Arc<Mutex<MonitorScanSummary>>,
) -> Result<RollingAssetStepOutcome, MonitorError> {
    let session_path = required_path(&config.upload_session_path, "upload_session_path")?;
    let (heic, destination) = {
        let manifest = lock_shared(manifest, "rolling lifecycle manifest")?;
        let record = manifest.get(asset_id)?;
        if record.state != State::ConversionVerified
            || !record.proofs.contains_key("original_asset")
            || record.proofs.contains_key("upload")
        {
            return Ok(RollingAssetStepOutcome::skipped());
        }
        match upload_ready_heic_proof(&manifest, asset_id) {
            Ok(heic) => {
                let destination = original_asset_destination(record)?;
                (heic, destination)
            }
            Err(error) => {
                let message = error.to_string();
                let scan_started = {
                    let mut summary = lock_shared(summary, "rolling lifecycle summary")?;
                    record_monitor_failure(&mut summary, error);
                    summary.started_unix_seconds
                };
                log_monitor_event(
                    "upload_finished",
                    scan_started,
                    json!({
                        "asset_id": asset_id,
                        "uploaded": false,
                        "error": message,
                        "mode": "rolling_asset_queue",
                    }),
                );
                return Ok(RollingAssetStepOutcome::failed(false));
            }
        }
    };
    let heic_size = heic.size_bytes;
    let scan_started = {
        let mut summary = lock_shared(summary, "rolling lifecycle summary")?;
        summary.uploads_attempted = summary.uploads_attempted.saturating_add(1);
        summary.started_unix_seconds
    };
    log_monitor_event(
        "upload_started",
        scan_started,
        json!({
            "asset_id": asset_id,
            "size_bytes": heic_size,
            "timeout_seconds": config.upload_timeout_seconds,
            "mode": "rolling_asset_queue",
        }),
    );

    match run_upload_proof_direct_child_with_timeout(
        asset_id,
        &heic,
        &destination,
        session_path,
        config.upload_timeout_seconds,
    ) {
        Ok(output) => {
            let timings = output.timings.clone();
            let uploaded = {
                let mut manifest = lock_shared(manifest, "rolling lifecycle manifest")?;
                let mut summary = lock_shared(summary, "rolling lifecycle summary")?;
                record_rolling_asset_upload_proof(
                    state_store,
                    &mut manifest,
                    &mut summary,
                    asset_id,
                    output.proof,
                    heic_size,
                )?
            };
            let mut fields = json!({
                    "asset_id": asset_id,
                    "uploaded": uploaded,
                    "size_bytes": heic_size,
                    "mode": "rolling_asset_queue",
            });
            append_upload_timing_fields(&mut fields, timings.as_ref());
            log_monitor_event("upload_finished", scan_started, fields);
            Ok(if uploaded {
                RollingAssetStepOutcome::completed()
            } else {
                RollingAssetStepOutcome::failed(false)
            })
        }
        Err(error) => {
            let message = error.to_string();
            let should_fail_record = upload_error_should_fail_record(&error);
            {
                let mut summary = lock_shared(summary, "rolling lifecycle summary")?;
                record_monitor_failure(&mut summary, message.clone());
            }
            if should_fail_record {
                let mut manifest = lock_shared(manifest, "rolling lifecycle manifest")?;
                let previous = manifest.get(asset_id)?.clone();
                record_stage_failure(&mut manifest, asset_id, "upload", &message)?;
                persist_asset_record(
                    state_store,
                    &mut manifest,
                    previous,
                    asset_id,
                    scan_started,
                    "upload_failure",
                )?;
            }
            log_monitor_event(
                "upload_finished",
                scan_started,
                json!({
                    "asset_id": asset_id,
                    "uploaded": false,
                    "error": message,
                    "mode": "rolling_asset_queue",
                }),
            );
            Ok(RollingAssetStepOutcome::failed(false))
        }
    }
}

fn run_rolling_asset_local_mirror(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    asset_id: &str,
    manifest: &Arc<Mutex<Manifest>>,
    summary: &Arc<Mutex<MonitorScanSummary>>,
) -> Result<RollingAssetStepOutcome, MonitorError> {
    let request = {
        let snapshot =
            lock_shared(manifest, "rolling lifecycle manifest")?.snapshot_record(asset_id)?;
        let Some(request) = rolling_asset_local_mirror_request(config, &snapshot, asset_id)? else {
            return Ok(RollingAssetStepOutcome::skipped());
        };
        request
    };
    let scan_started = shared_scan_started(summary)?;

    match ensure_icloudpd_local_mirror_with_timeout(
        asset_id,
        config.local_mirror_timeout_seconds,
        request,
    ) {
        Ok(proof) => {
            let mut manifest = lock_shared(manifest, "rolling lifecycle manifest")?;
            let mut summary = lock_shared(summary, "rolling lifecycle summary")?;
            record_rolling_asset_local_mirror_proof(
                state_store,
                &mut manifest,
                &mut summary,
                asset_id,
                proof,
            )?;
            log_monitor_event(
                "local_mirror_finished",
                scan_started,
                json!({
                    "asset_id": asset_id,
                    "mirrored": true,
                    "mode": "rolling_asset_queue",
                }),
            );
            Ok(RollingAssetStepOutcome::completed())
        }
        Err(error) => {
            let message = error.to_string();
            log_monitor_event(
                "local_mirror_failed",
                scan_started,
                json!({
                    "asset_id": asset_id,
                    "mirrored": false,
                    "error": message,
                    "mode": "rolling_asset_queue",
                }),
            );
            let mut summary = lock_shared(summary, "rolling lifecycle summary")?;
            record_monitor_failure(&mut summary, error);
            Ok(RollingAssetStepOutcome::failed(false))
        }
    }
}

fn rolling_asset_local_mirror_request(
    config: &MonitorConfig,
    manifest: &Manifest,
    asset_id: &str,
) -> Result<Option<IcloudpdLocalMirrorRequest>, MonitorError> {
    let record = manifest.get(asset_id)?;
    if record.state != State::UploadVerified || record.proofs.contains_key("icloudpd_local_mirror")
    {
        return Ok(None);
    }
    let mirror_root = config.mirror_root.as_ref().unwrap_or(&config.download_root);
    Ok(Some(icloudpd_local_mirror_request(
        mirror_root,
        manifest,
        asset_id,
    )?))
}

fn icloudpd_local_mirror_request(
    mirror_root: &Path,
    manifest: &Manifest,
    asset_id: &str,
) -> Result<IcloudpdLocalMirrorRequest, MonitorError> {
    let record = manifest.get(asset_id)?;
    let (upload, heic) = icloudpd_local_mirror_ready_proofs(manifest, asset_id)?;
    let uploaded_heic_path =
        upload
            .uploaded_heic_path
            .clone()
            .ok_or(WorkflowError::EmptyProofField {
                field: "uploaded_heic_path",
            })?;
    let icloudpd_download_path = icloudpd_local_mirror_download_path(
        record,
        mirror_root,
        asset_id,
        &upload.uploaded_heic_sha256,
    )?;
    Ok(IcloudpdLocalMirrorRequest {
        uploaded_heic_asset_id: upload.uploaded_heic_asset_id,
        uploaded_heic_sha256: upload.uploaded_heic_sha256,
        uploaded_heic_path,
        size_bytes: heic.size_bytes,
        icloudpd_download_path,
    })
}

fn icloudpd_local_mirror_download_path(
    record: &AssetRecord,
    mirror_root: &Path,
    asset_id: &str,
    uploaded_heic_sha256: &str,
) -> Result<PathBuf, MonitorError> {
    let raw_parent = record
        .raw_path
        .parent()
        .ok_or_else(|| MonitorError::InvalidConfig {
            message: format!(
                "RAW path {} has no parent directory",
                record.raw_path.display()
            ),
        })?;
    let candidate = raw_parent.join(format!("{asset_id}.HEIC"));
    match fs::symlink_metadata(&candidate) {
        Ok(_) => Ok(candidate),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(
            icloudpd_local_mirror_destination(mirror_root, asset_id, uploaded_heic_sha256)?,
        ),
        Err(source) => Err(MonitorError::ReadMetadata {
            path: candidate,
            source,
        }),
    }
}

fn icloudpd_local_mirror_destination(
    mirror_root: &Path,
    asset_id: &str,
    uploaded_heic_sha256: &str,
) -> Result<PathBuf, WorkflowError> {
    if uploaded_heic_sha256.trim().is_empty() {
        return Err(WorkflowError::EmptyProofField {
            field: "uploaded_heic_sha256",
        });
    }
    if uploaded_heic_sha256.len() != 64
        || !uploaded_heic_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(WorkflowError::InvalidProofField {
            proof_key: "upload",
            field: "uploaded_heic_sha256",
            reason: "must be a 64-character hexadecimal SHA-256",
        });
    }
    let normalized_hash = uploaded_heic_sha256.to_ascii_lowercase();
    Ok(mirror_root.join(format!("{asset_id}-{normalized_hash}.HEIC")))
}

fn record_rolling_asset_upload_proof(
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    asset_id: &str,
    proof: UploadProof,
    heic_size: u64,
) -> Result<bool, MonitorError> {
    let previous = manifest.get(asset_id)?.clone();
    match record_upload_proof(manifest, asset_id, proof) {
        Ok(record) if record.state == State::UploadVerified => {
            summary.uploads_completed = summary.uploads_completed.saturating_add(1);
            summary.uploaded_heic_bytes = summary.uploaded_heic_bytes.saturating_add(heic_size);
            persist_asset_record(
                state_store,
                manifest,
                previous,
                asset_id,
                summary.started_unix_seconds,
                "upload_proof",
            )?;
            Ok(true)
        }
        Ok(_) => Ok(false),
        Err(error) => {
            record_monitor_failure(summary, MonitorError::Workflow(error));
            Ok(false)
        }
    }
}

fn record_rolling_asset_local_mirror_proof(
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    asset_id: &str,
    proof: IcloudpdLocalMirrorProof,
) -> Result<(), MonitorError> {
    let previous = manifest.get(asset_id)?.clone();
    record_icloudpd_local_mirror_proof(manifest, asset_id, proof)?;
    summary.mirrors_recorded = summary.mirrors_recorded.saturating_add(1);
    persist_asset_record(
        state_store,
        manifest,
        previous,
        asset_id,
        summary.started_unix_seconds,
        "local_mirror_proof",
    )?;
    Ok(())
}

fn rolling_asset_terminal_state(
    manifest: &Arc<Mutex<Manifest>>,
    asset_id: &str,
) -> Result<bool, MonitorError> {
    let manifest = lock_shared(manifest, "rolling lifecycle manifest")?;
    let record = manifest.get(asset_id)?;
    Ok(record.state.is_terminal()
        || (record.state == State::Failed && adjusted_source_required_proof(record).is_err()))
}

fn remove_stale_monitor_conversion_artifacts(
    config: &MonitorConfig,
    manifest: &Manifest,
    request: &ConversionExecutionRequest,
) -> Result<usize, MonitorError> {
    let record = manifest.get(&request.asset_id)?;
    if record.proofs.contains_key("conversion") {
        return Ok(0);
    }

    let mut removed = 0usize;
    for path in monitor_conversion_artifact_paths(&request.output_path, &record.raw_path) {
        if !path.starts_with(&config.heic_output_dir) {
            return Err(MonitorError::InvalidConfig {
                message: format!(
                    "refusing to remove generated conversion artifact outside HEIC output dir: {}",
                    path.display()
                ),
            });
        }
        removed = removed.saturating_add(remove_stale_monitor_conversion_artifact(&path)?);
    }
    Ok(removed)
}

fn monitor_conversion_artifact_paths(output_path: &Path, raw_path: &Path) -> Vec<PathBuf> {
    vec![
        output_path.to_path_buf(),
        monitor_generated_conversion_path(output_path, "embedded-preview.jpg"),
        monitor_generated_conversion_path(output_path, "oriented-preview.jpg"),
        monitor_generated_conversion_path(output_path, "heic-verify-preview.png"),
        monitor_generated_conversion_path(output_path, "raw-verify-preview.png"),
        monitor_staged_raw_path_for_output(output_path, raw_path),
    ]
}

fn monitor_generated_conversion_path(output_path: &Path, extension: &str) -> PathBuf {
    let mut path = output_path.to_path_buf();
    path.set_extension(extension);
    path
}

fn monitor_staged_raw_path_for_output(output_path: &Path, raw_path: &Path) -> PathBuf {
    let mut staged_path = output_path.to_path_buf();
    let mut extension = OsString::from("staged-raw");
    if let Some(raw_extension) = raw_path
        .extension()
        .filter(|extension| !extension.is_empty())
    {
        extension.push(".");
        extension.push(raw_extension);
    }
    staged_path.set_extension(extension);
    staged_path
}

fn remove_stale_monitor_conversion_artifact(path: &Path) -> Result<usize, MonitorError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
            fs::remove_file(path).map_err(|source| MonitorError::CommandFailed {
                program: "icloudpd-optimizer",
                message: format!(
                    "failed to remove stale generated conversion artifact {}: {source}",
                    path.display()
                ),
            })?;
            Ok(1)
        }
        Ok(_) => Err(MonitorError::InvalidConfig {
            message: format!(
                "refusing to remove stale generated conversion artifact that is not a file: {}",
                path.display()
            ),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(source) => Err(MonitorError::ReadMetadata {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn shared_scan_started(summary: &Arc<Mutex<MonitorScanSummary>>) -> Result<u64, MonitorError> {
    Ok(lock_shared(summary, "rolling lifecycle summary")?.started_unix_seconds)
}

fn persist_asset_record(
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    previous: AssetRecord,
    asset_id: &str,
    scan_started_unix_seconds: u64,
    proof_stage: &'static str,
) -> Result<(), MonitorError> {
    let elapsed = match state_store.persist_record(manifest.get(asset_id)?) {
        Ok(elapsed) => elapsed,
        Err(error) => {
            manifest.upsert(previous);
            return Err(MonitorError::StateStore(error));
        }
    };
    log_monitor_event(
        "asset_state_committed",
        scan_started_unix_seconds,
        json!({
            "asset_id": asset_id,
            "proof_stage": proof_stage,
            "state": manifest.get(asset_id)?.state.as_str(),
            "commit_wall_time_micros": elapsed.as_micros() as u64,
        }),
    );
    Ok(())
}

fn checkpoint_manifest_state(
    state_store: &AssetStateStore,
    manifest: &Manifest,
) -> Result<(), MonitorError> {
    state_store.persist_manifest_records(manifest)?;
    state_store.export_json()?;
    Ok(())
}

fn shared_asset_state_name(
    manifest: &Arc<Mutex<Manifest>>,
    asset_id: &str,
) -> Result<String, MonitorError> {
    Ok(lock_shared(manifest, "rolling lifecycle manifest")?
        .get(asset_id)?
        .state
        .as_str()
        .to_string())
}

fn lock_shared<'a, T>(
    value: &'a Arc<Mutex<T>>,
    name: &'static str,
) -> Result<MutexGuard<'a, T>, MonitorError> {
    value.lock().map_err(|_| MonitorError::CommandFailed {
        program: "icloudpd-optimizer",
        message: format!("{name} lock poisoned"),
    })
}

fn remaining_conversion_capacity(config: &MonitorConfig, summary: &MonitorScanSummary) -> usize {
    config
        .max_conversions_per_scan
        .saturating_sub(summary.conversions_attempted as usize)
}

fn rolling_lifecycle_made_forward_progress(
    before: &MonitorScanSummary,
    after: &MonitorScanSummary,
) -> bool {
    after.adjusted_sources_resolved > before.adjusted_sources_resolved
        || after.originals_resolved > before.originals_resolved
        || after.conversions_completed > before.conversions_completed
        || after.heics_verified > before.heics_verified
        || after.uploads_completed > before.uploads_completed
        || after.mirrors_recorded > before.mirrors_recorded
        || after.originals_deleted > before.originals_deleted
}

fn rolling_lifecycle_counters_moved(
    before: &MonitorScanSummary,
    after: &MonitorScanSummary,
) -> bool {
    after.originals_resolved > before.originals_resolved
        || after.heics_verified > before.heics_verified
        || after.uploads_completed > before.uploads_completed
        || after.mirrors_recorded > before.mirrors_recorded
        || after.originals_deleted > before.originals_deleted
}

fn rolling_lifecycle_should_continue(
    config: &MonitorConfig,
    before: &MonitorScanSummary,
    after: &MonitorScanSummary,
    active_ids: &[String],
    refreshed_active_ids: &[String],
) -> bool {
    if after.failures > before.failures && refreshed_active_ids != active_ids {
        return true;
    }
    if !rolling_lifecycle_made_forward_progress(before, after) {
        return false;
    }
    remaining_conversion_capacity(config, after) > 0
        || rolling_lifecycle_counters_moved(before, after)
}

fn lifecycle_stage_finished_fields(
    stage: LifecycleStage,
    summary: &MonitorScanSummary,
    wall_time_seconds: u64,
) -> serde_json::Value {
    let mut fields = match stage {
        LifecycleStage::DeleteOriginalAssets => json!({
            "stage": stage.name(),
            "failures": summary.failures,
            "originals_deleted": summary.originals_deleted,
        }),
        LifecycleStage::RecordLocalMirrors => json!({
            "stage": stage.name(),
            "failures": summary.failures,
            "mirrors_recorded": summary.mirrors_recorded,
        }),
        LifecycleStage::UploadVerifiedHeics => json!({
            "stage": stage.name(),
            "failures": summary.failures,
            "uploads_completed": summary.uploads_completed,
        }),
        LifecycleStage::VerifyConvertedHeics => json!({
            "stage": stage.name(),
            "failures": summary.failures,
            "heics_verified": summary.heics_verified,
        }),
        LifecycleStage::ResolveOriginalAssets => json!({
            "stage": stage.name(),
            "failures": summary.failures,
            "originals_resolved": summary.originals_resolved,
        }),
    };
    if let Some(fields) = fields.as_object_mut() {
        fields.insert("wall_time_seconds".to_string(), json!(wall_time_seconds));
    }
    fields
}

fn verify_converted_heics(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    active_lifecycle_asset_ids: &[String],
) -> Result<(), MonitorError> {
    let asset_ids = asset_ids_matching(manifest, config.max_lifecycle_per_scan, |record| {
        active_lifecycle_allows(Some(active_lifecycle_asset_ids), &record.asset_id)
            && record.state == State::Converted
            && !record.proofs.contains_key("heic")
    });
    for chunk in asset_ids.chunks(config.jobs.max(1)) {
        for asset_id in chunk {
            log_monitor_event(
                "heic_verify_started",
                summary.started_unix_seconds,
                json!({
                    "asset_id": asset_id,
                    "timeout_seconds": config.heic_verify_timeout_seconds,
                }),
            );
        }
        let manifest_snapshot = manifest.clone();
        let timeout_seconds = config.heic_verify_timeout_seconds;
        let outcomes = run_parallel_asset_job_chunk(chunk, move |asset_id| {
            verify_converted_heic(&manifest_snapshot, &asset_id, timeout_seconds)
        });
        let mut should_stop = false;
        let mut verified_assets = Vec::new();
        for outcome in outcomes {
            match outcome.result {
                Ok(verification) => {
                    let visual_metrics = verification.visual_metrics;
                    match record_heic_verification_or_failure(
                        manifest,
                        summary,
                        &outcome.asset_id,
                        verification.proof,
                    ) {
                        Ok(()) => verified_assets.push((outcome.asset_id, visual_metrics)),
                        Err(message) => {
                            let mut fields = json!({
                                "asset_id": outcome.asset_id,
                                "verified": false,
                                "error": message,
                            });
                            append_visual_verification_event_fields(&mut fields, visual_metrics);
                            log_monitor_event(
                                "heic_verify_finished",
                                summary.started_unix_seconds,
                                fields,
                            );
                        }
                    }
                }
                Err(error) => {
                    let message = error.to_string();
                    log_monitor_event(
                        "heic_verify_finished",
                        summary.started_unix_seconds,
                        json!({
                            "asset_id": outcome.asset_id,
                            "verified": false,
                            "error": message,
                        }),
                    );
                    should_stop |= matches!(error, MonitorError::CommandTimeout { .. });
                    record_monitor_failure(summary, error);
                }
            }
        }
        if !verified_assets.is_empty() {
            checkpoint_manifest_state(state_store, manifest)?;
            for (asset_id, visual_metrics) in verified_assets {
                let mut fields = json!({
                    "asset_id": asset_id,
                    "verified": true,
                });
                append_visual_verification_event_fields(&mut fields, visual_metrics);
                log_monitor_event("heic_verify_finished", summary.started_unix_seconds, fields);
            }
        }
        if should_stop {
            break;
        }
    }
    Ok(())
}

fn record_heic_verification_or_failure(
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    asset_id: &str,
    proof: HeicVerificationProof,
) -> Result<(), String> {
    match record_heic_verification(manifest, asset_id, proof) {
        Ok(_) => {
            summary.heics_verified = summary.heics_verified.saturating_add(1);
            Ok(())
        }
        Err(error) => {
            let kind = workflow_failure_kind(&error);
            let message = error.to_string();
            record_monitor_failure(summary, MonitorError::Workflow(error));
            let recorded = match kind {
                Some(kind) => record_stage_failure_with_kind(
                    manifest,
                    asset_id,
                    "heic_verify",
                    &message,
                    kind,
                ),
                None => record_stage_failure(manifest, asset_id, "heic_verify", &message),
            };
            if let Err(failure_error) = recorded {
                record_monitor_failure(summary, MonitorError::Workflow(failure_error));
            }
            Err(message)
        }
    }
}

fn record_conversion_execution_failure(
    manifest: &mut Manifest,
    asset_id: &str,
    message: &str,
    kind: Option<FailureKind>,
) -> Result<(), WorkflowError> {
    match kind {
        Some(kind) => {
            record_stage_failure_with_kind(manifest, asset_id, "conversion", message, kind)
        }
        None => record_stage_failure(manifest, asset_id, "conversion", message),
    }?;
    Ok(())
}

fn workflow_failure_kind(error: &WorkflowError) -> Option<FailureKind> {
    match error {
        WorkflowError::HeicVerificationFailed {
            field: "visual_content_ok",
        } => Some(FailureKind::HeicVisualContent),
        WorkflowError::HeicVerificationFailed {
            field: "visual_match_ok",
        } => Some(FailureKind::HeicVisualMatch),
        _ => None,
    }
}

fn resolve_original_assets(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    active_lifecycle_asset_ids: &[String],
) -> Result<(), MonitorError> {
    resolve_original_asset_batches(
        config,
        state_store,
        manifest,
        summary,
        active_lifecycle_asset_ids,
        None,
    )
}

fn resolve_original_asset_batches(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    active_lifecycle_asset_ids: &[String],
    max_batches: Option<usize>,
) -> Result<(), MonitorError> {
    let target_batches = original_asset_resolution_target_batches_to_run(
        manifest,
        config,
        Some(active_lifecycle_asset_ids),
        max_batches,
    )?;
    if target_batches.is_empty() {
        return Ok(());
    }

    let session_path = required_path(&config.delete_session_path, "delete_session_path")?;
    let session = load_cloudkit_delete_session(session_path)?;
    let run_parallel = max_batches.is_some_and(|limit| limit > 1) && target_batches.len() > 1;
    if run_parallel {
        return resolve_original_asset_batches_parallel(
            config,
            state_store,
            manifest,
            summary,
            session,
            target_batches,
            max_batches,
        );
    }

    let transport = ReqwestCloudKitDeleteTransport::new()?;
    let mut client = CloudKitDeleteClient::new(transport);
    for targets in target_batches {
        let asset_ids = targets
            .iter()
            .map(|target| target.asset_id.clone())
            .collect::<Vec<_>>();
        let min_capture = targets
            .iter()
            .map(|target| target.source_captured_unix_seconds)
            .min()
            .unwrap_or(0);
        let max_capture = targets
            .iter()
            .map(|target| target.source_captured_unix_seconds)
            .max()
            .unwrap_or(0);
        let started = current_unix_seconds();
        log_monitor_event(
            "original_asset_resolve_batch_started",
            summary.started_unix_seconds,
            json!({
                "targets": targets.len(),
                "min_capture_unix_seconds": min_capture,
                "max_capture_unix_seconds": max_capture,
                "capture_span_seconds": max_capture.saturating_sub(min_capture),
                "start_rank": config.cloudkit_start_rank,
                "page_size": config.cloudkit_page_size,
                "max_pages": config.cloudkit_max_pages,
                "batch_limit": max_batches,
            }),
        );
        match client.resolve_original_assets_batch_outcome(
            &session,
            &CloudKitOriginalAssetBatchResolveRequest {
                targets: targets.clone(),
                start_rank: config.cloudkit_start_rank,
                page_size: config.cloudkit_page_size,
                max_pages: config.cloudkit_max_pages,
            },
        ) {
            Ok(outcome) => {
                let resolution = record_original_asset_batch_outcome(
                    manifest,
                    &targets,
                    &session.zone,
                    outcome,
                    current_unix_seconds(),
                    summary,
                )?;
                if resolution.manifest_changed() {
                    checkpoint_manifest_state(state_store, manifest)?;
                }
                log_monitor_event(
                    "original_asset_resolve_batch_finished",
                    summary.started_unix_seconds,
                    original_asset_resolve_batch_finished_fields(
                        asset_ids.len(),
                        &resolution,
                        0,
                        &[],
                        current_unix_seconds().saturating_sub(started),
                        max_batches,
                        None,
                    ),
                );
            }
            Err(error) => {
                let should_fail_records = original_asset_resolve_error_should_fail_records(&error);
                let message = error.to_string();
                let unresolved_asset_ids = if should_fail_records {
                    asset_ids.clone()
                } else {
                    Vec::new()
                };
                record_monitor_failure(summary, message.clone());
                if should_fail_records {
                    record_lifecycle_failure_for_assets(
                        manifest,
                        &asset_ids,
                        "original_asset_resolve",
                        &message,
                    )?;
                    checkpoint_manifest_state(state_store, manifest)?;
                }
                log_monitor_event(
                    "original_asset_resolve_batch_finished",
                    summary.started_unix_seconds,
                    original_asset_resolve_batch_finished_fields(
                        asset_ids.len(),
                        &OriginalAssetResolutionMonitorSummary::default(),
                        asset_ids.len(),
                        &unresolved_asset_ids,
                        current_unix_seconds().saturating_sub(started),
                        max_batches,
                        Some(&message),
                    ),
                );
            }
        }
    }
    Ok(())
}

struct OriginalAssetResolveBatchJob {
    batch_index: usize,
    targets: Vec<CloudKitOriginalAssetResolveTarget>,
    asset_ids: Vec<String>,
    min_capture: u64,
    max_capture: u64,
    started_unix_seconds: u64,
}

struct OriginalAssetResolveBatchJobResult {
    job: OriginalAssetResolveBatchJob,
    result: Result<CloudKitOriginalAssetBatchResolveOutcome, UploadError>,
}

fn resolve_original_asset_batches_parallel(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    session: CloudKitDeleteSession,
    target_batches: Vec<Vec<CloudKitOriginalAssetResolveTarget>>,
    max_batches: Option<usize>,
) -> Result<(), MonitorError> {
    let jobs = target_batches
        .into_iter()
        .enumerate()
        .map(|(batch_index, targets)| {
            let asset_ids = targets
                .iter()
                .map(|target| target.asset_id.clone())
                .collect::<Vec<_>>();
            let min_capture = targets
                .iter()
                .map(|target| target.source_captured_unix_seconds)
                .min()
                .unwrap_or(0);
            let max_capture = targets
                .iter()
                .map(|target| target.source_captured_unix_seconds)
                .max()
                .unwrap_or(0);
            OriginalAssetResolveBatchJob {
                batch_index,
                targets,
                asset_ids,
                min_capture,
                max_capture,
                started_unix_seconds: current_unix_seconds(),
            }
        })
        .collect::<Vec<_>>();

    for job in &jobs {
        log_monitor_event(
            "original_asset_resolve_batch_started",
            summary.started_unix_seconds,
            json!({
                "targets": job.targets.len(),
                "min_capture_unix_seconds": job.min_capture,
                "max_capture_unix_seconds": job.max_capture,
                "capture_span_seconds": job.max_capture.saturating_sub(job.min_capture),
                "start_rank": config.cloudkit_start_rank,
                "page_size": config.cloudkit_page_size,
                "max_pages": config.cloudkit_max_pages,
                "batch_limit": max_batches,
                "batch_index": job.batch_index,
                "parallel": true,
            }),
        );
    }

    let handles = jobs
        .into_iter()
        .map(|job| {
            let session = session.clone();
            let start_rank = config.cloudkit_start_rank;
            let page_size = config.cloudkit_page_size;
            let max_pages = config.cloudkit_max_pages;
            thread::spawn(move || {
                let result = ReqwestCloudKitDeleteTransport::new().and_then(|transport| {
                    let mut client = CloudKitDeleteClient::new(transport);
                    client.resolve_original_assets_batch_outcome(
                        &session,
                        &CloudKitOriginalAssetBatchResolveRequest {
                            targets: job.targets.clone(),
                            start_rank,
                            page_size,
                            max_pages,
                        },
                    )
                });
                OriginalAssetResolveBatchJobResult { job, result }
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        let job_result = handle.join().map_err(|_| MonitorError::CommandFailed {
            program: "icloudpd-optimizer",
            message: "parallel original asset resolver panicked".to_string(),
        })?;
        record_original_asset_batch_job_result(
            state_store,
            manifest,
            summary,
            &session.zone,
            job_result,
            max_batches,
        )?;
    }
    Ok(())
}

fn record_original_asset_batch_job_result(
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    destination: &CloudKitLibraryDestination,
    job_result: OriginalAssetResolveBatchJobResult,
    max_batches: Option<usize>,
) -> Result<(), MonitorError> {
    let OriginalAssetResolveBatchJobResult { job, result } = job_result;
    match result {
        Ok(outcome) => {
            let resolution = record_original_asset_batch_outcome(
                manifest,
                &job.targets,
                destination,
                outcome,
                current_unix_seconds(),
                summary,
            )?;
            if resolution.manifest_changed() {
                checkpoint_manifest_state(state_store, manifest)?;
            }
            let mut fields = original_asset_resolve_batch_finished_fields(
                job.asset_ids.len(),
                &resolution,
                0,
                &[],
                current_unix_seconds().saturating_sub(job.started_unix_seconds),
                max_batches,
                None,
            );
            fields["batch_index"] = json!(job.batch_index);
            fields["parallel"] = json!(true);
            log_monitor_event(
                "original_asset_resolve_batch_finished",
                summary.started_unix_seconds,
                fields,
            );
        }
        Err(error) => {
            let should_fail_records = original_asset_resolve_error_should_fail_records(&error);
            let message = error.to_string();
            let unresolved_asset_ids = if should_fail_records {
                job.asset_ids.clone()
            } else {
                Vec::new()
            };
            record_monitor_failure(summary, message.clone());
            if should_fail_records {
                record_lifecycle_failure_for_assets(
                    manifest,
                    &job.asset_ids,
                    "original_asset_resolve",
                    &message,
                )?;
                checkpoint_manifest_state(state_store, manifest)?;
            }
            let mut fields = original_asset_resolve_batch_finished_fields(
                job.asset_ids.len(),
                &OriginalAssetResolutionMonitorSummary::default(),
                job.asset_ids.len(),
                &unresolved_asset_ids,
                current_unix_seconds().saturating_sub(job.started_unix_seconds),
                max_batches,
                Some(&message),
            );
            fields["batch_index"] = json!(job.batch_index);
            fields["parallel"] = json!(true);
            log_monitor_event(
                "original_asset_resolve_batch_finished",
                summary.started_unix_seconds,
                fields,
            );
        }
    }
    Ok(())
}

fn original_asset_resolution_target_batches_to_run(
    manifest: &Manifest,
    config: &MonitorConfig,
    active_lifecycle_asset_ids: Option<&[String]>,
    max_batches: Option<usize>,
) -> Result<Vec<Vec<CloudKitOriginalAssetResolveTarget>>, MonitorError> {
    let mut batches =
        original_asset_resolution_target_batches(manifest, config, active_lifecycle_asset_ids)?;
    if let Some(max_batches) = max_batches {
        batches.truncate(max_batches);
    }
    Ok(batches)
}

fn original_asset_resolve_error_should_fail_records(error: &UploadError) -> bool {
    matches!(error, UploadError::OriginalAssetResolveNotUnique { .. })
}

fn original_asset_resolve_batch_finished_fields(
    targets: usize,
    reconciliation: &OriginalAssetResolutionMonitorSummary,
    unresolved: usize,
    unresolved_asset_ids: &[String],
    wall_time_seconds: u64,
    batch_limit: Option<usize>,
    error: Option<&str>,
) -> serde_json::Value {
    let mut fields = json!({
        "targets": targets,
        "resolved": reconciliation.applied.exact_original,
        "no_action": reconciliation.applied.no_action,
        "needs_review": reconciliation.applied.needs_review,
        "deferred": reconciliation.deferred,
        "unresolved": unresolved,
        "unresolved_asset_ids": unresolved_asset_ids,
        "wall_time_seconds": wall_time_seconds,
        "batch_limit": batch_limit,
    });
    if let Some(error) = error {
        fields["error"] = json!(error);
    }
    fields
}

fn upload_verified_heics(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    active_lifecycle_asset_ids: &[String],
) -> Result<(), MonitorError> {
    let asset_ids = asset_ids_matching(manifest, config.max_lifecycle_per_scan, |record| {
        active_lifecycle_allows(Some(active_lifecycle_asset_ids), &record.asset_id)
            && record.state == State::ConversionVerified
            && record.proofs.contains_key("original_asset")
            && !record.proofs.contains_key("upload")
    });
    let session_path = required_path(&config.upload_session_path, "upload_session_path")?;
    let mut heic_sizes = BTreeMap::new();
    let mut upload_asset_ids = Vec::new();
    for asset_id in asset_ids {
        match upload_ready_heic_proof(manifest, &asset_id) {
            Ok(heic) => {
                summary.uploads_attempted = summary.uploads_attempted.saturating_add(1);
                heic_sizes.insert(asset_id.clone(), heic.size_bytes);
                log_monitor_event(
                    "upload_started",
                    summary.started_unix_seconds,
                    json!({
                        "asset_id": asset_id,
                        "size_bytes": heic.size_bytes,
                        "timeout_seconds": config.upload_timeout_seconds,
                    }),
                );
                upload_asset_ids.push(asset_id);
            }
            Err(error) => {
                let message = error.to_string();
                log_monitor_event(
                    "upload_finished",
                    summary.started_unix_seconds,
                    json!({
                        "asset_id": asset_id,
                        "uploaded": false,
                        "error": message,
                    }),
                );
                record_monitor_failure(summary, error);
            }
        }
    }
    for chunk in upload_asset_ids.chunks(config.jobs.max(1)) {
        let manifest_path = config.manifest_path.clone();
        let session_path = session_path.to_path_buf();
        let timeout_seconds = config.upload_timeout_seconds;
        let outcomes = run_parallel_asset_job_chunk(chunk, move |asset_id| {
            run_upload_proof_child_with_timeout(
                &manifest_path,
                &asset_id,
                &session_path,
                timeout_seconds,
            )
        });
        let mut should_stop = false;
        let mut manifest_changed = false;
        let mut uploaded_assets = Vec::new();
        for outcome in outcomes {
            match outcome.result {
                Ok(output) => {
                    match record_upload_proof(manifest, &outcome.asset_id, output.proof) {
                        Ok(record) if record.state == State::UploadVerified => {
                            summary.uploads_completed = summary.uploads_completed.saturating_add(1);
                            let heic_size = heic_sizes
                                .get(&outcome.asset_id)
                                .copied()
                                .unwrap_or_default();
                            summary.uploaded_heic_bytes =
                                summary.uploaded_heic_bytes.saturating_add(heic_size);
                            uploaded_assets.push((outcome.asset_id, heic_size, output.timings));
                        }
                        Ok(_) => {}
                        Err(error) => {
                            let message = error.to_string();
                            log_monitor_event(
                                "upload_finished",
                                summary.started_unix_seconds,
                                json!({
                                    "asset_id": outcome.asset_id,
                                    "uploaded": false,
                                    "error": message,
                                }),
                            );
                            record_monitor_failure(summary, MonitorError::Workflow(error));
                        }
                    }
                }
                Err(error) => {
                    let message = error.to_string();
                    if upload_error_should_fail_record(&error) {
                        record_stage_failure(manifest, &outcome.asset_id, "upload", &message)?;
                        manifest_changed = true;
                    }
                    log_monitor_event(
                        "upload_finished",
                        summary.started_unix_seconds,
                        json!({
                            "asset_id": outcome.asset_id,
                            "uploaded": false,
                            "error": message,
                        }),
                    );
                    should_stop |= matches!(error, MonitorError::UploadWorkflowTimeout { .. });
                    record_monitor_failure(summary, error);
                }
            }
        }
        if !uploaded_assets.is_empty() || manifest_changed {
            checkpoint_manifest_state(state_store, manifest)?;
        }
        if !uploaded_assets.is_empty() {
            for (asset_id, heic_size, timings) in uploaded_assets {
                let mut fields = json!({
                        "asset_id": asset_id,
                        "uploaded": true,
                        "size_bytes": heic_size,
                });
                append_upload_timing_fields(&mut fields, timings.as_ref());
                log_monitor_event("upload_finished", summary.started_unix_seconds, fields);
            }
        }
        if should_stop {
            break;
        }
    }
    Ok(())
}

fn append_upload_timing_fields(fields: &mut Value, timings: Option<&UploadTimings>) {
    let Some(timings) = timings else {
        return;
    };
    if let Value::Object(object) = fields {
        object.insert(
            "create_upload_url_wall_time_millis".to_string(),
            json!(timings.create_upload_url_wall_time_millis),
        );
        object.insert(
            "signed_upload_wall_time_millis".to_string(),
            json!(timings.signed_upload_wall_time_millis),
        );
        object.insert(
            "put_asset_wall_time_millis".to_string(),
            json!(timings.put_asset_wall_time_millis),
        );
        object.insert(
            "upload_status_wall_time_millis".to_string(),
            json!(timings.upload_status_wall_time_millis),
        );
        object.insert(
            "upload_status_polls".to_string(),
            json!(timings.upload_status_polls),
        );
        object.insert(
            "upload_total_wall_time_millis".to_string(),
            json!(timings.total_wall_time_millis),
        );
    }
}

fn upload_error_should_fail_record(error: &MonitorError) -> bool {
    match error {
        MonitorError::CommandFailed { message, .. } => [
            "failed to read verified HEIC",
            "verified HEIC is empty",
            "verified HEIC filename is missing",
            "verified HEIC path must end in .heic",
            "HEIC size mismatch",
            "HEIC SHA-256 mismatch",
        ]
        .iter()
        .any(|needle| message.contains(needle)),
        _ => false,
    }
}

fn run_upload_proof_child_with_timeout(
    manifest_path: &Path,
    asset_id: &str,
    session_path: &Path,
    timeout_seconds: u64,
) -> Result<UploadProofChildOutput, MonitorError> {
    let executable = env::current_exe().map_err(|source| MonitorError::CommandIo {
        program: "icloudpd-optimizer",
        source,
    })?;
    run_upload_proof_child_executable_with_timeout(
        &executable,
        manifest_path,
        asset_id,
        session_path,
        timeout_seconds,
    )
}

fn run_upload_proof_direct_child_with_timeout(
    asset_id: &str,
    heic: &HeicVerificationProof,
    destination: &CloudKitLibraryDestination,
    session_path: &Path,
    timeout_seconds: u64,
) -> Result<UploadProofChildOutput, MonitorError> {
    let executable = env::current_exe().map_err(|source| MonitorError::CommandIo {
        program: "icloudpd-optimizer",
        source,
    })?;
    run_upload_proof_direct_child_executable_with_timeout(
        &executable,
        asset_id,
        heic,
        destination,
        session_path,
        timeout_seconds,
    )
}

fn run_upload_proof_direct_child_executable_with_timeout(
    executable: &Path,
    asset_id: &str,
    heic: &HeicVerificationProof,
    destination: &CloudKitLibraryDestination,
    session_path: &Path,
    timeout_seconds: u64,
) -> Result<UploadProofChildOutput, MonitorError> {
    let mut command = Command::new(executable);
    command
        .args([
            "workflow",
            "upload-heic-proof-direct",
            "--asset-id",
            asset_id,
        ])
        .arg("--heic-path")
        .arg(&heic.heic_path)
        .arg("--heic-sha256")
        .arg(&heic.heic_sha256)
        .arg("--size-bytes")
        .arg(heic.size_bytes.to_string())
        .arg("--session")
        .arg(session_path)
        .arg("--database-scope")
        .arg(destination.database_scope.as_str())
        .arg("--zone-name")
        .arg(&destination.zone_name);

    let output = run_upload_child_with_timeout(asset_id, command, timeout_seconds)?;
    if !output.status.success() {
        return Err(MonitorError::CommandFailed {
            program: "icloudpd-optimizer",
            message: command_output_message(&output),
        });
    }
    parse_upload_proof_child_output(&output.stdout)
}

fn run_upload_proof_child_executable_with_timeout(
    executable: &Path,
    manifest_path: &Path,
    asset_id: &str,
    session_path: &Path,
    timeout_seconds: u64,
) -> Result<UploadProofChildOutput, MonitorError> {
    let mut command = Command::new(executable);
    command
        .args(["workflow", "upload-heic-proof", "--manifest"])
        .arg(manifest_path)
        .arg("--asset-id")
        .arg(asset_id)
        .arg("--session")
        .arg(session_path);

    let output = run_upload_child_with_timeout(asset_id, command, timeout_seconds)?;
    if !output.status.success() {
        return Err(MonitorError::CommandFailed {
            program: "icloudpd-optimizer",
            message: command_output_message(&output),
        });
    }
    parse_upload_proof_child_output(&output.stdout)
}

fn original_asset_destination(
    record: &AssetRecord,
) -> Result<CloudKitLibraryDestination, MonitorError> {
    let value = record
        .proofs
        .get("original_asset")
        .ok_or_else(|| WorkflowError::MissingProof {
            asset_id: record.asset_id.clone(),
            proof_key: "original_asset".to_string(),
        })?;
    let original: OriginalAssetProof =
        serde_json::from_value(value.clone()).map_err(|source| WorkflowError::ProofDecode {
            asset_id: record.asset_id.clone(),
            proof_key: "original_asset",
            source,
        })?;
    Ok(CloudKitLibraryDestination {
        database_scope: original.database_scope,
        zone_name: original.zone_name,
    })
}

#[derive(Debug)]
struct UploadProofChildOutput {
    proof: UploadProof,
    timings: Option<UploadTimings>,
}

fn parse_upload_proof_child_output(stdout: &[u8]) -> Result<UploadProofChildOutput, MonitorError> {
    let value: Value =
        serde_json::from_slice(stdout).map_err(|source| MonitorError::CommandFailed {
            program: "icloudpd-optimizer",
            message: format!("failed to decode upload proof JSON: {source}"),
        })?;
    let timings = value
        .get("upload_timings")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|source| MonitorError::CommandFailed {
            program: "icloudpd-optimizer",
            message: format!("failed to decode upload timing JSON: {source}"),
        })?;
    let proof: UploadProof =
        serde_json::from_value(value).map_err(|source| MonitorError::CommandFailed {
            program: "icloudpd-optimizer",
            message: format!("failed to decode upload proof JSON: {source}"),
        })?;
    Ok(UploadProofChildOutput { proof, timings })
}

fn run_upload_child_with_timeout(
    asset_id: &str,
    command: Command,
    timeout_seconds: u64,
) -> Result<Output, MonitorError> {
    run_icloudpd_child_with_timeout(command, timeout_seconds, || {
        MonitorError::UploadWorkflowTimeout {
            asset_id: asset_id.to_string(),
            timeout_seconds,
        }
    })
}

fn record_local_mirrors(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    active_lifecycle_asset_ids: &[String],
) -> Result<(), MonitorError> {
    let asset_ids = asset_ids_matching(manifest, config.max_lifecycle_per_scan, |record| {
        active_lifecycle_allows(Some(active_lifecycle_asset_ids), &record.asset_id)
            && record.state == State::UploadVerified
            && !record.proofs.contains_key("icloudpd_local_mirror")
    });
    let mirror_root = config.mirror_root.as_ref().unwrap_or(&config.download_root);
    for chunk in asset_ids.chunks(config.jobs.max(1)) {
        let manifest_snapshot = manifest.clone();
        let mirror_root = mirror_root.clone();
        let local_mirror_timeout_seconds = config.local_mirror_timeout_seconds;
        let outcomes = run_parallel_asset_job_chunk(chunk, move |asset_id| {
            let request =
                icloudpd_local_mirror_request(&mirror_root, &manifest_snapshot, &asset_id)?;
            ensure_icloudpd_local_mirror_with_timeout(
                &asset_id,
                local_mirror_timeout_seconds,
                request,
            )
        });
        let mut should_stop = false;
        let mut mirrored_asset_ids = Vec::new();
        for outcome in outcomes {
            match outcome.result {
                Ok(proof) => {
                    record_icloudpd_local_mirror_proof(manifest, &outcome.asset_id, proof)?;
                    summary.mirrors_recorded = summary.mirrors_recorded.saturating_add(1);
                    mirrored_asset_ids.push(outcome.asset_id);
                }
                Err(error) => {
                    should_stop |= matches!(error, MonitorError::LocalMirrorTimeout { .. });
                    record_monitor_failure(summary, error);
                }
            }
        }
        if !mirrored_asset_ids.is_empty() {
            checkpoint_manifest_state(state_store, manifest)?;
        }
        if should_stop {
            break;
        }
    }
    Ok(())
}

fn ensure_icloudpd_local_mirror_with_timeout(
    asset_id: &str,
    timeout_seconds: u64,
    request: IcloudpdLocalMirrorRequest,
) -> Result<IcloudpdLocalMirrorProof, MonitorError> {
    let executable = env::current_exe().map_err(|source| MonitorError::CommandIo {
        program: "icloudpd-optimizer",
        source,
    })?;
    let mut command = Command::new(executable);
    command
        .args([
            "workflow",
            "icloudpd-local-mirror-proof",
            "--uploaded-heic-asset-id",
            &request.uploaded_heic_asset_id,
            "--uploaded-heic-sha256",
            &request.uploaded_heic_sha256,
            "--uploaded-heic-path",
        ])
        .arg(&request.uploaded_heic_path)
        .arg("--size-bytes")
        .arg(request.size_bytes.to_string())
        .arg("--download-path")
        .arg(&request.icloudpd_download_path);

    let output = run_local_mirror_child_with_timeout(asset_id, command, timeout_seconds)?;
    if !output.status.success() {
        return Err(MonitorError::CommandFailed {
            program: "icloudpd-optimizer",
            message: command_output_message(&output),
        });
    }
    serde_json::from_slice(&output.stdout).map_err(|source| MonitorError::CommandFailed {
        program: "icloudpd-optimizer",
        message: format!("failed to decode local mirror proof JSON: {source}"),
    })
}

fn run_local_mirror_child_with_timeout(
    asset_id: &str,
    command: Command,
    timeout_seconds: u64,
) -> Result<Output, MonitorError> {
    run_icloudpd_child_with_timeout(command, timeout_seconds, || {
        MonitorError::LocalMirrorTimeout {
            asset_id: asset_id.to_string(),
            timeout_seconds,
        }
    })
}

fn run_icloudpd_child_with_timeout<F>(
    command: Command,
    timeout_seconds: u64,
    timeout_error: F,
) -> Result<Output, MonitorError>
where
    F: FnOnce() -> MonitorError,
{
    run_child_with_timeout(
        "icloudpd-optimizer",
        command,
        timeout_seconds,
        timeout_error,
    )
}

fn run_child_with_timeout<F>(
    program: &'static str,
    mut command: Command,
    timeout_seconds: u64,
    timeout_error: F,
) -> Result<Output, MonitorError>
where
    F: FnOnce() -> MonitorError,
{
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }

    let mut child = command
        .spawn()
        .map_err(|source| MonitorError::CommandIo { program, source })?;
    let stdout = child.stdout.take().ok_or_else(|| MonitorError::CommandIo {
        program,
        source: io::Error::other("child stdout was not piped"),
    })?;
    let stderr = child.stderr.take().ok_or_else(|| MonitorError::CommandIo {
        program,
        source: io::Error::other("child stderr was not piped"),
    })?;
    let stdout_reader = spawn_child_pipe_reader(stdout);
    let stderr_reader = spawn_child_pipe_reader(stderr);
    let timeout = Duration::from_secs(timeout_seconds);
    let started = Instant::now();
    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;

    loop {
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|source| MonitorError::CommandIo { program, source })?;
        }
        if stdout.is_none() {
            stdout = try_recv_child_pipe(program, "stdout", &stdout_reader)?;
        }
        if stderr.is_none() {
            stderr = try_recv_child_pipe(program, "stderr", &stderr_reader)?;
        }
        match (status, stdout.take(), stderr.take()) {
            (Some(status), Some(stdout), Some(stderr)) => {
                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            (pending_status, pending_stdout, pending_stderr) => {
                status = pending_status;
                stdout = pending_stdout;
                stderr = pending_stderr;
            }
        }
        if started.elapsed() >= timeout {
            kill_child_process_group(&mut child)
                .map_err(|source| MonitorError::CommandIo { program, source })?;
            thread::spawn(move || {
                let _ = child.wait();
            });
            return Err(timeout_error());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn spawn_child_pipe_reader<R>(mut pipe: R) -> mpsc::Receiver<io::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = pipe.read_to_end(&mut bytes).map(|_| bytes);
        let _ = sender.send(result);
    });
    receiver
}

fn try_recv_child_pipe(
    program: &'static str,
    stream: &'static str,
    receiver: &mpsc::Receiver<io::Result<Vec<u8>>>,
) -> Result<Option<Vec<u8>>, MonitorError> {
    match receiver.try_recv() {
        Ok(Ok(bytes)) => Ok(Some(bytes)),
        Ok(Err(source)) => Err(MonitorError::CommandIo { program, source }),
        Err(mpsc::TryRecvError::Empty) => Ok(None),
        Err(mpsc::TryRecvError::Disconnected) => Err(MonitorError::CommandIo {
            program,
            source: io::Error::other(format!("child {stream} reader disconnected")),
        }),
    }
}

#[cfg(unix)]
fn kill_child_process_group(child: &mut Child) -> io::Result<()> {
    let pid = child.id() as libc::pid_t;
    let result = unsafe { libc::kill(-pid, libc::SIGKILL) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(not(unix))]
fn kill_child_process_group(child: &mut Child) -> io::Result<()> {
    child.kill()
}

fn command_output_message(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if !stderr.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    };
    if detail.is_empty() {
        format!("exited with {}", output.status)
    } else {
        format!("exited with {}: {detail}", output.status)
    }
}

fn delete_original_assets(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    active_lifecycle_asset_ids: &[String],
) -> Result<(), MonitorError> {
    let session_path = required_path(&config.delete_session_path, "delete_session_path")?;
    let session = load_cloudkit_delete_session(session_path)?;
    let transport = ReqwestCloudKitDeleteTransport::new()?;
    let mut client = CloudKitDeleteClient::new(transport);
    delete_original_assets_with_client(
        config,
        state_store,
        manifest,
        summary,
        active_lifecycle_asset_ids,
        &session,
        &mut client,
    )?;
    Ok(())
}

fn is_upload_verified_delete_candidate(record: &AssetRecord) -> bool {
    record.state == State::UploadVerified && record.proofs.contains_key("icloudpd_local_mirror")
}

struct PreparedDeleteItem {
    raw_bytes: u64,
    heic_bytes: u64,
    prevalidated: PrevalidatedDelete,
}

struct ConfirmedDeleteItem {
    prepared: PreparedDeleteItem,
    outcome: CloudKitDeleteOutcome,
}

struct DeletePreflightFailure {
    asset_id: String,
    record_name: String,
    error: WorkflowError,
}

struct ReconciliationDeleteItem {
    raw_bytes: u64,
    heic_bytes: u64,
    reconciliation: DeleteReconciliation,
}

struct ConfirmedReconciliationItem {
    item: ReconciliationDeleteItem,
    outcome: CloudKitDeleteOutcome,
}

#[derive(Default)]
struct DeleteSubmissionResult {
    confirmed: Vec<ConfirmedDeleteItem>,
    attempted_deletes: usize,
    cloudkit_lookup_wall_time_millis: u64,
    cloudkit_modify_wall_time_millis: u64,
}

#[derive(Default)]
struct DeleteCommitTotals {
    recorded: u64,
    deleted_raw_bytes: u64,
    bytes_saved: u64,
    atomic_batch_commit_wall_time_micros: u64,
}

struct DeletePreparationBatch {
    prepared: Vec<PreparedDeleteItem>,
    changed_records: Vec<AssetRecord>,
    failures: Vec<MonitorError>,
}

struct DeletePreparationWindow {
    prepared: Vec<PreparedDeleteItem>,
    preparation_wall_time_millis: u64,
    atomic_batch_commit_wall_time_micros: u64,
}

#[derive(Default)]
struct DeleteReconciliationResult {
    remaining_asset_ids: Vec<String>,
    commit: DeleteCommitTotals,
    cloudkit_lookup_wall_time_millis: u64,
}

#[derive(Default)]
struct DeleteTimingTotals {
    preparation_wall_time_millis: u64,
    cloudkit_lookup_wall_time_millis: u64,
    cloudkit_modify_wall_time_millis: u64,
    atomic_batch_commit_wall_time_micros: u64,
    final_json_export_wall_time_millis: u64,
}

fn measure_delete_phase<T>(operation: impl FnOnce() -> T) -> (T, Duration) {
    let started = Instant::now();
    let result = operation();
    (result, started.elapsed())
}

struct DeletePreparationOutcome {
    prepared: Option<PreparedDeleteItem>,
    checkpoint_record: Option<AssetRecord>,
}

fn delete_original_assets_with_client<T: CloudKitDeleteTransport>(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    active_lifecycle_asset_ids: &[String],
    session: &CloudKitDeleteSession,
    client: &mut CloudKitDeleteClient<T>,
) -> Result<(), MonitorError> {
    let total_started = Instant::now();
    let asset_ids = delete_lifecycle_asset_ids(manifest, config, active_lifecycle_asset_ids);
    if asset_ids.is_empty() {
        return Ok(());
    }
    let window_size = delete_submission_window_size(config, asset_ids.len());
    log_monitor_event(
        "delete_batch_started",
        summary.started_unix_seconds,
        json!({
            "candidates": asset_ids.len(),
            "window_size": window_size,
        }),
    );

    let mut recorded = 0u64;
    let mut deleted_raw_bytes = 0u64;
    let mut bytes_saved = 0u64;
    let mut attempted_deletes = 0u64;
    let mut timings = DeleteTimingTotals::default();

    for (window_index, window_asset_ids) in asset_ids.chunks(window_size).enumerate() {
        let reconciliation = reconcile_delete_window(
            state_store,
            manifest,
            summary,
            window_asset_ids,
            session,
            client,
        )?;
        timings.cloudkit_lookup_wall_time_millis = timings
            .cloudkit_lookup_wall_time_millis
            .saturating_add(reconciliation.cloudkit_lookup_wall_time_millis);
        timings.atomic_batch_commit_wall_time_micros = timings
            .atomic_batch_commit_wall_time_micros
            .saturating_add(reconciliation.commit.atomic_batch_commit_wall_time_micros);
        recorded = recorded.saturating_add(reconciliation.commit.recorded);
        deleted_raw_bytes =
            deleted_raw_bytes.saturating_add(reconciliation.commit.deleted_raw_bytes);
        bytes_saved = bytes_saved.saturating_add(reconciliation.commit.bytes_saved);

        let preparation = process_delete_preparation_window(
            config,
            state_store,
            manifest,
            summary,
            &reconciliation.remaining_asset_ids,
            window_index,
        )?;
        timings.preparation_wall_time_millis = timings
            .preparation_wall_time_millis
            .saturating_add(preparation.preparation_wall_time_millis);
        timings.atomic_batch_commit_wall_time_micros = timings
            .atomic_batch_commit_wall_time_micros
            .saturating_add(preparation.atomic_batch_commit_wall_time_micros);
        let mut grouped = BTreeMap::<CloudKitLibraryDestination, Vec<PreparedDeleteItem>>::new();
        for item in preparation.prepared {
            let request = item.prevalidated.request();
            grouped
                .entry(CloudKitLibraryDestination {
                    database_scope: request.database_scope,
                    zone_name: request.zone_name.clone(),
                })
                .or_default()
                .push(item);
        }

        for items in grouped.into_values() {
            let submission = submit_prepared_delete_group(
                items,
                session,
                client,
                summary,
                DELETE_LIVE_RAW_MAX_AGE,
            );
            attempted_deletes =
                attempted_deletes.saturating_add(submission.attempted_deletes as u64);
            timings.cloudkit_lookup_wall_time_millis = timings
                .cloudkit_lookup_wall_time_millis
                .saturating_add(submission.cloudkit_lookup_wall_time_millis);
            timings.cloudkit_modify_wall_time_millis = timings
                .cloudkit_modify_wall_time_millis
                .saturating_add(submission.cloudkit_modify_wall_time_millis);
            if submission.confirmed.is_empty() {
                continue;
            }
            let commit = match stage_and_commit_confirmed_deletes(
                state_store,
                manifest,
                summary.started_unix_seconds,
                submission.confirmed,
            ) {
                Ok(commit) => commit,
                Err(error) => {
                    let correlation = new_monitor_failure_correlation(
                        summary.started_unix_seconds,
                        "delete_batch_commit_failed",
                    );
                    set_pending_monitor_failure_correlation(correlation.clone());
                    log_monitor_event(
                        "delete_batch_commit_failed",
                        summary.started_unix_seconds,
                        json!({
                            "error": error.to_string(),
                            "failure_id": correlation.failure_id,
                        }),
                    );
                    return Err(error);
                }
            };
            recorded = recorded.saturating_add(commit.recorded);
            deleted_raw_bytes = deleted_raw_bytes.saturating_add(commit.deleted_raw_bytes);
            bytes_saved = bytes_saved.saturating_add(commit.bytes_saved);
            timings.atomic_batch_commit_wall_time_micros = timings
                .atomic_batch_commit_wall_time_micros
                .saturating_add(commit.atomic_batch_commit_wall_time_micros);
        }
    }

    let (export_result, export_elapsed) = measure_delete_phase(|| state_store.export_json());
    export_result?;
    timings.final_json_export_wall_time_millis = export_elapsed.as_millis() as u64;
    summary.originals_deleted = summary.originals_deleted.saturating_add(recorded);
    summary.deleted_raw_bytes = summary.deleted_raw_bytes.saturating_add(deleted_raw_bytes);
    summary.bytes_saved = summary.bytes_saved.saturating_add(bytes_saved);
    let total_wall_time_millis = total_started.elapsed().as_millis() as u64;
    log_monitor_event(
        "delete_batch_finished",
        summary.started_unix_seconds,
        delete_batch_finished_fields(
            attempted_deletes,
            recorded,
            deleted_raw_bytes,
            bytes_saved,
            &timings,
            total_wall_time_millis,
        ),
    );
    Ok(())
}

fn delete_batch_finished_fields(
    attempted_deletes: u64,
    recorded_deletes: u64,
    deleted_raw_bytes: u64,
    bytes_saved: u64,
    timings: &DeleteTimingTotals,
    total_wall_time_millis: u64,
) -> Value {
    json!({
        "attempted_deletes": attempted_deletes,
        "recorded_deletes": recorded_deletes,
        "preparation_wall_time_millis": timings.preparation_wall_time_millis,
        "cloudkit_lookup_wall_time_millis": timings.cloudkit_lookup_wall_time_millis,
        "cloudkit_modify_wall_time_millis": timings.cloudkit_modify_wall_time_millis,
        "atomic_batch_commit_wall_time_micros": timings.atomic_batch_commit_wall_time_micros,
        "final_json_export_wall_time_millis": timings.final_json_export_wall_time_millis,
        "total_wall_time_millis": total_wall_time_millis,
        "deleted_raw_bytes": deleted_raw_bytes,
        "bytes_saved": bytes_saved,
    })
}

fn delete_submission_window_size(config: &MonitorConfig, queued_assets: usize) -> usize {
    config
        .jobs
        .clamp(1, CLOUDKIT_RECORDS_MODIFY_MAX_OPERATIONS)
        .min(queued_assets)
}

fn reconcile_delete_window<T: CloudKitDeleteTransport>(
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    asset_ids: &[String],
    session: &CloudKitDeleteSession,
    client: &mut CloudKitDeleteClient<T>,
) -> Result<DeleteReconciliationResult, MonitorError> {
    let mut result = DeleteReconciliationResult::default();
    let mut grouped = BTreeMap::<CloudKitLibraryDestination, Vec<ReconciliationDeleteItem>>::new();
    for asset_id in asset_ids {
        if manifest.get(asset_id)?.state != State::DeleteApproved {
            result.remaining_asset_ids.push(asset_id.clone());
            continue;
        }
        let reconciliation = match prepare_delete_reconciliation(manifest, asset_id) {
            Ok(reconciliation) => reconciliation,
            Err(error) => {
                record_monitor_failure(summary, MonitorError::Workflow(error));
                continue;
            }
        };
        let request = reconciliation.request();
        grouped
            .entry(CloudKitLibraryDestination {
                database_scope: request.database_scope,
                zone_name: request.zone_name.clone(),
            })
            .or_default()
            .push(ReconciliationDeleteItem {
                raw_bytes: raw_size_bytes(manifest, asset_id)?,
                heic_bytes: heic_size_bytes(manifest, asset_id)?,
                reconciliation,
            });
    }

    let mut confirmed = Vec::new();
    for items in grouped.into_values() {
        let batch_request = CloudKitDeleteBatchRequest {
            requests: items
                .iter()
                .map(|item| item.reconciliation.request().clone())
                .collect(),
        };
        let lookup_started = Instant::now();
        let lookup = match client.lookup_delete_states(session, &batch_request) {
            Ok(lookup) => lookup,
            Err(error) => {
                result.cloudkit_lookup_wall_time_millis = result
                    .cloudkit_lookup_wall_time_millis
                    .saturating_add(lookup_started.elapsed().as_millis() as u64);
                record_monitor_failure(summary, MonitorError::Upload(error));
                result.remaining_asset_ids.extend(
                    items
                        .iter()
                        .map(|item| item.reconciliation.asset_id().to_string()),
                );
                continue;
            }
        };
        result.cloudkit_lookup_wall_time_millis = result
            .cloudkit_lookup_wall_time_millis
            .saturating_add(lookup_started.elapsed().as_millis() as u64);

        let mut outcomes = lookup
            .confirmed_deleted
            .into_iter()
            .map(|outcome| (outcome.record_name.clone(), outcome))
            .collect::<BTreeMap<_, _>>();
        let unconfirmed = lookup
            .unconfirmed
            .into_iter()
            .map(|request| request.record_name)
            .collect::<BTreeSet<_>>();
        for item in items {
            let record_name = item.reconciliation.request().record_name.clone();
            if let Some(outcome) = outcomes.remove(&record_name) {
                confirmed.push(ConfirmedReconciliationItem { item, outcome });
            } else if unconfirmed.contains(&record_name) {
                result
                    .remaining_asset_ids
                    .push(item.reconciliation.asset_id().to_string());
            } else {
                return Err(MonitorError::CommandFailed {
                    program: "icloudpd-optimizer",
                    message: format!(
                        "CloudKit delete lookup omitted reconciliation result for {record_name}"
                    ),
                });
            }
        }
        if let Some(record_name) = outcomes.into_keys().next() {
            return Err(MonitorError::CommandFailed {
                program: "icloudpd-optimizer",
                message: format!(
                    "CloudKit delete lookup returned unrequested reconciliation outcome for {record_name}"
                ),
            });
        }
    }

    result.commit = stage_and_commit_reconciled_deletes(
        state_store,
        manifest,
        summary.started_unix_seconds,
        confirmed,
    )?;
    Ok(result)
}

fn stage_and_commit_reconciled_deletes(
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    scan_started_unix_seconds: u64,
    confirmed: Vec<ConfirmedReconciliationItem>,
) -> Result<DeleteCommitTotals, MonitorError> {
    if confirmed.is_empty() {
        return Ok(DeleteCommitTotals::default());
    }
    let mut staged = Manifest::new();
    for item in &confirmed {
        staged.upsert(manifest.get(item.item.reconciliation.asset_id())?.clone());
    }

    let mut changed_records = Vec::with_capacity(confirmed.len());
    let mut totals = DeleteCommitTotals::default();
    for confirmed_item in confirmed {
        let record = record_reconciled_delete_execution(
            &mut staged,
            confirmed_item.item.reconciliation,
            confirmed_item.outcome,
        )?;
        changed_records.push(record.clone());
        totals.recorded = totals.recorded.saturating_add(1);
        totals.deleted_raw_bytes = totals
            .deleted_raw_bytes
            .saturating_add(confirmed_item.item.raw_bytes);
        totals.bytes_saved = totals.bytes_saved.saturating_add(
            confirmed_item
                .item
                .raw_bytes
                .saturating_sub(confirmed_item.item.heic_bytes),
        );
    }
    let elapsed = state_store.persist_records_atomic(changed_records.iter())?;
    totals.atomic_batch_commit_wall_time_micros = elapsed.as_micros() as u64;
    for record in changed_records {
        manifest.upsert(record);
    }
    log_monitor_event(
        "asset_state_batch_committed",
        scan_started_unix_seconds,
        json!({
            "proof_stage": "delete_reconciliation",
            "atomic_batch_records": totals.recorded,
            "atomic_batch_commit_wall_time_micros": totals.atomic_batch_commit_wall_time_micros,
        }),
    );
    Ok(totals)
}

fn process_delete_preparation_window(
    config: &MonitorConfig,
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    asset_ids: &[String],
    window_index: usize,
) -> Result<DeletePreparationWindow, MonitorError> {
    let (preparation, preparation_elapsed) =
        measure_delete_phase(|| prepare_delete_items(config, manifest, asset_ids));
    for error in preparation.failures {
        record_monitor_failure(summary, error);
    }
    let preparation_wall_time_millis = preparation_elapsed.as_millis() as u64;
    let atomic_commit_micros = if preparation.changed_records.is_empty() {
        0
    } else {
        let elapsed = state_store.persist_records_atomic(preparation.changed_records.iter())?;
        for record in &preparation.changed_records {
            manifest.upsert(record.clone());
        }
        elapsed.as_micros() as u64
    };
    if !preparation.changed_records.is_empty() {
        log_monitor_event(
            "asset_state_batch_committed",
            summary.started_unix_seconds,
            json!({
                "proof_stage": "delete_approval",
                "atomic_batch_records": preparation.changed_records.len(),
                "atomic_batch_commit_wall_time_micros": atomic_commit_micros,
            }),
        );
    }
    log_monitor_event(
        "delete_window_prepared",
        summary.started_unix_seconds,
        json!({
            "window_index": window_index,
            "window_candidates": asset_ids.len(),
            "prepared_deletes": preparation.prepared.len(),
            "changed_approval_records": preparation.changed_records.len(),
            "preparation_wall_time_millis": preparation_wall_time_millis,
            "atomic_batch_commit_wall_time_micros": atomic_commit_micros,
        }),
    );
    Ok(DeletePreparationWindow {
        prepared: preparation.prepared,
        preparation_wall_time_millis,
        atomic_batch_commit_wall_time_micros: atomic_commit_micros,
    })
}

fn submit_prepared_delete_group<T: CloudKitDeleteTransport>(
    items: Vec<PreparedDeleteItem>,
    session: &CloudKitDeleteSession,
    client: &mut CloudKitDeleteClient<T>,
    summary: &mut MonitorScanSummary,
    max_live_raw_age: Duration,
) -> DeleteSubmissionResult {
    submit_prepared_delete_group_with_clock(
        items,
        session,
        client,
        summary,
        max_live_raw_age,
        SystemTime::now,
    )
}

fn submit_prepared_delete_group_with_clock<T, F>(
    items: Vec<PreparedDeleteItem>,
    session: &CloudKitDeleteSession,
    client: &mut CloudKitDeleteClient<T>,
    summary: &mut MonitorScanSummary,
    max_live_raw_age: Duration,
    mut now: F,
) -> DeleteSubmissionResult
where
    T: CloudKitDeleteTransport,
    F: FnMut() -> SystemTime,
{
    if items.is_empty() {
        return DeleteSubmissionResult::default();
    }

    let first_request = items[0].prevalidated.request();
    let database_scope = first_request.database_scope;
    let zone_name = first_request.zone_name.clone();
    let mut validation_failed = false;
    for item in &items {
        if let Err(error) = item
            .prevalidated
            .validate_live_raw_at(max_live_raw_age, now())
        {
            log_monitor_event(
                "delete_live_raw_validation_failed",
                summary.started_unix_seconds,
                json!({
                    "asset_id": item.prevalidated.asset_id(),
                    "record_name": item.prevalidated.request().record_name,
                    "max_age_seconds": max_live_raw_age.as_secs(),
                    "error": error.to_string(),
                }),
            );
            record_monitor_failure(summary, MonitorError::Workflow(error));
            validation_failed = true;
        }
    }
    if validation_failed {
        return DeleteSubmissionResult::default();
    }
    let batch_request = CloudKitDeleteBatchRequest {
        requests: items
            .iter()
            .map(|item| item.prevalidated.request().clone())
            .collect(),
    };
    let attempted_deletes = batch_request.requests.len();
    let modify_started = Instant::now();
    let outcomes = match client.delete_originals_batch_with_preflight(
        session,
        &batch_request,
        |_| {
            let request_time = now();
            let failures = items
                .iter()
                .filter_map(|item| {
                    item.prevalidated
                        .validate_freshness_at(max_live_raw_age, request_time)
                        .err()
                        .map(|error| DeletePreflightFailure {
                            asset_id: item.prevalidated.asset_id().to_string(),
                            record_name: item.prevalidated.request().record_name.clone(),
                            error,
                        })
                })
                .collect::<Vec<_>>();
            if failures.is_empty() {
                Ok(())
            } else {
                Err(failures)
            }
        },
    ) {
        Ok(outcomes) => outcomes,
        Err(CloudKitDeleteBatchSendError::Preflight(failures)) => {
            for failure in failures {
                log_monitor_event(
                    "delete_request_freshness_failed",
                    summary.started_unix_seconds,
                    json!({
                        "asset_id": failure.asset_id,
                        "record_name": failure.record_name,
                        "max_age_seconds": max_live_raw_age.as_secs(),
                        "error": failure.error.to_string(),
                    }),
                );
                record_monitor_failure(summary, MonitorError::Workflow(failure.error));
            }
            return DeleteSubmissionResult::default();
        }
        Err(CloudKitDeleteBatchSendError::InvalidRequest(error)) => {
            log_monitor_event(
                "delete_batch_request_rejected",
                summary.started_unix_seconds,
                json!({
                    "database_scope": database_scope.as_str(),
                    "zone_name": zone_name,
                    "error": error.to_string(),
                }),
            );
            record_monitor_failure(summary, MonitorError::Upload(error));
            return DeleteSubmissionResult::default();
        }
        Err(CloudKitDeleteBatchSendError::Remote(modify_error)) => {
            let cloudkit_modify_wall_time_millis = modify_started.elapsed().as_millis() as u64;
            let modify_error_message = modify_error.to_string();
            log_monitor_event(
                "delete_batch_cloudkit_ambiguous",
                summary.started_unix_seconds,
                json!({
                    "attempted_deletes": attempted_deletes,
                    "database_scope": database_scope.as_str(),
                    "zone_name": zone_name,
                    "error": modify_error_message,
                }),
            );
            let lookup_started = Instant::now();
            match client.lookup_delete_states(session, &batch_request) {
                Ok(reconciliation) => {
                    let cloudkit_lookup_wall_time_millis =
                        lookup_started.elapsed().as_millis() as u64;
                    let confirmed = reconciliation.confirmed_deleted.len();
                    let unconfirmed = reconciliation.unconfirmed.len();
                    log_monitor_event(
                        "delete_batch_reconciled",
                        summary.started_unix_seconds,
                        json!({
                            "attempted_deletes": attempted_deletes,
                            "confirmed_deleted": confirmed,
                            "unconfirmed": unconfirmed,
                            "database_scope": database_scope.as_str(),
                            "zone_name": zone_name,
                            "modify_error": modify_error_message,
                        }),
                    );
                    for request in &reconciliation.unconfirmed {
                        log_monitor_event(
                            "delete_reconciliation_unconfirmed",
                            summary.started_unix_seconds,
                            json!({
                                "record_name": request.record_name,
                                "database_scope": request.database_scope.as_str(),
                                "zone_name": request.zone_name,
                            }),
                        );
                    }
                    if unconfirmed > 0 {
                        record_monitor_failure(
                            summary,
                            format!(
                                "CloudKit delete remained unconfirmed for {unconfirmed} of {attempted_deletes} records after modify error: {modify_error_message}"
                            ),
                        );
                    }
                    return finish_delete_submission(
                        items,
                        reconciliation.confirmed_deleted,
                        attempted_deletes,
                        cloudkit_lookup_wall_time_millis,
                        cloudkit_modify_wall_time_millis,
                        summary,
                    );
                }
                Err(lookup_error) => {
                    let cloudkit_lookup_wall_time_millis =
                        lookup_started.elapsed().as_millis() as u64;
                    log_monitor_event(
                        "delete_batch_reconciliation_failed",
                        summary.started_unix_seconds,
                        json!({
                            "attempted_deletes": attempted_deletes,
                            "database_scope": database_scope.as_str(),
                            "zone_name": zone_name,
                            "modify_error": modify_error_message,
                            "lookup_error": lookup_error.to_string(),
                        }),
                    );
                    record_monitor_failure(
                        summary,
                        format!(
                            "CloudKit delete reconciliation failed after modify error ({modify_error_message}): {lookup_error}"
                        ),
                    );
                    return DeleteSubmissionResult {
                        attempted_deletes,
                        cloudkit_lookup_wall_time_millis,
                        cloudkit_modify_wall_time_millis,
                        ..DeleteSubmissionResult::default()
                    };
                }
            }
        }
    };

    finish_delete_submission(
        items,
        outcomes,
        attempted_deletes,
        0,
        modify_started.elapsed().as_millis() as u64,
        summary,
    )
}

fn finish_delete_submission(
    items: Vec<PreparedDeleteItem>,
    outcomes: Vec<CloudKitDeleteOutcome>,
    attempted_deletes: usize,
    cloudkit_lookup_wall_time_millis: u64,
    cloudkit_modify_wall_time_millis: u64,
    summary: &mut MonitorScanSummary,
) -> DeleteSubmissionResult {
    let confirmed = match pair_confirmed_delete_outcomes(items, outcomes) {
        Ok(confirmed) => confirmed,
        Err(error) => {
            log_monitor_event(
                "delete_batch_outcome_pairing_failed",
                summary.started_unix_seconds,
                json!({
                    "error": error.to_string(),
                }),
            );
            record_monitor_failure(summary, error);
            Vec::new()
        }
    };
    DeleteSubmissionResult {
        confirmed,
        attempted_deletes,
        cloudkit_lookup_wall_time_millis,
        cloudkit_modify_wall_time_millis,
    }
}

fn pair_confirmed_delete_outcomes(
    items: Vec<PreparedDeleteItem>,
    outcomes: Vec<CloudKitDeleteOutcome>,
) -> Result<Vec<ConfirmedDeleteItem>, MonitorError> {
    let mut outcomes_by_record_name = BTreeMap::new();
    for outcome in outcomes {
        let record_name = outcome.record_name.clone();
        if outcomes_by_record_name
            .insert(record_name.clone(), outcome)
            .is_some()
        {
            return Err(MonitorError::CommandFailed {
                program: "icloudpd-optimizer",
                message: format!("duplicate confirmed CloudKit delete outcome for {record_name}"),
            });
        }
    }

    let mut confirmed = Vec::new();
    for prepared in items {
        let record_name = prepared.prevalidated.request().record_name.clone();
        if let Some(outcome) = outcomes_by_record_name.remove(&record_name) {
            confirmed.push(ConfirmedDeleteItem { prepared, outcome });
        }
    }
    if let Some(record_name) = outcomes_by_record_name.into_keys().next() {
        return Err(MonitorError::CommandFailed {
            program: "icloudpd-optimizer",
            message: format!("confirmed CloudKit delete outcome was not requested: {record_name}"),
        });
    }
    Ok(confirmed)
}

fn stage_and_commit_confirmed_deletes(
    state_store: &AssetStateStore,
    manifest: &mut Manifest,
    scan_started_unix_seconds: u64,
    confirmed: Vec<ConfirmedDeleteItem>,
) -> Result<DeleteCommitTotals, MonitorError> {
    if confirmed.is_empty() {
        return Ok(DeleteCommitTotals::default());
    }

    let mut staged = Manifest::new();
    for item in &confirmed {
        staged.upsert(manifest.get(item.prepared.prevalidated.asset_id())?.clone());
    }
    let mut changed_records = Vec::with_capacity(confirmed.len());
    let mut totals = DeleteCommitTotals::default();
    for confirmed_item in confirmed {
        let asset_id = confirmed_item.prepared.prevalidated.asset_id().to_string();
        let record = record_prevalidated_delete_execution(
            &mut staged,
            confirmed_item.prepared.prevalidated,
            confirmed_item.outcome,
        )?;
        if record.state != State::Deleted {
            return Err(MonitorError::CommandFailed {
                program: "icloudpd-optimizer",
                message: format!("confirmed delete did not transition {asset_id} to deleted"),
            });
        }
        changed_records.push(record.clone());
        totals.recorded = totals.recorded.saturating_add(1);
        totals.deleted_raw_bytes = totals
            .deleted_raw_bytes
            .saturating_add(confirmed_item.prepared.raw_bytes);
        totals.bytes_saved = totals.bytes_saved.saturating_add(
            confirmed_item
                .prepared
                .raw_bytes
                .saturating_sub(confirmed_item.prepared.heic_bytes),
        );
    }

    let elapsed = state_store.persist_records_atomic(changed_records.iter())?;
    totals.atomic_batch_commit_wall_time_micros = elapsed.as_micros() as u64;
    for record in changed_records {
        manifest.upsert(record);
    }
    log_monitor_event(
        "asset_state_batch_committed",
        scan_started_unix_seconds,
        json!({
            "proof_stage": "delete_execution",
            "state": State::Deleted.as_str(),
            "atomic_batch_records": totals.recorded,
            "atomic_batch_commit_wall_time_micros": totals.atomic_batch_commit_wall_time_micros,
        }),
    );
    Ok(totals)
}

fn delete_lifecycle_asset_ids(
    manifest: &Manifest,
    config: &MonitorConfig,
    active_lifecycle_asset_ids: &[String],
) -> Vec<String> {
    let mut asset_ids = asset_ids_matching(manifest, config.max_lifecycle_per_scan, |record| {
        active_lifecycle_allows(Some(active_lifecycle_asset_ids), &record.asset_id)
            && is_upload_verified_delete_candidate(record)
    });
    asset_ids.extend(asset_ids_matching(
        manifest,
        config
            .max_lifecycle_per_scan
            .saturating_sub(asset_ids.len()),
        |record| {
            active_lifecycle_allows(Some(active_lifecycle_asset_ids), &record.asset_id)
                && matches!(record.state, State::DeleteEligible | State::DeleteApproved)
        },
    ));
    asset_ids
}

fn prepare_delete_items(
    config: &MonitorConfig,
    manifest: &Manifest,
    asset_ids: &[String],
) -> DeletePreparationBatch {
    let mut batch = DeletePreparationBatch {
        prepared: Vec::new(),
        changed_records: Vec::new(),
        failures: Vec::new(),
    };
    let worker_count = delete_prepare_worker_count(config, asset_ids.len());
    if worker_count == 0 {
        return batch;
    }

    for chunk in asset_ids.chunks(worker_count) {
        let mut handles = Vec::with_capacity(chunk.len());
        for asset_id in chunk {
            let asset_id = asset_id.clone();
            let delete_operator = config.delete_operator.clone();
            let snapshot = match manifest.snapshot_record(&asset_id) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    batch.failures.push(MonitorError::Manifest(error));
                    continue;
                }
            };
            handles.push((
                asset_id.clone(),
                thread::spawn(move || {
                    prepare_delete_item_snapshot(&delete_operator, snapshot, &asset_id)
                }),
            ));
        }

        for (asset_id, handle) in handles {
            match handle.join() {
                Ok(Ok(outcome)) => {
                    if let Some(record) = outcome.checkpoint_record {
                        batch.changed_records.push(record);
                    }
                    if let Some(item) = outcome.prepared {
                        batch.prepared.push(item);
                    }
                }
                Ok(Err(error)) => batch.failures.push(error),
                Err(_) => batch.failures.push(MonitorError::CommandFailed {
                    program: "icloudpd-optimizer",
                    message: format!("delete preparation worker panicked for {asset_id}"),
                }),
            }
        }
    }

    batch
}

fn delete_prepare_worker_count(config: &MonitorConfig, queued_assets: usize) -> usize {
    config.jobs.max(1).min(queued_assets)
}

fn prepare_delete_item_snapshot(
    delete_operator: &str,
    mut snapshot: Manifest,
    asset_id: &str,
) -> Result<DeletePreparationOutcome, MonitorError> {
    let (prepared, changed) = prepare_delete_item(delete_operator, &mut snapshot, asset_id)?;
    let checkpoint_record = if changed {
        Some(snapshot.get(asset_id)?.clone())
    } else {
        None
    };
    Ok(DeletePreparationOutcome {
        prepared,
        checkpoint_record,
    })
}

fn prepare_delete_item(
    delete_operator: &str,
    manifest: &mut Manifest,
    asset_id: &str,
) -> Result<(Option<PreparedDeleteItem>, bool), MonitorError> {
    let mut changed = false;
    if manifest.get(asset_id)?.state == State::UploadVerified {
        mark_delete_eligible(manifest, asset_id)?;
        changed = true;
    }
    if manifest.get(asset_id)?.state == State::DeleteEligible {
        approve_delete(manifest, asset_id, delete_operator)?;
        changed = true;
    }
    if manifest.get(asset_id)?.state != State::DeleteApproved {
        return Ok((None, changed));
    }
    let raw_bytes = raw_size_bytes(manifest, asset_id)?;
    let heic_bytes = heic_size_bytes(manifest, asset_id)?;
    let prevalidated = prevalidate_approved_original_delete(manifest, asset_id)?;
    Ok((
        Some(PreparedDeleteItem {
            raw_bytes,
            heic_bytes,
            prevalidated,
        }),
        changed,
    ))
}

fn pending_conversion_count(manifest: &Manifest, config: &MonitorConfig) -> usize {
    manifest
        .records()
        .values()
        .filter(|record| record.state == State::NasVerified)
        .filter(|record| !config.full_lifecycle || record.proofs.contains_key("original_asset"))
        .count()
}

fn pending_lifecycle_count(manifest: &Manifest) -> usize {
    manifest
        .records()
        .values()
        .filter(|record| is_lifecycle_candidate(record))
        .count()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LifecycleAdmissionBudget {
    max_slots: usize,
    occupied_slots: usize,
}

impl LifecycleAdmissionBudget {
    fn for_scan(manifest: &Manifest, max_lifecycle_per_scan: usize) -> Self {
        let marker_reservations = manifest
            .records()
            .values()
            .filter(|record| valid_adjusted_source_marker_reservation(record))
            .count();
        Self {
            max_slots: max_lifecycle_per_scan,
            occupied_slots: pending_lifecycle_count(manifest).saturating_add(marker_reservations),
        }
    }

    fn remaining_slots(self) -> usize {
        self.max_slots.saturating_sub(self.occupied_slots)
    }

    fn consume(&mut self) -> bool {
        if self.occupied_slots >= self.max_slots {
            return false;
        }
        self.occupied_slots = self.occupied_slots.saturating_add(1);
        true
    }

    fn release(&mut self, slots: usize) {
        self.occupied_slots = self.occupied_slots.saturating_sub(slots);
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct StartupDeleteAudit {
    upload_verified_missing_mirror: usize,
    upload_verified_with_mirror: usize,
    delete_eligible: usize,
    delete_approved: usize,
}

impl StartupDeleteAudit {
    fn uploaded_not_deleted_total(self) -> usize {
        self.upload_verified_missing_mirror
            .saturating_add(self.upload_verified_with_mirror)
            .saturating_add(self.delete_eligible)
            .saturating_add(self.delete_approved)
    }
}

fn startup_delete_audit(manifest: &Manifest) -> StartupDeleteAudit {
    let mut audit = StartupDeleteAudit::default();
    for record in manifest.records().values() {
        match record.state {
            State::UploadVerified if record.proofs.contains_key("icloudpd_local_mirror") => {
                audit.upload_verified_with_mirror =
                    audit.upload_verified_with_mirror.saturating_add(1);
            }
            State::UploadVerified => {
                audit.upload_verified_missing_mirror =
                    audit.upload_verified_missing_mirror.saturating_add(1);
            }
            State::DeleteEligible => {
                audit.delete_eligible = audit.delete_eligible.saturating_add(1);
            }
            State::DeleteApproved => {
                audit.delete_approved = audit.delete_approved.saturating_add(1);
            }
            _ => {}
        }
    }
    audit
}

fn startup_delete_audit_fields(
    audit: &StartupDeleteAudit,
    active_lifecycle_capacity: usize,
) -> serde_json::Value {
    json!({
        "uploaded_not_deleted_total": audit.uploaded_not_deleted_total(),
        "upload_verified_missing_mirror": audit.upload_verified_missing_mirror,
        "upload_verified_with_mirror": audit.upload_verified_with_mirror,
        "delete_eligible": audit.delete_eligible,
        "delete_approved": audit.delete_approved,
        "active_lifecycle_capacity": active_lifecycle_capacity,
    })
}

fn new_monitor_work_skip_reason(
    had_lifecycle_pending_at_start: bool,
    rolling_lifecycle: bool,
    active_lifecycle_count: usize,
    max_lifecycle_per_scan: usize,
) -> Option<&'static str> {
    if had_lifecycle_pending_at_start && !rolling_lifecycle {
        return Some("lifecycle_pending_at_scan_start");
    }
    if rolling_lifecycle
        && max_lifecycle_per_scan > 0
        && active_lifecycle_count >= max_lifecycle_per_scan
    {
        return Some("rolling_lifecycle_active_queue_full");
    }
    None
}

fn refresh_active_lifecycle_ids_after_discovery(
    config: &MonitorConfig,
    manifest: &Manifest,
    active_lifecycle_ids: &mut Vec<String>,
) {
    if config.full_lifecycle && (config.rolling_lifecycle || active_lifecycle_ids.is_empty()) {
        *active_lifecycle_ids = active_lifecycle_asset_ids_for_config(config, manifest);
    }
}

fn ensure_scan_root_access(path: &Path, _timeout_seconds: u64) -> Result<(), MonitorError> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let c_path =
            CString::new(path.as_os_str().as_bytes()).map_err(|_| MonitorError::InvalidConfig {
                message: format!(
                    "scan root path contains an interior NUL byte: {}",
                    path.display()
                ),
            })?;
        let status = unsafe { libc::access(c_path.as_ptr(), libc::R_OK | libc::X_OK) };
        if status != 0 {
            return Err(MonitorError::DownloadRootAccess {
                path: path.to_path_buf(),
                source: io::Error::last_os_error(),
            });
        }
    }
    #[cfg(target_os = "macos")]
    ensure_macos_scan_root_enumerable(path, _timeout_seconds)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn ensure_macos_scan_root_enumerable(
    path: &Path,
    timeout_seconds: u64,
) -> Result<(), MonitorError> {
    ensure_macos_scan_root_enumerable_with_probe(path, timeout_seconds, |path| {
        run_scan_root_preflight_probe(&path)
    })
}

#[cfg(target_os = "macos")]
fn ensure_macos_scan_root_enumerable_with_probe(
    path: &Path,
    timeout_seconds: u64,
    probe: impl FnOnce(PathBuf) -> Result<(), MonitorError> + Send + 'static,
) -> Result<(), MonitorError> {
    let path = path.to_path_buf();
    let (sender, receiver) = mpsc::channel();
    thread::spawn({
        let path = path.clone();
        move || {
            let _ = sender.send(probe(path));
        }
    });
    let timeout = Duration::from_secs(timeout_seconds);

    match receiver.recv_timeout(timeout) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(MonitorError::DownloadRootPreflight {
            path,
            message: format!("macOS directory preflight failed: {error}"),
        }),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(MonitorError::DownloadRootPreflight {
            path,
            message: format!(
                "macOS directory preflight timed out after {} seconds",
                timeout.as_secs()
            ),
        }),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(MonitorError::DownloadRootPreflight {
            path,
            message: "macOS directory preflight worker exited without a result".to_string(),
        }),
    }
}

pub fn run_scan_root_preflight_probe(path: &Path) -> Result<(), MonitorError> {
    let mut entries = fs::read_dir(path).map_err(|source| MonitorError::ReadDir {
        path: path.to_path_buf(),
        source,
    })?;
    if let Some(entry) = entries.next() {
        entry.map_err(|source| MonitorError::ReadDirEntry {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn log_monitor_event(event: &str, scan_started_unix_seconds: u64, fields: serde_json::Value) {
    eprintln!(
        "{}",
        json!({
            "event": event,
            "scan_started_unix_seconds": scan_started_unix_seconds,
            "at_unix_seconds": current_unix_seconds(),
            "fields": fields,
        })
    );
}

fn monitor_failure_event(
    error: &MonitorError,
    at_unix_seconds: u64,
    correlation: Option<&MonitorFailureCorrelation>,
) -> serde_json::Value {
    let mut event = json!({
        "event": "monitor_failed",
        "at_unix_seconds": at_unix_seconds,
        "fields": {
            "error": error.to_string(),
        },
    });
    if let Some(correlation) = correlation {
        event["fields"]["failure_id"] = json!(correlation.failure_id);
        event["fields"]["scan_started_unix_seconds"] = json!(correlation.scan_started_unix_seconds);
    }
    event
}

pub fn log_monitor_failure_event(error: &MonitorError) {
    let correlation = take_pending_monitor_failure_correlation();
    eprintln!(
        "{}",
        monitor_failure_event(error, current_unix_seconds(), correlation.as_ref())
    );
}

#[derive(Clone, Debug)]
struct MonitorFailureCorrelation {
    failure_id: String,
    scan_started_unix_seconds: u64,
}

fn new_monitor_failure_correlation(
    scan_started_unix_seconds: u64,
    stage_event: &'static str,
) -> MonitorFailureCorrelation {
    let sequence = MONITOR_FAILURE_SEQUENCE
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    MonitorFailureCorrelation {
        failure_id: format!(
            "{}:{scan_started_unix_seconds}:{stage_event}:{sequence}",
            std::process::id()
        ),
        scan_started_unix_seconds,
    }
}

fn set_pending_monitor_failure_correlation(correlation: MonitorFailureCorrelation) {
    PENDING_MONITOR_FAILURE_CORRELATION.with(|pending| {
        *pending.borrow_mut() = Some(correlation);
    });
}

fn take_pending_monitor_failure_correlation() -> Option<MonitorFailureCorrelation> {
    PENDING_MONITOR_FAILURE_CORRELATION.with(|pending| pending.borrow_mut().take())
}

fn clear_pending_monitor_failure_correlation() {
    PENDING_MONITOR_FAILURE_CORRELATION.with(|pending| {
        pending.borrow_mut().take();
    });
}

fn asset_ids_matching(
    manifest: &Manifest,
    limit: usize,
    predicate: impl Fn(&AssetRecord) -> bool,
) -> Vec<String> {
    manifest
        .records()
        .values()
        .filter(|record| predicate(record))
        .take(limit)
        .map(|record| record.asset_id.clone())
        .collect()
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct OriginalAssetResolverRetryAdmission {
    interrupted_retries_requeued: usize,
    total_failed_resolver_backlog: usize,
    available_lifecycle_capacity: usize,
    retry_admission_limit: usize,
    age_eligible_before: usize,
    recovered_now: usize,
    age_eligible_remaining: usize,
}

impl OriginalAssetResolverRetryAdmission {
    fn manifest_changed(self) -> bool {
        self.interrupted_retries_requeued > 0 || self.recovered_now > 0
    }
}

struct BoundedOldest<T> {
    limit: usize,
    selected: BinaryHeap<T>,
}

impl<T: Ord> BoundedOldest<T> {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            selected: BinaryHeap::new(),
        }
    }

    fn consider(&mut self, candidate: T) {
        if self.limit == 0 {
            return;
        }
        if self.selected.len() < self.limit {
            self.selected.push(candidate);
            return;
        }
        if self
            .selected
            .peek()
            .is_some_and(|newest_selected| candidate < *newest_selected)
        {
            self.selected.pop();
            self.selected.push(candidate);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.selected.len()
    }

    fn into_oldest(self) -> Vec<T> {
        self.selected.into_sorted_vec()
    }
}

#[derive(Debug)]
struct OriginalAssetResolverRetryCandidate<'a> {
    failure_timestamp: (u64, u32),
    asset_id: &'a str,
    retry_state: State,
}

impl PartialEq for OriginalAssetResolverRetryCandidate<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.failure_timestamp == other.failure_timestamp && self.asset_id == other.asset_id
    }
}

impl Eq for OriginalAssetResolverRetryCandidate<'_> {}

impl PartialOrd for OriginalAssetResolverRetryCandidate<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OriginalAssetResolverRetryCandidate<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.failure_timestamp
            .cmp(&other.failure_timestamp)
            .then_with(|| self.asset_id.cmp(other.asset_id))
    }
}

#[cfg(test)]
fn recover_original_asset_resolver_retries(
    manifest: &mut Manifest,
    max_lifecycle_per_scan: usize,
    max_original_resolver_retries_per_scan: usize,
    original_resolver_retry_min_age_seconds: u64,
    current_unix_seconds: u64,
) -> Result<OriginalAssetResolverRetryAdmission, ManifestError> {
    let mut lifecycle_budget = LifecycleAdmissionBudget::for_scan(manifest, max_lifecycle_per_scan);
    recover_original_asset_resolver_retries_with_budget(
        manifest,
        &mut lifecycle_budget,
        max_original_resolver_retries_per_scan,
        original_resolver_retry_min_age_seconds,
        current_unix_seconds,
    )
}

fn recover_original_asset_resolver_retries_with_budget(
    manifest: &mut Manifest,
    lifecycle_budget: &mut LifecycleAdmissionBudget,
    max_original_resolver_retries_per_scan: usize,
    original_resolver_retry_min_age_seconds: u64,
    current_unix_seconds: u64,
) -> Result<OriginalAssetResolverRetryAdmission, ManifestError> {
    let interrupted_retries_requeued = manifest
        .requeue_interrupted_retries_as_failed(interrupted_original_asset_resolver_retry_record);
    lifecycle_budget.release(interrupted_retries_requeued);
    let available_lifecycle_capacity = lifecycle_budget.remaining_slots();
    let retry_admission_limit =
        available_lifecycle_capacity.min(max_original_resolver_retries_per_scan);
    let mut total_failed_resolver_backlog = 0;
    let mut age_eligible_before = 0;
    let mut oldest_eligible = BoundedOldest::new(retry_admission_limit);
    for record in manifest.records().values() {
        if !failed_original_asset_resolver_record(record) {
            continue;
        }
        total_failed_resolver_backlog += 1;
        let Some(retry_state) = original_asset_resolver_retry_state(record) else {
            continue;
        };
        let Some(failure_timestamp) = record
            .failures
            .last()
            .and_then(|failure| parse_monitor_timestamp(&failure.recorded_at))
        else {
            continue;
        };
        if !monitor_timestamp_is_at_least_age(
            failure_timestamp,
            original_resolver_retry_min_age_seconds,
            current_unix_seconds,
        ) {
            continue;
        }
        age_eligible_before += 1;
        oldest_eligible.consider(OriginalAssetResolverRetryCandidate {
            failure_timestamp,
            asset_id: &record.asset_id,
            retry_state,
        });
    }

    if retry_admission_limit == 0 {
        return Ok(OriginalAssetResolverRetryAdmission {
            interrupted_retries_requeued,
            total_failed_resolver_backlog,
            available_lifecycle_capacity,
            retry_admission_limit,
            age_eligible_before,
            recovered_now: 0,
            age_eligible_remaining: age_eligible_before,
        });
    }

    let selected = oldest_eligible
        .into_oldest()
        .into_iter()
        .map(|candidate| (candidate.asset_id.to_string(), candidate.retry_state))
        .collect::<Vec<_>>();
    let mut recovered_now = 0;
    for (asset_id, retry_state) in selected {
        manifest.recover_failed_for_retry(&asset_id, retry_state)?;
        let consumed = lifecycle_budget.consume();
        debug_assert!(consumed, "selected retry must have a lifecycle slot");
        recovered_now += 1;
    }

    Ok(OriginalAssetResolverRetryAdmission {
        interrupted_retries_requeued,
        total_failed_resolver_backlog,
        available_lifecycle_capacity,
        retry_admission_limit,
        age_eligible_before,
        recovered_now,
        age_eligible_remaining: age_eligible_before.saturating_sub(recovered_now),
    })
}

const ORIGINAL_ASSET_RESOLVER_DOWNSTREAM_PROOFS: [&str; 7] = [
    "original_asset",
    "upload",
    "icloudpd_local_mirror",
    "delete_eligibility",
    "delete_approval",
    "delete",
    "uploaded_heic_delete",
];

fn interrupted_original_asset_resolver_retry_record(record: &AssetRecord) -> bool {
    record
        .failures
        .last()
        .is_some_and(|failure| failure.stage == "original_asset_resolve")
        && !original_asset_resolver_record_has_downstream_proof(record)
}

fn original_asset_resolver_record_has_downstream_proof(record: &AssetRecord) -> bool {
    ORIGINAL_ASSET_RESOLVER_DOWNSTREAM_PROOFS
        .iter()
        .any(|proof_key| record.proofs.contains_key(*proof_key))
}

fn failed_original_asset_resolver_record(record: &AssetRecord) -> bool {
    record.state == State::Failed
        && record
            .failures
            .last()
            .is_some_and(|failure| failure.stage == "original_asset_resolve")
}

fn original_asset_resolver_retry_state(record: &AssetRecord) -> Option<State> {
    if record.state != State::Failed
        || record
            .failures
            .last()
            .is_none_or(|failure| failure.stage != "original_asset_resolve")
        || original_asset_resolver_record_has_downstream_proof(record)
        || !original_asset_resolver_source_proofs_are_valid(record)
    {
        return None;
    }

    Some(if record.proofs.contains_key("heic") {
        State::ConversionVerified
    } else if record.proofs.contains_key("conversion") {
        State::Converted
    } else {
        State::NasVerified
    })
}

fn parse_monitor_timestamp(timestamp: &str) -> Option<(u64, u32)> {
    let (seconds, fractional) = timestamp.strip_suffix('Z')?.split_once('.')?;
    if fractional.is_empty() || fractional.len() > 9 {
        return None;
    }
    let fractional_digits = fractional.len() as u32;
    let seconds = seconds.parse().ok()?;
    let fractional: u32 = fractional.parse().ok()?;
    let scale = 10_u32.pow(9_u32.saturating_sub(fractional_digits));
    Some((seconds, fractional.checked_mul(scale)?))
}

fn monitor_timestamp_is_at_least_age(
    timestamp: (u64, u32),
    min_age_seconds: u64,
    current_unix_seconds: u64,
) -> bool {
    let Some(eligible_seconds) = timestamp.0.checked_add(min_age_seconds) else {
        return false;
    };
    (eligible_seconds, timestamp.1) <= (current_unix_seconds, 0)
}

fn original_asset_resolver_source_proofs_are_valid(record: &AssetRecord) -> bool {
    let Some(nas) = record
        .proofs
        .get("nas")
        .and_then(|proof| serde_json::from_value::<NasRawProof>(proof.clone()).ok())
    else {
        return false;
    };
    let Some(source_age) = record
        .proofs
        .get("source_age")
        .and_then(|proof| serde_json::from_value::<SourceAgeProof>(proof.clone()).ok())
    else {
        return false;
    };
    let min_age_floor_seconds = MIN_RAW_AGE_DAYS.saturating_mul(24 * 60 * 60);
    let relative_path_is_safe = !nas.relative_path.as_os_str().is_empty()
        && nas
            .relative_path
            .components()
            .all(|component| matches!(component, Component::Normal(_)));

    !nas.canonical_path.as_os_str().is_empty()
        && relative_path_is_safe
        && record.raw_path == nas.canonical_path
        && nas.size_bytes > 0
        && !nas.sha256.trim().is_empty()
        && nas.modified_unix_seconds == source_age.source_captured_unix_seconds
        && source_age.min_age_seconds >= min_age_floor_seconds
        && nas.age_seconds >= source_age.min_age_seconds
        && source_age
            .verified_at_unix_seconds
            .saturating_sub(source_age.source_captured_unix_seconds)
            >= source_age.min_age_seconds
}

fn original_asset_resolver_retry_admission_fields(
    admission: &OriginalAssetResolverRetryAdmission,
) -> serde_json::Value {
    json!({
        "interrupted_retries_requeued": admission.interrupted_retries_requeued,
        "total_failed_resolver_backlog": admission.total_failed_resolver_backlog,
        "available_lifecycle_capacity": admission.available_lifecycle_capacity,
        "retry_admission_limit": admission.retry_admission_limit,
        "age_eligible_backlog_before": admission.age_eligible_before,
        "recovered_now": admission.recovered_now,
        "age_eligible_backlog_remaining": admission.age_eligible_remaining,
    })
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct FailedRetryPolicyAdmission {
    admitted_by_category: BTreeMap<&'static str, usize>,
    terminalized_by_reason: BTreeMap<&'static str, usize>,
    exhausted: usize,
    blocked_missing_preview: usize,
    blocked_downstream_proof: usize,
    blocked_source_proof: usize,
    backoff: usize,
    unknown: usize,
}

impl FailedRetryPolicyAdmission {
    fn manifest_changed(&self) -> bool {
        !self.admitted_by_category.is_empty() || !self.terminalized_by_reason.is_empty()
    }
}

/// Immutable durable authorization for the later adjusted-source resolver.
///
/// The resolver is deliberately not run by this admission policy. A record
/// remains `Failed` until the future resolver stage validates this marker and
/// performs its own exact compare-and-swap recovery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdjustedSourceRequiredProof {
    schema_version: u64,
    policy_generation: String,
    asset_id: String,
    attempt: u64,
    trigger_failure_stage: String,
    trigger_failure_kind: FailureKind,
    trigger_failure_recorded_at: String,
    trigger_failure_digest: String,
    failure_count_at_admission: usize,
    failure_history_digest: String,
    nas_proof_digest: String,
    original_asset_proof_digest: String,
    original_record_name: String,
    original_record_change_tag: String,
    original_database_scope: CloudKitDatabaseScope,
    original_zone_name: String,
    failure_retry_proof_digest: Option<String>,
    admitted_at_unix_seconds: u64,
    required_retry_state: State,
    adjusted_source_relative_path: PathBuf,
}

impl AdjustedSourceRequiredProof {
    pub fn asset_id(&self) -> &str {
        &self.asset_id
    }

    pub fn attempt(&self) -> u64 {
        self.attempt
    }

    pub fn admitted_at_unix_seconds(&self) -> u64 {
        self.admitted_at_unix_seconds
    }

    pub fn required_retry_state(&self) -> State {
        self.required_retry_state
    }

    pub fn adjusted_source_relative_path(&self) -> &Path {
        &self.adjusted_source_relative_path
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum AdjustedSourceRequiredProofError {
    #[error("adjusted-source-required marker is missing")]
    Missing,
    #[error("adjusted-source-required marker is malformed or stale")]
    Malformed,
    #[error("adjusted-source-required marker has invalid source proofs")]
    SourceProof,
    #[error("adjusted-source-required marker has a blocking downstream proof")]
    DownstreamProof,
}

/// A manifest-only outcome for adjusted-source admission. The fields describe
/// queue state, while `manifest_changed` indicates that a marker was written
/// or replaced in this pass.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AdjustedSourceRequiredAdmission {
    pub first_ready: usize,
    pub resolver_retry_ready: usize,
    pub backoff: usize,
    pub exhausted: usize,
    pub malformed_or_unknown: usize,
    pub source_proof_blocked: usize,
    pub downstream_proof_blocked: usize,
    manifest_changed: bool,
}

impl AdjustedSourceRequiredAdmission {
    pub fn manifest_changed(&self) -> bool {
        self.manifest_changed
    }
}

#[derive(Clone, Debug)]
struct AdjustedSourceRequiredCandidate {
    asset_id: String,
    failure_timestamp: (u64, u32),
    proof: AdjustedSourceRequiredProof,
    kind: AdjustedSourceAdmissionKind,
}

impl PartialEq for AdjustedSourceRequiredCandidate {
    fn eq(&self, other: &Self) -> bool {
        self.failure_timestamp == other.failure_timestamp && self.asset_id == other.asset_id
    }
}

impl Eq for AdjustedSourceRequiredCandidate {}

impl PartialOrd for AdjustedSourceRequiredCandidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AdjustedSourceRequiredCandidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.failure_timestamp
            .cmp(&other.failure_timestamp)
            .then_with(|| self.asset_id.cmp(&other.asset_id))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdjustedSourceAdmissionKind {
    First,
    ResolverRetry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdjustedSourceQueueStatus {
    FirstReady,
    ResolverRetryReady,
    Backoff,
    Exhausted,
    MalformedOrUnknown,
    SourceProofBlocked,
    DownstreamProofBlocked,
}

const ADJUSTED_SOURCE_RECOVERY_BLOCKING_PROOFS: [&str; 12] = [
    "adjusted_source",
    "conversion",
    "conversion_performance",
    "heic",
    "upload",
    "icloudpd_local_mirror",
    "delete_eligibility",
    "delete_approval",
    "delete",
    "uploaded_heic_delete",
    FAILURE_REVIEW_PROOF,
    FAILURE_QUARANTINE_PROOF_NAME,
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FailureRetryProof {
    schema_version: u64,
    policy_generation: String,
    category: FailureKind,
    attempt: u64,
    last_failure_stage: String,
    last_failure_kind: FailureKind,
    last_failure_recorded_at: String,
    last_failure_digest: String,
    failure_count_at_admission: usize,
    admitted_at_unix_seconds: u64,
    retry_state: State,
}

#[derive(Clone, Debug, Serialize)]
struct FailureReviewProof {
    schema_version: u64,
    reason_code: String,
    policy_generation: String,
    last_failure_stage: String,
    last_failure_kind: FailureKind,
    last_failure_recorded_at: String,
    last_failure_digest: String,
    attempts_exhausted: u64,
    current_attempt: u64,
    applied_at_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug)]
struct FailedRetryPolicy {
    bucket: &'static str,
    retry_state: State,
    max_attempts: u64,
}

#[derive(Clone, Debug)]
struct FailedRetryCandidate {
    asset_id: String,
    failure_timestamp: (u64, u32),
    kind: FailureKind,
    attempt: u64,
    policy: FailedRetryPolicy,
}

const RETRY_BLOCKING_PROOFS: [&str; 7] = [
    "heic",
    "upload",
    "icloudpd_local_mirror",
    "delete_eligibility",
    "delete_approval",
    "delete",
    "uploaded_heic_delete",
];

#[cfg(test)]
fn admit_failed_retryable_assets(
    manifest: &mut Manifest,
    max_lifecycle_per_scan: usize,
    max_failed_retry_admissions_per_scan: usize,
    retry_min_age_seconds: u64,
    current_unix_seconds: u64,
) -> Result<FailedRetryPolicyAdmission, ManifestError> {
    let mut lifecycle_budget = LifecycleAdmissionBudget::for_scan(manifest, max_lifecycle_per_scan);
    admit_failed_retryable_assets_with_budget(
        manifest,
        &mut lifecycle_budget,
        max_failed_retry_admissions_per_scan,
        retry_min_age_seconds,
        current_unix_seconds,
    )
}

fn admit_failed_retryable_assets_with_budget(
    manifest: &mut Manifest,
    lifecycle_budget: &mut LifecycleAdmissionBudget,
    max_failed_retry_admissions_per_scan: usize,
    retry_min_age_seconds: u64,
    current_unix_seconds: u64,
) -> Result<FailedRetryPolicyAdmission, ManifestError> {
    let mut admission = FailedRetryPolicyAdmission::default();
    let mut candidates = Vec::new();
    let mut exhausted = Vec::new();
    let terminalize = manifest
        .records()
        .values()
        .filter(|record| {
            record.state == State::Failed
                && last_failure_kind(record) == Some(FailureKind::HeicVisualContent)
        })
        .map(|record| record.asset_id.clone())
        .collect::<Vec<_>>();

    for asset_id in terminalize {
        terminalize_failure_for_review(
            manifest,
            &asset_id,
            FailureKind::HeicVisualContent,
            "heic_visual_content",
            0,
            current_unix_seconds,
        )?;
        increment_static_count(&mut admission.terminalized_by_reason, "heic_visual_content");
    }

    for record in manifest.records().values() {
        if record.state != State::Failed {
            continue;
        }
        if has_retry_blocking_proof(record) {
            admission.blocked_downstream_proof =
                admission.blocked_downstream_proof.saturating_add(1);
            continue;
        }
        let Some(kind) = last_failure_kind(record) else {
            admission.unknown = admission.unknown.saturating_add(1);
            continue;
        };
        if record.proofs.contains_key(ADJUSTED_SOURCE_REQUIRED_PROOF)
            || kind == FailureKind::AdjustedSourceResolveFailed
        {
            admission.unknown = admission.unknown.saturating_add(1);
            continue;
        }
        if kind == FailureKind::EmbeddedPreviewUnavailable {
            admission.blocked_missing_preview = admission.blocked_missing_preview.saturating_add(1);
            continue;
        }
        let Some(policy) = failed_retry_policy(kind) else {
            admission.unknown = admission.unknown.saturating_add(1);
            continue;
        };
        if !failed_retry_source_proofs_are_valid(record) {
            admission.blocked_source_proof = admission.blocked_source_proof.saturating_add(1);
            continue;
        }
        let Ok(attempt) = failed_retry_attempt(record, kind, policy) else {
            admission.unknown = admission.unknown.saturating_add(1);
            continue;
        };
        if attempt >= policy.max_attempts {
            exhausted.push((record.asset_id.clone(), kind, attempt));
            continue;
        }
        if kind == FailureKind::HeicVisualMatch && !conversion_output_still_matches_proof(record) {
            admission.blocked_source_proof = admission.blocked_source_proof.saturating_add(1);
            continue;
        }
        let Some(failure_timestamp) = record
            .failures
            .last()
            .and_then(|failure| parse_monitor_timestamp(&failure.recorded_at))
        else {
            admission.backoff = admission.backoff.saturating_add(1);
            continue;
        };
        if !monitor_timestamp_is_at_least_age(
            failure_timestamp,
            retry_min_age_seconds,
            current_unix_seconds,
        ) {
            admission.backoff = admission.backoff.saturating_add(1);
            continue;
        }
        candidates.push(FailedRetryCandidate {
            asset_id: record.asset_id.clone(),
            failure_timestamp,
            kind,
            attempt,
            policy,
        });
    }

    for (asset_id, kind, attempt) in exhausted {
        terminalize_failure_for_review(
            manifest,
            &asset_id,
            kind,
            "retry_attempts_exhausted",
            attempt,
            current_unix_seconds,
        )?;
        admission.exhausted = admission.exhausted.saturating_add(1);
        increment_static_count(
            &mut admission.terminalized_by_reason,
            "retry_attempts_exhausted",
        );
    }

    let admission_limit = lifecycle_budget
        .remaining_slots()
        .min(max_failed_retry_admissions_per_scan);
    candidates.sort_by(|left, right| {
        left.failure_timestamp
            .cmp(&right.failure_timestamp)
            .then_with(|| left.asset_id.cmp(&right.asset_id))
    });
    for candidate in candidates.into_iter().take(admission_limit) {
        admit_failed_retry(manifest, &candidate, current_unix_seconds)?;
        let consumed = lifecycle_budget.consume();
        debug_assert!(consumed, "selected retry must have a lifecycle slot");
        increment_static_count(&mut admission.admitted_by_category, candidate.policy.bucket);
    }
    Ok(admission)
}

fn failed_retry_policy_admission_fields(
    admission: &FailedRetryPolicyAdmission,
) -> serde_json::Value {
    json!({
        "admitted_by_category": admission.admitted_by_category,
        "terminalized_by_reason": admission.terminalized_by_reason,
        "exhausted": admission.exhausted,
        "blocked_missing_preview": admission.blocked_missing_preview,
        "blocked_downstream_proof": admission.blocked_downstream_proof,
        "blocked_source_proof": admission.blocked_source_proof,
        "backoff": admission.backoff,
        "unknown": admission.unknown,
    })
}

fn adjusted_source_required_admission_fields(
    admission: &AdjustedSourceRequiredAdmission,
) -> serde_json::Value {
    json!({
        "first_ready": admission.first_ready,
        "resolver_retry_ready": admission.resolver_retry_ready,
        "backoff": admission.backoff,
        "exhausted": admission.exhausted,
        "malformed_or_unknown": admission.malformed_or_unknown,
        "source_proof_blocked": admission.source_proof_blocked,
        "downstream_proof_blocked": admission.downstream_proof_blocked,
    })
}

fn failed_retry_policy(kind: FailureKind) -> Option<FailedRetryPolicy> {
    match kind {
        FailureKind::HeicVisualMatch => Some(FailedRetryPolicy {
            bucket: "retryable_heic_visual_match",
            retry_state: State::Converted,
            max_attempts: 1,
        }),
        FailureKind::ConversionOutputUnreadable => Some(FailedRetryPolicy {
            bucket: "retryable_conversion_output_unreadable",
            retry_state: State::NasVerified,
            max_attempts: 1,
        }),
        FailureKind::ConversionMetadataFailed => Some(FailedRetryPolicy {
            bucket: "retryable_conversion_metadata_failed",
            retry_state: State::NasVerified,
            max_attempts: 1,
        }),
        FailureKind::ConversionTimedOut => Some(FailedRetryPolicy {
            bucket: "retryable_conversion_timed_out",
            retry_state: State::NasVerified,
            max_attempts: 3,
        }),
        FailureKind::RawStagingTimedOut => Some(FailedRetryPolicy {
            bucket: "retryable_raw_staging_timed_out",
            retry_state: State::NasVerified,
            max_attempts: 3,
        }),
        FailureKind::ConversionOutputAlreadyExists => Some(FailedRetryPolicy {
            bucket: "retryable_conversion_output_already_exists",
            retry_state: State::NasVerified,
            max_attempts: 3,
        }),
        FailureKind::StagedRawAlreadyExists => Some(FailedRetryPolicy {
            bucket: "retryable_staged_raw_already_exists",
            retry_state: State::NasVerified,
            max_attempts: 3,
        }),
        FailureKind::HeicVisualContent
        | FailureKind::EmbeddedPreviewUnavailable
        | FailureKind::AdjustedSourceResolveFailed => None,
    }
}

/// Decodes and validates a marker that is ready for the future resolver stage.
/// It accepts only an exact current marker; a resolver failure appended after a
/// marker is deliberately a retry-admission concern instead.
pub fn adjusted_source_required_proof(
    record: &AssetRecord,
) -> Result<AdjustedSourceRequiredProof, AdjustedSourceRequiredProofError> {
    let value = record
        .proofs
        .get(ADJUSTED_SOURCE_REQUIRED_PROOF)
        .ok_or(AdjustedSourceRequiredProofError::Missing)?;
    let proof = serde_json::from_value::<AdjustedSourceRequiredProof>(value.clone())
        .map_err(|_| AdjustedSourceRequiredProofError::Malformed)?;
    validate_adjusted_source_required_current(record, &proof)?;
    Ok(proof)
}

fn valid_adjusted_source_marker_reservation(record: &AssetRecord) -> bool {
    if record.state != State::Failed {
        return false;
    }
    if adjusted_source_required_proof(record).is_ok() {
        return true;
    }
    let Some(value) = record.proofs.get(ADJUSTED_SOURCE_REQUIRED_PROOF) else {
        return false;
    };
    let Ok(marker) = serde_json::from_value::<AdjustedSourceRequiredProof>(value.clone()) else {
        return false;
    };
    validate_adjusted_source_required_retry(record, &marker).is_ok()
}

/// Reserves bounded lifecycle capacity for typed missing-preview failures. The
/// only mutation is an adjusted-source marker replacement; records remain in
/// `Failed` for the resolver worker introduced in the next task.
pub fn admit_adjusted_source_required_assets(
    manifest: &mut Manifest,
    max_lifecycle_per_scan: usize,
    max_admissions_per_scan: usize,
    current_unix_seconds: u64,
) -> Result<AdjustedSourceRequiredAdmission, ManifestError> {
    let mut lifecycle_budget = LifecycleAdmissionBudget::for_scan(manifest, max_lifecycle_per_scan);
    admit_adjusted_source_required_assets_with_budget(
        manifest,
        &mut lifecycle_budget,
        max_admissions_per_scan,
        current_unix_seconds,
    )
}

fn admit_adjusted_source_required_assets_with_budget(
    manifest: &mut Manifest,
    lifecycle_budget: &mut LifecycleAdmissionBudget,
    max_admissions_per_scan: usize,
    current_unix_seconds: u64,
) -> Result<AdjustedSourceRequiredAdmission, ManifestError> {
    admit_adjusted_source_required_assets_with_budget_and_stager(
        manifest,
        lifecycle_budget,
        max_admissions_per_scan,
        current_unix_seconds,
        |staged, asset_id, value| {
            staged
                .record_proof(asset_id, ADJUSTED_SOURCE_REQUIRED_PROOF, value)
                .map(|_| ())
        },
    )
}

fn admit_adjusted_source_required_assets_with_budget_and_stager<F>(
    manifest: &mut Manifest,
    lifecycle_budget: &mut LifecycleAdmissionBudget,
    max_admissions_per_scan: usize,
    current_unix_seconds: u64,
    mut stage_proof: F,
) -> Result<AdjustedSourceRequiredAdmission, ManifestError>
where
    F: FnMut(&mut Manifest, &str, Value) -> Result<(), ManifestError>,
{
    let mut admission = AdjustedSourceRequiredAdmission::default();
    let first_capacity = max_admissions_per_scan.min(lifecycle_budget.remaining_slots());
    let mut first_candidates = BoundedOldest::new(first_capacity);
    let mut retry_candidates = BoundedOldest::new(max_admissions_per_scan);

    for record in manifest.records().values() {
        if record.state != State::Failed {
            continue;
        }

        if record.proofs.contains_key(ADJUSTED_SOURCE_REQUIRED_PROOF) {
            match adjusted_source_required_proof(record) {
                Ok(marker) => {
                    match marker.attempt {
                        1 => admission.first_ready = admission.first_ready.saturating_add(1),
                        _ => {
                            admission.resolver_retry_ready =
                                admission.resolver_retry_ready.saturating_add(1)
                        }
                    }
                    continue;
                }
                Err(AdjustedSourceRequiredProofError::SourceProof) => {
                    admission.source_proof_blocked =
                        admission.source_proof_blocked.saturating_add(1);
                    continue;
                }
                Err(AdjustedSourceRequiredProofError::DownstreamProof) => {
                    admission.downstream_proof_blocked =
                        admission.downstream_proof_blocked.saturating_add(1);
                    continue;
                }
                Err(AdjustedSourceRequiredProofError::Missing) => unreachable!(),
                Err(AdjustedSourceRequiredProofError::Malformed) => {}
            };

            let raw_marker = match record.proofs.get(ADJUSTED_SOURCE_REQUIRED_PROOF) {
                Some(value) => serde_json::from_value::<AdjustedSourceRequiredProof>(value.clone())
                    .map_err(|_| AdjustedSourceRequiredProofError::Malformed),
                None => Err(AdjustedSourceRequiredProofError::Missing),
            };
            let Ok(marker) = raw_marker else {
                admission.malformed_or_unknown = admission.malformed_or_unknown.saturating_add(1);
                continue;
            };
            match validate_adjusted_source_required_retry(record, &marker) {
                Ok(()) if marker.attempt >= ADJUSTED_SOURCE_RESOLVE_MAX_ATTEMPTS => {
                    admission.exhausted = admission.exhausted.saturating_add(1);
                }
                Ok(()) => {
                    let Some(failure_timestamp) = record
                        .failures
                        .last()
                        .and_then(|failure| parse_monitor_timestamp(&failure.recorded_at))
                    else {
                        admission.malformed_or_unknown =
                            admission.malformed_or_unknown.saturating_add(1);
                        continue;
                    };
                    if !monitor_timestamp_is_at_least_age(
                        failure_timestamp,
                        ADJUSTED_SOURCE_RESOLVE_RETRY_MIN_AGE_SECONDS,
                        current_unix_seconds,
                    ) {
                        admission.backoff = admission.backoff.saturating_add(1);
                        continue;
                    }
                    let Some(failure) = record.failures.last() else {
                        admission.malformed_or_unknown =
                            admission.malformed_or_unknown.saturating_add(1);
                        continue;
                    };
                    match build_adjusted_source_required_proof(
                        record,
                        failure,
                        marker.attempt.saturating_add(1),
                        current_unix_seconds,
                    ) {
                        Ok(proof) => retry_candidates.consider(AdjustedSourceRequiredCandidate {
                            asset_id: record.asset_id.clone(),
                            failure_timestamp,
                            proof,
                            kind: AdjustedSourceAdmissionKind::ResolverRetry,
                        }),
                        Err(error) => increment_adjusted_source_error(&mut admission, error),
                    }
                }
                Err(error) => increment_adjusted_source_error(&mut admission, error),
            }
            continue;
        }

        if typed_last_failure_kind(record) != Some(FailureKind::EmbeddedPreviewUnavailable) {
            continue;
        }
        let Some(failure) = record.failures.last() else {
            admission.malformed_or_unknown = admission.malformed_or_unknown.saturating_add(1);
            continue;
        };
        let Some(failure_timestamp) = parse_monitor_timestamp(&failure.recorded_at) else {
            admission.malformed_or_unknown = admission.malformed_or_unknown.saturating_add(1);
            continue;
        };
        match build_adjusted_source_required_proof(record, failure, 1, current_unix_seconds) {
            Ok(proof) => first_candidates.consider(AdjustedSourceRequiredCandidate {
                asset_id: record.asset_id.clone(),
                failure_timestamp,
                proof,
                kind: AdjustedSourceAdmissionKind::First,
            }),
            Err(error) => increment_adjusted_source_error(&mut admission, error),
        }
    }

    let mut candidates = first_candidates.into_oldest();
    candidates.extend(retry_candidates.into_oldest());
    candidates.sort();
    let mut staged_budget = *lifecycle_budget;
    let mut selected = Vec::new();
    for candidate in candidates {
        if selected.len() >= max_admissions_per_scan {
            break;
        }
        if candidate.kind == AdjustedSourceAdmissionKind::First && !staged_budget.consume() {
            continue;
        }
        selected.push(candidate);
    }

    let values = selected
        .iter()
        .map(|candidate| {
            serde_json::to_value(&candidate.proof)
                .map(|value| (candidate.asset_id.clone(), candidate.kind, value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if values.is_empty() {
        return Ok(admission);
    }

    let staged_records =
        stage_adjusted_source_required_updates(manifest, values, &mut stage_proof)?;
    let mut committed_admission = admission;
    for (kind, _) in &staged_records {
        match kind {
            AdjustedSourceAdmissionKind::First => {
                committed_admission.first_ready = committed_admission.first_ready.saturating_add(1)
            }
            AdjustedSourceAdmissionKind::ResolverRetry => {
                committed_admission.resolver_retry_ready =
                    committed_admission.resolver_retry_ready.saturating_add(1)
            }
        }
    }
    for (_, record) in staged_records {
        manifest.upsert(record);
    }
    *lifecycle_budget = staged_budget;
    committed_admission.manifest_changed = true;
    Ok(committed_admission)
}

fn stage_adjusted_source_required_updates<F>(
    manifest: &Manifest,
    values: Vec<(String, AdjustedSourceAdmissionKind, Value)>,
    stage_proof: &mut F,
) -> Result<Vec<(AdjustedSourceAdmissionKind, AssetRecord)>, ManifestError>
where
    F: FnMut(&mut Manifest, &str, Value) -> Result<(), ManifestError>,
{
    let mut staged_records = Vec::with_capacity(values.len());
    for (asset_id, kind, value) in values {
        let mut staged = manifest.snapshot_record(&asset_id)?;
        stage_proof(&mut staged, &asset_id, value)?;
        staged_records.push((kind, staged.get(&asset_id)?.clone()));
    }
    Ok(staged_records)
}

struct ScanRetryAdmissions {
    failed_retry: FailedRetryPolicyAdmission,
    adjusted_source_required: AdjustedSourceRequiredAdmission,
    original_asset_resolver: OriginalAssetResolverRetryAdmission,
}

fn admit_scan_retry_policies(
    manifest: &mut Manifest,
    max_lifecycle_per_scan: usize,
    max_failed_retry_admissions_per_scan: usize,
    failed_retry_min_age_seconds: u64,
    max_original_resolver_retries_per_scan: usize,
    original_resolver_retry_min_age_seconds: u64,
    current_unix_seconds: u64,
) -> Result<ScanRetryAdmissions, ManifestError> {
    let mut lifecycle_budget = LifecycleAdmissionBudget::for_scan(manifest, max_lifecycle_per_scan);
    let failed_retry = admit_failed_retryable_assets_with_budget(
        manifest,
        &mut lifecycle_budget,
        max_failed_retry_admissions_per_scan,
        failed_retry_min_age_seconds,
        current_unix_seconds,
    )?;
    let mut adjusted_source_required = admit_adjusted_source_required_assets_with_budget(
        manifest,
        &mut lifecycle_budget,
        max_failed_retry_admissions_per_scan,
        current_unix_seconds,
    )?;
    let terminalized_exhausted =
        terminalize_exhausted_adjusted_source_required_assets(manifest, current_unix_seconds)?;
    if terminalized_exhausted > 0 {
        adjusted_source_required.manifest_changed = true;
        lifecycle_budget.release(terminalized_exhausted);
    }
    let original_asset_resolver = recover_original_asset_resolver_retries_with_budget(
        manifest,
        &mut lifecycle_budget,
        max_original_resolver_retries_per_scan,
        original_resolver_retry_min_age_seconds,
        current_unix_seconds,
    )?;
    Ok(ScanRetryAdmissions {
        failed_retry,
        adjusted_source_required,
        original_asset_resolver,
    })
}

fn terminalize_exhausted_adjusted_source_required_assets(
    manifest: &mut Manifest,
    applied_at_unix_seconds: u64,
) -> Result<usize, ManifestError> {
    let asset_ids = manifest
        .records()
        .values()
        .filter(|record| record.state == State::Failed)
        .filter_map(|record| {
            let marker = record
                .proofs
                .get(ADJUSTED_SOURCE_REQUIRED_PROOF)
                .and_then(|value| {
                    serde_json::from_value::<AdjustedSourceRequiredProof>(value.clone()).ok()
                })?;
            (marker.attempt >= ADJUSTED_SOURCE_RESOLVE_MAX_ATTEMPTS
                && validate_adjusted_source_required_retry(record, &marker).is_ok())
            .then_some(record.asset_id.clone())
        })
        .collect::<Vec<_>>();
    for asset_id in &asset_ids {
        terminalize_adjusted_source_required_exhaustion(
            manifest,
            asset_id,
            applied_at_unix_seconds,
        )?;
    }
    Ok(asset_ids.len())
}

/// Returns only adjusted-source queue categories and performs no filesystem,
/// hashing, or network work. Callers supply time so retry backoff is testable.
pub fn adjusted_source_required_queue_counts(
    manifest: &Manifest,
    current_unix_seconds: u64,
) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for record in manifest.records().values() {
        let Some(status) = adjusted_source_queue_status(record, current_unix_seconds) else {
            continue;
        };
        let key = match status {
            AdjustedSourceQueueStatus::FirstReady => "adjusted_source_first_ready",
            AdjustedSourceQueueStatus::ResolverRetryReady => "adjusted_source_resolver_retry_ready",
            AdjustedSourceQueueStatus::Backoff => "adjusted_source_resolver_backoff",
            AdjustedSourceQueueStatus::Exhausted => "adjusted_source_resolver_exhausted",
            AdjustedSourceQueueStatus::MalformedOrUnknown => "adjusted_source_malformed_or_unknown",
            AdjustedSourceQueueStatus::SourceProofBlocked => "adjusted_source_source_proof_blocked",
            AdjustedSourceQueueStatus::DownstreamProofBlocked => {
                "adjusted_source_downstream_proof_blocked"
            }
        };
        *counts.entry(key.to_string()).or_default() += 1;
    }
    counts
}

/// Terminalizes an exhausted resolver lineage using the ordinary durable
/// failure-review proof. The worker can call this before attempting a fourth
/// resolver execution.
pub fn terminalize_adjusted_source_required_exhaustion(
    manifest: &mut Manifest,
    asset_id: &str,
    applied_at_unix_seconds: u64,
) -> Result<(), ManifestError> {
    let record = manifest.get(asset_id)?;
    let marker = record
        .proofs
        .get(ADJUSTED_SOURCE_REQUIRED_PROOF)
        .ok_or_else(|| ManifestError::UnknownAsset {
            asset_id: asset_id.to_string(),
        })
        .and_then(|value| {
            serde_json::from_value::<AdjustedSourceRequiredProof>(value.clone())
                .map_err(ManifestError::from)
        })?;
    if marker.attempt < ADJUSTED_SOURCE_RESOLVE_MAX_ATTEMPTS
        || validate_adjusted_source_required_retry(record, &marker).is_err()
    {
        return Err(ManifestError::InvalidTransition {
            asset_id: asset_id.to_string(),
            from: record.state,
            to: State::NeedsReview,
        });
    }

    let mut staged = manifest.clone();
    terminalize_failure_for_review(
        &mut staged,
        asset_id,
        FailureKind::AdjustedSourceResolveFailed,
        "adjusted_source_resolve_attempts_exhausted",
        ADJUSTED_SOURCE_RESOLVE_MAX_ATTEMPTS,
        applied_at_unix_seconds,
    )?;
    *manifest = staged;
    Ok(())
}

fn adjusted_source_queue_status(
    record: &AssetRecord,
    current_unix_seconds: u64,
) -> Option<AdjustedSourceQueueStatus> {
    if record.state != State::Failed {
        return None;
    }
    if record.proofs.contains_key(ADJUSTED_SOURCE_REQUIRED_PROOF) {
        let marker = match record
            .proofs
            .get(ADJUSTED_SOURCE_REQUIRED_PROOF)
            .and_then(|value| {
                serde_json::from_value::<AdjustedSourceRequiredProof>(value.clone()).ok()
            }) {
            Some(marker) => marker,
            None => return Some(AdjustedSourceQueueStatus::MalformedOrUnknown),
        };
        match validate_adjusted_source_required_queue_current(record, &marker) {
            Ok(()) => {
                return Some(if marker.attempt == 1 {
                    AdjustedSourceQueueStatus::FirstReady
                } else {
                    AdjustedSourceQueueStatus::ResolverRetryReady
                });
            }
            Err(AdjustedSourceRequiredProofError::SourceProof) => {
                return Some(AdjustedSourceQueueStatus::SourceProofBlocked);
            }
            Err(AdjustedSourceRequiredProofError::DownstreamProof) => {
                return Some(AdjustedSourceQueueStatus::DownstreamProofBlocked);
            }
            Err(AdjustedSourceRequiredProofError::Missing) => return None,
            Err(AdjustedSourceRequiredProofError::Malformed) => {}
        }
        return Some(
            match validate_adjusted_source_required_queue_retry(record, &marker) {
                Ok(()) if marker.attempt >= ADJUSTED_SOURCE_RESOLVE_MAX_ATTEMPTS => {
                    AdjustedSourceQueueStatus::Exhausted
                }
                Ok(()) => match record
                    .failures
                    .last()
                    .and_then(|failure| parse_monitor_timestamp(&failure.recorded_at))
                {
                    Some(timestamp)
                        if monitor_timestamp_is_at_least_age(
                            timestamp,
                            ADJUSTED_SOURCE_RESOLVE_RETRY_MIN_AGE_SECONDS,
                            current_unix_seconds,
                        ) =>
                    {
                        AdjustedSourceQueueStatus::ResolverRetryReady
                    }
                    Some(_) => AdjustedSourceQueueStatus::Backoff,
                    None => AdjustedSourceQueueStatus::MalformedOrUnknown,
                },
                Err(AdjustedSourceRequiredProofError::SourceProof) => {
                    AdjustedSourceQueueStatus::SourceProofBlocked
                }
                Err(AdjustedSourceRequiredProofError::DownstreamProof) => {
                    AdjustedSourceQueueStatus::DownstreamProofBlocked
                }
                Err(AdjustedSourceRequiredProofError::Missing)
                | Err(AdjustedSourceRequiredProofError::Malformed) => {
                    AdjustedSourceQueueStatus::MalformedOrUnknown
                }
            },
        );
    }

    if typed_last_failure_kind(record) != Some(FailureKind::EmbeddedPreviewUnavailable) {
        return (typed_last_failure_kind(record) == Some(FailureKind::AdjustedSourceResolveFailed))
            .then_some(AdjustedSourceQueueStatus::MalformedOrUnknown);
    }
    let Some(failure) = record.failures.last() else {
        return Some(AdjustedSourceQueueStatus::MalformedOrUnknown);
    };
    if parse_monitor_timestamp(&failure.recorded_at).is_none()
        || has_adjusted_source_recovery_blocking_proof(record)
    {
        return Some(if has_adjusted_source_recovery_blocking_proof(record) {
            AdjustedSourceQueueStatus::DownstreamProofBlocked
        } else {
            AdjustedSourceQueueStatus::MalformedOrUnknown
        });
    }
    if adjusted_source_recovery_original_proof(record).is_err() {
        return Some(AdjustedSourceQueueStatus::SourceProofBlocked);
    }
    if failure.kind != Some(FailureKind::EmbeddedPreviewUnavailable) {
        return Some(AdjustedSourceQueueStatus::MalformedOrUnknown);
    }
    Some(AdjustedSourceQueueStatus::FirstReady)
}

fn increment_adjusted_source_error(
    admission: &mut AdjustedSourceRequiredAdmission,
    error: AdjustedSourceRequiredProofError,
) {
    match error {
        AdjustedSourceRequiredProofError::SourceProof => {
            admission.source_proof_blocked = admission.source_proof_blocked.saturating_add(1)
        }
        AdjustedSourceRequiredProofError::DownstreamProof => {
            admission.downstream_proof_blocked =
                admission.downstream_proof_blocked.saturating_add(1)
        }
        AdjustedSourceRequiredProofError::Missing | AdjustedSourceRequiredProofError::Malformed => {
            admission.malformed_or_unknown = admission.malformed_or_unknown.saturating_add(1)
        }
    }
}

fn typed_last_failure_kind(record: &AssetRecord) -> Option<FailureKind> {
    record.failures.last().and_then(|failure| failure.kind)
}

fn validate_adjusted_source_required_queue_current(
    record: &AssetRecord,
    marker: &AdjustedSourceRequiredProof,
) -> Result<(), AdjustedSourceRequiredProofError> {
    validate_adjusted_source_required_queue_common(record, marker)?;
    if record.failures.len() != marker.failure_count_at_admission {
        return Err(AdjustedSourceRequiredProofError::Malformed);
    }
    let failure = record
        .failures
        .last()
        .ok_or(AdjustedSourceRequiredProofError::Malformed)?;
    queue_marker_trigger_matches(marker, failure)
}

fn validate_adjusted_source_required_queue_retry(
    record: &AssetRecord,
    marker: &AdjustedSourceRequiredProof,
) -> Result<(), AdjustedSourceRequiredProofError> {
    validate_adjusted_source_required_queue_common(record, marker)?;
    if record.failures.len()
        != marker
            .failure_count_at_admission
            .checked_add(1)
            .ok_or(AdjustedSourceRequiredProofError::Malformed)?
        || marker.failure_count_at_admission == 0
    {
        return Err(AdjustedSourceRequiredProofError::Malformed);
    }
    let trigger = record
        .failures
        .get(marker.failure_count_at_admission.saturating_sub(1))
        .ok_or(AdjustedSourceRequiredProofError::Malformed)?;
    queue_marker_trigger_matches(marker, trigger)?;
    (record.failures.last().and_then(|failure| failure.kind)
        == Some(FailureKind::AdjustedSourceResolveFailed))
    .then_some(())
    .ok_or(AdjustedSourceRequiredProofError::Malformed)
}

fn validate_adjusted_source_required_queue_common(
    record: &AssetRecord,
    marker: &AdjustedSourceRequiredProof,
) -> Result<(), AdjustedSourceRequiredProofError> {
    if marker.schema_version != ADJUSTED_SOURCE_REQUIRED_SCHEMA_VERSION
        || marker.policy_generation != ADJUSTED_SOURCE_REQUIRED_POLICY_GENERATION
        || marker.asset_id != record.asset_id
        || !(1..=ADJUSTED_SOURCE_RESOLVE_MAX_ATTEMPTS).contains(&marker.attempt)
        || marker.failure_count_at_admission == 0
        || marker.required_retry_state != State::NasVerified
        || marker.adjusted_source_relative_path != adjusted_source_relative_path(&record.asset_id)
        || record.state != State::Failed
    {
        return Err(AdjustedSourceRequiredProofError::Malformed);
    }
    if has_adjusted_source_recovery_blocking_proof(record) {
        return Err(AdjustedSourceRequiredProofError::DownstreamProof);
    }
    let original = adjusted_source_recovery_original_proof(record)?;
    if marker.original_record_name != original.record_name
        || marker.original_record_change_tag != original.record_change_tag
        || marker.original_database_scope != original.database_scope
        || marker.original_zone_name != original.zone_name
        || marker.failure_retry_proof_digest.is_some()
            != record.proofs.contains_key(FAILURE_RETRY_PROOF)
    {
        return Err(AdjustedSourceRequiredProofError::SourceProof);
    }
    Ok(())
}

fn queue_marker_trigger_matches(
    marker: &AdjustedSourceRequiredProof,
    failure: &FailureRecord,
) -> Result<(), AdjustedSourceRequiredProofError> {
    let expected_kind = if marker.attempt == 1 {
        FailureKind::EmbeddedPreviewUnavailable
    } else {
        FailureKind::AdjustedSourceResolveFailed
    };
    if failure.kind != Some(expected_kind)
        || marker.trigger_failure_kind != expected_kind
        || marker.trigger_failure_stage != failure.stage
        || marker.trigger_failure_recorded_at != failure.recorded_at
    {
        return Err(AdjustedSourceRequiredProofError::Malformed);
    }
    Ok(())
}

fn validate_adjusted_source_required_current(
    record: &AssetRecord,
    marker: &AdjustedSourceRequiredProof,
) -> Result<(), AdjustedSourceRequiredProofError> {
    validate_adjusted_source_required_common(record, marker)?;
    if record.failures.len() != marker.failure_count_at_admission
        || failure_history_digest(&record.failures) != marker.failure_history_digest
    {
        return Err(AdjustedSourceRequiredProofError::Malformed);
    }
    let failure = record
        .failures
        .last()
        .ok_or(AdjustedSourceRequiredProofError::Malformed)?;
    validate_adjusted_source_marker_trigger(marker, failure)
}

fn validate_adjusted_source_required_retry(
    record: &AssetRecord,
    marker: &AdjustedSourceRequiredProof,
) -> Result<(), AdjustedSourceRequiredProofError> {
    validate_adjusted_source_required_common(record, marker)?;
    let expected_failure_count = marker
        .failure_count_at_admission
        .checked_add(1)
        .ok_or(AdjustedSourceRequiredProofError::Malformed)?;
    if record.failures.len() != expected_failure_count
        || marker.failure_count_at_admission == 0
        || failure_history_digest(&record.failures[..marker.failure_count_at_admission])
            != marker.failure_history_digest
    {
        return Err(AdjustedSourceRequiredProofError::Malformed);
    }
    let trigger = record
        .failures
        .get(marker.failure_count_at_admission.saturating_sub(1))
        .ok_or(AdjustedSourceRequiredProofError::Malformed)?;
    validate_adjusted_source_marker_trigger(marker, trigger)?;
    let resolver_failure = record
        .failures
        .last()
        .ok_or(AdjustedSourceRequiredProofError::Malformed)?;
    (resolver_failure.kind == Some(FailureKind::AdjustedSourceResolveFailed))
        .then_some(())
        .ok_or(AdjustedSourceRequiredProofError::Malformed)
}

fn validate_adjusted_source_required_common(
    record: &AssetRecord,
    marker: &AdjustedSourceRequiredProof,
) -> Result<(), AdjustedSourceRequiredProofError> {
    if marker.schema_version != ADJUSTED_SOURCE_REQUIRED_SCHEMA_VERSION
        || marker.policy_generation != ADJUSTED_SOURCE_REQUIRED_POLICY_GENERATION
        || marker.asset_id != record.asset_id
        || !(1..=ADJUSTED_SOURCE_RESOLVE_MAX_ATTEMPTS).contains(&marker.attempt)
        || marker.failure_count_at_admission == 0
        || marker.required_retry_state != State::NasVerified
        || marker.adjusted_source_relative_path != adjusted_source_relative_path(&record.asset_id)
        || record.state != State::Failed
    {
        return Err(AdjustedSourceRequiredProofError::Malformed);
    }
    if has_adjusted_source_recovery_blocking_proof(record) {
        return Err(AdjustedSourceRequiredProofError::DownstreamProof);
    }
    let source = adjusted_source_recovery_source_context(record)?;
    if marker.nas_proof_digest != source.nas_proof_digest
        || marker.original_asset_proof_digest != source.original_asset_proof_digest
        || marker.original_record_name != source.original.record_name
        || marker.original_record_change_tag != source.original.record_change_tag
        || marker.original_database_scope != source.original.database_scope
        || marker.original_zone_name != source.original.zone_name
        || marker.failure_retry_proof_digest != source.failure_retry_proof_digest
    {
        return Err(AdjustedSourceRequiredProofError::SourceProof);
    }
    Ok(())
}

fn validate_adjusted_source_marker_trigger(
    marker: &AdjustedSourceRequiredProof,
    failure: &FailureRecord,
) -> Result<(), AdjustedSourceRequiredProofError> {
    let expected_kind = if marker.attempt == 1 {
        FailureKind::EmbeddedPreviewUnavailable
    } else {
        FailureKind::AdjustedSourceResolveFailed
    };
    if failure.kind != Some(expected_kind)
        || marker.trigger_failure_kind != expected_kind
        || marker.trigger_failure_stage != failure.stage
        || marker.trigger_failure_recorded_at != failure.recorded_at
        || marker.trigger_failure_digest != failure_digest(failure)
    {
        return Err(AdjustedSourceRequiredProofError::Malformed);
    }
    Ok(())
}

struct AdjustedSourceRecoverySourceContext {
    nas_proof_digest: String,
    original_asset_proof_digest: String,
    original: OriginalAssetProof,
    failure_retry_proof_digest: Option<String>,
}

fn adjusted_source_recovery_source_context(
    record: &AssetRecord,
) -> Result<AdjustedSourceRecoverySourceContext, AdjustedSourceRequiredProofError> {
    let original = adjusted_source_recovery_original_proof(record)?;
    let nas = record
        .proofs
        .get("nas")
        .ok_or(AdjustedSourceRequiredProofError::SourceProof)?;
    let original_value = record
        .proofs
        .get("original_asset")
        .ok_or(AdjustedSourceRequiredProofError::SourceProof)?;
    Ok(AdjustedSourceRecoverySourceContext {
        nas_proof_digest: value_digest(nas)?,
        original_asset_proof_digest: value_digest(original_value)?,
        original,
        failure_retry_proof_digest: record
            .proofs
            .get(FAILURE_RETRY_PROOF)
            .map(value_digest)
            .transpose()?,
    })
}

fn adjusted_source_recovery_original_proof(
    record: &AssetRecord,
) -> Result<OriginalAssetProof, AdjustedSourceRequiredProofError> {
    if !failed_retry_source_proofs_are_valid(record) {
        return Err(AdjustedSourceRequiredProofError::SourceProof);
    }
    record
        .proofs
        .get("original_asset")
        .ok_or(AdjustedSourceRequiredProofError::SourceProof)
        .and_then(|value| {
            serde_json::from_value::<OriginalAssetProof>(value.clone())
                .map_err(|_| AdjustedSourceRequiredProofError::SourceProof)
        })
}

fn build_adjusted_source_required_proof(
    record: &AssetRecord,
    failure: &FailureRecord,
    attempt: u64,
    admitted_at_unix_seconds: u64,
) -> Result<AdjustedSourceRequiredProof, AdjustedSourceRequiredProofError> {
    let expected_kind = if attempt == 1 {
        FailureKind::EmbeddedPreviewUnavailable
    } else {
        FailureKind::AdjustedSourceResolveFailed
    };
    if !(1..=ADJUSTED_SOURCE_RESOLVE_MAX_ATTEMPTS).contains(&attempt)
        || failure.kind != Some(expected_kind)
        || has_adjusted_source_recovery_blocking_proof(record)
    {
        return if has_adjusted_source_recovery_blocking_proof(record) {
            Err(AdjustedSourceRequiredProofError::DownstreamProof)
        } else {
            Err(AdjustedSourceRequiredProofError::Malformed)
        };
    }
    let source = adjusted_source_recovery_source_context(record)?;
    Ok(AdjustedSourceRequiredProof {
        schema_version: ADJUSTED_SOURCE_REQUIRED_SCHEMA_VERSION,
        policy_generation: ADJUSTED_SOURCE_REQUIRED_POLICY_GENERATION.to_string(),
        asset_id: record.asset_id.clone(),
        attempt,
        trigger_failure_stage: failure.stage.clone(),
        trigger_failure_kind: expected_kind,
        trigger_failure_recorded_at: failure.recorded_at.clone(),
        trigger_failure_digest: failure_digest(failure),
        failure_count_at_admission: record.failures.len(),
        failure_history_digest: failure_history_digest(&record.failures),
        nas_proof_digest: source.nas_proof_digest,
        original_asset_proof_digest: source.original_asset_proof_digest,
        original_record_name: source.original.record_name,
        original_record_change_tag: source.original.record_change_tag,
        original_database_scope: source.original.database_scope,
        original_zone_name: source.original.zone_name,
        failure_retry_proof_digest: source.failure_retry_proof_digest,
        admitted_at_unix_seconds,
        required_retry_state: State::NasVerified,
        adjusted_source_relative_path: adjusted_source_relative_path(&record.asset_id),
    })
}

fn has_adjusted_source_recovery_blocking_proof(record: &AssetRecord) -> bool {
    ADJUSTED_SOURCE_RECOVERY_BLOCKING_PROOFS
        .iter()
        .any(|proof_key| record.proofs.contains_key(*proof_key))
}

fn adjusted_source_relative_path(asset_id: &str) -> PathBuf {
    PathBuf::from(format!("{asset_id}.adjusted-source.jpg"))
}

fn value_digest(value: &Value) -> Result<String, AdjustedSourceRequiredProofError> {
    let encoded =
        serde_json::to_vec(value).map_err(|_| AdjustedSourceRequiredProofError::Malformed)?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

fn failure_history_digest(failures: &[FailureRecord]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"adjusted_source_failure_history_v1");
    for failure in failures {
        hasher.update(failure_digest(failure).as_bytes());
        hasher.update([0]);
    }
    format!("{:x}", hasher.finalize())
}

pub fn failed_retry_queue_counts(manifest: &Manifest) -> BTreeMap<String, u64> {
    failed_retry_queue_counts_at(manifest, current_unix_seconds())
}

/// Returns manifest-only retry queue categories at a caller-supplied time.
/// The injected timestamp keeps adjusted-source backoff deterministic in tests.
pub fn failed_retry_queue_counts_at(
    manifest: &Manifest,
    current_unix_seconds: u64,
) -> BTreeMap<String, u64> {
    let mut counts = adjusted_source_required_queue_counts(manifest, current_unix_seconds);
    for record in manifest.records().values() {
        if record.state != State::Failed {
            continue;
        }
        if adjusted_source_queue_status(record, current_unix_seconds).is_some() {
            continue;
        }
        let bucket = if has_retry_blocking_proof(record) {
            "blocked_downstream_proof"
        } else {
            match last_failure_kind(record) {
                Some(FailureKind::HeicVisualContent) => "terminalize_heic_visual_content",
                Some(FailureKind::EmbeddedPreviewUnavailable) => "blocked_missing_embedded_preview",
                Some(kind) => match failed_retry_policy(kind) {
                    Some(_) if !failed_retry_source_proofs_are_valid(record) => {
                        "blocked_source_proof"
                    }
                    Some(policy) if kind == FailureKind::HeicVisualMatch => {
                        match failed_retry_attempt(record, kind, policy) {
                            Ok(attempt) if attempt >= policy.max_attempts => {
                                "terminalize_retry_attempts_exhausted"
                            }
                            Ok(_) if !conversion_proof_has_expected_shape(record) => {
                                "blocked_source_proof"
                            }
                            Ok(_) => "retryable_heic_visual_match_pending_integrity_check",
                            Err(_) => "failed_unknown",
                        }
                    }
                    Some(policy) => match failed_retry_attempt(record, kind, policy) {
                        Ok(attempt) if attempt >= policy.max_attempts => {
                            "terminalize_retry_attempts_exhausted"
                        }
                        Ok(_) => policy.bucket,
                        Err(_) => "failed_unknown",
                    },
                    None => "failed_unknown",
                },
                None => "failed_unknown",
            }
        };
        *counts.entry(bucket.to_string()).or_default() += 1;
    }
    counts
}

fn admit_failed_retry(
    manifest: &mut Manifest,
    candidate: &FailedRetryCandidate,
    admitted_at_unix_seconds: u64,
) -> Result<(), ManifestError> {
    let failure = manifest
        .get(&candidate.asset_id)?
        .failures
        .last()
        .cloned()
        .ok_or_else(|| ManifestError::UnknownAsset {
            asset_id: candidate.asset_id.clone(),
        })?;
    let proof = FailureRetryProof {
        schema_version: FAILED_RETRY_POLICY_SCHEMA_VERSION,
        policy_generation: FAILED_RETRY_POLICY_GENERATION.to_string(),
        category: candidate.kind,
        attempt: candidate.attempt.saturating_add(1),
        last_failure_stage: failure.stage.clone(),
        last_failure_kind: candidate.kind,
        last_failure_recorded_at: failure.recorded_at.clone(),
        last_failure_digest: failure_digest(&failure),
        failure_count_at_admission: manifest.get(&candidate.asset_id)?.failures.len(),
        admitted_at_unix_seconds,
        retry_state: candidate.policy.retry_state,
    };
    manifest.record_proof(
        &candidate.asset_id,
        FAILURE_RETRY_PROOF,
        serde_json::to_value(proof)?,
    )?;
    manifest.recover_failed_for_retry(&candidate.asset_id, candidate.policy.retry_state)?;
    Ok(())
}

fn failed_retry_attempt(
    record: &AssetRecord,
    kind: FailureKind,
    policy: FailedRetryPolicy,
) -> Result<u64, ()> {
    let Some(proof) = record.proofs.get(FAILURE_RETRY_PROOF) else {
        return Ok(0);
    };
    let proof = serde_json::from_value::<FailureRetryProof>(proof.clone()).map_err(|_| ())?;
    if proof.schema_version != FAILED_RETRY_POLICY_SCHEMA_VERSION
        || proof.policy_generation != FAILED_RETRY_POLICY_GENERATION
        || proof.attempt == 0
        || proof.last_failure_kind != proof.category
    {
        return Err(());
    }
    let prior_policy = failed_retry_policy(proof.category).ok_or(())?;
    let expected_failure_count = proof.failure_count_at_admission.checked_add(1).ok_or(())?;
    if proof.retry_state != prior_policy.retry_state
        || proof.failure_count_at_admission == 0
        || record.failures.len() != expected_failure_count
    {
        return Err(());
    }
    let prior = record
        .failures
        .get(proof.failure_count_at_admission.saturating_sub(1))
        .ok_or(())?;
    if prior.stage != proof.last_failure_stage
        || prior.recorded_at != proof.last_failure_recorded_at
        || failure_digest(prior) != proof.last_failure_digest
        || failure_kind_for(record, prior) != Some(proof.last_failure_kind)
        || failure_kind_for(record, record.failures.last().ok_or(())?) != Some(kind)
    {
        return Err(());
    }
    if proof.category == kind {
        (proof.retry_state == policy.retry_state)
            .then_some(proof.attempt)
            .ok_or(())
    } else {
        Ok(0)
    }
}

fn has_retry_blocking_proof(record: &AssetRecord) -> bool {
    RETRY_BLOCKING_PROOFS
        .iter()
        .any(|proof_key| record.proofs.contains_key(*proof_key))
}

fn failed_retry_source_proofs_are_valid(record: &AssetRecord) -> bool {
    if !original_asset_resolver_source_proofs_are_valid(record) {
        return false;
    }
    let Some(nas) = record
        .proofs
        .get("nas")
        .and_then(|proof| serde_json::from_value::<NasRawProof>(proof.clone()).ok())
    else {
        return false;
    };
    let Some(original) = record
        .proofs
        .get("original_asset")
        .and_then(|proof| serde_json::from_value::<OriginalAssetProof>(proof.clone()).ok())
    else {
        return false;
    };
    record.raw_path.file_name().and_then(OsStr::to_str) == Some(original.filename.as_str())
        && original.size_bytes == nas.size_bytes
        && original.matched_raw_sha256 == nas.sha256
        && !original.record_name.trim().is_empty()
        && !original.record_change_tag.trim().is_empty()
        && !original.record_type.trim().is_empty()
        && !original.zone_name.trim().is_empty()
}

fn terminalize_failure_for_review(
    manifest: &mut Manifest,
    asset_id: &str,
    kind: FailureKind,
    reason_code: &'static str,
    attempts_exhausted: u64,
    applied_at_unix_seconds: u64,
) -> Result<(), ManifestError> {
    let failure =
        manifest
            .get(asset_id)?
            .failures
            .last()
            .ok_or_else(|| ManifestError::UnknownAsset {
                asset_id: asset_id.to_string(),
            })?;
    let proof = FailureReviewProof {
        schema_version: FAILED_RETRY_POLICY_SCHEMA_VERSION,
        reason_code: reason_code.to_string(),
        policy_generation: FAILED_RETRY_POLICY_GENERATION.to_string(),
        last_failure_stage: failure.stage.clone(),
        last_failure_kind: kind,
        last_failure_recorded_at: failure.recorded_at.clone(),
        last_failure_digest: failure_digest(failure),
        attempts_exhausted,
        current_attempt: attempts_exhausted,
        applied_at_unix_seconds,
    };
    manifest.terminalize_failed_with_proof(
        asset_id,
        FAILURE_REVIEW_PROOF,
        serde_json::to_value(proof)?,
    )?;
    Ok(())
}

fn failure_digest(failure: &FailureRecord) -> String {
    let mut hasher = Sha256::new();
    hasher.update(failure.stage.as_bytes());
    hasher.update([0]);
    hasher.update(failure.message.as_bytes());
    hasher.update([0]);
    hasher.update(failure.recorded_at.as_bytes());
    hasher.update([0]);
    hasher.update(
        failure
            .kind
            .map(FailureKind::as_str)
            .unwrap_or("legacy")
            .as_bytes(),
    );
    format!("{:x}", hasher.finalize())
}

fn last_failure_kind(record: &AssetRecord) -> Option<FailureKind> {
    let failure = record.failures.last()?;
    failure_kind_for(record, failure)
}

fn failure_kind_for(record: &AssetRecord, failure: &FailureRecord) -> Option<FailureKind> {
    failure
        .kind
        .or_else(|| legacy_failure_kind(record, failure))
}

fn legacy_failure_kind(record: &AssetRecord, failure: &FailureRecord) -> Option<FailureKind> {
    match (failure.stage.as_str(), failure.message.as_str()) {
        ("heic_verify", "HEIC verification failed: visual_content_ok") => {
            Some(FailureKind::HeicVisualContent)
        }
        ("heic_verify", "HEIC verification failed: visual_match_ok") => {
            Some(FailureKind::HeicVisualMatch)
        }
        ("conversion", "conversion command timed out after 120000 ms: heif-enc") => {
            Some(FailureKind::ConversionTimedOut)
        }
        ("conversion", "raw_staging command timed out after 120000 ms: icloudpd-optimizer") => {
            Some(FailureKind::RawStagingTimedOut)
        }
        ("conversion", "metadata command failed: exiftool exited with exit status: 1") => {
            Some(FailureKind::ConversionMetadataFailed)
        }
        _ => legacy_path_bearing_failure_kind(record, failure),
    }
}

fn legacy_path_bearing_failure_kind(
    record: &AssetRecord,
    failure: &FailureRecord,
) -> Option<FailureKind> {
    if failure.stage != "conversion" {
        return None;
    }
    let output_name = format!("{}.heic", record.asset_id);
    let oriented_name = format!("{}.oriented-preview.jpg", record.asset_id);
    let raw_extension = record.raw_path.extension()?.to_str()?;
    let staged_name = format!("{}.staged-raw.{raw_extension}", record.asset_id);
    if legacy_path_message_matches(
        &failure.message,
        "converted output is missing or unreadable at ",
        &oriented_name,
        LEGACY_OUTPUT_UNREADABLE_SUFFIX,
    ) {
        Some(FailureKind::ConversionOutputUnreadable)
    } else if legacy_path_message_matches(
        &failure.message,
        "converted output already exists at ",
        &output_name,
        "; refusing to overwrite without an explicit overwrite policy",
    ) {
        Some(FailureKind::ConversionOutputAlreadyExists)
    } else if legacy_path_message_matches(
        &failure.message,
        "staged RAW already exists at ",
        &staged_name,
        "; refusing to overwrite",
    ) {
        Some(FailureKind::StagedRawAlreadyExists)
    } else if legacy_path_message_matches(
        &failure.message,
        "RAW has neither PreviewImage nor JpgFromRaw embedded preview: ",
        &staged_name,
        "",
    ) {
        Some(FailureKind::EmbeddedPreviewUnavailable)
    } else {
        None
    }
}

fn legacy_path_message_matches(
    message: &str,
    prefix: &str,
    expected_filename: &str,
    suffix: &str,
) -> bool {
    let Some(path_and_suffix) = message.strip_prefix(prefix) else {
        return false;
    };
    path_and_suffix
        .strip_suffix(suffix)
        .and_then(|path| Path::new(path).file_name().and_then(OsStr::to_str))
        == Some(expected_filename)
}

fn increment_static_count(counts: &mut BTreeMap<&'static str, usize>, key: &'static str) {
    *counts.entry(key).or_default() += 1;
}

fn conversion_output_still_matches_proof(record: &AssetRecord) -> bool {
    let Some(value) = record.proofs.get("conversion") else {
        return false;
    };
    let Ok(proof) = serde_json::from_value::<ConversionResultProof>(value.clone()) else {
        return false;
    };
    let Ok(metadata) = fs::metadata(&proof.heic_path) else {
        return false;
    };
    metadata.is_file()
        && metadata.len() == proof.size_bytes
        && hash_file_sha256(&proof.heic_path).is_ok_and(|hash| hash == proof.heic_sha256)
}

fn conversion_proof_has_expected_shape(record: &AssetRecord) -> bool {
    let Some(value) = record.proofs.get("conversion") else {
        return false;
    };
    let Ok(proof) = serde_json::from_value::<ConversionResultProof>(value.clone()) else {
        return false;
    };
    !proof.heic_path.as_os_str().is_empty()
        && proof.size_bytes > 0
        && proof.heic_sha256.len() == 64
        && proof
            .heic_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
}

fn hash_file_sha256(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

struct OriginalAssetResolutionCandidate {
    asset_id: String,
    source_captured_unix_seconds: u64,
}

pub(crate) fn active_lifecycle_asset_ids_for_config(
    config: &MonitorConfig,
    manifest: &Manifest,
) -> Vec<String> {
    let limit = config.max_lifecycle_per_scan;
    if !config.rolling_lifecycle {
        return active_lifecycle_asset_ids(manifest, limit);
    }
    active_lifecycle_asset_ids_with_conversion_reserve(
        manifest,
        limit,
        rolling_lifecycle_active_conversion_reserve(config, limit),
    )
}

fn active_lifecycle_asset_ids(manifest: &Manifest, limit: usize) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }

    let mut active_ids = lifecycle_continuation_asset_ids(manifest, limit);
    let remaining = limit.saturating_sub(active_ids.len());
    if remaining == 0 {
        return active_ids;
    }

    active_ids.extend(densest_original_asset_resolution_windows(
        manifest,
        remaining,
        &active_ids,
    ));
    active_ids
}

fn active_lifecycle_asset_ids_with_conversion_reserve(
    manifest: &Manifest,
    limit: usize,
    conversion_reserve: usize,
) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }
    let conversion_reserve = conversion_reserve.min(limit);
    if conversion_reserve == 0 {
        return active_lifecycle_asset_ids(manifest, limit);
    }

    let conversion_ids = conversion_ready_lifecycle_asset_ids(manifest, conversion_reserve);
    if conversion_ids.is_empty() {
        return active_lifecycle_asset_ids(manifest, limit);
    }

    let conversion_id_set = conversion_ids.iter().cloned().collect::<BTreeSet<_>>();
    let non_conversion_limit = limit.saturating_sub(conversion_ids.len());
    let mut active_ids = lifecycle_continuation_asset_ids_excluding(
        manifest,
        non_conversion_limit,
        &conversion_id_set,
    );
    active_ids.extend(conversion_ids);

    let remaining = limit.saturating_sub(active_ids.len());
    if remaining > 0 {
        active_ids.extend(densest_original_asset_resolution_windows(
            manifest,
            remaining,
            &active_ids,
        ));
    }
    active_ids
}

fn rolling_lifecycle_active_conversion_reserve(config: &MonitorConfig, limit: usize) -> usize {
    if limit == 0 {
        return 0;
    }
    let configured_convert_slots = config
        .rolling_convert_stage_count
        .unwrap_or_else(|| config.jobs.max(1).div_ceil(2));
    configured_convert_slots
        .saturating_mul(2)
        .max(1)
        .min(limit / 2)
        .min(limit)
}

fn is_lifecycle_candidate(record: &AssetRecord) -> bool {
    matches!(
        record.state,
        State::NasVerified
            | State::Converted
            | State::ConversionVerified
            | State::UploadVerified
            | State::DeleteEligible
            | State::DeleteApproved
    )
}

fn is_lifecycle_continuation_candidate(record: &AssetRecord) -> bool {
    (record.state == State::Failed && adjusted_source_required_proof(record).is_ok())
        || matches!(
            record.state,
            State::Converted
                | State::ConversionVerified
                | State::UploadVerified
                | State::DeleteEligible
                | State::DeleteApproved
        )
        || (record.state == State::NasVerified && record.proofs.contains_key("original_asset"))
}

fn lifecycle_continuation_asset_ids(manifest: &Manifest, limit: usize) -> Vec<String> {
    lifecycle_continuation_asset_ids_excluding(manifest, limit, &BTreeSet::new())
}

fn lifecycle_continuation_asset_ids_excluding(
    manifest: &Manifest,
    limit: usize,
    excluded_asset_ids: &BTreeSet<String>,
) -> Vec<String> {
    let mut candidates = manifest
        .records()
        .values()
        .filter(|record| is_lifecycle_continuation_candidate(record))
        .filter(|record| !excluded_asset_ids.contains(&record.asset_id))
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        lifecycle_continuation_priority(left)
            .cmp(&lifecycle_continuation_priority(right))
            .then_with(|| raw_size_bytes_from_record(right).cmp(&raw_size_bytes_from_record(left)))
            .then_with(|| left.asset_id.cmp(&right.asset_id))
    });
    candidates
        .into_iter()
        .take(limit)
        .map(|record| record.asset_id.clone())
        .collect()
}

fn conversion_ready_lifecycle_asset_ids(manifest: &Manifest, limit: usize) -> Vec<String> {
    let mut candidates = manifest
        .records()
        .values()
        .filter(|record| record.state == State::NasVerified)
        .filter(|record| record.proofs.contains_key("original_asset"))
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        raw_size_bytes_from_record(right)
            .cmp(&raw_size_bytes_from_record(left))
            .then_with(|| left.asset_id.cmp(&right.asset_id))
    });
    candidates
        .into_iter()
        .take(limit)
        .map(|record| record.asset_id.clone())
        .collect()
}

fn lifecycle_continuation_priority(record: &AssetRecord) -> u8 {
    match record.state {
        State::DeleteApproved => 0,
        State::DeleteEligible => 1,
        State::UploadVerified if record.proofs.contains_key("icloudpd_local_mirror") => 2,
        State::UploadVerified => 3,
        State::ConversionVerified if record.proofs.contains_key("original_asset") => 4,
        State::Failed if adjusted_source_required_proof(record).is_ok() => 5,
        State::NasVerified if record.proofs.contains_key("original_asset") => 6,
        State::Converted if record.proofs.contains_key("original_asset") => 7,
        State::ConversionVerified => 8,
        State::Converted => 9,
        _ => 10,
    }
}

fn densest_original_asset_resolution_windows(
    manifest: &Manifest,
    limit: usize,
    already_active_ids: &[String],
) -> Vec<String> {
    if limit == 0 {
        return Vec::new();
    }

    let mut candidates = manifest
        .records()
        .values()
        .filter(|record| !active_lifecycle_allows(Some(already_active_ids), &record.asset_id))
        .filter(|record| {
            matches!(record.state, State::NasVerified | State::ConversionVerified)
                && !record.proofs.contains_key("original_asset")
        })
        .filter_map(original_asset_resolution_candidate)
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        left.source_captured_unix_seconds
            .cmp(&right.source_captured_unix_seconds)
            .then_with(|| left.asset_id.cmp(&right.asset_id))
    });

    let mut selected = Vec::new();
    while selected.len() < limit && !candidates.is_empty() {
        let remaining = limit.saturating_sub(selected.len());
        let Some(best_start) =
            densest_original_asset_resolution_window_start(&candidates, remaining)
        else {
            break;
        };
        let window_start = candidates[best_start].source_captured_unix_seconds;
        let window_end = candidates[best_start..]
            .iter()
            .position(|candidate| {
                candidate
                    .source_captured_unix_seconds
                    .saturating_sub(window_start)
                    > ORIGINAL_ASSET_RESOLVE_BATCH_WINDOW_SECONDS
            })
            .map(|offset| best_start + offset)
            .unwrap_or(candidates.len());
        let take_count = window_end.saturating_sub(best_start).min(remaining);
        selected.extend(
            candidates
                .drain(best_start..best_start + take_count)
                .map(|candidate| candidate.asset_id),
        );
    }
    selected
}

fn densest_original_asset_resolution_window_start(
    candidates: &[OriginalAssetResolutionCandidate],
    limit: usize,
) -> Option<usize> {
    if candidates.is_empty() || limit == 0 {
        return None;
    }

    let mut best_start = 0;
    let mut best_count = 0;
    let mut end = 0;
    for start in 0..candidates.len() {
        while end < candidates.len()
            && candidates[end]
                .source_captured_unix_seconds
                .saturating_sub(candidates[start].source_captured_unix_seconds)
                <= ORIGINAL_ASSET_RESOLVE_BATCH_WINDOW_SECONDS
        {
            end += 1;
        }
        let count = end.saturating_sub(start).min(limit);
        if count > best_count {
            best_start = start;
            best_count = count;
        }
    }
    (best_count > 0).then_some(best_start)
}

fn original_asset_resolution_candidate(
    record: &AssetRecord,
) -> Option<OriginalAssetResolutionCandidate> {
    let source_captured_unix_seconds = record
        .proofs
        .get("source_age")
        .and_then(|proof| proof.get("source_captured_unix_seconds"))
        .and_then(|captured_at| captured_at.as_u64())?;
    Some(OriginalAssetResolutionCandidate {
        asset_id: record.asset_id.clone(),
        source_captured_unix_seconds,
    })
}

fn active_lifecycle_allows(active_lifecycle_asset_ids: Option<&[String]>, asset_id: &str) -> bool {
    active_lifecycle_asset_ids
        .map(|asset_ids| asset_ids.iter().any(|active_id| active_id == asset_id))
        .unwrap_or(true)
}

fn original_asset_resolution_target_batches(
    manifest: &Manifest,
    config: &MonitorConfig,
    active_lifecycle_asset_ids: Option<&[String]>,
) -> Result<Vec<Vec<CloudKitOriginalAssetResolveTarget>>, MonitorError> {
    let mut targets = manifest
        .records()
        .values()
        .filter(|record| {
            active_lifecycle_allows(active_lifecycle_asset_ids, &record.asset_id)
                && matches!(
                    record.state,
                    State::NasVerified | State::Converted | State::ConversionVerified
                )
                && !record.proofs.contains_key("original_asset")
        })
        .map(|record| original_asset_resolve_target(manifest, &record.asset_id, config))
        .collect::<Result<Vec<_>, MonitorError>>()?;
    targets.sort_by(|left, right| {
        left.source_captured_unix_seconds
            .cmp(&right.source_captured_unix_seconds)
            .then_with(|| left.asset_id.cmp(&right.asset_id))
    });
    targets.truncate(config.max_lifecycle_per_scan);

    let mut batches: Vec<Vec<CloudKitOriginalAssetResolveTarget>> = Vec::new();
    let mut current_batch: Vec<CloudKitOriginalAssetResolveTarget> = Vec::new();
    let mut current_batch_start = 0;
    for target in targets {
        if current_batch.is_empty() {
            current_batch_start = target.source_captured_unix_seconds;
            current_batch.push(target);
            continue;
        }
        if target
            .source_captured_unix_seconds
            .saturating_sub(current_batch_start)
            <= ORIGINAL_ASSET_RESOLVE_BATCH_WINDOW_SECONDS
        {
            current_batch.push(target);
        } else {
            batches.push(current_batch);
            current_batch = vec![target];
            current_batch_start = current_batch[0].source_captured_unix_seconds;
        }
    }
    if !current_batch.is_empty() {
        batches.push(current_batch);
    }
    Ok(batches)
}

fn verify_converted_heic(
    manifest: &Manifest,
    asset_id: &str,
    timeout_seconds: u64,
) -> Result<VerifiedHeic, MonitorError> {
    let record = manifest.get(asset_id)?;
    let conversion = decode_monitor_proof::<ConversionResultProof>(record, "conversion")?;
    command_status_ok(
        "heif-info",
        &[conversion.heic_path.as_path()],
        timeout_seconds,
    )?;
    let orientation = command_stdout(
        "exiftool",
        &["-s", "-s", "-s", "-n", "-Orientation"],
        [conversion.heic_path.as_path()],
        timeout_seconds,
    )?;
    let metadata_copied = orientation.trim() == "1";
    let oriented_preview = oriented_preview_path(&conversion.heic_path);
    let visual_metrics =
        visual_metrics_for_conversion(&oriented_preview, &conversion.heic_path, timeout_seconds)?;
    let visual_match_ok = visual_metrics
        .reference_error
        .is_some_and(visual_match_is_within_bounds);
    let visual_content_ok = heic_has_visual_content(visual_metrics.candidate_stdev);

    Ok(VerifiedHeic {
        proof: HeicVerificationProof {
            heic_path: conversion.heic_path,
            heic_sha256: conversion.heic_sha256,
            size_bytes: conversion.size_bytes,
            heif_info_ok: true,
            metadata_copied,
            visual_content_ok,
            visual_match_ok,
            visual_rmse_ppm: visual_metrics
                .reference_error
                .map(|metrics| normalized_metric_ppm(metrics.rmse)),
            visual_mae_ppm: visual_metrics
                .reference_error
                .map(|metrics| normalized_metric_ppm(metrics.mae)),
        },
        visual_metrics,
    })
}

fn original_asset_resolve_target(
    manifest: &Manifest,
    asset_id: &str,
    config: &MonitorConfig,
) -> Result<CloudKitOriginalAssetResolveTarget, MonitorError> {
    let record = manifest.get(asset_id)?;
    let nas = decode_monitor_proof::<NasRawProof>(record, "nas")?;
    let source_age = decode_monitor_proof::<SourceAgeProof>(record, "source_age")?;
    let filename = record
        .raw_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .ok_or(WorkflowError::EmptyProofField { field: "filename" })?
        .to_string();
    Ok(CloudKitOriginalAssetResolveTarget {
        asset_id: asset_id.to_string(),
        raw_size_bytes: nas.size_bytes,
        source_captured_unix_seconds: source_age.source_captured_unix_seconds,
        capture_tolerance_seconds: config.capture_tolerance_seconds,
        filename,
        matched_raw_sha256: nas.sha256,
        replacement_candidate: None,
    })
}

fn raw_size_bytes(manifest: &Manifest, asset_id: &str) -> Result<u64, MonitorError> {
    let record = manifest.get(asset_id)?;
    Ok(decode_monitor_proof::<NasRawProof>(record, "nas")?.size_bytes)
}

fn heic_size_bytes(manifest: &Manifest, asset_id: &str) -> Result<u64, MonitorError> {
    let record = manifest.get(asset_id)?;
    Ok(decode_monitor_proof::<HeicVerificationProof>(record, "heic")?.size_bytes)
}

fn decode_monitor_proof<T: serde::de::DeserializeOwned>(
    record: &AssetRecord,
    proof_key: &'static str,
) -> Result<T, MonitorError> {
    let value = record
        .proofs
        .get(proof_key)
        .ok_or_else(|| WorkflowError::MissingProof {
            asset_id: record.asset_id.clone(),
            proof_key: proof_key.to_string(),
        })?;
    serde_json::from_value(value.clone())
        .map_err(|source| WorkflowError::ProofDecode {
            asset_id: record.asset_id.clone(),
            proof_key,
            source,
        })
        .map_err(MonitorError::Workflow)
}

fn required_path<'a>(
    value: &'a Option<PathBuf>,
    field: &'static str,
) -> Result<&'a Path, MonitorError> {
    value.as_deref().ok_or_else(|| MonitorError::InvalidConfig {
        message: format!("{field} is required"),
    })
}

fn oriented_preview_path(heic_path: &Path) -> PathBuf {
    let mut preview_path = heic_path.to_path_buf();
    preview_path.set_extension("oriented-preview.jpg");
    preview_path
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RgbPreview {
    width: u32,
    height: u32,
    pixels: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct VisualMetrics {
    candidate_stdev: f64,
    reference_error: Option<VisualErrorMetrics>,
    direct_reference_error: Option<VisualErrorMetrics>,
    match_basis: VisualMatchBasis,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct VisualErrorMetrics {
    rmse: f64,
    mae: f64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VisualMatchBasis {
    Direct,
    CodecNormalized,
    MissingReference,
}

impl VisualMatchBasis {
    fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::CodecNormalized => "codec_normalized",
            Self::MissingReference => "missing_reference",
        }
    }
}

fn append_visual_verification_event_fields(fields: &mut serde_json::Value, metrics: VisualMetrics) {
    let Some(fields) = fields.as_object_mut() else {
        return;
    };
    fields.insert(
        "visual_match_basis".to_string(),
        json!(metrics.match_basis.as_str()),
    );
    fields.insert(
        "visual_rmse_ppm".to_string(),
        json!(
            metrics
                .reference_error
                .map(|error| normalized_metric_ppm(error.rmse))
        ),
    );
    fields.insert(
        "visual_mae_ppm".to_string(),
        json!(
            metrics
                .reference_error
                .map(|error| normalized_metric_ppm(error.mae))
        ),
    );
    fields.insert(
        "direct_visual_rmse_ppm".to_string(),
        json!(
            metrics
                .direct_reference_error
                .map(|error| normalized_metric_ppm(error.rmse))
        ),
    );
    fields.insert(
        "direct_visual_mae_ppm".to_string(),
        json!(
            metrics
                .direct_reference_error
                .map(|error| normalized_metric_ppm(error.mae))
        ),
    );
}

#[derive(Clone, Debug)]
struct VerifiedHeic {
    proof: HeicVerificationProof,
    visual_metrics: VisualMetrics,
}

fn visual_metrics_for_conversion(
    reference: &Path,
    candidate: &Path,
    timeout_seconds: u64,
) -> Result<VisualMetrics, MonitorError> {
    visual_metrics_for_conversion_with_sips(
        reference,
        candidate,
        timeout_seconds,
        Path::new("sips"),
    )
}

fn visual_metrics_for_conversion_with_sips(
    reference: &Path,
    candidate: &Path,
    timeout_seconds: u64,
    sips_program: &Path,
) -> Result<VisualMetrics, MonitorError> {
    let candidate_preview_path = verification_preview_path(candidate, "heic");
    let reference_preview_path = verification_preview_path(candidate, "raw");
    let codec_normalized_reference_path = codec_normalized_reference_path(candidate);
    let codec_normalized_candidate_preview_path =
        verification_preview_path(candidate, "codec-normalized-candidate");
    let codec_normalized_reference_preview_path =
        verification_preview_path(&codec_normalized_reference_path, "heic");
    let result = (|| {
        if reference.exists() {
            render_visual_preview_pair_with_sips(
                sips_program,
                candidate,
                &candidate_preview_path,
                reference,
                &reference_preview_path,
                timeout_seconds,
            )?;
        } else {
            render_visual_preview_with_sips(
                sips_program,
                candidate,
                &candidate_preview_path,
                timeout_seconds,
            )?;
        }
        let candidate_preview = read_rgb_preview(&candidate_preview_path)?;
        let candidate_stdev = rgb_standard_deviation(&candidate_preview.pixels);
        let Some(direct_reference_error) = reference
            .exists()
            .then(|| {
                let reference_preview = read_rgb_preview(&reference_preview_path)?;
                normalized_rgb_error_metrics(&reference_preview, &candidate_preview)
            })
            .transpose()?
        else {
            return Ok(VisualMetrics {
                candidate_stdev,
                reference_error: None,
                direct_reference_error: None,
                match_basis: VisualMatchBasis::MissingReference,
            });
        };

        if !heic_has_visual_content(candidate_stdev)
            || visual_match_is_within_bounds(direct_reference_error)
        {
            return Ok(VisualMetrics {
                candidate_stdev,
                reference_error: Some(direct_reference_error),
                direct_reference_error: Some(direct_reference_error),
                match_basis: VisualMatchBasis::Direct,
            });
        }

        encode_codec_normalized_reference(
            sips_program,
            reference,
            &codec_normalized_reference_path,
            timeout_seconds,
        )?;
        render_visual_preview_pair_with_sips(
            sips_program,
            candidate,
            &codec_normalized_candidate_preview_path,
            &codec_normalized_reference_path,
            &codec_normalized_reference_preview_path,
            timeout_seconds,
        )?;
        let codec_normalized_candidate_preview =
            read_rgb_preview(&codec_normalized_candidate_preview_path)?;
        let codec_normalized_reference_preview =
            read_rgb_preview(&codec_normalized_reference_preview_path)?;
        let codec_normalized_error = normalized_rgb_error_metrics(
            &codec_normalized_reference_preview,
            &codec_normalized_candidate_preview,
        )?;
        Ok(VisualMetrics {
            candidate_stdev: rgb_standard_deviation(&codec_normalized_candidate_preview.pixels),
            reference_error: Some(codec_normalized_error),
            direct_reference_error: Some(direct_reference_error),
            match_basis: VisualMatchBasis::CodecNormalized,
        })
    })();
    let _ = fs::remove_file(candidate_preview_path);
    let _ = fs::remove_file(reference_preview_path);
    let _ = fs::remove_file(codec_normalized_candidate_preview_path);
    let _ = fs::remove_file(codec_normalized_reference_preview_path);
    let _ = fs::remove_file(codec_normalized_reference_path);
    result
}

fn codec_normalized_reference_path(candidate: &Path) -> PathBuf {
    let mut reference_path = candidate.to_path_buf();
    reference_path.set_extension("codec-normalized-reference.heic");
    reference_path
}

fn encode_codec_normalized_reference(
    sips_program: &Path,
    reference: &Path,
    output_path: &Path,
    timeout_seconds: u64,
) -> Result<(), MonitorError> {
    let mut command = Command::new(sips_program);
    command
        .args(["-s", "format", "heic", "-s", "formatOptions", "100"])
        .arg(reference)
        .arg("--out")
        .arg(output_path);
    let output = run_external_command_with_timeout("sips", command, timeout_seconds)?;
    if !output.status.success() {
        return Err(MonitorError::CommandFailed {
            program: "sips",
            message: format!("exited with {}", output.status),
        });
    }
    let metadata = fs::metadata(output_path).map_err(|source| MonitorError::ReadMetadata {
        path: output_path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(MonitorError::CommandFailed {
            program: "sips",
            message: format!(
                "codec-normalized reference was not created at {}",
                output_path.display()
            ),
        });
    }
    Ok(())
}

fn render_visual_preview_pair_with_sips(
    sips_program: &Path,
    candidate: &Path,
    candidate_output_path: &Path,
    reference: &Path,
    reference_output_path: &Path,
    timeout_seconds: u64,
) -> Result<(), MonitorError> {
    let sips_program = sips_program.to_path_buf();
    let candidate = candidate.to_path_buf();
    let candidate_output_path = candidate_output_path.to_path_buf();
    let reference = reference.to_path_buf();
    let reference_output_path = reference_output_path.to_path_buf();
    let candidate_sips_program = sips_program.clone();
    let candidate_handle = thread::spawn(move || {
        render_visual_preview_with_sips(
            &candidate_sips_program,
            &candidate,
            &candidate_output_path,
            timeout_seconds,
        )
    });
    let reference_handle = thread::spawn(move || {
        render_visual_preview_with_sips(
            &sips_program,
            &reference,
            &reference_output_path,
            timeout_seconds,
        )
    });
    let candidate_result = join_visual_preview_render(candidate_handle);
    let reference_result = join_visual_preview_render(reference_handle);
    candidate_result?;
    reference_result?;
    Ok(())
}

fn join_visual_preview_render(
    handle: thread::JoinHandle<Result<(), MonitorError>>,
) -> Result<(), MonitorError> {
    handle.join().map_err(|_| MonitorError::CommandFailed {
        program: "sips",
        message: "visual preview render worker panicked".to_string(),
    })?
}

fn verification_preview_path(heic_path: &Path, label: &str) -> PathBuf {
    let mut preview_path = heic_path.to_path_buf();
    preview_path.set_extension(format!("{label}-verify-preview.png"));
    preview_path
}

fn render_visual_preview_with_sips(
    sips_program: &Path,
    source: &Path,
    output_path: &Path,
    timeout_seconds: u64,
) -> Result<(), MonitorError> {
    let mut command = Command::new(sips_program);
    command
        .args(["-Z", MONITOR_VERIFY_PREVIEW_MAX_EDGE, "-s", "format", "png"])
        .arg(source)
        .arg("--out")
        .arg(output_path);
    let output = run_external_command_with_timeout("sips", command, timeout_seconds)?;
    if !output.status.success() {
        return Err(MonitorError::CommandFailed {
            program: "sips",
            message: format!("exited with {}", output.status),
        });
    }
    Ok(())
}

fn read_rgb_preview(path: &Path) -> Result<RgbPreview, MonitorError> {
    let image = image::open(path).map_err(|source| MonitorError::PreviewDecode {
        path: path.to_path_buf(),
        source,
    })?;
    let rgb = image.to_rgb8();
    Ok(RgbPreview {
        width: rgb.width(),
        height: rgb.height(),
        pixels: rgb.into_raw(),
    })
}

fn normalized_rgb_error_metrics(
    reference: &RgbPreview,
    candidate: &RgbPreview,
) -> Result<VisualErrorMetrics, MonitorError> {
    if reference.width != candidate.width || reference.height != candidate.height {
        return Err(MonitorError::PreviewDimensionMismatch {
            reference_width: reference.width,
            reference_height: reference.height,
            candidate_width: candidate.width,
            candidate_height: candidate.height,
        });
    }
    let (squared_error_sum, absolute_error_sum) = reference
        .pixels
        .iter()
        .zip(&candidate.pixels)
        .map(|(reference, candidate)| {
            let difference = f64::from(*reference) - f64::from(*candidate);
            (difference * difference, difference.abs())
        })
        .fold(
            (0.0, 0.0),
            |(squared_total, absolute_total), (squared, absolute)| {
                (squared_total + squared, absolute_total + absolute)
            },
        );
    let channel_count = reference.pixels.len();
    if channel_count == 0 {
        return Ok(VisualErrorMetrics {
            rmse: 0.0,
            mae: 0.0,
        });
    }
    Ok(VisualErrorMetrics {
        rmse: (squared_error_sum / channel_count as f64).sqrt() / 255.0,
        mae: absolute_error_sum / channel_count as f64 / 255.0,
    })
}

fn visual_match_is_within_bounds(metrics: VisualErrorMetrics) -> bool {
    metrics.rmse <= MONITOR_VISUAL_RMSE_MAX && metrics.mae <= MONITOR_VISUAL_MAE_MAX
}

fn normalized_metric_ppm(value: f64) -> u32 {
    (value.clamp(0.0, 1.0) * 1_000_000.0).round() as u32
}

fn rgb_standard_deviation(pixels: &[u8]) -> f64 {
    if pixels.is_empty() {
        return 0.0;
    }
    let channel_count = pixels.len() as f64;
    let mean = pixels
        .iter()
        .map(|channel| f64::from(*channel) / 255.0)
        .sum::<f64>()
        / channel_count;
    let variance = pixels
        .iter()
        .map(|channel| {
            let normalized = f64::from(*channel) / 255.0;
            let delta = normalized - mean;
            delta * delta
        })
        .sum::<f64>()
        / channel_count;
    variance.sqrt()
}

fn heic_has_visual_content(stdev: f64) -> bool {
    stdev >= MONITOR_HEIC_STDEV_MIN
}

fn command_status_ok(
    program: &'static str,
    paths: &[&Path],
    timeout_seconds: u64,
) -> Result<(), MonitorError> {
    let mut command = Command::new(program);
    command.args(paths);
    let output = run_external_command_with_timeout(program, command, timeout_seconds)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(MonitorError::CommandFailed {
            program,
            message: format!("exited with {}", output.status),
        })
    }
}

fn command_stdout<const N: usize>(
    program: &'static str,
    args: &[&str],
    paths: [&Path; N],
    timeout_seconds: u64,
) -> Result<String, MonitorError> {
    let mut command = Command::new(program);
    command.args(args);
    for path in paths {
        command.arg(path);
    }
    let output = run_external_command_with_timeout(program, command, timeout_seconds)?;
    if !output.status.success() {
        return Err(MonitorError::CommandFailed {
            program,
            message: format!("exited with {}", output.status),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn run_external_command_with_timeout(
    program: &'static str,
    command: Command,
    timeout_seconds: u64,
) -> Result<Output, MonitorError> {
    run_child_with_timeout(program, command, timeout_seconds, || {
        MonitorError::CommandTimeout {
            program,
            timeout_seconds,
        }
    })
}

fn record_monitor_failure(summary: &mut MonitorScanSummary, error: impl ToString) {
    summary.failures = summary.failures.saturating_add(1);
    summary.last_error = Some(error.to_string());
}

#[derive(Default)]
struct OriginalAssetResolutionMonitorSummary {
    applied: OriginalAssetResolutionBatchSummary,
    deferred: u64,
}

impl OriginalAssetResolutionMonitorSummary {
    fn manifest_changed(&self) -> bool {
        self.applied.exact_original > 0
            || self.applied.no_action > 0
            || self.applied.needs_review > 0
    }
}

fn record_original_asset_batch_outcome(
    manifest: &mut Manifest,
    targets: &[CloudKitOriginalAssetResolveTarget],
    destination: &CloudKitLibraryDestination,
    outcome: CloudKitOriginalAssetBatchResolveOutcome,
    observed_at_unix_seconds: u64,
    summary: &mut MonitorScanSummary,
) -> Result<OriginalAssetResolutionMonitorSummary, MonitorError> {
    let has_incomplete_transient = outcome.resolutions.values().any(|resolution| {
        matches!(
            resolution.disposition,
            crate::upload::CloudKitOriginalAssetResolveDisposition::IncompleteTransient
        )
    });
    let Some(inventory) = outcome.inventory else {
        return Ok(OriginalAssetResolutionMonitorSummary {
            deferred: targets.len() as u64,
            ..Default::default()
        });
    };
    if has_incomplete_transient {
        return Ok(OriginalAssetResolutionMonitorSummary {
            deferred: targets.len() as u64,
            ..Default::default()
        });
    }
    let applied = manifest.apply_original_asset_resolution_batch(OriginalAssetResolutionBatch {
        targets: targets.to_vec(),
        destination: destination.clone(),
        inventory,
        observed_at_unix_seconds,
        resolutions: outcome.resolutions,
    })?;
    summary.originals_resolved = summary
        .originals_resolved
        .saturating_add(applied.summary.exact_original);
    summary.no_action_records = summary
        .no_action_records
        .saturating_add(applied.summary.no_action);
    summary.needs_review_records = summary
        .needs_review_records
        .saturating_add(applied.summary.needs_review);
    Ok(OriginalAssetResolutionMonitorSummary {
        applied: applied.summary,
        deferred: 0,
    })
}

fn record_lifecycle_failure_for_assets(
    manifest: &mut Manifest,
    asset_ids: &[String],
    stage: &str,
    message: &str,
) -> Result<(), MonitorError> {
    for asset_id in asset_ids {
        record_stage_failure(manifest, asset_id, stage, message)?;
    }
    Ok(())
}

fn format_gib(bytes: u64) -> String {
    format!("{:.2}", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
}

enum VisitDecision {
    Continue,
    Stop,
}

fn visit_raw_paths(
    root: &Path,
    recursive: bool,
    visitor: &mut impl FnMut(PathBuf) -> Result<VisitDecision, MonitorError>,
) -> Result<VisitDecision, MonitorError> {
    visit_raw_paths_inner(root, recursive, visitor)
}

fn visit_raw_paths_inner(
    directory: &Path,
    recursive: bool,
    visitor: &mut impl FnMut(PathBuf) -> Result<VisitDecision, MonitorError>,
) -> Result<VisitDecision, MonitorError> {
    for entry in fs::read_dir(directory).map_err(|source| MonitorError::ReadDir {
        path: directory.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| MonitorError::ReadDirEntry {
            path: directory.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|source| MonitorError::ReadMetadata {
                path: path.clone(),
                source,
            })?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if recursive && metadata.is_dir() {
            if matches!(
                visit_raw_paths_inner(&path, recursive, visitor)?,
                VisitDecision::Stop
            ) {
                return Ok(VisitDecision::Stop);
            }
        } else if metadata.is_file()
            && is_raw_path(&path)
            && matches!(visitor(path)?, VisitDecision::Stop)
        {
            return Ok(VisitDecision::Stop);
        }
    }
    Ok(VisitDecision::Continue)
}

fn is_raw_path(path: &Path) -> bool {
    path.extension()
        .and_then(OsStr::to_str)
        .map(|extension| {
            RAW_EXTENSIONS
                .iter()
                .any(|candidate| extension.eq_ignore_ascii_case(candidate))
        })
        .unwrap_or(false)
}

fn monitor_asset_id(root: &Path, raw_path: &Path) -> Result<String, MonitorError> {
    let relative =
        raw_path
            .strip_prefix(root)
            .map_err(|_| MonitorError::RawOutsideDownloadRoot {
                root: root.to_path_buf(),
                path: raw_path.to_path_buf(),
            })?;
    let mut hasher = Sha256::new();
    hasher.update(relative.to_string_lossy().as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    Ok(format!("raw-{}", &digest[..16]))
}

fn workflow_error_is_not_ready(error: &WorkflowError) -> bool {
    matches!(
        error,
        WorkflowError::Proof(ProofError::RawTooNew { .. })
            | WorkflowError::Proof(ProofError::UnsupportedRawExtension { .. })
    )
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn write_json_atomic<T: Serialize>(destination: &Path, value: &T) -> io::Result<()> {
    let payload = serde_json::to_string_pretty(value)
        .map_err(|source| io::Error::new(io::ErrorKind::InvalidData, source))?;
    write_text_atomic(destination, &(payload + "\n"))
}

fn write_text_atomic(destination: &Path, payload: &str) -> io::Result<()> {
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temp_path = destination.with_extension(format!(
        "{}.tmp",
        destination
            .extension()
            .and_then(OsStr::to_str)
            .unwrap_or("file")
    ));
    let write_result = (|| -> io::Result<()> {
        let mut file = File::create(&temp_path)?;
        file.write_all(payload.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temp_path);
        return Err(error);
    }
    fs::rename(&temp_path, destination)?;
    Ok(())
}

fn validate_launchd_label(label: &str) -> Result<(), MonitorError> {
    if label.is_empty()
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(MonitorError::InvalidLaunchdLabel {
            label: label.to_string(),
        });
    }
    Ok(())
}

fn validate_bundle_identifier(bundle_id: &str) -> Result<(), MonitorError> {
    let has_separator = bundle_id.contains('.');
    if bundle_id.is_empty()
        || !has_separator
        || !bundle_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        || bundle_id.split('.').any(str::is_empty)
    {
        return Err(MonitorError::InvalidBundleIdentifier {
            bundle_id: bundle_id.to_string(),
        });
    }
    Ok(())
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("invalid monitor config: {message}")]
    InvalidConfig { message: String },
    #[error("failed to read monitor config {path}: {source}")]
    ReadConfig { path: PathBuf, source: io::Error },
    #[error("failed to parse monitor config {path}: {source}")]
    ParseConfig {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("failed to write monitor config {path}: {source}")]
    WriteConfig { path: PathBuf, source: io::Error },
    #[error("failed to read monitor stats {path}: {source}")]
    ReadStats { path: PathBuf, source: io::Error },
    #[error("failed to parse monitor stats {path}: {source}")]
    ParseStats {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("failed to write monitor stats {path}: {source}")]
    WriteStats { path: PathBuf, source: io::Error },
    #[error("failed to create directory {path}: {source}")]
    CreateDir { path: PathBuf, source: io::Error },
    #[error("failed to canonicalize monitor root {path}: {source}")]
    CanonicalizeRoot { path: PathBuf, source: io::Error },
    #[error(
        "monitor root {path} is not accessible for scanning: {source}; on macOS launchd jobs, grant the optimizer process access to network volumes or Full Disk Access"
    )]
    DownloadRootAccess { path: PathBuf, source: io::Error },
    #[error(
        "monitor root {path} failed the macOS scan preflight: {message}; grant the optimizer process access to network volumes or Full Disk Access"
    )]
    DownloadRootPreflight { path: PathBuf, message: String },
    #[error(
        "another icloudpd-optimizer monitor is already running for this manifest; lock held at {lock_path}"
    )]
    MonitorAlreadyRunning { lock_path: PathBuf },
    #[error("monitor locking is unsupported on this platform")]
    MonitorLockUnsupported,
    #[error("failed to use monitor lock {path}: {source}")]
    MonitorLockIo { path: PathBuf, source: io::Error },
    #[error("failed to read directory {path}: {source}")]
    ReadDir { path: PathBuf, source: io::Error },
    #[error("failed to read directory entry under {path}: {source}")]
    ReadDirEntry { path: PathBuf, source: io::Error },
    #[error("failed to read metadata for {path}: {source}")]
    ReadMetadata { path: PathBuf, source: io::Error },
    #[error("RAW path {path} is outside monitor root {root}")]
    RawOutsideDownloadRoot { root: PathBuf, path: PathBuf },
    #[error("manifest error: {0}")]
    Manifest(#[from] ManifestError),
    #[error("asset state store error: {0}")]
    StateStore(#[from] AssetStateStoreError),
    #[error("workflow error: {0}")]
    Workflow(#[from] WorkflowError),
    #[error("original asset reconciliation error: {0}")]
    OriginalAssetResolution(#[from] OriginalAssetResolutionError),
    #[error("conversion error: {0}")]
    Conversion(#[from] ConversionExecutionError),
    #[error("upload error: {0}")]
    Upload(#[from] UploadError),
    #[error("local mirror error: {0}")]
    LocalMirror(#[from] LocalMirrorError),
    #[error("local mirror proof timed out for {asset_id} after {timeout_seconds} seconds")]
    LocalMirrorTimeout {
        asset_id: String,
        timeout_seconds: u64,
    },
    #[error("upload timed out for {asset_id} after {timeout_seconds} seconds")]
    UploadWorkflowTimeout {
        asset_id: String,
        timeout_seconds: u64,
    },
    #[error("{stage} timed out for {asset_id} after {timeout_seconds} seconds")]
    DeleteWorkflowTimeout {
        stage: &'static str,
        asset_id: String,
        timeout_seconds: u64,
    },
    #[error("failed to run {program}: {source}")]
    CommandIo {
        program: &'static str,
        source: io::Error,
    },
    #[error("{program} failed: {message}")]
    CommandFailed {
        program: &'static str,
        message: String,
    },
    #[error("{program} timed out after {timeout_seconds} seconds")]
    CommandTimeout {
        program: &'static str,
        timeout_seconds: u64,
    },
    #[error("failed to decode visual preview {path}: {source}")]
    PreviewDecode {
        path: PathBuf,
        source: image::ImageError,
    },
    #[error(
        "visual preview dimensions differ: reference {reference_width}x{reference_height}, candidate {candidate_width}x{candidate_height}"
    )]
    PreviewDimensionMismatch {
        reference_width: u32,
        reference_height: u32,
        candidate_width: u32,
        candidate_height: u32,
    },
    #[error("invalid launchd label {label}")]
    InvalidLaunchdLabel { label: String },
    #[error("invalid bundle identifier {bundle_id}")]
    InvalidBundleIdentifier { bundle_id: String },
    #[error("failed to write launchd plist {path}: {source}")]
    WriteLaunchdPlist { path: PathBuf, source: io::Error },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adjusted_source::{
        AdjustedSourceError, CloudKitAdjustedSourceDownload, CloudKitAdjustedSourceResolver,
        CloudKitAdjustedSourceTransport,
    };
    use crate::upload::{
        CLOUDKIT_ORIGINAL_ASSET_RESOLVER_VERSION, CloudKitDatabaseScope,
        CloudKitOriginalAssetInventoryFingerprint, CloudKitOriginalAssetResolution,
        CloudKitOriginalAssetResolveDisposition, CloudKitOriginalAssetResolveObservations,
    };
    use filetime::{FileTime, set_file_mtime};
    use serde_json::Value;
    use serde_json::json;
    use std::io::Write;
    use url::Url;

    struct TestAdjustedSourceTransport {
        response: Value,
        bytes: Vec<u8>,
        destinations: Vec<CloudKitLibraryDestination>,
        lookup_calls: usize,
        download_calls: usize,
    }

    impl CloudKitAdjustedSourceTransport for TestAdjustedSourceTransport {
        fn post_records_lookup(
            &mut self,
            session: &CloudKitDeleteSession,
            _payload: Value,
        ) -> Result<Value, AdjustedSourceError> {
            self.lookup_calls = self.lookup_calls.saturating_add(1);
            self.destinations.push(session.zone.clone());
            Ok(self.response.clone())
        }

        fn download_resource_to_create_new(
            &mut self,
            _session: &CloudKitDeleteSession,
            _download_url: &Url,
            _expected_size_bytes: u64,
            temp_file: &mut File,
        ) -> Result<CloudKitAdjustedSourceDownload, AdjustedSourceError> {
            self.download_calls = self.download_calls.saturating_add(1);
            temp_file
                .write_all(&self.bytes)
                .expect("test adjusted-source transport should write JPEG bytes");
            temp_file
                .sync_all()
                .expect("test adjusted-source transport should sync JPEG bytes");
            Ok(CloudKitAdjustedSourceDownload {
                size_bytes: self.bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(&self.bytes)),
            })
        }
    }

    struct FailingAdjustedSourceTransport {
        lookup_calls: usize,
    }

    impl CloudKitAdjustedSourceTransport for FailingAdjustedSourceTransport {
        fn post_records_lookup(
            &mut self,
            _session: &CloudKitDeleteSession,
            _payload: Value,
        ) -> Result<Value, AdjustedSourceError> {
            self.lookup_calls = self.lookup_calls.saturating_add(1);
            Err(AdjustedSourceError::LookupTransport)
        }

        fn download_resource_to_create_new(
            &mut self,
            _session: &CloudKitDeleteSession,
            _download_url: &Url,
            _expected_size_bytes: u64,
            _temp_file: &mut File,
        ) -> Result<CloudKitAdjustedSourceDownload, AdjustedSourceError> {
            unreachable!("lookup failure must prevent a resource download")
        }
    }

    struct RacingAdjustedSourceTransport<'a> {
        response: Value,
        bytes: Vec<u8>,
        state_store: &'a AssetStateStore,
        newer_record: AssetRecord,
        raced: bool,
    }

    impl CloudKitAdjustedSourceTransport for RacingAdjustedSourceTransport<'_> {
        fn post_records_lookup(
            &mut self,
            _session: &CloudKitDeleteSession,
            _payload: Value,
        ) -> Result<Value, AdjustedSourceError> {
            if !self.raced {
                self.state_store
                    .persist_record(&self.newer_record)
                    .expect("racing writer should publish newer durable state");
                self.raced = true;
            }
            Ok(self.response.clone())
        }

        fn download_resource_to_create_new(
            &mut self,
            _session: &CloudKitDeleteSession,
            _download_url: &Url,
            _expected_size_bytes: u64,
            temp_file: &mut File,
        ) -> Result<CloudKitAdjustedSourceDownload, AdjustedSourceError> {
            temp_file
                .write_all(&self.bytes)
                .expect("racing transport should write JPEG bytes");
            temp_file
                .sync_all()
                .expect("racing transport should sync JPEG bytes");
            Ok(CloudKitAdjustedSourceDownload {
                size_bytes: self.bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(&self.bytes)),
            })
        }
    }

    #[derive(Default)]
    struct PoolAdjustedSourceCalls {
        lookup: usize,
        download: usize,
    }

    #[derive(Clone)]
    struct PoolFailingAdjustedSourceTransport {
        calls: Arc<Mutex<PoolAdjustedSourceCalls>>,
    }

    impl CloudKitAdjustedSourceTransport for PoolFailingAdjustedSourceTransport {
        fn post_records_lookup(
            &mut self,
            _session: &CloudKitDeleteSession,
            _payload: Value,
        ) -> Result<Value, AdjustedSourceError> {
            self.calls
                .lock()
                .expect("pool calls should not be poisoned")
                .lookup += 1;
            Err(AdjustedSourceError::LookupTransport)
        }

        fn download_resource_to_create_new(
            &mut self,
            _session: &CloudKitDeleteSession,
            _download_url: &Url,
            _expected_size_bytes: u64,
            _temp_file: &mut File,
        ) -> Result<CloudKitAdjustedSourceDownload, AdjustedSourceError> {
            self.calls
                .lock()
                .expect("pool calls should not be poisoned")
                .download += 1;
            unreachable!("a failing lookup must prevent a resource download")
        }
    }

    #[derive(Clone)]
    struct PoolRacingAdjustedSourceTransport {
        response: Value,
        bytes: Vec<u8>,
        state_store: Arc<AssetStateStore>,
        newer_record: AssetRecord,
        raced: Arc<Mutex<bool>>,
    }

    impl CloudKitAdjustedSourceTransport for PoolRacingAdjustedSourceTransport {
        fn post_records_lookup(
            &mut self,
            _session: &CloudKitDeleteSession,
            _payload: Value,
        ) -> Result<Value, AdjustedSourceError> {
            let mut raced = self.raced.lock().expect("race flag should not be poisoned");
            if !*raced {
                self.state_store
                    .persist_record(&self.newer_record)
                    .expect("racing writer should publish newer durable state");
                *raced = true;
            }
            Ok(self.response.clone())
        }

        fn download_resource_to_create_new(
            &mut self,
            _session: &CloudKitDeleteSession,
            _download_url: &Url,
            _expected_size_bytes: u64,
            temp_file: &mut File,
        ) -> Result<CloudKitAdjustedSourceDownload, AdjustedSourceError> {
            temp_file
                .write_all(&self.bytes)
                .expect("racing transport should write JPEG bytes");
            temp_file
                .sync_all()
                .expect("racing transport should sync JPEG bytes");
            Ok(CloudKitAdjustedSourceDownload {
                size_bytes: self.bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(&self.bytes)),
            })
        }
    }

    struct PanickingAdjustedSourceTransport;

    impl CloudKitAdjustedSourceTransport for PanickingAdjustedSourceTransport {
        fn post_records_lookup(
            &mut self,
            _session: &CloudKitDeleteSession,
            _payload: Value,
        ) -> Result<Value, AdjustedSourceError> {
            panic!("injected adjusted-source resolver panic")
        }

        fn download_resource_to_create_new(
            &mut self,
            _session: &CloudKitDeleteSession,
            _download_url: &Url,
            _expected_size_bytes: u64,
            _temp_file: &mut File,
        ) -> Result<CloudKitAdjustedSourceDownload, AdjustedSourceError> {
            unreachable!("a resolver panic must prevent a resource download")
        }
    }

    #[cfg(unix)]
    struct BlockingAdjustedSourceTransport {
        response: Value,
        bytes: Vec<u8>,
        lookup_started_sender: mpsc::Sender<()>,
        continue_receiver: mpsc::Receiver<()>,
    }

    #[cfg(unix)]
    impl CloudKitAdjustedSourceTransport for BlockingAdjustedSourceTransport {
        fn post_records_lookup(
            &mut self,
            _session: &CloudKitDeleteSession,
            _payload: Value,
        ) -> Result<Value, AdjustedSourceError> {
            self.lookup_started_sender
                .send(())
                .map_err(|_| AdjustedSourceError::LookupTransport)?;
            self.continue_receiver
                .recv()
                .map_err(|_| AdjustedSourceError::LookupTransport)?;
            Ok(self.response.clone())
        }

        fn download_resource_to_create_new(
            &mut self,
            _session: &CloudKitDeleteSession,
            _download_url: &Url,
            _expected_size_bytes: u64,
            temp_file: &mut File,
        ) -> Result<CloudKitAdjustedSourceDownload, AdjustedSourceError> {
            temp_file
                .write_all(&self.bytes)
                .map_err(|_| AdjustedSourceError::DownloadTransport)?;
            temp_file
                .sync_all()
                .map_err(|_| AdjustedSourceError::DownloadTransport)?;
            Ok(CloudKitAdjustedSourceDownload {
                size_bytes: self.bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(&self.bytes)),
            })
        }
    }

    #[cfg(unix)]
    fn fake_rolling_conversion_tools() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;

        let tools = tempfile::tempdir().expect("tool tempdir should be created");
        let write_tool = |name: &str, body: &str| {
            let path = tools.path().join(name);
            fs::write(&path, body).expect("fake conversion tool should be written");
            let mut permissions = fs::metadata(&path)
                .expect("fake conversion tool metadata should be readable")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions)
                .expect("fake conversion tool should be executable");
        };
        write_tool(
            "sips",
            r#"#!/bin/sh
out=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "--out" ]; then
    out="$arg"
    break
  fi
  previous="$arg"
done
[ -n "$out" ] || exit 41
printf 'fake-heic' > "$out"
"#,
        );
        write_tool(
            "heif-enc",
            r#"#!/bin/sh
out=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "-o" ]; then
    out="$arg"
  fi
  previous="$arg"
done
[ -n "$out" ] || exit 42
printf 'fake-heic' > "$out"
"#,
        );
        write_tool("exiftool", "#!/bin/sh\nexit 0\n");
        write_tool("heif-info", "#!/bin/sh\nexit 1\n");
        tools
    }

    #[cfg(unix)]
    const FAKE_NATIVE_VISUAL_VERIFIER_TIMEOUT_SECONDS: u64 = 5;

    #[cfg(unix)]
    struct FakeNativeVisualVerifier {
        _tempdir: tempfile::TempDir,
        program: PathBuf,
        reference: PathBuf,
        candidate: PathBuf,
        command_log: PathBuf,
    }

    #[cfg(unix)]
    impl FakeNativeVisualVerifier {
        fn new(
            direct_reference: RgbPreview,
            candidate: RgbPreview,
            normalized_reference: RgbPreview,
            fail_normalized_render: bool,
        ) -> Self {
            Self::new_with_failures(
                direct_reference,
                candidate,
                normalized_reference,
                fail_normalized_render,
                false,
            )
        }

        fn with_baseline_encode_failure(
            direct_reference: RgbPreview,
            candidate: RgbPreview,
            normalized_reference: RgbPreview,
        ) -> Self {
            Self::new_with_failures(
                direct_reference,
                candidate,
                normalized_reference,
                false,
                true,
            )
        }

        fn new_with_failures(
            direct_reference: RgbPreview,
            candidate: RgbPreview,
            normalized_reference: RgbPreview,
            fail_normalized_render: bool,
            fail_baseline_encode: bool,
        ) -> Self {
            use std::os::unix::fs::PermissionsExt;

            let tempdir = tempfile::tempdir().expect("tempdir should be created");
            let reference = tempdir.path().join("oriented-preview.jpg");
            let candidate_path = tempdir.path().join("candidate.heic");
            let direct_reference_png = tempdir.path().join("direct-reference.png");
            let candidate_png = tempdir.path().join("candidate.png");
            let normalized_reference_png = tempdir.path().join("normalized-reference.png");
            let command_log = tempdir.path().join("sips.log");
            let program = tempdir.path().join("sips");

            fs::write(&reference, b"oriented preview").expect("reference source should be created");
            fs::write(&candidate_path, b"candidate heic")
                .expect("candidate source should be created");
            write_rgb_preview_png(&direct_reference_png, &direct_reference);
            write_rgb_preview_png(&candidate_png, &candidate);
            write_rgb_preview_png(&normalized_reference_png, &normalized_reference);

            fs::write(
                &program,
                format!(
                    r#"#!/bin/sh
args="$*"
out=""
source=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--out" ]; then
    out="$2"
    break
  fi
  source="$1"
  shift
done
[ -n "$out" ] || exit 64
case "$out" in
  *.codec-normalized-reference.heic)
    case "$args" in
      *"formatOptions 100"*) ;;
      *) exit 65 ;;
    esac
    printf '%s\n' encode >> '{}'
    [ '{}' = "1" ] && {{
      printf '%s\n' encode_partial_failure >> '{}'
      printf 'partial' > "$out"
      printf '%s\n' partial_baseline_written >> '{}'
      exit 68
    }}
    printf 'heic' > "$out"
    exit 0
    ;;
esac
case "$source" in
  *candidate.heic)
    printf '%s\n' direct_candidate >> '{}'
    /bin/cp '{}' "$out"
    ;;
  *oriented-preview.jpg)
    printf '%s\n' direct_reference >> '{}'
    /bin/cp '{}' "$out"
    ;;
  *codec-normalized-reference.heic)
    printf '%s\n' normalized_reference >> '{}'
    [ '{}' = "1" ] && exit 66
    /bin/cp '{}' "$out"
    ;;
  *) exit 67 ;;
esac
"#,
                    command_log.display(),
                    if fail_baseline_encode { "1" } else { "0" },
                    command_log.display(),
                    command_log.display(),
                    command_log.display(),
                    candidate_png.display(),
                    command_log.display(),
                    direct_reference_png.display(),
                    command_log.display(),
                    if fail_normalized_render { "1" } else { "0" },
                    normalized_reference_png.display(),
                ),
            )
            .expect("fake sips script should be written");
            let mut permissions = fs::metadata(&program)
                .expect("fake sips metadata should be readable")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&program, permissions)
                .expect("fake sips script should be executable");

            Self {
                _tempdir: tempdir,
                program,
                reference,
                candidate: candidate_path,
                command_log,
            }
        }

        fn command_log(&self) -> Vec<String> {
            fs::read_to_string(&self.command_log)
                .unwrap_or_default()
                .lines()
                .map(str::to_string)
                .collect()
        }
    }

    #[cfg(unix)]
    fn write_rgb_preview_png(path: &Path, preview: &RgbPreview) {
        let image =
            image::RgbImage::from_raw(preview.width, preview.height, preview.pixels.clone())
                .expect("RGB preview pixels should match dimensions");
        image.save(path).expect("RGB preview PNG should be written");
    }

    struct FakeDeleteTransport {
        payloads: Vec<Value>,
        responses: Vec<Value>,
        response: Value,
    }

    impl CloudKitDeleteTransport for FakeDeleteTransport {
        fn post_records_modify(
            &mut self,
            _session: &CloudKitDeleteSession,
            payload: Value,
        ) -> Result<Value, UploadError> {
            self.payloads.push(payload);
            if self.responses.is_empty() {
                Ok(self.response.clone())
            } else {
                Ok(self.responses.remove(0))
            }
        }

        fn post_records_lookup(
            &mut self,
            _session: &CloudKitDeleteSession,
            _payload: Value,
        ) -> Result<Value, UploadError> {
            unreachable!("delete batch tests should not lookup records")
        }
    }

    struct RemoveRawBeforeDeleteResponseTransport {
        raw_path: PathBuf,
        payloads: Vec<Value>,
        response: Value,
    }

    impl CloudKitDeleteTransport for RemoveRawBeforeDeleteResponseTransport {
        fn post_records_modify(
            &mut self,
            _session: &CloudKitDeleteSession,
            payload: Value,
        ) -> Result<Value, UploadError> {
            self.payloads.push(payload);
            fs::remove_file(&self.raw_path)
                .expect("test transport should remove RAW after CloudKit request");
            Ok(self.response.clone())
        }

        fn post_records_lookup(
            &mut self,
            _session: &CloudKitDeleteSession,
            _payload: Value,
        ) -> Result<Value, UploadError> {
            unreachable!("delete batch tests should not lookup records")
        }
    }

    struct AmbiguousDeleteTransport {
        payloads: Vec<Value>,
        lookup_payloads: Vec<Value>,
        lookup_response: Value,
    }

    impl CloudKitDeleteTransport for AmbiguousDeleteTransport {
        fn post_records_modify(
            &mut self,
            _session: &CloudKitDeleteSession,
            payload: Value,
        ) -> Result<Value, UploadError> {
            self.payloads.push(payload);
            Err(UploadError::InvalidCloudKitDeleteResponse(
                "test transport lost the modify response",
            ))
        }

        fn post_records_lookup(
            &mut self,
            _session: &CloudKitDeleteSession,
            payload: Value,
        ) -> Result<Value, UploadError> {
            self.lookup_payloads.push(payload);
            Ok(self.lookup_response.clone())
        }
    }

    struct LookupThenModifyTransport {
        modify_payloads: Vec<Value>,
        lookup_payloads: Vec<Value>,
        lookup_response: Value,
        modify_response: Value,
    }

    impl CloudKitDeleteTransport for LookupThenModifyTransport {
        fn post_records_modify(
            &mut self,
            _session: &CloudKitDeleteSession,
            payload: Value,
        ) -> Result<Value, UploadError> {
            self.modify_payloads.push(payload);
            Ok(self.modify_response.clone())
        }

        fn post_records_lookup(
            &mut self,
            _session: &CloudKitDeleteSession,
            payload: Value,
        ) -> Result<Value, UploadError> {
            self.lookup_payloads.push(payload);
            Ok(self.lookup_response.clone())
        }
    }

    struct PersistConflictAfterModifyTransport {
        state_store: AssetStateStore,
        conflict_record: Option<AssetRecord>,
        payloads: Vec<Value>,
        response: Value,
    }

    impl CloudKitDeleteTransport for PersistConflictAfterModifyTransport {
        fn post_records_modify(
            &mut self,
            _session: &CloudKitDeleteSession,
            payload: Value,
        ) -> Result<Value, UploadError> {
            self.payloads.push(payload);
            self.state_store
                .persist_record(
                    &self
                        .conflict_record
                        .take()
                        .expect("test conflict should be injected once"),
                )
                .expect("test conflict should persist");
            Ok(self.response.clone())
        }

        fn post_records_lookup(
            &mut self,
            _session: &CloudKitDeleteSession,
            _payload: Value,
        ) -> Result<Value, UploadError> {
            unreachable!("successful modify should not require lookup")
        }
    }

    #[cfg(unix)]
    #[test]
    fn local_mirror_child_timeout_kills_stuck_command() {
        let mut command = Command::new("/bin/sleep");
        command.arg("5");

        let error = run_local_mirror_child_with_timeout("asset-timeout", command, 1)
            .expect_err("stuck child should time out");

        assert!(matches!(
            error,
            MonitorError::LocalMirrorTimeout {
                asset_id,
                timeout_seconds: 1
            } if asset_id == "asset-timeout"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn upload_child_timeout_kills_stuck_command() {
        let mut command = Command::new("/bin/sleep");
        command.arg("5");

        let error = run_upload_child_with_timeout("asset-timeout", command, 1)
            .expect_err("stuck upload child should time out");

        assert!(matches!(
            error,
            MonitorError::UploadWorkflowTimeout {
                asset_id,
                timeout_seconds: 1
            } if asset_id == "asset-timeout"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn child_timeout_covers_descendant_holding_output_pipe_open() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "/bin/sleep 5 &"]);
        let started = Instant::now();

        let error = run_external_command_with_timeout("sh", command, 1)
            .expect_err("descendant holding stdout open should time out");

        assert!(
            started.elapsed() < Duration::from_secs(3),
            "timeout should not wait for descendant output pipe close"
        );
        assert!(matches!(
            error,
            MonitorError::CommandTimeout {
                program: "sh",
                timeout_seconds: 1
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn child_output_capture_keeps_early_stdout_until_stderr_finishes() {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf out; exec 1>&-; /bin/sleep 1; printf err >&2"]);

        let output = run_external_command_with_timeout("sh", command, 3)
            .expect("staggered stdout and stderr should be captured");

        assert!(output.status.success());
        assert_eq!(output.stdout, b"out");
        assert_eq!(output.stderr, b"err");
    }

    #[test]
    fn parallel_asset_job_chunk_runs_jobs_concurrently() {
        let asset_ids = ["asset-a", "asset-b", "asset-c", "asset-d"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let started = Instant::now();

        let outcomes = run_parallel_asset_job_chunk(&asset_ids, |asset_id| {
            thread::sleep(Duration::from_millis(100));
            Ok(asset_id)
        });

        assert!(
            started.elapsed() < Duration::from_millis(250),
            "jobs should run in one parallel chunk, elapsed {:?}",
            started.elapsed()
        );
        assert_eq!(outcomes.len(), 4);
        assert!(outcomes.iter().all(|outcome| outcome.result.is_ok()));
    }

    #[cfg(unix)]
    #[test]
    fn upload_proof_children_can_run_concurrently() {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let helper_path = tempdir.path().join("fake-upload-proof-child");
        let barrier_dir = tempdir.path().join("upload-barrier");
        fs::create_dir(&barrier_dir).expect("barrier directory should be created");
        fs::write(
            &helper_path,
            format!(
                "#!/bin/sh\n\
                 /usr/bin/touch '{}/'$6\n\
                 attempts=0\n\
                 while [ ! -f '{}/asset-a' ] || [ ! -f '{}/asset-b' ]; do\n\
                   attempts=$((attempts + 1))\n\
                   [ \"$attempts\" -lt 200 ] || exit 97\n\
                   /bin/sleep 0.05\n\
                 done\n\
                 printf '%s\\n' '{{\"uploaded_heic_asset_id\":\"asset\",\"uploaded_heic_sha256\":\"sha\",\"database_scope\":\"private\",\"zone_name\":\"PrimarySync\",\"uploaded_heic_path\":\"/tmp/asset.heic\"}}'\n",
                barrier_dir.display(),
                barrier_dir.display(),
                barrier_dir.display(),
            ),
        )
        .expect("helper should be written");
        let mut permissions = fs::metadata(&helper_path)
            .expect("helper metadata should load")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&helper_path, permissions).expect("helper should be executable");
        let manifest_path = tempdir.path().join("manifest.json");
        let session_path = tempdir.path().join("session.json");
        let asset_ids = ["asset-a", "asset-b"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let outcomes = run_parallel_asset_job_chunk(&asset_ids, {
            let helper_path = helper_path.clone();
            move |asset_id| {
                run_upload_proof_child_executable_with_timeout(
                    &helper_path,
                    &manifest_path,
                    &asset_id,
                    &session_path,
                    15,
                )
            }
        });

        assert_eq!(outcomes.len(), 2);
        assert!(
            outcomes.iter().all(|outcome| outcome.result.is_ok()),
            "upload child failures: {:?}",
            outcomes
                .iter()
                .filter_map(|outcome| outcome.result.as_ref().err())
                .collect::<Vec<_>>()
        );
    }

    #[cfg(unix)]
    #[test]
    fn direct_upload_proof_child_receives_preverified_inputs() {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let helper_path = tempdir.path().join("fake-direct-upload-proof-child");
        let args_path = tempdir.path().join("args.txt");
        fs::write(
            &helper_path,
            format!(
                "#!/bin/sh\nfor arg in \"$@\"; do printf '%s\\n' \"$arg\"; done > '{}'\nprintf '%s\\n' '{{\"uploaded_heic_asset_id\":\"asset\",\"uploaded_heic_sha256\":\"sha\",\"database_scope\":\"shared\",\"zone_name\":\"SharedSync-test\",\"uploaded_heic_path\":\"/tmp/asset.heic\"}}'\n",
                args_path.display()
            ),
        )
        .expect("helper should be written");
        let mut permissions = fs::metadata(&helper_path)
            .expect("helper metadata should load")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&helper_path, permissions).expect("helper should be executable");

        let heic = HeicVerificationProof {
            heic_path: PathBuf::from("/tmp/asset.heic"),
            heic_sha256: "sha".to_string(),
            size_bytes: 123,
            heif_info_ok: true,
            metadata_copied: true,
            visual_content_ok: true,
            visual_match_ok: true,
            visual_rmse_ppm: None,
            visual_mae_ppm: None,
        };
        let destination = CloudKitLibraryDestination {
            database_scope: crate::upload::CloudKitDatabaseScope::Shared,
            zone_name: "SharedSync-test".to_string(),
        };
        let session_path = tempdir.path().join("session.json");

        let output = run_upload_proof_direct_child_executable_with_timeout(
            &helper_path,
            "raw-test",
            &heic,
            &destination,
            &session_path,
            5,
        )
        .expect("direct child output should parse");

        assert_eq!(output.proof.uploaded_heic_asset_id, "asset");
        let args = fs::read_to_string(args_path).expect("args should be captured");
        assert!(args.contains("upload-heic-proof-direct\n"));
        assert!(args.contains("--asset-id\nraw-test\n"));
        assert!(args.contains("--heic-path\n/tmp/asset.heic\n"));
        assert!(args.contains("--heic-sha256\nsha\n"));
        assert!(args.contains("--size-bytes\n123\n"));
        assert!(args.contains("--database-scope\nshared\n"));
        assert!(args.contains("--zone-name\nSharedSync-test\n"));
    }

    #[test]
    fn upload_proof_child_output_parses_optional_timings() {
        let output = parse_upload_proof_child_output(
            br#"{
                "uploaded_heic_asset_id": "asset",
                "uploaded_heic_sha256": "sha",
                "database_scope": "private",
                "zone_name": "PrimarySync",
                "uploaded_heic_path": "/tmp/asset.heic",
                "upload_timings": {
                    "create_upload_url_wall_time_millis": 1,
                    "signed_upload_wall_time_millis": 2,
                    "put_asset_wall_time_millis": 3,
                    "upload_status_wall_time_millis": 4,
                    "upload_status_polls": 5,
                    "total_wall_time_millis": 15
                }
            }"#,
        )
        .expect("output should parse");

        let timings = output.timings.expect("timings should be present");
        assert_eq!(timings.create_upload_url_wall_time_millis, 1);
        assert_eq!(timings.upload_status_polls, 5);
        assert_eq!(output.proof.uploaded_heic_asset_id, "asset");

        let output_without_timings = parse_upload_proof_child_output(
            br#"{
                "uploaded_heic_asset_id": "asset",
                "uploaded_heic_sha256": "sha",
                "database_scope": "private",
                "zone_name": "PrimarySync",
                "uploaded_heic_path": "/tmp/asset.heic"
            }"#,
        )
        .expect("legacy output should parse");
        assert!(output_without_timings.timings.is_none());
    }

    #[test]
    fn lifecycle_stage_finished_fields_include_wall_time_seconds() {
        let summary = MonitorScanSummary {
            uploads_completed: 2,
            ..MonitorScanSummary::default()
        };

        let fields =
            lifecycle_stage_finished_fields(LifecycleStage::UploadVerifiedHeics, &summary, 42);

        assert_eq!(fields["stage"], "upload_verified_heics");
        assert_eq!(fields["uploads_completed"], 2);
        assert_eq!(fields["wall_time_seconds"], 42);
    }

    #[cfg(unix)]
    #[test]
    fn external_command_timeout_reports_program_name() {
        let mut command = Command::new("/bin/sleep");
        command.arg("5");

        let error = run_external_command_with_timeout("sleep", command, 1)
            .expect_err("stuck external command should time out");

        assert!(matches!(
            error,
            MonitorError::CommandTimeout {
                program: "sleep",
                timeout_seconds: 1
            }
        ));
    }

    #[test]
    fn monitor_config_rejects_zero_upload_timeout() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.upload_timeout_seconds = 0;

        let error = config
            .validate()
            .expect_err("zero upload timeout should fail closed");

        assert!(matches!(
            error,
            MonitorError::InvalidConfig { message }
                if message == "upload_timeout_seconds must be greater than 0"
        ));
    }

    #[test]
    fn monitor_config_rejects_zero_heic_verify_timeout() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.heic_verify_timeout_seconds = 0;

        let error = config
            .validate()
            .expect_err("zero HEIC verify timeout should fail closed");

        assert!(matches!(
            error,
            MonitorError::InvalidConfig { message }
                if message == "heic_verify_timeout_seconds must be greater than 0"
        ));
    }

    #[test]
    fn monitor_config_defaults_and_validates_failed_retry_admission_limits() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        assert_eq!(config.max_failed_retry_admissions_per_scan, 16);
        assert_eq!(config.failed_retry_min_age_seconds, 300);

        config.max_failed_retry_admissions_per_scan = 0;
        assert!(matches!(
            config.validate(),
            Err(MonitorError::InvalidConfig { message })
                if message == "max_failed_retry_admissions_per_scan must be greater than 0"
        ));

        config.max_failed_retry_admissions_per_scan = 16;
        config.failed_retry_min_age_seconds = 0;
        assert!(matches!(
            config.validate(),
            Err(MonitorError::InvalidConfig { message })
                if message == "failed_retry_min_age_seconds must be greater than 0"
        ));
    }

    #[test]
    fn monitor_config_rejects_rolling_lifecycle_without_full_lifecycle() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.rolling_lifecycle = true;

        let error = config
            .validate()
            .expect_err("rolling lifecycle should require full lifecycle");

        assert!(matches!(
            error,
            MonitorError::InvalidConfig { message }
                if message == "rolling_lifecycle requires full_lifecycle"
        ));
    }

    #[test]
    fn monitor_config_rejects_state_database_inside_media_roots() {
        let config = MonitorConfig::new(
            "/nas/photos",
            "/nas/photos/state/manifest.json",
            "/local/heic",
        );

        let error = config
            .validate()
            .expect_err("state database on the NAS should fail closed");

        assert!(matches!(
            error,
            MonitorError::InvalidConfig { message }
                if message == "manifest and state database must be outside download, NAS, and mirror roots"
        ));
    }

    #[test]
    fn upload_verified_delete_candidate_requires_local_mirror_proof() {
        let mut record = lifecycle_record("asset-1", State::UploadVerified);
        assert!(!is_upload_verified_delete_candidate(&record));

        record.proofs.insert(
            "icloudpd_local_mirror".to_string(),
            json!({"sha256": "heic"}),
        );
        assert!(is_upload_verified_delete_candidate(&record));
    }

    #[test]
    fn startup_delete_audit_counts_uploaded_assets_not_deleted() {
        let mut manifest = Manifest::new();
        manifest.upsert(lifecycle_record(
            "uploaded-missing-mirror",
            State::UploadVerified,
        ));
        let mut uploaded_with_mirror =
            lifecycle_record("uploaded-with-mirror", State::UploadVerified);
        uploaded_with_mirror.proofs.insert(
            "icloudpd_local_mirror".to_string(),
            json!({"sha256": "heic"}),
        );
        manifest.upsert(uploaded_with_mirror);
        manifest.upsert(lifecycle_record("eligible", State::DeleteEligible));
        manifest.upsert(lifecycle_record("approved", State::DeleteApproved));
        manifest.upsert(lifecycle_record("deleted", State::Deleted));
        manifest.upsert(lifecycle_record("converted", State::ConversionVerified));

        let audit = startup_delete_audit(&manifest);

        assert_eq!(audit.upload_verified_missing_mirror, 1);
        assert_eq!(audit.upload_verified_with_mirror, 1);
        assert_eq!(audit.delete_eligible, 1);
        assert_eq!(audit.delete_approved, 1);
        assert_eq!(audit.uploaded_not_deleted_total(), 4);
    }

    #[test]
    fn startup_delete_audit_fields_are_readable() {
        let audit = StartupDeleteAudit {
            upload_verified_missing_mirror: 2,
            upload_verified_with_mirror: 3,
            delete_eligible: 5,
            delete_approved: 7,
        };

        let fields = startup_delete_audit_fields(&audit, 100);

        assert_eq!(fields["uploaded_not_deleted_total"], 17);
        assert_eq!(fields["upload_verified_missing_mirror"], 2);
        assert_eq!(fields["upload_verified_with_mirror"], 3);
        assert_eq!(fields["delete_eligible"], 5);
        assert_eq!(fields["delete_approved"], 7);
        assert_eq!(fields["active_lifecycle_capacity"], 100);
    }

    #[test]
    fn lifecycle_stage_sequence_prioritizes_terminal_work_when_auto_delete_is_enabled() {
        assert_eq!(
            lifecycle_stage_sequence(true),
            vec![
                LifecycleStage::DeleteOriginalAssets,
                LifecycleStage::RecordLocalMirrors,
                LifecycleStage::UploadVerifiedHeics,
                LifecycleStage::VerifyConvertedHeics,
                LifecycleStage::ResolveOriginalAssets,
            ]
        );
        assert_eq!(
            lifecycle_stage_sequence(false),
            vec![
                LifecycleStage::RecordLocalMirrors,
                LifecycleStage::UploadVerifiedHeics,
                LifecycleStage::VerifyConvertedHeics,
                LifecycleStage::ResolveOriginalAssets,
            ]
        );
    }

    #[test]
    fn rolling_lifecycle_worker_stage_sequence_advances_to_mirror_then_batch_delete() {
        assert_eq!(
            rolling_lifecycle_worker_stage_sequence_from(RollingAssetStep::ConvertHeic, true),
            vec![
                RollingAssetStep::ConvertHeic,
                RollingAssetStep::VerifyConvertedHeics,
                RollingAssetStep::UploadVerifiedHeics,
                RollingAssetStep::RecordLocalMirrors,
            ]
        );
        assert_eq!(
            rolling_lifecycle_worker_stage_sequence_from(RollingAssetStep::ConvertHeic, false),
            vec![
                RollingAssetStep::ConvertHeic,
                RollingAssetStep::VerifyConvertedHeics,
                RollingAssetStep::UploadVerifiedHeics,
                RollingAssetStep::RecordLocalMirrors,
            ]
        );

        assert_eq!(
            rolling_lifecycle_worker_stage_sequence_from(
                RollingAssetStep::UploadVerifiedHeics,
                true
            ),
            vec![
                RollingAssetStep::UploadVerifiedHeics,
                RollingAssetStep::RecordLocalMirrors,
            ]
        );
        assert_eq!(
            rolling_lifecycle_worker_stage_sequence_from(
                RollingAssetStep::RecordLocalMirrors,
                false
            ),
            vec![RollingAssetStep::RecordLocalMirrors]
        );
    }

    #[test]
    fn rolling_lifecycle_worker_count_uses_explicit_worker_slots_when_set() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.jobs = 8;
        assert_eq!(rolling_lifecycle_worker_count(&config, 100), 8);
        assert_eq!(rolling_lifecycle_worker_count(&config, 3), 3);

        config.rolling_worker_count = Some(64);
        assert_eq!(rolling_lifecycle_worker_count(&config, 100), 64);
        assert_eq!(rolling_lifecycle_worker_count(&config, 3), 3);
    }

    #[test]
    fn rolling_lifecycle_worker_queue_dedupes_asset_ids_without_reordering() {
        assert_eq!(
            dedupe_worker_asset_ids(vec![
                "asset-a".to_string(),
                "asset-b".to_string(),
                "asset-a".to_string(),
                "asset-c".to_string(),
                "asset-b".to_string(),
            ]),
            vec!["asset-a", "asset-b", "asset-c"]
        );
    }

    #[test]
    fn rolling_lifecycle_cpu_stage_jobs_cap_cpu_work_without_limiting_slots() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");

        config.jobs = 24;
        assert_eq!(rolling_lifecycle_cpu_stage_jobs(&config, 8), 8);

        config.jobs = 8;
        assert_eq!(rolling_lifecycle_cpu_stage_jobs(&config, 24), 8);

        config.jobs = 1;
        assert_eq!(rolling_lifecycle_cpu_stage_jobs(&config, 8), 1);

        config.jobs = 24;
        assert_eq!(rolling_lifecycle_cpu_stage_jobs(&config, 0), 1);

        config.jobs = 0;
        assert_eq!(rolling_lifecycle_cpu_stage_jobs(&config, 8), 1);
    }

    #[test]
    fn rolling_lifecycle_cpu_stage_jobs_use_configured_oversubscription_when_set() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.jobs = 24;
        config.rolling_cpu_stage_count = Some(12);

        assert_eq!(rolling_lifecycle_cpu_stage_jobs(&config, 8), 12);

        config.rolling_cpu_stage_count = Some(1);
        assert_eq!(rolling_lifecycle_cpu_stage_jobs(&config, 8), 1);
    }

    #[test]
    fn rolling_lifecycle_convert_stage_jobs_leave_cpu_room_for_verification() {
        let config = MonitorConfig::new("/download", "/manifest.json", "/heic");

        assert_eq!(rolling_lifecycle_convert_stage_jobs(&config, 8), 4);
        assert_eq!(rolling_lifecycle_convert_stage_jobs(&config, 7), 4);
        assert_eq!(rolling_lifecycle_convert_stage_jobs(&config, 2), 1);
        assert_eq!(rolling_lifecycle_convert_stage_jobs(&config, 1), 1);
        assert_eq!(rolling_lifecycle_convert_stage_jobs(&config, 0), 1);
    }

    #[test]
    fn rolling_lifecycle_convert_stage_jobs_use_configured_slots_when_set() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");

        config.rolling_convert_stage_count = Some(8);
        assert_eq!(rolling_lifecycle_convert_stage_jobs(&config, 8), 8);

        config.rolling_convert_stage_count = Some(99);
        assert_eq!(rolling_lifecycle_convert_stage_jobs(&config, 8), 8);

        config.rolling_convert_stage_count = Some(1);
        assert_eq!(rolling_lifecycle_convert_stage_jobs(&config, 8), 1);
    }

    #[test]
    fn rolling_lifecycle_mirror_stage_jobs_default_to_config_jobs() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");

        config.jobs = 12;
        config.rolling_worker_count = Some(64);
        assert_eq!(rolling_lifecycle_mirror_stage_jobs(&config), 12);

        config.jobs = 0;
        assert_eq!(rolling_lifecycle_mirror_stage_jobs(&config), 1);
    }

    #[test]
    fn rolling_lifecycle_cpu_permits_apply_only_to_cpu_bound_stages() {
        assert_eq!(
            rolling_asset_step_permit_policy(RollingAssetStep::ConvertHeic),
            RollingStagePermitPolicy::CpuAndConvert
        );
        assert_eq!(
            rolling_asset_step_permit_policy(RollingAssetStep::VerifyConvertedHeics),
            RollingStagePermitPolicy::Cpu
        );
        assert_eq!(
            rolling_asset_step_permit_policy(RollingAssetStep::UploadVerifiedHeics),
            RollingStagePermitPolicy::None
        );
        assert_eq!(
            rolling_asset_step_permit_policy(RollingAssetStep::RecordLocalMirrors),
            RollingStagePermitPolicy::Mirror
        );
        assert!(rolling_asset_step_uses_stage_permit(
            RollingAssetStep::RecordLocalMirrors
        ));
    }

    #[test]
    fn rolling_stage_permits_do_not_let_waiting_conversions_consume_cpu_slots() {
        let permits = Arc::new(RollingStagePermits::new(2, 1, 2));
        let first_convert = permits
            .acquire(RollingAssetStep::ConvertHeic)
            .expect("first convert should acquire")
            .expect("convert should use a permit");
        let (sender, receiver) = mpsc::channel();
        let waiting_permits = Arc::clone(&permits);
        let waiting_convert = thread::spawn(move || {
            let guard = waiting_permits
                .acquire(RollingAssetStep::ConvertHeic)
                .expect("waiting convert should eventually acquire")
                .expect("convert should use a permit");
            sender.send(()).expect("test receiver should be alive");
            drop(guard);
        });

        assert!(
            receiver.recv_timeout(Duration::from_millis(100)).is_err(),
            "second convert should wait for the convert lane"
        );
        let verify = permits
            .acquire(RollingAssetStep::VerifyConvertedHeics)
            .expect("verify should acquire a free CPU slot while convert waits")
            .expect("verify should use a CPU permit");
        assert!(
            receiver.recv_timeout(Duration::from_millis(100)).is_err(),
            "waiting convert should still be blocked by the convert lane"
        );
        drop(first_convert);
        drop(verify);
        receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("waiting convert should acquire after permits are released");
        waiting_convert
            .join()
            .expect("waiting convert thread should not panic");
    }

    #[test]
    fn rolling_stage_permits_limit_mirrors_without_consuming_cpu_slots() {
        let permits = Arc::new(RollingStagePermits::new(2, 1, 1));
        let first_mirror = permits
            .acquire(RollingAssetStep::RecordLocalMirrors)
            .expect("first mirror should acquire")
            .expect("mirror should use a permit");
        {
            let state = permits
                .state
                .lock()
                .expect("permit state should not be poisoned");
            assert_eq!(state.available_cpu_stage_slots, 2);
            assert_eq!(state.available_mirror_stage_slots, 0);
        }
        let verify = permits
            .acquire(RollingAssetStep::VerifyConvertedHeics)
            .expect("verify should acquire while mirror is running")
            .expect("verify should use a CPU permit");
        let (sender, receiver) = mpsc::channel();
        let waiting_permits = Arc::clone(&permits);
        let waiting_mirror = thread::spawn(move || {
            let guard = waiting_permits
                .acquire(RollingAssetStep::RecordLocalMirrors)
                .expect("waiting mirror should eventually acquire")
                .expect("mirror should use a permit");
            sender.send(()).expect("test receiver should be alive");
            drop(guard);
        });

        assert_eq!(permits.mirror_stage_slots(), 1);
        assert!(
            receiver.recv_timeout(Duration::from_millis(100)).is_err(),
            "second mirror should wait for the mirror lane"
        );
        drop(first_mirror);
        receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("waiting mirror should acquire after the mirror slot is released");
        drop(verify);
        waiting_mirror
            .join()
            .expect("waiting mirror thread should not panic");
    }

    #[test]
    fn rolling_conversion_reservations_hold_capacity_for_selected_resolvers() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.max_conversions_per_scan = 1;
        let reservations = Arc::new(RollingConversionReservations::new([
            "resolver-a".to_string()
        ]));
        let summary = Arc::new(Mutex::new(MonitorScanSummary::default()));

        let unreserved_reservations = Arc::clone(&reservations);
        let unreserved_summary = Arc::clone(&summary);
        let unreserved_config = config.clone();
        let unreserved = thread::spawn(move || {
            unreserved_reservations
                .claim_conversion_attempt(
                    "unreserved-conversion",
                    &unreserved_config,
                    &unreserved_summary,
                )
                .expect("unreserved worker capacity check should succeed")
        });
        assert!(
            !unreserved
                .join()
                .expect("unreserved worker should not panic"),
            "a non-resolver worker must not consume a selected resolver's conversion slot"
        );
        assert!(
            reservations
                .claim_conversion_attempt("resolver-a", &config, &summary)
                .expect("reserved resolver claim should succeed"),
            "the selected resolver must retain the conversion slot for its immediate next stage"
        );
        assert_eq!(
            summary
                .lock()
                .expect("summary should not be poisoned")
                .conversions_attempted,
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn rolling_resolve_retains_its_reserved_conversion_slot_until_immediate_convert() {
        const CHILD_ENV: &str = "ICLOUDPD_OPTIMIZER_ROLLING_SLOT_TEST_CHILD";
        if env::var_os(CHILD_ENV).is_none() {
            let tools = fake_rolling_conversion_tools();
            let status = Command::new(env::current_exe().expect("test binary path should resolve"))
                .args([
                    "--exact",
                    "monitor::tests::rolling_resolve_retains_its_reserved_conversion_slot_until_immediate_convert",
                    "--nocapture",
                ])
                .env(CHILD_ENV, "1")
                .env("PATH", tools.path())
                .status()
                .expect("isolated lifecycle test should run");
            assert!(status.success(), "isolated lifecycle test should pass");
            return;
        }

        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        fs::create_dir_all(&config.heic_output_dir).expect("HEIC root should be created");
        config.heic_output_dir =
            fs::canonicalize(&config.heic_output_dir).expect("HEIC root should canonicalize");
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        config.auto_delete = false;
        config.max_conversions_per_scan = 1;
        let raw_path = config.download_root.join("resolver.DNG");
        let raw_bytes = vec![b'r'; 64 * 1024];
        fs::write(&raw_path, &raw_bytes).expect("RAW should be written");
        let raw_path = fs::canonicalize(&raw_path).expect("RAW should canonicalize");
        let raw_sha256 = format!("{:x}", Sha256::digest(&raw_bytes));

        let mut manifest = Manifest::new();
        let mut resolver_record = policy_failed_record(
            "resolver-slot",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        );
        resolver_record.raw_path = raw_path.clone();
        resolver_record.proofs.insert(
            "nas".to_string(),
            json!({
                "canonical_path": raw_path,
                "relative_path": "resolver.DNG",
                "size_bytes": raw_bytes.len() as u64,
                "modified_unix_seconds": 100u64,
                "age_seconds": 2_592_000u64,
                "sha256": raw_sha256,
            }),
        );
        resolver_record
            .proofs
            .get_mut("original_asset")
            .expect("original proof")["size_bytes"] = json!(raw_bytes.len() as u64);
        resolver_record
            .proofs
            .get_mut("original_asset")
            .expect("original proof")["filename"] = json!("resolver.DNG");
        resolver_record
            .proofs
            .get_mut("original_asset")
            .expect("original proof")["matched_raw_sha256"] = json!(raw_sha256);
        manifest.upsert(resolver_record);
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("resolver marker should be admitted");
        let mut direct_record = lifecycle_record("direct-conversion", State::NasVerified);
        add_original_asset_proof(&mut direct_record);
        manifest.upsert(direct_record);

        let original = adjusted_source_recovery_original_proof(
            manifest
                .get("resolver-slot")
                .expect("marked resolver record"),
        )
        .expect("resolver source identity should be valid");
        let jpeg = test_adjusted_source_jpeg();
        let state_store = Arc::new(
            AssetStateStore::open_writer(
                &config.manifest_path,
                "test-writer",
                Duration::from_secs(60),
            )
            .expect("state store should open"),
        );
        state_store
            .persist_manifest_records(&manifest)
            .expect("initial records should persist");
        let shared_manifest = Arc::new(Mutex::new(manifest));
        let summary = Arc::new(Mutex::new(MonitorScanSummary {
            started_unix_seconds: 1_000,
            ..MonitorScanSummary::default()
        }));
        let reservations = Arc::new(RollingConversionReservations::new([
            "resolver-slot".to_string()
        ]));
        let stage_permits = Arc::new(RollingStagePermits::new(1, 1, 1));
        let (lookup_started_sender, lookup_started_receiver) = mpsc::channel();
        let (continue_sender, continue_receiver) = mpsc::channel();
        let worker_config = config.clone();
        let worker_state_store = Arc::clone(&state_store);
        let worker_manifest = Arc::clone(&shared_manifest);
        let worker_summary = Arc::clone(&summary);
        let worker_reservations = Arc::clone(&reservations);
        let worker_stage_permits = Arc::clone(&stage_permits);
        let worker_original = original.clone();
        let worker_jpeg = jpeg.clone();
        let worker = thread::spawn(move || {
            let base_read_session = test_delete_session();
            let mut resolver =
                CloudKitAdjustedSourceResolver::new(BlockingAdjustedSourceTransport {
                    response: test_adjusted_source_lookup_response(&worker_original, &worker_jpeg),
                    bytes: worker_jpeg,
                    lookup_started_sender,
                    continue_receiver,
                });
            let mut execution = RollingAssetExecutionContext {
                config: &worker_config,
                state_store: &worker_state_store,
                worker_id: 1,
                manifest: &worker_manifest,
                summary: &worker_summary,
                conversion_reservations: &worker_reservations,
                base_read_session: Some(&base_read_session),
                adjusted_source_resolver: Some(&mut resolver),
            };
            run_rolling_asset_lifecycle("resolver-slot", &worker_stage_permits, &mut execution)
        });

        match lookup_started_receiver.recv_timeout(Duration::from_secs(2)) {
            Ok(()) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let error = worker
                    .join()
                    .expect("resolver worker should not panic")
                    .expect_err("resolver worker should fail before lookup");
                panic!("resolver worker exited before lookup: {error}");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("resolver should pause before it completes");
            }
        }
        assert!(
            reservations
                .is_reserved("resolver-slot")
                .expect("reservation check should succeed")
        );
        assert_eq!(
            run_rolling_asset_conversion(
                &config,
                &state_store,
                "direct-conversion",
                &shared_manifest,
                &summary,
                &reservations,
            )
            .expect("direct conversion capacity check should succeed"),
            RollingAssetStepOutcome::skipped(),
            "a queued direct conversion must not steal the resolver's reserved slot"
        );
        assert_eq!(
            summary
                .lock()
                .expect("summary should not be poisoned")
                .conversions_attempted,
            0
        );
        continue_sender
            .send(())
            .expect("resolver should still be waiting");

        let delta = worker
            .join()
            .expect("resolver worker should not panic")
            .expect("resolver lifecycle should complete through conversion");
        assert_eq!(delta.adjusted_sources_resolved, 1);
        assert_eq!(delta.conversions_completed, 1);
        assert!(
            !reservations
                .is_reserved("resolver-slot")
                .expect("reservation check should succeed")
        );
        let summary = summary.lock().expect("summary should not be poisoned");
        assert_eq!(summary.conversions_attempted, 1);
        assert_eq!(summary.conversions_completed, 1);
        drop(summary);
        let manifest = shared_manifest
            .lock()
            .expect("manifest should not be poisoned");
        let resolved = manifest.get("resolver-slot").expect("resolved record");
        assert_eq!(resolved.state, State::Converted);
        assert!(!resolved.proofs.contains_key("upload"));
        assert!(!resolved.proofs.contains_key("delete"));
        assert_eq!(
            manifest
                .get("direct-conversion")
                .expect("direct record")
                .state,
            State::NasVerified
        );
    }

    #[test]
    fn rolling_resolver_error_releases_its_conversion_reservation_for_a_sibling() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.heic_output_dir).expect("HEIC root should be created");
        config.heic_output_dir =
            fs::canonicalize(&config.heic_output_dir).expect("HEIC root should canonicalize");
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        config.max_conversions_per_scan = 1;
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "resolver-error",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("resolver marker should be admitted");
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .expect("state store should open");
        state_store
            .persist_manifest_records(&manifest)
            .expect("initial record should persist");
        let shared_manifest = Arc::new(Mutex::new(manifest));
        let summary = Arc::new(Mutex::new(MonitorScanSummary {
            started_unix_seconds: 1_000,
            ..MonitorScanSummary::default()
        }));
        let original = adjusted_source_recovery_original_proof(
            shared_manifest
                .lock()
                .expect("shared manifest")
                .get("resolver-error")
                .expect("marked record"),
        )
        .expect("marked record should retain its source identity");
        let jpeg = test_adjusted_source_jpeg();
        let mut resolver = CloudKitAdjustedSourceResolver::new(TestAdjustedSourceTransport {
            response: test_adjusted_source_lookup_response(&original, &jpeg),
            bytes: jpeg,
            destinations: Vec::new(),
            lookup_calls: 0,
            download_calls: 0,
        });
        let reservations = Arc::new(RollingConversionReservations::new([
            "resolver-error".to_string()
        ]));
        let base_read_session = test_delete_session();
        let mut execution = RollingAssetExecutionContext {
            config: &config,
            state_store: &state_store,
            worker_id: 1,
            manifest: &shared_manifest,
            summary: &summary,
            conversion_reservations: &reservations,
            base_read_session: Some(&base_read_session),
            adjusted_source_resolver: Some(&mut resolver),
        };

        fail_next_adjusted_source_resolution_before_cas();
        let error = run_rolling_asset_lifecycle(
            "resolver-error",
            &Arc::new(RollingStagePermits::new(1, 1, 1)),
            &mut execution,
        )
        .expect_err("injected resolver error should leave the lifecycle");
        assert!(matches!(error, MonitorError::CommandFailed { .. }));
        assert!(
            reservations
                .claim_conversion_attempt("sibling-conversion", &config, &summary)
                .expect("sibling capacity claim should succeed"),
            "a resolver error must release its reservation before a sibling claims capacity"
        );
        assert_eq!(
            summary
                .lock()
                .expect("summary should not be poisoned")
                .conversions_attempted,
            1
        );
    }

    #[test]
    fn rolling_resolver_panic_releases_its_conversion_reservation_for_a_sibling() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.heic_output_dir).expect("HEIC root should be created");
        config.heic_output_dir =
            fs::canonicalize(&config.heic_output_dir).expect("HEIC root should canonicalize");
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        config.max_conversions_per_scan = 1;
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "resolver-panic",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("resolver marker should be admitted");
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .expect("state store should open");
        state_store
            .persist_manifest_records(&manifest)
            .expect("initial record should persist");
        let shared_manifest = Arc::new(Mutex::new(manifest));
        let summary = Arc::new(Mutex::new(MonitorScanSummary {
            started_unix_seconds: 1_000,
            ..MonitorScanSummary::default()
        }));
        let reservations = Arc::new(RollingConversionReservations::new([
            "resolver-panic".to_string()
        ]));
        let base_read_session = test_delete_session();
        let mut resolver = CloudKitAdjustedSourceResolver::new(PanickingAdjustedSourceTransport);
        let mut execution = RollingAssetExecutionContext {
            config: &config,
            state_store: &state_store,
            worker_id: 1,
            manifest: &shared_manifest,
            summary: &summary,
            conversion_reservations: &reservations,
            base_read_session: Some(&base_read_session),
            adjusted_source_resolver: Some(&mut resolver),
        };

        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_rolling_asset_lifecycle(
                "resolver-panic",
                &Arc::new(RollingStagePermits::new(1, 1, 1)),
                &mut execution,
            )
        }));
        assert!(unwind.is_err(), "injected resolver panic should unwind");
        assert!(
            reservations
                .claim_conversion_attempt("sibling-conversion", &config, &summary)
                .expect("sibling capacity claim should succeed"),
            "unwinding resolver work must release its reservation before a sibling claims capacity"
        );
        assert_eq!(
            summary
                .lock()
                .expect("summary should not be poisoned")
                .conversions_attempted,
            1
        );
    }

    #[test]
    fn rolling_lifecycle_preworker_resolver_runs_only_when_no_workers_are_progressable() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.jobs = 8;

        let mut manifest = Manifest::new();
        let mut ready = lifecycle_record("ready-to-convert", State::NasVerified);
        add_original_resolution_proofs(&mut ready, 1_000);
        add_original_asset_proof(&mut ready);
        manifest.upsert(ready);

        let mut unresolved = lifecycle_record("needs-original-match", State::NasVerified);
        add_original_resolution_proofs(&mut unresolved, 1_001);
        manifest.upsert(unresolved);

        let active_ids = vec![
            "ready-to-convert".to_string(),
            "needs-original-match".to_string(),
        ];

        assert!(rolling_lifecycle_should_resolve_before_workers(
            &manifest,
            &config,
            &active_ids,
            0,
        ));
        assert!(!rolling_lifecycle_should_resolve_before_workers(
            &manifest,
            &config,
            &active_ids,
            1,
        ));
        assert!(!rolling_lifecycle_should_resolve_before_workers(
            &manifest,
            &config,
            &["ready-to-convert".to_string()],
            1,
        ));
    }

    #[test]
    fn rolling_lifecycle_preworker_resolver_skips_unformed_targets() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.jobs = 8;

        let mut manifest = Manifest::new();
        manifest.upsert(lifecycle_record("missing-source-age", State::NasVerified));
        let active_ids = vec!["missing-source-age".to_string()];

        assert!(!rolling_lifecycle_should_resolve_before_workers(
            &manifest,
            &config,
            &active_ids,
            0,
        ));
    }

    #[test]
    fn rolling_lifecycle_preworker_resolver_does_not_delay_progressable_workers() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.jobs = 8;

        let mut manifest = Manifest::new();
        let mut unresolved = lifecycle_record("unresolved", State::NasVerified);
        add_original_resolution_proofs(&mut unresolved, 10_000);
        manifest.upsert(unresolved);
        let active_ids = vec!["unresolved".to_string()];

        assert!(!rolling_lifecycle_should_resolve_before_workers(
            &manifest,
            &config,
            &active_ids,
            1,
        ));
        assert!(rolling_lifecycle_should_resolve_before_workers(
            &manifest,
            &config,
            &active_ids,
            0,
        ));
    }

    #[test]
    fn rolling_lifecycle_resolver_batch_limit_scales_past_worker_slots() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.jobs = 8;
        config.rolling_original_resolve_batch_multiplier = 4;

        assert_eq!(rolling_lifecycle_resolve_batch_limit(&config, 100), 32);
        assert_eq!(rolling_lifecycle_resolve_batch_limit(&config, 3), 3);

        config.jobs = 0;
        assert_eq!(rolling_lifecycle_resolve_batch_limit(&config, 100), 4);
    }

    #[test]
    fn rolling_lifecycle_resolver_asset_ids_expand_resolution_window() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.max_lifecycle_per_scan = 4;
        config.rolling_original_resolve_active_window_multiplier = 3;

        let mut manifest = Manifest::new();
        manifest.upsert(lifecycle_record("active-delete", State::DeleteApproved));
        let mut active_ready = lifecycle_record("active-ready", State::NasVerified);
        add_original_asset_proof(&mut active_ready);
        manifest.upsert(active_ready);

        for index in 0..10 {
            let mut record = lifecycle_record(&format!("resolver-{index:02}"), State::NasVerified);
            add_original_resolution_proofs(&mut record, 10_000 + index);
            manifest.upsert(record);
        }

        let active_ids = vec!["active-delete".to_string(), "active-ready".to_string()];
        let resolver_ids = rolling_lifecycle_resolver_asset_ids(&manifest, &config, &active_ids);

        assert_eq!(resolver_ids.len(), 12);
        assert_eq!(&resolver_ids[..2], active_ids.as_slice());
        assert_eq!(
            resolver_ids[2..]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![
                "resolver-00",
                "resolver-01",
                "resolver-02",
                "resolver-03",
                "resolver-04",
                "resolver-05",
                "resolver-06",
                "resolver-07",
                "resolver-08",
                "resolver-09",
            ]
        );
    }

    #[test]
    fn rolling_lifecycle_worker_queue_skips_unresolved_nas_records() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;

        let mut manifest = Manifest::new();
        let mut unresolved = lifecycle_record("a-unresolved-nas", State::NasVerified);
        add_original_resolution_proofs(&mut unresolved, 1_000);
        manifest.upsert(unresolved);

        let mut ready = lifecycle_record("b-ready-nas", State::NasVerified);
        add_original_resolution_proofs(&mut ready, 1_100);
        add_original_asset_proof(&mut ready);
        manifest.upsert(ready);

        manifest.upsert(lifecycle_record("c-converted", State::Converted));
        let mut upload_blocked = lifecycle_record("d-upload-blocked", State::ConversionVerified);
        add_original_resolution_proofs(&mut upload_blocked, 1_200);
        manifest.upsert(upload_blocked);

        let active_ids = vec![
            "a-unresolved-nas".to_string(),
            "b-ready-nas".to_string(),
            "c-converted".to_string(),
            "d-upload-blocked".to_string(),
        ];

        assert_eq!(
            rolling_lifecycle_worker_asset_ids(
                &manifest,
                &config,
                &active_ids,
                active_ids.len(),
                1,
                &BTreeSet::new(),
            ),
            vec!["b-ready-nas", "c-converted"]
        );

        assert_eq!(
            rolling_lifecycle_worker_asset_ids(
                &manifest,
                &config,
                &active_ids,
                active_ids.len(),
                0,
                &BTreeSet::new(),
            ),
            vec!["c-converted"]
        );
    }

    #[test]
    fn terminal_reconciliation_states_stop_workers_and_are_not_progressable() {
        let config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        let mut manifest = Manifest::new();
        for (asset_id, state) in [
            ("no-action", State::NoAction),
            ("needs-review", State::NeedsReview),
        ] {
            manifest.upsert(lifecycle_record(asset_id, state));
        }
        let shared_manifest = Arc::new(Mutex::new(manifest.clone()));

        for asset_id in ["no-action", "needs-review"] {
            let record = manifest
                .get(asset_id)
                .expect("terminal record should exist");
            assert!(
                rolling_asset_terminal_state(&shared_manifest, asset_id)
                    .expect("terminal state check should succeed")
            );
            assert!(!rolling_lifecycle_record_can_run_worker_stage(
                record, &config, true,
            ));
            assert!(rolling_lifecycle_next_worker_step(record, &config, true).is_none());
        }
    }

    #[test]
    fn rolling_lifecycle_worker_queue_skips_assets_deferred_for_scan() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;

        let mut manifest = Manifest::new();
        manifest.upsert(lifecycle_record("a-waiting-mirror", State::UploadVerified));
        let mut ready = lifecycle_record("b-ready-nas", State::NasVerified);
        add_original_asset_proof(&mut ready);
        manifest.upsert(ready);

        let active_ids = vec!["a-waiting-mirror".to_string(), "b-ready-nas".to_string()];
        assert_eq!(
            rolling_lifecycle_worker_asset_ids(
                &manifest,
                &config,
                &active_ids,
                active_ids.len(),
                1,
                &BTreeSet::new(),
            ),
            vec!["a-waiting-mirror", "b-ready-nas"]
        );

        assert_eq!(
            rolling_lifecycle_worker_asset_ids(
                &manifest,
                &config,
                &active_ids,
                active_ids.len(),
                1,
                &BTreeSet::from(["a-waiting-mirror".to_string()]),
            ),
            vec!["b-ready-nas"]
        );
    }

    #[test]
    fn rolling_lifecycle_worker_queue_starts_at_real_next_step() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.full_lifecycle = true;
        config.auto_delete = true;

        let mut ready_to_convert = lifecycle_record("ready-to-convert", State::NasVerified);
        add_original_asset_proof(&mut ready_to_convert);
        assert_eq!(
            rolling_lifecycle_worker_stage_sequence(&ready_to_convert, &config),
            vec![
                RollingAssetStep::ConvertHeic,
                RollingAssetStep::VerifyConvertedHeics,
                RollingAssetStep::UploadVerifiedHeics,
                RollingAssetStep::RecordLocalMirrors,
            ]
        );

        let mut ready_to_upload = lifecycle_record("ready-to-upload", State::ConversionVerified);
        add_original_asset_proof(&mut ready_to_upload);
        assert_eq!(
            rolling_lifecycle_worker_stage_sequence(&ready_to_upload, &config),
            vec![
                RollingAssetStep::UploadVerifiedHeics,
                RollingAssetStep::RecordLocalMirrors,
            ]
        );

        let mut needs_resolver = lifecycle_record("needs-resolver", State::Converted);
        needs_resolver.proofs.insert(
            "heic".to_string(),
            json!({
                "heic_path": "/heic/needs-resolver.heic",
                "heic_sha256": "heic-sha",
                "size_bytes": 10u64,
            }),
        );
        assert!(
            rolling_lifecycle_worker_stage_sequence(&needs_resolver, &config).is_empty(),
            "converted HEIC without original_asset proof should wait for resolver feed"
        );
    }

    #[test]
    fn rolling_lifecycle_valid_marked_failed_record_starts_with_adjusted_source_resolution() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        config.max_lifecycle_per_scan = 1;

        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "needs-adjusted-source",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("valid adjusted-source marker should reserve lifecycle capacity");

        let record = manifest
            .get("needs-adjusted-source")
            .expect("marked record");
        assert_eq!(
            active_lifecycle_asset_ids_for_config(&config, &manifest),
            vec!["needs-adjusted-source"]
        );
        assert_eq!(
            rolling_lifecycle_worker_stage_sequence(record, &config),
            vec![
                RollingAssetStep::ResolveAdjustedSource,
                RollingAssetStep::ConvertHeic,
                RollingAssetStep::VerifyConvertedHeics,
                RollingAssetStep::UploadVerifiedHeics,
                RollingAssetStep::RecordLocalMirrors,
            ]
        );
    }

    #[test]
    fn rolling_worker_queue_caps_adjusted_resolvers_without_blocking_continuations() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;

        let mut manifest = Manifest::new();
        for asset_id in ["resolver-a", "resolver-b", "resolver-c"] {
            manifest.upsert(policy_failed_record(
                asset_id,
                "conversion",
                "RAW has no usable embedded preview",
                Some(FailureKind::EmbeddedPreviewUnavailable),
                "100.000000000Z",
            ));
        }
        manifest.upsert(lifecycle_record("continuation", State::Converted));
        admit_adjusted_source_required_assets(&mut manifest, 3, 3, 1_000)
            .expect("all marked resolver candidates should be admitted");
        let active_ids = vec![
            "resolver-a".to_string(),
            "resolver-b".to_string(),
            "resolver-c".to_string(),
            "continuation".to_string(),
        ];

        assert!(
            rolling_lifecycle_next_worker_step(
                manifest.get("resolver-a").expect("resolver record"),
                &config,
                false,
            )
            .is_none()
        );
        assert_eq!(
            rolling_lifecycle_worker_asset_ids(
                &manifest,
                &config,
                &active_ids,
                active_ids.len(),
                0,
                &BTreeSet::new(),
            ),
            vec!["continuation"]
        );
        assert_eq!(
            rolling_lifecycle_worker_asset_ids(
                &manifest,
                &config,
                &active_ids,
                active_ids.len(),
                1,
                &BTreeSet::new(),
            ),
            vec!["resolver-a", "continuation"]
        );
        assert_eq!(
            rolling_lifecycle_worker_asset_ids(
                &manifest,
                &config,
                &active_ids,
                active_ids.len(),
                2,
                &BTreeSet::new(),
            ),
            vec!["resolver-a", "resolver-b", "continuation"]
        );
    }

    #[test]
    fn rolling_adjusted_source_success_exact_cas_recovers_and_binds_private_or_shared_source() {
        for (database_scope, zone_name) in [
            (CloudKitDatabaseScope::Private, "PrimarySync"),
            (CloudKitDatabaseScope::Shared, "SharedSync"),
        ] {
            let tempdir = tempfile::tempdir().expect("tempdir should be created");
            let mut config = MonitorConfig::new(
                tempdir.path().join("download"),
                tempdir.path().join("manifest.json"),
                tempdir.path().join("heic"),
            );
            fs::create_dir_all(&config.heic_output_dir).expect("HEIC root should be created");
            config.heic_output_dir =
                fs::canonicalize(&config.heic_output_dir).expect("HEIC root should canonicalize");
            config.full_lifecycle = true;
            config.rolling_lifecycle = true;

            let mut manifest = Manifest::new();
            let mut record = policy_failed_record(
                "needs-adjusted-source",
                "conversion",
                "RAW has no usable embedded preview",
                Some(FailureKind::EmbeddedPreviewUnavailable),
                "100.000000000Z",
            );
            record
                .proofs
                .get_mut("original_asset")
                .expect("original proof")["database_scope"] = json!(database_scope);
            record
                .proofs
                .get_mut("original_asset")
                .expect("original proof")["zone_name"] = json!(zone_name);
            manifest.upsert(record);
            admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
                .expect("valid adjusted-source marker should be admitted");

            let state_store = AssetStateStore::open_writer(
                &config.manifest_path,
                "test-writer",
                Duration::from_secs(60),
            )
            .expect("state store should open");
            state_store
                .persist_manifest_records(&manifest)
                .expect("initial marked record should persist");
            let shared_manifest = Arc::new(Mutex::new(manifest));
            let summary = Arc::new(Mutex::new(MonitorScanSummary {
                started_unix_seconds: 1_000,
                ..MonitorScanSummary::default()
            }));
            let jpeg = test_adjusted_source_jpeg();
            let original = adjusted_source_recovery_original_proof(
                shared_manifest
                    .lock()
                    .expect("shared manifest")
                    .get("needs-adjusted-source")
                    .expect("marked record"),
            )
            .expect("marker source proof should be valid");
            let mut resolver = CloudKitAdjustedSourceResolver::new(TestAdjustedSourceTransport {
                response: test_adjusted_source_lookup_response(&original, &jpeg),
                bytes: jpeg.clone(),
                destinations: Vec::new(),
                lookup_calls: 0,
                download_calls: 0,
            });

            let outcome = run_rolling_adjusted_source_resolution_with(
                &config,
                &state_store,
                7,
                "needs-adjusted-source",
                &shared_manifest,
                &summary,
                &test_delete_session(),
                &mut resolver,
            )
            .expect("exact adjusted-source resolution should persist");

            assert_eq!(outcome, RollingAssetStepOutcome::completed());
            assert_eq!(
                summary
                    .lock()
                    .expect("rolling summary")
                    .adjusted_sources_resolved,
                1
            );
            let record = shared_manifest
                .lock()
                .expect("shared manifest")
                .get("needs-adjusted-source")
                .expect("recovered record")
                .clone();
            assert_eq!(record.state, State::NasVerified);
            let adjusted = record
                .proofs
                .get("adjusted_source")
                .expect("adjusted proof");
            assert_eq!(
                adjusted["localPath"],
                json!(
                    config
                        .heic_output_dir
                        .join("needs-adjusted-source.adjusted-source.jpg")
                )
            );
            assert_eq!(adjusted["databaseScope"], json!(database_scope));
            assert_eq!(adjusted["zoneName"], json!(zone_name));
            assert_eq!(
                rolling_lifecycle_worker_stage_sequence(&record, &config),
                vec![
                    RollingAssetStep::ConvertHeic,
                    RollingAssetStep::VerifyConvertedHeics,
                    RollingAssetStep::UploadVerifiedHeics,
                    RollingAssetStep::RecordLocalMirrors,
                ]
            );
            let transport = resolver.into_inner();
            assert_eq!(transport.lookup_calls, 1);
            assert_eq!(transport.download_calls, 1);
            assert_eq!(
                transport.destinations,
                vec![CloudKitLibraryDestination {
                    database_scope,
                    zone_name: zone_name.to_string(),
                }]
            );
            let persisted = state_store
                .load()
                .expect("persisted manifest")
                .get("needs-adjusted-source")
                .expect("persisted record")
                .clone();
            assert_eq!(persisted, record);
            assert!(
                !serde_json::to_string(&record)
                    .expect("record should serialize")
                    .contains("downloadURL")
            );
        }
    }

    #[test]
    fn rolling_adjusted_source_failure_preserves_marker_and_does_not_repeat_after_cas() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.heic_output_dir).expect("HEIC root should be created");
        config.heic_output_dir =
            fs::canonicalize(&config.heic_output_dir).expect("HEIC root should canonicalize");
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "fails-adjusted-source",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("valid adjusted-source marker should be admitted");
        let marker = manifest
            .get("fails-adjusted-source")
            .expect("marked record")
            .proofs[ADJUSTED_SOURCE_REQUIRED_PROOF]
            .clone();
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .expect("state store should open");
        state_store
            .persist_manifest_records(&manifest)
            .expect("initial marked record should persist");
        let shared_manifest = Arc::new(Mutex::new(manifest));
        let summary = Arc::new(Mutex::new(MonitorScanSummary {
            started_unix_seconds: 1_000,
            ..MonitorScanSummary::default()
        }));
        let mut resolver =
            CloudKitAdjustedSourceResolver::new(FailingAdjustedSourceTransport { lookup_calls: 0 });

        let first = run_rolling_adjusted_source_resolution_with(
            &config,
            &state_store,
            7,
            "fails-adjusted-source",
            &shared_manifest,
            &summary,
            &test_delete_session(),
            &mut resolver,
        )
        .expect("resolver failure should persist as a worker outcome");
        assert_eq!(first, RollingAssetStepOutcome::failed(true));
        assert_eq!(
            summary
                .lock()
                .expect("rolling summary")
                .adjusted_source_resolution_failures,
            1
        );
        let record = shared_manifest
            .lock()
            .expect("shared manifest")
            .get("fails-adjusted-source")
            .expect("failed record")
            .clone();
        assert_eq!(record.state, State::Failed);
        assert_eq!(record.proofs[ADJUSTED_SOURCE_REQUIRED_PROOF], marker);
        assert_eq!(record.failures.len(), 2);
        assert_eq!(record.failures[1].stage, "adjusted_source_resolve");
        assert_eq!(
            record.failures[1].kind,
            Some(FailureKind::AdjustedSourceResolveFailed)
        );

        let second = run_rolling_adjusted_source_resolution_with(
            &config,
            &state_store,
            7,
            "fails-adjusted-source",
            &shared_manifest,
            &summary,
            &test_delete_session(),
            &mut resolver,
        )
        .expect("stale marker should be skipped without another failure");
        assert_eq!(second, RollingAssetStepOutcome::skipped());
        assert_eq!(resolver.into_inner().lookup_calls, 1);
        assert_eq!(
            shared_manifest
                .lock()
                .expect("shared manifest")
                .get("fails-adjusted-source")
                .expect("failed record")
                .failures
                .len(),
            2
        );
    }

    #[test]
    fn rolling_adjusted_source_retry_waits_for_backoff_then_resumes_at_resolve() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        config.max_lifecycle_per_scan = 1;
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "retry-adjusted-source",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("first marker should be admitted");
        policy_failed_again_at(
            &mut manifest,
            "retry-adjusted-source",
            "adjusted_source_resolve",
            "resolver failed",
            FailureKind::AdjustedSourceResolveFailed,
            "400.000000000Z",
        );

        assert!(
            active_lifecycle_asset_ids_for_config(&config, &manifest).is_empty(),
            "a resolver failure must wait for the bounded retry admission"
        );
        let admission = admit_adjusted_source_required_assets(&mut manifest, 1, 1, 699)
            .expect("backoff evaluation should not mutate the marker");
        assert_eq!(admission.backoff, 1);
        assert!(active_lifecycle_asset_ids_for_config(&config, &manifest).is_empty());

        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 700)
            .expect("retry marker should be admitted after 300 seconds");
        let record = manifest
            .get("retry-adjusted-source")
            .expect("retry marker should remain failed until resolution");
        assert_eq!(
            rolling_lifecycle_worker_stage_sequence(record, &config).first(),
            Some(&RollingAssetStep::ResolveAdjustedSource)
        );
    }

    #[test]
    fn scan_retry_admission_terminalizes_exhausted_adjusted_source_lineage_before_rolling() {
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "exhausted-adjusted-source",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("first marker should be admitted");
        for (failed_at, re_admitted_at) in [(400, 700), (1_000, 1_300)] {
            policy_failed_again_at(
                &mut manifest,
                "exhausted-adjusted-source",
                "adjusted_source_resolve",
                "resolver failed",
                FailureKind::AdjustedSourceResolveFailed,
                &format!("{failed_at}.000000000Z"),
            );
            admit_adjusted_source_required_assets(&mut manifest, 1, 1, re_admitted_at)
                .expect("next bounded retry marker should be admitted");
        }
        policy_failed_again_at(
            &mut manifest,
            "exhausted-adjusted-source",
            "adjusted_source_resolve",
            "resolver failed",
            FailureKind::AdjustedSourceResolveFailed,
            "1600.000000000Z",
        );

        let admissions = admit_scan_retry_policies(&mut manifest, 1, 1, 300, 1, 300, 2_000)
            .expect("exhausted resolver lineage should be terminalized before worker selection");
        assert_eq!(admissions.adjusted_source_required.exhausted, 1);
        assert_eq!(
            manifest
                .get("exhausted-adjusted-source")
                .expect("exhausted record")
                .state,
            State::NeedsReview
        );
    }

    #[test]
    fn nonrolling_adjusted_source_resolution_never_calls_transport() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.heic_output_dir).expect("HEIC root should be created");
        config.full_lifecycle = true;
        config.rolling_lifecycle = false;
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "nonrolling-adjusted-source",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("marker should be admitted without authorizing a non-rolling resolver");
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .expect("state store should open");
        state_store
            .persist_manifest_records(&manifest)
            .expect("initial record should persist");
        let shared_manifest = Arc::new(Mutex::new(manifest));
        let summary = Arc::new(Mutex::new(MonitorScanSummary {
            started_unix_seconds: 1_000,
            ..MonitorScanSummary::default()
        }));
        let jpeg = test_adjusted_source_jpeg();
        let original = adjusted_source_recovery_original_proof(
            shared_manifest
                .lock()
                .expect("shared manifest")
                .get("nonrolling-adjusted-source")
                .expect("marked record"),
        )
        .expect("source proof should be valid");
        let mut resolver = CloudKitAdjustedSourceResolver::new(TestAdjustedSourceTransport {
            response: test_adjusted_source_lookup_response(&original, &jpeg),
            bytes: jpeg,
            destinations: Vec::new(),
            lookup_calls: 0,
            download_calls: 0,
        });

        assert_eq!(
            run_rolling_adjusted_source_resolution_with(
                &config,
                &state_store,
                7,
                "nonrolling-adjusted-source",
                &shared_manifest,
                &summary,
                &test_delete_session(),
                &mut resolver,
            )
            .expect("non-rolling resolver should safely skip"),
            RollingAssetStepOutcome::skipped()
        );
        let transport = resolver.into_inner();
        assert_eq!(transport.lookup_calls, 0);
        assert_eq!(transport.download_calls, 0);
    }

    #[test]
    fn rolling_adjusted_source_malformed_marker_never_calls_transport_or_mutates_record() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "tampered-adjusted-source",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("marker should be admitted before tampering");
        let mut tampered = manifest
            .get("tampered-adjusted-source")
            .expect("marked record")
            .clone();
        tampered
            .proofs
            .get_mut(ADJUSTED_SOURCE_REQUIRED_PROOF)
            .expect("marker proof")["asset_id"] = json!("different-asset");
        manifest.upsert(tampered);
        let before = manifest
            .get("tampered-adjusted-source")
            .expect("tampered record")
            .clone();
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .expect("state store should open");
        state_store
            .persist_manifest_records(&manifest)
            .expect("tampered record should persist unchanged");
        let shared_manifest = Arc::new(Mutex::new(manifest));
        let summary = Arc::new(Mutex::new(MonitorScanSummary {
            started_unix_seconds: 1_000,
            ..MonitorScanSummary::default()
        }));
        let mut resolver = CloudKitAdjustedSourceResolver::new(TestAdjustedSourceTransport {
            response: json!(null),
            bytes: Vec::new(),
            destinations: Vec::new(),
            lookup_calls: 0,
            download_calls: 0,
        });

        assert_eq!(
            run_rolling_adjusted_source_resolution_with(
                &config,
                &state_store,
                7,
                "tampered-adjusted-source",
                &shared_manifest,
                &summary,
                &test_delete_session(),
                &mut resolver,
            )
            .expect("malformed marker should skip without a resolver request"),
            RollingAssetStepOutcome::skipped()
        );
        let transport = resolver.into_inner();
        assert_eq!(transport.lookup_calls, 0);
        assert_eq!(transport.download_calls, 0);
        assert_eq!(
            shared_manifest
                .lock()
                .expect("shared manifest")
                .get("tampered-adjusted-source")
                .expect("record"),
            &before
        );
        assert_eq!(
            state_store
                .load()
                .expect("durable manifest")
                .get("tampered-adjusted-source")
                .expect("durable record"),
            &before
        );
    }

    #[test]
    fn rolling_pool_does_not_resolve_when_conversion_capacity_is_exhausted() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        config.max_conversions_per_scan = 1;
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "capacity-exhausted-adjusted-source",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("marker should be admitted");
        let before = manifest
            .get("capacity-exhausted-adjusted-source")
            .expect("marked record")
            .clone();
        let state_store = Arc::new(
            AssetStateStore::open_writer(
                &config.manifest_path,
                "test-writer",
                Duration::from_secs(60),
            )
            .expect("state store should open"),
        );
        state_store
            .persist_manifest_records(&manifest)
            .expect("initial marked record should persist");
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1_000,
            conversions_attempted: 1,
            ..MonitorScanSummary::default()
        };
        let calls = Arc::new(Mutex::new(PoolAdjustedSourceCalls::default()));
        let factory_calls = Arc::clone(&calls);

        run_rolling_lifecycle_worker_pool_with_transport_factory(
            &config,
            &state_store,
            &mut manifest,
            &mut summary,
            RollingLifecycleWorkerPoolInput {
                active_lifecycle_count: 1,
                worker_asset_ids: vec!["capacity-exhausted-adjusted-source".to_string()],
                deferred_worker_asset_ids: &mut BTreeSet::new(),
            },
            move || {
                Ok(PoolFailingAdjustedSourceTransport {
                    calls: Arc::clone(&factory_calls),
                })
            },
        )
        .expect("exhausted capacity must skip the resolver worker without an error");

        let calls = calls.lock().expect("pool calls should not be poisoned");
        assert_eq!(calls.lookup, 0);
        assert_eq!(calls.download, 0);
        drop(calls);
        assert_eq!(
            manifest
                .get("capacity-exhausted-adjusted-source")
                .expect("record"),
            &before
        );
        assert_eq!(
            state_store
                .load()
                .expect("durable manifest")
                .get("capacity-exhausted-adjusted-source")
                .expect("durable record"),
            &before
        );
    }

    #[test]
    fn adjusted_source_crash_after_download_before_cas_reuses_installed_file_on_resume() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.heic_output_dir).expect("HEIC root should be created");
        config.heic_output_dir =
            fs::canonicalize(&config.heic_output_dir).expect("HEIC root should canonicalize");
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "crash-adjusted-source",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("marker should be admitted");
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .expect("state store should open");
        state_store
            .persist_manifest_records(&manifest)
            .expect("initial record should persist");
        let shared_manifest = Arc::new(Mutex::new(manifest));
        let summary = Arc::new(Mutex::new(MonitorScanSummary {
            started_unix_seconds: 1_000,
            ..MonitorScanSummary::default()
        }));
        let jpeg = test_adjusted_source_jpeg();
        let original = adjusted_source_recovery_original_proof(
            shared_manifest
                .lock()
                .expect("shared manifest")
                .get("crash-adjusted-source")
                .expect("marked record"),
        )
        .expect("source proof should be valid");
        let mut first_resolver = CloudKitAdjustedSourceResolver::new(TestAdjustedSourceTransport {
            response: test_adjusted_source_lookup_response(&original, &jpeg),
            bytes: jpeg.clone(),
            destinations: Vec::new(),
            lookup_calls: 0,
            download_calls: 0,
        });

        fail_next_adjusted_source_resolution_before_cas();
        let error = run_rolling_adjusted_source_resolution_with(
            &config,
            &state_store,
            7,
            "crash-adjusted-source",
            &shared_manifest,
            &summary,
            &test_delete_session(),
            &mut first_resolver,
        )
        .expect_err("injected post-download fault should prevent the CAS");
        assert!(matches!(error, MonitorError::CommandFailed { .. }));
        assert_eq!(
            shared_manifest
                .lock()
                .expect("shared manifest")
                .get("crash-adjusted-source")
                .expect("record")
                .state,
            State::Failed
        );
        let adjusted_path = config
            .heic_output_dir
            .join("crash-adjusted-source.adjusted-source.jpg");
        assert_eq!(
            fs::read(&adjusted_path).expect("downloaded JPEG should survive"),
            jpeg
        );

        let mut resumed_resolver =
            CloudKitAdjustedSourceResolver::new(TestAdjustedSourceTransport {
                response: test_adjusted_source_lookup_response(&original, &jpeg),
                bytes: jpeg,
                destinations: Vec::new(),
                lookup_calls: 0,
                download_calls: 0,
            });
        assert_eq!(
            run_rolling_adjusted_source_resolution_with(
                &config,
                &state_store,
                7,
                "crash-adjusted-source",
                &shared_manifest,
                &summary,
                &test_delete_session(),
                &mut resumed_resolver,
            )
            .expect("restart should bind the already-installed exact JPEG"),
            RollingAssetStepOutcome::completed()
        );
        assert_eq!(
            shared_manifest
                .lock()
                .expect("shared manifest")
                .get("crash-adjusted-source")
                .expect("record")
                .state,
            State::NasVerified
        );
    }

    #[test]
    fn adjusted_source_cas_conflict_never_overwrites_newer_durable_state() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.heic_output_dir).expect("HEIC root should be created");
        config.heic_output_dir =
            fs::canonicalize(&config.heic_output_dir).expect("HEIC root should canonicalize");
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "cas-adjusted-source",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("marker should be admitted");
        let expected = manifest
            .get("cas-adjusted-source")
            .expect("marked record")
            .clone();
        let jpeg = test_adjusted_source_jpeg();
        let original = adjusted_source_recovery_original_proof(&expected)
            .expect("source proof should be valid");
        let conversion_output = config.heic_output_dir.join("cas-adjusted-source.heic");
        let mut preparer = CloudKitAdjustedSourceResolver::new(TestAdjustedSourceTransport {
            response: test_adjusted_source_lookup_response(&original, &jpeg),
            bytes: jpeg.clone(),
            destinations: Vec::new(),
            lookup_calls: 0,
            download_calls: 0,
        });
        let proof = preparer
            .resolve(
                &test_delete_session(),
                &CloudKitAdjustedSourceResolveRequest {
                    asset_id: "cas-adjusted-source".to_string(),
                    original_asset: original.clone(),
                    output_path: adjusted_source_path_for_output(&conversion_output),
                },
            )
            .expect("preparer should install the exact adjusted JPEG");
        let newer_record = stage_adjusted_source_resolution_success(
            &expected,
            "cas-adjusted-source",
            &conversion_output,
            proof,
        )
        .expect("prepared proof should create a safe durable continuation");
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .expect("state store should open");
        state_store
            .persist_manifest_records(&manifest)
            .expect("initial record should persist");
        let shared_manifest = Arc::new(Mutex::new(manifest));
        let summary = Arc::new(Mutex::new(MonitorScanSummary {
            started_unix_seconds: 1_000,
            ..MonitorScanSummary::default()
        }));
        let mut resolver = CloudKitAdjustedSourceResolver::new(RacingAdjustedSourceTransport {
            response: test_adjusted_source_lookup_response(&original, &jpeg),
            bytes: jpeg,
            state_store: &state_store,
            newer_record: newer_record.clone(),
            raced: false,
        });

        assert_eq!(
            run_rolling_adjusted_source_resolution_with(
                &config,
                &state_store,
                7,
                "cas-adjusted-source",
                &shared_manifest,
                &summary,
                &test_delete_session(),
                &mut resolver,
            )
            .expect("CAS conflict should be an idempotent no-op"),
            RollingAssetStepOutcome::attempted(false)
        );
        assert!(resolver.into_inner().raced);
        assert_eq!(
            shared_manifest
                .lock()
                .expect("shared manifest")
                .get("cas-adjusted-source")
                .expect("reconciled record"),
            &newer_record
        );
        assert_eq!(
            state_store
                .load()
                .expect("durable manifest")
                .get("cas-adjusted-source")
                .expect("newer record"),
            &newer_record
        );
    }

    #[test]
    fn rolling_pool_cas_conflict_reconciles_durable_record_before_checkpoint() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.heic_output_dir).expect("HEIC root should be created");
        config.heic_output_dir =
            fs::canonicalize(&config.heic_output_dir).expect("HEIC root should canonicalize");
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        config.max_conversions_per_scan = 1;
        config.delete_session_path = Some(tempdir.path().join("read-session.json"));
        write_test_read_session(
            config
                .delete_session_path
                .as_deref()
                .expect("read session path"),
        );

        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "pool-cas-adjusted-source",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("marker should be admitted");
        let expected = manifest
            .get("pool-cas-adjusted-source")
            .expect("marked record")
            .clone();
        let original = adjusted_source_recovery_original_proof(&expected)
            .expect("marked record should retain its original proof");
        let jpeg = test_adjusted_source_jpeg();
        let conversion_output = config.heic_output_dir.join("pool-cas-adjusted-source.heic");
        let mut preparer = CloudKitAdjustedSourceResolver::new(TestAdjustedSourceTransport {
            response: test_adjusted_source_lookup_response(&original, &jpeg),
            bytes: jpeg.clone(),
            destinations: Vec::new(),
            lookup_calls: 0,
            download_calls: 0,
        });
        let proof = preparer
            .resolve(
                &test_delete_session(),
                &CloudKitAdjustedSourceResolveRequest {
                    asset_id: "pool-cas-adjusted-source".to_string(),
                    original_asset: original.clone(),
                    output_path: adjusted_source_path_for_output(&conversion_output),
                },
            )
            .expect("preparer should install the exact adjusted JPEG");
        let newer_record = stage_adjusted_source_resolution_success(
            &expected,
            "pool-cas-adjusted-source",
            &conversion_output,
            proof,
        )
        .expect("prepared proof should create an authoritative recovered record");

        let state_store = Arc::new(
            AssetStateStore::open_writer(
                &config.manifest_path,
                "test-writer",
                Duration::from_secs(60),
            )
            .expect("state store should open"),
        );
        state_store
            .persist_manifest_records(&manifest)
            .expect("initial marked record should persist");
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1_000,
            ..MonitorScanSummary::default()
        };
        let raced = Arc::new(Mutex::new(false));
        let factory_original = original.clone();
        let factory_jpeg = jpeg.clone();
        let factory_state_store = Arc::clone(&state_store);
        let factory_newer_record = newer_record.clone();
        let factory_raced = Arc::clone(&raced);

        run_rolling_lifecycle_worker_pool_with_transport_factory(
            &config,
            &state_store,
            &mut manifest,
            &mut summary,
            RollingLifecycleWorkerPoolInput {
                active_lifecycle_count: 1,
                worker_asset_ids: vec!["pool-cas-adjusted-source".to_string()],
                deferred_worker_asset_ids: &mut BTreeSet::new(),
            },
            move || {
                Ok(PoolRacingAdjustedSourceTransport {
                    response: test_adjusted_source_lookup_response(
                        &factory_original,
                        &factory_jpeg,
                    ),
                    bytes: factory_jpeg.clone(),
                    state_store: Arc::clone(&factory_state_store),
                    newer_record: factory_newer_record.clone(),
                    raced: Arc::clone(&factory_raced),
                })
            },
        )
        .expect("CAS conflict should reconcile and let the pool checkpoint durable state");

        assert!(*raced.lock().expect("race flag should not be poisoned"));
        assert_eq!(
            manifest
                .get("pool-cas-adjusted-source")
                .expect("caller record"),
            &newer_record
        );
        assert_eq!(
            state_store
                .load()
                .expect("durable manifest")
                .get("pool-cas-adjusted-source")
                .expect("durable record"),
            &newer_record
        );
    }

    #[test]
    fn rolling_pool_rejects_nas_conflict_with_stale_downstream_proof() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.heic_output_dir).expect("HEIC root should be created");
        config.heic_output_dir =
            fs::canonicalize(&config.heic_output_dir).expect("HEIC root should canonicalize");
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        config.max_conversions_per_scan = 1;
        config.delete_session_path = Some(tempdir.path().join("read-session.json"));
        write_test_read_session(
            config
                .delete_session_path
                .as_deref()
                .expect("read session path"),
        );
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "stale-nas-conflict",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("marker should be admitted");
        let expected = manifest
            .get("stale-nas-conflict")
            .expect("marked record")
            .clone();
        let original = adjusted_source_recovery_original_proof(&expected)
            .expect("marked record should retain its original proof");
        let jpeg = test_adjusted_source_jpeg();
        let conversion_output = config.heic_output_dir.join("stale-nas-conflict.heic");
        let mut preparer = CloudKitAdjustedSourceResolver::new(TestAdjustedSourceTransport {
            response: test_adjusted_source_lookup_response(&original, &jpeg),
            bytes: jpeg.clone(),
            destinations: Vec::new(),
            lookup_calls: 0,
            download_calls: 0,
        });
        let proof = preparer
            .resolve(
                &test_delete_session(),
                &CloudKitAdjustedSourceResolveRequest {
                    asset_id: "stale-nas-conflict".to_string(),
                    original_asset: original.clone(),
                    output_path: adjusted_source_path_for_output(&conversion_output),
                },
            )
            .expect("preparer should install the exact adjusted JPEG");
        let mut stale_nas = stage_adjusted_source_resolution_success(
            &expected,
            "stale-nas-conflict",
            &conversion_output,
            proof,
        )
        .expect("prepared proof should create a clean recovered record");
        stale_nas
            .proofs
            .insert("icloudpd_local_mirror".to_string(), json!({"stale": true}));
        let state_store = Arc::new(
            AssetStateStore::open_writer(
                &config.manifest_path,
                "test-writer",
                Duration::from_secs(60),
            )
            .expect("state store should open"),
        );
        state_store
            .persist_manifest_records(&manifest)
            .expect("initial marked record should persist");
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1_000,
            ..MonitorScanSummary::default()
        };
        let raced = Arc::new(Mutex::new(false));
        let factory_original = original.clone();
        let factory_jpeg = jpeg.clone();
        let factory_state_store = Arc::clone(&state_store);
        let factory_stale_nas = stale_nas.clone();
        let factory_raced = Arc::clone(&raced);

        let error = run_rolling_lifecycle_worker_pool_with_transport_factory(
            &config,
            &state_store,
            &mut manifest,
            &mut summary,
            RollingLifecycleWorkerPoolInput {
                active_lifecycle_count: 1,
                worker_asset_ids: vec!["stale-nas-conflict".to_string()],
                deferred_worker_asset_ids: &mut BTreeSet::new(),
            },
            move || {
                Ok(PoolRacingAdjustedSourceTransport {
                    response: test_adjusted_source_lookup_response(
                        &factory_original,
                        &factory_jpeg,
                    ),
                    bytes: factory_jpeg.clone(),
                    state_store: Arc::clone(&factory_state_store),
                    newer_record: factory_stale_nas.clone(),
                    raced: Arc::clone(&factory_raced),
                })
            },
        )
        .expect_err("NasVerified rows with downstream proofs must fail closed");

        assert!(matches!(error, MonitorError::InvalidConfig { .. }));
        assert!(*raced.lock().expect("race flag should not be poisoned"));
        assert_eq!(
            manifest.get("stale-nas-conflict").expect("caller record"),
            &expected,
            "failed reconciliation must not replace the caller manifest"
        );
        assert_eq!(summary.adjusted_sources_resolved, 0);
        assert_eq!(summary.conversions_attempted, 0);
        assert_eq!(summary.conversions_completed, 0);
        assert_eq!(summary.uploads_completed, 0);
        assert_eq!(summary.mirrors_recorded, 0);
        assert_eq!(
            state_store
                .load()
                .expect("durable manifest")
                .get("stale-nas-conflict")
                .expect("durable record"),
            &stale_nas,
            "failed reconciliation must not checkpoint a stale row over durable state"
        );
    }

    #[test]
    fn rolling_pool_does_not_checkpoint_stale_manifest_after_malformed_conflict_record() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.heic_output_dir).expect("HEIC root should be created");
        config.heic_output_dir =
            fs::canonicalize(&config.heic_output_dir).expect("HEIC root should canonicalize");
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        config.max_conversions_per_scan = 1;
        config.delete_session_path = Some(tempdir.path().join("read-session.json"));
        write_test_read_session(
            config
                .delete_session_path
                .as_deref()
                .expect("read session path"),
        );
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "malformed-conflict-adjusted-source",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("marker should be admitted");
        let expected = manifest
            .get("malformed-conflict-adjusted-source")
            .expect("marked record")
            .clone();
        let original = adjusted_source_recovery_original_proof(&expected)
            .expect("marked record should retain its original proof");
        let jpeg = test_adjusted_source_jpeg();
        let mut malformed = expected.clone();
        malformed.state = State::ConversionVerified;
        malformed.updated_at = "200.000000000Z".to_string();
        let state_store = Arc::new(
            AssetStateStore::open_writer(
                &config.manifest_path,
                "test-writer",
                Duration::from_secs(60),
            )
            .expect("state store should open"),
        );
        state_store
            .persist_manifest_records(&manifest)
            .expect("initial marked record should persist");
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1_000,
            ..MonitorScanSummary::default()
        };
        let raced = Arc::new(Mutex::new(false));
        let factory_original = original.clone();
        let factory_jpeg = jpeg.clone();
        let factory_state_store = Arc::clone(&state_store);
        let factory_malformed = malformed.clone();
        let factory_raced = Arc::clone(&raced);

        let error = run_rolling_lifecycle_worker_pool_with_transport_factory(
            &config,
            &state_store,
            &mut manifest,
            &mut summary,
            RollingLifecycleWorkerPoolInput {
                active_lifecycle_count: 1,
                worker_asset_ids: vec!["malformed-conflict-adjusted-source".to_string()],
                deferred_worker_asset_ids: &mut BTreeSet::new(),
            },
            move || {
                Ok(PoolRacingAdjustedSourceTransport {
                    response: test_adjusted_source_lookup_response(
                        &factory_original,
                        &factory_jpeg,
                    ),
                    bytes: factory_jpeg.clone(),
                    state_store: Arc::clone(&factory_state_store),
                    newer_record: factory_malformed.clone(),
                    raced: Arc::clone(&factory_raced),
                })
            },
        )
        .expect_err("malformed authoritative conflict record must fail closed");

        assert!(matches!(error, MonitorError::InvalidConfig { .. }));
        assert!(*raced.lock().expect("race flag should not be poisoned"));
        assert_eq!(
            manifest
                .get("malformed-conflict-adjusted-source")
                .expect("caller record"),
            &expected,
            "the caller must not receive the stale shared copy after a failed reconciliation"
        );
        assert_eq!(
            state_store
                .load()
                .expect("durable manifest")
                .get("malformed-conflict-adjusted-source")
                .expect("durable record"),
            &malformed,
            "the pool must not checkpoint its stale expected row over durable state"
        );
    }

    #[test]
    fn rolling_pool_dedupes_duplicate_resolver_asset_ids_across_worker_slots() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        config.jobs = 2;
        config.rolling_worker_count = Some(2);
        config.max_conversions_per_scan = 1;
        fs::create_dir_all(&config.heic_output_dir).expect("HEIC root should be created");
        config.heic_output_dir =
            fs::canonicalize(&config.heic_output_dir).expect("HEIC root should canonicalize");
        config.delete_session_path = Some(tempdir.path().join("read-session.json"));
        write_test_read_session(
            config
                .delete_session_path
                .as_deref()
                .expect("read session path"),
        );
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "duplicate-adjusted-source",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("marker should be admitted");
        manifest.upsert(lifecycle_record("second-worker-slot", State::NoAction));
        let state_store = Arc::new(
            AssetStateStore::open_writer(
                &config.manifest_path,
                "test-writer",
                Duration::from_secs(60),
            )
            .expect("state store should open"),
        );
        state_store
            .persist_manifest_records(&manifest)
            .expect("initial records should persist");
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1_000,
            ..MonitorScanSummary::default()
        };
        let calls = Arc::new(Mutex::new(PoolAdjustedSourceCalls::default()));
        let factory_calls = Arc::clone(&calls);

        run_rolling_lifecycle_worker_pool_with_transport_factory(
            &config,
            &state_store,
            &mut manifest,
            &mut summary,
            RollingLifecycleWorkerPoolInput {
                active_lifecycle_count: 2,
                worker_asset_ids: vec![
                    "duplicate-adjusted-source".to_string(),
                    "duplicate-adjusted-source".to_string(),
                    "second-worker-slot".to_string(),
                ],
                deferred_worker_asset_ids: &mut BTreeSet::new(),
            },
            move || {
                Ok(PoolFailingAdjustedSourceTransport {
                    calls: Arc::clone(&factory_calls),
                })
            },
        )
        .expect("duplicate queue entries should be handled once by the worker pool");

        let calls = calls.lock().expect("pool calls should not be poisoned");
        assert_eq!(calls.lookup, 1);
        assert_eq!(calls.download, 0);
        drop(calls);
        let record = manifest
            .get("duplicate-adjusted-source")
            .expect("failed resolver record");
        assert_eq!(record.state, State::Failed);
        assert_eq!(record.failures.len(), 2);
        for proof_key in [
            "adjusted_source",
            "upload",
            "icloudpd_local_mirror",
            "delete",
        ] {
            assert!(
                !record.proofs.contains_key(proof_key),
                "duplicate workers must not produce {proof_key} side effects"
            );
        }
    }

    #[test]
    fn rolling_lifecycle_worker_stage_sequence_leaves_delete_ready_assets_for_batch_delete() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        config.auto_delete = true;
        fs::create_dir_all(&config.download_root).expect("download root should be created");

        let delete_ready = upload_verified_delete_ready_record("asset-a", &config.download_root);
        assert!(
            rolling_lifecycle_worker_stage_sequence(&delete_ready, &config).is_empty(),
            "delete-ready assets are handled by pass-level batch delete"
        );

        config.auto_delete = false;
        assert!(
            rolling_lifecycle_worker_stage_sequence(&delete_ready, &config).is_empty(),
            "delete-ready assets should wait when auto-delete is disabled"
        );
    }

    #[test]
    fn rolling_lifecycle_worker_queue_excludes_delete_ready_records_for_batch_delete() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        config.auto_delete = true;
        fs::create_dir_all(&config.download_root).expect("download root should be created");

        let mut manifest = Manifest::new();
        manifest.upsert(upload_verified_delete_ready_record(
            "a-delete-ready",
            &config.download_root,
        ));
        manifest.upsert(lifecycle_record("b-delete-approved", State::DeleteApproved));
        let mut ready = lifecycle_record("c-ready-nas", State::NasVerified);
        add_original_asset_proof(&mut ready);
        manifest.upsert(ready);

        let active_ids = vec![
            "a-delete-ready".to_string(),
            "b-delete-approved".to_string(),
            "c-ready-nas".to_string(),
        ];

        assert_eq!(
            delete_lifecycle_asset_ids(&manifest, &config, &active_ids),
            vec!["a-delete-ready", "b-delete-approved"]
        );
        assert_eq!(
            rolling_lifecycle_worker_asset_ids(
                &manifest,
                &config,
                &active_ids,
                active_ids.len(),
                1,
                &BTreeSet::new(),
            ),
            vec!["c-ready-nas"]
        );
    }

    #[test]
    fn rolling_lifecycle_delete_batch_respects_auto_delete_gate() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        config.auto_delete = false;
        let mut manifest = Manifest::new();
        manifest.upsert(upload_verified_delete_ready_record(
            "asset-a",
            &config.download_root,
        ));
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1,
            ..MonitorScanSummary::default()
        };
        let state_store = Arc::new(
            AssetStateStore::open_writer(
                &config.manifest_path,
                "test-writer",
                Duration::from_secs(60),
            )
            .expect("state store"),
        );

        run_rolling_lifecycle_delete_batch(
            &config,
            &state_store,
            &mut manifest,
            &mut summary,
            &["asset-a".to_string()],
        )
        .expect("auto-delete disabled should skip");

        assert_eq!(summary.originals_deleted, 0);
        assert_eq!(
            manifest.get("asset-a").expect("record should exist").state,
            State::UploadVerified
        );
    }

    #[test]
    fn rolling_upload_proof_is_persisted_before_next_stage() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        let mut record = upload_verified_delete_ready_record("asset-a", &config.download_root);
        record.state = State::ConversionVerified;
        record.proofs.remove("upload");
        record.proofs.remove("icloudpd_local_mirror");
        record.proofs.remove("original_asset");
        let heic = record.proofs["heic"].clone();
        let upload_proof = UploadProof {
            uploaded_heic_asset_id: "uploaded-asset-a".to_string(),
            uploaded_heic_sha256: heic["heic_sha256"]
                .as_str()
                .expect("heic hash should be string")
                .to_string(),
            database_scope: Default::default(),
            zone_name: "PrimarySync".to_string(),
            uploaded_heic_path: Some(PathBuf::from(
                heic["heic_path"]
                    .as_str()
                    .expect("heic path should be string"),
            )),
        };
        let mut manifest = Manifest::new();
        manifest.upsert(record);
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1,
            ..MonitorScanSummary::default()
        };
        let store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .expect("state store should open");

        let uploaded = record_rolling_asset_upload_proof(
            &store,
            &mut manifest,
            &mut summary,
            "asset-a",
            upload_proof,
            10,
        )
        .expect("upload proof should record and save");

        assert!(uploaded);
        assert_eq!(summary.uploads_completed, 1);
        assert_eq!(summary.uploaded_heic_bytes, 10);
        assert!(!config.manifest_path.exists());
        let persisted = store.load_or_import().expect("state store should reload");
        let persisted_record = persisted.get("asset-a").expect("asset should persist");
        assert_eq!(persisted_record.state, State::UploadVerified);
        assert!(persisted_record.proofs.contains_key("upload"));
    }

    #[test]
    fn rolling_state_commit_failure_restores_the_previous_in_memory_record() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let manifest_path = tempdir.path().join("manifest.json");
        let store =
            AssetStateStore::open_writer(&manifest_path, "test-writer", Duration::from_secs(60))
                .expect("state store should open");
        let mut manifest = Manifest::new();
        manifest.upsert(AssetRecord::new("asset-a", "/photos/asset-a.dng"));
        store
            .persist_record(manifest.get("asset-a").expect("asset should exist"))
            .expect("initial state should persist");
        let previous = manifest.get("asset-a").expect("asset should exist").clone();
        manifest
            .transition("asset-a", State::NasVerified, "nas", json!({"ok": true}))
            .expect("transition should apply in memory");
        let connection = rusqlite::Connection::open(store.path()).expect("database should open");
        connection
            .execute("DROP TABLE assets", [])
            .expect("test should break persistence");

        let error = persist_asset_record(
            &store,
            &mut manifest,
            previous.clone(),
            "asset-a",
            1,
            "nas_proof",
        )
        .expect_err("durable commit failure should fail closed");

        assert!(matches!(error, MonitorError::StateStore(_)));
        assert_eq!(
            manifest.get("asset-a").expect("asset should remain"),
            &previous
        );
    }

    #[test]
    fn rolling_local_mirror_proof_is_persisted_before_delete_batch() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        fs::create_dir_all(&config.heic_output_dir).expect("output dir should be created");
        let mirror_root = tempdir.path().join("mirror");
        fs::create_dir_all(&mirror_root).expect("mirror root should be created");
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        config.mirror_root = Some(mirror_root.clone());
        config.local_mirror_timeout_seconds = 10;
        let uploaded_path = tempdir.path().join("uploaded.heic");
        let heic_bytes = b"uploaded heic bytes";
        fs::write(&uploaded_path, heic_bytes).expect("uploaded HEIC should be written");
        let heic_sha = format!("{:x}", Sha256::digest(heic_bytes));
        let mut record = upload_verified_delete_ready_record("asset-a", &config.download_root);
        record.proofs.remove("icloudpd_local_mirror");
        record.proofs.remove("original_asset");
        record.proofs.insert(
            "conversion".to_string(),
            json!({
                "heic_path": uploaded_path,
                "heic_sha256": heic_sha,
                "size_bytes": heic_bytes.len() as u64,
            }),
        );
        record.proofs.insert(
            "conversion_performance".to_string(),
            json!({
                "schema_version": 1,
                "measured_at_unix_seconds": 1_800_000_001u64,
                "measurement_method": "monotonic_wall_clock",
                "conversion_tool": "test-tool",
                "heic_quality": 90,
                "raw_size_bytes": 100u64,
                "heic_size_bytes": heic_bytes.len() as u64,
                "convert_wall_time_millis": 10u64,
                "total_wall_time_millis": 11u64,
            }),
        );
        record.proofs.insert(
            "heic".to_string(),
            json!({
                "heic_path": uploaded_path,
                "heic_sha256": heic_sha,
                "size_bytes": heic_bytes.len() as u64,
                "heif_info_ok": true,
                "metadata_copied": true,
                "visual_content_ok": true,
                "visual_match_ok": true,
            }),
        );
        record.proofs.insert(
            "upload".to_string(),
            json!({
                "uploaded_heic_asset_id": "uploaded-asset-a",
                "uploaded_heic_sha256": heic_sha,
                "uploaded_heic_path": uploaded_path,
            }),
        );
        let mut manifest = Manifest::new();
        manifest.upsert(record);
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1,
            ..MonitorScanSummary::default()
        };
        let proof = crate::local_mirror::ensure_icloudpd_local_mirror(IcloudpdLocalMirrorRequest {
            uploaded_heic_asset_id: "uploaded-asset-a".to_string(),
            uploaded_heic_sha256: heic_sha,
            uploaded_heic_path: uploaded_path,
            size_bytes: heic_bytes.len() as u64,
            icloudpd_download_path: mirror_root.join("asset-a.HEIC"),
        })
        .expect("local mirror proof should be produced");
        let store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .expect("state store should open");

        record_rolling_asset_local_mirror_proof(
            &store,
            &mut manifest,
            &mut summary,
            "asset-a",
            proof,
        )
        .expect("local mirror proof should record and save");

        assert_eq!(summary.mirrors_recorded, 1);
        assert!(!config.manifest_path.exists());
        let persisted = store.load_or_import().expect("state store should reload");
        let persisted_record = persisted.get("asset-a").expect("asset should persist");
        assert_eq!(persisted_record.state, State::UploadVerified);
        assert!(
            persisted_record
                .proofs
                .contains_key("icloudpd_local_mirror")
        );
        assert!(mirror_root.join("asset-a.HEIC").exists());
    }

    #[test]
    fn rolling_original_asset_resolution_uses_expanded_batch_budget() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.jobs = 3;
        config.max_lifecycle_per_scan = 10;

        let mut manifest = Manifest::new();
        for (asset_id, captured_at) in [
            ("early", 1_000u64),
            ("middle", 5_000u64),
            ("late", 9_000u64),
            ("later", 13_000u64),
        ] {
            let mut record = lifecycle_record(asset_id, State::NasVerified);
            add_original_resolution_proofs(&mut record, captured_at);
            manifest.upsert(record);
        }

        let batches = original_asset_resolution_target_batches_to_run(
            &manifest,
            &config,
            None,
            Some(rolling_lifecycle_resolve_batch_limit(
                &config,
                manifest.records().len(),
            )),
        )
        .expect("targets should batch");
        let batch_asset_ids = batches
            .iter()
            .map(|batch| {
                batch
                    .iter()
                    .map(|target| target.asset_id.as_str())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        assert_eq!(
            batch_asset_ids,
            vec![vec!["early"], vec!["middle"], vec!["late"], vec!["later"]]
        );
    }

    #[test]
    fn rolling_lifecycle_continues_when_failed_slots_are_refilled() {
        let config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        let before = MonitorScanSummary::default();
        let mut after = before.clone();
        after.failures = 3;
        after.last_error =
            Some("CloudKit original asset resolver found no exact RAW resource".to_string());

        assert!(rolling_lifecycle_should_continue(
            &config,
            &before,
            &after,
            &["failed-a".to_string(), "failed-b".to_string()],
            &["next-a".to_string(), "next-b".to_string()],
        ));
        assert!(!rolling_lifecycle_should_continue(
            &config,
            &before,
            &after,
            &["failed-a".to_string(), "failed-b".to_string()],
            &["failed-a".to_string(), "failed-b".to_string()],
        ));
    }

    #[test]
    fn rolling_lifecycle_progress_ignores_attempts_without_successful_movement() {
        let before = MonitorScanSummary {
            uploads_attempted: 1,
            ..MonitorScanSummary::default()
        };
        let mut after = before.clone();
        after.uploads_attempted = 2;

        assert!(!rolling_lifecycle_made_forward_progress(&before, &after));

        after.heics_verified = 1;

        assert!(rolling_lifecycle_made_forward_progress(&before, &after));
    }

    #[test]
    fn rolling_conversion_requests_respect_remaining_capacity_and_active_set() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.full_lifecycle = true;
        config.max_conversions_per_scan = 10;

        let mut manifest = Manifest::new();
        for asset_id in ["active-a", "active-b", "outside-active"] {
            let mut record =
                AssetRecord::new(asset_id, PathBuf::from(format!("/raw/{asset_id}.DNG")));
            record.state = State::NasVerified;
            add_original_asset_proof(&mut record);
            manifest.upsert(record);
        }

        let active_asset_ids = vec!["active-a".to_string(), "active-b".to_string()];
        let requests =
            conversion_requests_with_limit(&manifest, &config, Some(&active_asset_ids), 1);

        assert_eq!(
            requests
                .iter()
                .map(|request| request.asset_id.as_str())
                .collect::<Vec<_>>(),
            vec!["active-a"]
        );
        assert!(
            conversion_requests_with_limit(&manifest, &config, Some(&active_asset_ids), 0)
                .is_empty()
        );
    }

    #[test]
    fn rolling_conversion_request_is_not_current_after_asset_progresses() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.full_lifecycle = true;

        let mut manifest = Manifest::new();
        let mut record = AssetRecord::new("asset-a", tempdir.path().join("IMG_0001.DNG"));
        record.state = State::NasVerified;
        add_original_asset_proof(&mut record);
        manifest.upsert(record.clone());

        assert!(rolling_conversion_request_is_current(
            &manifest, &config, "asset-a"
        ));

        record.state = State::UploadVerified;
        manifest.upsert(record.clone());
        assert!(!rolling_conversion_request_is_current(
            &manifest, &config, "asset-a"
        ));

        record.state = State::Deleted;
        manifest.upsert(record);
        assert!(!rolling_conversion_request_is_current(
            &manifest, &config, "asset-a"
        ));
    }

    #[test]
    fn rolling_conversion_removes_unproven_stale_generated_artifacts_before_retry() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        fs::create_dir_all(&config.heic_output_dir).expect("heic dir should be created");
        let raw_path = config.download_root.join("IMG_0001.DNG");
        fs::write(&raw_path, b"raw").expect("raw should be written");
        let output_path = config.heic_output_dir.join("asset-a.heic");
        let mut manifest = Manifest::new();
        let mut record = AssetRecord::new("asset-a", &raw_path);
        record.state = State::NasVerified;
        manifest.upsert(record);
        let request = ConversionExecutionRequest {
            asset_id: "asset-a".to_string(),
            output_path: output_path.clone(),
            heic_quality: 90,
            conversion_tool_version: None,
        };

        let artifact_paths = monitor_conversion_artifact_paths(&output_path, &raw_path);
        for path in &artifact_paths {
            fs::write(path, b"stale").expect("stale artifact should be written");
        }

        let removed = remove_stale_monitor_conversion_artifacts(&config, &manifest, &request)
            .expect("stale artifacts should be removed");

        assert_eq!(removed, artifact_paths.len());
        for path in artifact_paths {
            assert!(!path.exists(), "{} should be removed", path.display());
        }
    }

    #[test]
    fn rolling_conversion_keeps_artifacts_when_conversion_proof_exists() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        fs::create_dir_all(&config.heic_output_dir).expect("heic dir should be created");
        let raw_path = config.download_root.join("IMG_0001.DNG");
        fs::write(&raw_path, b"raw").expect("raw should be written");
        let output_path = config.heic_output_dir.join("asset-a.heic");
        let mut manifest = Manifest::new();
        let mut record = AssetRecord::new("asset-a", &raw_path);
        record.state = State::NasVerified;
        record
            .proofs
            .insert("conversion".to_string(), json!({"recorded": true}));
        manifest.upsert(record);
        let request = ConversionExecutionRequest {
            asset_id: "asset-a".to_string(),
            output_path: output_path.clone(),
            heic_quality: 90,
            conversion_tool_version: None,
        };
        fs::write(&output_path, b"proven").expect("output should be written");

        let removed = remove_stale_monitor_conversion_artifacts(&config, &manifest, &request)
            .expect("proven artifact should be kept");

        assert_eq!(removed, 0);
        assert_eq!(
            fs::read(&output_path).expect("output should remain readable"),
            b"proven"
        );
    }

    #[test]
    fn monitor_config_defaults_rolling_lifecycle_to_false_when_missing() {
        let config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        let mut value = serde_json::to_value(config).expect("config should serialize");
        value
            .as_object_mut()
            .expect("config should be an object")
            .remove("rolling_lifecycle");

        let config: MonitorConfig =
            serde_json::from_value(value).expect("missing rolling lifecycle should deserialize");

        assert!(!config.rolling_lifecycle);
    }

    #[test]
    fn rolling_lifecycle_workers_skip_delete_ready_assets_for_batch_delete() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        config.auto_delete = true;
        config.max_lifecycle_per_scan = 10;
        let mut manifest = Manifest::new();
        manifest.upsert(upload_verified_delete_ready_record(
            "asset-a",
            &config.download_root,
        ));
        manifest.upsert(lifecycle_record("asset-b", State::DeleteApproved));
        let active = vec!["asset-a".to_string(), "asset-b".to_string()];

        let worker_assets = rolling_lifecycle_worker_asset_ids(
            &manifest,
            &config,
            &active,
            config.max_lifecycle_per_scan,
            10,
            &BTreeSet::new(),
        );
        let delete_assets = delete_lifecycle_asset_ids(&manifest, &config, &active);

        assert!(worker_assets.is_empty());
        assert_eq!(delete_assets, active);
    }

    #[test]
    fn batched_delete_lifecycle_deletes_multiple_records_with_one_cloudkit_modify() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        config.jobs = 2;
        config.delete_operator = "batch-test".to_string();
        config.max_lifecycle_per_scan = 10;
        let mut manifest = Manifest::new();
        for asset_id in ["asset-a", "asset-b"] {
            manifest.upsert(upload_verified_delete_ready_record(
                asset_id,
                &config.download_root,
            ));
        }
        manifest
            .save_atomic(&config.manifest_path)
            .expect("manifest should save");
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .expect("state store");
        state_store.load_or_import().expect("import initial state");
        let session = test_delete_session();
        let mut transport = FakeDeleteTransport {
            payloads: Vec::new(),
            responses: Vec::new(),
            response: json!({
                "records": [
                    {
                        "recordName": "CPLAsset-asset-a",
                        "recordChangeTag": "deleted-tag-a",
                        "fields": {"isDeleted": {"value": 1}}
                    },
                    {
                        "recordName": "CPLAsset-asset-b",
                        "recordChangeTag": "deleted-tag-b",
                        "fields": {"isDeleted": {"value": true}}
                    }
                ]
            }),
        };
        let mut client = CloudKitDeleteClient::new(&mut transport);
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1,
            ..MonitorScanSummary::default()
        };
        let active = vec!["asset-a".to_string(), "asset-b".to_string()];

        delete_original_assets_with_client(
            &config,
            &state_store,
            &mut manifest,
            &mut summary,
            &active,
            &session,
            &mut client,
        )
        .expect("batch delete should complete");

        assert_eq!(summary.failures, 0, "{:?}", summary.last_error);
        assert_eq!(summary.originals_deleted, 2);
        assert_eq!(summary.deleted_raw_bytes, 200);
        assert_eq!(summary.bytes_saved, 180);
        assert_eq!(transport.payloads.len(), 1);
        assert_eq!(
            transport.payloads[0]["operations"]
                .as_array()
                .expect("operations should be array")
                .len(),
            2
        );
        assert_eq!(manifest.get("asset-a").unwrap().state, State::Deleted);
        assert_eq!(manifest.get("asset-b").unwrap().state, State::Deleted);
        assert_eq!(
            manifest.get("asset-a").unwrap().proofs["delete"]["deleted_record_name"],
            "CPLAsset-asset-a"
        );
        fs::remove_file(&config.manifest_path).expect("remove JSON checkpoint");
        let durable = state_store
            .load_or_import()
            .expect("load durable delete state");
        assert_eq!(durable.get("asset-a").unwrap().state, State::Deleted);
        assert_eq!(durable.get("asset-b").unwrap().state, State::Deleted);
    }

    #[test]
    fn batched_delete_consumes_prevalidated_token_without_post_cloudkit_nas_access() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        config.jobs = 2;
        config.delete_operator = "batch-test".to_string();
        let mut manifest = Manifest::new();
        let record = upload_verified_delete_ready_record("asset-a", &config.download_root);
        let raw_path = record.raw_path.clone();
        manifest.upsert(record);
        manifest
            .save_atomic(&config.manifest_path)
            .expect("manifest should save");
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .expect("state store");
        state_store.load_or_import().expect("import initial state");
        let mut transport = RemoveRawBeforeDeleteResponseTransport {
            raw_path: raw_path.clone(),
            payloads: Vec::new(),
            response: json!({
                "records": [{
                    "recordName": "CPLAsset-asset-a",
                    "recordChangeTag": "deleted-tag-a",
                    "fields": {"isDeleted": {"value": true}}
                }]
            }),
        };
        let session = test_delete_session();
        let mut client = CloudKitDeleteClient::new(&mut transport);
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1,
            ..MonitorScanSummary::default()
        };
        let active = vec!["asset-a".to_string()];

        delete_original_assets_with_client(
            &config,
            &state_store,
            &mut manifest,
            &mut summary,
            &active,
            &session,
            &mut client,
        )
        .expect("prevalidated batch delete should record without rereading RAW");

        assert!(!raw_path.exists());
        assert_eq!(summary.failures, 0, "{:?}", summary.last_error);
        assert_eq!(summary.originals_deleted, 1);
        assert_eq!(manifest.get("asset-a").unwrap().state, State::Deleted);
        assert_eq!(
            transport.payloads[0]["operations"][0]["record"]["recordName"],
            "CPLAsset-asset-a"
        );
        assert_eq!(
            transport.payloads[0]["operations"][0]["record"]["recordChangeTag"],
            "tag-asset-a"
        );
        let durable = state_store
            .load_or_import()
            .expect("load durable delete state");
        assert_eq!(durable.get("asset-a").unwrap().state, State::Deleted);
    }

    #[test]
    fn delete_submission_window_is_bounded_by_jobs_and_cloudkit_limit() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");

        config.jobs = 12;
        assert_eq!(delete_submission_window_size(&config, 500), 12);
        assert_eq!(delete_submission_window_size(&config, 5), 5);

        config.jobs = 500;
        assert_eq!(delete_submission_window_size(&config, 500), 200);

        config.jobs = 0;
        assert_eq!(delete_submission_window_size(&config, 500), 1);
    }

    #[test]
    fn preexisting_approved_delete_reconciles_without_raw_or_modify() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        config.delete_operator = "batch-test".to_string();
        let mut manifest = Manifest::new();
        let record = upload_verified_delete_ready_record("asset-a", &config.download_root);
        let raw_path = record.raw_path.clone();
        manifest.upsert(record);
        let _ = prepare_delete_item("batch-test", &mut manifest, "asset-a")
            .expect("approval should succeed");
        manifest.save_atomic(&config.manifest_path).unwrap();
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .unwrap();
        state_store.load_or_import().unwrap();
        fs::remove_file(&raw_path).expect("crash recovery must not require RAW access");
        let mut transport = LookupThenModifyTransport {
            modify_payloads: Vec::new(),
            lookup_payloads: Vec::new(),
            lookup_response: json!({"records": [{
                "recordName": "CPLAsset-asset-a",
                "recordType": "CPLAsset",
                "recordChangeTag": "deleted-tag-a",
                "fields": {"isDeleted": {"value": true}}
            }]}),
            modify_response: json!({"records": []}),
        };
        let mut client = CloudKitDeleteClient::new(&mut transport);
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1,
            ..MonitorScanSummary::default()
        };

        delete_original_assets_with_client(
            &config,
            &state_store,
            &mut manifest,
            &mut summary,
            &["asset-a".to_string()],
            &test_delete_session(),
            &mut client,
        )
        .expect("confirmed crash recovery should reconcile");

        assert_eq!(transport.lookup_payloads.len(), 1);
        assert!(transport.modify_payloads.is_empty());
        assert_eq!(summary.originals_deleted, 1);
        assert_eq!(manifest.get("asset-a").unwrap().state, State::Deleted);
    }

    #[test]
    fn unconfirmed_approved_lookup_runs_full_prevalidation_and_modify() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        config.delete_operator = "batch-test".to_string();
        let mut manifest = Manifest::new();
        manifest.upsert(upload_verified_delete_ready_record(
            "asset-a",
            &config.download_root,
        ));
        let _ = prepare_delete_item("batch-test", &mut manifest, "asset-a")
            .expect("approval should succeed");
        manifest.save_atomic(&config.manifest_path).unwrap();
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .unwrap();
        state_store.load_or_import().unwrap();
        let mut transport = LookupThenModifyTransport {
            modify_payloads: Vec::new(),
            lookup_payloads: Vec::new(),
            lookup_response: json!({"records": [{
                "recordName": "CPLAsset-asset-a",
                "recordType": "CPLAsset",
                "recordChangeTag": "tag-asset-a",
                "fields": {"isDeleted": {"value": false}}
            }]}),
            modify_response: json!({"records": [{
                "recordName": "CPLAsset-asset-a",
                "recordChangeTag": "deleted-tag-a",
                "fields": {"isDeleted": {"value": true}}
            }]}),
        };
        let mut client = CloudKitDeleteClient::new(&mut transport);
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1,
            ..MonitorScanSummary::default()
        };

        delete_original_assets_with_client(
            &config,
            &state_store,
            &mut manifest,
            &mut summary,
            &["asset-a".to_string()],
            &test_delete_session(),
            &mut client,
        )
        .expect("unconfirmed delete should proceed through live validation");

        assert_eq!(transport.lookup_payloads.len(), 1);
        assert_eq!(transport.modify_payloads.len(), 1);
        assert_eq!(manifest.get("asset-a").unwrap().state, State::Deleted);
    }

    #[test]
    fn lookup_error_still_runs_full_prevalidation_and_modify() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        config.delete_operator = "batch-test".to_string();
        let mut manifest = Manifest::new();
        manifest.upsert(upload_verified_delete_ready_record(
            "asset-a",
            &config.download_root,
        ));
        let _ = prepare_delete_item("batch-test", &mut manifest, "asset-a").unwrap();
        manifest.save_atomic(&config.manifest_path).unwrap();
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .unwrap();
        state_store.load_or_import().unwrap();
        let mut transport = LookupThenModifyTransport {
            modify_payloads: Vec::new(),
            lookup_payloads: Vec::new(),
            lookup_response: json!({"records": []}),
            modify_response: json!({"records": [{
                "recordName": "CPLAsset-asset-a",
                "recordChangeTag": "deleted-tag-a",
                "fields": {"isDeleted": {"value": true}}
            }]}),
        };
        let mut client = CloudKitDeleteClient::new(&mut transport);
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1,
            ..MonitorScanSummary::default()
        };

        delete_original_assets_with_client(
            &config,
            &state_store,
            &mut manifest,
            &mut summary,
            &["asset-a".to_string()],
            &test_delete_session(),
            &mut client,
        )
        .expect("lookup failure should fall through to live validation and modify");

        assert_eq!(transport.lookup_payloads.len(), 1);
        assert_eq!(transport.modify_payloads.len(), 1);
        assert_eq!(manifest.get("asset-a").unwrap().state, State::Deleted);
    }

    #[test]
    fn changed_approval_persistence_touches_only_window_records() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        config.delete_operator = "batch-test".to_string();
        let mut manifest = Manifest::new();
        manifest.upsert(upload_verified_delete_ready_record(
            "asset-a",
            &config.download_root,
        ));
        manifest.upsert(upload_verified_delete_ready_record(
            "asset-b",
            &config.download_root,
        ));
        manifest.save_atomic(&config.manifest_path).unwrap();
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .unwrap();
        state_store.load_or_import().unwrap();
        let mut newer_unrelated = manifest.get("asset-b").unwrap().clone();
        newer_unrelated.updated_at = "9999999999.000000000Z".to_string();
        newer_unrelated
            .proofs
            .insert("unrelated_writer".to_string(), json!(true));
        state_store.persist_record(&newer_unrelated).unwrap();
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1,
            ..MonitorScanSummary::default()
        };

        let window = process_delete_preparation_window(
            &config,
            &state_store,
            &mut manifest,
            &mut summary,
            &["asset-a".to_string()],
            0,
        )
        .expect("targeted approval commit should ignore unrelated durable state");

        assert_eq!(window.prepared.len(), 1);
        assert_eq!(
            manifest.get("asset-a").unwrap().state,
            State::DeleteApproved
        );
        assert!(
            !manifest
                .get("asset-b")
                .unwrap()
                .proofs
                .contains_key("unrelated_writer")
        );
        assert_eq!(
            state_store.load().unwrap().get("asset-b").unwrap(),
            &newer_unrelated
        );
    }

    #[test]
    fn final_request_preflight_blocks_all_tokens_after_suspension() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let download_root = tempdir.path().join("download");
        fs::create_dir_all(&download_root).unwrap();
        let mut manifest = Manifest::new();
        for asset_id in ["asset-a", "asset-b"] {
            manifest.upsert(upload_verified_delete_ready_record(
                asset_id,
                &download_root,
            ));
        }
        let first = prepare_delete_item("batch-test", &mut manifest, "asset-a")
            .unwrap()
            .0
            .unwrap();
        let second = prepare_delete_item("batch-test", &mut manifest, "asset-b")
            .unwrap()
            .0
            .unwrap();
        let first_validated = first.prevalidated.validated_at();
        let second_validated = second.prevalidated.validated_at();
        let request_time = first_validated.max(second_validated) + Duration::from_secs(31);
        let mut times = VecDeque::from([first_validated, second_validated, request_time]);
        let mut transport = FakeDeleteTransport {
            payloads: Vec::new(),
            responses: Vec::new(),
            response: json!({"records": []}),
        };
        let mut client = CloudKitDeleteClient::new(&mut transport);
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1,
            ..MonitorScanSummary::default()
        };

        let submission = submit_prepared_delete_group_with_clock(
            vec![first, second],
            &test_delete_session(),
            &mut client,
            &mut summary,
            Duration::from_secs(30),
            || {
                times
                    .pop_front()
                    .expect("validation time should be supplied")
            },
        );

        assert_eq!(submission.attempted_deletes, 0);
        assert!(transport.payloads.is_empty());
        assert_eq!(summary.failures, 2);
    }

    #[test]
    fn invalid_batch_request_does_not_call_transport_or_lookup() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let download_root = tempdir.path().join("download");
        fs::create_dir_all(&download_root).unwrap();
        let mut first_manifest = Manifest::new();
        first_manifest.upsert(upload_verified_delete_ready_record(
            "asset-a",
            &download_root,
        ));
        let mut second_manifest = first_manifest.clone();
        let first = prepare_delete_item("batch-test", &mut first_manifest, "asset-a")
            .unwrap()
            .0
            .unwrap();
        let second = prepare_delete_item("batch-test", &mut second_manifest, "asset-a")
            .unwrap()
            .0
            .unwrap();
        let mut transport = LookupThenModifyTransport {
            modify_payloads: Vec::new(),
            lookup_payloads: Vec::new(),
            lookup_response: json!({"records": []}),
            modify_response: json!({"records": []}),
        };
        let mut client = CloudKitDeleteClient::new(&mut transport);
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1,
            ..MonitorScanSummary::default()
        };

        let submission = submit_prepared_delete_group(
            vec![first, second],
            &test_delete_session(),
            &mut client,
            &mut summary,
            Duration::from_secs(30),
        );

        assert_eq!(submission.attempted_deletes, 0);
        assert!(transport.modify_payloads.is_empty());
        assert!(transport.lookup_payloads.is_empty());
        assert_eq!(summary.failures, 1);
    }

    #[test]
    fn confirmed_delete_staging_preserves_unrelated_main_records() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let download_root = tempdir.path().join("download");
        fs::create_dir_all(&download_root).unwrap();
        let mut manifest = Manifest::new();
        manifest.upsert(upload_verified_delete_ready_record(
            "asset-a",
            &download_root,
        ));
        manifest.upsert(upload_verified_delete_ready_record(
            "asset-b",
            &download_root,
        ));
        let (prepared, _) = prepare_delete_item("batch-test", &mut manifest, "asset-a").unwrap();
        let unrelated_before = manifest.get("asset-b").unwrap().clone();
        let state_store = AssetStateStore::open_writer(
            tempdir.path().join("manifest.json"),
            "test-writer",
            Duration::from_secs(60),
        )
        .unwrap();
        state_store.persist_manifest_records(&manifest).unwrap();

        let totals = stage_and_commit_confirmed_deletes(
            &state_store,
            &mut manifest,
            1,
            vec![ConfirmedDeleteItem {
                prepared: prepared.unwrap(),
                outcome: crate::upload::CloudKitDeleteOutcome {
                    record_name: "CPLAsset-asset-a".to_string(),
                    record_change_tag: "deleted-tag-a".to_string(),
                },
            }],
        )
        .expect("small staging commit should succeed");

        assert_eq!(totals.recorded, 1);
        assert_eq!(manifest.get("asset-a").unwrap().state, State::Deleted);
        assert_eq!(manifest.get("asset-b").unwrap(), &unrelated_before);
    }

    #[test]
    fn delete_timing_fields_are_present_and_bounded_by_total() {
        let total_started = Instant::now();
        let (_, preparation_elapsed) = measure_delete_phase(|| {
            thread::sleep(Duration::from_millis(2));
        });
        let (_, lookup_elapsed) = measure_delete_phase(|| {
            thread::sleep(Duration::from_millis(2));
        });
        let (_, modify_elapsed) = measure_delete_phase(|| {
            thread::sleep(Duration::from_millis(2));
        });
        let (_, commit_elapsed) = measure_delete_phase(|| {
            thread::sleep(Duration::from_millis(2));
        });
        let (_, export_elapsed) = measure_delete_phase(|| {
            thread::sleep(Duration::from_millis(2));
        });
        let timings = DeleteTimingTotals {
            preparation_wall_time_millis: preparation_elapsed.as_millis() as u64,
            cloudkit_lookup_wall_time_millis: lookup_elapsed.as_millis() as u64,
            cloudkit_modify_wall_time_millis: modify_elapsed.as_millis() as u64,
            atomic_batch_commit_wall_time_micros: commit_elapsed.as_micros() as u64,
            final_json_export_wall_time_millis: export_elapsed.as_millis() as u64,
        };
        let total_wall_time_millis = total_started.elapsed().as_millis() as u64;
        let fields = delete_batch_finished_fields(2, 2, 200, 180, &timings, total_wall_time_millis);

        for key in [
            "preparation_wall_time_millis",
            "cloudkit_lookup_wall_time_millis",
            "cloudkit_modify_wall_time_millis",
            "atomic_batch_commit_wall_time_micros",
            "final_json_export_wall_time_millis",
            "total_wall_time_millis",
        ] {
            assert!(fields.get(key).is_some(), "missing timing field {key}");
        }
        let bounded_millis = timings.preparation_wall_time_millis
            + timings.cloudkit_lookup_wall_time_millis
            + timings.cloudkit_modify_wall_time_millis
            + timings.atomic_batch_commit_wall_time_micros / 1_000
            + timings.final_json_export_wall_time_millis;
        assert!(bounded_millis <= fields["total_wall_time_millis"].as_u64().unwrap());
    }

    #[test]
    fn changed_or_expired_delete_token_blocks_before_transport() {
        for expired in [false, true] {
            let tempdir = tempfile::tempdir().expect("tempdir should be created");
            let download_root = tempdir.path().join("download");
            fs::create_dir_all(&download_root).expect("download root should be created");
            let mut manifest = Manifest::new();
            let record = upload_verified_delete_ready_record("asset-a", &download_root);
            let raw_path = record.raw_path.clone();
            manifest.upsert(record);
            let (prepared, _) = prepare_delete_item("batch-test", &mut manifest, "asset-a")
                .expect("delete should prevalidate");
            let prepared = prepared.expect("approved delete should be prepared");
            let max_age = if expired {
                thread::sleep(Duration::from_millis(2));
                Duration::ZERO
            } else {
                fs::write(&raw_path, b"changed raw bytes")
                    .expect("test should change the live RAW fingerprint");
                Duration::from_secs(30)
            };
            let mut transport = FakeDeleteTransport {
                payloads: Vec::new(),
                responses: Vec::new(),
                response: json!({"records": []}),
            };
            let session = test_delete_session();
            let mut client = CloudKitDeleteClient::new(&mut transport);
            let mut summary = MonitorScanSummary {
                started_unix_seconds: 1,
                ..MonitorScanSummary::default()
            };

            let submission = submit_prepared_delete_group(
                vec![prepared],
                &session,
                &mut client,
                &mut summary,
                max_age,
            );

            assert_eq!(submission.attempted_deletes, 0);
            assert!(submission.confirmed.is_empty());
            assert_eq!(summary.failures, 1);
            assert!(transport.payloads.is_empty());
            assert_eq!(
                manifest.get("asset-a").expect("asset should remain").state,
                State::DeleteApproved
            );
        }
    }

    #[test]
    fn ambiguous_modify_reconciles_confirmed_delete_without_failure() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        config.delete_operator = "batch-test".to_string();
        let mut manifest = Manifest::new();
        manifest.upsert(upload_verified_delete_ready_record(
            "asset-a",
            &config.download_root,
        ));
        manifest
            .save_atomic(&config.manifest_path)
            .expect("manifest should save");
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .expect("state store");
        state_store.load_or_import().expect("import initial state");
        let mut transport = AmbiguousDeleteTransport {
            payloads: Vec::new(),
            lookup_payloads: Vec::new(),
            lookup_response: json!({
                "records": [{
                    "recordName": "CPLAsset-asset-a",
                    "recordType": "CPLAsset",
                    "recordChangeTag": "deleted-tag-a",
                    "fields": {"isDeleted": {"value": true}}
                }]
            }),
        };
        let session = test_delete_session();
        let mut client = CloudKitDeleteClient::new(&mut transport);
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1,
            ..MonitorScanSummary::default()
        };
        let active = vec!["asset-a".to_string()];

        delete_original_assets_with_client(
            &config,
            &state_store,
            &mut manifest,
            &mut summary,
            &active,
            &session,
            &mut client,
        )
        .expect("strict lookup should reconcile remote delete success");

        assert_eq!(transport.payloads.len(), 1);
        assert_eq!(transport.lookup_payloads.len(), 1);
        assert_eq!(summary.failures, 0);
        assert_eq!(summary.originals_deleted, 1);
        assert_eq!(manifest.get("asset-a").unwrap().state, State::Deleted);
        assert_eq!(
            state_store.load().unwrap().get("asset-a").unwrap().state,
            State::Deleted
        );
    }

    #[test]
    fn unconfirmed_or_malformed_lookup_leaves_delete_approved() {
        let cases = [
            (
                "unconfirmed",
                json!({
                    "records": [{
                        "recordName": "CPLAsset-asset-a",
                        "recordType": "CPLAsset",
                        "recordChangeTag": "tag-asset-a",
                        "fields": {"isDeleted": {"value": false}}
                    }]
                }),
            ),
            ("malformed", json!({"records": []})),
        ];
        for (case, lookup_response) in cases {
            let tempdir = tempfile::tempdir().expect("tempdir should be created");
            let mut config = MonitorConfig::new(
                tempdir.path().join("download"),
                tempdir.path().join("manifest.json"),
                tempdir.path().join("heic"),
            );
            fs::create_dir_all(&config.download_root).expect("download root should be created");
            config.delete_operator = "batch-test".to_string();
            let mut manifest = Manifest::new();
            manifest.upsert(upload_verified_delete_ready_record(
                "asset-a",
                &config.download_root,
            ));
            manifest
                .save_atomic(&config.manifest_path)
                .expect("manifest should save");
            let state_store = AssetStateStore::open_writer(
                &config.manifest_path,
                "test-writer",
                Duration::from_secs(60),
            )
            .expect("state store");
            state_store.load_or_import().expect("import initial state");
            let mut transport = AmbiguousDeleteTransport {
                payloads: Vec::new(),
                lookup_payloads: Vec::new(),
                lookup_response,
            };
            let session = test_delete_session();
            let mut client = CloudKitDeleteClient::new(&mut transport);
            let mut summary = MonitorScanSummary {
                started_unix_seconds: 1,
                ..MonitorScanSummary::default()
            };
            let active = vec!["asset-a".to_string()];

            delete_original_assets_with_client(
                &config,
                &state_store,
                &mut manifest,
                &mut summary,
                &active,
                &session,
                &mut client,
            )
            .unwrap_or_else(|error| panic!("{case} lookup should fail closed in-band: {error}"));

            assert_eq!(transport.payloads.len(), 1);
            assert_eq!(transport.lookup_payloads.len(), 1);
            assert_eq!(summary.failures, 1);
            assert_eq!(
                manifest.get("asset-a").unwrap().state,
                State::DeleteApproved
            );
            assert_eq!(
                state_store.load().unwrap().get("asset-a").unwrap().state,
                State::DeleteApproved
            );
        }
    }

    #[test]
    fn atomic_delete_persistence_failure_keeps_main_manifest_unchanged() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        config.jobs = 2;
        config.delete_operator = "batch-test".to_string();
        let mut manifest = Manifest::new();
        let first = upload_verified_delete_ready_record("asset-a", &config.download_root);
        let second = upload_verified_delete_ready_record("asset-b", &config.download_root);
        let mut conflict_record = second.clone();
        conflict_record.state = State::DeleteApproved;
        conflict_record.updated_at = "9999999999.000000000Z".to_string();
        manifest.upsert(first);
        manifest.upsert(second);
        manifest
            .save_atomic(&config.manifest_path)
            .expect("manifest should save");
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .expect("state store");
        state_store.load_or_import().expect("import initial state");
        let mut transport = PersistConflictAfterModifyTransport {
            state_store: state_store.clone(),
            conflict_record: Some(conflict_record),
            payloads: Vec::new(),
            response: json!({
                "records": [
                    {
                        "recordName": "CPLAsset-asset-a",
                        "recordChangeTag": "deleted-tag-a",
                        "fields": {"isDeleted": {"value": true}}
                    },
                    {
                        "recordName": "CPLAsset-asset-b",
                        "recordChangeTag": "deleted-tag-b",
                        "fields": {"isDeleted": {"value": true}}
                    }
                ]
            }),
        };
        let session = test_delete_session();
        let mut client = CloudKitDeleteClient::new(&mut transport);
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1,
            ..MonitorScanSummary::default()
        };
        let active = vec!["asset-a".to_string(), "asset-b".to_string()];

        let error = delete_original_assets_with_client(
            &config,
            &state_store,
            &mut manifest,
            &mut summary,
            &active,
            &session,
            &mut client,
        )
        .expect_err("atomic persistence conflict must abort the confirmed chunk");

        assert!(matches!(error, MonitorError::StateStore(_)));
        assert_eq!(transport.payloads.len(), 1);
        assert_eq!(
            manifest.get("asset-a").unwrap().state,
            State::DeleteApproved
        );
        assert_eq!(
            manifest.get("asset-b").unwrap().state,
            State::DeleteApproved
        );
        assert_eq!(
            state_store.load().unwrap().get("asset-a").unwrap().state,
            State::DeleteApproved
        );
    }

    #[test]
    fn prepared_delete_rejects_stale_token_without_deleted_commit() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let download_root = tempdir.path().join("download");
        fs::create_dir_all(&download_root).expect("download root should be created");
        let mut manifest = Manifest::new();
        manifest.upsert(upload_verified_delete_ready_record(
            "asset-a",
            &download_root,
        ));
        let (prepared, changed) = prepare_delete_item("batch-test", &mut manifest, "asset-a")
            .expect("delete should prevalidate");
        let prepared = prepared.expect("approved delete should be prepared");
        assert!(changed);
        let mut changed_record = manifest.get("asset-a").expect("asset should exist").clone();
        changed_record.proofs.get_mut("upload").unwrap()["uploaded_heic_asset_id"] =
            json!("changed-upload");
        manifest.upsert(changed_record);

        let error = record_prevalidated_delete_execution(
            &mut manifest,
            prepared.prevalidated,
            crate::upload::CloudKitDeleteOutcome {
                record_name: "CPLAsset-asset-a".to_string(),
                record_change_tag: "deleted-tag-a".to_string(),
            },
        )
        .expect_err("stale token must fail closed");

        assert!(matches!(
            error,
            WorkflowError::PrevalidatedDeleteStale { field, .. } if field == "upload"
        ));
        assert_eq!(
            manifest.get("asset-a").expect("asset should remain").state,
            State::DeleteApproved
        );
    }

    #[test]
    fn prepared_delete_rejects_mismatched_outcome_without_deleted_commit() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let download_root = tempdir.path().join("download");
        fs::create_dir_all(&download_root).expect("download root should be created");
        let mut manifest = Manifest::new();
        manifest.upsert(upload_verified_delete_ready_record(
            "asset-a",
            &download_root,
        ));
        let (prepared, _) = prepare_delete_item("batch-test", &mut manifest, "asset-a")
            .expect("delete should prevalidate");
        let prepared = prepared.expect("approved delete should be prepared");

        let error = record_prevalidated_delete_execution(
            &mut manifest,
            prepared.prevalidated,
            crate::upload::CloudKitDeleteOutcome {
                record_name: "wrong-record".to_string(),
                record_change_tag: "deleted-tag-a".to_string(),
            },
        )
        .expect_err("mismatched CloudKit outcome must fail closed");

        assert!(matches!(
            error,
            WorkflowError::ProofMismatch {
                proof_key,
                field,
                ..
            } if proof_key == "original_asset" && field == "record_name"
        ));
        assert_eq!(
            manifest.get("asset-a").expect("asset should remain").state,
            State::DeleteApproved
        );
    }

    #[test]
    fn delete_preparation_uses_bounded_parallel_workers_without_reordering_results() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        config.jobs = 2;
        config.delete_operator = "batch-test".to_string();
        let mut manifest = Manifest::new();
        let active = (0..5)
            .map(|index| format!("asset-{index}"))
            .collect::<Vec<_>>();
        for asset_id in &active {
            manifest.upsert(upload_verified_delete_ready_record(
                asset_id,
                &config.download_root,
            ));
        }

        let batch = prepare_delete_items(&config, &manifest, &active);

        assert_eq!(batch.changed_records.len(), active.len());
        assert!(batch.failures.is_empty());
        assert_eq!(
            batch
                .prepared
                .iter()
                .map(|item| item.prevalidated.asset_id())
                .collect::<Vec<_>>(),
            active.iter().map(String::as_str).collect::<Vec<_>>()
        );
        assert_eq!(delete_prepare_worker_count(&config, active.len()), 2);
        assert!(active.iter().all(|asset_id| {
            manifest.get(asset_id).expect("asset").state == State::UploadVerified
        }));
        assert!(
            batch
                .changed_records
                .iter()
                .all(|record| record.state == State::DeleteApproved)
        );
    }

    #[test]
    fn delete_preparation_isolates_per_item_failures_without_blocking_valid_items() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        config.jobs = 2;
        config.delete_operator = "batch-test".to_string();
        let mut manifest = Manifest::new();
        manifest.upsert(upload_verified_delete_ready_record(
            "asset-ok",
            &config.download_root,
        ));
        let mut invalid = upload_verified_delete_ready_record("asset-bad", &config.download_root);
        invalid.proofs.remove("heic");
        manifest.upsert(invalid);
        let active = vec!["asset-ok".to_string(), "asset-bad".to_string()];

        let batch = prepare_delete_items(&config, &manifest, &active);

        assert_eq!(batch.changed_records.len(), 1);
        assert_eq!(
            batch
                .prepared
                .iter()
                .map(|item| item.prevalidated.asset_id())
                .collect::<Vec<_>>(),
            vec!["asset-ok"]
        );
        assert_eq!(batch.failures.len(), 1);
        assert_eq!(
            manifest.get("asset-ok").expect("valid asset").state,
            State::UploadVerified
        );
        assert_eq!(batch.changed_records[0].state, State::DeleteApproved);
        assert_eq!(
            manifest.get("asset-bad").expect("invalid asset").state,
            State::UploadVerified
        );
    }

    #[test]
    fn batched_delete_lifecycle_chunks_cloudkit_requests_at_service_limit() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        config.delete_operator = "batch-test".to_string();
        config.jobs = 500;
        config.max_lifecycle_per_scan = 201;
        let mut manifest = Manifest::new();
        let active = (0..201)
            .map(|index| format!("asset-{index:03}"))
            .collect::<Vec<_>>();
        for asset_id in &active {
            manifest.upsert(upload_verified_delete_ready_record(
                asset_id,
                &config.download_root,
            ));
        }
        manifest
            .save_atomic(&config.manifest_path)
            .expect("manifest should save");
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .expect("state store");
        state_store.load_or_import().expect("import initial state");
        let responses = active
            .chunks(200)
            .map(|chunk| {
                json!({
                    "records": chunk
                        .iter()
                        .map(|asset_id| json!({
                            "recordName": format!("CPLAsset-{asset_id}"),
                            "recordChangeTag": format!("deleted-{asset_id}"),
                            "fields": {"isDeleted": {"value": true}}
                        }))
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        let mut transport = FakeDeleteTransport {
            payloads: Vec::new(),
            responses,
            response: json!({"records": []}),
        };
        let session = test_delete_session();
        let mut client = CloudKitDeleteClient::new(&mut transport);
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1,
            ..MonitorScanSummary::default()
        };

        delete_original_assets_with_client(
            &config,
            &state_store,
            &mut manifest,
            &mut summary,
            &active,
            &session,
            &mut client,
        )
        .expect("chunked batch delete should complete");

        assert_eq!(summary.originals_deleted, 201);
        assert_eq!(transport.payloads.len(), 2);
        assert_eq!(
            transport.payloads[0]["operations"]
                .as_array()
                .unwrap()
                .len(),
            200
        );
        assert_eq!(
            transport.payloads[1]["operations"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(
            active
                .iter()
                .all(|asset_id| { manifest.get(asset_id).unwrap().state == State::Deleted })
        );
    }

    #[test]
    fn batched_delete_lifecycle_splits_cloudkit_modify_by_library_destination() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        config.delete_operator = "batch-test".to_string();
        config.max_lifecycle_per_scan = 10;
        let mut manifest = Manifest::new();
        let private_record = upload_verified_delete_ready_record("asset-a", &config.download_root);
        let mut shared_record =
            upload_verified_delete_ready_record("asset-b", &config.download_root);
        set_library_destination(&mut shared_record, "shared", "SharedSync-test-zone");
        manifest.upsert(private_record);
        manifest.upsert(shared_record);
        manifest
            .save_atomic(&config.manifest_path)
            .expect("manifest should save");
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .expect("state store");
        state_store.load_or_import().expect("import initial state");
        let session = test_delete_session();
        let mut transport = FakeDeleteTransport {
            payloads: Vec::new(),
            responses: vec![
                json!({
                    "records": [{
                        "recordName": "CPLAsset-asset-a",
                        "recordChangeTag": "deleted-tag-a",
                        "fields": {"isDeleted": {"value": true}}
                    }]
                }),
                json!({
                    "records": [{
                        "recordName": "CPLAsset-asset-b",
                        "recordChangeTag": "deleted-tag-b",
                        "fields": {"isDeleted": {"value": true}}
                    }]
                }),
            ],
            response: json!({"records": []}),
        };
        let mut client = CloudKitDeleteClient::new(&mut transport);
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1,
            ..MonitorScanSummary::default()
        };
        let active = vec!["asset-a".to_string(), "asset-b".to_string()];

        delete_original_assets_with_client(
            &config,
            &state_store,
            &mut manifest,
            &mut summary,
            &active,
            &session,
            &mut client,
        )
        .expect("mixed-library batch delete should complete");

        assert_eq!(summary.failures, 0, "{:?}", summary.last_error);
        assert_eq!(summary.originals_deleted, 2);
        assert_eq!(transport.payloads.len(), 2);
        let zones = transport
            .payloads
            .iter()
            .map(|payload| payload["zoneID"]["zoneName"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(zones, vec!["PrimarySync", "SharedSync-test-zone"]);
        assert_eq!(manifest.get("asset-a").unwrap().state, State::Deleted);
        assert_eq!(manifest.get("asset-b").unwrap().state, State::Deleted);
    }

    #[test]
    fn batched_delete_lifecycle_preserves_approved_checkpoint_on_cloudkit_failure() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        fs::create_dir_all(&config.download_root).expect("download root should be created");
        config.jobs = 2;
        config.delete_operator = "batch-test".to_string();
        let mut manifest = Manifest::new();
        for asset_id in ["asset-a", "asset-b"] {
            manifest.upsert(upload_verified_delete_ready_record(
                asset_id,
                &config.download_root,
            ));
        }
        manifest
            .save_atomic(&config.manifest_path)
            .expect("manifest should save");
        let state_store = AssetStateStore::open_writer(
            &config.manifest_path,
            "test-writer",
            Duration::from_secs(60),
        )
        .expect("state store");
        state_store.load_or_import().expect("import initial state");
        let session = test_delete_session();
        let mut transport = AmbiguousDeleteTransport {
            payloads: Vec::new(),
            lookup_payloads: Vec::new(),
            lookup_response: json!({"records": []}),
        };
        let mut client = CloudKitDeleteClient::new(&mut transport);
        let mut summary = MonitorScanSummary {
            started_unix_seconds: 1,
            ..MonitorScanSummary::default()
        };
        let active = vec!["asset-a".to_string(), "asset-b".to_string()];

        delete_original_assets_with_client(
            &config,
            &state_store,
            &mut manifest,
            &mut summary,
            &active,
            &session,
            &mut client,
        )
        .expect("CloudKit batch failure should be recorded, not panic");

        assert_eq!(summary.originals_deleted, 0);
        assert_eq!(summary.failures, 1);
        assert_eq!(transport.payloads.len(), 1);
        assert_eq!(transport.lookup_payloads.len(), 1);
        assert_eq!(
            manifest.get("asset-a").unwrap().state,
            State::DeleteApproved
        );
        assert_eq!(
            manifest.get("asset-b").unwrap().state,
            State::DeleteApproved
        );

        let saved = Manifest::load(&config.manifest_path).expect("manifest should reload");
        assert_eq!(saved.get("asset-a").unwrap().state, State::DeleteApproved);
        assert_eq!(saved.get("asset-b").unwrap().state, State::DeleteApproved);
    }

    #[test]
    fn lifecycle_failure_marks_batch_records_failed_without_dropping_proofs() {
        let mut manifest = Manifest::new();
        for asset_id in ["asset-a", "asset-b"] {
            let mut record =
                AssetRecord::new(asset_id, PathBuf::from(format!("/raw/{asset_id}.DNG")));
            record.state = State::ConversionVerified;
            record
                .proofs
                .insert("heic".to_string(), json!({"sha256": "kept"}));
            manifest.upsert(record);
        }

        let asset_ids = vec!["asset-a".to_string(), "asset-b".to_string()];
        record_lifecycle_failure_for_assets(
            &mut manifest,
            &asset_ids,
            "original_asset_resolve",
            "CloudKit original asset resolver found 0 matching candidates; expected exactly one",
        )
        .expect("failure should be recorded");

        for asset_id in asset_ids {
            let record = manifest.get(&asset_id).expect("record should exist");
            assert_eq!(record.state, State::Failed);
            assert_eq!(record.proofs["heic"], json!({"sha256": "kept"}));
            assert_eq!(record.failures.len(), 1);
            assert_eq!(record.failures[0].stage, "original_asset_resolve");
            assert!(record.failures[0].message.contains("0 matching candidates"));
        }
    }

    #[test]
    fn original_asset_batch_outcome_keeps_non_exact_reconciliation_outcomes_terminal() {
        let mut manifest = Manifest::new();
        for asset_id in ["asset-no-action", "asset-needs-review"] {
            manifest.upsert(failed_original_asset_resolve_record(
                asset_id,
                "1800000000.000000000Z",
            ));
        }
        let targets = ["asset-no-action", "asset-needs-review"]
            .into_iter()
            .map(|asset_id| CloudKitOriginalAssetResolveTarget {
                asset_id: asset_id.to_string(),
                raw_size_bytes: 9,
                source_captured_unix_seconds: 1_700_000_000,
                capture_tolerance_seconds: 2,
                filename: format!("{asset_id}.DNG"),
                matched_raw_sha256: "ab".repeat(32),
                replacement_candidate: None,
            })
            .collect::<Vec<_>>();
        let outcome = CloudKitOriginalAssetBatchResolveOutcome {
            resolutions: std::collections::BTreeMap::from([
                (
                    "asset-no-action".to_string(),
                    crate::upload::CloudKitOriginalAssetResolution {
                        observations: Default::default(),
                        disposition:
                            crate::upload::CloudKitOriginalAssetResolveDisposition::NoDateCandidate,
                    },
                ),
                (
                    "asset-needs-review".to_string(),
                    crate::upload::CloudKitOriginalAssetResolution {
                        observations: crate::upload::CloudKitOriginalAssetResolveObservations {
                            date_candidates: 1,
                            raw_resources: 1,
                            ..Default::default()
                        },
                        disposition:
                            crate::upload::CloudKitOriginalAssetResolveDisposition::RawSizeMismatch,
                    },
                ),
            ]),
            inventory: Some(crate::upload::CloudKitOriginalAssetInventoryFingerprint {
                resolver_version: crate::upload::CLOUDKIT_ORIGINAL_ASSET_RESOLVER_VERSION
                    .to_string(),
                sha256: "cd".repeat(32),
                records_scanned: 1,
            }),
        };
        let mut summary = MonitorScanSummary::default();
        let destination = test_delete_session().zone;

        let resolution = record_original_asset_batch_outcome(
            &mut manifest,
            &targets,
            &destination,
            outcome,
            1_800_000_000,
            &mut summary,
        )
        .expect("complete outcome should be recorded");

        assert!(resolution.manifest_changed());
        let no_action = manifest
            .get("asset-no-action")
            .expect("no-action asset should exist");
        assert_eq!(no_action.state, State::NoAction);
        assert!(no_action.proofs.contains_key("original_asset_resolution"));
        assert_eq!(no_action.failures[0].stage, "original_asset_resolve");
        let needs_review = manifest
            .get("asset-needs-review")
            .expect("needs-review asset should exist");
        assert_eq!(needs_review.state, State::NeedsReview);
        assert!(
            needs_review
                .proofs
                .contains_key("original_asset_resolution")
        );
        assert_eq!(needs_review.failures[0].stage, "original_asset_resolve");
        assert_eq!(summary.originals_resolved, 0);
        assert_eq!(summary.no_action_records, 1);
        assert_eq!(summary.needs_review_records, 1);
        assert_eq!(summary.failures, 0);
    }

    #[test]
    fn original_asset_batch_outcome_records_fresh_exact_original_proof_and_summary() {
        let asset_id = "asset-exact";
        let mut manifest = Manifest::new();
        manifest.upsert(fresh_original_asset_resolution_record(asset_id));
        let target = fresh_original_asset_resolution_target(asset_id);
        let destination = test_delete_session().zone;
        let outcome = CloudKitOriginalAssetBatchResolveOutcome {
            resolutions: BTreeMap::from([(
                asset_id.to_string(),
                exact_original_asset_resolution(asset_id),
            )]),
            inventory: Some(complete_original_asset_resolution_inventory()),
        };
        let mut summary = MonitorScanSummary::default();

        let resolution = record_original_asset_batch_outcome(
            &mut manifest,
            &[target],
            &destination,
            outcome,
            1_800_000_000,
            &mut summary,
        )
        .expect("complete exact outcome should be recorded");

        let record = manifest.get(asset_id).expect("exact asset should exist");
        assert!(resolution.manifest_changed());
        assert_eq!(record.state, State::NasVerified);
        assert_eq!(
            record.proofs["original_asset"]["record_name"],
            "CPLAsset-asset-exact"
        );
        assert!(record.proofs.contains_key("original_asset_resolution"));
        assert_eq!(summary.originals_resolved, 1);
        assert_eq!(summary.no_action_records, 0);
        assert_eq!(summary.needs_review_records, 0);
        assert_eq!(summary.failures, 0);
    }

    #[test]
    fn original_asset_batch_outcome_defers_entire_mixed_batch_without_mutation() {
        let exact_id = "asset-exact";
        let transient_id = "asset-transient";
        let mut manifest = Manifest::new();
        manifest.upsert(fresh_original_asset_resolution_record(exact_id));
        manifest.upsert(fresh_original_asset_resolution_record(transient_id));
        let before = manifest.clone();
        let targets = [
            fresh_original_asset_resolution_target(exact_id),
            fresh_original_asset_resolution_target(transient_id),
        ];
        let destination = test_delete_session().zone;
        let outcome = CloudKitOriginalAssetBatchResolveOutcome {
            resolutions: BTreeMap::from([
                (
                    exact_id.to_string(),
                    exact_original_asset_resolution(exact_id),
                ),
                (
                    transient_id.to_string(),
                    CloudKitOriginalAssetResolution {
                        observations: Default::default(),
                        disposition: CloudKitOriginalAssetResolveDisposition::IncompleteTransient,
                    },
                ),
            ]),
            inventory: Some(complete_original_asset_resolution_inventory()),
        };
        let mut summary = MonitorScanSummary::default();

        let resolution = record_original_asset_batch_outcome(
            &mut manifest,
            &targets,
            &destination,
            outcome,
            1_800_000_000,
            &mut summary,
        )
        .expect("mixed batch should defer without an error");

        assert_eq!(manifest, before);
        assert!(!resolution.manifest_changed());
        assert_eq!(resolution.deferred, 2);
        assert_eq!(summary.originals_resolved, 0);
        assert_eq!(summary.no_action_records, 0);
        assert_eq!(summary.needs_review_records, 0);
        assert_eq!(summary.failures, 0);
    }

    #[test]
    fn original_asset_resolve_batch_event_separates_terminal_outcomes_from_failures() {
        let failed_ids = vec!["asset-b".to_string(), "asset-c".to_string()];
        let reconciliation = OriginalAssetResolutionMonitorSummary {
            applied: OriginalAssetResolutionBatchSummary {
                exact_original: 1,
                no_action: 2,
                needs_review: 3,
            },
            deferred: 0,
        };
        let exact = original_asset_resolve_batch_finished_fields(
            6,
            &reconciliation,
            2,
            &failed_ids,
            7,
            Some(4),
            None,
        );
        assert_eq!(exact["unresolved"], 2);
        assert_eq!(exact["unresolved_asset_ids"], json!(["asset-b", "asset-c"]));
        assert_eq!(exact["resolved"], 1);
        assert_eq!(exact["no_action"], 2);
        assert_eq!(exact["needs_review"], 3);

        let aggregate_only = original_asset_resolve_batch_finished_fields(
            3,
            &OriginalAssetResolutionMonitorSummary::default(),
            3,
            &[],
            7,
            Some(4),
            Some("resolver unavailable"),
        );
        assert_eq!(aggregate_only["unresolved"], 3);
        assert_eq!(aggregate_only["unresolved_asset_ids"], json!([]));
    }

    #[test]
    fn monitor_failure_event_is_structured_for_dashboard_parsing() {
        let error = MonitorError::CommandFailed {
            program: "icloudpd-optimizer",
            message: "scan failed".to_string(),
        };
        let event = monitor_failure_event(&error, 123, None);

        assert_eq!(event["event"], "monitor_failed");
        assert_eq!(event["at_unix_seconds"], 123);
        assert_eq!(
            event["fields"]["error"],
            "icloudpd-optimizer failed: scan failed"
        );
    }

    #[test]
    fn correlated_monitor_failure_event_reuses_stage_id_without_tagging_independent_errors() {
        let error = MonitorError::CommandFailed {
            program: "icloudpd-optimizer",
            message: "commit failed".to_string(),
        };
        let correlation = new_monitor_failure_correlation(123, "delete_batch_commit_failed");
        set_pending_monitor_failure_correlation(correlation.clone());
        let inherited = take_pending_monitor_failure_correlation()
            .expect("outer monitor event should inherit stage correlation");
        let paired_event = monitor_failure_event(&error, 124, Some(&inherited));
        assert!(!correlation.failure_id.is_empty());
        assert_eq!(paired_event["fields"]["failure_id"], correlation.failure_id);
        assert_eq!(paired_event["fields"]["scan_started_unix_seconds"], 123);
        assert!(take_pending_monitor_failure_correlation().is_none());

        let independent_correlation =
            new_monitor_failure_correlation(123, "delete_batch_commit_failed");
        assert_ne!(correlation.failure_id, independent_correlation.failure_id);

        let independent = monitor_failure_event(
            &MonitorError::CommandFailed {
                program: "icloudpd-optimizer",
                message: "independent failure".to_string(),
            },
            124,
            None,
        );
        assert!(independent["fields"].get("failure_id").is_none());
    }

    #[test]
    fn incomplete_original_asset_scan_remains_retryable() {
        assert!(!original_asset_resolve_error_should_fail_records(
            &UploadError::OriginalAssetResolveIncomplete { matches: 0 }
        ));
        assert!(original_asset_resolve_error_should_fail_records(
            &UploadError::OriginalAssetResolveNotUnique { matches: 2 }
        ));
    }

    #[test]
    fn local_mirror_destination_is_stable_for_the_same_hash() {
        let mirror_root = Path::new("/mirror");
        let lowercase_hash = "ab".repeat(32);
        let uppercase_hash = lowercase_hash.to_ascii_uppercase();

        let first = icloudpd_local_mirror_destination(mirror_root, "raw-asset-1", &lowercase_hash)
            .expect("valid hash should produce a destination");
        let retry = icloudpd_local_mirror_destination(mirror_root, "raw-asset-1", &uppercase_hash)
            .expect("equivalent hash should produce the same destination");

        assert_eq!(first, retry);
        assert_eq!(
            first,
            mirror_root.join(format!("raw-asset-1-{lowercase_hash}.HEIC"))
        );
    }

    #[test]
    fn local_mirror_destination_separates_different_hashes() {
        let mirror_root = Path::new("/mirror");
        let first_hash = "11".repeat(32);
        let second_hash = "22".repeat(32);

        let first = icloudpd_local_mirror_destination(mirror_root, "raw-asset-1", &first_hash)
            .expect("first hash should be valid");
        let second = icloudpd_local_mirror_destination(mirror_root, "raw-asset-1", &second_hash)
            .expect("second hash should be valid");

        assert_ne!(first, second);
        assert_eq!(first.extension().and_then(OsStr::to_str), Some("HEIC"));
        assert_eq!(second.extension().and_then(OsStr::to_str), Some("HEIC"));
    }

    #[test]
    fn local_mirror_destination_rejects_empty_or_invalid_hashes() {
        let mirror_root = Path::new("/mirror");
        let empty = icloudpd_local_mirror_destination(mirror_root, "raw-asset-1", "   ")
            .expect_err("empty hash must fail closed");
        assert!(matches!(
            empty,
            WorkflowError::EmptyProofField {
                field: "uploaded_heic_sha256"
            }
        ));

        for invalid in ["abc", &"gg".repeat(32), &format!("{}.", "aa".repeat(31))] {
            let error = icloudpd_local_mirror_destination(mirror_root, "raw-asset-1", invalid)
                .expect_err("invalid hash must fail closed");
            assert!(matches!(
                error,
                WorkflowError::InvalidProofField {
                    proof_key: "upload",
                    field: "uploaded_heic_sha256",
                    ..
                }
            ));
        }
    }

    #[test]
    fn rolling_and_batch_mirror_requests_prefer_existing_per_record_download_candidates() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let private_raw_root = tempdir.path().join("private-library");
        let shared_raw_root = tempdir.path().join("shared-library");
        fs::create_dir_all(&private_raw_root).expect("private raw root should be created");
        fs::create_dir_all(&shared_raw_root).expect("shared raw root should be created");
        let mut config = MonitorConfig::new(
            &private_raw_root,
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        let mirror_root = tempdir.path().join("mirror");
        config.mirror_root = Some(mirror_root.clone());
        let uploaded_hash = "cd".repeat(32);
        let mut private_record =
            upload_verified_delete_ready_record("private-asset", &private_raw_root);
        let mut shared_record =
            upload_verified_delete_ready_record("shared-asset", &shared_raw_root);
        for record in [&mut private_record, &mut shared_record] {
            record.proofs.remove("icloudpd_local_mirror");
            for proof_key in ["conversion", "heic"] {
                record.proofs.get_mut(proof_key).unwrap()["heic_sha256"] = json!(uploaded_hash);
            }
            record.proofs.get_mut("upload").unwrap()["uploaded_heic_sha256"] = json!(uploaded_hash);
        }
        let private_candidate = private_record
            .raw_path
            .parent()
            .expect("private RAW should have a parent")
            .join("private-asset.HEIC");
        let shared_candidate = shared_record
            .raw_path
            .parent()
            .expect("shared RAW should have a parent")
            .join("shared-asset.HEIC");
        fs::write(&private_candidate, b"private candidate")
            .expect("private candidate should be written");
        fs::write(&shared_candidate, b"shared candidate")
            .expect("shared candidate should be written");
        let mut manifest = Manifest::new();
        manifest.upsert(private_record);
        manifest.upsert(shared_record);

        for (asset_id, expected) in [
            ("private-asset", private_candidate),
            ("shared-asset", shared_candidate),
        ] {
            let rolling = rolling_asset_local_mirror_request(&config, &manifest, asset_id)
                .expect("rolling request should be prepared")
                .expect("rolling asset should need a mirror");
            let batch = icloudpd_local_mirror_request(&mirror_root, &manifest, asset_id)
                .expect("batch request should be prepared");

            assert_eq!(rolling.icloudpd_download_path, expected);
            assert_eq!(batch.icloudpd_download_path, expected);
        }
    }

    #[test]
    fn rolling_and_batch_mirror_requests_use_controlled_destination_when_candidate_is_absent() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_root = tempdir.path().join("library");
        fs::create_dir_all(&raw_root).expect("raw root should be created");
        let mut config = MonitorConfig::new(
            &raw_root,
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        let mirror_root = tempdir.path().join("mirror");
        config.mirror_root = Some(mirror_root.clone());
        let uploaded_hash = "cd".repeat(32);
        let mut record = upload_verified_delete_ready_record("asset-a", &raw_root);
        record.proofs.remove("icloudpd_local_mirror");
        for proof_key in ["conversion", "heic"] {
            record.proofs.get_mut(proof_key).unwrap()["heic_sha256"] = json!(uploaded_hash);
        }
        record.proofs.get_mut("upload").unwrap()["uploaded_heic_sha256"] = json!(uploaded_hash);
        let mut manifest = Manifest::new();
        manifest.upsert(record);
        let expected = mirror_root.join(format!("asset-a-{uploaded_hash}.HEIC"));

        let rolling = rolling_asset_local_mirror_request(&config, &manifest, "asset-a")
            .expect("rolling request should be prepared")
            .expect("rolling asset should need a mirror");
        let batch = icloudpd_local_mirror_request(&mirror_root, &manifest, "asset-a")
            .expect("batch request should be prepared");

        assert_eq!(rolling.icloudpd_download_path, expected);
        assert_eq!(batch.icloudpd_download_path, expected);
    }

    fn lifecycle_record(asset_id: &str, state: State) -> AssetRecord {
        let mut record = AssetRecord::new(asset_id, PathBuf::from(format!("/raw/{asset_id}.DNG")));
        record.state = state;
        record
    }

    fn add_original_asset_proof(record: &mut AssetRecord) {
        record.proofs.insert(
            "original_asset".to_string(),
            json!({
                "record_name": format!("CPLAsset-{}", record.asset_id),
                "record_change_tag": "tag",
                "record_type": "CPLAsset",
                "filename": format!("{}.DNG", record.asset_id),
                "size_bytes": 9,
                "matched_raw_sha256": "raw-sha",
            }),
        );
    }

    fn set_library_destination(record: &mut AssetRecord, database_scope: &str, zone_name: &str) {
        for proof_key in ["original_asset", "upload"] {
            record
                .proofs
                .get_mut(proof_key)
                .expect("proof should exist")
                .as_object_mut()
                .expect("proof should be object")
                .insert("database_scope".to_string(), json!(database_scope));
            record
                .proofs
                .get_mut(proof_key)
                .expect("proof should exist")
                .as_object_mut()
                .expect("proof should be object")
                .insert("zone_name".to_string(), json!(zone_name));
        }
    }

    fn upload_verified_delete_ready_record(asset_id: &str, raw_root: &Path) -> AssetRecord {
        let raw_path = raw_root.join(format!("{asset_id}.DNG"));
        let raw_bytes = vec![asset_id.as_bytes()[0]; 100];
        fs::write(&raw_path, &raw_bytes).expect("raw file should be written");
        set_file_mtime(&raw_path, FileTime::from_unix_time(1_700_000_000, 0))
            .expect("raw mtime should be old");
        let raw_path = fs::canonicalize(&raw_path).expect("raw path should canonicalize");
        let mut record = AssetRecord::new(asset_id, raw_path.clone());
        record.state = State::UploadVerified;
        let raw_sha = format!("{:x}", Sha256::digest(&raw_bytes));
        let heic_sha = format!("heic-sha-{asset_id}");
        let heic_path = format!("/heic/{asset_id}.HEIC");
        record.proofs.insert(
            "nas".to_string(),
            json!({
                "canonical_path": raw_path,
                "relative_path": format!("{asset_id}.DNG"),
                "size_bytes": 100u64,
                "modified_unix_seconds": 1_700_000_000u64,
                "age_seconds": 2_592_000u64,
                "sha256": raw_sha,
            }),
        );
        record.proofs.insert(
            "conversion".to_string(),
            json!({
                "heic_path": heic_path,
                "heic_sha256": heic_sha,
                "size_bytes": 10u64,
            }),
        );
        record.proofs.insert(
            "conversion_performance".to_string(),
            json!({
                "schema_version": 1,
                "measured_at_unix_seconds": 1_800_000_001u64,
                "measurement_method": "monotonic_wall_clock",
                "conversion_tool": "test-tool",
                "heic_quality": 90,
                "raw_size_bytes": 100u64,
                "heic_size_bytes": 10u64,
                "convert_wall_time_millis": 10u64,
                "total_wall_time_millis": 11u64,
            }),
        );
        record.proofs.insert(
            "heic".to_string(),
            json!({
                "heic_path": heic_path,
                "heic_sha256": heic_sha,
                "size_bytes": 10u64,
                "heif_info_ok": true,
                "metadata_copied": true,
                "visual_content_ok": true,
                "visual_match_ok": true,
            }),
        );
        record.proofs.insert(
            "source_age".to_string(),
            json!({
                "source_captured_unix_seconds": 1_700_000_000u64,
                "verified_at_unix_seconds": 1_800_000_000u64,
                "min_age_seconds": 2_592_000u64,
            }),
        );
        record.proofs.insert(
            "upload".to_string(),
            json!({
                "uploaded_heic_asset_id": format!("uploaded-{asset_id}"),
                "uploaded_heic_sha256": heic_sha,
                "uploaded_heic_path": heic_path,
            }),
        );
        record.proofs.insert(
            "icloudpd_local_mirror".to_string(),
            json!({
                "uploaded_heic_asset_id": format!("uploaded-{asset_id}"),
                "uploaded_heic_sha256": heic_sha,
                "uploaded_heic_path": heic_path,
                "icloudpd_download_path": format!("/mirror/{asset_id}.HEIC"),
                "size_bytes": 10u64,
            }),
        );
        record.proofs.insert(
            "original_asset".to_string(),
            json!({
                "record_name": format!("CPLAsset-{asset_id}"),
                "record_change_tag": format!("tag-{asset_id}"),
                "record_type": "CPLAsset",
                "filename": format!("{asset_id}.DNG"),
                "size_bytes": 100u64,
                "matched_raw_sha256": raw_sha,
            }),
        );
        record
    }

    fn test_delete_session() -> CloudKitDeleteSession {
        CloudKitDeleteSession::from_json(
            &json!({
                "dsid": "123456789",
                "ckdatabasews_url": "https://p140-ckdatabasews.icloud.com:443",
                "cloudkit_query_params": [
                    {"name": "clientBuildNumber", "value": "2522Project44"},
                    {"name": "clientMasteringNumber", "value": "2522B2"},
                    {"name": "clientId", "value": "4f0b58d4-ff9d-4dc5-8f0b-9c4efc4fdb27"},
                    {"name": "dsid", "value": "123456789"},
                    {"name": "remapEnums", "value": "True"},
                    {"name": "getCurrentSyncToken", "value": "True"}
                ],
                "cookies": [
                    {"name": "X-APPLE-WEBAUTH-TOKEN", "value": "web-auth-token"},
                    {"name": "session", "value": "abc123"}
                ]
            })
            .to_string(),
        )
        .expect("test delete session should parse")
    }

    fn write_test_read_session(path: &Path) {
        fs::write(
            path,
            serde_json::to_vec(&json!({
                "dsid": "123456789",
                "ckdatabasews_url": "https://p140-ckdatabasews.icloud.com:443",
                "cloudkit_query_params": [
                    {"name": "clientBuildNumber", "value": "2522Project44"},
                    {"name": "clientMasteringNumber", "value": "2522B2"},
                    {"name": "clientId", "value": "test-client-id"},
                    {"name": "dsid", "value": "123456789"},
                    {"name": "remapEnums", "value": "True"},
                    {"name": "getCurrentSyncToken", "value": "True"}
                ],
                "cookies": [
                    {"name": "X-APPLE-WEBAUTH-TOKEN", "value": "test-web-auth-token"}
                ]
            }))
            .expect("test read session should serialize"),
        )
        .expect("test read session should write");
    }

    fn add_original_resolution_proofs(record: &mut AssetRecord, captured_at: u64) {
        record.proofs.insert(
            "nas".to_string(),
            json!({
                "canonical_path": format!("/raw/{}.DNG", record.asset_id),
                "relative_path": format!("{}.DNG", record.asset_id),
                "size_bytes": 9,
                "modified_unix_seconds": captured_at,
                "age_seconds": 2_592_000u64,
                "sha256": "raw-sha",
            }),
        );
        record.proofs.insert(
            "source_age".to_string(),
            json!({
                "source_captured_unix_seconds": captured_at,
                "verified_at_unix_seconds": 10_000u64,
                "min_age_seconds": 2_592_000u64,
            }),
        );
    }

    fn fresh_original_asset_resolution_record(asset_id: &str) -> AssetRecord {
        let mut record = lifecycle_record(asset_id, State::NasVerified);
        add_original_resolution_proofs(&mut record, 1_700_000_000);
        record.proofs.get_mut("nas").unwrap()["sha256"] = json!("ab".repeat(32));
        record.proofs.get_mut("source_age").unwrap()["verified_at_unix_seconds"] =
            json!(1_702_592_000u64);
        record
    }

    fn fresh_original_asset_resolution_target(
        asset_id: &str,
    ) -> CloudKitOriginalAssetResolveTarget {
        CloudKitOriginalAssetResolveTarget {
            asset_id: asset_id.to_string(),
            raw_size_bytes: 9,
            source_captured_unix_seconds: 1_700_000_000,
            capture_tolerance_seconds: 2,
            filename: format!("{asset_id}.DNG"),
            matched_raw_sha256: "ab".repeat(32),
            replacement_candidate: None,
        }
    }

    fn exact_original_asset_resolution(asset_id: &str) -> CloudKitOriginalAssetResolution {
        CloudKitOriginalAssetResolution {
            observations: CloudKitOriginalAssetResolveObservations {
                date_candidates: 1,
                raw_resources: 1,
                raw_size_matches: 1,
                raw_hash_matches: 1,
                ..Default::default()
            },
            disposition: CloudKitOriginalAssetResolveDisposition::ExactOriginal {
                proof: OriginalAssetProof {
                    record_name: format!("CPLAsset-{asset_id}"),
                    record_change_tag: format!("tag-{asset_id}"),
                    record_type: "CPLAsset".to_string(),
                    database_scope: CloudKitDatabaseScope::Private,
                    zone_name: "PrimarySync".to_string(),
                    filename: format!("{asset_id}.DNG"),
                    size_bytes: 9,
                    matched_raw_sha256: "ab".repeat(32),
                },
            },
        }
    }

    fn complete_original_asset_resolution_inventory() -> CloudKitOriginalAssetInventoryFingerprint {
        CloudKitOriginalAssetInventoryFingerprint {
            resolver_version: CLOUDKIT_ORIGINAL_ASSET_RESOLVER_VERSION.to_string(),
            sha256: "cd".repeat(32),
            records_scanned: 1,
        }
    }

    fn policy_failed_record(
        asset_id: &str,
        stage: &str,
        message: &str,
        kind: Option<FailureKind>,
        recorded_at: &str,
    ) -> AssetRecord {
        let mut record = lifecycle_record(asset_id, State::Failed);
        record.proofs.insert(
            "nas".to_string(),
            json!({
                "canonical_path": record.raw_path,
                "relative_path": format!("{asset_id}.DNG"),
                "size_bytes": 9u64,
                "modified_unix_seconds": 100u64,
                "age_seconds": 2_592_000u64,
                "sha256": "raw-sha",
            }),
        );
        record.proofs.insert(
            "source_age".to_string(),
            json!({
                "source_captured_unix_seconds": 100u64,
                "verified_at_unix_seconds": 2_592_100u64,
                "min_age_seconds": 2_592_000u64,
            }),
        );
        add_original_asset_proof(&mut record);
        record.failures.push(crate::manifest::FailureRecord {
            stage: stage.to_string(),
            message: message.to_string(),
            recorded_at: recorded_at.to_string(),
            kind,
        });
        record.updated_at = recorded_at.to_string();
        record
    }

    fn test_adjusted_source_jpeg() -> Vec<u8> {
        use image::codecs::jpeg::JpegEncoder;
        use image::{DynamicImage, Rgb, RgbImage};

        let mut image = RgbImage::new(2, 2);
        for (x, y, pixel) in image.enumerate_pixels_mut() {
            *pixel = Rgb([(x * 90) as u8, (y * 90) as u8, ((x + y) * 45) as u8]);
        }
        let mut bytes = Vec::new();
        JpegEncoder::new_with_quality(&mut bytes, 100)
            .encode_image(&DynamicImage::ImageRgb8(image))
            .expect("test adjusted-source JPEG should encode");
        bytes
    }

    fn test_adjusted_source_lookup_response(original: &OriginalAssetProof, jpeg: &[u8]) -> Value {
        json!({
            "records": [{
                "recordName": original.record_name,
                "recordType": "CPLAsset",
                "recordChangeTag": original.record_change_tag,
                "zoneID": {"zoneName": original.zone_name},
                "fields": {
                    "isDeleted": {"type": "INT64", "value": 0},
                    "resJPEGFullRes": {"type": "ASSETID", "value": {
                        "downloadURL": "https://example.icloud.com/adjusted.jpg",
                        "size": jpeg.len(),
                        "fileChecksum": "opaque-fingerprint",
                        "referenceChecksum": "opaque-reference-checksum",
                        "wrappingKey": "opaque-wrapping-key"
                    }},
                    "resJPEGFullWidth": {"type": "INT64", "value": 2},
                    "resJPEGFullHeight": {"type": "INT64", "value": 2},
                    "resJPEGFullFileType": {"type": "STRING", "value": "public.jpeg"},
                    "resJPEGFullFingerprint": {"type": "STRING", "value": "opaque-fingerprint"}
                }
            }]
        })
    }

    fn policy_failed_again(
        manifest: &mut Manifest,
        asset_id: &str,
        stage: &str,
        message: &str,
        kind: FailureKind,
    ) {
        policy_failed_again_at(manifest, asset_id, stage, message, kind, "100.000000000Z");
    }

    fn policy_failed_again_at(
        manifest: &mut Manifest,
        asset_id: &str,
        stage: &str,
        message: &str,
        kind: FailureKind,
        recorded_at: &str,
    ) {
        let mut record = manifest.get(asset_id).expect("asset should exist").clone();
        record.state = State::Failed;
        record.failures.push(crate::manifest::FailureRecord {
            stage: stage.to_string(),
            message: message.to_string(),
            recorded_at: recorded_at.to_string(),
            kind: Some(kind),
        });
        record.updated_at = recorded_at.to_string();
        manifest.upsert(record);
    }

    fn admitted_timeout_manifest(asset_id: &str) -> Manifest {
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            asset_id,
            "conversion",
            "conversion command timed out after 120000 ms: heif-enc",
            Some(FailureKind::ConversionTimedOut),
            "100.000000000Z",
        ));
        admit_failed_retryable_assets(&mut manifest, 1, 1, 300, 3_000_000)
            .expect("initial timeout retry should admit");
        manifest
    }

    fn failed_original_asset_resolve_record(
        asset_id: &str,
        failure_recorded_at: &str,
    ) -> AssetRecord {
        let mut record = lifecycle_record(asset_id, State::Failed);
        add_original_resolution_proofs(&mut record, 1_700_000_000);
        record.proofs.get_mut("nas").unwrap()["sha256"] = json!("ab".repeat(32));
        record.proofs.get_mut("source_age").unwrap()["verified_at_unix_seconds"] =
            json!(1_702_592_000u64);
        record.failures.push(crate::manifest::FailureRecord {
            stage: "original_asset_resolve".to_string(),
            message: "no exact RAW match".to_string(),
            recorded_at: failure_recorded_at.to_string(),
            kind: None,
        });
        record.updated_at = failure_recorded_at.to_string();
        record
    }

    fn interrupted_original_asset_resolve_retry_record(
        asset_id: &str,
        state: State,
        failure_recorded_at: &str,
    ) -> AssetRecord {
        let mut record = failed_original_asset_resolve_record(asset_id, failure_recorded_at);
        record.state = state;
        record
    }

    #[test]
    fn original_asset_resolver_retry_requires_exact_latest_stage_and_valid_source_proofs() {
        let mut manifest = Manifest::new();
        let mut repeated = failed_original_asset_resolve_record("eligible", "100.000000000Z");
        repeated.failures.insert(
            0,
            crate::manifest::FailureRecord {
                stage: "original_asset_resolve".to_string(),
                message: "older miss".to_string(),
                recorded_at: "050.000000000Z".to_string(),
                kind: None,
            },
        );
        manifest.upsert(repeated);

        let mut wrong_latest =
            failed_original_asset_resolve_record("wrong-latest", "100.000000000Z");
        wrong_latest.failures.push(crate::manifest::FailureRecord {
            stage: "conversion".to_string(),
            message: "later conversion failure".to_string(),
            recorded_at: "200.000000000Z".to_string(),
            kind: None,
        });
        wrong_latest.updated_at = "200.000000000Z".to_string();
        manifest.upsert(wrong_latest);

        let mut malformed_nas =
            failed_original_asset_resolve_record("malformed-nas", "100.000000000Z");
        malformed_nas
            .proofs
            .insert("nas".to_string(), json!({"size_bytes": 9}));
        manifest.upsert(malformed_nas);

        let mut stale_source_age =
            failed_original_asset_resolve_record("stale-source-age", "100.000000000Z");
        stale_source_age.proofs.insert(
            "source_age".to_string(),
            json!({
                "source_captured_unix_seconds": 1_700_000_000u64,
                "verified_at_unix_seconds": 1_700_000_001u64,
                "min_age_seconds": 2_592_000u64,
            }),
        );
        manifest.upsert(stale_source_age);

        let mut wrong_raw_identity =
            failed_original_asset_resolve_record("wrong-raw-identity", "100.000000000Z");
        wrong_raw_identity.raw_path = PathBuf::from("/raw/different.DNG");
        manifest.upsert(wrong_raw_identity);

        let admission =
            recover_original_asset_resolver_retries(&mut manifest, 10, 10, 86_400, 1_000_000)
                .expect("eligible resolver failure should recover");

        assert_eq!(admission.total_failed_resolver_backlog, 4);
        assert_eq!(admission.age_eligible_before, 1);
        assert_eq!(admission.recovered_now, 1);
        assert_eq!(admission.age_eligible_remaining, 0);
        assert_eq!(manifest.get("eligible").unwrap().state, State::NasVerified);
        for asset_id in [
            "wrong-latest",
            "malformed-nas",
            "stale-source-age",
            "wrong-raw-identity",
        ] {
            assert_eq!(manifest.get(asset_id).unwrap().state, State::Failed);
        }
    }

    #[test]
    fn original_asset_resolver_retry_excludes_every_downstream_safety_proof() {
        let downstream_proofs = [
            "original_asset",
            "upload",
            "icloudpd_local_mirror",
            "delete_eligibility",
            "delete_approval",
            "delete",
            "uploaded_heic_delete",
        ];
        let mut manifest = Manifest::new();
        for proof_key in downstream_proofs {
            let mut record = failed_original_asset_resolve_record(proof_key, "100.000000000Z");
            record
                .proofs
                .insert(proof_key.to_string(), json!({"preserved": true}));
            manifest.upsert(record);
        }

        let admission =
            recover_original_asset_resolver_retries(&mut manifest, 10, 10, 86_400, 1_000_000)
                .expect("downstream proofs should remain failed");

        assert_eq!(
            admission.total_failed_resolver_backlog,
            downstream_proofs.len()
        );
        assert_eq!(admission.age_eligible_before, 0);
        assert_eq!(admission.recovered_now, 0);
        assert_eq!(admission.age_eligible_remaining, 0);
        for proof_key in downstream_proofs {
            let record = manifest.get(proof_key).unwrap();
            assert_eq!(record.state, State::Failed);
            assert_eq!(record.proofs[proof_key], json!({"preserved": true}));
        }
    }

    #[test]
    fn original_asset_resolver_retry_restores_strongest_proof_consistent_state() {
        let mut manifest = Manifest::new();
        let nas = failed_original_asset_resolve_record("nas", "100.000000000Z");
        let nas_proofs = nas.proofs.clone();
        manifest.upsert(nas);

        let mut converted = failed_original_asset_resolve_record("converted", "200.000000000Z");
        converted.proofs.insert(
            "conversion".to_string(),
            json!({"heic_path": "/heic/converted.heic"}),
        );
        let converted_proofs = converted.proofs.clone();
        manifest.upsert(converted);

        let mut verified = failed_original_asset_resolve_record("verified", "300.000000000Z");
        verified.proofs.insert(
            "conversion".to_string(),
            json!({"heic_path": "/heic/verified.heic"}),
        );
        verified
            .proofs
            .insert("heic".to_string(), json!({"heif_info_ok": true}));
        let verified_proofs = verified.proofs.clone();
        manifest.upsert(verified);

        let admission =
            recover_original_asset_resolver_retries(&mut manifest, 3, 3, 86_400, 1_000_000)
                .expect("eligible resolver failures should recover");

        assert_eq!(admission.recovered_now, 3);
        assert_eq!(manifest.get("nas").unwrap().state, State::NasVerified);
        assert_eq!(manifest.get("converted").unwrap().state, State::Converted);
        assert_eq!(
            manifest.get("verified").unwrap().state,
            State::ConversionVerified
        );
        assert_eq!(manifest.get("nas").unwrap().proofs, nas_proofs);
        assert_eq!(manifest.get("converted").unwrap().proofs, converted_proofs);
        assert_eq!(manifest.get("verified").unwrap().proofs, verified_proofs);
    }

    #[test]
    fn original_asset_resolver_retry_uses_available_capacity_and_oldest_failures_first() {
        let mut manifest = Manifest::new();
        manifest.upsert(lifecycle_record("active", State::Converted));
        for (asset_id, recorded_at) in [
            ("newest", "400.000000000Z"),
            ("oldest", "100.000000000Z"),
            ("middle", "200.000000000Z"),
            ("newer", "300.000000000Z"),
        ] {
            manifest.upsert(failed_original_asset_resolve_record(asset_id, recorded_at));
        }

        let admission =
            recover_original_asset_resolver_retries(&mut manifest, 3, 3, 86_400, 1_000_000)
                .expect("bounded resolver failures should recover");

        assert_eq!(admission.available_lifecycle_capacity, 2);
        assert_eq!(admission.age_eligible_before, 4);
        assert_eq!(admission.recovered_now, 2);
        assert_eq!(admission.age_eligible_remaining, 2);
        assert_eq!(manifest.get("oldest").unwrap().state, State::NasVerified);
        assert_eq!(manifest.get("middle").unwrap().state, State::NasVerified);
        assert_eq!(manifest.get("newer").unwrap().state, State::Failed);
        assert_eq!(manifest.get("newest").unwrap().state, State::Failed);
        assert_eq!(pending_lifecycle_count(&manifest), 3);
    }

    #[test]
    fn original_asset_resolver_retry_cap_is_independent_from_lifecycle_capacity() {
        let mut manifest = Manifest::new();
        for (asset_id, recorded_at) in [
            ("oldest", "100.000000000Z"),
            ("middle", "200.000000000Z"),
            ("newest", "300.000000000Z"),
        ] {
            manifest.upsert(failed_original_asset_resolve_record(asset_id, recorded_at));
        }

        let admission =
            recover_original_asset_resolver_retries(&mut manifest, 512, 2, 86_400, 1_000_000)
                .expect("retry-specific cap should bound admission");

        assert_eq!(admission.available_lifecycle_capacity, 512);
        assert_eq!(admission.retry_admission_limit, 2);
        assert_eq!(admission.recovered_now, 2);
        assert_eq!(manifest.get("oldest").unwrap().state, State::NasVerified);
        assert_eq!(manifest.get("middle").unwrap().state, State::NasVerified);
        assert_eq!(manifest.get("newest").unwrap().state, State::Failed);
    }

    #[test]
    fn interrupted_resolver_retry_starts_never_accumulate_past_retry_cap() {
        const RETRY_CAP: usize = 16;
        let mut manifest = Manifest::new();
        for index in 0..(RETRY_CAP * 2) {
            manifest.upsert(failed_original_asset_resolve_record(
                &format!("asset-{index:02}"),
                &format!("{index:03}.000000000Z"),
            ));
        }

        for interrupted_start in 0..2 {
            let admission = recover_original_asset_resolver_retries(
                &mut manifest,
                512,
                RETRY_CAP,
                86_400,
                1_000_000,
            )
            .expect("resolver retry admission should succeed");

            assert_eq!(admission.recovered_now, RETRY_CAP);
            assert_eq!(
                admission.interrupted_retries_requeued,
                if interrupted_start == 0 { 0 } else { RETRY_CAP }
            );
            assert!(pending_lifecycle_count(&manifest) <= RETRY_CAP);
        }
    }

    #[test]
    fn interrupted_resolver_retry_zero_cap_requeues_without_changing_evidence() {
        let mut manifest = Manifest::new();
        let record = interrupted_original_asset_resolve_retry_record(
            "interrupted",
            State::ConversionVerified,
            "100.000000000Z",
        );
        let proofs = record.proofs.clone();
        let failures = record.failures.clone();
        manifest.upsert(record);

        let admission =
            recover_original_asset_resolver_retries(&mut manifest, 512, 0, 86_400, 1_000_000)
                .expect("zero-cap recovery should requeue interrupted work");

        assert_eq!(admission.interrupted_retries_requeued, 1);
        assert_eq!(admission.retry_admission_limit, 0);
        assert_eq!(admission.recovered_now, 0);
        assert!(admission.manifest_changed());
        let requeued = manifest.get("interrupted").unwrap();
        assert_eq!(requeued.state, State::Failed);
        assert_eq!(requeued.proofs, proofs);
        assert_eq!(requeued.failures, failures);
        assert_eq!(
            requeued.failures.last().unwrap().recorded_at,
            "100.000000000Z"
        );
    }

    #[test]
    fn interrupted_resolver_retries_restore_strongest_proof_consistent_states() {
        let mut manifest = Manifest::new();
        manifest.upsert(interrupted_original_asset_resolve_retry_record(
            "nas",
            State::NasVerified,
            "100.000000000Z",
        ));

        let mut converted = interrupted_original_asset_resolve_retry_record(
            "converted",
            State::ConversionVerified,
            "200.000000000Z",
        );
        converted.proofs.insert(
            "conversion".to_string(),
            json!({"heic_path": "/heic/converted.heic"}),
        );
        manifest.upsert(converted);

        let mut verified = interrupted_original_asset_resolve_retry_record(
            "verified",
            State::Converted,
            "300.000000000Z",
        );
        verified.proofs.insert(
            "conversion".to_string(),
            json!({"heic_path": "/heic/verified.heic"}),
        );
        verified
            .proofs
            .insert("heic".to_string(), json!({"heif_info_ok": true}));
        manifest.upsert(verified);

        let evidence = manifest
            .records()
            .iter()
            .map(|(asset_id, record)| {
                (
                    asset_id.clone(),
                    (record.proofs.clone(), record.failures.clone()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let admission =
            recover_original_asset_resolver_retries(&mut manifest, 3, 3, 86_400, 1_000_000)
                .expect("interrupted retries should be readmitted");

        assert_eq!(admission.interrupted_retries_requeued, 3);
        assert_eq!(admission.recovered_now, 3);
        assert_eq!(manifest.get("nas").unwrap().state, State::NasVerified);
        assert_eq!(manifest.get("converted").unwrap().state, State::Converted);
        assert_eq!(
            manifest.get("verified").unwrap().state,
            State::ConversionVerified
        );
        for (asset_id, (proofs, failures)) in evidence {
            let record = manifest.get(&asset_id).unwrap();
            assert_eq!(record.proofs, proofs);
            assert_eq!(record.failures, failures);
        }
    }

    #[test]
    fn interrupted_resolver_retries_with_downstream_proofs_are_not_requeued() {
        let downstream_proofs = [
            "original_asset",
            "upload",
            "icloudpd_local_mirror",
            "delete_eligibility",
            "delete_approval",
            "delete",
            "uploaded_heic_delete",
        ];
        let mut manifest = Manifest::new();
        for proof_key in downstream_proofs {
            let mut record = interrupted_original_asset_resolve_retry_record(
                proof_key,
                State::NasVerified,
                "100.000000000Z",
            );
            record
                .proofs
                .insert(proof_key.to_string(), json!({"preserved": true}));
            manifest.upsert(record);
        }

        let admission =
            recover_original_asset_resolver_retries(&mut manifest, 10, 10, 86_400, 1_000_000)
                .expect("downstream-proven records should remain active");

        assert_eq!(admission.interrupted_retries_requeued, 0);
        assert_eq!(admission.recovered_now, 0);
        for proof_key in downstream_proofs {
            let record = manifest.get(proof_key).unwrap();
            assert_eq!(record.state, State::NasVerified);
            assert_eq!(record.proofs[proof_key], json!({"preserved": true}));
        }
    }

    #[test]
    fn interrupted_resolver_retry_with_changed_source_requeues_and_stays_failed() {
        let mut manifest = Manifest::new();
        let mut record = interrupted_original_asset_resolve_retry_record(
            "changed-source",
            State::Converted,
            "100.000000000Z",
        );
        record.raw_path = PathBuf::from("/raw/replaced.DNG");
        manifest.upsert(record);

        let admission =
            recover_original_asset_resolver_retries(&mut manifest, 10, 10, 86_400, 1_000_000)
                .expect("changed source should fail closed");

        assert_eq!(admission.interrupted_retries_requeued, 1);
        assert_eq!(admission.total_failed_resolver_backlog, 1);
        assert_eq!(admission.age_eligible_before, 0);
        assert_eq!(admission.recovered_now, 0);
        assert_eq!(manifest.get("changed-source").unwrap().state, State::Failed);
    }

    #[test]
    fn bounded_oldest_selection_matches_full_sort_for_large_tied_input() {
        let candidates = (0..10_000)
            .rev()
            .map(|index| ((index % 31, 0), format!("asset-{index:05}")))
            .collect::<Vec<_>>();
        let mut expected = candidates.clone();
        expected.sort();
        expected.truncate(37);
        let mut selection = BoundedOldest::new(37);

        for candidate in candidates {
            selection.consider(candidate);
            assert!(selection.len() <= 37);
        }

        assert_eq!(selection.into_oldest(), expected);
    }

    #[test]
    fn bounded_oldest_selection_retains_nothing_for_zero_limit() {
        let mut selection = BoundedOldest::new(0);

        for candidate in 0..10_000 {
            selection.consider(candidate);
            assert_eq!(selection.len(), 0);
        }

        assert!(selection.into_oldest().is_empty());
    }

    #[test]
    fn original_asset_resolver_retry_zero_limit_preserves_backlog_metrics() {
        let mut manifest = Manifest::new();
        manifest.upsert(lifecycle_record("active", State::Converted));
        manifest.upsert(failed_original_asset_resolve_record(
            "oldest",
            "100.000000000Z",
        ));
        manifest.upsert(failed_original_asset_resolve_record(
            "newest",
            "200.000000000Z",
        ));

        let admission =
            recover_original_asset_resolver_retries(&mut manifest, 1, 16, 86_400, 1_000_000)
                .expect("zero admission should still report backlog");

        assert_eq!(admission.total_failed_resolver_backlog, 2);
        assert_eq!(admission.available_lifecycle_capacity, 0);
        assert_eq!(admission.retry_admission_limit, 0);
        assert_eq!(admission.age_eligible_before, 2);
        assert_eq!(admission.recovered_now, 0);
        assert_eq!(admission.age_eligible_remaining, 2);
        assert_eq!(manifest.get("oldest").unwrap().state, State::Failed);
        assert_eq!(manifest.get("newest").unwrap().state, State::Failed);
    }

    #[test]
    fn original_asset_resolver_retry_breaks_timestamp_ties_by_asset_id() {
        let mut manifest = Manifest::new();
        for asset_id in ["asset-z", "asset-a", "asset-m"] {
            manifest.upsert(failed_original_asset_resolve_record(
                asset_id,
                "100.000000000Z",
            ));
        }

        let admission =
            recover_original_asset_resolver_retries(&mut manifest, 512, 2, 86_400, 1_000_000)
                .expect("asset id should deterministically break timestamp ties");

        assert_eq!(admission.recovered_now, 2);
        assert_eq!(manifest.get("asset-a").unwrap().state, State::NasVerified);
        assert_eq!(manifest.get("asset-m").unwrap().state, State::NasVerified);
        assert_eq!(manifest.get("asset-z").unwrap().state, State::Failed);
    }

    #[test]
    fn original_asset_resolver_retry_age_is_eligible_at_exact_boundary() {
        let mut manifest = Manifest::new();
        manifest.upsert(failed_original_asset_resolve_record(
            "at-boundary",
            "100.000000000Z",
        ));
        manifest.upsert(failed_original_asset_resolve_record(
            "too-young",
            "101.000000000Z",
        ));

        let admission =
            recover_original_asset_resolver_retries(&mut manifest, 10, 10, 86_400, 86_500)
                .expect("age boundary should be deterministic");

        assert_eq!(admission.total_failed_resolver_backlog, 2);
        assert_eq!(admission.age_eligible_before, 1);
        assert_eq!(admission.recovered_now, 1);
        assert_eq!(
            manifest.get("at-boundary").unwrap().state,
            State::NasVerified
        );
        assert_eq!(manifest.get("too-young").unwrap().state, State::Failed);
    }

    #[test]
    fn just_refailed_resolver_item_moves_behind_older_backlog() {
        let mut manifest = Manifest::new();
        manifest.upsert(failed_original_asset_resolve_record(
            "just-refailed",
            "100.000000000Z",
        ));
        manifest.upsert(failed_original_asset_resolve_record(
            "older-backlog",
            "200.000000000Z",
        ));

        let first = recover_original_asset_resolver_retries(&mut manifest, 1, 1, 86_400, 1_000_000)
            .expect("oldest resolver failure should recover");
        assert_eq!(first.recovered_now, 1);
        assert_eq!(
            manifest.get("just-refailed").unwrap().state,
            State::NasVerified
        );
        manifest
            .record_failure(
                "just-refailed",
                "original_asset_resolve",
                "failed again after retry",
            )
            .expect("re-failure should be recorded");

        let second = recover_original_asset_resolver_retries(
            &mut manifest,
            1,
            1,
            0,
            current_unix_seconds().saturating_add(1),
        )
        .expect("older backlog should recover before a re-failure");

        assert_eq!(second.age_eligible_before, 2);
        assert_eq!(second.recovered_now, 1);
        assert_eq!(second.age_eligible_remaining, 1);
        assert_eq!(
            manifest.get("older-backlog").unwrap().state,
            State::NasVerified
        );
        assert_eq!(manifest.get("just-refailed").unwrap().state, State::Failed);
    }

    #[test]
    fn original_asset_resolver_retry_rejects_future_and_invalid_failure_timestamps() {
        let mut manifest = Manifest::new();
        manifest.upsert(failed_original_asset_resolve_record("invalid", "invalid"));
        manifest.upsert(failed_original_asset_resolve_record(
            "future",
            "1000.000000000Z",
        ));

        let admission = recover_original_asset_resolver_retries(&mut manifest, 10, 10, 100, 999)
            .expect("invalid timestamps should fail closed");

        assert_eq!(admission.total_failed_resolver_backlog, 2);
        assert_eq!(admission.age_eligible_before, 0);
        assert_eq!(admission.recovered_now, 0);
        assert_eq!(manifest.get("invalid").unwrap().state, State::Failed);
        assert_eq!(manifest.get("future").unwrap().state, State::Failed);
    }

    #[test]
    fn original_asset_resolver_retry_persists_through_strict_store() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let manifest_path = tempdir.path().join("manifest.json");
        let store =
            AssetStateStore::open_writer(&manifest_path, "test-writer", Duration::from_secs(60))
                .expect("state store should open");
        let mut manifest = Manifest::new();
        manifest.upsert(failed_original_asset_resolve_record(
            "resolver-retry",
            "100.000000000Z",
        ));
        store
            .persist_manifest_records(&manifest)
            .expect("failed record should persist");

        let admission =
            recover_original_asset_resolver_retries(&mut manifest, 1, 1, 86_400, 1_000_000)
                .expect("resolver retry should recover");
        checkpoint_manifest_state(&store, &manifest).expect("recovery should persist strictly");

        assert_eq!(admission.recovered_now, 1);
        let reloaded = store.load().expect("strict store should reload");
        assert_eq!(
            reloaded.get("resolver-retry").unwrap().state,
            State::NasVerified
        );
        assert_eq!(
            Manifest::load(&manifest_path)
                .expect("JSON export should reload")
                .get("resolver-retry")
                .unwrap()
                .state,
            State::NasVerified
        );
    }

    #[test]
    fn original_asset_resolver_retry_metrics_report_backlog_admission_and_remaining() {
        let admission = OriginalAssetResolverRetryAdmission {
            interrupted_retries_requeued: 3,
            total_failed_resolver_backlog: 9,
            available_lifecycle_capacity: 2,
            retry_admission_limit: 2,
            age_eligible_before: 4,
            recovered_now: 2,
            age_eligible_remaining: 2,
        };

        assert_eq!(
            original_asset_resolver_retry_admission_fields(&admission),
            json!({
                "interrupted_retries_requeued": 3,
                "total_failed_resolver_backlog": 9,
                "available_lifecycle_capacity": 2,
                "retry_admission_limit": 2,
                "age_eligible_backlog_before": 4,
                "recovered_now": 2,
                "age_eligible_backlog_remaining": 2,
            })
        );
    }

    #[test]
    fn monitor_config_defaults_original_resolver_retry_controls_when_missing() {
        let config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        let mut value = serde_json::to_value(config).expect("config should serialize");
        let object = value.as_object_mut().expect("config should be an object");
        object.remove("max_original_resolver_retries_per_scan");
        object.remove("original_resolver_retry_min_age_seconds");
        object.remove("max_failed_retry_admissions_per_scan");
        object.remove("failed_retry_min_age_seconds");

        let config: MonitorConfig =
            serde_json::from_value(value).expect("legacy config should deserialize");

        assert_eq!(config.max_original_resolver_retries_per_scan, 16);
        assert_eq!(config.original_resolver_retry_min_age_seconds, 86_400);
        assert_eq!(config.max_failed_retry_admissions_per_scan, 16);
        assert_eq!(config.failed_retry_min_age_seconds, 300);
    }

    #[test]
    fn monitor_config_rejects_zero_original_resolver_retry_controls() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.max_original_resolver_retries_per_scan = 0;
        assert!(matches!(
            config.validate(),
            Err(MonitorError::InvalidConfig { message })
                if message == "max_original_resolver_retries_per_scan must be greater than 0"
        ));

        config.max_original_resolver_retries_per_scan = 16;
        config.original_resolver_retry_min_age_seconds = 0;
        assert!(matches!(
            config.validate(),
            Err(MonitorError::InvalidConfig { message })
                if message == "original_resolver_retry_min_age_seconds must be greater than 0"
        ));
    }

    #[test]
    fn visual_content_failure_terminalizes_with_a_durable_review_proof() {
        let mut manifest = Manifest::new();
        let record = policy_failed_record(
            "visual-content",
            "heic_verify",
            "HEIC verification failed: visual_content_ok",
            Some(FailureKind::HeicVisualContent),
            "100.000000000Z",
        );
        manifest.upsert(record);

        admit_failed_retryable_assets(&mut manifest, 0, 16, 300, 3_000_000)
            .expect("visual-content failure should terminalize");

        let record = manifest
            .get("visual-content")
            .expect("record should remain");
        assert_eq!(record.state, State::NeedsReview);
        assert_eq!(
            record.proofs["failure_review"]["reason_code"],
            json!("heic_visual_content")
        );
    }

    #[test]
    fn visual_match_admits_once_for_the_policy_generation_then_terminalizes() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let heic_path = tempdir.path().join("visual-match.heic");
        let bytes = b"verified heic";
        fs::write(&heic_path, bytes).expect("HEIC should be written");
        let mut record = policy_failed_record(
            "visual-match",
            "heic_verify",
            "HEIC verification failed: visual_match_ok",
            None,
            "100.000000000Z",
        );
        for _ in 0..120 {
            record.failures.insert(
                0,
                crate::manifest::FailureRecord::new("conversion", "historical failure"),
            );
        }
        record.proofs.insert(
            "conversion".to_string(),
            json!({
                "heic_path": heic_path,
                "heic_sha256": format!("{:x}", Sha256::digest(bytes)),
                "size_bytes": bytes.len() as u64,
            }),
        );
        let mut manifest = Manifest::new();
        manifest.upsert(record);

        assert_eq!(
            failed_retry_queue_counts(&manifest)["retryable_heic_visual_match_pending_integrity_check"],
            1,
            "queue counts assets, not the 120 historical failure records"
        );

        let admission = admit_failed_retryable_assets(&mut manifest, 10, 16, 300, 3_000_000)
            .expect("first visual-match retry should admit");
        assert_eq!(
            admission.admitted_by_category["retryable_heic_visual_match"],
            1
        );
        let record = manifest.get("visual-match").expect("record should remain");
        assert_eq!(record.state, State::Converted);
        assert_eq!(record.proofs["failure_retry"]["attempt"], json!(1));

        policy_failed_again_at(
            &mut manifest,
            "visual-match",
            "heic_verify",
            "HEIC verification failed: visual_match_ok",
            FailureKind::HeicVisualMatch,
            "101.000000000Z",
        );
        let exhausted = admit_failed_retryable_assets(&mut manifest, 10, 16, 300, 3_000_000)
            .expect("exhausted retry should terminalize");
        assert_eq!(exhausted.exhausted, 1);
        let record = manifest.get("visual-match").expect("record should remain");
        assert_eq!(record.state, State::NeedsReview);
        assert_eq!(record.proofs["failure_review"]["current_attempt"], json!(1));
        assert_eq!(
            record.proofs["failure_review"]["last_failure_stage"],
            json!("heic_verify")
        );
        assert_eq!(
            record.proofs["failure_review"]["last_failure_kind"],
            json!("heic_visual_match")
        );
        assert_eq!(
            record.proofs["failure_review"]["last_failure_recorded_at"],
            json!("101.000000000Z")
        );
        assert_eq!(
            record.proofs["failure_review"]["last_failure_digest"],
            json!(failure_digest(record.failures.last().unwrap()))
        );
    }

    #[test]
    fn conversion_retry_budgets_and_capacity_are_bounded_oldest_first() {
        let mut manifest = Manifest::new();
        for (asset_id, recorded_at) in [("oldest", "100.000000000Z"), ("newest", "200.000000000Z")]
        {
            manifest.upsert(policy_failed_record(
                asset_id,
                "conversion",
                "conversion command timed out after 120000 ms: heif-enc",
                Some(FailureKind::ConversionTimedOut),
                recorded_at,
            ));
        }

        let admission = admit_failed_retryable_assets(&mut manifest, 1, 1, 300, 3_000_000)
            .expect("oldest retry should admit");
        assert_eq!(
            admission.admitted_by_category["retryable_conversion_timed_out"],
            1
        );
        assert_eq!(manifest.get("oldest").unwrap().state, State::NasVerified);
        assert_eq!(manifest.get("newest").unwrap().state, State::Failed);

        for (expected_attempt, timestamp) in [(2, "101.000000000Z"), (3, "102.000000000Z")] {
            policy_failed_again_at(
                &mut manifest,
                "oldest",
                "conversion",
                "conversion command timed out after 120000 ms: heif-enc",
                FailureKind::ConversionTimedOut,
                timestamp,
            );
            admit_failed_retryable_assets(&mut manifest, 1, 1, 300, 3_000_000)
                .expect("retry should admit before budget exhaustion");
            assert_eq!(manifest.get("oldest").unwrap().state, State::NasVerified);
            assert_eq!(
                manifest.get("oldest").unwrap().proofs["failure_retry"]["attempt"],
                json!(expected_attempt)
            );
        }
        policy_failed_again_at(
            &mut manifest,
            "oldest",
            "conversion",
            "conversion command timed out after 120000 ms: heif-enc",
            FailureKind::ConversionTimedOut,
            "103.000000000Z",
        );
        let exhausted = admit_failed_retryable_assets(&mut manifest, 1, 1, 300, 3_000_000)
            .expect("fourth failure should terminalize");
        assert_eq!(exhausted.exhausted, 1);
        let record = manifest.get("oldest").unwrap();
        assert_eq!(record.state, State::NeedsReview);
        assert_eq!(
            record.proofs[FAILURE_REVIEW_PROOF]["current_attempt"],
            json!(3)
        );
        assert_eq!(
            record.proofs[FAILURE_REVIEW_PROOF]["last_failure_recorded_at"],
            json!("103.000000000Z")
        );
    }

    #[test]
    fn one_attempt_conversion_categories_terminalize_after_their_retry_fails_again() {
        for (asset_id, kind, message) in [
            (
                "unreadable",
                FailureKind::ConversionOutputUnreadable,
                "converted output is missing or unreadable at /output/unreadable.oriented-preview.jpg: interrupted",
            ),
            (
                "metadata",
                FailureKind::ConversionMetadataFailed,
                "metadata command failed: exiftool exited with exit status: 1",
            ),
        ] {
            let mut manifest = Manifest::new();
            manifest.upsert(policy_failed_record(
                asset_id,
                "conversion",
                message,
                Some(kind),
                "100.000000000Z",
            ));

            admit_failed_retryable_assets(&mut manifest, 1, 1, 300, 3_000_000)
                .expect("first retry should admit");
            assert_eq!(manifest.get(asset_id).unwrap().state, State::NasVerified);
            assert_eq!(
                manifest.get(asset_id).unwrap().proofs["failure_retry"]["attempt"],
                json!(1)
            );

            policy_failed_again(&mut manifest, asset_id, "conversion", message, kind);
            let exhausted = admit_failed_retryable_assets(&mut manifest, 1, 1, 300, 3_000_000)
                .expect("failed retry should terminalize");
            assert_eq!(exhausted.exhausted, 1);
            assert_eq!(manifest.get(asset_id).unwrap().state, State::NeedsReview);
        }
    }

    #[test]
    fn retry_backoff_and_interrupted_admission_do_not_duplicate_attempts() {
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "recent",
            "conversion",
            "conversion command timed out after 120000 ms: heif-enc",
            Some(FailureKind::ConversionTimedOut),
            "2999900.000000000Z",
        ));
        manifest.upsert(policy_failed_record(
            "admitted",
            "conversion",
            "conversion command timed out after 120000 ms: heif-enc",
            Some(FailureKind::ConversionTimedOut),
            "100.000000000Z",
        ));

        let first = admit_failed_retryable_assets(&mut manifest, 2, 2, 300, 3_000_000)
            .expect("old retry should admit");
        assert_eq!(first.backoff, 1);
        assert_eq!(manifest.get("recent").unwrap().state, State::Failed);
        assert_eq!(
            manifest.get("admitted").unwrap().proofs["failure_retry"]["attempt"],
            json!(1)
        );

        let resumed = admit_failed_retryable_assets(&mut manifest, 2, 2, 300, 3_000_000)
            .expect("interrupted admitted state should continue without readmission");
        assert!(resumed.admitted_by_category.is_empty());
        assert_eq!(
            manifest.get("admitted").unwrap().proofs["failure_retry"]["attempt"],
            json!(1)
        );
    }

    #[test]
    fn queue_counts_visual_match_without_touching_its_unavailable_output() {
        let mut record = policy_failed_record(
            "visual-match",
            "heic_verify",
            "HEIC verification failed: visual_match_ok",
            Some(FailureKind::HeicVisualMatch),
            "100.000000000Z",
        );
        record.proofs.insert(
            "conversion".to_string(),
            json!({
                "heic_path": "/sentinel/unavailable-visual-match.heic",
                "heic_sha256": "ab".repeat(32),
                "size_bytes": 1u64,
            }),
        );
        let mut manifest = Manifest::new();
        manifest.upsert(record);

        assert_eq!(
            failed_retry_queue_counts(&manifest)["retryable_heic_visual_match_pending_integrity_check"],
            1
        );

        let admission = admit_failed_retryable_assets(&mut manifest, 1, 1, 300, 3_000_000)
            .expect("admission should fail closed after its integrity check");
        assert_eq!(admission.blocked_source_proof, 1);
        assert_eq!(manifest.get("visual-match").unwrap().state, State::Failed);
    }

    #[test]
    fn first_attempt_visual_matches_with_missing_or_malformed_conversion_proofs_are_blocked() {
        for (asset_id, conversion_proof) in [
            ("missing-proof", None),
            (
                "malformed-proof",
                Some(json!({
                    "heic_path": "",
                    "heic_sha256": "not-a-sha256",
                    "size_bytes": 0u64,
                })),
            ),
        ] {
            let mut record = policy_failed_record(
                asset_id,
                "heic_verify",
                "HEIC verification failed: visual_match_ok",
                Some(FailureKind::HeicVisualMatch),
                "100.000000000Z",
            );
            if let Some(conversion_proof) = conversion_proof {
                record
                    .proofs
                    .insert("conversion".to_string(), conversion_proof);
            }
            let mut manifest = Manifest::new();
            manifest.upsert(record);

            assert_eq!(
                failed_retry_queue_counts(&manifest)["blocked_source_proof"],
                1
            );
            let admission = admit_failed_retryable_assets(&mut manifest, 1, 1, 300, 3_000_000)
                .expect("first visual-match retry should fail closed without a valid proof");
            assert_eq!(admission.blocked_source_proof, 1);
            assert_eq!(manifest.get(asset_id).unwrap().state, State::Failed);
        }
    }

    #[test]
    fn exhausted_visual_matches_terminalize_before_conversion_proof_shape_validation() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let bytes = b"verified heic";
        for (asset_id, conversion_proof) in [
            ("exhausted-missing", None),
            (
                "exhausted-malformed",
                Some(json!({
                    "heic_path": "",
                    "heic_sha256": "not-a-sha256",
                    "size_bytes": 0u64,
                })),
            ),
        ] {
            let heic_path = tempdir.path().join(format!("{asset_id}.heic"));
            fs::write(&heic_path, bytes).expect("HEIC should be written");
            let mut record = policy_failed_record(
                asset_id,
                "heic_verify",
                "HEIC verification failed: visual_match_ok",
                Some(FailureKind::HeicVisualMatch),
                "100.000000000Z",
            );
            record.proofs.insert(
                "conversion".to_string(),
                json!({
                    "heic_path": heic_path,
                    "heic_sha256": format!("{:x}", Sha256::digest(bytes)),
                    "size_bytes": bytes.len() as u64,
                }),
            );
            let mut manifest = Manifest::new();
            manifest.upsert(record);
            admit_failed_retryable_assets(&mut manifest, 1, 1, 300, 3_000_000)
                .expect("initial visual-match retry should admit");

            policy_failed_again_at(
                &mut manifest,
                asset_id,
                "heic_verify",
                "HEIC verification failed: visual_match_ok",
                FailureKind::HeicVisualMatch,
                "101.000000000Z",
            );
            let mut record = manifest.get(asset_id).expect("asset should remain").clone();
            match conversion_proof {
                Some(conversion_proof) => {
                    record
                        .proofs
                        .insert("conversion".to_string(), conversion_proof);
                }
                None => {
                    record.proofs.remove("conversion");
                }
            }
            manifest.upsert(record);

            assert_eq!(
                failed_retry_queue_counts(&manifest)["terminalize_retry_attempts_exhausted"],
                1
            );
            let admission = admit_failed_retryable_assets(&mut manifest, 1, 1, 300, 3_000_000)
                .expect("exhausted visual-match retry should terminalize");
            assert_eq!(admission.exhausted, 1);
            assert_eq!(manifest.get(asset_id).unwrap().state, State::NeedsReview);
        }
    }

    #[test]
    fn visual_match_with_malformed_retry_lineage_is_unknown_before_proof_shape_validation() {
        let mut record = policy_failed_record(
            "malformed-lineage",
            "heic_verify",
            "HEIC verification failed: visual_match_ok",
            Some(FailureKind::HeicVisualMatch),
            "100.000000000Z",
        );
        record.proofs.insert(
            FAILURE_RETRY_PROOF.to_string(),
            json!({"schema_version": 2}),
        );
        let mut manifest = Manifest::new();
        manifest.upsert(record);

        assert_eq!(failed_retry_queue_counts(&manifest)["failed_unknown"], 1);
        let admission = admit_failed_retryable_assets(&mut manifest, 1, 1, 300, 3_000_000)
            .expect("malformed lineage should fail closed");
        assert_eq!(admission.unknown, 1);
        assert_eq!(
            manifest.get("malformed-lineage").unwrap().state,
            State::Failed
        );
    }

    #[test]
    fn failure_digest_distinguishes_identical_failures_at_different_times() {
        let first = crate::manifest::FailureRecord {
            stage: "conversion".to_string(),
            message: "conversion command timed out after 120000 ms: heif-enc".to_string(),
            recorded_at: "100.000000000Z".to_string(),
            kind: Some(FailureKind::ConversionTimedOut),
        };
        let second = crate::manifest::FailureRecord {
            recorded_at: "101.000000000Z".to_string(),
            ..first.clone()
        };

        assert_ne!(failure_digest(&first), failure_digest(&second));
    }

    #[test]
    fn failed_retry_lineage_blocks_state_regression_without_a_new_failure() {
        let mut manifest = admitted_timeout_manifest("state-regression");
        let mut record = manifest.get("state-regression").unwrap().clone();
        record.state = State::Failed;
        manifest.upsert(record);

        let admission = admit_failed_retryable_assets(&mut manifest, 1, 1, 300, 3_000_000)
            .expect("unproven retry lineage should not be admitted");

        assert_eq!(admission.unknown, 1);
        assert_eq!(
            manifest.get("state-regression").unwrap().state,
            State::Failed
        );
    }

    #[test]
    fn failed_retry_lineage_rejects_mutated_or_multiple_failure_history() {
        let mut mutated = admitted_timeout_manifest("mutated");
        let mut record = mutated.get("mutated").unwrap().clone();
        record.failures[0].message = "altered historical failure".to_string();
        mutated.upsert(record);
        policy_failed_again_at(
            &mut mutated,
            "mutated",
            "conversion",
            "conversion command timed out after 120000 ms: heif-enc",
            FailureKind::ConversionTimedOut,
            "101.000000000Z",
        );

        let mutated_admission = admit_failed_retryable_assets(&mut mutated, 1, 1, 300, 3_000_000)
            .expect("mutated history should fail closed");
        assert_eq!(mutated_admission.unknown, 1);
        assert_eq!(mutated.get("mutated").unwrap().state, State::Failed);

        let mut multiple = admitted_timeout_manifest("multiple");
        for timestamp in ["101.000000000Z", "102.000000000Z"] {
            policy_failed_again_at(
                &mut multiple,
                "multiple",
                "conversion",
                "conversion command timed out after 120000 ms: heif-enc",
                FailureKind::ConversionTimedOut,
                timestamp,
            );
        }

        let multiple_admission = admit_failed_retryable_assets(&mut multiple, 1, 1, 300, 3_000_000)
            .expect("multiple appended failures should fail closed");
        assert_eq!(multiple_admission.unknown, 1);
        assert_eq!(multiple.get("multiple").unwrap().state, State::Failed);
    }

    #[test]
    fn failed_retry_lineage_requires_matching_retry_state_and_carries_one_append() {
        let mut wrong_state = admitted_timeout_manifest("wrong-state");
        let mut record = wrong_state.get("wrong-state").unwrap().clone();
        record
            .proofs
            .get_mut(FAILURE_RETRY_PROOF)
            .and_then(Value::as_object_mut)
            .expect("retry proof should be an object")
            .insert("retry_state".to_string(), json!("converted"));
        wrong_state.upsert(record);
        policy_failed_again_at(
            &mut wrong_state,
            "wrong-state",
            "conversion",
            "conversion command timed out after 120000 ms: heif-enc",
            FailureKind::ConversionTimedOut,
            "101.000000000Z",
        );
        let wrong_state_admission =
            admit_failed_retryable_assets(&mut wrong_state, 1, 1, 300, 3_000_000)
                .expect("wrong retry state should fail closed");
        assert_eq!(wrong_state_admission.unknown, 1);

        let mut valid = admitted_timeout_manifest("valid");
        policy_failed_again_at(
            &mut valid,
            "valid",
            "conversion",
            "conversion command timed out after 120000 ms: heif-enc",
            FailureKind::ConversionTimedOut,
            "101.000000000Z",
        );
        let valid_admission = admit_failed_retryable_assets(&mut valid, 1, 1, 300, 3_000_000)
            .expect("one appended failure should carry the attempt");
        assert_eq!(
            valid_admission.admitted_by_category["retryable_conversion_timed_out"],
            1
        );
        let record = valid.get("valid").unwrap();
        let proof = &record.proofs[FAILURE_RETRY_PROOF];
        assert_eq!(proof["schema_version"], json!(2));
        assert_eq!(proof["attempt"], json!(2));
        assert_eq!(proof["last_failure_stage"], json!("conversion"));
        assert_eq!(proof["last_failure_kind"], json!("conversion_timed_out"));
        assert_eq!(proof["last_failure_recorded_at"], json!("101.000000000Z"));
        assert_eq!(proof["failure_count_at_admission"], json!(2));
        assert_eq!(proof["retry_state"], json!("nas_verified"));
        assert_eq!(
            proof["last_failure_digest"],
            json!(failure_digest(record.failures.last().unwrap()))
        );
    }

    #[test]
    fn valid_new_failure_category_starts_a_fresh_attempt_after_proven_lineage() {
        let mut manifest = admitted_timeout_manifest("new-category");
        policy_failed_again_at(
            &mut manifest,
            "new-category",
            "conversion",
            "metadata command failed: exiftool exited with exit status: 1",
            FailureKind::ConversionMetadataFailed,
            "101.000000000Z",
        );

        let admission = admit_failed_retryable_assets(&mut manifest, 1, 1, 300, 3_000_000)
            .expect("new category with a proven appended failure should admit freshly");

        assert_eq!(
            admission.admitted_by_category["retryable_conversion_metadata_failed"],
            1
        );
        let proof = &manifest.get("new-category").unwrap().proofs[FAILURE_RETRY_PROOF];
        assert_eq!(proof["attempt"], json!(1));
        assert_eq!(proof["category"], json!("conversion_metadata_failed"));
    }

    #[test]
    fn retry_blocking_proofs_and_missing_preview_never_admit() {
        let mut manifest = Manifest::new();
        for proof_key in RETRY_BLOCKING_PROOFS {
            let mut record = policy_failed_record(
                proof_key,
                "conversion",
                "conversion command timed out after 120000 ms: heif-enc",
                Some(FailureKind::ConversionTimedOut),
                "100.000000000Z",
            );
            record
                .proofs
                .insert(proof_key.to_string(), json!({"present": true}));
            manifest.upsert(record);
        }
        manifest.upsert(policy_failed_record(
            "missing-preview",
            "conversion",
            "RAW has neither PreviewImage nor JpgFromRaw embedded preview: /raw/missing-preview.DNG",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        manifest.upsert(policy_failed_record(
            "unknown",
            "conversion",
            "unclassified failure",
            None,
            "100.000000000Z",
        ));

        let admission = admit_failed_retryable_assets(&mut manifest, 16, 16, 300, 3_000_000)
            .expect("blocked records should not fail policy evaluation");
        assert_eq!(
            admission.blocked_downstream_proof,
            RETRY_BLOCKING_PROOFS.len()
        );
        assert_eq!(admission.blocked_missing_preview, 1);
        assert_eq!(admission.unknown, 1);
        for asset_id in RETRY_BLOCKING_PROOFS
            .iter()
            .copied()
            .chain(["missing-preview", "unknown"])
        {
            assert_eq!(manifest.get(asset_id).unwrap().state, State::Failed);
        }
    }

    #[test]
    fn adjusted_source_first_admission_keeps_failed_and_records_exact_marker() {
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "adjusted-first",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));

        let admission = admit_adjusted_source_required_assets(&mut manifest, 1, 1, 3_000_000)
            .expect("typed missing-preview failure should receive an adjusted-source marker");

        assert_eq!(admission.first_ready, 1);
        assert_eq!(admission.resolver_retry_ready, 0);
        let record = manifest
            .get("adjusted-first")
            .expect("record should remain");
        assert_eq!(record.state, State::Failed);
        let marker = &record.proofs[ADJUSTED_SOURCE_REQUIRED_PROOF];
        assert_eq!(marker["schema_version"], json!(1));
        assert_eq!(
            marker["policy_generation"],
            json!("adjusted_source_required_v1")
        );
        assert_eq!(marker["asset_id"], json!("adjusted-first"));
        assert_eq!(marker["attempt"], json!(1));
        assert_eq!(
            marker["trigger_failure_kind"],
            json!("embedded_preview_unavailable")
        );
        assert_eq!(marker["failure_count_at_admission"], json!(1));
        assert_eq!(
            marker["trigger_failure_digest"],
            json!(failure_digest(record.failures.last().unwrap()))
        );
        assert_eq!(
            marker["failure_history_digest"],
            json!(failure_history_digest(&record.failures))
        );
        assert_eq!(marker["required_retry_state"], json!("nas_verified"));
        assert_eq!(
            marker["adjusted_source_relative_path"],
            json!("adjusted-first.adjusted-source.jpg")
        );
        assert_eq!(marker["failure_retry_proof_digest"], Value::Null);
        assert!(adjusted_source_required_proof(record).is_ok());
    }

    #[test]
    fn adjusted_source_marker_survives_restart_and_retries_once_after_backoff() {
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "adjusted-retry",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("first admission should write the marker");
        let marker_before_restart = manifest
            .get("adjusted-retry")
            .expect("marker record should exist")
            .proofs[ADJUSTED_SOURCE_REQUIRED_PROOF]
            .clone();

        let resumed = admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_001)
            .expect("restart should reuse the durable marker");
        assert_eq!(resumed.first_ready, 1);
        assert!(!resumed.manifest_changed());
        assert_eq!(
            manifest.get("adjusted-retry").unwrap().proofs[ADJUSTED_SOURCE_REQUIRED_PROOF],
            marker_before_restart
        );

        policy_failed_again_at(
            &mut manifest,
            "adjusted-retry",
            "adjusted_source_resolve",
            "CloudKit adjusted source lookup failed",
            FailureKind::AdjustedSourceResolveFailed,
            "400.000000000Z",
        );
        let retry = admit_adjusted_source_required_assets(&mut manifest, 1, 1, 700)
            .expect("one resolver failure should admit retry attempt two after backoff");
        assert_eq!(retry.resolver_retry_ready, 1);
        let record = manifest.get("adjusted-retry").unwrap();
        assert_eq!(record.state, State::Failed);
        assert_eq!(
            record.proofs[ADJUSTED_SOURCE_REQUIRED_PROOF]["attempt"],
            json!(2)
        );
        assert_eq!(
            record.proofs[ADJUSTED_SOURCE_REQUIRED_PROOF]["failure_count_at_admission"],
            json!(2)
        );
        assert_eq!(
            record.proofs[ADJUSTED_SOURCE_REQUIRED_PROOF]["failure_history_digest"],
            json!(failure_history_digest(&record.failures))
        );
        assert!(adjusted_source_required_proof(record).is_ok());
    }

    #[test]
    fn adjusted_source_retry_backoff_and_attempt_exhaustion_are_bounded() {
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "adjusted-exhausted",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("first admission should succeed");
        policy_failed_again_at(
            &mut manifest,
            "adjusted-exhausted",
            "adjusted_source_resolve",
            "resolver failure one",
            FailureKind::AdjustedSourceResolveFailed,
            "400.000000000Z",
        );

        let too_young = admit_adjusted_source_required_assets(&mut manifest, 1, 1, 699)
            .expect("young resolver failure should be deferred");
        assert_eq!(too_young.backoff, 1);
        assert_eq!(
            manifest.get("adjusted-exhausted").unwrap().proofs[ADJUSTED_SOURCE_REQUIRED_PROOF]["attempt"],
            json!(1)
        );
        assert_eq!(
            adjusted_source_required_queue_counts(&manifest, 699)["adjusted_source_resolver_backoff"],
            1
        );

        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 700)
            .expect("second resolver attempt should be admitted");
        policy_failed_again_at(
            &mut manifest,
            "adjusted-exhausted",
            "adjusted_source_resolve",
            "resolver failure two",
            FailureKind::AdjustedSourceResolveFailed,
            "1000.000000000Z",
        );
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_300)
            .expect("third resolver attempt should be admitted");
        policy_failed_again_at(
            &mut manifest,
            "adjusted-exhausted",
            "adjusted_source_resolve",
            "resolver failure three",
            FailureKind::AdjustedSourceResolveFailed,
            "1_600.000000000Z",
        );

        let exhausted = admit_adjusted_source_required_assets(&mut manifest, 1, 1, 2_000)
            .expect("a fourth resolver execution must not be admitted");
        assert_eq!(exhausted.exhausted, 1);
        assert_eq!(
            adjusted_source_required_queue_counts(&manifest, 2_000)["adjusted_source_resolver_exhausted"],
            1
        );
        assert_eq!(
            manifest.get("adjusted-exhausted").unwrap().state,
            State::Failed
        );

        terminalize_adjusted_source_required_exhaustion(&mut manifest, "adjusted-exhausted", 2_000)
            .expect("exhausted resolver lineage should terminalize with failure-review evidence");
        let record = manifest.get("adjusted-exhausted").unwrap();
        assert_eq!(record.state, State::NeedsReview);
        assert_eq!(
            record.proofs[FAILURE_REVIEW_PROOF]["reason_code"],
            json!("adjusted_source_resolve_attempts_exhausted")
        );
    }

    #[test]
    fn adjusted_source_policy_rejects_forged_lineage_without_mutation() {
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "forged-adjusted",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("first admission should succeed");
        policy_failed_again_at(
            &mut manifest,
            "forged-adjusted",
            "adjusted_source_resolve",
            "resolver failure",
            FailureKind::AdjustedSourceResolveFailed,
            "400.000000000Z",
        );
        let base = manifest.clone();
        for (name, mutate) in [
            (
                "history",
                Box::new(|record: &mut AssetRecord| {
                    record.failures[0].message = "forged historical failure".to_string();
                }) as Box<dyn Fn(&mut AssetRecord)>,
            ),
            (
                "original",
                Box::new(|record: &mut AssetRecord| {
                    record.proofs.get_mut("original_asset").unwrap()["record_name"] =
                        json!("forged");
                }),
            ),
            (
                "nas",
                Box::new(|record: &mut AssetRecord| {
                    record.proofs.get_mut("nas").unwrap()["sha256"] = json!("forged");
                }),
            ),
            (
                "failure-retry",
                Box::new(|record: &mut AssetRecord| {
                    record
                        .proofs
                        .insert("failure_retry".to_string(), json!({"forged": true}));
                }),
            ),
            (
                "marker",
                Box::new(|record: &mut AssetRecord| {
                    record
                        .proofs
                        .get_mut(ADJUSTED_SOURCE_REQUIRED_PROOF)
                        .unwrap()["attempt"] = json!(2);
                }),
            ),
            (
                "extra-failure",
                Box::new(|record: &mut AssetRecord| {
                    record.failures.push(crate::manifest::FailureRecord {
                        stage: "adjusted_source_resolve".to_string(),
                        message: "extra resolver failure".to_string(),
                        recorded_at: "401.000000000Z".to_string(),
                        kind: Some(FailureKind::AdjustedSourceResolveFailed),
                    });
                }),
            ),
        ] {
            let mut forged = base.clone();
            let mut record = forged.get("forged-adjusted").unwrap().clone();
            mutate(&mut record);
            forged.upsert(record);
            let before_admission = forged.clone();

            let admission = admit_adjusted_source_required_assets(&mut forged, 1, 1, 1_000)
                .unwrap_or_else(|error| panic!("{name} must fail closed: {error}"));
            assert_eq!(forged, before_admission, "{name} must not partially mutate");
            assert_eq!(forged.get("forged-adjusted").unwrap().state, State::Failed);
            assert_eq!(
                admission.source_proof_blocked + admission.malformed_or_unknown,
                1,
                "{name} must be rejected by admission"
            );
        }
    }

    #[test]
    fn adjusted_source_marker_binds_existing_failure_retry_and_rejects_kind_reset() {
        let mut manifest = admitted_timeout_manifest("retry-bound-adjusted");
        policy_failed_again_at(
            &mut manifest,
            "retry-bound-adjusted",
            "conversion",
            "RAW has no usable embedded preview",
            FailureKind::EmbeddedPreviewUnavailable,
            "400.000000000Z",
        );
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("missing-preview marker should bind the existing generic retry proof");
        let marker = manifest.get("retry-bound-adjusted").unwrap().proofs
            [ADJUSTED_SOURCE_REQUIRED_PROOF]
            .clone();
        assert!(marker["failure_retry_proof_digest"].is_string());

        policy_failed_again_at(
            &mut manifest,
            "retry-bound-adjusted",
            "conversion",
            "conversion command timed out after 120000 ms: heif-enc",
            FailureKind::ConversionTimedOut,
            "500.000000000Z",
        );
        let before = manifest.clone();
        let admission = admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("a changed failure kind must not reset adjusted-source attempts");
        assert_eq!(admission.malformed_or_unknown, 1);
        assert_eq!(manifest, before);
    }

    #[test]
    fn adjusted_source_admission_rejects_legacy_missing_preview_without_inference() {
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "legacy-missing-preview",
            "conversion",
            "RAW has neither PreviewImage nor JpgFromRaw embedded preview: /staging/legacy-missing-preview.staged-raw.DNG",
            None,
            "100.000000000Z",
        ));

        let admission = admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("legacy records should remain untouched");
        assert_eq!(admission.first_ready, 0);
        let record = manifest.get("legacy-missing-preview").unwrap();
        assert_eq!(record.state, State::Failed);
        assert!(!record.proofs.contains_key(ADJUSTED_SOURCE_REQUIRED_PROOF));
        assert!(adjusted_source_required_queue_counts(&manifest, 1_000).is_empty());
    }

    #[test]
    fn adjusted_source_queue_counts_are_manifest_only_and_time_injected() {
        let mut manifest = Manifest::new();
        for asset_id in ["first", "source", "downstream"] {
            manifest.upsert(policy_failed_record(
                asset_id,
                "conversion",
                "RAW has no usable embedded preview",
                Some(FailureKind::EmbeddedPreviewUnavailable),
                "100.000000000Z",
            ));
        }
        let mut source = manifest.get("source").unwrap().clone();
        source.proofs.remove("nas");
        manifest.upsert(source);
        let mut downstream = manifest.get("downstream").unwrap().clone();
        downstream
            .proofs
            .insert("conversion".to_string(), json!({"present": true}));
        manifest.upsert(downstream);
        manifest.upsert(policy_failed_record(
            "unknown",
            "adjusted_source_resolve",
            "resolver failure without an admission marker",
            Some(FailureKind::AdjustedSourceResolveFailed),
            "100.000000000Z",
        ));

        admit_adjusted_source_required_assets(&mut manifest, 4, 4, 1_000)
            .expect("the first record should receive a marker");
        policy_failed_again_at(
            &mut manifest,
            "first",
            "adjusted_source_resolve",
            "resolver failure",
            FailureKind::AdjustedSourceResolveFailed,
            "400.000000000Z",
        );

        let backoff = failed_retry_queue_counts_at(&manifest, 699);
        assert_eq!(backoff["adjusted_source_resolver_backoff"], 1);
        assert_eq!(backoff["adjusted_source_source_proof_blocked"], 1);
        assert_eq!(backoff["adjusted_source_downstream_proof_blocked"], 1);
        assert_eq!(backoff["adjusted_source_malformed_or_unknown"], 1);

        let ready = failed_retry_queue_counts_at(&manifest, 700);
        assert_eq!(ready["adjusted_source_resolver_retry_ready"], 1);
        assert_eq!(ready["adjusted_source_source_proof_blocked"], 1);
        assert_eq!(ready["adjusted_source_downstream_proof_blocked"], 1);
        assert_eq!(ready["adjusted_source_malformed_or_unknown"], 1);
    }

    #[test]
    fn adjusted_source_policy_blocks_downstream_proofs_and_generic_recovery() {
        let mut manifest = Manifest::new();
        let mut downstream = policy_failed_record(
            "downstream-adjusted",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        );
        downstream
            .proofs
            .insert("conversion".to_string(), json!({"present": true}));
        manifest.upsert(downstream);
        let downstream_admission =
            admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
                .expect("downstream evidence should block adjusted-source admission");
        assert_eq!(downstream_admission.downstream_proof_blocked, 1);
        assert_eq!(
            adjusted_source_required_queue_counts(&manifest, 1_000)["adjusted_source_downstream_proof_blocked"],
            1
        );

        manifest.upsert(policy_failed_record(
            "generic-adjusted",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 2, 2, 1_000)
            .expect("marker should be written before generic exclusion check");
        policy_failed_again_at(
            &mut manifest,
            "generic-adjusted",
            "conversion",
            "conversion command timed out after 120000 ms: heif-enc",
            FailureKind::ConversionTimedOut,
            "400.000000000Z",
        );
        let generic = admit_failed_retryable_assets(&mut manifest, 2, 2, 300, 1_000)
            .expect("generic retry evaluation should not recover adjusted-source work");
        assert_eq!(generic.unknown, 1);
        assert_eq!(
            manifest.get("generic-adjusted").unwrap().state,
            State::Failed
        );
        assert_eq!(
            manifest.get("generic-adjusted").unwrap().proofs[ADJUSTED_SOURCE_REQUIRED_PROOF]["attempt"],
            json!(1)
        );
    }

    #[test]
    fn adjusted_source_admission_is_ordered_capacity_bounded_and_duplicate_free() {
        let mut manifest = Manifest::new();
        for (asset_id, recorded_at) in [
            ("middle", "200.000000000Z"),
            ("newest", "300.000000000Z"),
            ("oldest", "100.000000000Z"),
        ] {
            manifest.upsert(policy_failed_record(
                asset_id,
                "conversion",
                "RAW has no usable embedded preview",
                Some(FailureKind::EmbeddedPreviewUnavailable),
                recorded_at,
            ));
        }

        let first = admit_adjusted_source_required_assets(&mut manifest, 2, 2, 1_000)
            .expect("oldest candidates should consume bounded marker capacity");
        assert_eq!(first.first_ready, 2);
        for asset_id in ["oldest", "middle"] {
            assert!(
                manifest
                    .get(asset_id)
                    .unwrap()
                    .proofs
                    .contains_key(ADJUSTED_SOURCE_REQUIRED_PROOF)
            );
        }
        assert!(
            !manifest
                .get("newest")
                .unwrap()
                .proofs
                .contains_key(ADJUSTED_SOURCE_REQUIRED_PROOF)
        );

        let restart = admit_adjusted_source_required_assets(&mut manifest, 2, 2, 1_001)
            .expect("existing markers should reserve capacity without duplicating admission");
        assert_eq!(restart.first_ready, 2);
        assert!(!restart.manifest_changed());
        assert!(
            !manifest
                .get("newest")
                .unwrap()
                .proofs
                .contains_key(ADJUSTED_SOURCE_REQUIRED_PROOF)
        );
    }

    #[test]
    fn adjusted_source_selector_shares_one_ordered_cap_between_first_and_retry_candidates() {
        let mut base = Manifest::new();
        base.upsert(policy_failed_record(
            "z-retry",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "050.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut base, 2, 2, 1_000)
            .expect("first resolver marker should be admitted");
        policy_failed_again_at(
            &mut base,
            "z-retry",
            "adjusted_source_resolve",
            "resolver failure",
            FailureKind::AdjustedSourceResolveFailed,
            "100.000000000Z",
        );
        base.upsert(policy_failed_record(
            "a-first",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "200.000000000Z",
        ));

        let mut cap_one = base.clone();
        let admission = admit_adjusted_source_required_assets(&mut cap_one, 2, 1, 1_000)
            .expect("one shared admission token should select the oldest retry");
        assert_eq!(admission.resolver_retry_ready, 1);
        assert_eq!(admission.first_ready, 0);
        assert_eq!(
            cap_one.get("z-retry").unwrap().proofs[ADJUSTED_SOURCE_REQUIRED_PROOF]["attempt"],
            json!(2)
        );
        assert!(
            !cap_one
                .get("a-first")
                .unwrap()
                .proofs
                .contains_key(ADJUSTED_SOURCE_REQUIRED_PROOF)
        );

        let mut cap_zero = base;
        let before = cap_zero.clone();
        let admission = admit_adjusted_source_required_assets(&mut cap_zero, 2, 0, 1_000)
            .expect("zero shared admission tokens must admit neither candidate");
        assert_eq!(admission.first_ready, 0);
        assert_eq!(admission.resolver_retry_ready, 0);
        assert_eq!(cap_zero, before);
    }

    #[test]
    fn adjusted_source_bounded_selector_keeps_a_later_retry_when_first_slots_are_exhausted() {
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "retry-later",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "010.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 2, 2, 1_000)
            .expect("first marker should reserve one of two lifecycle slots");
        policy_failed_again_at(
            &mut manifest,
            "retry-later",
            "adjusted_source_resolve",
            "resolver failure",
            FailureKind::AdjustedSourceResolveFailed,
            "400.000000000Z",
        );
        for (asset_id, recorded_at) in [
            ("first-oldest", "100.000000000Z"),
            ("first-skipped", "200.000000000Z"),
        ] {
            manifest.upsert(policy_failed_record(
                asset_id,
                "conversion",
                "RAW has no usable embedded preview",
                Some(FailureKind::EmbeddedPreviewUnavailable),
                recorded_at,
            ));
        }

        let mut budget = LifecycleAdmissionBudget::for_scan(&manifest, 2);
        assert_eq!(budget.remaining_slots(), 1);
        let admission =
            admit_adjusted_source_required_assets_with_budget(&mut manifest, &mut budget, 2, 1_000)
                .expect("the later retry must remain selectable after first slots are exhausted");

        assert_eq!(admission.first_ready, 1);
        assert_eq!(admission.resolver_retry_ready, 1);
        assert!(
            manifest
                .get("first-oldest")
                .unwrap()
                .proofs
                .contains_key(ADJUSTED_SOURCE_REQUIRED_PROOF)
        );
        assert!(
            !manifest
                .get("first-skipped")
                .unwrap()
                .proofs
                .contains_key(ADJUSTED_SOURCE_REQUIRED_PROOF)
        );
        assert_eq!(
            manifest.get("retry-later").unwrap().proofs[ADJUSTED_SOURCE_REQUIRED_PROOF]["attempt"],
            json!(2)
        );
    }

    #[test]
    fn adjusted_source_bounded_selection_updates_only_the_oldest_selected_records() {
        let mut manifest = Manifest::new();
        for index in 0..256 {
            let asset_id = format!("candidate-{index:03}");
            let recorded_at = format!("{index:03}.000000000Z");
            manifest.upsert(policy_failed_record(
                &asset_id,
                "conversion",
                "RAW has no usable embedded preview",
                Some(FailureKind::EmbeddedPreviewUnavailable),
                &recorded_at,
            ));
        }
        let before = manifest.clone();

        let admission = admit_adjusted_source_required_assets(&mut manifest, 4, 4, 1_000)
            .expect("bounded selection should admit exactly the four oldest candidates");

        assert_eq!(admission.first_ready, 4);
        for index in 0..256 {
            let asset_id = format!("candidate-{index:03}");
            let record = manifest.get(&asset_id).unwrap();
            if index < 4 {
                assert!(
                    record.proofs.contains_key(ADJUSTED_SOURCE_REQUIRED_PROOF),
                    "{asset_id} should be selected"
                );
                assert_ne!(record, before.get(&asset_id).unwrap());
            } else {
                assert_eq!(record, before.get(&asset_id).unwrap());
            }
        }
    }

    #[test]
    fn adjusted_source_staging_error_rolls_back_selected_records_and_budget() {
        let mut manifest = Manifest::new();
        for (asset_id, recorded_at) in [("first", "100.000000000Z"), ("second", "200.000000000Z")] {
            manifest.upsert(policy_failed_record(
                asset_id,
                "conversion",
                "RAW has no usable embedded preview",
                Some(FailureKind::EmbeddedPreviewUnavailable),
                recorded_at,
            ));
        }
        let before_manifest = manifest.clone();
        let mut budget = LifecycleAdmissionBudget::for_scan(&manifest, 2);
        let before_budget = budget;

        let error = admit_adjusted_source_required_assets_with_budget_and_stager(
            &mut manifest,
            &mut budget,
            2,
            1_000,
            |staged, asset_id, value| {
                if asset_id == "second" {
                    return Err(ManifestError::UnknownAsset {
                        asset_id: "injected-staging-error".to_string(),
                    });
                }
                staged
                    .record_proof(asset_id, ADJUSTED_SOURCE_REQUIRED_PROOF, value)
                    .map(|_| ())
            },
        )
        .expect_err("an injected selected-record staging failure must abort the whole admission");

        assert!(matches!(error, ManifestError::UnknownAsset { .. }));
        assert_eq!(manifest, before_manifest);
        assert_eq!(budget, before_budget);
    }

    #[test]
    fn scan_admission_does_not_spend_an_existing_adjusted_marker_reservation_twice() {
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "adjusted-reservation",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("first adjusted marker should reserve the only lifecycle slot");
        manifest.upsert(policy_failed_record(
            "generic-retry",
            "conversion",
            "conversion command timed out after 120000 ms: heif-enc",
            Some(FailureKind::ConversionTimedOut),
            "100.000000000Z",
        ));

        let admissions =
            admit_scan_retry_policies(&mut manifest, 1, 16, 300, 16, 86_400, 1_000_000)
                .expect("shared lifecycle budget should preserve the marker reservation");

        assert!(admissions.failed_retry.admitted_by_category.is_empty());
        assert_eq!(manifest.get("generic-retry").unwrap().state, State::Failed);
        assert_eq!(
            manifest.get("adjusted-reservation").unwrap().state,
            State::Failed
        );

        let repeated = admit_scan_retry_policies(&mut manifest, 1, 16, 300, 16, 86_400, 1_000_000)
            .expect("the same marker must reserve exactly one slot on later scans");
        assert!(repeated.failed_retry.admitted_by_category.is_empty());
        assert_eq!(manifest.get("generic-retry").unwrap().state, State::Failed);
    }

    #[test]
    fn scan_admission_generic_recovery_leaves_no_slot_for_a_new_adjusted_marker() {
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "generic-first",
            "conversion",
            "conversion command timed out after 120000 ms: heif-enc",
            Some(FailureKind::ConversionTimedOut),
            "100.000000000Z",
        ));
        manifest.upsert(policy_failed_record(
            "adjusted-second",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "200.000000000Z",
        ));

        let admissions =
            admit_scan_retry_policies(&mut manifest, 1, 16, 300, 16, 86_400, 1_000_000)
                .expect("generic recovery should consume the scan's only lifecycle slot");

        assert_eq!(
            admissions.failed_retry.admitted_by_category["retryable_conversion_timed_out"],
            1
        );
        assert_eq!(
            manifest.get("generic-first").unwrap().state,
            State::NasVerified
        );
        let adjusted = manifest.get("adjusted-second").unwrap();
        assert_eq!(adjusted.state, State::Failed);
        assert!(!adjusted.proofs.contains_key(ADJUSTED_SOURCE_REQUIRED_PROOF));
    }

    #[test]
    fn scan_admission_new_adjusted_marker_leaves_no_slot_for_original_resolver_retry() {
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "adjusted-first",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        manifest.upsert(failed_original_asset_resolve_record(
            "original-second",
            "100.000000000Z",
        ));

        let admissions =
            admit_scan_retry_policies(&mut manifest, 1, 16, 300, 16, 86_400, 1_000_000)
                .expect("new adjusted marker should consume the scan's only lifecycle slot");

        assert_eq!(admissions.adjusted_source_required.first_ready, 1);
        assert_eq!(admissions.original_asset_resolver.recovered_now, 0);
        assert!(
            manifest
                .get("adjusted-first")
                .unwrap()
                .proofs
                .contains_key(ADJUSTED_SOURCE_REQUIRED_PROOF)
        );
        assert_eq!(
            manifest.get("original-second").unwrap().state,
            State::Failed
        );
    }

    #[test]
    fn scan_admission_retry_marker_uses_a_token_but_not_a_second_lifecycle_slot() {
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "z-retry",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "010.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("first marker should reserve the only slot");
        policy_failed_again_at(
            &mut manifest,
            "z-retry",
            "adjusted_source_resolve",
            "resolver failure",
            FailureKind::AdjustedSourceResolveFailed,
            "100.000000000Z",
        );
        manifest.upsert(policy_failed_record(
            "a-first",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "050.000000000Z",
        ));

        let admissions = admit_scan_retry_policies(&mut manifest, 1, 1, 300, 16, 86_400, 1_000_000)
            .expect("reserved retry should remain eligible when new first markers have no slot");

        assert_eq!(admissions.adjusted_source_required.resolver_retry_ready, 1);
        assert_eq!(admissions.adjusted_source_required.first_ready, 0);
        assert_eq!(
            manifest.get("z-retry").unwrap().proofs[ADJUSTED_SOURCE_REQUIRED_PROOF]["attempt"],
            json!(2)
        );
        assert!(
            !manifest
                .get("a-first")
                .unwrap()
                .proofs
                .contains_key(ADJUSTED_SOURCE_REQUIRED_PROOF)
        );
    }

    #[test]
    fn lifecycle_budget_reserves_only_valid_adjusted_marker_lineages_and_does_not_leak() {
        let mut ready = Manifest::new();
        ready.upsert(policy_failed_record(
            "ready",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut ready, 1, 1, 1_000)
            .expect("ready marker should be admitted");

        let mut backoff = Manifest::new();
        backoff.upsert(policy_failed_record(
            "backoff",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut backoff, 1, 1, 1_000)
            .expect("backoff marker should be admitted");
        policy_failed_again_at(
            &mut backoff,
            "backoff",
            "adjusted_source_resolve",
            "resolver failure",
            FailureKind::AdjustedSourceResolveFailed,
            "900.000000000Z",
        );

        let mut retry_ready = Manifest::new();
        retry_ready.upsert(policy_failed_record(
            "retry-ready",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut retry_ready, 1, 1, 1_000)
            .expect("retry-ready marker should be admitted");
        policy_failed_again_at(
            &mut retry_ready,
            "retry-ready",
            "adjusted_source_resolve",
            "resolver failure",
            FailureKind::AdjustedSourceResolveFailed,
            "400.000000000Z",
        );

        let mut exhausted = Manifest::new();
        exhausted.upsert(policy_failed_record(
            "exhausted",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut exhausted, 1, 1, 1_000)
            .expect("first exhausted marker should be admitted");
        for (timestamp, admitted_at) in [("400.000000000Z", 700), ("800.000000000Z", 1_100)] {
            policy_failed_again_at(
                &mut exhausted,
                "exhausted",
                "adjusted_source_resolve",
                "resolver failure",
                FailureKind::AdjustedSourceResolveFailed,
                timestamp,
            );
            admit_adjusted_source_required_assets(&mut exhausted, 1, 1, admitted_at)
                .expect("resolver retry should preserve its reservation");
        }
        policy_failed_again_at(
            &mut exhausted,
            "exhausted",
            "adjusted_source_resolve",
            "terminal resolver failure",
            FailureKind::AdjustedSourceResolveFailed,
            "1200.000000000Z",
        );

        let mut malformed = Manifest::new();
        malformed.upsert(policy_failed_record(
            "malformed",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut malformed, 1, 1, 1_000)
            .expect("malformed marker should start as a valid marker");
        let mut malformed_record = malformed.get("malformed").unwrap().clone();
        malformed_record
            .proofs
            .get_mut(ADJUSTED_SOURCE_REQUIRED_PROOF)
            .unwrap()["failure_history_digest"] = json!("forged");
        malformed.upsert(malformed_record);

        let mut manifest = Manifest::new();
        for source in [&ready, &backoff, &retry_ready, &exhausted, &malformed] {
            for record in source.records().values() {
                manifest.upsert(record.clone());
            }
        }
        let mut budget = LifecycleAdmissionBudget::for_scan(&manifest, 5);
        assert_eq!(budget.remaining_slots(), 1);
        let before = budget;
        let before_manifest = manifest.clone();

        let admission =
            admit_adjusted_source_required_assets_with_budget(&mut manifest, &mut budget, 0, 1_000)
                .expect(
                    "zero admission cap should not leak budget while classifying malformed markers",
                );

        assert_eq!(admission.malformed_or_unknown, 1);
        assert_eq!(budget, before);
        assert_eq!(manifest, before_manifest);
        assert_eq!(manifest.get("ready").unwrap().state, State::Failed);
        assert_eq!(manifest.get("backoff").unwrap().state, State::Failed);
        assert_eq!(manifest.get("retry-ready").unwrap().state, State::Failed);
        assert_eq!(manifest.get("exhausted").unwrap().state, State::Failed);
        assert_eq!(manifest.get("malformed").unwrap().state, State::Failed);
    }

    #[test]
    fn lifecycle_budget_preserves_over_capacity_debt_when_an_interrupted_retry_requeues() {
        let mut manifest = Manifest::new();
        manifest.upsert(interrupted_original_asset_resolve_retry_record(
            "interrupted",
            State::NasVerified,
            "100.000000000Z",
        ));
        manifest.upsert(lifecycle_record("still-active", State::NasVerified));
        let mut budget = LifecycleAdmissionBudget::for_scan(&manifest, 1);
        assert_eq!(budget.remaining_slots(), 0);

        let admission = recover_original_asset_resolver_retries_with_budget(
            &mut manifest,
            &mut budget,
            16,
            0,
            1_000_000,
        )
        .expect("requeue should preserve capacity debt without admitting work");

        assert_eq!(admission.interrupted_retries_requeued, 1);
        assert_eq!(admission.recovered_now, 0);
        assert_eq!(budget.remaining_slots(), 0);
        assert_eq!(manifest.get("interrupted").unwrap().state, State::Failed);
        assert_eq!(
            manifest.get("still-active").unwrap().state,
            State::NasVerified
        );
    }

    #[test]
    fn lifecycle_budget_releases_overcommit_debt_only_after_occupancy_drops_below_capacity() {
        let mut manifest = Manifest::new();
        for asset_id in ["active-a", "active-b", "active-c"] {
            manifest.upsert(lifecycle_record(asset_id, State::NasVerified));
        }
        let mut budget = LifecycleAdmissionBudget::for_scan(&manifest, 1);
        assert_eq!(budget.max_slots, 1);
        assert_eq!(budget.occupied_slots, 3);
        assert_eq!(budget.remaining_slots(), 0);

        budget.release(1);
        assert_eq!(budget.occupied_slots, 2);
        assert_eq!(budget.remaining_slots(), 0);
        budget.release(1);
        assert_eq!(budget.occupied_slots, 1);
        assert_eq!(budget.remaining_slots(), 0);
        budget.release(1);
        assert_eq!(budget.occupied_slots, 0);
        assert_eq!(budget.remaining_slots(), 1);
        assert!(budget.consume());
        assert_eq!(budget.remaining_slots(), 0);
    }

    #[test]
    fn lifecycle_budget_counts_valid_adjusted_marker_reservations_as_occupancy_debt() {
        let mut manifest = Manifest::new();
        manifest.upsert(policy_failed_record(
            "marker-reservation",
            "conversion",
            "RAW has no usable embedded preview",
            Some(FailureKind::EmbeddedPreviewUnavailable),
            "100.000000000Z",
        ));
        admit_adjusted_source_required_assets(&mut manifest, 1, 1, 1_000)
            .expect("marker should be admitted before adding active work");
        manifest.upsert(lifecycle_record("active", State::NasVerified));

        let mut budget = LifecycleAdmissionBudget::for_scan(&manifest, 1);
        assert_eq!(budget.occupied_slots, 2);
        assert_eq!(budget.remaining_slots(), 0);
        budget.release(1);
        assert_eq!(budget.occupied_slots, 1);
        assert_eq!(budget.remaining_slots(), 0);
        budget.release(1);
        assert_eq!(budget.occupied_slots, 0);
        assert_eq!(budget.remaining_slots(), 1);
        assert!(
            manifest
                .get("marker-reservation")
                .unwrap()
                .proofs
                .contains_key(ADJUSTED_SOURCE_REQUIRED_PROOF)
        );
    }

    #[test]
    fn legacy_failure_classification_is_exact_and_asset_bound() {
        let record = policy_failed_record(
            "asset",
            "conversion",
            "converted output is missing or unreadable at /output/asset.oriented-preview.jpg: No such file or directory (os error 2)",
            None,
            "100.000000000Z",
        );
        assert_eq!(
            last_failure_kind(&record),
            Some(FailureKind::ConversionOutputUnreadable)
        );
        for (stage, message) in [
            (
                "upload",
                "converted output is missing or unreadable at /output/asset.oriented-preview.jpg: No such file or directory (os error 2)",
            ),
            (
                "conversion",
                "converted output is missing or unreadable at /output/other.oriented-preview.jpg: No such file or directory (os error 2)",
            ),
            (
                "conversion",
                "converted output is missing or unreadable at /output/asset.oriented-preview.jpg: interrupted",
            ),
            (
                "conversion",
                "converted output is missing or unreadable at /output/asset.oriented-preview.jpg: Permission denied (os error 13)",
            ),
            (
                "conversion",
                "converted output is missing or unreadable at /output/asset.oriented-preview.jpg",
            ),
        ] {
            let record = policy_failed_record("asset", stage, message, None, "100.000000000Z");
            assert_eq!(last_failure_kind(&record), None);
        }
    }

    #[test]
    fn legacy_staged_preview_unavailable_is_blocked_without_admission_or_terminalization() {
        let mut manifest = Manifest::new();
        let record = policy_failed_record(
            "asset",
            "conversion",
            "RAW has neither PreviewImage nor JpgFromRaw embedded preview: /staging/asset.staged-raw.DNG",
            None,
            "100.000000000Z",
        );
        assert_eq!(
            last_failure_kind(&record),
            Some(FailureKind::EmbeddedPreviewUnavailable)
        );
        manifest.upsert(record);

        assert_eq!(
            failed_retry_queue_counts(&manifest)["blocked_missing_embedded_preview"],
            1
        );
        let admission = admit_failed_retryable_assets(&mut manifest, 16, 16, 300, 3_000_000)
            .expect("legacy missing preview should remain a blocked failure");

        assert_eq!(admission.blocked_missing_preview, 1);
        assert!(admission.admitted_by_category.is_empty());
        assert!(admission.terminalized_by_reason.is_empty());
        assert_eq!(manifest.get("asset").unwrap().state, State::Failed);
    }

    #[test]
    fn legacy_staged_preview_unavailable_requires_the_exact_staged_path_message() {
        for (stage, message) in [
            (
                "upload",
                "RAW has neither PreviewImage nor JpgFromRaw embedded preview: /staging/asset.staged-raw.DNG",
            ),
            (
                "conversion",
                "RAW has neither PreviewImage nor JpgFromRaw embedded preview: /staging/other.staged-raw.DNG",
            ),
            (
                "conversion",
                "RAW has neither PreviewImage nor JpgFromRaw embedded preview: /staging/asset.staged-raw.DNG interrupted",
            ),
            (
                "conversion",
                "RAW preview unavailable: /staging/asset.staged-raw.DNG",
            ),
        ] {
            let record = policy_failed_record("asset", stage, message, None, "100.000000000Z");
            assert_eq!(last_failure_kind(&record), None);
        }
    }

    #[test]
    fn failed_retry_admission_persists_proof_and_state_to_strict_store() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let manifest_path = tempdir.path().join("manifest.json");
        let store =
            AssetStateStore::open_writer(&manifest_path, "test-writer", Duration::from_secs(60))
                .expect("state store should open");
        let mut manifest = Manifest::new();
        let mut failed = policy_failed_record(
            "conversion-timeout",
            "conversion",
            "conversion command timed out after 120000 ms: heif-enc",
            Some(FailureKind::ConversionTimedOut),
            "100.000000000Z",
        );
        failed.updated_at = "100.000000000Z".to_string();
        manifest.upsert(failed.clone());
        store
            .persist_manifest_records(&manifest)
            .expect("failed state should persist");

        let admission = admit_failed_retryable_assets(&mut manifest, 1, 1, 300, 3_000_000)
            .expect("failed retry should admit");

        assert_eq!(
            admission.admitted_by_category["retryable_conversion_timed_out"],
            1
        );
        let recovered = manifest
            .get("conversion-timeout")
            .expect("asset should recover");
        assert_eq!(recovered.state, State::NasVerified);
        assert!(recovered.updated_at > failed.updated_at);
        store
            .persist_manifest_records(&manifest)
            .expect("recovered state should persist with a newer timestamp");
        let reloaded = store.load().expect("state store should reload");
        let reloaded_record = reloaded
            .get("conversion-timeout")
            .expect("asset should reload");
        assert_eq!(reloaded_record.state, State::NasVerified);
        assert_eq!(reloaded_record.updated_at, recovered.updated_at);
        assert_eq!(reloaded_record.proofs["failure_retry"]["attempt"], json!(1));

        let mut reloaded_for_retry = store.load().expect("state store should reload");
        policy_failed_again_at(
            &mut reloaded_for_retry,
            "conversion-timeout",
            "conversion",
            "conversion command timed out after 120000 ms: heif-enc",
            FailureKind::ConversionTimedOut,
            "101.000000000Z",
        );
        let resumed = admit_failed_retryable_assets(&mut reloaded_for_retry, 1, 1, 300, 3_000_000)
            .expect("reloaded retry proof should carry exactly one appended failure");
        assert_eq!(
            resumed.admitted_by_category["retryable_conversion_timed_out"],
            1
        );
        assert_eq!(
            reloaded_for_retry.get("conversion-timeout").unwrap().proofs[FAILURE_RETRY_PROOF]["attempt"],
            json!(2)
        );
    }

    #[test]
    fn full_lifecycle_conversion_requests_wait_for_original_asset_proof() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.full_lifecycle = true;

        let mut manifest = Manifest::new();
        let mut unproven = lifecycle_record("unproven", State::NasVerified);
        add_original_resolution_proofs(&mut unproven, 1_000);
        manifest.upsert(unproven);
        let mut proven = AssetRecord::new("proven", PathBuf::from("/raw/proven.DNG"));
        proven.state = State::NasVerified;
        proven.proofs.insert(
            "original_asset".to_string(),
            json!({
                "record_name": "CPLAsset-proven",
                "record_change_tag": "tag-proven",
                "record_type": "CPLAsset",
                "filename": "proven.DNG",
                "size_bytes": 9,
                "matched_raw_sha256": "raw-sha",
            }),
        );
        manifest.upsert(proven);

        let active_asset_ids = active_lifecycle_asset_ids(&manifest, config.max_lifecycle_per_scan);
        let requests = conversion_requests(&manifest, &config, Some(&active_asset_ids));

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].asset_id, "proven");
    }

    #[test]
    fn non_lifecycle_conversion_requests_do_not_require_original_asset_proof() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );

        let mut manifest = Manifest::new();
        let mut record = AssetRecord::new("unproven", PathBuf::from("/raw/unproven.DNG"));
        record.state = State::NasVerified;
        manifest.upsert(record);

        let requests = conversion_requests(&manifest, &config, None);

        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].asset_id, "unproven");
    }

    #[test]
    fn original_asset_resolution_batches_include_nas_verified_records() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        let mut manifest = Manifest::new();
        for (asset_id, state, has_original_proof, captured_at) in [
            ("nas-unproven", State::NasVerified, false, 1_000u64),
            ("nas-proven", State::NasVerified, true, 1_100u64),
            (
                "verified-unproven",
                State::ConversionVerified,
                false,
                1_200u64,
            ),
            ("converted", State::Converted, false, 1_300u64),
            ("failed", State::Failed, false, 1_400u64),
        ] {
            let mut record =
                AssetRecord::new(asset_id, PathBuf::from(format!("/raw/{asset_id}.DNG")));
            record.state = state;
            record.proofs.insert(
                "nas".to_string(),
                json!({
                    "canonical_path": format!("/raw/{asset_id}.DNG"),
                    "relative_path": format!("{asset_id}.DNG"),
                    "size_bytes": 9,
                    "modified_unix_seconds": captured_at,
                    "age_seconds": 2_592_000u64,
                    "sha256": "raw-sha",
                }),
            );
            record.proofs.insert(
                "source_age".to_string(),
                json!({
                    "source_captured_unix_seconds": captured_at,
                    "verified_at_unix_seconds": 10_000u64,
                    "min_age_seconds": 2_592_000u64,
                }),
            );
            if has_original_proof {
                record.proofs.insert(
                    "original_asset".to_string(),
                    json!({"record_name": "already-proven"}),
                );
            }
            manifest.upsert(record);
        }

        let batches = original_asset_resolution_target_batches(&manifest, &config, None)
            .expect("targets should batch");
        let asset_ids = batches
            .iter()
            .flat_map(|batch| batch.iter().map(|target| target.asset_id.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(
            asset_ids,
            vec!["nas-unproven", "verified-unproven", "converted"]
        );
    }

    #[test]
    fn original_asset_resolution_batches_are_sorted_and_date_local() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.max_lifecycle_per_scan = 10;
        let mut manifest = Manifest::new();
        for (asset_id, captured_at) in [
            ("late", 9_000u64),
            ("early-b", 1_200u64),
            ("middle-b", 4_800u64),
            ("early-a", 1_000u64),
            ("middle-a", 4_700u64),
        ] {
            let mut record =
                AssetRecord::new(asset_id, PathBuf::from(format!("/raw/{asset_id}.DNG")));
            record.state = State::NasVerified;
            record.proofs.insert(
                "nas".to_string(),
                json!({
                    "canonical_path": format!("/raw/{asset_id}.DNG"),
                    "relative_path": format!("{asset_id}.DNG"),
                    "size_bytes": 9,
                    "modified_unix_seconds": captured_at,
                    "age_seconds": 2_592_000u64,
                    "sha256": "raw-sha",
                }),
            );
            record.proofs.insert(
                "source_age".to_string(),
                json!({
                    "source_captured_unix_seconds": captured_at,
                    "verified_at_unix_seconds": 10_000u64,
                    "min_age_seconds": 2_592_000u64,
                }),
            );
            manifest.upsert(record);
        }

        let batches = original_asset_resolution_target_batches(&manifest, &config, None)
            .expect("targets should batch");
        let batch_asset_ids = batches
            .iter()
            .map(|batch| {
                batch
                    .iter()
                    .map(|target| target.asset_id.as_str())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        assert_eq!(
            batch_asset_ids,
            vec![
                vec!["early-a", "early-b"],
                vec!["middle-a", "middle-b"],
                vec!["late"],
            ]
        );
    }

    #[test]
    fn rolling_original_asset_resolution_can_take_one_batch_per_pass() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.max_lifecycle_per_scan = 10;
        let mut manifest = Manifest::new();
        for (asset_id, captured_at) in [
            ("early-a", 1_000u64),
            ("early-b", 1_100u64),
            ("middle", 4_700u64),
            ("late", 9_000u64),
        ] {
            let mut record =
                AssetRecord::new(asset_id, PathBuf::from(format!("/raw/{asset_id}.DNG")));
            record.state = State::NasVerified;
            record.proofs.insert(
                "nas".to_string(),
                json!({
                    "canonical_path": format!("/raw/{asset_id}.DNG"),
                    "relative_path": format!("{asset_id}.DNG"),
                    "size_bytes": 9,
                    "modified_unix_seconds": captured_at,
                    "age_seconds": 2_592_000u64,
                    "sha256": "raw-sha",
                }),
            );
            record.proofs.insert(
                "source_age".to_string(),
                json!({
                    "source_captured_unix_seconds": captured_at,
                    "verified_at_unix_seconds": 10_000u64,
                    "min_age_seconds": 2_592_000u64,
                }),
            );
            manifest.upsert(record);
        }

        let batches =
            original_asset_resolution_target_batches_to_run(&manifest, &config, None, Some(1))
                .expect("targets should batch");
        let batch_asset_ids = batches
            .iter()
            .map(|batch| {
                batch
                    .iter()
                    .map(|target| target.asset_id.as_str())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        assert_eq!(batch_asset_ids, vec![vec!["early-a", "early-b"]]);
    }

    #[test]
    fn original_asset_resolution_batches_limit_after_capture_time_sort() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.max_lifecycle_per_scan = 2;
        let mut manifest = Manifest::new();
        for (asset_id, captured_at) in [
            ("z-late", 9_000u64),
            ("a-middle", 4_700u64),
            ("m-early", 1_000u64),
        ] {
            let mut record =
                AssetRecord::new(asset_id, PathBuf::from(format!("/raw/{asset_id}.DNG")));
            record.state = State::NasVerified;
            record.proofs.insert(
                "nas".to_string(),
                json!({
                    "canonical_path": format!("/raw/{asset_id}.DNG"),
                    "relative_path": format!("{asset_id}.DNG"),
                    "size_bytes": 9,
                    "modified_unix_seconds": captured_at,
                    "age_seconds": 2_592_000u64,
                    "sha256": "raw-sha",
                }),
            );
            record.proofs.insert(
                "source_age".to_string(),
                json!({
                    "source_captured_unix_seconds": captured_at,
                    "verified_at_unix_seconds": 10_000u64,
                    "min_age_seconds": 2_592_000u64,
                }),
            );
            manifest.upsert(record);
        }

        let batches = original_asset_resolution_target_batches(&manifest, &config, None)
            .expect("targets should batch");
        let asset_ids = batches
            .iter()
            .flat_map(|batch| batch.iter().map(|target| target.asset_id.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(asset_ids, vec!["m-early", "a-middle"]);
    }

    #[test]
    fn active_lifecycle_asset_ids_prioritizes_continuation_work_before_new_resolution() {
        let mut manifest = Manifest::new();
        for (asset_id, captured_at) in [
            ("a-new-raw-1", 10_000u64),
            ("b-new-raw-2", 10_100u64),
            ("c-new-raw-3", 10_200u64),
        ] {
            let mut record = lifecycle_record(asset_id, State::NasVerified);
            add_original_resolution_proofs(&mut record, captured_at);
            manifest.upsert(record);
        }
        manifest.upsert(lifecycle_record("d-converted", State::Converted));
        let mut proven_nas = lifecycle_record("e-proven-nas", State::NasVerified);
        add_original_asset_proof(&mut proven_nas);
        manifest.upsert(proven_nas);

        assert_eq!(
            active_lifecycle_asset_ids(&manifest, 2),
            vec!["e-proven-nas", "d-converted"]
        );
    }

    #[test]
    fn active_lifecycle_asset_ids_prioritizes_larger_assets_within_same_stage() {
        let mut manifest = Manifest::new();
        for (asset_id, size_bytes) in [
            ("a-small-ready", 9u64),
            ("b-large-ready", 90u64),
            ("c-medium-ready", 40u64),
        ] {
            let mut record = lifecycle_record(asset_id, State::NasVerified);
            record.proofs.insert(
                "nas".to_string(),
                json!({
                    "canonical_path": format!("/raw/{asset_id}.DNG"),
                    "relative_path": format!("{asset_id}.DNG"),
                    "size_bytes": size_bytes,
                    "modified_unix_seconds": 10_000u64,
                    "age_seconds": 2_592_000u64,
                    "sha256": "raw-sha",
                }),
            );
            add_original_asset_proof(&mut record);
            manifest.upsert(record);
        }

        assert_eq!(
            active_lifecycle_asset_ids(&manifest, 2),
            vec!["b-large-ready", "c-medium-ready"]
        );
    }

    #[test]
    fn active_lifecycle_asset_ids_selects_dense_date_local_resolution_window() {
        let mut manifest = Manifest::new();
        for (asset_id, captured_at) in [
            ("a-sparse-early", 1_000u64),
            ("b-dense-1", 10_000u64),
            ("c-dense-2", 10_100u64),
            ("d-dense-3", 10_200u64),
            (
                "e-outside-window",
                10_000u64 + ORIGINAL_ASSET_RESOLVE_BATCH_WINDOW_SECONDS + 1,
            ),
        ] {
            let mut record = lifecycle_record(asset_id, State::NasVerified);
            add_original_resolution_proofs(&mut record, captured_at);
            manifest.upsert(record);
        }

        assert_eq!(
            active_lifecycle_asset_ids(&manifest, 4),
            vec!["b-dense-1", "c-dense-2", "d-dense-3", "a-sparse-early"]
        );
    }

    #[test]
    fn active_lifecycle_asset_ids_fills_limit_from_multiple_resolution_windows() {
        let mut manifest = Manifest::new();
        for index in 0..21 {
            manifest.upsert(lifecycle_record(
                &format!("continuation-{index:02}"),
                State::Converted,
            ));
        }
        for (window_index, window_start) in [
            10_000u64,
            10_000u64 + ORIGINAL_ASSET_RESOLVE_BATCH_WINDOW_SECONDS + 10,
            10_000u64 + (ORIGINAL_ASSET_RESOLVE_BATCH_WINDOW_SECONDS + 10) * 2,
        ]
        .into_iter()
        .enumerate()
        {
            for index in 0..30 {
                let asset_id = format!("window-{window_index}-{index:02}");
                let mut record = lifecycle_record(&asset_id, State::NasVerified);
                add_original_resolution_proofs(&mut record, window_start + index);
                manifest.upsert(record);
            }
        }

        let active_ids = active_lifecycle_asset_ids(&manifest, 100);

        assert_eq!(active_ids.len(), 100);
        assert_eq!(active_ids[0], "continuation-00");
        assert_eq!(active_ids[20], "continuation-20");
        assert_eq!(active_ids[21], "window-0-00");
        assert_eq!(active_ids[50], "window-0-29");
        assert_eq!(active_ids[51], "window-1-00");
        assert_eq!(active_ids[80], "window-1-29");
        assert_eq!(active_ids[81], "window-2-00");
        assert_eq!(active_ids[99], "window-2-18");
    }

    #[test]
    fn active_lifecycle_asset_ids_excludes_terminal_and_undiscovered_records() {
        let mut manifest = Manifest::new();
        for (asset_id, state) in [
            ("a-discovered", State::Discovered),
            ("b-failed", State::Failed),
            ("c-deleted", State::Deleted),
        ] {
            manifest.upsert(lifecycle_record(asset_id, state));
        }
        let mut raw = lifecycle_record("d-new-raw", State::NasVerified);
        add_original_resolution_proofs(&mut raw, 10_000);
        manifest.upsert(raw);

        assert_eq!(active_lifecycle_asset_ids(&manifest, 10), vec!["d-new-raw"]);
    }

    #[test]
    fn active_lifecycle_asset_ids_selects_bounded_continuation_candidates() {
        let mut manifest = Manifest::new();
        for (asset_id, state) in [
            ("a-discovered", State::Discovered),
            ("b-nas", State::NasVerified),
            ("c-converted", State::Converted),
            ("d-verified", State::ConversionVerified),
            ("e-uploaded", State::UploadVerified),
            ("f-eligible", State::DeleteEligible),
            ("g-approved", State::DeleteApproved),
            ("h-deleted", State::Deleted),
            ("i-failed", State::Failed),
        ] {
            let mut record =
                AssetRecord::new(asset_id, PathBuf::from(format!("/raw/{asset_id}.DNG")));
            record.state = state;
            manifest.upsert(record);
        }

        assert_eq!(
            active_lifecycle_asset_ids(&manifest, 4),
            vec!["g-approved", "f-eligible", "e-uploaded", "d-verified"]
        );
    }

    #[test]
    fn rolling_asset_lifecycle_stops_after_skipped_or_unproductive_stage() {
        assert!(rolling_asset_step_stops_lifecycle(
            &RollingAssetStepOutcome::skipped()
        ));
        assert!(!rolling_asset_step_stops_lifecycle(
            &RollingAssetStepOutcome::attempted(true)
        ));
        assert!(rolling_asset_step_stops_lifecycle(
            &RollingAssetStepOutcome::attempted(false)
        ));
    }

    #[test]
    fn rolling_asset_lifecycle_delta_is_scoped_and_bounded_to_one_asset() {
        let mut completed = RollingAssetLifecycleDelta::default();
        for step in [
            RollingAssetStep::ConvertHeic,
            RollingAssetStep::VerifyConvertedHeics,
            RollingAssetStep::UploadVerifiedHeics,
            RollingAssetStep::RecordLocalMirrors,
            RollingAssetStep::ConvertHeic,
        ] {
            completed.record(step, &RollingAssetStepOutcome::completed());
        }

        assert_eq!(completed.conversions_completed, 1);
        assert_eq!(completed.heics_verified, 1);
        assert_eq!(completed.uploads_completed, 1);
        assert_eq!(completed.mirrors_recorded, 1);
        assert_eq!(completed.failures, 0);

        let mut failed = RollingAssetLifecycleDelta::default();
        failed.record(
            RollingAssetStep::VerifyConvertedHeics,
            &RollingAssetStepOutcome::failed(false),
        );
        failed.record(
            RollingAssetStep::UploadVerifiedHeics,
            &RollingAssetStepOutcome::failed(false),
        );
        assert_eq!(failed.failures, 1);
        assert_eq!(failed.heics_verified, 0);
        assert_eq!(failed.uploads_completed, 0);
    }

    #[test]
    fn upload_integrity_errors_fail_record_but_put_asset_conflicts_retry() {
        assert!(upload_error_should_fail_record(&MonitorError::CommandFailed {
            program: "icloudpd-optimizer",
            message: "upload failed: HEIC size mismatch at /heic/a.heic: expected 100 bytes, got 10 bytes".to_string(),
        }));
        assert!(upload_error_should_fail_record(&MonitorError::CommandFailed {
            program: "icloudpd-optimizer",
            message: "upload failed: failed to read verified HEIC at /heic/a.heic: No such file or directory".to_string(),
        }));
        assert!(!upload_error_should_fail_record(
            &MonitorError::CommandFailed {
                program: "icloudpd-optimizer",
                message:
                    "upload failed: iCloud Photos putAsset rejected the upload with status 409"
                        .to_string(),
            }
        ));
        assert!(!upload_error_should_fail_record(
            &MonitorError::UploadWorkflowTimeout {
                asset_id: "asset".to_string(),
                timeout_seconds: 60,
            }
        ));
    }

    #[test]
    fn upload_conflict_with_a_heic_proof_is_reported_blocked_and_not_recovered() {
        let mut manifest = Manifest::new();
        let mut record = lifecycle_record("upload-conflict", State::Failed);
        record
            .proofs
            .insert("heic".to_string(), json!({"verified": true}));
        record.failures.push(crate::manifest::FailureRecord::new(
            "upload",
            "iCloud Photos putAsset rejected the upload with status 409",
        ));
        manifest.upsert(record);

        let admission = admit_failed_retryable_assets(&mut manifest, 1, 1, 300, 3_000_000)
            .expect("blocked upload conflict should not fail policy evaluation");

        assert_eq!(admission.blocked_downstream_proof, 1);
        assert_eq!(
            manifest.get("upload-conflict").unwrap().state,
            State::Failed
        );
    }

    #[test]
    fn active_lifecycle_asset_ids_prioritizes_terminal_work_before_cloudkit_resolution() {
        let mut manifest = Manifest::new();
        for (asset_id, state) in [
            ("a-needs-original-resolution", State::ConversionVerified),
            ("b-delete-approved", State::DeleteApproved),
            ("c-uploaded-needs-mirror", State::UploadVerified),
        ] {
            manifest.upsert(lifecycle_record(asset_id, state));
        }
        let mut converted = lifecycle_record("d-converted-needs-local-verify", State::Converted);
        converted.proofs.insert(
            "original_asset".to_string(),
            json!({
                "record_name": "CPLAsset-d-converted-needs-local-verify",
                "record_change_tag": "tag",
                "record_type": "CPLAsset",
                "filename": "d-converted-needs-local-verify.DNG",
                "size_bytes": 9,
                "matched_raw_sha256": "raw-sha",
            }),
        );
        manifest.upsert(converted);

        assert_eq!(
            active_lifecycle_asset_ids(&manifest, 3),
            vec![
                "b-delete-approved",
                "c-uploaded-needs-mirror",
                "d-converted-needs-local-verify",
            ]
        );
    }

    #[test]
    fn rolling_active_lifecycle_reserves_conversion_ready_assets() {
        let mut manifest = Manifest::new();
        for index in 0..20 {
            manifest.upsert(lifecycle_record(
                &format!("uploaded-needs-mirror-{index:02}"),
                State::UploadVerified,
            ));
        }
        for (index, size_bytes) in [10u64, 90, 40, 80, 30].into_iter().enumerate() {
            let asset_id = format!("convert-ready-{index}");
            let mut record = lifecycle_record(&asset_id, State::NasVerified);
            add_original_asset_proof(&mut record);
            record.proofs.insert(
                "nas".to_string(),
                json!({
                    "canonical_path": format!("/raw/{asset_id}.DNG"),
                    "relative_path": format!("{asset_id}.DNG"),
                    "size_bytes": size_bytes,
                    "modified_unix_seconds": 10_000u64,
                    "age_seconds": 2_592_000u64,
                    "sha256": "raw-sha",
                }),
            );
            manifest.upsert(record);
        }
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.rolling_lifecycle = true;
        config.max_lifecycle_per_scan = 10;
        config.rolling_convert_stage_count = Some(2);

        let active_ids = active_lifecycle_asset_ids_for_config(&config, &manifest);
        let conversion_ready = active_ids
            .iter()
            .filter(|asset_id| asset_id.starts_with("convert-ready-"))
            .cloned()
            .collect::<Vec<_>>();

        assert_eq!(active_ids.len(), 10);
        assert_eq!(
            conversion_ready,
            vec![
                "convert-ready-1",
                "convert-ready-3",
                "convert-ready-2",
                "convert-ready-4",
            ]
        );
        assert_eq!(
            active_ids
                .iter()
                .filter(|asset_id| asset_id.starts_with("uploaded-needs-mirror-"))
                .count(),
            6
        );
    }

    #[test]
    fn rolling_active_lifecycle_ids_refill_after_discovery_when_capacity_remains() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.full_lifecycle = true;
        config.rolling_lifecycle = true;
        config.max_lifecycle_per_scan = 2;

        let mut manifest = Manifest::new();
        manifest.upsert(lifecycle_record("old-converted", State::Converted));
        let mut active_asset_ids =
            active_lifecycle_asset_ids(&manifest, config.max_lifecycle_per_scan);
        assert_eq!(active_asset_ids, vec!["old-converted"]);

        let mut discovered = lifecycle_record("new-ready", State::NasVerified);
        add_original_resolution_proofs(&mut discovered, 10_000);
        manifest.upsert(discovered);

        refresh_active_lifecycle_ids_after_discovery(&config, &manifest, &mut active_asset_ids);

        assert_eq!(active_asset_ids, vec!["old-converted", "new-ready"]);
    }

    #[test]
    fn staged_active_lifecycle_ids_do_not_refill_after_discovery_when_nonempty() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.full_lifecycle = true;
        config.max_lifecycle_per_scan = 2;

        let mut manifest = Manifest::new();
        manifest.upsert(lifecycle_record("old-converted", State::Converted));
        let mut active_asset_ids =
            active_lifecycle_asset_ids(&manifest, config.max_lifecycle_per_scan);

        let mut discovered = lifecycle_record("new-ready", State::NasVerified);
        add_original_resolution_proofs(&mut discovered, 10_000);
        manifest.upsert(discovered);

        refresh_active_lifecycle_ids_after_discovery(&config, &manifest, &mut active_asset_ids);

        assert_eq!(active_asset_ids, vec!["old-converted"]);
    }

    #[test]
    fn full_lifecycle_conversion_requests_are_restricted_to_active_set() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.full_lifecycle = true;
        config.max_lifecycle_per_scan = 2;

        let mut manifest = Manifest::new();
        for (asset_id, state, has_original_proof) in [
            ("a-ready", State::NasVerified, true),
            ("b-other-stage", State::Converted, false),
            ("c-ready-outside-window", State::NasVerified, false),
        ] {
            let mut record =
                AssetRecord::new(asset_id, PathBuf::from(format!("/raw/{asset_id}.DNG")));
            record.state = state;
            if has_original_proof {
                record.proofs.insert(
                    "original_asset".to_string(),
                    json!({
                        "record_name": format!("CPLAsset-{asset_id}"),
                        "record_change_tag": "tag",
                        "record_type": "CPLAsset",
                        "filename": format!("{asset_id}.DNG"),
                        "size_bytes": 9,
                        "matched_raw_sha256": "raw-sha",
                    }),
                );
            }
            manifest.upsert(record);
        }

        let active_asset_ids = active_lifecycle_asset_ids(&manifest, config.max_lifecycle_per_scan);
        let requests = conversion_requests(&manifest, &config, Some(&active_asset_ids));

        assert_eq!(active_asset_ids, vec!["a-ready", "b-other-stage"]);
        assert_eq!(
            requests
                .iter()
                .map(|request| request.asset_id.as_str())
                .collect::<Vec<_>>(),
            vec!["a-ready"]
        );
    }

    #[test]
    fn full_lifecycle_original_resolution_is_restricted_to_active_set() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.full_lifecycle = true;
        config.max_lifecycle_per_scan = 2;
        let mut manifest = Manifest::new();
        for asset_id in ["a-nas", "b-converted", "c-nas-outside-window"] {
            let mut record =
                AssetRecord::new(asset_id, PathBuf::from(format!("/raw/{asset_id}.DNG")));
            record.state = if asset_id == "b-converted" {
                State::Converted
            } else {
                State::NasVerified
            };
            record.proofs.insert(
                "nas".to_string(),
                json!({
                    "canonical_path": format!("/raw/{asset_id}.DNG"),
                    "relative_path": format!("{asset_id}.DNG"),
                    "size_bytes": 9,
                    "modified_unix_seconds": 1_000u64,
                    "age_seconds": 2_592_000u64,
                    "sha256": "raw-sha",
                }),
            );
            record.proofs.insert(
                "source_age".to_string(),
                json!({
                    "source_captured_unix_seconds": 1_000u64,
                    "verified_at_unix_seconds": 10_000u64,
                    "min_age_seconds": 2_592_000u64,
                }),
            );
            manifest.upsert(record);
        }

        let active_asset_ids = active_lifecycle_asset_ids(&manifest, config.max_lifecycle_per_scan);
        let batches =
            original_asset_resolution_target_batches(&manifest, &config, Some(&active_asset_ids))
                .expect("targets should batch");
        let asset_ids = batches
            .iter()
            .flat_map(|batch| batch.iter().map(|target| target.asset_id.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(active_asset_ids, vec!["b-converted", "a-nas"]);
        assert_eq!(asset_ids, vec!["a-nas", "b-converted"]);
    }

    #[test]
    fn pending_lifecycle_count_includes_nas_verified_work() {
        let mut manifest = Manifest::new();
        for (asset_id, state) in [
            ("discovered", State::Discovered),
            ("nas", State::NasVerified),
            ("converted", State::Converted),
            ("verified", State::ConversionVerified),
            ("uploaded", State::UploadVerified),
            ("eligible", State::DeleteEligible),
            ("approved", State::DeleteApproved),
            ("deleted", State::Deleted),
            ("failed", State::Failed),
        ] {
            let mut record =
                AssetRecord::new(asset_id, PathBuf::from(format!("/raw/{asset_id}.DNG")));
            record.state = state;
            manifest.upsert(record);
        }

        assert_eq!(pending_lifecycle_count(&manifest), 6);
    }

    #[test]
    fn staged_scan_start_lifecycle_work_suppresses_new_monitor_work_for_entire_scan() {
        let mut record = AssetRecord::new("asset", PathBuf::from("/raw/asset.DNG"));
        record.state = State::NasVerified;
        let mut manifest = Manifest::new();
        manifest.upsert(record);

        let had_lifecycle_pending_at_start = pending_lifecycle_count(&manifest) > 0;
        manifest
            .record_failure("asset", "original_asset_resolve", "no matching candidate")
            .expect("failure should be recorded");

        assert_eq!(pending_lifecycle_count(&manifest), 0);
        assert_eq!(
            new_monitor_work_skip_reason(had_lifecycle_pending_at_start, false, 0, 100),
            Some("lifecycle_pending_at_scan_start")
        );
    }

    #[test]
    fn rolling_scan_start_lifecycle_work_skips_new_monitor_work_only_when_active_queue_is_full() {
        let mut record = AssetRecord::new("asset", PathBuf::from("/raw/asset.DNG"));
        record.state = State::NasVerified;
        let mut manifest = Manifest::new();
        manifest.upsert(record);

        let had_lifecycle_pending_at_start = pending_lifecycle_count(&manifest) > 0;
        manifest
            .record_failure("asset", "original_asset_resolve", "no matching candidate")
            .expect("failure should be recorded");

        assert_eq!(pending_lifecycle_count(&manifest), 0);
        assert_eq!(
            new_monitor_work_skip_reason(had_lifecycle_pending_at_start, true, 99, 100),
            None
        );
        assert_eq!(
            new_monitor_work_skip_reason(had_lifecycle_pending_at_start, true, 100, 100),
            Some("rolling_lifecycle_active_queue_full")
        );
    }

    #[test]
    fn visual_content_threshold_accepts_low_contrast_verified_heics() {
        assert!(heic_has_visual_content(0.00461285));
        assert!(!heic_has_visual_content(0.0));
    }

    #[test]
    fn native_preview_metrics_accept_identical_non_blank_images() {
        let preview = RgbPreview {
            width: 2,
            height: 1,
            pixels: vec![0, 0, 0, 255, 255, 255],
        };

        assert_eq!(
            normalized_rgb_error_metrics(&preview, &preview)
                .expect("same dimensions should compare"),
            VisualErrorMetrics {
                rmse: 0.0,
                mae: 0.0,
            }
        );
        assert!(heic_has_visual_content(rgb_standard_deviation(
            &preview.pixels
        )));
    }

    #[test]
    fn visual_match_threshold_accepts_measured_heic_compression_band() {
        let measured_false_failure = VisualErrorMetrics {
            rmse: 0.026_874_4,
            mae: 0.018_730_2,
        };

        assert!(visual_match_is_within_bounds(measured_false_failure));
        assert!(!visual_match_is_within_bounds(VisualErrorMetrics {
            rmse: MONITOR_VISUAL_RMSE_MAX + 0.000_1,
            mae: 0.0,
        }));
        assert!(!visual_match_is_within_bounds(VisualErrorMetrics {
            rmse: 0.0,
            mae: MONITOR_VISUAL_MAE_MAX + 0.000_1,
        }));
        assert_eq!(normalized_metric_ppm(0.026_874_4), 26_874);
    }

    #[cfg(unix)]
    #[test]
    fn native_visual_verification_direct_pass_skips_codec_normalization() {
        let candidate = RgbPreview {
            width: 2,
            height: 1,
            pixels: vec![0, 0, 0, 255, 255, 255],
        };
        let fake =
            FakeNativeVisualVerifier::new(candidate.clone(), candidate.clone(), candidate, false);

        let metrics = visual_metrics_for_conversion_with_sips(
            &fake.reference,
            &fake.candidate,
            FAKE_NATIVE_VISUAL_VERIFIER_TIMEOUT_SECONDS,
            &fake.program,
        )
        .expect("directly matching previews should verify");

        assert_eq!(metrics.match_basis, VisualMatchBasis::Direct);
        assert!(
            metrics
                .reference_error
                .is_some_and(visual_match_is_within_bounds)
        );
        assert!(
            metrics
                .direct_reference_error
                .is_some_and(visual_match_is_within_bounds)
        );
        let commands = fake.command_log();
        assert_eq!(commands.len(), 2);
        assert!(!commands.iter().any(|command| command == "encode"));
    }

    #[cfg(unix)]
    #[test]
    fn native_visual_verification_blank_candidate_skips_codec_normalization() {
        let blank = RgbPreview {
            width: 2,
            height: 1,
            pixels: vec![0, 0, 0, 0, 0, 0],
        };
        let fake = FakeNativeVisualVerifier::new(
            RgbPreview {
                width: 2,
                height: 1,
                pixels: vec![255, 255, 255, 255, 255, 255],
            },
            blank.clone(),
            blank,
            false,
        );

        let metrics = visual_metrics_for_conversion_with_sips(
            &fake.reference,
            &fake.candidate,
            FAKE_NATIVE_VISUAL_VERIFIER_TIMEOUT_SECONDS,
            &fake.program,
        )
        .expect("blank candidate should remain a verification result");

        assert_eq!(metrics.match_basis, VisualMatchBasis::Direct);
        assert!(!heic_has_visual_content(metrics.candidate_stdev));
        assert!(
            metrics
                .reference_error
                .is_some_and(|error| !visual_match_is_within_bounds(error))
        );
        assert!(!fake.command_log().iter().any(|command| command == "encode"));
    }

    #[cfg(unix)]
    #[test]
    fn native_visual_verification_uses_codec_normalized_metrics_after_direct_failure() {
        let candidate = RgbPreview {
            width: 2,
            height: 1,
            pixels: vec![0, 0, 0, 255, 255, 255],
        };
        let fake = FakeNativeVisualVerifier::new(
            RgbPreview {
                width: 2,
                height: 1,
                pixels: vec![0, 0, 0, 0, 0, 0],
            },
            candidate.clone(),
            candidate,
            false,
        );
        let baseline = codec_normalized_reference_path(&fake.candidate);
        let temporary_paths = [
            verification_preview_path(&fake.candidate, "heic"),
            verification_preview_path(&fake.candidate, "raw"),
            baseline.clone(),
            verification_preview_path(&baseline, "heic"),
            verification_preview_path(&fake.candidate, "codec-normalized-candidate"),
        ];

        let metrics = visual_metrics_for_conversion_with_sips(
            &fake.reference,
            &fake.candidate,
            FAKE_NATIVE_VISUAL_VERIFIER_TIMEOUT_SECONDS,
            &fake.program,
        )
        .expect("codec-normalized preview should verify");

        assert_eq!(metrics.match_basis, VisualMatchBasis::CodecNormalized);
        assert!(
            metrics
                .direct_reference_error
                .is_some_and(|error| !visual_match_is_within_bounds(error))
        );
        assert!(
            metrics
                .reference_error
                .is_some_and(visual_match_is_within_bounds)
        );
        let commands = fake.command_log();
        assert_eq!(commands.len(), 5);
        assert!(commands.iter().any(|command| command == "encode"));
        assert!(
            commands
                .iter()
                .any(|command| command == "normalized_reference")
        );
        assert!(temporary_paths.iter().all(|path| !path.exists()));
    }

    #[cfg(unix)]
    #[test]
    fn native_visual_verification_rejects_failed_codec_normalized_metrics() {
        let candidate = RgbPreview {
            width: 2,
            height: 1,
            pixels: vec![0, 0, 0, 255, 255, 255],
        };
        let fake = FakeNativeVisualVerifier::new(
            RgbPreview {
                width: 2,
                height: 1,
                pixels: vec![0, 0, 0, 0, 0, 0],
            },
            candidate,
            RgbPreview {
                width: 2,
                height: 1,
                pixels: vec![0, 0, 0, 0, 0, 0],
            },
            false,
        );

        let metrics = visual_metrics_for_conversion_with_sips(
            &fake.reference,
            &fake.candidate,
            FAKE_NATIVE_VISUAL_VERIFIER_TIMEOUT_SECONDS,
            &fake.program,
        )
        .expect("failed normalized metrics should remain a verification result");

        assert_eq!(metrics.match_basis, VisualMatchBasis::CodecNormalized);
        assert!(
            metrics
                .reference_error
                .is_some_and(|error| !visual_match_is_within_bounds(error))
        );
    }

    #[cfg(unix)]
    #[test]
    fn native_visual_verification_cleans_up_and_fails_closed_when_normalized_render_fails() {
        let candidate = RgbPreview {
            width: 2,
            height: 1,
            pixels: vec![0, 0, 0, 255, 255, 255],
        };
        let fake = FakeNativeVisualVerifier::new(
            RgbPreview {
                width: 2,
                height: 1,
                pixels: vec![0, 0, 0, 0, 0, 0],
            },
            candidate.clone(),
            candidate,
            true,
        );
        let baseline = codec_normalized_reference_path(&fake.candidate);
        let temporary_paths = [
            verification_preview_path(&fake.candidate, "heic"),
            verification_preview_path(&fake.candidate, "raw"),
            baseline.clone(),
            verification_preview_path(&baseline, "heic"),
            verification_preview_path(&fake.candidate, "codec-normalized-candidate"),
        ];

        let error = visual_metrics_for_conversion_with_sips(
            &fake.reference,
            &fake.candidate,
            FAKE_NATIVE_VISUAL_VERIFIER_TIMEOUT_SECONDS,
            &fake.program,
        )
        .expect_err("normalized preview render failure must fail verification");

        assert!(matches!(
            error,
            MonitorError::CommandFailed {
                program: "sips",
                ..
            }
        ));
        assert!(temporary_paths.iter().all(|path| !path.exists()));
    }

    #[cfg(unix)]
    #[test]
    fn native_visual_verification_cleans_up_partial_baseline_when_encode_fails() {
        let candidate = RgbPreview {
            width: 2,
            height: 1,
            pixels: vec![0, 0, 0, 255, 255, 255],
        };
        let fake = FakeNativeVisualVerifier::with_baseline_encode_failure(
            RgbPreview {
                width: 2,
                height: 1,
                pixels: vec![0, 0, 0, 0, 0, 0],
            },
            candidate.clone(),
            candidate,
        );
        let baseline = codec_normalized_reference_path(&fake.candidate);
        let temporary_paths = [
            verification_preview_path(&fake.candidate, "heic"),
            verification_preview_path(&fake.candidate, "raw"),
            baseline.clone(),
            verification_preview_path(&baseline, "heic"),
            verification_preview_path(&fake.candidate, "codec-normalized-candidate"),
        ];

        let error = visual_metrics_for_conversion_with_sips(
            &fake.reference,
            &fake.candidate,
            FAKE_NATIVE_VISUAL_VERIFIER_TIMEOUT_SECONDS,
            &fake.program,
        )
        .expect_err("partial baseline encode failure must fail verification");

        assert!(matches!(
            error,
            MonitorError::CommandFailed {
                program: "sips",
                message,
            } if message.contains("68")
        ));
        let commands = fake.command_log();
        assert!(
            commands
                .iter()
                .any(|command| command == "encode_partial_failure")
        );
        assert!(
            commands
                .iter()
                .any(|command| command == "partial_baseline_written")
        );
        assert!(
            !commands
                .iter()
                .any(|command| command == "normalized_reference")
        );
        assert!(temporary_paths.iter().all(|path| !path.exists()));
    }

    #[test]
    fn visual_verification_event_fields_include_basis_and_direct_effective_metrics() {
        let mut fields = json!({"asset_id": "asset-1"});

        append_visual_verification_event_fields(
            &mut fields,
            VisualMetrics {
                candidate_stdev: 0.25,
                reference_error: Some(VisualErrorMetrics {
                    rmse: 0.0024,
                    mae: 0.0012,
                }),
                direct_reference_error: Some(VisualErrorMetrics {
                    rmse: 0.045,
                    mae: 0.024,
                }),
                match_basis: VisualMatchBasis::CodecNormalized,
            },
        );

        assert_eq!(fields["asset_id"], json!("asset-1"));
        assert_eq!(fields["visual_match_basis"], json!("codec_normalized"));
        assert_eq!(fields["visual_rmse_ppm"], json!(2_400));
        assert_eq!(fields["visual_mae_ppm"], json!(1_200));
        assert_eq!(fields["direct_visual_rmse_ppm"], json!(45_000));
        assert_eq!(fields["direct_visual_mae_ppm"], json!(24_000));
    }

    #[test]
    fn rolling_stage_permits_consume_one_cpu_slot_per_cpu_stage() {
        let permits = Arc::new(RollingStagePermits::new(4, 2, 4));
        let _first = permits
            .acquire(RollingAssetStep::VerifyConvertedHeics)
            .expect("permit acquire should succeed")
            .expect("verify should hold a CPU permit");
        let _second = permits
            .acquire(RollingAssetStep::ConvertHeic)
            .expect("permit acquire should succeed")
            .expect("convert should hold CPU and convert permits");

        let state = permits
            .state
            .lock()
            .expect("permit state should not be poisoned");

        assert_eq!(state.available_cpu_stage_slots, 2);
        assert_eq!(state.available_convert_stage_slots, 1);
        assert_eq!(state.waiting_cpu_only_slots, 0);
    }

    #[test]
    fn rolling_stage_permits_prioritize_quality_waiters_over_new_conversions() {
        let state = RollingStagePermitState {
            available_cpu_stage_slots: 1,
            available_convert_stage_slots: 1,
            available_mirror_stage_slots: 1,
            waiting_cpu_only_slots: 1,
        };

        assert!(
            state.should_wait_for(true),
            "new conversions should wait when quality checks are queued for CPU"
        );
        assert!(
            !state.should_wait_for(false),
            "quality checks should be allowed to claim the available CPU slot"
        );
    }

    #[test]
    fn native_preview_metrics_reject_blank_images_as_no_visual_content() {
        let blank = RgbPreview {
            width: 2,
            height: 1,
            pixels: vec![255, 255, 255, 255, 255, 255],
        };

        assert!(!heic_has_visual_content(rgb_standard_deviation(
            &blank.pixels
        )));
    }

    #[test]
    fn native_preview_metrics_fail_closed_on_dimension_mismatch() {
        let reference = RgbPreview {
            width: 2,
            height: 1,
            pixels: vec![0, 0, 0, 255, 255, 255],
        };
        let candidate = RgbPreview {
            width: 1,
            height: 2,
            pixels: vec![0, 0, 0, 255, 255, 255],
        };

        let error = normalized_rgb_error_metrics(&reference, &candidate)
            .expect_err("dimension mismatch should fail closed");

        assert!(matches!(
            error,
            MonitorError::PreviewDimensionMismatch {
                reference_width: 2,
                reference_height: 1,
                candidate_width: 1,
                candidate_height: 2,
            }
        ));
    }

    #[test]
    fn native_preview_pair_render_panics_fail_closed() {
        let handle = thread::spawn(|| -> Result<(), MonitorError> {
            panic!("simulated render panic");
        });

        let error = join_visual_preview_render(handle)
            .expect_err("preview worker panic should fail verification");

        assert!(matches!(
            error,
            MonitorError::CommandFailed {
                program: "sips",
                ..
            }
        ));
    }

    #[test]
    fn rejected_heic_verification_records_failure_without_aborting() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut record = upload_verified_delete_ready_record("asset", tempdir.path());
        record.state = State::Converted;
        record.proofs.remove("heic");

        let mut manifest = Manifest::new();
        manifest.upsert(record);
        let mut summary = MonitorScanSummary::default();
        let proof = HeicVerificationProof {
            heic_path: PathBuf::from("/heic/asset.HEIC"),
            heic_sha256: "heic-sha-asset".to_string(),
            size_bytes: 10,
            heif_info_ok: true,
            metadata_copied: true,
            visual_content_ok: false,
            visual_match_ok: true,
            visual_rmse_ppm: Some(0),
            visual_mae_ppm: Some(0),
        };

        let error =
            record_heic_verification_or_failure(&mut manifest, &mut summary, "asset", proof)
                .expect_err("rejected HEIC proof should be recorded as a per-asset failure");

        assert!(error.contains("visual_content_ok"));
        assert_eq!(summary.heics_verified, 0);
        assert_eq!(summary.failures, 1);
        assert!(
            summary
                .last_error
                .as_deref()
                .expect("failure should be captured")
                .contains("visual_content_ok")
        );
        let record = manifest.get("asset").expect("asset should remain present");
        assert_eq!(record.state, State::Failed);
        assert!(!record.proofs.contains_key("heic"));
        assert_eq!(record.failures[0].stage, "heic_verify");
        assert!(record.failures[0].message.contains("visual_content_ok"));
        assert_eq!(
            record.failures[0].kind,
            Some(FailureKind::HeicVisualContent)
        );
    }

    #[cfg(unix)]
    #[test]
    fn monitor_run_guard_rejects_second_owner_for_same_manifest() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("state/manifest.json"),
            tempdir.path().join("heic"),
        );

        let first = acquire_monitor_run_guard(&config).expect("first owner should lock");
        let error =
            acquire_monitor_run_guard(&config).expect_err("second owner should fail closed");

        assert!(matches!(
            error,
            MonitorError::MonitorAlreadyRunning { lock_path }
                if lock_path == monitor_run_lock_path(&config)
        ));
        drop(first);

        acquire_monitor_run_guard(&config).expect("lock should release when owner drops");
    }

    #[cfg(unix)]
    #[test]
    fn monitor_run_guard_drop_releases_state_writer_lease() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("state/manifest.json"),
            tempdir.path().join("heic"),
        );

        {
            let mut guard = acquire_monitor_run_guard(&config).expect("first guard should lock");
            guard
                .state_store(&config.manifest_path)
                .expect("guard should own state writer");
        }

        AssetStateStore::open_writer(&config.manifest_path, "writer-b", Duration::from_secs(1))
            .expect("dropping the guard should release the sqlite writer lease");
    }

    #[cfg(unix)]
    #[test]
    fn monitor_guard_revalidates_its_lock_before_opening_a_state_writer() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("state/manifest.json"),
            tempdir.path().join("heic"),
        );
        let mut guard = acquire_monitor_run_guard(&config).expect("monitor guard should lock");
        let lock_path = monitor_run_lock_path(&config);
        let moved_lock_path = tempdir.path().join("moved-monitor.lock");
        fs::rename(&lock_path, &moved_lock_path).expect("move held lock path");
        fs::write(&lock_path, b"replacement monitor lock\n").expect("replace lock path");

        let error = guard
            .state_store(&config.manifest_path)
            .expect_err("replaced lock must block state-writer creation");
        assert!(matches!(error, MonitorError::MonitorLockIo { path, .. } if path == lock_path));
        assert!(!AssetStateStore::db_path_for_manifest(&config.manifest_path).exists());
    }

    #[cfg(unix)]
    #[test]
    fn monitor_guard_heartbeat_keeps_short_lease_live_and_surfaces_fencing() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("state/manifest.json"),
            tempdir.path().join("heic"),
        );
        let mut guard = acquire_monitor_run_guard(&config).expect("monitor guard should lock");
        let state_store = guard
            .state_store(&config.manifest_path)
            .expect("guard should own state writer")
            .clone();

        thread::sleep(MONITOR_STATE_LEASE_TTL.saturating_mul(3));
        assert!(matches!(
            AssetStateStore::open_writer(&config.manifest_path, "writer-b", Duration::from_secs(1)),
            Err(AssetStateStoreError::WriterLeaseHeld { .. })
        ));

        state_store
            .release_writer_lease()
            .expect("force heartbeat fencing for regression coverage");
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match state_store.load() {
                Err(AssetStateStoreError::WriterLeaseHeartbeatLost { .. }) => break,
                Ok(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                Ok(_) => panic!("a fenced heartbeat must be reported instead of continuing"),
                Err(error) => panic!("heartbeat must surface its fencing error: {error}"),
            }
        }
        assert!(matches!(
            guard.state_store(&config.manifest_path),
            Err(MonitorError::StateStore(
                AssetStateStoreError::WriterLeaseHeartbeatLost { .. },
            ))
        ));

        drop(guard);
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match AssetStateStore::open_writer(
                &config.manifest_path,
                "writer-c",
                Duration::from_secs(1),
            ) {
                Ok(writer) => {
                    writer
                        .release_writer_lease()
                        .expect("replacement writer should release its lease");
                    break;
                }
                Err(AssetStateStoreError::WriterLeaseHeld { .. }) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("heartbeat shutdown must allow bounded takeover: {error}"),
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn run_monitor_once_preflight_failure_does_not_create_state_db() {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let download_root = tempdir.path().join("download");
        fs::create_dir_all(&download_root).expect("download root should be created");
        fs::set_permissions(&download_root, fs::Permissions::from_mode(0o000))
            .expect("permissions should be restricted");
        let config = MonitorConfig::new(
            download_root.clone(),
            tempdir.path().join("state/manifest.json"),
            tempdir.path().join("heic"),
        );
        let mut guard = acquire_monitor_run_guard(&config).expect("monitor guard should lock");

        let result = run_monitor_once(&config, &mut guard);

        fs::set_permissions(&download_root, fs::Permissions::from_mode(0o700))
            .expect("permissions should be restored");
        assert!(matches!(
            result,
            Err(MonitorError::DownloadRootAccess { .. })
        ));
        assert!(
            !AssetStateStore::db_path_for_manifest(&config.manifest_path).exists(),
            "preflight failure should not create or mutate the durable state database"
        );
    }

    #[cfg(unix)]
    #[test]
    fn scan_root_access_check_rejects_unreadable_directory() {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let path = tempdir.path();
        fs::set_permissions(path, fs::Permissions::from_mode(0o000))
            .expect("permissions should be restricted");

        let result = ensure_scan_root_access(path, default_scan_root_preflight_timeout_seconds());

        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("permissions should be restored");
        assert!(matches!(
            result,
            Err(MonitorError::DownloadRootAccess { .. })
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_scan_root_preflight_timeout_fails_closed_in_process() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");

        let result = ensure_macos_scan_root_enumerable_with_probe(tempdir.path(), 1, |_path| {
            std::thread::sleep(std::time::Duration::from_secs(2));
            Ok(())
        });

        assert!(matches!(
            result,
            Err(MonitorError::DownloadRootPreflight { message, .. })
                if message.contains("timed out after 1 seconds")
        ));
    }
}

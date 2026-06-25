use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(target_os = "macos")]
use std::sync::mpsc;
#[cfg(target_os = "macos")]
use std::thread;
#[cfg(target_os = "macos")]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::conversion_execution::{
    ConversionExecutionError, ConversionExecutionRequest, execute_measured_conversions,
};
use crate::local_mirror::{
    IcloudpdLocalMirrorRequest, LocalMirrorError, ensure_icloudpd_local_mirror,
};
use crate::manifest::{AssetRecord, Manifest, ManifestError, State};
use crate::proof::{MIN_RAW_AGE_DAYS, NasRawProof, ProofError};
use crate::upload::{
    CloudKitDeleteClient, CloudKitOriginalAssetBatchResolveOutcome,
    CloudKitOriginalAssetBatchResolveRequest, CloudKitOriginalAssetResolveTarget,
    ReqwestCloudKitDeleteTransport, UploadError, build_upload_proof, load_cloudkit_delete_session,
    run_icloud_upload, verify_local_heic,
};
use crate::workflow::{
    ConversionResultProof, HeicVerificationProof, SourceAgeProof, WorkflowError, approve_delete,
    approved_original_delete_request, icloudpd_local_mirror_ready_proofs, mark_delete_eligible,
    prove_and_record_nas, record_delete_execution, record_heic_verification,
    record_icloudpd_local_mirror_proof, record_original_asset_batch_proofs,
    record_source_age_proof, record_stage_failure, record_upload_proof, upload_ready_heic_proof,
};

const MONITOR_CONFIG_SCHEMA_VERSION: u64 = 1;
const MONITOR_STATS_SCHEMA_VERSION: u64 = 1;
const DEFAULT_CAPTURE_TOLERANCE_SECONDS: u64 = 2;
const DEFAULT_CLOUDKIT_PAGE_SIZE: u64 = 200;
const DEFAULT_CLOUDKIT_MAX_PAGES: u64 = 2000;
const DEFAULT_SCAN_ROOT_PREFLIGHT_TIMEOUT_SECONDS: u64 = 30;
const ORIGINAL_ASSET_RESOLVE_BATCH_WINDOW_SECONDS: u64 = 60 * 60;
const MONITOR_VISUAL_RMSE_MAX: f64 = 0.02;
const MONITOR_HEIC_STDEV_MIN: f64 = 0.005;
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
    pub heic_quality: u8,
    pub max_conversions_per_scan: usize,
    #[serde(default = "default_scan_recursive")]
    pub scan_recursive: bool,
    pub conversion_tool_version: Option<String>,
    #[serde(default)]
    pub full_lifecycle: bool,
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
            heic_quality: 90,
            max_conversions_per_scan: 25,
            scan_recursive: true,
            conversion_tool_version: None,
            full_lifecycle: false,
            auto_delete: false,
            upload_session_path: None,
            delete_session_path: None,
            mirror_root: None,
            delete_operator: default_delete_operator(),
            max_lifecycle_per_scan: default_max_lifecycle_per_scan(),
            capture_tolerance_seconds: default_capture_tolerance_seconds(),
            cloudkit_start_rank: 0,
            cloudkit_page_size: default_cloudkit_page_size(),
            cloudkit_max_pages: default_cloudkit_max_pages(),
            scan_root_preflight_timeout_seconds: default_scan_root_preflight_timeout_seconds(),
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
}

pub fn run_monitor_once(config: &MonitorConfig) -> Result<MonitorScanSummary, MonitorError> {
    config.validate()?;
    fs::create_dir_all(&config.heic_output_dir).map_err(|source| MonitorError::CreateDir {
        path: config.heic_output_dir.clone(),
        source,
    })?;

    let started = current_unix_seconds();
    let mut stats = MonitorStats::load(&config.stats_path)?;
    stats.scans_started = stats.scans_started.saturating_add(1);
    stats.last_scan_started_unix_seconds = Some(started);

    let mut manifest = load_manifest_for_monitor(&config.manifest_path)?;
    let mut summary = MonitorScanSummary {
        started_unix_seconds: started,
        ..MonitorScanSummary::default()
    };
    let mut active_lifecycle_ids = if config.full_lifecycle {
        active_lifecycle_asset_ids(&manifest, config.max_lifecycle_per_scan)
    } else {
        Vec::new()
    };
    let had_lifecycle_pending_at_start = config.full_lifecycle && !active_lifecycle_ids.is_empty();
    log_monitor_event(
        "scan_started",
        started,
        json!({
            "full_lifecycle": config.full_lifecycle,
            "active_lifecycle": active_lifecycle_ids.len(),
            "had_lifecycle_pending_at_start": had_lifecycle_pending_at_start,
            "max_conversions_per_scan": config.max_conversions_per_scan,
            "max_lifecycle_per_scan": config.max_lifecycle_per_scan,
            "scan_recursive": config.scan_recursive,
        }),
    );

    if config.full_lifecycle {
        log_monitor_event(
            "lifecycle_started",
            started,
            json!({
                "pending_lifecycle": pending_lifecycle_count(&manifest),
                "position": "before_discovery",
            }),
        );
        run_lifecycle_stages(config, &mut manifest, &mut summary, &active_lifecycle_ids)?;
    }

    if !should_skip_new_monitor_work(had_lifecycle_pending_at_start) {
        let download_root = fs::canonicalize(&config.download_root).map_err(|source| {
            MonitorError::CanonicalizeRoot {
                path: config.download_root.clone(),
                source,
            }
        })?;
        ensure_scan_root_access(&download_root, config.scan_root_preflight_timeout_seconds)?;
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
                    | Some(State::Failed) => {
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

        manifest
            .save_atomic(&config.manifest_path)
            .map_err(MonitorError::Manifest)?;
    } else {
        log_monitor_event(
            "new_work_skipped",
            started,
            json!({
                "reason": "lifecycle_pending_at_scan_start",
                "pending_lifecycle_after_lifecycle": pending_lifecycle_count(&manifest),
            }),
        );
    }

    if config.full_lifecycle && active_lifecycle_ids.is_empty() {
        active_lifecycle_ids = active_lifecycle_asset_ids(&manifest, config.max_lifecycle_per_scan);
    }

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
        resolve_original_assets(config, &mut manifest, &mut summary, &active_lifecycle_ids)?;
        manifest
            .save_atomic(&config.manifest_path)
            .map_err(MonitorError::Manifest)?;
    }

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
        match execute_measured_conversions(&manifest, requests, config.jobs) {
            Ok(updated) => {
                summary.conversions_completed = summary.conversions_attempted;
                manifest = updated;
                manifest
                    .save_atomic(&config.manifest_path)
                    .map_err(MonitorError::Manifest)?;
            }
            Err(error) => {
                summary.failures = summary.failures.saturating_add(1);
                summary.last_error = Some(error.to_string());
            }
        }
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
        run_lifecycle_stages(config, &mut manifest, &mut summary, &active_lifecycle_ids)?;
    }

    manifest
        .save_atomic(&config.manifest_path)
        .map_err(MonitorError::Manifest)?;

    summary.finished_unix_seconds = current_unix_seconds();
    summary.state_counts = state_counts(&manifest);
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
    manifest
        .records()
        .values()
        .filter(|record| record.state == State::NasVerified)
        .filter(|record| active_lifecycle_allows(active_lifecycle_asset_ids, &record.asset_id))
        .filter(|record| !config.full_lifecycle || record.proofs.contains_key("original_asset"))
        .take(config.max_conversions_per_scan)
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

fn run_lifecycle_stages(
    config: &MonitorConfig,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    active_lifecycle_asset_ids: &[String],
) -> Result<(), MonitorError> {
    verify_converted_heics(config, manifest, summary, active_lifecycle_asset_ids)?;
    resolve_original_assets(config, manifest, summary, active_lifecycle_asset_ids)?;
    upload_verified_heics(config, manifest, summary, active_lifecycle_asset_ids)?;
    record_local_mirrors(config, manifest, summary, active_lifecycle_asset_ids)?;
    if config.auto_delete {
        delete_original_assets(config, manifest, summary, active_lifecycle_asset_ids)?;
    }
    Ok(())
}

fn verify_converted_heics(
    config: &MonitorConfig,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    active_lifecycle_asset_ids: &[String],
) -> Result<(), MonitorError> {
    let asset_ids = asset_ids_matching(manifest, config.max_lifecycle_per_scan, |record| {
        active_lifecycle_allows(Some(active_lifecycle_asset_ids), &record.asset_id)
            && record.state == State::Converted
            && !record.proofs.contains_key("heic")
    });
    for asset_id in asset_ids {
        match verify_converted_heic(manifest, &asset_id) {
            Ok(proof) => {
                record_heic_verification(manifest, &asset_id, proof)?;
                manifest
                    .save_atomic(&config.manifest_path)
                    .map_err(MonitorError::Manifest)?;
                summary.heics_verified = summary.heics_verified.saturating_add(1);
            }
            Err(error) => record_monitor_failure(summary, error),
        }
    }
    Ok(())
}

fn resolve_original_assets(
    config: &MonitorConfig,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    active_lifecycle_asset_ids: &[String],
) -> Result<(), MonitorError> {
    let target_batches = original_asset_resolution_target_batches(
        manifest,
        config,
        Some(active_lifecycle_asset_ids),
    )?;
    if target_batches.is_empty() {
        return Ok(());
    }

    let session_path = required_path(&config.delete_session_path, "delete_session_path")?;
    let session = load_cloudkit_delete_session(session_path)?;
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
            }),
        );
        match client.resolve_original_assets_batch_outcome(
            &session,
            &CloudKitOriginalAssetBatchResolveRequest {
                targets,
                start_rank: config.cloudkit_start_rank,
                page_size: config.cloudkit_page_size,
                max_pages: config.cloudkit_max_pages,
            },
        ) {
            Ok(outcome) => {
                let resolved = outcome.proofs.len();
                let unresolved = outcome.unresolved_asset_ids.len();
                if record_original_asset_batch_outcome(manifest, outcome, summary)? {
                    manifest
                        .save_atomic(&config.manifest_path)
                        .map_err(MonitorError::Manifest)?;
                }
                log_monitor_event(
                    "original_asset_resolve_batch_finished",
                    summary.started_unix_seconds,
                    json!({
                        "targets": asset_ids.len(),
                        "resolved": resolved,
                        "unresolved": unresolved,
                        "wall_time_seconds": current_unix_seconds().saturating_sub(started),
                    }),
                );
            }
            Err(error) => {
                let should_fail_records = original_asset_resolve_error_should_fail_records(&error);
                let message = error.to_string();
                record_monitor_failure(summary, message.clone());
                if should_fail_records {
                    record_lifecycle_failure_for_assets(
                        manifest,
                        &asset_ids,
                        "original_asset_resolve",
                        &message,
                    )?;
                    manifest
                        .save_atomic(&config.manifest_path)
                        .map_err(MonitorError::Manifest)?;
                }
                log_monitor_event(
                    "original_asset_resolve_batch_finished",
                    summary.started_unix_seconds,
                    json!({
                        "targets": asset_ids.len(),
                        "resolved": 0,
                        "unresolved": asset_ids.len(),
                        "wall_time_seconds": current_unix_seconds().saturating_sub(started),
                        "error": message,
                    }),
                );
            }
        }
    }
    Ok(())
}

fn original_asset_resolve_error_should_fail_records(error: &UploadError) -> bool {
    matches!(error, UploadError::OriginalAssetResolveNotUnique { .. })
}

fn upload_verified_heics(
    config: &MonitorConfig,
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
    for asset_id in asset_ids {
        summary.uploads_attempted = summary.uploads_attempted.saturating_add(1);
        let result = (|| -> Result<(), MonitorError> {
            let heic = upload_ready_heic_proof(manifest, &asset_id)?;
            verify_local_heic(&heic)?;
            let response = run_icloud_upload(&crate::upload::IcloudUploadRequest {
                session_path: session_path.to_path_buf(),
                heic_path: heic.heic_path.clone(),
            })?;
            let uploaded_bytes = heic.size_bytes;
            let proof = build_upload_proof(&heic, &response)?;
            record_upload_proof(manifest, &asset_id, proof)?;
            manifest
                .save_atomic(&config.manifest_path)
                .map_err(MonitorError::Manifest)?;
            summary.uploads_completed = summary.uploads_completed.saturating_add(1);
            summary.uploaded_heic_bytes =
                summary.uploaded_heic_bytes.saturating_add(uploaded_bytes);
            Ok(())
        })();
        if let Err(error) = result {
            record_monitor_failure(summary, error);
        }
    }
    Ok(())
}

fn record_local_mirrors(
    config: &MonitorConfig,
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
    for asset_id in asset_ids {
        let result = (|| -> Result<(), MonitorError> {
            let (upload, heic) = icloudpd_local_mirror_ready_proofs(manifest, &asset_id)?;
            let uploaded_heic_path =
                upload
                    .uploaded_heic_path
                    .clone()
                    .ok_or(WorkflowError::EmptyProofField {
                        field: "uploaded_heic_path",
                    })?;
            let proof = ensure_icloudpd_local_mirror(IcloudpdLocalMirrorRequest {
                uploaded_heic_asset_id: upload.uploaded_heic_asset_id,
                uploaded_heic_sha256: upload.uploaded_heic_sha256,
                uploaded_heic_path,
                size_bytes: heic.size_bytes,
                icloudpd_download_path: mirror_root.join(format!("{asset_id}.HEIC")),
            })?;
            record_icloudpd_local_mirror_proof(manifest, &asset_id, proof)?;
            manifest
                .save_atomic(&config.manifest_path)
                .map_err(MonitorError::Manifest)?;
            summary.mirrors_recorded = summary.mirrors_recorded.saturating_add(1);
            Ok(())
        })();
        if let Err(error) = result {
            record_monitor_failure(summary, error);
        }
    }
    Ok(())
}

fn delete_original_assets(
    config: &MonitorConfig,
    manifest: &mut Manifest,
    summary: &mut MonitorScanSummary,
    active_lifecycle_asset_ids: &[String],
) -> Result<(), MonitorError> {
    let session_path = required_path(&config.delete_session_path, "delete_session_path")?;
    let session = load_cloudkit_delete_session(session_path)?;
    let transport = ReqwestCloudKitDeleteTransport::new()?;
    let mut client = CloudKitDeleteClient::new(transport);

    let mut asset_ids = asset_ids_matching(manifest, config.max_lifecycle_per_scan, |record| {
        active_lifecycle_allows(Some(active_lifecycle_asset_ids), &record.asset_id)
            && record.state == State::UploadVerified
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

    for asset_id in asset_ids {
        let result = (|| -> Result<(), MonitorError> {
            if manifest.get(&asset_id)?.state == State::UploadVerified {
                mark_delete_eligible(manifest, &asset_id)?;
                manifest
                    .save_atomic(&config.manifest_path)
                    .map_err(MonitorError::Manifest)?;
            }
            if manifest.get(&asset_id)?.state == State::DeleteEligible {
                approve_delete(manifest, &asset_id, &config.delete_operator)?;
                manifest
                    .save_atomic(&config.manifest_path)
                    .map_err(MonitorError::Manifest)?;
            }
            if manifest.get(&asset_id)?.state != State::DeleteApproved {
                return Ok(());
            }
            let raw_bytes = raw_size_bytes(manifest, &asset_id)?;
            let heic_bytes = heic_size_bytes(manifest, &asset_id)?;
            let request = approved_original_delete_request(manifest, &asset_id)?;
            let outcome = client.delete_original(&session, &request)?;
            record_delete_execution(manifest, &asset_id, outcome)?;
            manifest
                .save_atomic(&config.manifest_path)
                .map_err(MonitorError::Manifest)?;
            summary.originals_deleted = summary.originals_deleted.saturating_add(1);
            summary.deleted_raw_bytes = summary.deleted_raw_bytes.saturating_add(raw_bytes);
            summary.bytes_saved = summary
                .bytes_saved
                .saturating_add(raw_bytes.saturating_sub(heic_bytes));
            Ok(())
        })();
        if let Err(error) = result {
            record_monitor_failure(summary, error);
        }
    }
    Ok(())
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

fn should_skip_new_monitor_work(had_lifecycle_pending_at_start: bool) -> bool {
    had_lifecycle_pending_at_start
}

fn ensure_scan_root_access(path: &Path, timeout_seconds: u64) -> Result<(), MonitorError> {
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
    ensure_macos_scan_root_enumerable(path, timeout_seconds)?;
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

fn active_lifecycle_asset_ids(manifest: &Manifest, limit: usize) -> Vec<String> {
    asset_ids_matching(manifest, limit, is_lifecycle_candidate)
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
                && matches!(record.state, State::NasVerified | State::ConversionVerified)
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
) -> Result<HeicVerificationProof, MonitorError> {
    let record = manifest.get(asset_id)?;
    let conversion = decode_monitor_proof::<ConversionResultProof>(record, "conversion")?;
    command_status_ok("heif-info", &[conversion.heic_path.as_path()])?;
    let orientation = command_stdout(
        "exiftool",
        &["-s", "-s", "-s", "-n", "-Orientation"],
        [conversion.heic_path.as_path()],
    )?;
    let metadata_copied = orientation.trim() == "1";
    let oriented_preview = oriented_preview_path(&conversion.heic_path);
    let visual_match_ok = if oriented_preview.exists() {
        image_rmse(&oriented_preview, &conversion.heic_path)? <= MONITOR_VISUAL_RMSE_MAX
    } else {
        false
    };
    let visual_content_ok = image_stdev(&conversion.heic_path)? >= MONITOR_HEIC_STDEV_MIN;

    Ok(HeicVerificationProof {
        heic_path: conversion.heic_path,
        heic_sha256: conversion.heic_sha256,
        size_bytes: conversion.size_bytes,
        heif_info_ok: true,
        metadata_copied,
        visual_content_ok,
        visual_match_ok,
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

fn image_rmse(reference: &Path, candidate: &Path) -> Result<f64, MonitorError> {
    let output = Command::new("magick")
        .args(["compare", "-metric", "RMSE"])
        .arg(reference)
        .arg(candidate)
        .arg("null:")
        .output()
        .map_err(|source| MonitorError::CommandIo {
            program: "magick",
            source,
        })?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    parse_parenthesized_float(&stderr).ok_or_else(|| MonitorError::CommandFailed {
        program: "magick",
        message: format!("failed to parse RMSE from {stderr:?}"),
    })
}

fn image_stdev(path: &Path) -> Result<f64, MonitorError> {
    let output = Command::new("magick")
        .arg(path)
        .args([
            "-colorspace",
            "RGB",
            "-format",
            "%[fx:standard_deviation]",
            "info:",
        ])
        .output()
        .map_err(|source| MonitorError::CommandIo {
            program: "magick",
            source,
        })?;
    if !output.status.success() {
        return Err(MonitorError::CommandFailed {
            program: "magick",
            message: format!("exited with {}", output.status),
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .trim()
        .parse::<f64>()
        .map_err(|_| MonitorError::CommandFailed {
            program: "magick",
            message: format!("failed to parse standard deviation from {stdout:?}"),
        })
}

fn command_status_ok(program: &'static str, paths: &[&Path]) -> Result<(), MonitorError> {
    let output = Command::new(program)
        .args(paths)
        .output()
        .map_err(|source| MonitorError::CommandIo { program, source })?;
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
) -> Result<String, MonitorError> {
    let mut command = Command::new(program);
    command.args(args);
    for path in paths {
        command.arg(path);
    }
    let output = command
        .output()
        .map_err(|source| MonitorError::CommandIo { program, source })?;
    if !output.status.success() {
        return Err(MonitorError::CommandFailed {
            program,
            message: format!("exited with {}", output.status),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn parse_parenthesized_float(value: &str) -> Option<f64> {
    let start = value.find('(')?;
    let rest = &value[start + 1..];
    let end = rest.find(')')?;
    rest[..end].trim().parse().ok()
}

fn record_monitor_failure(summary: &mut MonitorScanSummary, error: impl ToString) {
    summary.failures = summary.failures.saturating_add(1);
    summary.last_error = Some(error.to_string());
}

fn record_original_asset_batch_outcome(
    manifest: &mut Manifest,
    outcome: CloudKitOriginalAssetBatchResolveOutcome,
    summary: &mut MonitorScanSummary,
) -> Result<bool, MonitorError> {
    let resolved = outcome.proofs.len() as u64;
    let unresolved_asset_ids = outcome.unresolved_asset_ids;
    let has_manifest_changes = resolved > 0 || !unresolved_asset_ids.is_empty();
    if resolved > 0 {
        let resolved_asset_ids = outcome.proofs.keys().cloned().collect::<Vec<_>>();
        record_original_asset_batch_proofs(manifest, &resolved_asset_ids, outcome.proofs)?;
        summary.originals_resolved = summary.originals_resolved.saturating_add(resolved);
    }
    if !unresolved_asset_ids.is_empty() {
        let message = "CloudKit original asset resolver found no exact RAW resource for this asset; delete remains blocked";
        record_monitor_failure(summary, message);
        record_lifecycle_failure_for_assets(
            manifest,
            &unresolved_asset_ids,
            "original_asset_resolve",
            message,
        )?;
    }
    Ok(has_manifest_changes)
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

fn load_manifest_for_monitor(path: &Path) -> Result<Manifest, MonitorError> {
    match Manifest::load(path) {
        Ok(manifest) => Ok(manifest),
        Err(ManifestError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            Ok(Manifest::new())
        }
        Err(source) => Err(MonitorError::Manifest(source)),
    }
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

fn state_counts(manifest: &Manifest) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for record in manifest.records().values() {
        *counts.entry(record.state.as_str().to_string()).or_insert(0) += 1;
    }
    counts
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
    #[error("workflow error: {0}")]
    Workflow(#[from] WorkflowError),
    #[error("conversion error: {0}")]
    Conversion(#[from] ConversionExecutionError),
    #[error("upload error: {0}")]
    Upload(#[from] UploadError),
    #[error("local mirror error: {0}")]
    LocalMirror(#[from] LocalMirrorError),
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
    use serde_json::json;

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
    fn original_asset_batch_outcome_records_proofs_and_only_fails_unresolved_assets() {
        let mut manifest = Manifest::new();
        for asset_id in ["asset-a", "asset-b"] {
            let mut record =
                AssetRecord::new(asset_id, PathBuf::from(format!("/raw/{asset_id}.DNG")));
            record.state = State::ConversionVerified;
            record.proofs.insert(
                "nas".to_string(),
                json!({
                    "canonical_path": format!("/raw/{asset_id}.DNG"),
                    "relative_path": format!("{asset_id}.DNG"),
                    "size_bytes": 9,
                    "modified_unix_seconds": 1_800_000_000u64,
                    "age_seconds": 2_592_000u64,
                    "sha256": "raw-sha",
                }),
            );
            manifest.upsert(record);
        }
        let mut proofs = std::collections::BTreeMap::new();
        proofs.insert(
            "asset-a".to_string(),
            crate::workflow::OriginalAssetProof {
                record_name: "CPLAsset-original-a".to_string(),
                record_change_tag: "tag-a".to_string(),
                record_type: "CPLAsset".to_string(),
                filename: "asset-a.DNG".to_string(),
                size_bytes: 9,
                matched_raw_sha256: "raw-sha".to_string(),
            },
        );
        let outcome = CloudKitOriginalAssetBatchResolveOutcome {
            proofs,
            unresolved_asset_ids: vec!["asset-b".to_string()],
        };
        let mut summary = MonitorScanSummary::default();

        let changed = record_original_asset_batch_outcome(&mut manifest, outcome, &mut summary)
            .expect("partial outcome should be recorded");

        assert!(changed);
        let resolved = manifest
            .get("asset-a")
            .expect("resolved asset should exist");
        assert_eq!(resolved.state, State::ConversionVerified);
        assert_eq!(
            resolved.proofs["original_asset"]["record_name"],
            "CPLAsset-original-a"
        );
        assert!(resolved.failures.is_empty());
        let unresolved = manifest
            .get("asset-b")
            .expect("unresolved asset should exist");
        assert_eq!(unresolved.state, State::Failed);
        assert!(!unresolved.proofs.contains_key("original_asset"));
        assert_eq!(unresolved.failures[0].stage, "original_asset_resolve");
        assert_eq!(summary.originals_resolved, 1);
        assert_eq!(summary.failures, 1);
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
    fn full_lifecycle_conversion_requests_wait_for_original_asset_proof() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let mut config = MonitorConfig::new(
            tempdir.path().join("download"),
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        );
        config.full_lifecycle = true;

        let mut manifest = Manifest::new();
        let mut unproven = AssetRecord::new("unproven", PathBuf::from("/raw/unproven.DNG"));
        unproven.state = State::NasVerified;
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

        assert_eq!(asset_ids, vec!["nas-unproven", "verified-unproven"]);
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
    fn active_lifecycle_asset_ids_selects_bounded_manifest_order_candidates() {
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
            vec!["b-nas", "c-converted", "d-verified", "e-uploaded"]
        );
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
            ("c-ready-outside-window", State::NasVerified, true),
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

        assert_eq!(active_asset_ids, vec!["a-nas", "b-converted"]);
        assert_eq!(asset_ids, vec!["a-nas"]);
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
    fn scan_start_lifecycle_work_suppresses_new_monitor_work_for_entire_scan() {
        let mut record = AssetRecord::new("asset", PathBuf::from("/raw/asset.DNG"));
        record.state = State::NasVerified;
        let mut manifest = Manifest::new();
        manifest.upsert(record);

        let had_lifecycle_pending_at_start = pending_lifecycle_count(&manifest) > 0;
        manifest
            .record_failure("asset", "original_asset_resolve", "no matching candidate")
            .expect("failure should be recorded");

        assert_eq!(pending_lifecycle_count(&manifest), 0);
        assert!(should_skip_new_monitor_work(had_lifecycle_pending_at_start));
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

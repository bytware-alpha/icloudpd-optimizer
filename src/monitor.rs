use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::conversion_execution::{
    ConversionExecutionError, ConversionExecutionRequest, execute_measured_conversions,
};
use crate::manifest::{Manifest, ManifestError, State};
use crate::proof::{MIN_RAW_AGE_DAYS, ProofError};
use crate::workflow::{WorkflowError, prove_and_record_nas};

const MONITOR_CONFIG_SCHEMA_VERSION: u64 = 1;
const MONITOR_STATS_SCHEMA_VERSION: u64 = 1;
const RAW_EXTENSIONS: &[&str] = &[
    "dng", "cr2", "cr3", "nef", "arw", "raf", "rw2", "orf", "pef", "srw", "raw",
];

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
    pub conversion_tool_version: Option<String>,
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
            conversion_tool_version: None,
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

    let download_root = fs::canonicalize(&config.download_root).map_err(|source| {
        MonitorError::CanonicalizeRoot {
            path: config.download_root.clone(),
            source,
        }
    })?;
    let now = SystemTime::now();
    let mut pending_capacity = config
        .max_conversions_per_scan
        .saturating_sub(pending_conversion_count(&manifest));
    if pending_capacity > 0 {
        visit_raw_paths(&download_root, &mut |raw_path| {
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
                Ok(_) => {
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
    }

    manifest
        .save_atomic(&config.manifest_path)
        .map_err(MonitorError::Manifest)?;

    let requests = conversion_requests(&manifest, config);
    summary.conversions_attempted = requests.len() as u64;
    if !requests.is_empty() {
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

    summary.finished_unix_seconds = current_unix_seconds();
    summary.state_counts = state_counts(&manifest);
    stats.apply_scan(&summary);
    stats.save_atomic(&config.stats_path)?;

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

pub fn launchd_plist(label: &str, binary: &Path, config: &Path) -> Result<String, MonitorError> {
    validate_launchd_label(label)?;
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
            "  <key>RunAtLoad</key>\n",
            "  <true/>\n",
            "  <key>KeepAlive</key>\n",
            "  <true/>\n",
            "</dict>\n",
            "</plist>\n"
        ),
        label = escape_xml(label),
        binary = escape_xml(&binary.display().to_string()),
        config = escape_xml(&config.display().to_string()),
    ))
}

pub fn write_launchd_plist(
    label: &str,
    binary: &Path,
    config: &Path,
    output: &Path,
) -> Result<(), MonitorError> {
    let plist = launchd_plist(label, binary, config)?;
    write_text_atomic(output, &plist).map_err(|source| MonitorError::WriteLaunchdPlist {
        path: output.to_path_buf(),
        source,
    })
}

fn conversion_requests(
    manifest: &Manifest,
    config: &MonitorConfig,
) -> Vec<ConversionExecutionRequest> {
    manifest
        .records()
        .values()
        .filter(|record| record.state == State::NasVerified)
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

fn pending_conversion_count(manifest: &Manifest) -> usize {
    manifest
        .records()
        .values()
        .filter(|record| record.state == State::NasVerified)
        .count()
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
    visitor: &mut impl FnMut(PathBuf) -> Result<VisitDecision, MonitorError>,
) -> Result<VisitDecision, MonitorError> {
    visit_raw_paths_inner(root, visitor)
}

fn visit_raw_paths_inner(
    directory: &Path,
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
        if metadata.is_dir() {
            if matches!(visit_raw_paths_inner(&path, visitor)?, VisitDecision::Stop) {
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
    #[error("invalid launchd label {label}")]
    InvalidLaunchdLabel { label: String },
    #[error("failed to write launchd plist {path}: {source}")]
    WriteLaunchdPlist { path: PathBuf, source: io::Error },
}

use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::ErrorKind;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::conversion_backend::{
    TargetPlatform, current_backend_report, required_tools_for_target,
};
use crate::conversion_execution::{
    ConversionExecutionError, ConversionExecutionRequest, execute_measured_conversion,
    execute_measured_conversions, is_executable_file, run_raw_stage_copy_child,
};
use crate::local_mirror::{
    IcloudpdLocalMirrorRequest, LocalMirrorError, ensure_icloudpd_local_mirror,
};
use crate::manifest::{AssetRecord, Manifest, ManifestError, State};
use crate::metrics::VerifiedMetrics;
use crate::monitor::{
    MonitorConfig, MonitorError, MonitorScanSummary, MonitorStats, acquire_monitor_run_guard,
    launchd_plist, log_monitor_failure_event, render_tui, run_monitor_once,
    run_scan_root_preflight_probe, write_launchd_plist,
};
use crate::proof::NasRawProof;
use crate::service::{
    DEFAULT_SERVICE_LABEL, ServiceError, ServiceInstallRequest, default_plist_path,
    install_service, service_status, start_service, stop_service, tail_logs, uninstall_service,
};
use crate::state_store::{AssetStateStore, AssetStateStoreError};
use crate::upload::{
    CloudKitDatabaseScope, CloudKitDeleteClient, CloudKitDeleteRequest, CloudKitLibraryDestination,
    CloudKitLocalReplacementCandidate, CloudKitOriginalAssetBatchResolveOutcome,
    CloudKitOriginalAssetBatchResolveRequest, CloudKitOriginalAssetInventoryFingerprint,
    CloudKitOriginalAssetReadTransport, CloudKitOriginalAssetResolution,
    CloudKitOriginalAssetResolveDisposition, CloudKitOriginalAssetResolveRequest,
    CloudKitOriginalAssetResolveTarget, IcloudUploadRequest, ReqwestCloudKitDeleteTransport,
    ReqwestCloudKitReadTransport, UploadError, build_upload_proof, load_cloudkit_delete_session,
    load_upload_session, run_icloud_upload, validate_library_destination, verify_local_heic,
};
use crate::workflow::{
    ConversionPerformanceInput, ConversionResultProof, HeicVerificationProof, OriginalAssetProof,
    SourceAgeProof, UploadProof, WorkflowError, approve_delete, approved_original_delete_request,
    build_delete_plan, icloudpd_local_mirror_ready_proofs, mark_delete_eligible,
    prove_and_record_nas, record_conversion_performance, record_conversion_result,
    record_delete_execution, record_heic_verification, record_icloudpd_local_mirror_proof,
    record_original_asset_batch_proofs, record_original_asset_proof, record_source_age_proof,
    record_stage_failure, record_upload_proof, record_uploaded_heic_delete,
    upload_ready_heic_proof, uploaded_heic_delete_request,
};

const DAY_SECONDS: u64 = 24 * 60 * 60;

#[derive(Debug, Parser)]
#[command(
    name = "icloudpd-optimizer",
    version,
    about = "Fail-closed iCloudPD RAW optimization helper"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Manifest(ManifestArgs),
    Doctor(DoctorArgs),
    Workflow(WorkflowArgs),
    Monitor(MonitorArgs),
    Service(ServiceArgs),
    #[command(name = "__stage-raw-copy", hide = true)]
    StageRawCopy(StageRawCopyArgs),
}

#[derive(Debug, Args)]
struct ManifestArgs {
    #[command(subcommand)]
    command: ManifestCommand,
}

#[derive(Debug, Subcommand)]
enum ManifestCommand {
    Show(ManifestShowArgs),
    Migrate(ManifestMigrateArgs),
}

#[derive(Debug, Args)]
struct ManifestShowArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
}

#[derive(Debug, Args)]
struct ManifestMigrateArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    from: i32,
    #[arg(long)]
    to: i32,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    #[arg(long, required = true)]
    json: bool,
}

#[derive(Debug, Args)]
struct WorkflowArgs {
    #[command(subcommand)]
    command: WorkflowCommand,
}

#[derive(Debug, Args)]
struct MonitorArgs {
    #[command(subcommand)]
    command: MonitorCommand,
}

#[derive(Debug, Args)]
struct ServiceArgs {
    #[command(subcommand)]
    command: ServiceCommand,
}

#[derive(Debug, Args)]
struct StageRawCopyArgs {
    #[arg(value_name = "SOURCE")]
    source: PathBuf,
    #[arg(value_name = "DEST")]
    dest: PathBuf,
    #[arg(value_name = "EXPECTED_SIZE")]
    expected_size: u64,
    #[arg(value_name = "EXPECTED_SHA256")]
    expected_sha256: String,
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    #[command(about = "Install the macOS per-user LaunchAgent service")]
    Install(ServiceInstallArgs),
    #[command(
        name = "prime-access",
        about = "Prime macOS privacy access by safely touching configured NAS paths"
    )]
    PrimeAccess(ServicePrimeAccessArgs),
    #[command(about = "Start the installed macOS LaunchAgent service")]
    Start(ServiceStartArgs),
    #[command(about = "Stop the installed macOS LaunchAgent service")]
    Stop(ServiceLabelArgs),
    #[command(about = "Print launchd status for the service")]
    Status(ServiceLabelArgs),
    #[command(about = "Print recent service stdout/stderr logs")]
    Logs(ServiceLogsArgs),
    #[command(about = "Remove the LaunchAgent service")]
    Uninstall(ServiceUninstallArgs),
}

#[derive(Debug, Subcommand)]
enum MonitorCommand {
    #[command(about = "Write a simple monitor config JSON file")]
    Init(Box<MonitorInitArgs>),
    #[command(about = "Run the background monitor loop")]
    Run(MonitorRunArgs),
    #[command(about = "Print monitor stats")]
    Stats(MonitorStatsArgs),
    #[command(about = "Print the monitor queue and rolling worker plan")]
    Queue(MonitorQueueArgs),
    #[command(about = "Show a simple refreshing monitor TUI")]
    Tui(MonitorTuiArgs),
    #[command(
        name = "original-assets-audit",
        about = "Read-only CloudKit original/replacement inventory audit"
    )]
    OriginalAssetsAudit(MonitorOriginalAssetsAuditArgs),
    #[command(
        name = "launchd-plist",
        about = "Print or write a macOS user LaunchAgent plist"
    )]
    LaunchdPlist(MonitorLaunchdPlistArgs),
    #[command(name = "scan-root-preflight", hide = true)]
    ScanRootPreflight(MonitorScanRootPreflightArgs),
}

#[derive(Debug, Args)]
struct MonitorInitArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, value_name = "DIR")]
    download_root: PathBuf,
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long, value_name = "DIR")]
    heic_output_dir: PathBuf,
    #[arg(long, value_name = "DIR")]
    nas_root: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    stats: Option<PathBuf>,
    #[arg(long, default_value_t = 30)]
    min_age_days: u64,
    #[arg(long, default_value_t = 300)]
    scan_interval_seconds: u64,
    #[arg(long, default_value_t = 1)]
    jobs: usize,
    #[arg(long)]
    rolling_worker_count: Option<usize>,
    #[arg(long)]
    rolling_convert_stage_count: Option<usize>,
    #[arg(long, default_value_t = 90)]
    heic_quality: u8,
    #[arg(long, default_value_t = 25)]
    max_conversions_per_scan: usize,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_recursive_scan: bool,
    #[arg(long)]
    conversion_tool_version: Option<String>,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    full_lifecycle: bool,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    rolling_lifecycle: bool,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    auto_delete: bool,
    #[arg(long, value_name = "PATH")]
    upload_session: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    delete_session: Option<PathBuf>,
    #[arg(long, value_name = "DIR")]
    mirror_root: Option<PathBuf>,
    #[arg(long, default_value = "icloudpd-optimizer-monitor")]
    delete_operator: String,
    #[arg(long, default_value_t = 5)]
    max_lifecycle_per_scan: usize,
    #[arg(long, default_value_t = 16)]
    max_original_resolver_retries_per_scan: usize,
    #[arg(long, default_value_t = 86_400)]
    original_resolver_retry_min_age_seconds: u64,
    #[arg(long, default_value_t = 2)]
    capture_tolerance_seconds: u64,
    #[arg(long, default_value_t = 0)]
    cloudkit_start_rank: u64,
    #[arg(long, default_value_t = 200)]
    cloudkit_page_size: u64,
    #[arg(long, default_value_t = 2000)]
    cloudkit_max_pages: u64,
    #[arg(long, default_value_t = 30)]
    scan_root_preflight_timeout_seconds: u64,
    #[arg(long, default_value_t = 60)]
    local_mirror_timeout_seconds: u64,
    #[arg(long, default_value_t = 600)]
    upload_timeout_seconds: u64,
    #[arg(long, default_value_t = 60)]
    heic_verify_timeout_seconds: u64,
    #[arg(long, default_value_t = 2)]
    rolling_original_resolve_active_window_multiplier: usize,
    #[arg(long, default_value_t = 2)]
    rolling_original_resolve_batch_multiplier: usize,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    force: bool,
}

#[derive(Debug, Args)]
struct MonitorRunArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    once: bool,
}

#[derive(Debug, Args)]
struct MonitorScanRootPreflightArgs {
    #[arg(long, value_name = "PATH")]
    path: PathBuf,
}

#[derive(Debug, Args)]
struct MonitorStatsArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    json: bool,
}

#[derive(Debug, Args)]
struct MonitorQueueArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    json: bool,
    #[arg(long, default_value_t = 5)]
    chunks: usize,
}

#[derive(Debug, Args)]
struct MonitorTuiArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, default_value_t = 2)]
    refresh_seconds: u64,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    once: bool,
}

#[derive(Debug, Args)]
struct MonitorOriginalAssetsAuditArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
}

#[derive(Debug, Args)]
struct MonitorLaunchdPlistArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, default_value = "com.icloudpd-optimizer.monitor")]
    label: String,
    #[arg(long, value_name = "BUNDLE_ID")]
    associated_bundle_id: Option<String>,
    #[arg(long, value_name = "PATH")]
    bin: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    stdout: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    stderr: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ServiceInstallArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, default_value = DEFAULT_SERVICE_LABEL)]
    label: String,
    #[arg(long, value_name = "BUNDLE_ID")]
    associated_bundle_id: Option<String>,
    #[arg(long, value_name = "PATH")]
    bin: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    plist: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    stdout: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    stderr: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ServicePrimeAccessArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, value_name = "DIR")]
    write_canary_dir: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    status_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ServiceStartArgs {
    #[arg(long, default_value = DEFAULT_SERVICE_LABEL)]
    label: String,
    #[arg(long, value_name = "PATH")]
    plist: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct ServiceLabelArgs {
    #[arg(long, default_value = DEFAULT_SERVICE_LABEL)]
    label: String,
}

#[derive(Debug, Args)]
struct ServiceLogsArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, value_name = "PATH")]
    stdout: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    stderr: Option<PathBuf>,
    #[arg(long, default_value_t = 80)]
    lines: usize,
}

#[derive(Debug, Args)]
struct ServiceUninstallArgs {
    #[arg(long, default_value = DEFAULT_SERVICE_LABEL)]
    label: String,
    #[arg(long, value_name = "PATH")]
    plist: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum WorkflowCommand {
    NasVerified(WorkflowNasVerifiedArgs),
    #[command(about = "Run the actual conversion and record measured performance proofs")]
    Convert(WorkflowConvertArgs),
    #[command(
        name = "convert-batch",
        about = "Run multiple conversions with bounded parallelism and one manifest save"
    )]
    ConvertBatch(WorkflowConvertBatchArgs),
    #[command(name = "conversion-recorded", alias = "conversion-result")]
    ConversionResult(WorkflowConversionResultArgs),
    #[command(name = "conversion-performance")]
    ConversionPerformance(WorkflowConversionPerformanceArgs),
    HeicVerified(WorkflowHeicVerifiedArgs),
    #[command(about = "Upload with an external Photos upload session not produced by icloudpd")]
    UploadHeic(WorkflowUploadHeicArgs),
    #[command(name = "upload-heic-proof", hide = true)]
    UploadHeicProof(WorkflowUploadHeicArgs),
    #[command(name = "upload-heic-proof-direct", hide = true)]
    UploadHeicProofDirect(WorkflowUploadHeicProofDirectArgs),
    UploadVerified(WorkflowUploadVerifiedArgs),
    #[command(
        name = "uploaded-heic-delete-plan",
        about = "Resolve and hash-verify the uploaded HEIC replacement asset without deleting it"
    )]
    UploadedHeicDeletePlan(WorkflowDeleteUploadedHeicArgs),
    #[command(
        name = "delete-uploaded-heic",
        about = "Delete the uploaded HEIC replacement asset after hash-verifying its CloudKit resource"
    )]
    DeleteUploadedHeic(WorkflowDeleteUploadedHeicArgs),
    #[command(name = "icloudpd-local-mirror")]
    IcloudpdLocalMirror(WorkflowIcloudpdLocalMirrorArgs),
    #[command(name = "icloudpd-local-mirror-proof", hide = true)]
    IcloudpdLocalMirrorProof(WorkflowIcloudpdLocalMirrorProofArgs),
    OriginalAssetVerified(WorkflowOriginalAssetVerifiedArgs),
    #[command(
        name = "original-asset-resolve",
        about = "Resolve the original RAW CPLAsset identity from CloudKit records/query"
    )]
    OriginalAssetResolve(WorkflowOriginalAssetResolveArgs),
    #[command(
        name = "original-assets-resolve-batch",
        about = "Resolve original RAW CPLAsset identities for multiple manifest records in one CloudKit scan"
    )]
    OriginalAssetsResolveBatch(WorkflowOriginalAssetsResolveBatchArgs),
    MarkDeleteEligible(WorkflowAssetArgs),
    ApproveDelete(WorkflowApproveDeleteArgs),
    Failed(WorkflowFailedArgs),
    DeletePlan(WorkflowAssetArgs),
    #[command(about = "Execute the approved original asset delete with a CloudKit delete session")]
    DeleteExecute(WorkflowDeleteExecuteArgs),
}

#[derive(Debug, Args)]
struct WorkflowNasVerifiedArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    asset_id: String,
    #[arg(long, value_name = "PATH")]
    raw_path: PathBuf,
    #[arg(long, value_name = "ROOT")]
    nas_root: PathBuf,
    #[arg(long)]
    min_age_days: u64,
    #[arg(long)]
    source_captured_unix_seconds: Option<u64>,
}

#[derive(Debug, Args)]
struct WorkflowConversionResultArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    asset_id: String,
    #[arg(long, value_name = "PATH")]
    heic_path: PathBuf,
    #[arg(long)]
    heic_sha256: String,
    #[arg(long)]
    size_bytes: u64,
}

#[derive(Debug, Args)]
struct WorkflowConvertArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    asset_id: String,
    #[arg(
        long,
        value_name = "PATH",
        help = "HEIC output path for the actual conversion"
    )]
    output_path: PathBuf,
    #[arg(long, help = "HEIC quality used by the measured performance run")]
    heic_quality: u8,
    #[arg(long)]
    conversion_tool_version: Option<String>,
}

#[derive(Debug, Args)]
struct WorkflowConvertBatchArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    asset_id: Vec<String>,
    #[arg(
        long,
        value_name = "DIR",
        help = "Directory for <asset-id>.heic outputs"
    )]
    output_dir: PathBuf,
    #[arg(long, help = "HEIC quality used by the measured performance run")]
    heic_quality: u8,
    #[arg(long, default_value_t = 1, help = "Maximum conversions to run at once")]
    jobs: usize,
    #[arg(long)]
    conversion_tool_version: Option<String>,
}

#[derive(Debug, Args)]
struct WorkflowConversionPerformanceArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    asset_id: String,
    #[arg(long)]
    measured_at_unix_seconds: Option<u64>,
    #[arg(long)]
    conversion_tool: String,
    #[arg(long)]
    conversion_tool_version: Option<String>,
    #[arg(long)]
    heic_quality: u8,
    #[arg(long)]
    convert_wall_time_millis: u64,
    #[arg(long)]
    total_wall_time_millis: u64,
    #[arg(long)]
    user_cpu_time_millis: Option<u64>,
    #[arg(long)]
    system_cpu_time_millis: Option<u64>,
    #[arg(long)]
    peak_rss_kib: Option<u64>,
}

#[derive(Debug, Args)]
struct WorkflowHeicVerifiedArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    asset_id: String,
    #[arg(long, value_name = "PATH")]
    heic_path: PathBuf,
    #[arg(long)]
    heic_sha256: String,
    #[arg(long)]
    size_bytes: u64,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    heif_info_ok: bool,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    metadata_copied: bool,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    visual_content_ok: bool,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    visual_match_ok: bool,
}

#[derive(Debug, Args)]
struct WorkflowUploadHeicArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    asset_id: String,
    #[arg(
        long,
        value_name = "PATH",
        help = "External Photos upload session JSON; not produced by icloudpd"
    )]
    session: PathBuf,
}

#[derive(Debug, Args)]
struct WorkflowUploadHeicProofDirectArgs {
    #[arg(long)]
    asset_id: String,
    #[arg(long, value_name = "PATH")]
    heic_path: PathBuf,
    #[arg(long)]
    heic_sha256: String,
    #[arg(long)]
    size_bytes: u64,
    #[arg(
        long,
        value_name = "PATH",
        help = "External Photos upload session JSON; not produced by icloudpd"
    )]
    session: PathBuf,
    #[arg(long, value_enum)]
    database_scope: WorkflowCloudKitDatabaseScopeArg,
    #[arg(long)]
    zone_name: String,
}

#[derive(Debug, Args)]
struct WorkflowUploadVerifiedArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    asset_id: String,
    #[arg(long)]
    uploaded_heic_asset_id: String,
    #[arg(long)]
    uploaded_heic_sha256: String,
    #[arg(long, value_name = "PATH")]
    uploaded_heic_path: Option<PathBuf>,
    #[arg(long, value_enum)]
    database_scope: Option<WorkflowCloudKitDatabaseScopeArg>,
    #[arg(long)]
    zone_name: Option<String>,
}

#[derive(Debug, Args)]
struct WorkflowDeleteUploadedHeicArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    asset_id: String,
    #[arg(long, value_name = "PATH", help = "CloudKit delete session JSON")]
    session: PathBuf,
}

#[derive(Debug, Args)]
struct WorkflowIcloudpdLocalMirrorArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    asset_id: String,
    #[arg(long, value_name = "PATH")]
    download_path: PathBuf,
}

#[derive(Debug, Args)]
struct WorkflowIcloudpdLocalMirrorProofArgs {
    #[arg(long)]
    uploaded_heic_asset_id: String,
    #[arg(long)]
    uploaded_heic_sha256: String,
    #[arg(long, value_name = "PATH")]
    uploaded_heic_path: PathBuf,
    #[arg(long)]
    size_bytes: u64,
    #[arg(long, value_name = "PATH")]
    download_path: PathBuf,
}

#[derive(Debug, Args)]
struct WorkflowOriginalAssetVerifiedArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    asset_id: String,
    #[arg(long)]
    record_name: String,
    #[arg(long)]
    record_change_tag: String,
    #[arg(long)]
    record_type: String,
    #[arg(long)]
    filename: String,
    #[arg(long)]
    size_bytes: u64,
    #[arg(long)]
    matched_raw_sha256: String,
    #[arg(long, value_enum)]
    database_scope: Option<WorkflowCloudKitDatabaseScopeArg>,
    #[arg(long)]
    zone_name: Option<String>,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum WorkflowCloudKitDatabaseScopeArg {
    Private,
    Shared,
}

impl From<WorkflowCloudKitDatabaseScopeArg> for CloudKitDatabaseScope {
    fn from(value: WorkflowCloudKitDatabaseScopeArg) -> Self {
        match value {
            WorkflowCloudKitDatabaseScopeArg::Private => CloudKitDatabaseScope::Private,
            WorkflowCloudKitDatabaseScopeArg::Shared => CloudKitDatabaseScope::Shared,
        }
    }
}

#[derive(Debug, Args)]
struct WorkflowOriginalAssetResolveArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    asset_id: String,
    #[arg(long, value_name = "PATH", help = "CloudKit delete session JSON")]
    session: PathBuf,
    #[arg(long, default_value_t = 0)]
    start_rank: u64,
    #[arg(long, default_value_t = 200)]
    page_size: u64,
    #[arg(long, default_value_t = 100)]
    max_pages: u64,
    #[arg(long, default_value_t = 2)]
    capture_tolerance_seconds: u64,
}

#[derive(Debug, Args)]
struct WorkflowOriginalAssetsResolveBatchArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    asset_id: Vec<String>,
    #[arg(long, value_name = "PATH", help = "CloudKit delete session JSON")]
    session: PathBuf,
    #[arg(long, default_value_t = 0)]
    start_rank: u64,
    #[arg(long, default_value_t = 200)]
    page_size: u64,
    #[arg(long, default_value_t = 100)]
    max_pages: u64,
    #[arg(long, default_value_t = 2)]
    capture_tolerance_seconds: u64,
}

#[derive(Debug, Args)]
struct WorkflowAssetArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    asset_id: String,
}

#[derive(Debug, Args)]
struct WorkflowApproveDeleteArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    asset_id: String,
    #[arg(long)]
    operator: String,
}

#[derive(Debug, Args)]
struct WorkflowFailedArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    asset_id: String,
    #[arg(long)]
    stage: String,
    #[arg(long)]
    message: String,
}

#[derive(Debug, Args)]
struct WorkflowDeleteExecuteArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
    #[arg(long)]
    asset_id: String,
    #[arg(long, value_name = "PATH", help = "CloudKit delete session JSON")]
    session: PathBuf,
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("failed to load manifest at {path}: {source}")]
    LoadManifest {
        path: PathBuf,
        source: ManifestError,
    },
    #[error("failed to save manifest at {path}: {source}")]
    SaveManifest {
        path: PathBuf,
        source: ManifestError,
    },
    #[error("asset state store failed: {0}")]
    StateStore(#[from] AssetStateStoreError),
    #[error("workflow failed: {0}")]
    Workflow(#[from] WorkflowError),
    #[error("conversion failed: {0}")]
    Conversion(#[from] ConversionExecutionError),
    #[error("upload failed: {0}")]
    Upload(#[from] UploadError),
    #[error("local mirror failed: {0}")]
    LocalMirror(#[from] LocalMirrorError),
    #[error("monitor failed: {0}")]
    Monitor(#[from] MonitorError),
    #[error("service failed: {0}")]
    Service(#[from] ServiceError),
    #[error("config already exists at {path}; pass --force to overwrite")]
    ConfigAlreadyExists { path: PathBuf },
    #[error("unsafe batch asset id for output filename: {asset_id}")]
    UnsafeBatchAssetId { asset_id: String },
    #[error("invalid CloudKit destination: {message}")]
    InvalidCloudKitDestination { message: String },
    #[error("macOS app bundle does not contain a monitor config path resource")]
    MissingAppConfigResource,
    #[error("macOS access prime failed at {path}: {source}")]
    PrimeAccessIo { path: PathBuf, source: io::Error },
    #[error("macOS access prime failed: {message}")]
    PrimeAccess { message: String },
    #[error("failed to write JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("failed to write output: {0}")]
    Output(#[from] io::Error),
}

pub fn run() -> Result<(), CliError> {
    if should_run_default_app_prime() {
        return run_default_app_prime(&mut io::stdout());
    }
    run_with_writer(Cli::parse(), &mut io::stdout())
}

fn run_with_writer<W: Write>(cli: Cli, writer: &mut W) -> Result<(), CliError> {
    match cli.command {
        Command::Manifest(args) => run_manifest(args, writer),
        Command::Doctor(args) => run_doctor(args, writer),
        Command::Workflow(args) => run_workflow(args, writer),
        Command::Monitor(args) => run_monitor(args, writer),
        Command::Service(args) => run_service(args, writer),
        Command::StageRawCopy(args) => run_stage_raw_copy(args),
    }
}

fn run_stage_raw_copy(args: StageRawCopyArgs) -> Result<(), CliError> {
    run_raw_stage_copy_child(
        &args.source,
        &args.dest,
        args.expected_size,
        &args.expected_sha256,
    )?;
    Ok(())
}

fn run_manifest<W: Write>(args: ManifestArgs, writer: &mut W) -> Result<(), CliError> {
    match args.command {
        ManifestCommand::Show(args) => show_manifest(args, writer),
        ManifestCommand::Migrate(args) => migrate_manifest(args, writer),
    }
}

fn show_manifest<W: Write>(args: ManifestShowArgs, writer: &mut W) -> Result<(), CliError> {
    let manifest = load_existing_manifest(&args.manifest)?;
    let output = ManifestOutput {
        records: manifest.records().values().collect(),
    };
    serde_json::to_writer_pretty(&mut *writer, &output)?;
    writeln!(writer)?;
    Ok(())
}

fn migrate_manifest<W: Write>(args: ManifestMigrateArgs, writer: &mut W) -> Result<(), CliError> {
    let summary = AssetStateStore::migrate_schema_only(&args.manifest, args.from, args.to)?;
    serde_json::to_writer_pretty(&mut *writer, &summary)?;
    writeln!(writer)?;
    Ok(())
}

fn run_doctor<W: Write>(args: DoctorArgs, writer: &mut W) -> Result<(), CliError> {
    if args.json {
        let target = TargetPlatform::current();
        let backend = current_backend_report();
        let report = DoctorReport {
            platform: PlatformReport {
                os: target.os,
                arch: target.arch,
            },
            conversion_backend: DoctorConversionBackendReport {
                name: backend.name,
                workflow_convert_supported: backend.workflow_convert_supported,
                reason: backend.reason,
            },
            required_tools: required_tools_for_target(target)
                .iter()
                .copied()
                .map(|name| ToolReport {
                    name,
                    present: tool_present(name),
                })
                .collect(),
        };
        serde_json::to_writer_pretty(&mut *writer, &report)?;
        writeln!(writer)?;
    }
    Ok(())
}

fn run_workflow<W: Write>(args: WorkflowArgs, writer: &mut W) -> Result<(), CliError> {
    match args.command {
        WorkflowCommand::NasVerified(args) => workflow_nas_verified(args),
        WorkflowCommand::Convert(args) => workflow_convert(args),
        WorkflowCommand::ConvertBatch(args) => workflow_convert_batch(args),
        WorkflowCommand::ConversionResult(args) => workflow_conversion_result(args),
        WorkflowCommand::ConversionPerformance(args) => workflow_conversion_performance(args),
        WorkflowCommand::HeicVerified(args) => workflow_heic_verified(args),
        WorkflowCommand::UploadHeic(args) => workflow_upload_heic(args),
        WorkflowCommand::UploadHeicProof(args) => workflow_upload_heic_proof(args, writer),
        WorkflowCommand::UploadHeicProofDirect(args) => {
            workflow_upload_heic_proof_direct(args, writer)
        }
        WorkflowCommand::UploadVerified(args) => workflow_upload_verified(args),
        WorkflowCommand::UploadedHeicDeletePlan(args) => {
            workflow_uploaded_heic_delete_plan(args, writer)
        }
        WorkflowCommand::DeleteUploadedHeic(args) => workflow_delete_uploaded_heic(args),
        WorkflowCommand::IcloudpdLocalMirror(args) => workflow_icloudpd_local_mirror(args),
        WorkflowCommand::IcloudpdLocalMirrorProof(args) => {
            workflow_icloudpd_local_mirror_proof(args, writer)
        }
        WorkflowCommand::OriginalAssetVerified(args) => workflow_original_asset_verified(args),
        WorkflowCommand::OriginalAssetResolve(args) => workflow_original_asset_resolve(args),
        WorkflowCommand::OriginalAssetsResolveBatch(args) => {
            workflow_original_assets_resolve_batch(args)
        }
        WorkflowCommand::MarkDeleteEligible(args) => workflow_mark_delete_eligible(args),
        WorkflowCommand::ApproveDelete(args) => workflow_approve_delete(args),
        WorkflowCommand::Failed(args) => workflow_failed(args),
        WorkflowCommand::DeletePlan(args) => workflow_delete_plan(args, writer),
        WorkflowCommand::DeleteExecute(args) => workflow_delete_execute(args),
    }
}

fn run_monitor<W: Write>(args: MonitorArgs, writer: &mut W) -> Result<(), CliError> {
    match args.command {
        MonitorCommand::Init(args) => monitor_init(*args),
        MonitorCommand::Run(args) => monitor_run(args, writer),
        MonitorCommand::Stats(args) => monitor_stats(args, writer),
        MonitorCommand::Queue(args) => monitor_queue(args, writer),
        MonitorCommand::Tui(args) => monitor_tui(args, writer),
        MonitorCommand::OriginalAssetsAudit(args) => monitor_original_assets_audit(args, writer),
        MonitorCommand::LaunchdPlist(args) => monitor_launchd_plist(args, writer),
        MonitorCommand::ScanRootPreflight(args) => monitor_scan_root_preflight(args),
    }
}

fn run_service<W: Write>(args: ServiceArgs, writer: &mut W) -> Result<(), CliError> {
    match args.command {
        ServiceCommand::Install(args) => service_install(args, writer),
        ServiceCommand::PrimeAccess(args) => service_prime_access(args, writer),
        ServiceCommand::Start(args) => service_start(args),
        ServiceCommand::Stop(args) => service_stop(args),
        ServiceCommand::Status(args) => service_status_command(args, writer),
        ServiceCommand::Logs(args) => service_logs(args, writer),
        ServiceCommand::Uninstall(args) => service_uninstall(args),
    }
}

fn should_run_default_app_prime() -> bool {
    env::args_os().len() == 1
        && env::current_exe().ok().is_some_and(|path| {
            path.components()
                .any(|component| component.as_os_str().to_string_lossy().ends_with(".app"))
        })
}

fn run_default_app_prime<W: Write>(writer: &mut W) -> Result<(), CliError> {
    let config = app_resource_path("monitor-config-path")?;
    let config_text = fs::read_to_string(&config).map_err(|source| CliError::PrimeAccessIo {
        path: config.clone(),
        source,
    })?;
    let config_path = PathBuf::from(config_text.trim());
    prime_access(&config_path, None, None, writer)
}

fn app_resource_path(name: &str) -> Result<PathBuf, CliError> {
    let executable = env::current_exe()?;
    let Some(contents_dir) = executable
        .parent()
        .and_then(Path::parent)
        .filter(|path| path.file_name().is_some_and(|name| name == "Contents"))
    else {
        return Err(CliError::MissingAppConfigResource);
    };
    let path = contents_dir.join("Resources").join(name);
    if path.is_file() {
        Ok(path)
    } else {
        Err(CliError::MissingAppConfigResource)
    }
}

fn service_install<W: Write>(args: ServiceInstallArgs, writer: &mut W) -> Result<(), CliError> {
    let binary_path = match args.bin {
        Some(path) => path,
        None => env::current_exe()?,
    };
    let plist_path = match args.plist {
        Some(path) => path,
        None => default_plist_path(&args.label)?,
    };
    let stdout_path = args
        .stdout
        .unwrap_or_else(|| args.config.with_extension("stdout.log"));
    let stderr_path = args
        .stderr
        .unwrap_or_else(|| args.config.with_extension("stderr.log"));
    let summary = install_service(&ServiceInstallRequest {
        config_path: args.config,
        binary_path,
        plist_path,
        stdout_path,
        stderr_path,
        associated_bundle_id: Some(
            args.associated_bundle_id
                .unwrap_or_else(|| args.label.clone()),
        ),
        label: args.label,
    })?;
    writeln!(writer, "installed service {}", summary.label)?;
    writeln!(writer, "binary: {}", summary.binary_path.display())?;
    writeln!(writer, "launchd plist: {}", summary.plist_path.display())?;
    writeln!(
        writer,
        "If macOS denies NAS access, open the signed macOS app once, select the NAS folder, wait for access verification, then restart the service."
    )?;
    Ok(())
}

fn service_prime_access<W: Write>(
    args: ServicePrimeAccessArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    prime_access(
        &args.config,
        args.write_canary_dir.as_deref(),
        args.status_file.as_deref(),
        writer,
    )
}

fn prime_access<W: Write>(
    config_path: &Path,
    write_canary_dir: Option<&Path>,
    status_file: Option<&Path>,
    writer: &mut W,
) -> Result<(), CliError> {
    let result = prime_access_inner(config_path, write_canary_dir);
    if let Some(path) = status_file {
        write_prime_access_status(path, &result)?;
    }
    let report = result?;
    writeln!(writer, "macOS access prime succeeded")?;
    writeln!(writer, "config: {}", report.config_path.display())?;
    for root in &report.read_roots {
        writeln!(writer, "read ok: {}", root.display())?;
    }
    if let Some(write_dir) = &report.write_canary_dir {
        writeln!(writer, "write/read/delete ok: {}", write_dir.display())?;
    } else {
        writeln!(
            writer,
            "write/read/delete skipped: no NAS or mirror root configured"
        )?;
    }
    Ok(())
}

fn prime_access_inner(
    config_path: &Path,
    write_canary_dir: Option<&Path>,
) -> Result<ServicePrimeAccessReport, CliError> {
    let config = MonitorConfig::load(config_path)?;
    config.validate()?;
    let mut read_roots = Vec::new();
    prime_read_root(&config.download_root)?;
    read_roots.push(config.download_root.clone());
    if config.nas_root != config.download_root {
        prime_read_root(&config.nas_root)?;
        read_roots.push(config.nas_root.clone());
    }
    if let Some(mirror_root) = &config.mirror_root {
        if !read_roots.iter().any(|path| path == mirror_root) {
            prime_read_root(mirror_root)?;
            read_roots.push(mirror_root.clone());
        }
    }

    let write_dir = write_canary_dir
        .map(Path::to_path_buf)
        .or_else(|| config.mirror_root.clone())
        .or_else(|| Some(config.nas_root.clone()))
        .filter(|path| !path.as_os_str().is_empty());
    if let Some(write_dir) = &write_dir {
        prime_write_canary(write_dir)?;
    }

    Ok(ServicePrimeAccessReport {
        ok: true,
        config_path: config_path.to_path_buf(),
        read_roots,
        write_canary_dir: write_dir,
        error: None,
    })
}

fn prime_read_root(path: &Path) -> Result<(), CliError> {
    run_scan_root_preflight_probe(path).map_err(CliError::from)
}

fn prime_write_canary(dir: &Path) -> Result<(), CliError> {
    let canary = dir.join(format!(
        ".icloudpd-optimizer-access-canary-{}-{}",
        process::id(),
        current_unix_seconds_for_cli()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&canary)
            .map_err(|source| CliError::PrimeAccessIo {
                path: canary.clone(),
                source,
            })?;
        file.write_all(b"ok")
            .map_err(|source| CliError::PrimeAccessIo {
                path: canary.clone(),
                source,
            })?;
        drop(file);
        let contents = fs::read(&canary).map_err(|source| CliError::PrimeAccessIo {
            path: canary.clone(),
            source,
        })?;
        if contents != b"ok" {
            return Err(CliError::PrimeAccess {
                message: format!("canary readback mismatch at {}", canary.display()),
            });
        }
        fs::remove_file(&canary).map_err(|source| CliError::PrimeAccessIo {
            path: canary.clone(),
            source,
        })?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&canary);
    }
    result
}

fn write_prime_access_status(
    path: &Path,
    result: &Result<ServicePrimeAccessReport, CliError>,
) -> Result<(), CliError> {
    let status = match result {
        Ok(report) => report.clone(),
        Err(error) => ServicePrimeAccessReport {
            ok: false,
            config_path: PathBuf::new(),
            read_roots: Vec::new(),
            write_canary_dir: None,
            error: Some(error.to_string()),
        },
    };
    let text = serde_json::to_string_pretty(&status)?;
    fs::write(path, format!("{text}\n")).map_err(|source| CliError::PrimeAccessIo {
        path: path.to_path_buf(),
        source,
    })
}

fn current_unix_seconds_for_cli() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Debug, Serialize)]
struct ServicePrimeAccessReport {
    ok: bool,
    config_path: PathBuf,
    read_roots: Vec<PathBuf>,
    write_canary_dir: Option<PathBuf>,
    error: Option<String>,
}

fn service_start(args: ServiceStartArgs) -> Result<(), CliError> {
    let plist_path = match args.plist {
        Some(path) => path,
        None => default_plist_path(&args.label)?,
    };
    start_service(&args.label, &plist_path)?;
    Ok(())
}

fn service_stop(args: ServiceLabelArgs) -> Result<(), CliError> {
    stop_service(&args.label)?;
    Ok(())
}

fn service_status_command<W: Write>(
    args: ServiceLabelArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let output = service_status(&args.label)?;
    writer.write_all(output.stdout.as_bytes())?;
    writer.write_all(output.stderr.as_bytes())?;
    if output.status != 0 {
        return Err(ServiceError::CommandFailed {
            program: "launchctl print".to_string(),
            status: output.status,
            stderr: output.stderr,
        }
        .into());
    }
    Ok(())
}

fn service_logs<W: Write>(args: ServiceLogsArgs, writer: &mut W) -> Result<(), CliError> {
    let stdout_path = args
        .stdout
        .unwrap_or_else(|| args.config.with_extension("stdout.log"));
    let stderr_path = args
        .stderr
        .unwrap_or_else(|| args.config.with_extension("stderr.log"));
    writer.write_all(tail_logs(&stdout_path, &stderr_path, args.lines)?.as_bytes())?;
    writeln!(writer)?;
    Ok(())
}

fn service_uninstall(args: ServiceUninstallArgs) -> Result<(), CliError> {
    let plist_path = match args.plist {
        Some(path) => path,
        None => default_plist_path(&args.label)?,
    };
    uninstall_service(&args.label, &plist_path)?;
    Ok(())
}

fn monitor_scan_root_preflight(args: MonitorScanRootPreflightArgs) -> Result<(), CliError> {
    run_scan_root_preflight_probe(&args.path)?;
    Ok(())
}

#[derive(Serialize)]
struct OriginalAssetsAuditReport {
    targets: usize,
    skipped_targets: usize,
    destinations: Vec<OriginalAssetsAuditDestinationReport>,
    disposition_counts: BTreeMap<String, u64>,
    elapsed_millis: u128,
}

#[derive(Serialize)]
struct OriginalAssetsAuditDestinationReport {
    destination: CloudKitLibraryDestination,
    targets: usize,
    elapsed_millis: u128,
    inventory: Option<CloudKitOriginalAssetInventoryFingerprint>,
    resolutions: BTreeMap<String, CloudKitOriginalAssetResolution>,
    batch_error: Option<OriginalAssetsAuditBatchError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum OriginalAssetsAuditBatchError {
    Authentication,
    MalformedResponse,
    Transport,
    Transient,
}

struct OriginalAssetsAuditTarget {
    destination: CloudKitLibraryDestination,
    target: CloudKitOriginalAssetResolveTarget,
}

fn monitor_original_assets_audit<W: Write>(
    args: MonitorOriginalAssetsAuditArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let started = Instant::now();
    let config = MonitorConfig::load(&args.config)?;
    config.validate()?;
    let canonical_library_root = fs::canonicalize(&config.download_root).map_err(|source| {
        MonitorError::CanonicalizeRoot {
            path: config.download_root.clone(),
            source,
        }
    })?;
    run_scan_root_preflight_probe(&canonical_library_root)?;
    let state_store = AssetStateStore::open_read_only(&config.manifest_path)?;
    let manifest = state_store.load()?;
    let (destination_targets, skipped_targets) = original_assets_audit_targets(
        &manifest,
        &canonical_library_root,
        config.capture_tolerance_seconds,
    );
    let target_count = destination_targets.values().map(Vec::len).sum();
    let session_path =
        config
            .delete_session_path
            .as_deref()
            .ok_or(CliError::InvalidCloudKitDestination {
                message: "original-assets-audit requires delete_session_path".to_string(),
            })?;
    let destination_reports = match load_cloudkit_delete_session(session_path) {
        Ok(session) => destination_targets
            .into_iter()
            .map(|(destination, targets)| {
                original_assets_audit_destination_report(&session, destination, targets, &config)
            })
            .collect(),
        Err(error) => destination_targets
            .into_iter()
            .map(
                |(destination, targets)| OriginalAssetsAuditDestinationReport {
                    destination,
                    targets: targets.len(),
                    elapsed_millis: 0,
                    inventory: None,
                    resolutions: BTreeMap::new(),
                    batch_error: Some(original_assets_audit_batch_error(&error)),
                },
            )
            .collect(),
    };
    let mut report = OriginalAssetsAuditReport {
        targets: target_count,
        skipped_targets,
        destinations: destination_reports,
        disposition_counts: BTreeMap::new(),
        elapsed_millis: started.elapsed().as_millis(),
    };
    report.disposition_counts = original_assets_audit_disposition_counts(&report.destinations);
    serde_json::to_writer_pretty(&mut *writer, &report)?;
    writeln!(writer)?;
    eprintln!(
        "{}",
        original_assets_audit_human_summary(
            report.targets,
            report.skipped_targets,
            &report.destinations,
            report.elapsed_millis,
        )
    );
    Ok(())
}

fn original_assets_audit_destination_report(
    session: &crate::upload::CloudKitDeleteSession,
    destination: CloudKitLibraryDestination,
    targets: Vec<CloudKitOriginalAssetResolveTarget>,
    config: &MonitorConfig,
) -> OriginalAssetsAuditDestinationReport {
    let started = Instant::now();
    let result = ReqwestCloudKitReadTransport::new().and_then(|transport| {
        resolve_original_assets_audit_destination(
            session,
            &destination,
            &targets,
            config,
            transport,
        )
    });
    original_assets_audit_destination_report_from_result(
        destination,
        targets.len(),
        started,
        result,
    )
}

#[cfg(test)]
fn original_assets_audit_destination_report_with_transport<
    T: CloudKitOriginalAssetReadTransport,
>(
    session: &crate::upload::CloudKitDeleteSession,
    destination: CloudKitLibraryDestination,
    targets: Vec<CloudKitOriginalAssetResolveTarget>,
    config: &MonitorConfig,
    transport: T,
) -> OriginalAssetsAuditDestinationReport {
    let started = Instant::now();
    let result = resolve_original_assets_audit_destination(
        session,
        &destination,
        &targets,
        config,
        transport,
    );
    original_assets_audit_destination_report_from_result(
        destination,
        targets.len(),
        started,
        result,
    )
}

fn resolve_original_assets_audit_destination<T: CloudKitOriginalAssetReadTransport>(
    session: &crate::upload::CloudKitDeleteSession,
    destination: &CloudKitLibraryDestination,
    targets: &[CloudKitOriginalAssetResolveTarget],
    config: &MonitorConfig,
    transport: T,
) -> Result<CloudKitOriginalAssetBatchResolveOutcome, UploadError> {
    let mut destination_session = session.clone();
    destination_session.database_scope = destination.database_scope;
    destination_session.zone = destination.clone();
    let mut client = CloudKitDeleteClient::new(transport);
    client.resolve_original_assets_batch_outcome(
        &destination_session,
        &CloudKitOriginalAssetBatchResolveRequest {
            targets: targets.to_vec(),
            start_rank: config.cloudkit_start_rank,
            page_size: config.cloudkit_page_size,
            max_pages: config.cloudkit_max_pages,
        },
    )
}

fn original_assets_audit_destination_report_from_result(
    destination: CloudKitLibraryDestination,
    targets: usize,
    started: Instant,
    result: Result<CloudKitOriginalAssetBatchResolveOutcome, UploadError>,
) -> OriginalAssetsAuditDestinationReport {
    match result {
        Ok(outcome) => {
            let inventory = outcome.inventory.clone();
            OriginalAssetsAuditDestinationReport {
                destination,
                targets,
                elapsed_millis: started.elapsed().as_millis(),
                inventory,
                resolutions: redact_audit_resolutions(outcome),
                batch_error: None,
            }
        }
        Err(error) => OriginalAssetsAuditDestinationReport {
            destination,
            targets,
            elapsed_millis: started.elapsed().as_millis(),
            inventory: None,
            resolutions: BTreeMap::new(),
            batch_error: Some(original_assets_audit_batch_error(&error)),
        },
    }
}

fn original_assets_audit_targets(
    manifest: &Manifest,
    canonical_library_root: &Path,
    capture_tolerance_seconds: u64,
) -> (
    BTreeMap<CloudKitLibraryDestination, Vec<CloudKitOriginalAssetResolveTarget>>,
    usize,
) {
    let mut targets = BTreeMap::new();
    let mut skipped = 0_usize;
    for record in manifest.records().values() {
        if !original_assets_audit_eligible(record) {
            continue;
        }
        let Some(target) =
            original_assets_audit_target(record, canonical_library_root, capture_tolerance_seconds)
        else {
            skipped = skipped.saturating_add(1);
            continue;
        };
        targets
            .entry(target.destination)
            .or_insert_with(Vec::new)
            .push(target.target);
    }
    (targets, skipped)
}

fn original_assets_audit_eligible(record: &AssetRecord) -> bool {
    let failed_original_resolution = record.state == State::Failed
        && record
            .failures
            .last()
            .is_some_and(|failure| failure.stage == "original_asset_resolve");
    let missing_original = matches!(
        record.state,
        State::NasVerified | State::Converted | State::ConversionVerified | State::UploadVerified
    ) && !record.proofs.contains_key("original_asset");
    failed_original_resolution || missing_original
}

fn original_assets_audit_target(
    record: &AssetRecord,
    canonical_library_root: &Path,
    capture_tolerance_seconds: u64,
) -> Option<OriginalAssetsAuditTarget> {
    let nas = serde_json::from_value::<NasRawProof>(record.proofs.get("nas")?.clone()).ok()?;
    let source_age =
        serde_json::from_value::<SourceAgeProof>(record.proofs.get("source_age")?.clone()).ok()?;
    let canonical_raw_path = fs::canonicalize(&record.raw_path).ok()?;
    let relative_raw_path = canonical_raw_path
        .strip_prefix(canonical_library_root)
        .ok()?;
    let destination = original_assets_audit_destination(relative_raw_path)?;
    let filename = canonical_raw_path.file_name()?.to_str()?.to_string();
    Some(OriginalAssetsAuditTarget {
        destination,
        target: CloudKitOriginalAssetResolveTarget {
            asset_id: record.asset_id.clone(),
            raw_size_bytes: nas.size_bytes,
            source_captured_unix_seconds: source_age.source_captured_unix_seconds,
            capture_tolerance_seconds,
            filename,
            matched_raw_sha256: nas.sha256,
            replacement_candidate: original_assets_audit_replacement_candidate(
                canonical_library_root,
                relative_raw_path,
                &record.asset_id,
            ),
        },
    })
}

fn original_assets_audit_destination(
    relative_raw_path: &Path,
) -> Option<CloudKitLibraryDestination> {
    let Component::Normal(component) = relative_raw_path.components().next()? else {
        return None;
    };
    let library = component.to_str()?;
    if library == "PrimarySync" {
        return Some(CloudKitLibraryDestination::primary_sync());
    }
    library
        .starts_with("SharedSync-")
        .then(|| CloudKitLibraryDestination {
            database_scope: CloudKitDatabaseScope::Shared,
            zone_name: library.to_string(),
        })
}

fn original_assets_audit_replacement_candidate(
    canonical_library_root: &Path,
    relative_raw_path: &Path,
    asset_id: &str,
) -> Option<CloudKitLocalReplacementCandidate> {
    if asset_id.is_empty() || asset_id == "." || asset_id == ".." || asset_id.contains(['/', '\\'])
    {
        return None;
    }
    let candidate = canonical_library_root
        .join(relative_raw_path.parent()?)
        .join(format!("{asset_id}.HEIC"));
    let canonical_candidate = fs::canonicalize(candidate).ok()?;
    if !canonical_candidate.starts_with(canonical_library_root) || !canonical_candidate.is_file() {
        return None;
    }
    let candidate = hash_stable_file(&canonical_candidate).ok()?;
    (candidate.size_bytes > 0).then_some(candidate)
}

fn hash_stable_file(path: &Path) -> io::Result<CloudKitLocalReplacementCandidate> {
    hash_stable_file_with_before_hash(path, || {})
}

fn hash_stable_file_with_before_hash(
    path: &Path,
    before_hash: impl FnOnce(),
) -> io::Result<CloudKitLocalReplacementCandidate> {
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    before_hash();
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    let after = file.metadata()?;
    if !same_file_handle_metadata(&before, &after)
        || !canonical_path_still_points_to_open_file(path, &after)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "local replacement changed while hashing",
        ));
    }
    Ok(CloudKitLocalReplacementCandidate {
        sha256: format!("{:x}", hasher.finalize()),
        size_bytes: after.len(),
    })
}

fn same_file_handle_metadata(before: &Metadata, after: &Metadata) -> bool {
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return false;
    }
    #[cfg(unix)]
    {
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn canonical_path_still_points_to_open_file(path: &Path, open_file: &Metadata) -> bool {
    let Ok(final_path) = fs::canonicalize(path) else {
        return false;
    };
    if final_path != path {
        return false;
    }
    let Ok(final_metadata) = fs::metadata(final_path) else {
        return false;
    };
    #[cfg(unix)]
    {
        open_file.dev() == final_metadata.dev() && open_file.ino() == final_metadata.ino()
    }
    #[cfg(not(unix))]
    {
        same_file_handle_metadata(open_file, &final_metadata)
    }
}

fn redact_audit_resolutions(
    outcome: CloudKitOriginalAssetBatchResolveOutcome,
) -> BTreeMap<String, CloudKitOriginalAssetResolution> {
    outcome
        .resolutions
        .into_iter()
        .map(|(asset_id, resolution)| (compact_audit_asset_id(&asset_id), resolution))
        .collect()
}

fn compact_audit_asset_id(asset_id: &str) -> String {
    let digest = Sha256::digest(asset_id.as_bytes());
    format!(
        "asset-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5]
    )
}

fn original_assets_audit_batch_error(error: &UploadError) -> OriginalAssetsAuditBatchError {
    match error {
        UploadError::InvalidSession(_) | UploadError::DecodeSession { .. } => {
            OriginalAssetsAuditBatchError::Authentication
        }
        UploadError::MalformedCloudKitResponse { .. }
        | UploadError::InvalidCloudKitOriginalAssetResponse(_) => {
            OriginalAssetsAuditBatchError::MalformedResponse
        }
        UploadError::Network { .. }
        | UploadError::HttpClient { .. }
        | UploadError::UploadHttpStatus { .. }
        | UploadError::ReadUploadResponse { .. } => OriginalAssetsAuditBatchError::Transport,
        _ => OriginalAssetsAuditBatchError::Transient,
    }
}

fn original_assets_audit_disposition_counts(
    reports: &[OriginalAssetsAuditDestinationReport],
) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for resolution in reports
        .iter()
        .flat_map(|report| report.resolutions.values())
    {
        let disposition = match &resolution.disposition {
            CloudKitOriginalAssetResolveDisposition::ExactOriginal { .. } => "exact_original",
            CloudKitOriginalAssetResolveDisposition::ReplacementPresent { .. } => {
                "replacement_present"
            }
            CloudKitOriginalAssetResolveDisposition::NoDateCandidate => "no_date_candidate",
            CloudKitOriginalAssetResolveDisposition::NoRawResource => "no_raw_resource",
            CloudKitOriginalAssetResolveDisposition::RawSizeMismatch => "raw_size_mismatch",
            CloudKitOriginalAssetResolveDisposition::RawHashMismatch => "raw_hash_mismatch",
            CloudKitOriginalAssetResolveDisposition::Ambiguous => "ambiguous",
            CloudKitOriginalAssetResolveDisposition::IncompleteTransient => "incomplete_transient",
        };
        *counts.entry(disposition.to_string()).or_default() += 1;
    }
    counts
}

fn original_assets_audit_human_summary(
    targets: usize,
    skipped_targets: usize,
    reports: &[OriginalAssetsAuditDestinationReport],
    elapsed_millis: u128,
) -> String {
    let counts = original_assets_audit_disposition_counts(reports);
    let dispositions = if counts.is_empty() {
        "none".to_string()
    } else {
        counts
            .into_iter()
            .map(|(disposition, count)| format!("{disposition}={count}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    let destination_timings = if reports.is_empty() {
        "none".to_string()
    } else {
        reports
            .iter()
            .map(|report| {
                format!(
                    "{}:{}={}ms",
                    report.destination.database_scope.as_str(),
                    report.destination.zone_name,
                    report.elapsed_millis,
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    };
    format!(
        "original-assets-audit: targets={targets} skipped={skipped_targets} dispositions={dispositions} destination_timings={destination_timings} elapsed_ms={elapsed_millis}"
    )
}

fn monitor_init(args: MonitorInitArgs) -> Result<(), CliError> {
    if args.config.exists() && !args.force {
        return Err(CliError::ConfigAlreadyExists { path: args.config });
    }
    let mut config = MonitorConfig::new(args.download_root, args.manifest, args.heic_output_dir);
    if let Some(nas_root) = args.nas_root {
        config.nas_root = nas_root;
    }
    if let Some(stats_path) = args.stats {
        config.stats_path = stats_path;
    }
    config.min_age_days = args.min_age_days;
    config.scan_interval_seconds = args.scan_interval_seconds;
    config.jobs = args.jobs;
    config.rolling_worker_count = args.rolling_worker_count;
    config.rolling_convert_stage_count = args.rolling_convert_stage_count;
    config.heic_quality = args.heic_quality;
    config.max_conversions_per_scan = args.max_conversions_per_scan;
    config.scan_recursive = !args.no_recursive_scan;
    config.conversion_tool_version = args.conversion_tool_version;
    config.full_lifecycle = args.full_lifecycle;
    config.rolling_lifecycle = args.rolling_lifecycle;
    config.auto_delete = args.auto_delete;
    config.upload_session_path = args.upload_session;
    config.delete_session_path = args.delete_session;
    config.mirror_root = args.mirror_root;
    config.delete_operator = args.delete_operator;
    config.max_lifecycle_per_scan = args.max_lifecycle_per_scan;
    config.max_original_resolver_retries_per_scan = args.max_original_resolver_retries_per_scan;
    config.original_resolver_retry_min_age_seconds = args.original_resolver_retry_min_age_seconds;
    config.capture_tolerance_seconds = args.capture_tolerance_seconds;
    config.cloudkit_start_rank = args.cloudkit_start_rank;
    config.cloudkit_page_size = args.cloudkit_page_size;
    config.cloudkit_max_pages = args.cloudkit_max_pages;
    config.scan_root_preflight_timeout_seconds = args.scan_root_preflight_timeout_seconds;
    config.local_mirror_timeout_seconds = args.local_mirror_timeout_seconds;
    config.upload_timeout_seconds = args.upload_timeout_seconds;
    config.heic_verify_timeout_seconds = args.heic_verify_timeout_seconds;
    config.rolling_original_resolve_active_window_multiplier =
        args.rolling_original_resolve_active_window_multiplier;
    config.rolling_original_resolve_batch_multiplier =
        args.rolling_original_resolve_batch_multiplier;
    config.validate()?;
    config.save_atomic(args.config)?;
    Ok(())
}

fn monitor_run<W: Write>(args: MonitorRunArgs, writer: &mut W) -> Result<(), CliError> {
    let config = MonitorConfig::load(&args.config)?;
    config.validate()?;
    let mut guard = acquire_monitor_run_guard(&config)?;
    loop {
        match run_monitor_once(&config, &mut guard) {
            Ok(summary) => write_scan_summary(writer, &summary)?,
            Err(error) if args.once => {
                log_monitor_failure_event(&error);
                return Err(error.into());
            }
            Err(error) => {
                log_monitor_failure_event(&error);
                eprintln!("monitor failed: {error}");
            }
        }
        if args.once {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(config.scan_interval_seconds));
    }
}

fn write_scan_summary<W: Write>(
    writer: &mut W,
    summary: &MonitorScanSummary,
) -> Result<(), CliError> {
    serde_json::to_writer(&mut *writer, summary)?;
    writeln!(writer)?;
    writer.flush()?;
    Ok(())
}

fn monitor_stats<W: Write>(args: MonitorStatsArgs, writer: &mut W) -> Result<(), CliError> {
    let config = MonitorConfig::load(&args.config)?;
    let stats = MonitorStats::load(&config.stats_path)?;
    let manifest = load_manifest_for_write(&config.manifest_path)?;
    let verified_metrics = VerifiedMetrics::from_manifest(&manifest);
    let report = MonitorStatsReport {
        stats: stats_with_verified_metrics(stats, &verified_metrics),
        verified_metrics,
    };
    if args.json {
        serde_json::to_writer_pretty(&mut *writer, &report)?;
        writeln!(writer)?;
    } else {
        write!(
            writer,
            "{}\n{}",
            render_tui(&config, &report.stats),
            render_verified_metrics(&report.verified_metrics)
        )?;
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct MonitorStatsReport {
    stats: MonitorStats,
    verified_metrics: VerifiedMetrics,
}

fn stats_with_verified_metrics(mut stats: MonitorStats, metrics: &VerifiedMetrics) -> MonitorStats {
    stats.uploads_completed = metrics.uploaded_replacements;
    stats.originals_deleted = metrics.deleted_originals;
    stats.uploaded_heic_bytes = metrics.uploaded_heic_bytes;
    stats.deleted_raw_bytes = metrics.deleted_raw_bytes;
    stats.bytes_saved = metrics.verified_bytes_saved;
    stats.state_counts = metrics.state_counts.clone();
    stats
}

fn monitor_queue<W: Write>(args: MonitorQueueArgs, writer: &mut W) -> Result<(), CliError> {
    let config = MonitorConfig::load(&args.config)?;
    let manifest = load_manifest_for_write(&config.manifest_path)?;
    let report = MonitorQueueReport::from_manifest(&config, &manifest, args.chunks);
    if args.json {
        serde_json::to_writer_pretty(&mut *writer, &report)?;
        writeln!(writer)?;
    } else {
        writer.write_all(render_queue_report(&report).as_bytes())?;
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct MonitorQueueReport {
    configured_mode: &'static str,
    rolling_lifecycle: bool,
    jobs: usize,
    rolling_worker_count: usize,
    cpu_stage_slots: usize,
    convert_stage_slots: usize,
    max_lifecycle_per_scan: usize,
    max_original_resolver_retries_per_scan: usize,
    original_resolver_retry_min_age_seconds: u64,
    max_conversions_per_scan: usize,
    state_counts: BTreeMap<String, u64>,
    queue_counts: BTreeMap<String, u64>,
    failure_counts: BTreeMap<String, u64>,
    verified_metrics: VerifiedMetrics,
    active_lifecycle: Vec<QueueAsset>,
    worker_slots: Vec<QueueWorkerSlot>,
}

impl MonitorQueueReport {
    fn from_manifest(config: &MonitorConfig, manifest: &Manifest, chunk_limit: usize) -> Self {
        let active_lifecycle = queue_active_lifecycle_assets(config, manifest);
        let worker_slots = queue_worker_slots(config, &active_lifecycle, chunk_limit);
        let verified_metrics = VerifiedMetrics::from_manifest(manifest);
        let available_parallelism = std::thread::available_parallelism()
            .map(|parallelism| parallelism.get())
            .unwrap_or(1);
        let cpu_stage_slots =
            crate::monitor::rolling_lifecycle_cpu_stage_jobs(config, available_parallelism);
        let convert_stage_slots =
            crate::monitor::rolling_lifecycle_convert_stage_jobs(config, cpu_stage_slots);
        Self {
            configured_mode: if config.rolling_lifecycle {
                "rolling"
            } else {
                "phase"
            },
            rolling_lifecycle: config.rolling_lifecycle,
            jobs: config.jobs,
            rolling_worker_count: crate::monitor::rolling_lifecycle_configured_worker_count(config),
            cpu_stage_slots,
            convert_stage_slots,
            max_lifecycle_per_scan: config.max_lifecycle_per_scan,
            max_original_resolver_retries_per_scan: config.max_original_resolver_retries_per_scan,
            original_resolver_retry_min_age_seconds: config.original_resolver_retry_min_age_seconds,
            max_conversions_per_scan: config.max_conversions_per_scan,
            state_counts: verified_metrics.state_counts.clone(),
            queue_counts: queue_counts(manifest, config, &active_lifecycle),
            failure_counts: queue_failure_counts(manifest),
            verified_metrics,
            active_lifecycle,
            worker_slots,
        }
    }
}

#[derive(Debug, Serialize)]
struct QueueAsset {
    asset_id: String,
    state: String,
    next_stage: &'static str,
    raw_size_bytes: u64,
}

#[derive(Debug, Serialize)]
struct QueueWorkerSlot {
    worker_id: usize,
    first_asset_id: String,
    next_stage: &'static str,
    stages: Vec<&'static str>,
}

fn queue_counts(
    manifest: &Manifest,
    config: &MonitorConfig,
    active_lifecycle: &[QueueAsset],
) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    counts.insert(
        "active_lifecycle".to_string(),
        active_lifecycle.len() as u64,
    );
    for record in manifest.records().values() {
        match queue_next_stage(record, config) {
            "none" => {}
            stage => increment_count(&mut counts, stage),
        }
    }
    counts
}

fn queue_failure_counts(manifest: &Manifest) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for record in manifest.records().values() {
        if record.state != State::Failed {
            continue;
        }
        let message = record
            .failures
            .last()
            .map(|failure| failure.message.as_str())
            .unwrap_or("");
        let bucket = if message.contains("CloudKit original asset resolver found no exact RAW") {
            "blocked_original_asset_resolve"
        } else if message.contains("heif-enc") && message.contains("timed out") {
            "retryable_conversion_timeout"
        } else if message.contains("raw_staging") && message.contains("timed out") {
            "retryable_raw_staging_timeout"
        } else if message.contains("converted output already exists")
            || message.contains("failed to read verified HEIC")
            || message.contains("verified HEIC is empty")
            || message.contains("HEIC size mismatch")
            || message.contains("HEIC SHA-256 mismatch")
        {
            "retryable_stale_heic_output"
        } else if message.contains("staged RAW already exists") {
            "retryable_stale_staged_raw"
        } else if message.contains("visual_content_ok") {
            "blocked_visual_content"
        } else if message.contains("neither PreviewImage nor JpgFromRaw") {
            "blocked_missing_embedded_preview"
        } else {
            "failed_other"
        };
        increment_count(&mut counts, bucket);
    }
    counts
}

fn increment_count(counts: &mut BTreeMap<String, u64>, key: &str) {
    *counts.entry(key.to_string()).or_default() += 1;
}

fn queue_active_lifecycle_assets(config: &MonitorConfig, manifest: &Manifest) -> Vec<QueueAsset> {
    crate::monitor::active_lifecycle_asset_ids_for_config(config, manifest)
        .into_iter()
        .filter_map(|asset_id| manifest.records().get(&asset_id))
        .map(|record| queue_asset(record, "continue_lifecycle"))
        .collect()
}

fn queue_worker_slots(
    config: &MonitorConfig,
    active_lifecycle: &[QueueAsset],
    slot_limit: usize,
) -> Vec<QueueWorkerSlot> {
    active_lifecycle
        .iter()
        .filter(|asset| !matches!(asset.next_stage, "delete_original_assets"))
        .take(crate::monitor::rolling_lifecycle_configured_worker_count(
            config,
        ))
        .take(slot_limit)
        .enumerate()
        .map(|(index, asset)| QueueWorkerSlot {
            worker_id: index + 1,
            first_asset_id: asset.asset_id.clone(),
            next_stage: asset.next_stage,
            stages: queue_rolling_asset_stage_sequence(asset.next_stage, config.auto_delete),
        })
        .collect()
}

fn queue_rolling_asset_stage_sequence(
    next_stage: &'static str,
    _auto_delete: bool,
) -> Vec<&'static str> {
    let full_sequence = [
        "resolve_original_assets",
        "convert_heic",
        "verify_converted_heics",
        "upload_verified_heics",
        "record_local_mirrors",
    ];
    full_sequence
        .iter()
        .position(|stage| *stage == next_stage)
        .map(|index| full_sequence[index..].to_vec())
        .unwrap_or_else(|| vec![next_stage])
}

fn queue_asset(record: &AssetRecord, fallback_stage: &'static str) -> QueueAsset {
    QueueAsset {
        asset_id: record.asset_id.clone(),
        state: record.state.as_str().to_string(),
        next_stage: queue_next_stage_for_record(record).unwrap_or(fallback_stage),
        raw_size_bytes: queue_raw_size_bytes(record),
    }
}

fn queue_next_stage(record: &AssetRecord, config: &MonitorConfig) -> &'static str {
    if !config.full_lifecycle {
        return match record.state {
            State::NasVerified => "convert_heic",
            State::Converted => "verify_converted_heics",
            _ => "none",
        };
    }
    queue_next_stage_for_record(record).unwrap_or("none")
}

fn queue_next_stage_for_record(record: &AssetRecord) -> Option<&'static str> {
    match record.state {
        State::DeleteApproved => Some("delete_original_assets"),
        State::DeleteEligible => Some("delete_original_assets"),
        State::UploadVerified if record.proofs.contains_key("icloudpd_local_mirror") => {
            Some("delete_original_assets")
        }
        State::UploadVerified => Some("record_local_mirrors"),
        State::ConversionVerified if record.proofs.contains_key("original_asset") => {
            Some("upload_verified_heics")
        }
        State::ConversionVerified => Some("resolve_original_assets"),
        State::Converted
            if record.proofs.contains_key("heic")
                && record.proofs.contains_key("original_asset") =>
        {
            Some("upload_verified_heics")
        }
        State::Converted if record.proofs.contains_key("heic") => Some("resolve_original_assets"),
        State::Converted => Some("verify_converted_heics"),
        State::NasVerified if record.proofs.contains_key("original_asset") => Some("convert_heic"),
        State::NasVerified => Some("resolve_original_assets"),
        _ => None,
    }
}

fn queue_raw_size_bytes(record: &AssetRecord) -> u64 {
    record
        .proofs
        .get("nas")
        .and_then(|proof| proof.get("size_bytes"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

fn render_queue_report(report: &MonitorQueueReport) -> String {
    let mut output = String::new();
    output.push_str("monitor queue\n");
    output.push_str(&format!(
        "mode: {} | rolling_lifecycle={} | jobs={} | worker_slots={} | cpu_slots={} | convert_slots={} | lifecycle_cap={} | conversion_cap={}\n",
        report.configured_mode,
        report.rolling_lifecycle,
        report.jobs,
        report.rolling_worker_count,
        report.cpu_stage_slots,
        report.convert_stage_slots,
        report.max_lifecycle_per_scan,
        report.max_conversions_per_scan
    ));
    output.push_str("\nstates\n");
    append_counts(&mut output, &report.state_counts);
    output.push_str("\nqueue\n");
    append_counts(&mut output, &report.queue_counts);
    output.push_str("\nfailures\n");
    append_counts(&mut output, &report.failure_counts);
    output.push_str("\nactive lifecycle\n");
    for asset in report.active_lifecycle.iter().take(20) {
        output.push_str(&format!(
            "- {} | state={} | next={} | raw={}\n",
            asset.asset_id, asset.state, asset.next_stage, asset.raw_size_bytes
        ));
    }
    if report.active_lifecycle.len() > 20 {
        output.push_str(&format!(
            "- ... {} more active assets\n",
            report.active_lifecycle.len().saturating_sub(20)
        ));
    }
    output.push_str("\nrolling worker slots\n");
    if report.worker_slots.is_empty() {
        output.push_str("- none\n");
    } else {
        for slot in &report.worker_slots {
            output.push_str(&format!(
                "- worker {} | first_asset={} | next={} | stages={}\n",
                slot.worker_id,
                slot.first_asset_id,
                slot.next_stage,
                slot.stages.join(" -> ")
            ));
        }
    }
    output
}

fn append_counts(output: &mut String, counts: &BTreeMap<String, u64>) {
    if counts.is_empty() {
        output.push_str("- none\n");
        return;
    }
    for (key, count) in counts {
        output.push_str(&format!("- {key}: {count}\n"));
    }
}

fn render_verified_metrics(metrics: &VerifiedMetrics) -> String {
    format!(
        "verified manifest metrics\n\
         uploaded replacements: {}\n\
         uploaded HEIC bytes: {}\n\
         uploaded size proofs complete: {}\n\
         uploaded records missing size proofs: {}\n\
         deleted originals: {}\n\
         deleted RAW bytes: {}\n\
         deleted replacement HEIC bytes: {}\n\
         verified bytes saved: {}\n\
         size proofs complete: {}\n\
         deleted records missing size proofs: {}\n",
        metrics.uploaded_replacements,
        metrics.uploaded_heic_bytes,
        metrics.uploaded_size_metrics_complete,
        metrics.uploaded_records_missing_size_proofs,
        metrics.deleted_originals,
        metrics.deleted_raw_bytes,
        metrics.deleted_replacement_heic_bytes,
        metrics.verified_bytes_saved,
        metrics.deleted_size_metrics_complete,
        metrics.deleted_records_missing_size_proofs
    )
}

fn monitor_tui<W: Write>(args: MonitorTuiArgs, writer: &mut W) -> Result<(), CliError> {
    let config = MonitorConfig::load(&args.config)?;
    loop {
        let stats = MonitorStats::load(&config.stats_path)?;
        write!(writer, "\x1b[2J\x1b[H{}", render_tui(&config, &stats))?;
        writer.flush()?;
        if args.once {
            return Ok(());
        }
        thread::sleep(Duration::from_secs(args.refresh_seconds.max(1)));
    }
}

fn monitor_launchd_plist<W: Write>(
    args: MonitorLaunchdPlistArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let binary = match args.bin {
        Some(path) => path,
        None => env::current_exe()?,
    };
    let stdout_path = args
        .stdout
        .unwrap_or_else(|| args.config.with_extension("stdout.log"));
    let stderr_path = args
        .stderr
        .unwrap_or_else(|| args.config.with_extension("stderr.log"));
    if let Some(output) = args.output {
        write_launchd_plist(
            &args.label,
            &binary,
            &args.config,
            &stdout_path,
            &stderr_path,
            &output,
            args.associated_bundle_id.as_deref(),
        )?;
    } else {
        writer.write_all(
            launchd_plist(
                &args.label,
                &binary,
                &args.config,
                &stdout_path,
                &stderr_path,
                args.associated_bundle_id.as_deref(),
            )?
            .as_bytes(),
        )?;
    }
    Ok(())
}

fn workflow_nas_verified(args: WorkflowNasVerifiedArgs) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    let now = SystemTime::now();
    prove_and_record_nas(
        &mut manifest,
        &args.asset_id,
        &args.raw_path,
        &args.nas_root,
        args.min_age_days,
        now,
    )?;
    if let Some(source_captured_unix_seconds) = args.source_captured_unix_seconds {
        record_source_age_proof(
            &mut manifest,
            &args.asset_id,
            SourceAgeProof {
                source_captured_unix_seconds,
                verified_at_unix_seconds: system_time_unix_seconds(now),
                min_age_seconds: args.min_age_days.saturating_mul(DAY_SECONDS),
            },
        )?;
    }
    save_manifest(&manifest, &args.manifest)
}

fn workflow_convert(args: WorkflowConvertArgs) -> Result<(), CliError> {
    let manifest = load_manifest_for_write(&args.manifest)?;
    let updated = execute_measured_conversion(
        &manifest,
        ConversionExecutionRequest {
            asset_id: args.asset_id,
            output_path: args.output_path,
            heic_quality: args.heic_quality,
            conversion_tool_version: args.conversion_tool_version,
        },
    )?;
    save_manifest(&updated, &args.manifest)
}

fn workflow_convert_batch(args: WorkflowConvertBatchArgs) -> Result<(), CliError> {
    let manifest = load_manifest_for_write(&args.manifest)?;
    let asset_ids = convert_batch_target_asset_ids(&manifest, &args.asset_id);
    if asset_ids.is_empty() {
        return Err(ConversionExecutionError::EmptyBatch.into());
    }
    let requests = asset_ids
        .into_iter()
        .map(|asset_id| {
            let output_path = convert_batch_output_path(&args.output_dir, &asset_id)?;
            Ok(ConversionExecutionRequest {
                asset_id,
                output_path,
                heic_quality: args.heic_quality,
                conversion_tool_version: args.conversion_tool_version.clone(),
            })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let updated = execute_measured_conversions(&manifest, requests, args.jobs)?;
    save_manifest(&updated, &args.manifest)
}

fn workflow_conversion_result(args: WorkflowConversionResultArgs) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    record_conversion_result(
        &mut manifest,
        &args.asset_id,
        ConversionResultProof {
            heic_path: args.heic_path,
            heic_sha256: args.heic_sha256,
            size_bytes: args.size_bytes,
        },
    )?;
    save_manifest(&manifest, &args.manifest)
}

fn workflow_conversion_performance(
    args: WorkflowConversionPerformanceArgs,
) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    record_conversion_performance(
        &mut manifest,
        &args.asset_id,
        ConversionPerformanceInput {
            measured_at_unix_seconds: args
                .measured_at_unix_seconds
                .unwrap_or_else(|| system_time_unix_seconds(SystemTime::now())),
            conversion_tool: args.conversion_tool,
            conversion_tool_version: args.conversion_tool_version,
            heic_quality: args.heic_quality,
            convert_wall_time_millis: args.convert_wall_time_millis,
            total_wall_time_millis: args.total_wall_time_millis,
            user_cpu_time_millis: args.user_cpu_time_millis,
            system_cpu_time_millis: args.system_cpu_time_millis,
            peak_rss_kib: args.peak_rss_kib,
            conversion_command_timings: Vec::new(),
        },
    )?;
    save_manifest(&manifest, &args.manifest)
}

fn workflow_heic_verified(args: WorkflowHeicVerifiedArgs) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    record_heic_verification(
        &mut manifest,
        &args.asset_id,
        HeicVerificationProof {
            heic_path: args.heic_path,
            heic_sha256: args.heic_sha256,
            size_bytes: args.size_bytes,
            heif_info_ok: args.heif_info_ok,
            metadata_copied: args.metadata_copied,
            visual_content_ok: args.visual_content_ok,
            visual_match_ok: args.visual_match_ok,
            visual_rmse_ppm: None,
            visual_mae_ppm: None,
        },
    )?;
    save_manifest(&manifest, &args.manifest)
}

fn workflow_upload_heic(args: WorkflowUploadHeicArgs) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    let heic = upload_ready_heic_proof(&manifest, &args.asset_id)?;
    verify_local_heic(&heic)?;
    load_upload_session(&args.session)?;
    let destination = upload_destination_for_asset(&manifest, &args.asset_id)?;
    let response = run_icloud_upload(&IcloudUploadRequest {
        session_path: args.session,
        heic_path: heic.heic_path.clone(),
        destination,
    })?;
    let proof = build_upload_proof(&heic, &response)?;
    record_upload_proof(&mut manifest, &args.asset_id, proof)?;
    save_manifest(&manifest, &args.manifest)
}

fn workflow_upload_heic_proof<W: Write>(
    args: WorkflowUploadHeicArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let manifest = load_manifest_for_write(&args.manifest)?;
    let heic = upload_ready_heic_proof(&manifest, &args.asset_id)?;
    verify_local_heic(&heic)?;
    load_upload_session(&args.session)?;
    let destination = upload_destination_for_asset(&manifest, &args.asset_id)?;
    let response = run_icloud_upload(&IcloudUploadRequest {
        session_path: args.session,
        heic_path: heic.heic_path.clone(),
        destination,
    })?;
    let proof = build_upload_proof(&heic, &response)?;
    write_upload_proof_output(writer, &proof, &response.timings)
}

fn workflow_upload_heic_proof_direct<W: Write>(
    args: WorkflowUploadHeicProofDirectArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    if args.asset_id.trim().is_empty() {
        return Err(WorkflowError::EmptyProofField { field: "asset_id" }.into());
    }
    let heic = HeicVerificationProof {
        heic_path: args.heic_path,
        heic_sha256: args.heic_sha256,
        size_bytes: args.size_bytes,
        heif_info_ok: true,
        metadata_copied: true,
        visual_content_ok: true,
        visual_match_ok: true,
        visual_rmse_ppm: None,
        visual_mae_ppm: None,
    };
    verify_local_heic(&heic)?;
    load_upload_session(&args.session)?;
    let destination = validate_cli_library_destination(CloudKitLibraryDestination {
        database_scope: args.database_scope.into(),
        zone_name: args.zone_name,
    })?;
    let response = run_icloud_upload(&IcloudUploadRequest {
        session_path: args.session,
        heic_path: heic.heic_path.clone(),
        destination,
    })?;
    let proof = build_upload_proof(&heic, &response)?;
    write_upload_proof_output(writer, &proof, &response.timings)
}

fn write_upload_proof_output<W: Write>(
    writer: &mut W,
    proof: &UploadProof,
    timings: &crate::upload::UploadTimings,
) -> Result<(), CliError> {
    let mut output = serde_json::to_value(proof)?;
    if let serde_json::Value::Object(ref mut object) = output {
        object.insert("upload_timings".to_string(), serde_json::to_value(timings)?);
    }
    serde_json::to_writer_pretty(&mut *writer, &output)?;
    writeln!(writer)?;
    Ok(())
}

fn upload_destination_for_asset(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<CloudKitLibraryDestination, CliError> {
    let record = manifest.get(asset_id).map_err(WorkflowError::Manifest)?;
    let original: OriginalAssetProof = decode_workflow_proof(record, "original_asset")?;
    let destination = CloudKitLibraryDestination {
        database_scope: original.database_scope,
        zone_name: original.zone_name,
    };
    validate_cli_library_destination(destination)
}

fn workflow_upload_verified(args: WorkflowUploadVerifiedArgs) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    let destination = cli_library_destination(
        args.database_scope,
        args.zone_name,
        optional_original_destination_for_asset(&manifest, &args.asset_id)?,
    )?;
    record_upload_proof(
        &mut manifest,
        &args.asset_id,
        UploadProof {
            uploaded_heic_asset_id: args.uploaded_heic_asset_id,
            uploaded_heic_sha256: args.uploaded_heic_sha256,
            database_scope: destination.database_scope,
            zone_name: destination.zone_name,
            uploaded_heic_path: args.uploaded_heic_path,
        },
    )?;
    save_manifest(&manifest, &args.manifest)
}

fn workflow_uploaded_heic_delete_plan<W: Write>(
    args: WorkflowDeleteUploadedHeicArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let manifest = load_manifest_for_write(&args.manifest)?;
    let request = uploaded_heic_delete_request(&manifest, &args.asset_id)?;
    let session = load_cloudkit_delete_session(&args.session)?;
    let transport = ReqwestCloudKitDeleteTransport::new()?;
    let mut client = CloudKitDeleteClient::new(transport);
    let resolved = client.resolve_uploaded_heic_asset(&session, &request)?;
    serde_json::to_writer_pretty(&mut *writer, &resolved)?;
    writeln!(writer)?;
    Ok(())
}

fn workflow_delete_uploaded_heic(args: WorkflowDeleteUploadedHeicArgs) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    let request = uploaded_heic_delete_request(&manifest, &args.asset_id)?;
    let session = load_cloudkit_delete_session(&args.session)?;
    let transport = ReqwestCloudKitDeleteTransport::new()?;
    let mut client = CloudKitDeleteClient::new(transport);
    let resolved = client.resolve_uploaded_heic_asset(&session, &request)?;
    let outcome = client.delete_cpl_asset(
        &session,
        &CloudKitDeleteRequest {
            record_name: resolved.record_name.clone(),
            record_change_tag: resolved.record_change_tag.clone(),
            database_scope: request.database_scope,
            zone_name: request.zone_name.clone(),
        },
    )?;
    record_uploaded_heic_delete(&mut manifest, &args.asset_id, resolved, outcome)?;
    save_manifest(&manifest, &args.manifest)
}

fn workflow_icloudpd_local_mirror(args: WorkflowIcloudpdLocalMirrorArgs) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    let (upload, heic) = icloudpd_local_mirror_ready_proofs(&manifest, &args.asset_id)?;
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
        icloudpd_download_path: args.download_path,
    })?;
    record_icloudpd_local_mirror_proof(&mut manifest, &args.asset_id, proof)?;
    save_manifest(&manifest, &args.manifest)
}

fn workflow_icloudpd_local_mirror_proof<W: Write>(
    args: WorkflowIcloudpdLocalMirrorProofArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let proof = ensure_icloudpd_local_mirror(IcloudpdLocalMirrorRequest {
        uploaded_heic_asset_id: args.uploaded_heic_asset_id,
        uploaded_heic_sha256: args.uploaded_heic_sha256,
        uploaded_heic_path: args.uploaded_heic_path,
        size_bytes: args.size_bytes,
        icloudpd_download_path: args.download_path,
    })?;
    serde_json::to_writer_pretty(&mut *writer, &proof)?;
    writeln!(writer)?;
    Ok(())
}

fn workflow_original_asset_verified(
    args: WorkflowOriginalAssetVerifiedArgs,
) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    let destination = cli_library_destination(args.database_scope, args.zone_name, None)?;
    record_original_asset_proof(
        &mut manifest,
        &args.asset_id,
        OriginalAssetProof {
            record_name: args.record_name,
            record_change_tag: args.record_change_tag,
            record_type: args.record_type,
            database_scope: destination.database_scope,
            zone_name: destination.zone_name,
            filename: args.filename,
            size_bytes: args.size_bytes,
            matched_raw_sha256: args.matched_raw_sha256,
        },
    )?;
    save_manifest(&manifest, &args.manifest)
}

fn optional_original_destination_for_asset(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<Option<CloudKitLibraryDestination>, CliError> {
    let record = manifest.get(asset_id).map_err(WorkflowError::Manifest)?;
    let Some(value) = record.proofs.get("original_asset") else {
        return Ok(None);
    };
    let original: OriginalAssetProof =
        serde_json::from_value(value.clone()).map_err(|source| WorkflowError::ProofDecode {
            asset_id: record.asset_id.clone(),
            proof_key: "original_asset",
            source,
        })?;
    validate_cli_library_destination(CloudKitLibraryDestination {
        database_scope: original.database_scope,
        zone_name: original.zone_name,
    })
    .map(Some)
}

fn cli_library_destination(
    database_scope: Option<WorkflowCloudKitDatabaseScopeArg>,
    zone_name: Option<String>,
    fallback: Option<CloudKitLibraryDestination>,
) -> Result<CloudKitLibraryDestination, CliError> {
    if database_scope.is_none() && zone_name.is_none() {
        return validate_cli_library_destination(
            fallback.unwrap_or_else(CloudKitLibraryDestination::primary_sync),
        );
    }

    let database_scope = database_scope.map(CloudKitDatabaseScope::from);
    let zone_name = match zone_name {
        Some(zone_name) => zone_name,
        None => match (database_scope, fallback.as_ref()) {
            (Some(CloudKitDatabaseScope::Private), _) => "PrimarySync".to_string(),
            (Some(CloudKitDatabaseScope::Shared), Some(destination))
                if destination.database_scope == CloudKitDatabaseScope::Shared =>
            {
                destination.zone_name.clone()
            }
            (Some(CloudKitDatabaseScope::Shared), _) => {
                return Err(CliError::InvalidCloudKitDestination {
                    message: "--zone-name is required for shared CloudKit library proofs"
                        .to_string(),
                });
            }
            (None, Some(destination)) => destination.zone_name.clone(),
            (None, None) => "PrimarySync".to_string(),
        },
    };
    let database_scope = database_scope.unwrap_or_else(|| {
        if zone_name.starts_with("SharedSync-") {
            CloudKitDatabaseScope::Shared
        } else {
            CloudKitDatabaseScope::Private
        }
    });
    validate_cli_library_destination(CloudKitLibraryDestination {
        database_scope,
        zone_name,
    })
}

fn validate_cli_library_destination(
    destination: CloudKitLibraryDestination,
) -> Result<CloudKitLibraryDestination, CliError> {
    validate_library_destination(&destination).map_err(|error| {
        CliError::InvalidCloudKitDestination {
            message: error.to_string(),
        }
    })?;
    Ok(destination)
}

fn workflow_original_asset_resolve(args: WorkflowOriginalAssetResolveArgs) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    let (nas, source_age, filename) =
        original_asset_resolve_manifest_inputs(&manifest, &args.asset_id)?;
    let session = load_cloudkit_delete_session(&args.session)?;
    let transport = ReqwestCloudKitDeleteTransport::new()?;
    let mut client = CloudKitDeleteClient::new(transport);
    let proof = client.resolve_original_asset(
        &session,
        &CloudKitOriginalAssetResolveRequest {
            raw_size_bytes: nas.size_bytes,
            source_captured_unix_seconds: source_age.source_captured_unix_seconds,
            capture_tolerance_seconds: args.capture_tolerance_seconds,
            filename,
            matched_raw_sha256: nas.sha256,
            start_rank: args.start_rank,
            page_size: args.page_size,
            max_pages: args.max_pages,
        },
    )?;
    record_original_asset_proof(&mut manifest, &args.asset_id, proof)?;
    save_manifest(&manifest, &args.manifest)
}

fn workflow_original_assets_resolve_batch(
    args: WorkflowOriginalAssetsResolveBatchArgs,
) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    let asset_ids = original_asset_batch_target_asset_ids(&manifest, &args.asset_id);
    let targets: Vec<CloudKitOriginalAssetResolveTarget> = asset_ids
        .iter()
        .map(|asset_id| {
            let (nas, source_age, filename) =
                original_asset_resolve_manifest_inputs(&manifest, asset_id)?;
            Ok(CloudKitOriginalAssetResolveTarget {
                asset_id: asset_id.clone(),
                raw_size_bytes: nas.size_bytes,
                source_captured_unix_seconds: source_age.source_captured_unix_seconds,
                capture_tolerance_seconds: args.capture_tolerance_seconds,
                filename,
                matched_raw_sha256: nas.sha256,
                replacement_candidate: None,
            })
        })
        .collect::<Result<_, CliError>>()?;
    let session = load_cloudkit_delete_session(&args.session)?;
    let transport = ReqwestCloudKitDeleteTransport::new()?;
    let mut client = CloudKitDeleteClient::new(transport);
    let proofs = client.resolve_original_assets_batch(
        &session,
        &CloudKitOriginalAssetBatchResolveRequest {
            targets,
            start_rank: args.start_rank,
            page_size: args.page_size,
            max_pages: args.max_pages,
        },
    )?;
    record_original_asset_batch_proofs(&mut manifest, &asset_ids, proofs)?;
    save_manifest(&manifest, &args.manifest)
}

fn workflow_mark_delete_eligible(args: WorkflowAssetArgs) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    mark_delete_eligible(&mut manifest, &args.asset_id)?;
    save_manifest(&manifest, &args.manifest)
}

fn workflow_approve_delete(args: WorkflowApproveDeleteArgs) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    approve_delete(&mut manifest, &args.asset_id, &args.operator)?;
    save_manifest(&manifest, &args.manifest)
}

fn workflow_failed(args: WorkflowFailedArgs) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    record_stage_failure(&mut manifest, &args.asset_id, &args.stage, &args.message)?;
    save_manifest(&manifest, &args.manifest)
}

fn workflow_delete_plan<W: Write>(args: WorkflowAssetArgs, writer: &mut W) -> Result<(), CliError> {
    let manifest = load_existing_manifest(&args.manifest)?;
    let plan = build_delete_plan(&manifest, &args.asset_id)?;
    serde_json::to_writer_pretty(&mut *writer, &plan)?;
    writeln!(writer)?;
    Ok(())
}

fn workflow_delete_execute(args: WorkflowDeleteExecuteArgs) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    let request = approved_original_delete_request(&manifest, &args.asset_id)?;
    let session = load_cloudkit_delete_session(&args.session)?;
    let transport = ReqwestCloudKitDeleteTransport::new()?;
    let mut client = CloudKitDeleteClient::new(transport);
    let outcome = client.delete_original(&session, &request)?;
    record_delete_execution(&mut manifest, &args.asset_id, outcome)?;
    save_manifest(&manifest, &args.manifest)
}

fn load_manifest_for_write(path: &Path) -> Result<Manifest, CliError> {
    if AssetStateStore::db_path_for_manifest(path).exists() {
        return Ok(AssetStateStore::open_read_only(path)?.load()?);
    }
    match Manifest::load(path) {
        Ok(manifest) => Ok(manifest),
        Err(ManifestError::Io(error)) if error.kind() == ErrorKind::NotFound => Ok(Manifest::new()),
        Err(source) => Err(CliError::LoadManifest {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn load_existing_manifest(path: &Path) -> Result<Manifest, CliError> {
    if AssetStateStore::db_path_for_manifest(path).exists() {
        return Ok(AssetStateStore::open_read_only(path)?.load()?);
    }
    Manifest::load(path).map_err(|source| CliError::LoadManifest {
        path: path.to_path_buf(),
        source,
    })
}

fn original_asset_resolve_manifest_inputs(
    manifest: &Manifest,
    asset_id: &str,
) -> Result<(NasRawProof, SourceAgeProof, String), CliError> {
    let record = manifest.get(asset_id).map_err(WorkflowError::Manifest)?;
    let nas = decode_workflow_proof::<NasRawProof>(record, "nas")?;
    let source_age = decode_workflow_proof::<SourceAgeProof>(record, "source_age")?;
    let filename = record
        .raw_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .ok_or(WorkflowError::EmptyProofField { field: "filename" })?
        .to_string();
    Ok((nas, source_age, filename))
}

fn original_asset_batch_target_asset_ids(manifest: &Manifest, requested: &[String]) -> Vec<String> {
    if !requested.is_empty() {
        return requested.to_vec();
    }
    manifest
        .records()
        .values()
        .filter(|record| {
            record.state == State::UploadVerified && !record.proofs.contains_key("original_asset")
        })
        .map(|record| record.asset_id.clone())
        .collect()
}

fn convert_batch_target_asset_ids(manifest: &Manifest, requested: &[String]) -> Vec<String> {
    if !requested.is_empty() {
        return requested.to_vec();
    }
    manifest
        .records()
        .values()
        .filter(|record| record.state == State::NasVerified)
        .map(|record| record.asset_id.clone())
        .collect()
}

fn convert_batch_output_path(output_dir: &Path, asset_id: &str) -> Result<PathBuf, CliError> {
    if asset_id.trim().is_empty()
        || asset_id.contains('/')
        || asset_id.contains('\\')
        || asset_id == "."
        || asset_id == ".."
    {
        return Err(CliError::UnsafeBatchAssetId {
            asset_id: asset_id.to_string(),
        });
    }
    Ok(output_dir.join(format!("{asset_id}.heic")))
}

fn decode_workflow_proof<T: serde::de::DeserializeOwned>(
    record: &AssetRecord,
    proof_key: &'static str,
) -> Result<T, CliError> {
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
        .map_err(CliError::Workflow)
}

fn save_manifest(manifest: &Manifest, path: &Path) -> Result<(), CliError> {
    if AssetStateStore::db_path_for_manifest(path).exists() {
        let store = AssetStateStore::open_writer(
            path,
            Uuid::new_v4().to_string(),
            Duration::from_secs(60),
        )?;
        store.persist_manifest_records(manifest)?;
        store.export_json()?;
        return Ok(());
    }
    manifest
        .save_atomic(path)
        .map_err(|source| CliError::SaveManifest {
            path: path.to_path_buf(),
            source,
        })
}

fn system_time_unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn tool_present(tool_name: &str) -> bool {
    let Some(paths) = env::var_os("PATH") else {
        return false;
    };

    env::split_paths(&paths)
        .filter(|directory| !directory.as_os_str().is_empty())
        .any(|directory| is_executable_file(&directory.join(tool_name)))
}

#[derive(Serialize)]
struct ManifestOutput<'a> {
    records: Vec<&'a AssetRecord>,
}

#[derive(Serialize)]
struct DoctorReport {
    platform: PlatformReport,
    conversion_backend: DoctorConversionBackendReport,
    required_tools: Vec<ToolReport>,
}

#[derive(Serialize)]
struct PlatformReport {
    os: &'static str,
    arch: &'static str,
}

#[derive(Serialize)]
struct DoctorConversionBackendReport {
    name: &'static str,
    workflow_convert_supported: bool,
    reason: &'static str,
}

#[derive(Serialize)]
struct ToolReport {
    name: &'static str,
    present: bool,
}

#[cfg(test)]
mod original_assets_audit_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn audit_record(asset_id: &str, raw_path: PathBuf, root: &Path) -> AssetRecord {
        let raw = fs::read(&raw_path).expect("raw should be readable");
        let mut record = AssetRecord::new(asset_id, raw_path.clone());
        record.state = State::UploadVerified;
        record.proofs.insert(
            "nas".to_string(),
            serde_json::to_value(NasRawProof {
                canonical_path: fs::canonicalize(&raw_path).expect("raw should canonicalize"),
                relative_path: raw_path
                    .strip_prefix(root)
                    .expect("raw should be under the library root")
                    .to_path_buf(),
                size_bytes: raw.len() as u64,
                modified_unix_seconds: 1_700_000_000,
                age_seconds: 40 * DAY_SECONDS,
                sha256: format!("{:x}", Sha256::digest(raw)),
            })
            .expect("NAS proof should serialize"),
        );
        record.proofs.insert(
            "source_age".to_string(),
            serde_json::to_value(SourceAgeProof {
                source_captured_unix_seconds: 1_800_000_000,
                verified_at_unix_seconds: 1_800_000_100,
                min_age_seconds: 30 * DAY_SECONDS,
            })
            .expect("source age proof should serialize"),
        );
        record
    }

    #[derive(Clone, Copy)]
    enum AuditReadFailure {
        Authentication,
        MalformedResponse,
    }

    struct FailingAuditReadTransport {
        failure: AuditReadFailure,
    }

    impl CloudKitOriginalAssetReadTransport for FailingAuditReadTransport {
        fn post_records_query(
            &mut self,
            _session: &crate::upload::CloudKitDeleteSession,
            _payload: serde_json::Value,
        ) -> Result<serde_json::Value, UploadError> {
            match self.failure {
                AuditReadFailure::Authentication => Err(UploadError::InvalidSession(
                    "expired audit session".to_string(),
                )),
                AuditReadFailure::MalformedResponse => {
                    Err(UploadError::MalformedCloudKitResponse {
                        operation: "records_query",
                    })
                }
            }
        }

        fn download_resource(
            &mut self,
            _session: &crate::upload::CloudKitDeleteSession,
            _download_url: &url::Url,
            _expected_size_bytes: u64,
        ) -> Result<crate::upload::CloudKitResourceDownload, UploadError> {
            unreachable!("query failures must remain batch-level")
        }
    }

    fn audit_test_session() -> crate::upload::CloudKitDeleteSession {
        crate::upload::CloudKitDeleteSession::from_json(
            &serde_json::json!({
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
                "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "test-cookie"}]
            })
            .to_string(),
        )
        .expect("session should load")
    }

    fn audit_test_target() -> CloudKitOriginalAssetResolveTarget {
        let raw = b"audit-raw";
        CloudKitOriginalAssetResolveTarget {
            asset_id: "local-audit-asset".to_string(),
            raw_size_bytes: raw.len() as u64,
            source_captured_unix_seconds: 1_800_000_000,
            capture_tolerance_seconds: 2,
            filename: "IMG_0001.DNG".to_string(),
            matched_raw_sha256: format!("{:x}", Sha256::digest(raw)),
            replacement_candidate: None,
        }
    }

    #[test]
    fn audit_groups_primary_and_shared_assets_and_hashes_safe_siblings() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let root = tempdir.path().join("library");
        let primary_raw = root.join("PrimarySync/IMG_0001.DNG");
        let shared_raw = root.join("SharedSync-family/IMG_0002.DNG");
        fs::create_dir_all(primary_raw.parent().expect("raw should have a parent"))
            .expect("primary directory should be created");
        fs::create_dir_all(shared_raw.parent().expect("raw should have a parent"))
            .expect("shared directory should be created");
        fs::write(&primary_raw, b"primary-raw").expect("primary raw should save");
        fs::write(&shared_raw, b"shared-raw").expect("shared raw should save");
        fs::write(
            primary_raw
                .parent()
                .expect("raw should have a parent")
                .join("asset-primary.HEIC"),
            b"replacement",
        )
        .expect("replacement should save");
        let mut manifest = Manifest::new();
        manifest.upsert(audit_record("asset-primary", primary_raw, &root));
        manifest.upsert(audit_record("asset-shared", shared_raw, &root));

        let (groups, skipped) = original_assets_audit_targets(
            &manifest,
            &fs::canonicalize(&root).expect("root should canonicalize"),
            2,
        );

        assert_eq!(skipped, 0);
        assert_eq!(groups.len(), 2);
        let primary = groups
            .get(&CloudKitLibraryDestination::primary_sync())
            .expect("primary target should be grouped");
        assert_eq!(primary.len(), 1);
        assert_eq!(
            primary[0]
                .replacement_candidate
                .as_ref()
                .expect("safe sibling should be hashed")
                .size_bytes,
            b"replacement".len() as u64
        );
        let shared_destination = CloudKitLibraryDestination {
            database_scope: CloudKitDatabaseScope::Shared,
            zone_name: "SharedSync-family".to_string(),
        };
        assert_eq!(
            groups
                .get(&shared_destination)
                .expect("shared target should be grouped")
                .len(),
            1
        );
    }

    #[test]
    fn audit_output_ids_are_compact_and_do_not_echo_paths() {
        let asset_id = "/private/library/SharedSync-family/IMG_0001.DNG";
        let compact = compact_audit_asset_id(asset_id);

        assert!(compact.starts_with("asset-"));
        assert!(!compact.contains("private"));
        assert!(!compact.contains('/'));
    }

    #[test]
    fn audit_eligibility_covers_all_pre_delete_original_resolver_candidates() {
        for state in [
            State::NasVerified,
            State::Converted,
            State::ConversionVerified,
            State::UploadVerified,
        ] {
            let mut record = AssetRecord::new("asset", "/raw/asset.DNG");
            record.state = state;
            assert!(
                original_assets_audit_eligible(&record),
                "{state:?} without original proof should be audited"
            );
            record
                .proofs
                .insert("original_asset".to_string(), serde_json::json!({}));
            assert!(
                !original_assets_audit_eligible(&record),
                "{state:?} with original proof should not be audited"
            );
        }
        for state in [State::DeleteApproved, State::Deleted] {
            let mut record = AssetRecord::new("asset", "/raw/asset.DNG");
            record.state = state;
            assert!(
                !original_assets_audit_eligible(&record),
                "{state:?} must stay outside audit eligibility"
            );
        }
        let mut failed = AssetRecord::new("failed", "/raw/failed.DNG");
        failed.state = State::Failed;
        failed.failures.push(crate::manifest::FailureRecord::new(
            "original_asset_resolve",
            "resolver interrupted",
        ));
        assert!(original_assets_audit_eligible(&failed));
    }

    #[test]
    fn audit_human_summary_includes_counts_and_destination_timings() {
        let reports = vec![OriginalAssetsAuditDestinationReport {
            destination: CloudKitLibraryDestination::primary_sync(),
            targets: 2,
            inventory: None,
            resolutions: BTreeMap::from([
                (
                    "asset-a".to_string(),
                    CloudKitOriginalAssetResolution {
                        observations: Default::default(),
                        disposition: CloudKitOriginalAssetResolveDisposition::NoRawResource,
                    },
                ),
                (
                    "asset-b".to_string(),
                    CloudKitOriginalAssetResolution {
                        observations: Default::default(),
                        disposition: CloudKitOriginalAssetResolveDisposition::ExactOriginal {
                            proof: crate::workflow::OriginalAssetProof {
                                record_name: "record".to_string(),
                                record_change_tag: "tag".to_string(),
                                record_type: "CPLAsset".to_string(),
                                database_scope: CloudKitDatabaseScope::Private,
                                zone_name: "PrimarySync".to_string(),
                                filename: "asset.DNG".to_string(),
                                size_bytes: 1,
                                matched_raw_sha256: "sha".to_string(),
                            },
                        },
                    },
                ),
            ]),
            batch_error: None,
            elapsed_millis: 7,
        }];

        let summary = original_assets_audit_human_summary(2, 0, &reports, 11);

        assert!(summary.contains("exact_original=1"));
        assert!(summary.contains("no_raw_resource=1"));
        assert!(summary.contains("private:PrimarySync=7ms"));
        assert!(summary.contains("elapsed_ms=11"));
    }

    #[test]
    fn replacement_candidate_hash_rejects_a_file_changed_after_handle_open() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let replacement = tempdir.path().join("asset.HEIC");
        fs::write(&replacement, b"replacement").expect("replacement should save");

        let error = hash_stable_file_with_before_hash(&replacement, || {
            fs::write(&replacement, b"replacement changed")
                .expect("replacement mutation should succeed");
        })
        .expect_err("changed replacement bytes must not produce an exact local candidate");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn replacement_candidate_hash_rejects_same_size_rewrite_with_restored_mtime() {
        use filetime::{FileTime, set_file_mtime};
        use std::os::unix::fs::MetadataExt;

        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let replacement = tempdir.path().join("asset.HEIC");
        fs::write(&replacement, b"before").expect("replacement should save");
        let before = fs::metadata(&replacement).expect("replacement metadata should load");
        let original_mtime = FileTime::from_last_modification_time(&before);

        let error = hash_stable_file_with_before_hash(&replacement, || {
            fs::write(&replacement, b"after!").expect("replacement mutation should succeed");
            set_file_mtime(&replacement, original_mtime)
                .expect("replacement mtime should be restored");
        })
        .expect_err("same-size rewrite must not produce an exact local candidate");

        let after = fs::metadata(&replacement).expect("replacement metadata should reload");
        assert_ne!(
            (before.ctime(), before.ctime_nsec()),
            (after.ctime(), after.ctime_nsec())
        );
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn replacement_candidate_hash_rejects_a_path_replaced_after_handle_open() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let replacement = tempdir.path().join("asset.HEIC");
        let replacement_swap = tempdir.path().join("asset.HEIC.swap");
        fs::write(&replacement, b"before").expect("replacement should save");
        fs::write(&replacement_swap, b"after!").expect("replacement swap should save");

        let error = hash_stable_file_with_before_hash(&replacement, || {
            fs::rename(&replacement_swap, &replacement)
                .expect("replacement path should be replaced atomically");
        })
        .expect_err("replaced path must not produce an exact local candidate");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn original_assets_audit_marks_malformed_cloudkit_response_as_malformed() {
        assert!(matches!(
            original_assets_audit_batch_error(&UploadError::MalformedCloudKitResponse {
                operation: "records_query",
            }),
            OriginalAssetsAuditBatchError::MalformedResponse
        ));
    }

    #[test]
    fn audit_read_transport_only_queries_and_downloads_nonzero_targets() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let address = listener
            .local_addr()
            .expect("listener should have a local address");
        let raw = b"audit-raw".to_vec();
        let resource_url = format!("http://{address}/resource");
        let query_response = serde_json::json!({
            "records": [
                {
                    "recordName": "remote-raw-asset",
                    "recordType": "CPLAsset",
                    "recordChangeTag": "raw-change-tag",
                    "fields": {
                        "masterRef": {"value": {"recordName": "remote-raw-master"}},
                        "assetDate": {"value": 1_800_000_000_000_i64}
                    }
                },
                {
                    "recordName": "remote-raw-master",
                    "recordType": "CPLMaster",
                    "fields": {
                        "resOriginalRes": {
                            "value": {
                                "size": raw.len(),
                                "downloadURL": resource_url
                            }
                        },
                        "resOriginalFileType": {"value": "com.adobe.raw-image"},
                        "resOriginalFingerprint": {"value": "raw-fingerprint"}
                    }
                }
            ]
        })
        .to_string();
        let server_raw = raw.clone();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for (index, response_body) in [query_response.into_bytes(), server_raw]
                .into_iter()
                .enumerate()
            {
                let (mut stream, _) = listener.accept().expect("request should connect");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 1024];
                loop {
                    let read = stream
                        .read(&mut buffer)
                        .expect("request should be readable");
                    assert!(read > 0, "request should include headers");
                    request.extend_from_slice(&buffer[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
                let header_end = request
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .expect("request should include a header terminator")
                    + 4;
                let header_text = String::from_utf8(request[..header_end].to_vec())
                    .expect("request headers should be UTF-8");
                let content_length = header_text
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0);
                while request.len() < header_end + content_length {
                    let read = stream
                        .read(&mut buffer)
                        .expect("request body should be readable");
                    assert!(read > 0, "request body should not end early");
                    request.extend_from_slice(&buffer[..read]);
                }
                requests.push(
                    header_text
                        .lines()
                        .next()
                        .expect("request should include a request line")
                        .to_string(),
                );
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                    response_body.len()
                )
                .expect("response headers should write");
                stream
                    .write_all(&response_body)
                    .expect("response body should write");
                assert!(
                    index < 2,
                    "server should only receive expected read requests"
                );
            }
            requests
        });

        let mut session = audit_test_session();
        session.ckdatabasews_url =
            url::Url::parse(&format!("http://{address}")).expect("loopback URL should parse");
        let config = MonitorConfig::new("/audit/download", "/audit/manifest.json", "/audit/heic");
        let target = audit_test_target();
        let report = original_assets_audit_destination_report_with_transport(
            &session,
            CloudKitLibraryDestination::primary_sync(),
            vec![target],
            &config,
            ReqwestCloudKitReadTransport::new().expect("read transport should build"),
        );

        assert_eq!(report.targets, 1);
        assert!(report.batch_error.is_none(), "{:#?}", report.batch_error);
        assert_eq!(report.resolutions.len(), 1);
        let requests = server.join().expect("recording server should complete");
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with(
            "POST /database/1/com.apple.photos.cloud/production/private/records/query?"
        ));
        assert_eq!(requests[1], "GET /resource HTTP/1.1");
        assert!(
            requests
                .iter()
                .all(|request| !request.contains("records/modify") && !request.contains("upload"))
        );
    }

    #[test]
    fn audit_authentication_and_malformed_read_failures_are_batch_level() {
        let config = MonitorConfig::new("/audit/download", "/audit/manifest.json", "/audit/heic");
        for (failure, expected) in [
            (
                AuditReadFailure::Authentication,
                OriginalAssetsAuditBatchError::Authentication,
            ),
            (
                AuditReadFailure::MalformedResponse,
                OriginalAssetsAuditBatchError::MalformedResponse,
            ),
        ] {
            let report = original_assets_audit_destination_report_with_transport(
                &audit_test_session(),
                CloudKitLibraryDestination::primary_sync(),
                vec![audit_test_target()],
                &config,
                FailingAuditReadTransport { failure },
            );

            assert!(report.resolutions.is_empty());
            assert_eq!(report.batch_error, Some(expected));
        }
    }
}

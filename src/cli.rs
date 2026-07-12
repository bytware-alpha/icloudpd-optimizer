use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
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
use serde::{Deserialize, Serialize};
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
use crate::manifest::{
    AssetRecord, FailureKind, FailureQuarantineProof, Manifest, ManifestError, State,
};
use crate::metrics::VerifiedMetrics;
use crate::monitor::{
    LegacyEmbeddedPreviewMigrationClassification, MonitorConfig, MonitorError, MonitorScanSummary,
    MonitorStats, acquire_monitor_run_guard, classify_legacy_embedded_preview_migration,
    launchd_plist, log_monitor_failure_event, render_tui, run_monitor_once,
    run_scan_root_preflight_probe, write_launchd_plist,
};
use crate::proof::NasRawProof;
use crate::reconciliation::{OriginalAssetResolutionBatch, OriginalAssetResolutionError};
use crate::service::{
    DEFAULT_SERVICE_LABEL, ServiceError, ServiceInstallRequest, default_plist_path,
    install_service, service_status, start_service, stop_service, tail_logs, uninstall_service,
};
use crate::state_store::{AssetRecordExactCasUpdate, AssetStateStore, AssetStateStoreError};
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
    ConversionPerformanceInput, ConversionResultProof, ConversionSourceBinding,
    EMBEDDED_PREVIEW_CONVERSION_RECIPE, HeicVerificationProof, IcloudpdLocalMirrorProofDisposition,
    OriginalAssetProof, SourceAgeProof, UploadProof, WorkflowError, approve_delete,
    approved_original_delete_request, build_delete_plan, icloudpd_local_mirror_proof_disposition,
    icloudpd_local_mirror_ready_proofs, mark_delete_eligible, prove_and_record_nas,
    record_conversion_performance, record_conversion_result, record_delete_execution,
    record_heic_verification, record_icloudpd_local_mirror_proof,
    record_original_asset_batch_proofs, record_original_asset_proof, record_source_age_proof,
    record_stage_failure, record_upload_proof, record_uploaded_heic_delete,
    upload_ready_heic_proof, uploaded_heic_delete_request,
};

const DAY_SECONDS: u64 = 24 * 60 * 60;
const ORIGINAL_ASSETS_TARGET_SET_FINGERPRINT_VERSION: &[u8] = b"original-assets-target-set-v1";
const FAILED_ASSETS_QUARANTINE_TARGET_SET_FINGERPRINT_VERSION: &[u8] =
    b"failed-assets-quarantine-target-set-v2";
const LEGACY_FAILURES_CLASSIFY_TARGET_SET_FINGERPRINT_VERSION: &[u8] =
    b"legacy-failures-classify-target-set-v1";

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
        name = "original-assets-reconcile",
        about = "Query and optionally atomically reconcile one CloudKit original-assets destination"
    )]
    OriginalAssetsReconcile(MonitorOriginalAssetsReconcileArgs),
    #[command(
        name = "failed-assets-quarantine",
        about = "Atomically quarantine audited failed assets with historical remote side effects"
    )]
    FailedAssetsQuarantine(MonitorFailedAssetsQuarantineArgs),
    #[command(
        name = "legacy-failures-classify",
        about = "Offline audited migration for exact legacy missing-preview failures"
    )]
    LegacyFailuresClassify(MonitorLegacyFailuresClassifyArgs),
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
    #[arg(long, default_value_t = 16)]
    max_failed_retry_admissions_per_scan: usize,
    #[arg(long, default_value_t = 300)]
    failed_retry_min_age_seconds: u64,
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
struct MonitorOriginalAssetsReconcileArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, value_enum)]
    database_scope: WorkflowCloudKitDatabaseScopeArg,
    #[arg(long)]
    zone_name: String,
    #[arg(long)]
    expected_selected_target_count: u64,
    #[arg(long)]
    expected_unselected_destination_target_count: u64,
    #[arg(long)]
    expected_skipped_target_count: u64,
    #[arg(long)]
    expected_target_set_sha256: String,
    #[arg(long)]
    expected_inventory_sha256: String,
    #[arg(long)]
    expected_records_scanned: u64,
    #[arg(long)]
    expected_exact_original_count: u64,
    #[arg(long)]
    expected_replacement_present_count: u64,
    #[arg(long)]
    expected_no_date_candidate_count: u64,
    #[arg(long)]
    expected_no_raw_resource_count: u64,
    #[arg(long)]
    expected_raw_size_mismatch_count: u64,
    #[arg(long)]
    expected_raw_hash_mismatch_count: u64,
    #[arg(long)]
    expected_ambiguous_count: u64,
    #[arg(long)]
    expected_incomplete_transient_count: u64,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    apply: bool,
}

#[derive(Debug, Args)]
struct MonitorFailedAssetsQuarantineArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, value_name = "PATH")]
    evidence: PathBuf,
    #[arg(long, value_name = "HEX")]
    expected_evidence_sha256: String,
    #[arg(long, value_name = "N")]
    expected_failed_asset_count: u64,
    #[arg(long, value_name = "N")]
    expected_side_effect_asset_count: u64,
    #[arg(
        long,
        value_name = "HEX",
        help = "SHA-256 of the exact side-effect target and Failed cohort snapshot"
    )]
    expected_target_set_sha256: Option<String>,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    apply: bool,
}

#[derive(Debug, Args)]
struct MonitorLegacyFailuresClassifyArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(
        long,
        value_name = "HEX",
        help = "SHA-256 of the exact legacy missing-preview candidate snapshot"
    )]
    expected_target_set_sha256: Option<String>,
    #[arg(
        long,
        value_name = "N",
        help = "Candidate count reported by a prior dry-run"
    )]
    expected_candidate_count: Option<u64>,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    apply: bool,
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
    #[error("original-assets-reconcile gate failed: {message}")]
    OriginalAssetsReconcileGate { message: String },
    #[error("original-assets-reconcile {stage} failed")]
    OriginalAssetsReconcileFailure {
        stage: OriginalAssetsReconcileFailureStage,
    },
    #[error("original-assets-reconcile CloudKit {kind} failure")]
    OriginalAssetsReconcileCloudKitFailure {
        kind: OriginalAssetsReconcileCloudKitFailureKind,
    },
    #[error("original asset reconciliation failed: {0}")]
    OriginalAssetResolution(#[from] OriginalAssetResolutionError),
    #[error("original-assets-reconcile database commit succeeded but the JSON checkpoint is stale")]
    OriginalAssetsReconcileCheckpointStale,
    #[error("failed-assets-quarantine gate failed: {message}")]
    FailedAssetsQuarantineGate { message: String },
    #[error("failed-assets-quarantine database commit succeeded but the JSON checkpoint is stale")]
    FailedAssetsQuarantineCheckpointStale,
    #[error("legacy-failures-classify gate failed: {message}")]
    LegacyFailuresClassifyGate { message: String },
    #[error("legacy-failures-classify database commit succeeded but the JSON checkpoint is stale")]
    LegacyFailuresClassifyCheckpointStale,
    #[error("legacy-failures-classify dry-run report output failed; no mutation was performed")]
    LegacyFailuresClassifyDryRunReportOutput,
    #[error(
        "legacy-failures-classify database commit and JSON checkpoint succeeded but report output failed"
    )]
    LegacyFailuresClassifyReportOutputAfterCommit,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalAssetsReconcileFailureStage {
    Configuration,
    Root,
    State,
    Session,
    Domain,
    Persistence,
    Output,
}

impl fmt::Display for OriginalAssetsReconcileFailureStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stage = match self {
            Self::Configuration => "configuration",
            Self::Root => "root",
            Self::State => "state",
            Self::Session => "session",
            Self::Domain => "domain",
            Self::Persistence => "persistence",
            Self::Output => "output",
        };
        formatter.write_str(stage)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginalAssetsReconcileCloudKitFailureKind {
    Authentication,
    MalformedResponse,
    Transport,
    Transient,
}

impl fmt::Display for OriginalAssetsReconcileCloudKitFailureKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Authentication => "authentication",
            Self::MalformedResponse => "malformed-response",
            Self::Transport => "transport",
            Self::Transient => "transient",
        };
        formatter.write_str(kind)
    }
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
        MonitorCommand::OriginalAssetsReconcile(args) => {
            monitor_original_assets_reconcile(args, writer)
        }
        MonitorCommand::FailedAssetsQuarantine(args) => {
            monitor_failed_assets_quarantine(args, writer)
        }
        MonitorCommand::LegacyFailuresClassify(args) => {
            monitor_legacy_failures_classify(args, writer)
        }
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
    if let Some(mirror_root) = &config.mirror_root
        && !read_roots.iter().any(|path| path == mirror_root)
    {
        prime_read_root(mirror_root)?;
        read_roots.push(mirror_root.clone());
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
    skip_reason_counts: BTreeMap<String, u64>,
    destinations: Vec<OriginalAssetsAuditDestinationReport>,
    disposition_counts: BTreeMap<String, u64>,
    elapsed_millis: u128,
}

#[derive(Serialize)]
struct OriginalAssetsAuditDestinationReport {
    destination: CloudKitLibraryDestination,
    targets: usize,
    target_set_sha256: String,
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

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum OriginalAssetsAuditSkipReason {
    InvalidOrMissingNasProof,
    InvalidOrMissingSourceAgeProof,
    RawPathUnavailable,
    OutsideDownloadRoot,
    UnsupportedLibraryLayout,
    InvalidFilename,
}

impl OriginalAssetsAuditSkipReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidOrMissingNasProof => "invalid_or_missing_nas_proof",
            Self::InvalidOrMissingSourceAgeProof => "invalid_or_missing_source_age_proof",
            Self::RawPathUnavailable => "raw_path_unavailable",
            Self::OutsideDownloadRoot => "outside_download_root",
            Self::UnsupportedLibraryLayout => "unsupported_library_layout",
            Self::InvalidFilename => "invalid_filename",
        }
    }
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
    let (destination_targets, skipped_targets, skip_reason_counts) = original_assets_audit_targets(
        &manifest,
        &canonical_library_root,
        &config.download_root,
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
                    target_set_sha256: original_assets_target_set_sha256(&destination, &targets),
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
        skip_reason_counts,
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
            &report.skip_reason_counts,
            &report.destinations,
            report.elapsed_millis,
        )
    );
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OriginalAssetsReconcileExpectations {
    destination: CloudKitLibraryDestination,
    selected_target_count: u64,
    unselected_destination_target_count: u64,
    skipped_target_count: u64,
    target_set_sha256: String,
    inventory_sha256: String,
    records_scanned: u64,
    disposition_counts: OriginalAssetsReconcileDispositionCounts,
}

impl OriginalAssetsReconcileExpectations {
    fn from_args(args: &MonitorOriginalAssetsReconcileArgs) -> Result<Self, CliError> {
        let destination = validate_cli_library_destination(CloudKitLibraryDestination {
            database_scope: args.database_scope.into(),
            zone_name: args.zone_name.clone(),
        })?;
        let expectations = Self {
            destination,
            selected_target_count: args.expected_selected_target_count,
            unselected_destination_target_count: args.expected_unselected_destination_target_count,
            skipped_target_count: args.expected_skipped_target_count,
            target_set_sha256: args.expected_target_set_sha256.clone(),
            inventory_sha256: args.expected_inventory_sha256.clone(),
            records_scanned: args.expected_records_scanned,
            disposition_counts: OriginalAssetsReconcileDispositionCounts {
                exact_original: args.expected_exact_original_count,
                replacement_present: args.expected_replacement_present_count,
                no_date_candidate: args.expected_no_date_candidate_count,
                no_raw_resource: args.expected_no_raw_resource_count,
                raw_size_mismatch: args.expected_raw_size_mismatch_count,
                raw_hash_mismatch: args.expected_raw_hash_mismatch_count,
                ambiguous: args.expected_ambiguous_count,
                incomplete_transient: args.expected_incomplete_transient_count,
            },
        };
        expectations.validate_preflight()?;
        Ok(expectations)
    }

    fn validate_preflight(&self) -> Result<(), CliError> {
        if self.selected_target_count == 0 {
            return Err(original_assets_reconcile_gate(
                "expected selected target count must be positive",
            ));
        }
        if !is_sha256_fingerprint(&self.inventory_sha256) {
            return Err(original_assets_reconcile_gate(
                "expected inventory SHA-256 must be 64 hexadecimal characters",
            ));
        }
        if !is_sha256_fingerprint(&self.target_set_sha256) {
            return Err(original_assets_reconcile_gate(
                "expected target-set SHA-256 must be 64 hexadecimal characters",
            ));
        }
        if self.disposition_counts.total() != self.selected_target_count {
            return Err(original_assets_reconcile_gate(
                "expected disposition counts must sum to the expected selected target count",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
struct OriginalAssetsReconcileDispositionCounts {
    exact_original: u64,
    replacement_present: u64,
    no_date_candidate: u64,
    no_raw_resource: u64,
    raw_size_mismatch: u64,
    raw_hash_mismatch: u64,
    ambiguous: u64,
    incomplete_transient: u64,
}

impl OriginalAssetsReconcileDispositionCounts {
    fn from_resolutions(resolutions: &BTreeMap<String, CloudKitOriginalAssetResolution>) -> Self {
        let mut counts = Self::default();
        for resolution in resolutions.values() {
            match resolution.disposition {
                CloudKitOriginalAssetResolveDisposition::ExactOriginal { .. } => {
                    counts.exact_original = counts.exact_original.saturating_add(1);
                }
                CloudKitOriginalAssetResolveDisposition::ReplacementPresent { .. } => {
                    counts.replacement_present = counts.replacement_present.saturating_add(1);
                }
                CloudKitOriginalAssetResolveDisposition::NoDateCandidate => {
                    counts.no_date_candidate = counts.no_date_candidate.saturating_add(1);
                }
                CloudKitOriginalAssetResolveDisposition::NoRawResource => {
                    counts.no_raw_resource = counts.no_raw_resource.saturating_add(1);
                }
                CloudKitOriginalAssetResolveDisposition::RawSizeMismatch => {
                    counts.raw_size_mismatch = counts.raw_size_mismatch.saturating_add(1);
                }
                CloudKitOriginalAssetResolveDisposition::RawHashMismatch => {
                    counts.raw_hash_mismatch = counts.raw_hash_mismatch.saturating_add(1);
                }
                CloudKitOriginalAssetResolveDisposition::Ambiguous => {
                    counts.ambiguous = counts.ambiguous.saturating_add(1);
                }
                CloudKitOriginalAssetResolveDisposition::IncompleteTransient => {
                    counts.incomplete_transient = counts.incomplete_transient.saturating_add(1);
                }
            }
        }
        counts
    }

    fn total(&self) -> u64 {
        self.exact_original
            .saturating_add(self.replacement_present)
            .saturating_add(self.no_date_candidate)
            .saturating_add(self.no_raw_resource)
            .saturating_add(self.raw_size_mismatch)
            .saturating_add(self.raw_hash_mismatch)
            .saturating_add(self.ambiguous)
            .saturating_add(self.incomplete_transient)
    }
}

#[derive(Serialize)]
struct OriginalAssetsReconcileReport {
    destination: CloudKitLibraryDestination,
    target_set_sha256: String,
    counts: OriginalAssetsReconcileCounts,
    inventory: CloudKitOriginalAssetInventoryFingerprint,
    verified: bool,
    applied: bool,
    changed_count: u64,
    commit_elapsed_millis: u128,
}

#[derive(Serialize)]
struct OriginalAssetsReconcileCounts {
    selected_targets: u64,
    unselected_destination_targets: u64,
    skipped_targets: u64,
    dispositions: OriginalAssetsReconcileDispositionCounts,
}

struct VerifiedOriginalAssetsReconcileOutcome {
    inventory: CloudKitOriginalAssetInventoryFingerprint,
    disposition_counts: OriginalAssetsReconcileDispositionCounts,
}

fn monitor_original_assets_reconcile<W: Write>(
    args: MonitorOriginalAssetsReconcileArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let transport =
        ReqwestCloudKitReadTransport::new().map_err(original_assets_reconcile_cloudkit_failure)?;
    monitor_original_assets_reconcile_with_transport(args, writer, transport)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct FailedAssetsQuarantineEvidenceAsset {
    asset_id: String,
    successful_uploads: u64,
    delete_attempts: u64,
    deleted_finishes: u64,
    mirror_successes: u64,
}

impl FailedAssetsQuarantineEvidenceAsset {
    fn has_remote_side_effect(&self) -> bool {
        self.successful_uploads > 0
            || self.delete_attempts > 0
            || self.deleted_finishes > 0
            || self.mirror_successes > 0
    }
}

#[derive(Clone, Debug, Serialize)]
struct FailedAssetsQuarantineCounts {
    failed_assets: u64,
    with_upload_or_delete_side_effects: u64,
    clean_of_recorded_remote_side_effects: u64,
    side_effect_assets: u64,
}

#[derive(Debug)]
struct VerifiedFailedAssetsQuarantineEvidence {
    evidence_sha256: String,
    failed_asset_ids: BTreeSet<String>,
    side_effect_assets: BTreeMap<String, FailedAssetsQuarantineEvidenceAsset>,
    counts: FailedAssetsQuarantineCounts,
}

#[derive(Serialize)]
struct FailedAssetsQuarantineReport {
    evidence_sha256: String,
    target_set_sha256: String,
    counts: FailedAssetsQuarantineCounts,
    verified: bool,
    applied: bool,
    changed_count: u64,
}

fn monitor_failed_assets_quarantine<W: Write>(
    args: MonitorFailedAssetsQuarantineArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let evidence = load_failed_assets_quarantine_evidence(&args)?;
    let expected_target_set_sha256 = validate_failed_assets_quarantine_target_set_preflight(&args)?;
    let config = MonitorConfig::load(&args.config)
        .map_err(|_| failed_assets_quarantine_gate("monitor configuration could not be loaded"))?;
    config.validate().map_err(|_| {
        failed_assets_quarantine_gate("monitor configuration did not pass validation")
    })?;

    let (target_set_sha256, applied, changed_count) = if args.apply {
        let expected_target_set_sha256 = expected_target_set_sha256.ok_or_else(|| {
            failed_assets_quarantine_gate("apply requires an expected target-set SHA-256")
        })?;
        let mut guard = acquire_monitor_run_guard(&config).map_err(|_| {
            failed_assets_quarantine_gate(
                "monitor process lock or writer lease could not be acquired",
            )
        })?;
        let state_store = guard
            .state_store(&config.manifest_path)
            .map_err(|_| failed_assets_quarantine_gate("writer lease could not be acquired"))?;
        let mut manifest = state_store.load().map_err(|_| {
            failed_assets_quarantine_gate(
                "current state could not be loaded under the writer lease",
            )
        })?;
        validate_failed_assets_quarantine_failed_cohort(&manifest, &evidence.failed_asset_ids)?;
        let target_set_sha256 =
            failed_assets_quarantine_target_set_sha256(&manifest, &evidence.side_effect_assets)?;
        validate_failed_assets_quarantine_target_set_match(
            expected_target_set_sha256,
            &target_set_sha256,
        )?;
        let expected_records =
            failed_assets_quarantine_expected_records(&manifest, &evidence.side_effect_assets)?;
        let changed_records = apply_failed_assets_quarantine(
            &mut manifest,
            &evidence,
            &target_set_sha256,
            current_unix_seconds_for_cli(),
        )?;
        let changed_count = u64::try_from(changed_records.len()).map_err(|_| {
            failed_assets_quarantine_gate("quarantine update count exceeded the supported range")
        })?;
        persist_failed_assets_quarantine_updates(
            state_store,
            &expected_records,
            &changed_records,
            evidence.counts.side_effect_assets,
        )?;
        ensure_failed_assets_quarantine_checkpoint(|| state_store.export_json())?;
        (target_set_sha256, true, changed_count)
    } else {
        let state_store = AssetStateStore::open_immutable_read_only(&config.manifest_path)
            .map_err(|_| {
                failed_assets_quarantine_gate("immutable state snapshot could not be opened")
            })?;
        let manifest = state_store.load().map_err(|_| {
            failed_assets_quarantine_gate("immutable state snapshot could not be loaded")
        })?;
        validate_failed_assets_quarantine_failed_cohort(&manifest, &evidence.failed_asset_ids)?;
        let target_set_sha256 =
            failed_assets_quarantine_target_set_sha256(&manifest, &evidence.side_effect_assets)?;
        if let Some(expected_target_set_sha256) = expected_target_set_sha256 {
            validate_failed_assets_quarantine_target_set_match(
                expected_target_set_sha256,
                &target_set_sha256,
            )?;
        }
        state_store
            .revalidate_immutable_read_snapshot()
            .map_err(|_| {
                failed_assets_quarantine_gate(
                    "immutable state changed while the dry-run was verifying",
                )
            })?;
        (target_set_sha256, false, 0)
    };

    let report = FailedAssetsQuarantineReport {
        evidence_sha256: evidence.evidence_sha256,
        target_set_sha256,
        counts: evidence.counts,
        verified: true,
        applied,
        changed_count,
    };
    serde_json::to_writer_pretty(&mut *writer, &report)?;
    writeln!(writer)?;
    Ok(())
}

fn load_failed_assets_quarantine_evidence(
    args: &MonitorFailedAssetsQuarantineArgs,
) -> Result<VerifiedFailedAssetsQuarantineEvidence, CliError> {
    if !is_sha256_fingerprint(&args.expected_evidence_sha256) {
        return Err(failed_assets_quarantine_gate(
            "expected evidence SHA-256 must be 64 hexadecimal characters",
        ));
    }
    let bytes = fs::read(&args.evidence)
        .map_err(|_| failed_assets_quarantine_gate("evidence file could not be read"))?;
    let actual_evidence_sha256 = format!("{:x}", Sha256::digest(&bytes));
    if actual_evidence_sha256 != args.expected_evidence_sha256 {
        return Err(failed_assets_quarantine_gate(
            "evidence SHA-256 did not match the expected fingerprint",
        ));
    }
    let evidence: Vec<FailedAssetsQuarantineEvidenceAsset> = serde_json::from_slice(&bytes)
        .map_err(|_| {
            failed_assets_quarantine_gate("evidence JSON did not match the quarantine schema")
        })?;
    validate_failed_assets_quarantine_evidence(evidence, actual_evidence_sha256, args)
}

fn validate_failed_assets_quarantine_evidence(
    evidence: Vec<FailedAssetsQuarantineEvidenceAsset>,
    evidence_sha256: String,
    args: &MonitorFailedAssetsQuarantineArgs,
) -> Result<VerifiedFailedAssetsQuarantineEvidence, CliError> {
    let failed_assets = failed_assets_quarantine_asset_map(
        evidence,
        "evidence contains an empty or duplicate asset ID",
    )?;
    if failed_assets.is_empty() {
        return Err(failed_assets_quarantine_gate(
            "evidence failed-asset set must be nonempty",
        ));
    }
    let side_effect_assets = failed_assets
        .values()
        .filter(|asset| asset.has_remote_side_effect())
        .cloned()
        .map(|asset| (asset.asset_id.clone(), asset))
        .collect::<BTreeMap<_, _>>();
    let failed_asset_count = u64::try_from(failed_assets.len()).map_err(|_| {
        failed_assets_quarantine_gate("failed-asset count exceeded the supported range")
    })?;
    let side_effect_asset_count = u64::try_from(side_effect_assets.len()).map_err(|_| {
        failed_assets_quarantine_gate("side-effect target count exceeded the supported range")
    })?;
    let counts = FailedAssetsQuarantineCounts {
        failed_assets: failed_asset_count,
        with_upload_or_delete_side_effects: side_effect_asset_count,
        clean_of_recorded_remote_side_effects: failed_asset_count
            .checked_sub(side_effect_asset_count)
            .ok_or_else(|| {
                failed_assets_quarantine_gate("derived clean-asset count was invalid")
            })?,
        side_effect_assets: side_effect_asset_count,
    };
    if counts.side_effect_assets == 0 {
        return Err(failed_assets_quarantine_gate(
            "evidence target set must be nonempty",
        ));
    }
    if counts.failed_assets != args.expected_failed_asset_count {
        return Err(failed_assets_quarantine_gate(
            "failed-asset count did not match the expected value",
        ));
    }
    if counts.side_effect_assets != args.expected_side_effect_asset_count {
        return Err(failed_assets_quarantine_gate(
            "side-effect target count did not match the expected value",
        ));
    }
    Ok(VerifiedFailedAssetsQuarantineEvidence {
        evidence_sha256,
        failed_asset_ids: failed_assets.into_keys().collect(),
        side_effect_assets,
        counts,
    })
}

fn validate_failed_assets_quarantine_failed_cohort(
    manifest: &Manifest,
    expected_failed_asset_ids: &BTreeSet<String>,
) -> Result<(), CliError> {
    let current_failed_asset_ids = manifest
        .records()
        .iter()
        .filter(|(_, record)| record.state == State::Failed)
        .map(|(asset_id, _)| asset_id.clone())
        .collect::<BTreeSet<_>>();
    if &current_failed_asset_ids != expected_failed_asset_ids {
        return Err(failed_assets_quarantine_gate(
            "current Failed asset IDs did not exactly match the evidence asset IDs",
        ));
    }
    Ok(())
}

fn failed_assets_quarantine_asset_map(
    assets: Vec<FailedAssetsQuarantineEvidenceAsset>,
    error: &'static str,
) -> Result<BTreeMap<String, FailedAssetsQuarantineEvidenceAsset>, CliError> {
    let mut by_asset_id = BTreeMap::new();
    for asset in assets {
        if asset.asset_id.trim().is_empty()
            || by_asset_id.insert(asset.asset_id.clone(), asset).is_some()
        {
            return Err(failed_assets_quarantine_gate(error));
        }
    }
    Ok(by_asset_id)
}

fn validate_failed_assets_quarantine_target_set_preflight(
    args: &MonitorFailedAssetsQuarantineArgs,
) -> Result<Option<&str>, CliError> {
    let expected_target_set_sha256 = args.expected_target_set_sha256.as_deref();
    if args.apply && expected_target_set_sha256.is_none() {
        return Err(failed_assets_quarantine_gate(
            "apply requires an expected target-set SHA-256",
        ));
    }
    if expected_target_set_sha256.is_some_and(|value| !is_sha256_fingerprint(value)) {
        return Err(failed_assets_quarantine_gate(
            "expected target-set SHA-256 must be 64 hexadecimal characters",
        ));
    }
    Ok(expected_target_set_sha256)
}

fn failed_assets_quarantine_target_set_sha256(
    manifest: &Manifest,
    targets: &BTreeMap<String, FailedAssetsQuarantineEvidenceAsset>,
) -> Result<String, CliError> {
    let target_asset_ids = targets.keys().cloned().collect::<Vec<_>>();
    let failed_asset_ids = manifest
        .records()
        .iter()
        .filter(|(_, record)| record.state == State::Failed)
        .map(|(asset_id, _)| asset_id.clone())
        .collect::<Vec<_>>();
    let mut record_digests = BTreeMap::<String, [u8; 32]>::new();
    for asset_id in target_asset_ids.iter().chain(failed_asset_ids.iter()) {
        if record_digests.contains_key(asset_id) {
            continue;
        }
        let record = manifest.records().get(asset_id).ok_or_else(|| {
            failed_assets_quarantine_gate("a current record was missing from the fingerprint")
        })?;
        let exact_record = serde_json::to_vec(record).map_err(|_| {
            failed_assets_quarantine_gate("a target record could not be fingerprinted")
        })?;
        record_digests.insert(asset_id.clone(), Sha256::digest(exact_record).into());
    }
    let mut encoded = Vec::new();
    failed_assets_quarantine_target_set_append_field(
        &mut encoded,
        FAILED_ASSETS_QUARANTINE_TARGET_SET_FINGERPRINT_VERSION,
    );
    failed_assets_quarantine_target_set_append_record_digest_section(
        &mut encoded,
        b"side-effect-targets",
        &target_asset_ids,
        &record_digests,
    )?;
    failed_assets_quarantine_target_set_append_record_digest_section(
        &mut encoded,
        b"failed-cohort",
        &failed_asset_ids,
        &record_digests,
    )?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

fn failed_assets_quarantine_target_set_append_record_digest_section(
    encoded: &mut Vec<u8>,
    section_name: &[u8],
    asset_ids: &[String],
    record_digests: &BTreeMap<String, [u8; 32]>,
) -> Result<(), CliError> {
    failed_assets_quarantine_target_set_append_field(encoded, section_name);
    failed_assets_quarantine_target_set_append_field(
        encoded,
        &u64::try_from(asset_ids.len())
            .map_err(|_| {
                failed_assets_quarantine_gate(
                    "fingerprint record count exceeded the supported range",
                )
            })?
            .to_be_bytes(),
    );
    for asset_id in asset_ids {
        failed_assets_quarantine_target_set_append_field(encoded, asset_id.as_bytes());
        let digest = record_digests.get(asset_id).ok_or_else(|| {
            failed_assets_quarantine_gate(
                "a current record digest was missing from the fingerprint",
            )
        })?;
        failed_assets_quarantine_target_set_append_field(encoded, digest);
    }
    Ok(())
}

fn failed_assets_quarantine_target_set_append_field(encoded: &mut Vec<u8>, value: &[u8]) {
    encoded.extend_from_slice(&(value.len() as u64).to_be_bytes());
    encoded.extend_from_slice(value);
}

fn validate_failed_assets_quarantine_target_set_match(
    expected_target_set_sha256: &str,
    target_set_sha256: &str,
) -> Result<(), CliError> {
    if expected_target_set_sha256 != target_set_sha256 {
        return Err(failed_assets_quarantine_gate(
            "target set did not match the expected fingerprint",
        ));
    }
    Ok(())
}

fn failed_assets_quarantine_expected_records(
    manifest: &Manifest,
    targets: &BTreeMap<String, FailedAssetsQuarantineEvidenceAsset>,
) -> Result<BTreeMap<String, AssetRecord>, CliError> {
    targets
        .keys()
        .map(|asset_id| {
            let record = manifest.records().get(asset_id).ok_or_else(|| {
                failed_assets_quarantine_gate("a target was missing from the current state")
            })?;
            if record.state != State::Failed {
                return Err(failed_assets_quarantine_gate(
                    "every target must remain exactly Failed before apply",
                ));
            }
            Ok((asset_id.clone(), record.clone()))
        })
        .collect()
}

fn apply_failed_assets_quarantine(
    manifest: &mut Manifest,
    evidence: &VerifiedFailedAssetsQuarantineEvidence,
    target_set_sha256: &str,
    applied_at_unix_seconds: u64,
) -> Result<Vec<AssetRecord>, CliError> {
    evidence
        .side_effect_assets
        .values()
        .map(|asset| {
            manifest
                .quarantine_failed_for_historical_remote_side_effect(
                    &asset.asset_id,
                    FailureQuarantineProof::historical_remote_side_effect(
                        evidence.evidence_sha256.clone(),
                        target_set_sha256.to_string(),
                        asset.successful_uploads,
                        asset.delete_attempts,
                        asset.deleted_finishes,
                        asset.mirror_successes,
                        applied_at_unix_seconds,
                    ),
                )
                .cloned()
                .map_err(|_| {
                    failed_assets_quarantine_gate(
                        "a target could not transition from Failed to NeedsReview",
                    )
                })
        })
        .collect()
}

fn persist_failed_assets_quarantine_updates(
    state_store: &AssetStateStore,
    expected_records: &BTreeMap<String, AssetRecord>,
    changed_records: &[AssetRecord],
    expected_changed_count: u64,
) -> Result<(), CliError> {
    if u64::try_from(changed_records.len()).map_err(|_| {
        failed_assets_quarantine_gate("quarantine update count exceeded the supported range")
    })? != expected_changed_count
    {
        return Err(failed_assets_quarantine_gate(
            "quarantine updates did not match the complete target set",
        ));
    }
    state_store
        .persist_records_exact_cas_atomic(
            changed_records
                .iter()
                .map(|updated| {
                    let expected = expected_records.get(&updated.asset_id).ok_or_else(|| {
                        failed_assets_quarantine_gate(
                            "quarantine update did not have a pre-update state snapshot",
                        )
                    })?;
                    Ok(AssetRecordExactCasUpdate { expected, updated })
                })
                .collect::<Result<Vec<_>, CliError>>()?,
        )
        .map(|_| ())
        .map_err(failed_assets_quarantine_persistence_error)
}

fn failed_assets_quarantine_persistence_error(error: AssetStateStoreError) -> CliError {
    match error {
        AssetStateStoreError::ExactCasMismatch { .. } => failed_assets_quarantine_gate(
            "current state changed before the atomic quarantine commit",
        ),
        _ => failed_assets_quarantine_gate("atomic quarantine state commit did not complete"),
    }
}

fn ensure_failed_assets_quarantine_checkpoint(
    export: impl FnOnce() -> Result<Manifest, AssetStateStoreError>,
) -> Result<(), CliError> {
    export()
        .map(|_| ())
        .map_err(|_| CliError::FailedAssetsQuarantineCheckpointStale)
}

#[derive(Clone, Debug, Default, Serialize)]
struct LegacyFailuresClassifyCounts {
    records_scanned: u64,
    candidates: u64,
    non_failed: u64,
    missing_last_failure: u64,
    already_typed_last_failure: u64,
    downstream_proof_ambiguity: u64,
    classifier_mismatch: u64,
}

#[derive(Debug)]
struct LegacyFailuresClassifyCandidates {
    targets: BTreeMap<String, AssetRecord>,
    counts: LegacyFailuresClassifyCounts,
}

#[derive(Serialize)]
struct LegacyFailuresClassifyReport {
    target_set_sha256: String,
    counts: LegacyFailuresClassifyCounts,
    verified: bool,
    applied: bool,
    changed_count: u64,
}

fn monitor_legacy_failures_classify<W: Write>(
    args: MonitorLegacyFailuresClassifyArgs,
    writer: &mut W,
) -> Result<(), CliError> {
    let (expected_target_set_sha256, expected_candidate_count) =
        validate_legacy_failures_classify_preflight(&args)?;
    let config = MonitorConfig::load(&args.config)
        .map_err(|_| legacy_failures_classify_gate("monitor configuration could not be loaded"))?;
    config.validate().map_err(|_| {
        legacy_failures_classify_gate("monitor configuration did not pass validation")
    })?;

    let (target_set_sha256, counts, applied, changed_count) = if args.apply {
        let mut guard = acquire_monitor_run_guard(&config).map_err(|_| {
            legacy_failures_classify_gate(
                "monitor process lock or writer lease could not be acquired",
            )
        })?;
        let state_store = guard
            .state_store(&config.manifest_path)
            .map_err(|_| legacy_failures_classify_gate("writer lease could not be acquired"))?;
        let mut manifest = state_store.load().map_err(|_| {
            legacy_failures_classify_gate(
                "current state could not be loaded under the writer lease",
            )
        })?;
        let candidates = legacy_failures_classify_candidates(&manifest);
        let target_set_sha256 = legacy_failures_classify_target_set_sha256(&candidates.targets)?;
        validate_legacy_failures_classify_expectations(
            expected_target_set_sha256,
            expected_candidate_count,
            &target_set_sha256,
            candidates.counts.candidates,
        )?;
        let expected_records = candidates.targets;
        let changed_records =
            type_legacy_missing_preview_failures(&mut manifest, &expected_records)?;
        let changed_count = u64::try_from(changed_records.len()).map_err(|_| {
            legacy_failures_classify_gate("migration update count exceeded the supported range")
        })?;
        persist_legacy_failures_classify_updates(
            state_store,
            &expected_records,
            &changed_records,
            candidates.counts.candidates,
        )?;
        ensure_legacy_failures_classify_checkpoint(|| state_store.export_json())?;
        (target_set_sha256, candidates.counts, true, changed_count)
    } else {
        let state_store = AssetStateStore::open_immutable_read_only(&config.manifest_path)
            .map_err(|_| {
                legacy_failures_classify_gate("immutable state snapshot could not be opened")
            })?;
        let manifest = state_store.load().map_err(|_| {
            legacy_failures_classify_gate("immutable state snapshot could not be loaded")
        })?;
        let candidates = legacy_failures_classify_candidates(&manifest);
        let target_set_sha256 = legacy_failures_classify_target_set_sha256(&candidates.targets)?;
        validate_legacy_failures_classify_expectations(
            expected_target_set_sha256,
            expected_candidate_count,
            &target_set_sha256,
            candidates.counts.candidates,
        )?;
        state_store
            .revalidate_immutable_read_snapshot()
            .map_err(|_| {
                legacy_failures_classify_gate(
                    "immutable state changed while the dry-run was verifying",
                )
            })?;
        (target_set_sha256, candidates.counts, false, 0)
    };

    let report = LegacyFailuresClassifyReport {
        target_set_sha256,
        counts,
        verified: true,
        applied,
        changed_count,
    };
    write_legacy_failures_classify_report(&report, writer).map_err(|_| {
        if applied {
            CliError::LegacyFailuresClassifyReportOutputAfterCommit
        } else {
            CliError::LegacyFailuresClassifyDryRunReportOutput
        }
    })
}

fn write_legacy_failures_classify_report<W: Write>(
    report: &LegacyFailuresClassifyReport,
    writer: &mut W,
) -> Result<(), ()> {
    serde_json::to_writer_pretty(&mut *writer, report).map_err(|_| ())?;
    writeln!(writer).map_err(|_| ())
}

fn validate_legacy_failures_classify_preflight(
    args: &MonitorLegacyFailuresClassifyArgs,
) -> Result<(Option<&str>, Option<u64>), CliError> {
    let expected_target_set_sha256 = args.expected_target_set_sha256.as_deref();
    if args.apply && expected_target_set_sha256.is_none() {
        return Err(legacy_failures_classify_gate(
            "apply requires an expected target-set SHA-256",
        ));
    }
    if expected_target_set_sha256.is_some_and(|value| !is_sha256_fingerprint(value)) {
        return Err(legacy_failures_classify_gate(
            "expected target-set SHA-256 must be 64 hexadecimal characters",
        ));
    }
    if args.apply && args.expected_candidate_count.is_none() {
        return Err(legacy_failures_classify_gate(
            "apply requires an expected candidate count",
        ));
    }
    Ok((expected_target_set_sha256, args.expected_candidate_count))
}

fn legacy_failures_classify_candidates(manifest: &Manifest) -> LegacyFailuresClassifyCandidates {
    let mut targets = BTreeMap::new();
    let mut counts = LegacyFailuresClassifyCounts::default();
    for (asset_id, record) in manifest.records() {
        counts.records_scanned = counts.records_scanned.saturating_add(1);
        match classify_legacy_embedded_preview_migration(record) {
            LegacyEmbeddedPreviewMigrationClassification::Candidate => {
                counts.candidates = counts.candidates.saturating_add(1);
                targets.insert(asset_id.clone(), record.clone());
            }
            LegacyEmbeddedPreviewMigrationClassification::NonFailed => {
                counts.non_failed = counts.non_failed.saturating_add(1);
            }
            LegacyEmbeddedPreviewMigrationClassification::MissingLastFailure => {
                counts.missing_last_failure = counts.missing_last_failure.saturating_add(1);
            }
            LegacyEmbeddedPreviewMigrationClassification::AlreadyTypedLastFailure => {
                counts.already_typed_last_failure =
                    counts.already_typed_last_failure.saturating_add(1);
            }
            LegacyEmbeddedPreviewMigrationClassification::DownstreamProofAmbiguity => {
                counts.downstream_proof_ambiguity =
                    counts.downstream_proof_ambiguity.saturating_add(1);
            }
            LegacyEmbeddedPreviewMigrationClassification::ClassifierMismatch => {
                counts.classifier_mismatch = counts.classifier_mismatch.saturating_add(1);
            }
        }
    }
    LegacyFailuresClassifyCandidates { targets, counts }
}

fn legacy_failures_classify_target_set_sha256(
    targets: &BTreeMap<String, AssetRecord>,
) -> Result<String, CliError> {
    let mut encoded = Vec::new();
    legacy_failures_classify_target_set_append_field(
        &mut encoded,
        LEGACY_FAILURES_CLASSIFY_TARGET_SET_FINGERPRINT_VERSION,
    );
    let target_count = u64::try_from(targets.len()).map_err(|_| {
        legacy_failures_classify_gate("candidate count exceeded the supported range")
    })?;
    legacy_failures_classify_target_set_append_field(&mut encoded, &target_count.to_be_bytes());
    for (asset_id, record) in targets {
        let exact_record = serde_json::to_vec(record).map_err(|_| {
            legacy_failures_classify_gate("a candidate record could not be fingerprinted")
        })?;
        legacy_failures_classify_target_set_append_field(&mut encoded, asset_id.as_bytes());
        legacy_failures_classify_target_set_append_field(
            &mut encoded,
            Sha256::digest(exact_record).as_slice(),
        );
    }
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

fn legacy_failures_classify_target_set_append_field(encoded: &mut Vec<u8>, value: &[u8]) {
    encoded.extend_from_slice(&(value.len() as u64).to_be_bytes());
    encoded.extend_from_slice(value);
}

fn validate_legacy_failures_classify_expectations(
    expected_target_set_sha256: Option<&str>,
    expected_candidate_count: Option<u64>,
    target_set_sha256: &str,
    candidate_count: u64,
) -> Result<(), CliError> {
    if expected_candidate_count.is_some_and(|expected| expected != candidate_count) {
        return Err(legacy_failures_classify_gate(
            "candidate count did not match the expected value",
        ));
    }
    if expected_target_set_sha256
        .is_some_and(|expected| !expected.eq_ignore_ascii_case(target_set_sha256))
    {
        return Err(legacy_failures_classify_gate(
            "target set did not match the expected fingerprint",
        ));
    }
    Ok(())
}

fn type_legacy_missing_preview_failures(
    manifest: &mut Manifest,
    expected_records: &BTreeMap<String, AssetRecord>,
) -> Result<Vec<AssetRecord>, CliError> {
    expected_records
        .keys()
        .map(|asset_id| {
            let mut updated = manifest.records().get(asset_id).cloned().ok_or_else(|| {
                legacy_failures_classify_gate("a candidate was missing from the current state")
            })?;
            if classify_legacy_embedded_preview_migration(&updated)
                != LegacyEmbeddedPreviewMigrationClassification::Candidate
            {
                return Err(legacy_failures_classify_gate(
                    "a candidate no longer matched the exact legacy classification",
                ));
            }
            let last_failure = updated.failures.last_mut().ok_or_else(|| {
                legacy_failures_classify_gate("a candidate no longer had a final failure")
            })?;
            last_failure.kind = Some(FailureKind::EmbeddedPreviewUnavailable);
            manifest.upsert(updated.clone());
            Ok(updated)
        })
        .collect()
}

fn persist_legacy_failures_classify_updates(
    state_store: &AssetStateStore,
    expected_records: &BTreeMap<String, AssetRecord>,
    changed_records: &[AssetRecord],
    expected_changed_count: u64,
) -> Result<(), CliError> {
    if u64::try_from(changed_records.len()).map_err(|_| {
        legacy_failures_classify_gate("migration update count exceeded the supported range")
    })? != expected_changed_count
    {
        return Err(legacy_failures_classify_gate(
            "migration updates did not match the complete candidate set",
        ));
    }
    state_store
        .persist_records_exact_cas_atomic(
            changed_records
                .iter()
                .map(|updated| {
                    let expected = expected_records.get(&updated.asset_id).ok_or_else(|| {
                        legacy_failures_classify_gate(
                            "migration update did not have a pre-update state snapshot",
                        )
                    })?;
                    Ok(AssetRecordExactCasUpdate { expected, updated })
                })
                .collect::<Result<Vec<_>, CliError>>()?,
        )
        .map(|_| ())
        .map_err(legacy_failures_classify_persistence_error)
}

fn legacy_failures_classify_persistence_error(error: AssetStateStoreError) -> CliError {
    match error {
        AssetStateStoreError::ExactCasMismatch { .. } => legacy_failures_classify_gate(
            "current state changed before the atomic migration commit",
        ),
        _ => legacy_failures_classify_gate("atomic migration state commit did not complete"),
    }
}

fn ensure_legacy_failures_classify_checkpoint(
    export: impl FnOnce() -> Result<Manifest, AssetStateStoreError>,
) -> Result<(), CliError> {
    export()
        .map(|_| ())
        .map_err(|_| CliError::LegacyFailuresClassifyCheckpointStale)
}

fn monitor_original_assets_reconcile_with_transport<
    W: Write,
    T: CloudKitOriginalAssetReadTransport,
>(
    args: MonitorOriginalAssetsReconcileArgs,
    writer: &mut W,
    transport: T,
) -> Result<(), CliError> {
    let config = MonitorConfig::load(&args.config).map_err(|error| {
        original_assets_reconcile_stage_failure(
            error,
            OriginalAssetsReconcileFailureStage::Configuration,
        )
    })?;
    config.validate().map_err(|_| {
        original_assets_reconcile_failure(OriginalAssetsReconcileFailureStage::Configuration)
    })?;
    let expectations = OriginalAssetsReconcileExpectations::from_args(&args).map_err(|_| {
        original_assets_reconcile_failure(OriginalAssetsReconcileFailureStage::Configuration)
    })?;
    let canonical_library_root = fs::canonicalize(&config.download_root).map_err(|_| {
        original_assets_reconcile_failure(OriginalAssetsReconcileFailureStage::Root)
    })?;
    run_scan_root_preflight_probe(&canonical_library_root).map_err(|_| {
        original_assets_reconcile_failure(OriginalAssetsReconcileFailureStage::Root)
    })?;

    let mut guard = args
        .apply
        .then(|| acquire_monitor_run_guard(&config))
        .transpose()
        .map_err(|_| {
            original_assets_reconcile_failure(OriginalAssetsReconcileFailureStage::State)
        })?;
    let state_store = match guard.as_mut() {
        Some(guard) => guard
            .state_store(&config.manifest_path)
            .map_err(|_| {
                original_assets_reconcile_failure(OriginalAssetsReconcileFailureStage::State)
            })?
            .clone(),
        None => AssetStateStore::open_immutable_read_only(&config.manifest_path).map_err(|_| {
            original_assets_reconcile_failure(OriginalAssetsReconcileFailureStage::State)
        })?,
    };
    let mut manifest = state_store.load().map_err(|_| {
        original_assets_reconcile_failure(OriginalAssetsReconcileFailureStage::State)
    })?;
    let (mut destination_targets, skipped_targets, _) = original_assets_audit_targets(
        &manifest,
        &canonical_library_root,
        &config.download_root,
        config.capture_tolerance_seconds,
    );
    let selected_targets = destination_targets
        .remove(&expectations.destination)
        .unwrap_or_default();
    let selected_target_count = selected_targets.len() as u64;
    let target_set_sha256 =
        original_assets_target_set_sha256(&expectations.destination, &selected_targets);
    let unselected_destination_targets = destination_targets
        .values()
        .map(|targets| targets.len() as u64)
        .sum();
    let skipped_targets = skipped_targets as u64;

    validate_original_assets_reconcile_target_gates(
        &expectations,
        selected_target_count,
        unselected_destination_targets,
        skipped_targets,
    )?;
    validate_original_assets_reconcile_target_set_gate(&expectations, &target_set_sha256)?;
    let expected_records = if args.apply {
        selected_targets
            .iter()
            .map(|target| {
                manifest
                    .records()
                    .get(&target.asset_id)
                    .cloned()
                    .ok_or_else(|| {
                        original_assets_reconcile_gate(
                            "selected target no longer has a manifest record",
                        )
                    })
                    .map(|record| (target.asset_id.clone(), record))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?
    } else {
        BTreeMap::new()
    };

    let session_path = config.delete_session_path.as_deref().ok_or_else(|| {
        original_assets_reconcile_gate("original-assets-reconcile requires delete_session_path")
    })?;
    let session = load_cloudkit_delete_session(session_path).map_err(|_| {
        original_assets_reconcile_failure(OriginalAssetsReconcileFailureStage::Session)
    })?;
    let outcome = resolve_original_assets_audit_destination(
        &session,
        &expectations.destination,
        &selected_targets,
        &config,
        transport,
    )
    .map_err(original_assets_reconcile_cloudkit_failure)?;
    if !args.apply {
        state_store
            .revalidate_immutable_read_snapshot()
            .map_err(|_| {
                original_assets_reconcile_failure(OriginalAssetsReconcileFailureStage::State)
            })?;
    }
    let (verified, applied, changed_count, commit_elapsed_millis) = if args.apply {
        let (verified, changed_records) = apply_verified_original_assets_reconcile(
            &mut manifest,
            &expectations,
            selected_targets,
            unselected_destination_targets,
            skipped_targets,
            outcome,
            current_unix_seconds_for_cli(),
        )
        .map_err(|_| {
            original_assets_reconcile_failure(OriginalAssetsReconcileFailureStage::Domain)
        })?;
        let changed_count = changed_records.len() as u64;
        validate_original_assets_reconcile_update_set(&expected_records, &changed_records)?;
        let elapsed = state_store
            .persist_records_exact_cas_atomic(
                changed_records
                    .iter()
                    .map(|updated| {
                        expected_records
                        .get(&updated.asset_id)
                        .map(|expected| AssetRecordExactCasUpdate { expected, updated })
                        .ok_or_else(|| {
                            original_assets_reconcile_gate(
                                "reconciliation update did not have a pre-scan manifest snapshot",
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )
            .map_err(|_| {
                original_assets_reconcile_failure(OriginalAssetsReconcileFailureStage::Persistence)
            })?;
        ensure_original_assets_reconcile_checkpoint(|| state_store.export_json())?;
        (verified, true, changed_count, elapsed.as_millis())
    } else {
        (
            verify_original_assets_reconcile_outcome(
                &expectations,
                &selected_targets,
                unselected_destination_targets,
                skipped_targets,
                &outcome,
            )?,
            false,
            0,
            0,
        )
    };

    let report = OriginalAssetsReconcileReport {
        destination: expectations.destination,
        target_set_sha256,
        counts: OriginalAssetsReconcileCounts {
            selected_targets: selected_target_count,
            unselected_destination_targets,
            skipped_targets,
            dispositions: verified.disposition_counts,
        },
        inventory: verified.inventory,
        verified: true,
        applied,
        changed_count,
        commit_elapsed_millis,
    };
    serde_json::to_writer_pretty(&mut *writer, &report).map_err(|_| {
        original_assets_reconcile_failure(OriginalAssetsReconcileFailureStage::Output)
    })?;
    writeln!(writer).map_err(|_| {
        original_assets_reconcile_failure(OriginalAssetsReconcileFailureStage::Output)
    })?;
    Ok(())
}

fn validate_original_assets_reconcile_target_gates(
    expectations: &OriginalAssetsReconcileExpectations,
    selected_target_count: u64,
    unselected_destination_target_count: u64,
    skipped_target_count: u64,
) -> Result<(), CliError> {
    if selected_target_count == 0 {
        return Err(original_assets_reconcile_gate(
            "selected target count must be positive",
        ));
    }
    if selected_target_count != expectations.selected_target_count {
        return Err(original_assets_reconcile_gate(
            "selected target count did not match the expected value",
        ));
    }
    if unselected_destination_target_count != expectations.unselected_destination_target_count {
        return Err(original_assets_reconcile_gate(
            "unselected-destination target count did not match the expected value",
        ));
    }
    if skipped_target_count != expectations.skipped_target_count {
        return Err(original_assets_reconcile_gate(
            "skipped target count did not match the expected value",
        ));
    }
    Ok(())
}

fn verify_original_assets_reconcile_outcome(
    expectations: &OriginalAssetsReconcileExpectations,
    selected_targets: &[CloudKitOriginalAssetResolveTarget],
    unselected_destination_target_count: u64,
    skipped_target_count: u64,
    outcome: &CloudKitOriginalAssetBatchResolveOutcome,
) -> Result<VerifiedOriginalAssetsReconcileOutcome, CliError> {
    validate_original_assets_reconcile_target_gates(
        expectations,
        selected_targets.len() as u64,
        unselected_destination_target_count,
        skipped_target_count,
    )?;
    validate_original_assets_reconcile_target_set_gate(
        expectations,
        &original_assets_target_set_sha256(&expectations.destination, selected_targets),
    )?;
    let target_ids = selected_targets
        .iter()
        .map(|target| target.asset_id.as_str())
        .collect::<BTreeSet<_>>();
    let resolution_ids = outcome
        .resolutions
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if target_ids != resolution_ids {
        return Err(original_assets_reconcile_gate(
            "resolved target set did not match the selected target set",
        ));
    }
    let inventory = outcome.inventory.clone().ok_or_else(|| {
        original_assets_reconcile_gate("CloudKit response did not include an inventory fingerprint")
    })?;
    if inventory.resolver_version != crate::upload::CLOUDKIT_ORIGINAL_ASSET_RESOLVER_VERSION {
        return Err(original_assets_reconcile_gate(
            "CloudKit inventory resolver version was not recognized",
        ));
    }
    if !is_sha256_fingerprint(&inventory.sha256) {
        return Err(original_assets_reconcile_gate(
            "CloudKit inventory SHA-256 was invalid",
        ));
    }
    if inventory.sha256 != expectations.inventory_sha256 {
        return Err(original_assets_reconcile_gate(
            "inventory SHA-256 did not match the expected fingerprint",
        ));
    }
    if inventory.records_scanned != expectations.records_scanned {
        return Err(original_assets_reconcile_gate(
            "inventory records-scanned count did not match the expected value",
        ));
    }
    let disposition_counts =
        OriginalAssetsReconcileDispositionCounts::from_resolutions(&outcome.resolutions);
    if disposition_counts != expectations.disposition_counts {
        return Err(original_assets_reconcile_gate(
            "CloudKit disposition counts did not match the expected values",
        ));
    }
    if disposition_counts.incomplete_transient != 0 {
        return Err(original_assets_reconcile_gate(
            "CloudKit resolution contained incomplete or transient results",
        ));
    }
    Ok(VerifiedOriginalAssetsReconcileOutcome {
        inventory,
        disposition_counts,
    })
}

fn apply_verified_original_assets_reconcile(
    manifest: &mut Manifest,
    expectations: &OriginalAssetsReconcileExpectations,
    selected_targets: Vec<CloudKitOriginalAssetResolveTarget>,
    unselected_destination_target_count: u64,
    skipped_target_count: u64,
    outcome: CloudKitOriginalAssetBatchResolveOutcome,
    observed_at_unix_seconds: u64,
) -> Result<(VerifiedOriginalAssetsReconcileOutcome, Vec<AssetRecord>), CliError> {
    let verified = verify_original_assets_reconcile_outcome(
        expectations,
        &selected_targets,
        unselected_destination_target_count,
        skipped_target_count,
        &outcome,
    )?;
    let batch = OriginalAssetResolutionBatch {
        targets: selected_targets,
        destination: expectations.destination.clone(),
        inventory: verified.inventory.clone(),
        observed_at_unix_seconds,
        resolutions: outcome.resolutions,
    };
    let apply_result = manifest.apply_original_asset_resolution_batch(batch)?;
    Ok((verified, apply_result.changed_records))
}

fn original_assets_reconcile_gate(message: impl Into<String>) -> CliError {
    CliError::OriginalAssetsReconcileGate {
        message: message.into(),
    }
}

fn failed_assets_quarantine_gate(message: impl Into<String>) -> CliError {
    CliError::FailedAssetsQuarantineGate {
        message: message.into(),
    }
}

fn legacy_failures_classify_gate(message: impl Into<String>) -> CliError {
    CliError::LegacyFailuresClassifyGate {
        message: message.into(),
    }
}

fn original_assets_reconcile_failure(stage: OriginalAssetsReconcileFailureStage) -> CliError {
    CliError::OriginalAssetsReconcileFailure { stage }
}

fn original_assets_reconcile_stage_failure<E>(
    _error: E,
    stage: OriginalAssetsReconcileFailureStage,
) -> CliError {
    original_assets_reconcile_failure(stage)
}

fn original_assets_reconcile_cloudkit_failure(error: UploadError) -> CliError {
    let kind = match error {
        UploadError::InvalidSession(_) | UploadError::DecodeSession { .. } => {
            OriginalAssetsReconcileCloudKitFailureKind::Authentication
        }
        UploadError::MalformedCloudKitResponse { .. }
        | UploadError::InvalidCloudKitOriginalAssetResponse(_) => {
            OriginalAssetsReconcileCloudKitFailureKind::MalformedResponse
        }
        UploadError::Network { .. }
        | UploadError::HttpClient { .. }
        | UploadError::UploadHttpStatus { .. }
        | UploadError::ReadUploadResponse { .. } => {
            OriginalAssetsReconcileCloudKitFailureKind::Transport
        }
        _ => OriginalAssetsReconcileCloudKitFailureKind::Transient,
    };
    CliError::OriginalAssetsReconcileCloudKitFailure { kind }
}

fn validate_original_assets_reconcile_target_set_gate(
    expectations: &OriginalAssetsReconcileExpectations,
    target_set_sha256: &str,
) -> Result<(), CliError> {
    if expectations.target_set_sha256 != target_set_sha256 {
        return Err(original_assets_reconcile_gate(
            "selected target set did not match the expected fingerprint",
        ));
    }
    Ok(())
}

fn validate_original_assets_reconcile_update_set(
    expected_records: &BTreeMap<String, AssetRecord>,
    changed_records: &[AssetRecord],
) -> Result<(), CliError> {
    let changed_ids = changed_records
        .iter()
        .map(|record| record.asset_id.as_str())
        .collect::<BTreeSet<_>>();
    let expected_ids = expected_records
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if changed_ids != expected_ids || changed_records.len() != expected_records.len() {
        return Err(original_assets_reconcile_gate(
            "reconciliation updates did not match the complete pre-scan target set",
        ));
    }
    Ok(())
}

fn ensure_original_assets_reconcile_checkpoint(
    export: impl FnOnce() -> Result<Manifest, AssetStateStoreError>,
) -> Result<(), CliError> {
    export()
        .map(|_| ())
        .map_err(|_| CliError::OriginalAssetsReconcileCheckpointStale)
}

fn is_sha256_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn original_assets_target_set_sha256(
    destination: &CloudKitLibraryDestination,
    targets: &[CloudKitOriginalAssetResolveTarget],
) -> String {
    let mut encoded = Vec::new();
    original_assets_target_set_append_bytes_field(
        &mut encoded,
        ORIGINAL_ASSETS_TARGET_SET_FINGERPRINT_VERSION,
    );
    original_assets_target_set_append_bytes_field(
        &mut encoded,
        destination.database_scope.as_str().as_bytes(),
    );
    original_assets_target_set_append_bytes_field(&mut encoded, destination.zone_name.as_bytes());
    let mut encoded_targets = targets
        .iter()
        .map(original_assets_target_set_target_bytes)
        .collect::<Vec<_>>();
    encoded_targets.sort();
    original_assets_target_set_append_bytes_field(
        &mut encoded,
        &(encoded_targets.len() as u64).to_be_bytes(),
    );
    for encoded_target in encoded_targets {
        original_assets_target_set_append_bytes_field(&mut encoded, &encoded_target);
    }
    format!("{:x}", Sha256::digest(encoded))
}

fn original_assets_target_set_target_bytes(target: &CloudKitOriginalAssetResolveTarget) -> Vec<u8> {
    let mut encoded = Vec::new();
    original_assets_target_set_append_bytes_field(&mut encoded, target.asset_id.as_bytes());
    original_assets_target_set_append_bytes_field(
        &mut encoded,
        &target.source_captured_unix_seconds.to_be_bytes(),
    );
    original_assets_target_set_append_bytes_field(
        &mut encoded,
        &target.capture_tolerance_seconds.to_be_bytes(),
    );
    original_assets_target_set_append_bytes_field(&mut encoded, target.filename.as_bytes());
    original_assets_target_set_append_bytes_field(
        &mut encoded,
        &target.raw_size_bytes.to_be_bytes(),
    );
    original_assets_target_set_append_bytes_field(
        &mut encoded,
        target.matched_raw_sha256.as_bytes(),
    );
    match &target.replacement_candidate {
        Some(candidate) => {
            original_assets_target_set_append_bytes_field(&mut encoded, &[1]);
            original_assets_target_set_append_bytes_field(
                &mut encoded,
                &candidate.size_bytes.to_be_bytes(),
            );
            original_assets_target_set_append_bytes_field(
                &mut encoded,
                candidate.sha256.as_bytes(),
            );
        }
        None => original_assets_target_set_append_bytes_field(&mut encoded, &[0]),
    }
    encoded
}

fn original_assets_target_set_append_bytes_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn original_assets_audit_destination_report(
    session: &crate::upload::CloudKitDeleteSession,
    destination: CloudKitLibraryDestination,
    targets: Vec<CloudKitOriginalAssetResolveTarget>,
    config: &MonitorConfig,
) -> OriginalAssetsAuditDestinationReport {
    let started = Instant::now();
    let target_set_sha256 = original_assets_target_set_sha256(&destination, &targets);
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
        target_set_sha256,
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
    let target_set_sha256 = original_assets_target_set_sha256(&destination, &targets);
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
        target_set_sha256,
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
    target_set_sha256: String,
    started: Instant,
    result: Result<CloudKitOriginalAssetBatchResolveOutcome, UploadError>,
) -> OriginalAssetsAuditDestinationReport {
    match result {
        Ok(outcome) => {
            let inventory = outcome.inventory.clone();
            OriginalAssetsAuditDestinationReport {
                destination,
                targets,
                target_set_sha256,
                elapsed_millis: started.elapsed().as_millis(),
                inventory,
                resolutions: redact_audit_resolutions(outcome),
                batch_error: None,
            }
        }
        Err(error) => OriginalAssetsAuditDestinationReport {
            destination,
            targets,
            target_set_sha256,
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
    configured_download_root: &Path,
    capture_tolerance_seconds: u64,
) -> (
    BTreeMap<CloudKitLibraryDestination, Vec<CloudKitOriginalAssetResolveTarget>>,
    usize,
    BTreeMap<String, u64>,
) {
    let mut targets = BTreeMap::new();
    let mut skipped = 0_usize;
    let mut skip_reason_counts = BTreeMap::new();
    let configured_library_destination = configured_download_root
        .file_name()
        .and_then(|component| component.to_str())
        .and_then(original_assets_audit_library_destination);
    for record in manifest.records().values() {
        if !original_assets_audit_eligible(record) {
            continue;
        }
        let target = match original_assets_audit_target(
            record,
            canonical_library_root,
            configured_library_destination.as_ref(),
            capture_tolerance_seconds,
        ) {
            Ok(target) => target,
            Err(reason) => {
                skipped = skipped.saturating_add(1);
                *skip_reason_counts
                    .entry(reason.as_str().to_string())
                    .or_default() += 1;
                continue;
            }
        };
        targets
            .entry(target.destination)
            .or_insert_with(Vec::new)
            .push(target.target);
    }
    (targets, skipped, skip_reason_counts)
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
    configured_library_destination: Option<&CloudKitLibraryDestination>,
    capture_tolerance_seconds: u64,
) -> Result<OriginalAssetsAuditTarget, OriginalAssetsAuditSkipReason> {
    let nas = original_assets_audit_nas_proof(record)?;
    let source_age = original_assets_audit_source_age_proof(record)?;
    let canonical_raw_path = fs::canonicalize(&record.raw_path)
        .map_err(|_| OriginalAssetsAuditSkipReason::RawPathUnavailable)?;
    let relative_raw_path = canonical_raw_path
        .strip_prefix(canonical_library_root)
        .map_err(|_| OriginalAssetsAuditSkipReason::OutsideDownloadRoot)?;
    let destination =
        original_assets_audit_destination(configured_library_destination, relative_raw_path)
            .ok_or(OriginalAssetsAuditSkipReason::UnsupportedLibraryLayout)?;
    let filename = original_assets_audit_filename(&canonical_raw_path)?;
    Ok(OriginalAssetsAuditTarget {
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

fn original_assets_audit_nas_proof(
    record: &AssetRecord,
) -> Result<NasRawProof, OriginalAssetsAuditSkipReason> {
    let nas = record
        .proofs
        .get("nas")
        .cloned()
        .and_then(|proof| serde_json::from_value::<NasRawProof>(proof).ok())
        .ok_or(OriginalAssetsAuditSkipReason::InvalidOrMissingNasProof)?;
    (!nas.canonical_path.as_os_str().is_empty()
        && !nas.relative_path.as_os_str().is_empty()
        && nas.size_bytes > 0
        && !nas.sha256.trim().is_empty())
    .then_some(nas)
    .ok_or(OriginalAssetsAuditSkipReason::InvalidOrMissingNasProof)
}

fn original_assets_audit_source_age_proof(
    record: &AssetRecord,
) -> Result<SourceAgeProof, OriginalAssetsAuditSkipReason> {
    let source_age = record
        .proofs
        .get("source_age")
        .cloned()
        .and_then(|proof| serde_json::from_value::<SourceAgeProof>(proof).ok())
        .ok_or(OriginalAssetsAuditSkipReason::InvalidOrMissingSourceAgeProof)?;
    (source_age.source_captured_unix_seconds > 0
        && source_age.verified_at_unix_seconds >= source_age.source_captured_unix_seconds
        && source_age.min_age_seconds > 0)
        .then_some(source_age)
        .ok_or(OriginalAssetsAuditSkipReason::InvalidOrMissingSourceAgeProof)
}

fn original_assets_audit_filename(
    canonical_raw_path: &Path,
) -> Result<String, OriginalAssetsAuditSkipReason> {
    if !canonical_raw_path.is_file() {
        return Err(OriginalAssetsAuditSkipReason::InvalidFilename);
    }
    canonical_raw_path
        .file_name()
        .and_then(|filename| filename.to_str())
        .filter(|filename| {
            !filename.trim().is_empty()
                && *filename != "."
                && *filename != ".."
                && !filename.contains(['/', '\\'])
        })
        .map(ToOwned::to_owned)
        .ok_or(OriginalAssetsAuditSkipReason::InvalidFilename)
}

fn original_assets_audit_destination(
    configured_library_destination: Option<&CloudKitLibraryDestination>,
    relative_raw_path: &Path,
) -> Option<CloudKitLibraryDestination> {
    if !relative_raw_path
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
    {
        return None;
    }
    configured_library_destination.cloned().or_else(|| {
        relative_raw_path
            .components()
            .next()
            .and_then(|component| match component {
                Component::Normal(component) => component.to_str(),
                _ => None,
            })
            .and_then(original_assets_audit_library_destination)
    })
}

fn original_assets_audit_library_destination(library: &str) -> Option<CloudKitLibraryDestination> {
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
    skip_reason_counts: &BTreeMap<String, u64>,
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
    let skip_reasons = if skip_reason_counts.is_empty() {
        "none".to_string()
    } else {
        skip_reason_counts
            .iter()
            .map(|(reason, count)| format!("{reason}={count}"))
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
        "original-assets-audit: targets={targets} skipped={skipped_targets} skip_reasons={skip_reasons} dispositions={dispositions} destination_timings={destination_timings} elapsed_ms={elapsed_millis}"
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
    config.max_failed_retry_admissions_per_scan = args.max_failed_retry_admissions_per_scan;
    config.failed_retry_min_age_seconds = args.failed_retry_min_age_seconds;
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
    stats.terminal_records = metrics.terminal_records;
    stats.no_action_records = metrics.no_action_records;
    stats.needs_review_records = metrics.needs_review_records;
    stats.failed_records = metrics.failed_records;
    stats.pending_records = metrics.pending_records;
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
    max_failed_retry_admissions_per_scan: usize,
    failed_retry_min_age_seconds: u64,
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
            max_failed_retry_admissions_per_scan: config.max_failed_retry_admissions_per_scan,
            failed_retry_min_age_seconds: config.failed_retry_min_age_seconds,
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
        match queue_next_stage(manifest, record, config) {
            "none" => {}
            stage => increment_count(&mut counts, stage),
        }
    }
    counts
}

fn queue_failure_counts(manifest: &Manifest) -> BTreeMap<String, u64> {
    crate::monitor::failed_retry_queue_counts(manifest)
}

fn increment_count(counts: &mut BTreeMap<String, u64>, key: &str) {
    *counts.entry(key.to_string()).or_default() += 1;
}

fn queue_active_lifecycle_assets(config: &MonitorConfig, manifest: &Manifest) -> Vec<QueueAsset> {
    crate::monitor::active_lifecycle_asset_ids_for_config(config, manifest)
        .into_iter()
        .filter_map(|asset_id| manifest.records().get(&asset_id))
        .map(|record| queue_asset(manifest, record, config, "continue_lifecycle"))
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

fn queue_asset(
    manifest: &Manifest,
    record: &AssetRecord,
    config: &MonitorConfig,
    fallback_stage: &'static str,
) -> QueueAsset {
    QueueAsset {
        asset_id: record.asset_id.clone(),
        state: record.state.as_str().to_string(),
        next_stage: queue_next_stage_for_record(manifest, record, config).unwrap_or(fallback_stage),
        raw_size_bytes: queue_raw_size_bytes(record),
    }
}

fn queue_next_stage(
    manifest: &Manifest,
    record: &AssetRecord,
    config: &MonitorConfig,
) -> &'static str {
    if !config.full_lifecycle {
        return match record.state {
            State::NasVerified => "convert_heic",
            State::Converted => "verify_converted_heics",
            _ => "none",
        };
    }
    queue_next_stage_for_record(manifest, record, config).unwrap_or("none")
}

fn queue_next_stage_for_record(
    manifest: &Manifest,
    record: &AssetRecord,
    config: &MonitorConfig,
) -> Option<&'static str> {
    if record.state == State::UploadVerified {
        return match icloudpd_local_mirror_proof_disposition(manifest, &record.asset_id) {
            IcloudpdLocalMirrorProofDisposition::Current if config.auto_delete => {
                Some("delete_original_assets")
            }
            IcloudpdLocalMirrorProofDisposition::Current => None,
            IcloudpdLocalMirrorProofDisposition::Repairable => Some("record_local_mirrors"),
            IcloudpdLocalMirrorProofDisposition::Blocked => Some("blocked_local_mirror"),
        };
    }
    match record.state {
        State::DeleteApproved | State::DeleteEligible if config.auto_delete => {
            Some("delete_original_assets")
        }
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

#[cfg(test)]
mod queue_tests {
    use super::*;

    fn upload_verified_record(asset_id: &str, mirror_size_bytes: u64) -> AssetRecord {
        let heic_sha = "a".repeat(64);
        let heic_path = format!("/heic/{asset_id}.HEIC");
        let mut record = AssetRecord::new(asset_id, format!("/raw/{asset_id}.DNG"));
        record.state = State::UploadVerified;
        record.proofs.insert(
            "nas".to_string(),
            serde_json::json!({
                "canonical_path": format!("/raw/{asset_id}.DNG"),
                "relative_path": format!("{asset_id}.DNG"),
                "size_bytes": 100u64,
                "modified_unix_seconds": 1_700_000_000u64,
                "age_seconds": 2_592_000u64,
                "sha256": "b".repeat(64),
            }),
        );
        record.proofs.insert(
            "conversion".to_string(),
            serde_json::json!({
                "heic_path": heic_path,
                "heic_sha256": heic_sha,
                "size_bytes": 10u64,
                "conversion_recipe_id": EMBEDDED_PREVIEW_CONVERSION_RECIPE,
            }),
        );
        record.proofs.insert(
            "conversion_performance".to_string(),
            serde_json::json!({
                "schema_version": 1,
                "measured_at_unix_seconds": 1_800_000_001u64,
                "measurement_method": "monotonic_wall_clock",
                "conversion_tool": "test-tool",
                "conversion_recipe_id": EMBEDDED_PREVIEW_CONVERSION_RECIPE,
                "heic_quality": 90,
                "raw_size_bytes": 100u64,
                "heic_size_bytes": 10u64,
                "convert_wall_time_millis": 10u64,
                "total_wall_time_millis": 11u64,
            }),
        );
        record.proofs.insert(
            "heic".to_string(),
            serde_json::json!({
                "heic_path": heic_path,
                "heic_sha256": heic_sha,
                "size_bytes": 10u64,
                "conversion_recipe_id": EMBEDDED_PREVIEW_CONVERSION_RECIPE,
                "heif_info_ok": true,
                "metadata_copied": true,
                "visual_content_ok": true,
                "visual_match_ok": true,
            }),
        );
        record.proofs.insert(
            "upload".to_string(),
            serde_json::json!({
                "uploaded_heic_asset_id": format!("uploaded-{asset_id}"),
                "uploaded_heic_sha256": heic_sha,
                "uploaded_heic_path": heic_path,
            }),
        );
        record.proofs.insert(
            "icloudpd_local_mirror".to_string(),
            serde_json::json!({
                "uploaded_heic_asset_id": format!("uploaded-{asset_id}"),
                "uploaded_heic_sha256": heic_sha,
                "uploaded_heic_path": heic_path,
                "icloudpd_download_path": format!("/mirror/{asset_id}.HEIC"),
                "size_bytes": mirror_size_bytes,
            }),
        );
        record
    }

    #[test]
    fn deletion_disabled_queue_hides_delete_only_records_in_json_and_human_status() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.full_lifecycle = true;
        config.auto_delete = false;
        let mut manifest = Manifest::new();
        for (asset_id, state) in [
            ("eligible", State::DeleteEligible),
            ("approved", State::DeleteApproved),
        ] {
            let mut record = AssetRecord::new(asset_id, format!("/raw/{asset_id}.DNG"));
            record.state = state;
            manifest.upsert(record);
        }

        let report = MonitorQueueReport::from_manifest(&config, &manifest, 10);
        assert_eq!(report.queue_counts["active_lifecycle"], 0);
        assert!(!report.queue_counts.contains_key("delete_original_assets"));
        let json = serde_json::to_value(&report).expect("queue report should serialize");
        assert_eq!(json["queue_counts"]["active_lifecycle"], 0);
        assert!(!render_queue_report(&report).contains("delete_original_assets"));
    }

    #[test]
    fn deletion_disabled_queue_matches_runtime_for_valid_and_invalid_mirror_proofs_at_cap_one() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.full_lifecycle = true;
        config.auto_delete = false;
        config.max_lifecycle_per_scan = 1;
        let mut manifest = Manifest::new();
        manifest.upsert(upload_verified_record("terminal-mirror", 10));
        manifest.upsert(upload_verified_record("repair-mirror", 0));

        let runtime_active =
            crate::monitor::active_lifecycle_asset_ids_for_config(&config, &manifest);
        assert_eq!(
            crate::monitor::pending_lifecycle_count_for_config(&manifest, &config),
            1
        );
        assert_eq!(runtime_active, vec!["repair-mirror"]);

        let report = MonitorQueueReport::from_manifest(&config, &manifest, 10);
        assert_eq!(report.queue_counts["active_lifecycle"], 1);
        assert_eq!(report.queue_counts["record_local_mirrors"], 1);
        assert_eq!(
            report
                .active_lifecycle
                .iter()
                .map(|asset| asset.asset_id.as_str())
                .collect::<Vec<_>>(),
            runtime_active
        );
        let json = serde_json::to_value(&report).expect("queue report should serialize");
        assert_eq!(json["queue_counts"]["active_lifecycle"], 1);
        assert_eq!(json["queue_counts"]["record_local_mirrors"], 1);
        let human = render_queue_report(&report);
        assert!(human.contains("repair-mirror"));
        assert!(!human.contains("terminal-mirror"));
        assert!(human.contains("record_local_mirrors"));
    }

    #[test]
    fn deletion_disabled_queue_surfaces_blocked_upstream_mirror_without_admitting_it() {
        let mut config = MonitorConfig::new("/download", "/manifest.json", "/heic");
        config.full_lifecycle = true;
        config.auto_delete = false;
        config.max_lifecycle_per_scan = 1;
        let mut blocked = upload_verified_record("blocked-mirror", 10);
        blocked.proofs.remove("upload");
        let mut manifest = Manifest::new();
        manifest.upsert(blocked);

        assert_eq!(
            crate::monitor::pending_lifecycle_count_for_config(&manifest, &config),
            0
        );
        assert!(
            crate::monitor::active_lifecycle_asset_ids_for_config(&config, &manifest).is_empty()
        );
        let report = MonitorQueueReport::from_manifest(&config, &manifest, 10);
        assert_eq!(report.queue_counts["active_lifecycle"], 0);
        assert_eq!(report.queue_counts["blocked_local_mirror"], 1);
        let json = serde_json::to_value(&report).expect("queue report should serialize");
        assert_eq!(json["queue_counts"]["blocked_local_mirror"], 1);
        let human = render_queue_report(&report);
        assert!(human.contains("blocked_local_mirror"));
        assert!(!human.contains("record_local_mirrors"));
    }
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
         terminal records: {}\n\
         no-action records: {}\n\
         needs-review records: {}\n\
         failed records: {}\n\
         pending records: {}\n\
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
        metrics.terminal_records,
        metrics.no_action_records,
        metrics.needs_review_records,
        metrics.failed_records,
        metrics.pending_records,
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
            conversion_recipe_id: String::new(),
            source_binding: ConversionSourceBinding::EmbeddedPreview,
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
            conversion_recipe_id: String::new(),
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
            conversion_recipe_id: String::new(),
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
        conversion_recipe_id: EMBEDDED_PREVIEW_CONVERSION_RECIPE.to_string(),
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
mod failed_assets_quarantine_tests {
    use super::*;

    #[test]
    fn exact_cas_conflict_keeps_the_entire_quarantine_batch_unapplied() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let manifest_path = tempdir.path().join("manifest.json");
        let mut initial_manifest = Manifest::new();
        for asset_id in ["asset-alpha", "asset-beta"] {
            let mut record = AssetRecord::new(asset_id, tempdir.path().join("source.raw"));
            record.state = State::Failed;
            initial_manifest.upsert(record);
        }
        initial_manifest
            .save_atomic(&manifest_path)
            .expect("manifest should save");
        let state_store = AssetStateStore::open_writer(
            &manifest_path,
            "failed-assets-quarantine-test",
            Duration::from_secs(1),
        )
        .expect("state store should open");
        let snapshot = state_store
            .load_or_import()
            .expect("manifest should import");
        let targets = BTreeMap::from([
            (
                "asset-alpha".to_string(),
                FailedAssetsQuarantineEvidenceAsset {
                    asset_id: "asset-alpha".to_string(),
                    successful_uploads: 1,
                    delete_attempts: 0,
                    deleted_finishes: 0,
                    mirror_successes: 0,
                },
            ),
            (
                "asset-beta".to_string(),
                FailedAssetsQuarantineEvidenceAsset {
                    asset_id: "asset-beta".to_string(),
                    successful_uploads: 1,
                    delete_attempts: 0,
                    deleted_finishes: 0,
                    mirror_successes: 0,
                },
            ),
        ]);
        let evidence = VerifiedFailedAssetsQuarantineEvidence {
            evidence_sha256: "a".repeat(64),
            failed_asset_ids: BTreeSet::from(["asset-alpha".to_string(), "asset-beta".to_string()]),
            side_effect_assets: targets.clone(),
            counts: FailedAssetsQuarantineCounts {
                failed_assets: 2,
                with_upload_or_delete_side_effects: 2,
                clean_of_recorded_remote_side_effects: 0,
                side_effect_assets: 2,
            },
        };
        let expected_records =
            failed_assets_quarantine_expected_records(&snapshot, &targets).expect("snapshots");
        let target_set_sha256 =
            failed_assets_quarantine_target_set_sha256(&snapshot, &targets).expect("fingerprint");
        let mut updated_manifest = snapshot.clone();
        let changed_records = apply_failed_assets_quarantine(
            &mut updated_manifest,
            &evidence,
            &target_set_sha256,
            1_700_000_000,
        )
        .expect("updates should prepare");

        let mut stale_record = expected_records["asset-alpha"].clone();
        stale_record.proofs.insert(
            "concurrent_change".to_string(),
            serde_json::json!({"changed": true}),
        );
        stale_record.updated_at = "9999999999.000000000Z".to_string();
        state_store
            .persist_record(&stale_record)
            .expect("concurrent record should persist");

        let error = persist_failed_assets_quarantine_updates(
            &state_store,
            &expected_records,
            &changed_records,
            2,
        )
        .expect_err("stale snapshot must reject the whole batch");
        assert!(
            error
                .to_string()
                .contains("current state changed before the atomic quarantine commit")
        );
        let after = state_store.load().expect("state should load");
        for asset_id in ["asset-alpha", "asset-beta"] {
            let record = after.get(asset_id).expect("asset should exist");
            assert_eq!(record.state, State::Failed);
            assert!(!record.proofs.contains_key("failure_quarantine"));
        }
    }
}

#[cfg(test)]
mod legacy_failures_classify_tests {
    use super::*;

    fn legacy_missing_preview_record(asset_id: &str, raw_path: PathBuf) -> AssetRecord {
        let mut record = AssetRecord::new(asset_id, raw_path);
        record.state = State::Failed;
        record.failures.push(crate::manifest::FailureRecord {
            stage: "conversion".to_string(),
            message: format!(
                "RAW has neither PreviewImage nor JpgFromRaw embedded preview: /staging/{asset_id}.staged-raw.DNG"
            ),
            recorded_at: "100.000000000Z".to_string(),
            kind: None,
        });
        record.updated_at = "100.000000000Z".to_string();
        record
    }

    fn persisted_legacy_candidates() -> (
        tempfile::TempDir,
        AssetStateStore,
        BTreeMap<String, AssetRecord>,
    ) {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let manifest_path = tempdir.path().join("manifest.json");
        let mut manifest = Manifest::new();
        for asset_id in ["asset-alpha", "asset-beta"] {
            manifest.upsert(legacy_missing_preview_record(
                asset_id,
                tempdir.path().join(format!("{asset_id}.DNG")),
            ));
        }
        manifest
            .save_atomic(&manifest_path)
            .expect("manifest should save");
        let state_store = AssetStateStore::open_writer(
            &manifest_path,
            "legacy-failures-classify-test",
            Duration::from_secs(1),
        )
        .expect("state store should open");
        let snapshot = state_store
            .load_or_import()
            .expect("manifest should import");
        let candidates = legacy_failures_classify_candidates(&snapshot);
        assert_eq!(candidates.counts.candidates, 2);
        (tempdir, state_store, candidates.targets)
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("output fixture failed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn legacy_failures_classify_config_path(tempdir: &tempfile::TempDir) -> PathBuf {
        let download_root = tempdir.path().join("download");
        fs::create_dir_all(&download_root).expect("download root should be created");
        let config_path = tempdir.path().join("monitor.json");
        MonitorConfig::new(
            &download_root,
            tempdir.path().join("manifest.json"),
            tempdir.path().join("heic"),
        )
        .save_atomic(&config_path)
        .expect("monitor config should save");
        config_path
    }

    #[test]
    fn exact_cas_conflict_keeps_the_entire_legacy_classification_batch_unapplied() {
        let (_tempdir, state_store, expected_records) = persisted_legacy_candidates();
        let mut updated_manifest = state_store.load().expect("state should load");
        let changed_records =
            type_legacy_missing_preview_failures(&mut updated_manifest, &expected_records)
                .expect("updates should prepare");

        let mut stale_record = expected_records["asset-alpha"].clone();
        stale_record.proofs.insert(
            "concurrent_change".to_string(),
            serde_json::json!({"changed": true}),
        );
        stale_record.updated_at = "9999999999.000000000Z".to_string();
        state_store
            .persist_record(&stale_record)
            .expect("concurrent record should persist");

        let error = persist_legacy_failures_classify_updates(
            &state_store,
            &expected_records,
            &changed_records,
            2,
        )
        .expect_err("stale snapshot must reject the whole batch");
        assert!(
            error
                .to_string()
                .contains("current state changed before the atomic migration commit")
        );
        let after = state_store.load().expect("state should load");
        for asset_id in ["asset-alpha", "asset-beta"] {
            assert_eq!(
                after
                    .get(asset_id)
                    .expect("record should exist")
                    .failures
                    .last()
                    .expect("failure should exist")
                    .kind,
                None
            );
        }
    }

    #[test]
    fn checkpoint_failure_is_reported_after_legacy_classification_db_commit() {
        let (tempdir, state_store, expected_records) = persisted_legacy_candidates();
        let mut updated_manifest = state_store.load().expect("state should load");
        let changed_records =
            type_legacy_missing_preview_failures(&mut updated_manifest, &expected_records)
                .expect("updates should prepare");
        persist_legacy_failures_classify_updates(
            &state_store,
            &expected_records,
            &changed_records,
            2,
        )
        .expect("SQLite commit should succeed");

        let error = ensure_legacy_failures_classify_checkpoint(|| {
            Err(AssetStateStoreError::WriterLeaseRequired)
        })
        .expect_err("failed JSON checkpoint must be surfaced after commit");
        assert!(matches!(
            error,
            CliError::LegacyFailuresClassifyCheckpointStale
        ));
        let sqlite_manifest = state_store.load().expect("SQLite state should load");
        assert_eq!(
            sqlite_manifest
                .get("asset-alpha")
                .expect("record should exist")
                .failures
                .last()
                .expect("failure should exist")
                .kind,
            Some(FailureKind::EmbeddedPreviewUnavailable)
        );
        let checkpoint_manifest =
            Manifest::load(tempdir.path().join("manifest.json")).expect("checkpoint should load");
        assert_eq!(
            checkpoint_manifest
                .get("asset-alpha")
                .expect("record should exist")
                .failures
                .last()
                .expect("failure should exist")
                .kind,
            None
        );
    }

    #[test]
    fn legacy_classification_report_failure_distinguishes_dry_run_from_committed_apply() {
        let (tempdir, state_store, _) = persisted_legacy_candidates();
        let config_path = legacy_failures_classify_config_path(&tempdir);
        drop(state_store);

        let mut writer = FailingWriter;
        let dry_run_error = monitor_legacy_failures_classify(
            MonitorLegacyFailuresClassifyArgs {
                config: config_path.clone(),
                expected_target_set_sha256: None,
                expected_candidate_count: None,
                apply: false,
            },
            &mut writer,
        )
        .expect_err("dry-run report writer should fail");
        assert!(
            dry_run_error
                .to_string()
                .contains("dry-run report output failed; no mutation was performed")
        );
        let durable_before_apply =
            AssetStateStore::open_read_only(tempdir.path().join("manifest.json"))
                .expect("state store should open")
                .load()
                .expect("state should load");
        assert_eq!(
            durable_before_apply
                .get("asset-alpha")
                .expect("record should exist")
                .failures
                .last()
                .expect("failure should exist")
                .kind,
            None
        );

        let mut dry_run_report = Vec::new();
        monitor_legacy_failures_classify(
            MonitorLegacyFailuresClassifyArgs {
                config: config_path.clone(),
                expected_target_set_sha256: None,
                expected_candidate_count: None,
                apply: false,
            },
            &mut dry_run_report,
        )
        .expect("dry-run report should succeed");
        let report: serde_json::Value =
            serde_json::from_slice(&dry_run_report).expect("report should decode");
        let target_set_sha256 = report["target_set_sha256"]
            .as_str()
            .expect("target hash should be present")
            .to_string();

        let mut writer = FailingWriter;
        let apply_error = monitor_legacy_failures_classify(
            MonitorLegacyFailuresClassifyArgs {
                config: config_path,
                expected_target_set_sha256: Some(target_set_sha256),
                expected_candidate_count: Some(2),
                apply: true,
            },
            &mut writer,
        )
        .expect_err("apply report writer should fail after commit");
        assert!(
            apply_error
                .to_string()
                .contains("database commit and JSON checkpoint succeeded but report output failed")
        );
        let durable_after_apply =
            AssetStateStore::open_read_only(tempdir.path().join("manifest.json"))
                .expect("state store should open")
                .load()
                .expect("state should load");
        assert_eq!(
            durable_after_apply
                .get("asset-alpha")
                .expect("record should exist")
                .failures
                .last()
                .expect("failure should exist")
                .kind,
            Some(FailureKind::EmbeddedPreviewUnavailable)
        );
    }
}

#[cfg(test)]
mod original_assets_audit_tests {
    use super::*;
    use crate::upload::CloudKitDeleteTransport;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::{Duration, Instant};

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

    #[cfg(unix)]
    fn audit_report_for_configured_root(
        tempdir: &tempfile::TempDir,
        download_root: &Path,
        raw_path: PathBuf,
        proof_root: &Path,
    ) -> serde_json::Value {
        let mut manifest = Manifest::new();
        manifest.upsert(audit_record("symlinked-root-asset", raw_path, proof_root));
        let manifest_path = tempdir.path().join("manifest.json");
        manifest
            .save_atomic(&manifest_path)
            .expect("manifest should save");
        AssetStateStore::open_writer(
            &manifest_path,
            "audit-symlink-root-test",
            Duration::from_secs(1),
        )
        .expect("state store should open")
        .load_or_import()
        .expect("manifest should import into the state store");
        let session_path = tempdir.path().join("session.json");
        fs::write(&session_path, "{}".as_bytes()).expect("session fixture should save");
        let config_path = tempdir.path().join("monitor.json");
        let mut config =
            MonitorConfig::new(download_root, &manifest_path, tempdir.path().join("heic"));
        config.delete_session_path = Some(session_path);
        config
            .save_atomic(&config_path)
            .expect("config should save");

        let mut output = Vec::new();
        monitor_original_assets_audit(
            MonitorOriginalAssetsAuditArgs {
                config: config_path,
            },
            &mut output,
        )
        .expect("audit should use the configured root without a CloudKit session");
        serde_json::from_slice(&output).expect("audit output should be JSON")
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

    const RECORDING_SERVER_TIMEOUT: Duration = Duration::from_millis(500);

    struct RecordingServer {
        endpoint: url::Url,
        listener: TcpListener,
    }

    impl RecordingServer {
        fn bind() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
            listener
                .set_nonblocking(true)
                .expect("listener should become nonblocking");
            let endpoint = url::Url::parse(&format!(
                "http://{}",
                listener
                    .local_addr()
                    .expect("listener should have a local address")
            ))
            .expect("loopback endpoint should parse");
            Self { endpoint, listener }
        }

        fn endpoint(&self) -> &url::Url {
            &self.endpoint
        }

        fn serve(self, responses: Vec<Vec<u8>>) -> thread::JoinHandle<Vec<String>> {
            thread::spawn(move || {
                let mut requests = Vec::with_capacity(responses.len());
                for response in responses {
                    let mut stream = accept_recording_connection(&self.listener);
                    let request = read_recording_request(&mut stream);
                    write_recording_response(&mut stream, &response);
                    requests.push(request);
                }
                requests
            })
        }

        fn assert_no_requests(self) -> thread::JoinHandle<()> {
            thread::spawn(move || {
                let deadline = Instant::now() + RECORDING_SERVER_TIMEOUT;
                loop {
                    match self.listener.accept() {
                        Ok(_) => panic!("invalid session must not send a request"),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            if Instant::now() >= deadline {
                                return;
                            }
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("recording server accept failed: {error}"),
                    }
                }
            })
        }
    }

    fn accept_recording_connection(listener: &TcpListener) -> TcpStream {
        let deadline = Instant::now() + RECORDING_SERVER_TIMEOUT;
        loop {
            match listener.accept() {
                Ok((stream, _)) => return stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "timed out waiting for expected request"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("recording server accept failed: {error}"),
            }
        }
    }

    fn read_recording_request(stream: &mut TcpStream) -> String {
        let deadline = Instant::now() + RECORDING_SERVER_TIMEOUT;
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        let header_end = loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("timed out reading request headers");
            stream
                .set_read_timeout(Some(remaining))
                .expect("request read timeout should set");
            let read = stream
                .read(&mut buffer)
                .expect("request should be readable");
            assert!(read > 0, "request should include headers");
            request.extend_from_slice(&buffer[..read]);
            if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let header_text = String::from_utf8(request[..header_end].to_vec())
            .expect("request headers should be UTF-8");
        let content_length = header_text
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then_some(value.trim())
            })
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        while request.len() < header_end + content_length {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("timed out reading request body");
            stream
                .set_read_timeout(Some(remaining))
                .expect("request read timeout should set");
            let read = stream
                .read(&mut buffer)
                .expect("request body should be readable");
            assert!(read > 0, "request body should not end early");
            request.extend_from_slice(&buffer[..read]);
        }
        header_text
            .lines()
            .next()
            .expect("request should include a request line")
            .to_string()
    }

    fn write_recording_response(stream: &mut TcpStream, body: &[u8]) {
        stream
            .set_write_timeout(Some(RECORDING_SERVER_TIMEOUT))
            .expect("response write timeout should set");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .expect("response headers should write");
        stream.write_all(body).expect("response body should write");
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

        let (groups, skipped, skip_reasons) = original_assets_audit_targets(
            &manifest,
            &fs::canonicalize(&root).expect("root should canonicalize"),
            &root,
            2,
        );

        assert_eq!(skipped, 0);
        assert!(skip_reasons.is_empty());
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
        let shared = groups
            .get(&shared_destination)
            .expect("shared target should be grouped");
        assert_eq!(shared.len(), 1);
        assert!(
            shared[0].replacement_candidate.is_none(),
            "an unavailable stable replacement candidate must not skip the target"
        );
    }

    #[test]
    fn audit_groups_assets_when_download_root_is_primary_sync() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let root = tempdir.path().join("PrimarySync");
        let raw = root.join("IMG_0001.DNG");
        fs::create_dir_all(&root).expect("library directory should be created");
        fs::write(&raw, b"primary-raw").expect("primary raw should save");
        let mut manifest = Manifest::new();
        manifest.upsert(audit_record("asset-primary", raw, &root));

        let (groups, skipped, skip_reasons) = original_assets_audit_targets(
            &manifest,
            &fs::canonicalize(&root).expect("root should canonicalize"),
            &root,
            2,
        );

        assert_eq!(skipped, 0);
        assert!(skip_reasons.is_empty());
        assert_eq!(
            groups
                .get(&CloudKitLibraryDestination::primary_sync())
                .expect("primary target should be grouped")
                .len(),
            1
        );
    }

    #[test]
    fn audit_groups_assets_when_download_root_is_shared_sync() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let root = tempdir.path().join("SharedSync-family");
        let raw = root.join("IMG_0002.DNG");
        fs::create_dir_all(&root).expect("library directory should be created");
        fs::write(&raw, b"shared-raw").expect("shared raw should save");
        let mut manifest = Manifest::new();
        manifest.upsert(audit_record("asset-shared", raw, &root));

        let (groups, skipped, skip_reasons) = original_assets_audit_targets(
            &manifest,
            &fs::canonicalize(&root).expect("root should canonicalize"),
            &root,
            2,
        );

        assert_eq!(skipped, 0);
        assert!(skip_reasons.is_empty());
        let destination = CloudKitLibraryDestination {
            database_scope: CloudKitDatabaseScope::Shared,
            zone_name: "SharedSync-family".to_string(),
        };
        assert_eq!(
            groups
                .get(&destination)
                .expect("shared target should be grouped")
                .len(),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn audit_uses_primary_sync_symlink_name_when_target_basename_is_neutral() {
        use std::os::unix::fs::symlink;

        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let target = tempdir.path().join("neutral-primary-target");
        let raw = target.join("IMG_0001.DNG");
        fs::create_dir_all(&target).expect("target directory should be created");
        fs::write(&raw, b"primary-raw").expect("primary raw should save");
        let configured_root = tempdir.path().join("PrimarySync");
        symlink(&target, &configured_root).expect("primary symlink should be created");

        let report = audit_report_for_configured_root(&tempdir, &configured_root, raw, &target);

        assert_eq!(report["targets"], 1);
        assert_eq!(report["skipped_targets"], 0);
        assert_eq!(
            report["destinations"][0]["destination"],
            serde_json::json!({"database_scope": "private", "zone_name": "PrimarySync"})
        );
    }

    #[cfg(unix)]
    #[test]
    fn audit_uses_shared_sync_symlink_name_when_target_basename_is_neutral() {
        use std::os::unix::fs::symlink;

        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let target = tempdir.path().join("neutral-shared-target");
        let raw = target.join("IMG_0002.DNG");
        fs::create_dir_all(&target).expect("target directory should be created");
        fs::write(&raw, b"shared-raw").expect("shared raw should save");
        let configured_root = tempdir.path().join("SharedSync-family");
        symlink(&target, &configured_root).expect("shared symlink should be created");

        let report = audit_report_for_configured_root(&tempdir, &configured_root, raw, &target);

        assert_eq!(report["targets"], 1);
        assert_eq!(report["skipped_targets"], 0);
        assert_eq!(
            report["destinations"][0]["destination"],
            serde_json::json!({"database_scope": "shared", "zone_name": "SharedSync-family"})
        );
    }

    #[cfg(unix)]
    #[test]
    fn audit_uses_relative_library_for_parent_root_symlink_with_neutral_name() {
        use std::os::unix::fs::symlink;

        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let target = tempdir.path().join("neutral-parent-target");
        let raw = target.join("PrimarySync/IMG_0003.DNG");
        fs::create_dir_all(raw.parent().expect("raw should have a parent"))
            .expect("primary directory should be created");
        fs::write(&raw, b"parent-raw").expect("parent raw should save");
        let configured_root = tempdir.path().join("untrusted-parent-link");
        symlink(&target, &configured_root).expect("parent symlink should be created");

        let report = audit_report_for_configured_root(&tempdir, &configured_root, raw, &target);

        assert_eq!(report["targets"], 1);
        assert_eq!(
            report["destinations"][0]["destination"],
            serde_json::json!({"database_scope": "private", "zone_name": "PrimarySync"})
        );
    }

    #[test]
    fn audit_report_aggregates_redacted_skip_reasons() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let root = tempdir.path().join("library");
        let primary = root.join("PrimarySync");
        fs::create_dir_all(&primary).expect("primary directory should be created");
        let raw = primary.join("IMG_0001.DNG");
        fs::write(&raw, b"raw").expect("raw should save");

        let mut manifest = Manifest::new();
        let mut invalid_nas = audit_record("asset-invalid-nas", raw.clone(), &root);
        invalid_nas
            .proofs
            .insert("nas".to_string(), serde_json::json!({"size_bytes": 3}));
        manifest.upsert(invalid_nas);

        let mut invalid_source_age = audit_record("asset-invalid-source-age", raw.clone(), &root);
        invalid_source_age.proofs.insert(
            "source_age".to_string(),
            serde_json::json!({"source_captured_unix_seconds": 1}),
        );
        manifest.upsert(invalid_source_age);

        let mut missing_raw = audit_record("asset-missing-raw", raw.clone(), &root);
        missing_raw.raw_path = primary.join("not-present.DNG");
        manifest.upsert(missing_raw);

        let outside = tempdir.path().join("outside/secret.DNG");
        fs::create_dir_all(outside.parent().expect("outside raw should have a parent"))
            .expect("outside directory should be created");
        fs::write(&outside, b"outside").expect("outside raw should save");
        manifest.upsert(audit_record("asset-outside-root", outside, tempdir.path()));

        let unsupported = root.join("UnknownLibrary/secret.DNG");
        fs::create_dir_all(
            unsupported
                .parent()
                .expect("unsupported raw should have a parent"),
        )
        .expect("unsupported directory should be created");
        fs::write(&unsupported, b"unsupported").expect("unsupported raw should save");
        manifest.upsert(audit_record("asset-unsupported-layout", unsupported, &root));

        let mut invalid_filename = audit_record("asset-invalid-filename", raw, &root);
        invalid_filename.raw_path = primary.clone();
        manifest.upsert(invalid_filename);

        let manifest_path = tempdir.path().join("manifest.json");
        manifest
            .save_atomic(&manifest_path)
            .expect("manifest should save");
        AssetStateStore::open_writer(
            &manifest_path,
            "audit-skip-reasons-test",
            Duration::from_secs(1),
        )
        .expect("state store should open")
        .load_or_import()
        .expect("manifest should import into the state store");
        let session_path = tempdir.path().join("session.json");
        fs::write(&session_path, "{}".as_bytes()).expect("session fixture should save");
        let config_path = tempdir.path().join("monitor.json");
        let mut config = MonitorConfig::new(&root, &manifest_path, tempdir.path().join("heic"));
        config.delete_session_path = Some(session_path);
        config
            .save_atomic(&config_path)
            .expect("config should save");

        let mut output = Vec::new();
        monitor_original_assets_audit(
            MonitorOriginalAssetsAuditArgs {
                config: config_path,
            },
            &mut output,
        )
        .expect("audit should report skipped records without contacting CloudKit");

        let report: serde_json::Value =
            serde_json::from_slice(&output).expect("audit output should be JSON");
        assert_eq!(report["targets"], 0);
        assert_eq!(report["skipped_targets"], 6);
        assert_eq!(
            report["skip_reason_counts"],
            serde_json::json!({
                "invalid_or_missing_nas_proof": 1,
                "invalid_or_missing_source_age_proof": 1,
                "raw_path_unavailable": 1,
                "outside_download_root": 1,
                "unsupported_library_layout": 1,
                "invalid_filename": 1,
            })
        );
        let rendered = String::from_utf8(output).expect("audit output should be UTF-8");
        assert!(!rendered.contains("secret.DNG"));
        assert!(!rendered.contains("asset-outside-root"));
        assert!(!rendered.contains(&root.display().to_string()));
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

        let mut unrelated_failure = AssetRecord::new("unrelated", "/raw/unrelated.DNG");
        unrelated_failure.state = State::Failed;
        unrelated_failure
            .failures
            .push(crate::manifest::FailureRecord::new(
                "conversion",
                "converter interrupted",
            ));
        assert!(!original_assets_audit_eligible(&unrelated_failure));
    }

    #[test]
    fn audit_human_summary_includes_counts_and_destination_timings() {
        let reports = vec![OriginalAssetsAuditDestinationReport {
            destination: CloudKitLibraryDestination::primary_sync(),
            targets: 2,
            target_set_sha256: "a".repeat(64),
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

        let summary = original_assets_audit_human_summary(
            2,
            0,
            &BTreeMap::from([("invalid_filename".to_string(), 1)]),
            &reports,
            11,
        );

        assert!(summary.contains("exact_original=1"));
        assert!(summary.contains("no_raw_resource=1"));
        assert!(summary.contains("skip_reasons=invalid_filename=1"));
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
        let recorder = RecordingServer::bind();
        let raw = b"audit-raw".to_vec();
        let resource_url = recorder
            .endpoint()
            .join("resource")
            .expect("resource URL should resolve")
            .to_string();
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
        let endpoint = recorder.endpoint().clone();
        let server = recorder.serve(vec![query_response.into_bytes(), raw]);

        let session = audit_test_session();
        let config = MonitorConfig::new("/audit/download", "/audit/manifest.json", "/audit/heic");
        let target = audit_test_target();
        let report = original_assets_audit_destination_report_with_transport(
            &session,
            CloudKitLibraryDestination::primary_sync(),
            vec![target],
            &config,
            ReqwestCloudKitReadTransport::new_for_loopback_test(endpoint)
                .expect("read transport should build"),
        );

        assert_eq!(report.targets, 1);
        assert!(report.batch_error.is_none(), "{:#?}", report.batch_error);
        assert_eq!(report.resolutions.len(), 1);
        assert_eq!(
            report.target_set_sha256,
            original_assets_target_set_sha256(
                &CloudKitLibraryDestination::primary_sync(),
                &[audit_test_target()],
            )
        );
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
    fn audit_no_download_query_returns_without_waiting_for_an_extra_request() {
        let recorder = RecordingServer::bind();
        let endpoint = recorder.endpoint().clone();
        let server = recorder.serve(vec![
            serde_json::json!({"records": []}).to_string().into_bytes(),
        ]);
        let config = MonitorConfig::new("/audit/download", "/audit/manifest.json", "/audit/heic");
        let report = original_assets_audit_destination_report_with_transport(
            &audit_test_session(),
            CloudKitLibraryDestination::primary_sync(),
            vec![audit_test_target()],
            &config,
            ReqwestCloudKitReadTransport::new_for_loopback_test(endpoint)
                .expect("read transport should build"),
        );

        assert!(report.batch_error.is_none(), "{:#?}", report.batch_error);
        assert_eq!(
            server
                .join()
                .expect("recording server should complete")
                .len(),
            1
        );
    }

    #[test]
    fn mutated_http_or_non_apple_session_sends_no_cloudkit_request() {
        for scheme in ["http", "https"] {
            let recorder = RecordingServer::bind();
            let endpoint = recorder.endpoint().clone();
            let no_requests = recorder.assert_no_requests();
            let mut session = audit_test_session();
            let mut invalid_endpoint = endpoint.clone();
            invalid_endpoint
                .set_scheme(scheme)
                .expect("test endpoint scheme should update");
            session.ckdatabasews_url = invalid_endpoint;
            let payload = serde_json::json!({"zoneID": {"zoneName": "PrimarySync"}});
            let resource_url = endpoint
                .join("resource")
                .expect("resource URL should resolve");
            let mut read_transport = ReqwestCloudKitReadTransport::new_for_loopback_test(endpoint)
                .expect("read transport should build");
            let mut delete_transport =
                ReqwestCloudKitDeleteTransport::new().expect("delete transport should build");

            for error in [
                read_transport.post_records_query(&session, payload.clone()),
                delete_transport.post_records_lookup(&session, payload.clone()),
                delete_transport.post_records_modify(&session, payload.clone()),
            ] {
                assert!(matches!(error, Err(UploadError::InvalidSession(_))));
            }
            assert!(matches!(
                read_transport.download_resource(&session, &resource_url, 1),
                Err(UploadError::InvalidSession(_))
            ));
            no_requests
                .join()
                .expect("invalid session recorder should observe no requests");
        }
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

    fn reconcile_test_target(asset_id: &str) -> CloudKitOriginalAssetResolveTarget {
        CloudKitOriginalAssetResolveTarget {
            asset_id: asset_id.to_string(),
            raw_size_bytes: 42,
            source_captured_unix_seconds: 1_700_000_000,
            capture_tolerance_seconds: 2,
            filename: format!("{asset_id}.DNG"),
            matched_raw_sha256: "a".repeat(64),
            replacement_candidate: None,
        }
    }

    fn reconcile_test_record(target: &CloudKitOriginalAssetResolveTarget) -> AssetRecord {
        let raw_path = PathBuf::from(format!("/nas/{}", target.filename));
        let mut record = AssetRecord::new(&target.asset_id, raw_path.clone());
        record.state = State::NasVerified;
        record.proofs.insert(
            "nas".to_string(),
            serde_json::to_value(NasRawProof {
                canonical_path: raw_path,
                relative_path: PathBuf::from(&target.filename),
                size_bytes: target.raw_size_bytes,
                modified_unix_seconds: target.source_captured_unix_seconds,
                age_seconds: 40 * DAY_SECONDS,
                sha256: target.matched_raw_sha256.clone(),
            })
            .expect("NAS proof should serialize"),
        );
        record.proofs.insert(
            "source_age".to_string(),
            serde_json::to_value(SourceAgeProof {
                source_captured_unix_seconds: target.source_captured_unix_seconds,
                verified_at_unix_seconds: 1_800_000_000,
                min_age_seconds: 30 * DAY_SECONDS,
            })
            .expect("source age proof should serialize"),
        );
        record
    }

    fn reconcile_test_exact_resolution(
        target: &CloudKitOriginalAssetResolveTarget,
        record_name: &str,
    ) -> CloudKitOriginalAssetResolution {
        CloudKitOriginalAssetResolution {
            observations: crate::upload::CloudKitOriginalAssetResolveObservations {
                date_candidates: 1,
                raw_resources: 1,
                raw_size_matches: 1,
                raw_hash_matches: 1,
                ..Default::default()
            },
            disposition: CloudKitOriginalAssetResolveDisposition::ExactOriginal {
                proof: OriginalAssetProof {
                    record_name: record_name.to_string(),
                    record_change_tag: format!("{record_name}-tag"),
                    record_type: "CPLAsset".to_string(),
                    database_scope: CloudKitDatabaseScope::Private,
                    zone_name: "PrimarySync".to_string(),
                    filename: target.filename.clone(),
                    size_bytes: target.raw_size_bytes,
                    matched_raw_sha256: target.matched_raw_sha256.clone(),
                },
            },
        }
    }

    fn reconcile_test_outcome(
        targets: &[CloudKitOriginalAssetResolveTarget],
    ) -> CloudKitOriginalAssetBatchResolveOutcome {
        CloudKitOriginalAssetBatchResolveOutcome {
            resolutions: targets
                .iter()
                .enumerate()
                .map(|(index, target)| {
                    (
                        target.asset_id.clone(),
                        reconcile_test_exact_resolution(target, &format!("remote-{index}")),
                    )
                })
                .collect(),
            inventory: Some(CloudKitOriginalAssetInventoryFingerprint {
                resolver_version: crate::upload::CLOUDKIT_ORIGINAL_ASSET_RESOLVER_VERSION
                    .to_string(),
                sha256: "b".repeat(64),
                records_scanned: targets.len() as u64,
            }),
        }
    }

    fn reconcile_test_expectations(
        targets: &[CloudKitOriginalAssetResolveTarget],
    ) -> OriginalAssetsReconcileExpectations {
        OriginalAssetsReconcileExpectations {
            destination: CloudKitLibraryDestination::primary_sync(),
            selected_target_count: targets.len() as u64,
            unselected_destination_target_count: 0,
            skipped_target_count: 0,
            target_set_sha256: original_assets_target_set_sha256(
                &CloudKitLibraryDestination::primary_sync(),
                targets,
            ),
            inventory_sha256: "b".repeat(64),
            records_scanned: targets.len() as u64,
            disposition_counts: OriginalAssetsReconcileDispositionCounts {
                exact_original: targets.len() as u64,
                ..Default::default()
            },
        }
    }

    #[test]
    fn original_assets_reconcile_rejects_invalid_arguments_before_scanning() {
        let target = reconcile_test_target("asset-a");
        let mut expectations = reconcile_test_expectations(&[target]);
        expectations.selected_target_count = 0;
        assert!(expectations.validate_preflight().is_err());

        let mut expectations = reconcile_test_expectations(&[reconcile_test_target("asset-a")]);
        expectations.inventory_sha256 = "not-a-sha256".to_string();
        assert!(expectations.validate_preflight().is_err());

        let mut expectations = reconcile_test_expectations(&[reconcile_test_target("asset-a")]);
        expectations.disposition_counts.exact_original = 0;
        assert!(expectations.validate_preflight().is_err());

        assert!(
            validate_cli_library_destination(CloudKitLibraryDestination {
                database_scope: CloudKitDatabaseScope::Private,
                zone_name: "SharedSync-family".to_string(),
            })
            .is_err()
        );
    }

    #[test]
    fn original_assets_reconcile_gates_every_mismatch_without_manifest_mutation() {
        let target = reconcile_test_target("asset-a");
        let targets = vec![target.clone()];
        let mut source_manifest = Manifest::new();
        source_manifest.upsert(reconcile_test_record(&target));

        for mismatch in [
            "selected",
            "unselected",
            "skipped",
            "target-set",
            "missing-inventory",
            "fingerprint",
            "records-scanned",
            "disposition",
            "incomplete",
        ] {
            let mut manifest = source_manifest.clone();
            let mut expectations = reconcile_test_expectations(&targets);
            let mut outcome = reconcile_test_outcome(&targets);
            let (unselected, skipped) = match mismatch {
                "selected" => {
                    expectations.selected_target_count = 2;
                    expectations.disposition_counts.exact_original = 2;
                    (0, 0)
                }
                "unselected" => {
                    expectations.unselected_destination_target_count = 1;
                    (0, 0)
                }
                "skipped" => {
                    expectations.skipped_target_count = 1;
                    (0, 0)
                }
                "target-set" => {
                    let resolution = outcome
                        .resolutions
                        .remove(&target.asset_id)
                        .expect("resolution should exist");
                    outcome
                        .resolutions
                        .insert("unexpected-asset".to_string(), resolution);
                    (0, 0)
                }
                "missing-inventory" => {
                    outcome.inventory = None;
                    (0, 0)
                }
                "fingerprint" => {
                    expectations.inventory_sha256 = "c".repeat(64);
                    (0, 0)
                }
                "records-scanned" => {
                    expectations.records_scanned = 2;
                    (0, 0)
                }
                "disposition" => {
                    expectations.disposition_counts.exact_original = 0;
                    expectations.disposition_counts.no_raw_resource = 1;
                    (0, 0)
                }
                "incomplete" => {
                    outcome.resolutions.insert(
                        target.asset_id.clone(),
                        CloudKitOriginalAssetResolution {
                            observations: Default::default(),
                            disposition:
                                CloudKitOriginalAssetResolveDisposition::IncompleteTransient,
                        },
                    );
                    expectations.disposition_counts.exact_original = 0;
                    expectations.disposition_counts.incomplete_transient = 1;
                    (0, 0)
                }
                _ => unreachable!("all mismatch cases are enumerated"),
            };
            let before = manifest.clone();
            assert!(
                apply_verified_original_assets_reconcile(
                    &mut manifest,
                    &expectations,
                    targets.clone(),
                    unselected,
                    skipped,
                    outcome,
                    1_800_000_000,
                )
                .is_err()
            );
            assert_eq!(manifest, before, "{mismatch} must not mutate the manifest");
        }
    }

    #[test]
    fn original_assets_reconcile_rejects_same_count_target_source_substitution() {
        let target = reconcile_test_target("asset-a");
        let mut substituted = target.clone();
        substituted.source_captured_unix_seconds =
            substituted.source_captured_unix_seconds.saturating_add(1);

        let result = verify_original_assets_reconcile_outcome(
            &reconcile_test_expectations(&[target]),
            &[substituted.clone()],
            0,
            0,
            &reconcile_test_outcome(&[substituted]),
        );
        assert!(result.is_err());
        let error = result
            .err()
            .expect("target-set gate should reject substitution");

        assert!(matches!(
            error,
            CliError::OriginalAssetsReconcileGate { .. }
        ));
    }

    #[test]
    fn original_assets_reconcile_requires_one_update_for_every_pre_scan_target() {
        let first = reconcile_test_record(&reconcile_test_target("asset-a"));
        let second = reconcile_test_record(&reconcile_test_target("asset-b"));
        let expected = BTreeMap::from([
            (first.asset_id.clone(), first.clone()),
            (second.asset_id.clone(), second.clone()),
        ]);

        assert!(
            validate_original_assets_reconcile_update_set(&expected, std::slice::from_ref(&first),)
                .is_err()
        );
        assert!(
            validate_original_assets_reconcile_update_set(
                &BTreeMap::from([(first.asset_id.clone(), first.clone())]),
                &[first.clone(), first],
            )
            .is_err()
        );
    }

    fn reconcile_test_query_response(endpoint: &url::Url, raw: &[u8]) -> Vec<u8> {
        let resource_url = endpoint
            .join("resource")
            .expect("resource URL should resolve")
            .to_string();
        serde_json::json!({
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
        .to_string()
        .into_bytes()
    }

    #[derive(Debug, Eq, PartialEq)]
    struct ReconcileStateDirectoryEntry {
        contents: Vec<u8>,
        size_bytes: u64,
        read_only: bool,
        modified_unix_nanos: Option<u128>,
    }

    fn reconcile_state_directory_snapshot(
        directory: &Path,
    ) -> BTreeMap<String, ReconcileStateDirectoryEntry> {
        fs::read_dir(directory)
            .expect("state directory should be readable")
            .map(|entry| {
                let entry = entry.expect("state directory entry should be readable");
                let path = entry.path();
                let metadata = entry.metadata().expect("state entry metadata should load");
                assert!(
                    metadata.is_file(),
                    "state directory must contain only files"
                );
                let modified_unix_nanos = metadata
                    .modified()
                    .ok()
                    .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
                    .map(|duration| duration.as_nanos());
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    ReconcileStateDirectoryEntry {
                        contents: fs::read(path).expect("state entry should be readable"),
                        size_bytes: metadata.len(),
                        read_only: metadata.permissions().readonly(),
                        modified_unix_nanos,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn original_assets_reconcile_query_only_keeps_database_and_json_byte_identical() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let state_dir = tempdir.path().join("state");
        let download_root = tempdir.path().join("download");
        let raw_path = download_root.join("PrimarySync/IMG_0001.DNG");
        let manifest_path = state_dir.join("manifest.json");
        let config_path = state_dir.join("monitor.json");
        let session_path = state_dir.join("delete-session.json");
        fs::create_dir_all(&state_dir).expect("state directory should create");
        fs::create_dir_all(raw_path.parent().expect("raw parent should exist"))
            .expect("raw parent should create");
        let raw = b"audit-raw".to_vec();
        fs::write(&raw_path, &raw).expect("raw should save");
        let mut initial = Manifest::new();
        initial.upsert(audit_record("local-audit-asset", raw_path, &download_root));
        initial
            .save_atomic(&manifest_path)
            .expect("manifest should save");
        let writer = AssetStateStore::open_writer(
            &manifest_path,
            "original-assets-reconcile-query-test",
            Duration::from_secs(30),
        )
        .expect("state store should open");
        writer.load_or_import().expect("manifest should import");
        drop(writer);
        fs::write(
            &session_path,
            serde_json::json!({
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
        .expect("session should save");
        let mut config =
            MonitorConfig::new(&download_root, &manifest_path, tempdir.path().join("heic"));
        config.delete_session_path = Some(session_path);
        config
            .save_atomic(&config_path)
            .expect("config should save");

        let canonical_root = fs::canonicalize(&download_root).expect("root should canonicalize");
        let manifest = AssetStateStore::open_read_only(&manifest_path)
            .expect("state store should open read-only")
            .load()
            .expect("manifest should load");
        let (mut grouped_targets, skipped_targets, _) = original_assets_audit_targets(
            &manifest,
            &canonical_root,
            &download_root,
            config.capture_tolerance_seconds,
        );
        let targets = grouped_targets
            .remove(&CloudKitLibraryDestination::primary_sync())
            .expect("primary target should be selected");
        assert!(grouped_targets.is_empty());
        assert_eq!(skipped_targets, 0);

        let recorder = RecordingServer::bind();
        let endpoint = recorder.endpoint().clone();
        let server = recorder.serve(vec![
            reconcile_test_query_response(&endpoint, &raw),
            raw.clone(),
        ]);
        let outcome = resolve_original_assets_audit_destination(
            &audit_test_session(),
            &CloudKitLibraryDestination::primary_sync(),
            &targets,
            &config,
            ReqwestCloudKitReadTransport::new_for_loopback_test(endpoint)
                .expect("loopback transport should build"),
        )
        .expect("fixture outcome should resolve");
        server.join().expect("fixture server should complete");
        let inventory = outcome
            .inventory
            .expect("fixture outcome should be complete");
        let disposition_counts =
            OriginalAssetsReconcileDispositionCounts::from_resolutions(&outcome.resolutions);
        assert_eq!(disposition_counts.incomplete_transient, 0);
        let state_before = reconcile_state_directory_snapshot(&state_dir);

        let recorder = RecordingServer::bind();
        let endpoint = recorder.endpoint().clone();
        let server = recorder.serve(vec![reconcile_test_query_response(&endpoint, &raw), raw]);
        let mut output = Vec::new();
        monitor_original_assets_reconcile_with_transport(
            MonitorOriginalAssetsReconcileArgs {
                config: config_path,
                database_scope: WorkflowCloudKitDatabaseScopeArg::Private,
                zone_name: "PrimarySync".to_string(),
                expected_selected_target_count: 1,
                expected_unselected_destination_target_count: 0,
                expected_skipped_target_count: 0,
                expected_target_set_sha256: original_assets_target_set_sha256(
                    &CloudKitLibraryDestination::primary_sync(),
                    &targets,
                ),
                expected_inventory_sha256: inventory.sha256,
                expected_records_scanned: inventory.records_scanned,
                expected_exact_original_count: disposition_counts.exact_original,
                expected_replacement_present_count: disposition_counts.replacement_present,
                expected_no_date_candidate_count: disposition_counts.no_date_candidate,
                expected_no_raw_resource_count: disposition_counts.no_raw_resource,
                expected_raw_size_mismatch_count: disposition_counts.raw_size_mismatch,
                expected_raw_hash_mismatch_count: disposition_counts.raw_hash_mismatch,
                expected_ambiguous_count: disposition_counts.ambiguous,
                expected_incomplete_transient_count: disposition_counts.incomplete_transient,
                apply: false,
            },
            &mut output,
            ReqwestCloudKitReadTransport::new_for_loopback_test(endpoint)
                .expect("loopback transport should build"),
        )
        .expect("query-only reconciliation should succeed");
        let requests = server.join().expect("reconcile server should complete");
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|request| !request.contains("records/modify") && !request.contains("upload"))
        );
        let state_after = reconcile_state_directory_snapshot(&state_dir);
        let changed_entries = state_before
            .keys()
            .chain(state_after.keys())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|name| state_before.get(*name) != state_after.get(*name))
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            changed_entries.is_empty(),
            "query-only reconciliation changed state entries: {changed_entries:?}"
        );
        let rendered = String::from_utf8(output).expect("report should be UTF-8");
        assert!(!rendered.contains(tempdir.path().to_str().expect("temp path should be UTF-8")));
        assert!(!rendered.contains("local-audit-asset"));
        assert!(!rendered.contains("test-cookie"));
    }

    #[test]
    fn original_assets_reconcile_applies_two_records_in_one_atomic_persistence() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let manifest_path = tempdir.path().join("manifest.json");
        let targets = vec![
            reconcile_test_target("asset-a"),
            reconcile_test_target("asset-b"),
        ];
        let mut initial = Manifest::new();
        for target in &targets {
            initial.upsert(reconcile_test_record(target));
        }
        initial
            .save_atomic(&manifest_path)
            .expect("manifest should save");
        let store = AssetStateStore::open_writer(
            &manifest_path,
            "original-assets-reconcile-atomic-test",
            Duration::from_secs(30),
        )
        .expect("state store should open");
        store.load_or_import().expect("manifest should import");

        let mut manifest = store.load().expect("manifest should load");
        let (verified, changed_records) = apply_verified_original_assets_reconcile(
            &mut manifest,
            &reconcile_test_expectations(&targets),
            targets.clone(),
            0,
            0,
            reconcile_test_outcome(&targets),
            1_800_000_000,
        )
        .expect("complete matching outcome should apply");
        assert_eq!(verified.disposition_counts.exact_original, 2);
        assert_eq!(changed_records.len(), 2);
        store
            .persist_records_atomic(changed_records.iter())
            .expect("both changed records should commit together");
        store.export_json().expect("checkpoint should export");

        let persisted = store.load().expect("database should load");
        let checkpoint = Manifest::load(&manifest_path).expect("checkpoint should load");
        for target in targets {
            assert!(
                persisted
                    .get(&target.asset_id)
                    .expect("persisted record should exist")
                    .proofs
                    .contains_key("original_asset_resolution")
            );
            assert!(
                checkpoint
                    .get(&target.asset_id)
                    .expect("checkpoint record should exist")
                    .proofs
                    .contains_key("original_asset_resolution")
            );
        }
    }

    #[test]
    fn original_assets_reconcile_reports_a_stale_checkpoint_after_database_commit() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let manifest_path = tempdir.path().join("manifest.json");
        let targets = vec![reconcile_test_target("asset-a")];
        let mut initial = Manifest::new();
        initial.upsert(reconcile_test_record(&targets[0]));
        initial
            .save_atomic(&manifest_path)
            .expect("manifest should save");
        let store = AssetStateStore::open_writer(
            &manifest_path,
            "original-assets-reconcile-stale-checkpoint-test",
            Duration::from_secs(30),
        )
        .expect("state store should open");
        store.load_or_import().expect("manifest should import");

        let mut manifest = store.load().expect("manifest should load");
        let (_, changed_records) = apply_verified_original_assets_reconcile(
            &mut manifest,
            &reconcile_test_expectations(&targets),
            targets.clone(),
            0,
            0,
            reconcile_test_outcome(&targets),
            1_800_000_000,
        )
        .expect("outcome should apply");
        store
            .persist_records_atomic(changed_records.iter())
            .expect("database commit should succeed");
        let error = ensure_original_assets_reconcile_checkpoint(|| {
            Err(AssetStateStoreError::WriterLeaseRequired)
        })
        .expect_err("checkpoint export failure must be surfaced after the database commit");
        assert!(matches!(
            error,
            CliError::OriginalAssetsReconcileCheckpointStale
        ));
        assert!(
            store
                .load()
                .expect("database should remain readable")
                .get("asset-a")
                .expect("database record should exist")
                .proofs
                .contains_key("original_asset_resolution")
        );
        assert!(
            !Manifest::load(&manifest_path)
                .expect("stale checkpoint should remain readable")
                .get("asset-a")
                .expect("checkpoint record should exist")
                .proofs
                .contains_key("original_asset_resolution")
        );
    }

    #[test]
    fn original_assets_reconcile_errors_redact_underlying_sensitive_values() {
        let secret = "/secret/local/path asset-id cookie-value remote-record remote-tag";
        let errors = vec![
            original_assets_reconcile_stage_failure(
                MonitorError::InvalidConfig {
                    message: secret.to_string(),
                },
                OriginalAssetsReconcileFailureStage::Configuration,
            ),
            original_assets_reconcile_stage_failure(
                MonitorError::CanonicalizeRoot {
                    path: PathBuf::from(secret),
                    source: io::Error::other(secret),
                },
                OriginalAssetsReconcileFailureStage::Root,
            ),
            original_assets_reconcile_stage_failure(
                AssetStateStoreError::StaleRecord {
                    asset_id: secret.to_string(),
                },
                OriginalAssetsReconcileFailureStage::State,
            ),
            original_assets_reconcile_stage_failure(
                UploadError::InvalidSession(secret.to_string()),
                OriginalAssetsReconcileFailureStage::Session,
            ),
            original_assets_reconcile_cloudkit_failure(UploadError::InvalidSession(
                secret.to_string(),
            )),
            original_assets_reconcile_stage_failure(
                OriginalAssetResolutionError::InvalidTarget {
                    asset_id: secret.to_string(),
                    reason: "sensitive details",
                },
                OriginalAssetsReconcileFailureStage::Domain,
            ),
            original_assets_reconcile_stage_failure(
                AssetStateStoreError::ExactCasMismatch {
                    asset_id: secret.to_string(),
                },
                OriginalAssetsReconcileFailureStage::Persistence,
            ),
            original_assets_reconcile_stage_failure(
                io::Error::other(secret),
                OriginalAssetsReconcileFailureStage::Output,
            ),
        ];

        for error in errors {
            assert!(!error.to_string().contains(secret));
        }
        assert_eq!(
            CliError::OriginalAssetsReconcileCheckpointStale.to_string(),
            "original-assets-reconcile database commit succeeded but the JSON checkpoint is stale"
        );
    }
}

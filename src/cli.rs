use std::env;
use std::io::ErrorKind;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Args, Parser, Subcommand};
use serde::Serialize;
use thiserror::Error;

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
use crate::monitor::{
    MonitorConfig, MonitorError, MonitorScanSummary, MonitorStats, launchd_plist, render_tui,
    run_monitor_once, run_scan_root_preflight_probe, write_launchd_plist,
};
use crate::proof::NasRawProof;
use crate::service::{
    DEFAULT_SERVICE_LABEL, ServiceError, ServiceInstallRequest, default_plist_path,
    install_service, service_status, start_service, stop_service, tail_logs, uninstall_service,
};
use crate::upload::{
    CloudKitDeleteClient, CloudKitDeleteRequest, CloudKitOriginalAssetBatchResolveRequest,
    CloudKitOriginalAssetResolveRequest, CloudKitOriginalAssetResolveTarget, IcloudUploadRequest,
    ReqwestCloudKitDeleteTransport, UploadError, build_upload_proof, load_cloudkit_delete_session,
    run_icloud_upload, verify_local_heic,
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
}

#[derive(Debug, Args)]
struct ManifestShowArgs {
    #[arg(long, value_name = "PATH")]
    manifest: PathBuf,
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
    Init(MonitorInitArgs),
    #[command(about = "Run the background monitor loop")]
    Run(MonitorRunArgs),
    #[command(about = "Print monitor stats")]
    Stats(MonitorStatsArgs),
    #[command(about = "Show a simple refreshing monitor TUI")]
    Tui(MonitorTuiArgs),
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
struct MonitorTuiArgs {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
    #[arg(long, default_value_t = 2)]
    refresh_seconds: u64,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    once: bool,
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
    #[error("failed to write JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("failed to write output: {0}")]
    Output(#[from] io::Error),
}

pub fn run() -> Result<(), CliError> {
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
    }
}

fn show_manifest<W: Write>(args: ManifestShowArgs, writer: &mut W) -> Result<(), CliError> {
    let manifest = Manifest::load(&args.manifest).map_err(|source| CliError::LoadManifest {
        path: args.manifest.clone(),
        source,
    })?;
    let output = ManifestOutput {
        records: manifest.records().values().collect(),
    };
    serde_json::to_writer_pretty(&mut *writer, &output)?;
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
        WorkflowCommand::UploadVerified(args) => workflow_upload_verified(args),
        WorkflowCommand::UploadedHeicDeletePlan(args) => {
            workflow_uploaded_heic_delete_plan(args, writer)
        }
        WorkflowCommand::DeleteUploadedHeic(args) => workflow_delete_uploaded_heic(args),
        WorkflowCommand::IcloudpdLocalMirror(args) => workflow_icloudpd_local_mirror(args),
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
        MonitorCommand::Init(args) => monitor_init(args),
        MonitorCommand::Run(args) => monitor_run(args, writer),
        MonitorCommand::Stats(args) => monitor_stats(args, writer),
        MonitorCommand::Tui(args) => monitor_tui(args, writer),
        MonitorCommand::LaunchdPlist(args) => monitor_launchd_plist(args, writer),
        MonitorCommand::ScanRootPreflight(args) => monitor_scan_root_preflight(args),
    }
}

fn run_service<W: Write>(args: ServiceArgs, writer: &mut W) -> Result<(), CliError> {
    match args.command {
        ServiceCommand::Install(args) => service_install(args, writer),
        ServiceCommand::Start(args) => service_start(args),
        ServiceCommand::Stop(args) => service_stop(args),
        ServiceCommand::Status(args) => service_status_command(args, writer),
        ServiceCommand::Logs(args) => service_logs(args, writer),
        ServiceCommand::Uninstall(args) => service_uninstall(args),
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
        label: args.label,
    })?;
    writeln!(writer, "installed service {}", summary.label)?;
    writeln!(writer, "binary: {}", summary.binary_path.display())?;
    writeln!(writer, "launchd plist: {}", summary.plist_path.display())?;
    writeln!(
        writer,
        "If macOS denies NAS access, grant Network Volumes or Full Disk Access to the service binary after installing or updating it."
    )?;
    Ok(())
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
    config.heic_quality = args.heic_quality;
    config.max_conversions_per_scan = args.max_conversions_per_scan;
    config.scan_recursive = !args.no_recursive_scan;
    config.conversion_tool_version = args.conversion_tool_version;
    config.full_lifecycle = args.full_lifecycle;
    config.auto_delete = args.auto_delete;
    config.upload_session_path = args.upload_session;
    config.delete_session_path = args.delete_session;
    config.mirror_root = args.mirror_root;
    config.delete_operator = args.delete_operator;
    config.max_lifecycle_per_scan = args.max_lifecycle_per_scan;
    config.capture_tolerance_seconds = args.capture_tolerance_seconds;
    config.cloudkit_start_rank = args.cloudkit_start_rank;
    config.cloudkit_page_size = args.cloudkit_page_size;
    config.cloudkit_max_pages = args.cloudkit_max_pages;
    config.scan_root_preflight_timeout_seconds = args.scan_root_preflight_timeout_seconds;
    config.validate()?;
    config.save_atomic(args.config)?;
    Ok(())
}

fn monitor_run<W: Write>(args: MonitorRunArgs, writer: &mut W) -> Result<(), CliError> {
    let config = MonitorConfig::load(&args.config)?;
    config.validate()?;
    loop {
        match run_monitor_once(&config) {
            Ok(summary) => write_scan_summary(writer, &summary)?,
            Err(error) if args.once => return Err(error.into()),
            Err(error) => eprintln!("monitor failed: {error}"),
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
    if args.json {
        serde_json::to_writer_pretty(&mut *writer, &stats)?;
        writeln!(writer)?;
    } else {
        write!(writer, "{}", render_tui(&config, &stats))?;
    }
    Ok(())
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
        },
    )?;
    save_manifest(&manifest, &args.manifest)
}

fn workflow_upload_heic(args: WorkflowUploadHeicArgs) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    let heic = upload_ready_heic_proof(&manifest, &args.asset_id)?;
    verify_local_heic(&heic)?;
    let response = run_icloud_upload(&IcloudUploadRequest {
        session_path: args.session,
        heic_path: heic.heic_path.clone(),
    })?;
    let proof = build_upload_proof(&heic, &response)?;
    record_upload_proof(&mut manifest, &args.asset_id, proof)?;
    save_manifest(&manifest, &args.manifest)
}

fn workflow_upload_verified(args: WorkflowUploadVerifiedArgs) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    record_upload_proof(
        &mut manifest,
        &args.asset_id,
        UploadProof {
            uploaded_heic_asset_id: args.uploaded_heic_asset_id,
            uploaded_heic_sha256: args.uploaded_heic_sha256,
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

fn workflow_original_asset_verified(
    args: WorkflowOriginalAssetVerifiedArgs,
) -> Result<(), CliError> {
    let mut manifest = load_manifest_for_write(&args.manifest)?;
    record_original_asset_proof(
        &mut manifest,
        &args.asset_id,
        OriginalAssetProof {
            record_name: args.record_name,
            record_change_tag: args.record_change_tag,
            record_type: args.record_type,
            filename: args.filename,
            size_bytes: args.size_bytes,
            matched_raw_sha256: args.matched_raw_sha256,
        },
    )?;
    save_manifest(&manifest, &args.manifest)
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
    let manifest = Manifest::load(&args.manifest).map_err(|source| CliError::LoadManifest {
        path: args.manifest.clone(),
        source,
    })?;
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
    match Manifest::load(path) {
        Ok(manifest) => Ok(manifest),
        Err(ManifestError::Io(error)) if error.kind() == ErrorKind::NotFound => Ok(Manifest::new()),
        Err(source) => Err(CliError::LoadManifest {
            path: path.to_path_buf(),
            source,
        }),
    }
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

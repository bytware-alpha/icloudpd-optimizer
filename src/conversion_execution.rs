use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::adjusted_source::MaterializedAdjustedSource;
use crate::conversion::{
    CommandPlan, ConversionError, EmbeddedPreviewTag, ExifOrientation,
    plan_adjusted_source_conversion_for_target, plan_conversion_for_target,
    plan_conversion_for_target_with_preview_tag_and_orientation,
};
use crate::conversion_backend::{TargetPlatform, backend_report_for_target};
use crate::manifest::{FailureKind, Manifest, ManifestError, State};
use crate::proof::NasRawProof;
use crate::workflow::{
    ConversionCommandTiming, ConversionPerformanceInput, ConversionResultProof,
    ConversionSourceBinding, WorkflowError, materialize_adjusted_source_for_conversion,
    record_conversion_performance, record_conversion_result, stored_adjusted_source_for_conversion,
};

const DEFAULT_CHILD_COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const CHILD_COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(10);
const RAW_STAGE_HASH_BUFFER_BYTES: usize = 1024 * 1024;
const RAW_STAGE_COPY_CONCURRENCY: usize = 8;
const _: () = assert!(RAW_STAGE_COPY_CONCURRENCY >= 8);
const RAW_STAGING_STAGE: &str = "raw_staging";
static RAW_STAGE_COPY_SLOTS: RawStageCopySlots = RawStageCopySlots {
    available: Mutex::new(RAW_STAGE_COPY_CONCURRENCY),
    ready: Condvar::new(),
};

struct RawStageCopySlots {
    available: Mutex<usize>,
    ready: Condvar,
}

struct RawStageCopySlotGuard;

impl RawStageCopySlots {
    fn acquire(&self) -> RawStageCopySlotGuard {
        let mut available = self
            .available
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while *available == 0 {
            available = self
                .ready
                .wait(available)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        *available -= 1;
        RawStageCopySlotGuard
    }

    fn release(&self) {
        let mut available = self
            .available
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *available = (*available + 1).min(RAW_STAGE_COPY_CONCURRENCY);
        self.ready.notify_one();
    }
}

impl Drop for RawStageCopySlotGuard {
    fn drop(&mut self) {
        RAW_STAGE_COPY_SLOTS.release();
    }
}

#[cfg(test)]
static TEST_CHILD_COMMAND_TIMEOUT: std::sync::Mutex<Option<Duration>> = std::sync::Mutex::new(None);
#[cfg(test)]
static TEST_RAW_STAGE_COPY_COMMAND: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);
#[cfg(test)]
static TEST_ADJUSTED_ENCODER_STAGING_SWAP: std::sync::Mutex<Option<Vec<u8>>> =
    std::sync::Mutex::new(None);
#[cfg(test)]
static TEST_ADJUSTED_ENCODER_STAGING_SWAP_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[cfg(test)]
static TEST_ADJUSTED_DESCRIPTOR_LEAK_CHECK: std::sync::Mutex<
    Option<std::sync::Arc<std::sync::Mutex<Option<bool>>>>,
> = std::sync::Mutex::new(None);
#[cfg(test)]
static TEST_ADJUSTED_DESCRIPTOR_LEAK_CHECK_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversionExecutionRequest {
    pub asset_id: String,
    pub output_path: PathBuf,
    pub heic_quality: u8,
    pub conversion_tool_version: Option<String>,
}

pub fn execute_measured_conversion(
    manifest: &Manifest,
    request: ConversionExecutionRequest,
) -> Result<Manifest, ConversionExecutionError> {
    execute_measured_conversion_for_target(manifest, request, TargetPlatform::current())
}

pub fn execute_measured_conversions(
    manifest: &Manifest,
    requests: Vec<ConversionExecutionRequest>,
    jobs: usize,
) -> Result<Manifest, ConversionExecutionError> {
    execute_measured_conversions_for_target(manifest, requests, jobs, TargetPlatform::current())
}

fn execute_measured_conversions_for_target(
    manifest: &Manifest,
    requests: Vec<ConversionExecutionRequest>,
    jobs: usize,
    target: TargetPlatform,
) -> Result<Manifest, ConversionExecutionError> {
    if jobs == 0 {
        return Err(ConversionExecutionError::InvalidBatchJobs { jobs });
    }
    if requests.is_empty() {
        return Err(ConversionExecutionError::EmptyBatch);
    }
    reject_duplicate_batch_inputs(&requests)?;

    let mut updated = manifest.clone();
    let mut completed_output_paths: Vec<PathBuf> = Vec::new();
    for chunk in requests.chunks(jobs) {
        let mut handles = Vec::with_capacity(chunk.len());
        for request in chunk {
            let manifest_snapshot = updated.clone();
            let request = request.clone();
            let asset_id = request.asset_id.clone();
            let output_path = request.output_path.clone();
            handles.push((
                asset_id.clone(),
                output_path,
                thread::spawn(move || {
                    execute_measured_conversion_for_target(&manifest_snapshot, request, target)
                        .map(|manifest| (asset_id, manifest))
                }),
            ));
        }

        let mut chunk_results = Vec::with_capacity(handles.len());
        let mut first_error = None;
        for (asset_id, output_path, handle) in handles {
            match handle.join() {
                Ok(Ok((asset_id, manifest))) => {
                    chunk_results.push((asset_id, output_path, manifest))
                }
                Ok(Err(source)) => {
                    first_error.get_or_insert_with(|| {
                        ConversionExecutionError::BatchConversionFailed {
                            asset_id: asset_id.clone(),
                            source: Box::new(source),
                        }
                    });
                }
                Err(_) => {
                    first_error.get_or_insert_with(|| {
                        ConversionExecutionError::BatchWorkerPanicked {
                            asset_id: asset_id.clone(),
                        }
                    });
                }
            }
        }

        if let Some(error) = first_error {
            for path in &completed_output_paths {
                remove_conversion_output_path(path);
            }
            for (_, path, _) in &chunk_results {
                remove_conversion_output_path(path);
            }
            return Err(error);
        }

        for (asset_id, output_path, manifest) in chunk_results {
            let record = manifest.get(&asset_id)?.clone();
            updated.upsert(record);
            completed_output_paths.push(output_path);
        }
    }

    Ok(updated)
}

fn remove_conversion_output_path(path: &Path) {
    remove_failed_output(path);
    remove_generated_intermediates(path);
}

fn reject_duplicate_batch_inputs(
    requests: &[ConversionExecutionRequest],
) -> Result<(), ConversionExecutionError> {
    let mut asset_ids = BTreeSet::new();
    let mut output_paths = BTreeSet::new();
    for request in requests {
        if !asset_ids.insert(request.asset_id.clone()) {
            return Err(ConversionExecutionError::DuplicateBatchAsset {
                asset_id: request.asset_id.clone(),
            });
        }
        if !output_paths.insert(request.output_path.clone()) {
            return Err(ConversionExecutionError::DuplicateBatchOutput {
                path: request.output_path.clone(),
            });
        }
    }
    Ok(())
}

fn execute_measured_conversion_for_target(
    manifest: &Manifest,
    request: ConversionExecutionRequest,
    target: TargetPlatform,
) -> Result<Manifest, ConversionExecutionError> {
    let record = manifest.get(&request.asset_id)?;
    if record.state != State::NasVerified {
        return Err(ConversionExecutionError::Workflow(WorkflowError::Manifest(
            ManifestError::InvalidTransition {
                asset_id: request.asset_id,
                from: record.state,
                to: State::Converted,
            },
        )));
    }

    let raw_path = record.raw_path.clone();
    let backend = backend_report_for_target(target);
    if !backend.workflow_convert_supported {
        return Err(ConversionExecutionError::UnsupportedBackend {
            backend: backend.name,
            reason: backend.reason,
        });
    }

    let adjusted_source =
        stored_adjusted_source_for_conversion(manifest, &request.asset_id, &request.output_path)?;
    refuse_preexisting_output(&request.output_path)?;
    let staged_raw = stage_raw_for_conversion(
        &request.asset_id,
        &raw_path,
        record.proofs.get("nas"),
        &request.output_path,
    )?;
    let staged_raw_path = staged_raw.path();
    let materialized_adjusted_source = if adjusted_source.is_some() {
        materialize_adjusted_source_for_conversion(
            manifest,
            &request.asset_id,
            &request.output_path,
        )?
    } else {
        None
    };
    let plan = if let Some(materialized_source) = &materialized_adjusted_source {
        plan_adjusted_source_conversion_for_target(
            target,
            staged_raw_path,
            materialized_source.path(),
            &request.output_path,
            request.heic_quality,
        )?
    } else {
        let mut plan = plan_conversion_for_target(
            target,
            staged_raw_path,
            &request.output_path,
            request.heic_quality,
        )?;
        let preview_probe = probe_embedded_preview(staged_raw_path)?;
        if preview_probe.preview_tag != EmbeddedPreviewTag::PreviewImage
            || preview_probe.orientation.is_some()
        {
            plan = plan_conversion_for_target_with_preview_tag_and_orientation(
                target,
                staged_raw_path,
                &request.output_path,
                request.heic_quality,
                preview_probe.preview_tag,
                preview_probe.orientation,
            )?;
        }
        plan
    };
    let source_binding =
        adjusted_source
            .as_ref()
            .map_or(ConversionSourceBinding::EmbeddedPreview, |proof| {
                ConversionSourceBinding::AdjustedSource {
                    adjusted_source_proof_digest:
                        crate::adjusted_source::adjusted_source_proof_digest(proof),
                    adjusted_jpeg_sha256: proof.downloaded_sha256.clone(),
                    adjusted_jpeg_path: proof.local_path.clone(),
                }
            });
    let conversion_result = (|| {
        let total_started = Instant::now();
        let convert_started = Instant::now();
        let convert_outcome = match &materialized_adjusted_source {
            Some(materialized_source) => run_planned_adjusted_source_commands(
                "conversion",
                &plan.conversion_commands,
                materialized_source,
            )?,
            None => run_planned_commands("conversion", &plan.conversion_commands)?,
        };
        let convert_wall_time_millis = positive_millis(convert_started.elapsed());
        let metadata_usage = run_planned_command("metadata", &plan.metadata)?;
        let output = inspect_output(&request.output_path)?;
        let total_wall_time_millis = positive_millis(total_started.elapsed());
        let resource_usage = convert_outcome.resource_usage.combine(metadata_usage);

        let mut updated = manifest.clone();
        record_conversion_result(
            &mut updated,
            &request.asset_id,
            ConversionResultProof {
                heic_path: request.output_path.clone(),
                heic_sha256: output.sha256,
                size_bytes: output.size_bytes,
                source_binding,
            },
        )?;
        record_conversion_performance(
            &mut updated,
            &request.asset_id,
            ConversionPerformanceInput {
                measured_at_unix_seconds: current_unix_seconds(),
                conversion_tool: conversion_tool_name(&plan),
                conversion_tool_version: request.conversion_tool_version,
                heic_quality: request.heic_quality,
                convert_wall_time_millis,
                total_wall_time_millis,
                user_cpu_time_millis: resource_usage.user_cpu_time_millis,
                system_cpu_time_millis: resource_usage.system_cpu_time_millis,
                peak_rss_kib: resource_usage.peak_rss_kib,
                conversion_command_timings: convert_outcome.command_timings,
            },
        )?;

        Ok(updated)
    })();

    if let Err(error) = &conversion_result {
        remove_failed_output(&request.output_path);
        remove_generated_intermediates_after_error(&request.output_path, error);
    }

    conversion_result
}

fn stage_raw_for_conversion(
    asset_id: &str,
    raw_path: &Path,
    nas_proof_value: Option<&Value>,
    output_path: &Path,
) -> Result<StagedRaw, ConversionExecutionError> {
    let nas_proof = decode_staging_nas_proof(asset_id, raw_path, nas_proof_value)?;
    let staged_path = staged_raw_path_for_output(output_path, raw_path);
    refuse_preexisting_staged_raw(&staged_path)?;
    let staged_raw = StagedRaw { path: staged_path };

    run_raw_stage_copy_command(raw_path, &staged_raw.path, &nas_proof)?;
    verify_staged_raw_file(&staged_raw.path, nas_proof.size_bytes)?;
    verify_staged_raw_hash(&staged_raw.path, &nas_proof)?;

    Ok(staged_raw)
}

fn run_raw_stage_copy_command(
    raw_path: &Path,
    staged_path: &Path,
    nas_proof: &NasRawProof,
) -> Result<(), ConversionExecutionError> {
    #[cfg(test)]
    if TEST_RAW_STAGE_COPY_COMMAND
        .lock()
        .expect("test RAW stage copy command lock should not be poisoned")
        .is_none()
    {
        return copy_raw_stage_create_new(
            raw_path,
            staged_path,
            nas_proof.size_bytes,
            &nas_proof.sha256,
        );
    }

    with_raw_stage_copy_slot(|| {
        let RawStageCopyCommand { program, command } =
            raw_stage_copy_command(raw_path, staged_path, nas_proof)?;
        let outcome = wait_for_command_with_usage(RAW_STAGING_STAGE, &program, command)?;
        if !outcome.status.success() {
            return Err(ConversionExecutionError::CommandFailed {
                stage: RAW_STAGING_STAGE,
                program,
                status: outcome.status.to_string(),
            });
        }
        Ok(())
    })
}

fn with_raw_stage_copy_slot<T>(action: impl FnOnce() -> T) -> T {
    let _raw_stage_slot = RAW_STAGE_COPY_SLOTS.acquire();
    action()
}

fn raw_stage_copy_command(
    raw_path: &Path,
    staged_path: &Path,
    nas_proof: &NasRawProof,
) -> Result<RawStageCopyCommand, ConversionExecutionError> {
    #[cfg(test)]
    if let Some(program_path) = TEST_RAW_STAGE_COPY_COMMAND
        .lock()
        .expect("test RAW stage copy command lock should not be poisoned")
        .clone()
    {
        return Ok(raw_stage_copy_command_for_program(
            program_path,
            raw_path,
            staged_path,
            nas_proof,
        ));
    }

    let program_path = env::current_exe()?;
    Ok(raw_stage_copy_command_for_program(
        program_path,
        raw_path,
        staged_path,
        nas_proof,
    ))
}

fn raw_stage_copy_command_for_program(
    program_path: PathBuf,
    raw_path: &Path,
    staged_path: &Path,
    nas_proof: &NasRawProof,
) -> RawStageCopyCommand {
    let mut command = Command::new(&program_path);
    command
        .arg("__stage-raw-copy")
        .arg(raw_path)
        .arg(staged_path)
        .arg(nas_proof.size_bytes.to_string())
        .arg(&nas_proof.sha256)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    RawStageCopyCommand {
        program: program_path.display().to_string(),
        command,
    }
}

pub fn run_raw_stage_copy_child(
    raw_path: &Path,
    staged_path: &Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(), ConversionExecutionError> {
    let _timeout = RawStageChildSelfTimeout::install(child_command_timeout())?;
    copy_raw_stage_create_new(raw_path, staged_path, expected_size, expected_sha256)
}

fn copy_raw_stage_create_new(
    raw_path: &Path,
    staged_path: &Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(), ConversionExecutionError> {
    let result =
        copy_raw_stage_create_new_inner(raw_path, staged_path, expected_size, expected_sha256);
    if result.as_ref().is_err_and(|error| {
        !matches!(
            error,
            ConversionExecutionError::StagedRawAlreadyExists { .. }
        )
    }) {
        remove_failed_output(staged_path);
    }
    result
}

fn copy_raw_stage_create_new_inner(
    raw_path: &Path,
    staged_path: &Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<(), ConversionExecutionError> {
    let mut source =
        File::open(raw_path).map_err(|source| ConversionExecutionError::StagedRawReadFailed {
            path: raw_path.to_path_buf(),
            source,
        })?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(staged_path)
        .map_err(|source| {
            if source.kind() == io::ErrorKind::AlreadyExists {
                ConversionExecutionError::StagedRawAlreadyExists {
                    path: staged_path.to_path_buf(),
                }
            } else {
                ConversionExecutionError::StagedRawWriteFailed {
                    path: staged_path.to_path_buf(),
                    source,
                }
            }
        })?;
    let mut hasher = Sha256::new();
    let mut copied_size = 0_u64;
    let mut buffer = raw_stage_hash_buffer();
    loop {
        let read = source.read(&mut buffer).map_err(|source| {
            ConversionExecutionError::StagedRawReadFailed {
                path: raw_path.to_path_buf(),
                source,
            }
        })?;
        if read == 0 {
            break;
        }
        destination.write_all(&buffer[..read]).map_err(|source| {
            ConversionExecutionError::StagedRawWriteFailed {
                path: staged_path.to_path_buf(),
                source,
            }
        })?;
        hasher.update(&buffer[..read]);
        copied_size = copied_size.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }
    destination
        .sync_all()
        .map_err(|source| ConversionExecutionError::StagedRawWriteFailed {
            path: staged_path.to_path_buf(),
            source,
        })?;

    let actual_sha256 = format!("{:x}", hasher.finalize());
    if copied_size != expected_size {
        return Err(ConversionExecutionError::StagedRawSizeMismatch {
            path: staged_path.to_path_buf(),
            expected: expected_size,
            actual: copied_size,
        });
    }
    if actual_sha256 != expected_sha256 {
        return Err(ConversionExecutionError::StagedRawSha256Mismatch {
            path: staged_path.to_path_buf(),
            expected: expected_sha256.to_string(),
            actual: actual_sha256,
        });
    }
    Ok(())
}

struct RawStageChildSelfTimeout;

impl RawStageChildSelfTimeout {
    fn install(timeout: Duration) -> io::Result<Self> {
        install_raw_stage_child_self_timeout(timeout)?;
        Ok(Self)
    }
}

impl Drop for RawStageChildSelfTimeout {
    fn drop(&mut self) {
        let _ = clear_raw_stage_child_self_timeout();
    }
}

#[cfg(unix)]
fn install_raw_stage_child_self_timeout(timeout: Duration) -> io::Result<()> {
    let seconds = timeout.as_secs().max(1);
    let seconds = libc::c_uint::try_from(seconds).unwrap_or(libc::c_uint::MAX);
    unsafe {
        libc::alarm(seconds);
    }
    Ok(())
}

#[cfg(unix)]
fn clear_raw_stage_child_self_timeout() -> io::Result<()> {
    unsafe {
        libc::alarm(0);
    }
    Ok(())
}

#[cfg(not(unix))]
fn install_raw_stage_child_self_timeout(_timeout: Duration) -> io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn clear_raw_stage_child_self_timeout() -> io::Result<()> {
    Ok(())
}

fn verify_staged_raw_hash(
    staged_path: &Path,
    nas_proof: &NasRawProof,
) -> Result<(), ConversionExecutionError> {
    let mut staged_file = File::open(staged_path).map_err(|source| {
        ConversionExecutionError::StagedRawReadFailed {
            path: staged_path.to_path_buf(),
            source,
        }
    })?;
    let mut hasher = Sha256::new();
    let mut copied_size = 0_u64;
    let mut buffer = raw_stage_hash_buffer();
    loop {
        let read = staged_file.read(&mut buffer).map_err(|source| {
            ConversionExecutionError::StagedRawReadFailed {
                path: staged_path.to_path_buf(),
                source,
            }
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        copied_size = copied_size.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
    }

    let actual_sha256 = format!("{:x}", hasher.finalize());
    if copied_size != nas_proof.size_bytes {
        return Err(ConversionExecutionError::StagedRawSizeMismatch {
            path: staged_path.to_path_buf(),
            expected: nas_proof.size_bytes,
            actual: copied_size,
        });
    }
    if actual_sha256 != nas_proof.sha256 {
        return Err(ConversionExecutionError::StagedRawSha256Mismatch {
            path: staged_path.to_path_buf(),
            expected: nas_proof.sha256.clone(),
            actual: actual_sha256,
        });
    }
    Ok(())
}

fn raw_stage_hash_buffer() -> Vec<u8> {
    vec![0_u8; RAW_STAGE_HASH_BUFFER_BYTES]
}

fn decode_staging_nas_proof(
    asset_id: &str,
    raw_path: &Path,
    nas_proof_value: Option<&Value>,
) -> Result<NasRawProof, ConversionExecutionError> {
    let value =
        nas_proof_value.ok_or_else(|| ConversionExecutionError::StagingNasProofMissing {
            asset_id: asset_id.to_string(),
        })?;
    let proof: NasRawProof = serde_json::from_value(value.clone()).map_err(|source| {
        ConversionExecutionError::StagingNasProofMalformed {
            asset_id: asset_id.to_string(),
            source,
        }
    })?;
    validate_staging_nas_proof(asset_id, raw_path, &proof)?;
    Ok(proof)
}

fn validate_staging_nas_proof(
    asset_id: &str,
    raw_path: &Path,
    proof: &NasRawProof,
) -> Result<(), ConversionExecutionError> {
    if proof.canonical_path != raw_path {
        return Err(ConversionExecutionError::StagingNasProofPathMismatch {
            asset_id: asset_id.to_string(),
            expected: raw_path.to_path_buf(),
            actual: proof.canonical_path.clone(),
        });
    }
    if proof.size_bytes == 0 {
        return Err(ConversionExecutionError::StagingNasProofInvalid {
            asset_id: asset_id.to_string(),
            field: "size_bytes",
            reason: "must be greater than zero",
        });
    }
    if !is_valid_sha256_hex(&proof.sha256) {
        return Err(ConversionExecutionError::StagingNasProofInvalid {
            asset_id: asset_id.to_string(),
            field: "sha256",
            reason: "must be a 64-character hexadecimal SHA-256 digest",
        });
    }
    Ok(())
}

fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn refuse_preexisting_staged_raw(path: &Path) -> Result<(), ConversionExecutionError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(ConversionExecutionError::StagedRawAlreadyExists {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ConversionExecutionError::StagedRawWriteFailed {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn verify_staged_raw_file(path: &Path, expected_size: u64) -> Result<(), ConversionExecutionError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| {
        ConversionExecutionError::StagedRawReadFailed {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err(ConversionExecutionError::StagedRawNotRegular {
            path: path.to_path_buf(),
        });
    }
    if metadata.len() != expected_size {
        return Err(ConversionExecutionError::StagedRawSizeMismatch {
            path: path.to_path_buf(),
            expected: expected_size,
            actual: metadata.len(),
        });
    }
    Ok(())
}

fn staged_raw_path_for_output(output_path: &Path, raw_path: &Path) -> PathBuf {
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

struct StagedRaw {
    path: PathBuf,
}

impl StagedRaw {
    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for StagedRaw {
    fn drop(&mut self) {
        remove_failed_output(&self.path);
    }
}

fn conversion_tool_name(plan: &crate::conversion::ConversionPlan) -> String {
    match plan.conversion_commands.as_slice() {
        [] => plan.convert.program.clone(),
        [command] => command.program.clone(),
        commands => commands
            .iter()
            .map(|command| command.program.as_str())
            .collect::<Vec<_>>()
            .join("+"),
    }
}

fn refuse_preexisting_output(path: &Path) -> Result<(), ConversionExecutionError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(ConversionExecutionError::OutputAlreadyExists {
            path: path.to_path_buf(),
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ConversionExecutionError::OutputUnreadable {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn run_planned_command(
    stage: &'static str,
    plan: &CommandPlan,
) -> Result<ChildResourceUsage, ConversionExecutionError> {
    if let Some(path) = &plan.checked_output_path {
        refuse_preexisting_output(path)?;
    }
    let resolved_program = resolve_sanitized_path_tool(&plan.program)?;
    let mut command = Command::new(resolved_program);
    let stdout = match &plan.stdout_path {
        Some(path) => Stdio::from(create_new_stdout_file(path)?),
        None => Stdio::null(),
    };
    command.args(&plan.args).stdin(Stdio::null()).stdout(stdout);
    let outcome = wait_for_command_with_usage(stage, &plan.program, command)?;
    if !outcome.status.success() {
        return Err(ConversionExecutionError::CommandFailed {
            stage,
            program: plan.program.clone(),
            status: outcome.status.to_string(),
        });
    }
    if let Some(path) = &plan.stdout_path {
        inspect_required_intermediate_output(path)?;
    }
    if let Some(path) = &plan.checked_output_path {
        inspect_required_intermediate_output(path)?;
    }
    Ok(outcome.resource_usage)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreviewProbe {
    preview_tag: EmbeddedPreviewTag,
    orientation: Option<ExifOrientation>,
}

fn probe_embedded_preview(raw_path: &Path) -> Result<PreviewProbe, ConversionExecutionError> {
    let resolved_program = resolve_sanitized_path_tool("exiftool")?;
    let mut command = Command::new(resolved_program);
    command
        .args(["-j", "-n", "-PreviewImage", "-JpgFromRaw", "-Orientation#"])
        .arg(raw_path)
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    let output = run_command_with_output("preview_probe", "exiftool", command)?;
    if !output.status.success() {
        return Err(ConversionExecutionError::CommandFailed {
            stage: "preview_probe",
            program: "exiftool".to_string(),
            status: output.status.to_string(),
        });
    }
    let records: Vec<Value> = serde_json::from_slice(&output.stdout)
        .map_err(|source| ConversionExecutionError::PreviewProbeDecode { source })?;
    let fields = records
        .first()
        .and_then(Value::as_object)
        .ok_or(ConversionExecutionError::InvalidPreviewProbeResponse)?;
    let preview_tag = if has_embedded_preview_field(fields, "PreviewImage") {
        EmbeddedPreviewTag::PreviewImage
    } else if has_embedded_preview_field(fields, "JpgFromRaw") {
        EmbeddedPreviewTag::JpgFromRaw
    } else {
        return Err(ConversionExecutionError::EmbeddedPreviewUnavailable {
            path: raw_path.to_path_buf(),
        });
    };
    Ok(PreviewProbe {
        preview_tag,
        orientation: exif_orientation_field(fields),
    })
}

fn exif_orientation_field(fields: &Map<String, Value>) -> Option<ExifOrientation> {
    fields
        .get("Orientation")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .map(ExifOrientation::from_numeric)
}

fn has_embedded_preview_field(fields: &Map<String, Value>, key: &str) -> bool {
    fields.get(key).is_some_and(|value| match value {
        Value::String(value) => !value.trim().is_empty(),
        Value::Object(object) => !object.is_empty(),
        Value::Array(values) => !values.is_empty(),
        Value::Null => false,
        Value::Bool(_) | Value::Number(_) => true,
    })
}

fn create_new_stdout_file(path: &Path) -> Result<File, ConversionExecutionError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| {
            if source.kind() == io::ErrorKind::AlreadyExists {
                ConversionExecutionError::OutputAlreadyExists {
                    path: path.to_path_buf(),
                }
            } else {
                ConversionExecutionError::OutputUnreadable {
                    path: path.to_path_buf(),
                    source,
                }
            }
        })
}

fn remove_failed_output(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
            let _ = fs::remove_file(path);
        }
        _ => {}
    }
}

fn remove_generated_intermediates_after_error(
    output_path: &Path,
    error: &ConversionExecutionError,
) {
    let embedded_path = generated_intermediate_path(output_path, "embedded-preview.jpg");
    let oriented_path = generated_intermediate_path(output_path, "oriented-preview.jpg");
    match error {
        ConversionExecutionError::OutputAlreadyExists { path } if *path == embedded_path => {}
        ConversionExecutionError::OutputAlreadyExists { path } if *path == oriented_path => {
            remove_failed_output(&embedded_path);
        }
        _ => {
            remove_generated_intermediates(output_path);
        }
    }
}

fn remove_generated_intermediates(output_path: &Path) {
    remove_failed_output(&generated_intermediate_path(
        output_path,
        "embedded-preview.jpg",
    ));
    remove_failed_output(&generated_intermediate_path(
        output_path,
        "oriented-preview.jpg",
    ));
}

fn generated_intermediate_path(output_path: &Path, extension: &str) -> PathBuf {
    let mut path = output_path.to_path_buf();
    path.set_extension(extension);
    path
}

fn run_planned_commands(
    stage: &'static str,
    plans: &[CommandPlan],
) -> Result<PlannedCommandsOutcome, ConversionExecutionError> {
    let mut resource_usage = ChildResourceUsage::default();
    let mut command_timings = Vec::with_capacity(plans.len());
    for plan in plans {
        let started = Instant::now();
        let command_usage = run_planned_command(stage, plan)?;
        let wall_time_millis = positive_millis(started.elapsed());
        resource_usage = resource_usage.combine(command_usage);
        command_timings.push(ConversionCommandTiming {
            program: plan.program.clone(),
            wall_time_millis,
        });
    }
    Ok(PlannedCommandsOutcome {
        resource_usage,
        command_timings,
    })
}

fn run_planned_adjusted_source_commands(
    stage: &'static str,
    plans: &[CommandPlan],
    source: &MaterializedAdjustedSource,
) -> Result<PlannedCommandsOutcome, ConversionExecutionError> {
    let [plan] = plans else {
        return Err(ConversionExecutionError::AdjustedSourceCommandPlan);
    };
    let started = Instant::now();
    let resource_usage = run_planned_adjusted_source_command(stage, plan, source)?;
    Ok(PlannedCommandsOutcome {
        resource_usage,
        command_timings: vec![ConversionCommandTiming {
            program: plan.program.clone(),
            wall_time_millis: positive_millis(started.elapsed()),
        }],
    })
}

#[cfg(unix)]
fn run_planned_adjusted_source_command(
    stage: &'static str,
    plan: &CommandPlan,
    source: &MaterializedAdjustedSource,
) -> Result<ChildResourceUsage, ConversionExecutionError> {
    #[cfg(target_os = "macos")]
    if plan.program == "sips" {
        return run_macos_adjusted_source_command(stage, plan, source);
    }

    use std::os::unix::process::CommandExt;

    if let Some(path) = &plan.checked_output_path {
        refuse_preexisting_output(path)?;
    }
    if !fs::metadata("/dev/fd").is_ok_and(|metadata| metadata.is_dir()) {
        return Err(ConversionExecutionError::AdjustedSourceDescriptorUnavailable);
    }
    let descriptor = match plan.program.as_str() {
        "sips" => source.duplicate_file_for_encoder(),
        "heif-enc" => duplicate_linux_adjusted_source_for_encoder(source),
        _ => return Err(ConversionExecutionError::AdjustedSourceCommandPlan),
    }
    .map_err(|error| ConversionExecutionError::Workflow(WorkflowError::AdjustedSource(error)))?;
    let descriptor_fd = descriptor.raw_fd();
    let descriptor_input = descriptor.input_path();
    let matching_input_positions = plan
        .args
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| (argument == source.path().as_os_str()).then_some(index))
        .collect::<Vec<_>>();
    let [input_position] = matching_input_positions.as_slice() else {
        return Err(ConversionExecutionError::AdjustedSourceCommandPlan);
    };
    let mut args = plan.args.clone();
    args[*input_position] = descriptor_input;

    #[cfg(test)]
    let unrelated_child = test_spawn_unrelated_child_without_adjusted_descriptor(descriptor_fd)?;
    #[cfg(test)]
    test_replace_staging_path_after_validation(source.path())?;

    let resolved_program = resolve_sanitized_path_tool(&plan.program)?;
    let mut command = Command::new(resolved_program);
    let stdout = match &plan.stdout_path {
        Some(path) => Stdio::from(create_new_stdout_file(path)?),
        None => Stdio::null(),
    };
    unsafe {
        command.pre_exec(move || clear_close_on_exec(descriptor_fd));
    }
    command.args(&args).stdin(Stdio::null()).stdout(stdout);
    command.process_group(0);
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            drop(descriptor);
            #[cfg(test)]
            test_reap_unrelated_child(unrelated_child);
            return Err(error.into());
        }
    };
    drop(descriptor);
    #[cfg(test)]
    if let Err(error) = test_assert_parent_descriptor_closed(descriptor_fd, &child) {
        let _ = wait_for_child_with_usage(stage, &plan.program, child);
        let _ = test_wait_for_unrelated_child(unrelated_child);
        return Err(error);
    }
    let outcome = wait_for_child_with_usage(stage, &plan.program, child);
    #[cfg(test)]
    test_wait_for_unrelated_child(unrelated_child)?;
    let outcome = outcome?;
    if !outcome.status.success() {
        return Err(ConversionExecutionError::CommandFailed {
            stage,
            program: plan.program.clone(),
            status: outcome.status.to_string(),
        });
    }
    if let Some(path) = &plan.stdout_path {
        inspect_required_intermediate_output(path)?;
    }
    if let Some(path) = &plan.checked_output_path {
        inspect_required_intermediate_output(path)?;
    }
    Ok(outcome.resource_usage)
}

#[cfg(target_os = "macos")]
fn run_macos_adjusted_source_command(
    stage: &'static str,
    plan: &CommandPlan,
    source: &MaterializedAdjustedSource,
) -> Result<ChildResourceUsage, ConversionExecutionError> {
    use std::os::unix::process::CommandExt;

    source.revalidate_for_command().map_err(|error| {
        ConversionExecutionError::Workflow(WorkflowError::AdjustedSource(error))
    })?;
    if let Some(path) = &plan.checked_output_path {
        refuse_preexisting_output(path)?;
    }
    let matching_input_positions = plan
        .args
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| (argument == source.path().as_os_str()).then_some(index))
        .collect::<Vec<_>>();
    let [input_position] = matching_input_positions.as_slice() else {
        return Err(ConversionExecutionError::AdjustedSourceCommandPlan);
    };
    let mut args = plan.args.clone();
    args[*input_position] = source.path().as_os_str().to_os_string();

    let resolved_program = resolve_sanitized_path_tool(&plan.program)?;
    let mut command = Command::new(resolved_program);
    let stdout = match &plan.stdout_path {
        Some(path) => Stdio::from(create_new_stdout_file(path)?),
        None => Stdio::null(),
    };
    command.args(&args).stdin(Stdio::null()).stdout(stdout);
    command.process_group(0);
    let child = command.spawn()?;
    let outcome = wait_for_child_with_usage(stage, &plan.program, child)?;
    source.revalidate_for_command().map_err(|error| {
        ConversionExecutionError::Workflow(WorkflowError::AdjustedSource(error))
    })?;
    if !outcome.status.success() {
        return Err(ConversionExecutionError::CommandFailed {
            stage,
            program: plan.program.clone(),
            status: outcome.status.to_string(),
        });
    }
    if let Some(path) = &plan.stdout_path {
        inspect_required_intermediate_output(path)?;
    }
    if let Some(path) = &plan.checked_output_path {
        inspect_required_intermediate_output(path)?;
    }
    Ok(outcome.resource_usage)
}

#[cfg(target_os = "linux")]
fn duplicate_linux_adjusted_source_for_encoder(
    source: &MaterializedAdjustedSource,
) -> Result<
    crate::adjusted_source::AdjustedSourceEncoderDescriptor,
    crate::adjusted_source::AdjustedSourceError,
> {
    source.duplicate_directory_for_encoder()
}

#[cfg(not(target_os = "linux"))]
fn duplicate_linux_adjusted_source_for_encoder(
    source: &MaterializedAdjustedSource,
) -> Result<
    crate::adjusted_source::AdjustedSourceEncoderDescriptor,
    crate::adjusted_source::AdjustedSourceError,
> {
    // Cross-target planner tests run on macOS, whose /dev/fd does not support
    // descriptor-relative traversal. Native Linux execution always uses the
    // sealed directory descriptor above.
    source.duplicate_file_for_encoder()
}

#[cfg(unix)]
fn clear_close_on_exec(descriptor_fd: libc::c_int) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(descriptor_fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(descriptor_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) struct TestAdjustedEncoderStagingSwapGuard {
    previous: Option<Vec<u8>>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl TestAdjustedEncoderStagingSwapGuard {
    pub(crate) fn install(replacement: Vec<u8>) -> Self {
        let lock = TEST_ADJUSTED_ENCODER_STAGING_SWAP_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut configured = TEST_ADJUSTED_ENCODER_STAGING_SWAP
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = configured.replace(replacement);
        Self {
            previous,
            _lock: lock,
        }
    }
}

#[cfg(test)]
impl Drop for TestAdjustedEncoderStagingSwapGuard {
    fn drop(&mut self) {
        let mut configured = TEST_ADJUSTED_ENCODER_STAGING_SWAP
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *configured = self.previous.take();
    }
}

#[cfg(test)]
pub(crate) struct TestAdjustedDescriptorLeakCheckGuard {
    previous: Option<std::sync::Arc<std::sync::Mutex<Option<bool>>>>,
    observation: std::sync::Arc<std::sync::Mutex<Option<bool>>>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl TestAdjustedDescriptorLeakCheckGuard {
    pub(crate) fn install() -> Self {
        let lock = TEST_ADJUSTED_DESCRIPTOR_LEAK_CHECK_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut configured = TEST_ADJUSTED_DESCRIPTOR_LEAK_CHECK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let observation = std::sync::Arc::new(std::sync::Mutex::new(None));
        let previous = configured.replace(observation.clone());
        Self {
            previous,
            observation,
            _lock: lock,
        }
    }

    pub(crate) fn assert_parent_descriptor_was_closed(&self) {
        assert_eq!(
            *self
                .observation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Some(true),
            "the parent descriptor must be closed while the intended encoder child remains alive"
        );
    }
}

#[cfg(test)]
impl Drop for TestAdjustedDescriptorLeakCheckGuard {
    fn drop(&mut self) {
        let mut configured = TEST_ADJUSTED_DESCRIPTOR_LEAK_CHECK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *configured = self.previous.take();
    }
}

#[cfg(test)]
fn test_spawn_unrelated_child_without_adjusted_descriptor(
    descriptor_fd: libc::c_int,
) -> Result<Option<Child>, ConversionExecutionError> {
    let enabled = TEST_ADJUSTED_DESCRIPTOR_LEAK_CHECK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if enabled.is_none() {
        return Ok(None);
    }
    let descriptor_fd = descriptor_fd.to_string();
    Command::new("/bin/sh")
        .args([
            "-c",
            "test ! -e /dev/fd/$1 || exit 70; /bin/sleep 1",
            "adjusted-source-fd-leak-check",
            &descriptor_fd,
        ])
        .spawn()
        .map(Some)
        .map_err(ConversionExecutionError::Io)
}

#[cfg(test)]
fn test_assert_parent_descriptor_closed(
    descriptor_fd: libc::c_int,
    child: &Child,
) -> Result<(), ConversionExecutionError> {
    let observation = TEST_ADJUSTED_DESCRIPTOR_LEAK_CHECK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let Some(observation) = observation else {
        return Ok(());
    };
    let descriptor_closed = unsafe { libc::fcntl(descriptor_fd, libc::F_GETFD) } < 0
        && io::Error::last_os_error().raw_os_error() == Some(libc::EBADF);
    let child_is_alive = unsafe { libc::kill(child.id() as libc::pid_t, 0) } == 0;
    let passed = descriptor_closed && child_is_alive;
    *observation
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(passed);
    if passed {
        Ok(())
    } else {
        Err(ConversionExecutionError::Io(io::Error::other(
            "parent retained adjusted source descriptor after encoder spawn",
        )))
    }
}

#[cfg(test)]
fn test_wait_for_unrelated_child(
    unrelated_child: Option<Child>,
) -> Result<(), ConversionExecutionError> {
    let Some(mut unrelated_child) = unrelated_child else {
        return Ok(());
    };
    let status = unrelated_child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(ConversionExecutionError::Io(io::Error::other(
            "unrelated child inherited adjusted source descriptor",
        )))
    }
}

#[cfg(test)]
fn test_reap_unrelated_child(unrelated_child: Option<Child>) {
    if let Some(mut unrelated_child) = unrelated_child {
        let _ = unrelated_child.wait();
    }
}

#[cfg(test)]
fn test_replace_staging_path_after_validation(
    staged_path: &Path,
) -> Result<(), ConversionExecutionError> {
    let replacement = TEST_ADJUSTED_ENCODER_STAGING_SWAP
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let Some(replacement) = replacement else {
        return Ok(());
    };
    let staging_directory = staged_path.parent().ok_or_else(|| {
        ConversionExecutionError::Io(io::Error::other("staged source has no parent directory"))
    })?;
    let displaced_directory = staging_directory.with_extension("displaced-by-test");
    #[cfg(target_os = "macos")]
    {
        let _ = replacement;
        match fs::rename(staging_directory, displaced_directory) {
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(()),
            Err(error) => Err(ConversionExecutionError::Io(error)),
            Ok(()) => Err(ConversionExecutionError::Io(io::Error::other(
                "immutable macOS staging directory was renamed",
            ))),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        fs::rename(staging_directory, &displaced_directory)?;
        fs::create_dir(staging_directory)?;
        fs::write(staging_directory.join("source.jpg"), replacement)?;
        Ok(())
    }
}

#[cfg(not(unix))]
fn run_planned_adjusted_source_command(
    _stage: &'static str,
    _plan: &CommandPlan,
    _source: &MaterializedAdjustedSource,
) -> Result<ChildResourceUsage, ConversionExecutionError> {
    Err(ConversionExecutionError::AdjustedSourceDescriptorUnavailable)
}

fn resolve_sanitized_path_tool(program: &str) -> Result<PathBuf, ConversionExecutionError> {
    let Some(paths) = env::var_os("PATH") else {
        return Err(ConversionExecutionError::ToolNotFound {
            program: program.to_string(),
        });
    };

    env::split_paths(&paths)
        .filter(|directory| !directory.as_os_str().is_empty())
        .filter_map(|directory| {
            let candidate = directory.join(program);
            if is_executable_file(&candidate) {
                fs::canonicalize(candidate).ok()
            } else {
                None
            }
        })
        .next()
        .ok_or_else(|| ConversionExecutionError::ToolNotFound {
            program: program.to_string(),
        })
}

#[cfg(unix)]
pub(crate) fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    path.is_file()
        && path
            .metadata()
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

#[cfg(not(unix))]
pub(crate) fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(unix)]
fn wait_for_command_with_usage(
    stage: &'static str,
    program: &str,
    mut command: Command,
) -> Result<CommandOutcome, ConversionExecutionError> {
    use std::os::unix::process::CommandExt;

    command.process_group(0);
    let child = command.spawn()?;
    wait_for_child_with_usage(stage, program, child)
}

#[cfg(unix)]
fn wait_for_child_with_usage(
    stage: &'static str,
    program: &str,
    child: Child,
) -> Result<CommandOutcome, ConversionExecutionError> {
    use std::mem::MaybeUninit;
    use std::os::unix::process::ExitStatusExt;

    let pid = child.id() as libc::pid_t;
    let mut status = 0;
    let mut usage = MaybeUninit::<libc::rusage>::zeroed();
    let timeout = child_command_timeout();
    let started = Instant::now();

    loop {
        let result = unsafe { libc::wait4(pid, &mut status, libc::WNOHANG, usage.as_mut_ptr()) };
        if result > 0 {
            let usage = unsafe { usage.assume_init() };
            return Ok(CommandOutcome {
                status: ExitStatus::from_raw(status),
                resource_usage: ChildResourceUsage::from_rusage(&usage),
            });
        }
        if result == 0 {
            if started.elapsed() >= timeout {
                kill_and_reap_unix_child(pid, &mut status, usage.as_mut_ptr())?;
                return Err(command_timeout_error(stage, program, timeout));
            }
            thread::sleep(command_poll_interval(started.elapsed(), timeout));
            continue;
        }

        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

#[cfg(not(unix))]
fn wait_for_command_with_usage(
    stage: &'static str,
    program: &str,
    mut command: Command,
) -> Result<CommandOutcome, ConversionExecutionError> {
    let child = command.spawn()?;
    wait_for_child_with_usage(stage, program, child)
}

#[cfg(not(unix))]
fn wait_for_child_with_usage(
    stage: &'static str,
    program: &str,
    mut child: Child,
) -> Result<CommandOutcome, ConversionExecutionError> {
    let timeout = child_command_timeout();
    let started = Instant::now();

    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(CommandOutcome {
                status,
                resource_usage: ChildResourceUsage::default(),
            });
        }
        if started.elapsed() >= timeout {
            child.kill()?;
            let _ = child.wait()?;
            return Err(command_timeout_error(stage, program, timeout));
        }
        thread::sleep(command_poll_interval(started.elapsed(), timeout));
    }
}

fn run_command_with_output(
    stage: &'static str,
    program: &str,
    mut command: Command,
) -> Result<CommandOutput, ConversionExecutionError> {
    command.stdout(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;

        command.process_group(0);
    }
    let mut child = command.spawn()?;
    let mut stdout = child.stdout.take().ok_or_else(|| {
        ConversionExecutionError::Io(io::Error::other("child stdout was not piped"))
    })?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let outcome = wait_for_child_with_usage(stage, program, child);
    let stdout = match stdout_reader.join() {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(source)) => return Err(ConversionExecutionError::Io(source)),
        Err(_) => {
            return Err(ConversionExecutionError::Io(io::Error::other(
                "child stdout reader panicked",
            )));
        }
    };
    let outcome = outcome?;

    Ok(CommandOutput {
        status: outcome.status,
        stdout,
    })
}

fn child_command_timeout() -> Duration {
    #[cfg(test)]
    if let Some(timeout) = *TEST_CHILD_COMMAND_TIMEOUT
        .lock()
        .expect("test child command timeout lock should not be poisoned")
    {
        return timeout;
    }

    DEFAULT_CHILD_COMMAND_TIMEOUT
}

fn command_poll_interval(elapsed: Duration, timeout: Duration) -> Duration {
    timeout
        .saturating_sub(elapsed)
        .min(CHILD_COMMAND_POLL_INTERVAL)
}

fn command_timeout_error(
    stage: &'static str,
    program: &str,
    timeout: Duration,
) -> ConversionExecutionError {
    ConversionExecutionError::CommandTimedOut {
        stage,
        program: program.to_string(),
        timeout_millis: timeout.as_millis().max(1),
    }
}

#[cfg(unix)]
fn kill_and_reap_unix_child(
    pid: libc::pid_t,
    status: &mut libc::c_int,
    usage: *mut libc::rusage,
) -> io::Result<()> {
    let kill_result = unsafe { libc::kill(-pid, libc::SIGKILL) };
    if kill_result < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }

    loop {
        let wait_result = unsafe { libc::wait4(pid, status, 0, usage) };
        if wait_result >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn inspect_output(path: &Path) -> Result<ConvertedOutput, ConversionExecutionError> {
    inspect_output_with_optional_post_hash(path, Option::<fn(&Path) -> io::Result<()>>::None)
}

fn inspect_required_intermediate_output(path: &Path) -> Result<(), ConversionExecutionError> {
    let metadata =
        fs::metadata(path).map_err(|source| ConversionExecutionError::OutputUnreadable {
            path: path.to_path_buf(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(ConversionExecutionError::OutputUnreadable {
            path: path.to_path_buf(),
            source: io::Error::new(io::ErrorKind::InvalidData, "output is not a regular file"),
        });
    }
    if metadata.len() == 0 {
        return Err(ConversionExecutionError::OutputEmpty {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn inspect_output_with_optional_post_hash(
    path: &Path,
    post_hash: Option<impl FnOnce(&Path) -> io::Result<()>>,
) -> Result<ConvertedOutput, ConversionExecutionError> {
    let metadata =
        fs::metadata(path).map_err(|source| ConversionExecutionError::OutputUnreadable {
            path: path.to_path_buf(),
            source,
        })?;
    let before = OutputMetadataSnapshot::from_metadata(&metadata).map_err(|source| {
        ConversionExecutionError::OutputUnreadable {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(ConversionExecutionError::OutputEmpty {
            path: path.to_path_buf(),
        });
    }

    let mut file =
        File::open(path).map_err(|source| ConversionExecutionError::OutputUnreadable {
            path: path.to_path_buf(),
            source,
        })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let read = file.read(&mut buffer).map_err(|source| {
            ConversionExecutionError::OutputUnreadable {
                path: path.to_path_buf(),
                source,
            }
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    if let Some(post_hash) = post_hash {
        post_hash(path).map_err(|source| ConversionExecutionError::OutputUnreadable {
            path: path.to_path_buf(),
            source,
        })?;
    }
    let after_metadata =
        fs::metadata(path).map_err(|source| ConversionExecutionError::OutputUnreadable {
            path: path.to_path_buf(),
            source,
        })?;
    let after = OutputMetadataSnapshot::from_metadata(&after_metadata).map_err(|source| {
        ConversionExecutionError::OutputUnreadable {
            path: path.to_path_buf(),
            source,
        }
    })?;
    if before != after {
        return Err(ConversionExecutionError::OutputChanged {
            path: path.to_path_buf(),
        });
    }

    Ok(ConvertedOutput {
        size_bytes: metadata.len(),
        sha256: format!("{:x}", hasher.finalize()),
    })
}

#[cfg(test)]
fn inspect_output_with_post_hash_hook(
    path: &Path,
    post_hash: impl FnOnce(&Path) -> io::Result<()>,
) -> Result<ConvertedOutput, ConversionExecutionError> {
    inspect_output_with_optional_post_hash(path, Some(post_hash))
}

fn positive_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis())
        .unwrap_or(u64::MAX)
        .max(1)
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

struct ConvertedOutput {
    size_bytes: u64,
    sha256: String,
}

#[derive(Debug, Eq, PartialEq)]
struct OutputMetadataSnapshot {
    size_bytes: u64,
    modified: SystemTime,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl OutputMetadataSnapshot {
    fn from_metadata(metadata: &fs::Metadata) -> io::Result<Self> {
        Ok(Self {
            size_bytes: metadata.len(),
            modified: metadata.modified()?,
            #[cfg(unix)]
            device: {
                use std::os::unix::fs::MetadataExt;
                metadata.dev()
            },
            #[cfg(unix)]
            inode: {
                use std::os::unix::fs::MetadataExt;
                metadata.ino()
            },
        })
    }
}

struct CommandOutcome {
    status: ExitStatus,
    resource_usage: ChildResourceUsage,
}

struct CommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
}

struct RawStageCopyCommand {
    program: String,
    command: Command,
}

struct PlannedCommandsOutcome {
    resource_usage: ChildResourceUsage,
    command_timings: Vec<ConversionCommandTiming>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ChildResourceUsage {
    user_cpu_time_millis: Option<u64>,
    system_cpu_time_millis: Option<u64>,
    peak_rss_kib: Option<u64>,
}

impl ChildResourceUsage {
    fn combine(self, other: Self) -> Self {
        Self {
            user_cpu_time_millis: combine_sum(
                self.user_cpu_time_millis,
                other.user_cpu_time_millis,
            ),
            system_cpu_time_millis: combine_sum(
                self.system_cpu_time_millis,
                other.system_cpu_time_millis,
            ),
            peak_rss_kib: combine_max(self.peak_rss_kib, other.peak_rss_kib),
        }
    }

    #[cfg(unix)]
    fn from_rusage(usage: &libc::rusage) -> Self {
        Self {
            user_cpu_time_millis: Some(timeval_millis(usage.ru_utime)),
            system_cpu_time_millis: Some(timeval_millis(usage.ru_stime)),
            peak_rss_kib: normalize_peak_rss_kib(usage.ru_maxrss),
        }
    }
}

fn combine_sum(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.saturating_add(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn combine_max(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

#[cfg(unix)]
fn timeval_millis(value: libc::timeval) -> u64 {
    let seconds = u64::try_from(value.tv_sec).unwrap_or(0);
    let micros = u64::try_from(value.tv_usec).unwrap_or(0);
    seconds.saturating_mul(1_000).saturating_add(micros / 1_000)
}

#[cfg(all(unix, target_os = "macos"))]
fn normalize_peak_rss_kib(ru_maxrss: libc::c_long) -> Option<u64> {
    let bytes = u64::try_from(ru_maxrss).ok()?;
    if bytes == 0 {
        None
    } else {
        Some(bytes.div_ceil(1024))
    }
}

#[cfg(all(
    unix,
    not(target_os = "macos"),
    any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    )
))]
fn normalize_peak_rss_kib(ru_maxrss: libc::c_long) -> Option<u64> {
    match u64::try_from(ru_maxrss).ok()? {
        0 => None,
        value => Some(value),
    }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "macos",
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))
))]
fn normalize_peak_rss_kib(_ru_maxrss: libc::c_long) -> Option<u64> {
    None
}

#[derive(Debug, Error)]
pub enum ConversionExecutionError {
    #[error("conversion planning failed: {0}")]
    Plan(#[from] ConversionError),
    #[error("workflow failed: {0}")]
    Workflow(#[from] WorkflowError),
    #[error("manifest failed: {0}")]
    Manifest(#[from] ManifestError),
    #[error("failed to run conversion tool: {0}")]
    Io(#[from] io::Error),
    #[error("unsupported conversion backend {backend}: {reason}")]
    UnsupportedBackend {
        backend: &'static str,
        reason: &'static str,
    },
    #[error("conversion tool not found on sanitized PATH: {program}")]
    ToolNotFound { program: String },
    #[error(
        "adjusted conversion plan must contain exactly one encoder command with one staged input"
    )]
    AdjustedSourceCommandPlan,
    #[error("this platform cannot pass the validated adjusted JPEG descriptor to the encoder")]
    AdjustedSourceDescriptorUnavailable,
    #[error("{stage} command failed: {program} exited with {status}")]
    CommandFailed {
        stage: &'static str,
        program: String,
        status: String,
    },
    #[error("{stage} command timed out after {timeout_millis} ms: {program}")]
    CommandTimedOut {
        stage: &'static str,
        program: String,
        timeout_millis: u128,
    },
    #[error("failed to decode embedded preview probe output: {source}")]
    PreviewProbeDecode { source: serde_json::Error },
    #[error("embedded preview probe returned invalid output")]
    InvalidPreviewProbeResponse,
    #[error("RAW has neither PreviewImage nor JpgFromRaw embedded preview: {path}")]
    EmbeddedPreviewUnavailable { path: PathBuf },
    #[error("converted output is missing or unreadable at {path}: {source}")]
    OutputUnreadable { path: PathBuf, source: io::Error },
    #[error(
        "converted output already exists at {path}; refusing to overwrite without an explicit overwrite policy"
    )]
    OutputAlreadyExists { path: PathBuf },
    #[error("converted output is empty at {path}")]
    OutputEmpty { path: PathBuf },
    #[error("converted output changed while inspecting {path}; refusing to record a stale proof")]
    OutputChanged { path: PathBuf },
    #[error("NAS proof is missing for {asset_id}; refusing RAW staging")]
    StagingNasProofMissing { asset_id: String },
    #[error("NAS proof for {asset_id} is malformed: {source}")]
    StagingNasProofMalformed {
        asset_id: String,
        source: serde_json::Error,
    },
    #[error("NAS proof for {asset_id} has invalid {field}: {reason}")]
    StagingNasProofInvalid {
        asset_id: String,
        field: &'static str,
        reason: &'static str,
    },
    #[error(
        "NAS proof canonical_path for {asset_id} does not match record RAW path: expected {expected}, got {actual}"
    )]
    StagingNasProofPathMismatch {
        asset_id: String,
        expected: PathBuf,
        actual: PathBuf,
    },
    #[error("staged RAW already exists at {path}; refusing to overwrite")]
    StagedRawAlreadyExists { path: PathBuf },
    #[error("failed to read RAW for staging at {path}: {source}")]
    StagedRawReadFailed { path: PathBuf, source: io::Error },
    #[error("failed to write staged RAW at {path}: {source}")]
    StagedRawWriteFailed { path: PathBuf, source: io::Error },
    #[error("staged RAW at {path} is not a regular file")]
    StagedRawNotRegular { path: PathBuf },
    #[error("staged RAW size mismatch at {path}: expected {expected} bytes, copied {actual} bytes")]
    StagedRawSizeMismatch {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
    #[error("staged RAW sha256 mismatch at {path}: expected {expected}, copied {actual}")]
    StagedRawSha256Mismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    #[error("batch conversion requires at least one worker; got {jobs}")]
    InvalidBatchJobs { jobs: usize },
    #[error("batch conversion requires at least one asset")]
    EmptyBatch,
    #[error("batch conversion has duplicate asset id {asset_id}")]
    DuplicateBatchAsset { asset_id: String },
    #[error("batch conversion has duplicate output path {path}")]
    DuplicateBatchOutput { path: PathBuf },
    #[error("batch conversion worker panicked for {asset_id}")]
    BatchWorkerPanicked { asset_id: String },
    #[error("batch conversion failed for {asset_id}: {source}")]
    BatchConversionFailed {
        asset_id: String,
        source: Box<ConversionExecutionError>,
    },
}

impl ConversionExecutionError {
    pub fn failure_kind(&self) -> Option<FailureKind> {
        match self {
            Self::CommandTimedOut {
                stage: RAW_STAGING_STAGE,
                ..
            } => Some(FailureKind::RawStagingTimedOut),
            Self::CommandTimedOut { .. } => Some(FailureKind::ConversionTimedOut),
            Self::OutputUnreadable { .. } => Some(FailureKind::ConversionOutputUnreadable),
            Self::OutputAlreadyExists { .. } => Some(FailureKind::ConversionOutputAlreadyExists),
            Self::StagedRawAlreadyExists { .. } => Some(FailureKind::StagedRawAlreadyExists),
            Self::CommandFailed {
                stage: "metadata",
                program,
                ..
            } if program == "exiftool" => Some(FailureKind::ConversionMetadataFailed),
            Self::EmbeddedPreviewUnavailable { .. } => {
                Some(FailureKind::EmbeddedPreviewUnavailable)
            }
            Self::BatchConversionFailed { source, .. } => source.failure_kind(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::sync::{Mutex, MutexGuard};

    use crate::adjusted_source::{
        ADJUSTED_SOURCE_PROOF_SCHEMA_VERSION, CloudKitAdjustedSourceProof,
        TestMaterializationSwapGuard, adjusted_source_path_for_output,
        adjusted_source_proof_digest,
    };
    use crate::proof::NasRawProof;
    use crate::workflow::{
        ConversionSourceBinding, OriginalAssetProof, discover_raw_asset,
        record_adjusted_source_proof, record_nas_proof, record_original_asset_proof,
    };

    #[test]
    fn conversion_errors_expose_stable_failure_kinds_before_stringification() {
        use crate::manifest::FailureKind;

        let cases = [
            (
                ConversionExecutionError::CommandTimedOut {
                    stage: "conversion",
                    program: "heif-enc".to_string(),
                    timeout_millis: 120_000,
                },
                FailureKind::ConversionTimedOut,
            ),
            (
                ConversionExecutionError::CommandTimedOut {
                    stage: "raw_staging",
                    program: "icloudpd-optimizer".to_string(),
                    timeout_millis: 120_000,
                },
                FailureKind::RawStagingTimedOut,
            ),
            (
                ConversionExecutionError::OutputUnreadable {
                    path: PathBuf::from("asset.oriented-preview.jpg"),
                    source: io::Error::other("unreadable"),
                },
                FailureKind::ConversionOutputUnreadable,
            ),
            (
                ConversionExecutionError::OutputAlreadyExists {
                    path: PathBuf::from("asset.heic"),
                },
                FailureKind::ConversionOutputAlreadyExists,
            ),
            (
                ConversionExecutionError::StagedRawAlreadyExists {
                    path: PathBuf::from("asset.staged-raw.dng"),
                },
                FailureKind::StagedRawAlreadyExists,
            ),
            (
                ConversionExecutionError::CommandFailed {
                    stage: "metadata",
                    program: "exiftool".to_string(),
                    status: "exit status: 1".to_string(),
                },
                FailureKind::ConversionMetadataFailed,
            ),
            (
                ConversionExecutionError::EmbeddedPreviewUnavailable {
                    path: PathBuf::from("asset.dng"),
                },
                FailureKind::EmbeddedPreviewUnavailable,
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.failure_kind(), Some(expected));
        }
    }

    #[cfg(unix)]
    static PATH_LOCK: Mutex<()> = Mutex::new(());
    #[cfg(unix)]
    static RAW_STAGE_COPY_TEST_CONFIG_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn exif_orientation_field_maps_simple_rotations_and_preserves_unsupported_values() {
        let mut fields = Map::new();
        fields.insert("Orientation".to_string(), Value::from(6));
        assert_eq!(
            exif_orientation_field(&fields),
            Some(ExifOrientation::Rotate90Cw)
        );

        fields.insert("Orientation".to_string(), Value::from(5));
        assert_eq!(
            exif_orientation_field(&fields),
            Some(ExifOrientation::Unsupported(5))
        );

        fields.insert("Orientation".to_string(), Value::from("6"));
        assert_eq!(exif_orientation_field(&fields), None);
    }

    #[test]
    fn inspect_output_rejects_file_changed_after_hashing() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let output_path = tempdir.path().join("IMG_0001.heic");
        fs::write(&output_path, b"original-heic").expect("output should be written");

        let result = inspect_output_with_post_hash_hook(&output_path, |path| {
            fs::write(path, b"mutated-heic")
        });

        assert!(result.is_err(), "mutated output must fail closed");
    }

    #[test]
    fn conversion_cleanup_removes_only_generated_files_and_retains_adjusted_source_for_retry() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let output_path = tempdir.path().join("IMG_0001.heic");
        let adjusted_path = adjusted_source_path_for_output(&output_path);
        let embedded_path = embedded_preview_path(&output_path);
        let oriented_path = oriented_preview_path(&output_path);
        let staged_path = staged_raw_path_for_output(&output_path, Path::new("IMG_0001.dng"));
        fs::write(&output_path, b"partial-heic").expect("partial HEIC should be written");
        fs::write(&adjusted_path, b"proven-adjusted-source")
            .expect("adjusted source should be written");
        fs::write(&embedded_path, b"generated-preview")
            .expect("embedded preview should be written");
        fs::write(&oriented_path, b"generated-preview")
            .expect("oriented preview should be written");
        fs::write(&staged_path, b"staged-raw").expect("staged RAW should be written");

        remove_conversion_output_path(&output_path);
        remove_failed_output(&staged_path);

        assert_eq!(
            fs::read(&adjusted_path).expect("proven source must survive cleanup"),
            b"proven-adjusted-source"
        );
        assert!(!output_path.exists());
        assert!(!embedded_path.exists());
        assert!(!oriented_path.exists());
        assert!(!staged_path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn linux_conversion_runs_full_chain_and_records_chain_tool_name() {
        let tool_dir = fake_linux_conversion_tools();
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let output_path = tempdir.path().join("IMG_0001.heic");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let manifest = nas_verified_manifest(&raw_path);

        let updated = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: Some("linux-tools-1".to_string()),
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect("linux conversion chain should complete");

        let heic = fs::read(&output_path).expect("heic output should be readable");
        let record = updated.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::Converted);
        assert_eq!(
            record.proofs["conversion"]["heic_path"],
            output_path.to_string_lossy().as_ref()
        );
        assert_eq!(
            record.proofs["conversion"]["heic_sha256"],
            format!("{:x}", Sha256::digest(&heic))
        );
        assert_eq!(
            record.proofs["conversion_performance"]["conversion_tool"],
            "exiftool+exiftool+magick+heif-enc"
        );
        assert_eq!(
            record.proofs["conversion_performance"]["conversion_tool_version"],
            "linux-tools-1"
        );
        assert!(
            record.proofs["conversion_performance"]["total_wall_time_millis"]
                .as_u64()
                .expect("total wall time should be present")
                >= record.proofs["conversion_performance"]["convert_wall_time_millis"]
                    .as_u64()
                    .expect("convert wall time should be present")
        );
        let command_timings = record.proofs["conversion_performance"]["conversion_command_timings"]
            .as_array()
            .expect("command timings should be present");
        assert_eq!(command_timings.len(), 4);
        for (timing, program) in command_timings
            .iter()
            .zip(["exiftool", "exiftool", "magick", "heif-enc"])
        {
            assert_eq!(timing["program"], program);
            assert!(
                timing["wall_time_millis"]
                    .as_u64()
                    .expect("command timing should record positive millis")
                    > 0
            );
        }
        assert_eq!(
            fs::read_to_string(log_path).expect("command log should be readable"),
            "exiftool-preview\nexiftool-preview-orientation\nmagick-auto-orient\nheif-enc\nexiftool-metadata\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn linux_adjusted_conversion_skips_embedded_preview_probe_and_retains_proven_source() {
        let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
        write_executable_script(
            &tool_dir.path().join("heif-enc"),
            r#"#!/bin/sh
printf 'heif-enc\n' >> "$EXECUTION_LOG"
out=""
previous=""
input=""
for arg in "$@"; do
  if [ "$previous" = "-o" ]; then
    out="$arg"
  fi
  if [ "$arg" != "-q" ] && [ "$arg" != "-o" ] && [ "$previous" != "-q" ] && [ "$previous" != "-o" ]; then
    input="$arg"
  fi
  previous="$arg"
done
[ -n "$out" ] || exit 43
printf 'heif-input=%s\n' "$input" >> "$EXECUTION_LOG"
/bin/cat "$input" > "$out"
/bin/sleep 1
"#,
        );
        write_executable_script(
            &tool_dir.path().join("exiftool"),
            r#"#!/bin/sh
if [ "$1" = "-j" ] || [ "$1" = "-b" ]; then
  exit 66
fi
if [ "$1" = "-TagsFromFile" ]; then
  printf 'exiftool-metadata\n' >> "$EXECUTION_LOG"
  exit 0
fi
exit 67
"#,
        );
        write_executable_script(&tool_dir.path().join("magick"), "#!/bin/sh\nexit 68\n");
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let output_dir = tempdir
            .path()
            .canonicalize()
            .expect("tempdir should canonicalize")
            .join("out");
        fs::create_dir_all(&output_dir).expect("output directory should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        let raw_bytes = vec![b'r'; 4_096];
        fs::write(&raw_path, &raw_bytes).expect("raw should be written");
        let output_path = output_dir.join("IMG_0001.heic");
        let adjusted_path = adjusted_source_path_for_output(&output_path);
        let adjusted_bytes = adjusted_test_jpeg();
        fs::write(&adjusted_path, &adjusted_bytes).expect("adjusted JPEG should be written");
        let replacement_path = tempdir.path().join("replacement.jpg");
        let replacement_bytes = adjusted_test_jpeg_with_seed(197);
        fs::write(&replacement_path, &replacement_bytes)
            .expect("replacement JPEG should be written");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let mut manifest = nas_verified_manifest(&raw_path);
        let original = OriginalAssetProof {
            record_name: "original-record-1".to_string(),
            record_change_tag: "original-tag-1".to_string(),
            record_type: "CPLAsset".to_string(),
            database_scope: Default::default(),
            zone_name: "PrimarySync".to_string(),
            filename: "IMG_0001.dng".to_string(),
            size_bytes: raw_bytes.len() as u64,
            matched_raw_sha256: format!("{:x}", Sha256::digest(&raw_bytes)),
        };
        record_original_asset_proof(&mut manifest, "asset-1", original.clone())
            .expect("original asset proof should record");
        let adjusted =
            adjusted_test_proof("asset-1", &original, adjusted_path.clone(), &adjusted_bytes);
        record_adjusted_source_proof(&mut manifest, "asset-1", &output_path, adjusted.clone())
            .expect("adjusted proof should record");
        let _swap_guard = TestMaterializationSwapGuard::install(&replacement_path);
        let _staging_swap_guard = TestAdjustedEncoderStagingSwapGuard::install(
            b"untrusted lexical staging replacement".to_vec(),
        );
        let _descriptor_leak_guard = TestAdjustedDescriptorLeakCheckGuard::install();

        let updated = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect("adjusted conversion should complete without an embedded preview");
        _descriptor_leak_guard.assert_parent_descriptor_was_closed();

        let command_log = fs::read_to_string(&log_path).expect("command log should be readable");
        assert!(command_log.starts_with("heif-enc\nheif-input="));
        assert!(command_log.contains("/dev/fd/"));
        #[cfg(target_os = "linux")]
        assert!(
            command_log.lines().any(
                |line| line.starts_with("heif-input=/dev/fd/") && line.ends_with("/source.jpg")
            ),
            "heif-enc needs the exact directory-descriptor path with its .jpg suffix"
        );
        assert!(
            !command_log.contains(".conversion-"),
            "the encoder must not receive the lexical staged pathname"
        );
        assert!(
            !command_log.contains(adjusted_path.to_string_lossy().as_ref()),
            "encoder input must be the private materialization, not the proof pathname"
        );
        assert!(command_log.ends_with("exiftool-metadata\n"));
        assert_eq!(
            fs::read(&adjusted_path).expect("source should survive"),
            replacement_bytes
        );
        assert_eq!(
            fs::read(&output_path).expect("encoder output should be readable"),
            adjusted_bytes,
            "a source swap after materialization must not change encoder input"
        );
        assert!(!staged_raw_path_for_output(&output_path, &raw_path).exists());
        assert_eq!(
            serde_json::from_value::<ConversionSourceBinding>(
                updated.get("asset-1").expect("asset should exist").proofs["conversion"]
                    ["source_binding"]
                    .clone(),
            )
            .expect("source binding should deserialize"),
            ConversionSourceBinding::AdjustedSource {
                adjusted_source_proof_digest: adjusted_source_proof_digest(&adjusted),
                adjusted_jpeg_sha256: adjusted.downloaded_sha256,
                adjusted_jpeg_path: adjusted_path,
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn macos_adjusted_conversion_uses_private_staged_jpeg_with_dng_metadata_copy() {
        let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
        write_executable_script(
            &tool_dir.path().join("sips"),
            r#"#!/bin/sh
printf 'sips\n' >> "$EXECUTION_LOG"
input="$7"
for descriptor in /dev/fd/*; do
  target=$(/usr/bin/readlink "$descriptor" 2>/dev/null || true)
  case "$target" in
    /private/tmp/.icloudpd-adjusted-*) exit 69 ;;
  esac
done
out=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "--out" ]; then
    out="$arg"
  fi
  previous="$arg"
done
[ -n "$out" ] || exit 43
case "$input" in
  /private/tmp/.icloudpd-adjusted-*/source.jpg) ;;
  *) exit 44 ;;
esac
printf 'sips-input=%s\n' "$input" >> "$EXECUTION_LOG"
/bin/cat "$input" > "$out"
/bin/sleep 1
"#,
        );
        write_executable_script(
            &tool_dir.path().join("exiftool"),
            r#"#!/bin/sh
if [ "$1" = "-j" ] || [ "$1" = "-b" ]; then
  exit 66
fi
if [ "$1" = "-TagsFromFile" ]; then
  printf 'exiftool-metadata\n' >> "$EXECUTION_LOG"
  exit 0
fi
exit 67
"#,
        );
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let output_dir = tempdir
            .path()
            .canonicalize()
            .expect("tempdir should canonicalize")
            .join("out");
        fs::create_dir_all(&output_dir).expect("output directory should be created");
        let raw_path = tempdir.path().join("IMG_0002.dng");
        let raw_bytes = vec![b'r'; 4_096];
        fs::write(&raw_path, &raw_bytes).expect("raw should be written");
        let output_path = output_dir.join("IMG_0002.heic");
        let adjusted_path = adjusted_source_path_for_output(&output_path);
        let adjusted_bytes = adjusted_test_jpeg();
        fs::write(&adjusted_path, &adjusted_bytes).expect("adjusted JPEG should be written");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let mut manifest = nas_verified_manifest(&raw_path);
        let original = OriginalAssetProof {
            record_name: "original-record-2".to_string(),
            record_change_tag: "original-tag-2".to_string(),
            record_type: "CPLAsset".to_string(),
            database_scope: Default::default(),
            zone_name: "PrimarySync".to_string(),
            filename: "IMG_0002.dng".to_string(),
            size_bytes: raw_bytes.len() as u64,
            matched_raw_sha256: format!("{:x}", Sha256::digest(&raw_bytes)),
        };
        record_original_asset_proof(&mut manifest, "asset-1", original.clone())
            .expect("original asset proof should record");
        let adjusted =
            adjusted_test_proof("asset-1", &original, adjusted_path.clone(), &adjusted_bytes);
        record_adjusted_source_proof(&mut manifest, "asset-1", &output_path, adjusted)
            .expect("adjusted proof should record");

        execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("macos", "aarch64"),
        )
        .expect("macOS adjusted conversion should complete without preview extraction");

        let command_log = fs::read_to_string(&log_path).expect("command log should be readable");
        assert!(command_log.starts_with("sips\nsips-input="));
        assert!(
            command_log.lines().any(|line| line
                .starts_with("sips-input=/private/tmp/.icloudpd-adjusted-")
                && line.ends_with("/source.jpg")),
            "sips must receive only the immutable root-stable staging path"
        );
        assert!(!command_log.contains(adjusted_path.to_string_lossy().as_ref()));
        assert!(command_log.ends_with("exiftool-metadata\n"));
        assert_eq!(
            fs::read(&output_path).expect("output should be readable"),
            adjusted_bytes
        );
    }

    #[cfg(unix)]
    #[test]
    fn raw_staging_command_invokes_optimizer_owned_child_with_proof() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let fake_optimizer = tempdir.path().join("icloudpd-optimizer");
        fs::write(&fake_optimizer, b"").expect("fake optimizer path should be written");
        let _optimizer_guard = RawStageCopyCommandGuard::install(&fake_optimizer);
        let raw_path = tempdir.path().join("IMG_0001.dng");
        let staged_path = tempdir.path().join("IMG_0001.staged-raw.dng");
        let expected_sha256 = format!("{:x}", Sha256::digest(b"raw-bytes"));
        let nas_proof = NasRawProof {
            canonical_path: raw_path.clone(),
            relative_path: PathBuf::from("IMG_0001.dng"),
            size_bytes: 9,
            modified_unix_seconds: 1_700_000_000,
            age_seconds: 40 * 24 * 60 * 60,
            sha256: expected_sha256.clone(),
        };

        let RawStageCopyCommand { program, command } =
            raw_stage_copy_command(&raw_path, &staged_path, &nas_proof)
                .expect("staging command should be constructed");

        assert_eq!(program, fake_optimizer.display().to_string());
        assert_eq!(command.get_program(), fake_optimizer.as_os_str());
        assert_eq!(
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            vec![
                "__stage-raw-copy".to_string(),
                raw_path.to_string_lossy().into_owned(),
                staged_path.to_string_lossy().into_owned(),
                "9".to_string(),
                expected_sha256,
            ]
        );
    }

    #[test]
    fn raw_stage_child_copies_with_create_new_semantics_and_verifies_hash() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        let staged_path = tempdir.path().join("IMG_0001.staged-raw.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let expected_sha256 = format!("{:x}", Sha256::digest(b"raw-bytes"));

        run_raw_stage_copy_child(&raw_path, &staged_path, 9, &expected_sha256)
            .expect("child copy should succeed");

        assert_eq!(
            fs::read(&staged_path).expect("staged RAW should be readable"),
            b"raw-bytes"
        );
        let error = run_raw_stage_copy_child(&raw_path, &staged_path, 9, &expected_sha256)
            .expect_err("child copy must refuse a preexisting destination");
        assert!(matches!(
            error,
            ConversionExecutionError::StagedRawAlreadyExists { path } if path == staged_path
        ));
        assert_eq!(
            fs::read(&staged_path).expect("existing staged RAW should remain readable"),
            b"raw-bytes"
        );
    }

    #[test]
    fn raw_stage_child_hash_mismatch_removes_partial_destination() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        let staged_path = tempdir.path().join("IMG_0001.staged-raw.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let wrong_sha256 = format!("{:x}", Sha256::digest(b"other-raw"));

        let error = run_raw_stage_copy_child(&raw_path, &staged_path, 9, &wrong_sha256)
            .expect_err("child copy must fail on hash mismatch");

        assert!(matches!(
            error,
            ConversionExecutionError::StagedRawSha256Mismatch { path, .. } if path == staged_path
        ));
        assert!(
            !staged_path.exists(),
            "child copy must remove partial output on verification failure"
        );
    }

    #[test]
    fn raw_stage_hash_buffer_is_large_and_heap_allocated() {
        let buffer = raw_stage_hash_buffer();

        assert_eq!(buffer.len(), RAW_STAGE_HASH_BUFFER_BYTES);
        assert!(
            buffer.len() >= 1024 * 1024,
            "RAW staging uses large sequential reads to reduce NAS and local disk syscall overhead"
        );
    }

    #[cfg(unix)]
    #[test]
    fn raw_staging_commands_are_bounded_but_parallel_within_optimizer_process() {
        let active = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let worker_count = RAW_STAGE_COPY_CONCURRENCY * 2;
        let barrier = Arc::new(Barrier::new(worker_count));
        let handles = (0..worker_count)
            .map(|_| {
                let active = Arc::clone(&active);
                let max_seen = Arc::clone(&max_seen);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    with_raw_stage_copy_slot(|| {
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        max_seen.fetch_max(current, Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(25));
                        active.fetch_sub(1, Ordering::SeqCst);
                    });
                })
            })
            .collect::<Vec<_>>();

        for handle in handles {
            handle.join().expect("worker should not panic");
        }

        let max_seen = max_seen.load(Ordering::SeqCst);
        assert!(
            max_seen > 1,
            "staging should use more than one copy slot when workers are available"
        );
        assert!(
            max_seen <= RAW_STAGE_COPY_CONCURRENCY,
            "staging must remain bounded to avoid flooding the NAS"
        );
    }

    #[cfg(unix)]
    #[test]
    fn linux_conversion_uses_staged_raw_for_probe_and_conversion_commands() {
        let tool_dir = fake_linux_conversion_tools_rejecting_forbidden_raw(DEFAULT_HEIF_ENC_SCRIPT);
        let _path_guard = PathGuard::install(tool_dir.path());
        let copy_script = fake_stage_raw_copy_script(
            r#"#!/bin/sh
set -C
if [ "$1" != "__stage-raw-copy" ]; then
  exit 64
fi
printf '%s\n%s\n' "$2" "$3" > "$STAGE_COPY_LOG"
/bin/cat "$2" > "$3"
"#,
        );
        let _copy_guard = RawStageCopyCommandGuard::install(copy_script.path());
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let nas_dir = tempdir.path().join("nas");
        let output_dir = tempdir
            .path()
            .canonicalize()
            .expect("tempdir should canonicalize")
            .join("out");
        fs::create_dir_all(&nas_dir).expect("nas dir should be created");
        fs::create_dir_all(&output_dir).expect("output dir should be created");
        let raw_path = nas_dir.join("IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let output_path = output_dir.join("IMG_0001.heic");
        let staged_path = staged_raw_path_for_output(&output_path, &raw_path);
        let log_path = tempdir.path().join("commands.log");
        let raw_path_log = tempdir.path().join("raw-paths.log");
        let stage_copy_log = tempdir.path().join("stage-copy.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let _raw_log_guard = EnvVarGuard::install("RAW_PATH_LOG", &raw_path_log);
        let _stage_log_guard = EnvVarGuard::install("STAGE_COPY_LOG", &stage_copy_log);
        let _forbidden_guard = EnvVarGuard::install("FORBIDDEN_RAW_PATH", &raw_path);
        let manifest = nas_verified_manifest(&raw_path);

        let updated = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect("conversion should use staged RAW bytes instead of the NAS RAW path");

        let logged_paths = logged_raw_paths(&raw_path_log);
        assert_eq!(logged_paths.len(), 4);
        assert_eq!(
            logged_raw_paths(&stage_copy_log),
            vec![raw_path.clone(), staged_path.clone()]
        );
        for staged_path in &logged_paths {
            assert_ne!(staged_path, &raw_path);
            assert!(staged_path.starts_with(&output_dir));
            assert!(
                !staged_path.exists(),
                "staged RAW should be removed after successful conversion"
            );
        }
        let record = updated.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::Converted);
        assert_eq!(
            fs::read_to_string(log_path).expect("command log should be readable"),
            "exiftool-preview\nexiftool-preview-orientation\nmagick-auto-orient\nheif-enc\nexiftool-metadata\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn linux_raw_staging_copy_timeout_fails_without_output_or_proofs() {
        let tool_dir = fake_linux_conversion_tools();
        let _path_guard = PathGuard::install(tool_dir.path());
        let copy_script = fake_stage_raw_copy_script(
            r#"#!/bin/sh
set -C
if [ "$1" != "__stage-raw-copy" ]; then
  exit 64
fi
printf 'started\n' > "$STAGE_COPY_LOG"
printf 'partial-stage' > "$3"
/bin/sleep 5
"#,
        );
        let _copy_guard = RawStageCopyCommandGuard::install(copy_script.path());
        let _timeout_guard = CommandTimeoutGuard::install(Duration::from_millis(500));
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let output_dir = tempdir
            .path()
            .canonicalize()
            .expect("tempdir should canonicalize")
            .join("out");
        fs::create_dir_all(&output_dir).expect("output dir should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let output_path = output_dir.join("IMG_0001.heic");
        let staged_path = staged_raw_path_for_output(&output_path, &raw_path);
        let log_path = tempdir.path().join("commands.log");
        let stage_copy_log = tempdir.path().join("stage-copy.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let _stage_log_guard = EnvVarGuard::install("STAGE_COPY_LOG", &stage_copy_log);
        let manifest = nas_verified_manifest(&raw_path);

        let error = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect_err("hung staging copy child must time out");

        assert!(matches!(
            error,
            ConversionExecutionError::CommandTimedOut {
                stage: "raw_staging",
                program,
                ..
            } if program == copy_script.path().display().to_string()
        ));
        assert_eq!(
            fs::read_to_string(stage_copy_log).expect("stage copy log should be readable"),
            "started\n"
        );
        assert!(!staged_path.exists());
        assert!(!output_path.exists());
        assert!(
            !log_path.exists(),
            "conversion tools must not run after staging timeout"
        );
        let record = manifest.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::NasVerified);
        assert!(!record.proofs.contains_key("conversion"));
        assert!(!record.proofs.contains_key("conversion_performance"));
    }

    #[cfg(unix)]
    #[test]
    fn linux_raw_staging_hash_mismatch_fails_without_output_or_proofs() {
        let tool_dir = fake_linux_conversion_tools();
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let output_dir = tempdir.path().join("out");
        fs::create_dir_all(&output_dir).expect("output dir should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let output_path = output_dir.join("IMG_0001.heic");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let manifest = nas_verified_manifest(&raw_path);
        fs::write(&raw_path, b"raw-Bytes").expect("raw should be mutated after proof");

        let error = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect_err("staging should fail when copied bytes do not match the NAS proof");

        assert!(error.to_string().contains("sha256"));
        assert!(!output_path.exists());
        assert!(
            !log_path.exists(),
            "child tools must not run after staging failure"
        );
        assert!(
            fs::read_dir(&output_dir)
                .expect("output dir should remain readable")
                .next()
                .is_none(),
            "failed staging must not leave a staged RAW behind"
        );
        let record = manifest.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::NasVerified);
        assert!(!record.proofs.contains_key("conversion"));
        assert!(!record.proofs.contains_key("conversion_performance"));
    }

    #[cfg(unix)]
    #[test]
    fn linux_staged_raw_is_removed_after_conversion_failure() {
        let tool_dir = fake_linux_conversion_tools_rejecting_forbidden_raw(
            r#"#!/bin/sh
printf 'heif-enc\n' >> "$EXECUTION_LOG"
out=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "-o" ]; then
    out="$arg"
  fi
  previous="$arg"
done
if [ -n "$out" ]; then
  printf 'partial-heic' > "$out"
fi
exit 44
"#,
        );
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let nas_dir = tempdir.path().join("nas");
        let output_dir = tempdir.path().join("out");
        fs::create_dir_all(&nas_dir).expect("nas dir should be created");
        fs::create_dir_all(&output_dir).expect("output dir should be created");
        let raw_path = nas_dir.join("IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let output_path = output_dir.join("IMG_0001.heic");
        let log_path = tempdir.path().join("commands.log");
        let raw_path_log = tempdir.path().join("raw-paths.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let _raw_log_guard = EnvVarGuard::install("RAW_PATH_LOG", &raw_path_log);
        let _forbidden_guard = EnvVarGuard::install("FORBIDDEN_RAW_PATH", &raw_path);
        let manifest = nas_verified_manifest(&raw_path);

        let error = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect_err("conversion failure after staging should fail closed");

        assert!(matches!(
            error,
            ConversionExecutionError::CommandFailed {
                stage: "conversion",
                program,
                ..
            } if program == "heif-enc"
        ));
        for staged_path in logged_raw_paths(&raw_path_log) {
            assert_ne!(staged_path, raw_path);
            assert!(
                !staged_path.exists(),
                "staged RAW should be removed after conversion failure"
            );
        }
        assert!(!output_path.exists());
        assert!(!embedded_preview_path(&output_path).exists());
        assert!(!oriented_preview_path(&output_path).exists());
        let record = manifest.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::NasVerified);
        assert!(!record.proofs.contains_key("conversion"));
        assert!(!record.proofs.contains_key("conversion_performance"));
    }

    #[cfg(unix)]
    #[test]
    fn linux_refuses_preexisting_raw_stage_without_mutating_it_or_recording_proofs() {
        let tool_dir = fake_linux_conversion_tools();
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let output_dir = tempdir.path().join("out");
        fs::create_dir_all(&output_dir).expect("output dir should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let output_path = output_dir.join("IMG_0001.heic");
        let staged_path = staged_raw_path_for_output(&output_path, &raw_path);
        fs::write(&staged_path, b"existing-stage").expect("stage collision should be written");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let manifest = nas_verified_manifest(&raw_path);

        let error = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect_err("preexisting staged RAW should fail closed");

        assert!(matches!(
            error,
            ConversionExecutionError::StagedRawAlreadyExists { path } if path == staged_path
        ));
        assert_eq!(
            fs::read(&staged_path).expect("existing stage should remain readable"),
            b"existing-stage"
        );
        assert!(!output_path.exists());
        assert!(
            !log_path.exists(),
            "child tools must not run after staging collision"
        );
        let record = manifest.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::NasVerified);
        assert!(!record.proofs.contains_key("conversion"));
        assert!(!record.proofs.contains_key("conversion_performance"));
    }

    #[cfg(unix)]
    #[test]
    fn linux_conversion_uses_jpg_from_raw_when_preview_image_is_absent() {
        let tool_dir = fake_linux_conversion_tools_with_preview_and_heif_enc(
            r#"printf 'exiftool-jpg-from-raw\n' >> "$EXECUTION_LOG"
printf 'embedded-preview-jpeg'
exit 0
"#,
            DEFAULT_HEIF_ENC_SCRIPT,
        );
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let output_path = tempdir.path().join("IMG_0001.heic");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let _preview_arg_guard = EnvVarGuard::install("FAKE_PREVIEW_ARG", Path::new("-JpgFromRaw"));
        let manifest = nas_verified_manifest(&raw_path);

        let updated = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: Some("linux-tools-1".to_string()),
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect("JpgFromRaw preview should be a valid embedded conversion source");

        assert_eq!(
            fs::read_to_string(log_path).expect("command log should be readable"),
            "exiftool-jpg-from-raw\nexiftool-preview-orientation\nmagick-auto-orient\nheif-enc\nexiftool-metadata\n"
        );
        let record = updated.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::Converted);
        assert_eq!(
            record.proofs["conversion_performance"]["conversion_tool"],
            "exiftool+exiftool+magick+heif-enc"
        );
    }

    #[cfg(unix)]
    #[test]
    fn linux_batch_conversion_records_all_assets_after_parallel_success() {
        let tool_dir = fake_linux_conversion_tools();
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_1 = tempdir.path().join("IMG_0001.dng");
        let raw_2 = tempdir.path().join("IMG_0002.dng");
        fs::write(&raw_1, b"raw-1").expect("raw 1 should be written");
        fs::write(&raw_2, b"raw-2").expect("raw 2 should be written");
        let output_1 = tempdir.path().join("asset-1.heic");
        let output_2 = tempdir.path().join("asset-2.heic");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let manifest =
            nas_verified_manifest_with_assets(&[("asset-1", &raw_1), ("asset-2", &raw_2)]);

        let updated = execute_measured_conversions_for_target(
            &manifest,
            vec![
                ConversionExecutionRequest {
                    asset_id: "asset-1".to_string(),
                    output_path: output_1.clone(),
                    heic_quality: 91,
                    conversion_tool_version: Some("linux-tools-batch".to_string()),
                },
                ConversionExecutionRequest {
                    asset_id: "asset-2".to_string(),
                    output_path: output_2.clone(),
                    heic_quality: 91,
                    conversion_tool_version: Some("linux-tools-batch".to_string()),
                },
            ],
            2,
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect("batch conversion should complete");

        for (asset_id, output_path) in [("asset-1", output_1), ("asset-2", output_2)] {
            let heic = fs::read(&output_path).expect("heic output should be readable");
            let record = updated.get(asset_id).expect("asset should exist");
            assert_eq!(record.state, State::Converted);
            assert_eq!(
                record.proofs["conversion"]["heic_sha256"],
                format!("{:x}", Sha256::digest(&heic))
            );
            assert_eq!(
                record.proofs["conversion_performance"]["conversion_tool"],
                "exiftool+exiftool+magick+heif-enc"
            );
            assert_eq!(
                record.proofs["conversion_performance"]["conversion_tool_version"],
                "linux-tools-batch"
            );
        }
        assert_eq!(
            manifest.get("asset-1").expect("asset should exist").state,
            State::NasVerified
        );
        assert_eq!(
            manifest.get("asset-2").expect("asset should exist").state,
            State::NasVerified
        );
    }

    #[cfg(unix)]
    #[test]
    fn linux_batch_conversion_failure_returns_error_without_advancing_manifest() {
        let tool_dir = fake_linux_conversion_tools();
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_1 = tempdir.path().join("IMG_0001.dng");
        let raw_2 = tempdir.path().join("IMG_0002.dng");
        fs::write(&raw_1, b"raw-1").expect("raw 1 should be written");
        fs::write(&raw_2, b"raw-2").expect("raw 2 should be written");
        let output_1 = tempdir.path().join("asset-1.heic");
        let output_2 = tempdir.path().join("asset-2.heic");
        fs::write(&output_2, b"existing-output").expect("preexisting output should be written");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let manifest =
            nas_verified_manifest_with_assets(&[("asset-1", &raw_1), ("asset-2", &raw_2)]);

        let error = execute_measured_conversions_for_target(
            &manifest,
            vec![
                ConversionExecutionRequest {
                    asset_id: "asset-1".to_string(),
                    output_path: output_1.clone(),
                    heic_quality: 91,
                    conversion_tool_version: None,
                },
                ConversionExecutionRequest {
                    asset_id: "asset-2".to_string(),
                    output_path: output_2.clone(),
                    heic_quality: 91,
                    conversion_tool_version: None,
                },
            ],
            2,
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect_err("batch conversion must fail closed when any asset fails");

        assert!(matches!(
            error,
            ConversionExecutionError::BatchConversionFailed { asset_id, source }
                if asset_id == "asset-2"
                    && matches!(source.as_ref(), ConversionExecutionError::OutputAlreadyExists { path } if *path == output_2)
        ));
        assert_eq!(
            manifest.get("asset-1").expect("asset should exist").state,
            State::NasVerified
        );
        assert_eq!(
            manifest.get("asset-2").expect("asset should exist").state,
            State::NasVerified
        );
        assert!(
            !output_1.exists(),
            "successful worker output from a failed batch chunk must be removed"
        );
        assert_eq!(
            fs::read(&output_2).expect("preexisting output should remain readable"),
            b"existing-output"
        );
    }

    #[cfg(unix)]
    #[test]
    fn linux_batch_timeout_removes_successful_peer_outputs_and_intermediates() {
        let tool_dir = fake_linux_conversion_tools_with_preview_and_heif_enc(
            DEFAULT_PREVIEW_EXTRACTION_SCRIPT,
            r#"#!/bin/sh
printf 'heif-enc\n' >> "$EXECUTION_LOG"
out=""
input=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "-o" ]; then
    out="$arg"
  fi
  if [ "$arg" != "-q" ] && [ "$arg" != "-o" ] && [ "$previous" != "-q" ] && [ "$previous" != "-o" ]; then
    input="$arg"
  fi
  previous="$arg"
done
if [ -z "$out" ] || [ -z "$input" ]; then
  exit 43
fi
case "$out" in
  *asset-2*)
    printf 'partial-heic' > "$out"
    /bin/sleep 5
    ;;
esac
printf 'heic' > "$out"
"#,
        );
        let _path_guard = PathGuard::install(tool_dir.path());
        let _timeout_guard = CommandTimeoutGuard::install(Duration::from_millis(500));
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_1 = tempdir.path().join("IMG_0001.dng");
        let raw_2 = tempdir.path().join("IMG_0002.dng");
        fs::write(&raw_1, b"raw-1").expect("raw 1 should be written");
        fs::write(&raw_2, b"raw-2").expect("raw 2 should be written");
        let output_1 = tempdir.path().join("asset-1.heic");
        let output_2 = tempdir.path().join("asset-2.heic");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let manifest =
            nas_verified_manifest_with_assets(&[("asset-1", &raw_1), ("asset-2", &raw_2)]);

        let error = execute_measured_conversions_for_target(
            &manifest,
            vec![
                ConversionExecutionRequest {
                    asset_id: "asset-1".to_string(),
                    output_path: output_1.clone(),
                    heic_quality: 91,
                    conversion_tool_version: None,
                },
                ConversionExecutionRequest {
                    asset_id: "asset-2".to_string(),
                    output_path: output_2.clone(),
                    heic_quality: 91,
                    conversion_tool_version: None,
                },
            ],
            2,
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect_err("batch conversion must fail closed when a peer times out");

        assert!(matches!(
            error,
            ConversionExecutionError::BatchConversionFailed { asset_id, source }
                if asset_id == "asset-2"
                    && matches!(
                        source.as_ref(),
                        ConversionExecutionError::CommandTimedOut {
                            stage: "conversion",
                            program,
                            ..
                        } if program == "heif-enc"
                    )
        ));
        for asset_id in ["asset-1", "asset-2"] {
            assert_eq!(
                manifest.get(asset_id).expect("asset should exist").state,
                State::NasVerified
            );
        }
        for output_path in [&output_1, &output_2] {
            assert!(!output_path.exists());
            assert!(!embedded_preview_path(output_path).exists());
            assert!(!oriented_preview_path(output_path).exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn linux_batch_timeout_removes_outputs_from_completed_previous_chunks() {
        let tool_dir = fake_linux_conversion_tools_with_preview_and_heif_enc(
            DEFAULT_PREVIEW_EXTRACTION_SCRIPT,
            r#"#!/bin/sh
printf 'heif-enc\n' >> "$EXECUTION_LOG"
out=""
input=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "-o" ]; then
    out="$arg"
  fi
  if [ "$arg" != "-q" ] && [ "$arg" != "-o" ] && [ "$previous" != "-q" ] && [ "$previous" != "-o" ]; then
    input="$arg"
  fi
  previous="$arg"
done
if [ -z "$out" ] || [ -z "$input" ]; then
  exit 43
fi
case "$out" in
  *asset-2*)
    printf 'partial-heic' > "$out"
    /bin/sleep 5
    ;;
esac
printf 'heic' > "$out"
"#,
        );
        let _path_guard = PathGuard::install(tool_dir.path());
        let _timeout_guard = CommandTimeoutGuard::install(Duration::from_millis(500));
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_1 = tempdir.path().join("IMG_0001.dng");
        let raw_2 = tempdir.path().join("IMG_0002.dng");
        fs::write(&raw_1, b"raw-1").expect("raw 1 should be written");
        fs::write(&raw_2, b"raw-2").expect("raw 2 should be written");
        let output_1 = tempdir.path().join("asset-1.heic");
        let output_2 = tempdir.path().join("asset-2.heic");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let manifest =
            nas_verified_manifest_with_assets(&[("asset-1", &raw_1), ("asset-2", &raw_2)]);

        let error = execute_measured_conversions_for_target(
            &manifest,
            vec![
                ConversionExecutionRequest {
                    asset_id: "asset-1".to_string(),
                    output_path: output_1.clone(),
                    heic_quality: 91,
                    conversion_tool_version: None,
                },
                ConversionExecutionRequest {
                    asset_id: "asset-2".to_string(),
                    output_path: output_2.clone(),
                    heic_quality: 91,
                    conversion_tool_version: None,
                },
            ],
            1,
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect_err("later chunk timeout must fail the whole batch");

        assert!(matches!(
            error,
            ConversionExecutionError::BatchConversionFailed { asset_id, source }
                if asset_id == "asset-2"
                    && matches!(
                        source.as_ref(),
                        ConversionExecutionError::CommandTimedOut {
                            stage: "conversion",
                            program,
                            ..
                        } if program == "heif-enc"
                    )
        ));
        for asset_id in ["asset-1", "asset-2"] {
            assert_eq!(
                manifest.get(asset_id).expect("asset should exist").state,
                State::NasVerified
            );
        }
        for output_path in [&output_1, &output_2] {
            assert!(!output_path.exists());
            assert!(!embedded_preview_path(output_path).exists());
            assert!(!oriented_preview_path(output_path).exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn linux_conversion_chain_failure_removes_partial_output_and_does_not_record_proofs() {
        let tool_dir = fake_linux_conversion_tools_with_preview_and_heif_enc(
            DEFAULT_PREVIEW_EXTRACTION_SCRIPT,
            r#"#!/bin/sh
printf 'heif-enc\n' >> "$EXECUTION_LOG"
out=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "-o" ]; then
    out="$arg"
  fi
  previous="$arg"
done
if [ -n "$out" ]; then
  printf 'partial-heic' > "$out"
fi
exit 44
"#,
        );
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let output_path = tempdir.path().join("IMG_0001.heic");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let manifest = nas_verified_manifest(&raw_path);

        let error = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect_err("failing heif-enc should fail conversion");

        assert!(matches!(
            error,
            ConversionExecutionError::CommandFailed {
                stage: "conversion",
                program,
                ..
            } if program == "heif-enc"
        ));
        assert!(!output_path.exists());
        assert!(!embedded_preview_path(&output_path).exists());
        assert!(!oriented_preview_path(&output_path).exists());
        let record = manifest.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::NasVerified);
        assert!(!record.proofs.contains_key("conversion"));
        assert!(!record.proofs.contains_key("conversion_performance"));
        assert_eq!(
            fs::read_to_string(log_path).expect("command log should be readable"),
            "exiftool-preview\nexiftool-preview-orientation\nmagick-auto-orient\nheif-enc\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn linux_preview_extraction_failure_does_not_encode_or_record_proofs() {
        let tool_dir = fake_linux_conversion_tools_with_preview_and_heif_enc(
            r#"printf 'exiftool-preview\n' >> "$EXECUTION_LOG"
exit 41
"#,
            DEFAULT_HEIF_ENC_SCRIPT,
        );
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let output_path = tempdir.path().join("IMG_0001.heic");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let manifest = nas_verified_manifest(&raw_path);

        let error = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect_err("failing preview extraction should fail conversion");

        assert!(matches!(
            error,
            ConversionExecutionError::CommandFailed {
                stage: "conversion",
                program,
                ..
            } if program == "exiftool"
        ));
        assert!(!output_path.exists());
        assert!(!embedded_preview_path(&output_path).exists());
        assert!(!oriented_preview_path(&output_path).exists());
        let record = manifest.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::NasVerified);
        assert!(!record.proofs.contains_key("conversion"));
        assert!(!record.proofs.contains_key("conversion_performance"));
        assert_eq!(
            fs::read_to_string(log_path).expect("command log should be readable"),
            "exiftool-preview\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn linux_preview_orientation_copy_failure_does_not_encode_or_record_proofs() {
        let tool_dir = fake_linux_conversion_tools();
        let _path_guard = PathGuard::install(tool_dir.path());
        let _failure_guard =
            EnvVarGuard::install_value("FAIL_PREVIEW_ORIENTATION", OsString::from("1"));
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let output_path = tempdir.path().join("IMG_0001.heic");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let manifest = nas_verified_manifest(&raw_path);

        let error = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect_err("failing preview orientation copy should fail conversion");

        assert!(matches!(
            error,
            ConversionExecutionError::CommandFailed {
                stage: "conversion",
                program,
                ..
            } if program == "exiftool"
        ));
        assert!(!output_path.exists());
        let record = manifest.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::NasVerified);
        assert!(!record.proofs.contains_key("conversion"));
        assert!(!record.proofs.contains_key("conversion_performance"));
        assert_eq!(
            fs::read_to_string(log_path).expect("command log should be readable"),
            "exiftool-preview\nexiftool-preview-orientation\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn linux_preview_probe_timeout_fails_closed_without_recording_proofs() {
        let tool_dir = fake_linux_conversion_tools_with_probe_preview_and_heif_enc(
            "/bin/sleep 5\n",
            DEFAULT_PREVIEW_EXTRACTION_SCRIPT,
            DEFAULT_HEIF_ENC_SCRIPT,
        );
        let _path_guard = PathGuard::install(tool_dir.path());
        let _timeout_guard = CommandTimeoutGuard::install(Duration::from_millis(500));
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let output_path = tempdir.path().join("IMG_0001.heic");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let manifest = nas_verified_manifest(&raw_path);
        let started = Instant::now();
        let error = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect_err("hung preview probe should time out");

        assert!(
            started.elapsed() < Duration::from_secs(2),
            "timeout should return promptly"
        );
        assert!(
            matches!(
                error,
                ConversionExecutionError::CommandTimedOut {
                    stage: "preview_probe",
                    ref program,
                    ..
                } if program == "exiftool"
            ),
            "unexpected error: {error:?}"
        );
        assert!(!output_path.exists());
        assert!(!embedded_preview_path(&output_path).exists());
        assert!(!oriented_preview_path(&output_path).exists());
        let record = manifest.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::NasVerified);
        assert!(!record.proofs.contains_key("conversion"));
        assert!(!record.proofs.contains_key("conversion_performance"));
    }

    #[cfg(unix)]
    #[test]
    fn linux_planned_command_timeout_removes_outputs_and_does_not_record_proofs() {
        let tool_dir = fake_linux_conversion_tools_with_preview_and_heif_enc(
            DEFAULT_PREVIEW_EXTRACTION_SCRIPT,
            r#"#!/bin/sh
printf 'heif-enc\n' >> "$EXECUTION_LOG"
out=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "-o" ]; then
    out="$arg"
  fi
  previous="$arg"
done
if [ -n "$out" ]; then
  printf 'partial-heic' > "$out"
fi
/bin/sleep 5
"#,
        );
        let _path_guard = PathGuard::install(tool_dir.path());
        let _timeout_guard = CommandTimeoutGuard::install(Duration::from_secs(2));
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let output_path = tempdir.path().join("IMG_0001.heic");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let manifest = nas_verified_manifest(&raw_path);

        let error = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect_err("hung heif-enc should time out");

        assert!(
            matches!(
                error,
                ConversionExecutionError::CommandTimedOut {
                    stage: "conversion",
                    ref program,
                    ..
                } if program == "heif-enc"
            ),
            "unexpected error: {error:?}"
        );
        assert!(!output_path.exists());
        assert!(!embedded_preview_path(&output_path).exists());
        assert!(!oriented_preview_path(&output_path).exists());
        let record = manifest.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::NasVerified);
        assert!(!record.proofs.contains_key("conversion"));
        assert!(!record.proofs.contains_key("conversion_performance"));
        let command_log = fs::read_to_string(log_path).expect("command log should be readable");
        assert!(matches!(
            command_log.as_str(),
            "exiftool-preview\nexiftool-preview-orientation\nmagick-auto-orient\n"
                | "exiftool-preview\nexiftool-preview-orientation\nmagick-auto-orient\nheif-enc\n"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn linux_empty_preview_extraction_does_not_encode_or_record_proofs() {
        let tool_dir = fake_linux_conversion_tools_with_preview_and_heif_enc(
            r#"printf 'exiftool-preview\n' >> "$EXECUTION_LOG"
exit 0
"#,
            DEFAULT_HEIF_ENC_SCRIPT,
        );
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let output_path = tempdir.path().join("IMG_0001.heic");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let manifest = nas_verified_manifest(&raw_path);

        let error = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect_err("empty preview extraction should fail conversion");

        assert!(
            matches!(error, ConversionExecutionError::OutputEmpty { path } if path.ends_with("IMG_0001.embedded-preview.jpg"))
        );
        assert!(!output_path.exists());
        let record = manifest.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::NasVerified);
        assert!(!record.proofs.contains_key("conversion"));
        assert!(!record.proofs.contains_key("conversion_performance"));
        assert_eq!(
            fs::read_to_string(log_path).expect("command log should be readable"),
            "exiftool-preview\n"
        );
    }

    #[test]
    fn required_intermediate_output_rejects_missing_file() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let missing_path = tempdir.path().join("missing-preview.jpg");

        let error = inspect_required_intermediate_output(&missing_path)
            .expect_err("missing intermediate output should fail closed");

        assert!(matches!(
            error,
            ConversionExecutionError::OutputUnreadable { path, .. } if path == missing_path
        ));
    }

    #[cfg(unix)]
    #[test]
    fn linux_refuses_preexisting_preview_intermediate_without_mutating_it_or_recording_proofs() {
        let tool_dir = fake_linux_conversion_tools();
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let output_path = tempdir.path().join("IMG_0001.heic");
        let preview_path = embedded_preview_path(&output_path);
        fs::write(&preview_path, b"existing-preview").expect("preview should be written");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let manifest = nas_verified_manifest(&raw_path);

        let error = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect_err("preexisting preview intermediate should fail closed");

        assert!(matches!(
            error,
            ConversionExecutionError::OutputAlreadyExists { path } if path == preview_path
        ));
        assert_eq!(
            fs::read(&preview_path).expect("preview should remain readable"),
            b"existing-preview"
        );
        assert!(!output_path.exists());
        assert!(!log_path.exists());
        let record = manifest.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::NasVerified);
        assert!(!record.proofs.contains_key("conversion"));
        assert!(!record.proofs.contains_key("conversion_performance"));
    }

    #[cfg(unix)]
    #[test]
    fn linux_refuses_symlink_preview_intermediate_without_mutating_target_or_recording_proofs() {
        let tool_dir = fake_linux_conversion_tools();
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let output_path = tempdir.path().join("IMG_0001.heic");
        let preview_path = embedded_preview_path(&output_path);
        let symlink_target = tempdir.path().join("protected-preview-target.jpg");
        fs::write(&symlink_target, b"protected-preview").expect("symlink target should be written");
        std::os::unix::fs::symlink(&symlink_target, &preview_path)
            .expect("preview symlink should be created");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let manifest = nas_verified_manifest(&raw_path);

        let error = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect_err("symlink preview intermediate should fail closed");

        assert!(matches!(
            error,
            ConversionExecutionError::OutputAlreadyExists { path } if path == preview_path
        ));
        assert_eq!(
            fs::read(&symlink_target).expect("symlink target should remain readable"),
            b"protected-preview"
        );
        assert!(
            fs::symlink_metadata(&preview_path)
                .expect("preview symlink should remain")
                .file_type()
                .is_symlink()
        );
        assert!(!output_path.exists());
        assert!(!log_path.exists());
        let record = manifest.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::NasVerified);
        assert!(!record.proofs.contains_key("conversion"));
        assert!(!record.proofs.contains_key("conversion_performance"));
    }

    #[cfg(unix)]
    #[test]
    fn linux_refuses_preexisting_oriented_preview_without_mutating_it_or_recording_proofs() {
        let tool_dir = fake_linux_conversion_tools();
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let output_path = tempdir.path().join("IMG_0001.heic");
        let oriented_path = oriented_preview_path(&output_path);
        fs::write(&oriented_path, b"existing-oriented-preview")
            .expect("oriented preview should be written");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let manifest = nas_verified_manifest(&raw_path);

        let error = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect_err("preexisting oriented preview should fail closed");

        assert!(matches!(
            error,
            ConversionExecutionError::OutputAlreadyExists { path } if path == oriented_path
        ));
        assert_eq!(
            fs::read(&oriented_path).expect("oriented preview should remain readable"),
            b"existing-oriented-preview"
        );
        assert!(!output_path.exists());
        assert_eq!(
            fs::read_to_string(log_path).expect("command log should be readable"),
            "exiftool-preview\nexiftool-preview-orientation\n"
        );
        let record = manifest.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::NasVerified);
        assert!(!record.proofs.contains_key("conversion"));
        assert!(!record.proofs.contains_key("conversion_performance"));
    }

    #[cfg(unix)]
    #[test]
    fn linux_refuses_symlink_oriented_preview_without_mutating_target_or_recording_proofs() {
        let tool_dir = fake_linux_conversion_tools();
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let raw_path = tempdir.path().join("IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
        let output_path = tempdir.path().join("IMG_0001.heic");
        let oriented_path = oriented_preview_path(&output_path);
        let symlink_target = tempdir.path().join("protected-oriented-preview-target.jpg");
        fs::write(&symlink_target, b"protected-oriented-preview")
            .expect("symlink target should be written");
        std::os::unix::fs::symlink(&symlink_target, &oriented_path)
            .expect("oriented preview symlink should be created");
        let log_path = tempdir.path().join("commands.log");
        let _log_guard = EnvVarGuard::install("EXECUTION_LOG", &log_path);
        let manifest = nas_verified_manifest(&raw_path);

        let error = execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect_err("symlink oriented preview should fail closed");

        assert!(matches!(
            error,
            ConversionExecutionError::OutputAlreadyExists { path } if path == oriented_path
        ));
        assert_eq!(
            fs::read(&symlink_target).expect("symlink target should remain readable"),
            b"protected-oriented-preview"
        );
        assert!(
            fs::symlink_metadata(&oriented_path)
                .expect("oriented preview symlink should remain")
                .file_type()
                .is_symlink()
        );
        assert!(!output_path.exists());
        assert_eq!(
            fs::read_to_string(log_path).expect("command log should be readable"),
            "exiftool-preview\nexiftool-preview-orientation\n"
        );
        let record = manifest.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::NasVerified);
        assert!(!record.proofs.contains_key("conversion"));
        assert!(!record.proofs.contains_key("conversion_performance"));
    }

    #[cfg(unix)]
    fn fake_linux_conversion_tools() -> tempfile::TempDir {
        fake_linux_conversion_tools_with_preview_and_heif_enc(
            DEFAULT_PREVIEW_EXTRACTION_SCRIPT,
            DEFAULT_HEIF_ENC_SCRIPT,
        )
    }

    #[cfg(unix)]
    const DEFAULT_PREVIEW_EXTRACTION_SCRIPT: &str = r#"printf 'exiftool-preview\n' >> "$EXECUTION_LOG"
printf 'embedded-preview-jpeg'
exit 0
"#;

    #[cfg(unix)]
    const DEFAULT_HEIF_ENC_SCRIPT: &str = r#"#!/bin/sh
printf 'heif-enc\n' >> "$EXECUTION_LOG"
out=""
input=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "-o" ]; then
    out="$arg"
  fi
  if [ "$arg" != "-q" ] && [ "$arg" != "-o" ] && [ "$previous" != "-q" ] && [ "$previous" != "-o" ]; then
    input="$arg"
  fi
  previous="$arg"
done
if [ -z "$out" ] || [ -z "$input" ]; then
  exit 43
fi
preview_bytes=""
read -r preview_bytes < "$input"
if [ "$preview_bytes" != "oriented-preview-jpeg" ]; then
  exit 46
fi
printf 'heic' > "$out"
"#;

    fn embedded_preview_path(output_path: &Path) -> PathBuf {
        let mut preview_path = output_path.to_path_buf();
        preview_path.set_extension("embedded-preview.jpg");
        preview_path
    }

    fn oriented_preview_path(output_path: &Path) -> PathBuf {
        let mut preview_path = output_path.to_path_buf();
        preview_path.set_extension("oriented-preview.jpg");
        preview_path
    }

    #[cfg(unix)]
    fn adjusted_test_jpeg() -> Vec<u8> {
        adjusted_test_jpeg_with_seed(23)
    }

    #[cfg(unix)]
    fn adjusted_test_jpeg_with_seed(seed: u8) -> Vec<u8> {
        adjusted_test_jpeg_with_dimensions(4, 3, seed)
    }

    #[cfg(unix)]
    fn adjusted_test_jpeg_with_dimensions(width: u32, height: u32, seed: u8) -> Vec<u8> {
        use image::codecs::jpeg::JpegEncoder;
        use image::{DynamicImage, Rgb, RgbImage};

        let mut image = RgbImage::new(width, height);
        for (x, y, pixel) in image.enumerate_pixels_mut() {
            *pixel = Rgb([((x * 50) % 255) as u8, ((y * 70) % 255) as u8, seed]);
        }
        let mut bytes = Vec::new();
        JpegEncoder::new_with_quality(&mut bytes, 100)
            .encode_image(&DynamicImage::ImageRgb8(image))
            .expect("test adjusted JPEG should encode");
        bytes
    }

    #[cfg(unix)]
    fn adjusted_test_proof(
        asset_id: &str,
        original: &OriginalAssetProof,
        local_path: PathBuf,
        bytes: &[u8],
    ) -> CloudKitAdjustedSourceProof {
        CloudKitAdjustedSourceProof {
            schema_version: ADJUSTED_SOURCE_PROOF_SCHEMA_VERSION.to_string(),
            source_kind: "cloudkit_adjusted_res_jpeg_full_res".to_string(),
            asset_id: asset_id.to_string(),
            asset_record_name: original.record_name.clone(),
            asset_record_change_tag: original.record_change_tag.clone(),
            asset_record_type: original.record_type.clone(),
            resource_record_name: original.record_name.clone(),
            resource_record_change_tag: original.record_change_tag.clone(),
            resource_record_type: "CPLAsset".to_string(),
            database_scope: original.database_scope,
            zone_name: original.zone_name.clone(),
            master_record_name: None,
            resource_field: "resJPEGFullRes".to_string(),
            declared_file_type: "public.jpeg".to_string(),
            declared_fingerprint: "test-fingerprint".to_string(),
            declared_size_bytes: bytes.len() as u64,
            width: 4,
            height: 3,
            local_path,
            downloaded_size_bytes: bytes.len() as u64,
            downloaded_sha256: format!("{:x}", Sha256::digest(bytes)),
            orientation: 1,
            verified_at_unix_seconds: 1_800_000_001,
        }
    }

    #[cfg(unix)]
    #[test]
    fn linux_real_heif_encoder_accepts_a_sealed_directory_descriptor_jpeg_when_available() {
        #[cfg(not(target_os = "linux"))]
        {
            eprintln!("skipping real heif-enc directory-descriptor smoke: this host is not Linux");
        }
        #[cfg(target_os = "linux")]
        linux_real_heif_encoder_accepts_a_sealed_directory_descriptor_jpeg();
    }

    #[cfg(target_os = "linux")]
    fn linux_real_heif_encoder_accepts_a_sealed_directory_descriptor_jpeg() {
        use std::os::unix::fs::symlink;

        let Some(heif_enc) = executable_on_path("heif-enc") else {
            eprintln!("skipping real heif-enc smoke: heif-enc is unavailable");
            return;
        };
        let Some(heif_info) = executable_on_path("heif-info") else {
            eprintln!("skipping real heif-enc smoke: heif-info is unavailable");
            return;
        };
        let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
        symlink(&heif_enc, tool_dir.path().join("heif-enc"))
            .expect("real heif-enc should be exposed through sanitized PATH");
        write_executable_script(
            &tool_dir.path().join("exiftool"),
            r#"#!/bin/sh
if [ "$1" = "-j" ] || [ "$1" = "-b" ]; then
  exit 66
fi
if [ "$1" = "-TagsFromFile" ]; then
  exit 0
fi
exit 67
"#,
        );
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("test tempdir should be created");
        let output_dir = tempdir
            .path()
            .canonicalize()
            .expect("tempdir should canonicalize")
            .join("out");
        fs::create_dir(&output_dir).expect("output directory should be created");
        let raw_path = tempdir.path().join("IMG_REAL_HEIF.dng");
        let raw_bytes = vec![b'r'; 4_096];
        fs::write(&raw_path, &raw_bytes).expect("raw should be written");
        let output_path = output_dir.join("IMG_REAL_HEIF.heic");
        let adjusted_path = adjusted_source_path_for_output(&output_path);
        let adjusted_bytes = adjusted_test_jpeg_with_dimensions(64, 64, 31);
        fs::write(&adjusted_path, &adjusted_bytes).expect("adjusted JPEG should be written");
        let mut manifest = nas_verified_manifest(&raw_path);
        let original = OriginalAssetProof {
            record_name: "original-real-heif".to_string(),
            record_change_tag: "original-real-heif-tag".to_string(),
            record_type: "CPLAsset".to_string(),
            database_scope: Default::default(),
            zone_name: "PrimarySync".to_string(),
            filename: "IMG_REAL_HEIF.dng".to_string(),
            size_bytes: raw_bytes.len() as u64,
            matched_raw_sha256: format!("{:x}", Sha256::digest(&raw_bytes)),
        };
        record_original_asset_proof(&mut manifest, "asset-1", original.clone())
            .expect("original asset proof should record");
        let adjusted = CloudKitAdjustedSourceProof {
            width: 64,
            height: 64,
            ..adjusted_test_proof("asset-1", &original, adjusted_path.clone(), &adjusted_bytes)
        };
        record_adjusted_source_proof(&mut manifest, "asset-1", &output_path, adjusted)
            .expect("adjusted proof should record");

        execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("linux", "x86_64"),
        )
        .expect("real heif-enc should encode the sealed /dev/fd directory input");

        assert!(
            Command::new(heif_info)
                .arg(&output_path)
                .status()
                .expect("heif-info should run")
                .success(),
            "real heif-info must accept the 64x64 HEIC produced from the descriptor input"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_real_sips_accepts_a_sealed_file_descriptor_jpeg_when_available() {
        use std::os::unix::fs::symlink;

        let Some(sips) = executable_on_path("sips") else {
            eprintln!("skipping real sips descriptor smoke: sips is unavailable");
            return;
        };
        let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
        symlink(&sips, tool_dir.path().join("sips"))
            .expect("real sips should be exposed through sanitized PATH");
        write_executable_script(
            &tool_dir.path().join("exiftool"),
            r#"#!/bin/sh
if [ "$1" = "-j" ] || [ "$1" = "-b" ]; then
  exit 66
fi
if [ "$1" = "-TagsFromFile" ]; then
  exit 0
fi
exit 67
"#,
        );
        let _path_guard = PathGuard::install(tool_dir.path());
        let tempdir = tempfile::tempdir().expect("test tempdir should be created");
        let output_dir = tempdir
            .path()
            .canonicalize()
            .expect("tempdir should canonicalize")
            .join("out");
        fs::create_dir(&output_dir).expect("output directory should be created");
        let raw_path = tempdir.path().join("IMG_REAL_SIPS.dng");
        let raw_bytes = vec![b'r'; 4_096];
        fs::write(&raw_path, &raw_bytes).expect("raw should be written");
        let output_path = output_dir.join("IMG_REAL_SIPS.heic");
        let adjusted_path = adjusted_source_path_for_output(&output_path);
        let adjusted_bytes = adjusted_test_jpeg_with_dimensions(64, 64, 47);
        fs::write(&adjusted_path, &adjusted_bytes).expect("adjusted JPEG should be written");
        let mut manifest = nas_verified_manifest(&raw_path);
        let original = OriginalAssetProof {
            record_name: "original-real-sips".to_string(),
            record_change_tag: "original-real-sips-tag".to_string(),
            record_type: "CPLAsset".to_string(),
            database_scope: Default::default(),
            zone_name: "PrimarySync".to_string(),
            filename: "IMG_REAL_SIPS.dng".to_string(),
            size_bytes: raw_bytes.len() as u64,
            matched_raw_sha256: format!("{:x}", Sha256::digest(&raw_bytes)),
        };
        record_original_asset_proof(&mut manifest, "asset-1", original.clone())
            .expect("original asset proof should record");
        let adjusted = CloudKitAdjustedSourceProof {
            width: 64,
            height: 64,
            ..adjusted_test_proof("asset-1", &original, adjusted_path.clone(), &adjusted_bytes)
        };
        record_adjusted_source_proof(&mut manifest, "asset-1", &output_path, adjusted)
            .expect("adjusted proof should record");

        execute_measured_conversion_for_target(
            &manifest,
            ConversionExecutionRequest {
                asset_id: "asset-1".to_string(),
                output_path: output_path.clone(),
                heic_quality: 91,
                conversion_tool_version: None,
            },
            TargetPlatform::new("macos", "aarch64"),
        )
        .expect("real sips should encode the sealed /dev/fd file input");

        let dimensions = Command::new(sips)
            .args(["-g", "pixelWidth", "-g", "pixelHeight"])
            .arg(&output_path)
            .output()
            .expect("sips should inspect its output");
        assert!(dimensions.status.success());
        let dimensions = String::from_utf8_lossy(&dimensions.stdout);
        assert!(
            dimensions.contains("64"),
            "sips output must retain 64px dimensions"
        );
    }

    #[cfg(unix)]
    fn fake_linux_conversion_tools_with_preview_and_heif_enc(
        preview_extraction_body: &str,
        heif_enc_body: &str,
    ) -> tempfile::TempDir {
        fake_linux_conversion_tools_with_probe_preview_and_heif_enc(
            "",
            preview_extraction_body,
            heif_enc_body,
        )
    }

    #[cfg(unix)]
    fn fake_linux_conversion_tools_with_probe_preview_and_heif_enc(
        preview_probe_body: &str,
        preview_extraction_body: &str,
        heif_enc_body: &str,
    ) -> tempfile::TempDir {
        let tempdir = tempfile::tempdir().expect("tool tempdir should be created");
        write_executable_script(&tempdir.path().join("heif-enc"), heif_enc_body);
        write_executable_script(
            &tempdir.path().join("magick"),
            r#"#!/bin/sh
if [ "$2" = "-auto-orient" ]; then
  printf 'magick-auto-orient\n' >> "$EXECUTION_LOG"
  printf 'oriented-preview-jpeg'
  exit 0
fi
exit 47
"#,
        );
        let exiftool_body = format!(
            r#"#!/bin/sh
preview_arg="${{FAKE_PREVIEW_ARG:--PreviewImage}}"
if [ "$1" = "-j" ]; then
{preview_probe_body}
  if [ "$preview_arg" = "-JpgFromRaw" ]; then
    printf '[{{"JpgFromRaw":"(Binary data 20 bytes, use -b option to extract)"}}]\n'
  else
    printf '[{{"PreviewImage":"(Binary data 20 bytes, use -b option to extract)"}}]\n'
  fi
  exit 0
fi
if [ "$1" = "-b" ] && [ "$2" = "$preview_arg" ]; then
{preview_extraction_body}
fi
if [ "$1" = "-TagsFromFile" ] && [ "$3" = "-Orientation#" ]; then
  printf 'exiftool-preview-orientation\n' >> "$EXECUTION_LOG"
  if [ "${{FAIL_PREVIEW_ORIENTATION:-}}" = "1" ]; then
    exit 48
  fi
  exit 0
fi
printf 'exiftool-metadata\n' >> "$EXECUTION_LOG"
exit 0
"#
        );
        write_executable_script(&tempdir.path().join("exiftool"), &exiftool_body);
        tempdir
    }

    #[cfg(unix)]
    fn fake_linux_conversion_tools_rejecting_forbidden_raw(
        heif_enc_body: &str,
    ) -> tempfile::TempDir {
        let tempdir = tempfile::tempdir().expect("tool tempdir should be created");
        write_executable_script(&tempdir.path().join("heif-enc"), heif_enc_body);
        write_executable_script(
            &tempdir.path().join("magick"),
            r#"#!/bin/sh
if [ "$2" = "-auto-orient" ]; then
  printf 'magick-auto-orient\n' >> "$EXECUTION_LOG"
  printf 'oriented-preview-jpeg'
  exit 0
fi
exit 47
"#,
        );
        write_executable_script(
            &tempdir.path().join("exiftool"),
            r#"#!/bin/sh
log_and_check_raw() {
  raw="$1"
  if [ -n "${RAW_PATH_LOG:-}" ]; then
    printf '%s\n' "$raw" >> "$RAW_PATH_LOG"
  fi
  if [ "$raw" = "${FORBIDDEN_RAW_PATH:-}" ]; then
    exit 64
  fi
  if [ ! -f "$raw" ]; then
    exit 65
  fi
}
if [ "$1" = "-j" ]; then
  for raw_arg in "$@"; do :; done
  log_and_check_raw "$raw_arg"
  printf '[{"PreviewImage":"(Binary data 20 bytes, use -b option to extract)"}]\n'
  exit 0
fi
if [ "$1" = "-b" ] && [ "$2" = "-PreviewImage" ]; then
  log_and_check_raw "$3"
  printf 'exiftool-preview\n' >> "$EXECUTION_LOG"
  printf 'embedded-preview-jpeg'
  exit 0
fi
if [ "$1" = "-TagsFromFile" ] && [ "$3" = "-Orientation#" ]; then
  log_and_check_raw "$2"
  printf 'exiftool-preview-orientation\n' >> "$EXECUTION_LOG"
  exit 0
fi
if [ "$1" = "-TagsFromFile" ]; then
  log_and_check_raw "$2"
  printf 'exiftool-metadata\n' >> "$EXECUTION_LOG"
  exit 0
fi
exit 49
"#,
        );
        tempdir
    }

    #[cfg(unix)]
    fn write_executable_script(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, body).expect("fake tool should be written");
        let mut permissions = fs::metadata(path)
            .expect("fake tool metadata should be readable")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("fake tool should be executable");
    }

    #[cfg(unix)]
    fn executable_on_path(program: &str) -> Option<PathBuf> {
        env::var_os("PATH").and_then(|paths| {
            env::split_paths(&paths)
                .map(|directory| directory.join(program))
                .find(|candidate| is_executable_file(candidate))
        })
    }

    #[cfg(unix)]
    fn fake_stage_raw_copy_script(body: &str) -> FakeStageRawCopyScript {
        use std::os::unix::fs::PermissionsExt;

        let tempdir = tempfile::tempdir().expect("stage copy script dir should be created");
        let path = tempdir.path().join("stage-copy");
        fs::write(&path, body).expect("stage copy script should be written");
        let mut permissions = fs::metadata(&path)
            .expect("stage copy script metadata should be readable")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("stage copy script should be executable");
        FakeStageRawCopyScript {
            path,
            _tempdir: tempdir,
        }
    }

    #[cfg(unix)]
    struct FakeStageRawCopyScript {
        path: PathBuf,
        _tempdir: tempfile::TempDir,
    }

    #[cfg(unix)]
    impl FakeStageRawCopyScript {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    fn nas_verified_manifest(raw_path: &Path) -> Manifest {
        nas_verified_manifest_with_assets(&[("asset-1", raw_path)])
    }

    fn nas_verified_manifest_with_assets(assets: &[(&str, &Path)]) -> Manifest {
        let mut manifest = Manifest::new();
        for (index, (asset_id, raw_path)) in assets.iter().enumerate() {
            discover_raw_asset(&mut manifest, *asset_id, raw_path.to_path_buf())
                .expect("asset should be discovered");
            let raw = fs::read(raw_path).expect("raw should be readable");
            record_nas_proof(
                &mut manifest,
                asset_id,
                NasRawProof {
                    canonical_path: raw_path.to_path_buf(),
                    relative_path: PathBuf::from(format!("IMG_{:04}.dng", index + 1)),
                    size_bytes: u64::try_from(raw.len()).expect("raw length should fit in u64"),
                    modified_unix_seconds: 1_700_000_000,
                    age_seconds: 40 * 24 * 60 * 60,
                    sha256: format!("{:x}", Sha256::digest(&raw)),
                },
            )
            .expect("nas proof should be recorded");
        }
        manifest
    }

    #[cfg(unix)]
    fn logged_raw_paths(path: &Path) -> Vec<PathBuf> {
        fs::read_to_string(path)
            .expect("raw path log should be readable")
            .lines()
            .map(PathBuf::from)
            .collect()
    }

    #[cfg(unix)]
    struct PathGuard {
        previous: Option<OsString>,
        _lock: MutexGuard<'static, ()>,
    }

    #[cfg(unix)]
    impl PathGuard {
        fn install(path: &Path) -> Self {
            let lock = PATH_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let previous = env::var_os("PATH");
            unsafe {
                env::set_var("PATH", path);
            }
            Self {
                previous,
                _lock: lock,
            }
        }
    }

    #[cfg(unix)]
    impl Drop for PathGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.previous {
                    Some(previous) => env::set_var("PATH", previous),
                    None => env::remove_var("PATH"),
                }
            }
        }
    }

    #[cfg(unix)]
    struct CommandTimeoutGuard {
        previous: Option<Duration>,
    }

    #[cfg(unix)]
    impl CommandTimeoutGuard {
        fn install(timeout: Duration) -> Self {
            let mut configured = TEST_CHILD_COMMAND_TIMEOUT
                .lock()
                .expect("test child command timeout lock should not be poisoned");
            let previous = configured.replace(timeout);
            Self { previous }
        }
    }

    #[cfg(unix)]
    impl Drop for CommandTimeoutGuard {
        fn drop(&mut self) {
            let mut configured = TEST_CHILD_COMMAND_TIMEOUT
                .lock()
                .expect("test child command timeout lock should not be poisoned");
            *configured = self.previous;
        }
    }

    #[cfg(unix)]
    struct RawStageCopyCommandGuard {
        previous: Option<PathBuf>,
        _lock: MutexGuard<'static, ()>,
    }

    #[cfg(unix)]
    impl RawStageCopyCommandGuard {
        fn install(path: &Path) -> Self {
            let lock = RAW_STAGE_COPY_TEST_CONFIG_LOCK
                .lock()
                .expect("RAW stage copy test config lock should not be poisoned");
            let mut configured = TEST_RAW_STAGE_COPY_COMMAND
                .lock()
                .expect("test RAW stage copy command lock should not be poisoned");
            let previous = configured.replace(path.to_path_buf());
            Self {
                previous,
                _lock: lock,
            }
        }
    }

    #[cfg(unix)]
    impl Drop for RawStageCopyCommandGuard {
        fn drop(&mut self) {
            let mut configured = TEST_RAW_STAGE_COPY_COMMAND
                .lock()
                .expect("test RAW stage copy command lock should not be poisoned");
            *configured = self.previous.clone();
        }
    }

    #[cfg(unix)]
    struct EnvVarGuard {
        name: &'static str,
        previous: Option<OsString>,
    }

    #[cfg(unix)]
    impl EnvVarGuard {
        fn install(name: &'static str, value: &Path) -> Self {
            Self::install_value(name, value.as_os_str().to_os_string())
        }

        fn install_value(name: &'static str, value: OsString) -> Self {
            let previous = env::var_os(name);
            unsafe {
                env::set_var(name, value);
            }
            Self { name, previous }
        }
    }

    #[cfg(unix)]
    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.previous {
                    Some(previous) => env::set_var(self.name, previous),
                    None => env::remove_var(self.name),
                }
            }
        }
    }
}

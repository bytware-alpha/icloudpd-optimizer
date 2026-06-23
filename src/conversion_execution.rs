use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::conversion::{CommandPlan, ConversionError, plan_conversion_for_target};
use crate::conversion_backend::{TargetPlatform, backend_report_for_target};
use crate::manifest::{Manifest, ManifestError, State};
use crate::workflow::{
    ConversionPerformanceInput, ConversionResultProof, WorkflowError,
    record_conversion_performance, record_conversion_result,
};

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

    let plan = plan_conversion_for_target(
        target,
        &raw_path,
        &request.output_path,
        request.heic_quality,
    )?;
    refuse_preexisting_output(&request.output_path)?;
    let total_started = Instant::now();
    let convert_started = Instant::now();
    let convert_usage = run_planned_commands("conversion", &plan.conversion_commands)?;
    let convert_wall_time_millis = positive_millis(convert_started.elapsed());
    let metadata_usage = run_planned_command("metadata", &plan.metadata)?;
    let output = inspect_output(&request.output_path)?;
    let total_wall_time_millis = positive_millis(total_started.elapsed());
    let resource_usage = convert_usage.combine(metadata_usage);

    let mut updated = manifest.clone();
    record_conversion_result(
        &mut updated,
        &request.asset_id,
        ConversionResultProof {
            heic_path: request.output_path,
            heic_sha256: output.sha256,
            size_bytes: output.size_bytes,
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
        },
    )?;

    Ok(updated)
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
    let resolved_program = resolve_sanitized_path_tool(&plan.program)?;
    let mut command = Command::new(resolved_program);
    command
        .args(&plan.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    let outcome = wait_for_command_with_usage(command)?;
    if !outcome.status.success() {
        return Err(ConversionExecutionError::CommandFailed {
            stage,
            program: plan.program.clone(),
            status: outcome.status.to_string(),
        });
    }
    Ok(outcome.resource_usage)
}

fn run_planned_commands(
    stage: &'static str,
    plans: &[CommandPlan],
) -> Result<ChildResourceUsage, ConversionExecutionError> {
    let mut resource_usage = ChildResourceUsage::default();
    for plan in plans {
        resource_usage = resource_usage.combine(run_planned_command(stage, plan)?);
    }
    Ok(resource_usage)
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
    mut command: Command,
) -> Result<CommandOutcome, ConversionExecutionError> {
    use std::mem::MaybeUninit;
    use std::os::unix::process::ExitStatusExt;

    let child = command.spawn()?;
    let pid = child.id() as libc::pid_t;
    let mut status = 0;
    let mut usage = MaybeUninit::<libc::rusage>::zeroed();

    loop {
        let result = unsafe { libc::wait4(pid, &mut status, 0, usage.as_mut_ptr()) };
        if result >= 0 {
            let usage = unsafe { usage.assume_init() };
            return Ok(CommandOutcome {
                status: ExitStatus::from_raw(status),
                resource_usage: ChildResourceUsage::from_rusage(&usage),
            });
        }

        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

#[cfg(not(unix))]
fn wait_for_command_with_usage(
    mut command: Command,
) -> Result<CommandOutcome, ConversionExecutionError> {
    let status = command.status()?;
    Ok(CommandOutcome {
        status,
        resource_usage: ChildResourceUsage::default(),
    })
}

fn inspect_output(path: &Path) -> Result<ConvertedOutput, ConversionExecutionError> {
    inspect_output_with_optional_post_hash(path, Option::<fn(&Path) -> io::Result<()>>::None)
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
    #[error("{stage} command failed: {program} exited with {status}")]
    CommandFailed {
        stage: &'static str,
        program: String,
        status: String,
    },
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard};

    use crate::proof::NasRawProof;
    use crate::workflow::{discover_raw_asset, record_nas_proof};

    #[cfg(unix)]
    static PATH_LOCK: Mutex<()> = Mutex::new(());

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
            "dcraw_emu+magick+heif-enc"
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
        assert_eq!(
            fs::read_to_string(log_path).expect("command log should be readable"),
            "dcraw_emu\nmagick\nheif-enc\nexiftool\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn linux_conversion_chain_failure_does_not_record_output() {
        let tool_dir = fake_linux_conversion_tools_with_heif_enc(
            r#"#!/bin/sh
printf 'heif-enc\n' >> "$EXECUTION_LOG"
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
        let record = manifest.get("asset-1").expect("asset should exist");
        assert_eq!(record.state, State::NasVerified);
        assert!(!record.proofs.contains_key("conversion"));
        assert!(!record.proofs.contains_key("conversion_performance"));
        assert_eq!(
            fs::read_to_string(log_path).expect("command log should be readable"),
            "dcraw_emu\nmagick\nheif-enc\n"
        );
    }

    #[cfg(unix)]
    fn fake_linux_conversion_tools() -> tempfile::TempDir {
        fake_linux_conversion_tools_with_heif_enc(
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
if [ -z "$out" ]; then
  exit 43
fi
printf 'heic-bytes-from-linux-chain' > "$out"
"#,
        )
    }

    #[cfg(unix)]
    fn fake_linux_conversion_tools_with_heif_enc(heif_enc_body: &str) -> tempfile::TempDir {
        let tempdir = tempfile::tempdir().expect("tool tempdir should be created");
        write_executable_script(
            &tempdir.path().join("dcraw_emu"),
            r#"#!/bin/sh
printf 'dcraw_emu\n' >> "$EXECUTION_LOG"
out=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "-Z" ]; then
    out="$arg"
  fi
  previous="$arg"
done
if [ -z "$out" ]; then
  exit 42
fi
printf 'rendered-tiff' > "$out"
"#,
        );
        write_executable_script(
            &tempdir.path().join("magick"),
            r#"#!/bin/sh
printf 'magick\n' >> "$EXECUTION_LOG"
input="$1"
output="$2"
if [ -z "$input" ] || [ -z "$output" ]; then
  exit 45
fi
printf 'rendered-png' > "$output"
"#,
        );
        write_executable_script(&tempdir.path().join("heif-enc"), heif_enc_body);
        write_executable_script(
            &tempdir.path().join("exiftool"),
            r#"#!/bin/sh
printf 'exiftool\n' >> "$EXECUTION_LOG"
exit 0
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

    fn nas_verified_manifest(raw_path: &Path) -> Manifest {
        let mut manifest = Manifest::new();
        discover_raw_asset(&mut manifest, "asset-1", raw_path.to_path_buf())
            .expect("asset should be discovered");
        record_nas_proof(
            &mut manifest,
            "asset-1",
            NasRawProof {
                canonical_path: raw_path.to_path_buf(),
                relative_path: PathBuf::from("IMG_0001.dng"),
                size_bytes: 9,
                modified_unix_seconds: 1_700_000_000,
                age_seconds: 40 * 24 * 60 * 60,
                sha256: "raw-sha256".to_string(),
            },
        )
        .expect("nas proof should be recorded");
        manifest
    }

    #[cfg(unix)]
    struct PathGuard {
        previous: Option<OsString>,
        _lock: MutexGuard<'static, ()>,
    }

    #[cfg(unix)]
    impl PathGuard {
        fn install(path: &Path) -> Self {
            let lock = PATH_LOCK.lock().expect("PATH lock should be available");
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
    struct EnvVarGuard {
        name: &'static str,
        previous: Option<OsString>,
    }

    #[cfg(unix)]
    impl EnvVarGuard {
        fn install(name: &'static str, value: &Path) -> Self {
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

use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::conversion::{CommandPlan, ConversionError, plan_conversion};
use crate::conversion_backend::current_backend_report;
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
    let backend = current_backend_report();
    if !backend.workflow_convert_supported {
        return Err(ConversionExecutionError::UnsupportedBackend {
            backend: backend.name,
            reason: backend.reason,
        });
    }

    let plan = plan_conversion(&raw_path, &request.output_path, request.heic_quality)?;
    refuse_preexisting_output(&request.output_path)?;
    let total_started = Instant::now();
    let convert_started = Instant::now();
    let convert_usage = run_planned_command("conversion", &plan.convert)?;
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
            conversion_tool: plan.convert.program,
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
}

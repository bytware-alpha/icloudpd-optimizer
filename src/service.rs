use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

use crate::monitor::{MonitorConfig, MonitorError, write_launchd_plist};

pub const DEFAULT_SERVICE_LABEL: &str = "com.icloudpd-optimizer.monitor";

#[derive(Debug)]
pub struct ServiceInstallRequest {
    pub config_path: PathBuf,
    pub binary_path: PathBuf,
    pub plist_path: PathBuf,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    pub label: String,
    pub associated_bundle_id: Option<String>,
}

#[derive(Debug)]
pub struct ServiceInstallSummary {
    pub label: String,
    pub binary_path: PathBuf,
    pub plist_path: PathBuf,
}

#[derive(Debug)]
pub struct ServiceCommandOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn default_plist_path(label: &str) -> Result<PathBuf, ServiceError> {
    Ok(home_dir()?
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{label}.plist")))
}

pub fn install_service(
    request: &ServiceInstallRequest,
) -> Result<ServiceInstallSummary, ServiceError> {
    MonitorConfig::load(&request.config_path)?;
    validate_source_binary(&request.binary_path)?;
    ensure_parent_dir(&request.stdout_path)?;
    ensure_parent_dir(&request.stderr_path)?;

    write_launchd_plist(
        &request.label,
        &request.binary_path,
        &request.config_path,
        &request.stdout_path,
        &request.stderr_path,
        &request.plist_path,
        request.associated_bundle_id.as_deref(),
    )?;

    Ok(ServiceInstallSummary {
        label: request.label.clone(),
        binary_path: request.binary_path.clone(),
        plist_path: request.plist_path.clone(),
    })
}

pub fn start_service(label: &str, plist_path: &Path) -> Result<(), ServiceError> {
    let domain = launchctl_domain()?;
    run_command(
        Command::new("launchctl")
            .arg("bootstrap")
            .arg(&domain)
            .arg(plist_path),
    )?;
    run_command(
        Command::new("launchctl")
            .arg("kickstart")
            .arg("-k")
            .arg(format!("{domain}/{label}")),
    )?;
    Ok(())
}

pub fn stop_service(label: &str) -> Result<(), ServiceError> {
    let domain = launchctl_domain()?;
    run_command(
        Command::new("launchctl")
            .arg("bootout")
            .arg(format!("{domain}/{label}")),
    )?;
    Ok(())
}

pub fn service_status(label: &str) -> Result<ServiceCommandOutput, ServiceError> {
    let domain = launchctl_domain()?;
    run_command_capture(
        Command::new("launchctl")
            .arg("print")
            .arg(format!("{domain}/{label}")),
    )
}

pub fn uninstall_service(label: &str, plist_path: &Path) -> Result<(), ServiceError> {
    let _ = stop_service(label);
    if plist_path.exists() {
        fs::remove_file(plist_path).map_err(|source| ServiceError::Remove {
            path: plist_path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

pub fn tail_logs(
    stdout_path: &Path,
    stderr_path: &Path,
    lines: usize,
) -> Result<String, ServiceError> {
    let mut output = String::new();
    output.push_str("== stdout ==\n");
    output.push_str(&tail_file(stdout_path, lines)?);
    output.push_str("\n== stderr ==\n");
    output.push_str(&tail_file(stderr_path, lines)?);
    Ok(output)
}

fn validate_source_binary(path: &Path) -> Result<(), ServiceError> {
    let metadata = fs::metadata(path).map_err(|source| ServiceError::ReadMetadata {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(ServiceError::SourceBinaryNotFile {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> Result<(), ServiceError> {
    let Some(parent) = path.parent().filter(|path| !path.as_os_str().is_empty()) else {
        return Ok(());
    };
    fs::create_dir_all(parent).map_err(|source| ServiceError::CreateDir {
        path: parent.to_path_buf(),
        source,
    })
}

fn home_dir() -> Result<PathBuf, ServiceError> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(ServiceError::MissingHome)
}

fn launchctl_domain() -> Result<String, ServiceError> {
    if !cfg!(target_os = "macos") {
        return Err(ServiceError::UnsupportedPlatform {
            action: "launchctl service management",
        });
    }
    #[cfg(unix)]
    {
        Ok(format!("gui/{}", unsafe { libc::getuid() }))
    }
    #[cfg(not(unix))]
    {
        Err(ServiceError::UnsupportedPlatform {
            action: "launchctl service management",
        })
    }
}

fn run_command(command: &mut Command) -> Result<(), ServiceError> {
    let output = command.output().map_err(|source| ServiceError::CommandIo {
        program: command.get_program().to_string_lossy().into_owned(),
        source,
    })?;
    if output.status.success() {
        return Ok(());
    }
    Err(ServiceError::CommandFailed {
        program: command.get_program().to_string_lossy().into_owned(),
        status: output.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

fn run_command_capture(command: &mut Command) -> Result<ServiceCommandOutput, ServiceError> {
    let output = command.output().map_err(|source| ServiceError::CommandIo {
        program: command.get_program().to_string_lossy().into_owned(),
        source,
    })?;
    Ok(ServiceCommandOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

fn tail_file(path: &Path, lines: usize) -> Result<String, ServiceError> {
    let mut text = String::new();
    match File::open(path) {
        Ok(mut file) => {
            file.read_to_string(&mut text)
                .map_err(|source| ServiceError::Read {
                    path: path.to_path_buf(),
                    source,
                })?;
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(String::new()),
        Err(source) => {
            return Err(ServiceError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    let lines: Vec<&str> = text.lines().rev().take(lines).collect();
    Ok(lines.into_iter().rev().collect::<Vec<_>>().join("\n"))
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("{0}")]
    Monitor(#[from] MonitorError),
    #[error("HOME is not set")]
    MissingHome,
    #[error("{action} is only supported on macOS")]
    UnsupportedPlatform { action: &'static str },
    #[error("service source binary is not a file: {path}")]
    SourceBinaryNotFile { path: PathBuf },
    #[error("failed to read metadata for {path}: {source}")]
    ReadMetadata { path: PathBuf, source: io::Error },
    #[error("failed to create directory {path}: {source}")]
    CreateDir { path: PathBuf, source: io::Error },
    #[error("failed to read {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("failed to remove {path}: {source}")]
    Remove { path: PathBuf, source: io::Error },
    #[error("failed to run {program}: {source}")]
    CommandIo { program: String, source: io::Error },
    #[error("{program} failed with status {status}: {stderr}")]
    CommandFailed {
        program: String,
        status: i32,
        stderr: String,
    },
}

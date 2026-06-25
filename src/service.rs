use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

use crate::monitor::{MonitorConfig, MonitorError, write_launchd_plist};

pub const DEFAULT_SERVICE_LABEL: &str = "com.icloudpd-optimizer.monitor";
pub const DEFAULT_BUNDLE_ID: &str = "io.github.bytware-alpha.icloudpd-optimizer";
pub const DEFAULT_APP_NAME: &str = "iCloudPD Optimizer.app";
pub const SERVICE_EXECUTABLE_NAME: &str = "icloudpd-optimizer-service";

#[derive(Debug)]
pub struct ServiceInstallRequest {
    pub config_path: PathBuf,
    pub source_binary: PathBuf,
    pub app_path: PathBuf,
    pub plist_path: PathBuf,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    pub label: String,
    pub bundle_id: String,
    pub skip_codesign: bool,
    pub force: bool,
}

#[derive(Debug)]
pub struct ServiceInstallSummary {
    pub label: String,
    pub app_path: PathBuf,
    pub app_binary: PathBuf,
    pub plist_path: PathBuf,
    pub bundle_id: String,
}

#[derive(Debug)]
pub struct ServiceCommandOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn default_app_path() -> Result<PathBuf, ServiceError> {
    Ok(home_dir()?.join("Applications").join(DEFAULT_APP_NAME))
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
    validate_app_path(&request.app_path)?;
    validate_existing_app(&request.app_path, request.force)?;
    validate_source_binary(&request.source_binary)?;

    let contents_dir = request.app_path.join("Contents");
    let macos_dir = contents_dir.join("MacOS");
    let resources_dir = contents_dir.join("Resources");
    fs::create_dir_all(&macos_dir).map_err(|source| ServiceError::CreateDir {
        path: macos_dir.clone(),
        source,
    })?;
    fs::create_dir_all(&resources_dir).map_err(|source| ServiceError::CreateDir {
        path: resources_dir,
        source,
    })?;

    let app_binary = macos_dir.join(SERVICE_EXECUTABLE_NAME);
    if request.source_binary != app_binary {
        fs::copy(&request.source_binary, &app_binary).map_err(|source| {
            ServiceError::CopyBinary {
                source_path: request.source_binary.clone(),
                destination: app_binary.clone(),
                io_source: source,
            }
        })?;
    }
    make_executable(&app_binary)?;

    write_info_plist(
        &contents_dir.join("Info.plist"),
        &request.bundle_id,
        SERVICE_EXECUTABLE_NAME,
    )?;

    if cfg!(target_os = "macos") && !request.skip_codesign {
        run_command(
            Command::new("codesign")
                .arg("-f")
                .arg("-s")
                .arg("-")
                .arg(&request.app_path),
        )?;
    }

    write_launchd_plist(
        &request.label,
        &app_binary,
        &request.config_path,
        &request.stdout_path,
        &request.stderr_path,
        &request.plist_path,
        Some(&request.bundle_id),
    )?;

    Ok(ServiceInstallSummary {
        label: request.label.clone(),
        app_path: request.app_path.clone(),
        app_binary,
        plist_path: request.plist_path.clone(),
        bundle_id: request.bundle_id.clone(),
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

pub fn uninstall_service(
    label: &str,
    plist_path: &Path,
    app_path: &Path,
    keep_app: bool,
) -> Result<(), ServiceError> {
    let _ = stop_service(label);
    if plist_path.exists() {
        fs::remove_file(plist_path).map_err(|source| ServiceError::Remove {
            path: plist_path.to_path_buf(),
            source,
        })?;
    }
    if !keep_app && app_path.exists() {
        fs::remove_dir_all(app_path).map_err(|source| ServiceError::Remove {
            path: app_path.to_path_buf(),
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

fn validate_app_path(app_path: &Path) -> Result<(), ServiceError> {
    if app_path.extension() != Some(OsStr::new("app")) {
        return Err(ServiceError::InvalidAppPath {
            path: app_path.to_path_buf(),
        });
    }
    Ok(())
}

fn validate_existing_app(app_path: &Path, force: bool) -> Result<(), ServiceError> {
    if !app_path.exists() || force || app_path.join("Contents").join("Info.plist").exists() {
        return Ok(());
    }
    Err(ServiceError::AppExistsWithoutBundle {
        path: app_path.to_path_buf(),
    })
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

fn write_info_plist(
    path: &Path,
    bundle_id: &str,
    executable_name: &str,
) -> Result<(), ServiceError> {
    let payload = format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
            "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
            "<plist version=\"1.0\">\n",
            "<dict>\n",
            "  <key>CFBundleDevelopmentRegion</key>\n",
            "  <string>en</string>\n",
            "  <key>CFBundleDisplayName</key>\n",
            "  <string>iCloudPD Optimizer</string>\n",
            "  <key>CFBundleExecutable</key>\n",
            "  <string>{executable}</string>\n",
            "  <key>CFBundleIdentifier</key>\n",
            "  <string>{bundle_id}</string>\n",
            "  <key>CFBundleInfoDictionaryVersion</key>\n",
            "  <string>6.0</string>\n",
            "  <key>CFBundleName</key>\n",
            "  <string>iCloudPD Optimizer</string>\n",
            "  <key>CFBundlePackageType</key>\n",
            "  <string>APPL</string>\n",
            "  <key>CFBundleShortVersionString</key>\n",
            "  <string>{version}</string>\n",
            "  <key>CFBundleVersion</key>\n",
            "  <string>{version}</string>\n",
            "  <key>LSBackgroundOnly</key>\n",
            "  <true/>\n",
            "</dict>\n",
            "</plist>\n"
        ),
        executable = escape_xml(executable_name),
        bundle_id = escape_xml(bundle_id),
        version = env!("CARGO_PKG_VERSION"),
    );
    write_text_atomic(path, &payload).map_err(|source| ServiceError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn make_executable(path: &Path) -> Result<(), ServiceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path)
            .map_err(|source| ServiceError::ReadMetadata {
                path: path.to_path_buf(),
                source,
            })?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).map_err(|source| ServiceError::Write {
            path: path.to_path_buf(),
            source,
        })?;
    }
    Ok(())
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

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("{0}")]
    Monitor(#[from] MonitorError),
    #[error("HOME is not set")]
    MissingHome,
    #[error("{action} is only supported on macOS")]
    UnsupportedPlatform { action: &'static str },
    #[error("service app path must end in .app: {path}")]
    InvalidAppPath { path: PathBuf },
    #[error("service app path exists but is not an app bundle; pass --force to replace: {path}")]
    AppExistsWithoutBundle { path: PathBuf },
    #[error("service source binary is not a file: {path}")]
    SourceBinaryNotFile { path: PathBuf },
    #[error("failed to read metadata for {path}: {source}")]
    ReadMetadata { path: PathBuf, source: io::Error },
    #[error("failed to create directory {path}: {source}")]
    CreateDir { path: PathBuf, source: io::Error },
    #[error("failed to copy service binary from {source_path} to {destination}: {io_source}")]
    CopyBinary {
        source_path: PathBuf,
        destination: PathBuf,
        io_source: io::Error,
    },
    #[error("failed to write {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
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

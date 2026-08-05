use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

use crate::authorization_policy::{
    load_sealed, trusted_effective_user_home, validate_service_install_path,
};
use crate::monitor::{MonitorConfig, MonitorError, write_service_launchd_plist};

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
    Ok(trusted_effective_user_home()
        .map_err(|_| ServiceError::MissingHome)?
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{label}.plist")))
}

pub fn install_service(
    request: &ServiceInstallRequest,
) -> Result<ServiceInstallSummary, ServiceError> {
    // Admission precedes every durable mutation, including the hard-stop.  A
    // dashboard-local binary or an alternate label must never become a
    // launchd authority merely because it can write a plist.
    MonitorConfig::load(&request.config_path)?;
    validate_sealed_service_admission(request)?;
    ensure_parent_dir(&request.stdout_path)?;
    ensure_parent_dir(&request.stderr_path)?;
    let hard_stop_path = hard_stop_path_for_plist(&request.plist_path);
    engage_hard_stop(&hard_stop_path)?;

    write_service_launchd_plist(
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
    let hard_stop_path = hard_stop_path_for_plist(plist_path);
    start_service_in_domain(&domain, label, plist_path, &hard_stop_path, run_launchctl)
}

pub fn stop_service(label: &str, plist_path: &Path) -> Result<(), ServiceError> {
    let domain = launchctl_domain()?;
    let hard_stop_path = hard_stop_path_for_plist(plist_path);
    stop_service_in_domain(&domain, label, &hard_stop_path, run_launchctl)
}

fn start_service_in_domain<F>(
    domain: &str,
    label: &str,
    plist_path: &Path,
    hard_stop_path: &Path,
    mut run: F,
) -> Result<(), ServiceError>
where
    F: FnMut(&[OsString]) -> Result<(), ServiceError>,
{
    engage_hard_stop(hard_stop_path)?;
    let target = format!("{domain}/{label}");
    for command in [
        vec![OsString::from("enable"), OsString::from(&target)],
        vec![
            OsString::from("bootstrap"),
            OsString::from(domain),
            plist_path.as_os_str().to_os_string(),
        ],
        vec![
            OsString::from("kickstart"),
            OsString::from("-k"),
            OsString::from(&target),
        ],
    ] {
        if let Err(start) = run(&command) {
            let rollback = disable_and_unload_in_domain(domain, label, &mut run);
            return Err(ServiceError::StartHardStopped {
                start: Box::new(start),
                rollback: rollback.err().map(Box::new),
            });
        }
    }
    release_hard_stop(hard_stop_path)?;
    Ok(())
}

fn stop_service_in_domain<F>(
    domain: &str,
    label: &str,
    hard_stop_path: &Path,
    run: F,
) -> Result<(), ServiceError>
where
    F: FnMut(&[OsString]) -> Result<(), ServiceError>,
{
    engage_hard_stop(hard_stop_path)?;
    disable_and_unload_in_domain(domain, label, run)
}

fn hard_stop_path_for_plist(plist_path: &Path) -> PathBuf {
    plist_path.with_extension("hard-stop")
}

fn engage_hard_stop(path: &Path) -> Result<(), ServiceError> {
    ensure_parent_dir(path)?;
    use std::io::Write;
    let parent = hard_stop_parent(path)?;
    let temp_path = hard_stop_temp_path(path)?;
    let write_result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)?;
        file.write_all(b"production processing disabled\n")?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp_path, path)?;
        File::open(parent)?.sync_all()
    })();
    if let Err(source) = write_result {
        let _ = fs::remove_file(&temp_path);
        return Err(ServiceError::HardStopIo { source });
    }
    Ok(())
}

fn release_hard_stop(path: &Path) -> Result<(), ServiceError> {
    fs::remove_file(path).map_err(|source| ServiceError::HardStopIo { source })?;
    File::open(hard_stop_parent(path)?)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| ServiceError::HardStopIo { source })
}

fn hard_stop_parent(path: &Path) -> Result<&Path, ServiceError> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| ServiceError::HardStopIo {
            source: io::Error::other("hard-stop path has no parent"),
        })
}

fn hard_stop_temp_path(path: &Path) -> Result<PathBuf, ServiceError> {
    let parent = hard_stop_parent(path)?;
    let file_name = path.file_name().ok_or_else(|| ServiceError::HardStopIo {
        source: io::Error::other("hard-stop path has no file name"),
    })?;
    Ok(parent.join(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        uuid::Uuid::new_v4()
    )))
}

fn disable_and_unload_in_domain<F>(
    domain: &str,
    label: &str,
    mut run: F,
) -> Result<(), ServiceError>
where
    F: FnMut(&[OsString]) -> Result<(), ServiceError>,
{
    let target = format!("{domain}/{label}");
    let disable = run(&[OsString::from("disable"), OsString::from(&target)]);
    let bootout = run(&[OsString::from("bootout"), OsString::from(target)]);
    match (disable, bootout) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(disable), Ok(())) => Err(disable),
        (Ok(()), Err(bootout)) => Err(bootout),
        (Err(disable), Err(bootout)) => Err(ServiceError::DisableAndUnloadFailed {
            disable: Box::new(disable),
            bootout: Box::new(bootout),
        }),
    }
}

fn run_launchctl(arguments: &[OsString]) -> Result<(), ServiceError> {
    run_command(Command::new("launchctl").args(arguments))
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
    let _ = stop_service(label, plist_path);
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

fn validate_sealed_service_admission(request: &ServiceInstallRequest) -> Result<(), ServiceError> {
    if request.label != DEFAULT_SERVICE_LABEL
        || request.associated_bundle_id.as_deref() != Some(DEFAULT_SERVICE_LABEL)
    {
        return Err(ServiceError::SealedAdmission);
    }
    validate_source_binary(&request.binary_path)?;
    let bundle = request
        .binary_path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or(ServiceError::SealedAdmission)?;
    if request.binary_path != bundle.join("Contents/MacOS/ICloudPDOptimizerApp") {
        return Err(ServiceError::SealedAdmission);
    }
    let (policy, _) = load_sealed(bundle, unsafe { libc::geteuid() })
        .map_err(|_| ServiceError::SealedAdmission)?;
    validate_service_install_path(bundle, &policy).map_err(|_| ServiceError::SealedAdmission)?;
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
    #[error("service admission rejected: installed sealed Service authority is required")]
    SealedAdmission,
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
    #[error(
        "service start did not complete; production processing remains hard-stopped. Inspect service status and repair launchd before retrying"
    )]
    StartHardStopped {
        start: Box<ServiceError>,
        rollback: Option<Box<ServiceError>>,
    },
    #[error("service disable failed ({disable}) and unload failed ({bootout})")]
    DisableAndUnloadFailed {
        disable: Box<ServiceError>,
        bootout: Box<ServiceError>,
    },
    #[error("production processing is hard-stopped; run service start after repairing launchd")]
    ProductionHardStopped,
    #[error("failed to update the durable production hard-stop boundary")]
    HardStopIo { source: io::Error },
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: &str = "gui/501";
    const LABEL: &str = "com.example.icloudpd-optimizer";

    fn rendered(arguments: &[OsString]) -> Vec<String> {
        arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    fn command_failure() -> ServiceError {
        ServiceError::CommandFailed {
            program: "launchctl".to_owned(),
            status: 1,
            stderr: "simulated failure".to_owned(),
        }
    }

    fn expected_stop_commands() -> Vec<Vec<String>> {
        vec![
            vec!["disable".to_owned(), format!("{DOMAIN}/{LABEL}")],
            vec!["bootout".to_owned(), format!("{DOMAIN}/{LABEL}")],
        ]
    }

    #[test]
    fn sealed_admission_rejects_dashboard_binary_before_any_plist_mutation() {
        let tempdir = tempfile::tempdir().expect("temporary service directory");
        let plist_path = tempdir.path().join("monitor.plist");
        let request = ServiceInstallRequest {
            config_path: tempdir.path().join("missing-config.json"),
            binary_path: tempdir
                .path()
                .join("Dashboard.app/Contents/MacOS/ICloudPDOptimizerApp"),
            plist_path: plist_path.clone(),
            stdout_path: tempdir.path().join("stdout.log"),
            stderr_path: tempdir.path().join("stderr.log"),
            label: DEFAULT_SERVICE_LABEL.to_owned(),
            associated_bundle_id: Some(DEFAULT_SERVICE_LABEL.to_owned()),
        };
        assert!(matches!(
            validate_sealed_service_admission(&request),
            Err(ServiceError::ReadMetadata { .. }) | Err(ServiceError::SealedAdmission)
        ));
        assert!(
            !plist_path.exists(),
            "rejection must precede plist mutation"
        );
    }

    #[test]
    fn stop_persists_disabled_before_unloading() {
        let mut calls = Vec::new();
        let tempdir = tempfile::tempdir().expect("temporary hard-stop directory");
        let hard_stop_path = tempdir.path().join("service.stop");

        stop_service_in_domain(DOMAIN, LABEL, &hard_stop_path, |arguments| {
            assert!(
                hard_stop_path.exists(),
                "the barrier must be engaged before launchctl {}",
                rendered(arguments)[0]
            );
            calls.push(rendered(arguments));
            Ok(())
        })
        .expect("stop should succeed");

        assert_eq!(calls, expected_stop_commands());
        assert!(
            hard_stop_path.exists(),
            "stop must durably block processing first"
        );
    }

    #[test]
    fn start_enables_bootstraps_and_kickstarts_in_order() {
        let plist_path = Path::new("/tmp/icloudpd-optimizer.plist");
        let mut calls = Vec::new();
        let tempdir = tempfile::tempdir().expect("temporary hard-stop directory");
        let hard_stop_path = tempdir.path().join("service.stop");

        start_service_in_domain(DOMAIN, LABEL, plist_path, &hard_stop_path, |arguments| {
            assert!(
                hard_stop_path.exists(),
                "the barrier must be engaged before launchctl {}",
                rendered(arguments)[0]
            );
            calls.push(rendered(arguments));
            Ok(())
        })
        .expect("start should succeed");

        assert_eq!(
            calls,
            vec![
                vec!["enable".to_owned(), format!("{DOMAIN}/{LABEL}")],
                vec![
                    "bootstrap".to_owned(),
                    DOMAIN.to_owned(),
                    plist_path.display().to_string(),
                ],
                vec![
                    "kickstart".to_owned(),
                    "-k".to_owned(),
                    format!("{DOMAIN}/{LABEL}"),
                ],
            ]
        );
        assert!(
            !hard_stop_path.exists(),
            "a successful explicit start must release the hard stop"
        );
    }

    #[test]
    fn enable_failure_restores_persistently_disabled_and_unloaded_state() {
        let plist_path = Path::new("/tmp/icloudpd-optimizer.plist");
        let mut calls = Vec::new();
        let tempdir = tempfile::tempdir().expect("temporary hard-stop directory");
        let hard_stop_path = tempdir.path().join("service.stop");

        let result =
            start_service_in_domain(DOMAIN, LABEL, plist_path, &hard_stop_path, |arguments| {
                let command = rendered(arguments);
                let should_fail = command[0] == "enable";
                calls.push(command);
                if should_fail {
                    Err(command_failure())
                } else {
                    Ok(())
                }
            });

        assert!(result.is_err(), "enable failure must fail service start");
        assert_eq!(
            calls,
            vec![
                vec!["enable".to_owned(), format!("{DOMAIN}/{LABEL}")],
                expected_stop_commands()[0].clone(),
                expected_stop_commands()[1].clone(),
            ]
        );
        assert!(
            hard_stop_path.exists(),
            "failed start must retain the hard stop"
        );
    }

    #[test]
    fn bootstrap_failure_rolls_back_to_persistently_disabled_and_unloaded() {
        let plist_path = Path::new("/tmp/icloudpd-optimizer.plist");
        let mut calls = Vec::new();
        let tempdir = tempfile::tempdir().expect("temporary hard-stop directory");
        let hard_stop_path = tempdir.path().join("service.stop");

        let result =
            start_service_in_domain(DOMAIN, LABEL, plist_path, &hard_stop_path, |arguments| {
                let command = rendered(arguments);
                let should_fail = command[0] == "bootstrap";
                calls.push(command);
                if should_fail {
                    Err(command_failure())
                } else {
                    Ok(())
                }
            });

        assert!(result.is_err(), "bootstrap failure must fail service start");
        assert_eq!(
            calls,
            vec![
                vec!["enable".to_owned(), format!("{DOMAIN}/{LABEL}")],
                vec![
                    "bootstrap".to_owned(),
                    DOMAIN.to_owned(),
                    plist_path.display().to_string(),
                ],
                expected_stop_commands()[0].clone(),
                expected_stop_commands()[1].clone(),
            ]
        );
        assert!(
            hard_stop_path.exists(),
            "failed start must retain the hard stop"
        );
    }

    #[test]
    fn kickstart_failure_rolls_back_to_persistently_disabled_and_unloaded() {
        let plist_path = Path::new("/tmp/icloudpd-optimizer.plist");
        let mut calls = Vec::new();
        let tempdir = tempfile::tempdir().expect("temporary hard-stop directory");
        let hard_stop_path = tempdir.path().join("service.stop");

        let result =
            start_service_in_domain(DOMAIN, LABEL, plist_path, &hard_stop_path, |arguments| {
                let command = rendered(arguments);
                let should_fail = command[0] == "kickstart";
                calls.push(command);
                if should_fail {
                    Err(command_failure())
                } else {
                    Ok(())
                }
            });

        assert!(result.is_err(), "kickstart failure must fail service start");
        assert_eq!(
            calls,
            vec![
                vec!["enable".to_owned(), format!("{DOMAIN}/{LABEL}")],
                vec![
                    "bootstrap".to_owned(),
                    DOMAIN.to_owned(),
                    plist_path.display().to_string(),
                ],
                vec![
                    "kickstart".to_owned(),
                    "-k".to_owned(),
                    format!("{DOMAIN}/{LABEL}"),
                ],
                expected_stop_commands()[0].clone(),
                expected_stop_commands()[1].clone(),
            ]
        );
        assert!(
            hard_stop_path.exists(),
            "failed start must retain the hard stop"
        );
    }

    #[test]
    fn rollback_disable_failure_keeps_hard_stop_and_returns_redacted_actionable_error() {
        let tempdir = tempfile::tempdir().expect("temporary hard-stop directory");
        let hard_stop_path = tempdir.path().join("service.stop");
        let mut calls = Vec::new();
        let result = start_service_in_domain(
            DOMAIN,
            LABEL,
            Path::new("/tmp/icloudpd-optimizer.plist"),
            &hard_stop_path,
            |arguments| {
                assert!(hard_stop_path.exists(), "barrier must precede launchctl");
                let command = rendered(arguments);
                let result = match command[0].as_str() {
                    "bootstrap" | "disable" => Err(command_failure()),
                    _ => Ok(()),
                };
                calls.push(command);
                result
            },
        );

        let error = result.expect_err("start must fail when bootstrap fails");
        assert!(matches!(
            error,
            ServiceError::StartHardStopped {
                rollback: Some(_),
                ..
            }
        ));
        assert!(
            hard_stop_path.exists(),
            "unproven rollback must block production work"
        );
        assert!(!error.to_string().contains("simulated failure"));
        assert_eq!(
            calls,
            vec![
                vec!["enable".to_owned(), format!("{DOMAIN}/{LABEL}")],
                vec![
                    "bootstrap".to_owned(),
                    DOMAIN.to_owned(),
                    "/tmp/icloudpd-optimizer.plist".to_owned(),
                ],
                expected_stop_commands()[0].clone(),
                expected_stop_commands()[1].clone(),
            ],
            "bootout must still be attempted when rollback disable fails"
        );
    }

    #[test]
    fn rollback_bootout_failure_keeps_hard_stop_and_returns_redacted_actionable_error() {
        let tempdir = tempfile::tempdir().expect("temporary hard-stop directory");
        let hard_stop_path = tempdir.path().join("service.stop");
        let mut calls = Vec::new();
        let result = start_service_in_domain(
            DOMAIN,
            LABEL,
            Path::new("/tmp/icloudpd-optimizer.plist"),
            &hard_stop_path,
            |arguments| {
                assert!(hard_stop_path.exists(), "barrier must precede launchctl");
                let command = rendered(arguments);
                let result = match command[0].as_str() {
                    "kickstart" | "bootout" => Err(command_failure()),
                    _ => Ok(()),
                };
                calls.push(command);
                result
            },
        );

        let error = result.expect_err("start must fail when kickstart fails");
        assert!(matches!(
            error,
            ServiceError::StartHardStopped {
                rollback: Some(_),
                ..
            }
        ));
        assert!(
            hard_stop_path.exists(),
            "unproven unload must block production work"
        );
        assert_eq!(
            calls,
            vec![
                vec!["enable".to_owned(), format!("{DOMAIN}/{LABEL}")],
                vec![
                    "bootstrap".to_owned(),
                    DOMAIN.to_owned(),
                    "/tmp/icloudpd-optimizer.plist".to_owned(),
                ],
                vec![
                    "kickstart".to_owned(),
                    "-k".to_owned(),
                    format!("{DOMAIN}/{LABEL}"),
                ],
                expected_stop_commands()[0].clone(),
                expected_stop_commands()[1].clone(),
            ]
        );
    }

    #[test]
    fn combined_rollback_failure_keeps_hard_stop() {
        let tempdir = tempfile::tempdir().expect("temporary hard-stop directory");
        let hard_stop_path = tempdir.path().join("service.stop");
        let mut calls = Vec::new();
        let result = start_service_in_domain(
            DOMAIN,
            LABEL,
            Path::new("/tmp/icloudpd-optimizer.plist"),
            &hard_stop_path,
            |arguments| {
                assert!(hard_stop_path.exists(), "barrier must precede launchctl");
                let command = rendered(arguments);
                let result = match command[0].as_str() {
                    "enable" | "disable" | "bootout" => Err(command_failure()),
                    _ => Ok(()),
                };
                calls.push(command);
                result
            },
        );

        assert!(matches!(
            result,
            Err(ServiceError::StartHardStopped {
                rollback: Some(_),
                ..
            })
        ));
        assert!(
            hard_stop_path.exists(),
            "both rollback failures must retain the hard stop"
        );
        assert_eq!(
            calls,
            vec![
                vec!["enable".to_owned(), format!("{DOMAIN}/{LABEL}")],
                expected_stop_commands()[0].clone(),
                expected_stop_commands()[1].clone(),
            ],
            "combined rollback failure must attempt both commands"
        );
    }

    #[test]
    fn stop_disable_failure_still_attempts_bootout_with_barrier_engaged() {
        let tempdir = tempfile::tempdir().expect("temporary hard-stop directory");
        let hard_stop_path = tempdir.path().join("service.stop");
        let mut calls = Vec::new();

        let result = stop_service_in_domain(DOMAIN, LABEL, &hard_stop_path, |arguments| {
            assert!(hard_stop_path.exists(), "barrier must precede launchctl");
            let command = rendered(arguments);
            let result = if command[0] == "disable" {
                Err(command_failure())
            } else {
                Ok(())
            };
            calls.push(command);
            result
        });

        assert!(result.is_err(), "disable failure must fail stop");
        assert_eq!(calls, expected_stop_commands());
        assert!(
            hard_stop_path.exists(),
            "failed stop must retain the barrier"
        );
    }

    #[test]
    fn engage_hard_stop_replaces_existing_barrier() {
        let tempdir = tempfile::tempdir().expect("temporary hard-stop directory");
        let hard_stop_path = tempdir.path().join("service.stop");
        fs::write(&hard_stop_path, "stale\n").expect("write stale barrier");

        engage_hard_stop(&hard_stop_path).expect("engage barrier");

        assert_eq!(
            fs::read_to_string(&hard_stop_path).expect("read barrier"),
            "production processing disabled\n"
        );
    }
}

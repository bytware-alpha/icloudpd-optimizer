use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::{ffi::CString, os::unix::ffi::OsStrExt};

use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::workflow::IcloudpdLocalMirrorProof;

const HASH_BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcloudpdLocalMirrorRequest {
    pub uploaded_heic_asset_id: String,
    pub uploaded_heic_sha256: String,
    pub uploaded_heic_path: PathBuf,
    pub size_bytes: u64,
    pub icloudpd_download_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileIdentity {
    sha256: String,
    size_bytes: u64,
}

pub fn ensure_icloudpd_local_mirror(
    request: IcloudpdLocalMirrorRequest,
) -> Result<IcloudpdLocalMirrorProof, LocalMirrorError> {
    require_non_empty_path("uploaded_heic_path", &request.uploaded_heic_path)?;
    require_non_empty_path("icloudpd_download_path", &request.icloudpd_download_path)?;

    let source_identity = inspect_regular_file("uploaded_heic_path", &request.uploaded_heic_path)?;
    require_identity(
        "uploaded_heic_sha256",
        "size_bytes",
        &request.uploaded_heic_sha256,
        request.size_bytes,
        &source_identity,
    )?;

    match fs::symlink_metadata(&request.icloudpd_download_path) {
        Ok(metadata) => {
            let destination_identity = inspect_existing_metadata(
                "icloudpd_download_path",
                &request.icloudpd_download_path,
                metadata,
            )?;
            require_identity(
                "uploaded_heic_sha256",
                "size_bytes",
                &request.uploaded_heic_sha256,
                request.size_bytes,
                &destination_identity,
            )?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            copy_missing_destination(&request)?;
            let destination_identity =
                inspect_regular_file("icloudpd_download_path", &request.icloudpd_download_path)?;
            require_identity(
                "uploaded_heic_sha256",
                "size_bytes",
                &request.uploaded_heic_sha256,
                request.size_bytes,
                &destination_identity,
            )?;
        }
        Err(source) => {
            return Err(LocalMirrorError::Io {
                operation: "read metadata",
                path: request.icloudpd_download_path,
                source,
            });
        }
    }

    Ok(IcloudpdLocalMirrorProof {
        uploaded_heic_asset_id: request.uploaded_heic_asset_id,
        uploaded_heic_sha256: request.uploaded_heic_sha256,
        uploaded_heic_path: request.uploaded_heic_path,
        icloudpd_download_path: request.icloudpd_download_path,
        size_bytes: request.size_bytes,
    })
}

fn copy_missing_destination(request: &IcloudpdLocalMirrorRequest) -> Result<(), LocalMirrorError> {
    let parent = request
        .icloudpd_download_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = request
        .icloudpd_download_path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or(LocalMirrorError::InvalidPath {
            field: "icloudpd_download_path",
            path: request.icloudpd_download_path.clone(),
            reason: "must include a file name",
        })?;
    let temp_path = parent.join(format!(
        ".{}.icloudpd-local-mirror.{}.tmp",
        file_name.to_string_lossy(),
        Uuid::new_v4()
    ));

    let result = (|| -> Result<(), LocalMirrorError> {
        let mut source =
            File::open(&request.uploaded_heic_path).map_err(|source| LocalMirrorError::Io {
                operation: "open source",
                path: request.uploaded_heic_path.clone(),
                source,
            })?;
        let mut temp_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|source| LocalMirrorError::Io {
                operation: "create temp mirror",
                path: temp_path.clone(),
                source,
            })?;
        io::copy(&mut source, &mut temp_file).map_err(|source| LocalMirrorError::Io {
            operation: "copy mirror",
            path: temp_path.clone(),
            source,
        })?;
        temp_file
            .sync_all()
            .map_err(|source| LocalMirrorError::Io {
                operation: "sync temp mirror",
                path: temp_path.clone(),
                source,
            })?;
        drop(temp_file);

        let temp_identity = inspect_regular_file("icloudpd_download_path", &temp_path)?;
        require_identity(
            "uploaded_heic_sha256",
            "size_bytes",
            &request.uploaded_heic_sha256,
            request.size_bytes,
            &temp_identity,
        )?;

        install_mirror_without_overwrite(request, &temp_path)?;
        let _ = fs::remove_file(&temp_path);
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn install_mirror_without_overwrite(
    request: &IcloudpdLocalMirrorRequest,
    temp_path: &Path,
) -> Result<(), LocalMirrorError> {
    install_mirror_without_overwrite_with(request, temp_path, rename_without_overwrite)
}

fn install_mirror_without_overwrite_with<F>(
    request: &IcloudpdLocalMirrorRequest,
    temp_path: &Path,
    rename_without_overwrite_fn: F,
) -> Result<(), LocalMirrorError>
where
    F: FnOnce(&Path, &Path) -> io::Result<()>,
{
    match rename_without_overwrite_fn(temp_path, &request.icloudpd_download_path) {
        Ok(()) => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        Err(_) => {}
    }

    copy_temp_to_destination_without_overwrite(request, temp_path)
}

fn copy_temp_to_destination_without_overwrite(
    request: &IcloudpdLocalMirrorRequest,
    temp_path: &Path,
) -> Result<(), LocalMirrorError> {
    let mut source = File::open(temp_path).map_err(|source| LocalMirrorError::Io {
        operation: "open verified temp mirror",
        path: temp_path.to_path_buf(),
        source,
    })?;
    let mut destination = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&request.icloudpd_download_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        Err(source) => {
            return Err(LocalMirrorError::Io {
                operation: "create destination mirror without overwrite",
                path: request.icloudpd_download_path.clone(),
                source,
            });
        }
    };

    let result = (|| -> Result<(), LocalMirrorError> {
        io::copy(&mut source, &mut destination).map_err(|source| LocalMirrorError::Io {
            operation: "copy destination mirror",
            path: request.icloudpd_download_path.clone(),
            source,
        })?;
        destination
            .sync_all()
            .map_err(|source| LocalMirrorError::Io {
                operation: "sync destination mirror",
                path: request.icloudpd_download_path.clone(),
                source,
            })?;
        drop(destination);

        let destination_identity =
            inspect_regular_file("icloudpd_download_path", &request.icloudpd_download_path)?;
        require_identity(
            "uploaded_heic_sha256",
            "size_bytes",
            &request.uploaded_heic_sha256,
            request.size_bytes,
            &destination_identity,
        )
    })();

    if result.is_err() {
        let _ = fs::remove_file(&request.icloudpd_download_path);
    }
    result
}

#[cfg(target_os = "macos")]
fn rename_without_overwrite(from: &Path, to: &Path) -> io::Result<()> {
    let from = path_cstring(from)?;
    let to = path_cstring(to)?;
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn rename_without_overwrite(from: &Path, to: &Path) -> io::Result<()> {
    let from = path_cstring(from)?;
    let to = path_cstring(to)?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn rename_without_overwrite(_from: &Path, _to: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "rename without overwrite is not supported on this platform",
    ))
}

#[cfg(unix)]
fn path_cstring(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL byte"))
}

fn inspect_regular_file(
    field: &'static str,
    path: &Path,
) -> Result<FileIdentity, LocalMirrorError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| LocalMirrorError::Io {
        operation: "read metadata",
        path: path.to_path_buf(),
        source,
    })?;
    inspect_existing_metadata(field, path, metadata)
}

fn inspect_existing_metadata(
    field: &'static str,
    path: &Path,
    metadata: Metadata,
) -> Result<FileIdentity, LocalMirrorError> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(LocalMirrorError::Symlink {
            field,
            path: path.to_path_buf(),
        });
    }
    if file_type.is_dir() {
        return Err(LocalMirrorError::Directory {
            field,
            path: path.to_path_buf(),
        });
    }
    if !file_type.is_file() {
        return Err(LocalMirrorError::NotRegularFile {
            field,
            path: path.to_path_buf(),
        });
    }

    Ok(FileIdentity {
        sha256: hash_file_sha256(path)?,
        size_bytes: metadata.len(),
    })
}

fn hash_file_sha256(path: &Path) -> Result<String, LocalMirrorError> {
    let mut file = File::open(path).map_err(|source| LocalMirrorError::Io {
        operation: "open for hash",
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|source| LocalMirrorError::Io {
                operation: "read for hash",
                path: path.to_path_buf(),
                source,
            })?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn require_identity(
    hash_field: &'static str,
    size_field: &'static str,
    expected_hash: &str,
    expected_size: u64,
    identity: &FileIdentity,
) -> Result<(), LocalMirrorError> {
    if identity.sha256 != expected_hash {
        return Err(LocalMirrorError::Mismatch {
            field: hash_field,
            expected: expected_hash.to_string(),
            actual: identity.sha256.clone(),
        });
    }
    if identity.size_bytes != expected_size {
        return Err(LocalMirrorError::Mismatch {
            field: size_field,
            expected: expected_size.to_string(),
            actual: identity.size_bytes.to_string(),
        });
    }
    Ok(())
}

fn require_non_empty_path(field: &'static str, path: &Path) -> Result<(), LocalMirrorError> {
    if path.as_os_str().is_empty() {
        return Err(LocalMirrorError::EmptyPath { field });
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum LocalMirrorError {
    #[error("iCloudPD local mirror field {field} is required")]
    EmptyPath { field: &'static str },
    #[error("iCloudPD local mirror field {field} path {path} is invalid: {reason}")]
    InvalidPath {
        field: &'static str,
        path: PathBuf,
        reason: &'static str,
    },
    #[error("iCloudPD local mirror field {field} path {path} is a symlink")]
    Symlink { field: &'static str, path: PathBuf },
    #[error("iCloudPD local mirror field {field} path {path} is a directory")]
    Directory { field: &'static str, path: PathBuf },
    #[error("iCloudPD local mirror field {field} path {path} is not a regular file")]
    NotRegularFile { field: &'static str, path: PathBuf },
    #[error("iCloudPD local mirror field {field} mismatch: expected {expected}, got {actual}")]
    Mismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    #[error("failed to {operation} for iCloudPD local mirror at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mirror_request(
        source_path: PathBuf,
        destination_path: PathBuf,
        bytes: &[u8],
    ) -> IcloudpdLocalMirrorRequest {
        IcloudpdLocalMirrorRequest {
            uploaded_heic_asset_id: "uploaded-heic-asset".to_string(),
            uploaded_heic_sha256: hash_file_sha256(&source_path).expect("hash should succeed"),
            uploaded_heic_path: source_path,
            size_bytes: bytes.len() as u64,
            icloudpd_download_path: destination_path,
        }
    }

    #[test]
    fn mirror_install_falls_back_to_create_new_copy_when_rename_is_unsupported() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let temp_path = tempdir.path().join(".asset.tmp");
        let destination_path = tempdir.path().join("asset.HEIC");
        let bytes = b"verified-heic-bytes";
        fs::write(&temp_path, bytes).expect("temp mirror should be written");
        let request = mirror_request(temp_path.clone(), destination_path.clone(), bytes);

        install_mirror_without_overwrite_with(&request, &temp_path, |_from, _to| {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "rename without overwrite is unsupported",
            ))
        })
        .expect("fallback copy should install mirror");

        assert_eq!(
            fs::read(&destination_path).expect("destination should be readable"),
            bytes
        );
        assert_eq!(
            fs::read(&temp_path).expect("temp mirror should remain for caller cleanup"),
            bytes
        );
    }

    #[test]
    fn mirror_install_fallback_does_not_overwrite_existing_destination() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let temp_path = tempdir.path().join(".asset.tmp");
        let destination_path = tempdir.path().join("asset.HEIC");
        let bytes = b"verified-heic-bytes";
        let existing = b"existing-destination";
        fs::write(&temp_path, bytes).expect("temp mirror should be written");
        fs::write(&destination_path, existing).expect("existing destination should be written");
        let request = mirror_request(temp_path.clone(), destination_path.clone(), bytes);

        install_mirror_without_overwrite_with(&request, &temp_path, |_from, _to| {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "rename without overwrite is unsupported",
            ))
        })
        .expect("existing destination should be left for caller validation");

        assert_eq!(
            fs::read(&destination_path).expect("destination should be readable"),
            existing
        );
    }

    #[test]
    fn mirror_install_fallback_removes_created_destination_when_verification_fails() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let temp_path = tempdir.path().join(".asset.tmp");
        let destination_path = tempdir.path().join("asset.HEIC");
        let bytes = b"verified-heic-bytes";
        fs::write(&temp_path, bytes).expect("temp mirror should be written");
        let mut request = mirror_request(temp_path.clone(), destination_path.clone(), bytes);
        request.uploaded_heic_sha256 = "not-the-temp-hash".to_string();

        let error = copy_temp_to_destination_without_overwrite(&request, &temp_path)
            .expect_err("mismatch should fail");

        assert!(matches!(error, LocalMirrorError::Mismatch { .. }));
        assert!(
            !destination_path.exists(),
            "failed fallback copy should not leave a destination file"
        );
    }
}

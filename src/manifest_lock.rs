use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug)]
pub struct ManifestLockGuard {
    file: File,
}

#[derive(Debug, Error)]
pub enum ManifestLockError {
    #[error("manifest monitor lock is already held at {lock_path}")]
    Held { lock_path: PathBuf },
    #[error("manifest monitor lock must not be a symbolic link: {path}")]
    Symlink { path: PathBuf },
    #[error("failed to use manifest monitor lock {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

pub fn manifest_lock_path(manifest_path: &Path) -> PathBuf {
    manifest_path.with_extension("monitor.lock")
}

pub fn acquire_manifest_lock(
    manifest_path: &Path,
    owner_id: &str,
    create_parent: bool,
) -> Result<ManifestLockGuard, ManifestLockError> {
    let lock_path = manifest_lock_path(manifest_path);
    let parent = lock_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if create_parent {
        fs::create_dir_all(parent).map_err(|source| ManifestLockError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    match fs::symlink_metadata(&lock_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(ManifestLockError::Symlink { path: lock_path });
        }
        Ok(_) => {}
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ManifestLockError::Io {
                path: lock_path,
                source,
            });
        }
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let mut file = options
        .open(&lock_path)
        .map_err(|source| ManifestLockError::Io {
            path: lock_path.clone(),
            source,
        })?;

    #[cfg(unix)]
    {
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let source = io::Error::last_os_error();
            if matches!(
                source.raw_os_error(),
                Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN
            ) {
                return Err(ManifestLockError::Held { lock_path });
            }
            return Err(ManifestLockError::Io {
                path: lock_path,
                source,
            });
        }
    }

    file.set_len(0)
        .and_then(|()| {
            write!(
                file,
                "pid={}\nowner={}\nmanifest={}\n",
                std::process::id(),
                owner_id,
                manifest_path.display()
            )
        })
        .and_then(|()| file.sync_data())
        .map_err(|source| ManifestLockError::Io {
            path: lock_path,
            source,
        })?;

    Ok(ManifestLockGuard { file })
}

impl Drop for ManifestLockGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

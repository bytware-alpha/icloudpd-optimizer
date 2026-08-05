use std::fs::File;
#[cfg(unix)]
use std::fs::{self, OpenOptions};
use std::io;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use thiserror::Error;

#[derive(Debug)]
pub struct ManifestLockGuard {
    file: File,
    #[cfg(unix)]
    lock_path: PathBuf,
    #[cfg(unix)]
    identity: LockIdentity,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LockIdentity {
    device: u64,
    inode: u64,
    links: u64,
}

#[derive(Debug, Error)]
pub enum ManifestLockError {
    #[error("manifest locking is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("manifest monitor lock is already held at {lock_path}")]
    Held { lock_path: PathBuf },
    #[error(
        "legacy manifest monitor lock does not exist at {lock_path}; start and stop the local monitor once before schema migration"
    )]
    Missing { lock_path: PathBuf },
    #[error("manifest monitor lock must not be a symbolic link: {path}")]
    Symlink { path: PathBuf },
    #[error("manifest monitor lock must be a regular file: {path}")]
    NotRegular { path: PathBuf },
    #[error("manifest monitor lock must not be hard-linked ({links} links): {path}")]
    HardLink { path: PathBuf, links: u64 },
    #[error("manifest monitor lock changed after open: {path}")]
    IdentityChanged { path: PathBuf },
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
    #[cfg(not(unix))]
    {
        let _ = (manifest_path, owner_id, create_parent);
        return Err(ManifestLockError::UnsupportedPlatform);
    }
    #[cfg(unix)]
    acquire_manifest_lock_unix(manifest_path, owner_id, create_parent, false)
}

/// Acquires an existing legacy monitor lock without creating it.
///
/// Schema migration uses this path so it cannot manufacture a lock namespace that a
/// legacy monitor might not share.
pub fn acquire_existing_manifest_lock(
    manifest_path: &Path,
    owner_id: &str,
) -> Result<ManifestLockGuard, ManifestLockError> {
    #[cfg(not(unix))]
    {
        let _ = (manifest_path, owner_id);
        return Err(ManifestLockError::UnsupportedPlatform);
    }
    #[cfg(unix)]
    acquire_manifest_lock_unix(manifest_path, owner_id, false, true)
}

#[cfg(unix)]
fn acquire_manifest_lock_unix(
    manifest_path: &Path,
    owner_id: &str,
    create_parent: bool,
    require_existing: bool,
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

    let file = match fs::symlink_metadata(&lock_path) {
        Ok(metadata) => {
            validate_lock_metadata(&lock_path, &metadata)?;
            open_lock_file(&lock_path, false)?
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            if require_existing {
                return Err(ManifestLockError::Missing { lock_path });
            }
            open_lock_file(&lock_path, true)?
        }
        Err(source) => {
            return Err(ManifestLockError::Io {
                path: lock_path,
                source,
            });
        }
    };
    let identity = validate_open_lock_identity(&lock_path, &file, None)?;

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

    let mut file = file;
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
            path: lock_path.clone(),
            source,
        })?;

    Ok(ManifestLockGuard {
        file,
        lock_path,
        identity,
    })
}

#[cfg(unix)]
fn open_lock_file(path: &Path, create_new: bool) -> Result<File, ManifestLockError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(create_new)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW);
    options.open(path).map_err(|source| ManifestLockError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
fn validate_lock_metadata(path: &Path, metadata: &fs::Metadata) -> Result<(), ManifestLockError> {
    if metadata.file_type().is_symlink() {
        return Err(ManifestLockError::Symlink {
            path: path.to_path_buf(),
        });
    }
    if !metadata.file_type().is_file() {
        return Err(ManifestLockError::NotRegular {
            path: path.to_path_buf(),
        });
    }
    if metadata.nlink() != 1 {
        return Err(ManifestLockError::HardLink {
            path: path.to_path_buf(),
            links: metadata.nlink(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn validate_open_lock_identity(
    path: &Path,
    file: &File,
    expected: Option<LockIdentity>,
) -> Result<LockIdentity, ManifestLockError> {
    let path_metadata = fs::symlink_metadata(path).map_err(|source| ManifestLockError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_lock_metadata(path, &path_metadata)?;
    let file_metadata = file.metadata().map_err(|source| ManifestLockError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    validate_lock_metadata(path, &file_metadata)?;
    let path_identity = LockIdentity {
        device: path_metadata.dev(),
        inode: path_metadata.ino(),
        links: path_metadata.nlink(),
    };
    let file_identity = LockIdentity {
        device: file_metadata.dev(),
        inode: file_metadata.ino(),
        links: file_metadata.nlink(),
    };
    if path_identity != file_identity || expected.is_some_and(|identity| identity != file_identity)
    {
        return Err(ManifestLockError::IdentityChanged {
            path: path.to_path_buf(),
        });
    }
    Ok(file_identity)
}

impl ManifestLockGuard {
    /// Fails closed if the lock path no longer resolves to the inode that was flocked.
    pub fn revalidate(&self) -> Result<(), ManifestLockError> {
        #[cfg(not(unix))]
        {
            return Err(ManifestLockError::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            validate_open_lock_identity(&self.lock_path, &self.file, Some(self.identity))?;
            Ok(())
        }
    }
}

impl Drop for ManifestLockGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

#[cfg(all(test, not(unix)))]
mod tests {
    use super::*;

    #[test]
    fn manifest_locking_fails_closed_when_platform_flocking_is_unavailable() {
        let error = acquire_manifest_lock(Path::new("manifest.json"), "owner", false)
            .expect_err("unfenced manifest locking must not be available");
        assert!(matches!(error, ManifestLockError::UnsupportedPlatform));
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;

    #[test]
    fn guard_revalidation_rejects_a_replaced_lock_path() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest_path = tempdir.path().join("manifest.json");
        let lock_path = manifest_lock_path(&manifest_path);
        fs::write(&lock_path, b"legacy monitor lock\n").expect("create legacy lock");
        let guard =
            acquire_existing_manifest_lock(&manifest_path, "owner").expect("acquire existing lock");
        let moved_lock_path = tempdir.path().join("moved-monitor.lock");
        fs::rename(&lock_path, &moved_lock_path).expect("move locked path");
        fs::write(&lock_path, b"replacement lock\n").expect("replace locked path");

        let error = guard
            .revalidate()
            .expect_err("replaced lock path must invalidate the guard");
        assert!(matches!(error, ManifestLockError::IdentityChanged { path } if path == lock_path));
    }
}

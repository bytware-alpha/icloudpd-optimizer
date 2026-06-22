use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

const DAY_SECONDS: u64 = 24 * 60 * 60;
pub const MIN_RAW_AGE_DAYS: u64 = 30;
pub const MIN_RAW_AGE_SECONDS: u64 = MIN_RAW_AGE_DAYS * DAY_SECONDS;
const HASH_BUFFER_BYTES: usize = 64 * 1024;
const RAW_EXTENSIONS: &[&str] = &[
    "dng", "cr2", "cr3", "nef", "arw", "raf", "rw2", "orf", "pef", "srw", "raw",
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NasRawProof {
    pub canonical_path: PathBuf,
    pub relative_path: PathBuf,
    pub size_bytes: u64,
    pub modified_unix_seconds: u64,
    pub age_seconds: u64,
    pub sha256: String,
}

/// Proves that an old RAW file exists under a NAS root and records immutable facts about it.
///
/// ```no_run
/// # use std::time::SystemTime;
/// # use icloudpd_optimizer::proof::prove_nas_raw;
/// let proof = prove_nas_raw("/nas/photos", "/nas/photos/camera/IMG_0001.dng", 30, SystemTime::now())?;
/// assert!(proof.relative_path.ends_with("camera/IMG_0001.dng"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn prove_nas_raw(
    nas_root: impl AsRef<Path>,
    raw_path: impl AsRef<Path>,
    min_age_days: u64,
    now: SystemTime,
) -> Result<NasRawProof, ProofError> {
    prove_nas_raw_with_after_hash_hook(nas_root, raw_path, min_age_days, now, || {})
}

pub(crate) fn prove_nas_raw_with_min_age_seconds(
    nas_root: impl AsRef<Path>,
    raw_path: impl AsRef<Path>,
    min_age_seconds: u64,
    now: SystemTime,
) -> Result<NasRawProof, ProofError> {
    prove_nas_raw_with_min_age_seconds_after_hash_hook(
        nas_root,
        raw_path,
        min_age_seconds,
        now,
        || {},
    )
}

fn prove_nas_raw_with_after_hash_hook(
    nas_root: impl AsRef<Path>,
    raw_path: impl AsRef<Path>,
    min_age_days: u64,
    now: SystemTime,
    after_hash: impl FnOnce(),
) -> Result<NasRawProof, ProofError> {
    if min_age_days < MIN_RAW_AGE_DAYS {
        return Err(ProofError::MinAgeBelowSafetyFloor {
            requested_days: min_age_days,
            minimum_days: MIN_RAW_AGE_DAYS,
        });
    }
    prove_nas_raw_with_min_age_seconds_after_hash_hook(
        nas_root,
        raw_path,
        min_age_days.saturating_mul(DAY_SECONDS),
        now,
        after_hash,
    )
}

fn prove_nas_raw_with_min_age_seconds_after_hash_hook(
    nas_root: impl AsRef<Path>,
    raw_path: impl AsRef<Path>,
    min_age_seconds: u64,
    now: SystemTime,
    after_hash: impl FnOnce(),
) -> Result<NasRawProof, ProofError> {
    if min_age_seconds < MIN_RAW_AGE_SECONDS {
        return Err(ProofError::MinAgeSecondsBelowSafetyFloor {
            requested_seconds: min_age_seconds,
            minimum_seconds: MIN_RAW_AGE_SECONDS,
        });
    }

    let requested_root = nas_root.as_ref();
    let requested_raw = raw_path.as_ref();
    let canonical_root =
        fs::canonicalize(requested_root).map_err(|source| ProofError::CanonicalizeNasRoot {
            path: requested_root.to_path_buf(),
            source,
        })?;
    let root_metadata =
        fs::metadata(&canonical_root).map_err(|source| ProofError::ReadMetadata {
            path: canonical_root.clone(),
            source,
        })?;
    if !root_metadata.is_dir() {
        return Err(ProofError::NasRootNotDirectory {
            path: canonical_root,
        });
    }
    let canonical_raw =
        fs::canonicalize(requested_raw).map_err(|source| ProofError::CanonicalizeRaw {
            path: requested_raw.to_path_buf(),
            source,
        })?;

    if !canonical_raw.starts_with(&canonical_root) {
        return Err(ProofError::OutsideNasRoot {
            nas_root: canonical_root,
            raw_path: canonical_raw,
        });
    }

    let relative_path = canonical_raw
        .strip_prefix(&canonical_root)
        .map_err(|_| ProofError::OutsideNasRoot {
            nas_root: canonical_root.clone(),
            raw_path: canonical_raw.clone(),
        })?
        .to_path_buf();

    let mut raw_file = File::open(&canonical_raw).map_err(|source| ProofError::OpenRaw {
        path: canonical_raw.clone(),
        source,
    })?;
    let metadata_before = raw_file
        .metadata()
        .map_err(|source| ProofError::ReadMetadata {
            path: canonical_raw.clone(),
            source,
        })?;
    if !metadata_before.is_file() {
        return Err(ProofError::NotRegularFile {
            path: canonical_raw,
        });
    }
    let fingerprint_before = FileFingerprint::from_metadata(&canonical_raw, &metadata_before)?;

    let extension = raw_extension(&canonical_raw)?;
    if !RAW_EXTENSIONS.contains(&extension.as_str()) {
        return Err(ProofError::UnsupportedRawExtension {
            path: canonical_raw,
            extension,
        });
    }

    let modified_at = fingerprint_before.modified;
    let age = now
        .duration_since(modified_at)
        .map_err(|_| ProofError::ModifiedInFuture {
            path: canonical_raw.clone(),
        })?;
    let min_age = Duration::from_secs(min_age_seconds);
    if age < min_age {
        return Err(ProofError::RawTooNew {
            path: canonical_raw,
            age_seconds: age.as_secs(),
            min_age_seconds: min_age.as_secs(),
        });
    }

    let modified_unix_seconds = modified_at
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProofError::ModifiedBeforeUnixEpoch {
            path: canonical_raw.clone(),
        })?
        .as_secs();
    let sha256 = hash_file_sha256(&canonical_raw, &mut raw_file)?;
    after_hash();

    let metadata_after = raw_file
        .metadata()
        .map_err(|source| ProofError::ReadMetadata {
            path: canonical_raw.clone(),
            source,
        })?;
    let fingerprint_after = FileFingerprint::from_metadata(&canonical_raw, &metadata_after)?;
    if fingerprint_before != fingerprint_after {
        return Err(ProofError::RawChangedDuringProof {
            path: canonical_raw,
        });
    }

    let final_canonical_raw =
        fs::canonicalize(requested_raw).map_err(|_| ProofError::RawPathChangedDuringProof {
            original: canonical_raw.clone(),
            current: None,
        })?;
    if final_canonical_raw != canonical_raw {
        return Err(ProofError::RawPathChangedDuringProof {
            original: canonical_raw,
            current: Some(final_canonical_raw),
        });
    }

    let final_path_metadata =
        fs::metadata(&final_canonical_raw).map_err(|_| ProofError::RawPathChangedDuringProof {
            original: canonical_raw.clone(),
            current: Some(final_canonical_raw.clone()),
        })?;
    let final_path_fingerprint =
        FileFingerprint::from_metadata(&final_canonical_raw, &final_path_metadata)?;
    if fingerprint_after != final_path_fingerprint {
        return Err(ProofError::RawChangedDuringProof {
            path: canonical_raw,
        });
    }

    Ok(NasRawProof {
        canonical_path: canonical_raw,
        relative_path,
        size_bytes: fingerprint_before.len,
        modified_unix_seconds,
        age_seconds: age.as_secs(),
        sha256,
    })
}

fn raw_extension(path: &Path) -> Result<String, ProofError> {
    let Some(extension) = path.extension() else {
        return Err(ProofError::MissingRawExtension {
            path: path.to_path_buf(),
        });
    };

    Ok(extension.to_string_lossy().to_ascii_lowercase())
}

fn hash_file_sha256(path: &Path, file: &mut File) -> Result<String, ProofError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|source| ProofError::ReadRaw {
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileFingerprint {
    len: u64,
    modified: SystemTime,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    ctime: i64,
    #[cfg(unix)]
    ctime_nsec: i64,
}

impl FileFingerprint {
    fn from_metadata(path: &Path, metadata: &Metadata) -> Result<Self, ProofError> {
        let modified = metadata
            .modified()
            .map_err(|source| ProofError::ReadMetadata {
                path: path.to_path_buf(),
                source,
            })?;

        Ok(Self {
            len: metadata.len(),
            modified,
            #[cfg(unix)]
            dev: metadata.dev(),
            #[cfg(unix)]
            ino: metadata.ino(),
            #[cfg(unix)]
            ctime: metadata.ctime(),
            #[cfg(unix)]
            ctime_nsec: metadata.ctime_nsec(),
        })
    }
}

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("failed to canonicalize NAS root {path}: {source}")]
    CanonicalizeNasRoot { path: PathBuf, source: io::Error },
    #[error("failed to canonicalize RAW path {path}: {source}")]
    CanonicalizeRaw { path: PathBuf, source: io::Error },
    #[error("NAS root is not a directory: {path}")]
    NasRootNotDirectory { path: PathBuf },
    #[error("RAW path {raw_path} is outside NAS root {nas_root}")]
    OutsideNasRoot {
        nas_root: PathBuf,
        raw_path: PathBuf,
    },
    #[error("RAW path {path} has no extension")]
    MissingRawExtension { path: PathBuf },
    #[error("unsupported RAW extension for {path}: {extension}")]
    UnsupportedRawExtension { path: PathBuf, extension: String },
    #[error("RAW path is not a regular file: {path}")]
    NotRegularFile { path: PathBuf },
    #[error("failed to read metadata for {path}: {source}")]
    ReadMetadata { path: PathBuf, source: io::Error },
    #[error("RAW file modified time is in the future: {path}")]
    ModifiedInFuture { path: PathBuf },
    #[error("RAW file modified time is before the Unix epoch: {path}")]
    ModifiedBeforeUnixEpoch { path: PathBuf },
    #[error("RAW file is too new: {path} age {age_seconds}s < required {min_age_seconds}s")]
    RawTooNew {
        path: PathBuf,
        age_seconds: u64,
        min_age_seconds: u64,
    },
    #[error("minimum age {requested_days} days is below safety floor {minimum_days} days")]
    MinAgeBelowSafetyFloor {
        requested_days: u64,
        minimum_days: u64,
    },
    #[error("minimum age {requested_seconds}s is below safety floor {minimum_seconds}s")]
    MinAgeSecondsBelowSafetyFloor {
        requested_seconds: u64,
        minimum_seconds: u64,
    },
    #[error("failed to open RAW file {path}: {source}")]
    OpenRaw { path: PathBuf, source: io::Error },
    #[error("failed to read RAW file {path}: {source}")]
    ReadRaw { path: PathBuf, source: io::Error },
    #[error("RAW file changed while proof was being collected: {path}")]
    RawChangedDuringProof { path: PathBuf },
    #[error("RAW path changed while proof was being collected: {original}")]
    RawPathChangedDuringProof {
        original: PathBuf,
        current: Option<PathBuf>,
    },
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use filetime::{FileTime, set_file_mtime};

    use super::{ProofError, prove_nas_raw_with_after_hash_hook};

    const DAY: u64 = 24 * 60 * 60;
    const NOW_SECS: u64 = 1_700_000_000;

    fn fixed_now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(NOW_SECS)
    }

    fn write_file_with_age(
        root: &Path,
        relative_path: &str,
        body: &[u8],
        age_days: u64,
    ) -> PathBuf {
        let path = root.join(relative_path);
        fs::create_dir_all(path.parent().expect("test file should have a parent"))
            .expect("test parent directory should be created");
        fs::write(&path, body).expect("test file should be written");
        let modified_at = fixed_now() - Duration::from_secs(age_days * DAY);
        set_file_mtime(&path, FileTime::from_system_time(modified_at))
            .expect("test mtime should be set");
        path
    }

    #[test]
    fn rejects_raw_content_mutation_after_hashing() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let root = tempdir.path().join("nas");
        fs::create_dir_all(&root).expect("nas root should be created");
        let raw = write_file_with_age(&root, "camera/IMG_0100.dng", b"raw-bytes", 60);

        let error = prove_nas_raw_with_after_hash_hook(&root, &raw, 30, fixed_now(), || {
            OpenOptions::new()
                .append(true)
                .open(&raw)
                .expect("raw should open for mutation")
                .write_all(b"-changed")
                .expect("raw should mutate");
        })
        .expect_err("mutation during proof should fail closed");

        assert!(matches!(error, ProofError::RawChangedDuringProof { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_same_size_raw_rewrite_with_restored_mtime_after_hashing() {
        use std::os::unix::fs::MetadataExt;
        use std::thread;

        fn ctime(path: &Path) -> (i64, i64) {
            let metadata = fs::metadata(path).expect("test metadata should be readable");
            (metadata.ctime(), metadata.ctime_nsec())
        }

        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let root = tempdir.path().join("nas");
        fs::create_dir_all(&root).expect("nas root should be created");
        let raw = write_file_with_age(&root, "camera/IMG_0103.dng", b"raw-bytes", 60);
        let metadata = fs::metadata(&raw).expect("test metadata should be readable");
        let original_mtime =
            FileTime::from_system_time(metadata.modified().expect("test mtime should be readable"));
        let original_len = metadata.len();

        let error = prove_nas_raw_with_after_hash_hook(&root, &raw, 30, fixed_now(), || {
            let before_ctime = ctime(&raw);
            let replacements: [&[u8]; 2] = [b"alt-bytes", b"new-bytes"];

            for replacement in replacements.into_iter().cycle().take(20) {
                assert_eq!(replacement.len() as u64, original_len);
                fs::write(&raw, replacement).expect("raw should be rewritten");
                set_file_mtime(&raw, original_mtime).expect("test mtime should be restored");

                if ctime(&raw) != before_ctime {
                    return;
                }

                thread::sleep(Duration::from_millis(25));
            }

            panic!("test filesystem should update ctime after same-size rewrite");
        })
        .expect_err("same-size mutation with restored mtime should fail closed");

        assert!(matches!(error, ProofError::RawChangedDuringProof { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_requested_path_retarget_after_hashing() {
        use std::os::unix::fs::symlink;

        let root_dir = tempfile::tempdir().expect("root tempdir should be created");
        let outside_dir = tempfile::tempdir().expect("outside tempdir should be created");
        let root = root_dir.path().join("nas");
        fs::create_dir_all(&root).expect("nas root should be created");
        let raw = write_file_with_age(&root, "camera/IMG_0101.dng", b"raw-bytes", 60);
        let outside_raw = write_file_with_age(outside_dir.path(), "IMG_0101.dng", b"other", 60);
        let link = root.join("linked.dng");
        symlink(&raw, &link).expect("test symlink should be created");

        let error = prove_nas_raw_with_after_hash_hook(&root, &link, 30, fixed_now(), || {
            fs::remove_file(&link).expect("test symlink should be removed");
            symlink(&outside_raw, &link).expect("test symlink should be retargeted");
        })
        .expect_err("path retarget during proof should fail closed");

        assert!(matches!(
            error,
            ProofError::RawPathChangedDuringProof { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_canonical_path_replacement_after_hashing() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let root = tempdir.path().join("nas");
        fs::create_dir_all(&root).expect("nas root should be created");
        let raw = write_file_with_age(&root, "camera/IMG_0102.dng", b"raw-bytes", 60);
        let moved = root.join("camera/IMG_0102.old");

        let error = prove_nas_raw_with_after_hash_hook(&root, &raw, 30, fixed_now(), || {
            fs::rename(&raw, &moved).expect("raw should move away");
            fs::write(&raw, b"replacement").expect("replacement should be written");
        })
        .expect_err("canonical path replacement should fail closed");

        assert!(matches!(error, ProofError::RawChangedDuringProof { .. }));
    }
}

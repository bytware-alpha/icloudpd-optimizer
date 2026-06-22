use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use filetime::{FileTime, set_file_mtime};
use icloudpd_raw_compactor::proof::{ProofError, prove_nas_raw};

const DAY: u64 = 24 * 60 * 60;
const NOW_SECS: u64 = 1_700_000_000;

fn fixed_now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(NOW_SECS)
}

fn write_file_with_age(root: &Path, relative_path: &str, body: &[u8], age_days: u64) -> PathBuf {
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
fn rejects_min_age_days_below_safety_floor() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let root = tempdir.path().join("nas");
    fs::create_dir_all(&root).expect("nas root should be created");
    let raw = write_file_with_age(&root, "camera/IMG_0000.dng", b"raw-bytes", 60);

    let error =
        prove_nas_raw(&root, &raw, 0, fixed_now()).expect_err("weak age floor should fail closed");

    assert!(matches!(
        error,
        ProofError::MinAgeBelowSafetyFloor {
            requested_days: 0,
            minimum_days: 30
        }
    ));
}

#[test]
fn proves_old_raw_under_nas_root_with_structured_metadata() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let root = tempdir.path().join("nas");
    fs::create_dir_all(&root).expect("nas root should be created");
    let raw = write_file_with_age(&root, "camera/IMG_0001.dng", b"raw-bytes", 31);

    let proof = prove_nas_raw(&root, &raw, 30, fixed_now()).expect("proof should pass");

    assert_eq!(
        proof.canonical_path,
        fs::canonicalize(&raw).expect("raw should canonicalize")
    );
    assert_eq!(proof.relative_path, PathBuf::from("camera/IMG_0001.dng"));
    assert_eq!(proof.size_bytes, 9);
    assert_eq!(proof.modified_unix_seconds, NOW_SECS - 31 * DAY);
    assert_eq!(proof.age_seconds, 31 * DAY);
}

#[test]
fn accepts_raw_extensions_case_insensitively() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let root = tempdir.path().join("nas");
    fs::create_dir_all(&root).expect("nas root should be created");
    let raw = write_file_with_age(&root, "camera/IMG_0002.CR3", b"raw-bytes", 45);

    let proof = prove_nas_raw(&root, &raw, 30, fixed_now()).expect("proof should pass");

    assert_eq!(proof.relative_path, PathBuf::from("camera/IMG_0002.CR3"));
}

#[test]
fn rejects_raw_files_younger_than_minimum_age() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let root = tempdir.path().join("nas");
    fs::create_dir_all(&root).expect("nas root should be created");
    let raw = write_file_with_age(&root, "camera/IMG_0003.nef", b"raw-bytes", 29);

    let error =
        prove_nas_raw(&root, &raw, 30, fixed_now()).expect_err("too-new raw should fail closed");

    assert!(matches!(
        error,
        ProofError::RawTooNew {
            age_seconds,
            min_age_seconds,
            ..
        } if age_seconds == 29 * DAY && min_age_seconds == 30 * DAY
    ));
}

#[test]
fn rejects_non_raw_extensions() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let root = tempdir.path().join("nas");
    fs::create_dir_all(&root).expect("nas root should be created");
    let raw = write_file_with_age(&root, "camera/IMG_0004.jpg", b"jpeg-bytes", 60);

    let error = prove_nas_raw(&root, &raw, 30, fixed_now())
        .expect_err("non-raw extension should fail closed");

    assert!(matches!(
        error,
        ProofError::UnsupportedRawExtension { extension, .. } if extension == "jpg"
    ));
}

#[test]
fn rejects_canonical_raw_paths_outside_nas_root() {
    let root_dir = tempfile::tempdir().expect("root tempdir should be created");
    let outside_dir = tempfile::tempdir().expect("outside tempdir should be created");
    let root = root_dir.path().join("nas");
    fs::create_dir_all(&root).expect("nas root should be created");
    let raw = write_file_with_age(outside_dir.path(), "IMG_0005.dng", b"raw-bytes", 60);

    let error =
        prove_nas_raw(&root, &raw, 30, fixed_now()).expect_err("outside raw should fail closed");

    assert!(matches!(error, ProofError::OutsideNasRoot { .. }));
}

#[test]
fn rejects_nas_root_that_is_not_a_directory() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let raw = write_file_with_age(tempdir.path(), "IMG_0008.dng", b"raw-bytes", 60);

    let error = prove_nas_raw(&raw, &raw, 30, fixed_now())
        .expect_err("file used as nas root should fail closed");

    assert!(matches!(
        error,
        ProofError::NasRootNotDirectory { path } if path == fs::canonicalize(&raw).expect("raw should canonicalize")
    ));
}

#[cfg(unix)]
#[test]
fn rejects_symlink_escape_outside_nas_root() {
    use std::os::unix::fs::symlink;

    let root_dir = tempfile::tempdir().expect("root tempdir should be created");
    let outside_dir = tempfile::tempdir().expect("outside tempdir should be created");
    let root = root_dir.path().join("nas");
    fs::create_dir_all(&root).expect("nas root should be created");
    let outside_raw = write_file_with_age(outside_dir.path(), "IMG_0006.dng", b"raw-bytes", 60);
    let link_path = root.join("linked.dng");
    symlink(&outside_raw, &link_path).expect("test symlink should be created");

    let error = prove_nas_raw(&root, &link_path, 30, fixed_now())
        .expect_err("symlink escape should fail closed");

    assert!(matches!(error, ProofError::OutsideNasRoot { .. }));
}

#[test]
fn computes_streaming_sha256_for_known_raw_bytes() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let root = tempdir.path().join("nas");
    fs::create_dir_all(&root).expect("nas root should be created");
    let raw = write_file_with_age(&root, "camera/IMG_0007.raw", b"hello\n", 60);

    let proof = prove_nas_raw(&root, &raw, 30, fixed_now()).expect("proof should pass");

    assert_eq!(
        proof.sha256,
        "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
    );
}

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use filetime::{FileTime, set_file_mtime};
use icloudpd_optimizer::manifest::{AssetRecord, Manifest, State};
use icloudpd_optimizer::proof::NasRawProof;
use icloudpd_optimizer::workflow::{
    ConversionResultProof, HeicVerificationProof, SourceAgeProof, discover_raw_asset,
    record_conversion_result, record_heic_verification, record_nas_proof, record_source_age_proof,
};
use predicates::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const DAY: u64 = 24 * 60 * 60;

fn binary() -> Command {
    Command::cargo_bin("icloudpd-optimizer").expect("binary should build")
}

fn missing_tools_json() -> Value {
    json!({
        "tools": [
            {"name": "sips", "present": false},
            {"name": "heif-info", "present": false},
            {"name": "exiftool", "present": false}
        ]
    })
}

#[cfg(unix)]
fn write_executable(path: &std::path::Path) {
    write_executable_with_body(path, "#!/bin/sh\nexit 0\n");
}

#[cfg(unix)]
fn write_executable_with_body(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;

    fs::write(path, body).expect("executable test file should be written");
    let mut permissions = fs::metadata(path)
        .expect("executable test file metadata should be readable")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("executable test file should be executable");
}

#[cfg(unix)]
fn write_fake_required_tools(directory: &std::path::Path) {
    write_executable(&directory.join("sips"));
    write_executable(&directory.join("heif-info"));
    write_executable(&directory.join("exiftool"));
}

fn doctor_json_with_path(path: impl AsRef<std::ffi::OsStr>, cwd: &std::path::Path) -> Value {
    let output = binary()
        .args(["doctor", "--json"])
        .current_dir(cwd)
        .env("PATH", path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    serde_json::from_slice(&output).expect("stdout should be valid JSON")
}

fn write_old_raw(root: &std::path::Path, relative_path: &str, body: &[u8]) -> PathBuf {
    let path = root.join(relative_path);
    fs::create_dir_all(path.parent().expect("test raw should have a parent"))
        .expect("test raw parent should be created");
    fs::write(&path, body).expect("test raw should be written");
    let modified_at = SystemTime::now() - Duration::from_secs(40 * DAY);
    set_file_mtime(&path, FileTime::from_system_time(modified_at))
        .expect("test mtime should be set");
    path
}

fn nas_proof() -> NasRawProof {
    NasRawProof {
        canonical_path: PathBuf::from("/nas/photos/IMG_0001.dng"),
        relative_path: PathBuf::from("photos/IMG_0001.dng"),
        size_bytes: 42,
        modified_unix_seconds: 1_700_000_000,
        age_seconds: 40 * DAY,
        sha256: "raw-sha256".to_string(),
    }
}

fn conversion_proof() -> ConversionResultProof {
    ConversionResultProof {
        heic_path: PathBuf::from("/staging/IMG_0001.heic"),
        heic_sha256: "heic-sha256".to_string(),
        size_bytes: 24,
    }
}

fn heic_proof() -> HeicVerificationProof {
    HeicVerificationProof {
        heic_path: PathBuf::from("/staging/IMG_0001.heic"),
        heic_sha256: "heic-sha256".to_string(),
        size_bytes: 24,
        heif_info_ok: true,
        metadata_copied: true,
    }
}

fn old_source_age_proof() -> SourceAgeProof {
    SourceAgeProof {
        source_captured_unix_seconds: 1_800_000_000 - 40 * DAY,
        verified_at_unix_seconds: 1_800_000_000,
        min_age_seconds: 30 * DAY,
    }
}

fn source_captured_days_ago(days: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_secs();
    (now - days * DAY).to_string()
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn manifest_with_nas_verified(path: &std::path::Path) {
    let mut manifest = Manifest::new();
    discover_raw_asset(
        &mut manifest,
        "asset-1",
        PathBuf::from("/nas/photos/IMG_0001.dng"),
    )
    .expect("asset should be discovered");
    record_nas_proof(&mut manifest, "asset-1", nas_proof()).expect("nas proof should record");
    manifest.save_atomic(path).expect("manifest should save");
}

fn manifest_with_source_age_verified(path: &std::path::Path) {
    let mut manifest = Manifest::load(path).expect("manifest should load");
    record_source_age_proof(&mut manifest, "asset-1", old_source_age_proof())
        .expect("source age proof should record");
    manifest.save_atomic(path).expect("manifest should save");
}

fn manifest_with_conversion_verified(path: &std::path::Path) {
    let mut manifest = Manifest::new();
    discover_raw_asset(
        &mut manifest,
        "asset-1",
        PathBuf::from("/nas/photos/IMG_0001.dng"),
    )
    .expect("asset should be discovered");
    record_nas_proof(&mut manifest, "asset-1", nas_proof()).expect("nas proof should record");
    record_conversion_result(&mut manifest, "asset-1", conversion_proof())
        .expect("conversion should record");
    record_heic_verification(&mut manifest, "asset-1", heic_proof())
        .expect("heic verification should record");
    record_source_age_proof(&mut manifest, "asset-1", old_source_age_proof())
        .expect("source age proof should record");
    manifest.save_atomic(path).expect("manifest should save");
}

fn manifest_with_real_conversion_verified(path: &std::path::Path, heic_path: PathBuf, body: &[u8]) {
    let mut manifest = Manifest::new();
    discover_raw_asset(
        &mut manifest,
        "asset-1",
        PathBuf::from("/nas/photos/IMG_0001.dng"),
    )
    .expect("asset should be discovered");
    record_nas_proof(&mut manifest, "asset-1", nas_proof()).expect("nas proof should record");
    record_conversion_result(
        &mut manifest,
        "asset-1",
        ConversionResultProof {
            heic_path: heic_path.clone(),
            heic_sha256: sha256_hex(body),
            size_bytes: body.len() as u64,
        },
    )
    .expect("conversion should record");
    record_heic_verification(
        &mut manifest,
        "asset-1",
        HeicVerificationProof {
            heic_path,
            heic_sha256: sha256_hex(body),
            size_bytes: body.len() as u64,
            heif_info_ok: true,
            metadata_copied: true,
        },
    )
    .expect("heic verification should record");
    record_source_age_proof(&mut manifest, "asset-1", old_source_age_proof())
        .expect("source age proof should record");
    manifest.save_atomic(path).expect("manifest should save");
}

fn manifest_with_real_delete_approval(tempdir: &std::path::Path) -> (PathBuf, PathBuf, u64) {
    let tempdir = fs::canonicalize(tempdir).expect("tempdir should canonicalize");
    let manifest_path = tempdir.join("manifest.json");
    let nas_root = tempdir.join("nas");
    fs::create_dir_all(&nas_root).expect("nas root should be created");
    let raw_path = write_old_raw(&nas_root, "camera/IMG_0001.dng", b"raw-bytes");
    let source_captured = source_captured_days_ago(40);
    let manifest_arg = manifest_path
        .to_str()
        .expect("manifest path should be utf8");

    binary()
        .args([
            "workflow",
            "nas-verified",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--raw-path",
            raw_path.to_str().expect("raw path should be utf8"),
            "--nas-root",
            nas_root.to_str().expect("nas root should be utf8"),
            "--min-age-days",
            "30",
            "--source-captured-unix-seconds",
            &source_captured,
        ])
        .assert()
        .success();
    binary()
        .args([
            "workflow",
            "conversion-recorded",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--heic-path",
            "/staging/IMG_0001.heic",
            "--heic-sha256",
            "heic-sha256",
            "--size-bytes",
            "24",
        ])
        .assert()
        .success();
    binary()
        .args([
            "workflow",
            "heic-verified",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--heic-path",
            "/staging/IMG_0001.heic",
            "--heic-sha256",
            "heic-sha256",
            "--size-bytes",
            "24",
            "--heif-info-ok",
            "--metadata-copied",
        ])
        .assert()
        .success();
    binary()
        .args([
            "workflow",
            "upload-verified",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--uploaded-heic-asset-id",
            "icloud-heic-asset-1",
            "--uploaded-heic-sha256",
            "heic-sha256",
            "--uploaded-heic-path",
            "/staging/IMG_0001.heic",
        ])
        .assert()
        .success();
    binary()
        .args([
            "workflow",
            "mark-delete-eligible",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
        ])
        .assert()
        .success();
    binary()
        .args([
            "workflow",
            "approve-delete",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--operator",
            "operator",
        ])
        .assert()
        .success();

    (
        manifest_path,
        raw_path,
        source_captured
            .parse::<u64>()
            .expect("source captured should parse"),
    )
}

#[test]
fn version_and_help_succeed_through_parser() {
    binary()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("icloudpd-optimizer"));

    binary()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("manifest"))
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("workflow"));

    binary()
        .args(["workflow", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("conversion-recorded"))
        .stdout(predicate::str::contains("heic-verified"));
}

#[test]
fn manifest_show_prints_existing_manifest_as_pretty_json_without_mutating_it() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let raw_path = PathBuf::from("/photos/raw/asset-1.dng");
    let mut manifest = Manifest::new();
    manifest.upsert(AssetRecord::new("asset-1", raw_path));
    manifest
        .save_atomic(&manifest_path)
        .expect("manifest should save");
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    let output = binary()
        .args(["manifest", "show", "--manifest"])
        .arg(&manifest_path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);

    let shown: Value = serde_json::from_slice(&output).expect("stdout should be valid JSON");
    assert!(output.windows(2).any(|window| window == b"\n "));
    assert_eq!(shown["records"][0]["asset_id"], "asset-1");
    assert_eq!(shown["records"][0]["raw_path"], "/photos/raw/asset-1.dng");
    assert_eq!(shown["records"][0]["state"], "discovered");
}

#[test]
fn manifest_show_missing_manifest_fails_without_creating_it() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("missing.json");

    binary()
        .args(["manifest", "show", "--manifest"])
        .arg(&manifest_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to load manifest"));

    assert!(!manifest_path.exists());
}

#[test]
fn manifest_show_bad_manifest_fails_without_mutating_it() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("bad.json");
    fs::write(&manifest_path, "{not-json").expect("bad manifest should be written");
    let before = fs::read_to_string(&manifest_path).expect("bad manifest should be readable");

    binary()
        .args(["manifest", "show", "--manifest"])
        .arg(&manifest_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to load manifest"));

    let after = fs::read_to_string(&manifest_path).expect("bad manifest should remain readable");
    assert_eq!(after, before);
}

#[test]
fn doctor_json_reports_required_tools_missing_under_empty_path() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");

    let shown = doctor_json_with_path(tempdir.path(), tempdir.path());

    assert_eq!(shown, missing_tools_json());
}

#[cfg(unix)]
#[test]
fn doctor_json_reports_heif_info_as_required() {
    let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
    let cwd = tempfile::tempdir().expect("cwd tempdir should be created");
    write_executable(&tool_dir.path().join("sips"));
    write_executable(&tool_dir.path().join("exiftool"));

    let shown = doctor_json_with_path(tool_dir.path(), cwd.path());

    assert_eq!(
        shown,
        json!({
            "tools": [
                {"name": "sips", "present": true},
                {"name": "heif-info", "present": false},
                {"name": "exiftool", "present": true}
            ]
        })
    );
}

#[cfg(unix)]
#[test]
fn doctor_json_ignores_empty_path_when_cwd_contains_matching_executables() {
    let cwd = tempfile::tempdir().expect("tempdir should be created");
    write_fake_required_tools(cwd.path());

    let shown = doctor_json_with_path("", cwd.path());

    assert_eq!(shown, missing_tools_json());
}

#[cfg(unix)]
#[test]
fn doctor_json_ignores_leading_trailing_and_doubled_empty_path_components() {
    let cwd = tempfile::tempdir().expect("tempdir should be created");
    let empty_dir = tempfile::tempdir().expect("empty PATH dir should be created");
    let other_empty_dir = tempfile::tempdir().expect("other empty PATH dir should be created");
    write_fake_required_tools(cwd.path());

    let cases = [
        format!(":{}", empty_dir.path().display()),
        format!("{}:", empty_dir.path().display()),
        format!(
            "{}::{}",
            empty_dir.path().display(),
            other_empty_dir.path().display()
        ),
    ];

    for path in cases {
        let shown = doctor_json_with_path(path, cwd.path());
        assert_eq!(shown, missing_tools_json());
    }
}

#[test]
fn workflow_nas_verified_creates_manifest_and_persists_proof_atomically() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let nas_root = tempdir.path().join("nas");
    fs::create_dir_all(&nas_root).expect("nas root should be created");
    let raw_path = write_old_raw(&nas_root, "camera/IMG_0001.dng", b"raw-bytes");
    let source_captured = source_captured_days_ago(40);

    binary()
        .args([
            "workflow",
            "nas-verified",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--raw-path",
            raw_path.to_str().expect("raw path should be utf8"),
            "--nas-root",
            nas_root.to_str().expect("nas root should be utf8"),
            "--min-age-days",
            "30",
            "--source-captured-unix-seconds",
            &source_captured,
        ])
        .assert()
        .success();

    let manifest = Manifest::load(&manifest_path).expect("manifest should load");
    let record = manifest.get("asset-1").expect("asset should exist");
    assert_eq!(record.state, State::NasVerified);
    assert_eq!(
        record.raw_path,
        fs::canonicalize(&raw_path).expect("raw path should canonicalize")
    );
    assert_eq!(
        record.proofs["nas"]["sha256"],
        "48c2a3cc55bca79baff97910b96c74b906fc5d893a1bc5ccd14d629d3f3ef715"
    );
    assert_eq!(
        record.proofs["source_age"]["source_captured_unix_seconds"],
        source_captured
            .parse::<u64>()
            .expect("source captured should parse")
    );
    assert!(
        fs::read_dir(tempdir.path())
            .expect("tempdir should be readable")
            .all(|entry| !entry
                .expect("entry should be readable")
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp"))
    );
}

#[test]
fn workflow_nas_verified_rejects_min_age_below_floor_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let nas_root = tempdir.path().join("nas");
    fs::create_dir_all(&nas_root).expect("nas root should be created");
    let raw_path = write_old_raw(&nas_root, "camera/IMG_0001.dng", b"raw-bytes");
    let source_captured = source_captured_days_ago(40);

    binary()
        .args([
            "workflow",
            "nas-verified",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--raw-path",
            raw_path.to_str().expect("raw path should be utf8"),
            "--nas-root",
            nas_root.to_str().expect("nas root should be utf8"),
            "--min-age-days",
            "0",
            "--source-captured-unix-seconds",
            &source_captured,
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("minimum age"))
        .stderr(predicate::str::contains("30"));

    assert!(!manifest_path.exists());
}

#[test]
fn workflow_conversion_result_and_heic_verified_commands_complete_conversion_gate() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    manifest_with_nas_verified(&manifest_path);
    manifest_with_source_age_verified(&manifest_path);
    let manifest_arg = manifest_path
        .to_str()
        .expect("manifest path should be utf8");

    binary()
        .args([
            "workflow",
            "conversion-recorded",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--heic-path",
            "/staging/IMG_0001.heic",
            "--heic-sha256",
            "heic-sha256",
            "--size-bytes",
            "24",
        ])
        .assert()
        .success();
    binary()
        .args([
            "workflow",
            "heic-verified",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--heic-path",
            "/staging/IMG_0001.heic",
            "--heic-sha256",
            "heic-sha256",
            "--size-bytes",
            "24",
            "--heif-info-ok",
            "--metadata-copied",
        ])
        .assert()
        .success();

    let manifest = Manifest::load(&manifest_path).expect("manifest should load");
    let record = manifest.get("asset-1").expect("asset should exist");
    assert_eq!(record.state, State::ConversionVerified);
    assert_eq!(record.proofs["conversion"]["heic_sha256"], "heic-sha256");
    assert_eq!(record.proofs["heic"]["heic_path"], "/staging/IMG_0001.heic");
}

#[test]
fn workflow_heic_verified_mismatch_fails_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    manifest_with_nas_verified(&manifest_path);
    manifest_with_source_age_verified(&manifest_path);
    let manifest_arg = manifest_path
        .to_str()
        .expect("manifest path should be utf8");
    binary()
        .args([
            "workflow",
            "conversion-recorded",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--heic-path",
            "/staging/IMG_0001.heic",
            "--heic-sha256",
            "heic-sha256",
            "--size-bytes",
            "24",
        ])
        .assert()
        .success();
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "heic-verified",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--heic-path",
            "/staging/IMG_0001.heic",
            "--heic-sha256",
            "other-heic-sha256",
            "--size-bytes",
            "24",
            "--heif-info-ok",
            "--metadata-copied",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("mismatch"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);
}

#[test]
fn workflow_heic_verified_requires_explicit_boolean_proofs_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    manifest_with_nas_verified(&manifest_path);
    let manifest_arg = manifest_path
        .to_str()
        .expect("manifest path should be utf8");
    binary()
        .args([
            "workflow",
            "conversion-recorded",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--heic-path",
            "/staging/IMG_0001.heic",
            "--heic-sha256",
            "heic-sha256",
            "--size-bytes",
            "24",
        ])
        .assert()
        .success();
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "heic-verified",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--heic-path",
            "/staging/IMG_0001.heic",
            "--heic-sha256",
            "heic-sha256",
            "--size-bytes",
            "24",
            "--heif-info-ok",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("metadata_copied"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);
}

#[test]
fn workflow_upload_verified_records_uploaded_heic_identity() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    manifest_with_conversion_verified(&manifest_path);

    binary()
        .args([
            "workflow",
            "upload-verified",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--uploaded-heic-asset-id",
            "icloud-heic-asset-1",
            "--uploaded-heic-sha256",
            "heic-sha256",
            "--uploaded-heic-path",
            "/staging/IMG_0001.heic",
        ])
        .assert()
        .success();

    let manifest = Manifest::load(&manifest_path).expect("manifest should load");
    let record = manifest.get("asset-1").expect("asset should exist");
    assert_eq!(record.state, State::UploadVerified);
    assert_eq!(
        record.proofs["upload"]["uploaded_heic_asset_id"],
        "icloud-heic-asset-1"
    );
    assert_eq!(
        record.proofs["upload"]["uploaded_heic_sha256"],
        "heic-sha256"
    );
}

#[test]
fn workflow_upload_heic_help_shows_session_not_python_credentials() {
    binary()
        .args(["workflow", "upload-heic", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--session"))
        .stdout(predicate::str::contains("--python").not())
        .stdout(predicate::str::contains("--apple-id").not())
        .stdout(predicate::str::contains("--cookie-directory").not())
        .stdout(predicate::str::contains("--accept-terms").not())
        .stdout(predicate::str::contains("--album").not());
}

#[test]
fn workflow_upload_heic_session_failure_does_not_mutate_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let session_path = tempdir.path().join("session.json");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    fs::write(
        &session_path,
        serde_json::json!({
            "dsid": "123456789",
            "upload_url": "https://evil.example/uploadimagews",
            "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "token"}]
        })
        .to_string(),
    )
    .expect("session should be written");
    manifest_with_real_conversion_verified(&manifest_path, heic_path, b"heic-bytes");
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "upload-heic",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--session",
            session_path.to_str().expect("session path should be utf8"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid upload session"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should be readable");
    assert_eq!(after, before);
}

#[test]
fn workflow_upload_heic_session_error_does_not_echo_cookie_value() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let session_path = tempdir.path().join("session.json");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    fs::write(
        &session_path,
        serde_json::json!({
            "dsid": "123456789",
            "upload_url": "https://upload.icloud.com/uploadimagews",
            "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "secret-cookie-token\n"}]
        })
        .to_string(),
    )
    .expect("session should be written");
    manifest_with_real_conversion_verified(&manifest_path, heic_path, b"heic-bytes");

    binary()
        .args([
            "workflow",
            "upload-heic",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--session",
            session_path.to_str().expect("session path should be utf8"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid upload session"))
        .stderr(predicate::str::contains("secret-cookie-token").not());
}

#[test]
fn workflow_upload_heic_valid_session_fails_closed_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let session_path = tempdir.path().join("session.json");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    fs::write(
        &session_path,
        serde_json::json!({
            "dsid": "123456789",
            "upload_url": "https://p140-uploadimagews.icloud.com:443",
            "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "token"}]
        })
        .to_string(),
    )
    .expect("session should be written");
    manifest_with_real_conversion_verified(&manifest_path, heic_path, b"heic-bytes");
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "upload-heic",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--session",
            session_path.to_str().expect("session path should be utf8"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "iCloud Photos upload is not enabled",
        ));

    let after = fs::read_to_string(&manifest_path).expect("manifest should be readable");
    assert_eq!(after, before);
}

#[test]
fn workflow_upload_heic_rechecks_heic_before_loading_session() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    manifest_with_real_conversion_verified(&manifest_path, heic_path.clone(), b"heic-bytes");
    fs::write(&heic_path, b"HEIC-BYTES").expect("heic should be changed");
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");
    let missing_session = tempdir.path().join("missing-session.json");

    binary()
        .args([
            "workflow",
            "upload-heic",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--session",
            missing_session
                .to_str()
                .expect("session path should be utf8"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("HEIC SHA-256 mismatch"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should be readable");
    assert_eq!(after, before);
}

#[test]
fn workflow_upload_verified_mismatch_fails_without_mutating_manifest() {
    let cases = [
        (
            "other-heic-sha256",
            Some("/staging/IMG_0001.heic"),
            "uploaded_heic_sha256",
            "mismatch",
        ),
        (
            "heic-sha256",
            Some("/other/IMG_0001.heic"),
            "uploaded_heic_path",
            "mismatch",
        ),
        ("heic-sha256", None, "uploaded_heic_path", "required"),
    ];

    for (uploaded_heic_sha256, uploaded_heic_path, expected_field, expected_message) in cases {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let manifest_path = tempdir.path().join("manifest.json");
        manifest_with_conversion_verified(&manifest_path);
        let manifest_arg = manifest_path
            .to_str()
            .expect("manifest path should be utf8");
        let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");
        let mut command = binary();
        command.args([
            "workflow",
            "upload-verified",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--uploaded-heic-asset-id",
            "icloud-heic-asset-1",
            "--uploaded-heic-sha256",
            uploaded_heic_sha256,
        ]);
        if let Some(path) = uploaded_heic_path {
            command.args(["--uploaded-heic-path", path]);
        }

        command
            .assert()
            .failure()
            .stderr(predicate::str::contains(expected_message))
            .stderr(predicate::str::contains(expected_field));

        let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
        assert_eq!(after, before);
    }
}

#[test]
fn workflow_mark_delete_eligible_requires_source_age_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    manifest_with_nas_verified(&manifest_path);
    let manifest_arg = manifest_path
        .to_str()
        .expect("manifest path should be utf8");

    binary()
        .args([
            "workflow",
            "conversion-recorded",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--heic-path",
            "/staging/IMG_0001.heic",
            "--heic-sha256",
            "heic-sha256",
            "--size-bytes",
            "24",
        ])
        .assert()
        .success();
    binary()
        .args([
            "workflow",
            "heic-verified",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--heic-path",
            "/staging/IMG_0001.heic",
            "--heic-sha256",
            "heic-sha256",
            "--size-bytes",
            "24",
            "--heif-info-ok",
            "--metadata-copied",
        ])
        .assert()
        .success();
    binary()
        .args([
            "workflow",
            "upload-verified",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--uploaded-heic-asset-id",
            "icloud-heic-asset-1",
            "--uploaded-heic-sha256",
            "heic-sha256",
            "--uploaded-heic-path",
            "/staging/IMG_0001.heic",
        ])
        .assert()
        .success();
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "mark-delete-eligible",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("source_age"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);
}

#[test]
fn workflow_mark_delete_eligible_rejects_too_new_source_age_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let nas_root = tempdir.path().join("nas");
    fs::create_dir_all(&nas_root).expect("nas root should be created");
    let raw_path = write_old_raw(&nas_root, "camera/IMG_0001.dng", b"raw-bytes");
    let source_captured = source_captured_days_ago(10);
    let manifest_arg = manifest_path
        .to_str()
        .expect("manifest path should be utf8");

    binary()
        .args([
            "workflow",
            "nas-verified",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--raw-path",
            raw_path.to_str().expect("raw path should be utf8"),
            "--nas-root",
            nas_root.to_str().expect("nas root should be utf8"),
            "--min-age-days",
            "30",
            "--source-captured-unix-seconds",
            &source_captured,
        ])
        .assert()
        .success();
    binary()
        .args([
            "workflow",
            "conversion-recorded",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--heic-path",
            "/staging/IMG_0001.heic",
            "--heic-sha256",
            "heic-sha256",
            "--size-bytes",
            "24",
        ])
        .assert()
        .success();
    binary()
        .args([
            "workflow",
            "heic-verified",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--heic-path",
            "/staging/IMG_0001.heic",
            "--heic-sha256",
            "heic-sha256",
            "--size-bytes",
            "24",
            "--heif-info-ok",
            "--metadata-copied",
        ])
        .assert()
        .success();
    binary()
        .args([
            "workflow",
            "upload-verified",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--uploaded-heic-asset-id",
            "icloud-heic-asset-1",
            "--uploaded-heic-sha256",
            "heic-sha256",
            "--uploaded-heic-path",
            "/staging/IMG_0001.heic",
        ])
        .assert()
        .success();
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "mark-delete-eligible",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("source age"))
        .stderr(predicate::str::contains("too new"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);
}

#[test]
fn workflow_invalid_write_command_fails_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    manifest_with_conversion_verified(&manifest_path);
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "mark-delete-eligible",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("upload"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);
}

#[test]
fn workflow_failed_command_records_failure_state() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    manifest_with_nas_verified(&manifest_path);

    binary()
        .args([
            "workflow",
            "failed",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--stage",
            "conversion",
            "--message",
            "vips exited 1",
        ])
        .assert()
        .success();

    let manifest = Manifest::load(&manifest_path).expect("manifest should load");
    let record = manifest.get("asset-1").expect("asset should exist");
    assert_eq!(record.state, State::Failed);
    assert_eq!(record.failures[0].stage, "conversion");
    assert_eq!(record.failures[0].message, "vips exited 1");
}

#[test]
fn workflow_delete_plan_prints_json_and_does_not_mutate_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let (manifest_path, raw_path, source_captured) =
        manifest_with_real_delete_approval(tempdir.path());
    let manifest_arg = manifest_path
        .to_str()
        .expect("manifest path should be utf8");
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    let output = binary()
        .args([
            "workflow",
            "delete-plan",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let shown: Value = serde_json::from_slice(&output).expect("stdout should be valid JSON");
    assert_eq!(shown["asset_id"], "asset-1");
    assert_eq!(shown["raw_path"], raw_path.to_string_lossy().as_ref());
    assert_eq!(
        shown["proofs"]["upload"]["uploaded_heic_asset_id"],
        "icloud-heic-asset-1"
    );
    assert_eq!(
        shown["proofs"]["source_age"]["source_captured_unix_seconds"],
        source_captured
    );
    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);
}

#[test]
fn workflow_delete_plan_rejects_changed_nas_bytes_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let (manifest_path, raw_path, _) = manifest_with_real_delete_approval(tempdir.path());
    let manifest = Manifest::load(&manifest_path).expect("manifest should load");
    let stored_modified =
        manifest.get("asset-1").expect("asset should exist").proofs["nas"]["modified_unix_seconds"]
            .as_u64()
            .expect("stored mtime should be a u64");
    fs::write(&raw_path, b"new-bytes").expect("raw bytes should mutate");
    set_file_mtime(
        &raw_path,
        FileTime::from_unix_time(stored_modified as i64, 0),
    )
    .expect("raw mtime should be restored");
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "delete-plan",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("sha256"))
        .stderr(predicate::str::contains("mismatch"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);
}

#[test]
fn workflow_delete_plan_rejects_malformed_nas_relative_path_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let (manifest_path, _, _) = manifest_with_real_delete_approval(tempdir.path());
    let mut manifest = Manifest::load(&manifest_path).expect("manifest should load");
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    record
        .proofs
        .get_mut("nas")
        .expect("nas proof should exist")["relative_path"] = json!("other/IMG_0001.dng");
    manifest.upsert(record);
    manifest
        .save_atomic(&manifest_path)
        .expect("manifest should save");
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "delete-plan",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("relative_path"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);
}

#[test]
fn workflow_delete_plan_rejects_forged_source_age_minimum_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let (manifest_path, _, _) = manifest_with_real_delete_approval(tempdir.path());
    let mut manifest = Manifest::load(&manifest_path).expect("manifest should load");
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    record
        .proofs
        .get_mut("source_age")
        .expect("source_age proof should exist")["min_age_seconds"] = json!(0);
    manifest.upsert(record);
    manifest
        .save_atomic(&manifest_path)
        .expect("manifest should save");
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "delete-plan",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("minimum age"))
        .stderr(predicate::str::contains("30"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);
}

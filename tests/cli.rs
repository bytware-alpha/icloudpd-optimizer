use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use filetime::{FileTime, set_file_mtime};
use icloudpd_optimizer::conversion_backend::{
    TargetPlatform, backend_report_for_target, required_tools_for_target,
};
use icloudpd_optimizer::manifest::{AssetRecord, Manifest, State};
use icloudpd_optimizer::proof::NasRawProof;
use icloudpd_optimizer::workflow::{
    ConversionPerformanceInput, ConversionResultProof, HeicVerificationProof, SourceAgeProof,
    discover_raw_asset, record_conversion_performance, record_conversion_result,
    record_heic_verification, record_nas_proof, record_source_age_proof,
};
use predicates::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const DAY: u64 = 24 * 60 * 60;

fn binary() -> Command {
    Command::cargo_bin("icloudpd-optimizer").expect("binary should build")
}

fn current_target_platform() -> TargetPlatform {
    TargetPlatform::new(std::env::consts::OS, std::env::consts::ARCH)
}

fn doctor_json_with_tool_presence(present: impl Fn(&str) -> bool) -> Value {
    let target = current_target_platform();
    let backend = backend_report_for_target(target);
    let required_tools: Vec<Value> = required_tools_for_target(target)
        .iter()
        .copied()
        .map(|name| json!({"name": name, "present": present(name)}))
        .collect();

    json!({
        "platform": {
            "os": target.os,
            "arch": target.arch
        },
        "conversion_backend": {
            "name": backend.name,
            "workflow_convert_supported": backend.workflow_convert_supported,
            "reason": backend.reason
        },
        "required_tools": required_tools
    })
}

fn missing_required_tools_json() -> Value {
    doctor_json_with_tool_presence(|_| false)
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
    write_executable(&directory.join("magick"));
    write_executable(&directory.join("exiftool"));
}

#[cfg(unix)]
fn write_fake_conversion_tools(directory: &std::path::Path) {
    write_executable_with_body(
        &directory.join("sips"),
        r#"#!/bin/sh
if [ "${FAIL_SIPS:-}" = "1" ]; then
  exit 42
fi
out=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "--out" ]; then
    out="$arg"
  fi
  previous="$arg"
done
if [ -z "$out" ]; then
  exit 43
fi
if [ "${MISSING_SIPS_OUTPUT:-}" = "1" ]; then
  exit 0
elif [ "${EMPTY_SIPS_OUTPUT:-}" = "1" ]; then
  : > "$out"
else
  printf 'heic-bytes-from-fake-sips' > "$out"
fi
"#,
    );
    write_executable_with_body(
        &directory.join("exiftool"),
        r#"#!/bin/sh
if [ "$1" = "-j" ]; then
  printf '[{"PreviewImage":"(Binary data 20 bytes, use -b option to extract)"}]\n'
  exit 0
fi
if [ "$1" = "-b" ] && [ "$2" = "-PreviewImage" ]; then
  printf 'embedded-preview-jpeg'
  exit 0
fi
if [ "$1" = "-TagsFromFile" ] && [ "$3" = "-Orientation#" ]; then
  if [ "${FAIL_PREVIEW_ORIENTATION:-}" = "1" ]; then
    exit 45
  fi
  exit 0
fi
if [ "$1" = "-TagsFromFile" ] && [ "${FAIL_EXIFTOOL:-}" = "1" ]; then
  exit 44
fi
exit 0
"#,
    );
    write_executable_with_body(
        &directory.join("magick"),
        r#"#!/bin/sh
if [ "$2" = "-auto-orient" ]; then
  printf 'oriented-preview-jpeg'
  exit 0
fi
exit 0
"#,
    );
    write_executable_with_body(
        &directory.join("heif-enc"),
        r#"#!/bin/sh
if [ "${FAIL_HEIF_ENC:-}" = "1" ]; then
  exit 45
fi
out=""
previous=""
for arg in "$@"; do
  if [ "$previous" = "-o" ]; then
    out="$arg"
  fi
  previous="$arg"
done
if [ -z "$out" ]; then
  exit 46
fi
printf 'heic-bytes-from-fake-heif-enc' > "$out"
"#,
    );
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

fn conversion_performance_input() -> ConversionPerformanceInput {
    ConversionPerformanceInput {
        measured_at_unix_seconds: 1_800_000_100,
        conversion_tool: "magick".to_string(),
        conversion_tool_version: Some("7.1.1-41".to_string()),
        heic_quality: 90,
        convert_wall_time_millis: 1_250,
        total_wall_time_millis: 1_500,
        user_cpu_time_millis: Some(1_100),
        system_cpu_time_millis: Some(90),
        peak_rss_kib: Some(256_000),
        conversion_command_timings: Vec::new(),
    }
}

fn heic_proof() -> HeicVerificationProof {
    HeicVerificationProof {
        heic_path: PathBuf::from("/staging/IMG_0001.heic"),
        heic_sha256: "heic-sha256".to_string(),
        size_bytes: 24,
        heif_info_ok: true,
        metadata_copied: true,
        visual_content_ok: true,
        visual_match_ok: true,
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

fn record_conversion_performance_cli(manifest_arg: &str) {
    binary()
        .args([
            "workflow",
            "conversion-performance",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--conversion-tool",
            "magick",
            "--conversion-tool-version",
            "7.1.1-41",
            "--heic-quality",
            "90",
            "--convert-wall-time-millis",
            "1250",
            "--total-wall-time-millis",
            "1500",
            "--user-cpu-time-millis",
            "1100",
            "--system-cpu-time-millis",
            "90",
            "--peak-rss-kib",
            "256000",
        ])
        .assert()
        .success();
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

fn manifest_with_real_nas_verified(path: &std::path::Path, raw_path: PathBuf, nas_root: PathBuf) {
    let mut manifest = Manifest::new();
    discover_raw_asset(&mut manifest, "asset-1", raw_path.clone())
        .expect("asset should be discovered");
    let raw = fs::read(&raw_path).expect("raw should be readable");
    record_nas_proof(
        &mut manifest,
        "asset-1",
        NasRawProof {
            canonical_path: raw_path.clone(),
            relative_path: raw_path
                .strip_prefix(&nas_root)
                .expect("raw should be under nas root")
                .to_path_buf(),
            size_bytes: raw.len() as u64,
            modified_unix_seconds: 1_700_000_000,
            age_seconds: 40 * DAY,
            sha256: sha256_hex(&raw),
        },
    )
    .expect("nas proof should record");
    manifest.save_atomic(path).expect("manifest should save");
}

fn manifest_with_real_nas_verified_assets(
    path: &std::path::Path,
    nas_root: &std::path::Path,
    assets: &[(&str, PathBuf)],
) {
    let mut manifest = Manifest::new();
    for (asset_id, raw_path) in assets {
        discover_raw_asset(&mut manifest, *asset_id, raw_path.clone())
            .expect("asset should be discovered");
        let raw = fs::read(raw_path).expect("raw should be readable");
        record_nas_proof(
            &mut manifest,
            asset_id,
            NasRawProof {
                canonical_path: raw_path.clone(),
                relative_path: raw_path
                    .strip_prefix(nas_root)
                    .expect("raw should be under nas root")
                    .to_path_buf(),
                size_bytes: raw.len() as u64,
                modified_unix_seconds: 1_700_000_000,
                age_seconds: 40 * DAY,
                sha256: sha256_hex(&raw),
            },
        )
        .expect("nas proof should record");
    }
    manifest.save_atomic(path).expect("manifest should save");
}

fn manifest_with_source_age_verified(path: &std::path::Path) {
    let mut manifest = Manifest::load(path).expect("manifest should load");
    record_source_age_proof(&mut manifest, "asset-1", old_source_age_proof())
        .expect("source age proof should record");
    manifest.save_atomic(path).expect("manifest should save");
}

fn record_original_asset_cli(manifest_arg: &str, size_bytes: &str, matched_raw_sha256: &str) {
    binary()
        .args([
            "workflow",
            "original-asset-verified",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--record-name",
            "original-record-1",
            "--record-change-tag",
            "old-change-tag",
            "--record-type",
            "CPLAsset",
            "--filename",
            "IMG_0001.dng",
            "--size-bytes",
            size_bytes,
            "--matched-raw-sha256",
            matched_raw_sha256,
        ])
        .assert()
        .success();
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
    record_conversion_performance(&mut manifest, "asset-1", conversion_performance_input())
        .expect("conversion performance should record");
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
    record_conversion_performance(&mut manifest, "asset-1", conversion_performance_input())
        .expect("conversion performance should record");
    record_heic_verification(
        &mut manifest,
        "asset-1",
        HeicVerificationProof {
            heic_path,
            heic_sha256: sha256_hex(body),
            size_bytes: body.len() as u64,
            heif_info_ok: true,
            metadata_copied: true,
            visual_content_ok: true,
            visual_match_ok: true,
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
    let heic_path = tempdir.join("staging").join("IMG_0001.heic");
    let download_path = tempdir.join("PrimarySync").join("IMG_0001.HEIC");
    fs::create_dir_all(heic_path.parent().expect("heic path should have parent"))
        .expect("heic parent should be created");
    fs::create_dir_all(
        download_path
            .parent()
            .expect("download path should have parent"),
    )
    .expect("download parent should be created");
    fs::write(&heic_path, b"heic-bytes").expect("verified HEIC should be written");
    let heic_sha256 = sha256_hex(b"heic-bytes");
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
            heic_path.to_str().expect("heic path should be utf8"),
            "--heic-sha256",
            &heic_sha256,
            "--size-bytes",
            "10",
        ])
        .assert()
        .success();
    record_conversion_performance_cli(manifest_arg);
    binary()
        .args([
            "workflow",
            "heic-verified",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--heic-path",
            heic_path.to_str().expect("heic path should be utf8"),
            "--heic-sha256",
            &heic_sha256,
            "--size-bytes",
            "10",
            "--heif-info-ok",
            "--metadata-copied",
            "--visual-content-ok",
            "--visual-match-ok",
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
            &heic_sha256,
            "--uploaded-heic-path",
            heic_path.to_str().expect("heic path should be utf8"),
        ])
        .assert()
        .success();
    binary()
        .args([
            "workflow",
            "icloudpd-local-mirror",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--download-path",
            download_path
                .to_str()
                .expect("download path should be utf8"),
        ])
        .assert()
        .success();
    let manifest = Manifest::load(&manifest_path).expect("manifest should load");
    let nas = manifest.get("asset-1").expect("asset should exist").proofs["nas"].clone();
    record_original_asset_cli(
        manifest_arg,
        &nas["size_bytes"]
            .as_u64()
            .expect("NAS size should be u64")
            .to_string(),
        nas["sha256"].as_str().expect("NAS sha should be a string"),
    );
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
fn workflow_original_asset_verified_records_original_identity() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    manifest_with_nas_verified(&manifest_path);
    let manifest_arg = manifest_path
        .to_str()
        .expect("manifest path should be utf8");

    record_original_asset_cli(manifest_arg, "42", "raw-sha256");

    let manifest = Manifest::load(&manifest_path).expect("manifest should load");
    let record = manifest.get("asset-1").expect("asset should exist");
    assert_eq!(
        record.proofs["original_asset"]["record_name"],
        "original-record-1"
    );
    assert_eq!(
        record.proofs["original_asset"]["record_change_tag"],
        "old-change-tag"
    );
    assert_eq!(record.proofs["original_asset"]["record_type"], "CPLAsset");
    assert_eq!(record.proofs["original_asset"]["filename"], "IMG_0001.dng");
    assert_eq!(record.proofs["original_asset"]["size_bytes"], 42);
    assert_eq!(
        record.proofs["original_asset"]["matched_raw_sha256"],
        "raw-sha256"
    );
}

#[test]
fn workflow_original_asset_verified_rejects_mismatched_nas_facts_without_mutating_manifest() {
    for (size_bytes, matched_raw_sha256, expected_field) in [
        ("41", "raw-sha256", "size_bytes"),
        ("42", "other-raw-sha256", "matched_raw_sha256"),
    ] {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let manifest_path = tempdir.path().join("manifest.json");
        manifest_with_nas_verified(&manifest_path);
        let manifest_arg = manifest_path
            .to_str()
            .expect("manifest path should be utf8");
        let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

        binary()
            .args([
                "workflow",
                "original-asset-verified",
                "--manifest",
                manifest_arg,
                "--asset-id",
                "asset-1",
                "--record-name",
                "original-record-1",
                "--record-change-tag",
                "old-change-tag",
                "--record-type",
                "CPLAsset",
                "--filename",
                "IMG_0001.dng",
                "--size-bytes",
                size_bytes,
                "--matched-raw-sha256",
                matched_raw_sha256,
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains(expected_field))
            .stderr(predicate::str::contains("mismatch"));

        let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
        assert_eq!(after, before);
    }
}

#[test]
fn workflow_original_asset_verified_requires_nas_proof_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let mut manifest = Manifest::new();
    discover_raw_asset(
        &mut manifest,
        "asset-1",
        PathBuf::from("/nas/photos/IMG_0001.dng"),
    )
    .expect("asset should be discovered");
    manifest
        .save_atomic(&manifest_path)
        .expect("manifest should save");
    let manifest_arg = manifest_path
        .to_str()
        .expect("manifest path should be utf8");
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "original-asset-verified",
            "--manifest",
            manifest_arg,
            "--asset-id",
            "asset-1",
            "--record-name",
            "original-record-1",
            "--record-change-tag",
            "old-change-tag",
            "--record-type",
            "CPLAsset",
            "--filename",
            "IMG_0001.dng",
            "--size-bytes",
            "42",
            "--matched-raw-sha256",
            "raw-sha256",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("nas"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);
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
        .stdout(predicate::str::contains("workflow"))
        .stdout(predicate::str::contains("__stage-raw-copy").not());

    binary()
        .args(["workflow", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("conversion-recorded"))
        .stdout(predicate::str::contains("heic-verified"));
}

#[test]
fn hidden_stage_raw_copy_command_copies_and_verifies_bytes() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let raw_path = tempdir.path().join("IMG_0001.dng");
    let staged_path = tempdir.path().join("IMG_0001.staged-raw.dng");
    fs::write(&raw_path, b"raw-bytes").expect("raw should be written");
    let expected_sha256 = format!("{:x}", Sha256::digest(b"raw-bytes"));

    binary()
        .args([
            "__stage-raw-copy",
            raw_path.to_str().expect("raw path should be utf8"),
            staged_path.to_str().expect("staged path should be utf8"),
            "9",
            &expected_sha256,
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(&staged_path).expect("staged RAW should be readable"),
        b"raw-bytes"
    );
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

#[cfg(unix)]
#[test]
fn monitor_init_writes_simple_config_without_overwriting() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let config_path = tempdir.path().join("monitor.json");
    let download_root = tempdir.path().join("download");
    let heic_dir = tempdir.path().join("heic");
    let manifest_path = tempdir.path().join("manifest.json");

    binary()
        .args([
            "monitor",
            "init",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--download-root",
            download_root
                .to_str()
                .expect("download root should be utf8"),
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--heic-output-dir",
            heic_dir.to_str().expect("heic dir should be utf8"),
            "--scan-interval-seconds",
            "60",
            "--jobs",
            "4",
        ])
        .assert()
        .success();

    let config: Value =
        serde_json::from_str(&fs::read_to_string(&config_path).expect("config should be readable"))
            .expect("config should be json");
    assert_eq!(config["schema_version"], 1);
    assert_eq!(
        config["download_root"],
        download_root.to_string_lossy().as_ref()
    );
    assert_eq!(config["nas_root"], download_root.to_string_lossy().as_ref());
    assert_eq!(
        config["manifest_path"],
        manifest_path.to_string_lossy().as_ref()
    );
    assert_eq!(
        config["heic_output_dir"],
        heic_dir.to_string_lossy().as_ref()
    );
    assert_eq!(config["scan_interval_seconds"], 60);
    assert_eq!(config["jobs"], 4);

    binary()
        .args([
            "monitor",
            "init",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--download-root",
            download_root
                .to_str()
                .expect("download root should be utf8"),
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--heic-output-dir",
            heic_dir.to_str().expect("heic dir should be utf8"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn monitor_scan_root_preflight_probe_reads_directory_or_fails_closed() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");

    binary()
        .args([
            "monitor",
            "scan-root-preflight",
            "--path",
            tempdir.path().to_str().expect("path should be utf8"),
        ])
        .assert()
        .success()
        .stdout("");

    binary()
        .args([
            "monitor",
            "scan-root-preflight",
            "--path",
            tempdir
                .path()
                .join("missing")
                .to_str()
                .expect("path should be utf8"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to read directory"));
}

#[cfg(unix)]
#[test]
fn monitor_run_once_converts_matching_old_raw_and_writes_stats() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
    write_fake_conversion_tools(tool_dir.path());
    let config_path = tempdir.path().join("monitor.json");
    let download_root = tempdir.path().join("download");
    let heic_dir = tempdir.path().join("heic");
    let manifest_path = tempdir.path().join("manifest.json");
    fs::create_dir_all(&download_root).expect("download root should be created");
    let raw_path = write_old_raw(&download_root, "PrimarySync/IMG_0001.DNG", b"raw-bytes");

    binary()
        .args([
            "monitor",
            "init",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--download-root",
            download_root
                .to_str()
                .expect("download root should be utf8"),
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--heic-output-dir",
            heic_dir.to_str().expect("heic dir should be utf8"),
            "--jobs",
            "2",
            "--conversion-tool-version",
            "monitor-test",
        ])
        .assert()
        .success();

    let run_output = binary()
        .args([
            "monitor",
            "run",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--once",
        ])
        .env("PATH", tool_dir.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let run_lines = String::from_utf8(run_output).expect("run output should be utf8");
    let scan_summary: Value =
        serde_json::from_str(run_lines.trim()).expect("run should log scan summary json");
    assert_eq!(scan_summary["raw_files_seen"], 1);
    assert_eq!(scan_summary["conversions_completed"], 1);

    let manifest = Manifest::load(&manifest_path).expect("manifest should load");
    let record = manifest
        .records()
        .values()
        .next()
        .expect("monitor should discover one record");
    assert_eq!(record.state, State::Converted);
    assert_eq!(
        record.proofs["nas"]["canonical_path"],
        fs::canonicalize(raw_path)
            .expect("raw should canonicalize")
            .to_string_lossy()
            .as_ref()
    );
    let heic_path = record.proofs["conversion"]["heic_path"]
        .as_str()
        .expect("conversion should record heic path");
    assert!(PathBuf::from(heic_path).exists());
    assert_eq!(
        record.proofs["conversion_performance"]["conversion_tool_version"],
        "monitor-test"
    );

    let stats_path = config_path.with_file_name("manifest.monitor-stats.json");
    let stats: Value =
        serde_json::from_str(&fs::read_to_string(&stats_path).expect("stats should be readable"))
            .expect("stats should be json");
    assert_eq!(stats["scans_started"], 1);
    assert_eq!(stats["scans_completed"], 1);
    assert_eq!(stats["raw_files_seen"], 1);
    assert_eq!(stats["candidates_verified"], 1);
    assert_eq!(stats["conversions_attempted"], 1);
    assert_eq!(stats["conversions_completed"], 1);
    assert_eq!(stats["uploads_completed"], 0);
    assert_eq!(stats["originals_deleted"], 0);
    assert_eq!(stats["bytes_saved"], 0);
    assert_eq!(stats["state_counts"]["converted"], 1);
}

#[cfg(unix)]
#[test]
fn monitor_init_can_enable_guarded_full_lifecycle_config() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let config_path = tempdir.path().join("monitor.json");
    let download_root = tempdir.path().join("download");
    let heic_dir = tempdir.path().join("heic");
    let manifest_path = tempdir.path().join("manifest.json");
    let upload_session = tempdir.path().join("upload-session.json");
    let delete_session = tempdir.path().join("delete-session.json");
    let mirror_root = tempdir.path().join("mirror");

    binary()
        .args([
            "monitor",
            "init",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--download-root",
            download_root
                .to_str()
                .expect("download root should be utf8"),
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--heic-output-dir",
            heic_dir.to_str().expect("heic dir should be utf8"),
            "--min-age-days",
            "30",
            "--full-lifecycle",
            "--auto-delete",
            "--upload-session",
            upload_session
                .to_str()
                .expect("upload session should be utf8"),
            "--delete-session",
            delete_session
                .to_str()
                .expect("delete session should be utf8"),
            "--mirror-root",
            mirror_root.to_str().expect("mirror root should be utf8"),
            "--delete-operator",
            "launchd-service",
            "--max-lifecycle-per-scan",
            "3",
            "--cloudkit-page-size",
            "50",
            "--cloudkit-max-pages",
            "12",
            "--capture-tolerance-seconds",
            "4",
            "--scan-root-preflight-timeout-seconds",
            "45",
        ])
        .assert()
        .success();

    let config: Value =
        serde_json::from_str(&fs::read_to_string(&config_path).expect("config should be readable"))
            .expect("config should be json");
    assert_eq!(config["min_age_days"], 30);
    assert_eq!(config["full_lifecycle"], true);
    assert_eq!(config["auto_delete"], true);
    assert_eq!(
        config["upload_session_path"],
        upload_session.to_string_lossy().as_ref()
    );
    assert_eq!(
        config["delete_session_path"],
        delete_session.to_string_lossy().as_ref()
    );
    assert_eq!(
        config["mirror_root"],
        mirror_root.to_string_lossy().as_ref()
    );
    assert_eq!(config["delete_operator"], "launchd-service");
    assert_eq!(config["max_lifecycle_per_scan"], 3);
    assert_eq!(config["cloudkit_page_size"], 50);
    assert_eq!(config["cloudkit_max_pages"], 12);
    assert_eq!(config["capture_tolerance_seconds"], 4);
    assert_eq!(config["scan_root_preflight_timeout_seconds"], 45);
}

#[cfg(unix)]
#[test]
fn monitor_run_once_honors_max_conversions_per_scan() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
    write_fake_conversion_tools(tool_dir.path());
    let config_path = tempdir.path().join("monitor.json");
    let download_root = tempdir.path().join("download");
    let heic_dir = tempdir.path().join("heic");
    let manifest_path = tempdir.path().join("manifest.json");
    fs::create_dir_all(&download_root).expect("download root should be created");
    write_old_raw(&download_root, "PrimarySync/IMG_0001.DNG", b"raw-one");
    write_old_raw(&download_root, "PrimarySync/IMG_0002.DNG", b"raw-two");

    binary()
        .args([
            "monitor",
            "init",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--download-root",
            download_root
                .to_str()
                .expect("download root should be utf8"),
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--heic-output-dir",
            heic_dir.to_str().expect("heic dir should be utf8"),
            "--max-conversions-per-scan",
            "1",
        ])
        .assert()
        .success();

    binary()
        .args([
            "monitor",
            "run",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--once",
        ])
        .env("PATH", tool_dir.path())
        .assert()
        .success();

    let manifest = Manifest::load(&manifest_path).expect("manifest should load");
    assert_eq!(manifest.records().len(), 1);
    assert_eq!(
        manifest
            .records()
            .values()
            .next()
            .expect("one record should exist")
            .state,
        State::Converted
    );
    assert_eq!(
        fs::read_dir(&heic_dir)
            .expect("heic dir should be readable")
            .filter(|entry| entry
                .as_ref()
                .expect("entry should be readable")
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("heic"))
            .count(),
        1
    );

    let stats: Value = serde_json::from_str(
        &fs::read_to_string(config_path.with_file_name("manifest.monitor-stats.json"))
            .expect("stats should be readable"),
    )
    .expect("stats should be json");
    assert_eq!(stats["conversions_attempted"], 1);
    assert_eq!(stats["conversions_completed"], 1);
}

#[cfg(unix)]
#[test]
fn monitor_run_once_marks_failed_conversion_and_keeps_successful_peer() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
    write_fake_conversion_tools(tool_dir.path());
    let config_path = tempdir.path().join("monitor.json");
    let download_root = tempdir.path().join("download");
    let heic_dir = tempdir.path().join("heic");
    let manifest_path = tempdir.path().join("manifest.json");
    fs::create_dir_all(&download_root).expect("download root should be created");
    let raw_1 = write_old_raw(&download_root, "PrimarySync/IMG_0001.DNG", b"raw-one");
    let raw_2 = write_old_raw(&download_root, "PrimarySync/IMG_0002.DNG", b"raw-two");

    binary()
        .args([
            "monitor",
            "init",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--download-root",
            download_root
                .to_str()
                .expect("download root should be utf8"),
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--heic-output-dir",
            heic_dir.to_str().expect("heic dir should be utf8"),
            "--jobs",
            "2",
            "--max-conversions-per-scan",
            "2",
        ])
        .assert()
        .success();

    manifest_with_real_nas_verified_assets(
        &manifest_path,
        &fs::canonicalize(&download_root).expect("download root should canonicalize"),
        &[
            (
                "batch-1",
                fs::canonicalize(&raw_1).expect("raw should canonicalize"),
            ),
            (
                "batch-2",
                fs::canonicalize(&raw_2).expect("raw should canonicalize"),
            ),
        ],
    );
    fs::create_dir_all(&heic_dir).expect("heic dir should be created");
    fs::write(heic_dir.join("batch-2.heic"), b"preexisting")
        .expect("preexisting output should be written");

    binary()
        .args([
            "monitor",
            "run",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--once",
        ])
        .env("PATH", tool_dir.path())
        .assert()
        .success();

    let manifest = Manifest::load(&manifest_path).expect("manifest should load");
    let converted = manifest
        .get("batch-1")
        .expect("converted asset should exist");
    assert_eq!(converted.state, State::Converted);
    assert!(converted.proofs.contains_key("conversion"));
    let failed = manifest.get("batch-2").expect("failed asset should exist");
    assert_eq!(failed.state, State::Failed);
    assert_eq!(failed.failures[0].stage, "conversion");
    assert!(
        failed.failures[0]
            .message
            .contains("converted output already exists")
    );

    let stats: Value = serde_json::from_str(
        &fs::read_to_string(config_path.with_file_name("manifest.monitor-stats.json"))
            .expect("stats should be readable"),
    )
    .expect("stats should be json");
    assert_eq!(stats["conversions_attempted"], 2);
    assert_eq!(stats["conversions_completed"], 1);
    assert_eq!(stats["failures"], 1);
    assert_eq!(stats["state_counts"]["converted"], 1);
    assert_eq!(stats["state_counts"]["failed"], 1);
}

#[cfg(unix)]
#[test]
fn monitor_run_once_can_scan_download_root_non_recursively() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
    write_fake_conversion_tools(tool_dir.path());
    let config_path = tempdir.path().join("monitor.json");
    let download_root = tempdir.path().join("download");
    let heic_dir = tempdir.path().join("heic");
    let manifest_path = tempdir.path().join("manifest.json");
    fs::create_dir_all(&download_root).expect("download root should be created");
    write_old_raw(&download_root, "IMG_ROOT.DNG", b"root-raw");
    write_old_raw(&download_root, "nested/IMG_NESTED.DNG", b"nested-raw");

    binary()
        .args([
            "monitor",
            "init",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--download-root",
            download_root
                .to_str()
                .expect("download root should be utf8"),
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--heic-output-dir",
            heic_dir.to_str().expect("heic dir should be utf8"),
            "--no-recursive-scan",
        ])
        .assert()
        .success();

    binary()
        .args([
            "monitor",
            "run",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--once",
        ])
        .env("PATH", tool_dir.path())
        .assert()
        .success();

    let config: Value =
        serde_json::from_str(&fs::read_to_string(&config_path).expect("config should be readable"))
            .expect("config should be json");
    assert_eq!(config["scan_recursive"], false);

    let manifest = Manifest::load(&manifest_path).expect("manifest should load");
    assert_eq!(manifest.records().len(), 1);
    let record = manifest
        .records()
        .values()
        .next()
        .expect("one root record should exist");
    assert_eq!(record.state, State::Converted);
    assert!(record.raw_path.ends_with("IMG_ROOT.DNG"));
}

#[cfg(unix)]
#[test]
fn monitor_run_once_skips_young_raw_without_manifest_record() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let config_path = tempdir.path().join("monitor.json");
    let download_root = tempdir.path().join("download");
    let heic_dir = tempdir.path().join("heic");
    let manifest_path = tempdir.path().join("manifest.json");
    fs::create_dir_all(download_root.join("PrimarySync")).expect("download root should be created");
    fs::write(download_root.join("PrimarySync/IMG_0001.DNG"), b"young-raw")
        .expect("young raw should be written");

    binary()
        .args([
            "monitor",
            "init",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--download-root",
            download_root
                .to_str()
                .expect("download root should be utf8"),
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--heic-output-dir",
            heic_dir.to_str().expect("heic dir should be utf8"),
        ])
        .assert()
        .success();

    binary()
        .args([
            "monitor",
            "run",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--once",
        ])
        .assert()
        .success();

    let manifest = Manifest::load(&manifest_path).expect("manifest should load");
    assert!(manifest.records().is_empty());
    let stats: Value = serde_json::from_str(
        &fs::read_to_string(config_path.with_file_name("manifest.monitor-stats.json"))
            .expect("stats should be readable"),
    )
    .expect("stats should be json");
    assert_eq!(stats["raw_files_seen"], 1);
    assert_eq!(stats["skipped_not_ready"], 1);
}

#[cfg(unix)]
#[test]
fn monitor_stats_tui_and_launchd_plist_are_simple_and_non_secret() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let config_path = tempdir.path().join("monitor.json");
    let download_root = tempdir.path().join("download");
    let heic_dir = tempdir.path().join("heic");
    let manifest_path = tempdir.path().join("manifest.json");

    binary()
        .args([
            "monitor",
            "init",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--download-root",
            download_root
                .to_str()
                .expect("download root should be utf8"),
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--heic-output-dir",
            heic_dir.to_str().expect("heic dir should be utf8"),
        ])
        .assert()
        .success();

    let stats_output = binary()
        .args([
            "monitor",
            "stats",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stats_text = String::from_utf8(stats_output).expect("stats should be utf8");
    assert!(stats_text.contains("icloudpd-optimizer monitor"));
    assert!(stats_text.contains("uploaded: 0"));
    assert!(stats_text.contains("deleted originals: 0"));
    assert!(stats_text.contains("saved: 0.00 GiB"));
    assert!(!stats_text.to_ascii_lowercase().contains("password"));
    assert!(!stats_text.to_ascii_lowercase().contains("token"));

    let tui_output = binary()
        .args([
            "monitor",
            "tui",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--once",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let tui_text = String::from_utf8(tui_output).expect("tui should be utf8");
    assert!(tui_text.contains("icloudpd-optimizer monitor"));
    assert!(tui_text.contains("Press Ctrl-C to stop"));

    let plist_output = binary()
        .args([
            "monitor",
            "launchd-plist",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--bin",
            "/usr/local/bin/icloudpd-optimizer",
            "--associated-bundle-id",
            "io.github.bytware-alpha.icloudpd-optimizer",
            "--stdout",
            tempdir
                .path()
                .join("monitor.stdout.log")
                .to_str()
                .expect("stdout path should be utf8"),
            "--stderr",
            tempdir
                .path()
                .join("monitor.stderr.log")
                .to_str()
                .expect("stderr path should be utf8"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let plist = String::from_utf8(plist_output).expect("plist should be utf8");
    assert!(plist.contains("<string>monitor</string>"));
    assert!(plist.contains("<string>run</string>"));
    assert!(plist.contains("<key>AssociatedBundleIdentifiers</key>"));
    assert!(plist.contains("<string>io.github.bytware-alpha.icloudpd-optimizer</string>"));
    assert!(plist.contains("<key>StandardOutPath</key>"));
    assert!(plist.contains("monitor.stdout.log"));
    assert!(plist.contains("<key>StandardErrorPath</key>"));
    assert!(plist.contains("monitor.stderr.log"));
    assert!(plist.contains("<key>EnvironmentVariables</key>"));
    assert!(plist.contains("/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"));
    assert!(!plist.contains("/config"));
    assert!(!plist.to_ascii_lowercase().contains("password"));
    assert!(!plist.to_ascii_lowercase().contains("token"));
}

#[test]
fn monitor_launchd_plist_rejects_invalid_associated_bundle_id() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let config_path = tempdir.path().join("monitor.json");

    binary()
        .args([
            "monitor",
            "launchd-plist",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--associated-bundle-id",
            "not a bundle id",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid bundle identifier"));
}

#[test]
fn service_install_creates_plain_launchagent_for_installed_binary() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let config_path = tempdir.path().join("monitor.json");
    let download_root = tempdir.path().join("download");
    let heic_dir = tempdir.path().join("heic");
    let manifest_path = tempdir.path().join("manifest.json");
    let plist_path = tempdir.path().join("com.icloudpd-optimizer.monitor.plist");
    let stdout_path = tempdir.path().join("monitor.stdout.log");
    let stderr_path = tempdir.path().join("monitor.stderr.log");
    let bin_path = assert_cmd::cargo::cargo_bin("icloudpd-optimizer");

    binary()
        .args([
            "monitor",
            "init",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--download-root",
            download_root
                .to_str()
                .expect("download root should be utf8"),
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--heic-output-dir",
            heic_dir.to_str().expect("heic dir should be utf8"),
        ])
        .assert()
        .success();

    let output = binary()
        .args([
            "service",
            "install",
            "--config",
            config_path.to_str().expect("config path should be utf8"),
            "--plist",
            plist_path.to_str().expect("plist path should be utf8"),
            "--bin",
            bin_path.to_str().expect("bin path should be utf8"),
            "--stdout",
            stdout_path.to_str().expect("stdout path should be utf8"),
            "--stderr",
            stderr_path.to_str().expect("stderr path should be utf8"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output_text = String::from_utf8(output).expect("service output should be utf8");
    assert!(output_text.contains("installed service com.icloudpd-optimizer.monitor"));
    assert!(output_text.contains(&bin_path.to_string_lossy().to_string()));
    assert!(output_text.contains("after installing or updating"));
    assert!(!output_text.contains(".app"));
    assert!(!output_text.to_ascii_lowercase().contains("password"));
    assert!(!output_text.to_ascii_lowercase().contains("token"));

    let launchd_plist = fs::read_to_string(&plist_path).expect("launchd plist should be readable");
    assert!(launchd_plist.contains(&bin_path.to_string_lossy().to_string()));
    assert!(!launchd_plist.contains("<key>AssociatedBundleIdentifiers</key>"));
    assert!(!launchd_plist.contains("io.github.bytware-alpha.icloudpd-optimizer"));
    assert!(launchd_plist.contains(&config_path.to_string_lossy().to_string()));
    assert!(launchd_plist.contains(&stdout_path.to_string_lossy().to_string()));
    assert!(launchd_plist.contains(&stderr_path.to_string_lossy().to_string()));
    assert!(
        !tempdir.path().join("iCloudPD Optimizer.app").exists(),
        "service install must not create an app bundle"
    );
}

#[test]
fn service_install_rejects_missing_config_without_writing_plist() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let plist_path = tempdir.path().join("com.icloudpd-optimizer.monitor.plist");
    let missing_config = tempdir.path().join("missing-monitor.json");
    let bin_path = assert_cmd::cargo::cargo_bin("icloudpd-optimizer");

    binary()
        .args([
            "service",
            "install",
            "--config",
            missing_config.to_str().expect("config path should be utf8"),
            "--plist",
            plist_path.to_str().expect("plist path should be utf8"),
            "--bin",
            bin_path.to_str().expect("bin path should be utf8"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed to read monitor config"));

    assert!(
        !plist_path.exists(),
        "missing config must not write a launchd plist"
    );
}

#[test]
fn apple_container_packaging_surface_is_documented() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let containerfile_path = repo_root.join("container/Containerfile");

    assert!(
        containerfile_path.exists(),
        "container/Containerfile should be committed"
    );

    let containerfile =
        fs::read_to_string(&containerfile_path).expect("Containerfile should be readable");
    for disallowed in [
        "/Users/",
        "/home/",
        "/config",
        "localhost",
        "127.0.0.1",
        "APPLE_ID",
        "PASSWORD",
        "SECRET",
        "TOKEN",
    ] {
        assert!(
            !containerfile.contains(disallowed),
            "Containerfile should not contain private marker {disallowed:?}"
        );
    }

    let justfile = fs::read_to_string(repo_root.join("Justfile")).expect("Justfile should exist");
    assert!(justfile.contains("apple-image-build"));
    assert!(justfile.contains("apple-image-doctor"));
    assert!(justfile.contains("oci-image-smoke"));
    assert!(justfile.contains("container build"));
    assert!(justfile.contains("--file container/Containerfile"));

    let readme = fs::read_to_string(repo_root.join("README.md")).expect("README should exist");
    assert!(readme.contains(
        "container build --tag icloudpd-optimizer:local --file container/Containerfile ."
    ));
    assert!(readme.contains("OCI"));
    assert!(readme.contains("Linux OCI runtimes"));
}

#[test]
fn homebrew_formula_installs_cli_and_defines_brew_service() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let formula_path = repo_root
        .join("packaging")
        .join("homebrew")
        .join("icloudpd-optimizer.rb");

    let formula = fs::read_to_string(&formula_path).expect("Homebrew formula should be readable");
    assert!(formula.contains("system \"cargo\", \"install\", *std_cargo_args"));
    assert!(formula.contains("head \"https://github.com/bytware-alpha/icloudpd-optimizer.git\""));
    assert!(formula.contains("service do"));
    assert!(formula.contains("run ["));
    assert!(formula.contains("opt_bin/\"icloudpd-optimizer\""));
    assert!(formula.contains("\"monitor\""));
    assert!(formula.contains("\"run\""));
    assert!(formula.contains("keep_alive true"));
    assert!(formula.contains("brew services start icloudpd-optimizer"));
    assert!(!formula.contains(".app"));
    for disallowed in [
        "/Users/", "/home/", "APPLE_ID", "PASSWORD", "SECRET", "TOKEN",
    ] {
        assert!(
            !formula.contains(disallowed),
            "Homebrew formula should not include local or secret marker {disallowed}"
        );
    }
}

#[test]
fn setup_and_install_docs_scope_platform_conversion_tools() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let justfile = fs::read_to_string(repo_root.join("Justfile")).expect("Justfile should exist");
    let readme = fs::read_to_string(repo_root.join("README.md")).expect("README should exist");

    assert!(justfile.contains("Darwin"));
    assert!(justfile.contains("require_tool sips"));
    assert!(!justfile.contains("require_tool dcraw_emu"));
    assert!(justfile.contains("require_tool heif-enc"));
    assert!(justfile.contains("Linux workflow convert uses exiftool"));

    assert!(
        readme.contains("`doctor --json` is authoritative for platform-specific required tools")
    );
    assert!(readme.contains("macOS host-native `workflow convert` requirements"));
    assert!(readme.contains("Linux source and OCI installs do not require `sips`"));
    assert!(readme.contains("Linux-native `workflow convert` requirements"));
    assert!(!readme.contains("dcraw_emu"));
    assert!(readme.contains("heif-enc"));
    assert!(!readme.contains("You will also need these tools available on `PATH`:\n\n- `sips`"));
}

#[test]
fn container_builder_uses_declared_supported_rust_version() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cargo_toml =
        fs::read_to_string(repo_root.join("Cargo.toml")).expect("Cargo.toml should be readable");
    let containerfile = fs::read_to_string(repo_root.join("container/Containerfile"))
        .expect("Containerfile should be readable");
    let rust_version = cargo_toml
        .lines()
        .find_map(|line| line.strip_prefix("rust-version = \""))
        .and_then(|version| version.strip_suffix('"'))
        .expect("Cargo.toml should declare rust-version");

    assert!(
        rust_version_at_least(rust_version, 1, 86),
        "locked dependency graph requires rustc 1.86 or newer"
    );
    assert!(
        containerfile.contains(&format!(
            "FROM docker.io/rust:{rust_version}-bookworm AS builder"
        )),
        "Containerfile builder image must match Cargo.toml rust-version"
    );
}

#[test]
fn container_image_provides_magick_command_on_bookworm() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let containerfile = fs::read_to_string(repo_root.join("container/Containerfile"))
        .expect("Containerfile should be readable");

    assert!(
        containerfile.contains("/usr/local/bin/magick"),
        "doctor requires magick, so the Linux image must provide that command"
    );
    assert!(
        !containerfile.contains("libraw-bin"),
        "Linux conversion uses the embedded preview path and should not ship the old raw-render decoder"
    );
    assert!(
        containerfile.contains("exec /usr/bin/compare"),
        "magick compare should dispatch to ImageMagick 6 compare on bookworm"
    );
    assert!(
        containerfile.contains("exec /usr/bin/convert"),
        "non-compare magick invocations should dispatch to ImageMagick 6 convert on bookworm"
    );
}

fn rust_version_at_least(version: &str, minimum_major: u64, minimum_minor: u64) -> bool {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|part| part.parse::<u64>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u64>().ok());

    matches!(
        (major, minor),
        (Some(major), Some(minor))
            if major > minimum_major || (major == minimum_major && minor >= minimum_minor)
    )
}

#[test]
fn doctor_json_reports_required_tools_missing_under_empty_path() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");

    let shown = doctor_json_with_path(tempdir.path(), tempdir.path());

    assert_eq!(shown, missing_required_tools_json());
}

#[test]
fn doctor_json_reports_platform_backend_support_and_required_tools() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let target = current_target_platform();
    let backend = backend_report_for_target(target);

    let shown = doctor_json_with_path(tempdir.path(), tempdir.path());

    assert_eq!(shown["platform"]["os"], std::env::consts::OS);
    assert_eq!(shown["platform"]["arch"], std::env::consts::ARCH);
    assert_eq!(shown["conversion_backend"]["name"], backend.name);
    assert_eq!(
        shown["conversion_backend"]["workflow_convert_supported"],
        backend.workflow_convert_supported
    );
    assert_eq!(shown["conversion_backend"]["reason"], backend.reason);
    assert_eq!(
        shown["required_tools"]
            .as_array()
            .expect("required tools should be array")
            .iter()
            .map(|tool| tool["name"].as_str().expect("tool name should be string"))
            .collect::<Vec<_>>(),
        required_tools_for_target(target)
    );
    assert!(
        shown["required_tools"]
            .as_array()
            .expect("required tools should be array")
            .iter()
            .all(|tool| tool["present"] == false)
    );
}

#[test]
fn backend_report_marks_linux_workflow_convert_supported_without_sips() {
    let target = TargetPlatform::new("linux", "x86_64");
    let report = backend_report_for_target(target);

    assert_eq!(report.name, "linux-native");
    assert!(report.workflow_convert_supported);
    assert!(!required_tools_for_target(target).contains(&"sips"));
    assert_eq!(
        required_tools_for_target(target),
        ["heif-enc", "heif-info", "magick", "exiftool"]
    );
}

#[test]
fn backend_report_marks_macos_workflow_convert_supported_with_sips() {
    let target = TargetPlatform::new("macos", "aarch64");
    let report = backend_report_for_target(target);

    assert_eq!(report.name, "macos-sips");
    assert!(report.workflow_convert_supported);
    assert!(required_tools_for_target(target).contains(&"sips"));
}

#[cfg(unix)]
#[test]
fn doctor_json_reports_heif_info_and_magick_as_required() {
    let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
    let cwd = tempfile::tempdir().expect("cwd tempdir should be created");
    write_executable(&tool_dir.path().join("sips"));
    write_executable(&tool_dir.path().join("exiftool"));

    let shown = doctor_json_with_path(tool_dir.path(), cwd.path());

    assert_eq!(
        shown,
        doctor_json_with_tool_presence(|name| name == "sips" || name == "exiftool")
    );
}

#[cfg(unix)]
#[test]
fn doctor_json_ignores_empty_path_when_cwd_contains_matching_executables() {
    let cwd = tempfile::tempdir().expect("tempdir should be created");
    write_fake_required_tools(cwd.path());

    let shown = doctor_json_with_path("", cwd.path());

    assert_eq!(shown, missing_required_tools_json());
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
        assert_eq!(shown, missing_required_tools_json());
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
fn workflow_conversion_result_performance_and_heic_verified_commands_complete_conversion_gate() {
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
            "conversion-result",
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
    record_conversion_performance_cli(manifest_arg);
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
            "--visual-content-ok",
            "--visual-match-ok",
        ])
        .assert()
        .success();

    let manifest = Manifest::load(&manifest_path).expect("manifest should load");
    let record = manifest.get("asset-1").expect("asset should exist");
    assert_eq!(record.state, State::ConversionVerified);
    assert_eq!(record.proofs["conversion"]["heic_sha256"], "heic-sha256");
    assert_eq!(
        record.proofs["conversion_performance"]["conversion_tool"],
        "magick"
    );
    assert_eq!(
        record.proofs["conversion_performance"]["conversion_tool_version"],
        "7.1.1-41"
    );
    assert_eq!(record.proofs["conversion_performance"]["heic_quality"], 90);
    assert_eq!(
        record.proofs["conversion_performance"]["raw_size_bytes"],
        42
    );
    assert_eq!(
        record.proofs["conversion_performance"]["heic_size_bytes"],
        24
    );
    assert_eq!(
        record.proofs["conversion_performance"]["measurement_method"],
        "monotonic_wall_clock"
    );
    assert!(
        record.proofs["conversion_performance"]["measured_at_unix_seconds"]
            .as_u64()
            .expect("measured_at should be filled")
            > 0
    );
    assert_eq!(record.proofs["heic"]["heic_path"], "/staging/IMG_0001.heic");
}

#[cfg(all(unix, target_os = "macos"))]
#[test]
fn workflow_convert_batch_runs_multiple_assets_with_bounded_parallelism() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
    write_fake_conversion_tools(tool_dir.path());
    let manifest_path = tempdir.path().join("manifest.json");
    let nas_root = tempdir.path().join("nas");
    let raw_1 = write_old_raw(&nas_root, "camera/IMG_0001.dng", b"raw-one");
    let raw_2 = write_old_raw(&nas_root, "camera/IMG_0002.dng", b"raw-two");
    manifest_with_real_nas_verified_assets(
        &manifest_path,
        &fs::canonicalize(&nas_root).expect("nas root should canonicalize"),
        &[
            (
                "batch-1",
                fs::canonicalize(&raw_1).expect("raw should canonicalize"),
            ),
            (
                "batch-2",
                fs::canonicalize(&raw_2).expect("raw should canonicalize"),
            ),
        ],
    );
    let output_dir = tempdir.path().join("converted");
    fs::create_dir(&output_dir).expect("output dir should be created");

    binary()
        .args([
            "workflow",
            "convert-batch",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "batch-1",
            "--asset-id",
            "batch-2",
            "--output-dir",
            output_dir.to_str().expect("output dir should be utf8"),
            "--heic-quality",
            "91",
            "--jobs",
            "2",
            "--conversion-tool-version",
            "sips-batch",
        ])
        .env("PATH", tool_dir.path())
        .assert()
        .success();

    let manifest = Manifest::load(&manifest_path).expect("manifest should load");
    for asset_id in ["batch-1", "batch-2"] {
        let output_path = output_dir.join(format!("{asset_id}.heic"));
        let heic = fs::read(&output_path).expect("heic output should be readable");
        let record = manifest.get(asset_id).expect("asset should exist");
        assert_eq!(record.state, State::Converted);
        assert_eq!(
            record.proofs["conversion"]["heic_path"],
            output_path.to_string_lossy().as_ref()
        );
        assert_eq!(
            record.proofs["conversion"]["heic_sha256"],
            sha256_hex(&heic)
        );
        assert_eq!(
            record.proofs["conversion_performance"]["conversion_tool"],
            "exiftool+exiftool+magick+sips"
        );
        assert_eq!(
            record.proofs["conversion_performance"]["conversion_tool_version"],
            "sips-batch"
        );
    }
}

#[cfg(all(unix, target_os = "macos"))]
#[test]
fn workflow_convert_batch_rejects_unsafe_asset_id_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    manifest_with_nas_verified(&manifest_path);
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");
    let output_dir = tempdir.path().join("converted");
    fs::create_dir(&output_dir).expect("output dir should be created");

    binary()
        .args([
            "workflow",
            "convert-batch",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "../bad",
            "--output-dir",
            output_dir.to_str().expect("output dir should be utf8"),
            "--heic-quality",
            "91",
            "--jobs",
            "2",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsafe batch asset id"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);
    assert!(
        fs::read_dir(&output_dir)
            .expect("output dir should remain readable")
            .next()
            .is_none()
    );
}

#[cfg(all(unix, target_os = "macos"))]
#[test]
fn workflow_convert_batch_failure_does_not_save_partial_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
    write_fake_conversion_tools(tool_dir.path());
    let manifest_path = tempdir.path().join("manifest.json");
    let nas_root = tempdir.path().join("nas");
    let raw_1 = write_old_raw(&nas_root, "camera/IMG_0001.dng", b"raw-one");
    let raw_2 = write_old_raw(&nas_root, "camera/IMG_0002.dng", b"raw-two");
    manifest_with_real_nas_verified_assets(
        &manifest_path,
        &fs::canonicalize(&nas_root).expect("nas root should canonicalize"),
        &[
            (
                "batch-1",
                fs::canonicalize(&raw_1).expect("raw should canonicalize"),
            ),
            (
                "batch-2",
                fs::canonicalize(&raw_2).expect("raw should canonicalize"),
            ),
        ],
    );
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");
    let output_dir = tempdir.path().join("converted");
    fs::create_dir(&output_dir).expect("output dir should be created");
    let preexisting = output_dir.join("batch-2.heic");
    fs::write(&preexisting, b"existing-output").expect("preexisting output should be written");
    let preexisting_before = fs::read(&preexisting).expect("preexisting output should be readable");

    binary()
        .args([
            "workflow",
            "convert-batch",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "batch-1",
            "--asset-id",
            "batch-2",
            "--output-dir",
            output_dir.to_str().expect("output dir should be utf8"),
            "--heic-quality",
            "91",
            "--jobs",
            "2",
        ])
        .env("PATH", tool_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "batch conversion failed for batch-2",
        ))
        .stderr(predicate::str::contains("already exists"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    let preexisting_after = fs::read(&preexisting).expect("preexisting output should be readable");
    assert_eq!(after, before);
    assert_eq!(preexisting_after, preexisting_before);
}

#[cfg(all(unix, target_os = "macos"))]
#[test]
fn workflow_convert_runs_tools_and_records_conversion_and_performance_atomically() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
    write_fake_conversion_tools(tool_dir.path());
    let manifest_path = tempdir.path().join("manifest.json");
    let nas_root = tempdir.path().join("nas");
    let raw_path = write_old_raw(&nas_root, "camera/IMG_0001.dng", b"raw-bytes");
    manifest_with_real_nas_verified(
        &manifest_path,
        fs::canonicalize(&raw_path).expect("raw should canonicalize"),
        fs::canonicalize(&nas_root).expect("nas root should canonicalize"),
    );
    let output_path = tempdir.path().join("IMG_0001.heic");

    binary()
        .args([
            "workflow",
            "convert",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--output-path",
            output_path.to_str().expect("output path should be utf8"),
            "--heic-quality",
            "91",
            "--conversion-tool-version",
            "sips-123",
        ])
        .env("PATH", tool_dir.path())
        .assert()
        .success();

    let heic = fs::read(&output_path).expect("heic output should be readable");
    let manifest = Manifest::load(&manifest_path).expect("manifest should load");
    let record = manifest.get("asset-1").expect("asset should exist");
    assert_eq!(record.state, State::Converted);
    assert_eq!(
        record.proofs["conversion"]["heic_path"],
        output_path.to_string_lossy().as_ref()
    );
    assert_eq!(
        record.proofs["conversion"]["heic_sha256"],
        sha256_hex(&heic)
    );
    assert_eq!(record.proofs["conversion"]["size_bytes"], heic.len() as u64);
    assert_eq!(
        record.proofs["conversion_performance"]["conversion_tool"],
        "exiftool+exiftool+magick+sips"
    );
    assert_eq!(
        record.proofs["conversion_performance"]["conversion_tool_version"],
        "sips-123"
    );
    assert_eq!(record.proofs["conversion_performance"]["heic_quality"], 91);
    assert!(
        record.proofs["conversion_performance"]["convert_wall_time_millis"]
            .as_u64()
            .expect("convert wall time should be present")
            > 0
    );
    assert!(
        record.proofs["conversion_performance"]["total_wall_time_millis"]
            .as_u64()
            .expect("total wall time should be present")
            >= record.proofs["conversion_performance"]["convert_wall_time_millis"]
                .as_u64()
                .expect("convert wall time should be present")
    );
}

#[cfg(all(unix, target_os = "macos"))]
#[test]
fn workflow_convert_ignores_empty_path_segments_without_mutating_manifest_or_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let empty_path_dir = tempfile::tempdir().expect("empty PATH dir should be created");
    write_fake_conversion_tools(tempdir.path());
    let manifest_path = tempdir.path().join("manifest.json");
    let nas_root = tempdir.path().join("nas");
    let raw_path = write_old_raw(&nas_root, "camera/IMG_0001.dng", b"raw-bytes");
    manifest_with_real_nas_verified(
        &manifest_path,
        fs::canonicalize(&raw_path).expect("raw should canonicalize"),
        fs::canonicalize(&nas_root).expect("nas root should canonicalize"),
    );
    let output_path = tempdir.path().join("IMG_0001.heic");
    let before_manifest = fs::read_to_string(&manifest_path).expect("manifest should be readable");
    let poisoned_path = format!(":{}:", empty_path_dir.path().display());

    binary()
        .args([
            "workflow",
            "convert",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--output-path",
            output_path.to_str().expect("output path should be utf8"),
            "--heic-quality",
            "91",
        ])
        .current_dir(tempdir.path())
        .env("PATH", poisoned_path)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "conversion tool not found on sanitized PATH: exiftool",
        ));

    let after_manifest = fs::read_to_string(&manifest_path).expect("manifest should be readable");
    assert_eq!(after_manifest, before_manifest);
    assert!(!output_path.exists());
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[test]
fn workflow_convert_fails_closed_on_unsupported_backend_without_mutating_manifest_or_output() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let nas_root = tempdir.path().join("nas");
    let raw_path = write_old_raw(&nas_root, "camera/IMG_0001.dng", b"raw-bytes");
    manifest_with_real_nas_verified(
        &manifest_path,
        fs::canonicalize(&raw_path).expect("raw should canonicalize"),
        fs::canonicalize(&nas_root).expect("nas root should canonicalize"),
    );
    let output_path = tempdir.path().join("IMG_0001.heic");
    let before_manifest = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "convert",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--output-path",
            output_path.to_str().expect("output path should be utf8"),
            "--heic-quality",
            "91",
        ])
        .env("PATH", tempdir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported conversion backend"))
        .stderr(predicate::str::contains(
            backend_report_for_target(current_target_platform()).name,
        ));

    let after_manifest = fs::read_to_string(&manifest_path).expect("manifest should be readable");
    assert_eq!(after_manifest, before_manifest);
    assert!(!output_path.exists());
}

#[cfg(all(unix, target_os = "macos"))]
#[test]
fn workflow_convert_refuses_preexisting_output_without_mutating_manifest_or_file() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
    write_fake_conversion_tools(tool_dir.path());
    let manifest_path = tempdir.path().join("manifest.json");
    let nas_root = tempdir.path().join("nas");
    let raw_path = write_old_raw(&nas_root, "camera/IMG_0001.dng", b"raw-bytes");
    manifest_with_real_nas_verified(
        &manifest_path,
        fs::canonicalize(&raw_path).expect("raw should canonicalize"),
        fs::canonicalize(&nas_root).expect("nas root should canonicalize"),
    );
    let output_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&output_path, b"existing-heic").expect("preexisting output should be written");
    let before_manifest = fs::read_to_string(&manifest_path).expect("manifest should be readable");
    let before_output = fs::read(&output_path).expect("output should be readable");

    binary()
        .args([
            "workflow",
            "convert",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--output-path",
            output_path.to_str().expect("output path should be utf8"),
            "--heic-quality",
            "91",
        ])
        .env("PATH", tool_dir.path())
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));

    let after_manifest = fs::read_to_string(&manifest_path).expect("manifest should be readable");
    let after_output = fs::read(&output_path).expect("output should remain readable");
    assert_eq!(after_manifest, before_manifest);
    assert_eq!(after_output, before_output);
}

#[cfg(all(unix, target_os = "macos"))]
#[test]
fn workflow_convert_failure_does_not_mutate_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
    write_fake_conversion_tools(tool_dir.path());
    let manifest_path = tempdir.path().join("manifest.json");
    let nas_root = tempdir.path().join("nas");
    let raw_path = write_old_raw(&nas_root, "camera/IMG_0001.dng", b"raw-bytes");
    manifest_with_real_nas_verified(
        &manifest_path,
        fs::canonicalize(&raw_path).expect("raw should canonicalize"),
        fs::canonicalize(&nas_root).expect("nas root should canonicalize"),
    );
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "convert",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--output-path",
            tempdir
                .path()
                .join("IMG_0001.heic")
                .to_str()
                .expect("output path should be utf8"),
            "--heic-quality",
            "91",
        ])
        .env("PATH", tool_dir.path())
        .env("FAIL_SIPS", "1")
        .assert()
        .failure()
        .stderr(predicate::str::contains("conversion command failed"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);
}

#[cfg(all(unix, target_os = "macos"))]
#[test]
fn workflow_convert_metadata_failure_does_not_mutate_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
    write_fake_conversion_tools(tool_dir.path());
    let manifest_path = tempdir.path().join("manifest.json");
    let nas_root = tempdir.path().join("nas");
    let raw_path = write_old_raw(&nas_root, "camera/IMG_0001.dng", b"raw-bytes");
    manifest_with_real_nas_verified(
        &manifest_path,
        fs::canonicalize(&raw_path).expect("raw should canonicalize"),
        fs::canonicalize(&nas_root).expect("nas root should canonicalize"),
    );
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "convert",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--output-path",
            tempdir
                .path()
                .join("IMG_0001.heic")
                .to_str()
                .expect("output path should be utf8"),
            "--heic-quality",
            "91",
        ])
        .env("PATH", tool_dir.path())
        .env("FAIL_EXIFTOOL", "1")
        .assert()
        .failure()
        .stderr(predicate::str::contains("metadata command failed"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);
}

#[cfg(all(unix, target_os = "macos"))]
#[test]
fn workflow_convert_empty_output_does_not_mutate_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
    write_fake_conversion_tools(tool_dir.path());
    let manifest_path = tempdir.path().join("manifest.json");
    let nas_root = tempdir.path().join("nas");
    let raw_path = write_old_raw(&nas_root, "camera/IMG_0001.dng", b"raw-bytes");
    manifest_with_real_nas_verified(
        &manifest_path,
        fs::canonicalize(&raw_path).expect("raw should canonicalize"),
        fs::canonicalize(&nas_root).expect("nas root should canonicalize"),
    );
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "convert",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--output-path",
            tempdir
                .path()
                .join("IMG_0001.heic")
                .to_str()
                .expect("output path should be utf8"),
            "--heic-quality",
            "91",
        ])
        .env("PATH", tool_dir.path())
        .env("EMPTY_SIPS_OUTPUT", "1")
        .assert()
        .failure()
        .stderr(predicate::str::contains("empty"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);
}

#[cfg(all(unix, target_os = "macos"))]
#[test]
fn workflow_convert_missing_output_does_not_mutate_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let tool_dir = tempfile::tempdir().expect("tool tempdir should be created");
    write_fake_conversion_tools(tool_dir.path());
    let manifest_path = tempdir.path().join("manifest.json");
    let nas_root = tempdir.path().join("nas");
    let raw_path = write_old_raw(&nas_root, "camera/IMG_0001.dng", b"raw-bytes");
    manifest_with_real_nas_verified(
        &manifest_path,
        fs::canonicalize(&raw_path).expect("raw should canonicalize"),
        fs::canonicalize(&nas_root).expect("nas root should canonicalize"),
    );
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "convert",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--output-path",
            tempdir
                .path()
                .join("IMG_0001.heic")
                .to_str()
                .expect("output path should be utf8"),
            "--heic-quality",
            "91",
        ])
        .env("PATH", tool_dir.path())
        .env("MISSING_SIPS_OUTPUT", "1")
        .assert()
        .failure()
        .stderr(predicate::str::contains("missing or unreadable"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);
}

#[test]
fn workflow_convert_help_describes_measured_actual_conversion() {
    binary()
        .args(["workflow", "convert", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("actual conversion"))
        .stdout(predicate::str::contains("measured performance"));
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
    record_conversion_performance_cli(manifest_arg);
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
            "--visual-content-ok",
            "--visual-match-ok",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("mismatch"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);
}

#[test]
fn workflow_heic_verified_requires_conversion_performance_without_mutating_manifest() {
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
            "conversion-result",
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
            "--metadata-copied",
            "--visual-content-ok",
            "--visual-match-ok",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("conversion_performance"));

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
    record_conversion_performance_cli(manifest_arg);
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
            "--metadata-copied",
            "--visual-match-ok",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("visual_content_ok"));

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
        .stdout(predicate::str::contains("external"))
        .stdout(predicate::str::contains("not produced by icloudpd"))
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
            "photosupload_url": "https://evil.example",
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
            "photosupload_url": "https://p140-photosupload.icloud.com:443",
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
fn workflow_upload_heic_rejects_legacy_uploadimagews_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let session_path = tempdir.path().join("session.json");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    fs::write(
        &session_path,
        serde_json::json!({
            "dsid": "123456789",
            "webservices": {
                "uploadimagews": {"url": "https://p140-uploadimagews.icloud.com:443"}
            },
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
        .stderr(predicate::str::contains("invalid upload session"))
        .stderr(predicate::str::contains("photosupload"));

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

fn manifest_with_real_upload_verified(
    manifest_path: &std::path::Path,
    heic_path: &std::path::Path,
    heic_bytes: &[u8],
) -> String {
    fs::create_dir_all(heic_path.parent().expect("heic path should have parent"))
        .expect("heic parent should be created");
    fs::write(heic_path, heic_bytes).expect("verified HEIC should be written");
    manifest_with_real_conversion_verified(manifest_path, heic_path.to_path_buf(), heic_bytes);
    let manifest_arg = manifest_path
        .to_str()
        .expect("manifest path should be utf8")
        .to_string();
    binary()
        .args([
            "workflow",
            "upload-verified",
            "--manifest",
            &manifest_arg,
            "--asset-id",
            "asset-1",
            "--uploaded-heic-asset-id",
            "icloud-heic-asset-1",
            "--uploaded-heic-sha256",
            &sha256_hex(heic_bytes),
            "--uploaded-heic-path",
            heic_path.to_str().expect("heic path should be utf8"),
        ])
        .assert()
        .success();
    manifest_arg
}

#[test]
fn workflow_icloudpd_local_mirror_copies_missing_destination_and_records_proof() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let heic_path = tempdir.path().join("staging").join("IMG_0001.heic");
    let download_path = tempdir.path().join("PrimarySync").join("IMG_0001.HEIC");
    fs::create_dir_all(download_path.parent().expect("download should have parent"))
        .expect("download parent should be created");
    let heic_bytes = b"heic-bytes";
    let manifest_arg = manifest_with_real_upload_verified(&manifest_path, &heic_path, heic_bytes);

    binary()
        .args([
            "workflow",
            "icloudpd-local-mirror",
            "--manifest",
            &manifest_arg,
            "--asset-id",
            "asset-1",
            "--download-path",
            download_path
                .to_str()
                .expect("download path should be utf8"),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(&download_path).expect("download mirror should be readable"),
        heic_bytes
    );
    let manifest = Manifest::load(&manifest_path).expect("manifest should load");
    let record = manifest.get("asset-1").expect("asset should exist");
    assert_eq!(
        record.proofs["icloudpd_local_mirror"]["uploaded_heic_asset_id"],
        "icloud-heic-asset-1"
    );
    assert_eq!(
        record.proofs["icloudpd_local_mirror"]["uploaded_heic_sha256"],
        sha256_hex(heic_bytes)
    );
    assert_eq!(
        record.proofs["icloudpd_local_mirror"]["icloudpd_download_path"],
        download_path.to_string_lossy().as_ref()
    );
    assert_eq!(
        record.proofs["icloudpd_local_mirror"]["size_bytes"],
        heic_bytes.len() as u64
    );
}

#[test]
fn workflow_icloudpd_local_mirror_accepts_existing_matching_destination_without_overwrite() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let heic_path = tempdir.path().join("staging").join("IMG_0001.heic");
    let download_path = tempdir.path().join("PrimarySync").join("IMG_0001.HEIC");
    fs::create_dir_all(download_path.parent().expect("download should have parent"))
        .expect("download parent should be created");
    let heic_bytes = b"heic-bytes";
    let manifest_arg = manifest_with_real_upload_verified(&manifest_path, &heic_path, heic_bytes);
    fs::write(&download_path, heic_bytes).expect("existing mirror should be written");
    let old_mtime = FileTime::from_unix_time(1_700_000_000, 0);
    set_file_mtime(&download_path, old_mtime).expect("mtime should be set");

    binary()
        .args([
            "workflow",
            "icloudpd-local-mirror",
            "--manifest",
            &manifest_arg,
            "--asset-id",
            "asset-1",
            "--download-path",
            download_path
                .to_str()
                .expect("download path should be utf8"),
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(&download_path).expect("existing mirror should be readable"),
        heic_bytes
    );
    assert_eq!(
        FileTime::from_last_modification_time(
            &fs::metadata(&download_path).expect("metadata should be readable")
        ),
        old_mtime
    );
}

#[test]
fn workflow_icloudpd_local_mirror_rejects_existing_mismatch_without_mutating_manifest_or_file() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let heic_path = tempdir.path().join("staging").join("IMG_0001.heic");
    let download_path = tempdir.path().join("PrimarySync").join("IMG_0001.HEIC");
    fs::create_dir_all(download_path.parent().expect("download should have parent"))
        .expect("download parent should be created");
    let heic_bytes = b"heic-bytes";
    let manifest_arg = manifest_with_real_upload_verified(&manifest_path, &heic_path, heic_bytes);
    fs::write(&download_path, b"other-bytes").expect("mismatched mirror should be written");
    let before_manifest = fs::read_to_string(&manifest_path).expect("manifest should be readable");
    let before_download = fs::read(&download_path).expect("download should be readable");

    binary()
        .args([
            "workflow",
            "icloudpd-local-mirror",
            "--manifest",
            &manifest_arg,
            "--asset-id",
            "asset-1",
            "--download-path",
            download_path
                .to_str()
                .expect("download path should be utf8"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("mismatch"));

    assert_eq!(
        fs::read_to_string(&manifest_path).expect("manifest should remain readable"),
        before_manifest
    );
    assert_eq!(
        fs::read(&download_path).expect("download should remain readable"),
        before_download
    );
}

#[test]
fn workflow_icloudpd_local_mirror_rejects_directory_destination_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let heic_path = tempdir.path().join("staging").join("IMG_0001.heic");
    let download_path = tempdir.path().join("PrimarySync");
    fs::create_dir_all(&download_path).expect("download directory should be created");
    let manifest_arg =
        manifest_with_real_upload_verified(&manifest_path, &heic_path, b"heic-bytes");
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "icloudpd-local-mirror",
            "--manifest",
            &manifest_arg,
            "--asset-id",
            "asset-1",
            "--download-path",
            download_path
                .to_str()
                .expect("download path should be utf8"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("directory"));

    assert_eq!(
        fs::read_to_string(&manifest_path).expect("manifest should remain readable"),
        before
    );
}

#[cfg(unix)]
#[test]
fn workflow_icloudpd_local_mirror_rejects_symlink_destination_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let heic_path = tempdir.path().join("staging").join("IMG_0001.heic");
    let download_path = tempdir.path().join("PrimarySync").join("IMG_0001.HEIC");
    let target_path = tempdir.path().join("target.HEIC");
    fs::create_dir_all(download_path.parent().expect("download should have parent"))
        .expect("download parent should be created");
    fs::write(&target_path, b"heic-bytes").expect("symlink target should be written");
    std::os::unix::fs::symlink(&target_path, &download_path)
        .expect("download symlink should be created");
    let manifest_arg =
        manifest_with_real_upload_verified(&manifest_path, &heic_path, b"heic-bytes");
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "icloudpd-local-mirror",
            "--manifest",
            &manifest_arg,
            "--asset-id",
            "asset-1",
            "--download-path",
            download_path
                .to_str()
                .expect("download path should be utf8"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("symlink"));

    assert_eq!(
        fs::read_to_string(&manifest_path).expect("manifest should remain readable"),
        before
    );
    assert_eq!(
        fs::read(&target_path).expect("symlink target should remain readable"),
        b"heic-bytes"
    );
}

#[test]
fn workflow_icloudpd_local_mirror_rejects_directory_source_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let heic_path = tempdir.path().join("staging").join("IMG_0001.heic");
    let download_path = tempdir.path().join("PrimarySync").join("IMG_0001.HEIC");
    fs::create_dir_all(&heic_path).expect("source directory should be created");
    fs::create_dir_all(download_path.parent().expect("download should have parent"))
        .expect("download parent should be created");
    manifest_with_real_conversion_verified(&manifest_path, heic_path.clone(), b"heic-bytes");
    let manifest_arg = manifest_path
        .to_str()
        .expect("manifest path should be utf8")
        .to_string();
    binary()
        .args([
            "workflow",
            "upload-verified",
            "--manifest",
            &manifest_arg,
            "--asset-id",
            "asset-1",
            "--uploaded-heic-asset-id",
            "icloud-heic-asset-1",
            "--uploaded-heic-sha256",
            &sha256_hex(b"heic-bytes"),
            "--uploaded-heic-path",
            heic_path.to_str().expect("heic path should be utf8"),
        ])
        .assert()
        .success();
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "icloudpd-local-mirror",
            "--manifest",
            &manifest_arg,
            "--asset-id",
            "asset-1",
            "--download-path",
            download_path
                .to_str()
                .expect("download path should be utf8"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("uploaded_heic_path"))
        .stderr(predicate::str::contains("directory"));

    assert_eq!(
        fs::read_to_string(&manifest_path).expect("manifest should remain readable"),
        before
    );
    assert!(!download_path.exists());
}

#[cfg(unix)]
#[test]
fn workflow_icloudpd_local_mirror_rejects_symlink_source_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    let heic_path = tempdir.path().join("staging").join("IMG_0001.heic");
    let target_path = tempdir.path().join("target.HEIC");
    let download_path = tempdir.path().join("PrimarySync").join("IMG_0001.HEIC");
    fs::create_dir_all(heic_path.parent().expect("heic should have parent"))
        .expect("heic parent should be created");
    fs::create_dir_all(download_path.parent().expect("download should have parent"))
        .expect("download parent should be created");
    fs::write(&target_path, b"heic-bytes").expect("symlink target should be written");
    std::os::unix::fs::symlink(&target_path, &heic_path).expect("source symlink should be created");
    manifest_with_real_conversion_verified(&manifest_path, heic_path.clone(), b"heic-bytes");
    let manifest_arg = manifest_path
        .to_str()
        .expect("manifest path should be utf8")
        .to_string();
    binary()
        .args([
            "workflow",
            "upload-verified",
            "--manifest",
            &manifest_arg,
            "--asset-id",
            "asset-1",
            "--uploaded-heic-asset-id",
            "icloud-heic-asset-1",
            "--uploaded-heic-sha256",
            &sha256_hex(b"heic-bytes"),
            "--uploaded-heic-path",
            heic_path.to_str().expect("heic path should be utf8"),
        ])
        .assert()
        .success();
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "icloudpd-local-mirror",
            "--manifest",
            &manifest_arg,
            "--asset-id",
            "asset-1",
            "--download-path",
            download_path
                .to_str()
                .expect("download path should be utf8"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("uploaded_heic_path"))
        .stderr(predicate::str::contains("symlink"));

    assert_eq!(
        fs::read_to_string(&manifest_path).expect("manifest should remain readable"),
        before
    );
    assert!(!download_path.exists());
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
    record_conversion_performance_cli(manifest_arg);
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
            "--visual-content-ok",
            "--visual-match-ok",
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
    record_conversion_performance_cli(manifest_arg);
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
            "--visual-content-ok",
            "--visual-match-ok",
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
        shown["proofs"]["icloudpd_local_mirror"]["uploaded_heic_asset_id"],
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
fn workflow_delete_execute_help_uses_session_without_manual_identity_overrides() {
    let output = binary()
        .args(["workflow", "delete-execute", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let help = String::from_utf8(output).expect("help should be utf8");

    assert!(help.contains("--session"));
    assert!(help.contains("CloudKit delete session"));
    assert!(!help.contains("--record-name"));
    assert!(!help.contains("--record-change-tag"));
}

#[test]
fn workflow_original_asset_resolve_help_exposes_cloudkit_scan_controls() {
    let output = binary()
        .args(["workflow", "original-asset-resolve", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let help = String::from_utf8(output).expect("help should be utf8");

    assert!(help.contains("--manifest"));
    assert!(help.contains("--asset-id"));
    assert!(help.contains("--session"));
    assert!(help.contains("--start-rank"));
    assert!(help.contains("--page-size"));
    assert!(help.contains("--max-pages"));
    assert!(help.contains("--capture-tolerance-seconds"));
    assert!(!help.contains("--record-name"));
    assert!(!help.contains("--record-change-tag"));
}

#[test]
fn workflow_original_assets_resolve_batch_help_exposes_cloudkit_scan_controls() {
    let output = binary()
        .args(["workflow", "original-assets-resolve-batch", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let help = String::from_utf8(output).expect("help should be utf8");

    assert!(help.contains("--manifest"));
    assert!(help.contains("--asset-id"));
    assert!(help.contains("--session"));
    assert!(help.contains("--start-rank"));
    assert!(help.contains("--page-size"));
    assert!(help.contains("--max-pages"));
    assert!(help.contains("--capture-tolerance-seconds"));
    assert!(!help.contains("--record-name"));
    assert!(!help.contains("--record-change-tag"));
}

#[test]
fn workflow_delete_execute_rejects_missing_session_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let (manifest_path, _, _) = manifest_with_real_delete_approval(tempdir.path());
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "delete-execute",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--session",
            tempdir
                .path()
                .join("missing-delete-session.json")
                .to_str()
                .expect("session path should be utf8"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("upload failed"))
        .stderr(predicate::str::contains("missing-delete-session.json"));

    let after = fs::read_to_string(&manifest_path).expect("manifest should remain readable");
    assert_eq!(after, before);
}

#[test]
fn workflow_delete_execute_requires_approved_state_without_mutating_manifest() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let manifest_path = tempdir.path().join("manifest.json");
    manifest_with_nas_verified(&manifest_path);
    let before = fs::read_to_string(&manifest_path).expect("manifest should be readable");

    binary()
        .args([
            "workflow",
            "delete-execute",
            "--manifest",
            manifest_path
                .to_str()
                .expect("manifest path should be utf8"),
            "--asset-id",
            "asset-1",
            "--session",
            tempdir
                .path()
                .join("missing-delete-session.json")
                .to_str()
                .expect("session path should be utf8"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("delete approval required"));

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

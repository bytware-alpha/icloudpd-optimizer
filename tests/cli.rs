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
    ConversionPerformanceInput, ConversionResultProof, HeicVerificationProof, OriginalAssetProof,
    SourceAgeProof, discover_raw_asset, record_conversion_performance, record_conversion_result,
    record_heic_verification, record_nas_proof, record_original_asset_proof,
    record_source_age_proof,
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
if [ "${FAIL_EXIFTOOL:-}" = "1" ]; then
  exit 44
fi
exit 0
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
    let mut manifest = Manifest::load(&manifest_path).expect("manifest should load");
    let nas = manifest.get("asset-1").expect("asset should exist").proofs["nas"].clone();
    record_original_asset_proof(
        &mut manifest,
        "asset-1",
        OriginalAssetProof {
            record_name: "original-record-1".to_string(),
            record_change_tag: "old-change-tag".to_string(),
            record_type: "CPLAsset".to_string(),
            filename: "IMG_0001.dng".to_string(),
            size_bytes: nas["size_bytes"].as_u64().expect("NAS size should be u64"),
            matched_raw_sha256: nas["sha256"]
                .as_str()
                .expect("NAS sha should be a string")
                .to_string(),
        },
    )
    .expect("original asset proof should record");
    manifest
        .save_atomic(&manifest_path)
        .expect("manifest should save");
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
fn setup_and_install_docs_scope_platform_conversion_tools() {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let justfile = fs::read_to_string(repo_root.join("Justfile")).expect("Justfile should exist");
    let readme = fs::read_to_string(repo_root.join("README.md")).expect("README should exist");

    assert!(justfile.contains("Darwin"));
    assert!(justfile.contains("require_tool sips"));
    assert!(justfile.contains("require_tool dcraw_emu"));
    assert!(justfile.contains("require_tool heif-enc"));
    assert!(justfile.contains("Linux workflow convert uses dcraw_emu"));

    assert!(
        readme.contains("`doctor --json` is authoritative for platform-specific required tools")
    );
    assert!(readme.contains("macOS host-native `workflow convert` requirements"));
    assert!(readme.contains("Linux source and OCI installs do not require `sips`"));
    assert!(readme.contains("Linux-native `workflow convert` requirements"));
    assert!(readme.contains("dcraw_emu"));
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
        cfg!(target_os = "macos")
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
        ["dcraw_emu", "heif-enc", "heif-info", "magick", "exiftool"]
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
        "sips"
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
            "conversion tool not found on sanitized PATH: sips",
        ));

    let after_manifest = fs::read_to_string(&manifest_path).expect("manifest should be readable");
    assert_eq!(after_manifest, before_manifest);
    assert!(!output_path.exists());
}

#[cfg(not(target_os = "macos"))]
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

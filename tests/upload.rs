use std::fs;
use std::path::{Path, PathBuf};

use icloudpd_optimizer::upload::{
    IcloudUploadRequest, IcloudUploadResponse, UploadError, build_upload_proof, run_icloud_upload,
};
use icloudpd_optimizer::workflow::HeicVerificationProof;
use sha2::{Digest, Sha256};

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(unix)]
fn write_executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;

    fs::write(path, body).expect("script should be written");
    let mut permissions = fs::metadata(path)
        .expect("script metadata should be readable")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("script should be executable");
}

fn heic_proof(path: PathBuf, bytes: &[u8]) -> HeicVerificationProof {
    HeicVerificationProof {
        heic_path: path,
        heic_sha256: sha256_hex(bytes),
        size_bytes: bytes.len() as u64,
        vipsheader_ok: true,
        metadata_copied: true,
    }
}

#[cfg(unix)]
#[test]
fn run_icloud_upload_invokes_python_helper_and_parses_asset_id() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let fake_python = tempdir.path().join("python");
    let argv_path = tempdir.path().join("argv.txt");
    write_executable(
        &fake_python,
        &format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nprintf '{{\"asset_id\":\"icloud-asset-1\",\"filename\":\"IMG_0001.heic\"}}\\n'\n",
            argv_path.display()
        ),
    );

    let response = run_icloud_upload(&IcloudUploadRequest {
        python: fake_python,
        apple_id: "person@example.com".to_string(),
        heic_path: PathBuf::from("/photos/IMG_0001.heic"),
        album: Some("Optimized".to_string()),
        cookie_directory: Some(PathBuf::from("/config/icloud")),
        accept_terms: true,
    })
    .expect("upload helper should parse");

    assert_eq!(
        response,
        IcloudUploadResponse {
            asset_id: "icloud-asset-1".to_string(),
            filename: Some("IMG_0001.heic".to_string()),
            master_id: None,
        }
    );

    let argv = fs::read_to_string(argv_path).expect("argv should be captured");
    assert!(argv.contains("--apple-id\nperson@example.com\n"));
    assert!(argv.contains("--file\n/photos/IMG_0001.heic\n"));
    assert!(argv.contains("--album\nOptimized\n"));
    assert!(argv.contains("--cookie-directory\n/config/icloud\n"));
    assert!(argv.contains("--accept-terms\n"));
}

#[cfg(unix)]
#[test]
fn run_icloud_upload_rejects_helper_failure() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let fake_python = tempdir.path().join("python");
    write_executable(
        &fake_python,
        "#!/bin/sh\nprintf '{\"error\":\"auth\",\"message\":\"2FA required\"}\\n' >&2\nexit 9\n",
    );

    let error = run_icloud_upload(&IcloudUploadRequest {
        python: fake_python,
        apple_id: "person@example.com".to_string(),
        heic_path: PathBuf::from("/photos/IMG_0001.heic"),
        album: None,
        cookie_directory: None,
        accept_terms: false,
    })
    .expect_err("helper failure should fail closed");

    assert!(matches!(error, UploadError::HelperFailed { .. }));
}

#[cfg(unix)]
#[test]
fn run_icloud_upload_rejects_invalid_json() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let fake_python = tempdir.path().join("python");
    write_executable(&fake_python, "#!/bin/sh\nprintf 'not-json\\n'\n");

    let error = run_icloud_upload(&IcloudUploadRequest {
        python: fake_python,
        apple_id: "person@example.com".to_string(),
        heic_path: PathBuf::from("/photos/IMG_0001.heic"),
        album: None,
        cookie_directory: None,
        accept_terms: false,
    })
    .expect_err("invalid helper JSON should fail closed");

    assert!(matches!(error, UploadError::DecodeHelperJson { .. }));
}

#[test]
fn build_upload_proof_requires_local_heic_to_match_verified_proof() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    let proof = heic_proof(heic_path.clone(), b"heic-bytes");

    let upload_proof = build_upload_proof(
        &proof,
        &IcloudUploadResponse {
            asset_id: "icloud-asset-1".to_string(),
            filename: Some("IMG_0001.heic".to_string()),
            master_id: None,
        },
    )
    .expect("matching HEIC should produce upload proof");

    assert_eq!(upload_proof.uploaded_heic_asset_id, "icloud-asset-1");
    assert_eq!(upload_proof.uploaded_heic_sha256, proof.heic_sha256);
    assert_eq!(upload_proof.uploaded_heic_path, Some(heic_path));
}

#[test]
fn build_upload_proof_rejects_changed_heic_bytes() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    let proof = heic_proof(heic_path, b"HEIC-BYTES");

    let error = build_upload_proof(
        &proof,
        &IcloudUploadResponse {
            asset_id: "icloud-asset-1".to_string(),
            filename: Some("IMG_0001.heic".to_string()),
            master_id: None,
        },
    )
    .expect_err("changed HEIC bytes should fail closed");

    assert!(matches!(error, UploadError::HeicHashMismatch { .. }));
}

#[test]
fn build_upload_proof_rejects_empty_uploaded_asset_id() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    let proof = heic_proof(heic_path, b"heic-bytes");

    let error = build_upload_proof(
        &proof,
        &IcloudUploadResponse {
            asset_id: "   ".to_string(),
            filename: Some("IMG_0001.heic".to_string()),
            master_id: None,
        },
    )
    .expect_err("empty uploaded asset id should fail closed");

    assert!(matches!(error, UploadError::MissingUploadedAssetId));
}

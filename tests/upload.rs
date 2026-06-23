use std::fs;
use std::path::{Path, PathBuf};

use icloudpd_optimizer::upload::{
    IcloudUploadOutcome, IcloudUploadRequest, IcloudUploadResponse, UploadError, UploadSession,
    build_upload_proof, load_upload_session, run_icloud_upload,
};
use icloudpd_optimizer::workflow::HeicVerificationProof;
use sha2::{Digest, Sha256};

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn heic_proof(path: PathBuf, bytes: &[u8]) -> HeicVerificationProof {
    HeicVerificationProof {
        heic_path: path,
        heic_sha256: sha256_hex(bytes),
        size_bytes: bytes.len() as u64,
        heif_info_ok: true,
        metadata_copied: true,
        visual_content_ok: true,
        visual_match_ok: true,
    }
}

fn write_session(path: &Path, body: &str) {
    fs::write(path, body).expect("session should be written");
}

fn valid_session_json() -> String {
    serde_json::json!({
        "dsid": "123456789",
        "upload_url": "https://upload.icloud.com/uploadimagews",
        "cookies": [
            {"name": "X-APPLE-WEBAUTH-TOKEN", "value": "token"},
            {"name": "session", "value": "abc123"}
        ]
    })
    .to_string()
}

#[test]
fn load_upload_session_rejects_malformed_json() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let session_path = tempdir.path().join("session.json");
    write_session(&session_path, "{not-json");

    let error = load_upload_session(&session_path).expect_err("bad JSON should fail closed");

    assert!(matches!(error, UploadError::DecodeSession { .. }));
}

#[test]
fn load_upload_session_rejects_insecure_or_smuggled_endpoints() {
    let cases = [
        "http://upload.icloud.com/uploadimagews",
        "https://user:pass@upload.icloud.com/uploadimagews",
        "https://upload.icloud.com/uploadimagews?next=https://evil.example",
        "https://upload.icloud.com/uploadimagews#fragment",
        "https://evil.example/uploadimagews",
        "https://setup.icloud.com/setup/ws/1/accountLogin",
        "https://www.icloud.com/",
        "https://upload.icloud.com/uploadimagews/other",
    ];

    for upload_url in cases {
        let json = serde_json::json!({
            "dsid": "123456789",
            "upload_url": upload_url,
            "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "token"}]
        })
        .to_string();

        let error = UploadSession::from_json(&json).expect_err("endpoint should be rejected");

        assert!(
            matches!(error, UploadError::InvalidSession(_)),
            "{upload_url} returned {error:?}"
        );
    }
}

#[test]
fn load_upload_session_accepts_webservices_uploadimagews_url() {
    let json = serde_json::json!({
        "dsid": "123456789",
        "webservices": {
            "uploadimagews": {"url": "https://upload.icloud.com/uploadimagews"}
        },
        "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "token"}]
    })
    .to_string();

    let session = UploadSession::from_json(&json).expect("webservices URL should be supported");

    assert_eq!(
        session.upload_url.as_str(),
        "https://upload.icloud.com/uploadimagews"
    );
}

#[test]
fn load_upload_session_accepts_current_uploadimagews_origin_url() {
    let json = serde_json::json!({
        "dsid": "123456789",
        "upload_url": "https://p140-uploadimagews.icloud.com:443",
        "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "token"}]
    })
    .to_string();

    let session =
        UploadSession::from_json(&json).expect("origin uploadimagews URL should be supported");

    assert_eq!(
        session.upload_url.as_str(),
        "https://p140-uploadimagews.icloud.com/"
    );
}

#[test]
fn load_upload_session_rejects_hostile_cookies_and_missing_auth_cookie() {
    let cases = [
        vec![("X-APPLE-WEBAUTH-TOKEN", "token\r\nInjected: yes")],
        vec![("X-APPLE-WEBAUTH-TOKEN", "token; admin=true")],
        vec![("bad\nname", "token")],
        vec![("bad name", "token")],
        vec![("bad,name", "token")],
        vec![(" bad", "token")],
        vec![("bad ", "token")],
        vec![("X-APPLE-WEBAUTH-TOKEN", " token")],
        vec![("X-APPLE-WEBAUTH-TOKEN", "token ")],
        vec![("session", "abc123")],
    ];

    for cookies in cases {
        let cookies: Vec<_> = cookies
            .into_iter()
            .map(|(name, value)| serde_json::json!({"name": name, "value": value}))
            .collect();
        let json = serde_json::json!({
            "dsid": "123456789",
            "upload_url": "https://upload.icloud.com/uploadimagews",
            "cookies": cookies
        })
        .to_string();

        let error = UploadSession::from_json(&json).expect_err("cookie should be rejected");

        assert!(matches!(error, UploadError::InvalidSession(_)));
    }
}

#[test]
fn load_upload_session_rejects_non_numeric_or_padded_dsid() {
    let cases = ["", "   ", "123 456", "abc123", "123\n456"];

    for dsid in cases {
        let json = serde_json::json!({
            "dsid": dsid,
            "upload_url": "https://upload.icloud.com/uploadimagews",
            "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "token"}]
        })
        .to_string();

        let error = UploadSession::from_json(&json).expect_err("DSID should be rejected");

        assert!(
            matches!(error, UploadError::InvalidSession(_)),
            "{dsid:?} returned {error:?}"
        );
    }
}

#[test]
fn run_icloud_upload_fails_closed_for_valid_session_and_heic() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let session_path = tempdir.path().join("session.json");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    write_session(&session_path, &valid_session_json());
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");

    let error = run_icloud_upload(&IcloudUploadRequest {
        session_path,
        heic_path,
    })
    .expect_err("direct iCloud Photos upload must fail closed until CloudKit support exists");

    assert!(matches!(
        error,
        UploadError::UnsupportedIcloudUploadProtocol
    ));
}

#[test]
fn run_icloud_upload_rejects_empty_heic_before_unsupported_protocol() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let session_path = tempdir.path().join("session.json");
    let empty_heic = tempdir.path().join("IMG_0001.heic");
    write_session(&session_path, &valid_session_json());
    fs::write(&empty_heic, b"").expect("empty heic should be written");

    let error = run_icloud_upload(&IcloudUploadRequest {
        session_path,
        heic_path: empty_heic,
    })
    .expect_err("empty HEIC fails");

    assert!(matches!(error, UploadError::EmptyHeic { .. }));
}

#[cfg(unix)]
#[test]
fn run_icloud_upload_rejects_non_utf8_filename_before_filesystem_access() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let session_path = tempdir.path().join("session.json");
    write_session(&session_path, &valid_session_json());
    let name = OsString::from_vec(vec![
        b'I', b'M', b'G', b'_', 0xff, b'.', b'h', b'e', b'i', b'c',
    ]);
    let heic_path = tempdir.path().join(name);

    let error = run_icloud_upload(&IcloudUploadRequest {
        session_path,
        heic_path,
    })
    .expect_err("non-UTF8 filename should fail before filesystem access");

    assert!(matches!(error, UploadError::InvalidFilename { .. }));
}

#[test]
fn build_upload_proof_rejects_when_streamed_bytes_differ_even_if_path_is_restored() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"verified-bytes").expect("heic should be written");
    let proof = heic_proof(heic_path.clone(), b"verified-bytes");
    fs::write(&heic_path, b"swapped!-bytes").expect("race should swap heic before upload");
    let upload = icloud_upload_for_bytes("icloud-asset-1", b"swapped!-bytes");
    fs::write(&heic_path, b"verified-bytes").expect("race should restore heic after upload");

    let error = build_upload_proof(&proof, &upload)
        .expect_err("streamed bytes must match verified HEIC proof");

    assert!(matches!(
        error,
        UploadError::StreamedHeicHashMismatch { .. }
    ));
    assert!(!error.to_string().contains(&sha256_hex(b"verified-bytes")));
    assert!(!error.to_string().contains(&sha256_hex(b"swapped!-bytes")));
}

#[test]
fn build_upload_proof_requires_local_heic_to_match_verified_proof() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    let proof = heic_proof(heic_path.clone(), b"heic-bytes");

    let upload_proof = build_upload_proof(
        &proof,
        &icloud_upload_for_bytes("icloud-asset-1", b"heic-bytes"),
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
        &icloud_upload_for_bytes("icloud-asset-1", b"HEIC-BYTES"),
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

    let error = build_upload_proof(&proof, &icloud_upload_for_bytes("   ", b"heic-bytes"))
        .expect_err("empty uploaded asset id should fail closed");

    assert!(matches!(error, UploadError::MissingUploadedAssetId));
}

fn icloud_upload_for_bytes(asset_id: impl Into<String>, bytes: &[u8]) -> IcloudUploadOutcome {
    IcloudUploadOutcome {
        response: IcloudUploadResponse {
            asset_id: asset_id.into(),
            filename: Some("IMG_0001.heic".to_string()),
            master_id: None,
        },
        streamed_heic_sha256: sha256_hex(bytes),
        streamed_size_bytes: bytes.len() as u64,
    }
}

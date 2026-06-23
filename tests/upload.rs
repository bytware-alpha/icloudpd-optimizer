use std::fs;
use std::path::{Path, PathBuf};

use icloudpd_optimizer::upload::{
    IcloudUploadOutcome, IcloudUploadRequest, IcloudUploadResponse, PhotosUploadClient,
    PhotosUploadEndpoint, PhotosUploadTransport, SingleFileUploadRequest, UploadError,
    UploadSession, build_upload_proof, load_upload_session, run_icloud_upload,
};
use icloudpd_optimizer::workflow::HeicVerificationProof;
use serde_json::{Value, json};
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
        "photosupload_url": "https://p140-photosupload.icloud.com:443",
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
        "http://photosupload.icloud.com",
        "https://user:pass@photosupload.icloud.com",
        "https://photosupload.icloud.com?next=https://evil.example",
        "https://photosupload.icloud.com#fragment",
        "https://evil.example",
        "https://setup.icloud.com/setup/ws/1/accountLogin",
        "https://www.icloud.com/",
        "https://p140-uploadimagews.icloud.com:443",
    ];

    for photosupload_url in cases {
        let json = serde_json::json!({
            "dsid": "123456789",
            "photosupload_url": photosupload_url,
            "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "token"}]
        })
        .to_string();

        let error = UploadSession::from_json(&json).expect_err("endpoint should be rejected");

        assert!(
            matches!(error, UploadError::InvalidSession(_)),
            "{photosupload_url} returned {error:?}"
        );
    }
}

#[test]
fn load_upload_session_rejects_legacy_uploadimagews_without_photosupload() {
    let json = serde_json::json!({
        "dsid": "123456789",
        "webservices": {
            "uploadimagews": {"url": "https://p140-uploadimagews.icloud.com:443"}
        },
        "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "token"}]
    })
    .to_string();

    let error = UploadSession::from_json(&json).expect_err("legacy uploadimagews is not enough");

    assert!(matches!(error, UploadError::InvalidSession(_)));
    assert!(error.to_string().contains("photosupload"));
}

#[test]
fn load_upload_session_accepts_webservices_photosupload_url() {
    let json = serde_json::json!({
        "dsid": "123456789",
        "webservices": {
            "photosupload": {"url": "https://p140-photosupload.icloud.com:443"}
        },
        "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "token"}]
    })
    .to_string();

    let session = UploadSession::from_json(&json).expect("webservices URL should be supported");

    assert_eq!(
        session.photosupload_url.as_str(),
        "https://p140-photosupload.icloud.com/"
    );
}

#[test]
fn load_upload_session_accepts_current_photosupload_origin_url() {
    let json = serde_json::json!({
        "dsid": "123456789",
        "photosupload_url": "https://p140-photosupload.icloud.com:443",
        "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "token"}]
    })
    .to_string();

    let session =
        UploadSession::from_json(&json).expect("origin photosupload URL should be supported");

    assert_eq!(
        session.photosupload_url.as_str(),
        "https://p140-photosupload.icloud.com/"
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
            "photosupload_url": "https://p140-photosupload.icloud.com:443",
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
            "photosupload_url": "https://p140-photosupload.icloud.com:443",
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
fn photos_upload_client_posts_v2_upload_sequence_and_returns_cpl_asset_id() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    let session = UploadSession::from_json(&valid_session_json()).expect("session should load");
    let mut transport = FakePhotosTransport::success();

    let outcome = PhotosUploadClient::new(&mut transport)
        .with_status_poll_delay(std::time::Duration::ZERO)
        .upload_heic(&session, &heic_path)
        .expect("V2 upload should succeed");

    assert_eq!(outcome.response.asset_id, "CPLAsset-123");
    assert_eq!(outcome.response.master_id.as_deref(), Some("CPLMaster-123"));
    assert_eq!(outcome.response.filename.as_deref(), Some("IMG_0001.heic"));
    assert_eq!(outcome.streamed_heic_sha256, sha256_hex(b"heic-bytes"));
    assert_eq!(outcome.streamed_size_bytes, b"heic-bytes".len() as u64);

    assert_eq!(transport.service_calls.len(), 3);
    assert_eq!(
        transport.service_calls[0].0,
        PhotosUploadEndpoint::CreateUploadUrl
    );
    assert_eq!(
        transport.service_calls[0].1["zoneName"],
        json!("PrimarySync")
    );
    let assets = transport.service_calls[0].1["assets"]
        .as_object()
        .expect("assets should be object");
    assert_eq!(assets.len(), 1);
    assert_eq!(assets.values().next(), Some(&json!(b"heic-bytes".len())));
    assert_eq!(
        transport.uploaded_urls,
        vec!["https://p140-uploadws.icloud.com/upload"]
    );
    assert_eq!(transport.service_calls[1].0, PhotosUploadEndpoint::PutAsset);
    assert_eq!(
        transport.service_calls[1].1["zoneName"],
        json!("PrimarySync")
    );
    assert_eq!(
        transport.service_calls[1].1["files"][0]["fileName"],
        json!("IMG_0001.heic")
    );
    assert_eq!(
        transport.service_calls[1].1["files"][0]["singleFileUploadRequest"]["receipt"],
        json!("receipt-123")
    );
    assert_eq!(
        transport.service_calls[2].0,
        PhotosUploadEndpoint::UploadStatus
    );
    assert_eq!(
        transport.service_calls[2].1,
        json!({"uploadJobIds": ["job-123"]})
    );
}

#[test]
fn photos_upload_client_rejects_signed_upload_size_mismatch_before_put_asset() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    let session = UploadSession::from_json(&valid_session_json()).expect("session should load");
    let mut transport = FakePhotosTransport::success();
    transport.single_file.size_bytes = 1;

    let error = PhotosUploadClient::new(&mut transport)
        .with_status_poll_delay(std::time::Duration::ZERO)
        .upload_heic(&session, &heic_path)
        .expect_err("server size mismatch should fail closed");

    assert!(matches!(
        error,
        UploadError::SignedUploadSizeMismatch { .. }
    ));
    assert_eq!(transport.service_calls.len(), 1);
}

#[test]
fn photos_upload_client_rejects_upload_status_error() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    let session = UploadSession::from_json(&valid_session_json()).expect("session should load");
    let mut transport = FakePhotosTransport::success();
    transport.status_response = json!({"job-123": {"errorCode": 415}});

    let error = PhotosUploadClient::new(&mut transport)
        .with_status_poll_delay(std::time::Duration::ZERO)
        .upload_heic(&session, &heic_path)
        .expect_err("status errors should fail closed");

    assert!(matches!(
        error,
        UploadError::PhotosUploadStatusFailed { error_code: 415 }
    ));
}

#[test]
fn photos_upload_client_rejects_unknown_terminal_status_even_with_complete_progress() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    let session = UploadSession::from_json(&valid_session_json()).expect("session should load");
    let mut transport = FakePhotosTransport::success();
    transport.status_response = json!({"job-123": {"status": "FAILED", "progress": 100}});

    let error = PhotosUploadClient::new(&mut transport)
        .with_status_poll_delay(std::time::Duration::ZERO)
        .upload_heic(&session, &heic_path)
        .expect_err("unknown terminal statuses should fail closed");

    assert!(matches!(
        error,
        UploadError::PhotosUploadStatusFailed { error_code: 0 }
    ));
}

#[test]
fn photos_upload_client_accepts_put_asset_success_with_response_status() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    let session = UploadSession::from_json(&valid_session_json()).expect("session should load");
    let mut transport = FakePhotosTransport::success();
    transport.put_asset_response = json!([{
        "uploadJobId": "job-123",
        "cplMaster": "CPLMaster-123",
        "cplAsset": "CPLAsset-123",
        "response": {"status": 200}
    }]);

    let outcome = PhotosUploadClient::new(&mut transport)
        .with_status_poll_delay(std::time::Duration::ZERO)
        .upload_heic(&session, &heic_path)
        .expect("putAsset success objects may include response status");

    assert_eq!(outcome.response.asset_id, "CPLAsset-123");
}

#[test]
fn photos_upload_client_rejects_put_asset_error_status_even_with_asset_fields() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    let session = UploadSession::from_json(&valid_session_json()).expect("session should load");
    let mut transport = FakePhotosTransport::success();
    transport.put_asset_response = json!([{
        "uploadJobId": "job-123",
        "cplMaster": "CPLMaster-123",
        "cplAsset": "CPLAsset-123",
        "response": {"status": 500}
    }]);

    let error = PhotosUploadClient::new(&mut transport)
        .with_status_poll_delay(std::time::Duration::ZERO)
        .upload_heic(&session, &heic_path)
        .expect_err("embedded putAsset error status should fail closed");

    assert!(matches!(
        error,
        UploadError::PhotosPutAssetRejected { status: 500 }
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

struct FakePhotosTransport {
    service_calls: Vec<(PhotosUploadEndpoint, Value)>,
    uploaded_urls: Vec<String>,
    single_file: SingleFileUploadRequest,
    put_asset_response: Value,
    status_response: Value,
}

impl FakePhotosTransport {
    fn success() -> Self {
        Self {
            service_calls: Vec::new(),
            uploaded_urls: Vec::new(),
            single_file: SingleFileUploadRequest {
                file_checksum: "file-checksum-123".to_string(),
                size_bytes: b"heic-bytes".len() as u64,
                wrapping_key: None,
                reference_checksum: "reference-checksum-123".to_string(),
                receipt: "receipt-123".to_string(),
            },
            put_asset_response: json!([{
                "uploadJobId": "job-123",
                "cplMaster": "CPLMaster-123",
                "cplAsset": "CPLAsset-123"
            }]),
            status_response: json!({"job-123": {"progress": 100}}),
        }
    }
}

impl PhotosUploadTransport for FakePhotosTransport {
    fn post_service_json(
        &mut self,
        _session: &UploadSession,
        endpoint: PhotosUploadEndpoint,
        payload: Value,
    ) -> Result<Value, UploadError> {
        self.service_calls.push((endpoint, payload));
        match endpoint {
            PhotosUploadEndpoint::CreateUploadUrl => Ok(json!({
                "uploadUrls": {
                    "uuid-123": "https://p140-uploadws.icloud.com/upload"
                }
            })),
            PhotosUploadEndpoint::PutAsset => Ok(self.put_asset_response.clone()),
            PhotosUploadEndpoint::UploadStatus => Ok(self.status_response.clone()),
        }
    }

    fn post_signed_upload(
        &mut self,
        _session: &UploadSession,
        upload_url: &url::Url,
        heic_path: &Path,
    ) -> Result<(SingleFileUploadRequest, String, u64), UploadError> {
        self.uploaded_urls.push(upload_url.as_str().to_string());
        let bytes = fs::read(heic_path).expect("fake upload should read HEIC");
        Ok((
            self.single_file.clone(),
            sha256_hex(&bytes),
            bytes.len() as u64,
        ))
    }
}

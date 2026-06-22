use std::cell::RefCell;
use std::fs;
use std::path::{Path, PathBuf};

use icloudpd_optimizer::upload::{
    IcloudUploadResponse, UploadError, UploadHttpRequest, UploadHttpResponse, UploadSession,
    UploadTransport, build_upload_proof, load_upload_session, upload_with_transport,
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
        vipsheader_ok: true,
        metadata_copied: true,
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

#[derive(Default)]
struct FakeTransport {
    response_body: String,
    requests: RefCell<Vec<UploadHttpRequest>>,
}

impl FakeTransport {
    fn with_response(response_body: impl Into<String>) -> Self {
        Self {
            response_body: response_body.into(),
            requests: RefCell::new(Vec::new()),
        }
    }
}

impl UploadTransport for FakeTransport {
    fn post(&self, request: UploadHttpRequest) -> Result<UploadHttpResponse, UploadError> {
        self.requests.borrow_mut().push(request);
        Ok(UploadHttpResponse {
            status: 200,
            body: self.response_body.clone(),
        })
    }
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
fn load_upload_session_rejects_hostile_cookies_and_missing_auth_cookie() {
    let cases = [
        vec![("X-APPLE-WEBAUTH-TOKEN", "token\r\nInjected: yes")],
        vec![("X-APPLE-WEBAUTH-TOKEN", "token; admin=true")],
        vec![("bad\nname", "token")],
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
fn upload_with_transport_posts_encoded_filename_and_parses_records() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG 0001+#.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    let session = UploadSession::from_json(&valid_session_json()).expect("session should load");
    let transport = FakeTransport::with_response(
        serde_json::json!({
            "records": [
                {"recordType": "CPLMaster", "recordName": "master-1"},
                {"recordType": "CPLAsset", "recordName": "asset-1"}
            ]
        })
        .to_string(),
    );

    let response =
        upload_with_transport(&session, &heic_path, &transport).expect("upload should parse");

    assert_eq!(
        response,
        IcloudUploadResponse {
            asset_id: "asset-1".to_string(),
            filename: Some("IMG 0001+#.heic".to_string()),
            master_id: Some("master-1".to_string()),
        }
    );
    let requests = transport.requests.borrow();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].content_len, b"heic-bytes".len() as u64);
    assert_eq!(requests[0].body_path, heic_path);
    assert_eq!(
        requests[0].url,
        "https://upload.icloud.com/uploadimagews/upload?dsid=123456789&filename=IMG+0001%2B%23.heic"
    );
    assert_eq!(
        requests[0].cookie_header,
        "X-APPLE-WEBAUTH-TOKEN=token; session=abc123"
    );
}

#[test]
fn upload_with_transport_fails_on_response_errors_or_missing_asset_record() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    let session = UploadSession::from_json(&valid_session_json()).expect("session should load");

    let upload_error = FakeTransport::with_response(
        serde_json::json!({"errors": [{"reason": "quota", "message": "full"}]}).to_string(),
    );
    let error = upload_with_transport(&session, &heic_path, &upload_error)
        .expect_err("upload errors should fail");
    assert!(matches!(error, UploadError::UploadResponseErrors(_)));

    let no_asset = FakeTransport::with_response(
        serde_json::json!({"records": [{"recordType": "CPLMaster", "recordName": "master-1"}]})
            .to_string(),
    );
    let error = upload_with_transport(&session, &heic_path, &no_asset)
        .expect_err("missing CPLAsset should fail");
    assert!(matches!(error, UploadError::MissingUploadedAssetId));
}

#[test]
fn upload_with_transport_rejects_bad_local_file_inputs() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let empty_heic = tempdir.path().join("IMG_0001.heic");
    fs::write(&empty_heic, b"").expect("empty heic should be written");
    let session = UploadSession::from_json(&valid_session_json()).expect("session should load");
    let transport = FakeTransport::default();

    let error =
        upload_with_transport(&session, &empty_heic, &transport).expect_err("empty HEIC fails");

    assert!(matches!(error, UploadError::EmptyHeic { .. }));
    assert!(transport.requests.borrow().is_empty());
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn upload_with_transport_rejects_non_utf8_filename_without_posting() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let name = OsString::from_vec(vec![
        b'I', b'M', b'G', b'_', 0xff, b'.', b'h', b'e', b'i', b'c',
    ]);
    let heic_path = tempdir.path().join(name);
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    let session = UploadSession::from_json(&valid_session_json()).expect("session should load");
    let transport = FakeTransport::default();

    let error = upload_with_transport(&session, &heic_path, &transport)
        .expect_err("non-UTF8 filename should fail");

    assert!(matches!(error, UploadError::InvalidFilename { .. }));
    assert!(transport.requests.borrow().is_empty());
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

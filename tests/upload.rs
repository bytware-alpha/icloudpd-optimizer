use std::cell::RefCell;
use std::fs;
use std::io::Read;
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
    fn post(
        &self,
        request: UploadHttpRequest,
        mut body: Box<dyn Read + Send>,
    ) -> Result<UploadHttpResponse, UploadError> {
        let mut uploaded = Vec::new();
        body.read_to_end(&mut uploaded)
            .expect("fake transport should read upload body");
        self.requests.borrow_mut().push(request);
        Ok(UploadHttpResponse {
            status: 200,
            body: self.response_body.clone(),
        })
    }
}

struct BodyCapturingTransport {
    response_body: String,
    uploaded_bodies: RefCell<Vec<Vec<u8>>>,
}

impl BodyCapturingTransport {
    fn with_response(response_body: impl Into<String>) -> Self {
        Self {
            response_body: response_body.into(),
            uploaded_bodies: RefCell::new(Vec::new()),
        }
    }
}

impl UploadTransport for BodyCapturingTransport {
    fn post(
        &self,
        _request: UploadHttpRequest,
        mut body: Box<dyn Read + Send>,
    ) -> Result<UploadHttpResponse, UploadError> {
        let mut uploaded = Vec::new();
        body.read_to_end(&mut uploaded)
            .expect("fake transport should read upload body");
        self.uploaded_bodies.borrow_mut().push(uploaded);
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
        response.response,
        IcloudUploadResponse {
            asset_id: "asset-1".to_string(),
            filename: Some("IMG 0001+#.heic".to_string()),
            master_id: Some("master-1".to_string()),
        }
    );
    assert_eq!(response.streamed_heic_sha256, sha256_hex(b"heic-bytes"));
    assert_eq!(response.streamed_size_bytes, b"heic-bytes".len() as u64);
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
        serde_json::json!({
            "errors": [{
                "reason": "quota",
                "message": "secret-response-token 123456789 IMG_0001.heic"
            }]
        })
        .to_string(),
    );
    let error = upload_with_transport(&session, &heic_path, &upload_error)
        .expect_err("upload errors should fail");
    assert!(matches!(error, UploadError::UploadResponseErrors(_)));
    let shown = error.to_string();
    assert!(!shown.contains("secret-response-token"));
    assert!(!shown.contains("123456789"));
    assert!(!shown.contains("IMG_0001.heic"));

    let no_asset = FakeTransport::with_response(
        serde_json::json!({"records": [{"recordType": "CPLMaster", "recordName": "master-1"}]})
            .to_string(),
    );
    let error = upload_with_transport(&session, &heic_path, &no_asset)
        .expect_err("missing CPLAsset should fail");
    assert!(matches!(error, UploadError::MissingUploadedAssetId));
}

#[test]
fn upload_with_transport_redacts_invalid_and_oversized_response_bodies() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    let session = UploadSession::from_json(&valid_session_json()).expect("session should load");

    let invalid = FakeTransport::with_response("not-json secret-response-token 123456789");
    let error = upload_with_transport(&session, &heic_path, &invalid)
        .expect_err("invalid response JSON should fail");
    assert!(matches!(error, UploadError::DecodeUploadJson { .. }));
    let shown = error.to_string();
    assert!(!shown.contains("secret-response-token"));
    assert!(!shown.contains("123456789"));

    let oversized_body = format!("{}{}", "secret-response-token", "x".repeat(70 * 1024));
    let oversized = FakeTransport::with_response(oversized_body);
    let error = upload_with_transport(&session, &heic_path, &oversized)
        .expect_err("oversized response should fail");
    assert!(matches!(error, UploadError::UploadResponseTooLarge { .. }));
    assert!(!error.to_string().contains("secret-response-token"));
}

#[test]
fn build_upload_proof_rejects_when_streamed_bytes_differ_even_if_path_is_restored() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"verified-bytes").expect("heic should be written");
    let proof = heic_proof(heic_path.clone(), b"verified-bytes");
    fs::write(&heic_path, b"swapped!-bytes").expect("race should swap heic before upload");
    let transport = BodyCapturingTransport::with_response(
        serde_json::json!({
            "records": [{"recordType": "CPLAsset", "recordName": "asset-1"}]
        })
        .to_string(),
    );
    let session = UploadSession::from_json(&valid_session_json()).expect("session should load");

    let upload = upload_with_transport(&session, &heic_path, &transport)
        .expect("swapped bytes can still produce an upload response");
    fs::write(&heic_path, b"verified-bytes").expect("race should restore heic after upload");

    assert_eq!(transport.uploaded_bodies.borrow()[0], b"swapped!-bytes");
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

#[cfg(unix)]
#[test]
fn upload_with_transport_rejects_non_utf8_filename_without_posting() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let name = OsString::from_vec(vec![
        b'I', b'M', b'G', b'_', 0xff, b'.', b'h', b'e', b'i', b'c',
    ]);
    let heic_path = tempdir.path().join(name);
    let session = UploadSession::from_json(&valid_session_json()).expect("session should load");
    let transport = FakeTransport::default();

    let error = upload_with_transport(&session, &heic_path, &transport)
        .expect_err("non-UTF8 filename should fail before filesystem access");

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

fn icloud_upload_for_bytes(
    asset_id: impl Into<String>,
    bytes: &[u8],
) -> icloudpd_optimizer::upload::IcloudUploadOutcome {
    icloudpd_optimizer::upload::IcloudUploadOutcome {
        response: IcloudUploadResponse {
            asset_id: asset_id.into(),
            filename: Some("IMG_0001.heic".to_string()),
            master_id: None,
        },
        streamed_heic_sha256: sha256_hex(bytes),
        streamed_size_bytes: bytes.len() as u64,
    }
}

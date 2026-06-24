use std::fs;
use std::path::{Path, PathBuf};

use icloudpd_optimizer::upload::{
    CloudKitDeleteClient, CloudKitDeleteRequest, CloudKitDeleteSession, CloudKitDeleteTransport,
    CloudKitOriginalAssetResolveRequest, IcloudUploadOutcome, IcloudUploadRequest,
    IcloudUploadResponse, PhotosUploadClient, PhotosUploadEndpoint, PhotosUploadTransport,
    SingleFileUploadRequest, UploadError, UploadSession, build_upload_proof, load_upload_session,
    run_icloud_upload,
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

fn valid_cloudkit_query_params() -> Vec<Value> {
    vec![
        json!({"name": "clientBuildNumber", "value": "2522Project44"}),
        json!({"name": "clientMasteringNumber", "value": "2522B2"}),
        json!({"name": "clientId", "value": "4f0b58d4-ff9d-4dc5-8f0b-9c4efc4fdb27"}),
        json!({"name": "dsid", "value": "123456789"}),
        json!({"name": "remapEnums", "value": "True"}),
        json!({"name": "getCurrentSyncToken", "value": "True"}),
    ]
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

fn valid_delete_session_json() -> String {
    serde_json::json!({
        "dsid": "123456789",
        "ckdatabasews_url": "https://p140-ckdatabasews.icloud.com:443",
        "cloudkit_query_params": valid_cloudkit_query_params(),
        "cookies": [
            {"name": "X-APPLE-WEBAUTH-TOKEN", "value": "web-auth-token"},
            {"name": "session", "value": "abc123"}
        ]
    })
    .to_string()
}

fn cloudkit_raw_pair(asset_name: &str, master_name: &str, change_tag: &str) -> Value {
    json!([
        {
            "recordName": asset_name,
            "recordType": "CPLAsset",
            "recordChangeTag": change_tag,
            "fields": {
                "masterRef": {"value": {"recordName": master_name}},
                "assetDate": {"value": 1_800_000_000_000_i64}
            }
        },
        {
            "recordName": master_name,
            "recordType": "CPLMaster",
            "fields": {
                "resOriginalRes": {
                    "value": {
                        "size": 42
                    }
                },
                "resOriginalFileType": {"value": "com.adobe.raw-image"},
                "resOriginalFingerprint": {"value": "fingerprint-123"},
                "resOriginalWidth": {"value": 8064},
                "resOriginalHeight": {"value": 6048}
            }
        }
    ])
}

fn original_asset_resolve_request() -> CloudKitOriginalAssetResolveRequest {
    CloudKitOriginalAssetResolveRequest {
        raw_size_bytes: 42,
        source_captured_unix_seconds: 1_800_000_000,
        capture_tolerance_seconds: 2,
        filename: "IMG_0001.dng".to_string(),
        matched_raw_sha256: "raw-sha256".to_string(),
        start_rank: 0,
        page_size: 200,
        max_pages: 100,
    }
}

#[test]
fn load_cloudkit_delete_session_accepts_current_ckdatabasews_origin_url() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("CloudKit delete session should load");

    assert_eq!(session.dsid, "123456789");
    assert_eq!(
        session.ckdatabasews_url.as_str(),
        "https://p140-ckdatabasews.icloud.com/"
    );
    assert_eq!(session.cloudkit_query_params.len(), 6);
    assert_eq!(session.cloudkit_query_params[0].name, "clientBuildNumber");
    assert_eq!(session.cloudkit_query_params[0].value, "2522Project44");
    assert_eq!(session.cookies.len(), 2);
}

#[test]
fn load_cloudkit_delete_session_accepts_webservices_ckdatabasews_url() {
    let json = serde_json::json!({
        "dsid": "123456789",
        "cloudkit_query_params": valid_cloudkit_query_params(),
        "webservices": {
            "ckdatabasews": {"url": "https://p140-ckdatabasews.icloud.com:443"}
        },
        "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "web-auth-token"}]
    })
    .to_string();

    let session = CloudKitDeleteSession::from_json(&json)
        .expect("webservices CloudKit URL should be supported");

    assert_eq!(
        session.ckdatabasews_url.as_str(),
        "https://p140-ckdatabasews.icloud.com/"
    );
}

#[test]
fn load_cloudkit_delete_session_fails_closed_on_missing_auth_material_or_bad_endpoint() {
    let cases = [
        serde_json::json!({
            "ckdatabasews_url": "https://p140-ckdatabasews.icloud.com:443",
            "cloudkit_query_params": valid_cloudkit_query_params(),
            "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "web-auth-token"}]
        }),
        serde_json::json!({
            "dsid": "123456789",
            "ckdatabasews_url": "https://p140-ckdatabasews.icloud.com:443",
            "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "web-auth-token"}]
        }),
        serde_json::json!({
            "dsid": "123456789",
            "ckdatabasews_url": "https://p140-ckdatabasews.icloud.com:443",
            "cloudkit_query_params": valid_cloudkit_query_params()
        }),
        serde_json::json!({
            "dsid": "123456789",
            "ckdatabasews_url": "https://evil.example",
            "cloudkit_query_params": valid_cloudkit_query_params(),
            "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "web-auth-token"}]
        }),
        serde_json::json!({
            "dsid": "123456789",
            "ckdatabasews_url": "https://p140-photosupload.icloud.com:443",
            "cloudkit_query_params": valid_cloudkit_query_params(),
            "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "web-auth-token"}]
        }),
    ];

    for body in cases {
        let error = CloudKitDeleteSession::from_json(&body.to_string())
            .expect_err("invalid delete session should fail closed");

        assert!(
            matches!(error, UploadError::InvalidSession(_)),
            "{body} returned {error:?}"
        );
        assert!(!error.to_string().contains("web-auth-token"));
        assert!(!error.to_string().contains("2522Project44"));
    }
}

#[test]
fn load_cloudkit_delete_session_rejects_incomplete_duplicate_or_smuggled_query_params() {
    let mut missing_required = valid_cloudkit_query_params();
    missing_required.retain(|param| param["name"] != "clientMasteringNumber");

    let mut duplicate = valid_cloudkit_query_params();
    duplicate.push(json!({"name": "clientBuildNumber", "value": "2522Project45"}));

    let mut unknown = valid_cloudkit_query_params();
    unknown.push(json!({"name": "ckWebAuthToken", "value": "legacy-token"}));

    let mut smuggled_name = valid_cloudkit_query_params();
    smuggled_name[0] =
        json!({"name": "clientBuildNumber&ckWebAuthToken", "value": "2522Project44"});

    let mut smuggled_value = valid_cloudkit_query_params();
    smuggled_value[0] =
        json!({"name": "clientBuildNumber", "value": "2522Project44&ckWebAuthToken=legacy-token"});

    let mut control_value = valid_cloudkit_query_params();
    control_value[0] =
        json!({"name": "clientBuildNumber", "value": "2522Project44\nInjected: yes"});

    let mut mismatched_dsid = valid_cloudkit_query_params();
    mismatched_dsid[3] = json!({"name": "dsid", "value": "987654321"});

    let cases = [
        missing_required,
        duplicate,
        unknown,
        smuggled_name,
        smuggled_value,
        control_value,
        mismatched_dsid,
    ];

    for cloudkit_query_params in cases {
        let json = serde_json::json!({
            "dsid": "123456789",
            "ckdatabasews_url": "https://p140-ckdatabasews.icloud.com:443",
            "cloudkit_query_params": cloudkit_query_params,
            "cookies": [{"name": "X-APPLE-WEBAUTH-TOKEN", "value": "web-auth-token"}]
        })
        .to_string();

        let error = CloudKitDeleteSession::from_json(&json)
            .expect_err("invalid CloudKit params should fail closed");

        assert!(matches!(error, UploadError::InvalidSession(_)));
        assert!(!error.to_string().contains("legacy-token"));
    }
}

#[test]
fn cloudkit_delete_client_posts_records_modify_update_and_confirms_deleted() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut transport = FakeCloudKitDeleteTransport::success();

    let outcome = CloudKitDeleteClient::new(&mut transport)
        .delete_original(
            &session,
            &CloudKitDeleteRequest {
                record_name: "CPLAsset-original-123".to_string(),
                record_change_tag: "change-tag-1".to_string(),
            },
        )
        .expect("confirmed CloudKit delete should succeed");

    assert_eq!(outcome.record_name, "CPLAsset-original-123");
    assert_eq!(outcome.record_change_tag, "change-tag-2");
    assert_eq!(transport.payloads.len(), 1);
    assert_eq!(
        transport.payloads[0],
        json!({
            "atomic": true,
            "desiredKeys": ["isDeleted"],
            "operations": [{
                "operationType": "update",
                "record": {
                    "recordName": "CPLAsset-original-123",
                    "recordType": "CPLAsset",
                    "recordChangeTag": "change-tag-1",
                    "fields": {
                        "isDeleted": {"value": 1}
                    }
                }
            }],
            "zoneID": {"zoneName": "PrimarySync"}
        })
    );
}

#[test]
fn cloudkit_delete_client_rejects_empty_identity_before_transport() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut transport = FakeCloudKitDeleteTransport::success();

    let error = CloudKitDeleteClient::new(&mut transport)
        .delete_original(
            &session,
            &CloudKitDeleteRequest {
                record_name: " ".to_string(),
                record_change_tag: "change-tag-1".to_string(),
            },
        )
        .expect_err("empty original asset id should fail closed");

    assert!(matches!(
        error,
        UploadError::InvalidCloudKitDeleteRequest(_)
    ));
    assert!(transport.payloads.is_empty());
}

#[test]
fn cloudkit_delete_client_rejects_missing_or_unsuccessful_delete_confirmation() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let cases = [
        json!({"records": []}),
        json!({"records": [{"recordName": "CPLAsset-original-123", "recordChangeTag": "change-tag-2"}]}),
        json!({"records": [{"recordName": "CPLAsset-original-123", "recordChangeTag": "change-tag-2", "fields": {"isDeleted": {"value": 0}}}]}),
        json!({"records": [{"recordName": "CPLAsset-original-123", "recordChangeTag": "change-tag-2", "serverErrorCode": "ACCESS_DENIED"}]}),
    ];

    for response in cases {
        let mut transport = FakeCloudKitDeleteTransport {
            payloads: Vec::new(),
            query_payloads: Vec::new(),
            response,
            query_responses: Vec::new(),
        };

        let error = CloudKitDeleteClient::new(&mut transport)
            .delete_original(
                &session,
                &CloudKitDeleteRequest {
                    record_name: "CPLAsset-original-123".to_string(),
                    record_change_tag: "change-tag-1".to_string(),
                },
            )
            .expect_err("missing delete confirmation should fail closed");

        assert!(matches!(
            error,
            UploadError::InvalidCloudKitDeleteResponse(_)
        ));
    }
}

#[test]
fn cloudkit_original_asset_resolver_records_exact_raw_match() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut transport = FakeCloudKitDeleteTransport::query_responses(vec![json!({
        "records": cloudkit_raw_pair("CPLAsset-original-123", "CPLMaster-raw-123", "change-tag-1")
    })]);

    let proof = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_asset(&session, &original_asset_resolve_request())
        .expect("exactly one RAW candidate should resolve");

    assert_eq!(proof.record_name, "CPLAsset-original-123");
    assert_eq!(proof.record_change_tag, "change-tag-1");
    assert_eq!(proof.record_type, "CPLAsset");
    assert_eq!(proof.filename, "IMG_0001.dng");
    assert_eq!(proof.size_bytes, 42);
    assert_eq!(proof.matched_raw_sha256, "raw-sha256");
    assert_eq!(transport.query_payloads.len(), 1);
    assert_eq!(
        transport.query_payloads[0]["query"]["recordType"],
        "CPLAssetAndMasterByAssetDateWithoutHiddenOrDeleted"
    );
    assert!(transport.query_payloads[0].get("direction").is_none());
    assert!(transport.query_payloads[0].get("startRank").is_none());
    assert_eq!(
        transport.query_payloads[0]["query"]["filterBy"],
        json!([
            {
                "fieldName": "direction",
                "comparator": "EQUALS",
                "fieldValue": {"type": "STRING", "value": "ASCENDING"}
            },
            {
                "fieldName": "startRank",
                "comparator": "EQUALS",
                "fieldValue": {"type": "INT64", "value": 0}
            }
        ])
    );
    assert_eq!(transport.query_payloads[0]["resultsLimit"], 200);
    let desired_keys = transport.query_payloads[0]["desiredKeys"]
        .as_array()
        .expect("desiredKeys should be an array");
    assert!(desired_keys.contains(&json!("resOriginalRes")));
    assert!(desired_keys.contains(&json!("resOriginalFileType")));
    assert!(desired_keys.contains(&json!("resOriginalAltRes")));
    assert!(desired_keys.contains(&json!("resOriginalVidComplFileType")));
    assert!(!desired_keys.contains(&json!("resOriginal")));
    assert!(!desired_keys.contains(&json!("resOriginalAlt")));
    assert_eq!(
        transport.query_payloads[0]["zoneID"],
        json!({"zoneName": "PrimarySync"})
    );
}

#[test]
fn cloudkit_original_asset_resolver_zero_matches_fails_closed() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut transport = FakeCloudKitDeleteTransport::query_responses(vec![json!({"records": []})]);

    let error = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_asset(&session, &original_asset_resolve_request())
        .expect_err("zero candidates must fail closed");

    assert!(matches!(
        error,
        UploadError::OriginalAssetResolveNotUnique { matches: 0 }
    ));
}

#[test]
fn cloudkit_original_asset_resolver_fails_when_max_pages_reached_without_exhaustion() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut request = original_asset_resolve_request();
    request.page_size = 2;
    request.max_pages = 1;
    let mut transport = FakeCloudKitDeleteTransport::query_responses(vec![json!({
        "records": cloudkit_raw_pair("CPLAsset-original-123", "CPLMaster-raw-123", "change-tag-1")
    })]);

    let error = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_asset(&session, &request)
        .expect_err("a full final page does not prove global uniqueness");

    assert!(matches!(
        error,
        UploadError::OriginalAssetResolveIncomplete { matches: 1 }
    ));
}

#[test]
fn cloudkit_original_asset_resolver_rejects_pagination_overflow_before_transport() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut request = original_asset_resolve_request();
    request.start_rank = u64::MAX;
    request.page_size = 2;
    request.max_pages = 2;
    let mut transport = FakeCloudKitDeleteTransport::query_responses(vec![
        json!({"records": []}),
        json!({"records": []}),
    ]);

    let error = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_asset(&session, &request)
        .expect_err("pagination overflow must fail closed");

    assert!(matches!(
        error,
        UploadError::InvalidCloudKitOriginalAssetRequest(_)
    ));
    assert!(transport.query_payloads.is_empty());
}

#[test]
fn cloudkit_original_asset_resolver_multiple_matches_fails_closed() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut records = cloudkit_raw_pair("CPLAsset-original-123", "CPLMaster-raw-123", "tag-1");
    records
        .as_array_mut()
        .expect("records should be array")
        .extend(
            cloudkit_raw_pair("CPLAsset-original-456", "CPLMaster-raw-456", "tag-2")
                .as_array()
                .expect("records should be array")
                .clone(),
        );
    let mut transport =
        FakeCloudKitDeleteTransport::query_responses(vec![json!({"records": records})]);

    let error = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_asset(&session, &original_asset_resolve_request())
        .expect_err("multiple candidates must fail closed");

    assert!(matches!(
        error,
        UploadError::OriginalAssetResolveNotUnique { matches: 2 }
    ));
}

#[test]
fn cloudkit_original_asset_resolver_rejects_non_raw_same_size_resource() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut records = cloudkit_raw_pair("CPLAsset-original-123", "CPLMaster-raw-123", "tag-1");
    records[1]["fields"]["resOriginalFileType"]["value"] = json!("public.jpeg");
    let mut transport =
        FakeCloudKitDeleteTransport::query_responses(vec![json!({"records": records})]);

    let error = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_asset(&session, &original_asset_resolve_request())
        .expect_err("JPEG resource must not match RAW identity");

    assert!(matches!(
        error,
        UploadError::OriginalAssetResolveNotUnique { matches: 0 }
    ));
}

#[test]
fn cloudkit_original_asset_resolver_malformed_response_fails_closed() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut transport = FakeCloudKitDeleteTransport::query_responses(vec![json!({
        "records": [{
            "recordName": "CPLAsset-original-123",
            "recordType": "CPLAsset",
            "recordChangeTag": "tag-1",
            "fields": {
                "assetDate": {"value": 1_800_000_000_000_i64}
            }
        }]
    })]);

    let error = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_asset(&session, &original_asset_resolve_request())
        .expect_err("malformed asset/master pairing must fail closed");

    assert!(matches!(
        error,
        UploadError::InvalidCloudKitOriginalAssetResponse(_)
    ));
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

struct FakeCloudKitDeleteTransport {
    payloads: Vec<Value>,
    query_payloads: Vec<Value>,
    response: Value,
    query_responses: Vec<Value>,
}

impl FakeCloudKitDeleteTransport {
    fn success() -> Self {
        Self {
            payloads: Vec::new(),
            query_payloads: Vec::new(),
            response: json!({
                "records": [{
                    "recordName": "CPLAsset-original-123",
                    "recordChangeTag": "change-tag-2",
                    "fields": {
                        "isDeleted": {"value": 1}
                    }
                }]
            }),
            query_responses: Vec::new(),
        }
    }

    fn query_responses(query_responses: Vec<Value>) -> Self {
        Self {
            payloads: Vec::new(),
            query_payloads: Vec::new(),
            response: json!({"records": []}),
            query_responses,
        }
    }
}

impl CloudKitDeleteTransport for FakeCloudKitDeleteTransport {
    fn post_records_modify(
        &mut self,
        _session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError> {
        self.payloads.push(payload);
        Ok(self.response.clone())
    }

    fn post_records_query(
        &mut self,
        _session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError> {
        self.query_payloads.push(payload);
        Ok(self.query_responses.remove(0))
    }
}

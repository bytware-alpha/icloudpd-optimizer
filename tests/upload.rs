use std::cell::{Cell, RefCell};
use std::fs;
use std::path::{Path, PathBuf};

use icloudpd_optimizer::upload::{
    CloudKitDatabaseScope, CloudKitDeleteBatchRequest, CloudKitDeleteBatchSendError,
    CloudKitDeleteClient, CloudKitDeleteOutcome, CloudKitDeleteRequest, CloudKitDeleteSession,
    CloudKitDeleteTransport, CloudKitLibraryDestination, CloudKitLocalReplacementCandidate,
    CloudKitOriginalAssetBatchResolveRequest, CloudKitOriginalAssetResolveDisposition,
    CloudKitOriginalAssetResolveRequest, CloudKitOriginalAssetResolveTarget,
    CloudKitUploadedHeicResolveRequest, IcloudUploadOutcome, IcloudUploadRequest,
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
        visual_rmse_ppm: Some(0),
        visual_mae_ppm: Some(0),
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

fn shared_delete_session_json() -> String {
    serde_json::json!({
        "dsid": "123456789",
        "ckdatabasews_url": "https://p140-ckdatabasews.icloud.com:443",
        "database_scope": "shared",
        "zone_id": {"zoneName": "SharedSync-ABCDEF123456"},
        "cloudkit_query_params": valid_cloudkit_query_params(),
        "cookies": [
            {"name": "X-APPLE-WEBAUTH-TOKEN", "value": "web-auth-token"},
            {"name": "session", "value": "abc123"}
        ]
    })
    .to_string()
}

fn cloudkit_raw_pair(asset_name: &str, master_name: &str, change_tag: &str) -> Value {
    cloudkit_raw_pair_with(
        asset_name,
        master_name,
        change_tag,
        9,
        1_800_000_000_000_i64,
    )
}

fn cloudkit_raw_pair_with(
    asset_name: &str,
    master_name: &str,
    change_tag: &str,
    size_bytes: u64,
    asset_date_millis: i64,
) -> Value {
    json!([
        {
            "recordName": asset_name,
            "recordType": "CPLAsset",
            "recordChangeTag": change_tag,
            "fields": {
                "masterRef": {"value": {"recordName": master_name}},
                "assetDate": {"value": asset_date_millis}
            }
        },
        {
            "recordName": master_name,
            "recordType": "CPLMaster",
            "fields": {
                "resOriginalRes": {
                    "value": {
                        "size": size_bytes,
                        "downloadURL": "https://p140-icloud-content.icloud.com/raw-original"
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

fn cloudkit_raw_pair_with_url(
    asset_name: &str,
    master_name: &str,
    change_tag: &str,
    size_bytes: u64,
    asset_date_millis: i64,
    download_url: &str,
) -> Value {
    let mut records = cloudkit_raw_pair_with(
        asset_name,
        master_name,
        change_tag,
        size_bytes,
        asset_date_millis,
    );
    records[1]["fields"]["resOriginalRes"]["value"]["downloadURL"] = json!(download_url);
    records
}

fn cloudkit_asset_raw_alt_pair_with_url(
    asset_name: &str,
    master_name: &str,
    change_tag: &str,
    size_bytes: u64,
    asset_date_millis: i64,
    download_url: &str,
) -> Value {
    let mut records = cloudkit_raw_pair_with_url(
        asset_name,
        master_name,
        change_tag,
        size_bytes,
        asset_date_millis,
        download_url,
    );
    let asset_fields = records[0]["fields"]
        .as_object_mut()
        .expect("asset fields should be an object");
    asset_fields.insert(
        "resOriginalAltRes".to_string(),
        json!({
            "value": {
                "size": size_bytes,
                "downloadURL": download_url
            }
        }),
    );
    asset_fields.insert(
        "resOriginalAltFileType".to_string(),
        json!({"value": "com.adobe.raw-image"}),
    );

    let master_fields = records[1]["fields"]
        .as_object_mut()
        .expect("master fields should be an object");
    master_fields.insert(
        "resOriginalRes".to_string(),
        json!({
            "value": {
                "size": 1_234_567,
                "downloadURL": "https://p140-icloud-content.icloud.com/visible-heic"
            }
        }),
    );
    master_fields.insert(
        "resOriginalFileType".to_string(),
        json!({"value": "public.heic"}),
    );
    records
}

fn cloudkit_uploaded_heic_asset(asset_name: &str, master_name: &str, change_tag: &str) -> Value {
    json!({
        "records": [{
            "recordName": asset_name,
            "recordType": "CPLAsset",
            "recordChangeTag": change_tag,
            "fields": {
                "masterRef": {"value": {"recordName": master_name}},
                "isDeleted": {"value": 0}
            }
        }]
    })
}

fn cloudkit_uploaded_heic_master(master_name: &str, size_bytes: u64, download_url: &str) -> Value {
    json!({
        "records": [{
            "recordName": master_name,
            "recordType": "CPLMaster",
            "recordChangeTag": "master-change-tag",
            "fields": {
                "resOriginalRes": {
                    "value": {
                        "size": size_bytes,
                        "downloadURL": download_url
                    }
                },
                "resOriginalFileType": {"value": "public.heic"}
            }
        }]
    })
}

fn original_asset_resolve_request() -> CloudKitOriginalAssetResolveRequest {
    let raw_bytes = b"raw-bytes";
    CloudKitOriginalAssetResolveRequest {
        raw_size_bytes: raw_bytes.len() as u64,
        source_captured_unix_seconds: 1_800_000_000,
        capture_tolerance_seconds: 2,
        filename: "IMG_0001.dng".to_string(),
        matched_raw_sha256: sha256_hex(raw_bytes),
        start_rank: 0,
        page_size: 200,
        max_pages: 100,
    }
}

fn batch_resolve_target(
    asset_id: &str,
    filename: &str,
    raw_bytes: &[u8],
) -> CloudKitOriginalAssetResolveTarget {
    CloudKitOriginalAssetResolveTarget {
        asset_id: asset_id.to_string(),
        raw_size_bytes: raw_bytes.len() as u64,
        source_captured_unix_seconds: 1_800_000_000,
        capture_tolerance_seconds: 2,
        filename: filename.to_string(),
        matched_raw_sha256: sha256_hex(raw_bytes),
        replacement_candidate: None,
    }
}

fn batch_resolve_request(
    targets: Vec<CloudKitOriginalAssetResolveTarget>,
) -> CloudKitOriginalAssetBatchResolveRequest {
    CloudKitOriginalAssetBatchResolveRequest {
        targets,
        start_rank: 0,
        page_size: 200,
        max_pages: 100,
    }
}

fn primary_delete_request(record_name: &str, record_change_tag: &str) -> CloudKitDeleteRequest {
    CloudKitDeleteRequest {
        record_name: record_name.to_string(),
        record_change_tag: record_change_tag.to_string(),
        database_scope: CloudKitDatabaseScope::Private,
        zone_name: "PrimarySync".to_string(),
    }
}

fn primary_uploaded_heic_resolve_request(
    uploaded_asset_id: &str,
    expected_heic_sha256: String,
    expected_size_bytes: u64,
) -> CloudKitUploadedHeicResolveRequest {
    CloudKitUploadedHeicResolveRequest {
        uploaded_asset_id: uploaded_asset_id.to_string(),
        expected_heic_sha256,
        expected_size_bytes,
        database_scope: CloudKitDatabaseScope::Private,
        zone_name: "PrimarySync".to_string(),
    }
}

fn start_ranks(transport: &FakeCloudKitDeleteTransport) -> Vec<u64> {
    transport
        .query_payloads
        .iter()
        .map(|payload| {
            payload["query"]["filterBy"][1]["fieldValue"]["value"]
                .as_u64()
                .expect("startRank should be numeric")
        })
        .collect()
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
fn load_cloudkit_delete_session_accepts_shared_library_scope_and_zone() {
    let session = CloudKitDeleteSession::from_json(&shared_delete_session_json())
        .expect("shared library session should load");

    assert_eq!(session.database_scope, CloudKitDatabaseScope::Shared);
    assert_eq!(
        session.zone,
        CloudKitLibraryDestination {
            database_scope: CloudKitDatabaseScope::Shared,
            zone_name: "SharedSync-ABCDEF123456".to_string(),
        }
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
            &primary_delete_request("CPLAsset-original-123", "change-tag-1"),
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
fn cloudkit_delete_client_posts_one_records_modify_for_batch_deletes() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut transport = FakeCloudKitDeleteTransport {
        payloads: Vec::new(),
        query_payloads: Vec::new(),
        lookup_payloads: Vec::new(),
        downloaded_urls: Vec::new(),
        response: json!({
            "records": [
                {
                    "recordName": "CPLAsset-original-123",
                    "recordChangeTag": "change-tag-2",
                    "fields": {"isDeleted": {"value": 1}}
                },
                {
                    "recordName": "CPLAsset-original-456",
                    "recordChangeTag": "change-tag-4",
                    "fields": {"isDeleted": {"value": true}}
                }
            ]
        }),
        query_responses: Vec::new(),
        lookup_responses: Vec::new(),
        resource_bodies: Vec::new(),
    };

    let outcomes = CloudKitDeleteClient::new(&mut transport)
        .delete_originals_batch(
            &session,
            &CloudKitDeleteBatchRequest {
                requests: vec![
                    primary_delete_request("CPLAsset-original-123", "change-tag-1"),
                    primary_delete_request("CPLAsset-original-456", "change-tag-3"),
                ],
            },
        )
        .expect("batch delete should confirm both records");

    assert_eq!(outcomes.len(), 2);
    assert_eq!(outcomes[0].record_name, "CPLAsset-original-123");
    assert_eq!(outcomes[0].record_change_tag, "change-tag-2");
    assert_eq!(outcomes[1].record_name, "CPLAsset-original-456");
    assert_eq!(outcomes[1].record_change_tag, "change-tag-4");
    assert_eq!(transport.payloads.len(), 1);
    assert_eq!(
        transport.payloads[0],
        json!({
            "atomic": true,
            "desiredKeys": ["isDeleted"],
            "operations": [
                {
                    "operationType": "update",
                    "record": {
                        "recordName": "CPLAsset-original-123",
                        "recordType": "CPLAsset",
                        "recordChangeTag": "change-tag-1",
                        "fields": {"isDeleted": {"value": 1}}
                    }
                },
                {
                    "operationType": "update",
                    "record": {
                        "recordName": "CPLAsset-original-456",
                        "recordType": "CPLAsset",
                        "recordChangeTag": "change-tag-3",
                        "fields": {"isDeleted": {"value": 1}}
                    }
                }
            ],
            "zoneID": {"zoneName": "PrimarySync"}
        })
    );
}

#[test]
fn cloudkit_batch_delete_preflight_runs_after_validation_and_payload_construction() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let invalid_request = CloudKitDeleteBatchRequest {
        requests: vec![primary_delete_request(" ", "change-tag-1")],
    };
    let invalid_preflight_called = Cell::new(false);
    let mut transport = FakeCloudKitDeleteTransport::success();

    let error = CloudKitDeleteClient::new(&mut transport)
        .delete_originals_batch_with_preflight(&session, &invalid_request, |_| {
            invalid_preflight_called.set(true);
            Ok::<(), &'static str>(())
        })
        .expect_err("invalid request must fail before preflight");

    assert!(!error.transport_was_called());
    assert!(matches!(
        error,
        CloudKitDeleteBatchSendError::InvalidRequest(UploadError::InvalidCloudKitDeleteRequest(_))
    ));
    assert!(!invalid_preflight_called.get());
    assert!(transport.payloads.is_empty());

    let request = CloudKitDeleteBatchRequest {
        requests: vec![primary_delete_request(
            "CPLAsset-original-123",
            "change-tag-1",
        )],
    };
    let preflight_payload = RefCell::new(None);
    let error = CloudKitDeleteClient::new(&mut transport)
        .delete_originals_batch_with_preflight(&session, &request, |payload| {
            preflight_payload.replace(Some(payload.clone()));
            Err("stale token")
        })
        .expect_err("preflight rejection must fail before transport");

    assert!(!error.transport_was_called());
    assert!(matches!(
        error,
        CloudKitDeleteBatchSendError::Preflight("stale token")
    ));
    assert_eq!(
        preflight_payload.into_inner(),
        Some(json!({
            "atomic": true,
            "desiredKeys": ["isDeleted"],
            "operations": [{
                "operationType": "update",
                "record": {
                    "recordName": "CPLAsset-original-123",
                    "recordType": "CPLAsset",
                    "recordChangeTag": "change-tag-1",
                    "fields": {"isDeleted": {"value": 1}}
                }
            }],
            "zoneID": {"zoneName": "PrimarySync"}
        }))
    );
    assert!(transport.payloads.is_empty());
}

#[test]
fn cloudkit_batch_delete_successful_preflight_sends_exactly_once() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let request = CloudKitDeleteBatchRequest {
        requests: vec![primary_delete_request(
            "CPLAsset-original-123",
            "change-tag-1",
        )],
    };
    let preflight_calls = Cell::new(0);
    let mut transport = FakeCloudKitDeleteTransport::success();

    let outcomes = CloudKitDeleteClient::new(&mut transport)
        .delete_originals_batch_with_preflight(&session, &request, |_| {
            preflight_calls.set(preflight_calls.get() + 1);
            Ok::<(), &'static str>(())
        })
        .expect("successful preflight should send the batch");

    assert_eq!(preflight_calls.get(), 1);
    assert_eq!(transport.payloads.len(), 1);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].record_name, "CPLAsset-original-123");
}

#[test]
fn cloudkit_batch_delete_remote_failure_is_distinct_from_unsent_rejection() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let request = CloudKitDeleteBatchRequest {
        requests: vec![primary_delete_request(
            "CPLAsset-original-123",
            "change-tag-1",
        )],
    };
    let mut transport = FakeCloudKitDeleteTransport::modify_response(json!({"records": []}));

    let error = CloudKitDeleteClient::new(&mut transport)
        .delete_originals_batch_with_preflight(&session, &request, |_| Ok::<(), &'static str>(()))
        .expect_err("ambiguous modify response must remain a remote failure");

    assert!(error.transport_was_called());
    assert!(matches!(
        error,
        CloudKitDeleteBatchSendError::Remote(UploadError::InvalidCloudKitDeleteResponse(_))
    ));
    assert_eq!(transport.payloads.len(), 1);
}

#[test]
fn cloudkit_delete_state_lookup_confirms_exact_deleted_records() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let request = CloudKitDeleteBatchRequest {
        requests: vec![
            primary_delete_request("CPLAsset-original-123", "change-tag-1"),
            primary_delete_request("CPLAsset-original-456", "change-tag-3"),
        ],
    };
    let mut transport = FakeCloudKitDeleteTransport::lookup_responses_with_downloads(
        vec![json!({
            "records": [
                {
                    "recordName": "CPLAsset-original-456",
                    "recordType": "CPLAsset",
                    "recordChangeTag": "change-tag-4",
                    "fields": {"isDeleted": {"value": true}}
                },
                {
                    "recordName": "CPLAsset-original-123",
                    "recordChangeTag": "change-tag-2",
                    "fields": {"isDeleted": {"value": 1}}
                }
            ]
        })],
        vec![],
    );

    let result = CloudKitDeleteClient::new(&mut transport)
        .lookup_delete_states(&session, &request)
        .expect("strict lookup should confirm both deleted records");

    assert_eq!(
        result.confirmed_deleted,
        vec![
            CloudKitDeleteOutcome {
                record_name: "CPLAsset-original-123".to_string(),
                record_change_tag: "change-tag-2".to_string(),
            },
            CloudKitDeleteOutcome {
                record_name: "CPLAsset-original-456".to_string(),
                record_change_tag: "change-tag-4".to_string(),
            }
        ]
    );
    assert!(result.unconfirmed.is_empty());
    assert!(transport.payloads.is_empty());
    assert_eq!(
        transport.lookup_payloads,
        vec![json!({
            "records": [
                {"recordName": "CPLAsset-original-123"},
                {"recordName": "CPLAsset-original-456"}
            ],
            "desiredKeys": ["isDeleted"],
            "zoneID": {"zoneName": "PrimarySync"}
        })]
    );
}

#[test]
fn cloudkit_delete_state_lookup_returns_mixed_confirmed_and_unconfirmed_results() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let deleted = primary_delete_request("CPLAsset-original-123", "change-tag-1");
    let unconfirmed = primary_delete_request("CPLAsset-original-456", "change-tag-3");
    let request = CloudKitDeleteBatchRequest {
        requests: vec![deleted, unconfirmed.clone()],
    };
    let mut transport = FakeCloudKitDeleteTransport::lookup_responses_with_downloads(
        vec![json!({
            "records": [
                {
                    "recordName": "CPLAsset-original-456",
                    "recordType": "CPLAsset",
                    "recordChangeTag": "change-tag-3",
                    "fields": {"isDeleted": {"value": false}}
                },
                {
                    "recordName": "CPLAsset-original-123",
                    "recordType": "CPLAsset",
                    "recordChangeTag": "change-tag-2",
                    "fields": {"isDeleted": {"value": true}}
                }
            ]
        })],
        vec![],
    );

    let result = CloudKitDeleteClient::new(&mut transport)
        .lookup_delete_states(&session, &request)
        .expect("false delete state should remain explicitly unconfirmed");

    assert_eq!(result.confirmed_deleted.len(), 1);
    assert_eq!(
        result.confirmed_deleted[0].record_name,
        "CPLAsset-original-123"
    );
    assert_eq!(result.unconfirmed, vec![unconfirmed]);
}

#[test]
fn cloudkit_delete_state_lookup_rejects_missing_duplicate_wrong_name_or_type() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let two_requests = || CloudKitDeleteBatchRequest {
        requests: vec![
            primary_delete_request("CPLAsset-original-123", "change-tag-1"),
            primary_delete_request("CPLAsset-original-456", "change-tag-3"),
        ],
    };
    let one_request = || CloudKitDeleteBatchRequest {
        requests: vec![primary_delete_request(
            "CPLAsset-original-123",
            "change-tag-1",
        )],
    };
    let cases = [
        (
            two_requests(),
            json!({"records": [{
                "recordName": "CPLAsset-original-123",
                "recordChangeTag": "change-tag-2",
                "fields": {"isDeleted": {"value": true}}
            }]}),
        ),
        (
            two_requests(),
            json!({"records": [
                {
                    "recordName": "CPLAsset-original-123",
                    "recordChangeTag": "change-tag-2",
                    "fields": {"isDeleted": {"value": true}}
                },
                {
                    "recordName": "CPLAsset-original-123",
                    "recordChangeTag": "change-tag-4",
                    "fields": {"isDeleted": {"value": true}}
                }
            ]}),
        ),
        (
            one_request(),
            json!({"records": [{
                "recordName": "CPLAsset-other",
                "recordChangeTag": "change-tag-2",
                "fields": {"isDeleted": {"value": true}}
            }]}),
        ),
        (
            one_request(),
            json!({"records": [{
                "recordName": "CPLAsset-original-123",
                "recordType": "CPLMaster",
                "recordChangeTag": "change-tag-2",
                "fields": {"isDeleted": {"value": true}}
            }]}),
        ),
    ];

    for (request, response) in cases {
        let mut transport =
            FakeCloudKitDeleteTransport::lookup_responses_with_downloads(vec![response], vec![]);
        let error = CloudKitDeleteClient::new(&mut transport)
            .lookup_delete_states(&session, &request)
            .expect_err("ambiguous lookup response must fail closed");

        assert!(matches!(
            error,
            UploadError::InvalidCloudKitDeleteLookupResponse(_)
        ));
    }
}

#[test]
fn cloudkit_delete_state_lookup_rejects_invalid_confirmed_tags_and_values() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let request = CloudKitDeleteBatchRequest {
        requests: vec![primary_delete_request(
            "CPLAsset-original-123",
            "change-tag-1",
        )],
    };
    let cases = [
        json!({"records": [{
            "recordName": "CPLAsset-original-123",
            "recordType": "CPLAsset",
            "recordChangeTag": "",
            "fields": {"isDeleted": {"value": true}}
        }]}),
        json!({"records": [{
            "recordName": "CPLAsset-original-123",
            "recordType": "CPLAsset",
            "recordChangeTag": "change-tag-1",
            "fields": {"isDeleted": {"value": true}}
        }]}),
        json!({"records": [{
            "recordName": "CPLAsset-original-123",
            "recordType": "CPLAsset",
            "recordChangeTag": "change-tag-2",
            "fields": {"isDeleted": {"value": "true"}}
        }]}),
    ];

    for response in cases {
        let mut transport =
            FakeCloudKitDeleteTransport::lookup_responses_with_downloads(vec![response], vec![]);
        let error = CloudKitDeleteClient::new(&mut transport)
            .lookup_delete_states(&session, &request)
            .expect_err("malformed confirmation must not synthesize an outcome");

        assert!(matches!(
            error,
            UploadError::InvalidCloudKitDeleteLookupResponse(_)
        ));
    }
}

#[test]
fn cloudkit_delete_state_lookup_rejects_record_errors_and_malformed_records() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let request = CloudKitDeleteBatchRequest {
        requests: vec![primary_delete_request(
            "CPLAsset-original-123",
            "change-tag-1",
        )],
    };
    let cases = [
        json!({"records": [{
            "recordName": "CPLAsset-original-123",
            "serverErrorCode": "NOT_FOUND",
            "reason": "record missing"
        }]}),
        json!({}),
        json!({"records": [{}]}),
        json!({"records": [{
            "recordName": "CPLAsset-original-123",
            "recordChangeTag": "change-tag-2"
        }]}),
        json!({"records": [{
            "recordName": "CPLAsset-original-123",
            "recordType": null,
            "recordChangeTag": "change-tag-2",
            "fields": {"isDeleted": {"value": true}}
        }]}),
    ];

    for response in cases {
        let mut transport =
            FakeCloudKitDeleteTransport::lookup_responses_with_downloads(vec![response], vec![]);
        let error = CloudKitDeleteClient::new(&mut transport)
            .lookup_delete_states(&session, &request)
            .expect_err("record errors and malformed records must fail closed");

        assert!(matches!(
            error,
            UploadError::InvalidCloudKitDeleteLookupResponse(_)
        ));
    }
}

#[test]
fn cloudkit_delete_state_lookup_rejects_invalid_input_before_transport() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let duplicate = CloudKitDeleteBatchRequest {
        requests: vec![
            primary_delete_request("CPLAsset-original-123", "change-tag-1"),
            primary_delete_request("CPLAsset-original-123", "change-tag-2"),
        ],
    };
    let mixed_destination = CloudKitDeleteBatchRequest {
        requests: vec![
            primary_delete_request("CPLAsset-original-123", "change-tag-1"),
            CloudKitDeleteRequest {
                record_name: "CPLAsset-original-456".to_string(),
                record_change_tag: "change-tag-3".to_string(),
                database_scope: CloudKitDatabaseScope::Shared,
                zone_name: "SharedSync-ABCDEF123456".to_string(),
            },
        ],
    };

    for request in [duplicate, mixed_destination] {
        let mut transport = FakeCloudKitDeleteTransport::success();
        let error = CloudKitDeleteClient::new(&mut transport)
            .lookup_delete_states(&session, &request)
            .expect_err("ambiguous lookup input must fail before transport");

        assert!(matches!(
            error,
            UploadError::InvalidCloudKitDeleteRequest(_)
        ));
        assert!(transport.lookup_payloads.is_empty());
        assert!(transport.payloads.is_empty());
    }
}

#[test]
fn cloudkit_delete_client_rejects_partial_batch_delete_confirmation() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut transport = FakeCloudKitDeleteTransport {
        payloads: Vec::new(),
        query_payloads: Vec::new(),
        lookup_payloads: Vec::new(),
        downloaded_urls: Vec::new(),
        response: json!({
            "records": [
                {
                    "recordName": "CPLAsset-original-123",
                    "recordChangeTag": "change-tag-2",
                    "fields": {"isDeleted": {"value": 1}}
                },
                {
                    "recordName": "CPLAsset-original-456",
                    "recordChangeTag": "change-tag-4",
                    "serverErrorCode": "SERVER_RECORD_CHANGED"
                }
            ]
        }),
        query_responses: Vec::new(),
        lookup_responses: Vec::new(),
        resource_bodies: Vec::new(),
    };

    let error = CloudKitDeleteClient::new(&mut transport)
        .delete_originals_batch(
            &session,
            &CloudKitDeleteBatchRequest {
                requests: vec![
                    primary_delete_request("CPLAsset-original-123", "change-tag-1"),
                    primary_delete_request("CPLAsset-original-456", "change-tag-3"),
                ],
            },
        )
        .expect_err("partial delete confirmation must fail closed");

    assert!(matches!(
        error,
        UploadError::InvalidCloudKitDeleteResponse(_)
    ));
    assert_eq!(transport.payloads.len(), 1);
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
                database_scope: CloudKitDatabaseScope::Private,
                zone_name: "PrimarySync".to_string(),
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
            lookup_payloads: Vec::new(),
            downloaded_urls: Vec::new(),
            response,
            query_responses: Vec::new(),
            lookup_responses: Vec::new(),
            resource_bodies: Vec::new(),
        };

        let error = CloudKitDeleteClient::new(&mut transport)
            .delete_original(
                &session,
                &primary_delete_request("CPLAsset-original-123", "change-tag-1"),
            )
            .expect_err("missing delete confirmation should fail closed");

        assert!(matches!(
            error,
            UploadError::InvalidCloudKitDeleteResponse(_)
        ));
    }
}

#[test]
fn cloudkit_delete_client_resolves_uploaded_heic_asset_by_hash_before_delete() {
    let session =
        CloudKitDeleteSession::from_json(&valid_delete_session_json()).expect("session loads");
    let heic_bytes = b"bad-uploaded-heic";
    let mut transport = FakeCloudKitDeleteTransport::lookup_responses_with_downloads(
        vec![
            cloudkit_uploaded_heic_asset(
                "CPLAsset-uploaded-heic-123",
                "CPLMaster-heic-123",
                "tag-1",
            ),
            cloudkit_uploaded_heic_master(
                "CPLMaster-heic-123",
                heic_bytes.len() as u64,
                "https://p140-icloud-content.icloud.com/uploaded-heic",
            ),
        ],
        vec![heic_bytes.to_vec()],
    );

    let resolved = CloudKitDeleteClient::new(&mut transport)
        .resolve_uploaded_heic_asset(
            &session,
            &primary_uploaded_heic_resolve_request(
                "CPLAsset-uploaded-heic-123",
                sha256_hex(heic_bytes),
                heic_bytes.len() as u64,
            ),
        )
        .expect("uploaded HEIC should resolve after byte proof");

    assert_eq!(resolved.record_name, "CPLAsset-uploaded-heic-123");
    assert_eq!(resolved.record_change_tag, "tag-1");
    assert_eq!(resolved.master_record_name, "CPLMaster-heic-123");
    assert_eq!(resolved.size_bytes, heic_bytes.len() as u64);
    assert_eq!(transport.lookup_payloads.len(), 2);
    assert_eq!(
        transport.lookup_payloads[0]["records"][0]["recordName"],
        "CPLAsset-uploaded-heic-123"
    );
    assert_eq!(
        transport.lookup_payloads[1]["records"][0]["recordName"],
        "CPLMaster-heic-123"
    );
    assert_eq!(
        transport.downloaded_urls,
        vec!["https://p140-icloud-content.icloud.com/uploaded-heic"]
    );
}

#[test]
fn cloudkit_delete_client_rejects_uploaded_heic_hash_mismatch_without_delete_payload() {
    let session =
        CloudKitDeleteSession::from_json(&valid_delete_session_json()).expect("session loads");
    let mut transport = FakeCloudKitDeleteTransport::lookup_responses_with_downloads(
        vec![
            cloudkit_uploaded_heic_asset(
                "CPLAsset-uploaded-heic-123",
                "CPLMaster-heic-123",
                "tag-1",
            ),
            cloudkit_uploaded_heic_master(
                "CPLMaster-heic-123",
                17,
                "https://p140-icloud-content.icloud.com/uploaded-heic",
            ),
        ],
        vec![b"bad-uploaded-heic".to_vec()],
    );

    let error = CloudKitDeleteClient::new(&mut transport)
        .resolve_uploaded_heic_asset(
            &session,
            &primary_uploaded_heic_resolve_request(
                "CPLAsset-uploaded-heic-123",
                sha256_hex(b"different-heic"),
                17,
            ),
        )
        .expect_err("hash mismatch must fail closed");

    assert!(matches!(
        error,
        UploadError::CloudKitUploadedHeicDownloadHashMismatch { .. }
    ));
    assert!(transport.payloads.is_empty());
}

#[test]
fn cloudkit_delete_client_rejects_already_deleted_uploaded_heic() {
    let session =
        CloudKitDeleteSession::from_json(&valid_delete_session_json()).expect("session loads");
    let mut deleted_asset =
        cloudkit_uploaded_heic_asset("CPLAsset-uploaded-heic-123", "CPLMaster-heic-123", "tag-1");
    deleted_asset["records"][0]["fields"]["isDeleted"]["value"] = json!(1);
    let mut transport =
        FakeCloudKitDeleteTransport::lookup_responses_with_downloads(vec![deleted_asset], vec![]);

    let error = CloudKitDeleteClient::new(&mut transport)
        .resolve_uploaded_heic_asset(
            &session,
            &primary_uploaded_heic_resolve_request(
                "CPLAsset-uploaded-heic-123",
                sha256_hex(b"bad-uploaded-heic"),
                17,
            ),
        )
        .expect_err("already deleted uploaded HEIC must fail closed");

    assert!(matches!(
        error,
        UploadError::InvalidCloudKitUploadedHeicResponse(_)
    ));
    assert!(transport.payloads.is_empty());
    assert!(transport.downloaded_urls.is_empty());
}

#[test]
fn cloudkit_delete_client_deletes_resolved_uploaded_heic_record() {
    let session =
        CloudKitDeleteSession::from_json(&valid_delete_session_json()).expect("session loads");
    let mut transport = FakeCloudKitDeleteTransport {
        payloads: Vec::new(),
        query_payloads: Vec::new(),
        lookup_payloads: Vec::new(),
        downloaded_urls: Vec::new(),
        response: json!({
            "records": [{
                "recordName": "CPLAsset-uploaded-heic-123",
                "recordChangeTag": "tag-2",
                "fields": {"isDeleted": {"value": 1}}
            }]
        }),
        query_responses: Vec::new(),
        lookup_responses: Vec::new(),
        resource_bodies: Vec::new(),
    };

    let outcome = CloudKitDeleteClient::new(&mut transport)
        .delete_cpl_asset(
            &session,
            &primary_delete_request("CPLAsset-uploaded-heic-123", "tag-1"),
        )
        .expect("delete should confirm uploaded HEIC record");

    assert_eq!(outcome.record_name, "CPLAsset-uploaded-heic-123");
    assert_eq!(outcome.record_change_tag, "tag-2");
    assert_eq!(
        transport.payloads[0]["operations"][0]["record"]["recordName"],
        "CPLAsset-uploaded-heic-123"
    );
    assert_eq!(
        transport.payloads[0]["operations"][0]["record"]["recordChangeTag"],
        "tag-1"
    );
}

#[test]
fn cloudkit_original_asset_resolver_records_exact_raw_match() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({
            "records": cloudkit_raw_pair("CPLAsset-original-123", "CPLMaster-raw-123", "change-tag-1")
        })],
        vec![b"raw-bytes".to_vec()],
    );

    let proof = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_asset(&session, &original_asset_resolve_request())
        .expect("exactly one RAW candidate should resolve");

    assert_eq!(proof.record_name, "CPLAsset-original-123");
    assert_eq!(proof.record_change_tag, "change-tag-1");
    assert_eq!(proof.record_type, "CPLAsset");
    assert_eq!(proof.filename, "IMG_0001.dng");
    assert_eq!(proof.size_bytes, 9);
    assert_eq!(proof.matched_raw_sha256, sha256_hex(b"raw-bytes"));
    assert_eq!(
        transport.downloaded_urls,
        vec!["https://p140-icloud-content.icloud.com/raw-original"]
    );
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
fn cloudkit_original_asset_resolver_records_asset_side_raw_alternative() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({
            "records": cloudkit_asset_raw_alt_pair_with_url(
                "CPLAsset-original-123",
                "CPLMaster-visible-123",
                "change-tag-1",
                9,
                1_800_000_000_000,
                "https://p140-icloud-content.icloud.com/asset-side-raw-alt"
            )
        })],
        vec![b"raw-bytes".to_vec()],
    );

    let proof = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_asset(&session, &original_asset_resolve_request())
        .expect("asset-side RAW alternative should resolve by exact content hash");

    assert_eq!(proof.record_name, "CPLAsset-original-123");
    assert_eq!(proof.record_change_tag, "change-tag-1");
    assert_eq!(
        transport.downloaded_urls,
        vec!["https://p140-icloud-content.icloud.com/asset-side-raw-alt"]
    );
}

#[test]
fn cloudkit_original_asset_resolver_records_shared_library_destination() {
    let session =
        CloudKitDeleteSession::from_json(&shared_delete_session_json()).expect("session loads");
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({
            "records": cloudkit_raw_pair("CPLAsset-original-123", "CPLMaster-raw-123", "change-tag-1")
        })],
        vec![b"raw-bytes".to_vec()],
    );

    let proof = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_asset(&session, &original_asset_resolve_request())
        .expect("shared library original should resolve");

    assert_eq!(proof.database_scope, CloudKitDatabaseScope::Shared);
    assert_eq!(proof.zone_name, "SharedSync-ABCDEF123456");
    assert_eq!(
        transport.query_payloads[0]["zoneID"],
        json!({"zoneName": "SharedSync-ABCDEF123456"})
    );
}

#[test]
fn cloudkit_original_asset_batch_resolver_records_two_targets_from_one_scan() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut records = cloudkit_raw_pair_with(
        "CPLAsset-original-123",
        "CPLMaster-raw-123",
        "tag-1",
        9,
        1_800_000_000_000,
    );
    records
        .as_array_mut()
        .expect("records should be array")
        .extend(
            cloudkit_raw_pair_with(
                "CPLAsset-original-456",
                "CPLMaster-raw-456",
                "tag-2",
                11,
                1_800_000_000_000,
            )
            .as_array()
            .expect("records should be array")
            .clone(),
        );
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"raw-bytes".to_vec(), b"other-bytes".to_vec()],
    );

    let proofs = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch(
            &session,
            &batch_resolve_request(vec![
                batch_resolve_target("asset-1", "IMG_0001.dng", b"raw-bytes"),
                batch_resolve_target("asset-2", "IMG_0002.dng", b"other-bytes"),
            ]),
        )
        .expect("two exact targets should resolve in one scan");

    assert_eq!(transport.query_payloads.len(), 1);
    assert_eq!(proofs["asset-1"].record_name, "CPLAsset-original-123");
    assert_eq!(proofs["asset-2"].record_name, "CPLAsset-original-456");
    assert_eq!(proofs["asset-2"].filename, "IMG_0002.dng");
    assert_eq!(proofs["asset-2"].size_bytes, 11);
}

#[test]
fn cloudkit_original_asset_batch_resolver_records_asset_side_raw_alternative() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({
            "records": cloudkit_asset_raw_alt_pair_with_url(
                "CPLAsset-original-123",
                "CPLMaster-visible-123",
                "change-tag-1",
                9,
                1_800_000_000_000,
                "https://p140-icloud-content.icloud.com/asset-side-raw-alt"
            )
        })],
        vec![b"raw-bytes".to_vec()],
    );

    let proofs = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch(
            &session,
            &batch_resolve_request(vec![batch_resolve_target(
                "asset-1",
                "IMG_0001.dng",
                b"raw-bytes",
            )]),
        )
        .expect("batch resolver should inspect asset-side RAW alternatives");

    assert_eq!(proofs["asset-1"].record_name, "CPLAsset-original-123");
    assert_eq!(proofs["asset-1"].record_change_tag, "change-tag-1");
    assert_eq!(
        transport.downloaded_urls,
        vec!["https://p140-icloud-content.icloud.com/asset-side-raw-alt"]
    );
}

#[test]
fn cloudkit_original_asset_batch_resolver_seeks_to_target_date_window() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let target_time = 1_718_222_196_u64;
    let mut target = batch_resolve_target("asset-1", "IMG_0001.dng", b"raw-bytes");
    target.source_captured_unix_seconds = target_time;
    target.capture_tolerance_seconds = 2;
    let mut request = batch_resolve_request(vec![target]);
    request.page_size = 2;
    request.max_pages = 10;
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![
            json!({"records": cloudkit_raw_pair_with(
                "CPLAsset-too-new-0",
                "CPLMaster-too-new-0",
                "tag-new-0",
                9,
                ((target_time + 40_000_000) * 1000) as i64,
            )}),
            json!({"records": cloudkit_raw_pair_with(
                "CPLAsset-too-new-1",
                "CPLMaster-too-new-1",
                "tag-new-1",
                9,
                ((target_time + 20_000_000) * 1000) as i64,
            )}),
            json!({"records": cloudkit_raw_pair_with(
                "CPLAsset-too-new-2",
                "CPLMaster-too-new-2",
                "tag-new-2",
                9,
                ((target_time + 10_000_000) * 1000) as i64,
            )}),
            json!({"records": cloudkit_raw_pair_with(
                "CPLAsset-too-old-4",
                "CPLMaster-too-old-4",
                "tag-old-4",
                9,
                ((target_time - 10_000_000) * 1000) as i64,
            )}),
            json!({"records": cloudkit_raw_pair_with(
                "CPLAsset-original-123",
                "CPLMaster-raw-123",
                "tag-1",
                9,
                (target_time * 1000) as i64,
            )}),
        ],
        vec![b"raw-bytes".to_vec()],
    );

    let proofs = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch(&session, &request)
        .expect("date seek should land on the target window");

    assert_eq!(proofs["asset-1"].record_name, "CPLAsset-original-123");
    assert_eq!(start_ranks(&transport), vec![0, 1, 2, 4, 3]);
    assert_eq!(
        transport.downloaded_urls,
        vec!["https://p140-icloud-content.icloud.com/raw-original".to_string()]
    );
}

#[test]
fn cloudkit_original_asset_batch_resolver_seeks_back_from_too_old_start_rank() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let target_time = 1_718_222_196_u64;
    let mut target = batch_resolve_target("asset-1", "IMG_0001.dng", b"raw-bytes");
    target.source_captured_unix_seconds = target_time;
    target.capture_tolerance_seconds = 2;
    let mut request = batch_resolve_request(vec![target]);
    request.start_rank = 8;
    request.page_size = 2;
    request.max_pages = 10;
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![
            json!({"records": cloudkit_raw_pair_with(
                "CPLAsset-too-old-8",
                "CPLMaster-too-old-8",
                "tag-old-8",
                9,
                ((target_time - 40_000_000) * 1000) as i64,
            )}),
            json!({"records": cloudkit_raw_pair_with(
                "CPLAsset-too-old-7",
                "CPLMaster-too-old-7",
                "tag-old-7",
                9,
                ((target_time - 20_000_000) * 1000) as i64,
            )}),
            json!({"records": cloudkit_raw_pair_with(
                "CPLAsset-too-old-5",
                "CPLMaster-too-old-5",
                "tag-old-5",
                9,
                ((target_time - 10_000_000) * 1000) as i64,
            )}),
            json!({"records": cloudkit_raw_pair_with(
                "CPLAsset-too-new-1",
                "CPLMaster-too-new-1",
                "tag-new-1",
                9,
                ((target_time + 10_000_000) * 1000) as i64,
            )}),
            json!({"records": cloudkit_raw_pair_with(
                "CPLAsset-too-new-3",
                "CPLMaster-too-new-3",
                "tag-new-3",
                9,
                ((target_time + 5_000_000) * 1000) as i64,
            )}),
            json!({"records": cloudkit_raw_pair_with(
                "CPLAsset-original-123",
                "CPLMaster-raw-123",
                "tag-1",
                9,
                (target_time * 1000) as i64,
            )}),
        ],
        vec![b"raw-bytes".to_vec()],
    );

    let proofs = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch(&session, &request)
        .expect("date seek should move toward newer pages when start rank is too old");

    assert_eq!(proofs["asset-1"].record_name, "CPLAsset-original-123");
    assert_eq!(start_ranks(&transport), vec![8, 7, 5, 1, 3, 4]);
}

#[test]
fn cloudkit_original_asset_batch_resolver_counts_seek_probes_against_page_cap() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let target_time = 1_718_222_196_u64;
    let mut target = batch_resolve_target("asset-1", "IMG_0001.dng", b"raw-bytes");
    target.source_captured_unix_seconds = target_time;
    target.capture_tolerance_seconds = 2;
    let mut request = batch_resolve_request(vec![target]);
    request.page_size = 2;
    request.max_pages = 3;
    let mut transport = FakeCloudKitDeleteTransport::query_responses(vec![
        json!({"records": cloudkit_raw_pair_with(
            "CPLAsset-too-new-0",
            "CPLMaster-too-new-0",
            "tag-new-0",
            9,
            ((target_time + 40_000_000) * 1000) as i64,
        )}),
        json!({"records": cloudkit_raw_pair_with(
            "CPLAsset-too-new-1",
            "CPLMaster-too-new-1",
            "tag-new-1",
            9,
            ((target_time + 20_000_000) * 1000) as i64,
        )}),
        json!({"records": cloudkit_raw_pair_with(
            "CPLAsset-too-new-2",
            "CPLMaster-too-new-2",
            "tag-new-2",
            9,
            ((target_time + 10_000_000) * 1000) as i64,
        )}),
    ]);

    let outcome = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch_outcome(&session, &request)
        .expect("unbracketed date seek should remain a typed transient outcome");

    assert!(matches!(
        outcome.resolutions["asset-1"].disposition,
        CloudKitOriginalAssetResolveDisposition::IncompleteTransient
    ));
    assert!(!outcome.inventory.complete);
    assert_eq!(start_ranks(&transport), vec![0, 1, 2]);
    assert!(transport.downloaded_urls.is_empty());
}

#[test]
fn cloudkit_original_asset_batch_resolver_scans_until_date_window_is_past() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let target_time = 1_718_222_196_u64;
    let mut target = batch_resolve_target("asset-1", "IMG_0001.dng", b"raw-bytes");
    target.source_captured_unix_seconds = target_time;
    target.capture_tolerance_seconds = 2;
    let mut request = batch_resolve_request(vec![target]);
    request.page_size = 2;
    request.max_pages = 4;
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![
            json!({"records": cloudkit_raw_pair_with(
                "CPLAsset-too-new-0",
                "CPLMaster-too-new-0",
                "tag-new-0",
                9,
                ((target_time + 10_000_000) * 1000) as i64,
            )}),
            json!({
                "records": cloudkit_raw_pair_with(
                    "CPLAsset-original-123",
                    "CPLMaster-raw-123",
                    "tag-1",
                    9,
                    (target_time * 1000) as i64,
                ),
                "continuationMarker": "next-page"
            }),
            json!({"records": cloudkit_raw_pair_with(
                "CPLAsset-too-old-2",
                "CPLMaster-too-old-2",
                "tag-old-2",
                9,
                ((target_time - 10_000_000) * 1000) as i64,
            )}),
        ],
        vec![b"raw-bytes".to_vec()],
    );

    let proofs = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch(&session, &request)
        .expect("resolver should prove the capture window is exhausted");

    assert_eq!(proofs["asset-1"].record_name, "CPLAsset-original-123");
    assert_eq!(start_ranks(&transport), vec![0, 1, 1]);
    assert_eq!(
        transport.query_payloads[2]["continuationMarker"],
        json!("next-page")
    );
}

#[test]
fn cloudkit_original_asset_batch_resolver_fails_when_any_target_unresolved() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let records = cloudkit_raw_pair_with(
        "CPLAsset-original-123",
        "CPLMaster-raw-123",
        "tag-1",
        9,
        1_800_000_000_000,
    );
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"raw-bytes".to_vec()],
    );

    let error = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch(
            &session,
            &batch_resolve_request(vec![
                batch_resolve_target("asset-1", "IMG_0001.dng", b"raw-bytes"),
                batch_resolve_target("asset-2", "IMG_0002.dng", b"other-raw"),
            ]),
        )
        .expect_err("one unresolved target must fail the whole batch");

    assert!(matches!(
        error,
        UploadError::OriginalAssetResolveNotUnique { matches: 0 }
    ));
}

#[test]
fn cloudkit_original_asset_batch_outcome_isolates_unresolved_targets() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let records = cloudkit_raw_pair_with(
        "CPLAsset-original-123",
        "CPLMaster-raw-123",
        "tag-1",
        9,
        1_800_000_000_000,
    );
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"raw-bytes".to_vec()],
    );

    let outcome = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch_outcome(
            &session,
            &batch_resolve_request(vec![
                batch_resolve_target("asset-1", "IMG_0001.dng", b"raw-bytes"),
                batch_resolve_target("asset-2", "IMG_0002.dng", b"other-raw"),
            ]),
        )
        .expect("monitor-facing outcome should preserve partial resolution");

    assert_eq!(
        outcome.exact_original_proofs()["asset-1"].record_name,
        "CPLAsset-original-123"
    );
    assert!(matches!(
        outcome.resolutions["asset-2"].disposition,
        CloudKitOriginalAssetResolveDisposition::RawHashMismatch
    ));
}

#[test]
fn cloudkit_original_asset_batch_reconciliation_keeps_exact_and_absent_targets_typed() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let records = cloudkit_raw_pair_with(
        "CPLAsset-original-123",
        "CPLMaster-raw-123",
        "tag-1",
        9,
        1_800_000_000_000,
    );
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"raw-bytes".to_vec()],
    );

    let outcome = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch_outcome(
            &session,
            &batch_resolve_request(vec![
                batch_resolve_target("asset-1", "IMG_0001.dng", b"raw-bytes"),
                batch_resolve_target("asset-2", "IMG_0002.dng", b"other-raw"),
            ]),
        )
        .expect("the completed inventory should report a disposition for every target");

    assert!(matches!(
        outcome.resolutions["asset-1"].disposition,
        CloudKitOriginalAssetResolveDisposition::ExactOriginal { .. }
    ));
    assert!(matches!(
        outcome.resolutions["asset-2"].disposition,
        CloudKitOriginalAssetResolveDisposition::RawHashMismatch
    ));
    assert_eq!(
        outcome.resolutions["asset-2"].observations.date_candidates,
        1
    );
    assert!(outcome.inventory.complete);
}

#[test]
fn cloudkit_original_asset_batch_reconciliation_classifies_each_terminal_absence() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let captured = 1_800_000_000_u64;
    let mut records = cloudkit_raw_pair_with(
        "CPLAsset-exact",
        "CPLMaster-exact",
        "tag-exact",
        9,
        (captured * 1000) as i64,
    );
    let mut no_raw = cloudkit_raw_pair_with(
        "CPLAsset-no-raw",
        "CPLMaster-no-raw",
        "tag-no-raw",
        9,
        ((captured + 10) * 1000) as i64,
    );
    no_raw[1]["fields"] = json!({});
    records
        .as_array_mut()
        .expect("records should be an array")
        .extend(
            no_raw
                .as_array()
                .expect("records should be an array")
                .clone(),
        );
    records
        .as_array_mut()
        .expect("records should be an array")
        .extend(
            cloudkit_raw_pair_with(
                "CPLAsset-wrong-size",
                "CPLMaster-wrong-size",
                "tag-wrong-size",
                8,
                ((captured + 20) * 1000) as i64,
            )
            .as_array()
            .expect("records should be an array")
            .clone(),
        );
    records
        .as_array_mut()
        .expect("records should be an array")
        .extend(
            cloudkit_raw_pair_with_url(
                "CPLAsset-wrong-hash",
                "CPLMaster-wrong-hash",
                "tag-wrong-hash",
                9,
                ((captured + 30) * 1000) as i64,
                "https://p140-icloud-content.icloud.com/wrong-hash",
            )
            .as_array()
            .expect("records should be an array")
            .clone(),
        );
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"raw-bytes".to_vec(), b"other-raw".to_vec()],
    );
    let target = |asset_id: &str, timestamp: u64| {
        let mut target = batch_resolve_target(asset_id, "IMG_0001.dng", b"raw-bytes");
        target.source_captured_unix_seconds = timestamp;
        target.capture_tolerance_seconds = 0;
        target
    };

    let outcome = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch_outcome(
            &session,
            &batch_resolve_request(vec![
                target("exact", captured),
                target("no-raw", captured + 10),
                target("wrong-size", captured + 20),
                target("wrong-hash", captured + 30),
                target("no-date", captured + 100),
            ]),
        )
        .expect("a complete scan should classify every target without a batch abort");

    assert!(matches!(
        outcome.resolutions["exact"].disposition,
        CloudKitOriginalAssetResolveDisposition::ExactOriginal { .. }
    ));
    assert!(matches!(
        outcome.resolutions["no-raw"].disposition,
        CloudKitOriginalAssetResolveDisposition::NoRawResource
    ));
    assert!(matches!(
        outcome.resolutions["wrong-size"].disposition,
        CloudKitOriginalAssetResolveDisposition::RawSizeMismatch
    ));
    assert!(matches!(
        outcome.resolutions["wrong-hash"].disposition,
        CloudKitOriginalAssetResolveDisposition::RawHashMismatch
    ));
    assert!(matches!(
        outcome.resolutions["no-date"].disposition,
        CloudKitOriginalAssetResolveDisposition::NoDateCandidate
    ));
    assert_eq!(
        outcome.resolutions["wrong-hash"]
            .observations
            .date_candidates,
        1
    );
    assert_eq!(
        outcome.resolutions["wrong-hash"].observations.raw_resources,
        1
    );
    assert_eq!(
        outcome.resolutions["wrong-hash"]
            .observations
            .raw_size_matches,
        1
    );
    assert_eq!(
        outcome.resolutions["wrong-hash"]
            .observations
            .raw_hash_matches,
        0
    );
    assert!(transport.payloads.is_empty());
    assert!(transport.lookup_payloads.is_empty());
}

#[test]
fn cloudkit_original_asset_batch_reconciliation_reports_remote_replacement_without_delete_proof() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let replacement = b"replacement-heic";
    let mut records = cloudkit_raw_pair_with(
        "CPLAsset-replacement",
        "CPLMaster-replacement",
        "tag-replacement",
        9,
        1_800_000_000_000,
    );
    records[1]["fields"]["resOriginalAltRes"] = json!({"value": {
        "size": replacement.len(),
        "downloadURL": "https://p140-icloud-content.icloud.com/replacement"
    }});
    records[1]["fields"]["resOriginalAltFileType"] = json!({"value": "public.heic"});
    let mut target = batch_resolve_target("asset-1", "IMG_0001.dng", b"other-raw");
    target.replacement_candidate = Some(CloudKitLocalReplacementCandidate {
        sha256: sha256_hex(replacement),
        size_bytes: replacement.len() as u64,
    });
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"raw-bytes".to_vec(), replacement.to_vec()],
    );

    let outcome = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch_outcome(&session, &batch_resolve_request(vec![target]))
        .expect("a replacement match should be an audit result");

    let CloudKitOriginalAssetResolveDisposition::ReplacementPresent { proof } =
        &outcome.resolutions["asset-1"].disposition
    else {
        panic!("replacement must not be reported as an original-delete proof");
    };
    assert_eq!(proof.record_name, "CPLAsset-replacement");
    assert_eq!(proof.size_bytes, replacement.len() as u64);
    assert!(outcome.exact_original_proofs().is_empty());
    assert_eq!(
        outcome.resolutions["asset-1"]
            .observations
            .replacement_resource_matches,
        1
    );
}

#[test]
fn cloudkit_original_asset_batch_reconciliation_marks_exact_and_replacement_ambiguous() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let replacement = b"replacement-heic";
    let mut records = cloudkit_raw_pair_with(
        "CPLAsset-both",
        "CPLMaster-both",
        "tag-both",
        9,
        1_800_000_000_000,
    );
    records[1]["fields"]["resOriginalAltRes"] = json!({"value": {
        "size": replacement.len(),
        "downloadURL": "https://p140-icloud-content.icloud.com/both-replacement"
    }});
    records[1]["fields"]["resOriginalAltFileType"] = json!({"value": "public.heif"});
    let mut target = batch_resolve_target("asset-1", "IMG_0001.dng", b"raw-bytes");
    target.replacement_candidate = Some(CloudKitLocalReplacementCandidate {
        sha256: sha256_hex(replacement),
        size_bytes: replacement.len() as u64,
    });
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"raw-bytes".to_vec(), replacement.to_vec()],
    );

    let outcome = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch_outcome(&session, &batch_resolve_request(vec![target]))
        .expect("both evidence classes should remain manual-safe");

    assert!(matches!(
        outcome.resolutions["asset-1"].disposition,
        CloudKitOriginalAssetResolveDisposition::Ambiguous
    ));
    assert!(outcome.exact_original_proofs().is_empty());
}

#[test]
fn cloudkit_original_asset_batch_reconciliation_scans_four_thousand_targets_once() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let targets = (0..4_000)
        .map(|index| batch_resolve_target(&format!("asset-{index}"), "IMG_0001.dng", b"raw-bytes"))
        .collect();
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": cloudkit_raw_pair_with(
            "CPLAsset-shared",
            "CPLMaster-shared",
            "tag-shared",
            9,
            1_800_000_000_000,
        )})],
        vec![b"raw-bytes".to_vec()],
    );

    let outcome = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch_outcome(&session, &batch_resolve_request(targets))
        .expect("one destination inventory should cover every target");

    assert_eq!(outcome.resolutions.len(), 4_000);
    assert_eq!(transport.query_payloads.len(), 1);
    assert_eq!(transport.downloaded_urls.len(), 1);
    assert!(outcome.resolutions.values().all(|resolution| matches!(
        resolution.disposition,
        CloudKitOriginalAssetResolveDisposition::Ambiguous
    )));
}

#[test]
fn cloudkit_original_asset_batch_reconciliation_rejects_an_invalid_local_replacement_candidate() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut target = batch_resolve_target("asset-1", "IMG_0001.dng", b"raw-bytes");
    target.replacement_candidate = Some(CloudKitLocalReplacementCandidate {
        sha256: String::new(),
        size_bytes: 0,
    });
    let mut transport = FakeCloudKitDeleteTransport::query_responses(vec![]);

    let error = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch_outcome(&session, &batch_resolve_request(vec![target]))
        .expect_err("a malformed local replacement candidate must not start a CloudKit scan");

    assert!(matches!(
        error,
        UploadError::InvalidCloudKitOriginalAssetRequest(_)
    ));
    assert!(transport.query_payloads.is_empty());
}

#[test]
fn cloudkit_original_asset_batch_inventory_fingerprint_includes_scanned_window_records() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let captured = 1_800_000_000_u64;
    let request = {
        let mut first = batch_resolve_target("asset-1", "IMG_0001.dng", b"raw-bytes");
        first.source_captured_unix_seconds = captured;
        first.capture_tolerance_seconds = 0;
        let mut second = batch_resolve_target("asset-2", "IMG_0002.dng", b"other-raw");
        second.source_captured_unix_seconds = captured + 100;
        second.capture_tolerance_seconds = 0;
        batch_resolve_request(vec![first, second])
    };
    let mut records = cloudkit_raw_pair_with(
        "CPLAsset-exact",
        "CPLMaster-exact",
        "tag-exact",
        9,
        (captured * 1000) as i64,
    );
    let gap_records = cloudkit_raw_pair_with(
        "CPLAsset-gap",
        "CPLMaster-gap",
        "tag-gap",
        9,
        ((captured + 50) * 1000) as i64,
    );
    records
        .as_array_mut()
        .expect("records should be an array")
        .extend(
            gap_records
                .as_array()
                .expect("records should be an array")
                .clone(),
        );
    let mut changed_records = records.clone();
    changed_records[2]["recordChangeTag"] = json!("tag-gap-changed");
    let mut first_transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"raw-bytes".to_vec()],
    );
    let mut second_transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": changed_records})],
        vec![b"raw-bytes".to_vec()],
    );

    let first = CloudKitDeleteClient::new(&mut first_transport)
        .resolve_original_assets_batch_outcome(&session, &request)
        .expect("first inventory should resolve");
    let second = CloudKitDeleteClient::new(&mut second_transport)
        .resolve_original_assets_batch_outcome(&session, &request)
        .expect("changed inventory should resolve");

    assert!(first.inventory.complete);
    assert_eq!(first.inventory.records_scanned, 4);
    assert_ne!(first.inventory.sha256, second.inventory.sha256);
}

#[test]
fn cloudkit_original_asset_batch_resolver_forwards_continuation_once() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut request = batch_resolve_request(vec![
        batch_resolve_target("asset-1", "IMG_0001.dng", b"raw-bytes"),
        batch_resolve_target("asset-2", "IMG_0002.dng", b"other-bytes"),
    ]);
    request.max_pages = 2;
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![
            json!({
                "records": cloudkit_raw_pair_with(
                    "CPLAsset-original-123",
                    "CPLMaster-raw-123",
                    "tag-1",
                    9,
                    1_800_000_000_000,
                ),
                "continuationMarker": "next-page"
            }),
            json!({
                "records": cloudkit_raw_pair_with(
                    "CPLAsset-original-456",
                    "CPLMaster-raw-456",
                    "tag-2",
                    11,
                    1_800_000_000_000,
                )
            }),
        ],
        vec![b"raw-bytes".to_vec(), b"other-bytes".to_vec()],
    );

    let proofs = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch(&session, &request)
        .expect("targets should resolve across continued pages");

    assert_eq!(proofs.len(), 2);
    assert!(
        transport.query_payloads[0]
            .get("continuationMarker")
            .is_none()
    );
    assert_eq!(
        transport.query_payloads[1]["continuationMarker"],
        json!("next-page")
    );
    assert_eq!(transport.query_payloads.len(), 2);
}

#[test]
fn cloudkit_original_asset_batch_resolver_scan_cap_with_continuation_fails_closed() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut request = batch_resolve_request(vec![
        batch_resolve_target("asset-1", "IMG_0001.dng", b"raw-bytes"),
        batch_resolve_target("asset-2", "IMG_0002.dng", b"other-bytes"),
    ]);
    request.max_pages = 1;
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({
            "records": cloudkit_raw_pair_with(
                "CPLAsset-original-123",
                "CPLMaster-raw-123",
                "tag-1",
                9,
                1_800_000_000_000,
            ),
            "continuationMarker": "next-page"
        })],
        vec![b"raw-bytes".to_vec()],
    );

    let outcome = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch_outcome(&session, &request)
        .expect("scan cap before exhaustion should remain a typed transient outcome");

    assert!(outcome.resolutions.values().all(|resolution| matches!(
        resolution.disposition,
        CloudKitOriginalAssetResolveDisposition::IncompleteTransient
    )));
    assert!(!outcome.inventory.complete);
}

#[test]
fn cloudkit_original_asset_batch_resolver_duplicate_candidate_for_one_target_fails_closed() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut records = cloudkit_raw_pair_with(
        "CPLAsset-original-123",
        "CPLMaster-raw-123",
        "tag-1",
        9,
        1_800_000_000_000,
    );
    records
        .as_array_mut()
        .expect("records should be array")
        .extend(
            cloudkit_raw_pair_with(
                "CPLAsset-original-456",
                "CPLMaster-raw-456",
                "tag-2",
                9,
                1_800_000_000_000,
            )
            .as_array()
            .expect("records should be array")
            .clone(),
        );
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"raw-bytes".to_vec(), b"raw-bytes".to_vec()],
    );

    let outcome = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch_outcome(
            &session,
            &batch_resolve_request(vec![batch_resolve_target(
                "asset-1",
                "IMG_0001.dng",
                b"raw-bytes",
            )]),
        )
        .expect("duplicate exact candidates should stay scoped to the affected target");

    assert!(matches!(
        outcome.resolutions["asset-1"].disposition,
        CloudKitOriginalAssetResolveDisposition::Ambiguous
    ));
}

#[test]
fn cloudkit_original_asset_batch_resolver_duplicate_original_for_two_targets_fails_closed() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let records = cloudkit_raw_pair_with(
        "CPLAsset-original-123",
        "CPLMaster-raw-123",
        "tag-1",
        9,
        1_800_000_000_000,
    );
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"raw-bytes".to_vec()],
    );

    let outcome = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch_outcome(
            &session,
            &batch_resolve_request(vec![
                batch_resolve_target("asset-1", "IMG_0001.dng", b"raw-bytes"),
                batch_resolve_target("asset-2", "IMG_0002.dng", b"raw-bytes"),
            ]),
        )
        .expect("one CloudKit original should only make its conflicting targets ambiguous");

    assert!(outcome.resolutions.values().all(|resolution| matches!(
        resolution.disposition,
        CloudKitOriginalAssetResolveDisposition::Ambiguous
    )));
}

#[test]
fn cloudkit_original_asset_batch_resolver_skips_wrong_hash_and_resolves_later_exact_match() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut records = cloudkit_raw_pair_with_url(
        "CPLAsset-original-123",
        "CPLMaster-raw-123",
        "tag-1",
        9,
        1_800_000_000_000,
        "https://p140-icloud-content.icloud.com/wrong-original",
    );
    records
        .as_array_mut()
        .expect("records should be array")
        .extend(
            cloudkit_raw_pair_with_url(
                "CPLAsset-original-456",
                "CPLMaster-raw-456",
                "tag-2",
                9,
                1_800_000_000_000,
                "https://p140-icloud-content.icloud.com/exact-original",
            )
            .as_array()
            .expect("records should be array")
            .clone(),
        );
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"wrong-raw".to_vec(), b"raw-bytes".to_vec()],
    );

    let proofs = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch(
            &session,
            &batch_resolve_request(vec![batch_resolve_target(
                "asset-1",
                "IMG_0001.dng",
                b"raw-bytes",
            )]),
        )
        .expect("later exact candidate should resolve after a wrong plausible hash");

    assert_eq!(proofs["asset-1"].record_name, "CPLAsset-original-456");
    assert_eq!(transport.downloaded_urls.len(), 2);
}

#[test]
fn cloudkit_original_asset_batch_resolver_ignores_out_of_window_malformed_master() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut records = cloudkit_raw_pair_with_url(
        "CPLAsset-out-of-window",
        "CPLMaster-out-of-window",
        "tag-old",
        9,
        1_700_000_000_000,
        "https://p140-icloud-content.icloud.com/out-of-window",
    );
    records[1]["fields"]
        .as_object_mut()
        .expect("fields should be an object")
        .remove("resOriginalFileType");
    records
        .as_array_mut()
        .expect("records should be array")
        .extend(
            cloudkit_raw_pair_with_url(
                "CPLAsset-original-456",
                "CPLMaster-raw-456",
                "tag-2",
                9,
                1_800_000_000_000,
                "https://p140-icloud-content.icloud.com/exact-original",
            )
            .as_array()
            .expect("records should be array")
            .clone(),
        );
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"raw-bytes".to_vec()],
    );

    let proofs = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch(
            &session,
            &batch_resolve_request(vec![batch_resolve_target(
                "asset-1",
                "IMG_0001.dng",
                b"raw-bytes",
            )]),
        )
        .expect("out-of-window malformed records should not abort batch resolution");

    assert_eq!(proofs["asset-1"].record_name, "CPLAsset-original-456");
    assert_eq!(
        transport.downloaded_urls,
        vec!["https://p140-icloud-content.icloud.com/exact-original".to_string()]
    );
}

#[test]
fn cloudkit_original_asset_batch_resolver_same_size_time_targets_resolve_by_exact_hash() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut records = cloudkit_raw_pair_with_url(
        "CPLAsset-original-123",
        "CPLMaster-raw-123",
        "tag-1",
        9,
        1_800_000_000_000,
        "https://p140-icloud-content.icloud.com/raw-a",
    );
    records
        .as_array_mut()
        .expect("records should be array")
        .extend(
            cloudkit_raw_pair_with_url(
                "CPLAsset-original-456",
                "CPLMaster-raw-456",
                "tag-2",
                9,
                1_800_000_000_000,
                "https://p140-icloud-content.icloud.com/raw-b",
            )
            .as_array()
            .expect("records should be array")
            .clone(),
        );
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"raw-bytes".to_vec(), b"other-raw".to_vec()],
    );

    let proofs = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch(
            &session,
            &batch_resolve_request(vec![
                batch_resolve_target("asset-1", "IMG_0001.dng", b"raw-bytes"),
                batch_resolve_target("asset-2", "IMG_0002.dng", b"other-raw"),
            ]),
        )
        .expect("same size/time targets should resolve by exact content hash");

    assert_eq!(proofs["asset-1"].record_name, "CPLAsset-original-123");
    assert_eq!(proofs["asset-2"].record_name, "CPLAsset-original-456");
    assert_eq!(
        transport.downloaded_urls,
        vec![
            "https://p140-icloud-content.icloud.com/raw-a".to_string(),
            "https://p140-icloud-content.icloud.com/raw-b".to_string(),
        ]
    );
}

#[test]
fn cloudkit_original_asset_batch_resolver_reuses_duplicate_resource_downloads() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let records = cloudkit_raw_pair_with_url(
        "CPLAsset-original-123",
        "CPLMaster-raw-123",
        "tag-1",
        9,
        1_800_000_000_000,
        "https://p140-icloud-content.icloud.com/shared-raw",
    );
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"raw-bytes".to_vec()],
    );

    let error = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_assets_batch(
            &session,
            &batch_resolve_request(vec![
                batch_resolve_target("asset-1", "IMG_0001.dng", b"raw-bytes"),
                batch_resolve_target("asset-2", "IMG_0002.dng", b"other-raw"),
            ]),
        )
        .expect_err("the unmatched target still fails the all-or-none batch");

    assert!(matches!(
        error,
        UploadError::OriginalAssetResolveNotUnique { matches: 0 }
    ));
    assert_eq!(
        transport.downloaded_urls,
        vec!["https://p140-icloud-content.icloud.com/shared-raw".to_string()]
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
fn cloudkit_original_asset_resolver_short_page_with_continuation_keeps_scanning() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut request = original_asset_resolve_request();
    request.page_size = 200;
    request.max_pages = 2;
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![
            json!({"records": [], "continuationMarker": "next-page"}),
            json!({
                "records": cloudkit_raw_pair(
                    "CPLAsset-original-123",
                    "CPLMaster-raw-123",
                    "change-tag-1",
                )
            }),
        ],
        vec![b"raw-bytes".to_vec()],
    );

    let proof = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_asset(&session, &request)
        .expect("later exact match should resolve after continued short page");

    assert_eq!(proof.record_name, "CPLAsset-original-123");
    assert_eq!(transport.query_payloads.len(), 2);
    assert!(
        transport.query_payloads[0]
            .get("continuationMarker")
            .is_none()
    );
    assert_eq!(
        transport.query_payloads[1]["continuationMarker"],
        json!("next-page")
    );
    assert_eq!(
        transport.query_payloads[1]["query"]["filterBy"][1]["fieldValue"]["value"],
        0
    );
}

#[test]
fn cloudkit_original_asset_resolver_short_page_without_continuation_stops() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut request = original_asset_resolve_request();
    request.page_size = 200;
    request.max_pages = 2;
    let mut transport = FakeCloudKitDeleteTransport::query_responses(vec![
        json!({"records": []}),
        json!({
            "records": cloudkit_raw_pair(
                "CPLAsset-original-123",
                "CPLMaster-raw-123",
                "change-tag-1",
            )
        }),
    ]);

    let error = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_asset(&session, &request)
        .expect_err("absence of continuation proves exhaustion");

    assert!(matches!(
        error,
        UploadError::OriginalAssetResolveNotUnique { matches: 0 }
    ));
    assert_eq!(transport.query_payloads.len(), 1);
}

#[test]
fn cloudkit_original_asset_resolver_rejects_malformed_continuation_markers() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");

    for continuation_marker in [json!(""), json!("   "), json!(42), json!(true)] {
        let mut request = original_asset_resolve_request();
        request.max_pages = 1;
        let mut transport = FakeCloudKitDeleteTransport::query_responses(vec![json!({
            "records": [],
            "continuationMarker": continuation_marker,
        })]);

        let error = CloudKitDeleteClient::new(&mut transport)
            .resolve_original_asset(&session, &request)
            .expect_err("malformed continuation markers must fail closed");

        assert!(matches!(
            error,
            UploadError::InvalidCloudKitOriginalAssetResponse(_)
        ));
    }
}

#[test]
fn cloudkit_original_asset_resolver_fails_when_max_pages_reached_without_exhaustion() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut request = original_asset_resolve_request();
    request.page_size = 2;
    request.max_pages = 1;
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({
            "records": cloudkit_raw_pair("CPLAsset-original-123", "CPLMaster-raw-123", "change-tag-1"),
            "continuationMarker": "next-page"
        })],
        vec![b"raw-bytes".to_vec()],
    );

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
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"raw-bytes".to_vec(), b"raw-bytes".to_vec()],
    );

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
fn cloudkit_original_asset_resolver_rejects_direct_resource_object() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut records = cloudkit_raw_pair("CPLAsset-original-123", "CPLMaster-raw-123", "tag-1");
    records[1]["fields"]["resOriginalRes"] =
        json!({"size": 9, "downloadURL": "https://p140-icloud-content.icloud.com/raw-original"});
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"raw-bytes".to_vec()],
    );

    let error = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_asset(&session, &original_asset_resolve_request())
        .expect_err("direct resource objects must fail closed");

    assert!(matches!(
        error,
        UploadError::InvalidCloudKitOriginalAssetResponse(_)
    ));
}

#[test]
fn cloudkit_original_asset_resolver_rejects_alternate_size_names() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut records = cloudkit_raw_pair("CPLAsset-original-123", "CPLMaster-raw-123", "tag-1");
    records[1]["fields"]["resOriginalRes"]["value"] = json!({
        "sizeBytes": 9,
        "downloadURL": "https://p140-icloud-content.icloud.com/raw-original"
    });
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"raw-bytes".to_vec()],
    );

    let error = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_asset(&session, &original_asset_resolve_request())
        .expect_err("alternate size names must fail closed");

    assert!(matches!(
        error,
        UploadError::InvalidCloudKitOriginalAssetResponse(_)
    ));
}

#[test]
fn cloudkit_original_asset_resolver_rejects_mismatched_download_hash() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let records = cloudkit_raw_pair("CPLAsset-original-123", "CPLMaster-raw-123", "tag-1");
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"other-raw".to_vec()],
    );

    let error = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_asset(&session, &original_asset_resolve_request())
        .expect_err("download hash mismatch must fail closed");

    assert!(matches!(
        error,
        UploadError::OriginalAssetResolveNotUnique { matches: 0 }
    ));
}

#[test]
fn cloudkit_original_asset_resolver_rejects_missing_download_url() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let mut records = cloudkit_raw_pair("CPLAsset-original-123", "CPLMaster-raw-123", "tag-1");
    records[1]["fields"]["resOriginalRes"]["value"]
        .as_object_mut()
        .expect("resource value should be object")
        .remove("downloadURL");
    let mut transport =
        FakeCloudKitDeleteTransport::query_responses(vec![json!({"records": records})]);

    let error = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_asset(&session, &original_asset_resolve_request())
        .expect_err("missing downloadURL must fail closed");

    assert!(matches!(
        error,
        UploadError::InvalidCloudKitOriginalAssetResponse(_)
    ));
}

#[test]
fn cloudkit_original_asset_resolver_rejects_wrong_download_byte_count() {
    let session = CloudKitDeleteSession::from_json(&valid_delete_session_json())
        .expect("session should load");
    let records = cloudkit_raw_pair("CPLAsset-original-123", "CPLMaster-raw-123", "tag-1");
    let mut transport = FakeCloudKitDeleteTransport::query_responses_with_downloads(
        vec![json!({"records": records})],
        vec![b"raw-bytes-extra".to_vec()],
    );

    let error = CloudKitDeleteClient::new(&mut transport)
        .resolve_original_asset(&session, &original_asset_resolve_request())
        .expect_err("wrong byte count must fail closed");

    assert!(matches!(
        error,
        UploadError::CloudKitOriginalAssetDownloadSizeMismatch { .. }
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
fn photos_upload_client_accepts_duplicate_put_asset_response_as_existing_upload() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    let session = UploadSession::from_json(&valid_session_json()).expect("session should load");
    let mut transport = FakePhotosTransport::success();
    transport.put_asset_response = json!([{
        "cplMaster": "CPLMaster-existing",
        "cplAsset": "CPLAsset-existing",
        "response": {
            "status": 409,
            "errorMessage": "duplicate photo found"
        }
    }]);

    let outcome = PhotosUploadClient::new(&mut transport)
        .with_status_poll_delay(std::time::Duration::ZERO)
        .upload_heic(&session, &heic_path)
        .expect("duplicate putAsset responses identify an existing upload");

    assert_eq!(outcome.response.asset_id, "CPLAsset-existing");
    assert_eq!(
        outcome.response.master_id.as_deref(),
        Some("CPLMaster-existing")
    );
    assert_eq!(outcome.streamed_heic_sha256, sha256_hex(b"heic-bytes"));
    assert_eq!(outcome.streamed_size_bytes, b"heic-bytes".len() as u64);
    assert_eq!(transport.service_calls.len(), 2);
    assert_eq!(
        transport.service_calls[0].0,
        PhotosUploadEndpoint::CreateUploadUrl
    );
    assert_eq!(transport.service_calls[1].0, PhotosUploadEndpoint::PutAsset);
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
        UploadError::PhotosPutAssetRejected { status: 500, detail }
            if detail.contains("\"status\":500") && detail.contains("CPLAsset-123")
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
        destination: CloudKitLibraryDestination::primary_sync(),
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
        destination: CloudKitLibraryDestination::primary_sync(),
    })
    .expect_err("non-UTF8 filename should fail before filesystem access");

    assert!(matches!(error, UploadError::InvalidFilename { .. }));
}

#[test]
fn run_icloud_upload_rejects_png_filename_before_upload_session_use() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let session_path = tempdir.path().join("session.json");
    write_session(&session_path, &valid_session_json());
    let png_path = tempdir.path().join("IMG_0001.heic-preview.png");
    fs::write(&png_path, b"png-bytes").expect("png should be written");

    let error = run_icloud_upload(&IcloudUploadRequest {
        session_path,
        heic_path: png_path.clone(),
        destination: CloudKitLibraryDestination::primary_sync(),
    })
    .expect_err("PNG preview files must not be accepted as HEIC upload candidates");

    assert!(matches!(
        error,
        UploadError::InvalidHeicExtension { path } if path == png_path
    ));
}

#[test]
fn photos_upload_client_posts_requested_shared_library_zone() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    let session = UploadSession::from_json(&valid_session_json()).expect("session should load");
    let mut transport = FakePhotosTransport::success();
    let destination = CloudKitLibraryDestination {
        database_scope: CloudKitDatabaseScope::Shared,
        zone_name: "SharedSync-ABCDEF123456".to_string(),
    };

    let outcome = PhotosUploadClient::new(&mut transport)
        .with_status_poll_delay(std::time::Duration::ZERO)
        .upload_heic_to_library(&session, &heic_path, &destination)
        .expect("shared library upload should succeed");

    assert_eq!(
        transport.service_calls[0].1["zoneName"],
        json!("SharedSync-ABCDEF123456")
    );
    assert_eq!(
        transport.service_calls[1].1["zoneName"],
        json!("SharedSync-ABCDEF123456")
    );
    assert_eq!(
        outcome.response.database_scope,
        CloudKitDatabaseScope::Shared
    );
    assert_eq!(outcome.response.zone_name, "SharedSync-ABCDEF123456");
}

#[test]
fn photos_upload_client_rejects_private_non_primary_zone() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let heic_path = tempdir.path().join("IMG_0001.heic");
    fs::write(&heic_path, b"heic-bytes").expect("heic should be written");
    let session = UploadSession::from_json(&valid_session_json()).expect("session should load");
    let mut transport = FakePhotosTransport::success();
    let destination = CloudKitLibraryDestination {
        database_scope: CloudKitDatabaseScope::Private,
        zone_name: "TypoSync".to_string(),
    };

    let error = PhotosUploadClient::new(&mut transport)
        .upload_heic_to_library(&session, &heic_path, &destination)
        .expect_err("private uploads must not route to arbitrary zones");

    assert!(matches!(error, UploadError::InvalidSession(_)));
    assert!(transport.service_calls.is_empty());
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
    assert_eq!(upload_proof.database_scope, CloudKitDatabaseScope::Private);
    assert_eq!(upload_proof.zone_name, "PrimarySync");
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
            database_scope: CloudKitDatabaseScope::Private,
            zone_name: "PrimarySync".to_string(),
        },
        streamed_heic_sha256: sha256_hex(bytes),
        streamed_size_bytes: bytes.len() as u64,
        timings: Default::default(),
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
    lookup_payloads: Vec<Value>,
    downloaded_urls: Vec<String>,
    response: Value,
    query_responses: Vec<Value>,
    lookup_responses: Vec<Value>,
    resource_bodies: Vec<Vec<u8>>,
}

impl FakeCloudKitDeleteTransport {
    fn success() -> Self {
        Self {
            payloads: Vec::new(),
            query_payloads: Vec::new(),
            lookup_payloads: Vec::new(),
            downloaded_urls: Vec::new(),
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
            lookup_responses: Vec::new(),
            resource_bodies: Vec::new(),
        }
    }

    fn modify_response(response: Value) -> Self {
        Self {
            response,
            ..Self::success()
        }
    }

    fn query_responses(query_responses: Vec<Value>) -> Self {
        Self {
            payloads: Vec::new(),
            query_payloads: Vec::new(),
            lookup_payloads: Vec::new(),
            downloaded_urls: Vec::new(),
            response: json!({"records": []}),
            query_responses,
            lookup_responses: Vec::new(),
            resource_bodies: Vec::new(),
        }
    }

    fn query_responses_with_downloads(
        query_responses: Vec<Value>,
        resource_bodies: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            payloads: Vec::new(),
            query_payloads: Vec::new(),
            lookup_payloads: Vec::new(),
            downloaded_urls: Vec::new(),
            response: json!({"records": []}),
            query_responses,
            lookup_responses: Vec::new(),
            resource_bodies,
        }
    }

    fn lookup_responses_with_downloads(
        lookup_responses: Vec<Value>,
        resource_bodies: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            payloads: Vec::new(),
            query_payloads: Vec::new(),
            lookup_payloads: Vec::new(),
            downloaded_urls: Vec::new(),
            response: json!({"records": []}),
            query_responses: Vec::new(),
            lookup_responses,
            resource_bodies,
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

    fn post_records_lookup(
        &mut self,
        _session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError> {
        self.lookup_payloads.push(payload);
        Ok(self.lookup_responses.remove(0))
    }

    fn download_resource(
        &mut self,
        _session: &CloudKitDeleteSession,
        download_url: &url::Url,
        expected_size_bytes: u64,
    ) -> Result<icloudpd_optimizer::upload::CloudKitResourceDownload, UploadError> {
        self.downloaded_urls.push(download_url.as_str().to_string());
        let bytes = self.resource_bodies.remove(0);
        let size_bytes = bytes.len() as u64;
        if size_bytes != expected_size_bytes {
            return Err(UploadError::CloudKitOriginalAssetDownloadSizeMismatch {
                expected: expected_size_bytes,
                actual: size_bytes,
            });
        }
        Ok(icloudpd_optimizer::upload::CloudKitResourceDownload {
            sha256: sha256_hex(&bytes),
            size_bytes,
        })
    }
}

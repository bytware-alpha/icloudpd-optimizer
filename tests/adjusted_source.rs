use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use icloudpd_optimizer::adjusted_source::{
    AdjustedSourceError, CloudKitAdjustedSourceDownload, CloudKitAdjustedSourceProof,
    CloudKitAdjustedSourceResolveRequest, CloudKitAdjustedSourceResolver,
    CloudKitAdjustedSourceTransport,
};
use icloudpd_optimizer::upload::{
    CloudKitDatabaseScope, CloudKitDeleteSession, CloudKitLibraryDestination,
};
use icloudpd_optimizer::workflow::OriginalAssetProof;
use image::codecs::jpeg::JpegEncoder;
use image::{DynamicImage, GrayImage, Luma, Rgb, RgbImage};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use url::Url;

const ASSET_RECORD: &str = "asset-record";
const ASSET_TAG: &str = "asset-tag";
const MASTER_RECORD: &str = "master-record";
const MASTER_TAG: &str = "master-tag";
const ZONE: &str = "PrimarySync";
const FINGERPRINT: &str = "opaque-file-checksum";

fn nonblank_jpeg(width: u32, height: u32) -> Vec<u8> {
    let mut image = RgbImage::new(width, height);
    for (x, y, pixel) in image.enumerate_pixels_mut() {
        *pixel = Rgb([
            ((x * 41 + y * 17) % 255) as u8,
            ((x * 13 + y * 73 + 19) % 255) as u8,
            ((x * 67 + y * 29 + 37) % 255) as u8,
        ]);
    }
    let mut bytes = Vec::new();
    JpegEncoder::new_with_quality(&mut bytes, 100)
        .encode_image(&DynamicImage::ImageRgb8(image))
        .expect("nonblank test JPEG should encode");
    bytes
}

fn uniform_jpeg(width: u32, height: u32) -> Vec<u8> {
    let image = GrayImage::from_pixel(width, height, Luma([0]));
    let mut bytes = Vec::new();
    JpegEncoder::new_with_quality(&mut bytes, 100)
        .encode_image(&DynamicImage::ImageLuma8(image))
        .expect("uniform test JPEG should encode");
    bytes
}

fn jpeg_with_exif_orientation(width: u32, height: u32, orientation: u8) -> Vec<u8> {
    let mut jpeg = nonblank_jpeg(width, height);
    let exif = [
        b'E',
        b'x',
        b'i',
        b'f',
        0,
        0,
        b'I',
        b'I',
        42,
        0,
        8,
        0,
        0,
        0,
        1,
        0,
        0x12,
        0x01,
        3,
        0,
        1,
        0,
        0,
        0,
        orientation,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let length = (exif.len() + 2) as u16;
    let mut segment = vec![0xff, 0xe1];
    segment.extend_from_slice(&length.to_be_bytes());
    segment.extend_from_slice(&exif);
    jpeg.splice(2..2, segment);
    jpeg
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn session() -> CloudKitDeleteSession {
    CloudKitDeleteSession {
        dsid: "test-account".to_string(),
        ckdatabasews_url: Url::parse("https://example.invalid").expect("test URL"),
        cloudkit_query_params: Vec::new(),
        cookies: Vec::new(),
        database_scope: CloudKitDatabaseScope::Private,
        zone: CloudKitLibraryDestination::primary_sync(),
    }
}

fn original_proof() -> OriginalAssetProof {
    OriginalAssetProof {
        record_name: ASSET_RECORD.to_string(),
        record_change_tag: ASSET_TAG.to_string(),
        record_type: "CPLAsset".to_string(),
        database_scope: CloudKitDatabaseScope::Private,
        zone_name: ZONE.to_string(),
        filename: "source.dng".to_string(),
        size_bytes: 42,
        matched_raw_sha256: "raw-sha256".to_string(),
    }
}

fn resolve_request(output_path: PathBuf) -> CloudKitAdjustedSourceResolveRequest {
    CloudKitAdjustedSourceResolveRequest {
        asset_id: "local-asset".to_string(),
        original_asset: original_proof(),
        output_path,
    }
}

fn zone() -> Value {
    json!({"zoneName": ZONE})
}

fn wrapper(kind: &str, value: Value) -> Value {
    json!({"type": kind, "value": value})
}

fn nondeleted() -> Value {
    wrapper("INT64", json!(0))
}

fn adjusted_fields(bytes: &[u8], width: u32, height: u32) -> Value {
    json!({
        "resJPEGFullRes": wrapper("ASSETID", json!({
            "downloadURL": "https://example.icloud.com/adjusted.jpg",
            "size": bytes.len(),
            "fileChecksum": FINGERPRINT,
            "referenceChecksum": "opaque-reference-checksum",
            "wrappingKey": "opaque-wrapping-key"
        })),
        "resJPEGFullWidth": wrapper("INT64", json!(width)),
        "resJPEGFullHeight": wrapper("INT64", json!(height)),
        "resJPEGFullFileType": wrapper("STRING", json!("public.jpeg")),
        "resJPEGFullFingerprint": wrapper("STRING", json!(FINGERPRINT))
    })
}

fn master_ref() -> Value {
    wrapper(
        "REFERENCE",
        json!({
            "recordName": MASTER_RECORD,
            "action": "DELETE_SELF",
            "zoneID": zone()
        }),
    )
}

fn record(record_name: &str, record_type: &str, change_tag: &str, fields: Value) -> Value {
    let mut fields = fields.as_object().expect("test fields object").clone();
    fields.insert("isDeleted".to_string(), nondeleted());
    json!({
        "recordName": record_name,
        "recordType": record_type,
        "recordChangeTag": change_tag,
        "zoneID": zone(),
        "fields": fields
    })
}

fn direct_asset_record(bytes: &[u8], width: u32, height: u32) -> Value {
    record(
        ASSET_RECORD,
        "CPLAsset",
        ASSET_TAG,
        adjusted_fields(bytes, width, height),
    )
}

fn master_record(bytes: &[u8], width: u32, height: u32) -> Value {
    record(
        MASTER_RECORD,
        "CPLMaster",
        MASTER_TAG,
        adjusted_fields(bytes, width, height),
    )
}

#[derive(Default)]
struct FakeTransport {
    lookups: VecDeque<Value>,
    downloads: VecDeque<Vec<u8>>,
    lookup_payloads: Vec<Value>,
    download_calls: usize,
}

impl CloudKitAdjustedSourceTransport for FakeTransport {
    fn post_records_lookup(
        &mut self,
        _session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, AdjustedSourceError> {
        self.lookup_payloads.push(payload);
        Ok(self
            .lookups
            .pop_front()
            .expect("lookup response should exist"))
    }

    fn download_resource_to_create_new(
        &mut self,
        _session: &CloudKitDeleteSession,
        _download_url: &Url,
        _expected_size_bytes: u64,
        temp_path: &Path,
    ) -> Result<CloudKitAdjustedSourceDownload, AdjustedSourceError> {
        self.download_calls += 1;
        let bytes = self
            .downloads
            .pop_front()
            .expect("download bytes should exist");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temp_path)
            .expect("fake transport should create temp");
        file.write_all(&bytes)
            .expect("fake transport should write temp");
        file.sync_all().expect("fake transport should sync temp");
        Ok(CloudKitAdjustedSourceDownload {
            size_bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
        })
    }
}

struct FailingAfterTempTransport {
    lookup: Value,
    temp_paths: Vec<PathBuf>,
}

impl CloudKitAdjustedSourceTransport for FailingAfterTempTransport {
    fn post_records_lookup(
        &mut self,
        _session: &CloudKitDeleteSession,
        _payload: Value,
    ) -> Result<Value, AdjustedSourceError> {
        Ok(self.lookup.clone())
    }

    fn download_resource_to_create_new(
        &mut self,
        _session: &CloudKitDeleteSession,
        _download_url: &Url,
        _expected_size_bytes: u64,
        temp_path: &Path,
    ) -> Result<CloudKitAdjustedSourceDownload, AdjustedSourceError> {
        self.temp_paths.push(temp_path.to_path_buf());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temp_path)
            .expect("fake transport should create temp");
        file.write_all(b"partial")
            .expect("fake transport should write partial bytes");
        Err(AdjustedSourceError::Filesystem)
    }
}

fn no_temp_files(directory: &Path) -> bool {
    std::fs::read_dir(directory)
        .expect("test directory should read")
        .all(|entry| {
            !entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .contains(".adjusted-")
        })
}

fn resolve_error(record: Value) -> (AdjustedSourceError, FakeTransport, tempfile::TempDir) {
    let mut transport = FakeTransport {
        lookups: VecDeque::from([json!({"records": [record]})]),
        ..Default::default()
    };
    let directory = tempdir().expect("test directory");
    let error = CloudKitAdjustedSourceResolver::new(&mut transport)
        .resolve(
            &session(),
            &resolve_request(directory.path().join("adjusted.jpg")),
        )
        .expect_err("invalid response must fail closed");
    (error, transport, directory)
}

#[test]
fn resolves_direct_asset_with_exact_adjusted_contract_and_redacted_proof() {
    let bytes = nonblank_jpeg(4, 3);
    let mut transport = FakeTransport {
        lookups: VecDeque::from([json!({"records": [direct_asset_record(&bytes, 4, 3)]})]),
        downloads: VecDeque::from([bytes.clone()]),
        ..Default::default()
    };
    let directory = tempdir().expect("test directory");
    let output_path = directory.path().join("adjusted.jpg");

    let proof = CloudKitAdjustedSourceResolver::new(&mut transport)
        .resolve(&session(), &resolve_request(output_path.clone()))
        .expect("direct adjusted JPEG should resolve");

    assert_eq!(proof.resource_record_name, ASSET_RECORD);
    assert_eq!(proof.resource_record_change_tag, ASSET_TAG);
    assert_eq!(proof.resource_record_type, "CPLAsset");
    assert_eq!(proof.declared_fingerprint, FINGERPRINT);
    assert_eq!(proof.declared_size_bytes, bytes.len() as u64);
    assert_eq!(proof.downloaded_sha256, sha256_hex(&bytes));
    assert_eq!(proof.width, 4);
    assert_eq!(proof.height, 3);
    assert_eq!(proof.orientation, 1);
    assert_eq!(std::fs::read(&output_path).expect("output bytes"), bytes);
    assert_eq!(transport.lookup_payloads.len(), 1);
    assert_eq!(
        transport.lookup_payloads[0]["desiredKeys"],
        json!([
            "masterRef",
            "isDeleted",
            "resJPEGFullRes",
            "resJPEGFullWidth",
            "resJPEGFullHeight",
            "resJPEGFullFileType",
            "resJPEGFullFingerprint"
        ])
    );
    let encoded = serde_json::to_string(&proof).expect("proof serializes");
    let decoded: CloudKitAdjustedSourceProof =
        serde_json::from_str(&encoded).expect("proof deserializes");
    assert_eq!(decoded, proof);
    for forbidden in [
        "downloadURL",
        "cookies",
        "session",
        "headers",
        "example.icloud.com",
    ] {
        assert!(!encoded.contains(forbidden));
    }
}

#[test]
fn resolves_exact_master_fallback_only_when_asset_has_no_adjusted_fields() {
    let bytes = nonblank_jpeg(4, 3);
    let asset = record(
        ASSET_RECORD,
        "CPLAsset",
        ASSET_TAG,
        json!({"masterRef": master_ref()}),
    );
    let mut transport = FakeTransport {
        lookups: VecDeque::from([
            json!({"records": [asset]}),
            json!({"records": [master_record(&bytes, 4, 3)]}),
        ]),
        downloads: VecDeque::from([bytes]),
        ..Default::default()
    };
    let directory = tempdir().expect("test directory");

    let proof = CloudKitAdjustedSourceResolver::new(&mut transport)
        .resolve(
            &session(),
            &resolve_request(directory.path().join("adjusted.jpg")),
        )
        .expect("exact master fallback should resolve");

    assert_eq!(proof.master_record_name.as_deref(), Some(MASTER_RECORD));
    assert_eq!(proof.resource_record_name, MASTER_RECORD);
    assert_eq!(proof.resource_record_change_tag, MASTER_TAG);
    assert_eq!(transport.lookup_payloads.len(), 2);
    assert_eq!(transport.lookup_payloads[1]["desiredKeys"][0], "isDeleted");
}

#[test]
fn direct_asset_precedence_never_parses_or_looks_up_master() {
    let bytes = nonblank_jpeg(4, 3);
    let mut asset = direct_asset_record(&bytes, 4, 3);
    asset["fields"]["masterRef"] = json!({"type": "not-reference", "value": null});
    let mut transport = FakeTransport {
        lookups: VecDeque::from([json!({"records": [asset]})]),
        downloads: VecDeque::from([bytes]),
        ..Default::default()
    };
    let directory = tempdir().expect("test directory");

    let proof = CloudKitAdjustedSourceResolver::new(&mut transport)
        .resolve(
            &session(),
            &resolve_request(directory.path().join("adjusted.jpg")),
        )
        .expect("complete direct asset must take precedence");

    assert_eq!(proof.resource_record_name, ASSET_RECORD);
    assert_eq!(transport.lookup_payloads.len(), 1);
}

#[test]
fn partial_or_malformed_asset_adjusted_fields_fail_without_master_fallback() {
    let bytes = nonblank_jpeg(4, 3);
    for mutation in [
        ("resJPEGFullWidth", Value::Null),
        (
            "resJPEGFullRes",
            json!({"type": "ASSETID", "value": "malformed"}),
        ),
    ] {
        let mut asset = direct_asset_record(&bytes, 4, 3);
        if mutation.1.is_null() {
            asset["fields"]
                .as_object_mut()
                .expect("fields")
                .remove(mutation.0);
        } else {
            asset["fields"][mutation.0] = mutation.1;
        }
        asset["fields"]["masterRef"] = master_ref();
        let mut transport = FakeTransport {
            lookups: VecDeque::from([json!({"records": [asset]})]),
            ..Default::default()
        };
        let directory = tempdir().expect("test directory");
        let error = CloudKitAdjustedSourceResolver::new(&mut transport)
            .resolve(
                &session(),
                &resolve_request(directory.path().join("adjusted.jpg")),
            )
            .expect_err("partial adjusted metadata must not fall back");
        assert!(matches!(error, AdjustedSourceError::InvalidResponse(_)));
        assert_eq!(transport.lookup_payloads.len(), 1);
        assert_eq!(transport.download_calls, 0);
    }
}

#[test]
fn rejects_lookup_cardinality_identity_deletion_and_required_zone_failures() {
    let bytes = nonblank_jpeg(4, 3);
    let mut deleted = direct_asset_record(&bytes, 4, 3);
    deleted["fields"]["isDeleted"] = wrapper("INT64", json!(1));
    let mut wrong_type = direct_asset_record(&bytes, 4, 3);
    wrong_type["recordType"] = json!("CPLMaster");
    let mut wrong_tag = direct_asset_record(&bytes, 4, 3);
    wrong_tag["recordChangeTag"] = json!("other-tag");
    let mut missing_zone = direct_asset_record(&bytes, 4, 3);
    missing_zone
        .as_object_mut()
        .expect("record")
        .remove("zoneID");
    let mut wrong_zone = direct_asset_record(&bytes, 4, 3);
    wrong_zone["zoneID"] = json!({"zoneName": "OtherZone"});
    let mut server_error = direct_asset_record(&bytes, 4, 3);
    server_error["serverErrorCode"] = json!("CONFLICT");

    let responses = [
        json!({"records": []}),
        json!({"records": [direct_asset_record(&bytes, 4, 3), direct_asset_record(&bytes, 4, 3)]}),
        json!({"records": [deleted]}),
        json!({"records": [wrong_type]}),
        json!({"records": [wrong_tag]}),
        json!({"records": [missing_zone]}),
        json!({"records": [wrong_zone]}),
        json!({"records": [server_error]}),
    ];
    for response in responses {
        let mut transport = FakeTransport {
            lookups: VecDeque::from([response]),
            ..Default::default()
        };
        let directory = tempdir().expect("test directory");
        let error = CloudKitAdjustedSourceResolver::new(&mut transport)
            .resolve(
                &session(),
                &resolve_request(directory.path().join("adjusted.jpg")),
            )
            .expect_err("invalid lookup record must fail closed");
        assert!(matches!(error, AdjustedSourceError::InvalidResponse(_)));
        assert_eq!(transport.download_calls, 0);
    }
}

#[test]
fn rejects_master_reference_type_action_name_or_zone_failures_before_lookup() {
    let invalid_refs = [
        json!({"type": "STRING", "value": {"recordName": MASTER_RECORD, "action": "DELETE_SELF", "zoneID": zone()}}),
        wrapper(
            "REFERENCE",
            json!({"recordName": MASTER_RECORD, "action": "NONE", "zoneID": zone()}),
        ),
        wrapper(
            "REFERENCE",
            json!({"recordName": "", "action": "DELETE_SELF", "zoneID": zone()}),
        ),
        wrapper(
            "REFERENCE",
            json!({"recordName": MASTER_RECORD, "action": "DELETE_SELF"}),
        ),
        wrapper(
            "REFERENCE",
            json!({"recordName": MASTER_RECORD, "action": "DELETE_SELF", "zoneID": {"zoneName": "OtherZone"}}),
        ),
    ];
    for master_ref_value in invalid_refs {
        let asset = record(
            ASSET_RECORD,
            "CPLAsset",
            ASSET_TAG,
            json!({"masterRef": master_ref_value}),
        );
        let mut transport = FakeTransport {
            lookups: VecDeque::from([json!({"records": [asset]})]),
            ..Default::default()
        };
        let directory = tempdir().expect("test directory");
        let error = CloudKitAdjustedSourceResolver::new(&mut transport)
            .resolve(
                &session(),
                &resolve_request(directory.path().join("adjusted.jpg")),
            )
            .expect_err("invalid master reference must fail closed");
        assert!(matches!(error, AdjustedSourceError::InvalidResponse(_)));
        assert_eq!(transport.lookup_payloads.len(), 1);
    }
}

#[test]
fn rejects_exact_wrapper_types_and_asset_checksum_contract_failures() {
    let bytes = nonblank_jpeg(4, 3);
    let wrapper_failures = [
        ("resJPEGFullRes", wrapper("STRING", json!({}))),
        ("resJPEGFullWidth", wrapper("STRING", json!(4))),
        ("resJPEGFullHeight", wrapper("INT64", json!("3"))),
        (
            "resJPEGFullFileType",
            wrapper("INT64", json!("public.jpeg")),
        ),
        (
            "resJPEGFullFingerprint",
            wrapper("INT64", json!(FINGERPRINT)),
        ),
    ];
    for (field, value) in wrapper_failures {
        let mut asset = direct_asset_record(&bytes, 4, 3);
        asset["fields"][field] = value;
        let (error, transport, _) = resolve_error(asset);
        assert!(matches!(error, AdjustedSourceError::InvalidResponse(_)));
        assert_eq!(transport.download_calls, 0);
    }

    for asset_mutation in [
        ("fileChecksum", Value::Null),
        ("referenceChecksum", Value::Null),
        ("wrappingKey", Value::Null),
        ("size", json!(0)),
        ("fileChecksum", json!("different-opaque-checksum")),
    ] {
        let mut asset = direct_asset_record(&bytes, 4, 3);
        if asset_mutation.1.is_null() {
            asset["fields"]["resJPEGFullRes"]["value"]
                .as_object_mut()
                .expect("asset value")
                .remove(asset_mutation.0);
        } else {
            asset["fields"]["resJPEGFullRes"]["value"][asset_mutation.0] = asset_mutation.1;
        }
        let (error, transport, _) = resolve_error(asset);
        assert!(matches!(error, AdjustedSourceError::InvalidResponse(_)));
        assert_eq!(transport.download_calls, 0);
    }
}

#[test]
fn rejects_bad_resource_url_and_every_non_jpeg_file_type_before_download() {
    let bytes = nonblank_jpeg(4, 3);
    let mut bad_url = direct_asset_record(&bytes, 4, 3);
    bad_url["fields"]["resJPEGFullRes"]["value"]["downloadURL"] =
        json!("http://invalid.example/adjusted.jpg");
    let (error, transport, _) = resolve_error(bad_url);
    assert!(matches!(error, AdjustedSourceError::InvalidResourceUrl));
    assert_eq!(transport.download_calls, 0);

    for file_type in ["public.heic", "public.png", "other"] {
        let mut asset = direct_asset_record(&bytes, 4, 3);
        asset["fields"]["resJPEGFullFileType"]["value"] = json!(file_type);
        let (error, transport, _) = resolve_error(asset);
        assert!(matches!(error, AdjustedSourceError::InvalidResponse(_)));
        assert_eq!(transport.download_calls, 0);
    }
}

#[test]
fn rejects_short_or_oversize_streams_and_cleans_temp() {
    let expected = nonblank_jpeg(4, 3);
    for bytes in [
        expected[..expected.len() - 1].to_vec(),
        [expected.clone(), vec![0]].concat(),
    ] {
        let mut transport = FakeTransport {
            lookups: VecDeque::from([json!({"records": [direct_asset_record(&expected, 4, 3)]})]),
            downloads: VecDeque::from([bytes]),
            ..Default::default()
        };
        let directory = tempdir().expect("test directory");
        let error = CloudKitAdjustedSourceResolver::new(&mut transport)
            .resolve(
                &session(),
                &resolve_request(directory.path().join("adjusted.jpg")),
            )
            .expect_err("size mismatch must fail closed");
        assert!(matches!(error, AdjustedSourceError::DownloadedSizeMismatch));
        assert!(no_temp_files(directory.path()));
        assert!(!directory.path().join("adjusted.jpg").exists());
    }
}

#[test]
fn rejects_corrupt_wrong_dimension_oriented_and_blank_jpegs() {
    let valid = nonblank_jpeg(4, 3);
    let cases = [
        (b"not-a-jpeg".to_vec(), 4, 3),
        (valid.clone(), 3, 4),
        (jpeg_with_exif_orientation(4, 3, 6), 4, 3),
        (uniform_jpeg(4, 3), 4, 3),
    ];
    for (bytes, width, height) in cases {
        let mut transport = FakeTransport {
            lookups: VecDeque::from([
                json!({"records": [direct_asset_record(&bytes, width, height)]}),
            ]),
            downloads: VecDeque::from([bytes]),
            ..Default::default()
        };
        let directory = tempdir().expect("test directory");
        let error = CloudKitAdjustedSourceResolver::new(&mut transport)
            .resolve(
                &session(),
                &resolve_request(directory.path().join("adjusted.jpg")),
            )
            .expect_err("invalid rendered JPEG must fail closed");
        assert!(matches!(error, AdjustedSourceError::InvalidJpeg));
        assert!(no_temp_files(directory.path()));
    }
}

#[test]
fn cleans_temp_after_transport_failure_and_never_uses_original_resource_fallback() {
    let bytes = nonblank_jpeg(4, 3);
    let mut failing = FailingAfterTempTransport {
        lookup: json!({"records": [direct_asset_record(&bytes, 4, 3)]}),
        temp_paths: Vec::new(),
    };
    let directory = tempdir().expect("test directory");
    let error = CloudKitAdjustedSourceResolver::new(&mut failing)
        .resolve(
            &session(),
            &resolve_request(directory.path().join("adjusted.jpg")),
        )
        .expect_err("transport failure must clean temp");
    assert!(matches!(error, AdjustedSourceError::Filesystem));
    assert_eq!(failing.temp_paths.len(), 1);
    assert!(!failing.temp_paths[0].exists());

    let asset = record(
        ASSET_RECORD,
        "CPLAsset",
        ASSET_TAG,
        json!({"masterRef": master_ref()}),
    );
    let master = record(
        MASTER_RECORD,
        "CPLMaster",
        MASTER_TAG,
        json!({
            "resOriginalRes": wrapper("ASSETID", json!({"downloadURL": "https://example.icloud.com/original", "size": bytes.len()}))
        }),
    );
    let mut transport = FakeTransport {
        lookups: VecDeque::from([json!({"records": [asset]}), json!({"records": [master]})]),
        ..Default::default()
    };
    let directory = tempdir().expect("test directory");
    let error = CloudKitAdjustedSourceResolver::new(&mut transport)
        .resolve(
            &session(),
            &resolve_request(directory.path().join("adjusted.jpg")),
        )
        .expect_err("original resource must never be selected");
    assert!(matches!(error, AdjustedSourceError::InvalidResponse(_)));
    assert_eq!(transport.download_calls, 0);
}

#[test]
fn accepts_only_exact_existing_regular_jpeg_and_rejects_mismatch_symlink_or_directory() {
    let bytes = nonblank_jpeg(4, 3);
    let directory = tempdir().expect("test directory");
    let output_path = directory.path().join("adjusted.jpg");
    std::fs::write(&output_path, &bytes).expect("existing exact JPEG");
    let mut transport = FakeTransport {
        lookups: VecDeque::from([json!({"records": [direct_asset_record(&bytes, 4, 3)]})]),
        downloads: VecDeque::from([bytes.clone()]),
        ..Default::default()
    };
    CloudKitAdjustedSourceResolver::new(&mut transport)
        .resolve(&session(), &resolve_request(output_path.clone()))
        .expect("exact existing JPEG should be accepted");

    let mismatch = vec![7_u8; bytes.len()];
    std::fs::write(&output_path, &mismatch).expect("mismatch");
    let mut transport = FakeTransport {
        lookups: VecDeque::from([json!({"records": [direct_asset_record(&bytes, 4, 3)]})]),
        downloads: VecDeque::from([bytes.clone()]),
        ..Default::default()
    };
    let error = CloudKitAdjustedSourceResolver::new(&mut transport)
        .resolve(&session(), &resolve_request(output_path.clone()))
        .expect_err("mismatch must never be overwritten");
    assert!(matches!(error, AdjustedSourceError::ExistingOutputMismatch));
    assert_eq!(
        std::fs::read(&output_path).expect("mismatch stays"),
        mismatch
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let symlink_path = directory.path().join("symlink.jpg");
        let target = directory.path().join("target.jpg");
        std::fs::write(&target, &bytes).expect("target");
        symlink(&target, &symlink_path).expect("symlink");
        let mut transport = FakeTransport {
            lookups: VecDeque::from([json!({"records": [direct_asset_record(&bytes, 4, 3)]})]),
            downloads: VecDeque::from([bytes.clone()]),
            ..Default::default()
        };
        let error = CloudKitAdjustedSourceResolver::new(&mut transport)
            .resolve(&session(), &resolve_request(symlink_path.clone()))
            .expect_err("symlink must fail closed");
        assert!(matches!(error, AdjustedSourceError::UnsafeOutputPath));
        assert!(
            std::fs::symlink_metadata(&symlink_path)
                .expect("symlink")
                .file_type()
                .is_symlink()
        );
    }

    let directory_path = directory.path().join("directory.jpg");
    std::fs::create_dir(&directory_path).expect("directory");
    let mut transport = FakeTransport {
        lookups: VecDeque::from([json!({"records": [direct_asset_record(&bytes, 4, 3)]})]),
        downloads: VecDeque::from([bytes]),
        ..Default::default()
    };
    let error = CloudKitAdjustedSourceResolver::new(&mut transport)
        .resolve(&session(), &resolve_request(directory_path.clone()))
        .expect_err("directory must fail closed");
    assert!(matches!(error, AdjustedSourceError::UnsafeOutputPath));
    assert!(directory_path.is_dir());
    assert!(no_temp_files(directory.path()));
}

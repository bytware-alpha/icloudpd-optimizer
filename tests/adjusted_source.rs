use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

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
use image::{DynamicImage, RgbImage};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use url::Url;

fn jpeg_bytes(width: u32, height: u32) -> Vec<u8> {
    let image = DynamicImage::ImageRgb8(RgbImage::new(width, height));
    let mut bytes = Vec::new();
    JpegEncoder::new(&mut bytes)
        .encode_image(&image)
        .expect("test JPEG should encode");
    bytes
}

fn jpeg_bytes_with_exif_orientation(width: u32, height: u32, orientation: u8) -> Vec<u8> {
    let mut jpeg = jpeg_bytes(width, height);
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
        record_name: "asset-record".to_string(),
        record_change_tag: "asset-tag".to_string(),
        record_type: "CPLAsset".to_string(),
        database_scope: CloudKitDatabaseScope::Private,
        zone_name: "PrimarySync".to_string(),
        filename: "source.dng".to_string(),
        size_bytes: 42,
        matched_raw_sha256: "raw-sha256".to_string(),
    }
}

#[derive(Default)]
struct FakeAdjustedSourceTransport {
    lookups: VecDeque<Value>,
    downloads: VecDeque<Vec<u8>>,
    lookup_payloads: Vec<Value>,
    download_calls: usize,
}

struct FailingAfterTempTransport {
    lookup: Value,
    temp_paths: Vec<std::path::PathBuf>,
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

impl CloudKitAdjustedSourceTransport for FakeAdjustedSourceTransport {
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
        let bytes = self.downloads.pop_front().expect("download should exist");
        self.download_calls += 1;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temp_path)
            .expect("fake transport should create its temp path");
        file.write_all(&bytes)
            .expect("fake transport should write JPEG bytes");
        file.sync_all()
            .expect("fake transport should sync JPEG bytes");
        Ok(CloudKitAdjustedSourceDownload {
            size_bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
        })
    }
}

fn adjusted_resource_record(
    record_name: &str,
    record_type: &str,
    change_tag: &str,
    bytes: &[u8],
    width: u32,
    height: u32,
) -> Value {
    json!({
        "recordName": record_name,
        "recordType": record_type,
        "recordChangeTag": change_tag,
        "fields": {
            "resJPEGFullRes": {"value": {
                "downloadURL": "https://example.icloud.com/adjusted.jpg",
                "size": bytes.len()
            }},
            "resJPEGFullResWidth": {"value": width},
            "resJPEGFullResHeight": {"value": height},
            "resJPEGFullResFileType": {"value": "public.jpeg"},
            "resJPEGFullResFingerprint": {"value": "remote-fingerprint"}
        }
    })
}

fn resolve_request(output_path: std::path::PathBuf) -> CloudKitAdjustedSourceResolveRequest {
    CloudKitAdjustedSourceResolveRequest {
        asset_id: "local-asset".to_string(),
        original_asset: original_proof(),
        output_path,
    }
}

fn no_temp_files(directory: &Path) -> bool {
    std::fs::read_dir(directory)
        .expect("test directory should be readable")
        .all(|entry| {
            !entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .contains(".adjusted-")
        })
}

#[test]
fn resolves_direct_asset_adjusted_jpeg_to_a_verified_proof() {
    let bytes = jpeg_bytes(3, 2);
    let mut transport = FakeAdjustedSourceTransport {
        lookups: VecDeque::from([json!({
            "records": [{
                "recordName": "asset-record",
                "recordType": "CPLAsset",
                "recordChangeTag": "asset-tag",
                "fields": {
                    "resJPEGFullRes": {"value": {
                        "downloadURL": "https://example.icloud.com/adjusted.jpg",
                        "size": bytes.len()
                    }},
                    "resJPEGFullResWidth": {"value": 3},
                    "resJPEGFullResHeight": {"value": 2},
                    "resJPEGFullResFileType": {"value": "public.jpeg"},
                    "resJPEGFullResFingerprint": {"value": "remote-fingerprint"}
                }
            }]
        })]),
        downloads: VecDeque::from([bytes.clone()]),
        ..Default::default()
    };
    let directory = tempdir().expect("test directory");
    let output_path = directory.path().join("adjusted.jpg");

    let proof = CloudKitAdjustedSourceResolver::new(&mut transport)
        .resolve(
            &session(),
            &CloudKitAdjustedSourceResolveRequest {
                asset_id: "local-asset".to_string(),
                original_asset: original_proof(),
                output_path: output_path.clone(),
            },
        )
        .expect("direct adjusted JPEG should resolve");

    assert_eq!(proof.asset_id, "local-asset");
    assert_eq!(proof.resource_record_name, "asset-record");
    assert_eq!(proof.resource_record_type, "CPLAsset");
    assert_eq!(proof.resource_field, "resJPEGFullRes");
    assert_eq!(proof.downloaded_size_bytes, bytes.len() as u64);
    assert_eq!(proof.downloaded_sha256, sha256_hex(&bytes));
    assert_eq!(proof.width, 3);
    assert_eq!(proof.height, 2);
    assert_eq!(proof.orientation, 1);
    assert_eq!(proof.local_path, output_path);
    assert_eq!(
        std::fs::read(&proof.local_path).expect("output bytes"),
        bytes
    );

    assert_eq!(transport.lookup_payloads.len(), 1);
    assert_eq!(
        transport.lookup_payloads[0]["desiredKeys"],
        json!([
            "masterRef",
            "resJPEGFullRes",
            "resJPEGFullResWidth",
            "resJPEGFullResHeight",
            "resJPEGFullResFileType",
            "resJPEGFullResFingerprint"
        ])
    );
}

#[test]
fn resolves_master_adjusted_jpeg_only_after_an_exact_master_lookup() {
    let bytes = jpeg_bytes(4, 3);
    let mut transport = FakeAdjustedSourceTransport {
        lookups: VecDeque::from([
            json!({
                "records": [{
                    "recordName": "asset-record",
                    "recordType": "CPLAsset",
                    "recordChangeTag": "asset-tag",
                    "fields": {"masterRef": {"value": {"recordName": "master-record"}}}
                }]
            }),
            json!({"records": [adjusted_resource_record(
                "master-record", "CPLMaster", "master-tag", &bytes, 4, 3
            )]}),
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
        .expect("master adjusted JPEG should resolve");

    assert_eq!(proof.master_record_name.as_deref(), Some("master-record"));
    assert_eq!(proof.resource_record_name, "master-record");
    assert_eq!(proof.resource_record_change_tag, "master-tag");
    assert_eq!(proof.resource_record_type, "CPLMaster");
    assert_eq!(transport.lookup_payloads.len(), 2);
    assert_eq!(
        transport.lookup_payloads[1]["records"][0]["recordName"],
        "master-record"
    );
}

#[test]
fn rejects_asset_identity_or_change_tag_mismatch_before_download() {
    let bytes = jpeg_bytes(3, 2);
    for record in [
        adjusted_resource_record("other-asset", "CPLAsset", "asset-tag", &bytes, 3, 2),
        adjusted_resource_record("asset-record", "CPLAsset", "other-tag", &bytes, 3, 2),
    ] {
        let mut transport = FakeAdjustedSourceTransport {
            lookups: VecDeque::from([json!({"records": [record]})]),
            ..Default::default()
        };
        let directory = tempdir().expect("test directory");
        let error = CloudKitAdjustedSourceResolver::new(&mut transport)
            .resolve(
                &session(),
                &resolve_request(directory.path().join("adjusted.jpg")),
            )
            .expect_err("identity mismatch must fail closed");
        assert!(matches!(error, AdjustedSourceError::InvalidResponse(_)));
        assert_eq!(transport.download_calls, 0);
        assert!(no_temp_files(directory.path()));
    }
}

#[test]
fn rejects_absent_or_malformed_master_reference_before_download() {
    for fields in [
        json!({}),
        json!({"masterRef": {"value": "master-record"}}),
        json!({"masterRef": {"value": {"recordName": ""}}}),
        json!({"masterRef": {"value": {"recordName": "master-record", "zoneID": {"zoneName": "wrong-zone"}}}}),
    ] {
        let mut transport = FakeAdjustedSourceTransport {
            lookups: VecDeque::from([json!({"records": [{
                "recordName": "asset-record",
                "recordType": "CPLAsset",
                "recordChangeTag": "asset-tag",
                "fields": fields
            }]})]),
            ..Default::default()
        };
        let directory = tempdir().expect("test directory");
        let error = CloudKitAdjustedSourceResolver::new(&mut transport)
            .resolve(
                &session(),
                &resolve_request(directory.path().join("adjusted.jpg")),
            )
            .expect_err("missing or malformed master reference must fail closed");
        assert!(matches!(error, AdjustedSourceError::InvalidResponse(_)));
        assert_eq!(transport.download_calls, 0);
        assert!(no_temp_files(directory.path()));
    }
}

#[test]
fn rejects_each_required_adjusted_metadata_field_before_download() {
    let bytes = jpeg_bytes(3, 2);
    for field in [
        "resJPEGFullRes",
        "resJPEGFullResWidth",
        "resJPEGFullResHeight",
        "resJPEGFullResFileType",
        "resJPEGFullResFingerprint",
    ] {
        let mut record =
            adjusted_resource_record("asset-record", "CPLAsset", "asset-tag", &bytes, 3, 2);
        record["fields"]
            .as_object_mut()
            .expect("fields object")
            .remove(field);
        let mut transport = FakeAdjustedSourceTransport {
            lookups: VecDeque::from([json!({"records": [record]})]),
            ..Default::default()
        };
        let directory = tempdir().expect("test directory");
        let error = CloudKitAdjustedSourceResolver::new(&mut transport)
            .resolve(
                &session(),
                &resolve_request(directory.path().join("adjusted.jpg")),
            )
            .expect_err("missing adjusted metadata must fail closed");
        assert!(matches!(error, AdjustedSourceError::InvalidResponse(_)));
        assert_eq!(transport.download_calls, 0);
    }
}

#[test]
fn rejects_malformed_or_zero_adjusted_metadata_wrappers_before_download() {
    let bytes = jpeg_bytes(3, 2);
    let mutations = [
        ("resJPEGFullRes", json!({"value": "not-an-object"})),
        ("resJPEGFullResWidth", json!({"value": 0})),
        ("resJPEGFullResHeight", json!({"value": "2"})),
        ("resJPEGFullResFileType", json!({"value": ""})),
        ("resJPEGFullResFingerprint", json!({"value": []})),
    ];
    for (field, value) in mutations {
        let mut record =
            adjusted_resource_record("asset-record", "CPLAsset", "asset-tag", &bytes, 3, 2);
        record["fields"][field] = value;
        let mut transport = FakeAdjustedSourceTransport {
            lookups: VecDeque::from([json!({"records": [record]})]),
            ..Default::default()
        };
        let directory = tempdir().expect("test directory");
        let error = CloudKitAdjustedSourceResolver::new(&mut transport)
            .resolve(
                &session(),
                &resolve_request(directory.path().join("adjusted.jpg")),
            )
            .expect_err("malformed adjusted metadata must fail closed");
        assert!(matches!(error, AdjustedSourceError::InvalidResponse(_)));
        assert_eq!(transport.download_calls, 0);
    }
}

#[test]
fn rejects_bad_url_and_non_jpeg_file_type_before_download() {
    let bytes = jpeg_bytes(3, 2);
    let mut bad_url =
        adjusted_resource_record("asset-record", "CPLAsset", "asset-tag", &bytes, 3, 2);
    bad_url["fields"]["resJPEGFullRes"]["value"]["downloadURL"] =
        json!("http://invalid.example/adjusted.jpg");
    let mut bad_file_type =
        adjusted_resource_record("asset-record", "CPLAsset", "asset-tag", &bytes, 3, 2);
    bad_file_type["fields"]["resJPEGFullResFileType"]["value"] = json!("public.heic");

    for record in [bad_url, bad_file_type] {
        let mut transport = FakeAdjustedSourceTransport {
            lookups: VecDeque::from([json!({"records": [record]})]),
            ..Default::default()
        };
        let directory = tempdir().expect("test directory");
        let error = CloudKitAdjustedSourceResolver::new(&mut transport)
            .resolve(
                &session(),
                &resolve_request(directory.path().join("adjusted.jpg")),
            )
            .expect_err("unsafe resource metadata must fail closed");
        assert!(matches!(
            error,
            AdjustedSourceError::InvalidResourceUrl | AdjustedSourceError::InvalidResponse(_)
        ));
        assert_eq!(transport.download_calls, 0);
    }
}

#[test]
fn rejects_short_or_long_streams_and_cleans_the_temp_artifact() {
    let expected = jpeg_bytes(3, 2);
    for bytes in [
        expected[..expected.len() - 1].to_vec(),
        [expected.clone(), vec![0]].concat(),
    ] {
        let mut transport = FakeAdjustedSourceTransport {
            lookups: VecDeque::from([json!({"records": [adjusted_resource_record(
                "asset-record", "CPLAsset", "asset-tag", &expected, 3, 2
            )]})]),
            downloads: VecDeque::from([bytes]),
            ..Default::default()
        };
        let directory = tempdir().expect("test directory");
        let error = CloudKitAdjustedSourceResolver::new(&mut transport)
            .resolve(
                &session(),
                &resolve_request(directory.path().join("adjusted.jpg")),
            )
            .expect_err("short or long stream must fail closed");
        assert!(matches!(error, AdjustedSourceError::DownloadedSizeMismatch));
        assert!(no_temp_files(directory.path()));
        assert!(!directory.path().join("adjusted.jpg").exists());
    }
}

#[test]
fn rejects_corrupt_or_dimension_mismatched_jpeg_and_cleans_temp() {
    let valid = jpeg_bytes(3, 2);
    for (bytes, width, height) in [(b"not-a-jpeg".to_vec(), 3, 2), (valid.clone(), 2, 3)] {
        let mut transport = FakeAdjustedSourceTransport {
            lookups: VecDeque::from([json!({"records": [adjusted_resource_record(
                "asset-record", "CPLAsset", "asset-tag", &bytes, width, height
            )]})]),
            downloads: VecDeque::from([bytes]),
            ..Default::default()
        };
        let directory = tempdir().expect("test directory");
        let error = CloudKitAdjustedSourceResolver::new(&mut transport)
            .resolve(
                &session(),
                &resolve_request(directory.path().join("adjusted.jpg")),
            )
            .expect_err("invalid JPEG must fail closed");
        assert!(matches!(error, AdjustedSourceError::InvalidJpeg));
        assert!(no_temp_files(directory.path()));
    }
}

#[test]
fn rejects_exif_oriented_jpeg_and_cleans_temp() {
    let bytes = jpeg_bytes_with_exif_orientation(3, 2, 6);
    let mut transport = FakeAdjustedSourceTransport {
        lookups: VecDeque::from([json!({"records": [adjusted_resource_record(
            "asset-record", "CPLAsset", "asset-tag", &bytes, 3, 2
        )]})]),
        downloads: VecDeque::from([bytes]),
        ..Default::default()
    };
    let directory = tempdir().expect("test directory");
    let error = CloudKitAdjustedSourceResolver::new(&mut transport)
        .resolve(
            &session(),
            &resolve_request(directory.path().join("adjusted.jpg")),
        )
        .expect_err("EXIF rotation must fail closed");
    assert!(matches!(error, AdjustedSourceError::InvalidJpeg));
    assert!(no_temp_files(directory.path()));
}

#[test]
fn cleans_temp_when_the_transport_fails_after_creating_it() {
    let bytes = jpeg_bytes(3, 2);
    let mut transport = FailingAfterTempTransport {
        lookup: json!({"records": [adjusted_resource_record(
            "asset-record", "CPLAsset", "asset-tag", &bytes, 3, 2
        )]}),
        temp_paths: Vec::new(),
    };
    let directory = tempdir().expect("test directory");
    let error = CloudKitAdjustedSourceResolver::new(&mut transport)
        .resolve(
            &session(),
            &resolve_request(directory.path().join("adjusted.jpg")),
        )
        .expect_err("transport failure after temp creation must fail closed");
    assert!(matches!(error, AdjustedSourceError::Filesystem));
    assert_eq!(transport.temp_paths.len(), 1);
    assert!(!transport.temp_paths[0].exists());
    assert!(no_temp_files(directory.path()));
}

#[test]
fn accepts_only_exact_existing_regular_output_and_proof_never_serializes_sensitive_transport_data()
{
    let bytes = jpeg_bytes(3, 2);
    let directory = tempdir().expect("test directory");
    let output_path = directory.path().join("adjusted.jpg");
    std::fs::write(&output_path, &bytes).expect("existing exact output");
    let mut transport = FakeAdjustedSourceTransport {
        lookups: VecDeque::from([json!({"records": [adjusted_resource_record(
            "asset-record", "CPLAsset", "asset-tag", &bytes, 3, 2
        )]})]),
        downloads: VecDeque::from([bytes.clone()]),
        ..Default::default()
    };

    let proof = CloudKitAdjustedSourceResolver::new(&mut transport)
        .resolve(&session(), &resolve_request(output_path.clone()))
        .expect("exact existing output should be idempotent");
    let encoded = serde_json::to_value(&proof).expect("proof should serialize");
    let decoded: CloudKitAdjustedSourceProof =
        serde_json::from_value(encoded.clone()).expect("proof should deserialize");
    assert_eq!(decoded, proof);
    let serialized = encoded.to_string();
    for forbidden in [
        "downloadURL",
        "cookies",
        "session",
        "headers",
        "example.icloud.com",
    ] {
        assert!(!serialized.contains(forbidden));
    }
    assert!(no_temp_files(directory.path()));

    let different = vec![0_u8; bytes.len()];
    std::fs::write(&output_path, &different).expect("mismatched existing output");
    let mut mismatch_transport = FakeAdjustedSourceTransport {
        lookups: VecDeque::from([json!({"records": [adjusted_resource_record(
            "asset-record", "CPLAsset", "asset-tag", &bytes, 3, 2
        )]})]),
        downloads: VecDeque::from([bytes]),
        ..Default::default()
    };
    let error = CloudKitAdjustedSourceResolver::new(&mut mismatch_transport)
        .resolve(&session(), &resolve_request(output_path.clone()))
        .expect_err("mismatched output must never be overwritten");
    assert!(matches!(error, AdjustedSourceError::ExistingOutputMismatch));
    assert_eq!(
        std::fs::read(&output_path).expect("existing output"),
        different
    );
    assert!(no_temp_files(directory.path()));
}

#[cfg(unix)]
#[test]
fn rejects_symlink_and_directory_outputs_without_overwriting_them() {
    use std::os::unix::fs::symlink;

    let bytes = jpeg_bytes(3, 2);
    for output_kind in ["symlink", "directory"] {
        let directory = tempdir().expect("test directory");
        let output_path = directory.path().join("adjusted.jpg");
        if output_kind == "symlink" {
            let target = directory.path().join("target.jpg");
            std::fs::write(&target, b"target").expect("symlink target");
            symlink(&target, &output_path).expect("output symlink");
        } else {
            std::fs::create_dir(&output_path).expect("output directory");
        }
        let mut transport = FakeAdjustedSourceTransport {
            lookups: VecDeque::from([json!({"records": [adjusted_resource_record(
                "asset-record", "CPLAsset", "asset-tag", &bytes, 3, 2
            )]})]),
            downloads: VecDeque::from([bytes.clone()]),
            ..Default::default()
        };
        let error = CloudKitAdjustedSourceResolver::new(&mut transport)
            .resolve(&session(), &resolve_request(output_path.clone()))
            .expect_err("unsafe output must fail closed");
        assert!(matches!(error, AdjustedSourceError::UnsafeOutputPath));
        assert!(no_temp_files(directory.path()));
        if output_kind == "symlink" {
            assert!(
                std::fs::symlink_metadata(&output_path)
                    .expect("symlink metadata")
                    .file_type()
                    .is_symlink()
            );
        } else {
            assert!(output_path.is_dir());
        }
    }
}

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use filetime::{FileTime, set_file_mtime};
use icloudpd_optimizer::adjusted_source::{
    ADJUSTED_SOURCE_PROOF_SCHEMA_VERSION, CloudKitAdjustedSourceProof,
    adjusted_source_path_for_output, adjusted_source_proof_digest,
};
use icloudpd_optimizer::manifest::{AssetRecord, FailureKind, Manifest, ManifestError, State};
use icloudpd_optimizer::proof::{NasRawProof, ProofError, prove_nas_raw};
use icloudpd_optimizer::upload::{CloudKitDeleteOutcome, CloudKitUploadedHeicAsset};
use icloudpd_optimizer::workflow::{
    ConversionCommandTiming, ConversionPerformanceInput, ConversionResultInput,
    ConversionSourceBinding, HeicVerificationInput, IcloudpdLocalMirrorProof, OriginalAssetProof,
    SourceAgeProof, UploadProof, WorkflowError, approve_delete, build_delete_plan,
    discover_raw_asset, mark_delete_eligible, prepare_delete_reconciliation,
    prevalidate_approved_original_delete, prove_and_record_nas, record_adjusted_source_proof,
    record_conversion_performance, record_conversion_result, record_delete_execution,
    record_heic_verification, record_icloudpd_local_mirror_proof, record_nas_proof,
    record_original_asset_batch_proofs, record_original_asset_proof,
    record_prevalidated_delete_execution, record_reconciled_delete_execution,
    record_source_age_proof, record_stage_failure, record_stage_failure_with_kind,
    record_upload_proof, record_uploaded_heic_delete, upload_ready_heic_proof,
    uploaded_heic_delete_request,
};
use serde_json::json;
use sha2::{Digest, Sha256};

const DAY: u64 = 24 * 60 * 60;
const SOURCE_AGE_VERIFIED_AT: u64 = 1_800_000_000;
const RAW_BYTES_ASSET_1: &[u8] = b"raw-bytes-that-are-larger-than-heic";
const RAW_BYTES_ASSET_2: &[u8] = b"other-raw-bytes-that-are-larger-than-heic";

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

#[test]
fn public_upsert_strips_forged_current_recipe_claims() {
    let mut manifest = Manifest::new();
    let mut record = AssetRecord::new("asset-1", "/nas/photos/IMG_0001.dng");
    record.proofs.insert(
        "conversion".to_string(),
        json!({"conversion_recipe_id": "embedded-preview-normalized-v1"}),
    );
    manifest.upsert(record);

    assert_eq!(
        manifest.get("asset-1").expect("asset should exist").proofs["conversion"]["conversion_recipe_id"],
        ""
    );
}

fn conversion_proof() -> ConversionResultInput {
    ConversionResultInput {
        heic_path: PathBuf::from("/staging/IMG_0001.heic"),
        heic_sha256: "heic-sha256".to_string(),
        size_bytes: 24,
        source_binding: ConversionSourceBinding::EmbeddedPreview,
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

fn heic_proof() -> HeicVerificationInput {
    HeicVerificationInput {
        heic_path: PathBuf::from("/staging/IMG_0001.heic"),
        heic_sha256: "heic-sha256".to_string(),
        size_bytes: 24,
        heif_info_ok: true,
        metadata_copied: true,
        visual_content_ok: true,
        visual_match_ok: true,
        visual_rmse_ppm: Some(0),
        visual_mae_ppm: Some(0),
    }
}

#[test]
fn current_conversion_recipe_is_required_before_upload() {
    for recipe in [None, Some("embedded-preview-legacy-v0")] {
        let mut manifest = trusted_current_manifest(conversion_verified_manifest());
        let mut record = manifest.get("asset-1").expect("asset should exist").clone();
        let performance = record
            .proofs
            .get_mut("conversion_performance")
            .expect("performance proof should exist");
        match recipe {
            Some(recipe) => performance["conversion_recipe_id"] = json!(recipe),
            None => {
                performance
                    .as_object_mut()
                    .expect("performance proof should be an object")
                    .remove("conversion_recipe_id");
            }
        }
        manifest = replace_trusted_record(record);

        let error = upload_ready_heic_proof(&manifest, "asset-1")
            .expect_err("missing or old recipe must not be upload-ready");
        assert!(matches!(
            error,
            WorkflowError::ConversionRecipeOutdated {
                proof_key: "conversion_performance",
                ..
            }
        ));
    }
}

#[test]
fn conversion_and_heic_recipe_gate_matrix_blocks_upload_and_delete_admission() {
    for (proof_key, recipe) in [
        ("conversion", None),
        ("conversion", Some("embedded-preview-legacy-v0")),
        ("heic", None),
        ("heic", Some("embedded-preview-legacy-v0")),
    ] {
        let mut conversion_verified = trusted_current_manifest(conversion_verified_manifest());
        let mut record = conversion_verified
            .get("asset-1")
            .expect("asset should exist")
            .clone();
        let proof = record
            .proofs
            .get_mut(proof_key)
            .expect("proof should exist");
        match recipe {
            Some(recipe) => proof["conversion_recipe_id"] = json!(recipe),
            None => {
                proof
                    .as_object_mut()
                    .expect("proof should be an object")
                    .remove("conversion_recipe_id");
            }
        }
        conversion_verified = replace_trusted_record(record);
        assert!(matches!(
            upload_ready_heic_proof(&conversion_verified, "asset-1"),
            Err(WorkflowError::ConversionRecipeOutdated { .. })
        ));

        let mut upload_verified = trusted_current_manifest(upload_verified_manifest());
        let mut record = upload_verified
            .get("asset-1")
            .expect("asset should exist")
            .clone();
        let proof = record
            .proofs
            .get_mut(proof_key)
            .expect("proof should exist");
        match recipe {
            Some(recipe) => proof["conversion_recipe_id"] = json!(recipe),
            None => {
                proof
                    .as_object_mut()
                    .expect("proof should be an object")
                    .remove("conversion_recipe_id");
            }
        }
        upload_verified = replace_trusted_record(record);
        assert!(matches!(
            mark_delete_eligible(&mut upload_verified, "asset-1"),
            Err(WorkflowError::ConversionRecipeOutdated { .. })
        ));
        assert!(build_delete_plan(&upload_verified, "asset-1").is_err());
    }

    let (_tempdir, mut current, _raw_path) = real_upload_verified_manifest();
    mark_delete_eligible(&mut current, "asset-1").expect("current recipe should be eligible");
    approve_delete(&mut current, "asset-1", "operator")
        .expect("current recipe should be approvable");
    assert!(build_delete_plan(&current, "asset-1").is_ok());
}

fn upload_proof() -> UploadProof {
    UploadProof {
        uploaded_heic_asset_id: "icloud-heic-asset-1".to_string(),
        uploaded_heic_sha256: "heic-sha256".to_string(),
        database_scope: Default::default(),
        zone_name: "PrimarySync".to_string(),
        uploaded_heic_path: Some(PathBuf::from("/staging/IMG_0001.heic")),
    }
}

fn local_mirror_proof() -> IcloudpdLocalMirrorProof {
    IcloudpdLocalMirrorProof {
        uploaded_heic_asset_id: "icloud-heic-asset-1".to_string(),
        uploaded_heic_sha256: "heic-sha256".to_string(),
        uploaded_heic_path: PathBuf::from("/staging/IMG_0001.heic"),
        icloudpd_download_path: PathBuf::from("/PrimarySync/IMG_0001.HEIC"),
        size_bytes: 24,
    }
}

fn original_asset_proof() -> OriginalAssetProof {
    OriginalAssetProof {
        record_name: "original-record-1".to_string(),
        record_change_tag: "old-change-tag".to_string(),
        record_type: "CPLAsset".to_string(),
        database_scope: Default::default(),
        zone_name: "PrimarySync".to_string(),
        filename: "IMG_0001.dng".to_string(),
        size_bytes: 42,
        matched_raw_sha256: "raw-sha256".to_string(),
    }
}

fn adjusted_source_proof(
    asset_id: &str,
    original: &OriginalAssetProof,
    local_path: PathBuf,
    bytes: &[u8],
) -> CloudKitAdjustedSourceProof {
    CloudKitAdjustedSourceProof {
        schema_version: ADJUSTED_SOURCE_PROOF_SCHEMA_VERSION.to_string(),
        source_kind: "cloudkit_adjusted_res_jpeg_full_res".to_string(),
        asset_id: asset_id.to_string(),
        asset_record_name: original.record_name.clone(),
        asset_record_change_tag: original.record_change_tag.clone(),
        asset_record_type: original.record_type.clone(),
        resource_record_name: original.record_name.clone(),
        resource_record_change_tag: original.record_change_tag.clone(),
        resource_record_type: "CPLAsset".to_string(),
        database_scope: original.database_scope,
        zone_name: original.zone_name.clone(),
        master_record_name: None,
        resource_field: "resJPEGFullRes".to_string(),
        declared_file_type: "public.jpeg".to_string(),
        declared_fingerprint: "test-fingerprint".to_string(),
        declared_size_bytes: bytes.len() as u64,
        width: 4,
        height: 3,
        local_path,
        downloaded_size_bytes: bytes.len() as u64,
        downloaded_sha256: format!("{:x}", Sha256::digest(bytes)),
        orientation: 1,
        verified_at_unix_seconds: 1_800_000_001,
    }
}

fn nonblank_adjusted_jpeg() -> Vec<u8> {
    use image::codecs::jpeg::JpegEncoder;
    use image::{DynamicImage, Rgb, RgbImage};

    let mut image = RgbImage::new(4, 3);
    for (x, y, pixel) in image.enumerate_pixels_mut() {
        *pixel = Rgb([x as u8 * 50, y as u8 * 70, 23]);
    }
    let mut bytes = Vec::new();
    JpegEncoder::new_with_quality(&mut bytes, 100)
        .encode_image(&DynamicImage::ImageRgb8(image))
        .expect("test adjusted JPEG should encode");
    bytes
}

fn delete_outcome() -> CloudKitDeleteOutcome {
    CloudKitDeleteOutcome {
        record_name: "original-record-1".to_string(),
        record_change_tag: "deleted-change-tag".to_string(),
    }
}

fn uploaded_heic_asset() -> CloudKitUploadedHeicAsset {
    CloudKitUploadedHeicAsset {
        record_name: "icloud-heic-asset-1".to_string(),
        record_change_tag: "uploaded-old-change-tag".to_string(),
        master_record_name: "icloud-heic-master-1".to_string(),
        matched_heic_sha256: "heic-sha256".to_string(),
        size_bytes: 24,
    }
}

fn uploaded_heic_delete_outcome() -> CloudKitDeleteOutcome {
    CloudKitDeleteOutcome {
        record_name: "icloud-heic-asset-1".to_string(),
        record_change_tag: "uploaded-deleted-change-tag".to_string(),
    }
}

fn source_age_proof(age_days: u64) -> SourceAgeProof {
    SourceAgeProof {
        source_captured_unix_seconds: SOURCE_AGE_VERIFIED_AT - age_days * DAY,
        verified_at_unix_seconds: SOURCE_AGE_VERIFIED_AT,
        min_age_seconds: 30 * DAY,
    }
}

fn old_source_age_proof() -> SourceAgeProof {
    source_age_proof(40)
}

fn write_old_raw(root: &Path, relative_path: &str, body: &[u8]) -> PathBuf {
    let path = root.join(relative_path);
    fs::create_dir_all(path.parent().expect("test raw should have a parent"))
        .expect("test raw parent should be created");
    fs::write(&path, body).expect("test raw should be written");
    let modified_at = SystemTime::now() - Duration::from_secs(40 * DAY);
    set_file_mtime(&path, FileTime::from_system_time(modified_at))
        .expect("test raw mtime should be set");
    path
}

fn set_raw_mtime(path: &Path, unix_seconds: u64) {
    set_file_mtime(path, FileTime::from_unix_time(unix_seconds as i64, 0))
        .expect("test raw mtime should be restored");
}

fn conversion_verified_manifest() -> Manifest {
    let mut manifest = conversion_performance_manifest();
    record_heic_verification(&mut manifest, "asset-1", heic_proof())
        .expect("heic verification should record");
    manifest
}

fn source_age_verified_manifest() -> Manifest {
    let mut manifest = conversion_verified_manifest();
    record_source_age_proof(&mut manifest, "asset-1", old_source_age_proof())
        .expect("source age proof should record");
    manifest
}

fn upload_verified_manifest() -> Manifest {
    let mut manifest = trusted_current_manifest(source_age_verified_manifest());
    record_upload_proof(&mut manifest, "asset-1", upload_proof())
        .expect("upload proof should record");
    record_icloudpd_local_mirror_proof(&mut manifest, "asset-1", local_mirror_proof())
        .expect("local mirror proof should record");
    record_original_asset_proof(&mut manifest, "asset-1", original_asset_proof())
        .expect("original asset proof should record");
    manifest
}

fn trusted_current_manifest(manifest: Manifest) -> Manifest {
    let mut record = manifest
        .get("asset-1")
        .expect("fixture should contain asset")
        .clone();
    for proof_name in ["conversion", "conversion_performance", "heic"] {
        record
            .proofs
            .get_mut(proof_name)
            .expect("proof should exist")["conversion_recipe_id"] =
            json!("embedded-preview-normalized-v1");
    }
    replace_trusted_record(record)
}

fn replace_trusted_record(record: AssetRecord) -> Manifest {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let path = tempdir.path().join("manifest.json");
    fs::write(
        &path,
        serde_json::to_vec(&json!({"records": [record]})).expect("fixture should serialize"),
    )
    .expect("fixture should persist");
    Manifest::load(path).expect("trusted fixture should load")
}

fn real_upload_verified_manifest() -> (tempfile::TempDir, Manifest, PathBuf) {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let nas_root = tempdir.path().join("nas");
    fs::create_dir_all(&nas_root).expect("nas root should be created");
    let raw_path = write_old_raw(&nas_root, "camera/IMG_0001.dng", RAW_BYTES_ASSET_1);
    let proof = prove_nas_raw(&nas_root, &raw_path, 30, SystemTime::now())
        .expect("real NAS proof should record");
    let canonical_raw_path = proof.canonical_path.clone();

    let mut manifest = Manifest::new();
    discover_raw_asset(&mut manifest, "asset-1", proof.canonical_path.clone())
        .expect("asset should be discovered");
    record_nas_proof(&mut manifest, "asset-1", proof).expect("nas proof should record");
    record_conversion_result(&mut manifest, "asset-1", conversion_proof())
        .expect("conversion should record");
    record_conversion_performance(&mut manifest, "asset-1", conversion_performance_input())
        .expect("conversion performance should record");
    record_heic_verification(&mut manifest, "asset-1", heic_proof())
        .expect("heic verification should record");
    record_source_age_proof(&mut manifest, "asset-1", old_source_age_proof())
        .expect("source age proof should record");
    manifest = trusted_current_manifest(manifest);
    record_upload_proof(&mut manifest, "asset-1", upload_proof())
        .expect("upload proof should record");
    record_icloudpd_local_mirror_proof(&mut manifest, "asset-1", local_mirror_proof())
        .expect("local mirror proof should record");
    let nas = manifest.get("asset-1").expect("asset should exist").proofs["nas"].clone();
    record_original_asset_proof(
        &mut manifest,
        "asset-1",
        OriginalAssetProof {
            size_bytes: nas["size_bytes"].as_u64().expect("NAS size should be u64"),
            matched_raw_sha256: nas["sha256"]
                .as_str()
                .expect("NAS sha should be a string")
                .to_string(),
            ..original_asset_proof()
        },
    )
    .expect("original asset proof should record");

    (tempdir, manifest, canonical_raw_path)
}

fn two_asset_upload_verified_manifest() -> Manifest {
    let mut manifest = Manifest::new();
    for (asset_id, filename, raw_bytes, raw_sha256, heic_path, heic_sha256, heic_size) in [
        (
            "asset-1",
            "IMG_0001.dng",
            RAW_BYTES_ASSET_1,
            "raw-sha256-1",
            "/staging/IMG_0001.heic",
            "heic-sha256-1",
            10,
        ),
        (
            "asset-2",
            "IMG_0002.dng",
            RAW_BYTES_ASSET_2,
            "raw-sha256-2",
            "/staging/IMG_0002.heic",
            "heic-sha256-2",
            11,
        ),
    ] {
        let raw_path = PathBuf::from(format!("/nas/photos/{filename}"));
        discover_raw_asset(&mut manifest, asset_id, raw_path.clone())
            .expect("asset should be discovered");
        record_nas_proof(
            &mut manifest,
            asset_id,
            NasRawProof {
                canonical_path: raw_path.clone(),
                relative_path: PathBuf::from(format!("photos/{filename}")),
                size_bytes: raw_bytes.len() as u64,
                modified_unix_seconds: 1_700_000_000,
                age_seconds: 40 * DAY,
                sha256: raw_sha256.to_string(),
            },
        )
        .expect("nas proof should record");
        record_conversion_result(
            &mut manifest,
            asset_id,
            ConversionResultInput {
                heic_path: PathBuf::from(heic_path),
                heic_sha256: heic_sha256.to_string(),
                size_bytes: heic_size,
                source_binding: ConversionSourceBinding::EmbeddedPreview,
            },
        )
        .expect("conversion should record");
        record_conversion_performance(&mut manifest, asset_id, conversion_performance_input())
            .expect("conversion performance should record");
        record_heic_verification(
            &mut manifest,
            asset_id,
            HeicVerificationInput {
                heic_path: PathBuf::from(heic_path),
                heic_sha256: heic_sha256.to_string(),
                size_bytes: heic_size,
                heif_info_ok: true,
                metadata_copied: true,
                visual_content_ok: true,
                visual_match_ok: true,
                visual_rmse_ppm: Some(0),
                visual_mae_ppm: Some(0),
            },
        )
        .expect("heic verification should record");
        record_source_age_proof(&mut manifest, asset_id, old_source_age_proof())
            .expect("source age proof should record");
        record_upload_proof(
            &mut manifest,
            asset_id,
            UploadProof {
                uploaded_heic_asset_id: format!("icloud-{asset_id}"),
                uploaded_heic_sha256: heic_sha256.to_string(),
                database_scope: Default::default(),
                zone_name: "PrimarySync".to_string(),
                uploaded_heic_path: Some(PathBuf::from(heic_path)),
            },
        )
        .expect("upload proof should record");
        record_icloudpd_local_mirror_proof(
            &mut manifest,
            asset_id,
            IcloudpdLocalMirrorProof {
                uploaded_heic_asset_id: format!("icloud-{asset_id}"),
                uploaded_heic_sha256: heic_sha256.to_string(),
                uploaded_heic_path: PathBuf::from(heic_path),
                icloudpd_download_path: PathBuf::from(format!(
                    "/PrimarySync/{}",
                    Path::new(heic_path)
                        .file_name()
                        .expect("heic path should have filename")
                        .to_string_lossy()
                )),
                size_bytes: heic_size,
            },
        )
        .expect("local mirror proof should record");
    }
    manifest
}

fn real_delete_approved_manifest() -> (tempfile::TempDir, Manifest, PathBuf) {
    let (tempdir, mut manifest, canonical_raw_path) = real_upload_verified_manifest();
    mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
    approve_delete(&mut manifest, "asset-1", "operator").expect("approval should record");

    (tempdir, manifest, canonical_raw_path)
}

#[test]
fn record_original_asset_batch_proofs_rejects_missing_result_without_partial_mutation() {
    let mut manifest = two_asset_upload_verified_manifest();
    let before = manifest.clone();
    let mut proofs = std::collections::BTreeMap::new();
    proofs.insert(
        "asset-1".to_string(),
        OriginalAssetProof {
            record_name: "CPLAsset-original-123".to_string(),
            record_change_tag: "tag-1".to_string(),
            record_type: "CPLAsset".to_string(),
            database_scope: Default::default(),
            zone_name: "PrimarySync".to_string(),
            filename: "IMG_0001.dng".to_string(),
            size_bytes: RAW_BYTES_ASSET_1.len() as u64,
            matched_raw_sha256: "raw-sha256-1".to_string(),
        },
    );

    let error = record_original_asset_batch_proofs(
        &mut manifest,
        &["asset-1".to_string(), "asset-2".to_string()],
        proofs,
    )
    .expect_err("missing batch result must fail atomically");

    assert!(matches!(
        error,
        WorkflowError::MissingBatchOriginalAssetProof { .. }
    ));
    assert_eq!(manifest, before);
}

#[test]
fn record_original_asset_batch_proofs_keeps_records_upload_verified_without_delete_state() {
    let mut manifest = two_asset_upload_verified_manifest();
    let mut proofs = std::collections::BTreeMap::new();
    proofs.insert(
        "asset-1".to_string(),
        OriginalAssetProof {
            record_name: "CPLAsset-original-123".to_string(),
            record_change_tag: "tag-1".to_string(),
            record_type: "CPLAsset".to_string(),
            database_scope: Default::default(),
            zone_name: "PrimarySync".to_string(),
            filename: "IMG_0001.dng".to_string(),
            size_bytes: RAW_BYTES_ASSET_1.len() as u64,
            matched_raw_sha256: "raw-sha256-1".to_string(),
        },
    );
    proofs.insert(
        "asset-2".to_string(),
        OriginalAssetProof {
            record_name: "CPLAsset-original-456".to_string(),
            record_change_tag: "tag-2".to_string(),
            record_type: "CPLAsset".to_string(),
            database_scope: Default::default(),
            zone_name: "PrimarySync".to_string(),
            filename: "IMG_0002.dng".to_string(),
            size_bytes: RAW_BYTES_ASSET_2.len() as u64,
            matched_raw_sha256: "raw-sha256-2".to_string(),
        },
    );

    record_original_asset_batch_proofs(
        &mut manifest,
        &["asset-1".to_string(), "asset-2".to_string()],
        proofs,
    )
    .expect("complete batch proofs should record");

    for asset_id in ["asset-1", "asset-2"] {
        let record = manifest.get(asset_id).expect("asset should exist");
        assert_eq!(record.state, State::UploadVerified);
        assert!(record.proofs.contains_key("original_asset"));
        assert!(!record.proofs.contains_key("delete_eligibility"));
        assert!(!record.proofs.contains_key("delete_approval"));
        assert!(!record.proofs.contains_key("delete"));
    }
}

#[test]
fn record_original_asset_batch_proofs_rejects_extra_result_without_mutating() {
    let mut manifest = two_asset_upload_verified_manifest();
    let before = manifest.clone();
    let mut proofs = std::collections::BTreeMap::new();
    proofs.insert(
        "asset-1".to_string(),
        OriginalAssetProof {
            record_name: "CPLAsset-original-123".to_string(),
            record_change_tag: "tag-1".to_string(),
            record_type: "CPLAsset".to_string(),
            database_scope: Default::default(),
            zone_name: "PrimarySync".to_string(),
            filename: "IMG_0001.dng".to_string(),
            size_bytes: RAW_BYTES_ASSET_1.len() as u64,
            matched_raw_sha256: "raw-sha256-1".to_string(),
        },
    );
    proofs.insert(
        "asset-3".to_string(),
        OriginalAssetProof {
            record_name: "CPLAsset-original-789".to_string(),
            record_change_tag: "tag-3".to_string(),
            record_type: "CPLAsset".to_string(),
            database_scope: Default::default(),
            zone_name: "PrimarySync".to_string(),
            filename: "IMG_0003.dng".to_string(),
            size_bytes: 12,
            matched_raw_sha256: "raw-sha256-3".to_string(),
        },
    );

    let error = record_original_asset_batch_proofs(&mut manifest, &["asset-1".to_string()], proofs)
        .expect_err("unexpected batch result must fail atomically");

    assert!(matches!(
        error,
        WorkflowError::UnexpectedBatchOriginalAssetProof { .. }
    ));
    assert_eq!(manifest, before);
}

#[test]
fn record_original_asset_batch_proofs_rejects_duplicate_original_identity_without_mutating() {
    let mut manifest = two_asset_upload_verified_manifest();
    let before = manifest.clone();
    let mut proofs = std::collections::BTreeMap::new();
    proofs.insert(
        "asset-1".to_string(),
        OriginalAssetProof {
            record_name: "CPLAsset-original-123".to_string(),
            record_change_tag: "tag-1".to_string(),
            record_type: "CPLAsset".to_string(),
            database_scope: Default::default(),
            zone_name: "PrimarySync".to_string(),
            filename: "IMG_0001.dng".to_string(),
            size_bytes: RAW_BYTES_ASSET_1.len() as u64,
            matched_raw_sha256: "raw-sha256-1".to_string(),
        },
    );
    proofs.insert(
        "asset-2".to_string(),
        OriginalAssetProof {
            record_name: "CPLAsset-original-123".to_string(),
            record_change_tag: "tag-1".to_string(),
            record_type: "CPLAsset".to_string(),
            database_scope: Default::default(),
            zone_name: "PrimarySync".to_string(),
            filename: "IMG_0002.dng".to_string(),
            size_bytes: RAW_BYTES_ASSET_2.len() as u64,
            matched_raw_sha256: "raw-sha256-2".to_string(),
        },
    );

    let error = record_original_asset_batch_proofs(
        &mut manifest,
        &["asset-1".to_string(), "asset-2".to_string()],
        proofs,
    )
    .expect_err("duplicate original record identity must fail atomically");

    assert!(matches!(
        error,
        WorkflowError::DuplicateBatchOriginalAssetProof { .. }
    ));
    assert_eq!(manifest, before);
}

fn forged_delete_approved_manifest(
    mutate: impl FnOnce(&mut AssetRecord),
) -> (tempfile::TempDir, Manifest) {
    let (tempdir, mut manifest, _) = real_delete_approved_manifest();
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    mutate(&mut record);
    manifest.upsert(record);
    (tempdir, manifest)
}

fn proof_mut<'a>(record: &'a mut AssetRecord, proof_key: &str) -> &'a mut serde_json::Value {
    record
        .proofs
        .get_mut(proof_key)
        .expect("proof should exist")
}

fn converted_manifest() -> Manifest {
    let mut manifest = Manifest::new();
    discover_raw_asset(&mut manifest, "asset-1", "/nas/photos/IMG_0001.dng")
        .expect("asset should be discovered");
    record_nas_proof(&mut manifest, "asset-1", nas_proof()).expect("nas proof should record");
    record_conversion_result(&mut manifest, "asset-1", conversion_proof())
        .expect("conversion should record");
    manifest
}

#[test]
fn adjusted_conversion_requires_exact_proof_binding_and_carries_it_into_delete_lineage() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let nas_root = tempdir.path().join("nas");
    let raw_path = write_old_raw(
        &nas_root,
        "camera/IMG_0001.dng",
        b"raw-bytes-that-are-larger-than-the-adjusted-heic-proof",
    );
    let nas = prove_nas_raw(&nas_root, &raw_path, 30, SystemTime::now())
        .expect("NAS proof should be recorded");
    let output_path = tempdir
        .path()
        .canonicalize()
        .expect("temp directory should canonicalize")
        .join("out/IMG_0001.heic");
    fs::create_dir_all(output_path.parent().expect("output parent should exist"))
        .expect("output parent should be created");
    let adjusted_path = adjusted_source_path_for_output(&output_path);
    let adjusted_bytes = nonblank_adjusted_jpeg();
    fs::write(&adjusted_path, &adjusted_bytes).expect("adjusted JPEG should be written");

    let mut manifest = Manifest::new();
    discover_raw_asset(&mut manifest, "asset-1", nas.canonical_path.clone())
        .expect("asset should be discovered");
    record_nas_proof(&mut manifest, "asset-1", nas.clone()).expect("NAS proof should record");
    let original = OriginalAssetProof {
        record_name: "original-record-1".to_string(),
        record_change_tag: "old-change-tag".to_string(),
        record_type: "CPLAsset".to_string(),
        database_scope: Default::default(),
        zone_name: "PrimarySync".to_string(),
        filename: "IMG_0001.dng".to_string(),
        size_bytes: nas.size_bytes,
        matched_raw_sha256: nas.sha256.clone(),
    };
    record_original_asset_proof(&mut manifest, "asset-1", original.clone())
        .expect("original asset proof should record");
    let wrong_asset = adjusted_source_proof(
        "other-asset",
        &original,
        adjusted_path.clone(),
        &adjusted_bytes,
    );
    let before_wrong_asset = manifest.clone();
    let error = record_adjusted_source_proof(&mut manifest, "asset-1", &output_path, wrong_asset)
        .expect_err("a well-formed proof for a different asset must be rejected");
    assert!(matches!(error, WorkflowError::AdjustedSource(_)));
    assert_eq!(
        manifest, before_wrong_asset,
        "wrong-asset proof must not mutate the manifest"
    );
    let adjusted =
        adjusted_source_proof("asset-1", &original, adjusted_path.clone(), &adjusted_bytes);
    record_adjusted_source_proof(&mut manifest, "asset-1", &output_path, adjusted.clone())
        .expect("adjusted source proof should record while NAS-verified");
    let error =
        record_adjusted_source_proof(&mut manifest, "asset-1", &output_path, adjusted.clone())
            .expect_err("adjusted source proof must not be overwritten");
    assert!(matches!(
        error,
        WorkflowError::AdjustedSourceProofAlreadyRecorded { .. }
    ));

    let unbound = ConversionResultInput {
        heic_path: output_path.clone(),
        heic_sha256: "heic-sha256".to_string(),
        size_bytes: 24,
        source_binding: ConversionSourceBinding::EmbeddedPreview,
    };
    let before = manifest.clone();
    let error = record_conversion_result(&mut manifest, "asset-1", unbound)
        .expect_err("adjusted proof must not permit an unbound conversion");
    assert!(matches!(
        error,
        WorkflowError::ConversionSourceBindingMismatch { .. }
    ));
    assert_eq!(manifest, before);

    let binding = ConversionSourceBinding::AdjustedSource {
        adjusted_source_proof_digest: adjusted_source_proof_digest(&adjusted),
        adjusted_jpeg_sha256: adjusted.downloaded_sha256.clone(),
        adjusted_jpeg_path: adjusted_path.clone(),
    };
    for invalid_binding in [
        ConversionSourceBinding::AdjustedSource {
            adjusted_source_proof_digest: "a".repeat(64),
            adjusted_jpeg_sha256: adjusted.downloaded_sha256.clone(),
            adjusted_jpeg_path: adjusted_path.clone(),
        },
        ConversionSourceBinding::AdjustedSource {
            adjusted_source_proof_digest: adjusted_source_proof_digest(&adjusted),
            adjusted_jpeg_sha256: "b".repeat(64),
            adjusted_jpeg_path: adjusted_path.clone(),
        },
        ConversionSourceBinding::AdjustedSource {
            adjusted_source_proof_digest: adjusted_source_proof_digest(&adjusted),
            adjusted_jpeg_sha256: adjusted.downloaded_sha256.clone(),
            adjusted_jpeg_path: PathBuf::from("/other/IMG_0001.adjusted-source.jpg"),
        },
    ] {
        let error = record_conversion_result(
            &mut manifest,
            "asset-1",
            ConversionResultInput {
                heic_path: output_path.clone(),
                heic_sha256: "heic-sha256".to_string(),
                size_bytes: 24,
                source_binding: invalid_binding,
            },
        )
        .expect_err("every adjusted binding field must match the durable proof");
        assert!(matches!(
            error,
            WorkflowError::ConversionSourceBindingMismatch { .. }
        ));
        assert_eq!(manifest, before);
    }
    record_conversion_result(
        &mut manifest,
        "asset-1",
        ConversionResultInput {
            heic_path: output_path.clone(),
            heic_sha256: "heic-sha256".to_string(),
            size_bytes: 24,
            source_binding: binding.clone(),
        },
    )
    .expect("exact adjusted conversion binding should record");
    record_conversion_performance(&mut manifest, "asset-1", conversion_performance_input())
        .expect("conversion performance should record");
    record_heic_verification(
        &mut manifest,
        "asset-1",
        HeicVerificationInput {
            heic_path: output_path.clone(),
            heic_sha256: "heic-sha256".to_string(),
            size_bytes: 24,
            heif_info_ok: true,
            metadata_copied: true,
            visual_content_ok: true,
            visual_match_ok: true,
            visual_rmse_ppm: Some(0),
            visual_mae_ppm: Some(0),
        },
    )
    .expect("HEIC verification should record");
    record_source_age_proof(&mut manifest, "asset-1", old_source_age_proof())
        .expect("source age should record");
    record_upload_proof(
        &mut manifest,
        "asset-1",
        UploadProof {
            uploaded_heic_asset_id: "icloud-heic-asset-1".to_string(),
            uploaded_heic_sha256: "heic-sha256".to_string(),
            database_scope: Default::default(),
            zone_name: "PrimarySync".to_string(),
            uploaded_heic_path: Some(output_path.clone()),
        },
    )
    .expect("upload proof should record");
    record_icloudpd_local_mirror_proof(
        &mut manifest,
        "asset-1",
        IcloudpdLocalMirrorProof {
            uploaded_heic_asset_id: "icloud-heic-asset-1".to_string(),
            uploaded_heic_sha256: "heic-sha256".to_string(),
            uploaded_heic_path: output_path.clone(),
            icloudpd_download_path: PathBuf::from("/PrimarySync/IMG_0001.HEIC"),
            size_bytes: 24,
        },
    )
    .expect("mirror proof should record");
    mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
    approve_delete(&mut manifest, "asset-1", "operator").expect("approval should record");

    assert_eq!(
        manifest.get("asset-1").expect("asset should exist").proofs["delete_approval"]["adjusted_source_proof_key"],
        "adjusted_source"
    );
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist").proofs["delete_approval"]["adjusted_source_proof_digest"],
        adjusted_source_proof_digest(&adjusted)
    );

    let plan = build_delete_plan(&manifest, "asset-1").expect("delete plan should build");
    assert!(
        plan.required_proof_keys
            .contains(&"adjusted_source".to_string())
    );
    assert_eq!(
        plan.proofs["delete_eligibility"]["adjusted_source_proof_digest"],
        adjusted_source_proof_digest(&adjusted)
    );
    assert_eq!(
        plan.proofs["conversion"]["source_binding"],
        serde_json::to_value(binding).unwrap()
    );

    let prevalidated = prevalidate_approved_original_delete(&manifest, "asset-1")
        .expect("adjusted delete should prevalidate with approval lineage");
    let approval_original = manifest.get("asset-1").expect("asset should exist").clone();
    let mut approval_tampered = approval_original.clone();
    proof_mut(&mut approval_tampered, "delete_approval")["adjusted_source_proof_digest"] =
        json!("e".repeat(64));
    manifest.upsert(approval_tampered);
    assert!(
        build_delete_plan(&manifest, "asset-1").is_err(),
        "approval lineage tampering must block delete planning"
    );
    let error = record_prevalidated_delete_execution(&mut manifest, prevalidated, delete_outcome())
        .expect_err("approval lineage tampering must stale a prevalidated delete");
    assert!(matches!(
        error,
        WorkflowError::PrevalidatedDeleteStale { field, .. } if field == "delete_approval"
    ));
    manifest.upsert(approval_original);

    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    proof_mut(&mut record, "adjusted_source")["downloadedSha256"] = json!("f".repeat(64));
    manifest.upsert(record);
    assert!(
        build_delete_plan(&manifest, "asset-1").is_err(),
        "adjusted source tampering must block delete planning"
    );
}

#[test]
fn embedded_preview_delete_approval_remains_legacy_compatible_without_adjusted_fields() {
    let (_tempdir, manifest, _) = real_delete_approved_manifest();
    let approval = &manifest.get("asset-1").expect("asset should exist").proofs["delete_approval"];

    assert_eq!(approval["operator"], "operator");
    assert!(approval.get("adjusted_source_proof_key").is_none());
    assert!(approval.get("adjusted_source_proof_digest").is_none());
    build_delete_plan(&manifest, "asset-1")
        .expect("legacy embedded-preview approval should remain delete-plan compatible");
}

#[test]
fn embedded_preview_workflow_rejects_an_unproven_adjusted_conversion_claim() {
    let mut manifest = Manifest::new();
    discover_raw_asset(&mut manifest, "asset-1", "/nas/photos/IMG_0001.dng")
        .expect("asset should be discovered");
    record_nas_proof(&mut manifest, "asset-1", nas_proof()).expect("NAS proof should record");
    let before = manifest.clone();

    let error = record_conversion_result(
        &mut manifest,
        "asset-1",
        ConversionResultInput {
            heic_path: PathBuf::from("/staging/IMG_0001.heic"),
            heic_sha256: "heic-sha256".to_string(),
            size_bytes: 24,
            source_binding: ConversionSourceBinding::AdjustedSource {
                adjusted_source_proof_digest: "a".repeat(64),
                adjusted_jpeg_sha256: "b".repeat(64),
                adjusted_jpeg_path: PathBuf::from("/staging/IMG_0001.adjusted-source.jpg"),
            },
        },
    )
    .expect_err("normal conversion must not claim adjusted lineage");

    assert!(matches!(
        error,
        WorkflowError::ConversionSourceBindingMismatch { .. }
    ));
    assert_eq!(manifest, before);
}

#[test]
fn adjusted_source_proof_rejects_discovered_or_unknown_assets_without_mutation() {
    let mut manifest = Manifest::new();
    discover_raw_asset(&mut manifest, "asset-1", "/nas/photos/IMG_0001.dng")
        .expect("asset should be discovered");
    let proof = adjusted_source_proof(
        "asset-1",
        &original_asset_proof(),
        PathBuf::from("/staging/IMG_0001.adjusted-source.jpg"),
        &nonblank_adjusted_jpeg(),
    );
    let before = manifest.clone();

    let error = record_adjusted_source_proof(
        &mut manifest,
        "asset-1",
        "/staging/IMG_0001.heic",
        proof.clone(),
    )
    .expect_err("discovered asset must not accept adjusted proof");
    assert!(matches!(
        error,
        WorkflowError::AdjustedSourceUnavailable {
            state: State::Discovered,
            ..
        }
    ));
    assert_eq!(manifest, before);

    let error = record_adjusted_source_proof(
        &mut manifest,
        "unknown-asset",
        "/staging/IMG_0001.heic",
        proof,
    )
    .expect_err("unknown asset must not accept adjusted proof");
    assert!(matches!(
        error,
        WorkflowError::Manifest(ManifestError::UnknownAsset { .. })
    ));
    assert_eq!(manifest, before);
}

fn conversion_performance_manifest() -> Manifest {
    let mut manifest = converted_manifest();
    record_conversion_performance(&mut manifest, "asset-1", conversion_performance_input())
        .expect("conversion performance should record");
    manifest
}

#[test]
fn conversion_performance_rejects_replacements_without_byte_savings() {
    let cases = [42, 43];

    for heic_size in cases {
        let mut manifest = Manifest::new();
        discover_raw_asset(&mut manifest, "asset-1", "/nas/photos/IMG_0001.dng")
            .expect("asset should be discovered");
        record_nas_proof(&mut manifest, "asset-1", nas_proof()).expect("nas proof should record");
        record_conversion_result(
            &mut manifest,
            "asset-1",
            ConversionResultInput {
                size_bytes: heic_size,
                ..conversion_proof()
            },
        )
        .expect("conversion should record");

        let error =
            record_conversion_performance(&mut manifest, "asset-1", conversion_performance_input())
                .expect_err("no-savings replacements must fail closed");

        assert!(matches!(
            error,
            WorkflowError::InvalidProofField {
                proof_key: "conversion_performance",
                field: "heic_size_bytes",
                ..
            }
        ));
        assert!(
            !manifest
                .get("asset-1")
                .expect("asset should exist")
                .proofs
                .contains_key("conversion_performance")
        );
    }
}

#[test]
fn original_asset_proof_records_icloud_identity_bound_to_nas() {
    let mut manifest = converted_manifest();

    let record = record_original_asset_proof(&mut manifest, "asset-1", original_asset_proof())
        .expect("original asset proof should record");

    assert_eq!(record.state, State::Converted);
    assert_eq!(
        record.proofs["original_asset"]["record_name"],
        "original-record-1"
    );
    assert_eq!(
        record.proofs["original_asset"]["record_change_tag"],
        "old-change-tag"
    );
    assert_eq!(record.proofs["original_asset"]["record_type"], "CPLAsset");
    assert_eq!(record.proofs["original_asset"]["filename"], "IMG_0001.dng");
    assert_eq!(record.proofs["original_asset"]["size_bytes"], 42);
    assert_eq!(
        record.proofs["original_asset"]["matched_raw_sha256"],
        "raw-sha256"
    );
}

#[test]
fn original_asset_proof_fails_closed_without_nas_or_valid_identity() {
    let cases = [
        (
            "record_name",
            OriginalAssetProof {
                record_name: " ".to_string(),
                ..original_asset_proof()
            },
        ),
        (
            "record_change_tag",
            OriginalAssetProof {
                record_change_tag: " ".to_string(),
                ..original_asset_proof()
            },
        ),
        (
            "filename",
            OriginalAssetProof {
                filename: " ".to_string(),
                ..original_asset_proof()
            },
        ),
        (
            "record_type",
            OriginalAssetProof {
                record_type: "CPLMaster".to_string(),
                ..original_asset_proof()
            },
        ),
        (
            "size_bytes",
            OriginalAssetProof {
                size_bytes: 41,
                ..original_asset_proof()
            },
        ),
        (
            "matched_raw_sha256",
            OriginalAssetProof {
                matched_raw_sha256: "other-raw-sha256".to_string(),
                ..original_asset_proof()
            },
        ),
    ];

    for (field, proof) in cases {
        let mut manifest = converted_manifest();
        let before = manifest.get("asset-1").expect("asset should exist").clone();

        let error = record_original_asset_proof(&mut manifest, "asset-1", proof)
            .expect_err("invalid original asset proof must fail closed");

        if matches!(field, "record_name" | "record_change_tag" | "filename") {
            assert!(matches!(
                error,
                WorkflowError::EmptyProofField { field: actual } if actual == field
            ));
        } else if field == "record_type" {
            assert!(matches!(
                error,
                WorkflowError::ProofMismatch {
                    proof_key: "original_asset",
                    field: "record_type",
                    ..
                }
            ));
        } else {
            assert!(matches!(
                error,
                WorkflowError::ProofMismatch {
                    proof_key: "nas",
                    field: actual,
                    ..
                } if actual == field
            ));
        }
        assert_eq!(
            manifest.get("asset-1").expect("asset should exist"),
            &before
        );
    }

    let mut manifest = Manifest::new();
    manifest.upsert(AssetRecord::new(
        "asset-1",
        PathBuf::from("/nas/photos/IMG_0001.dng"),
    ));
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = record_original_asset_proof(&mut manifest, "asset-1", original_asset_proof())
        .expect_err("NAS proof is required before original identity");

    assert!(matches!(
        error,
        WorkflowError::MissingProof {
            proof_key,
            ..
        } if proof_key == "nas"
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
}

#[test]
fn prove_and_record_nas_rejects_min_age_below_floor_without_mutation() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let nas_root = tempdir.path().join("nas");
    fs::create_dir_all(&nas_root).expect("nas root should be created");
    let raw_path = write_old_raw(&nas_root, "camera/IMG_0000.dng", b"raw-bytes");
    let mut manifest = Manifest::new();

    let error = prove_and_record_nas(
        &mut manifest,
        "asset-1",
        &raw_path,
        &nas_root,
        0,
        SystemTime::now(),
    )
    .expect_err("weak NAS age floor should fail closed");

    assert!(matches!(
        error,
        WorkflowError::Proof(ProofError::MinAgeBelowSafetyFloor {
            requested_days: 0,
            minimum_days: 30
        })
    ));
    assert!(manifest.records().is_empty());
}

#[test]
fn valid_ordered_workflow_reaches_delete_plan_without_deleting() {
    let (_tempdir, manifest, raw_path) = real_delete_approved_manifest();

    let plan = build_delete_plan(&manifest, "asset-1").expect("delete plan should build");
    let record = manifest.get("asset-1").expect("asset should exist");

    assert_eq!(record.state, State::DeleteApproved);
    assert!(!record.proofs.contains_key("delete"));
    assert_eq!(plan.asset_id, "asset-1");
    assert_eq!(plan.raw_path, raw_path);
    assert_eq!(
        plan.required_proof_keys,
        vec![
            "nas",
            "original_asset",
            "conversion",
            "conversion_performance",
            "heic",
            "source_age",
            "upload",
            "icloudpd_local_mirror",
            "delete_eligibility",
            "delete_approval"
        ]
    );
    assert_eq!(
        plan.proofs["upload"]["uploaded_heic_asset_id"],
        "icloud-heic-asset-1"
    );
    assert_eq!(
        plan.proofs["source_age"]["source_captured_unix_seconds"],
        SOURCE_AGE_VERIFIED_AT - 40 * DAY
    );
    assert_eq!(
        plan.proofs["delete_eligibility"]["conversion_performance_proof_key"],
        "conversion_performance"
    );
    assert_eq!(
        plan.proofs["icloudpd_local_mirror"]["icloudpd_download_path"],
        "/PrimarySync/IMG_0001.HEIC"
    );
    assert_eq!(
        plan.proofs["delete_eligibility"]["icloudpd_local_mirror_proof_key"],
        "icloudpd_local_mirror"
    );
    assert_eq!(
        plan.proofs["delete_eligibility"]["original_asset_proof_key"],
        "original_asset"
    );
    assert_eq!(
        plan.proofs["original_asset"]["record_name"],
        "original-record-1"
    );
}

#[test]
fn delete_eligibility_requires_original_asset_identity_without_mutation() {
    let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    record.proofs.remove("original_asset");
    manifest.upsert(record);
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = mark_delete_eligible(&mut manifest, "asset-1")
        .expect_err("original asset identity is required before delete eligibility");

    assert!(matches!(
        error,
        WorkflowError::MissingProof {
            proof_key,
            ..
        } if proof_key == "original_asset"
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
    assert!(!before.proofs.contains_key("delete_eligibility"));
}

#[test]
fn delete_approval_revalidates_original_asset_identity() {
    let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
    mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    proof_mut(&mut record, "original_asset")["matched_raw_sha256"] = json!("forged-raw-sha256");
    manifest.upsert(record);
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = approve_delete(&mut manifest, "asset-1", "operator")
        .expect_err("approval must revalidate original asset identity");

    assert!(matches!(
        error,
        WorkflowError::ProofMismatch {
            proof_key: "nas",
            field: "matched_raw_sha256",
            ..
        }
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
    assert!(!before.proofs.contains_key("delete_approval"));
}

#[test]
fn delete_plan_revalidates_original_asset_identity() {
    let (_tempdir, manifest) = forged_delete_approved_manifest(|record| {
        proof_mut(record, "original_asset")["record_name"] = json!(" ");
    });

    let error = build_delete_plan(&manifest, "asset-1")
        .expect_err("delete plan must revalidate original identity");

    assert!(matches!(
        error,
        WorkflowError::EmptyProofField {
            field: "record_name"
        }
    ));
}

#[test]
fn prevalidated_delete_records_without_rehashing_nas_after_cloudkit_delete() {
    let (_tempdir, mut manifest, raw_path) = real_delete_approved_manifest();
    let prevalidated = prevalidate_approved_original_delete(&manifest, "asset-1")
        .expect("approved delete should prevalidate");

    assert_eq!(prevalidated.asset_id(), "asset-1");
    assert_eq!(prevalidated.request().record_name, "original-record-1");
    assert_eq!(prevalidated.request().record_change_tag, "old-change-tag");

    fs::remove_file(raw_path).expect("test should prove result recording does not read NAS");
    let record =
        record_prevalidated_delete_execution(&mut manifest, prevalidated, delete_outcome())
            .expect("accepted CloudKit delete should record from prevalidated facts");

    assert_eq!(record.state, State::Deleted);
    assert_eq!(
        record.proofs["delete"]["uploaded_heic_asset_id"],
        "icloud-heic-asset-1"
    );
}

#[test]
fn prevalidated_delete_still_rehashes_nas_before_cloudkit_delete() {
    let (_tempdir, manifest, raw_path) = real_delete_approved_manifest();
    let stored_modified =
        manifest.get("asset-1").expect("asset should exist").proofs["nas"]["modified_unix_seconds"]
            .as_u64()
            .expect("stored mtime should be a u64");
    fs::write(&raw_path, b"new-bytes-that-are-larger-than-heic")
        .expect("test raw should be changed");
    set_raw_mtime(&raw_path, stored_modified);

    let error = prevalidate_approved_original_delete(&manifest, "asset-1")
        .expect_err("changed NAS bytes must block prevalidation");

    assert!(matches!(
        error,
        WorkflowError::ProofMismatch {
            proof_key: "nas",
            field: "sha256",
            ..
        }
    ));
}

#[test]
fn live_prevalidation_fails_closed_when_raw_is_missing() {
    let (_tempdir, manifest, raw_path) = real_delete_approved_manifest();
    fs::remove_file(raw_path).expect("test RAW should be removed");

    let error = prevalidate_approved_original_delete(&manifest, "asset-1")
        .expect_err("missing RAW must still block live prevalidation");

    assert!(matches!(
        error,
        WorkflowError::Proof(ProofError::CanonicalizeRaw { .. })
    ));
}

#[test]
fn prevalidated_delete_cannot_be_created_without_delete_approval() {
    let manifest = upload_verified_manifest();

    let error = prevalidate_approved_original_delete(&manifest, "asset-1")
        .expect_err("unapproved manifest must not produce a prevalidated delete");

    assert!(matches!(
        error,
        WorkflowError::DeletePlanUnavailable {
            state: State::UploadVerified,
            ..
        }
    ));
}

#[test]
fn prevalidated_delete_rejects_changed_proof_snapshot_without_mutation() {
    let (_tempdir, mut manifest, _) = real_delete_approved_manifest();
    let prevalidated = prevalidate_approved_original_delete(&manifest, "asset-1")
        .expect("approved delete should prevalidate");
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    proof_mut(&mut record, "upload")["uploaded_heic_asset_id"] = json!("changed-upload");
    manifest.upsert(record);
    let before = manifest.clone();

    let error = record_prevalidated_delete_execution(&mut manifest, prevalidated, delete_outcome())
        .expect_err("changed proof snapshot must invalidate prevalidation");

    assert!(matches!(
        error,
        WorkflowError::PrevalidatedDeleteStale { field, .. } if field == "upload"
    ));
    assert_eq!(manifest, before);
}

#[test]
fn delete_reconciliation_records_missing_raw_after_confirmed_remote_delete() {
    let (_tempdir, mut manifest, raw_path) = real_delete_approved_manifest();
    fs::remove_file(raw_path).expect("test RAW should be removed after remote delete");

    let reconciliation = prepare_delete_reconciliation(&manifest, "asset-1")
        .expect("reconciliation should not require live NAS access");

    assert_eq!(reconciliation.asset_id(), "asset-1");
    assert_eq!(reconciliation.request().record_name, "original-record-1");
    assert_eq!(reconciliation.request().record_change_tag, "old-change-tag");

    let record =
        record_reconciled_delete_execution(&mut manifest, reconciliation, delete_outcome())
            .expect("strict confirmed remote delete should record");

    assert_eq!(record.state, State::Deleted);
    assert_eq!(
        record.proofs["delete"]["uploaded_heic_asset_id"],
        "icloud-heic-asset-1"
    );
}

#[test]
fn delete_reconciliation_rejects_stale_proof_snapshot_without_mutation() {
    let (_tempdir, mut manifest, _) = real_delete_approved_manifest();
    let reconciliation = prepare_delete_reconciliation(&manifest, "asset-1")
        .expect("approved delete should build reconciliation token");
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    proof_mut(&mut record, "upload")["uploaded_heic_asset_id"] = json!("changed-upload");
    manifest.upsert(record);
    let before = manifest.clone();

    let error = record_reconciled_delete_execution(&mut manifest, reconciliation, delete_outcome())
        .expect_err("changed proof snapshot must invalidate reconciliation");

    assert!(matches!(
        error,
        WorkflowError::DeleteReconciliationStale { field, .. } if field == "upload"
    ));
    assert_eq!(manifest, before);
}

#[test]
fn delete_reconciliation_rejects_mismatched_outcome_without_mutation() {
    let (_tempdir, mut manifest, _) = real_delete_approved_manifest();
    let reconciliation = prepare_delete_reconciliation(&manifest, "asset-1")
        .expect("approved delete should build reconciliation token");
    let before = manifest.clone();

    let error = record_reconciled_delete_execution(
        &mut manifest,
        reconciliation,
        CloudKitDeleteOutcome {
            record_name: "other-record".to_string(),
            ..delete_outcome()
        },
    )
    .expect_err("reconciled outcome must match the stored original");

    assert!(matches!(
        error,
        WorkflowError::ProofMismatch {
            proof_key: "original_asset",
            field: "record_name",
            ..
        }
    ));
    assert_eq!(manifest, before);
}

#[test]
fn delete_reconciliation_cannot_be_created_without_delete_approval() {
    let manifest = upload_verified_manifest();

    let error = prepare_delete_reconciliation(&manifest, "asset-1")
        .expect_err("unapproved manifest must not produce reconciliation token");

    assert!(matches!(
        error,
        WorkflowError::DeletePlanUnavailable {
            state: State::UploadVerified,
            ..
        }
    ));
}

#[test]
fn prevalidated_delete_rejects_token_after_asset_already_transitioned() {
    let (_tempdir, mut manifest, _) = real_delete_approved_manifest();
    let prevalidated = prevalidate_approved_original_delete(&manifest, "asset-1")
        .expect("approved delete should prevalidate");
    record_delete_execution(&mut manifest, "asset-1", delete_outcome())
        .expect("parallel completion should transition the asset");
    let before = manifest.clone();

    let error = record_prevalidated_delete_execution(&mut manifest, prevalidated, delete_outcome())
        .expect_err("stale token must not record a second delete");

    assert!(matches!(
        error,
        WorkflowError::Manifest(ManifestError::InvalidTransition {
            from: State::Deleted,
            to: State::Deleted,
            ..
        })
    ));
    assert_eq!(manifest, before);
}

#[test]
fn prevalidated_delete_rejects_changed_raw_path_without_mutation() {
    let (_tempdir, mut manifest, _) = real_delete_approved_manifest();
    let prevalidated = prevalidate_approved_original_delete(&manifest, "asset-1")
        .expect("approved delete should prevalidate");
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    record.raw_path = PathBuf::from("/other/IMG_0001.dng");
    manifest.upsert(record);
    let before = manifest.clone();

    let error = record_prevalidated_delete_execution(&mut manifest, prevalidated, delete_outcome())
        .expect_err("changed raw path must invalidate prevalidation");

    assert!(matches!(
        error,
        WorkflowError::PrevalidatedDeleteStale { field, .. } if field == "raw_path"
    ));
    assert_eq!(manifest, before);
}

#[test]
fn prevalidated_delete_rejects_wrong_cloudkit_outcome_without_mutation() {
    let (_tempdir, mut manifest, _) = real_delete_approved_manifest();
    let prevalidated = prevalidate_approved_original_delete(&manifest, "asset-1")
        .expect("approved delete should prevalidate");
    let before = manifest.clone();

    let error = record_prevalidated_delete_execution(
        &mut manifest,
        prevalidated,
        CloudKitDeleteOutcome {
            record_name: "other-record".to_string(),
            ..delete_outcome()
        },
    )
    .expect_err("CloudKit outcome must match the prevalidated original");

    assert!(matches!(
        error,
        WorkflowError::ProofMismatch {
            proof_key: "original_asset",
            field: "record_name",
            ..
        }
    ));
    assert_eq!(manifest, before);
}

#[test]
fn prevalidated_delete_live_raw_token_accepts_unchanged_file_before_cloudkit() {
    let (_tempdir, manifest, _) = real_delete_approved_manifest();
    let prevalidated = prevalidate_approved_original_delete(&manifest, "asset-1")
        .expect("approved delete should prevalidate");

    prevalidated
        .validate_freshness_at(Duration::from_secs(60), prevalidated.validated_at())
        .expect("fresh token should pass cheap freshness check");
    prevalidated
        .validate_live_raw_at(Duration::from_secs(60), prevalidated.validated_at())
        .expect("unchanged fresh RAW token should remain valid");
}

#[test]
fn prevalidated_delete_live_raw_token_expires_before_cloudkit() {
    let (_tempdir, manifest, _) = real_delete_approved_manifest();
    let prevalidated = prevalidate_approved_original_delete(&manifest, "asset-1")
        .expect("approved delete should prevalidate");

    let error = prevalidated
        .validate_freshness_at(
            Duration::from_secs(5),
            prevalidated.validated_at() + Duration::from_secs(6),
        )
        .expect_err("expired prevalidation token must fail closed");

    assert!(matches!(
        error,
        WorkflowError::PrevalidatedDeleteExpired { asset_id, .. } if asset_id == "asset-1"
    ));
}

#[test]
fn prevalidated_delete_freshness_rejects_backward_clock_before_cloudkit() {
    let (_tempdir, manifest, _) = real_delete_approved_manifest();
    let prevalidated = prevalidate_approved_original_delete(&manifest, "asset-1")
        .expect("approved delete should prevalidate");

    let error = prevalidated
        .validate_freshness_at(
            Duration::from_secs(60),
            prevalidated.validated_at() - Duration::from_secs(1),
        )
        .expect_err("backward SystemTime movement must fail closed");

    assert!(matches!(
        error,
        WorkflowError::PrevalidatedDeleteClockMovedBackwards { asset_id } if asset_id == "asset-1"
    ));
}

#[test]
fn prevalidated_delete_live_raw_token_rejects_same_size_bytes_with_restored_mtime() {
    let (_tempdir, manifest, raw_path) = real_delete_approved_manifest();
    let prevalidated = prevalidate_approved_original_delete(&manifest, "asset-1")
        .expect("approved delete should prevalidate");
    let stored_modified =
        manifest.get("asset-1").expect("asset should exist").proofs["nas"]["modified_unix_seconds"]
            .as_u64()
            .expect("stored mtime should be a u64");
    fs::write(&raw_path, vec![b'X'; RAW_BYTES_ASSET_1.len()])
        .expect("same-size raw should be replaced");
    set_raw_mtime(&raw_path, stored_modified);

    let error = prevalidated
        .validate_live_raw_at(Duration::from_secs(60), prevalidated.validated_at())
        .expect_err("same-size mutation with restored mtime must fail closed");

    assert!(matches!(
        error,
        WorkflowError::PrevalidatedDeleteStale { field, .. } if field == "raw_fingerprint"
    ));
}

#[test]
fn prevalidated_delete_live_raw_token_rejects_inode_swap_at_same_path() {
    let (tempdir, manifest, raw_path) = real_delete_approved_manifest();
    let prevalidated = prevalidate_approved_original_delete(&manifest, "asset-1")
        .expect("approved delete should prevalidate");
    let stored_modified =
        manifest.get("asset-1").expect("asset should exist").proofs["nas"]["modified_unix_seconds"]
            .as_u64()
            .expect("stored mtime should be a u64");
    let replacement = tempdir.path().join("replacement.dng");
    fs::write(&replacement, RAW_BYTES_ASSET_1).expect("replacement raw should be written");
    set_raw_mtime(&replacement, stored_modified);
    fs::rename(&replacement, &raw_path).expect("replacement should swap into original path");
    set_raw_mtime(&raw_path, stored_modified);

    let error = prevalidated
        .validate_live_raw_at(Duration::from_secs(60), prevalidated.validated_at())
        .expect_err("inode swap must fail closed");

    assert!(matches!(
        error,
        WorkflowError::PrevalidatedDeleteStale { field, .. } if field == "raw_fingerprint"
    ));
}

#[test]
fn delete_execution_records_confirmed_delete_and_transitions_to_deleted() {
    let (_tempdir, mut manifest, _) = real_delete_approved_manifest();

    let record = record_delete_execution(&mut manifest, "asset-1", delete_outcome())
        .expect("confirmed delete should record");

    assert_eq!(record.state, State::Deleted);
    assert_eq!(
        record.proofs["delete"]["deleted_record_name"],
        "original-record-1"
    );
    assert_eq!(
        record.proofs["delete"]["old_record_change_tag"],
        "old-change-tag"
    );
    assert_eq!(
        record.proofs["delete"]["confirmed_deleted_change_tag"],
        "deleted-change-tag"
    );
    assert_eq!(
        record.proofs["delete"]["uploaded_heic_asset_id"],
        "icloud-heic-asset-1"
    );
}

#[test]
fn delete_execution_fails_closed_for_mismatched_outcome_or_unapproved_state() {
    let (_tempdir, mut manifest, _) = real_delete_approved_manifest();
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = record_delete_execution(
        &mut manifest,
        "asset-1",
        CloudKitDeleteOutcome {
            record_name: "other-record".to_string(),
            ..delete_outcome()
        },
    )
    .expect_err("mismatched delete outcome must fail closed");

    assert!(matches!(
        error,
        WorkflowError::ProofMismatch {
            proof_key: "original_asset",
            field: "record_name",
            ..
        }
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );

    let mut unapproved = upload_verified_manifest();
    let before = unapproved
        .get("asset-1")
        .expect("asset should exist")
        .clone();
    let error = record_delete_execution(&mut unapproved, "asset-1", delete_outcome())
        .expect_err("delete execution requires approval");

    assert!(matches!(
        error,
        WorkflowError::Manifest(ManifestError::InvalidTransition {
            from: State::UploadVerified,
            to: State::Deleted,
            ..
        })
    ));
    assert_eq!(
        unapproved.get("asset-1").expect("asset should exist"),
        &before
    );
}

#[test]
fn delete_execution_fails_closed_without_original_identity_or_with_forged_facts() {
    let (_tempdir, mut manifest, _) = real_delete_approved_manifest();
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    record.proofs.remove("original_asset");
    manifest.upsert(record);
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = record_delete_execution(&mut manifest, "asset-1", delete_outcome())
        .expect_err("delete execution requires original identity proof");

    assert!(matches!(
        error,
        WorkflowError::MissingProof {
            proof_key,
            ..
        } if proof_key == "original_asset"
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );

    let (_tempdir, mut manifest, _) = real_delete_approved_manifest();
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    proof_mut(&mut record, "delete_eligibility")["uploaded_heic_asset_id"] =
        json!("forged-heic-asset");
    manifest.upsert(record);
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = record_delete_execution(&mut manifest, "asset-1", delete_outcome())
        .expect_err("delete execution revalidates delete facts");

    assert!(matches!(
        error,
        WorkflowError::ProofMismatch {
            proof_key: "delete_eligibility",
            field: "uploaded_heic_asset_id",
            ..
        }
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
}

#[test]
fn delete_execution_requires_new_non_empty_change_tag_without_mutation() {
    for record_change_tag in [" ", "old-change-tag"] {
        let (_tempdir, mut manifest, _) = real_delete_approved_manifest();
        let before = manifest.get("asset-1").expect("asset should exist").clone();

        let error = record_delete_execution(
            &mut manifest,
            "asset-1",
            CloudKitDeleteOutcome {
                record_change_tag: record_change_tag.to_string(),
                ..delete_outcome()
            },
        )
        .expect_err("delete execution requires a new confirmed change tag");

        if record_change_tag.trim().is_empty() {
            assert!(matches!(
                error,
                WorkflowError::EmptyProofField {
                    field: "confirmed_deleted_change_tag"
                }
            ));
        } else {
            assert!(matches!(
                error,
                WorkflowError::ProofMismatch {
                    proof_key: "delete",
                    field: "confirmed_deleted_change_tag",
                    ..
                }
            ));
        }
        assert_eq!(
            manifest.get("asset-1").expect("asset should exist"),
            &before
        );
    }
}

#[test]
fn delete_plan_revalidates_persisted_heic_verification_flags() {
    let cases = [
        (
            "heif_info_ok",
            "forged heif-info failure must block delete plan",
        ),
        (
            "metadata_copied",
            "forged metadata proof must block delete plan",
        ),
        (
            "visual_content_ok",
            "forged visual-content proof must block delete plan",
        ),
        (
            "visual_match_ok",
            "forged visual-match proof must block delete plan",
        ),
    ];

    for (field, message) in cases {
        let (_tempdir, manifest) = forged_delete_approved_manifest(|record| {
            proof_mut(record, "heic")[field] = json!(false);
        });

        let error = build_delete_plan(&manifest, "asset-1").expect_err(message);

        assert!(matches!(
            error,
            WorkflowError::HeicVerificationFailed {
                field: actual
            } if actual == field
        ));
    }
}

#[test]
fn delete_plan_rejects_legacy_heic_proof_without_visual_validation() {
    let (_tempdir, manifest) = forged_delete_approved_manifest(|record| {
        let proof = proof_mut(record, "heic");
        proof
            .as_object_mut()
            .expect("proof should be an object")
            .remove("visual_content_ok");
        proof
            .as_object_mut()
            .expect("proof should be an object")
            .remove("visual_match_ok");
    });

    let error = build_delete_plan(&manifest, "asset-1")
        .expect_err("legacy visual proof must block delete plan");

    assert!(matches!(
        error,
        WorkflowError::ProofDecode {
            proof_key: "heic",
            ..
        }
    ));
}

#[test]
fn delete_plan_revalidates_upload_hash_and_path_against_heic() {
    let cases = [
        ("uploaded_heic_sha256", json!("other-heic-sha256")),
        ("uploaded_heic_path", json!("/other/IMG_0001.heic")),
    ];

    for (field, value) in cases {
        let (_tempdir, manifest) = forged_delete_approved_manifest(|record| {
            proof_mut(record, "upload")[field] = value;
        });

        let error = build_delete_plan(&manifest, "asset-1")
            .expect_err("forged upload proof must block delete plan");

        assert!(matches!(
            error,
            WorkflowError::ProofMismatch {
                proof_key: "heic",
                field: actual,
                ..
            } if actual == field
        ));
    }
}

#[test]
fn delete_plan_revalidates_icloudpd_local_mirror_binding() {
    let cases = [
        ("uploaded_heic_asset_id", json!("other-heic-asset")),
        ("uploaded_heic_sha256", json!("other-heic-sha256")),
        ("uploaded_heic_path", json!("/other/IMG_0001.heic")),
        ("size_bytes", json!(25)),
    ];

    for (field, value) in cases {
        let (_tempdir, manifest) = forged_delete_approved_manifest(|record| {
            proof_mut(record, "icloudpd_local_mirror")[field] = value;
        });

        let error = build_delete_plan(&manifest, "asset-1")
            .expect_err("forged local mirror proof must block delete plan");

        assert!(matches!(
            error,
            WorkflowError::ProofMismatch {
                proof_key: "icloudpd_local_mirror",
                field: actual,
                ..
            } if actual == field
        ));
    }
}

#[test]
fn delete_plan_revalidates_conversion_performance_sizes() {
    let cases = [
        ("raw_size_bytes", json!(41)),
        ("heic_size_bytes", json!(25)),
    ];

    for (field, value) in cases {
        let (_tempdir, manifest) = forged_delete_approved_manifest(|record| {
            proof_mut(record, "conversion_performance")[field] = value;
        });

        let error = build_delete_plan(&manifest, "asset-1")
            .expect_err("forged conversion performance sizes must block delete plan");

        assert!(matches!(
            error,
            WorkflowError::ProofMismatch {
                proof_key: "conversion_performance",
                field: actual,
                ..
            } if actual == field
        ));
    }
}

#[test]
fn delete_plan_revalidates_source_age_freshness() {
    let (_tempdir, manifest) = forged_delete_approved_manifest(|record| {
        proof_mut(record, "source_age")["source_captured_unix_seconds"] =
            json!(SOURCE_AGE_VERIFIED_AT - 10 * DAY);
    });

    let error = build_delete_plan(&manifest, "asset-1")
        .expect_err("too-new persisted source age must block delete plan");

    assert!(matches!(
        error,
        WorkflowError::SourceAgeTooNew {
            age_seconds,
            min_age_seconds,
            ..
        } if age_seconds == 10 * DAY && min_age_seconds == 30 * DAY
    ));
}

#[test]
fn delete_plan_rejects_forged_source_age_minimum_below_floor() {
    let (_tempdir, manifest) = forged_delete_approved_manifest(|record| {
        proof_mut(record, "source_age")["min_age_seconds"] = json!(0);
    });

    let error = build_delete_plan(&manifest, "asset-1")
        .expect_err("forged source age minimum must block delete plan");

    assert!(matches!(
        error,
        WorkflowError::MinAgeBelowSafetyFloor {
            requested_seconds: 0,
            minimum_seconds,
            ..
        } if minimum_seconds == 30 * DAY
    ));
}

#[test]
fn delete_plan_rejects_malformed_persisted_nas_proof() {
    let (_tempdir, manifest) = forged_delete_approved_manifest(|record| {
        proof_mut(record, "nas")["size_bytes"] = json!("42");
    });

    let error = build_delete_plan(&manifest, "asset-1")
        .expect_err("malformed persisted NAS proof must block delete plan");

    assert!(matches!(
        error,
        WorkflowError::ProofDecode {
            proof_key: "nas",
            ..
        }
    ));
}

#[test]
fn delete_plan_rejects_empty_persisted_nas_identity_fields() {
    let cases = [
        ("canonical_path", json!("")),
        ("relative_path", json!("")),
        ("sha256", json!("  ")),
    ];

    for (field, value) in cases {
        let (_tempdir, manifest) = forged_delete_approved_manifest(|record| {
            proof_mut(record, "nas")[field] = value;
        });

        let error = build_delete_plan(&manifest, "asset-1")
            .expect_err("empty persisted NAS proof fields must block delete plan");

        assert!(matches!(
            error,
            WorkflowError::EmptyProofField { field: actual } if actual == field
        ));
    }
}

#[test]
fn delete_plan_rejects_non_positive_persisted_nas_size() {
    let (_tempdir, manifest) = forged_delete_approved_manifest(|record| {
        proof_mut(record, "nas")["size_bytes"] = json!(0);
    });

    let error = build_delete_plan(&manifest, "asset-1")
        .expect_err("zero-byte persisted NAS proof must block delete plan");

    assert!(matches!(
        error,
        WorkflowError::InvalidProofField {
            proof_key: "nas",
            field: "size_bytes",
            ..
        }
    ));
}

#[test]
fn delete_plan_rejects_too_new_persisted_nas_proof() {
    let (_tempdir, manifest) = forged_delete_approved_manifest(|record| {
        proof_mut(record, "nas")["age_seconds"] = json!(10 * DAY);
    });

    let error = build_delete_plan(&manifest, "asset-1")
        .expect_err("too-new persisted NAS proof must block delete plan");

    assert!(matches!(
        error,
        WorkflowError::NasProofTooNew {
            age_seconds,
            min_age_seconds,
            ..
        } if age_seconds == 10 * DAY && min_age_seconds == 30 * DAY
    ));
}

#[test]
fn delete_plan_rejects_persisted_nas_path_that_does_not_match_raw_path() {
    let (_tempdir, manifest) = forged_delete_approved_manifest(|record| {
        proof_mut(record, "nas")["canonical_path"] = json!("/nas/photos/other.dng");
    });

    let error = build_delete_plan(&manifest, "asset-1")
        .expect_err("NAS proof for a different RAW must block delete plan");

    assert!(matches!(
        error,
        WorkflowError::ProofMismatch {
            proof_key: "nas",
            field: "canonical_path",
            ..
        }
    ));
}

#[test]
fn delete_plan_reproves_nas_raw_and_rejects_changed_bytes_after_approval() {
    let (_tempdir, manifest, raw_path) = real_delete_approved_manifest();
    let stored_modified =
        manifest.get("asset-1").expect("asset should exist").proofs["nas"]["modified_unix_seconds"]
            .as_u64()
            .expect("stored mtime should be a u64");
    fs::write(&raw_path, b"new-bytes-that-are-larger-than-heic").expect("raw bytes should mutate");
    set_raw_mtime(&raw_path, stored_modified);

    let error = build_delete_plan(&manifest, "asset-1")
        .expect_err("changed NAS bytes must block delete plan");

    assert!(matches!(
        error,
        WorkflowError::ProofMismatch {
            proof_key: "nas",
            field: "sha256",
            ..
        }
    ));
}

#[test]
fn delete_plan_rejects_nas_relative_path_that_cannot_derive_root() {
    let (_tempdir, manifest) = forged_delete_approved_manifest(|record| {
        proof_mut(record, "nas")["relative_path"] = json!("other/IMG_0001.dng");
    });

    let error = build_delete_plan(&manifest, "asset-1")
        .expect_err("malformed NAS relative path must block delete plan");

    assert!(matches!(
        error,
        WorkflowError::InvalidProofField {
            proof_key: "nas",
            field: "relative_path",
            ..
        }
    ));
}

#[test]
fn delete_plan_revalidates_delete_eligibility_against_current_facts() {
    let (_tempdir, manifest) = forged_delete_approved_manifest(|record| {
        proof_mut(record, "delete_eligibility")["uploaded_heic_sha256"] =
            json!("stale-heic-sha256");
    });

    let error = build_delete_plan(&manifest, "asset-1")
        .expect_err("stale delete eligibility proof must block delete plan");

    assert!(matches!(
        error,
        WorkflowError::ProofMismatch {
            proof_key: "delete_eligibility",
            field: "uploaded_heic_sha256",
            ..
        }
    ));
}

#[test]
fn delete_plan_rejects_malformed_persisted_upload_proof() {
    let (_tempdir, manifest) = forged_delete_approved_manifest(|record| {
        proof_mut(record, "upload")["uploaded_heic_sha256"] = json!(42);
    });

    let error = build_delete_plan(&manifest, "asset-1")
        .expect_err("malformed persisted upload proof must block delete plan");

    assert!(matches!(
        error,
        WorkflowError::ProofDecode {
            proof_key: "upload",
            ..
        }
    ));
}

#[test]
fn skip_attempts_fail_without_mutating_manifest() {
    let mut manifest = Manifest::new();
    manifest.upsert(AssetRecord::new(
        "asset-1",
        PathBuf::from("/nas/photos/IMG_0001.dng"),
    ));
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    record_conversion_result(&mut manifest, "asset-1", conversion_proof())
        .expect_err("conversion cannot skip NAS proof");

    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
}

#[test]
fn failure_records_block_delete_eligibility() {
    let mut manifest = Manifest::new();
    discover_raw_asset(&mut manifest, "asset-1", "/nas/photos/IMG_0001.dng")
        .expect("asset should be discovered");
    record_nas_proof(&mut manifest, "asset-1", nas_proof()).expect("nas proof should record");

    record_stage_failure(&mut manifest, "asset-1", "conversion", "vips exited 1")
        .expect("failure should record");
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    mark_delete_eligible(&mut manifest, "asset-1")
        .expect_err("failed asset cannot become delete eligible");

    let after = manifest.get("asset-1").expect("asset should exist");
    assert_eq!(after, &before);
    assert_eq!(after.state, State::Failed);
    assert_eq!(after.failures[0].stage, "conversion");
    assert!(!after.proofs.contains_key("delete_eligibility"));
}

#[test]
fn typed_stage_failure_persists_its_stable_kind() {
    let mut manifest = Manifest::new();
    discover_raw_asset(&mut manifest, "asset-1", "/nas/photos/IMG_0001.dng")
        .expect("asset should be discovered");
    record_nas_proof(&mut manifest, "asset-1", nas_proof()).expect("NAS proof should record");

    record_stage_failure_with_kind(
        &mut manifest,
        "asset-1",
        "conversion",
        "converted output is missing or unreadable",
        FailureKind::ConversionOutputUnreadable,
    )
    .expect("typed failure should record");

    assert_eq!(
        manifest
            .get("asset-1")
            .expect("asset should remain")
            .failures[0]
            .kind,
        Some(FailureKind::ConversionOutputUnreadable)
    );
}

#[test]
fn upload_proof_records_heic_identity_for_future_skip() {
    let mut manifest = conversion_verified_manifest();

    record_upload_proof(&mut manifest, "asset-1", upload_proof())
        .expect("upload proof should record");

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
    assert_eq!(
        record.proofs["upload"]["uploaded_heic_path"],
        "/staging/IMG_0001.heic"
    );
}

#[test]
fn uploaded_heic_delete_request_uses_uploaded_asset_and_heic_hash() {
    let manifest = upload_verified_manifest();

    let request = uploaded_heic_delete_request(&manifest, "asset-1")
        .expect("uploaded HEIC delete request should build from upload proof");

    assert_eq!(request.uploaded_asset_id, "icloud-heic-asset-1");
    assert_eq!(request.expected_heic_sha256, "heic-sha256");
    assert_eq!(request.expected_size_bytes, 24);
}

#[test]
fn uploaded_heic_delete_request_rejects_original_asset_target() {
    let mut manifest = upload_verified_manifest();
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    proof_mut(&mut record, "upload")["uploaded_heic_asset_id"] = json!("original-record-1");
    manifest.upsert(record);

    let error = uploaded_heic_delete_request(&manifest, "asset-1")
        .expect_err("uploaded HEIC delete must not target original RAW asset");

    assert!(matches!(
        error,
        WorkflowError::InvalidProofField {
            proof_key: "upload",
            field: "uploaded_heic_asset_id",
            ..
        }
    ));
}

#[test]
fn uploaded_heic_delete_records_repair_proof_without_changing_deleted_state() {
    let (_tempdir, mut manifest, _) = real_delete_approved_manifest();
    record_delete_execution(&mut manifest, "asset-1", delete_outcome())
        .expect("original delete should record");

    let record = record_uploaded_heic_delete(
        &mut manifest,
        "asset-1",
        uploaded_heic_asset(),
        uploaded_heic_delete_outcome(),
    )
    .expect("uploaded HEIC repair delete proof should record");

    assert_eq!(record.state, State::Deleted);
    assert_eq!(
        record.proofs["uploaded_heic_delete"]["uploaded_heic_asset_id"],
        "icloud-heic-asset-1"
    );
    assert_eq!(
        record.proofs["uploaded_heic_delete"]["deleted_record_name"],
        "icloud-heic-asset-1"
    );
    assert_eq!(
        record.proofs["uploaded_heic_delete"]["matched_heic_sha256"],
        "heic-sha256"
    );
    assert_eq!(
        record.proofs["uploaded_heic_delete"]["confirmed_deleted_change_tag"],
        "uploaded-deleted-change-tag"
    );
}

#[test]
fn uploaded_heic_delete_rejects_mismatched_deleted_record_without_mutation() {
    let mut manifest = upload_verified_manifest();
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = record_uploaded_heic_delete(
        &mut manifest,
        "asset-1",
        uploaded_heic_asset(),
        CloudKitDeleteOutcome {
            record_name: "other-uploaded-heic".to_string(),
            record_change_tag: "uploaded-deleted-change-tag".to_string(),
        },
    )
    .expect_err("delete outcome must match uploaded HEIC asset");

    assert!(matches!(
        error,
        WorkflowError::ProofMismatch {
            proof_key: "uploaded_heic_delete",
            field: "deleted_record_name",
            ..
        }
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
}

#[test]
fn heic_verification_must_match_conversion_path_hash_and_size_without_mutation() {
    let cases = [
        (
            "heic_path",
            HeicVerificationInput {
                heic_path: PathBuf::from("/other/IMG_0001.heic"),
                ..heic_proof()
            },
        ),
        (
            "heic_sha256",
            HeicVerificationInput {
                heic_sha256: "other-heic-sha256".to_string(),
                ..heic_proof()
            },
        ),
        (
            "size_bytes",
            HeicVerificationInput {
                size_bytes: 25,
                ..heic_proof()
            },
        ),
    ];

    for (field, proof) in cases {
        let mut manifest = conversion_performance_manifest();
        let before = manifest.get("asset-1").expect("asset should exist").clone();

        let error = record_heic_verification(&mut manifest, "asset-1", proof)
            .expect_err("HEIC proof must bind to conversion proof");

        assert!(matches!(
            error,
            WorkflowError::ProofMismatch {
                proof_key: "conversion",
                field: actual,
                ..
            } if actual == field
        ));
        assert_eq!(
            manifest.get("asset-1").expect("asset should exist"),
            &before
        );
    }
}

#[test]
fn heic_verification_requires_conversion_performance_without_mutation() {
    let mut manifest = converted_manifest();
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = record_heic_verification(&mut manifest, "asset-1", heic_proof())
        .expect_err("conversion performance proof is required before HEIC verification");

    assert!(matches!(
        error,
        WorkflowError::MissingProof {
            proof_key,
            ..
        } if proof_key == "conversion_performance"
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
    assert!(!before.proofs.contains_key("heic"));
}

#[test]
fn conversion_performance_records_derived_sizes_and_metrics() {
    let mut manifest = converted_manifest();

    let record =
        record_conversion_performance(&mut manifest, "asset-1", conversion_performance_input())
            .expect("conversion performance should record");

    assert_eq!(record.state, State::Converted);
    let proof = &record.proofs["conversion_performance"];
    assert_eq!(proof["schema_version"], 1);
    assert_eq!(proof["measured_at_unix_seconds"], 1_800_000_100);
    assert_eq!(proof["measurement_method"], "monotonic_wall_clock");
    assert_eq!(proof["conversion_tool"], "magick");
    assert_eq!(proof["conversion_tool_version"], "7.1.1-41");
    assert_eq!(
        proof["conversion_recipe_id"],
        "embedded-preview-normalized-v1"
    );
    assert_eq!(proof["heic_quality"], 90);
    assert_eq!(proof["raw_size_bytes"], 42);
    assert_eq!(proof["heic_size_bytes"], 24);
    assert_eq!(proof["convert_wall_time_millis"], 1_250);
    assert_eq!(proof["total_wall_time_millis"], 1_500);
    assert_eq!(proof["user_cpu_time_millis"], 1_100);
    assert_eq!(proof["system_cpu_time_millis"], 90);
    assert_eq!(proof["peak_rss_kib"], 256_000);
    assert!(proof.get("conversion_command_timings").is_none());
}

#[test]
fn conversion_performance_records_ordered_command_timings() {
    let mut manifest = converted_manifest();

    let record = record_conversion_performance(
        &mut manifest,
        "asset-1",
        ConversionPerformanceInput {
            conversion_command_timings: vec![
                ConversionCommandTiming {
                    program: "dcraw_emu".to_string(),
                    wall_time_millis: 4_888,
                },
                ConversionCommandTiming {
                    program: "magick".to_string(),
                    wall_time_millis: 29_267,
                },
                ConversionCommandTiming {
                    program: "heif-enc".to_string(),
                    wall_time_millis: 80_798,
                },
            ],
            ..conversion_performance_input()
        },
    )
    .expect("conversion performance should record command timings");

    assert_eq!(
        record.proofs["conversion_performance"]["conversion_command_timings"],
        json!([
            {
                "program": "dcraw_emu",
                "wall_time_millis": 4_888
            },
            {
                "program": "magick",
                "wall_time_millis": 29_267
            },
            {
                "program": "heif-enc",
                "wall_time_millis": 80_798
            }
        ])
    );
}

#[test]
fn conversion_performance_is_frozen_after_conversion_verified_without_mutation() {
    let mut manifest = conversion_verified_manifest();
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = record_conversion_performance(
        &mut manifest,
        "asset-1",
        ConversionPerformanceInput {
            measured_at_unix_seconds: 1_900_000_000,
            conversion_tool: "other-tool".to_string(),
            convert_wall_time_millis: 2_500,
            total_wall_time_millis: 3_000,
            ..conversion_performance_input()
        },
    )
    .expect_err("conversion performance proof must freeze after HEIC verification");

    assert!(matches!(
        error,
        WorkflowError::Manifest(ManifestError::InvalidTransition {
            from: State::ConversionVerified,
            to: State::Converted,
            ..
        })
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
}

#[test]
fn invalid_conversion_performance_metrics_fail_without_mutation() {
    let cases = [
        (
            "convert_wall_time_millis",
            ConversionPerformanceInput {
                convert_wall_time_millis: 0,
                ..conversion_performance_input()
            },
        ),
        (
            "total_wall_time_millis",
            ConversionPerformanceInput {
                convert_wall_time_millis: 1_250,
                total_wall_time_millis: 1_000,
                ..conversion_performance_input()
            },
        ),
        (
            "conversion_tool",
            ConversionPerformanceInput {
                conversion_tool: "  ".to_string(),
                ..conversion_performance_input()
            },
        ),
        (
            "conversion_tool_version",
            ConversionPerformanceInput {
                conversion_tool_version: Some("  ".to_string()),
                ..conversion_performance_input()
            },
        ),
        (
            "heic_quality",
            ConversionPerformanceInput {
                heic_quality: 0,
                ..conversion_performance_input()
            },
        ),
        (
            "heic_quality",
            ConversionPerformanceInput {
                heic_quality: 101,
                ..conversion_performance_input()
            },
        ),
        (
            "conversion_command_timings.program",
            ConversionPerformanceInput {
                conversion_command_timings: vec![ConversionCommandTiming {
                    program: "  ".to_string(),
                    wall_time_millis: 1,
                }],
                ..conversion_performance_input()
            },
        ),
        (
            "conversion_command_timings.wall_time_millis",
            ConversionPerformanceInput {
                conversion_command_timings: vec![ConversionCommandTiming {
                    program: "magick".to_string(),
                    wall_time_millis: 0,
                }],
                ..conversion_performance_input()
            },
        ),
    ];

    for (field, input) in cases {
        let mut manifest = converted_manifest();
        let before = manifest.get("asset-1").expect("asset should exist").clone();

        let error = record_conversion_performance(&mut manifest, "asset-1", input)
            .expect_err("invalid conversion performance metrics must fail closed");

        if matches!(
            field,
            "conversion_tool" | "conversion_tool_version" | "conversion_command_timings.program"
        ) {
            assert!(matches!(
                error,
                WorkflowError::EmptyProofField { field: actual } if actual == field
            ));
        } else {
            assert!(matches!(
                error,
                WorkflowError::InvalidProofField {
                    proof_key: "conversion_performance",
                    field: actual,
                    ..
                } if actual == field
            ));
        }
        assert_eq!(
            manifest.get("asset-1").expect("asset should exist"),
            &before
        );
        assert!(!before.proofs.contains_key("conversion_performance"));
    }
}

#[test]
fn heic_verification_requires_visual_proofs_without_mutation() {
    let cases = [
        (
            "visual_content_ok",
            HeicVerificationInput {
                visual_content_ok: false,
                ..heic_proof()
            },
        ),
        (
            "visual_match_ok",
            HeicVerificationInput {
                visual_match_ok: false,
                ..heic_proof()
            },
        ),
    ];

    for (field, proof) in cases {
        let mut manifest = conversion_performance_manifest();
        let before = manifest.get("asset-1").expect("asset should exist").clone();

        let error = record_heic_verification(&mut manifest, "asset-1", proof)
            .expect_err("visual validation is required before conversion verification");

        assert!(matches!(
            error,
            WorkflowError::HeicVerificationFailed {
                field: actual
            } if actual == field
        ));
        assert_eq!(
            manifest.get("asset-1").expect("asset should exist"),
            &before
        );
    }
}

#[test]
fn upload_ready_revalidates_visual_proofs() {
    let mut manifest = conversion_verified_manifest();
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    proof_mut(&mut record, "heic")["visual_match_ok"] = json!(false);
    manifest.upsert(record);

    let error = upload_ready_heic_proof(&manifest, "asset-1")
        .expect_err("forged visual proof must not be upload-ready");

    assert!(matches!(
        error,
        WorkflowError::HeicVerificationFailed {
            field: "visual_match_ok"
        }
    ));
}

#[test]
fn upload_ready_rejects_legacy_raw_sensor_render_conversion_tool() {
    let mut manifest = conversion_verified_manifest();
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    proof_mut(&mut record, "conversion_performance")["conversion_tool"] =
        json!("dcraw_emu+magick+heif-enc");
    manifest.upsert(record);

    let error = upload_ready_heic_proof(&manifest, "asset-1")
        .expect_err("legacy raw sensor render must not be upload-ready");

    assert!(matches!(
        error,
        WorkflowError::InvalidProofField {
            proof_key: "conversion_performance",
            field: "conversion_tool",
            ..
        }
    ));
}

#[test]
fn upload_ready_requires_conversion_performance_proof() {
    let mut manifest = conversion_verified_manifest();
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    record.proofs.remove("conversion_performance");
    manifest.upsert(record);

    let error = upload_ready_heic_proof(&manifest, "asset-1")
        .expect_err("legacy conversion verification without performance must not be upload-ready");

    assert!(matches!(
        error,
        WorkflowError::MissingProof {
            proof_key,
            ..
        } if proof_key == "conversion_performance"
    ));
}

#[test]
fn upload_proof_requires_conversion_performance_without_mutation() {
    let mut manifest = conversion_verified_manifest();
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    record.proofs.remove("conversion_performance");
    manifest.upsert(record);
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = record_upload_proof(&mut manifest, "asset-1", upload_proof())
        .expect_err("upload proof must require conversion performance proof");

    assert!(matches!(
        error,
        WorkflowError::MissingProof {
            proof_key,
            ..
        } if proof_key == "conversion_performance"
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
    assert!(!before.proofs.contains_key("upload"));
}

#[test]
fn upload_proof_must_match_heic_hash_and_path_without_mutation() {
    let cases = [
        (
            "uploaded_heic_sha256",
            UploadProof {
                uploaded_heic_sha256: "other-heic-sha256".to_string(),
                ..upload_proof()
            },
        ),
        (
            "uploaded_heic_path",
            UploadProof {
                uploaded_heic_path: Some(PathBuf::from("/other/IMG_0001.heic")),
                ..upload_proof()
            },
        ),
    ];

    for (field, proof) in cases {
        let mut manifest = conversion_verified_manifest();
        let before = manifest.get("asset-1").expect("asset should exist").clone();

        let error = record_upload_proof(&mut manifest, "asset-1", proof)
            .expect_err("upload proof must bind to verified HEIC proof");

        assert!(matches!(
            error,
            WorkflowError::ProofMismatch {
                proof_key: "heic",
                field: actual,
                ..
            } if actual == field
        ));
        assert_eq!(
            manifest.get("asset-1").expect("asset should exist"),
            &before
        );
    }
}

#[test]
fn upload_proof_requires_uploaded_path_without_mutation() {
    let mut manifest = conversion_verified_manifest();
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = record_upload_proof(
        &mut manifest,
        "asset-1",
        UploadProof {
            uploaded_heic_path: None,
            ..upload_proof()
        },
    )
    .expect_err("upload proof must include the uploaded HEIC path");

    assert!(matches!(
        error,
        WorkflowError::EmptyProofField {
            field: "uploaded_heic_path"
        }
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
}

#[test]
fn icloudpd_local_mirror_proof_records_uploaded_heic_download_identity() {
    let mut manifest = source_age_verified_manifest();
    record_upload_proof(&mut manifest, "asset-1", upload_proof())
        .expect("upload proof should record");

    let record = record_icloudpd_local_mirror_proof(&mut manifest, "asset-1", local_mirror_proof())
        .expect("local mirror proof should record");

    assert_eq!(record.state, State::UploadVerified);
    assert_eq!(
        record.proofs["icloudpd_local_mirror"]["uploaded_heic_asset_id"],
        "icloud-heic-asset-1"
    );
    assert_eq!(
        record.proofs["icloudpd_local_mirror"]["uploaded_heic_sha256"],
        "heic-sha256"
    );
    assert_eq!(
        record.proofs["icloudpd_local_mirror"]["uploaded_heic_path"],
        "/staging/IMG_0001.heic"
    );
    assert_eq!(
        record.proofs["icloudpd_local_mirror"]["icloudpd_download_path"],
        "/PrimarySync/IMG_0001.HEIC"
    );
    assert_eq!(record.proofs["icloudpd_local_mirror"]["size_bytes"], 24);
}

#[test]
fn icloudpd_local_mirror_proof_validates_upload_and_heic_binding_without_mutation() {
    let cases = [
        (
            "uploaded_heic_asset_id",
            IcloudpdLocalMirrorProof {
                uploaded_heic_asset_id: "other-heic-asset".to_string(),
                ..local_mirror_proof()
            },
        ),
        (
            "uploaded_heic_sha256",
            IcloudpdLocalMirrorProof {
                uploaded_heic_sha256: "other-heic-sha256".to_string(),
                ..local_mirror_proof()
            },
        ),
        (
            "uploaded_heic_path",
            IcloudpdLocalMirrorProof {
                uploaded_heic_path: PathBuf::from("/other/IMG_0001.heic"),
                ..local_mirror_proof()
            },
        ),
        (
            "size_bytes",
            IcloudpdLocalMirrorProof {
                size_bytes: 25,
                ..local_mirror_proof()
            },
        ),
    ];

    for (field, proof) in cases {
        let mut manifest = source_age_verified_manifest();
        record_upload_proof(&mut manifest, "asset-1", upload_proof())
            .expect("upload proof should record");
        let before = manifest.get("asset-1").expect("asset should exist").clone();

        let error = record_icloudpd_local_mirror_proof(&mut manifest, "asset-1", proof)
            .expect_err("mirror proof must bind to verified upload facts");

        assert!(matches!(
            error,
            WorkflowError::ProofMismatch {
                proof_key: "icloudpd_local_mirror",
                field: actual,
                ..
            } if actual == field
        ));
        assert_eq!(
            manifest.get("asset-1").expect("asset should exist"),
            &before
        );
        assert!(!before.proofs.contains_key("icloudpd_local_mirror"));
    }
}

#[test]
fn icloudpd_local_mirror_proof_rejects_empty_download_path_without_mutation() {
    let mut manifest = source_age_verified_manifest();
    record_upload_proof(&mut manifest, "asset-1", upload_proof())
        .expect("upload proof should record");
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = record_icloudpd_local_mirror_proof(
        &mut manifest,
        "asset-1",
        IcloudpdLocalMirrorProof {
            icloudpd_download_path: PathBuf::new(),
            ..local_mirror_proof()
        },
    )
    .expect_err("download path is required");

    assert!(matches!(
        error,
        WorkflowError::EmptyProofField {
            field: "icloudpd_download_path"
        }
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
}

#[test]
fn delete_eligibility_requires_conversion_performance_without_mutation() {
    let mut manifest = upload_verified_manifest();
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    record.proofs.remove("conversion_performance");
    manifest.upsert(record);
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = mark_delete_eligible(&mut manifest, "asset-1")
        .expect_err("delete eligibility must require conversion performance proof");

    assert!(matches!(
        error,
        WorkflowError::MissingProof {
            proof_key,
            ..
        } if proof_key == "conversion_performance"
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
    assert!(!before.proofs.contains_key("delete_eligibility"));
}

#[test]
fn delete_eligibility_requires_icloudpd_local_mirror_without_mutation() {
    let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    record.proofs.remove("icloudpd_local_mirror");
    manifest.upsert(record);
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = mark_delete_eligible(&mut manifest, "asset-1")
        .expect_err("delete eligibility must require local iCloudPD mirror proof");

    assert!(matches!(
        error,
        WorkflowError::MissingProof {
            proof_key,
            ..
        } if proof_key == "icloudpd_local_mirror"
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
    assert!(!before.proofs.contains_key("delete_eligibility"));
}

#[test]
fn delete_eligibility_records_icloudpd_local_mirror_binding() {
    let (_tempdir, mut manifest, _) = real_upload_verified_manifest();

    mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");

    let record = manifest.get("asset-1").expect("asset should exist");
    assert_eq!(
        record.proofs["delete_eligibility"]["icloudpd_local_mirror_proof_key"],
        "icloudpd_local_mirror"
    );
    assert_eq!(
        record.proofs["delete_eligibility"]["icloudpd_download_path"],
        "/PrimarySync/IMG_0001.HEIC"
    );
    assert_eq!(
        record.proofs["delete_eligibility"]["mirrored_heic_sha256"],
        "heic-sha256"
    );
    assert_eq!(
        record.proofs["delete_eligibility"]["mirrored_size_bytes"],
        24
    );
}

#[test]
fn icloudpd_local_mirror_proof_repairs_existing_delete_states() {
    for approved in [false, true] {
        let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
        mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
        if approved {
            approve_delete(&mut manifest, "asset-1", "operator").expect("approval should record");
        }
        let mut record = manifest.get("asset-1").expect("asset should exist").clone();
        record.proofs.remove("icloudpd_local_mirror");
        let eligibility = proof_mut(&mut record, "delete_eligibility")
            .as_object_mut()
            .expect("eligibility proof should be an object");
        eligibility.remove("icloudpd_local_mirror_proof_key");
        eligibility.remove("icloudpd_download_path");
        eligibility.remove("mirrored_heic_sha256");
        eligibility.remove("mirrored_size_bytes");
        manifest.upsert(record);

        record_icloudpd_local_mirror_proof(&mut manifest, "asset-1", local_mirror_proof())
            .expect("recording mirror proof should repair legacy delete state");

        let record = manifest.get("asset-1").expect("asset should exist");
        assert_eq!(
            record.state,
            if approved {
                State::DeleteApproved
            } else {
                State::DeleteEligible
            }
        );
        assert_eq!(
            record.proofs["delete_eligibility"]["icloudpd_local_mirror_proof_key"],
            "icloudpd_local_mirror"
        );
        assert!(record.proofs.contains_key("icloudpd_local_mirror"));
        if approved {
            build_delete_plan(&manifest, "asset-1").expect("repaired approved record should plan");
        }
    }
}

#[test]
fn delete_eligibility_revalidates_conversion_performance_without_mutation() {
    let mut manifest = upload_verified_manifest();
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    proof_mut(&mut record, "conversion_performance")["raw_size_bytes"] = json!(41);
    manifest.upsert(record);
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = mark_delete_eligible(&mut manifest, "asset-1")
        .expect_err("delete eligibility must revalidate conversion performance proof");

    assert!(matches!(
        error,
        WorkflowError::ProofMismatch {
            proof_key: "conversion_performance",
            field: "raw_size_bytes",
            ..
        }
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
    assert!(!before.proofs.contains_key("delete_eligibility"));
}

#[test]
fn delete_eligibility_revalidates_heic_identity_without_mutation() {
    let cases = [
        ("heic_path", json!("/other/IMG_0001.heic")),
        ("heic_sha256", json!("other-heic-sha256")),
        ("size_bytes", json!(25)),
    ];

    for (field, value) in cases {
        let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
        let mut record = manifest.get("asset-1").expect("asset should exist").clone();
        proof_mut(&mut record, "heic")[field] = value;
        manifest.upsert(record);
        let before = manifest.get("asset-1").expect("asset should exist").clone();

        let error = mark_delete_eligible(&mut manifest, "asset-1")
            .expect_err("forged HEIC proof must block delete eligibility");

        assert!(matches!(
            error,
            WorkflowError::ProofMismatch {
                proof_key: "conversion",
                field: actual,
                ..
            } if actual == field
        ));
        assert_eq!(
            manifest.get("asset-1").expect("asset should exist"),
            &before
        );
        assert!(!before.proofs.contains_key("delete_eligibility"));
    }
}

#[test]
fn delete_eligibility_revalidates_upload_binding_without_mutation() {
    let cases = [
        ("uploaded_heic_sha256", json!("other-heic-sha256")),
        ("uploaded_heic_path", json!("/other/IMG_0001.heic")),
    ];

    for (field, value) in cases {
        let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
        let mut record = manifest.get("asset-1").expect("asset should exist").clone();
        proof_mut(&mut record, "upload")[field] = value;
        manifest.upsert(record);
        let before = manifest.get("asset-1").expect("asset should exist").clone();

        let error = mark_delete_eligible(&mut manifest, "asset-1")
            .expect_err("forged upload proof must block delete eligibility");

        assert!(matches!(
            error,
            WorkflowError::ProofMismatch {
                proof_key: "heic",
                field: actual,
                ..
            } if actual == field
        ));
        assert_eq!(
            manifest.get("asset-1").expect("asset should exist"),
            &before
        );
        assert!(!before.proofs.contains_key("delete_eligibility"));
    }
}

#[test]
fn delete_eligibility_revalidates_nas_size_without_mutation() {
    let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    proof_mut(&mut record, "nas")["size_bytes"] = json!(43);
    proof_mut(&mut record, "conversion_performance")["raw_size_bytes"] = json!(43);
    manifest.upsert(record);
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = mark_delete_eligible(&mut manifest, "asset-1")
        .expect_err("forged NAS size must block delete eligibility");

    assert!(matches!(
        error,
        WorkflowError::ProofMismatch {
            proof_key: "nas",
            field: "size_bytes",
            ..
        }
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
    assert!(!before.proofs.contains_key("delete_eligibility"));
}

#[test]
fn delete_eligibility_uses_bounded_stored_proofs_without_live_nas_reproof() {
    let (_tempdir, mut manifest, raw_path) = real_upload_verified_manifest();
    let stored_modified =
        manifest.get("asset-1").expect("asset should exist").proofs["nas"]["modified_unix_seconds"]
            .as_u64()
            .expect("stored mtime should be a u64");
    fs::write(&raw_path, b"new-bytes-that-are-larger-than-heic").expect("raw bytes should mutate");
    set_raw_mtime(&raw_path, stored_modified);

    let record = mark_delete_eligible(&mut manifest, "asset-1")
        .expect("delete eligibility should use only the bounded stored proof chain");

    assert_eq!(record.state, State::DeleteEligible);
    assert!(record.proofs.contains_key("delete_eligibility"));
}

#[test]
fn delete_eligibility_revalidates_source_age_without_mutation() {
    let cases = [
        (
            "source_captured_unix_seconds",
            json!(SOURCE_AGE_VERIFIED_AT - 10 * DAY),
        ),
        ("min_age_seconds", json!(0)),
    ];

    for (field, value) in cases {
        let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
        let mut record = manifest.get("asset-1").expect("asset should exist").clone();
        proof_mut(&mut record, "source_age")[field] = value;
        manifest.upsert(record);
        let before = manifest.get("asset-1").expect("asset should exist").clone();

        let error = mark_delete_eligible(&mut manifest, "asset-1")
            .expect_err("forged source age proof must block delete eligibility");

        if field == "source_captured_unix_seconds" {
            assert!(matches!(
                error,
                WorkflowError::SourceAgeTooNew {
                    age_seconds,
                    min_age_seconds,
                    ..
                } if age_seconds == 10 * DAY && min_age_seconds == 30 * DAY
            ));
        } else {
            assert!(matches!(
                error,
                WorkflowError::MinAgeBelowSafetyFloor {
                    requested_seconds: 0,
                    minimum_seconds,
                    ..
                } if minimum_seconds == 30 * DAY
            ));
        }
        assert_eq!(
            manifest.get("asset-1").expect("asset should exist"),
            &before
        );
        assert!(!before.proofs.contains_key("delete_eligibility"));
    }
}

#[test]
fn delete_approval_requires_conversion_performance_without_mutation() {
    let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
    mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    record.proofs.remove("conversion_performance");
    manifest.upsert(record);
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = approve_delete(&mut manifest, "asset-1", "operator")
        .expect_err("delete approval must require conversion performance proof");

    assert!(matches!(
        error,
        WorkflowError::MissingProof {
            proof_key,
            ..
        } if proof_key == "conversion_performance"
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
    assert!(!before.proofs.contains_key("delete_approval"));
}

#[test]
fn delete_approval_revalidates_conversion_performance_without_mutation() {
    let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
    mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    proof_mut(&mut record, "conversion_performance")["heic_size_bytes"] = json!(25);
    manifest.upsert(record);
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = approve_delete(&mut manifest, "asset-1", "operator")
        .expect_err("delete approval must revalidate conversion performance proof");

    assert!(matches!(
        error,
        WorkflowError::ProofMismatch {
            proof_key: "conversion_performance",
            field: "heic_size_bytes",
            ..
        }
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
    assert!(!before.proofs.contains_key("delete_approval"));
}

#[test]
fn delete_approval_revalidates_heic_identity_without_mutation() {
    let cases = [
        ("visual_content_ok", json!(false)),
        ("heic_sha256", json!("other-heic-sha256")),
    ];

    for (field, value) in cases {
        let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
        mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
        let mut record = manifest.get("asset-1").expect("asset should exist").clone();
        proof_mut(&mut record, "heic")[field] = value;
        manifest.upsert(record);
        let before = manifest.get("asset-1").expect("asset should exist").clone();

        let error = approve_delete(&mut manifest, "asset-1", "operator")
            .expect_err("forged HEIC proof must block delete approval");

        if field == "visual_content_ok" {
            assert!(matches!(
                error,
                WorkflowError::HeicVerificationFailed {
                    field: "visual_content_ok"
                }
            ));
        } else {
            assert!(matches!(
                error,
                WorkflowError::ProofMismatch {
                    proof_key: "conversion",
                    field: "heic_sha256",
                    ..
                }
            ));
        }
        assert_eq!(
            manifest.get("asset-1").expect("asset should exist"),
            &before
        );
        assert!(!before.proofs.contains_key("delete_approval"));
    }
}

#[test]
fn delete_approval_revalidates_upload_binding_without_mutation() {
    let cases = [
        ("uploaded_heic_sha256", json!("other-heic-sha256")),
        ("uploaded_heic_path", json!("/other/IMG_0001.heic")),
    ];

    for (field, value) in cases {
        let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
        mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
        let mut record = manifest.get("asset-1").expect("asset should exist").clone();
        proof_mut(&mut record, "upload")[field] = value;
        manifest.upsert(record);
        let before = manifest.get("asset-1").expect("asset should exist").clone();

        let error = approve_delete(&mut manifest, "asset-1", "operator")
            .expect_err("forged upload proof must block delete approval");

        assert!(matches!(
            error,
            WorkflowError::ProofMismatch {
                proof_key: "heic",
                field: actual,
                ..
            } if actual == field
        ));
        assert_eq!(
            manifest.get("asset-1").expect("asset should exist"),
            &before
        );
        assert!(!before.proofs.contains_key("delete_approval"));
    }
}

#[test]
fn delete_approval_revalidates_icloudpd_local_mirror_without_mutation() {
    let cases = [
        ("uploaded_heic_asset_id", json!("other-heic-asset")),
        ("uploaded_heic_sha256", json!("other-heic-sha256")),
        ("uploaded_heic_path", json!("/other/IMG_0001.heic")),
        ("size_bytes", json!(25)),
    ];

    for (field, value) in cases {
        let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
        mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
        let mut record = manifest.get("asset-1").expect("asset should exist").clone();
        proof_mut(&mut record, "icloudpd_local_mirror")[field] = value;
        manifest.upsert(record);
        let before = manifest.get("asset-1").expect("asset should exist").clone();

        let error = approve_delete(&mut manifest, "asset-1", "operator")
            .expect_err("forged local mirror proof must block delete approval");

        assert!(matches!(
            error,
            WorkflowError::ProofMismatch {
                proof_key: "icloudpd_local_mirror",
                field: actual,
                ..
            } if actual == field
        ));
        assert_eq!(
            manifest.get("asset-1").expect("asset should exist"),
            &before
        );
        assert!(!before.proofs.contains_key("delete_approval"));
    }
}

#[test]
fn delete_approval_uses_bounded_stored_proofs_without_live_nas_reproof() {
    let (_tempdir, mut manifest, raw_path) = real_upload_verified_manifest();
    mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
    let stored_modified =
        manifest.get("asset-1").expect("asset should exist").proofs["nas"]["modified_unix_seconds"]
            .as_u64()
            .expect("stored mtime should be a u64");
    fs::write(&raw_path, b"new-bytes-that-are-larger-than-heic").expect("raw bytes should mutate");
    set_raw_mtime(&raw_path, stored_modified);

    let record = approve_delete(&mut manifest, "asset-1", "operator")
        .expect("delete approval should use only the bounded stored proof chain");

    assert_eq!(record.state, State::DeleteApproved);
    assert!(record.proofs.contains_key("delete_approval"));

    let error = prevalidate_approved_original_delete(&manifest, "asset-1")
        .expect_err("changed NAS bytes must still block live delete prevalidation");

    assert!(matches!(
        error,
        WorkflowError::ProofMismatch {
            proof_key: "nas",
            field: "sha256",
            ..
        }
    ));
}

#[test]
fn delete_approval_revalidates_source_age_without_mutation() {
    let cases = [
        (
            "source_captured_unix_seconds",
            json!(SOURCE_AGE_VERIFIED_AT - 10 * DAY),
        ),
        ("min_age_seconds", json!(0)),
    ];

    for (field, value) in cases {
        let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
        mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
        let mut record = manifest.get("asset-1").expect("asset should exist").clone();
        proof_mut(&mut record, "source_age")[field] = value;
        manifest.upsert(record);
        let before = manifest.get("asset-1").expect("asset should exist").clone();

        let error = approve_delete(&mut manifest, "asset-1", "operator")
            .expect_err("forged source age proof must block delete approval");

        if field == "source_captured_unix_seconds" {
            assert!(matches!(
                error,
                WorkflowError::SourceAgeTooNew {
                    age_seconds,
                    min_age_seconds,
                    ..
                } if age_seconds == 10 * DAY && min_age_seconds == 30 * DAY
            ));
        } else {
            assert!(matches!(
                error,
                WorkflowError::MinAgeBelowSafetyFloor {
                    requested_seconds: 0,
                    minimum_seconds,
                    ..
                } if minimum_seconds == 30 * DAY
            ));
        }
        assert_eq!(
            manifest.get("asset-1").expect("asset should exist"),
            &before
        );
        assert!(!before.proofs.contains_key("delete_approval"));
    }
}

#[test]
fn delete_approval_revalidates_delete_eligibility_without_mutation() {
    let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
    mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    proof_mut(&mut record, "delete_eligibility")["uploaded_heic_sha256"] =
        json!("stale-heic-sha256");
    manifest.upsert(record);
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = approve_delete(&mut manifest, "asset-1", "operator")
        .expect_err("stale delete eligibility proof must block delete approval");

    assert!(matches!(
        error,
        WorkflowError::ProofMismatch {
            proof_key: "delete_eligibility",
            field: "uploaded_heic_sha256",
            ..
        }
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
    assert!(!before.proofs.contains_key("delete_approval"));
}

#[test]
fn delete_eligibility_requires_source_age_proof_without_mutation() {
    let mut manifest = conversion_verified_manifest();
    record_upload_proof(&mut manifest, "asset-1", upload_proof())
        .expect("upload proof should record");
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = mark_delete_eligible(&mut manifest, "asset-1")
        .expect_err("source age proof is required before delete eligibility");

    assert!(matches!(
        error,
        WorkflowError::MissingProof {
            proof_key,
            ..
        } if proof_key == "source_age"
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
    assert!(!before.proofs.contains_key("source_age"));
}

#[test]
fn delete_eligibility_rejects_too_new_source_age_without_mutation() {
    let mut manifest = conversion_verified_manifest();
    record_source_age_proof(&mut manifest, "asset-1", source_age_proof(10))
        .expect("source age evidence should record even when too new");
    record_upload_proof(&mut manifest, "asset-1", upload_proof())
        .expect("upload proof should record");
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = mark_delete_eligible(&mut manifest, "asset-1")
        .expect_err("too-new source age must block delete eligibility");

    assert!(matches!(
        error,
        WorkflowError::SourceAgeTooNew {
            age_seconds,
            min_age_seconds,
            ..
        } if age_seconds == 10 * DAY && min_age_seconds == 30 * DAY
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
    assert!(!before.proofs.contains_key("delete_eligibility"));
}

#[test]
fn source_age_proof_rejects_minimum_below_floor_without_mutation() {
    let mut manifest = conversion_verified_manifest();
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = record_source_age_proof(
        &mut manifest,
        "asset-1",
        SourceAgeProof {
            min_age_seconds: 0,
            ..old_source_age_proof()
        },
    )
    .expect_err("weak source age floor should fail closed");

    assert!(matches!(
        error,
        WorkflowError::MinAgeBelowSafetyFloor {
            requested_seconds: 0,
            minimum_seconds,
            ..
        } if minimum_seconds == 30 * DAY
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
    assert!(!before.proofs.contains_key("source_age"));
}

#[test]
fn source_age_proof_can_be_recorded_after_upload_before_delete_eligibility() {
    let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
    let mut record = manifest.get("asset-1").expect("asset should exist").clone();
    record.proofs.remove("source_age");
    manifest.upsert(record);

    record_source_age_proof(&mut manifest, "asset-1", old_source_age_proof())
        .expect("source age proof should remain valid before delete eligibility");
    mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");

    let record = manifest.get("asset-1").expect("asset should exist");
    assert_eq!(record.state, State::DeleteEligible);
    assert_eq!(
        record.proofs["source_age"]["source_captured_unix_seconds"],
        SOURCE_AGE_VERIFIED_AT - 40 * DAY
    );
}

#[test]
fn source_age_proof_cannot_be_weakened_after_delete_eligibility() {
    let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
    mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = record_source_age_proof(&mut manifest, "asset-1", source_age_proof(10))
        .expect_err("delete-eligible source age proof must be frozen");

    assert!(matches!(
        error,
        WorkflowError::SourceAgeProofFrozen {
            asset_id,
            state: State::DeleteEligible
        } if asset_id == "asset-1"
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
}

#[test]
fn source_age_proof_cannot_be_weakened_after_delete_approval() {
    let (_tempdir, mut manifest, _) = real_delete_approved_manifest();
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = record_source_age_proof(&mut manifest, "asset-1", source_age_proof(10))
        .expect_err("delete-approved source age proof must be frozen");

    assert!(matches!(
        error,
        WorkflowError::SourceAgeProofFrozen {
            asset_id,
            state: State::DeleteApproved
        } if asset_id == "asset-1"
    ));
    let plan = build_delete_plan(&manifest, "asset-1").expect("delete plan should still build");
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
    assert_eq!(
        plan.proofs["source_age"]["source_captured_unix_seconds"],
        SOURCE_AGE_VERIFIED_AT - 40 * DAY
    );
}

#[test]
fn delete_plan_is_unavailable_before_explicit_approval() {
    let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
    mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = build_delete_plan(&manifest, "asset-1")
        .expect_err("approval is required before a delete plan exists");

    assert!(matches!(
        error,
        WorkflowError::DeletePlanUnavailable {
            state: State::DeleteEligible,
            ..
        }
    ));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
}

#[test]
fn delete_approval_requires_non_empty_operator() {
    let (_tempdir, mut manifest, _) = real_upload_verified_manifest();
    mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = approve_delete(&mut manifest, "asset-1", "  ").expect_err("operator is required");

    assert!(matches!(error, WorkflowError::EmptyOperator));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
}

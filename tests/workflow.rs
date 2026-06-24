use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use filetime::{FileTime, set_file_mtime};
use icloudpd_optimizer::manifest::{AssetRecord, Manifest, ManifestError, State};
use icloudpd_optimizer::proof::{NasRawProof, ProofError, prove_nas_raw};
use icloudpd_optimizer::upload::CloudKitDeleteOutcome;
use icloudpd_optimizer::workflow::{
    ConversionCommandTiming, ConversionPerformanceInput, ConversionPerformanceProof,
    ConversionResultProof, HeicVerificationProof, OriginalAssetProof, SourceAgeProof, UploadProof,
    WorkflowError, approve_delete, build_delete_plan, discover_raw_asset, mark_delete_eligible,
    prove_and_record_nas, record_conversion_performance, record_conversion_result,
    record_delete_execution, record_heic_verification, record_nas_proof,
    record_original_asset_batch_proofs, record_original_asset_proof, record_source_age_proof,
    record_stage_failure, record_upload_proof, upload_ready_heic_proof,
};
use serde_json::json;

const DAY: u64 = 24 * 60 * 60;
const SOURCE_AGE_VERIFIED_AT: u64 = 1_800_000_000;

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

fn conversion_proof() -> ConversionResultProof {
    ConversionResultProof {
        heic_path: PathBuf::from("/staging/IMG_0001.heic"),
        heic_sha256: "heic-sha256".to_string(),
        size_bytes: 24,
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

fn heic_proof() -> HeicVerificationProof {
    HeicVerificationProof {
        heic_path: PathBuf::from("/staging/IMG_0001.heic"),
        heic_sha256: "heic-sha256".to_string(),
        size_bytes: 24,
        heif_info_ok: true,
        metadata_copied: true,
        visual_content_ok: true,
        visual_match_ok: true,
    }
}

#[test]
fn heic_verification_proof_accepts_legacy_vipsheader_field() {
    let proof: HeicVerificationProof = serde_json::from_value(json!({
        "heic_path": "/staging/IMG_0001.heic",
        "heic_sha256": "heic-sha256",
        "size_bytes": 24,
        "vipsheader_ok": true,
        "metadata_copied": true,
        "visual_content_ok": true,
        "visual_match_ok": true
    }))
    .expect("legacy proof field should deserialize");

    assert!(proof.heif_info_ok);
}

fn upload_proof() -> UploadProof {
    UploadProof {
        uploaded_heic_asset_id: "icloud-heic-asset-1".to_string(),
        uploaded_heic_sha256: "heic-sha256".to_string(),
        uploaded_heic_path: Some(PathBuf::from("/staging/IMG_0001.heic")),
    }
}

fn original_asset_proof() -> OriginalAssetProof {
    OriginalAssetProof {
        record_name: "original-record-1".to_string(),
        record_change_tag: "old-change-tag".to_string(),
        record_type: "CPLAsset".to_string(),
        filename: "IMG_0001.dng".to_string(),
        size_bytes: 42,
        matched_raw_sha256: "raw-sha256".to_string(),
    }
}

fn delete_outcome() -> CloudKitDeleteOutcome {
    CloudKitDeleteOutcome {
        record_name: "original-record-1".to_string(),
        record_change_tag: "deleted-change-tag".to_string(),
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
    let mut manifest = source_age_verified_manifest();
    record_upload_proof(&mut manifest, "asset-1", upload_proof())
        .expect("upload proof should record");
    record_original_asset_proof(&mut manifest, "asset-1", original_asset_proof())
        .expect("original asset proof should record");
    manifest
}

fn real_upload_verified_manifest() -> (tempfile::TempDir, Manifest, PathBuf) {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let nas_root = tempdir.path().join("nas");
    fs::create_dir_all(&nas_root).expect("nas root should be created");
    let raw_path = write_old_raw(&nas_root, "camera/IMG_0001.dng", b"raw-bytes");
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
    record_upload_proof(&mut manifest, "asset-1", upload_proof())
        .expect("upload proof should record");
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
            b"raw-bytes".as_slice(),
            "raw-sha256-1",
            "/staging/IMG_0001.heic",
            "heic-sha256-1",
            10,
        ),
        (
            "asset-2",
            "IMG_0002.dng",
            b"other-bytes".as_slice(),
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
            ConversionResultProof {
                heic_path: PathBuf::from(heic_path),
                heic_sha256: heic_sha256.to_string(),
                size_bytes: heic_size,
            },
        )
        .expect("conversion should record");
        record_conversion_performance(&mut manifest, asset_id, conversion_performance_input())
            .expect("conversion performance should record");
        record_heic_verification(
            &mut manifest,
            asset_id,
            HeicVerificationProof {
                heic_path: PathBuf::from(heic_path),
                heic_sha256: heic_sha256.to_string(),
                size_bytes: heic_size,
                heif_info_ok: true,
                metadata_copied: true,
                visual_content_ok: true,
                visual_match_ok: true,
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
                uploaded_heic_path: Some(PathBuf::from(heic_path)),
            },
        )
        .expect("upload proof should record");
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
            filename: "IMG_0001.dng".to_string(),
            size_bytes: 9,
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
            filename: "IMG_0001.dng".to_string(),
            size_bytes: 9,
            matched_raw_sha256: "raw-sha256-1".to_string(),
        },
    );
    proofs.insert(
        "asset-2".to_string(),
        OriginalAssetProof {
            record_name: "CPLAsset-original-456".to_string(),
            record_change_tag: "tag-2".to_string(),
            record_type: "CPLAsset".to_string(),
            filename: "IMG_0002.dng".to_string(),
            size_bytes: 11,
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
            filename: "IMG_0001.dng".to_string(),
            size_bytes: 9,
            matched_raw_sha256: "raw-sha256-1".to_string(),
        },
    );
    proofs.insert(
        "asset-3".to_string(),
        OriginalAssetProof {
            record_name: "CPLAsset-original-789".to_string(),
            record_change_tag: "tag-3".to_string(),
            record_type: "CPLAsset".to_string(),
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

fn conversion_performance_manifest() -> Manifest {
    let mut manifest = converted_manifest();
    record_conversion_performance(&mut manifest, "asset-1", conversion_performance_input())
        .expect("conversion performance should record");
    manifest
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
    fs::write(&raw_path, b"new-bytes").expect("raw bytes should mutate");
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
fn heic_verification_must_match_conversion_path_hash_and_size_without_mutation() {
    let cases = [
        (
            "heic_path",
            HeicVerificationProof {
                heic_path: PathBuf::from("/other/IMG_0001.heic"),
                ..heic_proof()
            },
        ),
        (
            "heic_sha256",
            HeicVerificationProof {
                heic_sha256: "other-heic-sha256".to_string(),
                ..heic_proof()
            },
        ),
        (
            "size_bytes",
            HeicVerificationProof {
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
fn conversion_performance_accepts_legacy_proof_without_command_timings() {
    let proof: ConversionPerformanceProof = serde_json::from_value(json!({
        "schema_version": 1,
        "measured_at_unix_seconds": 1_800_000_100,
        "measurement_method": "monotonic_wall_clock",
        "conversion_tool": "magick",
        "conversion_tool_version": "7.1.1-41",
        "heic_quality": 90,
        "raw_size_bytes": 42,
        "heic_size_bytes": 24,
        "convert_wall_time_millis": 1_250,
        "total_wall_time_millis": 1_500,
        "user_cpu_time_millis": 1_100,
        "system_cpu_time_millis": 90,
        "peak_rss_kib": 256_000
    }))
    .expect("legacy conversion performance proof should deserialize");

    assert_eq!(proof.conversion_command_timings, Vec::new());
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
            HeicVerificationProof {
                visual_content_ok: false,
                ..heic_proof()
            },
        ),
        (
            "visual_match_ok",
            HeicVerificationProof {
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
fn delete_eligibility_reproves_live_nas_bytes_without_mutation() {
    let (_tempdir, mut manifest, raw_path) = real_upload_verified_manifest();
    let stored_modified =
        manifest.get("asset-1").expect("asset should exist").proofs["nas"]["modified_unix_seconds"]
            .as_u64()
            .expect("stored mtime should be a u64");
    fs::write(&raw_path, b"new-bytes").expect("raw bytes should mutate");
    set_raw_mtime(&raw_path, stored_modified);
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = mark_delete_eligible(&mut manifest, "asset-1")
        .expect_err("changed NAS bytes must block delete eligibility");

    assert!(matches!(
        error,
        WorkflowError::ProofMismatch {
            proof_key: "nas",
            field: "sha256",
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
fn delete_approval_reproves_live_nas_bytes_without_mutation() {
    let (_tempdir, mut manifest, raw_path) = real_upload_verified_manifest();
    mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
    let stored_modified =
        manifest.get("asset-1").expect("asset should exist").proofs["nas"]["modified_unix_seconds"]
            .as_u64()
            .expect("stored mtime should be a u64");
    fs::write(&raw_path, b"new-bytes").expect("raw bytes should mutate");
    set_raw_mtime(&raw_path, stored_modified);
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = approve_delete(&mut manifest, "asset-1", "operator")
        .expect_err("changed NAS bytes must block delete approval");

    assert!(matches!(
        error,
        WorkflowError::ProofMismatch {
            proof_key: "nas",
            field: "sha256",
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

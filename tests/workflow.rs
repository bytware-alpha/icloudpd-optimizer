use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use filetime::{FileTime, set_file_mtime};
use icloudpd_optimizer::manifest::{AssetRecord, Manifest, State};
use icloudpd_optimizer::proof::{NasRawProof, ProofError, prove_nas_raw};
use icloudpd_optimizer::workflow::{
    ConversionPerformanceInput, ConversionResultProof, HeicVerificationProof, SourceAgeProof,
    UploadProof, WorkflowError, approve_delete, build_delete_plan, discover_raw_asset,
    mark_delete_eligible, prove_and_record_nas, record_conversion_performance,
    record_conversion_result, record_heic_verification, record_nas_proof, record_source_age_proof,
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
    manifest
}

fn real_delete_approved_manifest() -> (tempfile::TempDir, Manifest, PathBuf) {
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
    mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
    approve_delete(&mut manifest, "asset-1", "operator").expect("approval should record");

    (tempdir, manifest, canonical_raw_path)
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
            "heic_quality",
            ConversionPerformanceInput {
                heic_quality: 0,
                ..conversion_performance_input()
            },
        ),
    ];

    for (field, input) in cases {
        let mut manifest = converted_manifest();
        let before = manifest.get("asset-1").expect("asset should exist").clone();

        let error = record_conversion_performance(&mut manifest, "asset-1", input)
            .expect_err("invalid conversion performance metrics must fail closed");

        if field == "conversion_tool" {
            assert!(matches!(
                error,
                WorkflowError::EmptyProofField {
                    field: "conversion_tool"
                }
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
    let mut manifest = conversion_verified_manifest();
    record_upload_proof(&mut manifest, "asset-1", upload_proof())
        .expect("upload proof should record before source age");

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
    let mut manifest = upload_verified_manifest();
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
    let mut manifest = upload_verified_manifest();
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
    let mut manifest = upload_verified_manifest();
    mark_delete_eligible(&mut manifest, "asset-1").expect("delete eligibility should record");
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let error = approve_delete(&mut manifest, "asset-1", "  ").expect_err("operator is required");

    assert!(matches!(error, WorkflowError::EmptyOperator));
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
}

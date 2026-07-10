use icloudpd_optimizer::manifest::{AssetRecord, Manifest, State};
use icloudpd_optimizer::metrics::VerifiedMetrics;
use serde_json::json;

#[test]
fn verified_metrics_use_manifest_proof_sizes_for_deleted_records() {
    let mut manifest = Manifest::new();
    manifest.upsert(deleted_record("raw-a", 100, 12));
    manifest.upsert(deleted_record("raw-b", 250, 25));
    manifest.upsert(upload_verified_record("raw-c", 500, 50));

    let metrics = VerifiedMetrics::from_manifest(&manifest);

    assert_eq!(metrics.total_records, 3);
    assert_eq!(metrics.state_counts["deleted"], 2);
    assert_eq!(metrics.state_counts["upload_verified"], 1);
    assert_eq!(metrics.uploaded_replacements, 3);
    assert_eq!(metrics.uploaded_heic_bytes, 87);
    assert!(metrics.uploaded_size_metrics_complete);
    assert_eq!(metrics.uploaded_records_missing_size_proofs, 0);
    assert_eq!(metrics.deleted_originals, 2);
    assert_eq!(metrics.deleted_raw_bytes, 350);
    assert_eq!(metrics.deleted_replacement_heic_bytes, 37);
    assert_eq!(metrics.verified_bytes_saved, 313);
    assert!(metrics.deleted_size_metrics_complete);
    assert_eq!(metrics.deleted_records_missing_size_proofs, 0);
}

#[test]
fn verified_metrics_report_missing_size_proofs_without_estimating() {
    let mut manifest = Manifest::new();
    let mut record = deleted_record("raw-a", 100, 12);
    record.proofs.get_mut("heic").unwrap()["size_bytes"] = json!(null);
    record.proofs.get_mut("icloudpd_local_mirror").unwrap()["size_bytes"] = json!(null);
    manifest.upsert(record);

    let metrics = VerifiedMetrics::from_manifest(&manifest);

    assert_eq!(metrics.deleted_originals, 1);
    assert_eq!(metrics.deleted_raw_bytes, 0);
    assert_eq!(metrics.deleted_replacement_heic_bytes, 0);
    assert_eq!(metrics.verified_bytes_saved, 0);
    assert!(!metrics.deleted_size_metrics_complete);
    assert_eq!(metrics.deleted_records_missing_size_proofs, 1);
}

#[test]
fn verified_metrics_require_uploaded_heic_size_proof_for_deleted_records() {
    let mut manifest = Manifest::new();
    let mut record = deleted_record("raw-a", 100, 12);
    record.proofs.remove("icloudpd_local_mirror");
    manifest.upsert(record);

    let metrics = VerifiedMetrics::from_manifest(&manifest);

    assert_eq!(metrics.deleted_originals, 1);
    assert_eq!(metrics.deleted_raw_bytes, 0);
    assert_eq!(metrics.deleted_replacement_heic_bytes, 0);
    assert_eq!(metrics.verified_bytes_saved, 0);
    assert!(!metrics.deleted_size_metrics_complete);
    assert_eq!(metrics.deleted_records_missing_size_proofs, 1);
}

#[test]
fn verified_metrics_net_mixed_savings_and_expansion_from_aggregate_totals() {
    let mut manifest = Manifest::new();
    manifest.upsert(deleted_record("expanded", 1, 78_127_881));
    manifest.upsert(deleted_record("saved", 79_144_954_591, 15_404_778_127));

    let metrics = VerifiedMetrics::from_manifest(&manifest);

    assert_eq!(metrics.deleted_raw_bytes, 79_144_954_592);
    assert_eq!(metrics.deleted_replacement_heic_bytes, 15_482_906_008);
    assert_eq!(metrics.verified_bytes_saved, 63_662_048_584);
    assert!(metrics.deleted_size_metrics_complete);
}

#[test]
fn verified_metrics_clamp_all_expansion_aggregate_to_zero() {
    let mut manifest = Manifest::new();
    manifest.upsert(deleted_record("expanded-a", 100, 125));
    manifest.upsert(deleted_record("expanded-b", 20, 30));

    let metrics = VerifiedMetrics::from_manifest(&manifest);

    assert_eq!(metrics.deleted_raw_bytes, 120);
    assert_eq!(metrics.deleted_replacement_heic_bytes, 155);
    assert_eq!(metrics.verified_bytes_saved, 0);
    assert!(metrics.deleted_size_metrics_complete);
}

#[test]
fn verified_metrics_preserve_representable_net_when_component_totals_overflow_u64() {
    let mut manifest = Manifest::new();
    manifest.upsert(deleted_record("boundary-a", u64::MAX, u64::MAX - 100));
    manifest.upsert(deleted_record("boundary-b", 200, 150));

    let metrics = VerifiedMetrics::from_manifest(&manifest);

    assert_eq!(metrics.deleted_raw_bytes, u64::MAX);
    assert_eq!(metrics.deleted_replacement_heic_bytes, u64::MAX);
    assert_eq!(metrics.verified_bytes_saved, 150);
    assert!(!metrics.deleted_size_metrics_complete);
    assert_eq!(metrics.deleted_records_missing_size_proofs, 0);
}

#[test]
fn verified_metrics_fail_closed_when_aggregate_net_overflows_u64() {
    let mut manifest = Manifest::new();
    manifest.upsert(deleted_record("boundary-a", u64::MAX, 0));
    manifest.upsert(deleted_record("boundary-b", 1, 0));

    let metrics = VerifiedMetrics::from_manifest(&manifest);

    assert_eq!(metrics.deleted_raw_bytes, u64::MAX);
    assert_eq!(metrics.deleted_replacement_heic_bytes, 0);
    assert_eq!(metrics.verified_bytes_saved, u64::MAX);
    assert!(!metrics.deleted_size_metrics_complete);
    assert_eq!(metrics.deleted_records_missing_size_proofs, 0);
}

#[test]
fn verified_metrics_mark_uploaded_sizes_incomplete_when_total_overflows_u64() {
    let mut manifest = Manifest::new();
    manifest.upsert(upload_verified_record("boundary-a", 0, u64::MAX));
    manifest.upsert(upload_verified_record("boundary-b", 0, 1));

    let metrics = VerifiedMetrics::from_manifest(&manifest);

    assert_eq!(metrics.uploaded_heic_bytes, u64::MAX);
    assert!(!metrics.uploaded_size_metrics_complete);
    assert_eq!(metrics.uploaded_records_missing_size_proofs, 0);
}

fn deleted_record(asset_id: &str, raw_bytes: u64, heic_bytes: u64) -> AssetRecord {
    let mut record = upload_verified_record(asset_id, raw_bytes, heic_bytes);
    record.state = State::Deleted;
    record.proofs.insert(
        "delete".to_string(),
        json!({
            "old_record_change_tag": "old-tag",
            "deleted_record_name": format!("CPLAsset-{asset_id}"),
            "confirmed_deleted_change_tag": "deleted-tag",
            "uploaded_heic_asset_id": format!("uploaded-{asset_id}"),
        }),
    );
    record
}

fn upload_verified_record(asset_id: &str, raw_bytes: u64, heic_bytes: u64) -> AssetRecord {
    let mut record = AssetRecord::new(asset_id, format!("/raw/{asset_id}.DNG"));
    record.state = State::UploadVerified;
    record.proofs.insert(
        "nas".to_string(),
        json!({
            "canonical_path": format!("/raw/{asset_id}.DNG"),
            "relative_path": format!("{asset_id}.DNG"),
            "size_bytes": raw_bytes,
            "modified_unix_seconds": 1_700_000_000u64,
            "age_seconds": 2_592_000u64,
            "sha256": format!("raw-sha-{asset_id}"),
        }),
    );
    record.proofs.insert(
        "heic".to_string(),
        json!({
            "heic_path": format!("/heic/{asset_id}.HEIC"),
            "heic_sha256": format!("heic-sha-{asset_id}"),
            "size_bytes": heic_bytes,
            "heif_info_ok": true,
            "metadata_copied": true,
            "visual_content_ok": true,
            "visual_match_ok": true,
        }),
    );
    record.proofs.insert(
        "upload".to_string(),
        json!({
            "uploaded_heic_asset_id": format!("uploaded-{asset_id}"),
            "uploaded_heic_sha256": format!("heic-sha-{asset_id}"),
            "uploaded_heic_path": format!("/heic/{asset_id}.HEIC"),
        }),
    );
    record.proofs.insert(
        "icloudpd_local_mirror".to_string(),
        json!({
            "uploaded_heic_asset_id": format!("uploaded-{asset_id}"),
            "uploaded_heic_sha256": format!("heic-sha-{asset_id}"),
            "uploaded_heic_path": format!("/heic/{asset_id}.HEIC"),
            "icloudpd_download_path": format!("/mirror/{asset_id}.HEIC"),
            "size_bytes": heic_bytes,
        }),
    );
    record
}

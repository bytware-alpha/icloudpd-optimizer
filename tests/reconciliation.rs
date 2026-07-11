use std::collections::BTreeMap;
use std::path::PathBuf;

use icloudpd_optimizer::manifest::{AssetRecord, FailureRecord, Manifest, State};
use icloudpd_optimizer::proof::NasRawProof;
use icloudpd_optimizer::reconciliation::{
    OriginalAssetResolutionBatch, OriginalAssetResolutionProof,
};
use icloudpd_optimizer::upload::{
    CloudKitDatabaseScope, CloudKitLibraryDestination, CloudKitLocalReplacementCandidate,
    CloudKitOriginalAssetInventoryFingerprint, CloudKitOriginalAssetResolution,
    CloudKitOriginalAssetResolveDisposition, CloudKitOriginalAssetResolveObservations,
    CloudKitOriginalAssetResolveTarget, CloudKitReplacementResourceProof,
};
use icloudpd_optimizer::workflow::{
    ConversionPerformanceProof, ConversionResultProof, HeicVerificationProof, OriginalAssetProof,
    SourceAgeProof, UploadProof, WorkflowError, mark_delete_eligible, record_source_age_proof,
};

const DAY: u64 = 24 * 60 * 60;
const RAW_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HEIC_SHA256: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn target(asset_id: &str) -> CloudKitOriginalAssetResolveTarget {
    CloudKitOriginalAssetResolveTarget {
        asset_id: asset_id.to_string(),
        raw_size_bytes: 42,
        source_captured_unix_seconds: 1_700_000_000,
        capture_tolerance_seconds: 60,
        filename: "IMG_0001.dng".to_string(),
        matched_raw_sha256: RAW_SHA256.to_string(),
        replacement_candidate: None,
    }
}

fn exact_original_resolution() -> CloudKitOriginalAssetResolution {
    exact_original_resolution_with_record_name("CPLAsset-original")
}

fn exact_original_resolution_with_record_name(
    record_name: &str,
) -> CloudKitOriginalAssetResolution {
    CloudKitOriginalAssetResolution {
        observations: CloudKitOriginalAssetResolveObservations {
            date_candidates: 1,
            raw_resources: 1,
            raw_size_matches: 1,
            raw_hash_matches: 1,
            ..Default::default()
        },
        disposition: CloudKitOriginalAssetResolveDisposition::ExactOriginal {
            proof: OriginalAssetProof {
                record_name: record_name.to_string(),
                record_change_tag: "change-tag".to_string(),
                record_type: "CPLAsset".to_string(),
                database_scope: Default::default(),
                zone_name: "PrimarySync".to_string(),
                filename: "IMG_0001.dng".to_string(),
                size_bytes: 42,
                matched_raw_sha256: RAW_SHA256.to_string(),
            },
        },
    }
}

fn coherent_observations(
    disposition: &CloudKitOriginalAssetResolveDisposition,
) -> CloudKitOriginalAssetResolveObservations {
    match disposition {
        CloudKitOriginalAssetResolveDisposition::ExactOriginal { .. } => {
            CloudKitOriginalAssetResolveObservations {
                date_candidates: 1,
                raw_resources: 1,
                raw_size_matches: 1,
                raw_hash_matches: 1,
                ..Default::default()
            }
        }
        CloudKitOriginalAssetResolveDisposition::ReplacementPresent { .. } => {
            CloudKitOriginalAssetResolveObservations {
                date_candidates: 1,
                replacement_resource_matches: 1,
                ..Default::default()
            }
        }
        CloudKitOriginalAssetResolveDisposition::NoDateCandidate => {
            CloudKitOriginalAssetResolveObservations::default()
        }
        CloudKitOriginalAssetResolveDisposition::NoRawResource => {
            CloudKitOriginalAssetResolveObservations {
                date_candidates: 1,
                ..Default::default()
            }
        }
        CloudKitOriginalAssetResolveDisposition::RawSizeMismatch => {
            CloudKitOriginalAssetResolveObservations {
                date_candidates: 1,
                raw_resources: 1,
                ..Default::default()
            }
        }
        CloudKitOriginalAssetResolveDisposition::RawHashMismatch => {
            CloudKitOriginalAssetResolveObservations {
                date_candidates: 1,
                raw_resources: 1,
                raw_size_matches: 1,
                ..Default::default()
            }
        }
        CloudKitOriginalAssetResolveDisposition::Ambiguous => {
            CloudKitOriginalAssetResolveObservations {
                date_candidates: 1,
                raw_resources: 1,
                raw_size_matches: 1,
                raw_hash_matches: 2,
                ambiguity_evidence: 1,
                ..Default::default()
            }
        }
        CloudKitOriginalAssetResolveDisposition::IncompleteTransient => {
            CloudKitOriginalAssetResolveObservations::default()
        }
    }
}

fn failed_resolver_record(asset_id: &str) -> AssetRecord {
    let mut record = AssetRecord::new(asset_id, PathBuf::from("/nas/photos/IMG_0001.dng"));
    record.state = State::Failed;
    record.proofs.insert(
        "nas".to_string(),
        serde_json::to_value(NasRawProof {
            canonical_path: record.raw_path.clone(),
            relative_path: PathBuf::from("photos/IMG_0001.dng"),
            size_bytes: 42,
            modified_unix_seconds: 1_700_000_000,
            age_seconds: 40 * DAY,
            sha256: RAW_SHA256.to_string(),
        })
        .unwrap(),
    );
    record.proofs.insert(
        "source_age".to_string(),
        serde_json::to_value(SourceAgeProof {
            source_captured_unix_seconds: 1_700_000_000,
            verified_at_unix_seconds: 1_800_000_000,
            min_age_seconds: 30 * DAY,
        })
        .unwrap(),
    );
    record.failures.push(FailureRecord {
        stage: "original_asset_resolve".to_string(),
        message: "old resolver failure".to_string(),
        recorded_at: "1700000000.000000000Z".to_string(),
        kind: None,
    });
    record
}

fn batch(
    asset_id: &str,
    resolution: CloudKitOriginalAssetResolution,
) -> OriginalAssetResolutionBatch {
    let mut target = target(asset_id);
    if matches!(
        &resolution.disposition,
        CloudKitOriginalAssetResolveDisposition::ReplacementPresent { .. }
    ) {
        target.replacement_candidate = Some(CloudKitLocalReplacementCandidate {
            sha256: HEIC_SHA256.to_string(),
            size_bytes: 24,
        });
    }
    OriginalAssetResolutionBatch {
        targets: vec![target],
        destination: CloudKitLibraryDestination::primary_sync(),
        inventory: CloudKitOriginalAssetInventoryFingerprint {
            resolver_version: "cloudkit-original-asset-reconcile-v1".to_string(),
            sha256: "a".repeat(64),
            records_scanned: 1,
        },
        observed_at_unix_seconds: 1_800_000_000,
        resolutions: BTreeMap::from([(asset_id.to_string(), resolution)]),
    }
}

fn replacement_resolution() -> CloudKitOriginalAssetResolution {
    CloudKitOriginalAssetResolution {
        observations: CloudKitOriginalAssetResolveObservations {
            date_candidates: 1,
            replacement_resource_matches: 1,
            ..Default::default()
        },
        disposition: CloudKitOriginalAssetResolveDisposition::ReplacementPresent {
            proof: CloudKitReplacementResourceProof {
                record_name: "CPLAsset-replacement".to_string(),
                record_change_tag: "replacement-tag".to_string(),
                record_type: "CPLAsset".to_string(),
                database_scope: Default::default(),
                zone_name: "PrimarySync".to_string(),
                resource_field: "resOriginalRes".to_string(),
                size_bytes: 24,
                matched_heic_sha256: HEIC_SHA256.to_string(),
            },
        },
    }
}

fn failed_resolver_record_at_strength(asset_id: &str, strength: State) -> AssetRecord {
    let mut record = failed_resolver_record(asset_id);
    record.proofs.insert(
        "conversion".to_string(),
        serde_json::to_value(ConversionResultProof {
            heic_path: PathBuf::from("/staging/IMG_0001.heic"),
            heic_sha256: HEIC_SHA256.to_string(),
            size_bytes: 24,
        })
        .unwrap(),
    );
    if matches!(strength, State::ConversionVerified | State::UploadVerified) {
        record.proofs.insert(
            "conversion_performance".to_string(),
            serde_json::to_value(ConversionPerformanceProof {
                schema_version: 1,
                measured_at_unix_seconds: 1_800_000_000,
                measurement_method: "monotonic_wall_clock".to_string(),
                conversion_tool: "sips".to_string(),
                conversion_tool_version: Some("1.0".to_string()),
                heic_quality: 100,
                raw_size_bytes: 42,
                heic_size_bytes: 24,
                convert_wall_time_millis: 10,
                total_wall_time_millis: 20,
                user_cpu_time_millis: Some(5),
                system_cpu_time_millis: Some(2),
                peak_rss_kib: Some(1_024),
                conversion_command_timings: Vec::new(),
            })
            .unwrap(),
        );
        record.proofs.insert(
            "heic".to_string(),
            serde_json::to_value(HeicVerificationProof {
                heic_path: PathBuf::from("/staging/IMG_0001.heic"),
                heic_sha256: HEIC_SHA256.to_string(),
                size_bytes: 24,
                heif_info_ok: true,
                metadata_copied: true,
                visual_content_ok: true,
                visual_match_ok: true,
                visual_rmse_ppm: Some(0),
                visual_mae_ppm: Some(0),
            })
            .unwrap(),
        );
    }
    if strength == State::UploadVerified {
        record.proofs.insert(
            "upload".to_string(),
            serde_json::to_value(UploadProof {
                uploaded_heic_asset_id: "uploaded-heic".to_string(),
                uploaded_heic_sha256: HEIC_SHA256.to_string(),
                database_scope: Default::default(),
                zone_name: "PrimarySync".to_string(),
                uploaded_heic_path: Some(PathBuf::from("/staging/IMG_0001.heic")),
            })
            .unwrap(),
        );
    }
    if strength == State::NasVerified {
        record.proofs.remove("conversion");
    }
    record
}

#[test]
fn exact_original_resolution_records_durable_proof_and_restores_nas_state() {
    let mut manifest = Manifest::new();
    manifest.upsert(failed_resolver_record("asset-1"));

    let result = manifest
        .apply_original_asset_resolution_batch(batch("asset-1", exact_original_resolution()))
        .expect("complete exact resolution should apply");

    assert_eq!(result.changed_records.len(), 1);
    assert_eq!(result.summary.exact_original, 1);
    let record = manifest.get("asset-1").unwrap();
    assert_eq!(record.state, State::NasVerified);
    assert_eq!(record.failures.len(), 1);
    assert!(record.proofs.contains_key("original_asset"));
    let proof: OriginalAssetResolutionProof =
        serde_json::from_value(record.proofs["original_asset_resolution"].clone()).unwrap();
    assert_eq!(proof.inventory.sha256, "a".repeat(64));
    assert_eq!(proof.observations.raw_hash_matches, 1);
}

#[test]
fn non_exact_resolutions_classify_terminally_without_original_or_delete_eligibility() {
    let cases = [
        (
            "no-date",
            CloudKitOriginalAssetResolveDisposition::NoDateCandidate,
            State::NoAction,
        ),
        (
            "no-raw",
            CloudKitOriginalAssetResolveDisposition::NoRawResource,
            State::NoAction,
        ),
        (
            "replacement",
            replacement_resolution().disposition,
            State::NoAction,
        ),
        (
            "size-mismatch",
            CloudKitOriginalAssetResolveDisposition::RawSizeMismatch,
            State::NeedsReview,
        ),
        (
            "hash-mismatch",
            CloudKitOriginalAssetResolveDisposition::RawHashMismatch,
            State::NeedsReview,
        ),
        (
            "ambiguous",
            CloudKitOriginalAssetResolveDisposition::Ambiguous,
            State::NeedsReview,
        ),
    ];

    for (asset_id, disposition, expected_state) in cases {
        let mut manifest = Manifest::new();
        manifest.upsert(failed_resolver_record(asset_id));
        let resolution = CloudKitOriginalAssetResolution {
            observations: coherent_observations(&disposition),
            disposition,
        };

        let result = manifest
            .apply_original_asset_resolution_batch(batch(asset_id, resolution))
            .expect("complete non-exact resolution should apply terminal classification");

        let record = manifest.get(asset_id).unwrap();
        assert_eq!(record.state, expected_state);
        assert_eq!(record.failures.len(), 1);
        assert!(!record.proofs.contains_key("original_asset"));
        assert!(!record.proofs.contains_key("delete_eligibility"));
        assert!(mark_delete_eligible(&mut manifest, asset_id).is_err());
        if expected_state == State::NoAction {
            assert_eq!(result.summary.no_action, 1);
        } else {
            assert_eq!(result.summary.needs_review, 1);
        }
    }
}

#[test]
fn exact_original_resolution_restores_the_strongest_proof_consistent_state() {
    for expected_state in [
        State::NasVerified,
        State::Converted,
        State::ConversionVerified,
        State::UploadVerified,
    ] {
        let asset_id = expected_state.as_str();
        let mut manifest = Manifest::new();
        manifest.upsert(failed_resolver_record_at_strength(asset_id, expected_state));

        manifest
            .apply_original_asset_resolution_batch(batch(asset_id, exact_original_resolution()))
            .expect("exact resolution should restore lifecycle progress");

        assert_eq!(manifest.get(asset_id).unwrap().state, expected_state);
    }
}

#[test]
fn non_failed_sources_require_their_exact_validated_lifecycle_strength() {
    let mut manifest = Manifest::new();
    let mut record = failed_resolver_record("asset-1");
    record.state = State::UploadVerified;
    record.failures.clear();
    manifest.upsert(record);
    let before = manifest.clone();

    assert!(
        manifest
            .apply_original_asset_resolution_batch(batch("asset-1", exact_original_resolution()))
            .is_err()
    );
    assert_eq!(manifest, before);
}

#[test]
fn lifecycle_proofs_require_full_sha256_and_bound_upload_paths() {
    let mut manifest = Manifest::new();
    let mut record = failed_resolver_record_at_strength("asset-1", State::ConversionVerified);
    record.proofs.get_mut("conversion").unwrap()["heic_sha256"] = serde_json::json!("short");
    record.proofs.get_mut("heic").unwrap()["heic_sha256"] = serde_json::json!("short");
    manifest.upsert(record);
    let before = manifest.clone();
    assert!(
        manifest
            .apply_original_asset_resolution_batch(batch("asset-1", exact_original_resolution()))
            .is_err()
    );
    assert_eq!(manifest, before);

    let mut manifest = Manifest::new();
    let mut record = failed_resolver_record_at_strength("asset-2", State::UploadVerified);
    record.proofs.get_mut("upload").unwrap()["uploaded_heic_path"] = serde_json::Value::Null;
    manifest.upsert(record);
    let before = manifest.clone();
    assert!(
        manifest
            .apply_original_asset_resolution_batch(batch("asset-2", exact_original_resolution()))
            .is_err()
    );
    assert_eq!(manifest, before);

    let mut manifest = Manifest::new();
    let mut record = failed_resolver_record_at_strength("asset-3", State::ConversionVerified);
    record.proofs.get_mut("heic").unwrap()["heic_path"] = serde_json::json!("/staging/other.heic");
    manifest.upsert(record);
    let before = manifest.clone();
    assert!(
        manifest
            .apply_original_asset_resolution_batch(batch("asset-3", exact_original_resolution()))
            .is_err()
    );
    assert_eq!(manifest, before);

    let mut manifest = Manifest::new();
    let mut record = failed_resolver_record_at_strength("asset-4", State::UploadVerified);
    record.proofs.get_mut("upload").unwrap()["zone_name"] = serde_json::json!("SharedSync-other");
    manifest.upsert(record);
    let before = manifest.clone();
    assert!(
        manifest
            .apply_original_asset_resolution_batch(batch("asset-4", exact_original_resolution()))
            .is_err()
    );
    assert_eq!(manifest, before);
}

#[test]
fn reconciliation_requires_shared_conversion_performance_for_heic_or_upload_progress() {
    let mut manifest = Manifest::new();
    let mut record = failed_resolver_record_at_strength("asset-1", State::ConversionVerified);
    record.proofs.remove("conversion_performance");
    manifest.upsert(record);
    let before = manifest.clone();

    assert!(
        manifest
            .apply_original_asset_resolution_batch(batch("asset-1", exact_original_resolution()))
            .is_err()
    );
    assert_eq!(manifest, before);
}

#[test]
fn exact_timestamp_window_is_a_valid_reconciliation_target() {
    let mut manifest = Manifest::new();
    manifest.upsert(failed_resolver_record("asset-1"));
    let mut resolution_batch = batch("asset-1", exact_original_resolution());
    resolution_batch.targets[0].capture_tolerance_seconds = 0;

    manifest
        .apply_original_asset_resolution_batch(resolution_batch)
        .expect("zero tolerance represents an exact timestamp window");
    assert_eq!(manifest.get("asset-1").unwrap().state, State::NasVerified);
}

#[test]
fn complete_empty_inventory_is_a_valid_no_action_proof() {
    let mut manifest = Manifest::new();
    manifest.upsert(failed_resolver_record("asset-1"));
    let disposition = CloudKitOriginalAssetResolveDisposition::NoDateCandidate;
    let mut resolution_batch = batch(
        "asset-1",
        CloudKitOriginalAssetResolution {
            observations: coherent_observations(&disposition),
            disposition,
        },
    );
    resolution_batch.inventory.records_scanned = 0;

    manifest
        .apply_original_asset_resolution_batch(resolution_batch)
        .expect("a complete empty CloudKit window is valid evidence");
    assert_eq!(manifest.get("asset-1").unwrap().state, State::NoAction);
}

#[test]
fn remote_record_identity_is_scoped_to_database_and_zone() {
    let record_name = "CPLAsset-same-name";
    let mut manifest = Manifest::new();
    manifest.upsert(failed_resolver_record("private"));
    manifest
        .apply_original_asset_resolution_batch(batch(
            "private",
            exact_original_resolution_with_record_name(record_name),
        ))
        .unwrap();
    manifest.upsert(failed_resolver_record("shared"));

    let destination = CloudKitLibraryDestination {
        database_scope: CloudKitDatabaseScope::Shared,
        zone_name: "SharedSync-test".to_string(),
    };
    let mut resolution = exact_original_resolution_with_record_name(record_name);
    let CloudKitOriginalAssetResolveDisposition::ExactOriginal { proof } =
        &mut resolution.disposition
    else {
        unreachable!();
    };
    proof.database_scope = destination.database_scope;
    proof.zone_name.clone_from(&destination.zone_name);
    let mut resolution_batch = batch("shared", resolution);
    resolution_batch.destination = destination;

    manifest
        .apply_original_asset_resolution_batch(resolution_batch)
        .expect("equal record names in different CloudKit destinations are distinct");
    assert_eq!(manifest.get("shared").unwrap().state, State::NasVerified);
}

#[test]
fn persisted_resolution_proofs_bind_record_source_original_and_state() {
    for case in [
        "nas-size",
        "source-capture",
        "top-level-original",
        "lifecycle-state",
    ] {
        let mut historical = Manifest::new();
        historical.upsert(failed_resolver_record("historical"));
        historical
            .apply_original_asset_resolution_batch(batch(
                "historical",
                exact_original_resolution_with_record_name("CPLAsset-historical"),
            ))
            .unwrap();
        let mut historical_record = historical.get("historical").unwrap().clone();
        match case {
            "nas-size" => {
                historical_record.proofs.get_mut("nas").unwrap()["size_bytes"] =
                    serde_json::json!(43)
            }
            "source-capture" => {
                historical_record.proofs.get_mut("source_age").unwrap()["source_captured_unix_seconds"] =
                    serde_json::json!(1_700_000_001u64);
            }
            "top-level-original" => {
                historical_record.proofs.get_mut("original_asset").unwrap()["matched_raw_sha256"] =
                    serde_json::json!(HEIC_SHA256);
            }
            "lifecycle-state" => historical_record.state = State::Converted,
            _ => unreachable!(),
        }

        let mut manifest = Manifest::new();
        manifest.upsert(failed_resolver_record("target"));
        manifest.upsert(historical_record);
        let before = manifest.clone();
        assert!(
            manifest
                .apply_original_asset_resolution_batch(batch(
                    "target",
                    exact_original_resolution_with_record_name("CPLAsset-target"),
                ))
                .is_err()
        );
        assert_eq!(manifest, before, "{case} must fail closed");
    }
}

#[test]
fn persisted_exact_resolution_rejects_unproven_later_or_failed_state() {
    for case in ["delete-eligible", "failed"] {
        let mut historical = Manifest::new();
        historical.upsert(failed_resolver_record_at_strength(
            "historical",
            State::UploadVerified,
        ));
        historical
            .apply_original_asset_resolution_batch(batch(
                "historical",
                exact_original_resolution_with_record_name("CPLAsset-historical"),
            ))
            .unwrap();
        let mut historical_record = historical.get("historical").unwrap().clone();
        historical_record.state = match case {
            "delete-eligible" => State::DeleteEligible,
            "failed" => State::Failed,
            _ => unreachable!(),
        };

        let mut manifest = Manifest::new();
        manifest.upsert(failed_resolver_record("target"));
        manifest.upsert(historical_record);
        let before = manifest.clone();
        assert!(
            manifest
                .apply_original_asset_resolution_batch(batch(
                    "target",
                    exact_original_resolution_with_record_name("CPLAsset-target"),
                ))
                .is_err()
        );
        assert_eq!(manifest, before, "{case} must fail closed");
    }
}

#[test]
fn persisted_exact_resolution_accepts_a_proven_later_failure() {
    let mut historical = Manifest::new();
    historical.upsert(failed_resolver_record_at_strength(
        "historical",
        State::UploadVerified,
    ));
    historical
        .apply_original_asset_resolution_batch(batch(
            "historical",
            exact_original_resolution_with_record_name("CPLAsset-historical"),
        ))
        .unwrap();
    let mut historical_record = historical.get("historical").unwrap().clone();
    historical_record.state = State::Failed;
    historical_record.failures.push(FailureRecord {
        stage: "upload_verify".to_string(),
        message: "later retryable failure".to_string(),
        recorded_at: "1800000001.000000000Z".to_string(),
        kind: None,
    });

    let mut manifest = Manifest::new();
    manifest.upsert(historical_record);
    manifest.upsert(failed_resolver_record("target"));
    manifest
        .apply_original_asset_resolution_batch(batch(
            "target",
            exact_original_resolution_with_record_name("CPLAsset-target"),
        ))
        .expect("a proof-consistent later failure must remain valid history");
    assert_eq!(manifest.get("target").unwrap().state, State::NasVerified);
}

#[test]
fn persisted_non_exact_resolution_requires_its_terminal_state_without_delete_or_original_proofs() {
    for case in ["state", "original", "delete"] {
        let mut historical = Manifest::new();
        historical.upsert(failed_resolver_record("historical"));
        historical
            .apply_original_asset_resolution_batch(batch(
                "historical",
                CloudKitOriginalAssetResolution {
                    observations: coherent_observations(
                        &CloudKitOriginalAssetResolveDisposition::NoDateCandidate,
                    ),
                    disposition: CloudKitOriginalAssetResolveDisposition::NoDateCandidate,
                },
            ))
            .unwrap();
        let mut historical_record = historical.get("historical").unwrap().clone();
        match case {
            "state" => historical_record.state = State::NeedsReview,
            "original" => {
                let CloudKitOriginalAssetResolveDisposition::ExactOriginal { proof } =
                    exact_original_resolution_with_record_name("CPLAsset-unrelated").disposition
                else {
                    unreachable!();
                };
                historical_record.proofs.insert(
                    "original_asset".to_string(),
                    serde_json::to_value(proof).unwrap(),
                );
            }
            "delete" => {
                historical_record
                    .proofs
                    .insert("delete".to_string(), serde_json::json!({"confirmed": true}));
            }
            _ => unreachable!(),
        }

        let mut manifest = Manifest::new();
        manifest.upsert(failed_resolver_record("target"));
        manifest.upsert(historical_record);
        let before = manifest.clone();
        assert!(
            manifest
                .apply_original_asset_resolution_batch(batch(
                    "target",
                    exact_original_resolution_with_record_name("CPLAsset-target"),
                ))
                .is_err()
        );
        assert_eq!(manifest, before, "{case} must fail closed");
    }
}

#[test]
fn batch_and_failed_source_admission_are_strict_and_atomic() {
    for case in [
        "zero-capture",
        "unsafe-filename",
        "short-target-hash",
        "short-nas-hash",
        "observed-before-source",
        "invalid-destination",
        "control-remote-identity",
        "wrong-failure-stage",
        "existing-resolution",
    ] {
        let mut manifest = Manifest::new();
        let mut record = failed_resolver_record("asset-1");
        if case == "wrong-failure-stage" {
            record.failures.last_mut().unwrap().stage = "conversion".to_string();
        }
        if case == "existing-resolution" {
            record.proofs.insert(
                "original_asset_resolution".to_string(),
                serde_json::json!({}),
            );
        }
        if case == "short-nas-hash" {
            record.proofs.get_mut("nas").unwrap()["sha256"] = serde_json::json!("short");
        }
        manifest.upsert(record);
        let before = manifest.clone();
        let mut resolution_batch = batch("asset-1", exact_original_resolution());

        match case {
            "zero-capture" => resolution_batch.targets[0].source_captured_unix_seconds = 0,
            "unsafe-filename" => {
                resolution_batch.targets[0].filename = "nested/IMG_0001.dng".to_string()
            }
            "short-target-hash" => {
                resolution_batch.targets[0].matched_raw_sha256 = "short".to_string()
            }
            "short-nas-hash" => {}
            "observed-before-source" => resolution_batch.observed_at_unix_seconds = 1_699_999_999,
            "invalid-destination" => {
                resolution_batch.destination.zone_name = "SharedSync-in-private-db".to_string();
            }
            "control-remote-identity" => {
                let CloudKitOriginalAssetResolveDisposition::ExactOriginal { proof } =
                    &mut resolution_batch
                        .resolutions
                        .get_mut("asset-1")
                        .unwrap()
                        .disposition
                else {
                    unreachable!();
                };
                proof.record_name = "CPLAsset\ninvalid".to_string();
            }
            "wrong-failure-stage" | "existing-resolution" => {}
            _ => unreachable!(),
        }

        assert!(
            manifest
                .apply_original_asset_resolution_batch(resolution_batch)
                .is_err()
        );
        assert_eq!(manifest, before, "{case} must fail without mutation");
    }
}

#[test]
fn resolver_dispositions_reject_contradictory_observations_without_mutation() {
    let exact_proof = match exact_original_resolution().disposition {
        CloudKitOriginalAssetResolveDisposition::ExactOriginal { proof } => proof,
        _ => unreachable!(),
    };
    let mut replacement_without_evidence = replacement_resolution();
    replacement_without_evidence.observations = CloudKitOriginalAssetResolveObservations::default();
    let contradictory = [
        CloudKitOriginalAssetResolution {
            observations: CloudKitOriginalAssetResolveObservations::default(),
            disposition: CloudKitOriginalAssetResolveDisposition::ExactOriginal {
                proof: exact_proof,
            },
        },
        CloudKitOriginalAssetResolution {
            observations: CloudKitOriginalAssetResolveObservations {
                date_candidates: 1,
                ..Default::default()
            },
            disposition: CloudKitOriginalAssetResolveDisposition::NoDateCandidate,
        },
        CloudKitOriginalAssetResolution {
            observations: CloudKitOriginalAssetResolveObservations::default(),
            disposition: CloudKitOriginalAssetResolveDisposition::NoRawResource,
        },
        CloudKitOriginalAssetResolution {
            observations: CloudKitOriginalAssetResolveObservations {
                raw_resources: 1,
                raw_size_matches: 1,
                ..Default::default()
            },
            disposition: CloudKitOriginalAssetResolveDisposition::RawSizeMismatch,
        },
        CloudKitOriginalAssetResolution {
            observations: CloudKitOriginalAssetResolveObservations {
                raw_resources: 1,
                raw_size_matches: 1,
                raw_hash_matches: 1,
                ..Default::default()
            },
            disposition: CloudKitOriginalAssetResolveDisposition::RawHashMismatch,
        },
        CloudKitOriginalAssetResolution {
            observations: CloudKitOriginalAssetResolveObservations {
                date_candidates: 1,
                raw_resources: 1,
                raw_size_matches: 1,
                download_size_mismatches: 1,
                ..Default::default()
            },
            disposition: CloudKitOriginalAssetResolveDisposition::RawHashMismatch,
        },
        CloudKitOriginalAssetResolution {
            observations: CloudKitOriginalAssetResolveObservations::default(),
            disposition: CloudKitOriginalAssetResolveDisposition::Ambiguous,
        },
        replacement_without_evidence,
    ];

    for resolution in contradictory {
        let mut manifest = Manifest::new();
        manifest.upsert(failed_resolver_record("asset-1"));
        let before = manifest.clone();
        assert!(
            manifest
                .apply_original_asset_resolution_batch(batch("asset-1", resolution))
                .is_err()
        );
        assert_eq!(manifest, before);
    }
}

#[test]
fn existing_original_and_resolution_proofs_are_a_strict_remote_identity_index() {
    for proof_key in ["original_asset", "original_asset_resolution"] {
        let mut manifest = Manifest::new();
        manifest.upsert(failed_resolver_record("target"));
        let mut malformed = AssetRecord::new("malformed", "/nas/photos/malformed.dng");
        malformed.state = State::NoAction;
        malformed.proofs.insert(
            proof_key.to_string(),
            serde_json::json!({"malformed": true}),
        );
        manifest.upsert(malformed);
        let before = manifest.clone();

        assert!(
            manifest
                .apply_original_asset_resolution_batch(batch("target", exact_original_resolution()))
                .is_err()
        );
        assert_eq!(
            manifest, before,
            "{proof_key} must fail closed when malformed"
        );
    }

    let mut historical = Manifest::new();
    historical.upsert(failed_resolver_record("historic"));
    historical
        .apply_original_asset_resolution_batch(batch("historic", replacement_resolution()))
        .unwrap();
    let historical_record = historical.get("historic").unwrap().clone();

    let mut manifest = Manifest::new();
    manifest.upsert(failed_resolver_record("target"));
    manifest.upsert(historical_record);
    let before = manifest.clone();
    assert!(
        manifest
            .apply_original_asset_resolution_batch(batch("target", replacement_resolution()))
            .is_err()
    );
    assert_eq!(manifest, before);

    let mut historical = Manifest::new();
    historical.upsert(failed_resolver_record("historic-exact"));
    historical
        .apply_original_asset_resolution_batch(batch("historic-exact", exact_original_resolution()))
        .unwrap();
    let mut historical_record = historical.get("historic-exact").unwrap().clone();
    historical_record.proofs.remove("original_asset");
    let mut manifest = Manifest::new();
    manifest.upsert(failed_resolver_record("target-exact"));
    manifest.upsert(historical_record);
    let before = manifest.clone();
    assert!(
        manifest
            .apply_original_asset_resolution_batch(batch(
                "target-exact",
                exact_original_resolution()
            ))
            .is_err()
    );
    assert_eq!(manifest, before);
}

#[test]
fn batch_application_is_atomic_for_bad_source_outcome_transient_and_inventory() {
    let cases = ["bad-source", "bad-outcome", "transient", "bad-inventory"];
    for case in cases {
        let mut manifest = Manifest::new();
        manifest.upsert(failed_resolver_record("asset-a"));
        manifest.upsert(failed_resolver_record("asset-b"));
        let resolutions = BTreeMap::from([
            ("asset-a".to_string(), exact_original_resolution()),
            ("asset-b".to_string(), exact_original_resolution()),
        ]);
        let mut resolution_batch = OriginalAssetResolutionBatch {
            targets: vec![target("asset-a"), target("asset-b")],
            destination: CloudKitLibraryDestination::primary_sync(),
            inventory: CloudKitOriginalAssetInventoryFingerprint {
                resolver_version: "cloudkit-original-asset-reconcile-v1".to_string(),
                sha256: "a".repeat(64),
                records_scanned: 2,
            },
            observed_at_unix_seconds: 1_800_000_000,
            resolutions,
        };

        match case {
            "bad-source" => {
                let mut bad = manifest.get("asset-b").unwrap().clone();
                bad.proofs.remove("source_age");
                manifest.upsert(bad);
            }
            "bad-outcome" => {
                let CloudKitOriginalAssetResolveDisposition::ExactOriginal { proof } =
                    &mut resolution_batch
                        .resolutions
                        .get_mut("asset-b")
                        .unwrap()
                        .disposition
                else {
                    unreachable!();
                };
                proof.record_name = "CPLAsset-original-b".to_string();
                proof.size_bytes = 41;
            }
            "transient" => {
                resolution_batch
                    .resolutions
                    .get_mut("asset-b")
                    .unwrap()
                    .disposition = CloudKitOriginalAssetResolveDisposition::IncompleteTransient;
            }
            "bad-inventory" => resolution_batch.inventory.sha256 = "not-a-fingerprint".to_string(),
            _ => unreachable!(),
        }

        let before = manifest.clone();
        assert!(
            manifest
                .apply_original_asset_resolution_batch(resolution_batch)
                .is_err()
        );
        assert_eq!(
            manifest, before,
            "{case} must not partially mutate the manifest"
        );
    }
}

#[test]
fn source_binding_and_duplicate_remote_identity_fail_closed() {
    let mut manifest = Manifest::new();
    manifest.upsert(failed_resolver_record("asset-a"));
    let before = manifest.clone();
    let mut source_mismatch = batch("asset-a", exact_original_resolution());
    source_mismatch.targets[0].matched_raw_sha256 = "different-sha".to_string();
    assert!(
        manifest
            .apply_original_asset_resolution_batch(source_mismatch)
            .is_err()
    );
    assert_eq!(manifest, before);

    manifest.upsert(failed_resolver_record("asset-b"));
    let before = manifest.clone();
    let duplicate_remote = OriginalAssetResolutionBatch {
        targets: vec![target("asset-a"), target("asset-b")],
        destination: CloudKitLibraryDestination::primary_sync(),
        inventory: CloudKitOriginalAssetInventoryFingerprint {
            resolver_version: "cloudkit-original-asset-reconcile-v1".to_string(),
            sha256: "a".repeat(64),
            records_scanned: 2,
        },
        observed_at_unix_seconds: 1_800_000_000,
        resolutions: BTreeMap::from([
            ("asset-a".to_string(), exact_original_resolution()),
            ("asset-b".to_string(), exact_original_resolution()),
        ]),
    };
    assert!(
        manifest
            .apply_original_asset_resolution_batch(duplicate_remote)
            .is_err()
    );
    assert_eq!(manifest, before);
}

#[test]
fn resolution_proof_and_legacy_record_json_round_trip() {
    let mut manifest = Manifest::new();
    manifest.upsert(failed_resolver_record("asset-1"));
    manifest
        .apply_original_asset_resolution_batch(batch("asset-1", exact_original_resolution()))
        .unwrap();
    let value = manifest.get("asset-1").unwrap().proofs["original_asset_resolution"].clone();
    let proof: OriginalAssetResolutionProof = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(proof).unwrap(), value);

    let legacy = serde_json::json!({
        "asset_id": "legacy",
        "raw_path": "/nas/photos/legacy.dng",
        "state": "upload_verified",
        "proofs": {},
        "failures": [],
        "updated_at": "1700000000.000000000Z"
    });
    let record: AssetRecord = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(record.state, State::UploadVerified);
    assert_eq!(serde_json::to_value(record).unwrap(), legacy);
}

#[test]
fn reconciliation_terminal_states_freeze_source_age_proofs() {
    for state in [State::NoAction, State::NeedsReview] {
        let mut manifest = Manifest::new();
        let mut record = failed_resolver_record(state.as_str());
        record.state = state;
        manifest.upsert(record);

        let error = record_source_age_proof(
            &mut manifest,
            state.as_str(),
            SourceAgeProof {
                source_captured_unix_seconds: 1_700_000_000,
                verified_at_unix_seconds: 1_800_000_000,
                min_age_seconds: 30 * DAY,
            },
        )
        .expect_err("terminal reconciliation classifications must freeze source proof updates");
        assert!(matches!(error, WorkflowError::SourceAgeProofFrozen { .. }));
    }
}

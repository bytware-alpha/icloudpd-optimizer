use std::collections::BTreeMap;
use std::path::PathBuf;

use icloudpd_optimizer::manifest::{AssetRecord, FailureRecord, Manifest, State};
use icloudpd_optimizer::proof::NasRawProof;
use icloudpd_optimizer::reconciliation::{
    OriginalAssetResolutionBatch, OriginalAssetResolutionProof,
};
use icloudpd_optimizer::upload::{
    CloudKitLibraryDestination, CloudKitLocalReplacementCandidate,
    CloudKitOriginalAssetInventoryFingerprint, CloudKitOriginalAssetResolution,
    CloudKitOriginalAssetResolveDisposition, CloudKitOriginalAssetResolveObservations,
    CloudKitOriginalAssetResolveTarget, CloudKitReplacementResourceProof,
};
use icloudpd_optimizer::workflow::{
    ConversionResultProof, HeicVerificationProof, OriginalAssetProof, SourceAgeProof, UploadProof,
    WorkflowError, mark_delete_eligible, record_source_age_proof,
};

const DAY: u64 = 24 * 60 * 60;

fn target(asset_id: &str) -> CloudKitOriginalAssetResolveTarget {
    CloudKitOriginalAssetResolveTarget {
        asset_id: asset_id.to_string(),
        raw_size_bytes: 42,
        source_captured_unix_seconds: 1_700_000_000,
        capture_tolerance_seconds: 60,
        filename: "IMG_0001.dng".to_string(),
        matched_raw_sha256: "raw-sha256".to_string(),
        replacement_candidate: None,
    }
}

fn exact_original_resolution() -> CloudKitOriginalAssetResolution {
    CloudKitOriginalAssetResolution {
        observations: CloudKitOriginalAssetResolveObservations::default(),
        disposition: CloudKitOriginalAssetResolveDisposition::ExactOriginal {
            proof: OriginalAssetProof {
                record_name: "CPLAsset-original".to_string(),
                record_change_tag: "change-tag".to_string(),
                record_type: "CPLAsset".to_string(),
                database_scope: Default::default(),
                zone_name: "PrimarySync".to_string(),
                filename: "IMG_0001.dng".to_string(),
                size_bytes: 42,
                matched_raw_sha256: "raw-sha256".to_string(),
            },
        },
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
            sha256: "raw-sha256".to_string(),
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
            sha256: "heic-sha256".to_string(),
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
        observations: CloudKitOriginalAssetResolveObservations::default(),
        disposition: CloudKitOriginalAssetResolveDisposition::ReplacementPresent {
            proof: CloudKitReplacementResourceProof {
                record_name: "CPLAsset-replacement".to_string(),
                record_change_tag: "replacement-tag".to_string(),
                record_type: "CPLAsset".to_string(),
                database_scope: Default::default(),
                zone_name: "PrimarySync".to_string(),
                resource_field: "resOriginalRes".to_string(),
                size_bytes: 24,
                matched_heic_sha256: "heic-sha256".to_string(),
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
            heic_sha256: "heic-sha256".to_string(),
            size_bytes: 24,
        })
        .unwrap(),
    );
    if matches!(strength, State::ConversionVerified | State::UploadVerified) {
        record.proofs.insert(
            "heic".to_string(),
            serde_json::to_value(HeicVerificationProof {
                heic_path: PathBuf::from("/staging/IMG_0001.heic"),
                heic_sha256: "heic-sha256".to_string(),
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
                uploaded_heic_sha256: "heic-sha256".to_string(),
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
            observations: CloudKitOriginalAssetResolveObservations::default(),
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

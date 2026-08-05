use std::path::PathBuf;

use icloudpd_optimizer::manifest::{AssetRecord, Manifest, ManifestError, State};
use serde_json::json;

#[test]
fn allows_full_linear_safety_transitions_with_proofs() {
    let mut manifest = Manifest::new();
    manifest.upsert(AssetRecord::new(
        "asset-1",
        PathBuf::from("/photos/raw/asset-1.dng"),
    ));

    let transitions = [
        (
            State::NasVerified,
            "nas",
            json!({"path": "/nas/asset-1.dng", "size": 10}),
        ),
        (
            State::Converted,
            "conversion",
            json!({"heic_path": "/tmp/asset-1.heic"}),
        ),
        (
            State::ConversionVerified,
            "heic",
            json!({"sha256": "abc123"}),
        ),
        (
            State::UploadVerified,
            "upload",
            json!({"icloud_asset_id": "asset-1-heic"}),
        ),
        (
            State::DeleteEligible,
            "eligibility",
            json!({"reason": "upload accepted"}),
        ),
        (
            State::DeleteApproved,
            "approval",
            json!({"approved_by": "operator"}),
        ),
        (
            State::Deleted,
            "delete",
            json!({"deleted_at": "2026-06-21T12:00:00Z"}),
        ),
    ];

    for (state, proof_name, proof) in transitions {
        manifest
            .transition("asset-1", state, proof_name, proof)
            .expect("linear transition should be accepted");
    }

    let record = manifest.get("asset-1").expect("asset should exist");
    assert_eq!(record.state, State::Deleted);
    assert_eq!(record.proofs["nas"]["path"], "/nas/asset-1.dng");
    assert_eq!(record.proofs["upload"]["icloud_asset_id"], "asset-1-heic");
    assert_eq!(
        record.proofs["delete"]["deleted_at"],
        "2026-06-21T12:00:00Z"
    );
}

#[test]
fn rejects_skip_straight_to_deleted_without_mutating_asset() {
    let mut manifest = Manifest::new();
    manifest.upsert(AssetRecord::new(
        "asset-1",
        PathBuf::from("/photos/raw/asset-1.dng"),
    ));
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let err = manifest
        .transition(
            "asset-1",
            State::Deleted,
            "delete",
            json!({"deleted_at": "now"}),
        )
        .expect_err("skip to deleted must fail closed");

    assert!(matches!(err, ManifestError::InvalidTransition { .. }));
    assert!(err.to_string().contains("discovered -> deleted"));
    let after = manifest.get("asset-1").expect("asset should exist");
    assert_eq!(after, &before);
    assert_eq!(after.state, State::Discovered);
    assert!(!after.proofs.contains_key("delete"));
}

#[test]
fn rejects_late_skip_to_delete_eligible_without_mutating_asset() {
    let mut manifest = Manifest::new();
    manifest.upsert(AssetRecord::new(
        "asset-1",
        PathBuf::from("/photos/raw/asset-1.dng"),
    ));
    manifest
        .transition(
            "asset-1",
            State::NasVerified,
            "nas",
            json!({"path": "/nas/asset-1.dng"}),
        )
        .expect("nas transition should pass");
    manifest
        .transition(
            "asset-1",
            State::Converted,
            "conversion",
            json!({"heic_path": "/tmp/asset-1.heic"}),
        )
        .expect("conversion transition should pass");
    manifest
        .transition(
            "asset-1",
            State::ConversionVerified,
            "heic",
            json!({"sha256": "abc123"}),
        )
        .expect("verification transition should pass");
    let before = manifest.get("asset-1").expect("asset should exist").clone();

    let err = manifest
        .transition(
            "asset-1",
            State::DeleteEligible,
            "eligibility",
            json!({"reason": "skip"}),
        )
        .expect_err("late delete eligibility skip must fail closed");

    assert!(matches!(err, ManifestError::InvalidTransition { .. }));
    assert!(
        err.to_string()
            .contains("conversion_verified -> delete_eligible")
    );
    assert_eq!(
        manifest.get("asset-1").expect("asset should exist"),
        &before
    );
}

#[test]
fn record_failure_preserves_proofs_and_does_not_add_delete_proof() {
    let mut manifest = Manifest::new();
    manifest.upsert(AssetRecord::new(
        "asset-1",
        PathBuf::from("/photos/raw/asset-1.dng"),
    ));
    manifest
        .transition(
            "asset-1",
            State::NasVerified,
            "nas",
            json!({"path": "/nas/asset-1.dng"}),
        )
        .expect("nas transition should pass");

    let failed = manifest
        .record_failure("asset-1", "conversion", "dcraw failed")
        .expect("failure should be recorded");

    assert_eq!(failed.state, State::Failed);
    assert_eq!(
        failed.proofs,
        [("nas".to_string(), json!({"path": "/nas/asset-1.dng"}))].into()
    );
    assert_eq!(failed.failures.len(), 1);
    assert_eq!(failed.failures[0].stage, "conversion");
    assert_eq!(failed.failures[0].message, "dcraw failed");
    assert!(!failed.proofs.contains_key("delete"));
}

#[test]
fn save_atomic_and_load_roundtrip_manifest_records() {
    let tempdir = tempfile::tempdir().expect("tempdir should be created");
    let path = tempdir.path().join("manifest.json");
    let mut manifest = Manifest::new();
    manifest.upsert(AssetRecord::new(
        "asset-1",
        PathBuf::from("/photos/raw/asset-1.dng"),
    ));
    manifest
        .transition(
            "asset-1",
            State::NasVerified,
            "nas",
            json!({"path": "/nas/asset-1.dng"}),
        )
        .expect("nas transition should pass");
    manifest
        .record_failure("asset-1", "conversion", "dcraw failed")
        .expect("failure should be recorded");

    manifest
        .save_atomic(&path)
        .expect("manifest should save atomically");
    let loaded = Manifest::load(&path).expect("manifest should load");

    assert_eq!(
        loaded.get("asset-1").expect("loaded asset should exist"),
        manifest.get("asset-1").expect("saved asset should exist")
    );
    assert_eq!(loaded.records(), manifest.records());
}

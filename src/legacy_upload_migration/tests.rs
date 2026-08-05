use std::cell::Cell;
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use super::{
    LEGACY_UPLOAD_MIGRATION_PROOF_NAME, LEGACY_UPLOAD_MIGRATION_SCHEMA_VERSION,
    LegacyUploadMigrationAuthorizedPhaseTransition, LegacyUploadMigrationAuthorizedPreparation,
    LegacyUploadMigrationCasUpdate, LegacyUploadMigrationCohortAuthority,
    LegacyUploadMigrationCommitError, LegacyUploadMigrationError, LegacyUploadMigrationIdentity,
    LegacyUploadMigrationJournal, LegacyUploadMigrationManifestRecordAuthority,
    LegacyUploadMigrationPhase, LegacyUploadMigrationPhaseAuthority,
    LegacyUploadMigrationQuarantineFileIdentity, LegacyUploadMigrationQuarantineKind,
    LegacyUploadMigrationQuarantineMember, LegacyUploadMigrationQuarantinePlan,
    LegacyUploadMigrationQuarantineRoot, LegacyUploadMigrationRawInput,
    LegacyUploadMigrationTransitionShape,
    advance_legacy_upload_migration_record as advance_authorized_record,
    advance_legacy_upload_migration_record_with_witness as advance_legacy_upload_migration_record,
    canonical_digest, classify_legacy_upload_migration_records,
    legacy_upload_migration_record_digest,
    persist_two_legacy_upload_migration_preparations_exact_cas,
    persist_two_legacy_upload_migration_records_exact_cas as persist_authorized_records,
    persist_two_legacy_upload_migration_records_exact_cas_internal as persist_two_legacy_upload_migration_records_exact_cas,
    phase_authority_witness_sha256, prepare_legacy_upload_migration_record,
    seal_legacy_upload_migration_quarantine_plan, validate_journal_for_record,
    validate_legacy_upload_migration_record, validate_legacy_upload_migration_record_update,
};
use crate::manifest::{
    AssetRecord, FailureKind, FailureQuarantineProof, FailureRecord, Manifest, ManifestError, State,
};
use crate::state_store::{AssetRecordExactCasUpdate, AssetStateStore, AssetStateStoreError};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn digest(label: &str) -> String {
    format!("{:x}", Sha256::digest(label.as_bytes()))
}

fn registry_row_count(store: &AssetStateStore) -> i64 {
    rusqlite::Connection::open(store.path())
        .unwrap()
        .query_row(
            "SELECT count(*) FROM legacy_upload_migration_registry",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

fn durable_asset_rows(store: &AssetStateStore) -> Vec<(String, String)> {
    let connection = rusqlite::Connection::open(store.path()).unwrap();
    let mut statement = connection
        .prepare("SELECT asset_id, record_json FROM assets ORDER BY asset_id")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn record(asset_id: &str) -> AssetRecord {
    AssetRecord {
        asset_id: asset_id.to_string(),
        raw_path: format!("/raw/{asset_id}.dng").into(),
        state: State::UploadVerified,
        proofs: BTreeMap::from([
            ("nas".to_string(), json!({"sha256": digest("raw")})),
            (
                "original_asset".to_string(),
                json!({"record_name": format!("original-{asset_id}")}),
            ),
            (
                "conversion".to_string(),
                json!({"sha256": digest("conversion")}),
            ),
            ("upload".to_string(), json!({"sha256": digest("upload")})),
            (
                "icloudpd_local_mirror".to_string(),
                json!({"sha256": digest("mirror")}),
            ),
        ]),
        failures: vec![FailureRecord::new("historical", "preserve")],
        updated_at: "2026-07-13T00:00:00Z".to_string(),
    }
}

fn lifecycle_conversion_proofs(asset_id: &str) -> BTreeMap<String, Value> {
    let heic_path = format!("/heic/{asset_id}.heic");
    let heic_sha256 = digest(&format!("new-heic-{asset_id}"));
    BTreeMap::from([
        (
            "conversion".to_string(),
            json!({
                "heic_path": heic_path,
                "heic_sha256": heic_sha256,
                "size_bytes": 50,
                "conversion_recipe_id": "embedded-preview-normalized-v1",
                "source_binding": "embedded_preview",
            }),
        ),
        (
            "conversion_performance".to_string(),
            json!({
                "schema_version": 1,
                "measured_at_unix_seconds": 1_752_400_000_u64,
                "measurement_method": "monotonic_wall_clock",
                "conversion_tool": "sips",
                "conversion_recipe_id": "embedded-preview-normalized-v1",
                "heic_quality": 90,
                "raw_size_bytes": 100,
                "heic_size_bytes": 50,
                "convert_wall_time_millis": 10,
                "total_wall_time_millis": 12,
            }),
        ),
        (
            "heic".to_string(),
            json!({
                "heic_path": heic_path,
                "heic_sha256": heic_sha256,
                "size_bytes": 50,
                "conversion_recipe_id": "embedded-preview-normalized-v1",
                "heif_info_ok": true,
                "metadata_copied": true,
                "visual_content_ok": true,
                "visual_match_ok": true,
            }),
        ),
    ])
}

fn lifecycle_upload_proof(asset_id: &str) -> Value {
    json!({
        "uploaded_heic_asset_id": format!("new-upload-{asset_id}"),
        "uploaded_heic_sha256": digest(&format!("new-heic-{asset_id}")),
        "database_scope": "private",
        "zone_name": "PrimarySync",
        "uploaded_heic_path": format!("/heic/{asset_id}.heic"),
    })
}

fn lifecycle_mirror_proof(asset_id: &str) -> Value {
    json!({
        "uploaded_heic_asset_id": format!("new-upload-{asset_id}"),
        "uploaded_heic_sha256": digest(&format!("new-heic-{asset_id}")),
        "uploaded_heic_path": format!("/heic/{asset_id}.heic"),
        "icloudpd_download_path": format!("/mirror/{asset_id}.heic"),
        "size_bytes": 50,
    })
}

fn lifecycle_record(asset_id: &str) -> AssetRecord {
    let raw_path = format!("/raw/{asset_id}.dng");
    let old_heic_path = format!("/heic/old-{asset_id}.heic");
    let old_heic_sha256 = digest(&format!("old-heic-{asset_id}"));
    AssetRecord {
        asset_id: asset_id.to_string(),
        raw_path: raw_path.clone().into(),
        state: State::UploadVerified,
        proofs: BTreeMap::from([
            (
                "nas".to_string(),
                json!({
                    "canonical_path": raw_path,
                    "relative_path": format!("{asset_id}.dng"),
                    "size_bytes": 100,
                    "modified_unix_seconds": 1_700_000_000_u64,
                    "age_seconds": 3_000_000_u64,
                    "sha256": digest(&format!("raw-{asset_id}")),
                }),
            ),
            (
                "original_asset".to_string(),
                json!({
                    "record_name": format!("original-{asset_id}"),
                    "record_change_tag": "original-tag",
                    "record_type": "CPLMaster",
                    "database_scope": "private",
                    "zone_name": "PrimarySync",
                    "filename": format!("{asset_id}.dng"),
                    "size_bytes": 100,
                    "matched_raw_sha256": digest(&format!("raw-{asset_id}")),
                }),
            ),
            (
                "source_age".to_string(),
                json!({
                    "source_captured_unix_seconds": 1_700_000_000_u64,
                    "verified_at_unix_seconds": 1_703_000_000_u64,
                    "min_age_seconds": 2_592_000_u64,
                }),
            ),
            (
                "conversion".to_string(),
                json!({
                    "heic_path": old_heic_path,
                    "heic_sha256": old_heic_sha256,
                    "size_bytes": 40,
                    "conversion_recipe_id": "embedded-preview-normalized-v1",
                    "source_binding": "embedded_preview",
                }),
            ),
            (
                "conversion_performance".to_string(),
                json!({
                    "schema_version": 1,
                    "measured_at_unix_seconds": 1_703_000_000_u64,
                    "measurement_method": "monotonic_wall_clock",
                    "conversion_tool": "sips",
                    "conversion_recipe_id": "embedded-preview-normalized-v1",
                    "heic_quality": 90,
                    "raw_size_bytes": 100,
                    "heic_size_bytes": 40,
                    "convert_wall_time_millis": 9,
                    "total_wall_time_millis": 11,
                }),
            ),
            (
                "heic".to_string(),
                json!({
                    "heic_path": old_heic_path,
                    "heic_sha256": old_heic_sha256,
                    "size_bytes": 40,
                    "conversion_recipe_id": "embedded-preview-normalized-v1",
                    "heif_info_ok": true,
                    "metadata_copied": true,
                    "visual_content_ok": true,
                    "visual_match_ok": true,
                }),
            ),
            (
                "upload".to_string(),
                json!({
                    "uploaded_heic_asset_id": format!("old-upload-{asset_id}"),
                    "uploaded_heic_sha256": old_heic_sha256,
                    "database_scope": "private",
                    "zone_name": "PrimarySync",
                    "uploaded_heic_path": old_heic_path,
                }),
            ),
            (
                "icloudpd_local_mirror".to_string(),
                json!({
                    "uploaded_heic_asset_id": format!("old-upload-{asset_id}"),
                    "uploaded_heic_sha256": old_heic_sha256,
                    "uploaded_heic_path": old_heic_path,
                    "icloudpd_download_path": format!("/mirror/old-{asset_id}.heic"),
                    "size_bytes": 40,
                }),
            ),
        ]),
        failures: vec![FailureRecord::new("historical", "preserve")],
        updated_at: "2026-07-13T00:00:00Z".to_string(),
    }
}

fn lifecycle_phase_candidate(
    current: &AssetRecord,
    phase: LegacyUploadMigrationPhase,
) -> AssetRecord {
    let mut candidate = current.clone();
    match phase {
        LegacyUploadMigrationPhase::Reset => {
            candidate.state = State::NasVerified;
            for proof_name in [
                "conversion",
                "conversion_performance",
                "heic",
                "upload",
                "icloudpd_local_mirror",
            ] {
                candidate.proofs.remove(proof_name);
            }
        }
        LegacyUploadMigrationPhase::Converted => {
            candidate.state = State::ConversionVerified;
            candidate
                .proofs
                .extend(lifecycle_conversion_proofs(&candidate.asset_id));
        }
        LegacyUploadMigrationPhase::UploadVerified => {
            candidate.state = State::UploadVerified;
            candidate.proofs.insert(
                "upload".to_string(),
                lifecycle_upload_proof(&candidate.asset_id),
            );
        }
        LegacyUploadMigrationPhase::Mirrored => {
            candidate.proofs.insert(
                "icloudpd_local_mirror".to_string(),
                lifecycle_mirror_proof(&candidate.asset_id),
            );
        }
        _ => {}
    }
    candidate
}

fn lifecycle_candidate(current: &AssetRecord, phase: LegacyUploadMigrationPhase) -> AssetRecord {
    let candidate = lifecycle_phase_candidate(current, phase);
    advance_legacy_upload_migration_record(&candidate, phase, &witness(phase)).unwrap()
}

fn lifecycle_record_at_phase(asset_id: &str, target: LegacyUploadMigrationPhase) -> AssetRecord {
    let mut current = prepare(&lifecycle_record(asset_id));
    if target == LegacyUploadMigrationPhase::Prepared {
        return current;
    }
    for phase in LegacyUploadMigrationPhase::ORDER.into_iter().skip(1) {
        current = lifecycle_candidate(&current, phase);
        if phase == target {
            return current;
        }
    }
    unreachable!("target phase belongs to the fixed migration order")
}

fn identity_for(record: &AssetRecord) -> LegacyUploadMigrationIdentity {
    let quarantine_plan =
        seal_legacy_upload_migration_quarantine_plan(LegacyUploadMigrationQuarantinePlan {
            schema_version: 1,
            roots: vec![LegacyUploadMigrationQuarantineRoot {
                canonical_path: PathBuf::from("/quarantine"),
                device: 1,
                inode: 1,
                owner: 501,
                mode: 0o700,
            }],
            members: (0..9)
                .map(|index| LegacyUploadMigrationQuarantineMember {
                    asset_id: format!("member-{index}"),
                    kind: match index {
                        0..=1 => LegacyUploadMigrationQuarantineKind::Final,
                        2..=6 => LegacyUploadMigrationQuarantineKind::Reference,
                        _ => LegacyUploadMigrationQuarantineKind::OldMirror,
                    },
                    source_path: PathBuf::from(format!("/source/{index}")),
                    destination_path: PathBuf::from(format!("/quarantine/cohort/{index}")),
                    source: LegacyUploadMigrationQuarantineFileIdentity {
                        device: 1,
                        inode: index + 10,
                        owner: 501,
                        mode: 0o600,
                        link_count: 1,
                        size_bytes: 1,
                        modified_unix_seconds: 1,
                        modified_unix_nanoseconds: 0,
                        sha256: digest(&format!("member-{index}")),
                    },
                    root_device: 1,
                })
                .collect(),
            raw_inputs: (0..10)
                .map(|index| LegacyUploadMigrationRawInput {
                    asset_id: format!("raw-{index}"),
                    path: PathBuf::from(format!("/raw/{index}")),
                    source: LegacyUploadMigrationQuarantineFileIdentity {
                        device: 3,
                        inode: index + 100,
                        owner: 501,
                        mode: 0o600,
                        link_count: 1,
                        size_bytes: 1,
                        modified_unix_seconds: 1,
                        modified_unix_nanoseconds: 0,
                        sha256: digest(&format!("raw-{index}")),
                    },
                })
                .collect(),
            plan_sha256: String::new(),
        })
        .unwrap();
    LegacyUploadMigrationIdentity {
        migration_id: digest("migration"),
        evidence_sha256: digest("evidence"),
        cohort_sha256: digest("cohort"),
        asset_id: record.asset_id.clone(),
        source_record_sha256: legacy_upload_migration_record_digest(record).unwrap(),
        old_uploaded_asset_id: format!("replacement-{}", record.asset_id),
        old_uploaded_master_id: format!("replacement-master-{}", record.asset_id),
        destination_sha256: digest("destination"),
        original_asset_identity_sha256: digest("original"),
        old_conversion_lineage_sha256: digest("conversion-lineage"),
        old_upload_lineage_sha256: digest("upload-lineage"),
        old_mirror_lineage_sha256: digest("mirror-lineage"),
        quarantine_plan,
    }
}

fn witness(phase: LegacyUploadMigrationPhase) -> String {
    digest(phase.as_str())
}

#[test]
fn two_device_quarantine_plan_seals_exact_members_and_rejects_device_drift() {
    let mut plan = identity_for(&lifecycle_record("asset-plan")).quarantine_plan;
    plan.roots.push(LegacyUploadMigrationQuarantineRoot {
        canonical_path: PathBuf::from("/nas-quarantine"),
        device: 2,
        inode: 2,
        owner: 501,
        mode: 0o700,
    });
    for member in plan.members.iter_mut().skip(6) {
        member.source.device = 2;
        member.root_device = 2;
        member.destination_path = PathBuf::from("/nas-quarantine/cohort")
            .join(member.destination_path.file_name().unwrap());
    }
    let sealed = seal_legacy_upload_migration_quarantine_plan(plan).unwrap();
    assert_eq!(sealed.roots.len(), 2);
    assert_eq!(
        sealed
            .members
            .iter()
            .filter(|member| member.root_device == 2)
            .count(),
        3
    );

    let mut drifted = sealed;
    drifted.members[0].root_device = 2;
    assert!(seal_legacy_upload_migration_quarantine_plan(drifted).is_err());
}

fn test_cohort_authority(
    first: &AssetRecord,
    second: &AssetRecord,
) -> LegacyUploadMigrationCohortAuthority {
    LegacyUploadMigrationCohortAuthority {
        preparations: [first, second].map(|record| LegacyUploadMigrationAuthorizedPreparation {
            identity: identity_for(record),
            prepared_witness_sha256: witness(LegacyUploadMigrationPhase::Prepared),
        }),
    }
}

fn prepare_authorized(
    record: &AssetRecord,
    authority: &LegacyUploadMigrationCohortAuthority,
) -> AssetRecord {
    prepare_legacy_upload_migration_record(record, authority).unwrap()
}

fn prepare_authorized_pair(
    first: &AssetRecord,
    second: &AssetRecord,
) -> (
    LegacyUploadMigrationCohortAuthority,
    AssetRecord,
    AssetRecord,
) {
    let authority = test_cohort_authority(first, second);
    let prepared_first = prepare_authorized(first, &authority);
    let prepared_second = prepare_authorized(second, &authority);
    (authority, prepared_first, prepared_second)
}

fn test_phase_authority(
    expected: [&AssetRecord; 2],
    candidates: [&AssetRecord; 2],
    to: LegacyUploadMigrationPhase,
) -> (LegacyUploadMigrationPhaseAuthority, [AssetRecord; 2]) {
    let journals =
        candidates.map(|candidate| validate_journal_for_record(candidate, false).unwrap());
    let from = journals[0].entries.last().unwrap().phase;
    assert_eq!(journals[1].entries.last().unwrap().phase, from);
    let identity = &journals[0].identity;
    assert_eq!(journals[1].identity.migration_id, identity.migration_id);
    assert_eq!(
        journals[1].identity.evidence_sha256,
        identity.evidence_sha256
    );
    assert_eq!(journals[1].identity.cohort_sha256, identity.cohort_sha256);

    let transitions = std::array::from_fn(|index| {
        let expected_record_sha256 =
            legacy_upload_migration_record_digest(expected[index]).unwrap();
        let candidate_record_sha256 =
            legacy_upload_migration_record_digest(candidates[index]).unwrap();
        let payload_sha256 = canonical_digest(&json!({
            "schema_version": 1,
            "asset_id": candidates[index].asset_id,
            "from": from,
            "to": to,
            "expected_record_sha256": expected_record_sha256,
            "candidate_record_sha256": candidate_record_sha256,
            "typed_gate_receipt_sha256": digest(&format!(
                "typed-gate-{}-{}",
                candidates[index].asset_id,
                to.as_str()
            )),
        }))
        .unwrap();
        LegacyUploadMigrationAuthorizedPhaseTransition {
            asset_id: candidates[index].asset_id.clone(),
            expected_record_sha256,
            candidate_record_sha256,
            updated_record_sha256: digest("pending-updated-record"),
            payload_sha256,
            witness_sha256: digest("pending-phase-witness"),
        }
    });
    let mut authority = LegacyUploadMigrationPhaseAuthority {
        migration_id: identity.migration_id.clone(),
        evidence_sha256: identity.evidence_sha256.clone(),
        cohort_sha256: identity.cohort_sha256.clone(),
        from,
        to,
        transitions,
    };
    for index in 0..authority.transitions.len() {
        let witness =
            phase_authority_witness_sha256(&authority, &authority.transitions[index]).unwrap();
        authority.transitions[index].witness_sha256 = witness;
    }
    let updated = std::array::from_fn(|index| {
        advance_legacy_upload_migration_record(
            candidates[index],
            to,
            &authority.transitions[index].witness_sha256,
        )
        .unwrap()
    });
    for (transition, updated) in authority.transitions.iter_mut().zip(&updated) {
        transition.updated_record_sha256 = legacy_upload_migration_record_digest(updated).unwrap();
    }
    (authority, updated)
}

pub(crate) fn db_loaded_lifecycle_pair_at_phase(
    target: LegacyUploadMigrationPhase,
) -> (tempfile::TempDir, AssetStateStore, Manifest) {
    let temp = tempfile::tempdir().unwrap();
    let manifest_path = temp.path().join("manifest.json");
    let mut seed = Manifest::new();
    seed.upsert(lifecycle_record("asset-a"));
    seed.upsert(lifecycle_record("asset-b"));
    seed.save_atomic(&manifest_path).unwrap();

    let writer = AssetStateStore::open_writer(
        &manifest_path,
        "legacy-upload-migration-generic-mutator-test",
        Duration::from_secs(30),
    )
    .unwrap();
    let initial = writer.load_or_import().unwrap();
    let initial_a = initial.get("asset-a").unwrap().clone();
    let initial_b = initial.get("asset-b").unwrap().clone();
    let (preparation_authority, prepared_a, prepared_b) =
        prepare_authorized_pair(&initial_a, &initial_b);
    persist_two_legacy_upload_migration_preparations_exact_cas(
        &writer,
        &preparation_authority,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &initial_a,
                updated: &prepared_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &initial_b,
                updated: &prepared_b,
            },
        ],
    )
    .unwrap();

    let mut current_a = prepared_a;
    let mut current_b = prepared_b;
    if target != LegacyUploadMigrationPhase::Prepared {
        for phase in LegacyUploadMigrationPhase::ORDER.into_iter().skip(1) {
            let candidate_a = lifecycle_phase_candidate(&current_a, phase);
            let candidate_b = lifecycle_phase_candidate(&current_b, phase);
            let (phase_authority, [updated_a, updated_b]) = test_phase_authority(
                [&current_a, &current_b],
                [&candidate_a, &candidate_b],
                phase,
            );
            persist_authorized_records(
                &writer,
                &phase_authority,
                [
                    LegacyUploadMigrationCasUpdate {
                        expected: &current_a,
                        updated: &updated_a,
                    },
                    LegacyUploadMigrationCasUpdate {
                        expected: &current_b,
                        updated: &updated_b,
                    },
                ],
            )
            .unwrap();
            current_a = updated_a;
            current_b = updated_b;
            if phase == target {
                break;
            }
        }
    }

    writer.export_json().unwrap();
    let durable = writer.load().unwrap();
    assert_eq!(
        validate_legacy_upload_migration_record(durable.get("asset-a").unwrap())
            .unwrap()
            .entries
            .last()
            .unwrap()
            .phase,
        target
    );
    (temp, writer, durable)
}

fn manifest_record_bytes(manifest: &Manifest) -> Vec<u8> {
    serde_json::to_vec(manifest.records()).unwrap()
}

fn assert_generic_manifest_mutation_rejected(
    durable: &Manifest,
    mutate: impl FnOnce(&mut Manifest) -> Result<(), ManifestError>,
) {
    let mut candidate = durable.clone();
    let before = manifest_record_bytes(&candidate);
    assert!(matches!(
        mutate(&mut candidate),
        Err(ManifestError::ReservedInternalProofRequiresAuthority)
    ));
    assert_eq!(manifest_record_bytes(&candidate), before);
}

fn reseal_phase_authority(authority: &mut LegacyUploadMigrationPhaseAuthority) {
    for index in 0..authority.transitions.len() {
        let witness =
            phase_authority_witness_sha256(authority, &authority.transitions[index]).unwrap();
        authority.transitions[index].witness_sha256 = witness;
    }
}

fn assert_phase_authority_rejected_without_writes(
    writer: &AssetStateStore,
    authority: &LegacyUploadMigrationPhaseAuthority,
    expected: [&AssetRecord; 2],
    updated: [&AssetRecord; 2],
) {
    let before = writer.load().unwrap();
    assert!(matches!(
        persist_authorized_records(
            writer,
            authority,
            [
                LegacyUploadMigrationCasUpdate {
                    expected: expected[0],
                    updated: updated[0],
                },
                LegacyUploadMigrationCasUpdate {
                    expected: expected[1],
                    updated: updated[1],
                },
            ],
        ),
        Err(LegacyUploadMigrationCommitError::PhaseAuthorityMismatch)
    ));
    assert_eq!(writer.load().unwrap(), before);
}

fn set_state_for_phase(record: &mut AssetRecord, phase: LegacyUploadMigrationPhase) {
    record.state = match phase {
        LegacyUploadMigrationPhase::Prepared
        | LegacyUploadMigrationPhase::DeleteConfirmed
        | LegacyUploadMigrationPhase::Quarantined => State::UploadVerified,
        LegacyUploadMigrationPhase::Reset => State::NasVerified,
        LegacyUploadMigrationPhase::Converted | LegacyUploadMigrationPhase::UploadPrepared => {
            State::ConversionVerified
        }
        LegacyUploadMigrationPhase::UploadVerified
        | LegacyUploadMigrationPhase::Mirrored
        | LegacyUploadMigrationPhase::Complete => State::UploadVerified,
    };
}

fn prepare(record: &AssetRecord) -> AssetRecord {
    let companion = lifecycle_record(&format!("{}-test-authority-companion", record.asset_id));
    let authority = test_cohort_authority(record, &companion);
    prepare_authorized(record, &authority)
}

fn complete_journal(mut record: AssetRecord) -> AssetRecord {
    for phase in LegacyUploadMigrationPhase::ORDER.into_iter().skip(1) {
        set_state_for_phase(&mut record, phase);
        record = advance_legacy_upload_migration_record(&record, phase, &witness(phase)).unwrap();
    }
    record
}

fn journal(record: &AssetRecord) -> LegacyUploadMigrationJournal {
    serde_json::from_value(record.proofs[LEGACY_UPLOAD_MIGRATION_PROOF_NAME].clone()).unwrap()
}

fn replace_journal(record: &mut AssetRecord, journal: &LegacyUploadMigrationJournal) {
    record.proofs.insert(
        LEGACY_UPLOAD_MIGRATION_PROOF_NAME.to_string(),
        serde_json::to_value(journal).unwrap(),
    );
}

#[derive(Clone, Copy)]
enum UnknownFieldLocation {
    Journal,
    Identity,
    Entry(usize),
}

#[derive(Clone, Copy, Debug)]
enum DuplicateJsonLocation {
    Journal,
    Identity,
    Entry(usize),
    Witness(usize),
    NestedObject,
}

#[derive(Clone, Copy, Debug)]
enum UnknownRecordBodyFieldLocation {
    AssetRecord,
    FailureRecord,
}

const DUPLICATE_JSON_LOCATIONS: [DuplicateJsonLocation; 7] = [
    DuplicateJsonLocation::Journal,
    DuplicateJsonLocation::Identity,
    DuplicateJsonLocation::Entry(0),
    DuplicateJsonLocation::Entry(4),
    DuplicateJsonLocation::Entry(8),
    DuplicateJsonLocation::Witness(4),
    DuplicateJsonLocation::NestedObject,
];

fn insert_after_nth(input: &str, needle: &str, occurrence: usize, inserted: &str) -> String {
    let mut search_start = 0;
    let mut matched = None;
    for _ in 0..=occurrence {
        let relative = input[search_start..]
            .find(needle)
            .unwrap_or_else(|| panic!("missing raw JSON marker {needle:?}"));
        let start = search_start + relative;
        matched = Some(start);
        search_start = start + needle.len();
    }
    let insertion_at = matched.unwrap() + needle.len();
    format!(
        "{}{}{}",
        &input[..insertion_at],
        inserted,
        &input[insertion_at..]
    )
}

fn record_json_with_duplicate_key(record: &AssetRecord, location: DuplicateJsonLocation) -> String {
    let raw = serde_json::to_string(record).unwrap();
    let migration_id = digest("migration");
    let journal_schema = format!("\"schema_version\":{LEGACY_UPLOAD_MIGRATION_SCHEMA_VERSION}");
    match location {
        DuplicateJsonLocation::Journal => {
            insert_after_nth(&raw, &journal_schema, 0, &format!(",{journal_schema}"))
        }
        DuplicateJsonLocation::Identity => insert_after_nth(
            &raw,
            &format!("\"migration_id\":\"{migration_id}\""),
            0,
            ",\"migration_id\":\"duplicate-migration\"",
        ),
        DuplicateJsonLocation::Entry(index) => insert_after_nth(
            &raw,
            &format!("\"ordinal\":{index}"),
            0,
            &format!(",\"ordinal\":{index}"),
        ),
        DuplicateJsonLocation::Witness(index) => insert_after_nth(
            &raw,
            &format!(
                "\"witness_sha256\":\"{}\"",
                witness(LegacyUploadMigrationPhase::ORDER[index])
            ),
            0,
            ",\"witness_sha256\":\"duplicate-witness\"",
        ),
        DuplicateJsonLocation::NestedObject => insert_after_nth(
            &raw,
            &journal_schema,
            0,
            ",\"nested\":{\"value\":1,\"value\":2}",
        ),
    }
}

fn manifest_json(record_json: &str) -> String {
    format!("{{\"records\":[{record_json}]}}")
}

fn inject_unknown_record_body_field(
    record: &AssetRecord,
    location: UnknownRecordBodyFieldLocation,
) -> String {
    let mut value = serde_json::to_value(record).unwrap();
    match location {
        UnknownRecordBodyFieldLocation::AssetRecord => {
            value
                .as_object_mut()
                .unwrap()
                .insert("unknown_record_field".to_string(), json!(true));
        }
        UnknownRecordBodyFieldLocation::FailureRecord => {
            value["failures"][0]
                .as_object_mut()
                .unwrap()
                .insert("unknown_failure_field".to_string(), json!(true));
        }
    }
    serde_json::to_string(&value).unwrap()
}

fn assert_duplicate_json_error(error: &serde_json::Error) {
    assert!(
        error.to_string().contains("duplicate JSON object key"),
        "expected duplicate-key error, got {error}"
    );
}

const OPERATOR_REDACTION_SENTINELS: [&str; 7] = [
    "SENTINEL_ASSET_ID",
    "SENTINEL_PATH",
    "SENTINEL_REMOTE_ID",
    "SENTINEL_FILENAME",
    "SENTINEL_ACCOUNT",
    "SENTINEL_HASH",
    "SENTINEL_RAW_KEY",
];

fn sentinel_payload() -> String {
    OPERATOR_REDACTION_SENTINELS.join("__")
}

fn assert_operator_error_redacted(error: &impl Error, expected_stable_category: &str) {
    let mut rendered = format!("{error}\n{error:?}");
    let mut source = error.source();
    while let Some(nested) = source {
        rendered.push('\n');
        rendered.push_str(&nested.to_string());
        source = nested.source();
    }
    assert!(
        rendered.contains(expected_stable_category),
        "missing stable category {expected_stable_category:?}: {rendered}"
    );
    for sentinel in OPERATOR_REDACTION_SENTINELS {
        assert!(
            !rendered.contains(sentinel),
            "operator output leaked {sentinel}"
        );
    }
}

fn sensitive_migration_json_error() -> LegacyUploadMigrationError {
    let mut value = serde_json::to_value(journal(&prepare(&record("asset-a")))).unwrap();
    value["entries"][0]["phase"] = json!(sentinel_payload());
    LegacyUploadMigrationError::Json(
        serde_json::from_value::<LegacyUploadMigrationJournal>(value)
            .expect_err("sentinel phase must be rejected"),
    )
}

fn inject_unknown_field(record: &AssetRecord, location: UnknownFieldLocation) -> AssetRecord {
    let mut changed = record.clone();
    let proof = changed
        .proofs
        .get_mut(LEGACY_UPLOAD_MIGRATION_PROOF_NAME)
        .unwrap();
    match location {
        UnknownFieldLocation::Journal => {
            proof["unknown_journal_field"] = json!(true);
        }
        UnknownFieldLocation::Identity => {
            proof["identity"]["unknown_identity_field"] = json!(true);
        }
        UnknownFieldLocation::Entry(index) => {
            proof["entries"][index]["unknown_entry_field"] = json!(true);
        }
    }
    changed
}

#[test]
fn journal_advances_every_phase_with_a_valid_hash_chain() {
    let initial = record("asset-a");
    let completed = complete_journal(prepare(&initial));
    let journal = validate_legacy_upload_migration_record(&completed).unwrap();

    assert_eq!(
        journal.schema_version,
        LEGACY_UPLOAD_MIGRATION_SCHEMA_VERSION
    );
    assert_eq!(
        journal
            .entries
            .iter()
            .map(|entry| entry.phase)
            .collect::<Vec<_>>(),
        LegacyUploadMigrationPhase::ORDER
    );
    assert_eq!(journal.entries.len(), 9);
    assert_eq!(journal.entries.last().unwrap().ordinal, 8);
}

#[test]
fn identical_phase_replay_is_idempotent_but_different_replay_fails() {
    let prepared = prepare(&record("asset-a"));
    let replayed = advance_legacy_upload_migration_record(
        &prepared,
        LegacyUploadMigrationPhase::Prepared,
        &witness(LegacyUploadMigrationPhase::Prepared),
    )
    .unwrap();
    assert_eq!(replayed, prepared);

    let error = advance_legacy_upload_migration_record(
        &prepared,
        LegacyUploadMigrationPhase::Prepared,
        &digest("different"),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        LegacyUploadMigrationError::ReplayMismatch { .. }
    ));
}

#[test]
fn skipped_and_backward_phases_fail_closed() {
    let prepared = prepare(&record("asset-a"));
    let skipped = advance_legacy_upload_migration_record(
        &prepared,
        LegacyUploadMigrationPhase::Quarantined,
        &witness(LegacyUploadMigrationPhase::Quarantined),
    )
    .unwrap_err();
    assert!(matches!(
        skipped,
        LegacyUploadMigrationError::InvalidPhaseTransition { .. }
    ));

    let confirmed = advance_legacy_upload_migration_record(
        &prepared,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();
    let backward = advance_legacy_upload_migration_record(
        &confirmed,
        LegacyUploadMigrationPhase::Prepared,
        &witness(LegacyUploadMigrationPhase::Prepared),
    )
    .unwrap_err();
    assert!(matches!(
        backward,
        LegacyUploadMigrationError::InvalidPhaseTransition { .. }
    ));
}

#[test]
fn complete_is_immutable_and_identical_completion_replay_is_a_noop() {
    let completed = complete_journal(prepare(&record("asset-a")));
    let replayed = advance_legacy_upload_migration_record(
        &completed,
        LegacyUploadMigrationPhase::Complete,
        &witness(LegacyUploadMigrationPhase::Complete),
    )
    .unwrap();
    assert_eq!(replayed, completed);

    let error = advance_legacy_upload_migration_record(
        &completed,
        LegacyUploadMigrationPhase::Complete,
        &digest("different-completion"),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        LegacyUploadMigrationError::CompleteImmutable
    ));
}

#[test]
fn state_phase_mismatch_fails_without_mutating_the_record() {
    let prepared = prepare(&record("asset-a"));
    let before = prepared.clone();
    let error = advance_legacy_upload_migration_record(
        &prepared,
        LegacyUploadMigrationPhase::Reset,
        &witness(LegacyUploadMigrationPhase::Reset),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        LegacyUploadMigrationError::InvalidPhaseTransition { .. }
    ));
    assert_eq!(prepared, before);

    let mut confirmed = advance_legacy_upload_migration_record(
        &prepared,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();
    confirmed.state = State::NasVerified;
    let error = advance_legacy_upload_migration_record(
        &confirmed,
        LegacyUploadMigrationPhase::Quarantined,
        &witness(LegacyUploadMigrationPhase::Quarantined),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        LegacyUploadMigrationError::StateMismatch { .. }
    ));
}

#[test]
fn tampered_chain_witness_identity_and_cohort_fail_validation() {
    let confirmed = advance_legacy_upload_migration_record(
        &prepare(&record("asset-a")),
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();

    for mutate in [
        |journal: &mut LegacyUploadMigrationJournal| {
            journal.entries[1].previous_entry_sha256 = digest("wrong-prior")
        },
        |journal: &mut LegacyUploadMigrationJournal| {
            journal.entries[0].witness_sha256 = digest("wrong-witness")
        },
        |journal: &mut LegacyUploadMigrationJournal| {
            journal.identity.old_uploaded_asset_id = "other-replacement".to_string()
        },
        |journal: &mut LegacyUploadMigrationJournal| {
            journal.identity.cohort_sha256 = digest("other-cohort")
        },
    ] {
        let mut tampered = confirmed.clone();
        let mut value = journal(&tampered);
        mutate(&mut value);
        replace_journal(&mut tampered, &value);
        assert!(matches!(
            validate_legacy_upload_migration_record(&tampered),
            Err(LegacyUploadMigrationError::JournalTampered { .. })
        ));
    }
}

#[test]
fn malformed_digests_remote_identity_and_schema_fail_closed() {
    let base = record("asset-a");
    let companion = record("asset-b");
    let mut authority = test_cohort_authority(&base, &companion);
    authority.preparations[0].identity.evidence_sha256 = "ABC".to_string();
    assert!(matches!(
        prepare_legacy_upload_migration_record(&base, &authority),
        Err(LegacyUploadMigrationError::InvalidDigest { .. })
    ));

    let mut authority = test_cohort_authority(&base, &companion);
    authority.preparations[0].identity.old_uploaded_asset_id = "unsafe\nidentity".to_string();
    assert!(matches!(
        prepare_legacy_upload_migration_record(&base, &authority),
        Err(LegacyUploadMigrationError::InvalidRemoteIdentity { .. })
    ));

    let mut prepared = prepare(&base);
    let mut value = journal(&prepared);
    value.schema_version += 1;
    replace_journal(&mut prepared, &value);
    assert!(matches!(
        validate_legacy_upload_migration_record(&prepared),
        Err(LegacyUploadMigrationError::UnsupportedSchemaVersion { .. })
    ));
}

#[test]
fn preparation_binds_the_exact_source_record_and_preserves_unrelated_bytes() {
    let initial = record("asset-a");
    let companion = record("asset-b");
    let authority = test_cohort_authority(&initial, &companion);
    let mut altered = initial.clone();
    altered
        .proofs
        .insert("unrelated".to_string(), json!({"changed": true}));
    assert!(matches!(
        prepare_legacy_upload_migration_record(&altered, &authority),
        Err(LegacyUploadMigrationError::SourceRecordMismatch)
    ));

    let prepared = prepare(&initial);
    assert_eq!(prepared.asset_id, initial.asset_id);
    assert_eq!(prepared.raw_path, initial.raw_path);
    assert_eq!(prepared.state, initial.state);
    assert_eq!(prepared.failures, initial.failures);
    assert_eq!(prepared.updated_at, initial.updated_at);
    for (name, proof) in &initial.proofs {
        assert_eq!(prepared.proofs.get(name), Some(proof));
    }
    assert_eq!(prepared.proofs.len(), initial.proofs.len() + 1);
}

#[test]
fn authoritative_exact_cas_prepares_and_advances_two_records_atomically() {
    let temp = tempfile::tempdir().unwrap();
    let manifest_path = temp.path().join("manifest.json");
    let mut seed = Manifest::new();
    seed.upsert(record("asset-a"));
    seed.upsert(record("asset-b"));
    seed.save_atomic(&manifest_path).unwrap();

    let writer = AssetStateStore::open_writer(
        &manifest_path,
        "legacy-upload-migration-test",
        Duration::from_secs(30),
    )
    .unwrap();
    let durable = writer.load_or_import().unwrap();
    let expected_a = durable.get("asset-a").unwrap().clone();
    let expected_b = durable.get("asset-b").unwrap().clone();
    let (authority, prepared_a, prepared_b) = prepare_authorized_pair(&expected_a, &expected_b);
    persist_two_legacy_upload_migration_preparations_exact_cas(
        &writer,
        &authority,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &expected_a,
                updated: &prepared_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &expected_b,
                updated: &prepared_b,
            },
        ],
    )
    .unwrap();

    let current = writer.load().unwrap();
    assert_eq!(current.get("asset-a").unwrap(), &prepared_a);
    assert_eq!(current.get("asset-b").unwrap(), &prepared_b);
    let current_a = current.get("asset-a").unwrap().clone();
    let current_b = current.get("asset-b").unwrap().clone();
    let (phase_authority, [advanced_a, advanced_b]) = test_phase_authority(
        [&current_a, &current_b],
        [&current_a, &current_b],
        LegacyUploadMigrationPhase::DeleteConfirmed,
    );
    assert_eq!(
        advance_authorized_record(&current_a, &phase_authority).unwrap(),
        advanced_a
    );
    assert_eq!(
        advance_authorized_record(&current_b, &phase_authority).unwrap(),
        advanced_b
    );
    persist_authorized_records(
        &writer,
        &phase_authority,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &current_a,
                updated: &advanced_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &current_b,
                updated: &advanced_b,
            },
        ],
    )
    .unwrap();
    writer.export_json().unwrap();

    let checkpoint = Manifest::load(&manifest_path).unwrap();
    for asset_id in ["asset-a", "asset-b"] {
        let durable_journal =
            validate_legacy_upload_migration_record(writer.load().unwrap().get(asset_id).unwrap())
                .unwrap();
        let checkpoint_journal =
            validate_legacy_upload_migration_record(checkpoint.get(asset_id).unwrap()).unwrap();
        assert_eq!(durable_journal, checkpoint_journal);
        assert_eq!(durable_journal.entries.len(), 2);
    }
}

#[test]
fn sealed_registry_prevents_dual_row_removal_from_overwriting_checkpoint() {
    let temp = tempfile::tempdir().unwrap();
    let manifest_path = temp.path().join("manifest.json");
    let mut seed = Manifest::new();
    seed.upsert(record("asset-a"));
    seed.upsert(record("asset-b"));
    seed.save_atomic(&manifest_path).unwrap();
    let writer = AssetStateStore::open_writer(
        &manifest_path,
        "legacy-upload-migration-dual-row-removal-test",
        Duration::from_secs(30),
    )
    .unwrap();
    let initial = writer.load_or_import().unwrap();
    let initial_a = initial.get("asset-a").unwrap().clone();
    let initial_b = initial.get("asset-b").unwrap().clone();
    let (authority, prepared_a, prepared_b) = prepare_authorized_pair(&initial_a, &initial_b);
    persist_two_legacy_upload_migration_preparations_exact_cas(
        &writer,
        &authority,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &initial_a,
                updated: &prepared_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &initial_b,
                updated: &prepared_b,
            },
        ],
    )
    .unwrap();
    writer.export_json().unwrap();
    let checkpoint_before = fs::read(&manifest_path).unwrap();

    rusqlite::Connection::open(writer.path())
        .unwrap()
        .execute("DELETE FROM assets", [])
        .unwrap();

    writer
        .export_json()
        .expect_err("sealed registry must prevent a zero-member downgrade export");
    assert_eq!(fs::read(&manifest_path).unwrap(), checkpoint_before);
}

#[test]
fn preparation_registry_and_records_roll_back_together_on_exact_cas_failure() {
    let temp = tempfile::tempdir().unwrap();
    let manifest_path = temp.path().join("manifest.json");
    let mut seed = Manifest::new();
    seed.upsert(record("asset-a"));
    seed.upsert(record("asset-b"));
    seed.save_atomic(&manifest_path).unwrap();
    let writer = AssetStateStore::open_writer(
        &manifest_path,
        "legacy-upload-migration-registry-rollback-test",
        Duration::from_secs(30),
    )
    .unwrap();
    let initial = writer.load_or_import().unwrap();
    let initial_a = initial.get("asset-a").unwrap().clone();
    let initial_b = initial.get("asset-b").unwrap().clone();
    let (authority, prepared_a, prepared_b) = prepare_authorized_pair(&initial_a, &initial_b);
    let mut drifted_b = initial_b.clone();
    drifted_b.updated_at = "2026-07-13T00:00:01Z".to_string();
    drifted_b
        .proofs
        .insert("concurrent".to_string(), json!({"changed": true}));
    writer.persist_record(&drifted_b).unwrap();

    persist_two_legacy_upload_migration_preparations_exact_cas(
        &writer,
        &authority,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &initial_a,
                updated: &prepared_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &initial_b,
                updated: &prepared_b,
            },
        ],
    )
    .expect_err("stale preparation must roll back the registry insert");

    assert_eq!(registry_row_count(&writer), 0);
    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &initial_a);
    assert_eq!(after.get("asset-b").unwrap(), &drifted_b);
    assert!(after.records().values().all(|record| {
        !record
            .proofs
            .contains_key(LEGACY_UPLOAD_MIGRATION_PROOF_NAME)
    }));
}

#[test]
fn preparation_permit_accepts_only_an_exact_registry_and_record_replay() {
    let (temp, writer, prepared_a, prepared_b) = prepared_pair("preparation-replay");
    let journals = [&prepared_a, &prepared_b]
        .map(|record| validate_legacy_upload_migration_record(record).unwrap());
    let authority = LegacyUploadMigrationCohortAuthority {
        preparations: journals.map(|journal| LegacyUploadMigrationAuthorizedPreparation {
            identity: journal.identity,
            prepared_witness_sha256: journal.entries[0].witness_sha256.clone(),
        }),
    };

    persist_two_legacy_upload_migration_preparations_exact_cas(
        &writer,
        &authority,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &prepared_a,
                updated: &prepared_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &prepared_b,
                updated: &prepared_b,
            },
        ],
    )
    .expect("exact preparation and registry replay must be idempotent");

    assert_eq!(registry_row_count(&writer), 1);
    assert_eq!(writer.load().unwrap().get("asset-a").unwrap(), &prepared_a);
    assert_eq!(writer.load().unwrap().get("asset-b").unwrap(), &prepared_b);
    drop(temp);
}

#[test]
fn sealed_registry_prevents_dual_proof_removal_from_overwriting_checkpoint() {
    let (temp, writer, _) = db_loaded_lifecycle_pair_at_phase(LegacyUploadMigrationPhase::Complete);
    let manifest_path = temp.path().join("manifest.json");
    let checkpoint_before = fs::read(&manifest_path).unwrap();
    let durable = writer.load().unwrap();
    let connection = rusqlite::Connection::open(writer.path()).unwrap();
    for asset_id in ["asset-a", "asset-b"] {
        let mut stripped = durable.get(asset_id).unwrap().clone();
        stripped.proofs.remove(LEGACY_UPLOAD_MIGRATION_PROOF_NAME);
        connection
            .execute(
                "UPDATE assets SET record_json = ?1 WHERE asset_id = ?2",
                rusqlite::params![serde_json::to_string(&stripped).unwrap(), asset_id],
            )
            .unwrap();
    }

    writer
        .export_json()
        .expect_err("registry must reject dual journal removal before checkpoint export");
    assert_eq!(fs::read(&manifest_path).unwrap(), checkpoint_before);
}

#[test]
fn registry_deletion_fails_classification_and_export_without_asset_or_checkpoint_writes() {
    let (temp, writer, _) = db_loaded_lifecycle_pair_at_phase(LegacyUploadMigrationPhase::Complete);
    let manifest_path = temp.path().join("manifest.json");
    let rows_before = durable_asset_rows(&writer);
    let checkpoint_before = fs::read(&manifest_path).unwrap();
    rusqlite::Connection::open(writer.path())
        .unwrap()
        .execute("DELETE FROM legacy_upload_migration_registry", [])
        .unwrap();

    assert!(matches!(
        writer.load(),
        Err(AssetStateStoreError::JsonCheckpointRegistryMismatch)
    ));
    assert!(matches!(
        writer.export_json(),
        Err(AssetStateStoreError::JsonCheckpointRegistryMismatch)
    ));
    assert_eq!(durable_asset_rows(&writer), rows_before);
    assert_eq!(fs::read(&manifest_path).unwrap(), checkpoint_before);
}

#[test]
fn noncanonical_or_tampered_database_registry_fails_before_asset_or_checkpoint_writes() {
    let (temp, writer, durable) =
        db_loaded_lifecycle_pair_at_phase(LegacyUploadMigrationPhase::Complete);
    let manifest_path = temp.path().join("manifest.json");
    let rows_before = durable_asset_rows(&writer);
    let checkpoint_before = fs::read(&manifest_path).unwrap();
    let registry = durable.legacy_upload_migration_registry().unwrap();
    let noncanonical = serde_json::to_string_pretty(registry).unwrap();
    rusqlite::Connection::open(writer.path())
        .unwrap()
        .execute(
            "UPDATE legacy_upload_migration_registry SET registry_json = ?1",
            [noncanonical],
        )
        .unwrap();

    assert!(matches!(
        writer.load(),
        Err(AssetStateStoreError::LegacyUploadMigrationRegistryMismatch)
    ));
    assert!(writer.export_json().is_err());
    assert_eq!(durable_asset_rows(&writer), rows_before);
    assert_eq!(fs::read(&manifest_path).unwrap(), checkpoint_before);
}

#[test]
fn phase_cas_rejects_changed_registry_before_record_updates() {
    let (temp, writer, prepared_a, prepared_b) = prepared_pair("registry-phase-cas");
    writer.export_json().unwrap();
    let manifest_path = temp.path().join("manifest.json");
    let rows_before = durable_asset_rows(&writer);
    let checkpoint_before = fs::read(&manifest_path).unwrap();
    let updated_a = lifecycle_candidate(&prepared_a, LegacyUploadMigrationPhase::DeleteConfirmed);
    let updated_b = lifecycle_candidate(&prepared_b, LegacyUploadMigrationPhase::DeleteConfirmed);
    rusqlite::Connection::open(writer.path())
        .unwrap()
        .execute(
            "UPDATE legacy_upload_migration_registry SET registry_sha256 = ?1",
            [digest("tampered-registry")],
        )
        .unwrap();

    let error = persist_two_legacy_upload_migration_records_exact_cas(
        &writer,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &prepared_a,
                updated: &updated_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &prepared_b,
                updated: &updated_b,
            },
        ],
    )
    .expect_err("phase CAS must verify the immutable registry");
    assert!(matches!(
        error,
        LegacyUploadMigrationCommitError::StateStore(
            AssetStateStoreError::LegacyUploadMigrationRegistryMismatch
        )
    ));
    assert_eq!(durable_asset_rows(&writer), rows_before);
    assert_eq!(fs::read(&manifest_path).unwrap(), checkpoint_before);
}

#[test]
fn mismatched_valid_checkpoint_registry_cannot_replace_authoritative_binding() {
    let (temp, writer, _) = db_loaded_lifecycle_pair_at_phase(LegacyUploadMigrationPhase::Complete);
    let manifest_path = temp.path().join("manifest.json");
    let rows_before = durable_asset_rows(&writer);
    let (other_temp, other_writer, _) =
        db_loaded_lifecycle_pair_at_phase(LegacyUploadMigrationPhase::Complete);
    let other_checkpoint = fs::read(other_temp.path().join("manifest.json")).unwrap();
    assert_ne!(fs::read(&manifest_path).unwrap(), other_checkpoint);
    fs::write(&manifest_path, &other_checkpoint).unwrap();

    assert!(matches!(
        writer.export_json(),
        Err(AssetStateStoreError::JsonCheckpointRegistryMismatch)
    ));
    assert_eq!(durable_asset_rows(&writer), rows_before);
    assert_eq!(fs::read(&manifest_path).unwrap(), other_checkpoint);
    other_writer.release_writer_lease().unwrap();
}

#[test]
fn checkpoint_restore_import_preserves_registry_and_complete_pair() {
    let (source_temp, source_writer, source) =
        db_loaded_lifecycle_pair_at_phase(LegacyUploadMigrationPhase::Complete);
    let restored_temp = tempfile::tempdir().unwrap();
    let restored_path = restored_temp.path().join("manifest.json");
    fs::copy(source_temp.path().join("manifest.json"), &restored_path).unwrap();
    let restored_writer = AssetStateStore::open_writer(
        &restored_path,
        "legacy-upload-migration-registry-restore-test",
        Duration::from_secs(30),
    )
    .unwrap();

    let restored = restored_writer.load_or_import().unwrap();
    assert_eq!(restored, source);
    assert_eq!(registry_row_count(&restored_writer), 1);
    let (ordinary, sealed) = classify_legacy_upload_migration_records(&restored)
        .unwrap()
        .into_parts();
    assert!(ordinary.records().is_empty());
    assert_eq!(sealed.len(), 2);
    source_writer.release_writer_lease().unwrap();
}

#[test]
fn complete_record_body_tampering_fails_validation_classification_load_and_export() {
    fn tamper_raw_path(record: &mut AssetRecord) {
        record.raw_path = PathBuf::from("/raw/tampered.dng");
    }
    fn tamper_failures(record: &mut AssetRecord) {
        record.failures.push(FailureRecord::new("tampered", "body"));
    }
    fn tamper_updated_at(record: &mut AssetRecord) {
        record.updated_at = "2026-07-13T00:00:01Z".to_string();
    }
    fn tamper_proof(record: &mut AssetRecord, proof_name: &str) {
        record
            .proofs
            .insert(proof_name.to_string(), json!({"tampered": true}));
    }
    fn tamper_conversion(record: &mut AssetRecord) {
        tamper_proof(record, "conversion");
    }
    fn tamper_conversion_performance(record: &mut AssetRecord) {
        tamper_proof(record, "conversion_performance");
    }
    fn tamper_heic(record: &mut AssetRecord) {
        tamper_proof(record, "heic");
    }
    fn tamper_upload(record: &mut AssetRecord) {
        tamper_proof(record, "upload");
    }
    fn tamper_mirror(record: &mut AssetRecord) {
        tamper_proof(record, "icloudpd_local_mirror");
    }
    fn tamper_uploaded_heic_delete(record: &mut AssetRecord) {
        tamper_proof(record, "uploaded_heic_delete");
    }
    fn tamper_state(record: &mut AssetRecord) {
        record.state = State::NeedsReview;
    }
    fn add_extra_proof(record: &mut AssetRecord) {
        record
            .proofs
            .insert("injected".to_string(), json!({"unexpected": true}));
    }
    fn remove_proof(record: &mut AssetRecord) {
        assert!(record.proofs.remove("nas").is_some());
    }

    type RecordBodyTamper = (&'static str, fn(&mut AssetRecord));
    let cases: [RecordBodyTamper; 12] = [
        ("raw_path", tamper_raw_path),
        ("failures", tamper_failures),
        ("updated_at", tamper_updated_at),
        ("conversion", tamper_conversion),
        ("conversion_performance", tamper_conversion_performance),
        ("heic", tamper_heic),
        ("upload", tamper_upload),
        ("mirror", tamper_mirror),
        ("uploaded_heic_delete", tamper_uploaded_heic_delete),
        ("state", tamper_state),
        ("extra_proof", add_extra_proof),
        ("removed_proof", remove_proof),
    ];

    for (case, mutate) in cases {
        let (temp, writer, durable) =
            db_loaded_lifecycle_pair_at_phase(LegacyUploadMigrationPhase::Complete);
        let manifest_path = temp.path().join("manifest.json");
        let checkpoint_before = fs::read(&manifest_path).unwrap();
        let mut tampered = durable.get("asset-a").unwrap().clone();
        mutate(&mut tampered);

        assert!(
            matches!(
                validate_legacy_upload_migration_record(&tampered),
                Err(LegacyUploadMigrationError::JournalTampered {
                    field: "record_body_sha256"
                })
            ),
            "{case}: record validation accepted a changed body"
        );
        let mut tampered_manifest = durable.clone();
        tampered_manifest.replace_record_unchecked_for_tamper_test(tampered.clone());
        assert!(
            matches!(
                classify_legacy_upload_migration_records(&tampered_manifest),
                Err(LegacyUploadMigrationError::JournalTampered {
                    field: "record_body_sha256"
                })
            ),
            "{case}: classification accepted a changed body"
        );

        rusqlite::Connection::open(writer.path())
            .unwrap()
            .execute(
                "UPDATE assets
                 SET state = ?1, updated_at = ?2, record_json = ?3
                 WHERE asset_id = ?4",
                rusqlite::params![
                    tampered.state.as_str(),
                    tampered.updated_at,
                    serde_json::to_string(&tampered).unwrap(),
                    tampered.asset_id,
                ],
            )
            .unwrap();
        assert!(
            writer.load().is_err(),
            "{case}: database load accepted tampering"
        );
        assert!(
            writer.export_json().is_err(),
            "{case}: checkpoint export accepted tampering"
        );
        assert_eq!(
            fs::read(&manifest_path).unwrap(),
            checkpoint_before,
            "{case}: rejected tampering overwrote the checkpoint"
        );
    }
}

#[test]
fn direct_sql_unknown_record_body_fields_fail_load_classification_and_export_without_writes() {
    for (case, location) in [
        UnknownRecordBodyFieldLocation::AssetRecord,
        UnknownRecordBodyFieldLocation::FailureRecord,
    ]
    .into_iter()
    .enumerate()
    {
        let (temp, writer, durable) =
            db_loaded_lifecycle_pair_at_phase(LegacyUploadMigrationPhase::Complete);
        let manifest_path = temp.path().join("manifest.json");
        let checkpoint_before = fs::read(&manifest_path).unwrap();
        let raw = inject_unknown_record_body_field(durable.get("asset-a").unwrap(), location);
        rusqlite::Connection::open(writer.path())
            .unwrap()
            .execute(
                "UPDATE assets SET record_json = ?1 WHERE asset_id = 'asset-a'",
                [raw],
            )
            .unwrap();
        let rows_after_tamper = durable_asset_rows(&writer);

        assert!(
            writer.load().is_err(),
            "{case} {location:?}: database load accepted an unknown field"
        );
        let classification = writer.load().and_then(|manifest| {
            classify_legacy_upload_migration_records(&manifest)
                .map(|_| manifest)
                .map_err(|_| AssetStateStoreError::LegacyUploadMigrationRegistryMismatch)
        });
        assert!(
            classification.is_err(),
            "{case} {location:?}: classification path accepted an unknown field"
        );
        assert!(
            writer.export_json().is_err(),
            "{case} {location:?}: export accepted an unknown field"
        );
        assert_eq!(durable_asset_rows(&writer), rows_after_tamper);
        assert_eq!(fs::read(&manifest_path).unwrap(), checkpoint_before);
    }
}

#[test]
fn checkpoint_unknown_record_body_fields_fail_import_without_database_or_checkpoint_mutation() {
    let (source_temp, source_writer, source) =
        db_loaded_lifecycle_pair_at_phase(LegacyUploadMigrationPhase::Complete);
    let source_checkpoint = fs::read_to_string(source_temp.path().join("manifest.json")).unwrap();

    for (case, location) in [
        UnknownRecordBodyFieldLocation::AssetRecord,
        UnknownRecordBodyFieldLocation::FailureRecord,
    ]
    .into_iter()
    .enumerate()
    {
        let mut checkpoint: Value = serde_json::from_str(&source_checkpoint).unwrap();
        let raw = inject_unknown_record_body_field(source.get("asset-a").unwrap(), location);
        checkpoint["records"][0] = serde_json::from_str(&raw).unwrap();
        let invalid_checkpoint = serde_json::to_vec_pretty(&checkpoint).unwrap();
        let restored_temp = tempfile::tempdir().unwrap();
        let restored_path = restored_temp.path().join("manifest.json");
        fs::write(&restored_path, &invalid_checkpoint).unwrap();

        assert!(
            Manifest::load(&restored_path).is_err(),
            "{case} {location:?}: checkpoint load accepted an unknown field"
        );
        let writer = AssetStateStore::open_writer(
            &restored_path,
            format!("unknown-record-body-import-{case}"),
            Duration::from_secs(30),
        )
        .unwrap();
        let rows_before = durable_asset_rows(&writer);
        assert!(
            writer.load_or_import().is_err(),
            "{case} {location:?}: checkpoint import accepted an unknown field"
        );
        assert_eq!(durable_asset_rows(&writer), rows_before);
        assert_eq!(registry_row_count(&writer), 0);
        assert_eq!(fs::read(&restored_path).unwrap(), invalid_checkpoint);
    }
    source_writer.release_writer_lease().unwrap();
}

#[test]
fn checkpoint_registry_duplicate_keys_fail_strict_json_import_without_database_rows() {
    let (source_temp, source_writer, source) =
        db_loaded_lifecycle_pair_at_phase(LegacyUploadMigrationPhase::Complete);
    let mut checkpoint = fs::read_to_string(source_temp.path().join("manifest.json")).unwrap();
    let duplicate =
        serde_json::to_string_pretty(source.legacy_upload_migration_registry().unwrap()).unwrap();
    let close = checkpoint.rfind('\n').unwrap();
    checkpoint.insert_str(
        close,
        &format!(",\n  \"legacy_upload_migration_registry\": {duplicate}"),
    );
    let restored_temp = tempfile::tempdir().unwrap();
    let restored_path = restored_temp.path().join("manifest.json");
    fs::write(&restored_path, checkpoint).unwrap();
    let restored_writer = AssetStateStore::open_writer(
        &restored_path,
        "legacy-upload-migration-registry-duplicate-key-test",
        Duration::from_secs(30),
    )
    .unwrap();

    assert!(matches!(
        restored_writer.load_or_import(),
        Err(AssetStateStoreError::Manifest(ManifestError::Json(_)))
    ));
    assert!(restored_writer.load().unwrap().records().is_empty());
    assert_eq!(registry_row_count(&restored_writer), 0);
    source_writer.release_writer_lease().unwrap();
}

#[test]
fn authoritative_exact_cas_persists_all_nine_phases_and_exact_replays() {
    let temp = tempfile::tempdir().unwrap();
    let manifest_path = temp.path().join("manifest.json");
    let mut seed = Manifest::new();
    seed.upsert(lifecycle_record("asset-a"));
    seed.upsert(lifecycle_record("asset-b"));
    seed.save_atomic(&manifest_path).unwrap();

    let writer = AssetStateStore::open_writer(
        &manifest_path,
        "legacy-upload-migration-lifecycle-test",
        Duration::from_secs(30),
    )
    .unwrap();
    let durable = writer.load_or_import().unwrap();
    let initial_a = durable.get("asset-a").unwrap().clone();
    let initial_b = durable.get("asset-b").unwrap().clone();
    let (authority, prepared_a, prepared_b) = prepare_authorized_pair(&initial_a, &initial_b);
    persist_two_legacy_upload_migration_preparations_exact_cas(
        &writer,
        &authority,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &initial_a,
                updated: &prepared_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &initial_b,
                updated: &prepared_b,
            },
        ],
    )
    .unwrap();

    let mut current_a = prepared_a;
    let mut current_b = prepared_b;
    for phase in LegacyUploadMigrationPhase::ORDER.into_iter().skip(1) {
        let candidate_a = lifecycle_phase_candidate(&current_a, phase);
        let candidate_b = lifecycle_phase_candidate(&current_b, phase);
        let (phase_authority, [updated_a, updated_b]) = test_phase_authority(
            [&current_a, &current_b],
            [&candidate_a, &candidate_b],
            phase,
        );
        assert_eq!(
            advance_authorized_record(&candidate_a, &phase_authority).unwrap(),
            updated_a
        );
        assert_eq!(
            advance_authorized_record(&candidate_b, &phase_authority).unwrap(),
            updated_b
        );
        persist_authorized_records(
            &writer,
            &phase_authority,
            [
                LegacyUploadMigrationCasUpdate {
                    expected: &current_a,
                    updated: &updated_a,
                },
                LegacyUploadMigrationCasUpdate {
                    expected: &current_b,
                    updated: &updated_b,
                },
            ],
        )
        .unwrap_or_else(|error| panic!("{phase:?} failed: {error:?}"));
        assert_eq!(
            advance_authorized_record(&updated_a, &phase_authority).unwrap(),
            updated_a
        );
        assert_eq!(
            advance_authorized_record(&updated_b, &phase_authority).unwrap(),
            updated_b
        );
        persist_authorized_records(
            &writer,
            &phase_authority,
            [
                LegacyUploadMigrationCasUpdate {
                    expected: &updated_a,
                    updated: &updated_a,
                },
                LegacyUploadMigrationCasUpdate {
                    expected: &updated_b,
                    updated: &updated_b,
                },
            ],
        )
        .unwrap_or_else(|error| panic!("{phase:?} replay failed: {error:?}"));

        let after = writer.load().unwrap();
        assert_eq!(after.get("asset-a").unwrap(), &updated_a);
        assert_eq!(after.get("asset-b").unwrap(), &updated_b);
        current_a = updated_a;
        current_b = updated_b;
    }

    assert_eq!(
        journal(&current_a).entries.last().unwrap().phase,
        LegacyUploadMigrationPhase::Complete
    );
    assert_eq!(
        journal(&current_b).entries.last().unwrap().phase,
        LegacyUploadMigrationPhase::Complete
    );
    for record in [&current_a, &current_b] {
        assert_eq!(record.state, State::UploadVerified);
        assert!(!record.proofs.contains_key("uploaded_heic_delete"));
        assert!(record.proofs.contains_key("conversion"));
        assert!(record.proofs.contains_key("conversion_performance"));
        assert!(record.proofs.contains_key("heic"));
        assert!(record.proofs.contains_key("upload"));
        assert!(record.proofs.contains_key("icloudpd_local_mirror"));
    }
}

#[test]
fn db_loaded_migration_manifest_rejects_every_generic_mutator_without_writes() {
    let (temp, writer, durable) =
        db_loaded_lifecycle_pair_at_phase(LegacyUploadMigrationPhase::Reset);
    let checkpoint_path = temp.path().join("manifest.json");
    let checkpoint_before = fs::read(&checkpoint_path).unwrap();
    let asset_id = "asset-a";

    assert_generic_manifest_mutation_rejected(&durable, |manifest| {
        manifest
            .record_failure(asset_id, "generic", "must reject")
            .map(|_| ())
    });
    assert_generic_manifest_mutation_rejected(&durable, |manifest| {
        manifest
            .record_failure_with_kind(
                asset_id,
                "generic",
                "must reject",
                Some(FailureKind::AdjustedSourceResolveFailed),
            )
            .map(|_| ())
    });
    assert_generic_manifest_mutation_rejected(&durable, |manifest| {
        manifest
            .recover_failed_for_retry(asset_id, State::Converted)
            .map(|_| ())
    });
    assert_generic_manifest_mutation_rejected(&durable, |manifest| {
        manifest
            .quarantine_failed_for_historical_remote_side_effect(
                asset_id,
                FailureQuarantineProof::historical_remote_side_effect(
                    digest("evidence"),
                    digest("targets"),
                    1,
                    1,
                    1,
                    1,
                    1_752_400_000,
                ),
            )
            .map(|_| ())
    });
    assert_generic_manifest_mutation_rejected(&durable, |manifest| {
        manifest
            .terminalize_failed_with_proof(asset_id, "terminal", json!({"must": "reject"}))
            .map(|_| ())
    });
    assert_generic_manifest_mutation_rejected(&durable, |manifest| {
        manifest
            .apply_original_asset_resolution_update(
                asset_id,
                State::NasVerified,
                Some(json!({"must": "reject"})),
                json!({"must": "reject"}),
            )
            .map(|_| ())
    });
    let interrupted_retry_predicate_called = Cell::new(false);
    assert_generic_manifest_mutation_rejected(&durable, |manifest| {
        manifest
            .requeue_interrupted_retries_as_failed(|_| {
                interrupted_retry_predicate_called.set(true);
                true
            })
            .map(|_| ())
    });
    assert!(!interrupted_retry_predicate_called.get());
    assert_generic_manifest_mutation_rejected(&durable, |manifest| {
        manifest
            .transition(
                asset_id,
                State::Converted,
                "ordinary",
                json!({"must": "reject"}),
            )
            .map(|_| ())
    });
    assert_generic_manifest_mutation_rejected(&durable, |manifest| {
        manifest
            .transition_trusted(
                asset_id,
                State::Converted,
                "ordinary",
                json!({"must": "reject"}),
            )
            .map(|_| ())
    });
    assert_generic_manifest_mutation_rejected(&durable, |manifest| {
        manifest
            .record_proof(asset_id, "ordinary", json!({"must": "reject"}))
            .map(|_| ())
    });
    assert_generic_manifest_mutation_rejected(&durable, |manifest| {
        manifest
            .record_trusted_proof(asset_id, "ordinary", json!({"must": "reject"}))
            .map(|_| ())
    });
    assert_generic_manifest_mutation_rejected(&durable, |manifest| {
        manifest.snapshot_record(asset_id).map(|_| ())
    });
    assert_generic_manifest_mutation_rejected(&durable, |manifest| {
        manifest.save_atomic(&checkpoint_path)
    });
    assert_generic_manifest_mutation_rejected(&durable, |manifest| {
        manifest.save_atomic_trusted(&checkpoint_path)
    });

    for trusted in [false, true] {
        let mut candidate = durable.clone();
        let before = manifest_record_bytes(&candidate);
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let replacement = AssetRecord::new(asset_id, "/replacement/asset-a.dng");
            if trusted {
                candidate.upsert_trusted(replacement);
            } else {
                candidate.upsert(replacement);
            }
        }));
        assert!(rejected.is_err());
        assert_eq!(manifest_record_bytes(&candidate), before);
    }

    assert_eq!(writer.load().unwrap(), durable);
    assert_eq!(fs::read(&checkpoint_path).unwrap(), checkpoint_before);
}

#[test]
fn sealed_record_classification_is_read_only_and_fails_closed_for_noncomplete_journals() {
    let (_temp, _writer, mut completed) =
        db_loaded_lifecycle_pair_at_phase(LegacyUploadMigrationPhase::Complete);
    let ordinary = AssetRecord::new("ordinary", "/raw/ordinary.dng");
    completed.upsert_trusted(ordinary.clone());
    let completed_before = manifest_record_bytes(&completed);
    let (ordinary_manifest, sealed_asset_ids) =
        classify_legacy_upload_migration_records(&completed)
            .unwrap()
            .into_parts();
    assert_eq!(manifest_record_bytes(&completed), completed_before);
    assert_eq!(ordinary_manifest.records().len(), 1);
    assert_eq!(ordinary_manifest.get("ordinary").unwrap(), &ordinary);
    assert_eq!(
        sealed_asset_ids,
        ["asset-a".to_string(), "asset-b".to_string()]
            .into_iter()
            .collect()
    );

    let (_temp, _writer, incomplete) =
        db_loaded_lifecycle_pair_at_phase(LegacyUploadMigrationPhase::Reset);
    let incomplete_before = manifest_record_bytes(&incomplete);
    assert!(matches!(
        classify_legacy_upload_migration_records(&incomplete),
        Err(LegacyUploadMigrationError::IncompleteJournal {
            phase: LegacyUploadMigrationPhase::Reset,
        })
    ));
    assert_eq!(manifest_record_bytes(&incomplete), incomplete_before);

    let single_payload = serde_json::to_vec(&json!({
        "records": [completed.get("asset-a").unwrap()],
    }))
    .unwrap();
    assert!(matches!(
        Manifest::load_from_reader(single_payload.as_slice()),
        Err(ManifestError::ReservedInternalProofCapabilityMismatch)
    ));

    let mut tampered_record = completed.get("asset-a").unwrap().clone();
    tampered_record
        .proofs
        .get_mut(LEGACY_UPLOAD_MIGRATION_PROOF_NAME)
        .unwrap()["entries"][0]["witness_sha256"] = json!(digest("tampered-witness"));
    let payload = serde_json::to_vec(&json!({"records": [tampered_record]})).unwrap();
    assert!(matches!(
        Manifest::load_from_reader(payload.as_slice()),
        Err(ManifestError::ReservedInternalProofCapabilityMismatch)
    ));
}

#[test]
fn sealed_registry_classification_covers_all_nine_phases() {
    for phase in LegacyUploadMigrationPhase::ORDER {
        let (_temp, _writer, manifest) = db_loaded_lifecycle_pair_at_phase(phase);
        assert!(manifest.legacy_upload_migration_registry().is_some());
        let result = classify_legacy_upload_migration_records(&manifest);
        if phase == LegacyUploadMigrationPhase::Complete {
            let (ordinary, sealed) = result.unwrap().into_parts();
            assert!(ordinary.records().is_empty());
            assert_eq!(sealed.len(), 2);
        } else {
            assert!(matches!(
                result,
                Err(LegacyUploadMigrationError::IncompleteJournal { phase: actual })
                    if actual == phase
            ));
        }
    }
}

#[test]
fn journals_without_registry_fail_central_classification() {
    let prepared = prepare(&record("asset-a"));
    let authority = LegacyUploadMigrationManifestRecordAuthority::for_record(&prepared).unwrap();
    let mut manifest = Manifest::new();
    manifest
        .upsert_legacy_upload_migration_record(&authority, prepared)
        .unwrap();

    assert!(matches!(
        classify_legacy_upload_migration_records(&manifest),
        Err(LegacyUploadMigrationError::RegistryMissing)
    ));
}

#[test]
fn phase_authority_binds_cohort_pair_phase_records_witness_and_payload_without_writes() {
    let (temp, writer, prepared_a, prepared_b) = prepared_pair("phase-authority-binding");

    macro_rules! assert_rejected {
        ($mutate:expr) => {{
            let (mut authority, updated) = test_phase_authority(
                [&prepared_a, &prepared_b],
                [&prepared_a, &prepared_b],
                LegacyUploadMigrationPhase::DeleteConfirmed,
            );
            $mutate(&mut authority);
            assert!(matches!(
                advance_authorized_record(&prepared_a, &authority),
                Err(LegacyUploadMigrationError::PhaseAuthorityMismatch)
            ));
            assert_phase_authority_rejected_without_writes(
                &writer,
                &authority,
                [&prepared_a, &prepared_b],
                [&updated[0], &updated[1]],
            );
        }};
    }

    assert_rejected!(|authority: &mut LegacyUploadMigrationPhaseAuthority| {
        authority.cohort_sha256 = digest("different-authorized-cohort");
        reseal_phase_authority(authority);
    });
    assert_rejected!(|authority: &mut LegacyUploadMigrationPhaseAuthority| {
        authority.from = LegacyUploadMigrationPhase::DeleteConfirmed;
        authority.to = LegacyUploadMigrationPhase::Quarantined;
        reseal_phase_authority(authority);
    });
    assert_rejected!(|authority: &mut LegacyUploadMigrationPhaseAuthority| {
        authority.transitions[0].candidate_record_sha256 = digest("different-candidate");
        reseal_phase_authority(authority);
    });
    assert_rejected!(|authority: &mut LegacyUploadMigrationPhaseAuthority| {
        authority.transitions[0].updated_record_sha256 = digest("different-updated");
    });
    assert_rejected!(|authority: &mut LegacyUploadMigrationPhaseAuthority| {
        authority.transitions[0].witness_sha256 = digest("different-witness");
    });
    assert_rejected!(|authority: &mut LegacyUploadMigrationPhaseAuthority| {
        authority.transitions[0].payload_sha256 = digest("different-payload");
    });

    let (mut wrong_pair, updated) = test_phase_authority(
        [&prepared_a, &prepared_b],
        [&prepared_a, &prepared_b],
        LegacyUploadMigrationPhase::DeleteConfirmed,
    );
    wrong_pair.transitions[1].asset_id = "different-asset".to_string();
    reseal_phase_authority(&mut wrong_pair);
    assert!(matches!(
        advance_authorized_record(&prepared_b, &wrong_pair),
        Err(LegacyUploadMigrationError::PhaseAuthorityMismatch)
    ));
    assert_phase_authority_rejected_without_writes(
        &writer,
        &wrong_pair,
        [&prepared_a, &prepared_b],
        [&updated[0], &updated[1]],
    );

    let (mut wrong_expected, updated) = test_phase_authority(
        [&prepared_a, &prepared_b],
        [&prepared_a, &prepared_b],
        LegacyUploadMigrationPhase::DeleteConfirmed,
    );
    wrong_expected.transitions[0].expected_record_sha256 = digest("different-expected");
    reseal_phase_authority(&mut wrong_expected);
    assert_phase_authority_rejected_without_writes(
        &writer,
        &wrong_expected,
        [&prepared_a, &prepared_b],
        [&updated[0], &updated[1]],
    );

    assert_eq!(writer.load().unwrap().get("asset-a").unwrap(), &prepared_a);
    assert_eq!(writer.load().unwrap().get("asset-b").unwrap(), &prepared_b);
    drop(temp);
}

#[test]
fn sealed_manifest_record_authority_preserves_exact_snapshot_and_rejects_substitution() {
    let initial_a = record("asset-a");
    let initial_b = record("asset-b");
    let (_, prepared_a, prepared_b) = prepare_authorized_pair(&initial_a, &initial_b);
    let authority_a =
        LegacyUploadMigrationManifestRecordAuthority::for_record(&prepared_a).unwrap();
    let authority_b =
        LegacyUploadMigrationManifestRecordAuthority::for_record(&prepared_b).unwrap();

    let mut manifest = Manifest::new();
    manifest
        .upsert_legacy_upload_migration_record(&authority_a, prepared_a.clone())
        .unwrap();
    manifest
        .upsert_legacy_upload_migration_record(&authority_b, prepared_b.clone())
        .unwrap();
    let snapshot = manifest
        .snapshot_legacy_upload_migration_record(&authority_a, "asset-a")
        .unwrap();
    assert_eq!(snapshot.records().len(), 1);
    assert_eq!(snapshot.get("asset-a").unwrap(), &prepared_a);
    validate_legacy_upload_migration_record(snapshot.get("asset-a").unwrap()).unwrap();

    let before = manifest.clone();
    assert!(matches!(
        manifest.upsert_legacy_upload_migration_record(&authority_a, prepared_b.clone()),
        Err(ManifestError::ReservedInternalProofCapabilityMismatch)
    ));
    let mut tampered = prepared_a.clone();
    tampered
        .proofs
        .insert("substituted".to_string(), json!({"forged": true}));
    assert!(matches!(
        manifest.upsert_legacy_upload_migration_record(&authority_a, tampered),
        Err(ManifestError::ReservedInternalProofCapabilityMismatch)
    ));
    assert!(matches!(
        manifest.snapshot_legacy_upload_migration_record(&authority_a, "asset-b"),
        Err(ManifestError::ReservedInternalProofCapabilityMismatch)
    ));
    assert_eq!(manifest, before);
}

#[test]
fn journal_only_phases_reject_deletion_conversion_upload_and_mirror_mutations() {
    let prepared = lifecycle_record_at_phase("asset-a", LegacyUploadMigrationPhase::Prepared);
    let confirmed = lifecycle_candidate(&prepared, LegacyUploadMigrationPhase::DeleteConfirmed);

    for proof_name in [
        "uploaded_heic_delete",
        "conversion",
        "upload",
        "icloudpd_local_mirror",
    ] {
        let mut changed = confirmed.clone();
        changed.proofs.insert(
            proof_name.to_string(),
            json!({"forged_at_wrong_phase": proof_name}),
        );
        assert!(matches!(
            validate_legacy_upload_migration_record_update(&prepared, &changed),
            Err(LegacyUploadMigrationCommitError::InvalidRecordTransition)
        ));
    }
}

#[test]
fn phase_owned_deltas_reject_state_skips_and_upstream_proof_changes() {
    let quarantined = lifecycle_record_at_phase("asset-a", LegacyUploadMigrationPhase::Quarantined);
    let reset = lifecycle_candidate(&quarantined, LegacyUploadMigrationPhase::Reset);

    let mut skipped_state = reset.clone();
    skipped_state.state = State::ConversionVerified;
    assert!(matches!(
        validate_legacy_upload_migration_record_update(&quarantined, &skipped_state),
        Err(LegacyUploadMigrationCommitError::InvalidRecordTransition)
    ));

    for proof_name in ["nas", "original_asset", "source_age"] {
        let mut removed = reset.clone();
        removed.proofs.remove(proof_name);
        assert!(matches!(
            validate_legacy_upload_migration_record_update(&quarantined, &removed),
            Err(LegacyUploadMigrationCommitError::InvalidRecordTransition)
        ));

        let mut altered = reset.clone();
        altered
            .proofs
            .insert(proof_name.to_string(), json!({"forged": proof_name}));
        assert!(matches!(
            validate_legacy_upload_migration_record_update(&quarantined, &altered),
            Err(LegacyUploadMigrationCommitError::InvalidRecordTransition)
        ));
    }
}

#[test]
fn typed_phase_deltas_reject_forged_conversion_upload_and_mirror_proofs() {
    let reset = lifecycle_record_at_phase("asset-a", LegacyUploadMigrationPhase::Reset);
    let converted = lifecycle_candidate(&reset, LegacyUploadMigrationPhase::Converted);
    let mut forged_conversion = converted.clone();
    forged_conversion.proofs.get_mut("conversion").unwrap()["heic_sha256"] =
        json!(digest("forged-conversion"));
    assert!(matches!(
        validate_legacy_upload_migration_record_update(&reset, &forged_conversion),
        Err(LegacyUploadMigrationCommitError::InvalidRecordTransition)
    ));
    let mut noncanonical_conversion = converted.clone();
    noncanonical_conversion.proofs.get_mut("heic").unwrap()["unexpected"] = json!(true);
    assert!(matches!(
        validate_legacy_upload_migration_record_update(&reset, &noncanonical_conversion),
        Err(LegacyUploadMigrationCommitError::InvalidRecordTransition)
    ));

    let upload_prepared =
        lifecycle_record_at_phase("asset-a", LegacyUploadMigrationPhase::UploadPrepared);
    let uploaded =
        lifecycle_candidate(&upload_prepared, LegacyUploadMigrationPhase::UploadVerified);
    let mut forged_upload = uploaded.clone();
    forged_upload.proofs.get_mut("upload").unwrap()["uploaded_heic_sha256"] =
        json!(digest("forged-upload"));
    assert!(matches!(
        validate_legacy_upload_migration_record_update(&upload_prepared, &forged_upload),
        Err(LegacyUploadMigrationCommitError::InvalidRecordTransition)
    ));

    let mirrored = lifecycle_candidate(&uploaded, LegacyUploadMigrationPhase::Mirrored);
    let mut forged_mirror = mirrored.clone();
    forged_mirror
        .proofs
        .get_mut("icloudpd_local_mirror")
        .unwrap()["uploaded_heic_asset_id"] = json!("wrong-upload");
    assert!(matches!(
        validate_legacy_upload_migration_record_update(&uploaded, &forged_mirror),
        Err(LegacyUploadMigrationCommitError::InvalidRecordTransition)
    ));
}

#[test]
fn exact_cas_conflict_changes_neither_record() {
    let temp = tempfile::tempdir().unwrap();
    let manifest_path = temp.path().join("manifest.json");
    let mut seed = Manifest::new();
    seed.upsert(record("asset-a"));
    seed.upsert(record("asset-b"));
    seed.save_atomic(&manifest_path).unwrap();
    let writer = AssetStateStore::open_writer(
        &manifest_path,
        "legacy-upload-migration-conflict-test",
        Duration::from_secs(30),
    )
    .unwrap();
    let durable = writer.load_or_import().unwrap();
    let expected_a = durable.get("asset-a").unwrap().clone();
    let expected_b = durable.get("asset-b").unwrap().clone();
    let (authority, prepared_a, prepared_b) = prepare_authorized_pair(&expected_a, &expected_b);
    persist_two_legacy_upload_migration_preparations_exact_cas(
        &writer,
        &authority,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &expected_a,
                updated: &prepared_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &expected_b,
                updated: &prepared_b,
            },
        ],
    )
    .unwrap();
    let advanced_a = advance_legacy_upload_migration_record(
        &prepared_a,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();
    let advanced_b = advance_legacy_upload_migration_record(
        &prepared_b,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();
    persist_two_legacy_upload_migration_records_exact_cas(
        &writer,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &prepared_a,
                updated: &advanced_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &prepared_b,
                updated: &advanced_b,
            },
        ],
    )
    .unwrap();

    let error = persist_two_legacy_upload_migration_records_exact_cas(
        &writer,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &prepared_a,
                updated: &advanced_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &prepared_b,
                updated: &advanced_b,
            },
        ],
    )
    .unwrap_err();
    assert!(matches!(
        error,
        LegacyUploadMigrationCommitError::StateStore(AssetStateStoreError::ExactCasMismatch { .. })
    ));

    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &advanced_a);
    assert_eq!(after.get("asset-b").unwrap(), &advanced_b);
}

#[test]
fn journal_json_seals_quarantine_paths_without_credentials() {
    let prepared = prepare(&record("asset-a"));
    let value: Value = prepared.proofs[LEGACY_UPLOAD_MIGRATION_PROOF_NAME].clone();
    let encoded = serde_json::to_string(&value).unwrap();
    let journal: LegacyUploadMigrationJournal = serde_json::from_value(value).unwrap();

    assert_eq!(journal.identity.quarantine_plan.members.len(), 9);
    assert_eq!(journal.identity.quarantine_plan.raw_inputs.len(), 10);
    assert!(encoded.contains("/quarantine/"));
    assert!(encoded.contains("/raw/"));
    for forbidden in ["session", "password", "cookie"] {
        assert!(!encoded.contains(forbidden));
    }
}

#[test]
fn exact_record_transition_rejects_rollback_and_truncation() {
    let prepared = prepare(&record("asset-a"));
    let confirmed = advance_legacy_upload_migration_record(
        &prepared,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();
    let mut truncated = confirmed.clone();
    let mut truncated_journal = journal(&truncated);
    truncated_journal.entries.truncate(1);
    replace_journal(&mut truncated, &truncated_journal);

    for rolled_back in [prepared, truncated] {
        assert!(matches!(
            validate_legacy_upload_migration_record_update(&confirmed, &rolled_back),
            Err(LegacyUploadMigrationCommitError::InvalidRecordTransition)
        ));
    }
}

#[test]
fn exact_record_transition_rejects_every_unrelated_record_mutation() {
    let prepared = prepare(&record("asset-a"));
    let confirmed = advance_legacy_upload_migration_record(
        &prepared,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();
    let mut mutations = Vec::new();

    let mut changed = confirmed.clone();
    changed
        .proofs
        .insert("unrelated".to_string(), json!({"new": true}));
    mutations.push(changed);
    let mut changed = confirmed.clone();
    changed.proofs.remove("nas");
    mutations.push(changed);
    let mut changed = confirmed.clone();
    changed.state = State::DeleteEligible;
    mutations.push(changed);
    let mut changed = confirmed.clone();
    changed
        .failures
        .push(FailureRecord::new("injected", "change"));
    mutations.push(changed);
    let mut changed = confirmed.clone();
    changed.raw_path = "/different/raw.dng".into();
    mutations.push(changed);
    let mut changed = confirmed.clone();
    changed.updated_at = "2026-07-13T00:00:01Z".to_string();
    mutations.push(changed);

    for changed in mutations {
        assert!(matches!(
            validate_legacy_upload_migration_record_update(&prepared, &changed),
            Err(LegacyUploadMigrationCommitError::InvalidRecordTransition)
        ));
    }
}

#[test]
fn exact_record_transition_accepts_only_identical_replay_or_one_next_entry() {
    let prepared = prepare(&record("asset-a"));
    assert_eq!(
        validate_legacy_upload_migration_record_update(&prepared, &prepared).unwrap(),
        LegacyUploadMigrationTransitionShape::Replay {
            phase: LegacyUploadMigrationPhase::Prepared,
        }
    );

    let confirmed = advance_legacy_upload_migration_record(
        &prepared,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();
    assert_eq!(
        validate_legacy_upload_migration_record_update(&prepared, &confirmed).unwrap(),
        LegacyUploadMigrationTransitionShape::Advance {
            from: LegacyUploadMigrationPhase::Prepared,
            to: LegacyUploadMigrationPhase::DeleteConfirmed,
        }
    );
}

#[test]
fn atomic_pair_rejects_one_replay_plus_one_advance_without_writes() {
    let (temp, writer, prepared_a, prepared_b) = prepared_pair("mixed");
    let advanced_b = advance_legacy_upload_migration_record(
        &prepared_b,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();

    let error = persist_two_legacy_upload_migration_records_exact_cas(
        &writer,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &prepared_a,
                updated: &prepared_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &prepared_b,
                updated: &advanced_b,
            },
        ],
    )
    .unwrap_err();
    assert!(matches!(
        error,
        LegacyUploadMigrationCommitError::BatchTransitionMismatch
    ));
    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &prepared_a);
    assert_eq!(after.get("asset-b").unwrap(), &prepared_b);
    drop(temp);
}

#[test]
fn atomic_pair_rejects_one_invalid_record_without_writes() {
    let (temp, writer, prepared_a, prepared_b) = prepared_pair("invalid");
    let advanced_a = advance_legacy_upload_migration_record(
        &prepared_a,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();
    let mut invalid_b = advance_legacy_upload_migration_record(
        &prepared_b,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();
    invalid_b
        .proofs
        .insert("unrelated".to_string(), json!(true));

    assert!(matches!(
        persist_two_legacy_upload_migration_records_exact_cas(
            &writer,
            [
                LegacyUploadMigrationCasUpdate {
                    expected: &prepared_a,
                    updated: &advanced_a,
                },
                LegacyUploadMigrationCasUpdate {
                    expected: &prepared_b,
                    updated: &invalid_b,
                },
            ],
        ),
        Err(LegacyUploadMigrationCommitError::InvalidRecordTransition)
    ));
    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &prepared_a);
    assert_eq!(after.get("asset-b").unwrap(), &prepared_b);
    drop(temp);
}

#[test]
fn atomic_reset_pair_rejects_delta_disagreement_without_writing_either_record() {
    let (temp, writer, quarantined_a, quarantined_b) = lifecycle_pair_at_phase(
        "reset-delta-disagreement",
        LegacyUploadMigrationPhase::Quarantined,
    );
    let reset_a = lifecycle_candidate(&quarantined_a, LegacyUploadMigrationPhase::Reset);
    let mut reset_b = lifecycle_candidate(&quarantined_b, LegacyUploadMigrationPhase::Reset);
    reset_b.proofs.remove("nas");

    assert!(matches!(
        persist_two_legacy_upload_migration_records_exact_cas(
            &writer,
            [
                LegacyUploadMigrationCasUpdate {
                    expected: &quarantined_a,
                    updated: &reset_a,
                },
                LegacyUploadMigrationCasUpdate {
                    expected: &quarantined_b,
                    updated: &reset_b,
                },
            ],
        ),
        Err(LegacyUploadMigrationCommitError::InvalidRecordTransition)
    ));
    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &quarantined_a);
    assert_eq!(after.get("asset-b").unwrap(), &quarantined_b);
    drop(temp);
}

#[test]
fn atomic_pair_accepts_an_exact_two_record_replay() {
    let (temp, writer, prepared_a, prepared_b) = prepared_pair("replay");
    persist_two_legacy_upload_migration_records_exact_cas(
        &writer,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &prepared_a,
                updated: &prepared_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &prepared_b,
                updated: &prepared_b,
            },
        ],
    )
    .unwrap();
    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &prepared_a);
    assert_eq!(after.get("asset-b").unwrap(), &prepared_b);
    drop(temp);
}

fn prepared_pair(
    owner_suffix: &str,
) -> (tempfile::TempDir, AssetStateStore, AssetRecord, AssetRecord) {
    let temp = tempfile::tempdir().unwrap();
    let manifest_path = temp.path().join("manifest.json");
    let mut seed = Manifest::new();
    seed.upsert(record("asset-a"));
    seed.upsert(record("asset-b"));
    seed.save_atomic(&manifest_path).unwrap();
    let writer = AssetStateStore::open_writer(
        &manifest_path,
        format!("legacy-upload-migration-{owner_suffix}-test"),
        Duration::from_secs(30),
    )
    .unwrap();
    let initial = writer.load_or_import().unwrap();
    let expected_a = initial.get("asset-a").unwrap().clone();
    let expected_b = initial.get("asset-b").unwrap().clone();
    let (authority, prepared_a, prepared_b) = prepare_authorized_pair(&expected_a, &expected_b);
    persist_two_legacy_upload_migration_preparations_exact_cas(
        &writer,
        &authority,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &expected_a,
                updated: &prepared_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &expected_b,
                updated: &prepared_b,
            },
        ],
    )
    .unwrap();
    (temp, writer, prepared_a, prepared_b)
}

fn lifecycle_pair_at_phase(
    owner_suffix: &str,
    target: LegacyUploadMigrationPhase,
) -> (tempfile::TempDir, AssetStateStore, AssetRecord, AssetRecord) {
    let temp = tempfile::tempdir().unwrap();
    let manifest_path = temp.path().join("manifest.json");
    let mut seed = Manifest::new();
    seed.upsert(lifecycle_record("asset-a"));
    seed.upsert(lifecycle_record("asset-b"));
    seed.save_atomic(&manifest_path).unwrap();
    let writer = AssetStateStore::open_writer(
        &manifest_path,
        format!("legacy-upload-migration-{owner_suffix}-test"),
        Duration::from_secs(30),
    )
    .unwrap();
    let initial = writer.load_or_import().unwrap();
    let expected_a = initial.get("asset-a").unwrap().clone();
    let expected_b = initial.get("asset-b").unwrap().clone();
    let (authority, prepared_a, prepared_b) = prepare_authorized_pair(&expected_a, &expected_b);
    let mut current_a = prepared_a;
    let mut current_b = prepared_b;
    persist_two_legacy_upload_migration_preparations_exact_cas(
        &writer,
        &authority,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &expected_a,
                updated: &current_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &expected_b,
                updated: &current_b,
            },
        ],
    )
    .unwrap();
    if target == LegacyUploadMigrationPhase::Prepared {
        return (temp, writer, current_a, current_b);
    }

    for phase in LegacyUploadMigrationPhase::ORDER.into_iter().skip(1) {
        let updated_a = lifecycle_candidate(&current_a, phase);
        let updated_b = lifecycle_candidate(&current_b, phase);
        persist_two_legacy_upload_migration_records_exact_cas(
            &writer,
            [
                LegacyUploadMigrationCasUpdate {
                    expected: &current_a,
                    updated: &updated_a,
                },
                LegacyUploadMigrationCasUpdate {
                    expected: &current_b,
                    updated: &updated_b,
                },
            ],
        )
        .unwrap();
        current_a = updated_a;
        current_b = updated_b;
        if phase == target {
            return (temp, writer, current_a, current_b);
        }
    }
    unreachable!("target phase belongs to the fixed migration order")
}

#[test]
fn validation_rejects_unknown_fields_at_every_persisted_object_level() {
    let completed = complete_journal(prepare(&record("asset-a")));
    for location in [
        UnknownFieldLocation::Journal,
        UnknownFieldLocation::Identity,
        UnknownFieldLocation::Entry(0),
        UnknownFieldLocation::Entry(4),
        UnknownFieldLocation::Entry(8),
    ] {
        let changed = inject_unknown_field(&completed, location);
        assert!(validate_legacy_upload_migration_record(&changed).is_err());
    }
}

#[test]
fn prepare_and_advance_reject_unknown_fields_without_changing_the_input() {
    let prepared = prepare(&record("asset-a"));
    let identity = journal(&prepared).identity;
    let companion = record("asset-b");
    let mut authority = test_cohort_authority(&record("asset-a"), &companion);
    authority.preparations[0].identity = identity;
    let unknown_prepare = inject_unknown_field(&prepared, UnknownFieldLocation::Journal);
    let before_prepare = unknown_prepare.clone();
    assert!(prepare_legacy_upload_migration_record(&unknown_prepare, &authority).is_err());
    assert_eq!(unknown_prepare, before_prepare);

    let unknown_advance = inject_unknown_field(&prepared, UnknownFieldLocation::Identity);
    let before_advance = unknown_advance.clone();
    assert!(
        advance_legacy_upload_migration_record(
            &unknown_advance,
            LegacyUploadMigrationPhase::DeleteConfirmed,
            &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
        )
        .is_err()
    );
    assert_eq!(unknown_advance, before_advance);
}

#[test]
fn authoritative_cas_rejects_unknown_entry_field_before_writing_either_record() {
    let (temp, writer, prepared_a, prepared_b) = prepared_pair("unknown-field");
    let advanced_a = advance_legacy_upload_migration_record(
        &prepared_a,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();
    let advanced_b = advance_legacy_upload_migration_record(
        &prepared_b,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();
    let advanced_b = inject_unknown_field(&advanced_b, UnknownFieldLocation::Entry(1));

    assert!(matches!(
        persist_two_legacy_upload_migration_records_exact_cas(
            &writer,
            [
                LegacyUploadMigrationCasUpdate {
                    expected: &prepared_a,
                    updated: &advanced_a,
                },
                LegacyUploadMigrationCasUpdate {
                    expected: &prepared_b,
                    updated: &advanced_b,
                },
            ],
        ),
        Err(LegacyUploadMigrationCommitError::InvalidRecordTransition)
    ));
    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &prepared_a);
    assert_eq!(after.get("asset-b").unwrap(), &prepared_b);
    drop(temp);
}

#[test]
fn strict_valid_journal_round_trips_to_identical_canonical_json() {
    let value = journal(&complete_journal(prepare(&record("asset-a"))));
    let encoded = serde_json::to_vec(&value).unwrap();
    let decoded: LegacyUploadMigrationJournal = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), encoded);
}

#[test]
fn direct_schema_deserialization_rejects_duplicate_json_keys() {
    let value = journal(&prepare(&record("asset-a")));
    let encoded = serde_json::to_string(&value).unwrap();
    let duplicated = format!("{{\"schema_version\":1,{}", &encoded[1..]);
    assert!(serde_json::from_str::<LegacyUploadMigrationJournal>(&duplicated).is_err());
}

#[test]
fn migration_error_boundaries_redact_nested_json_and_state_store_details() {
    let json_error = sensitive_migration_json_error();
    assert!(matches!(json_error, LegacyUploadMigrationError::Json(_)));
    assert_eq!(json_error.category(), "invalid_json");
    assert!(json_error.json_error().is_some());
    assert_operator_error_redacted(
        &json_error,
        "legacy upload migration journal JSON is invalid",
    );
    assert!(json_error.source().is_none());

    let sensitive_path = PathBuf::from(format!("/private/{}", sentinel_payload()));
    let commit_error =
        LegacyUploadMigrationCommitError::StateStore(AssetStateStoreError::JsonCheckpointUnsafe {
            path: sensitive_path.clone(),
        });
    match &commit_error {
        LegacyUploadMigrationCommitError::StateStore(
            AssetStateStoreError::JsonCheckpointUnsafe { path },
        ) => assert_eq!(path, &sensitive_path),
        other => panic!("typed state-store error was not preserved: {other:?}"),
    }
    assert_eq!(commit_error.category(), "state_store");
    assert!(commit_error.state_store_error().is_some());
    assert_operator_error_redacted(&commit_error, "legacy upload migration state commit failed");
    assert!(commit_error.source().is_none());
}

#[test]
fn monitor_cli_and_serialized_report_wrappers_keep_migration_errors_redacted() {
    let cli_error = crate::cli::CliError::Monitor(
        crate::monitor::MonitorError::LegacyUploadMigration(sensitive_migration_json_error()),
    );

    assert_operator_error_redacted(
        &cli_error,
        "legacy upload migration journal JSON is invalid",
    );
    let report = serde_json::to_string(&json!({
        "category": "legacy_upload_migration_invalid_json",
        "error": cli_error.to_string(),
    }))
    .unwrap();
    assert!(report.contains("legacy_upload_migration_invalid_json"));
    for sentinel in OPERATOR_REDACTION_SENTINELS {
        assert!(
            !report.contains(sentinel),
            "serialized report leaked {sentinel}"
        );
    }
}

#[test]
fn preparation_authority_and_advance_reject_requested_asset_identity_mismatch() {
    let original = record("asset-a");
    let companion = record("asset-c");
    let mut authority = test_cohort_authority(&original, &companion);
    authority.preparations[0].identity.asset_id = "asset-b".to_string();
    let before = original.clone();
    assert!(matches!(
        prepare_legacy_upload_migration_record(&original, &authority),
        Err(LegacyUploadMigrationError::CohortAuthorityMismatch)
    ));
    assert_eq!(original, before);

    let prepared = prepare(&original);
    let mut wrong_record = prepared.clone();
    wrong_record.asset_id = "asset-b".to_string();
    let before = wrong_record.clone();
    assert!(matches!(
        advance_legacy_upload_migration_record(
            &wrong_record,
            LegacyUploadMigrationPhase::DeleteConfirmed,
            &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
        ),
        Err(LegacyUploadMigrationError::IdentityMismatch)
    ));
    assert_eq!(wrong_record, before);
}

#[test]
fn atomic_wrapper_rejects_duplicate_asset_updates_without_writes() {
    let (temp, writer, prepared_a, prepared_b) = prepared_pair("duplicate-request");
    let advanced_a = advance_legacy_upload_migration_record(
        &prepared_a,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();
    let error = persist_two_legacy_upload_migration_records_exact_cas(
        &writer,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &prepared_a,
                updated: &advanced_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &prepared_a,
                updated: &advanced_a,
            },
        ],
    )
    .unwrap_err();
    assert!(matches!(
        error,
        LegacyUploadMigrationCommitError::DuplicateAsset
    ));
    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &prepared_a);
    assert_eq!(after.get("asset-b").unwrap(), &prepared_b);
    drop(temp);
}

#[test]
fn atomic_wrapper_rejects_expected_updated_asset_id_mismatch_without_writes() {
    let (temp, writer, prepared_a, prepared_b) = prepared_pair("mismatched-request");
    let confirmed_a = advance_legacy_upload_migration_record(
        &prepared_a,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();
    let confirmed_b = advance_legacy_upload_migration_record(
        &prepared_b,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();

    assert!(matches!(
        persist_two_legacy_upload_migration_records_exact_cas(
            &writer,
            [
                LegacyUploadMigrationCasUpdate {
                    expected: &prepared_a,
                    updated: &confirmed_b,
                },
                LegacyUploadMigrationCasUpdate {
                    expected: &prepared_b,
                    updated: &confirmed_a,
                },
            ],
        ),
        Err(LegacyUploadMigrationCommitError::InvalidRecordTransition)
    ));
    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &prepared_a);
    assert_eq!(after.get("asset-b").unwrap(), &prepared_b);
    drop(temp);
}

#[test]
fn preparation_wrapper_rejects_cross_cohort_pair_without_writes() {
    let temp = tempfile::tempdir().unwrap();
    let manifest_path = temp.path().join("manifest.json");
    let mut seed = Manifest::new();
    seed.upsert(record("asset-a"));
    seed.upsert(record("asset-b"));
    seed.save_atomic(&manifest_path).unwrap();
    let writer = AssetStateStore::open_writer(
        &manifest_path,
        "legacy-upload-migration-cross-cohort-test",
        Duration::from_secs(30),
    )
    .unwrap();
    let initial = writer.load_or_import().unwrap();
    let expected_a = initial.get("asset-a").unwrap().clone();
    let expected_b = initial.get("asset-b").unwrap().clone();
    let authority = test_cohort_authority(&expected_a, &expected_b);
    let prepared_a = prepare_authorized(&expected_a, &authority);
    let mut other_authority = test_cohort_authority(&expected_a, &expected_b);
    for preparation in &mut other_authority.preparations {
        preparation.identity.cohort_sha256 = digest("other-cohort");
    }
    let prepared_b = prepare_authorized(&expected_b, &other_authority);

    assert!(matches!(
        persist_two_legacy_upload_migration_preparations_exact_cas(
            &writer,
            &authority,
            [
                LegacyUploadMigrationCasUpdate {
                    expected: &expected_a,
                    updated: &prepared_a,
                },
                LegacyUploadMigrationCasUpdate {
                    expected: &expected_b,
                    updated: &prepared_b,
                },
            ],
        ),
        Err(LegacyUploadMigrationCommitError::CohortAuthorityMismatch)
    ));
    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &expected_a);
    assert_eq!(after.get("asset-b").unwrap(), &expected_b);
}

#[test]
fn atomic_wrapper_rejects_different_phase_progress_without_writes() {
    let (temp, writer, prepared_a, prepared_b) = prepared_pair("phase-progress");
    let confirmed_a = advance_legacy_upload_migration_record(
        &prepared_a,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();
    let confirmed_b = advance_legacy_upload_migration_record(
        &prepared_b,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();
    let quarantined_b = advance_legacy_upload_migration_record(
        &confirmed_b,
        LegacyUploadMigrationPhase::Quarantined,
        &witness(LegacyUploadMigrationPhase::Quarantined),
    )
    .unwrap();

    assert!(matches!(
        persist_two_legacy_upload_migration_records_exact_cas(
            &writer,
            [
                LegacyUploadMigrationCasUpdate {
                    expected: &prepared_a,
                    updated: &confirmed_a,
                },
                LegacyUploadMigrationCasUpdate {
                    expected: &confirmed_b,
                    updated: &quarantined_b,
                },
            ],
        ),
        Err(LegacyUploadMigrationCommitError::BatchTransitionMismatch)
    ));
    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &prepared_a);
    assert_eq!(after.get("asset-b").unwrap(), &prepared_b);
    drop(temp);
}

#[test]
fn atomic_wrapper_requires_writer_lease_and_changes_nothing_without_it() {
    let (temp, writer, prepared_a, prepared_b) = prepared_pair("missing-writer");
    drop(writer);
    let manifest_path = temp.path().join("manifest.json");
    let read_only = AssetStateStore::open_read_only(&manifest_path).unwrap();
    let confirmed_a = advance_legacy_upload_migration_record(
        &prepared_a,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();
    let confirmed_b = advance_legacy_upload_migration_record(
        &prepared_b,
        LegacyUploadMigrationPhase::DeleteConfirmed,
        &witness(LegacyUploadMigrationPhase::DeleteConfirmed),
    )
    .unwrap();

    assert!(matches!(
        persist_two_legacy_upload_migration_records_exact_cas(
            &read_only,
            [
                LegacyUploadMigrationCasUpdate {
                    expected: &prepared_a,
                    updated: &confirmed_a,
                },
                LegacyUploadMigrationCasUpdate {
                    expected: &prepared_b,
                    updated: &confirmed_b,
                },
            ],
        ),
        Err(LegacyUploadMigrationCommitError::StateStore(
            AssetStateStoreError::WriterLeaseRequired
        ))
    ));
    let after = read_only.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &prepared_a);
    assert_eq!(after.get("asset-b").unwrap(), &prepared_b);
}

fn generic_writer_fixture(
    owner_suffix: &str,
) -> (tempfile::TempDir, AssetStateStore, AssetRecord, AssetRecord) {
    let temp = tempfile::tempdir().unwrap();
    let manifest_path = temp.path().join("manifest.json");
    let mut seed = Manifest::new();
    seed.upsert(record("asset-a"));
    seed.upsert(record("asset-b"));
    seed.save_atomic(&manifest_path).unwrap();
    let writer = AssetStateStore::open_writer(
        &manifest_path,
        format!("legacy-upload-migration-untrusted-{owner_suffix}"),
        Duration::from_secs(30),
    )
    .unwrap();
    let current = writer.load_or_import().unwrap();
    let expected_a = current.get("asset-a").unwrap().clone();
    let expected_b = current.get("asset-b").unwrap().clone();
    (temp, writer, expected_a, expected_b)
}

#[test]
fn public_single_record_persistence_rejects_reserved_journal_without_writes() {
    let (temp, writer, expected_a, expected_b) = generic_writer_fixture("single");
    let prepared_a = prepare(&expected_a);

    assert!(matches!(
        writer.persist_record(&prepared_a),
        Err(AssetStateStoreError::ReservedInternalProofRequiresAuthority)
    ));
    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &expected_a);
    assert_eq!(after.get("asset-b").unwrap(), &expected_b);
    drop(temp);
}

#[test]
fn public_batch_persistence_rejects_reserved_journal_without_writes() {
    let (temp, writer, expected_a, expected_b) = generic_writer_fixture("batch");
    let prepared_a = prepare(&expected_a);
    let prepared_b = prepare(&expected_b);

    assert!(matches!(
        writer.persist_records_atomic([&prepared_a, &prepared_b]),
        Err(AssetStateStoreError::ReservedInternalProofRequiresAuthority)
    ));
    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &expected_a);
    assert_eq!(after.get("asset-b").unwrap(), &expected_b);
    drop(temp);
}

#[test]
fn public_exact_cas_rejects_reserved_journal_without_writes() {
    let (temp, writer, expected_a, expected_b) = generic_writer_fixture("cas");
    let prepared_a = prepare(&expected_a);
    let prepared_b = prepare(&expected_b);

    assert!(matches!(
        writer.persist_records_exact_cas_atomic([
            AssetRecordExactCasUpdate {
                expected: &expected_a,
                updated: &prepared_a,
            },
            AssetRecordExactCasUpdate {
                expected: &expected_b,
                updated: &prepared_b,
            },
        ]),
        Err(AssetStateStoreError::ReservedInternalProofRequiresAuthority)
    ));
    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &expected_a);
    assert_eq!(after.get("asset-b").unwrap(), &expected_b);
    drop(temp);
}

#[test]
fn public_manifest_persistence_rejects_reserved_journal_without_writes() {
    let (temp, writer, expected_a, expected_b) = generic_writer_fixture("manifest");
    let mut requested = Manifest::new();
    let prepared_a = prepare(&expected_a);
    let authority = LegacyUploadMigrationManifestRecordAuthority::for_record(&prepared_a).unwrap();
    requested
        .upsert_legacy_upload_migration_record(&authority, prepared_a)
        .unwrap();
    requested.upsert(expected_b.clone());

    assert!(matches!(
        writer.persist_manifest_records(&requested),
        Err(AssetStateStoreError::ReservedInternalProofRequiresAuthority)
    ));
    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &expected_a);
    assert_eq!(after.get("asset-b").unwrap(), &expected_b);
    drop(temp);
}

#[test]
fn public_manifest_save_rejects_reserved_journal_without_creating_checkpoint() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().join("forged-checkpoint.json");
    let mut requested = Manifest::new();
    let prepared = prepare(&record("asset-a"));
    let authority = LegacyUploadMigrationManifestRecordAuthority::for_record(&prepared).unwrap();
    requested
        .upsert_legacy_upload_migration_record(&authority, prepared)
        .unwrap();

    assert!(matches!(
        requested.save_atomic(&destination),
        Err(ManifestError::ReservedInternalProofRequiresAuthority)
    ));
    assert!(!destination.exists());
}

#[test]
fn snapshot_import_rejects_reserved_journal_without_importing_any_record() {
    let temp = tempfile::tempdir().unwrap();
    let manifest_path = temp.path().join("manifest.json");
    let prepared = prepare(&record("asset-a"));
    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&json!({"records": [prepared]})).unwrap(),
    )
    .unwrap();
    let writer = AssetStateStore::open_writer(
        &manifest_path,
        "legacy-upload-migration-untrusted-import",
        Duration::from_secs(30),
    )
    .unwrap();

    assert!(matches!(
        writer.load_or_import(),
        Err(AssetStateStoreError::Manifest(
            ManifestError::ReservedInternalProofCapabilityMismatch
        ))
    ));
    let asset_count: i64 = rusqlite::Connection::open(writer.path())
        .unwrap()
        .query_row("SELECT count(*) FROM assets", [], |row| row.get(0))
        .unwrap();
    assert_eq!(asset_count, 0);
}

#[test]
fn public_manifest_transition_rejects_reserved_proof_before_mutation() {
    let mut manifest = Manifest::new();
    manifest.upsert(AssetRecord::new("asset-a", "/raw/asset-a.dng"));
    let before = manifest.get("asset-a").unwrap().clone();

    assert!(matches!(
        manifest.transition(
            "asset-a",
            State::NasVerified,
            LEGACY_UPLOAD_MIGRATION_PROOF_NAME,
            json!({"forged": true}),
        ),
        Err(ManifestError::ReservedInternalProofRequiresAuthority)
    ));
    assert_eq!(manifest.get("asset-a").unwrap(), &before);

    let mut failed = record("failed-asset");
    failed.state = State::Failed;
    let mut manifest = Manifest::new();
    manifest.upsert(failed);
    let before = manifest.get("failed-asset").unwrap().clone();
    assert!(matches!(
        manifest.terminalize_failed_with_proof(
            "failed-asset",
            LEGACY_UPLOAD_MIGRATION_PROOF_NAME,
            json!({"forged": true}),
        ),
        Err(ManifestError::ReservedInternalProofRequiresAuthority)
    ));
    assert_eq!(manifest.get("failed-asset").unwrap(), &before);
}

#[test]
fn public_exact_cas_cannot_remove_an_authoritative_reserved_journal() {
    let (temp, writer, expected_a, expected_b) = generic_writer_fixture("cas-removal");
    let (authority, prepared_a, prepared_b) = prepare_authorized_pair(&expected_a, &expected_b);
    persist_two_legacy_upload_migration_preparations_exact_cas(
        &writer,
        &authority,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &expected_a,
                updated: &prepared_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &expected_b,
                updated: &prepared_b,
            },
        ],
    )
    .unwrap();

    assert!(matches!(
        writer.persist_records_exact_cas_atomic([
            AssetRecordExactCasUpdate {
                expected: &prepared_a,
                updated: &expected_a,
            },
            AssetRecordExactCasUpdate {
                expected: &prepared_b,
                updated: &expected_b,
            },
        ]),
        Err(AssetStateStoreError::ReservedInternalProofRequiresAuthority)
    ));
    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &prepared_a);
    assert_eq!(after.get("asset-b").unwrap(), &prepared_b);
    drop(temp);
}

#[test]
fn public_non_cas_writers_cannot_remove_an_authoritative_reserved_journal() {
    let (temp, writer, expected_a, expected_b) = generic_writer_fixture("non-cas-removal");
    let (authority, prepared_a, prepared_b) = prepare_authorized_pair(&expected_a, &expected_b);
    persist_two_legacy_upload_migration_preparations_exact_cas(
        &writer,
        &authority,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &expected_a,
                updated: &prepared_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &expected_b,
                updated: &prepared_b,
            },
        ],
    )
    .unwrap();
    let mut without_journal_a = prepared_a.clone();
    without_journal_a
        .proofs
        .remove(LEGACY_UPLOAD_MIGRATION_PROOF_NAME);
    without_journal_a.updated_at = "2026-07-14T00:00:00Z".to_string();
    let mut without_journal_b = prepared_b.clone();
    without_journal_b
        .proofs
        .remove(LEGACY_UPLOAD_MIGRATION_PROOF_NAME);
    without_journal_b.updated_at = "2026-07-14T00:00:00Z".to_string();

    assert!(matches!(
        writer.persist_record(&without_journal_a),
        Err(AssetStateStoreError::ReservedInternalProofRequiresAuthority)
    ));
    assert!(matches!(
        writer.persist_records_atomic([&without_journal_a, &without_journal_b]),
        Err(AssetStateStoreError::ReservedInternalProofRequiresAuthority)
    ));
    let mut manifest = Manifest::new();
    manifest.upsert(without_journal_a);
    manifest.upsert(without_journal_b);
    assert!(matches!(
        writer.persist_manifest_records(&manifest),
        Err(AssetStateStoreError::ReservedInternalProofRequiresAuthority)
    ));

    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &prepared_a);
    assert_eq!(after.get("asset-b").unwrap(), &prepared_b);
    drop(temp);
}

#[test]
fn generic_trusted_cas_cannot_bypass_the_sealed_migration_write_authority() {
    let (temp, writer, expected_a, expected_b) = generic_writer_fixture("trusted-cas-seal");
    let (_, prepared_a, prepared_b) = prepare_authorized_pair(&expected_a, &expected_b);

    assert!(matches!(
        writer.persist_records_exact_cas_atomic_trusted([
            AssetRecordExactCasUpdate {
                expected: &expected_a,
                updated: &prepared_a,
            },
            AssetRecordExactCasUpdate {
                expected: &expected_b,
                updated: &prepared_b,
            },
        ]),
        Err(AssetStateStoreError::ReservedInternalProofRequiresAuthority)
    ));
    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), &expected_a);
    assert_eq!(after.get("asset-b").unwrap(), &expected_b);
    drop(temp);
}

fn assert_preparation_authority_rejected_without_writes(
    writer: &AssetStateStore,
    authority: &LegacyUploadMigrationCohortAuthority,
    expected_a: &AssetRecord,
    expected_b: &AssetRecord,
    prepared_a: &AssetRecord,
    prepared_b: &AssetRecord,
) {
    assert!(matches!(
        persist_two_legacy_upload_migration_preparations_exact_cas(
            writer,
            authority,
            [
                LegacyUploadMigrationCasUpdate {
                    expected: expected_a,
                    updated: prepared_a,
                },
                LegacyUploadMigrationCasUpdate {
                    expected: expected_b,
                    updated: prepared_b,
                },
            ],
        ),
        Err(LegacyUploadMigrationCommitError::CohortAuthorityMismatch)
    ));
    let after = writer.load().unwrap();
    assert_eq!(after.get("asset-a").unwrap(), expected_a);
    assert_eq!(after.get("asset-b").unwrap(), expected_b);
}

#[test]
fn authoritative_preparation_rejects_substituted_identity_and_witness_tokens() {
    let (temp, writer, expected_a, expected_b) = generic_writer_fixture("token-substitution");
    let (_, prepared_a, prepared_b) = prepare_authorized_pair(&expected_a, &expected_b);

    let mut substituted_identity = test_cohort_authority(&expected_a, &expected_b);
    substituted_identity.preparations[0]
        .identity
        .destination_sha256 = digest("substituted-destination");
    assert_preparation_authority_rejected_without_writes(
        &writer,
        &substituted_identity,
        &expected_a,
        &expected_b,
        &prepared_a,
        &prepared_b,
    );

    let mut substituted_witness = test_cohort_authority(&expected_a, &expected_b);
    for preparation in &mut substituted_witness.preparations {
        preparation.prepared_witness_sha256 = digest("substituted-preparation-witness");
    }
    assert_preparation_authority_rejected_without_writes(
        &writer,
        &substituted_witness,
        &expected_a,
        &expected_b,
        &prepared_a,
        &prepared_b,
    );
    drop(temp);
}

#[test]
fn cohort_authority_requires_two_distinct_assets_in_one_exact_cohort() {
    let (temp, writer, expected_a, expected_b) = generic_writer_fixture("token-shape");
    let (_, prepared_a, prepared_b) = prepare_authorized_pair(&expected_a, &expected_b);

    let mut duplicate_asset = test_cohort_authority(&expected_a, &expected_b);
    duplicate_asset.preparations[1].identity = duplicate_asset.preparations[0].identity.clone();
    assert_preparation_authority_rejected_without_writes(
        &writer,
        &duplicate_asset,
        &expected_a,
        &expected_b,
        &prepared_a,
        &prepared_b,
    );

    let mut split_cohort = test_cohort_authority(&expected_a, &expected_b);
    split_cohort.preparations[1].identity.cohort_sha256 = digest("split-cohort");
    assert_preparation_authority_rejected_without_writes(
        &writer,
        &split_cohort,
        &expected_a,
        &expected_b,
        &prepared_a,
        &prepared_b,
    );
    drop(temp);
}

#[test]
fn manifest_and_checkpoint_ingestion_reject_duplicate_migration_keys_before_import() {
    let completed = complete_journal(prepare(&record("asset-a")));

    for (case, location) in DUPLICATE_JSON_LOCATIONS.into_iter().enumerate() {
        let temp = tempfile::tempdir().unwrap();
        let manifest_path = temp.path().join("manifest.json");
        let duplicate = record_json_with_duplicate_key(&completed, location);
        std::fs::write(&manifest_path, manifest_json(&duplicate)).unwrap();

        let error = Manifest::load(&manifest_path).unwrap_err();
        match &error {
            ManifestError::Json(source) => assert_duplicate_json_error(source),
            other => panic!("expected duplicate-key JSON error for {location:?}, got {other}"),
        }

        let writer = AssetStateStore::open_writer(
            &manifest_path,
            format!("legacy-upload-migration-duplicate-json-{case}"),
            Duration::from_secs(30),
        )
        .unwrap();
        let error = writer.load_or_import().unwrap_err();
        match &error {
            AssetStateStoreError::Manifest(ManifestError::Json(source)) => {
                assert_duplicate_json_error(source);
            }
            other => panic!("expected duplicate-key import error for {location:?}, got {other}"),
        }
        assert!(writer.load().unwrap().records().is_empty());
    }
}

#[test]
fn sqlite_record_ingestion_rejects_duplicate_migration_keys_after_direct_tampering() {
    for (case, location) in DUPLICATE_JSON_LOCATIONS.into_iter().enumerate() {
        let (temp, writer, expected_a, expected_b) =
            generic_writer_fixture(&format!("duplicate-sqlite-{case}"));
        let (authority, prepared_a, prepared_b) = prepare_authorized_pair(&expected_a, &expected_b);
        persist_two_legacy_upload_migration_preparations_exact_cas(
            &writer,
            &authority,
            [
                LegacyUploadMigrationCasUpdate {
                    expected: &expected_a,
                    updated: &prepared_a,
                },
                LegacyUploadMigrationCasUpdate {
                    expected: &expected_b,
                    updated: &prepared_b,
                },
            ],
        )
        .unwrap();
        drop(writer);

        let completed_a = complete_journal(prepared_a);
        let duplicate = record_json_with_duplicate_key(&completed_a, location);
        let manifest_path = temp.path().join("manifest.json");
        let connection =
            rusqlite::Connection::open(AssetStateStore::db_path_for_manifest(&manifest_path))
                .unwrap();
        connection
            .execute(
                "UPDATE assets SET record_json = ?1 WHERE asset_id = 'asset-a'",
                [duplicate],
            )
            .unwrap();
        drop(connection);

        let reader = AssetStateStore::open_read_only(&manifest_path).unwrap();
        let error = reader.load().unwrap_err();
        match &error {
            AssetStateStoreError::DecodeRecord { asset_id, source } => {
                assert_eq!(asset_id, "asset-a");
                assert_duplicate_json_error(source);
            }
            other => panic!("expected duplicate-key database error for {location:?}, got {other}"),
        }
    }
}

#[test]
fn sealed_database_read_rejects_a_tampered_migration_journal() {
    let (temp, writer, expected_a, expected_b) = generic_writer_fixture("sealed-db-read");
    let (authority, prepared_a, prepared_b) = prepare_authorized_pair(&expected_a, &expected_b);
    persist_two_legacy_upload_migration_preparations_exact_cas(
        &writer,
        &authority,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &expected_a,
                updated: &prepared_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &expected_b,
                updated: &prepared_b,
            },
        ],
    )
    .unwrap();
    drop(writer);

    let mut tampered = prepared_a;
    tampered
        .proofs
        .get_mut(LEGACY_UPLOAD_MIGRATION_PROOF_NAME)
        .unwrap()["entries"][0]["witness_sha256"] = json!(digest("tampered-database-witness"));
    let manifest_path = temp.path().join("manifest.json");
    let connection =
        rusqlite::Connection::open(AssetStateStore::db_path_for_manifest(&manifest_path)).unwrap();
    connection
        .execute(
            "UPDATE assets SET record_json = ?1 WHERE asset_id = 'asset-a'",
            [serde_json::to_string(&tampered).unwrap()],
        )
        .unwrap();
    drop(connection);

    let reader = AssetStateStore::open_read_only(&manifest_path).unwrap();
    assert!(matches!(
        reader.load(),
        Err(AssetStateStoreError::Manifest(
            ManifestError::ReservedInternalProofCapabilityMismatch
        ))
    ));
}

#[test]
fn canonical_manifest_checkpoint_and_sqlite_records_still_round_trip() {
    let completed = complete_journal(prepare(&record("asset-a")));
    let temp = tempfile::tempdir().unwrap();
    let checkpoint_path = temp.path().join("trusted-checkpoint.json");
    std::fs::write(
        &checkpoint_path,
        manifest_json(&serde_json::to_string(&completed).unwrap()),
    )
    .unwrap();
    assert!(matches!(
        Manifest::load(&checkpoint_path),
        Err(ManifestError::ReservedInternalProofCapabilityMismatch)
    ));

    let (temp, writer, expected_a, expected_b) = generic_writer_fixture("canonical-sqlite");
    let (authority, prepared_a, prepared_b) = prepare_authorized_pair(&expected_a, &expected_b);
    persist_two_legacy_upload_migration_preparations_exact_cas(
        &writer,
        &authority,
        [
            LegacyUploadMigrationCasUpdate {
                expected: &expected_a,
                updated: &prepared_a,
            },
            LegacyUploadMigrationCasUpdate {
                expected: &expected_b,
                updated: &prepared_b,
            },
        ],
    )
    .unwrap();
    drop(writer);
    let reader = AssetStateStore::open_read_only(temp.path().join("manifest.json")).unwrap();
    let durable = reader.load().unwrap();
    assert_eq!(durable.get("asset-a").unwrap(), &prepared_a);
    assert_eq!(durable.get("asset-b").unwrap(), &prepared_b);
    validate_legacy_upload_migration_record(durable.get("asset-a").unwrap()).unwrap();
    validate_legacy_upload_migration_record(durable.get("asset-b").unwrap()).unwrap();

    let temp = tempfile::tempdir().unwrap();
    let manifest_path = temp.path().join("manifest.json");
    let ordinary = record("ordinary-asset");
    std::fs::write(
        &manifest_path,
        manifest_json(&serde_json::to_string(&ordinary).unwrap()),
    )
    .unwrap();
    let writer = AssetStateStore::open_writer(
        &manifest_path,
        "legacy-upload-migration-canonical-ordinary",
        Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(
        writer
            .load_or_import()
            .unwrap()
            .get("ordinary-asset")
            .unwrap(),
        &ordinary
    );
}

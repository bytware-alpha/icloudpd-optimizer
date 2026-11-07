//! Local staging for the documented Photos app import. This does not contact
//! Apple, does not choose a library, and does not record an upload.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::manifest::{Manifest, ManifestError, State};
use crate::workflow::{WorkflowError, ensure_upload_dispatch_allowed};

pub const PHOTOS_IMPORT_HANDOFF_PROOF: &str = "photos_import_handoff";
const HANDOFF_SCHEMA_VERSION: u64 = 1;
const REQUIRED_LIBRARY_CHOICE: &str = "shared_library";

/// Steps taken from Apple's Photos and iCloud Photos support articles.
/// The optimizer does not perform them.
pub const PHOTOS_APP_SHARED_LIBRARY_USER_STEP: &str = "On the Mac, keep Photos > Settings > General > Copy items to the Photos library selected. Referenced files are not stored in iCloud. Choose File > Import, select this staged HEIC, click Review for Import, and choose Shared Library from the Add To menu. Your Library is the personal library and is a different destination. Leave the NAS original and this staged file in place. This handoff does not upload, does not record remote readback, and does not choose the library.";

#[derive(Debug, Error)]
pub enum PhotosImportHandoffError {
    #[error(transparent)]
    Workflow(#[from] WorkflowError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("asset id cannot be used as a handoff filename")]
    UnsafeAssetId,
    #[error("handoff directory is not usable")]
    HandoffDirectory,
    #[error("verified HEIC bytes do not match the stored proof")]
    HeicBytesMismatch,
    #[error("staged HEIC does not match the handoff proof")]
    StagedBytesMismatch,
    #[error("refusing to replace a different staged HEIC; roll the handoff back first")]
    StagedFileConflict,
    #[error("refusing to delete the verified HEIC or the NAS original")]
    RefusingToDeleteSource,
    #[error("filesystem error during photos import handoff")]
    Io(#[source] io::Error),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PhotosImportHandoffProof {
    pub schema_version: u64,
    pub staged_path: PathBuf,
    pub staged_heic_sha256: String,
    pub staged_size_bytes: u64,
    pub source_heic_sha256: String,
    pub library_choice_required: String,
    pub records_upload: bool,
    pub records_remote_readback: bool,
    pub cloud_import_performed: bool,
    pub user_step: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PhotosImportHandoffReport {
    pub asset_id: String,
    pub state: State,
    pub changed: bool,
    pub proof: PhotosImportHandoffProof,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PhotosImportHandoffRollbackReport {
    pub asset_id: String,
    pub state: State,
    pub removed: bool,
    pub staged_file_removed: bool,
}

pub fn stage_verified_heic_for_photos_import(
    manifest: &mut Manifest,
    asset_id: &str,
    handoff_dir: &Path,
) -> Result<PhotosImportHandoffReport, PhotosImportHandoffError> {
    safe_asset_file_name(asset_id)?;
    let record = manifest.get(asset_id)?;
    if let Some(existing) = record.proofs.get(PHOTOS_IMPORT_HANDOFF_PROOF).cloned() {
        let state = record.state;
        let existing: PhotosImportHandoffProof =
            serde_json::from_value(existing).map_err(WorkflowError::from)?;
        let staged_path = handoff_dir.join(format!("{asset_id}.heic"));
        if existing.staged_path != staged_path
            || existing.records_upload
            || existing.records_remote_readback
            || existing.cloud_import_performed
            || existing.library_choice_required != REQUIRED_LIBRARY_CHOICE
        {
            return Err(PhotosImportHandoffError::StagedFileConflict);
        }
        let staged =
            hash_file(&staged_path).map_err(|_| PhotosImportHandoffError::StagedBytesMismatch)?;
        if staged.sha256 != existing.staged_heic_sha256
            || staged.size_bytes != existing.staged_size_bytes
        {
            return Err(PhotosImportHandoffError::StagedBytesMismatch);
        }
        let source_path = record
            .proofs
            .get("heic")
            .and_then(|proof| proof.get("heic_path"))
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .ok_or(PhotosImportHandoffError::HeicBytesMismatch)?;
        let source = hash_file(&source_path).map_err(PhotosImportHandoffError::Io)?;
        if source.sha256 != existing.source_heic_sha256
            || source.size_bytes != existing.staged_size_bytes
        {
            return Err(PhotosImportHandoffError::HeicBytesMismatch);
        }
        return Ok(PhotosImportHandoffReport {
            asset_id: asset_id.to_string(),
            state,
            changed: false,
            proof: existing,
        });
    }
    let heic = ensure_upload_dispatch_allowed(manifest, asset_id)?;
    let source_bytes = hash_file(&heic.heic_path).map_err(PhotosImportHandoffError::Io)?;
    if source_bytes.sha256 != heic.heic_sha256 || source_bytes.size_bytes != heic.size_bytes {
        return Err(PhotosImportHandoffError::HeicBytesMismatch);
    }
    fs::create_dir_all(handoff_dir).map_err(|_| PhotosImportHandoffError::HandoffDirectory)?;
    if !handoff_dir.is_dir() {
        return Err(PhotosImportHandoffError::HandoffDirectory);
    }
    let staged_path = handoff_dir.join(format!("{asset_id}.heic"));
    if same_file(&heic.heic_path, &staged_path).map_err(PhotosImportHandoffError::Io)? {
        return Err(PhotosImportHandoffError::RefusingToDeleteSource);
    }
    if staged_path.exists() {
        let staged = hash_file(&staged_path).map_err(PhotosImportHandoffError::Io)?;
        if staged != source_bytes {
            return Err(PhotosImportHandoffError::StagedFileConflict);
        }
    } else {
        copy_verified_bytes(&heic.heic_path, &staged_path, &source_bytes)?;
    }
    let proof = PhotosImportHandoffProof {
        schema_version: HANDOFF_SCHEMA_VERSION,
        staged_path,
        staged_heic_sha256: source_bytes.sha256.clone(),
        staged_size_bytes: source_bytes.size_bytes,
        source_heic_sha256: source_bytes.sha256,
        library_choice_required: REQUIRED_LIBRARY_CHOICE.to_string(),
        records_upload: false,
        records_remote_readback: false,
        cloud_import_performed: false,
        user_step: PHOTOS_APP_SHARED_LIBRARY_USER_STEP.to_string(),
    };
    let value = serde_json::to_value(&proof).map_err(WorkflowError::from)?;
    manifest.record_proof(asset_id, PHOTOS_IMPORT_HANDOFF_PROOF, value)?;
    let state = manifest.get(asset_id)?.state;
    Ok(PhotosImportHandoffReport {
        asset_id: asset_id.to_string(),
        state,
        changed: true,
        proof,
    })
}

pub fn rollback_photos_import_handoff(
    manifest: &mut Manifest,
    asset_id: &str,
) -> Result<PhotosImportHandoffRollbackReport, PhotosImportHandoffError> {
    let record = manifest.get(asset_id)?;
    let Some(existing) = record.proofs.get(PHOTOS_IMPORT_HANDOFF_PROOF).cloned() else {
        return Ok(PhotosImportHandoffRollbackReport {
            asset_id: asset_id.to_string(),
            state: record.state,
            removed: false,
            staged_file_removed: false,
        });
    };
    let proof: PhotosImportHandoffProof =
        serde_json::from_value(existing).map_err(WorkflowError::from)?;
    let raw_path = record.raw_path.clone();
    let heic_path = record
        .proofs
        .get("heic")
        .and_then(|proof| proof.get("heic_path"))
        .and_then(Value::as_str)
        .map(PathBuf::from);
    if same_file(&proof.staged_path, &raw_path).unwrap_or(true)
        || heic_path
            .as_ref()
            .is_some_and(|path| same_file(&proof.staged_path, path).unwrap_or(true))
    {
        return Err(PhotosImportHandoffError::RefusingToDeleteSource);
    }
    let mut staged_file_removed = false;
    if proof.staged_path.exists() {
        let staged = hash_file(&proof.staged_path).map_err(PhotosImportHandoffError::Io)?;
        if staged.sha256 != proof.staged_heic_sha256 || staged.size_bytes != proof.staged_size_bytes
        {
            return Err(PhotosImportHandoffError::StagedBytesMismatch);
        }
        fs::remove_file(&proof.staged_path).map_err(PhotosImportHandoffError::Io)?;
        staged_file_removed = true;
    }
    manifest.remove_proof_preserving_state(asset_id, PHOTOS_IMPORT_HANDOFF_PROOF)?;
    Ok(PhotosImportHandoffRollbackReport {
        asset_id: asset_id.to_string(),
        state: manifest.get(asset_id)?.state,
        removed: true,
        staged_file_removed,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HashedFile {
    sha256: String,
    size_bytes: u64,
}

fn hash_file(path: &Path) -> io::Result<HashedFile> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut size_bytes = 0_u64;
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size_bytes = size_bytes
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("file size overflow"))?;
        hasher.update(&buffer[..read]);
    }
    Ok(HashedFile {
        sha256: format!("{:x}", hasher.finalize()),
        size_bytes,
    })
}

fn copy_verified_bytes(
    source: &Path,
    destination: &Path,
    expected: &HashedFile,
) -> Result<(), PhotosImportHandoffError> {
    let temporary = destination.with_extension("heic.partial");
    let copy_result = (|| {
        let mut input = File::open(source)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        io::copy(&mut input, &mut output)?;
        output.flush()?;
        output.sync_all()?;
        Ok::<(), io::Error>(())
    })();
    if let Err(error) = copy_result {
        let _ = fs::remove_file(&temporary);
        return Err(PhotosImportHandoffError::Io(error));
    }
    let copied = match hash_file(&temporary) {
        Ok(copied) => copied,
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(PhotosImportHandoffError::Io(error));
        }
    };
    if copied != *expected {
        let _ = fs::remove_file(&temporary);
        return Err(PhotosImportHandoffError::HeicBytesMismatch);
    }
    let source_after = hash_file(source).map_err(PhotosImportHandoffError::Io)?;
    if source_after != *expected {
        let _ = fs::remove_file(&temporary);
        return Err(PhotosImportHandoffError::HeicBytesMismatch);
    }
    if let Err(error) = fs::rename(&temporary, destination) {
        let _ = fs::remove_file(&temporary);
        return Err(PhotosImportHandoffError::Io(error));
    }
    Ok(())
}

fn same_file(left: &Path, right: &Path) -> io::Result<bool> {
    if left == right {
        return Ok(true);
    }
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => Ok(left == right),
        (Err(error), _) | (_, Err(error)) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

fn safe_asset_file_name(asset_id: &str) -> Result<(), PhotosImportHandoffError> {
    if asset_id.is_empty()
        || asset_id == "."
        || asset_id == ".."
        || asset_id.contains(['/', '\\', '\0'])
    {
        Err(PhotosImportHandoffError::UnsafeAssetId)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operation_hold::{HeldRemoteOperation, OperationHold, apply_operation_hold};
    use crate::proof::prove_nas_raw;
    use crate::upload::CloudKitDatabaseScope;
    use crate::workflow::{
        ConversionPerformanceInput, ConversionResultInput, ConversionSourceBinding,
        HeicVerificationInput, discover_raw_asset, mark_delete_eligible,
        record_current_conversion_performance, record_current_conversion_result,
        record_current_heic_verification, record_nas_proof,
    };
    use filetime::{FileTime, set_file_mtime};
    use std::time::{Duration, SystemTime};

    fn verified_manifest(root: &Path, heic_bytes: &[u8]) -> (Manifest, PathBuf) {
        let nas_root = root.join("nas");
        fs::create_dir_all(nas_root.join("camera")).unwrap();
        let raw_path = nas_root.join("camera/IMG_0001.dng");
        fs::write(&raw_path, b"raw-bytes-that-are-larger-than-heic").unwrap();
        set_file_mtime(
            &raw_path,
            FileTime::from_system_time(SystemTime::now() - Duration::from_secs(40 * 24 * 60 * 60)),
        )
        .unwrap();
        let proof = prove_nas_raw(&nas_root, &raw_path, 30, SystemTime::now()).unwrap();
        let heic_path = root.join("verified.heic");
        fs::write(&heic_path, heic_bytes).unwrap();
        let heic_sha256 = hash_file(&heic_path).unwrap().sha256;
        let mut manifest = Manifest::new();
        discover_raw_asset(&mut manifest, "IMG_0001", proof.canonical_path.clone()).unwrap();
        record_nas_proof(&mut manifest, "IMG_0001", proof).unwrap();
        record_current_conversion_result(
            &mut manifest,
            "IMG_0001",
            ConversionResultInput {
                heic_path: heic_path.clone(),
                heic_sha256: heic_sha256.clone(),
                size_bytes: heic_bytes.len() as u64,
                source_binding: ConversionSourceBinding::EmbeddedPreview,
            },
        )
        .unwrap();
        record_current_conversion_performance(
            &mut manifest,
            "IMG_0001",
            ConversionPerformanceInput {
                measured_at_unix_seconds: 1_800_000_100,
                conversion_tool: "magick".to_string(),
                conversion_tool_version: Some("7.1.1-41".to_string()),
                heic_quality: 90,
                convert_wall_time_millis: 10,
                total_wall_time_millis: 12,
                user_cpu_time_millis: None,
                system_cpu_time_millis: None,
                peak_rss_kib: None,
                conversion_command_timings: Vec::new(),
            },
        )
        .unwrap();
        record_current_heic_verification(
            &mut manifest,
            "IMG_0001",
            HeicVerificationInput {
                heic_path: heic_path.clone(),
                heic_sha256,
                size_bytes: heic_bytes.len() as u64,
                heif_info_ok: true,
                metadata_copied: true,
                visual_content_ok: true,
                visual_match_ok: true,
                visual_rmse_ppm: Some(0),
                visual_mae_ppm: Some(0),
            },
        )
        .unwrap();
        (manifest, heic_path)
    }

    #[test]
    fn handoff_copies_heic_bytes_without_upload_delete_or_moving_the_original() {
        let root = tempfile::tempdir().unwrap();
        let heic_bytes = b"heic-bytes-not-a-real-container";
        let (mut manifest, heic_path) = verified_manifest(root.path(), heic_bytes);
        let raw_before = fs::read(manifest.get("IMG_0001").unwrap().raw_path.clone()).unwrap();
        let handoff_dir = root.path().join("handoff");
        let report =
            stage_verified_heic_for_photos_import(&mut manifest, "IMG_0001", &handoff_dir).unwrap();
        assert!(report.changed);
        assert!(!report.proof.records_upload);
        assert!(!report.proof.records_remote_readback);
        assert!(!report.proof.cloud_import_performed);
        assert_eq!(report.proof.library_choice_required, "shared_library");
        assert!(report.proof.user_step.contains("Shared Library"));
        assert_eq!(
            fs::read(&report.proof.staged_path).unwrap(),
            heic_bytes.as_slice()
        );
        assert_eq!(fs::read(&heic_path).unwrap(), heic_bytes.as_slice());
        assert_eq!(
            fs::read(manifest.get("IMG_0001").unwrap().raw_path.clone()).unwrap(),
            raw_before
        );
        assert_eq!(
            manifest.get("IMG_0001").unwrap().state,
            State::ConversionVerified
        );
        assert!(
            !manifest
                .get("IMG_0001")
                .unwrap()
                .proofs
                .contains_key("upload")
        );
        assert!(
            !manifest
                .get("IMG_0001")
                .unwrap()
                .proofs
                .contains_key("remote_readback")
        );
        assert!(mark_delete_eligible(&mut manifest, "IMG_0001").is_err());
        let again =
            stage_verified_heic_for_photos_import(&mut manifest, "IMG_0001", &handoff_dir).unwrap();
        assert!(!again.changed);
        let rollback = rollback_photos_import_handoff(&mut manifest, "IMG_0001").unwrap();
        assert!(rollback.removed);
        assert!(rollback.staged_file_removed);
        assert!(!report.proof.staged_path.exists());
        assert_eq!(fs::read(&heic_path).unwrap(), heic_bytes.as_slice());
        assert_eq!(
            fs::read(manifest.get("IMG_0001").unwrap().raw_path.clone()).unwrap(),
            raw_before
        );
        assert!(
            !manifest
                .get("IMG_0001")
                .unwrap()
                .proofs
                .contains_key(PHOTOS_IMPORT_HANDOFF_PROOF)
        );
        assert_eq!(
            manifest.get("IMG_0001").unwrap().state,
            State::ConversionVerified
        );
    }

    #[test]
    fn handoff_refuses_a_held_asset_and_leaves_no_staged_file() {
        let root = tempfile::tempdir().unwrap();
        let (mut manifest, heic_path) = verified_manifest(root.path(), b"held-heic");
        let destination = crate::upload::CloudKitLibraryDestination {
            database_scope: CloudKitDatabaseScope::Shared,
            zone_name: "SharedSync-LIBRARY".to_string(),
            owner_record_name: Some("_owner".to_string()),
        };
        let hold =
            OperationHold::uncertain(HeldRemoteOperation::Upload, destination, 1_700_000_000)
                .unwrap();
        assert!(apply_operation_hold(&mut manifest, "IMG_0001", hold).unwrap());
        let handoff_dir = root.path().join("handoff");
        let error = stage_verified_heic_for_photos_import(&mut manifest, "IMG_0001", &handoff_dir)
            .expect_err("a hold must block the handoff");
        assert!(matches!(
            error,
            PhotosImportHandoffError::Workflow(WorkflowError::RemoteOperationHeld { .. })
        ));
        assert!(!handoff_dir.join("IMG_0001.heic").exists());
        assert_eq!(fs::read(heic_path).unwrap(), b"held-heic");
    }
}

//! Durable per-asset exclusion for an uncertain remote upload or move.
//!
//! The hold is not a failure and not a quarantine. It keeps the asset's state,
//! historical proofs, and failure metadata, and it blocks another upload, local
//! mirror, or original delete until an operator releases that same hold.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::manifest::{AssetRecord, Manifest, ManifestError, State};
use crate::upload::{
    CloudKitDatabaseScope, CloudKitLibraryDestination, validate_library_destination,
};

pub const OPERATION_HOLD_PROOF_NAME: &str = "operation_hold";
pub const OPERATION_HOLD_SCHEMA_VERSION: u64 = 1;
pub const UNCERTAIN_REMOTE_OPERATION_REASON: &str = "uncertain_remote_operation";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HeldRemoteOperation {
    Upload,
    Move,
}

impl HeldRemoteOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Move => "move",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationHold {
    pub schema_version: u64,
    pub reason_code: String,
    pub operation: HeldRemoteOperation,
    pub database_scope: CloudKitDatabaseScope,
    pub zone_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_record_name: Option<String>,
    pub recorded_at_unix_seconds: u64,
}

impl OperationHold {
    pub fn uncertain(
        operation: HeldRemoteOperation,
        destination: CloudKitLibraryDestination,
        recorded_at_unix_seconds: u64,
    ) -> Result<Self, OperationHoldError> {
        let hold = Self {
            schema_version: OPERATION_HOLD_SCHEMA_VERSION,
            reason_code: UNCERTAIN_REMOTE_OPERATION_REASON.to_string(),
            operation,
            database_scope: destination.database_scope,
            zone_name: destination.zone_name,
            owner_record_name: destination.owner_record_name,
            recorded_at_unix_seconds,
        };
        hold.validate()?;
        Ok(hold)
    }

    pub fn validate(&self) -> Result<(), OperationHoldError> {
        if self.schema_version != OPERATION_HOLD_SCHEMA_VERSION {
            return Err(OperationHoldError::InvalidHold {
                reason: "unsupported schema",
            });
        }
        if self.reason_code != UNCERTAIN_REMOTE_OPERATION_REASON {
            return Err(OperationHoldError::InvalidHold {
                reason: "unsupported reason",
            });
        }
        if self.recorded_at_unix_seconds == 0 {
            return Err(OperationHoldError::InvalidHold {
                reason: "recorded time must be positive",
            });
        }
        validate_library_destination(&CloudKitLibraryDestination {
            database_scope: self.database_scope,
            zone_name: self.zone_name.clone(),
            owner_record_name: self.owner_record_name.clone(),
        })
        .map_err(|_| OperationHoldError::InvalidHold {
            reason: "CloudKit library destination is invalid",
        })?;
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum OperationHoldError {
    #[error("asset {asset_id} was not found")]
    UnknownAsset { asset_id: String },
    #[error("operation hold is invalid: {reason}")]
    InvalidHold { reason: &'static str },
    #[error("operation hold for {asset_id} is malformed and remains in force")]
    Malformed { asset_id: String },
    #[error("operation hold for {asset_id} already records a different exclusion")]
    Conflict { asset_id: String },
    #[error("remote upload or move for {asset_id} is held until explicit reconciliation")]
    Held { asset_id: String },
    #[error("manifest error: {0}")]
    Manifest(#[from] ManifestError),
}

/// Any stored hold blocks a later upload, move, or delete. A malformed hold
/// stays in force so a damaged exclusion cannot fall back open.
pub fn remote_mutation_blocked(record: &AssetRecord) -> bool {
    record.proofs.contains_key(OPERATION_HOLD_PROOF_NAME)
}

pub fn blocks_upload_scheduling(record: &AssetRecord) -> bool {
    remote_mutation_blocked(record) && upload_is_next_remote_stage(record)
}

pub fn blocks_move_or_delete_scheduling(record: &AssetRecord) -> bool {
    remote_mutation_blocked(record)
        && matches!(
            record.state,
            State::UploadVerified | State::DeleteEligible | State::DeleteApproved
        )
}

pub fn blocks_scheduled_remote_mutation(record: &AssetRecord) -> bool {
    blocks_upload_scheduling(record) || blocks_move_or_delete_scheduling(record)
}

pub fn ensure_remote_mutation_allowed(record: &AssetRecord) -> Result<(), OperationHoldError> {
    if remote_mutation_blocked(record) {
        Err(OperationHoldError::Held {
            asset_id: record.asset_id.clone(),
        })
    } else {
        Ok(())
    }
}

fn upload_is_next_remote_stage(record: &AssetRecord) -> bool {
    match record.state {
        State::ConversionVerified => record.proofs.contains_key("original_asset"),
        State::Converted => {
            record.proofs.contains_key("heic") && record.proofs.contains_key("original_asset")
        }
        _ => false,
    }
}

pub fn stored_operation_hold(
    record: &AssetRecord,
) -> Result<Option<OperationHold>, OperationHoldError> {
    let Some(value) = record.proofs.get(OPERATION_HOLD_PROOF_NAME) else {
        return Ok(None);
    };
    let hold: OperationHold =
        serde_json::from_value(value.clone()).map_err(|_| OperationHoldError::Malformed {
            asset_id: record.asset_id.clone(),
        })?;
    hold.validate().map_err(|_| OperationHoldError::Malformed {
        asset_id: record.asset_id.clone(),
    })?;
    Ok(Some(hold))
}

/// Inserts one hold without changing state, failures, or any other proof.
/// Applying the same hold again does not rewrite the record.
pub fn apply_operation_hold(
    manifest: &mut Manifest,
    asset_id: &str,
    hold: OperationHold,
) -> Result<bool, OperationHoldError> {
    hold.validate()?;
    let record = manifest
        .get(asset_id)
        .map_err(|_| OperationHoldError::UnknownAsset {
            asset_id: asset_id.to_string(),
        })?;
    if record.proofs.contains_key(OPERATION_HOLD_PROOF_NAME) {
        let existing =
            stored_operation_hold(record)?.ok_or_else(|| OperationHoldError::Malformed {
                asset_id: asset_id.to_string(),
            })?;
        if existing == hold {
            return Ok(false);
        }
        return Err(OperationHoldError::Conflict {
            asset_id: asset_id.to_string(),
        });
    }
    let proof = serde_json::to_value(&hold).map_err(|_| OperationHoldError::InvalidHold {
        reason: "hold could not be encoded",
    })?;
    manifest.record_proof(asset_id, OPERATION_HOLD_PROOF_NAME, proof)?;
    Ok(true)
}

/// Removes one exact hold. A different or malformed hold stays in place.
/// Releasing an asset that is not held leaves the record unchanged.
pub fn release_operation_hold(
    manifest: &mut Manifest,
    asset_id: &str,
    expected: &OperationHold,
) -> Result<bool, OperationHoldError> {
    expected.validate()?;
    let record = manifest
        .get(asset_id)
        .map_err(|_| OperationHoldError::UnknownAsset {
            asset_id: asset_id.to_string(),
        })?;
    let Some(existing) = stored_operation_hold(record)? else {
        return Ok(false);
    };
    if &existing != expected {
        return Err(OperationHoldError::Conflict {
            asset_id: asset_id.to_string(),
        });
    }
    manifest.remove_proof_preserving_state(asset_id, OPERATION_HOLD_PROOF_NAME)?;
    Ok(true)
}

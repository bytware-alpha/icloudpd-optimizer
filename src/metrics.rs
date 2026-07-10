use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::manifest::{AssetRecord, Manifest, State};

const METRICS_SCHEMA_VERSION: u64 = 2;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifiedMetrics {
    pub schema_version: u64,
    pub total_records: u64,
    pub state_counts: BTreeMap<String, u64>,
    #[serde(default)]
    pub terminal_records: u64,
    #[serde(default)]
    pub no_action_records: u64,
    #[serde(default)]
    pub needs_review_records: u64,
    #[serde(default)]
    pub failed_records: u64,
    #[serde(default)]
    pub pending_records: u64,
    pub uploaded_replacements: u64,
    pub uploaded_heic_bytes: u64,
    pub uploaded_size_metrics_complete: bool,
    pub uploaded_records_missing_size_proofs: u64,
    pub deleted_originals: u64,
    pub deleted_raw_bytes: u64,
    pub deleted_replacement_heic_bytes: u64,
    pub verified_bytes_saved: u64,
    pub deleted_size_metrics_complete: bool,
    pub deleted_records_missing_size_proofs: u64,
}

impl VerifiedMetrics {
    pub fn from_manifest(manifest: &Manifest) -> Self {
        let mut metrics = Self {
            schema_version: METRICS_SCHEMA_VERSION,
            uploaded_size_metrics_complete: true,
            deleted_size_metrics_complete: true,
            ..Self::default()
        };
        let mut uploaded_heic_bytes = 0u128;
        let mut deleted_raw_bytes = 0u128;
        let mut deleted_replacement_heic_bytes = 0u128;

        for record in manifest.records().values() {
            metrics.total_records = metrics.total_records.saturating_add(1);
            *metrics
                .state_counts
                .entry(record.state.as_str().to_string())
                .or_insert(0) += 1;
            if record.state.is_terminal() {
                metrics.terminal_records = metrics.terminal_records.saturating_add(1);
            }
            match record.state {
                State::NoAction => {
                    metrics.no_action_records = metrics.no_action_records.saturating_add(1);
                }
                State::NeedsReview => {
                    metrics.needs_review_records = metrics.needs_review_records.saturating_add(1);
                }
                State::Failed => {
                    metrics.failed_records = metrics.failed_records.saturating_add(1);
                }
                state if !state.is_terminal() => {
                    metrics.pending_records = metrics.pending_records.saturating_add(1);
                }
                _ => {}
            }

            if record.proofs.contains_key("upload") {
                metrics.uploaded_replacements = metrics.uploaded_replacements.saturating_add(1);
                match proof_size_bytes(record, "heic") {
                    Some(heic_bytes) => {
                        uploaded_heic_bytes += u128::from(heic_bytes);
                    }
                    None => {
                        metrics.uploaded_size_metrics_complete = false;
                        metrics.uploaded_records_missing_size_proofs = metrics
                            .uploaded_records_missing_size_proofs
                            .saturating_add(1);
                    }
                }
            }

            if record.state != State::Deleted {
                continue;
            }
            metrics.deleted_originals = metrics.deleted_originals.saturating_add(1);
            let raw_bytes = proof_size_bytes(record, "nas");
            let heic_bytes = proof_size_bytes(record, "icloudpd_local_mirror");
            match (raw_bytes, heic_bytes) {
                (Some(raw_bytes), Some(heic_bytes)) => {
                    deleted_raw_bytes += u128::from(raw_bytes);
                    deleted_replacement_heic_bytes += u128::from(heic_bytes);
                }
                _ => {
                    metrics.deleted_size_metrics_complete = false;
                    metrics.deleted_records_missing_size_proofs = metrics
                        .deleted_records_missing_size_proofs
                        .saturating_add(1);
                }
            }
        }

        let (uploaded_heic_bytes, uploaded_bytes_complete) = public_u64(uploaded_heic_bytes);
        metrics.uploaded_heic_bytes = uploaded_heic_bytes;
        metrics.uploaded_size_metrics_complete &= uploaded_bytes_complete;

        let verified_bytes_saved = deleted_raw_bytes.saturating_sub(deleted_replacement_heic_bytes);
        let (deleted_raw_bytes, raw_bytes_complete) = public_u64(deleted_raw_bytes);
        let (deleted_replacement_heic_bytes, replacement_bytes_complete) =
            public_u64(deleted_replacement_heic_bytes);
        let (verified_bytes_saved, net_bytes_complete) = public_u64(verified_bytes_saved);
        metrics.deleted_raw_bytes = deleted_raw_bytes;
        metrics.deleted_replacement_heic_bytes = deleted_replacement_heic_bytes;
        metrics.verified_bytes_saved = verified_bytes_saved;
        metrics.deleted_size_metrics_complete &=
            raw_bytes_complete && replacement_bytes_complete && net_bytes_complete;

        metrics
    }
}

fn public_u64(value: u128) -> (u64, bool) {
    match u64::try_from(value) {
        Ok(value) => (value, true),
        Err(_) => (u64::MAX, false),
    }
}

fn proof_size_bytes(record: &AssetRecord, proof_key: &str) -> Option<u64> {
    record.proofs.get(proof_key)?.get("size_bytes")?.as_u64()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::AssetRecord;
    use serde_json::json;

    #[test]
    fn proof_size_reads_the_record_already_being_aggregated() {
        let mut record = AssetRecord::new("asset-a", "/raw/asset-a.DNG");
        record
            .proofs
            .insert("heic".to_string(), json!({"size_bytes": 42}));

        assert_eq!(proof_size_bytes(&record, "heic"), Some(42));
    }
}

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant};

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::workflow::{HeicVerificationProof, OriginalAssetProof, UploadProof};

const HASH_BUFFER_BYTES: usize = 1024 * 1024;
const MAX_UPLOAD_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_UPLOAD_ERROR_DETAIL_CHARS: usize = 2048;
const PRIMARY_SYNC_ZONE: &str = "PrimarySync";
pub const CLOUDKIT_RECORDS_MODIFY_MAX_OPERATIONS: usize = 200;
const SHARED_SYNC_ZONE_PREFIX: &str = "SharedSync-";
const DEFAULT_LOCAL_TIME_ZONE_ID: &str = "UTC";
const DEFAULT_UPLOAD_STATUS_POLLS: usize = 120;
const DEFAULT_UPLOAD_STATUS_POLL_DELAY: Duration = Duration::from_secs(1);
const REQUIRED_CLOUDKIT_QUERY_PARAM_NAMES: [&str; 6] = [
    "clientBuildNumber",
    "clientMasteringNumber",
    "clientId",
    "dsid",
    "remapEnums",
    "getCurrentSyncToken",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcloudUploadRequest {
    pub session_path: PathBuf,
    pub heic_path: PathBuf,
    pub destination: CloudKitLibraryDestination,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct IcloudUploadResponse {
    pub asset_id: String,
    pub filename: Option<String>,
    pub master_id: Option<String>,
    pub database_scope: CloudKitDatabaseScope,
    pub zone_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcloudUploadOutcome {
    pub response: IcloudUploadResponse,
    pub streamed_heic_sha256: String,
    pub streamed_size_bytes: u64,
    pub timings: UploadTimings,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct UploadTimings {
    pub create_upload_url_wall_time_millis: u64,
    pub signed_upload_wall_time_millis: u64,
    pub put_asset_wall_time_millis: u64,
    pub upload_status_wall_time_millis: u64,
    pub upload_status_polls: usize,
    pub total_wall_time_millis: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadCookie {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadSession {
    pub dsid: String,
    pub photosupload_url: Url,
    pub cookies: Vec<UploadCookie>,
    pub local_time_zone_id: String,
    pub time_zone_offset_minutes: i32,
}

impl UploadSession {
    pub fn from_json(json: &str) -> Result<Self, UploadError> {
        let raw: RawUploadSession = serde_json::from_str(json)
            .map_err(|source| UploadError::DecodeSession { path: None, source })?;
        raw.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitDeleteSession {
    pub dsid: String,
    pub ckdatabasews_url: Url,
    pub cloudkit_query_params: Vec<CloudKitQueryParam>,
    pub cookies: Vec<UploadCookie>,
    pub database_scope: CloudKitDatabaseScope,
    pub zone: CloudKitLibraryDestination,
}

impl CloudKitDeleteSession {
    pub fn from_json(json: &str) -> Result<Self, UploadError> {
        let raw: RawCloudKitDeleteSession = serde_json::from_str(json)
            .map_err(|source| UploadError::DecodeSession { path: None, source })?;
        raw.validate()
    }

    fn validate(&self) -> Result<(), UploadError> {
        validate_dsid_value(&self.dsid)?;
        validate_ckdatabasews_url(self.ckdatabasews_url.as_str())?;
        validate_cloudkit_query_param_values(&self.cloudkit_query_params, &self.dsid)?;
        if self.database_scope != self.zone.database_scope {
            return Err(UploadError::InvalidSession(
                "CloudKit session database scope must match its zone".to_string(),
            ));
        }
        validate_library_destination(&self.zone)?;
        validate_cloudkit_cookies(&self.cookies)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitQueryParam {
    pub name: String,
    pub value: String,
}

#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "lowercase")]
pub enum CloudKitDatabaseScope {
    #[default]
    Private,
    Shared,
}

impl CloudKitDatabaseScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Shared => "shared",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CloudKitLibraryDestination {
    #[serde(default)]
    pub database_scope: CloudKitDatabaseScope,
    #[serde(default = "primary_sync_zone_name")]
    pub zone_name: String,
}

impl CloudKitLibraryDestination {
    pub fn primary_sync() -> Self {
        Self {
            database_scope: CloudKitDatabaseScope::Private,
            zone_name: primary_sync_zone_name(),
        }
    }

    fn zone_id_payload(&self) -> Value {
        json!({"zoneName": self.zone_name})
    }
}

fn primary_sync_zone_name() -> String {
    PRIMARY_SYNC_ZONE.to_string()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitDeleteRequest {
    pub record_name: String,
    pub record_change_tag: String,
    pub database_scope: CloudKitDatabaseScope,
    pub zone_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitDeleteBatchRequest {
    pub requests: Vec<CloudKitDeleteRequest>,
}

#[derive(Debug, Error)]
pub enum CloudKitDeleteBatchSendError<E> {
    #[error("CloudKit batch delete request was rejected before transport: {0}")]
    InvalidRequest(#[source] UploadError),
    #[error("CloudKit batch delete preflight was rejected before transport")]
    Preflight(E),
    #[error("CloudKit batch delete remote result is ambiguous: {0}")]
    Remote(#[source] UploadError),
}

impl<E> CloudKitDeleteBatchSendError<E> {
    pub fn transport_was_called(&self) -> bool {
        matches!(self, Self::Remote(_))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitDeleteOutcome {
    pub record_name: String,
    pub record_change_tag: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitDeleteStateLookupResult {
    pub confirmed_deleted: Vec<CloudKitDeleteOutcome>,
    pub unconfirmed: Vec<CloudKitDeleteRequest>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitUploadedHeicResolveRequest {
    pub uploaded_asset_id: String,
    pub expected_heic_sha256: String,
    pub expected_size_bytes: u64,
    pub database_scope: CloudKitDatabaseScope,
    pub zone_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CloudKitUploadedHeicAsset {
    pub record_name: String,
    pub record_change_tag: String,
    pub master_record_name: String,
    pub matched_heic_sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitResourceDownload {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitOriginalAssetResolveRequest {
    pub raw_size_bytes: u64,
    pub source_captured_unix_seconds: u64,
    pub capture_tolerance_seconds: u64,
    pub filename: String,
    pub matched_raw_sha256: String,
    pub start_rank: u64,
    pub page_size: u64,
    pub max_pages: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitOriginalAssetResolveTarget {
    pub asset_id: String,
    pub raw_size_bytes: u64,
    pub source_captured_unix_seconds: u64,
    pub capture_tolerance_seconds: u64,
    pub filename: String,
    pub matched_raw_sha256: String,
    pub replacement_candidate: Option<CloudKitLocalReplacementCandidate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CloudKitLocalReplacementCandidate {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitOriginalAssetBatchResolveRequest {
    pub targets: Vec<CloudKitOriginalAssetResolveTarget>,
    pub start_rank: u64,
    pub page_size: u64,
    pub max_pages: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct CloudKitOriginalAssetResolveObservations {
    pub date_candidates: u64,
    pub raw_resources: u64,
    pub raw_size_matches: u64,
    pub raw_hash_matches: u64,
    pub replacement_resource_matches: u64,
    pub download_size_mismatches: u64,
    pub ambiguity_evidence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CloudKitReplacementResourceProof {
    pub record_name: String,
    pub record_change_tag: String,
    pub record_type: String,
    pub database_scope: CloudKitDatabaseScope,
    pub zone_name: String,
    pub resource_field: String,
    pub size_bytes: u64,
    pub matched_heic_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum CloudKitOriginalAssetResolveDisposition {
    ExactOriginal {
        proof: OriginalAssetProof,
    },
    ReplacementPresent {
        proof: CloudKitReplacementResourceProof,
    },
    NoDateCandidate,
    NoRawResource,
    RawSizeMismatch,
    RawHashMismatch,
    Ambiguous,
    IncompleteTransient,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CloudKitOriginalAssetResolution {
    pub observations: CloudKitOriginalAssetResolveObservations,
    #[serde(flatten)]
    pub disposition: CloudKitOriginalAssetResolveDisposition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CloudKitOriginalAssetInventoryFingerprint {
    pub resolver_version: String,
    pub sha256: String,
    /// Unique normalized CPLAsset inventory identities scanned in the proven date window.
    pub records_scanned: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CloudKitOriginalAssetBatchResolveOutcome {
    pub resolutions: BTreeMap<String, CloudKitOriginalAssetResolution>,
    pub inventory: Option<CloudKitOriginalAssetInventoryFingerprint>,
}

impl CloudKitOriginalAssetBatchResolveOutcome {
    pub fn exact_original_proofs(&self) -> BTreeMap<String, OriginalAssetProof> {
        self.resolutions
            .iter()
            .filter_map(|(asset_id, resolution)| match &resolution.disposition {
                CloudKitOriginalAssetResolveDisposition::ExactOriginal { proof } => {
                    Some((asset_id.clone(), proof.clone()))
                }
                _ => None,
            })
            .collect()
    }

    pub fn non_exact_asset_ids(&self) -> Vec<String> {
        self.resolutions
            .iter()
            .filter(|(_, resolution)| {
                !matches!(
                    resolution.disposition,
                    CloudKitOriginalAssetResolveDisposition::ExactOriginal { .. }
                )
            })
            .map(|(asset_id, _)| asset_id.clone())
            .collect()
    }
}

pub fn load_upload_session(path: &Path) -> Result<UploadSession, UploadError> {
    let json = std::fs::read_to_string(path).map_err(|source| UploadError::ReadSession {
        path: path.to_path_buf(),
        source,
    })?;
    let raw: RawUploadSession =
        serde_json::from_str(&json).map_err(|source| UploadError::DecodeSession {
            path: Some(path.to_path_buf()),
            source,
        })?;
    raw.validate()
}

pub fn load_cloudkit_delete_session(path: &Path) -> Result<CloudKitDeleteSession, UploadError> {
    let json = std::fs::read_to_string(path).map_err(|source| UploadError::ReadSession {
        path: path.to_path_buf(),
        source,
    })?;
    let raw: RawCloudKitDeleteSession =
        serde_json::from_str(&json).map_err(|source| UploadError::DecodeSession {
            path: Some(path.to_path_buf()),
            source,
        })?;
    raw.validate()
}

pub fn run_icloud_upload(
    request: &IcloudUploadRequest,
) -> Result<IcloudUploadOutcome, UploadError> {
    let session = load_upload_session(&request.session_path)?;
    let transport = ReqwestPhotosUploadTransport::new()?;
    PhotosUploadClient::new(transport).upload_heic_to_library(
        &session,
        &request.heic_path,
        &request.destination,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PhotosUploadEndpoint {
    CreateUploadUrl,
    PutAsset,
    UploadStatus,
}

impl PhotosUploadEndpoint {
    fn as_str(self) -> &'static str {
        match self {
            Self::CreateUploadUrl => "createUploadUrl",
            Self::PutAsset => "putAsset",
            Self::UploadStatus => "uploadStatus",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SingleFileUploadRequest {
    pub file_checksum: String,
    #[serde(rename = "size")]
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrapping_key: Option<String>,
    pub reference_checksum: String,
    pub receipt: String,
}

pub trait PhotosUploadTransport {
    fn post_service_json(
        &mut self,
        session: &UploadSession,
        endpoint: PhotosUploadEndpoint,
        payload: Value,
    ) -> Result<Value, UploadError>;

    fn post_signed_upload(
        &mut self,
        session: &UploadSession,
        upload_url: &Url,
        heic_path: &Path,
    ) -> Result<(SingleFileUploadRequest, String, u64), UploadError>;
}

pub trait CloudKitDeleteTransport {
    fn post_records_modify(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError>;

    fn post_records_lookup(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError>;
}

pub trait CloudKitOriginalAssetReadTransport {
    fn post_records_query(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError>;

    fn download_resource(
        &mut self,
        session: &CloudKitDeleteSession,
        download_url: &Url,
        expected_size_bytes: u64,
    ) -> Result<CloudKitResourceDownload, UploadError>;
}

impl<T: CloudKitDeleteTransport + ?Sized> CloudKitDeleteTransport for &mut T {
    fn post_records_modify(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError> {
        (**self).post_records_modify(session, payload)
    }

    fn post_records_lookup(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError> {
        (**self).post_records_lookup(session, payload)
    }
}

impl<T: CloudKitOriginalAssetReadTransport + ?Sized> CloudKitOriginalAssetReadTransport for &mut T {
    fn post_records_query(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError> {
        (**self).post_records_query(session, payload)
    }

    fn download_resource(
        &mut self,
        session: &CloudKitDeleteSession,
        download_url: &Url,
        expected_size_bytes: u64,
    ) -> Result<CloudKitResourceDownload, UploadError> {
        (**self).download_resource(session, download_url, expected_size_bytes)
    }
}

impl<T: PhotosUploadTransport + ?Sized> PhotosUploadTransport for &mut T {
    fn post_service_json(
        &mut self,
        session: &UploadSession,
        endpoint: PhotosUploadEndpoint,
        payload: Value,
    ) -> Result<Value, UploadError> {
        (**self).post_service_json(session, endpoint, payload)
    }

    fn post_signed_upload(
        &mut self,
        session: &UploadSession,
        upload_url: &Url,
        heic_path: &Path,
    ) -> Result<(SingleFileUploadRequest, String, u64), UploadError> {
        (**self).post_signed_upload(session, upload_url, heic_path)
    }
}

pub struct PhotosUploadClient<T> {
    transport: T,
    status_poll_delay: Duration,
    max_status_polls: usize,
}

impl<T: PhotosUploadTransport> PhotosUploadClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            status_poll_delay: DEFAULT_UPLOAD_STATUS_POLL_DELAY,
            max_status_polls: DEFAULT_UPLOAD_STATUS_POLLS,
        }
    }

    pub fn with_status_poll_delay(mut self, delay: Duration) -> Self {
        self.status_poll_delay = delay;
        self
    }

    pub fn with_max_status_polls(mut self, max_status_polls: usize) -> Self {
        self.max_status_polls = max_status_polls;
        self
    }

    pub fn upload_heic(
        &mut self,
        session: &UploadSession,
        heic_path: &Path,
    ) -> Result<IcloudUploadOutcome, UploadError> {
        self.upload_heic_to_library(
            session,
            heic_path,
            &CloudKitLibraryDestination::primary_sync(),
        )
    }

    pub fn upload_heic_to_library(
        &mut self,
        session: &UploadSession,
        heic_path: &Path,
        destination: &CloudKitLibraryDestination,
    ) -> Result<IcloudUploadOutcome, UploadError> {
        let total_started = Instant::now();
        validate_library_destination(destination)?;
        validate_candidate_heic(heic_path)?;
        let filename = heic_filename(heic_path)?;
        let metadata = std::fs::metadata(heic_path).map_err(|source| UploadError::ReadHeic {
            path: heic_path.to_path_buf(),
            source,
        })?;
        let heic_size = metadata.len();
        let last_modified_millis = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0);

        let create_started = Instant::now();
        let create_response = self.transport.post_service_json(
            session,
            PhotosUploadEndpoint::CreateUploadUrl,
            create_upload_url_payload(heic_size, destination),
        )?;
        let create_upload_url_wall_time_millis = create_started.elapsed().as_millis() as u64;
        let upload_url = parse_create_upload_url_response(create_response)?;
        let signed_upload_started = Instant::now();
        let (single_file, streamed_heic_sha256, streamed_size_bytes) = self
            .transport
            .post_signed_upload(session, &upload_url, heic_path)?;
        let signed_upload_wall_time_millis = signed_upload_started.elapsed().as_millis() as u64;
        validate_single_file_upload_request(&single_file)?;
        if single_file.size_bytes != heic_size {
            return Err(UploadError::SignedUploadSizeMismatch {
                expected: heic_size,
                actual: single_file.size_bytes,
            });
        }
        if streamed_size_bytes != heic_size {
            return Err(UploadError::StreamedHeicSizeMismatch {
                expected: heic_size,
                actual: streamed_size_bytes,
            });
        }

        let put_asset_started = Instant::now();
        let put_response = self.transport.post_service_json(
            session,
            PhotosUploadEndpoint::PutAsset,
            put_asset_payload(
                &filename,
                last_modified_millis,
                session.time_zone_offset_minutes,
                &session.local_time_zone_id,
                &single_file,
                destination,
            ),
        )?;
        let put_asset_wall_time_millis = put_asset_started.elapsed().as_millis() as u64;
        let put_asset = parse_put_asset_response(put_response)?;
        let upload_status_started = Instant::now();
        let upload_status_polls = if let Some(upload_job_id) = put_asset.upload_job_id.as_deref() {
            self.poll_until_upload_complete(session, upload_job_id)?
        } else {
            0
        };
        let upload_status_wall_time_millis = upload_status_started.elapsed().as_millis() as u64;
        let total_wall_time_millis = total_started.elapsed().as_millis() as u64;

        Ok(IcloudUploadOutcome {
            response: IcloudUploadResponse {
                asset_id: put_asset.cpl_asset,
                filename: Some(filename),
                master_id: Some(put_asset.cpl_master),
                database_scope: destination.database_scope,
                zone_name: destination.zone_name.clone(),
            },
            streamed_heic_sha256,
            streamed_size_bytes,
            timings: UploadTimings {
                create_upload_url_wall_time_millis,
                signed_upload_wall_time_millis,
                put_asset_wall_time_millis,
                upload_status_wall_time_millis,
                upload_status_polls,
                total_wall_time_millis,
            },
        })
    }

    fn poll_until_upload_complete(
        &mut self,
        session: &UploadSession,
        upload_job_id: &str,
    ) -> Result<usize, UploadError> {
        if self.max_status_polls == 0 {
            return Err(UploadError::PhotosUploadStatusTimedOut);
        }

        for attempt in 0..self.max_status_polls {
            let response = self.transport.post_service_json(
                session,
                PhotosUploadEndpoint::UploadStatus,
                json!({ "uploadJobIds": [upload_job_id] }),
            )?;
            match parse_upload_status_response(response, upload_job_id)? {
                UploadStatusState::Complete => return Ok(attempt + 1),
                UploadStatusState::InProgress => {
                    if attempt + 1 < self.max_status_polls && !self.status_poll_delay.is_zero() {
                        sleep(self.status_poll_delay);
                    }
                }
            }
        }

        Err(UploadError::PhotosUploadStatusTimedOut)
    }
}

pub struct CloudKitDeleteClient<T> {
    transport: T,
}

impl<T> CloudKitDeleteClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}

impl<T: CloudKitDeleteTransport> CloudKitDeleteClient<T> {
    pub fn delete_original(
        &mut self,
        session: &CloudKitDeleteSession,
        request: &CloudKitDeleteRequest,
    ) -> Result<CloudKitDeleteOutcome, UploadError> {
        self.delete_cpl_asset(session, request)
    }

    pub fn delete_cpl_asset(
        &mut self,
        session: &CloudKitDeleteSession,
        request: &CloudKitDeleteRequest,
    ) -> Result<CloudKitDeleteOutcome, UploadError> {
        validate_cloudkit_delete_request(request)?;
        let response = self
            .transport
            .post_records_modify(session, cloudkit_delete_payload(request))?;
        parse_cloudkit_delete_response(response, request)
    }

    pub fn delete_originals_batch(
        &mut self,
        session: &CloudKitDeleteSession,
        request: &CloudKitDeleteBatchRequest,
    ) -> Result<Vec<CloudKitDeleteOutcome>, UploadError> {
        validate_cloudkit_delete_batch_request(request)?;
        let response = self
            .transport
            .post_records_modify(session, cloudkit_delete_batch_payload(request))?;
        parse_cloudkit_delete_batch_response(response, request)
    }

    pub fn delete_originals_batch_with_preflight<E, F>(
        &mut self,
        session: &CloudKitDeleteSession,
        request: &CloudKitDeleteBatchRequest,
        preflight: F,
    ) -> Result<Vec<CloudKitDeleteOutcome>, CloudKitDeleteBatchSendError<E>>
    where
        F: FnOnce(&Value) -> Result<(), E>,
    {
        validate_cloudkit_delete_batch_request(request)
            .map_err(CloudKitDeleteBatchSendError::InvalidRequest)?;
        let payload = cloudkit_delete_batch_payload(request);
        preflight(&payload).map_err(CloudKitDeleteBatchSendError::Preflight)?;
        let response = self
            .transport
            .post_records_modify(session, payload)
            .map_err(CloudKitDeleteBatchSendError::Remote)?;
        parse_cloudkit_delete_batch_response(response, request)
            .map_err(CloudKitDeleteBatchSendError::Remote)
    }

    pub fn lookup_delete_states(
        &mut self,
        session: &CloudKitDeleteSession,
        request: &CloudKitDeleteBatchRequest,
    ) -> Result<CloudKitDeleteStateLookupResult, UploadError> {
        validate_cloudkit_delete_batch_request(request)?;
        let first = request
            .requests
            .first()
            .ok_or(UploadError::InvalidCloudKitDeleteRequest(
                "at least one original asset delete request is required",
            ))?;
        let destination = CloudKitLibraryDestination {
            database_scope: first.database_scope,
            zone_name: first.zone_name.clone(),
        };
        let record_names: Vec<&str> = request
            .requests
            .iter()
            .map(|request| request.record_name.as_str())
            .collect();
        let response = self.transport.post_records_lookup(
            session,
            cloudkit_records_lookup_payload(&record_names, &["isDeleted"], &destination),
        )?;
        parse_cloudkit_delete_state_lookup_response(response, request)
    }
}

impl<T: CloudKitDeleteTransport + CloudKitOriginalAssetReadTransport> CloudKitDeleteClient<T> {
    pub fn resolve_uploaded_heic_asset(
        &mut self,
        session: &CloudKitDeleteSession,
        request: &CloudKitUploadedHeicResolveRequest,
    ) -> Result<CloudKitUploadedHeicAsset, UploadError> {
        validate_uploaded_heic_resolve_request(request)?;
        let destination = CloudKitLibraryDestination {
            database_scope: request.database_scope,
            zone_name: request.zone_name.clone(),
        };
        let asset_response = self.transport.post_records_lookup(
            session,
            cloudkit_records_lookup_payload(
                &[request.uploaded_asset_id.as_str()],
                &["masterRef", "isDeleted"],
                &destination,
            ),
        )?;
        let asset = parse_uploaded_heic_asset_lookup_response(asset_response, request)?;
        let master_response = self.transport.post_records_lookup(
            session,
            cloudkit_records_lookup_payload(
                &[asset.master_record_name.as_str()],
                &[
                    "resOriginalRes",
                    "resOriginalFileType",
                    "resOriginalAltRes",
                    "resOriginalAltFileType",
                    "resSidecarRes",
                    "resSidecarFileType",
                    "resOriginalVidComplRes",
                    "resOriginalVidComplFileType",
                ],
                &destination,
            ),
        )?;
        let download_url = parse_uploaded_heic_master_lookup_response(
            master_response,
            &asset.master_record_name,
            request.expected_size_bytes,
        )?;
        let download = self.transport.download_resource(
            session,
            &download_url,
            request.expected_size_bytes,
        )?;
        if download.sha256 != request.expected_heic_sha256 {
            return Err(UploadError::CloudKitUploadedHeicDownloadHashMismatch {
                expected: request.expected_heic_sha256.clone(),
                actual: download.sha256,
            });
        }
        Ok(CloudKitUploadedHeicAsset {
            record_name: asset.record_name,
            record_change_tag: asset.record_change_tag,
            master_record_name: asset.master_record_name,
            matched_heic_sha256: request.expected_heic_sha256.clone(),
            size_bytes: download.size_bytes,
        })
    }
}

impl<T: CloudKitOriginalAssetReadTransport> CloudKitDeleteClient<T> {
    pub fn resolve_original_asset(
        &mut self,
        session: &CloudKitDeleteSession,
        request: &CloudKitOriginalAssetResolveRequest,
    ) -> Result<OriginalAssetProof, UploadError> {
        validate_original_asset_resolve_request(request)?;
        validate_original_asset_pagination_range(request)?;
        let target_window = OriginalAssetDateWindow::new(
            request.source_captured_unix_seconds,
            request.capture_tolerance_seconds,
        );
        let mut matches = Vec::new();
        let mut exhausted = false;
        let seek_result = seek_original_asset_query_page(
            request.start_rank,
            request.page_size,
            request.max_pages,
            &target_window,
            |start_rank| {
                let payload = cloudkit_original_asset_query_payload(
                    start_rank,
                    request.page_size,
                    None,
                    &session.zone,
                );
                let response = self.transport.post_records_query(session, payload)?;
                parse_original_asset_query_response(response, request, &session.zone)
            },
        )?;
        let mut pages_read = seek_result.pages_read;
        let mut next_page = Some(seek_result.page);

        while let Some(positioned_page) = next_page.take() {
            match positioned_page.page.position_against(&target_window) {
                OriginalAssetPagePosition::TooNew => {
                    return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
                        "records/query returned non-monotonic assetDate pages",
                    ));
                }
                OriginalAssetPagePosition::Empty
                    if positioned_page.page.continuation_marker.is_some() => {}
                OriginalAssetPagePosition::TooOld | OriginalAssetPagePosition::Empty => {
                    exhausted = true;
                    break;
                }
                OriginalAssetPagePosition::Overlaps => {}
            }

            let continuation_marker = positioned_page.page.continuation_marker.clone();
            for candidate in positioned_page.page.matches {
                let download = self.transport.download_resource(
                    session,
                    &candidate.download_url,
                    request.raw_size_bytes,
                )?;
                if download.size_bytes != request.raw_size_bytes {
                    return Err(UploadError::CloudKitOriginalAssetDownloadSizeMismatch {
                        expected: request.raw_size_bytes,
                        actual: download.size_bytes,
                    });
                }
                if download.sha256 == request.matched_raw_sha256 {
                    matches.push(candidate.proof);
                }
            }
            if matches.len() > 1 {
                return Err(UploadError::OriginalAssetResolveNotUnique {
                    matches: matches.len(),
                });
            }

            let Some(marker) = continuation_marker else {
                exhausted = true;
                break;
            };
            if pages_read >= request.max_pages {
                break;
            }
            let payload = cloudkit_original_asset_query_payload(
                positioned_page.start_rank,
                request.page_size,
                Some(&marker),
                &session.zone,
            );
            let response = self.transport.post_records_query(session, payload)?;
            pages_read = pages_read.saturating_add(1);
            next_page = Some(PositionedOriginalAssetQueryPage {
                start_rank: positioned_page.start_rank,
                page: parse_original_asset_query_response(response, request, &session.zone)?,
            });
        }
        if !exhausted {
            return Err(UploadError::OriginalAssetResolveIncomplete {
                matches: matches.len(),
            });
        }
        match matches.len() {
            1 => Ok(matches.remove(0)),
            count => Err(UploadError::OriginalAssetResolveNotUnique { matches: count }),
        }
    }

    pub fn resolve_original_assets_batch(
        &mut self,
        session: &CloudKitDeleteSession,
        request: &CloudKitOriginalAssetBatchResolveRequest,
    ) -> Result<BTreeMap<String, OriginalAssetProof>, UploadError> {
        let outcome = self.resolve_original_assets_batch_outcome(session, request)?;
        let proofs = outcome.exact_original_proofs();
        if proofs.len() != outcome.resolutions.len() {
            return Err(UploadError::OriginalAssetResolveNotUnique { matches: 0 });
        }
        Ok(proofs)
    }

    pub fn resolve_original_assets_batch_outcome(
        &mut self,
        session: &CloudKitDeleteSession,
        request: &CloudKitOriginalAssetBatchResolveRequest,
    ) -> Result<CloudKitOriginalAssetBatchResolveOutcome, UploadError> {
        validate_original_asset_batch_resolve_request(request)?;
        validate_original_asset_batch_pagination_range(request)?;
        let target_index = OriginalAssetTargetIndex::new(&request.targets);
        let mut cohort_work =
            vec![OriginalAssetCohortResolutionWork::default(); target_index.cohort_count()];
        let target_window = target_index.date_window();
        let mut download_cache: BTreeMap<(String, u64), CachedCloudKitResourceDownload> =
            BTreeMap::new();
        let mut inventory_records = BTreeSet::new();
        let mut exhausted = false;
        let seek_result = match seek_original_asset_query_page(
            request.start_rank,
            request.page_size,
            request.max_pages,
            &target_window,
            |start_rank| {
                let payload = cloudkit_original_asset_query_payload(
                    start_rank,
                    request.page_size,
                    None,
                    &session.zone,
                );
                let response = self.transport.post_records_query(session, payload)?;
                parse_original_asset_batch_query_response(response, &target_index, &session.zone)
            },
        ) {
            Ok(result) => result,
            Err(UploadError::OriginalAssetResolveIncomplete { .. }) => {
                return Ok(build_batch_resolve_outcome(
                    request,
                    &target_index,
                    &target_window,
                    &session.zone,
                    OriginalAssetBatchResolveScanEvidence {
                        cohort_work,
                        inventory_records,
                        complete: false,
                        force_transient: true,
                    },
                ));
            }
            Err(error) => return Err(error),
        };
        let mut pages_read = seek_result.pages_read;
        let mut next_page = Some(seek_result.page);

        while let Some(positioned_page) = next_page.take() {
            match positioned_page.page.position_against(&target_window) {
                OriginalAssetPagePosition::TooNew => {
                    return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
                        "records/query returned non-monotonic assetDate pages",
                    ));
                }
                OriginalAssetPagePosition::Empty
                    if positioned_page.page.continuation_marker.is_some() => {}
                OriginalAssetPagePosition::TooOld | OriginalAssetPagePosition::Empty => {
                    exhausted = true;
                    break;
                }
                OriginalAssetPagePosition::Overlaps => {}
            }

            let continuation_marker = positioned_page.page.continuation_marker.clone();
            inventory_records.extend(positioned_page.page.inventory_records.iter().cloned());
            for increment in &positioned_page.page.observation_increments {
                let work = cohort_work.get_mut(increment.cohort_index).ok_or(
                    UploadError::InvalidCloudKitOriginalAssetResponse(
                        "records/query observed an unknown target cohort",
                    ),
                )?;
                work.observations.date_candidates = work
                    .observations
                    .date_candidates
                    .saturating_add(increment.date_candidates);
                work.observations.raw_resources = work
                    .observations
                    .raw_resources
                    .saturating_add(increment.raw_resources);
                for (size_bytes, matches) in &increment.raw_size_matches {
                    *work.raw_size_matches.entry(*size_bytes).or_default() = work
                        .raw_size_matches
                        .get(size_bytes)
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(*matches);
                }
            }
            for candidate in positioned_page.page.matches {
                let cache_key = (
                    candidate.resource.download_url.as_str().to_string(),
                    candidate.resource.size_bytes,
                );
                let download = if let Some(download) = download_cache.get(&cache_key) {
                    download.clone()
                } else {
                    let download = match self.transport.download_resource(
                        session,
                        &candidate.resource.download_url,
                        candidate.resource.size_bytes,
                    ) {
                        Ok(download) if download.size_bytes == candidate.resource.size_bytes => {
                            CachedCloudKitResourceDownload::Downloaded(download)
                        }
                        Ok(_)
                        | Err(UploadError::CloudKitOriginalAssetDownloadSizeMismatch { .. }) => {
                            CachedCloudKitResourceDownload::SizeMismatch
                        }
                        Err(error) => return Err(error),
                    };
                    download_cache.insert(cache_key, download.clone());
                    download
                };
                let CachedCloudKitResourceDownload::Downloaded(download) = download else {
                    for cohort_index in &candidate.cohort_indexes {
                        let cohort = &target_index.cohorts[*cohort_index];
                        let work = &mut cohort_work[*cohort_index];
                        match candidate.resource.kind {
                            CloudKitOriginalAssetCandidateKind::Raw
                                if cohort
                                    .raw_target_sizes
                                    .contains(&candidate.resource.size_bytes) =>
                            {
                                let count = work
                                    .incomplete_raw_sizes
                                    .entry(candidate.resource.size_bytes)
                                    .or_default();
                                *count = count.saturating_add(1);
                            }
                            CloudKitOriginalAssetCandidateKind::Replacement
                                if cohort
                                    .replacement_target_sizes
                                    .contains(&candidate.resource.size_bytes) =>
                            {
                                let count = work
                                    .incomplete_replacement_sizes
                                    .entry(candidate.resource.size_bytes)
                                    .or_default();
                                *count = count.saturating_add(1);
                            }
                            _ => {}
                        }
                    }
                    continue;
                };
                let key = OriginalAssetMatchKey {
                    size_bytes: candidate.resource.size_bytes,
                    sha256: download.sha256,
                };
                let remote_identity =
                    remote_resource_identity(&candidate.asset.record_name, &candidate.resource);
                let remote_match = OriginalAssetRemoteMatch {
                    asset: candidate.asset,
                    resource_field: candidate.resource.field.clone(),
                };
                for cohort_index in candidate.cohort_indexes {
                    let cohort = &target_index.cohorts[cohort_index];
                    let work = &mut cohort_work[cohort_index];
                    match candidate.resource.kind {
                        CloudKitOriginalAssetCandidateKind::Raw
                            if cohort.raw_target_counts.contains_key(&key) =>
                        {
                            work.raw_matches
                                .entry(key.clone())
                                .or_default()
                                .insert(remote_identity.clone(), remote_match.clone());
                        }
                        CloudKitOriginalAssetCandidateKind::Replacement
                            if cohort.replacement_target_counts.contains_key(&key) =>
                        {
                            work.replacement_matches
                                .entry(key.clone())
                                .or_default()
                                .insert(remote_identity.clone(), remote_match.clone());
                        }
                        _ => {}
                    }
                }
            }

            let Some(marker) = continuation_marker else {
                exhausted = true;
                break;
            };
            if pages_read >= request.max_pages {
                break;
            }
            let payload = cloudkit_original_asset_query_payload(
                positioned_page.start_rank,
                request.page_size,
                Some(&marker),
                &session.zone,
            );
            let response = self.transport.post_records_query(session, payload)?;
            pages_read = pages_read.saturating_add(1);
            next_page = Some(PositionedOriginalAssetQueryPage {
                start_rank: positioned_page.start_rank,
                page: parse_original_asset_batch_query_response(
                    response,
                    &target_index,
                    &session.zone,
                )?,
            });
        }
        if !exhausted {
            return Ok(build_batch_resolve_outcome(
                request,
                &target_index,
                &target_window,
                &session.zone,
                OriginalAssetBatchResolveScanEvidence {
                    cohort_work,
                    inventory_records,
                    complete: false,
                    force_transient: true,
                },
            ));
        }
        Ok(build_batch_resolve_outcome(
            request,
            &target_index,
            &target_window,
            &session.zone,
            OriginalAssetBatchResolveScanEvidence {
                cohort_work,
                inventory_records,
                complete: true,
                force_transient: false,
            },
        ))
    }
}

pub const CLOUDKIT_ORIGINAL_ASSET_RESOLVER_VERSION: &str = "cloudkit-original-asset-reconcile-v1";

fn build_batch_resolve_outcome(
    request: &CloudKitOriginalAssetBatchResolveRequest,
    target_index: &OriginalAssetTargetIndex,
    target_window: &OriginalAssetDateWindow,
    destination: &CloudKitLibraryDestination,
    evidence: OriginalAssetBatchResolveScanEvidence,
) -> CloudKitOriginalAssetBatchResolveOutcome {
    let OriginalAssetBatchResolveScanEvidence {
        cohort_work,
        inventory_records,
        complete,
        force_transient,
    } = evidence;
    let mut claims = BTreeMap::<String, BTreeSet<OriginalAssetCohortMatchGroupKey>>::new();
    let mut ambiguous_groups = BTreeSet::new();
    for (cohort_index, work) in cohort_work.iter().enumerate() {
        let cohort = &target_index.cohorts[cohort_index];
        for (kind, matches, target_counts) in [
            (
                CloudKitOriginalAssetCandidateKind::Raw,
                &work.raw_matches,
                &cohort.raw_target_counts,
            ),
            (
                CloudKitOriginalAssetCandidateKind::Replacement,
                &work.replacement_matches,
                &cohort.replacement_target_counts,
            ),
        ] {
            for (key, candidates) in matches {
                let group = OriginalAssetCohortMatchGroupKey {
                    cohort_index,
                    kind,
                    key: key.clone(),
                };
                if candidates.len() > 1 || target_counts.get(key).copied().unwrap_or(0) > 1 {
                    ambiguous_groups.insert(group.clone());
                }
                for remote_identity in candidates.keys() {
                    claims
                        .entry(remote_identity.clone())
                        .or_default()
                        .insert(group.clone());
                }
            }
        }
    }
    for groups in claims.values().filter(|groups| groups.len() > 1) {
        ambiguous_groups.extend(groups.iter().cloned());
    }

    let resolutions = request
        .targets
        .iter()
        .enumerate()
        .map(|(target_position, target)| {
            let cohort_index = target_index.target_cohort_indexes[target_position];
            let work = &cohort_work[cohort_index];
            let raw_key = OriginalAssetMatchKey {
                size_bytes: target.raw_size_bytes,
                sha256: target.matched_raw_sha256.clone(),
            };
            let replacement_key =
                target
                    .replacement_candidate
                    .as_ref()
                    .map(|replacement| OriginalAssetMatchKey {
                        size_bytes: replacement.size_bytes,
                        sha256: replacement.sha256.clone(),
                    });
            let raw_matches = work.raw_matches.get(&raw_key);
            let replacement_matches = replacement_key
                .as_ref()
                .and_then(|key| work.replacement_matches.get(key));
            let raw_group = OriginalAssetCohortMatchGroupKey {
                cohort_index,
                kind: CloudKitOriginalAssetCandidateKind::Raw,
                key: raw_key.clone(),
            };
            let replacement_group =
                replacement_key
                    .as_ref()
                    .map(|key| OriginalAssetCohortMatchGroupKey {
                        cohort_index,
                        kind: CloudKitOriginalAssetCandidateKind::Replacement,
                        key: key.clone(),
                    });
            let mut observations = work.observations.clone();
            observations.raw_size_matches = *work
                .raw_size_matches
                .get(&target.raw_size_bytes)
                .unwrap_or(&0);
            observations.raw_hash_matches = raw_matches.map_or(0, |matches| matches.len() as u64);
            observations.replacement_resource_matches =
                replacement_matches.map_or(0, |matches| matches.len() as u64);
            observations.download_size_mismatches = work
                .incomplete_raw_sizes
                .get(&target.raw_size_bytes)
                .copied()
                .unwrap_or(0)
                .saturating_add(
                    target
                        .replacement_candidate
                        .as_ref()
                        .and_then(|replacement| {
                            work.incomplete_replacement_sizes
                                .get(&replacement.size_bytes)
                        })
                        .copied()
                        .unwrap_or(0),
                );
            let incomplete_candidate_evidence = work
                .incomplete_raw_sizes
                .contains_key(&target.raw_size_bytes)
                || target
                    .replacement_candidate
                    .as_ref()
                    .is_some_and(|replacement| {
                        work.incomplete_replacement_sizes
                            .contains_key(&replacement.size_bytes)
                    });
            let ambiguous = ambiguous_groups.contains(&raw_group)
                || replacement_group
                    .as_ref()
                    .is_some_and(|group| ambiguous_groups.contains(group))
                || (raw_matches.is_some_and(|matches| !matches.is_empty())
                    && replacement_matches.is_some_and(|matches| !matches.is_empty()));
            if ambiguous {
                observations.ambiguity_evidence = 1;
            }
            let disposition = if force_transient || incomplete_candidate_evidence {
                CloudKitOriginalAssetResolveDisposition::IncompleteTransient
            } else if ambiguous {
                CloudKitOriginalAssetResolveDisposition::Ambiguous
            } else if let Some(candidate) = raw_matches.and_then(|matches| matches.values().next())
            {
                CloudKitOriginalAssetResolveDisposition::ExactOriginal {
                    proof: OriginalAssetProof {
                        record_name: candidate.asset.record_name.clone(),
                        record_change_tag: candidate.asset.record_change_tag.clone(),
                        record_type: "CPLAsset".to_string(),
                        database_scope: destination.database_scope,
                        zone_name: destination.zone_name.clone(),
                        filename: target.filename.clone(),
                        size_bytes: target.raw_size_bytes,
                        matched_raw_sha256: target.matched_raw_sha256.clone(),
                    },
                }
            } else if let Some(candidate) =
                replacement_matches.and_then(|matches| matches.values().next())
            {
                CloudKitOriginalAssetResolveDisposition::ReplacementPresent {
                    proof: CloudKitReplacementResourceProof {
                        record_name: candidate.asset.record_name.clone(),
                        record_change_tag: candidate.asset.record_change_tag.clone(),
                        record_type: "CPLAsset".to_string(),
                        database_scope: destination.database_scope,
                        zone_name: destination.zone_name.clone(),
                        resource_field: candidate.resource_field.clone(),
                        size_bytes: target
                            .replacement_candidate
                            .as_ref()
                            .expect("replacement match requires a local candidate")
                            .size_bytes,
                        matched_heic_sha256: target
                            .replacement_candidate
                            .as_ref()
                            .expect("replacement match requires a local candidate")
                            .sha256
                            .clone(),
                    },
                }
            } else if observations.date_candidates == 0 {
                CloudKitOriginalAssetResolveDisposition::NoDateCandidate
            } else if observations.raw_resources == 0 {
                CloudKitOriginalAssetResolveDisposition::NoRawResource
            } else if observations.raw_size_matches == 0 {
                CloudKitOriginalAssetResolveDisposition::RawSizeMismatch
            } else {
                CloudKitOriginalAssetResolveDisposition::RawHashMismatch
            };
            (
                target.asset_id.clone(),
                CloudKitOriginalAssetResolution {
                    observations,
                    disposition,
                },
            )
        })
        .collect();

    CloudKitOriginalAssetBatchResolveOutcome {
        resolutions,
        inventory: (complete && !force_transient).then(|| {
            cloudkit_original_asset_inventory_fingerprint(
                destination,
                target_window,
                &inventory_records,
            )
        }),
    }
}

struct OriginalAssetBatchResolveScanEvidence {
    cohort_work: Vec<OriginalAssetCohortResolutionWork>,
    inventory_records: BTreeSet<String>,
    complete: bool,
    force_transient: bool,
}

fn cloudkit_original_asset_inventory_fingerprint(
    destination: &CloudKitLibraryDestination,
    target_window: &OriginalAssetDateWindow,
    records: &BTreeSet<String>,
) -> CloudKitOriginalAssetInventoryFingerprint {
    let mut hasher = Sha256::new();
    for component in [
        CLOUDKIT_ORIGINAL_ASSET_RESOLVER_VERSION.to_string(),
        destination.database_scope.as_str().to_string(),
        destination.zone_name.clone(),
        target_window.start_unix_seconds.to_string(),
        target_window.end_unix_seconds.to_string(),
    ] {
        hasher.update(component.as_bytes());
        hasher.update([0]);
    }
    for record in records {
        hasher.update(record.as_bytes());
        hasher.update([0]);
    }
    CloudKitOriginalAssetInventoryFingerprint {
        resolver_version: CLOUDKIT_ORIGINAL_ASSET_RESOLVER_VERSION.to_string(),
        sha256: format!("{:x}", hasher.finalize()),
        records_scanned: records.len() as u64,
    }
}

pub struct ReqwestPhotosUploadTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestPhotosUploadTransport {
    pub fn new() -> Result<Self, UploadError> {
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|source| UploadError::HttpClient { source })?;
        Ok(Self { client })
    }
}

impl PhotosUploadTransport for ReqwestPhotosUploadTransport {
    fn post_service_json(
        &mut self,
        session: &UploadSession,
        endpoint: PhotosUploadEndpoint,
        payload: Value,
    ) -> Result<Value, UploadError> {
        let url = photosupload_service_url(session, endpoint)?;
        let response = self
            .client
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "text/plain;charset=UTF-8")
            .header(reqwest::header::COOKIE, cookie_header(session)?)
            .body(payload.to_string())
            .send()
            .map_err(|source| UploadError::Network {
                operation: endpoint.as_str(),
                source,
            })?;
        read_json_response(response, endpoint.as_str())
    }

    fn post_signed_upload(
        &mut self,
        session: &UploadSession,
        upload_url: &Url,
        heic_path: &Path,
    ) -> Result<(SingleFileUploadRequest, String, u64), UploadError> {
        validate_signed_upload_url(upload_url)?;
        let file = File::open(heic_path).map_err(|source| UploadError::ReadHeic {
            path: heic_path.to_path_buf(),
            source,
        })?;
        let size = file
            .metadata()
            .map_err(|source| UploadError::ReadHeic {
                path: heic_path.to_path_buf(),
                source,
            })?
            .len();
        let progress = Arc::new(Mutex::new(HashProgress::default()));
        let reader = HashingFile::new(file, Arc::clone(&progress));
        let response = self
            .client
            .post(upload_url.clone())
            .header(reqwest::header::CONTENT_TYPE, "text/plain")
            .header(reqwest::header::CONTENT_LENGTH, size)
            .header(reqwest::header::COOKIE, cookie_header(session)?)
            .body(reqwest::blocking::Body::sized(reader, size))
            .send()
            .map_err(|source| UploadError::Network {
                operation: "signed_upload",
                source,
            })?;
        let value = read_json_response(response, "signed_upload")?;
        let response: SignedUploadResponse =
            serde_json::from_value(value).map_err(|source| UploadError::DecodeUploadResponse {
                operation: "signed_upload",
                source,
            })?;
        let (streamed_heic_sha256, streamed_size_bytes) = finalize_hash_progress(progress)?;
        Ok((
            response.single_file,
            streamed_heic_sha256,
            streamed_size_bytes,
        ))
    }
}

struct ReqwestCloudKitTransport {
    client: reqwest::blocking::Client,
}

const CLOUDKIT_ORIGIN: &str = "https://www.icloud.com";
const CLOUDKIT_REFERER: &str = "https://www.icloud.com/";
const CLOUDKIT_BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";

impl ReqwestCloudKitTransport {
    pub fn new() -> Result<Self, UploadError> {
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|source| UploadError::HttpClient { source })?;
        Ok(Self { client })
    }

    fn post_records_json(
        &self,
        session: &CloudKitDeleteSession,
        url: Url,
        payload: Value,
        operation: &'static str,
        parse_response: fn(reqwest::blocking::Response, &'static str) -> Result<Value, UploadError>,
    ) -> Result<Value, UploadError> {
        session.validate()?;
        let response = self
            .client
            .post(url)
            .headers(cloudkit_records_request_headers(session)?)
            .body(payload.to_string())
            .send()
            .map_err(|source| UploadError::Network { operation, source })?;
        parse_response(response, operation)
    }

    fn download_resource(
        &self,
        session: &CloudKitDeleteSession,
        download_url: &Url,
        expected_size_bytes: u64,
    ) -> Result<CloudKitResourceDownload, UploadError> {
        validate_cloudkit_resource_download_url(download_url)?;
        session.validate()?;
        let mut response = self
            .client
            .get(download_url.clone())
            .headers(cloudkit_resource_download_headers(session)?)
            .send()
            .map_err(|source| UploadError::Network {
                operation: "resource_download",
                source,
            })?;
        let status = response.status();
        if !status.is_success() {
            return Err(UploadError::UploadHttpStatus {
                operation: "resource_download",
                status: status.as_u16(),
            });
        }

        let mut hasher = Sha256::new();
        let mut size_bytes = 0_u64;
        let mut buffer = [0_u8; HASH_BUFFER_BYTES];
        loop {
            let bytes_read =
                response
                    .read(&mut buffer)
                    .map_err(|source| UploadError::ReadUploadResponse {
                        operation: "resource_download",
                        source,
                    })?;
            if bytes_read == 0 {
                break;
            }
            size_bytes = size_bytes.checked_add(bytes_read as u64).ok_or(
                UploadError::CloudKitOriginalAssetDownloadSizeMismatch {
                    expected: expected_size_bytes,
                    actual: u64::MAX,
                },
            )?;
            if size_bytes > expected_size_bytes {
                return Err(UploadError::CloudKitOriginalAssetDownloadSizeMismatch {
                    expected: expected_size_bytes,
                    actual: size_bytes,
                });
            }
            hasher.update(&buffer[..bytes_read]);
        }
        if size_bytes != expected_size_bytes {
            return Err(UploadError::CloudKitOriginalAssetDownloadSizeMismatch {
                expected: expected_size_bytes,
                actual: size_bytes,
            });
        }
        Ok(CloudKitResourceDownload {
            sha256: format!("{:x}", hasher.finalize()),
            size_bytes,
        })
    }
}

pub struct ReqwestCloudKitDeleteTransport {
    transport: ReqwestCloudKitTransport,
}

impl ReqwestCloudKitDeleteTransport {
    pub fn new() -> Result<Self, UploadError> {
        Ok(Self {
            transport: ReqwestCloudKitTransport::new()?,
        })
    }
}

impl CloudKitDeleteTransport for ReqwestCloudKitDeleteTransport {
    fn post_records_modify(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError> {
        let url = cloudkit_records_modify_url(session, payload_database_scope(&payload, session))?;
        self.transport.post_records_json(
            session,
            url,
            payload,
            "records_modify",
            read_json_response,
        )
    }

    fn post_records_lookup(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError> {
        let url = cloudkit_records_lookup_url(session, payload_database_scope(&payload, session))?;
        self.transport.post_records_json(
            session,
            url,
            payload,
            "records_lookup",
            read_json_response,
        )
    }
}

impl CloudKitOriginalAssetReadTransport for ReqwestCloudKitDeleteTransport {
    fn post_records_query(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError> {
        let url = cloudkit_records_query_url(session, payload_database_scope(&payload, session))?;
        self.transport.post_records_json(
            session,
            url,
            payload,
            "records_query",
            read_cloudkit_json_response,
        )
    }

    fn download_resource(
        &mut self,
        session: &CloudKitDeleteSession,
        download_url: &Url,
        expected_size_bytes: u64,
    ) -> Result<CloudKitResourceDownload, UploadError> {
        self.transport
            .download_resource(session, download_url, expected_size_bytes)
    }
}

/// CloudKit transport restricted to original-asset queries and resource downloads.
///
/// ```compile_fail
/// use icloudpd_optimizer::upload::{CloudKitDeleteTransport, ReqwestCloudKitReadTransport};
///
/// fn requires_delete<T: CloudKitDeleteTransport>(_transport: T) {}
/// requires_delete(ReqwestCloudKitReadTransport::new().unwrap());
/// ```
pub struct ReqwestCloudKitReadTransport {
    transport: ReqwestCloudKitTransport,
    #[cfg(test)]
    endpoint_override: Option<Url>,
}

impl ReqwestCloudKitReadTransport {
    pub fn new() -> Result<Self, UploadError> {
        Ok(Self {
            transport: ReqwestCloudKitTransport::new()?,
            #[cfg(test)]
            endpoint_override: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_loopback_test(endpoint: Url) -> Result<Self, UploadError> {
        validate_loopback_test_endpoint(&endpoint)?;
        Ok(Self {
            transport: ReqwestCloudKitTransport::new()?,
            endpoint_override: Some(endpoint),
        })
    }

    fn records_query_url(
        &self,
        session: &CloudKitDeleteSession,
        database_scope: CloudKitDatabaseScope,
    ) -> Result<Url, UploadError> {
        #[cfg(test)]
        if let Some(endpoint) = &self.endpoint_override {
            return cloudkit_records_query_url_with_base(session, endpoint.clone(), database_scope);
        }
        cloudkit_records_query_url(session, database_scope)
    }
}

impl CloudKitOriginalAssetReadTransport for ReqwestCloudKitReadTransport {
    fn post_records_query(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError> {
        let url = self.records_query_url(session, payload_database_scope(&payload, session))?;
        self.transport.post_records_json(
            session,
            url,
            payload,
            "records_query",
            read_cloudkit_json_response,
        )
    }

    fn download_resource(
        &mut self,
        session: &CloudKitDeleteSession,
        download_url: &Url,
        expected_size_bytes: u64,
    ) -> Result<CloudKitResourceDownload, UploadError> {
        self.transport
            .download_resource(session, download_url, expected_size_bytes)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateUploadUrlResponse {
    upload_urls: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedUploadResponse {
    single_file: SingleFileUploadRequest,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutAssetSuccess {
    upload_job_id: Option<String>,
    cpl_master: String,
    cpl_asset: String,
}

enum UploadStatusState {
    InProgress,
    Complete,
}

#[derive(Default)]
struct HashProgress {
    hasher: Sha256,
    bytes: u64,
}

struct HashingFile {
    file: File,
    progress: Arc<Mutex<HashProgress>>,
    buffer: Vec<u8>,
    position: usize,
    filled: usize,
}

impl HashingFile {
    fn new(file: File, progress: Arc<Mutex<HashProgress>>) -> Self {
        Self {
            file,
            progress,
            buffer: vec![0_u8; HASH_BUFFER_BYTES],
            position: 0,
            filled: 0,
        }
    }

    fn fill_buffer(&mut self) -> std::io::Result<usize> {
        self.position = 0;
        self.filled = self.file.read(&mut self.buffer)?;
        if self.filled > 0 {
            let mut progress = self
                .progress
                .lock()
                .map_err(|_| std::io::Error::other("hash progress lock poisoned"))?;
            progress.hasher.update(&self.buffer[..self.filled]);
            progress.bytes += self.filled as u64;
        }
        Ok(self.filled)
    }
}

impl Read for HashingFile {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.position == self.filled && self.fill_buffer()? == 0 {
            return Ok(0);
        }
        let available = self.filled - self.position;
        let bytes_to_copy = available.min(output.len());
        output[..bytes_to_copy]
            .copy_from_slice(&self.buffer[self.position..self.position + bytes_to_copy]);
        self.position += bytes_to_copy;
        Ok(bytes_to_copy)
    }
}

fn create_upload_url_payload(size_bytes: u64, destination: &CloudKitLibraryDestination) -> Value {
    let mut assets = Map::new();
    assets.insert(Uuid::new_v4().to_string(), json!(size_bytes));
    json!({
        "zoneName": destination.zone_name,
        "assets": assets,
    })
}

fn put_asset_payload(
    filename: &str,
    last_modified_millis: u64,
    time_zone_offset_minutes: i32,
    local_time_zone_id: &str,
    single_file: &SingleFileUploadRequest,
    destination: &CloudKitLibraryDestination,
) -> Value {
    json!({
        "zoneName": destination.zone_name,
        "localTimeZoneId": local_time_zone_id,
        "files": [{
            "fileName": filename,
            "lastModDate": last_modified_millis,
            "timeZoneOffset": time_zone_offset_minutes,
            "singleFileUploadRequest": single_file,
        }],
    })
}

fn cloudkit_delete_payload(request: &CloudKitDeleteRequest) -> Value {
    let destination = CloudKitLibraryDestination {
        database_scope: request.database_scope,
        zone_name: request.zone_name.clone(),
    };
    json!({
        "atomic": true,
        "desiredKeys": ["isDeleted"],
        "operations": [{
            "operationType": "update",
            "record": {
                "recordName": request.record_name,
                "recordType": "CPLAsset",
                "recordChangeTag": request.record_change_tag,
                "fields": {
                    "isDeleted": {"value": 1}
                }
            }
        }],
        "zoneID": destination.zone_id_payload()
    })
}

fn cloudkit_delete_batch_payload(request: &CloudKitDeleteBatchRequest) -> Value {
    let destination = request
        .requests
        .first()
        .map(|request| CloudKitLibraryDestination {
            database_scope: request.database_scope,
            zone_name: request.zone_name.clone(),
        })
        .unwrap_or_else(CloudKitLibraryDestination::primary_sync);
    let operations: Vec<Value> = request
        .requests
        .iter()
        .map(|request| {
            json!({
                "operationType": "update",
                "record": {
                    "recordName": request.record_name,
                    "recordType": "CPLAsset",
                    "recordChangeTag": request.record_change_tag,
                    "fields": {
                        "isDeleted": {"value": 1}
                    }
                }
            })
        })
        .collect();

    json!({
        "atomic": true,
        "desiredKeys": ["isDeleted"],
        "operations": operations,
        "zoneID": destination.zone_id_payload()
    })
}

fn cloudkit_records_lookup_payload(
    record_names: &[&str],
    desired_keys: &[&str],
    destination: &CloudKitLibraryDestination,
) -> Value {
    let records: Vec<Value> = record_names
        .iter()
        .map(|record_name| json!({ "recordName": record_name }))
        .collect();
    json!({
        "records": records,
        "desiredKeys": desired_keys,
        "zoneID": destination.zone_id_payload()
    })
}

fn cloudkit_original_asset_query_payload(
    start_rank: u64,
    page_size: u64,
    continuation_marker: Option<&str>,
    destination: &CloudKitLibraryDestination,
) -> Value {
    let mut payload = json!({
        "query": {
            "recordType": "CPLAssetAndMasterByAssetDateWithoutHiddenOrDeleted",
            "filterBy": [
                {
                    "fieldName": "direction",
                    "comparator": "EQUALS",
                    "fieldValue": {"type": "STRING", "value": "ASCENDING"}
                },
                {
                    "fieldName": "startRank",
                    "comparator": "EQUALS",
                    "fieldValue": {"type": "INT64", "value": start_rank}
                }
            ]
        },
        "resultsLimit": page_size,
        "desiredKeys": [
            "masterRef",
            "assetDate",
            "resOriginalRes",
            "resOriginalFileType",
            "resOriginalFingerprint",
            "resOriginalWidth",
            "resOriginalHeight",
            "resOriginalAltRes",
            "resOriginalAltFileType",
            "resOriginalAltFingerprint",
            "resOriginalAltWidth",
            "resOriginalAltHeight",
            "resSidecarRes",
            "resSidecarFileType",
            "resSidecarFingerprint",
            "resSidecarWidth",
            "resSidecarHeight",
            "resOriginalVidComplRes",
            "resOriginalVidComplFileType",
            "resOriginalVidComplFingerprint",
            "resOriginalVidComplWidth",
            "resOriginalVidComplHeight"
        ],
        "zoneID": destination.zone_id_payload()
    });
    if let Some(marker) = continuation_marker {
        payload["continuationMarker"] = json!(marker);
    }
    payload
}

fn original_asset_query_start_rank(
    start_rank: u64,
    page_size: u64,
    page: u64,
) -> Result<u64, UploadError> {
    let offset =
        page.checked_mul(page_size)
            .ok_or(UploadError::InvalidCloudKitOriginalAssetRequest(
                "pagination start rank overflow",
            ))?;
    start_rank
        .checked_add(offset)
        .ok_or(UploadError::InvalidCloudKitOriginalAssetRequest(
            "pagination start rank overflow",
        ))
}

fn seek_original_asset_query_page<T>(
    start_rank: u64,
    page_size: u64,
    max_pages: u64,
    target_window: &OriginalAssetDateWindow,
    mut query_page: impl FnMut(u64) -> Result<OriginalAssetQueryPage<T>, UploadError>,
) -> Result<OriginalAssetSeekResult<T>, UploadError> {
    let mut pages_read = 0;
    let first_page = read_original_asset_rank_page(start_rank, &mut pages_read, &mut query_page)?;
    match first_page.page.position_against(target_window) {
        OriginalAssetPagePosition::TooNew => {}
        OriginalAssetPagePosition::TooOld => {
            return seek_original_asset_query_page_toward_newer(
                first_page,
                page_size,
                max_pages,
                target_window,
                pages_read,
                query_page,
            );
        }
        OriginalAssetPagePosition::Overlaps | OriginalAssetPagePosition::Empty => {
            return Ok(OriginalAssetSeekResult {
                page: first_page,
                pages_read,
            });
        }
    }

    let mut lower_rank = start_rank;
    let mut step = first_page
        .page
        .asset_count()
        .max(1)
        .max(page_size.saturating_div(2).max(1));
    let mut upper_page = loop {
        if pages_read >= max_pages {
            return Err(UploadError::OriginalAssetResolveIncomplete { matches: 0 });
        }
        let probe_rank = checked_rank_add(start_rank, step)?;
        let page = read_original_asset_rank_page(probe_rank, &mut pages_read, &mut query_page)?;
        if page.page.position_against(target_window) == OriginalAssetPagePosition::TooNew {
            lower_rank = probe_rank;
            step = step
                .checked_mul(2)
                .ok_or(UploadError::InvalidCloudKitOriginalAssetRequest(
                    "pagination start rank overflow",
                ))?;
            continue;
        }
        break page;
    };

    while lower_rank.saturating_add(1) < upper_page.start_rank {
        if pages_read >= max_pages {
            return Err(UploadError::OriginalAssetResolveIncomplete { matches: 0 });
        }
        let mid_rank = lower_rank + (upper_page.start_rank - lower_rank) / 2;
        let page = read_original_asset_rank_page(mid_rank, &mut pages_read, &mut query_page)?;
        if page.page.position_against(target_window) == OriginalAssetPagePosition::TooNew {
            lower_rank = mid_rank;
        } else {
            upper_page = page;
        }
    }

    Ok(OriginalAssetSeekResult {
        page: upper_page,
        pages_read,
    })
}

fn seek_original_asset_query_page_toward_newer<T>(
    first_page: PositionedOriginalAssetQueryPage<T>,
    page_size: u64,
    max_pages: u64,
    target_window: &OriginalAssetDateWindow,
    mut pages_read: u64,
    mut query_page: impl FnMut(u64) -> Result<OriginalAssetQueryPage<T>, UploadError>,
) -> Result<OriginalAssetSeekResult<T>, UploadError> {
    if first_page.start_rank == 0 {
        return Ok(OriginalAssetSeekResult {
            page: first_page,
            pages_read,
        });
    }

    let mut upper_page = first_page;
    let mut step = upper_page
        .page
        .asset_count()
        .max(1)
        .max(page_size.saturating_div(2).max(1));
    let lower_page = loop {
        if pages_read >= max_pages {
            return Err(UploadError::OriginalAssetResolveIncomplete { matches: 0 });
        }
        let probe_rank = upper_page.start_rank.saturating_sub(step);
        let page = read_original_asset_rank_page(probe_rank, &mut pages_read, &mut query_page)?;
        match page.page.position_against(target_window) {
            OriginalAssetPagePosition::TooOld if probe_rank > 0 => {
                upper_page = page;
                step =
                    step.checked_mul(2)
                        .ok_or(UploadError::InvalidCloudKitOriginalAssetRequest(
                            "pagination start rank overflow",
                        ))?;
            }
            OriginalAssetPagePosition::TooOld => {
                return Ok(OriginalAssetSeekResult { page, pages_read });
            }
            _ => break page,
        }
    };

    if lower_page.page.position_against(target_window) != OriginalAssetPagePosition::TooNew {
        return Ok(OriginalAssetSeekResult {
            page: lower_page,
            pages_read,
        });
    }

    let mut lower_rank = lower_page.start_rank;
    while lower_rank.saturating_add(1) < upper_page.start_rank {
        if pages_read >= max_pages {
            return Err(UploadError::OriginalAssetResolveIncomplete { matches: 0 });
        }
        let mid_rank = lower_rank + (upper_page.start_rank - lower_rank) / 2;
        let page = read_original_asset_rank_page(mid_rank, &mut pages_read, &mut query_page)?;
        match page.page.position_against(target_window) {
            OriginalAssetPagePosition::TooNew => lower_rank = mid_rank,
            OriginalAssetPagePosition::Overlaps | OriginalAssetPagePosition::Empty => {
                return Ok(OriginalAssetSeekResult { page, pages_read });
            }
            OriginalAssetPagePosition::TooOld => upper_page = page,
        }
    }

    Ok(OriginalAssetSeekResult {
        page: upper_page,
        pages_read,
    })
}

fn read_original_asset_rank_page<T>(
    start_rank: u64,
    pages_read: &mut u64,
    query_page: &mut impl FnMut(u64) -> Result<OriginalAssetQueryPage<T>, UploadError>,
) -> Result<PositionedOriginalAssetQueryPage<T>, UploadError> {
    let page = query_page(start_rank)?;
    *pages_read = pages_read.saturating_add(1);
    Ok(PositionedOriginalAssetQueryPage { start_rank, page })
}

fn checked_rank_add(start_rank: u64, offset: u64) -> Result<u64, UploadError> {
    start_rank
        .checked_add(offset)
        .ok_or(UploadError::InvalidCloudKitOriginalAssetRequest(
            "pagination start rank overflow",
        ))
}

fn parse_create_upload_url_response(value: Value) -> Result<Url, UploadError> {
    let response: CreateUploadUrlResponse =
        serde_json::from_value(value).map_err(|source| UploadError::DecodeUploadResponse {
            operation: PhotosUploadEndpoint::CreateUploadUrl.as_str(),
            source,
        })?;
    if response.upload_urls.len() != 1 {
        return Err(UploadError::InvalidPhotosUploadResponse(
            "createUploadUrl must return exactly one upload URL",
        ));
    }
    let (_, raw_url) =
        response
            .upload_urls
            .into_iter()
            .next()
            .ok_or(UploadError::InvalidPhotosUploadResponse(
                "createUploadUrl returned no upload URL",
            ))?;
    let url = Url::parse(&raw_url).map_err(|_| {
        UploadError::InvalidPhotosUploadResponse("createUploadUrl returned an invalid URL")
    })?;
    validate_signed_upload_url(&url)?;
    Ok(url)
}

fn parse_put_asset_response(value: Value) -> Result<PutAssetSuccess, UploadError> {
    let items = value
        .as_array()
        .ok_or(UploadError::InvalidPhotosUploadResponse(
            "putAsset response must be an array",
        ))?;
    if items.len() != 1 {
        return Err(UploadError::InvalidPhotosUploadResponse(
            "putAsset must return exactly one item",
        ));
    }
    let item = &items[0];
    let response_status = item
        .get("response")
        .and_then(|response| response.get("status"))
        .and_then(Value::as_u64);
    if let Some(status) = response_status.filter(|status| *status != 200) {
        if status == 409 && is_duplicate_put_asset_response(item) {
            let success = decode_put_asset_success(item)?;
            validate_put_asset_identifiers(&success)?;
            return Ok(success);
        }
        return Err(UploadError::PhotosPutAssetRejected {
            status: status as u16,
            detail: bounded_upload_error_detail(item),
        });
    }
    if item.get("uploadJobId").is_some()
        && item.get("cplMaster").is_some()
        && item.get("cplAsset").is_some()
    {
        let success = decode_put_asset_success(item)?;
        if success
            .upload_job_id
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            return Err(UploadError::InvalidPhotosUploadResponse(
                "putAsset did not return uploadJobId",
            ));
        }
        validate_put_asset_identifiers(&success)?;
        return Ok(success);
    }
    Err(UploadError::InvalidPhotosUploadResponse(
        "putAsset response was neither success nor error",
    ))
}

fn decode_put_asset_success(item: &Value) -> Result<PutAssetSuccess, UploadError> {
    serde_json::from_value(item.clone()).map_err(|source| UploadError::DecodeUploadResponse {
        operation: PhotosUploadEndpoint::PutAsset.as_str(),
        source,
    })
}

fn validate_put_asset_identifiers(success: &PutAssetSuccess) -> Result<(), UploadError> {
    if success.cpl_master.trim().is_empty() {
        return Err(UploadError::InvalidPhotosUploadResponse(
            "putAsset did not return cplMaster",
        ));
    }
    if success.cpl_asset.trim().is_empty() {
        return Err(UploadError::MissingUploadedAssetId);
    }
    Ok(())
}

fn is_duplicate_put_asset_response(item: &Value) -> bool {
    item.get("cplMaster").is_some()
        && item.get("cplAsset").is_some()
        && item
            .get("response")
            .and_then(|response| response.get("errorMessage"))
            .and_then(Value::as_str)
            == Some("duplicate photo found")
}

fn bounded_upload_error_detail(value: &Value) -> String {
    let mut detail = value.to_string();
    if detail.len() > MAX_UPLOAD_ERROR_DETAIL_CHARS {
        detail.truncate(MAX_UPLOAD_ERROR_DETAIL_CHARS);
        detail.push_str("...");
    }
    detail
}

fn parse_upload_status_response(
    value: Value,
    upload_job_id: &str,
) -> Result<UploadStatusState, UploadError> {
    let status = value
        .get(upload_job_id)
        .ok_or(UploadError::InvalidPhotosUploadResponse(
            "uploadStatus did not include the upload job",
        ))?;
    if let Some(error_code) = status.get("errorCode").and_then(Value::as_u64) {
        return Err(UploadError::PhotosUploadStatusFailed { error_code });
    }
    if let Some(status_text) = status.get("status").and_then(Value::as_str) {
        return match status_text {
            "COMPLETED" => Ok(UploadStatusState::Complete),
            "ERROR" | "FAILED" => Err(UploadError::PhotosUploadStatusFailed { error_code: 0 }),
            _ => Err(UploadError::InvalidPhotosUploadResponse(
                "uploadStatus returned an unknown status",
            )),
        };
    }
    if status
        .get("progress")
        .and_then(Value::as_f64)
        .is_some_and(|progress| progress >= 100.0)
    {
        return Ok(UploadStatusState::Complete);
    }
    Ok(UploadStatusState::InProgress)
}

fn parse_cloudkit_delete_response(
    value: Value,
    request: &CloudKitDeleteRequest,
) -> Result<CloudKitDeleteOutcome, UploadError> {
    let records = value.get("records").and_then(Value::as_array).ok_or(
        UploadError::InvalidCloudKitDeleteResponse("records/modify response must include records"),
    )?;
    if records.len() != 1 {
        return Err(UploadError::InvalidCloudKitDeleteResponse(
            "records/modify must return exactly one record",
        ));
    }
    parse_cloudkit_delete_record(&records[0], request)
}

fn parse_cloudkit_delete_batch_response(
    value: Value,
    request: &CloudKitDeleteBatchRequest,
) -> Result<Vec<CloudKitDeleteOutcome>, UploadError> {
    let records = value.get("records").and_then(Value::as_array).ok_or(
        UploadError::InvalidCloudKitDeleteResponse("records/modify response must include records"),
    )?;
    if records.len() != request.requests.len() {
        return Err(UploadError::InvalidCloudKitDeleteResponse(
            "records/modify batch returned a different record count",
        ));
    }

    let mut records_by_name = BTreeMap::new();
    for record in records {
        let record_name = record.get("recordName").and_then(Value::as_str).ok_or(
            UploadError::InvalidCloudKitDeleteResponse(
                "records/modify response missing recordName",
            ),
        )?;
        if records_by_name
            .insert(record_name.to_string(), record)
            .is_some()
        {
            return Err(UploadError::InvalidCloudKitDeleteResponse(
                "records/modify batch returned duplicate recordName",
            ));
        }
    }

    let mut outcomes = Vec::with_capacity(request.requests.len());
    for request in &request.requests {
        let record = records_by_name.get(&request.record_name).ok_or(
            UploadError::InvalidCloudKitDeleteResponse(
                "records/modify batch omitted a requested recordName",
            ),
        )?;
        outcomes.push(parse_cloudkit_delete_record(record, request)?);
    }
    Ok(outcomes)
}

fn parse_cloudkit_delete_state_lookup_response(
    value: Value,
    request: &CloudKitDeleteBatchRequest,
) -> Result<CloudKitDeleteStateLookupResult, UploadError> {
    let records = value.get("records").and_then(Value::as_array).ok_or(
        UploadError::InvalidCloudKitDeleteLookupResponse(
            "records/lookup response must include records",
        ),
    )?;
    if records.len() != request.requests.len() {
        return Err(UploadError::InvalidCloudKitDeleteLookupResponse(
            "records/lookup returned a different record count",
        ));
    }

    let mut records_by_name = BTreeMap::new();
    for record in records {
        if record.get("serverErrorCode").is_some() {
            return Err(UploadError::InvalidCloudKitDeleteLookupResponse(
                "records/lookup returned a record error",
            ));
        }
        let record_name = record.get("recordName").and_then(Value::as_str).ok_or(
            UploadError::InvalidCloudKitDeleteLookupResponse(
                "records/lookup response missing recordName",
            ),
        )?;
        if records_by_name.insert(record_name, record).is_some() {
            return Err(UploadError::InvalidCloudKitDeleteLookupResponse(
                "records/lookup returned duplicate recordName",
            ));
        }
    }

    let mut confirmed_deleted = Vec::new();
    let mut unconfirmed = Vec::new();
    for request in &request.requests {
        let record = records_by_name.get(request.record_name.as_str()).ok_or(
            UploadError::InvalidCloudKitDeleteLookupResponse(
                "records/lookup omitted a requested recordName",
            ),
        )?;
        if let Some(record_type) = record.get("recordType") {
            let record_type =
                record_type
                    .as_str()
                    .ok_or(UploadError::InvalidCloudKitDeleteLookupResponse(
                        "records/lookup returned malformed recordType",
                    ))?;
            if record_type != "CPLAsset" {
                return Err(UploadError::InvalidCloudKitDeleteLookupResponse(
                    "records/lookup returned a non-CPLAsset recordType",
                ));
            }
        }
        let record_change_tag = record
            .get("recordChangeTag")
            .and_then(Value::as_str)
            .ok_or(UploadError::InvalidCloudKitDeleteLookupResponse(
                "records/lookup response missing recordChangeTag",
            ))?;
        if record_change_tag.trim().is_empty() {
            return Err(UploadError::InvalidCloudKitDeleteLookupResponse(
                "records/lookup returned an empty recordChangeTag",
            ));
        }
        let is_deleted = record
            .get("fields")
            .and_then(|fields| fields.get("isDeleted"))
            .and_then(|is_deleted| is_deleted.get("value"))
            .ok_or(UploadError::InvalidCloudKitDeleteLookupResponse(
                "records/lookup response missing isDeleted",
            ))?;
        let is_deleted = match (is_deleted.as_bool(), is_deleted.as_i64()) {
            (Some(value), _) => value,
            (_, Some(0)) => false,
            (_, Some(1)) => true,
            _ => {
                return Err(UploadError::InvalidCloudKitDeleteLookupResponse(
                    "records/lookup returned malformed isDeleted",
                ));
            }
        };

        if !is_deleted {
            unconfirmed.push(request.clone());
            continue;
        }
        if record_change_tag == request.record_change_tag {
            return Err(UploadError::InvalidCloudKitDeleteLookupResponse(
                "records/lookup confirmed delete without a changed recordChangeTag",
            ));
        }
        confirmed_deleted.push(CloudKitDeleteOutcome {
            record_name: request.record_name.clone(),
            record_change_tag: record_change_tag.to_string(),
        });
    }

    Ok(CloudKitDeleteStateLookupResult {
        confirmed_deleted,
        unconfirmed,
    })
}

fn parse_cloudkit_delete_record(
    record: &Value,
    request: &CloudKitDeleteRequest,
) -> Result<CloudKitDeleteOutcome, UploadError> {
    if record.get("serverErrorCode").is_some() {
        return Err(UploadError::InvalidCloudKitDeleteResponse(
            "records/modify returned a record error",
        ));
    }
    let record_name = record.get("recordName").and_then(Value::as_str).ok_or(
        UploadError::InvalidCloudKitDeleteResponse("records/modify response missing recordName"),
    )?;
    if record_name != request.record_name {
        return Err(UploadError::InvalidCloudKitDeleteResponse(
            "records/modify confirmed a different recordName",
        ));
    }
    let record_change_tag = record
        .get("recordChangeTag")
        .and_then(Value::as_str)
        .ok_or(UploadError::InvalidCloudKitDeleteResponse(
            "records/modify response missing recordChangeTag",
        ))?;
    if record_change_tag.trim().is_empty() {
        return Err(UploadError::InvalidCloudKitDeleteResponse(
            "records/modify response returned an empty recordChangeTag",
        ));
    }
    let is_deleted = record
        .get("fields")
        .and_then(|fields| fields.get("isDeleted"))
        .and_then(|is_deleted| is_deleted.get("value"));
    if !matches!(is_deleted.and_then(Value::as_i64), Some(1))
        && !matches!(is_deleted.and_then(Value::as_bool), Some(true))
    {
        return Err(UploadError::InvalidCloudKitDeleteResponse(
            "records/modify did not confirm isDeleted",
        ));
    }
    Ok(CloudKitDeleteOutcome {
        record_name: record_name.to_string(),
        record_change_tag: record_change_tag.to_string(),
    })
}

struct OriginalAssetQueryPage<T> {
    continuation_marker: Option<String>,
    matches: Vec<T>,
    asset_dates: Vec<u64>,
    observation_increments: Vec<OriginalAssetCohortObservationIncrement>,
    inventory_records: Vec<String>,
}

impl<T> OriginalAssetQueryPage<T> {
    fn asset_count(&self) -> u64 {
        self.asset_dates.len() as u64
    }

    fn date_bounds(&self) -> Option<(u64, u64)> {
        let min = self.asset_dates.iter().min()?;
        let max = self.asset_dates.iter().max()?;
        Some((*min, *max))
    }

    fn position_against(&self, window: &OriginalAssetDateWindow) -> OriginalAssetPagePosition {
        let Some((min_asset_date, max_asset_date)) = self.date_bounds() else {
            return OriginalAssetPagePosition::Empty;
        };
        if min_asset_date > window.end_unix_seconds {
            OriginalAssetPagePosition::TooNew
        } else if max_asset_date < window.start_unix_seconds {
            OriginalAssetPagePosition::TooOld
        } else {
            OriginalAssetPagePosition::Overlaps
        }
    }
}

struct PositionedOriginalAssetQueryPage<T> {
    start_rank: u64,
    page: OriginalAssetQueryPage<T>,
}

struct OriginalAssetSeekResult<T> {
    page: PositionedOriginalAssetQueryPage<T>,
    pages_read: u64,
}

struct OriginalAssetCandidate {
    proof: OriginalAssetProof,
    download_url: Url,
}

struct OriginalAssetBatchCandidate {
    asset: OriginalAssetRemoteAsset,
    resource: OriginalAssetRemoteResource,
    cohort_indexes: Vec<usize>,
}

#[derive(Clone)]
struct OriginalAssetRemoteAsset {
    record_name: String,
    record_change_tag: String,
}

#[derive(Clone)]
struct OriginalAssetRemoteMatch {
    asset: OriginalAssetRemoteAsset,
    resource_field: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum CloudKitOriginalAssetCandidateKind {
    Raw,
    Replacement,
}

#[derive(Clone)]
enum CachedCloudKitResourceDownload {
    Downloaded(CloudKitResourceDownload),
    SizeMismatch,
}

#[derive(Clone, Default)]
struct OriginalAssetCohortResolutionWork {
    observations: CloudKitOriginalAssetResolveObservations,
    raw_size_matches: BTreeMap<u64, u64>,
    incomplete_raw_sizes: BTreeMap<u64, u64>,
    incomplete_replacement_sizes: BTreeMap<u64, u64>,
    raw_matches: BTreeMap<OriginalAssetMatchKey, BTreeMap<String, OriginalAssetRemoteMatch>>,
    replacement_matches:
        BTreeMap<OriginalAssetMatchKey, BTreeMap<String, OriginalAssetRemoteMatch>>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct OriginalAssetMatchKey {
    size_bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct OriginalAssetCohortMatchGroupKey {
    cohort_index: usize,
    kind: CloudKitOriginalAssetCandidateKind,
    key: OriginalAssetMatchKey,
}

#[derive(Default)]
struct OriginalAssetCohortObservationIncrement {
    cohort_index: usize,
    date_candidates: u64,
    raw_resources: u64,
    raw_size_matches: BTreeMap<u64, u64>,
}

struct OriginalAssetTargetIndex {
    cohorts: Vec<OriginalAssetTargetCohort>,
    target_cohort_indexes: Vec<usize>,
}

#[derive(Clone, Copy)]
struct OriginalAssetDateWindow {
    start_unix_seconds: u64,
    end_unix_seconds: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OriginalAssetPagePosition {
    TooNew,
    Overlaps,
    TooOld,
    Empty,
}

struct OriginalAssetTargetCohort {
    start_unix_seconds: u64,
    end_unix_seconds: u64,
    raw_target_counts: BTreeMap<OriginalAssetMatchKey, usize>,
    replacement_target_counts: BTreeMap<OriginalAssetMatchKey, usize>,
    raw_target_sizes: BTreeSet<u64>,
    replacement_target_sizes: BTreeSet<u64>,
}

impl OriginalAssetDateWindow {
    fn new(source_captured_unix_seconds: u64, capture_tolerance_seconds: u64) -> Self {
        Self {
            start_unix_seconds: source_captured_unix_seconds
                .saturating_sub(capture_tolerance_seconds),
            end_unix_seconds: source_captured_unix_seconds
                .saturating_add(capture_tolerance_seconds),
        }
    }
}

impl OriginalAssetTargetIndex {
    fn new(targets: &[CloudKitOriginalAssetResolveTarget]) -> Self {
        let mut target_date_windows = BTreeMap::<(u64, u64), Vec<usize>>::new();
        for (index, target) in targets.iter().enumerate() {
            target_date_windows
                .entry((
                    target
                        .source_captured_unix_seconds
                        .saturating_sub(target.capture_tolerance_seconds),
                    target
                        .source_captured_unix_seconds
                        .saturating_add(target.capture_tolerance_seconds),
                ))
                .or_default()
                .push(index);
        }
        let mut target_cohort_indexes = vec![0; targets.len()];
        let cohorts = target_date_windows
            .into_iter()
            .enumerate()
            .map(
                |(cohort_index, ((start_unix_seconds, end_unix_seconds), target_indexes))| {
                    let mut raw_target_counts = BTreeMap::new();
                    let mut replacement_target_counts = BTreeMap::new();
                    let mut raw_target_sizes = BTreeSet::new();
                    let mut replacement_target_sizes = BTreeSet::new();
                    for target_index in &target_indexes {
                        target_cohort_indexes[*target_index] = cohort_index;
                        let target = &targets[*target_index];
                        let raw_key = OriginalAssetMatchKey {
                            size_bytes: target.raw_size_bytes,
                            sha256: target.matched_raw_sha256.clone(),
                        };
                        raw_target_sizes.insert(raw_key.size_bytes);
                        *raw_target_counts.entry(raw_key).or_default() += 1;
                        if let Some(replacement) = &target.replacement_candidate {
                            let replacement_key = OriginalAssetMatchKey {
                                size_bytes: replacement.size_bytes,
                                sha256: replacement.sha256.clone(),
                            };
                            replacement_target_sizes.insert(replacement_key.size_bytes);
                            *replacement_target_counts
                                .entry(replacement_key)
                                .or_default() += 1;
                        }
                    }
                    OriginalAssetTargetCohort {
                        start_unix_seconds,
                        end_unix_seconds,
                        raw_target_counts,
                        replacement_target_counts,
                        raw_target_sizes,
                        replacement_target_sizes,
                    }
                },
            )
            .collect();
        Self {
            cohorts,
            target_cohort_indexes,
        }
    }

    fn cohort_indexes_for_asset_date(&self, asset_date_unix_seconds: u64) -> Vec<usize> {
        let upper_bound = self
            .cohorts
            .partition_point(|cohort| cohort.start_unix_seconds <= asset_date_unix_seconds);
        self.cohorts[..upper_bound]
            .iter()
            .enumerate()
            .filter(|(_, cohort)| asset_date_unix_seconds <= cohort.end_unix_seconds)
            .map(|(cohort_index, _)| cohort_index)
            .collect()
    }

    fn cohort_count(&self) -> usize {
        self.cohorts.len()
    }

    fn date_window(&self) -> OriginalAssetDateWindow {
        let start_unix_seconds = self
            .cohorts
            .iter()
            .map(|cohort| cohort.start_unix_seconds)
            .min()
            .unwrap_or(0);
        let end_unix_seconds = self
            .cohorts
            .iter()
            .map(|cohort| cohort.end_unix_seconds)
            .max()
            .unwrap_or(0);
        OriginalAssetDateWindow {
            start_unix_seconds,
            end_unix_seconds,
        }
    }
}

#[derive(Clone)]
struct CloudKitAssetRecord {
    record_name: String,
    record_change_tag: String,
    master_record_name: String,
    asset_date_unix_seconds: u64,
    record: Value,
}

fn parse_original_asset_query_response(
    value: Value,
    request: &CloudKitOriginalAssetResolveRequest,
    destination: &CloudKitLibraryDestination,
) -> Result<OriginalAssetQueryPage<OriginalAssetCandidate>, UploadError> {
    let records = value.get("records").and_then(Value::as_array).ok_or(
        UploadError::InvalidCloudKitOriginalAssetResponse(
            "records/query response must include records",
        ),
    )?;
    let continuation_marker = parse_cloudkit_continuation_marker(&value)?;
    let mut assets = Vec::new();
    let mut masters = std::collections::BTreeMap::new();

    for record in records {
        if record.get("serverErrorCode").is_some() {
            return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
                "records/query returned a record error",
            ));
        }
        let record_type = required_record_string(record, "recordType")?;
        match record_type {
            "CPLAsset" => assets.push(parse_cloudkit_asset_record(record)?),
            "CPLMaster" => {
                let record_name = required_record_string(record, "recordName")?.to_string();
                if masters.insert(record_name, record).is_some() {
                    return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
                        "records/query returned duplicate CPLMaster recordName",
                    ));
                }
            }
            _ => {}
        }
    }

    let asset_dates = assets
        .iter()
        .map(|asset| asset.asset_date_unix_seconds)
        .collect();
    let mut matches = Vec::new();
    for asset in assets {
        let master = masters.get(&asset.master_record_name).ok_or(
            UploadError::InvalidCloudKitOriginalAssetResponse(
                "records/query returned an asset without its master",
            ),
        )?;
        if !asset_date_matches(
            asset.asset_date_unix_seconds,
            request.source_captured_unix_seconds,
            request.capture_tolerance_seconds,
        ) {
            continue;
        }
        let mut target_sizes = BTreeSet::new();
        target_sizes.insert(request.raw_size_bytes);
        for (_, download_url) in
            record_pair_matching_raw_resource_urls(&asset.record, master, &target_sizes)?
        {
            matches.push(OriginalAssetCandidate {
                proof: OriginalAssetProof {
                    record_name: asset.record_name.clone(),
                    record_change_tag: asset.record_change_tag.clone(),
                    record_type: "CPLAsset".to_string(),
                    database_scope: destination.database_scope,
                    zone_name: destination.zone_name.clone(),
                    filename: request.filename.clone(),
                    size_bytes: request.raw_size_bytes,
                    matched_raw_sha256: request.matched_raw_sha256.clone(),
                },
                download_url,
            });
        }
    }

    Ok(OriginalAssetQueryPage {
        continuation_marker,
        matches,
        asset_dates,
        observation_increments: Vec::new(),
        inventory_records: Vec::new(),
    })
}

fn parse_original_asset_batch_query_response(
    value: Value,
    target_index: &OriginalAssetTargetIndex,
    _destination: &CloudKitLibraryDestination,
) -> Result<OriginalAssetQueryPage<OriginalAssetBatchCandidate>, UploadError> {
    let records = value.get("records").and_then(Value::as_array).ok_or(
        UploadError::InvalidCloudKitOriginalAssetResponse(
            "records/query response must include records",
        ),
    )?;
    let continuation_marker = parse_cloudkit_continuation_marker(&value)?;
    let mut assets = Vec::new();
    let mut masters = BTreeMap::new();

    for record in records {
        if record.get("serverErrorCode").is_some() {
            return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
                "records/query returned a record error",
            ));
        }
        let record_type = required_record_string(record, "recordType")?;
        match record_type {
            "CPLAsset" => assets.push(parse_cloudkit_asset_record(record)?),
            "CPLMaster" => {
                let record_name = required_record_string(record, "recordName")?.to_string();
                if masters.insert(record_name, record).is_some() {
                    return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
                        "records/query returned duplicate CPLMaster recordName",
                    ));
                }
            }
            _ => {}
        }
    }

    let asset_dates = assets
        .iter()
        .map(|asset| asset.asset_date_unix_seconds)
        .collect();
    let mut matches = Vec::new();
    let mut observation_increments = Vec::new();
    let mut inventory_records = BTreeSet::new();
    let inventory_window = target_index.date_window();
    for asset in assets {
        let matching_cohort_indexes =
            target_index.cohort_indexes_for_asset_date(asset.asset_date_unix_seconds);
        let in_inventory_window = asset.asset_date_unix_seconds
            >= inventory_window.start_unix_seconds
            && asset.asset_date_unix_seconds <= inventory_window.end_unix_seconds;
        if matching_cohort_indexes.is_empty() && !in_inventory_window {
            continue;
        }
        let master = masters.get(&asset.master_record_name).ok_or(
            UploadError::InvalidCloudKitOriginalAssetResponse(
                "records/query returned an asset without its master",
            ),
        )?;
        let resources = record_pair_original_asset_resources(&asset.record, master)?;
        inventory_records.insert(normalized_inventory_asset_identity(&asset, master)?);
        if matching_cohort_indexes.is_empty() {
            continue;
        }
        for cohort_index in &matching_cohort_indexes {
            let mut increment = OriginalAssetCohortObservationIncrement {
                cohort_index: *cohort_index,
                date_candidates: 1,
                ..OriginalAssetCohortObservationIncrement::default()
            };
            for resource in &resources {
                if resource.kind == CloudKitOriginalAssetCandidateKind::Raw {
                    increment.raw_resources = increment.raw_resources.saturating_add(1);
                    *increment
                        .raw_size_matches
                        .entry(resource.size_bytes)
                        .or_default() = increment
                        .raw_size_matches
                        .get(&resource.size_bytes)
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(1);
                }
            }
            observation_increments.push(increment);
        }
        let asset = OriginalAssetRemoteAsset {
            record_name: asset.record_name,
            record_change_tag: asset.record_change_tag,
        };
        matches.extend(resources.into_iter().filter_map(|resource| {
            let relevant = matching_cohort_indexes.iter().any(|cohort_index| {
                let cohort = &target_index.cohorts[*cohort_index];
                match resource.kind {
                    CloudKitOriginalAssetCandidateKind::Raw => {
                        cohort.raw_target_sizes.contains(&resource.size_bytes)
                    }
                    CloudKitOriginalAssetCandidateKind::Replacement => cohort
                        .replacement_target_sizes
                        .contains(&resource.size_bytes),
                }
            });
            if relevant {
                Some(OriginalAssetBatchCandidate {
                    asset: asset.clone(),
                    resource,
                    cohort_indexes: matching_cohort_indexes.clone(),
                })
            } else {
                None
            }
        }));
    }

    Ok(OriginalAssetQueryPage {
        continuation_marker,
        matches,
        asset_dates,
        observation_increments,
        inventory_records: inventory_records.into_iter().collect(),
    })
}

struct UploadedHeicAssetLookup {
    record_name: String,
    record_change_tag: String,
    master_record_name: String,
}

fn parse_uploaded_heic_asset_lookup_response(
    value: Value,
    request: &CloudKitUploadedHeicResolveRequest,
) -> Result<UploadedHeicAssetLookup, UploadError> {
    let records = cloudkit_lookup_records(&value)?;
    if records.len() != 1 {
        return Err(UploadError::InvalidCloudKitUploadedHeicResponse(
            "records/lookup must return exactly one uploaded HEIC asset",
        ));
    }
    let record = &records[0];
    reject_cloudkit_record_error(record, "records/lookup")?;
    require_record_type(record, "CPLAsset")?;
    let record_name = required_record_string(record, "recordName")?;
    if record_name != request.uploaded_asset_id {
        return Err(UploadError::InvalidCloudKitUploadedHeicResponse(
            "records/lookup returned a different uploaded HEIC asset",
        ));
    }
    let record_change_tag = required_record_string(record, "recordChangeTag")?;
    if record_change_tag.trim().is_empty() {
        return Err(UploadError::InvalidCloudKitUploadedHeicResponse(
            "uploaded HEIC recordChangeTag is empty",
        ));
    }
    let fields = record_fields(record)?;
    if field_value(fields, "isDeleted").is_some_and(cloudkit_truthy) {
        return Err(UploadError::InvalidCloudKitUploadedHeicResponse(
            "uploaded HEIC asset is already deleted",
        ));
    }
    let master_record_name = field_value(fields, "masterRef")
        .and_then(master_ref_record_name)
        .ok_or(UploadError::InvalidCloudKitUploadedHeicResponse(
            "uploaded HEIC asset missing masterRef",
        ))?;
    if master_record_name.trim().is_empty() {
        return Err(UploadError::InvalidCloudKitUploadedHeicResponse(
            "uploaded HEIC masterRef is empty",
        ));
    }
    Ok(UploadedHeicAssetLookup {
        record_name: record_name.to_string(),
        record_change_tag: record_change_tag.to_string(),
        master_record_name: master_record_name.to_string(),
    })
}

fn parse_uploaded_heic_master_lookup_response(
    value: Value,
    expected_master_record_name: &str,
    expected_size_bytes: u64,
) -> Result<Url, UploadError> {
    let records = cloudkit_lookup_records(&value)?;
    if records.len() != 1 {
        return Err(UploadError::InvalidCloudKitUploadedHeicResponse(
            "records/lookup must return exactly one uploaded HEIC master",
        ));
    }
    let record = &records[0];
    reject_cloudkit_record_error(record, "records/lookup")?;
    require_record_type(record, "CPLMaster")?;
    let record_name = required_record_string(record, "recordName")?;
    if record_name != expected_master_record_name {
        return Err(UploadError::InvalidCloudKitUploadedHeicResponse(
            "records/lookup returned a different uploaded HEIC master",
        ));
    }
    master_matching_heic_resource_url(record, expected_size_bytes)
}

fn cloudkit_lookup_records(value: &Value) -> Result<&Vec<Value>, UploadError> {
    value.get("records").and_then(Value::as_array).ok_or(
        UploadError::InvalidCloudKitUploadedHeicResponse(
            "records/lookup response must include records",
        ),
    )
}

fn reject_cloudkit_record_error(
    record: &Value,
    operation: &'static str,
) -> Result<(), UploadError> {
    if record.get("serverErrorCode").is_some() {
        return Err(UploadError::InvalidCloudKitUploadedHeicResponse(
            match operation {
                "records/lookup" => "records/lookup returned a record error",
                _ => "CloudKit returned a record error",
            },
        ));
    }
    Ok(())
}

fn require_record_type(record: &Value, expected: &'static str) -> Result<(), UploadError> {
    let record_type = required_record_string(record, "recordType")?;
    if record_type != expected {
        return Err(UploadError::InvalidCloudKitUploadedHeicResponse(
            "CloudKit record has an unexpected recordType",
        ));
    }
    Ok(())
}

fn parse_cloudkit_continuation_marker(value: &Value) -> Result<Option<String>, UploadError> {
    let Some(response) = value.as_object() else {
        return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
            "records/query response must be an object",
        ));
    };
    let Some(marker) = response.get("continuationMarker") else {
        return Ok(None);
    };
    let marker = marker
        .as_str()
        .filter(|value| !value.trim().is_empty())
        .ok_or(UploadError::InvalidCloudKitOriginalAssetResponse(
            "records/query continuationMarker must be a non-empty string",
        ))?;
    Ok(Some(marker.to_string()))
}

fn parse_cloudkit_asset_record(record: &Value) -> Result<CloudKitAssetRecord, UploadError> {
    let record_name = required_record_string(record, "recordName")?;
    let record_change_tag = required_record_string(record, "recordChangeTag")?;
    if record_name.trim().is_empty() || record_change_tag.trim().is_empty() {
        return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
            "CPLAsset identity cannot be empty",
        ));
    }
    let fields = record_fields(record)?;
    let master_record_name = field_value(fields, "masterRef")
        .and_then(master_ref_record_name)
        .ok_or(UploadError::InvalidCloudKitOriginalAssetResponse(
            "CPLAsset missing masterRef",
        ))?;
    if master_record_name.trim().is_empty() {
        return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
            "CPLAsset masterRef cannot be empty",
        ));
    }
    let asset_date_unix_seconds = field_value(fields, "assetDate")
        .and_then(cloudkit_unix_seconds)
        .ok_or(UploadError::InvalidCloudKitOriginalAssetResponse(
            "CPLAsset missing assetDate",
        ))?;
    Ok(CloudKitAssetRecord {
        record_name: record_name.to_string(),
        record_change_tag: record_change_tag.to_string(),
        master_record_name: master_record_name.to_string(),
        asset_date_unix_seconds,
        record: record.clone(),
    })
}

struct RawResourceUrlMatches {
    saw_resource: bool,
    matches: Vec<(u64, Url)>,
}

#[derive(Clone)]
struct OriginalAssetRemoteResource {
    field: String,
    kind: CloudKitOriginalAssetCandidateKind,
    size_bytes: u64,
    download_url: Url,
}

fn record_pair_original_asset_resources(
    asset: &Value,
    master: &Value,
) -> Result<Vec<OriginalAssetRemoteResource>, UploadError> {
    let mut seen = BTreeSet::new();
    let mut resources = Vec::new();
    for record in [asset, master] {
        for resource in record_original_asset_resources(record)? {
            let key = (
                resource.kind as u8,
                resource.size_bytes,
                resource.download_url.as_str().to_string(),
            );
            if seen.insert(key) {
                resources.push(resource);
            }
        }
    }
    Ok(resources)
}

fn record_original_asset_resources(
    record: &Value,
) -> Result<Vec<OriginalAssetRemoteResource>, UploadError> {
    let fields = record_fields(record)?;
    let mut resources = Vec::new();
    for prefix in [
        "resOriginal",
        "resOriginalAlt",
        "resSidecar",
        "resOriginalVidCompl",
    ] {
        let resource_field = format!("{prefix}Res");
        let Some(resource_field_value) = fields.get(&resource_field) else {
            continue;
        };
        let resource = field_value_object(resource_field_value).ok_or(
            UploadError::InvalidCloudKitOriginalAssetResponse(
                "CloudKit original resource field is malformed",
            ),
        )?;
        let size_bytes = resource_size_bytes(resource).ok_or(
            UploadError::InvalidCloudKitOriginalAssetResponse(
                "CloudKit original resource missing size",
            ),
        )?;
        let file_type_key = format!("{prefix}FileType");
        let file_type = field_string(fields, &file_type_key).ok_or(
            UploadError::InvalidCloudKitOriginalAssetResponse(
                "CloudKit original resource missing file type",
            ),
        )?;
        let kind = if resource_type_is_raw(file_type) {
            Some(CloudKitOriginalAssetCandidateKind::Raw)
        } else if resource_type_is_heic(file_type) {
            Some(CloudKitOriginalAssetCandidateKind::Replacement)
        } else {
            None
        };
        let Some(kind) = kind else {
            continue;
        };
        resources.push(OriginalAssetRemoteResource {
            field: resource_field,
            kind,
            size_bytes,
            download_url: resource_download_url(resource)?,
        });
    }
    Ok(resources)
}

fn remote_resource_identity(
    asset_record_name: &str,
    resource: &OriginalAssetRemoteResource,
) -> String {
    format!(
        "{asset_record_name}\u{1f}{}\u{1f}{}\u{1f}{}",
        resource.field, resource.kind as u8, resource.size_bytes
    )
}

fn normalized_inventory_asset_identity(
    asset: &CloudKitAssetRecord,
    master: &Value,
) -> Result<String, UploadError> {
    // Keep this limited to stable record relationships and resource metadata;
    // download URLs and record change tags rotate independently of inventory.
    let master_record_name = required_record_string(master, "recordName")?;
    let mut resources = BTreeSet::new();
    for (record_role, record) in [("asset", &asset.record), ("master", master)] {
        let fields = record_fields(record)?;
        for prefix in [
            "resOriginal",
            "resOriginalAlt",
            "resSidecar",
            "resOriginalVidCompl",
        ] {
            let Some(resource) =
                normalized_inventory_resource_identity(record_role, fields, prefix)?
            else {
                continue;
            };
            resources.insert(resource);
        }
    }
    Ok(format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
        asset.record_name,
        asset.master_record_name,
        asset.asset_date_unix_seconds,
        master_record_name,
        resources.into_iter().collect::<Vec<_>>().join("\u{1e}"),
    ))
}

fn normalized_inventory_resource_identity(
    record_role: &str,
    fields: &serde_json::Map<String, Value>,
    prefix: &str,
) -> Result<Option<String>, UploadError> {
    let resource_field = format!("{prefix}Res");
    let fingerprint_field = format!("{prefix}Fingerprint");
    let resource_field_value = match (fields.get(&resource_field), fields.get(&fingerprint_field)) {
        (None, None) => return Ok(None),
        (Some(resource), Some(_)) => resource,
        (Some(_), None) => {
            return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
                "CloudKit original resource missing fingerprint",
            ));
        }
        (None, Some(_)) => {
            return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
                "CloudKit original fingerprint has no resource",
            ));
        }
    };
    let resource = field_value_object(resource_field_value).ok_or(
        UploadError::InvalidCloudKitOriginalAssetResponse(
            "CloudKit original resource field is malformed",
        ),
    )?;
    let size_bytes =
        resource_size_bytes(resource).ok_or(UploadError::InvalidCloudKitOriginalAssetResponse(
            "CloudKit original resource missing size",
        ))?;
    let file_type_key = format!("{prefix}FileType");
    let file_type = field_string(fields, &file_type_key).ok_or(
        UploadError::InvalidCloudKitOriginalAssetResponse(
            "CloudKit original resource missing file type",
        ),
    )?;
    let fingerprint = field_string(fields, &fingerprint_field)
        .filter(|fingerprint| !fingerprint.trim().is_empty())
        .ok_or(UploadError::InvalidCloudKitOriginalAssetResponse(
            "CloudKit original resource fingerprint is malformed or conflicting",
        ))?;
    Ok(Some(format!(
        "{record_role}\u{1f}{resource_field}\u{1f}{}\u{1f}{size_bytes}\u{1f}{fingerprint}",
        file_type.to_ascii_lowercase(),
    )))
}

fn record_pair_matching_raw_resource_urls(
    asset: &Value,
    master: &Value,
    target_sizes: &BTreeSet<u64>,
) -> Result<Vec<(u64, Url)>, UploadError> {
    let mut saw_resource = false;
    let mut seen = BTreeSet::new();
    let mut matches = Vec::new();
    for record in [asset, master] {
        let record_matches = record_matching_raw_resource_urls(record, target_sizes)?;
        saw_resource |= record_matches.saw_resource;
        for (size_bytes, download_url) in record_matches.matches {
            if seen.insert((size_bytes, download_url.as_str().to_string())) {
                matches.push((size_bytes, download_url));
            }
        }
    }
    if !saw_resource {
        return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
            "CloudKit original record pair missing original resources",
        ));
    }
    Ok(matches)
}

fn record_matching_raw_resource_urls(
    record: &Value,
    target_sizes: &BTreeSet<u64>,
) -> Result<RawResourceUrlMatches, UploadError> {
    let fields = record_fields(record)?;
    let mut saw_resource = false;
    let mut matches = Vec::new();
    for prefix in [
        "resOriginal",
        "resOriginalAlt",
        "resSidecar",
        "resOriginalVidCompl",
    ] {
        let res_key = format!("{prefix}Res");
        let Some(resource_field) = fields.get(&res_key) else {
            continue;
        };
        saw_resource = true;
        let Some(resource) = field_value_object(resource_field) else {
            return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
                "CloudKit original resource field is malformed",
            ));
        };
        let Some(size_bytes) = resource_size_bytes(resource) else {
            return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
                "CloudKit original resource missing size",
            ));
        };
        if !target_sizes.contains(&size_bytes) {
            continue;
        }
        let file_type_key = format!("{prefix}FileType");
        let Some(file_type) = field_string(fields, &file_type_key) else {
            return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
                "CloudKit original resource missing file type",
            ));
        };
        if resource_type_is_raw(file_type) {
            matches.push((size_bytes, resource_download_url(resource)?));
        }
    }
    Ok(RawResourceUrlMatches {
        saw_resource,
        matches,
    })
}

fn master_matching_heic_resource_url(
    master: &Value,
    expected_size_bytes: u64,
) -> Result<Url, UploadError> {
    let fields = record_fields(master)?;
    let mut saw_resource = false;
    let mut matches = Vec::new();
    for prefix in [
        "resOriginal",
        "resOriginalAlt",
        "resSidecar",
        "resOriginalVidCompl",
    ] {
        let res_key = format!("{prefix}Res");
        let Some(resource_field) = fields.get(&res_key) else {
            continue;
        };
        saw_resource = true;
        let Some(resource) = field_value_object(resource_field) else {
            return Err(UploadError::InvalidCloudKitUploadedHeicResponse(
                "CPLMaster HEIC resource field is malformed",
            ));
        };
        let Some(size_bytes) = resource_size_bytes(resource) else {
            return Err(UploadError::InvalidCloudKitUploadedHeicResponse(
                "CPLMaster HEIC resource missing size",
            ));
        };
        if size_bytes != expected_size_bytes {
            continue;
        }
        let file_type_key = format!("{prefix}FileType");
        let Some(file_type) = field_string(fields, &file_type_key) else {
            return Err(UploadError::InvalidCloudKitUploadedHeicResponse(
                "CPLMaster HEIC resource missing file type",
            ));
        };
        if resource_type_is_heic(file_type) {
            matches.push(resource_download_url(resource)?);
        }
    }
    if !saw_resource {
        return Err(UploadError::InvalidCloudKitUploadedHeicResponse(
            "CPLMaster missing HEIC resources",
        ));
    }
    match matches.len() {
        1 => Ok(matches.remove(0)),
        0 => Err(UploadError::InvalidCloudKitUploadedHeicResponse(
            "CPLMaster has no HEIC resource matching the expected size",
        )),
        _ => Err(UploadError::InvalidCloudKitUploadedHeicResponse(
            "CPLMaster has multiple HEIC resources matching the expected size",
        )),
    }
}

fn required_record_string<'a>(
    record: &'a Value,
    key: &'static str,
) -> Result<&'a str, UploadError> {
    record.get(key).and_then(Value::as_str).ok_or(
        UploadError::InvalidCloudKitOriginalAssetResponse(match key {
            "recordName" => "record missing recordName",
            "recordType" => "record missing recordType",
            _ => "record missing recordChangeTag",
        }),
    )
}

fn record_fields(record: &Value) -> Result<&Map<String, Value>, UploadError> {
    record.get("fields").and_then(Value::as_object).ok_or(
        UploadError::InvalidCloudKitOriginalAssetResponse("record missing fields"),
    )
}

fn field_value<'a>(fields: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    fields.get(key).and_then(|field| field.get("value"))
}

fn field_value_object(field: &Value) -> Option<&Map<String, Value>> {
    field.get("value").and_then(Value::as_object)
}

fn field_string<'a>(fields: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    field_value(fields, key).and_then(Value::as_str)
}

fn master_ref_record_name(value: &Value) -> Option<&str> {
    value
        .get("recordName")
        .and_then(Value::as_str)
        .or_else(|| value.as_str())
}

fn cloudkit_truthy(value: &Value) -> bool {
    matches!(value.as_i64(), Some(1)) || matches!(value.as_bool(), Some(true))
}

fn cloudkit_unix_seconds(value: &Value) -> Option<u64> {
    let numeric = value
        .as_i64()
        .map(|value| value as f64)
        .or_else(|| value.as_u64().map(|value| value as f64))
        .or_else(|| value.as_f64())?;
    if !numeric.is_finite() || numeric < 0.0 {
        return None;
    }
    let seconds = if numeric >= 10_000_000_000.0 {
        numeric / 1000.0
    } else {
        numeric
    };
    Some(seconds.round() as u64)
}

fn asset_date_matches(asset_date: u64, source_captured: u64, tolerance: u64) -> bool {
    asset_date.abs_diff(source_captured) <= tolerance
}

fn resource_size_bytes(resource: &Map<String, Value>) -> Option<u64> {
    resource.get("size").and_then(Value::as_u64)
}

fn resource_download_url(resource: &Map<String, Value>) -> Result<Url, UploadError> {
    let raw_url = resource
        .get("downloadURL")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(UploadError::InvalidCloudKitOriginalAssetResponse(
            "CPLMaster resource missing downloadURL",
        ))?;
    let url = Url::parse(raw_url).map_err(|_| {
        UploadError::InvalidCloudKitOriginalAssetResponse(
            "CPLMaster resource downloadURL is invalid",
        )
    })?;
    validate_cloudkit_resource_download_url(&url)?;
    Ok(url)
}

fn resource_type_is_raw(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value == "dng"
        || value.contains("raw")
        || value.contains("digital-negative")
        || value.contains("adobe.raw-image")
}

fn resource_type_is_heic(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value == "heic"
        || value == "heif"
        || value.contains("heic")
        || value.contains("heif")
        || value.contains("hevc")
}

fn validate_single_file_upload_request(
    single_file: &SingleFileUploadRequest,
) -> Result<(), UploadError> {
    if single_file.file_checksum.trim().is_empty() {
        return Err(UploadError::InvalidPhotosUploadResponse(
            "signed upload response missing fileChecksum",
        ));
    }
    if single_file.reference_checksum.trim().is_empty() {
        return Err(UploadError::InvalidPhotosUploadResponse(
            "signed upload response missing referenceChecksum",
        ));
    }
    if single_file.receipt.trim().is_empty() {
        return Err(UploadError::InvalidPhotosUploadResponse(
            "signed upload response missing receipt",
        ));
    }
    Ok(())
}

fn photosupload_service_url(
    session: &UploadSession,
    endpoint: PhotosUploadEndpoint,
) -> Result<Url, UploadError> {
    let mut base = session.photosupload_url.clone();
    {
        let mut path = base.path().trim_end_matches('/').to_string();
        path.push_str("/photosupload/");
        path.push_str(endpoint.as_str());
        base.set_path(&path);
    }
    base.set_query(Some(&format!("dsid={}", session.dsid)));
    Ok(base)
}

fn payload_database_scope(
    payload: &Value,
    session: &CloudKitDeleteSession,
) -> CloudKitDatabaseScope {
    payload
        .get("zoneID")
        .and_then(|zone_id| zone_id.get("zoneName"))
        .and_then(Value::as_str)
        .map(|zone_name| {
            if zone_name.starts_with(SHARED_SYNC_ZONE_PREFIX) {
                CloudKitDatabaseScope::Shared
            } else {
                CloudKitDatabaseScope::Private
            }
        })
        .unwrap_or(session.database_scope)
}

fn cloudkit_records_modify_url(
    session: &CloudKitDeleteSession,
    database_scope: CloudKitDatabaseScope,
) -> Result<Url, UploadError> {
    let mut base = session.ckdatabasews_url.clone();
    base.set_path(&format!(
        "/database/1/com.apple.photos.cloud/production/{}/records/modify",
        database_scope.as_str()
    ));
    {
        let mut query = base.query_pairs_mut();
        query.clear();
        for param in &session.cloudkit_query_params {
            query.append_pair(&param.name, &param.value);
        }
    }
    Ok(base)
}

fn cloudkit_records_query_url(
    session: &CloudKitDeleteSession,
    database_scope: CloudKitDatabaseScope,
) -> Result<Url, UploadError> {
    cloudkit_records_query_url_with_base(session, session.ckdatabasews_url.clone(), database_scope)
}

fn cloudkit_records_query_url_with_base(
    session: &CloudKitDeleteSession,
    mut base: Url,
    database_scope: CloudKitDatabaseScope,
) -> Result<Url, UploadError> {
    base.set_path(&format!(
        "/database/1/com.apple.photos.cloud/production/{}/records/query",
        database_scope.as_str()
    ));
    {
        let mut query = base.query_pairs_mut();
        query.clear();
        for param in &session.cloudkit_query_params {
            query.append_pair(&param.name, &param.value);
        }
    }
    Ok(base)
}

fn cloudkit_records_lookup_url(
    session: &CloudKitDeleteSession,
    database_scope: CloudKitDatabaseScope,
) -> Result<Url, UploadError> {
    let mut base = session.ckdatabasews_url.clone();
    base.set_path(&format!(
        "/database/1/com.apple.photos.cloud/production/{}/records/lookup",
        database_scope.as_str()
    ));
    {
        let mut query = base.query_pairs_mut();
        query.clear();
        for param in &session.cloudkit_query_params {
            query.append_pair(&param.name, &param.value);
        }
    }
    Ok(base)
}

fn validate_signed_upload_url(url: &Url) -> Result<(), UploadError> {
    if url.scheme() != "https" {
        return Err(UploadError::InvalidPhotosUploadResponse(
            "signed upload URL must use https",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(UploadError::InvalidPhotosUploadResponse(
            "signed upload URL must not include credentials",
        ));
    }
    if url.fragment().is_some() {
        return Err(UploadError::InvalidPhotosUploadResponse(
            "signed upload URL must not include a fragment",
        ));
    }
    let host = url
        .host_str()
        .ok_or(UploadError::InvalidPhotosUploadResponse(
            "signed upload URL host is required",
        ))?;
    if !is_allowed_icloud_host(host) {
        return Err(UploadError::InvalidPhotosUploadResponse(
            "signed upload URL host is not an Apple iCloud host",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn validate_loopback_test_endpoint(url: &Url) -> Result<(), UploadError> {
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || url.port().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().trim_end_matches('/').is_empty()
    {
        return Err(UploadError::InvalidSession(
            "test CloudKit endpoint must be an absolute loopback HTTP URL".to_string(),
        ));
    }
    Ok(())
}

fn validate_cloudkit_resource_download_url(url: &Url) -> Result<(), UploadError> {
    #[cfg(test)]
    let loopback_test_url =
        url.scheme() == "http" && url.host_str() == Some("127.0.0.1") && url.port().is_some();
    #[cfg(not(test))]
    let loopback_test_url = false;
    if url.scheme() != "https" && !loopback_test_url {
        return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
            "resource downloadURL must use https",
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
            "resource downloadURL must not include credentials",
        ));
    }
    if url.fragment().is_some() {
        return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
            "resource downloadURL must not include a fragment",
        ));
    }
    let host = url
        .host_str()
        .ok_or(UploadError::InvalidCloudKitOriginalAssetResponse(
            "resource downloadURL host is required",
        ))?;
    if !loopback_test_url && !is_allowed_icloud_host(host) {
        return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
            "resource downloadURL host is not an Apple iCloud host",
        ));
    }
    Ok(())
}

fn cookie_header(session: &UploadSession) -> Result<String, UploadError> {
    cookie_header_for(&session.cookies)
}

fn cloudkit_records_request_headers(
    session: &CloudKitDeleteSession,
) -> Result<reqwest::header::HeaderMap, UploadError> {
    let mut headers = cloudkit_authenticated_headers(session)?;
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        reqwest::header::HeaderValue::from_static("text/plain;charset=UTF-8"),
    );
    headers.insert(
        reqwest::header::ORIGIN,
        reqwest::header::HeaderValue::from_static(CLOUDKIT_ORIGIN),
    );
    headers.insert(
        reqwest::header::REFERER,
        reqwest::header::HeaderValue::from_static(CLOUDKIT_REFERER),
    );
    Ok(headers)
}

fn cloudkit_resource_download_headers(
    session: &CloudKitDeleteSession,
) -> Result<reqwest::header::HeaderMap, UploadError> {
    cloudkit_authenticated_headers(session)
}

fn cloudkit_authenticated_headers(
    session: &CloudKitDeleteSession,
) -> Result<reqwest::header::HeaderMap, UploadError> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static(CLOUDKIT_BROWSER_USER_AGENT),
    );
    headers.insert(
        reqwest::header::COOKIE,
        reqwest::header::HeaderValue::from_str(&cookie_header_for(&session.cookies)?)
            .map_err(|_| UploadError::InvalidSession("cookies cannot form a header".to_string()))?,
    );
    Ok(headers)
}

fn cookie_header_for(cookies: &[UploadCookie]) -> Result<String, UploadError> {
    let value = cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ");
    reqwest::header::HeaderValue::from_str(&value)
        .map_err(|_| UploadError::InvalidSession("cookies cannot form a header".to_string()))?;
    Ok(value)
}

fn read_json_response(
    response: reqwest::blocking::Response,
    operation: &'static str,
) -> Result<Value, UploadError> {
    let body = read_json_response_body(response, operation)?;
    serde_json::from_slice(&body)
        .map_err(|source| UploadError::DecodeUploadResponse { operation, source })
}

fn read_cloudkit_json_response(
    response: reqwest::blocking::Response,
    operation: &'static str,
) -> Result<Value, UploadError> {
    let body = read_json_response_body(response, operation)?;
    parse_cloudkit_json_response(&body, operation)
}

fn read_json_response_body(
    mut response: reqwest::blocking::Response,
    operation: &'static str,
) -> Result<Vec<u8>, UploadError> {
    let status = response.status();
    if !status.is_success() {
        return Err(UploadError::UploadHttpStatus {
            operation,
            status: status.as_u16(),
        });
    }
    let mut limited = response.by_ref().take(MAX_UPLOAD_RESPONSE_BYTES + 1);
    let mut body = Vec::new();
    limited
        .read_to_end(&mut body)
        .map_err(|source| UploadError::ReadUploadResponse { operation, source })?;
    if body.len() as u64 > MAX_UPLOAD_RESPONSE_BYTES {
        return Err(UploadError::UploadResponseTooLarge { operation });
    }
    Ok(body)
}

fn parse_cloudkit_json_response(
    body: &[u8],
    operation: &'static str,
) -> Result<Value, UploadError> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let StrictJsonValue(value) = StrictJsonValue::deserialize(&mut deserializer)
        .map_err(|_| UploadError::MalformedCloudKitResponse { operation })?;
    deserializer
        .end()
        .map_err(|_| UploadError::MalformedCloudKitResponse { operation })?;
    Ok(value)
}

struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonValueVisitor)
    }
}

struct StrictJsonValueVisitor;

impl<'de> Visitor<'de> for StrictJsonValueVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(|value| StrictJsonValue(Value::Number(value)))
            .ok_or_else(|| E::custom("JSON number must be finite"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value.to_string())))
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value.to_string())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictJsonValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let StrictJsonValue(value) = map.next_value()?;
            object.insert(key, value);
        }
        Ok(StrictJsonValue(Value::Object(object)))
    }
}

fn finalize_hash_progress(
    progress: Arc<Mutex<HashProgress>>,
) -> Result<(String, u64), UploadError> {
    let mut progress = progress
        .lock()
        .map_err(|_| UploadError::InvalidPhotosUploadResponse("hash progress lock poisoned"))?;
    let hasher = std::mem::take(&mut progress.hasher);
    Ok((format!("{:x}", hasher.finalize()), progress.bytes))
}

pub fn verify_local_heic(proof: &HeicVerificationProof) -> Result<(), UploadError> {
    let metadata = std::fs::metadata(&proof.heic_path).map_err(|source| UploadError::ReadHeic {
        path: proof.heic_path.clone(),
        source,
    })?;
    if metadata.len() != proof.size_bytes {
        return Err(UploadError::HeicSizeMismatch {
            path: proof.heic_path.clone(),
            expected: proof.size_bytes,
            actual: metadata.len(),
        });
    }

    let actual = hash_file_sha256(&proof.heic_path)?;
    if actual != proof.heic_sha256 {
        return Err(UploadError::HeicHashMismatch {
            path: proof.heic_path.clone(),
            expected: proof.heic_sha256.clone(),
            actual,
        });
    }

    Ok(())
}

pub fn build_upload_proof(
    heic: &HeicVerificationProof,
    upload: &IcloudUploadOutcome,
) -> Result<UploadProof, UploadError> {
    if upload.response.asset_id.trim().is_empty() {
        return Err(UploadError::MissingUploadedAssetId);
    }
    if upload.streamed_size_bytes != heic.size_bytes {
        return Err(UploadError::StreamedHeicSizeMismatch {
            expected: heic.size_bytes,
            actual: upload.streamed_size_bytes,
        });
    }
    if upload.streamed_heic_sha256 != heic.heic_sha256 {
        return Err(UploadError::StreamedHeicHashMismatch {
            expected: heic.heic_sha256.clone(),
            actual: upload.streamed_heic_sha256.clone(),
        });
    }
    verify_local_heic(heic)?;

    Ok(UploadProof {
        uploaded_heic_asset_id: upload.response.asset_id.clone(),
        uploaded_heic_sha256: heic.heic_sha256.clone(),
        database_scope: upload.response.database_scope,
        zone_name: upload.response.zone_name.clone(),
        uploaded_heic_path: Some(heic.heic_path.clone()),
    })
}

#[derive(Debug, Deserialize)]
struct RawUploadSession {
    dsid: Option<String>,
    photosupload_url: Option<String>,
    webservices: Option<RawWebServices>,
    cookies: Option<Vec<RawCookie>>,
    local_time_zone_id: Option<String>,
    time_zone_offset_minutes: Option<i32>,
    #[serde(default)]
    _cookiejar_path: Option<PathBuf>,
}

impl RawUploadSession {
    fn validate(self) -> Result<UploadSession, UploadError> {
        let dsid = validate_dsid(self.dsid)?;
        let photosupload_url = self
            .photosupload_url
            .or_else(|| {
                self.webservices
                    .and_then(|webservices| webservices.photosupload)
                    .and_then(|photosupload| photosupload.url)
            })
            .ok_or_else(|| {
                UploadError::InvalidSession(
                    "photosupload_url or webservices.photosupload.url is required".to_string(),
                )
            })?;
        let photosupload_url = validate_photosupload_url(&photosupload_url)?;
        let local_time_zone_id = match self.local_time_zone_id {
            Some(value) => {
                let value = required_nonempty(Some(value), "local_time_zone_id")?;
                reject_control_chars(&value, "local_time_zone_id")?;
                value
            }
            None => DEFAULT_LOCAL_TIME_ZONE_ID.to_string(),
        };
        let time_zone_offset_minutes = self.time_zone_offset_minutes.unwrap_or(0);
        if !(-1440..=1440).contains(&time_zone_offset_minutes) {
            return Err(UploadError::InvalidSession(
                "time_zone_offset_minutes is outside the valid range".to_string(),
            ));
        }
        let cookies = self
            .cookies
            .ok_or_else(|| UploadError::InvalidSession("cookies are required".to_string()))?;
        if cookies.is_empty() {
            return Err(UploadError::InvalidSession(
                "cookies cannot be empty".to_string(),
            ));
        }
        let cookies: Vec<UploadCookie> = cookies
            .into_iter()
            .map(RawCookie::validate)
            .collect::<Result<_, _>>()?;
        if !cookies
            .iter()
            .any(|cookie| cookie.name == "X-APPLE-WEBAUTH-TOKEN")
        {
            return Err(UploadError::InvalidSession(
                "missing X-APPLE-WEBAUTH-TOKEN cookie".to_string(),
            ));
        }
        Ok(UploadSession {
            dsid,
            photosupload_url,
            cookies,
            local_time_zone_id,
            time_zone_offset_minutes,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawCloudKitDeleteSession {
    dsid: Option<String>,
    ckdatabasews_url: Option<String>,
    webservices: Option<RawWebServices>,
    database_scope: Option<CloudKitDatabaseScope>,
    zone_name: Option<String>,
    zone_id: Option<RawCloudKitZoneId>,
    cloudkit_query_params: Option<Vec<RawCloudKitQueryParam>>,
    cookies: Option<Vec<RawCookie>>,
    #[serde(default)]
    _cookiejar_path: Option<PathBuf>,
}

impl RawCloudKitDeleteSession {
    fn validate(self) -> Result<CloudKitDeleteSession, UploadError> {
        let dsid = validate_dsid(self.dsid)?;
        let ckdatabasews_url = self
            .ckdatabasews_url
            .or_else(|| {
                self.webservices
                    .and_then(|webservices| webservices.ckdatabasews)
                    .and_then(|ckdatabasews| ckdatabasews.url)
            })
            .ok_or_else(|| {
                UploadError::InvalidSession(
                    "ckdatabasews_url or webservices.ckdatabasews.url is required".to_string(),
                )
            })?;
        let ckdatabasews_url = validate_ckdatabasews_url(&ckdatabasews_url)?;
        let cloudkit_query_params =
            validate_cloudkit_query_params(self.cloudkit_query_params, &dsid)?;
        let zone_name = self
            .zone_name
            .or_else(|| self.zone_id.and_then(|zone_id| zone_id.zone_name))
            .unwrap_or_else(primary_sync_zone_name);
        let database_scope = self.database_scope.unwrap_or_else(|| {
            if zone_name.starts_with(SHARED_SYNC_ZONE_PREFIX) {
                CloudKitDatabaseScope::Shared
            } else {
                CloudKitDatabaseScope::Private
            }
        });
        let zone = CloudKitLibraryDestination {
            database_scope,
            zone_name,
        };
        validate_library_destination(&zone)?;
        let cookies = self
            .cookies
            .ok_or_else(|| UploadError::InvalidSession("cookies are required".to_string()))?;
        if cookies.is_empty() {
            return Err(UploadError::InvalidSession(
                "cookies cannot be empty".to_string(),
            ));
        }
        let cookies: Vec<UploadCookie> = cookies
            .into_iter()
            .map(RawCookie::validate)
            .collect::<Result<_, _>>()?;
        if !cookies
            .iter()
            .any(|cookie| cookie.name == "X-APPLE-WEBAUTH-TOKEN")
        {
            return Err(UploadError::InvalidSession(
                "missing X-APPLE-WEBAUTH-TOKEN cookie".to_string(),
            ));
        }
        let session = CloudKitDeleteSession {
            dsid,
            ckdatabasews_url,
            cloudkit_query_params,
            cookies,
            database_scope,
            zone,
        };
        session.validate()?;
        Ok(session)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCloudKitZoneId {
    zone_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawCloudKitQueryParam {
    name: Option<String>,
    value: Option<String>,
}

impl RawCloudKitQueryParam {
    fn validate(self) -> Result<CloudKitQueryParam, UploadError> {
        let name = required_nonempty(self.name, "cloudkit query param name")?;
        let value = required_nonempty(self.value, "cloudkit query param value")?;
        let param = CloudKitQueryParam { name, value };
        validate_cloudkit_query_param(&param)?;
        Ok(param)
    }
}

#[derive(Debug, Deserialize)]
struct RawWebServices {
    photosupload: Option<RawServiceUrl>,
    ckdatabasews: Option<RawServiceUrl>,
}

#[derive(Debug, Deserialize)]
struct RawServiceUrl {
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawCookie {
    name: Option<String>,
    value: Option<String>,
}

impl RawCookie {
    fn validate(self) -> Result<UploadCookie, UploadError> {
        let name = required_nonempty(self.name, "cookie name")?;
        let value = required_nonempty(self.value, "cookie value")?;
        let cookie = UploadCookie { name, value };
        validate_cloudkit_cookie(&cookie)?;
        Ok(cookie)
    }
}

fn validate_photosupload_url(raw_url: &str) -> Result<Url, UploadError> {
    let url = Url::parse(raw_url).map_err(|_| {
        UploadError::InvalidSession("photosupload_url must be an absolute HTTPS URL".to_string())
    })?;
    if url.scheme() != "https" {
        return Err(UploadError::InvalidSession(
            "photosupload_url must use https".to_string(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(UploadError::InvalidSession(
            "photosupload_url must not include credentials".to_string(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(UploadError::InvalidSession(
            "photosupload_url must not include query or fragment".to_string(),
        ));
    }
    let host = url.host_str().ok_or_else(|| {
        UploadError::InvalidSession("photosupload_url host is required".to_string())
    })?;
    if !is_photosupload_service_host(host) {
        return Err(UploadError::InvalidSession(
            "photosupload_url host is not an Apple Photos upload host".to_string(),
        ));
    }
    let path = url.path().trim_end_matches('/');
    if !path.is_empty() {
        return Err(UploadError::InvalidSession(
            "photosupload_url path must be empty or /".to_string(),
        ));
    }
    Ok(url)
}

fn validate_ckdatabasews_url(raw_url: &str) -> Result<Url, UploadError> {
    let url = Url::parse(raw_url).map_err(|_| {
        UploadError::InvalidSession("ckdatabasews_url must be an absolute HTTPS URL".to_string())
    })?;
    if url.scheme() != "https" {
        return Err(UploadError::InvalidSession(
            "ckdatabasews_url must use https".to_string(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(UploadError::InvalidSession(
            "ckdatabasews_url must not include credentials".to_string(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(UploadError::InvalidSession(
            "ckdatabasews_url must not include query or fragment".to_string(),
        ));
    }
    let host = url.host_str().ok_or_else(|| {
        UploadError::InvalidSession("ckdatabasews_url host is required".to_string())
    })?;
    if !is_ckdatabasews_service_host(host) {
        return Err(UploadError::InvalidSession(
            "ckdatabasews_url host is not an Apple CloudKit database host".to_string(),
        ));
    }
    let path = url.path().trim_end_matches('/');
    if !path.is_empty() {
        return Err(UploadError::InvalidSession(
            "ckdatabasews_url path must be empty or /".to_string(),
        ));
    }
    Ok(url)
}

fn is_allowed_icloud_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "icloud.com"
        || host.ends_with(".icloud.com")
        || host == "icloud.com.cn"
        || host.ends_with(".icloud.com.cn")
        || host == "icloud-content.com"
        || host.ends_with(".icloud-content.com")
        || host == "icloud-content.com.cn"
        || host.ends_with(".icloud-content.com.cn")
}

fn is_photosupload_service_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "photosupload.icloud.com"
        || host.ends_with("-photosupload.icloud.com")
        || host == "photosupload.icloud.com.cn"
        || host.ends_with("-photosupload.icloud.com.cn")
}

fn is_ckdatabasews_service_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "ckdatabasews.icloud.com"
        || host.ends_with("-ckdatabasews.icloud.com")
        || host == "ckdatabasews.icloud.com.cn"
        || host.ends_with("-ckdatabasews.icloud.com.cn")
}

fn validate_dsid(value: Option<String>) -> Result<String, UploadError> {
    let dsid = required_nonempty(value, "dsid")?;
    validate_dsid_value(&dsid)?;
    Ok(dsid)
}

fn validate_dsid_value(dsid: &str) -> Result<(), UploadError> {
    if dsid.is_empty() {
        return Err(UploadError::InvalidSession("dsid is required".to_string()));
    }
    reject_control_chars(dsid, "dsid")?;
    if !dsid.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(UploadError::InvalidSession(
            "dsid must contain only ASCII digits".to_string(),
        ));
    }
    Ok(())
}

fn validate_cloudkit_query_params(
    raw_params: Option<Vec<RawCloudKitQueryParam>>,
    dsid: &str,
) -> Result<Vec<CloudKitQueryParam>, UploadError> {
    let raw_params = raw_params.ok_or_else(|| {
        UploadError::InvalidSession("cloudkit_query_params are required".to_string())
    })?;
    let mut params = Vec::with_capacity(raw_params.len());
    for raw_param in raw_params {
        params.push(raw_param.validate()?);
    }
    validate_cloudkit_query_param_values(&params, dsid)?;
    Ok(params)
}

fn validate_cloudkit_query_param_values(
    params: &[CloudKitQueryParam],
    dsid: &str,
) -> Result<(), UploadError> {
    if params.is_empty() {
        return Err(UploadError::InvalidSession(
            "cloudkit_query_params cannot be empty".to_string(),
        ));
    }

    let mut seen = std::collections::BTreeSet::new();
    for param in params {
        validate_cloudkit_query_param(param)?;
        if !REQUIRED_CLOUDKIT_QUERY_PARAM_NAMES.contains(&param.name.as_str()) {
            return Err(UploadError::InvalidSession(
                "cloudkit_query_params contain an unsupported parameter".to_string(),
            ));
        }
        if !seen.insert(param.name.clone()) {
            return Err(UploadError::InvalidSession(
                "cloudkit_query_params contain a duplicate parameter".to_string(),
            ));
        }
    }

    for required in REQUIRED_CLOUDKIT_QUERY_PARAM_NAMES {
        if !seen.contains(required) {
            return Err(UploadError::InvalidSession(format!(
                "cloudkit_query_params missing {required}"
            )));
        }
    }

    let query_dsid = params
        .iter()
        .find(|param| param.name == "dsid")
        .map(|param| param.value.as_str())
        .ok_or_else(|| {
            UploadError::InvalidSession("cloudkit_query_params missing dsid".to_string())
        })?;
    if query_dsid != dsid {
        return Err(UploadError::InvalidSession(
            "cloudkit_query_params dsid must match session dsid".to_string(),
        ));
    }
    for boolean_param in ["remapEnums", "getCurrentSyncToken"] {
        let value = params
            .iter()
            .find(|param| param.name == boolean_param)
            .map(|param| param.value.as_str())
            .ok_or_else(|| {
                UploadError::InvalidSession(format!(
                    "cloudkit_query_params missing {boolean_param}"
                ))
            })?;
        if value != "True" {
            return Err(UploadError::InvalidSession(format!(
                "cloudkit_query_params {boolean_param} must be True"
            )));
        }
    }
    Ok(())
}

fn validate_cloudkit_query_param(param: &CloudKitQueryParam) -> Result<(), UploadError> {
    if param.name.is_empty() || param.value.is_empty() {
        return Err(UploadError::InvalidSession(
            "cloudkit query params cannot be empty".to_string(),
        ));
    }
    reject_control_chars(&param.name, "cloudkit query param name")?;
    reject_control_chars(&param.value, "cloudkit query param value")?;
    if param.name.trim() != param.name || param.value.trim() != param.value {
        return Err(UploadError::InvalidSession(
            "cloudkit query params must not include leading or trailing whitespace".to_string(),
        ));
    }
    if !param.name.bytes().all(is_cloudkit_query_param_name_byte) {
        return Err(UploadError::InvalidSession(
            "cloudkit query param name contains an invalid character".to_string(),
        ));
    }
    if !param.value.bytes().all(is_cloudkit_query_param_value_byte) {
        return Err(UploadError::InvalidSession(
            "cloudkit query param value contains an invalid character".to_string(),
        ));
    }
    Ok(())
}

fn validate_cloudkit_cookies(cookies: &[UploadCookie]) -> Result<(), UploadError> {
    if cookies.is_empty() {
        return Err(UploadError::InvalidSession(
            "cookies cannot be empty".to_string(),
        ));
    }
    for cookie in cookies {
        validate_cloudkit_cookie(cookie)?;
    }
    if !cookies
        .iter()
        .any(|cookie| cookie.name == "X-APPLE-WEBAUTH-TOKEN")
    {
        return Err(UploadError::InvalidSession(
            "missing X-APPLE-WEBAUTH-TOKEN cookie".to_string(),
        ));
    }
    Ok(())
}

fn validate_cloudkit_cookie(cookie: &UploadCookie) -> Result<(), UploadError> {
    if cookie.name.is_empty() || cookie.value.is_empty() {
        return Err(UploadError::InvalidSession(
            "cookies cannot be empty".to_string(),
        ));
    }
    reject_control_chars(&cookie.name, "cookie name")?;
    reject_control_chars(&cookie.value, "cookie value")?;
    if !cookie.name.bytes().all(is_cookie_name_byte) {
        return Err(UploadError::InvalidSession(
            "cookie name contains an invalid character".to_string(),
        ));
    }
    if !cookie.value.bytes().all(is_cookie_value_byte) {
        return Err(UploadError::InvalidSession(
            "cookie value contains an invalid character".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_library_destination(
    destination: &CloudKitLibraryDestination,
) -> Result<(), UploadError> {
    if destination.zone_name.trim().is_empty() {
        return Err(UploadError::InvalidSession(
            "CloudKit zone name cannot be empty".to_string(),
        ));
    }
    reject_control_chars(&destination.zone_name, "CloudKit zone name")?;
    if destination.zone_name.trim() != destination.zone_name {
        return Err(UploadError::InvalidSession(
            "CloudKit zone name must not include leading or trailing whitespace".to_string(),
        ));
    }
    if destination.database_scope == CloudKitDatabaseScope::Shared
        && !destination.zone_name.starts_with(SHARED_SYNC_ZONE_PREFIX)
    {
        return Err(UploadError::InvalidSession(
            "shared CloudKit library zone must start with SharedSync-".to_string(),
        ));
    }
    if destination.database_scope == CloudKitDatabaseScope::Private
        && destination.zone_name.starts_with(SHARED_SYNC_ZONE_PREFIX)
    {
        return Err(UploadError::InvalidSession(
            "SharedSync zones must use the shared CloudKit database scope".to_string(),
        ));
    }
    if destination.database_scope == CloudKitDatabaseScope::Private
        && destination.zone_name != PRIMARY_SYNC_ZONE
    {
        return Err(UploadError::InvalidSession(
            "private CloudKit library zone must be PrimarySync".to_string(),
        ));
    }
    Ok(())
}

fn validate_cloudkit_delete_request(request: &CloudKitDeleteRequest) -> Result<(), UploadError> {
    if request.record_name.trim().is_empty() {
        return Err(UploadError::InvalidCloudKitDeleteRequest(
            "original asset recordName is required",
        ));
    }
    if request.record_change_tag.trim().is_empty() {
        return Err(UploadError::InvalidCloudKitDeleteRequest(
            "original asset recordChangeTag is required",
        ));
    }
    reject_cloudkit_identity_chars(&request.record_name, "original asset recordName")?;
    reject_cloudkit_identity_chars(&request.record_change_tag, "original asset recordChangeTag")?;
    validate_library_destination(&CloudKitLibraryDestination {
        database_scope: request.database_scope,
        zone_name: request.zone_name.clone(),
    })?;
    Ok(())
}

fn validate_cloudkit_delete_batch_request(
    request: &CloudKitDeleteBatchRequest,
) -> Result<(), UploadError> {
    if request.requests.is_empty() {
        return Err(UploadError::InvalidCloudKitDeleteRequest(
            "at least one original asset delete request is required",
        ));
    }
    let mut record_names = BTreeSet::new();
    let first_destination = request.requests.first().map(|delete_request| {
        (
            delete_request.database_scope,
            delete_request.zone_name.as_str(),
        )
    });
    for delete_request in &request.requests {
        validate_cloudkit_delete_request(delete_request)?;
        if !record_names.insert(delete_request.record_name.as_str()) {
            return Err(UploadError::InvalidCloudKitDeleteRequest(
                "batch delete has duplicate original asset recordName",
            ));
        }
        if first_destination
            != Some((
                delete_request.database_scope,
                delete_request.zone_name.as_str(),
            ))
        {
            return Err(UploadError::InvalidCloudKitDeleteRequest(
                "batch delete cannot mix CloudKit library destinations",
            ));
        }
    }
    Ok(())
}

fn validate_uploaded_heic_resolve_request(
    request: &CloudKitUploadedHeicResolveRequest,
) -> Result<(), UploadError> {
    if request.uploaded_asset_id.trim().is_empty() {
        return Err(UploadError::InvalidCloudKitUploadedHeicRequest(
            "uploaded HEIC asset id is required",
        ));
    }
    if request.expected_heic_sha256.trim().is_empty() {
        return Err(UploadError::InvalidCloudKitUploadedHeicRequest(
            "expected HEIC SHA-256 is required",
        ));
    }
    if request.expected_size_bytes == 0 {
        return Err(UploadError::InvalidCloudKitUploadedHeicRequest(
            "expected HEIC size must be positive",
        ));
    }
    reject_cloudkit_identity_chars(&request.uploaded_asset_id, "uploaded HEIC asset id")?;
    validate_library_destination(&CloudKitLibraryDestination {
        database_scope: request.database_scope,
        zone_name: request.zone_name.clone(),
    })?;
    Ok(())
}

fn validate_original_asset_resolve_request(
    request: &CloudKitOriginalAssetResolveRequest,
) -> Result<(), UploadError> {
    validate_original_asset_target_fields(
        request.raw_size_bytes,
        &request.filename,
        &request.matched_raw_sha256,
    )?;
    if request.page_size == 0 {
        return Err(UploadError::InvalidCloudKitOriginalAssetRequest(
            "page size must be positive",
        ));
    }
    if request.max_pages == 0 {
        return Err(UploadError::InvalidCloudKitOriginalAssetRequest(
            "max pages must be positive",
        ));
    }
    Ok(())
}

fn validate_original_asset_batch_resolve_request(
    request: &CloudKitOriginalAssetBatchResolveRequest,
) -> Result<(), UploadError> {
    if request.targets.is_empty() {
        return Err(UploadError::InvalidCloudKitOriginalAssetRequest(
            "batch targets are required",
        ));
    }
    if request.page_size == 0 {
        return Err(UploadError::InvalidCloudKitOriginalAssetRequest(
            "page size must be positive",
        ));
    }
    if request.max_pages == 0 {
        return Err(UploadError::InvalidCloudKitOriginalAssetRequest(
            "max pages must be positive",
        ));
    }
    let mut asset_ids = std::collections::BTreeSet::new();
    for target in &request.targets {
        if target.asset_id.trim().is_empty() {
            return Err(UploadError::InvalidCloudKitOriginalAssetRequest(
                "asset id is required",
            ));
        }
        if !asset_ids.insert(target.asset_id.as_str()) {
            return Err(UploadError::InvalidCloudKitOriginalAssetRequest(
                "duplicate asset id in batch targets",
            ));
        }
        validate_original_asset_target_fields(
            target.raw_size_bytes,
            &target.filename,
            &target.matched_raw_sha256,
        )?;
        if let Some(replacement) = &target.replacement_candidate {
            if replacement.size_bytes == 0 {
                return Err(UploadError::InvalidCloudKitOriginalAssetRequest(
                    "replacement candidate size must be positive",
                ));
            }
            if replacement.sha256.trim().is_empty() {
                return Err(UploadError::InvalidCloudKitOriginalAssetRequest(
                    "replacement candidate SHA-256 is required",
                ));
            }
        }
    }
    Ok(())
}

fn validate_original_asset_target_fields(
    raw_size_bytes: u64,
    filename: &str,
    matched_raw_sha256: &str,
) -> Result<(), UploadError> {
    if raw_size_bytes == 0 {
        return Err(UploadError::InvalidCloudKitOriginalAssetRequest(
            "raw size must be positive",
        ));
    }
    if filename.trim().is_empty() {
        return Err(UploadError::InvalidCloudKitOriginalAssetRequest(
            "filename is required",
        ));
    }
    if matched_raw_sha256.trim().is_empty() {
        return Err(UploadError::InvalidCloudKitOriginalAssetRequest(
            "matched RAW SHA-256 is required",
        ));
    }
    Ok(())
}

fn validate_original_asset_pagination_range(
    request: &CloudKitOriginalAssetResolveRequest,
) -> Result<(), UploadError> {
    original_asset_query_start_rank(request.start_rank, request.page_size, request.max_pages - 1)?;
    Ok(())
}

fn validate_original_asset_batch_pagination_range(
    request: &CloudKitOriginalAssetBatchResolveRequest,
) -> Result<(), UploadError> {
    original_asset_query_start_rank(request.start_rank, request.page_size, request.max_pages - 1)?;
    Ok(())
}

fn reject_cloudkit_identity_chars(value: &str, field: &'static str) -> Result<(), UploadError> {
    if value.chars().any(char::is_control) {
        return Err(UploadError::InvalidCloudKitDeleteRequest(match field {
            "original asset recordName" => "original asset recordName contains control characters",
            _ => "original asset recordChangeTag contains control characters",
        }));
    }
    Ok(())
}

fn required_nonempty(value: Option<String>, field: &str) -> Result<String, UploadError> {
    let value = value.ok_or_else(|| UploadError::InvalidSession(format!("{field} is required")))?;
    if value.trim().is_empty() {
        return Err(UploadError::InvalidSession(format!(
            "{field} cannot be empty"
        )));
    }
    Ok(value)
}

fn reject_control_chars(value: &str, field: &str) -> Result<(), UploadError> {
    if value.chars().any(char::is_control) {
        return Err(UploadError::InvalidSession(format!(
            "{field} contains control characters"
        )));
    }
    Ok(())
}

fn is_cookie_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_cookie_value_byte(byte: u8) -> bool {
    (0x21..=0x7e).contains(&byte) && byte != b';'
}

fn is_cloudkit_query_param_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

fn is_cloudkit_query_param_value_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

fn heic_filename(path: &Path) -> Result<String, UploadError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| UploadError::InvalidFilename {
            path: path.to_path_buf(),
        })?
        .to_str()
        .ok_or_else(|| UploadError::InvalidFilename {
            path: path.to_path_buf(),
        })?;
    if file_name.trim().is_empty() {
        return Err(UploadError::InvalidFilename {
            path: path.to_path_buf(),
        });
    }
    Ok(file_name.to_string())
}

fn validate_candidate_heic(path: &Path) -> Result<(), UploadError> {
    heic_filename(path)?;
    let has_heic_extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("heic"));
    if !has_heic_extension {
        return Err(UploadError::InvalidHeicExtension {
            path: path.to_path_buf(),
        });
    }
    let metadata = std::fs::metadata(path).map_err(|source| UploadError::ReadHeic {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() == 0 {
        return Err(UploadError::EmptyHeic {
            path: path.to_path_buf(),
        });
    }
    File::open(path).map_err(|source| UploadError::ReadHeic {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hashing_file_hashes_exact_streamed_bytes_with_small_reads() {
        let tempdir = tempfile::tempdir().expect("tempdir should be created");
        let heic_path = tempdir.path().join("IMG_0001.heic");
        let bytes: Vec<u8> = (0..(HASH_BUFFER_BYTES + 137))
            .map(|index| (index % 251) as u8)
            .collect();
        std::fs::write(&heic_path, &bytes).expect("HEIC bytes should be written");
        let file = File::open(&heic_path).expect("HEIC file should open");
        let progress = Arc::new(Mutex::new(HashProgress::default()));
        let mut reader = HashingFile::new(file, Arc::clone(&progress));
        let mut streamed = Vec::new();
        let mut small_buffer = [0_u8; 7];

        loop {
            let bytes_read = reader
                .read(&mut small_buffer)
                .expect("stream read should succeed");
            if bytes_read == 0 {
                break;
            }
            streamed.extend_from_slice(&small_buffer[..bytes_read]);
        }

        let (sha256, size_bytes) =
            finalize_hash_progress(progress).expect("hash progress should finalize");
        assert_eq!(streamed, bytes);
        assert_eq!(size_bytes, bytes.len() as u64);
        assert_eq!(sha256, format!("{:x}", Sha256::digest(&bytes)));
    }

    fn valid_delete_session() -> CloudKitDeleteSession {
        CloudKitDeleteSession::from_json(
            &json!({
                "dsid": "123456789",
                "ckdatabasews_url": "https://p140-ckdatabasews.icloud.com:443",
                "cloudkit_query_params": [
                    {"name": "clientBuildNumber", "value": "2522Project44"},
                    {"name": "clientMasteringNumber", "value": "2522B2"},
                    {"name": "clientId", "value": "4f0b58d4-ff9d-4dc5-8f0b-9c4efc4fdb27"},
                    {"name": "dsid", "value": "123456789"},
                    {"name": "remapEnums", "value": "True"},
                    {"name": "getCurrentSyncToken", "value": "True"}
                ],
                "cookies": [
                    {"name": "X-APPLE-WEBAUTH-TOKEN", "value": "web-auth-token"},
                    {"name": "session", "value": "abc123"}
                ]
            })
            .to_string(),
        )
        .expect("session should load")
    }

    #[test]
    fn cloudkit_session_revalidation_rejects_public_field_mutations() {
        let mut session = valid_delete_session();
        session.dsid = "not-a-dsid".to_string();
        assert!(matches!(
            session.validate(),
            Err(UploadError::InvalidSession(_))
        ));

        let mut session = valid_delete_session();
        session.ckdatabasews_url =
            Url::parse("http://127.0.0.1:12345").expect("test URL should parse");
        assert!(matches!(
            session.validate(),
            Err(UploadError::InvalidSession(_))
        ));

        let mut session = valid_delete_session();
        session.cloudkit_query_params[3].value = "different-dsid".to_string();
        assert!(matches!(
            session.validate(),
            Err(UploadError::InvalidSession(_))
        ));

        let mut session = valid_delete_session();
        session.cookies[0].value = "cookie\nsmuggling".to_string();
        assert!(matches!(
            session.validate(),
            Err(UploadError::InvalidSession(_))
        ));

        let mut session = valid_delete_session();
        session.database_scope = CloudKitDatabaseScope::Shared;
        assert!(matches!(
            session.validate(),
            Err(UploadError::InvalidSession(_))
        ));

        let mut session = valid_delete_session();
        session.zone.zone_name = "SharedSync-mismatched-zone".to_string();
        assert!(matches!(
            session.validate(),
            Err(UploadError::InvalidSession(_))
        ));
    }

    #[test]
    fn cloudkit_records_modify_url_uses_pyi_cloud_query_params() {
        let session = valid_delete_session();

        let url = cloudkit_records_modify_url(&session, CloudKitDatabaseScope::Private)
            .expect("URL should build");

        assert_eq!(
            url.as_str(),
            "https://p140-ckdatabasews.icloud.com/database/1/com.apple.photos.cloud/production/private/records/modify?clientBuildNumber=2522Project44&clientMasteringNumber=2522B2&clientId=4f0b58d4-ff9d-4dc5-8f0b-9c4efc4fdb27&dsid=123456789&remapEnums=True&getCurrentSyncToken=True"
        );
        assert!(!url.query().unwrap_or_default().contains("ckWebAuthToken"));
    }

    #[test]
    fn cloudkit_records_query_url_uses_pyi_cloud_query_params() {
        let session = valid_delete_session();

        let url = cloudkit_records_query_url(&session, CloudKitDatabaseScope::Private)
            .expect("URL should build");

        assert_eq!(
            url.as_str(),
            "https://p140-ckdatabasews.icloud.com/database/1/com.apple.photos.cloud/production/private/records/query?clientBuildNumber=2522Project44&clientMasteringNumber=2522B2&clientId=4f0b58d4-ff9d-4dc5-8f0b-9c4efc4fdb27&dsid=123456789&remapEnums=True&getCurrentSyncToken=True"
        );
        assert!(!url.query().unwrap_or_default().contains("ckWebAuthToken"));
    }

    #[test]
    fn cloudkit_records_headers_include_browser_context_without_exposing_token_shortcuts() {
        let session = valid_delete_session();

        let headers = cloudkit_records_request_headers(&session).expect("headers should build");

        assert_eq!(
            headers.get(reqwest::header::CONTENT_TYPE).unwrap(),
            "text/plain;charset=UTF-8"
        );
        assert_eq!(
            headers.get(reqwest::header::ORIGIN).unwrap(),
            "https://www.icloud.com"
        );
        assert_eq!(
            headers.get(reqwest::header::REFERER).unwrap(),
            "https://www.icloud.com/"
        );
        let user_agent = headers
            .get(reqwest::header::USER_AGENT)
            .expect("User-Agent should be present")
            .to_str()
            .expect("User-Agent should be visible");
        assert!(user_agent.contains("Mozilla/5.0"));
        assert!(!user_agent.trim().is_empty());
        assert!(headers.contains_key(reqwest::header::COOKIE));
        assert!(
            !headers
                .iter()
                .filter(|(name, _)| **name != reqwest::header::COOKIE)
                .any(|(_, value)| value
                    .to_str()
                    .unwrap_or_default()
                    .contains("web-auth-token"))
        );
    }
}

fn hash_file_sha256(path: &Path) -> Result<String, UploadError> {
    let mut file = File::open(path).map_err(|source| UploadError::ReadHeic {
        path: path.to_path_buf(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|source| UploadError::ReadHeic {
                path: path.to_path_buf(),
                source,
            })?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[derive(Debug, Error)]
pub enum UploadError {
    #[error("failed to read upload session at {path}: {source}")]
    ReadSession {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to decode upload session JSON: {source}")]
    DecodeSession {
        path: Option<PathBuf>,
        source: serde_json::Error,
    },
    #[error("invalid upload session: {0}")]
    InvalidSession(String),
    #[error(
        "iCloud Photos upload is not enabled: direct uploadimagews POST is not the iCloud Photos upload protocol; CloudKit /assets/upload and /records/modify support must be implemented first"
    )]
    UnsupportedIcloudUploadProtocol,
    #[error("failed to build iCloud upload HTTP client")]
    HttpClient {
        #[source]
        source: reqwest::Error,
    },
    #[error("iCloud upload network request failed during {operation}")]
    Network {
        operation: &'static str,
        #[source]
        source: reqwest::Error,
    },
    #[error("iCloud upload returned HTTP {status} during {operation}")]
    UploadHttpStatus {
        operation: &'static str,
        status: u16,
    },
    #[error("failed to read iCloud upload response during {operation}: {source}")]
    ReadUploadResponse {
        operation: &'static str,
        source: std::io::Error,
    },
    #[error("iCloud upload response during {operation} exceeded the size limit")]
    UploadResponseTooLarge { operation: &'static str },
    #[error("failed to decode iCloud upload response during {operation}: {source}")]
    DecodeUploadResponse {
        operation: &'static str,
        source: serde_json::Error,
    },
    #[error("CloudKit response during {operation} is malformed")]
    MalformedCloudKitResponse { operation: &'static str },
    #[error("invalid iCloud Photos upload response: {0}")]
    InvalidPhotosUploadResponse(&'static str),
    #[error("invalid CloudKit delete request: {0}")]
    InvalidCloudKitDeleteRequest(&'static str),
    #[error("invalid CloudKit delete response: {0}")]
    InvalidCloudKitDeleteResponse(&'static str),
    #[error("invalid CloudKit delete lookup response: {0}")]
    InvalidCloudKitDeleteLookupResponse(&'static str),
    #[error("invalid CloudKit original asset request: {0}")]
    InvalidCloudKitOriginalAssetRequest(&'static str),
    #[error("invalid CloudKit original asset response: {0}")]
    InvalidCloudKitOriginalAssetResponse(&'static str),
    #[error("invalid CloudKit uploaded HEIC request: {0}")]
    InvalidCloudKitUploadedHeicRequest(&'static str),
    #[error("invalid CloudKit uploaded HEIC response: {0}")]
    InvalidCloudKitUploadedHeicResponse(&'static str),
    #[error(
        "CloudKit original asset resolver found {matches} matching candidates; expected exactly one"
    )]
    OriginalAssetResolveNotUnique { matches: usize },
    #[error(
        "CloudKit original asset resolver reached the scan limit with {matches} matching candidates; exact uniqueness is unproven"
    )]
    OriginalAssetResolveIncomplete { matches: usize },
    #[error(
        "CloudKit original asset download size mismatch: expected {expected} bytes, downloaded {actual} bytes"
    )]
    CloudKitOriginalAssetDownloadSizeMismatch { expected: u64, actual: u64 },
    #[error(
        "CloudKit uploaded HEIC download hash mismatch: expected {expected}, downloaded {actual}"
    )]
    CloudKitUploadedHeicDownloadHashMismatch { expected: String, actual: String },
    #[error(
        "signed upload size mismatch: expected {expected} bytes, service reported {actual} bytes"
    )]
    SignedUploadSizeMismatch { expected: u64, actual: u64 },
    #[error("iCloud Photos putAsset rejected the upload with status {status}: {detail}")]
    PhotosPutAssetRejected { status: u16, detail: String },
    #[error("iCloud Photos upload status failed with error code {error_code}")]
    PhotosUploadStatusFailed { error_code: u64 },
    #[error("iCloud Photos upload status did not complete before the poll limit")]
    PhotosUploadStatusTimedOut,
    #[error("iCloud upload did not return a CPLAsset recordName")]
    MissingUploadedAssetId,
    #[error("failed to read verified HEIC at {path}: {source}")]
    ReadHeic {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("verified HEIC is empty at {path}")]
    EmptyHeic { path: PathBuf },
    #[error("verified HEIC filename is missing or is not UTF-8 at {path}")]
    InvalidFilename { path: PathBuf },
    #[error("verified HEIC path must end in .heic: {path}")]
    InvalidHeicExtension { path: PathBuf },
    #[error("HEIC size mismatch at {path}: expected {expected} bytes, got {actual} bytes")]
    HeicSizeMismatch {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
    #[error("HEIC SHA-256 mismatch at {path}")]
    HeicHashMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    #[error("streamed HEIC size mismatch: expected {expected} bytes, uploaded {actual} bytes")]
    StreamedHeicSizeMismatch { expected: u64, actual: u64 },
    #[error("streamed HEIC SHA-256 mismatch")]
    StreamedHeicHashMismatch { expected: String, actual: String },
}

#[cfg(test)]
mod batch_reconciliation_performance_tests {
    use super::*;

    #[test]
    fn cloudkit_records_query_response_rejects_duplicate_fingerprint_object_keys() {
        let error = parse_cloudkit_json_response(
            br#"{
                "records": [{
                    "recordName": "CPLMaster-1",
                    "recordType": "CPLMaster",
                    "fields": {
                        "resOriginalFingerprint": {"value": "fingerprint-first"},
                        "resOriginalFingerprint": {"value": "fingerprint-second"}
                    }
                }]
            }"#,
            "records_query",
        )
        .expect_err("duplicate CloudKit object keys must not reach the resolver as a Value");

        assert!(matches!(
            error,
            UploadError::MalformedCloudKitResponse {
                operation: "records_query"
            }
        ));
    }

    #[test]
    fn cloudkit_records_query_response_accepts_unique_nested_fingerprint_keys() {
        let response = parse_cloudkit_json_response(
            br#"{
                "records": [{
                    "recordName": "CPLMaster-1",
                    "recordType": "CPLMaster",
                    "fields": {
                        "resOriginalFingerprint": {"value": "fingerprint-original"},
                        "resOriginalAltFingerprint": {"value": "fingerprint-alternative"}
                    }
                }]
            }"#,
            "records_query",
        )
        .expect("unique CloudKit response should decode");

        assert_eq!(
            response["records"][0]["fields"]["resOriginalFingerprint"]["value"],
            "fingerprint-original"
        );
    }

    #[test]
    fn dense_timestamp_cohort_indexes_thousands_of_targets_and_records_once() {
        const COUNT: usize = 4_096;
        let targets = (0..COUNT)
            .map(|index| CloudKitOriginalAssetResolveTarget {
                asset_id: format!("asset-{index}"),
                raw_size_bytes: 9,
                source_captured_unix_seconds: 1_800_000_000,
                capture_tolerance_seconds: 2,
                filename: format!("IMG_{index:04}.DNG"),
                matched_raw_sha256: format!("raw-{index}"),
                replacement_candidate: None,
            })
            .collect::<Vec<_>>();
        let index = OriginalAssetTargetIndex::new(&targets);

        assert_eq!(index.cohort_count(), 1);
        assert!((0..COUNT).all(|_| index.cohort_indexes_for_asset_date(1_800_000_000) == [0]));
    }

    #[test]
    fn dense_timestamp_parser_emits_one_resource_candidate_per_remote_record() {
        const COUNT: usize = 2_048;
        let targets = (0..COUNT)
            .map(|index| CloudKitOriginalAssetResolveTarget {
                asset_id: format!("asset-{index}"),
                raw_size_bytes: 9,
                source_captured_unix_seconds: 1_800_000_000,
                capture_tolerance_seconds: 2,
                filename: format!("IMG_{index:04}.DNG"),
                matched_raw_sha256: format!("raw-{index}"),
                replacement_candidate: None,
            })
            .collect::<Vec<_>>();
        let target_index = OriginalAssetTargetIndex::new(&targets);
        let mut records = Vec::with_capacity(COUNT * 2);
        for index in 0..COUNT {
            let master = format!("CPLMaster-{index}");
            records.push(serde_json::json!({
                "recordName": format!("CPLAsset-{index}"),
                "recordType": "CPLAsset",
                "recordChangeTag": format!("tag-{index}"),
                "fields": {
                    "masterRef": {"value": {"recordName": master}},
                    "assetDate": {"value": 1_800_000_000_000_i64}
                }
            }));
            records.push(serde_json::json!({
                "recordName": format!("CPLMaster-{index}"),
                "recordType": "CPLMaster",
                "fields": {
                    "resOriginalRes": {"value": {
                        "size": 9,
                        "downloadURL": format!("https://p140-icloud-content.icloud.com/raw-{index}")
                    }},
                    "resOriginalFileType": {"value": "com.adobe.raw-image"},
                    "resOriginalFingerprint": {"value": format!("fingerprint-{index}")}
                }
            }));
        }

        let page = parse_original_asset_batch_query_response(
            serde_json::json!({"records": records}),
            &target_index,
            &CloudKitLibraryDestination::primary_sync(),
        )
        .expect("dense inventory page should parse");

        assert_eq!(page.matches.len(), COUNT);
        assert_eq!(page.observation_increments.len(), COUNT);
    }
}

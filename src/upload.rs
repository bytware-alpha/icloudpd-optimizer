use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::workflow::{HeicVerificationProof, OriginalAssetProof, UploadProof};

const HASH_BUFFER_BYTES: usize = 64 * 1024;
const MAX_UPLOAD_RESPONSE_BYTES: u64 = 1024 * 1024;
const PRIMARY_SYNC_ZONE: &str = "PrimarySync";
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
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct IcloudUploadResponse {
    pub asset_id: String,
    pub filename: Option<String>,
    pub master_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcloudUploadOutcome {
    pub response: IcloudUploadResponse,
    pub streamed_heic_sha256: String,
    pub streamed_size_bytes: u64,
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
}

impl CloudKitDeleteSession {
    pub fn from_json(json: &str) -> Result<Self, UploadError> {
        let raw: RawCloudKitDeleteSession = serde_json::from_str(json)
            .map_err(|source| UploadError::DecodeSession { path: None, source })?;
        raw.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitQueryParam {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitDeleteRequest {
    pub record_name: String,
    pub record_change_tag: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitDeleteOutcome {
    pub record_name: String,
    pub record_change_tag: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitUploadedHeicResolveRequest {
    pub uploaded_asset_id: String,
    pub expected_heic_sha256: String,
    pub expected_size_bytes: u64,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitOriginalAssetBatchResolveRequest {
    pub targets: Vec<CloudKitOriginalAssetResolveTarget>,
    pub start_rank: u64,
    pub page_size: u64,
    pub max_pages: u64,
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
    validate_candidate_heic(&request.heic_path)?;
    let transport = ReqwestPhotosUploadTransport::new()?;
    PhotosUploadClient::new(transport).upload_heic(&session, &request.heic_path)
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

    fn post_records_query(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError>;

    fn post_records_lookup(
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

    fn post_records_query(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError> {
        (**self).post_records_query(session, payload)
    }

    fn post_records_lookup(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError> {
        (**self).post_records_lookup(session, payload)
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

        let create_response = self.transport.post_service_json(
            session,
            PhotosUploadEndpoint::CreateUploadUrl,
            create_upload_url_payload(heic_size),
        )?;
        let upload_url = parse_create_upload_url_response(create_response)?;
        let (single_file, streamed_heic_sha256, streamed_size_bytes) = self
            .transport
            .post_signed_upload(session, &upload_url, heic_path)?;
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

        let put_response = self.transport.post_service_json(
            session,
            PhotosUploadEndpoint::PutAsset,
            put_asset_payload(
                &filename,
                last_modified_millis,
                session.time_zone_offset_minutes,
                &session.local_time_zone_id,
                &single_file,
            ),
        )?;
        let put_asset = parse_put_asset_response(put_response)?;
        self.poll_until_upload_complete(session, &put_asset.upload_job_id)?;

        Ok(IcloudUploadOutcome {
            response: IcloudUploadResponse {
                asset_id: put_asset.cpl_asset,
                filename: Some(filename),
                master_id: Some(put_asset.cpl_master),
            },
            streamed_heic_sha256,
            streamed_size_bytes,
        })
    }

    fn poll_until_upload_complete(
        &mut self,
        session: &UploadSession,
        upload_job_id: &str,
    ) -> Result<(), UploadError> {
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
                UploadStatusState::Complete => return Ok(()),
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

impl<T: CloudKitDeleteTransport> CloudKitDeleteClient<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

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

    pub fn resolve_uploaded_heic_asset(
        &mut self,
        session: &CloudKitDeleteSession,
        request: &CloudKitUploadedHeicResolveRequest,
    ) -> Result<CloudKitUploadedHeicAsset, UploadError> {
        validate_uploaded_heic_resolve_request(request)?;
        let asset_response = self.transport.post_records_lookup(
            session,
            cloudkit_records_lookup_payload(
                &[request.uploaded_asset_id.as_str()],
                &["masterRef", "isDeleted"],
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
                let payload =
                    cloudkit_original_asset_query_payload(start_rank, request.page_size, None);
                let response = self.transport.post_records_query(session, payload)?;
                parse_original_asset_query_response(response, request)
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
            );
            let response = self.transport.post_records_query(session, payload)?;
            pages_read = pages_read.saturating_add(1);
            next_page = Some(PositionedOriginalAssetQueryPage {
                start_rank: positioned_page.start_rank,
                page: parse_original_asset_query_response(response, request)?,
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
        validate_original_asset_batch_resolve_request(request)?;
        validate_original_asset_batch_pagination_range(request)?;
        let mut matches: BTreeMap<String, Vec<OriginalAssetProof>> = request
            .targets
            .iter()
            .map(|target| (target.asset_id.clone(), Vec::new()))
            .collect();
        let target_index = OriginalAssetTargetIndex::new(&request.targets);
        let target_window = target_index.date_window();
        let mut download_cache: BTreeMap<(String, u64), CloudKitResourceDownload> = BTreeMap::new();
        let mut matched_original_record_names = BTreeSet::new();
        let mut exhausted = false;
        let seek_result = seek_original_asset_query_page(
            request.start_rank,
            request.page_size,
            request.max_pages,
            &target_window,
            |start_rank| {
                let payload =
                    cloudkit_original_asset_query_payload(start_rank, request.page_size, None);
                let response = self.transport.post_records_query(session, payload)?;
                parse_original_asset_batch_query_response(response, &request.targets, &target_index)
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
                let cache_key = (
                    candidate.download_url.as_str().to_string(),
                    candidate.raw_size_bytes,
                );
                let download = if let Some(download) = download_cache.get(&cache_key) {
                    download.clone()
                } else {
                    let download = self.transport.download_resource(
                        session,
                        &candidate.download_url,
                        candidate.raw_size_bytes,
                    )?;
                    if download.size_bytes != candidate.raw_size_bytes {
                        return Err(UploadError::CloudKitOriginalAssetDownloadSizeMismatch {
                            expected: candidate.raw_size_bytes,
                            actual: download.size_bytes,
                        });
                    }
                    download_cache.insert(cache_key, download.clone());
                    download
                };
                if download.sha256 != candidate.matched_raw_sha256 {
                    continue;
                }
                if !matched_original_record_names.insert(candidate.proof.record_name.clone()) {
                    return Err(UploadError::OriginalAssetResolveNotUnique { matches: 2 });
                }
                let target_matches = matches.get_mut(&candidate.asset_id).ok_or(
                    UploadError::InvalidCloudKitOriginalAssetResponse(
                        "records/query matched an unknown batch target",
                    ),
                )?;
                target_matches.push(candidate.proof);
                if target_matches.len() > 1 {
                    return Err(UploadError::OriginalAssetResolveNotUnique {
                        matches: target_matches.len(),
                    });
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
            );
            let response = self.transport.post_records_query(session, payload)?;
            pages_read = pages_read.saturating_add(1);
            next_page = Some(PositionedOriginalAssetQueryPage {
                start_rank: positioned_page.start_rank,
                page: parse_original_asset_batch_query_response(
                    response,
                    &request.targets,
                    &target_index,
                )?,
            });
        }
        let exact_matches = matches.values().map(Vec::len).sum();
        if !exhausted {
            return Err(UploadError::OriginalAssetResolveIncomplete {
                matches: exact_matches,
            });
        }
        let mut proofs = BTreeMap::new();
        for target in &request.targets {
            let mut target_matches = matches.remove(&target.asset_id).ok_or(
                UploadError::InvalidCloudKitOriginalAssetResponse(
                    "records/query missing a batch target",
                ),
            )?;
            match target_matches.len() {
                1 => {
                    proofs.insert(target.asset_id.clone(), target_matches.remove(0));
                }
                count => return Err(UploadError::OriginalAssetResolveNotUnique { matches: count }),
            }
        }
        Ok(proofs)
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
        let reader = HashingFile {
            file,
            progress: Arc::clone(&progress),
        };
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

pub struct ReqwestCloudKitDeleteTransport {
    client: reqwest::blocking::Client,
}

const CLOUDKIT_ORIGIN: &str = "https://www.icloud.com";
const CLOUDKIT_REFERER: &str = "https://www.icloud.com/";
const CLOUDKIT_BROWSER_USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";

impl ReqwestCloudKitDeleteTransport {
    pub fn new() -> Result<Self, UploadError> {
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(|source| UploadError::HttpClient { source })?;
        Ok(Self { client })
    }
}

impl CloudKitDeleteTransport for ReqwestCloudKitDeleteTransport {
    fn post_records_modify(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError> {
        let url = cloudkit_records_modify_url(session)?;
        let response = self
            .client
            .post(url)
            .headers(cloudkit_records_request_headers(session)?)
            .body(payload.to_string())
            .send()
            .map_err(|source| UploadError::Network {
                operation: "records_modify",
                source,
            })?;
        read_json_response(response, "records_modify")
    }

    fn post_records_query(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError> {
        let url = cloudkit_records_query_url(session)?;
        let response = self
            .client
            .post(url)
            .headers(cloudkit_records_request_headers(session)?)
            .body(payload.to_string())
            .send()
            .map_err(|source| UploadError::Network {
                operation: "records_query",
                source,
            })?;
        read_json_response(response, "records_query")
    }

    fn post_records_lookup(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError> {
        let url = cloudkit_records_lookup_url(session)?;
        let response = self
            .client
            .post(url)
            .headers(cloudkit_records_request_headers(session)?)
            .body(payload.to_string())
            .send()
            .map_err(|source| UploadError::Network {
                operation: "records_lookup",
                source,
            })?;
        read_json_response(response, "records_lookup")
    }

    fn download_resource(
        &mut self,
        session: &CloudKitDeleteSession,
        download_url: &Url,
        expected_size_bytes: u64,
    ) -> Result<CloudKitResourceDownload, UploadError> {
        validate_cloudkit_resource_download_url(download_url)?;
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
    upload_job_id: String,
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
}

impl Read for HashingFile {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.file.read(buffer)?;
        if bytes_read > 0 {
            let mut progress = self
                .progress
                .lock()
                .map_err(|_| std::io::Error::other("hash progress lock poisoned"))?;
            progress.hasher.update(&buffer[..bytes_read]);
            progress.bytes += bytes_read as u64;
        }
        Ok(bytes_read)
    }
}

fn create_upload_url_payload(size_bytes: u64) -> Value {
    let mut assets = Map::new();
    assets.insert(Uuid::new_v4().to_string(), json!(size_bytes));
    json!({
        "zoneName": PRIMARY_SYNC_ZONE,
        "assets": assets,
    })
}

fn put_asset_payload(
    filename: &str,
    last_modified_millis: u64,
    time_zone_offset_minutes: i32,
    local_time_zone_id: &str,
    single_file: &SingleFileUploadRequest,
) -> Value {
    json!({
        "zoneName": PRIMARY_SYNC_ZONE,
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
        "zoneID": {"zoneName": PRIMARY_SYNC_ZONE}
    })
}

fn cloudkit_records_lookup_payload(record_names: &[&str], desired_keys: &[&str]) -> Value {
    let records: Vec<Value> = record_names
        .iter()
        .map(|record_name| json!({ "recordName": record_name }))
        .collect();
    json!({
        "records": records,
        "desiredKeys": desired_keys,
        "zoneID": {"zoneName": PRIMARY_SYNC_ZONE}
    })
}

fn cloudkit_original_asset_query_payload(
    start_rank: u64,
    page_size: u64,
    continuation_marker: Option<&str>,
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
        "zoneID": {"zoneName": PRIMARY_SYNC_ZONE}
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
    if first_page.page.position_against(target_window) != OriginalAssetPagePosition::TooNew {
        return Ok(OriginalAssetSeekResult {
            page: first_page,
            pages_read,
        });
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
        return Err(UploadError::PhotosPutAssetRejected {
            status: status as u16,
        });
    }
    if item.get("uploadJobId").is_some()
        && item.get("cplMaster").is_some()
        && item.get("cplAsset").is_some()
    {
        let success: PutAssetSuccess = serde_json::from_value(item.clone()).map_err(|source| {
            UploadError::DecodeUploadResponse {
                operation: PhotosUploadEndpoint::PutAsset.as_str(),
                source,
            }
        })?;
        if success.upload_job_id.trim().is_empty() {
            return Err(UploadError::InvalidPhotosUploadResponse(
                "putAsset did not return uploadJobId",
            ));
        }
        if success.cpl_master.trim().is_empty() {
            return Err(UploadError::InvalidPhotosUploadResponse(
                "putAsset did not return cplMaster",
            ));
        }
        if success.cpl_asset.trim().is_empty() {
            return Err(UploadError::MissingUploadedAssetId);
        }
        return Ok(success);
    }
    Err(UploadError::InvalidPhotosUploadResponse(
        "putAsset response was neither success nor error",
    ))
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
    let record = &records[0];
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
    asset_id: String,
    raw_size_bytes: u64,
    matched_raw_sha256: String,
    proof: OriginalAssetProof,
    download_url: Url,
}

struct OriginalAssetTargetIndex {
    target_date_windows: Vec<OriginalAssetTargetDateWindow>,
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

struct OriginalAssetTargetDateWindow {
    start_unix_seconds: u64,
    end_unix_seconds: u64,
    target_index: usize,
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
        let mut target_date_windows = Vec::with_capacity(targets.len());
        for (index, target) in targets.iter().enumerate() {
            target_date_windows.push(OriginalAssetTargetDateWindow {
                start_unix_seconds: target
                    .source_captured_unix_seconds
                    .saturating_sub(target.capture_tolerance_seconds),
                end_unix_seconds: target
                    .source_captured_unix_seconds
                    .saturating_add(target.capture_tolerance_seconds),
                target_index: index,
            });
        }
        target_date_windows.sort_by_key(|window| window.start_unix_seconds);
        Self {
            target_date_windows,
        }
    }

    fn indexes_for_asset_date(&self, asset_date_unix_seconds: u64) -> Vec<usize> {
        let upper_bound = self
            .target_date_windows
            .partition_point(|window| window.start_unix_seconds <= asset_date_unix_seconds);
        self.target_date_windows[..upper_bound]
            .iter()
            .filter(|window| asset_date_unix_seconds <= window.end_unix_seconds)
            .map(|window| window.target_index)
            .collect()
    }

    fn date_window(&self) -> OriginalAssetDateWindow {
        let start_unix_seconds = self
            .target_date_windows
            .iter()
            .map(|window| window.start_unix_seconds)
            .min()
            .unwrap_or(0);
        let end_unix_seconds = self
            .target_date_windows
            .iter()
            .map(|window| window.end_unix_seconds)
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
}

fn parse_original_asset_query_response(
    value: Value,
    request: &CloudKitOriginalAssetResolveRequest,
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
                masters.insert(record_name, record);
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
        if let Some(download_url) =
            master_matching_raw_resource_url(master, request.raw_size_bytes)?
        {
            matches.push(OriginalAssetCandidate {
                proof: OriginalAssetProof {
                    record_name: asset.record_name,
                    record_change_tag: asset.record_change_tag,
                    record_type: "CPLAsset".to_string(),
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
    })
}

fn parse_original_asset_batch_query_response(
    value: Value,
    targets: &[CloudKitOriginalAssetResolveTarget],
    target_index: &OriginalAssetTargetIndex,
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
                masters.insert(record_name, record);
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
        let date_matching_target_indexes =
            target_index.indexes_for_asset_date(asset.asset_date_unix_seconds);
        if date_matching_target_indexes.is_empty() {
            continue;
        }
        let master = masters.get(&asset.master_record_name).ok_or(
            UploadError::InvalidCloudKitOriginalAssetResponse(
                "records/query returned an asset without its master",
            ),
        )?;
        let mut date_matching_target_indexes_by_size: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for target_index in date_matching_target_indexes {
            date_matching_target_indexes_by_size
                .entry(targets[target_index].raw_size_bytes)
                .or_default()
                .push(target_index);
        }
        let date_matching_target_sizes = date_matching_target_indexes_by_size
            .keys()
            .copied()
            .collect();
        for (raw_size_bytes, download_url) in
            master_matching_raw_resource_urls(master, &date_matching_target_sizes)?
        {
            let Some(target_indexes) = date_matching_target_indexes_by_size.get(&raw_size_bytes)
            else {
                continue;
            };
            for target_index in target_indexes {
                let target = &targets[*target_index];
                matches.push(OriginalAssetBatchCandidate {
                    asset_id: target.asset_id.clone(),
                    raw_size_bytes: target.raw_size_bytes,
                    matched_raw_sha256: target.matched_raw_sha256.clone(),
                    proof: OriginalAssetProof {
                        record_name: asset.record_name.clone(),
                        record_change_tag: asset.record_change_tag.clone(),
                        record_type: "CPLAsset".to_string(),
                        filename: target.filename.clone(),
                        size_bytes: target.raw_size_bytes,
                        matched_raw_sha256: target.matched_raw_sha256.clone(),
                    },
                    download_url: download_url.clone(),
                });
            }
        }
    }

    Ok(OriginalAssetQueryPage {
        continuation_marker,
        matches,
        asset_dates,
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
    })
}

fn master_matching_raw_resource_url(
    master: &Value,
    raw_size_bytes: u64,
) -> Result<Option<Url>, UploadError> {
    let fields = record_fields(master)?;
    let mut saw_resource = false;
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
                "CPLMaster resource field is malformed",
            ));
        };
        let Some(size_bytes) = resource_size_bytes(resource) else {
            return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
                "CPLMaster resource missing size",
            ));
        };
        if size_bytes != raw_size_bytes {
            continue;
        }
        let file_type_key = format!("{prefix}FileType");
        let Some(file_type) = field_string(fields, &file_type_key) else {
            return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
                "CPLMaster resource missing file type",
            ));
        };
        if resource_type_is_raw(file_type) {
            return Ok(Some(resource_download_url(resource)?));
        }
    }
    if !saw_resource {
        return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
            "CPLMaster missing original resources",
        ));
    }
    Ok(None)
}

fn master_matching_raw_resource_urls(
    master: &Value,
    target_sizes: &std::collections::BTreeSet<u64>,
) -> Result<Vec<(u64, Url)>, UploadError> {
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
            return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
                "CPLMaster resource field is malformed",
            ));
        };
        let Some(size_bytes) = resource_size_bytes(resource) else {
            return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
                "CPLMaster resource missing size",
            ));
        };
        if !target_sizes.contains(&size_bytes) {
            continue;
        }
        let file_type_key = format!("{prefix}FileType");
        let Some(file_type) = field_string(fields, &file_type_key) else {
            return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
                "CPLMaster resource missing file type",
            ));
        };
        if resource_type_is_raw(file_type) {
            matches.push((size_bytes, resource_download_url(resource)?));
        }
    }
    if !saw_resource {
        return Err(UploadError::InvalidCloudKitOriginalAssetResponse(
            "CPLMaster missing original resources",
        ));
    }
    Ok(matches)
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

fn cloudkit_records_modify_url(session: &CloudKitDeleteSession) -> Result<Url, UploadError> {
    let mut base = session.ckdatabasews_url.clone();
    base.set_path("/database/1/com.apple.photos.cloud/production/private/records/modify");
    {
        let mut query = base.query_pairs_mut();
        query.clear();
        for param in &session.cloudkit_query_params {
            query.append_pair(&param.name, &param.value);
        }
    }
    Ok(base)
}

fn cloudkit_records_query_url(session: &CloudKitDeleteSession) -> Result<Url, UploadError> {
    let mut base = session.ckdatabasews_url.clone();
    base.set_path("/database/1/com.apple.photos.cloud/production/private/records/query");
    {
        let mut query = base.query_pairs_mut();
        query.clear();
        for param in &session.cloudkit_query_params {
            query.append_pair(&param.name, &param.value);
        }
    }
    Ok(base)
}

fn cloudkit_records_lookup_url(session: &CloudKitDeleteSession) -> Result<Url, UploadError> {
    let mut base = session.ckdatabasews_url.clone();
    base.set_path("/database/1/com.apple.photos.cloud/production/private/records/lookup");
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

fn validate_cloudkit_resource_download_url(url: &Url) -> Result<(), UploadError> {
    if url.scheme() != "https" {
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
    if !is_allowed_icloud_host(host) {
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
    mut response: reqwest::blocking::Response,
    operation: &'static str,
) -> Result<Value, UploadError> {
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
    serde_json::from_slice(&body)
        .map_err(|source| UploadError::DecodeUploadResponse { operation, source })
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
        Ok(CloudKitDeleteSession {
            dsid,
            ckdatabasews_url,
            cloudkit_query_params,
            cookies,
        })
    }
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
        reject_control_chars(&name, "cloudkit query param name")?;
        reject_control_chars(&value, "cloudkit query param value")?;
        if name.trim() != name || value.trim() != value {
            return Err(UploadError::InvalidSession(
                "cloudkit query params must not include leading or trailing whitespace".to_string(),
            ));
        }
        if !name.bytes().all(is_cloudkit_query_param_name_byte) {
            return Err(UploadError::InvalidSession(
                "cloudkit query param name contains an invalid character".to_string(),
            ));
        }
        if !value.bytes().all(is_cloudkit_query_param_value_byte) {
            return Err(UploadError::InvalidSession(
                "cloudkit query param value contains an invalid character".to_string(),
            ));
        }
        Ok(CloudKitQueryParam { name, value })
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
        reject_control_chars(&name, "cookie name")?;
        reject_control_chars(&value, "cookie value")?;
        if !name.bytes().all(is_cookie_name_byte) {
            return Err(UploadError::InvalidSession(
                "cookie name contains an invalid character".to_string(),
            ));
        }
        if !value.bytes().all(is_cookie_value_byte) {
            return Err(UploadError::InvalidSession(
                "cookie value contains an invalid character".to_string(),
            ));
        }
        Ok(UploadCookie { name, value })
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
    reject_control_chars(&dsid, "dsid")?;
    if !dsid.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(UploadError::InvalidSession(
            "dsid must contain only ASCII digits".to_string(),
        ));
    }
    Ok(dsid)
}

fn validate_cloudkit_query_params(
    raw_params: Option<Vec<RawCloudKitQueryParam>>,
    dsid: &str,
) -> Result<Vec<CloudKitQueryParam>, UploadError> {
    let raw_params = raw_params.ok_or_else(|| {
        UploadError::InvalidSession("cloudkit_query_params are required".to_string())
    })?;
    if raw_params.is_empty() {
        return Err(UploadError::InvalidSession(
            "cloudkit_query_params cannot be empty".to_string(),
        ));
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut params = Vec::with_capacity(raw_params.len());
    for raw_param in raw_params {
        let param = raw_param.validate()?;
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
        params.push(param);
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

    Ok(params)
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
    fn cloudkit_records_modify_url_uses_pyi_cloud_query_params() {
        let session = valid_delete_session();

        let url = cloudkit_records_modify_url(&session).expect("URL should build");

        assert_eq!(
            url.as_str(),
            "https://p140-ckdatabasews.icloud.com/database/1/com.apple.photos.cloud/production/private/records/modify?clientBuildNumber=2522Project44&clientMasteringNumber=2522B2&clientId=4f0b58d4-ff9d-4dc5-8f0b-9c4efc4fdb27&dsid=123456789&remapEnums=True&getCurrentSyncToken=True"
        );
        assert!(!url.query().unwrap_or_default().contains("ckWebAuthToken"));
    }

    #[test]
    fn cloudkit_records_query_url_uses_pyi_cloud_query_params() {
        let session = valid_delete_session();

        let url = cloudkit_records_query_url(&session).expect("URL should build");

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
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];

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
    #[error("invalid iCloud Photos upload response: {0}")]
    InvalidPhotosUploadResponse(&'static str),
    #[error("invalid CloudKit delete request: {0}")]
    InvalidCloudKitDeleteRequest(&'static str),
    #[error("invalid CloudKit delete response: {0}")]
    InvalidCloudKitDeleteResponse(&'static str),
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
    #[error("iCloud Photos putAsset rejected the upload with status {status}")]
    PhotosPutAssetRejected { status: u16 },
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

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

use crate::workflow::{HeicVerificationProof, UploadProof};

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
}

impl<T: CloudKitDeleteTransport + ?Sized> CloudKitDeleteTransport for &mut T {
    fn post_records_modify(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, UploadError> {
        (**self).post_records_modify(session, payload)
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
        validate_cloudkit_delete_request(request)?;
        let response = self
            .transport
            .post_records_modify(session, cloudkit_delete_payload(request))?;
        parse_cloudkit_delete_response(response, request)
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
            .header(reqwest::header::CONTENT_TYPE, "text/plain;charset=UTF-8")
            .header(
                reqwest::header::COOKIE,
                cookie_header_for(&session.cookies)?,
            )
            .body(payload.to_string())
            .send()
            .map_err(|source| UploadError::Network {
                operation: "records_modify",
                source,
            })?;
        read_json_response(response, "records_modify")
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

fn cookie_header(session: &UploadSession) -> Result<String, UploadError> {
    cookie_header_for(&session.cookies)
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

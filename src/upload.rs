use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::Url;
use reqwest::blocking::{Body, Client};
use reqwest::header::{CONTENT_TYPE, COOKIE, HeaderValue};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::workflow::{HeicVerificationProof, UploadProof};

const HASH_BUFFER_BYTES: usize = 64 * 1024;
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(60);

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
pub struct UploadCookie {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadSession {
    pub dsid: String,
    pub upload_url: Url,
    pub cookies: Vec<UploadCookie>,
}

impl UploadSession {
    pub fn from_json(json: &str) -> Result<Self, UploadError> {
        let raw: RawUploadSession = serde_json::from_str(json)
            .map_err(|source| UploadError::DecodeSession { path: None, source })?;
        raw.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadHttpRequest {
    pub url: String,
    pub cookie_header: String,
    pub body_path: PathBuf,
    pub content_len: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadHttpResponse {
    pub status: u16,
    pub body: String,
}

pub trait UploadTransport {
    fn post(&self, request: UploadHttpRequest) -> Result<UploadHttpResponse, UploadError>;
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

pub fn run_icloud_upload(
    request: &IcloudUploadRequest,
) -> Result<IcloudUploadResponse, UploadError> {
    let session = load_upload_session(&request.session_path)?;
    let transport = ReqwestUploadTransport::new()?;
    upload_with_transport(&session, &request.heic_path, &transport)
}

pub fn upload_with_transport(
    session: &UploadSession,
    heic_path: &Path,
    transport: &dyn UploadTransport,
) -> Result<IcloudUploadResponse, UploadError> {
    let metadata = std::fs::metadata(heic_path).map_err(|source| UploadError::ReadHeic {
        path: heic_path.to_path_buf(),
        source,
    })?;
    if metadata.len() == 0 {
        return Err(UploadError::EmptyHeic {
            path: heic_path.to_path_buf(),
        });
    }
    let filename = heic_filename(heic_path)?;
    let request = UploadHttpRequest {
        url: upload_endpoint(session, &filename)?,
        cookie_header: cookie_header(session),
        body_path: heic_path.to_path_buf(),
        content_len: metadata.len(),
    };
    let response = transport.post(request)?;
    if !(200..300).contains(&response.status) {
        return Err(UploadError::HttpStatus(response.status));
    }
    parse_upload_response(&response.body, filename)
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
    response: &IcloudUploadResponse,
) -> Result<UploadProof, UploadError> {
    if response.asset_id.trim().is_empty() {
        return Err(UploadError::MissingUploadedAssetId);
    }
    verify_local_heic(heic)?;

    Ok(UploadProof {
        uploaded_heic_asset_id: response.asset_id.clone(),
        uploaded_heic_sha256: heic.heic_sha256.clone(),
        uploaded_heic_path: Some(heic.heic_path.clone()),
    })
}

struct ReqwestUploadTransport {
    client: Client,
}

impl ReqwestUploadTransport {
    fn new() -> Result<Self, UploadError> {
        let client = Client::builder()
            .timeout(UPLOAD_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .https_only(true)
            .use_rustls_tls()
            .build()
            .map_err(UploadError::BuildHttpClient)?;
        Ok(Self { client })
    }
}

impl UploadTransport for ReqwestUploadTransport {
    fn post(&self, request: UploadHttpRequest) -> Result<UploadHttpResponse, UploadError> {
        let file = File::open(&request.body_path).map_err(|source| UploadError::ReadHeic {
            path: request.body_path.clone(),
            source,
        })?;
        let mut cookie = HeaderValue::from_str(&request.cookie_header)
            .map_err(|_| UploadError::InvalidSession("cookie header is invalid".to_string()))?;
        cookie.set_sensitive(true);
        let response = self
            .client
            .post(&request.url)
            .header(COOKIE, cookie)
            .header(CONTENT_TYPE, "application/octet-stream")
            .body(Body::sized(file, request.content_len))
            .send()
            .map_err(UploadError::Http)?;
        let status = response.status().as_u16();
        let body = response.text().map_err(UploadError::Http)?;
        Ok(UploadHttpResponse { status, body })
    }
}

#[derive(Debug, Deserialize)]
struct RawUploadSession {
    dsid: Option<String>,
    upload_url: Option<String>,
    webservices: Option<RawWebServices>,
    cookies: Option<Vec<RawCookie>>,
    #[serde(default)]
    _cookiejar_path: Option<PathBuf>,
}

impl RawUploadSession {
    fn validate(self) -> Result<UploadSession, UploadError> {
        let dsid = required_nonempty(self.dsid, "dsid")?;
        reject_control_chars(&dsid, "dsid")?;
        let upload_url = self
            .upload_url
            .or_else(|| {
                self.webservices
                    .and_then(|webservices| webservices.uploadimagews)
                    .and_then(|uploadimagews| uploadimagews.url)
            })
            .ok_or_else(|| UploadError::InvalidSession("upload_url is required".to_string()))?;
        let upload_url = validate_upload_url(&upload_url)?;
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
            upload_url,
            cookies,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawWebServices {
    uploadimagews: Option<RawUploadImageWs>,
}

#[derive(Debug, Deserialize)]
struct RawUploadImageWs {
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
        if name.contains(';') || name.contains('=') {
            return Err(UploadError::InvalidSession(
                "cookie name contains an invalid delimiter".to_string(),
            ));
        }
        if value.contains(';') {
            return Err(UploadError::InvalidSession(
                "cookie value contains an invalid delimiter".to_string(),
            ));
        }
        Ok(UploadCookie { name, value })
    }
}

#[derive(Debug, Deserialize)]
struct UploadApiResponse {
    #[serde(default)]
    records: Vec<UploadRecord>,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct UploadRecord {
    #[serde(default, rename = "recordType", alias = "record_type", alias = "type")]
    record_type: String,
    #[serde(default, rename = "recordName", alias = "record_name")]
    record_name: String,
}

fn validate_upload_url(raw_url: &str) -> Result<Url, UploadError> {
    let url = Url::parse(raw_url).map_err(|_| {
        UploadError::InvalidSession("upload_url must be an absolute HTTPS URL".to_string())
    })?;
    if url.scheme() != "https" {
        return Err(UploadError::InvalidSession(
            "upload_url must use https".to_string(),
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(UploadError::InvalidSession(
            "upload_url must not include credentials".to_string(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(UploadError::InvalidSession(
            "upload_url must not include query or fragment".to_string(),
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| UploadError::InvalidSession("upload_url host is required".to_string()))?;
    if !is_allowed_icloud_host(host) {
        return Err(UploadError::InvalidSession(
            "upload_url host is not an Apple iCloud host".to_string(),
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

fn upload_endpoint(session: &UploadSession, filename: &str) -> Result<String, UploadError> {
    let mut url = session.upload_url.clone();
    let mut path = url.path().trim_end_matches('/').to_string();
    path.push_str("/upload");
    url.set_path(&path);
    url.query_pairs_mut()
        .append_pair("dsid", &session.dsid)
        .append_pair("filename", filename);
    Ok(url.to_string())
}

fn cookie_header(session: &UploadSession) -> String {
    session
        .cookies
        .iter()
        .map(|cookie| format!("{}={}", cookie.name, cookie.value))
        .collect::<Vec<_>>()
        .join("; ")
}

fn parse_upload_response(
    body: &str,
    fallback_filename: String,
) -> Result<IcloudUploadResponse, UploadError> {
    let response: UploadApiResponse =
        serde_json::from_str(body).map_err(|source| UploadError::DecodeUploadJson {
            source,
            body: body.to_string(),
        })?;
    if !response.errors.is_empty() {
        return Err(UploadError::UploadResponseErrors(
            serde_json::to_string(&response.errors).unwrap_or_else(|_| "upload errors".to_string()),
        ));
    }

    let mut asset_id = None;
    let mut master_id = None;
    for record in response.records {
        if record.record_name.trim().is_empty() {
            continue;
        }
        match record.record_type.as_str() {
            "CPLAsset" => asset_id = Some(record.record_name),
            "CPLMaster" => master_id = Some(record.record_name),
            _ => {}
        }
    }

    let asset_id = asset_id.ok_or(UploadError::MissingUploadedAssetId)?;
    if asset_id.trim().is_empty() {
        return Err(UploadError::MissingUploadedAssetId);
    }
    Ok(IcloudUploadResponse {
        asset_id,
        filename: Some(fallback_filename),
        master_id,
    })
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
    #[error("failed to build iCloud upload HTTP client: {0}")]
    BuildHttpClient(reqwest::Error),
    #[error("iCloud upload HTTP request failed: {0}")]
    Http(reqwest::Error),
    #[error("iCloud upload returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("failed to decode iCloud upload response `{body}`: {source}")]
    DecodeUploadJson {
        source: serde_json::Error,
        body: String,
    },
    #[error("iCloud upload response contained errors: {0}")]
    UploadResponseErrors(String),
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
    #[error("HEIC SHA-256 mismatch at {path}: expected {expected}, got {actual}")]
    HeicHashMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
}

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::workflow::{HeicVerificationProof, UploadProof};

const HASH_BUFFER_BYTES: usize = 64 * 1024;

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
) -> Result<IcloudUploadOutcome, UploadError> {
    let _session = load_upload_session(&request.session_path)?;
    validate_candidate_heic(&request.heic_path)?;
    Err(UploadError::UnsupportedIcloudUploadProtocol)
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
        if !dsid.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(UploadError::InvalidSession(
                "dsid must contain only ASCII digits".to_string(),
            ));
        }
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
    let path = url.path().trim_end_matches('/');
    if path.is_empty() {
        if !is_uploadimagews_service_host(host) {
            return Err(UploadError::InvalidSession(
                "root upload_url must use an uploadimagews iCloud host".to_string(),
            ));
        }
    } else if path != "/uploadimagews" {
        return Err(UploadError::InvalidSession(
            "upload_url path must be empty, /, or /uploadimagews".to_string(),
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

fn is_uploadimagews_service_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "uploadimagews.icloud.com"
        || host.ends_with("-uploadimagews.icloud.com")
        || host == "uploadimagews.icloud.com.cn"
        || host.ends_with("-uploadimagews.icloud.com.cn")
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

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::workflow::{HeicVerificationProof, UploadProof};

const HASH_BUFFER_BYTES: usize = 64 * 1024;
const PYICLOUD_UPLOAD_HELPER: &str = include_str!("../scripts/icloud_upload.py");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcloudUploadRequest {
    pub python: PathBuf,
    pub apple_id: String,
    pub heic_path: PathBuf,
    pub album: Option<String>,
    pub cookie_directory: Option<PathBuf>,
    pub accept_terms: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct IcloudUploadResponse {
    pub asset_id: String,
    pub filename: Option<String>,
    pub master_id: Option<String>,
}

pub fn run_icloud_upload(
    request: &IcloudUploadRequest,
) -> Result<IcloudUploadResponse, UploadError> {
    let mut command = Command::new(&request.python);
    command
        .arg("-c")
        .arg(PYICLOUD_UPLOAD_HELPER)
        .arg("--apple-id")
        .arg(&request.apple_id)
        .arg("--file")
        .arg(&request.heic_path);

    if let Some(album) = &request.album {
        command.arg("--album").arg(album);
    }
    if let Some(cookie_directory) = &request.cookie_directory {
        command.arg("--cookie-directory").arg(cookie_directory);
    }
    if request.accept_terms {
        command.arg("--accept-terms");
    }

    let output = command
        .output()
        .map_err(|source| UploadError::SpawnHelper {
            python: request.python.clone(),
            source,
        })?;

    if !output.status.success() {
        return Err(UploadError::HelperFailed {
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    let response: IcloudUploadResponse =
        serde_json::from_slice(&output.stdout).map_err(|source| UploadError::DecodeHelperJson {
            source,
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        })?;
    if response.asset_id.trim().is_empty() {
        return Err(UploadError::MissingUploadedAssetId);
    }

    Ok(response)
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

fn hash_file_sha256(path: &Path) -> Result<String, UploadError> {
    let mut file = std::fs::File::open(path).map_err(|source| UploadError::ReadHeic {
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
    #[error("failed to run iCloud upload helper {python}: {source}")]
    SpawnHelper {
        python: PathBuf,
        source: std::io::Error,
    },
    #[error("iCloud upload helper failed with status {status:?}: {stderr}")]
    HelperFailed { status: Option<i32>, stderr: String },
    #[error("failed to decode iCloud upload helper JSON output `{stdout}`: {source}")]
    DecodeHelperJson {
        source: serde_json::Error,
        stdout: String,
    },
    #[error("iCloud upload helper did not return an uploaded asset id")]
    MissingUploadedAssetId,
    #[error("failed to read verified HEIC at {path}: {source}")]
    ReadHeic {
        path: PathBuf,
        source: std::io::Error,
    },
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

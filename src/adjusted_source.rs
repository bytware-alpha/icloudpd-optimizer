use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use image::ImageDecoder;
use image::codecs::jpeg::JpegDecoder;
use image::metadata::Orientation;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::upload::{
    CloudKitDatabaseScope, CloudKitDeleteSession, CloudKitLibraryDestination,
    validate_cloudkit_resource_download_url,
};
use crate::workflow::OriginalAssetProof;

const ADJUSTED_SOURCE_PROOF_SCHEMA_VERSION: &str = "cloudkit-adjusted-source-v1";
const ADJUSTED_SOURCE_KIND: &str = "cloudkit_adjusted_res_jpeg_full_res";
const ADJUSTED_RESOURCE_FIELD: &str = "resJPEGFullRes";
const MAX_DECODED_JPEG_BYTES: u64 = 256 * 1024 * 1024;
const HASH_BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitAdjustedSourceResolveRequest {
    pub asset_id: String,
    pub original_asset: OriginalAssetProof,
    pub output_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloudKitAdjustedSourceDownload {
    pub size_bytes: u64,
    pub sha256: String,
}

/// Compile-time restricted to CloudKit record lookup and resource download.
///
/// ```compile_fail
/// use icloudpd_optimizer::adjusted_source::CloudKitAdjustedSourceTransport;
/// use icloudpd_optimizer::upload::{CloudKitDeleteTransport, ReqwestCloudKitReadTransport};
///
/// fn requires_delete<T: CloudKitDeleteTransport>(_transport: T) {}
/// requires_delete(ReqwestCloudKitReadTransport::new().unwrap());
/// ```
pub trait CloudKitAdjustedSourceTransport {
    fn post_records_lookup(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, AdjustedSourceError>;

    /// Streams a resource into `temp_path`, which must be created with create-new semantics.
    fn download_resource_to_create_new(
        &mut self,
        session: &CloudKitDeleteSession,
        download_url: &Url,
        expected_size_bytes: u64,
        temp_path: &Path,
    ) -> Result<CloudKitAdjustedSourceDownload, AdjustedSourceError>;
}

impl<T: CloudKitAdjustedSourceTransport + ?Sized> CloudKitAdjustedSourceTransport for &mut T {
    fn post_records_lookup(
        &mut self,
        session: &CloudKitDeleteSession,
        payload: Value,
    ) -> Result<Value, AdjustedSourceError> {
        (**self).post_records_lookup(session, payload)
    }

    fn download_resource_to_create_new(
        &mut self,
        session: &CloudKitDeleteSession,
        download_url: &Url,
        expected_size_bytes: u64,
        temp_path: &Path,
    ) -> Result<CloudKitAdjustedSourceDownload, AdjustedSourceError> {
        (**self).download_resource_to_create_new(
            session,
            download_url,
            expected_size_bytes,
            temp_path,
        )
    }
}

pub struct CloudKitAdjustedSourceResolver<T> {
    transport: T,
}

impl<T> CloudKitAdjustedSourceResolver<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub fn into_inner(self) -> T {
        self.transport
    }
}

impl<T: CloudKitAdjustedSourceTransport> CloudKitAdjustedSourceResolver<T> {
    pub fn resolve(
        &mut self,
        session: &CloudKitDeleteSession,
        request: &CloudKitAdjustedSourceResolveRequest,
    ) -> Result<CloudKitAdjustedSourceProof, AdjustedSourceError> {
        let destination = validate_request(session, request)?;
        let asset = lookup_exact_record(
            &mut self.transport,
            session,
            &request.original_asset.record_name,
            &request.original_asset.record_change_tag,
            "CPLAsset",
            &destination,
            &[
                "masterRef",
                ADJUSTED_RESOURCE_FIELD,
                "resJPEGFullResWidth",
                "resJPEGFullResHeight",
                "resJPEGFullResFileType",
                "resJPEGFullResFingerprint",
            ],
        )?;
        let asset_fields = record_fields(&asset)?;
        let source = match parse_adjusted_resource(&asset, None)? {
            Some(resource) => resource,
            None => {
                let master_record_name = parse_master_ref(asset_fields, &destination)?;
                let master = lookup_exact_record(
                    &mut self.transport,
                    session,
                    &master_record_name,
                    "",
                    "CPLMaster",
                    &destination,
                    &[
                        ADJUSTED_RESOURCE_FIELD,
                        "resJPEGFullResWidth",
                        "resJPEGFullResHeight",
                        "resJPEGFullResFileType",
                        "resJPEGFullResFingerprint",
                    ],
                )?;
                parse_adjusted_resource(&master, Some(master_record_name))?.ok_or(
                    AdjustedSourceError::InvalidResponse(
                        "exact master record omitted resJPEGFullRes",
                    ),
                )?
            }
        };
        let temp_path = unique_temp_path(&request.output_path)?;
        let mut temp = TempCleanup::new(temp_path.clone());
        let download = self.transport.download_resource_to_create_new(
            session,
            &source.download_url,
            source.size_bytes,
            &temp_path,
        )?;
        let temp_identity = inspect_regular_file(&temp_path)?;
        if temp_identity.size_bytes != source.size_bytes || download.size_bytes != source.size_bytes
        {
            return Err(AdjustedSourceError::DownloadedSizeMismatch);
        }
        if !is_sha256(&download.sha256) || temp_identity.sha256 != download.sha256 {
            return Err(AdjustedSourceError::DownloadedHashMismatch);
        }
        sync_file(&temp_path)?;
        verify_jpeg(&temp_path, source.width, source.height)?;

        match inspect_existing_output(&request.output_path)? {
            Some(existing) if existing == temp_identity => {}
            Some(_) => return Err(AdjustedSourceError::ExistingOutputMismatch),
            None => install_without_overwrite(&temp_path, &request.output_path)?,
        }
        sync_file(&request.output_path)?;
        let final_identity = inspect_regular_file(&request.output_path)?;
        if final_identity != temp_identity {
            return Err(AdjustedSourceError::InstalledOutputMismatch);
        }
        verify_jpeg(&request.output_path, source.width, source.height)?;
        temp.remove();

        Ok(CloudKitAdjustedSourceProof {
            schema_version: ADJUSTED_SOURCE_PROOF_SCHEMA_VERSION.to_string(),
            source_kind: ADJUSTED_SOURCE_KIND.to_string(),
            asset_id: request.asset_id.clone(),
            asset_record_name: request.original_asset.record_name.clone(),
            asset_record_change_tag: request.original_asset.record_change_tag.clone(),
            asset_record_type: request.original_asset.record_type.clone(),
            resource_record_name: source.record_name,
            resource_record_change_tag: source.record_change_tag,
            resource_record_type: source.record_type,
            database_scope: destination.database_scope,
            zone_name: destination.zone_name,
            master_record_name: source.master_record_name,
            resource_field: ADJUSTED_RESOURCE_FIELD.to_string(),
            declared_file_type: source.file_type,
            declared_fingerprint: source.fingerprint,
            declared_size_bytes: source.size_bytes,
            width: source.width,
            height: source.height,
            local_path: request.output_path.clone(),
            downloaded_size_bytes: final_identity.size_bytes,
            downloaded_sha256: final_identity.sha256,
            orientation: 1,
            verified_at_unix_seconds: verified_timestamp()?,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudKitAdjustedSourceProof {
    pub schema_version: String,
    pub source_kind: String,
    pub asset_id: String,
    pub asset_record_name: String,
    pub asset_record_change_tag: String,
    pub asset_record_type: String,
    pub resource_record_name: String,
    pub resource_record_change_tag: String,
    pub resource_record_type: String,
    pub database_scope: CloudKitDatabaseScope,
    pub zone_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub master_record_name: Option<String>,
    pub resource_field: String,
    pub declared_file_type: String,
    pub declared_fingerprint: String,
    pub declared_size_bytes: u64,
    pub width: u32,
    pub height: u32,
    pub local_path: PathBuf,
    pub downloaded_size_bytes: u64,
    pub downloaded_sha256: String,
    pub orientation: u8,
    pub verified_at_unix_seconds: u64,
}

#[derive(Debug, Error)]
pub enum AdjustedSourceError {
    #[error("adjusted source request is invalid: {0}")]
    InvalidRequest(&'static str),
    #[error("adjusted source CloudKit response is invalid: {0}")]
    InvalidResponse(&'static str),
    #[error("adjusted source resource URL is invalid")]
    InvalidResourceUrl,
    #[error("adjusted source lookup transport failed")]
    LookupTransport,
    #[error("adjusted source download transport failed")]
    DownloadTransport,
    #[error("adjusted source temporary file is invalid")]
    InvalidTemporaryFile,
    #[error("adjusted source output path is unsafe")]
    UnsafeOutputPath,
    #[error("adjusted source output already exists with different bytes")]
    ExistingOutputMismatch,
    #[error("adjusted source download size did not match the declared resource")]
    DownloadedSizeMismatch,
    #[error("adjusted source download hash did not match the streamed artifact")]
    DownloadedHashMismatch,
    #[error("adjusted source installed output did not match the verified temporary artifact")]
    InstalledOutputMismatch,
    #[error("adjusted source JPEG validation failed")]
    InvalidJpeg,
    #[error("adjusted source filesystem operation failed")]
    Filesystem,
    #[error("adjusted source timestamp is unavailable")]
    Clock,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileIdentity {
    size_bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug)]
struct AdjustedResource {
    record_name: String,
    record_change_tag: String,
    record_type: String,
    master_record_name: Option<String>,
    download_url: Url,
    size_bytes: u64,
    width: u32,
    height: u32,
    file_type: String,
    fingerprint: String,
}

struct TempCleanup {
    path: PathBuf,
    active: bool,
}

impl TempCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path, active: true }
    }

    fn remove(&mut self) {
        if self.active {
            let _ = fs::remove_file(&self.path);
            self.active = false;
        }
    }
}

impl Drop for TempCleanup {
    fn drop(&mut self) {
        self.remove();
    }
}

fn validate_request(
    session: &CloudKitDeleteSession,
    request: &CloudKitAdjustedSourceResolveRequest,
) -> Result<CloudKitLibraryDestination, AdjustedSourceError> {
    if request.asset_id.trim().is_empty() {
        return Err(AdjustedSourceError::InvalidRequest("asset ID is empty"));
    }
    if request.original_asset.record_name.trim().is_empty()
        || request.original_asset.record_change_tag.trim().is_empty()
        || request.original_asset.record_type != "CPLAsset"
        || request.original_asset.zone_name.trim().is_empty()
    {
        return Err(AdjustedSourceError::InvalidRequest(
            "original asset proof identity is invalid",
        ));
    }
    let destination = CloudKitLibraryDestination {
        database_scope: request.original_asset.database_scope,
        zone_name: request.original_asset.zone_name.clone(),
    };
    if session.database_scope != destination.database_scope || session.zone != destination {
        return Err(AdjustedSourceError::InvalidRequest(
            "session destination differs from original asset proof",
        ));
    }
    validate_output_path(&request.output_path)?;
    Ok(destination)
}

fn validate_output_path(path: &Path) -> Result<(), AdjustedSourceError> {
    if path.as_os_str().is_empty()
        || path.extension().and_then(|extension| extension.to_str()) != Some("jpg")
        || path.file_name().is_none()
    {
        return Err(AdjustedSourceError::UnsafeOutputPath);
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| AdjustedSourceError::UnsafeOutputPath)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err(AdjustedSourceError::UnsafeOutputPath);
    }
    Ok(())
}

fn lookup_exact_record<T: CloudKitAdjustedSourceTransport>(
    transport: &mut T,
    session: &CloudKitDeleteSession,
    record_name: &str,
    expected_change_tag: &str,
    expected_type: &'static str,
    destination: &CloudKitLibraryDestination,
    desired_keys: &[&str],
) -> Result<Value, AdjustedSourceError> {
    let payload = json!({
        "records": [{"recordName": record_name}],
        "desiredKeys": desired_keys,
        "zoneID": {"zoneName": destination.zone_name},
    });
    let response = transport
        .post_records_lookup(session, payload)
        .map_err(|_| AdjustedSourceError::LookupTransport)?;
    let records = response.get("records").and_then(Value::as_array).ok_or(
        AdjustedSourceError::InvalidResponse("lookup response omitted records"),
    )?;
    if records.len() != 1 {
        return Err(AdjustedSourceError::InvalidResponse(
            "lookup response did not contain exactly one record",
        ));
    }
    let record = records[0].clone();
    if record.get("serverErrorCode").is_some() || record.get("serverErrorReason").is_some() {
        return Err(AdjustedSourceError::InvalidResponse(
            "lookup response returned a record error",
        ));
    }
    if record_string(&record, "recordName")? != record_name
        || record_string(&record, "recordType")? != expected_type
    {
        return Err(AdjustedSourceError::InvalidResponse(
            "lookup response identity differs from requested record",
        ));
    }
    let change_tag = record_string(&record, "recordChangeTag")?;
    if change_tag.is_empty()
        || (!expected_change_tag.is_empty() && change_tag != expected_change_tag)
    {
        return Err(AdjustedSourceError::InvalidResponse(
            "lookup response change tag differs from the required record",
        ));
    }
    validate_record_destination(&record, destination)?;
    Ok(record)
}

fn validate_record_destination(
    record: &Value,
    destination: &CloudKitLibraryDestination,
) -> Result<(), AdjustedSourceError> {
    let Some(zone) = record.get("zoneID") else {
        return Ok(());
    };
    let zone = zone
        .as_object()
        .ok_or(AdjustedSourceError::InvalidResponse(
            "lookup record zone is malformed",
        ))?;
    if zone.get("zoneName").and_then(Value::as_str) != Some(destination.zone_name.as_str()) {
        return Err(AdjustedSourceError::InvalidResponse(
            "lookup record zone differs from the original asset proof",
        ));
    }
    Ok(())
}

fn parse_adjusted_resource(
    record: &Value,
    master_record_name: Option<String>,
) -> Result<Option<AdjustedResource>, AdjustedSourceError> {
    let fields = record_fields(record)?;
    let resource_field = match fields.get(ADJUSTED_RESOURCE_FIELD) {
        Some(value) => value,
        None => return Ok(None),
    };
    let resource = wrapped_value_object(resource_field, ADJUSTED_RESOURCE_FIELD)?;
    let download_url = resource.get("downloadURL").and_then(Value::as_str).ok_or(
        AdjustedSourceError::InvalidResponse("resJPEGFullRes download URL is malformed"),
    )?;
    let download_url =
        Url::parse(download_url).map_err(|_| AdjustedSourceError::InvalidResourceUrl)?;
    validate_cloudkit_resource_download_url(&download_url)
        .map_err(|_| AdjustedSourceError::InvalidResourceUrl)?;
    let size_bytes = resource
        .get("size")
        .and_then(Value::as_u64)
        .filter(|size| *size > 0)
        .ok_or(AdjustedSourceError::InvalidResponse(
            "resJPEGFullRes size is missing or zero",
        ))?;
    let width = wrapped_positive_u32(fields, "resJPEGFullResWidth")?;
    let height = wrapped_positive_u32(fields, "resJPEGFullResHeight")?;
    let file_type = wrapped_nonempty_string(fields, "resJPEGFullResFileType")?;
    if !matches!(
        file_type.to_ascii_lowercase().as_str(),
        "public.jpeg" | "image/jpeg"
    ) {
        return Err(AdjustedSourceError::InvalidResponse(
            "resJPEGFullRes file type is not JPEG",
        ));
    }
    let fingerprint = wrapped_nonempty_string(fields, "resJPEGFullResFingerprint")?;
    Ok(Some(AdjustedResource {
        record_name: record_string(record, "recordName")?.to_string(),
        record_change_tag: record_string(record, "recordChangeTag")?.to_string(),
        record_type: record_string(record, "recordType")?.to_string(),
        master_record_name,
        download_url,
        size_bytes,
        width,
        height,
        file_type,
        fingerprint,
    }))
}

fn parse_master_ref(
    fields: &Map<String, Value>,
    destination: &CloudKitLibraryDestination,
) -> Result<String, AdjustedSourceError> {
    let master_ref = wrapped_value_object(
        fields
            .get("masterRef")
            .ok_or(AdjustedSourceError::InvalidResponse(
                "asset record omitted masterRef",
            ))?,
        "masterRef",
    )?;
    if let Some(zone) = master_ref.get("zoneID") {
        let zone = zone
            .as_object()
            .ok_or(AdjustedSourceError::InvalidResponse(
                "masterRef zone is malformed",
            ))?;
        if zone.get("zoneName").and_then(Value::as_str) != Some(destination.zone_name.as_str()) {
            return Err(AdjustedSourceError::InvalidResponse(
                "masterRef zone differs from the original asset proof",
            ));
        }
    }
    master_ref
        .get("recordName")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .map(ToString::to_string)
        .ok_or(AdjustedSourceError::InvalidResponse(
            "masterRef record name is malformed",
        ))
}

fn record_fields(record: &Value) -> Result<&Map<String, Value>, AdjustedSourceError> {
    record
        .get("fields")
        .and_then(Value::as_object)
        .ok_or(AdjustedSourceError::InvalidResponse(
            "lookup record fields are malformed",
        ))
}

fn record_string<'a>(record: &'a Value, key: &'static str) -> Result<&'a str, AdjustedSourceError> {
    record
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(AdjustedSourceError::InvalidResponse(
            "lookup record identity is malformed",
        ))
}

fn wrapped_value_object<'a>(
    field: &'a Value,
    _field_name: &'static str,
) -> Result<&'a Map<String, Value>, AdjustedSourceError> {
    field
        .as_object()
        .and_then(|wrapper| wrapper.get("value"))
        .and_then(Value::as_object)
        .ok_or(AdjustedSourceError::InvalidResponse(
            "adjusted resource wrapper is malformed",
        ))
}

fn wrapped_positive_u32(
    fields: &Map<String, Value>,
    name: &'static str,
) -> Result<u32, AdjustedSourceError> {
    fields
        .get(name)
        .and_then(Value::as_object)
        .and_then(|wrapper| wrapper.get("value"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or(AdjustedSourceError::InvalidResponse(
            "adjusted resource dimensions are malformed",
        ))
}

fn wrapped_nonempty_string(
    fields: &Map<String, Value>,
    name: &'static str,
) -> Result<String, AdjustedSourceError> {
    fields
        .get(name)
        .and_then(Value::as_object)
        .and_then(|wrapper| wrapper.get("value"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string)
        .ok_or(AdjustedSourceError::InvalidResponse(
            "adjusted resource metadata is malformed",
        ))
}

fn unique_temp_path(output_path: &Path) -> Result<PathBuf, AdjustedSourceError> {
    let parent = output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file_name = output_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(AdjustedSourceError::UnsafeOutputPath)?;
    Ok(parent.join(format!(".{file_name}.adjusted-{}.tmp", Uuid::new_v4())))
}

fn inspect_existing_output(path: &Path) -> Result<Option<FileIdentity>, AdjustedSourceError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => inspect_metadata(path, metadata).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(AdjustedSourceError::Filesystem),
    }
}

fn inspect_regular_file(path: &Path) -> Result<FileIdentity, AdjustedSourceError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| AdjustedSourceError::Filesystem)?;
    inspect_metadata(path, metadata)
}

fn inspect_metadata(
    path: &Path,
    metadata: fs::Metadata,
) -> Result<FileIdentity, AdjustedSourceError> {
    let kind = metadata.file_type();
    if kind.is_symlink() || kind.is_dir() || !kind.is_file() {
        return Err(AdjustedSourceError::UnsafeOutputPath);
    }
    Ok(FileIdentity {
        size_bytes: metadata.len(),
        sha256: hash_file(path)?,
    })
}

fn hash_file(path: &Path) -> Result<String, AdjustedSourceError> {
    let mut file = File::open(path).map_err(|_| AdjustedSourceError::Filesystem)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; HASH_BUFFER_BYTES];
    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|_| AdjustedSourceError::Filesystem)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sync_file(path: &Path) -> Result<(), AdjustedSourceError> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| AdjustedSourceError::Filesystem)
}

fn verify_jpeg(path: &Path, width: u32, height: u32) -> Result<(), AdjustedSourceError> {
    let file = File::open(path).map_err(|_| AdjustedSourceError::InvalidJpeg)?;
    let mut decoder =
        JpegDecoder::new(BufReader::new(file)).map_err(|_| AdjustedSourceError::InvalidJpeg)?;
    if decoder.dimensions() != (width, height)
        || decoder
            .orientation()
            .map_err(|_| AdjustedSourceError::InvalidJpeg)?
            != Orientation::NoTransforms
    {
        return Err(AdjustedSourceError::InvalidJpeg);
    }
    let decoded_size = decoder.total_bytes();
    if decoded_size > MAX_DECODED_JPEG_BYTES {
        return Err(AdjustedSourceError::InvalidJpeg);
    }
    let decoded_size =
        usize::try_from(decoded_size).map_err(|_| AdjustedSourceError::InvalidJpeg)?;
    let mut decoded = vec![0_u8; decoded_size];
    decoder
        .read_image(&mut decoded)
        .map_err(|_| AdjustedSourceError::InvalidJpeg)
}

fn install_without_overwrite(
    temp_path: &Path,
    output_path: &Path,
) -> Result<(), AdjustedSourceError> {
    install_without_overwrite_with(temp_path, output_path, rename_without_overwrite)
}

fn install_without_overwrite_with<F>(
    temp_path: &Path,
    output_path: &Path,
    rename: F,
) -> Result<(), AdjustedSourceError>
where
    F: FnOnce(&Path, &Path) -> io::Result<()>,
{
    match rename(temp_path, output_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(_) => copy_without_overwrite(temp_path, output_path),
    }
}

fn copy_without_overwrite(temp_path: &Path, output_path: &Path) -> Result<(), AdjustedSourceError> {
    let mut source = File::open(temp_path).map_err(|_| AdjustedSourceError::Filesystem)?;
    let mut destination = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        Err(_) => return Err(AdjustedSourceError::Filesystem),
    };
    let result = (|| {
        io::copy(&mut source, &mut destination).map_err(|_| AdjustedSourceError::Filesystem)?;
        destination
            .sync_all()
            .map_err(|_| AdjustedSourceError::Filesystem)
    })();
    if result.is_err() {
        let _ = fs::remove_file(output_path);
    }
    result
}

#[cfg(target_os = "macos")]
fn rename_without_overwrite(from: &Path, to: &Path) -> io::Result<()> {
    let from = path_cstring(from)?;
    let to = path_cstring(to)?;
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn rename_without_overwrite(from: &Path, to: &Path) -> io::Result<()> {
    let from = path_cstring(from)?;
    let to = path_cstring(to)?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn rename_without_overwrite(_from: &Path, _to: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "rename unsupported",
    ))
}

#[cfg(unix)]
fn path_cstring(path: &Path) -> io::Result<CString> {
    use std::os::unix::ffi::OsStrExt;

    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path has NUL"))
}

#[cfg(not(unix))]
fn path_cstring(_path: &Path) -> io::Result<CString> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "path encoding unsupported",
    ))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn verified_timestamp() -> Result<u64, AdjustedSourceError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| AdjustedSourceError::Clock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_overwrite_install_copies_with_create_new_when_rename_is_unavailable() {
        let directory = tempfile::tempdir().expect("test directory");
        let temp_path = directory.path().join("source.tmp");
        let output_path = directory.path().join("adjusted.jpg");
        fs::write(&temp_path, b"verified JPEG bytes").expect("temporary artifact");

        install_without_overwrite_with(&temp_path, &output_path, |_, _| {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "test rename unavailable",
            ))
        })
        .expect("fallback copy should install without overwrite");

        assert_eq!(
            fs::read(&output_path).expect("output artifact"),
            b"verified JPEG bytes"
        );
        assert!(
            temp_path.exists(),
            "fallback copy must retain the source temp"
        );
    }
}

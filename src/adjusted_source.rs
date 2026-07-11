use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
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
const ADJUSTED_WIDTH_FIELD: &str = "resJPEGFullWidth";
const ADJUSTED_HEIGHT_FIELD: &str = "resJPEGFullHeight";
const ADJUSTED_FILE_TYPE_FIELD: &str = "resJPEGFullFileType";
const ADJUSTED_FINGERPRINT_FIELD: &str = "resJPEGFullFingerprint";
pub const MAX_ADJUSTED_SOURCE_ENCODED_BYTES: u64 = 128 * 1024 * 1024;
const MAX_DECODED_JPEG_BYTES: u64 = 256 * 1024 * 1024;
const MIN_VISUAL_STDEV: f64 = 0.001;
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

    /// Streams a resource into the caller-created, create-new destination-directory temp file.
    fn download_resource_to_create_new(
        &mut self,
        session: &CloudKitDeleteSession,
        download_url: &Url,
        expected_size_bytes: u64,
        temp_file: &mut File,
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
        temp_file: &mut File,
    ) -> Result<CloudKitAdjustedSourceDownload, AdjustedSourceError> {
        (**self).download_resource_to_create_new(
            session,
            download_url,
            expected_size_bytes,
            temp_file,
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

#[cfg(unix)]
impl<T: CloudKitAdjustedSourceTransport> CloudKitAdjustedSourceResolver<T> {
    pub fn resolve(
        &mut self,
        session: &CloudKitDeleteSession,
        request: &CloudKitAdjustedSourceResolveRequest,
    ) -> Result<CloudKitAdjustedSourceProof, AdjustedSourceError> {
        let destination = validate_request(session, request)?;
        let output = AnchoredOutput::open(&request.output_path)?;
        let asset = lookup_exact_record(
            &mut self.transport,
            session,
            &request.original_asset.record_name,
            &request.original_asset.record_change_tag,
            "CPLAsset",
            &destination,
            &[
                "masterRef",
                "isDeleted",
                ADJUSTED_RESOURCE_FIELD,
                ADJUSTED_WIDTH_FIELD,
                ADJUSTED_HEIGHT_FIELD,
                ADJUSTED_FILE_TYPE_FIELD,
                ADJUSTED_FINGERPRINT_FIELD,
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
                        "isDeleted",
                        ADJUSTED_RESOURCE_FIELD,
                        ADJUSTED_WIDTH_FIELD,
                        ADJUSTED_HEIGHT_FIELD,
                        ADJUSTED_FILE_TYPE_FIELD,
                        ADJUSTED_FINGERPRINT_FIELD,
                    ],
                )?;
                parse_adjusted_resource(&master, Some(master_record_name))?.ok_or(
                    AdjustedSourceError::InvalidResponse(
                        "exact master record omitted resJPEGFullRes",
                    ),
                )?
            }
        };
        if source.size_bytes > MAX_ADJUSTED_SOURCE_ENCODED_BYTES {
            return Err(AdjustedSourceError::DeclaredResourceTooLarge);
        }
        let mut temp = output.create_temp()?;
        let download = self.transport.download_resource_to_create_new(
            session,
            &source.download_url,
            source.size_bytes,
            temp.file_mut()?,
        )?;
        temp.sync_and_close()?;
        let temp_artifact = temp.open_regular()?;
        let temp_identity = temp_artifact.identity.clone();
        if temp_identity.size_bytes != source.size_bytes || download.size_bytes != source.size_bytes
        {
            return Err(AdjustedSourceError::DownloadedSizeMismatch);
        }
        if !is_sha256(&download.sha256) || temp_identity.sha256 != download.sha256 {
            return Err(AdjustedSourceError::DownloadedHashMismatch);
        }
        verify_jpeg(&temp_artifact.file, source.width, source.height)?;

        let final_artifact = match output.open_final()? {
            Some(existing) => {
                if !existing.identity.matches_bytes(&temp_identity) {
                    return Err(AdjustedSourceError::ExistingOutputMismatch);
                }
                existing
            }
            None => {
                let result = temp.install_exclusive(&temp_identity)?;
                output.final_after_install(&temp_identity, result)?
            }
        };
        verify_jpeg(&final_artifact.file, source.width, source.height)?;
        final_artifact
            .file
            .sync_all()
            .map_err(|_| AdjustedSourceError::Filesystem)?;
        output.fsync_parent()?;
        output.ensure_final_identity(&final_artifact.identity)?;
        temp.cleanup()?;

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
            downloaded_size_bytes: final_artifact.identity.size_bytes,
            downloaded_sha256: final_artifact.identity.sha256.clone(),
            orientation: 1,
            verified_at_unix_seconds: verified_timestamp()?,
        })
    }
}

#[cfg(not(unix))]
impl<T: CloudKitAdjustedSourceTransport> CloudKitAdjustedSourceResolver<T> {
    pub fn resolve(
        &mut self,
        _session: &CloudKitDeleteSession,
        _request: &CloudKitAdjustedSourceResolveRequest,
    ) -> Result<CloudKitAdjustedSourceProof, AdjustedSourceError> {
        Err(AdjustedSourceError::Filesystem)
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
    #[error("adjusted source declared resource exceeds the encoded JPEG limit")]
    DeclaredResourceTooLarge,
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
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl FileIdentity {
    fn matches_bytes(&self, other: &Self) -> bool {
        self.size_bytes == other.size_bytes && self.sha256 == other.sha256
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StagingDirectoryIdentity {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
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

#[cfg(unix)]
struct AnchoredOutput {
    parent: File,
    final_name: CString,
}

#[cfg(unix)]
struct OpenArtifact {
    file: File,
    identity: FileIdentity,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstallResult {
    Installed,
    AlreadyExists,
}

#[cfg(unix)]
struct AnchoredTemp<'a> {
    output: &'a AnchoredOutput,
    staging_name: CString,
    staging: File,
    staging_identity: StagingDirectoryIdentity,
    file_name: CString,
    file: Option<File>,
    active: bool,
}

#[cfg(unix)]
impl AnchoredOutput {
    fn open(path: &Path) -> Result<Self, AdjustedSourceError> {
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStrExt;

        let file_name = path
            .file_name()
            .filter(|name| !name.is_empty())
            .filter(|_name| path.extension() == Some(std::ffi::OsStr::new("jpg")))
            .ok_or(AdjustedSourceError::UnsafeOutputPath)?;
        let final_name = CString::new(file_name.as_bytes())
            .map_err(|_| AdjustedSourceError::UnsafeOutputPath)?;
        let mut parent = if path.is_absolute() {
            open_directory_at(libc::AT_FDCWD, c"/")?
        } else {
            open_directory_at(libc::AT_FDCWD, c".")?
        };
        let components = path.components().collect::<Vec<_>>();
        let final_position = components
            .iter()
            .rposition(|component| matches!(component, Component::Normal(_)))
            .ok_or(AdjustedSourceError::UnsafeOutputPath)?;
        if final_position != components.len().saturating_sub(1) {
            return Err(AdjustedSourceError::UnsafeOutputPath);
        }
        for component in &components[..final_position] {
            match component {
                Component::RootDir => {
                    if !path.is_absolute() {
                        return Err(AdjustedSourceError::UnsafeOutputPath);
                    }
                }
                Component::Normal(name) => {
                    let name = CString::new(name.as_bytes())
                        .map_err(|_| AdjustedSourceError::UnsafeOutputPath)?;
                    parent = open_directory_at(parent.as_raw_fd(), &name)?;
                }
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                    return Err(AdjustedSourceError::UnsafeOutputPath);
                }
            }
        }
        let metadata = parent
            .metadata()
            .map_err(|_| AdjustedSourceError::Filesystem)?;
        if !metadata.is_dir() {
            return Err(AdjustedSourceError::UnsafeOutputPath);
        }
        Ok(Self { parent, final_name })
    }

    fn create_temp(&self) -> Result<AnchoredTemp<'_>, AdjustedSourceError> {
        use std::os::fd::AsRawFd;

        let prefix = std::str::from_utf8(self.final_name.to_bytes())
            .map_err(|_| AdjustedSourceError::UnsafeOutputPath)?;
        for _ in 0..16 {
            let staging_name =
                CString::new(format!(".{prefix}.adjusted-{}.staging", Uuid::new_v4()))
                    .map_err(|_| AdjustedSourceError::Filesystem)?;
            match create_staging_directory_at(self.parent.as_raw_fd(), &staging_name) {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(libc::EEXIST) => continue,
                Err(_) => return Err(AdjustedSourceError::Filesystem),
            }
            let staging = open_directory_at(self.parent.as_raw_fd(), &staging_name)
                .map_err(|_| AdjustedSourceError::Filesystem)?;
            let staging_identity = inspect_staging_directory(&staging)?;
            let file_name =
                CString::new("source.jpg").map_err(|_| AdjustedSourceError::Filesystem)?;
            match open_temp_at(staging.as_raw_fd(), &file_name) {
                Ok(file) => {
                    return Ok(AnchoredTemp::new(
                        self,
                        staging_name,
                        staging,
                        staging_identity,
                        file_name,
                        file,
                    ));
                }
                Err(_) => {
                    let _ = remove_owned_staging_directory(
                        self,
                        &staging_name,
                        &staging,
                        staging_identity,
                    );
                    return Err(AdjustedSourceError::Filesystem);
                }
            }
        }
        Err(AdjustedSourceError::Filesystem)
    }

    fn open_final(&self) -> Result<Option<OpenArtifact>, AdjustedSourceError> {
        use std::os::fd::AsRawFd;

        open_optional_regular_at(self.parent.as_raw_fd(), &self.final_name)?
            .map(inspect_open_file)
            .transpose()
    }

    fn final_after_install(
        &self,
        expected: &FileIdentity,
        result: InstallResult,
    ) -> Result<OpenArtifact, AdjustedSourceError> {
        let final_artifact = self
            .open_final()?
            .ok_or(AdjustedSourceError::InstalledOutputMismatch)?;
        match result {
            InstallResult::Installed if final_artifact.identity != *expected => {
                Err(AdjustedSourceError::InstalledOutputMismatch)
            }
            InstallResult::AlreadyExists if !final_artifact.identity.matches_bytes(expected) => {
                Err(AdjustedSourceError::ExistingOutputMismatch)
            }
            InstallResult::Installed | InstallResult::AlreadyExists => Ok(final_artifact),
        }
    }

    fn fsync_parent(&self) -> Result<(), AdjustedSourceError> {
        self.parent
            .sync_all()
            .map_err(|_| AdjustedSourceError::Filesystem)
    }

    fn ensure_final_identity(&self, expected: &FileIdentity) -> Result<(), AdjustedSourceError> {
        let current = self
            .open_final()?
            .ok_or(AdjustedSourceError::InstalledOutputMismatch)?;
        if current.identity != *expected {
            return Err(AdjustedSourceError::InstalledOutputMismatch);
        }
        Ok(())
    }
}

#[cfg(unix)]
impl<'a> AnchoredTemp<'a> {
    fn new(
        output: &'a AnchoredOutput,
        staging_name: CString,
        staging: File,
        staging_identity: StagingDirectoryIdentity,
        file_name: CString,
        file: File,
    ) -> Self {
        Self {
            output,
            staging_name,
            staging,
            staging_identity,
            file_name,
            file: Some(file),
            active: true,
        }
    }

    fn file_mut(&mut self) -> Result<&mut File, AdjustedSourceError> {
        self.file
            .as_mut()
            .ok_or(AdjustedSourceError::InvalidTemporaryFile)
    }

    fn open_regular(&self) -> Result<OpenArtifact, AdjustedSourceError> {
        use std::os::fd::AsRawFd;

        self.validate_staging()?;
        inspect_open_file(open_regular_at(self.staging.as_raw_fd(), &self.file_name)?)
    }

    fn sync_and_close(&mut self) -> Result<(), AdjustedSourceError> {
        let file = self
            .file
            .as_ref()
            .ok_or(AdjustedSourceError::InvalidTemporaryFile)?;
        file.sync_all()
            .map_err(|_| AdjustedSourceError::Filesystem)?;
        self.file.take();
        Ok(())
    }

    fn install_exclusive(
        &self,
        expected: &FileIdentity,
    ) -> Result<InstallResult, AdjustedSourceError> {
        use std::os::fd::AsRawFd;

        let current = self.open_regular()?;
        if current.identity != *expected {
            return Err(AdjustedSourceError::InvalidTemporaryFile);
        }
        match rename_without_overwrite_at(
            self.staging.as_raw_fd(),
            &self.file_name,
            self.output.parent.as_raw_fd(),
            &self.output.final_name,
        ) {
            Ok(()) => Ok(InstallResult::Installed),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                Ok(InstallResult::AlreadyExists)
            }
            Err(_) => Err(AdjustedSourceError::Filesystem),
        }
    }

    fn cleanup(&mut self) -> Result<(), AdjustedSourceError> {
        use std::os::fd::AsRawFd;

        if !self.active {
            return Ok(());
        }
        self.file.take();
        self.validate_staging()?;
        let unlink =
            unsafe { libc::unlinkat(self.staging.as_raw_fd(), self.file_name.as_ptr(), 0) };
        if unlink != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            return Err(AdjustedSourceError::Filesystem);
        }
        self.remove_empty_staging_directory()?;
        self.active = false;
        Ok(())
    }

    fn validate_staging(&self) -> Result<(), AdjustedSourceError> {
        if inspect_staging_directory(&self.staging)? != self.staging_identity {
            return Err(AdjustedSourceError::InvalidTemporaryFile);
        }
        Ok(())
    }

    fn remove_empty_staging_directory(&self) -> Result<(), AdjustedSourceError> {
        remove_owned_staging_directory(
            self.output,
            &self.staging_name,
            &self.staging,
            self.staging_identity,
        )
    }
}

#[cfg(unix)]
impl Drop for AnchoredTemp<'_> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(not(unix))]
struct AnchoredOutput;

#[cfg(not(unix))]
impl AnchoredOutput {
    fn open(_path: &Path) -> Result<Self, AdjustedSourceError> {
        Err(AdjustedSourceError::Filesystem)
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
    Ok(destination)
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
    require_non_deleted(&record)?;
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
    let zone = record
        .get("zoneID")
        .ok_or(AdjustedSourceError::InvalidResponse(
            "lookup record omitted zone identity",
        ))?;
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
    let adjusted_fields = [
        ADJUSTED_RESOURCE_FIELD,
        ADJUSTED_WIDTH_FIELD,
        ADJUSTED_HEIGHT_FIELD,
        ADJUSTED_FILE_TYPE_FIELD,
        ADJUSTED_FINGERPRINT_FIELD,
    ];
    let present = adjusted_fields
        .iter()
        .filter(|field| fields.contains_key(**field))
        .count();
    if present == 0 {
        return Ok(None);
    }
    if present != adjusted_fields.len() {
        return Err(AdjustedSourceError::InvalidResponse(
            "adjusted resource fields are partial",
        ));
    }
    let resource = wrapped_value_object(fields, ADJUSTED_RESOURCE_FIELD, "ASSETID")?;
    let download_url = required_nonempty_object_string(resource, "downloadURL")?;
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
    let file_checksum = required_nonempty_object_string(resource, "fileChecksum")?;
    let _reference_checksum = required_nonempty_object_string(resource, "referenceChecksum")?;
    let _wrapping_key = required_nonempty_object_string(resource, "wrappingKey")?;
    let width = wrapped_positive_u32(fields, ADJUSTED_WIDTH_FIELD)?;
    let height = wrapped_positive_u32(fields, ADJUSTED_HEIGHT_FIELD)?;
    let file_type = wrapped_nonempty_string(fields, ADJUSTED_FILE_TYPE_FIELD)?;
    if !matches!(file_type.as_str(), "public.jpeg" | "image/jpeg") {
        return Err(AdjustedSourceError::InvalidResponse(
            "resJPEGFullRes file type is not JPEG",
        ));
    }
    let fingerprint = wrapped_nonempty_string(fields, ADJUSTED_FINGERPRINT_FIELD)?;
    if fingerprint != file_checksum {
        return Err(AdjustedSourceError::InvalidResponse(
            "resJPEGFullRes fingerprint differs from fileChecksum",
        ));
    }
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
    let master_ref = wrapped_value_object(fields, "masterRef", "REFERENCE")?;
    if master_ref.get("action").and_then(Value::as_str) != Some("DELETE_SELF") {
        return Err(AdjustedSourceError::InvalidResponse(
            "masterRef action is not DELETE_SELF",
        ));
    }
    validate_zone_identity(
        master_ref.get("zoneID"),
        destination,
        "masterRef zone differs from the original asset proof",
    )?;
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

fn require_non_deleted(record: &Value) -> Result<(), AdjustedSourceError> {
    let fields = record_fields(record)?;
    let deleted = fields.get("isDeleted").and_then(Value::as_object).ok_or(
        AdjustedSourceError::InvalidResponse("lookup record isDeleted is malformed"),
    )?;
    let is_deleted = match (
        deleted.get("type").and_then(Value::as_str),
        deleted.get("value"),
    ) {
        (Some("INT64"), Some(value)) => value.as_i64() != Some(0),
        (Some("BOOLEAN"), Some(value)) => value.as_bool() != Some(false),
        _ => {
            return Err(AdjustedSourceError::InvalidResponse(
                "lookup record isDeleted is malformed",
            ));
        }
    };
    if is_deleted {
        return Err(AdjustedSourceError::InvalidResponse(
            "lookup record is deleted",
        ));
    }
    Ok(())
}

fn validate_zone_identity(
    zone: Option<&Value>,
    destination: &CloudKitLibraryDestination,
    error: &'static str,
) -> Result<(), AdjustedSourceError> {
    let zone = zone
        .and_then(Value::as_object)
        .ok_or(AdjustedSourceError::InvalidResponse(error))?;
    if zone.get("zoneName").and_then(Value::as_str) != Some(destination.zone_name.as_str()) {
        return Err(AdjustedSourceError::InvalidResponse(error));
    }
    Ok(())
}

fn wrapped_value_object<'a>(
    fields: &'a Map<String, Value>,
    field_name: &'static str,
    expected_type: &'static str,
) -> Result<&'a Map<String, Value>, AdjustedSourceError> {
    fields
        .get(field_name)
        .and_then(Value::as_object)
        .filter(|wrapper| wrapper.get("type").and_then(Value::as_str) == Some(expected_type))
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
        .filter(|wrapper| wrapper.get("type").and_then(Value::as_str) == Some("INT64"))
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
        .filter(|wrapper| wrapper.get("type").and_then(Value::as_str) == Some("STRING"))
        .and_then(|wrapper| wrapper.get("value"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string)
        .ok_or(AdjustedSourceError::InvalidResponse(
            "adjusted resource metadata is malformed",
        ))
}

fn required_nonempty_object_string<'a>(
    object: &'a Map<String, Value>,
    field_name: &'static str,
) -> Result<&'a str, AdjustedSourceError> {
    object
        .get(field_name)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(AdjustedSourceError::InvalidResponse(
            "adjusted resource asset metadata is malformed",
        ))
}

#[cfg(unix)]
fn open_directory_at(dirfd: libc::c_int, name: &CStr) -> Result<File, AdjustedSourceError> {
    use std::os::fd::FromRawFd;

    let fd = unsafe {
        libc::openat(
            dirfd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(AdjustedSourceError::UnsafeOutputPath);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn open_temp_at(dirfd: libc::c_int, name: &CStr) -> io::Result<File> {
    use std::os::fd::FromRawFd;

    let fd = unsafe {
        libc::openat(
            dirfd,
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(unix)]
fn create_staging_directory_at(dirfd: libc::c_int, name: &CStr) -> io::Result<()> {
    let result = unsafe { libc::mkdirat(dirfd, name.as_ptr(), 0o700) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn open_regular_at(dirfd: libc::c_int, name: &CStr) -> Result<File, AdjustedSourceError> {
    open_optional_regular_at(dirfd, name)?.ok_or(AdjustedSourceError::Filesystem)
}

#[cfg(unix)]
fn open_optional_regular_at(
    dirfd: libc::c_int,
    name: &CStr,
) -> Result<Option<File>, AdjustedSourceError> {
    use std::os::fd::FromRawFd;

    let fd = unsafe {
        libc::openat(
            dirfd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENOENT) => Ok(None),
            Some(libc::ELOOP) => Err(AdjustedSourceError::UnsafeOutputPath),
            _ => Err(AdjustedSourceError::Filesystem),
        };
    }
    Ok(Some(unsafe { File::from_raw_fd(fd) }))
}

#[cfg(unix)]
fn inspect_staging_directory(
    directory: &File,
) -> Result<StagingDirectoryIdentity, AdjustedSourceError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = directory
        .metadata()
        .map_err(|_| AdjustedSourceError::Filesystem)?;
    let mode = metadata.mode() & 0o777;
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } || mode != 0o700 {
        return Err(AdjustedSourceError::InvalidTemporaryFile);
    }
    Ok(StagingDirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        owner: metadata.uid(),
        mode,
    })
}

#[cfg(unix)]
fn staging_link_count(directory: &File) -> Result<u64, AdjustedSourceError> {
    use std::os::unix::fs::MetadataExt;

    directory
        .metadata()
        .map(|metadata| metadata.nlink())
        .map_err(|_| AdjustedSourceError::Filesystem)
}

#[cfg(unix)]
fn remove_owned_staging_directory(
    output: &AnchoredOutput,
    staging_name: &CStr,
    staging: &File,
    expected: StagingDirectoryIdentity,
) -> Result<(), AdjustedSourceError> {
    use std::os::fd::AsRawFd;

    if inspect_staging_directory(staging)? != expected || staging_link_count(staging)? != 2 {
        return Err(AdjustedSourceError::InvalidTemporaryFile);
    }
    let named_staging = open_directory_at(output.parent.as_raw_fd(), staging_name)
        .map_err(|_| AdjustedSourceError::Filesystem)?;
    if inspect_staging_directory(&named_staging)? != expected
        || staging_link_count(&named_staging)? != 2
    {
        return Err(AdjustedSourceError::InvalidTemporaryFile);
    }
    let remove = unsafe {
        libc::unlinkat(
            output.parent.as_raw_fd(),
            staging_name.as_ptr(),
            libc::AT_REMOVEDIR,
        )
    };
    if remove != 0 {
        return Err(AdjustedSourceError::Filesystem);
    }
    output.fsync_parent()
}

#[cfg(unix)]
fn inspect_open_file(file: File) -> Result<OpenArtifact, AdjustedSourceError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file
        .metadata()
        .map_err(|_| AdjustedSourceError::Filesystem)?;
    if !metadata.file_type().is_file() {
        return Err(AdjustedSourceError::UnsafeOutputPath);
    }
    Ok(OpenArtifact {
        identity: FileIdentity {
            size_bytes: metadata.len(),
            sha256: hash_open_file(&file)?,
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        file,
    })
}

fn hash_open_file(file: &File) -> Result<String, AdjustedSourceError> {
    let mut file = file
        .try_clone()
        .map_err(|_| AdjustedSourceError::Filesystem)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| AdjustedSourceError::Filesystem)?;
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

fn verify_jpeg(file: &File, width: u32, height: u32) -> Result<(), AdjustedSourceError> {
    let mut file = file
        .try_clone()
        .map_err(|_| AdjustedSourceError::InvalidJpeg)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| AdjustedSourceError::InvalidJpeg)?;
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
    let channels = decoder.color_type().bytes_per_pixel() as usize;
    let mut decoded = vec![0_u8; decoded_size];
    decoder
        .read_image(&mut decoded)
        .map_err(|_| AdjustedSourceError::InvalidJpeg)?;
    let standard_deviation = rgb_standard_deviation(&decoded, channels)?;
    if standard_deviation < MIN_VISUAL_STDEV {
        return Err(AdjustedSourceError::InvalidJpeg);
    }
    Ok(())
}

fn rgb_standard_deviation(decoded: &[u8], channels: usize) -> Result<f64, AdjustedSourceError> {
    if channels == 0 || decoded.is_empty() || decoded.len() % channels != 0 {
        return Err(AdjustedSourceError::InvalidJpeg);
    }
    let count = decoded.len() as f64;
    let mean = decoded
        .iter()
        .map(|value| f64::from(*value) / 255.0)
        .sum::<f64>()
        / count;
    let variance = decoded
        .iter()
        .map(|value| {
            let delta = f64::from(*value) / 255.0 - mean;
            delta * delta
        })
        .sum::<f64>()
        / count;
    Ok(variance.sqrt())
}

#[cfg(target_os = "macos")]
fn rename_without_overwrite_at(
    from_dirfd: libc::c_int,
    from: &CStr,
    to_dirfd: libc::c_int,
    to: &CStr,
) -> io::Result<()> {
    let result = unsafe {
        libc::renameatx_np(
            from_dirfd,
            from.as_ptr(),
            to_dirfd,
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
fn rename_without_overwrite_at(
    from_dirfd: libc::c_int,
    from: &CStr,
    to_dirfd: libc::c_int,
    to: &CStr,
) -> io::Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            from_dirfd,
            from.as_ptr(),
            to_dirfd,
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
fn rename_without_overwrite_at(
    _from_dirfd: libc::c_int,
    _from: &CStr,
    _to_dirfd: libc::c_int,
    _to: &CStr,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "rename unsupported",
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
    use std::io::Write;

    #[cfg(unix)]
    #[test]
    fn exclusive_rename_never_overwrites_an_existing_destination() {
        let directory = tempfile::tempdir().expect("test directory");
        let output_path = directory
            .path()
            .canonicalize()
            .expect("stable test directory")
            .join("adjusted.jpg");
        let output = AnchoredOutput::open(&output_path).expect("anchored output");
        let mut temp = output.create_temp().expect("create-new temp");
        temp.file_mut()
            .expect("open temp")
            .write_all(b"verified JPEG bytes")
            .expect("write temp");
        temp.sync_and_close().expect("sync temp");
        let expected = temp.open_regular().expect("reopen temp").identity;
        std::fs::write(&output_path, b"existing output").expect("existing destination");

        let result = temp
            .install_exclusive(&expected)
            .expect("occupied destination is a normal race outcome");

        assert!(matches!(result, InstallResult::AlreadyExists));
        assert_eq!(
            std::fs::read(&output_path).expect("existing output bytes"),
            b"existing output"
        );
        temp.cleanup().expect("cleanup staging directory");
    }

    #[cfg(unix)]
    #[test]
    fn already_exists_with_identical_bytes_accepts_the_concurrent_winner() {
        let directory = tempfile::tempdir().expect("test directory");
        let output_path = directory
            .path()
            .canonicalize()
            .expect("stable test directory")
            .join("adjusted.jpg");
        let output = AnchoredOutput::open(&output_path).expect("anchored output");
        let bytes = b"verified JPEG bytes";
        let mut temp = output.create_temp().expect("create-new temp");
        temp.file_mut()
            .expect("open temp")
            .write_all(bytes)
            .expect("write temp");
        temp.sync_and_close().expect("sync temp");
        let expected = temp.open_regular().expect("reopen temp").identity;
        std::fs::write(&output_path, bytes).expect("concurrent winner");

        let result = temp
            .install_exclusive(&expected)
            .expect("occupied destination is a normal race outcome");
        let winner = output
            .final_after_install(&expected, result)
            .expect("identical concurrent winner must be accepted");

        assert!(matches!(result, InstallResult::AlreadyExists));
        assert!(winner.identity.matches_bytes(&expected));
        assert_ne!(
            winner.identity, expected,
            "concurrent winner has another inode"
        );
        temp.cleanup().expect("cleanup staging directory");
    }

    #[cfg(unix)]
    #[test]
    fn already_exists_with_different_bytes_rejects_the_concurrent_winner() {
        let directory = tempfile::tempdir().expect("test directory");
        let output_path = directory
            .path()
            .canonicalize()
            .expect("stable test directory")
            .join("adjusted.jpg");
        let output = AnchoredOutput::open(&output_path).expect("anchored output");
        let mut temp = output.create_temp().expect("create-new temp");
        temp.file_mut()
            .expect("open temp")
            .write_all(b"verified JPEG bytes")
            .expect("write temp");
        temp.sync_and_close().expect("sync temp");
        let expected = temp.open_regular().expect("reopen temp").identity;
        std::fs::write(&output_path, b"different winner").expect("concurrent winner");

        let result = temp
            .install_exclusive(&expected)
            .expect("occupied destination is a normal race outcome");
        let error = match output.final_after_install(&expected, result) {
            Ok(_) => panic!("different concurrent winner must fail closed"),
            Err(error) => error,
        };

        assert!(matches!(result, InstallResult::AlreadyExists));
        assert!(matches!(error, AdjustedSourceError::ExistingOutputMismatch));
        assert_eq!(
            std::fs::read(&output_path).expect("winner remains"),
            b"different winner"
        );
        temp.cleanup().expect("cleanup staging directory");
    }
}

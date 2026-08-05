use std::cell::Cell;
use std::ffi::{CString, c_char, c_int, c_void};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

use crate::authorization_policy::{load_sealed, validate_service_install_path};
use serde::Serialize;
use sha2::{Digest, Sha256};
use smb2::client::{Connection, Session, Tree};
use smb2::types::{Dialect, status::NtStatus};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

// Windows interactive passwords are limited to 127 characters. This allows
// twice that many four-byte UTF-8 scalars while still bounding the Keychain
// buffer before any slice or owned copy is created.
const MAX_KEYCHAIN_PASSWORD_BYTES: u32 = 1024;
const SMB_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const CANARY_DIRECTORY_PREFIX: &str = ".icloudpd-optimizer-smb-noreplace-canary-";
const CANARY_PAYLOAD_BYTES: u64 = 16;
const CANARY_CLEANUP_MAX_ATTEMPTS: usize = 3;
const CANARY_ENTRY_NAMES: [&str; 4] = [
    "missing-source",
    "missing-destination",
    "collision-source",
    "collision-destination",
];

const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const MOUNT_RECOVERY_URL_MAX_BYTES: u64 = 4096;
const MOUNT_RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SmbMountBinding {
    pub mount_root: PathBuf,
    pub mount_from: String,
    pub service_name: String,
    pub resolved_host: String,
    pub port: u16,
    pub share: String,
    pub account: String,
    pub auth_reference_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SmbMountBindingProof {
    pub mount_root_sha256: String,
    pub mount_from_sha256: String,
    pub service_name_sha256: String,
    pub resolved_host_sha256: String,
    pub port: u16,
    pub share_sha256: String,
    pub account_sha256: String,
    pub auth_reference_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SmbMountRecoveryReceipt {
    pub schema_version: u64,
    pub recovered_mount: bool,
    pub url_sha256: String,
    pub caller_executable_sha256: String,
    pub caller_designated_requirement_sha256: String,
    pub mount_owner: u32,
    pub mount_observation_sha256: String,
    pub binding: SmbMountBindingProof,
    pub canary: SmbNoReplaceCanaryReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SmbSessionProof {
    pub dialect: String,
    pub signing_active: bool,
    pub server_requires_signing: bool,
    pub session_requires_signing: bool,
    pub session_is_guest: bool,
    pub session_is_null: bool,
    pub encryption_active: bool,
    pub session_requires_encryption: bool,
    pub share_requires_encryption: bool,
    pub signing_algorithm: String,
    pub server_guid_sha256: String,
    pub session_id_sha256: String,
    pub share_sha256: String,
    pub is_dfs: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SmbNoReplaceCanaryReceipt {
    pub schema_version: u64,
    pub binding: SmbMountBindingProof,
    pub session: SmbSessionProof,
    pub missing_target_rename: bool,
    pub collision_status: String,
    pub collision_preserved_both: bool,
    pub cleanup_complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SmbRenameResult {
    Renamed,
    Collision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SmbPathPair {
    Local,
    Mounted(SmbMountBinding),
}

pub(crate) fn classify_smb_path_pair(
    source: Option<SmbMountBinding>,
    destination: Option<SmbMountBinding>,
) -> Result<SmbPathPair, SmbNoReplaceError> {
    match (source, destination) {
        (None, None) => Ok(SmbPathPair::Local),
        (Some(source), Some(destination)) if source == destination => {
            Ok(SmbPathPair::Mounted(source))
        }
        _ => Err(SmbNoReplaceError::PathBinding),
    }
}

#[derive(Debug, Error)]
pub enum SmbNoReplaceError {
    #[error("SMB no-replace gate failed: category=mount_binding")]
    MountBinding,
    #[error("SMB no-replace gate failed: category=service_resolution")]
    ServiceResolution,
    #[error("SMB no-replace gate failed: category=credential_reference")]
    CredentialReference,
    #[error("SMB no-replace gate failed: category=credential_not_found")]
    CredentialNotFound,
    #[error("SMB no-replace gate failed: category=credential_access")]
    CredentialAccess,
    #[error("SMB no-replace gate failed: category=credential_interaction")]
    CredentialInteraction,
    #[error("SMB no-replace gate failed: category=mount_recovery_input")]
    MountRecoveryInput,
    #[error("SMB no-replace gate failed: category=mount_recovery")]
    MountRecovery,
    #[error("SMB no-replace gate failed: category=mount_recovery_timeout")]
    MountRecoveryTimeout,
    #[error("SMB no-replace gate failed: category=mount_recovery_mismatch")]
    MountRecoveryMismatch,
    #[error("SMB no-replace gate failed: category=session_security stage={stage} reason={reason}")]
    SessionSecurity {
        stage: SmbSessionSecurityStage,
        reason: SmbSessionSecurityReason,
    },
    #[error("SMB no-replace gate failed: category=path_binding")]
    PathBinding,
    #[error("SMB no-replace gate failed: category=protocol")]
    Protocol,
    #[error("SMB no-replace gate failed: category=ambiguous")]
    Ambiguous,
    #[error("SMB no-replace gate failed: category=canary")]
    Canary,
    #[error("SMB no-replace gate failed: category=canary_cleanup stage={stage} reason={reason}")]
    CanaryCleanup {
        stage: SmbCanaryCleanupStage,
        reason: SmbCanaryCleanupReason,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmbCanaryCleanupStage {
    PathValidation,
    DirectoryInspection,
    EntryEnumeration,
    EntryInspection,
    EntryRemoval,
    DirectoryRemoval,
    PostRemovalValidation,
}

impl fmt::Display for SmbCanaryCleanupStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PathValidation => "path_validation",
            Self::DirectoryInspection => "directory_inspection",
            Self::EntryEnumeration => "entry_enumeration",
            Self::EntryInspection => "entry_inspection",
            Self::EntryRemoval => "entry_removal",
            Self::DirectoryRemoval => "directory_removal",
            Self::PostRemovalValidation => "post_removal_validation",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmbCanaryCleanupReason {
    PathMismatch,
    DirectoryIdentityMismatch,
    EntryIdentityMismatch,
    UnexpectedEntry,
    RemovalNotConfirmed,
    NotFound,
    PermissionDenied,
    Interrupted,
    WouldBlock,
    TimedOut,
    ReadOnlyFilesystem,
    DirectoryNotEmpty,
    ResourceBusy,
    InvalidInput,
    Unsupported,
    Io,
}

impl fmt::Display for SmbCanaryCleanupReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PathMismatch => "path_mismatch",
            Self::DirectoryIdentityMismatch => "directory_identity_mismatch",
            Self::EntryIdentityMismatch => "entry_identity_mismatch",
            Self::UnexpectedEntry => "unexpected_entry",
            Self::RemovalNotConfirmed => "removal_not_confirmed",
            Self::NotFound => "not_found",
            Self::PermissionDenied => "permission_denied",
            Self::Interrupted => "interrupted",
            Self::WouldBlock => "would_block",
            Self::TimedOut => "timed_out",
            Self::ReadOnlyFilesystem => "read_only_filesystem",
            Self::DirectoryNotEmpty => "directory_not_empty",
            Self::ResourceBusy => "resource_busy",
            Self::InvalidInput => "invalid_input",
            Self::Unsupported => "unsupported",
            Self::Io => "io",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmbSessionSecurityStage {
    Runtime,
    Connect,
    Negotiate,
    SessionSetup,
    SessionIdentity,
    TreeConnect,
    ShareEncryption,
    SessionParameters,
    PostConnectValidation,
}

impl fmt::Display for SmbSessionSecurityStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Runtime => "runtime",
            Self::Connect => "connect",
            Self::Negotiate => "negotiate",
            Self::SessionSetup => "session_setup",
            Self::SessionIdentity => "session_identity",
            Self::TreeConnect => "tree_connect",
            Self::ShareEncryption => "share_encryption",
            Self::SessionParameters => "session_parameters",
            Self::PostConnectValidation => "post_connect_validation",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SmbSessionSecurityReason {
    RuntimeInitialization,
    OperationTimedOut,
    TransportIo,
    TransportPermissionDenied,
    TransportConnectionRefused,
    TransportConnectionReset,
    TransportHostUnreachable,
    TransportNetworkUnreachable,
    TransportConnectionAborted,
    TransportNotConnected,
    TransportAddressInUse,
    TransportAddressNotAvailable,
    TransportNetworkDown,
    TransportTimedOut,
    TransportWouldBlock,
    TransportInterrupted,
    TransportUnexpectedEof,
    Disconnected,
    AuthenticationRejected,
    SigningRequired,
    AccessDenied,
    NotFound,
    AlreadyExists,
    SharingViolation,
    IsDirectory,
    NotDirectory,
    DiskFull,
    Unsupported,
    ServerRejected,
    InvalidProtocolData,
    DfsReferral,
    Cancelled,
    SessionExpired,
    UnexpectedOperation,
    GuestSession,
    NullSession,
    GuestAndNullSession,
    MissingEncryptionKeys,
    MissingEncryptionCipher,
    EncryptionActivationRejected,
    MissingNegotiatedParameters,
    DialectNotSmb311,
    EmptyAccount,
    SessionSigningDisabled,
    SigningInactive,
    DiagnosticSessionMissing,
    DiagnosticSessionMismatch,
    RequiredEncryptionInactive,
    UnexpectedEncryptionActive,
    ShareMismatch,
    ServerMismatch,
    DfsShare,
}

impl fmt::Display for SmbSessionSecurityReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RuntimeInitialization => "runtime_initialization",
            Self::OperationTimedOut => "operation_timed_out",
            Self::TransportIo => "transport_io",
            Self::TransportPermissionDenied => "transport_permission_denied",
            Self::TransportConnectionRefused => "transport_connection_refused",
            Self::TransportConnectionReset => "transport_connection_reset",
            Self::TransportHostUnreachable => "transport_host_unreachable",
            Self::TransportNetworkUnreachable => "transport_network_unreachable",
            Self::TransportConnectionAborted => "transport_connection_aborted",
            Self::TransportNotConnected => "transport_not_connected",
            Self::TransportAddressInUse => "transport_address_in_use",
            Self::TransportAddressNotAvailable => "transport_address_not_available",
            Self::TransportNetworkDown => "transport_network_down",
            Self::TransportTimedOut => "transport_timed_out",
            Self::TransportWouldBlock => "transport_would_block",
            Self::TransportInterrupted => "transport_interrupted",
            Self::TransportUnexpectedEof => "transport_unexpected_eof",
            Self::Disconnected => "disconnected",
            Self::AuthenticationRejected => "authentication_rejected",
            Self::SigningRequired => "signing_required",
            Self::AccessDenied => "access_denied",
            Self::NotFound => "not_found",
            Self::AlreadyExists => "already_exists",
            Self::SharingViolation => "sharing_violation",
            Self::IsDirectory => "is_directory",
            Self::NotDirectory => "not_directory",
            Self::DiskFull => "disk_full",
            Self::Unsupported => "unsupported",
            Self::ServerRejected => "server_rejected",
            Self::InvalidProtocolData => "invalid_protocol_data",
            Self::DfsReferral => "dfs_referral",
            Self::Cancelled => "cancelled",
            Self::SessionExpired => "session_expired",
            Self::UnexpectedOperation => "unexpected_operation",
            Self::GuestSession => "guest_session",
            Self::NullSession => "null_session",
            Self::GuestAndNullSession => "guest_and_null_session",
            Self::MissingEncryptionKeys => "missing_encryption_keys",
            Self::MissingEncryptionCipher => "missing_encryption_cipher",
            Self::EncryptionActivationRejected => "encryption_activation_rejected",
            Self::MissingNegotiatedParameters => "missing_negotiated_parameters",
            Self::DialectNotSmb311 => "dialect_not_smb311",
            Self::EmptyAccount => "empty_account",
            Self::SessionSigningDisabled => "session_signing_disabled",
            Self::SigningInactive => "signing_inactive",
            Self::DiagnosticSessionMissing => "diagnostic_session_missing",
            Self::DiagnosticSessionMismatch => "diagnostic_session_mismatch",
            Self::RequiredEncryptionInactive => "required_encryption_inactive",
            Self::UnexpectedEncryptionActive => "unexpected_encryption_active",
            Self::ShareMismatch => "share_mismatch",
            Self::ServerMismatch => "server_mismatch",
            Self::DfsShare => "dfs_share",
        })
    }
}

pub(crate) struct SmbNoReplaceSession {
    binding: SmbMountBinding,
    runtime: tokio::runtime::Runtime,
    connection: Connection,
    session: Session,
    tree: Tree,
    proof: SmbSessionProof,
}

#[derive(Clone, Copy)]
struct SessionSecurityFacts {
    dialect_is_smb311: bool,
    account_nonempty: bool,
    session_signing_required: bool,
    session_is_guest: bool,
    session_is_null: bool,
    signing_active: bool,
    diagnostic_session_present: bool,
    diagnostic_session_matches: bool,
    encryption_active: bool,
    session_encryption_required: bool,
    share_encryption_required: bool,
    share_matches: bool,
    server_matches: bool,
    is_dfs: bool,
}

#[cfg(test)]
fn authenticated_session_identity(session_is_guest: bool, session_is_null: bool) -> bool {
    session_identity_failure(session_is_guest, session_is_null).is_none()
}

fn session_identity_failure(
    session_is_guest: bool,
    session_is_null: bool,
) -> Option<SmbSessionSecurityReason> {
    match (session_is_guest, session_is_null) {
        (false, false) => None,
        (true, false) => Some(SmbSessionSecurityReason::GuestSession),
        (false, true) => Some(SmbSessionSecurityReason::NullSession),
        (true, true) => Some(SmbSessionSecurityReason::GuestAndNullSession),
    }
}

fn session_security_failure(facts: SessionSecurityFacts) -> Option<SmbSessionSecurityReason> {
    let encryption_required = facts.session_encryption_required || facts.share_encryption_required;
    if !facts.dialect_is_smb311 {
        Some(SmbSessionSecurityReason::DialectNotSmb311)
    } else if !facts.account_nonempty {
        Some(SmbSessionSecurityReason::EmptyAccount)
    } else if !facts.session_signing_required {
        Some(SmbSessionSecurityReason::SessionSigningDisabled)
    } else if let Some(reason) =
        session_identity_failure(facts.session_is_guest, facts.session_is_null)
    {
        Some(reason)
    } else if !facts.signing_active {
        Some(SmbSessionSecurityReason::SigningInactive)
    } else if !facts.diagnostic_session_present {
        Some(SmbSessionSecurityReason::DiagnosticSessionMissing)
    } else if !facts.diagnostic_session_matches {
        Some(SmbSessionSecurityReason::DiagnosticSessionMismatch)
    } else if encryption_required && !facts.encryption_active {
        Some(SmbSessionSecurityReason::RequiredEncryptionInactive)
    } else if !encryption_required && facts.encryption_active {
        Some(SmbSessionSecurityReason::UnexpectedEncryptionActive)
    } else if !facts.share_matches {
        Some(SmbSessionSecurityReason::ShareMismatch)
    } else if !facts.server_matches {
        Some(SmbSessionSecurityReason::ServerMismatch)
    } else if facts.is_dfs {
        Some(SmbSessionSecurityReason::DfsShare)
    } else {
        None
    }
}

#[cfg(test)]
fn session_security_valid(facts: SessionSecurityFacts) -> bool {
    session_security_failure(facts).is_none()
}

fn session_security_error(
    stage: SmbSessionSecurityStage,
    reason: SmbSessionSecurityReason,
) -> SmbNoReplaceError {
    SmbNoReplaceError::SessionSecurity { stage, reason }
}

fn transport_io_reason(kind: std::io::ErrorKind) -> SmbSessionSecurityReason {
    match kind {
        std::io::ErrorKind::PermissionDenied => SmbSessionSecurityReason::TransportPermissionDenied,
        std::io::ErrorKind::ConnectionRefused => {
            SmbSessionSecurityReason::TransportConnectionRefused
        }
        std::io::ErrorKind::ConnectionReset => SmbSessionSecurityReason::TransportConnectionReset,
        std::io::ErrorKind::HostUnreachable => SmbSessionSecurityReason::TransportHostUnreachable,
        std::io::ErrorKind::NetworkUnreachable => {
            SmbSessionSecurityReason::TransportNetworkUnreachable
        }
        std::io::ErrorKind::ConnectionAborted => {
            SmbSessionSecurityReason::TransportConnectionAborted
        }
        std::io::ErrorKind::NotConnected => SmbSessionSecurityReason::TransportNotConnected,
        std::io::ErrorKind::AddrInUse => SmbSessionSecurityReason::TransportAddressInUse,
        std::io::ErrorKind::AddrNotAvailable => {
            SmbSessionSecurityReason::TransportAddressNotAvailable
        }
        std::io::ErrorKind::NetworkDown => SmbSessionSecurityReason::TransportNetworkDown,
        std::io::ErrorKind::TimedOut => SmbSessionSecurityReason::TransportTimedOut,
        std::io::ErrorKind::WouldBlock => SmbSessionSecurityReason::TransportWouldBlock,
        std::io::ErrorKind::Interrupted => SmbSessionSecurityReason::TransportInterrupted,
        std::io::ErrorKind::UnexpectedEof => SmbSessionSecurityReason::TransportUnexpectedEof,
        _ => SmbSessionSecurityReason::TransportIo,
    }
}

fn smb_operation_error(stage: SmbSessionSecurityStage, error: smb2::Error) -> SmbNoReplaceError {
    let reason = match &error {
        smb2::Error::Io(error) => transport_io_reason(error.kind()),
        _ => match error.kind() {
            smb2::ErrorKind::AuthRequired => SmbSessionSecurityReason::AuthenticationRejected,
            smb2::ErrorKind::SigningRequired => SmbSessionSecurityReason::SigningRequired,
            smb2::ErrorKind::AccessDenied => SmbSessionSecurityReason::AccessDenied,
            smb2::ErrorKind::NotFound => SmbSessionSecurityReason::NotFound,
            smb2::ErrorKind::AlreadyExists => SmbSessionSecurityReason::AlreadyExists,
            smb2::ErrorKind::SharingViolation => SmbSessionSecurityReason::SharingViolation,
            smb2::ErrorKind::IsADirectory => SmbSessionSecurityReason::IsDirectory,
            smb2::ErrorKind::NotADirectory => SmbSessionSecurityReason::NotDirectory,
            smb2::ErrorKind::DiskFull => SmbSessionSecurityReason::DiskFull,
            smb2::ErrorKind::ConnectionLost => SmbSessionSecurityReason::Disconnected,
            smb2::ErrorKind::TimedOut => SmbSessionSecurityReason::OperationTimedOut,
            smb2::ErrorKind::Cancelled => SmbSessionSecurityReason::Cancelled,
            smb2::ErrorKind::SessionExpired => SmbSessionSecurityReason::SessionExpired,
            smb2::ErrorKind::DfsReferral => SmbSessionSecurityReason::DfsReferral,
            smb2::ErrorKind::InvalidData => SmbSessionSecurityReason::InvalidProtocolData,
            smb2::ErrorKind::TooLarge => SmbSessionSecurityReason::UnexpectedOperation,
            smb2::ErrorKind::Io => SmbSessionSecurityReason::TransportIo,
            smb2::ErrorKind::Unsupported => SmbSessionSecurityReason::Unsupported,
            smb2::ErrorKind::Other => SmbSessionSecurityReason::ServerRejected,
            _ => SmbSessionSecurityReason::UnexpectedOperation,
        },
    };
    session_security_error(stage, reason)
}

impl SmbMountBinding {
    /// Finds the mounted filesystem lexically, without opening `path`.
    /// This is used to prove the SMB capability before governed paths are touched.
    pub(crate) fn discover_for_path(path: &Path) -> Result<Option<Self>, SmbNoReplaceError> {
        validate_absolute_lexical_path(path)?;
        let stat = mounted_filesystem_for_path(path)?;
        if fixed_c_string(&stat.f_fstypename)? != "smbfs" {
            return Ok(None);
        }
        let mount_root = PathBuf::from(fixed_c_string(&stat.f_mntonname)?);
        let mount_from = fixed_c_string(&stat.f_mntfromname)?;
        let (account, service_name, share) = parse_mount_from(&mount_from)?;
        let (resolved_host, port) = deterministic_connection_endpoint(&service_name)?;
        if port != 445 || account.is_empty() || share.is_empty() {
            return Err(SmbNoReplaceError::MountBinding);
        }
        Ok(Some(Self {
            mount_root,
            mount_from,
            service_name,
            resolved_host,
            port,
            share,
            account,
            auth_reference_sha256: String::new(),
        }))
    }

    pub fn discover_mount_root(path: &Path) -> Result<Self, SmbNoReplaceError> {
        let binding = Self::discover_for_path(path)?.ok_or(SmbNoReplaceError::MountBinding)?;
        Self::validate_discovered_mount_root_with(binding, path, statfs_for)
    }

    fn validate_discovered_mount_root_with<F>(
        binding: Self,
        path: &Path,
        statfs: F,
    ) -> Result<Self, SmbNoReplaceError>
    where
        F: FnOnce(&Path) -> Result<libc::statfs, SmbNoReplaceError>,
    {
        if path != binding.mount_root {
            return Err(SmbNoReplaceError::MountBinding);
        }
        binding.validate_exact_mount_root_with(path, statfs)?;
        Ok(binding)
    }

    pub(crate) fn redacted_proof(&self) -> Result<SmbMountBindingProof, SmbNoReplaceError> {
        if self.auth_reference_sha256.len() != 64
            || !self
                .auth_reference_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(SmbNoReplaceError::CredentialReference);
        }
        Ok(SmbMountBindingProof {
            mount_root_sha256: sha256_path(&self.mount_root),
            mount_from_sha256: sha256_bytes(self.mount_from.as_bytes()),
            service_name_sha256: sha256_bytes(self.service_name.as_bytes()),
            resolved_host_sha256: sha256_bytes(self.resolved_host.as_bytes()),
            port: self.port,
            share_sha256: sha256_bytes(self.share.as_bytes()),
            account_sha256: sha256_bytes(self.account.as_bytes()),
            auth_reference_sha256: self.auth_reference_sha256.clone(),
        })
    }

    pub(crate) fn same_mount_endpoint(&self, other: &Self) -> bool {
        self.mount_root == other.mount_root
            && self.mount_from == other.mount_from
            && self.service_name == other.service_name
            && self.resolved_host == other.resolved_host
            && self.port == other.port
            && self.share == other.share
            && self.account == other.account
    }

    pub fn validate_existing_path(&self, path: &Path) -> Result<(), SmbNoReplaceError> {
        self.relative_share_path(path)?;
        let stat = statfs_for(path)?;
        self.validate_bound_statfs(&stat)
    }

    fn validate_exact_mount_root(&self, path: &Path) -> Result<(), SmbNoReplaceError> {
        self.validate_exact_mount_root_with(path, statfs_for)
    }

    fn validate_exact_mount_root_with<F>(
        &self,
        path: &Path,
        statfs: F,
    ) -> Result<(), SmbNoReplaceError>
    where
        F: FnOnce(&Path) -> Result<libc::statfs, SmbNoReplaceError>,
    {
        validate_absolute_lexical_path(path)?;
        if path != self.mount_root {
            return Err(SmbNoReplaceError::PathBinding);
        }
        let stat = statfs(path)?;
        self.validate_bound_statfs(&stat)
    }

    fn validate_bound_statfs(&self, stat: &libc::statfs) -> Result<(), SmbNoReplaceError> {
        let mounted_root = fixed_c_string(&stat.f_mntonname)?;
        if fixed_c_string(&stat.f_fstypename)? != "smbfs"
            || Path::new(&mounted_root) != self.mount_root
            || fixed_c_string(&stat.f_mntfromname)? != self.mount_from
        {
            return Err(SmbNoReplaceError::PathBinding);
        }
        Ok(())
    }

    pub fn validate_existing_parent_for(&self, path: &Path) -> Result<(), SmbNoReplaceError> {
        let parent = path.parent().ok_or(SmbNoReplaceError::PathBinding)?;
        self.validate_existing_path(parent)
    }

    fn relative_share_path(&self, path: &Path) -> Result<String, SmbNoReplaceError> {
        validate_absolute_lexical_path(path)?;
        let relative = path
            .strip_prefix(&self.mount_root)
            .map_err(|_| SmbNoReplaceError::PathBinding)?;
        if relative.as_os_str().is_empty()
            || relative.components().any(|part| {
                !matches!(part, Component::Normal(_)) || part.as_os_str().as_bytes().contains(&0)
            })
        {
            return Err(SmbNoReplaceError::PathBinding);
        }
        relative
            .to_str()
            .map(str::to_owned)
            .ok_or(SmbNoReplaceError::PathBinding)
    }
}

impl SmbNoReplaceSession {
    pub fn connect(mut binding: SmbMountBinding) -> Result<Self, SmbNoReplaceError> {
        let (password, auth_reference_sha256) =
            keychain_credential(&binding.service_name, &binding.account)?;
        binding.auth_reference_sha256 = auth_reference_sha256;
        Self::connect_with_password(binding, password.as_str())
    }

    fn connect_with_password(
        binding: SmbMountBinding,
        password: &str,
    ) -> Result<Self, SmbNoReplaceError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| {
                session_security_error(
                    SmbSessionSecurityStage::Runtime,
                    SmbSessionSecurityReason::RuntimeInitialization,
                )
            })?;
        let address = format!(
            "{}:{}",
            binding.resolved_host.trim_end_matches('.'),
            binding.port
        );
        let active_stage = Cell::new(SmbSessionSecurityStage::Connect);
        let connected = runtime.block_on(async {
            tokio::time::timeout(SMB_OPERATION_TIMEOUT, async {
                active_stage.set(SmbSessionSecurityStage::Connect);
                let mut connection = Connection::connect(&address, Duration::from_secs(10))
                    .await
                    .map_err(|error| {
                        smb_operation_error(SmbSessionSecurityStage::Connect, error)
                    })?;
                active_stage.set(SmbSessionSecurityStage::Negotiate);
                connection.negotiate().await.map_err(|error| {
                    smb_operation_error(SmbSessionSecurityStage::Negotiate, error)
                })?;
                active_stage.set(SmbSessionSecurityStage::SessionSetup);
                let session = Session::setup(&mut connection, &binding.account, password, "")
                    .await
                    .map_err(|error| {
                        smb_operation_error(SmbSessionSecurityStage::SessionSetup, error)
                    })?;
                active_stage.set(SmbSessionSecurityStage::SessionIdentity);
                if let Some(reason) = session_identity_failure(
                    session.session_flags.is_guest(),
                    session.session_flags.is_null(),
                ) {
                    return Err(session_security_error(
                        SmbSessionSecurityStage::SessionIdentity,
                        reason,
                    ));
                }
                active_stage.set(SmbSessionSecurityStage::TreeConnect);
                let tree = Tree::connect(&mut connection, &binding.share)
                    .await
                    .map_err(|error| {
                        smb_operation_error(SmbSessionSecurityStage::TreeConnect, error)
                    })?;
                if tree.encrypt_data && !connection.should_encrypt() {
                    active_stage.set(SmbSessionSecurityStage::ShareEncryption);
                    let (Some(encryption_key), Some(decryption_key)) =
                        (&session.encryption_key, &session.decryption_key)
                    else {
                        return Err(session_security_error(
                            SmbSessionSecurityStage::ShareEncryption,
                            SmbSessionSecurityReason::MissingEncryptionKeys,
                        ));
                    };
                    let cipher = connection
                        .params()
                        .and_then(|params| params.cipher)
                        .ok_or_else(|| {
                            session_security_error(
                                SmbSessionSecurityStage::ShareEncryption,
                                SmbSessionSecurityReason::MissingEncryptionCipher,
                            )
                        })?;
                    connection
                        .activate_encryption(encryption_key.clone(), decryption_key.clone(), cipher)
                        .map_err(|_| {
                            session_security_error(
                                SmbSessionSecurityStage::ShareEncryption,
                                SmbSessionSecurityReason::EncryptionActivationRejected,
                            )
                        })?;
                }
                Ok::<_, SmbNoReplaceError>((connection, session, tree))
            })
            .await
        });
        let (connection, session, tree) = match connected {
            Ok(result) => result?,
            Err(_) => {
                return Err(session_security_error(
                    active_stage.get(),
                    SmbSessionSecurityReason::OperationTimedOut,
                ));
            }
        };
        let params = connection.params().ok_or_else(|| {
            session_security_error(
                SmbSessionSecurityStage::SessionParameters,
                SmbSessionSecurityReason::MissingNegotiatedParameters,
            )
        })?;
        let diagnostics = connection.diagnostics();
        let diagnostic_session_present = diagnostics.session.is_some();
        let failure = session_security_failure(SessionSecurityFacts {
            dialect_is_smb311: params.dialect == Dialect::Smb3_1_1,
            account_nonempty: !binding.account.is_empty(),
            session_signing_required: session.should_sign,
            session_is_guest: session.session_flags.is_guest(),
            session_is_null: session.session_flags.is_null(),
            signing_active: diagnostics.signing.active,
            diagnostic_session_present,
            diagnostic_session_matches: diagnostics.session.as_ref().is_some_and(|value| {
                value.should_sign
                    && value.session_id == session.session_id
                    && value.signing_algorithm == session.signing_algorithm
            }),
            encryption_active: diagnostics.encryption.active,
            session_encryption_required: session.should_encrypt,
            share_encryption_required: tree.encrypt_data,
            share_matches: tree.share_name == binding.share,
            server_matches: tree.server.trim_end_matches('.')
                == binding.resolved_host.trim_end_matches('.'),
            is_dfs: tree.is_dfs,
        });
        if let Some(reason) = failure {
            return Err(session_security_error(
                SmbSessionSecurityStage::PostConnectValidation,
                reason,
            ));
        }
        let proof = SmbSessionProof {
            dialect: params.dialect.to_string(),
            signing_active: diagnostics.signing.active,
            server_requires_signing: params.signing_required,
            session_requires_signing: session.should_sign,
            session_is_guest: session.session_flags.is_guest(),
            session_is_null: session.session_flags.is_null(),
            encryption_active: diagnostics.encryption.active,
            session_requires_encryption: session.should_encrypt,
            share_requires_encryption: tree.encrypt_data,
            signing_algorithm: format!("{:?}", session.signing_algorithm),
            server_guid_sha256: sha256_bytes(params.server_guid.to_string().as_bytes()),
            session_id_sha256: sha256_bytes(&session.session_id.0.to_le_bytes()),
            share_sha256: sha256_bytes(tree.share_name.as_bytes()),
            is_dfs: tree.is_dfs,
        };
        Ok(Self {
            binding,
            runtime,
            connection,
            session,
            tree,
            proof,
        })
    }

    pub(crate) fn binding(&self) -> &SmbMountBinding {
        &self.binding
    }

    pub(crate) fn proof(&self) -> &SmbSessionProof {
        &self.proof
    }

    pub(crate) fn rename_noreplace(
        &mut self,
        source: &Path,
        destination: &Path,
    ) -> Result<SmbRenameResult, SmbNoReplaceError> {
        self.binding.validate_existing_path(source)?;
        self.binding.validate_existing_parent_for(destination)?;
        let source_relative = self.binding.relative_share_path(source)?;
        let destination_relative = self.binding.relative_share_path(destination)?;
        let result = self.runtime.block_on(async {
            tokio::time::timeout(
                SMB_OPERATION_TIMEOUT,
                self.tree.rename(
                    &mut self.connection,
                    &source_relative,
                    &destination_relative,
                ),
            )
            .await
        });
        match result {
            Ok(Ok(())) => Ok(SmbRenameResult::Renamed),
            Ok(Err(error)) if error.status() == Some(NtStatus::OBJECT_NAME_COLLISION) => {
                Ok(SmbRenameResult::Collision)
            }
            Err(_)
            | Ok(Err(smb2::Error::Disconnected | smb2::Error::Timeout | smb2::Error::Io(_))) => {
                Err(SmbNoReplaceError::Ambiguous)
            }
            Ok(Err(_)) => Err(SmbNoReplaceError::Protocol),
        }
    }
}

/// Proves supplied dashboard password bytes against the exact SMB endpoint
/// before any Keychain mutation. This performs authenticated session setup and
/// a tree connect; it never mounts, writes, or selects ambient credentials.
pub(crate) fn validate_supplied_credential(
    binding: &SmbMountBinding,
    password: &[u8],
) -> Result<(), SmbNoReplaceError> {
    let password =
        std::str::from_utf8(password).map_err(|_| SmbNoReplaceError::CredentialAccess)?;
    SmbNoReplaceSession::connect_with_password(binding.clone(), password).map(|_| ())
}

impl Drop for SmbNoReplaceSession {
    fn drop(&mut self) {
        self.session.signing_key.zeroize();
        if let Some(key) = self.session.encryption_key.as_mut() {
            key.zeroize();
        }
        if let Some(key) = self.session.decryption_key.as_mut() {
            key.zeroize();
        }
    }
}

pub fn run_disposable_canary(
    mount_root: &Path,
) -> Result<SmbNoReplaceCanaryReceipt, SmbNoReplaceError> {
    let binding = SmbMountBinding::discover_mount_root(mount_root)?;
    prove_disposable_canary(binding).map(|(_, receipt)| receipt)
}

struct SmbMountRecoveryAuthority {
    url: String,
    url_sha256: String,
    service_name: String,
    share: String,
    account: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SmbMountRecoverySigner {
    executable_sha256: String,
    designated_requirement_sha256: String,
}

fn parse_mount_recovery_designated_requirement(
    stdout: &[u8],
    stderr: &[u8],
) -> Result<String, SmbNoReplaceError> {
    const REQUIREMENT_PREFIX: &str = "designated => anchor apple generic and identifier \"com.icloudpd-optimizer.helper\" and certificate leaf[subject.OU] = \"";
    let mut designated = None;
    let mut executable = None;

    for stream in [stdout, stderr] {
        let rendered =
            std::str::from_utf8(stream).map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
        for line in rendered.lines().filter(|line| !line.is_empty()) {
            if let Some(path) = line.strip_prefix("Executable=") {
                if path.is_empty() || executable.replace(path).is_some() {
                    return Err(SmbNoReplaceError::MountRecoveryInput);
                }
                continue;
            }
            if !line.starts_with("designated => ") || designated.replace(line.to_owned()).is_some()
            {
                return Err(SmbNoReplaceError::MountRecoveryInput);
            }
        }
    }

    if executable.is_none() {
        return Err(SmbNoReplaceError::MountRecoveryInput);
    }
    let designated = designated.ok_or(SmbNoReplaceError::MountRecoveryInput)?;
    let team_id = designated
        .strip_prefix(REQUIREMENT_PREFIX)
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| {
            value.len() == 10
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        })
        .ok_or(SmbNoReplaceError::MountRecoveryInput)?;
    debug_assert!(!team_id.is_empty());
    Ok(designated)
}

fn current_mount_recovery_signer(
    service_bundle: &Path,
) -> Result<SmbMountRecoverySigner, SmbNoReplaceError> {
    let (policy, _) = load_sealed(service_bundle, unsafe { libc::geteuid() })
        .map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
    validate_service_install_path(service_bundle, &policy)
        .map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
    let expected_designated_requirement_sha256 = sha256_bytes(
        policy
            .helper_designated_requirement
            .as_deref()
            .ok_or(SmbNoReplaceError::MountRecoveryInput)?
            .as_bytes(),
    );
    let executable = std::env::current_exe().map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
    let mut executable_options = OpenOptions::new();
    executable_options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut executable_file = executable_options
        .open(&executable)
        .map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
    let initial_metadata = executable_file
        .metadata()
        .map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
    if !initial_metadata.file_type().is_file()
        || initial_metadata.nlink() != 1
        || initial_metadata.len() == 0
    {
        return Err(SmbNoReplaceError::MountRecoveryInput);
    }
    let initial_identity = (
        initial_metadata.dev(),
        initial_metadata.ino(),
        initial_metadata.mode(),
        initial_metadata.uid(),
        initial_metadata.gid(),
        initial_metadata.nlink(),
        initial_metadata.len(),
        initial_metadata.mtime(),
        initial_metadata.mtime_nsec(),
        initial_metadata.ctime(),
        initial_metadata.ctime_nsec(),
    );
    let executable_sha256 = sha256_open_mount_recovery_file(&mut executable_file)?;
    let verify = Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "--verbose=2"])
        .arg(&executable)
        .output()
        .map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
    if !verify.status.success() {
        return Err(SmbNoReplaceError::MountRecoveryInput);
    }
    let requirement = Command::new("/usr/bin/codesign")
        .args(["-d", "-r-"])
        .arg(&executable)
        .output()
        .map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
    if !requirement.status.success() {
        return Err(SmbNoReplaceError::MountRecoveryInput);
    }
    let designated =
        parse_mount_recovery_designated_requirement(&requirement.stdout, &requirement.stderr)?;
    let designated_requirement_sha256 = sha256_bytes(designated.as_bytes());
    if designated_requirement_sha256 != expected_designated_requirement_sha256 {
        return Err(SmbNoReplaceError::MountRecoveryMismatch);
    }
    if std::fs::canonicalize(&executable).ok()
        != std::fs::canonicalize(
            service_bundle.join(
                policy
                    .helper_relative_path
                    .as_deref()
                    .ok_or(SmbNoReplaceError::MountRecoveryInput)?,
            ),
        )
        .ok()
    {
        return Err(SmbNoReplaceError::MountRecoveryMismatch);
    }
    let held_metadata = executable_file
        .metadata()
        .map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
    let held_identity = (
        held_metadata.dev(),
        held_metadata.ino(),
        held_metadata.mode(),
        held_metadata.uid(),
        held_metadata.gid(),
        held_metadata.nlink(),
        held_metadata.len(),
        held_metadata.mtime(),
        held_metadata.mtime_nsec(),
        held_metadata.ctime(),
        held_metadata.ctime_nsec(),
    );
    let mut named_file = executable_options
        .open(&executable)
        .map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
    let named_metadata = named_file
        .metadata()
        .map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
    let named_identity = (
        named_metadata.dev(),
        named_metadata.ino(),
        named_metadata.mode(),
        named_metadata.uid(),
        named_metadata.gid(),
        named_metadata.nlink(),
        named_metadata.len(),
        named_metadata.mtime(),
        named_metadata.mtime_nsec(),
        named_metadata.ctime(),
        named_metadata.ctime_nsec(),
    );
    if held_identity != initial_identity
        || named_identity != initial_identity
        || sha256_open_mount_recovery_file(&mut executable_file)? != executable_sha256
        || sha256_open_mount_recovery_file(&mut named_file)? != executable_sha256
    {
        return Err(SmbNoReplaceError::MountRecoveryMismatch);
    }
    Ok(SmbMountRecoverySigner {
        executable_sha256,
        designated_requirement_sha256,
    })
}

fn sha256_open_mount_recovery_file(file: &mut File) -> Result<String, SmbNoReplaceError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn read_mount_recovery_authority(
    url_file: &Path,
    expected_url_sha256: &str,
) -> Result<SmbMountRecoveryAuthority, SmbNoReplaceError> {
    if !valid_lower_sha256(expected_url_sha256) {
        return Err(SmbNoReplaceError::MountRecoveryInput);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(url_file)
        .map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
    let metadata = file
        .metadata()
        .map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || !(1..=MOUNT_RECOVERY_URL_MAX_BYTES).contains(&metadata.len())
    {
        return Err(SmbNoReplaceError::MountRecoveryInput);
    }
    let mut url = String::new();
    file.read_to_string(&mut url)
        .map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
    while matches!(url.as_bytes().last(), Some(b'\n' | b'\r')) {
        url.pop();
    }
    if url.is_empty()
        || url.bytes().any(|byte| byte.is_ascii_control())
        || sha256_bytes(url.as_bytes()) != expected_url_sha256
    {
        return Err(SmbNoReplaceError::MountRecoveryInput);
    }
    let parsed = url::Url::parse(&url).map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
    let service_name = parsed
        .host_str()
        .filter(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        })
        .ok_or(SmbNoReplaceError::MountRecoveryInput)?
        .to_owned();
    deterministic_connection_endpoint(&service_name)?;
    let account = parsed.username().to_owned();
    if account.is_empty()
        || !account
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(SmbNoReplaceError::MountRecoveryInput);
    }
    let mut segments = parsed
        .path_segments()
        .ok_or(SmbNoReplaceError::MountRecoveryInput)?;
    let share = segments
        .next()
        .filter(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
        .ok_or(SmbNoReplaceError::MountRecoveryInput)?
        .to_owned();
    if segments.next().is_some()
        || parsed.scheme() != "smb"
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.as_str() != format!("smb://{account}@{service_name}/{share}")
    {
        return Err(SmbNoReplaceError::MountRecoveryInput);
    }
    Ok(SmbMountRecoveryAuthority {
        url,
        url_sha256: expected_url_sha256.to_owned(),
        service_name,
        share,
        account,
    })
}

/// Builds the only unmounted credential-validation binding admitted by the
/// sealed recovery URL. The mount path is lexical only here: no filesystem
/// access or ambient mount state is consulted before password validation.
pub(crate) fn credential_binding_from_sealed_authority(
    expected_mount_root: &Path,
    url_file: &Path,
    expected_url_sha256: &str,
) -> Result<SmbMountBinding, SmbNoReplaceError> {
    validate_mount_recovery_root(expected_mount_root)?;
    let authority = read_mount_recovery_authority(url_file, expected_url_sha256)?;
    let (resolved_host, port) = deterministic_connection_endpoint(&authority.service_name)?;
    if port != 445 {
        return Err(SmbNoReplaceError::MountRecoveryInput);
    }
    Ok(SmbMountBinding {
        mount_root: expected_mount_root.to_path_buf(),
        mount_from: authority.url,
        service_name: authority.service_name,
        resolved_host,
        port,
        share: authority.share,
        account: authority.account,
        auth_reference_sha256: String::new(),
    })
}

fn valid_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

struct OwnedCf(*const c_void);

impl OwnedCf {
    fn new(value: *const c_void) -> Result<Self, SmbNoReplaceError> {
        if value.is_null() {
            Err(SmbNoReplaceError::MountRecovery)
        } else {
            Ok(Self(value))
        }
    }
}

impl Drop for OwnedCf {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0) };
    }
}

fn cf_string(bytes: &[u8]) -> Result<OwnedCf, SmbNoReplaceError> {
    let value = unsafe {
        CFStringCreateWithBytes(
            ptr::null(),
            bytes.as_ptr(),
            bytes
                .len()
                .try_into()
                .map_err(|_| SmbNoReplaceError::MountRecoveryInput)?,
            CF_STRING_ENCODING_UTF8,
            0,
        )
    };
    OwnedCf::new(value)
}

struct NetFsCredentials {
    username: OwnedCf,
    password: OwnedCf,
}

fn netfs_credential_refs(
    account: &str,
    password: &Zeroizing<String>,
) -> Result<NetFsCredentials, SmbNoReplaceError> {
    Ok(NetFsCredentials {
        username: cf_string(account.as_bytes())?,
        password: cf_string(password.as_bytes())?,
    })
}

/// Mounts only with the one exact, helper-authorized Keychain item bound to
/// `authority`.  NetFS must never be allowed to select a credential itself:
/// that would make its NoUI behavior depend on ambient Keychain state.
fn mount_with_netfs_keychain_credentials(
    authority: &SmbMountRecoveryAuthority,
    expected_mount_root: &Path,
) -> Result<(), SmbNoReplaceError> {
    // Keep the password in a Zeroizing allocation until CoreFoundation has
    // copied it into the bounded CFString used by this synchronous call.  It
    // is neither serialized nor passed through a process boundary.
    let (password, _auth_reference_sha256) =
        keychain_credential(&authority.service_name, &authority.account)?;
    let credentials = netfs_credential_refs(&authority.account, &password)?;
    let url_string = cf_string(authority.url.as_bytes())?;
    let url =
        OwnedCf::new(unsafe { CFURLCreateWithString(ptr::null(), url_string.0, ptr::null()) })?;
    // NetFS owns selection and creation of its default mountpoint.  Supplying
    // either the absent final path or /Volumes as `mountpath` asks it to mount
    // *on* that path and can block in the SMB plug-in.  Admission requires the
    // exact expected path to be absent, and the returned mountpoint is checked
    // below, so accepting NetFS's default is safe only when it is exact.
    let ui_option_key = cf_string(b"UIOption")?;
    let no_ui_value = cf_string(b"NoUI")?;
    let open_options = OwnedCf::new(unsafe {
        CFDictionaryCreateMutable(
            ptr::null(),
            1,
            ptr::addr_of!(kCFTypeDictionaryKeyCallBacks).cast(),
            ptr::addr_of!(kCFTypeDictionaryValueCallBacks).cast(),
        )
        .cast()
    })?;
    unsafe {
        CFDictionarySetValue(open_options.0.cast_mut(), ui_option_key.0, no_ui_value.0);
    }
    let expected_mount_root_string = cf_string(expected_mount_root.as_os_str().as_bytes())?;
    let mut mountpoints: *const c_void = ptr::null();
    let status = unsafe {
        NetFSMountURLSync(
            url.0,
            ptr::null(),
            credentials.username.0,
            credentials.password.0,
            open_options.0.cast_mut(),
            ptr::null_mut(),
            &mut mountpoints,
        )
    };
    if status != 0 || mountpoints.is_null() {
        if !mountpoints.is_null() {
            unsafe { CFRelease(mountpoints) };
        }
        return Err(SmbNoReplaceError::MountRecovery);
    }
    let mountpoints = OwnedCf(mountpoints);
    if unsafe { CFArrayGetCount(mountpoints.0) } != 1 {
        return Err(SmbNoReplaceError::MountRecoveryMismatch);
    }
    let mounted_path = unsafe { CFArrayGetValueAtIndex(mountpoints.0, 0) };
    if mounted_path.is_null()
        || unsafe { CFStringCompare(mounted_path, expected_mount_root_string.0, 0) } != 0
    {
        return Err(SmbNoReplaceError::MountRecoveryMismatch);
    }
    Ok(())
}

fn binding_matches_authority(
    binding: &SmbMountBinding,
    authority: &SmbMountRecoveryAuthority,
    expected_mount_root: &Path,
) -> bool {
    binding.mount_root == expected_mount_root
        && binding.service_name == authority.service_name
        && binding.share == authority.share
        && binding.account == authority.account
        && binding.port == 445
}

fn validate_mount_recovery_root(mount_root: &Path) -> Result<(), SmbNoReplaceError> {
    validate_absolute_lexical_path(mount_root)?;
    if mount_root.parent() != Some(Path::new("/Volumes"))
        || mount_root.file_name().is_none()
        || mount_root.components().count() != 3
    {
        return Err(SmbNoReplaceError::MountRecoveryInput);
    }
    Ok(())
}

fn run_mount_recovery_child_bounded(
    mount_root: &Path,
    url_file: &Path,
    expected_url_sha256: &str,
    service_bundle: &Path,
) -> Result<(), SmbNoReplaceError> {
    let executable = std::env::current_exe().map_err(|_| SmbNoReplaceError::MountRecoveryInput)?;
    let mut child = Command::new(executable)
        .args(["monitor", "smb-mount-recover-child", "--mount-root"])
        .arg(mount_root)
        .arg("--url-file")
        .arg(url_file)
        .arg("--expected-url-sha256")
        .arg(expected_url_sha256)
        .arg("--service-bundle")
        .arg(service_bundle)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| SmbNoReplaceError::MountRecovery)?;
    let deadline = Instant::now() + MOUNT_RECOVERY_TIMEOUT;
    loop {
        match child
            .try_wait()
            .map_err(|_| SmbNoReplaceError::MountRecovery)?
        {
            Some(status) if status.success() => return Ok(()),
            Some(_) => return Err(SmbNoReplaceError::MountRecovery),
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(50)),
            None => {
                child.kill().map_err(|_| SmbNoReplaceError::Ambiguous)?;
                child.wait().map_err(|_| SmbNoReplaceError::Ambiguous)?;
                return Err(SmbNoReplaceError::MountRecoveryTimeout);
            }
        }
    }
}

pub fn run_mount_recovery_child(
    mount_root: &Path,
    url_file: &Path,
    expected_url_sha256: &str,
    service_bundle: &Path,
) -> Result<(), SmbNoReplaceError> {
    validate_mount_recovery_root(mount_root)?;
    let _signer = current_mount_recovery_signer(service_bundle)?;
    let authority = read_mount_recovery_authority(url_file, expected_url_sha256)?;
    // The privileged NetFS operation owns creation of this exact /Volumes
    // mountpoint.  Accepting a caller-created directory would both require
    // weaker ownership semantics and make rollback unable to distinguish it
    // from an unrelated path.
    match fs::symlink_metadata(mount_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => return Err(SmbNoReplaceError::MountRecoveryMismatch),
        Err(_) => return Err(SmbNoReplaceError::MountRecovery),
    }
    if let Err(error) = mount_with_netfs_keychain_credentials(&authority, mount_root) {
        if SmbMountBinding::discover_for_path(mount_root)
            .ok()
            .flatten()
            .is_some()
            && rollback_fresh_recovery_mount(mount_root, &authority).is_err()
        {
            return Err(SmbNoReplaceError::Ambiguous);
        }
        if mount_root.exists() {
            return Err(SmbNoReplaceError::Ambiguous);
        }
        return Err(error);
    }
    let validated = SmbMountBinding::discover_mount_root(mount_root).and_then(|binding| {
        let stat = statfs_for(mount_root)?;
        if binding_matches_authority(&binding, &authority, mount_root)
            && stat.f_owner == unsafe { libc::geteuid() }
        {
            Ok(())
        } else {
            Err(SmbNoReplaceError::MountRecoveryMismatch)
        }
    });
    if let Err(error) = validated {
        if rollback_fresh_recovery_mount(mount_root, &authority).is_err() {
            return Err(SmbNoReplaceError::Ambiguous);
        }
        return Err(error);
    }
    Ok(())
}

fn rollback_fresh_recovery_mount(
    mount_root: &Path,
    authority: &SmbMountRecoveryAuthority,
) -> Result<(), SmbNoReplaceError> {
    let binding = SmbMountBinding::discover_mount_root(mount_root)
        .map_err(|_| SmbNoReplaceError::Ambiguous)?;
    let mount_stat = statfs_for(mount_root).map_err(|_| SmbNoReplaceError::Ambiguous)?;
    if !binding_matches_authority(&binding, authority, mount_root)
        || mount_stat.f_owner != unsafe { libc::geteuid() }
    {
        return Err(SmbNoReplaceError::Ambiguous);
    }
    let mount_root_c = CString::new(mount_root.as_os_str().as_bytes())
        .map_err(|_| SmbNoReplaceError::Ambiguous)?;
    if unsafe { libc::unmount(mount_root_c.as_ptr(), 0) } != 0 {
        return Err(SmbNoReplaceError::Ambiguous);
    }
    if SmbMountBinding::discover_for_path(mount_root)
        .map_err(|_| SmbNoReplaceError::Ambiguous)?
        .is_some()
    {
        return Err(SmbNoReplaceError::Ambiguous);
    }
    // Admission proved this path absent.  NetFS therefore must remove the
    // mountpoint it created.  Do not delete a residual directory: once it is
    // visible after unmount, this process cannot prove it was ours.
    match fs::symlink_metadata(mount_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(SmbNoReplaceError::Ambiguous),
    }
    Ok(())
}

pub fn recover_mount_and_run_disposable_canary(
    mount_root: &Path,
    url_file: &Path,
    expected_url_sha256: &str,
    service_bundle: &Path,
) -> Result<SmbMountRecoveryReceipt, SmbNoReplaceError> {
    validate_mount_recovery_root(mount_root)?;
    let signer = current_mount_recovery_signer(service_bundle)?;
    let authority = read_mount_recovery_authority(url_file, expected_url_sha256)?;
    let discovered = SmbMountBinding::discover_for_path(mount_root)?;
    let (mut binding, recovered_mount) = match discovered {
        Some(binding) => (binding, false),
        None => {
            if mount_root.exists() {
                return Err(SmbNoReplaceError::MountRecoveryMismatch);
            }
            let mounted = run_mount_recovery_child_bounded(
                mount_root,
                url_file,
                expected_url_sha256,
                service_bundle,
            );
            if let Err(error) = mounted {
                if SmbMountBinding::discover_for_path(mount_root)
                    .ok()
                    .flatten()
                    .is_some()
                {
                    if rollback_fresh_recovery_mount(mount_root, &authority).is_err() {
                        return Err(SmbNoReplaceError::Ambiguous);
                    }
                } else if mount_root.exists() {
                    return Err(SmbNoReplaceError::Ambiguous);
                }
                return Err(error);
            }
            let recovered_binding = match SmbMountBinding::discover_mount_root(mount_root) {
                Ok(binding) => binding,
                Err(error) => {
                    if rollback_fresh_recovery_mount(mount_root, &authority).is_err() {
                        return Err(SmbNoReplaceError::Ambiguous);
                    }
                    return Err(error);
                }
            };
            (recovered_binding, true)
        }
    };
    let result = (|| {
        if !binding_matches_authority(&binding, &authority, mount_root) {
            return Err(SmbNoReplaceError::MountRecoveryMismatch);
        }
        let mount_stat = statfs_for(mount_root)?;
        let mount_owner = mount_stat.f_owner;
        if mount_owner != unsafe { libc::geteuid() } {
            return Err(SmbNoReplaceError::MountRecoveryMismatch);
        }
        if binding.auth_reference_sha256.is_empty() {
            let (_, auth_reference_sha256) =
                keychain_credential(&binding.service_name, &binding.account)?;
            binding.auth_reference_sha256 = auth_reference_sha256;
        }
        let binding_proof = binding.redacted_proof()?;
        let mount_observation_sha256 = sha256_bytes(
            serde_json::to_vec(&(&binding.mount_root, &binding.mount_from, mount_owner))
                .map_err(|_| SmbNoReplaceError::MountRecovery)?
                .as_slice(),
        );
        let (_, canary) = prove_disposable_canary(binding)?;
        if canary.binding != binding_proof {
            return Err(SmbNoReplaceError::MountRecoveryMismatch);
        }
        Ok(SmbMountRecoveryReceipt {
            schema_version: 2,
            recovered_mount,
            url_sha256: authority.url_sha256.clone(),
            caller_executable_sha256: signer.executable_sha256,
            caller_designated_requirement_sha256: signer.designated_requirement_sha256,
            mount_owner,
            mount_observation_sha256,
            binding: binding_proof,
            canary,
        })
    })();
    if result.is_err()
        && recovered_mount
        && rollback_fresh_recovery_mount(mount_root, &authority).is_err()
    {
        return Err(SmbNoReplaceError::Ambiguous);
    }
    result
}

/// Removes one explicitly named, strictly validated prior canary residue and
/// then runs a new disposable canary. This never searches for residue paths.
pub fn run_disposable_canary_recovering(
    mount_root: &Path,
    exact_prior_residue: &Path,
) -> Result<SmbNoReplaceCanaryReceipt, SmbNoReplaceError> {
    let binding = SmbMountBinding::discover_mount_root(mount_root)?;
    binding.validate_exact_mount_root(&binding.mount_root)?;
    cleanup_canary_directory(&binding.mount_root, exact_prior_residue, None)?;
    prove_disposable_canary(binding).map(|(_, receipt)| receipt)
}

#[derive(Clone, Copy)]
struct CanaryExpectedEntry {
    name: &'static str,
    identity: FileIdentity,
}

#[derive(Clone, Copy)]
struct CanaryCleanupExpectation {
    directory_device: u64,
    directory_inode: u64,
    entries: [CanaryExpectedEntry; 3],
}

struct ValidatedCanaryEntry {
    name: String,
    identity: FileIdentity,
}

/// Returns the exact session that passed the canary. Callers must retain this
/// session for every governed no-replace rename authorized by the receipt.
pub(crate) fn prove_disposable_canary(
    binding: SmbMountBinding,
) -> Result<(SmbNoReplaceSession, SmbNoReplaceCanaryReceipt), SmbNoReplaceError> {
    binding.validate_exact_mount_root(&binding.mount_root)?;
    let directory = binding
        .mount_root
        .join(format!("{CANARY_DIRECTORY_PREFIX}{}", Uuid::new_v4()));
    fs::create_dir(&directory).map_err(|_| SmbNoReplaceError::Canary)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .map_err(|_| SmbNoReplaceError::Canary)?;
    let metadata = fs::symlink_metadata(&directory).map_err(|_| SmbNoReplaceError::Canary)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        let _ = cleanup_canary_directory(&binding.mount_root, &directory, None);
        return Err(SmbNoReplaceError::Canary);
    }

    let result = run_canary_in_directory(&binding, &directory);
    let expected_cleanup = result
        .as_ref()
        .ok()
        .map(|(_, _, entries)| CanaryCleanupExpectation {
            directory_device: metadata.dev(),
            directory_inode: metadata.ino(),
            entries: *entries,
        });
    let cleanup =
        cleanup_canary_directory(&binding.mount_root, &directory, expected_cleanup.as_ref());
    match (result, cleanup) {
        (Ok((session, mut receipt, _)), Ok(())) => {
            receipt.cleanup_complete = true;
            Ok((session, receipt))
        }
        (_, Err(error)) => Err(error),
        (Err(error), Ok(())) => Err(error),
    }
}

fn run_canary_in_directory(
    binding: &SmbMountBinding,
    directory: &Path,
) -> Result<
    (
        SmbNoReplaceSession,
        SmbNoReplaceCanaryReceipt,
        [CanaryExpectedEntry; 3],
    ),
    SmbNoReplaceError,
> {
    let first_source = directory.join("missing-source");
    let first_destination = directory.join("missing-destination");
    let collision_source = directory.join("collision-source");
    let collision_destination = directory.join("collision-destination");
    let first_bytes = Uuid::new_v4().as_bytes().to_vec();
    let collision_source_bytes = Uuid::new_v4().as_bytes().to_vec();
    let collision_destination_bytes = Uuid::new_v4().as_bytes().to_vec();
    let first_held = create_canary_file(&first_source, &first_bytes)?;
    let collision_source_held = create_canary_file(&collision_source, &collision_source_bytes)?;
    let collision_destination_held =
        create_canary_file(&collision_destination, &collision_destination_bytes)?;
    let first_identity = file_identity(&first_held)?;
    let collision_source_identity = file_identity(&collision_source_held)?;
    let collision_destination_identity = file_identity(&collision_destination_held)?;

    let mut session = SmbNoReplaceSession::connect(binding.clone())?;
    let first_result = session.rename_noreplace(&first_source, &first_destination);
    let first_renamed = !first_source.exists()
        && file_identity_path(&first_destination).ok() == Some(first_identity)
        && read_exact_file(&first_destination).ok().as_ref() == Some(&first_bytes);
    match first_result {
        Ok(SmbRenameResult::Renamed) if first_renamed => {}
        Err(SmbNoReplaceError::Ambiguous) if first_renamed => {}
        _ => return Err(SmbNoReplaceError::Canary),
    }

    if session.rename_noreplace(&collision_source, &collision_destination)?
        != SmbRenameResult::Collision
        || file_identity_path(&collision_source)? != collision_source_identity
        || file_identity_path(&collision_destination)? != collision_destination_identity
        || read_exact_file(&collision_source)? != collision_source_bytes
        || read_exact_file(&collision_destination)? != collision_destination_bytes
    {
        return Err(SmbNoReplaceError::Canary);
    }
    drop(first_held);
    drop(collision_source_held);
    drop(collision_destination_held);
    let receipt = SmbNoReplaceCanaryReceipt {
        schema_version: 2,
        binding: session.binding().redacted_proof()?,
        session: session.proof().clone(),
        missing_target_rename: true,
        collision_status: "STATUS_OBJECT_NAME_COLLISION".to_owned(),
        collision_preserved_both: true,
        cleanup_complete: false,
    };
    Ok((
        session,
        receipt,
        [
            CanaryExpectedEntry {
                name: "missing-destination",
                identity: first_identity,
            },
            CanaryExpectedEntry {
                name: "collision-source",
                identity: collision_source_identity,
            },
            CanaryExpectedEntry {
                name: "collision-destination",
                identity: collision_destination_identity,
            },
        ],
    ))
}

fn create_canary_file(path: &Path, bytes: &[u8]) -> Result<File, SmbNoReplaceError> {
    let mut file = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| SmbNoReplaceError::Canary)?;
    file.write_all(bytes)
        .map_err(|_| SmbNoReplaceError::Canary)?;
    file.sync_all().map_err(|_| SmbNoReplaceError::Canary)?;
    Ok(file)
}

fn canary_cleanup_error(
    stage: SmbCanaryCleanupStage,
    reason: SmbCanaryCleanupReason,
) -> SmbNoReplaceError {
    SmbNoReplaceError::CanaryCleanup { stage, reason }
}

fn canary_cleanup_io_error(
    stage: SmbCanaryCleanupStage,
    error: std::io::Error,
) -> SmbNoReplaceError {
    let reason = match error.kind() {
        std::io::ErrorKind::NotFound => SmbCanaryCleanupReason::NotFound,
        std::io::ErrorKind::PermissionDenied => SmbCanaryCleanupReason::PermissionDenied,
        std::io::ErrorKind::Interrupted => SmbCanaryCleanupReason::Interrupted,
        std::io::ErrorKind::WouldBlock => SmbCanaryCleanupReason::WouldBlock,
        std::io::ErrorKind::TimedOut => SmbCanaryCleanupReason::TimedOut,
        std::io::ErrorKind::ReadOnlyFilesystem => SmbCanaryCleanupReason::ReadOnlyFilesystem,
        std::io::ErrorKind::DirectoryNotEmpty => SmbCanaryCleanupReason::DirectoryNotEmpty,
        std::io::ErrorKind::ResourceBusy => SmbCanaryCleanupReason::ResourceBusy,
        std::io::ErrorKind::InvalidInput => SmbCanaryCleanupReason::InvalidInput,
        std::io::ErrorKind::Unsupported => SmbCanaryCleanupReason::Unsupported,
        _ => SmbCanaryCleanupReason::Io,
    };
    canary_cleanup_error(stage, reason)
}

fn retry_canary_cleanup_interrupted<T>(
    mut operation: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<T> {
    for attempt in 1..=CANARY_CLEANUP_MAX_ATTEMPTS {
        match operation() {
            Err(error)
                if error.kind() == std::io::ErrorKind::Interrupted
                    && attempt < CANARY_CLEANUP_MAX_ATTEMPTS => {}
            result => return result,
        }
    }
    unreachable!("bounded cleanup retry loop always returns on its final attempt")
}

fn exact_canary_directory_path(mount_root: &Path, directory: &Path) -> bool {
    if !mount_root.is_absolute()
        || !directory.is_absolute()
        || directory.parent() != Some(mount_root)
        || directory
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return false;
    }
    let Some(name) = directory.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(suffix) = name.strip_prefix(CANARY_DIRECTORY_PREFIX) else {
        return false;
    };
    Uuid::parse_str(suffix)
        .is_ok_and(|uuid| uuid.get_version_num() == 4 && uuid.to_string() == suffix)
}

fn canary_entry_identity(metadata: &fs::Metadata, directory_device: u64) -> Option<FileIdentity> {
    (metadata.file_type().is_file()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.dev() == directory_device
        && metadata.size() == CANARY_PAYLOAD_BYTES
        && metadata.nlink() == 1
        && metadata.mode() & 0o600 == 0o600
        && metadata.mode() & 0o077 == 0)
        .then_some(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
        })
}

fn cleanup_canary_directory(
    mount_root: &Path,
    directory: &Path,
    expected: Option<&CanaryCleanupExpectation>,
) -> Result<(), SmbNoReplaceError> {
    if !exact_canary_directory_path(mount_root, directory) {
        return Err(canary_cleanup_error(
            SmbCanaryCleanupStage::PathValidation,
            SmbCanaryCleanupReason::PathMismatch,
        ));
    }
    let mount_metadata = retry_canary_cleanup_interrupted(|| fs::symlink_metadata(mount_root))
        .map_err(|error| {
            canary_cleanup_io_error(SmbCanaryCleanupStage::DirectoryInspection, error)
        })?;
    let directory_metadata = retry_canary_cleanup_interrupted(|| fs::symlink_metadata(directory))
        .map_err(|error| {
        canary_cleanup_io_error(SmbCanaryCleanupStage::DirectoryInspection, error)
    })?;
    let directory_identity_valid = mount_metadata.file_type().is_dir()
        && directory_metadata.file_type().is_dir()
        && directory_metadata.uid() == unsafe { libc::geteuid() }
        && directory_metadata.dev() == mount_metadata.dev()
        && directory_metadata.mode() & 0o777 == 0o700
        && expected.is_none_or(|expected| {
            expected.directory_device == directory_metadata.dev()
                && expected.directory_inode == directory_metadata.ino()
        });
    if !directory_identity_valid {
        return Err(canary_cleanup_error(
            SmbCanaryCleanupStage::DirectoryInspection,
            SmbCanaryCleanupReason::DirectoryIdentityMismatch,
        ));
    }

    let read_dir = retry_canary_cleanup_interrupted(|| fs::read_dir(directory))
        .map_err(|error| canary_cleanup_io_error(SmbCanaryCleanupStage::EntryEnumeration, error))?;
    let mut entries = Vec::new();
    for entry in read_dir {
        let entry = entry.map_err(|error| {
            canary_cleanup_io_error(SmbCanaryCleanupStage::EntryEnumeration, error)
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(canary_cleanup_error(
                SmbCanaryCleanupStage::EntryInspection,
                SmbCanaryCleanupReason::UnexpectedEntry,
            ));
        };
        if !CANARY_ENTRY_NAMES.contains(&name) {
            return Err(canary_cleanup_error(
                SmbCanaryCleanupStage::EntryInspection,
                SmbCanaryCleanupReason::UnexpectedEntry,
            ));
        }
        let metadata = retry_canary_cleanup_interrupted(|| fs::symlink_metadata(entry.path()))
            .map_err(|error| {
                canary_cleanup_io_error(SmbCanaryCleanupStage::EntryInspection, error)
            })?;
        let Some(identity) = canary_entry_identity(&metadata, directory_metadata.dev()) else {
            return Err(canary_cleanup_error(
                SmbCanaryCleanupStage::EntryInspection,
                SmbCanaryCleanupReason::EntryIdentityMismatch,
            ));
        };
        if entries.iter().any(|entry: &ValidatedCanaryEntry| {
            entry.name == name
                || (entry.identity.device == identity.device
                    && entry.identity.inode == identity.inode)
        }) {
            return Err(canary_cleanup_error(
                SmbCanaryCleanupStage::EntryInspection,
                SmbCanaryCleanupReason::EntryIdentityMismatch,
            ));
        }
        entries.push(ValidatedCanaryEntry {
            name: name.to_owned(),
            identity,
        });
    }

    if let Some(expected) = expected {
        let identities_match = entries.len() == expected.entries.len()
            && expected.entries.iter().all(|expected| {
                entries
                    .iter()
                    .any(|entry| entry.name == expected.name && entry.identity == expected.identity)
            });
        if !identities_match {
            return Err(canary_cleanup_error(
                SmbCanaryCleanupStage::EntryInspection,
                SmbCanaryCleanupReason::EntryIdentityMismatch,
            ));
        }
    }

    for name in CANARY_ENTRY_NAMES {
        let Some(entry) = entries.iter().find(|entry| entry.name == name) else {
            continue;
        };
        let path = directory.join(name);
        let current =
            retry_canary_cleanup_interrupted(|| fs::symlink_metadata(&path)).map_err(|error| {
                canary_cleanup_io_error(SmbCanaryCleanupStage::EntryInspection, error)
            })?;
        if canary_entry_identity(&current, directory_metadata.dev()) != Some(entry.identity) {
            return Err(canary_cleanup_error(
                SmbCanaryCleanupStage::EntryInspection,
                SmbCanaryCleanupReason::EntryIdentityMismatch,
            ));
        }
        retry_canary_cleanup_interrupted(|| fs::remove_file(&path))
            .map_err(|error| canary_cleanup_io_error(SmbCanaryCleanupStage::EntryRemoval, error))?;
        match retry_canary_cleanup_interrupted(|| fs::symlink_metadata(&path)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(canary_cleanup_io_error(
                    SmbCanaryCleanupStage::EntryRemoval,
                    error,
                ));
            }
            _ => {
                return Err(canary_cleanup_error(
                    SmbCanaryCleanupStage::EntryRemoval,
                    SmbCanaryCleanupReason::RemovalNotConfirmed,
                ));
            }
        }
    }

    let mut remaining = retry_canary_cleanup_interrupted(|| fs::read_dir(directory))
        .map_err(|error| canary_cleanup_io_error(SmbCanaryCleanupStage::EntryEnumeration, error))?;
    match remaining.next() {
        None => {}
        Some(Ok(_)) => {
            return Err(canary_cleanup_error(
                SmbCanaryCleanupStage::EntryEnumeration,
                SmbCanaryCleanupReason::UnexpectedEntry,
            ));
        }
        Some(Err(error)) => {
            return Err(canary_cleanup_io_error(
                SmbCanaryCleanupStage::EntryEnumeration,
                error,
            ));
        }
    }
    drop(remaining);
    let current_directory = retry_canary_cleanup_interrupted(|| fs::symlink_metadata(directory))
        .map_err(|error| {
            canary_cleanup_io_error(SmbCanaryCleanupStage::DirectoryInspection, error)
        })?;
    if current_directory.dev() != directory_metadata.dev()
        || current_directory.ino() != directory_metadata.ino()
        || !current_directory.file_type().is_dir()
        || current_directory.uid() != unsafe { libc::geteuid() }
        || current_directory.mode() & 0o777 != 0o700
    {
        return Err(canary_cleanup_error(
            SmbCanaryCleanupStage::DirectoryInspection,
            SmbCanaryCleanupReason::DirectoryIdentityMismatch,
        ));
    }
    retry_canary_cleanup_interrupted(|| fs::remove_dir(directory))
        .map_err(|error| canary_cleanup_io_error(SmbCanaryCleanupStage::DirectoryRemoval, error))?;
    match retry_canary_cleanup_interrupted(|| fs::symlink_metadata(directory)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(canary_cleanup_io_error(
            SmbCanaryCleanupStage::PostRemovalValidation,
            error,
        )),
        Ok(_) => Err(canary_cleanup_error(
            SmbCanaryCleanupStage::PostRemovalValidation,
            SmbCanaryCleanupReason::RemovalNotConfirmed,
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
}

fn file_identity(file: &File) -> Result<FileIdentity, SmbNoReplaceError> {
    let metadata = file.metadata().map_err(|_| SmbNoReplaceError::Canary)?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
    })
}

fn file_identity_path(path: &Path) -> Result<FileIdentity, SmbNoReplaceError> {
    let file = File::open(path).map_err(|_| SmbNoReplaceError::Canary)?;
    file_identity(&file)
}

fn read_exact_file(path: &Path) -> Result<Vec<u8>, SmbNoReplaceError> {
    let mut file = File::open(path).map_err(|_| SmbNoReplaceError::Canary)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| SmbNoReplaceError::Canary)?;
    Ok(bytes)
}

fn validate_absolute_lexical_path(path: &Path) -> Result<(), SmbNoReplaceError> {
    if !path.is_absolute()
        || path.as_os_str().as_bytes().contains(&0)
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(SmbNoReplaceError::PathBinding);
    }
    Ok(())
}

fn mounted_filesystem_for_path(path: &Path) -> Result<libc::statfs, SmbNoReplaceError> {
    let mut mounts = ptr::null_mut();
    let count = unsafe { libc::getmntinfo(&mut mounts, libc::MNT_NOWAIT) };
    if count <= 0 || mounts.is_null() {
        return Err(SmbNoReplaceError::MountBinding);
    }
    let entries = unsafe { std::slice::from_raw_parts(mounts, count as usize) };
    entries
        .iter()
        .filter_map(|entry| {
            let root = fixed_c_string(&entry.f_mntonname).ok().map(PathBuf::from)?;
            path.starts_with(&root)
                .then_some((root.components().count(), *entry))
        })
        .max_by_key(|(component_count, _)| *component_count)
        .map(|(_, entry)| entry)
        .ok_or(SmbNoReplaceError::MountBinding)
}

fn statfs_for(path: &Path) -> Result<libc::statfs, SmbNoReplaceError> {
    let path =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| SmbNoReplaceError::MountBinding)?;
    let mut value = MaybeUninit::<libc::statfs>::zeroed();
    if unsafe { libc::statfs(path.as_ptr(), value.as_mut_ptr()) } != 0 {
        return Err(SmbNoReplaceError::MountBinding);
    }
    Ok(unsafe { value.assume_init() })
}

fn fixed_c_string<const N: usize>(bytes: &[c_char; N]) -> Result<String, SmbNoReplaceError> {
    let length = bytes.iter().position(|value| *value == 0).unwrap_or(N);
    let raw = bytes[..length]
        .iter()
        .map(|value| *value as u8)
        .collect::<Vec<_>>();
    String::from_utf8(raw).map_err(|_| SmbNoReplaceError::MountBinding)
}

fn parse_mount_from(value: &str) -> Result<(String, String, String), SmbNoReplaceError> {
    let without_prefix = value
        .strip_prefix("//")
        .ok_or(SmbNoReplaceError::MountBinding)?;
    let (authority, share) = without_prefix
        .split_once('/')
        .ok_or(SmbNoReplaceError::MountBinding)?;
    if share.is_empty() || share.contains('/') || authority.matches('@').count() != 1 {
        return Err(SmbNoReplaceError::MountBinding);
    }
    let (account, service) = authority
        .split_once('@')
        .ok_or(SmbNoReplaceError::MountBinding)?;
    if account.is_empty() || service.is_empty() {
        return Err(SmbNoReplaceError::MountBinding);
    }
    Ok((account.to_owned(), service.to_owned(), share.to_owned()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sha256_path(path: &Path) -> String {
    sha256_bytes(path.as_os_str().as_bytes())
}

fn persistent_reference_sha256(bytes: &[u8]) -> Result<String, SmbNoReplaceError> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(SmbNoReplaceError::CredentialReference);
    }
    Ok(sha256_bytes(bytes))
}

fn valid_keychain_password_length(length: u32) -> bool {
    (1..=MAX_KEYCHAIN_PASSWORD_BYTES).contains(&length)
}

fn keychain_credential(
    service: &str,
    account: &str,
) -> Result<(Zeroizing<String>, String), SmbNoReplaceError> {
    // The C boundary serializes the process-global Keychain interaction flag
    // across both metadata lookup and secret copy, then restores its prior
    // value. Pre-toggling it here races concurrent workers and can re-enable
    // UI during another no-UI read.
    keychain_credential_without_interaction(service, account)
}

fn keychain_credential_without_interaction(
    service: &str,
    account: &str,
) -> Result<(Zeroizing<String>, String), SmbNoReplaceError> {
    let mut length = 0_u32;
    let mut data: *mut c_void = ptr::null_mut();
    let mut item: *const c_void = ptr::null();
    let service =
        std::ffi::CString::new(service).map_err(|_| SmbNoReplaceError::CredentialReference)?;
    let account =
        std::ffi::CString::new(account).map_err(|_| SmbNoReplaceError::CredentialReference)?;
    // This C boundary enumerates all candidates, filters the complete
    // dedicated tuple, and rejects zero or multiple matches. Never use the
    // first-match Security.framework convenience lookup here.
    let status = unsafe {
        keychain_copy_exact_smb_credential(
            service.as_ptr(),
            account.as_ptr(),
            &mut length,
            &mut data,
            &mut item,
        )
    };
    if status != 0 || data.is_null() || !valid_keychain_password_length(length) || item.is_null() {
        unsafe { keychain_zeroize_and_free_exact_smb_credential(length, data) };
        if !item.is_null() {
            unsafe { CFRelease(item) };
        }
        return Err(match status {
            1 => SmbNoReplaceError::CredentialNotFound,
            3 => SmbNoReplaceError::CredentialInteraction,
            4 => SmbNoReplaceError::CredentialAccess,
            _ => SmbNoReplaceError::CredentialReference,
        });
    }
    let bytes = unsafe { std::slice::from_raw_parts_mut(data.cast::<u8>(), length as usize) };
    let secret = Zeroizing::new(bytes.to_vec());
    let password = std::str::from_utf8(&secret)
        .map(str::to_owned)
        .map(Zeroizing::new)
        .map_err(|_| SmbNoReplaceError::CredentialReference);
    unsafe { keychain_zeroize_and_free_exact_smb_credential(length, data) };
    let mut persistent_reference: *const c_void = ptr::null();
    let persistent_status =
        unsafe { SecKeychainItemCreatePersistentReference(item, &mut persistent_reference) };
    let reference_sha256 = if persistent_status == 0 && !persistent_reference.is_null() {
        let length = unsafe { CFDataGetLength(persistent_reference) };
        let pointer = unsafe { CFDataGetBytePtr(persistent_reference) };
        if !(1..=4096).contains(&length) || pointer.is_null() {
            Err(SmbNoReplaceError::CredentialReference)
        } else {
            let length = length as usize;
            persistent_reference_sha256(unsafe { std::slice::from_raw_parts(pointer, length) })
        }
    } else {
        Err(SmbNoReplaceError::CredentialReference)
    };
    if !persistent_reference.is_null() {
        unsafe { CFRelease(persistent_reference) };
    }
    unsafe { CFRelease(item) };
    Ok((password?, reference_sha256?))
}

fn deterministic_connection_endpoint(service: &str) -> Result<(String, u16), SmbNoReplaceError> {
    let suffix = "._smb._tcp.local";
    let instance = service
        .strip_suffix(suffix)
        .filter(|value| !value.is_empty())
        .ok_or(SmbNoReplaceError::ServiceResolution)?;
    if instance.len() > 63
        || instance.starts_with('-')
        || instance.ends_with('-')
        || !instance
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(SmbNoReplaceError::ServiceResolution);
    }
    // This is the one deterministic endpoint admitted for service-style
    // smbfs mounts. It is not a fallback: the cross-view canary must then
    // prove that this exact signed SMB session mutates the mounted share.
    Ok((format!("{instance}.local"), 445))
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn keychain_copy_exact_smb_credential(
        server: *const c_char,
        account: *const c_char,
        password_length: *mut u32,
        password_data: *mut *mut c_void,
        item_ref: *mut *const c_void,
    ) -> i32;
    fn keychain_zeroize_and_free_exact_smb_credential(length: u32, data: *mut c_void);
    fn SecKeychainItemCreatePersistentReference(
        item_ref: *const c_void,
        persistent_item_ref: *mut *const c_void,
    ) -> i32;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: *const c_void);
    fn CFDataGetLength(data: *const c_void) -> isize;
    fn CFDataGetBytePtr(data: *const c_void) -> *const u8;
    fn CFStringCreateWithBytes(
        allocator: *const c_void,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        is_external_representation: u8,
    ) -> *const c_void;
    fn CFURLCreateWithString(
        allocator: *const c_void,
        url_string: *const c_void,
        base_url: *const c_void,
    ) -> *const c_void;
    fn CFDictionaryCreateMutable(
        allocator: *const c_void,
        capacity: isize,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> *mut c_void;
    fn CFDictionarySetValue(dictionary: *mut c_void, key: *const c_void, value: *const c_void);
    fn CFArrayGetCount(array: *const c_void) -> isize;
    fn CFArrayGetValueAtIndex(array: *const c_void, index: isize) -> *const c_void;
    fn CFStringCompare(left: *const c_void, right: *const c_void, options: u64) -> isize;

    static kCFTypeDictionaryKeyCallBacks: u8;
    static kCFTypeDictionaryValueCallBacks: u8;
}

#[link(name = "NetFS", kind = "framework")]
unsafe extern "C" {
    fn NetFSMountURLSync(
        url: *const c_void,
        mount_path: *const c_void,
        user: *const c_void,
        password: *const c_void,
        open_options: *mut c_void,
        mount_options: *mut c_void,
        mountpoints: *mut *const c_void,
    ) -> c_int;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_recovery_signer_requires_exact_team_requirement_and_helper_identifier() {
        let canonical = "designated => anchor apple generic and identifier \"com.icloudpd-optimizer.helper\" and certificate leaf[subject.OU] = \"ABCDEFGHIJ\"";
        let valid = format!("Executable=/sealed/helper\n{canonical}\n");
        assert_eq!(
            parse_mount_recovery_designated_requirement(valid.as_bytes(), b"").unwrap(),
            canonical
        );
        assert_eq!(
            sha256_bytes(
                parse_mount_recovery_designated_requirement(valid.as_bytes(), b"")
                    .unwrap()
                    .as_bytes(),
            ),
            sha256_bytes(canonical.as_bytes())
        );
        assert!(
            parse_mount_recovery_designated_requirement(
                format!(
                    "Executable=/sealed/helper\n{}\n",
                    canonical.trim_start_matches("designated => ")
                )
                .as_bytes(),
                b"",
            )
            .is_err()
        );
        assert!(parse_mount_recovery_designated_requirement(
            b"Executable=/sealed/helper\ndesignated => anchor apple generic and identifier \"other\" and certificate leaf[subject.OU] = \"ABCDEFGHIJ\"\n",
            b"",
        )
        .is_err());
        assert!(
            parse_mount_recovery_designated_requirement(valid.as_bytes(), canonical.as_bytes(),)
                .is_err()
        );
    }

    #[test]
    fn mount_recovery_authority_is_owner_only_hash_bound_and_canonical() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("url");
        let url = "smb://user@home._smb._tcp.local/home";
        fs::write(&path, format!("{url}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let expected = sha256_bytes(url.as_bytes());
        let authority = read_mount_recovery_authority(&path, &expected).unwrap();
        assert_eq!(authority.url, url);
        assert_eq!(authority.service_name, "home._smb._tcp.local");
        assert_eq!(authority.account, "user");
        assert_eq!(authority.share, "home");

        fs::write(&path, "smb://user:secret@home._smb._tcp.local/home\n").unwrap();
        assert!(matches!(
            read_mount_recovery_authority(
                &path,
                &sha256_bytes(b"smb://user:secret@home._smb._tcp.local/home")
            ),
            Err(SmbNoReplaceError::MountRecoveryInput)
        ));
    }

    #[test]
    fn sealed_authority_builds_only_a_lexical_unmounted_credential_binding() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("url");
        let url = "smb://user@home._smb._tcp.local/home";
        fs::write(&path, url).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let binding = credential_binding_from_sealed_authority(
            Path::new("/Volumes/home"),
            &path,
            &sha256_bytes(url.as_bytes()),
        )
        .unwrap();
        assert_eq!(binding.mount_root, Path::new("/Volumes/home"));
        assert_eq!(binding.service_name, "home._smb._tcp.local");
        assert_eq!(binding.account, "user");
        assert_eq!(binding.share, "home");
        assert_eq!(binding.port, 445);
    }

    fn mount_statfs(fstype: &str, mount_root: &str, mount_from: &str) -> libc::statfs {
        fn write_c_string<const N: usize>(destination: &mut [c_char; N], value: &str) {
            assert!(value.len() < N);
            for (destination, source) in destination.iter_mut().zip(value.bytes()) {
                *destination = source as c_char;
            }
        }

        let mut stat = unsafe { MaybeUninit::<libc::statfs>::zeroed().assume_init() };
        write_c_string(&mut stat.f_fstypename, fstype);
        write_c_string(&mut stat.f_mntonname, mount_root);
        write_c_string(&mut stat.f_mntfromname, mount_from);
        stat
    }

    #[test]
    fn rejects_relative_parent_and_root_paths() {
        assert!(matches!(
            validate_absolute_lexical_path(Path::new("relative/file")),
            Err(SmbNoReplaceError::PathBinding)
        ));
        assert!(matches!(
            validate_absolute_lexical_path(Path::new("/Volumes/home/../other")),
            Err(SmbNoReplaceError::PathBinding)
        ));
        assert!(validate_absolute_lexical_path(Path::new("/Volumes/home/file")).is_ok());
    }

    fn create_cleanup_test_directory(mount_root: &Path, names: &[&str]) -> PathBuf {
        let directory = mount_root.join(format!("{CANARY_DIRECTORY_PREFIX}{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        for name in names {
            let path = directory.join(name);
            fs::write(&path, [7_u8; CANARY_PAYLOAD_BYTES as usize]).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        directory
    }

    #[test]
    fn cleanup_accepts_only_one_exact_direct_child_canary_path() {
        let mount = tempfile::tempdir().unwrap();
        let uuid = Uuid::new_v4();
        let exact = mount
            .path()
            .join(format!("{CANARY_DIRECTORY_PREFIX}{uuid}"));
        assert!(exact_canary_directory_path(mount.path(), &exact));
        assert!(!exact_canary_directory_path(
            mount.path(),
            &mount.path().join(format!(
                "{CANARY_DIRECTORY_PREFIX}{}",
                uuid.to_string().to_uppercase()
            ))
        ));
        assert!(!exact_canary_directory_path(
            mount.path(),
            &mount
                .path()
                .join("nested")
                .join(format!("{CANARY_DIRECTORY_PREFIX}{}", Uuid::new_v4()))
        ));
        assert!(!exact_canary_directory_path(
            mount.path(),
            &mount.path().join(format!("unrelated-{uuid}"))
        ));
    }

    #[test]
    fn cleanup_removes_only_exact_validated_expected_canary_entries() {
        let mount = tempfile::tempdir().unwrap();
        let directory = create_cleanup_test_directory(
            mount.path(),
            &[
                "missing-destination",
                "collision-source",
                "collision-destination",
            ],
        );
        let directory_metadata = fs::symlink_metadata(&directory).unwrap();
        let expected = CanaryCleanupExpectation {
            directory_device: directory_metadata.dev(),
            directory_inode: directory_metadata.ino(),
            entries: [
                CanaryExpectedEntry {
                    name: "missing-destination",
                    identity: file_identity_path(&directory.join("missing-destination")).unwrap(),
                },
                CanaryExpectedEntry {
                    name: "collision-source",
                    identity: file_identity_path(&directory.join("collision-source")).unwrap(),
                },
                CanaryExpectedEntry {
                    name: "collision-destination",
                    identity: file_identity_path(&directory.join("collision-destination")).unwrap(),
                },
            ],
        };
        cleanup_canary_directory(mount.path(), &directory, Some(&expected)).unwrap();
        assert!(!directory.exists());
    }

    #[test]
    fn cleanup_recovers_one_exact_validated_prior_residue_without_a_manifest() {
        let mount = tempfile::tempdir().unwrap();
        let directory = create_cleanup_test_directory(
            mount.path(),
            &[
                "missing-destination",
                "collision-source",
                "collision-destination",
            ],
        );
        cleanup_canary_directory(mount.path(), &directory, None).unwrap();
        assert!(!directory.exists());
    }

    #[test]
    fn cleanup_rejects_changed_identity_before_removing_anything() {
        let mount = tempfile::tempdir().unwrap();
        let directory = create_cleanup_test_directory(
            mount.path(),
            &[
                "missing-destination",
                "collision-source",
                "collision-destination",
            ],
        );
        let directory_metadata = fs::symlink_metadata(&directory).unwrap();
        let expected = CanaryCleanupExpectation {
            directory_device: directory_metadata.dev(),
            directory_inode: directory_metadata.ino(),
            entries: [
                CanaryExpectedEntry {
                    name: "missing-destination",
                    identity: file_identity_path(&directory.join("missing-destination")).unwrap(),
                },
                CanaryExpectedEntry {
                    name: "collision-source",
                    identity: file_identity_path(&directory.join("collision-source")).unwrap(),
                },
                CanaryExpectedEntry {
                    name: "collision-destination",
                    identity: file_identity_path(&directory.join("collision-destination")).unwrap(),
                },
            ],
        };
        let changed = directory.join("collision-source");
        let replacement = directory.join("missing-source");
        fs::write(&replacement, [8_u8; CANARY_PAYLOAD_BYTES as usize]).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::remove_file(&changed).unwrap();
        fs::rename(replacement, &changed).unwrap();

        let error =
            cleanup_canary_directory(mount.path(), &directory, Some(&expected)).unwrap_err();
        assert_eq!(
            error.to_string(),
            "SMB no-replace gate failed: category=canary_cleanup stage=entry_inspection reason=entry_identity_mismatch"
        );
        for name in [
            "missing-destination",
            "collision-source",
            "collision-destination",
        ] {
            assert!(directory.join(name).exists());
        }
    }

    #[test]
    fn cleanup_rejects_unexpected_entry_before_removing_anything() {
        let mount = tempfile::tempdir().unwrap();
        let directory = create_cleanup_test_directory(
            mount.path(),
            &["missing-destination", "unrelated-user-file"],
        );
        let error = cleanup_canary_directory(mount.path(), &directory, None).unwrap_err();
        assert_eq!(
            error.to_string(),
            "SMB no-replace gate failed: category=canary_cleanup stage=entry_inspection reason=unexpected_entry"
        );
        assert!(directory.join("missing-destination").exists());
        assert!(directory.join("unrelated-user-file").exists());
    }

    #[test]
    fn cleanup_rejects_wrong_size_before_removing_anything() {
        let mount = tempfile::tempdir().unwrap();
        let directory = create_cleanup_test_directory(
            mount.path(),
            &["missing-destination", "collision-source"],
        );
        fs::write(directory.join("collision-source"), [9_u8; 15]).unwrap();
        let error = cleanup_canary_directory(mount.path(), &directory, None).unwrap_err();
        assert_eq!(
            error.to_string(),
            "SMB no-replace gate failed: category=canary_cleanup stage=entry_inspection reason=entry_identity_mismatch"
        );
        assert!(directory.join("missing-destination").exists());
        assert!(directory.join("collision-source").exists());
    }

    #[test]
    fn cleanup_retries_only_interrupted_operations_with_a_small_bound() {
        let mut eventually_succeeds = 0;
        let result = retry_canary_cleanup_interrupted(|| {
            eventually_succeeds += 1;
            if eventually_succeeds < CANARY_CLEANUP_MAX_ATTEMPTS {
                Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
            } else {
                Ok(())
            }
        });
        assert!(result.is_ok());
        assert_eq!(eventually_succeeds, CANARY_CLEANUP_MAX_ATTEMPTS);

        let mut interrupted = 0;
        let error = retry_canary_cleanup_interrupted::<()>(|| {
            interrupted += 1;
            Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
        })
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
        assert_eq!(interrupted, CANARY_CLEANUP_MAX_ATTEMPTS);

        let mut permission_denied = 0;
        let error = retry_canary_cleanup_interrupted::<()>(|| {
            permission_denied += 1;
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
        })
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(permission_denied, 1);
    }

    #[test]
    fn cleanup_io_errors_emit_only_fixed_stage_and_reason_codes() {
        let error = canary_cleanup_io_error(
            SmbCanaryCleanupStage::EntryRemoval,
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private mount and filename must not escape",
            ),
        );
        assert_eq!(
            error.to_string(),
            "SMB no-replace gate failed: category=canary_cleanup stage=entry_removal reason=permission_denied"
        );
        assert!(!error.to_string().contains("private"));
        assert!(!error.to_string().contains("filename"));
    }

    #[test]
    fn binding_proof_redacts_all_raw_identifiers() {
        let binding = SmbMountBinding {
            mount_root: PathBuf::from("/Volumes/private-share"),
            mount_from: "//secret-user@host._smb._tcp.local/secret-share".to_owned(),
            service_name: "host._smb._tcp.local".to_owned(),
            resolved_host: "host.local.".to_owned(),
            port: 445,
            share: "secret-share".to_owned(),
            account: "secret-user".to_owned(),
            auth_reference_sha256: "a".repeat(64),
        };
        let encoded = serde_json::to_string(&binding.redacted_proof().unwrap()).unwrap();
        for secret in [
            "private-share",
            "secret-user",
            "secret-share",
            "host._smb._tcp.local",
            "host.local",
        ] {
            assert!(!encoded.contains(secret));
        }
        assert!(encoded.contains(&"a".repeat(64)));
    }

    #[test]
    fn auth_binding_uses_only_exact_persistent_reference_bytes() {
        let first = persistent_reference_sha256(b"persistent-keychain-reference-one").unwrap();
        let second = persistent_reference_sha256(b"persistent-keychain-reference-two").unwrap();
        let reconstructed_query =
            sha256_bytes(b"internet-password\0host._smb._tcp.local\0user\0smb");
        assert_ne!(first, second);
        assert_ne!(first, reconstructed_query);
        assert_ne!(second, reconstructed_query);
        assert!(persistent_reference_sha256(&[]).is_err());
        assert!(persistent_reference_sha256(&vec![0; 4097]).is_err());
    }

    #[test]
    fn keychain_password_copy_has_a_small_explicit_bound() {
        assert!(!valid_keychain_password_length(0));
        assert!(valid_keychain_password_length(1));
        assert!(valid_keychain_password_length(MAX_KEYCHAIN_PASSWORD_BYTES));
        assert!(!valid_keychain_password_length(
            MAX_KEYCHAIN_PASSWORD_BYTES + 1
        ));
    }

    #[test]
    fn keychain_credential_delegates_no_ui_state_to_the_serializing_native_boundary() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/smb_noreplace.rs"));
        let start = source.find("fn keychain_credential(").unwrap();
        let body = &source[start
            ..source
                .find("fn keychain_credential_without_interaction(")
                .unwrap()];
        assert!(body.contains("keychain_credential_without_interaction(service, account)"));
        assert!(!body.contains("SecKeychainSetUserInteractionAllowed"));
    }

    #[test]
    fn keychain_lookup_enumerates_the_complete_dedicated_tuple() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/smb_noreplace.rs"));
        let start = source
            .find("fn keychain_credential_without_interaction(")
            .unwrap();
        let body = &source[start
            ..source
                .find("fn deterministic_connection_endpoint(")
                .unwrap()];
        assert!(body.contains("keychain_copy_exact_smb_credential"));
        assert!(!body.contains("SecKeychainFindInternetPassword"));
        assert!(body.contains("keychain_zeroize_and_free_exact_smb_credential"));
    }

    #[test]
    fn netfs_credential_refs_are_non_null_and_keep_the_zeroizing_password_type() {
        let password: Zeroizing<String> = Zeroizing::new("test-password".to_owned());
        let credentials = netfs_credential_refs("exact-account", &password).unwrap();
        assert!(!credentials.username.0.is_null());
        assert!(!credentials.password.0.is_null());
    }

    #[test]
    fn mount_recovery_uses_only_the_exact_keychain_credential_in_process() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/smb_noreplace.rs"));
        let start = source
            .find("fn mount_with_netfs_keychain_credentials(")
            .unwrap();
        let body = &source[start..source.find("fn binding_matches_authority(").unwrap()];
        assert!(body.contains("keychain_credential(&authority.service_name, &authority.account)"));
        assert!(body.contains("netfs_credential_refs(&authority.account, &password)"));
        assert!(body.contains("credentials.username.0,"));
        assert!(body.contains("credentials.password.0,"));
        assert!(!body.contains("ptr::null(),\n            ptr::null(),"));
        assert!(!body.contains("Command::"));
        assert!(!body.contains("std::env::"));
        assert!(!body.contains("fs::write"));
    }

    #[test]
    fn netfs_uses_the_default_mountpoint_for_an_absent_volumes_path() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/smb_noreplace.rs"));
        let start = source
            .find("fn mount_with_netfs_keychain_credentials(")
            .unwrap();
        let body = &source[start..source.find("fn binding_matches_authority(").unwrap()];
        assert!(body.contains("NetFSMountURLSync(\n            url.0,\n            ptr::null(),"));
        assert!(body.contains("ptr::null_mut(),"));
        assert!(!body.contains("mount_at_directory_key"));
        assert!(!body.contains("kCFBooleanTrue"));
    }

    #[test]
    fn recovery_leaves_an_absent_volumes_mountpoint_for_privileged_netfs() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/smb_noreplace.rs"));
        let start = source
            .find("pub fn recover_mount_and_run_disposable_canary(")
            .unwrap();
        let body = &source[start..source.find("/// Removes one explicitly named").unwrap()];
        assert!(body.contains("if mount_root.exists()"));
        assert!(body.contains("run_mount_recovery_child_bounded("));
        assert!(!body.contains("fs::create_dir(mount_root)"));
        assert!(!body.contains("fs::set_permissions(mount_root"));
    }

    #[test]
    fn recovery_child_rejects_a_preexisting_mountpoint_before_netfs() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/smb_noreplace.rs"));
        let start = source.find("pub fn run_mount_recovery_child(").unwrap();
        let body = &source[start..source.find("fn rollback_fresh_recovery_mount(").unwrap()];
        let admission = body.find("match fs::symlink_metadata(mount_root)").unwrap();
        let netfs = body.find("mount_with_netfs_keychain_credentials").unwrap();
        assert!(admission < netfs);
        assert!(body.contains("Ok(_) => return Err(SmbNoReplaceError::MountRecoveryMismatch)"));
        assert!(body.contains("ErrorKind::NotFound"));
    }

    #[test]
    fn recovery_validates_exact_binding_and_leaves_residual_path_ambiguous() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/smb_noreplace.rs"));
        let child_start = source.find("pub fn run_mount_recovery_child(").unwrap();
        let child = &source[child_start..source.find("fn rollback_fresh_recovery_mount(").unwrap()];
        assert!(child.contains("SmbMountBinding::discover_mount_root(mount_root)"));
        assert!(child.contains("binding_matches_authority(&binding, &authority, mount_root)"));
        assert!(child.contains("stat.f_owner == unsafe { libc::geteuid() }"));

        let rollback_start = source.find("fn rollback_fresh_recovery_mount(").unwrap();
        let rollback = &source[rollback_start
            ..source
                .find("pub fn recover_mount_and_run_disposable_canary(")
                .unwrap()];
        assert!(rollback.contains("unsafe { libc::unmount(mount_root_c.as_ptr(), 0) }"));
        assert!(rollback.contains("ErrorKind::NotFound"));
        assert!(rollback.contains("SmbNoReplaceError::Ambiguous"));
        assert!(!rollback.contains("fs::remove_dir"));
    }

    #[test]
    fn binding_proof_rejects_missing_persistent_item_reference() {
        let binding = SmbMountBinding {
            mount_root: PathBuf::from("/Volumes/share"),
            mount_from: "//user@host._smb._tcp.local/share".to_owned(),
            service_name: "host._smb._tcp.local".to_owned(),
            resolved_host: "host.local".to_owned(),
            port: 445,
            share: "share".to_owned(),
            account: "user".to_owned(),
            auth_reference_sha256: String::new(),
        };
        assert!(matches!(
            binding.redacted_proof(),
            Err(SmbNoReplaceError::CredentialReference)
        ));
    }

    #[test]
    fn parses_only_exact_single_share_mounts() {
        assert_eq!(
            parse_mount_from("//home@home._smb._tcp.local/home").unwrap(),
            (
                "home".to_owned(),
                "home._smb._tcp.local".to_owned(),
                "home".to_owned()
            )
        );
        for invalid in [
            "/home",
            "//home._smb._tcp.local/home",
            "//home@host/share/nested",
            "//home@@host/share",
        ] {
            assert!(parse_mount_from(invalid).is_err());
        }
    }

    #[test]
    fn service_mount_has_one_deterministic_connection_endpoint() {
        assert_eq!(
            deterministic_connection_endpoint("zeus._smb._tcp.local").unwrap(),
            ("zeus.local".to_owned(), 445)
        );
        for invalid in [
            "zeus.local",
            "zeus._smb._tcp.local.",
            "friendly server._smb._tcp.local",
            "-zeus._smb._tcp.local",
            "zeus-._smb._tcp.local",
        ] {
            assert!(deterministic_connection_endpoint(invalid).is_err());
        }
    }

    #[test]
    fn session_security_rejects_every_downgrade_and_binding_mismatch() {
        let valid = SessionSecurityFacts {
            dialect_is_smb311: true,
            account_nonempty: true,
            session_signing_required: true,
            session_is_guest: false,
            session_is_null: false,
            signing_active: true,
            diagnostic_session_present: true,
            diagnostic_session_matches: true,
            encryption_active: false,
            session_encryption_required: false,
            share_encryption_required: false,
            share_matches: true,
            server_matches: true,
            is_dfs: false,
        };
        assert!(session_security_valid(valid));
        for (invalid, reason) in [
            (
                SessionSecurityFacts {
                    dialect_is_smb311: false,
                    ..valid
                },
                SmbSessionSecurityReason::DialectNotSmb311,
            ),
            (
                SessionSecurityFacts {
                    account_nonempty: false,
                    ..valid
                },
                SmbSessionSecurityReason::EmptyAccount,
            ),
            (
                SessionSecurityFacts {
                    session_signing_required: false,
                    ..valid
                },
                SmbSessionSecurityReason::SessionSigningDisabled,
            ),
            (
                SessionSecurityFacts {
                    session_is_guest: true,
                    ..valid
                },
                SmbSessionSecurityReason::GuestSession,
            ),
            (
                SessionSecurityFacts {
                    session_is_null: true,
                    ..valid
                },
                SmbSessionSecurityReason::NullSession,
            ),
            (
                SessionSecurityFacts {
                    signing_active: false,
                    ..valid
                },
                SmbSessionSecurityReason::SigningInactive,
            ),
            (
                SessionSecurityFacts {
                    diagnostic_session_present: false,
                    diagnostic_session_matches: false,
                    ..valid
                },
                SmbSessionSecurityReason::DiagnosticSessionMissing,
            ),
            (
                SessionSecurityFacts {
                    diagnostic_session_matches: false,
                    ..valid
                },
                SmbSessionSecurityReason::DiagnosticSessionMismatch,
            ),
            (
                SessionSecurityFacts {
                    share_matches: false,
                    ..valid
                },
                SmbSessionSecurityReason::ShareMismatch,
            ),
            (
                SessionSecurityFacts {
                    server_matches: false,
                    ..valid
                },
                SmbSessionSecurityReason::ServerMismatch,
            ),
            (
                SessionSecurityFacts {
                    is_dfs: true,
                    ..valid
                },
                SmbSessionSecurityReason::DfsShare,
            ),
        ] {
            assert!(!session_security_valid(invalid));
            assert_eq!(session_security_failure(invalid), Some(reason));
        }
    }

    #[test]
    fn pre_tree_connect_identity_gate_rejects_exact_guest_and_null_flags() {
        assert!(authenticated_session_identity(false, false));
        assert!(!authenticated_session_identity(true, false));
        assert!(!authenticated_session_identity(false, true));
        assert!(!authenticated_session_identity(true, true));
        assert_eq!(
            session_identity_failure(true, true),
            Some(SmbSessionSecurityReason::GuestAndNullSession)
        );
    }

    #[test]
    fn session_security_errors_emit_only_fixed_stage_and_reason_codes() {
        let authentication = smb_operation_error(
            SmbSessionSecurityStage::SessionSetup,
            smb2::Error::Auth {
                message: "credential and server detail must not escape".to_owned(),
            },
        );
        assert_eq!(
            authentication.to_string(),
            "SMB no-replace gate failed: category=session_security stage=session_setup reason=authentication_rejected"
        );
        assert!(!authentication.to_string().contains("credential"));

        let referral = smb_operation_error(
            SmbSessionSecurityStage::TreeConnect,
            smb2::Error::DfsReferralRequired {
                path: "/private/redacted/path".to_owned(),
            },
        );
        assert_eq!(
            referral.to_string(),
            "SMB no-replace gate failed: category=session_security stage=tree_connect reason=dfs_referral"
        );
        assert!(!referral.to_string().contains("private"));

        let access_denied = smb_operation_error(
            SmbSessionSecurityStage::TreeConnect,
            smb2::Error::Protocol {
                status: NtStatus::ACCESS_DENIED,
                command: smb2::types::Command::TreeConnect,
            },
        );
        assert_eq!(
            access_denied.to_string(),
            "SMB no-replace gate failed: category=session_security stage=tree_connect reason=access_denied"
        );

        let transport = smb_operation_error(
            SmbSessionSecurityStage::Connect,
            smb2::Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private host and credential detail must not escape",
            )),
        );
        assert_eq!(
            transport.to_string(),
            "SMB no-replace gate failed: category=session_security stage=connect reason=transport_permission_denied"
        );
        assert!(!transport.to_string().contains("private"));
        assert!(!transport.to_string().contains("credential"));
    }

    #[test]
    fn transport_io_errors_emit_only_fixed_error_kind_codes() {
        for (kind, reason) in [
            (
                std::io::ErrorKind::PermissionDenied,
                SmbSessionSecurityReason::TransportPermissionDenied,
            ),
            (
                std::io::ErrorKind::ConnectionRefused,
                SmbSessionSecurityReason::TransportConnectionRefused,
            ),
            (
                std::io::ErrorKind::ConnectionReset,
                SmbSessionSecurityReason::TransportConnectionReset,
            ),
            (
                std::io::ErrorKind::HostUnreachable,
                SmbSessionSecurityReason::TransportHostUnreachable,
            ),
            (
                std::io::ErrorKind::NetworkUnreachable,
                SmbSessionSecurityReason::TransportNetworkUnreachable,
            ),
            (
                std::io::ErrorKind::ConnectionAborted,
                SmbSessionSecurityReason::TransportConnectionAborted,
            ),
            (
                std::io::ErrorKind::NotConnected,
                SmbSessionSecurityReason::TransportNotConnected,
            ),
            (
                std::io::ErrorKind::AddrInUse,
                SmbSessionSecurityReason::TransportAddressInUse,
            ),
            (
                std::io::ErrorKind::AddrNotAvailable,
                SmbSessionSecurityReason::TransportAddressNotAvailable,
            ),
            (
                std::io::ErrorKind::NetworkDown,
                SmbSessionSecurityReason::TransportNetworkDown,
            ),
            (
                std::io::ErrorKind::TimedOut,
                SmbSessionSecurityReason::TransportTimedOut,
            ),
            (
                std::io::ErrorKind::WouldBlock,
                SmbSessionSecurityReason::TransportWouldBlock,
            ),
            (
                std::io::ErrorKind::Interrupted,
                SmbSessionSecurityReason::TransportInterrupted,
            ),
            (
                std::io::ErrorKind::UnexpectedEof,
                SmbSessionSecurityReason::TransportUnexpectedEof,
            ),
            (
                std::io::ErrorKind::InvalidData,
                SmbSessionSecurityReason::TransportIo,
            ),
        ] {
            assert_eq!(transport_io_reason(kind), reason);
        }
    }

    #[test]
    fn session_security_enforces_exact_session_and_share_encryption_policy() {
        let mut facts = SessionSecurityFacts {
            dialect_is_smb311: true,
            account_nonempty: true,
            session_signing_required: true,
            session_is_guest: false,
            session_is_null: false,
            signing_active: true,
            diagnostic_session_present: true,
            diagnostic_session_matches: true,
            encryption_active: true,
            session_encryption_required: true,
            share_encryption_required: false,
            share_matches: true,
            server_matches: true,
            is_dfs: false,
        };
        assert!(session_security_valid(facts));
        facts.encryption_active = false;
        assert!(!session_security_valid(facts));
        assert_eq!(
            session_security_failure(facts),
            Some(SmbSessionSecurityReason::RequiredEncryptionInactive)
        );
        facts.session_encryption_required = false;
        facts.share_encryption_required = true;
        assert!(!session_security_valid(facts));
        facts.encryption_active = true;
        assert!(session_security_valid(facts));
        facts.share_encryption_required = false;
        assert!(!session_security_valid(facts));
        assert_eq!(
            session_security_failure(facts),
            Some(SmbSessionSecurityReason::UnexpectedEncryptionActive)
        );
    }

    #[test]
    fn relative_share_path_rejects_wrong_mount_and_mount_root() {
        let binding = SmbMountBinding {
            mount_root: PathBuf::from("/Volumes/share"),
            mount_from: "//user@host._smb._tcp.local/share".to_owned(),
            service_name: "host._smb._tcp.local".to_owned(),
            resolved_host: "host.local.".to_owned(),
            port: 445,
            share: "share".to_owned(),
            account: "user".to_owned(),
            auth_reference_sha256: "a".repeat(64),
        };
        assert_eq!(
            binding
                .relative_share_path(Path::new("/Volumes/share/folder/file"))
                .unwrap(),
            "folder/file"
        );
        assert!(
            binding
                .relative_share_path(Path::new("/Volumes/other/file"))
                .is_err()
        );
        assert!(
            binding
                .relative_share_path(Path::new("/Volumes/share"))
                .is_err()
        );
    }

    #[test]
    fn exact_mount_root_discovery_validation_reaches_the_canary_gate() {
        let binding = SmbMountBinding {
            mount_root: PathBuf::from("/Volumes/share"),
            mount_from: "//user@host._smb._tcp.local/share".to_owned(),
            service_name: "host._smb._tcp.local".to_owned(),
            resolved_host: "host.local.".to_owned(),
            port: 445,
            share: "share".to_owned(),
            account: "user".to_owned(),
            auth_reference_sha256: String::new(),
        };
        let exact_stat = mount_statfs(
            "smbfs",
            "/Volumes/share",
            "//user@host._smb._tcp.local/share",
        );

        let discovered = SmbMountBinding::validate_discovered_mount_root_with(
            binding.clone(),
            Path::new("/Volumes/share"),
            |_| Ok(exact_stat),
        )
        .expect("the exact bound mount root must reach the canary gate");
        assert_eq!(discovered, binding);
        assert!(matches!(
            discovered.validate_existing_path(Path::new("/Volumes/share")),
            Err(SmbNoReplaceError::PathBinding)
        ));

        let wrong_stat = mount_statfs(
            "apfs",
            "/Volumes/share",
            "//user@host._smb._tcp.local/share",
        );
        assert!(matches!(
            binding.validate_exact_mount_root_with(Path::new("/Volumes/share"), |_| Ok(wrong_stat)),
            Err(SmbNoReplaceError::PathBinding)
        ));
    }

    #[test]
    fn mixed_apfs_smb_recovery_seam_requires_one_exact_binding() {
        let binding = SmbMountBinding {
            mount_root: PathBuf::from("/Volumes/share"),
            mount_from: "//user@host._smb._tcp.local/share".to_owned(),
            service_name: "host._smb._tcp.local".to_owned(),
            resolved_host: "host.local.".to_owned(),
            port: 445,
            share: "share".to_owned(),
            account: "user".to_owned(),
            auth_reference_sha256: String::new(),
        };
        assert_eq!(
            classify_smb_path_pair(None, None).unwrap(),
            SmbPathPair::Local
        );
        assert_eq!(
            classify_smb_path_pair(Some(binding.clone()), Some(binding.clone())).unwrap(),
            SmbPathPair::Mounted(binding.clone())
        );
        assert!(classify_smb_path_pair(Some(binding.clone()), None).is_err());
        assert!(classify_smb_path_pair(None, Some(binding.clone())).is_err());

        for mismatched in [
            SmbMountBinding {
                resolved_host: "wrong.local.".to_owned(),
                ..binding.clone()
            },
            SmbMountBinding {
                share: "wrong-share".to_owned(),
                ..binding.clone()
            },
            SmbMountBinding {
                mount_root: PathBuf::from("/Volumes/wrong"),
                ..binding.clone()
            },
        ] {
            assert!(
                classify_smb_path_pair(Some(binding.clone()), Some(mismatched)).is_err(),
                "server, share, and mount-path mismatches must fail closed"
            );
        }
    }
}

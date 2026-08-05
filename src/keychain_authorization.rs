//! Narrow macOS Keychain ACL authorization for the already-validated SMB mount.
//!
//! This module deliberately has no network, filesystem-recovery, journal, or
//! deletion dependencies.  Its C boundary accepts only the non-secret tuple
//! derived from `SmbMountBinding` and returns a redacted stable result class.
use std::ffi::CString;
use std::fmt;
use std::io::{Read, Write};
use zeroize::Zeroizing;

const MAX_DASHBOARD_PASSWORD_BYTES: usize = 1024;

#[cfg(target_os = "macos")]
use crate::authorization_policy::validate_dashboard_parent;
use crate::authorization_policy::{
    AuthorizationPolicyError, validate_exact_installed_service_helper,
};
use crate::smb_noreplace::{
    SmbMountBinding, SmbNoReplaceError, SmbNoReplaceSession, SmbSessionSecurityReason,
    SmbSessionSecurityStage, validate_supplied_credential,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialProof {
    Authorized,
    NotFound,
    Ambiguous,
    InteractionRequired,
    AccessDenied,
    ServerRejected,
    ServerRejectedWithDetail(CredentialValidationFailure),
    KeychainValidationWithDetail(KeychainValidationFailure),
    IntegrityMismatch,
}

/// The two SMB validation phases that can reach a server-facing check during
/// credential setup.  These are deliberately fixed labels: the dashboard must
/// never surface an endpoint, a password, or an underlying library error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CredentialValidationCategory {
    SuppliedCredential,
    StoredCredential,
}

impl CredentialValidationCategory {
    fn stable_code(self) -> &'static str {
        match self {
            Self::SuppliedCredential => "supplied_credential_validation",
            Self::StoredCredential => "stored_credential_validation",
        }
    }
}

/// Typed, redacted context for a real SMB session validation failure.  It
/// stores only allowlisted enums produced by the SMB gate, never the source
/// error text (which can contain an endpoint or server-provided detail).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialValidationFailure {
    category: CredentialValidationCategory,
    stage: SmbSessionSecurityStage,
    reason: SmbSessionSecurityReason,
}

impl CredentialValidationFailure {
    fn new(
        category: CredentialValidationCategory,
        stage: SmbSessionSecurityStage,
        reason: SmbSessionSecurityReason,
    ) -> Self {
        Self {
            category,
            stage,
            reason,
        }
    }

    fn category(self) -> &'static str {
        self.category.stable_code()
    }

    fn stage(self) -> SmbSessionSecurityStage {
        self.stage
    }

    fn reason(self) -> SmbSessionSecurityReason {
        self.reason
    }
}

// These fixed stage and reason codes are the entire C-to-Rust diagnostic
// vocabulary for Security.framework failures. They intentionally exclude raw
// OSStatus values, paths, requirements, item attributes, and framework text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeychainValidationStage {
    HelperRequirement,
    DurableAccessConstruction,
    V2Enumeration,
    ItemCreation,
    ReenumerationIdentity,
    GeneratedAclProof,
    NoUiDataProof,
    DataOnlyReplacement,
    PostRefreshProof,
    Rollback,
}

impl KeychainValidationStage {
    fn from_code(code: libc::c_int) -> Option<Self> {
        match code {
            1 => Some(Self::HelperRequirement),
            2 => Some(Self::DurableAccessConstruction),
            3 => Some(Self::V2Enumeration),
            4 => Some(Self::ItemCreation),
            5 => Some(Self::ReenumerationIdentity),
            6 => Some(Self::GeneratedAclProof),
            7 => Some(Self::NoUiDataProof),
            8 => Some(Self::DataOnlyReplacement),
            9 => Some(Self::PostRefreshProof),
            10 => Some(Self::Rollback),
            _ => None,
        }
    }

    fn stable_code(self) -> &'static str {
        match self {
            Self::HelperRequirement => "helper_requirement",
            Self::DurableAccessConstruction => "durable_access_construction",
            Self::V2Enumeration => "v2_enumeration",
            Self::ItemCreation => "item_creation",
            Self::ReenumerationIdentity => "reenumeration_identity",
            Self::GeneratedAclProof => "generated_acl_proof",
            Self::NoUiDataProof => "no_ui_data_proof",
            Self::DataOnlyReplacement => "data_only_replacement",
            Self::PostRefreshProof => "post_refresh_proof",
            Self::Rollback => "rollback",
        }
    }
}

impl fmt::Display for KeychainValidationStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.stable_code())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeychainValidationReason {
    IntegrityMismatch,
    InteractionRequired,
    AccessDenied,
    Ambiguous,
    NotFound,
}

impl KeychainValidationReason {
    fn from_code(code: libc::c_int) -> Option<Self> {
        match code {
            1 => Some(Self::IntegrityMismatch),
            2 => Some(Self::InteractionRequired),
            3 => Some(Self::AccessDenied),
            4 => Some(Self::Ambiguous),
            5 => Some(Self::NotFound),
            _ => None,
        }
    }

    fn stable_class(self) -> &'static str {
        match self {
            Self::IntegrityMismatch => "integrity_mismatch",
            Self::InteractionRequired => "interaction_required",
            Self::AccessDenied => "access_denied",
            Self::Ambiguous => "ambiguous",
            Self::NotFound => "not_found",
        }
    }
}

impl fmt::Display for KeychainValidationReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.stable_class())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeychainValidationFailure {
    stage: KeychainValidationStage,
    reason: KeychainValidationReason,
}

impl KeychainValidationFailure {
    fn new(stage: KeychainValidationStage, reason: KeychainValidationReason) -> Self {
        Self { stage, reason }
    }

    fn stage(self) -> KeychainValidationStage {
        self.stage
    }

    fn reason(self) -> KeychainValidationReason {
        self.reason
    }
}

const KEYCHAIN_DIAGNOSTIC_BASE: libc::c_int = 1000;
const KEYCHAIN_DIAGNOSTIC_REASON_STRIDE: libc::c_int = 8;

fn keychain_validation_failure(code: libc::c_int) -> Option<KeychainValidationFailure> {
    let offset = code.checked_sub(KEYCHAIN_DIAGNOSTIC_BASE)?;
    let stage = KeychainValidationStage::from_code(offset / KEYCHAIN_DIAGNOSTIC_REASON_STRIDE)?;
    let reason = KeychainValidationReason::from_code(offset % KEYCHAIN_DIAGNOSTIC_REASON_STRIDE)?;
    Some(KeychainValidationFailure::new(stage, reason))
}

impl CredentialProof {
    pub fn stable_class(self) -> &'static str {
        match self {
            Self::Authorized => "authorized",
            Self::NotFound => "not_found",
            Self::Ambiguous => "ambiguous",
            Self::InteractionRequired => "interaction_required",
            Self::AccessDenied => "access_denied",
            Self::ServerRejected | Self::ServerRejectedWithDetail(_) => "server_rejected",
            Self::KeychainValidationWithDetail(failure) => failure.reason().stable_class(),
            Self::IntegrityMismatch => "integrity_mismatch",
        }
    }

    /// Writes the only supported machine-readable authorization report. The
    /// detailed forms are restricted to typed SMB and Keychain failures; all
    /// other results retain their existing stable, one-field contract.
    pub(crate) fn write_redacted_json<W: Write>(self, writer: &mut W) -> std::io::Result<()> {
        match self {
            Self::ServerRejectedWithDetail(failure) => writeln!(
                writer,
                "{{\"status\":\"server_rejected\",\"category\":\"{}\",\"stage\":\"{}\",\"reason\":\"{}\"}}",
                failure.category(),
                failure.stage(),
                failure.reason(),
            ),
            Self::KeychainValidationWithDetail(failure) => writeln!(
                writer,
                "{{\"status\":\"{}\",\"category\":\"keychain_validation\",\"stage\":\"{}\",\"reason\":\"{}\"}}",
                failure.reason(),
                failure.stage(),
                failure.reason(),
            ),
            _ => writeln!(writer, "{{\"status\":\"{}\"}}", self.stable_class()),
        }
    }

    pub(crate) fn write_redacted_human<W: Write>(self, writer: &mut W) -> std::io::Result<()> {
        match self {
            Self::ServerRejectedWithDetail(failure) => writeln!(
                writer,
                "smb_credential status=server_rejected category={} stage={} reason={}",
                failure.category(),
                failure.stage(),
                failure.reason(),
            ),
            Self::KeychainValidationWithDetail(failure) => writeln!(
                writer,
                "smb_credential status={} category=keychain_validation stage={} reason={}",
                failure.reason(),
                failure.stage(),
                failure.reason(),
            ),
            _ => writeln!(writer, "smb_credential status={}", self.stable_class()),
        }
    }
}

fn supplied_credential_validation_failure(error: SmbNoReplaceError) -> CredentialProof {
    match error {
        SmbNoReplaceError::SessionSecurity { stage, reason } => {
            CredentialProof::ServerRejectedWithDetail(CredentialValidationFailure::new(
                CredentialValidationCategory::SuppliedCredential,
                stage,
                reason,
            ))
        }
        // The dashboard's UTF-8, bounded input is validated before this call;
        // anything else is an internal integrity failure, not a password
        // rejection. Never downgrade it to a retryable server status.
        _ => CredentialProof::IntegrityMismatch,
    }
}

fn stored_credential_validation_failure(error: SmbNoReplaceError) -> CredentialProof {
    match error {
        SmbNoReplaceError::SessionSecurity { stage, reason } => {
            CredentialProof::ServerRejectedWithDetail(CredentialValidationFailure::new(
                CredentialValidationCategory::StoredCredential,
                stage,
                reason,
            ))
        }
        SmbNoReplaceError::CredentialNotFound => CredentialProof::NotFound,
        SmbNoReplaceError::CredentialInteraction => CredentialProof::InteractionRequired,
        SmbNoReplaceError::CredentialAccess => CredentialProof::AccessDenied,
        // A persistent-reference, binding, or other local proof failure must
        // remain fail-closed rather than be presented as a bad NAS password.
        _ => CredentialProof::IntegrityMismatch,
    }
}

/// Re-reads the dedicated Keychain item and repeats the exact SMB session
/// validation after storage.  This is a separate integrity gate from the
/// supplied-password check and must not be conflated with it in the UI.
pub(crate) fn validate_stored_credential(binding: SmbMountBinding) -> CredentialProof {
    match SmbNoReplaceSession::connect(binding) {
        Ok(_) => CredentialProof::Authorized,
        Err(error) => stored_credential_validation_failure(error),
    }
}

fn policy_error(_: AuthorizationPolicyError) -> CredentialProof {
    CredentialProof::IntegrityMismatch
}

fn c(value: &str) -> Result<CString, CredentialProof> {
    CString::new(value).map_err(|_| CredentialProof::IntegrityMismatch)
}

fn result(code: libc::c_int) -> CredentialProof {
    match code {
        0 => CredentialProof::Authorized,
        1 => CredentialProof::NotFound,
        2 => CredentialProof::Ambiguous,
        3 => CredentialProof::InteractionRequired,
        4 => CredentialProof::AccessDenied,
        _ => keychain_validation_failure(code)
            .map(CredentialProof::KeychainValidationWithDetail)
            .unwrap_or(CredentialProof::IntegrityMismatch),
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn keychain_prove_exact_smb_credential(
        server: *const libc::c_char,
        account: *const libc::c_char,
        helper_requirement: *const libc::c_char,
    ) -> libc::c_int;
    fn keychain_store_exact_smb_credential(
        server: *const libc::c_char,
        account: *const libc::c_char,
        password: *const u8,
        password_length: libc::size_t,
        helper_requirement: *const libc::c_char,
    ) -> libc::c_int;
}

/// GUI-mediated credential setup.  The password is accepted only from the
/// anonymous stdin pipe created by the dashboard, never from argv or env.
pub(crate) fn store_from_stdin(
    service_bundle: &std::path::Path,
    binding: &SmbMountBinding,
) -> CredentialProof {
    let current = match std::env::current_exe() {
        Ok(v) => v,
        Err(_) => return CredentialProof::IntegrityMismatch,
    };
    let (policy, _) =
        match validate_exact_installed_service_helper(service_bundle, &current, unsafe {
            libc::geteuid()
        }) {
            Ok(v) => v,
            Err(e) => return policy_error(e),
        };
    #[cfg(target_os = "macos")]
    if validate_dashboard_parent(service_bundle, unsafe { libc::getppid() }).is_err() {
        return CredentialProof::AccessDenied;
    }
    // Never grow a secret allocation based on untrusted stdin. Read one byte
    // beyond the accepted maximum so oversized or trailing input is rejected
    // before it can be passed to Security.framework.
    let mut password = Zeroizing::new([0_u8; MAX_DASHBOARD_PASSWORD_BYTES + 1]);
    let mut password_length = 0;
    while password_length < password.len() {
        match std::io::stdin().read(&mut password[password_length..]) {
            Ok(0) => break,
            Ok(read) => password_length += read,
            Err(_) => return CredentialProof::IntegrityMismatch,
        }
    }
    if password_length == 0
        || password_length > MAX_DASHBOARD_PASSWORD_BYTES
        || password[..password_length]
            .iter()
            .any(|byte| matches!(byte, b'\n' | b'\r'))
    {
        return CredentialProof::IntegrityMismatch;
    }
    let helper_requirement = match policy.helper_designated_requirement.as_deref() {
        Some(requirement) => requirement,
        None => return CredentialProof::IntegrityMismatch,
    };
    // Prove exact endpoint, authenticated session, and exact share before the
    // dedicated v2 Keychain item can be created. This cannot use an
    // ambient Finder session because the supplied bytes are passed directly to
    // the SMB client.
    if let Err(error) = validate_supplied_credential(binding, &password[..password_length]) {
        return supplied_credential_validation_failure(error);
    }
    let (server, account, helper_requirement) = match (
        c(&binding.service_name),
        c(&binding.account),
        c(helper_requirement),
    ) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        _ => return CredentialProof::IntegrityMismatch,
    };
    #[cfg(target_os = "macos")]
    unsafe {
        result(keychain_store_exact_smb_credential(
            server.as_ptr(),
            account.as_ptr(),
            password.as_ptr(),
            password_length,
            helper_requirement.as_ptr(),
        ))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (server, account, helper_requirement);
        CredentialProof::IntegrityMismatch
    }
}

/// Runs only the credential read check. It cannot construct downstream adapters.
pub(crate) fn prove(
    service_bundle: &std::path::Path,
    binding: &SmbMountBinding,
) -> CredentialProof {
    let current_executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(_) => return CredentialProof::IntegrityMismatch,
    };
    let (policy, _) =
        match validate_exact_installed_service_helper(service_bundle, &current_executable, unsafe {
            libc::geteuid()
        }) {
            Ok(value) => value,
            Err(error) => return policy_error(error),
        };
    let helper_requirement = match policy.helper_designated_requirement.as_deref() {
        Some(requirement) => match c(requirement) {
            Ok(requirement) => requirement,
            Err(proof) => return proof,
        },
        None => return CredentialProof::IntegrityMismatch,
    };
    let (server, account) = match (c(&binding.service_name), c(&binding.account)) {
        (Ok(server), Ok(account)) => (server, account),
        _ => return CredentialProof::IntegrityMismatch,
    };
    #[cfg(target_os = "macos")]
    unsafe {
        result(keychain_prove_exact_smb_credential(
            server.as_ptr(),
            account.as_ptr(),
            helper_requirement.as_ptr(),
        ))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (server, account, helper_requirement);
        CredentialProof::IntegrityMismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_statuses_are_only_stable_redacted_classes() {
        assert_eq!(result(0), CredentialProof::Authorized);
        assert_eq!(result(1), CredentialProof::NotFound);
        assert_eq!(result(2), CredentialProof::Ambiguous);
        assert_eq!(result(3), CredentialProof::InteractionRequired);
        assert_eq!(result(4), CredentialProof::AccessDenied);
        assert_eq!(result(-1), CredentialProof::IntegrityMismatch);
        let server_rejected =
            CredentialProof::ServerRejectedWithDetail(CredentialValidationFailure::new(
                CredentialValidationCategory::SuppliedCredential,
                SmbSessionSecurityStage::SessionSetup,
                SmbSessionSecurityReason::AuthenticationRejected,
            ));
        let keychain_validation =
            CredentialProof::KeychainValidationWithDetail(KeychainValidationFailure::new(
                KeychainValidationStage::NoUiDataProof,
                KeychainValidationReason::InteractionRequired,
            ));
        for proof in [
            CredentialProof::Authorized,
            CredentialProof::NotFound,
            CredentialProof::Ambiguous,
            CredentialProof::InteractionRequired,
            CredentialProof::AccessDenied,
            CredentialProof::ServerRejected,
            server_rejected,
            keychain_validation,
            CredentialProof::IntegrityMismatch,
        ] {
            assert!(matches!(
                proof.stable_class(),
                "authorized"
                    | "not_found"
                    | "ambiguous"
                    | "interaction_required"
                    | "access_denied"
                    | "server_rejected"
                    | "integrity_mismatch"
            ));
        }
    }

    #[test]
    fn session_validation_reports_only_fixed_redacted_codes() {
        let supplied = supplied_credential_validation_failure(SmbNoReplaceError::SessionSecurity {
            stage: SmbSessionSecurityStage::SessionSetup,
            reason: SmbSessionSecurityReason::AuthenticationRejected,
        });
        let stored = stored_credential_validation_failure(SmbNoReplaceError::SessionSecurity {
            stage: SmbSessionSecurityStage::PostConnectValidation,
            reason: SmbSessionSecurityReason::SigningInactive,
        });

        let mut supplied_json = Vec::new();
        supplied.write_redacted_json(&mut supplied_json).unwrap();
        assert_eq!(
            String::from_utf8(supplied_json).unwrap(),
            "{\"status\":\"server_rejected\",\"category\":\"supplied_credential_validation\",\"stage\":\"session_setup\",\"reason\":\"authentication_rejected\"}\n"
        );

        let mut stored_json = Vec::new();
        stored.write_redacted_json(&mut stored_json).unwrap();
        assert_eq!(
            String::from_utf8(stored_json).unwrap(),
            "{\"status\":\"server_rejected\",\"category\":\"stored_credential_validation\",\"stage\":\"post_connect_validation\",\"reason\":\"signing_inactive\"}\n"
        );
    }

    #[test]
    fn keychain_diagnostic_codes_map_to_fixed_redacted_stages_and_reasons() {
        let cases = [
            (
                1009,
                KeychainValidationStage::HelperRequirement,
                KeychainValidationReason::IntegrityMismatch,
            ),
            (
                1018,
                KeychainValidationStage::DurableAccessConstruction,
                KeychainValidationReason::InteractionRequired,
            ),
            (
                1027,
                KeychainValidationStage::V2Enumeration,
                KeychainValidationReason::AccessDenied,
            ),
            (
                1036,
                KeychainValidationStage::ItemCreation,
                KeychainValidationReason::Ambiguous,
            ),
            (
                1045,
                KeychainValidationStage::ReenumerationIdentity,
                KeychainValidationReason::NotFound,
            ),
            (
                1049,
                KeychainValidationStage::GeneratedAclProof,
                KeychainValidationReason::IntegrityMismatch,
            ),
            (
                1058,
                KeychainValidationStage::NoUiDataProof,
                KeychainValidationReason::InteractionRequired,
            ),
            (
                1067,
                KeychainValidationStage::DataOnlyReplacement,
                KeychainValidationReason::AccessDenied,
            ),
            (
                1076,
                KeychainValidationStage::PostRefreshProof,
                KeychainValidationReason::Ambiguous,
            ),
            (
                1085,
                KeychainValidationStage::Rollback,
                KeychainValidationReason::NotFound,
            ),
        ];

        for (code, stage, reason) in cases {
            assert_eq!(
                result(code),
                CredentialProof::KeychainValidationWithDetail(KeychainValidationFailure::new(
                    stage, reason
                ))
            );
        }
        assert_eq!(result(1008), CredentialProof::IntegrityMismatch);
        assert_eq!(result(1086), CredentialProof::IntegrityMismatch);
    }

    #[test]
    fn keychain_diagnostic_serialization_is_exact_and_nondetailed_statuses_remain_one_field() {
        let proof = CredentialProof::KeychainValidationWithDetail(KeychainValidationFailure::new(
            KeychainValidationStage::GeneratedAclProof,
            KeychainValidationReason::IntegrityMismatch,
        ));
        let mut json = Vec::new();
        proof.write_redacted_json(&mut json).unwrap();
        assert_eq!(
            String::from_utf8(json).unwrap(),
            "{\"status\":\"integrity_mismatch\",\"category\":\"keychain_validation\",\"stage\":\"generated_acl_proof\",\"reason\":\"integrity_mismatch\"}\n"
        );

        let mut human = Vec::new();
        proof.write_redacted_human(&mut human).unwrap();
        assert_eq!(
            String::from_utf8(human).unwrap(),
            "smb_credential status=integrity_mismatch category=keychain_validation stage=generated_acl_proof reason=integrity_mismatch\n"
        );

        for proof in [
            CredentialProof::NotFound,
            CredentialProof::Ambiguous,
            CredentialProof::InteractionRequired,
            CredentialProof::AccessDenied,
            CredentialProof::IntegrityMismatch,
        ] {
            let mut json = Vec::new();
            proof.write_redacted_json(&mut json).unwrap();
            assert_eq!(
                String::from_utf8(json).unwrap(),
                format!("{{\"status\":\"{}\"}}\n", proof.stable_class())
            );
        }
    }

    #[test]
    fn stored_credential_failures_keep_keychain_classes_and_fail_closed() {
        assert_eq!(
            stored_credential_validation_failure(SmbNoReplaceError::CredentialNotFound),
            CredentialProof::NotFound
        );
        assert_eq!(
            stored_credential_validation_failure(SmbNoReplaceError::CredentialInteraction),
            CredentialProof::InteractionRequired
        );
        assert_eq!(
            stored_credential_validation_failure(SmbNoReplaceError::CredentialAccess),
            CredentialProof::AccessDenied
        );
        assert_eq!(
            stored_credential_validation_failure(SmbNoReplaceError::CredentialReference),
            CredentialProof::IntegrityMismatch
        );
        assert_eq!(
            supplied_credential_validation_failure(SmbNoReplaceError::CredentialAccess),
            CredentialProof::IntegrityMismatch
        );
    }

    #[test]
    fn native_boundary_is_metadata_first_and_credential_only() {
        let native = include_str!("keychain_authorization_macos.c");
        assert!(native.contains("kSecInternetPasswordItemClass"));
        assert!(native.contains("authentication_type = kSecAuthenticationTypeDefault"));
        assert!(native.contains("sizeof(authentication_type), &authentication_type"));
        assert!(native.contains("memcmp(found->attr[4].data, &authentication_type"));
        assert!(!native.contains("kSecAuthenticationTypeItemAttr, sizeof(zero), &zero"));
        assert!(native.contains("kSecSecurityDomainItemAttr"));
        assert!(native.contains("kSecPathItemAttr"));
        assert!(native.contains("found->attr[3].length == sizeof(zero)"));
        assert!(native.contains("optimizer_domain_v2"));
        assert!(native.contains("found->attr[5].length == sizeof(optimizer_domain_v2) - 1"));
        assert!(native.contains("found->attr[6].length == 0"));
        assert!(native.contains("return KC_AMBIGUOUS"));
        assert!(native.contains("keychain_copy_exact_smb_credential"));
        assert!(native.contains("keychain_zeroize_and_free_exact_smb_credential"));
        assert!(native.contains("KC_KEYCHAIN_DIAGNOSTIC_BASE = 1000"));
        assert!(native.contains("KC_KEYCHAIN_DIAGNOSTIC_REASON_STRIDE = 8"));
        assert!(native.contains("keychain_diagnostic(KC_KEYCHAIN_STAGE_HELPER_REQUIREMENT"));
        assert!(native.contains("keychain_diagnostic(KC_KEYCHAIN_STAGE_V2_ENUMERATION"));
        assert!(native.contains("keychain_diagnostic(KC_KEYCHAIN_STAGE_ROLLBACK"));
        assert!(native.contains("copy_data_with_interaction_disabled(item, &length, &data)"));
        assert!(native.contains("SecKeychainSetUserInteractionAllowed(false)"));
        assert!(native.contains("keychain_interaction_lock"));
        let proof = &native[native
            .find("int keychain_prove_exact_smb_credential(")
            .unwrap()
            ..native
                .find("int keychain_copy_exact_smb_credential(")
                .unwrap()];
        assert!(
            proof.find("begin_without_interaction").unwrap() < proof.find("exact_v2_item").unwrap()
        );
        assert!(native.contains("SecKeychainItemFreeAttributesAndData(NULL, data)"));
        assert!(native.contains("memset(data, 0, length)"));
        assert!(!native.contains("NetFS"));
        assert!(!native.contains("CloudKit"));
        assert!(native.contains("SecKeychainItemCreateFromContent"));
        assert!(!native.contains("SecKeychainAddInternetPassword"));
        assert!(native.contains("delete_just_created_or_integrity"));
    }

    #[test]
    fn dashboard_stdin_is_bounded_before_any_secret_allocation() {
        let source = include_str!("keychain_authorization.rs");
        let start = source.find("pub(crate) fn store_from_stdin(").unwrap();
        let body = &source[start
            ..source
                .find("/// Runs only the credential read check.")
                .unwrap()];
        assert!(body.contains("[0_u8; MAX_DASHBOARD_PASSWORD_BYTES + 1]"));
        assert!(body.contains("password_length > MAX_DASHBOARD_PASSWORD_BYTES"));
        assert!(body.contains("matches!(byte, b'\\n' | b'\\r')"));
        assert!(!body.contains("read_to_end"));
    }

    #[test]
    fn supplied_password_is_validated_before_keychain_mutation() {
        let source = include_str!("keychain_authorization.rs");
        let start = source.find("pub(crate) fn store_from_stdin(").unwrap();
        let body = &source[start
            ..source
                .find("/// Runs only the credential read check.")
                .unwrap()];
        let validation = body.find("validate_supplied_credential").unwrap();
        let mutation = body.find("keychain_store_exact_smb_credential").unwrap();
        assert!(validation < mutation);
        assert!(body.contains("supplied_credential_validation_failure(error)"));
    }

    #[test]
    fn v2_namespace_isolated_from_retired_v1_and_exactly_scoped() {
        let native = include_str!("keychain_authorization_macos.c");
        assert!(native.contains("optimizer_domain_v1_retired"));
        assert!(native.contains("optimizer_domain_v2"));
        let exact_v2 = &native[native.find("static int exact_v2_item(").unwrap()
            ..native
                .find("static int begin_without_interaction(")
                .unwrap()];
        assert!(exact_v2.contains("optimizer_domain_v2"));
        assert!(!exact_v2.contains("optimizer_domain_v1_retired"));
        for attribute in [
            "kSecServerItemAttr",
            "kSecAccountItemAttr",
            "kSecProtocolItemAttr",
            "kSecPortItemAttr",
            "kSecAuthenticationTypeItemAttr",
            "kSecSecurityDomainItemAttr",
            "kSecPathItemAttr",
        ] {
            assert!(exact_v2.contains(attribute), "missing {attribute}");
        }
        assert!(exact_v2.contains("return KC_AMBIGUOUS"));
        assert!(exact_v2.contains("found->attr[6].length == 0"));
    }

    #[test]
    fn v2_create_or_refresh_uses_the_sealed_requirement_and_rolls_back_only_new_items() {
        let native = include_str!("keychain_authorization_macos.c");
        assert!(native.contains("if (!left || !right) return left == right;"));
        assert!(native.contains("static Boolean nullable_strings_equal"));
        assert!(native.contains("SecTrustedApplicationCopyExternalRepresentation"));
        assert!(native.contains("SecTrustedApplicationCreateFromRequirement"));
        assert!(native.contains("current_helper_matches_requirement"));
        assert!(native.contains("SecCodeCopySelf"));
        assert!(native.contains("SecCodeCheckValidity"));
        assert!(native.contains("SecAccessCreate"));
        assert!(native.contains("item_access_matches(item, expected_access, &matches)"));
        assert!(native.contains("SecKeychainItemModifyAttributesAndData("));
        assert!(native.contains("item, NULL, (UInt32)password_length, password"));
        assert!(!native.contains("SecKeychainItemSetAccess"));
        assert!(!native.contains("SecTrustedApplicationCreateFromPath"));
        assert!(!native.contains("path_bound_predecessor"));
        let writer = &native[native
            .find("int keychain_store_exact_smb_credential(")
            .unwrap()..];
        let existing = writer
            .find("result = exact_v2_item(server, account, &item);")
            .unwrap();
        let refresh_proof = writer
            .find("KC_KEYCHAIN_STAGE_GENERATED_ACL_PROOF")
            .unwrap();
        let replacement = writer
            .find("result = replace_exact_v2_secret_data(item, password, password_length);")
            .unwrap();
        let refresh_reenumeration = writer[replacement..]
            .find("result = reenumerate_same_exact_v2_item(server, account, item, &exact);")
            .unwrap()
            + replacement;
        let refresh_post_proof = writer[refresh_reenumeration..]
            .find("KC_KEYCHAIN_STAGE_POST_REFRESH_PROOF")
            .unwrap()
            + refresh_reenumeration;
        let create = writer
            .find("result = create_exact_v2_item(server, account, password, password_length,\n                                creation_access, &item);")
            .unwrap();
        let reenumerate = writer[create..]
            .find("result = reenumerate_same_exact_v2_item(server, account, item, &exact);")
            .unwrap()
            + create;
        let post_create_proof = writer[reenumerate..]
            .find("KC_KEYCHAIN_STAGE_POST_REFRESH_PROOF")
            .unwrap()
            + reenumerate;
        assert!(
            existing < refresh_proof
                && refresh_proof < replacement
                && replacement < refresh_reenumeration
                && refresh_reenumeration < refresh_post_proof
                && refresh_post_proof < create
                && create < reenumerate
        );
        assert!(reenumerate < post_create_proof);
        assert!(writer.contains("if (result == KC_AUTHORIZED) result = KC_INTEGRITY;"));
        assert!(writer.contains("created = item != NULL;"));
        assert!(writer.contains("if (created && result != KC_AUTHORIZED)"));
        assert!(writer.contains("delete_just_created_or_integrity(item, result)"));
        let rollback = &native[native
            .find("static int delete_just_created_or_integrity(")
            .unwrap()
            ..native
                .find("/* This proof is deliberately local to an already-enumerated v2 record.")
                .unwrap()];
        assert!(rollback.contains("begin_without_interaction(&original_allowed)"));
        assert!(rollback.contains("SecKeychainItemDelete(item)"));
        assert!(rollback.contains("finish_without_interaction_with_diagnostic("));
    }

    #[test]
    fn keychain_diagnostic_phases_preserve_store_and_recovery_ordering() {
        let native = include_str!("keychain_authorization_macos.c");
        let writer = &native[native
            .find("int keychain_store_exact_smb_credential(")
            .unwrap()..];
        let helper_requirement = writer.find("KC_KEYCHAIN_STAGE_HELPER_REQUIREMENT").unwrap();
        let durable_access = writer
            .find("KC_KEYCHAIN_STAGE_DURABLE_ACCESS_CONSTRUCTION")
            .unwrap();
        let existing_enumeration = writer
            .find("result = exact_v2_item(server, account, &item);")
            .unwrap();
        let generated_acl = writer
            .find("KC_KEYCHAIN_STAGE_GENERATED_ACL_PROOF")
            .unwrap();
        let no_ui_data = writer.find("KC_KEYCHAIN_STAGE_NO_UI_DATA_PROOF").unwrap();
        let replacement = writer
            .find("result = replace_exact_v2_secret_data(item, password, password_length);")
            .unwrap();
        let replacement_diagnostic = writer[replacement..]
            .find("KC_KEYCHAIN_STAGE_DATA_ONLY_REPLACEMENT")
            .unwrap()
            + replacement;
        let refreshed_identity = writer[replacement_diagnostic..]
            .find("KC_KEYCHAIN_STAGE_REENUMERATION_IDENTITY")
            .unwrap()
            + replacement_diagnostic;
        let refreshed_proof = writer[refreshed_identity..]
            .find("KC_KEYCHAIN_STAGE_POST_REFRESH_PROOF")
            .unwrap()
            + refreshed_identity;
        let create = writer
            .find("result = create_exact_v2_item(server, account, password, password_length,\n                                creation_access, &item);")
            .unwrap();
        let created_identity = writer[create..]
            .find("KC_KEYCHAIN_STAGE_REENUMERATION_IDENTITY")
            .unwrap()
            + create;
        let created_proof = writer[created_identity..]
            .find("KC_KEYCHAIN_STAGE_POST_REFRESH_PROOF")
            .unwrap()
            + created_identity;
        assert!(
            helper_requirement < durable_access
                && durable_access < existing_enumeration
                && existing_enumeration < generated_acl
                && generated_acl < no_ui_data
                && no_ui_data < replacement
                && replacement < replacement_diagnostic
                && replacement_diagnostic < refreshed_identity
                && refreshed_identity < refreshed_proof
                && refreshed_proof < create
                && create < created_identity
                && created_identity < created_proof
        );

        let rollback = &native[native
            .find("static int delete_just_created_or_integrity(")
            .unwrap()
            ..native
                .find("/* This proof is deliberately local to an already-enumerated v2 record.")
                .unwrap()];
        assert!(rollback.contains("KC_KEYCHAIN_STAGE_ROLLBACK"));
        assert!(!writer[..create].contains("KC_KEYCHAIN_STAGE_ROLLBACK"));
    }

    #[test]
    fn v2_crash_retry_or_password_rotation_proves_existing_state_before_mutation() {
        let native = include_str!("keychain_authorization_macos.c");
        let no_ui_proof = &native[native
            .find("static int prove_item_access_and_data_without_ui(")
            .unwrap()
            ..native
                .find("static int reenumerate_same_exact_v2_item(")
                .unwrap()];
        let writer = &native[native
            .find("int keychain_store_exact_smb_credential(")
            .unwrap()..];
        let existing_branch = &writer[..writer.find("if (result != KC_NOT_FOUND)").unwrap()];

        let no_ui = no_ui_proof.find("begin_without_interaction").unwrap();
        let acl = no_ui_proof.find("item_access_matches").unwrap();
        let read = no_ui_proof
            .find("copy_data_with_interaction_disabled")
            .unwrap();
        let zeroize = no_ui_proof.find("zeroize_and_free_data").unwrap();
        let restore = no_ui_proof.find("finish_without_interaction").unwrap();
        assert!(no_ui < acl && acl < read && read < zeroize && zeroize < restore);

        assert!(existing_branch.contains("result = exact_v2_item(server, account, &item);"));
        assert!(existing_branch.contains("KC_KEYCHAIN_STAGE_GENERATED_ACL_PROOF"));
        assert!(
            existing_branch
                .contains("replace_exact_v2_secret_data(item, password, password_length)")
        );
        assert!(
            existing_branch
                .contains("reenumerate_same_exact_v2_item(server, account, item, &exact)")
        );
        assert!(existing_branch.contains("KC_KEYCHAIN_STAGE_POST_REFRESH_PROOF"));
        assert!(!existing_branch.contains("create_exact_v2_item"));
        assert!(!existing_branch.contains("delete_just_created_or_integrity"));

        let precondition = existing_branch
            .find("KC_KEYCHAIN_STAGE_GENERATED_ACL_PROOF")
            .unwrap();
        let mutation = existing_branch
            .find("replace_exact_v2_secret_data(item, password, password_length)")
            .unwrap();
        assert!(precondition < mutation);
    }

    #[test]
    fn generated_acl_requires_exact_owner_and_complete_acl_shape() {
        let native = include_str!("keychain_authorization_macos.c");
        assert!(
            native
                .contains("SecAccessCopyOwnerAndACL(access, user_id, group_id, owner_type, NULL)",)
        );
        assert!(native.contains("SecAccessCopyACLList(access, acls)"));
        assert!(native.contains("static int access_matches_generated_shape"));
        assert!(native.contains("static int persisted_acl_multisets_equal"));
        assert!(native.contains("canonical_integrity_acl"));
        assert!(native.contains("canonical_partition_acl"));
        assert!(native.contains("copy_current_team_identifier"));
        assert!(
            native.contains("actual_user != expected_user || actual_group != expected_group ||")
        );
        assert!(native.contains("trusted_application_equal("));
        assert!(!native.contains("CFArrayGetCount(actual_acls) != 1"));

        let final_shape = &native[native.find("static int item_access_matches(").unwrap()
            ..native.find("static int create_requirement(").unwrap()];
        assert!(final_shape.contains("access_matches_generated_shape(actual, expected, matches)"));
    }

    #[test]
    fn sealed_helper_requirement_is_passed_to_every_native_keychain_read_or_write() {
        let source = include_str!("keychain_authorization.rs");
        assert!(source.contains("policy.helper_designated_requirement.as_deref()"));
        assert!(source.contains("helper_requirement.as_ptr()"));
        assert!(source.contains("fn keychain_prove_exact_smb_credential("));
        assert!(source.contains("fn keychain_store_exact_smb_credential("));
        let store_ffi = &source[source
            .find("fn keychain_store_exact_smb_credential(")
            .unwrap()
            ..source.find("/// GUI-mediated credential setup.").unwrap()];
        assert!(!store_ffi.contains("helper: *const libc::c_char,"));
    }

    #[test]
    fn v2_refresh_never_touches_retired_v1_namespace() {
        let native = include_str!("keychain_authorization_macos.c");
        let exact_v2 = &native[native.find("static int exact_v2_item(").unwrap()
            ..native
                .find("static int begin_without_interaction(")
                .unwrap()];
        let writer = &native[native
            .find("int keychain_store_exact_smb_credential(")
            .unwrap()..];
        assert!(exact_v2.contains("optimizer_domain_v2"));
        assert!(writer.contains("exact_v2_item(server, account, &item)"));
        assert!(!writer.contains("optimizer_domain_v1_retired"));
        assert!(!writer.contains("kSecAuthenticationTypeItemAttr, sizeof(zero), &zero"));
    }

    #[test]
    fn authorization_command_revalidates_the_stored_v2_secret_over_smb() {
        let source = include_str!("cli.rs");
        let start = source.find("fn run_smb_credential<W: Write>(").unwrap();
        let body = &source[start..source.find("#[cfg(not(target_os = \"macos\"))]").unwrap()];
        let store = body
            .find("store_smb_credential(&args.service_bundle, &binding)")
            .unwrap();
        let revalidation = body.find("validate_stored_credential(binding)").unwrap();
        assert!(store < revalidation);

        let keychain = include_str!("keychain_authorization.rs");
        let stored_validation = &keychain[keychain
            .find("pub(crate) fn validate_stored_credential(")
            .unwrap()
            ..keychain.find("fn policy_error(").unwrap()];
        assert!(stored_validation.contains("SmbNoReplaceSession::connect(binding)"));
    }
}

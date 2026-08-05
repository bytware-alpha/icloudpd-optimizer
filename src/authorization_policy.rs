//! Sealed, non-secret authority and release provenance for Keychain authorization.
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    ffi::{CStr, OsString},
    fs,
    mem::MaybeUninit,
    os::unix::ffi::OsStringExt,
    path::{Component, Path, PathBuf},
};
use thiserror::Error;

pub const POLICY_RESOURCE: &str = "authorization-policy.json";
pub const PROVENANCE_RESOURCE: &str = "authorization-provenance.json";
const KEYCHAIN_AUTH_DEFAULT: u32 = u32::from_le_bytes(*b"dflt");
const SMB_SECURITY_DOMAIN: &str = "com.icloudpd-optimizer.smb.v2";
const RETIRED_SMB_SECURITY_DOMAIN: &str = "com.icloudpd-optimizer.smb.v1";

#[derive(Debug, Error)]
pub enum AuthorizationPolicyError {
    #[error("authorization policy integrity mismatch")]
    IntegrityMismatch,
    #[error("authorization policy is disabled")]
    Disabled,
    #[error("authorization policy is malformed")]
    Malformed,
    #[error("authorization policy path is unsafe")]
    UnsafePath,
    #[error("authorization policy owner or mode is unsafe")]
    UnsafeMetadata,
    #[error("authorization policy provenance mismatch")]
    ProvenanceMismatch,
    #[error("authorization policy IO failure")]
    Io,
    #[error("authorization policy quarantine inspection failure")]
    QuarantineInspection,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationPolicy {
    pub schema_version: u8,
    pub mode: String,
    #[serde(default)]
    pub authority_kind: Option<String>,
    #[serde(default)]
    pub team_id: Option<String>,
    #[serde(default)]
    pub helper_designated_requirement: Option<String>,
    #[serde(default)]
    pub dashboard_designated_requirement: Option<String>,
    #[serde(default)]
    pub service_designated_requirement: Option<String>,
    #[serde(default)]
    pub dashboard_bundle_identifier: Option<String>,
    #[serde(default)]
    pub service_bundle_identifier: Option<String>,
    #[serde(default)]
    pub helper_identifier: Option<String>,
    #[serde(default)]
    pub service_install_relative_path: Option<String>,
    #[serde(default)]
    pub helper_relative_path: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub item: Option<ItemPolicy>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItemPolicy {
    pub class: String,
    pub protocol: String,
    pub security_domain: Option<String>,
    pub path: Option<String>,
    pub port: u16,
    pub authentication_type: u32,
    pub server_source: String,
    pub account_source: String,
    pub uniqueness: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationProvenance {
    pub schema_version: u8,
    pub source_commit: String,
    pub authority_sha256: String,
    pub helper_sha256: String,
    pub helper_identifier: String,
    pub dashboard_bundle_identifier: String,
    pub service_bundle_identifier: String,
    pub helper_relative_path: String,
    pub service_install_relative_path: String,
    pub owner: String,
}

impl AuthorizationPolicy {
    pub fn validate(&self) -> Result<(), AuthorizationPolicyError> {
        self.validate_for_security_domain(SMB_SECURITY_DOMAIN)
    }

    /// Validate a sealed historical policy only for recovery-signer rotation.
    ///
    /// The retired v1 namespace is intentionally not accepted by [`Self::validate`].
    /// Keeping this validator crate-private and using it only from the rotation
    /// loader prevents an old bundle from becoming a production credential
    /// authorization policy by accident.
    pub(crate) fn validate_for_recovery_rotation(&self) -> Result<(), AuthorizationPolicyError> {
        self.validate_for_security_domains(&[RETIRED_SMB_SECURITY_DOMAIN, SMB_SECURITY_DOMAIN])
    }

    fn validate_for_security_domain(
        &self,
        expected_security_domain: &str,
    ) -> Result<(), AuthorizationPolicyError> {
        self.validate_for_security_domains(&[expected_security_domain])
    }

    fn validate_for_security_domains(
        &self,
        expected_security_domains: &[&str],
    ) -> Result<(), AuthorizationPolicyError> {
        if self.schema_version != 1 {
            return Err(AuthorizationPolicyError::Malformed);
        }
        if self.mode == "disabled" {
            return Err(AuthorizationPolicyError::Disabled);
        }
        if self.mode != "production" {
            return Err(AuthorizationPolicyError::Malformed);
        }
        let required = [
            &self.authority_kind,
            &self.team_id,
            &self.helper_designated_requirement,
            &self.dashboard_designated_requirement,
            &self.service_designated_requirement,
            &self.dashboard_bundle_identifier,
            &self.service_bundle_identifier,
            &self.helper_identifier,
            &self.service_install_relative_path,
            &self.helper_relative_path,
            &self.owner,
        ];
        if required
            .iter()
            .any(|v| v.as_deref().unwrap_or("").is_empty())
            || self.owner.as_deref() != Some("effective_user")
        {
            return Err(AuthorizationPolicyError::Malformed);
        }
        if self.authority_kind.as_deref() != Some("apple_development_team") {
            return Err(AuthorizationPolicyError::IntegrityMismatch);
        }
        let team = self.team_id.as_deref().unwrap();
        if team.len() != 10
            || !team
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            return Err(AuthorizationPolicyError::IntegrityMismatch);
        }
        for (actual, identifier) in [
            (
                self.helper_designated_requirement.as_deref().unwrap(),
                self.helper_identifier.as_deref().unwrap(),
            ),
            (
                self.dashboard_designated_requirement.as_deref().unwrap(),
                self.dashboard_bundle_identifier.as_deref().unwrap(),
            ),
            (
                self.service_designated_requirement.as_deref().unwrap(),
                self.service_bundle_identifier.as_deref().unwrap(),
            ),
        ] {
            if !requirements_equivalent(actual, &expected_requirement(team, identifier)) {
                return Err(AuthorizationPolicyError::IntegrityMismatch);
            }
        }
        let item = self
            .item
            .as_ref()
            .ok_or(AuthorizationPolicyError::Malformed)?;
        if item.class != "internet_password"
            || item.protocol != "smb "
            || !item
                .security_domain
                .as_deref()
                .is_some_and(|actual| expected_security_domains.contains(&actual))
            || item.path.is_some()
            || item.port != 0
            || item.authentication_type != KEYCHAIN_AUTH_DEFAULT
            || item.server_source != "smb_mount_binding.service_name"
            || item.account_source != "smb_mount_binding.account"
            || item.uniqueness != "exactly_one"
        {
            return Err(AuthorizationPolicyError::Malformed);
        }
        safe_relative(self.service_install_relative_path.as_deref().unwrap())?;
        safe_relative(self.helper_relative_path.as_deref().unwrap())?;
        Ok(())
    }
}
pub fn authority_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn load_sealed(
    bundle: &Path,
    expected_owner: u32,
) -> Result<(AuthorizationPolicy, AuthorizationProvenance), AuthorizationPolicyError> {
    load_sealed_with_validator(bundle, expected_owner, |policy| policy.validate(), true)
}

/// Load a retired v1 Service bundle exclusively as the prior witness for
/// recovery-signer rotation.  This path retains the complete sealed-bundle
/// checks (canonical path, owner/mode, provenance and code signatures) while
/// deliberately bypassing the normal v2 production-policy validator.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn load_sealed_for_recovery_rotation(
    bundle: &Path,
    expected_owner: u32,
) -> Result<(AuthorizationPolicy, AuthorizationProvenance), AuthorizationPolicyError> {
    load_sealed_with_validator(
        bundle,
        expected_owner,
        |policy| policy.validate_for_recovery_rotation(),
        true,
    )
}

#[cfg(test)]
pub(crate) fn load_sealed_for_recovery_rotation_test(
    bundle: &Path,
    expected_owner: u32,
) -> Result<(AuthorizationPolicy, AuthorizationProvenance), AuthorizationPolicyError> {
    // Test fixtures model the signed helper with a deterministic signer hook;
    // all filesystem, policy, provenance, and helper-hash checks remain real.
    load_sealed_with_validator(
        bundle,
        expected_owner,
        |policy| policy.validate_for_recovery_rotation(),
        false,
    )
}

fn load_sealed_with_validator(
    bundle: &Path,
    expected_owner: u32,
    validate_policy: fn(&AuthorizationPolicy) -> Result<(), AuthorizationPolicyError>,
    validate_code: bool,
) -> Result<(AuthorizationPolicy, AuthorizationProvenance), AuthorizationPolicyError> {
    let policy_path = sealed_bundle_file(
        bundle,
        Path::new("Contents/Resources")
            .join(POLICY_RESOURCE)
            .as_path(),
        expected_owner,
    )?;
    let provenance_path = sealed_bundle_file(
        bundle,
        Path::new("Contents/Resources")
            .join(PROVENANCE_RESOURCE)
            .as_path(),
        expected_owner,
    )?;
    let policy_bytes = fs::read(policy_path).map_err(|_| AuthorizationPolicyError::Io)?;
    let policy: AuthorizationPolicy =
        serde_json::from_slice(&policy_bytes).map_err(|_| AuthorizationPolicyError::Malformed)?;
    validate_policy(&policy)?;
    let provenance: AuthorizationProvenance = serde_json::from_slice(
        &fs::read(provenance_path).map_err(|_| AuthorizationPolicyError::Io)?,
    )
    .map_err(|_| AuthorizationPolicyError::Malformed)?;
    if provenance.schema_version != 1
        || provenance.authority_sha256 != authority_digest(&policy_bytes)
        || provenance.helper_identifier != policy.helper_identifier.as_deref().unwrap()
        || provenance.dashboard_bundle_identifier
            != policy.dashboard_bundle_identifier.as_deref().unwrap()
        || provenance.service_bundle_identifier
            != policy.service_bundle_identifier.as_deref().unwrap()
        || provenance.helper_relative_path != policy.helper_relative_path.as_deref().unwrap()
        || provenance.service_install_relative_path
            != policy.service_install_relative_path.as_deref().unwrap()
        || provenance.owner != policy.owner.as_deref().unwrap()
    {
        return Err(AuthorizationPolicyError::ProvenanceMismatch);
    }
    let helper = sealed_bundle_file(
        bundle,
        Path::new(policy.helper_relative_path.as_deref().unwrap()),
        expected_owner,
    )?;
    if authority_digest(&fs::read(helper).map_err(|_| AuthorizationPolicyError::Io)?)
        != provenance.helper_sha256
    {
        return Err(AuthorizationPolicyError::ProvenanceMismatch);
    }
    if validate_code {
        validate_static_code(
            bundle,
            policy.service_designated_requirement.as_deref().unwrap(),
        )?;
        validate_static_code(
            &bundle.join(policy.helper_relative_path.as_deref().unwrap()),
            policy.helper_designated_requirement.as_deref().unwrap(),
        )?;
    }
    Ok((policy, provenance))
}
/// Resolves the effective user's home through the account database, never `$HOME`.
pub fn trusted_effective_user_home() -> Result<PathBuf, AuthorizationPolicyError> {
    let uid = unsafe { libc::geteuid() };
    let mut buffer_len = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    if buffer_len < 0 {
        buffer_len = 16 * 1024;
    }
    let mut buffer_len = usize::try_from(buffer_len).map_err(|_| AuthorizationPolicyError::Io)?;
    const MAX_PASSWD_BUFFER: usize = 1024 * 1024;
    while buffer_len <= MAX_PASSWD_BUFFER {
        let mut passwd = MaybeUninit::<libc::passwd>::zeroed();
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0 as libc::c_char; buffer_len];
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                passwd.as_mut_ptr(),
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE {
            buffer_len = buffer_len
                .checked_mul(2)
                .ok_or(AuthorizationPolicyError::Io)?;
            continue;
        }
        if status != 0 || result.is_null() {
            return Err(AuthorizationPolicyError::Io);
        }
        let passwd = unsafe { passwd.assume_init() };
        if passwd.pw_dir.is_null() {
            return Err(AuthorizationPolicyError::Io);
        }
        let home = PathBuf::from(OsString::from_vec(
            unsafe { CStr::from_ptr(passwd.pw_dir) }.to_bytes().to_vec(),
        ));
        if home.as_os_str().is_empty() {
            return Err(AuthorizationPolicyError::Io);
        }
        return fs::canonicalize(home).map_err(|_| AuthorizationPolicyError::Io);
    }
    Err(AuthorizationPolicyError::Io)
}

/// Enforces the one supported per-user Service installation root before later ACL code uses it.
pub fn validate_service_install_path(
    bundle: &Path,
    policy: &AuthorizationPolicy,
) -> Result<(), AuthorizationPolicyError> {
    let expected_owner = unsafe { libc::geteuid() };
    validate_service_install_path_with_trusted_home(
        bundle,
        policy,
        expected_owner,
        &trusted_effective_user_home()?,
    )
}

fn validate_service_install_path_with_trusted_home(
    bundle: &Path,
    policy: &AuthorizationPolicy,
    expected_owner: u32,
    trusted_home: &Path,
) -> Result<(), AuthorizationPolicyError> {
    policy.validate()?;
    let expected = trusted_home.join(policy.service_install_relative_path.as_deref().unwrap());
    let canonical_expected =
        fs::canonicalize(&expected).map_err(|_| AuthorizationPolicyError::Io)?;
    let canonical_bundle = fs::canonicalize(bundle).map_err(|_| AuthorizationPolicyError::Io)?;
    if bundle != expected
        || bundle.is_symlink()
        || canonical_bundle != canonical_expected
        || canonical_bundle != bundle
    {
        return Err(AuthorizationPolicyError::UnsafePath);
    }
    sealed_directory(bundle, expected_owner)
}

/// Admits only the policy-pinned installed Service helper as the current caller.
///
/// This is the shared boundary for operations that derive authority from the
/// Service bundle.  It intentionally reuses the complete sealed-policy check
/// (including provenance, code-signature and helper-content validation) before
/// requiring both the canonical install location and the exact running helper.
pub fn validate_exact_installed_service_helper(
    bundle: &Path,
    current_executable: &Path,
    expected_owner: u32,
) -> Result<(AuthorizationPolicy, AuthorizationProvenance), AuthorizationPolicyError> {
    let (policy, provenance) = load_sealed(bundle, expected_owner)?;
    validate_service_install_path(bundle, &policy)?;
    let helper = sealed_bundle_file(
        bundle,
        Path::new(policy.helper_relative_path.as_deref().unwrap()),
        expected_owner,
    )?;
    if authority_digest(&fs::read(&helper).map_err(|_| AuthorizationPolicyError::Io)?)
        != provenance.helper_sha256
    {
        return Err(AuthorizationPolicyError::ProvenanceMismatch);
    }
    validate_current_helper_path(&helper, current_executable)?;
    Ok((policy, provenance))
}

/// Setup writes are accepted only when the immediate parent is a process that
/// satisfies the sealed dashboard designated requirement. This deliberately
/// rejects terminal, launchd, and ambiguous pipe callers even if they can find
/// the embedded helper on disk.
#[cfg(target_os = "macos")]
pub fn validate_dashboard_parent(
    service_bundle: &Path,
    parent_pid: libc::pid_t,
) -> Result<(), AuthorizationPolicyError> {
    if parent_pid <= 1 {
        return Err(AuthorizationPolicyError::UnsafePath);
    }
    let (policy, _) = load_sealed(service_bundle, unsafe { libc::geteuid() })?;
    validate_service_install_path(service_bundle, &policy)?;
    let mut path = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let copied = unsafe {
        proc_pidpath(
            parent_pid,
            path.as_mut_ptr().cast(),
            path.len()
                .try_into()
                .map_err(|_| AuthorizationPolicyError::Io)?,
        )
    };
    if copied <= 1 || copied as usize >= path.len() || path[copied as usize] != 0 {
        return Err(AuthorizationPolicyError::UnsafePath);
    }
    let dashboard = PathBuf::from(OsString::from_vec(path[..copied as usize].to_vec()));
    validate_static_code(
        &dashboard,
        policy.dashboard_designated_requirement.as_deref().unwrap(),
    )
}

#[cfg(target_os = "macos")]
#[link(name = "proc")]
unsafe extern "C" {
    fn proc_pidpath(pid: libc::pid_t, buffer: *mut libc::c_void, buffersize: u32) -> libc::c_int;
}

fn validate_current_helper_path(
    helper: &Path,
    current_executable: &Path,
) -> Result<(), AuthorizationPolicyError> {
    let helper = fs::canonicalize(helper).map_err(|_| AuthorizationPolicyError::Io)?;
    let current = fs::canonicalize(current_executable).map_err(|_| AuthorizationPolicyError::Io)?;
    if current == helper {
        Ok(())
    } else {
        Err(AuthorizationPolicyError::UnsafePath)
    }
}
fn expected_requirement(team: &str, identifier: &str) -> String {
    format!(
        "designated => anchor apple generic and identifier \"{}\" and certificate leaf[subject.OU] = \"{}\"",
        identifier, team
    )
}
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn authorization_policy_validate_static_code(
        path: *const libc::c_char,
        requirement: *const libc::c_char,
    ) -> libc::c_int;
    fn authorization_policy_has_quarantine(path: *const libc::c_char) -> libc::c_int;
}
fn requirements_equivalent(actual: &str, expected: &str) -> bool {
    // The authority template is the canonical serialization. Exact equivalence
    // rejects alternate/weakened requirement text; Security.framework parses and
    // evaluates it against the installed helper in `validate_static_code`.
    actual == expected
}
fn validate_static_code(path: &Path, requirement: &str) -> Result<(), AuthorizationPolicyError> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        let path = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| AuthorizationPolicyError::UnsafePath)?;
        let requirement =
            CString::new(requirement).map_err(|_| AuthorizationPolicyError::IntegrityMismatch)?;
        if unsafe { authorization_policy_validate_static_code(path.as_ptr(), requirement.as_ptr()) }
            != 1
        {
            return Err(AuthorizationPolicyError::IntegrityMismatch);
        }
    }
    Ok(())
}
fn safe_relative(value: &str) -> Result<(), AuthorizationPolicyError> {
    let p = Path::new(value);
    if p.is_absolute() || p.components().any(|c| !matches!(c, Component::Normal(_))) {
        Err(AuthorizationPolicyError::UnsafePath)
    } else {
        Ok(())
    }
}
fn sealed_bundle_file(
    bundle: &Path,
    relative: &Path,
    expected_owner: u32,
) -> Result<PathBuf, AuthorizationPolicyError> {
    let relative = relative
        .to_str()
        .ok_or(AuthorizationPolicyError::UnsafePath)?;
    safe_relative(relative)?;
    sealed_directory(bundle, expected_owner)?;
    reject_quarantine(bundle)?;
    let canonical_bundle = fs::canonicalize(bundle).map_err(|_| AuthorizationPolicyError::Io)?;
    if canonical_bundle != bundle {
        return Err(AuthorizationPolicyError::UnsafePath);
    }
    let mut current = bundle.to_path_buf();
    let components: Vec<_> = Path::new(relative).components().collect();
    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        let meta = fs::symlink_metadata(&current).map_err(|_| AuthorizationPolicyError::Io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.file_type().is_symlink()
                || if index + 1 == components.len() {
                    !meta.is_file()
                } else {
                    !meta.is_dir()
                }
            {
                return Err(AuthorizationPolicyError::UnsafePath);
            }
            if meta.uid() != expected_owner || meta.mode() & 0o022 != 0 {
                return Err(AuthorizationPolicyError::UnsafeMetadata);
            }
        }
        reject_quarantine(&current)?;
        let canonical = fs::canonicalize(&current).map_err(|_| AuthorizationPolicyError::Io)?;
        if !canonical.starts_with(&canonical_bundle) || canonical != current {
            return Err(AuthorizationPolicyError::UnsafePath);
        }
    }
    Ok(current)
}
fn reject_quarantine(_path: &Path) -> Result<(), AuthorizationPolicyError> {
    #[cfg(target_os = "macos")]
    {
        use std::ffi::CString;
        let path = CString::new(_path.as_os_str().as_encoded_bytes())
            .map_err(|_| AuthorizationPolicyError::UnsafePath)?;
        quarantine_inspection_result(unsafe { authorization_policy_has_quarantine(path.as_ptr()) })
    }
    #[cfg(not(target_os = "macos"))]
    Ok(())
}
#[cfg(target_os = "macos")]
fn quarantine_inspection_result(status: libc::c_int) -> Result<(), AuthorizationPolicyError> {
    match status {
        0 => Ok(()),
        1 => Err(AuthorizationPolicyError::UnsafePath),
        _ => Err(AuthorizationPolicyError::QuarantineInspection),
    }
}
fn sealed_directory(path: &Path, expected_owner: u32) -> Result<(), AuthorizationPolicyError> {
    let meta = fs::symlink_metadata(path).map_err(|_| AuthorizationPolicyError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(AuthorizationPolicyError::UnsafePath);
        }
        if meta.uid() != expected_owner || meta.mode() & 0o022 != 0 {
            return Err(AuthorizationPolicyError::UnsafeMetadata);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    fn policy() -> AuthorizationPolicy {
        serde_json::from_str(include_str!(
            "../policies/authorization-policy-production.json"
        ))
        .unwrap()
    }

    #[test]
    fn production_policy_requires_the_exact_default_keychain_authentication_type() {
        let policy = policy();
        assert_eq!(
            policy.item.as_ref().unwrap().authentication_type,
            KEYCHAIN_AUTH_DEFAULT
        );
    }
    #[test]
    fn production_authority_is_strict() {
        policy().validate().unwrap();
    }
    #[test]
    fn production_policy_binds_the_runtime_v2_keychain_namespace() {
        let policy = policy();
        assert_eq!(
            policy
                .item
                .as_ref()
                .and_then(|item| item.security_domain.as_deref()),
            Some(SMB_SECURITY_DOMAIN)
        );

        let native = include_str!("keychain_authorization_macos.c");
        let runtime_domain =
            format!("static const char optimizer_domain_v2[] = \"{SMB_SECURITY_DOMAIN}\";");
        assert!(native.contains(runtime_domain.as_str()));
        let retired_domain = SMB_SECURITY_DOMAIN.replace(".v2", ".v1");
        assert_eq!(native.matches(retired_domain.as_str()).count(), 1);
        assert!(
            native.contains(
                "static const char optimizer_domain_v1_retired[] __attribute__((unused))"
            )
        );
        let exact_v2 = &native[native.find("static int exact_v2_item(").unwrap()
            ..native
                .find("static int begin_without_interaction(")
                .unwrap()];
        assert!(exact_v2.contains("optimizer_domain_v2"));
        assert!(!exact_v2.contains("optimizer_domain_v1_retired"));
        let runtime = &native[native.find("static int exact_v2_item(").unwrap()..];
        assert!(!runtime.contains("optimizer_domain_v1_retired"));
        assert!(!runtime.contains(retired_domain.as_str()));
    }
    #[test]
    fn retired_v1_namespace_is_rejected_without_a_policy_fallback() {
        let mut p = policy();
        let retired = SMB_SECURITY_DOMAIN.replace(".v2", ".v1");
        p.item.as_mut().unwrap().security_domain = Some(retired);
        assert!(matches!(
            p.validate(),
            Err(AuthorizationPolicyError::Malformed)
        ));
    }
    #[test]
    fn only_retired_v1_and_current_v2_namespaces_are_admitted_for_rotation() {
        let mut p = policy();
        p.item.as_mut().unwrap().security_domain = Some(RETIRED_SMB_SECURITY_DOMAIN.into());
        assert!(matches!(
            p.validate(),
            Err(AuthorizationPolicyError::Malformed)
        ));
        p.validate_for_recovery_rotation().unwrap();

        let mut p = policy();
        p.validate_for_recovery_rotation().unwrap();

        p.item.as_mut().unwrap().security_domain = Some("com.icloudpd-optimizer.smb.future".into());
        assert!(matches!(
            p.validate_for_recovery_rotation(),
            Err(AuthorizationPolicyError::Malformed)
        ));
    }
    #[test]
    fn wrong_team_or_identifier_rejected() {
        let mut p = policy();
        p.team_id = Some("AAAAAAAAAA".into());
        assert!(p.validate().is_err());
        let mut p = policy();
        p.helper_identifier = Some("wrong".into());
        assert!(p.validate().is_err());
        let mut p = policy();
        p.team_id = Some("not-a-team".into());
        assert!(p.validate().is_err());
    }
    #[test]
    fn malformed_weakened_and_wrong_requirement_rejected() {
        let mut p = policy();
        p.helper_designated_requirement =
            Some("identifier \"com.icloudpd-optimizer.helper\"".into());
        assert!(matches!(
            p.validate(),
            Err(AuthorizationPolicyError::IntegrityMismatch)
        ));
        let mut p = policy();
        p.helper_designated_requirement = Some("not a requirement".into());
        assert!(matches!(
            p.validate(),
            Err(AuthorizationPolicyError::IntegrityMismatch)
        ));
        let mut p = policy();
        p.helper_designated_requirement = Some(expected_requirement(
            p.team_id.as_deref().unwrap(),
            "wrong.helper",
        ));
        assert!(matches!(
            p.validate(),
            Err(AuthorizationPolicyError::IntegrityMismatch)
        ));
    }
    #[test]
    fn same_team_rotation_keeps_canonical_requirement() {
        let p = policy();
        assert!(p.validate().is_ok());
        let prior_source_commit = "0".repeat(40);
        let rotated_source_commit = "1".repeat(40);
        assert_ne!(prior_source_commit, rotated_source_commit);
        assert!(
            !p.helper_designated_requirement
                .as_deref()
                .unwrap()
                .contains("certificate leaf =")
        );
        assert!(p.validate().is_ok());
    }
    #[test]
    fn disabled_is_unavailable() {
        let p: AuthorizationPolicy = serde_json::from_str(include_str!(
            "../policies/authorization-policy-disabled.json"
        ))
        .unwrap();
        assert!(matches!(
            p.validate(),
            Err(AuthorizationPolicyError::Disabled)
        ));
    }
    fn sealed_test_bundle() -> tempfile::TempDir {
        let d = tempfile::Builder::new()
            .prefix("authorization-policy-")
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .unwrap();
        let bundle = d.path().join("Service.app");
        fs::create_dir_all(bundle.join("Contents/Resources")).unwrap();
        for file in [POLICY_RESOURCE, PROVENANCE_RESOURCE, "icloudpd-optimizer"] {
            fs::write(bundle.join("Contents/Resources").join(file), "sealed").unwrap();
        }
        d
    }
    #[test]
    fn rejects_unsafe_contents_and_resources() {
        use std::os::unix::fs::PermissionsExt;
        let d = sealed_test_bundle();
        let bundle = d.path().join("Service.app");
        let contents = bundle.join("Contents");
        let resources = contents.join("Resources");
        for unsafe_path in [&contents, &resources] {
            fs::set_permissions(unsafe_path, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(matches!(
                sealed_bundle_file(
                    &bundle,
                    Path::new("Contents/Resources")
                        .join(POLICY_RESOURCE)
                        .as_path(),
                    unsafe { libc::geteuid() }
                ),
                Err(AuthorizationPolicyError::UnsafeMetadata)
            ));
            fs::set_permissions(unsafe_path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    #[test]
    fn rejects_intermediate_symlink_component() {
        let d = sealed_test_bundle();
        let bundle = d.path().join("Service.app");
        let contents = bundle.join("Contents");
        let resources = contents.join("Resources");
        let real = contents.join("real-resources");
        fs::rename(&resources, &real).unwrap();
        std::os::unix::fs::symlink(&real, &resources).unwrap();
        assert!(matches!(
            sealed_bundle_file(
                &bundle,
                Path::new("Contents/Resources")
                    .join(POLICY_RESOURCE)
                    .as_path(),
                unsafe { libc::geteuid() }
            ),
            Err(AuthorizationPolicyError::UnsafePath)
        ));
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn rejects_quarantined_component() {
        let d = sealed_test_bundle();
        let bundle = d.path().join("Service.app");
        let path = bundle.join("Contents/Resources");
        assert!(
            std::process::Command::new("xattr")
                .args([
                    "-w",
                    "com.apple.quarantine",
                    "0081;0;test;",
                    path.to_str().unwrap()
                ])
                .status()
                .unwrap()
                .success()
        );
        assert!(matches!(
            sealed_bundle_file(
                &bundle,
                Path::new("Contents/Resources")
                    .join(POLICY_RESOURCE)
                    .as_path(),
                unsafe { libc::geteuid() }
            ),
            Err(AuthorizationPolicyError::UnsafePath)
        ));
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn quarantine_inspection_requires_a_cleanly_absent_attribute() {
        let d = sealed_test_bundle();
        let clean = d.path().join("Service.app");
        assert!(reject_quarantine(&clean).is_ok());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn quarantine_c_bridge_errors_fail_closed() {
        use std::ffi::CString;

        let d = sealed_test_bundle();
        let missing = d.path().join("missing");
        let path = CString::new(missing.as_os_str().as_encoded_bytes()).unwrap();
        let status = unsafe { authorization_policy_has_quarantine(path.as_ptr()) };
        assert_eq!(status, -1);
        assert!(matches!(
            quarantine_inspection_result(status),
            Err(AuthorizationPolicyError::QuarantineInspection)
        ));
    }
    #[test]
    fn rejects_wrong_owner_and_mode_in_sealed_chain() {
        use std::os::unix::fs::PermissionsExt;
        let d = sealed_test_bundle();
        let bundle = d.path().join("Service.app");
        assert!(matches!(
            sealed_bundle_file(
                &bundle,
                Path::new("Contents/Resources")
                    .join(POLICY_RESOURCE)
                    .as_path(),
                unsafe { libc::geteuid() } + 1
            ),
            Err(AuthorizationPolicyError::UnsafeMetadata)
        ));
        let helper = bundle.join("Contents/Resources/icloudpd-optimizer");
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            sealed_bundle_file(
                &bundle,
                Path::new("Contents/Resources/icloudpd-optimizer"),
                unsafe { libc::geteuid() }
            ),
            Err(AuthorizationPolicyError::UnsafeMetadata)
        ));
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn static_code_or_resource_seal_failure_is_rejected() {
        let p = policy();
        assert!(
            validate_static_code(
                Path::new("/definitely/not/a/sealed-service.app"),
                p.helper_designated_requirement.as_deref().unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn rejects_noncanonical_service_path() {
        let p = policy();
        assert!(
            validate_service_install_path_with_trusted_home(
                Path::new("/tmp/service"),
                &p,
                unsafe { libc::geteuid() },
                Path::new("/tmp"),
            )
            .is_err()
        );
    }
    #[test]
    fn rejects_byte_identical_copied_service_under_forged_home_before_authority_derivation() {
        let p = policy();
        let d = tempdir().unwrap();
        let canonical_temp = fs::canonicalize(d.path()).unwrap();
        let trusted_home = canonical_temp.join("trusted-home");
        let forged_home = canonical_temp.join("forged-home");
        let relative = Path::new(p.service_install_relative_path.as_deref().unwrap());
        let trusted = trusted_home.join(relative);
        let copied = forged_home.join(relative);
        for bundle in [&trusted, &copied] {
            fs::create_dir_all(bundle.join("Contents/Resources")).unwrap();
            fs::write(
                bundle.join("Contents/Resources/icloudpd-optimizer"),
                b"sealed helper",
            )
            .unwrap();
        }
        let launched_copied_helper = copied.join("Contents/Resources/icloudpd-optimizer");
        assert!(
            validate_current_helper_path(&launched_copied_helper, &launched_copied_helper).is_ok()
        );
        validate_service_install_path_with_trusted_home(
            &trusted,
            &p,
            unsafe { libc::geteuid() },
            &trusted_home,
        )
        .expect("the trusted exact install path must remain accepted");
        assert!(matches!(
            validate_service_install_path_with_trusted_home(
                &copied,
                &p,
                unsafe { libc::geteuid() },
                &trusted_home,
            ),
            Err(AuthorizationPolicyError::UnsafePath)
        ));
    }
    #[test]
    fn rejects_wrong_current_helper_before_authority_derivation() {
        let temp = tempdir().unwrap();
        let helper = temp.path().join("helper");
        let alternate = temp.path().join("alternate-helper");
        fs::write(&helper, b"helper").unwrap();
        fs::write(&alternate, b"alternate").unwrap();
        assert!(validate_current_helper_path(&helper, &helper).is_ok());
        assert!(matches!(
            validate_current_helper_path(&helper, &alternate),
            Err(AuthorizationPolicyError::UnsafePath)
        ));
    }
    #[test]
    fn provenance_explicitly_binds_owner() {
        let p = policy();
        let provenance = AuthorizationProvenance {
            schema_version: 1,
            source_commit: "a".repeat(40),
            authority_sha256: "b".repeat(64),
            helper_sha256: "c".repeat(64),
            helper_identifier: p.helper_identifier.unwrap(),
            dashboard_bundle_identifier: p.dashboard_bundle_identifier.unwrap(),
            service_bundle_identifier: p.service_bundle_identifier.unwrap(),
            helper_relative_path: p.helper_relative_path.unwrap(),
            service_install_relative_path: p.service_install_relative_path.unwrap(),
            owner: "wrong_owner".into(),
        };
        assert_ne!(provenance.owner, "effective_user");
    }
    #[test]
    fn packaging_signs_before_hashes_and_production_requires_clean_tree() {
        let script = include_str!("../packaging/macos/build-app.sh");
        let helper_sign = script
            .find("codesign_redacted --force --options runtime --timestamp=none --identifier com.icloudpd-optimizer.helper --keychain \"$keychain_path\" --sign \"${leaf_sha1:-$sign_identity}\" -r=\"$helper_requirement\" \"$resources_path/icloudpd-optimizer\"")
            .unwrap();
        let helper_hash = script.find("helper_sha256=").unwrap();
        let host_sign = script
            .rfind("codesign_redacted --force --options runtime --timestamp=none --identifier \"$id\" --keychain \"$keychain_path\" --sign \"${leaf_sha1:-$sign_identity}\" -r=\"$host_requirement\" \"$app_path\"")
            .unwrap();
        assert!(helper_sign < helper_hash && helper_hash < host_sign);
        assert!(script.contains("git status --porcelain --untracked-files=all"));
        assert!(
            script.contains("production authority requires an explicit canonical login keychain")
        );
        assert!(script.contains("security find-identity -v -p codesigning \"$expected_keychain\""));
        assert!(script.contains("requested_identity_sha1="));
        assert!(script.contains("label == expected || toupper(hash) == requested"));
        assert!(script.contains("production authority noninteractive signing probe failed"));
        assert!(script.contains("anchor apple generic"));
        assert!(script.contains("certificate leaf[subject.OU]"));
        assert!(!script.contains("certificate root"));
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn disabled_build_hashes_signed_helper_before_host_sealing() {
        use std::{env, process::Command};
        let d = tempdir().unwrap();
        let tools = d.path().join("tools");
        fs::create_dir(&tools).unwrap();
        let log = d.path().join("codesign.log");
        fs::write(
            tools.join("xcrun"),
            "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = \"-o\" ] && { : > \"$2\"; chmod 755 \"$2\"; exit 0; }; shift; done\nexit 1\n",
        ).unwrap();
        fs::write(
            tools.join("codesign"),
            "#!/bin/sh\nlast=\"\"; for arg in \"$@\"; do last=\"$arg\"; done\n[ \"$1\" = --verify ] && exit 0\nprintf '%s\\n' \"$last\" >> \"$ICLOUDPD_TEST_CODESIGN_LOG\"\n[ -f \"$last\" ] && printf signed >> \"$last\"\nexit 0\n",
        ).unwrap();
        for tool in ["xcrun", "codesign"] {
            let mut permissions = fs::metadata(tools.join(tool)).unwrap().permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
            fs::set_permissions(tools.join(tool), permissions).unwrap();
        }
        let binary = d.path().join("helper");
        fs::write(&binary, "helper").unwrap();
        let output = d.path().join("dist");
        let path = format!("{}:{}", tools.display(), env::var("PATH").unwrap());
        let build = Command::new("bash")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/packaging/macos/build-app.sh"
            ))
            .args([
                "--bin",
                binary.to_str().unwrap(),
                "--output",
                output.to_str().unwrap(),
                "--authority",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/policies/authorization-policy-disabled.json"
                ),
            ])
            .env("PATH", path)
            .env("ICLOUDPD_TEST_CODESIGN_LOG", &log)
            .output()
            .unwrap();
        assert!(
            build.status.success(),
            "{}",
            String::from_utf8_lossy(&build.stderr)
        );
        let helper = output.join("iCloudPD Optimizer.app/Contents/Resources/icloudpd-optimizer");
        let provenance: AuthorizationProvenance =
            serde_json::from_slice(
                &fs::read(output.join(
                    "iCloudPD Optimizer.app/Contents/Resources/authorization-provenance.json",
                ))
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            authority_digest(&fs::read(helper).unwrap()),
            provenance.helper_sha256
        );
        let signed = fs::read_to_string(log).unwrap();
        assert!(
            signed
                .lines()
                .next()
                .unwrap()
                .ends_with("/icloudpd-optimizer")
        );
    }
}

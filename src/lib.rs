pub mod adjusted_source;
pub mod authorization_policy;
pub mod cli;
pub mod conversion;
pub mod conversion_backend;
pub mod conversion_execution;
#[cfg(target_os = "macos")]
pub mod keychain_authorization;
pub mod legacy_upload_migration;
pub mod local_mirror;
pub mod manifest;
pub mod manifest_lock;
pub mod metrics;
pub mod monitor;
pub mod proof;
pub mod reconciliation;
pub mod service;
#[cfg(target_os = "macos")]
pub mod smb_noreplace;
pub mod state_store;
mod strict_json;
pub mod upload;
pub mod workflow;

#[cfg(test)]
pub(crate) static PROCESS_PATH_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

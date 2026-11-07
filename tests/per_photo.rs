use icloudpd_optimizer::upload::{
    ProviderSessionDiagnosticClass, ProviderSessionRole, ProviderTransportFailureClass,
    UploadError, classify_provider_transport_failure, diagnose_provider_session,
};
use serde_json::json;

fn query_params() -> Vec<serde_json::Value> {
    vec![
        json!({"name": "clientBuildNumber", "value": "2522Project44"}),
        json!({"name": "clientMasteringNumber", "value": "2522B2"}),
        json!({"name": "clientId", "value": "4f0b58d4-ff9d-4dc5-8f0b-9c4efc4fdb27"}),
        json!({"name": "dsid", "value": "123456789"}),
        json!({"name": "remapEnums", "value": "True"}),
        json!({"name": "getCurrentSyncToken", "value": "True"}),
    ]
}

fn session(scope: &str, zone: &str, owner: Option<&str>) -> String {
    let mut value = json!({
        "dsid": "123456789",
        "ckdatabasews_url": "https://p140-ckdatabasews.icloud.com",
        "database_scope": scope,
        "zone_name": zone,
        "cloudkit_query_params": query_params(),
        "cookies": [
            {"name": "X-APPLE-WEBAUTH-TOKEN", "value": "SENTINEL_COOKIE_VALUE"},
            {"name": "session", "value": "SENTINEL_SESSION_VALUE"}
        ]
    });
    if let Some(owner) = owner {
        value["owner_record_name"] = json!(owner);
    }
    value.to_string()
}

#[test]
fn shared_sync_private_scope_is_local_misconfiguration_not_authentication() {
    let diagnostic = diagnose_provider_session(
        ProviderSessionRole::CloudKitRead,
        &session("private", "SharedSync-ABCDEF123456", Some("_shared-owner")),
    );
    assert_eq!(
        diagnostic.class,
        ProviderSessionDiagnosticClass::LocalMisconfiguration
    );
    assert_eq!(diagnostic.code, "shared_sync_requires_shared_scope");
    assert!(
        diagnostic
            .message
            .contains("SharedSync zones must use the shared CloudKit database scope")
    );
    assert!(!diagnostic.network_contacted);
    assert!(!diagnostic.authenticated);
    assert!(
        diagnostic
            .supported_requirement
            .contains("no supported provider setup")
    );
    let rendered = serde_json::to_string(&diagnostic).unwrap();
    assert!(!rendered.contains("SENTINEL_COOKIE_VALUE"));
    assert!(!rendered.contains("SENTINEL_SESSION_VALUE"));
    assert_eq!(
        classify_provider_transport_failure(&UploadError::InvalidSession(
            diagnostic.message.clone()
        )),
        ProviderTransportFailureClass::LocalMisconfiguration
    );
    assert_eq!(
        classify_provider_transport_failure(&UploadError::UploadHttpStatus {
            operation: "records_query",
            status: 401,
        }),
        ProviderTransportFailureClass::AuthRejection
    );
    assert_eq!(
        classify_provider_transport_failure(&UploadError::UploadHttpStatus {
            operation: "records_query",
            status: 500,
        }),
        ProviderTransportFailureClass::RemoteFailure
    );
}

#[test]
fn shared_schema_can_be_locally_valid_without_becoming_authenticated() {
    let diagnostic = diagnose_provider_session(
        ProviderSessionRole::CloudKitRead,
        &session("shared", "SharedSync-ABCDEF123456", Some("_shared-owner")),
    );
    assert_eq!(
        diagnostic.class,
        ProviderSessionDiagnosticClass::LocalConfigurationValid
    );
    assert!(!diagnostic.authenticated);
    assert!(!diagnostic.network_contacted);
    assert_eq!(
        classify_provider_transport_failure(&UploadError::PhotosPutAssetRejected {
            status: 403,
            detail: "SENTINEL_RESPONSE_BODY".to_string(),
        }),
        ProviderTransportFailureClass::AuthRejection
    );
}

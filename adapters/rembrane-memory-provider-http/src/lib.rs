//! Authenticated bounded HTTP client for Memory Provider Protocol discovery.

use std::io::Read;
use std::time::Duration;

use rembrane_provider_sdk::{
    CURRENT_MEMORY_PROVIDER_PROTOCOL, MEMORY_PROVIDER_DISCOVERY_PATH, MemoryProviderCapability,
    MemoryProviderConnection, MemoryProviderLimits, MemoryProviderManifest, MemoryProviderPolicy,
    MemoryProviderPrivacyMode, MemoryProviderTransport, ProviderError, ProviderProtocolVersion,
};
use reqwest::Url;
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::Deserialize;
use zeroize::Zeroizing;

const MAXIMUM_DISCOVERY_BYTES: u64 = 262_144;

pub struct HttpMemoryProviderClient {
    client: Client,
    discovery_endpoint: Url,
    bearer_token: Zeroizing<String>,
}

impl HttpMemoryProviderClient {
    pub fn new(base_url: &str, bearer_token: String) -> Result<Self, ProviderError> {
        let base = validate_base_url(base_url)?;
        validate_bearer_token(&bearer_token)?;
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| ProviderError::Unavailable)?;
        Ok(Self {
            client,
            discovery_endpoint: base
                .join(MEMORY_PROVIDER_DISCOVERY_PATH.trim_start_matches('/'))
                .map_err(|_| ProviderError::Unavailable)?,
            bearer_token: Zeroizing::new(bearer_token),
        })
    }

    pub fn discover(&self) -> Result<MemoryProviderManifest, ProviderError> {
        let response = self
            .client
            .get(self.discovery_endpoint.clone())
            .header(ACCEPT, "application/json")
            .bearer_auth(self.bearer_token.as_str())
            .send()
            .map_err(|_| ProviderError::Unavailable)?;
        let wire: DiscoveryBody = decode_json(response, MAXIMUM_DISCOVERY_BYTES)?;
        wire.try_into()
    }

    pub fn connect(
        &self,
        policy: &MemoryProviderPolicy,
        request_prefix: impl Into<String>,
    ) -> Result<MemoryProviderConnection, ProviderError> {
        MemoryProviderConnection::connect(self.discover()?, policy, request_prefix)
    }
}

fn validate_base_url(value: &str) -> Result<Url, ProviderError> {
    let mut url = Url::parse(value).map_err(|_| {
        ProviderError::InvalidConfiguration("memory provider base URL is invalid".to_owned())
    })?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(ProviderError::InvalidConfiguration(
            "memory provider base URL must be an origin without credentials".to_owned(),
        ));
    }
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "::1" | "localhost"));
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(ProviderError::InvalidConfiguration(
            "memory provider transport requires HTTPS outside exact loopback hosts".to_owned(),
        ));
    }
    url.set_path("/");
    Ok(url)
}

fn validate_bearer_token(value: &str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > 8192
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-')
        })
    {
        return Err(ProviderError::InvalidConfiguration(
            "memory provider bearer token is empty or header-unsafe".to_owned(),
        ));
    }
    Ok(())
}

fn decode_json<Body: for<'de> Deserialize<'de>>(
    response: Response,
    maximum_bytes: u64,
) -> Result<Body, ProviderError> {
    if !response.status().is_success() {
        return Err(ProviderError::Unavailable);
    }
    let is_json = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|kind| kind.eq_ignore_ascii_case("application/json"))
        });
    if !is_json
        || response
            .content_length()
            .is_some_and(|length| length > maximum_bytes)
    {
        return Err(ProviderError::Rejected(
            "memory provider returned an invalid response".to_owned(),
        ));
    }
    let mut body = Vec::new();
    response
        .take(maximum_bytes + 1)
        .read_to_end(&mut body)
        .map_err(|_| ProviderError::Unavailable)?;
    if body.len() as u64 > maximum_bytes {
        return Err(ProviderError::Rejected(
            "memory provider response exceeds the transport limit".to_owned(),
        ));
    }
    serde_json::from_slice(&body)
        .map_err(|_| ProviderError::Rejected("memory provider returned malformed JSON".to_owned()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DiscoveryBody {
    provider_id: String,
    provider_version: String,
    protocol_version: String,
    transports: Vec<String>,
    capabilities: Vec<String>,
    privacy_mode: String,
    #[serde(default)]
    supported_domains: Vec<String>,
    limits: DiscoveryLimits,
    operations: Vec<OperationBinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DiscoveryLimits {
    maximum_context_items: usize,
    maximum_context_bytes: usize,
    maximum_event_batch_items: usize,
    maximum_sync_batch_items: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct OperationBinding {
    operation: String,
    capability: String,
    oauth_scope: String,
    http_method: String,
    path_template: String,
}

impl TryFrom<DiscoveryBody> for MemoryProviderManifest {
    type Error = ProviderError;

    fn try_from(wire: DiscoveryBody) -> Result<Self, Self::Error> {
        let protocol_version = parse_protocol(&wire.protocol_version)?;
        let transports = wire
            .transports
            .iter()
            .map(|value| match value.as_str() {
                "https" => Ok(MemoryProviderTransport::Https),
                "mcp" => Ok(MemoryProviderTransport::Mcp),
                _ => Err(invalid_discovery()),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let capabilities = wire
            .capabilities
            .iter()
            .map(|value| parse_capability(value))
            .collect::<Result<Vec<_>, _>>()?;
        validate_operation_bindings(&wire.operations, &capabilities)?;
        let privacy_mode = match wire.privacy_mode.as_str() {
            "end_to_end_encrypted" => MemoryProviderPrivacyMode::EndToEndEncrypted,
            "trusted_boundary" => MemoryProviderPrivacyMode::TrustedBoundary,
            "provider_plaintext" => MemoryProviderPrivacyMode::ProviderPlaintext,
            _ => return Err(invalid_discovery()),
        };
        Self::new(
            wire.provider_id,
            wire.provider_version,
            protocol_version,
            transports,
            capabilities,
            privacy_mode,
            wire.supported_domains,
            MemoryProviderLimits {
                maximum_context_items: wire.limits.maximum_context_items,
                maximum_context_bytes: wire.limits.maximum_context_bytes,
                maximum_event_batch_items: wire.limits.maximum_event_batch_items,
                maximum_sync_batch_items: wire.limits.maximum_sync_batch_items,
            },
        )
    }
}

fn parse_protocol(value: &str) -> Result<ProviderProtocolVersion, ProviderError> {
    if value == "0.1" {
        Ok(CURRENT_MEMORY_PROVIDER_PROTOCOL)
    } else {
        Err(ProviderError::IncompatibleProtocol {
            required_major: CURRENT_MEMORY_PROVIDER_PROTOCOL.major,
            required_minor: CURRENT_MEMORY_PROVIDER_PROTOCOL.minor,
            offered_major: 0,
            offered_minor: 0,
        })
    }
}

fn parse_capability(value: &str) -> Result<MemoryProviderCapability, ProviderError> {
    [
        MemoryProviderCapability::ResolveContext,
        MemoryProviderCapability::ResolveQuestion,
        MemoryProviderCapability::RecordEvent,
        MemoryProviderCapability::ProposeMemory,
        MemoryProviderCapability::CheckpointActivity,
        MemoryProviderCapability::RecordDisclosure,
        MemoryProviderCapability::DeleteMemory,
        MemoryProviderCapability::ExplainMemory,
        MemoryProviderCapability::SyncPull,
        MemoryProviderCapability::SyncPush,
    ]
    .into_iter()
    .find(|capability| capability.as_str() == value)
    .ok_or_else(invalid_discovery)
}

fn validate_operation_bindings(
    bindings: &[OperationBinding],
    capabilities: &[MemoryProviderCapability],
) -> Result<(), ProviderError> {
    if bindings.len() != capabilities.len() {
        return Err(invalid_discovery());
    }
    for capability in capabilities {
        let operation = capability.as_str();
        let matches: Vec<_> = bindings
            .iter()
            .filter(|binding| binding.operation == operation)
            .collect();
        if matches.len() != 1 {
            return Err(invalid_discovery());
        }
        let binding = matches[0];
        if binding.capability != operation
            || binding.oauth_scope != operation_scope(*capability)
            || binding.http_method != operation_method(*capability)
            || binding.path_template != operation_path(*capability)
        {
            return Err(invalid_discovery());
        }
    }
    Ok(())
}

const fn operation_scope(capability: MemoryProviderCapability) -> &'static str {
    use MemoryProviderCapability as Capability;
    match capability {
        Capability::ResolveContext => "memory:context:read",
        Capability::ResolveQuestion => "memory:question:read",
        Capability::RecordEvent => "memory:event:write",
        Capability::ProposeMemory => "memory:proposal:write",
        Capability::CheckpointActivity => "memory:checkpoint:write",
        Capability::RecordDisclosure => "memory:disclosure:write",
        Capability::DeleteMemory => "memory:memory:delete",
        Capability::ExplainMemory => "memory:memory:explain",
        Capability::SyncPull => "memory:sync:read",
        Capability::SyncPush => "memory:sync:write",
    }
}

const fn operation_method(capability: MemoryProviderCapability) -> &'static str {
    use MemoryProviderCapability as Capability;
    match capability {
        Capability::ExplainMemory | Capability::SyncPull => "GET",
        Capability::DeleteMemory => "DELETE",
        _ => "POST",
    }
}

const fn operation_path(capability: MemoryProviderCapability) -> &'static str {
    use MemoryProviderCapability as Capability;
    match capability {
        Capability::ResolveContext => "/v1/context/resolve",
        Capability::ResolveQuestion => "/v1/questions/resolve",
        Capability::RecordEvent => "/v1/events",
        Capability::ProposeMemory => "/v1/memory/proposals",
        Capability::CheckpointActivity => "/v1/activities/{activity_id}/checkpoint",
        Capability::RecordDisclosure => "/v1/disclosures/receipt",
        Capability::DeleteMemory => "/v1/memories/{memory_id}",
        Capability::ExplainMemory => "/v1/memories/{memory_id}/explain",
        Capability::SyncPull => "/v1/sync/pull",
        Capability::SyncPush => "/v1/sync/push",
    }
}

fn invalid_discovery() -> ProviderError {
    ProviderError::InvalidConfiguration(
        "memory provider discovery does not match the canonical HTTP binding".to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::{DiscoveryBody, MemoryProviderManifest, validate_base_url, validate_bearer_token};

    const DISCOVERY: &str = r#"{
      "providerId":"rembrane.memory.example",
      "providerVersion":"1.0",
      "protocolVersion":"0.1",
      "transports":["https"],
      "capabilities":["resolve_context","delete_memory"],
      "privacyMode":"end_to_end_encrypted",
      "supportedDomains":["personal"],
      "limits":{
        "maximumContextItems":100,
        "maximumContextBytes":1048576,
        "maximumEventBatchItems":100,
        "maximumSyncBatchItems":100
      },
      "operations":[
        {
          "operation":"resolve_context",
          "capability":"resolve_context",
          "oauthScope":"memory:context:read",
          "httpMethod":"POST",
          "pathTemplate":"/v1/context/resolve"
        },
        {
          "operation":"delete_memory",
          "capability":"delete_memory",
          "oauthScope":"memory:memory:delete",
          "httpMethod":"DELETE",
          "pathTemplate":"/v1/memories/{memory_id}"
        }
      ]
    }"#;

    #[test]
    fn accepts_https_and_exact_loopback_origins_only() {
        for valid in ["https://memory.example.test", "http://127.0.0.1:8794"] {
            assert!(validate_base_url(valid).is_ok());
        }
        for invalid in [
            "http://memory.example.test",
            "https://user:secret@memory.example.test",
            "https://memory.example.test/provider",
            "https://memory.example.test?token=secret",
        ] {
            assert!(validate_base_url(invalid).is_err());
        }
    }

    #[test]
    fn rejects_header_unsafe_credentials() {
        assert!(validate_bearer_token("").is_err());
        assert!(validate_bearer_token("token with spaces").is_err());
        assert!(validate_bearer_token("token\r\ninjected:value").is_err());
        assert!(validate_bearer_token("opaque-token_123").is_ok());
    }

    #[test]
    fn parses_only_exact_canonical_operation_bindings() {
        let wire: DiscoveryBody = serde_json::from_str(DISCOVERY).expect("discovery JSON");
        let manifest = MemoryProviderManifest::try_from(wire).expect("manifest should validate");
        assert_eq!(manifest.id(), "rembrane.memory.example");

        let malformed = DISCOVERY.replace("\"memory:memory:delete\"", "\"memory:context:read\"");
        let wire: DiscoveryBody = serde_json::from_str(&malformed).expect("discovery JSON");
        assert!(MemoryProviderManifest::try_from(wire).is_err());
    }
}

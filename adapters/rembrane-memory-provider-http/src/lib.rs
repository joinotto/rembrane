//! Authenticated bounded HTTP client for Memory Provider Protocol discovery.

use std::io::Read;
use std::time::Duration;

use rembrane_domain::{
    ActivityId, ContextPackId, DisclosureId, EntityId, EvidenceId, EvidenceReference,
    EvidenceSource, MemoryId, MemoryKind, MemoryScope,
};
use rembrane_provider_sdk::{
    CURRENT_MEMORY_PROVIDER_PROTOCOL, MEMORY_PROVIDER_DISCOVERY_PATH, MemoryProviderCapability,
    MemoryProviderConnection, MemoryProviderContextItem, MemoryProviderDisclosureConstraint,
    MemoryProviderLimits, MemoryProviderManifest, MemoryProviderPolicy, MemoryProviderPrivacyMode,
    MemoryProviderRequest, MemoryProviderResponse, MemoryProviderSensitivity,
    MemoryProviderTransport, ProviderError, ProviderProtocolVersion, ResolveContextPayload,
    ResolveContextResult,
};
use reqwest::Url;
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAXIMUM_DISCOVERY_BYTES: u64 = 262_144;
const MAXIMUM_OPERATION_BYTES: u64 = 1_500_000;

pub struct HttpMemoryProviderClient {
    client: Client,
    base_url: Url,
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
            base_url: base.clone(),
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
        if !response.status().is_success() {
            return Err(ProviderError::Unavailable);
        }
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

    pub fn resolve_context(
        &self,
        request: &MemoryProviderRequest<ResolveContextPayload>,
    ) -> Result<MemoryProviderResponse<ResolveContextResult>, ProviderError> {
        let endpoint = self
            .base_url
            .join("v1/context/resolve")
            .map_err(|_| ProviderError::Unavailable)?;
        let body = RequestEnvelope {
            request_id: request.request_id().as_str(),
            protocol_version: "0.1",
            operation: "resolve_context",
            payload: ResolveContextBody::from(request.payload()),
        };
        let response = self.post_json(endpoint, &body)?;
        let status = response.status().as_u16();
        let wire: ResponseEnvelope<ResolveContextResultBody> =
            decode_json(response, MAXIMUM_OPERATION_BYTES)?;
        validate_response_identity(request, &wire.request_id, &wire.protocol_version)?;
        match (wire.result, wire.error) {
            (Some(result), None) if (200..300).contains(&status) => {
                Ok(request.success(result.into_domain(request.payload())?))
            }
            (None, Some(error)) if !(200..300).contains(&status) => {
                Ok(request.error(parse_error_code(&error.code)?))
            }
            _ => Err(ProviderError::Rejected(
                "memory provider response status and envelope disagree".to_owned(),
            )),
        }
    }

    fn post_json<Body: Serialize>(
        &self,
        endpoint: Url,
        body: &Body,
    ) -> Result<Response, ProviderError> {
        let encoded = serde_json::to_vec(body).map_err(|_| {
            ProviderError::InvalidConfiguration(
                "memory provider request could not be encoded".to_owned(),
            )
        })?;
        if encoded.len() as u64 > MAXIMUM_OPERATION_BYTES {
            return Err(ProviderError::InvalidConfiguration(
                "memory provider request exceeds the transport limit".to_owned(),
            ));
        }
        self.client
            .post(endpoint)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .bearer_auth(self.bearer_token.as_str())
            .body(encoded)
            .send()
            .map_err(|_| ProviderError::Unavailable)
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RequestEnvelope<'request, Payload> {
    request_id: &'request str,
    protocol_version: &'static str,
    operation: &'static str,
    payload: Payload,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResolveContextBody<'request> {
    purpose: &'request str,
    query: &'request str,
    selector: SelectorBody<'request>,
    maximum_items: usize,
    maximum_bytes: usize,
}

impl<'request> From<&'request ResolveContextPayload> for ResolveContextBody<'request> {
    fn from(payload: &'request ResolveContextPayload) -> Self {
        Self {
            purpose: payload.purpose(),
            query: payload.query(),
            selector: SelectorBody::from(payload.selector().scope()),
            maximum_items: payload.maximum_items(),
            maximum_bytes: payload.maximum_bytes(),
        }
    }
}

#[derive(Serialize)]
#[serde(tag = "scope", rename_all = "lowercase")]
enum SelectorBody<'request> {
    Global,
    Domain { domain: &'request str },
    Entity { entity_id: &'request str },
    Activity { activity_id: &'request str },
}

impl<'request> From<&'request MemoryScope> for SelectorBody<'request> {
    fn from(scope: &'request MemoryScope) -> Self {
        match scope {
            MemoryScope::Global => Self::Global,
            MemoryScope::Domain { name } => Self::Domain { domain: name },
            MemoryScope::Entity { id } => Self::Entity {
                entity_id: id.as_str(),
            },
            MemoryScope::Activity { id } => Self::Activity {
                activity_id: id.as_str(),
            },
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ResponseEnvelope<ResultBody> {
    request_id: String,
    protocol_version: String,
    result: Option<ResultBody>,
    error: Option<ErrorBody>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorBody {
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ResolveContextResultBody {
    context_pack_id: String,
    disclosure_id: String,
    items: Vec<ContextItemBody>,
}

impl ResolveContextResultBody {
    fn into_domain(
        self,
        request: &ResolveContextPayload,
    ) -> Result<ResolveContextResult, ProviderError> {
        let items = self
            .items
            .into_iter()
            .map(ContextItemBody::into_domain)
            .collect::<Result<Vec<_>, _>>()?;
        ResolveContextResult::new(
            ContextPackId::new(self.context_pack_id),
            DisclosureId::new(self.disclosure_id),
            items,
            request,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ContextItemBody {
    memory_id: String,
    version: u64,
    scope: SelectorResultBody,
    kind: String,
    content: String,
    evidence: Vec<EvidenceBody>,
    confidence_millionths: u32,
    valid_from_epoch_seconds: Option<u64>,
    valid_until_epoch_seconds: Option<u64>,
    sensitivity: String,
    disclosure_constraints: Vec<DisclosureConstraintBody>,
}

impl ContextItemBody {
    fn into_domain(self) -> Result<MemoryProviderContextItem, ProviderError> {
        MemoryProviderContextItem::new(
            MemoryId::new(self.memory_id),
            self.version,
            self.scope.into_domain()?,
            parse_memory_kind(&self.kind)?,
            self.content,
            self.evidence
                .into_iter()
                .map(EvidenceBody::into_domain)
                .collect::<Result<Vec<_>, _>>()?,
            self.confidence_millionths,
            self.valid_from_epoch_seconds,
            self.valid_until_epoch_seconds,
            parse_sensitivity(&self.sensitivity)?,
            self.disclosure_constraints
                .into_iter()
                .map(DisclosureConstraintBody::into_domain)
                .collect::<Result<Vec<_>, _>>()?,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SelectorResultBody {
    scope: String,
    domain: Option<String>,
    entity_id: Option<String>,
    activity_id: Option<String>,
}

impl SelectorResultBody {
    fn into_domain(self) -> Result<MemoryScope, ProviderError> {
        match (
            self.scope.as_str(),
            self.domain,
            self.entity_id,
            self.activity_id,
        ) {
            ("global", None, None, None) => Ok(MemoryScope::Global),
            ("domain", Some(name), None, None) => Ok(MemoryScope::Domain { name }),
            ("entity", None, Some(id), None) => Ok(MemoryScope::Entity {
                id: EntityId::new(id),
            }),
            ("activity", None, None, Some(id)) => Ok(MemoryScope::Activity {
                id: ActivityId::new(id),
            }),
            _ => Err(invalid_operation_response()),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EvidenceBody {
    evidence_id: String,
    source: String,
}

impl EvidenceBody {
    fn into_domain(self) -> Result<EvidenceReference, ProviderError> {
        let source = match self.source.as_str() {
            "user_statement" => EvidenceSource::UserStatement,
            "agent_observation" => EvidenceSource::AgentObservation,
            "tool_result" => EvidenceSource::ToolResult,
            "imported_record" => EvidenceSource::ImportedRecord,
            "workspace_decision" => EvidenceSource::WorkspaceDecision,
            _ => return Err(invalid_operation_response()),
        };
        Ok(EvidenceReference::new(
            EvidenceId::new(self.evidence_id),
            source,
        ))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DisclosureConstraintBody {
    r#type: String,
    expires_at_epoch_seconds: Option<u64>,
}

impl DisclosureConstraintBody {
    fn into_domain(self) -> Result<MemoryProviderDisclosureConstraint, ProviderError> {
        match (self.r#type.as_str(), self.expires_at_epoch_seconds) {
            ("purpose_bound", None) => Ok(MemoryProviderDisclosureConstraint::PurposeBound),
            ("no_training", None) => Ok(MemoryProviderDisclosureConstraint::NoTraining),
            ("no_retention", None) => Ok(MemoryProviderDisclosureConstraint::NoRetention),
            ("expires_at", Some(value)) if value > 0 => {
                Ok(MemoryProviderDisclosureConstraint::ExpiresAt(value))
            }
            _ => Err(invalid_operation_response()),
        }
    }
}

fn validate_response_identity(
    request: &MemoryProviderRequest<impl rembrane_provider_sdk::MemoryProviderPayload>,
    response_request_id: &str,
    response_protocol: &str,
) -> Result<(), ProviderError> {
    if response_request_id != request.request_id().as_str() || response_protocol != "0.1" {
        return Err(ProviderError::Rejected(
            "memory provider response correlation mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn parse_memory_kind(value: &str) -> Result<MemoryKind, ProviderError> {
    match value {
        "preference" => Ok(MemoryKind::Preference),
        "semantic" => Ok(MemoryKind::Semantic),
        "episodic" => Ok(MemoryKind::Episodic),
        "procedural" => Ok(MemoryKind::Procedural),
        "observation" => Ok(MemoryKind::Observation),
        "working" => Ok(MemoryKind::Working),
        _ => Err(invalid_operation_response()),
    }
}

fn parse_sensitivity(value: &str) -> Result<MemoryProviderSensitivity, ProviderError> {
    match value {
        "personal" => Ok(MemoryProviderSensitivity::Personal),
        "sensitive" => Ok(MemoryProviderSensitivity::Sensitive),
        "restricted" => Ok(MemoryProviderSensitivity::Restricted),
        _ => Err(invalid_operation_response()),
    }
}

fn parse_error_code(
    value: &str,
) -> Result<rembrane_provider_sdk::MemoryProviderErrorCode, ProviderError> {
    use rembrane_provider_sdk::MemoryProviderErrorCode as Code;
    match value {
        "invalid_request" => Ok(Code::InvalidRequest),
        "access_denied" => Ok(Code::AccessDenied),
        "not_found" => Ok(Code::NotFound),
        "conflict" => Ok(Code::Conflict),
        "rate_limited" => Ok(Code::RateLimited),
        "unsupported" => Ok(Code::Unsupported),
        "unavailable" => Ok(Code::Unavailable),
        _ => Err(invalid_operation_response()),
    }
}

fn invalid_operation_response() -> ProviderError {
    ProviderError::Rejected("memory provider returned an invalid operation response".to_owned())
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
    use rembrane_domain::{EntityId, MemoryScope};
    use rembrane_provider_sdk::{
        CURRENT_MEMORY_PROVIDER_PROTOCOL, MemoryProviderCapability, MemoryProviderConnection,
        MemoryProviderContextSelector, MemoryProviderLimits, MemoryProviderManifest,
        MemoryProviderPolicy, MemoryProviderPrivacyMode, MemoryProviderTransport,
        ResolveContextPayload,
    };

    use super::{
        DiscoveryBody, RequestEnvelope, ResolveContextBody, ResolveContextResultBody,
        validate_base_url, validate_bearer_token,
    };

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

    #[test]
    fn serializes_context_requests_without_connection_identity() {
        let limits = MemoryProviderLimits {
            maximum_context_items: 100,
            maximum_context_bytes: 1_048_576,
            maximum_event_batch_items: 100,
            maximum_sync_batch_items: 100,
        };
        let payload = ResolveContextPayload::new(
            "continue project",
            "current implementation",
            MemoryProviderContextSelector::entity(EntityId::new("project_rembrane"))
                .expect("selector"),
            20,
            65_536,
            limits,
        )
        .expect("payload");
        let manifest = MemoryProviderManifest::new(
            "rembrane.memory.test".to_owned(),
            "test".to_owned(),
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            vec![MemoryProviderTransport::Https],
            vec![MemoryProviderCapability::ResolveContext],
            MemoryProviderPrivacyMode::EndToEndEncrypted,
            vec!["personal".to_owned()],
            limits,
        )
        .expect("manifest");
        let policy = MemoryProviderPolicy::new(
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            MemoryProviderTransport::Https,
            vec![MemoryProviderCapability::ResolveContext],
            vec![MemoryProviderPrivacyMode::EndToEndEncrypted],
            MemoryProviderLimits {
                maximum_context_items: 1,
                maximum_context_bytes: 1,
                maximum_event_batch_items: 1,
                maximum_sync_batch_items: 1,
            },
        )
        .expect("policy");
        let connection =
            MemoryProviderConnection::connect(manifest, &policy, "context-test").expect("connect");
        let request = connection.request(payload).expect("request");
        let encoded = serde_json::to_value(RequestEnvelope {
            request_id: request.request_id().as_str(),
            protocol_version: "0.1",
            operation: "resolve_context",
            payload: ResolveContextBody::from(request.payload()),
        })
        .expect("request JSON");
        assert_eq!(encoded["payload"]["selector"]["scope"], "entity");
        assert_eq!(
            encoded["payload"]["selector"]["entityId"],
            "project_rembrane"
        );
        assert!(encoded["payload"].get("workspaceId").is_none());
        assert!(encoded["payload"].get("subjectId").is_none());
    }

    #[test]
    fn reconstructs_and_bounds_context_results() {
        let limits = MemoryProviderLimits {
            maximum_context_items: 10,
            maximum_context_bytes: 1_024,
            maximum_event_batch_items: 1,
            maximum_sync_batch_items: 1,
        };
        let request = ResolveContextPayload::new(
            "personalize",
            "what should I call the user",
            MemoryProviderContextSelector::global(),
            2,
            100,
            limits,
        )
        .expect("request");
        let wire: ResolveContextResultBody = serde_json::from_str(
            r#"{
              "contextPackId":"context_pack_01",
              "disclosureId":"disclosure_01",
              "items":[{
                "memoryId":"memory_01",
                "version":1,
                "scope":{"scope":"global"},
                "kind":"preference",
                "content":"Call the user Hippo.",
                "evidence":[{
                  "evidenceId":"evidence_01",
                  "source":"user_statement"
                }],
                "confidenceMillionths":1000000,
                "validFromEpochSeconds":1,
                "validUntilEpochSeconds":null,
                "sensitivity":"personal",
                "disclosureConstraints":[{"type":"purpose_bound"}]
              }]
            }"#,
        )
        .expect("result JSON");
        let result = wire.into_domain(&request).expect("canonical result");
        assert_eq!(result.items().len(), 1);
        assert_eq!(result.items()[0].scope(), &MemoryScope::Global);
        assert_eq!(result.items()[0].content(), "Call the user Hippo.");
    }
}

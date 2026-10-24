//! Authenticated and bounded HTTP transport for a Rembrane-owned Graphiti
//! sidecar. This protocol boundary is intentionally narrower than Graphiti's
//! native API so callers cannot select provider namespaces or authorization.

use std::io::Read;
use std::time::Duration;

use rembrane_domain::KnowledgeEdgeId;
use rembrane_graph_graphiti::{
    GraphitiEdge, GraphitiEdgeDeletion, GraphitiNeighbourLookup, GraphitiNode,
    GraphitiNodeDeletion, GraphitiTransport,
};
use rembrane_provider_sdk::{
    CURRENT_PROVIDER_PROTOCOL, CandidateKnowledgeEdge, Capability, GraphDirection,
    GraphitiErrorCode, GraphitiRequest, GraphitiRequestId, GraphitiResponse,
    MAX_GRAPHITI_REQUEST_BYTES, MAX_GRAPHITI_RESPONSE_BYTES, ProviderError, ProviderLimits,
    ProviderManifest, ProviderProtocolVersion,
};
use reqwest::Url;
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub struct HttpGraphitiTransport {
    client: Client,
    manifest_endpoint: Url,
    node_upsert_endpoint: Url,
    edge_upsert_endpoint: Url,
    neighbours_endpoint: Url,
    node_delete_endpoint: Url,
    edge_delete_endpoint: Url,
    bearer_token: Zeroizing<String>,
}

impl HttpGraphitiTransport {
    pub fn new(base_url: &str, bearer_token: String) -> Result<Self, ProviderError> {
        Self::new_with_secret(base_url, Zeroizing::new(bearer_token))
    }

    /// Builds a transport from an already resolved zeroizing credential.
    ///
    /// # Errors
    ///
    /// Returns a provider error when the endpoint or credential is invalid or
    /// the bounded HTTP client cannot be constructed.
    pub fn new_with_secret(
        base_url: &str,
        bearer_token: Zeroizing<String>,
    ) -> Result<Self, ProviderError> {
        let base = validate_base_url(base_url)?;
        validate_bearer_token(&bearer_token)?;
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| ProviderError::Unavailable)?;
        let endpoint = |path: &str| base.join(path).map_err(|_| ProviderError::Unavailable);
        Ok(Self {
            client,
            manifest_endpoint: endpoint("v0.1/manifest")?,
            node_upsert_endpoint: endpoint("v0.1/nodes:upsert")?,
            edge_upsert_endpoint: endpoint("v0.1/edges:upsert")?,
            neighbours_endpoint: endpoint("v0.1/neighbours:query")?,
            node_delete_endpoint: endpoint("v0.1/nodes:delete")?,
            edge_delete_endpoint: endpoint("v0.1/edges:delete")?,
            bearer_token,
        })
    }

    fn get(&self, endpoint: Url) -> Result<Response, ProviderError> {
        self.client
            .get(endpoint)
            .header(ACCEPT, "application/json")
            .bearer_auth(self.bearer_token.as_str())
            .send()
            .map_err(|_| ProviderError::Unavailable)
    }

    fn post<Body: Serialize>(&self, endpoint: Url, body: &Body) -> Result<Response, ProviderError> {
        let encoded = serde_json::to_vec(body).map_err(|_| {
            ProviderError::InvalidConfiguration("Graphiti request could not be encoded".to_owned())
        })?;
        if encoded.len() > MAX_GRAPHITI_REQUEST_BYTES {
            return Err(ProviderError::InvalidConfiguration(
                "Graphiti request exceeds the transport limit".to_owned(),
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

    fn decode<ResponseBody: for<'de> Deserialize<'de>>(
        response: Response,
    ) -> Result<ResponseBody, ProviderError> {
        let status = response.status();
        if !status.is_success() {
            return Err(if matches!(status.as_u16(), 400 | 409 | 413 | 422) {
                ProviderError::Rejected("Graphiti sidecar rejected request".to_owned())
            } else {
                ProviderError::Unavailable
            });
        }
        let json = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("application/json"))
            });
        if !json
            || response
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<usize>().ok())
                .is_some_and(|length| length > MAX_GRAPHITI_RESPONSE_BYTES)
        {
            return Err(ProviderError::Rejected(
                "Graphiti sidecar returned an invalid response".to_owned(),
            ));
        }
        let mut bytes = Vec::new();
        response
            .take((MAX_GRAPHITI_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ProviderError::Unavailable)?;
        if bytes.len() > MAX_GRAPHITI_RESPONSE_BYTES {
            return Err(ProviderError::Rejected(
                "Graphiti sidecar response exceeds the transport limit".to_owned(),
            ));
        }
        serde_json::from_slice(&bytes).map_err(|_| {
            ProviderError::Rejected("Graphiti sidecar returned malformed JSON".to_owned())
        })
    }

    fn decode_ack(
        request: &GraphitiRequest<impl rembrane_provider_sdk::GraphitiPayload<Result = ()>>,
        response: Response,
    ) -> Result<GraphitiResponse<()>, ProviderError> {
        let wire: WireResponse<Acknowledgement> = Self::decode(response)?;
        wire.into_response(request, |acknowledgement| {
            acknowledgement.accepted.then_some(()).ok_or_else(|| {
                ProviderError::Rejected("Graphiti sidecar did not acknowledge mutation".to_owned())
            })
        })
    }
}

impl GraphitiTransport for HttpGraphitiTransport {
    fn discover(&self) -> Result<ProviderManifest, ProviderError> {
        let wire: ManifestBody = Self::decode(self.get(self.manifest_endpoint.clone())?)?;
        wire.try_into()
    }

    fn upsert_node(
        &self,
        request: &GraphitiRequest<GraphitiNode>,
    ) -> Result<GraphitiResponse<()>, ProviderError> {
        let response = self.post(
            self.node_upsert_endpoint.clone(),
            &Envelope::new(request, NodeBody::from(request.payload())),
        )?;
        Self::decode_ack(request, response)
    }

    fn upsert_edge(
        &self,
        request: &GraphitiRequest<GraphitiEdge>,
    ) -> Result<GraphitiResponse<()>, ProviderError> {
        let response = self.post(
            self.edge_upsert_endpoint.clone(),
            &Envelope::new(request, EdgeBody::from(request.payload())),
        )?;
        Self::decode_ack(request, response)
    }

    fn neighbours(
        &self,
        request: &GraphitiRequest<GraphitiNeighbourLookup>,
    ) -> Result<GraphitiResponse<Vec<CandidateKnowledgeEdge>>, ProviderError> {
        let response = self.post(
            self.neighbours_endpoint.clone(),
            &Envelope::new(request, NeighbourBody::from(request.payload())),
        )?;
        let wire: WireResponse<NeighbourResult> = Self::decode(response)?;
        wire.into_response(request, |result| {
            result
                .candidates
                .into_iter()
                .map(|candidate| {
                    if candidate.edge_id.is_empty() || candidate.version == 0 {
                        return Err(ProviderError::Rejected(
                            "Graphiti sidecar returned an invalid candidate".to_owned(),
                        ));
                    }
                    Ok(CandidateKnowledgeEdge {
                        edge_id: KnowledgeEdgeId::new(candidate.edge_id),
                        version: candidate.version,
                    })
                })
                .collect()
        })
    }

    fn delete_node(
        &self,
        request: &GraphitiRequest<GraphitiNodeDeletion>,
    ) -> Result<GraphitiResponse<()>, ProviderError> {
        let response = self.post(
            self.node_delete_endpoint.clone(),
            &Envelope::new(request, NodeDeletionBody::from(request.payload())),
        )?;
        Self::decode_ack(request, response)
    }

    fn delete_edge(
        &self,
        request: &GraphitiRequest<GraphitiEdgeDeletion>,
    ) -> Result<GraphitiResponse<()>, ProviderError> {
        let response = self.post(
            self.edge_delete_endpoint.clone(),
            &Envelope::new(request, EdgeDeletionBody::from(request.payload())),
        )?;
        Self::decode_ack(request, response)
    }
}

fn validate_base_url(value: &str) -> Result<Url, ProviderError> {
    let mut url = Url::parse(value).map_err(|_| {
        ProviderError::InvalidConfiguration("Graphiti base URL is invalid".to_owned())
    })?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(ProviderError::InvalidConfiguration(
            "Graphiti base URL must be an origin without credentials".to_owned(),
        ));
    }
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "::1"));
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(ProviderError::InvalidConfiguration(
            "Graphiti transport requires HTTPS outside exact loopback hosts".to_owned(),
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
            "Graphiti bearer token is empty or header-unsafe".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Envelope<'request, Payload> {
    request_id: &'request str,
    protocol_version: &'static str,
    operation: &'static str,
    namespace: &'request str,
    idempotency_key: Option<&'request str>,
    payload: Payload,
}

impl<'request, Payload> Envelope<'request, Payload> {
    fn new<Canonical>(request: &'request GraphitiRequest<Canonical>, payload: Payload) -> Self
    where
        Canonical: rembrane_provider_sdk::GraphitiPayload,
    {
        Self {
            request_id: request.request_id().as_str(),
            protocol_version: "0.1",
            operation: operation_name(request.operation()),
            namespace: request.namespace().as_str(),
            idempotency_key: request
                .idempotency_key()
                .map(rembrane_provider_sdk::GraphitiIdempotencyKey::as_str),
            payload,
        }
    }
}

const fn operation_name(operation: rembrane_provider_sdk::GraphitiOperation) -> &'static str {
    use rembrane_provider_sdk::GraphitiOperation;
    match operation {
        GraphitiOperation::UpsertNode => "upsertNode",
        GraphitiOperation::UpsertEdge => "upsertEdge",
        GraphitiOperation::Neighbours => "neighbours",
        GraphitiOperation::DeleteNode => "deleteNode",
        GraphitiOperation::DeleteEdge => "deleteEdge",
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeBody<'value> {
    node_id: &'value str,
    kind: &'static str,
    label: &'value str,
    aliases: &'value [String],
    valid_from_epoch_seconds: u64,
    valid_until_epoch_seconds: Option<u64>,
    recorded_at_epoch_seconds: u64,
    version: u64,
}

impl<'value> From<&'value GraphitiNode> for NodeBody<'value> {
    fn from(node: &'value GraphitiNode) -> Self {
        Self {
            node_id: &node.node_id,
            kind: node.kind,
            label: &node.label,
            aliases: &node.aliases,
            valid_from_epoch_seconds: node.valid_from_epoch_seconds,
            valid_until_epoch_seconds: node.valid_until_epoch_seconds,
            recorded_at_epoch_seconds: node.recorded_at_epoch_seconds,
            version: node.version,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EdgeBody<'value> {
    edge_id: &'value str,
    source_id: &'value str,
    target_id: &'value str,
    relation: &'value str,
    valid_from_epoch_seconds: u64,
    valid_until_epoch_seconds: Option<u64>,
    recorded_at_epoch_seconds: u64,
    version: u64,
    supersedes_edge_id: Option<&'value str>,
}

impl<'value> From<&'value GraphitiEdge> for EdgeBody<'value> {
    fn from(edge: &'value GraphitiEdge) -> Self {
        Self {
            edge_id: &edge.edge_id,
            source_id: &edge.source_id,
            target_id: &edge.target_id,
            relation: &edge.relation,
            valid_from_epoch_seconds: edge.valid_from_epoch_seconds,
            valid_until_epoch_seconds: edge.valid_until_epoch_seconds,
            recorded_at_epoch_seconds: edge.recorded_at_epoch_seconds,
            version: edge.version,
            supersedes_edge_id: edge.supersedes_edge_id.as_deref(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NeighbourBody<'value> {
    node_id: &'value str,
    direction: &'static str,
    valid_at_epoch_seconds: u64,
    maximum_candidates: usize,
}

impl<'value> From<&'value GraphitiNeighbourLookup> for NeighbourBody<'value> {
    fn from(query: &'value GraphitiNeighbourLookup) -> Self {
        Self {
            node_id: &query.node_id,
            direction: match query.direction {
                GraphDirection::Incoming => "incoming",
                GraphDirection::Outgoing => "outgoing",
                GraphDirection::Both => "both",
            },
            valid_at_epoch_seconds: query.valid_at_epoch_seconds,
            maximum_candidates: query.maximum_candidates,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeDeletionBody<'value> {
    node_id: &'value str,
    through_version: u64,
}

impl<'value> From<&'value GraphitiNodeDeletion> for NodeDeletionBody<'value> {
    fn from(deletion: &'value GraphitiNodeDeletion) -> Self {
        Self {
            node_id: &deletion.node_id,
            through_version: deletion.through_version,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EdgeDeletionBody<'value> {
    edge_id: &'value str,
    through_version: u64,
}

impl<'value> From<&'value GraphitiEdgeDeletion> for EdgeDeletionBody<'value> {
    fn from(deletion: &'value GraphitiEdgeDeletion) -> Self {
        Self {
            edge_id: &deletion.edge_id,
            through_version: deletion.through_version,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ManifestBody {
    provider_id: String,
    provider_version: String,
    protocol_version: String,
    capabilities: Vec<String>,
    plaintext_processing: bool,
    limits: ManifestLimits,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ManifestLimits {
    #[serde(rename = "maximumBatchItems")]
    batch_items: usize,
    #[serde(rename = "maximumContentBytes")]
    content_bytes: usize,
    #[serde(rename = "maximumCandidates")]
    candidates: usize,
}

impl TryFrom<ManifestBody> for ProviderManifest {
    type Error = ProviderError;

    fn try_from(wire: ManifestBody) -> Result<Self, Self::Error> {
        if wire.protocol_version != "0.1" {
            return Err(ProviderError::IncompatibleProtocol {
                required_major: CURRENT_PROVIDER_PROTOCOL.major,
                required_minor: CURRENT_PROVIDER_PROTOCOL.minor,
                offered_major: 0,
                offered_minor: 0,
            });
        }
        let capabilities = wire
            .capabilities
            .into_iter()
            .map(|capability| match capability.as_str() {
                "graphUpsert" => Ok(Capability::GraphUpsert),
                "graphTraverse" => Ok(Capability::GraphTraverse),
                "delete" => Ok(Capability::Delete),
                "workspaceFilter" => Ok(Capability::WorkspaceFilter),
                "versionedRecords" => Ok(Capability::VersionedRecords),
                "healthCheck" => Ok(Capability::HealthCheck),
                _ => Err(ProviderError::InvalidConfiguration(
                    "Graphiti manifest declares an unknown capability".to_owned(),
                )),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let manifest = Self {
            id: wire.provider_id,
            version: wire.provider_version,
            protocol_version: CURRENT_PROVIDER_PROTOCOL,
            capabilities,
            plaintext_processing: wire.plaintext_processing,
            limits: ProviderLimits {
                maximum_batch_items: wire.limits.batch_items,
                maximum_content_bytes: wire.limits.content_bytes,
                maximum_candidates: wire.limits.candidates,
            },
        };
        manifest.validate_structure()?;
        Ok(manifest)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireResponse<Payload> {
    request_id: String,
    protocol_version: String,
    result: Option<Payload>,
    error: Option<String>,
}

impl<Payload> WireResponse<Payload> {
    fn into_response<Canonical, ResultPayload>(
        self,
        request: &GraphitiRequest<Canonical>,
        convert: impl FnOnce(Payload) -> Result<ResultPayload, ProviderError>,
    ) -> Result<GraphitiResponse<ResultPayload>, ProviderError>
    where
        Canonical: rembrane_provider_sdk::GraphitiPayload<Result = ResultPayload>,
    {
        let request_id = GraphitiRequestId::new(self.request_id)?;
        let protocol_version = parse_protocol(&self.protocol_version)?;
        let result = match (self.result, self.error) {
            (Some(payload), None) => Ok(convert(payload)?),
            (None, Some(code)) => Err(parse_error(&code)?),
            _ => {
                return Err(ProviderError::Rejected(
                    "Graphiti response must contain exactly one result or error".to_owned(),
                ));
            }
        };
        let response = GraphitiResponse::from_parts(request_id, protocol_version, result);
        request.validate_response(&response)?;
        Ok(response)
    }
}

fn parse_protocol(value: &str) -> Result<ProviderProtocolVersion, ProviderError> {
    if value == "0.1" {
        Ok(CURRENT_PROVIDER_PROTOCOL)
    } else {
        Err(ProviderError::Rejected(
            "Graphiti response protocol is incompatible".to_owned(),
        ))
    }
}

fn parse_error(value: &str) -> Result<GraphitiErrorCode, ProviderError> {
    match value {
        "invalidRequest" => Ok(GraphitiErrorCode::InvalidRequest),
        "conflict" => Ok(GraphitiErrorCode::Conflict),
        "unavailable" => Ok(GraphitiErrorCode::Unavailable),
        "internal" => Ok(GraphitiErrorCode::Internal),
        _ => Err(ProviderError::Rejected(
            "Graphiti response contains an unknown error code".to_owned(),
        )),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Acknowledgement {
    accepted: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct NeighbourResult {
    candidates: Vec<WireCandidate>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireCandidate {
    edge_id: String,
    version: u64,
}

#[cfg(test)]
mod tests {
    use rembrane_provider_sdk::{GraphitiConnection, GraphitiIdempotencyKey};

    use super::{
        Acknowledgement, Envelope, GraphitiNodeDeletion, ManifestBody, ProviderManifest,
        WireResponse, validate_base_url, validate_bearer_token,
    };

    #[test]
    fn accepts_https_and_exact_loopback_origins_only() {
        for valid in ["https://graph.example.test", "http://127.0.0.1:8793"] {
            assert!(validate_base_url(valid).is_ok());
        }
        for invalid in [
            "http://graph.example.test",
            "http://localhost:8793",
            "https://user:secret@graph.example.test",
            "https://graph.example.test/provider",
            "https://graph.example.test?token=secret",
            "https://graph.example.test#fragment",
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
    fn rejects_unknown_manifest_capabilities() {
        let wire: ManifestBody = serde_json::from_str(
            r#"{
                "providerId":"rembrane.graph.graphiti",
                "providerVersion":"1.0",
                "protocolVersion":"0.1",
                "capabilities":["graphUpsert","execShell"],
                "plaintextProcessing":true,
                "limits":{
                    "maximumBatchItems":1,
                    "maximumContentBytes":262144,
                    "maximumCandidates":100
                }
            }"#,
        )
        .expect("manifest JSON");
        assert!(ProviderManifest::try_from(wire).is_err());
    }

    #[test]
    fn wire_response_must_correlate_to_the_originating_request() {
        let connection = GraphitiConnection::new("graphiti-http-test").expect("connection");
        let request = connection
            .request(
                &rembrane_domain::WorkspaceId::new("workspace"),
                Some(GraphitiIdempotencyKey::new("rembrane.delete.node.1").expect("key")),
                GraphitiNodeDeletion {
                    node_id: "node".to_owned(),
                    through_version: 1,
                },
            )
            .expect("request");
        let wire = WireResponse {
            request_id: "another_request_00000001".to_owned(),
            protocol_version: "0.1".to_owned(),
            result: Some(Acknowledgement { accepted: true }),
            error: None,
        };
        assert!(
            wire.into_response(&request, |ack| {
                ack.accepted
                    .then_some(())
                    .ok_or(rembrane_provider_sdk::ProviderError::Unavailable)
            })
            .is_err()
        );
        let envelope = Envelope::new(&request, super::NodeDeletionBody::from(request.payload()));
        assert_eq!(envelope.namespace, request.namespace().as_str());
    }
}

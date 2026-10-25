//! Authenticated bounded HTTP client for Memory Provider Protocol discovery.

use std::io::Read;
use std::time::Duration;

use rembrane_domain::{
    ActivityId, CheckpointId, ContextPackId, DisclosureId, EntityId, EventId, EvidenceId,
    EvidenceReference, EvidenceSource, MemoryId, MemoryKind, MemoryScope,
};
use rembrane_provider_sdk::{
    CURRENT_MEMORY_PROVIDER_PROTOCOL, CheckpointActivityPayload, CheckpointActivityResult,
    DeleteMemoryPayload, DeleteMemoryResult, ExplainMemoryPayload, ExplainMemoryResult,
    MEMORY_PROVIDER_DISCOVERY_PATH, MemoryProviderAcceptedMutation, MemoryProviderCapability,
    MemoryProviderClient, MemoryProviderConnection, MemoryProviderContextItem,
    MemoryProviderDisclosedMemory, MemoryProviderDisclosureConstraint, MemoryProviderEvent,
    MemoryProviderLimits, MemoryProviderManifest, MemoryProviderPolicy, MemoryProviderPrivacyMode,
    MemoryProviderPulledChange, MemoryProviderPushMutation, MemoryProviderRecordedEvent,
    MemoryProviderRequest, MemoryProviderResponse, MemoryProviderSensitivity,
    MemoryProviderSyncCursor, MemoryProviderSyncOperation, MemoryProviderSyncResource,
    MemoryProviderTransport, ProposeMemoryPayload, ProposeMemoryResult, ProviderError,
    ProviderProtocolVersion, RecordDisclosurePayload, RecordDisclosureResult, RecordEventPayload,
    RecordEventResult, ResolveContextPayload, ResolveContextResult, ResolveQuestionPayload,
    ResolveQuestionResult, SyncPullPayload, SyncPullResult, SyncPushPayload, SyncPushResult,
};
use reqwest::blocking::{Client, Request, Response};
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap};
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAXIMUM_DISCOVERY_BYTES: u64 = 262_144;
const MAXIMUM_OPERATION_BYTES: u64 = 1_500_000;
const MAXIMUM_DISCOVERY_TRANSPORTS: usize = 2;
const MAXIMUM_DISCOVERY_CAPABILITIES: usize = 10;
const REQUEST_ID_HEADER: &str = "x-rembrane-request-id";
const PROTOCOL_VERSION_HEADER: &str = "x-rembrane-protocol-version";

pub struct HttpMemoryProviderClient {
    client: Client,
    base_url: Url,
    discovery_endpoint: Url,
    bearer_token: Zeroizing<String>,
}

impl HttpMemoryProviderClient {
    pub fn new(base_url: &str, bearer_token: String) -> Result<Self, ProviderError> {
        Self::new_with_secret(base_url, Zeroizing::new(bearer_token))
    }

    /// Builds a client from an already resolved zeroizing credential.
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
        validate_bearer_token(bearer_token.as_str())?;
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
            bearer_token,
        })
    }

    pub fn discover(&self) -> Result<MemoryProviderManifest, ProviderError> {
        let response = self
            .client
            .get(self.discovery_endpoint.clone())
            .header(ACCEPT, "application/json")
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
        let body = ResolveContextBody::from(request.payload());
        let response = self.post_json(endpoint, &body, request.request_id().as_str())?;
        match decode_operation_response::<ResolveContextResultBody, _>(response, request)? {
            Ok(result) => Ok(request.success(result.into_domain(request.payload())?)),
            Err(error) => Ok(request.error(error)),
        }
    }

    pub fn resolve_question(
        &self,
        request: &MemoryProviderRequest<ResolveQuestionPayload>,
    ) -> Result<MemoryProviderResponse<ResolveQuestionResult>, ProviderError> {
        let endpoint = self
            .base_url
            .join("v1/questions/resolve")
            .map_err(|_| ProviderError::Unavailable)?;
        let body = ResolveQuestionBody::from(request.payload());
        let response = self.post_json(endpoint, &body, request.request_id().as_str())?;
        match decode_operation_response::<ResolveQuestionResultBody, _>(response, request)? {
            Ok(result) => Ok(request.success(result.into_domain(request.payload())?)),
            Err(error) => Ok(request.error(error)),
        }
    }

    pub fn propose_memory(
        &self,
        request: &MemoryProviderRequest<ProposeMemoryPayload>,
    ) -> Result<MemoryProviderResponse<ProposeMemoryResult>, ProviderError> {
        let endpoint = self
            .base_url
            .join("v1/memory/proposals")
            .map_err(|_| ProviderError::Unavailable)?;
        let body = ProposeMemoryBody::from(request.payload());
        let response = self.post_json(endpoint, &body, request.request_id().as_str())?;
        match decode_operation_response::<ProposeMemoryResultBody, _>(response, request)? {
            Ok(result) => Ok(request.success(ProposeMemoryResult::new(
                MemoryId::new(result.memory_id),
                result.version,
            )?)),
            Err(error) => Ok(request.error(error)),
        }
    }

    pub fn record_events(
        &self,
        request: &MemoryProviderRequest<RecordEventPayload>,
    ) -> Result<MemoryProviderResponse<RecordEventResult>, ProviderError> {
        let endpoint = self
            .base_url
            .join("v1/events")
            .map_err(|_| ProviderError::Unavailable)?;
        let body = RecordEventBody::from(request.payload());
        let response = self.post_json(endpoint, &body, request.request_id().as_str())?;
        match decode_operation_response::<RecordEventResultBody, _>(response, request)? {
            Ok(result) => Ok(request.success(result.into_domain(request.payload())?)),
            Err(error) => Ok(request.error(error)),
        }
    }

    pub fn checkpoint_activity(
        &self,
        request: &MemoryProviderRequest<CheckpointActivityPayload>,
    ) -> Result<MemoryProviderResponse<CheckpointActivityResult>, ProviderError> {
        let endpoint = activity_subresource_endpoint(
            &self.base_url,
            request.payload().activity_id().as_str(),
            "checkpoint",
        )?;
        let body = CheckpointActivityBody::from(request.payload());
        let response = self.post_json(endpoint, &body, request.request_id().as_str())?;
        match decode_operation_response::<CheckpointActivityResultBody, _>(response, request)? {
            Ok(result) => Ok(request.success(result.into_domain(request.payload())?)),
            Err(error) => Ok(request.error(error)),
        }
    }

    pub fn record_disclosure(
        &self,
        request: &MemoryProviderRequest<RecordDisclosurePayload>,
    ) -> Result<MemoryProviderResponse<RecordDisclosureResult>, ProviderError> {
        let endpoint = self
            .base_url
            .join("v1/disclosures/receipt")
            .map_err(|_| ProviderError::Unavailable)?;
        let body = RecordDisclosureBody::from(request.payload());
        let response = self.post_json(endpoint, &body, request.request_id().as_str())?;
        match decode_operation_response::<RecordDisclosureResultBody, _>(response, request)? {
            Ok(result) => Ok(
                request.success(RecordDisclosureResult::new(DisclosureId::new(
                    result.disclosure_id,
                ))?),
            ),
            Err(error) => Ok(request.error(error)),
        }
    }

    pub fn sync_pull(
        &self,
        request: &MemoryProviderRequest<SyncPullPayload>,
    ) -> Result<MemoryProviderResponse<SyncPullResult>, ProviderError> {
        let endpoint = sync_pull_endpoint(&self.base_url, request.payload())?;
        let response = self.get(endpoint, request.request_id().as_str())?;
        match decode_operation_response::<SyncPullResultBody, _>(response, request)? {
            Ok(result) => Ok(request.success(result.into_domain(request.payload())?)),
            Err(error) => Ok(request.error(error)),
        }
    }

    pub fn sync_push(
        &self,
        request: &MemoryProviderRequest<SyncPushPayload>,
    ) -> Result<MemoryProviderResponse<SyncPushResult>, ProviderError> {
        let endpoint = self
            .base_url
            .join("v1/sync/push")
            .map_err(|_| ProviderError::Unavailable)?;
        let body = SyncPushBody::from(request.payload());
        let response = self.post_json(endpoint, &body, request.request_id().as_str())?;
        match decode_operation_response::<SyncPushResultBody, _>(response, request)? {
            Ok(result) => Ok(request.success(result.into_domain(request.payload())?)),
            Err(error) => Ok(request.error(error)),
        }
    }

    pub fn delete_memory(
        &self,
        request: &MemoryProviderRequest<DeleteMemoryPayload>,
    ) -> Result<MemoryProviderResponse<DeleteMemoryResult>, ProviderError> {
        let endpoint = memory_endpoint(&self.base_url, request.payload().memory_id().as_str())?;
        let body = DeleteMemoryBody::from(request.payload());
        let response = self.delete_json(endpoint, &body, request.request_id().as_str())?;
        match decode_operation_response::<DeleteMemoryResultBody, _>(response, request)? {
            Ok(result) => {
                if result.memory_id != request.payload().memory_id().as_str() {
                    return Err(ProviderError::Rejected(
                        "memory provider deletion returned another memory id".to_owned(),
                    ));
                }
                Ok(request.success(DeleteMemoryResult::new(
                    MemoryId::new(result.memory_id),
                    result.deleted_version,
                    result.tombstone_version,
                )?))
            }
            Err(error) => Ok(request.error(error)),
        }
    }

    pub fn explain_memory(
        &self,
        request: &MemoryProviderRequest<ExplainMemoryPayload>,
    ) -> Result<MemoryProviderResponse<ExplainMemoryResult>, ProviderError> {
        let endpoint = explain_memory_endpoint(&self.base_url, request.payload())?;
        let response = self.get(endpoint, request.request_id().as_str())?;
        match decode_operation_response::<ExplainMemoryResultBody, _>(response, request)? {
            Ok(result) => Ok(request.success(result.into_domain(request.payload())?)),
            Err(error) => Ok(request.error(error)),
        }
    }

    fn get(&self, endpoint: Url, request_id: &str) -> Result<Response, ProviderError> {
        let request = self.build_get_request(endpoint, request_id)?;
        self.client
            .execute(request)
            .map_err(|_| ProviderError::Unavailable)
    }

    fn build_get_request(&self, endpoint: Url, request_id: &str) -> Result<Request, ProviderError> {
        self.client
            .get(endpoint)
            .header(ACCEPT, "application/json")
            .header(REQUEST_ID_HEADER, request_id)
            .header(PROTOCOL_VERSION_HEADER, "0.1")
            .bearer_auth(self.bearer_token.as_str())
            .build()
            .map_err(|_| ProviderError::Unavailable)
    }

    fn post_json<Body: Serialize>(
        &self,
        endpoint: Url,
        body: &Body,
        request_id: &str,
    ) -> Result<Response, ProviderError> {
        let request = self.build_json_request(Method::POST, endpoint, body, request_id)?;
        self.client
            .execute(request)
            .map_err(|_| ProviderError::Unavailable)
    }

    fn delete_json<Body: Serialize>(
        &self,
        endpoint: Url,
        body: &Body,
        request_id: &str,
    ) -> Result<Response, ProviderError> {
        let request = self.build_json_request(Method::DELETE, endpoint, body, request_id)?;
        self.client
            .execute(request)
            .map_err(|_| ProviderError::Unavailable)
    }

    fn build_json_request<Body: Serialize>(
        &self,
        method: Method,
        endpoint: Url,
        body: &Body,
        request_id: &str,
    ) -> Result<Request, ProviderError> {
        let encoded = encode_operation_body(body)?;
        self.client
            .request(method, endpoint)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header(REQUEST_ID_HEADER, request_id)
            .header(PROTOCOL_VERSION_HEADER, "0.1")
            .bearer_auth(self.bearer_token.as_str())
            .body(bytes::Bytes::from_owner(encoded))
            .build()
            .map_err(|_| ProviderError::Unavailable)
    }
}

impl MemoryProviderClient for HttpMemoryProviderClient {
    fn discover(&self) -> Result<MemoryProviderManifest, ProviderError> {
        Self::discover(self)
    }

    fn resolve_context(
        &self,
        request: &MemoryProviderRequest<ResolveContextPayload>,
    ) -> Result<MemoryProviderResponse<ResolveContextResult>, ProviderError> {
        Self::resolve_context(self, request)
    }

    fn resolve_question(
        &self,
        request: &MemoryProviderRequest<ResolveQuestionPayload>,
    ) -> Result<MemoryProviderResponse<ResolveQuestionResult>, ProviderError> {
        Self::resolve_question(self, request)
    }

    fn propose_memory(
        &self,
        request: &MemoryProviderRequest<ProposeMemoryPayload>,
    ) -> Result<MemoryProviderResponse<ProposeMemoryResult>, ProviderError> {
        Self::propose_memory(self, request)
    }

    fn record_events(
        &self,
        request: &MemoryProviderRequest<RecordEventPayload>,
    ) -> Result<MemoryProviderResponse<RecordEventResult>, ProviderError> {
        Self::record_events(self, request)
    }

    fn checkpoint_activity(
        &self,
        request: &MemoryProviderRequest<CheckpointActivityPayload>,
    ) -> Result<MemoryProviderResponse<CheckpointActivityResult>, ProviderError> {
        Self::checkpoint_activity(self, request)
    }

    fn record_disclosure(
        &self,
        request: &MemoryProviderRequest<RecordDisclosurePayload>,
    ) -> Result<MemoryProviderResponse<RecordDisclosureResult>, ProviderError> {
        Self::record_disclosure(self, request)
    }

    fn delete_memory(
        &self,
        request: &MemoryProviderRequest<DeleteMemoryPayload>,
    ) -> Result<MemoryProviderResponse<DeleteMemoryResult>, ProviderError> {
        Self::delete_memory(self, request)
    }

    fn explain_memory(
        &self,
        request: &MemoryProviderRequest<ExplainMemoryPayload>,
    ) -> Result<MemoryProviderResponse<ExplainMemoryResult>, ProviderError> {
        Self::explain_memory(self, request)
    }

    fn sync_pull(
        &self,
        request: &MemoryProviderRequest<SyncPullPayload>,
    ) -> Result<MemoryProviderResponse<SyncPullResult>, ProviderError> {
        Self::sync_pull(self, request)
    }

    fn sync_push(
        &self,
        request: &MemoryProviderRequest<SyncPushPayload>,
    ) -> Result<MemoryProviderResponse<SyncPushResult>, ProviderError> {
        Self::sync_push(self, request)
    }
}

fn encode_operation_body<Body: Serialize>(
    body: &Body,
) -> Result<Zeroizing<Vec<u8>>, ProviderError> {
    let encoded = Zeroizing::new(serde_json::to_vec(body).map_err(|_| {
        ProviderError::InvalidConfiguration(
            "memory provider request could not be encoded".to_owned(),
        )
    })?);
    if encoded.len() as u64 > MAXIMUM_OPERATION_BYTES {
        return Err(ProviderError::InvalidConfiguration(
            "memory provider request exceeds the transport limit".to_owned(),
        ));
    }
    Ok(encoded)
}

fn memory_endpoint(base_url: &Url, memory_id: &str) -> Result<Url, ProviderError> {
    let mut endpoint = base_url
        .join("v1/memories/")
        .map_err(|_| ProviderError::Unavailable)?;
    endpoint
        .path_segments_mut()
        .map_err(|()| {
            ProviderError::InvalidConfiguration("memory provider URL cannot be a base".to_owned())
        })?
        .pop_if_empty()
        .push(memory_id);
    Ok(endpoint)
}

fn memory_subresource_endpoint(
    base_url: &Url,
    memory_id: &str,
    subresource: &str,
) -> Result<Url, ProviderError> {
    let mut endpoint = memory_endpoint(base_url, memory_id)?;
    endpoint
        .path_segments_mut()
        .map_err(|()| {
            ProviderError::InvalidConfiguration("memory provider URL cannot be a base".to_owned())
        })?
        .push(subresource);
    Ok(endpoint)
}

fn explain_memory_endpoint(
    base_url: &Url,
    payload: &ExplainMemoryPayload,
) -> Result<Url, ProviderError> {
    let mut endpoint =
        memory_subresource_endpoint(base_url, payload.memory_id().as_str(), "explain")?;
    endpoint
        .query_pairs_mut()
        .append_pair("version", &payload.version().to_string())
        .append_pair("purpose", payload.purpose());
    Ok(endpoint)
}

fn sync_pull_endpoint(base_url: &Url, payload: &SyncPullPayload) -> Result<Url, ProviderError> {
    let mut endpoint = base_url
        .join("v1/sync/pull")
        .map_err(|_| ProviderError::Unavailable)?;
    {
        let mut query = endpoint.query_pairs_mut();
        if let Some(cursor) = payload.cursor() {
            query.append_pair("cursor", cursor.as_str());
        }
        query.append_pair("maximumItems", &payload.maximum_items().to_string());
    }
    Ok(endpoint)
}

fn activity_subresource_endpoint(
    base_url: &Url,
    activity_id: &str,
    subresource: &str,
) -> Result<Url, ProviderError> {
    let mut endpoint = base_url
        .join("v1/activities/")
        .map_err(|_| ProviderError::Unavailable)?;
    endpoint
        .path_segments_mut()
        .map_err(|()| {
            ProviderError::InvalidConfiguration("memory provider URL cannot be a base".to_owned())
        })?
        .pop_if_empty()
        .push(activity_id)
        .push(subresource);
    Ok(endpoint)
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
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "::1"));
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
    let mut body = Zeroizing::new(Vec::new());
    response
        .take(maximum_bytes + 1)
        .read_to_end(&mut body)
        .map_err(|_| ProviderError::Unavailable)?;
    if body.len() as u64 > maximum_bytes {
        return Err(ProviderError::Rejected(
            "memory provider response exceeds the transport limit".to_owned(),
        ));
    }
    serde_json::from_slice(body.as_slice())
        .map_err(|_| ProviderError::Rejected("memory provider returned malformed JSON".to_owned()))
}

fn decode_operation_response<ResultBody, Payload>(
    response: Response,
    request: &MemoryProviderRequest<Payload>,
) -> Result<Result<ResultBody, rembrane_provider_sdk::MemoryProviderErrorCode>, ProviderError>
where
    ResultBody: for<'de> Deserialize<'de>,
    Payload: rembrane_provider_sdk::MemoryProviderPayload,
{
    validate_response_headers(response.headers(), request.request_id().as_str())?;
    if response.status().is_success() {
        Ok(Ok(decode_json(response, MAXIMUM_OPERATION_BYTES)?))
    } else {
        let error: ErrorBody = decode_json(response, MAXIMUM_OPERATION_BYTES)?;
        Ok(Err(parse_error_code(&error.code)?))
    }
}

fn validate_response_headers(headers: &HeaderMap, request_id: &str) -> Result<(), ProviderError> {
    let response_request_id = headers
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok());
    let response_protocol = headers
        .get(PROTOCOL_VERSION_HEADER)
        .and_then(|value| value.to_str().ok());
    if response_request_id != Some(request_id) || response_protocol != Some("0.1") {
        return Err(ProviderError::Rejected(
            "memory provider response correlation mismatch".to_owned(),
        ));
    }
    Ok(())
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResolveQuestionBody<'request> {
    purpose: &'request str,
    question: &'request str,
    selector: SelectorBody<'request>,
    maximum_supporting_items: usize,
    maximum_answer_bytes: usize,
}

impl<'request> From<&'request ResolveQuestionPayload> for ResolveQuestionBody<'request> {
    fn from(payload: &'request ResolveQuestionPayload) -> Self {
        Self {
            purpose: payload.purpose(),
            question: payload.question(),
            selector: SelectorBody::from(payload.selector().scope()),
            maximum_supporting_items: payload.maximum_supporting_items(),
            maximum_answer_bytes: payload.maximum_answer_bytes(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProposeMemoryBody<'request> {
    idempotency_key: &'request str,
    selector: SelectorBody<'request>,
    kind: &'static str,
    content: &'request str,
    evidence_source: &'static str,
    source_reference: Option<&'request str>,
    observed_at_epoch_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordEventBody<'request> {
    idempotency_key: &'request str,
    events: Vec<MemoryEventBody<'request>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckpointActivityBody<'request> {
    idempotency_key: &'request str,
    activity_id: &'request str,
    entity_id: Option<&'request str>,
    expected_version: Option<u64>,
    goal: Option<&'request str>,
    summary: &'request str,
    next_steps: &'request [String],
    blockers: &'request [String],
    state_fingerprint: Option<&'request str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecordDisclosureBody<'request> {
    idempotency_key: &'request str,
    context_pack_id: &'request str,
    purpose: &'request str,
    memories: Vec<ExactMemoryRevisionRequestBody<'request>>,
    disclosed_at_epoch_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SyncPushBody<'request> {
    idempotency_key: &'request str,
    base_cursor: &'request str,
    mutations: Vec<PushSyncMutationBody<'request>>,
}

impl<'request> From<&'request SyncPushPayload> for SyncPushBody<'request> {
    fn from(payload: &'request SyncPushPayload) -> Self {
        Self {
            idempotency_key: payload.idempotency_key().as_str(),
            base_cursor: payload.base_cursor().as_str(),
            mutations: payload
                .mutations()
                .iter()
                .map(PushSyncMutationBody::from)
                .collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PushSyncMutationBody<'request> {
    mutation_id: &'request str,
    resource: &'static str,
    resource_id: &'request str,
    expected_version: Option<u64>,
    operation: &'static str,
    payload: Option<&'request str>,
    payload_sha256: Option<&'request str>,
}

impl<'request> From<&'request MemoryProviderPushMutation> for PushSyncMutationBody<'request> {
    fn from(mutation: &'request MemoryProviderPushMutation) -> Self {
        Self {
            mutation_id: mutation.mutation_id(),
            resource: sync_resource_name(mutation.resource()),
            resource_id: mutation.resource_id(),
            expected_version: mutation.expected_version(),
            operation: sync_operation_name(mutation.operation()),
            payload: mutation.payload(),
            payload_sha256: mutation.payload_sha256(),
        }
    }
}

impl<'request> From<&'request RecordDisclosurePayload> for RecordDisclosureBody<'request> {
    fn from(payload: &'request RecordDisclosurePayload) -> Self {
        Self {
            idempotency_key: payload.idempotency_key().as_str(),
            context_pack_id: payload.context_pack_id().as_str(),
            purpose: payload.purpose(),
            memories: payload
                .memories()
                .iter()
                .map(ExactMemoryRevisionRequestBody::from)
                .collect(),
            disclosed_at_epoch_seconds: payload.disclosed_at_epoch_seconds(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExactMemoryRevisionRequestBody<'request> {
    memory_id: &'request str,
    version: u64,
}

impl<'request> From<&'request MemoryProviderDisclosedMemory>
    for ExactMemoryRevisionRequestBody<'request>
{
    fn from(memory: &'request MemoryProviderDisclosedMemory) -> Self {
        Self {
            memory_id: memory.memory_id().as_str(),
            version: memory.version(),
        }
    }
}

impl<'request> From<&'request CheckpointActivityPayload> for CheckpointActivityBody<'request> {
    fn from(payload: &'request CheckpointActivityPayload) -> Self {
        Self {
            idempotency_key: payload.idempotency_key().as_str(),
            activity_id: payload.activity_id().as_str(),
            entity_id: payload.entity_id().map(EntityId::as_str),
            expected_version: payload.expected_version(),
            goal: payload.goal(),
            summary: payload.summary(),
            next_steps: payload.next_steps(),
            blockers: payload.blockers(),
            state_fingerprint: payload.state_fingerprint(),
        }
    }
}

impl<'request> From<&'request RecordEventPayload> for RecordEventBody<'request> {
    fn from(payload: &'request RecordEventPayload) -> Self {
        Self {
            idempotency_key: payload.idempotency_key().as_str(),
            events: payload.events().iter().map(MemoryEventBody::from).collect(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemoryEventBody<'request> {
    event_type: &'request str,
    selector: SelectorBody<'request>,
    data: &'request str,
    source_reference: Option<&'request str>,
    observed_at_epoch_seconds: u64,
}

impl<'request> From<&'request MemoryProviderEvent> for MemoryEventBody<'request> {
    fn from(event: &'request MemoryProviderEvent) -> Self {
        Self {
            event_type: event.event_type(),
            selector: SelectorBody::from(event.selector().scope()),
            data: event.data(),
            source_reference: event.source_reference(),
            observed_at_epoch_seconds: event.observed_at_epoch_seconds(),
        }
    }
}

impl<'request> From<&'request ProposeMemoryPayload> for ProposeMemoryBody<'request> {
    fn from(payload: &'request ProposeMemoryPayload) -> Self {
        Self {
            idempotency_key: payload.idempotency_key().as_str(),
            selector: SelectorBody::from(payload.selector().scope()),
            kind: memory_kind_name(payload.kind()),
            content: payload.content(),
            evidence_source: evidence_source_name(payload.evidence_source()),
            source_reference: payload.source_reference(),
            observed_at_epoch_seconds: payload.observed_at_epoch_seconds(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteMemoryBody<'request> {
    idempotency_key: &'request str,
    memory_id: &'request str,
    expected_version: u64,
    reason: &'request str,
}

impl<'request> From<&'request DeleteMemoryPayload> for DeleteMemoryBody<'request> {
    fn from(payload: &'request DeleteMemoryPayload) -> Self {
        Self {
            idempotency_key: payload.idempotency_key().as_str(),
            memory_id: payload.memory_id().as_str(),
            expected_version: payload.expected_version(),
            reason: payload.reason(),
        }
    }
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
#[serde(
    tag = "scope",
    rename_all = "lowercase",
    rename_all_fields = "camelCase"
)]
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ResolveQuestionResultBody {
    answer: String,
    supporting_memories: Vec<ExactMemoryRevisionBody>,
    context_pack_id: String,
    disclosure_id: String,
}

impl ResolveQuestionResultBody {
    fn into_domain(
        self,
        request: &ResolveQuestionPayload,
    ) -> Result<ResolveQuestionResult, ProviderError> {
        if self.supporting_memories.len() > request.maximum_supporting_items() {
            return Err(ProviderError::Rejected(
                "memory provider returned too many supporting memories".to_owned(),
            ));
        }
        ResolveQuestionResult::new(
            self.answer,
            self.supporting_memories
                .into_iter()
                .map(ExactMemoryRevisionBody::into_domain)
                .collect::<Result<Vec<_>, _>>()?,
            ContextPackId::new(self.context_pack_id),
            DisclosureId::new(self.disclosure_id),
            request,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ExactMemoryRevisionBody {
    memory_id: String,
    version: u64,
}

impl ExactMemoryRevisionBody {
    fn into_domain(self) -> Result<MemoryProviderDisclosedMemory, ProviderError> {
        MemoryProviderDisclosedMemory::new(MemoryId::new(self.memory_id), self.version)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProposeMemoryResultBody {
    memory_id: String,
    version: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordEventResultBody {
    events: Vec<RecordedEventBody>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CheckpointActivityResultBody {
    checkpoint_id: String,
    version: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RecordDisclosureResultBody {
    disclosure_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SyncPullResultBody {
    changes: Vec<PulledSyncChangeBody>,
    next_cursor: String,
    has_more: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SyncPushResultBody {
    accepted: Vec<AcceptedSyncMutationBody>,
    next_cursor: String,
}

impl SyncPushResultBody {
    fn into_domain(self, request: &SyncPushPayload) -> Result<SyncPushResult, ProviderError> {
        if self.accepted.len() != request.mutations().len() {
            return Err(ProviderError::Rejected(
                "memory provider sync push result count does not match the submitted batch"
                    .to_owned(),
            ));
        }
        SyncPushResult::new(
            self.accepted
                .into_iter()
                .map(AcceptedSyncMutationBody::into_domain)
                .collect::<Result<Vec<_>, _>>()?,
            MemoryProviderSyncCursor::new(self.next_cursor)?,
            request,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AcceptedSyncMutationBody {
    mutation_id: String,
    version: u64,
    sequence: u64,
}

impl AcceptedSyncMutationBody {
    fn into_domain(self) -> Result<MemoryProviderAcceptedMutation, ProviderError> {
        MemoryProviderAcceptedMutation::new(self.mutation_id, self.version, self.sequence)
    }
}

impl SyncPullResultBody {
    fn into_domain(self, request: &SyncPullPayload) -> Result<SyncPullResult, ProviderError> {
        if self.changes.len() > request.maximum_items() {
            return Err(ProviderError::Rejected(
                "memory provider sync pull returned too many changes".to_owned(),
            ));
        }
        SyncPullResult::new(
            self.changes
                .into_iter()
                .map(PulledSyncChangeBody::into_domain)
                .collect::<Result<Vec<_>, _>>()?,
            MemoryProviderSyncCursor::new(self.next_cursor)?,
            self.has_more,
            request,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PulledSyncChangeBody {
    change_id: String,
    sequence: u64,
    resource: String,
    resource_id: String,
    version: u64,
    operation: String,
    payload: Option<String>,
    payload_sha256: Option<String>,
}

impl PulledSyncChangeBody {
    fn into_domain(self) -> Result<MemoryProviderPulledChange, ProviderError> {
        MemoryProviderPulledChange::new(
            self.change_id,
            self.sequence,
            parse_sync_resource(&self.resource)?,
            self.resource_id,
            self.version,
            parse_sync_operation(&self.operation)?,
            self.payload,
            self.payload_sha256,
        )
    }
}

impl CheckpointActivityResultBody {
    fn into_domain(
        self,
        request: &CheckpointActivityPayload,
    ) -> Result<CheckpointActivityResult, ProviderError> {
        let expected_result_version = request
            .expected_version()
            .map_or(Some(1), |version| version.checked_add(1))
            .ok_or_else(|| {
                ProviderError::Rejected(
                    "memory provider checkpoint request version cannot advance".to_owned(),
                )
            })?;
        if self.version != expected_result_version {
            return Err(ProviderError::Rejected(
                "memory provider checkpoint returned a non-consecutive version".to_owned(),
            ));
        }
        CheckpointActivityResult::new(CheckpointId::new(self.checkpoint_id), self.version)
    }
}

impl RecordEventResultBody {
    fn into_domain(self, request: &RecordEventPayload) -> Result<RecordEventResult, ProviderError> {
        if self.events.len() != request.events().len() {
            return Err(ProviderError::Rejected(
                "memory provider event result does not match the submitted batch".to_owned(),
            ));
        }
        RecordEventResult::new(
            self.events
                .into_iter()
                .map(RecordedEventBody::into_domain)
                .collect::<Result<Vec<_>, _>>()?,
            MemoryProviderLimits {
                maximum_context_items: 1,
                maximum_context_bytes: 1,
                maximum_event_batch_items: request.events().len(),
                maximum_sync_batch_items: 1,
            },
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RecordedEventBody {
    event_id: String,
    sequence: u64,
}

impl RecordedEventBody {
    fn into_domain(self) -> Result<MemoryProviderRecordedEvent, ProviderError> {
        MemoryProviderRecordedEvent::new(EventId::new(self.event_id), self.sequence)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DeleteMemoryResultBody {
    memory_id: String,
    deleted_version: u64,
    tombstone_version: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ExplainMemoryResultBody {
    memory_id: String,
    version: u64,
    explanation: String,
    evidence: Vec<EvidenceBody>,
}

impl ExplainMemoryResultBody {
    fn into_domain(
        self,
        request: &ExplainMemoryPayload,
    ) -> Result<ExplainMemoryResult, ProviderError> {
        if self.memory_id != request.memory_id().as_str() || self.version != request.version() {
            return Err(ProviderError::Rejected(
                "memory provider explanation returned another memory revision".to_owned(),
            ));
        }
        ExplainMemoryResult::new(
            MemoryId::new(self.memory_id),
            self.version,
            self.explanation,
            self.evidence
                .into_iter()
                .map(EvidenceBody::into_domain)
                .collect::<Result<Vec<_>, _>>()?,
        )
    }
}

impl ResolveContextResultBody {
    fn into_domain(
        self,
        request: &ResolveContextPayload,
    ) -> Result<ResolveContextResult, ProviderError> {
        if self.items.len() > request.maximum_items() {
            return Err(ProviderError::Rejected(
                "memory provider returned too many context items".to_owned(),
            ));
        }
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

const fn memory_kind_name(value: MemoryKind) -> &'static str {
    match value {
        MemoryKind::Preference => "preference",
        MemoryKind::Semantic => "semantic",
        MemoryKind::Episodic => "episodic",
        MemoryKind::Procedural => "procedural",
        MemoryKind::Observation => "observation",
        MemoryKind::Working => "working",
    }
}

const fn evidence_source_name(value: EvidenceSource) -> &'static str {
    match value {
        EvidenceSource::UserStatement => "user_statement",
        EvidenceSource::AgentObservation => "agent_observation",
        EvidenceSource::ToolResult => "tool_result",
        EvidenceSource::ImportedRecord => "imported_record",
        EvidenceSource::WorkspaceDecision => "workspace_decision",
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

fn parse_sync_resource(value: &str) -> Result<MemoryProviderSyncResource, ProviderError> {
    match value {
        "memory" => Ok(MemoryProviderSyncResource::Memory),
        "evidence" => Ok(MemoryProviderSyncResource::Evidence),
        "activity_checkpoint" => Ok(MemoryProviderSyncResource::ActivityCheckpoint),
        "disclosure_receipt" => Ok(MemoryProviderSyncResource::DisclosureReceipt),
        "entity" => Ok(MemoryProviderSyncResource::Entity),
        "event" => Ok(MemoryProviderSyncResource::Event),
        _ => Err(invalid_operation_response()),
    }
}

const fn sync_resource_name(value: MemoryProviderSyncResource) -> &'static str {
    match value {
        MemoryProviderSyncResource::Memory => "memory",
        MemoryProviderSyncResource::Evidence => "evidence",
        MemoryProviderSyncResource::ActivityCheckpoint => "activity_checkpoint",
        MemoryProviderSyncResource::DisclosureReceipt => "disclosure_receipt",
        MemoryProviderSyncResource::Entity => "entity",
        MemoryProviderSyncResource::Event => "event",
    }
}

fn parse_sync_operation(value: &str) -> Result<MemoryProviderSyncOperation, ProviderError> {
    match value {
        "upsert" => Ok(MemoryProviderSyncOperation::Upsert),
        "delete" => Ok(MemoryProviderSyncOperation::Delete),
        _ => Err(invalid_operation_response()),
    }
}

const fn sync_operation_name(value: MemoryProviderSyncOperation) -> &'static str {
    match value {
        MemoryProviderSyncOperation::Upsert => "upsert",
        MemoryProviderSyncOperation::Delete => "delete",
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
    #[serde(rename = "maximumContextItems")]
    context_items: usize,
    #[serde(rename = "maximumContextBytes")]
    context_bytes: usize,
    #[serde(rename = "maximumEventBatchItems")]
    event_batch_items: usize,
    #[serde(rename = "maximumSyncBatchItems")]
    sync_batch_items: usize,
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
        if wire.transports.len() > MAXIMUM_DISCOVERY_TRANSPORTS
            || wire.capabilities.len() > MAXIMUM_DISCOVERY_CAPABILITIES
            || wire.operations.len() > MAXIMUM_DISCOVERY_CAPABILITIES
        {
            return Err(invalid_discovery());
        }
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
                maximum_context_items: wire.limits.context_items,
                maximum_context_bytes: wire.limits.context_bytes,
                maximum_event_batch_items: wire.limits.event_batch_items,
                maximum_sync_batch_items: wire.limits.sync_batch_items,
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
    use rembrane_domain::{EntityId, EvidenceSource, MemoryKind, MemoryScope};
    use rembrane_provider_sdk::{
        CURRENT_MEMORY_PROVIDER_PROTOCOL, CheckpointActivityPayload, ExplainMemoryPayload,
        MemoryProviderCapability, MemoryProviderConnection, MemoryProviderContextSelector,
        MemoryProviderDisclosedMemory, MemoryProviderEvent, MemoryProviderIdempotencyKey,
        MemoryProviderLimits, MemoryProviderManifest, MemoryProviderPolicy,
        MemoryProviderPrivacyMode, MemoryProviderPushMutation, MemoryProviderSyncCursor,
        MemoryProviderSyncOperation, MemoryProviderSyncResource, MemoryProviderTransport,
        ProposeMemoryPayload, ProviderError, RecordDisclosurePayload, RecordEventPayload,
        ResolveContextPayload, ResolveQuestionPayload, SyncPullPayload, SyncPushPayload,
    };

    use super::{
        CheckpointActivityBody, CheckpointActivityResultBody, DiscoveryBody,
        ExplainMemoryResultBody, HttpMemoryProviderClient, ProposeMemoryBody, RecordDisclosureBody,
        RecordDisclosureResultBody, RecordEventBody, RecordEventResultBody, ResolveContextBody,
        ResolveContextResultBody, ResolveQuestionBody, ResolveQuestionResultBody,
        SyncPullResultBody, SyncPushBody, SyncPushResultBody, activity_subresource_endpoint,
        explain_memory_endpoint, memory_endpoint, memory_subresource_endpoint, sync_pull_endpoint,
        validate_base_url, validate_bearer_token, validate_response_headers,
    };
    use reqwest::Method;
    use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

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
            "http://localhost:8794",
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

    fn connection(capability: MemoryProviderCapability) -> MemoryProviderConnection {
        let limits = MemoryProviderLimits {
            maximum_context_items: 10,
            maximum_context_bytes: 1_048_576,
            maximum_event_batch_items: 10,
            maximum_sync_batch_items: 10,
        };
        let manifest = MemoryProviderManifest::new(
            "rembrane.memory.wire-test".to_owned(),
            "test".to_owned(),
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            vec![MemoryProviderTransport::Https],
            vec![capability],
            MemoryProviderPrivacyMode::EndToEndEncrypted,
            Vec::new(),
            limits,
        )
        .expect("manifest");
        let policy = MemoryProviderPolicy::new(
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            MemoryProviderTransport::Https,
            vec![capability],
            vec![MemoryProviderPrivacyMode::EndToEndEncrypted],
            limits,
        )
        .expect("policy");
        MemoryProviderConnection::connect(manifest, &policy, "wire-test").expect("connection")
    }

    #[test]
    fn proposal_request_uses_direct_body_and_correlation_headers_without_a_socket() {
        let client =
            HttpMemoryProviderClient::new("http://127.0.0.1:8794", "wire-token".to_owned())
                .expect("client");
        let request = connection(MemoryProviderCapability::ProposeMemory)
            .request(
                ProposeMemoryPayload::new(
                    MemoryProviderIdempotencyKey::new("proposal_0123456789abcdef").expect("key"),
                    MemoryProviderContextSelector::global(),
                    MemoryKind::Preference,
                    "Call the user Hippo.",
                    EvidenceSource::UserStatement,
                    None,
                    1,
                    1,
                )
                .expect("payload"),
            )
            .expect("request");
        let endpoint = client
            .base_url
            .join("v1/memory/proposals")
            .expect("endpoint");
        let body = ProposeMemoryBody::from(request.payload());
        let wire = client
            .build_json_request(Method::POST, endpoint, &body, request.request_id().as_str())
            .expect("wire request");

        assert_eq!(wire.method(), Method::POST);
        assert_eq!(wire.url().path(), "/v1/memory/proposals");
        assert_eq!(wire.headers()[AUTHORIZATION], "Bearer wire-token");
        assert_eq!(wire.headers()[super::PROTOCOL_VERSION_HEADER], "0.1");
        let body = wire
            .body()
            .and_then(reqwest::blocking::Body::as_bytes)
            .expect("in-memory request body");
        let json: serde_json::Value = serde_json::from_slice(body).expect("JSON body");
        assert_eq!(json["content"], "Call the user Hippo.");
        assert!(json.get("payload").is_none());
        assert!(json.get("requestId").is_none());
    }

    #[test]
    fn explanation_request_encodes_path_and_query_without_a_socket_or_body() {
        let client =
            HttpMemoryProviderClient::new("http://127.0.0.1:8794", "wire-token".to_owned())
                .expect("client");
        let request = connection(MemoryProviderCapability::ExplainMemory)
            .request(
                ExplainMemoryPayload::new(
                    rembrane_domain::MemoryId::new("memory/01"),
                    7,
                    "why remember this",
                )
                .expect("payload"),
            )
            .expect("request");
        let endpoint =
            explain_memory_endpoint(&client.base_url, request.payload()).expect("endpoint");
        let wire = client
            .build_get_request(endpoint, request.request_id().as_str())
            .expect("wire request");

        assert_eq!(wire.method(), Method::GET);
        assert_eq!(wire.url().path(), "/v1/memories/memory%2F01/explain");
        assert_eq!(
            wire.url().query(),
            Some("version=7&purpose=why+remember+this")
        );
        assert_eq!(wire.headers()[AUTHORIZATION], "Bearer wire-token");
        assert!(wire.body().is_none());
    }

    #[test]
    fn requires_exact_https_response_correlation_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            super::REQUEST_ID_HEADER,
            HeaderValue::from_static("request_0123456789"),
        );
        headers.insert(
            super::PROTOCOL_VERSION_HEADER,
            HeaderValue::from_static("0.1"),
        );
        assert!(validate_response_headers(&headers, "request_0123456789").is_ok());
        assert!(validate_response_headers(&headers, "request_9876543210").is_err());

        headers.insert(
            super::PROTOCOL_VERSION_HEADER,
            HeaderValue::from_static("0.2"),
        );
        assert!(validate_response_headers(&headers, "request_0123456789").is_err());
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
    fn rejects_discovery_collections_above_the_protocol_surface() {
        let mut discovery: serde_json::Value =
            serde_json::from_str(DISCOVERY).expect("discovery fixture");
        discovery["transports"] = serde_json::json!(["https", "mcp", "https"]);
        let wire: DiscoveryBody =
            serde_json::from_value(discovery).expect("discovery shape should decode");

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
        let encoded = serde_json::to_value(ResolveContextBody::from(request.payload()))
            .expect("request JSON");
        assert_eq!(encoded["selector"]["scope"], "entity");
        assert_eq!(encoded["selector"]["entityId"], "project_rembrane");
        assert!(encoded.get("workspaceId").is_none());
        assert!(encoded.get("subjectId").is_none());
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

    #[test]
    fn serializes_and_bounds_grounded_question_answers() {
        let limits = MemoryProviderLimits {
            maximum_context_items: 10,
            maximum_context_bytes: 1_024,
            maximum_event_batch_items: 1,
            maximum_sync_batch_items: 1,
        };
        let request = ResolveQuestionPayload::new(
            "continue a project",
            "What should the next coding agent implement?",
            MemoryProviderContextSelector::domain("development").expect("selector"),
            2,
            512,
            limits,
        )
        .expect("request");
        let encoded =
            serde_json::to_value(ResolveQuestionBody::from(&request)).expect("request JSON");
        assert_eq!(encoded["selector"]["scope"], "domain");
        assert_eq!(encoded["selector"]["domain"], "development");
        assert_eq!(encoded["maximumSupportingItems"], 2);
        assert_eq!(encoded["maximumAnswerBytes"], 512);
        assert!(encoded.get("workspaceId").is_none());
        assert!(encoded.get("subjectId").is_none());

        let wire: ResolveQuestionResultBody = serde_json::from_str(
            r#"{
              "answer":"Implement the event ingestion binding next.",
              "supportingMemories":[
                {"memoryId":"memory_01","version":3},
                {"memoryId":"memory_02","version":1}
              ],
              "contextPackId":"context_pack_01",
              "disclosureId":"disclosure_01"
            }"#,
        )
        .expect("result JSON");
        let result = wire.into_domain(&request).expect("canonical result");
        assert_eq!(result.supporting_memories().len(), 2);
        assert_eq!(result.supporting_memories()[0].version(), 3);
        assert_eq!(result.context_pack_id().as_str(), "context_pack_01");

        let oversized: ResolveQuestionResultBody = serde_json::from_str(
            r#"{
              "answer":"This result contains too many supporting revisions.",
              "supportingMemories":[
                {"memoryId":"memory_01","version":1},
                {"memoryId":"memory_02","version":1},
                {"memoryId":"memory_03","version":1}
              ],
              "contextPackId":"context_pack_01",
              "disclosureId":"disclosure_01"
            }"#,
        )
        .expect("result JSON");
        assert!(oversized.into_domain(&request).is_err());
    }

    #[test]
    fn serializes_proposals_without_confirmation_or_tenant_identity() {
        let payload = ProposeMemoryPayload::new(
            MemoryProviderIdempotencyKey::new("proposal_0123456789abcdef").expect("key"),
            MemoryProviderContextSelector::global(),
            rembrane_domain::MemoryKind::Preference,
            "Call the user Hippo.",
            rembrane_domain::EvidenceSource::UserStatement,
            Some("conversation-turn-42".to_owned()),
            100,
            101,
        )
        .expect("proposal");
        let encoded = serde_json::to_value(ProposeMemoryBody::from(&payload))
            .expect("proposal should encode");
        assert_eq!(encoded["selector"]["scope"], "global");
        assert_eq!(encoded["kind"], "preference");
        assert_eq!(encoded["evidenceSource"], "user_statement");
        assert!(encoded.get("workspaceId").is_none());
        assert!(encoded.get("subjectId").is_none());
        assert!(encoded.get("confirmed").is_none());
    }

    #[test]
    fn serializes_and_validates_ordered_event_batches() {
        let limits = MemoryProviderLimits {
            maximum_context_items: 1,
            maximum_context_bytes: 1,
            maximum_event_batch_items: 2,
            maximum_sync_batch_items: 1,
        };
        let event = MemoryProviderEvent::new(
            "development.work-trace",
            MemoryProviderContextSelector::entity(EntityId::new("project_rembrane"))
                .expect("selector"),
            r#"{"summary":"implemented event transport"}"#,
            Some("git:d93d621".to_owned()),
            100,
            100,
        )
        .expect("event");
        let payload = RecordEventPayload::new(
            MemoryProviderIdempotencyKey::new("events_0123456789abcdef").expect("key"),
            vec![event],
            limits,
        )
        .expect("payload");
        let encoded = serde_json::to_value(RecordEventBody::from(&payload)).expect("request JSON");
        assert_eq!(encoded["events"][0]["eventType"], "development.work-trace");
        assert_eq!(encoded["events"][0]["selector"]["scope"], "entity");
        assert_eq!(
            encoded["events"][0]["selector"]["entityId"],
            "project_rembrane"
        );
        assert!(encoded.get("workspaceId").is_none());
        assert!(encoded.get("subjectId").is_none());
        assert!(encoded["events"][0].get("actorId").is_none());

        let wire: RecordEventResultBody =
            serde_json::from_str(r#"{"events":[{"eventId":"event_01","sequence":41}]}"#)
                .expect("result JSON");
        let result = wire.into_domain(&payload).expect("canonical result");
        assert_eq!(result.events()[0].event_id().as_str(), "event_01");
        assert_eq!(result.events()[0].sequence(), 41);

        let mismatched: RecordEventResultBody =
            serde_json::from_str(r#"{"events":[]}"#).expect("result JSON");
        assert!(mismatched.into_domain(&payload).is_err());
    }

    #[test]
    fn serializes_and_version_binds_activity_checkpoints() {
        let create = CheckpointActivityPayload::create(
            MemoryProviderIdempotencyKey::new("checkpoint_0123456789abcdef").expect("key"),
            rembrane_domain::ActivityId::new("activity/rembrane"),
            Some(EntityId::new("project_rembrane")),
            "Ship the portable memory provider",
            "Question and event transports are complete.",
            vec!["Implement checkpoint transport.".to_owned()],
            vec!["Dependency registry is unavailable.".to_owned()],
            Some("git:4cdf31e".to_owned()),
        )
        .expect("checkpoint");
        let encoded =
            serde_json::to_value(CheckpointActivityBody::from(&create)).expect("request JSON");
        assert_eq!(encoded["activityId"], "activity/rembrane");
        assert_eq!(encoded["entityId"], "project_rembrane");
        assert_eq!(encoded["expectedVersion"], serde_json::Value::Null);
        assert_eq!(encoded["goal"], "Ship the portable memory provider");
        assert!(encoded.get("workspaceId").is_none());
        assert!(encoded.get("subjectId").is_none());

        let result: CheckpointActivityResultBody =
            serde_json::from_str(r#"{"checkpointId":"checkpoint_01","version":1}"#)
                .expect("result JSON");
        assert_eq!(
            result
                .into_domain(&create)
                .expect("canonical result")
                .version(),
            1
        );

        let update = CheckpointActivityPayload::update(
            MemoryProviderIdempotencyKey::new("checkpoint_1123456789abcdef").expect("key"),
            rembrane_domain::ActivityId::new("activity/rembrane"),
            Some(EntityId::new("project_rembrane")),
            3,
            "Checkpoint transport is complete.",
            vec!["Implement disclosure transport.".to_owned()],
            Vec::new(),
            Some("git:pending".to_owned()),
        )
        .expect("checkpoint");
        let stale: CheckpointActivityResultBody =
            serde_json::from_str(r#"{"checkpointId":"checkpoint_01","version":3}"#)
                .expect("result JSON");
        assert!(stale.into_domain(&update).is_err());
    }

    #[test]
    fn percent_encodes_activity_identity_before_checkpoint_subresource() {
        let base = validate_base_url("https://memory.example.test").expect("base URL");
        let endpoint =
            activity_subresource_endpoint(&base, "activity/with?reserved#bytes", "checkpoint")
                .expect("endpoint");
        assert_eq!(
            endpoint.as_str(),
            "https://memory.example.test/v1/activities/activity%2Fwith%3Freserved%23bytes/checkpoint"
        );
        assert_eq!(endpoint.path_segments().expect("segments").count(), 4);
    }

    #[test]
    fn serializes_append_only_disclosure_receipts_without_caller_identity() {
        let payload = RecordDisclosurePayload::new(
            MemoryProviderIdempotencyKey::new("disclosure_0123456789abcdef").expect("key"),
            rembrane_domain::ContextPackId::new("context_pack_01"),
            "continue development work",
            vec![
                MemoryProviderDisclosedMemory::new(rembrane_domain::MemoryId::new("memory_01"), 3)
                    .expect("revision"),
                MemoryProviderDisclosedMemory::new(rembrane_domain::MemoryId::new("memory_02"), 1)
                    .expect("revision"),
            ],
            100,
            100,
        )
        .expect("payload");
        let encoded =
            serde_json::to_value(RecordDisclosureBody::from(&payload)).expect("request JSON");
        assert_eq!(encoded["contextPackId"], "context_pack_01");
        assert_eq!(encoded["memories"][0]["memoryId"], "memory_01");
        assert_eq!(encoded["memories"][0]["version"], 3);
        assert_eq!(encoded["disclosedAtEpochSeconds"], 100);
        assert!(encoded.get("workspaceId").is_none());
        assert!(encoded.get("subjectId").is_none());
        assert!(encoded.get("clientId").is_none());

        let result: RecordDisclosureResultBody =
            serde_json::from_str(r#"{"disclosureId":"disclosure_01"}"#).expect("result JSON");
        let canonical = rembrane_provider_sdk::RecordDisclosureResult::new(
            rembrane_domain::DisclosureId::new(result.disclosure_id),
        )
        .expect("canonical result");
        assert_eq!(canonical.disclosure_id().as_str(), "disclosure_01");
    }

    #[test]
    fn serializes_and_validates_ordered_sync_pull_pages() {
        let limits = MemoryProviderLimits {
            maximum_context_items: 1,
            maximum_context_bytes: 1,
            maximum_event_batch_items: 1,
            maximum_sync_batch_items: 2,
        };
        let request = SyncPullPayload::new(
            Some(MemoryProviderSyncCursor::new("cursor_0123456789_start").expect("cursor")),
            2,
            limits,
        )
        .expect("request");
        let endpoint = sync_pull_endpoint(
            &validate_base_url("https://memory.example.test").expect("base"),
            &request,
        )
        .expect("endpoint");
        assert_eq!(
            endpoint.as_str(),
            "https://memory.example.test/v1/sync/pull?cursor=cursor_0123456789_start&maximumItems=2"
        );

        let wire: SyncPullResultBody = serde_json::from_str(
            r#"{
              "changes":[
                {
                  "changeId":"change_01",
                  "sequence":7,
                  "resource":"memory",
                  "resourceId":"memory_01",
                  "version":3,
                  "operation":"upsert",
                  "payload":"ciphertext",
                  "payloadSha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                },
                {
                  "changeId":"change_02",
                  "sequence":8,
                  "resource":"memory",
                  "resourceId":"memory_02",
                  "version":4,
                  "operation":"delete"
                }
              ],
              "nextCursor":"cursor_0123456789_next",
              "hasMore":false
            }"#,
        )
        .expect("result JSON");
        let result = wire.into_domain(&request).expect("canonical result");
        assert_eq!(result.changes().len(), 2);
        assert_eq!(result.changes()[1].sequence(), 8);
        assert!(result.changes()[1].payload().is_none());
        assert_eq!(result.next_cursor().as_str(), "cursor_0123456789_next");

        let unordered: SyncPullResultBody = serde_json::from_str(
            r#"{
              "changes":[
                {
                  "changeId":"change_02",
                  "sequence":8,
                  "resource":"event",
                  "resourceId":"event_02",
                  "version":1,
                  "operation":"delete"
                },
                {
                  "changeId":"change_01",
                  "sequence":7,
                  "resource":"event",
                  "resourceId":"event_01",
                  "version":1,
                  "operation":"delete"
                }
              ],
              "nextCursor":"cursor_0123456789_next",
              "hasMore":false
            }"#,
        )
        .expect("result JSON");
        assert!(unordered.into_domain(&request).is_err());

        let oversized: SyncPullResultBody = serde_json::from_str(
            r#"{
              "changes":[
                {"changeId":"change_01","sequence":7,"resource":"event","resourceId":"event_01","version":1,"operation":"delete"},
                {"changeId":"change_02","sequence":8,"resource":"event","resourceId":"event_02","version":1,"operation":"delete"},
                {"changeId":"change_03","sequence":9,"resource":"event","resourceId":"event_03","version":1,"operation":"delete"}
              ],
              "nextCursor":"cursor_0123456789_next",
              "hasMore":false
            }"#,
        )
        .expect("result JSON");
        assert!(matches!(
            oversized.into_domain(&request),
            Err(ProviderError::Rejected(message))
                if message == "memory provider sync pull returned too many changes"
        ));
    }

    #[test]
    fn serializes_and_validates_atomic_ordered_sync_pushes() {
        const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let limits = MemoryProviderLimits {
            maximum_context_items: 1,
            maximum_context_bytes: 1,
            maximum_event_batch_items: 1,
            maximum_sync_batch_items: 2,
        };
        let request = SyncPushPayload::new(
            MemoryProviderIdempotencyKey::new("syncpush_0123456789").expect("key"),
            MemoryProviderSyncCursor::new("cursor_0123456789_base").expect("cursor"),
            vec![
                MemoryProviderPushMutation::new(
                    "mutation_01",
                    MemoryProviderSyncResource::Memory,
                    "memory_01",
                    None,
                    MemoryProviderSyncOperation::Upsert,
                    Some("ciphertext".to_owned()),
                    Some(DIGEST.to_owned()),
                )
                .expect("mutation"),
                MemoryProviderPushMutation::new(
                    "mutation_02",
                    MemoryProviderSyncResource::Event,
                    "event_01",
                    Some(3),
                    MemoryProviderSyncOperation::Delete,
                    None,
                    None,
                )
                .expect("mutation"),
            ],
            limits,
        )
        .expect("request");
        let encoded = serde_json::to_value(SyncPushBody::from(&request)).expect("request JSON");
        assert_eq!(encoded["baseCursor"], "cursor_0123456789_base");
        assert_eq!(encoded["mutations"][0]["resource"], "memory");
        assert_eq!(encoded["mutations"][0]["operation"], "upsert");
        assert_eq!(encoded["mutations"][1]["operation"], "delete");
        assert_eq!(encoded["mutations"][1]["payload"], serde_json::Value::Null);
        assert!(encoded.get("workspaceId").is_none());
        assert!(encoded.get("clientId").is_none());

        let wire: SyncPushResultBody = serde_json::from_str(
            r#"{
              "accepted":[
                {"mutationId":"mutation_01","version":1,"sequence":9},
                {"mutationId":"mutation_02","version":4,"sequence":10}
              ],
              "nextCursor":"cursor_0123456789_next"
            }"#,
        )
        .expect("result JSON");
        let result = wire.into_domain(&request).expect("canonical result");
        assert_eq!(result.accepted().len(), 2);
        assert_eq!(result.accepted()[1].sequence(), 10);
        assert_eq!(result.next_cursor().as_str(), "cursor_0123456789_next");

        let reordered: SyncPushResultBody = serde_json::from_str(
            r#"{
              "accepted":[
                {"mutationId":"mutation_02","version":4,"sequence":9},
                {"mutationId":"mutation_01","version":1,"sequence":10}
              ],
              "nextCursor":"cursor_0123456789_next"
            }"#,
        )
        .expect("result JSON");
        assert!(reordered.into_domain(&request).is_err());

        let oversized: SyncPushResultBody = serde_json::from_str(
            r#"{
              "accepted":[
                {"mutationId":"mutation_01","version":1,"sequence":9},
                {"mutationId":"mutation_02","version":4,"sequence":10},
                {"mutationId":"mutation_03","version":1,"sequence":11}
              ],
              "nextCursor":"cursor_0123456789_next"
            }"#,
        )
        .expect("result JSON");
        assert!(matches!(
            oversized.into_domain(&request),
            Err(ProviderError::Rejected(message))
                if message == "memory provider sync push result count does not match the submitted batch"
        ));
    }

    #[test]
    fn percent_encodes_memory_identity_as_one_path_segment() {
        let base = validate_base_url("https://memory.example.test").expect("base URL");
        let endpoint = memory_endpoint(&base, "memory/with?reserved#bytes").expect("endpoint");
        assert_eq!(
            endpoint.as_str(),
            "https://memory.example.test/v1/memories/memory%2Fwith%3Freserved%23bytes"
        );
        assert_eq!(
            endpoint.path_segments().expect("segments").count(),
            3,
            "opaque memory identity must remain one final path segment"
        );
    }

    #[test]
    fn binds_explanations_to_one_exact_memory_revision() {
        let payload = ExplainMemoryPayload::new(
            rembrane_domain::MemoryId::new("memory_01"),
            7,
            "explain personalization",
        )
        .expect("payload");
        let endpoint = explain_memory_endpoint(
            &validate_base_url("https://memory.example.test").expect("base"),
            &payload,
        )
        .expect("endpoint");
        assert_eq!(
            endpoint.as_str(),
            "https://memory.example.test/v1/memories/memory_01/explain?version=7&purpose=explain+personalization"
        );

        let wire: ExplainMemoryResultBody = serde_json::from_str(
            r#"{
              "memoryId":"memory_01",
              "version":7,
              "explanation":"The user explicitly selected this preferred name.",
              "evidence":[{"evidenceId":"evidence_01","source":"user_statement"}]
            }"#,
        )
        .expect("result JSON");
        let result = wire.into_domain(&payload).expect("canonical result");
        assert_eq!(result.memory_id().as_str(), "memory_01");
        assert_eq!(result.version(), 7);
        assert_eq!(result.evidence().len(), 1);

        let mismatched: ExplainMemoryResultBody = serde_json::from_str(
            r#"{
              "memoryId":"memory_01",
              "version":8,
              "explanation":"A different revision must not be accepted.",
              "evidence":[{"evidenceId":"evidence_01","source":"user_statement"}]
            }"#,
        )
        .expect("result JSON");
        assert!(mismatched.into_domain(&payload).is_err());
    }

    #[test]
    fn builds_safe_memory_explanation_endpoint() {
        let base = validate_base_url("https://memory.example.test").expect("base URL");
        let endpoint = memory_subresource_endpoint(&base, "memory/with?reserved#bytes", "explain")
            .expect("endpoint");
        assert_eq!(
            endpoint.as_str(),
            "https://memory.example.test/v1/memories/memory%2Fwith%3Freserved%23bytes/explain"
        );
        assert_eq!(endpoint.path_segments().expect("segments").count(), 4);
    }
}

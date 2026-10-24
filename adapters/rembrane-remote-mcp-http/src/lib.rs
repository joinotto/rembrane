//! HTTP-facing authorization gate for remote MCP server transports.
//!
//! This adapter performs only the minimum bounded JSON-RPC classification
//! needed for authorization. The official MCP SDK remains responsible for
//! protocol execution, while this gate ensures every accepted request has
//! already passed bearer, origin, method/tool, session, and tenant checks.

use std::future::Future;

use axum::{
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{
            ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST, ORIGIN, RETRY_AFTER, WWW_AUTHENTICATE,
        },
    },
    response::{IntoResponse, Response},
};
use rembrane_application::{
    RemoteAccessAuthenticator, RemoteHttpAuthorization, RemoteHttpAuthorizationError,
    RemoteSessionHttpError, RemoteSessionRegistry, RemoteTokenVerifier,
};
use rembrane_config::RemoteMcpConfig;
use rembrane_contracts::{RemoteMcpRequestAuthorization, RemoteSessionId, VerifiedRemoteAccess};
use serde::Deserialize;
use zeroize::Zeroizing;

pub const MCP_SESSION_HEADER: &str = "Mcp-Session-Id";
pub const MAX_REMOTE_MCP_REQUEST_BYTES: usize = 1_048_576;
const MCP_SESSION_HEADER_NAME: HeaderName = HeaderName::from_static("mcp-session-id");
const MCP_PROTOCOL_VERSION_HEADER_NAME: HeaderName =
    HeaderName::from_static("mcp-protocol-version");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteMcpInvocation {
    method: String,
    tool_name: Option<String>,
}

impl RemoteMcpInvocation {
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    #[must_use]
    pub fn tool_name(&self) -> Option<&str> {
        self.tool_name.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteMcpProtocolHeaders {
    content_type: String,
    accept: String,
    protocol_version: Option<String>,
}

impl RemoteMcpProtocolHeaders {
    #[must_use]
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    #[must_use]
    pub fn accept(&self) -> &str {
        &self.accept
    }

    #[must_use]
    pub fn protocol_version(&self) -> Option<&str> {
        self.protocol_version.as_deref()
    }

    fn transport_neutral() -> Self {
        Self {
            content_type: "application/json".to_owned(),
            accept: "application/json, text/event-stream".to_owned(),
            protocol_version: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedRemoteMcpEventStream {
    access: VerifiedRemoteAccess,
    accept: String,
    protocol_version: Option<String>,
}

pub trait AuthorizedRemoteMcpEventStreamDispatcher {
    type Output;
    type Error;
    type DispatchFuture: Future<Output = Result<Self::Output, Self::Error>> + Send;

    fn open(
        &self,
        access: VerifiedRemoteAccess,
        accept: String,
        protocol_version: Option<String>,
    ) -> Self::DispatchFuture;
}

impl AuthorizedRemoteMcpEventStream {
    #[must_use]
    pub const fn access(&self) -> &VerifiedRemoteAccess {
        &self.access
    }

    #[must_use]
    pub fn accept(&self) -> &str {
        &self.accept
    }

    #[must_use]
    pub fn protocol_version(&self) -> Option<&str> {
        self.protocol_version.as_deref()
    }

    #[must_use]
    pub fn into_parts(self) -> (VerifiedRemoteAccess, String, Option<String>) {
        (self.access, self.accept, self.protocol_version)
    }

    /// Consumes the authorization proof and opens the server event stream
    /// through one asynchronous transport dispatcher.
    ///
    /// # Errors
    ///
    /// Returns the transport dispatcher's error.
    pub async fn dispatch_with<Dispatcher>(
        self,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, Dispatcher::Error>
    where
        Dispatcher: AuthorizedRemoteMcpEventStreamDispatcher,
    {
        let (access, accept, protocol_version) = self.into_parts();
        dispatcher.open(access, accept, protocol_version).await
    }
}

/// One authorized MCP request whose identity, operation classification, and
/// exact bounded body remain coupled until dispatch.
pub struct AuthorizedRemoteMcpRequest {
    access: VerifiedRemoteAccess,
    invocation: RemoteMcpInvocation,
    protocol_headers: RemoteMcpProtocolHeaders,
    body: Zeroizing<Vec<u8>>,
}

/// Transport port for handing one fully authorized request to an MCP protocol
/// implementation.
///
/// Implementations receive owned, coupled dispatch inputs. They cannot ask
/// this boundary to authorize one body and dispatch another.
pub trait AuthorizedRemoteMcpDispatcher {
    type Output;
    type Error;
    type DispatchFuture: Future<Output = Result<Self::Output, Self::Error>> + Send;

    fn dispatch(
        &self,
        access: VerifiedRemoteAccess,
        invocation: RemoteMcpInvocation,
        protocol_headers: RemoteMcpProtocolHeaders,
        body: Zeroizing<Vec<u8>>,
    ) -> Self::DispatchFuture;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteMcpDispatchError<DispatchError> {
    Authorization(RemoteMcpHttpRejection),
    Dispatch(DispatchError),
}

impl AuthorizedRemoteMcpRequest {
    #[must_use]
    pub const fn access(&self) -> &VerifiedRemoteAccess {
        &self.access
    }

    #[must_use]
    pub const fn invocation(&self) -> &RemoteMcpInvocation {
        &self.invocation
    }

    #[must_use]
    pub const fn protocol_headers(&self) -> &RemoteMcpProtocolHeaders {
        &self.protocol_headers
    }

    /// Returns only the exact bytes that passed classification and OAuth
    /// authorization. The backing buffer is zeroized when this object drops.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.body.as_slice()
    }

    /// Consumes the authorization proof and transfers its coupled identity,
    /// classified invocation, and exact zeroizing body to the transport
    /// dispatcher.
    ///
    /// Consuming the object prevents an adapter from retaining an
    /// authorization decision while independently replacing its request
    /// buffer before official SDK dispatch.
    #[must_use]
    pub fn into_dispatch_parts(
        self,
    ) -> (
        VerifiedRemoteAccess,
        RemoteMcpInvocation,
        RemoteMcpProtocolHeaders,
        Zeroizing<Vec<u8>>,
    ) {
        (
            self.access,
            self.invocation,
            self.protocol_headers,
            self.body,
        )
    }

    /// Consumes this proof and transfers it to one authorized transport
    /// dispatcher.
    ///
    /// # Errors
    ///
    /// Returns the dispatcher's error without recreating or retaining the
    /// authorization proof.
    pub async fn dispatch_with<Dispatcher>(
        self,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, Dispatcher::Error>
    where
        Dispatcher: AuthorizedRemoteMcpDispatcher,
    {
        let (access, invocation, protocol_headers, body) = self.into_dispatch_parts();
        dispatcher
            .dispatch(access, invocation, protocol_headers, body)
            .await
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonRpcEnvelope {
    jsonrpc: String,
    method: String,
    #[serde(default)]
    id: JsonRpcId,
    #[serde(default)]
    params: Option<serde_json::Value>,
}

#[derive(Default)]
enum JsonRpcId {
    #[default]
    Missing,
    Present(serde_json::Value),
}

impl<'de> Deserialize<'de> for JsonRpcId {
    fn deserialize<Deserializer>(deserializer: Deserializer) -> Result<Self, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        serde_json::Value::deserialize(deserializer).map(Self::Present)
    }
}

/// Classifies one bounded JSON-RPC request before SDK dispatch.
///
/// # Errors
///
/// Returns a forbidden response for empty, oversized, malformed, batched, or
/// unsupported JSON-RPC input.
pub fn classify_remote_mcp_request(
    body: &[u8],
) -> Result<RemoteMcpInvocation, RemoteMcpHttpRejection> {
    if body.is_empty() || body.len() > MAX_REMOTE_MCP_REQUEST_BYTES {
        return Err(RemoteMcpHttpGate::forbidden());
    }
    let envelope: JsonRpcEnvelope =
        serde_json::from_slice(body).map_err(|_| RemoteMcpHttpGate::forbidden())?;
    if envelope.jsonrpc != "2.0"
        || matches!(envelope.id, JsonRpcId::Present(serde_json::Value::Null))
    {
        return Err(RemoteMcpHttpGate::forbidden());
    }
    let tool_name = if envelope.method == "tools/call" {
        envelope
            .params
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .and_then(|params| params.get("name"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    } else {
        None
    };
    RemoteMcpRequestAuthorization::classify(&envelope.method, tool_name.as_deref())
        .ok_or_else(RemoteMcpHttpGate::forbidden)?;
    Ok(RemoteMcpInvocation {
        method: envelope.method,
        tool_name,
    })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RemoteMcpHttpRequest<'request> {
    pub authorization: Option<&'request str>,
    pub host: Option<&'request str>,
    pub origin: Option<&'request str>,
    pub session_id: Option<&'request str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteMcpHttpRejection {
    pub status: u16,
    pub www_authenticate: Option<String>,
    pub retry_after_seconds: Option<u64>,
}

impl IntoResponse for RemoteMcpHttpRejection {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = status.into_response();
        if let Some(challenge) = self.www_authenticate
            && let Ok(value) = HeaderValue::from_str(&challenge)
        {
            response.headers_mut().insert(WWW_AUTHENTICATE, value);
        }
        if let Some(seconds) = self.retry_after_seconds
            && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
        {
            response.headers_mut().insert(RETRY_AFTER, value);
        }
        response
    }
}

/// Converts Axum's parsed header map into the transport-neutral request
/// contract without accepting ambiguous duplicate security headers.
///
/// # Errors
///
/// Returns a fail-closed forbidden response for duplicate or non-text
/// authorization, host, origin, or session headers.
pub fn request_from_axum_headers(
    headers: &HeaderMap,
) -> Result<RemoteMcpHttpRequest<'_>, RemoteMcpHttpRejection> {
    protocol_headers_from_axum(headers)?;
    security_request_from_axum_headers(headers)
}

fn security_request_from_axum_headers(
    headers: &HeaderMap,
) -> Result<RemoteMcpHttpRequest<'_>, RemoteMcpHttpRejection> {
    let authorization = unique_header(headers, &AUTHORIZATION)?;
    let host = unique_header(headers, &HOST)?;
    let origin = unique_header(headers, &ORIGIN)?;
    let session_id = unique_header(headers, &MCP_SESSION_HEADER_NAME)?;
    Ok(RemoteMcpHttpRequest {
        authorization,
        host,
        origin,
        session_id,
    })
}

fn require_event_stream_accept(headers: &HeaderMap) -> Result<(), RemoteMcpHttpRejection> {
    let Some(value) = unique_header(headers, &ACCEPT)? else {
        return Err(RemoteMcpHttpRejection {
            status: 406,
            www_authenticate: None,
            retry_after_seconds: None,
        });
    };
    if value.len() <= 1_024
        && value.split(',').any(|media_range| {
            media_range
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("text/event-stream")
        })
    {
        Ok(())
    } else {
        Err(RemoteMcpHttpRejection {
            status: 406,
            www_authenticate: None,
            retry_after_seconds: None,
        })
    }
}

fn event_stream_headers_from_axum(
    headers: &HeaderMap,
) -> Result<(String, Option<String>), RemoteMcpHttpRejection> {
    require_event_stream_accept(headers)?;
    let accept = unique_header(headers, &ACCEPT)?.unwrap_or_default();
    let protocol_version = unique_header(headers, &MCP_PROTOCOL_VERSION_HEADER_NAME)?;
    if protocol_version.is_some_and(|value| !valid_protocol_version(value)) {
        return Err(RemoteMcpHttpRejection {
            status: 400,
            www_authenticate: None,
            retry_after_seconds: None,
        });
    }
    Ok((accept.to_owned(), protocol_version.map(str::to_owned)))
}

fn protocol_headers_from_axum(
    headers: &HeaderMap,
) -> Result<RemoteMcpProtocolHeaders, RemoteMcpHttpRejection> {
    let content_type = unique_header(headers, &CONTENT_TYPE)?;
    let accept = unique_header(headers, &ACCEPT)?;
    let protocol_version = unique_header(headers, &MCP_PROTOCOL_VERSION_HEADER_NAME)?;
    require_json_content_type(content_type)?;
    require_mcp_accept(accept)?;
    if content_type.is_some_and(|value| value.len() > 256)
        || accept.is_some_and(|value| value.len() > 1_024)
    {
        return Err(RemoteMcpHttpGate::forbidden());
    }
    if protocol_version.is_some_and(|value| !valid_protocol_version(value)) {
        return Err(RemoteMcpHttpRejection {
            status: 400,
            www_authenticate: None,
            retry_after_seconds: None,
        });
    }
    Ok(RemoteMcpProtocolHeaders {
        content_type: content_type.unwrap_or_default().to_owned(),
        accept: accept.unwrap_or_default().to_owned(),
        protocol_version: protocol_version.map(str::to_owned),
    })
}

fn valid_protocol_version(value: &str) -> bool {
    value.len() == 10
        && value.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 => byte == b'-',
            _ => byte.is_ascii_digit(),
        })
}

fn require_json_content_type(value: Option<&str>) -> Result<(), RemoteMcpHttpRejection> {
    let Some(value) = value else {
        return Err(RemoteMcpHttpRejection {
            status: 415,
            www_authenticate: None,
            retry_after_seconds: None,
        });
    };
    let media_type = value.split(';').next().unwrap_or_default().trim();
    if media_type.eq_ignore_ascii_case("application/json") {
        Ok(())
    } else {
        Err(RemoteMcpHttpRejection {
            status: 415,
            www_authenticate: None,
            retry_after_seconds: None,
        })
    }
}

fn require_mcp_accept(value: Option<&str>) -> Result<(), RemoteMcpHttpRejection> {
    let Some(value) = value else {
        return Err(RemoteMcpHttpRejection {
            status: 406,
            www_authenticate: None,
            retry_after_seconds: None,
        });
    };
    let mut accepts_json = false;
    let mut accepts_events = false;
    for media_range in value.split(',') {
        let media_type = media_range.split(';').next().unwrap_or_default().trim();
        accepts_json |= media_type.eq_ignore_ascii_case("application/json");
        accepts_events |= media_type.eq_ignore_ascii_case("text/event-stream");
    }
    if accepts_json && accepts_events {
        Ok(())
    } else {
        Err(RemoteMcpHttpRejection {
            status: 406,
            www_authenticate: None,
            retry_after_seconds: None,
        })
    }
}

fn unique_header<'headers>(
    headers: &'headers HeaderMap,
    name: &HeaderName,
) -> Result<Option<&'headers str>, RemoteMcpHttpRejection> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(RemoteMcpHttpGate::forbidden());
    }
    first
        .map(|value| value.to_str().map_err(|_| RemoteMcpHttpGate::forbidden()))
        .transpose()
}

/// Performs exact-body OAuth authorization for an Axum request before the
/// same bytes are dispatched to the official MCP SDK service.
///
/// # Errors
///
/// Returns an HTTP-ready rejection for malformed or ambiguous headers,
/// malformed JSON-RPC, invalid credentials, untrusted host/origin, or missing
/// operation scope.
pub fn authorize_axum_stateless_body<Verifier>(
    gate: &RemoteMcpHttpGate,
    authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
    headers: &HeaderMap,
    body: &[u8],
    now_epoch_seconds: u64,
) -> Result<AuthorizedRemoteMcpRequest, RemoteMcpHttpRejection>
where
    Verifier: RemoteTokenVerifier,
{
    let protocol_headers = protocol_headers_from_axum(headers)?;
    let mut authorized = gate.authorize_stateless_body(
        authorization,
        request_from_axum_headers(headers)?,
        body,
        now_epoch_seconds,
    )?;
    authorized.protocol_headers = protocol_headers;
    Ok(authorized)
}

/// Owned authorization service suitable for Axum router state.
///
/// It owns the verifier and validated deployment values, then creates the
/// short-lived borrowing authentication objects for each request. This avoids
/// self-referential state while preserving per-request token verification.
pub struct RemoteMcpAxumAuthorization<Verifier> {
    gate: RemoteMcpHttpGate,
    verifier: Verifier,
    issuer: String,
    resource: String,
    trusted_origins: Vec<String>,
}

impl<Verifier> RemoteMcpAxumAuthorization<Verifier>
where
    Verifier: RemoteTokenVerifier,
{
    /// Builds an owned Axum authorization service from one validated remote
    /// MCP deployment profile.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection when the configured session capacity
    /// or derived HTTP gate is invalid.
    pub fn from_config(
        maximum_sessions: usize,
        config: &RemoteMcpConfig,
        verifier: Verifier,
    ) -> Result<Self, RemoteMcpHttpRejection> {
        Ok(Self {
            gate: RemoteMcpHttpGate::from_config(maximum_sessions, config)?,
            verifier,
            issuer: config.issuer().to_owned(),
            resource: config.resource().to_owned(),
            trusted_origins: config.trusted_origins().to_vec(),
        })
    }

    /// Authorizes one stateless Axum request and its exact JSON-RPC bytes.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed HTTP rejection when headers, body,
    /// authentication, origin, host, or operation scope are invalid.
    pub fn authorize_stateless_body(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        now_epoch_seconds: u64,
    ) -> Result<AuthorizedRemoteMcpRequest, RemoteMcpHttpRejection> {
        let authenticator =
            RemoteAccessAuthenticator::new(&self.verifier, &self.issuer, &self.resource);
        let trusted_origins = self
            .trusted_origins
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let authorization = RemoteHttpAuthorization::new(&authenticator, &trusted_origins);
        authorize_axum_stateless_body(&self.gate, &authorization, headers, body, now_epoch_seconds)
    }

    /// Authorizes a stateless Streamable HTTP GET before the SDK opens its
    /// server event stream.
    ///
    /// # Errors
    ///
    /// Returns 406 for invalid event-stream negotiation, or the normal
    /// fail-closed bearer, origin, host, and session rejection.
    pub fn authorize_event_stream(
        &self,
        headers: &HeaderMap,
        now_epoch_seconds: u64,
    ) -> Result<AuthorizedRemoteMcpEventStream, RemoteMcpHttpRejection> {
        let (accept, protocol_version) = event_stream_headers_from_axum(headers)?;
        let request = security_request_from_axum_headers(headers)?;
        let authenticator =
            RemoteAccessAuthenticator::new(&self.verifier, &self.issuer, &self.resource);
        let trusted_origins = self
            .trusted_origins
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let authorization = RemoteHttpAuthorization::new(&authenticator, &trusted_origins);
        let access =
            self.gate
                .authorize_stateless_connection(&authorization, request, now_epoch_seconds)?;
        Ok(AuthorizedRemoteMcpEventStream {
            access,
            accept,
            protocol_version,
        })
    }

    /// Authorizes and opens one stateless server event stream without
    /// exposing an intermediate reusable proof to the HTTP adapter.
    ///
    /// # Errors
    ///
    /// Distinguishes HTTP-ready authentication/authorization rejection from a
    /// downstream event-stream dispatch failure.
    pub async fn authorize_and_dispatch_event_stream<Dispatcher>(
        &self,
        headers: &HeaderMap,
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
    where
        Dispatcher: AuthorizedRemoteMcpEventStreamDispatcher,
    {
        self.authorize_event_stream(headers, now_epoch_seconds)
            .map_err(RemoteMcpDispatchError::Authorization)?
            .dispatch_with(dispatcher)
            .await
            .map_err(RemoteMcpDispatchError::Dispatch)
    }

    /// Authorizes and dispatches one exact stateless request without exposing
    /// an intermediate reusable authorization decision to the HTTP adapter.
    ///
    /// # Errors
    ///
    /// Distinguishes HTTP-ready authentication/authorization rejection from a
    /// downstream protocol-dispatch failure.
    pub async fn authorize_and_dispatch<Dispatcher>(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
    where
        Dispatcher: AuthorizedRemoteMcpDispatcher,
    {
        self.authorize_stateless_body(headers, body, now_epoch_seconds)
            .map_err(RemoteMcpDispatchError::Authorization)?
            .dispatch_with(dispatcher)
            .await
            .map_err(RemoteMcpDispatchError::Dispatch)
    }
}

pub struct RemoteMcpHttpGate {
    sessions: RemoteSessionRegistry,
    resource_metadata_url: String,
    allowed_hosts: Vec<String>,
}

impl RemoteMcpHttpGate {
    /// Builds the gate directly from the validated deployment profile.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection when session capacity is invalid.
    pub fn from_config(
        maximum_sessions: usize,
        config: &RemoteMcpConfig,
    ) -> Result<Self, RemoteMcpHttpRejection> {
        Self::new(
            maximum_sessions,
            config.protected_resource_metadata_url(),
            &[config.resource_authority()],
        )
    }

    /// Creates a bounded remote MCP HTTP gate.
    ///
    /// # Errors
    ///
    /// Rejects zero capacity or a resource metadata URL that is not HTTPS.
    pub fn new(
        maximum_sessions: usize,
        resource_metadata_url: impl Into<String>,
        allowed_hosts: &[&str],
    ) -> Result<Self, RemoteMcpHttpRejection> {
        let resource_metadata_url = resource_metadata_url.into();
        if !resource_metadata_url.starts_with("https://")
            || resource_metadata_url.bytes().any(|byte| {
                byte.is_ascii_whitespace()
                    || byte.is_ascii_control()
                    || matches!(byte, b'"' | b'\\')
            })
        {
            return Err(Self::forbidden());
        }
        if allowed_hosts.is_empty()
            || allowed_hosts.len() > 32
            || allowed_hosts
                .iter()
                .any(|host| !Self::valid_authority(host))
        {
            return Err(Self::forbidden());
        }
        let mut allowed_hosts = allowed_hosts
            .iter()
            .map(|host| (*host).to_owned())
            .collect::<Vec<_>>();
        allowed_hosts.sort();
        allowed_hosts.dedup();
        let sessions =
            RemoteSessionRegistry::new(maximum_sessions).map_err(|_| Self::capacity_exceeded())?;
        Ok(Self {
            sessions,
            resource_metadata_url,
            allowed_hosts,
        })
    }

    /// Authorizes an initialize request and binds the supplied session ID.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection for invalid headers, authorization,
    /// duplicate sessions, or capacity exhaustion.
    pub fn establish<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        self.require_allowed_host(request.host)?;
        let session_id = Self::session_id(request.session_id)?;
        self.sessions
            .authorize_and_establish_for_http(
                authorization,
                session_id,
                request.authorization,
                request.origin,
                now_epoch_seconds,
            )
            .map_err(|error| self.rejection(error))
    }

    /// Reauthenticates and authorizes one established MCP request before the
    /// official SDK receives its JSON-RPC body.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection for missing or invalid session,
    /// authentication, origin, method, tool, scope, or tenant binding.
    pub fn authorize<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        method: &str,
        tool_name: Option<&str>,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        self.require_allowed_host(request.host)?;
        let session_id = Self::session_id(request.session_id)?;
        self.sessions
            .authorize_request_for_http(
                authorization,
                &session_id,
                request.authorization,
                request.origin,
                method,
                tool_name,
                now_epoch_seconds,
            )
            .map_err(|error| self.rejection(error))
    }

    /// Authorizes one stateless MCP request without accepting or creating a
    /// transport session.
    ///
    /// This is the authorization boundary for modern Streamable HTTP requests
    /// whose protocol version does not use `Mcp-Session-Id`. The bearer token
    /// is still verified on every request, and method/tool classification,
    /// host, origin, and narrow OAuth scope checks remain mandatory.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection for invalid credentials, host, origin,
    /// method/tool classification, or OAuth scope.
    pub fn authorize_stateless<Verifier>(
        &self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        method: &str,
        tool_name: Option<&str>,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        self.require_allowed_host(request.host)?;
        if request.session_id.is_some() {
            return Err(Self::forbidden());
        }
        match RemoteMcpRequestAuthorization::classify(method, tool_name)
            .ok_or_else(Self::forbidden)?
        {
            RemoteMcpRequestAuthorization::Connection => authorization
                .authorize_connection_for_http(
                    request.authorization,
                    request.origin,
                    now_epoch_seconds,
                )
                .map_err(|error| self.authorization_rejection(error)),
            RemoteMcpRequestAuthorization::Tool(operation) => authorization
                .authorize_tool_for_http(
                    request.authorization,
                    request.origin,
                    operation.tool_name(),
                    now_epoch_seconds,
                )
                .map_err(|error| self.authorization_rejection(error)),
        }
    }

    fn authorize_stateless_connection<Verifier>(
        &self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        self.require_allowed_host(request.host)?;
        if request.session_id.is_some() {
            return Err(Self::forbidden());
        }
        authorization
            .authorize_connection_for_http(request.authorization, request.origin, now_epoch_seconds)
            .map_err(|error| self.authorization_rejection(error))
    }

    /// Classifies and authorizes one stateless JSON-RPC body as a single
    /// operation so callers cannot authorize metadata that differs from the
    /// bytes later dispatched to the protocol SDK.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection for invalid JSON-RPC, credentials,
    /// host, origin, method, tool, or OAuth scope.
    pub fn authorize_stateless_body<Verifier>(
        &self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        body: &[u8],
        now_epoch_seconds: u64,
    ) -> Result<AuthorizedRemoteMcpRequest, RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        let invocation = classify_remote_mcp_request(body)?;
        let access = self.authorize_stateless(
            authorization,
            request,
            invocation.method(),
            invocation.tool_name(),
            now_epoch_seconds,
        )?;
        Ok(AuthorizedRemoteMcpRequest {
            access,
            invocation,
            protocol_headers: RemoteMcpProtocolHeaders::transport_neutral(),
            body: Zeroizing::new(body.to_vec()),
        })
    }

    /// Reauthenticates and removes one established MCP session.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection for missing or invalid session,
    /// authentication, origin, or tenant binding.
    pub fn terminate<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        now_epoch_seconds: u64,
    ) -> Result<(), RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        self.require_allowed_host(request.host)?;
        let session_id = Self::session_id(request.session_id)?;
        self.sessions
            .authorize_and_terminate_for_http(
                authorization,
                &session_id,
                request.authorization,
                request.origin,
                now_epoch_seconds,
            )
            .map_err(|error| self.rejection(error))
    }

    fn session_id(value: Option<&str>) -> Result<RemoteSessionId, RemoteMcpHttpRejection> {
        value
            .ok_or_else(Self::forbidden)
            .and_then(|value| RemoteSessionId::new(value).map_err(|_| Self::forbidden()))
    }

    fn require_allowed_host(&self, host: Option<&str>) -> Result<(), RemoteMcpHttpRejection> {
        let host = host.ok_or_else(Self::forbidden)?;
        if self.allowed_hosts.iter().any(|allowed| allowed == host) {
            Ok(())
        } else {
            Err(Self::forbidden())
        }
    }

    fn valid_authority(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 255
            && !value.bytes().any(|byte| {
                byte.is_ascii_whitespace()
                    || byte.is_ascii_control()
                    || matches!(byte, b'/' | b'\\' | b'"' | b'\'' | b'@')
            })
    }

    fn rejection(&self, error: RemoteSessionHttpError) -> RemoteMcpHttpRejection {
        match error {
            RemoteSessionHttpError::Unauthorized => RemoteMcpHttpRejection {
                status: 401,
                www_authenticate: Some(format!(
                    "Bearer resource_metadata=\"{}\"",
                    self.resource_metadata_url
                )),
                retry_after_seconds: None,
            },
            RemoteSessionHttpError::Forbidden => Self::forbidden(),
            RemoteSessionHttpError::Conflict => RemoteMcpHttpRejection {
                status: 409,
                www_authenticate: None,
                retry_after_seconds: None,
            },
            RemoteSessionHttpError::CapacityExceeded => Self::capacity_exceeded(),
        }
    }

    fn authorization_rejection(
        &self,
        error: RemoteHttpAuthorizationError,
    ) -> RemoteMcpHttpRejection {
        match error {
            RemoteHttpAuthorizationError::Unauthorized => {
                self.rejection(RemoteSessionHttpError::Unauthorized)
            }
            RemoteHttpAuthorizationError::Forbidden => Self::forbidden(),
        }
    }

    fn forbidden() -> RemoteMcpHttpRejection {
        RemoteMcpHttpRejection {
            status: 403,
            www_authenticate: None,
            retry_after_seconds: None,
        }
    }

    fn capacity_exceeded() -> RemoteMcpHttpRejection {
        RemoteMcpHttpRejection {
            status: 503,
            www_authenticate: None,
            retry_after_seconds: Some(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use axum::{
        Router,
        body::{Body, Bytes, to_bytes},
        extract::State,
        http::{
            HeaderMap, HeaderValue, Request,
            header::{
                ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST, ORIGIN, RETRY_AFTER, WWW_AUTHENTICATE,
            },
        },
        response::IntoResponse,
        routing::{get, post},
    };
    use rembrane_application::{
        RemoteAccessAuthenticator, RemoteHttpAuthorization, RemoteTokenVerificationError,
        RemoteTokenVerifier,
    };
    use rembrane_config::{RemoteMcpConfig, SecretReference};
    use rembrane_contracts::{RemoteAccessScope, RemoteTokenClaims};
    use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};
    use tower::ServiceExt;

    use super::{
        AuthorizedRemoteMcpDispatcher, AuthorizedRemoteMcpEventStreamDispatcher,
        MCP_PROTOCOL_VERSION_HEADER_NAME, MCP_SESSION_HEADER_NAME, RemoteMcpAxumAuthorization,
        RemoteMcpDispatchError, RemoteMcpHttpGate, RemoteMcpHttpRejection, RemoteMcpHttpRequest,
        RemoteMcpInvocation, authorize_axum_stateless_body, classify_remote_mcp_request,
        request_from_axum_headers,
    };

    struct Verifier;

    struct RecordingDispatcher;
    struct RecordingEventStreamDispatcher;

    impl AuthorizedRemoteMcpEventStreamDispatcher for RecordingEventStreamDispatcher {
        type Output = (String, String, Option<String>);
        type Error = std::convert::Infallible;
        type DispatchFuture = std::future::Ready<Result<Self::Output, Self::Error>>;

        fn open(
            &self,
            access: rembrane_contracts::VerifiedRemoteAccess,
            accept: String,
            protocol_version: Option<String>,
        ) -> Self::DispatchFuture {
            std::future::ready(Ok((
                access.workspace_id().to_string(),
                accept,
                protocol_version,
            )))
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct RecordedDispatch {
        workspace: String,
        method: String,
        tool_name: Option<String>,
        content_type: String,
        accept: String,
        protocol_version: Option<String>,
        body: Vec<u8>,
    }

    impl AuthorizedRemoteMcpDispatcher for RecordingDispatcher {
        type Output = RecordedDispatch;
        type Error = std::convert::Infallible;
        type DispatchFuture = std::future::Ready<Result<Self::Output, Self::Error>>;

        fn dispatch(
            &self,
            access: rembrane_contracts::VerifiedRemoteAccess,
            invocation: RemoteMcpInvocation,
            protocol_headers: super::RemoteMcpProtocolHeaders,
            body: zeroize::Zeroizing<Vec<u8>>,
        ) -> Self::DispatchFuture {
            std::future::ready(Ok(RecordedDispatch {
                workspace: access.workspace_id().to_string(),
                method: invocation.method().to_owned(),
                tool_name: invocation.tool_name().map(str::to_owned),
                content_type: protocol_headers.content_type().to_owned(),
                accept: protocol_headers.accept().to_owned(),
                protocol_version: protocol_headers.protocol_version().map(str::to_owned),
                body: body.as_slice().to_vec(),
            }))
        }
    }

    impl RemoteTokenVerifier for Verifier {
        fn verify(&self, token: &str) -> Result<RemoteTokenClaims, RemoteTokenVerificationError> {
            let workspace = match token {
                "workspace-one" => "workspace_01",
                "workspace-two" => "workspace_02",
                _ => return Err(RemoteTokenVerificationError),
            };
            Ok(RemoteTokenClaims {
                issuer: "https://identity.example.test".to_owned(),
                audience: vec!["https://memory.example.test/mcp".to_owned()],
                subject_id: PrincipalId::new("principal_01"),
                client_id: ClientId::new("client_01"),
                workspace_id: WorkspaceId::new(workspace),
                scopes: BTreeSet::from([
                    RemoteAccessScope::ContextRead,
                    RemoteAccessScope::MemoryWrite,
                ]),
                expires_at_epoch_seconds: 2_000,
                not_before_epoch_seconds: None,
            })
        }
    }

    fn request<'a>(token: &'a str, session: &'a str) -> RemoteMcpHttpRequest<'a> {
        RemoteMcpHttpRequest {
            authorization: Some(token),
            host: Some("memory.example.test"),
            origin: Some("https://agent.example.test"),
            session_id: Some(session),
        }
    }

    #[test]
    fn gate_maps_authentication_capacity_and_cross_tenant_outcomes() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let origins = ["https://agent.example.test"];
        let authorization = RemoteHttpAuthorization::new(&authenticator, &origins);
        let mut gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let session = "session_0123456789abcdef";

        let unauthorized = gate
            .establish(&authorization, request("Bearer invalid", session), 1_000)
            .expect_err("invalid token must fail");
        assert_eq!(unauthorized.status, 401);
        assert!(unauthorized.www_authenticate.is_some());

        gate.establish(
            &authorization,
            request("Bearer workspace-one", session),
            1_000,
        )
        .expect("valid initialize should establish");

        let replay = gate
            .authorize(
                &authorization,
                request("Bearer workspace-two", session),
                "tools/list",
                None,
                1_100,
            )
            .expect_err("cross-tenant replay must fail");
        assert_eq!(replay.status, 403);
        assert!(replay.www_authenticate.is_none());

        let capacity = gate
            .establish(
                &authorization,
                request("Bearer workspace-one", "session_fedcba9876543210"),
                1_100,
            )
            .expect_err("second session must exceed capacity");
        assert_eq!(capacity.status, 503);
        assert_eq!(capacity.retry_after_seconds, Some(1));

        gate.terminate(
            &authorization,
            request("Bearer workspace-one", session),
            1_200,
        )
        .expect("valid delete should terminate");
    }

    #[test]
    fn gate_rejects_unsafe_challenge_and_session_values() {
        assert!(
            RemoteMcpHttpGate::new(
                1,
                "http://memory.example.test/metadata",
                &["memory.example.test"],
            )
            .is_err()
        );
        assert!(
            RemoteMcpHttpGate::new(
                1,
                "https://memory.example.test/metadata\" injected",
                &["memory.example.test"],
            )
            .is_err()
        );
        assert!(RemoteMcpHttpGate::new(1, "https://memory.example.test/metadata", &[]).is_err());
        assert!(
            RemoteMcpHttpGate::new(
                1,
                "https://memory.example.test/metadata",
                &["memory.example.test/path"],
            )
            .is_err()
        );

        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let authorization = RemoteHttpAuthorization::new(&authenticator, &[]);
        let mut gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/metadata",
            &["memory.example.test"],
        )
        .expect("valid gate");
        let rejection = gate
            .establish(
                &authorization,
                RemoteMcpHttpRequest {
                    authorization: Some("Bearer workspace-one"),
                    host: Some("memory.example.test"),
                    origin: None,
                    session_id: Some("invalid session"),
                },
                1_000,
            )
            .expect_err("unsafe session header must fail");
        assert_eq!(rejection.status, 403);

        let hostile_host = gate
            .establish(
                &authorization,
                RemoteMcpHttpRequest {
                    authorization: Some("Bearer workspace-one"),
                    host: Some("attacker.example.test"),
                    origin: None,
                    session_id: Some("session_0123456789abcdef"),
                },
                1_000,
            )
            .expect_err("untrusted host must fail before session creation");
        assert_eq!(hostile_host.status, 403);
    }

    #[test]
    fn gate_derives_host_and_challenge_from_one_validated_resource() {
        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("OAUTH_SECRET").expect("reference should be valid"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("remote profile should be valid");
        assert!(RemoteMcpHttpGate::from_config(10, &config).is_ok());
    }

    #[test]
    fn stateless_gate_reauthenticates_without_transport_sessions() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let origins = ["https://agent.example.test"];
        let authorization = RemoteHttpAuthorization::new(&authenticator, &origins);
        let gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let request = |token| RemoteMcpHttpRequest {
            authorization: Some(token),
            host: Some("memory.example.test"),
            origin: Some("https://agent.example.test"),
            session_id: None,
        };

        let access = gate
            .authorize_stateless(
                &authorization,
                request("Bearer workspace-one"),
                "tools/call",
                Some("rembrane_resolve_context"),
                1_000,
            )
            .expect("scoped stateless request should authenticate");
        assert_eq!(access.workspace_id().as_str(), "workspace_01");

        let unauthorized = gate
            .authorize_stateless(
                &authorization,
                request("Bearer invalid"),
                "tools/list",
                None,
                1_000,
            )
            .expect_err("invalid token must be challenged");
        assert_eq!(unauthorized.status, 401);
        assert!(unauthorized.www_authenticate.is_some());

        let insufficient_scope = gate
            .authorize_stateless(
                &authorization,
                request("Bearer workspace-one"),
                "tools/call",
                Some("rembrane_create_trip"),
                1_000,
            )
            .expect_err("missing tool scope must be forbidden");
        assert_eq!(insufficient_scope.status, 403);

        let stateful_header = gate
            .authorize_stateless(
                &authorization,
                RemoteMcpHttpRequest {
                    session_id: Some("session_0123456789abcdef"),
                    ..request("Bearer workspace-one")
                },
                "tools/list",
                None,
                1_000,
            )
            .expect_err("stateless boundary must reject session ambiguity");
        assert_eq!(stateful_header.status, 403);
    }

    #[test]
    fn json_rpc_classifier_fails_closed_before_sdk_dispatch() {
        let invocation = classify_remote_mcp_request(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rembrane_resolve_context","arguments":{}}}"#,
        )
        .expect("known tool request should classify");
        assert_eq!(invocation.method(), "tools/call");
        assert_eq!(invocation.tool_name(), Some("rembrane_resolve_context"));

        for body in [
            br"[]".as_slice(),
            br#"{"jsonrpc":"1.0","id":1,"method":"tools/list"}"#,
            br#"{"jsonrpc":"2.0","id":null,"method":"tools/list"}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"future_tool"}}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"resources/list"}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","extra":true}"#,
        ] {
            assert!(
                classify_remote_mcp_request(body).is_err(),
                "unsupported body must fail closed"
            );
        }
    }

    #[tokio::test]
    async fn stateless_body_authorization_cannot_drift_from_dispatched_bytes() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let authorization = RemoteHttpAuthorization::new(&authenticator, &[]);
        let gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let request = RemoteMcpHttpRequest {
            authorization: Some("Bearer workspace-one"),
            host: Some("memory.example.test"),
            origin: None,
            session_id: None,
        };
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rembrane_resolve_context","arguments":{}}}"#;
        let authorized = gate
            .authorize_stateless_body(&authorization, request, body, 1_000)
            .expect("body and its exact scope should authorize together");
        assert_eq!(authorized.access().workspace_id().as_str(), "workspace_01");
        assert_eq!(
            authorized.invocation().tool_name(),
            Some("rembrane_resolve_context")
        );
        assert_eq!(authorized.body(), body);
        let dispatched = authorized
            .dispatch_with(&RecordingDispatcher)
            .await
            .expect("authorized dispatch cannot fail");
        assert_eq!(dispatched.workspace, "workspace_01");
        assert_eq!(dispatched.method, "tools/call");
        assert_eq!(
            dispatched.tool_name.as_deref(),
            Some("rembrane_resolve_context")
        );
        assert_eq!(dispatched.content_type, "application/json");
        assert_eq!(dispatched.accept, "application/json, text/event-stream");
        assert_eq!(dispatched.protocol_version, None);
        assert_eq!(dispatched.body, body);

        let travel_body = br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"rembrane_create_trip","arguments":{}}}"#;
        assert_eq!(
            gate.authorize_stateless_body(&authorization, request, travel_body, 1_000)
                .err()
                .expect("body requiring an absent scope must fail")
                .status,
            403
        );
    }

    #[test]
    fn axum_boundary_rejects_duplicate_security_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.append(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        headers.append(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-two"),
        );
        assert!(
            request_from_axum_headers(&headers).is_err(),
            "multiple credentials must never be collapsed by the HTTP adapter"
        );

        headers.remove(AUTHORIZATION);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        headers.append(HOST, HeaderValue::from_static("attacker.example.test"));
        assert!(
            request_from_axum_headers(&headers).is_err(),
            "multiple host authorities must fail closed"
        );

        headers = HeaderMap::new();
        for (name, first, second) in [
            (&CONTENT_TYPE, "application/json", "text/plain"),
            (&ACCEPT, "application/json", "text/event-stream"),
            (
                &MCP_PROTOCOL_VERSION_HEADER_NAME,
                "2025-03-26",
                "2026-07-28",
            ),
        ] {
            headers.insert(name, HeaderValue::from_str(first).expect("valid header"));
            headers.append(name, HeaderValue::from_str(second).expect("valid header"));
            assert!(
                request_from_axum_headers(&headers).is_err(),
                "ambiguous protocol header must fail closed"
            );
            headers.clear();
        }

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        assert_eq!(
            request_from_axum_headers(&headers)
                .expect_err("non-JSON requests must fail")
                .status,
            415
        );

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        assert_eq!(
            request_from_axum_headers(&headers)
                .expect_err("MCP clients must accept event streams")
                .status,
            406
        );

        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            MCP_PROTOCOL_VERSION_HEADER_NAME,
            HeaderValue::from_static("future-version"),
        );
        assert_eq!(
            request_from_axum_headers(&headers)
                .expect_err("arbitrary protocol version text must fail")
                .status,
            400
        );
    }

    #[test]
    fn axum_boundary_authorizes_the_exact_body_and_maps_rejections() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let origins = ["https://agent.example.test"];
        let authorization = RemoteHttpAuthorization::new(&authenticator, &origins);
        let gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            MCP_PROTOCOL_VERSION_HEADER_NAME,
            HeaderValue::from_static("2025-03-26"),
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        headers.insert(
            ORIGIN,
            HeaderValue::from_static("https://agent.example.test"),
        );
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rembrane_resolve_context","arguments":{}}}"#;

        let authorized =
            authorize_axum_stateless_body(&gate, &authorization, &headers, body, 1_000)
                .expect("Axum request should authorize before dispatch");
        assert_eq!(authorized.access().workspace_id().as_str(), "workspace_01");
        assert_eq!(
            authorized.invocation().tool_name(),
            Some("rembrane_resolve_context")
        );
        assert_eq!(authorized.body(), body);
        let (access, invocation, protocol_headers, dispatched_body) =
            authorized.into_dispatch_parts();
        assert_eq!(access.workspace_id().as_str(), "workspace_01");
        assert_eq!(invocation.method(), "tools/call");
        assert_eq!(invocation.tool_name(), Some("rembrane_resolve_context"));
        assert_eq!(protocol_headers.content_type(), "application/json");
        assert_eq!(
            protocol_headers.accept(),
            "application/json, text/event-stream"
        );
        assert_eq!(protocol_headers.protocol_version(), Some("2025-03-26"));
        assert_eq!(dispatched_body.as_slice(), body);

        headers.insert(
            MCP_SESSION_HEADER_NAME,
            HeaderValue::from_static("session_0123456789abcdef"),
        );
        let rejection = authorize_axum_stateless_body(&gate, &authorization, &headers, body, 1_000)
            .err()
            .expect("stateless endpoint must reject session ambiguity");
        let response = rejection.into_response();
        assert_eq!(response.status(), 403);
        assert!(!response.headers().contains_key(WWW_AUTHENTICATE));

        headers.remove(MCP_SESSION_HEADER_NAME);
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer invalid"));
        let rejection = authorize_axum_stateless_body(&gate, &authorization, &headers, body, 1_000)
            .err()
            .expect("invalid credential must produce a bearer challenge");
        let response = rejection.into_response();
        assert_eq!(response.status(), 401);
        assert!(response.headers().contains_key(WWW_AUTHENTICATE));
        assert!(!response.headers().contains_key(RETRY_AFTER));
    }

    async fn authorized_workspace(
        State(authorization): State<Arc<RemoteMcpAxumAuthorization<Verifier>>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<String, RemoteMcpHttpRejection> {
        match authorization
            .authorize_and_dispatch(&headers, &body, 1_000, &RecordingDispatcher)
            .await
        {
            Ok(dispatched) => Ok(dispatched.workspace),
            Err(RemoteMcpDispatchError::Authorization(rejection)) => Err(rejection),
            Err(RemoteMcpDispatchError::Dispatch(infallible)) => match infallible {},
        }
    }

    async fn authorized_event_workspace(
        State(authorization): State<Arc<RemoteMcpAxumAuthorization<Verifier>>>,
        headers: HeaderMap,
    ) -> Result<String, RemoteMcpHttpRejection> {
        match authorization
            .authorize_and_dispatch_event_stream(&headers, 1_000, &RecordingEventStreamDispatcher)
            .await
        {
            Ok((workspace, _, _)) => Ok(workspace),
            Err(RemoteMcpDispatchError::Authorization(rejection)) => Err(rejection),
            Err(RemoteMcpDispatchError::Dispatch(infallible)) => match infallible {},
        }
    }

    #[tokio::test]
    async fn owned_axum_service_preserves_dispatched_tenant_identity() {
        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("OAUTH_SECRET").expect("reference should be valid"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("remote profile should be valid");
        let authorization = Arc::new(
            RemoteMcpAxumAuthorization::from_config(16, &config, Verifier)
                .expect("owned authorization service should initialize"),
        );
        let app = Router::new()
            .route("/mcp", post(authorized_workspace))
            .with_state(authorization);
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rembrane_resolve_context","arguments":{}}}"#;

        for (token, expected_workspace) in [
            ("workspace-one", "workspace_01"),
            ("workspace-two", "workspace_02"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/mcp")
                        .header(HOST, "memory.example.test")
                        .header(CONTENT_TYPE, "application/json")
                        .header(ACCEPT, "application/json, text/event-stream")
                        .header(AUTHORIZATION, format!("Bearer {token}"))
                        .header(ORIGIN, "https://agent.example.test")
                        .body(Body::from(body))
                        .expect("request should build"),
                )
                .await
                .expect("in-memory router should respond");
            assert_eq!(response.status(), 200);
            let response_body = to_bytes(response.into_body(), 128)
                .await
                .expect("bounded response should read");
            assert_eq!(response_body.as_ref(), expected_workspace.as_bytes());
        }

        let denied = app
            .oneshot(
                Request::post("/mcp")
                    .header(HOST, "memory.example.test")
                    .header(CONTENT_TYPE, "application/json")
                    .header(ACCEPT, "application/json, text/event-stream")
                    .header(AUTHORIZATION, "Bearer workspace-one")
                    .header(ORIGIN, "https://attacker.example.test")
                    .body(Body::from(body))
                    .expect("request should build"),
            )
            .await
            .expect("in-memory router should respond");
        assert_eq!(denied.status(), 403);
    }

    #[tokio::test]
    async fn concurrent_event_stream_routes_preserve_tenant_identity() {
        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("OAUTH_SECRET").expect("reference should be valid"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("remote profile should be valid");
        let authorization = Arc::new(
            RemoteMcpAxumAuthorization::from_config(16, &config, Verifier)
                .expect("owned authorization service should initialize"),
        );
        let app = Router::new()
            .route("/mcp", get(authorized_event_workspace))
            .with_state(authorization);
        let request = |token: &'static str, origin: &'static str| {
            Request::get("/mcp")
                .header(HOST, "memory.example.test")
                .header(ACCEPT, "text/event-stream")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header(ORIGIN, origin)
                .header(MCP_PROTOCOL_VERSION_HEADER_NAME, "2025-03-26")
                .body(Body::empty())
                .expect("request should build")
        };

        let workspace_one = app
            .clone()
            .oneshot(request("workspace-one", "https://agent.example.test"));
        let workspace_two = app
            .clone()
            .oneshot(request("workspace-two", "https://agent.example.test"));
        let denied = app.oneshot(request("workspace-one", "https://attacker.example.test"));
        let (workspace_one, workspace_two, denied) =
            tokio::join!(workspace_one, workspace_two, denied);

        let workspace_one = workspace_one.expect("first stream route should respond");
        assert_eq!(workspace_one.status(), 200);
        assert_eq!(
            to_bytes(workspace_one.into_body(), 128)
                .await
                .expect("first response should remain bounded"),
            "workspace_01"
        );

        let workspace_two = workspace_two.expect("second stream route should respond");
        assert_eq!(workspace_two.status(), 200);
        assert_eq!(
            to_bytes(workspace_two.into_body(), 128)
                .await
                .expect("second response should remain bounded"),
            "workspace_02"
        );

        assert_eq!(
            denied.expect("denied stream route should respond").status(),
            403
        );
    }

    #[tokio::test]
    async fn owned_service_authorizes_and_dispatches_as_one_operation() {
        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("OAUTH_SECRET").expect("reference should be valid"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("remote profile should be valid");
        let authorization = RemoteMcpAxumAuthorization::from_config(16, &config, Verifier)
            .expect("owned authorization service should initialize");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-two"),
        );
        headers.insert(
            ORIGIN,
            HeaderValue::from_static("https://agent.example.test"),
        );
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rembrane_resolve_context","arguments":{}}}"#;

        let dispatched = authorization
            .authorize_and_dispatch(&headers, body, 1_000, &RecordingDispatcher)
            .await
            .expect("authorized request should dispatch");
        assert_eq!(dispatched.workspace, "workspace_02");
        assert_eq!(dispatched.content_type, "application/json");
        assert_eq!(dispatched.accept, "application/json, text/event-stream");
        assert_eq!(dispatched.body, body);

        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer invalid"));
        let error = authorization
            .authorize_and_dispatch(&headers, body, 1_000, &RecordingDispatcher)
            .await
            .expect_err("invalid token must never reach dispatch");
        assert!(matches!(
            error,
            RemoteMcpDispatchError::Authorization(RemoteMcpHttpRejection { status: 401, .. })
        ));
    }

    #[tokio::test]
    async fn owned_service_authorizes_stateless_event_stream_gets() {
        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("OAUTH_SECRET").expect("reference should be valid"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("remote profile should be valid");
        let authorization = RemoteMcpAxumAuthorization::from_config(16, &config, Verifier)
            .expect("owned authorization service should initialize");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        headers.insert(
            ORIGIN,
            HeaderValue::from_static("https://agent.example.test"),
        );
        headers.insert(ACCEPT, HeaderValue::from_static("text/event-stream"));
        headers.insert(
            MCP_PROTOCOL_VERSION_HEADER_NAME,
            HeaderValue::from_static("2025-03-26"),
        );

        let dispatched = authorization
            .authorize_and_dispatch_event_stream(&headers, 1_000, &RecordingEventStreamDispatcher)
            .await
            .expect("authorized stream dispatch cannot fail");
        assert_eq!(dispatched.0, "workspace_01");
        assert_eq!(dispatched.1, "text/event-stream");
        assert_eq!(dispatched.2.as_deref(), Some("2025-03-26"));

        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        assert!(matches!(
            authorization
                .authorize_and_dispatch_event_stream(
                    &headers,
                    1_000,
                    &RecordingEventStreamDispatcher
                )
                .await
                .expect_err("GET must negotiate event-stream"),
            RemoteMcpDispatchError::Authorization(RemoteMcpHttpRejection { status: 406, .. })
        ));

        headers.insert(ACCEPT, HeaderValue::from_static("text/event-stream"));
        headers.insert(
            MCP_SESSION_HEADER_NAME,
            HeaderValue::from_static("session_0123456789abcdef"),
        );
        assert_eq!(
            authorization
                .authorize_event_stream(&headers, 1_000)
                .expect_err("stateless GET must reject legacy session headers")
                .status,
            403
        );

        headers.remove(MCP_SESSION_HEADER_NAME);
        headers.insert(
            MCP_PROTOCOL_VERSION_HEADER_NAME,
            HeaderValue::from_static("future-version"),
        );
        assert_eq!(
            authorization
                .authorize_event_stream(&headers, 1_000)
                .expect_err("arbitrary GET protocol versions must fail")
                .status,
            400
        );
    }
}

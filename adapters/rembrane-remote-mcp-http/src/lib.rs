//! HTTP-facing authorization gate for remote MCP server transports.
//!
//! This adapter performs only the minimum bounded JSON-RPC classification
//! needed for authorization. The official MCP SDK remains responsible for
//! protocol execution, while this gate ensures every accepted request has
//! already passed bearer, origin, method/tool, session, and tenant checks.

use axum::{
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode,
        header::{AUTHORIZATION, HOST, ORIGIN, RETRY_AFTER, WWW_AUTHENTICATE},
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

/// One authorized MCP request whose identity, operation classification, and
/// exact bounded body remain coupled until dispatch.
pub struct AuthorizedRemoteMcpRequest {
    access: VerifiedRemoteAccess,
    invocation: RemoteMcpInvocation,
    body: Zeroizing<Vec<u8>>,
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
        Zeroizing<Vec<u8>>,
    ) {
        (self.access, self.invocation, self.body)
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
    Ok(RemoteMcpHttpRequest {
        authorization: unique_header(headers, &AUTHORIZATION)?,
        host: unique_header(headers, &HOST)?,
        origin: unique_header(headers, &ORIGIN)?,
        session_id: unique_header(headers, &MCP_SESSION_HEADER_NAME)?,
    })
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
    gate.authorize_stateless_body(
        authorization,
        request_from_axum_headers(headers)?,
        body,
        now_epoch_seconds,
    )
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
            header::{AUTHORIZATION, HOST, ORIGIN, RETRY_AFTER, WWW_AUTHENTICATE},
        },
        response::IntoResponse,
        routing::post,
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
        MCP_SESSION_HEADER_NAME, RemoteMcpAxumAuthorization, RemoteMcpHttpGate,
        RemoteMcpHttpRejection, RemoteMcpHttpRequest, authorize_axum_stateless_body,
        classify_remote_mcp_request, request_from_axum_headers,
    };

    struct Verifier;

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

    #[test]
    fn stateless_body_authorization_cannot_drift_from_dispatched_bytes() {
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
        let (access, invocation, dispatched_body) = authorized.into_dispatch_parts();
        assert_eq!(access.workspace_id().as_str(), "workspace_01");
        assert_eq!(invocation.method(), "tools/call");
        assert_eq!(invocation.tool_name(), Some("rembrane_resolve_context"));
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
        authorization
            .authorize_stateless_body(&headers, &body, 1_000)
            .map(|authorized| authorized.access().workspace_id().to_string())
    }

    #[tokio::test]
    async fn owned_axum_service_preserves_verified_tenant_identity() {
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
                    .header(AUTHORIZATION, "Bearer workspace-one")
                    .header(ORIGIN, "https://attacker.example.test")
                    .body(Body::from(body))
                    .expect("request should build"),
            )
            .await
            .expect("in-memory router should respond");
        assert_eq!(denied.status(), 403);
    }
}

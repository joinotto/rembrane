use std::error::Error;
use std::fmt::{Display, Formatter};

use rembrane_contracts::{
    RemoteAccessScope, RemoteMcpOperation, RemoteTokenClaims, VerifiedRemoteAccess,
};

use crate::ApplicationError;

pub const MAX_REMOTE_BEARER_TOKEN_BYTES: usize = 8_192;

pub trait RemoteTokenVerifier {
    /// Verifies token integrity and returns trusted decoded claims.
    ///
    /// Implementations must validate the token signature or perform
    /// authenticated introspection. They must not return unverified claims.
    ///
    /// # Errors
    ///
    /// Returns an opaque error for every invalid, expired, revoked, malformed,
    /// or unverifiable token.
    fn verify(&self, bearer_token: &str)
    -> Result<RemoteTokenClaims, RemoteTokenVerificationError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteTokenVerificationError;

impl Display for RemoteTokenVerificationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("remote access token could not be verified")
    }
}

impl Error for RemoteTokenVerificationError {}

pub struct RemoteAccessAuthenticator<'verifier, Verifier> {
    verifier: &'verifier Verifier,
    expected_issuer: &'verifier str,
    expected_resource: &'verifier str,
}

impl<'verifier, Verifier> RemoteAccessAuthenticator<'verifier, Verifier>
where
    Verifier: RemoteTokenVerifier,
{
    #[must_use]
    pub const fn new(
        verifier: &'verifier Verifier,
        expected_issuer: &'verifier str,
        expected_resource: &'verifier str,
    ) -> Self {
        Self {
            verifier,
            expected_issuer,
            expected_resource,
        }
    }

    /// Authenticates a bearer token and validates the authorization ceiling
    /// required by one remote MCP operation.
    ///
    /// # Errors
    ///
    /// Returns `AccessDenied` without exposing whether token verification,
    /// issuer, audience, time, identity, workspace, or scope validation failed.
    pub fn authenticate(
        &self,
        bearer_token: &str,
        now_epoch_seconds: u64,
        required_scope: RemoteAccessScope,
    ) -> Result<VerifiedRemoteAccess, ApplicationError> {
        if bearer_token.is_empty() {
            return Err(ApplicationError::AccessDenied);
        }
        self.verifier
            .verify(bearer_token)
            .map_err(|_| ApplicationError::AccessDenied)?
            .validate(
                self.expected_issuer,
                self.expected_resource,
                now_epoch_seconds,
                required_scope,
            )
            .map_err(|_| ApplicationError::AccessDenied)
    }

    /// Authenticates a non-tool MCP protocol request.
    ///
    /// # Errors
    ///
    /// Returns `AccessDenied` for an empty, unverifiable, invalid, expired, or
    /// scope-free token.
    pub fn authenticate_connection(
        &self,
        bearer_token: &str,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, ApplicationError> {
        if bearer_token.is_empty() {
            return Err(ApplicationError::AccessDenied);
        }
        self.verifier
            .verify(bearer_token)
            .map_err(|_| ApplicationError::AccessDenied)?
            .validate_connection(
                self.expected_issuer,
                self.expected_resource,
                now_epoch_seconds,
            )
            .map_err(|_| ApplicationError::AccessDenied)
    }
}

pub struct RemoteHttpAuthorization<'authenticator, 'verifier, Verifier> {
    authenticator: &'authenticator RemoteAccessAuthenticator<'verifier, Verifier>,
    trusted_origins: &'authenticator [&'authenticator str],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteHttpAuthorizationError {
    Unauthorized,
    Forbidden,
}

impl<'authenticator, 'verifier, Verifier>
    RemoteHttpAuthorization<'authenticator, 'verifier, Verifier>
where
    Verifier: RemoteTokenVerifier,
{
    #[must_use]
    pub const fn new(
        authenticator: &'authenticator RemoteAccessAuthenticator<'verifier, Verifier>,
        trusted_origins: &'authenticator [&'authenticator str],
    ) -> Self {
        Self {
            authenticator,
            trusted_origins,
        }
    }

    /// Authorizes one remote MCP tool request.
    ///
    /// Browser-originated requests require an exact trusted-origin match.
    /// Requests without an `Origin` header remain valid for native MCP clients.
    /// The bearer token is verified again on every invocation.
    ///
    /// # Errors
    ///
    /// Returns `AccessDenied` for malformed authorization, an untrusted origin,
    /// an unknown tool, invalid claims, or insufficient OAuth scope.
    pub fn authorize_tool(
        &self,
        authorization_header: Option<&str>,
        origin_header: Option<&str>,
        tool_name: &str,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, ApplicationError> {
        self.authorize_tool_for_http(
            authorization_header,
            origin_header,
            tool_name,
            now_epoch_seconds,
        )
        .map_err(|_| ApplicationError::AccessDenied)
    }

    /// Authorizes a tool request while preserving the HTTP authentication
    /// outcome required to produce a correct bearer response.
    ///
    /// # Errors
    ///
    /// Returns `Unauthorized` for missing, malformed, unverifiable, or invalid
    /// bearer credentials. Returns `Forbidden` only after credentials validate
    /// but the browser origin, tool, or required scope is not authorized.
    pub fn authorize_tool_for_http(
        &self,
        authorization_header: Option<&str>,
        origin_header: Option<&str>,
        tool_name: &str,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, RemoteHttpAuthorizationError> {
        let bearer_token = authorization_header
            .and_then(parse_bearer_token)
            .ok_or(RemoteHttpAuthorizationError::Unauthorized)?;
        let access = self
            .authenticator
            .authenticate_connection(bearer_token, now_epoch_seconds)
            .map_err(|_| RemoteHttpAuthorizationError::Unauthorized)?;
        self.require_trusted_origin_for_http(origin_header)?;
        let operation = RemoteMcpOperation::from_tool_name(tool_name)
            .ok_or(RemoteHttpAuthorizationError::Forbidden)?;
        if !access.allows(operation.required_scope()) {
            return Err(RemoteHttpAuthorizationError::Forbidden);
        }
        Ok(access)
    }

    /// Authorizes a non-tool MCP protocol request with the same bearer and
    /// browser-origin policy used for tool requests.
    ///
    /// # Errors
    ///
    /// Returns `AccessDenied` when the origin or token is invalid.
    pub fn authorize_connection(
        &self,
        authorization_header: Option<&str>,
        origin_header: Option<&str>,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, ApplicationError> {
        self.authorize_connection_for_http(authorization_header, origin_header, now_epoch_seconds)
            .map_err(|_| ApplicationError::AccessDenied)
    }

    /// Authorizes protocol traffic while preserving HTTP 401/403 semantics.
    ///
    /// # Errors
    ///
    /// Returns `Unauthorized` for invalid credentials and `Forbidden` for an
    /// authenticated request from an untrusted browser origin.
    pub fn authorize_connection_for_http(
        &self,
        authorization_header: Option<&str>,
        origin_header: Option<&str>,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, RemoteHttpAuthorizationError> {
        let bearer_token = authorization_header
            .and_then(parse_bearer_token)
            .ok_or(RemoteHttpAuthorizationError::Unauthorized)?;
        let access = self
            .authenticator
            .authenticate_connection(bearer_token, now_epoch_seconds)
            .map_err(|_| RemoteHttpAuthorizationError::Unauthorized)?;
        self.require_trusted_origin_for_http(origin_header)?;
        Ok(access)
    }

    fn require_trusted_origin_for_http(
        &self,
        origin_header: Option<&str>,
    ) -> Result<(), RemoteHttpAuthorizationError> {
        if origin_header
            .is_some_and(|origin| origin.is_empty() || !self.trusted_origins.contains(&origin))
        {
            Err(RemoteHttpAuthorizationError::Forbidden)
        } else {
            Ok(())
        }
    }
}

fn parse_bearer_token(header: &str) -> Option<&str> {
    let (scheme, token) = header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.is_empty()
        || token.len() > MAX_REMOTE_BEARER_TOKEN_BYTES
        || token
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return None;
    }
    Some(token)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use rembrane_contracts::{RemoteAccessScope, RemoteTokenClaims};
    use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};

    use super::{
        MAX_REMOTE_BEARER_TOKEN_BYTES, RemoteAccessAuthenticator, RemoteHttpAuthorization,
        RemoteHttpAuthorizationError, RemoteTokenVerificationError, RemoteTokenVerifier,
        parse_bearer_token,
    };
    use crate::ApplicationError;

    struct TestVerifier;

    impl RemoteTokenVerifier for TestVerifier {
        fn verify(
            &self,
            bearer_token: &str,
        ) -> Result<RemoteTokenClaims, RemoteTokenVerificationError> {
            if bearer_token != "signed-token" {
                return Err(RemoteTokenVerificationError);
            }
            Ok(RemoteTokenClaims {
                issuer: "https://identity.example.test".to_owned(),
                audience: vec!["https://memory.example.test/mcp".to_owned()],
                subject_id: PrincipalId::new("principal_01"),
                client_id: ClientId::new("client_01"),
                workspace_id: WorkspaceId::new("workspace_01"),
                scopes: BTreeSet::from([
                    RemoteAccessScope::ContextRead,
                    RemoteAccessScope::TravelRead,
                ]),
                expires_at_epoch_seconds: 2_000,
                not_before_epoch_seconds: None,
            })
        }
    }

    fn authenticator() -> RemoteAccessAuthenticator<'static, TestVerifier> {
        static VERIFIER: TestVerifier = TestVerifier;
        RemoteAccessAuthenticator::new(
            &VERIFIER,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        )
    }

    #[test]
    fn converts_verified_claims_into_connection_bound_identity() {
        let access = authenticator()
            .authenticate("signed-token", 1_000, RemoteAccessScope::ContextRead)
            .expect("valid signed token should authenticate");

        assert_eq!(access.subject_id().as_str(), "principal_01");
        assert_eq!(access.client_id().as_str(), "client_01");
        assert_eq!(access.workspace_id().as_str(), "workspace_01");
    }

    #[test]
    fn verifier_and_scope_failures_are_non_enumerating() {
        assert_eq!(
            authenticator()
                .authenticate("invalid-token", 1_000, RemoteAccessScope::ContextRead)
                .expect_err("invalid token must fail"),
            ApplicationError::AccessDenied
        );
        assert_eq!(
            authenticator()
                .authenticate("signed-token", 1_000, RemoteAccessScope::MemoryWrite)
                .expect_err("missing scope must fail"),
            ApplicationError::AccessDenied
        );
        assert_eq!(
            authenticator()
                .authenticate("", 1_000, RemoteAccessScope::ContextRead)
                .expect_err("empty token must fail"),
            ApplicationError::AccessDenied
        );
    }

    #[test]
    fn bearer_parser_accepts_one_token_and_rejects_ambiguous_headers() {
        assert_eq!(
            parse_bearer_token("Bearer signed-token"),
            Some("signed-token")
        );
        assert_eq!(
            parse_bearer_token("bearer signed-token"),
            Some("signed-token")
        );
        assert_eq!(parse_bearer_token("signed-token"), None);
        assert_eq!(parse_bearer_token("Basic signed-token"), None);
        assert_eq!(parse_bearer_token("Bearer "), None);
        assert_eq!(parse_bearer_token("Bearer signed token"), None);
        assert_eq!(parse_bearer_token("Bearer signed-token\n"), None);
        assert_eq!(
            parse_bearer_token(&format!(
                "Bearer {}",
                "x".repeat(MAX_REMOTE_BEARER_TOKEN_BYTES + 1)
            )),
            None
        );
    }

    #[test]
    fn http_boundary_reauthenticates_known_tools_and_checks_browser_origin() {
        let authenticator = authenticator();
        let trusted_origins = ["https://app.example.test"];
        let http = RemoteHttpAuthorization::new(&authenticator, &trusted_origins);

        let access = http
            .authorize_tool(
                Some("Bearer signed-token"),
                Some("https://app.example.test"),
                "rembrane_resolve_context",
                1_000,
            )
            .expect("trusted request should authenticate");
        assert_eq!(access.workspace_id().as_str(), "workspace_01");

        assert_eq!(
            http.authorize_tool(
                Some("Bearer signed-token"),
                Some("https://evil.example.test"),
                "rembrane_resolve_context",
                1_000,
            )
            .expect_err("untrusted browser origin must fail"),
            ApplicationError::AccessDenied
        );
        assert_eq!(
            http.authorize_tool(
                Some("Bearer signed-token"),
                None,
                "untrusted_future_tool",
                1_000,
            )
            .expect_err("unknown tools must fail closed"),
            ApplicationError::AccessDenied
        );
        assert_eq!(
            http.authorize_tool(
                Some("Bearer signed-token"),
                None,
                "rembrane_remember_preference",
                1_000,
            )
            .expect_err("operation scope is checked on every request"),
            ApplicationError::AccessDenied
        );

        let protocol_access = http
            .authorize_connection(Some("Bearer signed-token"), None, 1_000)
            .expect("protocol requests should require a valid scoped token");
        assert_eq!(protocol_access.client_id().as_str(), "client_01");
    }

    #[test]
    fn http_boundary_preserves_bearer_unauthorized_and_forbidden_outcomes() {
        let authenticator = authenticator();
        let trusted_origins = ["https://app.example.test"];
        let http = RemoteHttpAuthorization::new(&authenticator, &trusted_origins);

        for authorization_header in [None, Some("Basic signed-token"), Some("Bearer invalid")] {
            assert_eq!(
                http.authorize_connection_for_http(authorization_header, None, 1_000)
                    .expect_err("invalid credentials must be unauthorized"),
                RemoteHttpAuthorizationError::Unauthorized
            );
        }
        assert_eq!(
            http.authorize_tool_for_http(
                Some("Bearer signed-token"),
                None,
                "rembrane_remember_preference",
                1_000,
            )
            .expect_err("valid token without required scope must be forbidden"),
            RemoteHttpAuthorizationError::Forbidden
        );
        assert_eq!(
            http.authorize_tool_for_http(
                Some("Bearer signed-token"),
                Some("https://evil.example.test"),
                "rembrane_resolve_context",
                1_000,
            )
            .expect_err("authenticated untrusted origin must be forbidden"),
            RemoteHttpAuthorizationError::Forbidden
        );
    }
}

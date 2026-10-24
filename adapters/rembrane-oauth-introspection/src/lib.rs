//! OAuth token introspection without coupling the core to one HTTP client.
//!
//! The transport implementation owns TLS, authorization-server credentials,
//! timeouts, and RFC 7662 HTTP exchange. This adapter accepts only an
//! authenticated response and converts active claims into Rembrane's
//! fail-closed remote-access contract.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};

use rembrane_application::{RemoteTokenVerificationError, RemoteTokenVerifier};
use rembrane_contracts::{RemoteAccessScope, RemoteTokenClaims};
use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};

pub trait IntrospectionTransport {
    /// Performs an authenticated RFC 7662 introspection request.
    ///
    /// The implementation must authenticate the Rembrane resource server,
    /// require TLS outside loopback development, bound response sizes and
    /// timeouts, and never log the token or client credential.
    ///
    /// # Errors
    ///
    /// Returns an opaque transport error for network, TLS, authentication,
    /// status, decoding, or response-limit failures.
    fn introspect(&self, token: &str)
    -> Result<IntrospectionResponse, IntrospectionTransportError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntrospectionResponse {
    pub active: bool,
    pub issuer: Option<String>,
    pub audience: Vec<String>,
    pub subject: Option<String>,
    pub client_id: Option<String>,
    pub workspace_id: Option<String>,
    pub scope: Option<String>,
    pub expires_at_epoch_seconds: Option<u64>,
    pub not_before_epoch_seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IntrospectionTransportError;

impl Display for IntrospectionTransportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OAuth introspection transport failed")
    }
}

impl Error for IntrospectionTransportError {}

pub struct IntrospectionTokenVerifier<Transport> {
    transport: Transport,
}

impl<Transport> IntrospectionTokenVerifier<Transport> {
    #[must_use]
    pub const fn new(transport: Transport) -> Self {
        Self { transport }
    }
}

impl<Transport> RemoteTokenVerifier for IntrospectionTokenVerifier<Transport>
where
    Transport: IntrospectionTransport,
{
    fn verify(
        &self,
        bearer_token: &str,
    ) -> Result<RemoteTokenClaims, RemoteTokenVerificationError> {
        if bearer_token.is_empty() {
            return Err(RemoteTokenVerificationError);
        }
        let response = self
            .transport
            .introspect(bearer_token)
            .map_err(|_| RemoteTokenVerificationError)?;
        if !response.active {
            return Err(RemoteTokenVerificationError);
        }
        let issuer = required(response.issuer)?;
        let subject_id = PrincipalId::new(required(response.subject)?);
        let client_id = ClientId::new(required(response.client_id)?);
        let workspace_id = WorkspaceId::new(required(response.workspace_id)?);
        let expires_at_epoch_seconds = response
            .expires_at_epoch_seconds
            .filter(|expiry| *expiry > 0)
            .ok_or(RemoteTokenVerificationError)?;
        if response.audience.is_empty() || response.audience.iter().any(String::is_empty) {
            return Err(RemoteTokenVerificationError);
        }
        let scopes = parse_scopes(response.scope.as_deref().unwrap_or_default())?;

        Ok(RemoteTokenClaims {
            issuer,
            audience: response.audience,
            subject_id,
            client_id,
            workspace_id,
            scopes,
            expires_at_epoch_seconds,
            not_before_epoch_seconds: response.not_before_epoch_seconds,
        })
    }
}

fn required(value: Option<String>) -> Result<String, RemoteTokenVerificationError> {
    value
        .filter(|value| !value.is_empty())
        .ok_or(RemoteTokenVerificationError)
}

fn parse_scopes(value: &str) -> Result<BTreeSet<RemoteAccessScope>, RemoteTokenVerificationError> {
    let mut scopes = BTreeSet::new();
    for scope in value.split_ascii_whitespace() {
        let scope = match scope {
            "rembrane:context:read" => RemoteAccessScope::ContextRead,
            "rembrane:memory:write" => RemoteAccessScope::MemoryWrite,
            "rembrane:checkpoint:read" => RemoteAccessScope::CheckpointRead,
            "rembrane:checkpoint:write" => RemoteAccessScope::CheckpointWrite,
            "rembrane:travel:read" => RemoteAccessScope::TravelRead,
            "rembrane:travel:write" => RemoteAccessScope::TravelWrite,
            _ => continue,
        };
        scopes.insert(scope);
    }
    if scopes.is_empty() {
        return Err(RemoteTokenVerificationError);
    }
    Ok(scopes)
}

#[cfg(test)]
mod tests {
    use super::{
        IntrospectionResponse, IntrospectionTokenVerifier, IntrospectionTransport,
        IntrospectionTransportError,
    };
    use rembrane_application::RemoteTokenVerifier;
    use rembrane_contracts::RemoteAccessScope;

    struct FixtureTransport {
        response: IntrospectionResponse,
    }

    impl IntrospectionTransport for FixtureTransport {
        fn introspect(
            &self,
            token: &str,
        ) -> Result<IntrospectionResponse, IntrospectionTransportError> {
            if token != "opaque-access-token" {
                return Err(IntrospectionTransportError);
            }
            Ok(self.response.clone())
        }
    }

    fn active_response() -> IntrospectionResponse {
        IntrospectionResponse {
            active: true,
            issuer: Some("https://identity.example.test".to_owned()),
            audience: vec!["https://memory.example.test/mcp".to_owned()],
            subject: Some("principal_01".to_owned()),
            client_id: Some("client_01".to_owned()),
            workspace_id: Some("workspace_01".to_owned()),
            scope: Some(
                "openid rembrane:context:read ignored:extension rembrane:travel:read".to_owned(),
            ),
            expires_at_epoch_seconds: Some(2_000),
            not_before_epoch_seconds: Some(900),
        }
    }

    #[test]
    fn converts_active_authenticated_introspection_into_canonical_claims() {
        let verifier = IntrospectionTokenVerifier::new(FixtureTransport {
            response: active_response(),
        });
        let claims = verifier
            .verify("opaque-access-token")
            .expect("active response should verify");

        assert_eq!(claims.subject_id.as_str(), "principal_01");
        assert_eq!(claims.workspace_id.as_str(), "workspace_01");
        assert!(claims.scopes.contains(&RemoteAccessScope::ContextRead));
        assert!(claims.scopes.contains(&RemoteAccessScope::TravelRead));
        assert_eq!(claims.scopes.len(), 2);
    }

    #[test]
    fn rejects_inactive_incomplete_and_transport_failed_tokens() {
        let mut inactive = active_response();
        inactive.active = false;
        assert!(
            IntrospectionTokenVerifier::new(FixtureTransport { response: inactive })
                .verify("opaque-access-token")
                .is_err()
        );

        let mut incomplete = active_response();
        incomplete.workspace_id = None;
        assert!(
            IntrospectionTokenVerifier::new(FixtureTransport {
                response: incomplete,
            })
            .verify("opaque-access-token")
            .is_err()
        );

        assert!(
            IntrospectionTokenVerifier::new(FixtureTransport {
                response: active_response(),
            })
            .verify("wrong-token")
            .is_err()
        );
    }
}

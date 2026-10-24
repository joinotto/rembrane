use std::error::Error;
use std::fmt::{Display, Formatter};

use rembrane_contracts::{RemoteAccessScope, RemoteTokenClaims, VerifiedRemoteAccess};

use crate::ApplicationError;

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
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use rembrane_contracts::{RemoteAccessScope, RemoteTokenClaims};
    use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};

    use super::{RemoteAccessAuthenticator, RemoteTokenVerificationError, RemoteTokenVerifier};
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
}

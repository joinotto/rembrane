use std::collections::BTreeMap;

use rembrane_contracts::{
    RemoteMcpRequestAuthorization, RemoteSessionBinding, RemoteSessionId, VerifiedRemoteAccess,
};

use crate::{ApplicationError, RemoteHttpAuthorization, RemoteTokenVerifier};

pub struct RemoteSessionRegistry {
    sessions: BTreeMap<RemoteSessionId, RemoteSessionBinding>,
    maximum_sessions: usize,
}

impl RemoteSessionRegistry {
    /// Creates a bounded in-process remote session registry.
    ///
    /// # Errors
    ///
    /// Returns a validation error when the configured capacity is zero.
    pub fn new(maximum_sessions: usize) -> Result<Self, ApplicationError> {
        if maximum_sessions == 0 {
            return Err(ApplicationError::Validation(
                "remote session capacity must be positive".to_owned(),
            ));
        }
        Ok(Self {
            sessions: BTreeMap::new(),
            maximum_sessions,
        })
    }

    /// Establishes a session bound to one verified authorization context.
    ///
    /// # Errors
    ///
    /// Returns `AlreadyExists` for a duplicate identifier and
    /// `StorageUnavailable` when the configured capacity is exhausted.
    pub fn establish(
        &mut self,
        session_id: RemoteSessionId,
        access: &VerifiedRemoteAccess,
        now_epoch_seconds: u64,
    ) -> Result<(), ApplicationError> {
        self.prune_expired(now_epoch_seconds);
        if self.sessions.contains_key(&session_id) {
            return Err(ApplicationError::AlreadyExists);
        }
        if self.sessions.len() >= self.maximum_sessions {
            return Err(ApplicationError::StorageUnavailable);
        }
        self.sessions.insert(session_id, access.session_binding());
        Ok(())
    }

    /// Authenticates an initialize request and establishes its session.
    ///
    /// # Errors
    ///
    /// Returns a non-enumerating authorization error for invalid origin or
    /// bearer credentials, and the normal bounded-registry errors for a
    /// duplicate identifier or exhausted live-session capacity.
    pub fn authorize_and_establish<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        session_id: RemoteSessionId,
        authorization_header: Option<&str>,
        origin_header: Option<&str>,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, ApplicationError>
    where
        Verifier: RemoteTokenVerifier,
    {
        let access = authorization.authorize_connection(
            authorization_header,
            origin_header,
            now_epoch_seconds,
        )?;
        self.establish(session_id, &access, now_epoch_seconds)?;
        Ok(access)
    }

    /// Reauthenticates a tool invocation and its existing session binding.
    ///
    /// # Errors
    ///
    /// Returns `AccessDenied` for invalid request authorization, unknown tools,
    /// unknown sessions, expired sessions, or authorization substitution.
    pub fn authorize_tool<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        session_id: &RemoteSessionId,
        authorization_header: Option<&str>,
        origin_header: Option<&str>,
        tool_name: &str,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, ApplicationError>
    where
        Verifier: RemoteTokenVerifier,
    {
        let access = authorization.authorize_tool(
            authorization_header,
            origin_header,
            tool_name,
            now_epoch_seconds,
        )?;
        self.revalidate(session_id, &access, now_epoch_seconds)?;
        Ok(access)
    }

    /// Reauthenticates a non-tool protocol request and its session binding.
    ///
    /// # Errors
    ///
    /// Returns `AccessDenied` for invalid request authorization, an unknown or
    /// expired session, or any authorization substitution.
    pub fn authorize_connection<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        session_id: &RemoteSessionId,
        authorization_header: Option<&str>,
        origin_header: Option<&str>,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, ApplicationError>
    where
        Verifier: RemoteTokenVerifier,
    {
        let access = authorization.authorize_connection(
            authorization_header,
            origin_header,
            now_epoch_seconds,
        )?;
        self.revalidate(session_id, &access, now_epoch_seconds)?;
        Ok(access)
    }

    /// Classifies and authorizes one established-session MCP request.
    ///
    /// # Errors
    ///
    /// Returns `AccessDenied` for every unsupported method or malformed
    /// method/tool combination, as well as any request or session
    /// authorization failure.
    pub fn authorize_request<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        session_id: &RemoteSessionId,
        authorization_header: Option<&str>,
        origin_header: Option<&str>,
        method: &str,
        tool_name: Option<&str>,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, ApplicationError>
    where
        Verifier: RemoteTokenVerifier,
    {
        match RemoteMcpRequestAuthorization::classify(method, tool_name)
            .ok_or(ApplicationError::AccessDenied)?
        {
            RemoteMcpRequestAuthorization::Connection => self.authorize_connection(
                authorization,
                session_id,
                authorization_header,
                origin_header,
                now_epoch_seconds,
            ),
            RemoteMcpRequestAuthorization::Tool(operation) => self.authorize_tool(
                authorization,
                session_id,
                authorization_header,
                origin_header,
                operation.tool_name(),
                now_epoch_seconds,
            ),
        }
    }

    /// Reauthenticates and deletes a remote session.
    ///
    /// # Errors
    ///
    /// Returns `AccessDenied` without revealing whether request authorization
    /// or the session binding failed.
    pub fn authorize_and_terminate<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        session_id: &RemoteSessionId,
        authorization_header: Option<&str>,
        origin_header: Option<&str>,
        now_epoch_seconds: u64,
    ) -> Result<(), ApplicationError>
    where
        Verifier: RemoteTokenVerifier,
    {
        let access = authorization.authorize_connection(
            authorization_header,
            origin_header,
            now_epoch_seconds,
        )?;
        self.terminate(session_id, &access, now_epoch_seconds)
    }

    /// Removes bindings whose non-extending authorization lifetime elapsed.
    ///
    /// This keeps abandoned sessions from permanently consuming the bounded
    /// registry. It does not inspect or reveal their authorization fields.
    pub fn prune_expired(&mut self, now_epoch_seconds: u64) {
        self.sessions
            .retain(|_, binding| !binding.is_expired(now_epoch_seconds));
    }

    /// Reauthenticates an existing session against its exact binding.
    ///
    /// # Errors
    ///
    /// Returns the same non-enumerating `AccessDenied` result for an unknown,
    /// expired, or authorization-mismatched session.
    pub fn revalidate(
        &mut self,
        session_id: &RemoteSessionId,
        access: &VerifiedRemoteAccess,
        now_epoch_seconds: u64,
    ) -> Result<(), ApplicationError> {
        self.sessions
            .get_mut(session_id)
            .ok_or(ApplicationError::AccessDenied)?
            .revalidate(access, now_epoch_seconds)
            .map_err(|_| ApplicationError::AccessDenied)
    }

    /// Deletes a session only after its current authorization has been
    /// revalidated.
    ///
    /// # Errors
    ///
    /// Returns `AccessDenied` for an unknown, expired, or mismatched session.
    pub fn terminate(
        &mut self,
        session_id: &RemoteSessionId,
        access: &VerifiedRemoteAccess,
        now_epoch_seconds: u64,
    ) -> Result<(), ApplicationError> {
        self.revalidate(session_id, access, now_epoch_seconds)?;
        self.sessions.remove(session_id);
        Ok(())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use rembrane_contracts::{
        RemoteAccessScope, RemoteSessionId, RemoteTokenClaims, VerifiedRemoteAccess,
    };
    use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};

    use super::RemoteSessionRegistry;
    use crate::{
        ApplicationError, RemoteAccessAuthenticator, RemoteHttpAuthorization,
        RemoteTokenVerificationError, RemoteTokenVerifier,
    };

    struct FixtureVerifier;

    impl RemoteTokenVerifier for FixtureVerifier {
        fn verify(
            &self,
            bearer_token: &str,
        ) -> Result<RemoteTokenClaims, RemoteTokenVerificationError> {
            match bearer_token {
                "workspace-one" => Ok(claims(
                    "workspace_01",
                    &[
                        RemoteAccessScope::ContextRead,
                        RemoteAccessScope::MemoryWrite,
                    ],
                )),
                "workspace-two" => Ok(claims(
                    "workspace_02",
                    &[
                        RemoteAccessScope::ContextRead,
                        RemoteAccessScope::MemoryWrite,
                    ],
                )),
                _ => Err(RemoteTokenVerificationError),
            }
        }
    }

    fn claims(workspace: &str, scopes: &[RemoteAccessScope]) -> RemoteTokenClaims {
        RemoteTokenClaims {
            issuer: "https://identity.example.test".to_owned(),
            audience: vec!["https://memory.example.test/mcp".to_owned()],
            subject_id: PrincipalId::new("principal_01"),
            client_id: ClientId::new("client_01"),
            workspace_id: WorkspaceId::new(workspace),
            scopes: scopes.iter().copied().collect::<BTreeSet<_>>(),
            expires_at_epoch_seconds: 2_000,
            not_before_epoch_seconds: None,
        }
    }

    fn access(workspace: &str, scopes: &[RemoteAccessScope]) -> VerifiedRemoteAccess {
        claims(workspace, scopes)
            .validate_connection(
                "https://identity.example.test",
                "https://memory.example.test/mcp",
                1_000,
            )
            .expect("fixture access should validate")
    }

    #[test]
    fn registry_bounds_duplicates_capacity_and_authenticated_deletion() {
        let mut registry = RemoteSessionRegistry::new(1).expect("capacity should be valid");
        let first =
            RemoteSessionId::new("session_0123456789abcdef").expect("session id should be valid");
        let second =
            RemoteSessionId::new("session_fedcba9876543210").expect("session id should be valid");
        let access = access("workspace_01", &[RemoteAccessScope::ContextRead]);

        registry
            .establish(first.clone(), &access, 1_000)
            .expect("first session should establish");
        assert_eq!(
            registry
                .establish(first.clone(), &access, 1_000)
                .expect_err("duplicate must fail"),
            ApplicationError::AlreadyExists
        );
        assert_eq!(
            registry
                .establish(second, &access, 1_000)
                .expect_err("capacity must be enforced"),
            ApplicationError::StorageUnavailable
        );
        registry
            .terminate(&first, &access, 1_100)
            .expect("bound access should terminate session");
        assert!(registry.is_empty());
    }

    #[test]
    fn registry_rejects_unknown_cross_tenant_and_scope_changed_sessions() {
        let mut registry = RemoteSessionRegistry::new(2).expect("capacity should be valid");
        let session =
            RemoteSessionId::new("session_0123456789abcdef").expect("session id should be valid");
        let bound_access = access(
            "workspace_01",
            &[
                RemoteAccessScope::ContextRead,
                RemoteAccessScope::TravelRead,
            ],
        );
        registry
            .establish(session.clone(), &bound_access, 1_000)
            .expect("session should establish");

        let unknown =
            RemoteSessionId::new("session_fedcba9876543210").expect("session id should be valid");
        assert_eq!(
            registry
                .revalidate(&unknown, &bound_access, 1_100)
                .expect_err("unknown session must fail"),
            ApplicationError::AccessDenied
        );
        assert_eq!(
            registry
                .revalidate(
                    &session,
                    &access("workspace_02", &[RemoteAccessScope::ContextRead]),
                    1_100,
                )
                .expect_err("tenant substitution must fail"),
            ApplicationError::AccessDenied
        );
        assert_eq!(
            registry
                .revalidate(
                    &session,
                    &access("workspace_01", &[RemoteAccessScope::ContextRead]),
                    1_100,
                )
                .expect_err("scope substitution must fail"),
            ApplicationError::AccessDenied
        );
    }

    #[test]
    fn registry_reclaims_expired_capacity_before_establishing() {
        let mut registry = RemoteSessionRegistry::new(1).expect("capacity should be valid");
        let expired =
            RemoteSessionId::new("session_0123456789abcdef").expect("session id should be valid");
        let replacement =
            RemoteSessionId::new("session_fedcba9876543210").expect("session id should be valid");
        let access = access("workspace_01", &[RemoteAccessScope::ContextRead]);

        registry
            .establish(expired, &access, 1_000)
            .expect("first session should establish");
        registry
            .establish(replacement.clone(), &access, 2_000)
            .expect("expired session should not consume capacity");

        assert_eq!(registry.len(), 1);
        registry
            .revalidate(&replacement, &access, 1_999)
            .expect("replacement session should remain available");
    }

    #[test]
    fn lifecycle_reauthenticates_every_request_and_denies_tenant_substitution() {
        let verifier = FixtureVerifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let trusted_origins = ["https://agent.example.test"];
        let authorization = RemoteHttpAuthorization::new(&authenticator, &trusted_origins);
        let mut registry = RemoteSessionRegistry::new(2).expect("capacity should be valid");
        let session =
            RemoteSessionId::new("session_0123456789abcdef").expect("session id should be valid");

        let established = registry
            .authorize_and_establish(
                &authorization,
                session.clone(),
                Some("Bearer workspace-one"),
                Some("https://agent.example.test"),
                1_000,
            )
            .expect("initialize should authenticate");
        assert_eq!(established.workspace_id().as_str(), "workspace_01");

        let tool_access = registry
            .authorize_tool(
                &authorization,
                &session,
                Some("Bearer workspace-one"),
                Some("https://agent.example.test"),
                "rembrane_remember_preference",
                1_100,
            )
            .expect("bound tool request should authenticate");
        assert_eq!(tool_access.workspace_id().as_str(), "workspace_01");

        assert_eq!(
            registry
                .authorize_connection(
                    &authorization,
                    &session,
                    Some("Bearer workspace-two"),
                    Some("https://agent.example.test"),
                    1_100,
                )
                .expect_err("tenant substitution must fail"),
            ApplicationError::AccessDenied
        );
        assert_eq!(
            registry
                .authorize_tool(
                    &authorization,
                    &session,
                    Some("Bearer workspace-one"),
                    Some("https://evil.example.test"),
                    "rembrane.resolve_context",
                    1_100,
                )
                .expect_err("origin substitution must fail"),
            ApplicationError::AccessDenied
        );

        registry
            .authorize_and_terminate(
                &authorization,
                &session,
                Some("Bearer workspace-one"),
                Some("https://agent.example.test"),
                1_200,
            )
            .expect("bound delete should authenticate");
        assert!(registry.is_empty());
    }

    #[test]
    fn request_classifier_dispatches_tools_and_rejects_unknown_methods() {
        let verifier = FixtureVerifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let authorization = RemoteHttpAuthorization::new(&authenticator, &[]);
        let mut registry = RemoteSessionRegistry::new(1).expect("capacity should be valid");
        let session =
            RemoteSessionId::new("session_0123456789abcdef").expect("session id should be valid");
        registry
            .authorize_and_establish(
                &authorization,
                session.clone(),
                Some("Bearer workspace-one"),
                None,
                1_000,
            )
            .expect("initialize should authenticate");

        registry
            .authorize_request(
                &authorization,
                &session,
                Some("Bearer workspace-one"),
                None,
                "tools/call",
                Some("rembrane_remember_preference"),
                1_100,
            )
            .expect("known scoped tool should authenticate");
        registry
            .authorize_request(
                &authorization,
                &session,
                Some("Bearer workspace-one"),
                None,
                "tools/list",
                None,
                1_100,
            )
            .expect("known connection method should authenticate");

        for (method, tool_name) in [
            ("resources/read", None),
            ("tools/call", None),
            ("tools/call", Some("untrusted_future_tool")),
            ("tools/list", Some("rembrane_resolve_context")),
        ] {
            assert_eq!(
                registry
                    .authorize_request(
                        &authorization,
                        &session,
                        Some("Bearer workspace-one"),
                        None,
                        method,
                        tool_name,
                        1_100,
                    )
                    .expect_err("unsupported request shape must fail closed"),
                ApplicationError::AccessDenied
            );
        }
    }
}

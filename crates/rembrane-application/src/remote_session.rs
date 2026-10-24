use std::collections::BTreeMap;

use rembrane_contracts::{RemoteSessionBinding, RemoteSessionId, VerifiedRemoteAccess};

use crate::ApplicationError;

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
    ) -> Result<(), ApplicationError> {
        if self.sessions.contains_key(&session_id) {
            return Err(ApplicationError::AlreadyExists);
        }
        if self.sessions.len() >= self.maximum_sessions {
            return Err(ApplicationError::StorageUnavailable);
        }
        self.sessions.insert(session_id, access.session_binding());
        Ok(())
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
    use crate::ApplicationError;

    fn access(workspace: &str, scopes: &[RemoteAccessScope]) -> VerifiedRemoteAccess {
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
            .establish(first.clone(), &access)
            .expect("first session should establish");
        assert_eq!(
            registry
                .establish(first.clone(), &access)
                .expect_err("duplicate must fail"),
            ApplicationError::AlreadyExists
        );
        assert_eq!(
            registry
                .establish(second, &access)
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
            .establish(session.clone(), &bound_access)
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
}

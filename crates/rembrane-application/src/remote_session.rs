use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use rembrane_contracts::{
    RemoteMcpRequestAuthorization, RemoteSessionBinding, RemoteSessionId, VerifiedRemoteAccess,
};

use crate::{
    ApplicationError, RemoteHttpAuthorization, RemoteHttpAuthorizationError, RemoteTokenVerifier,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteSessionHttpError {
    Unauthorized,
    Forbidden,
    Conflict,
    CapacityExceeded,
}

pub struct RemoteSessionRegistry {
    sessions: BTreeMap<RemoteSessionId, SessionRecord>,
    pending_initializations: BTreeMap<u64, Arc<()>>,
    next_reservation_id: u64,
    maximum_sessions: usize,
}

struct SessionRecord {
    binding: RemoteSessionBinding,
    incarnation: Arc<()>,
}

/// Opaque, process-local identity of one established binding. Holding the
/// identity prevents allocation reuse from making a replacement look equal.
/// This is a mutation-completion guard, not ongoing stream authorization.
#[derive(Clone)]
pub struct RemoteSessionMutationGuard {
    session_id: RemoteSessionId,
    incarnation: Arc<()>,
}

impl fmt::Debug for RemoteSessionMutationGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteSessionMutationGuard(<redacted>)")
    }
}

pub struct RemoteSessionReservation {
    id: u64,
    incarnation: Arc<()>,
}

impl PartialEq for RemoteSessionReservation {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id && Arc::ptr_eq(&self.incarnation, &other.incarnation)
    }
}

impl Eq for RemoteSessionReservation {}

impl fmt::Debug for RemoteSessionReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteSessionReservation(<redacted>)")
    }
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
            pending_initializations: BTreeMap::new(),
            next_reservation_id: 1,
            maximum_sessions,
        })
    }

    /// Reserves one anonymous initialization slot before an SDK-generated
    /// session identifier exists.
    ///
    /// The move-only reservation must be consumed by
    /// [`Self::commit_reservation`] or [`Self::cancel_reservation`]. It owns an
    /// opaque identity for this exact slot; a numeric counter is not portable
    /// authority across registries.
    ///
    /// # Errors
    ///
    /// Returns `StorageUnavailable` when live sessions plus pending
    /// initializations reach the configured bound, or reservation identifiers
    /// can no longer be generated safely.
    pub fn reserve_initialization(
        &mut self,
        now_epoch_seconds: u64,
    ) -> Result<RemoteSessionReservation, ApplicationError> {
        self.prune_expired(now_epoch_seconds);
        if self
            .sessions
            .len()
            .saturating_add(self.pending_initializations.len())
            >= self.maximum_sessions
        {
            return Err(ApplicationError::StorageUnavailable);
        }
        let id = self.next_reservation_id;
        self.next_reservation_id = self
            .next_reservation_id
            .checked_add(1)
            .ok_or(ApplicationError::StorageUnavailable)?;
        if self.pending_initializations.contains_key(&id) {
            return Err(ApplicationError::StorageUnavailable);
        }
        let incarnation = Arc::new(());
        self.pending_initializations
            .insert(id, Arc::clone(&incarnation));
        Ok(RemoteSessionReservation { id, incarnation })
    }

    /// Commits an SDK-generated session into its previously reserved slot.
    ///
    /// The reservation is consumed even when the generated identifier
    /// conflicts, preventing failed initialization from leaking capacity.
    ///
    /// # Errors
    ///
    /// Returns `AccessDenied` for a foreign or already consumed reservation,
    /// `AlreadyExists` for an identifier collision, or the normal bounded
    /// registry error.
    #[allow(clippy::needless_pass_by_value)]
    pub fn commit_reservation(
        &mut self,
        reservation: RemoteSessionReservation,
        session_id: RemoteSessionId,
        access: &VerifiedRemoteAccess,
        now_epoch_seconds: u64,
    ) -> Result<(), ApplicationError> {
        if !self.matches_reservation(&reservation) {
            return Err(ApplicationError::AccessDenied);
        }
        self.pending_initializations.remove(&reservation.id);
        self.establish(session_id, access, now_epoch_seconds)
    }

    /// Releases one pending SDK initialization slot without creating a
    /// session.
    ///
    /// # Errors
    ///
    /// Returns `AccessDenied` for a foreign or already consumed reservation.
    #[allow(clippy::needless_pass_by_value)]
    pub fn cancel_reservation(
        &mut self,
        reservation: RemoteSessionReservation,
    ) -> Result<(), ApplicationError> {
        if self.matches_reservation(&reservation) {
            self.pending_initializations.remove(&reservation.id);
            Ok(())
        } else {
            Err(ApplicationError::AccessDenied)
        }
    }

    fn matches_reservation(&self, reservation: &RemoteSessionReservation) -> bool {
        self.pending_initializations
            .get(&reservation.id)
            .is_some_and(|incarnation| Arc::ptr_eq(incarnation, &reservation.incarnation))
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
        self.establish_guarded(session_id, access, now_epoch_seconds)
            .map(|_| ())
    }

    /// Establishes a session and atomically captures its unique incarnation
    /// for asynchronous initialization rollback.
    ///
    /// # Errors
    ///
    /// Returns the same authorization/collision/capacity errors as `establish`.
    pub fn establish_guarded(
        &mut self,
        session_id: RemoteSessionId,
        access: &VerifiedRemoteAccess,
        now_epoch_seconds: u64,
    ) -> Result<RemoteSessionMutationGuard, ApplicationError> {
        if access.expires_at_epoch_seconds() <= now_epoch_seconds
            || access.ensure_current().is_err()
        {
            return Err(ApplicationError::AccessDenied);
        }
        self.prune_expired(now_epoch_seconds);
        if self.sessions.contains_key(&session_id) {
            return Err(ApplicationError::AlreadyExists);
        }
        if self
            .sessions
            .len()
            .saturating_add(self.pending_initializations.len())
            >= self.maximum_sessions
        {
            return Err(ApplicationError::StorageUnavailable);
        }
        let incarnation = Arc::new(());
        let guard = RemoteSessionMutationGuard {
            session_id: session_id.clone(),
            incarnation: Arc::clone(&incarnation),
        };
        self.sessions.insert(
            session_id,
            SessionRecord {
                binding: access.session_binding(),
                incarnation,
            },
        );
        Ok(guard)
    }

    /// Rolls back an exact, unchanged binding after compatibility
    /// initialization failed. This is internal cleanup, not client deletion.
    ///
    /// The original proof may have elapsed while dispatching. Every claim
    /// and the original expiry ceiling must still match the binding; a changed
    /// binding is never removed. The guard must have been captured before
    /// dispatch: matching claims/expiry alone cannot distinguish a same-ID
    /// replacement. Do not expose this port as an HTTP endpoint.
    ///
    /// # Errors
    ///
    /// Returns `AccessDenied` for a missing, foreign, or changed binding.
    pub fn rollback_establishment(
        &mut self,
        guard: &RemoteSessionMutationGuard,
        access: &VerifiedRemoteAccess,
    ) -> Result<(), ApplicationError> {
        if !self.matches_guard(guard)
            || self
                .sessions
                .get(&guard.session_id)
                .map(|record| &record.binding)
                != Some(&access.session_binding())
        {
            return Err(ApplicationError::AccessDenied);
        }
        self.sessions.remove(&guard.session_id);
        Ok(())
    }

    /// Revalidates and captures one existing binding before asynchronous
    /// mutation dispatch. Capture is not permission to bypass proof lifetime.
    ///
    /// # Errors
    ///
    /// Returns non-enumerating `AccessDenied` for unknown, expired, or foreign
    /// authority. Capture before, never after, a downstream wait.
    pub fn capture_mutation_guard(
        &mut self,
        session_id: &RemoteSessionId,
        access: &VerifiedRemoteAccess,
        now_epoch_seconds: u64,
    ) -> Result<RemoteSessionMutationGuard, ApplicationError> {
        self.revalidate(session_id, access, now_epoch_seconds)?;
        let record = self
            .sessions
            .get(session_id)
            .ok_or(ApplicationError::AccessDenied)?;
        Ok(RemoteSessionMutationGuard {
            session_id: session_id.clone(),
            incarnation: Arc::clone(&record.incarnation),
        })
    }

    fn matches_guard(&self, guard: &RemoteSessionMutationGuard) -> bool {
        self.sessions
            .get(&guard.session_id)
            .is_some_and(|record| Arc::ptr_eq(&record.incarnation, &guard.incarnation))
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

    /// Authenticates and establishes an HTTP session while preserving the
    /// transport outcome required for a correct bearer response.
    ///
    /// # Errors
    ///
    /// Returns `Unauthorized` only for invalid credentials, `Forbidden` for
    /// an authenticated but untrusted origin, `Conflict` for a duplicate
    /// session identifier, and `CapacityExceeded` for bounded-registry
    /// exhaustion.
    pub fn authorize_and_establish_for_http<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        session_id: RemoteSessionId,
        authorization_header: Option<&str>,
        origin_header: Option<&str>,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, RemoteSessionHttpError>
    where
        Verifier: RemoteTokenVerifier,
    {
        let access = authorization
            .authorize_connection_for_http(authorization_header, origin_header, now_epoch_seconds)
            .map_err(RemoteSessionHttpError::from)?;
        self.establish(session_id, &access, now_epoch_seconds)
            .map_err(|error| match error {
                ApplicationError::AlreadyExists => RemoteSessionHttpError::Conflict,
                ApplicationError::StorageUnavailable => RemoteSessionHttpError::CapacityExceeded,
                _ => RemoteSessionHttpError::Forbidden,
            })?;
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
        let mut access = authorization.authorize_tool(
            authorization_header,
            origin_header,
            tool_name,
            now_epoch_seconds,
        )?;
        self.revalidate_access(session_id, &mut access, now_epoch_seconds)?;
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
        let mut access = authorization.authorize_connection(
            authorization_header,
            origin_header,
            now_epoch_seconds,
        )?;
        self.revalidate_access(session_id, &mut access, now_epoch_seconds)?;
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

    /// Classifies and authorizes an established-session HTTP MCP request
    /// without collapsing bearer authentication into a generic denial.
    ///
    /// # Errors
    ///
    /// Returns `Unauthorized` for invalid credentials and `Forbidden` for an
    /// authenticated origin, tool, scope, session, or tenant mismatch.
    pub fn authorize_request_for_http<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        session_id: &RemoteSessionId,
        authorization_header: Option<&str>,
        origin_header: Option<&str>,
        method: &str,
        tool_name: Option<&str>,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, RemoteSessionHttpError>
    where
        Verifier: RemoteTokenVerifier,
    {
        let mut access = authorization
            .authorize_request_for_http(
                authorization_header,
                origin_header,
                method,
                tool_name,
                now_epoch_seconds,
            )
            .map_err(RemoteSessionHttpError::from)?;
        self.revalidate_access(session_id, &mut access, now_epoch_seconds)
            .map_err(|_| RemoteSessionHttpError::Forbidden)?;
        Ok(access)
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

    /// Reauthenticates and terminates an HTTP MCP session while retaining
    /// correct 401 versus 403 semantics.
    ///
    /// # Errors
    ///
    /// Returns `Unauthorized` for invalid credentials and `Forbidden` for an
    /// authenticated origin, session, or tenant mismatch.
    pub fn authorize_and_terminate_for_http<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        session_id: &RemoteSessionId,
        authorization_header: Option<&str>,
        origin_header: Option<&str>,
        now_epoch_seconds: u64,
    ) -> Result<(), RemoteSessionHttpError>
    where
        Verifier: RemoteTokenVerifier,
    {
        let access = self.authorize_termination_for_http(
            authorization,
            session_id,
            authorization_header,
            origin_header,
            now_epoch_seconds,
        )?;
        self.terminate(session_id, &access, now_epoch_seconds)
            .map_err(|_| RemoteSessionHttpError::Forbidden)
    }

    /// Reauthenticates and revalidates an HTTP MCP session for termination
    /// without removing its binding.
    ///
    /// This supports transports that must first obtain downstream confirmation
    /// before committing local session deletion.
    ///
    /// # Errors
    ///
    /// Returns `Unauthorized` for invalid credentials and `Forbidden` for an
    /// authenticated origin, session, or tenant mismatch.
    pub fn authorize_termination_for_http<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        session_id: &RemoteSessionId,
        authorization_header: Option<&str>,
        origin_header: Option<&str>,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, RemoteSessionHttpError>
    where
        Verifier: RemoteTokenVerifier,
    {
        let mut access = authorization
            .authorize_connection_for_http(authorization_header, origin_header, now_epoch_seconds)
            .map_err(RemoteSessionHttpError::from)?;
        self.revalidate_access(session_id, &mut access, now_epoch_seconds)
            .map_err(|_| RemoteSessionHttpError::Forbidden)?;
        Ok(access)
    }

    /// Removes bindings whose non-extending authorization lifetime elapsed.
    ///
    /// This keeps abandoned sessions from permanently consuming the bounded
    /// registry. It does not inspect or reveal their authorization fields.
    pub fn prune_expired(&mut self, now_epoch_seconds: u64) {
        self.sessions
            .retain(|_, record| !record.binding.is_expired(now_epoch_seconds));
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
            .binding
            .revalidate(access, now_epoch_seconds)
            .map_err(|_| ApplicationError::AccessDenied)
    }

    /// Revalidates and carries the original session lifetime into the proof
    /// returned to queued dispatch and response-delivery code.
    ///
    /// # Errors
    ///
    /// Returns non-enumerating `AccessDenied` for unknown, expired, or foreign
    /// sessions. Valid signed token claims are not rewritten.
    pub fn revalidate_access(
        &mut self,
        session_id: &RemoteSessionId,
        access: &mut VerifiedRemoteAccess,
        now_epoch_seconds: u64,
    ) -> Result<(), ApplicationError> {
        self.sessions
            .get_mut(session_id)
            .ok_or(ApplicationError::AccessDenied)?
            .binding
            .revalidate_access(access, now_epoch_seconds)
            .map_err(|_| ApplicationError::AccessDenied)
    }

    /// Deletes a session only after its current authorization has been
    /// revalidated. This synchronous helper does not distinguish incarnations
    /// across waits; async transports must use `commit_termination` instead.
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

    /// Commits a confirmed asynchronous DELETE only to the binding captured
    /// before dispatch. Even identical claims/ID cannot alias a replacement.
    ///
    /// # Errors
    ///
    /// Denies missing/replaced/foreign-registry guards and expired or substituted
    /// authority without removing the current binding.
    pub fn commit_termination(
        &mut self,
        guard: &RemoteSessionMutationGuard,
        access: &VerifiedRemoteAccess,
        now_epoch_seconds: u64,
    ) -> Result<(), ApplicationError> {
        if !self.matches_guard(guard) {
            return Err(ApplicationError::AccessDenied);
        }
        self.terminate(&guard.session_id, access, now_epoch_seconds)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    #[must_use]
    pub fn pending_initializations(&self) -> usize {
        self.pending_initializations.len()
    }
}

impl From<RemoteHttpAuthorizationError> for RemoteSessionHttpError {
    fn from(error: RemoteHttpAuthorizationError) -> Self {
        match error {
            RemoteHttpAuthorizationError::Unauthorized => Self::Unauthorized,
            RemoteHttpAuthorizationError::Forbidden => Self::Forbidden,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use rembrane_contracts::{
        RemoteAccessScope, RemoteSessionId, RemoteTokenClaims, VerifiedRemoteAccess,
    };
    use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};

    use super::{RemoteSessionHttpError, RemoteSessionRegistry};
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
    fn anonymous_initialization_reservations_bound_and_release_capacity() {
        let access = access("workspace_01", &[RemoteAccessScope::ContextRead]);
        let session = RemoteSessionId::new("session_reserved_0123456789")
            .expect("session id should be valid");
        let mut registry = RemoteSessionRegistry::new(1).expect("capacity should be valid");
        let reservation = registry
            .reserve_initialization(1_000)
            .expect("first initialization should reserve capacity");
        assert_eq!(registry.pending_initializations(), 1);
        assert_eq!(
            registry
                .establish(session.clone(), &access, 1_000)
                .expect_err("normal establishment must respect pending capacity"),
            ApplicationError::StorageUnavailable
        );
        registry
            .commit_reservation(reservation, session.clone(), &access, 1_000)
            .expect("reserved initialization should commit");
        assert_eq!(registry.pending_initializations(), 0);
        assert_eq!(registry.len(), 1);

        registry
            .terminate(&session, &access, 1_001)
            .expect("committed session should terminate");
        let cancelled = registry
            .reserve_initialization(1_002)
            .expect("released capacity should reserve again");
        registry
            .cancel_reservation(cancelled)
            .expect("cancelled initialization should release capacity");
        assert_eq!(registry.pending_initializations(), 0);
        registry
            .establish(session.clone(), &access, 1_003)
            .expect("cancelled reservation must leave capacity reusable");

        let mut collision_registry =
            RemoteSessionRegistry::new(2).expect("collision capacity should be valid");
        collision_registry
            .establish(session.clone(), &access, 1_004)
            .expect("collision fixture session should establish");
        let collision = collision_registry
            .reserve_initialization(1_004)
            .expect("collision fixture should reserve");
        assert_eq!(
            collision_registry
                .commit_reservation(collision, session, &access, 1_004)
                .expect_err("duplicate generated ID must fail"),
            ApplicationError::AlreadyExists
        );
        assert_eq!(collision_registry.pending_initializations(), 0);
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
    fn foreign_reservation_cannot_cancel_another_registry_slot() {
        let mut first = RemoteSessionRegistry::new(1).unwrap();
        let mut second = RemoteSessionRegistry::new(1).unwrap();
        let foreign = first.reserve_initialization(1_000).unwrap();
        let local = second.reserve_initialization(1_000).unwrap();
        assert_eq!(
            foreign.id, local.id,
            "numeric counters deliberately collide"
        );
        assert_eq!(
            second.cancel_reservation(foreign),
            Err(ApplicationError::AccessDenied),
        );
        assert_eq!(first.pending_initializations(), 1);
        assert_eq!(second.pending_initializations(), 1);
        second.cancel_reservation(local).unwrap();
        assert_eq!(second.pending_initializations(), 0);
    }

    #[test]
    fn foreign_reservation_cannot_commit_using_another_registry_slot() {
        let mut first = RemoteSessionRegistry::new(1).unwrap();
        let mut second = RemoteSessionRegistry::new(1).unwrap();
        let foreign = first.reserve_initialization(1_000).unwrap();
        let local = second.reserve_initialization(1_000).unwrap();
        assert_eq!(foreign.id, local.id);
        let session = RemoteSessionId::new("session_0123456789abcdef").unwrap();
        let access = access("workspace_01", &[RemoteAccessScope::ContextRead]);
        assert_eq!(
            second.commit_reservation(foreign, session.clone(), &access, 1_000),
            Err(ApplicationError::AccessDenied),
        );
        assert!(second.is_empty());
        assert_eq!(first.pending_initializations(), 1);
        assert_eq!(second.pending_initializations(), 1);
        second
            .commit_reservation(local, session, &access, 1_000)
            .unwrap();
        assert_eq!(second.pending_initializations(), 0);
        assert_eq!(second.len(), 1);
    }

    #[test]
    fn distinct_registry_reservations_with_equal_counters_are_not_equal() {
        let mut first = RemoteSessionRegistry::new(1).unwrap();
        let mut second = RemoteSessionRegistry::new(1).unwrap();
        let left = first.reserve_initialization(1_000).unwrap();
        let right = second.reserve_initialization(1_000).unwrap();
        assert_eq!(left.id, right.id);
        assert_ne!(left, right);
        first.cancel_reservation(left).unwrap();
        second.cancel_reservation(right).unwrap();
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
        assert_eq!(
            registry.establish(replacement.clone(), &access, 2_000),
            Err(ApplicationError::AccessDenied),
            "an expired token must not establish its replacement",
        );
        let mut renewed = claims("workspace_01", &[RemoteAccessScope::ContextRead]);
        renewed.expires_at_epoch_seconds = 3_000;
        let renewed = renewed
            .validate_connection(
                "https://identity.example.test",
                "https://memory.example.test/mcp",
                2_000,
            )
            .expect("fresh replacement proof");
        registry
            .establish(replacement.clone(), &renewed, 2_000)
            .expect("expired session should not consume capacity");

        assert_eq!(registry.len(), 1);
        registry
            .revalidate(&replacement, &renewed, 2_001)
            .expect("replacement session should remain available");
    }

    #[test]
    fn elapsed_proof_cannot_commit_a_reserved_session() {
        let mut registry = RemoteSessionRegistry::new(1).expect("capacity");
        let reservation = registry.reserve_initialization(1_000).expect("reservation");
        let mut elapsed = access("workspace_01", &[RemoteAccessScope::ContextRead]);
        assert!(
            elapsed
                .constrain_validity(
                    std::time::Instant::now()
                        .checked_sub(std::time::Duration::from_secs(2))
                        .expect("fixture observation"),
                    1_999,
                )
                .is_err()
        );
        assert_eq!(
            registry.commit_reservation(
                reservation,
                RemoteSessionId::new("session_0123456789abcdef").expect("session"),
                &elapsed,
                1_000,
            ),
            Err(ApplicationError::AccessDenied),
        );
        assert!(registry.is_empty());
        let replacement = registry
            .reserve_initialization(1_000)
            .expect("released capacity");
        registry.cancel_reservation(replacement).expect("cleanup");
    }

    #[test]
    fn elapsed_session_cannot_be_refreshed_and_is_pruned_with_stale_epoch_time() {
        use std::time::{Duration, Instant};
        let mut registry = RemoteSessionRegistry::new(1).unwrap();
        let session = RemoteSessionId::new("session_0123456789abcdef").unwrap();
        let mut original = access("workspace_01", &[RemoteAccessScope::ContextRead]);
        original.constrain_validity(Instant::now(), 1_999).unwrap();
        registry
            .establish(session.clone(), &original, 1_000)
            .unwrap();
        std::thread::sleep(Duration::from_millis(1_100));
        let mut fresh = access("workspace_01", &[RemoteAccessScope::ContextRead]);
        assert!(fresh.ensure_current().is_ok());
        assert_eq!(
            registry.revalidate_access(&session, &mut fresh, 1_000),
            Err(ApplicationError::AccessDenied),
        );
        assert_eq!(
            registry.terminate(&session, &fresh, 1_000),
            Err(ApplicationError::AccessDenied),
        );
        registry.prune_expired(1_000);
        assert!(registry.is_empty());
        let slot = registry.reserve_initialization(1_000).unwrap();
        registry.cancel_reservation(slot).unwrap();
    }

    #[test]
    fn every_session_authorization_path_returns_the_original_dispatch_ceiling() {
        let verifier = FixtureVerifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let authorization = RemoteHttpAuthorization::new(&authenticator, &[]);
        let mut registry = RemoteSessionRegistry::new(4).unwrap();
        let original = access(
            "workspace_01",
            &[
                RemoteAccessScope::ContextRead,
                RemoteAccessScope::MemoryWrite,
            ],
        );
        let session = RemoteSessionId::new("session_0123456789abcdef").unwrap();
        registry
            .establish(session.clone(), &original, 1_000)
            .unwrap();
        let connection = registry
            .authorize_connection(
                &authorization,
                &session,
                Some("Bearer workspace-one"),
                None,
                1_000,
            )
            .unwrap();
        let tool = registry
            .authorize_tool(
                &authorization,
                &session,
                Some("Bearer workspace-one"),
                None,
                "rembrane_resolve_context",
                1_000,
            )
            .unwrap();
        let request = registry
            .authorize_request_for_http(
                &authorization,
                &session,
                Some("Bearer workspace-one"),
                None,
                "tools/list",
                None,
                1_000,
            )
            .unwrap();
        let deletion = registry
            .authorize_termination_for_http(
                &authorization,
                &session,
                Some("Bearer workspace-one"),
                None,
                1_000,
            )
            .unwrap();
        for proof in [connection, tool, request, deletion] {
            assert_eq!(proof.validity_deadline(), original.validity_deadline());
            assert_eq!(proof.expires_at_epoch_seconds(), 2_000);
        }
        assert_eq!(
            registry.len(),
            1,
            "authorization does not delete the session"
        );
    }

    #[test]
    fn failed_establishment_rollback_requires_exact_binding_but_not_current_lifetime() {
        let mut registry = RemoteSessionRegistry::new(1).expect("capacity");
        let session = RemoteSessionId::new("session_0123456789abcdef").expect("session");
        let mut original = access("workspace_01", &[RemoteAccessScope::ContextRead]);
        let guard = registry
            .establish_guarded(session.clone(), &original, 1_000)
            .expect("establish");
        assert_eq!(
            registry.rollback_establishment(
                &guard,
                &access("workspace_02", &[RemoteAccessScope::ContextRead]),
            ),
            Err(ApplicationError::AccessDenied),
        );
        assert_eq!(
            registry.rollback_establishment(
                &guard,
                &access("workspace_01", &[RemoteAccessScope::MemoryWrite]),
            ),
            Err(ApplicationError::AccessDenied),
        );
        let mut changed = claims("workspace_01", &[RemoteAccessScope::ContextRead]);
        changed.expires_at_epoch_seconds = 3_000;
        let changed = changed
            .validate_connection(
                "https://identity.example.test",
                "https://memory.example.test/mcp",
                1_000,
            )
            .expect("changed expiry");
        assert_eq!(
            registry.rollback_establishment(&guard, &changed),
            Err(ApplicationError::AccessDenied),
        );
        assert_eq!(registry.len(), 1);
        assert!(
            original
                .constrain_validity(
                    std::time::Instant::now()
                        .checked_sub(std::time::Duration::from_secs(2))
                        .expect("fixture observation"),
                    1_999,
                )
                .is_err()
        );
        registry
            .rollback_establishment(&guard, &original)
            .expect("exact cleanup");
        assert!(registry.is_empty());
        assert_eq!(
            registry.rollback_establishment(&guard, &original),
            Err(ApplicationError::AccessDenied),
        );
    }

    #[test]
    fn mutation_guards_cannot_alias_same_id_and_same_proof_replacements() {
        let mut registry = RemoteSessionRegistry::new(1).unwrap();
        let session = RemoteSessionId::new("session_0123456789abcdef").unwrap();
        let original = access("workspace_01", &[RemoteAccessScope::ContextRead]);
        let old = registry
            .establish_guarded(session.clone(), &original, 1_000)
            .unwrap();
        registry.terminate(&session, &original, 1_000).unwrap();
        registry
            .establish(session.clone(), &original, 1_000)
            .unwrap();
        let replacement = registry
            .capture_mutation_guard(&session, &original, 1_000)
            .unwrap();
        assert!(!format!("{old:?}").contains(session.as_str()));
        assert_eq!(
            registry.rollback_establishment(&old, &original),
            Err(ApplicationError::AccessDenied),
        );
        assert_eq!(
            registry.commit_termination(&old, &original, 1_000),
            Err(ApplicationError::AccessDenied),
        );
        assert_eq!(registry.len(), 1);
        registry
            .commit_termination(&replacement, &original, 1_000)
            .unwrap();
        assert!(registry.is_empty());
        assert_eq!(
            registry.commit_termination(&replacement, &original, 1_000),
            Err(ApplicationError::AccessDenied),
        );
    }

    #[test]
    fn mutation_guards_are_instance_bound_even_with_identical_ids_and_claims() {
        let mut first = RemoteSessionRegistry::new(1).unwrap();
        let mut second = RemoteSessionRegistry::new(1).unwrap();
        let session = RemoteSessionId::new("session_0123456789abcdef").unwrap();
        let original = access("workspace_01", &[RemoteAccessScope::ContextRead]);
        let guard = first
            .establish_guarded(session.clone(), &original, 1_000)
            .unwrap();
        second.establish(session, &original, 1_000).unwrap();
        assert_eq!(
            second.rollback_establishment(&guard, &original),
            Err(ApplicationError::AccessDenied),
        );
        assert_eq!(
            second.commit_termination(&guard, &original, 1_000),
            Err(ApplicationError::AccessDenied),
        );
        assert_eq!(second.len(), 1);
        first.rollback_establishment(&guard, &original).unwrap();
        assert!(first.is_empty());
    }

    #[test]
    fn pruning_cannot_restore_a_previous_mutation_guard() {
        let mut registry = RemoteSessionRegistry::new(1).unwrap();
        let session = RemoteSessionId::new("session_0123456789abcdef").unwrap();
        let original = access("workspace_01", &[RemoteAccessScope::ContextRead]);
        let guard = registry
            .establish_guarded(session.clone(), &original, 1_000)
            .unwrap();
        registry.prune_expired(2_000);
        assert!(registry.is_empty());
        registry
            .establish(session.clone(), &original, 1_000)
            .unwrap();
        assert_eq!(
            registry.rollback_establishment(&guard, &original),
            Err(ApplicationError::AccessDenied),
        );
        assert_eq!(
            registry.commit_termination(&guard, &original, 1_000),
            Err(ApplicationError::AccessDenied),
        );
        registry.revalidate(&session, &original, 1_000).unwrap();
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

    #[test]
    fn http_lifecycle_preserves_auth_outcomes_and_denies_cross_tenant_replay() {
        let verifier = FixtureVerifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let trusted_origins = ["https://agent.example.test"];
        let authorization = RemoteHttpAuthorization::new(&authenticator, &trusted_origins);
        let mut registry = RemoteSessionRegistry::new(1).expect("capacity should be valid");
        let session =
            RemoteSessionId::new("session_0123456789abcdef").expect("session id should be valid");

        assert_eq!(
            registry
                .authorize_and_establish_for_http(
                    &authorization,
                    session.clone(),
                    None,
                    Some("https://agent.example.test"),
                    1_000,
                )
                .expect_err("missing bearer must be unauthorized"),
            RemoteSessionHttpError::Unauthorized
        );
        assert_eq!(
            registry
                .authorize_and_establish_for_http(
                    &authorization,
                    session.clone(),
                    Some("Bearer workspace-one"),
                    Some("https://evil.example.test"),
                    1_000,
                )
                .expect_err("untrusted authenticated origin must be forbidden"),
            RemoteSessionHttpError::Forbidden
        );
        registry
            .authorize_and_establish_for_http(
                &authorization,
                session.clone(),
                Some("Bearer workspace-one"),
                Some("https://agent.example.test"),
                1_000,
            )
            .expect("valid request should establish");

        assert_eq!(
            registry
                .authorize_request_for_http(
                    &authorization,
                    &session,
                    Some("Bearer invalid"),
                    Some("https://agent.example.test"),
                    "tools/list",
                    None,
                    1_100,
                )
                .expect_err("invalid bearer must remain unauthorized"),
            RemoteSessionHttpError::Unauthorized
        );
        assert_eq!(
            registry
                .authorize_request_for_http(
                    &authorization,
                    &session,
                    Some("Bearer workspace-two"),
                    Some("https://agent.example.test"),
                    "tools/list",
                    None,
                    1_100,
                )
                .expect_err("cross-tenant replay must be forbidden"),
            RemoteSessionHttpError::Forbidden
        );
        assert_eq!(
            registry
                .authorize_request_for_http(
                    &authorization,
                    &session,
                    Some("Bearer workspace-one"),
                    Some("https://agent.example.test"),
                    "tools/call",
                    Some("untrusted_future_tool"),
                    1_100,
                )
                .expect_err("unknown tool must fail closed"),
            RemoteSessionHttpError::Forbidden
        );
        registry
            .authorize_and_terminate_for_http(
                &authorization,
                &session,
                Some("Bearer workspace-one"),
                Some("https://agent.example.test"),
                1_200,
            )
            .expect("bound session should terminate");
    }

    #[test]
    fn termination_authorization_does_not_commit_session_deletion() {
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
            .authorize_and_establish_for_http(
                &authorization,
                session.clone(),
                Some("Bearer workspace-one"),
                None,
                1_000,
            )
            .expect("valid request should establish");

        let access = registry
            .authorize_termination_for_http(
                &authorization,
                &session,
                Some("Bearer workspace-one"),
                None,
                1_100,
            )
            .expect("bound session should authorize termination");
        assert_eq!(
            registry.len(),
            1,
            "authorization alone must not commit deletion"
        );
        registry
            .terminate(&session, &access, 1_100)
            .expect("confirmed termination should commit deletion");
        assert!(registry.is_empty());
    }
}

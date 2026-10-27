use std::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::{body::Body, http::Response};
use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use rembrane_application::RemoteSessionDispatchGuard;
use rembrane_contracts::{RemoteSessionId, VerifiedRemoteAccess};
use tokio::sync::watch;

use crate::delivery_limits::DeliveryBudget;
use crate::{RemoteMcpResponseBudgetError, RemoteMcpResponsePermit};

/// Opaque transport errors: underlying body/driver diagnostics are not retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteMcpStreamError {
    ExpiredAuthorization,
    RevokedAuthorization,
    InvalidRevocationAuthority,
    InvalidResponsePermit,
    DeliveryLimitExceeded,
    TransportFailure,
}

impl fmt::Display for RemoteMcpStreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExpiredAuthorization => "remote response authorization expired",
            Self::RevokedAuthorization => "remote response authorization revoked",
            Self::InvalidRevocationAuthority => "remote response authority mismatch",
            Self::InvalidResponsePermit => "remote response admission authority mismatch",
            Self::DeliveryLimitExceeded => "remote response delivery limit exceeded",
            Self::TransportFailure => "remote response transport unavailable",
        })
    }
}

impl std::error::Error for RemoteMcpStreamError {}

/// Sticky, claim-bound cancellation authority for one group of responses.
///
/// The HTTP integration must connect this to real token/membership/session
/// revocation. It is not introspection. Dropping all controller clones fails
/// closed for subscribers, since their authority monitor is then unavailable.
#[derive(Clone)]
pub struct RemoteMcpStreamRevocation {
    access: VerifiedRemoteAccess,
    sender: watch::Sender<bool>,
}

/// A read-only signal bound to the controller's original verified claims.
#[derive(Clone)]
pub struct RemoteMcpStreamRevocationSignal {
    access: VerifiedRemoteAccess,
    receiver: watch::Receiver<bool>,
}

impl fmt::Debug for RemoteMcpStreamRevocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteMcpStreamRevocation(<redacted>)")
    }
}

impl fmt::Debug for RemoteMcpStreamRevocationSignal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteMcpStreamRevocationSignal(<redacted>)")
    }
}

impl RemoteMcpStreamRevocation {
    /// Creates a controller without retaining any bearer credential.
    ///
    /// # Errors
    ///
    /// Rejects an already expired proof.
    pub fn new(access: &VerifiedRemoteAccess) -> Result<Self, RemoteMcpStreamError> {
        access
            .ensure_current()
            .map_err(|_| RemoteMcpStreamError::ExpiredAuthorization)?;
        let (sender, _) = watch::channel(false);
        Ok(Self {
            access: access.clone(),
            sender,
        })
    }

    #[must_use]
    pub fn subscribe(&self) -> RemoteMcpStreamRevocationSignal {
        RemoteMcpStreamRevocationSignal {
            access: self.access.clone(),
            receiver: self.sender.subscribe(),
        }
    }

    /// Revokes existing and future subscribers. No reset/renewal API exists.
    pub fn revoke(&self) {
        self.sender.send_replace(true);
    }

    /// Waits until no signals/bodies remain, allowing an integration's authority
    /// monitor to release resources. Create subscribers before starting this
    /// wait; new subscribers must still follow the integration's admission lock.
    pub async fn closed(&self) {
        self.sender.closed().await;
    }
}

type GuardFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

// Per-body idle checking, not a spawned task or token introspection loop.
const SESSION_RECHECK_INTERVAL: Duration = Duration::from_millis(100);

struct SessionAuthorization {
    id: RemoteSessionId,
    access: VerifiedRemoteAccess,
    guard: RemoteSessionDispatchGuard,
    invalidation: GuardFuture,
}

impl SessionAuthorization {
    fn new(
        id: RemoteSessionId,
        access: &VerifiedRemoteAccess,
        guard: RemoteSessionDispatchGuard,
    ) -> Result<Self, RemoteMcpStreamError> {
        guard
            .ensure_current(&id, access)
            .map_err(|_| RemoteMcpStreamError::RevokedAuthorization)?;
        let monitor_id = id.clone();
        let monitor_access = access.clone();
        let monitor_guard = guard.clone();
        let invalidation = Box::pin(async move {
            loop {
                tokio::time::sleep(SESSION_RECHECK_INTERVAL).await;
                if monitor_guard
                    .ensure_current(&monitor_id, &monitor_access)
                    .is_err()
                {
                    return;
                }
            }
        });
        Ok(Self {
            id,
            access: access.clone(),
            guard,
            invalidation,
        })
    }

    fn is_denied(&mut self, context: &mut Context<'_>) -> bool {
        self.guard.ensure_current(&self.id, &self.access).is_err()
            || self.invalidation.as_mut().poll(context).is_ready()
    }
}

struct StreamAuthorization {
    deadline: Instant,
    expiry: GuardFuture,
    revocation: GuardFuture,
    session: Option<SessionAuthorization>,
}

impl StreamAuthorization {
    fn poll_denial(&mut self, context: &mut Context<'_>) -> Option<RemoteMcpStreamError> {
        if Instant::now() >= self.deadline || self.expiry.as_mut().poll(context).is_ready() {
            return Some(RemoteMcpStreamError::ExpiredAuthorization);
        }
        if self.revocation.as_mut().poll(context).is_ready() {
            return Some(RemoteMcpStreamError::RevokedAuthorization);
        }
        if self
            .session
            .as_mut()
            .is_some_and(|session| session.is_denied(context))
        {
            return Some(RemoteMcpStreamError::RevokedAuthorization);
        }
        None
    }
}

/// Stops forwarding every kind of HTTP frame after expiry or revocation.
///
/// Polling requires a Tokio runtime with its timer driver enabled. The original
/// proof/controller deadlines are never renewed. Pending bodies are woken by
/// the deadline or revocation signal, even when no provider event arrives.
pub struct RemoteMcpGuardedBody {
    body: Option<Body>,
    authorization: Option<StreamAuthorization>,
    permit: Option<RemoteMcpResponsePermit>,
    delivery: Option<DeliveryBudget>,
}

// Own cleanup while discarding a rejected frame/error. If its destructor
// unwinds, this owner's Drop still destroys the body with admission retained.
struct ResponseCleanup {
    body: Option<Body>,
    permit: Option<RemoteMcpResponsePermit>,
}

impl Drop for ResponseCleanup {
    fn drop(&mut self) {
        let body = self.body.take();
        let permit = self.permit.take();
        drop(body);
        drop(permit);
    }
}

impl fmt::Debug for RemoteMcpGuardedBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteMcpGuardedBody")
            .field("active", &self.body.is_some())
            .finish_non_exhaustive()
    }
}

impl RemoteMcpGuardedBody {
    /// Wraps a response body with non-renewable, claim-bound delivery authority.
    ///
    /// # Errors
    ///
    /// Rejects foreign claims, expired proof/controller authority, already
    /// revoked signals, or a lost controller before returning a usable body.
    pub fn new(
        body: Body,
        access: &VerifiedRemoteAccess,
        signal: RemoteMcpStreamRevocationSignal,
    ) -> Result<Self, RemoteMcpStreamError> {
        Self::construct(body, access, signal, None)
    }

    /// Transfers admission reserved before dispatch into response ownership.
    /// Capacity remains held through actual provider-body teardown, including
    /// rejected construction, consumer cancellation, and destructor unwinding.
    ///
    /// # Errors
    ///
    /// Rejects invalid delivery authority or a foreign/expired reservation.
    pub fn new_with_permit(
        body: Body,
        access: &VerifiedRemoteAccess,
        signal: RemoteMcpStreamRevocationSignal,
        permit: RemoteMcpResponsePermit,
    ) -> Result<Self, RemoteMcpStreamError> {
        Self::construct(body, access, signal, Some(permit))
    }

    fn construct(
        body: Body,
        access: &VerifiedRemoteAccess,
        signal: RemoteMcpStreamRevocationSignal,
        permit: Option<RemoteMcpResponsePermit>,
    ) -> Result<Self, RemoteMcpStreamError> {
        // Establish teardown ownership before any validation that can reject.
        let delivery = permit
            .as_ref()
            .and_then(RemoteMcpResponsePermit::delivery_limits)
            .map(DeliveryBudget::new);
        let mut guarded = Self {
            body: Some(body),
            authorization: None,
            permit,
            delivery,
        };
        guarded.authorization = Some(Self::authorize_body(
            access,
            signal,
            guarded.permit.as_ref(),
        )?);
        Ok(guarded)
    }

    fn authorize_body(
        access: &VerifiedRemoteAccess,
        signal: RemoteMcpStreamRevocationSignal,
        permit: Option<&RemoteMcpResponsePermit>,
    ) -> Result<StreamAuthorization, RemoteMcpStreamError> {
        // Consuming the signal in this call closes it before rejected
        // construction runs the provider destructor.
        if let Some(permit) = permit {
            permit.ensure_current_for(access).map_err(|error| {
                if error == RemoteMcpResponseBudgetError::ExpiredAuthorization {
                    RemoteMcpStreamError::ExpiredAuthorization
                } else {
                    RemoteMcpStreamError::InvalidResponsePermit
                }
            })?;
        }
        if signal.access != *access {
            return Err(RemoteMcpStreamError::InvalidRevocationAuthority);
        }
        access
            .ensure_current()
            .and_then(|()| signal.access.ensure_current())
            .map_err(|_| RemoteMcpStreamError::ExpiredAuthorization)?;
        if signal.receiver.has_changed().is_err() || *signal.receiver.borrow() {
            return Err(RemoteMcpStreamError::RevokedAuthorization);
        }
        let mut deadline = access
            .validity_deadline()
            .min(signal.access.validity_deadline());
        if let Some(permit) = permit {
            deadline = deadline.min(permit.deadline());
        }
        let mut receiver = signal.receiver;
        let revocation = Box::pin(async move {
            loop {
                let revoked = *receiver.borrow_and_update();
                if revoked || receiver.changed().await.is_err() {
                    return;
                }
            }
        });
        let expiry = Box::pin(async move {
            tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
        });
        Ok(StreamAuthorization {
            deadline,
            expiry,
            revocation,
            session: None,
        })
    }

    /// Adds exact local-session authority to the existing claim-bound guard.
    ///
    /// Every frame is checked before and after provider polling. Idle bodies
    /// recheck the captured incarnation/latest shortened deadline every 100 ms
    /// while polled, without spawning a task or touching the global registry.
    /// Token/membership revocation still requires the supplied live controller.
    ///
    /// # Errors
    ///
    /// Rejects invalid base authority or removed/expired/substituted session
    /// authority before returning a usable body.
    pub fn new_with_session(
        body: Body,
        access: &VerifiedRemoteAccess,
        signal: RemoteMcpStreamRevocationSignal,
        session_id: RemoteSessionId,
        session_guard: RemoteSessionDispatchGuard,
    ) -> Result<Self, RemoteMcpStreamError> {
        Self::new(body, access, signal)?.with_session(access, session_id, session_guard)
    }

    /// Composes reserved response capacity and exact local-session authority.
    ///
    /// # Errors
    ///
    /// Rejects invalid delivery/session authority or reservation binding.
    pub fn new_with_session_and_permit(
        body: Body,
        access: &VerifiedRemoteAccess,
        signal: RemoteMcpStreamRevocationSignal,
        session_id: RemoteSessionId,
        session_guard: RemoteSessionDispatchGuard,
        permit: RemoteMcpResponsePermit,
    ) -> Result<Self, RemoteMcpStreamError> {
        Self::new_with_permit(body, access, signal, permit)?.with_session(
            access,
            session_id,
            session_guard,
        )
    }

    fn with_session(
        mut self,
        access: &VerifiedRemoteAccess,
        session_id: RemoteSessionId,
        session_guard: RemoteSessionDispatchGuard,
    ) -> Result<Self, RemoteMcpStreamError> {
        let session = SessionAuthorization::new(session_id, access, session_guard)?;
        self.authorization
            .as_mut()
            .ok_or(RemoteMcpStreamError::TransportFailure)?
            .session = Some(session);
        Ok(self)
    }

    fn finish(&mut self) {
        self.finish_with_discard(());
    }

    fn finish_with_discard<Resource>(&mut self, resource: Resource) {
        let cleanup = ResponseCleanup {
            body: self.body.take(),
            permit: self.permit.take(),
        };
        // Close all authority before any untrusted destructor runs. Cleanup
        // ownership survives a discarded-resource panic without returning
        // quota before body teardown or retaining a half-open wrapper.
        self.authorization = None;
        self.delivery = None;
        drop(resource);
        drop(cleanup);
    }

    fn deny(
        &mut self,
        error: RemoteMcpStreamError,
    ) -> Poll<Option<Result<Frame<Bytes>, RemoteMcpStreamError>>> {
        self.deny_after_discard(error, ())
    }

    fn deny_after_discard<Resource>(
        &mut self,
        error: RemoteMcpStreamError,
        resource: Resource,
    ) -> Poll<Option<Result<Frame<Bytes>, RemoteMcpStreamError>>> {
        self.finish_with_discard(resource);
        Poll::Ready(Some(Err(error)))
    }
}

impl Drop for RemoteMcpGuardedBody {
    fn drop(&mut self) {
        self.finish();
    }
}

impl HttpBody for RemoteMcpGuardedBody {
    type Data = Bytes;
    type Error = RemoteMcpStreamError;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let Some(authorization) = this.authorization.as_mut() else {
            return Poll::Ready(None);
        };
        if let Some(error) = authorization.poll_denial(context) {
            return this.deny(error);
        }
        let result = Pin::new(this.body.as_mut().expect("active authorization has a body"))
            .poll_frame(context);
        // A body may revoke authority or consume the remaining lifetime while
        // being polled. Never forward even its final frame without rechecking.
        if let Some(error) = this
            .authorization
            .as_mut()
            .expect("authorization remains active while polling")
            .poll_denial(context)
        {
            return this.deny_after_discard(error, result);
        }
        match result {
            Poll::Ready(Some(Err(error))) => {
                this.deny_after_discard(RemoteMcpStreamError::TransportFailure, error)
            }
            Poll::Ready(None) => {
                this.finish();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Ok(frame))) => {
                let exceeded = this
                    .delivery
                    .as_mut()
                    .is_some_and(|delivery| delivery.admit(&frame).is_err());
                // Accounting is bounded by configured metadata/frame limits,
                // but can still consume time. Recheck authority before
                // exposing data, even when accounting itself rejected it.
                if let Some(error) = this
                    .authorization
                    .as_mut()
                    .expect("authorization remains active during accounting")
                    .poll_denial(context)
                {
                    return this.deny_after_discard(error, frame);
                }
                if exceeded {
                    return this
                        .deny_after_discard(RemoteMcpStreamError::DeliveryLimitExceeded, frame);
                }
                // HTTP consumers may stop polling after an end-marked final
                // frame. Release monitor/provider ownership now, not only
                // after a subsequent EOF poll that may never happen.
                if this.body.as_ref().is_some_and(HttpBody::is_end_stream) {
                    this.finish();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.as_ref().is_none_or(HttpBody::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        let hint = self
            .body
            .as_ref()
            .map_or_else(|| SizeHint::with_exact(0), HttpBody::size_hint);
        self.delivery
            .as_ref()
            .map_or(hint, |delivery| delivery.size_hint(&hint))
    }
}

/// Preserves status and headers while enforcing authority on response delivery.
///
/// SDK initialization callers must retain exact session cleanup ownership and
/// compensate a successfully created session if wrapping is rejected. This
/// helper does not manage SDK sessions or replace per-operation authorization.
///
/// # Errors
///
/// Returns the guarded body's fail-closed construction error.
pub fn guard_remote_mcp_response(
    response: Response<Body>,
    access: &VerifiedRemoteAccess,
    signal: RemoteMcpStreamRevocationSignal,
) -> Result<Response<Body>, RemoteMcpStreamError> {
    let (parts, body) = response.into_parts();
    let body = RemoteMcpGuardedBody::new(body, access, signal)?;
    Ok(Response::from_parts(parts, Body::new(body)))
}

/// Composes token/controller and exact local-session response authority.
///
/// Use for established-session memory/event delivery, not a DELETE
/// confirmation whose binding was intentionally removed. This does not
/// terminate SDK sessions, connect external revocation, or prove HTTP wiring.
///
/// # Errors
///
/// Returns opaque body-construction rejection. Initialization callers must
/// retain exact cleanup ownership if an already created SDK session is rejected.
pub fn guard_remote_mcp_session_response(
    response: Response<Body>,
    access: &VerifiedRemoteAccess,
    signal: RemoteMcpStreamRevocationSignal,
    session_id: RemoteSessionId,
    session_guard: RemoteSessionDispatchGuard,
) -> Result<Response<Body>, RemoteMcpStreamError> {
    let (parts, body) = response.into_parts();
    let body =
        RemoteMcpGuardedBody::new_with_session(body, access, signal, session_id, session_guard)?;
    Ok(Response::from_parts(parts, Body::new(body)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, StatusCode};
    use rembrane_contracts::{RemoteAccessScope, RemoteTokenClaims};
    use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};
    use std::{
        collections::{BTreeSet, VecDeque},
        future::poll_fn,
        io,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    fn fixture_claims(workspace: &str) -> RemoteTokenClaims {
        RemoteTokenClaims {
            issuer: "https://private-issuer.example".to_owned(),
            audience: vec!["https://private-resource.example/mcp".to_owned()],
            subject_id: PrincipalId::new("private-principal"),
            client_id: ClientId::new("private-client"),
            workspace_id: WorkspaceId::new(workspace),
            scopes: BTreeSet::from([RemoteAccessScope::ContextRead]),
            expires_at_epoch_seconds: 1_100,
            not_before_epoch_seconds: None,
        }
    }

    fn access(workspace: &str) -> VerifiedRemoteAccess {
        fixture_claims(workspace)
            .validate_connection(
                "https://private-issuer.example",
                "https://private-resource.example/mcp",
                1_000,
            )
            .expect("fixture proof")
    }

    struct FixtureBody {
        frames: VecDeque<Frame<Bytes>>,
        pending: bool,
        error: Option<io::Error>,
        on_poll: Option<Box<dyn FnOnce() + Send>>,
        on_drop: Option<Box<dyn FnOnce() + Send>>,
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
        end_when_empty: bool,
        advertised_hint: Option<SizeHint>,
    }

    impl FixtureBody {
        fn new(frames: Vec<Frame<Bytes>>, pending: bool) -> Self {
            Self {
                frames: frames.into(),
                pending,
                error: None,
                on_poll: None,
                on_drop: None,
                polls: Arc::new(AtomicUsize::new(0)),
                drops: Arc::new(AtomicUsize::new(0)),
                end_when_empty: false,
                advertised_hint: None,
            }
        }
    }

    impl Drop for FixtureBody {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
            if let Some(on_drop) = self.on_drop.take() {
                on_drop();
            }
        }
    }

    impl HttpBody for FixtureBody {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
            let this = self.get_mut();
            this.polls.fetch_add(1, Ordering::SeqCst);
            if let Some(on_poll) = this.on_poll.take() {
                on_poll();
            }
            if let Some(error) = this.error.take() {
                return Poll::Ready(Some(Err(error)));
            }
            if let Some(frame) = this.frames.pop_front() {
                return Poll::Ready(Some(Ok(frame)));
            }
            if this.pending {
                Poll::Pending
            } else {
                Poll::Ready(None)
            }
        }

        fn is_end_stream(&self) -> bool {
            self.end_when_empty && self.frames.is_empty() && !self.pending && self.error.is_none()
        }

        fn size_hint(&self) -> SizeHint {
            self.advertised_hint.unwrap_or_default()
        }
    }

    struct FixtureOwnedBytes {
        data: &'static [u8],
        on_drop: Option<Box<dyn FnOnce() + Send>>,
    }

    impl AsRef<[u8]> for FixtureOwnedBytes {
        fn as_ref(&self) -> &[u8] {
            self.data
        }
    }

    impl Drop for FixtureOwnedBytes {
        fn drop(&mut self) {
            if let Some(callback) = self.on_drop.take() {
                callback();
            }
        }
    }

    struct FixtureDriverError {
        on_drop: Option<Box<dyn FnOnce() + Send + Sync>>,
    }

    impl fmt::Debug for FixtureDriverError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("FixtureDriverError(<redacted>)")
        }
    }

    impl fmt::Display for FixtureDriverError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("private provider diagnostic")
        }
    }

    impl std::error::Error for FixtureDriverError {}

    impl Drop for FixtureDriverError {
        fn drop(&mut self) {
            if let Some(callback) = self.on_drop.take() {
                callback();
            }
        }
    }

    async fn next(
        body: &mut RemoteMcpGuardedBody,
    ) -> Option<Result<Frame<Bytes>, RemoteMcpStreamError>> {
        poll_fn(|context| Pin::new(&mut *body).poll_frame(context)).await
    }

    fn session_fixture() -> (
        rembrane_application::RemoteSessionRegistry,
        RemoteSessionId,
        VerifiedRemoteAccess,
        RemoteSessionDispatchGuard,
    ) {
        let mut registry = rembrane_application::RemoteSessionRegistry::new(2).unwrap();
        let id = RemoteSessionId::new("response-session-identity").unwrap();
        let mut proof = access("workspace-owner");
        registry.establish(id.clone(), &proof, 1_000).unwrap();
        let guard = registry
            .capture_dispatch_guard(&id, &mut proof, 1_000)
            .unwrap();
        (registry, id, proof, guard)
    }

    #[tokio::test]
    async fn rejected_provider_objects_close_authority_before_teardown_and_retain_quota() {
        use crate::{
            RemoteMcpDeliveryLimits, RemoteMcpResponseBudget, RemoteMcpResponseBudgetError,
        };

        for case in ["transport-error", "revoked", "limit"] {
            let proof = access("owner");
            let limits = RemoteMcpDeliveryLimits::new(1, 1, 0, 0, 1).unwrap();
            let budget = RemoteMcpResponseBudget::new_with_delivery_limits(1, 1, limits).unwrap();
            let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
            let observer = controller.clone();
            let resource_budget = budget.clone();
            let resource_proof = proof.clone();
            let mut fixture = FixtureBody::new(vec![], false);
            let body_drops = fixture.drops.clone();
            let body_drops_at_discard = body_drops.clone();
            let callback = move || {
                assert_eq!(
                    observer.sender.receiver_count(),
                    0,
                    "authority must close before discarded resources"
                );
                assert_eq!(
                    resource_budget.reserve(&resource_proof).unwrap_err(),
                    RemoteMcpResponseBudgetError::Exhausted,
                    "quota must survive discarded resources"
                );
                assert_eq!(body_drops_at_discard.load(Ordering::SeqCst), 0);
            };
            if case == "transport-error" {
                fixture.error = Some(io::Error::other(FixtureDriverError {
                    on_drop: Some(Box::new(callback)),
                }));
            } else {
                fixture
                    .frames
                    .push_back(Frame::data(Bytes::from_owner(FixtureOwnedBytes {
                        data: b"private-frame",
                        on_drop: Some(Box::new(callback)),
                    })));
            }
            if case == "revoked" {
                let revoke = controller.clone();
                fixture.on_poll = Some(Box::new(move || revoke.revoke()));
            }
            let mut body = RemoteMcpGuardedBody::new_with_permit(
                Body::new(fixture),
                &proof,
                controller.subscribe(),
                budget.reserve(&proof).unwrap(),
            )
            .unwrap();
            let error = next(&mut body).await.unwrap().unwrap_err();
            assert_eq!(
                error,
                match case {
                    "limit" => RemoteMcpStreamError::DeliveryLimitExceeded,
                    "revoked" => RemoteMcpStreamError::RevokedAuthorization,
                    _ => RemoteMcpStreamError::TransportFailure,
                }
            );
            assert!(!error.to_string().contains("private"));
            assert_eq!(body_drops.load(Ordering::SeqCst), 1);
            assert!(next(&mut body).await.is_none());
            assert!(budget.reserve(&proof).is_ok());
        }
    }

    #[test]
    fn blocked_discard_keeps_capacity_through_frame_or_error_and_body_destruction() {
        use crate::{
            RemoteMcpDeliveryLimits, RemoteMcpResponseBudget, RemoteMcpResponseBudgetError,
        };

        for case in ["frame", "error"] {
            let proof = access("owner");
            let limits = RemoteMcpDeliveryLimits::new(1, 1, 0, 0, 1).unwrap();
            let budget = RemoteMcpResponseBudget::new_with_delivery_limits(2, 1, limits).unwrap();
            let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
            let (entered, observed) = std::sync::mpsc::channel();
            let (release, resume) = std::sync::mpsc::channel();
            let resume = std::sync::Mutex::new(resume);
            let mut fixture = FixtureBody::new(vec![], false);
            let drops = fixture.drops.clone();
            let callback = move || {
                entered.send(()).unwrap();
                resume
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap();
            };
            if case == "frame" {
                fixture
                    .frames
                    .push_back(Frame::data(Bytes::from_owner(FixtureOwnedBytes {
                        data: b"oversized",
                        on_drop: Some(Box::new(callback)),
                    })));
            } else {
                fixture.error = Some(io::Error::other(FixtureDriverError {
                    on_drop: Some(Box::new(callback)),
                }));
            }
            let mut body = RemoteMcpGuardedBody::new_with_permit(
                Body::new(fixture),
                &proof,
                controller.subscribe(),
                budget.reserve(&proof).unwrap(),
            )
            .unwrap();
            let worker = std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                    .unwrap()
                    .block_on(async move { next(&mut body).await.unwrap().unwrap_err() })
            });
            observed.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(controller.sender.receiver_count(), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 0);
            assert_eq!(
                budget.reserve(&proof).unwrap_err(),
                RemoteMcpResponseBudgetError::Exhausted
            );
            let unrelated = budget.reserve(&access("another-workspace")).unwrap();
            release.send(()).unwrap();
            assert_eq!(
                worker.join().unwrap(),
                if case == "frame" {
                    RemoteMcpStreamError::DeliveryLimitExceeded
                } else {
                    RemoteMcpStreamError::TransportFailure
                }
            );
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert!(budget.reserve(&proof).is_ok());
            drop(unrelated);
        }
    }

    #[tokio::test]
    async fn discard_unwind_still_destroys_provider_body_and_returns_quota() {
        use crate::{RemoteMcpDeliveryLimits, RemoteMcpResponseBudget};

        for case in ["frame", "error"] {
            let proof = access("owner");
            let limits = RemoteMcpDeliveryLimits::new(1, 1, 0, 0, 1).unwrap();
            let budget = RemoteMcpResponseBudget::new_with_delivery_limits(1, 1, limits).unwrap();
            let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
            let mut fixture = FixtureBody::new(vec![], false);
            let drops = fixture.drops.clone();
            let callback = || panic!("fixture discarded resource failure");
            if case == "frame" {
                fixture
                    .frames
                    .push_back(Frame::data(Bytes::from_owner(FixtureOwnedBytes {
                        data: b"oversized",
                        on_drop: Some(Box::new(callback)),
                    })));
            } else {
                fixture.error = Some(io::Error::other(FixtureDriverError {
                    on_drop: Some(Box::new(callback)),
                }));
            }
            let mut body = RemoteMcpGuardedBody::new_with_permit(
                Body::new(fixture),
                &proof,
                controller.subscribe(),
                budget.reserve(&proof).unwrap(),
            )
            .unwrap();
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut context = Context::from_waker(std::task::Waker::noop());
                    Pin::new(&mut body).poll_frame(&mut context)
                }))
                .is_err()
            );
            assert_eq!(controller.sender.receiver_count(), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert!(body.is_end_stream());
            assert!(next(&mut body).await.is_none());
            assert!(budget.reserve(&proof).is_ok());
        }
    }

    #[tokio::test]
    async fn reserved_delivery_policy_denies_oversize_and_cumulative_frames() {
        use crate::{
            RemoteMcpDeliveryLimits, RemoteMcpResponseBudget, RemoteMcpResponseBudgetError,
        };

        for case in [
            "data-frame",
            "total-data",
            "trailer-bytes",
            "trailer-fields",
            "total-trailer-bytes",
            "total-trailer-fields",
            "empty-frames",
        ] {
            let proof = access("owner");
            let limits = RemoteMcpDeliveryLimits::new(4, 6, 6, 2, 4).unwrap();
            let budget = RemoteMcpResponseBudget::new_with_delivery_limits(1, 1, limits).unwrap();
            let permit = budget.reserve(&proof).unwrap();
            let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
            let (frames, allowed) = match case {
                "data-frame" => (vec![Frame::data(Bytes::from_static(b"12345"))], 0),
                "total-data" => (
                    vec![
                        Frame::data(Bytes::from_static(b"1234")),
                        Frame::data(Bytes::from_static(b"12")),
                        Frame::data(Bytes::from_static(b"x")),
                    ],
                    2,
                ),
                "trailer-bytes" => {
                    let mut trailers = HeaderMap::new();
                    trailers.insert("x", "private-provider-value".parse().unwrap());
                    (vec![Frame::trailers(trailers)], 0)
                }
                "trailer-fields" => {
                    let mut trailers = HeaderMap::new();
                    for _ in 0..3 {
                        trailers.append("x", "".parse().unwrap());
                    }
                    (vec![Frame::trailers(trailers)], 0)
                }
                "total-trailer-bytes" => {
                    let frames = ["a", "bbbb"]
                        .into_iter()
                        .map(|value| {
                            let mut trailers = HeaderMap::new();
                            trailers.insert("x", value.parse().unwrap());
                            Frame::trailers(trailers)
                        })
                        .collect();
                    (frames, 1)
                }
                "total-trailer-fields" => {
                    let frames = (0..3)
                        .map(|_| {
                            let mut trailers = HeaderMap::new();
                            trailers.insert("x", "".parse().unwrap());
                            Frame::trailers(trailers)
                        })
                        .collect();
                    (frames, 2)
                }
                _ => ((0..5).map(|_| Frame::data(Bytes::new())).collect(), 4),
            };
            let observer = controller.clone();
            let destructor_budget = budget.clone();
            let destructor_proof = proof.clone();
            let mut fixture = FixtureBody::new(frames, false);
            fixture.end_when_empty = true;
            let polls = fixture.polls.clone();
            let drops = fixture.drops.clone();
            fixture.on_drop = Some(Box::new(move || {
                assert_eq!(observer.sender.receiver_count(), 0);
                assert_eq!(
                    destructor_budget.reserve(&destructor_proof).unwrap_err(),
                    RemoteMcpResponseBudgetError::Exhausted
                );
            }));
            let mut body = RemoteMcpGuardedBody::new_with_permit(
                Body::new(fixture),
                &proof,
                controller.subscribe(),
                permit,
            )
            .unwrap();
            for _ in 0..allowed {
                assert!(next(&mut body).await.unwrap().is_ok());
            }
            let error = next(&mut body).await.unwrap().unwrap_err();
            assert_eq!(error, RemoteMcpStreamError::DeliveryLimitExceeded, "{case}");
            assert!(!error.to_string().contains("private-provider-value"));
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert!(next(&mut body).await.is_none());
            assert_eq!(polls.load(Ordering::SeqCst), allowed + 1);
            assert_eq!(body.size_hint().exact(), Some(0));
            assert!(budget.reserve(&proof).is_ok());
        }
    }

    #[tokio::test]
    async fn delivery_counters_are_per_response_and_exact_boundaries_complete() {
        use crate::{RemoteMcpDeliveryLimits, RemoteMcpResponseBudget};

        let (_registry, id, proof, guard) = session_fixture();
        let limits = RemoteMcpDeliveryLimits::new(4, 6, 0, 0, 3).unwrap();
        let budget = RemoteMcpResponseBudget::new_with_delivery_limits(2, 2, limits).unwrap();
        let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
        let mut bodies = Vec::new();
        for _ in 0..2 {
            let mut fixture = FixtureBody::new(
                vec![
                    Frame::data(Bytes::from_static(b"1234")),
                    Frame::data(Bytes::from_static(b"12")),
                    Frame::trailers(HeaderMap::new()),
                ],
                false,
            );
            fixture.end_when_empty = true;
            bodies.push(
                RemoteMcpGuardedBody::new_with_session_and_permit(
                    Body::new(fixture),
                    &proof,
                    controller.subscribe(),
                    id.clone(),
                    guard.clone(),
                    budget.clone().reserve(&proof).unwrap(),
                )
                .unwrap(),
            );
        }
        for body in &mut bodies {
            assert_eq!(body.size_hint().upper(), Some(6));
            assert!(next(body).await.unwrap().is_ok());
            assert_eq!(body.size_hint().upper(), Some(2));
            assert!(next(body).await.unwrap().is_ok());
            assert_eq!(body.size_hint().exact(), Some(0));
            assert!(next(body).await.unwrap().unwrap().is_trailers());
            assert!(next(body).await.is_none());
        }
        assert_eq!(controller.sender.receiver_count(), 0);
        let first = budget.reserve(&proof).unwrap();
        let second = budget.reserve(&proof).unwrap();
        drop((first, second));
    }

    #[tokio::test]
    async fn post_poll_revocation_wins_over_delivery_limit_failure() {
        use crate::{RemoteMcpDeliveryLimits, RemoteMcpResponseBudget};

        let proof = access("owner");
        let limits = RemoteMcpDeliveryLimits::new(1, 1, 0, 0, 1).unwrap();
        let budget = RemoteMcpResponseBudget::new_with_delivery_limits(1, 1, limits).unwrap();
        let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
        let revoke = controller.clone();
        let mut fixture =
            FixtureBody::new(vec![Frame::data(Bytes::from_static(b"too-large"))], false);
        fixture.on_poll = Some(Box::new(move || revoke.revoke()));
        let mut body = RemoteMcpGuardedBody::new_with_permit(
            Body::new(fixture),
            &proof,
            controller.subscribe(),
            budget.reserve(&proof).unwrap(),
        )
        .unwrap();
        assert_eq!(
            next(&mut body).await.unwrap().unwrap_err(),
            RemoteMcpStreamError::RevokedAuthorization
        );
        assert!(budget.reserve(&proof).is_ok());
    }

    #[tokio::test]
    async fn misleading_provider_size_hint_cannot_bypass_actual_frame_checks() {
        use crate::{RemoteMcpDeliveryLimits, RemoteMcpResponseBudget};

        let proof = access("owner");
        let limits = RemoteMcpDeliveryLimits::new(1, 1, 0, 0, 1).unwrap();
        let budget = RemoteMcpResponseBudget::new_with_delivery_limits(1, 1, limits).unwrap();
        let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
        let mut fixture = FixtureBody::new(
            vec![Frame::data(Bytes::from_static(b"larger-than-advertised"))],
            false,
        );
        fixture.advertised_hint = Some(SizeHint::with_exact(0));
        let mut body = RemoteMcpGuardedBody::new_with_permit(
            Body::new(fixture),
            &proof,
            controller.subscribe(),
            budget.reserve(&proof).unwrap(),
        )
        .unwrap();
        assert_eq!(body.size_hint().exact(), Some(0));
        assert_eq!(
            next(&mut body).await.unwrap().unwrap_err(),
            RemoteMcpStreamError::DeliveryLimitExceeded
        );
        assert!(next(&mut body).await.is_none());
        assert!(budget.reserve(&proof).is_ok());
    }

    #[tokio::test]
    async fn response_capacity_survives_every_completion_and_rejection_destructor() {
        use crate::{RemoteMcpResponseBudget, RemoteMcpResponseBudgetError};

        for completion in [
            "drop",
            "eof",
            "final-frame",
            "error",
            "revoked",
            "session-reject",
            "base-reject",
            "permit-reject",
        ] {
            let (_registry, id, owner, session_guard) = session_fixture();
            let proof = if completion == "permit-reject" {
                access("foreign-workspace")
            } else {
                owner.clone()
            };
            let budget = RemoteMcpResponseBudget::new(1, 1).unwrap();
            let permit = budget.reserve(&owner).unwrap();
            let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
            let observer = controller.clone();
            let destructor_budget = budget.clone();
            let destructor_owner = owner.clone();
            let mut fixture = FixtureBody::new(
                if completion == "final-frame" {
                    vec![Frame::data(Bytes::from_static(b"final"))]
                } else {
                    vec![]
                },
                matches!(
                    completion,
                    "drop" | "revoked" | "session-reject" | "base-reject" | "permit-reject"
                ),
            );
            fixture.end_when_empty = completion == "final-frame";
            if completion == "error" {
                fixture.error = Some(io::Error::other("private fixture error"));
            }
            let drops = fixture.drops.clone();
            fixture.on_drop = Some(Box::new(move || {
                assert_eq!(observer.sender.receiver_count(), 0);
                assert_eq!(
                    destructor_budget.reserve(&destructor_owner).unwrap_err(),
                    RemoteMcpResponseBudgetError::Exhausted,
                    "capacity must survive provider teardown"
                );
            }));
            if completion == "base-reject" {
                controller.revoke();
            }
            let result = RemoteMcpGuardedBody::new_with_session_and_permit(
                Body::new(fixture),
                &proof,
                controller.subscribe(),
                if completion == "session-reject" {
                    RemoteSessionId::new("foreign-response-session").unwrap()
                } else {
                    id
                },
                session_guard,
                permit,
            );
            if completion.ends_with("-reject") {
                assert!(result.is_err());
            } else {
                let mut guarded = result.unwrap();
                if completion == "revoked" {
                    controller.revoke();
                }
                match completion {
                    "drop" => {}
                    "final-frame" => assert!(next(&mut guarded).await.unwrap().is_ok()),
                    "eof" => assert!(next(&mut guarded).await.is_none()),
                    _ => assert!(next(&mut guarded).await.unwrap().is_err()),
                }
                if completion != "drop" {
                    // Capacity returns at completion, even if the consumer
                    // retains the closed wrapper without an extra EOF poll.
                    assert!(budget.reserve(&owner).is_ok());
                }
                drop(guarded);
            }
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert!(budget.reserve(&owner).is_ok());
        }
    }

    #[tokio::test]
    async fn response_capacity_remains_held_during_provider_poll() {
        use crate::{RemoteMcpResponseBudget, RemoteMcpResponseBudgetError};

        let proof = access("owner");
        let budget = RemoteMcpResponseBudget::new(1, 1).unwrap();
        let permit = budget.reserve(&proof).unwrap();
        let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
        let observer = budget.clone();
        let poll_proof = proof.clone();
        let mut fixture = FixtureBody::new(vec![], false);
        fixture.on_poll = Some(Box::new(move || {
            assert_eq!(
                observer.reserve(&poll_proof).unwrap_err(),
                RemoteMcpResponseBudgetError::Exhausted
            );
        }));
        let mut body = RemoteMcpGuardedBody::new_with_permit(
            Body::new(fixture),
            &proof,
            controller.subscribe(),
            permit,
        )
        .unwrap();
        assert!(next(&mut body).await.is_none());
        assert!(budget.reserve(&proof).is_ok());
    }

    #[test]
    fn blocked_provider_teardown_retains_quota_without_blocking_other_workspace() {
        use crate::{RemoteMcpResponseBudget, RemoteMcpResponseBudgetError};

        let proof = access("owner");
        let budget = RemoteMcpResponseBudget::new(2, 1).unwrap();
        let permit = budget.reserve(&proof).unwrap();
        let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
        let (entered, observed) = std::sync::mpsc::channel();
        let (release, resume) = std::sync::mpsc::channel();
        let mut fixture = FixtureBody::new(vec![], true);
        fixture.on_drop = Some(Box::new(move || {
            entered.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(5)).unwrap();
        }));
        let guarded = RemoteMcpGuardedBody::new_with_permit(
            Body::new(fixture),
            &proof,
            controller.subscribe(),
            permit,
        )
        .unwrap();
        let teardown = std::thread::spawn(move || drop(guarded));
        observed.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(controller.sender.receiver_count(), 0);
        assert_eq!(
            budget.reserve(&proof).unwrap_err(),
            RemoteMcpResponseBudgetError::Exhausted
        );
        let unrelated = budget.reserve(&access("another-workspace")).unwrap();
        release.send(()).unwrap();
        teardown.join().unwrap();
        assert!(budget.reserve(&proof).is_ok());
        drop(unrelated);
    }

    #[test]
    fn provider_destructor_unwinding_returns_capacity_and_closes_authority() {
        use crate::RemoteMcpResponseBudget;

        let proof = access("owner");
        let budget = RemoteMcpResponseBudget::new(1, 1).unwrap();
        let permit = budget.reserve(&proof).unwrap();
        let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
        let mut fixture = FixtureBody::new(vec![], true);
        fixture.on_drop = Some(Box::new(|| panic!("fixture provider teardown")));
        let guarded = RemoteMcpGuardedBody::new_with_permit(
            Body::new(fixture),
            &proof,
            controller.subscribe(),
            permit,
        )
        .unwrap();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(guarded))).is_err());
        assert_eq!(controller.sender.receiver_count(), 0);
        assert!(budget.reserve(&proof).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn reservation_deadline_cannot_be_renewed_by_same_claims_response_proof() {
        use crate::RemoteMcpResponseBudget;

        let proof = access("owner");
        let mut short = proof.clone();
        short.constrain_validity(Instant::now(), 1_099).unwrap();
        let budget = RemoteMcpResponseBudget::new(1, 1).unwrap();
        let permit = budget.reserve(&short).unwrap();
        let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
        let fixture = FixtureBody::new(vec![], true);
        let drops = fixture.drops.clone();
        let mut body = RemoteMcpGuardedBody::new_with_permit(
            Body::new(fixture),
            &proof,
            controller.subscribe(),
            permit,
        )
        .unwrap();
        let waiting = next(&mut body);
        tokio::pin!(waiting);
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(
            waiting.await.unwrap().unwrap_err(),
            RemoteMcpStreamError::ExpiredAuthorization
        );
        assert!(proof.ensure_current().is_ok());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(budget.reserve(&proof).is_ok());
    }

    #[test]
    fn consumer_drop_releases_authority_before_provider_destructor() {
        for completion in ["drop", "base-reject", "session-reject"] {
            let (_registry, _id, proof, guard) = session_fixture();
            let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
            let observer = controller.clone();
            let mut fixture = FixtureBody::new(vec![], true);
            fixture.on_drop = Some(Box::new(move || {
                assert_eq!(
                    observer.sender.receiver_count(),
                    0,
                    "authority must close before provider teardown"
                );
            }));
            if completion == "session-reject" {
                assert!(
                    RemoteMcpGuardedBody::new_with_session(
                        Body::new(fixture),
                        &proof,
                        controller.subscribe(),
                        RemoteSessionId::new("foreign-response-session").unwrap(),
                        guard,
                    )
                    .is_err()
                );
            } else if completion == "base-reject" {
                assert!(
                    RemoteMcpGuardedBody::new(
                        Body::new(fixture),
                        &access("workspace-other"),
                        controller.subscribe(),
                    )
                    .is_err()
                );
            } else {
                let body =
                    RemoteMcpGuardedBody::new(Body::new(fixture), &proof, controller.subscribe())
                        .unwrap();
                drop(body);
            }
        }
    }

    #[tokio::test]
    async fn session_removal_blocks_remaining_frames_despite_same_claims_replacement() {
        let (mut registry, id, proof, guard) = session_fixture();
        let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
        let fixture = FixtureBody::new(
            vec![
                Frame::data(Bytes::from_static(b"before")),
                Frame::data(Bytes::from_static(b"private-after")),
            ],
            false,
        );
        let polls = Arc::clone(&fixture.polls);
        let drops = Arc::clone(&fixture.drops);
        let mut body = RemoteMcpGuardedBody::new_with_session(
            Body::new(fixture),
            &proof,
            controller.subscribe(),
            id.clone(),
            guard,
        )
        .unwrap();
        assert_eq!(
            next(&mut body).await.unwrap().unwrap().into_data().unwrap(),
            "before"
        );
        registry.terminate(&id, &proof, 1_000).unwrap();
        registry.establish(id, &proof, 1_000).unwrap();
        assert_eq!(
            next(&mut body).await.unwrap().unwrap_err(),
            RemoteMcpStreamError::RevokedAuthorization
        );
        assert!(next(&mut body).await.is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        controller.closed().await;
    }

    #[tokio::test(start_paused = true)]
    async fn session_invalidation_wakes_idle_bodies_without_provider_events() {
        for removal in ["delete", "rollback", "prune", "drop"] {
            let (mut registry, id, proof, guard) = session_fixture();
            let mutation = registry.capture_mutation_guard(&id, &proof, 1_000).unwrap();
            let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
            let fixture = FixtureBody::new(vec![], true);
            let polls = Arc::clone(&fixture.polls);
            let drops = Arc::clone(&fixture.drops);
            let mut body = RemoteMcpGuardedBody::new_with_session(
                Body::new(fixture),
                &proof,
                controller.subscribe(),
                id.clone(),
                guard,
            )
            .unwrap();
            let task = tokio::spawn(async move { next(&mut body).await.unwrap().unwrap_err() });
            tokio::task::yield_now().await;
            assert_eq!(polls.load(Ordering::SeqCst), 1);
            match removal {
                "delete" => registry.terminate(&id, &proof, 1_000).unwrap(),
                "rollback" => registry.rollback_establishment(&mutation, &proof).unwrap(),
                "prune" => registry.prune_expired(proof.expires_at_epoch_seconds()),
                "drop" => drop(registry),
                _ => unreachable!(),
            }
            tokio::time::advance(SESSION_RECHECK_INTERVAL).await;
            assert_eq!(
                task.await.unwrap(),
                RemoteMcpStreamError::RevokedAuthorization
            );
            assert_eq!(polls.load(Ordering::SeqCst), 1);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            controller.closed().await;
        }
    }

    #[tokio::test]
    async fn shortened_session_ceiling_wakes_idle_delivery_with_original_proof_still_current() {
        let (mut registry, id, proof, guard) = session_fixture();
        let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
        let started = Arc::new(tokio::sync::Notify::new());
        let observed = Arc::clone(&started);
        let mut fixture = FixtureBody::new(vec![], true);
        fixture.on_poll = Some(Box::new(move || observed.notify_one()));
        let drops = Arc::clone(&fixture.drops);
        let mut body = RemoteMcpGuardedBody::new_with_session(
            Body::new(fixture),
            &proof,
            controller.subscribe(),
            id.clone(),
            guard,
        )
        .unwrap();
        let task = tokio::spawn(async move { next(&mut body).await.unwrap().unwrap_err() });
        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .unwrap();
        let mut shorter = proof.clone();
        shorter
            .constrain_validity(
                Instant::now()
                    .checked_sub(Duration::from_millis(800))
                    .unwrap(),
                shorter.expires_at_epoch_seconds() - 1,
            )
            .unwrap();
        registry
            .revalidate_access(&id, &mut shorter, 1_000)
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap(),
            RemoteMcpStreamError::RevokedAuthorization
        );
        assert!(proof.ensure_current().is_ok());
        assert_eq!(registry.len(), 1); // No prune or fresh dispatch capture was required.
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        controller.closed().await;
    }

    #[tokio::test]
    async fn session_removal_during_provider_poll_discards_data_and_trailers() {
        for trailers in [false, true] {
            let (registry, id, proof, guard) = session_fixture();
            let registry = Arc::new(std::sync::Mutex::new(registry));
            let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
            let frame = if trailers {
                let mut headers = HeaderMap::new();
                headers.insert("private-data", "must-not-forward".parse().unwrap());
                Frame::trailers(headers)
            } else {
                Frame::data(Bytes::from_static(b"must-not-forward"))
            };
            let mut fixture = FixtureBody::new(vec![frame], false);
            let changed_registry = Arc::clone(&registry);
            let changed_id = id.clone();
            let changed_proof = proof.clone();
            fixture.on_poll = Some(Box::new(move || {
                let mut registry = changed_registry.lock().unwrap();
                registry
                    .terminate(&changed_id, &changed_proof, 1_000)
                    .unwrap();
                registry
                    .establish(changed_id, &changed_proof, 1_000)
                    .unwrap();
            }));
            let drops = Arc::clone(&fixture.drops);
            let mut body = RemoteMcpGuardedBody::new_with_session(
                Body::new(fixture),
                &proof,
                controller.subscribe(),
                id,
                guard,
            )
            .unwrap();
            assert_eq!(
                next(&mut body).await.unwrap().unwrap_err(),
                RemoteMcpStreamError::RevokedAuthorization
            );
            assert!(next(&mut body).await.is_none());
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(registry.lock().unwrap().len(), 1);
            controller.closed().await;
        }
    }

    #[test]
    fn session_body_construction_rejects_removed_and_substituted_authority_without_polling() {
        for substitution in ["session", "proof", "removed"] {
            let (mut registry, id, proof, guard) = session_fixture();
            if substitution == "removed" {
                registry.terminate(&id, &proof, 1_000).unwrap();
            }
            let id = if substitution == "session" {
                RemoteSessionId::new("foreign-response-session").unwrap()
            } else {
                id
            };
            let proof = if substitution == "proof" {
                access("workspace-other")
            } else {
                proof
            };
            let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
            let fixture =
                FixtureBody::new(vec![Frame::data(Bytes::from_static(b"private"))], false);
            let polls = Arc::clone(&fixture.polls);
            let drops = Arc::clone(&fixture.drops);
            assert_eq!(
                RemoteMcpGuardedBody::new_with_session(
                    Body::new(fixture),
                    &proof,
                    controller.subscribe(),
                    id,
                    guard,
                )
                .unwrap_err(),
                RemoteMcpStreamError::RevokedAuthorization
            );
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(controller.sender.receiver_count(), 0);
        }
    }

    #[tokio::test]
    async fn session_response_preserves_http_metadata_and_still_requires_controller_authority() {
        let (_registry, id, proof, guard) = session_fixture();
        let controller = RemoteMcpStreamRevocation::new(&proof).unwrap();
        let response = Response::builder()
            .status(StatusCode::ACCEPTED)
            .header("content-type", "text/event-stream")
            .body(Body::from("current-session-data"))
            .unwrap();
        let response = guard_remote_mcp_session_response(
            response,
            &proof,
            controller.subscribe(),
            id.clone(),
            guard.clone(),
        )
        .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 100)
                .await
                .unwrap(),
            "current-session-data"
        );
        let mut body = RemoteMcpGuardedBody::new_with_session(
            Body::from("must-not-forward"),
            &proof,
            controller.subscribe(),
            id,
            guard,
        )
        .unwrap();
        controller.revoke();
        assert_eq!(
            next(&mut body).await.unwrap().unwrap_err(),
            RemoteMcpStreamError::RevokedAuthorization
        );
        assert!(next(&mut body).await.is_none());
        controller.closed().await;
    }

    #[tokio::test]
    async fn current_authority_preserves_data_and_trailers_then_releases_body() {
        let access = access("workspace-owner");
        let controller = RemoteMcpStreamRevocation::new(&access).unwrap();
        let mut trailers = HeaderMap::new();
        trailers.insert("x-fixture", "complete".parse().unwrap());
        let fixture = FixtureBody::new(
            vec![
                Frame::data(Bytes::from_static(b"fixture-data")),
                Frame::trailers(trailers.clone()),
            ],
            false,
        );
        let drops = Arc::clone(&fixture.drops);
        let mut body =
            RemoteMcpGuardedBody::new(Body::new(fixture), &access, controller.subscribe()).unwrap();
        assert_eq!(
            next(&mut body).await.unwrap().unwrap().into_data().unwrap(),
            "fixture-data"
        );
        assert_eq!(
            next(&mut body)
                .await
                .unwrap()
                .unwrap()
                .into_trailers()
                .unwrap(),
            trailers
        );
        assert!(next(&mut body).await.is_none());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(body.is_end_stream());
        assert_eq!(body.size_hint().exact(), Some(0));
    }

    #[tokio::test]
    async fn revoked_body_forwards_no_additional_frames_and_returns_only_one_error() {
        let access = access("workspace-owner");
        let controller = RemoteMcpStreamRevocation::new(&access).unwrap();
        let fixture = FixtureBody::new(
            vec![
                Frame::data(Bytes::from_static(b"before")),
                Frame::data(Bytes::from_static(b"private-after")),
            ],
            false,
        );
        let polls = Arc::clone(&fixture.polls);
        let drops = Arc::clone(&fixture.drops);
        let mut body =
            RemoteMcpGuardedBody::new(Body::new(fixture), &access, controller.subscribe()).unwrap();
        assert_eq!(
            next(&mut body).await.unwrap().unwrap().into_data().unwrap(),
            "before"
        );
        controller.revoke();
        assert_eq!(
            next(&mut body).await.unwrap().unwrap_err(),
            RemoteMcpStreamError::RevokedAuthorization
        );
        assert!(next(&mut body).await.is_none());
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_wakes_an_idle_stream_without_polling_its_provider_again() {
        let access = access("workspace-owner");
        let controller = RemoteMcpStreamRevocation::new(&access).unwrap();
        let fixture = FixtureBody::new(vec![], true);
        let polls = Arc::clone(&fixture.polls);
        let drops = Arc::clone(&fixture.drops);
        let mut body =
            RemoteMcpGuardedBody::new(Body::new(fixture), &access, controller.subscribe()).unwrap();
        let task = tokio::spawn(async move { next(&mut body).await.unwrap().unwrap_err() });
        tokio::task::yield_now().await;
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        tokio::time::advance(Duration::from_secs(101)).await;
        assert_eq!(
            task.await.unwrap(),
            RemoteMcpStreamError::ExpiredAuthorization
        );
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn revocation_wakes_an_idle_stream_without_a_provider_event() {
        let access = access("workspace-owner");
        let controller = RemoteMcpStreamRevocation::new(&access).unwrap();
        let fixture = FixtureBody::new(vec![], true);
        let drops = Arc::clone(&fixture.drops);
        let mut body =
            RemoteMcpGuardedBody::new(Body::new(fixture), &access, controller.subscribe()).unwrap();
        let task = tokio::spawn(async move { next(&mut body).await.unwrap().unwrap_err() });
        tokio::task::yield_now().await;
        controller.revoke();
        assert_eq!(
            task.await.unwrap(),
            RemoteMcpStreamError::RevokedAuthorization
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn losing_all_controller_clones_fails_closed_but_one_clone_keeps_authority_alive() {
        let access = access("workspace-owner");
        let controller = RemoteMcpStreamRevocation::new(&access).unwrap();
        let surviving = controller.clone();
        let mut body =
            RemoteMcpGuardedBody::new(Body::from("first"), &access, controller.subscribe())
                .unwrap();
        drop(controller);
        assert!(next(&mut body).await.unwrap().is_ok());
        let fixture = FixtureBody::new(vec![], true);
        let mut body =
            RemoteMcpGuardedBody::new(Body::new(fixture), &access, surviving.subscribe()).unwrap();
        let task = tokio::spawn(async move { next(&mut body).await.unwrap().unwrap_err() });
        tokio::task::yield_now().await;
        drop(surviving);
        assert_eq!(
            task.await.unwrap(),
            RemoteMcpStreamError::RevokedAuthorization
        );
    }

    #[tokio::test]
    async fn revocation_during_provider_poll_discards_data_and_trailer_frames() {
        for frame in [
            Frame::data(Bytes::from_static(b"private-frame")),
            Frame::trailers(HeaderMap::new()),
        ] {
            let access = access("workspace-owner");
            let controller = RemoteMcpStreamRevocation::new(&access).unwrap();
            let revoker = controller.clone();
            let mut fixture = FixtureBody::new(vec![frame], false);
            fixture.on_poll = Some(Box::new(move || revoker.revoke()));
            let mut body =
                RemoteMcpGuardedBody::new(Body::new(fixture), &access, controller.subscribe())
                    .unwrap();
            assert_eq!(
                next(&mut body).await.unwrap().unwrap_err(),
                RemoteMcpStreamError::RevokedAuthorization
            );
            assert!(next(&mut body).await.is_none());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn equal_claims_cannot_renew_the_original_controller_deadline() {
        let access = access("workspace-owner");
        let mut narrowed = access.clone();
        narrowed.constrain_validity(Instant::now(), 1_099).unwrap();
        assert_eq!(narrowed, access);
        assert!(narrowed.validity_deadline() < access.validity_deadline());
        let controller = RemoteMcpStreamRevocation::new(&narrowed).unwrap();
        let fixture = FixtureBody::new(vec![], true);
        let mut body =
            RemoteMcpGuardedBody::new(Body::new(fixture), &access, controller.subscribe()).unwrap();
        let task = tokio::spawn(async move { next(&mut body).await.unwrap().unwrap_err() });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(
            task.await.unwrap(),
            RemoteMcpStreamError::ExpiredAuthorization
        );
    }

    #[test]
    fn construction_rejects_foreign_expired_revoked_or_unmonitored_authority() {
        let access = access("workspace-owner");
        let foreign = super::tests::access("workspace-foreign");
        let controller = RemoteMcpStreamRevocation::new(&access).unwrap();
        assert_eq!(
            RemoteMcpGuardedBody::new(Body::empty(), &foreign, controller.subscribe()).unwrap_err(),
            RemoteMcpStreamError::InvalidRevocationAuthority,
        );
        let mut expired = access.clone();
        assert!(expired.constrain_validity(Instant::now(), 1_100).is_err());
        assert_eq!(
            RemoteMcpStreamRevocation::new(&expired).unwrap_err(),
            RemoteMcpStreamError::ExpiredAuthorization
        );
        assert_eq!(
            RemoteMcpGuardedBody::new(Body::empty(), &expired, controller.subscribe()).unwrap_err(),
            RemoteMcpStreamError::ExpiredAuthorization,
        );
        controller.revoke();
        controller.revoke();
        assert_eq!(
            RemoteMcpGuardedBody::new(Body::empty(), &access, controller.subscribe()).unwrap_err(),
            RemoteMcpStreamError::RevokedAuthorization,
        );
        let other = RemoteMcpStreamRevocation::new(&access).unwrap();
        let signal = other.subscribe();
        drop(other);
        assert_eq!(
            RemoteMcpGuardedBody::new(Body::empty(), &access, signal).unwrap_err(),
            RemoteMcpStreamError::RevokedAuthorization,
        );
    }

    #[tokio::test]
    async fn transport_failure_is_redacted_and_releases_body() {
        let access = access("workspace-owner");
        let controller = RemoteMcpStreamRevocation::new(&access).unwrap();
        let mut fixture = FixtureBody::new(vec![], false);
        fixture.error = Some(io::Error::other("private-driver-and-credential"));
        let drops = Arc::clone(&fixture.drops);
        let mut body =
            RemoteMcpGuardedBody::new(Body::new(fixture), &access, controller.subscribe()).unwrap();
        let error = next(&mut body).await.unwrap().unwrap_err();
        assert_eq!(error, RemoteMcpStreamError::TransportFailure);
        assert!(!format!("{error:?} {error}").contains("private-driver"));
        assert!(next(&mut body).await.is_none());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn response_helper_preserves_status_headers_and_guarded_payload() {
        let access = access("workspace-owner");
        let controller = RemoteMcpStreamRevocation::new(&access).unwrap();
        let response = Response::builder()
            .status(StatusCode::ACCEPTED)
            .header("content-type", "text/event-stream")
            .header("mcp-session-id", "fixture-session")
            .body(Body::from("fixture-payload"))
            .unwrap();
        let response =
            guard_remote_mcp_response(response, &access, controller.subscribe()).unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.headers()["mcp-session-id"], "fixture-session");
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 100)
                .await
                .unwrap(),
            "fixture-payload"
        );
    }

    #[test]
    fn debug_is_redacted_and_dropping_a_consumer_releases_the_provider() {
        let access = access("private-workspace");
        let controller = RemoteMcpStreamRevocation::new(&access).unwrap();
        let signal = controller.subscribe();
        let fixture = FixtureBody::new(vec![], true);
        let drops = Arc::clone(&fixture.drops);
        let body = RemoteMcpGuardedBody::new(Body::new(fixture), &access, signal.clone()).unwrap();
        let debug = format!("{controller:?} {signal:?} {body:?}");
        assert!(!debug.contains("private-"));
        drop(body);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn every_bound_claim_rejects_signal_substitution() {
        let access = access("workspace-owner");
        let controller = RemoteMcpStreamRevocation::new(&access).unwrap();
        for index in 0..7 {
            let mut claims = fixture_claims("workspace-owner");
            match index {
                0 => claims.issuer = "https://other-issuer.example".to_owned(),
                1 => claims.audience = vec!["https://other-resource.example/mcp".to_owned()],
                2 => claims.subject_id = PrincipalId::new("other-principal"),
                3 => claims.client_id = ClientId::new("other-client"),
                4 => claims.workspace_id = WorkspaceId::new("other-workspace"),
                5 => claims.scopes = BTreeSet::from([RemoteAccessScope::GraphRead]),
                _ => claims.expires_at_epoch_seconds += 1,
            }
            let issuer = claims.issuer.clone();
            let resource = claims.audience[0].clone();
            let other = claims
                .validate_connection(&issuer, &resource, 1_000)
                .unwrap();
            assert_eq!(
                RemoteMcpGuardedBody::new(Body::empty(), &other, controller.subscribe())
                    .unwrap_err(),
                RemoteMcpStreamError::InvalidRevocationAuthority,
            );
        }
    }

    #[tokio::test]
    async fn revocation_fans_out_only_to_the_bound_controller_subscribers() {
        let owner = access("workspace-owner");
        let other = access("workspace-other");
        let controller = RemoteMcpStreamRevocation::new(&owner).unwrap();
        let independent = RemoteMcpStreamRevocation::new(&other).unwrap();
        let mut first =
            RemoteMcpGuardedBody::new(Body::from("private-first"), &owner, controller.subscribe())
                .unwrap();
        let mut second =
            RemoteMcpGuardedBody::new(Body::from("private-second"), &owner, controller.subscribe())
                .unwrap();
        let mut unrelated =
            RemoteMcpGuardedBody::new(Body::from("other-data"), &other, independent.subscribe())
                .unwrap();
        controller.revoke();
        for body in [&mut first, &mut second] {
            assert_eq!(
                next(body).await.unwrap().unwrap_err(),
                RemoteMcpStreamError::RevokedAuthorization
            );
        }
        assert_eq!(
            next(&mut unrelated)
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap(),
            "other-data"
        );
    }

    #[tokio::test]
    async fn consumer_drop_or_eof_releases_the_waiting_authority_monitor() {
        for completion in 0..3 {
            let access = access("workspace-owner");
            let controller = RemoteMcpStreamRevocation::new(&access).unwrap();
            let inner = if completion == 2 {
                Body::from("final-frame")
            } else {
                Body::new(FixtureBody::new(vec![], completion == 0))
            };
            let mut body =
                RemoteMcpGuardedBody::new(inner, &access, controller.subscribe()).unwrap();
            let monitor = controller.clone();
            let task = tokio::spawn(async move { monitor.closed().await });
            tokio::task::yield_now().await;
            assert!(!task.is_finished());
            if completion != 0 {
                if completion == 1 {
                    assert!(next(&mut body).await.is_none());
                } else {
                    assert_eq!(
                        next(&mut body).await.unwrap().unwrap().into_data().unwrap(),
                        "final-frame",
                    );
                }
                task.await.unwrap();
                assert!(body.is_end_stream());
            } else {
                drop(body);
                task.await.unwrap();
            }
        }
    }
}

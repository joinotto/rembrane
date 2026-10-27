use std::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use axum::{body::Body, http::Response};
use bytes::Bytes;
use http_body::{Body as HttpBody, Frame, SizeHint};
use rembrane_contracts::VerifiedRemoteAccess;
use tokio::sync::watch;

/// Opaque transport errors: underlying body/driver diagnostics are not retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteMcpStreamError {
    ExpiredAuthorization,
    RevokedAuthorization,
    InvalidRevocationAuthority,
    TransportFailure,
}

impl fmt::Display for RemoteMcpStreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExpiredAuthorization => "remote response authorization expired",
            Self::RevokedAuthorization => "remote response authorization revoked",
            Self::InvalidRevocationAuthority => "remote response authority mismatch",
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

struct StreamAuthorization {
    deadline: Instant,
    expiry: GuardFuture,
    revocation: GuardFuture,
}

impl StreamAuthorization {
    fn poll_denial(&mut self, context: &mut Context<'_>) -> Option<RemoteMcpStreamError> {
        if Instant::now() >= self.deadline || self.expiry.as_mut().poll(context).is_ready() {
            return Some(RemoteMcpStreamError::ExpiredAuthorization);
        }
        if self.revocation.as_mut().poll(context).is_ready() {
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
        let deadline = access
            .validity_deadline()
            .min(signal.access.validity_deadline());
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
        Ok(Self {
            body: Some(body),
            authorization: Some(StreamAuthorization {
                deadline,
                expiry,
                revocation,
            }),
        })
    }

    fn finish(&mut self) {
        // Mark both halves closed before a user-supplied body's destructor
        // runs. Even if that destructor unwinds, no authority remains active.
        let body = self.body.take();
        self.authorization = None;
        drop(body);
    }

    fn deny(
        &mut self,
        error: RemoteMcpStreamError,
    ) -> Poll<Option<Result<Frame<Bytes>, RemoteMcpStreamError>>> {
        self.finish();
        Poll::Ready(Some(Err(error)))
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
            return this.deny(error);
        }
        match result {
            Poll::Ready(Some(Err(_))) => this.deny(RemoteMcpStreamError::TransportFailure),
            Poll::Ready(None) => {
                this.finish();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Ok(frame))) => {
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
        self.body
            .as_ref()
            .map_or_else(|| SizeHint::with_exact(0), HttpBody::size_hint)
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
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    }

    impl FixtureBody {
        fn new(frames: Vec<Frame<Bytes>>, pending: bool) -> Self {
            Self {
                frames: frames.into(),
                pending,
                error: None,
                on_poll: None,
                polls: Arc::new(AtomicUsize::new(0)),
                drops: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl Drop for FixtureBody {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
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
    }

    async fn next(
        body: &mut RemoteMcpGuardedBody,
    ) -> Option<Result<Frame<Bytes>, RemoteMcpStreamError>> {
        poll_fn(|context| Pin::new(&mut *body).poll_frame(context)).await
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

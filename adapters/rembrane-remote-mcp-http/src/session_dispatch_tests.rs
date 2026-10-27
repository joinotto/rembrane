//! Deletion/replacement while Tower readiness is pending must revoke admission.

use std::{
    convert::Infallible,
    future::{Future, Ready, ready},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use axum::{body::Body, http::Request, response::Response};
use rembrane_application::RemoteTokenVerifier;
use tokio::sync::{Notify, Semaphore};
use zeroize::Zeroizing;

use crate::{
    AuthorizedTowerMcpDispatcher, RemoteMcpDispatchError, TenantAwareTowerMcpDispatchError,
    TenantAwareTowerMcpDispatcher, TowerMcpDispatchError, tests::session_metadata_fixture,
};

type Readiness = Pin<Box<dyn Future<Output = ()> + Send + Sync>>;

struct DelayedReadiness {
    started: Arc<Notify>,
    release: Arc<Semaphore>,
    calls: Arc<AtomicUsize>,
    waiting: Option<Readiness>,
}

impl Clone for DelayedReadiness {
    fn clone(&self) -> Self {
        Self {
            started: Arc::clone(&self.started),
            release: Arc::clone(&self.release),
            calls: Arc::clone(&self.calls),
            waiting: None,
        }
    }
}

impl tower::Service<Request<Body>> for DelayedReadiness {
    type Response = Response;
    type Error = Infallible;
    type Future = Ready<Result<Response, Infallible>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.waiting.is_none() {
            self.started.notify_one();
            let release = Arc::clone(&self.release);
            self.waiting = Some(Box::pin(async move {
                drop(release.acquire_owned().await.unwrap());
            }));
        }
        self.waiting
            .as_mut()
            .unwrap()
            .as_mut()
            .poll(context)
            .map(Ok)
    }

    fn call(&mut self, _: Request<Body>) -> Self::Future {
        self.calls.fetch_add(1, Ordering::SeqCst);
        ready(Ok(Response::new(Body::empty())))
    }
}

async fn deletion_during_readiness(is_get: bool, replace: bool) {
    let (authorization, id, headers) = session_metadata_fixture();
    let authorization = Arc::new(authorization);
    let started = Arc::new(Notify::new());
    let release = Arc::new(Semaphore::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let dispatcher = AuthorizedTowerMcpDispatcher::new(DelayedReadiness {
        started: Arc::clone(&started),
        release: Arc::clone(&release),
        calls: Arc::clone(&calls),
        waiting: None,
    });
    let task_authorization = Arc::clone(&authorization);
    let pending = tokio::spawn(async move {
        if is_get {
            task_authorization
                .shared
                .authorize_and_dispatch_session_event_stream(&headers, 1_000, &dispatcher)
                .await
        } else {
            task_authorization
                .shared
                .authorize_and_dispatch_owned_session(
                    &headers,
                    Zeroizing::new(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_vec()),
                    1_000,
                    &dispatcher,
                )
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(2), started.notified())
        .await
        .unwrap();
    let access = authorization
        .shared
        .verifier
        .verify("workspace-one")
        .unwrap()
        .validate_connection(
            &authorization.shared.issuer,
            &authorization.shared.resource,
            1_000,
        )
        .unwrap();
    {
        let mut gate = authorization.shared.gate.lock().unwrap();
        gate.sessions.terminate(&id, &access, 1_000).unwrap();
        if replace {
            gate.sessions.establish(id, &access, 1_000).unwrap();
        }
    }
    release.add_permits(1);
    let result = tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(
            result,
            Err(RemoteMcpDispatchError::Dispatch(
                TowerMcpDispatchError::RevokedSession
            ))
        ),
        "removed session must not regain authority after readiness"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        authorization.shared.gate.lock().unwrap().sessions.len(),
        usize::from(replace)
    );
}

#[tokio::test]
async fn queued_session_post_cannot_dispatch_after_deletion_or_same_claims_replacement() {
    for replace in [false, true] {
        deletion_during_readiness(false, replace).await;
    }
}

#[tokio::test]
async fn queued_session_get_cannot_dispatch_after_deletion_or_same_claims_replacement() {
    for replace in [false, true] {
        deletion_during_readiness(true, replace).await;
    }
}

#[tokio::test]
async fn queued_session_dispatch_cannot_cross_a_tenant_factory_wait_after_replacement() {
    for is_get in [false, true] {
        let (authorization, id, headers) = session_metadata_fixture();
        let authorization = Arc::new(authorization);
        let started = Arc::new(Notify::new());
        let (release, wait_for_release) = std::sync::mpsc::channel();
        let wait_for_release = Arc::new(std::sync::Mutex::new(wait_for_release));
        let calls = Arc::new(AtomicUsize::new(0));
        let factory_started = Arc::clone(&started);
        let service_calls = Arc::clone(&calls);
        let mut dispatcher = TenantAwareTowerMcpDispatcher::new(
            move |_: &rembrane_contracts::VerifiedRemoteAccess| {
                factory_started.notify_one();
                wait_for_release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap();
                let calls = Arc::clone(&service_calls);
                Ok::<_, Infallible>(tower::service_fn(move |_: Request<Body>| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    ready(Ok::<_, Infallible>(Response::new(Body::empty())))
                }))
            },
        );
        dispatcher.factory_operations = Arc::new(Semaphore::new(1));
        let task_authorization = Arc::clone(&authorization);
        let pending = tokio::spawn(async move {
            if is_get {
                task_authorization
                    .shared
                    .authorize_and_dispatch_session_event_stream(&headers, 1_000, &dispatcher)
                    .await
            } else {
                task_authorization
                    .shared
                    .authorize_and_dispatch_owned_session(
                        &headers,
                        Zeroizing::new(
                            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_vec(),
                        ),
                        1_000,
                        &dispatcher,
                    )
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .unwrap();
        let access = authorization
            .shared
            .verifier
            .verify("workspace-one")
            .unwrap()
            .validate_connection(
                &authorization.shared.issuer,
                &authorization.shared.resource,
                1_000,
            )
            .unwrap();
        {
            let mut gate = authorization.shared.gate.lock().unwrap();
            gate.sessions.terminate(&id, &access, 1_000).unwrap();
            gate.sessions.establish(id, &access, 1_000).unwrap();
        }
        release.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), pending)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            result,
            Err(RemoteMcpDispatchError::Dispatch(
                TenantAwareTowerMcpDispatchError::RevokedSession,
            ))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(authorization.shared.gate.lock().unwrap().sessions.len(), 1);
    }
}

#[tokio::test]
async fn borrowing_session_proofs_keep_the_original_guard_across_owned_dispatch() {
    for is_get in [false, true] {
        let (authorization, id, headers) = session_metadata_fixture();
        let calls = Arc::new(AtomicUsize::new(0));
        let service_calls = Arc::clone(&calls);
        let dispatcher =
            AuthorizedTowerMcpDispatcher::new(tower::service_fn(move |_: Request<Body>| {
                service_calls.fetch_add(1, Ordering::SeqCst);
                ready(Ok::<_, Infallible>(Response::new(Body::empty())))
            }));
        let verifier = crate::tests::Verifier;
        let authenticator = rembrane_application::RemoteAccessAuthenticator::new(
            &verifier,
            &authorization.shared.issuer,
            &authorization.shared.resource,
        );
        let authentication =
            rembrane_application::RemoteHttpAuthorization::new(&authenticator, &[]);
        let (post, stream) = {
            let mut gate = authorization.shared.gate.lock().unwrap();
            let post = if is_get {
                None
            } else {
                Some(
                    crate::authorize_axum_session_body(
                        &mut gate,
                        &authentication,
                        &headers,
                        br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
                        1_000,
                    )
                    .unwrap(),
                )
            };
            let stream = if is_get {
                Some(
                    crate::authorize_axum_session_event_stream(
                        &mut gate,
                        &authentication,
                        &headers,
                        1_000,
                    )
                    .unwrap(),
                )
            } else {
                None
            };
            let access = verifier
                .verify("workspace-one")
                .unwrap()
                .validate_connection(
                    &authorization.shared.issuer,
                    &authorization.shared.resource,
                    1_000,
                )
                .unwrap();
            gate.sessions.terminate(&id, &access, 1_000).unwrap();
            gate.sessions.establish(id, &access, 1_000).unwrap();
            (post, stream)
        };
        let result = if let Some(post) = post {
            post.dispatch_with(&dispatcher).await
        } else {
            stream.unwrap().dispatch_with(&dispatcher).await
        };
        assert!(matches!(result, Err(TowerMcpDispatchError::RevokedSession)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

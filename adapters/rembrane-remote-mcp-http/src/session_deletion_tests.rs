//! HTTP status confirmation is distinct from successful Tower transport I/O.

use std::{
    convert::Infallible,
    future::{Ready, ready},
    sync::{
        Arc,
        atomic::{AtomicU16, AtomicUsize, Ordering},
    },
};

use axum::{
    body::Body,
    http::{HeaderMap, Request, StatusCode, header::AUTHORIZATION},
    response::Response,
};
use rembrane_application::{
    RemoteAccessAuthenticator, RemoteHttpAuthorization, RemoteTokenVerifier,
};
use rembrane_contracts::{RemoteSessionId, VerifiedRemoteAccess};
use tokio::sync::Semaphore;

use crate::{
    AuthorizedRemoteMcpSessionDeletionDispatcher, AuthorizedTowerMcpDispatcher,
    MCP_SESSION_HEADER_NAME, RemoteMcpAxumAuthorization, RemoteMcpDispatchError,
    TenantAwareTowerMcpDispatchError, TenantAwareTowerMcpDispatcher, TowerMcpDispatchError,
    authorize_axum_session_deletion,
    tests::{Verifier, session_metadata_fixture},
};

fn replace_binding(authorization: &RemoteMcpAxumAuthorization<Verifier>, id: &RemoteSessionId) {
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
    let mut gate = authorization.shared.gate.lock().unwrap();
    gate.sessions.terminate(id, &access, 1_000).unwrap();
    gate.sessions.establish(id.clone(), &access, 1_000).unwrap();
}

#[tokio::test]
async fn late_successful_delete_does_not_remove_a_same_claims_replacement() {
    let (authorization, id, headers) = session_metadata_fixture();
    let authorization = Arc::new(authorization);
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let service_started = Arc::clone(&started);
    let service_release = Arc::clone(&release);
    let dispatcher =
        AuthorizedTowerMcpDispatcher::new(tower::service_fn(move |_: Request<Body>| {
            let started = Arc::clone(&service_started);
            let release = Arc::clone(&service_release);
            async move {
                started.notify_one();
                release.notified().await;
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }
        }));
    let task_authorization = Arc::clone(&authorization);
    let pending = tokio::spawn(async move {
        task_authorization
            .shared
            .authorize_and_dispatch_termination(&headers, 1_000, &dispatcher)
            .await
    });
    started.notified().await;
    replace_binding(&authorization, &id);
    release.notify_one();
    let result = pending.await.unwrap();
    assert!(matches!(
        result,
        Err(RemoteMcpDispatchError::Authorization(
            crate::RemoteMcpHttpRejection { status: 403, .. }
        ))
    ));
    assert_retained(&authorization, &id);
}

#[tokio::test]
async fn late_initialization_rollback_does_not_remove_a_same_claims_replacement() {
    let (authorization, id, headers) = session_metadata_fixture();
    let authorization = Arc::new(authorization);
    {
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
        authorization
            .shared
            .gate
            .lock()
            .unwrap()
            .sessions
            .terminate(&id, &access, 1_000)
            .unwrap();
    }
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let service_started = Arc::clone(&started);
    let service_release = Arc::clone(&release);
    let dispatcher =
        AuthorizedTowerMcpDispatcher::new(tower::service_fn(move |_: Request<Body>| {
            let started = Arc::clone(&service_started);
            let release = Arc::clone(&service_release);
            async move {
                started.notify_one();
                release.notified().await;
                Err::<Response, _>("late initialization failure".to_owned())
            }
        }));
    let task_authorization = Arc::clone(&authorization);
    let pending = tokio::spawn(async move {
        task_authorization.shared.establish_and_dispatch_owned_session(
            &headers,
            zeroize::Zeroizing::new(
                br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"race-test","version":"1"}}}"#.to_vec(),
            ),
            1_000, &dispatcher,
        ).await
    });
    started.notified().await;
    replace_binding(&authorization, &id);
    release.notify_one();
    let result = pending.await.unwrap();
    assert!(matches!(
        result,
        Err(RemoteMcpDispatchError::Authorization(
            crate::RemoteMcpHttpRejection { status: 403, .. }
        ))
    ));
    assert_retained(&authorization, &id);
}

const UNCONFIRMED: [StatusCode; 9] = [
    StatusCode::CONTINUE,
    StatusCode::MOVED_PERMANENTLY,
    StatusCode::UNAUTHORIZED,
    StatusCode::FORBIDDEN,
    StatusCode::NOT_FOUND,
    StatusCode::METHOD_NOT_ALLOWED,
    StatusCode::TOO_MANY_REQUESTS,
    StatusCode::INTERNAL_SERVER_ERROR,
    StatusCode::SERVICE_UNAVAILABLE,
];

fn response_service(
    status: Arc<AtomicU16>,
    calls: Arc<AtomicUsize>,
) -> impl tower::Service<
    Request<Body>,
    Response = Response,
    Error = Infallible,
    Future = Ready<Result<Response, Infallible>>,
> + Clone
+ Send {
    tower::service_fn(move |request: Request<Body>| {
        assert_eq!(request.method(), axum::http::Method::DELETE);
        assert!(request.headers().contains_key(MCP_SESSION_HEADER_NAME));
        assert!(!request.headers().contains_key(AUTHORIZATION));
        assert!(request.extensions().get::<VerifiedRemoteAccess>().is_some());
        calls.fetch_add(1, Ordering::SeqCst);
        let response_status = StatusCode::from_u16(status.load(Ordering::SeqCst)).unwrap();
        let body = if response_status.is_success() {
            Body::empty()
        } else {
            Body::from("private provider response")
        };
        let response = Response::builder()
            .status(response_status)
            .body(body)
            .unwrap();
        ready(Ok(response))
    })
}

fn assert_retained(authorization: &RemoteMcpAxumAuthorization<Verifier>, id: &RemoteSessionId) {
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
    let mut gate = authorization.shared.gate.lock().unwrap();
    gate.sessions.revalidate(id, &access, 1_000).unwrap();
    assert_eq!(gate.sessions.len(), 1);
}

async fn dispatch<Dispatcher>(
    authorization: &mut RemoteMcpAxumAuthorization<Verifier>,
    headers: &HeaderMap,
    shared: bool,
    dispatcher: &Dispatcher,
) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
where
    Dispatcher: AuthorizedRemoteMcpSessionDeletionDispatcher,
{
    if shared {
        authorization
            .shared
            .authorize_and_dispatch_termination(headers, 1_000, dispatcher)
            .await
    } else {
        authorization
            .authorize_and_dispatch_session_deletion(headers, 1_000, dispatcher)
            .await
    }
}

#[tokio::test]
async fn owned_and_shared_delete_retain_bindings_for_every_failed_http_class() {
    for shared in [false, true] {
        for failure in UNCONFIRMED {
            let (mut authorization, id, headers) = session_metadata_fixture();
            let status = Arc::new(AtomicU16::new(failure.as_u16()));
            let calls = Arc::new(AtomicUsize::new(0));
            let dispatcher = AuthorizedTowerMcpDispatcher::new(response_service(
                Arc::clone(&status),
                Arc::clone(&calls),
            ));
            let result = dispatch(&mut authorization, &headers, shared, &dispatcher).await;
            assert!(matches!(
                result,
                Err(RemoteMcpDispatchError::Dispatch(
                    TowerMcpDispatchError::InvalidSdkResponse,
                ))
            ));
            assert_retained(&authorization, &id);
            status.store(StatusCode::ACCEPTED.as_u16(), Ordering::SeqCst);
            let response = dispatch(&mut authorization, &headers, shared, &dispatcher)
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED);
            assert!(
                authorization
                    .shared
                    .gate
                    .lock()
                    .unwrap()
                    .sessions
                    .is_empty()
            );
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        }
    }
}

#[tokio::test]
async fn tenant_delete_requires_http_confirmation_before_local_commit() {
    for shared in [false, true] {
        for failure in UNCONFIRMED {
            let (mut authorization, id, headers) = session_metadata_fixture();
            let status = Arc::new(AtomicU16::new(failure.as_u16()));
            let calls = Arc::new(AtomicUsize::new(0));
            let factory_status = Arc::clone(&status);
            let factory_calls = Arc::clone(&calls);
            let mut dispatcher =
                TenantAwareTowerMcpDispatcher::new(move |_: &VerifiedRemoteAccess| {
                    Ok::<_, Infallible>(response_service(
                        Arc::clone(&factory_status),
                        Arc::clone(&factory_calls),
                    ))
                });
            dispatcher.factory_operations = Arc::new(Semaphore::new(2));
            let result = dispatch(&mut authorization, &headers, shared, &dispatcher).await;
            assert!(matches!(
                result,
                Err(RemoteMcpDispatchError::Dispatch(
                    TenantAwareTowerMcpDispatchError::InvalidSdkResponse,
                ))
            ));
            assert_retained(&authorization, &id);
            status.store(StatusCode::NO_CONTENT.as_u16(), Ordering::SeqCst);
            let response = dispatch(&mut authorization, &headers, shared, &dispatcher)
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert!(
                authorization
                    .shared
                    .gate
                    .lock()
                    .unwrap()
                    .sessions
                    .is_empty()
            );
            assert_eq!(calls.load(Ordering::SeqCst), 2);
        }
    }
}

#[tokio::test]
async fn borrowing_delete_keeps_retryable_authority_after_http_failure() {
    for failure in UNCONFIRMED {
        let (authorization, id, headers) = session_metadata_fixture();
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            &authorization.shared.issuer,
            &authorization.shared.resource,
        );
        let policy = RemoteHttpAuthorization::new(&authenticator, &[]);
        let status = Arc::new(AtomicU16::new(failure.as_u16()));
        let calls = Arc::new(AtomicUsize::new(0));
        let dispatcher = AuthorizedTowerMcpDispatcher::new(response_service(
            Arc::clone(&status),
            Arc::clone(&calls),
        ));
        // A directly owned gate models the borrowing compatibility API without
        // holding an unrelated shared-service mutex across downstream waits.
        let mut gate = authorization.shared.gate.into_inner().unwrap();
        let result =
            authorize_axum_session_deletion(&mut gate, &policy, &headers, 1_000, &dispatcher).await;
        assert!(matches!(
            result,
            Err(RemoteMcpDispatchError::Dispatch(
                TowerMcpDispatchError::InvalidSdkResponse,
            ))
        ));
        let access = verifier
            .verify("workspace-one")
            .unwrap()
            .validate_connection(
                &authorization.shared.issuer,
                &authorization.shared.resource,
                1_000,
            )
            .unwrap();
        gate.sessions.revalidate(&id, &access, 1_000).unwrap();
        assert_eq!(gate.sessions.len(), 1);
        status.store(StatusCode::OK.as_u16(), Ordering::SeqCst);
        let result =
            authorize_axum_session_deletion(&mut gate, &policy, &headers, 1_000, &dispatcher)
                .await
                .unwrap();
        assert_eq!(result.status(), StatusCode::OK);
        assert!(gate.sessions.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}

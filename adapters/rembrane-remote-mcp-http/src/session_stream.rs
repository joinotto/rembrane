//! Session-bound GET authorization, separate from the stateless stream port.
//! The official SDK owns event delivery; replay remains unsupported here.

use std::{fmt, future::Future, pin::Pin};

use axum::{
    body::Body,
    http::{
        HeaderMap, Method, Request,
        header::{ACCEPT, HOST, ORIGIN},
    },
};
use rembrane_application::{RemoteHttpAuthorization, RemoteSessionHttpError, RemoteTokenVerifier};
use rembrane_contracts::{RemoteSessionId, VerifiedRemoteAccess};

use super::{
    AuthorizedRemoteMcpEventStream, AuthorizedTowerMcpDispatcher, AuthorizedTowerMcpServiceFactory,
    MCP_PROTOCOL_VERSION_HEADER_NAME, MCP_SESSION_HEADER_NAME, RemoteMcpAxumAuthorization,
    RemoteMcpDispatchError, RemoteMcpHttpGate, RemoteMcpHttpRejection,
    SharedRemoteMcpAxumAuthorization, TenantAwareTowerMcpDispatchError,
    TenantAwareTowerMcpDispatcher, TowerMcpDispatchError, call_current_service,
    event_stream_headers_from_axum, insert_optional_validated_header, insert_validated_header,
    lock_rejection, security_request_from_axum_headers, tenant_dispatch_error,
};

/// One reauthenticated session GET. Its session, canonical tenant proof, and
/// validated transport metadata remain coupled until consuming dispatch.
pub struct AuthorizedRemoteMcpSessionEventStream {
    stream: AuthorizedRemoteMcpEventStream,
    session_id: RemoteSessionId,
}

impl fmt::Debug for AuthorizedRemoteMcpSessionEventStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedRemoteMcpSessionEventStream")
            .field("stream", &self.stream)
            .field("session_id", &self.session_id)
            .finish()
    }
}

impl AuthorizedRemoteMcpSessionEventStream {
    #[must_use]
    pub const fn access(&self) -> &VerifiedRemoteAccess {
        self.stream.access()
    }

    #[must_use]
    pub const fn session_id(&self) -> &RemoteSessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn transport(&self) -> &AuthorizedRemoteMcpEventStream {
        &self.stream
    }

    /// Consumes the coupled proof. Implementations must preserve this session
    /// identifier and check the proof after waits and before opening a stream.
    #[must_use]
    pub fn into_parts(self) -> (AuthorizedRemoteMcpEventStream, RemoteSessionId) {
        (self.stream, self.session_id)
    }

    /// Hands one session-bound authorization to the transport.
    ///
    /// # Errors
    ///
    /// Returns downstream dispatch failure without converting it to authority.
    pub async fn dispatch_with<Dispatcher>(
        self,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, Dispatcher::Error>
    where
        Dispatcher: AuthorizedRemoteMcpSessionEventStreamDispatcher,
    {
        dispatcher.open_session(self).await
    }
}

/// Transport port distinct from stateless GET. Admission must enforce proof
/// lifetime after waits. Ongoing streams require response guarding and a live
/// claim-bound revocation monitor; admission alone does not provide either.
pub trait AuthorizedRemoteMcpSessionEventStreamDispatcher {
    type Output;
    type Error;
    type DispatchFuture: Future<Output = Result<Self::Output, Self::Error>> + Send;

    fn open_session(&self, stream: AuthorizedRemoteMcpSessionEventStream) -> Self::DispatchFuture;
}

/// Borrowing compatibility API for session-bound GET. Verification is
/// synchronous: do not run a blocking network verifier on an async executor.
///
/// # Errors
///
/// Rejects replay, negotiation/header errors, missing/expired/substituted
/// sessions, invalid credentials, and untrusted host/origin. Unknown and
/// foreign sessions have the same non-enumerating forbidden response.
pub fn authorize_axum_session_event_stream<Verifier>(
    gate: &mut RemoteMcpHttpGate,
    authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
    headers: &HeaderMap,
    now_epoch_seconds: u64,
) -> Result<AuthorizedRemoteMcpSessionEventStream, RemoteMcpHttpRejection>
where
    Verifier: RemoteTokenVerifier,
{
    let (accept, protocol_version) = event_stream_headers_from_axum(headers)?;
    let request = security_request_from_axum_headers(headers)?;
    gate.require_allowed_host(request.host)?;
    let session_id = RemoteMcpHttpGate::session_id(request.session_id)?;
    let mut access = authorization
        .authorize_connection_for_http(request.authorization, request.origin, now_epoch_seconds)
        .map_err(|error| gate.rejection(error.into()))?;
    gate.sessions
        .revalidate_access(&session_id, &mut access, now_epoch_seconds)
        .map_err(|_| gate.rejection(RemoteSessionHttpError::Forbidden))?;
    Ok(AuthorizedRemoteMcpSessionEventStream {
        stream: AuthorizedRemoteMcpEventStream {
            access,
            accept,
            protocol_version,
            validated_host: request.host.map(str::to_owned),
            validated_origin: request.origin.map(str::to_owned),
        },
        session_id,
    })
}

impl<Verifier> SharedRemoteMcpAxumAuthorization<Verifier>
where
    Verifier: RemoteTokenVerifier + Send + Sync + 'static,
{
    /// Reauthenticates and dispatches an established-session GET. Verification
    /// runs on bounded workers; no registry lock spans verification or dispatch.
    ///
    /// # Errors
    ///
    /// Separates fail-closed HTTP/session authorization from dispatch failure.
    /// Replay is explicitly unsupported and returns 400 before provider calls.
    pub async fn authorize_and_dispatch_session_event_stream<Dispatcher>(
        &self,
        headers: &HeaderMap,
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
    where
        Dispatcher: AuthorizedRemoteMcpSessionEventStreamDispatcher,
    {
        let (accept, protocol_version) = event_stream_headers_from_axum(headers)
            .map_err(RemoteMcpDispatchError::Authorization)?;
        let request = security_request_from_axum_headers(headers)
            .map_err(RemoteMcpDispatchError::Authorization)?;
        let session_id = RemoteMcpHttpGate::session_id(request.session_id)
            .map_err(RemoteMcpDispatchError::Authorization)?;
        {
            let gate = self
                .gate
                .lock()
                .map_err(|_| RemoteMcpDispatchError::Authorization(lock_rejection()))?;
            gate.require_allowed_host(request.host)
                .map_err(RemoteMcpDispatchError::Authorization)?;
        }
        let mut access = self
            .authorize_on_worker(
                request.authorization,
                request.origin,
                None,
                now_epoch_seconds,
            )
            .await
            .map_err(RemoteMcpDispatchError::Authorization)?;
        {
            let mut gate = self
                .gate
                .lock()
                .map_err(|_| RemoteMcpDispatchError::Authorization(lock_rejection()))?;
            gate.sessions
                .revalidate_access(&session_id, &mut access, now_epoch_seconds)
                .map_err(|_| {
                    RemoteMcpDispatchError::Authorization(
                        gate.rejection(RemoteSessionHttpError::Forbidden),
                    )
                })?;
        }
        AuthorizedRemoteMcpSessionEventStream {
            stream: AuthorizedRemoteMcpEventStream {
                access,
                accept,
                protocol_version,
                validated_host: request.host.map(str::to_owned),
                validated_origin: request.origin.map(str::to_owned),
            },
            session_id,
        }
        .dispatch_with(dispatcher)
        .await
        .map_err(RemoteMcpDispatchError::Dispatch)
    }
}

impl<Verifier> RemoteMcpAxumAuthorization<Verifier>
where
    Verifier: RemoteTokenVerifier + Send + Sync + 'static,
{
    /// Uses the shared bounded-worker/session boundary for a session GET.
    ///
    /// # Errors
    ///
    /// Returns authorization, replay rejection, or downstream dispatch failure.
    pub async fn authorize_and_dispatch_session_event_stream<Dispatcher>(
        &self,
        headers: &HeaderMap,
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
    where
        Dispatcher: AuthorizedRemoteMcpSessionEventStreamDispatcher,
    {
        self.shared
            .authorize_and_dispatch_session_event_stream(headers, now_epoch_seconds, dispatcher)
            .await
    }
}

fn session_get_request<Error>(
    stream: AuthorizedRemoteMcpSessionEventStream,
) -> Result<Request<Body>, TowerMcpDispatchError<Error>> {
    let (transport, session_id) = stream.into_parts();
    let (access, accept, version, host, origin) = transport.into_parts();
    let host = host.ok_or(TowerMcpDispatchError::InvalidAuthorizedMetadata)?;
    let mut request = Request::builder()
        .method(Method::GET)
        .body(Body::empty())
        .map_err(|_| TowerMcpDispatchError::InvalidAuthorizedMetadata)?;
    insert_validated_header(request.headers_mut(), ACCEPT, &accept)?;
    insert_validated_header(request.headers_mut(), HOST, &host)?;
    insert_validated_header(
        request.headers_mut(),
        MCP_SESSION_HEADER_NAME,
        session_id.as_str(),
    )?;
    insert_optional_validated_header(
        request.headers_mut(),
        MCP_PROTOCOL_VERSION_HEADER_NAME,
        version.as_deref(),
    )?;
    insert_optional_validated_header(request.headers_mut(), ORIGIN, origin.as_deref())?;
    request.extensions_mut().insert(access);
    Ok(request)
}

impl<Service> AuthorizedRemoteMcpSessionEventStreamDispatcher
    for AuthorizedTowerMcpDispatcher<Service>
where
    Service: tower::Service<Request<Body>> + Clone + Send + 'static,
    Service::Future: Send + 'static,
    Service::Response: Send + 'static,
    Service::Error: Send + 'static,
{
    type Output = Service::Response;
    type Error = TowerMcpDispatchError<Service::Error>;
    type DispatchFuture =
        Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send + 'static>>;

    fn open_session(&self, stream: AuthorizedRemoteMcpSessionEventStream) -> Self::DispatchFuture {
        let service = self.service.clone();
        Box::pin(async move {
            let request = session_get_request(stream)?;
            call_current_service(service, request).await
        })
    }
}

impl<Factory> AuthorizedRemoteMcpSessionEventStreamDispatcher
    for TenantAwareTowerMcpDispatcher<Factory>
where
    Factory: AuthorizedTowerMcpServiceFactory,
    Factory::Service: tower::Service<Request<Body>> + Send + 'static,
    <Factory::Service as tower::Service<Request<Body>>>::Future: Send + 'static,
    <Factory::Service as tower::Service<Request<Body>>>::Response: Send + 'static,
    <Factory::Service as tower::Service<Request<Body>>>::Error: Send + 'static,
    Factory::Error: Send + 'static,
{
    type Output = <Factory::Service as tower::Service<Request<Body>>>::Response;
    type Error = TenantAwareTowerMcpDispatchError<
        Factory::Error,
        <Factory::Service as tower::Service<Request<Body>>>::Error,
    >;
    type DispatchFuture =
        Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send + 'static>>;

    fn open_session(&self, stream: AuthorizedRemoteMcpSessionEventStream) -> Self::DispatchFuture {
        let dispatcher = self.clone();
        Box::pin(async move {
            let service = dispatcher.create_service(stream.access()).await?;
            let request = session_get_request(stream).map_err(tenant_dispatch_error)?;
            call_current_service(service, request)
                .await
                .map_err(tenant_dispatch_error)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        future::{Ready, ready},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    use axum::http::{
        HeaderValue,
        header::{AUTHORIZATION, CONTENT_TYPE},
    };
    use rembrane_application::{RemoteAccessAuthenticator, RemoteTokenVerificationError};
    use rembrane_config::{RemoteMcpConfig, SecretReference};
    use rembrane_contracts::{RemoteAccessScope, RemoteTokenClaims};
    use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};
    use tokio::sync::Semaphore;

    use super::{
        ACCEPT, AuthorizedRemoteMcpSessionEventStream,
        AuthorizedRemoteMcpSessionEventStreamDispatcher, AuthorizedTowerMcpDispatcher, Body, HOST,
        HeaderMap, MCP_PROTOCOL_VERSION_HEADER_NAME, MCP_SESSION_HEADER_NAME, Method, ORIGIN, Pin,
        RemoteHttpAuthorization, RemoteMcpAxumAuthorization, RemoteMcpDispatchError,
        RemoteMcpHttpGate, RemoteMcpHttpRejection, RemoteSessionId, RemoteTokenVerifier, Request,
        TenantAwareTowerMcpDispatcher, TowerMcpDispatchError, VerifiedRemoteAccess,
        authorize_axum_session_event_stream,
    };

    const LAST_EVENT_ID: axum::http::HeaderName =
        axum::http::HeaderName::from_static("last-event-id");

    struct Verifier(Arc<AtomicUsize>);

    impl RemoteTokenVerifier for Verifier {
        fn verify(&self, token: &str) -> Result<RemoteTokenClaims, RemoteTokenVerificationError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            if token == "invalid" {
                return Err(RemoteTokenVerificationError);
            }
            let mut claims = RemoteTokenClaims {
                issuer: "https://identity.example.test".to_owned(),
                audience: vec!["https://memory.example.test/mcp".to_owned()],
                subject_id: PrincipalId::new("principal_01"),
                client_id: ClientId::new("client_01"),
                workspace_id: WorkspaceId::new("workspace_01"),
                scopes: [RemoteAccessScope::ContextRead].into(),
                expires_at_epoch_seconds: 2_000,
                not_before_epoch_seconds: None,
            };
            match token {
                "one" => {}
                "workspace" => claims.workspace_id = WorkspaceId::new("workspace_02"),
                "subject" => claims.subject_id = PrincipalId::new("principal_02"),
                "client" => claims.client_id = ClientId::new("client_02"),
                "scope" => claims.scopes = [RemoteAccessScope::GraphRead].into(),
                "issuer" => claims.issuer = "https://foreign.example.test".to_owned(),
                "audience" => claims.audience = vec!["https://foreign.example.test/mcp".to_owned()],
                "expired" => claims.expires_at_epoch_seconds = 999,
                _ => return Err(RemoteTokenVerificationError),
            }
            Ok(claims)
        }
    }

    struct Fixture {
        authorization: RemoteMcpAxumAuthorization<Verifier>,
        id: RemoteSessionId,
        headers: HeaderMap,
        original: VerifiedRemoteAccess,
        verifications: Arc<AtomicUsize>,
    }

    impl Fixture {
        fn new() -> Self {
            let verifications = Arc::new(AtomicUsize::new(0));
            let config = RemoteMcpConfig::new(
                "https://memory.example.test/mcp".to_owned(),
                "https://identity.example.test".to_owned(),
                "https://identity.example.test/introspect".to_owned(),
                "rembrane".to_owned(),
                SecretReference::environment("OAUTH_SECRET").unwrap(),
                vec!["https://agent.example.test".to_owned()],
            )
            .unwrap();
            let mut authorization = RemoteMcpAxumAuthorization::from_config(
                2,
                &config,
                Verifier(Arc::clone(&verifications)),
            )
            .unwrap();
            authorization.shared.authorization_operations = Arc::new(Semaphore::new(2));
            let mut original = authorization
                .shared
                .verifier
                .verify("one")
                .unwrap()
                .validate_connection(config.issuer(), config.resource(), 1_000)
                .unwrap();
            original.constrain_validity(Instant::now(), 1_900).unwrap();
            let id = RemoteSessionId::new("session_stream_0123456789").unwrap();
            authorization
                .shared
                .gate
                .lock()
                .unwrap()
                .sessions
                .establish(id.clone(), &original, 1_000)
                .unwrap();
            let mut headers = HeaderMap::new();
            headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
            headers.insert(
                ORIGIN,
                HeaderValue::from_static("https://agent.example.test"),
            );
            headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer one"));
            headers.insert(ACCEPT, HeaderValue::from_static("text/event-stream"));
            headers.insert(
                MCP_SESSION_HEADER_NAME,
                HeaderValue::from_str(id.as_str()).unwrap(),
            );
            headers.insert(
                MCP_PROTOCOL_VERSION_HEADER_NAME,
                HeaderValue::from_static("2025-03-26"),
            );
            headers.insert(
                "x-private-input",
                HeaderValue::from_static("must-not-forward"),
            );
            Self {
                authorization,
                id,
                headers,
                original,
                verifications,
            }
        }

        fn borrowed(&self) -> AuthorizedRemoteMcpSessionEventStream {
            let shared = &self.authorization.shared;
            let authenticator = RemoteAccessAuthenticator::new(
                shared.verifier.as_ref(),
                &shared.issuer,
                &shared.resource,
            );
            let origins = shared
                .trusted_origins
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            let policy = RemoteHttpAuthorization::new(&authenticator, &origins);
            authorize_axum_session_event_stream(
                &mut shared.gate.lock().unwrap(),
                &policy,
                &self.headers,
                1_000,
            )
            .unwrap()
        }
    }

    fn echo(request: Request<Body>) -> Ready<Result<Request<Body>, Infallible>> {
        ready(Ok(request))
    }

    async fn assert_request(request: Request<Body>, fixture: &Fixture) {
        assert_eq!(request.method(), Method::GET);
        assert_eq!(
            request.headers()[MCP_SESSION_HEADER_NAME],
            fixture.id.as_str()
        );
        assert_eq!(request.headers()[HOST], "memory.example.test");
        assert_eq!(request.headers()[ORIGIN], "https://agent.example.test");
        assert_eq!(request.headers()[ACCEPT], "text/event-stream");
        assert_eq!(
            request.headers()[MCP_PROTOCOL_VERSION_HEADER_NAME],
            "2025-03-26"
        );
        for name in [
            AUTHORIZATION,
            CONTENT_TYPE,
            LAST_EVENT_ID,
            "x-private-input".parse().unwrap(),
        ] {
            assert!(!request.headers().contains_key(name));
        }
        let proof = request.extensions().get::<VerifiedRemoteAccess>().unwrap();
        assert_eq!(proof.workspace_id(), &WorkspaceId::new("workspace_01"));
        assert_eq!(
            proof.validity_deadline(),
            fixture.original.validity_deadline()
        );
        assert_eq!(proof.expires_at_epoch_seconds(), 2_000);
        assert!(
            axum::body::to_bytes(request.into_body(), 1)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn owned_shared_and_borrowed_get_preserve_exact_session_and_tenant() {
        let fixture = Fixture::new();
        let direct = AuthorizedTowerMcpDispatcher::new(tower::service_fn(echo));
        let mut tenant = TenantAwareTowerMcpDispatcher::new(|access: &VerifiedRemoteAccess| {
            assert_eq!(access.workspace_id(), &WorkspaceId::new("workspace_01"));
            Ok::<_, Infallible>(tower::service_fn(echo))
        });
        tenant.factory_operations = Arc::new(Semaphore::new(2));
        let owned = fixture
            .authorization
            .authorize_and_dispatch_session_event_stream(&fixture.headers, 1_000, &direct)
            .await
            .unwrap();
        let shared = fixture
            .authorization
            .shared
            .authorize_and_dispatch_session_event_stream(&fixture.headers, 1_000, &tenant)
            .await
            .unwrap();
        let borrowed = fixture.borrowed();
        assert_eq!(borrowed.session_id(), &fixture.id);
        assert_eq!(
            borrowed.transport().validated_origin(),
            Some("https://agent.example.test")
        );
        assert!(!format!("{borrowed:?}").contains(fixture.id.as_str()));
        let borrowed_request = borrowed.dispatch_with(&direct).await.unwrap();
        for request in [owned, shared, borrowed_request] {
            assert_request(request, &fixture).await;
        }
        assert_eq!(
            fixture
                .authorization
                .shared
                .gate
                .lock()
                .unwrap()
                .sessions
                .len(),
            1
        );
        assert_eq!(fixture.verifications.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn every_bound_authority_substitution_is_denied_before_dispatch() {
        let mut fixture = Fixture::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let direct = AuthorizedTowerMcpDispatcher::new(tower::service_fn(move |request| {
            observed.fetch_add(1, Ordering::SeqCst);
            echo(request)
        }));
        for (token, status) in [
            ("workspace", 403),
            ("subject", 403),
            ("client", 403),
            ("scope", 403),
            ("issuer", 401),
            ("audience", 401),
            ("expired", 401),
            ("invalid", 401),
        ] {
            fixture.headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
            );
            let result = fixture
                .authorization
                .authorize_and_dispatch_session_event_stream(&fixture.headers, 1_000, &direct)
                .await;
            assert!(
                matches!(result, Err(RemoteMcpDispatchError::Authorization(
                RemoteMcpHttpRejection { status: actual, .. }
            )) if actual == status),
                "unexpected rejection for {token}"
            );
        }
        fixture
            .headers
            .insert(AUTHORIZATION, HeaderValue::from_static("Bearer one"));
        fixture.headers.insert(
            MCP_SESSION_HEADER_NAME,
            HeaderValue::from_static("session_unknown_0123456789"),
        );
        let unknown = fixture
            .authorization
            .authorize_and_dispatch_session_event_stream(&fixture.headers, 1_000, &direct)
            .await;
        assert!(matches!(
            unknown,
            Err(RemoteMcpDispatchError::Authorization(
                RemoteMcpHttpRejection { status: 403, .. }
            ))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn replay_and_invalid_get_headers_fail_before_verification() {
        let mut fixture = Fixture::new();
        let direct = AuthorizedTowerMcpDispatcher::new(tower::service_fn(echo));
        for cursor in [
            HeaderValue::from_static(""),
            HeaderValue::from_static("foreign-workspace-event"),
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        ] {
            fixture.headers.insert(LAST_EVENT_ID, cursor);
            let result = fixture
                .authorization
                .authorize_and_dispatch_session_event_stream(&fixture.headers, 1_000, &direct)
                .await;
            assert!(matches!(
                result,
                Err(RemoteMcpDispatchError::Authorization(
                    RemoteMcpHttpRejection { status: 400, .. }
                ))
            ));
        }
        fixture
            .headers
            .append(LAST_EVENT_ID, HeaderValue::from_static("duplicate"));
        assert!(
            fixture
                .authorization
                .authorize_and_dispatch_session_event_stream(&fixture.headers, 1_000, &direct,)
                .await
                .is_err()
        );
        fixture.headers.remove(LAST_EVENT_ID);
        fixture
            .headers
            .insert(ACCEPT, HeaderValue::from_static("application/json"));
        assert!(matches!(
            fixture
                .authorization
                .authorize_and_dispatch_session_event_stream(&fixture.headers, 1_000, &direct,)
                .await,
            Err(RemoteMcpDispatchError::Authorization(
                RemoteMcpHttpRejection { status: 406, .. }
            ))
        ));
        assert_eq!(fixture.verifications.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn all_stateless_get_entrypoints_explicitly_reject_replay() {
        let mut fixture = Fixture::new();
        fixture.headers.remove(MCP_SESSION_HEADER_NAME);
        let direct = AuthorizedTowerMcpDispatcher::new(tower::service_fn(echo));
        for cursor in [
            HeaderValue::from_static(""),
            HeaderValue::from_static("foreign-workspace-event"),
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        ] {
            fixture.headers.insert(LAST_EVENT_ID, cursor);
            let owned = fixture
                .authorization
                .authorize_and_dispatch_event_stream(&fixture.headers, 1_000, &direct)
                .await;
            let shared = fixture
                .authorization
                .shared
                .authorize_and_dispatch_event_stream(&fixture.headers, 1_000, &direct)
                .await;
            for result in [owned, shared] {
                assert!(matches!(
                    result,
                    Err(RemoteMcpDispatchError::Authorization(
                        RemoteMcpHttpRejection { status: 400, .. }
                    ))
                ));
            }
            assert_eq!(
                fixture
                    .authorization
                    .authorize_event_stream(&fixture.headers, 1_000,)
                    .unwrap_err()
                    .status,
                400
            );
        }
        assert_eq!(fixture.verifications.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stateless_port_stays_separate_and_missing_session_never_dispatches() {
        let mut fixture = Fixture::new();
        let direct = AuthorizedTowerMcpDispatcher::new(tower::service_fn(echo));
        assert!(
            fixture
                .authorization
                .authorize_and_dispatch_event_stream(&fixture.headers, 1_000, &direct,)
                .await
                .is_err()
        );
        fixture.headers.remove(MCP_SESSION_HEADER_NAME);
        assert!(
            fixture
                .authorization
                .authorize_and_dispatch_session_event_stream(&fixture.headers, 1_000, &direct,)
                .await
                .is_err()
        );
        assert_eq!(fixture.verifications.load(Ordering::SeqCst), 1);
        let request = fixture
            .authorization
            .authorize_and_dispatch_event_stream(&fixture.headers, 1_000, &direct)
            .await
            .unwrap();
        assert!(!request.headers().contains_key(MCP_SESSION_HEADER_NAME));
    }

    #[tokio::test]
    async fn session_stream_dispatch_does_not_hold_the_registry_lock() {
        struct Probe<'gate>(&'gate Mutex<RemoteMcpHttpGate>);
        impl AuthorizedRemoteMcpSessionEventStreamDispatcher for Probe<'_> {
            type Output = ();
            type Error = Infallible;
            type DispatchFuture = Ready<Result<(), Infallible>>;
            fn open_session(
                &self,
                _: AuthorizedRemoteMcpSessionEventStream,
            ) -> Self::DispatchFuture {
                assert!(
                    self.0.try_lock().is_ok(),
                    "dispatch must not hold the registry lock"
                );
                ready(Ok(()))
            }
        }
        let fixture = Fixture::new();
        fixture
            .authorization
            .authorize_and_dispatch_session_event_stream(
                &fixture.headers,
                1_000,
                &Probe(&fixture.authorization.shared.gate),
            )
            .await
            .unwrap();
    }

    struct DelayedReady {
        calls: Arc<AtomicUsize>,
        timer: Pin<Box<tokio::time::Sleep>>,
    }

    impl Clone for DelayedReady {
        fn clone(&self) -> Self {
            Self {
                calls: Arc::clone(&self.calls),
                timer: Box::pin(tokio::time::sleep(Duration::from_millis(1_200))),
            }
        }
    }

    impl tower::Service<Request<Body>> for DelayedReady {
        type Response = Request<Body>;
        type Error = Infallible;
        type Future = Ready<Result<Self::Response, Infallible>>;

        fn poll_ready(
            &mut self,
            context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Infallible>> {
            std::future::Future::poll(self.timer.as_mut(), context).map(|()| Ok(()))
        }

        fn call(&mut self, request: Request<Body>) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            echo(request)
        }
    }

    #[tokio::test]
    async fn readiness_wait_cannot_extend_the_original_session_deadline() {
        let mut fixture = Fixture::new();
        fixture
            .original
            .constrain_validity(Instant::now(), 1_999)
            .unwrap();
        fixture
            .authorization
            .shared
            .gate
            .lock()
            .unwrap()
            .sessions
            .revalidate_access(&fixture.id, &mut fixture.original, 1_000)
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let dispatcher = AuthorizedTowerMcpDispatcher::new(DelayedReady {
            calls: Arc::clone(&calls),
            timer: Box::pin(tokio::time::sleep(Duration::from_millis(1_200))),
        });
        let result = fixture
            .authorization
            .authorize_and_dispatch_session_event_stream(&fixture.headers, 1_000, &dispatcher)
            .await;
        assert!(matches!(
            result,
            Err(RemoteMcpDispatchError::Dispatch(
                TowerMcpDispatchError::ExpiredAuthorization,
            ))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        // A valid refreshed token and stale epoch snapshot cannot open an
        // elapsed session.
        let result = fixture
            .authorization
            .authorize_and_dispatch_session_event_stream(&fixture.headers, 1_000, &dispatcher)
            .await;
        assert!(matches!(
            result,
            Err(RemoteMcpDispatchError::Authorization(
                RemoteMcpHttpRejection { status: 403, .. }
            ))
        ));
    }

    #[tokio::test]
    async fn tenant_factory_wait_cannot_extend_the_original_session_deadline() {
        let mut fixture = Fixture::new();
        fixture
            .original
            .constrain_validity(Instant::now(), 1_999)
            .unwrap();
        fixture
            .authorization
            .shared
            .gate
            .lock()
            .unwrap()
            .sessions
            .revalidate_access(&fixture.id, &mut fixture.original, 1_000)
            .unwrap();
        let builds = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let observed_builds = Arc::clone(&builds);
        let observed_calls = Arc::clone(&calls);
        let mut dispatcher = TenantAwareTowerMcpDispatcher::new(move |_: &VerifiedRemoteAccess| {
            observed_builds.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(1_100));
            let observed = Arc::clone(&observed_calls);
            Ok::<_, Infallible>(tower::service_fn(move |request| {
                observed.fetch_add(1, Ordering::SeqCst);
                echo(request)
            }))
        });
        dispatcher.factory_operations = Arc::new(Semaphore::new(2));
        let result = fixture
            .authorization
            .authorize_and_dispatch_session_event_stream(&fixture.headers, 1_000, &dispatcher)
            .await;
        assert!(matches!(
            result,
            Err(RemoteMcpDispatchError::Dispatch(
                super::TenantAwareTowerMcpDispatchError::ExpiredAuthorization,
            ))
        ));
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

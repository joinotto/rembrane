//! HTTP-facing authorization gate for remote MCP server transports.
//!
//! This adapter performs only the minimum bounded JSON-RPC classification
//! needed for authorization. The official MCP SDK remains responsible for
//! protocol execution, while this gate ensures every accepted request has
//! already passed bearer, origin, method/tool, session, and tenant checks.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode,
        header::{
            ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST, ORIGIN, RETRY_AFTER, WWW_AUTHENTICATE,
        },
    },
    response::{IntoResponse, Response},
};
use rembrane_application::{
    RemoteAccessAuthenticator, RemoteHttpAuthorization, RemoteHttpAuthorizationError,
    RemoteSessionHttpError, RemoteSessionRegistry, RemoteTokenVerifier,
};
use rembrane_config::RemoteMcpConfig;
use rembrane_contracts::{RemoteMcpRequestAuthorization, RemoteSessionId, VerifiedRemoteAccess};
use serde::Deserialize;
use tower::ServiceExt;
use zeroize::Zeroizing;

pub const MCP_SESSION_HEADER: &str = "Mcp-Session-Id";
pub const MAX_REMOTE_MCP_REQUEST_BYTES: usize = 1_048_576;
pub const MAX_REMOTE_MCP_HEADER_BYTES: usize = 8_192;
pub const MAX_REMOTE_MCP_TENANT_SERVICES: usize = 10_000;
const MCP_SESSION_HEADER_NAME: HeaderName = HeaderName::from_static("mcp-session-id");
const MCP_PROTOCOL_VERSION_HEADER_NAME: HeaderName =
    HeaderName::from_static("mcp-protocol-version");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteMcpInvocation {
    method: String,
    tool_name: Option<String>,
}

impl RemoteMcpInvocation {
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    #[must_use]
    pub fn tool_name(&self) -> Option<&str> {
        self.tool_name.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteMcpProtocolHeaders {
    content_type: String,
    accept: String,
    protocol_version: Option<String>,
    validated_host: Option<String>,
    validated_origin: Option<String>,
}

impl RemoteMcpProtocolHeaders {
    #[must_use]
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    #[must_use]
    pub fn accept(&self) -> &str {
        &self.accept
    }

    #[must_use]
    pub fn protocol_version(&self) -> Option<&str> {
        self.protocol_version.as_deref()
    }

    /// Returns the exact public host that passed the outer authorization gate.
    #[must_use]
    pub fn validated_host(&self) -> Option<&str> {
        self.validated_host.as_deref()
    }

    /// Returns the exact browser origin that passed the outer authorization
    /// gate, when the request supplied one.
    #[must_use]
    pub fn validated_origin(&self) -> Option<&str> {
        self.validated_origin.as_deref()
    }

    fn transport_neutral() -> Self {
        Self {
            content_type: "application/json".to_owned(),
            accept: "application/json, text/event-stream".to_owned(),
            protocol_version: None,
            validated_host: None,
            validated_origin: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedRemoteMcpEventStream {
    access: VerifiedRemoteAccess,
    accept: String,
    protocol_version: Option<String>,
    validated_host: Option<String>,
    validated_origin: Option<String>,
}

pub trait AuthorizedRemoteMcpEventStreamDispatcher {
    type Output;
    type Error;
    type DispatchFuture: Future<Output = Result<Self::Output, Self::Error>> + Send;

    fn open(
        &self,
        access: VerifiedRemoteAccess,
        accept: String,
        protocol_version: Option<String>,
        validated_host: Option<String>,
        validated_origin: Option<String>,
    ) -> Self::DispatchFuture;
}

pub trait AuthorizedRemoteMcpSessionDeletionDispatcher {
    type Output;
    type Error;
    type DispatchFuture: Future<Output = Result<Self::Output, Self::Error>> + Send;

    fn terminate(
        &self,
        access: VerifiedRemoteAccess,
        session_id: RemoteSessionId,
        protocol_version: Option<String>,
        validated_host: String,
        validated_origin: Option<String>,
    ) -> Self::DispatchFuture;
}

impl AuthorizedRemoteMcpEventStream {
    #[must_use]
    pub const fn access(&self) -> &VerifiedRemoteAccess {
        &self.access
    }

    #[must_use]
    pub fn accept(&self) -> &str {
        &self.accept
    }

    #[must_use]
    pub fn protocol_version(&self) -> Option<&str> {
        self.protocol_version.as_deref()
    }

    #[must_use]
    pub fn validated_host(&self) -> Option<&str> {
        self.validated_host.as_deref()
    }

    #[must_use]
    pub fn validated_origin(&self) -> Option<&str> {
        self.validated_origin.as_deref()
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        VerifiedRemoteAccess,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    ) {
        (
            self.access,
            self.accept,
            self.protocol_version,
            self.validated_host,
            self.validated_origin,
        )
    }

    /// Consumes the authorization proof and opens the server event stream
    /// through one asynchronous transport dispatcher.
    ///
    /// # Errors
    ///
    /// Returns the transport dispatcher's error.
    pub async fn dispatch_with<Dispatcher>(
        self,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, Dispatcher::Error>
    where
        Dispatcher: AuthorizedRemoteMcpEventStreamDispatcher,
    {
        let (access, accept, protocol_version, validated_host, validated_origin) =
            self.into_parts();
        dispatcher
            .open(
                access,
                accept,
                protocol_version,
                validated_host,
                validated_origin,
            )
            .await
    }
}

/// One authorized MCP request whose identity, operation classification, and
/// exact bounded body remain coupled until dispatch.
pub struct AuthorizedRemoteMcpRequest {
    access: VerifiedRemoteAccess,
    invocation: RemoteMcpInvocation,
    protocol_headers: RemoteMcpProtocolHeaders,
    body: Zeroizing<Vec<u8>>,
}

/// Transport port for handing one fully authorized request to an MCP protocol
/// implementation.
///
/// Implementations receive owned, coupled dispatch inputs. They cannot ask
/// this boundary to authorize one body and dispatch another.
pub trait AuthorizedRemoteMcpDispatcher {
    type Output;
    type Error;
    type DispatchFuture: Future<Output = Result<Self::Output, Self::Error>> + Send;

    fn dispatch(
        &self,
        access: VerifiedRemoteAccess,
        invocation: RemoteMcpInvocation,
        protocol_headers: RemoteMcpProtocolHeaders,
        body: Zeroizing<Vec<u8>>,
    ) -> Self::DispatchFuture;
}

/// Successful official-SDK initialization output paired with the validated
/// session identifier returned in the downstream HTTP response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitializedRemoteMcpSession<Output> {
    output: Output,
    session_id: RemoteSessionId,
}

impl<Output> InitializedRemoteMcpSession<Output> {
    #[must_use]
    pub const fn new(output: Output, session_id: RemoteSessionId) -> Self {
        Self { output, session_id }
    }

    #[must_use]
    pub const fn output(&self) -> &Output {
        &self.output
    }

    #[must_use]
    pub const fn session_id(&self) -> &RemoteSessionId {
        &self.session_id
    }

    #[must_use]
    pub fn into_parts(self) -> (Output, RemoteSessionId) {
        (self.output, self.session_id)
    }
}

/// Transport port for confirmed official-SDK session initialization.
///
/// Implementations must validate and extract the canonical session identifier
/// from the successful SDK response. `terminate` compensates a downstream
/// session when the bounded local tenant binding cannot be committed.
pub trait AuthorizedRemoteMcpInitializationDispatcher {
    type Output;
    type InitializeError;
    type TerminationError;
    type InitializeFuture: Future<Output = Result<InitializedRemoteMcpSession<Self::Output>, Self::InitializeError>>
        + Send;
    type TerminationFuture: Future<Output = Result<(), Self::TerminationError>> + Send;

    fn initialize(
        &self,
        access: VerifiedRemoteAccess,
        invocation: RemoteMcpInvocation,
        protocol_headers: RemoteMcpProtocolHeaders,
        body: Zeroizing<Vec<u8>>,
    ) -> Self::InitializeFuture;

    fn terminate(
        &self,
        access: VerifiedRemoteAccess,
        session_id: RemoteSessionId,
        protocol_headers: RemoteMcpProtocolHeaders,
    ) -> Self::TerminationFuture;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteMcpInitializationError<InitializeError, TerminationError> {
    Authorization(RemoteMcpHttpRejection),
    Initialize(InitializeError),
    Commit {
        rejection: RemoteMcpHttpRejection,
        termination_error: Option<TerminationError>,
    },
}

/// Adapts authorized POST requests to a cloneable Tower MCP service.
///
/// The official Rust MCP SDK's `StreamableHttpService` implements this Tower
/// contract. Verified access is inserted into request extensions, while only
/// headers already validated by the outer authorization gate are rebuilt.
#[derive(Clone)]
pub struct AuthorizedTowerMcpDispatcher<Service> {
    service: Service,
}

impl<Service> AuthorizedTowerMcpDispatcher<Service> {
    #[must_use]
    pub const fn new(service: Service) -> Self {
        Self { service }
    }
}

/// Builds a tenant-pinned MCP Tower service only after OAuth authorization.
///
/// A multi-tenant remote endpoint must not reuse a handler whose canonical
/// identity was initialized for another tenant. Implementations should create
/// or select a service using the exact verified access supplied here.
pub trait AuthorizedTowerMcpServiceFactory: Clone + Send + Sync + 'static {
    type Service;
    type Error;

    fn create(&self, access: &VerifiedRemoteAccess) -> Result<Self::Service, Self::Error>;
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RemoteTenantServiceKey {
    issuer: String,
    resource: String,
    subject_id: String,
    client_id: String,
    workspace_id: String,
    scopes: Vec<&'static str>,
}

impl From<&VerifiedRemoteAccess> for RemoteTenantServiceKey {
    fn from(access: &VerifiedRemoteAccess) -> Self {
        Self {
            issuer: access.issuer().to_owned(),
            resource: access.resource().to_owned(),
            subject_id: access.subject_id().to_string(),
            client_id: access.client_id().to_string(),
            workspace_id: access.workspace_id().to_string(),
            scopes: access
                .scopes()
                .map(rembrane_contracts::RemoteAccessScope::as_str)
                .collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TenantServiceCacheConfigurationError {
    InvalidCapacity,
}

#[derive(Debug)]
pub enum TenantServiceCacheError<FactoryError> {
    CapacityExceeded,
    LockUnavailable,
    Factory(FactoryError),
}

#[derive(Clone)]
struct CachedTenantService<Service> {
    service: Service,
    retain_until_epoch_seconds: u64,
}

/// Retains one tenant-pinned Tower service for the lifetime of its MCP
/// transport sessions.
///
/// The cache never evicts a service because an eviction could silently discard
/// official SDK session state. Deployments should choose a capacity aligned
/// with their authenticated remote-session ceiling.
#[derive(Clone)]
pub struct BoundedTenantTowerMcpServiceCache<Factory, Service> {
    factory: Factory,
    maximum_services: usize,
    services: Arc<Mutex<BTreeMap<RemoteTenantServiceKey, CachedTenantService<Service>>>>,
}

impl<Factory, Service> BoundedTenantTowerMcpServiceCache<Factory, Service> {
    /// Creates a fail-closed tenant service cache.
    ///
    /// # Errors
    ///
    /// Returns an error when capacity is zero or exceeds the canonical tenant
    /// service ceiling.
    pub fn new(
        maximum_services: usize,
        factory: Factory,
    ) -> Result<Self, TenantServiceCacheConfigurationError> {
        if !(1..=MAX_REMOTE_MCP_TENANT_SERVICES).contains(&maximum_services) {
            return Err(TenantServiceCacheConfigurationError::InvalidCapacity);
        }
        Ok(Self {
            factory,
            maximum_services,
            services: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.services.lock().map_or(0, |services| services.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Removes services whose latest validated token expiry has passed.
    ///
    /// The caller should use the same trusted clock supplied to remote token
    /// validation. A cached service's retention deadline only extends when an
    /// otherwise exact tenant and scope identity presents a later expiry.
    ///
    /// # Errors
    ///
    /// Returns an error if another thread poisoned the cache lock.
    pub fn prune_expired(
        &self,
        now_epoch_seconds: u64,
    ) -> Result<usize, TenantServiceCacheError<std::convert::Infallible>> {
        let mut services = self
            .services
            .lock()
            .map_err(|_| TenantServiceCacheError::LockUnavailable)?;
        let previous = services.len();
        services.retain(|_, cached| cached.retain_until_epoch_seconds > now_epoch_seconds);
        Ok(previous.saturating_sub(services.len()))
    }
}

impl<Factory, Service, FactoryError> AuthorizedTowerMcpServiceFactory
    for BoundedTenantTowerMcpServiceCache<Factory, Service>
where
    Factory:
        Fn(&VerifiedRemoteAccess) -> Result<Service, FactoryError> + Clone + Send + Sync + 'static,
    Service: Clone + Send + 'static,
    FactoryError: Send + 'static,
{
    type Service = Service;
    type Error = TenantServiceCacheError<FactoryError>;

    fn create(&self, access: &VerifiedRemoteAccess) -> Result<Self::Service, Self::Error> {
        let key = RemoteTenantServiceKey::from(access);
        let mut services = self
            .services
            .lock()
            .map_err(|_| TenantServiceCacheError::LockUnavailable)?;
        if let Some(cached) = services.get_mut(&key) {
            cached.retain_until_epoch_seconds = cached
                .retain_until_epoch_seconds
                .max(access.expires_at_epoch_seconds());
            return Ok(cached.service.clone());
        }
        if services.len() >= self.maximum_services {
            return Err(TenantServiceCacheError::CapacityExceeded);
        }
        let service = (self.factory)(access).map_err(TenantServiceCacheError::Factory)?;
        services.insert(
            key,
            CachedTenantService {
                service: service.clone(),
                retain_until_epoch_seconds: access.expires_at_epoch_seconds(),
            },
        );
        Ok(service)
    }
}

impl<Factory, Service, FactoryError> AuthorizedTowerMcpServiceFactory for Factory
where
    Factory:
        Fn(&VerifiedRemoteAccess) -> Result<Service, FactoryError> + Clone + Send + Sync + 'static,
{
    type Service = Service;
    type Error = FactoryError;

    fn create(&self, access: &VerifiedRemoteAccess) -> Result<Self::Service, Self::Error> {
        self(access)
    }
}

/// Dispatches authorized traffic through a service selected for that exact
/// verified tenant.
#[derive(Clone)]
pub struct TenantAwareTowerMcpDispatcher<Factory> {
    factory: Factory,
}

impl<Factory> TenantAwareTowerMcpDispatcher<Factory> {
    #[must_use]
    pub const fn new(factory: Factory) -> Self {
        Self { factory }
    }
}

#[derive(Debug)]
pub enum TowerMcpDispatchError<ServiceError> {
    InvalidAuthorizedMetadata,
    InvalidSdkResponse,
    Service(ServiceError),
}

#[derive(Debug)]
pub enum TenantAwareTowerMcpDispatchError<FactoryError, ServiceError> {
    InvalidAuthorizedMetadata,
    InvalidSdkResponse,
    Factory(FactoryError),
    Service(ServiceError),
}

impl<Service> AuthorizedRemoteMcpDispatcher for AuthorizedTowerMcpDispatcher<Service>
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

    fn dispatch(
        &self,
        access: VerifiedRemoteAccess,
        invocation: RemoteMcpInvocation,
        protocol_headers: RemoteMcpProtocolHeaders,
        body: Zeroizing<Vec<u8>>,
    ) -> Self::DispatchFuture {
        let service = self.service.clone();
        Box::pin(async move {
            let mut request = Request::builder()
                .method(Method::POST)
                .body(Body::from(bytes::Bytes::from_owner(body)))
                .map_err(|_| TowerMcpDispatchError::InvalidAuthorizedMetadata)?;
            insert_validated_header(
                request.headers_mut(),
                CONTENT_TYPE,
                protocol_headers.content_type(),
            )?;
            insert_validated_header(request.headers_mut(), ACCEPT, protocol_headers.accept())?;
            insert_optional_validated_header(
                request.headers_mut(),
                MCP_PROTOCOL_VERSION_HEADER_NAME,
                protocol_headers.protocol_version(),
            )?;
            insert_optional_validated_header(
                request.headers_mut(),
                HOST,
                protocol_headers.validated_host(),
            )?;
            insert_optional_validated_header(
                request.headers_mut(),
                ORIGIN,
                protocol_headers.validated_origin(),
            )?;
            request.extensions_mut().insert(access);
            request.extensions_mut().insert(invocation);
            service
                .oneshot(request)
                .await
                .map_err(TowerMcpDispatchError::Service)
        })
    }
}

impl<Service> AuthorizedRemoteMcpInitializationDispatcher for AuthorizedTowerMcpDispatcher<Service>
where
    Service: tower::Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    Service::Future: Send + 'static,
    Service::Error: Send + 'static,
{
    type Output = Response;
    type InitializeError = TowerMcpDispatchError<Service::Error>;
    type TerminationError = TowerMcpDispatchError<Service::Error>;
    type InitializeFuture = Pin<
        Box<
            dyn Future<
                    Output = Result<
                        InitializedRemoteMcpSession<Self::Output>,
                        Self::InitializeError,
                    >,
                > + Send
                + 'static,
        >,
    >;
    type TerminationFuture =
        Pin<Box<dyn Future<Output = Result<(), Self::TerminationError>> + Send + 'static>>;

    fn initialize(
        &self,
        access: VerifiedRemoteAccess,
        invocation: RemoteMcpInvocation,
        protocol_headers: RemoteMcpProtocolHeaders,
        body: Zeroizing<Vec<u8>>,
    ) -> Self::InitializeFuture {
        let service = self.service.clone();
        Box::pin(async move {
            let mut request = Request::builder()
                .method(Method::POST)
                .body(Body::from(bytes::Bytes::from_owner(body)))
                .map_err(|_| TowerMcpDispatchError::InvalidAuthorizedMetadata)?;
            insert_validated_header(
                request.headers_mut(),
                CONTENT_TYPE,
                protocol_headers.content_type(),
            )?;
            insert_validated_header(request.headers_mut(), ACCEPT, protocol_headers.accept())?;
            insert_optional_validated_header(
                request.headers_mut(),
                MCP_PROTOCOL_VERSION_HEADER_NAME,
                protocol_headers.protocol_version(),
            )?;
            insert_optional_validated_header(
                request.headers_mut(),
                HOST,
                protocol_headers.validated_host(),
            )?;
            insert_optional_validated_header(
                request.headers_mut(),
                ORIGIN,
                protocol_headers.validated_origin(),
            )?;
            request.extensions_mut().insert(access);
            request.extensions_mut().insert(invocation);
            let response = service
                .oneshot(request)
                .await
                .map_err(TowerMcpDispatchError::Service)?;
            if !response.status().is_success() {
                return Err(TowerMcpDispatchError::InvalidSdkResponse);
            }
            let mut session_headers = response.headers().get_all(MCP_SESSION_HEADER_NAME).iter();
            let session_header = session_headers
                .next()
                .ok_or(TowerMcpDispatchError::InvalidSdkResponse)?;
            if session_headers.next().is_some() {
                return Err(TowerMcpDispatchError::InvalidSdkResponse);
            }
            let session_id = session_header
                .to_str()
                .ok()
                .and_then(|value| RemoteSessionId::new(value.to_owned()).ok())
                .ok_or(TowerMcpDispatchError::InvalidSdkResponse)?;
            Ok(InitializedRemoteMcpSession::new(response, session_id))
        })
    }

    fn terminate(
        &self,
        access: VerifiedRemoteAccess,
        session_id: RemoteSessionId,
        protocol_headers: RemoteMcpProtocolHeaders,
    ) -> Self::TerminationFuture {
        let service = self.service.clone();
        Box::pin(async move {
            let validated_host = protocol_headers
                .validated_host()
                .ok_or(TowerMcpDispatchError::InvalidAuthorizedMetadata)?;
            let mut request = Request::builder()
                .method(Method::DELETE)
                .body(Body::empty())
                .map_err(|_| TowerMcpDispatchError::InvalidAuthorizedMetadata)?;
            insert_validated_header(
                request.headers_mut(),
                MCP_SESSION_HEADER_NAME,
                session_id.as_str(),
            )?;
            insert_optional_validated_header(
                request.headers_mut(),
                MCP_PROTOCOL_VERSION_HEADER_NAME,
                protocol_headers.protocol_version(),
            )?;
            insert_validated_header(request.headers_mut(), HOST, validated_host)?;
            insert_optional_validated_header(
                request.headers_mut(),
                ORIGIN,
                protocol_headers.validated_origin(),
            )?;
            request.extensions_mut().insert(access);
            let response = service
                .oneshot(request)
                .await
                .map_err(TowerMcpDispatchError::Service)?;
            if !response.status().is_success() {
                return Err(TowerMcpDispatchError::InvalidSdkResponse);
            }
            Ok(())
        })
    }
}

impl<Service> AuthorizedRemoteMcpEventStreamDispatcher for AuthorizedTowerMcpDispatcher<Service>
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

    fn open(
        &self,
        access: VerifiedRemoteAccess,
        accept: String,
        protocol_version: Option<String>,
        validated_host: Option<String>,
        validated_origin: Option<String>,
    ) -> Self::DispatchFuture {
        let service = self.service.clone();
        Box::pin(async move {
            let mut request = Request::builder()
                .method(Method::GET)
                .body(Body::empty())
                .map_err(|_| TowerMcpDispatchError::InvalidAuthorizedMetadata)?;
            insert_validated_header(request.headers_mut(), ACCEPT, &accept)?;
            insert_optional_validated_header(
                request.headers_mut(),
                MCP_PROTOCOL_VERSION_HEADER_NAME,
                protocol_version.as_deref(),
            )?;
            insert_optional_validated_header(
                request.headers_mut(),
                HOST,
                validated_host.as_deref(),
            )?;
            insert_optional_validated_header(
                request.headers_mut(),
                ORIGIN,
                validated_origin.as_deref(),
            )?;
            request.extensions_mut().insert(access);
            service
                .oneshot(request)
                .await
                .map_err(TowerMcpDispatchError::Service)
        })
    }
}

impl<Service> AuthorizedRemoteMcpSessionDeletionDispatcher for AuthorizedTowerMcpDispatcher<Service>
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

    fn terminate(
        &self,
        access: VerifiedRemoteAccess,
        session_id: RemoteSessionId,
        protocol_version: Option<String>,
        validated_host: String,
        validated_origin: Option<String>,
    ) -> Self::DispatchFuture {
        let service = self.service.clone();
        Box::pin(async move {
            let mut request = Request::builder()
                .method(Method::DELETE)
                .body(Body::empty())
                .map_err(|_| TowerMcpDispatchError::InvalidAuthorizedMetadata)?;
            insert_validated_header(
                request.headers_mut(),
                MCP_SESSION_HEADER_NAME,
                session_id.as_str(),
            )?;
            insert_optional_validated_header(
                request.headers_mut(),
                MCP_PROTOCOL_VERSION_HEADER_NAME,
                protocol_version.as_deref(),
            )?;
            insert_validated_header(request.headers_mut(), HOST, &validated_host)?;
            insert_optional_validated_header(
                request.headers_mut(),
                ORIGIN,
                validated_origin.as_deref(),
            )?;
            request.extensions_mut().insert(access);
            service
                .oneshot(request)
                .await
                .map_err(TowerMcpDispatchError::Service)
        })
    }
}

impl<Factory> AuthorizedRemoteMcpDispatcher for TenantAwareTowerMcpDispatcher<Factory>
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

    fn dispatch(
        &self,
        access: VerifiedRemoteAccess,
        invocation: RemoteMcpInvocation,
        protocol_headers: RemoteMcpProtocolHeaders,
        body: Zeroizing<Vec<u8>>,
    ) -> Self::DispatchFuture {
        let factory = self.factory.clone();
        Box::pin(async move {
            let service = factory
                .create(&access)
                .map_err(TenantAwareTowerMcpDispatchError::Factory)?;
            let mut request = Request::builder()
                .method(Method::POST)
                .body(Body::from(bytes::Bytes::from_owner(body)))
                .map_err(|_| TenantAwareTowerMcpDispatchError::InvalidAuthorizedMetadata)?;
            insert_tenant_validated_header(
                request.headers_mut(),
                CONTENT_TYPE,
                protocol_headers.content_type(),
            )?;
            insert_tenant_validated_header(
                request.headers_mut(),
                ACCEPT,
                protocol_headers.accept(),
            )?;
            insert_optional_tenant_validated_header(
                request.headers_mut(),
                MCP_PROTOCOL_VERSION_HEADER_NAME,
                protocol_headers.protocol_version(),
            )?;
            insert_optional_tenant_validated_header(
                request.headers_mut(),
                HOST,
                protocol_headers.validated_host(),
            )?;
            insert_optional_tenant_validated_header(
                request.headers_mut(),
                ORIGIN,
                protocol_headers.validated_origin(),
            )?;
            request.extensions_mut().insert(access);
            request.extensions_mut().insert(invocation);
            service
                .oneshot(request)
                .await
                .map_err(TenantAwareTowerMcpDispatchError::Service)
        })
    }
}

impl<Factory> AuthorizedRemoteMcpInitializationDispatcher for TenantAwareTowerMcpDispatcher<Factory>
where
    Factory: AuthorizedTowerMcpServiceFactory,
    Factory::Service: tower::Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    <Factory::Service as tower::Service<Request<Body>>>::Future: Send + 'static,
    <Factory::Service as tower::Service<Request<Body>>>::Error: Send + 'static,
    Factory::Error: Send + 'static,
{
    type Output = Response;
    type InitializeError = TenantAwareTowerMcpDispatchError<
        Factory::Error,
        <Factory::Service as tower::Service<Request<Body>>>::Error,
    >;
    type TerminationError = Self::InitializeError;
    type InitializeFuture = Pin<
        Box<
            dyn Future<
                    Output = Result<
                        InitializedRemoteMcpSession<Self::Output>,
                        Self::InitializeError,
                    >,
                > + Send
                + 'static,
        >,
    >;
    type TerminationFuture =
        Pin<Box<dyn Future<Output = Result<(), Self::TerminationError>> + Send + 'static>>;

    fn initialize(
        &self,
        access: VerifiedRemoteAccess,
        invocation: RemoteMcpInvocation,
        protocol_headers: RemoteMcpProtocolHeaders,
        body: Zeroizing<Vec<u8>>,
    ) -> Self::InitializeFuture {
        let factory = self.factory.clone();
        Box::pin(async move {
            let service = factory
                .create(&access)
                .map_err(TenantAwareTowerMcpDispatchError::Factory)?;
            let mut request = Request::builder()
                .method(Method::POST)
                .body(Body::from(bytes::Bytes::from_owner(body)))
                .map_err(|_| TenantAwareTowerMcpDispatchError::InvalidAuthorizedMetadata)?;
            insert_tenant_validated_header(
                request.headers_mut(),
                CONTENT_TYPE,
                protocol_headers.content_type(),
            )?;
            insert_tenant_validated_header(
                request.headers_mut(),
                ACCEPT,
                protocol_headers.accept(),
            )?;
            insert_optional_tenant_validated_header(
                request.headers_mut(),
                MCP_PROTOCOL_VERSION_HEADER_NAME,
                protocol_headers.protocol_version(),
            )?;
            insert_optional_tenant_validated_header(
                request.headers_mut(),
                HOST,
                protocol_headers.validated_host(),
            )?;
            insert_optional_tenant_validated_header(
                request.headers_mut(),
                ORIGIN,
                protocol_headers.validated_origin(),
            )?;
            request.extensions_mut().insert(access);
            request.extensions_mut().insert(invocation);
            let response = service
                .oneshot(request)
                .await
                .map_err(TenantAwareTowerMcpDispatchError::Service)?;
            if !response.status().is_success() {
                return Err(TenantAwareTowerMcpDispatchError::InvalidSdkResponse);
            }
            let mut session_headers = response.headers().get_all(MCP_SESSION_HEADER_NAME).iter();
            let session_header = session_headers
                .next()
                .ok_or(TenantAwareTowerMcpDispatchError::InvalidSdkResponse)?;
            if session_headers.next().is_some() {
                return Err(TenantAwareTowerMcpDispatchError::InvalidSdkResponse);
            }
            let session_id = session_header
                .to_str()
                .ok()
                .and_then(|value| RemoteSessionId::new(value.to_owned()).ok())
                .ok_or(TenantAwareTowerMcpDispatchError::InvalidSdkResponse)?;
            Ok(InitializedRemoteMcpSession::new(response, session_id))
        })
    }

    fn terminate(
        &self,
        access: VerifiedRemoteAccess,
        session_id: RemoteSessionId,
        protocol_headers: RemoteMcpProtocolHeaders,
    ) -> Self::TerminationFuture {
        let factory = self.factory.clone();
        Box::pin(async move {
            let validated_host = protocol_headers
                .validated_host()
                .ok_or(TenantAwareTowerMcpDispatchError::InvalidAuthorizedMetadata)?;
            let service = factory
                .create(&access)
                .map_err(TenantAwareTowerMcpDispatchError::Factory)?;
            let mut request = Request::builder()
                .method(Method::DELETE)
                .body(Body::empty())
                .map_err(|_| TenantAwareTowerMcpDispatchError::InvalidAuthorizedMetadata)?;
            insert_tenant_validated_header(
                request.headers_mut(),
                MCP_SESSION_HEADER_NAME,
                session_id.as_str(),
            )?;
            insert_optional_tenant_validated_header(
                request.headers_mut(),
                MCP_PROTOCOL_VERSION_HEADER_NAME,
                protocol_headers.protocol_version(),
            )?;
            insert_tenant_validated_header(request.headers_mut(), HOST, validated_host)?;
            insert_optional_tenant_validated_header(
                request.headers_mut(),
                ORIGIN,
                protocol_headers.validated_origin(),
            )?;
            request.extensions_mut().insert(access);
            let response = service
                .oneshot(request)
                .await
                .map_err(TenantAwareTowerMcpDispatchError::Service)?;
            if !response.status().is_success() {
                return Err(TenantAwareTowerMcpDispatchError::InvalidSdkResponse);
            }
            Ok(())
        })
    }
}

impl<Factory> AuthorizedRemoteMcpEventStreamDispatcher for TenantAwareTowerMcpDispatcher<Factory>
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

    fn open(
        &self,
        access: VerifiedRemoteAccess,
        accept: String,
        protocol_version: Option<String>,
        validated_host: Option<String>,
        validated_origin: Option<String>,
    ) -> Self::DispatchFuture {
        let factory = self.factory.clone();
        Box::pin(async move {
            let service = factory
                .create(&access)
                .map_err(TenantAwareTowerMcpDispatchError::Factory)?;
            let mut request = Request::builder()
                .method(Method::GET)
                .body(Body::empty())
                .map_err(|_| TenantAwareTowerMcpDispatchError::InvalidAuthorizedMetadata)?;
            insert_tenant_validated_header(request.headers_mut(), ACCEPT, &accept)?;
            insert_optional_tenant_validated_header(
                request.headers_mut(),
                MCP_PROTOCOL_VERSION_HEADER_NAME,
                protocol_version.as_deref(),
            )?;
            insert_optional_tenant_validated_header(
                request.headers_mut(),
                HOST,
                validated_host.as_deref(),
            )?;
            insert_optional_tenant_validated_header(
                request.headers_mut(),
                ORIGIN,
                validated_origin.as_deref(),
            )?;
            request.extensions_mut().insert(access);
            service
                .oneshot(request)
                .await
                .map_err(TenantAwareTowerMcpDispatchError::Service)
        })
    }
}

impl<Factory> AuthorizedRemoteMcpSessionDeletionDispatcher
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

    fn terminate(
        &self,
        access: VerifiedRemoteAccess,
        session_id: RemoteSessionId,
        protocol_version: Option<String>,
        validated_host: String,
        validated_origin: Option<String>,
    ) -> Self::DispatchFuture {
        let factory = self.factory.clone();
        Box::pin(async move {
            let service = factory
                .create(&access)
                .map_err(TenantAwareTowerMcpDispatchError::Factory)?;
            let mut request = Request::builder()
                .method(Method::DELETE)
                .body(Body::empty())
                .map_err(|_| TenantAwareTowerMcpDispatchError::InvalidAuthorizedMetadata)?;
            insert_tenant_validated_header(
                request.headers_mut(),
                MCP_SESSION_HEADER_NAME,
                session_id.as_str(),
            )?;
            insert_optional_tenant_validated_header(
                request.headers_mut(),
                MCP_PROTOCOL_VERSION_HEADER_NAME,
                protocol_version.as_deref(),
            )?;
            insert_tenant_validated_header(request.headers_mut(), HOST, &validated_host)?;
            insert_optional_tenant_validated_header(
                request.headers_mut(),
                ORIGIN,
                validated_origin.as_deref(),
            )?;
            request.extensions_mut().insert(access);
            service
                .oneshot(request)
                .await
                .map_err(TenantAwareTowerMcpDispatchError::Service)
        })
    }
}

fn insert_tenant_validated_header<FactoryError, ServiceError>(
    headers: &mut HeaderMap,
    name: HeaderName,
    value: &str,
) -> Result<(), TenantAwareTowerMcpDispatchError<FactoryError, ServiceError>> {
    let value = HeaderValue::from_str(value)
        .map_err(|_| TenantAwareTowerMcpDispatchError::InvalidAuthorizedMetadata)?;
    headers.insert(name, value);
    Ok(())
}

fn insert_optional_tenant_validated_header<FactoryError, ServiceError>(
    headers: &mut HeaderMap,
    name: HeaderName,
    value: Option<&str>,
) -> Result<(), TenantAwareTowerMcpDispatchError<FactoryError, ServiceError>> {
    if let Some(value) = value {
        insert_tenant_validated_header(headers, name, value)?;
    }
    Ok(())
}

fn insert_validated_header<ServiceError>(
    headers: &mut HeaderMap,
    name: HeaderName,
    value: &str,
) -> Result<(), TowerMcpDispatchError<ServiceError>> {
    let value = HeaderValue::from_str(value)
        .map_err(|_| TowerMcpDispatchError::InvalidAuthorizedMetadata)?;
    headers.insert(name, value);
    Ok(())
}

fn insert_optional_validated_header<ServiceError>(
    headers: &mut HeaderMap,
    name: HeaderName,
    value: Option<&str>,
) -> Result<(), TowerMcpDispatchError<ServiceError>> {
    if let Some(value) = value {
        insert_validated_header(headers, name, value)?;
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemoteMcpDispatchError<DispatchError> {
    Authorization(RemoteMcpHttpRejection),
    Dispatch(DispatchError),
}

impl AuthorizedRemoteMcpRequest {
    #[must_use]
    pub const fn access(&self) -> &VerifiedRemoteAccess {
        &self.access
    }

    #[must_use]
    pub const fn invocation(&self) -> &RemoteMcpInvocation {
        &self.invocation
    }

    #[must_use]
    pub const fn protocol_headers(&self) -> &RemoteMcpProtocolHeaders {
        &self.protocol_headers
    }

    /// Returns only the exact bytes that passed classification and OAuth
    /// authorization. The backing buffer is zeroized when this object drops.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        self.body.as_slice()
    }

    /// Consumes the authorization proof and transfers its coupled identity,
    /// classified invocation, and exact zeroizing body to the transport
    /// dispatcher.
    ///
    /// Consuming the object prevents an adapter from retaining an
    /// authorization decision while independently replacing its request
    /// buffer before official SDK dispatch.
    #[must_use]
    pub fn into_dispatch_parts(
        self,
    ) -> (
        VerifiedRemoteAccess,
        RemoteMcpInvocation,
        RemoteMcpProtocolHeaders,
        Zeroizing<Vec<u8>>,
    ) {
        (
            self.access,
            self.invocation,
            self.protocol_headers,
            self.body,
        )
    }

    /// Consumes this proof and transfers it to one authorized transport
    /// dispatcher.
    ///
    /// # Errors
    ///
    /// Returns the dispatcher's error without recreating or retaining the
    /// authorization proof.
    pub async fn dispatch_with<Dispatcher>(
        self,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, Dispatcher::Error>
    where
        Dispatcher: AuthorizedRemoteMcpDispatcher,
    {
        let (access, invocation, protocol_headers, body) = self.into_dispatch_parts();
        dispatcher
            .dispatch(access, invocation, protocol_headers, body)
            .await
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JsonRpcEnvelope {
    jsonrpc: String,
    method: String,
    #[serde(default)]
    id: JsonRpcId,
    #[serde(default)]
    params: Option<JsonRpcParams>,
}

#[derive(Deserialize)]
struct JsonRpcParams {
    #[serde(default)]
    name: Option<String>,
}

#[derive(Default)]
enum JsonRpcId {
    #[default]
    Missing,
    Present(serde_json::Value),
}

impl JsonRpcId {
    fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }

    fn is_sdk_request_id(&self) -> bool {
        match self {
            Self::Present(serde_json::Value::Number(value)) => value.as_i64().is_some(),
            Self::Present(serde_json::Value::String(_)) => true,
            Self::Missing | Self::Present(_) => false,
        }
    }
}

impl<'de> Deserialize<'de> for JsonRpcId {
    fn deserialize<Deserializer>(deserializer: Deserializer) -> Result<Self, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        serde_json::Value::deserialize(deserializer).map(Self::Present)
    }
}

/// Classifies one bounded JSON-RPC request before SDK dispatch.
///
/// # Errors
///
/// Returns a forbidden response for empty, oversized, malformed, batched, or
/// unsupported JSON-RPC input.
pub fn classify_remote_mcp_request(
    body: &[u8],
) -> Result<RemoteMcpInvocation, RemoteMcpHttpRejection> {
    if body.is_empty() || body.len() > MAX_REMOTE_MCP_REQUEST_BYTES {
        return Err(RemoteMcpHttpGate::forbidden());
    }
    let envelope: JsonRpcEnvelope =
        serde_json::from_slice(body).map_err(|_| RemoteMcpHttpGate::forbidden())?;
    let valid_id = match envelope.method.as_str() {
        "notifications/initialized" | "notifications/cancelled" => envelope.id.is_missing(),
        "initialize" | "ping" | "tools/list" | "tools/call" => envelope.id.is_sdk_request_id(),
        _ => false,
    };
    if envelope.jsonrpc != "2.0" || !valid_id {
        return Err(RemoteMcpHttpGate::forbidden());
    }
    let tool_name = if envelope.method == "tools/call" {
        envelope
            .params
            .as_ref()
            .and_then(|params| params.name.as_deref())
            .map(str::to_owned)
    } else {
        None
    };
    RemoteMcpRequestAuthorization::classify(&envelope.method, tool_name.as_deref())
        .ok_or_else(RemoteMcpHttpGate::forbidden)?;
    Ok(RemoteMcpInvocation {
        method: envelope.method,
        tool_name,
    })
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RemoteMcpHttpRequest<'request> {
    pub authorization: Option<&'request str>,
    pub host: Option<&'request str>,
    pub origin: Option<&'request str>,
    pub session_id: Option<&'request str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteMcpHttpRejection {
    pub status: u16,
    pub www_authenticate: Option<String>,
    pub retry_after_seconds: Option<u64>,
}

impl IntoResponse for RemoteMcpHttpRejection {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let mut response = status.into_response();
        if let Some(challenge) = self.www_authenticate
            && let Ok(value) = HeaderValue::from_str(&challenge)
        {
            response.headers_mut().insert(WWW_AUTHENTICATE, value);
        }
        if let Some(seconds) = self.retry_after_seconds
            && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
        {
            response.headers_mut().insert(RETRY_AFTER, value);
        }
        response
    }
}

/// Converts Axum's parsed header map into the transport-neutral request
/// contract without accepting ambiguous duplicate security headers.
///
/// # Errors
///
/// Returns a fail-closed forbidden response for duplicate or non-text
/// authorization, host, origin, or session headers.
pub fn request_from_axum_headers(
    headers: &HeaderMap,
) -> Result<RemoteMcpHttpRequest<'_>, RemoteMcpHttpRejection> {
    protocol_headers_from_axum(headers)?;
    security_request_from_axum_headers(headers)
}

fn security_request_from_axum_headers(
    headers: &HeaderMap,
) -> Result<RemoteMcpHttpRequest<'_>, RemoteMcpHttpRejection> {
    let authorization = unique_header(headers, &AUTHORIZATION)?;
    let host = unique_header(headers, &HOST)?;
    let origin = unique_header(headers, &ORIGIN)?;
    let session_id = unique_header(headers, &MCP_SESSION_HEADER_NAME)?;
    Ok(RemoteMcpHttpRequest {
        authorization,
        host,
        origin,
        session_id,
    })
}

fn require_event_stream_accept(headers: &HeaderMap) -> Result<(), RemoteMcpHttpRejection> {
    let Some(value) = unique_header(headers, &ACCEPT)? else {
        return Err(RemoteMcpHttpRejection {
            status: 406,
            www_authenticate: None,
            retry_after_seconds: None,
        });
    };
    if value.len() <= 1_024
        && value.split(',').any(|media_range| {
            media_range
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .eq_ignore_ascii_case("text/event-stream")
        })
    {
        Ok(())
    } else {
        Err(RemoteMcpHttpRejection {
            status: 406,
            www_authenticate: None,
            retry_after_seconds: None,
        })
    }
}

fn event_stream_headers_from_axum(
    headers: &HeaderMap,
) -> Result<(String, Option<String>), RemoteMcpHttpRejection> {
    require_event_stream_accept(headers)?;
    let accept = unique_header(headers, &ACCEPT)?.unwrap_or_default();
    let protocol_version = unique_header(headers, &MCP_PROTOCOL_VERSION_HEADER_NAME)?;
    if protocol_version.is_some_and(|value| !valid_protocol_version(value)) {
        return Err(RemoteMcpHttpRejection {
            status: 400,
            www_authenticate: None,
            retry_after_seconds: None,
        });
    }
    Ok((accept.to_owned(), protocol_version.map(str::to_owned)))
}

fn session_deletion_from_axum_headers(
    headers: &HeaderMap,
) -> Result<(RemoteMcpHttpRequest<'_>, Option<&str>), RemoteMcpHttpRejection> {
    let request = security_request_from_axum_headers(headers)?;
    let protocol_version = unique_header(headers, &MCP_PROTOCOL_VERSION_HEADER_NAME)?;
    if protocol_version.is_some_and(|value| !valid_protocol_version(value)) {
        return Err(RemoteMcpHttpRejection {
            status: 400,
            www_authenticate: None,
            retry_after_seconds: None,
        });
    }
    Ok((request, protocol_version))
}

fn protocol_headers_from_axum(
    headers: &HeaderMap,
) -> Result<RemoteMcpProtocolHeaders, RemoteMcpHttpRejection> {
    let content_type = unique_header(headers, &CONTENT_TYPE)?;
    let accept = unique_header(headers, &ACCEPT)?;
    let protocol_version = unique_header(headers, &MCP_PROTOCOL_VERSION_HEADER_NAME)?;
    require_json_content_type(content_type)?;
    require_mcp_accept(accept)?;
    if content_type.is_some_and(|value| value.len() > 256)
        || accept.is_some_and(|value| value.len() > 1_024)
    {
        return Err(RemoteMcpHttpGate::forbidden());
    }
    if protocol_version.is_some_and(|value| !valid_protocol_version(value)) {
        return Err(RemoteMcpHttpRejection {
            status: 400,
            www_authenticate: None,
            retry_after_seconds: None,
        });
    }
    Ok(RemoteMcpProtocolHeaders {
        content_type: content_type.unwrap_or_default().to_owned(),
        accept: accept.unwrap_or_default().to_owned(),
        protocol_version: protocol_version.map(str::to_owned),
        validated_host: None,
        validated_origin: None,
    })
}

fn valid_protocol_version(value: &str) -> bool {
    value.len() == 10
        && value.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 => byte == b'-',
            _ => byte.is_ascii_digit(),
        })
}

fn require_json_content_type(value: Option<&str>) -> Result<(), RemoteMcpHttpRejection> {
    let Some(value) = value else {
        return Err(RemoteMcpHttpRejection {
            status: 415,
            www_authenticate: None,
            retry_after_seconds: None,
        });
    };
    let media_type = value.split(';').next().unwrap_or_default().trim();
    if media_type.eq_ignore_ascii_case("application/json") {
        Ok(())
    } else {
        Err(RemoteMcpHttpRejection {
            status: 415,
            www_authenticate: None,
            retry_after_seconds: None,
        })
    }
}

fn require_mcp_accept(value: Option<&str>) -> Result<(), RemoteMcpHttpRejection> {
    let Some(value) = value else {
        return Err(RemoteMcpHttpRejection {
            status: 406,
            www_authenticate: None,
            retry_after_seconds: None,
        });
    };
    let mut accepts_json = false;
    let mut accepts_events = false;
    for media_range in value.split(',') {
        let media_type = media_range.split(';').next().unwrap_or_default().trim();
        accepts_json |= media_type.eq_ignore_ascii_case("application/json");
        accepts_events |= media_type.eq_ignore_ascii_case("text/event-stream");
    }
    if accepts_json && accepts_events {
        Ok(())
    } else {
        Err(RemoteMcpHttpRejection {
            status: 406,
            www_authenticate: None,
            retry_after_seconds: None,
        })
    }
}

fn unique_header<'headers>(
    headers: &'headers HeaderMap,
    name: &HeaderName,
) -> Result<Option<&'headers str>, RemoteMcpHttpRejection> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(RemoteMcpHttpGate::forbidden());
    }
    first
        .map(|value| {
            if value.as_bytes().len() > MAX_REMOTE_MCP_HEADER_BYTES {
                return Err(RemoteMcpHttpGate::forbidden());
            }
            value.to_str().map_err(|_| RemoteMcpHttpGate::forbidden())
        })
        .transpose()
}

/// Performs exact-body OAuth authorization for an Axum request before the
/// same bytes are dispatched to the official MCP SDK service.
///
/// # Errors
///
/// Returns an HTTP-ready rejection for malformed or ambiguous headers,
/// malformed JSON-RPC, invalid credentials, untrusted host/origin, or missing
/// operation scope.
pub fn authorize_axum_stateless_body<Verifier>(
    gate: &RemoteMcpHttpGate,
    authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
    headers: &HeaderMap,
    body: &[u8],
    now_epoch_seconds: u64,
) -> Result<AuthorizedRemoteMcpRequest, RemoteMcpHttpRejection>
where
    Verifier: RemoteTokenVerifier,
{
    authorize_axum_stateless_owned_body(
        gate,
        authorization,
        headers,
        Zeroizing::new(body.to_vec()),
        now_epoch_seconds,
    )
}

/// Consumes and authorizes one owned Axum request body without cloning its
/// sensitive JSON-RPC bytes before SDK dispatch.
///
/// # Errors
///
/// Returns an HTTP-ready rejection for malformed or ambiguous headers,
/// malformed JSON-RPC, invalid credentials, untrusted host/origin, or missing
/// operation scope.
pub fn authorize_axum_stateless_owned_body<Verifier>(
    gate: &RemoteMcpHttpGate,
    authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
    headers: &HeaderMap,
    body: Zeroizing<Vec<u8>>,
    now_epoch_seconds: u64,
) -> Result<AuthorizedRemoteMcpRequest, RemoteMcpHttpRejection>
where
    Verifier: RemoteTokenVerifier,
{
    let mut protocol_headers = protocol_headers_from_axum(headers)?;
    let request = request_from_axum_headers(headers)?;
    protocol_headers.validated_host = request.host.map(str::to_owned);
    protocol_headers.validated_origin = request.origin.map(str::to_owned);
    let mut authorized =
        gate.authorize_stateless_owned_body(authorization, request, body, now_epoch_seconds)?;
    authorized.protocol_headers = protocol_headers;
    Ok(authorized)
}

/// Performs exact-body OAuth authorization for an established Axum session
/// before transferring the same bytes to the MCP SDK service.
///
/// # Errors
///
/// Returns an HTTP-ready rejection for malformed or ambiguous headers,
/// missing or foreign sessions, malformed JSON-RPC, invalid credentials,
/// untrusted host/origin, or missing operation scope.
pub fn authorize_axum_session_body<Verifier>(
    gate: &mut RemoteMcpHttpGate,
    authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
    headers: &HeaderMap,
    body: &[u8],
    now_epoch_seconds: u64,
) -> Result<AuthorizedRemoteMcpRequest, RemoteMcpHttpRejection>
where
    Verifier: RemoteTokenVerifier,
{
    authorize_axum_session_owned_body(
        gate,
        authorization,
        headers,
        Zeroizing::new(body.to_vec()),
        now_epoch_seconds,
    )
}

/// Consumes and authorizes one established-session Axum body without cloning
/// its sensitive JSON-RPC bytes before SDK dispatch.
///
/// # Errors
///
/// Returns an HTTP-ready rejection for malformed or ambiguous headers,
/// missing or foreign sessions, malformed JSON-RPC, invalid credentials,
/// untrusted host/origin, or missing operation scope.
pub fn authorize_axum_session_owned_body<Verifier>(
    gate: &mut RemoteMcpHttpGate,
    authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
    headers: &HeaderMap,
    body: Zeroizing<Vec<u8>>,
    now_epoch_seconds: u64,
) -> Result<AuthorizedRemoteMcpRequest, RemoteMcpHttpRejection>
where
    Verifier: RemoteTokenVerifier,
{
    let mut protocol_headers = protocol_headers_from_axum(headers)?;
    let request = request_from_axum_headers(headers)?;
    protocol_headers.validated_host = request.host.map(str::to_owned);
    protocol_headers.validated_origin = request.origin.map(str::to_owned);
    let mut authorized =
        gate.authorize_session_owned_body(authorization, request, body, now_epoch_seconds)?;
    authorized.protocol_headers = protocol_headers;
    Ok(authorized)
}

/// Authenticates an exact Axum `initialize` body and establishes its declared
/// transport session.
///
/// Body classification occurs before authentication and capacity mutation, so
/// malformed or substituted non-initialize requests cannot reserve sessions.
///
/// # Errors
///
/// Returns an HTTP-ready rejection for malformed or ambiguous headers,
/// non-initialize JSON-RPC, invalid credentials, untrusted host/origin,
/// duplicate sessions, or capacity exhaustion.
pub fn establish_axum_session_body<Verifier>(
    gate: &mut RemoteMcpHttpGate,
    authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
    headers: &HeaderMap,
    body: &[u8],
    now_epoch_seconds: u64,
) -> Result<AuthorizedRemoteMcpRequest, RemoteMcpHttpRejection>
where
    Verifier: RemoteTokenVerifier,
{
    establish_axum_session_owned_body(
        gate,
        authorization,
        headers,
        Zeroizing::new(body.to_vec()),
        now_epoch_seconds,
    )
}

/// Consumes, classifies, and authenticates one owned Axum `initialize` body
/// before establishing its declared transport session.
///
/// # Errors
///
/// Returns an HTTP-ready rejection for malformed or ambiguous headers,
/// non-initialize JSON-RPC, invalid credentials, untrusted host/origin,
/// duplicate sessions, or capacity exhaustion.
pub fn establish_axum_session_owned_body<Verifier>(
    gate: &mut RemoteMcpHttpGate,
    authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
    headers: &HeaderMap,
    body: Zeroizing<Vec<u8>>,
    now_epoch_seconds: u64,
) -> Result<AuthorizedRemoteMcpRequest, RemoteMcpHttpRejection>
where
    Verifier: RemoteTokenVerifier,
{
    let mut protocol_headers = protocol_headers_from_axum(headers)?;
    let request = request_from_axum_headers(headers)?;
    protocol_headers.validated_host = request.host.map(str::to_owned);
    protocol_headers.validated_origin = request.origin.map(str::to_owned);
    let mut authorized =
        gate.establish_session_owned_body(authorization, request, body, now_epoch_seconds)?;
    authorized.protocol_headers = protocol_headers;
    Ok(authorized)
}

/// Establishes and dispatches an exact Axum `initialize` request, rolling the
/// new session binding back when downstream SDK initialization fails.
///
/// # Errors
///
/// Distinguishes HTTP-ready header, body, OAuth, tenant, or capacity rejection
/// from downstream protocol-dispatch failure.
pub async fn establish_and_dispatch_axum_session<Verifier, Dispatcher>(
    gate: &mut RemoteMcpHttpGate,
    authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
    headers: &HeaderMap,
    body: &[u8],
    now_epoch_seconds: u64,
    dispatcher: &Dispatcher,
) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
where
    Verifier: RemoteTokenVerifier,
    Dispatcher: AuthorizedRemoteMcpDispatcher,
{
    establish_and_dispatch_axum_owned_session(
        gate,
        authorization,
        headers,
        Zeroizing::new(body.to_vec()),
        now_epoch_seconds,
        dispatcher,
    )
    .await
}

/// Consumes, establishes, and dispatches one owned Axum `initialize` body,
/// rolling its new session binding back when SDK initialization fails.
///
/// # Errors
///
/// Distinguishes HTTP-ready header, body, OAuth, tenant, or capacity rejection
/// from downstream protocol-dispatch failure.
pub async fn establish_and_dispatch_axum_owned_session<Verifier, Dispatcher>(
    gate: &mut RemoteMcpHttpGate,
    authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
    headers: &HeaderMap,
    body: Zeroizing<Vec<u8>>,
    now_epoch_seconds: u64,
    dispatcher: &Dispatcher,
) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
where
    Verifier: RemoteTokenVerifier,
    Dispatcher: AuthorizedRemoteMcpDispatcher,
{
    let protocol_headers =
        protocol_headers_from_axum(headers).map_err(RemoteMcpDispatchError::Authorization)?;
    let request =
        request_from_axum_headers(headers).map_err(RemoteMcpDispatchError::Authorization)?;
    gate.establish_and_dispatch_owned_session_body(
        authorization,
        request,
        protocol_headers,
        body,
        now_epoch_seconds,
        dispatcher,
    )
    .await
}

/// Authorizes and dispatches one sessionless Axum initialization, then commits
/// only the official SDK response session identifier.
///
/// # Errors
///
/// Distinguishes HTTP/OAuth authorization, downstream initialization, local
/// binding, and compensating termination failures.
pub async fn initialize_and_commit_axum_session<Verifier, Dispatcher>(
    gate: &mut RemoteMcpHttpGate,
    authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
    headers: &HeaderMap,
    body: &[u8],
    now_epoch_seconds: u64,
    dispatcher: &Dispatcher,
) -> Result<
    InitializedRemoteMcpSession<Dispatcher::Output>,
    RemoteMcpInitializationError<Dispatcher::InitializeError, Dispatcher::TerminationError>,
>
where
    Verifier: RemoteTokenVerifier,
    Dispatcher: AuthorizedRemoteMcpInitializationDispatcher,
{
    initialize_and_commit_axum_owned_session(
        gate,
        authorization,
        headers,
        Zeroizing::new(body.to_vec()),
        now_epoch_seconds,
        dispatcher,
    )
    .await
}

/// Consumes one sessionless Axum initialization body and preserves its single
/// zeroizing allocation through official SDK dispatch and confirmed binding.
///
/// # Errors
///
/// Distinguishes HTTP/OAuth authorization, downstream initialization, local
/// binding, and compensating termination failures.
pub async fn initialize_and_commit_axum_owned_session<Verifier, Dispatcher>(
    gate: &mut RemoteMcpHttpGate,
    authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
    headers: &HeaderMap,
    body: Zeroizing<Vec<u8>>,
    now_epoch_seconds: u64,
    dispatcher: &Dispatcher,
) -> Result<
    InitializedRemoteMcpSession<Dispatcher::Output>,
    RemoteMcpInitializationError<Dispatcher::InitializeError, Dispatcher::TerminationError>,
>
where
    Verifier: RemoteTokenVerifier,
    Dispatcher: AuthorizedRemoteMcpInitializationDispatcher,
{
    let protocol_headers =
        protocol_headers_from_axum(headers).map_err(RemoteMcpInitializationError::Authorization)?;
    let request =
        request_from_axum_headers(headers).map_err(RemoteMcpInitializationError::Authorization)?;
    gate.initialize_and_commit_sdk_session(
        authorization,
        request,
        protocol_headers,
        body,
        now_epoch_seconds,
        dispatcher,
    )
    .await
}

/// Reauthenticates an Axum session DELETE, dispatches it to the protocol
/// service, and commits local deletion only after downstream success.
///
/// # Errors
///
/// Distinguishes HTTP-ready header, OAuth, tenant, protocol, or session
/// rejection from downstream dispatch failure.
pub async fn authorize_axum_session_deletion<Verifier, Dispatcher>(
    gate: &mut RemoteMcpHttpGate,
    authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
    headers: &HeaderMap,
    now_epoch_seconds: u64,
    dispatcher: &Dispatcher,
) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
where
    Verifier: RemoteTokenVerifier,
    Dispatcher: AuthorizedRemoteMcpSessionDeletionDispatcher,
{
    let (request, protocol_version) = session_deletion_from_axum_headers(headers)
        .map_err(RemoteMcpDispatchError::Authorization)?;
    gate.authorize_and_dispatch_termination(
        authorization,
        request,
        protocol_version,
        now_epoch_seconds,
        dispatcher,
    )
    .await
}

/// Owned authorization service suitable for Axum router state.
///
/// It owns the verifier and validated deployment values, then creates the
/// short-lived borrowing authentication objects for each request. This avoids
/// self-referential state while preserving per-request token verification.
pub struct RemoteMcpAxumAuthorization<Verifier> {
    gate: RemoteMcpHttpGate,
    verifier: Verifier,
    issuer: String,
    resource: String,
    trusted_origins: Vec<String>,
}

/// Thread-safe remote MCP authorization state for concurrent HTTP routing.
///
/// The bounded session registry is locked only for local authorization or
/// commit work. Downstream SDK futures are never awaited while that lock is
/// held, so one slow tenant cannot serialize unrelated protocol execution.
pub struct SharedRemoteMcpAxumAuthorization<Verifier> {
    gate: Mutex<RemoteMcpHttpGate>,
    verifier: Verifier,
    issuer: String,
    resource: String,
    trusted_origins: Vec<String>,
}

impl<Verifier> SharedRemoteMcpAxumAuthorization<Verifier>
where
    Verifier: RemoteTokenVerifier,
{
    /// Builds concurrent authorization state from one validated deployment
    /// profile.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection when the configured session capacity
    /// or derived HTTP gate is invalid.
    pub fn from_config(
        maximum_sessions: usize,
        config: &RemoteMcpConfig,
        verifier: Verifier,
    ) -> Result<Self, RemoteMcpHttpRejection> {
        Ok(Self {
            gate: Mutex::new(RemoteMcpHttpGate::from_config(maximum_sessions, config)?),
            verifier,
            issuer: config.issuer().to_owned(),
            resource: config.resource().to_owned(),
            trusted_origins: config.trusted_origins().to_vec(),
        })
    }

    /// Consumes one sessionless initialization without holding the shared
    /// registry lock across official SDK initialization or compensation.
    ///
    /// # Errors
    ///
    /// Distinguishes authorization, initialization, binding, and compensating
    /// downstream termination failures.
    pub async fn initialize_and_commit_owned_session<Dispatcher>(
        &self,
        headers: &HeaderMap,
        body: Zeroizing<Vec<u8>>,
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<
        InitializedRemoteMcpSession<Dispatcher::Output>,
        RemoteMcpInitializationError<Dispatcher::InitializeError, Dispatcher::TerminationError>,
    >
    where
        Dispatcher: AuthorizedRemoteMcpInitializationDispatcher,
    {
        let protocol_headers = protocol_headers_from_axum(headers)
            .map_err(RemoteMcpInitializationError::Authorization)?;
        let request = request_from_axum_headers(headers)
            .map_err(RemoteMcpInitializationError::Authorization)?;
        let authenticator =
            RemoteAccessAuthenticator::new(&self.verifier, &self.issuer, &self.resource);
        let trusted_origins = self
            .trusted_origins
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let authorization = RemoteHttpAuthorization::new(&authenticator, &trusted_origins);
        let authorized = {
            let gate = self
                .gate
                .lock()
                .map_err(|_| RemoteMcpInitializationError::Authorization(lock_rejection()))?;
            gate.authorize_sessionless_initialize_owned_body(
                &authorization,
                request,
                body,
                now_epoch_seconds,
            )
            .map_err(RemoteMcpInitializationError::Authorization)?
        };
        let access = authorized.access().clone();
        let (access_for_dispatch, invocation, _, body) = authorized.into_dispatch_parts();
        let termination_headers = protocol_headers.clone();
        let initialized = dispatcher
            .initialize(access_for_dispatch, invocation, protocol_headers, body)
            .await
            .map_err(RemoteMcpInitializationError::Initialize)?;
        let session_id = initialized.session_id().clone();
        let commit = self
            .gate
            .lock()
            .map_err(|_| RemoteMcpInitializationError::Authorization(lock_rejection()))?
            .commit_sdk_generated_session(session_id.clone(), &access, now_epoch_seconds);
        if let Err(rejection) = commit {
            let termination_error = dispatcher
                .terminate(access, session_id, termination_headers)
                .await
                .err();
            return Err(RemoteMcpInitializationError::Commit {
                rejection,
                termination_error,
            });
        }
        Ok(initialized)
    }
}

fn lock_rejection() -> RemoteMcpHttpRejection {
    RemoteMcpHttpRejection {
        status: 503,
        www_authenticate: None,
        retry_after_seconds: Some(1),
    }
}

impl<Verifier> RemoteMcpAxumAuthorization<Verifier>
where
    Verifier: RemoteTokenVerifier,
{
    /// Builds an owned Axum authorization service from one validated remote
    /// MCP deployment profile.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection when the configured session capacity
    /// or derived HTTP gate is invalid.
    pub fn from_config(
        maximum_sessions: usize,
        config: &RemoteMcpConfig,
        verifier: Verifier,
    ) -> Result<Self, RemoteMcpHttpRejection> {
        Ok(Self {
            gate: RemoteMcpHttpGate::from_config(maximum_sessions, config)?,
            verifier,
            issuer: config.issuer().to_owned(),
            resource: config.resource().to_owned(),
            trusted_origins: config.trusted_origins().to_vec(),
        })
    }

    /// Authorizes one stateless Axum request and its exact JSON-RPC bytes.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed HTTP rejection when headers, body,
    /// authentication, origin, host, or operation scope are invalid.
    pub fn authorize_stateless_body(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        now_epoch_seconds: u64,
    ) -> Result<AuthorizedRemoteMcpRequest, RemoteMcpHttpRejection> {
        let authenticator =
            RemoteAccessAuthenticator::new(&self.verifier, &self.issuer, &self.resource);
        let trusted_origins = self
            .trusted_origins
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let authorization = RemoteHttpAuthorization::new(&authenticator, &trusted_origins);
        authorize_axum_stateless_body(&self.gate, &authorization, headers, body, now_epoch_seconds)
    }

    /// Authorizes a stateless Streamable HTTP GET before the SDK opens its
    /// server event stream.
    ///
    /// # Errors
    ///
    /// Returns 406 for invalid event-stream negotiation, or the normal
    /// fail-closed bearer, origin, host, and session rejection.
    pub fn authorize_event_stream(
        &self,
        headers: &HeaderMap,
        now_epoch_seconds: u64,
    ) -> Result<AuthorizedRemoteMcpEventStream, RemoteMcpHttpRejection> {
        let (accept, protocol_version) = event_stream_headers_from_axum(headers)?;
        let request = security_request_from_axum_headers(headers)?;
        let authenticator =
            RemoteAccessAuthenticator::new(&self.verifier, &self.issuer, &self.resource);
        let trusted_origins = self
            .trusted_origins
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let authorization = RemoteHttpAuthorization::new(&authenticator, &trusted_origins);
        let access =
            self.gate
                .authorize_stateless_connection(&authorization, request, now_epoch_seconds)?;
        Ok(AuthorizedRemoteMcpEventStream {
            access,
            accept,
            protocol_version,
            validated_host: request.host.map(str::to_owned),
            validated_origin: request.origin.map(str::to_owned),
        })
    }

    /// Authorizes and opens one stateless server event stream without
    /// exposing an intermediate reusable proof to the HTTP adapter.
    ///
    /// # Errors
    ///
    /// Distinguishes HTTP-ready authentication/authorization rejection from a
    /// downstream event-stream dispatch failure.
    pub async fn authorize_and_dispatch_event_stream<Dispatcher>(
        &self,
        headers: &HeaderMap,
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
    where
        Dispatcher: AuthorizedRemoteMcpEventStreamDispatcher,
    {
        self.authorize_event_stream(headers, now_epoch_seconds)
            .map_err(RemoteMcpDispatchError::Authorization)?
            .dispatch_with(dispatcher)
            .await
            .map_err(RemoteMcpDispatchError::Dispatch)
    }

    /// Authorizes and dispatches one exact stateless request without exposing
    /// an intermediate reusable authorization decision to the HTTP adapter.
    ///
    /// # Errors
    ///
    /// Distinguishes HTTP-ready authentication/authorization rejection from a
    /// downstream protocol-dispatch failure.
    pub async fn authorize_and_dispatch<Dispatcher>(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
    where
        Dispatcher: AuthorizedRemoteMcpDispatcher,
    {
        self.authorize_and_dispatch_owned(
            headers,
            Zeroizing::new(body.to_vec()),
            now_epoch_seconds,
            dispatcher,
        )
        .await
    }

    /// Consumes, authorizes, and dispatches one owned stateless body without
    /// creating a second plaintext request allocation.
    ///
    /// # Errors
    ///
    /// Distinguishes HTTP-ready authentication/authorization rejection from a
    /// downstream protocol-dispatch failure.
    pub async fn authorize_and_dispatch_owned<Dispatcher>(
        &self,
        headers: &HeaderMap,
        body: Zeroizing<Vec<u8>>,
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
    where
        Dispatcher: AuthorizedRemoteMcpDispatcher,
    {
        let authenticator =
            RemoteAccessAuthenticator::new(&self.verifier, &self.issuer, &self.resource);
        let trusted_origins = self
            .trusted_origins
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let authorization = RemoteHttpAuthorization::new(&authenticator, &trusted_origins);
        authorize_axum_stateless_owned_body(
            &self.gate,
            &authorization,
            headers,
            body,
            now_epoch_seconds,
        )
        .map_err(RemoteMcpDispatchError::Authorization)?
        .dispatch_with(dispatcher)
        .await
        .map_err(RemoteMcpDispatchError::Dispatch)
    }

    /// Authorizes and dispatches one sessionless initialization through the
    /// owned deployment verifier, committing only the official SDK response
    /// session identifier.
    ///
    /// # Errors
    ///
    /// Distinguishes authorization, initialization, binding, and compensating
    /// downstream termination failures.
    pub async fn initialize_and_commit_session<Dispatcher>(
        &mut self,
        headers: &HeaderMap,
        body: &[u8],
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<
        InitializedRemoteMcpSession<Dispatcher::Output>,
        RemoteMcpInitializationError<Dispatcher::InitializeError, Dispatcher::TerminationError>,
    >
    where
        Dispatcher: AuthorizedRemoteMcpInitializationDispatcher,
    {
        self.initialize_and_commit_owned_session(
            headers,
            Zeroizing::new(body.to_vec()),
            now_epoch_seconds,
            dispatcher,
        )
        .await
    }

    /// Consumes one sessionless initialization through the owned deployment
    /// verifier without creating a second plaintext request allocation.
    ///
    /// # Errors
    ///
    /// Distinguishes authorization, initialization, binding, and compensating
    /// downstream termination failures.
    pub async fn initialize_and_commit_owned_session<Dispatcher>(
        &mut self,
        headers: &HeaderMap,
        body: Zeroizing<Vec<u8>>,
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<
        InitializedRemoteMcpSession<Dispatcher::Output>,
        RemoteMcpInitializationError<Dispatcher::InitializeError, Dispatcher::TerminationError>,
    >
    where
        Dispatcher: AuthorizedRemoteMcpInitializationDispatcher,
    {
        let authenticator =
            RemoteAccessAuthenticator::new(&self.verifier, &self.issuer, &self.resource);
        let trusted_origins = self
            .trusted_origins
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let authorization = RemoteHttpAuthorization::new(&authenticator, &trusted_origins);
        initialize_and_commit_axum_owned_session(
            &mut self.gate,
            &authorization,
            headers,
            body,
            now_epoch_seconds,
            dispatcher,
        )
        .await
    }

    /// Establishes and dispatches one exact session initialization through
    /// the owned verifier and validated deployment profile.
    ///
    /// # Errors
    ///
    /// Distinguishes HTTP-ready initialization rejection from downstream
    /// protocol failure and rolls back sessions after failed dispatch.
    pub async fn establish_and_dispatch_session<Dispatcher>(
        &mut self,
        headers: &HeaderMap,
        body: &[u8],
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
    where
        Dispatcher: AuthorizedRemoteMcpDispatcher,
    {
        self.establish_and_dispatch_owned_session(
            headers,
            Zeroizing::new(body.to_vec()),
            now_epoch_seconds,
            dispatcher,
        )
        .await
    }

    /// Consumes, establishes, and dispatches one owned session initialization
    /// without creating a second plaintext request allocation.
    ///
    /// # Errors
    ///
    /// Distinguishes HTTP-ready initialization rejection from downstream
    /// protocol failure and rolls back sessions after failed dispatch.
    pub async fn establish_and_dispatch_owned_session<Dispatcher>(
        &mut self,
        headers: &HeaderMap,
        body: Zeroizing<Vec<u8>>,
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
    where
        Dispatcher: AuthorizedRemoteMcpDispatcher,
    {
        let authenticator =
            RemoteAccessAuthenticator::new(&self.verifier, &self.issuer, &self.resource);
        let trusted_origins = self
            .trusted_origins
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let authorization = RemoteHttpAuthorization::new(&authenticator, &trusted_origins);
        establish_and_dispatch_axum_owned_session(
            &mut self.gate,
            &authorization,
            headers,
            body,
            now_epoch_seconds,
            dispatcher,
        )
        .await
    }

    /// Reauthenticates and dispatches one exact established-session request
    /// through the owned verifier and validated deployment profile.
    ///
    /// # Errors
    ///
    /// Distinguishes HTTP-ready session, authentication, tenant, method, or
    /// scope rejection from downstream protocol failure.
    pub async fn authorize_and_dispatch_session<Dispatcher>(
        &mut self,
        headers: &HeaderMap,
        body: &[u8],
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
    where
        Dispatcher: AuthorizedRemoteMcpDispatcher,
    {
        self.authorize_and_dispatch_owned_session(
            headers,
            Zeroizing::new(body.to_vec()),
            now_epoch_seconds,
            dispatcher,
        )
        .await
    }

    /// Consumes, reauthenticates, and dispatches one owned established-session
    /// request without creating a second plaintext request allocation.
    ///
    /// # Errors
    ///
    /// Distinguishes HTTP-ready session, authentication, tenant, method, or
    /// scope rejection from downstream protocol failure.
    pub async fn authorize_and_dispatch_owned_session<Dispatcher>(
        &mut self,
        headers: &HeaderMap,
        body: Zeroizing<Vec<u8>>,
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
    where
        Dispatcher: AuthorizedRemoteMcpDispatcher,
    {
        let authenticator =
            RemoteAccessAuthenticator::new(&self.verifier, &self.issuer, &self.resource);
        let trusted_origins = self
            .trusted_origins
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let authorization = RemoteHttpAuthorization::new(&authenticator, &trusted_origins);
        authorize_axum_session_owned_body(
            &mut self.gate,
            &authorization,
            headers,
            body,
            now_epoch_seconds,
        )
        .map_err(RemoteMcpDispatchError::Authorization)?
        .dispatch_with(dispatcher)
        .await
        .map_err(RemoteMcpDispatchError::Dispatch)
    }

    /// Reauthenticates, dispatches, and commits deletion of one established
    /// session through the owned verifier and validated deployment profile.
    ///
    /// # Errors
    ///
    /// Distinguishes HTTP-ready header, authentication, tenant, or session
    /// rejection from downstream protocol failure. Failed downstream deletion
    /// retains the local binding for a safe retry.
    pub async fn authorize_and_dispatch_session_deletion<Dispatcher>(
        &mut self,
        headers: &HeaderMap,
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
    where
        Dispatcher: AuthorizedRemoteMcpSessionDeletionDispatcher,
    {
        let authenticator =
            RemoteAccessAuthenticator::new(&self.verifier, &self.issuer, &self.resource);
        let trusted_origins = self
            .trusted_origins
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let authorization = RemoteHttpAuthorization::new(&authenticator, &trusted_origins);
        authorize_axum_session_deletion(
            &mut self.gate,
            &authorization,
            headers,
            now_epoch_seconds,
            dispatcher,
        )
        .await
    }
}

pub struct RemoteMcpHttpGate {
    sessions: RemoteSessionRegistry,
    resource_metadata_url: String,
    allowed_hosts: Vec<String>,
}

impl RemoteMcpHttpGate {
    /// Builds the gate directly from the validated deployment profile.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection when session capacity is invalid.
    pub fn from_config(
        maximum_sessions: usize,
        config: &RemoteMcpConfig,
    ) -> Result<Self, RemoteMcpHttpRejection> {
        Self::new(
            maximum_sessions,
            config.protected_resource_metadata_url(),
            &[config.resource_authority()],
        )
    }

    /// Creates a bounded remote MCP HTTP gate.
    ///
    /// # Errors
    ///
    /// Rejects zero capacity or a resource metadata URL that is not HTTPS.
    pub fn new(
        maximum_sessions: usize,
        resource_metadata_url: impl Into<String>,
        allowed_hosts: &[&str],
    ) -> Result<Self, RemoteMcpHttpRejection> {
        let resource_metadata_url = resource_metadata_url.into();
        if !resource_metadata_url.starts_with("https://")
            || resource_metadata_url.bytes().any(|byte| {
                byte.is_ascii_whitespace()
                    || byte.is_ascii_control()
                    || matches!(byte, b'"' | b'\\')
            })
        {
            return Err(Self::forbidden());
        }
        if allowed_hosts.is_empty()
            || allowed_hosts.len() > 32
            || allowed_hosts
                .iter()
                .any(|host| !Self::valid_authority(host))
        {
            return Err(Self::forbidden());
        }
        let mut allowed_hosts = allowed_hosts
            .iter()
            .map(|host| (*host).to_owned())
            .collect::<Vec<_>>();
        allowed_hosts.sort();
        allowed_hosts.dedup();
        let sessions =
            RemoteSessionRegistry::new(maximum_sessions).map_err(|_| Self::capacity_exceeded())?;
        Ok(Self {
            sessions,
            resource_metadata_url,
            allowed_hosts,
        })
    }

    /// Authorizes an initialize request and binds the supplied session ID.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection for invalid headers, authorization,
    /// duplicate sessions, or capacity exhaustion.
    pub fn establish<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        self.require_allowed_host(request.host)?;
        let session_id = Self::session_id(request.session_id)?;
        self.sessions
            .authorize_and_establish_for_http(
                authorization,
                session_id,
                request.authorization,
                request.origin,
                now_epoch_seconds,
            )
            .map_err(|error| self.rejection(error))
    }

    /// Authorizes a protocol-correct initialize request before the official
    /// SDK generates its session identifier.
    ///
    /// This path deliberately does not reserve local session capacity. The
    /// downstream SDK response must be inspected and its generated identifier
    /// committed through a later confirmed-session step.
    ///
    /// # Errors
    ///
    /// Rejects a supplied session header, malformed or non-initialize JSON-RPC,
    /// invalid credentials, or an untrusted host/origin.
    pub fn authorize_sessionless_initialize_owned_body<Verifier>(
        &self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        body: Zeroizing<Vec<u8>>,
        now_epoch_seconds: u64,
    ) -> Result<AuthorizedRemoteMcpRequest, RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        self.require_allowed_host(request.host)?;
        if request.session_id.is_some() {
            return Err(Self::forbidden());
        }
        let invocation = classify_remote_mcp_request(body.as_slice())?;
        if invocation.method() != "initialize" || invocation.tool_name().is_some() {
            return Err(Self::forbidden());
        }
        let access = authorization
            .authorize_connection_for_http(request.authorization, request.origin, now_epoch_seconds)
            .map_err(|error| self.rejection(error.into()))?;
        Ok(AuthorizedRemoteMcpRequest {
            access,
            invocation,
            protocol_headers: RemoteMcpProtocolHeaders::transport_neutral(),
            body,
        })
    }

    /// Commits the session identifier returned by a successfully dispatched
    /// official SDK initialize response.
    ///
    /// Callers must invoke this only after validating the downstream response
    /// and extracting its canonical `Mcp-Session-Id`. The binding uses the
    /// exact verified access carried by the preceding sessionless initialize
    /// proof; bearer credentials are not accepted or retained here.
    ///
    /// # Errors
    ///
    /// Returns conflict for a duplicate generated identifier, capacity
    /// exhaustion when the bounded registry is full, and an opaque forbidden
    /// response for any other invalid state.
    pub fn commit_sdk_generated_session(
        &mut self,
        session_id: RemoteSessionId,
        access: &VerifiedRemoteAccess,
        now_epoch_seconds: u64,
    ) -> Result<(), RemoteMcpHttpRejection> {
        self.sessions
            .establish(session_id, access, now_epoch_seconds)
            .map_err(|error| {
                self.rejection(match error {
                    rembrane_application::ApplicationError::AlreadyExists => {
                        RemoteSessionHttpError::Conflict
                    }
                    rembrane_application::ApplicationError::StorageUnavailable => {
                        RemoteSessionHttpError::CapacityExceeded
                    }
                    _ => RemoteSessionHttpError::Forbidden,
                })
            })
    }

    /// Authorizes and dispatches one sessionless initialization, then commits
    /// only the session identifier confirmed by the official SDK response.
    ///
    /// If local duplicate or capacity enforcement rejects the generated
    /// identifier, the downstream session is terminated before this operation
    /// returns. A termination failure is preserved in the typed commit error
    /// so the transport can fail closed and surface an operational alert.
    ///
    /// # Errors
    ///
    /// Distinguishes authorization, downstream initialization, and local
    /// commit failures. Commit failures include any compensating downstream
    /// termination failure.
    pub async fn initialize_and_commit_sdk_session<Verifier, Dispatcher>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        mut protocol_headers: RemoteMcpProtocolHeaders,
        body: Zeroizing<Vec<u8>>,
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<
        InitializedRemoteMcpSession<Dispatcher::Output>,
        RemoteMcpInitializationError<Dispatcher::InitializeError, Dispatcher::TerminationError>,
    >
    where
        Verifier: RemoteTokenVerifier,
        Dispatcher: AuthorizedRemoteMcpInitializationDispatcher,
    {
        protocol_headers.validated_host = request.host.map(str::to_owned);
        protocol_headers.validated_origin = request.origin.map(str::to_owned);
        let authorized = self
            .authorize_sessionless_initialize_owned_body(
                authorization,
                request,
                body,
                now_epoch_seconds,
            )
            .map_err(RemoteMcpInitializationError::Authorization)?;
        let access = authorized.access().clone();
        let (access_for_dispatch, invocation, _, body) = authorized.into_dispatch_parts();
        let termination_headers = protocol_headers.clone();
        let initialized = dispatcher
            .initialize(access_for_dispatch, invocation, protocol_headers, body)
            .await
            .map_err(RemoteMcpInitializationError::Initialize)?;
        let session_id = initialized.session_id().clone();
        if let Err(rejection) =
            self.commit_sdk_generated_session(session_id.clone(), &access, now_epoch_seconds)
        {
            let termination_error = dispatcher
                .terminate(access, session_id, termination_headers)
                .await
                .err();
            return Err(RemoteMcpInitializationError::Commit {
                rejection,
                termination_error,
            });
        }
        Ok(initialized)
    }

    /// Classifies an exact `initialize` body before authenticating and
    /// allocating its session binding.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection for invalid JSON-RPC, any method other
    /// than `initialize`, invalid session or credentials, untrusted
    /// host/origin, duplicate sessions, or capacity exhaustion.
    pub fn establish_session_body<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        body: &[u8],
        now_epoch_seconds: u64,
    ) -> Result<AuthorizedRemoteMcpRequest, RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        self.establish_session_owned_body(
            authorization,
            request,
            Zeroizing::new(body.to_vec()),
            now_epoch_seconds,
        )
    }

    /// Consumes and classifies an owned `initialize` body before authentication
    /// and session allocation.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection for invalid JSON-RPC, any method other
    /// than `initialize`, invalid session or credentials, untrusted
    /// host/origin, duplicate sessions, or capacity exhaustion.
    pub fn establish_session_owned_body<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        body: Zeroizing<Vec<u8>>,
        now_epoch_seconds: u64,
    ) -> Result<AuthorizedRemoteMcpRequest, RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        let invocation = classify_remote_mcp_request(body.as_slice())?;
        if invocation.method() != "initialize" || invocation.tool_name().is_some() {
            return Err(Self::forbidden());
        }
        let access = self.establish(authorization, request, now_epoch_seconds)?;
        Ok(AuthorizedRemoteMcpRequest {
            access,
            invocation,
            protocol_headers: RemoteMcpProtocolHeaders::transport_neutral(),
            body,
        })
    }

    /// Establishes and dispatches one exact initialization request, retaining
    /// the session only after downstream SDK success.
    ///
    /// # Errors
    ///
    /// Distinguishes HTTP-ready authorization or capacity rejection from a
    /// downstream dispatch failure. Failed dispatch rolls the newly allocated
    /// session back before returning.
    pub async fn establish_and_dispatch_session_body<Verifier, Dispatcher>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        protocol_headers: RemoteMcpProtocolHeaders,
        body: &[u8],
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
    where
        Verifier: RemoteTokenVerifier,
        Dispatcher: AuthorizedRemoteMcpDispatcher,
    {
        self.establish_and_dispatch_owned_session_body(
            authorization,
            request,
            protocol_headers,
            Zeroizing::new(body.to_vec()),
            now_epoch_seconds,
            dispatcher,
        )
        .await
    }

    /// Consumes and dispatches one owned initialization request, retaining the
    /// session only after downstream SDK success.
    ///
    /// # Errors
    ///
    /// Distinguishes HTTP-ready authorization or capacity rejection from a
    /// downstream dispatch failure. Failed dispatch rolls the newly allocated
    /// session back before returning.
    pub async fn establish_and_dispatch_owned_session_body<Verifier, Dispatcher>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        mut protocol_headers: RemoteMcpProtocolHeaders,
        body: Zeroizing<Vec<u8>>,
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
    where
        Verifier: RemoteTokenVerifier,
        Dispatcher: AuthorizedRemoteMcpDispatcher,
    {
        let session_id =
            Self::session_id(request.session_id).map_err(RemoteMcpDispatchError::Authorization)?;
        protocol_headers.validated_host = request.host.map(str::to_owned);
        protocol_headers.validated_origin = request.origin.map(str::to_owned);
        let mut authorized = self
            .establish_session_owned_body(authorization, request, body, now_epoch_seconds)
            .map_err(RemoteMcpDispatchError::Authorization)?;
        authorized.protocol_headers = protocol_headers;
        let access = authorized.access().clone();
        match authorized.dispatch_with(dispatcher).await {
            Ok(output) => Ok(output),
            Err(error) => {
                self.sessions
                    .terminate(&session_id, &access, now_epoch_seconds)
                    .map_err(|_| {
                        RemoteMcpDispatchError::Authorization(
                            self.rejection(RemoteSessionHttpError::Forbidden),
                        )
                    })?;
                Err(RemoteMcpDispatchError::Dispatch(error))
            }
        }
    }

    /// Reauthenticates and authorizes one established MCP request before the
    /// official SDK receives its JSON-RPC body.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection for missing or invalid session,
    /// authentication, origin, method, tool, scope, or tenant binding.
    pub fn authorize<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        method: &str,
        tool_name: Option<&str>,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        self.require_allowed_host(request.host)?;
        let session_id = Self::session_id(request.session_id)?;
        self.sessions
            .authorize_request_for_http(
                authorization,
                &session_id,
                request.authorization,
                request.origin,
                method,
                tool_name,
                now_epoch_seconds,
            )
            .map_err(|error| self.rejection(error))
    }

    /// Classifies and authorizes one established-session JSON-RPC body as a
    /// single consuming proof.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection for invalid JSON-RPC, session,
    /// credentials, tenant binding, host, origin, method, tool, or scope.
    pub fn authorize_session_body<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        body: &[u8],
        now_epoch_seconds: u64,
    ) -> Result<AuthorizedRemoteMcpRequest, RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        self.authorize_session_owned_body(
            authorization,
            request,
            Zeroizing::new(body.to_vec()),
            now_epoch_seconds,
        )
    }

    /// Consumes and authorizes one owned established-session JSON-RPC body.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection for invalid JSON-RPC, session,
    /// credentials, tenant binding, host, origin, method, tool, or scope.
    pub fn authorize_session_owned_body<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        body: Zeroizing<Vec<u8>>,
        now_epoch_seconds: u64,
    ) -> Result<AuthorizedRemoteMcpRequest, RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        let invocation = classify_remote_mcp_request(body.as_slice())?;
        let access = self.authorize(
            authorization,
            request,
            invocation.method(),
            invocation.tool_name(),
            now_epoch_seconds,
        )?;
        Ok(AuthorizedRemoteMcpRequest {
            access,
            invocation,
            protocol_headers: RemoteMcpProtocolHeaders::transport_neutral(),
            body,
        })
    }

    /// Authorizes one stateless MCP request without accepting or creating a
    /// transport session.
    ///
    /// This is the authorization boundary for modern Streamable HTTP requests
    /// whose protocol version does not use `Mcp-Session-Id`. The bearer token
    /// is still verified on every request, and method/tool classification,
    /// host, origin, and narrow OAuth scope checks remain mandatory.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection for invalid credentials, host, origin,
    /// method/tool classification, or OAuth scope.
    pub fn authorize_stateless<Verifier>(
        &self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        method: &str,
        tool_name: Option<&str>,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        self.require_allowed_host(request.host)?;
        if request.session_id.is_some() || method == "notifications/cancelled" {
            return Err(Self::forbidden());
        }
        match RemoteMcpRequestAuthorization::classify(method, tool_name)
            .ok_or_else(Self::forbidden)?
        {
            RemoteMcpRequestAuthorization::Connection => authorization
                .authorize_connection_for_http(
                    request.authorization,
                    request.origin,
                    now_epoch_seconds,
                )
                .map_err(|error| self.authorization_rejection(error)),
            RemoteMcpRequestAuthorization::Tool(operation) => authorization
                .authorize_tool_for_http(
                    request.authorization,
                    request.origin,
                    operation.tool_name(),
                    now_epoch_seconds,
                )
                .map_err(|error| self.authorization_rejection(error)),
        }
    }

    fn authorize_stateless_connection<Verifier>(
        &self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        self.require_allowed_host(request.host)?;
        if request.session_id.is_some() {
            return Err(Self::forbidden());
        }
        authorization
            .authorize_connection_for_http(request.authorization, request.origin, now_epoch_seconds)
            .map_err(|error| self.authorization_rejection(error))
    }

    /// Classifies and authorizes one stateless JSON-RPC body as a single
    /// operation so callers cannot authorize metadata that differs from the
    /// bytes later dispatched to the protocol SDK.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection for invalid JSON-RPC, credentials,
    /// host, origin, method, tool, or OAuth scope.
    pub fn authorize_stateless_body<Verifier>(
        &self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        body: &[u8],
        now_epoch_seconds: u64,
    ) -> Result<AuthorizedRemoteMcpRequest, RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        self.authorize_stateless_owned_body(
            authorization,
            request,
            Zeroizing::new(body.to_vec()),
            now_epoch_seconds,
        )
    }

    /// Consumes and authorizes one owned stateless JSON-RPC body without
    /// cloning the plaintext request buffer.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection for invalid JSON-RPC, credentials,
    /// host, origin, method, tool, or OAuth scope.
    pub fn authorize_stateless_owned_body<Verifier>(
        &self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        body: Zeroizing<Vec<u8>>,
        now_epoch_seconds: u64,
    ) -> Result<AuthorizedRemoteMcpRequest, RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        let invocation = classify_remote_mcp_request(body.as_slice())?;
        let access = self.authorize_stateless(
            authorization,
            request,
            invocation.method(),
            invocation.tool_name(),
            now_epoch_seconds,
        )?;
        Ok(AuthorizedRemoteMcpRequest {
            access,
            invocation,
            protocol_headers: RemoteMcpProtocolHeaders::transport_neutral(),
            body,
        })
    }

    /// Reauthenticates and removes one established MCP session.
    ///
    /// # Errors
    ///
    /// Returns an HTTP-ready rejection for missing or invalid session,
    /// authentication, origin, or tenant binding.
    pub fn terminate<Verifier>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        now_epoch_seconds: u64,
    ) -> Result<(), RemoteMcpHttpRejection>
    where
        Verifier: RemoteTokenVerifier,
    {
        self.require_allowed_host(request.host)?;
        let session_id = Self::session_id(request.session_id)?;
        self.sessions
            .authorize_and_terminate_for_http(
                authorization,
                &session_id,
                request.authorization,
                request.origin,
                now_epoch_seconds,
            )
            .map_err(|error| self.rejection(error))
    }

    /// Reauthenticates a bound session, dispatches its DELETE to the protocol
    /// service, and commits local deletion only after downstream success.
    ///
    /// # Errors
    ///
    /// Distinguishes HTTP-ready authentication or session rejection from a
    /// downstream dispatch failure. A failed dispatch leaves the local
    /// session binding intact for a safe retry.
    pub async fn authorize_and_dispatch_termination<Verifier, Dispatcher>(
        &mut self,
        authorization: &RemoteHttpAuthorization<'_, '_, Verifier>,
        request: RemoteMcpHttpRequest<'_>,
        protocol_version: Option<&str>,
        now_epoch_seconds: u64,
        dispatcher: &Dispatcher,
    ) -> Result<Dispatcher::Output, RemoteMcpDispatchError<Dispatcher::Error>>
    where
        Verifier: RemoteTokenVerifier,
        Dispatcher: AuthorizedRemoteMcpSessionDeletionDispatcher,
    {
        if protocol_version.is_some_and(|value| !valid_protocol_version(value)) {
            return Err(RemoteMcpDispatchError::Authorization(
                RemoteMcpHttpRejection {
                    status: 400,
                    www_authenticate: None,
                    retry_after_seconds: None,
                },
            ));
        }
        self.require_allowed_host(request.host)
            .map_err(RemoteMcpDispatchError::Authorization)?;
        let session_id =
            Self::session_id(request.session_id).map_err(RemoteMcpDispatchError::Authorization)?;
        let access = self
            .sessions
            .authorize_termination_for_http(
                authorization,
                &session_id,
                request.authorization,
                request.origin,
                now_epoch_seconds,
            )
            .map_err(|error| RemoteMcpDispatchError::Authorization(self.rejection(error)))?;
        let output = dispatcher
            .terminate(
                access.clone(),
                session_id.clone(),
                protocol_version.map(str::to_owned),
                request.host.unwrap_or_default().to_owned(),
                request.origin.map(str::to_owned),
            )
            .await
            .map_err(RemoteMcpDispatchError::Dispatch)?;
        self.sessions
            .terminate(&session_id, &access, now_epoch_seconds)
            .map_err(|_| {
                RemoteMcpDispatchError::Authorization(
                    self.rejection(RemoteSessionHttpError::Forbidden),
                )
            })?;
        Ok(output)
    }

    fn session_id(value: Option<&str>) -> Result<RemoteSessionId, RemoteMcpHttpRejection> {
        value
            .ok_or_else(Self::forbidden)
            .and_then(|value| RemoteSessionId::new(value).map_err(|_| Self::forbidden()))
    }

    fn require_allowed_host(&self, host: Option<&str>) -> Result<(), RemoteMcpHttpRejection> {
        let host = host.ok_or_else(Self::forbidden)?;
        if self.allowed_hosts.iter().any(|allowed| allowed == host) {
            Ok(())
        } else {
            Err(Self::forbidden())
        }
    }

    fn valid_authority(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 255
            && !value.bytes().any(|byte| {
                byte.is_ascii_whitespace()
                    || byte.is_ascii_control()
                    || matches!(byte, b'/' | b'\\' | b'"' | b'\'' | b'@')
            })
    }

    fn rejection(&self, error: RemoteSessionHttpError) -> RemoteMcpHttpRejection {
        match error {
            RemoteSessionHttpError::Unauthorized => RemoteMcpHttpRejection {
                status: 401,
                www_authenticate: Some(format!(
                    "Bearer resource_metadata=\"{}\"",
                    self.resource_metadata_url
                )),
                retry_after_seconds: None,
            },
            RemoteSessionHttpError::Forbidden => Self::forbidden(),
            RemoteSessionHttpError::Conflict => RemoteMcpHttpRejection {
                status: 409,
                www_authenticate: None,
                retry_after_seconds: None,
            },
            RemoteSessionHttpError::CapacityExceeded => Self::capacity_exceeded(),
        }
    }

    fn authorization_rejection(
        &self,
        error: RemoteHttpAuthorizationError,
    ) -> RemoteMcpHttpRejection {
        match error {
            RemoteHttpAuthorizationError::Unauthorized => {
                self.rejection(RemoteSessionHttpError::Unauthorized)
            }
            RemoteHttpAuthorizationError::Forbidden => Self::forbidden(),
        }
    }

    fn forbidden() -> RemoteMcpHttpRejection {
        RemoteMcpHttpRejection {
            status: 403,
            www_authenticate: None,
            retry_after_seconds: None,
        }
    }

    fn capacity_exceeded() -> RemoteMcpHttpRejection {
        RemoteMcpHttpRejection {
            status: 503,
            www_authenticate: None,
            retry_after_seconds: Some(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::{Arc, Mutex},
    };

    use axum::{
        Router,
        body::{Body, Bytes, to_bytes},
        extract::State,
        http::{
            HeaderMap, HeaderValue, Method, Request, StatusCode,
            header::{
                ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST, ORIGIN, RETRY_AFTER, WWW_AUTHENTICATE,
            },
        },
        response::{IntoResponse, Response},
        routing::{get, post},
    };
    use rembrane_application::{
        RemoteAccessAuthenticator, RemoteHttpAuthorization, RemoteTokenVerificationError,
        RemoteTokenVerifier,
    };
    use rembrane_config::{RemoteMcpConfig, SecretReference};
    use rembrane_contracts::{RemoteAccessScope, RemoteSessionId, RemoteTokenClaims};
    use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};
    use rembrane_oauth_introspection::{
        IntrospectionResponse, IntrospectionTokenVerifier, IntrospectionTransport,
        IntrospectionTransportError,
    };
    use tower::ServiceExt;

    use super::{
        AuthorizedRemoteMcpDispatcher, AuthorizedRemoteMcpEventStreamDispatcher,
        AuthorizedRemoteMcpInitializationDispatcher, AuthorizedRemoteMcpSessionDeletionDispatcher,
        AuthorizedTowerMcpDispatcher, AuthorizedTowerMcpServiceFactory,
        BoundedTenantTowerMcpServiceCache, InitializedRemoteMcpSession,
        MAX_REMOTE_MCP_HEADER_BYTES, MCP_PROTOCOL_VERSION_HEADER_NAME, MCP_SESSION_HEADER_NAME,
        RemoteMcpAxumAuthorization, RemoteMcpDispatchError, RemoteMcpHttpGate,
        RemoteMcpHttpRejection, RemoteMcpHttpRequest, RemoteMcpInitializationError,
        RemoteMcpInvocation, SharedRemoteMcpAxumAuthorization, TenantAwareTowerMcpDispatchError,
        TenantAwareTowerMcpDispatcher, TenantServiceCacheError, authorize_axum_session_body,
        authorize_axum_session_deletion, authorize_axum_stateless_body,
        authorize_axum_stateless_owned_body, classify_remote_mcp_request,
        establish_and_dispatch_axum_session, establish_axum_session_body,
        request_from_axum_headers,
    };

    struct Verifier;
    struct OAuthFixtureTransport;

    struct RecordingDispatcher;
    struct RecordingEventStreamDispatcher;
    struct AllocationRecordingDispatcher;

    type TowerInitializationCall = (
        Method,
        String,
        Option<String>,
        Option<HeaderValue>,
        Option<HeaderValue>,
        bool,
    );

    fn assert_compensated_tower_initialization(calls: &[TowerInitializationCall]) {
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].0, Method::POST);
        assert_eq!(calls[0].1, "workspace_01");
        assert_eq!(calls[0].2, None);
        assert_eq!(calls[1].0, Method::DELETE);
        assert_eq!(calls[1].1, "workspace_01");
        assert_eq!(
            calls[1].2.as_deref(),
            Some("session_generated_tower_0123456789")
        );
        for call in calls {
            assert_eq!(
                call.3.as_ref().and_then(|value| value.to_str().ok()),
                Some("memory.example.test")
            );
            assert_eq!(
                call.4.as_ref().and_then(|value| value.to_str().ok()),
                Some("https://agent.example.test")
            );
            assert!(!call.5, "bearer credential must not reach the SDK service");
        }
    }

    fn assert_tenant_compensation(
        constructions: &Mutex<Vec<String>>,
        calls: &Mutex<Vec<(String, String, Method)>>,
    ) {
        assert_eq!(
            *constructions.lock().expect("construction log"),
            ["workspace_01"]
        );
        assert_eq!(
            *calls.lock().expect("call log"),
            [
                (
                    "workspace_01".to_owned(),
                    "workspace_01".to_owned(),
                    Method::POST
                ),
                (
                    "workspace_01".to_owned(),
                    "workspace_01".to_owned(),
                    Method::DELETE
                )
            ]
        );
    }

    struct ConfirmedInitializationDispatcher {
        session_id: RemoteSessionId,
        terminated: Arc<Mutex<Vec<(String, String)>>>,
        fail_termination: bool,
    }

    struct LockProbeInitializationDispatcher<'gate> {
        gate: &'gate Mutex<RemoteMcpHttpGate>,
        session_id: RemoteSessionId,
        observed_unlocked: Arc<Mutex<Vec<bool>>>,
    }

    impl AuthorizedRemoteMcpInitializationDispatcher for LockProbeInitializationDispatcher<'_> {
        type Output = ();
        type InitializeError = std::convert::Infallible;
        type TerminationError = std::convert::Infallible;
        type InitializeFuture = std::future::Ready<
            Result<InitializedRemoteMcpSession<Self::Output>, Self::InitializeError>,
        >;
        type TerminationFuture = std::future::Ready<Result<(), Self::TerminationError>>;

        fn initialize(
            &self,
            _access: rembrane_contracts::VerifiedRemoteAccess,
            _invocation: RemoteMcpInvocation,
            _protocol_headers: super::RemoteMcpProtocolHeaders,
            _body: zeroize::Zeroizing<Vec<u8>>,
        ) -> Self::InitializeFuture {
            self.observed_unlocked
                .lock()
                .expect("probe log")
                .push(self.gate.try_lock().is_ok());
            std::future::ready(Ok(InitializedRemoteMcpSession::new(
                (),
                self.session_id.clone(),
            )))
        }

        fn terminate(
            &self,
            _access: rembrane_contracts::VerifiedRemoteAccess,
            _session_id: RemoteSessionId,
            _protocol_headers: super::RemoteMcpProtocolHeaders,
        ) -> Self::TerminationFuture {
            std::future::ready(Ok(()))
        }
    }

    impl AuthorizedRemoteMcpInitializationDispatcher for ConfirmedInitializationDispatcher {
        type Output = (String, Vec<u8>);
        type InitializeError = &'static str;
        type TerminationError = &'static str;
        type InitializeFuture = std::future::Ready<
            Result<InitializedRemoteMcpSession<Self::Output>, Self::InitializeError>,
        >;
        type TerminationFuture = std::future::Ready<Result<(), Self::TerminationError>>;

        fn initialize(
            &self,
            access: rembrane_contracts::VerifiedRemoteAccess,
            _invocation: RemoteMcpInvocation,
            _protocol_headers: super::RemoteMcpProtocolHeaders,
            body: zeroize::Zeroizing<Vec<u8>>,
        ) -> Self::InitializeFuture {
            std::future::ready(Ok(InitializedRemoteMcpSession::new(
                (access.workspace_id().to_string(), body.as_slice().to_vec()),
                self.session_id.clone(),
            )))
        }

        fn terminate(
            &self,
            access: rembrane_contracts::VerifiedRemoteAccess,
            session_id: RemoteSessionId,
            _protocol_headers: super::RemoteMcpProtocolHeaders,
        ) -> Self::TerminationFuture {
            self.terminated
                .lock()
                .expect("termination recording lock should remain available")
                .push((
                    access.workspace_id().to_string(),
                    session_id.as_str().to_owned(),
                ));
            std::future::ready(if self.fail_termination {
                Err("termination failed")
            } else {
                Ok(())
            })
        }
    }

    impl AuthorizedRemoteMcpDispatcher for AllocationRecordingDispatcher {
        type Output = (usize, Vec<u8>);
        type Error = std::convert::Infallible;
        type DispatchFuture = std::future::Ready<Result<Self::Output, Self::Error>>;

        fn dispatch(
            &self,
            _access: rembrane_contracts::VerifiedRemoteAccess,
            _invocation: RemoteMcpInvocation,
            _protocol_headers: super::RemoteMcpProtocolHeaders,
            body: zeroize::Zeroizing<Vec<u8>>,
        ) -> Self::DispatchFuture {
            std::future::ready(Ok((body.as_ptr() as usize, body.as_slice().to_vec())))
        }
    }

    impl AuthorizedRemoteMcpEventStreamDispatcher for RecordingEventStreamDispatcher {
        type Output = (
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        );
        type Error = std::convert::Infallible;
        type DispatchFuture = std::future::Ready<Result<Self::Output, Self::Error>>;

        fn open(
            &self,
            access: rembrane_contracts::VerifiedRemoteAccess,
            accept: String,
            protocol_version: Option<String>,
            validated_host: Option<String>,
            validated_origin: Option<String>,
        ) -> Self::DispatchFuture {
            std::future::ready(Ok((
                access.workspace_id().to_string(),
                accept,
                protocol_version,
                validated_host,
                validated_origin,
            )))
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct RecordedDispatch {
        workspace: String,
        method: String,
        tool_name: Option<String>,
        content_type: String,
        accept: String,
        protocol_version: Option<String>,
        validated_host: Option<String>,
        validated_origin: Option<String>,
        body: Vec<u8>,
    }

    impl AuthorizedRemoteMcpDispatcher for RecordingDispatcher {
        type Output = RecordedDispatch;
        type Error = std::convert::Infallible;
        type DispatchFuture = std::future::Ready<Result<Self::Output, Self::Error>>;

        fn dispatch(
            &self,
            access: rembrane_contracts::VerifiedRemoteAccess,
            invocation: RemoteMcpInvocation,
            protocol_headers: super::RemoteMcpProtocolHeaders,
            body: zeroize::Zeroizing<Vec<u8>>,
        ) -> Self::DispatchFuture {
            std::future::ready(Ok(RecordedDispatch {
                workspace: access.workspace_id().to_string(),
                method: invocation.method().to_owned(),
                tool_name: invocation.tool_name().map(str::to_owned),
                content_type: protocol_headers.content_type().to_owned(),
                accept: protocol_headers.accept().to_owned(),
                protocol_version: protocol_headers.protocol_version().map(str::to_owned),
                validated_host: protocol_headers.validated_host().map(str::to_owned),
                validated_origin: protocol_headers.validated_origin().map(str::to_owned),
                body: body.as_slice().to_vec(),
            }))
        }
    }

    impl RemoteTokenVerifier for Verifier {
        fn verify(&self, token: &str) -> Result<RemoteTokenClaims, RemoteTokenVerificationError> {
            let (workspace, graph_read) = match token {
                "workspace-one" => ("workspace_01", true),
                "workspace-two" => ("workspace_02", true),
                "workspace-one-no-graph" => ("workspace_01", false),
                _ => return Err(RemoteTokenVerificationError),
            };
            let mut scopes = BTreeSet::from([
                RemoteAccessScope::ContextRead,
                RemoteAccessScope::MemoryWrite,
            ]);
            if graph_read {
                scopes.insert(RemoteAccessScope::GraphRead);
            }
            Ok(RemoteTokenClaims {
                issuer: "https://identity.example.test".to_owned(),
                audience: vec!["https://memory.example.test/mcp".to_owned()],
                subject_id: PrincipalId::new("principal_01"),
                client_id: ClientId::new("client_01"),
                workspace_id: WorkspaceId::new(workspace),
                scopes,
                expires_at_epoch_seconds: 2_000,
                not_before_epoch_seconds: None,
            })
        }
    }

    impl IntrospectionTransport for OAuthFixtureTransport {
        fn introspect(
            &self,
            token: &str,
        ) -> Result<IntrospectionResponse, IntrospectionTransportError> {
            let (workspace, audience, scope, expiry) = match token {
                "oauth-workspace-one" => (
                    "workspace_01",
                    "https://memory.example.test/mcp",
                    "rembrane:context:read",
                    2_000,
                ),
                "oauth-workspace-two" => (
                    "workspace_02",
                    "https://memory.example.test/mcp",
                    "rembrane:context:read",
                    2_000,
                ),
                "oauth-wrong-audience" => (
                    "workspace_01",
                    "https://other.example.test/mcp",
                    "rembrane:context:read",
                    2_000,
                ),
                "oauth-expired" => (
                    "workspace_01",
                    "https://memory.example.test/mcp",
                    "rembrane:context:read",
                    999,
                ),
                "oauth-missing-scope" => (
                    "workspace_01",
                    "https://memory.example.test/mcp",
                    "rembrane:travel:read",
                    2_000,
                ),
                _ => return Err(IntrospectionTransportError),
            };
            Ok(IntrospectionResponse {
                active: true,
                issuer: Some("https://identity.example.test".to_owned()),
                audience: vec![audience.to_owned()],
                subject: Some(format!("principal_{workspace}")),
                client_id: Some(format!("client_{workspace}")),
                workspace_id: Some(workspace.to_owned()),
                scope: Some(scope.to_owned()),
                expires_at_epoch_seconds: Some(expiry),
                not_before_epoch_seconds: None,
            })
        }
    }

    fn request<'a>(token: &'a str, session: &'a str) -> RemoteMcpHttpRequest<'a> {
        RemoteMcpHttpRequest {
            authorization: Some(token),
            host: Some("memory.example.test"),
            origin: Some("https://agent.example.test"),
            session_id: Some(session),
        }
    }

    fn initialize_body() -> zeroize::Zeroizing<Vec<u8>> {
        zeroize::Zeroizing::new(
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#
                .to_vec(),
        )
    }

    fn verified_access(
        workspace: &str,
        expiry: u64,
        scopes: BTreeSet<RemoteAccessScope>,
    ) -> rembrane_contracts::VerifiedRemoteAccess {
        RemoteTokenClaims {
            issuer: "https://identity.example.test".to_owned(),
            audience: vec!["https://memory.example.test/mcp".to_owned()],
            subject_id: PrincipalId::new("principal_01"),
            client_id: ClientId::new("client_01"),
            workspace_id: WorkspaceId::new(workspace),
            scopes,
            expires_at_epoch_seconds: expiry,
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
    fn gate_maps_authentication_capacity_and_cross_tenant_outcomes() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let origins = ["https://agent.example.test"];
        let authorization = RemoteHttpAuthorization::new(&authenticator, &origins);
        let mut gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let session = "session_0123456789abcdef";

        let unauthorized = gate
            .establish(&authorization, request("Bearer invalid", session), 1_000)
            .expect_err("invalid token must fail");
        assert_eq!(unauthorized.status, 401);
        assert!(unauthorized.www_authenticate.is_some());

        gate.establish(
            &authorization,
            request("Bearer workspace-one", session),
            1_000,
        )
        .expect("valid initialize should establish");

        let replay = gate
            .authorize(
                &authorization,
                request("Bearer workspace-two", session),
                "tools/list",
                None,
                1_100,
            )
            .expect_err("cross-tenant replay must fail");
        assert_eq!(replay.status, 403);
        assert!(replay.www_authenticate.is_none());

        let capacity = gate
            .establish(
                &authorization,
                request("Bearer workspace-one", "session_fedcba9876543210"),
                1_100,
            )
            .expect_err("second session must exceed capacity");
        assert_eq!(capacity.status, 503);
        assert_eq!(capacity.retry_after_seconds, Some(1));

        gate.terminate(
            &authorization,
            request("Bearer workspace-one", session),
            1_200,
        )
        .expect("valid delete should terminate");
    }

    #[test]
    fn sessionless_initialize_authorizes_without_reserving_client_supplied_id() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let origins = ["https://agent.example.test"];
        let authorization = RemoteHttpAuthorization::new(&authenticator, &origins);
        let mut gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let initialize = zeroize::Zeroizing::new(
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#
                .to_vec(),
        );
        let authorized = gate
            .authorize_sessionless_initialize_owned_body(
                &authorization,
                RemoteMcpHttpRequest {
                    authorization: Some("Bearer workspace-one"),
                    host: Some("memory.example.test"),
                    origin: Some("https://agent.example.test"),
                    session_id: None,
                },
                initialize,
                1_000,
            )
            .expect("sessionless initialize should authorize");
        assert_eq!(authorized.invocation().method(), "initialize");
        assert_eq!(authorized.access().workspace_id().as_str(), "workspace_01");

        let generated = RemoteSessionId::new("session_sdk_generated_0123456789")
            .expect("generated session fixture should validate");
        gate.commit_sdk_generated_session(generated.clone(), authorized.access(), 1_000)
            .expect("official SDK session should commit");
        let authorized_tool = gate
            .authorize(
                &authorization,
                request("Bearer workspace-one", generated.as_str()),
                "tools/list",
                None,
                1_001,
            )
            .expect("committed SDK session should authorize");
        assert_eq!(authorized_tool.workspace_id().as_str(), "workspace_01");

        let duplicate = gate
            .commit_sdk_generated_session(generated, authorized.access(), 1_001)
            .expect_err("duplicate generated session must fail");
        assert_eq!(duplicate.status, 409);

        let supplied_session = match gate.authorize_sessionless_initialize_owned_body(
                &authorization,
                RemoteMcpHttpRequest {
                    authorization: Some("Bearer workspace-one"),
                    host: Some("memory.example.test"),
                    origin: Some("https://agent.example.test"),
                    session_id: Some("session_attacker_supplied"),
                },
                zeroize::Zeroizing::new(
                    br#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#
                        .to_vec(),
                ),
                1_000,
            ) {
            Ok(_) => panic!("client-supplied initialize session must fail"),
            Err(error) => error,
        };
        assert_eq!(supplied_session.status, 403);
    }

    #[test]
    fn generated_session_binding_preserves_exact_tenant_and_capacity() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let origins = ["https://agent.example.test"];
        let authorization = RemoteHttpAuthorization::new(&authenticator, &origins);
        let mut gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let access = authorization
            .authorize_connection(
                Some("Bearer workspace-one"),
                Some("https://agent.example.test"),
                1_000,
            )
            .expect("fixture access should authorize");
        let session = RemoteSessionId::new("session_sdk_generated_abcdefghij")
            .expect("generated session fixture should validate");
        gate.commit_sdk_generated_session(session.clone(), &access, 1_000)
            .expect("generated session should bind");

        let cross_tenant = gate
            .authorize(
                &authorization,
                request("Bearer workspace-two", session.as_str()),
                "tools/list",
                None,
                1_001,
            )
            .expect_err("generated session must reject another tenant");
        assert_eq!(cross_tenant.status, 403);

        let other_access = authorization
            .authorize_connection(
                Some("Bearer workspace-two"),
                Some("https://agent.example.test"),
                1_001,
            )
            .expect("second tenant fixture should authorize");
        let capacity = gate
            .commit_sdk_generated_session(
                RemoteSessionId::new("session_sdk_generated_klmnopqrst")
                    .expect("generated session fixture should validate"),
                &other_access,
                1_001,
            )
            .expect_err("second generated session must respect capacity");
        assert_eq!(capacity.status, 503);
    }

    #[tokio::test]
    async fn confirmed_sdk_initialization_commits_generated_session() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let origins = ["https://agent.example.test"];
        let authorization = RemoteHttpAuthorization::new(&authenticator, &origins);
        let mut gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let session_id = RemoteSessionId::new("session_sdk_confirmed_0123456789")
            .expect("generated session fixture should validate");
        let terminated = Arc::new(Mutex::new(Vec::new()));
        let dispatcher = ConfirmedInitializationDispatcher {
            session_id: session_id.clone(),
            terminated: Arc::clone(&terminated),
            fail_termination: false,
        };
        let body = zeroize::Zeroizing::new(
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#
                .to_vec(),
        );
        let initialized = gate
            .initialize_and_commit_sdk_session(
                &authorization,
                RemoteMcpHttpRequest {
                    authorization: Some("Bearer workspace-one"),
                    host: Some("memory.example.test"),
                    origin: Some("https://agent.example.test"),
                    session_id: None,
                },
                super::RemoteMcpProtocolHeaders::transport_neutral(),
                body,
                1_000,
                &dispatcher,
            )
            .await
            .expect("confirmed SDK initialization should commit");
        assert_eq!(initialized.session_id(), &session_id);
        assert_eq!(initialized.output().0, "workspace_01");
        assert!(
            terminated
                .lock()
                .expect("termination recording lock should remain available")
                .is_empty()
        );

        let authorized = gate
            .authorize(
                &authorization,
                request("Bearer workspace-one", session_id.as_str()),
                "tools/list",
                None,
                1_001,
            )
            .expect("confirmed generated session should authorize");
        assert_eq!(authorized.workspace_id().as_str(), "workspace_01");
    }

    #[tokio::test]
    async fn failed_generated_session_commit_terminates_downstream_session() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let origins = ["https://agent.example.test"];
        let authorization = RemoteHttpAuthorization::new(&authenticator, &origins);
        let mut gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let existing_access = authorization
            .authorize_connection(
                Some("Bearer workspace-one"),
                Some("https://agent.example.test"),
                1_000,
            )
            .expect("fixture access should authorize");
        gate.commit_sdk_generated_session(
            RemoteSessionId::new("session_existing_0123456789")
                .expect("existing session fixture should validate"),
            &existing_access,
            1_000,
        )
        .expect("existing session should fill capacity");

        let generated = RemoteSessionId::new("session_orphan_candidate_0123456789")
            .expect("generated session fixture should validate");
        let terminated = Arc::new(Mutex::new(Vec::new()));
        let dispatcher = ConfirmedInitializationDispatcher {
            session_id: generated.clone(),
            terminated: Arc::clone(&terminated),
            fail_termination: true,
        };
        let error = gate
            .initialize_and_commit_sdk_session(
                &authorization,
                RemoteMcpHttpRequest {
                    authorization: Some("Bearer workspace-two"),
                    host: Some("memory.example.test"),
                    origin: Some("https://agent.example.test"),
                    session_id: None,
                },
                super::RemoteMcpProtocolHeaders::transport_neutral(),
                zeroize::Zeroizing::new(
                    br#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#
                        .to_vec(),
                ),
                1_001,
                &dispatcher,
            )
            .await
            .expect_err("capacity rejection must compensate downstream state");
        assert_eq!(
            error,
            RemoteMcpInitializationError::Commit {
                rejection: RemoteMcpHttpRejection {
                    status: 503,
                    www_authenticate: None,
                    retry_after_seconds: Some(1),
                },
                termination_error: Some("termination failed"),
            }
        );
        assert_eq!(
            *terminated
                .lock()
                .expect("termination recording lock should remain available"),
            vec![(
                "workspace_02".to_owned(),
                "session_orphan_candidate_0123456789".to_owned()
            )]
        );
    }

    #[tokio::test]
    async fn session_delete_commits_only_after_tower_confirmation() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let origins = ["https://agent.example.test"];
        let authorization = RemoteHttpAuthorization::new(&authenticator, &origins);
        let mut gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let session = "session_0123456789abcdef";
        gate.establish(
            &authorization,
            request("Bearer workspace-one", session),
            1_000,
        )
        .expect("session should establish");
        let service = tower::service_fn(
            |mut request: axum::http::Request<axum::body::Body>| async move {
                let access = request
                    .extensions_mut()
                    .remove::<rembrane_contracts::VerifiedRemoteAccess>()
                    .expect("verified access extension");
                Ok::<_, std::convert::Infallible>((
                    request.method().clone(),
                    request
                        .headers()
                        .get(MCP_SESSION_HEADER_NAME)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned),
                    request.headers().contains_key(AUTHORIZATION),
                    access.workspace_id().to_string(),
                ))
            },
        );
        let mut delete_headers = HeaderMap::new();
        delete_headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        delete_headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        delete_headers.insert(
            ORIGIN,
            HeaderValue::from_static("https://agent.example.test"),
        );
        delete_headers.insert(
            MCP_SESSION_HEADER_NAME,
            HeaderValue::from_static("session_0123456789abcdef"),
        );
        delete_headers.insert(
            MCP_PROTOCOL_VERSION_HEADER_NAME,
            HeaderValue::from_static("2025-03-26"),
        );
        let dispatched = authorize_axum_session_deletion(
            &mut gate,
            &authorization,
            &delete_headers,
            1_100,
            &AuthorizedTowerMcpDispatcher::new(service),
        )
        .await
        .expect("confirmed deletion");
        assert_eq!(dispatched.0, Method::DELETE);
        assert_eq!(dispatched.1.as_deref(), Some(session));
        assert!(!dispatched.2, "bearer must stop at authorization boundary");
        assert_eq!(dispatched.3, "workspace_01");
        assert_eq!(
            gate.authorize(
                &authorization,
                request("Bearer workspace-one", session),
                "tools/list",
                None,
                1_100,
            )
            .expect_err("confirmed deletion must remove local binding")
            .status,
            403
        );
    }

    #[test]
    fn established_session_authorization_couples_tenant_to_exact_body() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let authorization = RemoteHttpAuthorization::new(&authenticator, &[]);
        let mut gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let session = "session_0123456789abcdef";
        gate.establish(
            &authorization,
            RemoteMcpHttpRequest {
                authorization: Some("Bearer workspace-one"),
                host: Some("memory.example.test"),
                origin: None,
                session_id: Some(session),
            },
            1_000,
        )
        .expect("session should establish");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            MCP_SESSION_HEADER_NAME,
            HeaderValue::from_static("session_0123456789abcdef"),
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rembrane_resolve_context","arguments":{}}}"#;
        let authorized =
            authorize_axum_session_body(&mut gate, &authorization, &headers, body, 1_100)
                .expect("session body should authorize");
        assert_eq!(authorized.access().workspace_id().as_str(), "workspace_01");
        assert_eq!(
            authorized.invocation().tool_name(),
            Some("rembrane_resolve_context")
        );
        assert_eq!(authorized.body(), body);

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-two"),
        );
        assert_eq!(
            authorize_axum_session_body(&mut gate, &authorization, &headers, body, 1_100)
                .err()
                .expect("foreign tenant must not reuse a session")
                .status,
            403
        );
    }

    #[test]
    fn session_initialization_classifies_body_before_allocating_capacity() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let authorization = RemoteHttpAuthorization::new(&authenticator, &[]);
        let mut gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            MCP_SESSION_HEADER_NAME,
            HeaderValue::from_static("session_0123456789abcdef"),
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        let substituted = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;
        assert_eq!(
            establish_axum_session_body(&mut gate, &authorization, &headers, substituted, 1_000,)
                .err()
                .expect("non-initialize body must fail before session allocation")
                .status,
            403
        );

        let initialize = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
        let authorized =
            establish_axum_session_body(&mut gate, &authorization, &headers, initialize, 1_000)
                .expect("valid initialize should still have capacity");
        assert_eq!(authorized.invocation().method(), "initialize");
        assert_eq!(authorized.access().workspace_id().as_str(), "workspace_01");
        assert_eq!(authorized.body(), initialize);

        assert_eq!(
            establish_axum_session_body(&mut gate, &authorization, &headers, initialize, 1_000)
                .err()
                .expect("duplicate session must remain rejected")
                .status,
            409
        );
    }

    #[tokio::test]
    async fn failed_sdk_initialization_rolls_back_new_session_capacity() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let authorization = RemoteHttpAuthorization::new(&authenticator, &[]);
        let mut gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            MCP_SESSION_HEADER_NAME,
            HeaderValue::from_static("session_0123456789abcdef"),
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        let initialize = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
        let failing = tower::service_fn(
            |_request: axum::http::Request<axum::body::Body>| async move {
                Err::<(), _>("SDK initialization failed")
            },
        );
        assert!(matches!(
            establish_and_dispatch_axum_session(
                &mut gate,
                &authorization,
                &headers,
                initialize,
                1_000,
                &AuthorizedTowerMcpDispatcher::new(failing),
            )
            .await,
            Err(RemoteMcpDispatchError::Dispatch(_))
        ));

        establish_axum_session_body(&mut gate, &authorization, &headers, initialize, 1_000)
            .expect("failed SDK dispatch must release the session identifier and capacity");
    }

    #[tokio::test]
    async fn failed_session_delete_dispatch_retains_local_binding() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let authorization = RemoteHttpAuthorization::new(&authenticator, &[]);
        let mut gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let session = "session_0123456789abcdef";
        let session_request = |token| RemoteMcpHttpRequest {
            authorization: Some(token),
            host: Some("memory.example.test"),
            origin: None,
            session_id: Some(session),
        };
        gate.establish(
            &authorization,
            session_request("Bearer workspace-one"),
            1_000,
        )
        .expect("session should establish");
        let failing = tower::service_fn(
            |_request: axum::http::Request<axum::body::Body>| async move {
                Err::<(), _>("downstream unavailable")
            },
        );
        assert!(matches!(
            gate.authorize_and_dispatch_termination(
                &authorization,
                session_request("Bearer workspace-one"),
                None,
                1_100,
                &AuthorizedTowerMcpDispatcher::new(failing),
            )
            .await,
            Err(RemoteMcpDispatchError::Dispatch(_))
        ));
        gate.authorize(
            &authorization,
            session_request("Bearer workspace-one"),
            "tools/list",
            None,
            1_100,
        )
        .expect("failed dispatch must retain retryable binding");
    }

    #[test]
    fn gate_rejects_unsafe_challenge_and_session_values() {
        assert!(
            RemoteMcpHttpGate::new(
                1,
                "http://memory.example.test/metadata",
                &["memory.example.test"],
            )
            .is_err()
        );
        assert!(
            RemoteMcpHttpGate::new(
                1,
                "https://memory.example.test/metadata\" injected",
                &["memory.example.test"],
            )
            .is_err()
        );
        assert!(RemoteMcpHttpGate::new(1, "https://memory.example.test/metadata", &[]).is_err());
        assert!(
            RemoteMcpHttpGate::new(
                1,
                "https://memory.example.test/metadata",
                &["memory.example.test/path"],
            )
            .is_err()
        );

        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let authorization = RemoteHttpAuthorization::new(&authenticator, &[]);
        let mut gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/metadata",
            &["memory.example.test"],
        )
        .expect("valid gate");
        let rejection = gate
            .establish(
                &authorization,
                RemoteMcpHttpRequest {
                    authorization: Some("Bearer workspace-one"),
                    host: Some("memory.example.test"),
                    origin: None,
                    session_id: Some("invalid session"),
                },
                1_000,
            )
            .expect_err("unsafe session header must fail");
        assert_eq!(rejection.status, 403);

        let hostile_host = gate
            .establish(
                &authorization,
                RemoteMcpHttpRequest {
                    authorization: Some("Bearer workspace-one"),
                    host: Some("attacker.example.test"),
                    origin: None,
                    session_id: Some("session_0123456789abcdef"),
                },
                1_000,
            )
            .expect_err("untrusted host must fail before session creation");
        assert_eq!(hostile_host.status, 403);
    }

    #[test]
    fn gate_derives_host_and_challenge_from_one_validated_resource() {
        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("OAUTH_SECRET").expect("reference should be valid"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("remote profile should be valid");
        assert!(RemoteMcpHttpGate::from_config(10, &config).is_ok());
    }

    #[test]
    fn stateless_gate_reauthenticates_without_transport_sessions() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let origins = ["https://agent.example.test"];
        let authorization = RemoteHttpAuthorization::new(&authenticator, &origins);
        let gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let request = |token| RemoteMcpHttpRequest {
            authorization: Some(token),
            host: Some("memory.example.test"),
            origin: Some("https://agent.example.test"),
            session_id: None,
        };

        let access = gate
            .authorize_stateless(
                &authorization,
                request("Bearer workspace-one"),
                "tools/call",
                Some("rembrane_resolve_context"),
                1_000,
            )
            .expect("scoped stateless request should authenticate");
        assert_eq!(access.workspace_id().as_str(), "workspace_01");

        let unauthorized = gate
            .authorize_stateless(
                &authorization,
                request("Bearer invalid"),
                "tools/list",
                None,
                1_000,
            )
            .expect_err("invalid token must be challenged");
        assert_eq!(unauthorized.status, 401);
        assert!(unauthorized.www_authenticate.is_some());

        let insufficient_scope = gate
            .authorize_stateless(
                &authorization,
                request("Bearer workspace-one"),
                "tools/call",
                Some("rembrane_create_trip"),
                1_000,
            )
            .expect_err("missing tool scope must be forbidden");
        assert_eq!(insufficient_scope.status, 403);

        let stateful_header = gate
            .authorize_stateless(
                &authorization,
                RemoteMcpHttpRequest {
                    session_id: Some("session_0123456789abcdef"),
                    ..request("Bearer workspace-one")
                },
                "tools/list",
                None,
                1_000,
            )
            .expect_err("stateless boundary must reject session ambiguity");
        assert_eq!(stateful_header.status, 403);

        let cross_request_cancellation = gate
            .authorize_stateless(
                &authorization,
                request("Bearer workspace-one"),
                "notifications/cancelled",
                None,
                1_000,
            )
            .expect_err(
                "stateless cancellation must remain disabled until request ownership is tenant-bound",
            );
        assert_eq!(cross_request_cancellation.status, 403);
    }

    #[test]
    fn json_rpc_classifier_fails_closed_before_sdk_dispatch() {
        let invocation = classify_remote_mcp_request(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rembrane_resolve_context","arguments":{}}}"#,
        )
        .expect("known tool request should classify");
        assert_eq!(invocation.method(), "tools/call");
        assert_eq!(invocation.tool_name(), Some("rembrane_resolve_context"));

        for body in [
            br"[]".as_slice(),
            br#"{"jsonrpc":"1.0","id":1,"method":"tools/list"}"#,
            br#"{"jsonrpc":"2.0","id":null,"method":"tools/list"}"#,
            br#"{"jsonrpc":"2.0","method":"tools/list"}"#,
            br#"{"jsonrpc":"2.0","id":true,"method":"tools/list"}"#,
            br#"{"jsonrpc":"2.0","id":1.5,"method":"tools/list"}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"notifications/initialized"}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"future_tool"}}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"resources/list"}"#,
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","extra":true}"#,
        ] {
            assert!(
                classify_remote_mcp_request(body).is_err(),
                "unsupported body must fail closed"
            );
        }

        for body in [
            br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.as_slice(),
            br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#,
            br#"{"jsonrpc":"2.0","id":"request-01","method":"tools/list"}"#,
            br#"{"jsonrpc":"2.0","id":-1,"method":"ping"}"#,
        ] {
            classify_remote_mcp_request(body).expect("valid SDK request shape should classify");
        }
    }

    #[test]
    fn json_rpc_classifier_extracts_only_authorization_metadata() {
        let body = br#"{"jsonrpc":"2.0","id":"request-1","method":"tools/call","params":{"name":"rembrane_resolve_context","arguments":{"private_notes":["alpha",{"nested":"secret"}],"limit":20}}}"#;
        let invocation =
            classify_remote_mcp_request(body).expect("valid tool call should classify");

        assert_eq!(invocation.method(), "tools/call");
        assert_eq!(invocation.tool_name(), Some("rembrane_resolve_context"));
    }

    #[tokio::test]
    async fn stateless_body_authorization_cannot_drift_from_dispatched_bytes() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let authorization = RemoteHttpAuthorization::new(&authenticator, &[]);
        let gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let request = RemoteMcpHttpRequest {
            authorization: Some("Bearer workspace-one"),
            host: Some("memory.example.test"),
            origin: None,
            session_id: None,
        };
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rembrane_resolve_context","arguments":{}}}"#;
        let authorized = gate
            .authorize_stateless_body(&authorization, request, body, 1_000)
            .expect("body and its exact scope should authorize together");
        assert_eq!(authorized.access().workspace_id().as_str(), "workspace_01");
        assert_eq!(
            authorized.invocation().tool_name(),
            Some("rembrane_resolve_context")
        );
        assert_eq!(authorized.body(), body);
        let dispatched = authorized
            .dispatch_with(&RecordingDispatcher)
            .await
            .expect("authorized dispatch cannot fail");
        assert_eq!(dispatched.workspace, "workspace_01");
        assert_eq!(dispatched.method, "tools/call");
        assert_eq!(
            dispatched.tool_name.as_deref(),
            Some("rembrane_resolve_context")
        );
        assert_eq!(dispatched.content_type, "application/json");
        assert_eq!(dispatched.accept, "application/json, text/event-stream");
        assert_eq!(dispatched.protocol_version, None);
        assert_eq!(dispatched.body, body);

        let travel_body = br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"rembrane_create_trip","arguments":{}}}"#;
        assert_eq!(
            gate.authorize_stateless_body(&authorization, request, travel_body, 1_000)
                .err()
                .expect("body requiring an absent scope must fail")
                .status,
            403
        );

        let cancellation =
            br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#;
        assert_eq!(
            gate.authorize_stateless_body(&authorization, request, cancellation, 1_000)
                .err()
                .expect("stateless cancellation must fail closed")
                .status,
            403
        );
    }

    #[tokio::test]
    async fn tower_dispatcher_preserves_verified_tenant_and_validated_protocol_input() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let authorization = RemoteHttpAuthorization::new(&authenticator, &[]);
        let gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            MCP_PROTOCOL_VERSION_HEADER_NAME,
            HeaderValue::from_static("2025-03-26"),
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rembrane_resolve_context","arguments":{}}}"#;
        let authorized =
            authorize_axum_stateless_body(&gate, &authorization, &headers, body, 1_000)
                .expect("authorized request");
        let service = tower::service_fn(
            |mut request: axum::http::Request<axum::body::Body>| async move {
                let access = request
                    .extensions_mut()
                    .remove::<rembrane_contracts::VerifiedRemoteAccess>()
                    .expect("verified access extension");
                let invocation = request
                    .extensions_mut()
                    .remove::<RemoteMcpInvocation>()
                    .expect("classified invocation extension");
                let protocol = request
                    .headers()
                    .get(MCP_PROTOCOL_VERSION_HEADER_NAME)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let forwarded_authorization = request.headers().contains_key(AUTHORIZATION);
                let bytes = axum::body::to_bytes(request.into_body(), 1_048_576)
                    .await
                    .expect("bounded body");
                Ok::<_, std::convert::Infallible>((
                    access.workspace_id().to_string(),
                    invocation.tool_name().map(str::to_owned),
                    protocol,
                    forwarded_authorization,
                    bytes.to_vec(),
                ))
            },
        );
        let dispatched = authorized
            .dispatch_with(&AuthorizedTowerMcpDispatcher::new(service))
            .await
            .expect("Tower dispatch");

        assert_eq!(dispatched.0, "workspace_01");
        assert_eq!(dispatched.1.as_deref(), Some("rembrane_resolve_context"));
        assert_eq!(dispatched.2.as_deref(), Some("2025-03-26"));
        assert!(
            !dispatched.3,
            "bearer credential must stop at OAuth boundary"
        );
        assert_eq!(dispatched.4, body);
    }

    #[tokio::test]
    async fn tower_initialization_validates_response_and_compensates_with_delete() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let origins = ["https://agent.example.test"];
        let authorization = RemoteHttpAuthorization::new(&authenticator, &origins);
        let mut gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let existing_access = authorization
            .authorize_connection(Some("Bearer workspace-two"), None, 1_000)
            .expect("fixture access should authorize");
        gate.commit_sdk_generated_session(
            RemoteSessionId::new("session_existing_tower_0123456789")
                .expect("existing session fixture should validate"),
            &existing_access,
            1_000,
        )
        .expect("existing session should fill capacity");

        let calls = Arc::new(Mutex::new(Vec::<TowerInitializationCall>::new()));
        let calls_from_service = Arc::clone(&calls);
        let service = tower::service_fn(move |mut request: Request<Body>| {
            let calls = Arc::clone(&calls_from_service);
            async move {
                let access = request
                    .extensions_mut()
                    .remove::<rembrane_contracts::VerifiedRemoteAccess>()
                    .expect("verified access extension");
                let session = request
                    .headers()
                    .get(MCP_SESSION_HEADER_NAME)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                calls.lock().expect("call log").push((
                    request.method().clone(),
                    access.workspace_id().to_string(),
                    session,
                    request.headers().get(HOST).cloned(),
                    request.headers().get(ORIGIN).cloned(),
                    request.headers().contains_key(AUTHORIZATION),
                ));
                let response = if request.method() == Method::POST {
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(
                            MCP_SESSION_HEADER_NAME,
                            "session_generated_tower_0123456789",
                        )
                        .body(Body::from("initialized"))
                        .expect("initialize response should build")
                } else {
                    Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(Body::empty())
                        .expect("termination response should build")
                };
                Ok::<_, std::convert::Infallible>(response)
            }
        });
        let dispatcher = AuthorizedTowerMcpDispatcher::new(service);
        let error = gate
            .initialize_and_commit_sdk_session(
                &authorization,
                RemoteMcpHttpRequest {
                    authorization: Some("Bearer workspace-one"),
                    host: Some("memory.example.test"),
                    origin: Some("https://agent.example.test"),
                    session_id: None,
                },
                super::RemoteMcpProtocolHeaders::transport_neutral(),
                zeroize::Zeroizing::new(
                    br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#
                        .to_vec(),
                ),
                1_001,
                &dispatcher,
            )
            .await
            .expect_err("full local capacity should trigger SDK compensation");
        assert!(
            matches!(
                &error,
                RemoteMcpInitializationError::Commit {
                    rejection: RemoteMcpHttpRejection { status: 503, .. },
                    termination_error: None,
                }
            ),
            "unexpected initialization error: {error:?}"
        );
        assert_compensated_tower_initialization(&calls.lock().expect("call log"));
    }

    #[tokio::test]
    async fn tower_initialization_rejects_missing_or_duplicate_session_response() {
        for duplicate in [false, true] {
            let service = tower::service_fn(move |_request: Request<Body>| async move {
                let mut response = Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::empty())
                    .expect("response should build");
                if duplicate {
                    response.headers_mut().append(
                        MCP_SESSION_HEADER_NAME,
                        HeaderValue::from_static("session_one_0123456789"),
                    );
                    response.headers_mut().append(
                        MCP_SESSION_HEADER_NAME,
                        HeaderValue::from_static("session_two_0123456789"),
                    );
                }
                Ok::<_, std::convert::Infallible>(response)
            });
            let dispatcher = AuthorizedTowerMcpDispatcher::new(service);
            let access = verified_access(
                "workspace_01",
                2_000,
                [RemoteAccessScope::ContextRead].into_iter().collect(),
            );
            let result = AuthorizedRemoteMcpInitializationDispatcher::initialize(
                &dispatcher,
                access,
                RemoteMcpInvocation {
                    method: "initialize".to_owned(),
                    tool_name: None,
                },
                super::RemoteMcpProtocolHeaders::transport_neutral(),
                zeroize::Zeroizing::new(Vec::new()),
            )
            .await;
            assert!(matches!(
                result,
                Err(super::TowerMcpDispatchError::InvalidSdkResponse)
            ));
        }
    }

    #[tokio::test]
    async fn tenant_aware_tower_factory_selects_service_after_exact_authorization() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let authorization = RemoteHttpAuthorization::new(&authenticator, &[]);
        let gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let selected = Arc::new(Mutex::new(Vec::new()));
        let selected_by_factory = Arc::clone(&selected);
        let dispatcher = TenantAwareTowerMcpDispatcher::new(
            move |access: &rembrane_contracts::VerifiedRemoteAccess| {
                let selected_workspace = access.workspace_id().to_string();
                selected_by_factory
                    .lock()
                    .expect("selection log")
                    .push(selected_workspace.clone());
                Ok::<_, std::convert::Infallible>(tower::service_fn(
                    move |mut request: axum::http::Request<Body>| {
                        let selected_workspace = selected_workspace.clone();
                        async move {
                            let dispatched_workspace = request
                                .extensions_mut()
                                .remove::<rembrane_contracts::VerifiedRemoteAccess>()
                                .expect("verified access extension")
                                .workspace_id()
                                .to_string();
                            Ok::<_, std::convert::Infallible>((
                                selected_workspace,
                                dispatched_workspace,
                                request.headers().contains_key(AUTHORIZATION),
                            ))
                        }
                    },
                ))
            },
        );
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rembrane_resolve_context","arguments":{}}}"#;

        for (token, workspace) in [
            ("Bearer workspace-one", "workspace_01"),
            ("Bearer workspace-two", "workspace_02"),
        ] {
            let request = RemoteMcpHttpRequest {
                authorization: Some(token),
                host: Some("memory.example.test"),
                origin: None,
                session_id: None,
            };
            let authorized = gate
                .authorize_stateless_body(&authorization, request, body, 1_000)
                .expect("tenant request should authorize");
            let outcome = authorized
                .dispatch_with(&dispatcher)
                .await
                .expect("tenant service dispatch");
            assert_eq!(outcome.0, workspace);
            assert_eq!(outcome.1, workspace);
            assert!(!outcome.2, "bearer must not cross the OAuth boundary");
        }

        assert_eq!(
            *selected.lock().expect("selection log"),
            ["workspace_01", "workspace_02"]
        );
    }

    #[test]
    fn tenant_service_cache_reuses_exact_identity_across_token_refresh() {
        let builds = Arc::new(Mutex::new(0_u64));
        let builds_from_factory = Arc::clone(&builds);
        let cache = BoundedTenantTowerMcpServiceCache::new(
            2,
            move |access: &rembrane_contracts::VerifiedRemoteAccess| {
                let mut builds = builds_from_factory.lock().expect("build count");
                *builds += 1;
                Ok::<_, std::convert::Infallible>(format!("{}-{builds}", access.workspace_id()))
            },
        )
        .expect("cache capacity");
        let scopes = BTreeSet::from([
            RemoteAccessScope::ContextRead,
            RemoteAccessScope::MemoryWrite,
        ]);
        let first = verified_access("workspace_01", 2_000, scopes.clone());
        let refreshed = verified_access("workspace_01", 3_000, scopes);

        let first_service = cache.create(&first).expect("first service");
        let refreshed_service = cache.create(&refreshed).expect("cached service");

        assert_eq!(first_service, refreshed_service);
        assert_eq!(*builds.lock().expect("build count"), 1);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.prune_expired(2_500).expect("prune cache"), 0);
        assert_eq!(cache.prune_expired(3_000).expect("prune cache"), 1);
        assert!(cache.is_empty());
    }

    #[test]
    fn tenant_service_cache_separates_scope_and_workspace_and_fails_at_capacity() {
        let cache = BoundedTenantTowerMcpServiceCache::new(
            2,
            |access: &rembrane_contracts::VerifiedRemoteAccess| {
                Ok::<_, std::convert::Infallible>(access.workspace_id().to_string())
            },
        )
        .expect("cache capacity");
        let context = BTreeSet::from([RemoteAccessScope::ContextRead]);
        let context_and_write = BTreeSet::from([
            RemoteAccessScope::ContextRead,
            RemoteAccessScope::MemoryWrite,
        ]);
        let workspace_one = verified_access("workspace_01", 2_000, context.clone());
        let workspace_one_writable = verified_access("workspace_01", 2_000, context_and_write);
        let workspace_two = verified_access("workspace_02", 2_000, context);

        cache.create(&workspace_one).expect("workspace one");
        cache
            .create(&workspace_one_writable)
            .expect("scope-separated service");
        assert!(matches!(
            cache.create(&workspace_two),
            Err(TenantServiceCacheError::CapacityExceeded)
        ));
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.prune_expired(2_000).expect("prune cache"), 2);
        assert_eq!(
            cache.create(&workspace_two).expect("reclaimed capacity"),
            "workspace_02"
        );
    }

    #[test]
    fn tenant_service_cache_rejects_unbounded_configuration() {
        let factory = |_access: &rembrane_contracts::VerifiedRemoteAccess| {
            Ok::<_, std::convert::Infallible>(())
        };
        assert!(BoundedTenantTowerMcpServiceCache::<_, ()>::new(0, factory).is_err());
        assert!(
            BoundedTenantTowerMcpServiceCache::<_, ()>::new(
                super::MAX_REMOTE_MCP_TENANT_SERVICES + 1,
                factory
            )
            .is_err()
        );
    }

    #[test]
    fn tenant_service_cache_constructs_once_under_concurrent_first_access() {
        let builds = Arc::new(Mutex::new(0_u64));
        let builds_from_factory = Arc::clone(&builds);
        let cache = BoundedTenantTowerMcpServiceCache::new(
            1,
            move |_access: &rembrane_contracts::VerifiedRemoteAccess| {
                let mut builds = builds_from_factory.lock().expect("build count");
                *builds += 1;
                Ok::<_, std::convert::Infallible>(*builds)
            },
        )
        .expect("cache capacity");
        let access = verified_access(
            "workspace_01",
            2_000,
            BTreeSet::from([RemoteAccessScope::ContextRead]),
        );
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let cache = cache.clone();
            let access = access.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                cache.create(&access).expect("cached service")
            }));
        }
        barrier.wait();
        let services = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .collect::<Vec<_>>();

        assert_eq!(services, [1, 1]);
        assert_eq!(*builds.lock().expect("build count"), 1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn failed_tenant_service_construction_does_not_consume_capacity() {
        let attempts = Arc::new(Mutex::new(0_u64));
        let attempts_from_factory = Arc::clone(&attempts);
        let cache = BoundedTenantTowerMcpServiceCache::new(
            1,
            move |access: &rembrane_contracts::VerifiedRemoteAccess| {
                let mut attempts = attempts_from_factory.lock().expect("attempt count");
                *attempts += 1;
                if *attempts == 1 {
                    Err("temporary construction failure")
                } else {
                    Ok(access.workspace_id().to_string())
                }
            },
        )
        .expect("cache capacity");
        let access = verified_access(
            "workspace_01",
            2_000,
            BTreeSet::from([RemoteAccessScope::ContextRead]),
        );

        assert!(matches!(
            cache.create(&access),
            Err(TenantServiceCacheError::Factory(
                "temporary construction failure"
            ))
        ));
        assert!(cache.is_empty());
        assert_eq!(
            cache.create(&access).expect("retry should construct"),
            "workspace_01"
        );
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test]
    async fn tenant_aware_tower_factory_selects_get_and_delete_services_per_tenant() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let selected = Arc::new(Mutex::new(Vec::new()));
        let selected_by_factory = Arc::clone(&selected);
        let dispatcher = TenantAwareTowerMcpDispatcher::new(
            move |access: &rembrane_contracts::VerifiedRemoteAccess| {
                let selected_workspace = access.workspace_id().to_string();
                selected_by_factory
                    .lock()
                    .expect("selection log")
                    .push(selected_workspace.clone());
                Ok::<_, std::convert::Infallible>(tower::service_fn(
                    move |mut request: axum::http::Request<Body>| {
                        let selected_workspace = selected_workspace.clone();
                        async move {
                            let dispatched_workspace = request
                                .extensions_mut()
                                .remove::<rembrane_contracts::VerifiedRemoteAccess>()
                                .expect("verified access extension")
                                .workspace_id()
                                .to_string();
                            let method = request.method().clone();
                            let session = request
                                .headers()
                                .get(MCP_SESSION_HEADER_NAME)
                                .and_then(|value| value.to_str().ok())
                                .map(str::to_owned);
                            Ok::<_, std::convert::Infallible>((
                                selected_workspace,
                                dispatched_workspace,
                                method,
                                session,
                            ))
                        }
                    },
                ))
            },
        );
        let workspace_one = authenticator
            .authenticate("workspace-one", 1_000, RemoteAccessScope::ContextRead)
            .expect("workspace one access");
        let workspace_two = authenticator
            .authenticate("workspace-two", 1_000, RemoteAccessScope::ContextRead)
            .expect("workspace two access");

        let event_stream = dispatcher
            .open(
                workspace_one,
                "text/event-stream".to_owned(),
                Some("2025-03-26".to_owned()),
                Some("memory.example.test".to_owned()),
                None,
            )
            .await
            .expect("tenant event stream dispatch");
        assert_eq!(event_stream.0, "workspace_01");
        assert_eq!(event_stream.1, "workspace_01");
        assert_eq!(event_stream.2, Method::GET);
        assert_eq!(event_stream.3, None);

        let deletion = dispatcher
            .terminate(
                workspace_two,
                rembrane_contracts::RemoteSessionId::new("session_0123456789abcdef")
                    .expect("session id"),
                Some("2025-03-26".to_owned()),
                "memory.example.test".to_owned(),
                None,
            )
            .await
            .expect("tenant deletion dispatch");
        assert_eq!(deletion.0, "workspace_02");
        assert_eq!(deletion.1, "workspace_02");
        assert_eq!(deletion.2, Method::DELETE);
        assert_eq!(deletion.3.as_deref(), Some("session_0123456789abcdef"));

        assert_eq!(
            *selected.lock().expect("selection log"),
            ["workspace_01", "workspace_02"]
        );
    }

    #[tokio::test]
    async fn tenant_aware_initialization_binds_distinct_sdk_sessions() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let authorization = RemoteHttpAuthorization::new(&authenticator, &[]);
        let mut gate = RemoteMcpHttpGate::new(
            2,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let selected = Arc::new(Mutex::new(Vec::new()));
        let selected_by_factory = Arc::clone(&selected);
        let factory = BoundedTenantTowerMcpServiceCache::new(
            2,
            move |access: &rembrane_contracts::VerifiedRemoteAccess| {
                let workspace = access.workspace_id().to_string();
                selected_by_factory
                    .lock()
                    .expect("selection log")
                    .push(workspace.clone());
                Ok::<_, std::convert::Infallible>(tower::service_fn(
                    move |mut request: Request<Body>| {
                        let workspace = workspace.clone();
                        async move {
                            let dispatched_workspace = request
                                .extensions_mut()
                                .remove::<rembrane_contracts::VerifiedRemoteAccess>()
                                .expect("verified access extension")
                                .workspace_id()
                                .to_string();
                            assert_eq!(workspace, dispatched_workspace);
                            assert!(!request.headers().contains_key(AUTHORIZATION));
                            let session = format!("session_{workspace}_0123456789");
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header(MCP_SESSION_HEADER_NAME, session)
                                    .body(Body::empty())
                                    .expect("SDK response should build"),
                            )
                        }
                    },
                ))
            },
        )
        .expect("tenant cache should be valid");
        let dispatcher = TenantAwareTowerMcpDispatcher::new(factory);
        let mut sessions = Vec::new();
        for (token, expected_workspace) in [
            ("Bearer workspace-one", "workspace_01"),
            ("Bearer workspace-two", "workspace_02"),
        ] {
            let initialized = gate
                .initialize_and_commit_sdk_session(
                    &authorization,
                    RemoteMcpHttpRequest {
                        authorization: Some(token),
                        host: Some("memory.example.test"),
                        origin: None,
                        session_id: None,
                    },
                    super::RemoteMcpProtocolHeaders::transport_neutral(),
                    initialize_body(),
                    1_000,
                    &dispatcher,
                )
                .await
                .expect("tenant SDK initialization should commit");
            assert_eq!(
                initialized.session_id().as_str(),
                format!("session_{expected_workspace}_0123456789")
            );
            sessions.push((token, initialized.session_id().clone(), expected_workspace));
        }

        for (token, session, expected_workspace) in sessions {
            let access = gate
                .authorize(
                    &authorization,
                    RemoteMcpHttpRequest {
                        authorization: Some(token),
                        host: Some("memory.example.test"),
                        origin: None,
                        session_id: Some(session.as_str()),
                    },
                    "tools/list",
                    None,
                    1_001,
                )
                .expect("generated tenant session should authorize");
            assert_eq!(access.workspace_id().as_str(), expected_workspace);
        }
        assert_eq!(
            *selected.lock().expect("selection log"),
            ["workspace_01", "workspace_02"]
        );
    }

    #[tokio::test]
    async fn tenant_aware_commit_rejection_uses_same_cached_service_for_compensation() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let authorization = RemoteHttpAuthorization::new(&authenticator, &[]);
        let mut gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let existing_access = authorization
            .authorize_connection(Some("Bearer workspace-two"), None, 1_000)
            .expect("fixture access should authorize");
        gate.commit_sdk_generated_session(
            RemoteSessionId::new("session_existing_tenant_0123456789")
                .expect("existing session fixture should validate"),
            &existing_access,
            1_000,
        )
        .expect("existing session should fill local capacity");

        let constructions = Arc::new(Mutex::new(Vec::new()));
        let constructions_from_factory = Arc::clone(&constructions);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let calls_from_factory = Arc::clone(&calls);
        let factory = BoundedTenantTowerMcpServiceCache::new(
            1,
            move |access: &rembrane_contracts::VerifiedRemoteAccess| {
                let workspace = access.workspace_id().to_string();
                constructions_from_factory
                    .lock()
                    .expect("construction log")
                    .push(workspace.clone());
                let calls = Arc::clone(&calls_from_factory);
                Ok::<_, std::convert::Infallible>(tower::service_fn(
                    move |mut request: Request<Body>| {
                        let calls = Arc::clone(&calls);
                        let workspace = workspace.clone();
                        async move {
                            let dispatched_workspace = request
                                .extensions_mut()
                                .remove::<rembrane_contracts::VerifiedRemoteAccess>()
                                .expect("verified access extension")
                                .workspace_id()
                                .to_string();
                            let method = request.method().clone();
                            calls.lock().expect("call log").push((
                                workspace.clone(),
                                dispatched_workspace,
                                method.clone(),
                            ));
                            let mut response = Response::builder().status(StatusCode::OK);
                            if method == Method::POST {
                                response = response.header(
                                    MCP_SESSION_HEADER_NAME,
                                    "session_tenant_compensate_0123456789",
                                );
                            }
                            Ok::<_, std::convert::Infallible>(
                                response.body(Body::empty()).expect("response should build"),
                            )
                        }
                    },
                ))
            },
        )
        .expect("tenant cache should be valid");
        let dispatcher = TenantAwareTowerMcpDispatcher::new(factory);
        let error = gate
            .initialize_and_commit_sdk_session(
                &authorization,
                RemoteMcpHttpRequest {
                    authorization: Some("Bearer workspace-one"),
                    host: Some("memory.example.test"),
                    origin: None,
                    session_id: None,
                },
                super::RemoteMcpProtocolHeaders::transport_neutral(),
                initialize_body(),
                1_001,
                &dispatcher,
            )
            .await
            .expect_err("full local capacity must compensate the SDK session");
        assert!(matches!(
            error,
            RemoteMcpInitializationError::Commit {
                rejection: RemoteMcpHttpRejection { status: 503, .. },
                termination_error: None,
            }
        ));
        assert_tenant_compensation(&constructions, &calls);
    }

    #[tokio::test]
    async fn tenant_aware_tower_factory_failure_stops_before_protocol_dispatch() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let authorization = RemoteHttpAuthorization::new(&authenticator, &[]);
        let gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let protocol_calls = Arc::new(Mutex::new(0_u64));
        let protocol_calls_from_service = Arc::clone(&protocol_calls);
        let fallback_service = tower::service_fn(move |_request: Request<Body>| {
            let protocol_calls = Arc::clone(&protocol_calls_from_service);
            async move {
                *protocol_calls.lock().expect("protocol call count") += 1;
                Ok::<_, std::convert::Infallible>(())
            }
        });
        let dispatcher = TenantAwareTowerMcpDispatcher::new(
            move |_access: &rembrane_contracts::VerifiedRemoteAccess| -> Result<_, &'static str> {
                if std::hint::black_box(true) {
                    Err("tenant service unavailable")
                } else {
                    Ok(fallback_service.clone())
                }
            },
        );
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rembrane_resolve_context","arguments":{}}}"#;
        let authorized = gate
            .authorize_stateless_body(
                &authorization,
                RemoteMcpHttpRequest {
                    authorization: Some("Bearer workspace-one"),
                    host: Some("memory.example.test"),
                    origin: None,
                    session_id: None,
                },
                body,
                1_000,
            )
            .expect("tenant request should authorize");

        let error = authorized
            .dispatch_with(&dispatcher)
            .await
            .expect_err("factory failure must stop dispatch");
        assert!(matches!(
            error,
            TenantAwareTowerMcpDispatchError::Factory("tenant service unavailable")
        ));
        assert_eq!(*protocol_calls.lock().expect("protocol call count"), 0);
    }

    #[tokio::test]
    async fn owned_axum_authorization_preserves_one_zeroizing_body_allocation() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let authorization = RemoteHttpAuthorization::new(&authenticator, &[]);
        let gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        let body =
            zeroize::Zeroizing::new(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_vec());
        let original_allocation = body.as_ptr() as usize;
        let expected = body.as_slice().to_vec();

        let authorized =
            authorize_axum_stateless_owned_body(&gate, &authorization, &headers, body, 1_000)
                .expect("owned request should authorize");
        let (dispatched_allocation, dispatched_body) = authorized
            .dispatch_with(&AllocationRecordingDispatcher)
            .await
            .expect("owned request should dispatch");

        assert_eq!(dispatched_allocation, original_allocation);
        assert_eq!(dispatched_body, expected);
    }

    #[test]
    fn axum_boundary_rejects_duplicate_or_oversized_security_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.append(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        headers.append(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-two"),
        );
        assert!(
            request_from_axum_headers(&headers).is_err(),
            "multiple credentials must never be collapsed by the HTTP adapter"
        );

        headers.remove(AUTHORIZATION);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        headers.append(HOST, HeaderValue::from_static("attacker.example.test"));
        assert!(
            request_from_axum_headers(&headers).is_err(),
            "multiple host authorities must fail closed"
        );

        headers = HeaderMap::new();
        for (name, first, second) in [
            (&CONTENT_TYPE, "application/json", "text/plain"),
            (&ACCEPT, "application/json", "text/event-stream"),
            (
                &MCP_PROTOCOL_VERSION_HEADER_NAME,
                "2025-03-26",
                "2026-07-28",
            ),
        ] {
            headers.insert(name, HeaderValue::from_str(first).expect("valid header"));
            headers.append(name, HeaderValue::from_str(second).expect("valid header"));
            assert!(
                request_from_axum_headers(&headers).is_err(),
                "ambiguous protocol header must fail closed"
            );
            headers.clear();
        }

        for name in [
            &AUTHORIZATION,
            &HOST,
            &ORIGIN,
            &CONTENT_TYPE,
            &ACCEPT,
            &MCP_SESSION_HEADER_NAME,
            &MCP_PROTOCOL_VERSION_HEADER_NAME,
        ] {
            headers.insert(
                name,
                HeaderValue::from_bytes(&vec![b'x'; MAX_REMOTE_MCP_HEADER_BYTES + 1])
                    .expect("large visible ASCII header"),
            );
            assert!(
                request_from_axum_headers(&headers).is_err(),
                "oversized security header must fail at the outer boundary"
            );
            headers.clear();
        }

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        assert_eq!(
            request_from_axum_headers(&headers)
                .expect_err("non-JSON requests must fail")
                .status,
            415
        );

        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        assert_eq!(
            request_from_axum_headers(&headers)
                .expect_err("MCP clients must accept event streams")
                .status,
            406
        );

        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            MCP_PROTOCOL_VERSION_HEADER_NAME,
            HeaderValue::from_static("future-version"),
        );
        assert_eq!(
            request_from_axum_headers(&headers)
                .expect_err("arbitrary protocol version text must fail")
                .status,
            400
        );
    }

    #[test]
    fn axum_boundary_authorizes_the_exact_body_and_maps_rejections() {
        let verifier = Verifier;
        let authenticator = RemoteAccessAuthenticator::new(
            &verifier,
            "https://identity.example.test",
            "https://memory.example.test/mcp",
        );
        let origins = ["https://agent.example.test"];
        let authorization = RemoteHttpAuthorization::new(&authenticator, &origins);
        let gate = RemoteMcpHttpGate::new(
            1,
            "https://memory.example.test/.well-known/oauth-protected-resource/mcp",
            &["memory.example.test"],
        )
        .expect("gate should be valid");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            MCP_PROTOCOL_VERSION_HEADER_NAME,
            HeaderValue::from_static("2025-03-26"),
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        headers.insert(
            ORIGIN,
            HeaderValue::from_static("https://agent.example.test"),
        );
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rembrane_resolve_context","arguments":{}}}"#;

        let authorized =
            authorize_axum_stateless_body(&gate, &authorization, &headers, body, 1_000)
                .expect("Axum request should authorize before dispatch");
        assert_eq!(authorized.access().workspace_id().as_str(), "workspace_01");
        assert_eq!(
            authorized.invocation().tool_name(),
            Some("rembrane_resolve_context")
        );
        assert_eq!(authorized.body(), body);
        let (access, invocation, protocol_headers, dispatched_body) =
            authorized.into_dispatch_parts();
        assert_eq!(access.workspace_id().as_str(), "workspace_01");
        assert_eq!(invocation.method(), "tools/call");
        assert_eq!(invocation.tool_name(), Some("rembrane_resolve_context"));
        assert_eq!(protocol_headers.content_type(), "application/json");
        assert_eq!(
            protocol_headers.accept(),
            "application/json, text/event-stream"
        );
        assert_eq!(protocol_headers.protocol_version(), Some("2025-03-26"));
        assert_eq!(
            protocol_headers.validated_host(),
            Some("memory.example.test")
        );
        assert_eq!(
            protocol_headers.validated_origin(),
            Some("https://agent.example.test")
        );
        assert_eq!(dispatched_body.as_slice(), body);

        headers.insert(
            MCP_SESSION_HEADER_NAME,
            HeaderValue::from_static("session_0123456789abcdef"),
        );
        let rejection = authorize_axum_stateless_body(&gate, &authorization, &headers, body, 1_000)
            .err()
            .expect("stateless endpoint must reject session ambiguity");
        let response = rejection.into_response();
        assert_eq!(response.status(), 403);
        assert!(!response.headers().contains_key(WWW_AUTHENTICATE));

        headers.remove(MCP_SESSION_HEADER_NAME);
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer invalid"));
        let rejection = authorize_axum_stateless_body(&gate, &authorization, &headers, body, 1_000)
            .err()
            .expect("invalid credential must produce a bearer challenge");
        let response = rejection.into_response();
        assert_eq!(response.status(), 401);
        assert!(response.headers().contains_key(WWW_AUTHENTICATE));
        assert!(!response.headers().contains_key(RETRY_AFTER));
    }

    async fn authorized_workspace(
        State(authorization): State<Arc<RemoteMcpAxumAuthorization<Verifier>>>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<String, RemoteMcpHttpRejection> {
        match authorization
            .authorize_and_dispatch(&headers, &body, 1_000, &RecordingDispatcher)
            .await
        {
            Ok(dispatched) => Ok(dispatched.workspace),
            Err(RemoteMcpDispatchError::Authorization(rejection)) => Err(rejection),
            Err(RemoteMcpDispatchError::Dispatch(infallible)) => match infallible {},
        }
    }

    async fn authorized_event_workspace(
        State(authorization): State<Arc<RemoteMcpAxumAuthorization<Verifier>>>,
        headers: HeaderMap,
    ) -> Result<String, RemoteMcpHttpRejection> {
        match authorization
            .authorize_and_dispatch_event_stream(&headers, 1_000, &RecordingEventStreamDispatcher)
            .await
        {
            Ok((workspace, _, _, _, _)) => Ok(workspace),
            Err(RemoteMcpDispatchError::Authorization(rejection)) => Err(rejection),
            Err(RemoteMcpDispatchError::Dispatch(infallible)) => match infallible {},
        }
    }

    async fn introspected_workspace(
        State(authorization): State<
            Arc<RemoteMcpAxumAuthorization<IntrospectionTokenVerifier<OAuthFixtureTransport>>>,
        >,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<String, RemoteMcpHttpRejection> {
        match authorization
            .authorize_and_dispatch(&headers, &body, 1_000, &RecordingDispatcher)
            .await
        {
            Ok(dispatched) => Ok(dispatched.workspace),
            Err(RemoteMcpDispatchError::Authorization(rejection)) => Err(rejection),
            Err(RemoteMcpDispatchError::Dispatch(infallible)) => match infallible {},
        }
    }

    #[tokio::test]
    async fn owned_axum_service_preserves_dispatched_tenant_identity() {
        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("OAUTH_SECRET").expect("reference should be valid"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("remote profile should be valid");
        let authorization = Arc::new(
            RemoteMcpAxumAuthorization::from_config(16, &config, Verifier)
                .expect("owned authorization service should initialize"),
        );
        let app = Router::new()
            .route("/mcp", post(authorized_workspace))
            .with_state(authorization);
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rembrane_resolve_context","arguments":{}}}"#;

        for (token, expected_workspace) in [
            ("workspace-one", "workspace_01"),
            ("workspace-two", "workspace_02"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/mcp")
                        .header(HOST, "memory.example.test")
                        .header(CONTENT_TYPE, "application/json")
                        .header(ACCEPT, "application/json, text/event-stream")
                        .header(AUTHORIZATION, format!("Bearer {token}"))
                        .header(ORIGIN, "https://agent.example.test")
                        .body(Body::from(body))
                        .expect("request should build"),
                )
                .await
                .expect("in-memory router should respond");
            assert_eq!(response.status(), 200);
            let response_body = to_bytes(response.into_body(), 128)
                .await
                .expect("bounded response should read");
            assert_eq!(response_body.as_ref(), expected_workspace.as_bytes());
        }

        let denied = app
            .oneshot(
                Request::post("/mcp")
                    .header(HOST, "memory.example.test")
                    .header(CONTENT_TYPE, "application/json")
                    .header(ACCEPT, "application/json, text/event-stream")
                    .header(AUTHORIZATION, "Bearer workspace-one")
                    .header(ORIGIN, "https://attacker.example.test")
                    .body(Body::from(body))
                    .expect("request should build"),
            )
            .await
            .expect("in-memory router should respond");
        assert_eq!(denied.status(), 403);
    }

    #[tokio::test]
    async fn owned_axum_service_confirms_sdk_generated_session() {
        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("OAUTH_SECRET").expect("reference should be valid"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("remote profile should be valid");
        let mut authorization = RemoteMcpAxumAuthorization::from_config(16, &config, Verifier)
            .expect("owned authorization service should initialize");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        headers.insert(
            ORIGIN,
            HeaderValue::from_static("https://agent.example.test"),
        );
        let generated = RemoteSessionId::new("session_owned_sdk_0123456789")
            .expect("generated session fixture should validate");
        let terminated = Arc::new(Mutex::new(Vec::new()));
        let dispatcher = ConfirmedInitializationDispatcher {
            session_id: generated.clone(),
            terminated: Arc::clone(&terminated),
            fail_termination: false,
        };
        let initialize = zeroize::Zeroizing::new(
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#
                .to_vec(),
        );
        let initialized = authorization
            .initialize_and_commit_owned_session(&headers, initialize, 1_000, &dispatcher)
            .await
            .expect("owned service should commit the SDK-generated session");
        assert_eq!(initialized.session_id(), &generated);
        assert_eq!(initialized.output().0, "workspace_01");

        headers.insert(
            MCP_SESSION_HEADER_NAME,
            HeaderValue::from_str(generated.as_str()).expect("session header should validate"),
        );
        let tool_result = authorization
            .authorize_and_dispatch_session(
                &headers,
                br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
                1_001,
                &RecordingDispatcher,
            )
            .await
            .expect("committed generated session should authorize later requests");
        assert_eq!(tool_result.workspace, "workspace_01");
        assert_eq!(tool_result.method, "tools/list");
        assert!(
            terminated
                .lock()
                .expect("termination recording lock should remain available")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn shared_axum_initialization_never_awaits_with_registry_locked() {
        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("OAUTH_SECRET").expect("reference should be valid"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("remote profile should be valid");
        let authorization = SharedRemoteMcpAxumAuthorization::from_config(2, &config, Verifier)
            .expect("shared authorization should initialize");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        headers.insert(
            ORIGIN,
            HeaderValue::from_static("https://agent.example.test"),
        );
        let observed_unlocked = Arc::new(Mutex::new(Vec::new()));
        let dispatcher = LockProbeInitializationDispatcher {
            gate: &authorization.gate,
            session_id: RemoteSessionId::new("session_shared_probe_0123456789")
                .expect("session fixture should validate"),
            observed_unlocked: Arc::clone(&observed_unlocked),
        };

        authorization
            .initialize_and_commit_owned_session(&headers, initialize_body(), 1_000, &dispatcher)
            .await
            .expect("first shared initialization should commit");
        let duplicate = authorization
            .initialize_and_commit_owned_session(&headers, initialize_body(), 1_001, &dispatcher)
            .await
            .expect_err("duplicate SDK session should fail local commit");
        assert!(matches!(
            duplicate,
            RemoteMcpInitializationError::Commit {
                rejection: RemoteMcpHttpRejection { status: 409, .. },
                termination_error: None,
            }
        ));
        assert_eq!(
            *observed_unlocked.lock().expect("probe log"),
            [true, true],
            "SDK dispatch and compensation must run outside the registry lock"
        );
    }

    #[tokio::test]
    async fn owned_service_dispatches_exact_session_lifecycle_for_one_tenant() {
        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("OAUTH_SECRET").expect("reference should be valid"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("remote profile should be valid");
        let mut authorization = RemoteMcpAxumAuthorization::from_config(16, &config, Verifier)
            .expect("owned authorization service should initialize");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        headers.insert(
            ORIGIN,
            HeaderValue::from_static("https://agent.example.test"),
        );
        headers.insert(
            MCP_SESSION_HEADER_NAME,
            HeaderValue::from_static("session_0123456789abcdef"),
        );
        let initialize = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
        let initialized = authorization
            .establish_and_dispatch_session(&headers, initialize, 1_000, &RecordingDispatcher)
            .await
            .expect("owned service should establish and dispatch");
        assert_eq!(initialized.workspace, "workspace_01");
        assert_eq!(initialized.method, "initialize");
        assert_eq!(initialized.body, initialize);

        let body = br#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"rembrane_resolve_context","arguments":{}}}"#;
        let dispatched = authorization
            .authorize_and_dispatch_session(&headers, body, 1_100, &RecordingDispatcher)
            .await
            .expect("same tenant should reuse its established session");
        assert_eq!(dispatched.workspace, "workspace_01");
        assert_eq!(dispatched.body, body);

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-two"),
        );
        assert!(matches!(
            authorization
                .authorize_and_dispatch_session(&headers, body, 1_100, &RecordingDispatcher)
                .await,
            Err(RemoteMcpDispatchError::Authorization(
                RemoteMcpHttpRejection { status: 403, .. }
            ))
        ));

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        let deletion_service = tower::service_fn(
            |mut request: axum::http::Request<axum::body::Body>| async move {
                let access = request
                    .extensions_mut()
                    .remove::<rembrane_contracts::VerifiedRemoteAccess>()
                    .expect("verified access extension");
                Ok::<_, std::convert::Infallible>((
                    request.method().clone(),
                    access.workspace_id().to_string(),
                    request.headers().contains_key(AUTHORIZATION),
                ))
            },
        );
        let deleted = authorization
            .authorize_and_dispatch_session_deletion(
                &headers,
                1_200,
                &AuthorizedTowerMcpDispatcher::new(deletion_service),
            )
            .await
            .expect("owned service should confirm and commit deletion");
        assert_eq!(deleted.0, Method::DELETE);
        assert_eq!(deleted.1, "workspace_01");
        assert!(!deleted.2, "bearer must stop at the authorization boundary");

        assert!(matches!(
            authorization
                .authorize_and_dispatch_session(&headers, body, 1_200, &RecordingDispatcher)
                .await,
            Err(RemoteMcpDispatchError::Authorization(
                RemoteMcpHttpRejection { status: 403, .. }
            ))
        ));
    }

    #[tokio::test]
    async fn owned_session_lifecycle_preserves_each_zeroizing_body_allocation() {
        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("OAUTH_SECRET").expect("reference should be valid"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("remote profile should be valid");
        let mut authorization = RemoteMcpAxumAuthorization::from_config(16, &config, Verifier)
            .expect("owned authorization service should initialize");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        headers.insert(
            ORIGIN,
            HeaderValue::from_static("https://agent.example.test"),
        );
        headers.insert(
            MCP_SESSION_HEADER_NAME,
            HeaderValue::from_static("session_fedcba9876543210"),
        );

        let initialize = zeroize::Zeroizing::new(
            br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#.to_vec(),
        );
        let initialize_allocation = initialize.as_ptr() as usize;
        let initialized = authorization
            .establish_and_dispatch_owned_session(
                &headers,
                initialize,
                1_000,
                &AllocationRecordingDispatcher,
            )
            .await
            .expect("owned initialization should dispatch");
        assert_eq!(initialized.0, initialize_allocation);

        let request =
            zeroize::Zeroizing::new(br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#.to_vec());
        let request_allocation = request.as_ptr() as usize;
        let dispatched = authorization
            .authorize_and_dispatch_owned_session(
                &headers,
                request,
                1_100,
                &AllocationRecordingDispatcher,
            )
            .await
            .expect("owned established-session request should dispatch");
        assert_eq!(dispatched.0, request_allocation);
    }

    #[tokio::test]
    async fn rfc7662_introspection_preserves_tenants_and_denies_invalid_claims() {
        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("OAUTH_SECRET").expect("reference should be valid"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("remote profile should be valid");
        let verifier = IntrospectionTokenVerifier::new(OAuthFixtureTransport);
        let authorization = Arc::new(
            RemoteMcpAxumAuthorization::from_config(16, &config, verifier)
                .expect("introspection-backed authorization should initialize"),
        );
        let app = Router::new()
            .route("/mcp", post(introspected_workspace))
            .with_state(authorization);
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rembrane_resolve_context","arguments":{}}}"#;
        let request = |token: &'static str| {
            Request::post("/mcp")
                .header(HOST, "memory.example.test")
                .header(CONTENT_TYPE, "application/json")
                .header(ACCEPT, "application/json, text/event-stream")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header(ORIGIN, "https://agent.example.test")
                .body(Body::from(body))
                .expect("request should build")
        };

        for (token, expected_workspace) in [
            ("oauth-workspace-one", "workspace_01"),
            ("oauth-workspace-two", "workspace_02"),
        ] {
            let response = app
                .clone()
                .oneshot(request(token))
                .await
                .expect("router should respond");
            assert_eq!(response.status(), 200);
            let response_body = to_bytes(response.into_body(), 128)
                .await
                .expect("bounded response should read");
            assert_eq!(response_body.as_ref(), expected_workspace.as_bytes());
        }

        for token in [
            "oauth-wrong-audience",
            "oauth-expired",
            "oauth-missing-scope",
            "oauth-unknown",
        ] {
            let response = app
                .clone()
                .oneshot(request(token))
                .await
                .expect("router should reject invalid OAuth authority");
            assert!(
                response.status() == 401 || response.status() == 403,
                "invalid OAuth authority must fail closed"
            );
        }
    }

    #[tokio::test]
    async fn graph_dispatch_requires_scope_and_preserves_tenant_identity() {
        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("OAUTH_SECRET").expect("reference should be valid"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("remote profile should be valid");
        let authorization = RemoteMcpAxumAuthorization::from_config(16, &config, Verifier)
            .expect("owned authorization service should initialize");
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rembrane_resolve_graph_context","arguments":{"nodeId":"project_01","direction":"outgoing","validAtEpochSeconds":1700000000,"purpose":"continue project graph","entityId":"project_01"}}}"#;
        let headers = |token: &'static str| {
            let mut headers = HeaderMap::new();
            headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            headers.insert(
                ACCEPT,
                HeaderValue::from_static("application/json, text/event-stream"),
            );
            headers.insert(AUTHORIZATION, HeaderValue::from_static(token));
            headers.insert(
                ORIGIN,
                HeaderValue::from_static("https://agent.example.test"),
            );
            headers
        };

        for (token, expected_workspace) in [
            ("Bearer workspace-one", "workspace_01"),
            ("Bearer workspace-two", "workspace_02"),
        ] {
            let dispatched = authorization
                .authorize_and_dispatch(&headers(token), body, 1_000, &RecordingDispatcher)
                .await
                .expect("graph-scoped request should dispatch");
            assert_eq!(dispatched.workspace, expected_workspace);
            assert_eq!(dispatched.method, "tools/call");
            assert_eq!(
                dispatched.tool_name.as_deref(),
                Some("rembrane_resolve_graph_context")
            );
            assert_eq!(dispatched.body, body);
        }

        let denied = authorization
            .authorize_and_dispatch(
                &headers("Bearer workspace-one-no-graph"),
                body,
                1_000,
                &RecordingDispatcher,
            )
            .await
            .expect_err("token without graph scope must not reach dispatch");
        assert!(matches!(
            denied,
            RemoteMcpDispatchError::Authorization(RemoteMcpHttpRejection { status: 403, .. })
        ));
    }

    #[tokio::test]
    async fn concurrent_event_stream_routes_preserve_tenant_identity() {
        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("OAUTH_SECRET").expect("reference should be valid"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("remote profile should be valid");
        let authorization = Arc::new(
            RemoteMcpAxumAuthorization::from_config(16, &config, Verifier)
                .expect("owned authorization service should initialize"),
        );
        let app = Router::new()
            .route("/mcp", get(authorized_event_workspace))
            .with_state(authorization);
        let request = |token: &'static str, origin: &'static str| {
            Request::get("/mcp")
                .header(HOST, "memory.example.test")
                .header(ACCEPT, "text/event-stream")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header(ORIGIN, origin)
                .header(MCP_PROTOCOL_VERSION_HEADER_NAME, "2025-03-26")
                .body(Body::empty())
                .expect("request should build")
        };

        let workspace_one = app
            .clone()
            .oneshot(request("workspace-one", "https://agent.example.test"));
        let workspace_two = app
            .clone()
            .oneshot(request("workspace-two", "https://agent.example.test"));
        let denied = app.oneshot(request("workspace-one", "https://attacker.example.test"));
        let (workspace_one, workspace_two, denied) =
            tokio::join!(workspace_one, workspace_two, denied);

        let workspace_one = workspace_one.expect("first stream route should respond");
        assert_eq!(workspace_one.status(), 200);
        assert_eq!(
            to_bytes(workspace_one.into_body(), 128)
                .await
                .expect("first response should remain bounded"),
            "workspace_01"
        );

        let workspace_two = workspace_two.expect("second stream route should respond");
        assert_eq!(workspace_two.status(), 200);
        assert_eq!(
            to_bytes(workspace_two.into_body(), 128)
                .await
                .expect("second response should remain bounded"),
            "workspace_02"
        );

        assert_eq!(
            denied.expect("denied stream route should respond").status(),
            403
        );
    }

    #[tokio::test]
    async fn owned_service_authorizes_and_dispatches_as_one_operation() {
        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("OAUTH_SECRET").expect("reference should be valid"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("remote profile should be valid");
        let authorization = RemoteMcpAxumAuthorization::from_config(16, &config, Verifier)
            .expect("owned authorization service should initialize");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-two"),
        );
        headers.insert(
            ORIGIN,
            HeaderValue::from_static("https://agent.example.test"),
        );
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"rembrane_resolve_context","arguments":{}}}"#;

        let dispatched = authorization
            .authorize_and_dispatch(&headers, body, 1_000, &RecordingDispatcher)
            .await
            .expect("authorized request should dispatch");
        assert_eq!(dispatched.workspace, "workspace_02");
        assert_eq!(dispatched.content_type, "application/json");
        assert_eq!(dispatched.accept, "application/json, text/event-stream");
        assert_eq!(dispatched.body, body);

        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer invalid"));
        let error = authorization
            .authorize_and_dispatch(&headers, body, 1_000, &RecordingDispatcher)
            .await
            .expect_err("invalid token must never reach dispatch");
        assert!(matches!(
            error,
            RemoteMcpDispatchError::Authorization(RemoteMcpHttpRejection { status: 401, .. })
        ));
    }

    #[tokio::test]
    async fn owned_service_authorizes_stateless_event_stream_gets() {
        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("OAUTH_SECRET").expect("reference should be valid"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("remote profile should be valid");
        let authorization = RemoteMcpAxumAuthorization::from_config(16, &config, Verifier)
            .expect("owned authorization service should initialize");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        headers.insert(
            ORIGIN,
            HeaderValue::from_static("https://agent.example.test"),
        );
        headers.insert(ACCEPT, HeaderValue::from_static("text/event-stream"));
        headers.insert(
            MCP_PROTOCOL_VERSION_HEADER_NAME,
            HeaderValue::from_static("2025-03-26"),
        );

        let dispatched = authorization
            .authorize_and_dispatch_event_stream(&headers, 1_000, &RecordingEventStreamDispatcher)
            .await
            .expect("authorized stream dispatch cannot fail");
        assert_eq!(dispatched.0, "workspace_01");
        assert_eq!(dispatched.1, "text/event-stream");
        assert_eq!(dispatched.2.as_deref(), Some("2025-03-26"));
        assert_eq!(dispatched.3.as_deref(), Some("memory.example.test"));
        assert_eq!(dispatched.4.as_deref(), Some("https://agent.example.test"));

        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        assert!(matches!(
            authorization
                .authorize_and_dispatch_event_stream(
                    &headers,
                    1_000,
                    &RecordingEventStreamDispatcher
                )
                .await
                .expect_err("GET must negotiate event-stream"),
            RemoteMcpDispatchError::Authorization(RemoteMcpHttpRejection { status: 406, .. })
        ));

        headers.insert(ACCEPT, HeaderValue::from_static("text/event-stream"));
        headers.insert(
            MCP_SESSION_HEADER_NAME,
            HeaderValue::from_static("session_0123456789abcdef"),
        );
        assert_eq!(
            authorization
                .authorize_event_stream(&headers, 1_000)
                .expect_err("stateless GET must reject legacy session headers")
                .status,
            403
        );

        headers.remove(MCP_SESSION_HEADER_NAME);
        headers.insert(
            MCP_PROTOCOL_VERSION_HEADER_NAME,
            HeaderValue::from_static("future-version"),
        );
        assert_eq!(
            authorization
                .authorize_event_stream(&headers, 1_000)
                .expect_err("arbitrary GET protocol versions must fail")
                .status,
            400
        );
    }

    #[tokio::test]
    async fn tower_dispatcher_opens_event_stream_with_verified_tenant_only() {
        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("OAUTH_SECRET").expect("reference should be valid"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("remote profile should be valid");
        let authorization = RemoteMcpAxumAuthorization::from_config(16, &config, Verifier)
            .expect("owned authorization service should initialize");
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("memory.example.test"));
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer workspace-one"),
        );
        headers.insert(
            ORIGIN,
            HeaderValue::from_static("https://agent.example.test"),
        );
        headers.insert(ACCEPT, HeaderValue::from_static("text/event-stream"));
        headers.insert(
            MCP_PROTOCOL_VERSION_HEADER_NAME,
            HeaderValue::from_static("2025-03-26"),
        );
        let service = tower::service_fn(
            |mut request: axum::http::Request<axum::body::Body>| async move {
                let access = request
                    .extensions_mut()
                    .remove::<rembrane_contracts::VerifiedRemoteAccess>()
                    .expect("verified access extension");
                let method = request.method().as_str().to_owned();
                let has_authorization = request.headers().contains_key(AUTHORIZATION);
                let body = axum::body::to_bytes(request.into_body(), 1)
                    .await
                    .expect("empty GET body");
                Ok::<_, std::convert::Infallible>((
                    access.workspace_id().to_string(),
                    method,
                    body.is_empty(),
                    has_authorization,
                ))
            },
        );

        let dispatched = authorization
            .authorize_and_dispatch_event_stream(
                &headers,
                1_000,
                &AuthorizedTowerMcpDispatcher::new(service),
            )
            .await
            .expect("authorized Tower event stream");
        assert_eq!(
            dispatched,
            ("workspace_01".to_owned(), "GET".to_owned(), true, false)
        );
    }
}

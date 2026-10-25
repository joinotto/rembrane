use std::sync::atomic::{AtomicU64, Ordering};

use crate::{ProviderError, ProviderProtocolVersion};

pub const MEMORY_PROVIDER_DISCOVERY_PATH: &str = "/.well-known/ai-memory";
pub const CURRENT_MEMORY_PROVIDER_PROTOCOL: ProviderProtocolVersion =
    ProviderProtocolVersion::new(0, 1);

pub(crate) mod sealed {
    pub trait Sealed {}
}

/// A canonical payload whose protocol operation cannot be caller-selected.
///
/// The trait is sealed so downstream crates cannot bind arbitrary payloads to
/// privileged operations.
pub trait MemoryProviderPayload: sealed::Sealed {
    type Result;

    const OPERATION: MemoryProviderOperation;
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MemoryProviderTransport {
    Https,
    Mcp,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MemoryProviderCapability {
    ResolveContext,
    ResolveQuestion,
    RecordEvent,
    ProposeMemory,
    CheckpointActivity,
    RecordDisclosure,
    DeleteMemory,
    ExplainMemory,
    SyncPull,
    SyncPush,
}

impl MemoryProviderCapability {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResolveContext => "resolve_context",
            Self::ResolveQuestion => "resolve_question",
            Self::RecordEvent => "record_event",
            Self::ProposeMemory => "propose_memory",
            Self::CheckpointActivity => "checkpoint_activity",
            Self::RecordDisclosure => "record_disclosure",
            Self::DeleteMemory => "delete_memory",
            Self::ExplainMemory => "explain_memory",
            Self::SyncPull => "sync_pull",
            Self::SyncPush => "sync_push",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MemoryProviderScope {
    ContextRead,
    QuestionRead,
    EventWrite,
    ProposalWrite,
    CheckpointWrite,
    DisclosureWrite,
    MemoryDelete,
    MemoryExplain,
    SyncRead,
    SyncWrite,
}

impl MemoryProviderScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContextRead => "memory:context:read",
            Self::QuestionRead => "memory:question:read",
            Self::EventWrite => "memory:event:write",
            Self::ProposalWrite => "memory:proposal:write",
            Self::CheckpointWrite => "memory:checkpoint:write",
            Self::DisclosureWrite => "memory:disclosure:write",
            Self::MemoryDelete => "memory:memory:delete",
            Self::MemoryExplain => "memory:memory:explain",
            Self::SyncRead => "memory:sync:read",
            Self::SyncWrite => "memory:sync:write",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MemoryProviderHttpMethod {
    Get,
    Post,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MemoryProviderOperation {
    ResolveContext,
    ResolveQuestion,
    RecordEvent,
    ProposeMemory,
    CheckpointActivity,
    RecordDisclosure,
    DeleteMemory,
    ExplainMemory,
    SyncPull,
    SyncPush,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MemoryProviderRequestId(String);

impl MemoryProviderRequestId {
    /// Creates an opaque correlation identifier safe for logs and headers.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error unless the identifier contains
    /// 16-128 URL-safe ASCII characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderError> {
        let value = value.into();
        if !(16..=128).contains(&value.len())
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory provider request id must contain 16 to 128 URL-safe ASCII characters"
                    .to_owned(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MemoryProviderIdempotencyKey(String);

impl MemoryProviderIdempotencyKey {
    /// Creates a mutation idempotency key safe for protocol headers and logs.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error unless the key contains 16-128
    /// URL-safe ASCII characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderError> {
        let value = value.into();
        if !(16..=128).contains(&value.len())
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory provider idempotency key must contain 16 to 128 URL-safe ASCII characters"
                    .to_owned(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryProviderRequest<Payload> {
    request_id: MemoryProviderRequestId,
    protocol_version: ProviderProtocolVersion,
    operation: MemoryProviderOperation,
    payload: Payload,
}

impl<Payload: MemoryProviderPayload> MemoryProviderRequest<Payload> {
    /// Creates an operation-bound request envelope.
    ///
    /// # Errors
    ///
    /// Returns an incompatible-protocol error when the requested version is
    /// newer or belongs to a different major protocol generation.
    pub fn new(
        request_id: MemoryProviderRequestId,
        protocol_version: ProviderProtocolVersion,
        payload: Payload,
    ) -> Result<Self, ProviderError> {
        if !CURRENT_MEMORY_PROVIDER_PROTOCOL.is_compatible_with(protocol_version) {
            return Err(ProviderError::IncompatibleProtocol {
                required_major: protocol_version.major,
                required_minor: protocol_version.minor,
                offered_major: CURRENT_MEMORY_PROVIDER_PROTOCOL.major,
                offered_minor: CURRENT_MEMORY_PROVIDER_PROTOCOL.minor,
            });
        }
        Ok(Self {
            request_id,
            protocol_version,
            operation: Payload::OPERATION,
            payload,
        })
    }

    /// Creates a success response containing only this operation's canonical
    /// result type.
    #[must_use]
    pub fn success(&self, result: Payload::Result) -> MemoryProviderResponse<Payload::Result> {
        MemoryProviderResponse {
            request_id: self.request_id.clone(),
            protocol_version: self.protocol_version,
            body: MemoryProviderResponseBody::Success(result),
        }
    }

    /// Creates a correlated portable error response for this operation.
    #[must_use]
    pub fn error(&self, error: MemoryProviderErrorCode) -> MemoryProviderResponse<Payload::Result> {
        MemoryProviderResponse {
            request_id: self.request_id.clone(),
            protocol_version: self.protocol_version,
            body: MemoryProviderResponseBody::Error(error),
        }
    }

    /// Verifies that a response belongs to this exact request and negotiated
    /// protocol version.
    ///
    /// # Errors
    ///
    /// Returns a rejected-operation error when a transport returns a response
    /// correlated to another request or protocol version.
    pub fn validate_response<'response>(
        &self,
        response: &'response MemoryProviderResponse<Payload::Result>,
    ) -> Result<&'response MemoryProviderResponseBody<Payload::Result>, ProviderError> {
        if response.request_id != self.request_id
            || response.protocol_version != self.protocol_version
        {
            return Err(ProviderError::Rejected(
                "memory provider response correlation mismatch".to_owned(),
            ));
        }
        Ok(&response.body)
    }
}

impl<Payload> MemoryProviderRequest<Payload> {
    #[must_use]
    pub const fn request_id(&self) -> &MemoryProviderRequestId {
        &self.request_id
    }

    #[must_use]
    pub const fn protocol_version(&self) -> ProviderProtocolVersion {
        self.protocol_version
    }

    #[must_use]
    pub const fn operation(&self) -> MemoryProviderOperation {
        self.operation
    }

    #[must_use]
    pub const fn payload(&self) -> &Payload {
        &self.payload
    }

    #[must_use]
    pub fn into_payload(self) -> Payload {
        self.payload
    }
}

#[derive(Debug)]
pub struct MemoryProviderConnection {
    manifest: MemoryProviderManifest,
    request_prefix: String,
    next_request: AtomicU64,
}

impl MemoryProviderConnection {
    /// Accepts a discovered provider and creates a capability-bound request
    /// factory.
    ///
    /// # Errors
    ///
    /// Returns an error when discovery fails policy validation or the
    /// connection's public request namespace is malformed.
    pub fn connect(
        manifest: MemoryProviderManifest,
        policy: &MemoryProviderPolicy,
        request_prefix: impl Into<String>,
    ) -> Result<Self, ProviderError> {
        policy.validate(&manifest)?;
        let request_prefix = request_prefix.into();
        if !(8..=64).contains(&request_prefix.len())
            || !request_prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory provider request prefix must contain 8 to 64 URL-safe ASCII characters"
                    .to_owned(),
            ));
        }
        Ok(Self {
            manifest,
            request_prefix,
            next_request: AtomicU64::new(1),
        })
    }

    /// Creates a typed request only when discovery advertised its capability.
    ///
    /// # Errors
    ///
    /// Returns a missing-capability error rather than attempting an
    /// undeclared operation, and returns unavailable if the request sequence
    /// is exhausted.
    pub fn request<Payload: MemoryProviderPayload>(
        &self,
        payload: Payload,
    ) -> Result<MemoryProviderRequest<Payload>, ProviderError> {
        let operation = Payload::OPERATION;
        let capability = operation.capability();
        if !self.manifest.supports(capability) {
            return Err(ProviderError::MissingCapability(
                capability.as_str().to_owned(),
            ));
        }
        let sequence = self.next_sequence()?;
        let request_id = MemoryProviderRequestId::new(format!(
            "{}-{}-{sequence}",
            self.request_prefix,
            operation.as_str()
        ))?;
        MemoryProviderRequest::new(request_id, CURRENT_MEMORY_PROVIDER_PROTOCOL, payload)
    }

    #[must_use]
    pub const fn manifest(&self) -> &MemoryProviderManifest {
        &self.manifest
    }

    fn next_sequence(&self) -> Result<u64, ProviderError> {
        let mut current = self.next_request.load(Ordering::Relaxed);
        loop {
            let next = current.checked_add(1).ok_or(ProviderError::Unavailable)?;
            match self.next_request.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(current),
                Err(observed) => current = observed,
            }
        }
    }
}

macro_rules! bind_payload {
    ($payload:path, $result:path, $operation:expr) => {
        impl sealed::Sealed for $payload {}

        impl MemoryProviderPayload for $payload {
            type Result = $result;

            const OPERATION: MemoryProviderOperation = $operation;
        }
    };
}

bind_payload!(
    crate::memory_context::ResolveContextPayload,
    crate::memory_context::ResolveContextResult,
    MemoryProviderOperation::ResolveContext
);
bind_payload!(
    crate::memory_question::ResolveQuestionPayload,
    crate::memory_question::ResolveQuestionResult,
    MemoryProviderOperation::ResolveQuestion
);
bind_payload!(
    crate::memory_event::RecordEventPayload,
    crate::memory_event::RecordEventResult,
    MemoryProviderOperation::RecordEvent
);
bind_payload!(
    crate::memory_mutation::ProposeMemoryPayload,
    crate::memory_mutation::ProposeMemoryResult,
    MemoryProviderOperation::ProposeMemory
);
bind_payload!(
    crate::memory_checkpoint::CheckpointActivityPayload,
    crate::memory_checkpoint::CheckpointActivityResult,
    MemoryProviderOperation::CheckpointActivity
);
bind_payload!(
    crate::memory_disclosure::RecordDisclosurePayload,
    crate::memory_disclosure::RecordDisclosureResult,
    MemoryProviderOperation::RecordDisclosure
);
bind_payload!(
    crate::memory_lifecycle::DeleteMemoryPayload,
    crate::memory_lifecycle::DeleteMemoryResult,
    MemoryProviderOperation::DeleteMemory
);
bind_payload!(
    crate::memory_lifecycle::ExplainMemoryPayload,
    crate::memory_lifecycle::ExplainMemoryResult,
    MemoryProviderOperation::ExplainMemory
);
bind_payload!(
    crate::memory_sync::SyncPullPayload,
    crate::memory_sync::SyncPullResult,
    MemoryProviderOperation::SyncPull
);
bind_payload!(
    crate::memory_sync::SyncPushPayload,
    crate::memory_sync::SyncPushResult,
    MemoryProviderOperation::SyncPush
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryProviderErrorCode {
    InvalidRequest,
    AccessDenied,
    NotFound,
    Conflict,
    RateLimited,
    Unsupported,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryProviderResponseBody<Payload> {
    Success(Payload),
    Error(MemoryProviderErrorCode),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryProviderResponse<Payload> {
    request_id: MemoryProviderRequestId,
    protocol_version: ProviderProtocolVersion,
    body: MemoryProviderResponseBody<Payload>,
}

impl<Payload> MemoryProviderResponse<Payload> {
    #[must_use]
    pub const fn request_id(&self) -> &MemoryProviderRequestId {
        &self.request_id
    }

    #[must_use]
    pub const fn protocol_version(&self) -> ProviderProtocolVersion {
        self.protocol_version
    }

    #[must_use]
    pub const fn body(&self) -> &MemoryProviderResponseBody<Payload> {
        &self.body
    }

    #[must_use]
    pub fn into_body(self) -> MemoryProviderResponseBody<Payload> {
        self.body
    }
}

impl MemoryProviderOperation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResolveContext => "resolve_context",
            Self::ResolveQuestion => "resolve_question",
            Self::RecordEvent => "record_event",
            Self::ProposeMemory => "propose_memory",
            Self::CheckpointActivity => "checkpoint_activity",
            Self::RecordDisclosure => "record_disclosure",
            Self::DeleteMemory => "delete_memory",
            Self::ExplainMemory => "explain_memory",
            Self::SyncPull => "sync_pull",
            Self::SyncPush => "sync_push",
        }
    }

    #[must_use]
    pub const fn capability(self) -> MemoryProviderCapability {
        match self {
            Self::ResolveContext => MemoryProviderCapability::ResolveContext,
            Self::ResolveQuestion => MemoryProviderCapability::ResolveQuestion,
            Self::RecordEvent => MemoryProviderCapability::RecordEvent,
            Self::ProposeMemory => MemoryProviderCapability::ProposeMemory,
            Self::CheckpointActivity => MemoryProviderCapability::CheckpointActivity,
            Self::RecordDisclosure => MemoryProviderCapability::RecordDisclosure,
            Self::DeleteMemory => MemoryProviderCapability::DeleteMemory,
            Self::ExplainMemory => MemoryProviderCapability::ExplainMemory,
            Self::SyncPull => MemoryProviderCapability::SyncPull,
            Self::SyncPush => MemoryProviderCapability::SyncPush,
        }
    }

    #[must_use]
    pub const fn required_scope(self) -> MemoryProviderScope {
        match self {
            Self::ResolveContext => MemoryProviderScope::ContextRead,
            Self::ResolveQuestion => MemoryProviderScope::QuestionRead,
            Self::RecordEvent => MemoryProviderScope::EventWrite,
            Self::ProposeMemory => MemoryProviderScope::ProposalWrite,
            Self::CheckpointActivity => MemoryProviderScope::CheckpointWrite,
            Self::RecordDisclosure => MemoryProviderScope::DisclosureWrite,
            Self::DeleteMemory => MemoryProviderScope::MemoryDelete,
            Self::ExplainMemory => MemoryProviderScope::MemoryExplain,
            Self::SyncPull => MemoryProviderScope::SyncRead,
            Self::SyncPush => MemoryProviderScope::SyncWrite,
        }
    }

    #[must_use]
    pub const fn http_method(self) -> MemoryProviderHttpMethod {
        match self {
            Self::ExplainMemory | Self::SyncPull => MemoryProviderHttpMethod::Get,
            Self::DeleteMemory => MemoryProviderHttpMethod::Delete,
            Self::ResolveContext
            | Self::ResolveQuestion
            | Self::RecordEvent
            | Self::ProposeMemory
            | Self::CheckpointActivity
            | Self::RecordDisclosure
            | Self::SyncPush => MemoryProviderHttpMethod::Post,
        }
    }

    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::ResolveContext => "/v1/context/resolve",
            Self::ResolveQuestion => "/v1/questions/resolve",
            Self::RecordEvent => "/v1/events",
            Self::ProposeMemory => "/v1/memory/proposals",
            Self::CheckpointActivity => "/v1/activities/{activity_id}/checkpoint",
            Self::RecordDisclosure => "/v1/disclosures/receipt",
            Self::DeleteMemory => "/v1/memories/{memory_id}",
            Self::ExplainMemory => "/v1/memories/{memory_id}/explain",
            Self::SyncPull => "/v1/sync/pull",
            Self::SyncPush => "/v1/sync/push",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryProviderPrivacyMode {
    /// The provider stores and transports opaque end-to-end encrypted data.
    EndToEndEncrypted,
    /// Plaintext processing is confined to the user's trusted deployment.
    TrustedBoundary,
    /// The remote provider may receive plaintext after explicit policy checks.
    ProviderPlaintext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryProviderLimits {
    pub maximum_context_items: usize,
    pub maximum_context_bytes: usize,
    pub maximum_event_batch_items: usize,
    pub maximum_sync_batch_items: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryProviderManifest {
    id: String,
    version: String,
    protocol_version: ProviderProtocolVersion,
    transports: Vec<MemoryProviderTransport>,
    capabilities: Vec<MemoryProviderCapability>,
    privacy_mode: MemoryProviderPrivacyMode,
    supported_domains: Vec<String>,
    limits: MemoryProviderLimits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryProviderPolicy {
    minimum_protocol_version: ProviderProtocolVersion,
    required_transport: MemoryProviderTransport,
    required_capabilities: Vec<MemoryProviderCapability>,
    allowed_privacy_modes: Vec<MemoryProviderPrivacyMode>,
    minimum_limits: MemoryProviderLimits,
}

impl MemoryProviderPolicy {
    /// Creates a fail-closed policy for accepting a discovered provider.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error when capabilities or privacy
    /// modes are empty or duplicated, or any required limit is zero.
    pub fn new(
        minimum_protocol_version: ProviderProtocolVersion,
        required_transport: MemoryProviderTransport,
        required_capabilities: Vec<MemoryProviderCapability>,
        allowed_privacy_modes: Vec<MemoryProviderPrivacyMode>,
        minimum_limits: MemoryProviderLimits,
    ) -> Result<Self, ProviderError> {
        validate_unique_nonempty("required capabilities", &required_capabilities)?;
        validate_unique_nonempty("allowed privacy modes", &allowed_privacy_modes)?;
        if minimum_limits.maximum_context_items == 0
            || minimum_limits.maximum_context_bytes == 0
            || minimum_limits.maximum_event_batch_items == 0
            || minimum_limits.maximum_sync_batch_items == 0
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory provider policy limits must be greater than zero".to_owned(),
            ));
        }
        Ok(Self {
            minimum_protocol_version,
            required_transport,
            required_capabilities,
            allowed_privacy_modes,
            minimum_limits,
        })
    }

    /// Validates discovery against every policy requirement.
    ///
    /// # Errors
    ///
    /// Returns an incompatible-protocol error for a version mismatch and an
    /// invalid-configuration error for every other unmet requirement.
    pub fn validate(&self, manifest: &MemoryProviderManifest) -> Result<(), ProviderError> {
        if !manifest.is_protocol_compatible(self.minimum_protocol_version) {
            return Err(ProviderError::IncompatibleProtocol {
                required_major: self.minimum_protocol_version.major,
                required_minor: self.minimum_protocol_version.minor,
                offered_major: manifest.protocol_version().major,
                offered_minor: manifest.protocol_version().minor,
            });
        }
        if !manifest.transports().contains(&self.required_transport) {
            return Err(ProviderError::InvalidConfiguration(
                "memory provider does not support the required transport".to_owned(),
            ));
        }
        if self
            .required_capabilities
            .iter()
            .any(|capability| !manifest.supports(*capability))
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory provider does not support every required capability".to_owned(),
            ));
        }
        if !self
            .allowed_privacy_modes
            .contains(&manifest.privacy_mode())
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory provider privacy mode is not allowed by policy".to_owned(),
            ));
        }
        let offered = manifest.limits();
        if offered.maximum_context_items < self.minimum_limits.maximum_context_items
            || offered.maximum_context_bytes < self.minimum_limits.maximum_context_bytes
            || offered.maximum_event_batch_items < self.minimum_limits.maximum_event_batch_items
            || offered.maximum_sync_batch_items < self.minimum_limits.maximum_sync_batch_items
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory provider limits are below policy minimums".to_owned(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub const fn minimum_protocol_version(&self) -> ProviderProtocolVersion {
        self.minimum_protocol_version
    }

    #[must_use]
    pub const fn required_transport(&self) -> MemoryProviderTransport {
        self.required_transport
    }

    #[must_use]
    pub fn required_capabilities(&self) -> &[MemoryProviderCapability] {
        &self.required_capabilities
    }

    #[must_use]
    pub fn allowed_privacy_modes(&self) -> &[MemoryProviderPrivacyMode] {
        &self.allowed_privacy_modes
    }

    #[must_use]
    pub const fn minimum_limits(&self) -> MemoryProviderLimits {
        self.minimum_limits
    }
}

impl MemoryProviderManifest {
    /// Creates one validated, immutable memory-provider discovery manifest.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for malformed identifiers,
    /// empty or duplicate capability/transport declarations, malformed or
    /// duplicate domains, or zero operation limits.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        version: String,
        protocol_version: ProviderProtocolVersion,
        transports: Vec<MemoryProviderTransport>,
        capabilities: Vec<MemoryProviderCapability>,
        privacy_mode: MemoryProviderPrivacyMode,
        supported_domains: Vec<String>,
        limits: MemoryProviderLimits,
    ) -> Result<Self, ProviderError> {
        validate_identifier("memory provider id", &id)?;
        if version.trim().is_empty()
            || version.len() > 100
            || version
                .bytes()
                .any(|byte| byte.is_ascii_control() || !byte.is_ascii())
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory provider version must contain 1 to 100 safe ASCII characters".to_owned(),
            ));
        }
        validate_unique_nonempty("transports", &transports)?;
        validate_unique_nonempty("capabilities", &capabilities)?;
        if limits.maximum_context_items == 0
            || limits.maximum_context_bytes == 0
            || limits.maximum_event_batch_items == 0
            || limits.maximum_sync_batch_items == 0
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory provider limits must be greater than zero".to_owned(),
            ));
        }

        let mut domains = Vec::with_capacity(supported_domains.len());
        for domain in supported_domains {
            validate_identifier("supported domain", &domain)?;
            if domains.contains(&domain) {
                return Err(ProviderError::InvalidConfiguration(
                    "supported domains must be unique".to_owned(),
                ));
            }
            domains.push(domain);
        }

        Ok(Self {
            id,
            version,
            protocol_version,
            transports,
            capabilities,
            privacy_mode,
            supported_domains: domains,
            limits,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub const fn protocol_version(&self) -> ProviderProtocolVersion {
        self.protocol_version
    }

    #[must_use]
    pub fn transports(&self) -> &[MemoryProviderTransport] {
        &self.transports
    }

    #[must_use]
    pub fn capabilities(&self) -> &[MemoryProviderCapability] {
        &self.capabilities
    }

    #[must_use]
    pub const fn privacy_mode(&self) -> MemoryProviderPrivacyMode {
        self.privacy_mode
    }

    #[must_use]
    pub fn supported_domains(&self) -> &[String] {
        &self.supported_domains
    }

    #[must_use]
    pub const fn limits(&self) -> MemoryProviderLimits {
        self.limits
    }

    #[must_use]
    pub fn supports(&self, capability: MemoryProviderCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    #[must_use]
    pub const fn is_protocol_compatible(&self, required: ProviderProtocolVersion) -> bool {
        self.protocol_version.is_compatible_with(required)
    }
}

fn validate_unique_nonempty<T>(plural_label: &str, values: &[T]) -> Result<(), ProviderError>
where
    T: Eq,
{
    if values.is_empty() {
        return Err(ProviderError::InvalidConfiguration(format!(
            "memory provider must declare at least one of: {plural_label}"
        )));
    }
    if values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
    {
        return Err(ProviderError::InvalidConfiguration(format!(
            "memory provider {plural_label} must be unique"
        )));
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str) -> Result<(), ProviderError> {
    if value.len() < 2
        || value.len() > 255
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return Err(ProviderError::InvalidConfiguration(format!(
            "{label} must match ^[a-z0-9][a-z0-9._-]+$"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CURRENT_MEMORY_PROVIDER_PROTOCOL, MEMORY_PROVIDER_DISCOVERY_PATH, MemoryProviderCapability,
        MemoryProviderConnection, MemoryProviderErrorCode, MemoryProviderHttpMethod,
        MemoryProviderLimits, MemoryProviderManifest, MemoryProviderOperation,
        MemoryProviderPolicy, MemoryProviderPrivacyMode, MemoryProviderRequest,
        MemoryProviderRequestId, MemoryProviderResponseBody, MemoryProviderScope,
        MemoryProviderTransport,
    };
    use crate::{
        MemoryProviderContextSelector, ProviderError, ProviderProtocolVersion,
        ResolveContextPayload, ResolveQuestionPayload,
    };

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct TestPayload;

    impl super::sealed::Sealed for TestPayload {}

    impl super::MemoryProviderPayload for TestPayload {
        type Result = &'static str;

        const OPERATION: MemoryProviderOperation = MemoryProviderOperation::ResolveContext;
    }

    fn manifest() -> MemoryProviderManifest {
        MemoryProviderManifest::new(
            "rembrane.local".to_owned(),
            "0.1.0".to_owned(),
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            vec![MemoryProviderTransport::Https, MemoryProviderTransport::Mcp],
            vec![
                MemoryProviderCapability::ResolveContext,
                MemoryProviderCapability::ProposeMemory,
                MemoryProviderCapability::CheckpointActivity,
                MemoryProviderCapability::RecordDisclosure,
            ],
            MemoryProviderPrivacyMode::EndToEndEncrypted,
            vec!["personal".to_owned(), "development".to_owned()],
            MemoryProviderLimits {
                maximum_context_items: 50,
                maximum_context_bytes: 131_072,
                maximum_event_batch_items: 100,
                maximum_sync_batch_items: 500,
            },
        )
        .expect("fixture manifest should validate")
    }

    fn policy() -> MemoryProviderPolicy {
        MemoryProviderPolicy::new(
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            MemoryProviderTransport::Https,
            vec![
                MemoryProviderCapability::ResolveContext,
                MemoryProviderCapability::ProposeMemory,
            ],
            vec![MemoryProviderPrivacyMode::EndToEndEncrypted],
            MemoryProviderLimits {
                maximum_context_items: 20,
                maximum_context_bytes: 65_536,
                maximum_event_batch_items: 50,
                maximum_sync_batch_items: 100,
            },
        )
        .expect("fixture policy should validate")
    }

    #[test]
    fn advertises_versioned_memory_provider_discovery() {
        let manifest = manifest();

        assert_eq!(MEMORY_PROVIDER_DISCOVERY_PATH, "/.well-known/ai-memory");
        assert_eq!(manifest.id(), "rembrane.local");
        assert!(manifest.is_protocol_compatible(ProviderProtocolVersion::new(0, 1)));
        assert!(!manifest.is_protocol_compatible(ProviderProtocolVersion::new(1, 0)));
        assert!(manifest.supports(MemoryProviderCapability::ResolveContext));
        assert_eq!(
            manifest.privacy_mode(),
            MemoryProviderPrivacyMode::EndToEndEncrypted
        );
        assert_eq!(manifest.supported_domains(), ["personal", "development"]);
    }

    #[test]
    fn protocol_negotiation_accepts_newer_minor_and_rejects_older_or_other_major() {
        assert!(
            ProviderProtocolVersion::new(1, 2)
                .is_compatible_with(ProviderProtocolVersion::new(1, 0))
        );
        assert!(
            !ProviderProtocolVersion::new(1, 0)
                .is_compatible_with(ProviderProtocolVersion::new(1, 1))
        );
        assert!(
            !ProviderProtocolVersion::new(2, 0)
                .is_compatible_with(ProviderProtocolVersion::new(1, 0))
        );
    }

    #[test]
    fn accepts_only_manifests_satisfying_the_complete_provider_policy() {
        let policy = policy();
        assert_eq!(policy.validate(&manifest()), Ok(()));

        let plaintext_manifest = MemoryProviderManifest::new(
            "rembrane.plaintext".to_owned(),
            "0.1.0".to_owned(),
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            vec![MemoryProviderTransport::Https],
            vec![
                MemoryProviderCapability::ResolveContext,
                MemoryProviderCapability::ProposeMemory,
            ],
            MemoryProviderPrivacyMode::ProviderPlaintext,
            Vec::new(),
            MemoryProviderLimits {
                maximum_context_items: 20,
                maximum_context_bytes: 65_536,
                maximum_event_batch_items: 50,
                maximum_sync_batch_items: 100,
            },
        )
        .expect("fixture manifest should validate");
        assert_eq!(
            policy.validate(&plaintext_manifest),
            Err(ProviderError::InvalidConfiguration(
                "memory provider privacy mode is not allowed by policy".to_owned()
            ))
        );
    }

    #[test]
    fn provider_policy_fails_closed_for_missing_features_and_small_limits() {
        let missing_transport = MemoryProviderManifest::new(
            "rembrane.missing-transport".to_owned(),
            "0.1.0".to_owned(),
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            vec![MemoryProviderTransport::Mcp],
            vec![
                MemoryProviderCapability::ResolveContext,
                MemoryProviderCapability::ProposeMemory,
            ],
            MemoryProviderPrivacyMode::EndToEndEncrypted,
            Vec::new(),
            MemoryProviderLimits {
                maximum_context_items: 20,
                maximum_context_bytes: 65_536,
                maximum_event_batch_items: 50,
                maximum_sync_batch_items: 100,
            },
        )
        .expect("fixture manifest should validate");
        let policy = policy();

        assert_eq!(
            policy.validate(&missing_transport),
            Err(ProviderError::InvalidConfiguration(
                "memory provider does not support the required transport".to_owned()
            ))
        );

        let missing_capability = MemoryProviderManifest::new(
            "rembrane.missing-capability".to_owned(),
            "0.1.0".to_owned(),
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            vec![MemoryProviderTransport::Https],
            vec![MemoryProviderCapability::ResolveContext],
            MemoryProviderPrivacyMode::EndToEndEncrypted,
            Vec::new(),
            MemoryProviderLimits {
                maximum_context_items: 20,
                maximum_context_bytes: 65_536,
                maximum_event_batch_items: 50,
                maximum_sync_batch_items: 100,
            },
        )
        .expect("fixture manifest should validate");
        assert_eq!(
            policy.validate(&missing_capability),
            Err(ProviderError::InvalidConfiguration(
                "memory provider does not support every required capability".to_owned()
            ))
        );

        let small_limits = MemoryProviderManifest::new(
            "rembrane.small-limits".to_owned(),
            "0.1.0".to_owned(),
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            vec![MemoryProviderTransport::Https],
            vec![
                MemoryProviderCapability::ResolveContext,
                MemoryProviderCapability::ProposeMemory,
            ],
            MemoryProviderPrivacyMode::EndToEndEncrypted,
            Vec::new(),
            MemoryProviderLimits {
                maximum_context_items: 19,
                maximum_context_bytes: 65_536,
                maximum_event_batch_items: 50,
                maximum_sync_batch_items: 100,
            },
        )
        .expect("fixture manifest should validate");
        assert_eq!(
            policy.validate(&small_limits),
            Err(ProviderError::InvalidConfiguration(
                "memory provider limits are below policy minimums".to_owned()
            ))
        );

        assert_eq!(
            MemoryProviderPolicy::new(
                CURRENT_MEMORY_PROVIDER_PROTOCOL,
                MemoryProviderTransport::Https,
                Vec::new(),
                vec![MemoryProviderPrivacyMode::EndToEndEncrypted],
                MemoryProviderLimits {
                    maximum_context_items: 1,
                    maximum_context_bytes: 1,
                    maximum_event_batch_items: 1,
                    maximum_sync_batch_items: 1,
                },
            ),
            Err(ProviderError::InvalidConfiguration(
                "memory provider must declare at least one of: required capabilities".to_owned()
            ))
        );
    }

    #[test]
    fn negotiated_connection_creates_unique_operation_bound_requests() {
        let connection = MemoryProviderConnection::connect(manifest(), &policy(), "client_alpha")
            .expect("connection should negotiate");
        let first = connection
            .request(
                ResolveContextPayload::new(
                    "continue project work".to_owned(),
                    "current implementation".to_owned(),
                    MemoryProviderContextSelector::global(),
                    10,
                    4096,
                    connection.manifest().limits(),
                )
                .expect("payload should validate"),
            )
            .expect("advertised operation should be available");
        let second = connection
            .request(
                ResolveContextPayload::new(
                    "continue project work".to_owned(),
                    "current implementation".to_owned(),
                    MemoryProviderContextSelector::global(),
                    10,
                    4096,
                    connection.manifest().limits(),
                )
                .expect("payload should validate"),
            )
            .expect("advertised operation should be available");

        assert_eq!(first.operation(), MemoryProviderOperation::ResolveContext);
        assert_ne!(first.request_id(), second.request_id());
        assert!(first.request_id().as_str().starts_with("client_alpha-"));
    }

    #[test]
    fn negotiated_connection_rejects_undeclared_operations() {
        let connection = MemoryProviderConnection::connect(manifest(), &policy(), "client_alpha")
            .expect("connection should negotiate");
        let payload = ResolveQuestionPayload::new(
            "answer a question".to_owned(),
            "What remains?".to_owned(),
            MemoryProviderContextSelector::global(),
            10,
            4096,
            connection.manifest().limits(),
        )
        .expect("payload should validate");

        assert_eq!(
            connection.request(payload),
            Err(ProviderError::MissingCapability(
                "resolve_question".to_owned()
            ))
        );
    }

    #[test]
    fn rejects_ambiguous_or_unbounded_discovery_manifests() {
        let duplicate_transport = MemoryProviderManifest::new(
            "rembrane.local".to_owned(),
            "0.1.0".to_owned(),
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            vec![
                MemoryProviderTransport::Https,
                MemoryProviderTransport::Https,
            ],
            vec![MemoryProviderCapability::ResolveContext],
            MemoryProviderPrivacyMode::TrustedBoundary,
            Vec::new(),
            MemoryProviderLimits {
                maximum_context_items: 1,
                maximum_context_bytes: 1,
                maximum_event_batch_items: 1,
                maximum_sync_batch_items: 1,
            },
        );
        assert_eq!(
            duplicate_transport,
            Err(ProviderError::InvalidConfiguration(
                "memory provider transports must be unique".to_owned()
            ))
        );

        let invalid_domain = MemoryProviderManifest::new(
            "rembrane.local".to_owned(),
            "0.1.0".to_owned(),
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            vec![MemoryProviderTransport::Https],
            vec![MemoryProviderCapability::ResolveContext],
            MemoryProviderPrivacyMode::ProviderPlaintext,
            vec!["Travel Plans".to_owned()],
            MemoryProviderLimits {
                maximum_context_items: 1,
                maximum_context_bytes: 0,
                maximum_event_batch_items: 1,
                maximum_sync_batch_items: 1,
            },
        );
        assert!(matches!(
            invalid_domain,
            Err(ProviderError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn every_operation_has_one_capability_scope_and_http_binding() {
        let cases = [
            (
                MemoryProviderOperation::ResolveContext,
                MemoryProviderCapability::ResolveContext,
                MemoryProviderScope::ContextRead,
                MemoryProviderHttpMethod::Post,
                "/v1/context/resolve",
            ),
            (
                MemoryProviderOperation::ResolveQuestion,
                MemoryProviderCapability::ResolveQuestion,
                MemoryProviderScope::QuestionRead,
                MemoryProviderHttpMethod::Post,
                "/v1/questions/resolve",
            ),
            (
                MemoryProviderOperation::RecordEvent,
                MemoryProviderCapability::RecordEvent,
                MemoryProviderScope::EventWrite,
                MemoryProviderHttpMethod::Post,
                "/v1/events",
            ),
            (
                MemoryProviderOperation::ProposeMemory,
                MemoryProviderCapability::ProposeMemory,
                MemoryProviderScope::ProposalWrite,
                MemoryProviderHttpMethod::Post,
                "/v1/memory/proposals",
            ),
            (
                MemoryProviderOperation::CheckpointActivity,
                MemoryProviderCapability::CheckpointActivity,
                MemoryProviderScope::CheckpointWrite,
                MemoryProviderHttpMethod::Post,
                "/v1/activities/{activity_id}/checkpoint",
            ),
            (
                MemoryProviderOperation::RecordDisclosure,
                MemoryProviderCapability::RecordDisclosure,
                MemoryProviderScope::DisclosureWrite,
                MemoryProviderHttpMethod::Post,
                "/v1/disclosures/receipt",
            ),
            (
                MemoryProviderOperation::DeleteMemory,
                MemoryProviderCapability::DeleteMemory,
                MemoryProviderScope::MemoryDelete,
                MemoryProviderHttpMethod::Delete,
                "/v1/memories/{memory_id}",
            ),
            (
                MemoryProviderOperation::ExplainMemory,
                MemoryProviderCapability::ExplainMemory,
                MemoryProviderScope::MemoryExplain,
                MemoryProviderHttpMethod::Get,
                "/v1/memories/{memory_id}/explain",
            ),
            (
                MemoryProviderOperation::SyncPull,
                MemoryProviderCapability::SyncPull,
                MemoryProviderScope::SyncRead,
                MemoryProviderHttpMethod::Get,
                "/v1/sync/pull",
            ),
            (
                MemoryProviderOperation::SyncPush,
                MemoryProviderCapability::SyncPush,
                MemoryProviderScope::SyncWrite,
                MemoryProviderHttpMethod::Post,
                "/v1/sync/push",
            ),
        ];

        for (operation, capability, scope, method, path) in cases {
            assert_eq!(operation.capability(), capability);
            assert_eq!(operation.required_scope(), scope);
            assert_eq!(operation.http_method(), method);
            assert_eq!(operation.path_template(), path);
            assert!(scope.as_str().starts_with("memory:"));
        }
    }

    #[test]
    fn envelopes_bind_operation_version_and_response_correlation() {
        let request_id = MemoryProviderRequestId::new("request_0123456789abcdef")
            .expect("request id should be valid");
        let request = MemoryProviderRequest::new(
            request_id.clone(),
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            TestPayload,
        )
        .expect("current request should be compatible");
        assert_eq!(request.request_id(), &request_id);
        assert_eq!(request.operation(), MemoryProviderOperation::ResolveContext);

        let success = request.success("context");
        assert_eq!(success.request_id(), &request_id);
        assert_eq!(
            success.body(),
            &MemoryProviderResponseBody::Success("context")
        );
        let denied = request.error(MemoryProviderErrorCode::AccessDenied);
        assert_eq!(
            denied.body(),
            &MemoryProviderResponseBody::Error(MemoryProviderErrorCode::AccessDenied)
        );
        assert_eq!(
            request.validate_response(&success),
            Ok(&MemoryProviderResponseBody::Success("context"))
        );

        let other_request = MemoryProviderRequest::new(
            MemoryProviderRequestId::new("request_fedcba9876543210")
                .expect("request id should be valid"),
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            TestPayload,
        )
        .expect("current request should be compatible");
        assert_eq!(
            other_request.validate_response(&success),
            Err(ProviderError::Rejected(
                "memory provider response correlation mismatch".to_owned()
            ))
        );

        assert_eq!(
            MemoryProviderRequest::new(request_id, ProviderProtocolVersion::new(0, 2), TestPayload,),
            Err(ProviderError::IncompatibleProtocol {
                required_major: 0,
                required_minor: 2,
                offered_major: 0,
                offered_minor: 1,
            })
        );
    }

    #[test]
    fn request_ids_reject_unsafe_or_unbounded_values() {
        for invalid in [
            "",
            "short",
            "request with spaces",
            "request/with/path",
            "request\r\ninjected",
        ] {
            assert!(MemoryProviderRequestId::new(invalid).is_err());
        }
        assert!(MemoryProviderRequestId::new("x".repeat(129)).is_err());
    }
}

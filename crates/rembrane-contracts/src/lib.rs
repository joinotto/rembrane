//! Transport-independent request and response contracts.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::time::{Duration, Instant};

use rembrane_domain::{
    ActivityId, ClientId, ContextPackId, DisclosureId, DisclosureReceipt, EntityId,
    GraphDisclosureDirection, KnowledgeEdge, KnowledgeNodeId, MemoryRecord, MemoryScope,
    PrincipalId, WorkspaceId,
};

pub const MAX_REMOTE_ISSUER_BYTES: usize = 2_048;
pub const MAX_REMOTE_AUDIENCES: usize = 16;
pub const MAX_REMOTE_AUDIENCE_BYTES: usize = 2_048;
pub const MAX_REMOTE_IDENTITY_BYTES: usize = 255;

#[derive(Clone, Eq, PartialEq)]
pub struct ResolveContextRequest {
    pub workspace_id: WorkspaceId,
    pub principal_id: PrincipalId,
    pub domain: Option<String>,
    pub entity_id: Option<EntityId>,
    pub activity_id: Option<ActivityId>,
    pub purpose: String,
    pub query: String,
    pub maximum_items: usize,
    pub maximum_bytes: usize,
}

impl fmt::Debug for ResolveContextRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolveContextRequest")
            .field("workspace_id", &"[REDACTED]")
            .field("principal_id", &"[REDACTED]")
            .field("domain_present", &self.domain.is_some())
            .field("entity_id_present", &self.entity_id.is_some())
            .field("activity_id_present", &self.activity_id.is_some())
            .field("purpose", &"[REDACTED]")
            .field("query", &"[REDACTED]")
            .field("maximum_items", &self.maximum_items)
            .field("maximum_bytes", &self.maximum_bytes)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ResolveContextResponse {
    pub items: Vec<MemoryRecord>,
    pub context_pack_id: ContextPackId,
    pub disclosure_id: DisclosureId,
}

impl fmt::Debug for ResolveContextResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolveContextResponse")
            .field("item_count", &self.items.len())
            .field("context_pack_id", &"[REDACTED]")
            .field("disclosure_id", &"[REDACTED]")
            .finish()
    }
}

/// Transport-neutral request for one authorized temporal graph neighbourhood.
#[derive(Clone, Eq, PartialEq)]
pub struct ResolveGraphContextRequest {
    pub workspace_id: WorkspaceId,
    pub principal_id: PrincipalId,
    pub node_id: KnowledgeNodeId,
    pub scope: MemoryScope,
    pub direction: GraphDisclosureDirection,
    pub valid_at_epoch_seconds: u64,
    pub maximum_candidates: usize,
    pub purpose: String,
}

impl fmt::Debug for ResolveGraphContextRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolveGraphContextRequest")
            .field("workspace_id", &"[REDACTED]")
            .field("principal_id", &"[REDACTED]")
            .field("node_id", &"[REDACTED]")
            .field("scope", &"[REDACTED]")
            .field("direction", &self.direction)
            .field("valid_at_epoch_seconds", &self.valid_at_epoch_seconds)
            .field("maximum_candidates", &self.maximum_candidates)
            .field("purpose", &"[REDACTED]")
            .finish()
    }
}

/// Canonical graph revisions returned after disclosure evidence is committed.
#[derive(Clone, Eq, PartialEq)]
pub struct ResolveGraphContextResponse {
    pub edges: Vec<KnowledgeEdge>,
    pub disclosure_id: DisclosureId,
}

impl fmt::Debug for ResolveGraphContextResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolveGraphContextResponse")
            .field("edge_count", &self.edges.len())
            .field("disclosure_id", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RecordDisclosureRequest {
    pub receipt: DisclosureReceipt,
}

impl fmt::Debug for RecordDisclosureRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordDisclosureRequest")
            .field("receipt", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RemoteAccessScope {
    ContextRead,
    MemoryWrite,
    CheckpointRead,
    CheckpointWrite,
    TravelRead,
    TravelWrite,
    GraphRead,
}

impl RemoteAccessScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContextRead => "rembrane:context:read",
            Self::MemoryWrite => "rembrane:memory:write",
            Self::CheckpointRead => "rembrane:checkpoint:read",
            Self::CheckpointWrite => "rembrane:checkpoint:write",
            Self::TravelRead => "rembrane:travel:read",
            Self::TravelWrite => "rembrane:travel:write",
            Self::GraphRead => "rembrane:graph:read",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteMcpOperation {
    ResolveContext,
    RememberPreference,
    RequestCorrection,
    ForgetMemory,
    RecordWorkTrace,
    CheckpointActivity,
    ResumeActivity,
    CreateTrip,
    CaptureBookingResearch,
    AddTripParticipant,
    AddTripConstraint,
    RecordTripDecision,
    ResolveTravelContext,
    ResolveGraphContext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteMcpRequestAuthorization {
    Connection,
    Tool(RemoteMcpOperation),
}

impl RemoteMcpRequestAuthorization {
    /// Classifies one MCP JSON-RPC request for authorization.
    ///
    /// The current Rembrane MCP surface exposes tools only. Unknown methods,
    /// tool metadata on non-tool methods, missing tool names, and unknown tool
    /// names fail closed so a transport adapter cannot accidentally authorize
    /// a newly introduced SDK method as generic connection traffic.
    #[must_use]
    pub fn classify(method: &str, tool_name: Option<&str>) -> Option<Self> {
        match (method, tool_name) {
            (
                "initialize"
                | "notifications/initialized"
                | "notifications/cancelled"
                | "ping"
                | "tools/list",
                None,
            ) => Some(Self::Connection),
            ("tools/call", Some(tool_name)) => {
                RemoteMcpOperation::from_tool_name(tool_name).map(Self::Tool)
            }
            _ => None,
        }
    }
}

impl RemoteMcpOperation {
    #[must_use]
    pub const fn tool_name(self) -> &'static str {
        match self {
            Self::ResolveContext => "rembrane_resolve_context",
            Self::RememberPreference => "rembrane_remember_preference",
            Self::RequestCorrection => "rembrane_request_correction",
            Self::ForgetMemory => "rembrane_forget_memory",
            Self::RecordWorkTrace => "rembrane_record_work_trace",
            Self::CheckpointActivity => "rembrane_checkpoint_activity",
            Self::ResumeActivity => "rembrane_resume_activity",
            Self::CreateTrip => "rembrane_create_trip",
            Self::CaptureBookingResearch => "rembrane_capture_booking_research",
            Self::AddTripParticipant => "rembrane_add_trip_participant",
            Self::AddTripConstraint => "rembrane_add_trip_constraint",
            Self::RecordTripDecision => "rembrane_record_trip_decision",
            Self::ResolveTravelContext => "rembrane_resolve_travel_context",
            Self::ResolveGraphContext => "rembrane_resolve_graph_context",
        }
    }

    #[must_use]
    pub fn from_tool_name(tool_name: &str) -> Option<Self> {
        match tool_name {
            "rembrane_resolve_context" => Some(Self::ResolveContext),
            "rembrane_remember_preference" => Some(Self::RememberPreference),
            "rembrane_request_correction" => Some(Self::RequestCorrection),
            "rembrane_forget_memory" => Some(Self::ForgetMemory),
            "rembrane_record_work_trace" => Some(Self::RecordWorkTrace),
            "rembrane_checkpoint_activity" => Some(Self::CheckpointActivity),
            "rembrane_resume_activity" => Some(Self::ResumeActivity),
            "rembrane_create_trip" => Some(Self::CreateTrip),
            "rembrane_capture_booking_research" => Some(Self::CaptureBookingResearch),
            "rembrane_add_trip_participant" => Some(Self::AddTripParticipant),
            "rembrane_add_trip_constraint" => Some(Self::AddTripConstraint),
            "rembrane_record_trip_decision" => Some(Self::RecordTripDecision),
            "rembrane_resolve_travel_context" => Some(Self::ResolveTravelContext),
            "rembrane_resolve_graph_context" => Some(Self::ResolveGraphContext),
            _ => None,
        }
    }

    #[must_use]
    pub const fn required_scope(self) -> RemoteAccessScope {
        match self {
            Self::ResolveContext => RemoteAccessScope::ContextRead,
            Self::RememberPreference
            | Self::RequestCorrection
            | Self::ForgetMemory
            | Self::RecordWorkTrace => RemoteAccessScope::MemoryWrite,
            Self::CheckpointActivity => RemoteAccessScope::CheckpointWrite,
            Self::ResumeActivity => RemoteAccessScope::CheckpointRead,
            Self::CreateTrip
            | Self::CaptureBookingResearch
            | Self::AddTripParticipant
            | Self::AddTripConstraint
            | Self::RecordTripDecision => RemoteAccessScope::TravelWrite,
            Self::ResolveTravelContext => RemoteAccessScope::TravelRead,
            Self::ResolveGraphContext => RemoteAccessScope::GraphRead,
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct RemoteTokenClaims {
    pub issuer: String,
    pub audience: Vec<String>,
    pub subject_id: PrincipalId,
    pub client_id: ClientId,
    pub workspace_id: WorkspaceId,
    pub scopes: BTreeSet<RemoteAccessScope>,
    pub expires_at_epoch_seconds: u64,
    pub not_before_epoch_seconds: Option<u64>,
}

#[derive(Clone)]
pub struct VerifiedRemoteAccess {
    issuer: String,
    resource: String,
    subject_id: PrincipalId,
    client_id: ClientId,
    workspace_id: WorkspaceId,
    scopes: BTreeSet<RemoteAccessScope>,
    expires_at_epoch_seconds: u64,
    valid_until: Instant,
}

// Equality describes the verified claims, not the time a proof was acquired.
// It must never be used as a substitute for ensure_current().
impl PartialEq for VerifiedRemoteAccess {
    fn eq(&self, other: &Self) -> bool {
        self.issuer == other.issuer
            && self.resource == other.resource
            && self.subject_id == other.subject_id
            && self.client_id == other.client_id
            && self.workspace_id == other.workspace_id
            && self.scopes == other.scopes
            && self.expires_at_epoch_seconds == other.expires_at_epoch_seconds
    }
}

impl Eq for VerifiedRemoteAccess {}

#[derive(Clone)]
pub struct RemoteSessionBinding {
    issuer: String,
    resource: String,
    subject_id: PrincipalId,
    client_id: ClientId,
    workspace_id: WorkspaceId,
    scopes: BTreeSet<RemoteAccessScope>,
    maximum_token_expiry_epoch_seconds: u64,
    valid_until: Instant,
}

// Binding equality describes exact claims and the epoch ceiling, not current
// authority. Internal rollback can use an elapsed/narrowed original proof;
// admission and dispatch must separately enforce the stored monotonic deadline.
impl PartialEq for RemoteSessionBinding {
    fn eq(&self, other: &Self) -> bool {
        self.issuer == other.issuer
            && self.resource == other.resource
            && self.subject_id == other.subject_id
            && self.client_id == other.client_id
            && self.workspace_id == other.workspace_id
            && self.scopes == other.scopes
            && self.maximum_token_expiry_epoch_seconds == other.maximum_token_expiry_epoch_seconds
    }
}

impl Eq for RemoteSessionBinding {}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct RemoteSessionId(String);

impl fmt::Debug for RemoteTokenClaims {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteTokenClaims")
            .field("issuer", &"[REDACTED]")
            .field("audience_count", &self.audience.len())
            .field("subject_id", &"[REDACTED]")
            .field("client_id", &"[REDACTED]")
            .field("workspace_id", &"[REDACTED]")
            .field("scope_count", &self.scopes.len())
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .field("not_before_epoch_seconds", &self.not_before_epoch_seconds)
            .finish()
    }
}

impl fmt::Debug for VerifiedRemoteAccess {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRemoteAccess")
            .field("issuer", &"[REDACTED]")
            .field("resource", &"[REDACTED]")
            .field("subject_id", &"[REDACTED]")
            .field("client_id", &"[REDACTED]")
            .field("workspace_id", &"[REDACTED]")
            .field("scope_count", &self.scopes.len())
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .field("valid_until", &"[PROCESS-LOCAL]")
            .finish()
    }
}

impl fmt::Debug for RemoteSessionBinding {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteSessionBinding")
            .field("issuer", &"[REDACTED]")
            .field("resource", &"[REDACTED]")
            .field("subject_id", &"[REDACTED]")
            .field("client_id", &"[REDACTED]")
            .field("workspace_id", &"[REDACTED]")
            .field("scope_count", &self.scopes.len())
            .field(
                "maximum_token_expiry_epoch_seconds",
                &self.maximum_token_expiry_epoch_seconds,
            )
            .field("valid_until", &"[PROCESS-LOCAL]")
            .finish()
    }
}

impl fmt::Debug for RemoteSessionId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteSessionId([REDACTED])")
    }
}

impl RemoteSessionId {
    /// Creates an opaque MCP session identifier.
    ///
    /// # Errors
    ///
    /// Returns an error unless the value is 16-128 URL-safe ASCII
    /// characters. Session identifiers are routing capabilities, not
    /// authentication credentials.
    pub fn new(value: impl Into<String>) -> Result<Self, RemoteAccessError> {
        let value = value.into();
        if !(16..=128).contains(&value.len())
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(RemoteAccessError::SessionIdentifier);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl RemoteTokenClaims {
    /// Validates a remote MCP protocol connection after cryptographic token
    /// verification or authenticated introspection.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid issuer, audience, time, identity,
    /// workspace binding, or an empty recognized scope set.
    pub fn validate_connection(
        self,
        expected_issuer: &str,
        expected_resource: &str,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, RemoteAccessError> {
        if self.scopes.is_empty() {
            return Err(RemoteAccessError::Scope);
        }
        self.validate_common(expected_issuer, expected_resource, now_epoch_seconds)
    }

    /// Validates authorization semantics after a transport adapter has already
    /// verified the token signature and decoded trusted claims.
    ///
    /// # Errors
    ///
    /// Returns an error when issuer, audience, validity time, canonical
    /// identity, workspace binding, or the required OAuth scope is invalid.
    pub fn validate(
        self,
        expected_issuer: &str,
        expected_resource: &str,
        now_epoch_seconds: u64,
        required_scope: RemoteAccessScope,
    ) -> Result<VerifiedRemoteAccess, RemoteAccessError> {
        if !self.scopes.contains(&required_scope) {
            return Err(RemoteAccessError::Scope);
        }
        self.validate_common(expected_issuer, expected_resource, now_epoch_seconds)
    }

    fn validate_common(
        self,
        expected_issuer: &str,
        expected_resource: &str,
        now_epoch_seconds: u64,
    ) -> Result<VerifiedRemoteAccess, RemoteAccessError> {
        if !valid_remote_claim(expected_issuer, MAX_REMOTE_ISSUER_BYTES)
            || !valid_remote_claim(&self.issuer, MAX_REMOTE_ISSUER_BYTES)
            || self.issuer != expected_issuer
        {
            return Err(RemoteAccessError::Issuer);
        }
        if !valid_remote_claim(expected_resource, MAX_REMOTE_AUDIENCE_BYTES)
            || self.audience.is_empty()
            || self.audience.len() > MAX_REMOTE_AUDIENCES
            || self
                .audience
                .iter()
                .any(|audience| !valid_remote_claim(audience, MAX_REMOTE_AUDIENCE_BYTES))
            || self
                .audience
                .iter()
                .enumerate()
                .any(|(index, audience)| self.audience[..index].contains(audience))
            || !self
                .audience
                .iter()
                .any(|audience| audience == expected_resource)
        {
            return Err(RemoteAccessError::Audience);
        }
        if self.expires_at_epoch_seconds <= now_epoch_seconds {
            return Err(RemoteAccessError::Expired);
        }
        if self
            .not_before_epoch_seconds
            .is_some_and(|not_before| not_before > now_epoch_seconds)
        {
            return Err(RemoteAccessError::NotYetValid);
        }
        if !valid_remote_claim(self.subject_id.as_str(), MAX_REMOTE_IDENTITY_BYTES)
            || !valid_remote_claim(self.client_id.as_str(), MAX_REMOTE_IDENTITY_BYTES)
            || !valid_remote_claim(self.workspace_id.as_str(), MAX_REMOTE_IDENTITY_BYTES)
        {
            return Err(RemoteAccessError::Identity);
        }
        Ok(VerifiedRemoteAccess {
            issuer: self.issuer,
            resource: expected_resource.to_owned(),
            subject_id: self.subject_id,
            client_id: self.client_id,
            workspace_id: self.workspace_id,
            scopes: self.scopes,
            expires_at_epoch_seconds: self.expires_at_epoch_seconds,
            valid_until: Instant::now()
                .checked_add(Duration::from_secs(
                    self.expires_at_epoch_seconds - now_epoch_seconds,
                ))
                .ok_or(RemoteAccessError::Expired)?,
        })
    }
}

fn valid_remote_claim(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

impl VerifiedRemoteAccess {
    /// Returns this proof's non-renewable process-local deadline.
    ///
    /// This instant is not a serializable expiry timestamp or a revocation
    /// check. Response transports may use it to stop an already opened stream;
    /// authorization still requires `ensure_current()` and canonical checks.
    #[must_use]
    pub const fn validity_deadline(&self) -> Instant {
        self.valid_until
    }

    /// Checks the process-local lifetime of this verification proof.
    ///
    /// Cloning or storing a proof does not renew its deadline. This check does
    /// not introspect token revocation or replace canonical membership checks.
    ///
    /// # Errors
    ///
    /// Returns `Expired` when the validated lifetime has elapsed.
    pub fn ensure_current(&self) -> Result<(), RemoteAccessError> {
        if Instant::now() >= self.valid_until {
            return Err(RemoteAccessError::Expired);
        }
        Ok(())
    }

    /// Narrows validity using the monotonic instant at which a trusted epoch
    /// time was sampled, including time spent waiting or verifying a token.
    ///
    /// This can only shorten the current deadline. It never changes claims,
    /// sessions, or token expiry and cannot renew an expired proof.
    ///
    /// # Errors
    ///
    /// Returns `Expired` for an expired or unrepresentable validity interval.
    pub fn constrain_validity(
        &mut self,
        observed_at: Instant,
        now_epoch_seconds: u64,
    ) -> Result<(), RemoteAccessError> {
        let deadline = self
            .expires_at_epoch_seconds
            .checked_sub(now_epoch_seconds)
            .filter(|seconds| *seconds > 0)
            .and_then(|seconds| observed_at.checked_add(Duration::from_secs(seconds)));
        let Some(deadline) = deadline else {
            self.valid_until = Instant::now();
            return Err(RemoteAccessError::Expired);
        };
        self.valid_until = self.valid_until.min(deadline);
        self.ensure_current()
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    #[must_use]
    pub const fn subject_id(&self) -> &PrincipalId {
        &self.subject_id
    }

    #[must_use]
    pub const fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub fn allows(&self, scope: RemoteAccessScope) -> bool {
        self.scopes.contains(&scope)
    }

    pub fn scopes(&self) -> impl Iterator<Item = RemoteAccessScope> + '_ {
        self.scopes.iter().copied()
    }

    #[must_use]
    pub const fn expires_at_epoch_seconds(&self) -> u64 {
        self.expires_at_epoch_seconds
    }

    #[must_use]
    pub fn session_binding(&self) -> RemoteSessionBinding {
        RemoteSessionBinding {
            issuer: self.issuer.clone(),
            resource: self.resource.clone(),
            subject_id: self.subject_id.clone(),
            client_id: self.client_id.clone(),
            workspace_id: self.workspace_id.clone(),
            scopes: self.scopes.clone(),
            maximum_token_expiry_epoch_seconds: self.expires_at_epoch_seconds,
            valid_until: self.valid_until,
        }
    }
}

impl RemoteSessionBinding {
    #[must_use]
    pub fn is_expired(&self, now_epoch_seconds: u64) -> bool {
        self.maximum_token_expiry_epoch_seconds <= now_epoch_seconds
            || Instant::now() >= self.valid_until
    }

    /// Validates that a reauthenticated request still belongs to this exact
    /// session authorization context.
    ///
    /// A refreshed token may expire later, but it cannot change issuer,
    /// resource, canonical identity, workspace, or the exact OAuth scope
    /// ceiling. A token whose expiry is shorter than the original session
    /// ceiling narrows the remaining session lifetime.
    ///
    /// # Errors
    ///
    /// Returns an error when the session has expired or any bound
    /// authorization field differs.
    pub fn revalidate(
        &mut self,
        access: &VerifiedRemoteAccess,
        now_epoch_seconds: u64,
    ) -> Result<(), RemoteAccessError> {
        if self.is_expired(now_epoch_seconds)
            || access.expires_at_epoch_seconds <= now_epoch_seconds
            || access.ensure_current().is_err()
        {
            return Err(RemoteAccessError::Expired);
        }
        if self.issuer != access.issuer
            || self.resource != access.resource
            || self.subject_id != access.subject_id
            || self.client_id != access.client_id
            || self.workspace_id != access.workspace_id
            || self.scopes != access.scopes
        {
            return Err(RemoteAccessError::SessionBinding);
        }
        self.maximum_token_expiry_epoch_seconds = self
            .maximum_token_expiry_epoch_seconds
            .min(access.expires_at_epoch_seconds);
        self.valid_until = self.valid_until.min(access.validity_deadline());
        Ok(())
    }

    /// Revalidates and narrows a dispatch proof to this session's original
    /// monotonic ceiling. Signed token claims remain unchanged.
    ///
    /// # Errors
    ///
    /// Rejects expired or substituted authority. A refreshed token cannot
    /// renew the session, including when the trusted epoch clock rolls back.
    pub fn revalidate_access(
        &mut self,
        access: &mut VerifiedRemoteAccess,
        now_epoch_seconds: u64,
    ) -> Result<(), RemoteAccessError> {
        self.revalidate(access, now_epoch_seconds)?;
        access.valid_until = access.valid_until.min(self.valid_until);
        access.ensure_current()
    }

    #[must_use]
    pub const fn maximum_token_expiry_epoch_seconds(&self) -> u64 {
        self.maximum_token_expiry_epoch_seconds
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteAccessError {
    Issuer,
    Audience,
    Expired,
    NotYetValid,
    Identity,
    Scope,
    SessionBinding,
    SessionIdentifier,
}

impl Display for RemoteAccessError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Issuer => "token issuer is not authorized",
            Self::Audience => "token audience does not include this resource",
            Self::Expired => "token is expired",
            Self::NotYetValid => "token is not yet valid",
            Self::Identity => "token identity binding is incomplete",
            Self::Scope => "token does not grant the required scope",
            Self::SessionBinding => "token does not match the remote MCP session",
            Self::SessionIdentifier => "remote MCP session identifier is invalid",
        })
    }
}

impl Error for RemoteAccessError {}

#[cfg(test)]
mod tests {
    use super::{
        ActivityId, ClientId, ContextPackId, DisclosureId, DisclosureReceipt, EntityId,
        GraphDisclosureDirection, KnowledgeNodeId, MAX_REMOTE_AUDIENCE_BYTES, MAX_REMOTE_AUDIENCES,
        MAX_REMOTE_IDENTITY_BYTES, MAX_REMOTE_ISSUER_BYTES, MemoryRecord, MemoryScope, PrincipalId,
        RecordDisclosureRequest, RemoteAccessError, RemoteAccessScope, RemoteMcpOperation,
        RemoteMcpRequestAuthorization, RemoteSessionId, RemoteTokenClaims, ResolveContextRequest,
        ResolveContextResponse, ResolveGraphContextRequest, ResolveGraphContextResponse,
        WorkspaceId,
    };
    use rembrane_domain::{
        EvidenceId, EvidenceReference, EvidenceSource, MemoryId, MemoryKind, MemoryStatus,
    };

    fn claims(scopes: &[RemoteAccessScope]) -> RemoteTokenClaims {
        RemoteTokenClaims {
            issuer: "https://identity.example.test".to_owned(),
            audience: vec!["https://memory.example.test/mcp".to_owned()],
            subject_id: PrincipalId::new("principal_01"),
            client_id: ClientId::new("client_01"),
            workspace_id: WorkspaceId::new("workspace_01"),
            scopes: scopes.iter().copied().collect(),
            expires_at_epoch_seconds: 2_000,
            not_before_epoch_seconds: Some(900),
        }
    }

    #[test]
    fn validates_exact_remote_resource_and_scope() {
        let access = claims(&[RemoteAccessScope::ContextRead])
            .validate(
                "https://identity.example.test",
                "https://memory.example.test/mcp",
                1_000,
                RemoteAccessScope::ContextRead,
            )
            .expect("claims should authorize the exact remote resource");

        assert_eq!(access.subject_id().as_str(), "principal_01");
        assert_eq!(access.workspace_id().as_str(), "workspace_01");
        assert!(access.allows(RemoteAccessScope::ContextRead));
        assert!(!access.allows(RemoteAccessScope::MemoryWrite));
    }

    #[test]
    fn elapsed_proof_cannot_be_renewed_by_cloning_or_a_later_observation() {
        use std::time::{Duration, Instant};
        let mut access = claims(&[RemoteAccessScope::ContextRead])
            .validate_connection(
                "https://identity.example.test",
                "https://memory.example.test/mcp",
                1_999,
            )
            .expect("one second lifetime");
        let original = access.clone();
        assert_eq!(
            access.constrain_validity(
                Instant::now()
                    .checked_sub(Duration::from_secs(2))
                    .expect("fixture observation"),
                1_999,
            ),
            Err(RemoteAccessError::Expired),
        );
        assert_eq!(
            access.clone().ensure_current(),
            Err(RemoteAccessError::Expired)
        );
        assert_eq!(
            access.constrain_validity(Instant::now() + Duration::from_secs(60), 1_000),
            Err(RemoteAccessError::Expired),
        );
        assert_eq!(access, original, "claim equality is not lifetime authority");
        assert_eq!(access.expires_at_epoch_seconds(), 2_000);
        let mut binding = original.session_binding();
        assert_eq!(
            binding.revalidate(&access, 1_999),
            Err(RemoteAccessError::Expired)
        );
    }

    #[test]
    fn session_dispatch_proof_keeps_original_deadline_without_rewriting_claims() {
        let original = claims(&[RemoteAccessScope::ContextRead])
            .validate_connection(
                "https://identity.example.test",
                "https://memory.example.test/mcp",
                1_000,
            )
            .unwrap();
        let mut binding = original.session_binding();
        let mut refreshed_claims = claims(&[RemoteAccessScope::ContextRead]);
        refreshed_claims.expires_at_epoch_seconds = 3_000;
        let mut refreshed = refreshed_claims
            .validate_connection(
                "https://identity.example.test",
                "https://memory.example.test/mcp",
                1_000,
            )
            .unwrap();
        let signed_claims = refreshed.clone();
        binding.revalidate_access(&mut refreshed, 1_000).unwrap();
        assert_eq!(refreshed, signed_claims);
        assert_eq!(refreshed.expires_at_epoch_seconds(), 3_000);
        assert_eq!(refreshed.validity_deadline(), original.validity_deadline());
        assert_eq!(binding.maximum_token_expiry_epoch_seconds(), 2_000);
    }

    #[test]
    fn session_mono_expiry_denies_refresh_despite_a_stale_epoch_snapshot() {
        use std::time::{Duration, Instant};
        let original = claims(&[RemoteAccessScope::ContextRead])
            .validate_connection(
                "https://identity.example.test",
                "https://memory.example.test/mcp",
                1_000,
            )
            .unwrap();
        let mut binding = original.session_binding();
        assert_eq!(binding.valid_until, original.validity_deadline());
        // Model an elapsed session clock without waiting for this long fixture
        // token's real lifetime. Registry tests separately exercise real expiry.
        binding.valid_until = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
        let mut refreshed = original.clone();
        assert!(refreshed.ensure_current().is_ok());
        assert!(binding.is_expired(900));
        assert_eq!(
            binding.revalidate_access(&mut refreshed, 1_000),
            Err(RemoteAccessError::Expired),
        );
    }

    #[test]
    fn shortened_session_deadline_cannot_be_restored_by_later_proofs() {
        use std::time::Instant;
        let original = claims(&[RemoteAccessScope::ContextRead])
            .validate_connection(
                "https://identity.example.test",
                "https://memory.example.test/mcp",
                1_000,
            )
            .unwrap();
        let mut binding = original.session_binding();
        let mut narrow = original.clone();
        narrow.constrain_validity(Instant::now(), 1_999).unwrap();
        binding.revalidate(&narrow, 1_000).unwrap();
        let mut later = original.clone();
        binding.revalidate_access(&mut later, 1_000).unwrap();
        assert_eq!(later.validity_deadline(), narrow.validity_deadline());
        assert_eq!(later.expires_at_epoch_seconds(), 2_000);
        let mut foreign = claims(&[RemoteAccessScope::ContextRead]);
        foreign.workspace_id = WorkspaceId::new("workspace_other");
        let mut foreign = foreign
            .validate_connection(
                "https://identity.example.test",
                "https://memory.example.test/mcp",
                1_000,
            )
            .unwrap();
        let deadline = binding.valid_until;
        assert_eq!(
            binding.revalidate_access(&mut foreign, 1_000),
            Err(RemoteAccessError::SessionBinding),
        );
        assert_eq!(binding.valid_until, deadline);
    }

    #[test]
    fn validity_constraints_can_only_shorten_the_existing_deadline() {
        use std::time::{Duration, Instant};
        let mut access = claims(&[RemoteAccessScope::ContextRead])
            .validate_connection(
                "https://identity.example.test",
                "https://memory.example.test/mcp",
                1_000,
            )
            .expect("fresh proof");
        let original = access.valid_until;
        access
            .constrain_validity(Instant::now() + Duration::from_secs(60), 900)
            .expect("later deadline cannot extend proof");
        assert_eq!(access.valid_until, original);
        let observed = Instant::now();
        access
            .constrain_validity(observed, 1_999)
            .expect("shorter limit");
        assert_eq!(access.valid_until, observed + Duration::from_secs(1));
        assert_eq!(access.clone().valid_until, access.valid_until);
        assert_eq!(access.expires_at_epoch_seconds(), 2_000);
        assert!(!format!("{access:?}").contains("Instant"));
    }

    #[test]
    fn expired_epoch_observation_invalidates_the_proof() {
        let mut access = claims(&[RemoteAccessScope::ContextRead])
            .validate_connection(
                "https://identity.example.test",
                "https://memory.example.test/mcp",
                1_000,
            )
            .expect("fresh proof");
        assert_eq!(
            access.constrain_validity(std::time::Instant::now(), 2_000),
            Err(RemoteAccessError::Expired),
        );
        assert_eq!(access.ensure_current(), Err(RemoteAccessError::Expired));
    }

    #[test]
    fn remote_access_diagnostics_redact_identity_and_session_capabilities() {
        let claims = claims(&[RemoteAccessScope::ContextRead]);
        let claims_debug = format!("{claims:?}");
        let access = claims
            .validate_connection(
                "https://identity.example.test",
                "https://memory.example.test/mcp",
                1_000,
            )
            .expect("claims should validate");
        let access_debug = format!("{access:?}");
        let binding_debug = format!("{:?}", access.session_binding());
        let session_id = RemoteSessionId::new("private-session-id").expect("session identifier");
        let session_debug = format!("{session_id:?}");

        for private in [
            "https://identity.example.test",
            "https://memory.example.test/mcp",
            "principal_01",
            "client_01",
            "workspace_01",
            "private-session-id",
        ] {
            assert!(!claims_debug.contains(private));
            assert!(!access_debug.contains(private));
            assert!(!binding_debug.contains(private));
            assert!(!session_debug.contains(private));
        }
        assert!(claims_debug.contains("scope_count: 1"));
        assert!(access_debug.contains("scope_count: 1"));
        assert!(binding_debug.contains("scope_count: 1"));
        assert!(session_debug.contains("[REDACTED]"));
    }

    #[test]
    fn context_contract_diagnostics_never_render_private_content() {
        let request = ResolveContextRequest {
            workspace_id: WorkspaceId::new("private-workspace"),
            principal_id: PrincipalId::new("private-principal"),
            domain: Some("private-domain".to_owned()),
            entity_id: Some(EntityId::new("private-entity")),
            activity_id: Some(ActivityId::new("private-activity")),
            purpose: "private purpose".to_owned(),
            query: "private memory query".to_owned(),
            maximum_items: 5,
            maximum_bytes: 4_096,
        };
        let memory = MemoryRecord::restore(
            MemoryId::new("private-memory"),
            WorkspaceId::new("private-workspace"),
            PrincipalId::new("private-principal"),
            MemoryScope::Global,
            MemoryKind::Semantic,
            MemoryStatus::Confirmed,
            "private remembered content",
            1,
            vec![EvidenceReference::new(
                EvidenceId::new("private-evidence"),
                EvidenceSource::UserStatement,
            )],
        )
        .expect("memory fixture");
        let response = ResolveContextResponse {
            items: vec![memory],
            context_pack_id: ContextPackId::new("private-context-pack"),
            disclosure_id: DisclosureId::new("private-disclosure"),
        };
        let graph_request = ResolveGraphContextRequest {
            workspace_id: WorkspaceId::new("private-workspace"),
            principal_id: PrincipalId::new("private-principal"),
            node_id: KnowledgeNodeId::new("private-node"),
            scope: MemoryScope::Entity {
                id: EntityId::new("private-entity"),
            },
            direction: GraphDisclosureDirection::Both,
            valid_at_epoch_seconds: 1_000,
            maximum_candidates: 10,
            purpose: "private graph purpose".to_owned(),
        };
        let graph_response = ResolveGraphContextResponse {
            edges: Vec::new(),
            disclosure_id: DisclosureId::new("private-graph-disclosure"),
        };
        let disclosure = RecordDisclosureRequest {
            receipt: DisclosureReceipt {
                id: DisclosureId::new("private-disclosure"),
                context_pack_id: ContextPackId::new("private-context-pack"),
                workspace_id: WorkspaceId::new("private-workspace"),
                subject_id: PrincipalId::new("private-principal"),
                client_id: ClientId::new("private-client"),
                purpose: "private disclosure purpose".to_owned(),
                memories: Vec::new(),
            },
        };

        for debug in [
            format!("{request:?}"),
            format!("{response:?}"),
            format!("{graph_request:?}"),
            format!("{graph_response:?}"),
            format!("{disclosure:?}"),
        ] {
            for private in [
                "private-workspace",
                "private-principal",
                "private-domain",
                "private-entity",
                "private-activity",
                "private purpose",
                "private memory query",
                "private-memory",
                "private remembered content",
                "private-evidence",
                "private-context-pack",
                "private-disclosure",
                "private-node",
                "private graph purpose",
                "private-graph-disclosure",
                "private-client",
                "private disclosure purpose",
            ] {
                assert!(!debug.contains(private));
            }
        }
        assert!(format!("{response:?}").contains("item_count: 1"));
        assert!(format!("{graph_response:?}").contains("edge_count: 0"));
    }

    #[test]
    fn rejects_wrong_audience_expiry_and_missing_scope() {
        assert_eq!(
            claims(&[RemoteAccessScope::ContextRead])
                .validate(
                    "https://identity.example.test",
                    "https://other.example.test/mcp",
                    1_000,
                    RemoteAccessScope::ContextRead,
                )
                .expect_err("resource confusion must fail"),
            RemoteAccessError::Audience
        );
        assert_eq!(
            claims(&[RemoteAccessScope::ContextRead])
                .validate(
                    "https://identity.example.test",
                    "https://memory.example.test/mcp",
                    2_000,
                    RemoteAccessScope::ContextRead,
                )
                .expect_err("expiry boundary must fail"),
            RemoteAccessError::Expired
        );
        assert_eq!(
            claims(&[RemoteAccessScope::ContextRead])
                .validate(
                    "https://identity.example.test",
                    "https://memory.example.test/mcp",
                    1_000,
                    RemoteAccessScope::TravelRead,
                )
                .expect_err("missing scope must fail"),
            RemoteAccessError::Scope
        );
    }

    #[test]
    fn rejects_future_not_before_and_wrong_issuer() {
        let mut future = claims(&[RemoteAccessScope::ContextRead]);
        future.not_before_epoch_seconds = Some(1_001);
        assert_eq!(
            future
                .validate(
                    "https://identity.example.test",
                    "https://memory.example.test/mcp",
                    1_000,
                    RemoteAccessScope::ContextRead,
                )
                .expect_err("future token must fail"),
            RemoteAccessError::NotYetValid
        );
        assert_eq!(
            claims(&[RemoteAccessScope::ContextRead])
                .validate(
                    "https://untrusted.example.test",
                    "https://memory.example.test/mcp",
                    1_000,
                    RemoteAccessScope::ContextRead,
                )
                .expect_err("issuer confusion must fail"),
            RemoteAccessError::Issuer
        );
    }

    #[test]
    fn transport_neutral_claims_reject_oversized_ambiguous_or_control_bearing_values() {
        let validate = |claims: RemoteTokenClaims| {
            claims.validate_connection(
                "https://identity.example.test",
                "https://memory.example.test/mcp",
                1_000,
            )
        };

        let mut oversized_issuer = claims(&[RemoteAccessScope::ContextRead]);
        oversized_issuer.issuer = "x".repeat(MAX_REMOTE_ISSUER_BYTES + 1);
        assert_eq!(
            validate(oversized_issuer).expect_err("oversized issuer must fail"),
            RemoteAccessError::Issuer
        );

        let mut excessive_audiences = claims(&[RemoteAccessScope::ContextRead]);
        excessive_audiences.audience =
            vec!["https://memory.example.test/mcp".to_owned(); MAX_REMOTE_AUDIENCES + 1];
        assert_eq!(
            validate(excessive_audiences).expect_err("excessive audiences must fail"),
            RemoteAccessError::Audience
        );

        let mut duplicate_audiences = claims(&[RemoteAccessScope::ContextRead]);
        duplicate_audiences
            .audience
            .push("https://memory.example.test/mcp".to_owned());
        assert_eq!(
            validate(duplicate_audiences).expect_err("duplicate audiences must fail"),
            RemoteAccessError::Audience
        );

        let mut oversized_audience = claims(&[RemoteAccessScope::ContextRead]);
        oversized_audience.audience = vec!["x".repeat(MAX_REMOTE_AUDIENCE_BYTES + 1)];
        assert_eq!(
            validate(oversized_audience).expect_err("oversized audience must fail"),
            RemoteAccessError::Audience
        );

        let mut control_identity = claims(&[RemoteAccessScope::ContextRead]);
        control_identity.workspace_id = WorkspaceId::new("workspace\ninjected");
        assert_eq!(
            validate(control_identity).expect_err("control-bearing identity must fail"),
            RemoteAccessError::Identity
        );

        let mut whitespace_identity = claims(&[RemoteAccessScope::ContextRead]);
        whitespace_identity.client_id = ClientId::new(" client_01");
        assert_eq!(
            validate(whitespace_identity).expect_err("whitespace-bearing identity must fail"),
            RemoteAccessError::Identity
        );

        let mut whitespace_audience = claims(&[RemoteAccessScope::ContextRead]);
        whitespace_audience.audience = vec!["https://memory.example.test/mcp ".to_owned()];
        assert_eq!(
            validate(whitespace_audience).expect_err("whitespace-bearing audience must fail"),
            RemoteAccessError::Audience
        );

        let mut oversized_identity = claims(&[RemoteAccessScope::ContextRead]);
        oversized_identity.subject_id = PrincipalId::new("x".repeat(MAX_REMOTE_IDENTITY_BYTES + 1));
        assert_eq!(
            validate(oversized_identity).expect_err("oversized identity must fail"),
            RemoteAccessError::Identity
        );
    }

    #[test]
    fn protocol_connection_requires_a_recognized_scope() {
        let access = claims(&[RemoteAccessScope::CheckpointRead])
            .validate_connection(
                "https://identity.example.test",
                "https://memory.example.test/mcp",
                1_000,
            )
            .expect("scoped protocol connection should validate");
        assert!(access.allows(RemoteAccessScope::CheckpointRead));

        assert_eq!(
            claims(&[])
                .validate_connection(
                    "https://identity.example.test",
                    "https://memory.example.test/mcp",
                    1_000,
                )
                .expect_err("scope-free connection must fail"),
            RemoteAccessError::Scope
        );
    }

    #[test]
    fn session_binding_rejects_tenant_or_scope_substitution() {
        let access = claims(&[
            RemoteAccessScope::ContextRead,
            RemoteAccessScope::TravelRead,
        ])
        .validate_connection(
            "https://identity.example.test",
            "https://memory.example.test/mcp",
            1_000,
        )
        .expect("initial access should validate");
        let mut binding = access.session_binding();

        let mut refreshed_claims = claims(&[
            RemoteAccessScope::ContextRead,
            RemoteAccessScope::TravelRead,
        ]);
        refreshed_claims.expires_at_epoch_seconds = 1_900;
        let refreshed = refreshed_claims
            .validate_connection(
                "https://identity.example.test",
                "https://memory.example.test/mcp",
                1_100,
            )
            .expect("refresh should validate");
        binding
            .revalidate(&refreshed, 1_100)
            .expect("same authorization context should remain bound");
        assert_eq!(binding.maximum_token_expiry_epoch_seconds(), 1_900);

        let other_tenant = RemoteTokenClaims {
            workspace_id: WorkspaceId::new("workspace_other"),
            ..claims(&[
                RemoteAccessScope::ContextRead,
                RemoteAccessScope::TravelRead,
            ])
        }
        .validate_connection(
            "https://identity.example.test",
            "https://memory.example.test/mcp",
            1_100,
        )
        .expect("other tenant claims are structurally valid");
        assert_eq!(
            binding
                .revalidate(&other_tenant, 1_100)
                .expect_err("tenant substitution must fail"),
            RemoteAccessError::SessionBinding
        );

        let reduced_scope = claims(&[RemoteAccessScope::ContextRead])
            .validate_connection(
                "https://identity.example.test",
                "https://memory.example.test/mcp",
                1_100,
            )
            .expect("reduced token is structurally valid");
        assert_eq!(
            binding
                .revalidate(&reduced_scope, 1_100)
                .expect_err("scope substitution must fail"),
            RemoteAccessError::SessionBinding
        );
    }

    #[test]
    fn session_identifier_accepts_only_bounded_url_safe_values() {
        assert!(
            RemoteSessionId::new("session_0123456789abcdef")
                .expect("valid opaque id should parse")
                .as_str()
                .starts_with("session_")
        );
        for invalid in [
            "",
            "short",
            "session with spaces",
            "session/with/path",
            "session?query=value",
        ] {
            assert_eq!(
                RemoteSessionId::new(invalid).expect_err("invalid id must fail"),
                RemoteAccessError::SessionIdentifier
            );
        }
        assert_eq!(
            RemoteSessionId::new("x".repeat(129)).expect_err("oversized id must fail"),
            RemoteAccessError::SessionIdentifier
        );
    }

    #[test]
    fn maps_every_known_mcp_tool_to_a_narrow_scope_and_rejects_unknown_tools() {
        let cases = [
            ("rembrane_resolve_context", RemoteAccessScope::ContextRead),
            (
                "rembrane_remember_preference",
                RemoteAccessScope::MemoryWrite,
            ),
            (
                "rembrane_request_correction",
                RemoteAccessScope::MemoryWrite,
            ),
            ("rembrane_forget_memory", RemoteAccessScope::MemoryWrite),
            ("rembrane_record_work_trace", RemoteAccessScope::MemoryWrite),
            (
                "rembrane_checkpoint_activity",
                RemoteAccessScope::CheckpointWrite,
            ),
            (
                "rembrane_resume_activity",
                RemoteAccessScope::CheckpointRead,
            ),
            ("rembrane_create_trip", RemoteAccessScope::TravelWrite),
            (
                "rembrane_capture_booking_research",
                RemoteAccessScope::TravelWrite,
            ),
            (
                "rembrane_add_trip_participant",
                RemoteAccessScope::TravelWrite,
            ),
            (
                "rembrane_add_trip_constraint",
                RemoteAccessScope::TravelWrite,
            ),
            (
                "rembrane_record_trip_decision",
                RemoteAccessScope::TravelWrite,
            ),
            (
                "rembrane_resolve_travel_context",
                RemoteAccessScope::TravelRead,
            ),
        ];

        for (tool_name, expected_scope) in cases {
            let operation = RemoteMcpOperation::from_tool_name(tool_name)
                .expect("known MCP tool must have a remote operation");
            assert_eq!(operation.required_scope(), expected_scope);
        }
        assert_eq!(
            RemoteMcpOperation::from_tool_name("untrusted_future_tool"),
            None
        );
    }

    #[test]
    fn classifies_only_the_supported_mcp_request_surface() {
        for method in [
            "initialize",
            "notifications/initialized",
            "notifications/cancelled",
            "ping",
            "tools/list",
        ] {
            assert_eq!(
                RemoteMcpRequestAuthorization::classify(method, None),
                Some(RemoteMcpRequestAuthorization::Connection)
            );
        }
        assert_eq!(
            RemoteMcpRequestAuthorization::classify("tools/call", Some("rembrane_resolve_context")),
            Some(RemoteMcpRequestAuthorization::Tool(
                RemoteMcpOperation::ResolveContext
            ))
        );
        for (method, tool_name) in [
            ("resources/read", None),
            ("tools/call", None),
            ("tools/call", Some("untrusted_future_tool")),
            ("tools/list", Some("rembrane_resolve_context")),
        ] {
            assert_eq!(
                RemoteMcpRequestAuthorization::classify(method, tool_name),
                None
            );
        }
    }
}
mod channel;

pub use channel::{
    ChannelInboxSummary, ChannelKind, ChannelMessageError, ChannelSenderBinding,
    MAX_CHANNEL_EVENT_ID_BYTES, MAX_CHANNEL_IDENTITY_BYTES, MAX_CHANNEL_LOOKUP_KEY_BYTES,
    MAX_CHANNEL_TEXT_BYTES, VerifiedChannelMessage, channel_event_audit_target,
};

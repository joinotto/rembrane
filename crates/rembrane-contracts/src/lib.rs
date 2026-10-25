//! Transport-independent request and response contracts.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};

use rembrane_domain::{
    ActivityId, ClientId, ContextPackId, DisclosureId, DisclosureReceipt, EntityId, MemoryRecord,
    PrincipalId, WorkspaceId,
};

pub const MAX_REMOTE_ISSUER_BYTES: usize = 2_048;
pub const MAX_REMOTE_AUDIENCES: usize = 16;
pub const MAX_REMOTE_AUDIENCE_BYTES: usize = 2_048;
pub const MAX_REMOTE_IDENTITY_BYTES: usize = 255;

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveContextResponse {
    pub items: Vec<MemoryRecord>,
    pub context_pack_id: ContextPackId,
    pub disclosure_id: DisclosureId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordDisclosureRequest {
    pub receipt: DisclosureReceipt,
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

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRemoteAccess {
    issuer: String,
    resource: String,
    subject_id: PrincipalId,
    client_id: ClientId,
    workspace_id: WorkspaceId,
    scopes: BTreeSet<RemoteAccessScope>,
    expires_at_epoch_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteSessionBinding {
    issuer: String,
    resource: String,
    subject_id: PrincipalId,
    client_id: ClientId,
    workspace_id: WorkspaceId,
    scopes: BTreeSet<RemoteAccessScope>,
    maximum_token_expiry_epoch_seconds: u64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RemoteSessionId(String);

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
        })
    }
}

fn valid_remote_claim(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= maximum_bytes && !value.chars().any(char::is_control)
}

impl VerifiedRemoteAccess {
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
        }
    }
}

impl RemoteSessionBinding {
    #[must_use]
    pub const fn is_expired(&self, now_epoch_seconds: u64) -> bool {
        self.maximum_token_expiry_epoch_seconds <= now_epoch_seconds
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
        Ok(())
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
        ClientId, MAX_REMOTE_AUDIENCE_BYTES, MAX_REMOTE_AUDIENCES, MAX_REMOTE_IDENTITY_BYTES,
        MAX_REMOTE_ISSUER_BYTES, PrincipalId, RemoteAccessError, RemoteAccessScope,
        RemoteMcpOperation, RemoteMcpRequestAuthorization, RemoteSessionId, RemoteTokenClaims,
        WorkspaceId,
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
    MAX_CHANNEL_EVENT_ID_BYTES, MAX_CHANNEL_LOOKUP_KEY_BYTES, MAX_CHANNEL_TEXT_BYTES,
    VerifiedChannelMessage, channel_event_audit_target,
};

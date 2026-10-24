//! Transport-independent request and response contracts.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};

use rembrane_domain::{
    ActivityId, ClientId, ContextPackId, DisclosureId, DisclosureReceipt, EntityId, MemoryRecord,
    PrincipalId, WorkspaceId,
};

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
}

impl RemoteMcpOperation {
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

impl RemoteTokenClaims {
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
        if expected_issuer.is_empty() || self.issuer != expected_issuer {
            return Err(RemoteAccessError::Issuer);
        }
        if expected_resource.is_empty()
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
        if self.subject_id.as_str().is_empty()
            || self.client_id.as_str().is_empty()
            || self.workspace_id.as_str().is_empty()
        {
            return Err(RemoteAccessError::Identity);
        }
        if !self.scopes.contains(&required_scope) {
            return Err(RemoteAccessError::Scope);
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteAccessError {
    Issuer,
    Audience,
    Expired,
    NotYetValid,
    Identity,
    Scope,
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
        })
    }
}

impl Error for RemoteAccessError {}

#[cfg(test)]
mod tests {
    use super::{
        ClientId, PrincipalId, RemoteAccessError, RemoteAccessScope, RemoteMcpOperation,
        RemoteTokenClaims, WorkspaceId,
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
}

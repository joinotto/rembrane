use std::error::Error;
use std::fmt::{self, Display};

use crate::{AdministrativeAuditEventId, PrincipalId, WorkspaceId};

pub const MAX_AUDIT_TARGET_ID_BYTES: usize = 255;
pub const MAX_AUDIT_REQUEST_ID_BYTES: usize = 255;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdministrativeAction {
    MemberRemoved,
    KeyRotationRequired,
    KeyRotationCompleted,
    ScopeGrantChanged,
    RetentionPolicyChanged,
    LegalHoldPlaced,
    LegalHoldReleased,
}

impl AdministrativeAction {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::MemberRemoved => "member-removed",
            Self::KeyRotationRequired => "key-rotation-required",
            Self::KeyRotationCompleted => "key-rotation-completed",
            Self::ScopeGrantChanged => "scope-grant-changed",
            Self::RetentionPolicyChanged => "retention-policy-changed",
            Self::LegalHoldPlaced => "legal-hold-placed",
            Self::LegalHoldReleased => "legal-hold-released",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdministrativeTargetKind {
    Principal,
    KeyRotation,
    ScopeGrant,
    RetentionPolicy,
    LegalHold,
}

impl AdministrativeTargetKind {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Principal => "principal",
            Self::KeyRotation => "key-rotation",
            Self::ScopeGrant => "scope-grant",
            Self::RetentionPolicy => "retention-policy",
            Self::LegalHold => "legal-hold",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdministrativeAuditError {
    InvalidIdentity,
    InvalidTarget,
    InvalidRequestId,
    InvalidOccurrenceTime,
}

impl Display for AdministrativeAuditError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentity => "administrative audit identity is invalid",
            Self::InvalidTarget => "administrative audit target is invalid",
            Self::InvalidRequestId => "administrative audit request identity is invalid",
            Self::InvalidOccurrenceTime => "administrative audit occurrence time is invalid",
        })
    }
}

impl Error for AdministrativeAuditError {}

/// Immutable, content-free evidence of one privileged workspace operation.
///
/// The record deliberately excludes memory content, plaintext, credentials,
/// raw or wrapped keys, and arbitrary caller-supplied detail fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdministrativeAuditEvent {
    id: AdministrativeAuditEventId,
    workspace_id: WorkspaceId,
    actor_id: PrincipalId,
    action: AdministrativeAction,
    target_kind: AdministrativeTargetKind,
    target_id: String,
    request_id: String,
    occurred_at_epoch_seconds: u64,
}

impl AdministrativeAuditEvent {
    pub fn new(
        id: AdministrativeAuditEventId,
        workspace_id: WorkspaceId,
        actor_id: PrincipalId,
        action: AdministrativeAction,
        target_kind: AdministrativeTargetKind,
        target_id: impl Into<String>,
        request_id: impl Into<String>,
        occurred_at_epoch_seconds: u64,
    ) -> Result<Self, AdministrativeAuditError> {
        let target_id = target_id.into();
        let request_id = request_id.into();
        if !safe_identifier(id.as_str())
            || !safe_identifier(workspace_id.as_str())
            || !safe_identifier(actor_id.as_str())
        {
            return Err(AdministrativeAuditError::InvalidIdentity);
        }
        if target_id.len() > MAX_AUDIT_TARGET_ID_BYTES || !safe_identifier(&target_id) {
            return Err(AdministrativeAuditError::InvalidTarget);
        }
        if request_id.len() > MAX_AUDIT_REQUEST_ID_BYTES || !safe_identifier(&request_id) {
            return Err(AdministrativeAuditError::InvalidRequestId);
        }
        if occurred_at_epoch_seconds == 0 {
            return Err(AdministrativeAuditError::InvalidOccurrenceTime);
        }
        Ok(Self {
            id,
            workspace_id,
            actor_id,
            action,
            target_kind,
            target_id,
            request_id,
            occurred_at_epoch_seconds,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &AdministrativeAuditEventId {
        &self.id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn actor_id(&self) -> &PrincipalId {
        &self.actor_id
    }

    #[must_use]
    pub const fn action(&self) -> AdministrativeAction {
        self.action
    }

    #[must_use]
    pub const fn target_kind(&self) -> AdministrativeTargetKind {
        self.target_kind
    }

    #[must_use]
    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub const fn occurred_at_epoch_seconds(&self) -> u64 {
        self.occurred_at_epoch_seconds
    }
}

fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[cfg(test)]
mod tests {
    use super::{
        AdministrativeAction, AdministrativeAuditError, AdministrativeAuditEvent,
        AdministrativeTargetKind,
    };
    use crate::{AdministrativeAuditEventId, PrincipalId, WorkspaceId};

    #[test]
    fn records_only_bounded_content_free_administrative_evidence() {
        let event = AdministrativeAuditEvent::new(
            AdministrativeAuditEventId::new("audit_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("owner_01"),
            AdministrativeAction::KeyRotationCompleted,
            AdministrativeTargetKind::KeyRotation,
            "rotation_01",
            "request_01",
            1_798_000_000,
        )
        .expect("event should validate");

        assert_eq!(event.action().label(), "key-rotation-completed");
        assert_eq!(event.target_kind().label(), "key-rotation");
        assert_eq!(event.target_id(), "rotation_01");
        assert_eq!(event.request_id(), "request_01");
    }

    #[test]
    fn rejects_unbounded_ambiguous_or_timeless_evidence() {
        let event = |target: &str, request: &str, time| {
            AdministrativeAuditEvent::new(
                AdministrativeAuditEventId::new("audit_01"),
                WorkspaceId::new("workspace_01"),
                PrincipalId::new("owner_01"),
                AdministrativeAction::MemberRemoved,
                AdministrativeTargetKind::Principal,
                target,
                request,
                time,
            )
        };

        assert_eq!(
            event("member/unsafe", "request_01", 1),
            Err(AdministrativeAuditError::InvalidTarget)
        );
        assert_eq!(
            event("member_01", "", 1),
            Err(AdministrativeAuditError::InvalidRequestId)
        );
        assert_eq!(
            event("member_01", "request_01", 0),
            Err(AdministrativeAuditError::InvalidOccurrenceTime)
        );
    }
}

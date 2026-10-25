use std::error::Error;
use std::fmt::{self, Display};

use crate::{InvitationId, PrincipalId, WorkspaceId, WorkspaceRole};

pub const MAX_INVITATION_LIFETIME_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invitation {
    id: InvitationId,
    workspace_id: WorkspaceId,
    invited_principal_id: PrincipalId,
    invited_by: PrincipalId,
    role: WorkspaceRole,
    status: InvitationStatus,
    created_at_epoch_seconds: u64,
    expires_at_epoch_seconds: u64,
}

impl Invitation {
    pub fn new(
        id: InvitationId,
        workspace_id: WorkspaceId,
        invited_principal_id: PrincipalId,
        invited_by: PrincipalId,
        role: WorkspaceRole,
        created_at_epoch_seconds: u64,
        expires_at_epoch_seconds: u64,
    ) -> Result<Self, InvitationError> {
        if role == WorkspaceRole::Owner {
            return Err(InvitationError::OwnerRoleRequiresTransfer);
        }
        if invited_principal_id == invited_by {
            return Err(InvitationError::SelfInvitation);
        }
        let lifetime = expires_at_epoch_seconds
            .checked_sub(created_at_epoch_seconds)
            .ok_or(InvitationError::InvalidLifetime)?;
        if created_at_epoch_seconds == 0
            || lifetime == 0
            || lifetime > MAX_INVITATION_LIFETIME_SECONDS
        {
            return Err(InvitationError::InvalidLifetime);
        }

        Ok(Self {
            id,
            workspace_id,
            invited_principal_id,
            invited_by,
            role,
            status: InvitationStatus::Pending,
            created_at_epoch_seconds,
            expires_at_epoch_seconds,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &InvitationId {
        &self.id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn invited_principal_id(&self) -> &PrincipalId {
        &self.invited_principal_id
    }

    #[must_use]
    pub const fn invited_by(&self) -> &PrincipalId {
        &self.invited_by
    }

    #[must_use]
    pub const fn role(&self) -> WorkspaceRole {
        self.role
    }

    #[must_use]
    pub const fn status(&self) -> InvitationStatus {
        self.status
    }

    #[must_use]
    pub const fn created_at_epoch_seconds(&self) -> u64 {
        self.created_at_epoch_seconds
    }

    #[must_use]
    pub const fn expires_at_epoch_seconds(&self) -> u64 {
        self.expires_at_epoch_seconds
    }

    pub fn accept_at(mut self, now_epoch_seconds: u64) -> Result<Self, InvitationError> {
        if self.status != InvitationStatus::Pending {
            return Err(InvitationError::NotPending);
        }
        if now_epoch_seconds < self.created_at_epoch_seconds {
            return Err(InvitationError::NotYetValid);
        }
        if now_epoch_seconds >= self.expires_at_epoch_seconds {
            return Err(InvitationError::Expired);
        }
        self.status = InvitationStatus::Accepted;
        Ok(self)
    }

    pub fn revoke(mut self) -> Result<Self, InvitationError> {
        if self.status != InvitationStatus::Pending {
            return Err(InvitationError::NotPending);
        }
        self.status = InvitationStatus::Revoked;
        Ok(self)
    }

    pub fn expire_at(mut self, now_epoch_seconds: u64) -> Result<Self, InvitationError> {
        if self.status != InvitationStatus::Pending {
            return Err(InvitationError::NotPending);
        }
        if now_epoch_seconds < self.expires_at_epoch_seconds {
            return Err(InvitationError::NotExpired);
        }
        self.status = InvitationStatus::Expired;
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationError {
    NotPending,
    Expired,
    InvalidLifetime,
    NotYetValid,
    NotExpired,
    OwnerRoleRequiresTransfer,
    SelfInvitation,
}

impl Display for InvitationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPending => formatter.write_str("invitation is no longer pending"),
            Self::Expired => formatter.write_str("invitation has expired"),
            Self::InvalidLifetime => {
                formatter.write_str("invitation lifetime is invalid or exceeds 30 days")
            }
            Self::NotYetValid => formatter.write_str("invitation is not yet valid"),
            Self::NotExpired => formatter.write_str("invitation has not expired"),
            Self::OwnerRoleRequiresTransfer => {
                formatter.write_str("owner role requires an explicit ownership transfer")
            }
            Self::SelfInvitation => formatter.write_str("a principal cannot invite itself"),
        }
    }
}

impl Error for InvitationError {}

#[cfg(test)]
mod tests {
    use super::{Invitation, InvitationError, InvitationStatus, MAX_INVITATION_LIFETIME_SECONDS};
    use crate::{InvitationId, PrincipalId, WorkspaceId, WorkspaceRole};

    fn invitation(role: WorkspaceRole) -> Result<Invitation, InvitationError> {
        Invitation::new(
            InvitationId::new("invitation_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_guest"),
            PrincipalId::new("principal_owner"),
            role,
            1_000,
            2_000,
        )
    }

    #[test]
    fn accepts_pending_invitation_once() {
        let accepted = invitation(WorkspaceRole::Member)
            .expect("member invitation should be valid")
            .accept_at(1_500)
            .expect("pending invitation should accept");

        assert_eq!(accepted.status(), InvitationStatus::Accepted);
        assert_eq!(accepted.accept_at(1_500), Err(InvitationError::NotPending));
    }

    #[test]
    fn owner_role_cannot_be_granted_by_invitation() {
        assert_eq!(
            invitation(WorkspaceRole::Owner),
            Err(InvitationError::OwnerRoleRequiresTransfer)
        );
    }

    #[test]
    fn rejects_expired_future_and_unbounded_invitations() {
        let pending = invitation(WorkspaceRole::Member).expect("invitation");
        assert_eq!(
            pending.clone().accept_at(2_000),
            Err(InvitationError::Expired)
        );
        assert_eq!(pending.accept_at(999), Err(InvitationError::NotYetValid));
        assert_eq!(
            Invitation::new(
                InvitationId::new("invitation_02"),
                WorkspaceId::new("workspace_01"),
                PrincipalId::new("principal_guest"),
                PrincipalId::new("principal_owner"),
                WorkspaceRole::Member,
                1_000,
                1_000 + MAX_INVITATION_LIFETIME_SECONDS + 1,
            ),
            Err(InvitationError::InvalidLifetime)
        );
    }

    #[test]
    fn expiration_is_an_explicit_terminal_transition() {
        let expired = invitation(WorkspaceRole::Member)
            .expect("invitation")
            .expire_at(2_000)
            .expect("expiry boundary");
        assert_eq!(expired.status(), InvitationStatus::Expired);
        assert_eq!(expired.expire_at(2_000), Err(InvitationError::NotPending));
    }
}

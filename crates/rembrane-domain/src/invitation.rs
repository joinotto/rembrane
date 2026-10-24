use std::error::Error;
use std::fmt::{self, Display};

use crate::{InvitationId, PrincipalId, WorkspaceId, WorkspaceRole};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Invitation {
    id: InvitationId,
    workspace_id: WorkspaceId,
    invited_principal_id: PrincipalId,
    invited_by: PrincipalId,
    role: WorkspaceRole,
    status: InvitationStatus,
}

impl Invitation {
    pub fn new(
        id: InvitationId,
        workspace_id: WorkspaceId,
        invited_principal_id: PrincipalId,
        invited_by: PrincipalId,
        role: WorkspaceRole,
    ) -> Result<Self, InvitationError> {
        if role == WorkspaceRole::Owner {
            return Err(InvitationError::OwnerRoleRequiresTransfer);
        }
        if invited_principal_id == invited_by {
            return Err(InvitationError::SelfInvitation);
        }

        Ok(Self {
            id,
            workspace_id,
            invited_principal_id,
            invited_by,
            role,
            status: InvitationStatus::Pending,
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

    pub fn accept(mut self) -> Result<Self, InvitationError> {
        if self.status != InvitationStatus::Pending {
            return Err(InvitationError::NotPending);
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationError {
    NotPending,
    OwnerRoleRequiresTransfer,
    SelfInvitation,
}

impl Display for InvitationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPending => formatter.write_str("invitation is no longer pending"),
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
    use super::{Invitation, InvitationError, InvitationStatus};
    use crate::{InvitationId, PrincipalId, WorkspaceId, WorkspaceRole};

    fn invitation(role: WorkspaceRole) -> Result<Invitation, InvitationError> {
        Invitation::new(
            InvitationId::new("invitation_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_guest"),
            PrincipalId::new("principal_owner"),
            role,
        )
    }

    #[test]
    fn accepts_pending_invitation_once() {
        let accepted = invitation(WorkspaceRole::Member)
            .expect("member invitation should be valid")
            .accept()
            .expect("pending invitation should accept");

        assert_eq!(accepted.status(), InvitationStatus::Accepted);
        assert_eq!(accepted.accept(), Err(InvitationError::NotPending));
    }

    #[test]
    fn owner_role_cannot_be_granted_by_invitation() {
        assert_eq!(
            invitation(WorkspaceRole::Owner),
            Err(InvitationError::OwnerRoleRequiresTransfer)
        );
    }
}

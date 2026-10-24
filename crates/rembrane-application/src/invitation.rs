use rembrane_domain::{
    Invitation, InvitationId, Membership, PrincipalId, WorkspaceId, WorkspaceKind, WorkspaceRole,
};

use crate::{ApplicationError, InvitationRepository, MembershipRepository, WorkspaceRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateInvitationCommand {
    pub invitation_id: InvitationId,
    pub workspace_id: WorkspaceId,
    pub invited_principal_id: PrincipalId,
    pub invited_by: PrincipalId,
    pub role: WorkspaceRole,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeInvitationCommand {
    pub invitation_id: InvitationId,
    pub workspace_id: WorkspaceId,
    pub revoked_by: PrincipalId,
}

pub struct InvitationService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> InvitationService<'repository, Repository>
where
    Repository: InvitationRepository + MembershipRepository + WorkspaceRepository,
{
    pub fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn create(
        &mut self,
        command: CreateInvitationCommand,
    ) -> Result<Invitation, ApplicationError> {
        let workspace = self
            .repository
            .find_workspace(&command.workspace_id)?
            .ok_or(ApplicationError::NotFound)?;
        if workspace.kind() != WorkspaceKind::Shared {
            return Err(ApplicationError::AccessDenied);
        }
        let inviter = self
            .repository
            .find_membership(&command.workspace_id, &command.invited_by)?
            .ok_or(ApplicationError::AccessDenied)?;
        if !inviter.can_manage_members() {
            return Err(ApplicationError::AccessDenied);
        }
        if self
            .repository
            .find_principal(&command.invited_principal_id)?
            .is_none()
        {
            return Err(ApplicationError::NotFound);
        }
        if self
            .repository
            .find_membership(&command.workspace_id, &command.invited_principal_id)?
            .is_some()
        {
            return Err(ApplicationError::AlreadyExists);
        }

        let invitation = Invitation::new(
            command.invitation_id,
            command.workspace_id,
            command.invited_principal_id,
            command.invited_by,
            command.role,
        )
        .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        self.repository.insert_invitation(invitation.clone())?;
        Ok(invitation)
    }

    pub fn accept(
        &mut self,
        workspace_id: &WorkspaceId,
        invitation_id: &InvitationId,
        accepting_principal_id: &PrincipalId,
    ) -> Result<Membership, ApplicationError> {
        let invitation = self
            .repository
            .find_invitation(workspace_id, invitation_id)?
            .ok_or(ApplicationError::NotFound)?;
        if invitation.invited_principal_id() != accepting_principal_id {
            return Err(ApplicationError::NotFound);
        }
        let accepted = invitation
            .accept()
            .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        let membership = Membership::new(
            workspace_id.clone(),
            accepting_principal_id.clone(),
            accepted.role(),
        );
        self.repository
            .accept_invitation_with_membership(accepted, membership.clone())?;
        Ok(membership)
    }

    pub fn revoke(
        &mut self,
        command: RevokeInvitationCommand,
    ) -> Result<Invitation, ApplicationError> {
        let RevokeInvitationCommand {
            invitation_id,
            workspace_id,
            revoked_by,
        } = command;
        let actor = self
            .repository
            .find_membership(&workspace_id, &revoked_by)?
            .ok_or(ApplicationError::AccessDenied)?;
        if !actor.can_manage_members() {
            return Err(ApplicationError::AccessDenied);
        }
        let invitation = self
            .repository
            .find_invitation(&workspace_id, &invitation_id)?
            .ok_or(ApplicationError::NotFound)?;
        let expected_status = invitation.status();
        let revoked = invitation
            .revoke()
            .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        self.repository
            .replace_invitation(revoked.clone(), expected_status)?;
        Ok(revoked)
    }
}

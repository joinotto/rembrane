use rembrane_domain::{
    AdministrativeAction, AdministrativeAuditEvent, AdministrativeAuditEventId,
    AdministrativeTargetKind, Invitation, InvitationId, InvitationStatus, Membership, PrincipalId,
    WorkspaceId, WorkspaceKind, WorkspaceRole,
};

use crate::{ApplicationError, InvitationRepository, MembershipRepository, WorkspaceRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateInvitationCommand {
    pub invitation_id: InvitationId,
    pub workspace_id: WorkspaceId,
    pub invited_principal_id: PrincipalId,
    pub invited_by: PrincipalId,
    pub role: WorkspaceRole,
    pub request_id: String,
    pub created_at_epoch_seconds: u64,
    pub expires_at_epoch_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptInvitationCommand {
    pub invitation_id: InvitationId,
    pub workspace_id: WorkspaceId,
    pub accepting_principal_id: PrincipalId,
    pub request_id: String,
    pub accepted_at_epoch_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeInvitationCommand {
    pub invitation_id: InvitationId,
    pub workspace_id: WorkspaceId,
    pub revoked_by: PrincipalId,
    pub request_id: String,
    pub revoked_at_epoch_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListInvitationsQuery {
    pub workspace_id: WorkspaceId,
    pub requested_by: PrincipalId,
    pub status: Option<InvitationStatus>,
    pub limit: usize,
}

pub const MAXIMUM_INVITATION_LIST_ITEMS: usize = 100;

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
            command.created_at_epoch_seconds,
            command.expires_at_epoch_seconds,
        )
        .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        let audit = invitation_audit(
            &invitation,
            invitation.invited_by(),
            &command.request_id,
            AdministrativeAction::InvitationCreated,
            command.created_at_epoch_seconds,
        )?;
        self.repository
            .insert_invitation_replacing_expired(invitation.clone(), audit)?;
        Ok(invitation)
    }

    pub fn accept(
        &mut self,
        command: AcceptInvitationCommand,
    ) -> Result<Membership, ApplicationError> {
        let invitation = self
            .repository
            .find_invitation(&command.workspace_id, &command.invitation_id)?
            .ok_or(ApplicationError::NotFound)?;
        if invitation.invited_principal_id() != &command.accepting_principal_id {
            return Err(ApplicationError::NotFound);
        }
        let accepted = invitation
            .accept_at(command.accepted_at_epoch_seconds)
            .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        let membership = Membership::new(
            command.workspace_id,
            command.accepting_principal_id,
            accepted.role(),
        );
        let audit = invitation_audit(
            &accepted,
            membership.principal_id(),
            &command.request_id,
            AdministrativeAction::InvitationAccepted,
            command.accepted_at_epoch_seconds,
        )?;
        self.repository
            .accept_invitation_with_membership(accepted, membership.clone(), audit)?;
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
            request_id,
            revoked_at_epoch_seconds,
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
        if revoked_at_epoch_seconds < invitation.created_at_epoch_seconds() {
            return Err(ApplicationError::Validation(
                "invitation revocation predates invitation creation".to_owned(),
            ));
        }
        let expected_status = invitation.status();
        let revoked = invitation
            .revoke()
            .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        let audit = invitation_audit(
            &revoked,
            &revoked_by,
            &request_id,
            AdministrativeAction::InvitationRevoked,
            revoked_at_epoch_seconds,
        )?;
        self.repository
            .replace_invitation(revoked.clone(), expected_status, audit)?;
        Ok(revoked)
    }

    pub fn list(&self, query: &ListInvitationsQuery) -> Result<Vec<Invitation>, ApplicationError> {
        if query.limit == 0 || query.limit > MAXIMUM_INVITATION_LIST_ITEMS {
            return Err(ApplicationError::Validation(
                "invitation list limit must be between 1 and 100".to_owned(),
            ));
        }
        let actor = self
            .repository
            .find_membership(&query.workspace_id, &query.requested_by)?
            .ok_or(ApplicationError::AccessDenied)?;
        if !actor.can_manage_members() {
            return Err(ApplicationError::AccessDenied);
        }
        self.repository
            .list_invitations(&query.workspace_id, query.status, query.limit)
    }
}

fn invitation_audit(
    invitation: &Invitation,
    actor_id: &PrincipalId,
    request_id: &str,
    action: AdministrativeAction,
    occurred_at_epoch_seconds: u64,
) -> Result<AdministrativeAuditEvent, ApplicationError> {
    AdministrativeAuditEvent::new(
        AdministrativeAuditEventId::new(format!("audit:{}:{request_id}", action.label())),
        invitation.workspace_id().clone(),
        actor_id.clone(),
        action,
        AdministrativeTargetKind::Invitation,
        invitation.id().as_str(),
        request_id,
        occurred_at_epoch_seconds,
    )
    .map_err(|error| ApplicationError::Validation(error.to_string()))
}

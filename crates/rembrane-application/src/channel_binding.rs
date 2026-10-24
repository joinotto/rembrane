use std::time::{SystemTime, UNIX_EPOCH};

use rembrane_contracts::ChannelSenderBinding;
use rembrane_domain::{
    AdministrativeAction, AdministrativeAuditEvent, AdministrativeAuditEventId,
    AdministrativeTargetKind, PrincipalId,
};

use crate::{ApplicationError, ChannelSenderBindingRepository, MembershipRepository};

pub struct CreateChannelBindingCommand {
    pub binding: ChannelSenderBinding,
    pub created_by: PrincipalId,
    pub request_id: String,
}

pub struct RevokeChannelBindingCommand {
    pub binding: ChannelSenderBinding,
    pub revoked_by: PrincipalId,
    pub request_id: String,
}

pub struct ChannelBindingService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> ChannelBindingService<'repository, Repository>
where
    Repository: ChannelSenderBindingRepository + MembershipRepository,
{
    pub fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn create(
        &mut self,
        command: CreateChannelBindingCommand,
    ) -> Result<ChannelSenderBinding, ApplicationError> {
        authorize_administrator(
            self.repository,
            command.binding.workspace_id(),
            &command.created_by,
        )?;
        let audit = binding_audit(
            &command.binding,
            &command.created_by,
            &command.request_id,
            AdministrativeAction::ChannelBindingCreated,
        )?;
        self.repository
            .insert_channel_sender_binding_with_audit(command.binding.clone(), audit)?;
        Ok(command.binding)
    }

    pub fn revoke(
        &mut self,
        command: RevokeChannelBindingCommand,
    ) -> Result<ChannelSenderBinding, ApplicationError> {
        authorize_administrator(
            self.repository,
            command.binding.workspace_id(),
            &command.revoked_by,
        )?;
        let audit = binding_audit(
            &command.binding,
            &command.revoked_by,
            &command.request_id,
            AdministrativeAction::ChannelBindingRevoked,
        )?;
        self.repository
            .delete_channel_sender_binding_with_audit(&command.binding, audit)?;
        Ok(command.binding)
    }
}

fn authorize_administrator<Repository: MembershipRepository>(
    repository: &Repository,
    workspace_id: &rembrane_domain::WorkspaceId,
    actor_id: &PrincipalId,
) -> Result<(), ApplicationError> {
    let actor = repository
        .find_membership(workspace_id, actor_id)?
        .filter(rembrane_domain::Membership::is_active)
        .ok_or(ApplicationError::AccessDenied)?;
    if !actor.can_manage_members() {
        return Err(ApplicationError::AccessDenied);
    }
    Ok(())
}

fn binding_audit(
    binding: &ChannelSenderBinding,
    actor_id: &PrincipalId,
    request_id: &str,
    action: AdministrativeAction,
) -> Result<AdministrativeAuditEvent, ApplicationError> {
    let target_id = format!(
        "{}:{}:{}",
        binding.channel().label(),
        binding.principal_id().as_str(),
        binding.client_id().as_str()
    );
    AdministrativeAuditEvent::new(
        AdministrativeAuditEventId::new(format!("audit:{}:{request_id}", action.label())),
        binding.workspace_id().clone(),
        actor_id.clone(),
        action,
        AdministrativeTargetKind::ChannelBinding,
        target_id,
        request_id,
        now_epoch_seconds()?,
    )
    .map_err(|error| ApplicationError::Validation(error.to_string()))
}

fn now_epoch_seconds() -> Result<u64, ApplicationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApplicationError::StorageUnavailable)
        .map(|duration| duration.as_secs())
}

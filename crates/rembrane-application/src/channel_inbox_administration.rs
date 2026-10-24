use std::time::{SystemTime, UNIX_EPOCH};

use rembrane_contracts::{ChannelInboxSummary, ChannelKind};
use rembrane_domain::{
    AdministrativeAction, AdministrativeAuditEvent, AdministrativeAuditEventId,
    AdministrativeTargetKind, PrincipalId, WorkspaceId,
};

use crate::{ApplicationError, ChannelInboxAdministrationRepository, MembershipRepository};

pub struct ChannelInboxAdministrationService<'repository, Repository> {
    repository: &'repository mut Repository,
}

pub struct RequeueChannelMessageCommand {
    pub workspace_id: WorkspaceId,
    pub channel: ChannelKind,
    pub event_id: String,
    pub actor_id: PrincipalId,
    pub request_id: String,
}

impl<'repository, Repository> ChannelInboxAdministrationService<'repository, Repository>
where
    Repository: ChannelInboxAdministrationRepository + MembershipRepository,
{
    pub const fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn summary(
        &self,
        workspace_id: &WorkspaceId,
        actor_id: &PrincipalId,
    ) -> Result<ChannelInboxSummary, ApplicationError> {
        let actor = self
            .repository
            .find_membership(workspace_id, actor_id)?
            .filter(rembrane_domain::Membership::is_active)
            .ok_or(ApplicationError::AccessDenied)?;
        if !actor.can_manage_members() {
            return Err(ApplicationError::AccessDenied);
        }
        self.repository.channel_inbox_summary(workspace_id)
    }

    pub fn requeue(
        &mut self,
        command: RequeueChannelMessageCommand,
    ) -> Result<(), ApplicationError> {
        authorize_administrator(self.repository, &command.workspace_id, &command.actor_id)?;
        let target_id = format!("{}:{}", command.channel.label(), command.event_id);
        let audit = AdministrativeAuditEvent::new(
            AdministrativeAuditEventId::new(format!(
                "audit:{}:{}",
                AdministrativeAction::ChannelMessageRequeued.label(),
                command.request_id
            )),
            command.workspace_id.clone(),
            command.actor_id,
            AdministrativeAction::ChannelMessageRequeued,
            AdministrativeTargetKind::ChannelMessage,
            target_id,
            command.request_id,
            now_epoch_seconds()?,
        )
        .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        self.repository.requeue_quarantined_channel_message(
            &command.workspace_id,
            command.channel,
            &command.event_id,
            audit,
        )
    }
}

fn authorize_administrator<Repository: MembershipRepository>(
    repository: &Repository,
    workspace_id: &WorkspaceId,
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

fn now_epoch_seconds() -> Result<u64, ApplicationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApplicationError::StorageUnavailable)
        .map(|duration| duration.as_secs())
}

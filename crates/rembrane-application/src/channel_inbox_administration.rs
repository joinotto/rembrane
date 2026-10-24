use rembrane_contracts::ChannelInboxSummary;
use rembrane_domain::{PrincipalId, WorkspaceId};

use crate::{ApplicationError, ChannelInboxAdministrationRepository, MembershipRepository};

pub struct ChannelInboxAdministrationService<'repository, Repository> {
    repository: &'repository Repository,
}

impl<'repository, Repository> ChannelInboxAdministrationService<'repository, Repository>
where
    Repository: ChannelInboxAdministrationRepository + MembershipRepository,
{
    pub const fn new(repository: &'repository Repository) -> Self {
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
}

use rembrane_domain::{MemberScopeGrant, PrincipalId, ReadScope, WorkspaceId};

use crate::{ApplicationError, MemberScopeGrantRepository, MembershipRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantMemberScopeCommand {
    pub workspace_id: WorkspaceId,
    pub principal_id: PrincipalId,
    pub granted_by: PrincipalId,
    pub scope: ReadScope,
}

pub struct MemberScopeGrantService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> MemberScopeGrantService<'repository, Repository>
where
    Repository: MemberScopeGrantRepository + MembershipRepository,
{
    pub fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn grant(
        &mut self,
        command: GrantMemberScopeCommand,
    ) -> Result<MemberScopeGrant, ApplicationError> {
        let actor = self
            .repository
            .find_membership(&command.workspace_id, &command.granted_by)?
            .ok_or(ApplicationError::AccessDenied)?;
        if !actor.can_manage_members() {
            return Err(ApplicationError::AccessDenied);
        }
        let target = self
            .repository
            .find_membership(&command.workspace_id, &command.principal_id)?
            .ok_or(ApplicationError::NotFound)?;
        if !target.is_active() {
            return Err(ApplicationError::NotFound);
        }

        let grant =
            MemberScopeGrant::new(command.workspace_id, command.principal_id, command.scope);
        self.repository.insert_member_scope_grant(grant.clone())?;
        Ok(grant)
    }
}

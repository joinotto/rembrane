use rembrane_domain::{Membership, PrincipalId, WorkspaceId, WorkspaceRole};

use crate::{ApplicationError, MemberLifecycleRepository, MembershipRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoveMemberCommand {
    pub workspace_id: WorkspaceId,
    pub principal_id: PrincipalId,
    pub removed_by: PrincipalId,
}

pub struct MemberLifecycleService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> MemberLifecycleService<'repository, Repository>
where
    Repository: MemberLifecycleRepository + MembershipRepository,
{
    pub fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn remove(&mut self, command: RemoveMemberCommand) -> Result<Membership, ApplicationError> {
        let RemoveMemberCommand {
            workspace_id,
            principal_id,
            removed_by,
        } = command;
        let actor = self
            .repository
            .find_membership(&workspace_id, &removed_by)?
            .ok_or(ApplicationError::AccessDenied)?;
        let target = self
            .repository
            .find_membership(&workspace_id, &principal_id)?
            .ok_or(ApplicationError::NotFound)?;
        if !target.is_active() {
            return Err(ApplicationError::NotFound);
        }
        if !can_remove(actor.role(), target.role()) {
            return Err(ApplicationError::AccessDenied);
        }

        let expected_status = target.status();
        let removed = target.remove();
        self.repository
            .remove_member_and_scope_grants(removed.clone(), expected_status)?;
        Ok(removed)
    }
}

const fn can_remove(actor: WorkspaceRole, target: WorkspaceRole) -> bool {
    match actor {
        WorkspaceRole::Owner => !matches!(target, WorkspaceRole::Owner),
        WorkspaceRole::Admin => matches!(target, WorkspaceRole::Member | WorkspaceRole::Viewer),
        WorkspaceRole::Member | WorkspaceRole::Viewer => false,
    }
}

#[cfg(test)]
mod tests {
    use super::can_remove;
    use rembrane_domain::WorkspaceRole;

    #[test]
    fn role_hierarchy_protects_owners_and_peer_admins() {
        assert!(can_remove(WorkspaceRole::Owner, WorkspaceRole::Admin));
        assert!(can_remove(WorkspaceRole::Admin, WorkspaceRole::Member));
        assert!(!can_remove(WorkspaceRole::Admin, WorkspaceRole::Admin));
        assert!(!can_remove(WorkspaceRole::Owner, WorkspaceRole::Owner));
    }
}

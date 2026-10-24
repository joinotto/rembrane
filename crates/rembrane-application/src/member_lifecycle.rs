use rembrane_domain::{
    KeyRotationId, KeyRotationReceipt, KeyRotationStatus, Membership, PrincipalId, WorkspaceId,
    WorkspaceKeyRotation, WorkspaceRole,
};

use crate::{
    ApplicationError, KeyRotationRepository, MemberLifecycleRepository, MembershipRepository,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoveMemberCommand {
    pub workspace_id: WorkspaceId,
    pub principal_id: PrincipalId,
    pub removed_by: PrincipalId,
    pub rotation_id: KeyRotationId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteKeyRotationCommand {
    pub receipt: KeyRotationReceipt,
    pub completed_by: PrincipalId,
}

pub struct MemberLifecycleService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> MemberLifecycleService<'repository, Repository>
where
    Repository: KeyRotationRepository + MemberLifecycleRepository + MembershipRepository,
{
    pub fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn remove(&mut self, command: RemoveMemberCommand) -> Result<Membership, ApplicationError> {
        let RemoveMemberCommand {
            workspace_id,
            principal_id,
            removed_by,
            rotation_id,
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
        self.repository.remove_member_and_scope_grants(
            removed.clone(),
            expected_status,
            rotation_id,
            removed_by,
        )?;
        Ok(removed)
    }

    pub fn complete_key_rotation(
        &mut self,
        command: CompleteKeyRotationCommand,
    ) -> Result<WorkspaceKeyRotation, ApplicationError> {
        let workspace_id = command.receipt.workspace_id().clone();
        let actor = self
            .repository
            .find_membership(&workspace_id, &command.completed_by)?
            .ok_or(ApplicationError::AccessDenied)?;
        if !actor.is_active()
            || !matches!(actor.role(), WorkspaceRole::Owner | WorkspaceRole::Admin)
        {
            return Err(ApplicationError::AccessDenied);
        }
        let rotation = self
            .repository
            .latest_key_rotation(&workspace_id)?
            .ok_or(ApplicationError::NotFound)?;
        if rotation.status() != KeyRotationStatus::Required
            || rotation.generation() != command.receipt.generation()
            || rotation.workspace_id() != command.receipt.workspace_id()
        {
            return Err(ApplicationError::VersionConflict);
        }
        let mut canonical_recipients = self
            .repository
            .list_active_memberships(&workspace_id)?
            .into_iter()
            .map(|membership| membership.principal_id().clone())
            .collect::<Vec<_>>();
        canonical_recipients.sort();
        if canonical_recipients != command.receipt.recipient_ids() {
            return Err(ApplicationError::AccessDenied);
        }
        let receipt = command.receipt;
        let completed = rotation
            .complete(receipt.key_id(), command.completed_by)
            .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        self.repository.complete_key_rotation(
            completed.clone(),
            receipt.clone(),
            receipt.generation(),
        )?;
        Ok(completed)
    }

    pub fn orchestrate_key_rotation<Rotate>(
        &mut self,
        workspace_id: WorkspaceId,
        completed_by: PrincipalId,
        rotate: Rotate,
    ) -> Result<WorkspaceKeyRotation, ApplicationError>
    where
        Rotate: FnOnce(
            WorkspaceId,
            u64,
            Vec<PrincipalId>,
        ) -> Result<KeyRotationReceipt, ApplicationError>,
    {
        let actor = self
            .repository
            .find_membership(&workspace_id, &completed_by)?
            .ok_or(ApplicationError::AccessDenied)?;
        if !actor.is_active()
            || !matches!(actor.role(), WorkspaceRole::Owner | WorkspaceRole::Admin)
        {
            return Err(ApplicationError::AccessDenied);
        }
        let rotation = self
            .repository
            .latest_key_rotation(&workspace_id)?
            .ok_or(ApplicationError::NotFound)?;
        if rotation.status() != KeyRotationStatus::Required {
            return Err(ApplicationError::VersionConflict);
        }
        let mut recipients = self
            .repository
            .list_active_memberships(&workspace_id)?
            .into_iter()
            .map(|membership| membership.principal_id().clone())
            .collect::<Vec<_>>();
        recipients.sort();
        let receipt = rotate(workspace_id, rotation.generation(), recipients)?;
        self.complete_key_rotation(CompleteKeyRotationCommand {
            receipt,
            completed_by,
        })
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

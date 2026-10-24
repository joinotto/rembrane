use std::time::{SystemTime, UNIX_EPOCH};

use rembrane_domain::{
    AdministrativeAction, AdministrativeAuditEvent, AdministrativeAuditEventId,
    AdministrativeTargetKind, LegalHoldId, PrincipalId, WorkspaceId, WorkspaceLegalHold,
    WorkspaceRetentionPolicy,
};

use crate::{ApplicationError, MembershipRepository, RetentionRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetRetentionPolicyCommand {
    pub policy: WorkspaceRetentionPolicy,
    pub expected_version: Option<u64>,
    pub changed_by: PrincipalId,
    pub request_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlaceLegalHoldCommand {
    pub workspace_id: WorkspaceId,
    pub hold_id: LegalHoldId,
    pub placed_by: PrincipalId,
    pub request_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseLegalHoldCommand {
    pub workspace_id: WorkspaceId,
    pub hold_id: LegalHoldId,
    pub released_by: PrincipalId,
    pub request_id: String,
}

pub struct RetentionService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> RetentionService<'repository, Repository>
where
    Repository: MembershipRepository + RetentionRepository,
{
    pub fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn set_policy(
        &mut self,
        command: SetRetentionPolicyCommand,
    ) -> Result<WorkspaceRetentionPolicy, ApplicationError> {
        authorize_administrator(
            self.repository,
            command.policy.workspace_id(),
            &command.changed_by,
        )?;
        let audit = audit_event(
            command.policy.workspace_id(),
            &command.changed_by,
            AdministrativeAction::RetentionPolicyChanged,
            AdministrativeTargetKind::RetentionPolicy,
            command.policy.workspace_id().as_str(),
            &command.request_id,
        )?;
        self.repository.replace_retention_policy(
            command.policy.clone(),
            command.expected_version,
            audit,
        )?;
        Ok(command.policy)
    }

    pub fn place_legal_hold(
        &mut self,
        command: PlaceLegalHoldCommand,
    ) -> Result<WorkspaceLegalHold, ApplicationError> {
        authorize_administrator(self.repository, &command.workspace_id, &command.placed_by)?;
        let now = now_epoch_seconds()?;
        let hold = WorkspaceLegalHold::active(
            command.hold_id,
            command.workspace_id,
            command.placed_by.clone(),
            now,
        )
        .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        let audit = audit_event(
            hold.workspace_id(),
            &command.placed_by,
            AdministrativeAction::LegalHoldPlaced,
            AdministrativeTargetKind::LegalHold,
            hold.id().as_str(),
            &command.request_id,
        )?;
        self.repository.insert_legal_hold(hold.clone(), audit)?;
        Ok(hold)
    }

    pub fn release_legal_hold(
        &mut self,
        command: ReleaseLegalHoldCommand,
    ) -> Result<WorkspaceLegalHold, ApplicationError> {
        let ReleaseLegalHoldCommand {
            workspace_id,
            hold_id,
            released_by,
            request_id,
        } = command;
        authorize_administrator(self.repository, &workspace_id, &released_by)?;
        let current = self
            .repository
            .find_legal_hold(&workspace_id, &hold_id)?
            .ok_or(ApplicationError::NotFound)?;
        let expected_version = current.version();
        let released = current
            .release(released_by.clone(), now_epoch_seconds()?)
            .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        let audit = audit_event(
            released.workspace_id(),
            &released_by,
            AdministrativeAction::LegalHoldReleased,
            AdministrativeTargetKind::LegalHold,
            released.id().as_str(),
            &request_id,
        )?;
        self.repository
            .replace_legal_hold(released.clone(), expected_version, audit)?;
        Ok(released)
    }
}

fn authorize_administrator<Repository>(
    repository: &Repository,
    workspace_id: &WorkspaceId,
    actor_id: &PrincipalId,
) -> Result<(), ApplicationError>
where
    Repository: MembershipRepository,
{
    let actor = repository
        .find_membership(workspace_id, actor_id)?
        .ok_or(ApplicationError::AccessDenied)?;
    if !actor.can_manage_members() {
        return Err(ApplicationError::AccessDenied);
    }
    Ok(())
}

fn audit_event(
    workspace_id: &WorkspaceId,
    actor_id: &PrincipalId,
    action: AdministrativeAction,
    target_kind: AdministrativeTargetKind,
    target_id: &str,
    request_id: &str,
) -> Result<AdministrativeAuditEvent, ApplicationError> {
    AdministrativeAuditEvent::new(
        AdministrativeAuditEventId::new(format!("audit:{}:{request_id}", action.label())),
        workspace_id.clone(),
        actor_id.clone(),
        action,
        target_kind,
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

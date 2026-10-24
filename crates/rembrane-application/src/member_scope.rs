use std::time::{SystemTime, UNIX_EPOCH};

use rembrane_domain::{
    AdministrativeAction, AdministrativeAuditEvent, AdministrativeAuditEventId,
    AdministrativeTargetKind, MemberScopeGrant, PrincipalId, ReadScope, WorkspaceId,
};

use crate::{ApplicationError, MemberScopeGrantRepository, MembershipRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantMemberScopeCommand {
    pub workspace_id: WorkspaceId,
    pub principal_id: PrincipalId,
    pub granted_by: PrincipalId,
    pub scope: ReadScope,
    pub request_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeMemberScopeCommand {
    pub workspace_id: WorkspaceId,
    pub principal_id: PrincipalId,
    pub revoked_by: PrincipalId,
    pub scope: ReadScope,
    pub request_id: String,
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

        let grant = MemberScopeGrant::new(
            command.workspace_id.clone(),
            command.principal_id,
            command.scope,
        );
        let audit = scope_audit(
            &grant,
            &command.granted_by,
            &command.request_id,
            now_epoch_seconds()?,
        )?;
        self.repository
            .insert_member_scope_grant(grant.clone(), audit)?;
        Ok(grant)
    }

    pub fn revoke(
        &mut self,
        command: RevokeMemberScopeCommand,
    ) -> Result<MemberScopeGrant, ApplicationError> {
        let RevokeMemberScopeCommand {
            workspace_id,
            principal_id,
            revoked_by,
            scope,
            request_id,
        } = command;
        let actor = self
            .repository
            .find_membership(&workspace_id, &revoked_by)?
            .ok_or(ApplicationError::AccessDenied)?;
        if !actor.can_manage_members() {
            return Err(ApplicationError::AccessDenied);
        }
        let target = self
            .repository
            .find_membership(&workspace_id, &principal_id)?
            .ok_or(ApplicationError::NotFound)?;
        if !target.is_active() {
            return Err(ApplicationError::NotFound);
        }

        let grant = MemberScopeGrant::new(workspace_id, principal_id, scope);
        let audit = scope_audit(&grant, &revoked_by, &request_id, now_epoch_seconds()?)?;
        self.repository.delete_member_scope_grant(&grant, audit)?;
        Ok(grant)
    }
}

fn scope_audit(
    grant: &MemberScopeGrant,
    actor_id: &PrincipalId,
    request_id: &str,
    occurred_at_epoch_seconds: u64,
) -> Result<AdministrativeAuditEvent, ApplicationError> {
    let (scope_type, scope_value) = scope_identity(grant.scope());
    let target_id = if scope_value.is_empty() {
        format!("{}:{scope_type}", grant.principal_id().as_str())
    } else {
        format!(
            "{}:{scope_type}:{scope_value}",
            grant.principal_id().as_str()
        )
    };
    AdministrativeAuditEvent::new(
        AdministrativeAuditEventId::new(format!("audit:scope-grant-changed:{request_id}")),
        grant.workspace_id().clone(),
        actor_id.clone(),
        AdministrativeAction::ScopeGrantChanged,
        AdministrativeTargetKind::ScopeGrant,
        target_id,
        request_id,
        occurred_at_epoch_seconds,
    )
    .map_err(|error| ApplicationError::Validation(error.to_string()))
}

fn scope_identity(scope: &ReadScope) -> (&'static str, &str) {
    match scope {
        ReadScope::Global => ("global", ""),
        ReadScope::Domain { name } => ("domain", name),
        ReadScope::Entity { id } => ("entity", id.as_str()),
        ReadScope::Activity { id } => ("activity", id.as_str()),
    }
}

fn now_epoch_seconds() -> Result<u64, ApplicationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApplicationError::StorageUnavailable)
        .map(|duration| duration.as_secs())
}

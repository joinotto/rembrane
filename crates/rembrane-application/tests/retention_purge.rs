use rembrane_application::{
    ApplicationError, ExecuteRetentionPurgeCommand, MembershipRepository, RetentionPurgePlan,
    RetentionPurgeRepository, RetentionPurgeResult, RetentionRepository, RetentionService,
};
use rembrane_domain::{
    AdministrativeAuditEvent, LegalHoldId, Membership, PrincipalId, RetentionPeriod, WorkspaceId,
    WorkspaceLegalHold, WorkspaceRetentionPolicy, WorkspaceRole,
};

struct Repository {
    membership: Membership,
    policy: WorkspaceRetentionPolicy,
    holds: Vec<WorkspaceLegalHold>,
    executed_plan: Option<RetentionPurgePlan>,
}

impl Repository {
    fn new() -> Self {
        Self {
            membership: Membership::new(
                WorkspaceId::new("team"),
                PrincipalId::new("owner"),
                WorkspaceRole::Owner,
            ),
            policy: WorkspaceRetentionPolicy::new(
                WorkspaceId::new("team"),
                1,
                RetentionPeriod::days(30).expect("memory"),
                RetentionPeriod::days(7).expect("checkpoint"),
                RetentionPeriod::days(14).expect("travel"),
                RetentionPeriod::days(90).expect("disclosure"),
                RetentionPeriod::days(365).expect("event"),
                RetentionPeriod::Forever,
            )
            .expect("policy"),
            holds: Vec::new(),
            executed_plan: None,
        }
    }
}

impl MembershipRepository for Repository {
    fn insert_membership(&mut self, _membership: Membership) -> Result<(), ApplicationError> {
        unreachable!("not used")
    }

    fn find_membership(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Option<Membership>, ApplicationError> {
        Ok((self.membership.workspace_id() == workspace_id
            && self.membership.principal_id() == principal_id)
            .then(|| self.membership.clone()))
    }

    fn list_active_memberships(
        &self,
        _workspace_id: &WorkspaceId,
    ) -> Result<Vec<Membership>, ApplicationError> {
        unreachable!("not used")
    }

    fn replace_membership(&mut self, _membership: Membership) -> Result<(), ApplicationError> {
        unreachable!("not used")
    }
}

impl RetentionRepository for Repository {
    fn find_retention_policy(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<WorkspaceRetentionPolicy>, ApplicationError> {
        Ok((self.policy.workspace_id() == workspace_id).then(|| self.policy.clone()))
    }

    fn replace_retention_policy(
        &mut self,
        _policy: WorkspaceRetentionPolicy,
        _expected_version: Option<u64>,
        _audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        unreachable!("not used")
    }

    fn find_legal_hold(
        &self,
        _workspace_id: &WorkspaceId,
        _hold_id: &LegalHoldId,
    ) -> Result<Option<WorkspaceLegalHold>, ApplicationError> {
        unreachable!("not used")
    }

    fn list_active_legal_holds(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<WorkspaceLegalHold>, ApplicationError> {
        Ok(self
            .holds
            .iter()
            .filter(|hold| hold.workspace_id() == workspace_id)
            .cloned()
            .collect())
    }

    fn insert_legal_hold(
        &mut self,
        _hold: WorkspaceLegalHold,
        _audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        unreachable!("not used")
    }

    fn replace_legal_hold(
        &mut self,
        _hold: WorkspaceLegalHold,
        _expected_version: u64,
        _audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        unreachable!("not used")
    }
}

impl RetentionPurgeRepository for Repository {
    fn execute_retention_purge(
        &mut self,
        plan: &RetentionPurgePlan,
    ) -> Result<RetentionPurgeResult, ApplicationError> {
        self.executed_plan = Some(plan.clone());
        Ok(RetentionPurgeResult {
            memories: 2,
            ..RetentionPurgeResult::default()
        })
    }
}

#[test]
fn purge_derives_bounded_resource_cutoffs_and_never_targets_audit() {
    let mut repository = Repository::new();
    let now = 40_000_000;
    let result = RetentionService::new(&mut repository)
        .execute_purge(ExecuteRetentionPurgeCommand {
            workspace_id: WorkspaceId::new("team"),
            executed_by: PrincipalId::new("owner"),
            now_epoch_seconds: now,
            maximum_items: 25,
        })
        .expect("owner should execute purge");

    assert_eq!(result.total(), 2);
    let plan = repository.executed_plan.expect("plan should execute");
    assert_eq!(plan.maximum_items, 25);
    assert_eq!(plan.memory_cutoff_epoch_seconds, Some(now - 30 * 86_400));
    assert_eq!(
        plan.disclosure_cutoff_epoch_seconds,
        Some(now - 90 * 86_400)
    );
}

#[test]
fn active_legal_hold_prevents_repository_purge() {
    let mut repository = Repository::new();
    repository.holds.push(
        WorkspaceLegalHold::active(
            LegalHoldId::new("hold-01"),
            WorkspaceId::new("team"),
            PrincipalId::new("owner"),
            100,
        )
        .expect("hold"),
    );
    let error = RetentionService::new(&mut repository)
        .execute_purge(ExecuteRetentionPurgeCommand {
            workspace_id: WorkspaceId::new("team"),
            executed_by: PrincipalId::new("owner"),
            now_epoch_seconds: 40_000_000,
            maximum_items: 25,
        })
        .expect_err("active hold must block purge");

    assert_eq!(error, ApplicationError::AccessDenied);
    assert!(repository.executed_plan.is_none());
}

use rembrane_application::{
    AdministrativeAuditRepository, MembershipRepository, PlaceLegalHoldCommand,
    ReleaseLegalHoldCommand, RetentionRepository, RetentionService, SetRetentionPolicyCommand,
    WorkspaceRepository,
};
use rembrane_domain::{
    AdministrativeAction, LegalHoldId, LegalHoldStatus, Membership, Principal, PrincipalId,
    RetentionPeriod, Workspace, WorkspaceId, WorkspaceRetentionPolicy, WorkspaceRole,
};
use rembrane_store_memory::InMemoryStore;

fn store() -> InMemoryStore {
    let mut store = InMemoryStore::new();
    store
        .initialize_personal_workspace(
            Principal::new(PrincipalId::new("owner")),
            Workspace::personal(WorkspaceId::new("owner-personal")),
            Membership::new(
                WorkspaceId::new("owner-personal"),
                PrincipalId::new("owner"),
                WorkspaceRole::Owner,
            ),
        )
        .expect("owner should initialize");
    store
        .initialize_shared_workspace(
            Workspace::shared(WorkspaceId::new("team")),
            Membership::new(
                WorkspaceId::new("team"),
                PrincipalId::new("owner"),
                WorkspaceRole::Owner,
            ),
        )
        .expect("team should initialize");
    store
        .insert_membership(Membership::new(
            WorkspaceId::new("team"),
            PrincipalId::new("member"),
            WorkspaceRole::Member,
        ))
        .expect("member should initialize");
    store
}

fn policy(version: u64) -> WorkspaceRetentionPolicy {
    WorkspaceRetentionPolicy::new(
        WorkspaceId::new("team"),
        version,
        RetentionPeriod::days(30).expect("memory"),
        RetentionPeriod::days(7).expect("checkpoint"),
        RetentionPeriod::days(14).expect("travel"),
        RetentionPeriod::days(90).expect("disclosure"),
        RetentionPeriod::days(365).expect("events"),
        RetentionPeriod::days(365).expect("audit"),
    )
    .expect("policy")
}

#[test]
fn owner_manages_retention_and_legal_holds_with_atomic_audit() {
    let mut store = store();
    RetentionService::new(&mut store)
        .set_policy(SetRetentionPolicyCommand {
            policy: policy(1),
            expected_version: None,
            changed_by: PrincipalId::new("owner"),
            request_id: "retention-01".to_owned(),
        })
        .expect("owner should set policy");
    let placed = RetentionService::new(&mut store)
        .place_legal_hold(PlaceLegalHoldCommand {
            workspace_id: WorkspaceId::new("team"),
            hold_id: LegalHoldId::new("hold-01"),
            placed_by: PrincipalId::new("owner"),
            request_id: "hold-place-01".to_owned(),
        })
        .expect("owner should place hold");
    let released = RetentionService::new(&mut store)
        .release_legal_hold(ReleaseLegalHoldCommand {
            workspace_id: WorkspaceId::new("team"),
            hold_id: placed.id().clone(),
            released_by: PrincipalId::new("owner"),
            request_id: "hold-release-01".to_owned(),
        })
        .expect("owner should release hold");

    assert_eq!(released.status(), LegalHoldStatus::Released);
    assert_eq!(
        store
            .find_retention_policy(&WorkspaceId::new("team"))
            .expect("policy lookup")
            .expect("policy")
            .version(),
        1
    );
    let audit = store
        .list_administrative_audit(&WorkspaceId::new("team"), 0, 10)
        .expect("audit lookup");
    assert_eq!(
        audit
            .iter()
            .map(rembrane_domain::AdministrativeAuditEvent::action)
            .collect::<Vec<_>>(),
        vec![
            AdministrativeAction::RetentionPolicyChanged,
            AdministrativeAction::LegalHoldPlaced,
            AdministrativeAction::LegalHoldReleased,
        ]
    );
}

#[test]
fn ordinary_member_cannot_change_retention() {
    let mut store = store();
    let error = RetentionService::new(&mut store)
        .set_policy(SetRetentionPolicyCommand {
            policy: policy(1),
            expected_version: None,
            changed_by: PrincipalId::new("member"),
            request_id: "unauthorized-retention".to_owned(),
        })
        .expect_err("member must not set retention");

    assert_eq!(error, rembrane_application::ApplicationError::AccessDenied);
    assert!(
        store
            .find_retention_policy(&WorkspaceId::new("team"))
            .expect("policy lookup")
            .is_none()
    );
}

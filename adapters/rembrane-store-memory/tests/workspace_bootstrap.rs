use rembrane_application::{
    ApplicationError, MembershipRepository, WorkspaceRepository,
};
use rembrane_domain::{
    Membership, Principal, PrincipalId, Workspace, WorkspaceId, WorkspaceRole,
};
use rembrane_store_memory::InMemoryStore;

#[test]
fn atomically_initializes_personal_workspace_owner() {
    let principal_id = PrincipalId::new("principal_01");
    let workspace_id = WorkspaceId::new("workspace_01");
    let mut store = InMemoryStore::new();

    store
        .initialize_personal_workspace(
            Principal::new(principal_id.clone()),
            Workspace::personal(workspace_id.clone()),
            Membership::new(
                workspace_id.clone(),
                principal_id.clone(),
                WorkspaceRole::Owner,
            ),
        )
        .expect("valid bootstrap succeeds");

    assert!(
        store
            .find_principal(&principal_id)
            .expect("lookup succeeds")
            .is_some()
    );
    assert!(
        store
            .find_workspace(&workspace_id)
            .expect("lookup succeeds")
            .is_some()
    );
    assert!(
        store
            .find_membership(&workspace_id, &principal_id)
            .expect("lookup succeeds")
            .is_some()
    );
}

#[test]
fn rejects_mismatched_bootstrap_without_partial_records() {
    let principal_id = PrincipalId::new("principal_01");
    let workspace_id = WorkspaceId::new("workspace_01");
    let mut store = InMemoryStore::new();

    let error = store
        .initialize_personal_workspace(
            Principal::new(principal_id.clone()),
            Workspace::personal(workspace_id.clone()),
            Membership::new(
                WorkspaceId::new("workspace_other"),
                principal_id.clone(),
                WorkspaceRole::Owner,
            ),
        )
        .expect_err("mismatched membership must fail");

    assert!(matches!(error, ApplicationError::Validation(_)));
    assert!(
        store
            .find_principal(&principal_id)
            .expect("lookup succeeds")
            .is_none()
    );
    assert!(
        store
            .find_workspace(&workspace_id)
            .expect("lookup succeeds")
            .is_none()
    );
}

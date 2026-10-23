use rembrane_application::{
    ApplicationError, MembershipRepository, WorkspaceRepository,
};
use rembrane_domain::{
    Membership, Principal, PrincipalId, Workspace, WorkspaceId, WorkspaceRole,
};
use rembrane_store_sqlite::SqliteStore;

#[test]
fn persists_personal_workspace_bootstrap() {
    let principal_id = PrincipalId::new("principal_01");
    let workspace_id = WorkspaceId::new("workspace_01");
    let mut store = SqliteStore::open_in_memory().expect("database opens");

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
        .expect("bootstrap succeeds");

    assert!(store
        .find_principal(&principal_id)
        .expect("lookup succeeds")
        .is_some());
    assert!(store
        .find_workspace(&workspace_id)
        .expect("lookup succeeds")
        .is_some());
    assert!(store
        .find_membership(&workspace_id, &principal_id)
        .expect("lookup succeeds")
        .is_some());
}

#[test]
fn duplicate_bootstrap_does_not_create_partial_workspace() {
    let principal_id = PrincipalId::new("principal_01");
    let first_workspace_id = WorkspaceId::new("workspace_01");
    let second_workspace_id = WorkspaceId::new("workspace_02");
    let mut store = SqliteStore::open_in_memory().expect("database opens");

    store
        .initialize_personal_workspace(
            Principal::new(principal_id.clone()),
            Workspace::personal(first_workspace_id.clone()),
            Membership::new(
                first_workspace_id,
                principal_id.clone(),
                WorkspaceRole::Owner,
            ),
        )
        .expect("first bootstrap succeeds");

    let error = store
        .initialize_personal_workspace(
            Principal::new(principal_id.clone()),
            Workspace::personal(second_workspace_id.clone()),
            Membership::new(
                second_workspace_id.clone(),
                principal_id,
                WorkspaceRole::Owner,
            ),
        )
        .expect_err("duplicate principal must fail");

    assert_eq!(error, ApplicationError::AlreadyExists);
    assert!(store
        .find_workspace(&second_workspace_id)
        .expect("lookup succeeds")
        .is_none());
}

#[test]
fn membership_lookup_is_tenant_scoped() {
    let principal_id = PrincipalId::new("principal_01");
    let workspace_id = WorkspaceId::new("workspace_01");
    let mut store = SqliteStore::open_in_memory().expect("database opens");

    store
        .initialize_personal_workspace(
            Principal::new(principal_id.clone()),
            Workspace::personal(workspace_id.clone()),
            Membership::new(
                workspace_id,
                principal_id.clone(),
                WorkspaceRole::Owner,
            ),
        )
        .expect("bootstrap succeeds");

    assert!(store
        .find_membership(&WorkspaceId::new("workspace_other"), &principal_id)
        .expect("lookup succeeds")
        .is_none());
}

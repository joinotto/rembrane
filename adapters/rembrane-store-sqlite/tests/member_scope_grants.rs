use rembrane_application::{
    AuthorizeClientCommand, AuthorizeClientService, GrantMemberScopeCommand,
    MemberScopeGrantRepository, MemberScopeGrantService, MembershipRepository, WorkspaceRepository,
};
use rembrane_domain::{
    ClientId, EntityId, Membership, Principal, PrincipalId, ReadScope, Workspace, WorkspaceId,
    WorkspaceRole, WritePermission,
};
use rembrane_store_sqlite::SqliteStore;

fn initialized_store() -> SqliteStore {
    let mut store = SqliteStore::open_in_memory().expect("database should open");
    for principal in ["owner", "member"] {
        store
            .initialize_personal_workspace(
                Principal::new(PrincipalId::new(principal)),
                Workspace::personal(WorkspaceId::new(format!("{principal}-personal"))),
                Membership::new(
                    WorkspaceId::new(format!("{principal}-personal")),
                    PrincipalId::new(principal),
                    WorkspaceRole::Owner,
                ),
            )
            .expect("principal should initialize");
    }
    store
        .initialize_shared_workspace(
            Workspace::shared(WorkspaceId::new("team")),
            Membership::new(
                WorkspaceId::new("team"),
                PrincipalId::new("owner"),
                WorkspaceRole::Owner,
            ),
        )
        .expect("shared workspace should initialize");
    store
        .insert_membership(Membership::new(
            WorkspaceId::new("team"),
            PrincipalId::new("member"),
            WorkspaceRole::Member,
        ))
        .expect("member should initialize");
    store
}

#[test]
fn persisted_scope_filters_member_client_authorization() {
    let mut store = initialized_store();
    let allowed = ReadScope::Entity {
        id: EntityId::new("project_allowed"),
    };
    MemberScopeGrantService::new(&mut store)
        .grant(GrantMemberScopeCommand {
            workspace_id: WorkspaceId::new("team"),
            principal_id: PrincipalId::new("member"),
            granted_by: PrincipalId::new("owner"),
            scope: allowed.clone(),
        })
        .expect("owner should grant entity access");

    let grants = AuthorizeClientService::new(&store)
        .execute(AuthorizeClientCommand {
            client_id: ClientId::new("assistant"),
            workspace_id: WorkspaceId::new("team"),
            principal_id: PrincipalId::new("member"),
            requested_read_scopes: vec![
                allowed.clone(),
                ReadScope::Entity {
                    id: EntityId::new("project_denied"),
                },
            ],
            requested_write_permissions: vec![WritePermission::ProposeMemory],
        })
        .expect("member should authorize");

    assert_eq!(grants.read.scopes, vec![allowed.clone()]);
    assert_eq!(grants.write.scopes, vec![allowed]);
}

#[test]
fn grant_lookup_is_workspace_and_principal_scoped() {
    let mut store = initialized_store();
    MemberScopeGrantService::new(&mut store)
        .grant(GrantMemberScopeCommand {
            workspace_id: WorkspaceId::new("team"),
            principal_id: PrincipalId::new("member"),
            granted_by: PrincipalId::new("owner"),
            scope: ReadScope::Entity {
                id: EntityId::new("project"),
            },
        })
        .expect("owner should grant entity access");

    assert_eq!(
        store
            .list_member_scope_grants(&WorkspaceId::new("other"), &PrincipalId::new("member"))
            .expect("cross-workspace lookup should succeed"),
        Vec::new()
    );
    assert_eq!(
        store
            .list_member_scope_grants(&WorkspaceId::new("team"), &PrincipalId::new("owner"))
            .expect("cross-principal lookup should succeed"),
        Vec::new()
    );
}

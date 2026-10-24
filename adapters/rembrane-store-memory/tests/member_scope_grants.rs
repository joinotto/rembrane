use rembrane_application::{
    ApplicationError, AuthorizeClientCommand, AuthorizeClientService, GrantMemberScopeCommand,
    MemberLifecycleService, MemberScopeGrantRepository, MemberScopeGrantService,
    MembershipRepository, RemoveMemberCommand, WorkspaceRepository,
};
use rembrane_domain::{
    ClientId, EntityId, Membership, Principal, PrincipalId, ReadScope, Workspace, WorkspaceId,
    WorkspaceRole, WritePermission,
};
use rembrane_store_memory::InMemoryStore;

fn store_with_member() -> InMemoryStore {
    let mut store = InMemoryStore::new();
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
fn administrator_grant_limits_member_client_to_exact_entity() {
    let mut store = store_with_member();
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
        .expect("owner should grant entity scope");

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
fn ordinary_member_cannot_grant_scope() {
    let mut store = store_with_member();

    let error = MemberScopeGrantService::new(&mut store)
        .grant(GrantMemberScopeCommand {
            workspace_id: WorkspaceId::new("team"),
            principal_id: PrincipalId::new("member"),
            granted_by: PrincipalId::new("member"),
            scope: ReadScope::Entity {
                id: EntityId::new("project"),
            },
        })
        .expect_err("member must not grant its own scope");

    assert_eq!(error, ApplicationError::AccessDenied);
}

#[test]
fn owner_removal_revokes_membership_and_all_scope_grants() {
    let mut store = store_with_member();
    MemberScopeGrantService::new(&mut store)
        .grant(GrantMemberScopeCommand {
            workspace_id: WorkspaceId::new("team"),
            principal_id: PrincipalId::new("member"),
            granted_by: PrincipalId::new("owner"),
            scope: ReadScope::Entity {
                id: EntityId::new("project"),
            },
        })
        .expect("scope should be granted");

    MemberLifecycleService::new(&mut store)
        .remove(RemoveMemberCommand {
            workspace_id: WorkspaceId::new("team"),
            principal_id: PrincipalId::new("member"),
            removed_by: PrincipalId::new("owner"),
        })
        .expect("owner should remove member");

    assert!(
        !store
            .find_membership(&WorkspaceId::new("team"), &PrincipalId::new("member"))
            .expect("membership lookup should succeed")
            .expect("removed membership remains auditable")
            .is_active()
    );
    assert_eq!(
        store
            .list_member_scope_grants(&WorkspaceId::new("team"), &PrincipalId::new("member"))
            .expect("scope lookup should succeed"),
        Vec::new()
    );
    let error = AuthorizeClientService::new(&store)
        .execute(AuthorizeClientCommand {
            client_id: ClientId::new("assistant"),
            workspace_id: WorkspaceId::new("team"),
            principal_id: PrincipalId::new("member"),
            requested_read_scopes: vec![ReadScope::Entity {
                id: EntityId::new("project"),
            }],
            requested_write_permissions: vec![WritePermission::ProposeMemory],
        })
        .expect_err("removed member must not authorize");
    assert_eq!(error, ApplicationError::AccessDenied);
}

#[test]
fn owner_membership_cannot_be_removed() {
    let mut store = store_with_member();

    let error = MemberLifecycleService::new(&mut store)
        .remove(RemoveMemberCommand {
            workspace_id: WorkspaceId::new("team"),
            principal_id: PrincipalId::new("owner"),
            removed_by: PrincipalId::new("owner"),
        })
        .expect_err("ownership requires an explicit transfer");

    assert_eq!(error, ApplicationError::AccessDenied);
}

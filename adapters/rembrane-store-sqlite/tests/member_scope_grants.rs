use rembrane_application::{
    AuthorizeClientCommand, AuthorizeClientService, CompleteKeyRotationCommand,
    GrantMemberScopeCommand, KeyRotationRepository, MemberLifecycleService,
    MemberScopeGrantRepository, MemberScopeGrantService, MembershipRepository, RemoveMemberCommand,
    RevokeMemberScopeCommand, WorkspaceRepository,
};
use rembrane_domain::{
    ClientId, EntityId, KeyRotationReceipt, KeyRotationStatus, Membership, Principal, PrincipalId,
    ProviderId, ReadScope, Workspace, WorkspaceId, WorkspaceRole, WritePermission,
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
            request_id: "sqlite-grant-allowed".to_owned(),
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
            requested_read_permissions: Vec::new(),
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
            request_id: "sqlite-grant-project".to_owned(),
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

#[test]
fn persisted_member_removal_deletes_grants_and_denies_authorization() {
    let mut store = initialized_store();
    MemberScopeGrantService::new(&mut store)
        .grant(GrantMemberScopeCommand {
            workspace_id: WorkspaceId::new("team"),
            principal_id: PrincipalId::new("member"),
            granted_by: PrincipalId::new("owner"),
            scope: ReadScope::Entity {
                id: EntityId::new("project"),
            },
            request_id: "sqlite-grant-before-removal".to_owned(),
        })
        .expect("scope should be granted");

    MemberLifecycleService::new(&mut store)
        .remove(RemoveMemberCommand {
            workspace_id: WorkspaceId::new("team"),
            principal_id: PrincipalId::new("member"),
            removed_by: PrincipalId::new("owner"),
            rotation_id: rembrane_domain::KeyRotationId::new("rotation_01"),
        })
        .expect("owner should remove member");

    assert_eq!(
        store
            .list_member_scope_grants(&WorkspaceId::new("team"), &PrincipalId::new("member"))
            .expect("scope lookup should succeed"),
        Vec::new()
    );
    let rotation = store
        .latest_key_rotation(&WorkspaceId::new("team"))
        .expect("rotation lookup should succeed")
        .expect("member removal must require rotation");
    assert_eq!(rotation.generation(), 1);
    assert_eq!(rotation.removed_principal_id().as_str(), "member");
    assert_eq!(rotation.requested_by().as_str(), "owner");
    let completed = MemberLifecycleService::new(&mut store)
        .complete_key_rotation(CompleteKeyRotationCommand {
            receipt: KeyRotationReceipt::new(
                ProviderId::new("customer.kms"),
                "rotation-request-01",
                WorkspaceId::new("team"),
                1,
                "workspace-key:v2",
                vec![PrincipalId::new("owner")],
            )
            .expect("receipt"),
            completed_by: PrincipalId::new("owner"),
        })
        .expect("owner should complete exact pending generation");
    assert_eq!(completed.status(), KeyRotationStatus::Completed);
    let persisted = store
        .latest_key_rotation(&WorkspaceId::new("team"))
        .expect("rotation lookup should succeed")
        .expect("completed rotation remains auditable");
    assert_eq!(persisted.status(), KeyRotationStatus::Completed);
    assert_eq!(persisted.completed_key_id(), Some("workspace-key:v2"));
    let receipt = store
        .find_key_rotation_receipt(
            &WorkspaceId::new("team"),
            &rembrane_domain::KeyRotationId::new("rotation_01"),
        )
        .expect("receipt lookup")
        .expect("validated receipt remains auditable");
    assert_eq!(receipt.provider_id().as_str(), "customer.kms");
    assert_eq!(receipt.request_id(), "rotation-request-01");
    assert_eq!(receipt.recipient_ids(), &[PrincipalId::new("owner")]);
    let error = AuthorizeClientService::new(&store)
        .execute(AuthorizeClientCommand {
            client_id: ClientId::new("assistant"),
            workspace_id: WorkspaceId::new("team"),
            principal_id: PrincipalId::new("member"),
            requested_read_scopes: vec![ReadScope::Entity {
                id: EntityId::new("project"),
            }],
            requested_read_permissions: Vec::new(),
            requested_write_permissions: Vec::new(),
        })
        .expect_err("removed member must not authorize");
    assert_eq!(error, rembrane_application::ApplicationError::AccessDenied);
}

#[test]
fn persisted_scope_revocation_immediately_filters_authorization() {
    let mut store = initialized_store();
    let scope = ReadScope::Entity {
        id: EntityId::new("project"),
    };
    MemberScopeGrantService::new(&mut store)
        .grant(GrantMemberScopeCommand {
            workspace_id: WorkspaceId::new("team"),
            principal_id: PrincipalId::new("member"),
            granted_by: PrincipalId::new("owner"),
            scope: scope.clone(),
            request_id: "sqlite-grant-before-revoke".to_owned(),
        })
        .expect("scope should be granted");
    MemberScopeGrantService::new(&mut store)
        .revoke(RevokeMemberScopeCommand {
            workspace_id: WorkspaceId::new("team"),
            principal_id: PrincipalId::new("member"),
            revoked_by: PrincipalId::new("owner"),
            scope: scope.clone(),
            request_id: "sqlite-revoke-scope".to_owned(),
        })
        .expect("scope should be revoked");

    let grants = AuthorizeClientService::new(&store)
        .execute(AuthorizeClientCommand {
            client_id: ClientId::new("assistant"),
            workspace_id: WorkspaceId::new("team"),
            principal_id: PrincipalId::new("member"),
            requested_read_scopes: vec![scope],
            requested_read_permissions: Vec::new(),
            requested_write_permissions: vec![WritePermission::ProposeMemory],
        })
        .expect("active member should still authorize");
    assert_eq!(grants.read.scopes, Vec::<ReadScope>::new());
    assert_eq!(grants.write.scopes, Vec::<ReadScope>::new());
}

use rembrane_application::{
    ApplicationError, CreateInvitationCommand, InvitationRepository, InvitationService,
    MembershipRepository, WorkspaceRepository,
};
use rembrane_domain::{
    InvitationId, Membership, Principal, PrincipalId, Workspace, WorkspaceId, WorkspaceRole,
};
use rembrane_store_memory::InMemoryStore;

fn shared_store() -> InMemoryStore {
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
        .expect("owner identity should initialize");
    store
        .initialize_personal_workspace(
            Principal::new(PrincipalId::new("guest")),
            Workspace::personal(WorkspaceId::new("guest-personal")),
            Membership::new(
                WorkspaceId::new("guest-personal"),
                PrincipalId::new("guest"),
                WorkspaceRole::Owner,
            ),
        )
        .expect("guest identity should initialize");
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
}

fn command(invited_principal_id: &str) -> CreateInvitationCommand {
    CreateInvitationCommand {
        invitation_id: InvitationId::new("invite_01"),
        workspace_id: WorkspaceId::new("team"),
        invited_principal_id: PrincipalId::new(invited_principal_id),
        invited_by: PrincipalId::new("owner"),
        role: WorkspaceRole::Member,
    }
}

#[test]
fn invited_principal_accepts_membership_atomically() {
    let mut store = shared_store();
    let invitation = InvitationService::new(&mut store)
        .create(command("guest"))
        .expect("owner should invite member");
    let membership = InvitationService::new(&mut store)
        .accept(
            &WorkspaceId::new("team"),
            invitation.id(),
            &PrincipalId::new("guest"),
        )
        .expect("invited principal should accept");

    assert_eq!(membership.role(), WorkspaceRole::Member);
    assert!(
        store
            .find_membership(&WorkspaceId::new("team"), &PrincipalId::new("guest"))
            .expect("membership lookup should succeed")
            .is_some()
    );
}

#[test]
fn another_principal_cannot_enumerate_or_accept_invitation() {
    let mut store = shared_store();
    let invitation = InvitationService::new(&mut store)
        .create(command("guest"))
        .expect("owner should invite member");

    let error = InvitationService::new(&mut store)
        .accept(
            &WorkspaceId::new("team"),
            invitation.id(),
            &PrincipalId::new("attacker"),
        )
        .expect_err("other principal must be denied");

    assert_eq!(error, ApplicationError::NotFound);
}

#[test]
fn member_cannot_invite_another_principal() {
    let mut store = shared_store();
    store
        .insert_membership(Membership::new(
            WorkspaceId::new("team"),
            PrincipalId::new("member"),
            WorkspaceRole::Member,
        ))
        .expect("member setup should succeed");
    let mut attempted = command("guest");
    attempted.invited_by = PrincipalId::new("member");

    let error = InvitationService::new(&mut store)
        .create(attempted)
        .expect_err("member must not manage membership");

    assert_eq!(error, ApplicationError::AccessDenied);
}

#[test]
fn invitation_lookup_is_workspace_scoped() {
    let mut store = shared_store();
    let invitation = InvitationService::new(&mut store)
        .create(command("guest"))
        .expect("owner should invite member");

    assert!(
        store
            .find_invitation(&WorkspaceId::new("other"), invitation.id())
            .expect("lookup should succeed")
            .is_none()
    );
}

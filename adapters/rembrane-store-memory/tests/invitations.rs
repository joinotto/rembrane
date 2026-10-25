use rembrane_application::{
    ApplicationError, CreateInvitationCommand, InvitationRepository, InvitationService,
    MembershipRepository, RevokeInvitationCommand, WorkspaceRepository,
};
use rembrane_domain::{
    InvitationId, InvitationStatus, Membership, Principal, PrincipalId, Workspace, WorkspaceId,
    WorkspaceRole,
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
        created_at_epoch_seconds: 1_000,
        expires_at_epoch_seconds: 2_000,
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
            1_500,
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
            1_500,
        )
        .expect_err("other principal must be denied");

    assert_eq!(error, ApplicationError::NotFound);
}

#[test]
fn expired_invitation_cannot_create_membership() {
    let mut store = shared_store();
    let invitation = InvitationService::new(&mut store)
        .create(command("guest"))
        .expect("owner should invite member");

    let error = InvitationService::new(&mut store)
        .accept(
            &WorkspaceId::new("team"),
            invitation.id(),
            &PrincipalId::new("guest"),
            2_000,
        )
        .expect_err("expired invitation must fail");

    assert_eq!(
        error,
        ApplicationError::Validation("invitation has expired".to_owned())
    );
    assert!(
        store
            .find_membership(&WorkspaceId::new("team"), &PrincipalId::new("guest"))
            .expect("membership lookup")
            .is_none()
    );
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

#[test]
fn owner_can_revoke_pending_invitation() {
    let mut store = shared_store();
    let invitation = InvitationService::new(&mut store)
        .create(command("guest"))
        .expect("owner should invite member");

    let revoked = InvitationService::new(&mut store)
        .revoke(RevokeInvitationCommand {
            invitation_id: invitation.id().clone(),
            workspace_id: WorkspaceId::new("team"),
            revoked_by: PrincipalId::new("owner"),
        })
        .expect("owner should revoke pending invitation");

    assert_eq!(revoked.status(), InvitationStatus::Revoked);
    let error = InvitationService::new(&mut store)
        .accept(
            &WorkspaceId::new("team"),
            invitation.id(),
            &PrincipalId::new("guest"),
            1_500,
        )
        .expect_err("revoked invitation must not be accepted");
    assert_eq!(
        error,
        ApplicationError::Validation("invitation is no longer pending".to_owned())
    );
}

#[test]
fn member_cannot_revoke_invitation() {
    let mut store = shared_store();
    let invitation = InvitationService::new(&mut store)
        .create(command("guest"))
        .expect("owner should invite member");
    store
        .insert_membership(Membership::new(
            WorkspaceId::new("team"),
            PrincipalId::new("member"),
            WorkspaceRole::Member,
        ))
        .expect("member setup should succeed");

    let error = InvitationService::new(&mut store)
        .revoke(RevokeInvitationCommand {
            invitation_id: invitation.id().clone(),
            workspace_id: WorkspaceId::new("team"),
            revoked_by: PrincipalId::new("member"),
        })
        .expect_err("member must not revoke invitations");

    assert_eq!(error, ApplicationError::AccessDenied);
}

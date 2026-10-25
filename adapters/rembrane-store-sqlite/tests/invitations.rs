use rembrane_application::{
    ApplicationError, CreateInvitationCommand, InvitationRepository, InvitationService,
    MembershipRepository, RevokeInvitationCommand, WorkspaceRepository,
};
use rembrane_domain::{
    InvitationId, InvitationStatus, Membership, Principal, PrincipalId, Workspace, WorkspaceId,
    WorkspaceRole,
};
use rembrane_store_sqlite::SqliteStore;

fn initialized_store() -> SqliteStore {
    let mut store = SqliteStore::open_in_memory().expect("database should open");
    for principal in ["owner", "guest", "attacker"] {
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
}

fn invitation_command() -> CreateInvitationCommand {
    CreateInvitationCommand {
        invitation_id: InvitationId::new("invite_01"),
        workspace_id: WorkspaceId::new("team"),
        invited_principal_id: PrincipalId::new("guest"),
        invited_by: PrincipalId::new("owner"),
        role: WorkspaceRole::Member,
        created_at_epoch_seconds: 1_000,
        expires_at_epoch_seconds: 2_000,
    }
}

#[test]
fn persists_and_atomically_accepts_invitation() {
    let mut store = initialized_store();
    let invitation = InvitationService::new(&mut store)
        .create(invitation_command())
        .expect("owner should create invitation");

    let membership = InvitationService::new(&mut store)
        .accept(
            &WorkspaceId::new("team"),
            invitation.id(),
            &PrincipalId::new("guest"),
            1_500,
        )
        .expect("guest should accept invitation");

    assert_eq!(membership.role(), WorkspaceRole::Member);
    assert!(
        store
            .find_membership(&WorkspaceId::new("team"), &PrincipalId::new("guest"))
            .expect("membership lookup should succeed")
            .is_some()
    );
    let accepted = store
        .find_invitation(&WorkspaceId::new("team"), invitation.id())
        .expect("invitation lookup should succeed")
        .expect("invitation should remain auditable");
    assert_eq!(
        accepted.status(),
        rembrane_domain::InvitationStatus::Accepted
    );
}

#[test]
fn invitation_lookup_and_acceptance_do_not_cross_workspace_or_principal() {
    let mut store = initialized_store();
    let invitation = InvitationService::new(&mut store)
        .create(invitation_command())
        .expect("owner should create invitation");

    assert!(
        store
            .find_invitation(&WorkspaceId::new("other"), invitation.id())
            .expect("cross-workspace lookup should be safe")
            .is_none()
    );
    let error = InvitationService::new(&mut store)
        .accept(
            &WorkspaceId::new("team"),
            invitation.id(),
            &PrincipalId::new("attacker"),
            1_500,
        )
        .expect_err("another principal must not accept");
    assert_eq!(error, ApplicationError::NotFound);
    assert!(
        store
            .find_membership(&WorkspaceId::new("team"), &PrincipalId::new("guest"))
            .expect("membership lookup should succeed")
            .is_none()
    );
}

#[test]
fn persisted_expired_invitation_cannot_create_membership() {
    let mut store = initialized_store();
    let invitation = InvitationService::new(&mut store)
        .create(invitation_command())
        .expect("owner should create invitation");

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
fn second_acceptance_does_not_mutate_membership() {
    let mut store = initialized_store();
    let invitation = InvitationService::new(&mut store)
        .create(invitation_command())
        .expect("owner should create invitation");
    InvitationService::new(&mut store)
        .accept(
            &WorkspaceId::new("team"),
            invitation.id(),
            &PrincipalId::new("guest"),
            1_500,
        )
        .expect("first acceptance should succeed");

    let error = InvitationService::new(&mut store)
        .accept(
            &WorkspaceId::new("team"),
            invitation.id(),
            &PrincipalId::new("guest"),
            1_500,
        )
        .expect_err("accepted invitation must not be reusable");
    assert_eq!(
        error,
        ApplicationError::Validation("invitation is no longer pending".to_owned())
    );
}

#[test]
fn persisted_revocation_prevents_acceptance() {
    let mut store = initialized_store();
    let invitation = InvitationService::new(&mut store)
        .create(invitation_command())
        .expect("owner should create invitation");

    let revoked = InvitationService::new(&mut store)
        .revoke(RevokeInvitationCommand {
            invitation_id: invitation.id().clone(),
            workspace_id: WorkspaceId::new("team"),
            revoked_by: PrincipalId::new("owner"),
        })
        .expect("owner should revoke invitation");
    assert_eq!(revoked.status(), InvitationStatus::Revoked);

    let error = InvitationService::new(&mut store)
        .accept(
            &WorkspaceId::new("team"),
            invitation.id(),
            &PrincipalId::new("guest"),
            1_500,
        )
        .expect_err("revoked invitation cannot be accepted");
    assert_eq!(
        error,
        ApplicationError::Validation("invitation is no longer pending".to_owned())
    );
    assert!(
        store
            .find_membership(&WorkspaceId::new("team"), &PrincipalId::new("guest"))
            .expect("membership lookup should succeed")
            .is_none()
    );
}

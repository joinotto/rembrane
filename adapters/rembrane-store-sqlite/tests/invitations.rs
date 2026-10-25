use rembrane_application::{
    AcceptInvitationCommand, AdministrativeAuditRepository, ApplicationError,
    CreateInvitationCommand, InvitationRepository, InvitationService, ListInvitationsQuery,
    MembershipRepository, RevokeInvitationCommand, WorkspaceRepository,
};
use rembrane_domain::{
    AdministrativeAction, Invitation, InvitationId, InvitationStatus, Membership, Principal,
    PrincipalId, Workspace, WorkspaceId, WorkspaceRole,
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
        request_id: "request-create-01".to_owned(),
        created_at_epoch_seconds: 1_000,
        expires_at_epoch_seconds: 2_000,
    }
}

fn accept_command(
    invitation_id: &InvitationId,
    principal_id: &str,
    accepted_at_epoch_seconds: u64,
) -> AcceptInvitationCommand {
    AcceptInvitationCommand {
        invitation_id: invitation_id.clone(),
        workspace_id: WorkspaceId::new("team"),
        accepting_principal_id: PrincipalId::new(principal_id),
        request_id: format!("request-accept-{principal_id}"),
        accepted_at_epoch_seconds,
    }
}

#[test]
fn persists_and_atomically_accepts_invitation() {
    let mut store = initialized_store();
    let invitation = InvitationService::new(&mut store)
        .create(invitation_command())
        .expect("owner should create invitation");

    let membership = InvitationService::new(&mut store)
        .accept(accept_command(invitation.id(), "guest", 1_500))
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
fn invitation_creation_rejects_unknown_principal_at_repository_boundary() {
    let mut store = initialized_store();
    let mut command = invitation_command();
    command.invited_principal_id = PrincipalId::new("principal_unknown");
    assert_eq!(
        InvitationService::new(&mut store).create(command),
        Err(ApplicationError::NotFound)
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
        .accept(accept_command(invitation.id(), "attacker", 1_500))
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
        .accept(accept_command(invitation.id(), "guest", 2_000))
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
fn persisted_invitation_listing_is_bounded_filtered_ordered_and_admin_only() {
    let mut store = initialized_store();
    let first = InvitationService::new(&mut store)
        .create(invitation_command())
        .expect("first invitation");
    InvitationService::new(&mut store)
        .revoke(RevokeInvitationCommand {
            invitation_id: first.id().clone(),
            workspace_id: WorkspaceId::new("team"),
            revoked_by: PrincipalId::new("owner"),
            request_id: "request-revoke-list-01".to_owned(),
            revoked_at_epoch_seconds: 1_100,
        })
        .expect("first invitation should revoke");
    let mut second_command = invitation_command();
    second_command.invitation_id = InvitationId::new("invite_02");
    second_command.request_id = "request-create-list-02".to_owned();
    second_command.created_at_epoch_seconds = 1_200;
    second_command.expires_at_epoch_seconds = 2_200;
    let second = InvitationService::new(&mut store)
        .create(second_command)
        .expect("second invitation");

    let listed = InvitationService::new(&mut store)
        .list(&ListInvitationsQuery {
            workspace_id: WorkspaceId::new("team"),
            requested_by: PrincipalId::new("owner"),
            status: None,
            limit: 10,
        })
        .expect("owner should list invitations");
    assert_eq!(
        listed.iter().map(Invitation::id).collect::<Vec<_>>(),
        [second.id(), first.id()]
    );
    let pending = InvitationService::new(&mut store)
        .list(&ListInvitationsQuery {
            workspace_id: WorkspaceId::new("team"),
            requested_by: PrincipalId::new("owner"),
            status: Some(InvitationStatus::Pending),
            limit: 1,
        })
        .expect("status filter should be applied");
    assert_eq!(pending, [second.clone()]);

    InvitationService::new(&mut store)
        .accept(accept_command(second.id(), "guest", 1_500))
        .expect("guest should accept");
    assert_eq!(
        InvitationService::new(&mut store).list(&ListInvitationsQuery {
            workspace_id: WorkspaceId::new("team"),
            requested_by: PrincipalId::new("guest"),
            status: None,
            limit: 10,
        }),
        Err(ApplicationError::AccessDenied)
    );
    assert_eq!(
        InvitationService::new(&mut store).list(&ListInvitationsQuery {
            workspace_id: WorkspaceId::new("other"),
            requested_by: PrincipalId::new("owner"),
            status: None,
            limit: 10,
        }),
        Err(ApplicationError::AccessDenied)
    );
    assert!(matches!(
        InvitationService::new(&mut store).list(&ListInvitationsQuery {
            workspace_id: WorkspaceId::new("team"),
            requested_by: PrincipalId::new("owner"),
            status: None,
            limit: 0,
        }),
        Err(ApplicationError::Validation(_))
    ));
}

#[test]
fn persisted_reinvitation_atomically_expires_previous_pending_record() {
    let mut store = initialized_store();
    let first = InvitationService::new(&mut store)
        .create(invitation_command())
        .expect("first invitation");
    let mut second_command = invitation_command();
    second_command.invitation_id = InvitationId::new("invite_02");
    second_command.request_id = "request-create-02".to_owned();
    second_command.created_at_epoch_seconds = 2_000;
    second_command.expires_at_epoch_seconds = 3_000;

    let second = InvitationService::new(&mut store)
        .create(second_command)
        .expect("expired invitation should release uniqueness slot");

    assert_eq!(
        store
            .find_invitation(&WorkspaceId::new("team"), first.id())
            .expect("lookup")
            .expect("first invitation")
            .status(),
        InvitationStatus::Expired
    );
    assert_eq!(second.status(), InvitationStatus::Pending);
}

#[test]
fn failed_persisted_reinvitation_rolls_back_expiration() {
    let mut store = initialized_store();
    let first = InvitationService::new(&mut store)
        .create(invitation_command())
        .expect("first invitation");
    let mut duplicate = invitation_command();
    duplicate.created_at_epoch_seconds = 2_000;
    duplicate.expires_at_epoch_seconds = 3_000;

    assert_eq!(
        InvitationService::new(&mut store).create(duplicate),
        Err(ApplicationError::AlreadyExists)
    );
    assert_eq!(
        store
            .find_invitation(&WorkspaceId::new("team"), first.id())
            .expect("lookup")
            .expect("first invitation")
            .status(),
        InvitationStatus::Pending
    );
}

#[test]
fn second_acceptance_does_not_mutate_membership() {
    let mut store = initialized_store();
    let invitation = InvitationService::new(&mut store)
        .create(invitation_command())
        .expect("owner should create invitation");
    InvitationService::new(&mut store)
        .accept(accept_command(invitation.id(), "guest", 1_500))
        .expect("first acceptance should succeed");

    let error = InvitationService::new(&mut store)
        .accept(accept_command(invitation.id(), "guest", 1_500))
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
            request_id: "request-revoke-01".to_owned(),
            revoked_at_epoch_seconds: 1_500,
        })
        .expect("owner should revoke invitation");
    assert_eq!(revoked.status(), InvitationStatus::Revoked);

    let error = InvitationService::new(&mut store)
        .accept(accept_command(invitation.id(), "guest", 1_500))
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

#[test]
fn persisted_invitation_lifecycle_commits_audit_with_membership() {
    let mut store = initialized_store();
    let invitation = InvitationService::new(&mut store)
        .create(invitation_command())
        .expect("create");
    InvitationService::new(&mut store)
        .accept(accept_command(invitation.id(), "guest", 1_500))
        .expect("accept");

    let events = store
        .list_administrative_audit(&WorkspaceId::new("team"), 0, 10)
        .expect("audit");
    assert_eq!(
        events
            .iter()
            .map(rembrane_domain::AdministrativeAuditEvent::action)
            .collect::<Vec<_>>(),
        vec![
            AdministrativeAction::InvitationCreated,
            AdministrativeAction::InvitationAccepted,
        ]
    );
}

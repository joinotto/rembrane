use rembrane_application::{
    AcceptInvitationCommand, AdministrativeAuditRepository, ApplicationError,
    CreateInvitationCommand, InvitationRepository, InvitationService, ListInvitationsQuery,
    MembershipRepository, RevokeInvitationCommand, WorkspaceRepository,
};
use rembrane_domain::{
    AdministrativeAction, Invitation, InvitationId, InvitationStatus, Membership, Principal,
    PrincipalId, Workspace, WorkspaceId, WorkspaceRole,
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
fn invited_principal_accepts_membership_atomically() {
    let mut store = shared_store();
    let invitation = InvitationService::new(&mut store)
        .create(command("guest"))
        .expect("owner should invite member");
    let membership = InvitationService::new(&mut store)
        .accept(accept_command(invitation.id(), "guest", 1_500))
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
        .accept(accept_command(invitation.id(), "attacker", 1_500))
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
fn invitation_listing_is_bounded_filtered_ordered_and_admin_only() {
    let mut store = shared_store();
    let first = InvitationService::new(&mut store)
        .create(command("guest"))
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
    let mut second_command = command("guest");
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
    assert_eq!(pending, std::slice::from_ref(&second));
    assert_eq!(
        InvitationService::new(&mut store).list(&ListInvitationsQuery {
            workspace_id: WorkspaceId::new("other"),
            requested_by: PrincipalId::new("owner"),
            status: None,
            limit: 10,
        }),
        Err(ApplicationError::AccessDenied)
    );

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
    assert!(matches!(
        InvitationService::new(&mut store).list(&ListInvitationsQuery {
            workspace_id: WorkspaceId::new("team"),
            requested_by: PrincipalId::new("owner"),
            status: None,
            limit: 101,
        }),
        Err(ApplicationError::Validation(_))
    ));
}

#[test]
fn reinvitation_atomically_expires_the_previous_pending_record() {
    let mut store = shared_store();
    let first = InvitationService::new(&mut store)
        .create(command("guest"))
        .expect("first invitation");
    let mut second_command = command("guest");
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
fn failed_reinvitation_does_not_expire_the_previous_record() {
    let mut store = shared_store();
    let first = InvitationService::new(&mut store)
        .create(command("guest"))
        .expect("first invitation");
    let mut duplicate = command("guest");
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
            request_id: "request-revoke-01".to_owned(),
            revoked_at_epoch_seconds: 1_500,
        })
        .expect("owner should revoke pending invitation");

    assert_eq!(revoked.status(), InvitationStatus::Revoked);
    let error = InvitationService::new(&mut store)
        .accept(accept_command(invitation.id(), "guest", 1_500))
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
            request_id: "request-revoke-member".to_owned(),
            revoked_at_epoch_seconds: 1_500,
        })
        .expect_err("member must not revoke invitations");

    assert_eq!(error, ApplicationError::AccessDenied);
}

#[test]
fn revocation_time_cannot_predate_invitation() {
    let mut store = shared_store();
    let invitation = InvitationService::new(&mut store)
        .create(command("guest"))
        .expect("owner should invite member");

    let error = InvitationService::new(&mut store)
        .revoke(RevokeInvitationCommand {
            invitation_id: invitation.id().clone(),
            workspace_id: WorkspaceId::new("team"),
            revoked_by: PrincipalId::new("owner"),
            request_id: "request-revoke-before-create".to_owned(),
            revoked_at_epoch_seconds: 999,
        })
        .expect_err("revocation time must be causal");

    assert_eq!(
        error,
        ApplicationError::Validation(
            "invitation revocation predates invitation creation".to_owned()
        )
    );
    assert_eq!(
        store
            .find_invitation(&WorkspaceId::new("team"), invitation.id())
            .expect("lookup")
            .expect("invitation")
            .status(),
        InvitationStatus::Pending
    );
}

#[test]
fn invitation_lifecycle_writes_content_free_audit_evidence_atomically() {
    let mut store = shared_store();
    let invitation = InvitationService::new(&mut store)
        .create(command("guest"))
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
    assert!(events.iter().all(|event| event.target_id() == "invite_01"));
}

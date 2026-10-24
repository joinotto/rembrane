use rembrane_application::{ApplicationError, MembershipRepository};
use rembrane_domain::{Membership, MembershipStatus, PrincipalId, WorkspaceId, WorkspaceRole};
use rembrane_store_memory::InMemoryStore;

fn membership(workspace_id: &str, principal_id: &str, role: WorkspaceRole) -> Membership {
    Membership::new(
        WorkspaceId::new(workspace_id),
        PrincipalId::new(principal_id),
        role,
    )
}

#[test]
fn membership_lookup_requires_workspace_and_principal() {
    let mut store = InMemoryStore::new();
    store
        .insert_membership(membership(
            "workspace_private",
            "principal_01",
            WorkspaceRole::Owner,
        ))
        .expect("membership insert should succeed");

    assert!(
        store
            .find_membership(
                &WorkspaceId::new("workspace_other"),
                &PrincipalId::new("principal_01"),
            )
            .expect("membership lookup should succeed")
            .is_none()
    );
    assert!(
        store
            .find_membership(
                &WorkspaceId::new("workspace_private"),
                &PrincipalId::new("principal_other"),
            )
            .expect("membership lookup should succeed")
            .is_none()
    );
}

#[test]
fn removed_membership_replaces_active_state() {
    let mut store = InMemoryStore::new();
    let active = membership("workspace_01", "principal_01", WorkspaceRole::Member);
    store
        .insert_membership(active.clone())
        .expect("membership insert should succeed");
    store
        .replace_membership(active.remove())
        .expect("membership replacement should succeed");

    let current = store
        .find_membership(
            &WorkspaceId::new("workspace_01"),
            &PrincipalId::new("principal_01"),
        )
        .expect("membership lookup should succeed")
        .expect("membership should exist");

    assert_eq!(current.status(), MembershipStatus::Removed);
    assert!(!current.can_write_shared_memory());
}

#[test]
fn duplicate_membership_is_rejected() {
    let mut store = InMemoryStore::new();
    let member = membership("workspace_01", "principal_01", WorkspaceRole::Member);
    store
        .insert_membership(member.clone())
        .expect("membership insert should succeed");

    let error = store
        .insert_membership(member)
        .expect_err("duplicate membership should fail");

    assert_eq!(error, ApplicationError::AlreadyExists);
}

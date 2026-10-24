use rembrane_application::{
    ApplicationError, CanonicalMutationRepository, ShareProposalRepository, WorkspaceRepository,
};
use rembrane_domain::{
    CanonicalEvent, EventId, EventPayload, EvidenceId, EvidenceReference, EvidenceSource,
    Membership, MemoryId, MemoryRecord, MemoryScope, MemoryShareProposal, Principal, PrincipalId,
    ShareProposalId, ShareProposalStatus, Workspace, WorkspaceId, WorkspaceRole,
};
use rembrane_store_memory::InMemoryStore;

fn seeded_store() -> InMemoryStore {
    let principal_id = PrincipalId::new("principal_01");
    let personal_id = WorkspaceId::new("personal_01");
    let shared_id = WorkspaceId::new("shared_01");
    let mut store = InMemoryStore::new();
    store
        .initialize_personal_workspace(
            Principal::new(principal_id.clone()),
            Workspace::personal(personal_id.clone()),
            Membership::new(
                personal_id.clone(),
                principal_id.clone(),
                WorkspaceRole::Owner,
            ),
        )
        .expect("personal workspace should initialize");
    store
        .initialize_shared_workspace(
            Workspace::shared(shared_id.clone()),
            Membership::new(shared_id, principal_id.clone(), WorkspaceRole::Owner),
        )
        .expect("shared workspace should initialize");

    let memory = MemoryRecord::confirmed_preference(
        MemoryId::new("memory_01"),
        personal_id.clone(),
        principal_id.clone(),
        MemoryScope::Global,
        "Call me Hippo",
        EvidenceReference::new(
            EvidenceId::new("evidence_01"),
            EvidenceSource::UserStatement,
        ),
    )
    .expect("source memory should be valid");
    store
        .insert_memory_with_event(
            memory,
            CanonicalEvent::new(
                EventId::new("event_01"),
                personal_id,
                principal_id.clone(),
                Some(principal_id),
                1,
                EventPayload::MemoryCreated {
                    memory_id: MemoryId::new("memory_01"),
                    version: 1,
                },
            )
            .expect("source event should be valid"),
            Vec::new(),
            0,
        )
        .expect("source memory should persist");
    store
}

fn proposal(id: &str, version: u64) -> MemoryShareProposal {
    MemoryShareProposal::new(
        ShareProposalId::new(id),
        WorkspaceId::new("personal_01"),
        MemoryId::new("memory_01"),
        version,
        PrincipalId::new("principal_01"),
        WorkspaceId::new("shared_01"),
        MemoryScope::Global,
        PrincipalId::new("principal_01"),
    )
    .expect("proposal should be structurally valid")
}

#[test]
fn persists_and_scopes_content_free_share_proposal() {
    let mut store = seeded_store();
    store
        .insert_share_proposal(proposal("share_01", 1))
        .expect("exact source version should persist");

    assert!(
        store
            .find_share_proposal(
                &WorkspaceId::new("another_personal"),
                &ShareProposalId::new("share_01"),
            )
            .expect("tenant-scoped lookup should run")
            .is_none()
    );
    assert_eq!(
        store
            .list_share_proposals_for_source(
                &WorkspaceId::new("personal_01"),
                &PrincipalId::new("principal_01"),
            )
            .expect("source proposals should list")
            .len(),
        1
    );
}

#[test]
fn rejects_stale_source_and_optimistic_status_conflict() {
    let mut store = seeded_store();
    assert_eq!(
        store.insert_share_proposal(proposal("share_stale", 2)),
        Err(ApplicationError::VersionConflict)
    );

    let pending = proposal("share_01", 1);
    store
        .insert_share_proposal(pending.clone())
        .expect("pending proposal should persist");
    let approved = pending
        .approve(&PrincipalId::new("principal_01"))
        .expect("source owner should approve");
    store
        .replace_share_proposal(approved.clone(), ShareProposalStatus::Pending)
        .expect("pending proposal should transition once");
    assert_eq!(
        store.replace_share_proposal(approved, ShareProposalStatus::Pending),
        Err(ApplicationError::VersionConflict)
    );
}

use rembrane_application::{
    ApplicationError, CanonicalMutationRepository, ShareProposalRepository, WorkspaceRepository,
};
use rembrane_crypto_rustcrypto::RustCryptoRecordCipher;
use rembrane_domain::{
    CanonicalEvent, EventId, EventPayload, EvidenceId, EvidenceReference, EvidenceSource,
    Membership, MemoryId, MemoryRecord, MemoryScope, MemoryShareProposal, Principal, PrincipalId,
    ShareProposalId, ShareProposalStatus, Workspace, WorkspaceId, WorkspaceRole,
};
use rembrane_store_sqlite::SqliteStore;

fn seeded_store() -> SqliteStore<RustCryptoRecordCipher> {
    let principal_id = PrincipalId::new("principal_01");
    let personal_id = WorkspaceId::new("personal_01");
    let shared_id = WorkspaceId::new("shared_01");
    let mut store = SqliteStore::open_in_memory().expect("database should open");
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
    let mut store = store.with_cipher(
        RustCryptoRecordCipher::new("test-key", [11; 32]).expect("test key should be valid"),
    );
    store
        .insert_memory_with_event(
            MemoryRecord::confirmed_preference(
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
            .expect("source memory should be valid"),
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

fn proposal(id: &str, source_version: u64) -> MemoryShareProposal {
    MemoryShareProposal::new(
        ShareProposalId::new(id),
        WorkspaceId::new("personal_01"),
        MemoryId::new("memory_01"),
        source_version,
        PrincipalId::new("principal_01"),
        WorkspaceId::new("shared_01"),
        MemoryScope::Global,
        PrincipalId::new("principal_01"),
    )
    .expect("share proposal should be valid")
}

#[test]
fn persists_tenant_scoped_proposal_and_optimistic_transition() {
    let mut store = seeded_store();
    let pending = proposal("share_01", 1);
    store
        .insert_share_proposal(pending.clone())
        .expect("proposal should persist");
    assert!(
        store
            .find_share_proposal(
                &WorkspaceId::new("other_personal"),
                &ShareProposalId::new("share_01"),
            )
            .expect("tenant-scoped lookup should execute")
            .is_none()
    );

    let approved = pending
        .approve(&PrincipalId::new("principal_01"))
        .expect("source owner should approve");
    store
        .replace_share_proposal(approved.clone(), ShareProposalStatus::Pending)
        .expect("pending proposal should transition");
    assert_eq!(
        store
            .find_share_proposal(
                &WorkspaceId::new("personal_01"),
                &ShareProposalId::new("share_01"),
            )
            .expect("proposal lookup should execute"),
        Some(approved.clone())
    );
    assert_eq!(
        store.replace_share_proposal(approved, ShareProposalStatus::Pending),
        Err(ApplicationError::VersionConflict)
    );
}

#[test]
fn rejects_nonexistent_source_version() {
    assert_eq!(
        seeded_store().insert_share_proposal(proposal("share_stale", 2)),
        Err(ApplicationError::VersionConflict)
    );
}

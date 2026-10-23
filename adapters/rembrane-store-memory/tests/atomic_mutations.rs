use rembrane_application::{
    ApplicationError, CanonicalMutationRepository, EventRepository,
    MemoryRepository,
};
use rembrane_domain::{
    CanonicalEvent, EventId, EventPayload, EvidenceId, EvidenceReference,
    EvidenceSource, MemoryId, MemoryRecord, MemoryScope, PrincipalId,
    WorkspaceId,
};
use rembrane_store_memory::InMemoryStore;

fn memory() -> MemoryRecord {
    MemoryRecord::confirmed_preference(
        MemoryId::new("memory_01"),
        WorkspaceId::new("workspace_01"),
        PrincipalId::new("principal_01"),
        MemoryScope::Global,
        "Call me Hippo",
        EvidenceReference::new(
            EvidenceId::new("evidence_01"),
            EvidenceSource::UserStatement,
        ),
    )
    .expect("test memory should be valid")
}

fn event(sequence: u64) -> CanonicalEvent {
    CanonicalEvent::new(
        EventId::new(format!("event_{sequence}")),
        WorkspaceId::new("workspace_01"),
        PrincipalId::new("principal_01"),
        Some(PrincipalId::new("principal_01")),
        sequence,
        EventPayload::MemoryCreated {
            memory_id: MemoryId::new("memory_01"),
            version: 1,
        },
    )
    .expect("test event should be valid")
}

#[test]
fn sequence_failure_leaves_memory_and_event_unchanged() {
    let mut store = InMemoryStore::new();

    let error = store
        .insert_memory_with_event(memory(), event(2), 0)
        .expect_err("invalid event sequence should fail atomically");

    assert_eq!(error, ApplicationError::SequenceConflict);
    assert!(
        store
            .find(
                &WorkspaceId::new("workspace_01"),
                &MemoryId::new("memory_01"),
            )
            .expect("memory lookup should succeed")
            .is_none()
    );
    assert!(
        store
            .list_events_since(&WorkspaceId::new("workspace_01"), 0)
            .expect("event lookup should succeed")
            .is_empty()
    );
}

#[test]
fn valid_mutation_commits_memory_and_event_together() {
    let mut store = InMemoryStore::new();

    store
        .insert_memory_with_event(memory(), event(1), 0)
        .expect("valid atomic mutation should succeed");

    assert!(
        store
            .find(
                &WorkspaceId::new("workspace_01"),
                &MemoryId::new("memory_01"),
            )
            .expect("memory lookup should succeed")
            .is_some()
    );
    assert_eq!(
        store
            .list_events_since(&WorkspaceId::new("workspace_01"), 0)
            .expect("event lookup should succeed")
            .len(),
        1
    );
}

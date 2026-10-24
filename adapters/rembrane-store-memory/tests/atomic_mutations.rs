use rembrane_application::{
    ApplicationError, CanonicalMutationRepository, EventRepository, MemoryRepository,
    ProjectionOutboxRepository,
};
use rembrane_domain::{
    CanonicalEvent, EventId, EventPayload, EvidenceId, EvidenceReference, EvidenceSource, MemoryId,
    MemoryRecord, MemoryScope, PrincipalId, ProjectionJob, ProjectionJobId, ProjectionOperation,
    ProviderId, WorkspaceId,
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

fn projection(workspace_id: &str) -> ProjectionJob {
    ProjectionJob::new(
        ProjectionJobId::new("projection_01"),
        WorkspaceId::new(workspace_id),
        MemoryId::new("memory_01"),
        1,
        ProviderId::new("semantic.primary"),
        ProjectionOperation::Upsert,
    )
    .expect("test projection should be valid")
}

#[test]
fn sequence_failure_leaves_memory_and_event_unchanged() {
    let mut store = InMemoryStore::new();

    let error = store
        .insert_memory_with_event(memory(), event(2), Vec::new(), 0)
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
        .insert_memory_with_event(memory(), event(1), Vec::new(), 0)
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

#[test]
fn projection_validation_failure_rolls_back_entire_mutation() {
    let mut store = InMemoryStore::new();

    let error = store
        .insert_memory_with_event(memory(), event(1), vec![projection("workspace_other")], 0)
        .expect_err("mismatched projection should fail atomically");

    assert_eq!(
        error,
        ApplicationError::Validation(
            "projection does not match canonical memory mutation".to_owned()
        )
    );
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
    assert!(
        store
            .pending_projections(&ProviderId::new("semantic.primary"), 10)
            .expect("projection lookup should succeed")
            .is_empty()
    );
}

#[test]
fn valid_mutation_commits_outbox_record() {
    let mut store = InMemoryStore::new();

    store
        .insert_memory_with_event(memory(), event(1), vec![projection("workspace_01")], 0)
        .expect("valid atomic mutation should succeed");

    assert_eq!(
        store
            .pending_projections(&ProviderId::new("semantic.primary"), 10)
            .expect("projection lookup should succeed")
            .len(),
        1
    );
}

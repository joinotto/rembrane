use rembrane_application::{
    ApplicationError, DeleteMemoryCommand, MemoryLifecycleService,
    ReviseMemoryCommand,
};
use rembrane_domain::{
    CanonicalEvent, ClientId, EventId, EventPayload, EvidenceId,
    EvidenceReference, EvidenceSource, MemoryId, MemoryRecord, MemoryScope,
    MemoryStatus, PrincipalId, WorkspaceId, WriteGrant, WritePermission,
};
use rembrane_store_memory::InMemoryStore;

fn evidence(id: &str) -> EvidenceReference {
    EvidenceReference::new(
        EvidenceId::new(id),
        EvidenceSource::UserStatement,
    )
}

fn initial_memory() -> MemoryRecord {
    MemoryRecord::confirmed_preference(
        MemoryId::new("memory_01"),
        WorkspaceId::new("workspace_01"),
        PrincipalId::new("principal_01"),
        MemoryScope::Global,
        "Call me Hippo",
        evidence("evidence_create"),
    )
    .expect("test memory should be valid")
}

fn writer(subject_id: &str) -> WriteGrant {
    WriteGrant {
        client_id: ClientId::new("client_01"),
        workspace_id: WorkspaceId::new("workspace_01"),
        subject_id: PrincipalId::new(subject_id),
        permissions: vec![
            WritePermission::ReviseMemory,
            WritePermission::DeleteMemory,
        ],
    }
}

fn creation_event() -> CanonicalEvent {
    CanonicalEvent::new(
        EventId::new("event_create"),
        WorkspaceId::new("workspace_01"),
        PrincipalId::new("principal_01"),
        Some(PrincipalId::new("principal_01")),
        1,
        EventPayload::MemoryCreated {
            memory_id: MemoryId::new("memory_01"),
            version: 1,
        },
    )
    .expect("test event should be valid")
}

#[test]
fn revises_and_deletes_owned_memory() {
    let mut store = InMemoryStore::new();
    rembrane_application::CanonicalMutationRepository::insert_memory_with_event(
        &mut store,
        initial_memory(),
        creation_event(),
        Vec::new(),
        0,
    )
    .expect("initial insert should succeed");

    let mut service = MemoryLifecycleService::new(&mut store);
    let revised = service
        .revise(ReviseMemoryCommand {
            grant: writer("principal_01"),
            memory_id: MemoryId::new("memory_01"),
            expected_version: 1,
            content: "Call me Captain Hippo".to_owned(),
            evidence: evidence("evidence_revise"),
            event_id: EventId::new("event_revise"),
            expected_previous_sequence: 1,
            projections: Vec::new(),
        })
        .expect("revision should succeed");

    assert_eq!(revised.version(), 2);

    let deleted = service
        .delete(DeleteMemoryCommand {
            grant: writer("principal_01"),
            memory_id: MemoryId::new("memory_01"),
            expected_version: 2,
            evidence: evidence("evidence_delete"),
            event_id: EventId::new("event_delete"),
            expected_previous_sequence: 2,
            projections: Vec::new(),
        })
        .expect("deletion should succeed");

    assert_eq!(deleted.version(), 3);
    assert_eq!(deleted.status(), MemoryStatus::Deleted);
    assert!(deleted.content().is_empty());
}

#[test]
fn hides_memory_from_another_subject() {
    let mut store = InMemoryStore::new();
    rembrane_application::CanonicalMutationRepository::insert_memory_with_event(
        &mut store,
        initial_memory(),
        creation_event(),
        Vec::new(),
        0,
    )
    .expect("initial insert should succeed");

    let error = MemoryLifecycleService::new(&mut store)
        .revise(ReviseMemoryCommand {
            grant: writer("principal_other"),
            memory_id: MemoryId::new("memory_01"),
            expected_version: 1,
            content: "Malicious overwrite".to_owned(),
            evidence: evidence("evidence_other"),
            event_id: EventId::new("event_revise"),
            expected_previous_sequence: 1,
            projections: Vec::new(),
        })
        .expect_err("another subject must not revise memory");

    assert_eq!(error, ApplicationError::NotFound);
}

#[test]
fn rejects_stale_expected_version() {
    let mut store = InMemoryStore::new();
    rembrane_application::CanonicalMutationRepository::insert_memory_with_event(
        &mut store,
        initial_memory(),
        creation_event(),
        Vec::new(),
        0,
    )
    .expect("initial insert should succeed");

    let error = MemoryLifecycleService::new(&mut store)
        .delete(DeleteMemoryCommand {
            grant: writer("principal_01"),
            memory_id: MemoryId::new("memory_01"),
            expected_version: 2,
            evidence: evidence("evidence_delete"),
            event_id: EventId::new("event_delete"),
            expected_previous_sequence: 1,
            projections: Vec::new(),
        })
        .expect_err("stale deletion must fail");

    assert_eq!(error, ApplicationError::VersionConflict);
}

#[test]
fn denies_revision_without_explicit_permission() {
    let mut store = InMemoryStore::new();
    rembrane_application::CanonicalMutationRepository::insert_memory_with_event(
        &mut store,
        initial_memory(),
        creation_event(),
        Vec::new(),
        0,
    )
    .expect("initial insert should succeed");
    let mut denied = writer("principal_01");
    denied.permissions.clear();

    let error = MemoryLifecycleService::new(&mut store)
        .revise(ReviseMemoryCommand {
            grant: denied,
            memory_id: MemoryId::new("memory_01"),
            expected_version: 1,
            content: "Unauthorized change".to_owned(),
            evidence: evidence("evidence_unauthorized"),
            event_id: EventId::new("event_revise"),
            expected_previous_sequence: 1,
            projections: Vec::new(),
        })
        .expect_err("missing revision permission should fail");

    assert_eq!(error, ApplicationError::AccessDenied);
}

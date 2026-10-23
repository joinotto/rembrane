use rembrane_application::{
    ApplicationError, DeleteMemoryCommand, MemoryLifecycleService,
    MemoryRepository, ReviseMemoryCommand,
};
use rembrane_domain::{
    EvidenceId, EvidenceReference, EvidenceSource, MemoryId, MemoryRecord,
    MemoryScope, MemoryStatus, PrincipalId, WorkspaceId,
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
}

#[test]
fn revises_and_deletes_owned_memory() {
    let mut store = InMemoryStore::new();
    store
        .insert(initial_memory())
        .expect("initial insert should succeed");

    let mut service = MemoryLifecycleService::new(&mut store);
    let revised = service
        .revise(ReviseMemoryCommand {
            workspace_id: WorkspaceId::new("workspace_01"),
            subject_id: PrincipalId::new("principal_01"),
            memory_id: MemoryId::new("memory_01"),
            expected_version: 1,
            content: "Call me Captain Hippo".to_owned(),
            evidence: evidence("evidence_revise"),
        })
        .expect("revision should succeed");

    assert_eq!(revised.version, 2);

    let deleted = service
        .delete(DeleteMemoryCommand {
            workspace_id: WorkspaceId::new("workspace_01"),
            subject_id: PrincipalId::new("principal_01"),
            memory_id: MemoryId::new("memory_01"),
            expected_version: 2,
            evidence: evidence("evidence_delete"),
        })
        .expect("deletion should succeed");

    assert_eq!(deleted.version, 3);
    assert_eq!(deleted.status, MemoryStatus::Deleted);
    assert!(deleted.content.is_empty());
}

#[test]
fn hides_memory_from_another_subject() {
    let mut store = InMemoryStore::new();
    store
        .insert(initial_memory())
        .expect("initial insert should succeed");

    let error = MemoryLifecycleService::new(&mut store)
        .revise(ReviseMemoryCommand {
            workspace_id: WorkspaceId::new("workspace_01"),
            subject_id: PrincipalId::new("principal_other"),
            memory_id: MemoryId::new("memory_01"),
            expected_version: 1,
            content: "Malicious overwrite".to_owned(),
            evidence: evidence("evidence_other"),
        })
        .expect_err("another subject must not revise memory");

    assert_eq!(error, ApplicationError::NotFound);
}

#[test]
fn rejects_stale_expected_version() {
    let mut store = InMemoryStore::new();
    store
        .insert(initial_memory())
        .expect("initial insert should succeed");

    let error = MemoryLifecycleService::new(&mut store)
        .delete(DeleteMemoryCommand {
            workspace_id: WorkspaceId::new("workspace_01"),
            subject_id: PrincipalId::new("principal_01"),
            memory_id: MemoryId::new("memory_01"),
            expected_version: 2,
            evidence: evidence("evidence_delete"),
        })
        .expect_err("stale deletion must fail");

    assert_eq!(error, ApplicationError::VersionConflict);
}

use rembrane_application::{
    ApplicationError, RememberPreferenceCommand, RememberPreferenceService,
};
use rembrane_domain::{
    ClientId, EventId, EvidenceId, EvidenceReference, EvidenceSource, MemoryId,
    MemoryScope, PrincipalId, WorkspaceId, WriteGrant, WritePermission,
};
use rembrane_store_memory::InMemoryStore;

fn command(permissions: Vec<WritePermission>) -> RememberPreferenceCommand {
    RememberPreferenceCommand {
        grant: WriteGrant {
            client_id: ClientId::new("client_01"),
            workspace_id: WorkspaceId::new("workspace_01"),
            subject_id: PrincipalId::new("principal_01"),
            permissions,
        },
        memory_id: MemoryId::new("memory_01"),
        scope: MemoryScope::Global,
        content: "Call me Hippo".to_owned(),
        evidence: EvidenceReference::new(
            EvidenceId::new("evidence_01"),
            EvidenceSource::UserStatement,
        ),
        event_id: EventId::new("event_01"),
        expected_previous_sequence: 0,
        projections: Vec::new(),
    }
}

#[test]
fn remembers_confirmed_preference_with_permission() {
    let mut store = InMemoryStore::new();
    let memory = RememberPreferenceService::new(&mut store)
        .execute(command(vec![WritePermission::CreateMemory]))
        .expect("authorized write succeeds");

    assert_eq!(memory.content(), "Call me Hippo");
}

#[test]
fn denies_direct_creation_without_permission() {
    let mut store = InMemoryStore::new();
    let error = RememberPreferenceService::new(&mut store)
        .execute(command(Vec::new()))
        .expect_err("unauthorized write fails");

    assert_eq!(error, ApplicationError::AccessDenied);
}

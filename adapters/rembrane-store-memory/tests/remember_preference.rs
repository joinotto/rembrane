use rembrane_application::{
    ApplicationError, RememberPreferenceCommand, RememberPreferenceService,
};
use rembrane_domain::{
    ClientId, EventId, EvidenceId, EvidenceReference, EvidenceSource, MemoryId,
    MemoryScope, PrincipalId, ReadScope, WorkspaceId, WriteGrant,
    WritePermission,
};
use rembrane_store_memory::InMemoryStore;

fn command(permissions: Vec<WritePermission>) -> RememberPreferenceCommand {
    RememberPreferenceCommand {
        grant: WriteGrant {
            client_id: ClientId::new("client_01"),
            workspace_id: WorkspaceId::new("workspace_01"),
            subject_id: PrincipalId::new("principal_01"),
            scopes: vec![ReadScope::Global],
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

#[test]
fn denies_creation_outside_the_write_scope() {
    let mut scoped = command(vec![WritePermission::CreateMemory]);
    scoped.scope = MemoryScope::Entity {
        id: rembrane_domain::EntityId::new("project_01"),
    };
    let mut store = InMemoryStore::new();

    let error = RememberPreferenceService::new(&mut store)
        .execute(scoped)
        .expect_err("out-of-scope write must fail");

    assert_eq!(error, ApplicationError::AccessDenied);
}

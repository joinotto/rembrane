use rembrane_application::{
    MemoryRepository, ResolveContextCommand, SemanticContextService,
};
use rembrane_contracts::ResolveContextRequest;
use rembrane_domain::{
    ClientId, ContextPackId, DisclosureId, EntityId, EvidenceId,
    EvidenceReference, EvidenceSource, MemoryId, MemoryKind, MemoryRecord,
    MemoryScope, PrincipalId, ReadGrant, ReadScope, WorkspaceId,
};
use rembrane_provider_sdk::{
    AuthorizedMemoryProjection, SemanticMemoryProvider,
};
use rembrane_semantic_native::NativeSemanticProvider;
use rembrane_store_memory::InMemoryStore;

fn memory(
    memory_id: &str,
    subject_id: &str,
    scope: MemoryScope,
) -> MemoryRecord {
    MemoryRecord::confirmed_preference(
        MemoryId::new(memory_id),
        WorkspaceId::new("workspace_01"),
        PrincipalId::new(subject_id),
        scope,
        "The preferred package manager is pnpm",
        EvidenceReference::new(
            EvidenceId::new(format!("evidence_{memory_id}")),
            EvidenceSource::UserStatement,
        ),
    )
    .expect("test memory should be valid")
}

fn projection(memory: &MemoryRecord) -> AuthorizedMemoryProjection {
    AuthorizedMemoryProjection {
        workspace_id: memory.workspace_id().clone(),
        memory_id: memory.id().clone(),
        version: memory.version(),
        scope: memory.scope().clone(),
        kind: MemoryKind::Preference,
        content: memory.content().to_owned(),
    }
}

fn command(scopes: Vec<ReadScope>) -> ResolveContextCommand {
    ResolveContextCommand {
        request: ResolveContextRequest {
            workspace_id: WorkspaceId::new("workspace_01"),
            principal_id: PrincipalId::new("principal_01"),
            domain: Some("development".to_owned()),
            entity_id: Some(EntityId::new("project_01")),
            activity_id: None,
            purpose: "continue_project".to_owned(),
            query: "Which package manager should I use?".to_owned(),
            maximum_items: 10,
        },
        grant: ReadGrant {
            client_id: ClientId::new("coding_agent"),
            workspace_id: WorkspaceId::new("workspace_01"),
            subject_id: PrincipalId::new("principal_01"),
            scopes,
        },
        context_pack_id: ContextPackId::new("context_01"),
        disclosure_id: DisclosureId::new("disclosure_01"),
    }
}

#[test]
fn provider_candidate_is_rejected_without_canonical_grant() {
    let entity_memory = memory(
        "memory_01",
        "principal_01",
        MemoryScope::Entity {
            id: EntityId::new("project_01"),
        },
    );
    let mut store = InMemoryStore::new();
    store
        .insert(entity_memory.clone())
        .expect("memory insert should succeed");
    let mut provider = NativeSemanticProvider::new();
    provider
        .index(projection(&entity_memory))
        .expect("provider index should succeed");

    let response = SemanticContextService::new(&mut store, &provider)
        .execute(command(vec![ReadScope::Global]))
        .expect("authorized request should execute");

    assert!(response.items.is_empty());
    assert_eq!(store.disclosure_count(), 1);
}

#[test]
fn provider_candidate_for_another_subject_is_rejected() {
    let private_memory = memory(
        "memory_private",
        "principal_other",
        MemoryScope::Global,
    );
    let mut store = InMemoryStore::new();
    store
        .insert(private_memory.clone())
        .expect("memory insert should succeed");
    let mut provider = NativeSemanticProvider::new();
    provider
        .index(projection(&private_memory))
        .expect("provider index should succeed");

    let response = SemanticContextService::new(&mut store, &provider)
        .execute(command(vec![ReadScope::Global]))
        .expect("authorized request should execute");

    assert!(response.items.is_empty());
}

#[test]
fn authorized_current_candidate_is_returned() {
    let entity_memory = memory(
        "memory_01",
        "principal_01",
        MemoryScope::Entity {
            id: EntityId::new("project_01"),
        },
    );
    let mut store = InMemoryStore::new();
    store
        .insert(entity_memory.clone())
        .expect("memory insert should succeed");
    let mut provider = NativeSemanticProvider::new();
    provider
        .index(projection(&entity_memory))
        .expect("provider index should succeed");

    let response = SemanticContextService::new(&mut store, &provider)
        .execute(command(vec![ReadScope::Entity {
            id: EntityId::new("project_01"),
        }]))
        .expect("authorized resolution should succeed");

    assert_eq!(response.items.len(), 1);
    assert_eq!(response.items[0].id(), &MemoryId::new("memory_01"));
}

use rembrane_application::{
    CanonicalMutationRepository, ResolveContextCommand,
    ResolveContextService,
};
use rembrane_contracts::ResolveContextRequest;
use rembrane_domain::{
    CanonicalEvent, ClientId, ContextPackId, DisclosureId, EventId,
    EventPayload, EvidenceId, EvidenceReference, EvidenceSource, MemoryId,
    MemoryRecord, MemoryScope, PrincipalId, ReadGrant, ReadScope, WorkspaceId,
};
use rembrane_store_memory::InMemoryStore;

fn main() {
    let command = std::env::args().nth(1);

    match command.as_deref() {
        Some("version" | "--version" | "-V") => {
            println!("rembrane {}", env!("CARGO_PKG_VERSION"));
        }
        Some("demo") => print_demo(),
        _ => print_help(),
    }
}

fn print_demo() {
    let workspace_id = WorkspaceId::new("workspace_demo");
    let principal_id = PrincipalId::new("principal_demo");
    let memory = MemoryRecord::confirmed_preference(
        MemoryId::new("memory_demo"),
        workspace_id.clone(),
        principal_id.clone(),
        MemoryScope::Global,
        "Call me Hippo",
        EvidenceReference::new(
            EvidenceId::new("evidence_demo"),
            EvidenceSource::UserStatement,
        ),
    )
    .expect("built-in demo memory should be valid");

    let mut store = InMemoryStore::new();
    let event = CanonicalEvent::new(
        EventId::new("event_demo"),
        workspace_id.clone(),
        principal_id.clone(),
        Some(principal_id.clone()),
        1,
        EventPayload::MemoryCreated {
            memory_id: memory.id().clone(),
            version: memory.version(),
        },
    )
    .expect("built-in demo event should be valid");
    store
        .insert_memory_with_event(memory, event, Vec::new(), 0)
        .expect("built-in demo insert should succeed");

    let response = ResolveContextService::new(&mut store)
        .execute(ResolveContextCommand {
            request: ResolveContextRequest {
                workspace_id: workspace_id.clone(),
                principal_id: principal_id.clone(),
                domain: None,
                entity_id: None,
                activity_id: None,
                purpose: "personalize_assistant".to_owned(),
                query: "What should I call the user?".to_owned(),
                maximum_items: 5,
            },
            grant: ReadGrant {
                client_id: ClientId::new("second_assistant"),
                workspace_id,
                subject_id: principal_id,
                scopes: vec![ReadScope::Global],
            },
            context_pack_id: ContextPackId::new("context_demo"),
            disclosure_id: DisclosureId::new("disclosure_demo"),
        })
        .expect("built-in demo resolution should succeed");

    println!("Second assistant received:");
    for item in response.items {
        println!("- {}: {}", item.id(), item.content());
    }
    println!("Context pack: {}", response.context_pack_id);
    println!("Disclosure receipt: {}", response.disclosure_id);
}

fn print_help() {
    println!(
        "Rembrane — your memory across every connected AI\n\n\
         Usage:\n  rembrane version\n  rembrane demo"
    );
}

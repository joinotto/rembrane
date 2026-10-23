use rembrane_application::{
    CanonicalMutationRepository, ResolveContextCommand,
    ResolveContextService, WorkspaceRepository,
};
use rembrane_contracts::ResolveContextRequest;
use rembrane_domain::{
    CanonicalEvent, ClientId, ContextPackId, DisclosureId, EventId,
    EventPayload, EvidenceId, EvidenceReference, EvidenceSource, MemoryId,
    MemoryRecord, MemoryScope, Membership, Principal, PrincipalId, ReadGrant,
    ReadScope, Workspace, WorkspaceId, WorkspaceRole,
};
use rembrane_store_memory::InMemoryStore;
use rembrane_store_sqlite::SqliteStore;

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: Vec<String>) -> Result<(), String> {
    match arguments.first().map(String::as_str) {
        Some("version" | "--version" | "-V") => {
            println!("rembrane {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("demo") => {
            print_demo();
            Ok(())
        }
        Some("init") => initialize(&arguments[1..]),
        _ => {
            print_help();
            Ok(())
        }
    }
}

fn initialize(arguments: &[String]) -> Result<(), String> {
    let database = option(arguments, "--database")?;
    let principal = option(arguments, "--principal")?;
    let workspace = option(arguments, "--workspace")?;
    let database_path = std::path::Path::new(database);

    if let Some(parent) = database_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create database directory: {error}"))?;
    }

    let principal_id = PrincipalId::new(principal);
    let workspace_id = WorkspaceId::new(workspace);
    let mut store = SqliteStore::open(database_path)
        .map_err(|error| format!("cannot open database: {error}"))?;
    store
        .initialize_personal_workspace(
            Principal::new(principal_id.clone()),
            Workspace::personal(workspace_id.clone()),
            Membership::new(
                workspace_id.clone(),
                principal_id.clone(),
                WorkspaceRole::Owner,
            ),
        )
        .map_err(|error| format!("cannot initialize workspace: {error}"))?;

    println!("Initialized Rembrane");
    println!("Database: {}", database_path.display());
    println!("Principal: {principal_id}");
    println!("Workspace: {workspace_id}");
    Ok(())
}

fn option<'a>(arguments: &'a [String], name: &str) -> Result<&'a str, String> {
    let position = arguments
        .iter()
        .position(|argument| argument == name)
        .ok_or_else(|| format!("missing required option {name}"))?;
    arguments
        .get(position.saturating_add(1))
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty() && !value.starts_with("--"))
        .ok_or_else(|| format!("missing value for {name}"))
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
         Usage:\n\
           rembrane version\n\
           rembrane demo\n\
           rembrane init --database <path> --principal <id> --workspace <id>"
    );
}

#[cfg(test)]
mod tests {
    use super::option;

    #[test]
    fn parses_named_option_independent_of_order() {
        let arguments = vec![
            "--workspace".to_owned(),
            "workspace_01".to_owned(),
            "--database".to_owned(),
            "memory.db".to_owned(),
        ];

        assert_eq!(
            option(&arguments, "--database").expect("option exists"),
            "memory.db"
        );
    }

    #[test]
    fn rejects_option_without_value() {
        let arguments = vec![
            "--database".to_owned(),
            "--workspace".to_owned(),
            "workspace_01".to_owned(),
        ];

        assert!(option(&arguments, "--database").is_err());
    }
}

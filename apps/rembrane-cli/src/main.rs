use rembrane_application::{
    AuthorizeClientCommand, AuthorizeClientService, CanonicalMutationRepository,
    ClientGrantBundle, DeleteMemoryCommand, EventRepository,
    MembershipRepository, MemoryLifecycleService, MemoryRepository,
    RememberPreferenceCommand, RememberPreferenceService, ResolveContextCommand,
    ResolveContextService, ReviseMemoryCommand, WorkspaceRepository,
};
use rembrane_crypto_rustcrypto::RustCryptoRecordCipher;
use rembrane_contracts::ResolveContextRequest;
use rembrane_domain::{
    CanonicalEvent, ClientId, ContextPackId, DisclosureId, EventId,
    EventPayload, EvidenceId, EvidenceReference, EvidenceSource, MemoryId,
    MemoryRecord, MemoryScope, Membership, Principal, PrincipalId, ReadGrant,
    ReadScope, Workspace, WorkspaceId, WorkspaceRole, WritePermission,
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
        Some("doctor") => doctor(&arguments[1..]),
        Some("backup") => backup(&arguments[1..]),
        Some("restore") => restore(&arguments[1..]),
        Some("remember") => remember(&arguments[1..]),
        Some("recall") => recall(&arguments[1..]),
        Some("correct") => correct(&arguments[1..]),
        Some("forget") => forget(&arguments[1..]),
        _ => {
            print_help();
            Ok(())
        }
    }
}

fn backup(arguments: &[String]) -> Result<(), String> {
    let destination = std::path::Path::new(option(arguments, "--output")?);
    create_parent_directory(destination)?;
    let (store, principal_id, workspace_id) = encrypted_store(arguments)?;
    verify_installation(&store, &workspace_id, &principal_id)?;
    store
        .backup_to(destination)
        .map_err(|error| format!("cannot create backup: {error}"))?;

    println!("Encrypted backup created");
    println!("Output: {}", destination.display());
    Ok(())
}

fn restore(arguments: &[String]) -> Result<(), String> {
    let source = std::path::Path::new(option(arguments, "--input")?);
    let destination = std::path::Path::new(option(arguments, "--database")?);
    if destination.exists() {
        return Err("restore destination already exists".to_owned());
    }
    create_parent_directory(destination)?;
    std::fs::copy(source, destination)
        .map_err(|error| format!("cannot copy backup: {error}"))?;

    let result = (|| {
        let principal_id =
            PrincipalId::new(option(arguments, "--principal")?);
        let workspace_id =
            WorkspaceId::new(option(arguments, "--workspace")?);
        let cipher = RustCryptoRecordCipher::from_environment()
            .map_err(|error| format!("cannot load workspace cipher: {error}"))?;
        let store = SqliteStore::open(destination)
            .map_err(|error| format!("cannot open restored database: {error}"))?
            .with_cipher(cipher);
        verify_installation(&store, &workspace_id, &principal_id)
    })();

    if let Err(error) = result {
        std::fs::remove_file(destination).map_err(|cleanup_error| {
            format!(
                "{error}; additionally failed to remove invalid restore: \
                 {cleanup_error}"
            )
        })?;
        return Err(error);
    }

    println!("Encrypted backup restored");
    println!("Database: {}", destination.display());
    Ok(())
}

fn doctor(arguments: &[String]) -> Result<(), String> {
    let (store, principal_id, workspace_id) = encrypted_store(arguments)?;
    let (role, memory_count) =
        verify_installation(&store, &workspace_id, &principal_id)?;

    println!("Rembrane doctor: ready");
    println!("Database schema: compatible");
    println!("Workspace: {workspace_id}");
    println!("Principal: {principal_id}");
    println!("Membership: active ({role:?})");
    println!("Workspace key: loaded");
    println!("Authenticated encrypted records: {memory_count}");
    println!("Readable memories: {memory_count}");
    println!(
        "Secret sources: REMBRANE_WORKSPACE_KEY_ID, \
         REMBRANE_WORKSPACE_KEY_HEX"
    );
    Ok(())
}

fn verify_installation<C>(
    store: &SqliteStore<C>,
    workspace_id: &WorkspaceId,
    principal_id: &PrincipalId,
) -> Result<(WorkspaceRole, usize), String>
where
    C: rembrane_crypto::RecordCipher,
{
    let membership = store
        .find_membership(workspace_id, principal_id)
        .map_err(|error| format!("cannot inspect membership: {error}"))?
        .ok_or_else(|| {
            "principal is not a member of the configured workspace".to_owned()
        })?;
    if !membership.is_active() {
        return Err("configured workspace membership is not active".to_owned());
    }

    let memories = store
        .list_for_subject(workspace_id, principal_id)
        .map_err(|error| {
            format!(
                "cannot authenticate workspace memories with the configured key: {error}"
            )
        })?;
    Ok((membership.role(), memories.len()))
}

fn remember(arguments: &[String]) -> Result<(), String> {
    let content = option(arguments, "--content")?;
    let client_id =
        optional_option(arguments, "--client").unwrap_or("rembrane-cli");
    let (mut store, principal_id, workspace_id) =
        encrypted_store(arguments)?;
    let grants = authorize_client(
        &store,
        ClientId::new(client_id),
        &workspace_id,
        &principal_id,
        vec![ReadScope::Global],
        vec![WritePermission::CreateMemory],
    )?;
    let previous_sequence = current_sequence(&store, &workspace_id)?;
    let suffix = unique_suffix()?;
    let memory = RememberPreferenceService::new(&mut store)
        .execute(RememberPreferenceCommand {
            grant: grants.write,
            memory_id: MemoryId::new(format!("memory_{suffix}")),
            scope: MemoryScope::Global,
            content: content.to_owned(),
            evidence: EvidenceReference::new(
                EvidenceId::new(format!("evidence_{suffix}")),
                EvidenceSource::UserStatement,
            ),
            event_id: EventId::new(format!("event_{suffix}")),
            expected_previous_sequence: previous_sequence,
            projections: Vec::new(),
        })
        .map_err(|error| format!("cannot remember preference: {error}"))?;

    println!("Remembered {}", memory.id());
    Ok(())
}

fn correct(arguments: &[String]) -> Result<(), String> {
    let memory_id = MemoryId::new(option(arguments, "--memory")?);
    let expected_version = positive_u64(arguments, "--version")?;
    let content = option(arguments, "--content")?;
    let client_id =
        optional_option(arguments, "--client").unwrap_or("rembrane-cli");
    let (mut store, principal_id, workspace_id) =
        encrypted_store(arguments)?;
    let grants = authorize_client(
        &store,
        ClientId::new(client_id),
        &workspace_id,
        &principal_id,
        vec![ReadScope::Global],
        vec![WritePermission::ReviseMemory],
    )?;
    let previous_sequence = current_sequence(&store, &workspace_id)?;
    let suffix = unique_suffix()?;
    let memory = MemoryLifecycleService::new(&mut store)
        .revise(ReviseMemoryCommand {
            grant: grants.write,
            memory_id,
            expected_version,
            content: content.to_owned(),
            evidence: EvidenceReference::new(
                EvidenceId::new(format!("evidence_{suffix}")),
                EvidenceSource::UserStatement,
            ),
            event_id: EventId::new(format!("event_{suffix}")),
            expected_previous_sequence: previous_sequence,
            projections: Vec::new(),
        })
        .map_err(|error| format!("cannot correct memory: {error}"))?;

    println!("Corrected {} to version {}", memory.id(), memory.version());
    Ok(())
}

fn forget(arguments: &[String]) -> Result<(), String> {
    let memory_id = MemoryId::new(option(arguments, "--memory")?);
    let expected_version = positive_u64(arguments, "--version")?;
    let client_id =
        optional_option(arguments, "--client").unwrap_or("rembrane-cli");
    let (mut store, principal_id, workspace_id) =
        encrypted_store(arguments)?;
    let grants = authorize_client(
        &store,
        ClientId::new(client_id),
        &workspace_id,
        &principal_id,
        vec![ReadScope::Global],
        vec![WritePermission::DeleteMemory],
    )?;
    let previous_sequence = current_sequence(&store, &workspace_id)?;
    let suffix = unique_suffix()?;
    let memory = MemoryLifecycleService::new(&mut store)
        .delete(DeleteMemoryCommand {
            grant: grants.write,
            memory_id,
            expected_version,
            evidence: EvidenceReference::new(
                EvidenceId::new(format!("evidence_{suffix}")),
                EvidenceSource::UserStatement,
            ),
            event_id: EventId::new(format!("event_{suffix}")),
            expected_previous_sequence: previous_sequence,
            projections: Vec::new(),
        })
        .map_err(|error| format!("cannot forget memory: {error}"))?;

    println!("Deleted {} at version {}", memory.id(), memory.version());
    Ok(())
}

fn recall(arguments: &[String]) -> Result<(), String> {
    let client_id = option(arguments, "--client")?;
    let purpose = option(arguments, "--purpose")?;
    let query = option(arguments, "--query")?;
    let maximum_items = optional_option(arguments, "--limit")
        .map(str::parse::<usize>)
        .transpose()
        .map_err(|_| "--limit must be a positive integer".to_owned())?
        .unwrap_or(10);
    let (mut store, principal_id, workspace_id) =
        encrypted_store(arguments)?;
    let grants = authorize_client(
        &store,
        ClientId::new(client_id),
        &workspace_id,
        &principal_id,
        vec![ReadScope::Global],
        Vec::new(),
    )?;
    let suffix = unique_suffix()?;
    let response = ResolveContextService::new(&mut store)
        .execute(ResolveContextCommand {
            request: ResolveContextRequest {
                workspace_id: workspace_id.clone(),
                principal_id: principal_id.clone(),
                domain: None,
                entity_id: None,
                activity_id: None,
                purpose: purpose.to_owned(),
                query: query.to_owned(),
                maximum_items,
            },
            grant: grants.read,
            context_pack_id: ContextPackId::new(format!("context_{suffix}")),
            disclosure_id: DisclosureId::new(format!("disclosure_{suffix}")),
        })
        .map_err(|error| format!("cannot recall context: {error}"))?;

    for item in &response.items {
        println!("{}: {}", item.id(), item.content());
    }
    println!("Context pack: {}", response.context_pack_id);
    println!("Disclosure receipt: {}", response.disclosure_id);
    Ok(())
}

fn encrypted_store(
    arguments: &[String],
) -> Result<
    (
        SqliteStore<RustCryptoRecordCipher>,
        PrincipalId,
        WorkspaceId,
    ),
    String,
> {
    let database = option(arguments, "--database")?;
    let principal_id = PrincipalId::new(option(arguments, "--principal")?);
    let workspace_id = WorkspaceId::new(option(arguments, "--workspace")?);
    let cipher = RustCryptoRecordCipher::from_environment()
        .map_err(|error| format!("cannot load workspace cipher: {error}"))?;
    let store = SqliteStore::open(database)
        .map_err(|error| format!("cannot open database: {error}"))?
        .with_cipher(cipher);

    Ok((store, principal_id, workspace_id))
}

fn authorize_client<C>(
    store: &SqliteStore<C>,
    client_id: ClientId,
    workspace_id: &WorkspaceId,
    principal_id: &PrincipalId,
    read_scopes: Vec<ReadScope>,
    write_permissions: Vec<WritePermission>,
) -> Result<ClientGrantBundle, String> {
    AuthorizeClientService::new(store)
        .execute(AuthorizeClientCommand {
            client_id,
            workspace_id: workspace_id.clone(),
            principal_id: principal_id.clone(),
            requested_read_scopes: read_scopes,
            requested_write_permissions: write_permissions,
        })
        .map_err(|error| format!("cannot authorize client: {error}"))
}

fn current_sequence<C>(
    store: &SqliteStore<C>,
    workspace_id: &WorkspaceId,
) -> Result<u64, String>
where
    SqliteStore<C>: EventRepository,
{
    store
        .list_events_since(workspace_id, 0)
        .map_err(|error| format!("cannot inspect event stream: {error}"))
        .map(|events| events.last().map_or(0, CanonicalEvent::sequence))
}

fn positive_u64(arguments: &[String], name: &str) -> Result<u64, String> {
    let value = option(arguments, name)?
        .parse::<u64>()
        .map_err(|_| format!("{name} must be a positive integer"))?;
    if value == 0 {
        return Err(format!("{name} must be a positive integer"));
    }
    Ok(value)
}

fn unique_suffix() -> Result<u128, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(|_| "system clock is before the Unix epoch".to_owned())
}

fn initialize(arguments: &[String]) -> Result<(), String> {
    let database = option(arguments, "--database")?;
    let principal = option(arguments, "--principal")?;
    let workspace = option(arguments, "--workspace")?;
    let database_path = std::path::Path::new(database);

    create_parent_directory(database_path)?;

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

fn create_parent_directory(path: &std::path::Path) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create directory: {error}"))?;
    }
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

fn optional_option<'a>(arguments: &'a [String], name: &str) -> Option<&'a str> {
    let position = arguments.iter().position(|argument| argument == name)?;
    arguments
        .get(position.saturating_add(1))
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty() && !value.starts_with("--"))
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
           rembrane init --database <path> --principal <id> --workspace <id>\n\
           rembrane doctor --database <path> --principal <id> --workspace <id>\n\
           rembrane backup --database <path> --principal <id> \
             --workspace <id> --output <path>\n\
           rembrane restore --input <path> --database <new-path> \
             --principal <id> --workspace <id>\n\
           rembrane remember --database <path> --principal <id> \
             --workspace <id> --content <preference>\n\
           rembrane recall --database <path> --principal <id> \
             --workspace <id> --client <id> --purpose <purpose> --query <query>\n\
           rembrane correct --database <path> --principal <id> \
             --workspace <id> --memory <id> --version <n> --content <text>\n\
           rembrane forget --database <path> --principal <id> \
             --workspace <id> --memory <id> --version <n>"
    );
}

#[cfg(test)]
mod tests {
    use super::{option, positive_u64};

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

    #[test]
    fn rejects_zero_memory_version() {
        let arguments = vec!["--version".to_owned(), "0".to_owned()];

        assert!(positive_u64(&arguments, "--version").is_err());
    }
}

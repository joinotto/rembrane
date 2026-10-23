use rembrane_application::{
    CanonicalMutationRepository, EventRepository, MembershipRepository,
    RememberPreferenceCommand, RememberPreferenceService,
    ResolveContextCommand, ResolveContextService, WorkspaceRepository,
};
use rembrane_crypto_rustcrypto::RustCryptoRecordCipher;
use rembrane_contracts::ResolveContextRequest;
use rembrane_domain::{
    CanonicalEvent, ClientId, ContextPackId, DisclosureId, EventId,
    EventPayload, EvidenceId, EvidenceReference, EvidenceSource, MemoryId,
    MemoryRecord, MemoryScope, Membership, Principal, PrincipalId, ReadGrant,
    ReadScope, Workspace, WorkspaceId, WorkspaceRole, WriteGrant,
    WritePermission,
};
use rembrane_store_memory::InMemoryStore;
use rembrane_store_sqlite::SqliteStore;
use zeroize::Zeroizing;

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
        Some("remember") => remember(&arguments[1..]),
        Some("recall") => recall(&arguments[1..]),
        _ => {
            print_help();
            Ok(())
        }
    }
}

fn remember(arguments: &[String]) -> Result<(), String> {
    let content = option(arguments, "--content")?;
    let client_id =
        optional_option(arguments, "--client").unwrap_or("rembrane-cli");
    let (mut store, principal_id, workspace_id) =
        encrypted_store(arguments)?;
    require_active_membership(&store, &workspace_id, &principal_id)?;
    let previous_sequence = store
        .list_events_since(&workspace_id, 0)
        .map_err(|error| format!("cannot inspect event stream: {error}"))?
        .last()
        .map_or(0, CanonicalEvent::sequence);
    let suffix = unique_suffix()?;
    let memory = RememberPreferenceService::new(&mut store)
        .execute(RememberPreferenceCommand {
            grant: WriteGrant {
                client_id: ClientId::new(client_id),
                workspace_id,
                subject_id: principal_id,
                permissions: vec![WritePermission::CreateMemory],
            },
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
    require_active_membership(&store, &workspace_id, &principal_id)?;
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
            grant: ReadGrant {
                client_id: ClientId::new(client_id),
                workspace_id,
                subject_id: principal_id,
                scopes: vec![ReadScope::Global],
            },
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
    let key_id = std::env::var("REMBRANE_WORKSPACE_KEY_ID")
        .map_err(|_| "REMBRANE_WORKSPACE_KEY_ID is required".to_owned())?;
    let encoded_key = Zeroizing::new(
        std::env::var("REMBRANE_WORKSPACE_KEY_HEX")
            .map_err(|_| "REMBRANE_WORKSPACE_KEY_HEX is required".to_owned())?,
    );
    let key = decode_key(&encoded_key)?;
    let cipher = RustCryptoRecordCipher::new(key_id, key)
        .map_err(|error| format!("cannot initialize cipher: {error}"))?;
    let store = SqliteStore::open(database)
        .map_err(|error| format!("cannot open database: {error}"))?
        .with_cipher(cipher);

    Ok((store, principal_id, workspace_id))
}

fn require_active_membership<C>(
    store: &SqliteStore<C>,
    workspace_id: &WorkspaceId,
    principal_id: &PrincipalId,
) -> Result<(), String> {
    let membership = store
        .find_membership(workspace_id, principal_id)
        .map_err(|error| format!("cannot verify membership: {error}"))?
        .ok_or_else(|| "principal is not a workspace member".to_owned())?;
    if !membership.is_active() {
        return Err("workspace membership is not active".to_owned());
    }
    Ok(())
}

fn decode_key(encoded: &str) -> Result<[u8; 32], String> {
    if encoded.len() != 64 || !encoded.is_ascii() {
        return Err(
            "REMBRANE_WORKSPACE_KEY_HEX must contain 64 hexadecimal characters"
                .to_owned(),
        );
    }
    let mut key = [0_u8; 32];
    for (index, output) in key.iter_mut().enumerate() {
        let offset = index.saturating_mul(2);
        *output = u8::from_str_radix(&encoded[offset..offset + 2], 16)
            .map_err(|_| {
                "REMBRANE_WORKSPACE_KEY_HEX contains invalid hexadecimal"
                    .to_owned()
            })?;
    }
    Ok(key)
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
           rembrane remember --database <path> --principal <id> \
             --workspace <id> --content <preference>\n\
           rembrane recall --database <path> --principal <id> \
             --workspace <id> --client <id> --purpose <purpose> --query <query>"
    );
}

#[cfg(test)]
mod tests {
    use super::{decode_key, option};

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
    fn decodes_exact_workspace_key() {
        let encoded =
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let key = decode_key(encoded).expect("valid key decodes");

        assert_eq!(key[0], 0);
        assert_eq!(key[31], 31);
    }

    #[test]
    fn rejects_workspace_key_with_wrong_length() {
        assert!(decode_key("abcd").is_err());
    }
}

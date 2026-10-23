use rembrane_application::{
    ApplicationError, AuthorizeClientCommand, AuthorizeClientService,
    CanonicalMutationRepository, ClientGrantBundle, DeleteMemoryCommand,
    EventRepository, MembershipRepository, MemoryLifecycleService,
    MemoryRepository, RememberPreferenceCommand, RememberPreferenceService,
    ResolveContextCommand, ResolveContextService, ReviseMemoryCommand,
    WorkspaceRepository,
};
use rembrane_crypto_rustcrypto::RustCryptoRecordCipher;
use rembrane_contracts::ResolveContextRequest;
use rembrane_config::{
    ProviderConnection, ProviderKind, ProviderPlacement, SecretReference,
};
use rembrane_domain::{
    CanonicalEvent, ClientId, ContextPackId, DisclosureId, EventId,
    EventPayload, EvidenceId, EvidenceReference, EvidenceSource, MemoryId,
    MemoryRecord, MemoryScope, Membership, Principal, PrincipalId, ReadGrant,
    ReadScope, Workspace, WorkspaceId, WorkspaceRole, WritePermission,
};
use rembrane_store_memory::InMemoryStore;
use rembrane_store_sqlite::SqliteStore;

const EXPORT_MAGIC: &[u8; 16] = b"REMBRANE-EXPORT\n";
const EXPORT_VERSION: u32 = 1;

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
        Some("fingerprint-git") => fingerprint_git(&arguments[1..]),
        Some("mcp-config") => print_mcp_config(&arguments[1..]),
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

const MCP_ENVIRONMENT_VARIABLES: [&str; 7] = [
    "REMBRANE_DATABASE",
    "REMBRANE_PRINCIPAL_ID",
    "REMBRANE_WORKSPACE_ID",
    "REMBRANE_CLIENT_ID",
    "REMBRANE_READ_SCOPES",
    "REMBRANE_WORKSPACE_KEY_ID",
    "REMBRANE_WORKSPACE_KEY_HEX",
];

fn print_mcp_config(arguments: &[String]) -> Result<(), String> {
    let client = option(arguments, "--client")?;
    let server_binary = option(arguments, "--server-binary")?;
    let config = match client {
        "codex" => codex_mcp_config(server_binary),
        "claude-code" => claude_mcp_config(server_binary),
        "generic" => generic_mcp_config(server_binary),
        _ => {
            return Err(
                "--client must be codex, claude-code, or generic".to_owned(),
            );
        }
    };
    println!("{config}");
    Ok(())
}

fn generic_mcp_config(server_binary: &str) -> String {
    let variables = MCP_ENVIRONMENT_VARIABLES
        .iter()
        .map(|variable| format!("\"{variable}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"schemaVersion\":1,\"name\":\"rembrane\",\
         \"transport\":\"stdio\",\"command\":\"{}\",\"args\":[],\
         \"requiredEnvironment\":[{variables}]}}",
        escape_config_string(server_binary)
    )
}

fn codex_mcp_config(server_binary: &str) -> String {
    let variables = MCP_ENVIRONMENT_VARIABLES
        .iter()
        .map(|variable| format!("\"{variable}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "[mcp_servers.rembrane]\ncommand = \"{}\"\n\
         env_vars = [{variables}]\nrequired = true",
        escape_config_string(server_binary)
    )
}

fn claude_mcp_config(server_binary: &str) -> String {
    let environment = MCP_ENVIRONMENT_VARIABLES
        .iter()
        .map(|variable| {
            format!("\"{variable}\":\"${{{variable}}}\"")
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"mcpServers\":{{\"rembrane\":{{\"type\":\"stdio\",\
         \"command\":\"{}\",\"args\":[],\"env\":{{{environment}}}}}}}}}}",
        escape_config_string(server_binary)
    )
}

fn escape_config_string(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

fn fingerprint_git(arguments: &[String]) -> Result<(), String> {
    let repository = std::path::Path::new(option(arguments, "--repository")?);
    if !repository.is_dir() {
        return Err("Git repository path is not a directory".to_owned());
    }
    let head = git_output(repository, &["rev-parse", "--verify", "HEAD"])?;
    let status = git_output(
        repository,
        &["status", "--porcelain=v1", "--untracked-files=normal"],
    )?;
    let worktree = if status.is_empty() { "clean" } else { "dirty" };
    println!("git:{head}:{worktree}");
    Ok(())
}

fn git_output(
    repository: &std::path::Path,
    arguments: &[&str],
) -> Result<String, String> {
    let output = std::process::Command::new("git")
        .args(["-C"])
        .arg(repository)
        .args(arguments)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .map_err(|error| format!("cannot execute Git: {error}"))?;
    if !output.status.success() {
        return Err("cannot inspect Git repository".to_owned());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| "Git returned non-UTF-8 output".to_owned())
}

fn backup(arguments: &[String]) -> Result<(), String> {
    let destination = std::path::Path::new(option(arguments, "--output")?);
    create_parent_directory(destination)?;
    let (store, principal_id, workspace_id) = encrypted_store(arguments)?;
    verify_installation(&store, &workspace_id, &principal_id)?;
    if destination.exists() {
        return Err("backup destination already exists".to_owned());
    }
    let temporary = destination.with_extension(format!(
        "encrypted-snapshot-{}",
        unique_suffix()?
    ));
    let result = (|| {
        store
            .backup_to(&temporary)
            .map_err(|error| format!("cannot create snapshot: {error}"))?;
        write_export(&temporary, destination)
    })();
    let cleanup_result = if temporary.exists() {
        std::fs::remove_file(&temporary)
            .map_err(|error| format!("cannot remove temporary snapshot: {error}"))
    } else {
        Ok(())
    };
    if let Err(error) = result {
        let _ = std::fs::remove_file(destination);
        cleanup_result?;
        return Err(error);
    }
    cleanup_result?;

    println!("Encrypted backup created");
    println!("Format: rembrane-encrypted-export-v{EXPORT_VERSION}");
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
    read_export(source, destination)?;

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
    println!("Format: rembrane-encrypted-export-v{EXPORT_VERSION}");
    println!("Database: {}", destination.display());
    Ok(())
}

fn write_export(
    snapshot: &std::path::Path,
    destination: &std::path::Path,
) -> Result<(), String> {
    use std::io::Write;

    let payload_length = snapshot
        .metadata()
        .map_err(|error| format!("cannot inspect snapshot: {error}"))?
        .len();
    let mut input = std::fs::File::open(snapshot)
        .map_err(|error| format!("cannot open snapshot: {error}"))?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| format!("cannot create export: {error}"))?;
    output
        .write_all(EXPORT_MAGIC)
        .and_then(|()| output.write_all(&EXPORT_VERSION.to_be_bytes()))
        .and_then(|()| output.write_all(&payload_length.to_be_bytes()))
        .map_err(|error| format!("cannot write export header: {error}"))?;
    let copied = std::io::copy(&mut input, &mut output)
        .map_err(|error| format!("cannot write export payload: {error}"))?;
    if copied != payload_length {
        return Err("snapshot changed while export was created".to_owned());
    }
    output
        .flush()
        .map_err(|error| format!("cannot flush export: {error}"))
}

fn read_export(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> Result<(), String> {
    use std::io::{Read, Write};

    let mut input = std::fs::File::open(source)
        .map_err(|error| format!("cannot open export: {error}"))?;
    let mut magic = [0_u8; EXPORT_MAGIC.len()];
    input
        .read_exact(&mut magic)
        .map_err(|_| "export header is truncated".to_owned())?;
    if &magic != EXPORT_MAGIC {
        return Err("input is not a Rembrane encrypted export".to_owned());
    }
    let mut version = [0_u8; 4];
    input
        .read_exact(&mut version)
        .map_err(|_| "export version is truncated".to_owned())?;
    let version = u32::from_be_bytes(version);
    if version != EXPORT_VERSION {
        return Err(format!("unsupported encrypted export version {version}"));
    }
    let mut payload_length = [0_u8; 8];
    input
        .read_exact(&mut payload_length)
        .map_err(|_| "export payload length is truncated".to_owned())?;
    let payload_length = u64::from_be_bytes(payload_length);
    if payload_length == 0 {
        return Err("export payload is empty".to_owned());
    }
    let expected_length = u64::try_from(EXPORT_MAGIC.len() + 4 + 8)
        .ok()
        .and_then(|header| header.checked_add(payload_length))
        .ok_or_else(|| "export length exceeds supported range".to_owned())?;
    let actual_length = input
        .metadata()
        .map_err(|error| format!("cannot inspect export: {error}"))?
        .len();
    if actual_length != expected_length {
        return Err(if actual_length < expected_length {
            "export payload is truncated".to_owned()
        } else {
            "export contains trailing data".to_owned()
        });
    }

    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|error| format!("cannot create restore destination: {error}"))?;
    let copied = match std::io::copy(
        &mut input.by_ref().take(payload_length),
        &mut output,
    ) {
        Ok(copied) => copied,
        Err(error) => {
            drop(output);
            let _ = std::fs::remove_file(destination);
            return Err(format!("cannot restore export payload: {error}"));
        }
    };
    if copied != payload_length {
        let _ = std::fs::remove_file(destination);
        return Err("export payload is truncated".to_owned());
    }
    if let Err(error) = output.flush() {
        drop(output);
        let _ = std::fs::remove_file(destination);
        return Err(format!("cannot flush restored database: {error}"));
    }
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
    println!("Secret sources: {}", configured_secret_sources().join(", "));
    if arguments.iter().any(|argument| argument == "--privacy") {
        print_privacy_diagnostics()?;
    }
    Ok(())
}

fn print_privacy_diagnostics() -> Result<(), String> {
    let configured_scopes = std::env::var("REMBRANE_READ_SCOPES")
        .unwrap_or_else(|_| "global".to_owned());
    let scopes = rembrane_config::parse_read_scopes(&configured_scopes)
        .map_err(|error| {
            format!("invalid REMBRANE_READ_SCOPES configuration: {error}")
        })?;
    validate_configured_provider_profiles()?;

    println!("Privacy diagnostics:");
    println!("Processing location: local trusted boundary");
    let endpoints = configured_outbound_endpoints();
    if endpoints.is_empty() {
        println!("Outbound endpoints: none");
    } else {
        println!("Outbound endpoints:");
        for (source, endpoint) in endpoints {
            println!("- {source}: {endpoint}");
        }
    }
    println!("Configured read scopes: {}", format_read_scopes(&scopes));
    println!(
        "External provider plaintext policy: denied unless an authorized \
         adapter explicitly enters the trusted boundary"
    );
    Ok(())
}

fn validate_configured_provider_profiles() -> Result<(), String> {
    for (endpoint_variable, credential_variable, kind) in [
        ("MEM0_BASE_URL", "MEM0_API_KEY", ProviderKind::Mem0),
        (
            "GRAPHITI_BASE_URL",
            "GRAPHITI_CREDENTIALS",
            ProviderKind::Graphiti,
        ),
    ] {
        let Ok(endpoint) = std::env::var(endpoint_variable) else {
            continue;
        };
        if endpoint.trim().is_empty() {
            continue;
        }
        let credentials = std::env::var(credential_variable)
            .ok()
            .filter(|value| !value.is_empty())
            .map(|_| {
                SecretReference::environment(credential_variable)
                    .expect("built-in secret variable must be valid")
            })
            .into_iter()
            .collect();
        ProviderConnection::remote(
            kind,
            endpoint,
            credentials,
            ProviderPlacement::External,
        )
        .map_err(|error| {
            format!("invalid {endpoint_variable} configuration: {error}")
        })?;
    }
    Ok(())
}

fn configured_secret_sources() -> Vec<&'static str> {
    let mut sources = vec![
        "REMBRANE_WORKSPACE_KEY_ID",
        "REMBRANE_WORKSPACE_KEY_HEX",
    ];
    for source in ["MEM0_API_KEY", "GRAPHITI_CREDENTIALS"] {
        if std::env::var(source)
            .ok()
            .is_some_and(|value| !value.is_empty())
        {
            sources.push(source);
        }
    }
    sources
}

fn configured_outbound_endpoints() -> Vec<(&'static str, String)> {
    [
        "MEM0_BASE_URL",
        "GRAPHITI_BASE_URL",
        "MEMORY_OBJECT_ENDPOINT",
        "REMBRANE_REMOTE_MCP_URL",
    ]
    .into_iter()
    .filter_map(|source| {
        std::env::var(source)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(|value| (source, redact_endpoint(&value)))
    })
    .collect()
}

fn redact_endpoint(value: &str) -> String {
    let value = value.trim();
    let Some((scheme, remainder)) = value.split_once("://") else {
        return "<configured; origin unavailable>".to_owned();
    };
    let authority_end = remainder
        .find(|character| matches!(character, '/' | '?' | '#'))
        .unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if scheme.is_empty() || authority.is_empty() {
        "<configured; origin unavailable>".to_owned()
    } else {
        format!("{scheme}://{authority}")
    }
}

fn format_read_scopes(scopes: &[ReadScope]) -> String {
    scopes
        .iter()
        .map(|scope| match scope {
            ReadScope::Global => "global".to_owned(),
            ReadScope::Domain { name } => format!("domain:{name}"),
            ReadScope::Entity { id } => format!("entity:{id}"),
            ReadScope::Activity { id } => format!("activity:{id}"),
        })
        .collect::<Vec<_>>()
        .join(",")
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
    let scope = requested_memory_scope(arguments)?;
    let read_scope = read_scope(&scope);
    let client_id =
        optional_option(arguments, "--client").unwrap_or("rembrane-cli");
    let (mut store, principal_id, workspace_id) =
        encrypted_store(arguments)?;
    let grants = authorize_client(
        &store,
        ClientId::new(client_id),
        &workspace_id,
        &principal_id,
        vec![read_scope],
        vec![WritePermission::CreateMemory],
    )?;
    let previous_sequence = current_sequence(&store, &workspace_id)?;
    let suffix = unique_suffix()?;
    let memory = RememberPreferenceService::new(&mut store)
        .execute(RememberPreferenceCommand {
            grant: grants.write,
            memory_id: MemoryId::new(format!("memory_{suffix}")),
            scope,
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
    let scope = requested_memory_scope(arguments)?;
    let client_id =
        optional_option(arguments, "--client").unwrap_or("rembrane-cli");
    let (mut store, principal_id, workspace_id) =
        encrypted_store(arguments)?;
    let grants = authorize_client(
        &store,
        ClientId::new(client_id),
        &workspace_id,
        &principal_id,
        vec![read_scope(&scope)],
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
    let scope = requested_memory_scope(arguments)?;
    let client_id =
        optional_option(arguments, "--client").unwrap_or("rembrane-cli");
    let (mut store, principal_id, workspace_id) =
        encrypted_store(arguments)?;
    let grants = authorize_client(
        &store,
        ClientId::new(client_id),
        &workspace_id,
        &principal_id,
        vec![read_scope(&scope)],
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
    let maximum_bytes = optional_option(arguments, "--max-bytes")
        .map(str::parse::<usize>)
        .transpose()
        .map_err(|_| "--max-bytes must be a positive integer".to_owned())?
        .unwrap_or(65_536);
    if maximum_bytes == 0 {
        return Err("--max-bytes must be a positive integer".to_owned());
    }
    let (domain, entity_id, activity_id, read_scopes) =
        recall_scope_context(arguments);
    let (mut store, principal_id, workspace_id) =
        encrypted_store(arguments)?;
    let grants = authorize_client(
        &store,
        ClientId::new(client_id),
        &workspace_id,
        &principal_id,
        read_scopes,
        Vec::new(),
    )?;
    let suffix = unique_suffix()?;
    let response = ResolveContextService::new(&mut store)
        .execute(ResolveContextCommand {
            request: ResolveContextRequest {
                workspace_id: workspace_id.clone(),
                principal_id: principal_id.clone(),
                domain,
                entity_id,
                activity_id,
                purpose: purpose.to_owned(),
                query: query.to_owned(),
                maximum_items,
                maximum_bytes,
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

fn recall_scope_context(
    arguments: &[String],
) -> (
    Option<String>,
    Option<rembrane_domain::EntityId>,
    Option<rembrane_domain::ActivityId>,
    Vec<ReadScope>,
) {
    let domain = optional_option(arguments, "--domain").map(str::to_owned);
    let entity_id = optional_option(arguments, "--entity")
        .map(rembrane_domain::EntityId::new);
    let activity_id = optional_option(arguments, "--activity")
        .map(rembrane_domain::ActivityId::new);
    let mut scopes = vec![ReadScope::Global];
    if let Some(name) = &domain {
        scopes.push(ReadScope::Domain { name: name.clone() });
    }
    if let Some(id) = &entity_id {
        scopes.push(ReadScope::Entity { id: id.clone() });
    }
    if let Some(id) = &activity_id {
        scopes.push(ReadScope::Activity { id: id.clone() });
    }
    (domain, entity_id, activity_id, scopes)
}

fn requested_memory_scope(arguments: &[String]) -> Result<MemoryScope, String> {
    Ok(optional_requested_scope(arguments)?.unwrap_or(MemoryScope::Global))
}

fn optional_requested_scope(
    arguments: &[String],
) -> Result<Option<MemoryScope>, String> {
    let domain = optional_option(arguments, "--domain");
    let entity = optional_option(arguments, "--entity");
    let activity = optional_option(arguments, "--activity");
    let count =
        usize::from(domain.is_some())
            + usize::from(entity.is_some())
            + usize::from(activity.is_some());
    if count > 1 {
        return Err(
            "--domain, --entity, and --activity are mutually exclusive"
                .to_owned(),
        );
    }

    Ok(if let Some(name) = domain {
        Some(MemoryScope::Domain {
            name: name.to_owned(),
        })
    } else if let Some(id) = entity {
        Some(MemoryScope::Entity {
            id: rembrane_domain::EntityId::new(id),
        })
    } else {
        activity.map(|id| MemoryScope::Activity {
            id: rembrane_domain::ActivityId::new(id),
        })
    })
}

fn read_scope(scope: &MemoryScope) -> ReadScope {
    match scope {
        MemoryScope::Global => ReadScope::Global,
        MemoryScope::Domain { name } => ReadScope::Domain {
            name: name.clone(),
        },
        MemoryScope::Entity { id } => ReadScope::Entity { id: id.clone() },
        MemoryScope::Activity { id } => {
            ReadScope::Activity { id: id.clone() }
        }
    }
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
    let initialization = store
        .initialize_personal_workspace(
            Principal::new(principal_id.clone()),
            Workspace::personal(workspace_id.clone()),
            Membership::new(
                workspace_id.clone(),
                principal_id.clone(),
                WorkspaceRole::Owner,
            ),
        );
    let already_initialized = match initialization {
        Ok(()) => false,
        Err(ApplicationError::AlreadyExists) => {
            if existing_personal_workspace_is_valid(
                &store,
                &principal_id,
                &workspace_id,
            )? {
                true
            } else {
                return Err(
                    "cannot initialize workspace: existing state conflicts"
                        .to_owned(),
                );
            }
        }
        Err(error) => {
            return Err(format!("cannot initialize workspace: {error}"));
        }
    };

    if already_initialized {
        println!("Rembrane is already initialized");
    } else {
        println!("Initialized Rembrane");
    }
    println!("Database: {}", database_path.display());
    println!("Principal: {principal_id}");
    println!("Workspace: {workspace_id}");
    Ok(())
}

fn existing_personal_workspace_is_valid<C>(
    store: &SqliteStore<C>,
    principal_id: &PrincipalId,
    workspace_id: &WorkspaceId,
) -> Result<bool, String> {
    let principal = store
        .find_principal(principal_id)
        .map_err(|error| format!("cannot inspect principal: {error}"))?;
    let workspace = store
        .find_workspace(workspace_id)
        .map_err(|error| format!("cannot inspect workspace: {error}"))?;
    let membership = store
        .find_membership(workspace_id, principal_id)
        .map_err(|error| format!("cannot inspect membership: {error}"))?;

    Ok(principal.is_some()
        && workspace.is_some_and(|workspace| {
            workspace.kind() == rembrane_domain::WorkspaceKind::Personal
        })
        && membership.is_some_and(|membership| {
            membership.role() == WorkspaceRole::Owner
                && membership.is_active()
        }))
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
                maximum_bytes: 65_536,
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
           rembrane doctor --database <path> --principal <id> --workspace <id> \
             [--privacy]\n\
           rembrane backup --database <path> --principal <id> \
             --workspace <id> --output <path>\n\
           rembrane restore --input <path> --database <new-path> \
             --principal <id> --workspace <id>\n\
           rembrane fingerprint-git --repository <path>\n\
           rembrane mcp-config --client <codex|claude-code|generic> \
             --server-binary <path>\n\
           rembrane remember --database <path> --principal <id> \
             --workspace <id> --content <preference> \
             [--domain <name> | --entity <id> | --activity <id>]\n\
           rembrane recall --database <path> --principal <id> \
             --workspace <id> --client <id> --purpose <purpose> --query <query> \
             [--limit <items>] [--max-bytes <bytes>] \
             [--domain <name>] [--entity <id>] [--activity <id>]\n\
           rembrane correct --database <path> --principal <id> \
             --workspace <id> --memory <id> --version <n> --content <text> \
             [--domain <name> | --entity <id> | --activity <id>]\n\
           rembrane forget --database <path> --principal <id> \
             --workspace <id> --memory <id> --version <n> \
             [--domain <name> | --entity <id> | --activity <id>]"
    );
}

#[cfg(test)]
mod tests {
    use rembrane_domain::{EntityId, MemoryScope, ReadScope};

    use super::{
        EXPORT_MAGIC, claude_mcp_config, codex_mcp_config,
        format_read_scopes, generic_mcp_config, option, positive_u64,
        read_export, recall_scope_context, redact_endpoint,
        requested_memory_scope, write_export,
    };

    fn temporary_path(name: &str) -> std::path::PathBuf {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rembrane-cli-{name}-{}-{suffix}",
            std::process::id()
        ))
    }

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

    #[test]
    fn parses_one_entity_scope_and_rejects_ambiguous_scopes() {
        let scoped = vec![
            "--entity".to_owned(),
            "project_01".to_owned(),
        ];
        assert_eq!(
            requested_memory_scope(&scoped).expect("scope should parse"),
            MemoryScope::Entity {
                id: EntityId::new("project_01")
            }
        );

        let ambiguous = vec![
            "--domain".to_owned(),
            "development".to_owned(),
            "--entity".to_owned(),
            "project_01".to_owned(),
        ];
        assert!(requested_memory_scope(&ambiguous).is_err());
    }

    #[test]
    fn recall_combines_global_domain_entity_and_activity_scopes() {
        let arguments = vec![
            "--domain".to_owned(),
            "development".to_owned(),
            "--entity".to_owned(),
            "project_01".to_owned(),
            "--activity".to_owned(),
            "task_01".to_owned(),
        ];

        let (_, _, _, scopes) = recall_scope_context(&arguments);

        assert_eq!(scopes.len(), 4);
        assert_eq!(scopes[0], rembrane_domain::ReadScope::Global);
    }

    #[test]
    fn privacy_diagnostics_format_exact_scope_allowlist() {
        let scopes = vec![
            ReadScope::Global,
            ReadScope::Domain {
                name: "development".to_owned(),
            },
            ReadScope::Entity {
                id: EntityId::new("project_01"),
            },
        ];

        assert_eq!(
            format_read_scopes(&scopes),
            "global,domain:development,entity:project_01"
        );
    }

    #[test]
    fn privacy_diagnostics_redact_endpoint_credentials_and_paths() {
        assert_eq!(
            redact_endpoint(
                "https://operator:secret@graph.example/v1?token=hidden"
            ),
            "https://graph.example"
        );
        assert_eq!(
            redact_endpoint("not-a-url-with-secret"),
            "<configured; origin unavailable>"
        );
    }

    #[test]
    fn encrypted_export_framing_round_trips_exact_payload() {
        let snapshot = temporary_path("snapshot");
        let export = temporary_path("export");
        let restored = temporary_path("restored");
        let payload = b"encrypted sqlite fixture";
        std::fs::write(&snapshot, payload).expect("snapshot should be written");

        write_export(&snapshot, &export).expect("export should be created");
        read_export(&export, &restored).expect("export should restore");

        assert_eq!(
            std::fs::read(&restored).expect("restore should be readable"),
            payload
        );
        std::fs::remove_file(snapshot).expect("snapshot should be removed");
        std::fs::remove_file(export).expect("export should be removed");
        std::fs::remove_file(restored).expect("restore should be removed");
    }

    #[test]
    fn encrypted_export_rejects_unknown_version_without_destination() {
        let export = temporary_path("unknown-version");
        let restored = temporary_path("unknown-version-restored");
        let mut bytes = EXPORT_MAGIC.to_vec();
        bytes.extend_from_slice(&2_u32.to_be_bytes());
        bytes.extend_from_slice(&1_u64.to_be_bytes());
        bytes.push(1);
        std::fs::write(&export, bytes).expect("fixture should be written");

        assert!(read_export(&export, &restored).is_err());
        assert!(!restored.exists());
        std::fs::remove_file(export).expect("fixture should be removed");
    }

    #[test]
    fn mcp_configs_reference_secrets_without_embedding_values() {
        let codex = codex_mcp_config("/opt/rembrane-mcp");
        assert!(codex.contains("env_vars = ["));
        assert!(codex.contains("\"REMBRANE_WORKSPACE_KEY_HEX\""));
        assert!(!codex.contains("00010203"));

        let claude = claude_mcp_config("/opt/rembrane-mcp");
        assert!(claude.contains(
            "\"REMBRANE_WORKSPACE_KEY_HEX\":\"${REMBRANE_WORKSPACE_KEY_HEX}\""
        ));
        assert!(!claude.contains("00010203"));

        let generic = generic_mcp_config("/opt/rembrane-mcp");
        assert!(generic.contains("\"schemaVersion\":1"));
        assert!(generic.contains("\"transport\":\"stdio\""));
        assert!(generic.contains("\"requiredEnvironment\""));
        assert!(!generic.contains("00010203"));
    }
}

use rembrane_application::{
    AcceptInvitationCommand, AdministrativeAuditRepository, ApplicationError,
    AuthorizeClientCommand, AuthorizeClientService, CanonicalMutationRepository,
    ChannelBindingService, ChannelInboxAdministrationService, CheckpointRepository,
    ClientGrantBundle, CreateChannelBindingCommand, CreateInvitationCommand, DeleteMemoryCommand,
    EventRepository, ExecuteRetentionPurgeCommand, InvitationService, ListInvitationsQuery,
    MemberLifecycleService, MembershipRepository, MemoryLifecycleService, MemoryRepository,
    PlaceLegalHoldCommand, ReleaseLegalHoldCommand, RememberPreferenceCommand,
    RememberPreferenceService, RequeueChannelMessageCommand, ResolveContextCommand,
    ResolveContextService, RetentionService, ReviseMemoryCommand, RevokeChannelBindingCommand,
    RevokeInvitationCommand, SetRetentionPolicyCommand, WorkspaceRepository,
};
use rembrane_channel_mobile_share::derive_binding_lookup_keys as derive_mobile_binding_lookup_keys;
use rembrane_channel_whatsapp::derive_binding_lookup_keys as derive_whatsapp_binding_lookup_keys;
use rembrane_config::{ProviderConnection, ProviderKind, ProviderPlacement, SecretReference};
use rembrane_contracts::{ChannelKind, ChannelSenderBinding, ResolveContextRequest};
use rembrane_crypto_configured::ConfiguredRecordCipher;
use rembrane_domain::{
    CanonicalEvent, ClientId, ContextPackId, DisclosureId, EventId, EventPayload, EvidenceId,
    EvidenceReference, EvidenceSource, Invitation, InvitationStatus, LegalHoldId, Membership,
    MemoryId, MemoryRecord, MemoryScope, Principal, PrincipalId, ReadGrant, ReadScope,
    RetentionPeriod, Workspace, WorkspaceId, WorkspaceRetentionPolicy, WorkspaceRole,
    WritePermission,
};
use rembrane_memory_provider_configured::ConfiguredMemoryProvider;
use rembrane_provider_sdk::{
    CURRENT_MEMORY_PROVIDER_PROTOCOL, MemoryProviderCapability, MemoryProviderLimits,
    MemoryProviderPolicy, MemoryProviderPrivacyMode, MemoryProviderTransport,
    SEMANTIC_PROVIDER_CONFORMANCE_CASES, SEMANTIC_PROVIDER_CONFORMANCE_PROFILE_SHA256,
    SEMANTIC_PROVIDER_CONFORMANCE_SUITE_ID, SEMANTIC_PROVIDER_CONFORMANCE_SUITE_VERSION,
    SemanticProviderConformanceReport, verify_semantic_provider,
};
use rembrane_secret_local::{LocalSecretResolver, SecretResolver};
use rembrane_semantic_mem0::Mem0SemanticProvider;
use rembrane_semantic_native::NativeSemanticProvider;
use rembrane_semantic_supermemory::SupermemorySemanticProvider;
use rembrane_store_memory::InMemoryStore;
use rembrane_store_sqlite::SqliteStore;
use serde::Serialize;
use zeroize::Zeroizing;

const EXPORT_MAGIC: &[u8; 16] = b"REMBRANE-EXPORT\n";
const EXPORT_VERSION: u32 = 1;

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if let Err(error) = run(&arguments) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(arguments: &[String]) -> Result<(), String> {
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
        Some("workspace") => workspace(&arguments[1..]),
        Some("invitation") => invitation(&arguments[1..]),
        Some("doctor") => doctor(&arguments[1..]),
        Some("backup") => backup(&arguments[1..]),
        Some("restore") => restore(&arguments[1..]),
        Some("fingerprint-git") => fingerprint_git(&arguments[1..]),
        Some("mcp-config") => print_mcp_config(&arguments[1..]),
        Some("providers") => providers(&arguments[1..]),
        Some("memory-provider") => memory_provider(&arguments[1..]),
        Some("rotate-key") => rotate_key(&arguments[1..]),
        Some("audit") => audit(&arguments[1..]),
        Some("retention") => retention(&arguments[1..]),
        Some("legal-hold") => legal_hold(&arguments[1..]),
        Some("channel") => channel(&arguments[1..]),
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

fn channel(arguments: &[String]) -> Result<(), String> {
    if arguments.first().map(String::as_str) == Some("status") {
        return channel_status(&arguments[1..]);
    }
    if arguments.first().map(String::as_str) == Some("requeue") {
        return channel_requeue(&arguments[1..]);
    }
    channel_binding(arguments)
}

fn channel_binding(arguments: &[String]) -> Result<(), String> {
    let (operation, channel_kind, channel_label) = match arguments.first().map(String::as_str) {
        Some("bind-whatsapp") => ("bound", ChannelKind::WhatsAppBusiness, "whatsapp-business"),
        Some("unbind-whatsapp") => (
            "revoked",
            ChannelKind::WhatsAppBusiness,
            "whatsapp-business",
        ),
        Some("bind-mobile-share") => ("bound", ChannelKind::MobileShare, "mobile-share"),
        Some("unbind-mobile-share") => ("revoked", ChannelKind::MobileShare, "mobile-share"),
        _ => {
            return Err(
                "usage: rembrane channel <bind-whatsapp|unbind-whatsapp|bind-mobile-share|unbind-mobile-share> --database <path> --principal <owner-or-admin-id> --workspace <id> --subject <member-id> --client <id> --request <id>"
                    .to_owned(),
            );
        }
    };
    if arguments.len() == 1 {
        return Err("channel binding options are required".to_owned());
    }
    let arguments = &arguments[1..];
    let database = option(arguments, "--database")?;
    let principal_id = PrincipalId::new(option(arguments, "--principal")?);
    let workspace_id = WorkspaceId::new(option(arguments, "--workspace")?);
    let subject_id = PrincipalId::new(option(arguments, "--subject")?);
    let client_id = ClientId::new(option(arguments, "--client")?);
    let request_id = option(arguments, "--request")?;
    let (account_lookup_key, sender_lookup_key) = channel_lookup_keys(channel_kind)?;
    let mut store =
        SqliteStore::open(database).map_err(|error| format!("cannot open database: {error}"))?;
    let binding = ChannelSenderBinding::new(
        channel_kind,
        account_lookup_key,
        sender_lookup_key,
        workspace_id.clone(),
        subject_id.clone(),
        client_id.clone(),
    )
    .map_err(|_| format!("cannot create {channel_label} sender binding"))?;
    let mut service = ChannelBindingService::new(&mut store);
    if operation == "bound" {
        service
            .create(CreateChannelBindingCommand {
                binding,
                created_by: principal_id,
                request_id: request_id.to_owned(),
            })
            .map_err(|error| format!("cannot persist {channel_label} sender binding: {error}"))?;
    } else {
        service
            .revoke(RevokeChannelBindingCommand {
                binding,
                revoked_by: principal_id,
                request_id: request_id.to_owned(),
            })
            .map_err(|error| format!("cannot revoke {channel_label} sender binding: {error}"))?;
    }
    println!(
        "{}",
        serde_json::json!({
            "channel": channel_label,
            "workspaceId": workspace_id.as_str(),
            "principalId": subject_id.as_str(),
            "clientId": client_id.as_str(),
            "status": operation
        })
    );
    Ok(())
}

fn channel_lookup_keys(channel_kind: ChannelKind) -> Result<(String, String), String> {
    let keys = if channel_kind == ChannelKind::MobileShare {
        let account_identifier = secret_environment("REMBRANE_MOBILE_SHARE_ACCOUNT_ID")?;
        let device_identifier = secret_environment("REMBRANE_MOBILE_SHARE_DEVICE_ID")?;
        let lookup_secret = referenced_secret_environment(
            "REMBRANE_MOBILE_SHARE_BINDING_LOOKUP_SECRET_REFERENCE",
            "REMBRANE_MOBILE_SHARE_BINDING_LOOKUP_SECRET",
        )?;
        let lookup = derive_mobile_binding_lookup_keys(
            lookup_secret.as_bytes().to_vec(),
            &account_identifier,
            &device_identifier,
        )
        .map_err(|_| "cannot derive mobile-share binding lookup keys".to_owned())?;
        (
            lookup.account_lookup_key().to_owned(),
            lookup.device_lookup_key().to_owned(),
        )
    } else {
        let account_identifier = secret_environment("REMBRANE_WHATSAPP_ACCOUNT_ID")?;
        let sender_identifier = secret_environment("REMBRANE_WHATSAPP_SENDER_ID")?;
        let lookup_secret = referenced_secret_environment(
            "REMBRANE_WHATSAPP_BINDING_LOOKUP_SECRET_REFERENCE",
            "REMBRANE_WHATSAPP_BINDING_LOOKUP_SECRET",
        )?;
        let lookup = derive_whatsapp_binding_lookup_keys(
            lookup_secret.as_bytes().to_vec(),
            &account_identifier,
            &sender_identifier,
        )
        .map_err(|_| "cannot derive WhatsApp binding lookup keys".to_owned())?;
        (
            lookup.account_lookup_key().to_owned(),
            lookup.sender_lookup_key().to_owned(),
        )
    };
    Ok(keys)
}

fn channel_status(arguments: &[String]) -> Result<(), String> {
    let database = option(arguments, "--database")?;
    let principal_id = PrincipalId::new(option(arguments, "--principal")?);
    let workspace_id = WorkspaceId::new(option(arguments, "--workspace")?);
    let mut store =
        SqliteStore::open(database).map_err(|error| format!("cannot open database: {error}"))?;
    let summary = ChannelInboxAdministrationService::new(&mut store)
        .summary(&workspace_id, &principal_id)
        .map_err(|error| format!("cannot inspect channel inbox: {error}"))?;
    println!(
        "{}",
        serde_json::json!({
            "workspaceId": workspace_id.as_str(),
            "pending": summary.pending(),
            "processing": summary.processing(),
            "quarantined": summary.quarantined()
        })
    );
    Ok(())
}

fn channel_requeue(arguments: &[String]) -> Result<(), String> {
    let database = option(arguments, "--database")?;
    let actor_id = PrincipalId::new(option(arguments, "--principal")?);
    let workspace_id = WorkspaceId::new(option(arguments, "--workspace")?);
    let event_id = option(arguments, "--event")?.to_owned();
    let request_id = option(arguments, "--request")?.to_owned();
    let channel = match option(arguments, "--channel")? {
        "whatsapp-business" => ChannelKind::WhatsAppBusiness,
        "imessage-extension" => ChannelKind::IMessageExtension,
        "mobile-share" => ChannelKind::MobileShare,
        _ => {
            return Err(
                "channel must be whatsapp-business, imessage-extension, or mobile-share".to_owned(),
            );
        }
    };
    let mut store =
        SqliteStore::open(database).map_err(|error| format!("cannot open database: {error}"))?;
    ChannelInboxAdministrationService::new(&mut store)
        .requeue(RequeueChannelMessageCommand {
            workspace_id: workspace_id.clone(),
            channel,
            event_id: event_id.clone(),
            actor_id,
            request_id,
        })
        .map_err(|error| format!("cannot requeue channel message: {error}"))?;
    println!(
        "{}",
        serde_json::json!({
            "workspaceId": workspace_id.as_str(),
            "channel": channel.label(),
            "eventId": event_id,
            "status": "pending"
        })
    );
    Ok(())
}

fn secret_environment(name: &str) -> Result<Zeroizing<String>, String> {
    let value = Zeroizing::new(
        std::env::var(name).map_err(|_| format!("{name} is required in the environment"))?,
    );
    if value.is_empty() {
        return Err(format!("{name} is empty"));
    }
    Ok(value)
}

fn referenced_secret_environment(
    locator_name: &str,
    default_variable: &str,
) -> Result<Zeroizing<String>, String> {
    let locator = match std::env::var(locator_name) {
        Ok(locator) => locator,
        Err(std::env::VarError::NotPresent) => String::new(),
        Err(_) => return Err(format!("cannot read {locator_name}")),
    };
    let reference = selected_secret_reference(&locator, default_variable)?;
    LocalSecretResolver
        .resolve(&reference)
        .map_err(|_| format!("secret referenced by {locator_name} is unavailable or invalid"))
}

fn selected_secret_reference(
    locator: &str,
    default_variable: &str,
) -> Result<SecretReference, String> {
    if locator.is_empty() {
        SecretReference::environment(default_variable)
            .map_err(|_| "invalid default secret reference".to_owned())
    } else {
        locator
            .parse()
            .map_err(|_| "invalid secret reference".to_owned())
    }
}

fn rotate_key(arguments: &[String]) -> Result<(), String> {
    let (mut store, principal_id, workspace_id) = encrypted_store(arguments)?;
    let provider = ConfiguredRecordCipher::from_environment()
        .map_err(|error| format!("cannot load rotation key provider: {error}"))?;
    let completed = MemberLifecycleService::new(&mut store)
        .orchestrate_key_rotation(
            workspace_id,
            principal_id,
            |workspace_id, generation, recipients| {
                provider
                    .rotate_workspace_key(workspace_id, generation, recipients)
                    .map_err(|_| ApplicationError::StorageUnavailable)
            },
        )
        .map_err(|error| format!("cannot rotate workspace key: {error}"))?;
    println!(
        "{}",
        serde_json::json!({
            "workspaceId": completed.workspace_id().as_str(),
            "generation": completed.generation(),
            "keyId": completed.completed_key_id(),
            "status": "completed"
        })
    );
    Ok(())
}

fn audit(arguments: &[String]) -> Result<(), String> {
    if arguments.first().map(String::as_str) != Some("list") {
        return Err("usage: rembrane audit list --database <path> --principal <id> --workspace <id> [--after <epoch-seconds>] [--limit <items>]".to_owned());
    }
    let arguments = &arguments[1..];
    let (store, principal_id, workspace_id) = encrypted_store(arguments)?;
    require_workspace_administrator(&store, &workspace_id, &principal_id)?;
    let after =
        optional_option(arguments, "--after").map_or(Ok(0), |value| parse_u64(value, "--after"))?;
    let limit = optional_option(arguments, "--limit")
        .map_or(Ok(100), |value| parse_usize(value, "--limit"))?;
    let events = store
        .list_administrative_audit(&workspace_id, after, limit)
        .map_err(|error| format!("cannot list administrative audit: {error}"))?;
    println!(
        "{}",
        serde_json::Value::Array(
            events
                .iter()
                .map(|event| {
                    serde_json::json!({
                        "id": event.id().as_str(),
                        "workspaceId": event.workspace_id().as_str(),
                        "actorId": event.actor_id().as_str(),
                        "action": event.action().label(),
                        "targetKind": event.target_kind().label(),
                        "targetId": event.target_id(),
                        "requestId": event.request_id(),
                        "occurredAtEpochSeconds": event.occurred_at_epoch_seconds()
                    })
                })
                .collect()
        )
    );
    Ok(())
}

fn retention(arguments: &[String]) -> Result<(), String> {
    if arguments.first().map(String::as_str) == Some("purge") {
        let arguments = &arguments[1..];
        let (mut store, principal_id, workspace_id) = encrypted_store(arguments)?;
        let maximum_items = optional_option(arguments, "--limit")
            .map_or(Ok(100), |value| parse_usize(value, "--limit"))?;
        let now_epoch_seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_owned())?
            .as_secs();
        let result = RetentionService::new(&mut store)
            .execute_purge(ExecuteRetentionPurgeCommand {
                workspace_id,
                executed_by: principal_id,
                now_epoch_seconds,
                maximum_items,
            })
            .map_err(|error| format!("cannot execute retention purge: {error}"))?;
        println!(
            "{}",
            serde_json::json!({
                "memories": result.memories,
                "checkpoints": result.checkpoints,
                "travelResearch": result.travel_research,
                "disclosures": result.disclosures,
                "canonicalEvents": result.canonical_events,
                "total": result.total()
            })
        );
        return Ok(());
    }
    if arguments.first().map(String::as_str) != Some("set") {
        return Err("usage: rembrane retention set --database <path> --principal <id> --workspace <id> --request <id> --memory-days <days|forever> --checkpoint-days <days|forever> --travel-days <days|forever> --disclosure-days <days|forever> --event-days <days|forever> --audit-days <days|forever> [--expected-version <n>]".to_owned());
    }
    let arguments = &arguments[1..];
    let (mut store, principal_id, workspace_id) = encrypted_store(arguments)?;
    let expected_version = optional_option(arguments, "--expected-version")
        .map(|value| parse_u64(value, "--expected-version"))
        .transpose()?;
    let version = match expected_version {
        Some(value) => value
            .checked_add(1)
            .ok_or_else(|| "retention policy version is exhausted".to_owned())?,
        None => 1,
    };
    let policy = WorkspaceRetentionPolicy::new(
        workspace_id,
        version,
        retention_period_option(arguments, "--memory-days")?,
        retention_period_option(arguments, "--checkpoint-days")?,
        retention_period_option(arguments, "--travel-days")?,
        retention_period_option(arguments, "--disclosure-days")?,
        retention_period_option(arguments, "--event-days")?,
        retention_period_option(arguments, "--audit-days")?,
    )
    .map_err(|error| format!("invalid retention policy: {error}"))?;
    let policy = RetentionService::new(&mut store)
        .set_policy(SetRetentionPolicyCommand {
            policy,
            expected_version,
            changed_by: principal_id,
            request_id: option(arguments, "--request")?.to_owned(),
        })
        .map_err(|error| format!("cannot set retention policy: {error}"))?;
    println!(
        "{}",
        serde_json::json!({
            "workspaceId": policy.workspace_id().as_str(),
            "version": policy.version()
        })
    );
    Ok(())
}

fn legal_hold(arguments: &[String]) -> Result<(), String> {
    let operation = arguments
        .first()
        .map(String::as_str)
        .ok_or_else(|| "legal-hold operation is required".to_owned())?;
    let arguments = &arguments[1..];
    let (mut store, principal_id, workspace_id) = encrypted_store(arguments)?;
    let hold_id = LegalHoldId::new(option(arguments, "--hold")?);
    let request_id = option(arguments, "--request")?.to_owned();
    let hold = match operation {
        "place" => RetentionService::new(&mut store).place_legal_hold(PlaceLegalHoldCommand {
            workspace_id,
            hold_id,
            placed_by: principal_id,
            request_id,
        }),
        "release" => {
            RetentionService::new(&mut store).release_legal_hold(ReleaseLegalHoldCommand {
                workspace_id,
                hold_id,
                released_by: principal_id,
                request_id,
            })
        }
        _ => {
            return Err("usage: rembrane legal-hold <place|release> --database <path> --principal <id> --workspace <id> --hold <id> --request <id>".to_owned());
        }
    }
    .map_err(|error| format!("cannot {operation} legal hold: {error}"))?;
    println!(
        "{}",
        serde_json::json!({
            "workspaceId": hold.workspace_id().as_str(),
            "holdId": hold.id().as_str(),
            "version": hold.version(),
            "status": match hold.status() {
                rembrane_domain::LegalHoldStatus::Active => "active",
                rembrane_domain::LegalHoldStatus::Released => "released"
            }
        })
    );
    Ok(())
}

fn require_workspace_administrator<C>(
    store: &SqliteStore<C>,
    workspace_id: &WorkspaceId,
    principal_id: &PrincipalId,
) -> Result<(), String> {
    let membership = store
        .find_membership(workspace_id, principal_id)
        .map_err(|error| format!("cannot inspect membership: {error}"))?
        .filter(|membership| membership.is_active() && membership.can_manage_members());
    if membership.is_none() {
        return Err("workspace administrator access is required".to_owned());
    }
    Ok(())
}

fn retention_period_option(arguments: &[String], name: &str) -> Result<RetentionPeriod, String> {
    let value = option(arguments, name)?;
    if value == "forever" {
        return Ok(RetentionPeriod::Forever);
    }
    let days = value
        .parse::<u32>()
        .map_err(|_| format!("{name} must be a day count or forever"))?;
    RetentionPeriod::days(days).map_err(|error| format!("invalid {name}: {error}"))
}

fn parse_u64(value: &str, name: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|_| format!("{name} must be a non-negative integer"))
}

fn parse_usize(value: &str, name: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("{name} must be a non-negative integer"))
}

fn memory_provider(arguments: &[String]) -> Result<(), String> {
    let required_privacy_mode = requested_memory_privacy(arguments)?;
    let provider = ConfiguredMemoryProvider::from_environment(&memory_provider_check_policy(
        required_privacy_mode,
    )?)
    .map_err(|error| format!("memory provider check failed: {error}"))?;
    let manifest = provider.connection().manifest();
    let limits = manifest.limits();
    println!(
        "{}",
        serde_json::json!({
            "providerId": manifest.id(),
            "providerVersion": manifest.version(),
            "protocolVersion": format!(
                "{}.{}",
                manifest.protocol_version().major,
                manifest.protocol_version().minor
            ),
            "privacyMode": memory_privacy_mode_name(manifest.privacy_mode()),
            "requiredPrivacyMode": memory_privacy_mode_name(required_privacy_mode),
            "capabilities": manifest
                .capabilities()
                .iter()
                .map(|capability| capability.as_str())
                .collect::<Vec<_>>(),
            "supportedDomains": manifest.supported_domains(),
            "limits": {
                "maximumContextItems": limits.maximum_context_items,
                "maximumContextBytes": limits.maximum_context_bytes,
                "maximumEventBatchItems": limits.maximum_event_batch_items,
                "maximumSyncBatchItems": limits.maximum_sync_batch_items
            },
            "result": "pass"
        })
    );
    Ok(())
}

fn requested_memory_privacy(arguments: &[String]) -> Result<MemoryProviderPrivacyMode, String> {
    match arguments {
        [command] if command == "check" => Ok(MemoryProviderPrivacyMode::EndToEndEncrypted),
        [command, flag, value] if command == "check" && flag == "--privacy" => {
            match value.as_str() {
                "end-to-end-encrypted" => Ok(MemoryProviderPrivacyMode::EndToEndEncrypted),
                "trusted-boundary" => Ok(MemoryProviderPrivacyMode::TrustedBoundary),
                "provider-plaintext" => Ok(MemoryProviderPrivacyMode::ProviderPlaintext),
                _ => Err(memory_provider_usage()),
            }
        }
        _ => Err(memory_provider_usage()),
    }
}

fn memory_provider_usage() -> String {
    "usage: rembrane memory-provider check \
     [--privacy <end-to-end-encrypted|trusted-boundary|provider-plaintext>]"
        .to_owned()
}

fn memory_provider_check_policy(
    required_privacy_mode: MemoryProviderPrivacyMode,
) -> Result<MemoryProviderPolicy, String> {
    MemoryProviderPolicy::new(
        CURRENT_MEMORY_PROVIDER_PROTOCOL,
        MemoryProviderTransport::Https,
        vec![
            MemoryProviderCapability::ResolveContext,
            MemoryProviderCapability::ResolveQuestion,
            MemoryProviderCapability::RecordEvent,
            MemoryProviderCapability::ProposeMemory,
            MemoryProviderCapability::CheckpointActivity,
            MemoryProviderCapability::RecordDisclosure,
            MemoryProviderCapability::DeleteMemory,
            MemoryProviderCapability::ExplainMemory,
            MemoryProviderCapability::SyncPull,
            MemoryProviderCapability::SyncPush,
        ],
        vec![required_privacy_mode],
        MemoryProviderLimits {
            maximum_context_items: 1,
            maximum_context_bytes: 1,
            maximum_event_batch_items: 1,
            maximum_sync_batch_items: 1,
        },
    )
    .map_err(|error| format!("cannot construct memory provider check policy: {error}"))
}

const fn memory_privacy_mode_name(mode: MemoryProviderPrivacyMode) -> &'static str {
    match mode {
        MemoryProviderPrivacyMode::EndToEndEncrypted => "end_to_end_encrypted",
        MemoryProviderPrivacyMode::TrustedBoundary => "trusted_boundary",
        MemoryProviderPrivacyMode::ProviderPlaintext => "provider_plaintext",
    }
}

const PROVIDER_REGISTRY: &str = include_str!("../../../spec/provider-registry.json");

fn providers(arguments: &[String]) -> Result<(), String> {
    match arguments.first().map(String::as_str) {
        Some("list") if arguments.len() == 1 => {
            print!("{PROVIDER_REGISTRY}");
            Ok(())
        }
        Some("list") => Err("providers list does not accept additional arguments".to_owned()),
        Some("check") => {
            println!("{}", check_provider(arguments)?);
            Ok(())
        }
        Some("test") => {
            println!("{}", test_provider(arguments)?);
            Ok(())
        }
        Some(command) => Err(format!("unknown providers command: {command}")),
        None => {
            Err("providers requires a command; supported commands: list, check, test".to_owned())
        }
    }
}

fn check_provider(arguments: &[String]) -> Result<String, String> {
    let allow_experimental = arguments
        .iter()
        .any(|argument| argument == "--allow-experimental");
    let allow_provider_plaintext = arguments
        .iter()
        .any(|argument| argument == "--allow-provider-plaintext");
    let expected_arguments =
        5 + usize::from(allow_experimental) + usize::from(allow_provider_plaintext);
    if arguments.len() != expected_arguments
        || arguments
            .iter()
            .filter(|argument| *argument == "--allow-experimental")
            .count()
            > 1
        || arguments
            .iter()
            .filter(|argument| *argument == "--allow-provider-plaintext")
            .count()
            > 1
    {
        return Err(
            "usage: rembrane providers check --provider <id> --adapter-version <version> \
             [--allow-experimental] [--allow-provider-plaintext]"
                .to_owned(),
        );
    }
    check_provider_registry(
        PROVIDER_REGISTRY,
        option(arguments, "--provider")?,
        option(arguments, "--adapter-version")?,
        allow_experimental,
        allow_provider_plaintext,
    )
}

fn check_provider_registry(
    registry: &str,
    provider_id: &str,
    adapter_version: &str,
    allow_experimental: bool,
    allow_provider_plaintext: bool,
) -> Result<String, String> {
    let registry: serde_json::Value = serde_json::from_str(registry)
        .map_err(|_| "provider registry is not valid JSON".to_owned())?;
    let providers = registry
        .get("providers")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "provider registry has no provider array".to_owned())?;
    let matches = providers
        .iter()
        .filter(|provider| {
            provider.get("id").and_then(serde_json::Value::as_str) == Some(provider_id)
        })
        .collect::<Vec<_>>();
    let [provider] = matches.as_slice() else {
        return Err("provider registry does not contain exactly one matching provider".to_owned());
    };
    if provider
        .get("adapterVersion")
        .and_then(serde_json::Value::as_str)
        != Some(adapter_version)
    {
        return Err("provider adapter version does not match registry evidence".to_owned());
    }
    validate_provider_selection_evidence(provider, adapter_version)?;
    let status = provider
        .get("status")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "provider registry status is invalid".to_owned())?;
    let eligibility = match status {
        "compatible" => "compatible",
        "experimental" if allow_experimental => "experimental-opt-in",
        "experimental" => {
            return Err("experimental provider requires --allow-experimental".to_owned());
        }
        "deprecated" => {
            return Err("deprecated provider is not eligible for new selection".to_owned());
        }
        "revoked" => return Err("revoked provider is not eligible for selection".to_owned()),
        _ => return Err("provider registry status is invalid".to_owned()),
    };
    let plaintext_processing = provider
        .get("plaintextProcessing")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| "provider plaintext policy is invalid".to_owned())?;
    if plaintext_processing && !allow_provider_plaintext {
        return Err("plaintext provider requires --allow-provider-plaintext".to_owned());
    }
    let conformance = provider
        .get("conformance")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "provider conformance evidence is missing".to_owned())?;
    let source_revision = provider
        .pointer("/source/revision")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "provider source revision is invalid".to_owned())?;
    serde_json::to_string(&serde_json::json!({
        "schemaVersion": 1,
        "provider": provider_id,
        "adapterVersion": adapter_version,
        "status": status,
        "eligibility": eligibility,
        "protocolVersion": conformance.get("protocolVersion"),
        "deploymentModes": provider.get("deploymentModes"),
        "plaintextProcessing": plaintext_processing,
        "approvals": {
            "experimental": status == "experimental" && allow_experimental,
            "providerPlaintext": plaintext_processing && allow_provider_plaintext,
        },
        "evidence": {
            "suiteId": conformance.get("suiteId"),
            "suiteVersion": conformance.get("suiteVersion"),
            "profileSha256": conformance.get("profileSha256"),
            "testedAt": conformance.get("testedAt"),
            "sourceRevision": source_revision,
        },
    }))
    .map_err(|_| "could not serialize provider eligibility".to_owned())
}

fn validate_provider_selection_evidence(
    provider: &serde_json::Value,
    adapter_version: &str,
) -> Result<(), String> {
    let protocols = provider
        .get("protocolVersions")
        .and_then(serde_json::Value::as_array)
        .filter(|protocols| {
            !protocols.is_empty()
                && protocols.iter().all(|protocol| {
                    protocol.as_str().is_some_and(|value| {
                        value.len() >= 3
                            && value.len() <= 20
                            && value.split_once('.').is_some_and(|(major, minor)| {
                                !major.is_empty()
                                    && !minor.is_empty()
                                    && major.bytes().all(|byte| byte.is_ascii_digit())
                                    && minor.bytes().all(|byte| byte.is_ascii_digit())
                            })
                    })
                })
        })
        .ok_or_else(|| "provider protocol evidence is invalid".to_owned())?;
    let _deployment_modes = provider
        .get("deploymentModes")
        .and_then(serde_json::Value::as_array)
        .filter(|modes| !modes.is_empty() && modes.iter().all(serde_json::Value::is_string))
        .ok_or_else(|| "provider deployment evidence is invalid".to_owned())?;
    let _source_revision = provider
        .pointer("/source/revision")
        .and_then(serde_json::Value::as_str)
        .filter(|revision| {
            (7..=64).contains(&revision.len())
                && revision
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| "provider source revision is invalid".to_owned())?;
    let conformance = provider
        .get("conformance")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "provider conformance evidence is missing".to_owned())?;
    let protocol = conformance
        .get("protocolVersion")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "provider conformance protocol is invalid".to_owned())?;
    conformance
        .get("testedAt")
        .and_then(serde_json::Value::as_str)
        .filter(|tested_at| tested_at.ends_with('Z') && tested_at.len() == 20)
        .ok_or_else(|| "provider conformance timestamp is invalid".to_owned())?;
    if conformance
        .get("result")
        .and_then(serde_json::Value::as_str)
        != Some("pass")
        || conformance
            .get("suiteId")
            .and_then(serde_json::Value::as_str)
            != Some(SEMANTIC_PROVIDER_CONFORMANCE_SUITE_ID)
        || conformance
            .get("suiteVersion")
            .and_then(serde_json::Value::as_str)
            != Some(SEMANTIC_PROVIDER_CONFORMANCE_SUITE_VERSION)
        || conformance
            .get("profileSha256")
            .and_then(serde_json::Value::as_str)
            != Some(SEMANTIC_PROVIDER_CONFORMANCE_PROFILE_SHA256)
        || conformance
            .get("providerVersion")
            .and_then(serde_json::Value::as_str)
            != Some(adapter_version)
        || !protocols
            .iter()
            .any(|candidate| candidate.as_str() == Some(protocol))
    {
        return Err("provider conformance evidence is not eligible".to_owned());
    }
    let cases = conformance
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "provider conformance cases are invalid".to_owned())?;
    if cases.len() != SEMANTIC_PROVIDER_CONFORMANCE_CASES.len()
        || cases
            .iter()
            .zip(SEMANTIC_PROVIDER_CONFORMANCE_CASES)
            .any(|(case, expected)| {
                case.get("id").and_then(serde_json::Value::as_str) != Some(expected)
                    || case.get("result").and_then(serde_json::Value::as_str) != Some("pass")
            })
    {
        return Err("provider conformance cases are not eligible".to_owned());
    }
    Ok(())
}

fn test_provider(arguments: &[String]) -> Result<String, String> {
    if arguments.len() < 5 {
        return Err(
            "usage: rembrane providers test --provider <id> --namespace <unique-name> \
             [--allow-provider-plaintext]"
                .to_owned(),
        );
    }
    let provider_id = option(arguments, "--provider")?;
    let namespace = option(arguments, "--namespace")?;
    match provider_id {
        "rembrane.native" => {
            if arguments.len() != 5 {
                return Err("rembrane.native accepts only --provider and --namespace".to_owned());
            }
            let report = verify_semantic_provider(&mut NativeSemanticProvider::new(), namespace)
                .map_err(|error| format!("provider conformance failed: {error}"))?;
            serialize_provider_conformance(&report)
        }
        "mem0.oss" => {
            if arguments.len() != 6
                || arguments
                    .iter()
                    .filter(|argument| *argument == "--allow-provider-plaintext")
                    .count()
                    != 1
            {
                return Err("Mem0 conformance sends disposable plaintext; rerun with \
                     --allow-provider-plaintext after verifying the target"
                    .to_owned());
            }
            validate_external_conformance_namespace(namespace)?;
            let base_url = secret_environment("MEM0_BASE_URL")?;
            let api_key = std::env::var("MEM0_API_KEY")
                .map_err(|_| "MEM0_API_KEY is required in the environment".to_owned())?;
            let lookup_secret = secret_environment("MEM0_WORKSPACE_LOOKUP_SECRET")?;
            let mut provider = Mem0SemanticProvider::from_http(
                &base_url,
                api_key,
                lookup_secret.as_bytes().to_vec(),
            )
            .map_err(|error| format!("cannot configure Mem0 provider: {error}"))?;
            let report = verify_semantic_provider(&mut provider, namespace)
                .map_err(|error| format!("provider conformance failed: {error}"))?;
            serialize_provider_conformance(&report)
        }
        "supermemory.v5" => {
            if arguments.len() != 6
                || arguments
                    .iter()
                    .filter(|argument| *argument == "--allow-provider-plaintext")
                    .count()
                    != 1
            {
                return Err(
                    "Supermemory conformance sends disposable plaintext; rerun with \
                     --allow-provider-plaintext after verifying the target"
                        .to_owned(),
                );
            }
            validate_external_conformance_namespace(namespace)?;
            let base_url = secret_environment("SUPERMEMORY_BASE_URL")?;
            let api_key = std::env::var("SUPERMEMORY_API_KEY")
                .map_err(|_| "SUPERMEMORY_API_KEY is required in the environment".to_owned())?;
            let lookup_secret = secret_environment("SUPERMEMORY_WORKSPACE_LOOKUP_SECRET")?;
            let mut provider = SupermemorySemanticProvider::from_http(
                &base_url,
                api_key,
                lookup_secret.as_bytes().to_vec(),
            )
            .map_err(|error| format!("cannot configure Supermemory provider: {error}"))?;
            let report = verify_semantic_provider(&mut provider, namespace)
                .map_err(|error| format!("provider conformance failed: {error}"))?;
            serialize_provider_conformance(&report)
        }
        _ => Err(format!(
            "provider {provider_id} is not installed in this CLI build"
        )),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderConformanceOutput<'report> {
    suite_id: &'static str,
    suite_version: &'static str,
    profile_sha256: &'static str,
    provider: &'report str,
    provider_version: &'report str,
    protocol_version: String,
    namespace: &'report str,
    result: &'static str,
    cases: Vec<ProviderConformanceCaseOutput>,
}

#[derive(Serialize)]
struct ProviderConformanceCaseOutput {
    id: &'static str,
    result: &'static str,
}

fn serialize_provider_conformance(
    report: &SemanticProviderConformanceReport,
) -> Result<String, String> {
    let protocol = report.protocol_version();
    serde_json::to_string(&ProviderConformanceOutput {
        suite_id: SEMANTIC_PROVIDER_CONFORMANCE_SUITE_ID,
        suite_version: SEMANTIC_PROVIDER_CONFORMANCE_SUITE_VERSION,
        profile_sha256: SEMANTIC_PROVIDER_CONFORMANCE_PROFILE_SHA256,
        provider: report.provider_id(),
        provider_version: report.provider_version(),
        protocol_version: format!("{}.{}", protocol.major, protocol.minor),
        namespace: report.namespace(),
        result: "pass",
        cases: report
            .case_ids()
            .iter()
            .map(|id| ProviderConformanceCaseOutput { id, result: "pass" })
            .collect(),
    })
    .map_err(|_| "could not serialize provider conformance evidence".to_owned())
}

fn validate_external_conformance_namespace(namespace: &str) -> Result<(), String> {
    if !(16..=80).contains(&namespace.len())
        || namespace
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(
            "external provider namespace must contain 16-80 ASCII letters, digits, '.', '_', or \
             '-' and should include a freshly generated random suffix"
                .to_owned(),
        );
    }
    Ok(())
}

const MCP_BASE_ENVIRONMENT_VARIABLES: [&str; 6] = [
    "REMBRANE_DATABASE",
    "REMBRANE_PRINCIPAL_ID",
    "REMBRANE_WORKSPACE_ID",
    "REMBRANE_CLIENT_ID",
    "REMBRANE_READ_SCOPES",
    "REMBRANE_READ_PERMISSIONS",
];

fn print_mcp_config(arguments: &[String]) -> Result<(), String> {
    if arguments == ["clients"] {
        println!(
            "{}",
            serde_json::to_string(&mcp_client_catalog())
                .map_err(|_| "cannot serialize MCP client catalog".to_owned())?
        );
        return Ok(());
    }
    let client = option(arguments, "--client")?;
    let server_binary = option(arguments, "--server-binary")?;
    validate_mcp_server_binary(server_binary)?;
    let key_provider = optional_option(arguments, "--key-provider").unwrap_or("environment");
    let environment = mcp_environment_variables(key_provider)?;
    let config = render_mcp_config(client, server_binary, &environment)?;
    println!("{config}");
    Ok(())
}

fn render_mcp_config(
    client: &str,
    server_binary: &str,
    environment: &[&str],
) -> Result<String, String> {
    Ok(match client {
        "codex" => codex_mcp_config(server_binary, environment),
        "claude-code" => claude_mcp_config(server_binary, environment),
        "gemini-cli" => gemini_mcp_config(server_binary, environment),
        "cursor" => cursor_mcp_config(server_binary, environment),
        "vscode" => vscode_mcp_config(server_binary, environment),
        "zed" => zed_mcp_config(server_binary),
        "opencode" => opencode_mcp_config(server_binary, environment),
        "generic" => generic_mcp_config(server_binary, environment),
        _ => {
            return Err(
                "--client must be codex, claude-code, gemini-cli, cursor, vscode, zed, opencode, or generic".to_owned(),
            );
        }
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpClientDescriptor {
    id: &'static str,
    config_format: &'static str,
    environment_mode: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpClientCatalog {
    schema_version: u32,
    clients: [McpClientDescriptor; 8],
}

fn mcp_client_catalog() -> McpClientCatalog {
    McpClientCatalog {
        schema_version: 1,
        clients: [
            McpClientDescriptor {
                id: "codex",
                config_format: "toml",
                environment_mode: "inherit-allowlist",
            },
            McpClientDescriptor {
                id: "claude-code",
                config_format: "json",
                environment_mode: "placeholder",
            },
            McpClientDescriptor {
                id: "gemini-cli",
                config_format: "json",
                environment_mode: "placeholder",
            },
            McpClientDescriptor {
                id: "cursor",
                config_format: "json",
                environment_mode: "placeholder",
            },
            McpClientDescriptor {
                id: "vscode",
                config_format: "json",
                environment_mode: "placeholder",
            },
            McpClientDescriptor {
                id: "zed",
                config_format: "json",
                environment_mode: "process-inherited",
            },
            McpClientDescriptor {
                id: "opencode",
                config_format: "json",
                environment_mode: "placeholder",
            },
            McpClientDescriptor {
                id: "generic",
                config_format: "rembrane-stdio-manifest-v1",
                environment_mode: "required-environment",
            },
        ],
    }
}

fn validate_mcp_server_binary(server_binary: &str) -> Result<(), String> {
    if server_binary.trim().is_empty() || server_binary.len() > 4_096 {
        return Err("--server-binary must contain a bounded executable command".to_owned());
    }
    if server_binary.chars().any(char::is_control) {
        return Err("--server-binary must not contain control characters".to_owned());
    }
    Ok(())
}

fn mcp_environment_variables(key_provider: &str) -> Result<Vec<&'static str>, String> {
    let mut variables = MCP_BASE_ENVIRONMENT_VARIABLES.to_vec();
    match key_provider {
        "environment" => variables.extend([
            "REMBRANE_WORKSPACE_KEY_ID",
            "REMBRANE_WORKSPACE_KEY_REFERENCE",
        ]),
        "macos-keychain" => variables.extend([
            "REMBRANE_KEY_PROVIDER",
            "REMBRANE_WORKSPACE_KEY_ID",
            "REMBRANE_KEYCHAIN_SERVICE",
            "REMBRANE_KEYCHAIN_ACCOUNT",
            "REMBRANE_KEYCHAIN_HISTORICAL_KEYS",
        ]),
        "linux-secret-service" => variables.extend([
            "REMBRANE_KEY_PROVIDER",
            "REMBRANE_WORKSPACE_KEY_ID",
            "REMBRANE_SECRET_SERVICE_SERVICE",
            "REMBRANE_SECRET_SERVICE_ACCOUNT",
            "REMBRANE_SECRET_SERVICE_HISTORICAL_KEYS",
        ]),
        "windows-dpapi" => variables.extend([
            "REMBRANE_KEY_PROVIDER",
            "REMBRANE_WORKSPACE_KEY_ID",
            "REMBRANE_DPAPI_BLOB_PATH",
            "REMBRANE_DPAPI_HISTORICAL_KEYS",
        ]),
        "http" => variables.extend([
            "REMBRANE_KEY_PROVIDER",
            "REMBRANE_KEY_PROVIDER_BASE_URL",
            "REMBRANE_KEY_PROVIDER_TOKEN_REFERENCE",
        ]),
        provider => {
            return Err(format!(
                "unsupported --key-provider {provider}; expected environment, macos-keychain, linux-secret-service, windows-dpapi, or http"
            ));
        }
    }
    Ok(variables)
}

fn generic_mcp_config(server_binary: &str, environment: &[&str]) -> String {
    let variables = environment
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

fn codex_mcp_config(server_binary: &str, environment: &[&str]) -> String {
    let variables = environment
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

fn claude_mcp_config(server_binary: &str, variables: &[&str]) -> String {
    let environment = variables
        .iter()
        .map(|variable| {
            (
                (*variable).to_owned(),
                serde_json::Value::String(format!("${{{variable}}}")),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    serde_json::json!({
        "mcpServers": {
            "rembrane": {
                "type": "stdio",
                "command": server_binary,
                "args": [],
                "env": environment
            }
        }
    })
    .to_string()
}

fn gemini_mcp_config(server_binary: &str, variables: &[&str]) -> String {
    let environment = variables
        .iter()
        .map(|variable| {
            (
                (*variable).to_owned(),
                serde_json::Value::String(format!("${{{variable}}}")),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    serde_json::json!({
        "mcpServers": {
            "rembrane": {
                "command": server_binary,
                "args": [],
                "env": environment,
                "description": "Encrypted central memory through local Rembrane MCP"
            }
        }
    })
    .to_string()
}

fn cursor_mcp_config(server_binary: &str, variables: &[&str]) -> String {
    let environment = variables
        .iter()
        .map(|variable| {
            (
                (*variable).to_owned(),
                serde_json::Value::String(format!("${{env:{variable}}}")),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    serde_json::json!({
        "mcpServers": {
            "rembrane": {
                "type": "stdio",
                "command": server_binary,
                "args": [],
                "env": environment
            }
        }
    })
    .to_string()
}

fn vscode_mcp_config(server_binary: &str, variables: &[&str]) -> String {
    let environment = variables
        .iter()
        .map(|variable| {
            (
                (*variable).to_owned(),
                serde_json::Value::String(format!("${{env:{variable}}}")),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    serde_json::json!({
        "servers": {
            "rembrane": {
                "type": "stdio",
                "command": server_binary,
                "args": [],
                "env": environment
            }
        }
    })
    .to_string()
}

fn zed_mcp_config(server_binary: &str) -> String {
    serde_json::json!({
        "context_servers": {
            "rembrane": {
                "command": server_binary,
                "args": [],
                "env": {}
            }
        }
    })
    .to_string()
}

fn opencode_mcp_config(server_binary: &str, variables: &[&str]) -> String {
    let environment = variables
        .iter()
        .map(|variable| {
            (
                (*variable).to_owned(),
                serde_json::Value::String(format!("{{env:{variable}}}")),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    serde_json::json!({
        "$schema": "https://opencode.ai/config.json",
        "mcp": {
            "rembrane": {
                "type": "local",
                "command": [server_binary],
                "enabled": true,
                "environment": environment
            }
        }
    })
    .to_string()
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

fn git_output(repository: &std::path::Path, arguments: &[&str]) -> Result<String, String> {
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
    let temporary = destination.with_extension(format!("encrypted-snapshot-{}", unique_suffix()?));
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
        let principal_id = PrincipalId::new(option(arguments, "--principal")?);
        let workspace_id = WorkspaceId::new(option(arguments, "--workspace")?);
        let cipher = ConfiguredRecordCipher::from_environment()
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

fn write_export(snapshot: &std::path::Path, destination: &std::path::Path) -> Result<(), String> {
    use std::io::Write;

    let payload_length = snapshot
        .metadata()
        .map_err(|error| format!("cannot inspect snapshot: {error}"))?
        .len();
    let mut input =
        std::fs::File::open(snapshot).map_err(|error| format!("cannot open snapshot: {error}"))?;
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

fn read_export(source: &std::path::Path, destination: &std::path::Path) -> Result<(), String> {
    use std::io::{Read, Write};

    let mut input =
        std::fs::File::open(source).map_err(|error| format!("cannot open export: {error}"))?;
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
        &mut std::io::Read::by_ref(&mut input).take(payload_length),
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
    let (role, memory_count, event_count, checkpoint_count) =
        verify_installation(&store, &workspace_id, &principal_id)?;

    println!("Rembrane doctor: ready");
    println!("Database schema: compatible");
    println!("Workspace: {workspace_id}");
    println!("Principal: {principal_id}");
    println!("Membership: active ({role:?})");
    println!("Workspace key: loaded");
    println!("Authenticated encrypted records: {memory_count}");
    println!("Readable memories: {memory_count}");
    println!("Authenticated events: {event_count}");
    println!("Authenticated checkpoints: {checkpoint_count}");
    println!("Secret sources: {}", configured_secret_sources().join(", "));
    if arguments.iter().any(|argument| argument == "--privacy") {
        print_privacy_diagnostics()?;
    }
    Ok(())
}

fn print_privacy_diagnostics() -> Result<(), String> {
    let configured_scopes =
        std::env::var("REMBRANE_READ_SCOPES").unwrap_or_else(|_| "global".to_owned());
    let scopes = rembrane_config::parse_read_scopes(&configured_scopes)
        .map_err(|error| format!("invalid REMBRANE_READ_SCOPES configuration: {error}"))?;
    validate_configured_provider_profiles()?;

    println!("Privacy diagnostics:");
    println!("Processing location: local trusted boundary");
    println!("Encryption key provider: {}", configured_key_provider()?);
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
            "SUPERMEMORY_BASE_URL",
            "SUPERMEMORY_API_KEY",
            ProviderKind::Supermemory,
        ),
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
        ProviderConnection::remote(kind, endpoint, credentials, ProviderPlacement::External)
            .map_err(|error| format!("invalid {endpoint_variable} configuration: {error}"))?;
    }
    Ok(())
}

fn configured_secret_sources() -> Vec<&'static str> {
    let mut sources = match std::env::var("REMBRANE_KEY_PROVIDER")
        .unwrap_or_else(|_| "environment".to_owned())
        .as_str()
    {
        "macos-keychain" => vec!["macOS Keychain"],
        "linux-secret-service" => vec!["Linux Secret Service"],
        "windows-dpapi" => vec!["Windows DPAPI"],
        "http" => vec!["REMBRANE_KEY_PROVIDER_TOKEN"],
        _ => vec!["REMBRANE_WORKSPACE_KEY_ID", "REMBRANE_WORKSPACE_KEY_HEX"],
    };
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

fn configured_key_provider() -> Result<&'static str, String> {
    match std::env::var("REMBRANE_KEY_PROVIDER")
        .unwrap_or_else(|_| "environment".to_owned())
        .as_str()
    {
        "environment" => Ok("environment (development only)"),
        "macos-keychain" => Ok("macOS Keychain"),
        "linux-secret-service" => Ok("Linux Secret Service"),
        "windows-dpapi" => Ok("Windows DPAPI (current user)"),
        "http" => Ok("authenticated HTTP key provider"),
        provider => Err(format!(
            "unsupported REMBRANE_KEY_PROVIDER {provider}; expected environment, macos-keychain, linux-secret-service, windows-dpapi, or http"
        )),
    }
}

fn configured_outbound_endpoints() -> Vec<(&'static str, String)> {
    [
        "MEM0_BASE_URL",
        "GRAPHITI_BASE_URL",
        "MEMORY_OBJECT_ENDPOINT",
        "REMBRANE_REMOTE_MCP_URL",
        "REMBRANE_KEY_PROVIDER_BASE_URL",
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
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
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
) -> Result<(WorkspaceRole, usize, usize, usize), String>
where
    C: rembrane_crypto::RecordCipher,
{
    let membership = store
        .find_membership(workspace_id, principal_id)
        .map_err(|error| format!("cannot inspect membership: {error}"))?
        .ok_or_else(|| "principal is not a member of the configured workspace".to_owned())?;
    if !membership.is_active() {
        return Err("configured workspace membership is not active".to_owned());
    }

    let memories = store
        .list_for_subject(workspace_id, principal_id)
        .map_err(|error| {
            format!("cannot authenticate workspace memories with the configured key: {error}")
        })?;
    let events = store.list_events_since(workspace_id, 0).map_err(|error| {
        format!("cannot authenticate workspace events with the configured key: {error}")
    })?;
    let checkpoints = store
        .list_checkpoints_for_subject(workspace_id, principal_id)
        .map_err(|error| {
            format!("cannot authenticate workspace checkpoints with the configured key: {error}")
        })?;
    Ok((
        membership.role(),
        memories.len(),
        events.len(),
        checkpoints.len(),
    ))
}

fn remember(arguments: &[String]) -> Result<(), String> {
    let content = option(arguments, "--content")?;
    let scope = requested_memory_scope(arguments)?;
    let read_scope = read_scope(&scope);
    let client_id = optional_option(arguments, "--client").unwrap_or("rembrane-cli");
    let (mut store, principal_id, workspace_id) = encrypted_store(arguments)?;
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
    let client_id = optional_option(arguments, "--client").unwrap_or("rembrane-cli");
    let (mut store, principal_id, workspace_id) = encrypted_store(arguments)?;
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
    let client_id = optional_option(arguments, "--client").unwrap_or("rembrane-cli");
    let (mut store, principal_id, workspace_id) = encrypted_store(arguments)?;
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
    let (domain, entity_id, activity_id, read_scopes) = recall_scope_context(arguments);
    let (mut store, principal_id, workspace_id) = encrypted_store(arguments)?;
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
    let entity_id = optional_option(arguments, "--entity").map(rembrane_domain::EntityId::new);
    let activity_id =
        optional_option(arguments, "--activity").map(rembrane_domain::ActivityId::new);
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

fn optional_requested_scope(arguments: &[String]) -> Result<Option<MemoryScope>, String> {
    let domain = optional_option(arguments, "--domain");
    let entity = optional_option(arguments, "--entity");
    let activity = optional_option(arguments, "--activity");
    let count = usize::from(domain.is_some())
        + usize::from(entity.is_some())
        + usize::from(activity.is_some());
    if count > 1 {
        return Err("--domain, --entity, and --activity are mutually exclusive".to_owned());
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
        MemoryScope::Domain { name } => ReadScope::Domain { name: name.clone() },
        MemoryScope::Entity { id } => ReadScope::Entity { id: id.clone() },
        MemoryScope::Activity { id } => ReadScope::Activity { id: id.clone() },
    }
}

fn encrypted_store(
    arguments: &[String],
) -> Result<
    (
        SqliteStore<ConfiguredRecordCipher>,
        PrincipalId,
        WorkspaceId,
    ),
    String,
> {
    let database = option(arguments, "--database")?;
    let principal_id = PrincipalId::new(option(arguments, "--principal")?);
    let workspace_id = WorkspaceId::new(option(arguments, "--workspace")?);
    let cipher = ConfiguredRecordCipher::from_environment()
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
            requested_read_permissions: Vec::new(),
            requested_write_permissions: write_permissions,
        })
        .map_err(|error| format!("cannot authorize client: {error}"))
}

fn current_sequence<C>(store: &SqliteStore<C>, workspace_id: &WorkspaceId) -> Result<u64, String>
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

fn now_epoch_seconds() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before the Unix epoch".to_owned())
}

fn workspace(arguments: &[String]) -> Result<(), String> {
    if arguments.first().map(String::as_str) != Some("create-shared") {
        return Err(
            "usage: rembrane workspace create-shared --database <path> --principal <owner-id> --workspace <id>"
                .to_owned(),
        );
    }
    let arguments = &arguments[1..];
    let database = option(arguments, "--database")?;
    let owner_id = PrincipalId::new(option(arguments, "--principal")?);
    let workspace_id = WorkspaceId::new(option(arguments, "--workspace")?);
    let mut store =
        SqliteStore::open(database).map_err(|error| format!("cannot open database: {error}"))?;
    if store
        .find_principal(&owner_id)
        .map_err(|error| format!("cannot inspect owner: {error}"))?
        .is_none()
    {
        return Err("shared-workspace owner must initialize a personal identity first".to_owned());
    }
    store
        .initialize_shared_workspace(
            Workspace::shared(workspace_id.clone()),
            Membership::new(workspace_id.clone(), owner_id.clone(), WorkspaceRole::Owner),
        )
        .map_err(|error| format!("cannot create shared workspace: {error}"))?;
    println!(
        "{}",
        serde_json::json!({
            "workspaceId": workspace_id.as_str(),
            "ownerId": owner_id.as_str(),
            "kind": "shared"
        })
    );
    Ok(())
}

fn invitation(arguments: &[String]) -> Result<(), String> {
    let operation = arguments
        .first()
        .map(String::as_str)
        .ok_or_else(|| invitation_usage().to_owned())?;
    let arguments = &arguments[1..];
    let database = option(arguments, "--database")?;
    let principal_id = PrincipalId::new(option(arguments, "--principal")?);
    let workspace_id = WorkspaceId::new(option(arguments, "--workspace")?);
    let mut store =
        SqliteStore::open(database).map_err(|error| format!("cannot open database: {error}"))?;
    let mut service = InvitationService::new(&mut store);

    if operation == "list" {
        let status = optional_option(arguments, "--status")
            .map(invitation_status)
            .transpose()?;
        let limit = optional_option(arguments, "--limit")
            .map_or(Ok(100), |value| parse_usize(value, "--limit"))?;
        let invitations = service
            .list(&ListInvitationsQuery {
                workspace_id: workspace_id.clone(),
                requested_by: principal_id,
                status,
                limit,
            })
            .map_err(|error| format!("cannot list invitations: {error}"))?;
        println!("{}", invitation_list_json(&workspace_id, &invitations));
        return Ok(());
    }

    let invitation_id = rembrane_domain::InvitationId::new(option(arguments, "--invitation")?);
    let request_id = option(arguments, "--request")?.to_owned();
    let now = now_epoch_seconds()?;
    let (status, subject_id, role) = match operation {
        "create" => {
            let subject_id = PrincipalId::new(option(arguments, "--subject")?);
            let role = invitation_role(option(arguments, "--role")?)?;
            let lifetime = positive_u64(arguments, "--ttl-seconds")?;
            let expires_at = now
                .checked_add(lifetime)
                .ok_or_else(|| "invitation expiry exceeds supported time".to_owned())?;
            let created = service
                .create(CreateInvitationCommand {
                    invitation_id: invitation_id.clone(),
                    workspace_id: workspace_id.clone(),
                    invited_principal_id: subject_id.clone(),
                    invited_by: principal_id,
                    role,
                    request_id,
                    created_at_epoch_seconds: now,
                    expires_at_epoch_seconds: expires_at,
                })
                .map_err(|error| format!("cannot create invitation: {error}"))?;
            ("pending", subject_id, created.role())
        }
        "accept" => {
            let membership = service
                .accept(AcceptInvitationCommand {
                    invitation_id: invitation_id.clone(),
                    workspace_id: workspace_id.clone(),
                    accepting_principal_id: principal_id.clone(),
                    request_id,
                    accepted_at_epoch_seconds: now,
                })
                .map_err(|error| format!("cannot accept invitation: {error}"))?;
            ("accepted", principal_id, membership.role())
        }
        "revoke" => {
            let revoked = service
                .revoke(RevokeInvitationCommand {
                    invitation_id: invitation_id.clone(),
                    workspace_id: workspace_id.clone(),
                    revoked_by: principal_id,
                    request_id,
                    revoked_at_epoch_seconds: now,
                })
                .map_err(|error| format!("cannot revoke invitation: {error}"))?;
            (
                "revoked",
                revoked.invited_principal_id().clone(),
                revoked.role(),
            )
        }
        _ => return Err(invitation_usage().to_owned()),
    };
    println!(
        "{}",
        serde_json::json!({
            "invitationId": invitation_id.as_str(),
            "workspaceId": workspace_id.as_str(),
            "principalId": subject_id.as_str(),
            "role": workspace_role_label(role),
            "status": status
        })
    );
    Ok(())
}

fn invitation_role(value: &str) -> Result<WorkspaceRole, String> {
    match value {
        "admin" => Ok(WorkspaceRole::Admin),
        "member" => Ok(WorkspaceRole::Member),
        "viewer" => Ok(WorkspaceRole::Viewer),
        _ => Err("--role must be admin, member, or viewer".to_owned()),
    }
}

fn invitation_status(value: &str) -> Result<InvitationStatus, String> {
    match value {
        "pending" => Ok(InvitationStatus::Pending),
        "accepted" => Ok(InvitationStatus::Accepted),
        "revoked" => Ok(InvitationStatus::Revoked),
        "expired" => Ok(InvitationStatus::Expired),
        _ => Err("--status must be pending, accepted, revoked, or expired".to_owned()),
    }
}

const fn invitation_status_label(status: InvitationStatus) -> &'static str {
    match status {
        InvitationStatus::Pending => "pending",
        InvitationStatus::Accepted => "accepted",
        InvitationStatus::Revoked => "revoked",
        InvitationStatus::Expired => "expired",
    }
}

fn invitation_list_json(
    workspace_id: &WorkspaceId,
    invitations: &[Invitation],
) -> serde_json::Value {
    serde_json::json!({
        "workspaceId": workspace_id.as_str(),
        "invitations": invitations
            .iter()
            .map(|invitation| {
                serde_json::json!({
                    "invitationId": invitation.id().as_str(),
                    "invitedPrincipalId": invitation.invited_principal_id().as_str(),
                    "invitedBy": invitation.invited_by().as_str(),
                    "role": workspace_role_label(invitation.role()),
                    "status": invitation_status_label(invitation.status()),
                    "createdAtEpochSeconds": invitation.created_at_epoch_seconds(),
                    "expiresAtEpochSeconds": invitation.expires_at_epoch_seconds()
                })
            })
            .collect::<Vec<_>>()
    })
}

const fn workspace_role_label(role: WorkspaceRole) -> &'static str {
    match role {
        WorkspaceRole::Owner => "owner",
        WorkspaceRole::Admin => "admin",
        WorkspaceRole::Member => "member",
        WorkspaceRole::Viewer => "viewer",
    }
}

const fn invitation_usage() -> &'static str {
    "usage: rembrane invitation <create|accept|revoke|list> --database <path> --principal <id> --workspace <id> [--invitation <id> --request <id>] [--subject <id> --role <admin|member|viewer> --ttl-seconds <seconds>] [--status <pending|accepted|revoked|expired> --limit <1-100>]"
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
    let initialization = store.initialize_personal_workspace(
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
            if existing_personal_workspace_is_valid(&store, &principal_id, &workspace_id)? {
                true
            } else {
                return Err("cannot initialize workspace: existing state conflicts".to_owned());
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
        && workspace
            .is_some_and(|workspace| workspace.kind() == rembrane_domain::WorkspaceKind::Personal)
        && membership.is_some_and(|membership| {
            membership.role() == WorkspaceRole::Owner && membership.is_active()
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
                permissions: Vec::new(),
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
           rembrane workspace create-shared --database <path> \
             --principal <owner-id> --workspace <id>\n\
           rembrane invitation create --database <path> --principal <owner-or-admin-id> \
             --workspace <id> --invitation <id> --subject <id> \
             --role <admin|member|viewer> --ttl-seconds <seconds> --request <id>\n\
           rembrane invitation accept --database <path> --principal <invited-id> \
             --workspace <id> --invitation <id> --request <id>\n\
           rembrane invitation revoke --database <path> --principal <owner-or-admin-id> \
             --workspace <id> --invitation <id> --request <id>\n\
           rembrane invitation list --database <path> --principal <owner-or-admin-id> \
             --workspace <id> [--status <pending|accepted|revoked|expired>] [--limit <1-100>]\n\
           rembrane doctor --database <path> --principal <id> --workspace <id> \
             [--privacy]\n\
           rembrane backup --database <path> --principal <id> \
             --workspace <id> --output <path>\n\
           rembrane restore --input <path> --database <new-path> \
             --principal <id> --workspace <id>\n\
           rembrane fingerprint-git --repository <path>\n\
           rembrane providers list\n\
           rembrane providers check --provider <id> --adapter-version <version> \
             [--allow-experimental] [--allow-provider-plaintext]\n\
           rembrane providers test --provider <id> --namespace <unique-name>\n\
           rembrane memory-provider check \
             [--privacy <end-to-end-encrypted|trusted-boundary|provider-plaintext>]\n\
           rembrane rotate-key --database <path> --principal <owner-or-admin-id> \
             --workspace <shared-workspace-id>\n\
           rembrane audit list --database <path> --principal <owner-or-admin-id> \
             --workspace <id> [--after <epoch-seconds>] [--limit <items>]\n\
           rembrane retention set --database <path> --principal <owner-or-admin-id> \
             --workspace <id> --request <id> \
             --memory-days <days|forever> --checkpoint-days <days|forever> \
             --travel-days <days|forever> --disclosure-days <days|forever> \
             --event-days <days|forever> --audit-days <days|forever> \
             [--expected-version <n>]\n\
           rembrane retention purge --database <path> \
             --principal <owner-or-admin-id> --workspace <id> [--limit <items>]\n\
           rembrane legal-hold <place|release> --database <path> \
             --principal <owner-or-admin-id> --workspace <id> \
             --hold <id> --request <id>\n\
           rembrane channel status --database <path> --principal <owner-or-admin-id> \
             --workspace <id>\n\
           rembrane channel requeue --database <path> --principal <owner-or-admin-id> \
             --workspace <id> --channel <channel> --event <id> --request <id>\n\
           rembrane channel <bind-whatsapp|unbind-whatsapp|bind-mobile-share|unbind-mobile-share> --database <path> \
             --principal <owner-or-admin-id> --workspace <id> \
             --subject <active-member-id> --client <id> --request <id>\n\
           rembrane mcp-config \
             --client <codex|claude-code|gemini-cli|cursor|vscode|zed|opencode|generic> \
             --server-binary <path> \
             [--key-provider <environment|macos-keychain|linux-secret-service|windows-dpapi|http>]\n\
           rembrane mcp-config clients\n\
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
    use rembrane_application::{AdministrativeAuditRepository, MembershipRepository};
    use rembrane_domain::{
        AdministrativeAction, EntityId, Invitation, InvitationId, InvitationStatus, MemoryScope,
        PrincipalId, ReadScope, WorkspaceId, WorkspaceRole,
    };
    use rembrane_store_sqlite::SqliteStore;

    use super::{
        EXPORT_MAGIC, SEMANTIC_PROVIDER_CONFORMANCE_PROFILE_SHA256, check_provider_registry,
        claude_mcp_config, codex_mcp_config, cursor_mcp_config, format_read_scopes,
        gemini_mcp_config, generic_mcp_config, invitation_list_json, invitation_status,
        mcp_client_catalog, mcp_environment_variables, memory_privacy_mode_name,
        memory_provider_check_policy, opencode_mcp_config, option, positive_u64, providers,
        read_export, recall_scope_context, redact_endpoint, render_mcp_config,
        requested_memory_privacy, requested_memory_scope, run, selected_secret_reference,
        test_provider, validate_external_conformance_namespace, validate_mcp_server_binary,
        vscode_mcp_config, write_export, zed_mcp_config,
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

    fn request_run(arguments: &[&str]) -> Result<(), String> {
        run(&arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect::<Vec<_>>())
    }

    fn initialize_shared_fixture(database: &str) {
        request_run(&[
            "init",
            "--database",
            database,
            "--principal",
            "owner",
            "--workspace",
            "owner-personal",
        ])
        .expect("owner initialization");
        request_run(&[
            "init",
            "--database",
            database,
            "--principal",
            "guest",
            "--workspace",
            "guest-personal",
        ])
        .expect("guest initialization");
        request_run(&[
            "workspace",
            "create-shared",
            "--database",
            database,
            "--principal",
            "owner",
            "--workspace",
            "team",
        ])
        .expect("shared workspace");
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
    fn cli_creates_shared_workspace_and_accepts_audited_invitation() {
        let database = temporary_path("shared-workspace.db");
        let database = database.to_string_lossy().into_owned();
        initialize_shared_fixture(&database);
        request_run(&[
            "invitation",
            "create",
            "--database",
            &database,
            "--principal",
            "owner",
            "--workspace",
            "team",
            "--invitation",
            "invite_cli_01",
            "--subject",
            "guest",
            "--role",
            "member",
            "--ttl-seconds",
            "3600",
            "--request",
            "request_cli_create",
        ])
        .expect("invitation");
        request_run(&[
            "invitation",
            "list",
            "--database",
            &database,
            "--principal",
            "owner",
            "--workspace",
            "team",
            "--status",
            "pending",
            "--limit",
            "1",
        ])
        .expect("owner can list pending invitations");
        request_run(&[
            "invitation",
            "accept",
            "--database",
            &database,
            "--principal",
            "guest",
            "--workspace",
            "team",
            "--invitation",
            "invite_cli_01",
            "--request",
            "request_cli_accept",
        ])
        .expect("acceptance");
        request_run(&[
            "invitation",
            "list",
            "--database",
            &database,
            "--principal",
            "owner",
            "--workspace",
            "team",
            "--status",
            "accepted",
        ])
        .expect("owner can list accepted invitations");
        let member_listing = request_run(&[
            "invitation",
            "list",
            "--database",
            &database,
            "--principal",
            "guest",
            "--workspace",
            "team",
        ]);
        assert!(member_listing.is_err());

        let store = SqliteStore::open(&database).expect("database");
        let membership = store
            .find_membership(&WorkspaceId::new("team"), &PrincipalId::new("guest"))
            .expect("membership lookup")
            .expect("membership");
        assert_eq!(membership.role(), WorkspaceRole::Member);
        let audit = store
            .list_administrative_audit(&WorkspaceId::new("team"), 0, 10)
            .expect("audit");
        let actions = audit
            .iter()
            .map(rembrane_domain::AdministrativeAuditEvent::action)
            .collect::<Vec<_>>();
        assert_eq!(actions.len(), 2);
        assert!(actions.contains(&AdministrativeAction::InvitationCreated));
        assert!(actions.contains(&AdministrativeAction::InvitationAccepted));

        std::fs::remove_file(database).expect("fixture database should be removed");
    }

    #[test]
    fn invitation_listing_uses_closed_statuses_and_structured_output() {
        assert_eq!(
            invitation_status("expired").expect("known status"),
            InvitationStatus::Expired
        );
        assert!(invitation_status("all").is_err());

        let invitation = Invitation::new(
            InvitationId::new("invite_cli_json"),
            WorkspaceId::new("team"),
            PrincipalId::new("guest"),
            PrincipalId::new("owner"),
            WorkspaceRole::Viewer,
            100,
            200,
        )
        .expect("valid invitation");
        assert_eq!(
            invitation_list_json(&WorkspaceId::new("team"), &[invitation]),
            serde_json::json!({
                "workspaceId": "team",
                "invitations": [{
                    "invitationId": "invite_cli_json",
                    "invitedPrincipalId": "guest",
                    "invitedBy": "owner",
                    "role": "viewer",
                    "status": "pending",
                    "createdAtEpochSeconds": 100,
                    "expiresAtEpochSeconds": 200
                }]
            })
        );
    }

    #[test]
    fn channel_lookup_secret_reference_defaults_and_rejects_inline_values() {
        let default = selected_secret_reference("", "REMBRANE_WHATSAPP_BINDING_LOOKUP_SECRET")
            .expect("default environment reference");
        assert_eq!(
            default.environment_variable(),
            Some("REMBRANE_WHATSAPP_BINDING_LOOKUP_SECRET")
        );
        let file = selected_secret_reference(
            "file:/run/secrets/whatsapp-lookup",
            "REMBRANE_WHATSAPP_BINDING_LOOKUP_SECRET",
        )
        .expect("file reference");
        assert_eq!(file.file_path(), Some("/run/secrets/whatsapp-lookup"));
        assert!(
            selected_secret_reference("raw-secret", "REMBRANE_WHATSAPP_BINDING_LOOKUP_SECRET")
                .is_err()
        );
    }

    #[test]
    fn provider_registry_command_rejects_ambiguous_arguments() {
        assert!(providers(&[]).is_err());
        assert!(providers(&["unknown".to_owned()]).is_err());
        assert!(providers(&["list".to_owned(), "--extra".to_owned()]).is_err());
    }

    #[test]
    fn memory_provider_check_requires_the_complete_portable_surface() {
        let policy = memory_provider_check_policy(
            rembrane_provider_sdk::MemoryProviderPrivacyMode::EndToEndEncrypted,
        )
        .expect("policy");
        let manifest = rembrane_provider_sdk::MemoryProviderManifest::new(
            "incomplete.provider".to_owned(),
            "test".to_owned(),
            rembrane_provider_sdk::CURRENT_MEMORY_PROVIDER_PROTOCOL,
            vec![rembrane_provider_sdk::MemoryProviderTransport::Https],
            vec![rembrane_provider_sdk::MemoryProviderCapability::ResolveContext],
            rembrane_provider_sdk::MemoryProviderPrivacyMode::EndToEndEncrypted,
            Vec::new(),
            rembrane_provider_sdk::MemoryProviderLimits {
                maximum_context_items: 1,
                maximum_context_bytes: 1,
                maximum_event_batch_items: 1,
                maximum_sync_batch_items: 1,
            },
        )
        .expect("manifest");
        let error = policy
            .validate(&manifest)
            .expect_err("incomplete provider must fail");
        assert!(error.to_string().contains("every required capability"));
        assert_eq!(
            memory_privacy_mode_name(
                rembrane_provider_sdk::MemoryProviderPrivacyMode::TrustedBoundary
            ),
            "trusted_boundary"
        );
    }

    #[test]
    fn memory_provider_check_defaults_to_end_to_end_encryption() {
        assert_eq!(
            requested_memory_privacy(&["check".to_owned()]).expect("default privacy"),
            rembrane_provider_sdk::MemoryProviderPrivacyMode::EndToEndEncrypted
        );
    }

    #[test]
    fn memory_provider_check_requires_explicit_weaker_privacy() {
        assert_eq!(
            requested_memory_privacy(&[
                "check".to_owned(),
                "--privacy".to_owned(),
                "trusted-boundary".to_owned(),
            ])
            .expect("explicit trusted boundary"),
            rembrane_provider_sdk::MemoryProviderPrivacyMode::TrustedBoundary
        );
        assert!(
            requested_memory_privacy(&[
                "check".to_owned(),
                "--privacy".to_owned(),
                "unknown".to_owned(),
            ])
            .is_err()
        );
        assert!(
            requested_memory_privacy(&["check".to_owned(), "trusted-boundary".to_owned(),])
                .is_err()
        );
    }

    #[test]
    fn memory_provider_policy_rejects_an_unrequested_privacy_mode() {
        let policy = memory_provider_check_policy(
            rembrane_provider_sdk::MemoryProviderPrivacyMode::EndToEndEncrypted,
        )
        .expect("policy");
        let manifest = rembrane_provider_sdk::MemoryProviderManifest::new(
            "trusted.provider".to_owned(),
            "test".to_owned(),
            rembrane_provider_sdk::CURRENT_MEMORY_PROVIDER_PROTOCOL,
            vec![rembrane_provider_sdk::MemoryProviderTransport::Https],
            vec![
                rembrane_provider_sdk::MemoryProviderCapability::ResolveContext,
                rembrane_provider_sdk::MemoryProviderCapability::ResolveQuestion,
                rembrane_provider_sdk::MemoryProviderCapability::RecordEvent,
                rembrane_provider_sdk::MemoryProviderCapability::ProposeMemory,
                rembrane_provider_sdk::MemoryProviderCapability::CheckpointActivity,
                rembrane_provider_sdk::MemoryProviderCapability::RecordDisclosure,
                rembrane_provider_sdk::MemoryProviderCapability::DeleteMemory,
                rembrane_provider_sdk::MemoryProviderCapability::ExplainMemory,
                rembrane_provider_sdk::MemoryProviderCapability::SyncPull,
                rembrane_provider_sdk::MemoryProviderCapability::SyncPush,
            ],
            rembrane_provider_sdk::MemoryProviderPrivacyMode::TrustedBoundary,
            Vec::new(),
            rembrane_provider_sdk::MemoryProviderLimits {
                maximum_context_items: 1,
                maximum_context_bytes: 1,
                maximum_event_batch_items: 1,
                maximum_sync_batch_items: 1,
            },
        )
        .expect("manifest");

        let error = policy
            .validate(&manifest)
            .expect_err("weaker unrequested privacy must fail");
        assert!(error.to_string().contains("privacy mode"));
    }

    #[test]
    fn native_provider_can_run_shared_conformance_from_cli() {
        let report = test_provider(&[
            "test".to_owned(),
            "--provider".to_owned(),
            "rembrane.native".to_owned(),
            "--namespace".to_owned(),
            "cli-unit".to_owned(),
        ])
        .expect("native provider should pass conformance");

        let report: serde_json::Value =
            serde_json::from_str(&report).expect("conformance evidence should be JSON");
        assert_eq!(report["suiteId"], "rembrane.semantic-provider.core");
        assert_eq!(report["suiteVersion"], "0.1");
        assert_eq!(
            report["profileSha256"],
            SEMANTIC_PROVIDER_CONFORMANCE_PROFILE_SHA256
        );
        assert_eq!(report["provider"], "rembrane.native");
        assert_eq!(report["providerVersion"], env!("CARGO_PKG_VERSION"));
        assert_eq!(report["protocolVersion"], "0.1");
        assert_eq!(report["namespace"], "cli-unit");
        assert_eq!(report["result"], "pass");
        assert_eq!(report["cases"].as_array().expect("cases").len(), 6);
    }

    #[test]
    fn provider_selection_pins_build_and_requires_explicit_experimental_opt_in() {
        let denied = check_provider_registry(
            super::PROVIDER_REGISTRY,
            "rembrane.native",
            env!("CARGO_PKG_VERSION"),
            false,
            true,
        )
        .expect_err("experimental selection must require operator intent");
        assert!(denied.contains("--allow-experimental"));

        let selected = check_provider_registry(
            super::PROVIDER_REGISTRY,
            "rembrane.native",
            env!("CARGO_PKG_VERSION"),
            true,
            true,
        )
        .expect("explicit experimental selection");
        let selected: serde_json::Value =
            serde_json::from_str(&selected).expect("selection evidence should be JSON");
        assert_eq!(selected["provider"], "rembrane.native");
        assert_eq!(selected["adapterVersion"], env!("CARGO_PKG_VERSION"));
        assert_eq!(selected["eligibility"], "experimental-opt-in");

        let plaintext_denied = check_provider_registry(
            super::PROVIDER_REGISTRY,
            "rembrane.native",
            env!("CARGO_PKG_VERSION"),
            true,
            false,
        )
        .expect_err("plaintext processing must require separate operator intent");
        assert!(plaintext_denied.contains("--allow-provider-plaintext"));

        let mismatch = check_provider_registry(
            super::PROVIDER_REGISTRY,
            "rembrane.native",
            "attacker-substituted-build",
            true,
            true,
        )
        .expect_err("unregistered provider build must fail");
        assert!(mismatch.contains("version"));
    }

    #[test]
    fn provider_selection_requires_exact_passing_conformance_evidence() {
        let base: serde_json::Value =
            serde_json::from_str(super::PROVIDER_REGISTRY).expect("embedded registry");
        for (field, value) in [
            ("result", serde_json::Value::String("fail".to_owned())),
            ("profileSha256", serde_json::Value::String("a".repeat(64))),
            (
                "providerVersion",
                serde_json::Value::String("substituted".to_owned()),
            ),
        ] {
            let mut candidate = base.clone();
            candidate["providers"][0]["conformance"][field] = value;
            let candidate = serde_json::to_string(&candidate).expect("candidate registry");
            assert!(
                check_provider_registry(
                    &candidate,
                    "rembrane.native",
                    env!("CARGO_PKG_VERSION"),
                    true,
                    true,
                )
                .expect_err("rebound conformance evidence must fail")
                .contains("conformance")
            );
        }

        let mut reordered = base;
        reordered["providers"][0]["conformance"]["cases"]
            .as_array_mut()
            .expect("cases")
            .swap(0, 1);
        let reordered = serde_json::to_string(&reordered).expect("reordered registry");
        assert!(
            check_provider_registry(
                &reordered,
                "rembrane.native",
                env!("CARGO_PKG_VERSION"),
                true,
                true,
            )
            .expect_err("reordered cases must fail")
            .contains("cases")
        );
    }

    #[test]
    fn provider_selection_rejects_deprecated_revoked_and_ambiguous_records() {
        let base: serde_json::Value =
            serde_json::from_str(super::PROVIDER_REGISTRY).expect("embedded registry");
        for status in ["deprecated", "revoked"] {
            let mut candidate = base.clone();
            candidate["providers"][0]["status"] = serde_json::Value::String(status.to_owned());
            let candidate = serde_json::to_string(&candidate).expect("candidate registry");
            let error = check_provider_registry(
                &candidate,
                "rembrane.native",
                env!("CARGO_PKG_VERSION"),
                true,
                true,
            )
            .expect_err("withdrawn provider must fail");
            assert!(error.contains(status));
        }

        let mut duplicate = base;
        let provider = duplicate["providers"][0].clone();
        duplicate["providers"]
            .as_array_mut()
            .expect("providers")
            .push(provider);
        let duplicate = serde_json::to_string(&duplicate).expect("duplicate registry");
        assert!(
            check_provider_registry(
                &duplicate,
                "rembrane.native",
                env!("CARGO_PKG_VERSION"),
                true,
                true,
            )
            .expect_err("duplicate provider identity must fail")
            .contains("exactly one")
        );
    }

    #[test]
    fn provider_test_fails_for_adapter_not_in_build() {
        let error = test_provider(&[
            "test".to_owned(),
            "--provider".to_owned(),
            "community.example".to_owned(),
            "--namespace".to_owned(),
            "cli-unit".to_owned(),
        ])
        .expect_err("missing adapter must fail explicitly");

        assert!(error.contains("is not installed in this CLI build"));
    }

    #[test]
    fn mem0_provider_test_requires_explicit_plaintext_acknowledgement() {
        let error = test_provider(&[
            "test".to_owned(),
            "--provider".to_owned(),
            "mem0.oss".to_owned(),
            "--namespace".to_owned(),
            "cli-unit".to_owned(),
        ])
        .expect_err("Mem0 test must fail before reading credentials");

        assert!(error.contains("--allow-provider-plaintext"));
    }

    #[test]
    fn supermemory_provider_test_requires_explicit_plaintext_acknowledgement() {
        let error = test_provider(&[
            "test".to_owned(),
            "--provider".to_owned(),
            "supermemory.v5".to_owned(),
            "--namespace".to_owned(),
            "cli-unit".to_owned(),
        ])
        .expect_err("Supermemory test must fail before reading credentials");

        assert!(error.contains("--allow-provider-plaintext"));
    }

    #[test]
    fn external_provider_namespace_is_bounded_and_shell_safe() {
        assert!(validate_external_conformance_namespace("mem0-20261024-a8f21c").is_ok());
        for invalid in [
            "predictable",
            "contains whitespace 123",
            "contains/slash/1234",
            "contains\ncontrol-1234",
            "this-name-is-deliberately-made-longer-than-eighty-characters-to-prevent-unbounded-provider-identifiers",
        ] {
            assert!(validate_external_conformance_namespace(invalid).is_err());
        }
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
        let scoped = vec!["--entity".to_owned(), "project_01".to_owned()];
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
            redact_endpoint("https://operator:secret@graph.example/v1?token=hidden"),
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
        let environment =
            mcp_environment_variables("environment").expect("built-in provider should be valid");
        let codex = codex_mcp_config("/opt/rembrane-mcp", &environment);
        assert!(codex.contains("env_vars = ["));
        assert!(codex.contains("\"REMBRANE_WORKSPACE_KEY_REFERENCE\""));
        assert!(!codex.contains("REMBRANE_WORKSPACE_KEY_HEX"));
        assert!(!codex.contains("00010203"));

        let claude = claude_mcp_config("/opt/rembrane-mcp", &environment);
        assert!(claude.contains(
            "\"REMBRANE_WORKSPACE_KEY_REFERENCE\":\"${REMBRANE_WORKSPACE_KEY_REFERENCE}\""
        ));
        assert!(!claude.contains("REMBRANE_WORKSPACE_KEY_HEX"));
        assert!(!claude.contains("00010203"));

        let gemini = gemini_mcp_config("/opt/rembrane-mcp", &environment);
        assert!(gemini.contains("\"mcpServers\":{\"rembrane\""));
        assert!(gemini.contains(
            "\"REMBRANE_WORKSPACE_KEY_REFERENCE\":\"${REMBRANE_WORKSPACE_KEY_REFERENCE}\""
        ));
        assert!(!gemini.contains("REMBRANE_WORKSPACE_KEY_HEX"));
        assert!(!gemini.contains("00010203"));

        let cursor = cursor_mcp_config("/opt/rembrane-mcp", &environment);
        assert!(cursor.contains("\"mcpServers\":{\"rembrane\""));
        assert!(cursor.contains("\"${env:REMBRANE_WORKSPACE_KEY_REFERENCE}\""));
        assert!(!cursor.contains("REMBRANE_WORKSPACE_KEY_HEX"));
        assert!(!cursor.contains("00010203"));

        let vscode = vscode_mcp_config("/opt/rembrane-mcp", &environment);
        assert!(vscode.contains("\"servers\":{\"rembrane\""));
        assert!(vscode.contains("\"${env:REMBRANE_WORKSPACE_KEY_REFERENCE}\""));
        assert!(!vscode.contains("REMBRANE_WORKSPACE_KEY_HEX"));
        assert!(!vscode.contains("00010203"));

        let zed = zed_mcp_config("/opt/rembrane-mcp");
        assert!(zed.contains("\"context_servers\":{\"rembrane\""));
        assert!(zed.contains("\"env\":{}"));
        assert!(!zed.contains("${"));
        assert!(!zed.contains("REMBRANE_WORKSPACE_KEY_HEX"));
        assert!(!zed.contains("00010203"));

        let opencode = opencode_mcp_config("/opt/rembrane-mcp", &environment);
        assert!(opencode.contains("\"$schema\":\"https://opencode.ai/config.json\""));
        assert!(opencode.contains("\"type\":\"local\""));
        assert!(opencode.contains("\"command\":[\"/opt/rembrane-mcp\"]"));
        assert!(opencode.contains(
            "\"REMBRANE_WORKSPACE_KEY_REFERENCE\":\"{env:REMBRANE_WORKSPACE_KEY_REFERENCE}\""
        ));
        assert!(!opencode.contains("REMBRANE_WORKSPACE_KEY_HEX"));
        assert!(!opencode.contains("00010203"));

        let generic = generic_mcp_config("/opt/rembrane-mcp", &environment);
        assert!(generic.contains("\"schemaVersion\":1"));
        assert!(generic.contains("\"transport\":\"stdio\""));
        assert!(generic.contains("\"requiredEnvironment\""));
        assert!(generic.contains("REMBRANE_WORKSPACE_KEY_REFERENCE"));
        assert!(!generic.contains("REMBRANE_WORKSPACE_KEY_HEX"));
        assert!(!generic.contains("00010203"));
    }

    #[test]
    fn mcp_client_catalog_is_complete_unique_and_secret_custody_explicit() {
        let catalog = mcp_client_catalog();
        assert_eq!(catalog.schema_version, 1);
        let ids = catalog
            .clients
            .iter()
            .map(|client| client.id)
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            [
                "codex",
                "claude-code",
                "gemini-cli",
                "cursor",
                "vscode",
                "zed",
                "opencode",
                "generic",
            ]
        );
        let mut unique = ids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), ids.len());
        assert!(catalog.clients.iter().all(|client| {
            !client.config_format.is_empty() && !client.environment_mode.is_empty()
        }));
        assert_eq!(
            catalog
                .clients
                .iter()
                .find(|client| client.id == "zed")
                .map(|client| client.environment_mode),
            Some("process-inherited")
        );
        let serialized =
            serde_json::to_value(&catalog).expect("catalog serialization should succeed");
        let canonical: serde_json::Value = serde_json::from_str(include_str!(
            "../../../spec/examples/mcp-client-catalog.json"
        ))
        .expect("canonical client catalog fixture should be valid");
        assert_eq!(serialized, canonical);

        let environment =
            mcp_environment_variables("environment").expect("environment provider is valid");
        for client in &catalog.clients {
            let rendered = render_mcp_config(client.id, "/opt/rembrane-mcp", &environment)
                .expect("every catalog client must have a renderer");
            assert!(!rendered.is_empty());
            assert!(!rendered.contains("REMBRANE_WORKSPACE_KEY_HEX"));
        }
    }

    #[test]
    fn mcp_config_rejects_unsafe_or_unbounded_executable_commands() {
        for command in [
            "",
            "   ",
            "/opt/rembrane\n[mcp_servers.attacker]",
            "bad\0path",
        ] {
            assert!(
                validate_mcp_server_binary(command).is_err(),
                "unsafe executable command must be rejected"
            );
        }
        assert!(validate_mcp_server_binary(&"x".repeat(4_097)).is_err());
        assert!(validate_mcp_server_binary("/opt/Rembrane MCP/bin/rembrane-mcp").is_ok());
    }

    #[test]
    fn keychain_mcp_config_never_requests_raw_key_environment_variable() {
        let environment = mcp_environment_variables("macos-keychain")
            .expect("macOS keychain provider should be valid");
        let config = codex_mcp_config("/opt/rembrane-mcp", &environment);

        assert!(config.contains("\"REMBRANE_KEYCHAIN_SERVICE\""));
        assert!(config.contains("\"REMBRANE_KEYCHAIN_ACCOUNT\""));
        assert!(config.contains("\"REMBRANE_KEYCHAIN_HISTORICAL_KEYS\""));
        assert!(!config.contains("REMBRANE_WORKSPACE_KEY_HEX"));
    }

    #[test]
    fn http_key_provider_mcp_config_requires_only_a_token_reference() {
        let environment = mcp_environment_variables("http").expect("HTTP provider should be valid");
        assert!(environment.contains(&"REMBRANE_KEY_PROVIDER_TOKEN_REFERENCE"));
        assert!(!environment.contains(&"REMBRANE_KEY_PROVIDER_TOKEN"));
    }

    #[test]
    fn linux_secret_service_config_passes_only_lookup_metadata() {
        let environment = mcp_environment_variables("linux-secret-service")
            .expect("Linux Secret Service provider should be valid");
        let config = codex_mcp_config("/opt/rembrane-mcp", &environment);

        assert!(config.contains("\"REMBRANE_SECRET_SERVICE_SERVICE\""));
        assert!(config.contains("\"REMBRANE_SECRET_SERVICE_ACCOUNT\""));
        assert!(config.contains("\"REMBRANE_SECRET_SERVICE_HISTORICAL_KEYS\""));
        assert!(!config.contains("REMBRANE_WORKSPACE_KEY_HEX"));
    }

    #[test]
    fn windows_dpapi_config_passes_only_blob_references() {
        let environment = mcp_environment_variables("windows-dpapi")
            .expect("Windows DPAPI provider should be valid");
        let config = codex_mcp_config("/opt/rembrane-mcp", &environment);

        assert!(config.contains("\"REMBRANE_DPAPI_BLOB_PATH\""));
        assert!(config.contains("\"REMBRANE_DPAPI_HISTORICAL_KEYS\""));
        assert!(!config.contains("REMBRANE_WORKSPACE_KEY_HEX"));
    }

    #[test]
    fn http_key_provider_config_references_but_never_embeds_credentials() {
        let environment =
            mcp_environment_variables("http").expect("HTTP key provider should be valid");
        let config = codex_mcp_config("/opt/rembrane-mcp", &environment);

        assert!(config.contains("\"REMBRANE_KEY_PROVIDER_BASE_URL\""));
        assert!(config.contains("\"REMBRANE_KEY_PROVIDER_TOKEN_REFERENCE\""));
        assert!(!environment.contains(&"REMBRANE_KEY_PROVIDER_TOKEN"));
        assert!(!config.contains("replace-from-secret-store"));
        assert!(!config.contains("REMBRANE_WORKSPACE_KEY_HEX"));
    }
}

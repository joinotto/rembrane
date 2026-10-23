use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rembrane_application::{
    AuthorizeClientCommand, AuthorizeClientService, ClientGrantBundle,
    CheckpointService, CreateCheckpointCommand, DeleteMemoryCommand,
    EventRepository, MemoryLifecycleService, RememberPreferenceCommand,
    MemoryProposalService, ProposeMemoryCommand, RememberPreferenceService,
    ResolveContextCommand, ResolveContextService, ResumeActivityCommand,
    ReviseMemoryCommand, UpdateCheckpointCommand,
};
use rembrane_contracts::ResolveContextRequest;
use rembrane_config::parse_read_scopes;
use rembrane_crypto_rustcrypto::RustCryptoRecordCipher;
use rembrane_domain::{
    ActivityCheckpoint, ActivityId, CheckpointId, ClientId, ContextPackId,
    DisclosureId, EntityId, EventId, EvidenceId, EvidenceReference,
    EvidenceSource, MemoryId, MemoryKind, MemoryScope, PrincipalId, ReadScope,
    WorkspaceId, WritePermission,
};
use rembrane_store_sqlite::SqliteStore;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{
    ErrorData as McpError, ServiceExt, schemars, tool, tool_router,
    transport::stdio,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ResolveContextParameters {
    purpose: String,
    query: String,
    maximum_items: Option<usize>,
    maximum_bytes: Option<usize>,
    domain: Option<String>,
    entity_id: Option<String>,
    activity_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContextItem {
    memory_id: String,
    version: u64,
    content: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResolveContextOutput {
    context_pack_id: String,
    disclosure_id: String,
    items: Vec<ContextItem>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RememberPreferenceParameters {
    content: String,
    domain: Option<String>,
    entity_id: Option<String>,
    activity_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CorrectMemoryParameters {
    memory_id: String,
    expected_version: u64,
    replacement: String,
    domain: Option<String>,
    entity_id: Option<String>,
    activity_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ForgetMemoryParameters {
    memory_id: String,
    expected_version: u64,
    reason: String,
    domain: Option<String>,
    entity_id: Option<String>,
    activity_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WorkTraceParameters {
    activity_id: String,
    entity_id: Option<String>,
    summary: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MutationOutput {
    memory_id: String,
    version: u64,
    status: &'static str,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CheckpointParameters {
    activity_id: String,
    entity_id: Option<String>,
    expected_version: Option<u64>,
    goal: Option<String>,
    summary: String,
    next_steps: Option<Vec<String>>,
    blockers: Option<Vec<String>>,
    state_fingerprint: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ResumeActivityParameters {
    activity_id: String,
    current_state_fingerprint: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckpointOutput {
    checkpoint_id: String,
    activity_id: String,
    entity_id: Option<String>,
    goal: String,
    summary: String,
    next_steps: Vec<String>,
    blockers: Vec<String>,
    state_fingerprint: Option<String>,
    stale: Option<bool>,
    version: u64,
}

struct State {
    store: SqliteStore<RustCryptoRecordCipher>,
    principal_id: PrincipalId,
    workspace_id: WorkspaceId,
    client_id: ClientId,
    read_scopes: Vec<ReadScope>,
    next_id: u128,
}

#[derive(Clone)]
struct RembraneMcp {
    state: Arc<Mutex<State>>,
}

impl RembraneMcp {
    fn from_environment() -> Result<Self> {
        let database = required_environment("REMBRANE_DATABASE")?;
        let principal_id =
            PrincipalId::new(required_environment("REMBRANE_PRINCIPAL_ID")?);
        let workspace_id =
            WorkspaceId::new(required_environment("REMBRANE_WORKSPACE_ID")?);
        let client_id =
            ClientId::new(required_environment("REMBRANE_CLIENT_ID")?);
        let cipher = RustCryptoRecordCipher::from_environment()
            .context("failed to load workspace cipher")?;
        let read_scopes = parse_read_scopes(
            &std::env::var("REMBRANE_READ_SCOPES")
                .unwrap_or_else(|_| "global".to_owned()),
        )
        .map_err(anyhow::Error::msg)?;
        let store = SqliteStore::open(database)
            .context("failed to open Rembrane database")?
            .with_cipher(cipher);
        AuthorizeClientService::new(&store)
            .execute(AuthorizeClientCommand {
                client_id: client_id.clone(),
                workspace_id: workspace_id.clone(),
                principal_id: principal_id.clone(),
                requested_read_scopes: read_scopes.clone(),
                requested_write_permissions: Vec::new(),
            })
            .context("failed to authorize MCP connection")?;
        let next_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_nanos();

        Ok(Self {
            state: Arc::new(Mutex::new(State {
                store,
                principal_id,
                workspace_id,
                client_id,
                read_scopes,
                next_id,
            })),
        })
    }
}

#[tool_router(server_handler)]
impl RembraneMcp {
    #[tool(
        name = "rembrane_resolve_context",
        description = "Retrieve minimal confirmed memory authorized for this connection. A disclosure receipt is recorded."
    )]
    fn resolve_context(
        &self,
        Parameters(parameters): Parameters<ResolveContextParameters>,
    ) -> Result<String, McpError> {
        if parameters.purpose.trim().is_empty()
            || parameters.query.trim().is_empty()
        {
            return Err(McpError::invalid_params(
                "purpose and query must not be empty",
                None,
            ));
        }
        let maximum_items = parameters.maximum_items.unwrap_or(20);
        let maximum_bytes = parameters.maximum_bytes.unwrap_or(65_536);
        if !(1..=100).contains(&maximum_items) {
            return Err(McpError::invalid_params(
                "maximumItems must be between 1 and 100",
                None,
            ));
        }
        if !(1..=1_048_576).contains(&maximum_bytes) {
            return Err(McpError::invalid_params(
                "maximumBytes must be between 1 and 1048576",
                None,
            ));
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| McpError::internal_error("state lock failed", None))?;
        state.next_id = state.next_id.saturating_add(1);
        let suffix = state.next_id;
        let requested_scopes = request_scopes(
            &state.read_scopes,
            parameters.domain.as_deref(),
            parameters.entity_id.as_deref(),
            parameters.activity_id.as_deref(),
        );
        let grants = authorize(&state, requested_scopes, Vec::new())?;
        let principal_id = grants.read.subject_id.clone();
        let workspace_id = grants.read.workspace_id.clone();
        let response = ResolveContextService::new(&mut state.store)
            .execute(ResolveContextCommand {
                request: ResolveContextRequest {
                    workspace_id: workspace_id.clone(),
                    principal_id: principal_id.clone(),
                    domain: parameters.domain,
                    entity_id: parameters.entity_id.map(EntityId::new),
                    activity_id: parameters.activity_id.map(ActivityId::new),
                    purpose: parameters.purpose,
                    query: parameters.query,
                    maximum_items,
                    maximum_bytes,
                },
                grant: grants.read,
                context_pack_id: ContextPackId::new(format!(
                    "context_{suffix}"
                )),
                disclosure_id: DisclosureId::new(format!(
                    "disclosure_{suffix}"
                )),
            })
            .map_err(|error| {
                McpError::internal_error(
                    format!("context resolution failed: {error}"),
                    None,
                )
            })?;
        let output = ResolveContextOutput {
            context_pack_id: response.context_pack_id.to_string(),
            disclosure_id: response.disclosure_id.to_string(),
            items: response
                .items
                .into_iter()
                .map(|memory| ContextItem {
                    memory_id: memory.id().to_string(),
                    version: memory.version(),
                    content: memory.content().to_owned(),
                })
                .collect(),
        };

        serde_json::to_string(&output).map_err(|_| {
            McpError::internal_error("response serialization failed", None)
        })
    }

    #[tool(
        name = "rembrane_remember_preference",
        description = "Store a confirmed global preference when this connection has direct memory creation permission."
    )]
    fn remember_preference(
        &self,
        Parameters(parameters): Parameters<RememberPreferenceParameters>,
    ) -> Result<String, McpError> {
        if parameters.content.trim().is_empty() {
            return Err(McpError::invalid_params(
                "content must not be empty",
                None,
            ));
        }
        let mut state = lock_state(&self.state)?;
        let scope = memory_scope(
            parameters.domain.as_deref(),
            parameters.entity_id.as_deref(),
            parameters.activity_id.as_deref(),
        )?;
        let grants = authorize(
            &state,
            vec![read_scope(&scope)],
            vec![WritePermission::CreateMemory],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state);
        let memory = RememberPreferenceService::new(&mut state.store)
            .execute(RememberPreferenceCommand {
                grant: grants.write,
                memory_id: MemoryId::new(format!("memory_{suffix}")),
                scope,
                content: parameters.content,
                evidence: EvidenceReference::new(
                    EvidenceId::new(format!("evidence_{suffix}")),
                    EvidenceSource::UserStatement,
                ),
                event_id: EventId::new(format!("event_{suffix}")),
                expected_previous_sequence: previous_sequence,
                projections: Vec::new(),
            })
            .map_err(application_error)?;
        mutation_response(memory.id().to_string(), memory.version(), "confirmed")
    }

    #[tool(
        name = "rembrane_request_correction",
        description = "Directly correct a memory when this connection has revision permission."
    )]
    fn correct_memory(
        &self,
        Parameters(parameters): Parameters<CorrectMemoryParameters>,
    ) -> Result<String, McpError> {
        if parameters.memory_id.trim().is_empty()
            || parameters.replacement.trim().is_empty()
            || parameters.expected_version == 0
        {
            return Err(McpError::invalid_params(
                "memoryId, replacement, and a positive expectedVersion are required",
                None,
            ));
        }
        let mut state = lock_state(&self.state)?;
        let scope = memory_scope(
            parameters.domain.as_deref(),
            parameters.entity_id.as_deref(),
            parameters.activity_id.as_deref(),
        )?;
        let grants = authorize(
            &state,
            vec![read_scope(&scope)],
            vec![WritePermission::ReviseMemory],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state);
        let memory = MemoryLifecycleService::new(&mut state.store)
            .revise(ReviseMemoryCommand {
                grant: grants.write,
                memory_id: MemoryId::new(parameters.memory_id),
                expected_version: parameters.expected_version,
                content: parameters.replacement,
                evidence: EvidenceReference::new(
                    EvidenceId::new(format!("evidence_{suffix}")),
                    EvidenceSource::UserStatement,
                ),
                event_id: EventId::new(format!("event_{suffix}")),
                expected_previous_sequence: previous_sequence,
                projections: Vec::new(),
            })
            .map_err(application_error)?;
        mutation_response(memory.id().to_string(), memory.version(), "confirmed")
    }

    #[tool(
        name = "rembrane_forget_memory",
        description = "Create an encrypted deletion tombstone when this connection has deletion permission."
    )]
    fn forget_memory(
        &self,
        Parameters(parameters): Parameters<ForgetMemoryParameters>,
    ) -> Result<String, McpError> {
        if parameters.memory_id.trim().is_empty()
            || parameters.reason.trim().is_empty()
            || parameters.expected_version == 0
        {
            return Err(McpError::invalid_params(
                "memoryId, reason, and a positive expectedVersion are required",
                None,
            ));
        }
        let mut state = lock_state(&self.state)?;
        let scope = memory_scope(
            parameters.domain.as_deref(),
            parameters.entity_id.as_deref(),
            parameters.activity_id.as_deref(),
        )?;
        let grants = authorize(
            &state,
            vec![read_scope(&scope)],
            vec![WritePermission::DeleteMemory],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state);
        let memory = MemoryLifecycleService::new(&mut state.store)
            .delete(DeleteMemoryCommand {
                grant: grants.write,
                memory_id: MemoryId::new(parameters.memory_id),
                expected_version: parameters.expected_version,
                evidence: EvidenceReference::new(
                    EvidenceId::new(format!("evidence_{suffix}")),
                    EvidenceSource::UserStatement,
                ),
                event_id: EventId::new(format!("event_{suffix}")),
                expected_previous_sequence: previous_sequence,
                projections: Vec::new(),
            })
            .map_err(application_error)?;
        mutation_response(memory.id().to_string(), memory.version(), "deleted")
    }

    #[tool(
        name = "rembrane_record_work_trace",
        description = "Record an activity-scoped agent observation as proposed memory. It is not promoted to confirmed user truth."
    )]
    fn record_work_trace(
        &self,
        Parameters(parameters): Parameters<WorkTraceParameters>,
    ) -> Result<String, McpError> {
        if parameters.activity_id.trim().is_empty()
            || parameters.summary.trim().is_empty()
        {
            return Err(McpError::invalid_params(
                "activityId and summary must not be empty",
                None,
            ));
        }
        let mut state = lock_state(&self.state)?;
        let activity_id = ActivityId::new(parameters.activity_id);
        let scope = MemoryScope::Activity {
            id: activity_id.clone(),
        };
        let grants = authorize(
            &state,
            vec![ReadScope::Activity { id: activity_id }],
            vec![WritePermission::ProposeMemory],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state);
        let content = if let Some(entity_id) = parameters.entity_id {
            format!("[entity:{entity_id}] {}", parameters.summary)
        } else {
            parameters.summary
        };
        let memory = MemoryProposalService::new(&mut state.store)
            .propose(ProposeMemoryCommand {
                grant: grants.write,
                memory_id: MemoryId::new(format!("trace_{suffix}")),
                scope,
                kind: MemoryKind::Observation,
                content,
                evidence: EvidenceReference::new(
                    EvidenceId::new(format!("evidence_{suffix}")),
                    EvidenceSource::AgentObservation,
                ),
                event_id: EventId::new(format!("event_{suffix}")),
                expected_previous_sequence: previous_sequence,
                projections: Vec::new(),
            })
            .map_err(application_error)?;
        mutation_response(memory.id().to_string(), memory.version(), "proposed")
    }

    #[tool(
        name = "rembrane_checkpoint_activity",
        description = "Create or update an encrypted activity checkpoint for cross-agent continuation."
    )]
    fn checkpoint_activity(
        &self,
        Parameters(parameters): Parameters<CheckpointParameters>,
    ) -> Result<String, McpError> {
        if parameters.activity_id.trim().is_empty()
            || parameters.summary.trim().is_empty()
            || parameters.expected_version == Some(0)
        {
            return Err(McpError::invalid_params(
                "activityId, summary, and a positive expectedVersion are required",
                None,
            ));
        }
        let mut state = lock_state(&self.state)?;
        let activity_id = ActivityId::new(parameters.activity_id);
        let grants = authorize(
            &state,
            vec![ReadScope::Activity {
                id: activity_id.clone(),
            }],
            vec![WritePermission::WriteCheckpoint],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state);
        let next_steps = parameters.next_steps.unwrap_or_default();
        let blockers = parameters.blockers.unwrap_or_default();
        let checkpoint = if let Some(expected_version) =
            parameters.expected_version
        {
            let current = CheckpointService::new(&mut state.store)
                .resume(&ResumeActivityCommand {
                    grant: grants.read,
                    activity_id,
                })
                .map_err(application_error)?
                .ok_or_else(|| {
                    McpError::invalid_params("activity checkpoint not found", None)
                })?;
            if current.version() != expected_version {
                return Err(McpError::invalid_params(
                    "checkpoint version conflict",
                    None,
                ));
            }
            let updated = current
                .update(parameters.summary, next_steps, blockers)
                .map_err(|_| {
                    McpError::invalid_params("invalid checkpoint update", None)
                })?;
            let updated = if let Some(fingerprint) =
                parameters.state_fingerprint
            {
                updated.with_state_fingerprint(fingerprint).map_err(|_| {
                    McpError::invalid_params(
                        "invalid state fingerprint",
                        None,
                    )
                })?
            } else {
                updated
            };
            CheckpointService::new(&mut state.store)
                .update(UpdateCheckpointCommand {
                    grant: grants.write,
                    checkpoint: updated,
                    expected_version,
                    event_id: EventId::new(format!("event_{suffix}")),
                    expected_previous_sequence: previous_sequence,
                })
                .map_err(application_error)?
        } else {
            let goal = parameters
                .goal
                .filter(|goal| !goal.trim().is_empty())
                .ok_or_else(|| {
                    McpError::invalid_params(
                        "goal is required for a new checkpoint",
                        None,
                    )
                })?;
            let mut checkpoint = ActivityCheckpoint::new(
                CheckpointId::new(format!("checkpoint_{suffix}")),
                state.workspace_id.clone(),
                state.principal_id.clone(),
                activity_id,
                parameters.entity_id.map(EntityId::new),
                goal,
                parameters.summary,
                next_steps,
                blockers,
            )
            .map_err(|_| {
                McpError::invalid_params("invalid activity checkpoint", None)
            })?;
            if let Some(fingerprint) = parameters.state_fingerprint {
                checkpoint = checkpoint
                    .with_state_fingerprint(fingerprint)
                    .map_err(|_| {
                        McpError::invalid_params(
                            "invalid state fingerprint",
                            None,
                        )
                    })?;
            }
            CheckpointService::new(&mut state.store)
                .create(CreateCheckpointCommand {
                    grant: grants.write,
                    checkpoint,
                    event_id: EventId::new(format!("event_{suffix}")),
                    expected_previous_sequence: previous_sequence,
                })
                .map_err(application_error)?
        };

        checkpoint_response(&checkpoint, None)
    }

    #[tool(
        name = "rembrane_resume_activity",
        description = "Retrieve the latest encrypted checkpoint for one authorized activity."
    )]
    fn resume_activity(
        &self,
        Parameters(parameters): Parameters<ResumeActivityParameters>,
    ) -> Result<String, McpError> {
        if parameters.activity_id.trim().is_empty() {
            return Err(McpError::invalid_params(
                "activityId must not be empty",
                None,
            ));
        }
        let mut state = lock_state(&self.state)?;
        let activity_id = ActivityId::new(parameters.activity_id);
        let grants = authorize(
            &state,
            vec![ReadScope::Activity {
                id: activity_id.clone(),
            }],
            Vec::new(),
        )?;
        let checkpoint = CheckpointService::new(&mut state.store)
            .resume(&ResumeActivityCommand {
                grant: grants.read,
                activity_id,
            })
            .map_err(application_error)?;
        checkpoint.as_ref().map_or_else(
            || Ok("null".to_owned()),
            |checkpoint| {
                checkpoint_response(
                    checkpoint,
                    parameters.current_state_fingerprint.as_deref(),
                )
            },
        )
    }
}

fn lock_state(
    state: &Arc<Mutex<State>>,
) -> Result<std::sync::MutexGuard<'_, State>, McpError> {
    state
        .lock()
        .map_err(|_| McpError::internal_error("state lock failed", None))
}

fn authorize(
    state: &State,
    read_scopes: Vec<ReadScope>,
    write_permissions: Vec<WritePermission>,
) -> Result<ClientGrantBundle, McpError> {
    if read_scopes
        .iter()
        .any(|scope| !state.read_scopes.contains(scope))
    {
        return Err(McpError::invalid_params(
            "requested context is outside the connection read scopes",
            None,
        ));
    }
    AuthorizeClientService::new(&state.store)
        .execute(AuthorizeClientCommand {
            client_id: state.client_id.clone(),
            workspace_id: state.workspace_id.clone(),
            principal_id: state.principal_id.clone(),
            requested_read_scopes: read_scopes,
            requested_write_permissions: write_permissions,
        })
        .map_err(application_error)
}

fn request_scopes(
    allowed_scopes: &[ReadScope],
    domain: Option<&str>,
    entity_id: Option<&str>,
    activity_id: Option<&str>,
) -> Vec<ReadScope> {
    let mut scopes = Vec::new();
    if allowed_scopes.contains(&ReadScope::Global) {
        scopes.push(ReadScope::Global);
    }
    if let Some(name) = domain {
        scopes.push(ReadScope::Domain {
            name: name.to_owned(),
        });
    }
    if let Some(id) = entity_id {
        scopes.push(ReadScope::Entity {
            id: EntityId::new(id),
        });
    }
    if let Some(id) = activity_id {
        scopes.push(ReadScope::Activity {
            id: ActivityId::new(id),
        });
    }
    scopes
}

fn memory_scope(
    domain: Option<&str>,
    entity_id: Option<&str>,
    activity_id: Option<&str>,
) -> Result<MemoryScope, McpError> {
    let count = usize::from(domain.is_some())
        + usize::from(entity_id.is_some())
        + usize::from(activity_id.is_some());
    if count > 1 {
        return Err(McpError::invalid_params(
            "domain, entityId, and activityId are mutually exclusive",
            None,
        ));
    }
    if let Some(name) = domain {
        return Ok(MemoryScope::Domain {
            name: name.to_owned(),
        });
    }
    if let Some(id) = entity_id {
        return Ok(MemoryScope::Entity {
            id: EntityId::new(id),
        });
    }
    if let Some(id) = activity_id {
        return Ok(MemoryScope::Activity {
            id: ActivityId::new(id),
        });
    }
    Ok(MemoryScope::Global)
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

fn current_sequence(state: &State) -> Result<u64, McpError> {
    state
        .store
        .list_events_since(&state.workspace_id, 0)
        .map(|events| events.last().map_or(0, rembrane_domain::CanonicalEvent::sequence))
        .map_err(application_error)
}

fn next_id(state: &mut State) -> u128 {
    state.next_id = state.next_id.saturating_add(1);
    state.next_id
}

fn mutation_response(
    memory_id: String,
    version: u64,
    status: &'static str,
) -> Result<String, McpError> {
    serde_json::to_string(&MutationOutput {
        memory_id,
        version,
        status,
    })
    .map_err(|_| McpError::internal_error("response serialization failed", None))
}

fn checkpoint_response(
    checkpoint: &ActivityCheckpoint,
    current_state_fingerprint: Option<&str>,
) -> Result<String, McpError> {
    serde_json::to_string(&CheckpointOutput {
        checkpoint_id: checkpoint.id().to_string(),
        activity_id: checkpoint.activity_id().to_string(),
        entity_id: checkpoint.entity_id().map(ToString::to_string),
        goal: checkpoint.goal().to_owned(),
        summary: checkpoint.summary().to_owned(),
        next_steps: checkpoint.next_steps().to_vec(),
        blockers: checkpoint.blockers().to_vec(),
        state_fingerprint: checkpoint.state_fingerprint().map(str::to_owned),
        stale: current_state_fingerprint.and_then(|current| {
            checkpoint
                .state_fingerprint()
                .map(|recorded| recorded != current)
        }),
        version: checkpoint.version(),
    })
    .map_err(|_| McpError::internal_error("response serialization failed", None))
}

fn application_error(error: rembrane_application::ApplicationError) -> McpError {
    McpError::internal_error(format!("memory operation failed: {error}"), None)
}

fn required_environment(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

#[cfg(test)]
mod tests {
    use rembrane_domain::{EntityId, ReadScope};

    use super::request_scopes;

    #[test]
    fn context_requests_do_not_gain_unconfigured_global_access() {
        let allowed = vec![ReadScope::Entity {
            id: EntityId::new("project_01"),
        }];

        assert_eq!(
            request_scopes(&allowed, None, Some("project_01"), None),
            allowed
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let server = RembraneMcp::from_environment()?;
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

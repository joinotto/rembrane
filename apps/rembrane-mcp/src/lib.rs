use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rembrane_application::{
    AddTripConstraintCommand, AddTripParticipantCommand, AuthorizeClientCommand,
    AuthorizeClientService, CaptureBookingResearchCommand, CaptureBookingResearchService,
    CheckpointService, ClientGrantBundle, CreateCheckpointCommand, CreateTripCommand,
    DeleteMemoryCommand, EventRepository, MemoryLifecycleService, MemoryProposalService,
    ProposeMemoryCommand, RecordTripDecisionCommand, RememberPreferenceCommand,
    RememberPreferenceService, ResolveContextCommand, ResolveContextService,
    ResolveTravelContextCommand, ResumeActivityCommand, ReviseMemoryCommand, TravelContextResearch,
    TravelContextService, TravelContextTrip, TravelSensitiveProfile, TripService,
    UpdateCheckpointCommand,
};
use rembrane_config::{parse_read_permissions, parse_read_scopes};
use rembrane_contracts::{ResolveContextRequest, VerifiedRemoteAccess};
use rembrane_crypto_configured::ConfiguredRecordCipher;
use rembrane_domain::{
    ActivityCheckpoint, ActivityId, BookingResearch, BookingResearchId, BookingResearchKind,
    CheckpointId, ClientId, ContextPackId, DecisionStatus, DisclosureId, EntityId, EventId,
    EvidenceId, EvidenceReference, EvidenceSource, MemoryId, MemoryKind, MemoryScope, PrincipalId,
    ReadPermission, ReadScope, TravelDateWindow, Trip, TripConstraint, TripConstraintId,
    TripConstraintKind, TripDecision, TripDecisionId, TripParticipant, TripParticipantId,
    WorkspaceId, WritePermission,
};
use rembrane_store_sqlite::SqliteStore;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData as McpError, ServiceExt, schemars, tool, tool_router, transport::stdio};
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CaptureBookingResearchParameters {
    trip_id: String,
    kind: String,
    provider: String,
    summary: String,
    source_reference: String,
    evidence_source: String,
    observed_at: String,
    expires_at: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CreateTripParameters {
    title: String,
    origin: String,
    destinations: Vec<String>,
    depart_not_before: String,
    return_not_after: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AddTripParticipantParameters {
    trip_id: String,
    label: String,
    expected_trip_version: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AddTripConstraintParameters {
    trip_id: String,
    participant_id: Option<String>,
    kind: String,
    statement: String,
    evidence_source: String,
    expected_trip_version: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RecordTripDecisionParameters {
    trip_id: String,
    status: String,
    summary: String,
    rationale: Option<String>,
    evidence_source: String,
    expected_trip_version: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ResolveTravelContextParameters {
    trip_id: String,
    purpose: String,
    as_of: String,
    include_source_references: Option<bool>,
    include_sensitive_profile: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TripOutput {
    trip_id: String,
    version: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TripParticipantOutput {
    trip_id: String,
    participant_id: String,
    label: String,
    trip_version: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TripRevisionOutput {
    trip_id: String,
    record_id: String,
    trip_version: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BookingResearchOutput {
    research_id: String,
    trip_id: String,
    version: u64,
    expires_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TravelContextOutput {
    disclosure_id: String,
    trip: TravelTripOutput,
    fresh_research: Vec<TravelResearchOutput>,
    expired_research: Vec<TravelResearchOutput>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TravelTripOutput {
    trip_id: String,
    title: String,
    origin: String,
    destinations: Vec<String>,
    depart_not_before: String,
    return_not_after: String,
    version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sensitive_profile: Option<TravelSensitiveProfileOutput>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TravelSensitiveProfileOutput {
    participants: Vec<TravelParticipantOutput>,
    constraints: Vec<TravelConstraintOutput>,
    decisions: Vec<TravelDecisionOutput>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TravelParticipantOutput {
    participant_id: String,
    label: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TravelConstraintOutput {
    constraint_id: String,
    participant_id: Option<String>,
    kind: &'static str,
    statement: String,
    evidence_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TravelDecisionOutput {
    decision_id: String,
    status: &'static str,
    summary: String,
    rationale: Option<String>,
    decided_by: String,
    evidence_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TravelResearchOutput {
    research_id: String,
    kind: &'static str,
    provider: String,
    summary: String,
    evidence_id: String,
    observed_at: String,
    expires_at: String,
    version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_reference: Option<String>,
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
    disclosure_id: Option<String>,
    version: u64,
}

struct State {
    store: SqliteStore<ConfiguredRecordCipher>,
    principal_id: PrincipalId,
    workspace_id: WorkspaceId,
    client_id: ClientId,
    read_scopes: Vec<ReadScope>,
    read_permissions: Vec<ReadPermission>,
    next_id: u128,
}

#[derive(Clone)]
pub struct RembraneMcp {
    state: Arc<Mutex<State>>,
}

impl RembraneMcp {
    pub fn from_environment() -> Result<Self> {
        let database = required_environment("REMBRANE_DATABASE")?;
        let principal_id = PrincipalId::new(required_environment("REMBRANE_PRINCIPAL_ID")?);
        let workspace_id = WorkspaceId::new(required_environment("REMBRANE_WORKSPACE_ID")?);
        let client_id = ClientId::new(required_environment("REMBRANE_CLIENT_ID")?);
        Self::from_connection(database, principal_id, workspace_id, client_id)
    }

    /// Builds an MCP service whose canonical identity comes exclusively from
    /// verified remote access claims.
    ///
    /// # Errors
    ///
    /// Returns an error when storage, encryption, configured scope policy, or
    /// canonical workspace authorization cannot be initialized.
    pub fn from_verified_remote_access(access: &VerifiedRemoteAccess) -> Result<Self> {
        Self::from_connection(
            required_environment("REMBRANE_DATABASE")?,
            access.subject_id().clone(),
            access.workspace_id().clone(),
            access.client_id().clone(),
        )
    }

    fn from_connection(
        database: String,
        principal_id: PrincipalId,
        workspace_id: WorkspaceId,
        client_id: ClientId,
    ) -> Result<Self> {
        let cipher = ConfiguredRecordCipher::from_environment()
            .context("failed to load workspace cipher")?;
        let read_scopes = parse_read_scopes(
            &std::env::var("REMBRANE_READ_SCOPES").unwrap_or_else(|_| "global".to_owned()),
        )
        .map_err(anyhow::Error::msg)?;
        let read_permissions =
            parse_read_permissions(&std::env::var("REMBRANE_READ_PERMISSIONS").unwrap_or_default())
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
                requested_read_permissions: read_permissions.clone(),
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
                read_permissions,
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
        if parameters.purpose.trim().is_empty() || parameters.query.trim().is_empty() {
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
                context_pack_id: ContextPackId::new(format!("context_{suffix}")),
                disclosure_id: DisclosureId::new(format!("disclosure_{suffix}")),
            })
            .map_err(|error| {
                McpError::internal_error(format!("context resolution failed: {error}"), None)
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

        serde_json::to_string(&output)
            .map_err(|_| McpError::internal_error("response serialization failed", None))
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
            return Err(McpError::invalid_params("content must not be empty", None));
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
        if parameters.activity_id.trim().is_empty() || parameters.summary.trim().is_empty() {
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
        let checkpoint = if let Some(expected_version) = parameters.expected_version {
            let current = CheckpointService::new(&mut state.store)
                .load_for_update(&grants.read, &activity_id)
                .map_err(application_error)?
                .ok_or_else(|| McpError::invalid_params("activity checkpoint not found", None))?;
            if current.version() != expected_version {
                return Err(McpError::invalid_params(
                    "checkpoint version conflict",
                    None,
                ));
            }
            let updated = current
                .update(parameters.summary, next_steps, blockers)
                .map_err(|_| McpError::invalid_params("invalid checkpoint update", None))?;
            let updated = if let Some(fingerprint) = parameters.state_fingerprint {
                updated
                    .with_state_fingerprint(fingerprint)
                    .map_err(|_| McpError::invalid_params("invalid state fingerprint", None))?
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
                    McpError::invalid_params("goal is required for a new checkpoint", None)
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
            .map_err(|_| McpError::invalid_params("invalid activity checkpoint", None))?;
            if let Some(fingerprint) = parameters.state_fingerprint {
                checkpoint = checkpoint
                    .with_state_fingerprint(fingerprint)
                    .map_err(|_| McpError::invalid_params("invalid state fingerprint", None))?;
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

        checkpoint_response(&checkpoint, None, None)
    }

    #[tool(
        name = "rembrane_create_trip",
        description = "Create a new encrypted trip under the connection's travel-domain capability."
    )]
    fn create_trip(
        &self,
        Parameters(parameters): Parameters<CreateTripParameters>,
    ) -> Result<String, McpError> {
        let mut state = lock_state(&self.state)?;
        let grants = authorize(
            &state,
            vec![ReadScope::Domain {
                name: "travel".to_owned(),
            }],
            vec![WritePermission::CreateTrip],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state);
        let date_window =
            TravelDateWindow::new(parameters.depart_not_before, parameters.return_not_after)
                .map_err(|_| McpError::invalid_params("invalid trip date window", None))?;
        let trip = Trip::new(
            EntityId::new(format!("trip_{suffix}")),
            state.workspace_id.clone(),
            state.principal_id.clone(),
            parameters.title,
            parameters.origin,
            parameters.destinations,
            date_window,
        )
        .map_err(|_| McpError::invalid_params("invalid trip", None))?;
        let created = TripService::new(&mut state.store)
            .create(CreateTripCommand {
                grant: grants.write,
                trip,
                event_id: EventId::new(format!("event_{suffix}")),
                expected_previous_sequence: previous_sequence,
            })
            .map_err(application_error)?;
        let created_scope = ReadScope::Entity {
            id: created.id().clone(),
        };
        if !state.read_scopes.contains(&created_scope) {
            state.read_scopes.push(created_scope);
        }
        serde_json::to_string(&TripOutput {
            trip_id: created.id().to_string(),
            version: created.version(),
        })
        .map_err(|_| McpError::internal_error("response serialization failed", None))
    }

    #[tool(
        name = "rembrane_capture_booking_research",
        description = "Capture one encrypted, expiring, evidence-backed observation for an authorized trip."
    )]
    fn capture_booking_research(
        &self,
        Parameters(parameters): Parameters<CaptureBookingResearchParameters>,
    ) -> Result<String, McpError> {
        let kind = parse_research_kind(&parameters.kind).ok_or_else(|| {
            McpError::invalid_params(
                "kind must be flight, lodging, ground-transport, activity, or other",
                None,
            )
        })?;
        let evidence_source = parse_evidence_source(&parameters.evidence_source)
            .ok_or_else(|| McpError::invalid_params("evidenceSource is unsupported", None))?;
        let mut state = lock_state(&self.state)?;
        let trip_id = EntityId::new(parameters.trip_id);
        let grants = authorize(
            &state,
            vec![ReadScope::Entity {
                id: trip_id.clone(),
            }],
            vec![WritePermission::CaptureBookingResearch],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state);
        let research = BookingResearch::new(
            BookingResearchId::new(format!("research_{suffix}")),
            state.workspace_id.clone(),
            trip_id,
            state.principal_id.clone(),
            kind,
            parameters.provider,
            parameters.summary,
            parameters.source_reference,
            EvidenceReference::new(
                EvidenceId::new(format!("evidence_{suffix}")),
                evidence_source,
            ),
            parameters.observed_at,
            parameters.expires_at,
        )
        .map_err(|_| McpError::invalid_params("invalid booking research", None))?;
        let captured = CaptureBookingResearchService::new(&mut state.store)
            .execute(CaptureBookingResearchCommand {
                grant: grants.write,
                research,
                event_id: EventId::new(format!("event_{suffix}")),
                expected_previous_sequence: previous_sequence,
            })
            .map_err(application_error)?;
        serde_json::to_string(&BookingResearchOutput {
            research_id: captured.id().to_string(),
            trip_id: captured.trip_id().to_string(),
            version: captured.version(),
            expires_at: captured.expires_at().to_owned(),
        })
        .map_err(|_| McpError::internal_error("response serialization failed", None))
    }

    #[tool(
        name = "rembrane_add_trip_participant",
        description = "Atomically add one participant to an authorized trip without replacing unrelated trip state."
    )]
    fn add_trip_participant(
        &self,
        Parameters(parameters): Parameters<AddTripParticipantParameters>,
    ) -> Result<String, McpError> {
        let mut state = lock_state(&self.state)?;
        let trip_id = EntityId::new(parameters.trip_id);
        let grants = authorize(
            &state,
            vec![ReadScope::Entity {
                id: trip_id.clone(),
            }],
            vec![WritePermission::ReviseTrip],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state);
        let participant_id = TripParticipantId::new(format!("participant_{suffix}"));
        let participant = TripParticipant::new(participant_id.clone(), parameters.label)
            .map_err(|_| McpError::invalid_params("invalid trip participant", None))?;
        let revised = TripService::new(&mut state.store)
            .add_participant(AddTripParticipantCommand {
                grant: grants.write,
                trip_id,
                participant,
                expected_trip_version: parameters.expected_trip_version,
                event_id: EventId::new(format!("event_{suffix}")),
                expected_previous_sequence: previous_sequence,
            })
            .map_err(application_error)?;
        let stored = revised
            .participants()
            .iter()
            .find(|participant| participant.id() == &participant_id)
            .ok_or_else(|| McpError::internal_error("participant mutation was lost", None))?;
        serde_json::to_string(&TripParticipantOutput {
            trip_id: revised.id().to_string(),
            participant_id: stored.id().to_string(),
            label: stored.label().to_owned(),
            trip_version: revised.version(),
        })
        .map_err(|_| McpError::internal_error("response serialization failed", None))
    }

    #[tool(
        name = "rembrane_add_trip_constraint",
        description = "Atomically add one evidence-backed constraint to an authorized trip."
    )]
    fn add_trip_constraint(
        &self,
        Parameters(parameters): Parameters<AddTripConstraintParameters>,
    ) -> Result<String, McpError> {
        let kind = parse_constraint_kind(&parameters.kind)
            .ok_or_else(|| McpError::invalid_params("unsupported constraint kind", None))?;
        let evidence_source = parse_evidence_source(&parameters.evidence_source)
            .ok_or_else(|| McpError::invalid_params("unsupported evidence source", None))?;
        let mut state = lock_state(&self.state)?;
        let trip_id = EntityId::new(parameters.trip_id);
        let grants = authorize(
            &state,
            vec![ReadScope::Entity {
                id: trip_id.clone(),
            }],
            vec![WritePermission::ReviseTrip],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state);
        let constraint_id = TripConstraintId::new(format!("constraint_{suffix}"));
        let constraint = TripConstraint::new(
            constraint_id.clone(),
            parameters.participant_id.map(TripParticipantId::new),
            kind,
            parameters.statement,
            EvidenceReference::new(
                EvidenceId::new(format!("evidence_{suffix}")),
                evidence_source,
            ),
        )
        .map_err(|_| McpError::invalid_params("invalid trip constraint", None))?;
        let revised = TripService::new(&mut state.store)
            .add_constraint(AddTripConstraintCommand {
                grant: grants.write,
                trip_id,
                constraint,
                expected_trip_version: parameters.expected_trip_version,
                event_id: EventId::new(format!("event_{suffix}")),
                expected_previous_sequence: previous_sequence,
            })
            .map_err(application_error)?;
        serde_json::to_string(&TripRevisionOutput {
            trip_id: revised.id().to_string(),
            record_id: constraint_id.to_string(),
            trip_version: revised.version(),
        })
        .map_err(|_| McpError::internal_error("response serialization failed", None))
    }

    #[tool(
        name = "rembrane_record_trip_decision",
        description = "Atomically record one evidence-backed decision attributed to the authenticated principal."
    )]
    fn record_trip_decision(
        &self,
        Parameters(parameters): Parameters<RecordTripDecisionParameters>,
    ) -> Result<String, McpError> {
        let status = parse_decision_status(&parameters.status)
            .ok_or_else(|| McpError::invalid_params("unsupported decision status", None))?;
        let evidence_source = parse_evidence_source(&parameters.evidence_source)
            .ok_or_else(|| McpError::invalid_params("unsupported evidence source", None))?;
        let mut state = lock_state(&self.state)?;
        let trip_id = EntityId::new(parameters.trip_id);
        let grants = authorize(
            &state,
            vec![ReadScope::Entity {
                id: trip_id.clone(),
            }],
            vec![WritePermission::ReviseTrip],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state);
        let decision_id = TripDecisionId::new(format!("decision_{suffix}"));
        let decision = TripDecision::new(
            decision_id.clone(),
            status,
            parameters.summary,
            parameters.rationale,
            state.principal_id.clone(),
            EvidenceReference::new(
                EvidenceId::new(format!("evidence_{suffix}")),
                evidence_source,
            ),
        )
        .map_err(|_| McpError::invalid_params("invalid trip decision", None))?;
        let revised = TripService::new(&mut state.store)
            .record_decision(RecordTripDecisionCommand {
                grant: grants.write,
                trip_id,
                decision,
                expected_trip_version: parameters.expected_trip_version,
                event_id: EventId::new(format!("event_{suffix}")),
                expected_previous_sequence: previous_sequence,
            })
            .map_err(application_error)?;
        serde_json::to_string(&TripRevisionOutput {
            trip_id: revised.id().to_string(),
            record_id: decision_id.to_string(),
            trip_version: revised.version(),
        })
        .map_err(|_| McpError::internal_error("response serialization failed", None))
    }

    #[tool(
        name = "rembrane_resolve_travel_context",
        description = "Retrieve one authorized trip with fresh and expired research, recording an exact-version disclosure receipt."
    )]
    fn resolve_travel_context(
        &self,
        Parameters(parameters): Parameters<ResolveTravelContextParameters>,
    ) -> Result<String, McpError> {
        let mut state = lock_state(&self.state)?;
        let trip_id = EntityId::new(parameters.trip_id);
        let grants = authorize(
            &state,
            vec![ReadScope::Entity {
                id: trip_id.clone(),
            }],
            Vec::new(),
        )?;
        let disclosure_id = DisclosureId::new(format!("disclosure_{}", next_id(&mut state)));
        let context = TravelContextService::new(&mut state.store)
            .resolve(&ResolveTravelContextCommand {
                grant: grants.read,
                disclosure_id: disclosure_id.clone(),
                trip_id,
                purpose: parameters.purpose,
                as_of: parameters.as_of,
                include_source_references: parameters.include_source_references.unwrap_or(false),
                include_sensitive_profile: parameters.include_sensitive_profile.unwrap_or(false),
            })
            .map_err(application_error)?;
        serde_json::to_string(&TravelContextOutput {
            disclosure_id: disclosure_id.to_string(),
            trip: TravelTripOutput::from(&context.trip),
            fresh_research: context
                .fresh_research
                .iter()
                .map(TravelResearchOutput::from)
                .collect(),
            expired_research: context
                .expired_research
                .iter()
                .map(TravelResearchOutput::from)
                .collect(),
        })
        .map_err(|_| McpError::internal_error("response serialization failed", None))
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
        let disclosure_id = DisclosureId::new(format!("disclosure_{}", next_id(&mut state)));
        let checkpoint = CheckpointService::new(&mut state.store)
            .resume(&ResumeActivityCommand {
                grant: grants.read,
                activity_id,
                disclosure_id: disclosure_id.clone(),
                purpose: "resume-activity".to_owned(),
            })
            .map_err(application_error)?;
        checkpoint.as_ref().map_or_else(
            || Ok("null".to_owned()),
            |checkpoint| {
                checkpoint_response(
                    checkpoint,
                    parameters.current_state_fingerprint.as_deref(),
                    Some(&disclosure_id),
                )
            },
        )
    }
}

fn parse_research_kind(value: &str) -> Option<BookingResearchKind> {
    match value {
        "flight" => Some(BookingResearchKind::Flight),
        "lodging" => Some(BookingResearchKind::Lodging),
        "ground-transport" => Some(BookingResearchKind::GroundTransport),
        "activity" => Some(BookingResearchKind::Activity),
        "other" => Some(BookingResearchKind::Other),
        _ => None,
    }
}

fn parse_constraint_kind(value: &str) -> Option<TripConstraintKind> {
    match value {
        "accessibility" => Some(TripConstraintKind::Accessibility),
        "accommodation" => Some(TripConstraintKind::Accommodation),
        "budget" => Some(TripConstraintKind::Budget),
        "dietary" => Some(TripConstraintKind::Dietary),
        "documentation" => Some(TripConstraintKind::Documentation),
        "schedule" => Some(TripConstraintKind::Schedule),
        "transport" => Some(TripConstraintKind::Transport),
        "other" => Some(TripConstraintKind::Other),
        _ => None,
    }
}

fn parse_decision_status(value: &str) -> Option<DecisionStatus> {
    match value {
        "proposed" => Some(DecisionStatus::Proposed),
        "selected" => Some(DecisionStatus::Selected),
        "rejected" => Some(DecisionStatus::Rejected),
        _ => None,
    }
}

const fn constraint_kind_name(kind: TripConstraintKind) -> &'static str {
    match kind {
        TripConstraintKind::Accessibility => "accessibility",
        TripConstraintKind::Accommodation => "accommodation",
        TripConstraintKind::Budget => "budget",
        TripConstraintKind::Dietary => "dietary",
        TripConstraintKind::Documentation => "documentation",
        TripConstraintKind::Schedule => "schedule",
        TripConstraintKind::Transport => "transport",
        TripConstraintKind::Other => "other",
    }
}

const fn decision_status_name(status: DecisionStatus) -> &'static str {
    match status {
        DecisionStatus::Proposed => "proposed",
        DecisionStatus::Selected => "selected",
        DecisionStatus::Rejected => "rejected",
    }
}

fn research_kind_name(kind: BookingResearchKind) -> &'static str {
    match kind {
        BookingResearchKind::Flight => "flight",
        BookingResearchKind::Lodging => "lodging",
        BookingResearchKind::GroundTransport => "ground-transport",
        BookingResearchKind::Activity => "activity",
        BookingResearchKind::Other => "other",
    }
}

impl From<&TravelContextTrip> for TravelTripOutput {
    fn from(trip: &TravelContextTrip) -> Self {
        Self {
            trip_id: trip.id.to_string(),
            title: trip.title.clone(),
            origin: trip.origin.clone(),
            destinations: trip.destinations.clone(),
            depart_not_before: trip.depart_not_before.clone(),
            return_not_after: trip.return_not_after.clone(),
            version: trip.version,
            sensitive_profile: trip
                .sensitive_profile
                .as_ref()
                .map(TravelSensitiveProfileOutput::from),
        }
    }
}

impl From<&TravelSensitiveProfile> for TravelSensitiveProfileOutput {
    fn from(profile: &TravelSensitiveProfile) -> Self {
        Self {
            participants: profile
                .participants
                .iter()
                .map(|participant| TravelParticipantOutput {
                    participant_id: participant.id().to_string(),
                    label: participant.label().to_owned(),
                })
                .collect(),
            constraints: profile
                .constraints
                .iter()
                .map(|constraint| TravelConstraintOutput {
                    constraint_id: constraint.id().to_string(),
                    participant_id: constraint.participant_id().map(ToString::to_string),
                    kind: constraint_kind_name(constraint.kind()),
                    statement: constraint.statement().to_owned(),
                    evidence_id: constraint.evidence().id.to_string(),
                })
                .collect(),
            decisions: profile
                .decisions
                .iter()
                .map(|decision| TravelDecisionOutput {
                    decision_id: decision.id().to_string(),
                    status: decision_status_name(decision.status()),
                    summary: decision.summary().to_owned(),
                    rationale: decision.rationale().map(str::to_owned),
                    decided_by: decision.decided_by().to_string(),
                    evidence_id: decision.evidence().id.to_string(),
                })
                .collect(),
        }
    }
}

impl From<&TravelContextResearch> for TravelResearchOutput {
    fn from(research: &TravelContextResearch) -> Self {
        Self {
            research_id: research.id.to_string(),
            kind: research_kind_name(research.kind),
            provider: research.provider.clone(),
            summary: research.summary.clone(),
            evidence_id: research.evidence_id.to_string(),
            observed_at: research.observed_at.clone(),
            expires_at: research.expires_at.clone(),
            version: research.version,
            source_reference: research.source_reference.clone(),
        }
    }
}

fn parse_evidence_source(value: &str) -> Option<EvidenceSource> {
    match value {
        "user-statement" => Some(EvidenceSource::UserStatement),
        "agent-observation" => Some(EvidenceSource::AgentObservation),
        "tool-result" => Some(EvidenceSource::ToolResult),
        "imported-record" => Some(EvidenceSource::ImportedRecord),
        "workspace-decision" => Some(EvidenceSource::WorkspaceDecision),
        _ => None,
    }
}

fn lock_state(state: &Arc<Mutex<State>>) -> Result<std::sync::MutexGuard<'_, State>, McpError> {
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
            requested_read_permissions: state.read_permissions.clone(),
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
        MemoryScope::Domain { name } => ReadScope::Domain { name: name.clone() },
        MemoryScope::Entity { id } => ReadScope::Entity { id: id.clone() },
        MemoryScope::Activity { id } => ReadScope::Activity { id: id.clone() },
    }
}

fn current_sequence(state: &State) -> Result<u64, McpError> {
    state
        .store
        .list_events_since(&state.workspace_id, 0)
        .map(|events| {
            events
                .last()
                .map_or(0, rembrane_domain::CanonicalEvent::sequence)
        })
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
    disclosure_id: Option<&DisclosureId>,
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
        disclosure_id: disclosure_id.map(ToString::to_string),
        version: checkpoint.version(),
    })
    .map_err(|_| McpError::internal_error("response serialization failed", None))
}

fn application_error(error: rembrane_application::ApplicationError) -> McpError {
    use rembrane_application::ApplicationError;

    match error {
        ApplicationError::AccessDenied | ApplicationError::NotFound => {
            McpError::invalid_params("operation is not authorized or available", None)
        }
        ApplicationError::AlreadyExists => McpError::invalid_params("record already exists", None),
        ApplicationError::SequenceConflict | ApplicationError::VersionConflict => {
            McpError::invalid_params(
                "operation conflicts with newer state; refresh and retry",
                None,
            )
        }
        ApplicationError::Validation(message) => {
            McpError::invalid_params(format!("operation validation failed: {message}"), None)
        }
        ApplicationError::StorageUnavailable => {
            McpError::internal_error("memory storage is temporarily unavailable", None)
        }
    }
}

fn required_environment(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

pub async fn run_stdio() -> Result<()> {
    let server = RembraneMcp::from_environment()?;
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
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

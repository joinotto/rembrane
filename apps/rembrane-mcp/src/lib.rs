use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rembrane_application::{
    AddTripConstraintCommand, AddTripParticipantCommand, AuthorizeClientCommand,
    AuthorizeClientService, CaptureBookingResearchCommand, CaptureBookingResearchService,
    CheckpointService, ClientGrantBundle, CreateCheckpointCommand, CreateTripCommand,
    DeleteMemoryCommand, EventRepository, GraphContextService, MemoryLifecycleService,
    MemoryProposalService, ProposeMemoryCommand, RecordTripDecisionCommand,
    RememberPreferenceCommand, RememberPreferenceService, ResolveContextCommand,
    ResolveContextService, ResolveTravelContextCommand, ResumeActivityCommand, ReviseMemoryCommand,
    TravelContextResearch, TravelContextService, TravelContextTrip, TravelSensitiveProfile,
    TripService, UpdateCheckpointCommand,
};
use rembrane_config::{parse_read_permissions, parse_read_scopes};
use rembrane_contracts::{ResolveContextRequest, ResolveGraphContextRequest, VerifiedRemoteAccess};
use rembrane_crypto_configured::ConfiguredRecordCipher;
use rembrane_domain::{
    ActivityCheckpoint, ActivityId, BookingResearch, BookingResearchId, BookingResearchKind,
    CheckpointId, ClientId, ContextPackId, DecisionStatus, DisclosureId, EntityId, EventId,
    EvidenceId, EvidenceReference, EvidenceSource, GraphDisclosureDirection, KnowledgeNodeId,
    MemoryId, MemoryKind, MemoryScope, PrincipalId, ReadPermission, ReadScope, TravelDateWindow,
    Trip, TripConstraint, TripConstraintId, TripConstraintKind, TripDecision, TripDecisionId,
    TripParticipant, TripParticipantId, WorkspaceId, WritePermission,
};
use rembrane_graph_configured::ConfiguredGraphProvider;
use rembrane_store_sqlite::SqliteStore;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{
    ErrorData as McpError, RoleServer, ServiceExt, schemars, service::RequestContext, tool,
    tool_router, transport::stdio,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

const MAXIMUM_BLOCKING_OPERATIONS: usize = 8;
static BLOCKING_OPERATIONS: OnceLock<Arc<Semaphore>> = OnceLock::new();

#[derive(Deserialize, schemars::JsonSchema)]
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

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ResolveGraphContextParameters {
    node_id: String,
    direction: String,
    valid_at_epoch_seconds: u64,
    maximum_candidates: Option<usize>,
    purpose: String,
    domain: Option<String>,
    entity_id: Option<String>,
    activity_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphEdgeOutput {
    edge_id: String,
    source_node_id: String,
    target_node_id: String,
    relation: String,
    version: u64,
    valid_from_epoch_seconds: u64,
    valid_until_epoch_seconds: Option<u64>,
    recorded_at_epoch_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResolveGraphContextOutput {
    disclosure_id: String,
    edges: Vec<GraphEdgeOutput>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RememberPreferenceParameters {
    content: String,
    domain: Option<String>,
    entity_id: Option<String>,
    activity_id: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CorrectMemoryParameters {
    memory_id: String,
    expected_version: u64,
    replacement: String,
    domain: Option<String>,
    entity_id: Option<String>,
    activity_id: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ForgetMemoryParameters {
    memory_id: String,
    expected_version: u64,
    reason: String,
    domain: Option<String>,
    entity_id: Option<String>,
    activity_id: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
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

#[derive(Deserialize, schemars::JsonSchema)]
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

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ResumeActivityParameters {
    activity_id: String,
    current_state_fingerprint: Option<String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
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

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CreateTripParameters {
    title: String,
    origin: String,
    destinations: Vec<String>,
    depart_not_before: String,
    return_not_after: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AddTripParticipantParameters {
    trip_id: String,
    label: String,
    expected_trip_version: u64,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AddTripConstraintParameters {
    trip_id: String,
    participant_id: Option<String>,
    kind: String,
    statement: String,
    evidence_source: String,
    expected_trip_version: u64,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RecordTripDecisionParameters {
    trip_id: String,
    status: String,
    summary: String,
    rationale: Option<String>,
    evidence_source: String,
    expected_trip_version: u64,
}

#[derive(Deserialize, schemars::JsonSchema)]
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
    graph_provider: ConfiguredGraphProvider,
    policy: Arc<ConnectionPolicy>,
    read_scopes: Vec<ReadScope>,
    read_permissions: Vec<ReadPermission>,
    next_id: u128,
}

#[derive(Clone, Eq, PartialEq)]
struct ConnectionIdentity {
    principal: PrincipalId,
    workspace: WorkspaceId,
    client: ClientId,
}

struct ConnectionPolicy {
    identity: ConnectionIdentity,
    require_verified_request_identity: bool,
}

impl ConnectionIdentity {
    fn from_verified_remote_access(access: &VerifiedRemoteAccess) -> Self {
        Self {
            principal: access.subject_id().clone(),
            workspace: access.workspace_id().clone(),
            client: access.client_id().clone(),
        }
    }
}

#[derive(Clone)]
pub struct RembraneMcp {
    state: Arc<Mutex<State>>,
    policy: Arc<ConnectionPolicy>,
    blocking_operations: Arc<Semaphore>,
}

impl RembraneMcp {
    /// Initializes storage and providers synchronously.
    ///
    /// Call outside an async executor, or use [`Self::from_environment_async`].
    pub fn from_environment() -> Result<Self> {
        let database = required_environment("REMBRANE_DATABASE")?;
        let principal_id = PrincipalId::new(required_environment("REMBRANE_PRINCIPAL_ID")?);
        let workspace_id = WorkspaceId::new(required_environment("REMBRANE_WORKSPACE_ID")?);
        let client_id = ClientId::new(required_environment("REMBRANE_CLIENT_ID")?);
        Self::from_connection(
            database,
            ConnectionIdentity {
                principal: principal_id,
                workspace: workspace_id,
                client: client_id,
            },
            false,
        )
    }

    /// Builds an MCP service whose canonical identity comes exclusively from
    /// verified remote access claims.
    ///
    /// This is synchronous provider initialization. Async callers should use
    /// [`Self::from_verified_remote_access_async`] instead.
    ///
    /// # Errors
    ///
    /// Returns an error when storage, encryption, configured scope policy, or
    /// canonical workspace authorization cannot be initialized.
    pub fn from_verified_remote_access(access: &VerifiedRemoteAccess) -> Result<Self> {
        Self::from_connection(
            required_environment("REMBRANE_DATABASE")?,
            ConnectionIdentity::from_verified_remote_access(access),
            true,
        )
    }

    /// Initializes the stdio service on a bounded blocking worker.
    ///
    /// # Errors
    ///
    /// Returns an error if capacity is unavailable or initialization fails.
    pub async fn from_environment_async() -> Result<Self> {
        initialize_on_worker(Self::from_environment).await
    }

    /// Initializes a remote service on a bounded blocking worker using only
    /// verified claims. Its tools still require matching per-request proof.
    ///
    /// # Errors
    ///
    /// Returns an error if capacity is unavailable or initialization fails.
    pub async fn from_verified_remote_access_async(access: &VerifiedRemoteAccess) -> Result<Self> {
        let access = access.clone();
        initialize_on_worker(move || Self::from_verified_remote_access(&access)).await
    }

    fn from_connection(
        database: String,
        identity: ConnectionIdentity,
        require_verified_request_identity: bool,
    ) -> Result<Self> {
        let read_scopes = parse_read_scopes(
            &std::env::var("REMBRANE_READ_SCOPES").unwrap_or_else(|_| "global".to_owned()),
        )
        .map_err(anyhow::Error::msg)?;
        let read_permissions =
            parse_read_permissions(&std::env::var("REMBRANE_READ_PERMISSIONS").unwrap_or_default())
                .map_err(anyhow::Error::msg)?;
        let store = SqliteStore::open(database).context("failed to open Rembrane database")?;
        Self::from_store(
            store,
            identity,
            require_verified_request_identity,
            read_scopes,
            read_permissions,
            || {
                let cipher = ConfiguredRecordCipher::from_environment()
                    .context("failed to load workspace cipher")?;
                let graph_provider = ConfiguredGraphProvider::from_environment()
                    .context("failed to configure graph provider")?;
                Ok((cipher, graph_provider))
            },
        )
    }

    fn from_store<Initialize>(
        store: SqliteStore,
        identity: ConnectionIdentity,
        require_verified_request_identity: bool,
        read_scopes: Vec<ReadScope>,
        read_permissions: Vec<ReadPermission>,
        initialize: Initialize,
    ) -> Result<Self>
    where
        Initialize: FnOnce() -> Result<(ConfiguredRecordCipher, ConfiguredGraphProvider)>,
    {
        // Membership, pending rotation, and canonical scope policy are
        // metadata-only checks. Do not resolve keys or contact providers for
        // a rejected tenant just to perform them.
        AuthorizeClientService::new(&store)
            .execute(AuthorizeClientCommand {
                client_id: identity.client.clone(),
                workspace_id: identity.workspace.clone(),
                principal_id: identity.principal.clone(),
                requested_read_scopes: read_scopes.clone(),
                requested_read_permissions: read_permissions.clone(),
                requested_write_permissions: Vec::new(),
            })
            .context("failed to authorize MCP connection")?;
        let next_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_nanos();
        let (cipher, graph_provider) = initialize()?;
        let store = store.with_cipher(cipher);

        let policy = Arc::new(ConnectionPolicy {
            identity,
            require_verified_request_identity,
        });
        Ok(Self {
            state: Arc::new(Mutex::new(State {
                store,
                graph_provider,
                policy: Arc::clone(&policy),
                read_scopes,
                read_permissions,
                next_id,
            })),
            policy,
            blocking_operations: blocking_capacity(),
        })
    }

    async fn run_tool<T, F>(
        &self,
        context: RequestContext<RoleServer>,
        operation: F,
    ) -> Result<T, McpError>
    where
        T: Send + 'static,
        F: FnOnce(Self, RequestContext<RoleServer>) -> Result<T, McpError> + Send + 'static,
    {
        // Check immutable identity before admission without taking the store mutex.
        // The worker still reauthorizes current canonical membership and scopes.
        authorize_request_identity(&self.policy, &context)?;
        ensure_not_cancelled(&context)?;
        let server = self.clone();
        run_blocking_operation(Arc::clone(&self.blocking_operations), move || {
            ensure_not_cancelled(&context)?;
            operation(server, context)
        })
        .await
    }
}

fn blocking_capacity() -> Arc<Semaphore> {
    Arc::clone(
        BLOCKING_OPERATIONS.get_or_init(|| Arc::new(Semaphore::new(MAXIMUM_BLOCKING_OPERATIONS))),
    )
}

async fn initialize_on_worker<F>(initialize: F) -> Result<RembraneMcp>
where
    F: FnOnce() -> Result<RembraneMcp> + Send + 'static,
{
    run_blocking_operation(blocking_capacity(), move || Ok(initialize()))
        .await
        .map_err(|_| anyhow::anyhow!("MCP initialization worker unavailable or failed"))?
}

async fn run_blocking_operation<T, F>(capacity: Arc<Semaphore>, operation: F) -> Result<T, McpError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, McpError> + Send + 'static,
{
    let permit = capacity.try_acquire_owned().map_err(|_| {
        McpError::internal_error(
            "synchronous operation capacity is temporarily unavailable",
            None,
        )
    })?;
    tokio::task::spawn_blocking(move || {
        // An abandoned request must not free capacity while its work is running.
        let _permit = permit;
        operation()
    })
    .await
    .map_err(|_| McpError::internal_error("synchronous operation failed", None))?
}

fn ensure_not_cancelled(context: &RequestContext<RoleServer>) -> Result<(), McpError> {
    if context.ct.is_cancelled() {
        return Err(McpError::internal_error(
            "operation cancelled before execution",
            None,
        ));
    }
    Ok(())
}

#[allow(clippy::needless_pass_by_value, clippy::similar_names)]
#[tool_router(server_handler)]
impl RembraneMcp {
    #[tool(
        name = "rembrane_resolve_context",
        description = "Retrieve minimal confirmed memory authorized for this connection. A disclosure receipt is recorded."
    )]
    async fn resolve_context(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(parameters): Parameters<ResolveContextParameters>,
    ) -> Result<String, McpError> {
        self.run_tool(context, move |server, context| {
            server.resolve_context_sync(context, parameters)
        })
        .await
    }

    #[tool(
        name = "rembrane_resolve_graph_context",
        description = "Retrieve one authorized temporal graph neighbourhood. Canonical edge revisions are reauthorized and recorded in a disclosure receipt."
    )]
    async fn resolve_graph_context(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(parameters): Parameters<ResolveGraphContextParameters>,
    ) -> Result<String, McpError> {
        self.run_tool(context, move |server, context| {
            server.resolve_graph_context_sync(context, parameters)
        })
        .await
    }

    #[tool(
        name = "rembrane_remember_preference",
        description = "Store a confirmed global preference when this connection has direct memory creation permission."
    )]
    async fn remember_preference(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(parameters): Parameters<RememberPreferenceParameters>,
    ) -> Result<String, McpError> {
        self.run_tool(context, move |server, context| {
            server.remember_preference_sync(context, parameters)
        })
        .await
    }

    #[tool(
        name = "rembrane_request_correction",
        description = "Directly correct a memory when this connection has revision permission."
    )]
    async fn correct_memory(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(parameters): Parameters<CorrectMemoryParameters>,
    ) -> Result<String, McpError> {
        self.run_tool(context, move |server, context| {
            server.correct_memory_sync(context, parameters)
        })
        .await
    }

    #[tool(
        name = "rembrane_forget_memory",
        description = "Create an encrypted deletion tombstone when this connection has deletion permission."
    )]
    async fn forget_memory(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(parameters): Parameters<ForgetMemoryParameters>,
    ) -> Result<String, McpError> {
        self.run_tool(context, move |server, context| {
            server.forget_memory_sync(context, parameters)
        })
        .await
    }

    #[tool(
        name = "rembrane_record_work_trace",
        description = "Record an activity-scoped agent observation as proposed memory. It is not promoted to confirmed user truth."
    )]
    async fn record_work_trace(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(parameters): Parameters<WorkTraceParameters>,
    ) -> Result<String, McpError> {
        self.run_tool(context, move |server, context| {
            server.record_work_trace_sync(context, parameters)
        })
        .await
    }

    #[tool(
        name = "rembrane_checkpoint_activity",
        description = "Create or update an encrypted activity checkpoint for cross-agent continuation."
    )]
    async fn checkpoint_activity(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(parameters): Parameters<CheckpointParameters>,
    ) -> Result<String, McpError> {
        self.run_tool(context, move |server, context| {
            server.checkpoint_activity_sync(context, parameters)
        })
        .await
    }

    #[tool(
        name = "rembrane_create_trip",
        description = "Create a new encrypted trip under the connection's travel-domain capability."
    )]
    async fn create_trip(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(parameters): Parameters<CreateTripParameters>,
    ) -> Result<String, McpError> {
        self.run_tool(context, move |server, context| {
            server.create_trip_sync(context, parameters)
        })
        .await
    }

    #[tool(
        name = "rembrane_capture_booking_research",
        description = "Capture one encrypted, expiring, evidence-backed observation for an authorized trip."
    )]
    async fn capture_booking_research(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(parameters): Parameters<CaptureBookingResearchParameters>,
    ) -> Result<String, McpError> {
        self.run_tool(context, move |server, context| {
            server.capture_booking_research_sync(context, parameters)
        })
        .await
    }

    #[tool(
        name = "rembrane_add_trip_participant",
        description = "Atomically add one participant to an authorized trip without replacing unrelated trip state."
    )]
    async fn add_trip_participant(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(parameters): Parameters<AddTripParticipantParameters>,
    ) -> Result<String, McpError> {
        self.run_tool(context, move |server, context| {
            server.add_trip_participant_sync(context, parameters)
        })
        .await
    }

    #[tool(
        name = "rembrane_add_trip_constraint",
        description = "Atomically add one evidence-backed constraint to an authorized trip."
    )]
    async fn add_trip_constraint(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(parameters): Parameters<AddTripConstraintParameters>,
    ) -> Result<String, McpError> {
        self.run_tool(context, move |server, context| {
            server.add_trip_constraint_sync(context, parameters)
        })
        .await
    }

    #[tool(
        name = "rembrane_record_trip_decision",
        description = "Atomically record one evidence-backed decision attributed to the authenticated principal."
    )]
    async fn record_trip_decision(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(parameters): Parameters<RecordTripDecisionParameters>,
    ) -> Result<String, McpError> {
        self.run_tool(context, move |server, context| {
            server.record_trip_decision_sync(context, parameters)
        })
        .await
    }

    #[tool(
        name = "rembrane_resolve_travel_context",
        description = "Retrieve one authorized trip with fresh and expired research, recording an exact-version disclosure receipt."
    )]
    async fn resolve_travel_context(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(parameters): Parameters<ResolveTravelContextParameters>,
    ) -> Result<String, McpError> {
        self.run_tool(context, move |server, context| {
            server.resolve_travel_context_sync(context, parameters)
        })
        .await
    }

    #[tool(
        name = "rembrane_resume_activity",
        description = "Retrieve the latest encrypted checkpoint for one authorized activity."
    )]
    async fn resume_activity(
        &self,
        context: RequestContext<RoleServer>,
        Parameters(parameters): Parameters<ResumeActivityParameters>,
    ) -> Result<String, McpError> {
        self.run_tool(context, move |server, context| {
            server.resume_activity_sync(context, parameters)
        })
        .await
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

#[allow(clippy::needless_pass_by_value, clippy::similar_names)]
impl RembraneMcp {
    fn resolve_context_sync(
        &self,
        context: RequestContext<RoleServer>,
        parameters: ResolveContextParameters,
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
        let suffix = next_id(&mut state)?;
        let requested_scopes = request_scopes(
            &state.read_scopes,
            parameters.domain.as_deref(),
            parameters.entity_id.as_deref(),
            parameters.activity_id.as_deref(),
        );
        let grants = authorize(&state, &context, requested_scopes, Vec::new())?;
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

    fn resolve_graph_context_sync(
        &self,
        context: RequestContext<RoleServer>,
        parameters: ResolveGraphContextParameters,
    ) -> Result<String, McpError> {
        let direction = match parameters.direction.as_str() {
            "incoming" => GraphDisclosureDirection::Incoming,
            "outgoing" => GraphDisclosureDirection::Outgoing,
            "both" => GraphDisclosureDirection::Both,
            _ => {
                return Err(McpError::invalid_params(
                    "direction must be incoming, outgoing, or both",
                    None,
                ));
            }
        };
        let maximum_candidates = parameters.maximum_candidates.unwrap_or(20);
        if !(1..=100).contains(&maximum_candidates) {
            return Err(McpError::invalid_params(
                "maximumCandidates must be between 1 and 100",
                None,
            ));
        }
        let scope = memory_scope(
            parameters.domain.as_deref(),
            parameters.entity_id.as_deref(),
            parameters.activity_id.as_deref(),
        )?;
        let mut state = lock_state(&self.state)?;
        let grants = authorize(&state, &context, vec![read_scope(&scope)], Vec::new())?;
        let disclosure_id = DisclosureId::new(format!("disclosure_{}", next_id(&mut state)?));
        let request = ResolveGraphContextRequest {
            workspace_id: grants.read.workspace_id.clone(),
            principal_id: grants.read.subject_id.clone(),
            node_id: KnowledgeNodeId::new(parameters.node_id),
            scope,
            direction,
            valid_at_epoch_seconds: parameters.valid_at_epoch_seconds,
            maximum_candidates,
            purpose: parameters.purpose,
        };
        let State {
            store,
            graph_provider,
            ..
        } = &mut *state;
        let response = GraphContextService::new(store, graph_provider)
            .execute_request(request, grants.read, disclosure_id)
            .map_err(application_error)?;
        serde_json::to_string(&ResolveGraphContextOutput {
            disclosure_id: response.disclosure_id.to_string(),
            edges: response
                .edges
                .into_iter()
                .map(|edge| {
                    let validity = edge.validity();
                    GraphEdgeOutput {
                        edge_id: edge.id().to_string(),
                        source_node_id: edge.source_id().to_string(),
                        target_node_id: edge.target_id().to_string(),
                        relation: edge.relation().as_str().to_owned(),
                        version: edge.version(),
                        valid_from_epoch_seconds: validity.valid_from_epoch_seconds(),
                        valid_until_epoch_seconds: validity.valid_until_epoch_seconds(),
                        recorded_at_epoch_seconds: validity.recorded_at_epoch_seconds(),
                    }
                })
                .collect(),
        })
        .map_err(|_| McpError::internal_error("response serialization failed", None))
    }

    fn remember_preference_sync(
        &self,
        context: RequestContext<RoleServer>,
        parameters: RememberPreferenceParameters,
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
            &context,
            vec![read_scope(&scope)],
            vec![WritePermission::CreateMemory],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state)?;
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

    fn correct_memory_sync(
        &self,
        context: RequestContext<RoleServer>,
        parameters: CorrectMemoryParameters,
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
            &context,
            vec![read_scope(&scope)],
            vec![WritePermission::ReviseMemory],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state)?;
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

    fn forget_memory_sync(
        &self,
        context: RequestContext<RoleServer>,
        parameters: ForgetMemoryParameters,
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
            &context,
            vec![read_scope(&scope)],
            vec![WritePermission::DeleteMemory],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state)?;
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

    fn record_work_trace_sync(
        &self,
        context: RequestContext<RoleServer>,
        parameters: WorkTraceParameters,
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
            &context,
            vec![ReadScope::Activity { id: activity_id }],
            vec![WritePermission::ProposeMemory],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state)?;
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

    fn checkpoint_activity_sync(
        &self,
        context: RequestContext<RoleServer>,
        parameters: CheckpointParameters,
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
            &context,
            vec![ReadScope::Activity {
                id: activity_id.clone(),
            }],
            vec![WritePermission::WriteCheckpoint],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state)?;
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
                state.policy.identity.workspace.clone(),
                state.policy.identity.principal.clone(),
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

    fn create_trip_sync(
        &self,
        context: RequestContext<RoleServer>,
        parameters: CreateTripParameters,
    ) -> Result<String, McpError> {
        let mut state = lock_state(&self.state)?;
        let grants = authorize(
            &state,
            &context,
            vec![ReadScope::Domain {
                name: "travel".to_owned(),
            }],
            vec![WritePermission::CreateTrip],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state)?;
        let date_window =
            TravelDateWindow::new(parameters.depart_not_before, parameters.return_not_after)
                .map_err(|_| McpError::invalid_params("invalid trip date window", None))?;
        let trip = Trip::new(
            EntityId::new(format!("trip_{suffix}")),
            state.policy.identity.workspace.clone(),
            state.policy.identity.principal.clone(),
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

    fn capture_booking_research_sync(
        &self,
        context: RequestContext<RoleServer>,
        parameters: CaptureBookingResearchParameters,
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
            &context,
            vec![ReadScope::Entity {
                id: trip_id.clone(),
            }],
            vec![WritePermission::CaptureBookingResearch],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state)?;
        let research = BookingResearch::new(
            BookingResearchId::new(format!("research_{suffix}")),
            state.policy.identity.workspace.clone(),
            trip_id,
            state.policy.identity.principal.clone(),
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

    fn add_trip_participant_sync(
        &self,
        context: RequestContext<RoleServer>,
        parameters: AddTripParticipantParameters,
    ) -> Result<String, McpError> {
        let mut state = lock_state(&self.state)?;
        let trip_id = EntityId::new(parameters.trip_id);
        let grants = authorize(
            &state,
            &context,
            vec![ReadScope::Entity {
                id: trip_id.clone(),
            }],
            vec![WritePermission::ReviseTrip],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state)?;
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

    fn add_trip_constraint_sync(
        &self,
        context: RequestContext<RoleServer>,
        parameters: AddTripConstraintParameters,
    ) -> Result<String, McpError> {
        let kind = parse_constraint_kind(&parameters.kind)
            .ok_or_else(|| McpError::invalid_params("unsupported constraint kind", None))?;
        let evidence_source = parse_evidence_source(&parameters.evidence_source)
            .ok_or_else(|| McpError::invalid_params("unsupported evidence source", None))?;
        let mut state = lock_state(&self.state)?;
        let trip_id = EntityId::new(parameters.trip_id);
        let grants = authorize(
            &state,
            &context,
            vec![ReadScope::Entity {
                id: trip_id.clone(),
            }],
            vec![WritePermission::ReviseTrip],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state)?;
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

    fn record_trip_decision_sync(
        &self,
        context: RequestContext<RoleServer>,
        parameters: RecordTripDecisionParameters,
    ) -> Result<String, McpError> {
        let status = parse_decision_status(&parameters.status)
            .ok_or_else(|| McpError::invalid_params("unsupported decision status", None))?;
        let evidence_source = parse_evidence_source(&parameters.evidence_source)
            .ok_or_else(|| McpError::invalid_params("unsupported evidence source", None))?;
        let mut state = lock_state(&self.state)?;
        let trip_id = EntityId::new(parameters.trip_id);
        let grants = authorize(
            &state,
            &context,
            vec![ReadScope::Entity {
                id: trip_id.clone(),
            }],
            vec![WritePermission::ReviseTrip],
        )?;
        let previous_sequence = current_sequence(&state)?;
        let suffix = next_id(&mut state)?;
        let decision_id = TripDecisionId::new(format!("decision_{suffix}"));
        let decision = TripDecision::new(
            decision_id.clone(),
            status,
            parameters.summary,
            parameters.rationale,
            state.policy.identity.principal.clone(),
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

    fn resolve_travel_context_sync(
        &self,
        context: RequestContext<RoleServer>,
        parameters: ResolveTravelContextParameters,
    ) -> Result<String, McpError> {
        let mut state = lock_state(&self.state)?;
        let trip_id = EntityId::new(parameters.trip_id);
        let grants = authorize(
            &state,
            &context,
            vec![ReadScope::Entity {
                id: trip_id.clone(),
            }],
            Vec::new(),
        )?;
        let disclosure_id = DisclosureId::new(format!("disclosure_{}", next_id(&mut state)?));
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

    fn resume_activity_sync(
        &self,
        context: RequestContext<RoleServer>,
        parameters: ResumeActivityParameters,
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
            &context,
            vec![ReadScope::Activity {
                id: activity_id.clone(),
            }],
            Vec::new(),
        )?;
        let disclosure_id = DisclosureId::new(format!("disclosure_{}", next_id(&mut state)?));
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
    context: &RequestContext<RoleServer>,
    read_scopes: Vec<ReadScope>,
    write_permissions: Vec<WritePermission>,
) -> Result<ClientGrantBundle, McpError> {
    // Cancellation may arrive while this worker waits for the store mutex.
    // Check again before canonical authorization and any application mutation.
    ensure_not_cancelled(context)?;
    authorize_request_identity(&state.policy, context)?;
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
            client_id: state.policy.identity.client.clone(),
            workspace_id: state.policy.identity.workspace.clone(),
            principal_id: state.policy.identity.principal.clone(),
            requested_read_scopes: read_scopes,
            requested_read_permissions: state.read_permissions.clone(),
            requested_write_permissions: write_permissions,
        })
        .map_err(application_error)
}

fn authorize_request_identity(
    policy: &ConnectionPolicy,
    context: &RequestContext<RoleServer>,
) -> Result<(), McpError> {
    let verified_access = context
        .extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<VerifiedRemoteAccess>());
    if !request_identity_matches(
        &policy.identity,
        policy.require_verified_request_identity,
        verified_access,
    ) {
        return Err(McpError::invalid_params(
            "operation is not authorized or available",
            None,
        ));
    }
    Ok(())
}

fn request_identity_matches(
    expected: &ConnectionIdentity,
    required: bool,
    access: Option<&VerifiedRemoteAccess>,
) -> bool {
    if !required {
        return true;
    }
    access
        .is_some_and(|access| ConnectionIdentity::from_verified_remote_access(access) == *expected)
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
        .list_events_since(&state.policy.identity.workspace, 0)
        .map(|events| {
            events
                .last()
                .map_or(0, rembrane_domain::CanonicalEvent::sequence)
        })
        .map_err(application_error)
}

fn next_id(state: &mut State) -> Result<u128, McpError> {
    advance_identifier(&mut state.next_id)
        .ok_or_else(|| McpError::internal_error("identifier sequence exhausted", None))
}

fn advance_identifier(current: &mut u128) -> Option<u128> {
    let next = current.checked_add(1)?;
    *current = next;
    Some(next)
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
            drop(message);
            McpError::invalid_params("operation validation failed", None)
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
    let server = RembraneMcp::from_environment_async().await?;
    serve_stdio(server).await
}

/// Serves an already initialized service without constructing blocking providers
/// on the async executor. Synchronous constructors must be called outside it.
///
/// # Errors
///
/// Returns an error if the stdio service fails to initialize or terminates with
/// a transport error.
pub async fn serve_stdio(server: RembraneMcp) -> Result<()> {
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::Duration;

    use rembrane_application::{EventRepository, MembershipRepository, WorkspaceRepository};
    use rembrane_contracts::{RemoteAccessScope, RemoteTokenClaims};
    use rembrane_crypto_configured::ConfiguredRecordCipher;
    use rembrane_crypto_rustcrypto::{RustCryptoKeyringCipher, RustCryptoRecordCipher};
    use rembrane_domain::{
        ClientId, EntityId, Membership, Principal, PrincipalId, ReadScope, Workspace, WorkspaceId,
        WorkspaceRole,
    };
    use rembrane_graph_configured::ConfiguredGraphProvider;
    use rembrane_graph_native::NativeGraphProvider;
    use rembrane_store_sqlite::SqliteStore;
    use rmcp::{
        RoleServer, ServiceExt,
        model::RequestId,
        service::{RequestContext, RunningService},
    };
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream},
        sync::{Semaphore, oneshot},
        time::timeout,
    };

    use super::{
        ConnectionIdentity, RembraneMcp, advance_identifier, request_identity_matches,
        request_scopes, run_blocking_operation,
    };

    fn fixture_identity() -> ConnectionIdentity {
        ConnectionIdentity {
            principal: PrincipalId::new("principal_01"),
            workspace: WorkspaceId::new("workspace_01"),
            client: ClientId::new("client_01"),
        }
    }

    fn fixture_metadata_store() -> SqliteStore {
        let identity = fixture_identity();
        let mut store = SqliteStore::open_in_memory().expect("fixture store");
        store
            .initialize_personal_workspace(
                Principal::new(identity.principal.clone()),
                Workspace::personal(identity.workspace.clone()),
                Membership::new(
                    identity.workspace.clone(),
                    identity.principal.clone(),
                    WorkspaceRole::Owner,
                ),
            )
            .expect("fixture workspace");
        store
    }

    fn fixture_cipher() -> ConfiguredRecordCipher {
        ConfiguredRecordCipher::Local(
            RustCryptoKeyringCipher::new(
                RustCryptoRecordCipher::new("mcp-test-key", [7; 32]).expect("fixture cipher"),
                Vec::new(),
            )
            .expect("fixture keyring"),
        )
    }

    fn fixture_server(require_verified_request_identity: bool) -> RembraneMcp {
        let mut server = RembraneMcp::from_store(
            fixture_metadata_store(),
            fixture_identity(),
            require_verified_request_identity,
            vec![ReadScope::Global],
            Vec::new(),
            || {
                Ok((
                    fixture_cipher(),
                    ConfiguredGraphProvider::Native(NativeGraphProvider::new()),
                ))
            },
        )
        .expect("authorized fixture startup");
        server.blocking_operations = Arc::new(Semaphore::new(8));
        server.state.lock().expect("fixture state").next_id = 100;
        server
    }

    #[test]
    fn startup_rejects_unknown_or_foreign_identity_before_initializing_providers() {
        let mut unknown_principal = fixture_identity();
        unknown_principal.principal = PrincipalId::new("principal_missing");
        let mut unknown_workspace = fixture_identity();
        unknown_workspace.workspace = WorkspaceId::new("workspace_missing");
        let mut foreign_workspace = fixture_identity();
        foreign_workspace.workspace = WorkspaceId::new("workspace_other");
        for identity in [unknown_principal, unknown_workspace, foreign_workspace] {
            let mut store = fixture_metadata_store();
            store
                .initialize_personal_workspace(
                    Principal::new(PrincipalId::new("principal_other")),
                    Workspace::personal(WorkspaceId::new("workspace_other")),
                    Membership::new(
                        WorkspaceId::new("workspace_other"),
                        PrincipalId::new("principal_other"),
                        WorkspaceRole::Owner,
                    ),
                )
                .expect("foreign workspace");
            let called = std::cell::Cell::new(false);
            let error = RembraneMcp::from_store(
                store,
                identity,
                true,
                vec![ReadScope::Global],
                Vec::new(),
                || {
                    called.set(true);
                    panic!("rejected identity must not initialize keys or providers");
                },
            )
            .err()
            .expect("startup authorization denial");
            assert_eq!(error.to_string(), "failed to authorize MCP connection");
            assert!(!called.get());
        }
    }

    #[test]
    fn startup_rejects_inactive_membership_before_initializing_providers() {
        let identity = fixture_identity();
        let membership = Membership::new(
            identity.workspace.clone(),
            identity.principal.clone(),
            WorkspaceRole::Owner,
        );
        for inactive in [membership.clone().suspend(), membership.remove()] {
            let mut store = fixture_metadata_store();
            store
                .replace_membership(inactive)
                .expect("inactive fixture");
            let called = std::cell::Cell::new(false);
            let error = RembraneMcp::from_store(
                store,
                identity.clone(),
                true,
                vec![ReadScope::Global],
                Vec::new(),
                || {
                    called.set(true);
                    panic!("inactive membership must not initialize providers");
                },
            )
            .err()
            .expect("inactive membership denied");
            assert_eq!(error.to_string(), "failed to authorize MCP connection");
            assert!(!called.get());
        }
    }

    #[test]
    fn pending_key_rotation_denies_mcp_startup_without_initializing_providers() {
        let mut store = fixture_metadata_store();
        let other = PrincipalId::new("principal_other");
        let shared = WorkspaceId::new("workspace_shared");
        store
            .initialize_personal_workspace(
                Principal::new(other.clone()),
                Workspace::personal(WorkspaceId::new("workspace_other")),
                Membership::new(
                    WorkspaceId::new("workspace_other"),
                    other.clone(),
                    WorkspaceRole::Owner,
                ),
            )
            .expect("other principal");
        let mut identity = fixture_identity();
        store
            .initialize_shared_workspace(
                Workspace::shared(shared.clone()),
                Membership::new(
                    shared.clone(),
                    identity.principal.clone(),
                    WorkspaceRole::Owner,
                ),
            )
            .expect("shared workspace");
        store
            .insert_membership(Membership::new(
                shared.clone(),
                other.clone(),
                WorkspaceRole::Member,
            ))
            .expect("shared member");
        rembrane_application::MemberLifecycleService::new(&mut store)
            .remove(rembrane_application::RemoveMemberCommand {
                workspace_id: shared.clone(),
                principal_id: other,
                removed_by: identity.principal.clone(),
                rotation_id: rembrane_domain::KeyRotationId::new("rotation_startup"),
            })
            .expect("required key rotation");
        identity.workspace = shared;
        let called = std::cell::Cell::new(false);
        let error = RembraneMcp::from_store(
            store,
            identity,
            true,
            vec![ReadScope::Global],
            Vec::new(),
            || {
                called.set(true);
                panic!("rotation-blocked MCP must not load keys or providers");
            },
        )
        .err()
        .expect("rotation-blocked startup");
        assert_eq!(error.to_string(), "failed to authorize MCP connection");
        assert!(!called.get());
    }

    #[test]
    fn authorized_startup_initializes_providers_once_and_preserves_identity_policy() {
        let calls = std::cell::Cell::new(0);
        let server = RembraneMcp::from_store(
            fixture_metadata_store(),
            fixture_identity(),
            true,
            vec![ReadScope::Global],
            Vec::new(),
            || {
                calls.set(calls.get() + 1);
                Ok((
                    fixture_cipher(),
                    ConfiguredGraphProvider::Native(NativeGraphProvider::new()),
                ))
            },
        )
        .expect("authorized startup");
        assert_eq!(calls.get(), 1);
        assert!(server.policy.require_verified_request_identity);
        assert!(server.policy.identity == fixture_identity());
        let state = server.state.lock().expect("state");
        assert!(
            state
                .store
                .list_events_since(&state.policy.identity.workspace, 0)
                .expect("canonical events")
                .is_empty()
        );
    }

    #[test]
    fn authorized_startup_preserves_provider_failure_without_creating_a_service() {
        let calls = std::cell::Cell::new(0);
        let error = RembraneMcp::from_store(
            fixture_metadata_store(),
            fixture_identity(),
            true,
            vec![ReadScope::Global],
            Vec::new(),
            || {
                calls.set(calls.get() + 1);
                Err(anyhow::anyhow!("fixture provider unavailable"))
            },
        )
        .err()
        .expect("provider startup failure");
        assert_eq!(calls.get(), 1);
        assert_eq!(error.to_string(), "fixture provider unavailable");
    }

    async fn read_wire(client: &mut BufReader<DuplexStream>) -> serde_json::Value {
        let mut line = String::new();
        let bytes = timeout(Duration::from_secs(5), client.read_line(&mut line))
            .await
            .expect("bounded protocol response")
            .expect("protocol response");
        assert_ne!(bytes, 0, "unexpected transport closure");
        serde_json::from_str(&line).expect("protocol JSON")
    }

    async fn write_wire(client: &mut BufReader<DuplexStream>, value: serde_json::Value) {
        let mut bytes = serde_json::to_vec(&value).expect("protocol JSON");
        bytes.push(b'\n');
        timeout(Duration::from_secs(5), client.get_mut().write_all(&bytes))
            .await
            .expect("bounded protocol write")
            .expect("protocol write");
    }

    // Use the actual SDK transport and handshake, without a TCP listener or
    // uncached client transport dependencies. This also supplies a real peer
    // for RequestContext tests rather than constructing SDK internals.
    async fn fixture_connection(
        server: RembraneMcp,
    ) -> (
        RunningService<RoleServer, RembraneMcp>,
        BufReader<DuplexStream>,
    ) {
        let (server_transport, client_transport) = tokio::io::duplex(65_536);
        let pending = tokio::spawn(server.serve(server_transport));
        let mut client = BufReader::new(client_transport);
        write_wire(
            &mut client,
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "rembrane-runtime-test", "version": "1"}
                }
            }),
        )
        .await;
        let initialized = read_wire(&mut client).await;
        assert!(initialized.get("result").is_some(), "{initialized}");
        write_wire(
            &mut client,
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )
        .await;
        let service = timeout(Duration::from_secs(5), pending)
            .await
            .expect("bounded handshake")
            .expect("server task")
            .expect("server handshake");
        (service, client)
    }

    fn request_context(
        service: &RunningService<RoleServer, RembraneMcp>,
        access: Option<rembrane_contracts::VerifiedRemoteAccess>,
    ) -> RequestContext<RoleServer> {
        let mut context = RequestContext::new(RequestId::Number(99), service.peer().clone());
        if let Some(access) = access {
            let (mut parts, ()) = http::Request::new(()).into_parts();
            parts.extensions.insert(access);
            context.extensions.insert(parts);
        }
        context
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_worker_runs_outside_executor_and_supports_blocking_providers() {
        let executor_thread = std::thread::current().id();
        let capacity = Arc::new(Semaphore::new(1));
        let worker_thread = run_blocking_operation(Arc::clone(&capacity), || {
            let _client = reqwest::blocking::Client::builder()
                .build()
                .expect("blocking provider construction");
            Ok(std::thread::current().id())
        })
        .await
        .expect("worker response");
        assert_ne!(worker_thread, executor_thread);
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn saturated_or_closed_capacity_never_executes_operation() {
        let capacity = Arc::new(Semaphore::new(1));
        let permit = capacity.try_acquire().expect("saturate capacity");
        let error =
            run_blocking_operation(Arc::clone(&capacity), || -> Result<(), rmcp::ErrorData> {
                panic!("rejected work must not execute")
            })
            .await
            .expect_err("saturated");
        assert_eq!(
            error.message,
            "synchronous operation capacity is temporarily unavailable"
        );
        drop(permit);
        capacity.close();
        assert!(
            run_blocking_operation(capacity, || -> Result<(), rmcp::ErrorData> {
                panic!("closed work must not execute")
            })
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn failed_or_panicked_workers_release_capacity_without_disclosing_panic() {
        let capacity = Arc::new(Semaphore::new(1));
        assert!(
            run_blocking_operation(Arc::clone(&capacity), || -> Result<(), rmcp::ErrorData> {
                Err(rmcp::ErrorData::invalid_params("fixture failure", None))
            })
            .await
            .is_err()
        );
        assert_eq!(capacity.available_permits(), 1);
        let error =
            run_blocking_operation(Arc::clone(&capacity), || -> Result<(), rmcp::ErrorData> {
                panic!("private panic detail")
            })
            .await
            .expect_err("worker panic");
        assert_eq!(error.message, "synchronous operation failed");
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_waiter_retains_capacity_until_running_work_finishes() {
        let capacity = Arc::new(Semaphore::new(1));
        let (started, worker_started) = oneshot::channel();
        let (release, wait_for_release) = std::sync::mpsc::channel();
        let (finished, worker_finished) = oneshot::channel();
        let worker_capacity = Arc::clone(&capacity);
        let waiter = tokio::spawn(run_blocking_operation(worker_capacity, move || {
            started.send(()).expect("start signal");
            wait_for_release
                .recv_timeout(Duration::from_secs(5))
                .expect("bounded release wait");
            finished.send(()).expect("finish signal");
            Ok(())
        }));
        timeout(Duration::from_secs(5), worker_started)
            .await
            .expect("bounded worker start")
            .expect("worker started");
        // A single-thread executor remains responsive while synchronous work waits.
        tokio::task::yield_now().await;
        waiter.abort();
        assert!(waiter.await.expect_err("abandoned waiter").is_cancelled());
        assert_eq!(capacity.available_permits(), 0);
        assert!(
            run_blocking_operation(Arc::clone(&capacity), || -> Result<(), rmcp::ErrorData> {
                panic!("abandoned running work still owns capacity")
            })
            .await
            .is_err()
        );
        release.send(()).expect("release worker");
        timeout(Duration::from_secs(5), worker_finished)
            .await
            .expect("bounded worker completion")
            .expect("worker finished");
        let permit = timeout(Duration::from_secs(5), capacity.acquire())
            .await
            .expect("capacity eventually released")
            .expect("available capacity");
        drop(permit);
        assert_eq!(capacity.available_permits(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verified_identity_is_checked_before_admission_without_locking_store() {
        let server = fixture_server(true);
        let (service, _client) = fixture_connection(server.clone()).await;
        let capacity = Arc::clone(&server.blocking_operations);
        let _permits = capacity.try_acquire_many(8).expect("saturate capacity");
        // A wrong/missing proof must not inspect mutable state or report overload.
        let (locked, wait_for_lock) = oneshot::channel();
        let (release, wait_for_release) = std::sync::mpsc::channel();
        let state = Arc::clone(&server.state);
        let lock_holder = tokio::task::spawn_blocking(move || {
            let guard = state.lock().expect("hold store lock");
            locked.send(()).expect("lock signal");
            wait_for_release
                .recv_timeout(Duration::from_secs(5))
                .expect("bounded lock release");
            assert_eq!(guard.next_id, 100);
        });
        timeout(Duration::from_secs(5), wait_for_lock)
            .await
            .expect("bounded store lock")
            .expect("locked store");
        for access in [
            None,
            Some(remote_access("principal_01", "workspace_02", "client_01")),
            Some(remote_access("principal_02", "workspace_01", "client_01")),
            Some(remote_access("principal_01", "workspace_01", "client_02")),
        ] {
            let error = server
                .run_tool(
                    request_context(&service, access),
                    |_, _| -> Result<(), rmcp::ErrorData> {
                        panic!("invalid identity must not start work");
                    },
                )
                .await
                .expect_err("identity denial");
            assert_eq!(error.message, "operation is not authorized or available");
        }
        release.send(()).expect("release store lock");
        lock_holder.await.expect("store lock holder");
        let context = request_context(
            &service,
            Some(remote_access("principal_01", "workspace_01", "client_01")),
        );
        let error = server
            .run_tool(context.clone(), |_, _| Ok(()))
            .await
            .expect_err("verified identity reaches admission");
        assert_eq!(
            error.message,
            "synchronous operation capacity is temporarily unavailable"
        );
        context.ct.cancel();
        let error = server
            .run_tool(context, |_, _| Ok(()))
            .await
            .expect_err("cancelled request");
        assert_eq!(error.message, "operation cancelled before execution");
        service.cancel().await.expect("service shutdown");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_mcp_transport_executes_encrypted_memory_tools_on_workers() {
        let server = fixture_server(false);
        let (service, mut client) = fixture_connection(server.clone()).await;
        for (id, name, arguments) in [
            (
                2,
                "rembrane_remember_preference",
                serde_json::json!({"content": "Call me Hippo"}),
            ),
            (
                3,
                "rembrane_resolve_context",
                serde_json::json!({"purpose": "greeting", "query": "Hippo"}),
            ),
        ] {
            write_wire(
                &mut client,
                serde_json::json!({
                    "jsonrpc": "2.0", "id": id, "method": "tools/call",
                    "params": {"name": name, "arguments": arguments}
                }),
            )
            .await;
            let response = read_wire(&mut client).await;
            assert!(response.get("error").is_none(), "{response}");
            assert_ne!(response["result"]["isError"], true, "{response}");
            if id == 3 {
                let output: serde_json::Value = serde_json::from_str(
                    response["result"]["content"][0]["text"]
                        .as_str()
                        .expect("tool text"),
                )
                .expect("context response JSON");
                assert_eq!(output["items"][0]["content"], "Call me Hippo");
                assert!(output["disclosureId"].as_str().is_some());
            }
        }
        service.cancel().await.expect("service shutdown");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn real_tool_preserves_verified_proof_through_worker_authorization() {
        let server = fixture_server(true);
        let (service, _client) = fixture_connection(server.clone()).await;
        let output = server
            .remember_preference(
                request_context(
                    &service,
                    Some(remote_access("principal_01", "workspace_01", "client_01")),
                ),
                super::Parameters(super::RememberPreferenceParameters {
                    content: "Call me Hippo".to_owned(),
                    domain: None,
                    entity_id: None,
                    activity_id: None,
                }),
            )
            .await
            .expect("verified write");
        assert!(serde_json::from_str::<serde_json::Value>(&output).is_ok());
        let output = server
            .resolve_context(
                request_context(
                    &service,
                    Some(remote_access("principal_01", "workspace_01", "client_01")),
                ),
                super::Parameters(super::ResolveContextParameters {
                    purpose: "greeting".to_owned(),
                    query: "Hippo".to_owned(),
                    maximum_items: None,
                    maximum_bytes: None,
                    domain: None,
                    entity_id: None,
                    activity_id: None,
                }),
            )
            .await
            .expect("verified read");
        let output: serde_json::Value = serde_json::from_str(&output).expect("context JSON");
        assert_eq!(output["items"][0]["content"], "Call me Hippo");
        service.cancel().await.expect("service shutdown");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_while_waiting_for_store_prevents_memory_mutation() {
        let server = fixture_server(false);
        let (service, _client) = fixture_connection(server.clone()).await;
        let (locked, wait_for_lock) = oneshot::channel();
        let (release, wait_for_release) = std::sync::mpsc::channel();
        let state = Arc::clone(&server.state);
        let lock_holder = tokio::task::spawn_blocking(move || {
            let _guard = state.lock().expect("hold store lock");
            locked.send(()).expect("lock signal");
            wait_for_release
                .recv_timeout(Duration::from_secs(5))
                .expect("bounded lock release");
        });
        timeout(Duration::from_secs(5), wait_for_lock)
            .await
            .expect("bounded store lock")
            .expect("locked store");
        let context = request_context(&service, None);
        let cancellation = context.ct.clone();
        let worker_server = server.clone();
        let pending = tokio::spawn(async move {
            worker_server
                .remember_preference(
                    context,
                    super::Parameters(super::RememberPreferenceParameters {
                        content: "Must not persist".to_owned(),
                        domain: None,
                        entity_id: None,
                        activity_id: None,
                    }),
                )
                .await
        });
        timeout(Duration::from_secs(5), async {
            while server.blocking_operations.available_permits() == 8 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("operation admitted");
        cancellation.cancel();
        release.send(()).expect("release store lock");
        lock_holder.await.expect("lock holder finished");
        let error = timeout(Duration::from_secs(5), pending)
            .await
            .expect("bounded tool completion")
            .expect("tool task")
            .expect_err("cancelled write");
        assert_eq!(error.message, "operation cancelled before execution");
        {
            let state = server.state.lock().expect("fixture state");
            assert!(
                state
                    .store
                    .list_events_since(&state.policy.identity.workspace, 0)
                    .expect("fixture events")
                    .is_empty()
            );
        }
        service.cancel().await.expect("service shutdown");
    }

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

    #[test]
    fn generated_identifier_sequence_fails_closed_at_exhaustion() {
        let mut current = u128::MAX - 1;
        assert_eq!(advance_identifier(&mut current), Some(u128::MAX));
        assert_eq!(advance_identifier(&mut current), None);
        assert_eq!(advance_identifier(&mut current), None);
        assert_eq!(current, u128::MAX);
    }

    #[test]
    fn remote_handler_requires_exact_verified_request_identity() {
        let expected = ConnectionIdentity {
            principal: PrincipalId::new("principal_01"),
            workspace: WorkspaceId::new("workspace_01"),
            client: ClientId::new("client_01"),
        };
        let access = remote_access("principal_01", "workspace_01", "client_01");
        let other_tenant = remote_access("principal_01", "workspace_02", "client_01");

        assert!(request_identity_matches(&expected, true, Some(&access)));
        assert!(!request_identity_matches(&expected, true, None));
        assert!(!request_identity_matches(
            &expected,
            true,
            Some(&other_tenant)
        ));
        assert!(request_identity_matches(&expected, false, None));
    }

    fn remote_access(
        principal: &str,
        workspace: &str,
        client: &str,
    ) -> rembrane_contracts::VerifiedRemoteAccess {
        RemoteTokenClaims {
            issuer: "https://issuer.example".to_owned(),
            audience: vec!["https://memory.example/mcp".to_owned()],
            subject_id: PrincipalId::new(principal),
            client_id: ClientId::new(client),
            workspace_id: WorkspaceId::new(workspace),
            scopes: BTreeSet::from([RemoteAccessScope::ContextRead]),
            expires_at_epoch_seconds: 200,
            not_before_epoch_seconds: None,
        }
        .validate_connection("https://issuer.example", "https://memory.example/mcp", 100)
        .expect("valid remote access")
    }
}

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::extract::DefaultBodyLimit;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rembrane_application::{
    AcceptInvitationCommand, AddTripConstraintCommand, AddTripParticipantCommand,
    AdministrativeAuditRepository, ApplicationError, AuthorizeClientCommand,
    AuthorizeClientService, CaptureBookingResearchCommand, CaptureBookingResearchService,
    CheckpointService, ClientGrantBundle, CreateCheckpointCommand, CreateInvitationCommand,
    CreateTripCommand, ExecuteRetentionPurgeCommand, GraphContextService, InvitationRepository,
    InvitationService, KeyRotationRepository, ListInvitationsQuery, MemberLifecycleService,
    MembershipRepository, PlaceLegalHoldCommand, RecordTripDecisionCommand,
    ReleaseLegalHoldCommand, ResolveContextCommand, ResolveContextService,
    ResolveTravelContextCommand, ResumeActivityCommand, RetentionService, RevokeInvitationCommand,
    SetRetentionPolicyCommand, TravelContextResearch, TravelContextService, TravelContextTrip,
    TravelSensitiveProfile, TripService, UpdateCheckpointCommand, WorkspaceRepository,
};
use rembrane_config::{SecretReference, parse_read_permissions, parse_read_scopes};
use rembrane_contracts::{ResolveContextRequest, ResolveGraphContextRequest};
use rembrane_crypto_configured::ConfiguredRecordCipher;
use rembrane_domain::{
    ActivityCheckpoint, ActivityId, AdministrativeAuditEvent, BookingResearch, BookingResearchId,
    BookingResearchKind, CheckpointId, ClientId, ContextPackId, DecisionStatus, DisclosureId,
    EntityId, EventId, EvidenceId, EvidenceReference, EvidenceSource, GraphDisclosureDirection,
    InvitationId, InvitationStatus, KeyRotationStatus, KnowledgeNodeId, LegalHoldId, MemoryKind,
    MemoryScope, MemoryStatus, PrincipalId, ReadGrant, RetentionPeriod, TravelDateWindow, Trip,
    TripConstraint, TripConstraintId, TripConstraintKind, TripDecision, TripDecisionId,
    TripParticipant, TripParticipantId, WorkspaceId, WorkspaceKind, WorkspaceRetentionPolicy,
    WorkspaceRole, WriteGrant, WritePermission,
};
use rembrane_graph_configured::ConfiguredGraphProvider;
use rembrane_secret_local::{LocalSecretResolver, SecretResolver};
use rembrane_store_sqlite::SqliteStore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const MAXIMUM_API_TOKEN_BYTES: usize = 8_192;

#[derive(Clone)]
struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    runtime: Mutex<Runtime>,
    bearer_token: Zeroizing<String>,
    discovery: MemoryDiscovery,
    oauth_resource_metadata: Option<OAuthProtectedResourceMetadata>,
}

struct Runtime {
    store: SqliteStore<ConfiguredRecordCipher>,
    graph_provider: ConfiguredGraphProvider,
    rotation_provider: ConfiguredRecordCipher,
    read_grant: ReadGrant,
    write_grant: WriteGrant,
    next_id: u128,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ResolveRequest {
    workspace_id: String,
    subject_id: String,
    domain: Option<String>,
    entity_id: Option<String>,
    activity_id: Option<String>,
    purpose: String,
    query: String,
    maximum_items: usize,
    maximum_bytes: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ResolveGraphRequest {
    workspace_id: String,
    subject_id: String,
    node_id: String,
    direction: String,
    valid_at_epoch_seconds: u64,
    maximum_candidates: Option<usize>,
    purpose: String,
    domain: Option<String>,
    entity_id: Option<String>,
    activity_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CheckpointActivityRequest {
    workspace_id: String,
    subject_id: String,
    entity_id: Option<String>,
    goal: Option<String>,
    summary: String,
    #[serde(default)]
    next_steps: Vec<String>,
    #[serde(default)]
    blockers: Vec<String>,
    state_fingerprint: Option<String>,
    expected_version: Option<u64>,
    expected_previous_sequence: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ResumeActivityQuery {
    workspace_id: String,
    subject_id: String,
    purpose: Option<String>,
    state_fingerprint: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ActivityCheckpointResponse {
    checkpoint_id: String,
    workspace_id: String,
    subject_id: String,
    activity_id: String,
    entity_id: Option<String>,
    goal: String,
    summary: String,
    next_steps: Vec<String>,
    blockers: Vec<String>,
    state_fingerprint: Option<String>,
    version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    stale: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disclosure_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphEdgeResponse {
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
struct ResolveGraphResponse {
    disclosure_id: String,
    edges: Vec<GraphEdgeResponse>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RotateWorkspaceKeyRequest {
    workspace_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AuditQuery {
    workspace_id: String,
    after_epoch_seconds: Option<u64>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SetRetentionPolicyRequest {
    workspace_id: String,
    expected_version: Option<u64>,
    user_memory_days: Option<u32>,
    activity_checkpoint_days: Option<u32>,
    travel_research_days: Option<u32>,
    disclosure_receipt_days: Option<u32>,
    canonical_event_days: Option<u32>,
    administrative_audit_days: Option<u32>,
    request_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
struct LegalHoldRequest {
    workspace_id: String,
    hold_id: String,
    request_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ExecuteRetentionPurgeRequest {
    workspace_id: String,
    maximum_items: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CreateInvitationRequest {
    workspace_id: String,
    invitation_id: String,
    invited_principal_id: String,
    role: String,
    ttl_seconds: u64,
    request_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
struct InvitationTransitionRequest {
    workspace_id: String,
    invitation_id: String,
    request_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct InvitationListQuery {
    workspace_id: String,
    status: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvitationResponse {
    workspace_id: String,
    invitation_id: String,
    invited_principal_id: String,
    role: &'static str,
    status: &'static str,
    expires_at_epoch_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvitationListItemResponse {
    workspace_id: String,
    invitation_id: String,
    invited_principal_id: String,
    invited_by: String,
    role: &'static str,
    status: &'static str,
    created_at_epoch_seconds: u64,
    expires_at_epoch_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvitationListResponse {
    workspace_id: String,
    invitations: Vec<InvitationListItemResponse>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CaptureBookingResearchRequest {
    workspace_id: String,
    subject_id: String,
    trip_id: String,
    kind: String,
    provider: String,
    summary: String,
    source_reference: String,
    evidence_source: String,
    observed_at: String,
    expires_at: String,
    expected_previous_sequence: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CreateTripRequest {
    workspace_id: String,
    subject_id: String,
    title: String,
    origin: String,
    destinations: Vec<String>,
    depart_not_before: String,
    return_not_after: String,
    expected_previous_sequence: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AddTripParticipantRequest {
    workspace_id: String,
    subject_id: String,
    trip_id: String,
    label: String,
    expected_trip_version: u64,
    expected_previous_sequence: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct AddTripConstraintRequest {
    workspace_id: String,
    subject_id: String,
    trip_id: String,
    participant_id: Option<String>,
    kind: String,
    statement: String,
    evidence_source: String,
    expected_trip_version: u64,
    expected_previous_sequence: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RecordTripDecisionRequest {
    workspace_id: String,
    subject_id: String,
    trip_id: String,
    status: String,
    summary: String,
    rationale: Option<String>,
    evidence_source: String,
    expected_trip_version: u64,
    expected_previous_sequence: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ResolveTravelContextRequest {
    workspace_id: String,
    subject_id: String,
    trip_id: String,
    purpose: String,
    as_of: String,
    include_source_references: Option<bool>,
    include_sensitive_profile: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TripResponse {
    trip_id: String,
    workspace_id: String,
    owner_subject_id: String,
    version: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TripParticipantResponse {
    trip_id: String,
    participant_id: String,
    label: String,
    trip_version: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TripRevisionResponse {
    trip_id: String,
    record_id: String,
    trip_version: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BookingResearchResponse {
    id: String,
    workspace_id: String,
    trip_id: String,
    observed_by: String,
    version: u64,
    expires_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TravelContextResponse {
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
struct ResolveResponse {
    context_pack_id: String,
    disclosure_id: String,
    items: Vec<MemoryOutput>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemoryOutput {
    id: String,
    workspace_id: String,
    subject_id: String,
    scope: ScopeOutput,
    kind: &'static str,
    status: &'static str,
    content: String,
    version: u64,
    evidence: Vec<EvidenceOutput>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum ScopeOutput {
    Global,
    Domain { name: String },
    Entity { id: String },
    Activity { id: String },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceOutput {
    id: String,
    source: &'static str,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MemoryDiscovery {
    provider: DiscoveryProvider,
    protocol_versions: Vec<&'static str>,
    endpoints: DiscoveryEndpoints,
    capabilities: DiscoveryCapabilities,
    limits: DiscoveryLimits,
    privacy: DiscoveryPrivacy,
}

#[derive(Clone, Serialize)]
struct DiscoveryProvider {
    id: &'static str,
    name: &'static str,
    implementation: &'static str,
}

#[derive(Clone, Serialize)]
struct DiscoveryEndpoints {
    api: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_excessive_bools)]
struct DiscoveryCapabilities {
    context_resolution: bool,
    question_resolution: bool,
    memory_proposal: bool,
    activity_checkpoint: bool,
    disclosure_receipt: bool,
    deletion_propagation: bool,
    sync: bool,
    imports: Vec<&'static str>,
    exports: Vec<&'static str>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::struct_field_names)]
struct DiscoveryLimits {
    maximum_context_items: usize,
    maximum_context_bytes: usize,
    maximum_event_bytes: usize,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiscoveryPrivacy {
    processing_modes: Vec<&'static str>,
    disclosure_receipts: bool,
    plaintext_processing_location: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RotateWorkspaceKeyResponse {
    workspace_id: String,
    generation: u64,
    key_id: String,
    status: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdministrativeAuditResponse {
    events: Vec<AdministrativeAuditOutput>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdministrativeAuditOutput {
    id: String,
    workspace_id: String,
    actor_id: String,
    action: &'static str,
    target_kind: &'static str,
    target_id: String,
    request_id: String,
    occurred_at_epoch_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RetentionPolicyResponse {
    workspace_id: String,
    version: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LegalHoldResponse {
    workspace_id: String,
    hold_id: String,
    version: u64,
    status: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RetentionPurgeResponse {
    memories: usize,
    checkpoints: usize,
    travel_research: usize,
    disclosures: usize,
    canonical_events: usize,
    total: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Problem {
    code: &'static str,
    message: &'static str,
}

#[derive(Clone, Serialize)]
struct OAuthProtectedResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<&'static str>,
    bearer_methods_supported: Vec<&'static str>,
    resource_name: &'static str,
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(Problem {
                code: self.code,
                message: self.message,
            }),
        )
            .into_response()
    }
}

impl AppState {
    fn from_environment() -> Result<Self> {
        let database = required_environment("REMBRANE_DATABASE")?;
        let principal_id = PrincipalId::new(required_environment("REMBRANE_PRINCIPAL_ID")?);
        let workspace_id = WorkspaceId::new(required_environment("REMBRANE_WORKSPACE_ID")?);
        let client_id = ClientId::new(required_environment("REMBRANE_CLIENT_ID")?);
        let bearer_token = resolve_api_token()?;
        let discovery = memory_discovery_from_environment()?;
        let oauth_resource_metadata = oauth_resource_metadata_from_environment()?;
        let cipher = ConfiguredRecordCipher::from_environment()
            .context("failed to load workspace cipher")?;
        let rotation_provider = ConfiguredRecordCipher::from_environment()
            .context("failed to load workspace rotation provider")?;
        let graph_provider = ConfiguredGraphProvider::from_environment()
            .context("failed to configure graph provider")?;
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
        let grants = AuthorizeClientService::new(&store)
            .execute(AuthorizeClientCommand {
                client_id: client_id.clone(),
                workspace_id: workspace_id.clone(),
                principal_id: principal_id.clone(),
                requested_read_scopes: read_scopes,
                requested_read_permissions: read_permissions,
                requested_write_permissions: vec![
                    WritePermission::WriteCheckpoint,
                    WritePermission::CreateTrip,
                    WritePermission::ReviseTrip,
                    WritePermission::CaptureBookingResearch,
                ],
            })
            .or_else(|error| {
                if error == ApplicationError::AccessDenied {
                    management_only_grants(
                        &store,
                        client_id.clone(),
                        workspace_id.clone(),
                        principal_id.clone(),
                    )
                } else {
                    Err(error)
                }
            })
            .or_else(|error| {
                if error == ApplicationError::AccessDenied {
                    invitation_only_grants(&store, client_id, workspace_id, principal_id)
                } else {
                    Err(error)
                }
            })
            .context("failed to authorize API connection")?;
        let next_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_nanos();

        Ok(Self {
            inner: Arc::new(Inner {
                runtime: Mutex::new(Runtime {
                    store,
                    graph_provider,
                    rotation_provider,
                    read_grant: grants.read,
                    write_grant: grants.write,
                    next_id,
                }),
                bearer_token,
                discovery,
                oauth_resource_metadata,
            }),
        })
    }
}

fn resolve_api_token() -> Result<Zeroizing<String>> {
    let reference = match std::env::var("REMBRANE_API_TOKEN_REFERENCE") {
        Ok(locator) => selected_api_token_reference(&locator)?,
        Err(std::env::VarError::NotPresent) => selected_api_token_reference("")?,
        Err(error) => return Err(error).context("failed to read REMBRANE_API_TOKEN_REFERENCE"),
    };
    let token = LocalSecretResolver
        .resolve(&reference)
        .map_err(|_| anyhow::anyhow!("API bearer token is unavailable or invalid"))?;
    anyhow::ensure!(valid_api_token(&token), "API bearer token is invalid");
    Ok(token)
}

fn valid_api_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAXIMUM_API_TOKEN_BYTES
        && token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        })
}

fn selected_api_token_reference(locator: &str) -> Result<SecretReference> {
    if locator.is_empty() {
        SecretReference::environment("REMBRANE_API_TOKEN")
            .map_err(|_| anyhow::anyhow!("invalid default API token reference"))
    } else {
        locator
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid API token reference"))
    }
}

fn management_only_grants(
    store: &SqliteStore<ConfiguredRecordCipher>,
    client_id: ClientId,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
) -> Result<ClientGrantBundle, ApplicationError> {
    let membership = store
        .find_membership(&workspace_id, &principal_id)?
        .filter(|membership| {
            membership.is_active()
                && matches!(
                    membership.role(),
                    WorkspaceRole::Owner | WorkspaceRole::Admin
                )
        })
        .ok_or(ApplicationError::AccessDenied)?;
    let pending = store
        .latest_key_rotation(&workspace_id)?
        .is_some_and(|rotation| rotation.status() == KeyRotationStatus::Required);
    if !pending {
        return Err(ApplicationError::AccessDenied);
    }
    let read = ReadGrant {
        client_id: client_id.clone(),
        workspace_id: workspace_id.clone(),
        subject_id: membership.principal_id().clone(),
        scopes: Vec::new(),
        permissions: Vec::new(),
    };
    let write = WriteGrant {
        client_id,
        workspace_id,
        subject_id: principal_id,
        scopes: Vec::new(),
        permissions: Vec::new(),
    };
    Ok(ClientGrantBundle { read, write })
}

fn invitation_only_grants<C>(
    store: &SqliteStore<C>,
    client_id: ClientId,
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
) -> Result<ClientGrantBundle, ApplicationError> {
    if store.find_principal(&principal_id)?.is_none()
        || !store
            .find_workspace(&workspace_id)?
            .is_some_and(|workspace| workspace.kind() == WorkspaceKind::Shared)
        || store
            .find_membership(&workspace_id, &principal_id)?
            .is_some()
    {
        return Err(ApplicationError::AccessDenied);
    }
    Ok(ClientGrantBundle {
        read: ReadGrant {
            client_id: client_id.clone(),
            workspace_id: workspace_id.clone(),
            subject_id: principal_id.clone(),
            scopes: Vec::new(),
            permissions: Vec::new(),
        },
        write: WriteGrant {
            client_id,
            workspace_id,
            subject_id: principal_id,
            scopes: Vec::new(),
            permissions: Vec::new(),
        },
    })
}

async fn create_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateInvitationRequest>,
) -> Result<(StatusCode, Json<InvitationResponse>), ApiError> {
    authorize_bearer(&state, &headers)?;
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    authorize_management_workspace(&runtime, &request.workspace_id)?;
    let role = parse_invitation_role(&request.role).ok_or_else(ApiError::invalid_request)?;
    let created_at = now_epoch_seconds().map_err(|_| ApiError::internal())?;
    let expires_at = created_at
        .checked_add(request.ttl_seconds)
        .ok_or_else(ApiError::invalid_request)?;
    let inviter = runtime.write_grant.subject_id.clone();
    let workspace_id = runtime.write_grant.workspace_id.clone();
    let invitation = InvitationService::new(&mut runtime.store)
        .create(CreateInvitationCommand {
            invitation_id: InvitationId::new(request.invitation_id),
            workspace_id,
            invited_principal_id: PrincipalId::new(request.invited_principal_id),
            invited_by: inviter,
            role,
            request_id: request.request_id,
            created_at_epoch_seconds: created_at,
            expires_at_epoch_seconds: expires_at,
        })
        .map_err(ApiError::from_application)?;
    Ok((StatusCode::CREATED, Json(invitation_response(&invitation))))
}

async fn list_invitations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<InvitationListQuery>,
) -> Result<Json<InvitationListResponse>, ApiError> {
    authorize_bearer(&state, &headers)?;
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    authorize_management_workspace(&runtime, &query.workspace_id)?;
    let status = query
        .status
        .as_deref()
        .map(parse_invitation_status)
        .transpose()
        .map_err(|()| ApiError::invalid_request())?;
    let workspace_id = runtime.write_grant.workspace_id.clone();
    let requested_by = runtime.write_grant.subject_id.clone();
    let invitations = InvitationService::new(&mut runtime.store)
        .list(&ListInvitationsQuery {
            workspace_id: workspace_id.clone(),
            requested_by,
            status,
            limit: query.limit.unwrap_or(100),
        })
        .map_err(ApiError::from_application)?;
    Ok(Json(InvitationListResponse {
        workspace_id: workspace_id.to_string(),
        invitations: invitations
            .iter()
            .map(invitation_list_item_response)
            .collect(),
    }))
}

async fn accept_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<InvitationTransitionRequest>,
) -> Result<Json<InvitationResponse>, ApiError> {
    authorize_bearer(&state, &headers)?;
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    if request.workspace_id != runtime.write_grant.workspace_id.as_str() {
        return Err(ApiError::access_denied());
    }
    let invitation_id = InvitationId::new(request.invitation_id);
    let principal_id = runtime.write_grant.subject_id.clone();
    let workspace_id = runtime.write_grant.workspace_id.clone();
    InvitationService::new(&mut runtime.store)
        .accept(AcceptInvitationCommand {
            invitation_id: invitation_id.clone(),
            workspace_id: workspace_id.clone(),
            accepting_principal_id: principal_id,
            request_id: request.request_id,
            accepted_at_epoch_seconds: now_epoch_seconds().map_err(|_| ApiError::internal())?,
        })
        .map_err(ApiError::from_application)?;
    let invitation = runtime
        .store
        .find_invitation(&workspace_id, &invitation_id)
        .map_err(ApiError::from_application)?
        .ok_or_else(ApiError::internal)?;
    Ok(Json(invitation_response(&invitation)))
}

async fn revoke_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<InvitationTransitionRequest>,
) -> Result<Json<InvitationResponse>, ApiError> {
    authorize_bearer(&state, &headers)?;
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    authorize_management_workspace(&runtime, &request.workspace_id)?;
    let workspace_id = runtime.write_grant.workspace_id.clone();
    let revoked_by = runtime.write_grant.subject_id.clone();
    let invitation = InvitationService::new(&mut runtime.store)
        .revoke(RevokeInvitationCommand {
            invitation_id: InvitationId::new(request.invitation_id),
            workspace_id,
            revoked_by,
            request_id: request.request_id,
            revoked_at_epoch_seconds: now_epoch_seconds().map_err(|_| ApiError::internal())?,
        })
        .map_err(ApiError::from_application)?;
    Ok(Json(invitation_response(&invitation)))
}

fn invitation_response(invitation: &rembrane_domain::Invitation) -> InvitationResponse {
    InvitationResponse {
        workspace_id: invitation.workspace_id().to_string(),
        invitation_id: invitation.id().to_string(),
        invited_principal_id: invitation.invited_principal_id().to_string(),
        role: workspace_role_name(invitation.role()),
        status: invitation_status_name(invitation.status()),
        expires_at_epoch_seconds: invitation.expires_at_epoch_seconds(),
    }
}

fn invitation_list_item_response(
    invitation: &rembrane_domain::Invitation,
) -> InvitationListItemResponse {
    InvitationListItemResponse {
        workspace_id: invitation.workspace_id().to_string(),
        invitation_id: invitation.id().to_string(),
        invited_principal_id: invitation.invited_principal_id().to_string(),
        invited_by: invitation.invited_by().to_string(),
        role: workspace_role_name(invitation.role()),
        status: invitation_status_name(invitation.status()),
        created_at_epoch_seconds: invitation.created_at_epoch_seconds(),
        expires_at_epoch_seconds: invitation.expires_at_epoch_seconds(),
    }
}

const fn invitation_status_name(status: InvitationStatus) -> &'static str {
    match status {
        InvitationStatus::Pending => "pending",
        InvitationStatus::Accepted => "accepted",
        InvitationStatus::Revoked => "revoked",
        InvitationStatus::Expired => "expired",
    }
}

fn parse_invitation_role(value: &str) -> Option<WorkspaceRole> {
    match value {
        "admin" => Some(WorkspaceRole::Admin),
        "member" => Some(WorkspaceRole::Member),
        "viewer" => Some(WorkspaceRole::Viewer),
        _ => None,
    }
}

fn parse_invitation_status(value: &str) -> Result<InvitationStatus, ()> {
    match value {
        "pending" => Ok(InvitationStatus::Pending),
        "accepted" => Ok(InvitationStatus::Accepted),
        "revoked" => Ok(InvitationStatus::Revoked),
        "expired" => Ok(InvitationStatus::Expired),
        _ => Err(()),
    }
}

const fn workspace_role_name(role: WorkspaceRole) -> &'static str {
    match role {
        WorkspaceRole::Owner => "owner",
        WorkspaceRole::Admin => "admin",
        WorkspaceRole::Member => "member",
        WorkspaceRole::Viewer => "viewer",
    }
}

fn now_epoch_seconds() -> Result<u64, std::time::SystemTimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
}

async fn rotate_workspace_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RotateWorkspaceKeyRequest>,
) -> Result<Json<RotateWorkspaceKeyResponse>, ApiError> {
    authorize_bearer(&state, &headers)?;
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    if request.workspace_id != runtime.write_grant.workspace_id.as_str() {
        return Err(ApiError::access_denied());
    }
    let completed_by = runtime.write_grant.subject_id.clone();
    let workspace_id = runtime.write_grant.workspace_id.clone();
    let Runtime {
        store,
        rotation_provider,
        ..
    } = &mut *runtime;
    let completed = MemberLifecycleService::new(store)
        .orchestrate_key_rotation(
            workspace_id,
            completed_by,
            |workspace_id, generation, recipients| {
                rotation_provider
                    .rotate_workspace_key(workspace_id, generation, recipients)
                    .map_err(|_| ApplicationError::StorageUnavailable)
            },
        )
        .map_err(ApiError::from_application)?;
    let key_id = completed
        .completed_key_id()
        .ok_or_else(ApiError::internal)?
        .to_owned();
    Ok(Json(RotateWorkspaceKeyResponse {
        workspace_id: completed.workspace_id().to_string(),
        generation: completed.generation(),
        key_id,
        status: "completed",
    }))
}

async fn list_administrative_audit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AdministrativeAuditResponse>, ApiError> {
    authorize_bearer(&state, &headers)?;
    let runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    authorize_management_workspace(&runtime, &query.workspace_id)?;
    let events = runtime
        .store
        .list_administrative_audit(
            &runtime.write_grant.workspace_id,
            query.after_epoch_seconds.unwrap_or(0),
            query.limit.unwrap_or(100),
        )
        .map_err(ApiError::from_application)?;
    Ok(Json(AdministrativeAuditResponse {
        events: events.iter().map(AdministrativeAuditOutput::from).collect(),
    }))
}

async fn set_retention_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SetRetentionPolicyRequest>,
) -> Result<Json<RetentionPolicyResponse>, ApiError> {
    authorize_bearer(&state, &headers)?;
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    authorize_management_workspace(&runtime, &request.workspace_id)?;
    let version = match request.expected_version {
        Some(version) => version
            .checked_add(1)
            .ok_or_else(ApiError::invalid_request)?,
        None => 1,
    };
    let policy = WorkspaceRetentionPolicy::new(
        runtime.write_grant.workspace_id.clone(),
        version,
        retention_period(request.user_memory_days)?,
        retention_period(request.activity_checkpoint_days)?,
        retention_period(request.travel_research_days)?,
        retention_period(request.disclosure_receipt_days)?,
        retention_period(request.canonical_event_days)?,
        retention_period(request.administrative_audit_days)?,
    )
    .map_err(|_| ApiError::invalid_request())?;
    let actor = runtime.write_grant.subject_id.clone();
    let policy = RetentionService::new(&mut runtime.store)
        .set_policy(SetRetentionPolicyCommand {
            policy,
            expected_version: request.expected_version,
            changed_by: actor,
            request_id: request.request_id,
        })
        .map_err(ApiError::from_application)?;
    Ok(Json(RetentionPolicyResponse {
        workspace_id: policy.workspace_id().to_string(),
        version: policy.version(),
    }))
}

async fn place_legal_hold(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<LegalHoldRequest>,
) -> Result<(StatusCode, Json<LegalHoldResponse>), ApiError> {
    authorize_bearer(&state, &headers)?;
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    authorize_management_workspace(&runtime, &request.workspace_id)?;
    let actor = runtime.write_grant.subject_id.clone();
    let workspace_id = runtime.write_grant.workspace_id.clone();
    let hold = RetentionService::new(&mut runtime.store)
        .place_legal_hold(PlaceLegalHoldCommand {
            workspace_id,
            hold_id: LegalHoldId::new(request.hold_id),
            placed_by: actor,
            request_id: request.request_id,
        })
        .map_err(ApiError::from_application)?;
    Ok((StatusCode::CREATED, Json(LegalHoldResponse::from(&hold))))
}

async fn release_legal_hold(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<LegalHoldRequest>,
) -> Result<Json<LegalHoldResponse>, ApiError> {
    authorize_bearer(&state, &headers)?;
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    authorize_management_workspace(&runtime, &request.workspace_id)?;
    let actor = runtime.write_grant.subject_id.clone();
    let workspace_id = runtime.write_grant.workspace_id.clone();
    let hold = RetentionService::new(&mut runtime.store)
        .release_legal_hold(ReleaseLegalHoldCommand {
            workspace_id,
            hold_id: LegalHoldId::new(request.hold_id),
            released_by: actor,
            request_id: request.request_id,
        })
        .map_err(ApiError::from_application)?;
    Ok(Json(LegalHoldResponse::from(&hold)))
}

async fn execute_retention_purge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ExecuteRetentionPurgeRequest>,
) -> Result<Json<RetentionPurgeResponse>, ApiError> {
    authorize_bearer(&state, &headers)?;
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    authorize_management_workspace(&runtime, &request.workspace_id)?;
    let workspace_id = runtime.write_grant.workspace_id.clone();
    let executed_by = runtime.write_grant.subject_id.clone();
    let now_epoch_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ApiError::internal())?
        .as_secs();
    let result = RetentionService::new(&mut runtime.store)
        .execute_purge(ExecuteRetentionPurgeCommand {
            workspace_id,
            executed_by,
            now_epoch_seconds,
            maximum_items: request.maximum_items,
        })
        .map_err(ApiError::from_application)?;
    Ok(Json(RetentionPurgeResponse {
        memories: result.memories,
        checkpoints: result.checkpoints,
        travel_research: result.travel_research,
        disclosures: result.disclosures,
        canonical_events: result.canonical_events,
        total: result.total(),
    }))
}

fn authorize_management_workspace(runtime: &Runtime, workspace_id: &str) -> Result<(), ApiError> {
    if workspace_id != runtime.write_grant.workspace_id.as_str() {
        return Err(ApiError::access_denied());
    }
    let membership = runtime
        .store
        .find_membership(
            &runtime.write_grant.workspace_id,
            &runtime.write_grant.subject_id,
        )
        .map_err(ApiError::from_application)?
        .filter(|membership| membership.is_active() && membership.can_manage_members())
        .ok_or_else(ApiError::access_denied)?;
    if membership.principal_id() != &runtime.write_grant.subject_id {
        return Err(ApiError::access_denied());
    }
    Ok(())
}

fn retention_period(days: Option<u32>) -> Result<RetentionPeriod, ApiError> {
    days.map_or(Ok(RetentionPeriod::Forever), |days| {
        RetentionPeriod::days(days).map_err(|_| ApiError::invalid_request())
    })
}

async fn oauth_protected_resource(
    State(state): State<AppState>,
) -> Result<Json<OAuthProtectedResourceMetadata>, ApiError> {
    state
        .inner
        .oauth_resource_metadata
        .clone()
        .map(Json)
        .ok_or_else(ApiError::not_found)
}

fn next_id(runtime: &mut Runtime) -> Result<u128, ApiError> {
    advance_identifier(&mut runtime.next_id).ok_or_else(ApiError::internal)
}

fn advance_identifier(current: &mut u128) -> Option<u128> {
    let next = current.checked_add(1)?;
    *current = next;
    Some(next)
}

async fn checkpoint_activity(
    State(state): State<AppState>,
    Path(activity_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CheckpointActivityRequest>,
) -> Result<(StatusCode, Json<ActivityCheckpointResponse>), ApiError> {
    authorize_bearer(&state, &headers)?;
    if activity_id.trim().is_empty()
        || request.summary.trim().is_empty()
        || request.expected_version == Some(0)
    {
        return Err(ApiError::invalid_request());
    }
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    if request.workspace_id != runtime.write_grant.workspace_id.as_str()
        || request.subject_id != runtime.write_grant.subject_id.as_str()
    {
        return Err(ApiError::access_denied());
    }
    let activity_id = ActivityId::new(activity_id);
    let suffix = next_id(&mut runtime)?;
    let checkpoint = if let Some(expected_version) = request.expected_version {
        let read_grant = runtime.read_grant.clone();
        let current = CheckpointService::new(&mut runtime.store)
            .load_for_update(&read_grant, &activity_id)
            .map_err(ApiError::from_application)?
            .ok_or_else(ApiError::not_found)?;
        if current.version() != expected_version {
            return Err(ApiError::conflict());
        }
        let mut updated = current
            .update(request.summary, request.next_steps, request.blockers)
            .map_err(|_| ApiError::invalid_request())?;
        if let Some(fingerprint) = request.state_fingerprint {
            updated = updated
                .with_state_fingerprint(fingerprint)
                .map_err(|_| ApiError::invalid_request())?;
        }
        let write_grant = runtime.write_grant.clone();
        CheckpointService::new(&mut runtime.store)
            .update(UpdateCheckpointCommand {
                grant: write_grant,
                checkpoint: updated,
                expected_version,
                event_id: EventId::new(format!("event_{suffix}")),
                expected_previous_sequence: request.expected_previous_sequence,
            })
            .map_err(ApiError::from_application)?
    } else {
        let goal = request
            .goal
            .filter(|goal| !goal.trim().is_empty())
            .ok_or_else(ApiError::invalid_request)?;
        let mut created = ActivityCheckpoint::new(
            CheckpointId::new(format!("checkpoint_{suffix}")),
            runtime.write_grant.workspace_id.clone(),
            runtime.write_grant.subject_id.clone(),
            activity_id,
            request.entity_id.map(EntityId::new),
            goal,
            request.summary,
            request.next_steps,
            request.blockers,
        )
        .map_err(|_| ApiError::invalid_request())?;
        if let Some(fingerprint) = request.state_fingerprint {
            created = created
                .with_state_fingerprint(fingerprint)
                .map_err(|_| ApiError::invalid_request())?;
        }
        let write_grant = runtime.write_grant.clone();
        CheckpointService::new(&mut runtime.store)
            .create(CreateCheckpointCommand {
                grant: write_grant,
                checkpoint: created,
                event_id: EventId::new(format!("event_{suffix}")),
                expected_previous_sequence: request.expected_previous_sequence,
            })
            .map_err(ApiError::from_application)?
    };
    let status = if checkpoint.version() == 1 {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(activity_checkpoint_response(&checkpoint, None, None)),
    ))
}

async fn resume_activity(
    State(state): State<AppState>,
    Path(activity_id): Path<String>,
    Query(query): Query<ResumeActivityQuery>,
    headers: HeaderMap,
) -> Result<Json<ActivityCheckpointResponse>, ApiError> {
    authorize_bearer(&state, &headers)?;
    if activity_id.trim().is_empty() {
        return Err(ApiError::invalid_request());
    }
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    if query.workspace_id != runtime.read_grant.workspace_id.as_str()
        || query.subject_id != runtime.read_grant.subject_id.as_str()
    {
        return Err(ApiError::access_denied());
    }
    let suffix = next_id(&mut runtime)?;
    let disclosure_id = DisclosureId::new(format!("disclosure_{suffix}"));
    let read_grant = runtime.read_grant.clone();
    let checkpoint = CheckpointService::new(&mut runtime.store)
        .resume(&ResumeActivityCommand {
            grant: read_grant,
            activity_id: ActivityId::new(activity_id),
            disclosure_id: disclosure_id.clone(),
            purpose: query
                .purpose
                .unwrap_or_else(|| "resume-activity".to_owned()),
        })
        .map_err(ApiError::from_application)?
        .ok_or_else(ApiError::not_found)?;
    let stale_state = query
        .state_fingerprint
        .as_deref()
        .map(|fingerprint| checkpoint.is_stale_against(fingerprint));
    Ok(Json(activity_checkpoint_response(
        &checkpoint,
        stale_state,
        Some(&disclosure_id),
    )))
}

fn activity_checkpoint_response(
    checkpoint: &ActivityCheckpoint,
    stale: Option<bool>,
    disclosure_id: Option<&DisclosureId>,
) -> ActivityCheckpointResponse {
    ActivityCheckpointResponse {
        checkpoint_id: checkpoint.id().to_string(),
        workspace_id: checkpoint.workspace_id().to_string(),
        subject_id: checkpoint.subject_id().to_string(),
        activity_id: checkpoint.activity_id().to_string(),
        entity_id: checkpoint.entity_id().map(ToString::to_string),
        goal: checkpoint.goal().to_owned(),
        summary: checkpoint.summary().to_owned(),
        next_steps: checkpoint.next_steps().to_vec(),
        blockers: checkpoint.blockers().to_vec(),
        state_fingerprint: checkpoint.state_fingerprint().map(str::to_owned),
        version: checkpoint.version(),
        stale,
        disclosure_id: disclosure_id.map(ToString::to_string),
    }
}

async fn create_trip(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateTripRequest>,
) -> Result<(StatusCode, Json<TripResponse>), ApiError> {
    authorize_bearer(&state, &headers)?;
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    if request.workspace_id != runtime.write_grant.workspace_id.as_str()
        || request.subject_id != runtime.write_grant.subject_id.as_str()
    {
        return Err(ApiError::access_denied());
    }
    let suffix = next_id(&mut runtime)?;
    let date_window = TravelDateWindow::new(request.depart_not_before, request.return_not_after)
        .map_err(|_| ApiError::invalid_request())?;
    let trip = Trip::new(
        EntityId::new(format!("trip_{suffix}")),
        runtime.write_grant.workspace_id.clone(),
        runtime.write_grant.subject_id.clone(),
        request.title,
        request.origin,
        request.destinations,
        date_window,
    )
    .map_err(|_| ApiError::invalid_request())?;
    let write_grant = runtime.write_grant.clone();
    let created = TripService::new(&mut runtime.store)
        .create(CreateTripCommand {
            grant: write_grant,
            trip,
            event_id: EventId::new(format!("event_{suffix}")),
            expected_previous_sequence: request.expected_previous_sequence,
        })
        .map_err(ApiError::from_application)?;
    let created_scope = rembrane_domain::ReadScope::Entity {
        id: created.id().clone(),
    };
    if !runtime.read_grant.scopes.contains(&created_scope) {
        runtime.read_grant.scopes.push(created_scope.clone());
    }
    if !runtime.write_grant.scopes.contains(&created_scope) {
        runtime.write_grant.scopes.push(created_scope);
    }
    Ok((
        StatusCode::CREATED,
        Json(TripResponse {
            trip_id: created.id().to_string(),
            workspace_id: created.workspace_id().to_string(),
            owner_subject_id: created.owner_subject_id().to_string(),
            version: created.version(),
        }),
    ))
}

async fn capture_booking_research(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CaptureBookingResearchRequest>,
) -> Result<(StatusCode, Json<BookingResearchResponse>), ApiError> {
    authorize_bearer(&state, &headers)?;
    let kind = parse_research_kind(&request.kind).ok_or_else(ApiError::invalid_request)?;
    let evidence_source =
        parse_evidence_source(&request.evidence_source).ok_or_else(ApiError::invalid_request)?;
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    if request.workspace_id != runtime.write_grant.workspace_id.as_str()
        || request.subject_id != runtime.write_grant.subject_id.as_str()
    {
        return Err(ApiError::access_denied());
    }
    let suffix = next_id(&mut runtime)?;
    let research = BookingResearch::new(
        BookingResearchId::new(format!("research_{suffix}")),
        runtime.write_grant.workspace_id.clone(),
        EntityId::new(request.trip_id),
        runtime.write_grant.subject_id.clone(),
        kind,
        request.provider,
        request.summary,
        request.source_reference,
        EvidenceReference::new(
            EvidenceId::new(format!("evidence_{suffix}")),
            evidence_source,
        ),
        request.observed_at,
        request.expires_at,
    )
    .map_err(|_| ApiError::invalid_request())?;
    let write_grant = runtime.write_grant.clone();
    let captured = CaptureBookingResearchService::new(&mut runtime.store)
        .execute(CaptureBookingResearchCommand {
            grant: write_grant,
            research,
            event_id: EventId::new(format!("event_{suffix}")),
            expected_previous_sequence: request.expected_previous_sequence,
        })
        .map_err(ApiError::from_application)?;
    Ok((
        StatusCode::CREATED,
        Json(BookingResearchResponse {
            id: captured.id().to_string(),
            workspace_id: captured.workspace_id().to_string(),
            trip_id: captured.trip_id().to_string(),
            observed_by: captured.observed_by().to_string(),
            version: captured.version(),
            expires_at: captured.expires_at().to_owned(),
        }),
    ))
}

async fn add_trip_participant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AddTripParticipantRequest>,
) -> Result<(StatusCode, Json<TripParticipantResponse>), ApiError> {
    authorize_bearer(&state, &headers)?;
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    if request.workspace_id != runtime.write_grant.workspace_id.as_str()
        || request.subject_id != runtime.write_grant.subject_id.as_str()
    {
        return Err(ApiError::access_denied());
    }
    let suffix = next_id(&mut runtime)?;
    let participant_id = TripParticipantId::new(format!("participant_{suffix}"));
    let participant = TripParticipant::new(participant_id.clone(), request.label)
        .map_err(|_| ApiError::invalid_request())?;
    let write_grant = runtime.write_grant.clone();
    let revised = TripService::new(&mut runtime.store)
        .add_participant(AddTripParticipantCommand {
            grant: write_grant,
            trip_id: EntityId::new(request.trip_id),
            participant,
            expected_trip_version: request.expected_trip_version,
            event_id: EventId::new(format!("event_{suffix}")),
            expected_previous_sequence: request.expected_previous_sequence,
        })
        .map_err(ApiError::from_application)?;
    let stored = revised
        .participants()
        .iter()
        .find(|participant| participant.id() == &participant_id)
        .ok_or_else(ApiError::internal)?;
    Ok((
        StatusCode::CREATED,
        Json(TripParticipantResponse {
            trip_id: revised.id().to_string(),
            participant_id: stored.id().to_string(),
            label: stored.label().to_owned(),
            trip_version: revised.version(),
        }),
    ))
}

async fn add_trip_constraint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AddTripConstraintRequest>,
) -> Result<(StatusCode, Json<TripRevisionResponse>), ApiError> {
    authorize_bearer(&state, &headers)?;
    let kind = parse_constraint_kind(&request.kind).ok_or_else(ApiError::invalid_request)?;
    let evidence_source =
        parse_evidence_source(&request.evidence_source).ok_or_else(ApiError::invalid_request)?;
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    if request.workspace_id != runtime.write_grant.workspace_id.as_str()
        || request.subject_id != runtime.write_grant.subject_id.as_str()
    {
        return Err(ApiError::access_denied());
    }
    let suffix = next_id(&mut runtime)?;
    let constraint_id = TripConstraintId::new(format!("constraint_{suffix}"));
    let constraint = TripConstraint::new(
        constraint_id.clone(),
        request.participant_id.map(TripParticipantId::new),
        kind,
        request.statement,
        EvidenceReference::new(
            EvidenceId::new(format!("evidence_{suffix}")),
            evidence_source,
        ),
    )
    .map_err(|_| ApiError::invalid_request())?;
    let write_grant = runtime.write_grant.clone();
    let revised = TripService::new(&mut runtime.store)
        .add_constraint(AddTripConstraintCommand {
            grant: write_grant,
            trip_id: EntityId::new(request.trip_id),
            constraint,
            expected_trip_version: request.expected_trip_version,
            event_id: EventId::new(format!("event_{suffix}")),
            expected_previous_sequence: request.expected_previous_sequence,
        })
        .map_err(ApiError::from_application)?;
    Ok((
        StatusCode::CREATED,
        Json(TripRevisionResponse {
            trip_id: revised.id().to_string(),
            record_id: constraint_id.to_string(),
            trip_version: revised.version(),
        }),
    ))
}

async fn record_trip_decision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RecordTripDecisionRequest>,
) -> Result<(StatusCode, Json<TripRevisionResponse>), ApiError> {
    authorize_bearer(&state, &headers)?;
    let status = parse_decision_status(&request.status).ok_or_else(ApiError::invalid_request)?;
    let evidence_source =
        parse_evidence_source(&request.evidence_source).ok_or_else(ApiError::invalid_request)?;
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    if request.workspace_id != runtime.write_grant.workspace_id.as_str()
        || request.subject_id != runtime.write_grant.subject_id.as_str()
    {
        return Err(ApiError::access_denied());
    }
    let suffix = next_id(&mut runtime)?;
    let decision_id = TripDecisionId::new(format!("decision_{suffix}"));
    let decision = TripDecision::new(
        decision_id.clone(),
        status,
        request.summary,
        request.rationale,
        runtime.write_grant.subject_id.clone(),
        EvidenceReference::new(
            EvidenceId::new(format!("evidence_{suffix}")),
            evidence_source,
        ),
    )
    .map_err(|_| ApiError::invalid_request())?;
    let write_grant = runtime.write_grant.clone();
    let revised = TripService::new(&mut runtime.store)
        .record_decision(RecordTripDecisionCommand {
            grant: write_grant,
            trip_id: EntityId::new(request.trip_id),
            decision,
            expected_trip_version: request.expected_trip_version,
            event_id: EventId::new(format!("event_{suffix}")),
            expected_previous_sequence: request.expected_previous_sequence,
        })
        .map_err(ApiError::from_application)?;
    Ok((
        StatusCode::CREATED,
        Json(TripRevisionResponse {
            trip_id: revised.id().to_string(),
            record_id: decision_id.to_string(),
            trip_version: revised.version(),
        }),
    ))
}

async fn resolve_travel_context(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ResolveTravelContextRequest>,
) -> Result<Json<TravelContextResponse>, ApiError> {
    authorize_bearer(&state, &headers)?;
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    if request.workspace_id != runtime.read_grant.workspace_id.as_str()
        || request.subject_id != runtime.read_grant.subject_id.as_str()
    {
        return Err(ApiError::access_denied());
    }
    let trip_id = EntityId::new(request.trip_id);
    if !runtime.read_grant.allows(&MemoryScope::Entity {
        id: trip_id.clone(),
    }) {
        return Err(ApiError::access_denied());
    }
    let disclosure_id = DisclosureId::new(format!("disclosure_{}", next_id(&mut runtime)?));
    let read_grant = runtime.read_grant.clone();
    let context = TravelContextService::new(&mut runtime.store)
        .resolve(&ResolveTravelContextCommand {
            grant: read_grant,
            disclosure_id: disclosure_id.clone(),
            trip_id,
            purpose: request.purpose,
            as_of: request.as_of,
            include_source_references: request.include_source_references.unwrap_or(false),
            include_sensitive_profile: request.include_sensitive_profile.unwrap_or(false),
        })
        .map_err(ApiError::from_application)?;
    Ok(Json(TravelContextResponse {
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
    }))
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn memory_discovery(State(state): State<AppState>) -> Json<MemoryDiscovery> {
    Json(state.inner.discovery.clone())
}

async fn resolve_context(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ResolveRequest>,
) -> Result<Json<ResolveResponse>, ApiError> {
    authorize_bearer(&state, &headers)?;
    if request.purpose.trim().is_empty()
        || request.query.trim().is_empty()
        || !(1..=100).contains(&request.maximum_items)
        || request
            .maximum_bytes
            .is_some_and(|bytes| !(1..=1_048_576).contains(&bytes))
    {
        return Err(ApiError::invalid_request());
    }

    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    if request.workspace_id != runtime.read_grant.workspace_id.as_str()
        || request.subject_id != runtime.read_grant.subject_id.as_str()
    {
        return Err(ApiError::access_denied());
    }
    let suffix = next_id(&mut runtime)?;
    let read_grant = runtime.read_grant.clone();
    if !request_is_within_grant(&request, &read_grant) {
        return Err(ApiError::access_denied());
    }
    let workspace_id = read_grant.workspace_id.clone();
    let principal_id = read_grant.subject_id.clone();
    let response = ResolveContextService::new(&mut runtime.store)
        .execute(ResolveContextCommand {
            request: ResolveContextRequest {
                workspace_id: workspace_id.clone(),
                principal_id: principal_id.clone(),
                domain: request.domain,
                entity_id: request.entity_id.map(EntityId::new),
                activity_id: request.activity_id.map(ActivityId::new),
                purpose: request.purpose,
                query: request.query,
                maximum_items: request.maximum_items,
                maximum_bytes: request.maximum_bytes.unwrap_or(65_536),
            },
            grant: read_grant,
            context_pack_id: ContextPackId::new(format!("context_{suffix}")),
            disclosure_id: DisclosureId::new(format!("disclosure_{suffix}")),
        })
        .map_err(|_| ApiError::internal())?;

    Ok(Json(ResolveResponse {
        context_pack_id: response.context_pack_id.to_string(),
        disclosure_id: response.disclosure_id.to_string(),
        items: response.items.iter().map(MemoryOutput::from).collect(),
    }))
}

async fn resolve_graph_context(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ResolveGraphRequest>,
) -> Result<Json<ResolveGraphResponse>, ApiError> {
    authorize_bearer(&state, &headers)?;
    let direction = match request.direction.as_str() {
        "incoming" => GraphDisclosureDirection::Incoming,
        "outgoing" => GraphDisclosureDirection::Outgoing,
        "both" => GraphDisclosureDirection::Both,
        _ => return Err(ApiError::invalid_request()),
    };
    let maximum_candidates = request.maximum_candidates.unwrap_or(20);
    if request.purpose.trim().is_empty()
        || request.valid_at_epoch_seconds == 0
        || !(1..=100).contains(&maximum_candidates)
    {
        return Err(ApiError::invalid_request());
    }
    let scope = graph_request_scope(&request)?;
    let mut runtime = state
        .inner
        .runtime
        .lock()
        .map_err(|_| ApiError::internal())?;
    if request.workspace_id != runtime.read_grant.workspace_id.as_str()
        || request.subject_id != runtime.read_grant.subject_id.as_str()
        || !runtime.read_grant.allows(&scope)
    {
        return Err(ApiError::access_denied());
    }
    let disclosure_id = DisclosureId::new(format!("disclosure_{}", next_id(&mut runtime)?));
    let grant = runtime.read_grant.clone();
    let graph_request = ResolveGraphContextRequest {
        workspace_id: grant.workspace_id.clone(),
        principal_id: grant.subject_id.clone(),
        node_id: KnowledgeNodeId::new(request.node_id),
        scope,
        direction,
        valid_at_epoch_seconds: request.valid_at_epoch_seconds,
        maximum_candidates,
        purpose: request.purpose,
    };
    let Runtime {
        store,
        graph_provider,
        ..
    } = &mut *runtime;
    let response = GraphContextService::new(store, graph_provider)
        .execute_request(graph_request, grant, disclosure_id)
        .map_err(ApiError::from_application)?;
    Ok(Json(ResolveGraphResponse {
        disclosure_id: response.disclosure_id.to_string(),
        edges: response
            .edges
            .into_iter()
            .map(|edge| {
                let validity = edge.validity();
                GraphEdgeResponse {
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
    }))
}

fn graph_request_scope(request: &ResolveGraphRequest) -> Result<MemoryScope, ApiError> {
    let selected = usize::from(request.domain.is_some())
        + usize::from(request.entity_id.is_some())
        + usize::from(request.activity_id.is_some());
    if selected > 1 {
        return Err(ApiError::invalid_request());
    }
    Ok(if let Some(name) = &request.domain {
        MemoryScope::Domain { name: name.clone() }
    } else if let Some(id) = &request.entity_id {
        MemoryScope::Entity {
            id: EntityId::new(id),
        }
    } else if let Some(id) = &request.activity_id {
        MemoryScope::Activity {
            id: ActivityId::new(id),
        }
    } else {
        MemoryScope::Global
    })
}

fn request_is_within_grant(request: &ResolveRequest, grant: &ReadGrant) -> bool {
    let has_specific_scope =
        request.domain.is_some() || request.entity_id.is_some() || request.activity_id.is_some();
    (has_specific_scope || grant.allows(&MemoryScope::Global))
        && request
            .domain
            .as_ref()
            .is_none_or(|name| grant.allows(&MemoryScope::Domain { name: name.clone() }))
        && request.entity_id.as_ref().is_none_or(|id| {
            grant.allows(&MemoryScope::Entity {
                id: EntityId::new(id),
            })
        })
        && request.activity_id.as_ref().is_none_or(|id| {
            grant.allows(&MemoryScope::Activity {
                id: ActivityId::new(id),
            })
        })
}

fn authorize_bearer(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(header) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Err(ApiError::unauthenticated());
    };
    let Ok(header) = header.to_str() else {
        return Err(ApiError::unauthenticated());
    };
    let Some(token) = header.strip_prefix("Bearer ") else {
        return Err(ApiError::unauthenticated());
    };
    if !token_matches(&state.inner.bearer_token, token) {
        return Err(ApiError::unauthenticated());
    }
    Ok(())
}

fn token_matches(expected: &str, presented: &str) -> bool {
    presented.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1
}

impl ApiError {
    const fn invalid_request() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_request",
            message: "request validation failed",
        }
    }

    const fn unauthenticated() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthenticated",
            message: "authentication is missing or invalid",
        }
    }

    const fn access_denied() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "access_denied",
            message: "request is outside the connection grant",
        }
    }

    const fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: "request could not be completed",
        }
    }

    const fn conflict() -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "conflict",
            message: "a version or event sequence conflict occurred",
        }
    }

    const fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: "the requested canonical record was not found",
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    fn from_application(error: ApplicationError) -> Self {
        match error {
            ApplicationError::AccessDenied => Self::access_denied(),
            ApplicationError::NotFound => Self::not_found(),
            ApplicationError::AlreadyExists
            | ApplicationError::SequenceConflict
            | ApplicationError::VersionConflict => Self::conflict(),
            ApplicationError::Validation(_) => Self::invalid_request(),
            ApplicationError::StorageUnavailable => Self::internal(),
        }
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

impl From<&AdministrativeAuditEvent> for AdministrativeAuditOutput {
    fn from(event: &AdministrativeAuditEvent) -> Self {
        Self {
            id: event.id().to_string(),
            workspace_id: event.workspace_id().to_string(),
            actor_id: event.actor_id().to_string(),
            action: event.action().label(),
            target_kind: event.target_kind().label(),
            target_id: event.target_id().to_owned(),
            request_id: event.request_id().to_owned(),
            occurred_at_epoch_seconds: event.occurred_at_epoch_seconds(),
        }
    }
}

impl From<&rembrane_domain::WorkspaceLegalHold> for LegalHoldResponse {
    fn from(hold: &rembrane_domain::WorkspaceLegalHold) -> Self {
        Self {
            workspace_id: hold.workspace_id().to_string(),
            hold_id: hold.id().to_string(),
            version: hold.version(),
            status: match hold.status() {
                rembrane_domain::LegalHoldStatus::Active => "active",
                rembrane_domain::LegalHoldStatus::Released => "released",
            },
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

impl From<&rembrane_domain::MemoryRecord> for MemoryOutput {
    fn from(memory: &rembrane_domain::MemoryRecord) -> Self {
        Self {
            id: memory.id().to_string(),
            workspace_id: memory.workspace_id().to_string(),
            subject_id: memory.subject_id().to_string(),
            scope: ScopeOutput::from(memory.scope()),
            kind: encode_kind(memory.kind()),
            status: encode_status(memory.status()),
            content: memory.content().to_owned(),
            version: memory.version(),
            evidence: memory
                .evidence()
                .iter()
                .map(|evidence| EvidenceOutput {
                    id: evidence.id.to_string(),
                    source: match evidence.source {
                        rembrane_domain::EvidenceSource::UserStatement => "user-statement",
                        rembrane_domain::EvidenceSource::AgentObservation => "agent-observation",
                        rembrane_domain::EvidenceSource::ToolResult => "tool-result",
                        rembrane_domain::EvidenceSource::ImportedRecord => "imported-record",
                        rembrane_domain::EvidenceSource::WorkspaceDecision => "workspace-decision",
                    },
                })
                .collect(),
        }
    }
}

impl From<&MemoryScope> for ScopeOutput {
    fn from(scope: &MemoryScope) -> Self {
        match scope {
            MemoryScope::Global => Self::Global,
            MemoryScope::Domain { name } => Self::Domain { name: name.clone() },
            MemoryScope::Entity { id } => Self::Entity { id: id.to_string() },
            MemoryScope::Activity { id } => Self::Activity { id: id.to_string() },
        }
    }
}

const fn encode_kind(kind: MemoryKind) -> &'static str {
    match kind {
        MemoryKind::Preference => "preference",
        MemoryKind::Semantic => "semantic",
        MemoryKind::Episodic => "episodic",
        MemoryKind::Procedural => "procedural",
        MemoryKind::Observation => "observation",
        MemoryKind::Working => "working",
    }
}

const fn encode_status(status: MemoryStatus) -> &'static str {
    match status {
        MemoryStatus::Proposed => "proposed",
        MemoryStatus::Confirmed => "confirmed",
        MemoryStatus::Superseded => "superseded",
        MemoryStatus::Deleted => "deleted",
    }
}

fn required_environment(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

fn oauth_resource_metadata_from_environment() -> Result<Option<OAuthProtectedResourceMetadata>> {
    let resource = std::env::var("REMBRANE_MCP_RESOURCE").ok();
    let issuer = std::env::var("REMBRANE_OAUTH_ISSUER").ok();
    match (resource, issuer) {
        (None, None) => Ok(None),
        (Some(resource), Some(issuer)) => {
            anyhow::ensure!(
                resource.starts_with("https://") && issuer.starts_with("https://"),
                "remote MCP resource and OAuth issuer must use HTTPS"
            );
            Ok(Some(OAuthProtectedResourceMetadata {
                resource,
                authorization_servers: vec![issuer],
                scopes_supported: vec![
                    "rembrane:context:read",
                    "rembrane:memory:write",
                    "rembrane:checkpoint:read",
                    "rembrane:checkpoint:write",
                    "rembrane:travel:read",
                    "rembrane:travel:write",
                    "rembrane:graph:read",
                ],
                bearer_methods_supported: vec!["header"],
                resource_name: "Rembrane remote MCP",
            }))
        }
        _ => anyhow::bail!(
            "REMBRANE_MCP_RESOURCE and REMBRANE_OAUTH_ISSUER must be configured together"
        ),
    }
}

fn memory_discovery_from_environment() -> Result<MemoryDiscovery> {
    let listen = std::env::var("REMBRANE_LISTEN").unwrap_or_else(|_| "127.0.0.1:8787".to_owned());
    let api =
        std::env::var("REMBRANE_PUBLIC_API_URL").unwrap_or_else(|_| format!("http://{listen}/v1"));
    let uri = api
        .parse::<axum::http::Uri>()
        .context("REMBRANE_PUBLIC_API_URL must be an absolute URI")?;
    let scheme = uri
        .scheme_str()
        .context("REMBRANE_PUBLIC_API_URL must include a scheme")?;
    let authority = uri
        .authority()
        .context("REMBRANE_PUBLIC_API_URL must include an authority")?;
    let host = authority.host();
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "::1");
    anyhow::ensure!(
        scheme == "https" || (scheme == "http" && loopback),
        "REMBRANE_PUBLIC_API_URL must use HTTPS or explicit loopback HTTP"
    );
    anyhow::ensure!(
        !authority.as_str().contains('@') && uri.query().is_none(),
        "REMBRANE_PUBLIC_API_URL must not contain credentials or a query"
    );
    anyhow::ensure!(
        uri.path().ends_with("/v1"),
        "REMBRANE_PUBLIC_API_URL must identify the versioned /v1 API root"
    );
    let (processing_mode, plaintext_location) = if loopback {
        ("local-only", "user-device")
    } else {
        ("customer-gateway", "customer-gateway")
    };
    Ok(MemoryDiscovery {
        provider: DiscoveryProvider {
            id: "local.rembrane",
            name: "Rembrane",
            implementation: "rembrane",
        },
        protocol_versions: vec!["0.1"],
        endpoints: DiscoveryEndpoints { api },
        capabilities: DiscoveryCapabilities {
            context_resolution: true,
            question_resolution: false,
            memory_proposal: false,
            activity_checkpoint: true,
            disclosure_receipt: true,
            deletion_propagation: false,
            sync: false,
            imports: Vec::new(),
            exports: vec!["encrypted-archive"],
        },
        limits: DiscoveryLimits {
            maximum_context_items: 100,
            maximum_context_bytes: 1_048_576,
            maximum_event_bytes: 262_144,
        },
        privacy: DiscoveryPrivacy {
            processing_modes: vec![processing_mode],
            disclosure_receipts: true,
            plaintext_processing_location: plaintext_location,
        },
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let state = AppState::from_environment()?;
    let configured_address =
        std::env::var("REMBRANE_LISTEN").unwrap_or_else(|_| "127.0.0.1:8787".to_owned());
    let address = configured_address
        .parse::<std::net::SocketAddr>()
        .with_context(|| format!("invalid listen address {configured_address}"))?;
    let allow_non_loopback = std::env::var("REMBRANE_ALLOW_NON_LOOPBACK").as_deref() == Ok("1");
    anyhow::ensure!(
        address.ip().is_loopback() || allow_non_loopback,
        "non-loopback HTTP requires REMBRANE_ALLOW_NON_LOOPBACK=1 and a trusted TLS proxy"
    );
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("failed to bind {address}"))?;
    let app = Router::new()
        .route("/health", get(health))
        .route("/.well-known/ai-memory", get(memory_discovery))
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(oauth_protected_resource),
        )
        .route("/v1/context/resolve", post(resolve_context))
        .route("/v1/graph/context/resolve", post(resolve_graph_context))
        .route(
            "/v1/activities/{activity_id}/checkpoint",
            post(checkpoint_activity),
        )
        .route("/v1/activities/{activity_id}/resume", get(resume_activity))
        .route(
            "/v1/workspaces/invitations",
            get(list_invitations).post(create_invitation),
        )
        .route("/v1/workspaces/invitations/accept", post(accept_invitation))
        .route("/v1/workspaces/invitations/revoke", post(revoke_invitation))
        .route("/v1/workspaces/key-rotation", post(rotate_workspace_key))
        .route("/v1/administrative-audit", get(list_administrative_audit))
        .route("/v1/retention/policy", post(set_retention_policy))
        .route("/v1/retention/purge", post(execute_retention_purge))
        .route("/v1/retention/legal-holds", post(place_legal_hold))
        .route(
            "/v1/retention/legal-holds/release",
            post(release_legal_hold),
        )
        .route("/v1/travel/trips", post(create_trip))
        .route("/v1/travel/trip-participants", post(add_trip_participant))
        .route("/v1/travel/trip-constraints", post(add_trip_constraint))
        .route("/v1/travel/trip-decisions", post(record_trip_decision))
        .route("/v1/travel/context/resolve", post(resolve_travel_context))
        .route(
            "/v1/travel/booking-research",
            post(capture_booking_research),
        )
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state);
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use rembrane_application::WorkspaceRepository;
    use rembrane_domain::{
        ClientId, EntityId, InvitationStatus, Membership, MemoryScope, Principal, PrincipalId,
        ReadGrant, ReadScope, Workspace, WorkspaceId, WorkspaceRole,
    };
    use rembrane_store_sqlite::SqliteStore;

    use super::{
        ResolveGraphRequest, ResolveRequest, advance_identifier, graph_request_scope,
        invitation_only_grants, parse_invitation_role, parse_invitation_status,
        request_is_within_grant, selected_api_token_reference, token_matches, valid_api_token,
    };

    #[test]
    fn accepts_only_exact_bearer_token() {
        assert!(token_matches("secret-token", "secret-token"));
        assert!(!token_matches("secret-token", "secret-other"));
        assert!(!token_matches("secret-token", "short"));
    }

    #[test]
    fn invitation_status_filter_is_closed() {
        assert_eq!(
            parse_invitation_status("accepted"),
            Ok(InvitationStatus::Accepted)
        );
        assert!(parse_invitation_status("all").is_err());
        assert!(parse_invitation_status("PENDING").is_err());
    }

    #[test]
    fn api_token_reference_defaults_and_token_grammar_is_bounded() {
        let default = selected_api_token_reference("").expect("default environment reference");
        assert_eq!(default.environment_variable(), Some("REMBRANE_API_TOKEN"));
        let file = selected_api_token_reference("file:/run/secrets/rembrane-api-token")
            .expect("file reference");
        assert_eq!(file.file_path(), Some("/run/secrets/rembrane-api-token"));
        assert!(selected_api_token_reference("inline-token").is_err());

        assert!(valid_api_token("opaque-token_01.~+/="));
        for invalid in ["", "token with space", "token\nvalue", "token:value"] {
            assert!(!valid_api_token(invalid));
        }
        assert!(!valid_api_token(
            &"a".repeat(super::MAXIMUM_API_TOKEN_BYTES + 1)
        ));
    }

    #[test]
    fn rejects_request_scope_outside_connection_grant() {
        let request = ResolveRequest {
            workspace_id: "workspace_01".to_owned(),
            subject_id: "principal_01".to_owned(),
            domain: None,
            entity_id: Some("project_other".to_owned()),
            activity_id: None,
            purpose: "continue-project".to_owned(),
            query: "What is next?".to_owned(),
            maximum_items: 10,
            maximum_bytes: None,
        };
        let grant = ReadGrant {
            client_id: ClientId::new("client_01"),
            workspace_id: WorkspaceId::new("workspace_01"),
            subject_id: PrincipalId::new("principal_01"),
            scopes: vec![ReadScope::Entity {
                id: EntityId::new("project_01"),
            }],
            permissions: Vec::new(),
        };

        assert!(!request_is_within_grant(&request, &grant));

        let global_request = ResolveRequest {
            entity_id: None,
            ..request
        };
        assert!(!request_is_within_grant(&global_request, &grant));
    }

    #[test]
    fn graph_request_scope_is_explicit_and_unambiguous() {
        let mut request = ResolveGraphRequest {
            workspace_id: "workspace_01".to_owned(),
            subject_id: "principal_01".to_owned(),
            node_id: "node_project".to_owned(),
            direction: "outgoing".to_owned(),
            valid_at_epoch_seconds: 100,
            maximum_candidates: Some(20),
            purpose: "continue-project".to_owned(),
            domain: None,
            entity_id: Some("project_01".to_owned()),
            activity_id: None,
        };
        assert!(matches!(
            graph_request_scope(&request),
            Ok(MemoryScope::Entity { id }) if id == EntityId::new("project_01")
        ));

        request.domain = Some("development".to_owned());
        assert!(graph_request_scope(&request).is_err());
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
    fn invitation_only_connection_has_no_memory_or_mutation_authority() {
        let mut store = SqliteStore::open_in_memory().expect("database");
        for principal in ["owner", "guest"] {
            store
                .initialize_personal_workspace(
                    Principal::new(PrincipalId::new(principal)),
                    Workspace::personal(WorkspaceId::new(format!("{principal}-personal"))),
                    Membership::new(
                        WorkspaceId::new(format!("{principal}-personal")),
                        PrincipalId::new(principal),
                        WorkspaceRole::Owner,
                    ),
                )
                .expect("personal identity");
        }
        store
            .initialize_shared_workspace(
                Workspace::shared(WorkspaceId::new("team")),
                Membership::new(
                    WorkspaceId::new("team"),
                    PrincipalId::new("owner"),
                    WorkspaceRole::Owner,
                ),
            )
            .expect("shared workspace");

        let grants = invitation_only_grants(
            &store,
            ClientId::new("api_guest"),
            WorkspaceId::new("team"),
            PrincipalId::new("guest"),
        )
        .expect("unjoined known principal may accept an invitation");
        assert!(grants.read.scopes.is_empty());
        assert!(grants.read.permissions.is_empty());
        assert!(grants.write.scopes.is_empty());
        assert!(grants.write.permissions.is_empty());

        assert!(
            invitation_only_grants(
                &store,
                ClientId::new("api_owner"),
                WorkspaceId::new("team"),
                PrincipalId::new("owner"),
            )
            .is_err()
        );
        assert!(
            invitation_only_grants(
                &store,
                ClientId::new("api_unknown"),
                WorkspaceId::new("team"),
                PrincipalId::new("unknown"),
            )
            .is_err()
        );
        assert_eq!(
            parse_invitation_role("owner"),
            None,
            "invitations must never transfer ownership"
        );
    }
}

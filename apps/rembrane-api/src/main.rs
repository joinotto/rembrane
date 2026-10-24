use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use axum::extract::DefaultBodyLimit;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rembrane_application::{
    ApplicationError, AuthorizeClientCommand, AuthorizeClientService,
    CaptureBookingResearchCommand, CaptureBookingResearchService, CreateTripCommand,
    ResolveContextCommand, ResolveContextService, TripService,
};
use rembrane_config::parse_read_scopes;
use rembrane_contracts::ResolveContextRequest;
use rembrane_crypto_rustcrypto::RustCryptoRecordCipher;
use rembrane_domain::{
    ActivityId, BookingResearch, BookingResearchId, BookingResearchKind, ClientId, ContextPackId,
    DisclosureId, EntityId, EventId, EvidenceId, EvidenceReference, EvidenceSource, MemoryKind,
    MemoryScope, MemoryStatus, PrincipalId, ReadGrant, TravelDateWindow, Trip, WorkspaceId,
    WriteGrant, WritePermission,
};
use rembrane_store_sqlite::SqliteStore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Clone)]
struct AppState {
    inner: Arc<Inner>,
}

struct Inner {
    runtime: Mutex<Runtime>,
    bearer_token: Zeroizing<String>,
}

struct Runtime {
    store: SqliteStore<RustCryptoRecordCipher>,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Problem {
    code: &'static str,
    message: &'static str,
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
        let bearer_token = Zeroizing::new(required_environment("REMBRANE_API_TOKEN")?);
        anyhow::ensure!(!bearer_token.is_empty(), "REMBRANE_API_TOKEN is empty");
        let cipher = RustCryptoRecordCipher::from_environment()
            .context("failed to load workspace cipher")?;
        let read_scopes = parse_read_scopes(
            &std::env::var("REMBRANE_READ_SCOPES").unwrap_or_else(|_| "global".to_owned()),
        )
        .map_err(anyhow::Error::msg)?;
        let store = SqliteStore::open(database)
            .context("failed to open Rembrane database")?
            .with_cipher(cipher);
        let grants = AuthorizeClientService::new(&store)
            .execute(AuthorizeClientCommand {
                client_id,
                workspace_id,
                principal_id,
                requested_read_scopes: read_scopes,
                requested_write_permissions: vec![
                    WritePermission::CreateTrip,
                    WritePermission::CaptureBookingResearch,
                ],
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
                    read_grant: grants.read,
                    write_grant: grants.write,
                    next_id,
                }),
                bearer_token,
            }),
        })
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
    runtime.next_id = runtime.next_id.saturating_add(1);
    let suffix = runtime.next_id;
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
    runtime.next_id = runtime.next_id.saturating_add(1);
    let suffix = runtime.next_id;
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

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
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
    runtime.next_id = runtime.next_id.saturating_add(1);
    let suffix = runtime.next_id;
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

fn request_is_within_grant(request: &ResolveRequest, grant: &ReadGrant) -> bool {
    request
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
        .route("/v1/context/resolve", post(resolve_context))
        .route("/v1/travel/trips", post(create_trip))
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
    use rembrane_domain::{ClientId, EntityId, PrincipalId, ReadGrant, ReadScope, WorkspaceId};

    use super::{ResolveRequest, request_is_within_grant, token_matches};

    #[test]
    fn accepts_only_exact_bearer_token() {
        assert!(token_matches("secret-token", "secret-token"));
        assert!(!token_matches("secret-token", "secret-other"));
        assert!(!token_matches("secret-token", "short"));
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
        };

        assert!(!request_is_within_grant(&request, &grant));
    }
}

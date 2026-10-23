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
    AuthorizeClientCommand, AuthorizeClientService, ResolveContextCommand,
    ResolveContextService,
};
use rembrane_contracts::ResolveContextRequest;
use rembrane_crypto_rustcrypto::RustCryptoRecordCipher;
use rembrane_domain::{
    ActivityId, ClientId, ContextPackId, DisclosureId, EntityId, MemoryKind,
    MemoryScope, MemoryStatus, PrincipalId, ReadGrant, ReadScope, WorkspaceId,
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
        let principal_id =
            PrincipalId::new(required_environment("REMBRANE_PRINCIPAL_ID")?);
        let workspace_id =
            WorkspaceId::new(required_environment("REMBRANE_WORKSPACE_ID")?);
        let client_id =
            ClientId::new(required_environment("REMBRANE_CLIENT_ID")?);
        let bearer_token =
            Zeroizing::new(required_environment("REMBRANE_API_TOKEN")?);
        anyhow::ensure!(!bearer_token.is_empty(), "REMBRANE_API_TOKEN is empty");
        let key_id = required_environment("REMBRANE_WORKSPACE_KEY_ID")?;
        let encoded_key =
            Zeroizing::new(required_environment("REMBRANE_WORKSPACE_KEY_HEX")?);
        let key = decode_key(&encoded_key)?;
        let cipher = RustCryptoRecordCipher::new(key_id, key)
            .context("failed to initialize record cipher")?;
        let store = SqliteStore::open(database)
            .context("failed to open Rembrane database")?
            .with_cipher(cipher);
        let read_grant = AuthorizeClientService::new(&store)
            .execute(AuthorizeClientCommand {
                client_id,
                workspace_id,
                principal_id,
                requested_read_scopes: vec![ReadScope::Global],
                requested_write_permissions: Vec::new(),
            })
            .context("failed to authorize API connection")?
            .read;
        let next_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_nanos();

        Ok(Self {
            inner: Arc::new(Inner {
                runtime: Mutex::new(Runtime {
                    store,
                    read_grant,
                    next_id,
                }),
                bearer_token,
            }),
        })
    }
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
    presented
        .as_bytes()
        .ct_eq(expected.as_bytes())
        .unwrap_u8()
        == 1
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
                        rembrane_domain::EvidenceSource::UserStatement => {
                            "user-statement"
                        }
                        rembrane_domain::EvidenceSource::AgentObservation => {
                            "agent-observation"
                        }
                        rembrane_domain::EvidenceSource::ToolResult => "tool-result",
                        rembrane_domain::EvidenceSource::ImportedRecord => {
                            "imported-record"
                        }
                        rembrane_domain::EvidenceSource::WorkspaceDecision => {
                            "workspace-decision"
                        }
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
            MemoryScope::Activity { id } => {
                Self::Activity { id: id.to_string() }
            }
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

fn decode_key(encoded: &str) -> Result<[u8; 32]> {
    anyhow::ensure!(
        encoded.len() == 64 && encoded.is_ascii(),
        "REMBRANE_WORKSPACE_KEY_HEX must contain 64 hexadecimal characters"
    );
    let mut key = [0_u8; 32];
    for (index, output) in key.iter_mut().enumerate() {
        let offset = index.saturating_mul(2);
        *output = u8::from_str_radix(&encoded[offset..offset + 2], 16)
            .context("REMBRANE_WORKSPACE_KEY_HEX contains invalid hexadecimal")?;
    }
    Ok(key)
}

#[tokio::main]
async fn main() -> Result<()> {
    let state = AppState::from_environment()?;
    let configured_address = std::env::var("REMBRANE_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8787".to_owned());
    let address = configured_address
        .parse::<std::net::SocketAddr>()
        .with_context(|| format!("invalid listen address {configured_address}"))?;
    let allow_non_loopback =
        std::env::var("REMBRANE_ALLOW_NON_LOOPBACK").as_deref() == Ok("1");
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
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state);
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::token_matches;

    #[test]
    fn accepts_only_exact_bearer_token() {
        assert!(token_matches("secret-token", "secret-token"));
        assert!(!token_matches("secret-token", "secret-other"));
        assert!(!token_matches("secret-token", "short"));
    }
}

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rembrane_application::{
    AuthorizeClientCommand, AuthorizeClientService, ResolveContextCommand,
    ResolveContextService,
};
use rembrane_contracts::ResolveContextRequest;
use rembrane_crypto_rustcrypto::RustCryptoRecordCipher;
use rembrane_domain::{
    ClientId, ContextPackId, DisclosureId, PrincipalId, ReadGrant, ReadScope,
    WorkspaceId,
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

struct State {
    store: SqliteStore<RustCryptoRecordCipher>,
    read_grant: ReadGrant,
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
            .context("failed to authorize MCP connection")?
            .read;
        let next_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_nanos();

        Ok(Self {
            state: Arc::new(Mutex::new(State {
                store,
                read_grant,
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
        if !(1..=100).contains(&maximum_items) {
            return Err(McpError::invalid_params(
                "maximumItems must be between 1 and 100",
                None,
            ));
        }

        let mut state = self
            .state
            .lock()
            .map_err(|_| McpError::internal_error("state lock failed", None))?;
        state.next_id = state.next_id.saturating_add(1);
        let suffix = state.next_id;
        let read_grant = state.read_grant.clone();
        let principal_id = read_grant.subject_id.clone();
        let workspace_id = read_grant.workspace_id.clone();
        let response = ResolveContextService::new(&mut state.store)
            .execute(ResolveContextCommand {
                request: ResolveContextRequest {
                    workspace_id: workspace_id.clone(),
                    principal_id: principal_id.clone(),
                    domain: None,
                    entity_id: None,
                    activity_id: None,
                    purpose: parameters.purpose,
                    query: parameters.query,
                    maximum_items,
                },
                grant: read_grant,
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
}

fn required_environment(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let server = RembraneMcp::from_environment()?;
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rembrane_application::{
    MembershipRepository, ResolveContextCommand, ResolveContextService,
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
use zeroize::Zeroizing;

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
    principal_id: PrincipalId,
    workspace_id: WorkspaceId,
    client_id: ClientId,
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
        let key_id = required_environment("REMBRANE_WORKSPACE_KEY_ID")?;
        let encoded_key =
            Zeroizing::new(required_environment("REMBRANE_WORKSPACE_KEY_HEX")?);
        let key = decode_key(&encoded_key)?;
        let cipher = RustCryptoRecordCipher::new(key_id, key)
            .context("failed to initialize record cipher")?;
        let store = SqliteStore::open(database)
            .context("failed to open Rembrane database")?
            .with_cipher(cipher);
        let membership = store
            .find_membership(&workspace_id, &principal_id)
            .context("failed to verify MCP connection membership")?
            .context("MCP connection principal is not a workspace member")?;
        anyhow::ensure!(
            membership.is_active(),
            "MCP connection membership is not active"
        );
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
        let principal_id = state.principal_id.clone();
        let workspace_id = state.workspace_id.clone();
        let client_id = state.client_id.clone();
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
                grant: ReadGrant {
                    client_id,
                    workspace_id,
                    subject_id: principal_id,
                    scopes: vec![ReadScope::Global],
                },
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
    let server = RembraneMcp::from_environment()?;
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

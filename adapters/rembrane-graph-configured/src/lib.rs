//! Deployment-selected graph provider composition.

use std::time::{SystemTime, UNIX_EPOCH};

use rembrane_domain::{
    KnowledgeEdge, KnowledgeEdgeId, KnowledgeNode, KnowledgeNodeId, WorkspaceId,
};
use rembrane_graph_graphiti::GraphitiProvider;
use rembrane_graph_graphiti_http::HttpGraphitiTransport;
use rembrane_graph_native::NativeGraphProvider;
use rembrane_provider_sdk::{
    CandidateKnowledgeEdge, GraphNeighbourQuery, KnowledgeGraphProvider, ProviderError,
    ProviderManifest,
};

pub enum ConfiguredGraphProvider {
    Native(NativeGraphProvider),
    Graphiti(GraphitiProvider<HttpGraphitiTransport>),
}

impl ConfiguredGraphProvider {
    pub fn from_environment() -> Result<Self, ProviderError> {
        match std::env::var("REMBRANE_GRAPH_PROVIDER")
            .as_deref()
            .unwrap_or("native")
        {
            "native" => Ok(Self::Native(NativeGraphProvider::new())),
            "graphiti" => {
                if std::env::var("REMBRANE_GRAPH_PROVIDER_ALLOW_PLAINTEXT").as_deref() != Ok("true")
                {
                    return Err(ProviderError::InvalidConfiguration(
                        "Graphiti requires REMBRANE_GRAPH_PROVIDER_ALLOW_PLAINTEXT=true".to_owned(),
                    ));
                }
                let endpoint = required_environment("REMBRANE_GRAPHITI_BASE_URL")?;
                let token = required_environment("REMBRANE_GRAPHITI_BEARER_TOKEN")?;
                let transport = HttpGraphitiTransport::new(&endpoint, token)?;
                Ok(Self::Graphiti(GraphitiProvider::connect(
                    transport,
                    request_prefix()?,
                    true,
                )?))
            }
            _ => Err(ProviderError::InvalidConfiguration(
                "REMBRANE_GRAPH_PROVIDER must be native or graphiti".to_owned(),
            )),
        }
    }
}

impl KnowledgeGraphProvider for ConfiguredGraphProvider {
    fn manifest(&self) -> ProviderManifest {
        match self {
            Self::Native(provider) => provider.manifest(),
            Self::Graphiti(provider) => provider.manifest(),
        }
    }

    fn upsert_node(&mut self, node: KnowledgeNode) -> Result<(), ProviderError> {
        match self {
            Self::Native(provider) => provider.upsert_node(node),
            Self::Graphiti(provider) => provider.upsert_node(node),
        }
    }

    fn upsert_edge(&mut self, edge: KnowledgeEdge) -> Result<(), ProviderError> {
        match self {
            Self::Native(provider) => provider.upsert_edge(edge),
            Self::Graphiti(provider) => provider.upsert_edge(edge),
        }
    }

    fn neighbours(
        &self,
        query: &GraphNeighbourQuery,
    ) -> Result<Vec<CandidateKnowledgeEdge>, ProviderError> {
        match self {
            Self::Native(provider) => provider.neighbours(query),
            Self::Graphiti(provider) => provider.neighbours(query),
        }
    }

    fn delete_node(
        &mut self,
        workspace_id: &WorkspaceId,
        node_id: &KnowledgeNodeId,
        through_version: u64,
    ) -> Result<(), ProviderError> {
        match self {
            Self::Native(provider) => provider.delete_node(workspace_id, node_id, through_version),
            Self::Graphiti(provider) => {
                provider.delete_node(workspace_id, node_id, through_version)
            }
        }
    }

    fn delete_edge(
        &mut self,
        workspace_id: &WorkspaceId,
        edge_id: &KnowledgeEdgeId,
        through_version: u64,
    ) -> Result<(), ProviderError> {
        match self {
            Self::Native(provider) => provider.delete_edge(workspace_id, edge_id, through_version),
            Self::Graphiti(provider) => {
                provider.delete_edge(workspace_id, edge_id, through_version)
            }
        }
    }
}

fn required_environment(name: &str) -> Result<String, ProviderError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ProviderError::InvalidConfiguration(format!("{name} is required for Graphiti"))
        })
}

fn request_prefix() -> Result<String, ProviderError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProviderError::Unavailable)?
        .as_nanos();
    Ok(format!("graph-worker-{}-{now}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use rembrane_provider_sdk::KnowledgeGraphProvider;

    use super::{ConfiguredGraphProvider, request_prefix};

    #[test]
    fn native_provider_is_a_complete_default_without_configuration() {
        let provider =
            ConfiguredGraphProvider::Native(rembrane_graph_native::NativeGraphProvider::new());
        assert_eq!(provider.manifest().id, "rembrane.graph.native");
    }

    #[test]
    fn generated_request_prefix_is_safe_and_bounded() {
        let prefix = request_prefix().expect("system time should be available");
        assert!(prefix.starts_with("graph-worker-"));
        assert!(prefix.len() <= 96);
        assert!(
            prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
    }
}

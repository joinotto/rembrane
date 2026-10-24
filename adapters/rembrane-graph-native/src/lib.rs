//! Deterministic dependency-free temporal graph provider.
//!
//! This is the inspectable local baseline and conformance reference for
//! Graphiti and future graph adapters.

use rembrane_domain::{
    KnowledgeEdge, KnowledgeEdgeId, KnowledgeNode, KnowledgeNodeId, WorkspaceId,
};
use rembrane_provider_sdk::{
    CURRENT_PROVIDER_PROTOCOL, CandidateKnowledgeEdge, Capability, GraphDirection,
    GraphNeighbourQuery, KnowledgeGraphProvider, ProviderError, ProviderLimits, ProviderManifest,
    validate_graph_candidates,
};

const MAXIMUM_CANDIDATES: usize = 100;

#[derive(Debug, Default)]
pub struct NativeGraphProvider {
    nodes: Vec<KnowledgeNode>,
    edges: Vec<KnowledgeEdge>,
}

impl NativeGraphProvider {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl KnowledgeGraphProvider for NativeGraphProvider {
    fn manifest(&self) -> ProviderManifest {
        ProviderManifest {
            id: "rembrane.graph.native".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol_version: CURRENT_PROVIDER_PROTOCOL,
            capabilities: vec![
                Capability::GraphUpsert,
                Capability::GraphTraverse,
                Capability::Delete,
                Capability::WorkspaceFilter,
                Capability::VersionedRecords,
                Capability::HealthCheck,
            ],
            plaintext_processing: true,
            limits: ProviderLimits {
                maximum_batch_items: 1,
                maximum_content_bytes: 262_144,
                maximum_candidates: MAXIMUM_CANDIDATES,
            },
        }
    }

    fn upsert_node(&mut self, node: KnowledgeNode) -> Result<(), ProviderError> {
        reject_stale_node(&self.nodes, &node)?;
        self.nodes.retain(|stored| {
            stored.workspace_id() != node.workspace_id() || stored.id() != node.id()
        });
        self.nodes.push(node);
        Ok(())
    }

    fn upsert_edge(&mut self, edge: KnowledgeEdge) -> Result<(), ProviderError> {
        let endpoint_exists = |node_id: &KnowledgeNodeId| {
            self.nodes
                .iter()
                .any(|node| node.workspace_id() == edge.workspace_id() && node.id() == node_id)
        };
        if !endpoint_exists(edge.source_id()) || !endpoint_exists(edge.target_id()) {
            return Err(ProviderError::Rejected(
                "graph edge endpoints must exist in the same workspace".to_owned(),
            ));
        }
        reject_stale_edge(&self.edges, &edge)?;
        self.edges.retain(|stored| {
            stored.workspace_id() != edge.workspace_id() || stored.id() != edge.id()
        });
        self.edges.push(edge);
        Ok(())
    }

    fn neighbours(
        &self,
        query: &GraphNeighbourQuery,
    ) -> Result<Vec<CandidateKnowledgeEdge>, ProviderError> {
        query.validate()?;
        if query.maximum_candidates > MAXIMUM_CANDIDATES {
            return Err(ProviderError::Rejected(
                "graph candidate limit exceeds provider capacity".to_owned(),
            ));
        }
        let candidates: Vec<_> = self
            .edges
            .iter()
            .filter(|edge| edge.workspace_id() == &query.workspace_id)
            .filter(|edge| edge.validity().contains(query.valid_at_epoch_seconds))
            .filter(|edge| match query.direction {
                GraphDirection::Incoming => edge.target_id() == &query.node_id,
                GraphDirection::Outgoing => edge.source_id() == &query.node_id,
                GraphDirection::Both => {
                    edge.source_id() == &query.node_id || edge.target_id() == &query.node_id
                }
            })
            .take(query.maximum_candidates)
            .map(|edge| CandidateKnowledgeEdge {
                edge_id: edge.id().clone(),
                version: edge.version(),
            })
            .collect();
        validate_graph_candidates(&candidates, query.maximum_candidates)?;
        Ok(candidates)
    }

    fn delete_node(
        &mut self,
        workspace_id: &WorkspaceId,
        node_id: &KnowledgeNodeId,
        through_version: u64,
    ) -> Result<(), ProviderError> {
        self.nodes.retain(|node| {
            node.workspace_id() != workspace_id
                || node.id() != node_id
                || node.version() > through_version
        });
        self.edges.retain(|edge| {
            edge.workspace_id() != workspace_id
                || (edge.source_id() != node_id && edge.target_id() != node_id)
        });
        Ok(())
    }

    fn delete_edge(
        &mut self,
        workspace_id: &WorkspaceId,
        edge_id: &KnowledgeEdgeId,
        through_version: u64,
    ) -> Result<(), ProviderError> {
        self.edges.retain(|edge| {
            edge.workspace_id() != workspace_id
                || edge.id() != edge_id
                || edge.version() > through_version
        });
        Ok(())
    }
}

fn reject_stale_node(
    nodes: &[KnowledgeNode],
    candidate: &KnowledgeNode,
) -> Result<(), ProviderError> {
    if nodes.iter().any(|stored| {
        stored.workspace_id() == candidate.workspace_id()
            && stored.id() == candidate.id()
            && stored.version() > candidate.version()
    }) {
        return Err(ProviderError::Rejected(
            "stale graph node version cannot replace a newer projection".to_owned(),
        ));
    }
    Ok(())
}

fn reject_stale_edge(
    edges: &[KnowledgeEdge],
    candidate: &KnowledgeEdge,
) -> Result<(), ProviderError> {
    if edges.iter().any(|stored| {
        stored.workspace_id() == candidate.workspace_id()
            && stored.id() == candidate.id()
            && stored.version() > candidate.version()
    }) {
        return Err(ProviderError::Rejected(
            "stale graph edge version cannot replace a newer projection".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rembrane_provider_sdk::verify_knowledge_graph_provider;

    use super::NativeGraphProvider;

    #[test]
    fn passes_shared_graph_provider_conformance() {
        verify_knowledge_graph_provider(&mut NativeGraphProvider::new(), "native")
            .expect("native graph provider should conform");
    }
}

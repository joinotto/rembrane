use std::fmt;

use rembrane_domain::{
    KnowledgeEdge, KnowledgeEdgeId, KnowledgeNode, KnowledgeNodeId, WorkspaceId,
};

use crate::{ProviderError, ProviderManifest};

pub const MAX_GRAPH_CANDIDATES: usize = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphDirection {
    Incoming,
    Outgoing,
    Both,
}

#[derive(Clone, Eq, PartialEq)]
pub struct GraphNeighbourQuery {
    pub workspace_id: WorkspaceId,
    pub node_id: KnowledgeNodeId,
    pub direction: GraphDirection,
    pub valid_at_epoch_seconds: u64,
    pub maximum_candidates: usize,
}

impl fmt::Debug for GraphNeighbourQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GraphNeighbourQuery")
            .field("workspace_id", &"<redacted>")
            .field("node_id", &"<redacted>")
            .field("direction", &self.direction)
            .field("valid_at_epoch_seconds", &"<redacted>")
            .field("maximum_candidates", &self.maximum_candidates)
            .finish()
    }
}

impl GraphNeighbourQuery {
    pub fn validate(&self) -> Result<(), ProviderError> {
        if self.workspace_id.as_str().is_empty()
            || self.node_id.as_str().is_empty()
            || self.valid_at_epoch_seconds == 0
            || self.maximum_candidates == 0
            || self.maximum_candidates > MAX_GRAPH_CANDIDATES
        {
            return Err(ProviderError::InvalidConfiguration(
                "graph neighbour query is outside canonical bounds".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CandidateKnowledgeEdge {
    pub edge_id: KnowledgeEdgeId,
    pub version: u64,
}

impl fmt::Debug for CandidateKnowledgeEdge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateKnowledgeEdge")
            .field("edge_id", &"<redacted>")
            .field("version", &self.version)
            .finish()
    }
}

pub fn validate_graph_candidates(
    candidates: &[CandidateKnowledgeEdge],
    requested_limit: usize,
) -> Result<(), ProviderError> {
    if requested_limit == 0
        || requested_limit > MAX_GRAPH_CANDIDATES
        || candidates.len() > requested_limit
        || candidates
            .iter()
            .any(|candidate| candidate.edge_id.as_str().is_empty() || candidate.version == 0)
        || candidates.iter().enumerate().any(|(index, candidate)| {
            candidates[..index]
                .iter()
                .any(|seen| seen.edge_id == candidate.edge_id)
        })
    {
        return Err(ProviderError::Rejected(
            "graph provider returned invalid candidates".to_owned(),
        ));
    }
    Ok(())
}

/// Replaceable derived temporal graph engine.
///
/// The canonical core supplies the workspace namespace and must re-authorize
/// every returned identifier before disclosing graph-backed context.
pub trait KnowledgeGraphProvider {
    fn manifest(&self) -> ProviderManifest;

    fn upsert_node(&mut self, node: KnowledgeNode) -> Result<(), ProviderError>;

    fn upsert_edge(&mut self, edge: KnowledgeEdge) -> Result<(), ProviderError>;

    fn neighbours(
        &self,
        query: &GraphNeighbourQuery,
    ) -> Result<Vec<CandidateKnowledgeEdge>, ProviderError>;

    fn delete_node(
        &mut self,
        workspace_id: &WorkspaceId,
        node_id: &KnowledgeNodeId,
        through_version: u64,
    ) -> Result<(), ProviderError>;

    fn delete_edge(
        &mut self,
        workspace_id: &WorkspaceId,
        edge_id: &KnowledgeEdgeId,
        through_version: u64,
    ) -> Result<(), ProviderError>;
}

#[cfg(test)]
mod tests {
    use rembrane_domain::{KnowledgeEdgeId, KnowledgeNodeId, WorkspaceId};

    use super::{
        CandidateKnowledgeEdge, GraphDirection, GraphNeighbourQuery, MAX_GRAPH_CANDIDATES,
        validate_graph_candidates,
    };

    #[test]
    fn bounds_queries_and_rejects_duplicate_candidates() {
        let query = GraphNeighbourQuery {
            workspace_id: WorkspaceId::new("workspace_01"),
            node_id: KnowledgeNodeId::new("node_01"),
            direction: GraphDirection::Both,
            valid_at_epoch_seconds: 100,
            maximum_candidates: MAX_GRAPH_CANDIDATES,
        };
        query.validate().expect("query should validate");

        let candidate = CandidateKnowledgeEdge {
            edge_id: KnowledgeEdgeId::new("edge_01"),
            version: 1,
        };
        assert!(validate_graph_candidates(std::slice::from_ref(&candidate), 1).is_ok());
        assert!(validate_graph_candidates(&[candidate.clone(), candidate], 2).is_err());
    }

    #[test]
    fn graph_diagnostics_redact_tenant_resource_and_timeline_identities() {
        let query = GraphNeighbourQuery {
            workspace_id: WorkspaceId::new("private_workspace"),
            node_id: KnowledgeNodeId::new("private_node"),
            direction: GraphDirection::Incoming,
            valid_at_epoch_seconds: 1_900_000_001,
            maximum_candidates: 25,
        };
        let candidate = CandidateKnowledgeEdge {
            edge_id: KnowledgeEdgeId::new("private_edge"),
            version: 4,
        };

        let diagnostic = format!("{query:?} {candidate:?}");

        for private_value in [
            "private_workspace",
            "private_node",
            "1900000001",
            "private_edge",
        ] {
            assert!(!diagnostic.contains(private_value));
        }
        assert!(diagnostic.contains("direction: Incoming"));
        assert!(diagnostic.contains("maximum_candidates: 25"));
        assert!(diagnostic.contains("version: 4"));
    }
}

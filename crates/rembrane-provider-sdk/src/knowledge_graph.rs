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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphNeighbourQuery {
    pub workspace_id: WorkspaceId,
    pub node_id: KnowledgeNodeId,
    pub direction: GraphDirection,
    pub valid_at_epoch_seconds: u64,
    pub maximum_candidates: usize,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateKnowledgeEdge {
    pub edge_id: KnowledgeEdgeId,
    pub version: u64,
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
}

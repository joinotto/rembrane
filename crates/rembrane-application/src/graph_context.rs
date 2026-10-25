use rembrane_domain::{KnowledgeEdge, KnowledgeNodeId};
use rembrane_provider_sdk::{
    CURRENT_PROVIDER_PROTOCOL, Capability, GraphDirection, GraphNeighbourQuery,
    KnowledgeGraphProvider, ProviderPolicy, validate_graph_candidates,
};

use crate::{ApplicationError, KnowledgeGraphRepository};

/// Resolves graph-provider candidates only after exact canonical tenant,
/// version, endpoint, direction, and temporal reauthorization.
pub struct GraphContextService<'service, Repository, Provider> {
    repository: &'service Repository,
    provider: &'service Provider,
}

impl<'service, Repository, Provider> GraphContextService<'service, Repository, Provider>
where
    Repository: KnowledgeGraphRepository,
    Provider: KnowledgeGraphProvider,
{
    #[must_use]
    pub const fn new(repository: &'service Repository, provider: &'service Provider) -> Self {
        Self {
            repository,
            provider,
        }
    }

    pub fn execute(
        &self,
        query: GraphNeighbourQuery,
    ) -> Result<Vec<KnowledgeEdge>, ApplicationError> {
        query
            .validate()
            .map_err(|_| ApplicationError::Validation("invalid graph context query".to_owned()))?;
        let manifest = self.provider.manifest();
        ProviderPolicy {
            minimum_protocol_version: CURRENT_PROVIDER_PROTOCOL,
            required_capabilities: vec![
                Capability::GraphTraverse,
                Capability::WorkspaceFilter,
                Capability::VersionedRecords,
            ],
            allow_plaintext_processing: true,
        }
        .validate(&manifest)
        .map_err(|_| {
            ApplicationError::Validation(
                "provider does not satisfy graph context requirements".to_owned(),
            )
        })?;
        let candidate_limit = query
            .maximum_candidates
            .min(manifest.limits.maximum_candidates);
        if candidate_limit == 0 {
            return Err(ApplicationError::Validation(
                "provider graph candidate limit is invalid".to_owned(),
            ));
        }
        let provider_query = GraphNeighbourQuery {
            maximum_candidates: candidate_limit,
            ..query
        };
        let candidates = self
            .provider
            .neighbours(&provider_query)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        validate_graph_candidates(&candidates, candidate_limit)
            .map_err(|_| ApplicationError::StorageUnavailable)?;

        let mut edges = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let Some(edge) = self
                .repository
                .find_knowledge_edge(&provider_query.workspace_id, &candidate.edge_id)?
            else {
                continue;
            };
            if edge.version() == candidate.version
                && edge
                    .validity()
                    .contains(provider_query.valid_at_epoch_seconds)
                && matches_direction(&edge, &provider_query.node_id, provider_query.direction)
            {
                edges.push(edge);
            }
        }
        Ok(edges)
    }
}

fn matches_direction(
    edge: &KnowledgeEdge,
    node_id: &KnowledgeNodeId,
    direction: GraphDirection,
) -> bool {
    match direction {
        GraphDirection::Incoming => edge.target_id() == node_id,
        GraphDirection::Outgoing => edge.source_id() == node_id,
        GraphDirection::Both => edge.source_id() == node_id || edge.target_id() == node_id,
    }
}

#[cfg(test)]
mod tests {
    use rembrane_domain::{
        EvidenceId, EvidenceReference, EvidenceSource, KnowledgeEdge, KnowledgeEdgeId,
        KnowledgeNode, KnowledgeNodeId, KnowledgeRelationType, TemporalValidity, WorkspaceId,
    };
    use rembrane_provider_sdk::{
        CURRENT_PROVIDER_PROTOCOL, CandidateKnowledgeEdge, Capability, GraphDirection,
        GraphNeighbourQuery, KnowledgeGraphProvider, ProviderError, ProviderLimits,
        ProviderManifest,
    };

    use crate::{ApplicationError, KnowledgeDirection, KnowledgeGraphRepository};

    use super::GraphContextService;

    struct Repository {
        edges: Vec<KnowledgeEdge>,
    }

    impl KnowledgeGraphRepository for Repository {
        fn find_knowledge_node(
            &self,
            _workspace_id: &WorkspaceId,
            _node_id: &KnowledgeNodeId,
        ) -> Result<Option<KnowledgeNode>, ApplicationError> {
            Ok(None)
        }

        fn find_knowledge_edge(
            &self,
            workspace_id: &WorkspaceId,
            edge_id: &KnowledgeEdgeId,
        ) -> Result<Option<KnowledgeEdge>, ApplicationError> {
            Ok(self
                .edges
                .iter()
                .find(|edge| edge.workspace_id() == workspace_id && edge.id() == edge_id)
                .cloned())
        }

        fn list_neighbour_edges(
            &self,
            _workspace_id: &WorkspaceId,
            _node_id: &KnowledgeNodeId,
            _direction: KnowledgeDirection,
            _valid_at_epoch_seconds: u64,
            _limit: usize,
        ) -> Result<Vec<KnowledgeEdge>, ApplicationError> {
            Ok(Vec::new())
        }
    }

    struct Provider {
        candidates: Vec<CandidateKnowledgeEdge>,
    }

    impl KnowledgeGraphProvider for Provider {
        fn manifest(&self) -> ProviderManifest {
            ProviderManifest {
                id: "fixture.graph".to_owned(),
                version: "1".to_owned(),
                protocol_version: CURRENT_PROVIDER_PROTOCOL,
                capabilities: vec![
                    Capability::GraphUpsert,
                    Capability::GraphTraverse,
                    Capability::Delete,
                    Capability::WorkspaceFilter,
                    Capability::VersionedRecords,
                ],
                plaintext_processing: true,
                limits: ProviderLimits {
                    maximum_batch_items: 1,
                    maximum_content_bytes: 1024,
                    maximum_candidates: 10,
                },
            }
        }

        fn upsert_node(&mut self, _node: KnowledgeNode) -> Result<(), ProviderError> {
            Ok(())
        }

        fn upsert_edge(&mut self, _edge: KnowledgeEdge) -> Result<(), ProviderError> {
            Ok(())
        }

        fn neighbours(
            &self,
            _query: &GraphNeighbourQuery,
        ) -> Result<Vec<CandidateKnowledgeEdge>, ProviderError> {
            Ok(self.candidates.clone())
        }

        fn delete_node(
            &mut self,
            _workspace_id: &WorkspaceId,
            _node_id: &KnowledgeNodeId,
            _through_version: u64,
        ) -> Result<(), ProviderError> {
            Ok(())
        }

        fn delete_edge(
            &mut self,
            _workspace_id: &WorkspaceId,
            _edge_id: &KnowledgeEdgeId,
            _through_version: u64,
        ) -> Result<(), ProviderError> {
            Ok(())
        }
    }

    fn edge(id: &str, workspace: &str, source: &str, target: &str, version: u64) -> KnowledgeEdge {
        KnowledgeEdge::new(
            KnowledgeEdgeId::new(id),
            WorkspaceId::new(workspace),
            KnowledgeNodeId::new(source),
            KnowledgeNodeId::new(target),
            KnowledgeRelationType::new("uses").expect("relation"),
            vec![EvidenceReference::new(
                EvidenceId::new(format!("evidence_{id}")),
                EvidenceSource::ImportedRecord,
            )],
            TemporalValidity::new(100, Some(200), 100).expect("validity"),
            version,
            None,
        )
        .expect("edge")
    }

    #[test]
    fn returns_only_exact_canonical_neighbours() {
        let repository = Repository {
            edges: vec![
                edge("valid", "workspace_01", "project", "rust", 2),
                edge("wrong_direction", "workspace_01", "rust", "project", 1),
                edge("other_workspace", "workspace_02", "project", "secret", 1),
            ],
        };
        let provider = Provider {
            candidates: vec![
                CandidateKnowledgeEdge {
                    edge_id: KnowledgeEdgeId::new("valid"),
                    version: 2,
                },
                CandidateKnowledgeEdge {
                    edge_id: KnowledgeEdgeId::new("wrong_direction"),
                    version: 1,
                },
                CandidateKnowledgeEdge {
                    edge_id: KnowledgeEdgeId::new("other_workspace"),
                    version: 1,
                },
                CandidateKnowledgeEdge {
                    edge_id: KnowledgeEdgeId::new("missing"),
                    version: 1,
                },
            ],
        };

        let edges = GraphContextService::new(&repository, &provider)
            .execute(GraphNeighbourQuery {
                workspace_id: WorkspaceId::new("workspace_01"),
                node_id: KnowledgeNodeId::new("project"),
                direction: GraphDirection::Outgoing,
                valid_at_epoch_seconds: 150,
                maximum_candidates: 10,
            })
            .expect("graph context");

        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].id().as_str(), "valid");
    }

    #[test]
    fn filters_stale_and_temporally_invalid_candidates() {
        let repository = Repository {
            edges: vec![
                edge("stale", "workspace_01", "project", "rust", 2),
                edge("expired", "workspace_01", "project", "old", 1),
            ],
        };
        let provider = Provider {
            candidates: vec![
                CandidateKnowledgeEdge {
                    edge_id: KnowledgeEdgeId::new("stale"),
                    version: 1,
                },
                CandidateKnowledgeEdge {
                    edge_id: KnowledgeEdgeId::new("expired"),
                    version: 1,
                },
            ],
        };

        let edges = GraphContextService::new(&repository, &provider)
            .execute(GraphNeighbourQuery {
                workspace_id: WorkspaceId::new("workspace_01"),
                node_id: KnowledgeNodeId::new("project"),
                direction: GraphDirection::Both,
                valid_at_epoch_seconds: 250,
                maximum_candidates: 10,
            })
            .expect("graph context");

        assert!(edges.is_empty());
    }
}

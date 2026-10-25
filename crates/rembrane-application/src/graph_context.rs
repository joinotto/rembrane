use rembrane_contracts::{ResolveGraphContextRequest, ResolveGraphContextResponse};
use rembrane_domain::{
    DisclosedKnowledgeEdge, DisclosureId, GraphDisclosureDirection, GraphDisclosureReceipt,
    KnowledgeEdge, KnowledgeNodeId, MemoryScope, ReadGrant,
};
use rembrane_provider_sdk::{
    CURRENT_PROVIDER_PROTOCOL, Capability, GraphDirection, GraphNeighbourQuery,
    KnowledgeGraphProvider, ProviderPolicy, validate_graph_candidates,
};

use crate::{ApplicationError, GraphContextRepository};

pub struct ResolveGraphContextCommand {
    pub query: GraphNeighbourQuery,
    pub grant: ReadGrant,
    pub scope: MemoryScope,
    pub disclosure_id: DisclosureId,
    pub purpose: String,
}

/// Resolves graph-provider candidates only after exact canonical tenant,
/// version, endpoint, direction, and temporal reauthorization.
pub struct GraphContextService<'service, Repository, Provider> {
    repository: &'service mut Repository,
    provider: &'service Provider,
}

impl<'service, Repository, Provider> GraphContextService<'service, Repository, Provider>
where
    Repository: GraphContextRepository,
    Provider: KnowledgeGraphProvider,
{
    #[must_use]
    pub const fn new(repository: &'service mut Repository, provider: &'service Provider) -> Self {
        Self {
            repository,
            provider,
        }
    }

    pub fn execute(
        &mut self,
        command: ResolveGraphContextCommand,
    ) -> Result<Vec<KnowledgeEdge>, ApplicationError> {
        if command.grant.workspace_id != command.query.workspace_id
            || !command.grant.allows(&command.scope)
        {
            return Err(ApplicationError::AccessDenied);
        }
        if command.purpose.trim().is_empty() {
            return Err(ApplicationError::Validation(
                "graph disclosure purpose must not be empty".to_owned(),
            ));
        }
        let query = command.query;
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
        self.repository
            .append_graph_disclosure(GraphDisclosureReceipt {
                id: command.disclosure_id,
                workspace_id: provider_query.workspace_id,
                subject_id: command.grant.subject_id,
                client_id: command.grant.client_id,
                purpose: command.purpose,
                node_id: provider_query.node_id,
                direction: disclosure_direction(provider_query.direction),
                valid_at_epoch_seconds: provider_query.valid_at_epoch_seconds,
                edges: edges
                    .iter()
                    .map(|edge| DisclosedKnowledgeEdge {
                        id: edge.id().clone(),
                        version: edge.version(),
                    })
                    .collect(),
            })?;
        Ok(edges)
    }

    pub fn execute_request(
        &mut self,
        request: ResolveGraphContextRequest,
        grant: ReadGrant,
        disclosure_id: DisclosureId,
    ) -> Result<ResolveGraphContextResponse, ApplicationError> {
        if request.principal_id != grant.subject_id {
            return Err(ApplicationError::AccessDenied);
        }
        let response_disclosure_id = disclosure_id.clone();
        let edges = self.execute(ResolveGraphContextCommand {
            query: GraphNeighbourQuery {
                workspace_id: request.workspace_id,
                node_id: request.node_id,
                direction: provider_direction(request.direction),
                valid_at_epoch_seconds: request.valid_at_epoch_seconds,
                maximum_candidates: request.maximum_candidates,
            },
            grant,
            scope: request.scope,
            disclosure_id,
            purpose: request.purpose,
        })?;
        Ok(ResolveGraphContextResponse {
            edges,
            disclosure_id: response_disclosure_id,
        })
    }
}

const fn provider_direction(direction: GraphDisclosureDirection) -> GraphDirection {
    match direction {
        GraphDisclosureDirection::Incoming => GraphDirection::Incoming,
        GraphDisclosureDirection::Outgoing => GraphDirection::Outgoing,
        GraphDisclosureDirection::Both => GraphDirection::Both,
    }
}

const fn disclosure_direction(direction: GraphDirection) -> GraphDisclosureDirection {
    match direction {
        GraphDirection::Incoming => GraphDisclosureDirection::Incoming,
        GraphDirection::Outgoing => GraphDisclosureDirection::Outgoing,
        GraphDirection::Both => GraphDisclosureDirection::Both,
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
    use rembrane_contracts::ResolveGraphContextRequest;
    use rembrane_domain::{
        ClientId, DisclosureId, EvidenceId, EvidenceReference, EvidenceSource,
        GraphDisclosureDirection, GraphDisclosureReceipt, KnowledgeEdge, KnowledgeEdgeId,
        KnowledgeNode, KnowledgeNodeId, KnowledgeRelationType, MemoryScope, PrincipalId, ReadGrant,
        ReadScope, TemporalValidity, WorkspaceId,
    };
    use rembrane_provider_sdk::{
        CURRENT_PROVIDER_PROTOCOL, CandidateKnowledgeEdge, Capability, GraphDirection,
        GraphNeighbourQuery, KnowledgeGraphProvider, ProviderError, ProviderLimits,
        ProviderManifest,
    };

    use crate::{
        ApplicationError, GraphDisclosureRepository, KnowledgeDirection, KnowledgeGraphRepository,
    };

    use super::{GraphContextService, ResolveGraphContextCommand};

    struct Repository {
        edges: Vec<KnowledgeEdge>,
        disclosures: Vec<GraphDisclosureReceipt>,
        fail_disclosure: bool,
    }

    impl GraphDisclosureRepository for Repository {
        fn append_graph_disclosure(
            &mut self,
            receipt: GraphDisclosureReceipt,
        ) -> Result<(), ApplicationError> {
            if self.fail_disclosure {
                return Err(ApplicationError::StorageUnavailable);
            }
            self.disclosures.push(receipt);
            Ok(())
        }
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

    fn command(workspace_id: &str, valid_at_epoch_seconds: u64) -> ResolveGraphContextCommand {
        ResolveGraphContextCommand {
            query: GraphNeighbourQuery {
                workspace_id: WorkspaceId::new(workspace_id),
                node_id: KnowledgeNodeId::new("project"),
                direction: GraphDirection::Outgoing,
                valid_at_epoch_seconds,
                maximum_candidates: 10,
            },
            grant: ReadGrant {
                client_id: ClientId::new("client_01"),
                workspace_id: WorkspaceId::new(workspace_id),
                subject_id: PrincipalId::new("principal_01"),
                scopes: vec![ReadScope::Global],
                permissions: Vec::new(),
            },
            scope: MemoryScope::Global,
            disclosure_id: DisclosureId::new("disclosure_01"),
            purpose: "assistant_graph_context".to_owned(),
        }
    }

    #[test]
    fn returns_only_exact_canonical_neighbours() {
        let repository = Repository {
            edges: vec![
                edge("valid", "workspace_01", "project", "rust", 2),
                edge("wrong_direction", "workspace_01", "rust", "project", 1),
                edge("other_workspace", "workspace_02", "project", "secret", 1),
            ],
            disclosures: Vec::new(),
            fail_disclosure: false,
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

        let mut repository = repository;
        let edges = GraphContextService::new(&mut repository, &provider)
            .execute(command("workspace_01", 150))
            .expect("graph context");

        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].id().as_str(), "valid");
        assert_eq!(repository.disclosures.len(), 1);
        assert_eq!(repository.disclosures[0].edges.len(), 1);
        assert_eq!(repository.disclosures[0].edges[0].id.as_str(), "valid");
        assert_eq!(repository.disclosures[0].edges[0].version, 2);
        assert_eq!(
            repository.disclosures[0].direction,
            GraphDisclosureDirection::Outgoing
        );
    }

    #[test]
    fn filters_stale_and_temporally_invalid_candidates() {
        let repository = Repository {
            edges: vec![
                edge("stale", "workspace_01", "project", "rust", 2),
                edge("expired", "workspace_01", "project", "old", 1),
            ],
            disclosures: Vec::new(),
            fail_disclosure: false,
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

        let mut command = command("workspace_01", 250);
        command.query.direction = GraphDirection::Both;
        let mut repository = repository;
        let edges = GraphContextService::new(&mut repository, &provider)
            .execute(command)
            .expect("graph context");

        assert!(edges.is_empty());
        assert_eq!(repository.disclosures.len(), 1);
        assert!(repository.disclosures[0].edges.is_empty());
    }

    #[test]
    fn rejects_a_grant_for_another_workspace() {
        let mut repository = Repository {
            edges: Vec::new(),
            disclosures: Vec::new(),
            fail_disclosure: false,
        };
        let provider = Provider {
            candidates: Vec::new(),
        };
        let mut command = command("workspace_01", 150);
        command.grant.workspace_id = WorkspaceId::new("workspace_02");

        assert_eq!(
            GraphContextService::new(&mut repository, &provider).execute(command),
            Err(ApplicationError::AccessDenied)
        );
        assert!(repository.disclosures.is_empty());
    }

    #[test]
    fn rejects_ungranted_scope_and_empty_purpose_before_disclosure() {
        let mut repository = Repository {
            edges: Vec::new(),
            disclosures: Vec::new(),
            fail_disclosure: false,
        };
        let provider = Provider {
            candidates: Vec::new(),
        };
        let mut ungranted = command("workspace_01", 150);
        ungranted.scope = MemoryScope::Entity {
            id: rembrane_domain::EntityId::new("project_01"),
        };
        assert_eq!(
            GraphContextService::new(&mut repository, &provider).execute(ungranted),
            Err(ApplicationError::AccessDenied)
        );

        let mut empty_purpose = command("workspace_01", 150);
        empty_purpose.purpose = "  ".to_owned();
        assert!(matches!(
            GraphContextService::new(&mut repository, &provider).execute(empty_purpose),
            Err(ApplicationError::Validation(_))
        ));
        assert!(repository.disclosures.is_empty());
    }

    #[test]
    fn refuses_to_return_context_when_disclosure_persistence_fails() {
        let mut repository = Repository {
            edges: vec![edge("valid", "workspace_01", "project", "rust", 2)],
            disclosures: Vec::new(),
            fail_disclosure: true,
        };
        let provider = Provider {
            candidates: vec![CandidateKnowledgeEdge {
                edge_id: KnowledgeEdgeId::new("valid"),
                version: 2,
            }],
        };

        assert_eq!(
            GraphContextService::new(&mut repository, &provider)
                .execute(command("workspace_01", 150)),
            Err(ApplicationError::StorageUnavailable)
        );
        assert!(repository.disclosures.is_empty());
    }

    #[test]
    fn transport_request_binds_principal_and_returns_disclosure_identity() {
        let mut repository = Repository {
            edges: vec![edge("valid", "workspace_01", "project", "rust", 2)],
            disclosures: Vec::new(),
            fail_disclosure: false,
        };
        let provider = Provider {
            candidates: vec![CandidateKnowledgeEdge {
                edge_id: KnowledgeEdgeId::new("valid"),
                version: 2,
            }],
        };
        let request = ResolveGraphContextRequest {
            workspace_id: WorkspaceId::new("workspace_01"),
            principal_id: PrincipalId::new("principal_01"),
            node_id: KnowledgeNodeId::new("project"),
            scope: MemoryScope::Global,
            direction: GraphDisclosureDirection::Outgoing,
            valid_at_epoch_seconds: 150,
            maximum_candidates: 10,
            purpose: "assistant_graph_context".to_owned(),
        };
        let grant = command("workspace_01", 150).grant;
        let disclosure_id = DisclosureId::new("disclosure_transport_01");

        let response = GraphContextService::new(&mut repository, &provider)
            .execute_request(request.clone(), grant.clone(), disclosure_id.clone())
            .expect("transport request should resolve");
        assert_eq!(response.disclosure_id, disclosure_id);
        assert_eq!(response.edges.len(), 1);

        let mut substituted = request;
        substituted.principal_id = PrincipalId::new("principal_other");
        assert_eq!(
            GraphContextService::new(&mut repository, &provider).execute_request(
                substituted,
                grant,
                DisclosureId::new("disclosure_transport_02"),
            ),
            Err(ApplicationError::AccessDenied)
        );
        assert_eq!(repository.disclosures.len(), 1);
    }
}

//! Graphiti projection adapter over a replaceable authenticated transport.
//!
//! Rembrane derives the provider namespace, operation, and idempotency key.
//! The transport receives no authority to select another workspace.

use rembrane_domain::{
    KnowledgeEdge, KnowledgeEdgeId, KnowledgeNode, KnowledgeNodeId, KnowledgeNodeKind, WorkspaceId,
};
use rembrane_provider_sdk::{
    CURRENT_PROVIDER_PROTOCOL, CandidateKnowledgeEdge, Capability, GraphDirection,
    GraphNeighbourQuery, GraphitiConnection, GraphitiErrorCode, GraphitiIdempotencyKey,
    GraphitiOperation, GraphitiPayload, GraphitiRequest, GraphitiResponse, KnowledgeGraphProvider,
    ProviderError, ProviderLimits, ProviderManifest, ProviderPolicy, validate_graph_candidates,
};

const REQUIRED_CAPABILITIES: &[Capability] = &[
    Capability::GraphUpsert,
    Capability::GraphTraverse,
    Capability::Delete,
    Capability::WorkspaceFilter,
    Capability::VersionedRecords,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphitiNode {
    pub node_id: String,
    pub kind: &'static str,
    pub label: String,
    pub aliases: Vec<String>,
    pub valid_from_epoch_seconds: u64,
    pub valid_until_epoch_seconds: Option<u64>,
    pub recorded_at_epoch_seconds: u64,
    pub version: u64,
}

impl GraphitiPayload for GraphitiNode {
    type Result = ();

    const OPERATION: GraphitiOperation = GraphitiOperation::UpsertNode;

    fn validate(&self) -> Result<(), ProviderError> {
        if self.node_id.is_empty()
            || self.label.is_empty()
            || self.valid_from_epoch_seconds == 0
            || self.recorded_at_epoch_seconds == 0
            || self.version == 0
        {
            return Err(ProviderError::InvalidConfiguration(
                "Graphiti node projection is incomplete".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphitiEdge {
    pub edge_id: String,
    pub source_id: String,
    pub target_id: String,
    pub relation: String,
    pub valid_from_epoch_seconds: u64,
    pub valid_until_epoch_seconds: Option<u64>,
    pub recorded_at_epoch_seconds: u64,
    pub version: u64,
    pub supersedes_edge_id: Option<String>,
}

impl GraphitiPayload for GraphitiEdge {
    type Result = ();

    const OPERATION: GraphitiOperation = GraphitiOperation::UpsertEdge;

    fn validate(&self) -> Result<(), ProviderError> {
        if self.edge_id.is_empty()
            || self.source_id.is_empty()
            || self.target_id.is_empty()
            || self.source_id == self.target_id
            || self.relation.is_empty()
            || self.valid_from_epoch_seconds == 0
            || self.recorded_at_epoch_seconds == 0
            || self.version == 0
        {
            return Err(ProviderError::InvalidConfiguration(
                "Graphiti edge projection is incomplete".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphitiNeighbourLookup {
    pub node_id: String,
    pub direction: GraphDirection,
    pub valid_at_epoch_seconds: u64,
    pub maximum_candidates: usize,
}

impl GraphitiPayload for GraphitiNeighbourLookup {
    type Result = Vec<CandidateKnowledgeEdge>;

    const OPERATION: GraphitiOperation = GraphitiOperation::Neighbours;

    fn validate(&self) -> Result<(), ProviderError> {
        if self.node_id.is_empty()
            || self.valid_at_epoch_seconds == 0
            || self.maximum_candidates == 0
        {
            return Err(ProviderError::InvalidConfiguration(
                "Graphiti neighbour lookup is incomplete".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphitiNodeDeletion {
    pub node_id: String,
    pub through_version: u64,
}

impl GraphitiPayload for GraphitiNodeDeletion {
    type Result = ();

    const OPERATION: GraphitiOperation = GraphitiOperation::DeleteNode;

    fn validate(&self) -> Result<(), ProviderError> {
        validate_deletion(&self.node_id, self.through_version)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphitiEdgeDeletion {
    pub edge_id: String,
    pub through_version: u64,
}

impl GraphitiPayload for GraphitiEdgeDeletion {
    type Result = ();

    const OPERATION: GraphitiOperation = GraphitiOperation::DeleteEdge;

    fn validate(&self) -> Result<(), ProviderError> {
        validate_deletion(&self.edge_id, self.through_version)
    }
}

fn validate_deletion(id: &str, through_version: u64) -> Result<(), ProviderError> {
    if id.is_empty() || through_version == 0 {
        return Err(ProviderError::InvalidConfiguration(
            "Graphiti deletion requires identity and version".to_owned(),
        ));
    }
    Ok(())
}

/// Transport boundary implemented by the bounded HTTP adapter or test sidecar.
pub trait GraphitiTransport {
    fn discover(&self) -> Result<ProviderManifest, ProviderError>;

    fn upsert_node(
        &self,
        request: &GraphitiRequest<GraphitiNode>,
    ) -> Result<GraphitiResponse<()>, ProviderError>;

    fn upsert_edge(
        &self,
        request: &GraphitiRequest<GraphitiEdge>,
    ) -> Result<GraphitiResponse<()>, ProviderError>;

    fn neighbours(
        &self,
        request: &GraphitiRequest<GraphitiNeighbourLookup>,
    ) -> Result<GraphitiResponse<Vec<CandidateKnowledgeEdge>>, ProviderError>;

    fn delete_node(
        &self,
        request: &GraphitiRequest<GraphitiNodeDeletion>,
    ) -> Result<GraphitiResponse<()>, ProviderError>;

    fn delete_edge(
        &self,
        request: &GraphitiRequest<GraphitiEdgeDeletion>,
    ) -> Result<GraphitiResponse<()>, ProviderError>;
}

pub struct GraphitiProvider<Transport> {
    transport: Transport,
    connection: GraphitiConnection,
    manifest: ProviderManifest,
}

impl<Transport: GraphitiTransport> GraphitiProvider<Transport> {
    pub fn connect(
        transport: Transport,
        request_prefix: impl Into<String>,
        allow_plaintext_processing: bool,
    ) -> Result<Self, ProviderError> {
        let manifest = transport.discover()?;
        ProviderPolicy {
            minimum_protocol_version: CURRENT_PROVIDER_PROTOCOL,
            required_capabilities: REQUIRED_CAPABILITIES.to_vec(),
            allow_plaintext_processing,
        }
        .validate(&manifest)?;
        Ok(Self {
            transport,
            connection: GraphitiConnection::new(request_prefix)?,
            manifest,
        })
    }

    #[must_use]
    pub const fn transport(&self) -> &Transport {
        &self.transport
    }

    fn mutation_key(
        resource: &str,
        id: &str,
        version: u64,
    ) -> Result<GraphitiIdempotencyKey, ProviderError> {
        GraphitiIdempotencyKey::new(format!("rembrane.{resource}.{id}.{version}"))
    }

    fn accept<'response, ResultPayload>(
        request: &GraphitiRequest<impl GraphitiPayload<Result = ResultPayload>>,
        response: &'response GraphitiResponse<ResultPayload>,
    ) -> Result<&'response ResultPayload, ProviderError> {
        match request.validate_response(response)? {
            Ok(result) => Ok(result),
            Err(GraphitiErrorCode::Unavailable | GraphitiErrorCode::Internal) => {
                Err(ProviderError::Unavailable)
            }
            Err(GraphitiErrorCode::InvalidRequest | GraphitiErrorCode::Conflict) => Err(
                ProviderError::Rejected("Graphiti sidecar rejected projection".to_owned()),
            ),
        }
    }
}

impl<Transport: GraphitiTransport> KnowledgeGraphProvider for GraphitiProvider<Transport> {
    fn manifest(&self) -> ProviderManifest {
        self.manifest.clone()
    }

    fn upsert_node(&mut self, node: KnowledgeNode) -> Result<(), ProviderError> {
        let validity = node.validity();
        let request = self.connection.request(
            node.workspace_id(),
            Some(Self::mutation_key(
                "node",
                node.id().as_str(),
                node.version(),
            )?),
            GraphitiNode {
                node_id: node.id().as_str().to_owned(),
                kind: node_kind(node.kind()),
                label: node.label().to_owned(),
                aliases: node.aliases().to_vec(),
                valid_from_epoch_seconds: validity.valid_from_epoch_seconds(),
                valid_until_epoch_seconds: validity.valid_until_epoch_seconds(),
                recorded_at_epoch_seconds: validity.recorded_at_epoch_seconds(),
                version: node.version(),
            },
        )?;
        let response = self.transport.upsert_node(&request)?;
        Self::accept(&request, &response)?;
        Ok(())
    }

    fn upsert_edge(&mut self, edge: KnowledgeEdge) -> Result<(), ProviderError> {
        let validity = edge.validity();
        let request = self.connection.request(
            edge.workspace_id(),
            Some(Self::mutation_key(
                "edge",
                edge.id().as_str(),
                edge.version(),
            )?),
            GraphitiEdge {
                edge_id: edge.id().as_str().to_owned(),
                source_id: edge.source_id().as_str().to_owned(),
                target_id: edge.target_id().as_str().to_owned(),
                relation: edge.relation().as_str().to_owned(),
                valid_from_epoch_seconds: validity.valid_from_epoch_seconds(),
                valid_until_epoch_seconds: validity.valid_until_epoch_seconds(),
                recorded_at_epoch_seconds: validity.recorded_at_epoch_seconds(),
                version: edge.version(),
                supersedes_edge_id: edge.supersedes().map(|id| id.as_str().to_owned()),
            },
        )?;
        let response = self.transport.upsert_edge(&request)?;
        Self::accept(&request, &response)?;
        Ok(())
    }

    fn neighbours(
        &self,
        query: &GraphNeighbourQuery,
    ) -> Result<Vec<CandidateKnowledgeEdge>, ProviderError> {
        query.validate()?;
        if query.maximum_candidates > self.manifest.limits.maximum_candidates {
            return Err(ProviderError::Rejected(
                "graph candidate limit exceeds Graphiti capacity".to_owned(),
            ));
        }
        let request = self.connection.request(
            &query.workspace_id,
            None,
            GraphitiNeighbourLookup {
                node_id: query.node_id.as_str().to_owned(),
                direction: query.direction,
                valid_at_epoch_seconds: query.valid_at_epoch_seconds,
                maximum_candidates: query.maximum_candidates,
            },
        )?;
        let response = self.transport.neighbours(&request)?;
        let candidates = Self::accept(&request, &response)?.clone();
        validate_graph_candidates(&candidates, query.maximum_candidates)?;
        Ok(candidates)
    }

    fn delete_node(
        &mut self,
        workspace_id: &WorkspaceId,
        node_id: &KnowledgeNodeId,
        through_version: u64,
    ) -> Result<(), ProviderError> {
        let request = self.connection.request(
            workspace_id,
            Some(Self::mutation_key(
                "delete-node",
                node_id.as_str(),
                through_version,
            )?),
            GraphitiNodeDeletion {
                node_id: node_id.as_str().to_owned(),
                through_version,
            },
        )?;
        let response = self.transport.delete_node(&request)?;
        Self::accept(&request, &response)?;
        Ok(())
    }

    fn delete_edge(
        &mut self,
        workspace_id: &WorkspaceId,
        edge_id: &KnowledgeEdgeId,
        through_version: u64,
    ) -> Result<(), ProviderError> {
        let request = self.connection.request(
            workspace_id,
            Some(Self::mutation_key(
                "delete-edge",
                edge_id.as_str(),
                through_version,
            )?),
            GraphitiEdgeDeletion {
                edge_id: edge_id.as_str().to_owned(),
                through_version,
            },
        )?;
        let response = self.transport.delete_edge(&request)?;
        Self::accept(&request, &response)?;
        Ok(())
    }
}

const fn node_kind(kind: KnowledgeNodeKind) -> &'static str {
    match kind {
        KnowledgeNodeKind::Person => "person",
        KnowledgeNodeKind::Organization => "organization",
        KnowledgeNodeKind::Place => "place",
        KnowledgeNodeKind::Project => "project",
        KnowledgeNodeKind::Artifact => "artifact",
        KnowledgeNodeKind::Concept => "concept",
        KnowledgeNodeKind::Event => "event",
    }
}

#[must_use]
pub fn compatible_graphiti_manifest(version: impl Into<String>) -> ProviderManifest {
    ProviderManifest {
        id: "rembrane.graph.graphiti".to_owned(),
        version: version.into(),
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
            maximum_candidates: 100,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use rembrane_domain::{KnowledgeEdgeId, KnowledgeNodeId};
    use rembrane_provider_sdk::{
        CandidateKnowledgeEdge, GraphDirection, GraphitiNamespace, verify_knowledge_graph_provider,
    };

    use super::{
        GraphitiEdge, GraphitiEdgeDeletion, GraphitiNeighbourLookup, GraphitiNode,
        GraphitiNodeDeletion, GraphitiProvider, GraphitiRequest, GraphitiResponse,
        GraphitiTransport, ProviderError, ProviderManifest, compatible_graphiti_manifest,
    };

    #[derive(Clone)]
    struct StoredNode {
        namespace: GraphitiNamespace,
        node: GraphitiNode,
    }

    #[derive(Clone)]
    struct StoredEdge {
        namespace: GraphitiNamespace,
        edge: GraphitiEdge,
    }

    #[derive(Default)]
    struct MockSidecar {
        nodes: RefCell<Vec<StoredNode>>,
        edges: RefCell<Vec<StoredEdge>>,
        namespaces: RefCell<Vec<GraphitiNamespace>>,
    }

    impl GraphitiTransport for MockSidecar {
        fn discover(&self) -> Result<ProviderManifest, ProviderError> {
            Ok(compatible_graphiti_manifest("test"))
        }

        fn upsert_node(
            &self,
            request: &GraphitiRequest<GraphitiNode>,
        ) -> Result<GraphitiResponse<()>, ProviderError> {
            self.namespaces
                .borrow_mut()
                .push(request.namespace().clone());
            let mut nodes = self.nodes.borrow_mut();
            nodes.retain(|stored| {
                stored.namespace != *request.namespace()
                    || stored.node.node_id != request.payload().node_id
            });
            nodes.push(StoredNode {
                namespace: request.namespace().clone(),
                node: request.payload().clone(),
            });
            Ok(GraphitiResponse::success(request, ()))
        }

        fn upsert_edge(
            &self,
            request: &GraphitiRequest<GraphitiEdge>,
        ) -> Result<GraphitiResponse<()>, ProviderError> {
            let mut edges = self.edges.borrow_mut();
            edges.retain(|stored| {
                stored.namespace != *request.namespace()
                    || stored.edge.edge_id != request.payload().edge_id
            });
            edges.push(StoredEdge {
                namespace: request.namespace().clone(),
                edge: request.payload().clone(),
            });
            Ok(GraphitiResponse::success(request, ()))
        }

        fn neighbours(
            &self,
            request: &GraphitiRequest<GraphitiNeighbourLookup>,
        ) -> Result<GraphitiResponse<Vec<CandidateKnowledgeEdge>>, ProviderError> {
            let payload = request.payload();
            let candidates = self
                .edges
                .borrow()
                .iter()
                .filter(|stored| stored.namespace == *request.namespace())
                .filter(|stored| {
                    payload.valid_at_epoch_seconds >= stored.edge.valid_from_epoch_seconds
                        && stored
                            .edge
                            .valid_until_epoch_seconds
                            .is_none_or(|until| payload.valid_at_epoch_seconds < until)
                })
                .filter(|stored| match payload.direction {
                    GraphDirection::Incoming => stored.edge.target_id == payload.node_id,
                    GraphDirection::Outgoing => stored.edge.source_id == payload.node_id,
                    GraphDirection::Both => {
                        stored.edge.source_id == payload.node_id
                            || stored.edge.target_id == payload.node_id
                    }
                })
                .take(payload.maximum_candidates)
                .map(|stored| CandidateKnowledgeEdge {
                    edge_id: KnowledgeEdgeId::new(stored.edge.edge_id.clone()),
                    version: stored.edge.version,
                })
                .collect();
            Ok(GraphitiResponse::success(request, candidates))
        }

        fn delete_node(
            &self,
            request: &GraphitiRequest<GraphitiNodeDeletion>,
        ) -> Result<GraphitiResponse<()>, ProviderError> {
            self.nodes.borrow_mut().retain(|stored| {
                stored.namespace != *request.namespace()
                    || stored.node.node_id != request.payload().node_id
                    || stored.node.version > request.payload().through_version
            });
            self.edges.borrow_mut().retain(|stored| {
                stored.namespace != *request.namespace()
                    || (stored.edge.source_id != request.payload().node_id
                        && stored.edge.target_id != request.payload().node_id)
            });
            Ok(GraphitiResponse::success(request, ()))
        }

        fn delete_edge(
            &self,
            request: &GraphitiRequest<GraphitiEdgeDeletion>,
        ) -> Result<GraphitiResponse<()>, ProviderError> {
            self.edges.borrow_mut().retain(|stored| {
                stored.namespace != *request.namespace()
                    || stored.edge.edge_id != request.payload().edge_id
                    || stored.edge.version > request.payload().through_version
            });
            Ok(GraphitiResponse::success(request, ()))
        }
    }

    #[test]
    fn passes_shared_graph_provider_conformance() {
        let mut provider = GraphitiProvider::connect(MockSidecar::default(), "graphiti-test", true)
            .expect("provider should connect");
        verify_knowledge_graph_provider(&mut provider, "graphiti")
            .expect("Graphiti adapter should conform");
    }

    #[test]
    fn derives_namespaces_instead_of_accepting_provider_group_ids() {
        let mut provider = GraphitiProvider::connect(MockSidecar::default(), "graphiti-test", true)
            .expect("provider should connect");
        let node = rembrane_domain::KnowledgeNode::new(
            KnowledgeNodeId::new("node-a"),
            rembrane_domain::WorkspaceId::new("private-workspace"),
            rembrane_domain::KnowledgeNodeKind::Concept,
            "node".to_owned(),
            Vec::new(),
            vec![rembrane_domain::EvidenceReference::new(
                rembrane_domain::EvidenceId::new("evidence-a"),
                rembrane_domain::EvidenceSource::ImportedRecord,
            )],
            rembrane_domain::TemporalValidity::new(1, None, 1).expect("validity"),
            1,
        )
        .expect("node");
        rembrane_provider_sdk::KnowledgeGraphProvider::upsert_node(&mut provider, node)
            .expect("projection");
        let namespaces = provider.transport().namespaces.borrow();
        assert_eq!(namespaces.len(), 1);
        assert!(!namespaces[0].as_str().contains("private-workspace"));
    }
}

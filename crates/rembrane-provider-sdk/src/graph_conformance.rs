use rembrane_domain::{
    EvidenceId, EvidenceReference, EvidenceSource, KnowledgeEdge, KnowledgeEdgeId, KnowledgeNode,
    KnowledgeNodeId, KnowledgeNodeKind, KnowledgeRelationType, TemporalValidity, WorkspaceId,
};

use crate::{
    CURRENT_PROVIDER_PROTOCOL, Capability, ConformanceFailure, GraphDirection, GraphNeighbourQuery,
    KnowledgeGraphProvider, ProviderPolicy, validate_graph_candidates,
};

/// Exercises workspace isolation, temporal traversal, and bounded graph
/// deletion against a disposable provider namespace.
pub fn verify_knowledge_graph_provider(
    provider: &mut impl KnowledgeGraphProvider,
    fixture_namespace: &str,
) -> Result<(), ConformanceFailure> {
    let namespace = fixture_namespace.trim();
    if namespace.is_empty() || namespace.len() > 100 {
        return Err(ConformanceFailure::InvalidFixture);
    }
    let manifest = provider.manifest();
    ProviderPolicy {
        minimum_protocol_version: CURRENT_PROVIDER_PROTOCOL,
        required_capabilities: vec![
            Capability::GraphUpsert,
            Capability::GraphTraverse,
            Capability::Delete,
            Capability::WorkspaceFilter,
            Capability::VersionedRecords,
        ],
        allow_plaintext_processing: true,
    }
    .validate(&manifest)?;

    let workspace = WorkspaceId::new(format!("conformance.graph.{namespace}"));
    let other_workspace = WorkspaceId::new(format!("conformance.graph.other.{namespace}"));
    let source_id = KnowledgeNodeId::new(format!("node.source.{namespace}"));
    let target_id = KnowledgeNodeId::new(format!("node.target.{namespace}"));
    let edge_id = KnowledgeEdgeId::new(format!("edge.uses.{namespace}"));
    let validity = TemporalValidity::new(100, Some(200), 100)
        .map_err(|_| ConformanceFailure::InvalidFixture)?;
    let evidence = |suffix: &str| {
        EvidenceReference::new(
            EvidenceId::new(format!("evidence.{namespace}.{suffix}")),
            EvidenceSource::ImportedRecord,
        )
    };
    for (id, label) in [(source_id.clone(), "source"), (target_id.clone(), "target")] {
        provider.upsert_node(
            KnowledgeNode::new(
                id,
                workspace.clone(),
                KnowledgeNodeKind::Concept,
                format!("{label}-{namespace}"),
                Vec::new(),
                vec![evidence(label)],
                validity,
                1,
            )
            .map_err(|_| ConformanceFailure::InvalidFixture)?,
        )?;
    }
    provider.upsert_edge(
        KnowledgeEdge::new(
            edge_id.clone(),
            workspace.clone(),
            source_id.clone(),
            target_id,
            KnowledgeRelationType::new("uses").map_err(|_| ConformanceFailure::InvalidFixture)?,
            vec![evidence("edge")],
            validity,
            1,
            None,
        )
        .map_err(|_| ConformanceFailure::InvalidFixture)?,
    )?;

    let visible = query(provider, workspace.clone(), source_id.clone(), 150)?;
    if !visible
        .iter()
        .any(|candidate| candidate.edge_id == edge_id && candidate.version == 1)
    {
        return Err(ConformanceFailure::Behavior(
            "graph edge was not visible in its workspace and validity window".to_owned(),
        ));
    }
    if !query(provider, workspace.clone(), source_id.clone(), 200)?.is_empty() {
        return Err(ConformanceFailure::Behavior(
            "expired graph edge remained visible".to_owned(),
        ));
    }
    if query(provider, other_workspace, source_id.clone(), 150)?
        .iter()
        .any(|candidate| candidate.edge_id == edge_id)
    {
        return Err(ConformanceFailure::Behavior(
            "graph edge crossed a workspace boundary".to_owned(),
        ));
    }

    provider.delete_edge(&workspace, &edge_id, 1)?;
    if query(provider, workspace.clone(), source_id.clone(), 150)?
        .iter()
        .any(|candidate| candidate.edge_id == edge_id)
    {
        return Err(ConformanceFailure::Behavior(
            "deleted graph edge remained visible".to_owned(),
        ));
    }
    provider.delete_node(&workspace, &source_id, 1)?;
    Ok(())
}

fn query(
    provider: &impl KnowledgeGraphProvider,
    workspace_id: WorkspaceId,
    node_id: KnowledgeNodeId,
    valid_at_epoch_seconds: u64,
) -> Result<Vec<crate::CandidateKnowledgeEdge>, ConformanceFailure> {
    let query = GraphNeighbourQuery {
        workspace_id,
        node_id,
        direction: GraphDirection::Outgoing,
        valid_at_epoch_seconds,
        maximum_candidates: 10,
    };
    query.validate()?;
    let candidates = provider.neighbours(&query)?;
    validate_graph_candidates(&candidates, query.maximum_candidates)?;
    Ok(candidates)
}

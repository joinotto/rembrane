use rembrane_application::{
    GraphProjectionOutboxRepository, GraphProjectionWorker, KnowledgeGraphMutationRepository,
    ProjectionOutcome,
};
use rembrane_domain::{
    EvidenceId, EvidenceReference, EvidenceSource, GraphProjectionJob, GraphProjectionResource,
    KnowledgeNode, KnowledgeNodeId, KnowledgeNodeKind, ProjectionJobId, ProjectionOperation,
    ProviderId, TemporalValidity, WorkspaceId,
};
use rembrane_provider_sdk::{GraphDirection, GraphNeighbourQuery, KnowledgeGraphProvider};
use rembrane_store_memory::InMemoryStore;

use rembrane_graph_native::NativeGraphProvider;

#[test]
fn worker_projects_current_canonical_node_and_completes_job() {
    let workspace_id = WorkspaceId::new("workspace_01");
    let node_id = KnowledgeNodeId::new("node_project");
    let node = KnowledgeNode::new(
        node_id.clone(),
        workspace_id.clone(),
        KnowledgeNodeKind::Project,
        "Rembrane".to_owned(),
        Vec::new(),
        vec![EvidenceReference::new(
            EvidenceId::new("evidence_01"),
            EvidenceSource::UserStatement,
        )],
        TemporalValidity::new(100, None, 100).expect("validity should work"),
        1,
    )
    .expect("node should be valid");
    let provider_id = ProviderId::new("rembrane.graph.native");
    let job = GraphProjectionJob::new(
        ProjectionJobId::new("projection_01"),
        workspace_id.clone(),
        GraphProjectionResource::Node(node_id.clone()),
        1,
        provider_id.clone(),
        ProjectionOperation::Upsert,
    )
    .expect("job should be valid");
    let mut repository = InMemoryStore::new();
    repository
        .insert_knowledge_node(node)
        .expect("node should insert");
    repository
        .enqueue_graph_projection(job)
        .expect("job should enqueue");
    let mut provider = NativeGraphProvider::new();

    assert_eq!(
        GraphProjectionWorker::new(&mut repository, &mut provider, provider_id, 3)
            .expect("worker should initialize")
            .process_next()
            .expect("projection should process"),
        ProjectionOutcome::Completed
    );
    assert_eq!(
        provider
            .neighbours(&GraphNeighbourQuery {
                workspace_id,
                node_id,
                direction: GraphDirection::Both,
                valid_at_epoch_seconds: 100,
                maximum_candidates: 10,
            })
            .expect("empty neighbourhood should resolve"),
        Vec::new()
    );
}

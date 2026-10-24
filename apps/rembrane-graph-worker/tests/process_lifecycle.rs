use std::process::Command;

use rembrane_application::{
    CanonicalGraphMutationRepository, GraphProjectionOutboxRepository, WorkspaceRepository,
};
use rembrane_crypto_rustcrypto::RustCryptoRecordCipher;
use rembrane_domain::{
    EvidenceId, EvidenceReference, EvidenceSource, GraphProjectionJob, GraphProjectionResource,
    KnowledgeNode, KnowledgeNodeId, KnowledgeNodeKind, Membership, Principal, PrincipalId,
    ProjectionJobId, ProjectionOperation, ProjectionStatus, ProviderId, TemporalValidity,
    Workspace, WorkspaceId, WorkspaceRole,
};
use rembrane_store_sqlite::SqliteStore;

struct TemporaryDatabase(std::path::PathBuf);

impl TemporaryDatabase {
    fn new() -> Self {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock is valid")
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "rembrane-graph-worker-{suffix}-{}.sqlite",
            std::process::id()
        )))
    }
}

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        for suffix in ["-shm", "-wal"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
    }
}

fn cipher() -> RustCryptoRecordCipher {
    RustCryptoRecordCipher::new("worker-test-key", [7; 32]).expect("test key should be valid")
}

#[test]
fn worker_process_completes_a_real_encrypted_outbox_job() {
    let database = TemporaryDatabase::new();
    let workspace_id = WorkspaceId::new("workspace_worker_test");
    let principal_id = PrincipalId::new("principal_worker_test");
    let node_id = KnowledgeNodeId::new("node_worker_test");
    let job_id = ProjectionJobId::new("projection_worker_test");
    let provider_id = ProviderId::new("rembrane.graph.native");

    {
        let mut store = SqliteStore::open(&database.0)
            .expect("database should open")
            .with_cipher(cipher());
        store
            .initialize_personal_workspace(
                Principal::new(principal_id.clone()),
                Workspace::personal(workspace_id.clone()),
                Membership::new(workspace_id.clone(), principal_id, WorkspaceRole::Owner),
            )
            .expect("workspace should initialize");
        let node = KnowledgeNode::new(
            node_id.clone(),
            workspace_id.clone(),
            KnowledgeNodeKind::Project,
            "Rembrane worker lifecycle".to_owned(),
            Vec::new(),
            vec![EvidenceReference::new(
                EvidenceId::new("evidence_worker_test"),
                EvidenceSource::WorkspaceDecision,
            )],
            TemporalValidity::new(100, None, 100).expect("validity should work"),
            1,
        )
        .expect("node should be valid");
        let job = GraphProjectionJob::new(
            job_id.clone(),
            workspace_id.clone(),
            GraphProjectionResource::Node(node_id),
            1,
            provider_id,
            ProjectionOperation::Upsert,
        )
        .expect("job should be valid");
        store
            .insert_knowledge_node_with_projections(node, vec![job])
            .expect("node and outbox job should commit atomically");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_rembrane-graph-worker"))
        .env("REMBRANE_DATABASE", &database.0)
        .env("REMBRANE_KEY_PROVIDER", "environment")
        .env("REMBRANE_WORKSPACE_KEY_ID", "worker-test-key")
        .env("REMBRANE_WORKSPACE_KEY_HEX", "07".repeat(32))
        .env("REMBRANE_GRAPH_PROVIDER", "native")
        .env("REMBRANE_GRAPH_WORKER_RUN_ONCE", "1")
        .output()
        .expect("worker process should launch");
    assert!(
        output.status.success(),
        "worker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let store = SqliteStore::open(&database.0)
        .expect("database should reopen")
        .with_cipher(cipher());
    let completed = store
        .find_graph_projection(&workspace_id, &job_id)
        .expect("job lookup should succeed")
        .expect("job should remain auditable");
    assert_eq!(completed.status(), ProjectionStatus::Completed);
    assert_eq!(completed.attempts(), 1);
}

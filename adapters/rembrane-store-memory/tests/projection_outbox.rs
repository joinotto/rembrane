use rembrane_application::{ApplicationError, ProjectionOutboxRepository};
use rembrane_domain::{
    MemoryId, ProjectionJob, ProjectionJobId, ProjectionOperation, ProjectionStatus, ProviderId,
    WorkspaceId,
};
use rembrane_store_memory::InMemoryStore;

fn job(id: &str) -> ProjectionJob {
    ProjectionJob::new(
        ProjectionJobId::new(id),
        WorkspaceId::new("workspace_01"),
        MemoryId::new("memory_01"),
        1,
        ProviderId::new("semantic.primary"),
        ProjectionOperation::Upsert,
    )
    .expect("test job should be valid")
}

#[test]
fn rejects_duplicate_idempotency_tuple() {
    let mut store = InMemoryStore::new();
    store
        .enqueue_projection(job("projection_01"))
        .expect("first projection should enqueue");

    let error = store
        .enqueue_projection(job("projection_different_id"))
        .expect_err("duplicate projection tuple should fail");

    assert_eq!(error, ApplicationError::AlreadyExists);
}

#[test]
fn worker_transition_uses_optimistic_status_and_attempts() {
    let mut store = InMemoryStore::new();
    store
        .enqueue_projection(job("projection_01"))
        .expect("projection should enqueue");
    let pending = store
        .pending_projections(&ProviderId::new("semantic.primary"), 10)
        .expect("pending lookup should succeed")
        .into_iter()
        .next()
        .expect("projection should be pending");
    let processing = pending.begin().expect("pending projection should begin");
    store
        .replace_projection(processing.clone(), ProjectionStatus::Pending, 0)
        .expect("first worker should claim projection");

    let error = store
        .replace_projection(processing, ProjectionStatus::Pending, 0)
        .expect_err("second worker claim should conflict");

    assert_eq!(error, ApplicationError::VersionConflict);
}

#[test]
fn pending_query_is_provider_scoped_and_limited() {
    let mut store = InMemoryStore::new();
    store
        .enqueue_projection(job("projection_01"))
        .expect("projection should enqueue");

    assert_eq!(
        store
            .pending_projections(&ProviderId::new("semantic.other"), 10)
            .expect("pending lookup should succeed")
            .len(),
        0
    );
    assert_eq!(
        store
            .pending_projections(&ProviderId::new("semantic.primary"), 0)
            .expect("zero-limit lookup should succeed")
            .len(),
        0
    );
}

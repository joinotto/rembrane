use rembrane_application::{
    ApplicationError, CheckpointRepository,
};
use rembrane_domain::{
    ActivityCheckpoint, ActivityId, CheckpointId, EntityId, PrincipalId,
    WorkspaceId,
};
use rembrane_store_memory::InMemoryStore;

fn checkpoint(workspace_id: &str, subject_id: &str) -> ActivityCheckpoint {
    ActivityCheckpoint::new(
        CheckpointId::new("checkpoint_01"),
        WorkspaceId::new(workspace_id),
        PrincipalId::new(subject_id),
        ActivityId::new("activity_01"),
        Some(EntityId::new("project_01")),
        "Build Rembrane",
        "The domain layer is implemented.",
        vec!["Add an application service".to_owned()],
        Vec::new(),
    )
    .expect("test checkpoint should be valid")
}

#[test]
fn does_not_return_checkpoint_across_workspace_boundary() {
    let mut store = InMemoryStore::new();
    store
        .insert_checkpoint(checkpoint("workspace_private", "principal_01"))
        .expect("checkpoint insert should succeed");

    let result = store
        .latest_checkpoint(
            &WorkspaceId::new("workspace_other"),
            &PrincipalId::new("principal_01"),
            &ActivityId::new("activity_01"),
        )
        .expect("checkpoint lookup should succeed");

    assert!(result.is_none());
}

#[test]
fn does_not_return_checkpoint_to_another_subject() {
    let mut store = InMemoryStore::new();
    store
        .insert_checkpoint(checkpoint("workspace_01", "principal_private"))
        .expect("checkpoint insert should succeed");

    let result = store
        .latest_checkpoint(
            &WorkspaceId::new("workspace_01"),
            &PrincipalId::new("principal_other"),
            &ActivityId::new("activity_01"),
        )
        .expect("checkpoint lookup should succeed");

    assert!(result.is_none());
}

#[test]
fn rejects_stale_checkpoint_update() {
    let mut store = InMemoryStore::new();
    let original = checkpoint("workspace_01", "principal_01");
    store
        .insert_checkpoint(original.clone())
        .expect("checkpoint insert should succeed");
    let updated = original
        .update(
            "The application service is implemented.",
            vec!["Expose protocol contracts".to_owned()],
            Vec::new(),
        )
        .expect("checkpoint update should be valid");

    let error = store
        .replace_checkpoint(updated, 2)
        .expect_err("stale checkpoint update should fail");

    assert_eq!(error, ApplicationError::VersionConflict);
}

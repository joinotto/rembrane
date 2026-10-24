use rembrane_application::{ApplicationError, CheckpointMutationRepository, CheckpointRepository};
use rembrane_domain::{
    ActivityCheckpoint, ActivityId, CanonicalEvent, CheckpointId, EntityId, EventId, EventPayload,
    PrincipalId, WorkspaceId,
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

fn event(checkpoint: &ActivityCheckpoint, id: &str, sequence: u64) -> CanonicalEvent {
    CanonicalEvent::new(
        EventId::new(id),
        checkpoint.workspace_id().clone(),
        checkpoint.subject_id().clone(),
        Some(checkpoint.subject_id().clone()),
        sequence,
        EventPayload::ActivityCheckpointed {
            activity_id: checkpoint.activity_id().clone(),
            version: checkpoint.version(),
        },
    )
    .expect("test event should be valid")
}

#[test]
fn does_not_return_checkpoint_across_workspace_boundary() {
    let mut store = InMemoryStore::new();
    let checkpoint = checkpoint("workspace_private", "principal_01");
    let creation_event = event(&checkpoint, "event_01", 1);
    store
        .insert_checkpoint_with_event(checkpoint, creation_event, 0)
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
    let checkpoint = checkpoint("workspace_01", "principal_private");
    let creation_event = event(&checkpoint, "event_01", 1);
    store
        .insert_checkpoint_with_event(checkpoint, creation_event, 0)
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
    let creation_event = event(&original, "event_01", 1);
    store
        .insert_checkpoint_with_event(original.clone(), creation_event, 0)
        .expect("checkpoint insert should succeed");
    let updated = original
        .update(
            "The application service is implemented.",
            vec!["Expose protocol contracts".to_owned()],
            Vec::new(),
        )
        .expect("checkpoint update should be valid");

    let update_event = event(&updated, "event_02", 2);
    let error = store
        .replace_checkpoint_with_event(updated, 2, update_event, 1)
        .expect_err("stale checkpoint update should fail");

    assert_eq!(error, ApplicationError::VersionConflict);
}

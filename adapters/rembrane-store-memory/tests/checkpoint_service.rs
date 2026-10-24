use rembrane_application::{
    ApplicationError, CheckpointService, CreateCheckpointCommand, ResumeActivityCommand,
};
use rembrane_domain::{
    ActivityCheckpoint, ActivityId, CheckpointId, ClientId, DisclosureId, EventId, PrincipalId,
    ReadGrant, ReadScope, WorkspaceId, WriteGrant, WritePermission,
};
use rembrane_store_memory::InMemoryStore;

fn checkpoint() -> ActivityCheckpoint {
    ActivityCheckpoint::new(
        CheckpointId::new("checkpoint_01"),
        WorkspaceId::new("workspace_01"),
        PrincipalId::new("principal_01"),
        ActivityId::new("activity_01"),
        None,
        "Build the memory protocol",
        "Scoped read grants are implemented.",
        vec!["Define the first API schema".to_owned()],
        Vec::new(),
    )
    .expect("test checkpoint should be valid")
}

fn writer() -> WriteGrant {
    WriteGrant {
        client_id: ClientId::new("coding_agent"),
        workspace_id: WorkspaceId::new("workspace_01"),
        subject_id: PrincipalId::new("principal_01"),
        scopes: vec![ReadScope::Activity {
            id: ActivityId::new("activity_01"),
        }],
        permissions: vec![WritePermission::WriteCheckpoint],
    }
}

fn reader(activity_id: &str) -> ReadGrant {
    ReadGrant {
        client_id: ClientId::new("next_coding_agent"),
        workspace_id: WorkspaceId::new("workspace_01"),
        subject_id: PrincipalId::new("principal_01"),
        scopes: vec![ReadScope::Activity {
            id: ActivityId::new(activity_id),
        }],
        permissions: Vec::new(),
    }
}

#[test]
fn authorized_agent_can_create_and_another_can_resume() {
    let mut store = InMemoryStore::new();
    let mut service = CheckpointService::new(&mut store);
    service
        .create(CreateCheckpointCommand {
            grant: writer(),
            checkpoint: checkpoint(),
            event_id: EventId::new("event_01"),
            expected_previous_sequence: 0,
        })
        .expect("authorized checkpoint creation should succeed");

    let resumed = service
        .resume(&ResumeActivityCommand {
            grant: reader("activity_01"),
            activity_id: ActivityId::new("activity_01"),
            disclosure_id: DisclosureId::new("disclosure_01"),
            purpose: "continue-project".to_owned(),
        })
        .expect("authorized resume should succeed")
        .expect("checkpoint should exist");

    assert_eq!(resumed.summary(), "Scoped read grants are implemented.");
    assert_eq!(store.checkpoint_disclosure_count(), 1);
}

#[test]
fn activity_grant_cannot_resume_another_activity() {
    let mut store = InMemoryStore::new();
    let mut service = CheckpointService::new(&mut store);

    let error = service
        .resume(&ResumeActivityCommand {
            grant: reader("activity_other"),
            activity_id: ActivityId::new("activity_01"),
            disclosure_id: DisclosureId::new("disclosure_denied"),
            purpose: "continue-project".to_owned(),
        })
        .expect_err("mismatched activity grant should fail");

    assert_eq!(error, ApplicationError::AccessDenied);
    assert_eq!(store.checkpoint_disclosure_count(), 0);
}

#[test]
fn client_without_checkpoint_write_permission_is_denied() {
    let mut store = InMemoryStore::new();
    let mut denied = writer();
    denied.permissions.clear();

    let error = CheckpointService::new(&mut store)
        .create(CreateCheckpointCommand {
            grant: denied,
            checkpoint: checkpoint(),
            event_id: EventId::new("event_01"),
            expected_previous_sequence: 0,
        })
        .expect_err("missing write permission should fail");

    assert_eq!(error, ApplicationError::AccessDenied);
}

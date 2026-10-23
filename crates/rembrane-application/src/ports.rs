use rembrane_domain::{
    ActivityCheckpoint, ActivityId, CanonicalEvent, DisclosureReceipt,
    Membership, MemoryId, MemoryRecord, PrincipalId, WorkspaceId,
};

use crate::ApplicationError;

pub trait MemoryRepository {
    fn insert(&mut self, memory: MemoryRecord) -> Result<(), ApplicationError>;

    fn find(
        &self,
        workspace_id: &WorkspaceId,
        memory_id: &MemoryId,
    ) -> Result<Option<MemoryRecord>, ApplicationError>;

    fn list_for_subject(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
    ) -> Result<Vec<MemoryRecord>, ApplicationError>;

    fn replace(
        &mut self,
        memory: MemoryRecord,
        expected_version: u64,
    ) -> Result<(), ApplicationError>;
}

pub trait DisclosureRepository {
    fn append(
        &mut self,
        receipt: DisclosureReceipt,
    ) -> Result<(), ApplicationError>;
}

pub trait EventRepository {
    fn append_event(
        &mut self,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError>;

    fn list_events_since(
        &self,
        workspace_id: &WorkspaceId,
        sequence: u64,
    ) -> Result<Vec<CanonicalEvent>, ApplicationError>;
}

pub trait CanonicalMutationRepository: EventRepository + MemoryRepository {
    fn insert_memory_with_event(
        &mut self,
        memory: MemoryRecord,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError>;

    fn replace_memory_with_event(
        &mut self,
        memory: MemoryRecord,
        expected_memory_version: u64,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError>;
}

pub trait CheckpointRepository {
    fn insert_checkpoint(
        &mut self,
        checkpoint: ActivityCheckpoint,
    ) -> Result<(), ApplicationError>;

    fn latest_checkpoint(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
        activity_id: &ActivityId,
    ) -> Result<Option<ActivityCheckpoint>, ApplicationError>;

    fn replace_checkpoint(
        &mut self,
        checkpoint: ActivityCheckpoint,
        expected_version: u64,
    ) -> Result<(), ApplicationError>;
}

pub trait CheckpointMutationRepository: CheckpointRepository + EventRepository {
    fn insert_checkpoint_with_event(
        &mut self,
        checkpoint: ActivityCheckpoint,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError>;

    fn replace_checkpoint_with_event(
        &mut self,
        checkpoint: ActivityCheckpoint,
        expected_checkpoint_version: u64,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError>;
}

pub trait MembershipRepository {
    fn insert_membership(
        &mut self,
        membership: Membership,
    ) -> Result<(), ApplicationError>;

    fn find_membership(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Option<Membership>, ApplicationError>;

    fn replace_membership(
        &mut self,
        membership: Membership,
    ) -> Result<(), ApplicationError>;
}

use rembrane_domain::{
    ActivityCheckpoint, ActivityId, CanonicalEvent, CheckpointDisclosureReceipt, DisclosureReceipt,
    Invitation, InvitationId, Membership, MemoryId, MemoryRecord, Principal, PrincipalId,
    ProjectionJob, ProjectionJobId, ProjectionStatus, ProviderId, Workspace, WorkspaceId,
};

use crate::ApplicationError;

pub trait MemoryRepository {
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
}

pub trait DisclosureRepository {
    fn append(&mut self, receipt: DisclosureReceipt) -> Result<(), ApplicationError>;
}

pub trait CheckpointDisclosureRepository {
    fn append_checkpoint_disclosure(
        &mut self,
        receipt: CheckpointDisclosureReceipt,
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
        projections: Vec<ProjectionJob>,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError>;

    fn replace_memory_with_event(
        &mut self,
        memory: MemoryRecord,
        expected_memory_version: u64,
        event: CanonicalEvent,
        projections: Vec<ProjectionJob>,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError>;
}

pub trait CheckpointRepository {
    fn latest_checkpoint(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
        activity_id: &ActivityId,
    ) -> Result<Option<ActivityCheckpoint>, ApplicationError>;

    fn list_checkpoints_for_subject(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
    ) -> Result<Vec<ActivityCheckpoint>, ApplicationError>;
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
    fn insert_membership(&mut self, membership: Membership) -> Result<(), ApplicationError>;

    fn find_membership(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Option<Membership>, ApplicationError>;

    fn replace_membership(&mut self, membership: Membership) -> Result<(), ApplicationError>;
}

pub trait InvitationRepository {
    fn insert_invitation(&mut self, invitation: Invitation) -> Result<(), ApplicationError>;

    fn find_invitation(
        &self,
        workspace_id: &WorkspaceId,
        invitation_id: &InvitationId,
    ) -> Result<Option<Invitation>, ApplicationError>;

    fn accept_invitation_with_membership(
        &mut self,
        invitation: Invitation,
        membership: Membership,
    ) -> Result<(), ApplicationError>;
}

pub trait WorkspaceRepository {
    fn initialize_personal_workspace(
        &mut self,
        principal: Principal,
        workspace: Workspace,
        owner_membership: Membership,
    ) -> Result<(), ApplicationError>;

    fn initialize_shared_workspace(
        &mut self,
        workspace: Workspace,
        owner_membership: Membership,
    ) -> Result<(), ApplicationError>;

    fn find_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Option<Principal>, ApplicationError>;

    fn find_workspace(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<Workspace>, ApplicationError>;
}

pub trait ProjectionOutboxRepository {
    fn enqueue_projection(&mut self, job: ProjectionJob) -> Result<(), ApplicationError>;

    fn pending_projections(
        &self,
        provider_id: &ProviderId,
        limit: usize,
    ) -> Result<Vec<ProjectionJob>, ApplicationError>;

    fn replace_projection(
        &mut self,
        job: ProjectionJob,
        expected_status: ProjectionStatus,
        expected_attempts: u32,
    ) -> Result<(), ApplicationError>;

    fn find_projection(
        &self,
        workspace_id: &WorkspaceId,
        job_id: &ProjectionJobId,
    ) -> Result<Option<ProjectionJob>, ApplicationError>;
}

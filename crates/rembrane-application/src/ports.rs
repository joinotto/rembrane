use rembrane_domain::{
    ActivityCheckpoint, ActivityId, BookingResearch, BookingResearchId, CanonicalEvent,
    CheckpointDisclosureReceipt, DisclosureReceipt, EntityId, Invitation, InvitationId,
    InvitationStatus, KnowledgeEdge, KnowledgeEdgeId, KnowledgeNode, KnowledgeNodeId,
    MemberScopeGrant, Membership, MembershipStatus, MemoryId, MemoryRecord, MemoryShareProposal,
    Principal, PrincipalId, ProjectionJob, ProjectionJobId, ProjectionStatus, ProviderId,
    ShareProposalId, ShareProposalStatus, TravelDisclosureReceipt, Trip, Workspace, WorkspaceId,
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

pub const MAX_KNOWLEDGE_NEIGHBOURS: usize = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KnowledgeDirection {
    Incoming,
    Outgoing,
    Both,
}

pub trait KnowledgeGraphRepository {
    fn find_knowledge_node(
        &self,
        workspace_id: &WorkspaceId,
        node_id: &KnowledgeNodeId,
    ) -> Result<Option<KnowledgeNode>, ApplicationError>;

    fn find_knowledge_edge(
        &self,
        workspace_id: &WorkspaceId,
        edge_id: &KnowledgeEdgeId,
    ) -> Result<Option<KnowledgeEdge>, ApplicationError>;

    fn list_neighbour_edges(
        &self,
        workspace_id: &WorkspaceId,
        node_id: &KnowledgeNodeId,
        direction: KnowledgeDirection,
        valid_at_epoch_seconds: u64,
        limit: usize,
    ) -> Result<Vec<KnowledgeEdge>, ApplicationError>;
}

pub trait KnowledgeGraphMutationRepository: KnowledgeGraphRepository {
    fn insert_knowledge_node(&mut self, node: KnowledgeNode) -> Result<(), ApplicationError>;

    fn replace_knowledge_node(
        &mut self,
        node: KnowledgeNode,
        expected_version: u64,
    ) -> Result<(), ApplicationError>;

    fn insert_knowledge_edge(&mut self, edge: KnowledgeEdge) -> Result<(), ApplicationError>;

    fn replace_knowledge_edge(
        &mut self,
        edge: KnowledgeEdge,
        expected_version: u64,
    ) -> Result<(), ApplicationError>;
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

pub trait TravelDisclosureRepository {
    fn append_travel_disclosure(
        &mut self,
        receipt: TravelDisclosureReceipt,
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

pub trait TripRepository {
    fn find_trip(
        &self,
        workspace_id: &WorkspaceId,
        trip_id: &EntityId,
    ) -> Result<Option<Trip>, ApplicationError>;

    fn list_trips_for_owner(
        &self,
        workspace_id: &WorkspaceId,
        owner_subject_id: &PrincipalId,
    ) -> Result<Vec<Trip>, ApplicationError>;
}

pub trait TripMutationRepository: TripRepository + EventRepository {
    fn insert_trip_with_event(
        &mut self,
        trip: Trip,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError>;

    fn replace_trip_with_event(
        &mut self,
        trip: Trip,
        expected_trip_version: u64,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError>;
}

pub trait BookingResearchRepository {
    fn find_booking_research(
        &self,
        workspace_id: &WorkspaceId,
        research_id: &BookingResearchId,
    ) -> Result<Option<BookingResearch>, ApplicationError>;

    fn list_booking_research_for_trip(
        &self,
        workspace_id: &WorkspaceId,
        trip_id: &EntityId,
    ) -> Result<Vec<BookingResearch>, ApplicationError>;
}

pub trait BookingResearchMutationRepository: BookingResearchRepository + EventRepository {
    fn insert_booking_research_with_event(
        &mut self,
        research: BookingResearch,
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

    fn replace_invitation(
        &mut self,
        invitation: Invitation,
        expected_status: InvitationStatus,
    ) -> Result<(), ApplicationError>;
}

pub trait ShareProposalRepository {
    fn insert_share_proposal(
        &mut self,
        proposal: MemoryShareProposal,
    ) -> Result<(), ApplicationError>;

    fn find_share_proposal(
        &self,
        source_workspace_id: &WorkspaceId,
        proposal_id: &ShareProposalId,
    ) -> Result<Option<MemoryShareProposal>, ApplicationError>;

    fn list_share_proposals_for_source(
        &self,
        source_workspace_id: &WorkspaceId,
        source_subject_id: &PrincipalId,
    ) -> Result<Vec<MemoryShareProposal>, ApplicationError>;

    fn replace_share_proposal(
        &mut self,
        proposal: MemoryShareProposal,
        expected_status: ShareProposalStatus,
    ) -> Result<(), ApplicationError>;
}

pub trait ShareProposalMutationRepository:
    ShareProposalRepository + MemoryRepository + EventRepository
{
    fn insert_share_proposal_with_event(
        &mut self,
        proposal: MemoryShareProposal,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError>;

    fn approve_share_proposal_with_copy(
        &mut self,
        proposal: MemoryShareProposal,
        expected_status: ShareProposalStatus,
        target_memory: MemoryRecord,
        source_event: CanonicalEvent,
        target_event: CanonicalEvent,
        projections: Vec<ProjectionJob>,
        expected_source_sequence: u64,
        expected_target_sequence: u64,
    ) -> Result<(), ApplicationError>;
}

pub trait MemberScopeGrantRepository {
    fn insert_member_scope_grant(
        &mut self,
        grant: MemberScopeGrant,
    ) -> Result<(), ApplicationError>;

    fn list_member_scope_grants(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Vec<MemberScopeGrant>, ApplicationError>;

    fn delete_member_scope_grant(
        &mut self,
        grant: &MemberScopeGrant,
    ) -> Result<(), ApplicationError>;
}

pub trait MemberLifecycleRepository {
    fn remove_member_and_scope_grants(
        &mut self,
        membership: Membership,
        expected_status: MembershipStatus,
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

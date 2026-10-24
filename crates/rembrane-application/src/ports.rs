use rembrane_contracts::{ChannelKind, ChannelSenderBinding, VerifiedChannelMessage};
use rembrane_domain::{
    ActivityCheckpoint, ActivityId, AdministrativeAuditEvent, BookingResearch, BookingResearchId,
    CanonicalEvent, CheckpointDisclosureReceipt, DisclosureReceipt, EntityId, GraphProjectionJob,
    Invitation, InvitationId, InvitationStatus, KeyRotationId, KeyRotationReceipt, KnowledgeEdge,
    KnowledgeEdgeId, KnowledgeNode, KnowledgeNodeId, LegalHoldId, MemberScopeGrant, Membership,
    MembershipStatus, MemoryId, MemoryRecord, MemoryShareProposal, Principal, PrincipalId,
    ProjectionJob, ProjectionJobId, ProjectionStatus, ProviderId, ShareProposalId,
    ShareProposalStatus, TravelDisclosureReceipt, Trip, Workspace, WorkspaceId,
    WorkspaceKeyRotation, WorkspaceLegalHold, WorkspaceRetentionPolicy,
};

use crate::ApplicationError;
use crate::{RetentionPurgePlan, RetentionPurgeResult};

pub const MAX_ADMINISTRATIVE_AUDIT_PAGE: usize = 1_000;

/// Durable replay protection for authenticated messaging-channel events.
///
/// Implementations must atomically reject duplicate `(channel, event_id)`
/// pairs across every workspace and must not persist message content.
pub trait ChannelReplayRepository {
    fn accept_channel_event(
        &mut self,
        message: &VerifiedChannelMessage,
        now_epoch_seconds: u64,
        replay_window_seconds: u64,
        maximum_events: usize,
    ) -> Result<(), ApplicationError>;
}

pub trait ChannelSenderBindingRepository {
    fn find_channel_sender_binding(
        &self,
        channel: ChannelKind,
        account_lookup_key: &str,
        sender_lookup_key: &str,
    ) -> Result<Option<ChannelSenderBinding>, ApplicationError>;

    fn insert_channel_sender_binding(
        &mut self,
        binding: ChannelSenderBinding,
    ) -> Result<(), ApplicationError>;
}

pub trait AdministrativeAuditRepository {
    fn append_administrative_audit(
        &mut self,
        event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError>;

    fn list_administrative_audit(
        &self,
        workspace_id: &WorkspaceId,
        after_epoch_seconds: u64,
        limit: usize,
    ) -> Result<Vec<AdministrativeAuditEvent>, ApplicationError>;
}

pub trait RetentionRepository {
    fn find_retention_policy(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<WorkspaceRetentionPolicy>, ApplicationError>;

    fn replace_retention_policy(
        &mut self,
        policy: WorkspaceRetentionPolicy,
        expected_version: Option<u64>,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError>;

    fn find_legal_hold(
        &self,
        workspace_id: &WorkspaceId,
        hold_id: &LegalHoldId,
    ) -> Result<Option<WorkspaceLegalHold>, ApplicationError>;

    fn list_active_legal_holds(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<WorkspaceLegalHold>, ApplicationError>;

    fn insert_legal_hold(
        &mut self,
        hold: WorkspaceLegalHold,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError>;

    fn replace_legal_hold(
        &mut self,
        hold: WorkspaceLegalHold,
        expected_version: u64,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError>;
}

pub trait RetentionPurgeRepository {
    fn execute_retention_purge(
        &mut self,
        plan: &RetentionPurgePlan,
    ) -> Result<RetentionPurgeResult, ApplicationError>;
}

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

pub trait CanonicalGraphMutationRepository:
    KnowledgeGraphMutationRepository + GraphProjectionOutboxRepository
{
    fn insert_knowledge_node_with_projections(
        &mut self,
        node: KnowledgeNode,
        projections: Vec<GraphProjectionJob>,
    ) -> Result<(), ApplicationError>;

    fn replace_knowledge_node_with_projections(
        &mut self,
        node: KnowledgeNode,
        expected_version: u64,
        projections: Vec<GraphProjectionJob>,
    ) -> Result<(), ApplicationError>;

    fn insert_knowledge_edge_with_projections(
        &mut self,
        edge: KnowledgeEdge,
        projections: Vec<GraphProjectionJob>,
    ) -> Result<(), ApplicationError>;

    fn replace_knowledge_edge_with_projections(
        &mut self,
        edge: KnowledgeEdge,
        expected_version: u64,
        projections: Vec<GraphProjectionJob>,
    ) -> Result<(), ApplicationError>;
}

pub trait DisclosureRepository {
    fn append(&mut self, receipt: DisclosureReceipt) -> Result<(), ApplicationError>;
}

/// Compile-time repository capability required by every context read path.
///
/// Adapters cannot be used for context resolution unless they also persist
/// the exact disclosure receipt produced by that operation.
pub trait ContextReadRepository: MemoryRepository + DisclosureRepository {}

impl<T> ContextReadRepository for T where T: MemoryRepository + DisclosureRepository {}

pub trait CheckpointDisclosureRepository {
    fn append_checkpoint_disclosure(
        &mut self,
        receipt: CheckpointDisclosureReceipt,
    ) -> Result<(), ApplicationError>;
}

pub trait CheckpointReadRepository:
    CheckpointMutationRepository + CheckpointDisclosureRepository
{
}

impl<T> CheckpointReadRepository for T where
    T: CheckpointMutationRepository + CheckpointDisclosureRepository
{
}

pub trait TravelDisclosureRepository {
    fn append_travel_disclosure(
        &mut self,
        receipt: TravelDisclosureReceipt,
    ) -> Result<(), ApplicationError>;
}

pub trait TravelContextRepository:
    TripRepository + BookingResearchRepository + TravelDisclosureRepository
{
}

impl<T> TravelContextRepository for T where
    T: TripRepository + BookingResearchRepository + TravelDisclosureRepository
{
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

    fn list_active_memberships(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<Membership>, ApplicationError>;

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
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError>;

    fn list_member_scope_grants(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Vec<MemberScopeGrant>, ApplicationError>;

    fn delete_member_scope_grant(
        &mut self,
        grant: &MemberScopeGrant,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError>;
}

pub trait MemberLifecycleRepository {
    fn remove_member_and_scope_grants(
        &mut self,
        membership: Membership,
        expected_status: MembershipStatus,
        rotation_id: KeyRotationId,
        requested_by: PrincipalId,
        audit_events: Vec<AdministrativeAuditEvent>,
    ) -> Result<(), ApplicationError>;
}

pub trait KeyRotationRepository {
    fn latest_key_rotation(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<WorkspaceKeyRotation>, ApplicationError>;

    fn find_key_rotation_receipt(
        &self,
        workspace_id: &WorkspaceId,
        rotation_id: &KeyRotationId,
    ) -> Result<Option<KeyRotationReceipt>, ApplicationError>;

    fn complete_key_rotation(
        &mut self,
        rotation: WorkspaceKeyRotation,
        receipt: KeyRotationReceipt,
        expected_generation: u64,
        audit_event: AdministrativeAuditEvent,
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

pub trait GraphProjectionOutboxRepository {
    fn enqueue_graph_projection(&mut self, job: GraphProjectionJob)
    -> Result<(), ApplicationError>;

    fn pending_graph_projections(
        &self,
        provider_id: &ProviderId,
        limit: usize,
    ) -> Result<Vec<GraphProjectionJob>, ApplicationError>;

    fn replace_graph_projection(
        &mut self,
        job: GraphProjectionJob,
        expected_status: ProjectionStatus,
        expected_attempts: u32,
    ) -> Result<(), ApplicationError>;

    fn find_graph_projection(
        &self,
        workspace_id: &WorkspaceId,
        job_id: &ProjectionJobId,
    ) -> Result<Option<GraphProjectionJob>, ApplicationError>;
}

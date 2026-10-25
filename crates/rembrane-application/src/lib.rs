//! Application use cases and provider ports.
//!
//! Infrastructure adapters implement these ports. Application code must not
//! depend on a concrete database, graph, vector store, or memory engine.

mod authorize_client;
mod booking_research;
mod channel_binding;
mod channel_gateway;
mod channel_inbox_administration;
mod channel_inbox_worker;
mod checkpoint;
mod error;
mod graph_projection_worker;
mod invitation;
mod member_lifecycle;
mod member_scope;
mod ports;
mod projection_worker;
mod propose_memory;
mod remember_preference;
mod remote_access;
mod remote_session;
mod resolve_context;
mod retention;
mod revise_memory;
mod semantic_context;
mod share_memory;
mod travel_context;
mod trip;

pub use authorize_client::{AuthorizeClientCommand, AuthorizeClientService, ClientGrantBundle};
pub use booking_research::{CaptureBookingResearchCommand, CaptureBookingResearchService};
pub use channel_binding::{
    ChannelBindingService, CreateChannelBindingCommand, RevokeChannelBindingCommand,
};
pub use channel_gateway::ChannelReplayGuard;
pub use channel_inbox_administration::{
    ChannelInboxAdministrationService, RequeueChannelMessageCommand,
};
pub use channel_inbox_worker::{ChannelDispatchReport, ChannelInboxWorker};
pub use checkpoint::{
    CheckpointService, CreateCheckpointCommand, ResumeActivityCommand, UpdateCheckpointCommand,
};
pub use error::ApplicationError;
pub use graph_projection_worker::GraphProjectionWorker;
pub use invitation::{
    AcceptInvitationCommand, CreateInvitationCommand, InvitationService, RevokeInvitationCommand,
};
pub use member_lifecycle::{
    CompleteKeyRotationCommand, MemberLifecycleService, RemoveMemberCommand,
};
pub use member_scope::{
    GrantMemberScopeCommand, MemberScopeGrantService, RevokeMemberScopeCommand,
};
pub use ports::{
    AdministrativeAuditRepository, BookingResearchMutationRepository, BookingResearchRepository,
    CanonicalGraphMutationRepository, CanonicalMutationRepository,
    ChannelInboxAdministrationRepository, ChannelInboxRepository, ChannelIngressRepository,
    ChannelMessageProcessor, ChannelReplayRepository, ChannelSenderBindingRepository,
    CheckpointDisclosureRepository, CheckpointMutationRepository, CheckpointReadRepository,
    CheckpointRepository, ContextReadRepository, DisclosureRepository,
    DurableChannelIngressRepository, EventRepository, GraphProjectionOutboxRepository,
    InvitationRepository, KeyRotationRepository, KnowledgeDirection,
    KnowledgeGraphMutationRepository, KnowledgeGraphRepository, MAX_ADMINISTRATIVE_AUDIT_PAGE,
    MAX_CHANNEL_INBOX_PAGE, MAX_KNOWLEDGE_NEIGHBOURS, MemberLifecycleRepository,
    MemberScopeGrantRepository, MembershipRepository, MemoryRepository, ProjectionOutboxRepository,
    RetentionPurgeRepository, RetentionRepository, ShareProposalMutationRepository,
    ShareProposalRepository, TravelContextRepository, TravelDisclosureRepository,
    TripMutationRepository, TripRepository, WorkspaceRepository,
};
pub use projection_worker::{ProjectionOutcome, ProjectionWorker};
pub use propose_memory::{ConfirmMemoryCommand, MemoryProposalService, ProposeMemoryCommand};
pub use remember_preference::{RememberPreferenceCommand, RememberPreferenceService};
pub use remote_access::{
    RemoteAccessAuthenticator, RemoteHttpAuthorization, RemoteHttpAuthorizationError,
    RemoteTokenVerificationError, RemoteTokenVerifier,
};
pub use remote_session::{RemoteSessionHttpError, RemoteSessionRegistry};
pub use resolve_context::{ResolveContextCommand, ResolveContextService};
pub use retention::{
    ExecuteRetentionPurgeCommand, PlaceLegalHoldCommand, ReleaseLegalHoldCommand,
    RetentionPurgePlan, RetentionPurgeResult, RetentionService, SetRetentionPolicyCommand,
};
pub use revise_memory::{DeleteMemoryCommand, MemoryLifecycleService, ReviseMemoryCommand};
pub use semantic_context::SemanticContextService;
pub use share_memory::{
    ApproveShareProposalCommand, CreateShareProposalCommand, MemoryShareService,
};
pub use travel_context::{
    ResolveTravelContextCommand, TravelContext, TravelContextResearch, TravelContextService,
    TravelContextTrip, TravelSensitiveProfile,
};
pub use trip::{
    AddTripConstraintCommand, AddTripParticipantCommand, CreateTripCommand,
    RecordTripDecisionCommand, ReplaceTripCommand, TripService,
};

/// Returns whether `candidate` is the unique representable successor.
///
/// This fails closed at `u64::MAX` instead of accepting a repeated saturated
/// version or sequence.
#[must_use]
pub const fn is_strict_successor(previous: u64, candidate: u64) -> bool {
    matches!(previous.checked_add(1), Some(next) if next == candidate)
}

#[cfg(test)]
mod progression_tests {
    use super::is_strict_successor;

    #[test]
    fn strict_successor_never_accepts_a_saturated_version() {
        assert!(is_strict_successor(41, 42));
        assert!(!is_strict_successor(41, 41));
        assert!(!is_strict_successor(u64::MAX, u64::MAX));
    }
}

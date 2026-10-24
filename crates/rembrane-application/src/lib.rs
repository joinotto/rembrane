//! Application use cases and provider ports.
//!
//! Infrastructure adapters implement these ports. Application code must not
//! depend on a concrete database, graph, vector store, or memory engine.

mod authorize_client;
mod booking_research;
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
pub use checkpoint::{
    CheckpointService, CreateCheckpointCommand, ResumeActivityCommand, UpdateCheckpointCommand,
};
pub use error::ApplicationError;
pub use graph_projection_worker::GraphProjectionWorker;
pub use invitation::{CreateInvitationCommand, InvitationService, RevokeInvitationCommand};
pub use member_lifecycle::{
    CompleteKeyRotationCommand, MemberLifecycleService, RemoveMemberCommand,
};
pub use member_scope::{
    GrantMemberScopeCommand, MemberScopeGrantService, RevokeMemberScopeCommand,
};
pub use ports::{
    AdministrativeAuditRepository, BookingResearchMutationRepository, BookingResearchRepository,
    CanonicalGraphMutationRepository, CanonicalMutationRepository, CheckpointDisclosureRepository,
    CheckpointMutationRepository, CheckpointRepository, DisclosureRepository, EventRepository,
    GraphProjectionOutboxRepository, InvitationRepository, KeyRotationRepository,
    KnowledgeDirection, KnowledgeGraphMutationRepository, KnowledgeGraphRepository,
    MAX_ADMINISTRATIVE_AUDIT_PAGE, MAX_KNOWLEDGE_NEIGHBOURS, MemberLifecycleRepository,
    MemberScopeGrantRepository, MembershipRepository, MemoryRepository, ProjectionOutboxRepository,
    RetentionRepository, ShareProposalMutationRepository, ShareProposalRepository,
    TravelDisclosureRepository, TripMutationRepository, TripRepository, WorkspaceRepository,
};
pub use projection_worker::{ProjectionOutcome, ProjectionWorker};
pub use propose_memory::{ConfirmMemoryCommand, MemoryProposalService, ProposeMemoryCommand};
pub use remember_preference::{RememberPreferenceCommand, RememberPreferenceService};
pub use remote_access::{
    RemoteAccessAuthenticator, RemoteHttpAuthorization, RemoteHttpAuthorizationError,
    RemoteTokenVerificationError, RemoteTokenVerifier,
};
pub use remote_session::RemoteSessionRegistry;
pub use resolve_context::{ResolveContextCommand, ResolveContextService};
pub use retention::{
    PlaceLegalHoldCommand, ReleaseLegalHoldCommand, RetentionService, SetRetentionPolicyCommand,
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

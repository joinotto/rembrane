//! Application use cases and provider ports.
//!
//! Infrastructure adapters implement these ports. Application code must not
//! depend on a concrete database, graph, vector store, or memory engine.

mod authorize_client;
mod booking_research;
mod checkpoint;
mod error;
mod invitation;
mod member_lifecycle;
mod member_scope;
mod ports;
mod projection_worker;
mod propose_memory;
mod remember_preference;
mod resolve_context;
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
pub use invitation::{CreateInvitationCommand, InvitationService, RevokeInvitationCommand};
pub use member_lifecycle::{MemberLifecycleService, RemoveMemberCommand};
pub use member_scope::{
    GrantMemberScopeCommand, MemberScopeGrantService, RevokeMemberScopeCommand,
};
pub use ports::{
    BookingResearchMutationRepository, BookingResearchRepository, CanonicalMutationRepository,
    CheckpointDisclosureRepository, CheckpointMutationRepository, CheckpointRepository,
    DisclosureRepository, EventRepository, InvitationRepository, MemberLifecycleRepository,
    MemberScopeGrantRepository, MembershipRepository, MemoryRepository, ProjectionOutboxRepository,
    ShareProposalMutationRepository, ShareProposalRepository, TravelDisclosureRepository,
    TripMutationRepository, TripRepository, WorkspaceRepository,
};
pub use projection_worker::{ProjectionOutcome, ProjectionWorker};
pub use propose_memory::{ConfirmMemoryCommand, MemoryProposalService, ProposeMemoryCommand};
pub use remember_preference::{RememberPreferenceCommand, RememberPreferenceService};
pub use resolve_context::{ResolveContextCommand, ResolveContextService};
pub use revise_memory::{DeleteMemoryCommand, MemoryLifecycleService, ReviseMemoryCommand};
pub use semantic_context::SemanticContextService;
pub use share_memory::{
    ApproveShareProposalCommand, CreateShareProposalCommand, MemoryShareService,
};
pub use travel_context::{ResolveTravelContextCommand, TravelContext, TravelContextService};
pub use trip::{CreateTripCommand, ReplaceTripCommand, TripService};

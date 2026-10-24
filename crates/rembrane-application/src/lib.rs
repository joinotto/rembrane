//! Application use cases and provider ports.
//!
//! Infrastructure adapters implement these ports. Application code must not
//! depend on a concrete database, graph, vector store, or memory engine.

mod authorize_client;
mod checkpoint;
mod error;
mod invitation;
mod ports;
mod projection_worker;
mod propose_memory;
mod remember_preference;
mod resolve_context;
mod revise_memory;
mod semantic_context;

pub use authorize_client::{AuthorizeClientCommand, AuthorizeClientService, ClientGrantBundle};
pub use checkpoint::{
    CheckpointService, CreateCheckpointCommand, ResumeActivityCommand, UpdateCheckpointCommand,
};
pub use error::ApplicationError;
pub use invitation::{CreateInvitationCommand, InvitationService, RevokeInvitationCommand};
pub use ports::{
    CanonicalMutationRepository, CheckpointDisclosureRepository, CheckpointMutationRepository,
    CheckpointRepository, DisclosureRepository, EventRepository, InvitationRepository,
    MembershipRepository, MemoryRepository, ProjectionOutboxRepository, WorkspaceRepository,
};
pub use projection_worker::{ProjectionOutcome, ProjectionWorker};
pub use propose_memory::{ConfirmMemoryCommand, MemoryProposalService, ProposeMemoryCommand};
pub use remember_preference::{RememberPreferenceCommand, RememberPreferenceService};
pub use resolve_context::{ResolveContextCommand, ResolveContextService};
pub use revise_memory::{DeleteMemoryCommand, MemoryLifecycleService, ReviseMemoryCommand};
pub use semantic_context::SemanticContextService;

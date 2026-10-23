//! Application use cases and provider ports.
//!
//! Infrastructure adapters implement these ports. Application code must not
//! depend on a concrete database, graph, vector store, or memory engine.

mod error;
mod checkpoint;
mod authorize_client;
mod ports;
mod propose_memory;
mod revise_memory;
mod resolve_context;
mod semantic_context;

pub use error::ApplicationError;
pub use checkpoint::{
    CheckpointService, CreateCheckpointCommand, ResumeActivityCommand,
    UpdateCheckpointCommand,
};
pub use authorize_client::{
    AuthorizeClientCommand, AuthorizeClientService, ClientGrantBundle,
};
pub use ports::{
    CheckpointRepository, DisclosureRepository, EventRepository,
    MembershipRepository, MemoryRepository,
};
pub use propose_memory::{
    ConfirmMemoryCommand, MemoryProposalService, ProposeMemoryCommand,
};
pub use revise_memory::{
    DeleteMemoryCommand, MemoryLifecycleService, ReviseMemoryCommand,
};
pub use resolve_context::{ResolveContextCommand, ResolveContextService};
pub use semantic_context::SemanticContextService;

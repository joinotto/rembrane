//! Application use cases and provider ports.
//!
//! Infrastructure adapters implement these ports. Application code must not
//! depend on a concrete database, graph, vector store, or memory engine.

mod error;
mod checkpoint;
mod ports;
mod revise_memory;
mod resolve_context;

pub use error::ApplicationError;
pub use checkpoint::{
    CheckpointService, CreateCheckpointCommand, ResumeActivityCommand,
    UpdateCheckpointCommand,
};
pub use ports::{
    CheckpointRepository, DisclosureRepository, EventRepository,
    MemoryRepository,
};
pub use revise_memory::{
    DeleteMemoryCommand, MemoryLifecycleService, ReviseMemoryCommand,
};
pub use resolve_context::{ResolveContextCommand, ResolveContextService};

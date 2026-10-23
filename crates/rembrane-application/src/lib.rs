//! Application use cases and provider ports.
//!
//! Infrastructure adapters implement these ports. Application code must not
//! depend on a concrete database, graph, vector store, or memory engine.

mod error;
mod ports;
mod resolve_context;

pub use error::ApplicationError;
pub use ports::{DisclosureRepository, MemoryRepository};
pub use resolve_context::{ResolveContextCommand, ResolveContextService};

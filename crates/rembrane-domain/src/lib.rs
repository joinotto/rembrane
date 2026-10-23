//! Provider-independent domain types for Rembrane.
//!
//! This crate deliberately has no database, network, model, or framework
//! dependencies. Adapters depend on the domain; the domain never depends on
//! adapters.

mod identifier;
mod memory;
mod scope;

pub use identifier::{
    ActivityId, DisclosureId, EntityId, EvidenceId, MemoryId, PrincipalId,
    WorkspaceId,
};
pub use memory::{MemoryKind, MemoryRecord, MemoryStatus};
pub use provenance::{EvidenceReference, EvidenceSource};
pub use scope::MemoryScope;

mod provenance;

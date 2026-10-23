//! Provider-independent domain types for Rembrane.
//!
//! This crate deliberately has no database, network, model, or framework
//! dependencies. Adapters depend on the domain; the domain never depends on
//! adapters.

mod identifier;
mod memory;
mod disclosure;
mod event;
mod grant;
mod scope;

pub use disclosure::{DisclosedMemory, DisclosureReceipt};
pub use event::{CanonicalEvent, EventError, EventPayload};
pub use grant::{ReadGrant, ReadScope};
pub use identifier::{
    ActivityId, ClientId, ContextPackId, DisclosureId, EntityId, EventId,
    EvidenceId, MemoryId, PrincipalId, WorkspaceId,
};
pub use memory::{
    MemoryKind, MemoryLifecycleError, MemoryRecord, MemoryStatus,
};
pub use provenance::{EvidenceReference, EvidenceSource};
pub use scope::MemoryScope;

mod provenance;

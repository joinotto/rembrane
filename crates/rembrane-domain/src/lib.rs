//! Provider-independent domain types for Rembrane.
//!
//! This crate deliberately has no database, network, model, or framework
//! dependencies. Adapters depend on the domain; the domain never depends on
//! adapters.

mod activity;
mod disclosure;
mod event;
mod grant;
mod identifier;
mod memory;
mod provenance;
mod projection;
mod scope;
mod workspace;

pub use activity::{ActivityCheckpoint, CheckpointError};
pub use disclosure::{DisclosedMemory, DisclosureReceipt};
pub use event::{CanonicalEvent, EventError, EventPayload};
pub use grant::{ReadGrant, ReadScope, WriteGrant, WritePermission};
pub use identifier::{
    ActivityId, CheckpointId, ClientId, ContextPackId, DisclosureId, EntityId,
    EventId, EvidenceId, MemoryId, PrincipalId, ProjectionJobId, ProviderId,
    WorkspaceId,
};
pub use memory::{
    MemoryKind, MemoryLifecycleError, MemoryRecord, MemoryStatus,
};
pub use provenance::{EvidenceReference, EvidenceSource};
pub use projection::{
    ProjectionJob, ProjectionJobError, ProjectionOperation,
    ProjectionStatus,
};
pub use scope::MemoryScope;
pub use workspace::{
    Membership, MembershipStatus, Principal, Workspace, WorkspaceKind,
    WorkspaceRole,
};

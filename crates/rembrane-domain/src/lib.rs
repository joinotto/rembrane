//! Provider-independent domain types for Rembrane.
//!
//! This crate deliberately has no database, network, model, or framework
//! dependencies. Adapters depend on the domain; the domain never depends on
//! adapters.

mod activity;
mod booking_research;
mod disclosure;
mod event;
mod grant;
mod identifier;
mod invitation;
mod member_scope;
mod memory;
mod projection;
mod provenance;
mod scope;
mod share_proposal;
mod trip;
mod workspace;

pub use activity::{ActivityCheckpoint, CheckpointError, MAX_CHECKPOINT_PAYLOAD_BYTES};
pub use booking_research::{
    BookingResearch, BookingResearchError, BookingResearchKind, ResearchFreshness,
};
pub use disclosure::{CheckpointDisclosureReceipt, DisclosedMemory, DisclosureReceipt};
pub use event::{CanonicalEvent, EventError, EventPayload};
pub use grant::{ReadGrant, ReadScope, WriteGrant, WritePermission};
pub use identifier::{
    ActivityId, BookingResearchId, CheckpointId, ClientId, ContextPackId, DisclosureId, EntityId,
    EventId, EvidenceId, InvitationId, MemoryId, PrincipalId, ProjectionJobId, ProviderId,
    ShareProposalId, TripConstraintId, TripDecisionId, TripParticipantId, WorkspaceId,
};
pub use invitation::{Invitation, InvitationError, InvitationStatus};
pub use member_scope::MemberScopeGrant;
pub use memory::{
    MAX_MEMORY_CONTENT_BYTES, MemoryKind, MemoryLifecycleError, MemoryRecord, MemoryStatus,
};
pub use projection::{ProjectionJob, ProjectionJobError, ProjectionOperation, ProjectionStatus};
pub use provenance::{EvidenceReference, EvidenceSource};
pub use scope::MemoryScope;
pub use share_proposal::{MemoryShareProposal, ShareProposalError, ShareProposalStatus};
pub use trip::{
    DecisionStatus, TravelDateWindow, Trip, TripConstraint, TripConstraintKind, TripDecision,
    TripError, TripParticipant,
};
pub use workspace::{
    Membership, MembershipStatus, Principal, Workspace, WorkspaceKind, WorkspaceRole,
};

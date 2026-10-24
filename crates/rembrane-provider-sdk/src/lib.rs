//! Stable boundaries for replaceable Rembrane providers.
//!
//! Provider implementations must not make authorization decisions. They
//! receive already authorized projections and return candidate identifiers
//! that the canonical core re-authorizes before disclosure.

mod capability;
mod error;
mod semantic;

pub use capability::{
    CURRENT_PROVIDER_PROTOCOL, Capability, ProviderLimits, ProviderManifest, ProviderPolicy,
    ProviderProtocolVersion,
};
pub use error::ProviderError;
pub use semantic::{
    AuthorizedMemoryProjection, CandidateMemory, SemanticMemoryProvider, SemanticQuery,
};

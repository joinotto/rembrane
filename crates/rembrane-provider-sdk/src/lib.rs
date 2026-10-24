//! Stable boundaries for replaceable Rembrane providers.
//!
//! Provider implementations must not make authorization decisions. They
//! receive already authorized projections and return candidate identifiers
//! that the canonical core re-authorizes before disclosure.

mod capability;
mod conformance;
mod error;
mod memory_context;
mod memory_protocol;
mod semantic;

pub use capability::{
    CURRENT_PROVIDER_PROTOCOL, Capability, ProviderLimits, ProviderManifest, ProviderPolicy,
    ProviderProtocolVersion,
};
pub use conformance::{ConformanceFailure, verify_semantic_provider};
pub use error::ProviderError;
pub use memory_context::{
    MAX_CONTEXT_PURPOSE_BYTES, MAX_CONTEXT_QUERY_BYTES, MemoryProviderContextSelector,
    ResolveContextPayload,
};
pub use memory_protocol::{
    CURRENT_MEMORY_PROVIDER_PROTOCOL, MEMORY_PROVIDER_DISCOVERY_PATH, MemoryProviderCapability,
    MemoryProviderErrorCode, MemoryProviderHttpMethod, MemoryProviderLimits,
    MemoryProviderManifest, MemoryProviderOperation, MemoryProviderPrivacyMode,
    MemoryProviderRequest, MemoryProviderRequestId, MemoryProviderResponse,
    MemoryProviderResponseBody, MemoryProviderScope, MemoryProviderTransport,
};
pub use semantic::{
    AuthorizedMemoryProjection, CandidateMemory, SemanticMemoryProvider, SemanticQuery,
};

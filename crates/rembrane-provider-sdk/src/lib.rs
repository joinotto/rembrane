//! Stable boundaries for replaceable Rembrane providers.
//!
//! Provider implementations must not make authorization decisions. They
//! receive already authorized projections and return candidate identifiers
//! that the canonical core re-authorizes before disclosure.

mod capability;
mod conformance;
mod error;
mod memory_checkpoint;
mod memory_context;
mod memory_disclosure;
mod memory_mutation;
mod memory_protocol;
mod semantic;

pub use capability::{
    CURRENT_PROVIDER_PROTOCOL, Capability, ProviderLimits, ProviderManifest, ProviderPolicy,
    ProviderProtocolVersion,
};
pub use conformance::{ConformanceFailure, verify_semantic_provider};
pub use error::ProviderError;
pub use memory_checkpoint::{CheckpointActivityPayload, CheckpointActivityResult};
pub use memory_context::{
    MAX_CONTEXT_PURPOSE_BYTES, MAX_CONTEXT_QUERY_BYTES, MemoryProviderContextItem,
    MemoryProviderContextSelector, MemoryProviderDisclosureConstraint, MemoryProviderSensitivity,
    ResolveContextPayload, ResolveContextResult,
};
pub use memory_disclosure::{
    MAX_DISCLOSED_MEMORIES, MAX_DISCLOSURE_PURPOSE_BYTES, MemoryProviderDisclosedMemory,
    RecordDisclosurePayload, RecordDisclosureResult,
};
pub use memory_mutation::{MAX_SOURCE_REFERENCE_BYTES, ProposeMemoryPayload, ProposeMemoryResult};
pub use memory_protocol::{
    CURRENT_MEMORY_PROVIDER_PROTOCOL, MEMORY_PROVIDER_DISCOVERY_PATH, MemoryProviderCapability,
    MemoryProviderErrorCode, MemoryProviderHttpMethod, MemoryProviderIdempotencyKey,
    MemoryProviderLimits, MemoryProviderManifest, MemoryProviderOperation,
    MemoryProviderPrivacyMode, MemoryProviderRequest, MemoryProviderRequestId,
    MemoryProviderResponse, MemoryProviderResponseBody, MemoryProviderScope,
    MemoryProviderTransport,
};
pub use semantic::{
    AuthorizedMemoryProjection, CandidateMemory, SemanticMemoryProvider, SemanticQuery,
};

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
mod memory_event;
mod memory_lifecycle;
mod memory_mutation;
mod memory_protocol;
mod memory_question;
mod memory_sync;
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
pub use memory_event::{
    MAX_EVENT_DATA_BYTES, MAX_EVENT_SOURCE_REFERENCE_BYTES, MAX_EVENT_TYPE_BYTES,
    MemoryProviderEvent, MemoryProviderRecordedEvent, RecordEventPayload, RecordEventResult,
};
pub use memory_lifecycle::{
    DeleteMemoryPayload, DeleteMemoryResult, ExplainMemoryPayload, ExplainMemoryResult,
    MAX_DELETE_REASON_BYTES, MAX_EXPLAIN_PURPOSE_BYTES, MAX_EXPLANATION_BYTES,
    MAX_EXPLANATION_EVIDENCE,
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
pub use memory_question::{
    MAX_QUESTION_BYTES, MAX_QUESTION_PURPOSE_BYTES, ResolveQuestionPayload, ResolveQuestionResult,
};
pub use memory_sync::{
    MAX_SYNC_BATCH_BYTES, MAX_SYNC_CURSOR_BYTES, MAX_SYNC_PAYLOAD_BYTES,
    MAX_SYNC_RESOURCE_ID_BYTES, MemoryProviderAcceptedMutation, MemoryProviderPulledChange,
    MemoryProviderPushMutation, MemoryProviderSyncCursor, MemoryProviderSyncOperation,
    MemoryProviderSyncResource, SyncPullPayload, SyncPullResult, SyncPushPayload, SyncPushResult,
};
pub use semantic::{
    AuthorizedMemoryProjection, CandidateMemory, SemanticMemoryProvider, SemanticQuery,
};

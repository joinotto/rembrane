use crate::{
    CheckpointActivityPayload, CheckpointActivityResult, DeleteMemoryPayload, DeleteMemoryResult,
    ExplainMemoryPayload, ExplainMemoryResult, MemoryProviderRequest, MemoryProviderResponse,
    ProposeMemoryPayload, ProposeMemoryResult, ProviderError, RecordDisclosurePayload,
    RecordDisclosureResult, RecordEventPayload, RecordEventResult, ResolveContextPayload,
    ResolveContextResult, ResolveQuestionPayload, ResolveQuestionResult, SyncPullPayload,
    SyncPullResult, SyncPushPayload, SyncPushResult,
};

/// Transport-neutral execution boundary for Memory Provider Protocol.
///
/// Requests have already been created by a negotiated
/// `MemoryProviderConnection`, preventing arbitrary payload/operation
/// pairings. Implementations remain responsible for authenticated transport,
/// correlation validation, response bounds, and canonical result decoding.
pub trait MemoryProviderClient: Send + Sync {
    fn resolve_context(
        &self,
        request: &MemoryProviderRequest<ResolveContextPayload>,
    ) -> Result<MemoryProviderResponse<ResolveContextResult>, ProviderError>;

    fn resolve_question(
        &self,
        request: &MemoryProviderRequest<ResolveQuestionPayload>,
    ) -> Result<MemoryProviderResponse<ResolveQuestionResult>, ProviderError>;

    fn propose_memory(
        &self,
        request: &MemoryProviderRequest<ProposeMemoryPayload>,
    ) -> Result<MemoryProviderResponse<ProposeMemoryResult>, ProviderError>;

    fn record_events(
        &self,
        request: &MemoryProviderRequest<RecordEventPayload>,
    ) -> Result<MemoryProviderResponse<RecordEventResult>, ProviderError>;

    fn checkpoint_activity(
        &self,
        request: &MemoryProviderRequest<CheckpointActivityPayload>,
    ) -> Result<MemoryProviderResponse<CheckpointActivityResult>, ProviderError>;

    fn record_disclosure(
        &self,
        request: &MemoryProviderRequest<RecordDisclosurePayload>,
    ) -> Result<MemoryProviderResponse<RecordDisclosureResult>, ProviderError>;

    fn delete_memory(
        &self,
        request: &MemoryProviderRequest<DeleteMemoryPayload>,
    ) -> Result<MemoryProviderResponse<DeleteMemoryResult>, ProviderError>;

    fn explain_memory(
        &self,
        request: &MemoryProviderRequest<ExplainMemoryPayload>,
    ) -> Result<MemoryProviderResponse<ExplainMemoryResult>, ProviderError>;

    fn sync_pull(
        &self,
        request: &MemoryProviderRequest<SyncPullPayload>,
    ) -> Result<MemoryProviderResponse<SyncPullResult>, ProviderError>;

    fn sync_push(
        &self,
        request: &MemoryProviderRequest<SyncPushPayload>,
    ) -> Result<MemoryProviderResponse<SyncPushResult>, ProviderError>;
}

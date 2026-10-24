use rembrane_application::{
    CanonicalMutationRepository, ProjectionOutboxRepository, ProjectionOutcome, ProjectionWorker,
};
use rembrane_domain::{
    CanonicalEvent, EventId, EventPayload, EvidenceId, EvidenceReference, EvidenceSource, MemoryId,
    MemoryRecord, MemoryScope, PrincipalId, ProjectionJob, ProjectionJobId, ProjectionOperation,
    ProjectionStatus, ProviderId, WorkspaceId,
};
use rembrane_provider_sdk::{
    AuthorizedMemoryProjection, CURRENT_PROVIDER_PROTOCOL, CandidateMemory, Capability,
    ProviderError, ProviderLimits, ProviderManifest, SemanticMemoryProvider, SemanticQuery,
};
use rembrane_semantic_native::NativeSemanticProvider;
use rembrane_store_memory::InMemoryStore;

fn memory() -> MemoryRecord {
    MemoryRecord::confirmed_preference(
        MemoryId::new("memory_01"),
        WorkspaceId::new("workspace_01"),
        PrincipalId::new("principal_01"),
        MemoryScope::Global,
        "Call me Hippo",
        EvidenceReference::new(
            EvidenceId::new("evidence_01"),
            EvidenceSource::UserStatement,
        ),
    )
    .expect("test memory should be valid")
}

fn event() -> CanonicalEvent {
    CanonicalEvent::new(
        EventId::new("event_01"),
        WorkspaceId::new("workspace_01"),
        PrincipalId::new("principal_01"),
        Some(PrincipalId::new("principal_01")),
        1,
        EventPayload::MemoryCreated {
            memory_id: MemoryId::new("memory_01"),
            version: 1,
        },
    )
    .expect("test event should be valid")
}

fn job() -> ProjectionJob {
    ProjectionJob::new(
        ProjectionJobId::new("projection_01"),
        WorkspaceId::new("workspace_01"),
        MemoryId::new("memory_01"),
        1,
        ProviderId::new("rembrane.native"),
        ProjectionOperation::Upsert,
    )
    .expect("test projection should be valid")
}

fn seeded_store() -> InMemoryStore {
    let mut store = InMemoryStore::new();
    store
        .insert_memory_with_event(memory(), event(), vec![job()], 0)
        .expect("atomic seed should succeed");
    store
}

#[test]
fn worker_indexes_canonical_memory_and_completes_job() {
    let mut store = seeded_store();
    let mut provider = NativeSemanticProvider::new();
    {
        let mut worker = ProjectionWorker::new(
            &mut store,
            &mut provider,
            ProviderId::new("rembrane.native"),
            3,
        )
        .expect("worker configuration should be valid");
        assert_eq!(
            worker.process_next().expect("worker should run"),
            ProjectionOutcome::Completed
        );
    }

    let results = provider
        .search(&SemanticQuery {
            workspace_id: WorkspaceId::new("workspace_01"),
            text: "Hippo".to_owned(),
            maximum_candidates: 10,
        })
        .expect("provider search should succeed");
    assert_eq!(results.len(), 1);
    assert_eq!(
        store
            .find_projection(
                &WorkspaceId::new("workspace_01"),
                &ProjectionJobId::new("projection_01"),
            )
            .expect("job lookup should succeed")
            .expect("job should exist")
            .status(),
        ProjectionStatus::Completed
    );
}

#[test]
fn stale_projection_is_completed_without_overwriting_provider() {
    let mut store = seeded_store();
    let revised = memory()
        .revise(
            "Call me Captain Hippo",
            EvidenceReference::new(
                EvidenceId::new("evidence_02"),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("revision should be valid");
    let revision_event = CanonicalEvent::new(
        EventId::new("event_02"),
        WorkspaceId::new("workspace_01"),
        PrincipalId::new("principal_01"),
        Some(PrincipalId::new("principal_01")),
        2,
        EventPayload::MemoryRevised {
            memory_id: MemoryId::new("memory_01"),
            version: 2,
        },
    )
    .expect("revision event should be valid");
    store
        .replace_memory_with_event(revised, 1, revision_event, Vec::new(), 1)
        .expect("test replacement should succeed");
    let mut provider = NativeSemanticProvider::new();

    let outcome = ProjectionWorker::new(
        &mut store,
        &mut provider,
        ProviderId::new("rembrane.native"),
        3,
    )
    .expect("worker configuration should be valid")
    .process_next()
    .expect("worker should run");

    assert_eq!(outcome, ProjectionOutcome::Superseded);
    assert_eq!(
        provider
            .search(&SemanticQuery {
                workspace_id: WorkspaceId::new("workspace_01"),
                text: "Hippo".to_owned(),
                maximum_candidates: 10,
            })
            .expect("provider search should succeed")
            .len(),
        0
    );
}

#[derive(Default)]
struct FailingProvider;

impl SemanticMemoryProvider for FailingProvider {
    fn manifest(&self) -> ProviderManifest {
        ProviderManifest {
            id: "rembrane.native".to_owned(),
            version: "test".to_owned(),
            protocol_version: CURRENT_PROVIDER_PROTOCOL,
            capabilities: vec![
                Capability::Index,
                Capability::Search,
                Capability::Delete,
                Capability::WorkspaceFilter,
                Capability::VersionedRecords,
            ],
            plaintext_processing: true,
            limits: ProviderLimits {
                maximum_batch_items: 1,
                maximum_content_bytes: 262_144,
                maximum_candidates: 1_000,
            },
        }
    }

    fn index(&mut self, _projection: AuthorizedMemoryProjection) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable)
    }

    fn search(&self, _query: &SemanticQuery) -> Result<Vec<CandidateMemory>, ProviderError> {
        Err(ProviderError::Unavailable)
    }

    fn delete(
        &mut self,
        _workspace_id: &WorkspaceId,
        _memory_id: &MemoryId,
        _through_version: u64,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Unavailable)
    }
}

#[test]
fn provider_failures_retry_then_quarantine() {
    let mut store = seeded_store();
    let mut provider = FailingProvider;

    for expected in [ProjectionOutcome::Retried, ProjectionOutcome::Quarantined] {
        let outcome = ProjectionWorker::new(
            &mut store,
            &mut provider,
            ProviderId::new("rembrane.native"),
            2,
        )
        .expect("worker configuration should be valid")
        .process_next()
        .expect("worker state transition should succeed");
        assert_eq!(outcome, expected);
    }

    let stored = store
        .find_projection(
            &WorkspaceId::new("workspace_01"),
            &ProjectionJobId::new("projection_01"),
        )
        .expect("job lookup should succeed")
        .expect("job should exist");
    assert_eq!(stored.status(), ProjectionStatus::Quarantined);
    assert_eq!(stored.attempts(), 2);
}

#[derive(Default)]
struct UndersizedProvider;

impl SemanticMemoryProvider for UndersizedProvider {
    fn manifest(&self) -> ProviderManifest {
        ProviderManifest {
            id: "undersized".to_owned(),
            version: "test".to_owned(),
            protocol_version: CURRENT_PROVIDER_PROTOCOL,
            capabilities: vec![
                Capability::Index,
                Capability::Search,
                Capability::Delete,
                Capability::WorkspaceFilter,
                Capability::VersionedRecords,
            ],
            plaintext_processing: true,
            limits: ProviderLimits {
                maximum_batch_items: 1,
                maximum_content_bytes: 1,
                maximum_candidates: 10,
            },
        }
    }

    fn index(&mut self, _projection: AuthorizedMemoryProjection) -> Result<(), ProviderError> {
        unreachable!("worker construction must reject this provider")
    }

    fn search(&self, _query: &SemanticQuery) -> Result<Vec<CandidateMemory>, ProviderError> {
        unreachable!("worker construction must reject this provider")
    }

    fn delete(
        &mut self,
        _workspace_id: &WorkspaceId,
        _memory_id: &MemoryId,
        _through_version: u64,
    ) -> Result<(), ProviderError> {
        unreachable!("worker construction must reject this provider")
    }
}

#[test]
fn worker_rejects_provider_below_canonical_content_limit() {
    let mut store = seeded_store();
    let mut provider = UndersizedProvider;

    let error = ProjectionWorker::new(&mut store, &mut provider, ProviderId::new("undersized"), 3)
        .err()
        .expect("undersized provider must fail before processing");

    assert_eq!(
        error,
        rembrane_application::ApplicationError::Validation(
            "provider content limit is below the canonical memory limit".to_owned()
        )
    );
}

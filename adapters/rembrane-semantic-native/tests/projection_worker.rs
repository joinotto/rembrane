use rembrane_application::{
    ApplicationError, CanonicalMutationRepository, MemoryRepository, ProjectionOutboxRepository,
    ProjectionOutcome, ProjectionWorker,
};
use rembrane_domain::{
    CanonicalEvent, EventId, EventPayload, EvidenceId, EvidenceReference, EvidenceSource, MemoryId,
    MemoryRecord, MemoryScope, MemoryStatus, PrincipalId, ProjectionJob, ProjectionJobId,
    ProjectionOperation, ProjectionStatus, ProviderId, WorkspaceId,
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

// Deliberately violate repository routing contracts to exercise the
// application boundary before any plaintext is passed to a provider.
struct MisroutedRepository {
    inner: InMemoryStore,
    memory_override: Option<MemoryRecord>,
    job_override: Option<ProjectionJob>,
}

impl MemoryRepository for MisroutedRepository {
    fn find(
        &self,
        workspace_id: &WorkspaceId,
        memory_id: &MemoryId,
    ) -> Result<Option<MemoryRecord>, ApplicationError> {
        self.memory_override.as_ref().map_or_else(
            || self.inner.find(workspace_id, memory_id),
            |memory| Ok(Some(memory.clone())),
        )
    }

    fn list_for_subject(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
    ) -> Result<Vec<MemoryRecord>, ApplicationError> {
        self.inner.list_for_subject(workspace_id, subject_id)
    }
}

impl ProjectionOutboxRepository for MisroutedRepository {
    fn enqueue_projection(&mut self, job: ProjectionJob) -> Result<(), ApplicationError> {
        self.inner.enqueue_projection(job)
    }

    fn pending_projections(
        &self,
        provider_id: &ProviderId,
        limit: usize,
    ) -> Result<Vec<ProjectionJob>, ApplicationError> {
        self.job_override.as_ref().map_or_else(
            || self.inner.pending_projections(provider_id, limit),
            |job| Ok(vec![job.clone()]),
        )
    }

    fn replace_projection(
        &mut self,
        job: ProjectionJob,
        expected_status: ProjectionStatus,
        expected_attempts: u32,
    ) -> Result<(), ApplicationError> {
        self.inner
            .replace_projection(job, expected_status, expected_attempts)
    }

    fn find_projection(
        &self,
        workspace_id: &WorkspaceId,
        job_id: &ProjectionJobId,
    ) -> Result<Option<ProjectionJob>, ApplicationError> {
        self.inner.find_projection(workspace_id, job_id)
    }
}

fn overridden_memory(workspace: &str, id: &str, status: MemoryStatus) -> MemoryRecord {
    let original = memory();
    MemoryRecord::restore(
        MemoryId::new(id),
        WorkspaceId::new(workspace),
        original.subject_id().clone(),
        original.scope().clone(),
        original.kind(),
        status,
        if status == MemoryStatus::Deleted {
            ""
        } else {
            "private Hippo material"
        },
        original.version(),
        original.evidence().to_vec(),
    )
    .expect("valid override fixture")
}

fn assert_provider_empty(provider: &NativeSemanticProvider) {
    for workspace in ["workspace_01", "workspace_foreign"] {
        assert!(
            provider
                .search(&SemanticQuery {
                    workspace_id: WorkspaceId::new(workspace),
                    text: "Hippo".to_owned(),
                    maximum_candidates: 10,
                })
                .expect("search")
                .is_empty()
        );
    }
}

#[test]
fn worker_quarantines_misrouted_canonical_identity_without_indexing() {
    for (workspace, id) in [
        ("workspace_foreign", "memory_01"),
        ("workspace_01", "memory_unrelated"),
    ] {
        let mut repository = MisroutedRepository {
            inner: seeded_store(),
            memory_override: Some(overridden_memory(workspace, id, MemoryStatus::Confirmed)),
            job_override: None,
        };
        let mut provider = NativeSemanticProvider::new();
        let outcome = ProjectionWorker::new(
            &mut repository,
            &mut provider,
            ProviderId::new("rembrane.native"),
            1,
        )
        .expect("worker")
        .process_next()
        .expect("quarantine transition");
        assert_provider_empty(&provider);
        assert_eq!(outcome, ProjectionOutcome::Quarantined);
        let stored = repository
            .find_projection(job().workspace_id(), job().id())
            .expect("lookup")
            .expect("job");
        assert_eq!(stored.status(), ProjectionStatus::Quarantined);
        assert_eq!(stored.attempts(), 1);
    }
}

#[test]
fn worker_never_indexes_unconfirmed_canonical_memory() {
    for status in [
        MemoryStatus::Proposed,
        MemoryStatus::Superseded,
        MemoryStatus::Deleted,
    ] {
        let mut repository = MisroutedRepository {
            inner: seeded_store(),
            memory_override: Some(overridden_memory("workspace_01", "memory_01", status)),
            job_override: None,
        };
        let mut provider = NativeSemanticProvider::new();
        let outcome = ProjectionWorker::new(
            &mut repository,
            &mut provider,
            ProviderId::new("rembrane.native"),
            1,
        )
        .expect("worker")
        .process_next()
        .expect("stale transition");
        assert_provider_empty(&provider);
        assert_eq!(outcome, ProjectionOutcome::Superseded);
    }
}

#[test]
fn worker_denies_other_provider_jobs_before_claim_or_provider_work() {
    for operation in [ProjectionOperation::Upsert, ProjectionOperation::Delete] {
        let foreign_job = ProjectionJob::new(
            ProjectionJobId::new("projection_other"),
            job().workspace_id().clone(),
            job().memory_id().clone(),
            1,
            ProviderId::new("provider_other"),
            operation,
        )
        .expect("foreign provider job");
        let mut inner = seeded_store();
        inner
            .enqueue_projection(foreign_job.clone())
            .expect("queue foreign provider job");
        let mut repository = MisroutedRepository {
            inner,
            memory_override: None,
            job_override: Some(foreign_job.clone()),
        };
        let mut provider = NativeSemanticProvider::new();
        if operation == ProjectionOperation::Delete {
            let canonical = memory();
            provider
                .index(AuthorizedMemoryProjection {
                    workspace_id: canonical.workspace_id().clone(),
                    memory_id: canonical.id().clone(),
                    version: canonical.version(),
                    scope: canonical.scope().clone(),
                    kind: canonical.kind(),
                    content: canonical.content().to_owned(),
                })
                .expect("prime legitimate provider record");
        }
        let outcome = ProjectionWorker::new(
            &mut repository,
            &mut provider,
            ProviderId::new("rembrane.native"),
            1,
        )
        .expect("worker")
        .process_next();
        assert_eq!(outcome, Err(ApplicationError::AccessDenied));
        if operation == ProjectionOperation::Delete {
            let candidates = provider
                .search(&SemanticQuery {
                    workspace_id: WorkspaceId::new("workspace_01"),
                    text: "Hippo".to_owned(),
                    maximum_candidates: 10,
                })
                .expect("legitimate record survives foreign-provider deletion");
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].memory_id, MemoryId::new("memory_01"));
        } else {
            assert_provider_empty(&provider);
        }
        let stored = repository
            .find_projection(foreign_job.workspace_id(), foreign_job.id())
            .expect("lookup")
            .expect("job");
        assert_eq!(stored.status(), ProjectionStatus::Pending);
        assert_eq!(stored.attempts(), 0);
    }
}

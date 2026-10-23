use rembrane_application::{
    CanonicalMutationRepository, CheckpointMutationRepository,
    CheckpointRepository, DisclosureRepository, EventRepository,
    MemoryRepository, ProjectionOutboxRepository, WorkspaceRepository,
};
use rembrane_crypto_rustcrypto::RustCryptoRecordCipher;
use rembrane_domain::{
    ActivityCheckpoint, ActivityId, CanonicalEvent, CheckpointId, ClientId,
    ContextPackId, DisclosedMemory, DisclosureId, DisclosureReceipt, EntityId,
    EventId, EventPayload, EvidenceId, EvidenceReference, EvidenceSource,
    Membership, MemoryId, MemoryRecord, MemoryScope, Principal, PrincipalId,
    ProjectionJob, ProjectionJobId, ProjectionOperation, ProjectionStatus,
    ProviderId, Workspace, WorkspaceId, WorkspaceRole,
};
use rembrane_store_sqlite::SqliteStore;

struct TemporaryDatabase(std::path::PathBuf);

impl TemporaryDatabase {
    fn new() -> Self {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock is valid")
            .as_nanos();
        Self(std::env::temp_dir().join(format!(
            "rembrane-{suffix}-{}.sqlite",
            std::process::id()
        )))
    }
}

impl Drop for TemporaryDatabase {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn test_cipher() -> RustCryptoRecordCipher {
    RustCryptoRecordCipher::new("test-key", [7; 32])
        .expect("test key is valid")
}

fn initialized_store() -> SqliteStore<RustCryptoRecordCipher> {
    let principal_id = PrincipalId::new("principal_01");
    let workspace_id = WorkspaceId::new("workspace_01");
    let mut store = SqliteStore::open_in_memory().expect("database opens");
    store
        .initialize_personal_workspace(
            Principal::new(principal_id.clone()),
            Workspace::personal(workspace_id.clone()),
            Membership::new(workspace_id, principal_id, WorkspaceRole::Owner),
        )
        .expect("workspace initializes");
    store.with_cipher(test_cipher())
}

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
    .expect("fixture is valid")
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
    .expect("fixture is valid")
}

fn projection() -> ProjectionJob {
    ProjectionJob::new(
        ProjectionJobId::new("projection_01"),
        WorkspaceId::new("workspace_01"),
        MemoryId::new("memory_01"),
        1,
        ProviderId::new("semantic.primary"),
        ProjectionOperation::Upsert,
    )
    .expect("fixture is valid")
}

fn checkpoint() -> ActivityCheckpoint {
    ActivityCheckpoint::new(
        CheckpointId::new("checkpoint_01"),
        WorkspaceId::new("workspace_01"),
        PrincipalId::new("principal_01"),
        ActivityId::new("activity_01"),
        Some(EntityId::new("project_01")),
        "Implement authentication",
        "Callback implemented and unit tested.",
        vec!["Run integration tests".to_owned()],
        Vec::new(),
    )
    .expect("fixture is valid")
}

fn checkpoint_event(sequence: u64, version: u64) -> CanonicalEvent {
    CanonicalEvent::new(
        EventId::new(format!("checkpoint_event_{sequence}")),
        WorkspaceId::new("workspace_01"),
        PrincipalId::new("principal_01"),
        Some(PrincipalId::new("principal_01")),
        sequence,
        EventPayload::ActivityCheckpointed {
            activity_id: ActivityId::new("activity_01"),
            version,
        },
    )
    .expect("fixture is valid")
}

#[test]
fn atomically_persists_and_decrypts_memory_and_event() {
    let mut store = initialized_store();
    let expected = memory();

    store
        .insert_memory_with_event(expected.clone(), event(), Vec::new(), 0)
        .expect("canonical mutation succeeds");

    let stored = store
        .find(
            &WorkspaceId::new("workspace_01"),
            &MemoryId::new("memory_01"),
        )
        .expect("memory lookup succeeds")
        .expect("memory exists");
    let events = store
        .list_events_since(&WorkspaceId::new("workspace_01"), 0)
        .expect("event lookup succeeds");

    assert_eq!(stored, expected);
    assert_eq!(events, vec![event()]);
}

#[test]
fn encrypted_memory_lookup_is_workspace_scoped() {
    let mut store = initialized_store();
    store
        .insert_memory_with_event(memory(), event(), Vec::new(), 0)
        .expect("canonical mutation succeeds");

    let leaked = store
        .find(
            &WorkspaceId::new("workspace_other"),
            &MemoryId::new("memory_01"),
        )
        .expect("lookup succeeds");

    assert!(leaked.is_none());
    assert!(store
        .list_for_subject(
            &WorkspaceId::new("workspace_01"),
            &PrincipalId::new("principal_other"),
        )
        .expect("subject-scoped lookup succeeds")
        .is_empty());
}

#[test]
fn event_and_checkpoint_reads_are_workspace_scoped() {
    let mut store = initialized_store();
    store
        .insert_checkpoint_with_event(
            checkpoint(),
            checkpoint_event(1, 1),
            0,
        )
        .expect("checkpoint insert succeeds");

    assert!(store
        .list_events_since(&WorkspaceId::new("workspace_other"), 0)
        .expect("event lookup succeeds")
        .is_empty());
    assert!(store
        .latest_checkpoint(
            &WorkspaceId::new("workspace_other"),
            &PrincipalId::new("principal_01"),
            &ActivityId::new("activity_01"),
        )
        .expect("checkpoint lookup succeeds")
        .is_none());
    assert!(store
        .latest_checkpoint(
            &WorkspaceId::new("workspace_01"),
            &PrincipalId::new("principal_other"),
            &ActivityId::new("activity_01"),
        )
        .expect("subject-scoped checkpoint lookup succeeds")
        .is_none());
}

#[test]
fn sequence_conflict_rolls_back_memory() {
    let mut store = initialized_store();

    let error = store
        .insert_memory_with_event(memory(), event(), Vec::new(), 1)
        .expect_err("incorrect expected sequence must fail");

    assert_eq!(
        error,
        rembrane_application::ApplicationError::SequenceConflict
    );
    assert!(store
        .find(
            &WorkspaceId::new("workspace_01"),
            &MemoryId::new("memory_01"),
        )
        .expect("lookup succeeds")
        .is_none());
}

#[test]
fn persists_and_optimistically_updates_projection() {
    let mut store = initialized_store();
    store
        .insert_memory_with_event(
            memory(),
            event(),
            vec![projection()],
            0,
        )
        .expect("canonical mutation succeeds");

    let pending = store
        .pending_projections(&ProviderId::new("semantic.primary"), 10)
        .expect("pending lookup succeeds");
    assert_eq!(pending, vec![projection()]);

    let processing = pending[0].clone().begin().expect("job begins");
    store
        .replace_projection(
            processing.clone(),
            ProjectionStatus::Pending,
            0,
        )
        .expect("optimistic update succeeds");

    assert_eq!(
        store
            .find_projection(
                &WorkspaceId::new("workspace_01"),
                &ProjectionJobId::new("projection_01"),
            )
            .expect("projection lookup succeeds"),
        Some(processing)
    );
    assert!(store
        .find_projection(
            &WorkspaceId::new("workspace_other"),
            &ProjectionJobId::new("projection_01"),
        )
        .expect("cross-workspace lookup succeeds")
        .is_none());
}

#[test]
fn persists_and_resumes_latest_encrypted_checkpoint() {
    let mut store = initialized_store();
    let first = checkpoint();
    store
        .insert_checkpoint_with_event(
            first.clone(),
            checkpoint_event(1, 1),
            0,
        )
        .expect("checkpoint insert succeeds");

    let updated = first
        .update(
            "Integration test exposed a refresh race.",
            vec!["Add refresh locking".to_owned()],
            vec!["Need a concurrency fixture".to_owned()],
        )
        .expect("checkpoint update succeeds");
    store
        .replace_checkpoint_with_event(
            updated.clone(),
            1,
            checkpoint_event(2, 2),
            1,
        )
        .expect("checkpoint update persists");

    let resumed = store
        .latest_checkpoint(
            &WorkspaceId::new("workspace_01"),
            &PrincipalId::new("principal_01"),
            &ActivityId::new("activity_01"),
        )
        .expect("checkpoint lookup succeeds");
    let all = store
        .list_checkpoints_for_subject(
            &WorkspaceId::new("workspace_01"),
            &PrincipalId::new("principal_01"),
        )
        .expect("checkpoint list succeeds");

    assert_eq!(resumed, Some(updated));
    assert_eq!(all, vec![updated]);
}

#[test]
fn persists_exact_disclosure_once() {
    let mut store = initialized_store();
    store
        .insert_memory_with_event(memory(), event(), Vec::new(), 0)
        .expect("canonical mutation succeeds");
    let receipt = DisclosureReceipt {
        id: DisclosureId::new("disclosure_01"),
        context_pack_id: ContextPackId::new("context_01"),
        workspace_id: WorkspaceId::new("workspace_01"),
        subject_id: PrincipalId::new("principal_01"),
        client_id: ClientId::new("assistant_01"),
        purpose: "personalize-assistant".to_owned(),
        memories: vec![DisclosedMemory {
            id: MemoryId::new("memory_01"),
            version: 1,
        }],
    };

    store
        .append(receipt.clone())
        .expect("first disclosure persists");
    let duplicate = store
        .append(receipt)
        .expect_err("same disclosure cannot be recorded twice");

    assert_eq!(
        duplicate,
        rembrane_application::ApplicationError::AlreadyExists
    );
}

#[test]
fn rejects_ciphertext_substituted_between_workspaces() {
    let database = TemporaryDatabase::new();
    let mut store = SqliteStore::open(&database.0).expect("database opens");
    for (workspace, principal) in [
        ("workspace_01", "principal_01"),
        ("workspace_02", "principal_02"),
    ] {
        store
            .initialize_personal_workspace(
                Principal::new(PrincipalId::new(principal)),
                Workspace::personal(WorkspaceId::new(workspace)),
                Membership::new(
                    WorkspaceId::new(workspace),
                    PrincipalId::new(principal),
                    WorkspaceRole::Owner,
                ),
            )
            .expect("workspace initializes");
    }
    let mut store = store.with_cipher(test_cipher());
    for (workspace, principal, event_id, content) in [
        (
            "workspace_01",
            "principal_01",
            "event_01",
            "Call me Hippo",
        ),
        (
            "workspace_02",
            "principal_02",
            "event_02",
            "Call me Rhino",
        ),
    ] {
        let memory = MemoryRecord::confirmed_preference(
            MemoryId::new("memory_shared"),
            WorkspaceId::new(workspace),
            PrincipalId::new(principal),
            MemoryScope::Global,
            content,
            EvidenceReference::new(
                EvidenceId::new("evidence_01"),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("memory is valid");
        let event = CanonicalEvent::new(
            EventId::new(event_id),
            WorkspaceId::new(workspace),
            PrincipalId::new(principal),
            Some(PrincipalId::new(principal)),
            1,
            EventPayload::MemoryCreated {
                memory_id: MemoryId::new("memory_shared"),
                version: 1,
            },
        )
        .expect("event is valid");
        store
            .insert_memory_with_event(memory, event, Vec::new(), 0)
            .expect("memory persists");
    }
    drop(store);

    let connection = rusqlite::Connection::open(&database.0)
        .expect("tamper connection opens");
    connection
        .execute(
            "UPDATE memories
             SET content_ciphertext = (
                    SELECT content_ciphertext
                    FROM memories
                    WHERE workspace_id = 'workspace_01'
                      AND id = 'memory_shared'
                 ),
                 encryption_key_id = (
                    SELECT encryption_key_id
                    FROM memories
                    WHERE workspace_id = 'workspace_01'
                      AND id = 'memory_shared'
                 ),
                 encryption_algorithm = (
                    SELECT encryption_algorithm
                    FROM memories
                    WHERE workspace_id = 'workspace_01'
                      AND id = 'memory_shared'
                 ),
                 encryption_nonce = (
                    SELECT encryption_nonce
                    FROM memories
                    WHERE workspace_id = 'workspace_01'
                      AND id = 'memory_shared'
                 )
             WHERE workspace_id = 'workspace_02'
               AND id = 'memory_shared'",
            [],
        )
        .expect("test substitution succeeds");
    drop(connection);

    let store = SqliteStore::open(&database.0)
        .expect("database reopens")
        .with_cipher(test_cipher());
    let error = store
        .find(
            &WorkspaceId::new("workspace_02"),
            &MemoryId::new("memory_shared"),
        )
        .expect_err("workspace-bound authentication must fail");

    assert_eq!(
        error,
        rembrane_application::ApplicationError::StorageUnavailable
    );
}

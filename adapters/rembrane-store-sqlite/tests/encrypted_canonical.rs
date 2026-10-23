use rembrane_application::{
    CanonicalMutationRepository, EventRepository, MemoryRepository,
    ProjectionOutboxRepository, WorkspaceRepository,
};
use rembrane_crypto::{
    CryptoError, EncryptedPayload, EncryptionContext, RecordCipher,
};
use rembrane_domain::{
    CanonicalEvent, EventId, EventPayload, EvidenceId, EvidenceReference,
    EvidenceSource, Membership, MemoryId, MemoryRecord, MemoryScope, Principal,
    PrincipalId, ProjectionJob, ProjectionJobId, ProjectionOperation,
    ProjectionStatus, ProviderId, Workspace, WorkspaceId, WorkspaceRole,
};
use rembrane_store_sqlite::SqliteStore;

struct TestAuthenticatedCipher;

impl RecordCipher for TestAuthenticatedCipher {
    fn seal(
        &self,
        context: &EncryptionContext,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, CryptoError> {
        let associated_data = context.associated_data();
        let mut ciphertext = Vec::with_capacity(
            associated_data.len().saturating_add(plaintext.len()),
        );
        ciphertext.extend_from_slice(&associated_data);
        ciphertext.extend_from_slice(plaintext);
        EncryptedPayload::new(
            ciphertext,
            "test-key",
            "test-authenticated",
            vec![0; 24],
        )
    }

    fn open(
        &self,
        context: &EncryptionContext,
        payload: &EncryptedPayload,
    ) -> Result<Vec<u8>, CryptoError> {
        if payload.key_id() != "test-key"
            || payload.algorithm() != "test-authenticated"
        {
            return Err(CryptoError::AuthenticationFailed);
        }
        let associated_data = context.associated_data();
        payload
            .ciphertext()
            .strip_prefix(&associated_data)
            .map(|plaintext| plaintext.to_vec())
            .ok_or(CryptoError::AuthenticationFailed)
    }
}

fn initialized_store() -> SqliteStore<TestAuthenticatedCipher> {
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
    store.with_cipher(TestAuthenticatedCipher)
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
            .find_projection(&ProjectionJobId::new("projection_01"))
            .expect("projection lookup succeeds"),
        Some(processing)
    );
}

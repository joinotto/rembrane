use rembrane_application::{
    ApplicationError, EventRepository, TripMutationRepository, TripRepository, WorkspaceRepository,
};
use rembrane_crypto_rustcrypto::RustCryptoRecordCipher;
use rembrane_domain::{
    CanonicalEvent, EntityId, EventId, EventPayload, Membership, Principal, PrincipalId,
    TravelDateWindow, Trip, TripParticipant, TripParticipantId, Workspace, WorkspaceId,
    WorkspaceRole,
};
use rembrane_store_sqlite::SqliteStore;

fn seeded_store() -> SqliteStore<RustCryptoRecordCipher> {
    let mut store = SqliteStore::open_in_memory().expect("database should open");
    for (workspace, principal) in [
        ("workspace_01", "principal_01"),
        ("workspace_02", "principal_02"),
    ] {
        let workspace_id = WorkspaceId::new(workspace);
        let principal_id = PrincipalId::new(principal);
        store
            .initialize_personal_workspace(
                Principal::new(principal_id.clone()),
                Workspace::personal(workspace_id.clone()),
                Membership::new(workspace_id, principal_id, WorkspaceRole::Owner),
            )
            .expect("workspace should initialize");
    }
    store.with_cipher(
        RustCryptoRecordCipher::new("test-key", [19; 32]).expect("test key should be valid"),
    )
}

fn trip(workspace: &str, owner: &str, id: &str) -> Trip {
    Trip::new(
        EntityId::new(id),
        WorkspaceId::new(workspace),
        PrincipalId::new(owner),
        "Autumn trip",
        "Bengaluru",
        vec!["Kyoto".to_owned()],
        TravelDateWindow::new("2026-11-01", "2026-11-12").expect("date window should be valid"),
    )
    .expect("trip should be valid")
}

fn trip_event(
    workspace: &str,
    owner: &str,
    event_id: &str,
    sequence: u64,
    trip_id: &str,
    version: u64,
    revision: bool,
) -> CanonicalEvent {
    let payload = if revision {
        EventPayload::TripRevised {
            trip_id: EntityId::new(trip_id),
            version,
        }
    } else {
        EventPayload::TripCreated {
            trip_id: EntityId::new(trip_id),
            version,
        }
    };
    CanonicalEvent::new(
        EventId::new(event_id),
        WorkspaceId::new(workspace),
        PrincipalId::new(owner),
        Some(PrincipalId::new(owner)),
        sequence,
        payload,
    )
    .expect("event should be valid")
}

#[test]
fn encrypted_trip_reads_remain_tenant_and_owner_scoped() {
    let mut store = seeded_store();
    let first = trip("workspace_01", "principal_01", "trip_01");
    let second = trip("workspace_02", "principal_02", "trip_01");
    store
        .insert_trip_with_event(
            first.clone(),
            trip_event(
                "workspace_01",
                "principal_01",
                "event_trip_01",
                1,
                "trip_01",
                1,
                false,
            ),
            0,
        )
        .expect("first trip should persist");
    store
        .insert_trip_with_event(
            second.clone(),
            trip_event(
                "workspace_02",
                "principal_02",
                "event_trip_02",
                1,
                "trip_01",
                1,
                false,
            ),
            0,
        )
        .expect("same trip id should be valid in another workspace");

    assert_eq!(
        store
            .find_trip(&WorkspaceId::new("workspace_01"), &EntityId::new("trip_01"))
            .expect("trip lookup should execute"),
        Some(first)
    );
    assert_eq!(
        store
            .find_trip(&WorkspaceId::new("workspace_02"), &EntityId::new("trip_01"))
            .expect("trip lookup should execute"),
        Some(second)
    );
    assert!(
        store
            .list_trips_for_owner(
                &WorkspaceId::new("workspace_01"),
                &PrincipalId::new("principal_02"),
            )
            .expect("owner lookup should execute")
            .is_empty()
    );
    assert!(
        store
            .find_trip(
                &WorkspaceId::new("workspace_missing"),
                &EntityId::new("trip_01"),
            )
            .expect("unknown tenant lookup should execute")
            .is_none()
    );
}

#[test]
fn sequence_conflict_rolls_back_encrypted_trip_insert() {
    let mut store = seeded_store();
    let candidate = trip("workspace_01", "principal_01", "trip_rollback");

    assert_eq!(
        store.insert_trip_with_event(
            candidate,
            trip_event(
                "workspace_01",
                "principal_01",
                "event_trip_rollback",
                2,
                "trip_rollback",
                1,
                false,
            ),
            1,
        ),
        Err(ApplicationError::SequenceConflict)
    );
    assert!(
        store
            .find_trip(
                &WorkspaceId::new("workspace_01"),
                &EntityId::new("trip_rollback"),
            )
            .expect("trip lookup should execute")
            .is_none()
    );
    assert!(
        store
            .list_events_since(&WorkspaceId::new("workspace_01"), 0)
            .expect("event lookup should execute")
            .is_empty()
    );
}

#[test]
fn encrypted_trip_revision_is_optimistic_and_atomic() {
    let mut store = seeded_store();
    let original = trip("workspace_01", "principal_01", "trip_revision");
    store
        .insert_trip_with_event(
            original.clone(),
            trip_event(
                "workspace_01",
                "principal_01",
                "event_trip_created",
                1,
                "trip_revision",
                1,
                false,
            ),
            0,
        )
        .expect("trip should persist");
    let revised = original
        .add_participant(
            TripParticipant::new(
                TripParticipantId::new("participant_01"),
                "Primary traveller",
            )
            .expect("participant should be valid"),
        )
        .expect("trip revision should be valid");
    store
        .replace_trip_with_event(
            revised.clone(),
            1,
            trip_event(
                "workspace_01",
                "principal_01",
                "event_trip_revised",
                2,
                "trip_revision",
                2,
                true,
            ),
            1,
        )
        .expect("current revision should persist");

    assert_eq!(
        store.replace_trip_with_event(
            revised.clone(),
            1,
            trip_event(
                "workspace_01",
                "principal_01",
                "event_trip_stale",
                3,
                "trip_revision",
                2,
                true,
            ),
            2,
        ),
        Err(ApplicationError::VersionConflict)
    );
    assert_eq!(
        store
            .find_trip(
                &WorkspaceId::new("workspace_01"),
                &EntityId::new("trip_revision"),
            )
            .expect("trip lookup should execute"),
        Some(revised)
    );
    assert_eq!(
        store
            .list_events_since(&WorkspaceId::new("workspace_01"), 0)
            .expect("event lookup should execute")
            .len(),
        2
    );
}

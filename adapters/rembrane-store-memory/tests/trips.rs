use rembrane_application::{
    ApplicationError, CreateTripCommand, EventRepository, ReplaceTripCommand, TripRepository,
    TripService, WorkspaceRepository,
};
use rembrane_domain::{
    ClientId, EntityId, EventId, Membership, Principal, PrincipalId, ReadScope, TravelDateWindow,
    Trip, TripParticipant, TripParticipantId, Workspace, WorkspaceId, WorkspaceRole, WriteGrant,
    WritePermission,
};
use rembrane_store_memory::InMemoryStore;

fn store() -> InMemoryStore {
    let principal = PrincipalId::new("principal_01");
    let workspace = WorkspaceId::new("workspace_01");
    let mut store = InMemoryStore::new();
    store
        .initialize_personal_workspace(
            Principal::new(principal.clone()),
            Workspace::personal(workspace.clone()),
            Membership::new(workspace, principal, WorkspaceRole::Owner),
        )
        .expect("workspace should initialize");
    store
}

fn trip() -> Trip {
    Trip::new(
        EntityId::new("trip_tokyo"),
        WorkspaceId::new("workspace_01"),
        PrincipalId::new("principal_01"),
        "Tokyo",
        "Delhi",
        vec!["Tokyo".to_owned()],
        TravelDateWindow::new("2027-03-10", "2027-03-20").expect("date window should be valid"),
    )
    .expect("trip should be valid")
}

fn grant(permission: WritePermission) -> WriteGrant {
    let scopes = if permission == WritePermission::CreateTrip {
        vec![ReadScope::Domain {
            name: "travel".to_owned(),
        }]
    } else {
        vec![ReadScope::Entity {
            id: EntityId::new("trip_tokyo"),
        }]
    };
    WriteGrant {
        client_id: ClientId::new("travel_agent"),
        workspace_id: WorkspaceId::new("workspace_01"),
        subject_id: PrincipalId::new("principal_01"),
        scopes,
        permissions: vec![permission],
    }
}

#[test]
fn creates_and_revises_trip_with_atomic_audit_events() {
    let mut store = store();
    let created = TripService::new(&mut store)
        .create(CreateTripCommand {
            grant: grant(WritePermission::CreateTrip),
            trip: trip(),
            event_id: EventId::new("event_trip_created"),
            expected_previous_sequence: 0,
        })
        .expect("authorized trip should persist");
    let revised = created
        .add_participant(
            TripParticipant::new(TripParticipantId::new("traveller_01"), "Hippo")
                .expect("participant should be valid"),
        )
        .expect("trip should revise");
    TripService::new(&mut store)
        .replace(ReplaceTripCommand {
            grant: grant(WritePermission::ReviseTrip),
            trip: revised.clone(),
            expected_trip_version: 1,
            event_id: EventId::new("event_trip_revised"),
            expected_previous_sequence: 1,
        })
        .expect("authorized revision should persist");

    assert_eq!(
        store
            .find_trip(
                &WorkspaceId::new("workspace_01"),
                &EntityId::new("trip_tokyo"),
            )
            .expect("trip lookup should run"),
        Some(revised)
    );
    assert_eq!(
        store
            .list_events_since(&WorkspaceId::new("workspace_01"), 0)
            .expect("events should list")
            .len(),
        2
    );
}

#[test]
fn denies_wrong_scope_and_rolls_back_sequence_conflict() {
    let mut store = store();
    let mut denied_grant = grant(WritePermission::CreateTrip);
    denied_grant.scopes = vec![ReadScope::Global];
    assert_eq!(
        TripService::new(&mut store).create(CreateTripCommand {
            grant: denied_grant,
            trip: trip(),
            event_id: EventId::new("event_denied"),
            expected_previous_sequence: 0,
        }),
        Err(ApplicationError::AccessDenied)
    );
    let mut entity_only = grant(WritePermission::CreateTrip);
    entity_only.scopes = vec![ReadScope::Entity {
        id: EntityId::new("trip_tokyo"),
    }];
    assert_eq!(
        TripService::new(&mut store).create(CreateTripCommand {
            grant: entity_only,
            trip: trip(),
            event_id: EventId::new("event_entity_only"),
            expected_previous_sequence: 0,
        }),
        Err(ApplicationError::AccessDenied)
    );

    TripService::new(&mut store)
        .create(CreateTripCommand {
            grant: grant(WritePermission::CreateTrip),
            trip: trip(),
            event_id: EventId::new("event_trip_created"),
            expected_previous_sequence: 0,
        })
        .expect("trip should persist");
    let revised = trip()
        .add_participant(
            TripParticipant::new(TripParticipantId::new("traveller_01"), "Hippo")
                .expect("participant should be valid"),
        )
        .expect("trip should revise");
    assert_eq!(
        TripService::new(&mut store).replace(ReplaceTripCommand {
            grant: grant(WritePermission::ReviseTrip),
            trip: revised,
            expected_trip_version: 1,
            event_id: EventId::new("event_conflict"),
            expected_previous_sequence: 0,
        }),
        Err(ApplicationError::SequenceConflict)
    );
    assert_eq!(
        store
            .find_trip(
                &WorkspaceId::new("workspace_01"),
                &EntityId::new("trip_tokyo"),
            )
            .expect("trip lookup should run")
            .expect("trip should remain")
            .version(),
        1
    );
}

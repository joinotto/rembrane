use rembrane_application::{
    AddTripConstraintCommand, AddTripParticipantCommand, ApplicationError, CreateTripCommand,
    EventRepository, RecordTripDecisionCommand, ReplaceTripCommand, TripRepository, TripService,
    WorkspaceRepository,
};
use rembrane_domain::{
    ClientId, DecisionStatus, EntityId, EventId, EvidenceId, EvidenceReference, EvidenceSource,
    Membership, Principal, PrincipalId, ReadScope, TravelDateWindow, Trip, TripConstraint,
    TripConstraintId, TripConstraintKind, TripDecision, TripDecisionId, TripParticipant,
    TripParticipantId, Workspace, WorkspaceId, WorkspaceRole, WriteGrant, WritePermission,
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

#[test]
fn narrow_participant_mutation_preserves_existing_trip_state() {
    let mut store = store();
    TripService::new(&mut store)
        .create(CreateTripCommand {
            grant: grant(WritePermission::CreateTrip),
            trip: trip(),
            event_id: EventId::new("event_trip_created"),
            expected_previous_sequence: 0,
        })
        .expect("trip should persist");

    let revised = TripService::new(&mut store)
        .add_participant(AddTripParticipantCommand {
            grant: grant(WritePermission::ReviseTrip),
            trip_id: EntityId::new("trip_tokyo"),
            participant: TripParticipant::new(TripParticipantId::new("traveller_01"), "Hippo")
                .expect("participant should be valid"),
            expected_trip_version: 1,
            event_id: EventId::new("event_participant_added"),
            expected_previous_sequence: 1,
        })
        .expect("narrow participant mutation should persist");

    assert_eq!(revised.title(), "Tokyo");
    assert_eq!(revised.destinations(), ["Tokyo"]);
    assert_eq!(revised.participants()[0].label(), "Hippo");
    assert_eq!(revised.version(), 2);

    let stale = TripService::new(&mut store).add_participant(AddTripParticipantCommand {
        grant: grant(WritePermission::ReviseTrip),
        trip_id: EntityId::new("trip_tokyo"),
        participant: TripParticipant::new(TripParticipantId::new("traveller_02"), "Friend")
            .expect("participant should be valid"),
        expected_trip_version: 1,
        event_id: EventId::new("event_stale_participant"),
        expected_previous_sequence: 2,
    });
    assert_eq!(stale, Err(ApplicationError::VersionConflict));
}

#[test]
fn narrow_constraint_and_decision_mutations_preserve_attribution() {
    let mut store = store();
    TripService::new(&mut store)
        .create(CreateTripCommand {
            grant: grant(WritePermission::CreateTrip),
            trip: trip(),
            event_id: EventId::new("event_trip_created"),
            expected_previous_sequence: 0,
        })
        .expect("trip should persist");
    let constrained = TripService::new(&mut store)
        .add_constraint(AddTripConstraintCommand {
            grant: grant(WritePermission::ReviseTrip),
            trip_id: EntityId::new("trip_tokyo"),
            constraint: TripConstraint::new(
                TripConstraintId::new("constraint_01"),
                None,
                TripConstraintKind::Budget,
                "Keep lodging below the approved nightly budget",
                EvidenceReference::new(
                    EvidenceId::new("evidence_constraint_01"),
                    EvidenceSource::UserStatement,
                ),
            )
            .expect("constraint should be valid"),
            expected_trip_version: 1,
            event_id: EventId::new("event_constraint_added"),
            expected_previous_sequence: 1,
        })
        .expect("constraint should persist");
    assert_eq!(constrained.version(), 2);

    let decided = TripService::new(&mut store)
        .record_decision(RecordTripDecisionCommand {
            grant: grant(WritePermission::ReviseTrip),
            trip_id: EntityId::new("trip_tokyo"),
            decision: TripDecision::new(
                TripDecisionId::new("decision_01"),
                DecisionStatus::Selected,
                "Stay near Tokyo Station",
                Some("Simplifies rail transfers".to_owned()),
                PrincipalId::new("principal_01"),
                EvidenceReference::new(
                    EvidenceId::new("evidence_decision_01"),
                    EvidenceSource::WorkspaceDecision,
                ),
            )
            .expect("decision should be valid"),
            expected_trip_version: 2,
            event_id: EventId::new("event_decision_recorded"),
            expected_previous_sequence: 2,
        })
        .expect("decision should persist");
    assert_eq!(decided.constraints().len(), 1);
    assert_eq!(decided.decisions()[0].decided_by().as_str(), "principal_01");
    assert_eq!(decided.version(), 3);

    let spoofed = TripService::new(&mut store).record_decision(RecordTripDecisionCommand {
        grant: grant(WritePermission::ReviseTrip),
        trip_id: EntityId::new("trip_tokyo"),
        decision: TripDecision::new(
            TripDecisionId::new("decision_spoofed"),
            DecisionStatus::Proposed,
            "Spoofed decision",
            None,
            PrincipalId::new("principal_other"),
            EvidenceReference::new(
                EvidenceId::new("evidence_spoofed"),
                EvidenceSource::AgentObservation,
            ),
        )
        .expect("decision shape should be valid"),
        expected_trip_version: 3,
        event_id: EventId::new("event_spoofed"),
        expected_previous_sequence: 3,
    });
    assert_eq!(spoofed, Err(ApplicationError::AccessDenied));
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

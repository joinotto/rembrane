use rembrane_application::{
    BookingResearchRepository, CaptureBookingResearchCommand, CaptureBookingResearchService,
    EventRepository, TripMutationRepository,
};
use rembrane_domain::{
    BookingResearch, BookingResearchId, BookingResearchKind, CanonicalEvent, ClientId, EntityId,
    EventId, EventPayload, EvidenceId, EvidenceReference, EvidenceSource, PrincipalId, ReadScope,
    TravelDateWindow, Trip, WorkspaceId, WriteGrant, WritePermission,
};
use rembrane_store_memory::InMemoryStore;

fn trip() -> Trip {
    Trip::new(
        EntityId::new("trip_01"),
        WorkspaceId::new("workspace_01"),
        PrincipalId::new("principal_01"),
        "Autumn trip",
        "Bengaluru",
        vec!["Kyoto".to_owned()],
        TravelDateWindow::new("2026-11-01", "2026-11-12").expect("date window should be valid"),
    )
    .expect("trip should be valid")
}

fn research() -> BookingResearch {
    BookingResearch::new(
        BookingResearchId::new("research_01"),
        WorkspaceId::new("workspace_01"),
        EntityId::new("trip_01"),
        PrincipalId::new("principal_01"),
        BookingResearchKind::Flight,
        "airline-search",
        "Nonstop morning option",
        "opaque-result-01",
        EvidenceReference::new(EvidenceId::new("evidence_01"), EvidenceSource::ToolResult),
        "2026-10-24T10:00:00Z",
        "2026-10-24T10:30:00Z",
    )
    .expect("research should be valid")
}

fn grant(trip_id: &str) -> WriteGrant {
    WriteGrant {
        client_id: ClientId::new("assistant_01"),
        workspace_id: WorkspaceId::new("workspace_01"),
        subject_id: PrincipalId::new("principal_01"),
        scopes: vec![ReadScope::Entity {
            id: EntityId::new(trip_id),
        }],
        permissions: vec![WritePermission::CaptureBookingResearch],
    }
}

fn store_with_trip() -> InMemoryStore {
    let mut store = InMemoryStore::default();
    store
        .insert_trip_with_event(
            trip(),
            CanonicalEvent::new(
                EventId::new("event_trip_01"),
                WorkspaceId::new("workspace_01"),
                PrincipalId::new("principal_01"),
                Some(PrincipalId::new("principal_01")),
                1,
                EventPayload::TripCreated {
                    trip_id: EntityId::new("trip_01"),
                    version: 1,
                },
            )
            .expect("trip event should be valid"),
            0,
        )
        .expect("trip should persist");
    store
}

#[test]
fn captures_evidence_backed_research_with_atomic_event() {
    let mut store = store_with_trip();
    let expected = research();
    let captured = CaptureBookingResearchService::new(&mut store)
        .execute(CaptureBookingResearchCommand {
            grant: grant("trip_01"),
            research: expected.clone(),
            event_id: EventId::new("event_research_01"),
            expected_previous_sequence: 1,
        })
        .expect("authorized research should persist");

    assert_eq!(captured, expected);
    assert_eq!(
        store
            .list_booking_research_for_trip(
                &WorkspaceId::new("workspace_01"),
                &EntityId::new("trip_01"),
            )
            .expect("research lookup should execute"),
        vec![expected]
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
fn denies_wrong_trip_scope_and_rolls_back_sequence_conflict() {
    let mut store = store_with_trip();
    assert_eq!(
        CaptureBookingResearchService::new(&mut store).execute(CaptureBookingResearchCommand {
            grant: grant("trip_other"),
            research: research(),
            event_id: EventId::new("event_research_denied"),
            expected_previous_sequence: 1,
        },),
        Err(rembrane_application::ApplicationError::AccessDenied)
    );
    assert_eq!(
        CaptureBookingResearchService::new(&mut store).execute(CaptureBookingResearchCommand {
            grant: grant("trip_01"),
            research: research(),
            event_id: EventId::new("event_research_conflict"),
            expected_previous_sequence: 0,
        },),
        Err(rembrane_application::ApplicationError::SequenceConflict)
    );
    assert_eq!(
        store
            .list_booking_research_for_trip(
                &WorkspaceId::new("workspace_01"),
                &EntityId::new("trip_01"),
            )
            .expect("research lookup should execute"),
        Vec::<BookingResearch>::new()
    );
}

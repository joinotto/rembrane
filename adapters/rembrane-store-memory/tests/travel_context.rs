use rembrane_application::{
    BookingResearchMutationRepository, ResolveTravelContextCommand, TravelContextService,
    TripMutationRepository,
};
use rembrane_domain::{
    BookingResearch, BookingResearchId, BookingResearchKind, CanonicalEvent, ClientId, EntityId,
    EventId, EventPayload, EvidenceId, EvidenceReference, EvidenceSource, PrincipalId, ReadGrant,
    ReadScope, TravelDateWindow, Trip, WorkspaceId,
};
use rembrane_store_memory::InMemoryStore;

fn trip() -> Trip {
    Trip::new(
        EntityId::new("trip_01"),
        WorkspaceId::new("workspace_01"),
        PrincipalId::new("principal_01"),
        "Kyoto",
        "Bengaluru",
        vec!["Kyoto".to_owned()],
        TravelDateWindow::new("2026-11-01", "2026-11-12").expect("date window should be valid"),
    )
    .expect("trip should be valid")
}

fn research(id: &str, expires_at: &str) -> BookingResearch {
    BookingResearch::new(
        BookingResearchId::new(id),
        WorkspaceId::new("workspace_01"),
        EntityId::new("trip_01"),
        PrincipalId::new("principal_01"),
        BookingResearchKind::Flight,
        "flight-search",
        format!("option {id}"),
        format!("opaque-{id}"),
        EvidenceReference::new(
            EvidenceId::new(format!("evidence_{id}")),
            EvidenceSource::ToolResult,
        ),
        "2026-10-24T09:00:00Z",
        expires_at,
    )
    .expect("research should be valid")
}

fn event(sequence: u64, payload: EventPayload) -> CanonicalEvent {
    CanonicalEvent::new(
        EventId::new(format!("event_{sequence}")),
        WorkspaceId::new("workspace_01"),
        PrincipalId::new("principal_01"),
        Some(PrincipalId::new("principal_01")),
        sequence,
        payload,
    )
    .expect("event should be valid")
}

fn seeded_store() -> InMemoryStore {
    let mut store = InMemoryStore::default();
    store
        .insert_trip_with_event(
            trip(),
            event(
                1,
                EventPayload::TripCreated {
                    trip_id: EntityId::new("trip_01"),
                    version: 1,
                },
            ),
            0,
        )
        .expect("trip should persist");
    for (sequence, item) in [
        (2, research("expired", "2026-10-24T09:30:00Z")),
        (3, research("fresh", "2026-10-24T11:00:00Z")),
    ] {
        store
            .insert_booking_research_with_event(
                item.clone(),
                event(
                    sequence,
                    EventPayload::BookingResearchCaptured {
                        research_id: item.id().clone(),
                        trip_id: item.trip_id().clone(),
                        version: 1,
                    },
                ),
                sequence - 1,
            )
            .expect("research should persist");
    }
    store
}

fn grant(trip_id: &str) -> ReadGrant {
    ReadGrant {
        client_id: ClientId::new("assistant_02"),
        workspace_id: WorkspaceId::new("workspace_01"),
        subject_id: PrincipalId::new("principal_01"),
        scopes: vec![ReadScope::Entity {
            id: EntityId::new(trip_id),
        }],
    }
}

#[test]
fn separates_fresh_and_expired_research_for_handoff() {
    let store = seeded_store();
    let context = TravelContextService::new(&store)
        .resolve(&ResolveTravelContextCommand {
            grant: grant("trip_01"),
            trip_id: EntityId::new("trip_01"),
            as_of: "2026-10-24T10:00:00Z".to_owned(),
        })
        .expect("authorized context should resolve");

    assert_eq!(context.trip.id().as_str(), "trip_01");
    assert_eq!(context.fresh_research[0].id().as_str(), "fresh");
    assert_eq!(context.expired_research[0].id().as_str(), "expired");
}

#[test]
fn rejects_another_trip_scope_and_invalid_clock() {
    let store = seeded_store();
    assert_eq!(
        TravelContextService::new(&store).resolve(&ResolveTravelContextCommand {
            grant: grant("trip_other"),
            trip_id: EntityId::new("trip_01"),
            as_of: "2026-10-24T10:00:00Z".to_owned(),
        }),
        Err(rembrane_application::ApplicationError::AccessDenied)
    );
    assert!(matches!(
        TravelContextService::new(&store).resolve(&ResolveTravelContextCommand {
            grant: grant("trip_01"),
            trip_id: EntityId::new("trip_01"),
            as_of: "not-a-timestamp".to_owned(),
        }),
        Err(rembrane_application::ApplicationError::Validation(_))
    ));
}

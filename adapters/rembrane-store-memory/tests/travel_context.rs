use rembrane_application::{
    BookingResearchMutationRepository, ResolveTravelContextCommand, TravelContextService,
    TripMutationRepository,
};
use rembrane_domain::{
    BookingResearch, BookingResearchId, BookingResearchKind, CanonicalEvent, ClientId,
    DisclosureId, EntityId, EventId, EventPayload, EvidenceId, EvidenceReference, EvidenceSource,
    PrincipalId, ReadGrant, ReadPermission, ReadScope, ResearchFreshness, TravelDateWindow, Trip,
    WorkspaceId,
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
    grant_for_subject(trip_id, "principal_01")
}

fn grant_for_subject(trip_id: &str, subject_id: &str) -> ReadGrant {
    ReadGrant {
        client_id: ClientId::new("assistant_02"),
        workspace_id: WorkspaceId::new("workspace_01"),
        subject_id: PrincipalId::new(subject_id),
        scopes: vec![ReadScope::Entity {
            id: EntityId::new(trip_id),
        }],
        permissions: Vec::new(),
    }
}

#[test]
fn exact_scope_allows_a_shared_workspace_reader_without_changing_trip_ownership() {
    let mut store = seeded_store();
    let context = TravelContextService::new(&mut store)
        .resolve(&ResolveTravelContextCommand {
            grant: grant_for_subject("trip_01", "principal_02"),
            disclosure_id: DisclosureId::new("disclosure_shared_reader"),
            trip_id: EntityId::new("trip_01"),
            purpose: "continue shared trip planning".to_owned(),
            as_of: "2026-10-24T10:00:00Z".to_owned(),
            include_source_references: false,
        })
        .expect("an exact entity grant should authorize the shared reader");

    assert_eq!(context.trip.owner_subject_id().as_str(), "principal_01");
    assert_eq!(
        store.travel_disclosures()[0].subject_id.as_str(),
        "principal_02"
    );
}

#[test]
fn separates_fresh_and_expired_research_for_handoff() {
    let mut store = seeded_store();
    let context = TravelContextService::new(&mut store)
        .resolve(&ResolveTravelContextCommand {
            grant: grant("trip_01"),
            disclosure_id: DisclosureId::new("disclosure_01"),
            trip_id: EntityId::new("trip_01"),
            purpose: "continue flight planning".to_owned(),
            as_of: "2026-10-24T10:00:00Z".to_owned(),
            include_source_references: false,
        })
        .expect("authorized context should resolve");

    assert_eq!(context.trip.id().as_str(), "trip_01");
    assert_eq!(context.fresh_research[0].id.as_str(), "fresh");
    assert_eq!(context.expired_research[0].id.as_str(), "expired");
    assert_eq!(context.fresh_research[0].source_reference, None);
    let receipt = &store.travel_disclosures()[0];
    assert_eq!(receipt.trip_version, 1);
    assert!(!receipt.source_references_included);
    assert_eq!(receipt.research.len(), 2);
    assert!(
        receipt.research.iter().any(|item| {
            item.id.as_str() == "fresh" && item.freshness == ResearchFreshness::Fresh
        })
    );
}

#[test]
fn rejects_another_trip_scope_and_invalid_clock() {
    let mut store = seeded_store();
    assert_eq!(
        TravelContextService::new(&mut store).resolve(&ResolveTravelContextCommand {
            grant: grant("trip_other"),
            disclosure_id: DisclosureId::new("disclosure_denied"),
            trip_id: EntityId::new("trip_01"),
            purpose: "continue planning".to_owned(),
            as_of: "2026-10-24T10:00:00Z".to_owned(),
            include_source_references: false,
        }),
        Err(rembrane_application::ApplicationError::AccessDenied)
    );
    assert!(matches!(
        TravelContextService::new(&mut store).resolve(&ResolveTravelContextCommand {
            grant: grant("trip_01"),
            disclosure_id: DisclosureId::new("disclosure_invalid"),
            trip_id: EntityId::new("trip_01"),
            purpose: "continue planning".to_owned(),
            as_of: "not-a-timestamp".to_owned(),
            include_source_references: false,
        }),
        Err(rembrane_application::ApplicationError::Validation(_))
    ));
    assert_eq!(store.travel_disclosures(), []);
}

#[test]
fn sensitive_source_reference_requires_explicit_request_and_permission() {
    let mut store = seeded_store();
    let mut authorized_grant = grant("trip_01");
    authorized_grant
        .permissions
        .push(ReadPermission::RevealTravelSourceReferences);
    let context = TravelContextService::new(&mut store)
        .resolve(&ResolveTravelContextCommand {
            grant: authorized_grant,
            disclosure_id: DisclosureId::new("disclosure_sensitive"),
            trip_id: EntityId::new("trip_01"),
            purpose: "reopen selected flight result".to_owned(),
            as_of: "2026-10-24T10:00:00Z".to_owned(),
            include_source_references: true,
        })
        .expect("explicitly authorized source reference should resolve");
    assert_eq!(
        context.fresh_research[0].source_reference.as_deref(),
        Some("opaque-fresh")
    );
    assert!(store.travel_disclosures()[0].source_references_included);

    let error = TravelContextService::new(&mut store)
        .resolve(&ResolveTravelContextCommand {
            grant: grant("trip_01"),
            disclosure_id: DisclosureId::new("disclosure_sensitive_denied"),
            trip_id: EntityId::new("trip_01"),
            purpose: "reopen selected flight result".to_owned(),
            as_of: "2026-10-24T10:00:00Z".to_owned(),
            include_source_references: true,
        })
        .expect_err("scope alone must not reveal a source reference");
    assert_eq!(error, rembrane_application::ApplicationError::AccessDenied);
}

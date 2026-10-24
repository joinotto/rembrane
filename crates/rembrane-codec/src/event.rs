use rembrane_domain::{
    ActivityId, BookingResearchId, CanonicalEvent, ContextPackId, DisclosureId, EntityId, EventId,
    EventPayload, EvidenceId, MemoryId, PrincipalId, ShareProposalId, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::CodecError;

const EVENT_FORMAT: &str = "rembrane.event";
const EVENT_FORMAT_V1: u16 = 1;
const EVENT_FORMAT_V2: u16 = 2;
const EVENT_FORMAT_V3: u16 = 3;
const EVENT_FORMAT_V4: u16 = 4;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EventEnvelope {
    format: String,
    version: u16,
    record: EventDto,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EventDto {
    id: String,
    workspace_id: String,
    actor_id: String,
    subject_id: Option<String>,
    sequence: u64,
    payload: EventPayloadDto,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "kebab-case")]
enum EventPayloadDto {
    MemoryProposed {
        memory_id: String,
        version: u64,
    },
    MemoryConfirmed {
        memory_id: String,
        version: u64,
    },
    MemoryCreated {
        memory_id: String,
        version: u64,
    },
    MemoryRevised {
        memory_id: String,
        version: u64,
    },
    MemoryDeleted {
        memory_id: String,
        version: u64,
    },
    MemoryShareProposed {
        proposal_id: String,
        source_memory_id: String,
        source_version: u64,
        target_workspace_id: String,
    },
    MemoryShareApproved {
        proposal_id: String,
        target_workspace_id: String,
        target_memory_id: String,
    },
    MemoryShareRejected {
        proposal_id: String,
    },
    MemoryShareRevoked {
        proposal_id: String,
    },
    MemorySharedIn {
        proposal_id: String,
        source_workspace_id: String,
        source_memory_id: String,
        source_version: u64,
        target_memory_id: String,
        target_version: u64,
    },
    TripCreated {
        trip_id: String,
        version: u64,
    },
    TripRevised {
        trip_id: String,
        version: u64,
    },
    BookingResearchCaptured {
        research_id: String,
        trip_id: String,
        version: u64,
    },
    ObservationCaptured {
        evidence_id: String,
    },
    ActivityCheckpointed {
        activity_id: String,
        version: u64,
    },
    DisclosureRecorded {
        disclosure_id: String,
        context_pack_id: String,
    },
}

pub fn encode_event(event: &CanonicalEvent) -> Result<Vec<u8>, CodecError> {
    let envelope = EventEnvelope {
        format: EVENT_FORMAT.to_owned(),
        version: event_format_version(event.payload()),
        record: EventDto::from(event),
    };

    serde_json::to_vec(&envelope).map_err(|_| CodecError::MalformedPayload)
}

pub fn decode_event(payload: &[u8]) -> Result<CanonicalEvent, CodecError> {
    let envelope: EventEnvelope =
        serde_json::from_slice(payload).map_err(|_| CodecError::MalformedPayload)?;
    if envelope.format != EVENT_FORMAT {
        return Err(CodecError::UnsupportedFormat);
    }
    if !matches!(
        envelope.version,
        EVENT_FORMAT_V1 | EVENT_FORMAT_V2 | EVENT_FORMAT_V3 | EVENT_FORMAT_V4
    ) || (envelope.version == EVENT_FORMAT_V1 && envelope.record.payload.is_share_event())
        || (envelope.version < EVENT_FORMAT_V3 && envelope.record.payload.is_trip_event())
        || (envelope.version < EVENT_FORMAT_V4
            && envelope.record.payload.is_booking_research_event())
    {
        return Err(CodecError::UnsupportedVersion);
    }

    CanonicalEvent::try_from(envelope.record)
}

impl From<&CanonicalEvent> for EventDto {
    fn from(event: &CanonicalEvent) -> Self {
        Self {
            id: event.id().as_str().to_owned(),
            workspace_id: event.workspace_id().as_str().to_owned(),
            actor_id: event.actor_id().as_str().to_owned(),
            subject_id: event
                .subject_id()
                .map(|subject| subject.as_str().to_owned()),
            sequence: event.sequence(),
            payload: EventPayloadDto::from(event.payload()),
        }
    }
}

const fn event_format_version(payload: &EventPayload) -> u16 {
    match payload {
        EventPayload::BookingResearchCaptured { .. } => EVENT_FORMAT_V4,
        EventPayload::TripCreated { .. } | EventPayload::TripRevised { .. } => EVENT_FORMAT_V3,
        EventPayload::MemoryShareProposed { .. }
        | EventPayload::MemoryShareApproved { .. }
        | EventPayload::MemoryShareRejected { .. }
        | EventPayload::MemoryShareRevoked { .. }
        | EventPayload::MemorySharedIn { .. } => EVENT_FORMAT_V2,
        _ => EVENT_FORMAT_V1,
    }
}

impl EventPayloadDto {
    const fn is_share_event(&self) -> bool {
        matches!(
            self,
            Self::MemoryShareProposed { .. }
                | Self::MemoryShareApproved { .. }
                | Self::MemoryShareRejected { .. }
                | Self::MemoryShareRevoked { .. }
                | Self::MemorySharedIn { .. }
        )
    }

    const fn is_trip_event(&self) -> bool {
        matches!(self, Self::TripCreated { .. } | Self::TripRevised { .. })
    }

    const fn is_booking_research_event(&self) -> bool {
        matches!(self, Self::BookingResearchCaptured { .. })
    }
}

impl TryFrom<EventDto> for CanonicalEvent {
    type Error = CodecError;

    fn try_from(event: EventDto) -> Result<Self, Self::Error> {
        Self::new(
            EventId::new(event.id),
            WorkspaceId::new(event.workspace_id),
            PrincipalId::new(event.actor_id),
            event.subject_id.map(PrincipalId::new),
            event.sequence,
            EventPayload::from(event.payload),
        )
        .map_err(|_| CodecError::InvalidDomainRecord)
    }
}

impl From<&EventPayload> for EventPayloadDto {
    fn from(payload: &EventPayload) -> Self {
        match payload {
            EventPayload::MemoryProposed { memory_id, version } => Self::MemoryProposed {
                memory_id: memory_id.as_str().to_owned(),
                version: *version,
            },
            EventPayload::MemoryConfirmed { memory_id, version } => Self::MemoryConfirmed {
                memory_id: memory_id.as_str().to_owned(),
                version: *version,
            },
            EventPayload::MemoryCreated { memory_id, version } => Self::MemoryCreated {
                memory_id: memory_id.as_str().to_owned(),
                version: *version,
            },
            EventPayload::MemoryRevised { memory_id, version } => Self::MemoryRevised {
                memory_id: memory_id.as_str().to_owned(),
                version: *version,
            },
            EventPayload::MemoryDeleted { memory_id, version } => Self::MemoryDeleted {
                memory_id: memory_id.as_str().to_owned(),
                version: *version,
            },
            EventPayload::MemoryShareProposed {
                proposal_id,
                source_memory_id,
                source_version,
                target_workspace_id,
            } => Self::MemoryShareProposed {
                proposal_id: proposal_id.as_str().to_owned(),
                source_memory_id: source_memory_id.as_str().to_owned(),
                source_version: *source_version,
                target_workspace_id: target_workspace_id.as_str().to_owned(),
            },
            EventPayload::MemoryShareApproved {
                proposal_id,
                target_workspace_id,
                target_memory_id,
            } => Self::MemoryShareApproved {
                proposal_id: proposal_id.as_str().to_owned(),
                target_workspace_id: target_workspace_id.as_str().to_owned(),
                target_memory_id: target_memory_id.as_str().to_owned(),
            },
            EventPayload::MemoryShareRejected { proposal_id } => Self::MemoryShareRejected {
                proposal_id: proposal_id.as_str().to_owned(),
            },
            EventPayload::MemoryShareRevoked { proposal_id } => Self::MemoryShareRevoked {
                proposal_id: proposal_id.as_str().to_owned(),
            },
            EventPayload::MemorySharedIn {
                proposal_id,
                source_workspace_id,
                source_memory_id,
                source_version,
                target_memory_id,
                target_version,
            } => Self::MemorySharedIn {
                proposal_id: proposal_id.as_str().to_owned(),
                source_workspace_id: source_workspace_id.as_str().to_owned(),
                source_memory_id: source_memory_id.as_str().to_owned(),
                source_version: *source_version,
                target_memory_id: target_memory_id.as_str().to_owned(),
                target_version: *target_version,
            },
            EventPayload::TripCreated { trip_id, version } => Self::TripCreated {
                trip_id: trip_id.as_str().to_owned(),
                version: *version,
            },
            EventPayload::TripRevised { trip_id, version } => Self::TripRevised {
                trip_id: trip_id.as_str().to_owned(),
                version: *version,
            },
            EventPayload::BookingResearchCaptured {
                research_id,
                trip_id,
                version,
            } => Self::BookingResearchCaptured {
                research_id: research_id.as_str().to_owned(),
                trip_id: trip_id.as_str().to_owned(),
                version: *version,
            },
            EventPayload::ObservationCaptured { evidence_id } => Self::ObservationCaptured {
                evidence_id: evidence_id.as_str().to_owned(),
            },
            EventPayload::ActivityCheckpointed {
                activity_id,
                version,
            } => Self::ActivityCheckpointed {
                activity_id: activity_id.as_str().to_owned(),
                version: *version,
            },
            EventPayload::DisclosureRecorded {
                disclosure_id,
                context_pack_id,
            } => Self::DisclosureRecorded {
                disclosure_id: disclosure_id.as_str().to_owned(),
                context_pack_id: context_pack_id.as_str().to_owned(),
            },
        }
    }
}

impl From<EventPayloadDto> for EventPayload {
    fn from(payload: EventPayloadDto) -> Self {
        match payload {
            EventPayloadDto::MemoryProposed { memory_id, version } => Self::MemoryProposed {
                memory_id: MemoryId::new(memory_id),
                version,
            },
            EventPayloadDto::MemoryConfirmed { memory_id, version } => Self::MemoryConfirmed {
                memory_id: MemoryId::new(memory_id),
                version,
            },
            EventPayloadDto::MemoryCreated { memory_id, version } => Self::MemoryCreated {
                memory_id: MemoryId::new(memory_id),
                version,
            },
            EventPayloadDto::MemoryRevised { memory_id, version } => Self::MemoryRevised {
                memory_id: MemoryId::new(memory_id),
                version,
            },
            EventPayloadDto::MemoryDeleted { memory_id, version } => Self::MemoryDeleted {
                memory_id: MemoryId::new(memory_id),
                version,
            },
            EventPayloadDto::MemoryShareProposed {
                proposal_id,
                source_memory_id,
                source_version,
                target_workspace_id,
            } => Self::MemoryShareProposed {
                proposal_id: ShareProposalId::new(proposal_id),
                source_memory_id: MemoryId::new(source_memory_id),
                source_version,
                target_workspace_id: WorkspaceId::new(target_workspace_id),
            },
            EventPayloadDto::MemoryShareApproved {
                proposal_id,
                target_workspace_id,
                target_memory_id,
            } => Self::MemoryShareApproved {
                proposal_id: ShareProposalId::new(proposal_id),
                target_workspace_id: WorkspaceId::new(target_workspace_id),
                target_memory_id: MemoryId::new(target_memory_id),
            },
            EventPayloadDto::MemoryShareRejected { proposal_id } => Self::MemoryShareRejected {
                proposal_id: ShareProposalId::new(proposal_id),
            },
            EventPayloadDto::MemoryShareRevoked { proposal_id } => Self::MemoryShareRevoked {
                proposal_id: ShareProposalId::new(proposal_id),
            },
            EventPayloadDto::MemorySharedIn {
                proposal_id,
                source_workspace_id,
                source_memory_id,
                source_version,
                target_memory_id,
                target_version,
            } => Self::MemorySharedIn {
                proposal_id: ShareProposalId::new(proposal_id),
                source_workspace_id: WorkspaceId::new(source_workspace_id),
                source_memory_id: MemoryId::new(source_memory_id),
                source_version,
                target_memory_id: MemoryId::new(target_memory_id),
                target_version,
            },
            EventPayloadDto::TripCreated { trip_id, version } => Self::TripCreated {
                trip_id: EntityId::new(trip_id),
                version,
            },
            EventPayloadDto::TripRevised { trip_id, version } => Self::TripRevised {
                trip_id: EntityId::new(trip_id),
                version,
            },
            EventPayloadDto::BookingResearchCaptured {
                research_id,
                trip_id,
                version,
            } => Self::BookingResearchCaptured {
                research_id: BookingResearchId::new(research_id),
                trip_id: EntityId::new(trip_id),
                version,
            },
            EventPayloadDto::ObservationCaptured { evidence_id } => Self::ObservationCaptured {
                evidence_id: EvidenceId::new(evidence_id),
            },
            EventPayloadDto::ActivityCheckpointed {
                activity_id,
                version,
            } => Self::ActivityCheckpointed {
                activity_id: ActivityId::new(activity_id),
                version,
            },
            EventPayloadDto::DisclosureRecorded {
                disclosure_id,
                context_pack_id,
            } => Self::DisclosureRecorded {
                disclosure_id: DisclosureId::new(disclosure_id),
                context_pack_id: ContextPackId::new(context_pack_id),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use rembrane_domain::{
        CanonicalEvent, EntityId, EventId, EventPayload, MemoryId, PrincipalId, ShareProposalId,
        WorkspaceId,
    };

    use super::{decode_event, encode_event};

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

    #[test]
    fn round_trips_memory_created_event() {
        let original = event();
        let encoded = encode_event(&original).expect("encoding succeeds");
        let decoded = decode_event(&encoded).expect("decoding succeeds");

        assert_eq!(decoded, original);
    }

    #[test]
    fn preserves_event_v1_wire_fixture() {
        let encoded = encode_event(&event()).expect("encoding succeeds");
        let expected = include_str!("../fixtures/event-v1-memory-created.json")
            .trim_end()
            .as_bytes();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn round_trips_share_event_as_wire_version_two() {
        let event = CanonicalEvent::new(
            EventId::new("event_share_01"),
            WorkspaceId::new("personal_01"),
            PrincipalId::new("principal_01"),
            Some(PrincipalId::new("principal_01")),
            2,
            EventPayload::MemoryShareApproved {
                proposal_id: ShareProposalId::new("share_01"),
                target_workspace_id: WorkspaceId::new("team_01"),
                target_memory_id: MemoryId::new("shared_memory_01"),
            },
        )
        .expect("share event should be valid");

        let encoded = encode_event(&event).expect("share event should encode");
        let wire = std::str::from_utf8(&encoded).expect("JSON should be UTF-8");
        assert!(wire.contains("\"version\":2"));
        assert_eq!(
            decode_event(&encoded).expect("share event should decode"),
            event
        );
    }

    #[test]
    fn rejects_share_variant_claiming_wire_version_one() {
        let payload = br#"{
            "format":"rembrane.event",
            "version":1,
            "record":{
                "id":"event_share_01",
                "workspace_id":"personal_01",
                "actor_id":"principal_01",
                "subject_id":"principal_01",
                "sequence":2,
                "payload":{
                    "type":"memory-share-rejected",
                    "proposal_id":"share_01"
                }
            }
        }"#;

        assert_eq!(
            decode_event(payload),
            Err(super::CodecError::UnsupportedVersion)
        );
    }

    #[test]
    fn round_trips_trip_event_as_wire_version_three() {
        let event = CanonicalEvent::new(
            EventId::new("event_trip_01"),
            WorkspaceId::new("personal_01"),
            PrincipalId::new("principal_01"),
            Some(PrincipalId::new("principal_01")),
            3,
            EventPayload::TripCreated {
                trip_id: EntityId::new("trip_01"),
                version: 1,
            },
        )
        .expect("trip event should be valid");

        let encoded = encode_event(&event).expect("trip event should encode");
        let wire = std::str::from_utf8(&encoded).expect("JSON should be UTF-8");
        assert!(wire.contains("\"version\":3"));
        assert_eq!(
            decode_event(&encoded).expect("trip event should decode"),
            event
        );
    }

    #[test]
    fn rejects_trip_variant_claiming_older_wire_version() {
        let payload = br#"{
            "format":"rembrane.event",
            "version":2,
            "record":{
                "id":"event_trip_01",
                "workspace_id":"personal_01",
                "actor_id":"principal_01",
                "subject_id":"principal_01",
                "sequence":3,
                "payload":{
                    "type":"trip-created",
                    "trip_id":"trip_01",
                    "version":1
                }
            }
        }"#;

        assert_eq!(
            decode_event(payload),
            Err(super::CodecError::UnsupportedVersion)
        );
    }
}

use rembrane_domain::{
    ActivityId, CanonicalEvent, ContextPackId, DisclosureId, EventId, EventPayload, EvidenceId,
    MemoryId, PrincipalId, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::CodecError;

const EVENT_FORMAT: &str = "rembrane.event";
const EVENT_FORMAT_VERSION: u16 = 1;

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
        version: EVENT_FORMAT_VERSION,
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
    if envelope.version != EVENT_FORMAT_VERSION {
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
        CanonicalEvent, EventId, EventPayload, MemoryId, PrincipalId, WorkspaceId,
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
}

use rembrane_domain::{
    BookingResearch, BookingResearchId, BookingResearchKind, EntityId, EvidenceId,
    EvidenceReference, EvidenceSource, PrincipalId, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::CodecError;

const BOOKING_RESEARCH_FORMAT: &str = "rembrane.booking-research";
const BOOKING_RESEARCH_FORMAT_VERSION: u16 = 1;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BookingResearchEnvelope {
    format: String,
    version: u16,
    record: BookingResearchDto,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BookingResearchDto {
    id: String,
    workspace_id: String,
    trip_id: String,
    observed_by: String,
    kind: BookingResearchKindDto,
    provider: String,
    summary: String,
    source_reference: String,
    evidence: EvidenceDto,
    observed_at: String,
    expires_at: String,
    record_version: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum BookingResearchKindDto {
    Flight,
    Lodging,
    GroundTransport,
    Activity,
    Other,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceDto {
    id: String,
    source: EvidenceSourceDto,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum EvidenceSourceDto {
    UserStatement,
    AgentObservation,
    ToolResult,
    ImportedRecord,
    WorkspaceDecision,
}

pub fn encode_booking_research(research: &BookingResearch) -> Result<Vec<u8>, CodecError> {
    serde_json::to_vec(&BookingResearchEnvelope {
        format: BOOKING_RESEARCH_FORMAT.to_owned(),
        version: BOOKING_RESEARCH_FORMAT_VERSION,
        record: BookingResearchDto::from(research),
    })
    .map_err(|_| CodecError::MalformedPayload)
}

pub fn decode_booking_research(payload: &[u8]) -> Result<BookingResearch, CodecError> {
    let envelope: BookingResearchEnvelope =
        serde_json::from_slice(payload).map_err(|_| CodecError::MalformedPayload)?;
    if envelope.format != BOOKING_RESEARCH_FORMAT {
        return Err(CodecError::UnsupportedFormat);
    }
    if envelope.version != BOOKING_RESEARCH_FORMAT_VERSION {
        return Err(CodecError::UnsupportedVersion);
    }
    BookingResearch::try_from(envelope.record)
}

impl From<&BookingResearch> for BookingResearchDto {
    fn from(research: &BookingResearch) -> Self {
        Self {
            id: research.id().as_str().to_owned(),
            workspace_id: research.workspace_id().as_str().to_owned(),
            trip_id: research.trip_id().as_str().to_owned(),
            observed_by: research.observed_by().as_str().to_owned(),
            kind: BookingResearchKindDto::from(research.kind()),
            provider: research.provider().to_owned(),
            summary: research.summary().to_owned(),
            source_reference: research.source_reference().to_owned(),
            evidence: EvidenceDto::from(research.evidence()),
            observed_at: research.observed_at().to_owned(),
            expires_at: research.expires_at().to_owned(),
            record_version: research.version(),
        }
    }
}

impl TryFrom<BookingResearchDto> for BookingResearch {
    type Error = CodecError;

    fn try_from(research: BookingResearchDto) -> Result<Self, Self::Error> {
        Self::restore(
            BookingResearchId::new(research.id),
            WorkspaceId::new(research.workspace_id),
            EntityId::new(research.trip_id),
            PrincipalId::new(research.observed_by),
            BookingResearchKind::from(research.kind),
            research.provider,
            research.summary,
            research.source_reference,
            EvidenceReference::from(research.evidence),
            research.observed_at,
            research.expires_at,
            research.record_version,
        )
        .map_err(|_| CodecError::InvalidDomainRecord)
    }
}

impl From<BookingResearchKind> for BookingResearchKindDto {
    fn from(kind: BookingResearchKind) -> Self {
        match kind {
            BookingResearchKind::Flight => Self::Flight,
            BookingResearchKind::Lodging => Self::Lodging,
            BookingResearchKind::GroundTransport => Self::GroundTransport,
            BookingResearchKind::Activity => Self::Activity,
            BookingResearchKind::Other => Self::Other,
        }
    }
}

impl From<BookingResearchKindDto> for BookingResearchKind {
    fn from(kind: BookingResearchKindDto) -> Self {
        match kind {
            BookingResearchKindDto::Flight => Self::Flight,
            BookingResearchKindDto::Lodging => Self::Lodging,
            BookingResearchKindDto::GroundTransport => Self::GroundTransport,
            BookingResearchKindDto::Activity => Self::Activity,
            BookingResearchKindDto::Other => Self::Other,
        }
    }
}

impl From<&EvidenceReference> for EvidenceDto {
    fn from(evidence: &EvidenceReference) -> Self {
        Self {
            id: evidence.id.as_str().to_owned(),
            source: EvidenceSourceDto::from(evidence.source),
        }
    }
}

impl From<EvidenceDto> for EvidenceReference {
    fn from(evidence: EvidenceDto) -> Self {
        Self::new(
            EvidenceId::new(evidence.id),
            EvidenceSource::from(evidence.source),
        )
    }
}

impl From<EvidenceSource> for EvidenceSourceDto {
    fn from(source: EvidenceSource) -> Self {
        match source {
            EvidenceSource::UserStatement => Self::UserStatement,
            EvidenceSource::AgentObservation => Self::AgentObservation,
            EvidenceSource::ToolResult => Self::ToolResult,
            EvidenceSource::ImportedRecord => Self::ImportedRecord,
            EvidenceSource::WorkspaceDecision => Self::WorkspaceDecision,
        }
    }
}

impl From<EvidenceSourceDto> for EvidenceSource {
    fn from(source: EvidenceSourceDto) -> Self {
        match source {
            EvidenceSourceDto::UserStatement => Self::UserStatement,
            EvidenceSourceDto::AgentObservation => Self::AgentObservation,
            EvidenceSourceDto::ToolResult => Self::ToolResult,
            EvidenceSourceDto::ImportedRecord => Self::ImportedRecord,
            EvidenceSourceDto::WorkspaceDecision => Self::WorkspaceDecision,
        }
    }
}

#[cfg(test)]
mod tests {
    use rembrane_domain::{
        BookingResearch, BookingResearchId, BookingResearchKind, EntityId, EvidenceId,
        EvidenceReference, EvidenceSource, PrincipalId, WorkspaceId,
    };

    use super::{decode_booking_research, encode_booking_research};

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
        .expect("fixture should be valid")
    }

    #[test]
    fn round_trips_booking_research() {
        let original = research();
        let encoded = encode_booking_research(&original).expect("encoding should succeed");

        assert_eq!(
            decode_booking_research(&encoded).expect("decoding should succeed"),
            original
        );
    }

    #[test]
    fn rejects_zero_record_version() {
        let encoded = encode_booking_research(&research()).expect("encoding should succeed");
        let invalid = String::from_utf8(encoded)
            .expect("JSON should be UTF-8")
            .replace("\"record_version\":1", "\"record_version\":0");

        assert_eq!(
            decode_booking_research(invalid.as_bytes()),
            Err(crate::CodecError::InvalidDomainRecord)
        );
    }
}

use rembrane_domain::{
    DecisionStatus, EntityId, EvidenceId, EvidenceReference, EvidenceSource, PrincipalId,
    TravelDateWindow, Trip, TripConstraint, TripConstraintId, TripConstraintKind, TripDecision,
    TripDecisionId, TripParticipant, TripParticipantId, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use crate::CodecError;

const TRIP_FORMAT: &str = "rembrane.trip";
const TRIP_FORMAT_VERSION: u16 = 1;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TripEnvelope {
    format: String,
    version: u16,
    record: TripDto,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TripDto {
    id: String,
    workspace_id: String,
    owner_subject_id: String,
    title: String,
    origin: String,
    destinations: Vec<String>,
    date_window: DateWindowDto,
    participants: Vec<ParticipantDto>,
    constraints: Vec<ConstraintDto>,
    decisions: Vec<DecisionDto>,
    record_version: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DateWindowDto {
    depart_not_before: String,
    return_not_after: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ParticipantDto {
    id: String,
    label: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConstraintDto {
    id: String,
    participant_id: Option<String>,
    kind: ConstraintKindDto,
    statement: String,
    evidence: EvidenceDto,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ConstraintKindDto {
    Accessibility,
    Accommodation,
    Budget,
    Dietary,
    Documentation,
    Schedule,
    Transport,
    Other,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DecisionDto {
    id: String,
    status: DecisionStatusDto,
    summary: String,
    rationale: Option<String>,
    decided_by: String,
    evidence: EvidenceDto,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DecisionStatusDto {
    Proposed,
    Selected,
    Rejected,
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

pub fn encode_trip(trip: &Trip) -> Result<Vec<u8>, CodecError> {
    serde_json::to_vec(&TripEnvelope {
        format: TRIP_FORMAT.to_owned(),
        version: TRIP_FORMAT_VERSION,
        record: TripDto::from(trip),
    })
    .map_err(|_| CodecError::MalformedPayload)
}

pub fn decode_trip(payload: &[u8]) -> Result<Trip, CodecError> {
    let envelope: TripEnvelope =
        serde_json::from_slice(payload).map_err(|_| CodecError::MalformedPayload)?;
    if envelope.format != TRIP_FORMAT {
        return Err(CodecError::UnsupportedFormat);
    }
    if envelope.version != TRIP_FORMAT_VERSION {
        return Err(CodecError::UnsupportedVersion);
    }
    Trip::try_from(envelope.record)
}

impl From<&Trip> for TripDto {
    fn from(trip: &Trip) -> Self {
        Self {
            id: trip.id().as_str().to_owned(),
            workspace_id: trip.workspace_id().as_str().to_owned(),
            owner_subject_id: trip.owner_subject_id().as_str().to_owned(),
            title: trip.title().to_owned(),
            origin: trip.origin().to_owned(),
            destinations: trip.destinations().to_vec(),
            date_window: DateWindowDto {
                depart_not_before: trip.date_window().depart_not_before().to_owned(),
                return_not_after: trip.date_window().return_not_after().to_owned(),
            },
            participants: trip
                .participants()
                .iter()
                .map(ParticipantDto::from)
                .collect(),
            constraints: trip.constraints().iter().map(ConstraintDto::from).collect(),
            decisions: trip.decisions().iter().map(DecisionDto::from).collect(),
            record_version: trip.version(),
        }
    }
}

impl TryFrom<TripDto> for Trip {
    type Error = CodecError;

    fn try_from(trip: TripDto) -> Result<Self, Self::Error> {
        let date_window = TravelDateWindow::new(
            trip.date_window.depart_not_before,
            trip.date_window.return_not_after,
        )
        .map_err(|_| CodecError::InvalidDomainRecord)?;
        let participants = trip
            .participants
            .into_iter()
            .map(TripParticipant::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let constraints = trip
            .constraints
            .into_iter()
            .map(TripConstraint::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let decisions = trip
            .decisions
            .into_iter()
            .map(TripDecision::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Trip::restore(
            EntityId::new(trip.id),
            WorkspaceId::new(trip.workspace_id),
            PrincipalId::new(trip.owner_subject_id),
            trip.title,
            trip.origin,
            trip.destinations,
            date_window,
            participants,
            constraints,
            decisions,
            trip.record_version,
        )
        .map_err(|_| CodecError::InvalidDomainRecord)
    }
}

impl From<&TripParticipant> for ParticipantDto {
    fn from(participant: &TripParticipant) -> Self {
        Self {
            id: participant.id().as_str().to_owned(),
            label: participant.label().to_owned(),
        }
    }
}

impl TryFrom<ParticipantDto> for TripParticipant {
    type Error = CodecError;

    fn try_from(participant: ParticipantDto) -> Result<Self, Self::Error> {
        Self::new(TripParticipantId::new(participant.id), participant.label)
            .map_err(|_| CodecError::InvalidDomainRecord)
    }
}

impl From<&TripConstraint> for ConstraintDto {
    fn from(constraint: &TripConstraint) -> Self {
        Self {
            id: constraint.id().as_str().to_owned(),
            participant_id: constraint.participant_id().map(|id| id.as_str().to_owned()),
            kind: ConstraintKindDto::from(constraint.kind()),
            statement: constraint.statement().to_owned(),
            evidence: EvidenceDto::from(constraint.evidence()),
        }
    }
}

impl TryFrom<ConstraintDto> for TripConstraint {
    type Error = CodecError;

    fn try_from(constraint: ConstraintDto) -> Result<Self, Self::Error> {
        Self::new(
            TripConstraintId::new(constraint.id),
            constraint.participant_id.map(TripParticipantId::new),
            TripConstraintKind::from(constraint.kind),
            constraint.statement,
            EvidenceReference::from(constraint.evidence),
        )
        .map_err(|_| CodecError::InvalidDomainRecord)
    }
}

impl From<TripConstraintKind> for ConstraintKindDto {
    fn from(kind: TripConstraintKind) -> Self {
        match kind {
            TripConstraintKind::Accessibility => Self::Accessibility,
            TripConstraintKind::Accommodation => Self::Accommodation,
            TripConstraintKind::Budget => Self::Budget,
            TripConstraintKind::Dietary => Self::Dietary,
            TripConstraintKind::Documentation => Self::Documentation,
            TripConstraintKind::Schedule => Self::Schedule,
            TripConstraintKind::Transport => Self::Transport,
            TripConstraintKind::Other => Self::Other,
        }
    }
}

impl From<ConstraintKindDto> for TripConstraintKind {
    fn from(kind: ConstraintKindDto) -> Self {
        match kind {
            ConstraintKindDto::Accessibility => Self::Accessibility,
            ConstraintKindDto::Accommodation => Self::Accommodation,
            ConstraintKindDto::Budget => Self::Budget,
            ConstraintKindDto::Dietary => Self::Dietary,
            ConstraintKindDto::Documentation => Self::Documentation,
            ConstraintKindDto::Schedule => Self::Schedule,
            ConstraintKindDto::Transport => Self::Transport,
            ConstraintKindDto::Other => Self::Other,
        }
    }
}

impl From<&TripDecision> for DecisionDto {
    fn from(decision: &TripDecision) -> Self {
        Self {
            id: decision.id().as_str().to_owned(),
            status: DecisionStatusDto::from(decision.status()),
            summary: decision.summary().to_owned(),
            rationale: decision.rationale().map(str::to_owned),
            decided_by: decision.decided_by().as_str().to_owned(),
            evidence: EvidenceDto::from(decision.evidence()),
        }
    }
}

impl TryFrom<DecisionDto> for TripDecision {
    type Error = CodecError;

    fn try_from(decision: DecisionDto) -> Result<Self, Self::Error> {
        Self::new(
            TripDecisionId::new(decision.id),
            DecisionStatus::from(decision.status),
            decision.summary,
            decision.rationale,
            PrincipalId::new(decision.decided_by),
            EvidenceReference::from(decision.evidence),
        )
        .map_err(|_| CodecError::InvalidDomainRecord)
    }
}

impl From<DecisionStatus> for DecisionStatusDto {
    fn from(status: DecisionStatus) -> Self {
        match status {
            DecisionStatus::Proposed => Self::Proposed,
            DecisionStatus::Selected => Self::Selected,
            DecisionStatus::Rejected => Self::Rejected,
        }
    }
}

impl From<DecisionStatusDto> for DecisionStatus {
    fn from(status: DecisionStatusDto) -> Self {
        match status {
            DecisionStatusDto::Proposed => Self::Proposed,
            DecisionStatusDto::Selected => Self::Selected,
            DecisionStatusDto::Rejected => Self::Rejected,
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
    use super::{decode_trip, encode_trip};
    use rembrane_domain::{
        DecisionStatus, EntityId, EvidenceId, EvidenceReference, EvidenceSource, PrincipalId,
        TravelDateWindow, Trip, TripConstraint, TripConstraintId, TripConstraintKind, TripDecision,
        TripDecisionId, TripParticipant, TripParticipantId, WorkspaceId,
    };

    fn trip() -> Trip {
        Trip::new(
            EntityId::new("trip_tokyo"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            "Tokyo",
            "Delhi",
            vec!["Tokyo".to_owned()],
            TravelDateWindow::new("2027-03-10", "2027-03-20").expect("window should be valid"),
        )
        .expect("trip should be valid")
        .add_participant(
            TripParticipant::new(TripParticipantId::new("traveller_01"), "Hippo")
                .expect("participant should be valid"),
        )
        .expect("participant should be added")
        .add_constraint(
            TripConstraint::new(
                TripConstraintId::new("constraint_01"),
                Some(TripParticipantId::new("traveller_01")),
                TripConstraintKind::Dietary,
                "Vegetarian meals",
                EvidenceReference::new(
                    EvidenceId::new("evidence_constraint"),
                    EvidenceSource::UserStatement,
                ),
            )
            .expect("constraint should be valid"),
        )
        .expect("constraint should be added")
        .record_decision(
            TripDecision::new(
                TripDecisionId::new("decision_01"),
                DecisionStatus::Selected,
                "Prefer refundable fares",
                Some("Plans may change".to_owned()),
                PrincipalId::new("principal_01"),
                EvidenceReference::new(
                    EvidenceId::new("evidence_decision"),
                    EvidenceSource::WorkspaceDecision,
                ),
            )
            .expect("decision should be valid"),
        )
        .expect("decision should be recorded")
    }

    #[test]
    fn round_trips_complete_trip() {
        let expected = trip();
        let encoded = encode_trip(&expected).expect("trip should encode");
        assert_eq!(decode_trip(&encoded).expect("trip should decode"), expected);
    }

    #[test]
    fn rejects_unknown_format_version_and_dangling_participant() {
        let encoded = encode_trip(&trip()).expect("trip should encode");
        let mut value: serde_json::Value =
            serde_json::from_slice(&encoded).expect("encoded trip should be JSON");
        value["version"] = 2.into();
        assert!(decode_trip(&serde_json::to_vec(&value).expect("JSON should encode")).is_err());

        let mut value: serde_json::Value =
            serde_json::from_slice(&encoded).expect("encoded trip should be JSON");
        value["record"]["constraints"][0]["participant_id"] = "missing".into();
        assert!(decode_trip(&serde_json::to_vec(&value).expect("JSON should encode")).is_err());
    }
}

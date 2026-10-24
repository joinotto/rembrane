use std::error::Error;
use std::fmt::{self, Display};

use crate::{
    EntityId, EvidenceReference, PrincipalId, TripConstraintId, TripDecisionId, TripParticipantId,
    WorkspaceId,
};

pub const MAX_TRIP_FIELD_BYTES: usize = 4_096;
pub const MAX_TRIP_AGGREGATE_BYTES: usize = 262_144;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TravelDateWindow {
    depart_not_before: String,
    return_not_after: String,
}

impl TravelDateWindow {
    pub fn new(
        depart_not_before: impl Into<String>,
        return_not_after: impl Into<String>,
    ) -> Result<Self, TripError> {
        let depart_not_before = depart_not_before.into();
        let return_not_after = return_not_after.into();
        if !valid_iso_date(&depart_not_before)
            || !valid_iso_date(&return_not_after)
            || depart_not_before > return_not_after
        {
            return Err(TripError::InvalidDateWindow);
        }
        Ok(Self {
            depart_not_before,
            return_not_after,
        })
    }

    #[must_use]
    pub fn depart_not_before(&self) -> &str {
        &self.depart_not_before
    }

    #[must_use]
    pub fn return_not_after(&self) -> &str {
        &self.return_not_after
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TripParticipant {
    id: TripParticipantId,
    label: String,
}

impl TripParticipant {
    pub fn new(id: TripParticipantId, label: impl Into<String>) -> Result<Self, TripError> {
        let label = label.into();
        validate_field(&label)?;
        Ok(Self { id, label })
    }

    #[must_use]
    pub const fn id(&self) -> &TripParticipantId {
        &self.id
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TripConstraintKind {
    Accessibility,
    Accommodation,
    Budget,
    Dietary,
    Documentation,
    Schedule,
    Transport,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TripConstraint {
    id: TripConstraintId,
    participant_id: Option<TripParticipantId>,
    kind: TripConstraintKind,
    statement: String,
    evidence: EvidenceReference,
}

impl TripConstraint {
    pub fn new(
        id: TripConstraintId,
        participant_id: Option<TripParticipantId>,
        kind: TripConstraintKind,
        statement: impl Into<String>,
        evidence: EvidenceReference,
    ) -> Result<Self, TripError> {
        let statement = statement.into();
        validate_field(&statement)?;
        Ok(Self {
            id,
            participant_id,
            kind,
            statement,
            evidence,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &TripConstraintId {
        &self.id
    }

    #[must_use]
    pub const fn participant_id(&self) -> Option<&TripParticipantId> {
        self.participant_id.as_ref()
    }

    #[must_use]
    pub const fn kind(&self) -> TripConstraintKind {
        self.kind
    }

    #[must_use]
    pub fn statement(&self) -> &str {
        &self.statement
    }

    #[must_use]
    pub const fn evidence(&self) -> &EvidenceReference {
        &self.evidence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionStatus {
    Proposed,
    Selected,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TripDecision {
    id: TripDecisionId,
    status: DecisionStatus,
    summary: String,
    rationale: Option<String>,
    decided_by: PrincipalId,
    evidence: EvidenceReference,
}

impl TripDecision {
    pub fn new(
        id: TripDecisionId,
        status: DecisionStatus,
        summary: impl Into<String>,
        rationale: Option<String>,
        decided_by: PrincipalId,
        evidence: EvidenceReference,
    ) -> Result<Self, TripError> {
        let summary = summary.into();
        validate_field(&summary)?;
        if let Some(rationale) = rationale.as_deref() {
            validate_field(rationale)?;
        }
        Ok(Self {
            id,
            status,
            summary,
            rationale,
            decided_by,
            evidence,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &TripDecisionId {
        &self.id
    }

    #[must_use]
    pub const fn status(&self) -> DecisionStatus {
        self.status
    }

    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    #[must_use]
    pub fn rationale(&self) -> Option<&str> {
        self.rationale.as_deref()
    }

    #[must_use]
    pub const fn decided_by(&self) -> &PrincipalId {
        &self.decided_by
    }

    #[must_use]
    pub const fn evidence(&self) -> &EvidenceReference {
        &self.evidence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Trip {
    id: EntityId,
    workspace_id: WorkspaceId,
    owner_subject_id: PrincipalId,
    title: String,
    origin: String,
    destinations: Vec<String>,
    date_window: TravelDateWindow,
    participants: Vec<TripParticipant>,
    constraints: Vec<TripConstraint>,
    decisions: Vec<TripDecision>,
    version: u64,
}

impl Trip {
    pub fn restore(
        id: EntityId,
        workspace_id: WorkspaceId,
        owner_subject_id: PrincipalId,
        title: impl Into<String>,
        origin: impl Into<String>,
        destinations: Vec<String>,
        date_window: TravelDateWindow,
        participants: Vec<TripParticipant>,
        constraints: Vec<TripConstraint>,
        decisions: Vec<TripDecision>,
        version: u64,
    ) -> Result<Self, TripError> {
        if version == 0 {
            return Err(TripError::InvalidVersion);
        }
        let mut trip = Self::new(
            id,
            workspace_id,
            owner_subject_id,
            title,
            origin,
            destinations,
            date_window,
        )?;
        if has_duplicate_ids(&participants, TripParticipant::id)
            || has_duplicate_ids(&constraints, TripConstraint::id)
            || has_duplicate_ids(&decisions, TripDecision::id)
        {
            return Err(TripError::DuplicateItem);
        }
        if constraints.iter().any(|constraint| {
            constraint.participant_id().is_some_and(|participant_id| {
                !participants
                    .iter()
                    .any(|participant| participant.id() == participant_id)
            })
        }) {
            return Err(TripError::UnknownParticipant);
        }
        trip.participants = participants;
        trip.constraints = constraints;
        trip.decisions = decisions;
        trip.version = version;
        trip.validate_size()?;
        Ok(trip)
    }

    pub fn new(
        id: EntityId,
        workspace_id: WorkspaceId,
        owner_subject_id: PrincipalId,
        title: impl Into<String>,
        origin: impl Into<String>,
        destinations: Vec<String>,
        date_window: TravelDateWindow,
    ) -> Result<Self, TripError> {
        let title = title.into();
        let origin = origin.into();
        validate_field(&title)?;
        validate_field(&origin)?;
        if destinations.is_empty() {
            return Err(TripError::MissingDestination);
        }
        for destination in &destinations {
            validate_field(destination)?;
        }
        if has_duplicates(&destinations) {
            return Err(TripError::DuplicateItem);
        }
        let trip = Self {
            id,
            workspace_id,
            owner_subject_id,
            title,
            origin,
            destinations,
            date_window,
            participants: Vec::new(),
            constraints: Vec::new(),
            decisions: Vec::new(),
            version: 1,
        };
        trip.validate_size()?;
        Ok(trip)
    }

    pub fn add_participant(mut self, participant: TripParticipant) -> Result<Self, TripError> {
        if self
            .participants
            .iter()
            .any(|stored| stored.id() == participant.id())
        {
            return Err(TripError::DuplicateItem);
        }
        self.participants.push(participant);
        self.bump_version()?;
        self.validate_size()?;
        Ok(self)
    }

    pub fn add_constraint(mut self, constraint: TripConstraint) -> Result<Self, TripError> {
        if self
            .constraints
            .iter()
            .any(|stored| stored.id() == constraint.id())
        {
            return Err(TripError::DuplicateItem);
        }
        if constraint.participant_id().is_some_and(|participant_id| {
            !self
                .participants
                .iter()
                .any(|participant| participant.id() == participant_id)
        }) {
            return Err(TripError::UnknownParticipant);
        }
        self.constraints.push(constraint);
        self.bump_version()?;
        self.validate_size()?;
        Ok(self)
    }

    pub fn record_decision(mut self, decision: TripDecision) -> Result<Self, TripError> {
        if self
            .decisions
            .iter()
            .any(|stored| stored.id() == decision.id())
        {
            return Err(TripError::DuplicateItem);
        }
        self.decisions.push(decision);
        self.bump_version()?;
        self.validate_size()?;
        Ok(self)
    }

    fn bump_version(&mut self) -> Result<(), TripError> {
        self.version = self
            .version
            .checked_add(1)
            .ok_or(TripError::VersionOverflow)?;
        Ok(())
    }

    fn validate_size(&self) -> Result<(), TripError> {
        let total = self
            .destinations
            .iter()
            .map(String::len)
            .chain(self.participants.iter().map(|item| item.label.len()))
            .chain(self.constraints.iter().map(|item| item.statement.len()))
            .chain(self.decisions.iter().map(|item| item.summary.len()))
            .chain(
                self.decisions
                    .iter()
                    .filter_map(|item| item.rationale.as_ref().map(String::len)),
            )
            .chain([
                self.title.len(),
                self.origin.len(),
                self.date_window.depart_not_before.len(),
                self.date_window.return_not_after.len(),
            ])
            .try_fold(0_usize, usize::checked_add)
            .ok_or(TripError::AggregateTooLarge)?;
        if total > MAX_TRIP_AGGREGATE_BYTES {
            return Err(TripError::AggregateTooLarge);
        }
        Ok(())
    }

    #[must_use]
    pub const fn id(&self) -> &EntityId {
        &self.id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn owner_subject_id(&self) -> &PrincipalId {
        &self.owner_subject_id
    }

    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    #[must_use]
    pub fn destinations(&self) -> &[String] {
        &self.destinations
    }

    #[must_use]
    pub const fn date_window(&self) -> &TravelDateWindow {
        &self.date_window
    }

    #[must_use]
    pub fn participants(&self) -> &[TripParticipant] {
        &self.participants
    }

    #[must_use]
    pub fn constraints(&self) -> &[TripConstraint] {
        &self.constraints
    }

    #[must_use]
    pub fn decisions(&self) -> &[TripDecision] {
        &self.decisions
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }
}

fn validate_field(value: &str) -> Result<(), TripError> {
    if value.trim().is_empty() {
        return Err(TripError::EmptyField);
    }
    if value.len() > MAX_TRIP_FIELD_BYTES {
        return Err(TripError::FieldTooLarge);
    }
    Ok(())
}

fn has_duplicates(values: &[String]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

fn has_duplicate_ids<T, Id: PartialEq>(values: &[T], id: impl Fn(&T) -> &Id) -> bool {
    values.iter().enumerate().any(|(index, value)| {
        values[..index]
            .iter()
            .any(|earlier| id(earlier) == id(value))
    })
}

fn valid_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let Ok(year) = value[0..4].parse::<u32>() else {
        return false;
    };
    let Ok(month) = value[5..7].parse::<u32>() else {
        return false;
    };
    let Ok(day) = value[8..10].parse::<u32>() else {
        return false;
    };
    let maximum_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return false,
    };
    year > 0 && day > 0 && day <= maximum_day
}

const fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TripError {
    AggregateTooLarge,
    DuplicateItem,
    EmptyField,
    FieldTooLarge,
    InvalidDateWindow,
    InvalidVersion,
    MissingDestination,
    UnknownParticipant,
    VersionOverflow,
}

impl Display for TripError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AggregateTooLarge => "trip exceeds the canonical aggregate byte limit",
            Self::DuplicateItem => "trip item already exists",
            Self::EmptyField => "trip field must not be empty",
            Self::FieldTooLarge => "trip field exceeds the canonical byte limit",
            Self::InvalidDateWindow => "trip date window is invalid",
            Self::InvalidVersion => "trip version must be greater than zero",
            Self::MissingDestination => "trip requires at least one destination",
            Self::UnknownParticipant => "trip constraint references an unknown participant",
            Self::VersionOverflow => "trip version cannot be incremented",
        })
    }
}

impl Error for TripError {}

#[cfg(test)]
mod tests {
    use crate::{EvidenceId, EvidenceSource};

    use super::*;

    fn evidence(id: &str) -> EvidenceReference {
        EvidenceReference::new(EvidenceId::new(id), EvidenceSource::UserStatement)
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

    #[test]
    fn models_participant_constraint_and_attributed_decision() {
        let trip = trip()
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
                    evidence("evidence_constraint"),
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
                    evidence("evidence_decision"),
                )
                .expect("decision should be valid"),
            )
            .expect("decision should be recorded");

        assert_eq!(trip.participants().len(), 1);
        assert_eq!(trip.constraints().len(), 1);
        assert_eq!(trip.decisions().len(), 1);
        assert_eq!(trip.version(), 4);
    }

    #[test]
    fn rejects_unknown_participant_and_duplicate_destination() {
        let constraint = TripConstraint::new(
            TripConstraintId::new("constraint_01"),
            Some(TripParticipantId::new("unknown")),
            TripConstraintKind::Accessibility,
            "Step-free access",
            evidence("evidence_01"),
        )
        .expect("constraint should be structurally valid");
        assert_eq!(
            trip().add_constraint(constraint),
            Err(TripError::UnknownParticipant)
        );
        assert_eq!(
            Trip::new(
                EntityId::new("trip"),
                WorkspaceId::new("workspace"),
                PrincipalId::new("principal"),
                "Trip",
                "Delhi",
                vec!["Tokyo".to_owned(), "Tokyo".to_owned()],
                TravelDateWindow::new("2027-03-10", "2027-03-20").expect("window should be valid"),
            ),
            Err(TripError::DuplicateItem)
        );
    }

    #[test]
    fn validates_real_calendar_dates_and_ordering() {
        assert!(TravelDateWindow::new("2028-02-29", "2028-03-01").is_ok());
        assert_eq!(
            TravelDateWindow::new("2027-02-29", "2027-03-01"),
            Err(TripError::InvalidDateWindow)
        );
        assert_eq!(
            TravelDateWindow::new("2027-04-10", "2027-04-09"),
            Err(TripError::InvalidDateWindow)
        );
    }

    #[test]
    fn restore_rejects_invalid_version_and_dangling_participant_reference() {
        let window =
            TravelDateWindow::new("2027-03-10", "2027-03-20").expect("window should be valid");
        assert_eq!(
            Trip::restore(
                EntityId::new("trip"),
                WorkspaceId::new("workspace"),
                PrincipalId::new("principal"),
                "Trip",
                "Delhi",
                vec!["Tokyo".to_owned()],
                window.clone(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                0,
            ),
            Err(TripError::InvalidVersion)
        );
        let dangling = TripConstraint::new(
            TripConstraintId::new("constraint"),
            Some(TripParticipantId::new("missing")),
            TripConstraintKind::Schedule,
            "Depart after work",
            evidence("evidence"),
        )
        .expect("constraint should be structurally valid");
        assert_eq!(
            Trip::restore(
                EntityId::new("trip"),
                WorkspaceId::new("workspace"),
                PrincipalId::new("principal"),
                "Trip",
                "Delhi",
                vec!["Tokyo".to_owned()],
                window,
                Vec::new(),
                vec![dangling],
                Vec::new(),
                1,
            ),
            Err(TripError::UnknownParticipant)
        );
    }
}

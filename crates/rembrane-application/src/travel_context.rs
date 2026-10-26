use std::fmt;

use rembrane_domain::{
    BookingResearch, BookingResearchId, BookingResearchKind, DisclosedBookingResearch,
    DisclosureId, EntityId, EvidenceId, MemoryScope, PrincipalId, ReadGrant, ReadPermission,
    ResearchFreshness, TravelDisclosureReceipt, Trip, TripConstraint, TripDecision,
    TripParticipant,
};

use crate::{ApplicationError, TravelContextRepository};

#[derive(Clone, Eq, PartialEq)]
pub struct ResolveTravelContextCommand {
    pub grant: ReadGrant,
    pub disclosure_id: DisclosureId,
    pub trip_id: EntityId,
    pub purpose: String,
    pub as_of: String,
    pub include_source_references: bool,
    pub include_sensitive_profile: bool,
}

impl fmt::Debug for ResolveTravelContextCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolveTravelContextCommand")
            .field("purpose_bytes", &self.purpose.len())
            .field("as_of_bytes", &self.as_of.len())
            .field("include_source_references", &self.include_source_references)
            .field("include_sensitive_profile", &self.include_sensitive_profile)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TravelContext {
    pub trip: TravelContextTrip,
    pub fresh_research: Vec<TravelContextResearch>,
    pub expired_research: Vec<TravelContextResearch>,
}

impl fmt::Debug for TravelContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TravelContext")
            .field("trip", &self.trip)
            .field("fresh_research_count", &self.fresh_research.len())
            .field("expired_research_count", &self.expired_research.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TravelContextTrip {
    pub id: EntityId,
    pub owner_subject_id: PrincipalId,
    pub title: String,
    pub origin: String,
    pub destinations: Vec<String>,
    pub depart_not_before: String,
    pub return_not_after: String,
    pub version: u64,
    pub sensitive_profile: Option<TravelSensitiveProfile>,
}

impl fmt::Debug for TravelContextTrip {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TravelContextTrip")
            .field("destination_count", &self.destinations.len())
            .field("version", &self.version)
            .field(
                "sensitive_profile_included",
                &self.sensitive_profile.is_some(),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TravelSensitiveProfile {
    pub participants: Vec<TripParticipant>,
    pub constraints: Vec<TripConstraint>,
    pub decisions: Vec<TripDecision>,
}

impl fmt::Debug for TravelSensitiveProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TravelSensitiveProfile")
            .field("participant_count", &self.participants.len())
            .field("constraint_count", &self.constraints.len())
            .field("decision_count", &self.decisions.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct TravelContextResearch {
    pub id: BookingResearchId,
    pub kind: BookingResearchKind,
    pub provider: String,
    pub summary: String,
    pub source_reference: Option<String>,
    pub evidence_id: EvidenceId,
    pub observed_at: String,
    pub expires_at: String,
    pub version: u64,
}

impl fmt::Debug for TravelContextResearch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TravelContextResearch")
            .field("kind", &self.kind)
            .field("summary_bytes", &self.summary.len())
            .field(
                "source_reference_included",
                &self.source_reference.is_some(),
            )
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

pub struct TravelContextService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> TravelContextService<'repository, Repository>
where
    Repository: TravelContextRepository,
{
    pub const fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn resolve(
        &mut self,
        command: &ResolveTravelContextCommand,
    ) -> Result<TravelContext, ApplicationError> {
        if command.purpose.trim().is_empty() {
            return Err(ApplicationError::Validation(
                "travel context purpose must not be empty".to_owned(),
            ));
        }
        if command.include_source_references
            && !command
                .grant
                .allows_permission(ReadPermission::RevealTravelSourceReferences)
        {
            return Err(ApplicationError::AccessDenied);
        }
        if command.include_sensitive_profile
            && !command
                .grant
                .allows_permission(ReadPermission::RevealTravelSensitiveProfile)
        {
            return Err(ApplicationError::AccessDenied);
        }
        let scope = MemoryScope::Entity {
            id: command.trip_id.clone(),
        };
        if !command.grant.allows(&scope) {
            return Err(ApplicationError::AccessDenied);
        }
        let trip = self
            .repository
            .find_trip(&command.grant.workspace_id, &command.trip_id)?
            .ok_or(ApplicationError::NotFound)?;
        let research = self
            .repository
            .list_booking_research_for_trip(&command.grant.workspace_id, &command.trip_id)?;
        let mut fresh_research = Vec::new();
        let mut expired_research = Vec::new();
        for item in research {
            match item
                .freshness_at(&command.as_of)
                .map_err(|_| ApplicationError::Validation("invalid as-of timestamp".to_owned()))?
            {
                ResearchFreshness::Fresh => fresh_research.push(item),
                ResearchFreshness::Expired => expired_research.push(item),
            }
        }
        let disclosed_research = fresh_research
            .iter()
            .map(|item| DisclosedBookingResearch {
                id: item.id().clone(),
                version: item.version(),
                freshness: ResearchFreshness::Fresh,
            })
            .chain(
                expired_research
                    .iter()
                    .map(|item| DisclosedBookingResearch {
                        id: item.id().clone(),
                        version: item.version(),
                        freshness: ResearchFreshness::Expired,
                    }),
            )
            .collect();
        self.repository
            .append_travel_disclosure(TravelDisclosureReceipt {
                id: command.disclosure_id.clone(),
                workspace_id: command.grant.workspace_id.clone(),
                subject_id: command.grant.subject_id.clone(),
                client_id: command.grant.client_id.clone(),
                purpose: command.purpose.trim().to_owned(),
                trip_id: command.trip_id.clone(),
                trip_version: trip.version(),
                as_of: command.as_of.clone(),
                source_references_included: command.include_source_references,
                sensitive_profile_included: command.include_sensitive_profile,
                research: disclosed_research,
            })?;
        let include_source_references = command.include_source_references;
        Ok(TravelContext {
            trip: TravelContextTrip::new(&trip, command.include_sensitive_profile),
            fresh_research: fresh_research
                .iter()
                .map(|research| TravelContextResearch::new(research, include_source_references))
                .collect(),
            expired_research: expired_research
                .iter()
                .map(|research| TravelContextResearch::new(research, include_source_references))
                .collect(),
        })
    }
}

impl TravelContextTrip {
    fn new(trip: &Trip, include_sensitive_profile: bool) -> Self {
        Self {
            id: trip.id().clone(),
            owner_subject_id: trip.owner_subject_id().clone(),
            title: trip.title().to_owned(),
            origin: trip.origin().to_owned(),
            destinations: trip.destinations().to_vec(),
            depart_not_before: trip.date_window().depart_not_before().to_owned(),
            return_not_after: trip.date_window().return_not_after().to_owned(),
            version: trip.version(),
            sensitive_profile: include_sensitive_profile.then(|| TravelSensitiveProfile {
                participants: trip.participants().to_vec(),
                constraints: trip.constraints().to_vec(),
                decisions: trip.decisions().to_vec(),
            }),
        }
    }
}

impl TravelContextResearch {
    fn new(research: &BookingResearch, include_source_reference: bool) -> Self {
        Self {
            id: research.id().clone(),
            kind: research.kind(),
            provider: research.provider().to_owned(),
            summary: research.summary().to_owned(),
            source_reference: include_source_reference
                .then(|| research.source_reference().to_owned()),
            evidence_id: research.evidence().id.clone(),
            observed_at: research.observed_at().to_owned(),
            expires_at: research.expires_at().to_owned(),
            version: research.version(),
        }
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use rembrane_domain::{
        BookingResearchId, BookingResearchKind, EntityId, EvidenceId, PrincipalId,
    };

    use super::{TravelContextResearch, TravelContextTrip};

    #[test]
    fn travel_context_diagnostics_redact_plaintext_and_identity() {
        let trip = TravelContextTrip {
            id: EntityId::new("private-trip"),
            owner_subject_id: PrincipalId::new("private-owner"),
            title: "private title".to_owned(),
            origin: "private origin".to_owned(),
            destinations: vec!["private destination".to_owned()],
            depart_not_before: "private departure".to_owned(),
            return_not_after: "private return".to_owned(),
            version: 7,
            sensitive_profile: None,
        };
        let research = TravelContextResearch {
            id: BookingResearchId::new("private-research"),
            kind: BookingResearchKind::Flight,
            provider: "private provider".to_owned(),
            summary: "private summary".to_owned(),
            source_reference: Some("private source".to_owned()),
            evidence_id: EvidenceId::new("private-evidence"),
            observed_at: "private observed time".to_owned(),
            expires_at: "private expiry".to_owned(),
            version: 3,
        };

        let diagnostic = format!("{trip:?} {research:?}");
        for secret in [
            "private-trip",
            "private-owner",
            "private title",
            "private origin",
            "private destination",
            "private departure",
            "private return",
            "private-research",
            "private provider",
            "private summary",
            "private source",
            "private-evidence",
            "private observed time",
            "private expiry",
        ] {
            assert!(!diagnostic.contains(secret), "diagnostic exposed {secret}");
        }
    }
}

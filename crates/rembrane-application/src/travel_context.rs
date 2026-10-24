use rembrane_domain::{
    BookingResearch, BookingResearchId, BookingResearchKind, DisclosedBookingResearch,
    DisclosureId, EntityId, EvidenceId, MemoryScope, ReadGrant, ReadPermission, ResearchFreshness,
    TravelDisclosureReceipt, Trip,
};

use crate::{
    ApplicationError, BookingResearchRepository, TravelDisclosureRepository, TripRepository,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveTravelContextCommand {
    pub grant: ReadGrant,
    pub disclosure_id: DisclosureId,
    pub trip_id: EntityId,
    pub purpose: String,
    pub as_of: String,
    pub include_source_references: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TravelContext {
    pub trip: Trip,
    pub fresh_research: Vec<TravelContextResearch>,
    pub expired_research: Vec<TravelContextResearch>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

pub struct TravelContextService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> TravelContextService<'repository, Repository>
where
    Repository: TripRepository + BookingResearchRepository + TravelDisclosureRepository,
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
                research: disclosed_research,
            })?;
        let include_source_references = command.include_source_references;
        Ok(TravelContext {
            trip,
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

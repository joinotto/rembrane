use rembrane_domain::{
    BookingResearch, DisclosedBookingResearch, DisclosureId, EntityId, MemoryScope, ReadGrant,
    ResearchFreshness, TravelDisclosureReceipt, Trip,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TravelContext {
    pub trip: Trip,
    pub fresh_research: Vec<BookingResearch>,
    pub expired_research: Vec<BookingResearch>,
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
                research: disclosed_research,
            })?;
        Ok(TravelContext {
            trip,
            fresh_research,
            expired_research,
        })
    }
}

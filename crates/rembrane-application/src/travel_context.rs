use rembrane_domain::{BookingResearch, EntityId, MemoryScope, ReadGrant, ResearchFreshness, Trip};

use crate::{ApplicationError, BookingResearchRepository, TripRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveTravelContextCommand {
    pub grant: ReadGrant,
    pub trip_id: EntityId,
    pub as_of: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TravelContext {
    pub trip: Trip,
    pub fresh_research: Vec<BookingResearch>,
    pub expired_research: Vec<BookingResearch>,
}

pub struct TravelContextService<'repository, Repository> {
    repository: &'repository Repository,
}

impl<'repository, Repository> TravelContextService<'repository, Repository>
where
    Repository: TripRepository + BookingResearchRepository,
{
    pub const fn new(repository: &'repository Repository) -> Self {
        Self { repository }
    }

    pub fn resolve(
        &self,
        command: &ResolveTravelContextCommand,
    ) -> Result<TravelContext, ApplicationError> {
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
        Ok(TravelContext {
            trip,
            fresh_research,
            expired_research,
        })
    }
}

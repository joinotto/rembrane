use rembrane_domain::{
    BookingResearch, CanonicalEvent, EventId, EventPayload, MemoryScope, WriteGrant,
    WritePermission,
};

use crate::{ApplicationError, BookingResearchMutationRepository, TripRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureBookingResearchCommand {
    pub grant: WriteGrant,
    pub research: BookingResearch,
    pub event_id: EventId,
    pub expected_previous_sequence: u64,
}

pub struct CaptureBookingResearchService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> CaptureBookingResearchService<'repository, Repository>
where
    Repository: BookingResearchMutationRepository + TripRepository,
{
    pub const fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn execute(
        &mut self,
        command: CaptureBookingResearchCommand,
    ) -> Result<BookingResearch, ApplicationError> {
        let entity_scope = MemoryScope::Entity {
            id: command.research.trip_id().clone(),
        };
        if !command
            .grant
            .allows(WritePermission::CaptureBookingResearch)
            || !command.grant.allows_scope(&entity_scope)
            || command.grant.workspace_id != *command.research.workspace_id()
            || command.grant.subject_id != *command.research.observed_by()
        {
            return Err(ApplicationError::AccessDenied);
        }
        if self
            .repository
            .find_trip(command.research.workspace_id(), command.research.trip_id())?
            .is_none()
        {
            return Err(ApplicationError::NotFound);
        }
        let event = CanonicalEvent::new(
            command.event_id,
            command.research.workspace_id().clone(),
            command.grant.subject_id,
            Some(command.research.observed_by().clone()),
            command.expected_previous_sequence.saturating_add(1),
            EventPayload::BookingResearchCaptured {
                research_id: command.research.id().clone(),
                trip_id: command.research.trip_id().clone(),
                version: command.research.version(),
            },
        )
        .map_err(|_| ApplicationError::Validation("invalid booking research event".to_owned()))?;
        self.repository.insert_booking_research_with_event(
            command.research.clone(),
            event,
            command.expected_previous_sequence,
        )?;
        Ok(command.research)
    }
}

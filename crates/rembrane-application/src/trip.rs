use rembrane_domain::{
    CanonicalEvent, EntityId, EventId, EventPayload, MemoryScope, Trip, TripParticipant,
    WriteGrant, WritePermission,
};

use crate::{ApplicationError, TripMutationRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateTripCommand {
    pub grant: WriteGrant,
    pub trip: Trip,
    pub event_id: EventId,
    pub expected_previous_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplaceTripCommand {
    pub grant: WriteGrant,
    pub trip: Trip,
    pub expected_trip_version: u64,
    pub event_id: EventId,
    pub expected_previous_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddTripParticipantCommand {
    pub grant: WriteGrant,
    pub trip_id: EntityId,
    pub participant: TripParticipant,
    pub expected_trip_version: u64,
    pub event_id: EventId,
    pub expected_previous_sequence: u64,
}

pub struct TripService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> TripService<'repository, Repository>
where
    Repository: TripMutationRepository,
{
    pub const fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn create(&mut self, command: CreateTripCommand) -> Result<Trip, ApplicationError> {
        validate_create_grant(&command.grant, &command.trip)?;
        if command.trip.owner_subject_id() != &command.grant.subject_id {
            return Err(ApplicationError::AccessDenied);
        }
        let event = CanonicalEvent::new(
            command.event_id,
            command.trip.workspace_id().clone(),
            command.grant.subject_id,
            Some(command.trip.owner_subject_id().clone()),
            command.expected_previous_sequence.saturating_add(1),
            EventPayload::TripCreated {
                trip_id: command.trip.id().clone(),
                version: command.trip.version(),
            },
        )
        .map_err(|_| ApplicationError::Validation("invalid trip event".to_owned()))?;
        self.repository.insert_trip_with_event(
            command.trip.clone(),
            event,
            command.expected_previous_sequence,
        )?;
        Ok(command.trip)
    }

    pub fn replace(&mut self, command: ReplaceTripCommand) -> Result<Trip, ApplicationError> {
        validate_grant(&command.grant, &command.trip, WritePermission::ReviseTrip)?;
        let stored = self
            .repository
            .find_trip(command.trip.workspace_id(), command.trip.id())?
            .ok_or(ApplicationError::NotFound)?;
        if stored.owner_subject_id() != command.trip.owner_subject_id()
            || stored.version() != command.expected_trip_version
            || command.trip.version() != command.expected_trip_version.saturating_add(1)
        {
            return Err(ApplicationError::VersionConflict);
        }
        let event = CanonicalEvent::new(
            command.event_id,
            command.trip.workspace_id().clone(),
            command.grant.subject_id,
            Some(command.trip.owner_subject_id().clone()),
            command.expected_previous_sequence.saturating_add(1),
            EventPayload::TripRevised {
                trip_id: command.trip.id().clone(),
                version: command.trip.version(),
            },
        )
        .map_err(|_| ApplicationError::Validation("invalid trip event".to_owned()))?;
        self.repository.replace_trip_with_event(
            command.trip.clone(),
            command.expected_trip_version,
            event,
            command.expected_previous_sequence,
        )?;
        Ok(command.trip)
    }

    pub fn add_participant(
        &mut self,
        command: AddTripParticipantCommand,
    ) -> Result<Trip, ApplicationError> {
        let stored = self
            .repository
            .find_trip(&command.grant.workspace_id, &command.trip_id)?
            .ok_or(ApplicationError::NotFound)?;
        validate_grant(&command.grant, &stored, WritePermission::ReviseTrip)?;
        if stored.version() != command.expected_trip_version {
            return Err(ApplicationError::VersionConflict);
        }
        let revised = stored
            .add_participant(command.participant)
            .map_err(|_| ApplicationError::Validation("invalid trip participant".to_owned()))?;
        self.replace(ReplaceTripCommand {
            grant: command.grant,
            trip: revised,
            expected_trip_version: command.expected_trip_version,
            event_id: command.event_id,
            expected_previous_sequence: command.expected_previous_sequence,
        })
    }
}

fn validate_grant(
    grant: &WriteGrant,
    trip: &Trip,
    permission: WritePermission,
) -> Result<(), ApplicationError> {
    if !grant.allows(permission)
        || grant.workspace_id != *trip.workspace_id()
        || !grant.allows_scope(&MemoryScope::Entity {
            id: trip.id().clone(),
        })
    {
        return Err(ApplicationError::AccessDenied);
    }
    Ok(())
}

fn validate_create_grant(grant: &WriteGrant, trip: &Trip) -> Result<(), ApplicationError> {
    if !grant.allows(WritePermission::CreateTrip)
        || grant.workspace_id != *trip.workspace_id()
        || !grant.allows_scope(&MemoryScope::Domain {
            name: "travel".to_owned(),
        })
    {
        return Err(ApplicationError::AccessDenied);
    }
    Ok(())
}

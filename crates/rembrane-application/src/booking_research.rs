use std::fmt;

use rembrane_domain::{
    BookingResearch, CanonicalEvent, EventId, EventPayload, MemoryScope, WriteGrant,
    WritePermission,
};

use crate::{ApplicationError, BookingResearchMutationRepository, TripRepository};

#[derive(Clone, Eq, PartialEq)]
pub struct CaptureBookingResearchCommand {
    pub grant: WriteGrant,
    pub research: BookingResearch,
    pub event_id: EventId,
    pub expected_previous_sequence: u64,
}

impl fmt::Debug for CaptureBookingResearchCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaptureBookingResearchCommand")
            .field("research_kind", &self.research.kind())
            .field("research_version", &self.research.version())
            .field(
                "expected_previous_sequence",
                &self.expected_previous_sequence,
            )
            .finish_non_exhaustive()
    }
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
        let event_sequence = command
            .expected_previous_sequence
            .checked_add(1)
            .ok_or(ApplicationError::SequenceConflict)?;
        let event = CanonicalEvent::new(
            command.event_id,
            command.research.workspace_id().clone(),
            command.grant.subject_id,
            Some(command.research.observed_by().clone()),
            event_sequence,
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

#[cfg(test)]
mod diagnostic_tests {
    use rembrane_domain::{
        BookingResearch, BookingResearchId, BookingResearchKind, ClientId, EntityId, EventId,
        EvidenceId, EvidenceReference, EvidenceSource, PrincipalId, WorkspaceId, WriteGrant,
    };

    use super::CaptureBookingResearchCommand;

    #[test]
    fn booking_research_command_diagnostics_redact_private_context() {
        let research = BookingResearch::new(
            BookingResearchId::new("private-research"),
            WorkspaceId::new("private-workspace"),
            EntityId::new("private-trip"),
            PrincipalId::new("private-observer"),
            BookingResearchKind::Flight,
            "private airline",
            "private itinerary summary",
            "https://private.example/booking",
            EvidenceReference::new(
                EvidenceId::new("private-evidence"),
                EvidenceSource::ToolResult,
            ),
            "2026-10-26T10:00:00Z",
            "2026-10-27T10:00:00Z",
        )
        .expect("booking research fixture");
        let command = CaptureBookingResearchCommand {
            grant: WriteGrant {
                client_id: ClientId::new("private-client"),
                workspace_id: WorkspaceId::new("private-workspace"),
                subject_id: PrincipalId::new("private-observer"),
                scopes: Vec::new(),
                permissions: Vec::new(),
            },
            research,
            event_id: EventId::new("private-event"),
            expected_previous_sequence: 4,
        };

        let diagnostic = format!("{command:?}");
        for secret in [
            "private-research",
            "private-workspace",
            "private-trip",
            "private-observer",
            "private airline",
            "private itinerary summary",
            "private.example",
            "private-evidence",
            "private-client",
            "private-event",
        ] {
            assert!(!diagnostic.contains(secret), "diagnostic exposed {secret}");
        }
    }
}

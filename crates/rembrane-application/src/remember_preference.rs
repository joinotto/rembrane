use rembrane_domain::{
    CanonicalEvent, EventId, EventPayload, EvidenceReference, MemoryId,
    MemoryRecord, MemoryScope, ProjectionJob, WriteGrant, WritePermission,
};

use crate::{ApplicationError, CanonicalMutationRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RememberPreferenceCommand {
    pub grant: WriteGrant,
    pub memory_id: MemoryId,
    pub scope: MemoryScope,
    pub content: String,
    pub evidence: EvidenceReference,
    pub event_id: EventId,
    pub expected_previous_sequence: u64,
    pub projections: Vec<ProjectionJob>,
}
pub struct RememberPreferenceService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> RememberPreferenceService<'repository, Repository>
where
    Repository: CanonicalMutationRepository,
{
    pub fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn execute(
        &mut self,
        command: RememberPreferenceCommand,
    ) -> Result<MemoryRecord, ApplicationError> {
        if !command.grant.allows(WritePermission::CreateMemory)
            || !command.grant.allows_scope(&command.scope)
        {
            return Err(ApplicationError::AccessDenied);
        }

        let memory = MemoryRecord::confirmed_preference(
            command.memory_id,
            command.grant.workspace_id.clone(),
            command.grant.subject_id.clone(),
            command.scope,
            command.content,
            command.evidence,
        )
        .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        let sequence = command
            .expected_previous_sequence
            .checked_add(1)
            .ok_or(ApplicationError::SequenceConflict)?;
        let event = CanonicalEvent::new(
            command.event_id,
            command.grant.workspace_id,
            command.grant.subject_id.clone(),
            Some(command.grant.subject_id),
            sequence,
            EventPayload::MemoryCreated {
                memory_id: memory.id().clone(),
                version: memory.version(),
            },
        )
        .map_err(|error| ApplicationError::Validation(error.to_string()))?;

        self.repository.insert_memory_with_event(
            memory.clone(),
            event,
            command.projections,
            command.expected_previous_sequence,
        )?;
        Ok(memory)
    }
}

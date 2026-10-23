use rembrane_domain::{
    CanonicalEvent, EventId, EventPayload, EvidenceReference, MemoryId,
    MemoryKind, MemoryRecord, MemoryScope, ProjectionJob, WriteGrant,
    WritePermission,
};

use crate::{ApplicationError, CanonicalMutationRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposeMemoryCommand {
    pub grant: WriteGrant,
    pub memory_id: MemoryId,
    pub scope: MemoryScope,
    pub kind: MemoryKind,
    pub content: String,
    pub evidence: EvidenceReference,
    pub event_id: EventId,
    pub expected_previous_sequence: u64,
    pub projections: Vec<ProjectionJob>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmMemoryCommand {
    pub grant: WriteGrant,
    pub memory_id: MemoryId,
    pub expected_version: u64,
    pub evidence: EvidenceReference,
    pub event_id: EventId,
    pub expected_previous_sequence: u64,
    pub projections: Vec<ProjectionJob>,
}

pub struct MemoryProposalService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> MemoryProposalService<'repository, Repository>
where
    Repository: CanonicalMutationRepository,
{
    pub fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn propose(
        &mut self,
        command: ProposeMemoryCommand,
    ) -> Result<MemoryRecord, ApplicationError> {
        require_permission(&command.grant, WritePermission::ProposeMemory)?;

        let proposal = MemoryRecord::proposed(
            command.memory_id,
            command.grant.workspace_id,
            command.grant.subject_id,
            command.scope,
            command.kind,
            command.content,
            command.evidence,
        )
        .map_err(|error| ApplicationError::Validation(error.to_string()))?;

        let event = event(
            command.event_id,
            &command.grant,
            command.expected_previous_sequence,
            EventPayload::MemoryProposed {
                memory_id: proposal.id().clone(),
                version: proposal.version(),
            },
        )?;
        self.repository.insert_memory_with_event(
            proposal.clone(),
            event,
            command.projections,
            command.expected_previous_sequence,
        )?;
        Ok(proposal)
    }

    pub fn confirm(
        &mut self,
        command: ConfirmMemoryCommand,
    ) -> Result<MemoryRecord, ApplicationError> {
        require_permission(&command.grant, WritePermission::ConfirmMemory)?;

        let current = self
            .repository
            .find(&command.grant.workspace_id, &command.memory_id)?
            .ok_or(ApplicationError::NotFound)?;
        if current.subject_id() != &command.grant.subject_id {
            return Err(ApplicationError::NotFound);
        }
        if current.version() != command.expected_version {
            return Err(ApplicationError::VersionConflict);
        }

        let confirmed = current
            .confirm(command.evidence)
            .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        let event = event(
            command.event_id,
            &command.grant,
            command.expected_previous_sequence,
            EventPayload::MemoryConfirmed {
                memory_id: confirmed.id().clone(),
                version: confirmed.version(),
            },
        )?;
        self.repository.replace_memory_with_event(
            confirmed.clone(),
            command.expected_version,
            event,
            command.projections,
            command.expected_previous_sequence,
        )?;
        Ok(confirmed)
    }
}

fn event(
    event_id: EventId,
    grant: &WriteGrant,
    previous_sequence: u64,
    payload: EventPayload,
) -> Result<CanonicalEvent, ApplicationError> {
    let sequence = previous_sequence
        .checked_add(1)
        .ok_or(ApplicationError::SequenceConflict)?;
    CanonicalEvent::new(
        event_id,
        grant.workspace_id.clone(),
        grant.subject_id.clone(),
        Some(grant.subject_id.clone()),
        sequence,
        payload,
    )
    .map_err(|error| ApplicationError::Validation(error.to_string()))
}

fn require_permission(
    grant: &WriteGrant,
    permission: WritePermission,
) -> Result<(), ApplicationError> {
    if grant.allows(permission) {
        Ok(())
    } else {
        Err(ApplicationError::AccessDenied)
    }
}

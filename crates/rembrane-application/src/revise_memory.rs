use rembrane_domain::{
    CanonicalEvent, EventId, EventPayload, EvidenceReference, MemoryId, MemoryRecord, PrincipalId,
    ProjectionJob, WorkspaceId, WriteGrant, WritePermission,
};

use crate::{ApplicationError, CanonicalMutationRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviseMemoryCommand {
    pub grant: WriteGrant,
    pub memory_id: MemoryId,
    pub expected_version: u64,
    pub content: String,
    pub evidence: EvidenceReference,
    pub event_id: EventId,
    pub expected_previous_sequence: u64,
    pub projections: Vec<ProjectionJob>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteMemoryCommand {
    pub grant: WriteGrant,
    pub memory_id: MemoryId,
    pub expected_version: u64,
    pub evidence: EvidenceReference,
    pub event_id: EventId,
    pub expected_previous_sequence: u64,
    pub projections: Vec<ProjectionJob>,
}

pub struct MemoryLifecycleService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> MemoryLifecycleService<'repository, Repository>
where
    Repository: CanonicalMutationRepository,
{
    pub fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn revise(
        &mut self,
        command: ReviseMemoryCommand,
    ) -> Result<MemoryRecord, ApplicationError> {
        authorize(&command.grant, WritePermission::ReviseMemory)?;
        let current = self.load_owned(
            &command.grant.workspace_id,
            &command.grant.subject_id,
            &command.memory_id,
        )?;
        authorize_scope(&command.grant, &current)?;
        ensure_version(&current, command.expected_version)?;

        let revised = current
            .revise(command.content, command.evidence)
            .map_err(|error| ApplicationError::Validation(error.to_string()))?;

        let event = event(
            command.event_id,
            &command.grant,
            command.expected_previous_sequence,
            EventPayload::MemoryRevised {
                memory_id: revised.id().clone(),
                version: revised.version(),
            },
        )?;
        self.repository.replace_memory_with_event(
            revised.clone(),
            command.expected_version,
            event,
            command.projections,
            command.expected_previous_sequence,
        )?;
        Ok(revised)
    }

    pub fn delete(
        &mut self,
        command: DeleteMemoryCommand,
    ) -> Result<MemoryRecord, ApplicationError> {
        authorize(&command.grant, WritePermission::DeleteMemory)?;
        let current = self.load_owned(
            &command.grant.workspace_id,
            &command.grant.subject_id,
            &command.memory_id,
        )?;
        authorize_scope(&command.grant, &current)?;
        ensure_version(&current, command.expected_version)?;

        let deleted = current
            .delete(command.evidence)
            .map_err(|error| ApplicationError::Validation(error.to_string()))?;

        let event = event(
            command.event_id,
            &command.grant,
            command.expected_previous_sequence,
            EventPayload::MemoryDeleted {
                memory_id: deleted.id().clone(),
                version: deleted.version(),
            },
        )?;
        self.repository.replace_memory_with_event(
            deleted.clone(),
            command.expected_version,
            event,
            command.projections,
            command.expected_previous_sequence,
        )?;
        Ok(deleted)
    }

    fn load_owned(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
        memory_id: &MemoryId,
    ) -> Result<MemoryRecord, ApplicationError> {
        let memory = self
            .repository
            .find(workspace_id, memory_id)?
            .ok_or(ApplicationError::NotFound)?;

        if memory.subject_id() != subject_id {
            return Err(ApplicationError::NotFound);
        }

        Ok(memory)
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

fn authorize(grant: &WriteGrant, permission: WritePermission) -> Result<(), ApplicationError> {
    if grant.allows(permission) {
        Ok(())
    } else {
        Err(ApplicationError::AccessDenied)
    }
}

fn authorize_scope(grant: &WriteGrant, memory: &MemoryRecord) -> Result<(), ApplicationError> {
    if grant.allows_scope(memory.scope()) {
        Ok(())
    } else {
        Err(ApplicationError::AccessDenied)
    }
}

fn ensure_version(memory: &MemoryRecord, expected_version: u64) -> Result<(), ApplicationError> {
    if memory.version() == expected_version {
        Ok(())
    } else {
        Err(ApplicationError::VersionConflict)
    }
}

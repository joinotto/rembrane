use rembrane_domain::{
    EvidenceReference, MemoryId, MemoryRecord, PrincipalId, WorkspaceId,
};

use crate::{ApplicationError, MemoryRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviseMemoryCommand {
    pub workspace_id: WorkspaceId,
    pub subject_id: PrincipalId,
    pub memory_id: MemoryId,
    pub expected_version: u64,
    pub content: String,
    pub evidence: EvidenceReference,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteMemoryCommand {
    pub workspace_id: WorkspaceId,
    pub subject_id: PrincipalId,
    pub memory_id: MemoryId,
    pub expected_version: u64,
    pub evidence: EvidenceReference,
}

pub struct MemoryLifecycleService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> MemoryLifecycleService<'repository, Repository>
where
    Repository: MemoryRepository,
{
    pub fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn revise(
        &mut self,
        command: ReviseMemoryCommand,
    ) -> Result<MemoryRecord, ApplicationError> {
        let current = self.load_owned(
            &command.workspace_id,
            &command.subject_id,
            &command.memory_id,
        )?;
        ensure_version(&current, command.expected_version)?;

        let revised = current
            .revise(command.content, command.evidence)
            .map_err(|error| ApplicationError::Validation(error.to_string()))?;

        self.repository
            .replace(revised.clone(), command.expected_version)?;
        Ok(revised)
    }

    pub fn delete(
        &mut self,
        command: DeleteMemoryCommand,
    ) -> Result<MemoryRecord, ApplicationError> {
        let current = self.load_owned(
            &command.workspace_id,
            &command.subject_id,
            &command.memory_id,
        )?;
        ensure_version(&current, command.expected_version)?;

        let deleted = current
            .delete(command.evidence)
            .map_err(|error| ApplicationError::Validation(error.to_string()))?;

        self.repository
            .replace(deleted.clone(), command.expected_version)?;
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

fn ensure_version(
    memory: &MemoryRecord,
    expected_version: u64,
) -> Result<(), ApplicationError> {
    if memory.version() == expected_version {
        Ok(())
    } else {
        Err(ApplicationError::VersionConflict)
    }
}

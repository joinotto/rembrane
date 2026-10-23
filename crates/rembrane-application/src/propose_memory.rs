use rembrane_domain::{
    EvidenceReference, MemoryId, MemoryKind, MemoryRecord, MemoryScope,
    WriteGrant, WritePermission,
};

use crate::{ApplicationError, MemoryRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposeMemoryCommand {
    pub grant: WriteGrant,
    pub memory_id: MemoryId,
    pub scope: MemoryScope,
    pub kind: MemoryKind,
    pub content: String,
    pub evidence: EvidenceReference,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfirmMemoryCommand {
    pub grant: WriteGrant,
    pub memory_id: MemoryId,
    pub expected_version: u64,
    pub evidence: EvidenceReference,
}

pub struct MemoryProposalService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> MemoryProposalService<'repository, Repository>
where
    Repository: MemoryRepository,
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

        self.repository.insert(proposal.clone())?;
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
        self.repository
            .replace(confirmed.clone(), command.expected_version)?;
        Ok(confirmed)
    }
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

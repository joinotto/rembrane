use rembrane_domain::{
    ActivityCheckpoint, ActivityId, MemoryScope, ReadGrant, WriteGrant,
    WritePermission,
};

use crate::{ApplicationError, CheckpointRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateCheckpointCommand {
    pub grant: WriteGrant,
    pub checkpoint: ActivityCheckpoint,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateCheckpointCommand {
    pub grant: WriteGrant,
    pub checkpoint: ActivityCheckpoint,
    pub expected_version: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumeActivityCommand {
    pub grant: ReadGrant,
    pub activity_id: ActivityId,
}

pub struct CheckpointService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> CheckpointService<'repository, Repository>
where
    Repository: CheckpointRepository,
{
    pub fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn create(
        &mut self,
        command: CreateCheckpointCommand,
    ) -> Result<ActivityCheckpoint, ApplicationError> {
        authorize_write(&command.grant, &command.checkpoint)?;
        self.repository
            .insert_checkpoint(command.checkpoint.clone())?;
        Ok(command.checkpoint)
    }

    pub fn update(
        &mut self,
        command: UpdateCheckpointCommand,
    ) -> Result<ActivityCheckpoint, ApplicationError> {
        authorize_write(&command.grant, &command.checkpoint)?;
        self.repository.replace_checkpoint(
            command.checkpoint.clone(),
            command.expected_version,
        )?;
        Ok(command.checkpoint)
    }

    pub fn resume(
        &self,
        command: &ResumeActivityCommand,
    ) -> Result<Option<ActivityCheckpoint>, ApplicationError> {
        let activity_scope = MemoryScope::Activity {
            id: command.activity_id.clone(),
        };
        if !command.grant.allows(&activity_scope) {
            return Err(ApplicationError::AccessDenied);
        }

        self.repository.latest_checkpoint(
            &command.grant.workspace_id,
            &command.grant.subject_id,
            &command.activity_id,
        )
    }
}

fn authorize_write(
    grant: &WriteGrant,
    checkpoint: &ActivityCheckpoint,
) -> Result<(), ApplicationError> {
    if !grant.allows(WritePermission::WriteCheckpoint)
        || &grant.workspace_id != checkpoint.workspace_id()
        || &grant.subject_id != checkpoint.subject_id()
    {
        return Err(ApplicationError::AccessDenied);
    }

    Ok(())
}

use rembrane_domain::{
    ActivityCheckpoint, ActivityId, CanonicalEvent, EventId, EventPayload,
    MemoryScope, ReadGrant, WriteGrant, WritePermission,
};

use crate::{ApplicationError, CheckpointMutationRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateCheckpointCommand {
    pub grant: WriteGrant,
    pub checkpoint: ActivityCheckpoint,
    pub event_id: EventId,
    pub expected_previous_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateCheckpointCommand {
    pub grant: WriteGrant,
    pub checkpoint: ActivityCheckpoint,
    pub expected_version: u64,
    pub event_id: EventId,
    pub expected_previous_sequence: u64,
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
    Repository: CheckpointMutationRepository,
{
    pub fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn create(
        &mut self,
        command: CreateCheckpointCommand,
    ) -> Result<ActivityCheckpoint, ApplicationError> {
        authorize_write(&command.grant, &command.checkpoint)?;
        let event = checkpoint_event(
            command.event_id,
            &command.grant,
            &command.checkpoint,
            command.expected_previous_sequence,
        )?;
        self.repository.insert_checkpoint_with_event(
            command.checkpoint.clone(),
            event,
            command.expected_previous_sequence,
        )?;
        Ok(command.checkpoint)
    }

    pub fn update(
        &mut self,
        command: UpdateCheckpointCommand,
    ) -> Result<ActivityCheckpoint, ApplicationError> {
        authorize_write(&command.grant, &command.checkpoint)?;
        let event = checkpoint_event(
            command.event_id,
            &command.grant,
            &command.checkpoint,
            command.expected_previous_sequence,
        )?;
        self.repository.replace_checkpoint_with_event(
            command.checkpoint.clone(),
            command.expected_version,
            event,
            command.expected_previous_sequence,
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

fn checkpoint_event(
    event_id: EventId,
    grant: &WriteGrant,
    checkpoint: &ActivityCheckpoint,
    previous_sequence: u64,
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
        EventPayload::ActivityCheckpointed {
            activity_id: checkpoint.activity_id().clone(),
            version: checkpoint.version(),
        },
    )
    .map_err(|error| ApplicationError::Validation(error.to_string()))
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

use std::fmt;

use rembrane_domain::{
    ActivityCheckpoint, ActivityId, CanonicalEvent, CheckpointDisclosureReceipt, DisclosureId,
    EventId, EventPayload, MemoryScope, ReadGrant, WriteGrant, WritePermission,
};

use crate::{ApplicationError, CheckpointReadRepository};

#[derive(Clone, Eq, PartialEq)]
pub struct CreateCheckpointCommand {
    pub grant: WriteGrant,
    pub checkpoint: ActivityCheckpoint,
    pub event_id: EventId,
    pub expected_previous_sequence: u64,
}

impl fmt::Debug for CreateCheckpointCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateCheckpointCommand")
            .field(
                "expected_previous_sequence",
                &self.expected_previous_sequence,
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct UpdateCheckpointCommand {
    pub grant: WriteGrant,
    pub checkpoint: ActivityCheckpoint,
    pub expected_version: u64,
    pub event_id: EventId,
    pub expected_previous_sequence: u64,
}

impl fmt::Debug for UpdateCheckpointCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpdateCheckpointCommand")
            .field("expected_version", &self.expected_version)
            .field(
                "expected_previous_sequence",
                &self.expected_previous_sequence,
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ResumeActivityCommand {
    pub grant: ReadGrant,
    pub activity_id: ActivityId,
    pub disclosure_id: DisclosureId,
    pub purpose: String,
}

impl fmt::Debug for ResumeActivityCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResumeActivityCommand")
            .field("purpose_bytes", &self.purpose.len())
            .finish_non_exhaustive()
    }
}

pub struct CheckpointService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> CheckpointService<'repository, Repository>
where
    Repository: CheckpointReadRepository,
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
        &mut self,
        command: &ResumeActivityCommand,
    ) -> Result<Option<ActivityCheckpoint>, ApplicationError> {
        if command.purpose.trim().is_empty() {
            return Err(ApplicationError::Validation(
                "checkpoint disclosure purpose must not be empty".to_owned(),
            ));
        }
        let checkpoint = self.load_authorized(&command.grant, &command.activity_id)?;
        if let Some(checkpoint) = &checkpoint {
            self.repository
                .append_checkpoint_disclosure(CheckpointDisclosureReceipt {
                    id: command.disclosure_id.clone(),
                    workspace_id: command.grant.workspace_id.clone(),
                    subject_id: command.grant.subject_id.clone(),
                    client_id: command.grant.client_id.clone(),
                    purpose: command.purpose.clone(),
                    checkpoint_id: checkpoint.id().clone(),
                    checkpoint_version: checkpoint.version(),
                    activity_id: checkpoint.activity_id().clone(),
                })?;
        }
        Ok(checkpoint)
    }

    pub fn load_for_update(
        &self,
        grant: &ReadGrant,
        activity_id: &ActivityId,
    ) -> Result<Option<ActivityCheckpoint>, ApplicationError> {
        self.load_authorized(grant, activity_id)
    }

    fn load_authorized(
        &self,
        grant: &ReadGrant,
        activity_id: &ActivityId,
    ) -> Result<Option<ActivityCheckpoint>, ApplicationError> {
        let activity_scope = MemoryScope::Activity {
            id: activity_id.clone(),
        };
        if !grant.allows(&activity_scope) {
            return Err(ApplicationError::AccessDenied);
        }

        self.repository
            .latest_checkpoint(&grant.workspace_id, &grant.subject_id, activity_id)
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
        || !grant.allows_scope(&MemoryScope::Activity {
            id: checkpoint.activity_id().clone(),
        })
        || &grant.workspace_id != checkpoint.workspace_id()
        || &grant.subject_id != checkpoint.subject_id()
    {
        return Err(ApplicationError::AccessDenied);
    }

    Ok(())
}

#[cfg(test)]
mod diagnostic_tests {
    use rembrane_domain::{
        ActivityId, ClientId, DisclosureId, PrincipalId, ReadGrant, WorkspaceId,
    };

    use super::ResumeActivityCommand;

    #[test]
    fn checkpoint_resume_diagnostics_redact_purpose_and_identity() {
        let command = ResumeActivityCommand {
            grant: ReadGrant {
                client_id: ClientId::new("private-client"),
                workspace_id: WorkspaceId::new("private-workspace"),
                subject_id: PrincipalId::new("private-subject"),
                scopes: Vec::new(),
                permissions: Vec::new(),
            },
            activity_id: ActivityId::new("private-activity"),
            disclosure_id: DisclosureId::new("private-disclosure"),
            purpose: "continue private implementation".to_owned(),
        };

        let diagnostic = format!("{command:?}");
        for secret in [
            "private-client",
            "private-workspace",
            "private-subject",
            "private-activity",
            "private-disclosure",
            "continue private implementation",
        ] {
            assert!(!diagnostic.contains(secret), "diagnostic exposed {secret}");
        }
    }
}

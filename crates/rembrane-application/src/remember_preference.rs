use std::fmt;

use rembrane_domain::{
    CanonicalEvent, EventId, EventPayload, EvidenceReference, MemoryId, MemoryRecord, MemoryScope,
    ProjectionJob, WriteGrant, WritePermission,
};

use crate::{ApplicationError, CanonicalMutationRepository};

#[derive(Clone, Eq, PartialEq)]
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

impl fmt::Debug for RememberPreferenceCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RememberPreferenceCommand")
            .field("content_bytes", &self.content.len())
            .field(
                "expected_previous_sequence",
                &self.expected_previous_sequence,
            )
            .field("projection_count", &self.projections.len())
            .finish_non_exhaustive()
    }
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

#[cfg(test)]
mod diagnostic_tests {
    use rembrane_domain::{
        ClientId, EventId, EvidenceId, EvidenceReference, EvidenceSource, MemoryId, MemoryScope,
        PrincipalId, WorkspaceId, WriteGrant,
    };

    use super::RememberPreferenceCommand;

    #[test]
    fn preference_command_diagnostics_redact_plaintext_and_identity() {
        let command = RememberPreferenceCommand {
            grant: WriteGrant {
                client_id: ClientId::new("private-client"),
                workspace_id: WorkspaceId::new("private-workspace"),
                subject_id: PrincipalId::new("private-subject"),
                scopes: Vec::new(),
                permissions: Vec::new(),
            },
            memory_id: MemoryId::new("private-memory"),
            scope: MemoryScope::Domain {
                name: "private-domain".to_owned(),
            },
            content: "Call me Hippo".to_owned(),
            evidence: EvidenceReference::new(
                EvidenceId::new("private-evidence"),
                EvidenceSource::UserStatement,
            ),
            event_id: EventId::new("private-event"),
            expected_previous_sequence: 8,
            projections: Vec::new(),
        };

        let diagnostic = format!("{command:?}");
        for secret in [
            "private-client",
            "private-workspace",
            "private-subject",
            "private-memory",
            "private-domain",
            "Call me Hippo",
            "private-evidence",
            "private-event",
        ] {
            assert!(!diagnostic.contains(secret), "diagnostic exposed {secret}");
        }
    }
}

use std::fmt;

use rembrane_domain::{
    CanonicalEvent, EventId, EventPayload, EvidenceReference, MemoryId, MemoryRecord, MemoryScope,
    MemoryShareProposal, MemoryStatus, ProjectionJob, ShareProposalId, ShareProposalStatus,
    WriteGrant, WritePermission,
};

use crate::{ApplicationError, ShareProposalMutationRepository};

#[derive(Clone, Eq, PartialEq)]
pub struct CreateShareProposalCommand {
    pub source_grant: WriteGrant,
    pub target_grant: WriteGrant,
    pub proposal_id: ShareProposalId,
    pub source_memory_id: MemoryId,
    pub source_memory_version: u64,
    pub target_scope: MemoryScope,
    pub source_event_id: EventId,
    pub expected_source_sequence: u64,
}

impl fmt::Debug for CreateShareProposalCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateShareProposalCommand")
            .field("source_memory_version", &self.source_memory_version)
            .field("target_scope_kind", &scope_kind(&self.target_scope))
            .field("expected_source_sequence", &self.expected_source_sequence)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ApproveShareProposalCommand {
    pub source_grant: WriteGrant,
    pub target_grant: WriteGrant,
    pub proposal_id: ShareProposalId,
    pub target_memory_id: MemoryId,
    pub approval_evidence: EvidenceReference,
    pub source_event_id: EventId,
    pub target_event_id: EventId,
    pub expected_source_sequence: u64,
    pub expected_target_sequence: u64,
    pub projections: Vec<ProjectionJob>,
}

impl fmt::Debug for ApproveShareProposalCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApproveShareProposalCommand")
            .field("expected_source_sequence", &self.expected_source_sequence)
            .field("expected_target_sequence", &self.expected_target_sequence)
            .field("projection_count", &self.projections.len())
            .finish_non_exhaustive()
    }
}

pub struct MemoryShareService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> MemoryShareService<'repository, Repository>
where
    Repository: ShareProposalMutationRepository,
{
    pub fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn propose(
        &mut self,
        command: CreateShareProposalCommand,
    ) -> Result<MemoryShareProposal, ApplicationError> {
        validate_grant_pair(&command.source_grant, &command.target_grant)?;
        require_permission(&command.source_grant, WritePermission::ShareMemory)?;
        require_permission(&command.target_grant, WritePermission::ProposeMemory)?;
        require_scope(&command.target_grant, &command.target_scope)?;

        let source = self
            .repository
            .find(
                &command.source_grant.workspace_id,
                &command.source_memory_id,
            )?
            .ok_or(ApplicationError::NotFound)?;
        validate_source(
            &source,
            &command.source_grant,
            command.source_memory_version,
        )?;
        let proposal = MemoryShareProposal::new(
            command.proposal_id,
            command.source_grant.workspace_id.clone(),
            command.source_memory_id,
            command.source_memory_version,
            command.source_grant.subject_id.clone(),
            command.target_grant.workspace_id.clone(),
            command.target_scope,
            command.source_grant.subject_id.clone(),
        )
        .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        let event = CanonicalEvent::new(
            command.source_event_id,
            command.source_grant.workspace_id,
            command.source_grant.subject_id.clone(),
            Some(command.source_grant.subject_id),
            next_sequence(command.expected_source_sequence)?,
            EventPayload::MemoryShareProposed {
                proposal_id: proposal.id().clone(),
                source_memory_id: proposal.source_memory_id().clone(),
                source_version: proposal.source_memory_version(),
                target_workspace_id: proposal.target_workspace_id().clone(),
            },
        )
        .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        self.repository.insert_share_proposal_with_event(
            proposal.clone(),
            event,
            command.expected_source_sequence,
        )?;
        Ok(proposal)
    }

    pub fn approve(
        &mut self,
        command: ApproveShareProposalCommand,
    ) -> Result<MemoryRecord, ApplicationError> {
        validate_grant_pair(&command.source_grant, &command.target_grant)?;
        require_permission(&command.source_grant, WritePermission::ShareMemory)?;
        require_permission(&command.target_grant, WritePermission::CreateMemory)?;

        let pending = self
            .repository
            .find_share_proposal(&command.source_grant.workspace_id, &command.proposal_id)?
            .ok_or(ApplicationError::NotFound)?;
        if pending.source_subject_id() != &command.source_grant.subject_id
            || pending.target_workspace_id() != &command.target_grant.workspace_id
        {
            return Err(ApplicationError::NotFound);
        }
        require_scope(&command.target_grant, pending.target_scope())?;

        let source = self
            .repository
            .find(pending.source_workspace_id(), pending.source_memory_id())?
            .ok_or(ApplicationError::NotFound)?;
        validate_source(
            &source,
            &command.source_grant,
            pending.source_memory_version(),
        )?;
        let approved = pending
            .approve(&command.source_grant.subject_id)
            .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        let target = MemoryRecord::approved_share_copy(
            &source,
            command.target_memory_id,
            approved.target_workspace_id().clone(),
            approved.target_scope().clone(),
            command.approval_evidence,
        )
        .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        let source_event = CanonicalEvent::new(
            command.source_event_id,
            approved.source_workspace_id().clone(),
            command.source_grant.subject_id.clone(),
            Some(command.source_grant.subject_id.clone()),
            next_sequence(command.expected_source_sequence)?,
            EventPayload::MemoryShareApproved {
                proposal_id: approved.id().clone(),
                target_workspace_id: approved.target_workspace_id().clone(),
                target_memory_id: target.id().clone(),
            },
        )
        .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        let target_event = CanonicalEvent::new(
            command.target_event_id,
            approved.target_workspace_id().clone(),
            command.target_grant.subject_id.clone(),
            Some(command.target_grant.subject_id),
            next_sequence(command.expected_target_sequence)?,
            EventPayload::MemorySharedIn {
                proposal_id: approved.id().clone(),
                source_workspace_id: approved.source_workspace_id().clone(),
                source_memory_id: approved.source_memory_id().clone(),
                source_version: approved.source_memory_version(),
                target_memory_id: target.id().clone(),
                target_version: target.version(),
            },
        )
        .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        self.repository.approve_share_proposal_with_copy(
            approved,
            ShareProposalStatus::Pending,
            target.clone(),
            source_event,
            target_event,
            command.projections,
            command.expected_source_sequence,
            command.expected_target_sequence,
        )?;
        Ok(target)
    }
}

fn validate_grant_pair(source: &WriteGrant, target: &WriteGrant) -> Result<(), ApplicationError> {
    if source.workspace_id == target.workspace_id
        || source.subject_id != target.subject_id
        || source.client_id != target.client_id
    {
        return Err(ApplicationError::AccessDenied);
    }
    Ok(())
}

fn validate_source(
    source: &MemoryRecord,
    grant: &WriteGrant,
    expected_version: u64,
) -> Result<(), ApplicationError> {
    if source.subject_id() != &grant.subject_id {
        return Err(ApplicationError::NotFound);
    }
    if source.version() != expected_version || source.status() != MemoryStatus::Confirmed {
        return Err(ApplicationError::VersionConflict);
    }
    require_scope(grant, source.scope())
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

fn require_scope(grant: &WriteGrant, scope: &MemoryScope) -> Result<(), ApplicationError> {
    if grant.allows_scope(scope) {
        Ok(())
    } else {
        Err(ApplicationError::AccessDenied)
    }
}

fn next_sequence(previous: u64) -> Result<u64, ApplicationError> {
    previous
        .checked_add(1)
        .ok_or(ApplicationError::SequenceConflict)
}

const fn scope_kind(scope: &MemoryScope) -> &'static str {
    match scope {
        MemoryScope::Global => "global",
        MemoryScope::Domain { .. } => "domain",
        MemoryScope::Entity { .. } => "entity",
        MemoryScope::Activity { .. } => "activity",
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use rembrane_domain::{
        ClientId, EventId, MemoryId, MemoryScope, PrincipalId, ShareProposalId, WorkspaceId,
        WriteGrant,
    };

    use super::CreateShareProposalCommand;

    fn grant(workspace: &str) -> WriteGrant {
        WriteGrant {
            client_id: ClientId::new("private-client"),
            workspace_id: WorkspaceId::new(workspace),
            subject_id: PrincipalId::new("private-subject"),
            scopes: Vec::new(),
            permissions: Vec::new(),
        }
    }

    #[test]
    fn share_proposal_diagnostics_redact_cross_workspace_routing() {
        let command = CreateShareProposalCommand {
            source_grant: grant("private-source-workspace"),
            target_grant: grant("private-target-workspace"),
            proposal_id: ShareProposalId::new("private-proposal"),
            source_memory_id: MemoryId::new("private-memory"),
            source_memory_version: 7,
            target_scope: MemoryScope::Domain {
                name: "private-domain".to_owned(),
            },
            source_event_id: EventId::new("private-event"),
            expected_source_sequence: 11,
        };

        let diagnostic = format!("{command:?}");
        for secret in [
            "private-client",
            "private-subject",
            "private-source-workspace",
            "private-target-workspace",
            "private-proposal",
            "private-memory",
            "private-domain",
            "private-event",
        ] {
            assert!(!diagnostic.contains(secret), "diagnostic exposed {secret}");
        }
        assert!(diagnostic.contains("domain"));
    }
}

use std::error::Error;
use std::fmt::{self, Display};

use crate::{MemoryId, MemoryScope, PrincipalId, ShareProposalId, WorkspaceId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareProposalStatus {
    Pending,
    Approved,
    Rejected,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareProposalError {
    InvalidSourceVersion,
    SameWorkspace,
    NotPending,
    NotSourceOwner,
    NotAuthorizedToRevoke,
}

impl Display for ShareProposalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSourceVersion => {
                formatter.write_str("source memory version must be greater than zero")
            }
            Self::SameWorkspace => {
                formatter.write_str("private-to-shared proposal requires distinct workspaces")
            }
            Self::NotPending => formatter.write_str("share proposal is no longer pending"),
            Self::NotSourceOwner => {
                formatter.write_str("only the source memory owner may decide sharing")
            }
            Self::NotAuthorizedToRevoke => {
                formatter.write_str("only the proposer or source memory owner may revoke sharing")
            }
        }
    }
}

impl Error for ShareProposalError {}

/// Content-free intent to copy one exact private-memory version into another
/// workspace.
///
/// The source content is deliberately absent. It remains in the source
/// workspace until the source subject approves an atomic cross-workspace copy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryShareProposal {
    id: ShareProposalId,
    source_workspace_id: WorkspaceId,
    source_memory_id: MemoryId,
    source_memory_version: u64,
    source_subject_id: PrincipalId,
    target_workspace_id: WorkspaceId,
    target_scope: MemoryScope,
    proposed_by: PrincipalId,
    status: ShareProposalStatus,
}

impl MemoryShareProposal {
    pub fn new(
        id: ShareProposalId,
        source_workspace_id: WorkspaceId,
        source_memory_id: MemoryId,
        source_memory_version: u64,
        source_subject_id: PrincipalId,
        target_workspace_id: WorkspaceId,
        target_scope: MemoryScope,
        proposed_by: PrincipalId,
    ) -> Result<Self, ShareProposalError> {
        Self::restore(
            id,
            source_workspace_id,
            source_memory_id,
            source_memory_version,
            source_subject_id,
            target_workspace_id,
            target_scope,
            proposed_by,
            ShareProposalStatus::Pending,
        )
    }

    pub fn restore(
        id: ShareProposalId,
        source_workspace_id: WorkspaceId,
        source_memory_id: MemoryId,
        source_memory_version: u64,
        source_subject_id: PrincipalId,
        target_workspace_id: WorkspaceId,
        target_scope: MemoryScope,
        proposed_by: PrincipalId,
        status: ShareProposalStatus,
    ) -> Result<Self, ShareProposalError> {
        if source_memory_version == 0 {
            return Err(ShareProposalError::InvalidSourceVersion);
        }
        if source_workspace_id == target_workspace_id {
            return Err(ShareProposalError::SameWorkspace);
        }
        Ok(Self {
            id,
            source_workspace_id,
            source_memory_id,
            source_memory_version,
            source_subject_id,
            target_workspace_id,
            target_scope,
            proposed_by,
            status,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &ShareProposalId {
        &self.id
    }

    #[must_use]
    pub const fn source_workspace_id(&self) -> &WorkspaceId {
        &self.source_workspace_id
    }

    #[must_use]
    pub const fn source_memory_id(&self) -> &MemoryId {
        &self.source_memory_id
    }

    #[must_use]
    pub const fn source_memory_version(&self) -> u64 {
        self.source_memory_version
    }

    #[must_use]
    pub const fn source_subject_id(&self) -> &PrincipalId {
        &self.source_subject_id
    }

    #[must_use]
    pub const fn target_workspace_id(&self) -> &WorkspaceId {
        &self.target_workspace_id
    }

    #[must_use]
    pub const fn target_scope(&self) -> &MemoryScope {
        &self.target_scope
    }

    #[must_use]
    pub const fn proposed_by(&self) -> &PrincipalId {
        &self.proposed_by
    }

    #[must_use]
    pub const fn status(&self) -> ShareProposalStatus {
        self.status
    }

    pub fn approve(mut self, actor: &PrincipalId) -> Result<Self, ShareProposalError> {
        self.require_pending()?;
        self.require_source_owner(actor)?;
        self.status = ShareProposalStatus::Approved;
        Ok(self)
    }

    pub fn reject(mut self, actor: &PrincipalId) -> Result<Self, ShareProposalError> {
        self.require_pending()?;
        self.require_source_owner(actor)?;
        self.status = ShareProposalStatus::Rejected;
        Ok(self)
    }

    pub fn revoke(mut self, actor: &PrincipalId) -> Result<Self, ShareProposalError> {
        self.require_pending()?;
        if actor != &self.proposed_by && actor != &self.source_subject_id {
            return Err(ShareProposalError::NotAuthorizedToRevoke);
        }
        self.status = ShareProposalStatus::Revoked;
        Ok(self)
    }

    fn require_pending(&self) -> Result<(), ShareProposalError> {
        if self.status == ShareProposalStatus::Pending {
            Ok(())
        } else {
            Err(ShareProposalError::NotPending)
        }
    }

    fn require_source_owner(&self, actor: &PrincipalId) -> Result<(), ShareProposalError> {
        if actor == &self.source_subject_id {
            Ok(())
        } else {
            Err(ShareProposalError::NotSourceOwner)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MemoryShareProposal, ShareProposalError, ShareProposalStatus};
    use crate::{EntityId, MemoryId, MemoryScope, PrincipalId, ShareProposalId, WorkspaceId};

    fn proposal() -> MemoryShareProposal {
        MemoryShareProposal::new(
            ShareProposalId::new("share_01"),
            WorkspaceId::new("personal_01"),
            MemoryId::new("memory_01"),
            3,
            PrincipalId::new("owner_01"),
            WorkspaceId::new("team_01"),
            MemoryScope::Entity {
                id: EntityId::new("project_01"),
            },
            PrincipalId::new("agent_01"),
        )
        .expect("cross-workspace proposal should be valid")
    }

    #[test]
    fn only_source_owner_can_approve_content_disclosure() {
        assert_eq!(
            proposal().approve(&PrincipalId::new("agent_01")),
            Err(ShareProposalError::NotSourceOwner)
        );
        assert_eq!(
            proposal()
                .approve(&PrincipalId::new("owner_01"))
                .expect("source owner should approve")
                .status(),
            ShareProposalStatus::Approved
        );
    }

    #[test]
    fn proposer_can_revoke_before_approval() {
        let revoked = proposal()
            .revoke(&PrincipalId::new("agent_01"))
            .expect("proposer should revoke pending intent");
        assert_eq!(revoked.status(), ShareProposalStatus::Revoked);
        assert_eq!(
            revoked.approve(&PrincipalId::new("owner_01")),
            Err(ShareProposalError::NotPending)
        );
    }

    #[test]
    fn proposal_contains_reference_and_intent_but_no_content() {
        let proposal = proposal();
        assert_eq!(proposal.source_memory_version(), 3);
        assert_eq!(proposal.target_workspace_id(), &WorkspaceId::new("team_01"));
    }

    #[test]
    fn rejects_same_workspace_and_zero_source_version() {
        let create = |version, target| {
            MemoryShareProposal::new(
                ShareProposalId::new("share_01"),
                WorkspaceId::new("personal_01"),
                MemoryId::new("memory_01"),
                version,
                PrincipalId::new("owner_01"),
                WorkspaceId::new(target),
                MemoryScope::Global,
                PrincipalId::new("agent_01"),
            )
        };

        assert_eq!(
            create(0, "team_01"),
            Err(ShareProposalError::InvalidSourceVersion)
        );
        assert_eq!(
            create(1, "personal_01"),
            Err(ShareProposalError::SameWorkspace)
        );
    }
}

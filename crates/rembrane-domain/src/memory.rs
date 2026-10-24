use crate::{EvidenceReference, MemoryId, MemoryScope, PrincipalId, WorkspaceId};
use std::error::Error;
use std::fmt::{self, Display};

pub const MAX_MEMORY_CONTENT_BYTES: usize = 262_144;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryKind {
    Preference,
    Semantic,
    Episodic,
    Procedural,
    Observation,
    Working,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryStatus {
    Proposed,
    Confirmed,
    Superseded,
    Deleted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryLifecycleError {
    EmptyContent,
    ContentTooLarge,
    MissingEvidence,
    DuplicateEvidence,
    InvalidStatus,
    InvalidVersion,
    SameWorkspace,
    VersionOverflow,
}

impl Display for MemoryLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyContent => formatter.write_str("content must not be empty"),
            Self::ContentTooLarge => {
                formatter.write_str("content exceeds the canonical byte limit")
            }
            Self::MissingEvidence => formatter.write_str("memory must reference evidence"),
            Self::DuplicateEvidence => {
                formatter.write_str("memory evidence references must be unique")
            }
            Self::InvalidStatus => {
                formatter.write_str("memory status does not allow this transition")
            }
            Self::InvalidVersion => formatter.write_str("memory version must be greater than zero"),
            Self::SameWorkspace => {
                formatter.write_str("shared copy requires a different target workspace")
            }
            Self::VersionOverflow => formatter.write_str("memory version cannot be incremented"),
        }
    }
}

impl Error for MemoryLifecycleError {}

/// Canonical memory metadata and content.
///
/// Time, provenance, evidence, and encryption metadata will be introduced as
/// explicit value objects before persistence is implemented.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryRecord {
    id: MemoryId,
    workspace_id: WorkspaceId,
    subject_id: PrincipalId,
    scope: MemoryScope,
    kind: MemoryKind,
    status: MemoryStatus,
    content: String,
    version: u64,
    evidence: Vec<EvidenceReference>,
}

impl MemoryRecord {
    pub fn restore(
        id: MemoryId,
        workspace_id: WorkspaceId,
        subject_id: PrincipalId,
        scope: MemoryScope,
        kind: MemoryKind,
        status: MemoryStatus,
        content: impl Into<String>,
        version: u64,
        evidence: Vec<EvidenceReference>,
    ) -> Result<Self, MemoryLifecycleError> {
        let content = content.into();
        if version == 0 {
            return Err(MemoryLifecycleError::InvalidVersion);
        }
        if evidence.is_empty() {
            return Err(MemoryLifecycleError::MissingEvidence);
        }
        if status == MemoryStatus::Deleted {
            if !content.is_empty() {
                return Err(MemoryLifecycleError::InvalidStatus);
            }
        } else if content.trim().is_empty() {
            return Err(MemoryLifecycleError::EmptyContent);
        } else if content.len() > MAX_MEMORY_CONTENT_BYTES {
            return Err(MemoryLifecycleError::ContentTooLarge);
        }

        Ok(Self {
            id,
            workspace_id,
            subject_id,
            scope,
            kind,
            status,
            content,
            version,
            evidence,
        })
    }

    #[must_use]
    pub const fn id(&self) -> &MemoryId {
        &self.id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn subject_id(&self) -> &PrincipalId {
        &self.subject_id
    }

    #[must_use]
    pub const fn scope(&self) -> &MemoryScope {
        &self.scope
    }

    #[must_use]
    pub const fn kind(&self) -> MemoryKind {
        self.kind
    }

    #[must_use]
    pub const fn status(&self) -> MemoryStatus {
        self.status
    }

    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub fn evidence(&self) -> &[EvidenceReference] {
        &self.evidence
    }

    pub fn confirmed_preference(
        id: MemoryId,
        workspace_id: WorkspaceId,
        subject_id: PrincipalId,
        scope: MemoryScope,
        content: impl Into<String>,
        evidence: EvidenceReference,
    ) -> Result<Self, MemoryLifecycleError> {
        let content = content.into();
        if content.trim().is_empty() {
            return Err(MemoryLifecycleError::EmptyContent);
        }
        if content.len() > MAX_MEMORY_CONTENT_BYTES {
            return Err(MemoryLifecycleError::ContentTooLarge);
        }

        Ok(Self {
            id,
            workspace_id,
            subject_id,
            scope,
            kind: MemoryKind::Preference,
            status: MemoryStatus::Confirmed,
            content,
            version: 1,
            evidence: vec![evidence],
        })
    }

    pub fn proposed(
        id: MemoryId,
        workspace_id: WorkspaceId,
        subject_id: PrincipalId,
        scope: MemoryScope,
        kind: MemoryKind,
        content: impl Into<String>,
        evidence: EvidenceReference,
    ) -> Result<Self, MemoryLifecycleError> {
        let content = content.into();
        if content.trim().is_empty() {
            return Err(MemoryLifecycleError::EmptyContent);
        }
        if content.len() > MAX_MEMORY_CONTENT_BYTES {
            return Err(MemoryLifecycleError::ContentTooLarge);
        }

        Ok(Self {
            id,
            workspace_id,
            subject_id,
            scope,
            kind,
            status: MemoryStatus::Proposed,
            content,
            version: 1,
            evidence: vec![evidence],
        })
    }

    pub fn approved_share_copy(
        source: &Self,
        id: MemoryId,
        target_workspace_id: WorkspaceId,
        target_scope: MemoryScope,
        approval_evidence: EvidenceReference,
    ) -> Result<Self, MemoryLifecycleError> {
        if source.status != MemoryStatus::Confirmed {
            return Err(MemoryLifecycleError::InvalidStatus);
        }
        if source.workspace_id == target_workspace_id {
            return Err(MemoryLifecycleError::SameWorkspace);
        }
        if source
            .evidence
            .iter()
            .any(|evidence| evidence.id == approval_evidence.id)
        {
            return Err(MemoryLifecycleError::DuplicateEvidence);
        }
        let mut evidence = source.evidence.clone();
        evidence.push(approval_evidence);
        Ok(Self {
            id,
            workspace_id: target_workspace_id,
            subject_id: source.subject_id.clone(),
            scope: target_scope,
            kind: source.kind,
            status: MemoryStatus::Confirmed,
            content: source.content.clone(),
            version: 1,
            evidence,
        })
    }

    pub fn confirm(mut self, evidence: EvidenceReference) -> Result<Self, MemoryLifecycleError> {
        if self.status != MemoryStatus::Proposed {
            return Err(MemoryLifecycleError::InvalidStatus);
        }

        self.version = self
            .version
            .checked_add(1)
            .ok_or(MemoryLifecycleError::VersionOverflow)?;
        self.status = MemoryStatus::Confirmed;
        self.evidence.push(evidence);
        Ok(self)
    }

    pub fn revise(
        mut self,
        content: impl Into<String>,
        evidence: EvidenceReference,
    ) -> Result<Self, MemoryLifecycleError> {
        if self.status != MemoryStatus::Confirmed {
            return Err(MemoryLifecycleError::InvalidStatus);
        }

        let content = content.into();
        if content.trim().is_empty() {
            return Err(MemoryLifecycleError::EmptyContent);
        }
        if content.len() > MAX_MEMORY_CONTENT_BYTES {
            return Err(MemoryLifecycleError::ContentTooLarge);
        }

        self.version = self
            .version
            .checked_add(1)
            .ok_or(MemoryLifecycleError::VersionOverflow)?;
        self.content = content;
        self.evidence.push(evidence);
        Ok(self)
    }

    pub fn delete(mut self, evidence: EvidenceReference) -> Result<Self, MemoryLifecycleError> {
        if self.status == MemoryStatus::Deleted {
            return Err(MemoryLifecycleError::InvalidStatus);
        }

        self.version = self
            .version
            .checked_add(1)
            .ok_or(MemoryLifecycleError::VersionOverflow)?;
        self.status = MemoryStatus::Deleted;
        self.content.clear();
        self.evidence.push(evidence);
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::{MemoryKind, MemoryLifecycleError, MemoryRecord, MemoryStatus};
    use crate::{
        EvidenceId, EvidenceReference, EvidenceSource, MemoryId, MemoryScope, PrincipalId,
        WorkspaceId,
    };

    #[test]
    fn creates_confirmed_global_preference() {
        let memory = MemoryRecord::confirmed_preference(
            MemoryId::new("memory_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            MemoryScope::Global,
            "Call me Hippo",
            EvidenceReference::new(
                EvidenceId::new("evidence_01"),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("non-empty preference should be valid");

        assert_eq!(memory.kind, MemoryKind::Preference);
        assert_eq!(memory.status, MemoryStatus::Confirmed);
        assert_eq!(memory.version, 1);
        assert_eq!(memory.evidence.len(), 1);
    }

    #[test]
    fn revision_increments_version_and_preserves_evidence() {
        let original = MemoryRecord::confirmed_preference(
            MemoryId::new("memory_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            MemoryScope::Global,
            "Call me Hippo",
            EvidenceReference::new(
                EvidenceId::new("evidence_01"),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("non-empty preference should be valid");

        let revised = original
            .revise(
                "Call me Captain Hippo",
                EvidenceReference::new(
                    EvidenceId::new("evidence_02"),
                    EvidenceSource::UserStatement,
                ),
            )
            .expect("confirmed memory should be revisable");

        assert_eq!(revised.version, 2);
        assert_eq!(revised.content, "Call me Captain Hippo");
        assert_eq!(revised.evidence.len(), 2);
    }

    #[test]
    fn deletion_creates_versioned_tombstone() {
        let original = MemoryRecord::confirmed_preference(
            MemoryId::new("memory_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            MemoryScope::Global,
            "Call me Hippo",
            EvidenceReference::new(
                EvidenceId::new("evidence_01"),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("non-empty preference should be valid");

        let deleted = original
            .delete(EvidenceReference::new(
                EvidenceId::new("evidence_delete"),
                EvidenceSource::UserStatement,
            ))
            .expect("active memory should be deletable");

        assert_eq!(deleted.version, 2);
        assert_eq!(deleted.status, MemoryStatus::Deleted);
        assert_eq!(deleted.content, "");
    }

    #[test]
    fn rejects_empty_confirmed_preference() {
        let error = MemoryRecord::confirmed_preference(
            MemoryId::new("memory_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            MemoryScope::Global,
            " ",
            EvidenceReference::new(
                EvidenceId::new("evidence_01"),
                EvidenceSource::UserStatement,
            ),
        )
        .expect_err("empty confirmed memory should fail");

        assert_eq!(error, MemoryLifecycleError::EmptyContent);
    }

    #[test]
    fn proposal_requires_explicit_confirmation() {
        let proposal = MemoryRecord::proposed(
            MemoryId::new("memory_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            MemoryScope::Global,
            MemoryKind::Observation,
            "The user may prefer aisle seats.",
            EvidenceReference::new(
                EvidenceId::new("evidence_observation"),
                EvidenceSource::AgentObservation,
            ),
        )
        .expect("non-empty proposal should be valid");

        assert_eq!(proposal.status(), MemoryStatus::Proposed);

        let confirmed = proposal
            .confirm(EvidenceReference::new(
                EvidenceId::new("evidence_confirmation"),
                EvidenceSource::UserStatement,
            ))
            .expect("proposal should be confirmable");

        assert_eq!(confirmed.status(), MemoryStatus::Confirmed);
        assert_eq!(confirmed.version(), 2);
        assert_eq!(confirmed.evidence().len(), 2);
    }

    #[test]
    fn rejects_memory_content_over_the_canonical_limit() {
        let error = MemoryRecord::confirmed_preference(
            MemoryId::new("memory_large"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            MemoryScope::Global,
            "x".repeat(super::MAX_MEMORY_CONTENT_BYTES + 1),
            EvidenceReference::new(
                EvidenceId::new("evidence_large"),
                EvidenceSource::UserStatement,
            ),
        )
        .expect_err("oversized memory should fail");

        assert_eq!(error, MemoryLifecycleError::ContentTooLarge);
    }

    #[test]
    fn approved_share_copy_preserves_source_and_adds_approval() {
        let source = MemoryRecord::confirmed_preference(
            MemoryId::new("private_memory"),
            WorkspaceId::new("personal_01"),
            PrincipalId::new("principal_01"),
            MemoryScope::Global,
            "Call me Hippo",
            EvidenceReference::new(
                EvidenceId::new("evidence_source"),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("source should be valid");

        let shared = MemoryRecord::approved_share_copy(
            &source,
            MemoryId::new("shared_memory"),
            WorkspaceId::new("team_01"),
            MemoryScope::Global,
            EvidenceReference::new(
                EvidenceId::new("evidence_approval"),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("approved cross-workspace copy should be valid");

        assert_eq!(shared.subject_id(), source.subject_id());
        assert_eq!(shared.kind(), source.kind());
        assert_eq!(shared.content(), source.content());
        assert_eq!(shared.status(), MemoryStatus::Confirmed);
        assert_eq!(shared.version(), 1);
        assert_eq!(shared.evidence().len(), 2);
        assert_eq!(source.evidence().len(), 1);
    }

    #[test]
    fn shared_copy_rejects_same_workspace_and_duplicate_approval() {
        let source_evidence = EvidenceReference::new(
            EvidenceId::new("evidence_source"),
            EvidenceSource::UserStatement,
        );
        let source = MemoryRecord::confirmed_preference(
            MemoryId::new("private_memory"),
            WorkspaceId::new("personal_01"),
            PrincipalId::new("principal_01"),
            MemoryScope::Global,
            "Call me Hippo",
            source_evidence.clone(),
        )
        .expect("source should be valid");

        assert_eq!(
            MemoryRecord::approved_share_copy(
                &source,
                MemoryId::new("shared_memory"),
                WorkspaceId::new("personal_01"),
                MemoryScope::Global,
                EvidenceReference::new(EvidenceId::new("approval"), EvidenceSource::UserStatement,),
            ),
            Err(MemoryLifecycleError::SameWorkspace)
        );
        assert_eq!(
            MemoryRecord::approved_share_copy(
                &source,
                MemoryId::new("shared_memory"),
                WorkspaceId::new("team_01"),
                MemoryScope::Global,
                source_evidence,
            ),
            Err(MemoryLifecycleError::DuplicateEvidence)
        );
    }
}

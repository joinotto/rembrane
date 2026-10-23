use crate::{
    EvidenceReference, MemoryId, MemoryScope, PrincipalId, WorkspaceId,
};
use std::error::Error;
use std::fmt::{self, Display};

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
    InvalidStatus,
    VersionOverflow,
}

impl Display for MemoryLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyContent => formatter.write_str("content must not be empty"),
            Self::InvalidStatus => {
                formatter.write_str("memory status does not allow this transition")
            }
            Self::VersionOverflow => {
                formatter.write_str("memory version cannot be incremented")
            }
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

    #[must_use]
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

        self.version = self
            .version
            .checked_add(1)
            .ok_or(MemoryLifecycleError::VersionOverflow)?;
        self.content = content;
        self.evidence.push(evidence);
        Ok(self)
    }

    pub fn delete(
        mut self,
        evidence: EvidenceReference,
    ) -> Result<Self, MemoryLifecycleError> {
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
    use super::{
        MemoryKind, MemoryLifecycleError, MemoryRecord, MemoryStatus,
    };
    use crate::{
        EvidenceId, EvidenceReference, EvidenceSource, MemoryId, MemoryScope,
        PrincipalId, WorkspaceId,
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
        assert!(deleted.content.is_empty());
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
}

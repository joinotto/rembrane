use crate::{MemoryId, MemoryScope, PrincipalId, WorkspaceId};

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

/// Canonical memory metadata and content.
///
/// Time, provenance, evidence, and encryption metadata will be introduced as
/// explicit value objects before persistence is implemented.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryRecord {
    pub id: MemoryId,
    pub workspace_id: WorkspaceId,
    pub subject_id: PrincipalId,
    pub scope: MemoryScope,
    pub kind: MemoryKind,
    pub status: MemoryStatus,
    pub content: String,
    pub version: u64,
}

impl MemoryRecord {
    #[must_use]
    pub fn confirmed_preference(
        id: MemoryId,
        workspace_id: WorkspaceId,
        subject_id: PrincipalId,
        scope: MemoryScope,
        content: impl Into<String>,
    ) -> Self {
        Self {
            id,
            workspace_id,
            subject_id,
            scope,
            kind: MemoryKind::Preference,
            status: MemoryStatus::Confirmed,
            content: content.into(),
            version: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MemoryKind, MemoryRecord, MemoryStatus};
    use crate::{MemoryId, MemoryScope, PrincipalId, WorkspaceId};

    #[test]
    fn creates_confirmed_global_preference() {
        let memory = MemoryRecord::confirmed_preference(
            MemoryId::new("memory_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            MemoryScope::Global,
            "Call me Hippo",
        );

        assert_eq!(memory.kind, MemoryKind::Preference);
        assert_eq!(memory.status, MemoryStatus::Confirmed);
        assert_eq!(memory.version, 1);
    }
}

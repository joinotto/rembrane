//! Volatile reference adapter used by tests, examples, and local prototypes.

use rembrane_application::{
    ApplicationError, DisclosureRepository, MemoryRepository,
};
use rembrane_domain::{
    DisclosureReceipt, MemoryId, MemoryRecord, PrincipalId, WorkspaceId,
};

#[derive(Debug, Default)]
pub struct InMemoryStore {
    memories: Vec<MemoryRecord>,
    disclosures: Vec<DisclosureReceipt>,
}

impl InMemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn disclosure_count(&self) -> usize {
        self.disclosures.len()
    }
}

impl MemoryRepository for InMemoryStore {
    fn insert(&mut self, memory: MemoryRecord) -> Result<(), ApplicationError> {
        let duplicate = self.memories.iter().any(|stored| {
            stored.workspace_id() == memory.workspace_id()
                && stored.id() == memory.id()
        });

        if duplicate {
            return Err(ApplicationError::AlreadyExists);
        }

        self.memories.push(memory);
        Ok(())
    }

    fn find(
        &self,
        workspace_id: &WorkspaceId,
        memory_id: &MemoryId,
    ) -> Result<Option<MemoryRecord>, ApplicationError> {
        Ok(self
            .memories
            .iter()
            .find(|memory| {
                memory.workspace_id() == workspace_id
                    && memory.id() == memory_id
            })
            .cloned())
    }

    fn list_for_subject(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
    ) -> Result<Vec<MemoryRecord>, ApplicationError> {
        Ok(self
            .memories
            .iter()
            .filter(|memory| {
                memory.workspace_id() == workspace_id
                    && memory.subject_id() == subject_id
            })
            .cloned()
            .collect())
    }

    fn replace(
        &mut self,
        memory: MemoryRecord,
        expected_version: u64,
    ) -> Result<(), ApplicationError> {
        let stored = self
            .memories
            .iter_mut()
            .find(|stored| {
                stored.workspace_id() == memory.workspace_id()
                    && stored.id() == memory.id()
            })
            .ok_or(ApplicationError::NotFound)?;

        if stored.version() != expected_version
            || memory.version() != expected_version.saturating_add(1)
        {
            return Err(ApplicationError::VersionConflict);
        }

        *stored = memory;
        Ok(())
    }
}

impl DisclosureRepository for InMemoryStore {
    fn append(
        &mut self,
        receipt: DisclosureReceipt,
    ) -> Result<(), ApplicationError> {
        let duplicate = self
            .disclosures
            .iter()
            .any(|stored| stored.id == receipt.id);

        if duplicate {
            return Err(ApplicationError::AlreadyExists);
        }

        self.disclosures.push(receipt);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rembrane_application::{ApplicationError, MemoryRepository};
    use rembrane_domain::{
        EvidenceId, EvidenceReference, EvidenceSource, MemoryId, MemoryRecord,
        MemoryScope, PrincipalId, WorkspaceId,
    };

    use super::InMemoryStore;

    fn preference(
        memory_id: &str,
        workspace_id: &str,
        subject_id: &str,
        content: &str,
    ) -> MemoryRecord {
        MemoryRecord::confirmed_preference(
            MemoryId::new(memory_id),
            WorkspaceId::new(workspace_id),
            PrincipalId::new(subject_id),
            MemoryScope::Global,
            content,
            EvidenceReference::new(
                EvidenceId::new(format!("evidence_{memory_id}")),
                EvidenceSource::UserStatement,
            ),
        )
    }

    #[test]
    fn does_not_find_memory_across_workspace_boundary() {
        let mut store = InMemoryStore::new();
        store
            .insert(preference(
                "memory_01",
                "workspace_private",
                "principal_01",
                "Call me Hippo",
            ))
            .expect("insert should succeed");

        let result = store
            .find(
                &WorkspaceId::new("workspace_other"),
                &MemoryId::new("memory_01"),
            )
            .expect("lookup should succeed");

        assert!(result.is_none());
    }

    #[test]
    fn permits_same_memory_id_in_different_workspaces() {
        let mut store = InMemoryStore::new();
        store
            .insert(preference(
                "memory_01",
                "workspace_one",
                "principal_01",
                "Preference one",
            ))
            .expect("first insert should succeed");
        store
            .insert(preference(
                "memory_01",
                "workspace_two",
                "principal_02",
                "Preference two",
            ))
            .expect("second workspace insert should succeed");

        assert_eq!(
            store
                .list_for_subject(
                    &WorkspaceId::new("workspace_one"),
                    &PrincipalId::new("principal_01"),
                )
                .expect("lookup should succeed")
                .len(),
            1
        );
        assert_eq!(
            store
                .list_for_subject(
                    &WorkspaceId::new("workspace_two"),
                    &PrincipalId::new("principal_02"),
                )
                .expect("lookup should succeed")
                .len(),
            1
        );
    }

    #[test]
    fn rejects_duplicate_memory_within_workspace() {
        let mut store = InMemoryStore::new();
        let memory = preference(
            "memory_01",
            "workspace_one",
            "principal_01",
            "Call me Hippo",
        );

        store
            .insert(memory.clone())
            .expect("first insert should succeed");
        let error = store
            .insert(memory)
            .expect_err("duplicate insert should fail");

        assert_eq!(error, ApplicationError::AlreadyExists);
    }

    #[test]
    fn rejects_stale_revision() {
        let mut store = InMemoryStore::new();
        let original = preference(
            "memory_01",
            "workspace_one",
            "principal_01",
            "Call me Hippo",
        );
        store
            .insert(original.clone())
            .expect("initial insert should succeed");

        let revised = original
            .revise(
                "Call me Captain Hippo",
                rembrane_domain::EvidenceReference::new(
                    rembrane_domain::EvidenceId::new("evidence_revision"),
                    rembrane_domain::EvidenceSource::UserStatement,
                ),
            )
            .expect("revision should be valid");

        let error = store
            .replace(revised, 2)
            .expect_err("stale expected version should fail");

        assert_eq!(error, ApplicationError::VersionConflict);
    }
}

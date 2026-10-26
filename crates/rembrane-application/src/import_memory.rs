use std::collections::HashSet;

use rembrane_domain::{
    CanonicalEvent, EventId, EventPayload, EvidenceReference, MemoryId, MemoryKind, MemoryRecord,
    MemoryScope, WriteGrant, WritePermission,
};

use crate::{ApplicationError, MemoryImportRepository};

pub const MAXIMUM_MEMORY_IMPORT_ITEMS: usize = 10_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedMemoryProposal {
    pub memory_id: MemoryId,
    pub event_id: EventId,
    pub scope: MemoryScope,
    pub kind: MemoryKind,
    pub content: String,
    pub evidence: EvidenceReference,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportMemoryBatchCommand {
    pub grant: WriteGrant,
    pub items: Vec<ImportedMemoryProposal>,
    pub expected_previous_sequence: u64,
}

pub struct ImportMemoryBatchService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> ImportMemoryBatchService<'repository, Repository>
where
    Repository: MemoryImportRepository,
{
    pub fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn execute(
        &mut self,
        command: ImportMemoryBatchCommand,
    ) -> Result<Vec<MemoryRecord>, ApplicationError> {
        if command.items.len() > MAXIMUM_MEMORY_IMPORT_ITEMS {
            return Err(ApplicationError::Validation(
                "memory import batch exceeds the item limit".to_owned(),
            ));
        }
        if !command.grant.allows(WritePermission::ProposeMemory) {
            return Err(ApplicationError::AccessDenied);
        }
        let mut memory_ids = HashSet::new();
        let mut event_ids = HashSet::new();
        let mut mutations = Vec::with_capacity(command.items.len());
        for (offset, item) in command.items.into_iter().enumerate() {
            if !command.grant.allows_scope(&item.scope) {
                return Err(ApplicationError::AccessDenied);
            }
            if !memory_ids.insert(item.memory_id.clone())
                || !event_ids.insert(item.event_id.clone())
            {
                return Err(ApplicationError::Validation(
                    "memory import contains duplicate target identifiers".to_owned(),
                ));
            }
            let memory = MemoryRecord::proposed(
                item.memory_id,
                command.grant.workspace_id.clone(),
                command.grant.subject_id.clone(),
                item.scope,
                item.kind,
                item.content,
                item.evidence,
            )
            .map_err(|error| ApplicationError::Validation(error.to_string()))?;
            let increment = u64::try_from(offset)
                .ok()
                .and_then(|offset| offset.checked_add(1))
                .ok_or(ApplicationError::SequenceConflict)?;
            let sequence = command
                .expected_previous_sequence
                .checked_add(increment)
                .ok_or(ApplicationError::SequenceConflict)?;
            let event = CanonicalEvent::new(
                item.event_id,
                command.grant.workspace_id.clone(),
                command.grant.subject_id.clone(),
                Some(command.grant.subject_id.clone()),
                sequence,
                EventPayload::MemoryProposed {
                    memory_id: memory.id().clone(),
                    version: memory.version(),
                },
            )
            .map_err(|error| ApplicationError::Validation(error.to_string()))?;
            mutations.push((memory, event));
        }
        self.repository
            .insert_imported_memory_batch(&mutations, command.expected_previous_sequence)?;
        Ok(mutations.into_iter().map(|(memory, _)| memory).collect())
    }
}

#[cfg(test)]
mod tests {
    use rembrane_domain::{
        ClientId, EventId, EvidenceId, EvidenceReference, EvidenceSource, MemoryId, MemoryKind,
        MemoryScope, PrincipalId, ReadScope, WorkspaceId, WriteGrant, WritePermission,
    };

    use super::{ImportMemoryBatchCommand, ImportMemoryBatchService, ImportedMemoryProposal};
    use crate::{ApplicationError, MemoryImportRepository};

    #[derive(Default)]
    struct ImportRepository {
        mutations: Vec<(
            rembrane_domain::MemoryRecord,
            rembrane_domain::CanonicalEvent,
        )>,
    }

    impl MemoryImportRepository for ImportRepository {
        fn insert_imported_memory_batch(
            &mut self,
            mutations: &[(
                rembrane_domain::MemoryRecord,
                rembrane_domain::CanonicalEvent,
            )],
            _expected_previous_sequence: u64,
        ) -> Result<(), ApplicationError> {
            self.mutations.extend_from_slice(mutations);
            Ok(())
        }
    }

    fn grant(scopes: Vec<ReadScope>) -> WriteGrant {
        WriteGrant {
            client_id: ClientId::new("importer"),
            workspace_id: WorkspaceId::new("target"),
            subject_id: PrincipalId::new("hippo"),
            scopes,
            permissions: vec![WritePermission::ProposeMemory],
        }
    }

    fn item(id: &str, scope: MemoryScope) -> ImportedMemoryProposal {
        ImportedMemoryProposal {
            memory_id: MemoryId::new(format!("import_{id}")),
            event_id: EventId::new(format!("event_{id}")),
            scope,
            kind: MemoryKind::Preference,
            content: format!("memory {id}"),
            evidence: EvidenceReference::new(
                EvidenceId::new(format!("evidence_{id}")),
                EvidenceSource::ImportedRecord,
            ),
        }
    }

    #[test]
    fn imports_a_batch_as_destination_scoped_proposals() {
        let mut repository = ImportRepository::default();
        let records = ImportMemoryBatchService::new(&mut repository)
            .execute(ImportMemoryBatchCommand {
                grant: grant(vec![ReadScope::Global]),
                items: vec![
                    item("a", MemoryScope::Global),
                    item("b", MemoryScope::Global),
                ],
                expected_previous_sequence: 0,
            })
            .expect("batch import");

        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| {
            record.workspace_id() == &WorkspaceId::new("target")
                && record.subject_id() == &PrincipalId::new("hippo")
                && record.status() == rembrane_domain::MemoryStatus::Proposed
        }));
        assert_eq!(repository.mutations.len(), 2);
        assert_eq!(repository.mutations[0].1.sequence(), 1);
        assert_eq!(repository.mutations[1].1.sequence(), 2);
    }

    #[test]
    fn rejects_the_whole_batch_before_storage_on_scope_or_identity_failure() {
        let mut repository = ImportRepository::default();
        let duplicate = item("same", MemoryScope::Global);
        let error = ImportMemoryBatchService::new(&mut repository)
            .execute(ImportMemoryBatchCommand {
                grant: grant(vec![ReadScope::Global]),
                items: vec![
                    duplicate.clone(),
                    duplicate,
                    item(
                        "denied",
                        MemoryScope::Domain {
                            name: "travel".to_owned(),
                        },
                    ),
                ],
                expected_previous_sequence: 0,
            })
            .expect_err("invalid batch");

        assert!(matches!(
            error,
            ApplicationError::Validation(_) | ApplicationError::AccessDenied
        ));
        assert_eq!(repository.mutations.len(), 0);
    }
}

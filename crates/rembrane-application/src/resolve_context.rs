use rembrane_contracts::{
    ResolveContextRequest, ResolveContextResponse,
};
use rembrane_domain::{
    ContextPackId, DisclosedMemory, DisclosureId, DisclosureReceipt,
    MemoryRecord, MemoryScope, MemoryStatus, ReadGrant,
};

use crate::{ApplicationError, DisclosureRepository, MemoryRepository};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveContextCommand {
    pub request: ResolveContextRequest,
    pub grant: ReadGrant,
    pub context_pack_id: ContextPackId,
    pub disclosure_id: DisclosureId,
}

pub struct ResolveContextService<'repository, Repository> {
    repository: &'repository mut Repository,
}

impl<'repository, Repository> ResolveContextService<'repository, Repository>
where
    Repository: DisclosureRepository + MemoryRepository,
{
    pub fn new(repository: &'repository mut Repository) -> Self {
        Self { repository }
    }

    pub fn execute(
        &mut self,
        command: ResolveContextCommand,
    ) -> Result<ResolveContextResponse, ApplicationError> {
        validate(&command.request)?;
        authorize(&command)?;

        let mut items = self.repository.list_for_subject(
            &command.request.workspace_id,
            &command.request.principal_id,
        )?;

        items.retain(|memory| {
            memory.status() == MemoryStatus::Confirmed
                && scope_matches(memory, &command.request)
                && command.grant.allows(memory.scope())
        });
        items.sort_by_key(|memory| {
            std::cmp::Reverse(memory.scope().specificity())
        });
        items.truncate(command.request.maximum_items);

        let receipt = DisclosureReceipt {
            id: command.disclosure_id,
            context_pack_id: command.context_pack_id.clone(),
            workspace_id: command.request.workspace_id,
            subject_id: command.request.principal_id,
            client_id: command.grant.client_id,
            purpose: command.request.purpose,
            memories: items
                .iter()
                .map(|memory| DisclosedMemory {
                    id: memory.id().clone(),
                    version: memory.version(),
                })
                .collect(),
        };

        self.repository.append(receipt)?;

        Ok(ResolveContextResponse {
            items,
            context_pack_id: command.context_pack_id,
        })
    }
}

fn authorize(command: &ResolveContextCommand) -> Result<(), ApplicationError> {
    if command.grant.workspace_id != command.request.workspace_id
        || command.grant.subject_id != command.request.principal_id
    {
        return Err(ApplicationError::AccessDenied);
    }

    Ok(())
}

fn validate(request: &ResolveContextRequest) -> Result<(), ApplicationError> {
    if request.purpose.trim().is_empty() {
        return Err(ApplicationError::Validation(
            "purpose must not be empty".to_owned(),
        ));
    }

    if request.maximum_items == 0 {
        return Err(ApplicationError::Validation(
            "maximum_items must be greater than zero".to_owned(),
        ));
    }

    Ok(())
}

fn scope_matches(
    memory: &MemoryRecord,
    request: &ResolveContextRequest,
) -> bool {
    match memory.scope() {
        MemoryScope::Global => true,
        MemoryScope::Domain { name } => request.domain.as_ref() == Some(name),
        MemoryScope::Entity { id } => request.entity_id.as_ref() == Some(id),
        MemoryScope::Activity { id } => {
            request.activity_id.as_ref() == Some(id)
        }
    }
}

#[cfg(test)]
mod tests {
    use rembrane_contracts::ResolveContextRequest;
    use rembrane_domain::{
        ActivityId, ClientId, ContextPackId, DisclosureId, DisclosureReceipt,
        EntityId, EvidenceId, EvidenceReference, EvidenceSource, MemoryId,
        MemoryRecord, MemoryScope, PrincipalId, ReadGrant, ReadScope,
        WorkspaceId,
    };

    use super::{ResolveContextCommand, ResolveContextService};
    use crate::{
        ApplicationError, DisclosureRepository, MemoryRepository,
    };

    #[derive(Default)]
    struct TestRepository {
        memories: Vec<MemoryRecord>,
        disclosures: Vec<DisclosureReceipt>,
    }

    impl MemoryRepository for TestRepository {
        fn insert(
            &mut self,
            memory: MemoryRecord,
        ) -> Result<(), ApplicationError> {
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

            if stored.version() != expected_version {
                return Err(ApplicationError::VersionConflict);
            }

            *stored = memory;
            Ok(())
        }
    }

    impl DisclosureRepository for TestRepository {
        fn append(
            &mut self,
            receipt: DisclosureReceipt,
        ) -> Result<(), ApplicationError> {
            self.disclosures.push(receipt);
            Ok(())
        }
    }

    fn memory(id: &str, scope: MemoryScope) -> MemoryRecord {
        MemoryRecord::confirmed_preference(
            MemoryId::new(id),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            scope,
            id,
            EvidenceReference::new(
                EvidenceId::new(format!("evidence_{id}")),
                EvidenceSource::UserStatement,
            ),
        )
    }

    fn command(maximum_items: usize) -> ResolveContextCommand {
        ResolveContextCommand {
            request: ResolveContextRequest {
                workspace_id: WorkspaceId::new("workspace_01"),
                principal_id: PrincipalId::new("principal_01"),
                domain: Some("development".to_owned()),
                entity_id: Some(EntityId::new("project_01")),
                activity_id: Some(ActivityId::new("activity_01")),
                purpose: "continue_project".to_owned(),
                query: "What should I call the user?".to_owned(),
                maximum_items,
            },
            grant: ReadGrant {
                client_id: ClientId::new("client_01"),
                workspace_id: WorkspaceId::new("workspace_01"),
                subject_id: PrincipalId::new("principal_01"),
                scopes: vec![
                    ReadScope::Global,
                    ReadScope::Domain {
                        name: "development".to_owned(),
                    },
                    ReadScope::Entity {
                        id: EntityId::new("project_01"),
                    },
                    ReadScope::Activity {
                        id: ActivityId::new("activity_01"),
                    },
                ],
            },
            context_pack_id: ContextPackId::new("context_01"),
            disclosure_id: DisclosureId::new("disclosure_01"),
        }
    }

    #[test]
    fn returns_specific_memory_before_global_memory() {
        let mut repository = TestRepository {
            memories: vec![
                memory("global", MemoryScope::Global),
                memory(
                    "entity",
                    MemoryScope::Entity {
                        id: EntityId::new("project_01"),
                    },
                ),
            ],
            disclosures: Vec::new(),
        };

        let response = ResolveContextService::new(&mut repository)
            .execute(command(10))
            .expect("resolution should succeed");

        assert_eq!(response.items[0].id(), &MemoryId::new("entity"));
        assert_eq!(response.items[1].id(), &MemoryId::new("global"));
        assert_eq!(repository.disclosures.len(), 1);
        assert_eq!(repository.disclosures[0].memories.len(), 2);
    }

    #[test]
    fn excludes_unrelated_scopes_and_respects_limit() {
        let mut repository = TestRepository {
            memories: vec![
                memory("global", MemoryScope::Global),
                memory(
                    "other_entity",
                    MemoryScope::Entity {
                        id: EntityId::new("project_other"),
                    },
                ),
                memory(
                    "activity",
                    MemoryScope::Activity {
                        id: ActivityId::new("activity_01"),
                    },
                ),
            ],
            disclosures: Vec::new(),
        };

        let response = ResolveContextService::new(&mut repository)
            .execute(command(1))
            .expect("resolution should succeed");

        assert_eq!(response.items.len(), 1);
        assert_eq!(response.items[0].id(), &MemoryId::new("activity"));
        assert_eq!(repository.disclosures[0].memories.len(), 1);
    }

    #[test]
    fn rejects_empty_purpose_without_disclosure() {
        let mut repository = TestRepository::default();
        let mut invalid = command(5);
        invalid.request.purpose = " ".to_owned();

        let error = ResolveContextService::new(&mut repository)
            .execute(invalid)
            .expect_err("empty purpose should fail");

        assert_eq!(
            error,
            ApplicationError::Validation(
                "purpose must not be empty".to_owned()
            )
        );
        assert!(repository.disclosures.is_empty());
    }

    #[test]
    fn rejects_grant_for_another_workspace() {
        let mut repository = TestRepository::default();
        let mut unauthorized = command(5);
        unauthorized.grant.workspace_id = WorkspaceId::new("workspace_other");

        let error = ResolveContextService::new(&mut repository)
            .execute(unauthorized)
            .expect_err("cross-workspace grant should fail");

        assert_eq!(error, ApplicationError::AccessDenied);
        assert!(repository.disclosures.is_empty());
    }

    #[test]
    fn excludes_memory_outside_client_grant() {
        let mut repository = TestRepository {
            memories: vec![
                memory("global", MemoryScope::Global),
                memory(
                    "entity",
                    MemoryScope::Entity {
                        id: EntityId::new("project_01"),
                    },
                ),
            ],
            disclosures: Vec::new(),
        };
        let mut restricted = command(10);
        restricted.grant.scopes = vec![ReadScope::Global];

        let response = ResolveContextService::new(&mut repository)
            .execute(restricted)
            .expect("authorized global resolution should succeed");

        assert_eq!(response.items.len(), 1);
        assert_eq!(response.items[0].id(), &MemoryId::new("global"));
    }
}

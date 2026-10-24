use rembrane_contracts::{ResolveContextRequest, ResolveContextResponse};
use rembrane_domain::{
    ContextPackId, DisclosedMemory, DisclosureId, DisclosureReceipt, MemoryRecord, MemoryScope,
    MemoryStatus, ReadGrant,
};
use std::collections::BTreeSet;

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

        let mut items = self
            .repository
            .list_for_subject(&command.request.workspace_id, &command.request.principal_id)?;

        items.retain(|memory| {
            memory.status() == MemoryStatus::Confirmed
                && scope_matches(memory, &command.request)
                && command.grant.allows(memory.scope())
        });

        rank_by_relevance(&mut items, &command.request.query);
        apply_context_budget(
            &mut items,
            command.request.maximum_items,
            command.request.maximum_bytes,
        );

        let receipt = DisclosureReceipt {
            id: command.disclosure_id.clone(),
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
            disclosure_id: command.disclosure_id,
        })
    }
}

pub(crate) fn apply_context_budget(
    items: &mut Vec<MemoryRecord>,
    maximum_items: usize,
    maximum_bytes: usize,
) {
    let mut used_bytes = 0_usize;
    let mut selected = Vec::new();
    for memory in items.drain(..) {
        let Some(next_bytes) = used_bytes.checked_add(memory.content().len()) else {
            continue;
        };
        if next_bytes <= maximum_bytes {
            used_bytes = next_bytes;
            selected.push(memory);
            if selected.len() == maximum_items {
                break;
            }
        }
    }
    items.extend(selected);
}

fn rank_by_relevance(items: &mut Vec<MemoryRecord>, query: &str) {
    let query_tokens = tokens(query);
    let mut ranked = items
        .drain(..)
        .map(|memory| {
            let relevance = token_overlap(&query_tokens, memory.content());
            (memory, relevance)
        })
        .collect::<Vec<_>>();

    if ranked.iter().any(|(_, relevance)| *relevance > 0) {
        ranked.retain(|(_, relevance)| *relevance > 0);
    }

    ranked.sort_by(|(left, left_relevance), (right, right_relevance)| {
        right_relevance
            .cmp(left_relevance)
            .then_with(|| right.scope().specificity().cmp(&left.scope().specificity()))
            .then_with(|| left.id().as_str().cmp(right.id().as_str()))
    });

    items.extend(ranked.into_iter().map(|(memory, _)| memory));
}

fn token_overlap(query_tokens: &BTreeSet<String>, content: &str) -> usize {
    let content_tokens = tokens(content);
    query_tokens.intersection(&content_tokens).count()
}

fn tokens(value: &str) -> BTreeSet<String> {
    value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_lowercase)
        .collect()
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
    if request.maximum_bytes == 0 {
        return Err(ApplicationError::Validation(
            "maximum_bytes must be greater than zero".to_owned(),
        ));
    }

    Ok(())
}

fn scope_matches(memory: &MemoryRecord, request: &ResolveContextRequest) -> bool {
    match memory.scope() {
        MemoryScope::Global => true,
        MemoryScope::Domain { name } => request.domain.as_ref() == Some(name),
        MemoryScope::Entity { id } => request.entity_id.as_ref() == Some(id),
        MemoryScope::Activity { id } => request.activity_id.as_ref() == Some(id),
    }
}

#[cfg(test)]
mod tests {
    use rembrane_contracts::ResolveContextRequest;
    use rembrane_domain::{
        ActivityId, ClientId, ContextPackId, DisclosureId, DisclosureReceipt, EntityId, EvidenceId,
        EvidenceReference, EvidenceSource, MemoryId, MemoryRecord, MemoryScope, PrincipalId,
        ReadGrant, ReadScope, WorkspaceId,
    };

    use super::{ResolveContextCommand, ResolveContextService};
    use crate::{ApplicationError, DisclosureRepository, MemoryRepository};

    #[derive(Default)]
    struct TestRepository {
        memories: Vec<MemoryRecord>,
        disclosures: Vec<DisclosureReceipt>,
    }

    impl MemoryRepository for TestRepository {
        fn find(
            &self,
            workspace_id: &WorkspaceId,
            memory_id: &MemoryId,
        ) -> Result<Option<MemoryRecord>, ApplicationError> {
            Ok(self
                .memories
                .iter()
                .find(|memory| memory.workspace_id() == workspace_id && memory.id() == memory_id)
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
                    memory.workspace_id() == workspace_id && memory.subject_id() == subject_id
                })
                .cloned()
                .collect())
        }
    }

    impl DisclosureRepository for TestRepository {
        fn append(&mut self, receipt: DisclosureReceipt) -> Result<(), ApplicationError> {
            self.disclosures.push(receipt);
            Ok(())
        }
    }

    fn memory_with_content(id: &str, scope: MemoryScope, content: &str) -> MemoryRecord {
        MemoryRecord::confirmed_preference(
            MemoryId::new(id),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            scope,
            content,
            EvidenceReference::new(
                EvidenceId::new(format!("evidence_{id}")),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("test memory should be valid")
    }

    fn memory(id: &str, scope: MemoryScope) -> MemoryRecord {
        memory_with_content(id, scope, id)
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
                maximum_bytes: 65_536,
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
            ApplicationError::Validation("purpose must not be empty".to_owned())
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

    #[test]
    fn returns_only_query_relevant_memories_when_matches_exist() {
        let mut repository = TestRepository {
            memories: vec![
                memory_with_content(
                    "irrelevant",
                    MemoryScope::Global,
                    "The user prefers window seats.",
                ),
                memory_with_content(
                    "preferred_name",
                    MemoryScope::Global,
                    "Call the user Hippo.",
                ),
            ],
            disclosures: Vec::new(),
        };

        let response = ResolveContextService::new(&mut repository)
            .execute(command(10))
            .expect("resolution should succeed");

        assert_eq!(response.items.len(), 1);
        assert_eq!(response.items[0].id(), &MemoryId::new("preferred_name"));
        assert_eq!(
            repository.disclosures[0].memories,
            vec![DisclosedMemory {
                id: MemoryId::new("preferred_name"),
                version: 1,
            }]
        );
    }

    #[test]
    fn ranks_relevance_before_scope_specificity() {
        let mut repository = TestRepository {
            memories: vec![
                memory_with_content(
                    "activity_match",
                    MemoryScope::Activity {
                        id: ActivityId::new("activity_01"),
                    },
                    "Call Hippo.",
                ),
                memory_with_content(
                    "global_match",
                    MemoryScope::Global,
                    "Always call the user Hippo.",
                ),
            ],
            disclosures: Vec::new(),
        };

        let response = ResolveContextService::new(&mut repository)
            .execute(command(10))
            .expect("resolution should succeed");

        assert_eq!(response.items[0].id(), &MemoryId::new("global_match"));
        assert_eq!(response.items[1].id(), &MemoryId::new("activity_match"));
    }

    #[test]
    fn skips_memories_that_exceed_the_context_byte_budget() {
        let mut repository = TestRepository {
            memories: vec![
                memory_with_content(
                    "large",
                    MemoryScope::Global,
                    "Call the user a name that is much too long.",
                ),
                memory_with_content("small", MemoryScope::Global, "Call Hippo."),
            ],
            disclosures: Vec::new(),
        };
        let mut limited = command(10);
        limited.request.maximum_bytes = 11;

        let response = ResolveContextService::new(&mut repository)
            .execute(limited)
            .expect("resolution should succeed");

        assert_eq!(response.items.len(), 1);
        assert_eq!(response.items[0].id(), &MemoryId::new("small"));
        assert_eq!(repository.disclosures[0].memories.len(), 1);
    }
}

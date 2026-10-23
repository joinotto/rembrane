use rembrane_contracts::{ResolveContextRequest, ResolveContextResponse};
use rembrane_domain::{
    DisclosedMemory, DisclosureReceipt, MemoryScope, MemoryStatus,
};
use rembrane_provider_sdk::{SemanticMemoryProvider, SemanticQuery};

use crate::{
    ApplicationError, DisclosureRepository, MemoryRepository,
    ResolveContextCommand, resolve_context::apply_context_budget,
};

/// Resolves provider-ranked candidates only after canonical authorization.
pub struct SemanticContextService<'service, Repository, Provider> {
    repository: &'service mut Repository,
    provider: &'service Provider,
}

impl<'service, Repository, Provider>
    SemanticContextService<'service, Repository, Provider>
where
    Repository: DisclosureRepository + MemoryRepository,
    Provider: SemanticMemoryProvider,
{
    pub fn new(
        repository: &'service mut Repository,
        provider: &'service Provider,
    ) -> Self {
        Self {
            repository,
            provider,
        }
    }

    pub fn execute(
        &mut self,
        command: ResolveContextCommand,
    ) -> Result<ResolveContextResponse, ApplicationError> {
        if command.request.purpose.trim().is_empty()
            || command.request.query.trim().is_empty()
            || command.request.maximum_items == 0
            || command.request.maximum_bytes == 0
        {
            return Err(ApplicationError::Validation(
                "purpose, query, maximum_items, and maximum_bytes are required"
                    .to_owned(),
            ));
        }
        if command.grant.workspace_id != command.request.workspace_id
            || command.grant.subject_id != command.request.principal_id
        {
            return Err(ApplicationError::AccessDenied);
        }

        let candidate_limit = command.request.maximum_items.saturating_mul(4);
        let candidates = self
            .provider
            .search(&SemanticQuery {
                workspace_id: command.request.workspace_id.clone(),
                text: command.request.query.clone(),
                maximum_candidates: candidate_limit,
            })
            .map_err(|_| ApplicationError::StorageUnavailable)?;

        let mut items = Vec::new();
        for candidate in candidates {
            let Some(memory) = self.repository.find(
                &command.request.workspace_id,
                &candidate.memory_id,
            )? else {
                continue;
            };

            if memory.subject_id() != &command.request.principal_id
                || memory.version() != candidate.version
                || memory.status() != MemoryStatus::Confirmed
                || !command.grant.allows(memory.scope())
                || !requested_scope_matches(memory.scope(), &command.request)
            {
                continue;
            }

            items.push(memory);
        }
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

fn requested_scope_matches(
    scope: &MemoryScope,
    request: &ResolveContextRequest,
) -> bool {
    match scope {
        MemoryScope::Global => true,
        MemoryScope::Domain { name } => request.domain.as_ref() == Some(name),
        MemoryScope::Entity { id } => request.entity_id.as_ref() == Some(id),
        MemoryScope::Activity { id } => {
            request.activity_id.as_ref() == Some(id)
        }
    }
}

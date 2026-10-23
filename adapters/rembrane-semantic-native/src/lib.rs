//! Deterministic local retrieval baseline.
//!
//! This adapter is intentionally simple. It provides a dependency-free,
//! inspectable control for provider benchmarks and local prototypes; it is not
//! presented as state-of-the-art semantic retrieval.

use std::collections::BTreeSet;

use rembrane_domain::{MemoryId, WorkspaceId};
use rembrane_provider_sdk::{
    AuthorizedMemoryProjection, CandidateMemory, Capability, ProviderError,
    ProviderManifest, SemanticMemoryProvider, SemanticQuery,
};

#[derive(Debug, Default)]
pub struct NativeSemanticProvider {
    projections: Vec<AuthorizedMemoryProjection>,
}

impl NativeSemanticProvider {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl SemanticMemoryProvider for NativeSemanticProvider {
    fn manifest(&self) -> ProviderManifest {
        ProviderManifest {
            id: "rembrane.native".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            capabilities: vec![
                Capability::Index,
                Capability::Search,
                Capability::Delete,
                Capability::WorkspaceFilter,
                Capability::VersionedRecords,
                Capability::HealthCheck,
            ],
            plaintext_processing: true,
        }
    }

    fn index(
        &mut self,
        projection: AuthorizedMemoryProjection,
    ) -> Result<(), ProviderError> {
        if projection.content.trim().is_empty() {
            return Err(ProviderError::Rejected(
                "empty content cannot be indexed".to_owned(),
            ));
        }

        self.projections.retain(|stored| {
            stored.workspace_id != projection.workspace_id
                || stored.memory_id != projection.memory_id
        });
        self.projections.push(projection);
        Ok(())
    }

    fn search(
        &self,
        query: &SemanticQuery,
    ) -> Result<Vec<CandidateMemory>, ProviderError> {
        if query.maximum_candidates == 0 {
            return Err(ProviderError::Rejected(
                "maximum_candidates must be greater than zero".to_owned(),
            ));
        }

        let query_tokens = tokens(&query.text);
        if query_tokens.is_empty() {
            return Ok(Vec::new());
        }

        let mut candidates: Vec<_> = self
            .projections
            .iter()
            .filter(|projection| projection.workspace_id == query.workspace_id)
            .filter_map(|projection| {
                let content_tokens = tokens(&projection.content);
                let overlap = query_tokens
                    .intersection(&content_tokens)
                    .count();
                if overlap == 0 {
                    return None;
                }

                let score = overlap
                    .saturating_mul(1_000_000)
                    .checked_div(query_tokens.len())
                    .unwrap_or(0);
                Some(CandidateMemory {
                    memory_id: projection.memory_id.clone(),
                    version: projection.version,
                    score_millionths: u32::try_from(score).unwrap_or(1_000_000),
                })
            })
            .collect();

        candidates.sort_by(|left, right| {
            right
                .score_millionths
                .cmp(&left.score_millionths)
                .then_with(|| left.memory_id.cmp(&right.memory_id))
        });
        candidates.truncate(query.maximum_candidates);
        Ok(candidates)
    }

    fn delete(
        &mut self,
        workspace_id: &WorkspaceId,
        memory_id: &MemoryId,
        through_version: u64,
    ) -> Result<(), ProviderError> {
        self.projections.retain(|projection| {
            &projection.workspace_id != workspace_id
                || &projection.memory_id != memory_id
                || projection.version > through_version
        });
        Ok(())
    }
}

fn tokens(value: &str) -> BTreeSet<String> {
    value
        .split_whitespace()
        .map(|token| {
            token
                .trim_matches(|character: char| !character.is_alphanumeric())
                .to_lowercase()
        })
        .filter(|token| !token.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use rembrane_domain::{
        MemoryId, MemoryKind, MemoryScope, WorkspaceId,
    };
    use rembrane_provider_sdk::{
        AuthorizedMemoryProjection, SemanticMemoryProvider, SemanticQuery,
    };

    use super::NativeSemanticProvider;

    fn projection(
        workspace_id: &str,
        memory_id: &str,
        version: u64,
        content: &str,
    ) -> AuthorizedMemoryProjection {
        AuthorizedMemoryProjection {
            workspace_id: WorkspaceId::new(workspace_id),
            memory_id: MemoryId::new(memory_id),
            version,
            scope: MemoryScope::Global,
            kind: MemoryKind::Preference,
            content: content.to_owned(),
        }
    }

    #[test]
    fn search_never_crosses_workspace_boundary() {
        let mut provider = NativeSemanticProvider::new();
        provider
            .index(projection(
                "workspace_private",
                "memory_private",
                1,
                "Call me Hippo",
            ))
            .expect("index should succeed");

        let results = provider
            .search(&SemanticQuery {
                workspace_id: WorkspaceId::new("workspace_other"),
                text: "Hippo".to_owned(),
                maximum_candidates: 10,
            })
            .expect("search should succeed");

        assert!(results.is_empty());
    }

    #[test]
    fn newer projection_replaces_old_version() {
        let mut provider = NativeSemanticProvider::new();
        provider
            .index(projection(
                "workspace_01",
                "memory_01",
                1,
                "Call me Hippo",
            ))
            .expect("initial index should succeed");
        provider
            .index(projection(
                "workspace_01",
                "memory_01",
                2,
                "Call me Captain Hippo",
            ))
            .expect("reindex should succeed");

        let results = provider
            .search(&SemanticQuery {
                workspace_id: WorkspaceId::new("workspace_01"),
                text: "Captain".to_owned(),
                maximum_candidates: 10,
            })
            .expect("search should succeed");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].version, 2);
    }

    #[test]
    fn deletion_removes_matching_projection_versions() {
        let mut provider = NativeSemanticProvider::new();
        provider
            .index(projection(
                "workspace_01",
                "memory_01",
                2,
                "Call me Captain Hippo",
            ))
            .expect("index should succeed");
        provider
            .delete(
                &WorkspaceId::new("workspace_01"),
                &MemoryId::new("memory_01"),
                2,
            )
            .expect("delete should succeed");

        let results = provider
            .search(&SemanticQuery {
                workspace_id: WorkspaceId::new("workspace_01"),
                text: "Captain".to_owned(),
                maximum_candidates: 10,
            })
            .expect("search should succeed");

        assert!(results.is_empty());
    }
}

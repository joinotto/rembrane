use std::fmt;

use rembrane_domain::{MemoryId, MemoryKind, MemoryScope, WorkspaceId};

use crate::{ProviderError, ProviderManifest};

/// The minimum canonical data disclosed to an indexing provider.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedMemoryProjection {
    pub workspace_id: WorkspaceId,
    pub memory_id: MemoryId,
    pub version: u64,
    pub scope: MemoryScope,
    pub kind: MemoryKind,
    pub content: String,
}

impl fmt::Debug for AuthorizedMemoryProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedMemoryProjection")
            .field("workspace_id", &"<redacted>")
            .field("memory_id", &"<redacted>")
            .field("version", &self.version)
            .field("scope_specificity", &self.scope.specificity())
            .field("kind", &self.kind)
            .field("content_bytes", &self.content.len())
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SemanticQuery {
    pub workspace_id: WorkspaceId,
    pub text: String,
    pub maximum_candidates: usize,
}

impl fmt::Debug for SemanticQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemanticQuery")
            .field("workspace_id", &"<redacted>")
            .field("text_bytes", &self.text.len())
            .field("maximum_candidates", &self.maximum_candidates)
            .finish()
    }
}

/// An untrusted approximate-search result.
///
/// The score is intentionally represented as integer millionths to keep core
/// ordering deterministic across providers.
#[derive(Clone, Eq, PartialEq)]
pub struct CandidateMemory {
    pub memory_id: MemoryId,
    pub version: u64,
    pub score_millionths: u32,
}

impl fmt::Debug for CandidateMemory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidateMemory")
            .field("memory_id", &"<redacted>")
            .field("version", &self.version)
            .field("score_millionths", &self.score_millionths)
            .finish()
    }
}

pub trait SemanticMemoryProvider {
    fn manifest(&self) -> ProviderManifest;

    fn index(&mut self, projection: AuthorizedMemoryProjection) -> Result<(), ProviderError>;

    fn search(&self, query: &SemanticQuery) -> Result<Vec<CandidateMemory>, ProviderError>;

    fn delete(
        &mut self,
        workspace_id: &WorkspaceId,
        memory_id: &MemoryId,
        through_version: u64,
    ) -> Result<(), ProviderError>;
}

#[cfg(test)]
mod tests {
    use super::{AuthorizedMemoryProjection, CandidateMemory, SemanticQuery};
    use rembrane_domain::{MemoryId, MemoryKind, MemoryScope, WorkspaceId};

    #[test]
    fn semantic_diagnostics_redact_memory_content_queries_and_identities() {
        let projection = AuthorizedMemoryProjection {
            workspace_id: WorkspaceId::new("private_workspace"),
            memory_id: MemoryId::new("private_memory"),
            version: 7,
            scope: MemoryScope::Domain {
                name: "private_domain".to_owned(),
            },
            kind: MemoryKind::Semantic,
            content: "private semantic memory".to_owned(),
        };
        let query = SemanticQuery {
            workspace_id: WorkspaceId::new("private_workspace"),
            text: "private retrieval query".to_owned(),
            maximum_candidates: 12,
        };
        let candidate = CandidateMemory {
            memory_id: MemoryId::new("private_candidate"),
            version: 6,
            score_millionths: 875_000,
        };

        let diagnostic = format!("{projection:?} {query:?} {candidate:?}");

        for private_value in [
            "private_workspace",
            "private_memory",
            "private_domain",
            "private semantic memory",
            "private retrieval query",
            "private_candidate",
        ] {
            assert!(!diagnostic.contains(private_value));
        }
        assert!(diagnostic.contains("version: 7"));
        assert!(diagnostic.contains("scope_specificity: 1"));
        assert!(diagnostic.contains("content_bytes: 23"));
        assert!(diagnostic.contains("text_bytes: 23"));
        assert!(diagnostic.contains("maximum_candidates: 12"));
        assert!(diagnostic.contains("score_millionths: 875000"));
    }
}

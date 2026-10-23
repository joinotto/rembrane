use rembrane_domain::{MemoryId, MemoryKind, MemoryScope, WorkspaceId};

use crate::{ProviderError, ProviderManifest};

/// The minimum canonical data disclosed to an indexing provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedMemoryProjection {
    pub workspace_id: WorkspaceId,
    pub memory_id: MemoryId,
    pub version: u64,
    pub scope: MemoryScope,
    pub kind: MemoryKind,
    pub content: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticQuery {
    pub workspace_id: WorkspaceId,
    pub text: String,
    pub maximum_candidates: usize,
}

/// An untrusted approximate-search result.
///
/// The score is intentionally represented as integer millionths to keep core
/// ordering deterministic across providers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateMemory {
    pub memory_id: MemoryId,
    pub version: u64,
    pub score_millionths: u32,
}

pub trait SemanticMemoryProvider {
    fn manifest(&self) -> ProviderManifest;

    fn index(
        &mut self,
        projection: AuthorizedMemoryProjection,
    ) -> Result<(), ProviderError>;

    fn search(
        &self,
        query: &SemanticQuery,
    ) -> Result<Vec<CandidateMemory>, ProviderError>;

    fn delete(
        &mut self,
        workspace_id: &WorkspaceId,
        memory_id: &MemoryId,
        through_version: u64,
    ) -> Result<(), ProviderError>;
}

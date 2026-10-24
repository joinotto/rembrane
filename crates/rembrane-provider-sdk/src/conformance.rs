use std::error::Error;
use std::fmt::{self, Display};

use rembrane_domain::{MemoryId, MemoryKind, MemoryScope, WorkspaceId};

use crate::{
    AuthorizedMemoryProjection, CURRENT_PROVIDER_PROTOCOL, Capability, ProviderError,
    ProviderPolicy, SemanticMemoryProvider, SemanticQuery,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConformanceFailure {
    Behavior(String),
    InvalidFixture,
    Provider(ProviderError),
}

impl Display for ConformanceFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Behavior(message) => write!(formatter, "provider behavior failed: {message}"),
            Self::InvalidFixture => formatter.write_str("conformance fixture namespace is invalid"),
            Self::Provider(error) => write!(formatter, "provider conformance call failed: {error}"),
        }
    }
}

impl Error for ConformanceFailure {}

impl From<ProviderError> for ConformanceFailure {
    fn from(error: ProviderError) -> Self {
        Self::Provider(error)
    }
}

/// Exercises the mandatory synchronous semantic-provider contract.
///
/// The caller must supply a unique namespace and a disposable provider
/// instance or test tenant. The harness writes and deletes one fixture.
pub fn verify_semantic_provider(
    provider: &mut impl SemanticMemoryProvider,
    fixture_namespace: &str,
) -> Result<(), ConformanceFailure> {
    let namespace = fixture_namespace.trim();
    if namespace.is_empty() || namespace.len() > 100 {
        return Err(ConformanceFailure::InvalidFixture);
    }

    let manifest = provider.manifest();
    ProviderPolicy {
        minimum_protocol_version: CURRENT_PROVIDER_PROTOCOL,
        required_capabilities: vec![
            Capability::Index,
            Capability::Search,
            Capability::Delete,
            Capability::WorkspaceFilter,
            Capability::VersionedRecords,
        ],
        allow_plaintext_processing: true,
    }
    .validate(&manifest)?;

    let workspace = WorkspaceId::new(format!("conformance.workspace.{namespace}"));
    let other_workspace = WorkspaceId::new(format!("conformance.other.{namespace}"));
    let memory_id = MemoryId::new(format!("conformance.memory.{namespace}"));
    let token = format!("rembrane_conformance_{namespace}");
    if token.len() > manifest.limits.maximum_content_bytes {
        return Err(ConformanceFailure::InvalidFixture);
    }
    let candidate_limit = manifest.bounded_candidate_limit(10)?;

    provider.index(AuthorizedMemoryProjection {
        workspace_id: workspace.clone(),
        memory_id: memory_id.clone(),
        version: 1,
        scope: MemoryScope::Global,
        kind: MemoryKind::Semantic,
        content: token.clone(),
    })?;

    let visible = provider.search(&SemanticQuery {
        workspace_id: workspace.clone(),
        text: token.clone(),
        maximum_candidates: candidate_limit,
    })?;
    manifest.validate_candidates(&visible, candidate_limit)?;
    if !visible
        .iter()
        .any(|candidate| candidate.memory_id == memory_id && candidate.version == 1)
    {
        return Err(ConformanceFailure::Behavior(
            "indexed version was not returned in its workspace".to_owned(),
        ));
    }

    let leaked = provider.search(&SemanticQuery {
        workspace_id: other_workspace,
        text: token.clone(),
        maximum_candidates: candidate_limit,
    })?;
    manifest.validate_candidates(&leaked, candidate_limit)?;
    if leaked
        .iter()
        .any(|candidate| candidate.memory_id == memory_id)
    {
        return Err(ConformanceFailure::Behavior(
            "fixture crossed a workspace boundary".to_owned(),
        ));
    }

    provider.delete(&workspace, &memory_id, 1)?;
    let deleted = provider.search(&SemanticQuery {
        workspace_id: workspace,
        text: token,
        maximum_candidates: candidate_limit,
    })?;
    manifest.validate_candidates(&deleted, candidate_limit)?;
    if deleted
        .iter()
        .any(|candidate| candidate.memory_id == memory_id && candidate.version <= 1)
    {
        return Err(ConformanceFailure::Behavior(
            "deleted fixture remained searchable".to_owned(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ConformanceFailure, verify_semantic_provider};
    use crate::{
        AuthorizedMemoryProjection, CURRENT_PROVIDER_PROTOCOL, CandidateMemory, Capability,
        ProviderError, ProviderLimits, ProviderManifest, SemanticMemoryProvider, SemanticQuery,
    };
    use rembrane_domain::{MemoryId, WorkspaceId};

    #[derive(Default)]
    struct LeakyProvider {
        projection: Option<AuthorizedMemoryProjection>,
    }

    impl SemanticMemoryProvider for LeakyProvider {
        fn manifest(&self) -> ProviderManifest {
            ProviderManifest {
                id: "leaky".to_owned(),
                version: "test".to_owned(),
                protocol_version: CURRENT_PROVIDER_PROTOCOL,
                capabilities: vec![
                    Capability::Index,
                    Capability::Search,
                    Capability::Delete,
                    Capability::WorkspaceFilter,
                    Capability::VersionedRecords,
                ],
                plaintext_processing: false,
                limits: ProviderLimits {
                    maximum_batch_items: 1,
                    maximum_content_bytes: 1_024,
                    maximum_candidates: 10,
                },
            }
        }

        fn index(&mut self, projection: AuthorizedMemoryProjection) -> Result<(), ProviderError> {
            self.projection = Some(projection);
            Ok(())
        }

        fn search(&self, _query: &SemanticQuery) -> Result<Vec<CandidateMemory>, ProviderError> {
            Ok(self
                .projection
                .as_ref()
                .map(|projection| CandidateMemory {
                    memory_id: projection.memory_id.clone(),
                    version: projection.version,
                    score_millionths: 1_000_000,
                })
                .into_iter()
                .collect())
        }

        fn delete(
            &mut self,
            _workspace_id: &WorkspaceId,
            _memory_id: &MemoryId,
            _through_version: u64,
        ) -> Result<(), ProviderError> {
            self.projection = None;
            Ok(())
        }
    }

    #[test]
    fn detects_cross_workspace_provider_leak() {
        assert_eq!(
            verify_semantic_provider(&mut LeakyProvider::default(), "leak-test"),
            Err(ConformanceFailure::Behavior(
                "fixture crossed a workspace boundary".to_owned()
            ))
        );
    }
}

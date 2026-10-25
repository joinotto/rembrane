use std::error::Error;
use std::fmt::{self, Display};

use rembrane_domain::{MemoryId, MemoryKind, MemoryScope, WorkspaceId};

use crate::{
    AuthorizedMemoryProjection, CURRENT_PROVIDER_PROTOCOL, Capability, ProviderError,
    ProviderPolicy, ProviderProtocolVersion, SemanticMemoryProvider, SemanticQuery,
};

pub const SEMANTIC_PROVIDER_CONFORMANCE_SUITE_ID: &str = "rembrane.semantic-provider.core";
pub const SEMANTIC_PROVIDER_CONFORMANCE_SUITE_VERSION: &str = "0.1";
pub const SEMANTIC_PROVIDER_CONFORMANCE_CASES: [&str; 6] = [
    "manifest.compatible",
    "index.visible",
    "workspace.isolated",
    "replacement.exact",
    "stale-delete.preserves-current",
    "exact-delete.propagates",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticProviderConformanceReport {
    provider_id: String,
    provider_version: String,
    protocol_version: ProviderProtocolVersion,
    namespace: String,
}

impl SemanticProviderConformanceReport {
    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    #[must_use]
    pub fn provider_version(&self) -> &str {
        &self.provider_version
    }

    #[must_use]
    pub const fn protocol_version(&self) -> ProviderProtocolVersion {
        self.protocol_version
    }

    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    #[must_use]
    pub const fn case_ids(&self) -> &'static [&'static str] {
        &SEMANTIC_PROVIDER_CONFORMANCE_CASES
    }
}

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

fn search_validated(
    provider: &impl SemanticMemoryProvider,
    manifest: &crate::ProviderManifest,
    workspace_id: WorkspaceId,
    text: String,
    maximum_candidates: usize,
) -> Result<Vec<crate::CandidateMemory>, ConformanceFailure> {
    let candidates = provider.search(&SemanticQuery {
        workspace_id,
        text,
        maximum_candidates,
    })?;
    manifest.validate_candidates(&candidates, maximum_candidates)?;
    Ok(candidates)
}

fn verify_workspace_isolation(
    provider: &impl SemanticMemoryProvider,
    manifest: &crate::ProviderManifest,
    workspace: &WorkspaceId,
    other_workspace: WorkspaceId,
    memory_id: &MemoryId,
    token: &str,
    candidate_limit: usize,
) -> Result<(), ConformanceFailure> {
    let visible = search_validated(
        provider,
        manifest,
        workspace.clone(),
        token.to_owned(),
        candidate_limit,
    )?;
    if !visible
        .iter()
        .any(|candidate| &candidate.memory_id == memory_id && candidate.version == 1)
    {
        return Err(ConformanceFailure::Behavior(
            "indexed version was not returned in its workspace".to_owned(),
        ));
    }

    let leaked = search_validated(
        provider,
        manifest,
        other_workspace,
        token.to_owned(),
        candidate_limit,
    )?;
    if leaked
        .iter()
        .any(|candidate| &candidate.memory_id == memory_id)
    {
        return Err(ConformanceFailure::Behavior(
            "fixture crossed a workspace boundary".to_owned(),
        ));
    }
    Ok(())
}

fn verify_version_lifecycle(
    provider: &mut impl SemanticMemoryProvider,
    manifest: &crate::ProviderManifest,
    workspace: &WorkspaceId,
    memory_id: &MemoryId,
    first_token: String,
    second_token: String,
    candidate_limit: usize,
) -> Result<(), ConformanceFailure> {
    provider.index(AuthorizedMemoryProjection {
        workspace_id: workspace.clone(),
        memory_id: memory_id.clone(),
        version: 2,
        scope: MemoryScope::Global,
        kind: MemoryKind::Semantic,
        content: second_token.clone(),
    })?;

    let revised = search_validated(
        provider,
        manifest,
        workspace.clone(),
        second_token.clone(),
        candidate_limit,
    )?;
    if !revised
        .iter()
        .any(|candidate| &candidate.memory_id == memory_id && candidate.version == 2)
        || revised
            .iter()
            .any(|candidate| &candidate.memory_id == memory_id && candidate.version != 2)
    {
        return Err(ConformanceFailure::Behavior(
            "replacement version was not returned exactly".to_owned(),
        ));
    }

    let stale = search_validated(
        provider,
        manifest,
        workspace.clone(),
        first_token,
        candidate_limit,
    )?;
    if stale
        .iter()
        .any(|candidate| &candidate.memory_id == memory_id)
    {
        return Err(ConformanceFailure::Behavior(
            "superseded fixture remained searchable".to_owned(),
        ));
    }

    provider.delete(workspace, memory_id, 1)?;
    let preserved = search_validated(
        provider,
        manifest,
        workspace.clone(),
        second_token.clone(),
        candidate_limit,
    )?;
    if !preserved
        .iter()
        .any(|candidate| &candidate.memory_id == memory_id && candidate.version == 2)
    {
        return Err(ConformanceFailure::Behavior(
            "deletion through an older version removed the current version".to_owned(),
        ));
    }

    provider.delete(workspace, memory_id, 2)?;
    let deleted = search_validated(
        provider,
        manifest,
        workspace.clone(),
        second_token,
        candidate_limit,
    )?;
    if deleted
        .iter()
        .any(|candidate| &candidate.memory_id == memory_id && candidate.version <= 2)
    {
        return Err(ConformanceFailure::Behavior(
            "deleted fixture remained searchable".to_owned(),
        ));
    }
    Ok(())
}

/// Exercises the mandatory synchronous semantic-provider contract.
///
/// The caller must supply a unique namespace and a disposable provider
/// instance or test tenant. The harness writes two versions of one fixture
/// and deletes it.
pub fn verify_semantic_provider(
    provider: &mut impl SemanticMemoryProvider,
    fixture_namespace: &str,
) -> Result<SemanticProviderConformanceReport, ConformanceFailure> {
    let namespace = fixture_namespace.trim();
    if namespace.is_empty()
        || namespace.len() > 100
        || namespace
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'_' | b'-'))
    {
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
    let first_token = format!("rembrane_conformance_{namespace}_v1");
    let second_token = format!("rembrane_conformance_{namespace}_v2");
    if first_token.len() > manifest.limits.maximum_content_bytes
        || second_token.len() > manifest.limits.maximum_content_bytes
    {
        return Err(ConformanceFailure::InvalidFixture);
    }
    let candidate_limit = manifest.bounded_candidate_limit(10)?;

    provider.index(AuthorizedMemoryProjection {
        workspace_id: workspace.clone(),
        memory_id: memory_id.clone(),
        version: 1,
        scope: MemoryScope::Global,
        kind: MemoryKind::Semantic,
        content: first_token.clone(),
    })?;

    verify_workspace_isolation(
        provider,
        &manifest,
        &workspace,
        other_workspace,
        &memory_id,
        &first_token,
        candidate_limit,
    )?;
    verify_version_lifecycle(
        provider,
        &manifest,
        &workspace,
        &memory_id,
        first_token,
        second_token,
        candidate_limit,
    )?;
    Ok(SemanticProviderConformanceReport {
        provider_id: manifest.id,
        provider_version: manifest.version,
        protocol_version: manifest.protocol_version,
        namespace: namespace.to_owned(),
    })
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

    #[derive(Default)]
    struct OverDeletingProvider {
        projection: Option<AuthorizedMemoryProjection>,
    }

    impl SemanticMemoryProvider for OverDeletingProvider {
        fn manifest(&self) -> ProviderManifest {
            LeakyProvider::default().manifest()
        }

        fn index(&mut self, projection: AuthorizedMemoryProjection) -> Result<(), ProviderError> {
            self.projection = Some(projection);
            Ok(())
        }

        fn search(&self, query: &SemanticQuery) -> Result<Vec<CandidateMemory>, ProviderError> {
            Ok(self
                .projection
                .as_ref()
                .filter(|projection| {
                    projection.workspace_id == query.workspace_id
                        && projection.content == query.text
                })
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
            workspace_id: &WorkspaceId,
            memory_id: &MemoryId,
            _through_version: u64,
        ) -> Result<(), ProviderError> {
            if self.projection.as_ref().is_some_and(|projection| {
                &projection.workspace_id == workspace_id && &projection.memory_id == memory_id
            }) {
                self.projection = None;
            }
            Ok(())
        }
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

    #[test]
    fn detects_provider_that_ignores_delete_version_bound() {
        assert_eq!(
            verify_semantic_provider(&mut OverDeletingProvider::default(), "delete-bound-test"),
            Err(ConformanceFailure::Behavior(
                "deletion through an older version removed the current version".to_owned()
            ))
        );
    }

    #[test]
    fn rejects_unsafe_fixture_namespaces_before_provider_access() {
        for namespace in ["contains whitespace", "contains/slash", "contains\ncontrol"] {
            assert_eq!(
                verify_semantic_provider(&mut LeakyProvider::default(), namespace),
                Err(ConformanceFailure::InvalidFixture)
            );
        }
    }
}

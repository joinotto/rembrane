//! Canonical-to-Supermemory semantic projection mapping.

use std::collections::BTreeMap;

use rembrane_domain::{MemoryId, WorkspaceId};
use rembrane_provider_sdk::{
    AuthorizedMemoryProjection, CURRENT_PROVIDER_PROTOCOL, CandidateMemory, Capability,
    ProviderError, ProviderLimits, ProviderManifest, SemanticMemoryProvider, SemanticQuery,
};
use ring::hmac;
use zeroize::Zeroize;

const MAXIMUM_CONTENT_BYTES: usize = 262_144;
const MAXIMUM_CANDIDATES: usize = 1_000;
const MAXIMUM_PROVIDER_ID_BYTES: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupermemoryRecord {
    provider_id: String,
    canonical_memory_id: MemoryId,
    canonical_version: u64,
    score_millionths: Option<u32>,
}

impl SupermemoryRecord {
    pub fn new(
        provider_id: impl Into<String>,
        canonical_memory_id: MemoryId,
        canonical_version: u64,
        score_millionths: Option<u32>,
    ) -> Result<Self, ProviderError> {
        let provider_id = provider_id.into();
        if provider_id.is_empty()
            || provider_id.len() > MAXIMUM_PROVIDER_ID_BYTES
            || provider_id.chars().any(char::is_control)
            || canonical_version == 0
            || score_millionths.is_some_and(|score| score > 1_000_000)
        {
            return Err(ProviderError::Rejected(
                "Supermemory returned invalid projection metadata".to_owned(),
            ));
        }
        Ok(Self {
            provider_id,
            canonical_memory_id,
            canonical_version,
            score_millionths,
        })
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }
}

pub trait SupermemoryTransport {
    fn list(&self, namespace: &str) -> Result<Vec<SupermemoryRecord>, ProviderError>;
    fn upsert_exact(
        &mut self,
        namespace: &str,
        projection: &AuthorizedMemoryProjection,
    ) -> Result<(), ProviderError>;
    fn search(
        &self,
        namespace: &str,
        query: &str,
        maximum_candidates: usize,
    ) -> Result<Vec<SupermemoryRecord>, ProviderError>;
    fn delete(&mut self, namespace: &str, provider_id: &str) -> Result<(), ProviderError>;
}

pub struct SupermemorySemanticProvider<Transport> {
    transport: Transport,
    workspace_lookup_key: hmac::Key,
}

impl<Transport> SupermemorySemanticProvider<Transport> {
    pub fn new(
        transport: Transport,
        mut workspace_lookup_secret: Vec<u8>,
    ) -> Result<Self, ProviderError> {
        if workspace_lookup_secret.len() < 32 {
            workspace_lookup_secret.zeroize();
            return Err(ProviderError::InvalidConfiguration(
                "Supermemory workspace lookup secret must contain at least 32 bytes".to_owned(),
            ));
        }
        let workspace_lookup_key = hmac::Key::new(hmac::HMAC_SHA256, &workspace_lookup_secret);
        workspace_lookup_secret.zeroize();
        Ok(Self {
            transport,
            workspace_lookup_key,
        })
    }

    fn namespace(&self, workspace_id: &WorkspaceId) -> String {
        let signature = hmac::sign(&self.workspace_lookup_key, workspace_id.as_str().as_bytes());
        let mut namespace = String::from("rembrane-");
        for byte in signature.as_ref() {
            use std::fmt::Write;
            let _ = write!(namespace, "{byte:02x}");
        }
        namespace
    }
}

impl<Transport: SupermemoryTransport> SemanticMemoryProvider
    for SupermemorySemanticProvider<Transport>
{
    fn manifest(&self) -> ProviderManifest {
        ProviderManifest {
            id: "supermemory.v5".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            protocol_version: CURRENT_PROVIDER_PROTOCOL,
            capabilities: vec![
                Capability::Index,
                Capability::Search,
                Capability::Delete,
                Capability::WorkspaceFilter,
                Capability::VersionedRecords,
                Capability::HealthCheck,
            ],
            plaintext_processing: true,
            limits: ProviderLimits {
                maximum_batch_items: 1,
                maximum_content_bytes: MAXIMUM_CONTENT_BYTES,
                maximum_candidates: MAXIMUM_CANDIDATES,
            },
        }
    }

    fn index(&mut self, projection: AuthorizedMemoryProjection) -> Result<(), ProviderError> {
        if projection.version == 0
            || projection.content.trim().is_empty()
            || projection.content.len() > MAXIMUM_CONTENT_BYTES
        {
            return Err(ProviderError::Rejected(
                "projection is outside Supermemory adapter limits".to_owned(),
            ));
        }
        let namespace = self.namespace(&projection.workspace_id);
        for record in self.transport.list(&namespace)? {
            if record.canonical_memory_id == projection.memory_id {
                self.transport.delete(&namespace, record.provider_id())?;
            }
        }
        self.transport.upsert_exact(&namespace, &projection)
    }

    fn search(&self, query: &SemanticQuery) -> Result<Vec<CandidateMemory>, ProviderError> {
        if query.text.trim().is_empty()
            || query.maximum_candidates == 0
            || query.maximum_candidates > MAXIMUM_CANDIDATES
        {
            return Err(ProviderError::Rejected(
                "query is outside Supermemory adapter limits".to_owned(),
            ));
        }
        let namespace = self.namespace(&query.workspace_id);
        let mut newest = BTreeMap::<MemoryId, CandidateMemory>::new();
        for record in self
            .transport
            .search(&namespace, &query.text, query.maximum_candidates)?
        {
            let candidate = CandidateMemory {
                memory_id: record.canonical_memory_id,
                version: record.canonical_version,
                score_millionths: record.score_millionths.unwrap_or_default(),
            };
            if newest
                .get(&candidate.memory_id)
                .is_none_or(|current| current.version < candidate.version)
            {
                newest.insert(candidate.memory_id.clone(), candidate);
            }
        }
        let mut candidates = newest.into_values().collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            right
                .score_millionths
                .cmp(&left.score_millionths)
                .then_with(|| right.version.cmp(&left.version))
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
        let namespace = self.namespace(workspace_id);
        for record in self.transport.list(&namespace)? {
            if &record.canonical_memory_id == memory_id
                && record.canonical_version <= through_version
            {
                self.transport.delete(&namespace, record.provider_id())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rembrane_provider_sdk::{
        AuthorizedMemoryProjection, ProviderError, verify_semantic_provider,
    };

    use super::{SupermemoryRecord, SupermemorySemanticProvider, SupermemoryTransport};

    #[derive(Default)]
    struct FakeSupermemory {
        records: BTreeMap<String, Vec<(SupermemoryRecord, String)>>,
        next_id: u64,
    }

    impl SupermemoryTransport for FakeSupermemory {
        fn list(&self, namespace: &str) -> Result<Vec<SupermemoryRecord>, ProviderError> {
            Ok(self
                .records
                .get(namespace)
                .into_iter()
                .flatten()
                .map(|(r, _)| r.clone())
                .collect())
        }

        fn upsert_exact(
            &mut self,
            namespace: &str,
            projection: &AuthorizedMemoryProjection,
        ) -> Result<(), ProviderError> {
            self.next_id += 1;
            let record = SupermemoryRecord::new(
                format!("supermemory-{}", self.next_id),
                projection.memory_id.clone(),
                projection.version,
                Some(1_000_000),
            )?;
            self.records
                .entry(namespace.to_owned())
                .or_default()
                .push((record, projection.content.clone()));
            Ok(())
        }

        fn search(
            &self,
            namespace: &str,
            query: &str,
            _maximum_candidates: usize,
        ) -> Result<Vec<SupermemoryRecord>, ProviderError> {
            Ok(self
                .records
                .get(namespace)
                .into_iter()
                .flatten()
                .filter(|(_, content)| content.contains(query))
                .map(|(record, _)| record.clone())
                .collect())
        }

        fn delete(&mut self, namespace: &str, provider_id: &str) -> Result<(), ProviderError> {
            if let Some(records) = self.records.get_mut(namespace) {
                records.retain(|(record, _)| record.provider_id() != provider_id);
            }
            Ok(())
        }
    }

    #[test]
    fn passes_shared_conformance_with_pseudonymous_namespaces() {
        let mut provider =
            SupermemorySemanticProvider::new(FakeSupermemory::default(), vec![7; 32])
                .expect("valid lookup secret");
        verify_semantic_provider(&mut provider, "supermemory-mapping")
            .expect("mapping should preserve canonical semantics");
    }
}

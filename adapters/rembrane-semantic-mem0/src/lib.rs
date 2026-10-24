//! Canonical-to-Mem0 semantic projection mapping.
//!
//! Mem0 remains derived, replaceable state. This adapter never delegates
//! Rembrane authorization or canonical identity to Mem0.

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
pub struct Mem0Record {
    provider_id: String,
    canonical_memory_id: MemoryId,
    canonical_version: u64,
    score_millionths: Option<u32>,
}

impl Mem0Record {
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
                "Mem0 returned invalid projection metadata".to_owned(),
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

pub trait Mem0Transport {
    fn list(&self, user_id: &str) -> Result<Vec<Mem0Record>, ProviderError>;

    fn add_exact(
        &mut self,
        user_id: &str,
        projection: &AuthorizedMemoryProjection,
    ) -> Result<(), ProviderError>;

    fn search(
        &self,
        user_id: &str,
        query: &str,
        maximum_candidates: usize,
    ) -> Result<Vec<Mem0Record>, ProviderError>;

    fn delete(&mut self, provider_id: &str) -> Result<(), ProviderError>;
}

pub struct Mem0SemanticProvider<Transport> {
    transport: Transport,
    workspace_lookup_key: hmac::Key,
}

impl<Transport> Mem0SemanticProvider<Transport> {
    pub fn new(
        transport: Transport,
        mut workspace_lookup_secret: Vec<u8>,
    ) -> Result<Self, ProviderError> {
        if workspace_lookup_secret.len() < 32 {
            workspace_lookup_secret.zeroize();
            return Err(ProviderError::InvalidConfiguration(
                "Mem0 workspace lookup secret must contain at least 32 bytes".to_owned(),
            ));
        }
        let workspace_lookup_key = hmac::Key::new(hmac::HMAC_SHA256, &workspace_lookup_secret);
        workspace_lookup_secret.zeroize();
        Ok(Self {
            transport,
            workspace_lookup_key,
        })
    }

    fn user_id(&self, workspace_id: &WorkspaceId) -> String {
        let signature = hmac::sign(&self.workspace_lookup_key, workspace_id.as_str().as_bytes());
        let mut encoded = String::with_capacity(16 + 64);
        encoded.push_str("rembrane_ws_");
        for byte in signature.as_ref() {
            use std::fmt::Write;
            let _ = write!(encoded, "{byte:02x}");
        }
        encoded
    }
}

impl<Transport> SemanticMemoryProvider for Mem0SemanticProvider<Transport>
where
    Transport: Mem0Transport,
{
    fn manifest(&self) -> ProviderManifest {
        ProviderManifest {
            id: "mem0.oss".to_owned(),
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
                "projection is outside Mem0 adapter limits".to_owned(),
            ));
        }
        let user_id = self.user_id(&projection.workspace_id);
        let existing = self.transport.list(&user_id)?;
        for record in existing {
            if record.canonical_memory_id == projection.memory_id {
                self.transport.delete(record.provider_id())?;
            }
        }
        self.transport.add_exact(&user_id, &projection)
    }

    fn search(&self, query: &SemanticQuery) -> Result<Vec<CandidateMemory>, ProviderError> {
        if query.text.trim().is_empty()
            || query.maximum_candidates == 0
            || query.maximum_candidates > MAXIMUM_CANDIDATES
        {
            return Err(ProviderError::Rejected(
                "query is outside Mem0 adapter limits".to_owned(),
            ));
        }
        let user_id = self.user_id(&query.workspace_id);
        let mut newest = BTreeMap::<MemoryId, CandidateMemory>::new();
        for record in self
            .transport
            .search(&user_id, &query.text, query.maximum_candidates)?
        {
            let candidate = CandidateMemory {
                memory_id: record.canonical_memory_id,
                version: record.canonical_version,
                score_millionths: record.score_millionths.unwrap_or_default(),
            };
            match newest.get(&candidate.memory_id) {
                Some(current) if current.version >= candidate.version => {}
                _ => {
                    newest.insert(candidate.memory_id.clone(), candidate);
                }
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
        let user_id = self.user_id(workspace_id);
        for record in self.transport.list(&user_id)? {
            if &record.canonical_memory_id == memory_id
                && record.canonical_version <= through_version
            {
                self.transport.delete(record.provider_id())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rembrane_domain::{MemoryId, MemoryKind, MemoryScope, WorkspaceId};
    use rembrane_provider_sdk::{
        AuthorizedMemoryProjection, ProviderError, SemanticMemoryProvider, SemanticQuery,
        verify_semantic_provider,
    };

    use super::{Mem0Record, Mem0SemanticProvider, Mem0Transport};

    #[derive(Default)]
    struct FakeMem0 {
        records: BTreeMap<String, Vec<(Mem0Record, String)>>,
        next_id: u64,
    }

    impl Mem0Transport for FakeMem0 {
        fn list(&self, user_id: &str) -> Result<Vec<Mem0Record>, ProviderError> {
            Ok(self
                .records
                .get(user_id)
                .into_iter()
                .flatten()
                .map(|(record, _)| record.clone())
                .collect())
        }

        fn add_exact(
            &mut self,
            user_id: &str,
            projection: &AuthorizedMemoryProjection,
        ) -> Result<(), ProviderError> {
            self.next_id += 1;
            let record = Mem0Record::new(
                format!("mem0_{}", self.next_id),
                projection.memory_id.clone(),
                projection.version,
                Some(1_000_000),
            )?;
            self.records
                .entry(user_id.to_owned())
                .or_default()
                .push((record, projection.content.clone()));
            Ok(())
        }

        fn search(
            &self,
            user_id: &str,
            query: &str,
            _maximum_candidates: usize,
        ) -> Result<Vec<Mem0Record>, ProviderError> {
            Ok(self
                .records
                .get(user_id)
                .into_iter()
                .flatten()
                .filter(|(_, content)| content.contains(query))
                .map(|(record, _)| record.clone())
                .collect())
        }

        fn delete(&mut self, provider_id: &str) -> Result<(), ProviderError> {
            for records in self.records.values_mut() {
                records.retain(|(record, _)| record.provider_id() != provider_id);
            }
            Ok(())
        }
    }

    #[test]
    fn passes_semantic_provider_conformance_with_pseudonymous_partitions() {
        let mut provider =
            Mem0SemanticProvider::new(FakeMem0::default(), vec![7; 32]).expect("valid secret");
        verify_semantic_provider(&mut provider, "mem0-mapping")
            .expect("mapping should preserve canonical semantics");
    }

    #[test]
    fn rejects_invalid_records_and_queries() {
        assert!(Mem0Record::new("provider", MemoryId::new("memory"), 0, None).is_err());
        let provider =
            Mem0SemanticProvider::new(FakeMem0::default(), vec![8; 32]).expect("valid secret");
        assert!(
            provider
                .search(&SemanticQuery {
                    workspace_id: WorkspaceId::new("workspace"),
                    text: " ".to_owned(),
                    maximum_candidates: 10,
                })
                .is_err()
        );
    }

    #[test]
    fn replacement_deletes_old_provider_records() {
        let mut provider =
            Mem0SemanticProvider::new(FakeMem0::default(), vec![9; 32]).expect("valid secret");
        for version in [1, 2] {
            provider
                .index(AuthorizedMemoryProjection {
                    workspace_id: WorkspaceId::new("workspace"),
                    memory_id: MemoryId::new("memory"),
                    version,
                    scope: MemoryScope::Global,
                    kind: MemoryKind::Semantic,
                    content: format!("value-{version}"),
                })
                .expect("projection should index");
        }
        let results = provider
            .search(&SemanticQuery {
                workspace_id: WorkspaceId::new("workspace"),
                text: "value-2".to_owned(),
                maximum_candidates: 10,
            })
            .expect("search should succeed");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].version, 2);
    }
}

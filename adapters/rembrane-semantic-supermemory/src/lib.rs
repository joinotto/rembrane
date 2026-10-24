//! Canonical-to-Supermemory semantic projection mapping.

use std::collections::BTreeMap;
use std::io::Read;
use std::thread;
use std::time::Duration;

use rembrane_domain::{MemoryId, WorkspaceId};
use rembrane_provider_sdk::{
    AuthorizedMemoryProjection, CURRENT_PROVIDER_PROTOCOL, CandidateMemory, Capability,
    ProviderError, ProviderLimits, ProviderManifest, SemanticMemoryProvider, SemanticQuery,
};
use ring::hmac;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use reqwest::Url;
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};

const MAXIMUM_CONTENT_BYTES: usize = 262_144;
const MAXIMUM_CANDIDATES: usize = 1_000;
const MAXIMUM_PROVIDER_ID_BYTES: usize = 512;
const MAXIMUM_RESPONSE_RECORDS: usize = 1_000;
const MAXIMUM_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const READINESS_ATTEMPTS: usize = 20;
const READINESS_DELAY: Duration = Duration::from_millis(250);

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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireRecord {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    document_id: Option<String>,
    #[serde(default)]
    custom_id: Option<String>,
    metadata: WireMetadata,
    #[serde(default)]
    score: Option<f64>,
}

#[derive(Deserialize)]
struct WireMetadata {
    rembrane_memory_id: String,
    rembrane_version: u64,
}

#[derive(Deserialize)]
struct WireRecords {
    #[serde(default, alias = "documents")]
    results: Vec<WireRecord>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireDeletion {
    count: u64,
    #[serde(default)]
    errors: Vec<serde_json::Value>,
}

pub fn decode_records(bytes: &[u8]) -> Result<Vec<SupermemoryRecord>, ProviderError> {
    let wire: WireRecords = serde_json::from_slice(bytes)
        .map_err(|_| ProviderError::Rejected("Supermemory returned malformed JSON".to_owned()))?;
    if wire.results.len() > MAXIMUM_RESPONSE_RECORDS {
        return Err(ProviderError::Rejected(
            "Supermemory returned too many records".to_owned(),
        ));
    }
    wire.results.into_iter().map(decode_wire_record).collect()
}

fn decode_wire_record(record: WireRecord) -> Result<SupermemoryRecord, ProviderError> {
    let provider_id = record
        .custom_id
        .or(record.document_id)
        .or(record.id)
        .ok_or_else(|| {
            ProviderError::Rejected("Supermemory record identity is missing".to_owned())
        })?;
    let score = record
        .score
        .map(|score| {
            if !score.is_finite() || !(0.0..=1.0).contains(&score) {
                return Err(ProviderError::Rejected(
                    "Supermemory returned an invalid score".to_owned(),
                ));
            }
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            Ok((score * 1_000_000.0).round() as u32)
        })
        .transpose()?;
    SupermemoryRecord::new(
        provider_id,
        MemoryId::new(record.metadata.rembrane_memory_id),
        record.metadata.rembrane_version,
        score,
    )
}

pub fn deletion_confirmed(bytes: &[u8], provider_id: &str) -> Result<bool, ProviderError> {
    let wire: WireDeletion = serde_json::from_slice(bytes)
        .map_err(|_| ProviderError::Rejected("Supermemory returned malformed JSON".to_owned()))?;
    let _ = provider_id;
    Ok(wire.errors.is_empty() && wire.count == 1)
}

pub trait SupermemoryTransport {
    fn get(
        &self,
        namespace: &str,
        document_id: &str,
    ) -> Result<Option<SupermemoryRecord>, ProviderError>;
    fn upsert_exact(
        &mut self,
        namespace: &str,
        document_id: &str,
        projection: &AuthorizedMemoryProjection,
    ) -> Result<(), ProviderError>;
    fn await_ready(
        &mut self,
        namespace: &str,
        document_id: &str,
        projection: &AuthorizedMemoryProjection,
    ) -> Result<(), ProviderError>;
    fn search(
        &self,
        namespace: &str,
        query: &str,
        maximum_candidates: usize,
    ) -> Result<Vec<SupermemoryRecord>, ProviderError>;
    fn delete(&mut self, namespace: &str, provider_id: &str) -> Result<bool, ProviderError>;
}

pub struct HttpSupermemoryTransport {
    client: Client,
    base_url: Url,
    api_key: Zeroizing<String>,
}

impl HttpSupermemoryTransport {
    pub fn new(base_url: &str, api_key: String) -> Result<Self, ProviderError> {
        let base_url = validate_base_url(base_url)?;
        validate_api_key(&api_key)?;
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| ProviderError::Unavailable)?;
        Ok(Self {
            client,
            base_url,
            api_key: Zeroizing::new(api_key),
        })
    }

    fn endpoint(&self, namespace: &str, tail: &[&str]) -> Result<Url, ProviderError> {
        if !valid_namespace(namespace) {
            return Err(ProviderError::Rejected(
                "Supermemory namespace is invalid".to_owned(),
            ));
        }
        let mut endpoint = self.base_url.clone();
        let mut segments = endpoint
            .path_segments_mut()
            .map_err(|()| ProviderError::Unavailable)?;
        segments.extend(["ns", namespace]);
        segments.extend(tail.iter().copied());
        drop(segments);
        Ok(endpoint)
    }

    fn request(
        &self,
        request: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        request
            .header(ACCEPT, "application/json")
            .bearer_auth(self.api_key.as_str())
    }

    fn decode(response: Response) -> Result<Vec<u8>, ProviderError> {
        if !response.status().is_success() {
            return Err(match response.status().as_u16() {
                400 | 404 | 409 | 413 | 422 => {
                    ProviderError::Rejected("Supermemory rejected the operation".to_owned())
                }
                _ => ProviderError::Unavailable,
            });
        }
        let is_json = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("application/json"))
            });
        let too_large = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > MAXIMUM_RESPONSE_BYTES);
        if !is_json || too_large {
            return Err(ProviderError::Rejected(
                "Supermemory returned an invalid response".to_owned(),
            ));
        }
        let mut bytes = Vec::new();
        response
            .take((MAXIMUM_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ProviderError::Unavailable)?;
        if bytes.len() > MAXIMUM_RESPONSE_BYTES {
            return Err(ProviderError::Rejected(
                "Supermemory response exceeded the transport limit".to_owned(),
            ));
        }
        Ok(bytes)
    }

    fn search_records(
        &self,
        namespace: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<SupermemoryRecord>, ProviderError> {
        let response = self
            .request(self.client.post(self.endpoint(namespace, &["search"])?))
            .header(CONTENT_TYPE, "application/json")
            .json(&SearchBody {
                query,
                search_mode: "memories",
                limit,
            })
            .send()
            .map_err(|_| ProviderError::Unavailable)?;
        decode_records(&Self::decode(response)?)
    }
}

impl SupermemoryTransport for HttpSupermemoryTransport {
    fn get(
        &self,
        namespace: &str,
        document_id: &str,
    ) -> Result<Option<SupermemoryRecord>, ProviderError> {
        if !valid_provider_identifier(document_id, 255) {
            return Err(ProviderError::Rejected(
                "Supermemory document identity is invalid".to_owned(),
            ));
        }
        let response = self
            .request(
                self.client
                    .get(self.endpoint(namespace, &["document", document_id])?),
            )
            .send()
            .map_err(|_| ProviderError::Unavailable)?;
        if response.status().as_u16() == 404 {
            return Ok(None);
        }
        let wire: WireRecord = serde_json::from_slice(&Self::decode(response)?).map_err(|_| {
            ProviderError::Rejected("Supermemory returned malformed JSON".to_owned())
        })?;
        decode_wire_record(wire).map(Some)
    }

    fn upsert_exact(
        &mut self,
        namespace: &str,
        document_id: &str,
        projection: &AuthorizedMemoryProjection,
    ) -> Result<(), ProviderError> {
        if !valid_provider_identifier(document_id, 255) {
            return Err(ProviderError::Rejected(
                "Supermemory document identity is invalid".to_owned(),
            ));
        }
        let response = self
            .request(self.client.post(self.endpoint(namespace, &["document"])?))
            .header(CONTENT_TYPE, "application/json")
            .json(&DocumentBody {
                content: &projection.content,
                custom_id: document_id,
                metadata: MetadataBody {
                    memory_id: projection.memory_id.as_str(),
                    version: projection.version,
                },
            })
            .send()
            .map_err(|_| ProviderError::Unavailable)?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(ProviderError::Unavailable)
        }
    }

    fn await_ready(
        &mut self,
        namespace: &str,
        _document_id: &str,
        projection: &AuthorizedMemoryProjection,
    ) -> Result<(), ProviderError> {
        let query = projection.content.chars().take(512).collect::<String>();
        for attempt in 0..READINESS_ATTEMPTS {
            let ready = self
                .search_records(namespace, &query, 10)?
                .into_iter()
                .any(|record| {
                    record.canonical_memory_id == projection.memory_id
                        && record.canonical_version == projection.version
                });
            if ready {
                return Ok(());
            }
            if attempt + 1 < READINESS_ATTEMPTS {
                thread::sleep(READINESS_DELAY);
            }
        }
        Err(ProviderError::Unavailable)
    }

    fn search(
        &self,
        namespace: &str,
        query: &str,
        maximum_candidates: usize,
    ) -> Result<Vec<SupermemoryRecord>, ProviderError> {
        self.search_records(namespace, query, maximum_candidates)
    }

    fn delete(&mut self, namespace: &str, provider_id: &str) -> Result<bool, ProviderError> {
        if !valid_provider_identifier(provider_id, MAXIMUM_PROVIDER_ID_BYTES) {
            return Err(ProviderError::Rejected(
                "Supermemory document identity is invalid".to_owned(),
            ));
        }
        let response = self
            .request(self.client.delete(self.endpoint(namespace, &["document"])?))
            .header(CONTENT_TYPE, "application/json")
            .json(&DeleteBody { ids: [provider_id] })
            .send()
            .map_err(|_| ProviderError::Unavailable)?;
        deletion_confirmed(&Self::decode(response)?, provider_id)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchBody<'value> {
    #[serde(rename = "q")]
    query: &'value str,
    search_mode: &'static str,
    limit: usize,
}

#[derive(Serialize)]
struct MetadataBody<'value> {
    #[serde(rename = "rembrane_memory_id")]
    memory_id: &'value str,
    #[serde(rename = "rembrane_version")]
    version: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DocumentBody<'value> {
    content: &'value str,
    custom_id: &'value str,
    metadata: MetadataBody<'value>,
}

#[derive(Serialize)]
struct DeleteBody<'value> {
    ids: [&'value str; 1],
}

fn validate_base_url(value: &str) -> Result<Url, ProviderError> {
    let mut url = Url::parse(value).map_err(|_| {
        ProviderError::InvalidConfiguration("Supermemory base URL is invalid".to_owned())
    })?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "::1"));
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(ProviderError::InvalidConfiguration(
            "Supermemory base URL must be an HTTPS origin or literal loopback HTTP origin"
                .to_owned(),
        ));
    }
    url.set_path("/");
    Ok(url)
}

fn validate_api_key(value: &str) -> Result<(), ProviderError> {
    if value.len() < 8
        || value.len() > 4_096
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(ProviderError::InvalidConfiguration(
            "Supermemory API key is invalid".to_owned(),
        ));
    }
    Ok(())
}

pub struct SupermemorySemanticProvider<Transport> {
    transport: Transport,
    workspace_lookup_key: hmac::Key,
}

impl SupermemorySemanticProvider<HttpSupermemoryTransport> {
    pub fn from_http(
        base_url: &str,
        api_key: String,
        workspace_lookup_secret: Vec<u8>,
    ) -> Result<Self, ProviderError> {
        Self::new(
            HttpSupermemoryTransport::new(base_url, api_key)?,
            workspace_lookup_secret,
        )
    }
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
        let signature = self.pseudonym(b"namespace\0", workspace_id.as_str());
        let mut namespace = String::from("rembrane-");
        for byte in signature {
            use std::fmt::Write;
            let _ = write!(namespace, "{byte:02x}");
        }
        debug_assert!(valid_namespace(&namespace));
        namespace
    }

    fn document_id(&self, memory_id: &MemoryId) -> String {
        let signature = self.pseudonym(b"document\0", memory_id.as_str());
        let mut document_id = String::from("rembrane-");
        for byte in signature {
            use std::fmt::Write;
            let _ = write!(document_id, "{byte:02x}");
        }
        debug_assert!(valid_provider_identifier(&document_id, 255));
        document_id
    }

    fn pseudonym(&self, domain: &[u8], value: &str) -> [u8; 32] {
        let mut context = hmac::Context::with_key(&self.workspace_lookup_key);
        context.update(domain);
        context.update(value.as_bytes());
        let mut output = [0_u8; 32];
        output.copy_from_slice(context.sign().as_ref());
        output
    }
}

fn valid_namespace(value: &str) -> bool {
    valid_provider_identifier(value, 100)
}

fn valid_provider_identifier(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'-'))
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
        let document_id = self.document_id(&projection.memory_id);
        self.transport
            .upsert_exact(&namespace, &document_id, &projection)?;
        self.transport
            .await_ready(&namespace, &document_id, &projection)
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
        let document_id = self.document_id(memory_id);
        let Some(record) = self.transport.get(&namespace, &document_id)? else {
            return Ok(());
        };
        if &record.canonical_memory_id == memory_id
            && record.canonical_version <= through_version
            && !self.transport.delete(&namespace, &document_id)?
        {
            return Err(ProviderError::Unavailable);
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

    use super::{
        HttpSupermemoryTransport, SupermemoryRecord, SupermemorySemanticProvider,
        SupermemoryTransport, decode_records, deletion_confirmed, valid_namespace,
        valid_provider_identifier, validate_api_key,
    };

    #[derive(Default)]
    struct FakeSupermemory {
        records: BTreeMap<String, Vec<(SupermemoryRecord, String)>>,
        next_id: u64,
        fail_readiness: bool,
        fail_deletion_confirmation: bool,
    }

    impl SupermemoryTransport for FakeSupermemory {
        fn get(
            &self,
            namespace: &str,
            document_id: &str,
        ) -> Result<Option<SupermemoryRecord>, ProviderError> {
            Ok(self
                .records
                .get(namespace)
                .into_iter()
                .flatten()
                .find(|(record, _)| record.provider_id() == document_id)
                .map(|(record, _)| record.clone()))
        }

        fn upsert_exact(
            &mut self,
            namespace: &str,
            document_id: &str,
            projection: &AuthorizedMemoryProjection,
        ) -> Result<(), ProviderError> {
            self.next_id += 1;
            let records = self.records.entry(namespace.to_owned()).or_default();
            records.retain(|(record, _)| record.provider_id() != document_id);
            let record = SupermemoryRecord::new(
                document_id,
                projection.memory_id.clone(),
                projection.version,
                Some(1_000_000),
            )?;
            records.push((record, projection.content.clone()));
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

        fn await_ready(
            &mut self,
            _namespace: &str,
            _document_id: &str,
            _projection: &AuthorizedMemoryProjection,
        ) -> Result<(), ProviderError> {
            if self.fail_readiness {
                Err(ProviderError::Unavailable)
            } else {
                Ok(())
            }
        }

        fn delete(&mut self, namespace: &str, provider_id: &str) -> Result<bool, ProviderError> {
            if self.fail_deletion_confirmation {
                return Ok(false);
            }
            if let Some(records) = self.records.get_mut(namespace) {
                records.retain(|(record, _)| record.provider_id() != provider_id);
            }
            Ok(true)
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

    #[test]
    fn generated_namespace_obeys_provider_contract() {
        let provider = SupermemorySemanticProvider::new(FakeSupermemory::default(), vec![6; 32])
            .expect("valid lookup secret");
        let namespace = provider.namespace(&rembrane_domain::WorkspaceId::new(
            "workspace with provider-unsafe characters/?#",
        ));
        assert!(valid_namespace(&namespace));
        assert!(!namespace.contains("workspace"));
        assert_eq!(namespace.len(), 73);

        let document_id =
            provider.document_id(&rembrane_domain::MemoryId::new("../canonical?memory#id"));
        assert!(valid_provider_identifier(&document_id, 255));
        assert!(!document_id.contains("canonical"));
        assert_eq!(document_id.len(), 73);
    }

    #[test]
    fn wire_records_require_canonical_metadata_and_valid_scores() {
        let records = decode_records(
            br#"{"results":[{"documentId":"provider-01","metadata":{"rembrane_memory_id":"memory-01","rembrane_version":2},"score":0.75}]}"#,
        )
        .expect("valid response");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].canonical_version, 2);
        assert_eq!(records[0].score_millionths, Some(750_000));
        let records = decode_records(
            br#"{"documents":[{"id":"internal-01","customId":"rembrane-caller-01","metadata":{"rembrane_memory_id":"memory-01","rembrane_version":2}}]}"#,
        )
        .expect("document response with both identities");
        assert_eq!(records[0].provider_id(), "rembrane-caller-01");
        assert!(decode_records(br#"{"results":[{"id":"x","metadata":{},"score":2}]}"#).is_err());
    }

    #[test]
    fn deletion_requires_one_exact_success_and_no_failures() {
        assert!(
            deletion_confirmed(br#"{"count":1,"errors":[]}"#, "doc-01").expect("valid response")
        );
        assert!(
            !deletion_confirmed(br#"{"count":0,"errors":[{"id":"doc-01"}]}"#, "doc-01")
                .expect("valid partial response")
        );
        assert!(
            !deletion_confirmed(br#"{"count":0,"errors":[]}"#, "doc-01")
                .expect("valid empty response")
        );
    }

    #[test]
    fn http_configuration_and_paths_fail_closed() {
        for origin in ["https://api.supermemory.ai", "http://127.0.0.1:8788"] {
            assert!(HttpSupermemoryTransport::new(origin, "test-key-123456".to_owned()).is_ok());
        }
        for origin in [
            "http://api.supermemory.ai",
            "http://localhost:8788",
            "https://user@api.supermemory.ai",
            "https://api.supermemory.ai/path",
        ] {
            assert!(HttpSupermemoryTransport::new(origin, "test-key-123456".to_owned()).is_err());
        }
        assert!(validate_api_key("test-key-123456").is_ok());
        assert!(validate_api_key("short").is_err());
        assert!(validate_api_key("key\ninjected").is_err());

        let transport = HttpSupermemoryTransport::new(
            "https://api.supermemory.ai",
            "test-key-123456".to_owned(),
        )
        .expect("valid transport");
        assert_eq!(
            transport
                .endpoint("rembrane-test", &["document"])
                .expect("safe endpoint")
                .as_str(),
            "https://api.supermemory.ai/ns/rembrane-test/document"
        );
    }

    #[test]
    fn incomplete_ingestion_never_reports_projection_success() {
        use rembrane_domain::{MemoryId, MemoryKind, MemoryScope, WorkspaceId};
        use rembrane_provider_sdk::{AuthorizedMemoryProjection, SemanticMemoryProvider};

        let mut provider = SupermemorySemanticProvider::new(
            FakeSupermemory {
                fail_readiness: true,
                ..FakeSupermemory::default()
            },
            vec![8; 32],
        )
        .expect("valid lookup secret");
        let result = provider.index(AuthorizedMemoryProjection {
            workspace_id: WorkspaceId::new("workspace"),
            memory_id: MemoryId::new("memory"),
            version: 1,
            scope: MemoryScope::Global,
            kind: MemoryKind::Semantic,
            content: "Call me Hippo".to_owned(),
        });
        assert_eq!(result, Err(ProviderError::Unavailable));
    }

    #[test]
    fn unconfirmed_deletion_never_reports_success() {
        use rembrane_domain::{MemoryId, MemoryKind, MemoryScope, WorkspaceId};
        use rembrane_provider_sdk::{AuthorizedMemoryProjection, SemanticMemoryProvider};

        let mut provider =
            SupermemorySemanticProvider::new(FakeSupermemory::default(), vec![9; 32])
                .expect("valid lookup secret");
        let projection = AuthorizedMemoryProjection {
            workspace_id: WorkspaceId::new("workspace"),
            memory_id: MemoryId::new("memory"),
            version: 1,
            scope: MemoryScope::Global,
            kind: MemoryKind::Semantic,
            content: "Call me Hippo".to_owned(),
        };
        provider.index(projection).expect("initial projection");
        provider.transport.fail_deletion_confirmation = true;
        assert_eq!(
            provider.delete(&WorkspaceId::new("workspace"), &MemoryId::new("memory"), 1),
            Err(ProviderError::Unavailable)
        );
    }

    #[test]
    fn version_bounded_deletion_never_scans_the_namespace() {
        use rembrane_domain::{MemoryId, MemoryKind, MemoryScope, WorkspaceId};
        use rembrane_provider_sdk::{AuthorizedMemoryProjection, SemanticMemoryProvider};

        let workspace_id = WorkspaceId::new("workspace");
        let memory_id = MemoryId::new("memory");
        let mut provider =
            SupermemorySemanticProvider::new(FakeSupermemory::default(), vec![10; 32])
                .expect("valid lookup secret");
        provider
            .index(AuthorizedMemoryProjection {
                workspace_id: workspace_id.clone(),
                memory_id: memory_id.clone(),
                version: 2,
                scope: MemoryScope::Global,
                kind: MemoryKind::Semantic,
                content: "Call me Hippo".to_owned(),
            })
            .expect("initial projection");

        provider
            .delete(&workspace_id, &memory_id, 1)
            .expect("older bound must preserve the current projection");
        assert!(
            provider
                .transport
                .get(
                    &provider.namespace(&workspace_id),
                    &provider.document_id(&memory_id)
                )
                .expect("exact lookup")
                .is_some()
        );

        provider
            .delete(&workspace_id, &memory_id, 2)
            .expect("matching bound must delete by exact identity");
        assert!(
            provider
                .transport
                .get(
                    &provider.namespace(&workspace_id),
                    &provider.document_id(&memory_id)
                )
                .expect("exact lookup")
                .is_none()
        );
    }
}

//! Canonical-to-Mem0 semantic projection mapping.
//!
//! Mem0 remains derived, replaceable state. This adapter never delegates
//! Rembrane authorization or canonical identity to Mem0.

use std::collections::BTreeMap;
use std::io::Read;
use std::time::Duration;

use rembrane_config::{ProviderConnection, ProviderKind};
use rembrane_domain::{MemoryId, WorkspaceId};
use rembrane_provider_sdk::{
    AuthorizedMemoryProjection, CURRENT_PROVIDER_PROTOCOL, CandidateMemory, Capability,
    ProviderError, ProviderLimits, ProviderManifest, SemanticMemoryProvider, SemanticQuery,
};
use rembrane_secret_local::{SecretResolver, resolve_provider_credentials};
use ring::hmac;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use reqwest::Url;
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HeaderName};

const MAXIMUM_CONTENT_BYTES: usize = 262_144;
const MAXIMUM_CANDIDATES: usize = 1_000;
const MAXIMUM_PROVIDER_ID_BYTES: usize = 512;
const MAXIMUM_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MEM0_API_KEY_HEADER: HeaderName = HeaderName::from_static("x-api-key");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mem0Record {
    provider_id: String,
    canonical_memory_id: MemoryId,
    canonical_version: u64,
    canonical_binding: String,
    score_millionths: Option<u32>,
}

impl Mem0Record {
    pub fn new(
        provider_id: impl Into<String>,
        canonical_memory_id: MemoryId,
        canonical_version: u64,
        canonical_binding: impl Into<String>,
        score_millionths: Option<u32>,
    ) -> Result<Self, ProviderError> {
        let provider_id = provider_id.into();
        let canonical_binding = canonical_binding.into();
        if provider_id.is_empty()
            || provider_id.len() > MAXIMUM_PROVIDER_ID_BYTES
            || provider_id.chars().any(char::is_control)
            || canonical_version == 0
            || canonical_binding.len() != 64
            || !canonical_binding
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
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
            canonical_binding,
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
        canonical_binding: &str,
    ) -> Result<(), ProviderError>;

    fn search(
        &self,
        user_id: &str,
        query: &str,
        maximum_candidates: usize,
    ) -> Result<Vec<Mem0Record>, ProviderError>;

    fn delete(&mut self, provider_id: &str) -> Result<(), ProviderError>;
}

pub struct HttpMem0Transport {
    client: Client,
    memories_endpoint: Url,
    search_endpoint: Url,
    api_key: Zeroizing<String>,
}

impl HttpMem0Transport {
    pub fn new(base_url: &str, api_key: String) -> Result<Self, ProviderError> {
        Self::new_with_secret(base_url, Zeroizing::new(api_key))
    }

    /// Builds a Mem0 transport from an already resolved zeroizing API key.
    ///
    /// # Errors
    ///
    /// Returns a provider error when the origin or credential is invalid or
    /// the bounded HTTP client cannot be constructed.
    pub fn new_with_secret(
        base_url: &str,
        api_key: Zeroizing<String>,
    ) -> Result<Self, ProviderError> {
        let base = validate_base_url(base_url)?;
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
            memories_endpoint: base
                .join("memories")
                .map_err(|_| ProviderError::Unavailable)?,
            search_endpoint: base
                .join("search")
                .map_err(|_| ProviderError::Unavailable)?,
            api_key,
        })
    }

    fn decode_records(response: Response) -> Result<Vec<Mem0Record>, ProviderError> {
        let bytes = decode_json_bytes(response)?;
        let collection: WireCollection = serde_json::from_slice(&bytes).map_err(|_| {
            ProviderError::Rejected("Mem0 returned malformed record JSON".to_owned())
        })?;
        collection
            .into_records()
            .into_iter()
            .map(WireMemory::try_into_record)
            .collect()
    }

    fn delete_endpoint(&self, provider_id: &str) -> Result<Url, ProviderError> {
        let mut endpoint = self.memories_endpoint.clone();
        endpoint
            .path_segments_mut()
            .map_err(|()| ProviderError::Unavailable)?
            .push(provider_id);
        Ok(endpoint)
    }

    fn authenticated(
        &self,
        request: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        request
            .header(ACCEPT, "application/json")
            .header(MEM0_API_KEY_HEADER, self.api_key.as_str())
    }
}

impl Mem0Transport for HttpMem0Transport {
    fn list(&self, user_id: &str) -> Result<Vec<Mem0Record>, ProviderError> {
        let response = self
            .authenticated(
                self.client
                    .get(self.memories_endpoint.clone())
                    .query(&[("user_id", user_id)]),
            )
            .send()
            .map_err(|_| ProviderError::Unavailable)?;
        Self::decode_records(response)
    }

    fn add_exact(
        &mut self,
        user_id: &str,
        projection: &AuthorizedMemoryProjection,
        canonical_binding: &str,
    ) -> Result<(), ProviderError> {
        let body = AddMemoryBody {
            messages: [MemoryMessage {
                role: "user",
                content: &projection.content,
            }],
            user_id,
            metadata: ProjectionMetadata {
                memory_id: projection.memory_id.as_str(),
                version: projection.version,
                binding: canonical_binding,
            },
            infer: false,
        };
        let response = self
            .authenticated(self.client.post(self.memories_endpoint.clone()))
            .header(CONTENT_TYPE, "application/json")
            .json(&body)
            .send()
            .map_err(|_| ProviderError::Unavailable)?;
        require_success(&response)
    }

    fn search(
        &self,
        user_id: &str,
        query: &str,
        maximum_candidates: usize,
    ) -> Result<Vec<Mem0Record>, ProviderError> {
        let response = self
            .authenticated(self.client.post(self.search_endpoint.clone()))
            .header(CONTENT_TYPE, "application/json")
            .json(&SearchBody {
                query,
                user_id,
                top_k: maximum_candidates,
            })
            .send()
            .map_err(|_| ProviderError::Unavailable)?;
        Self::decode_records(response)
    }

    fn delete(&mut self, provider_id: &str) -> Result<(), ProviderError> {
        let response = self
            .authenticated(self.client.delete(self.delete_endpoint(provider_id)?))
            .send()
            .map_err(|_| ProviderError::Unavailable)?;
        require_success(&response)
    }
}

#[derive(Serialize)]
struct MemoryMessage<'value> {
    role: &'static str,
    content: &'value str,
}

#[derive(Serialize)]
struct ProjectionMetadata<'value> {
    #[serde(rename = "rembrane_memory_id")]
    memory_id: &'value str,
    #[serde(rename = "rembrane_version")]
    version: u64,
    #[serde(rename = "rembrane_binding")]
    binding: &'value str,
}

#[derive(Serialize)]
struct AddMemoryBody<'value> {
    messages: [MemoryMessage<'value>; 1],
    user_id: &'value str,
    metadata: ProjectionMetadata<'value>,
    infer: bool,
}

#[derive(Serialize)]
struct SearchBody<'value> {
    query: &'value str,
    user_id: &'value str,
    top_k: usize,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum WireCollection {
    Array(Vec<WireMemory>),
    Object {
        #[serde(default)]
        results: Vec<WireMemory>,
        #[serde(default)]
        memories: Vec<WireMemory>,
    },
}

impl WireCollection {
    fn into_records(self) -> Vec<WireMemory> {
        match self {
            Self::Array(records) => records,
            Self::Object {
                mut results,
                memories,
            } => {
                results.extend(memories);
                results
            }
        }
    }
}

#[derive(Deserialize)]
struct WireMemory {
    id: String,
    metadata: ProjectionMetadataWire,
    #[serde(default)]
    score: Option<f64>,
}

#[derive(Deserialize)]
struct ProjectionMetadataWire {
    #[serde(rename = "rembrane_memory_id")]
    memory_id: String,
    #[serde(rename = "rembrane_version")]
    version: u64,
    #[serde(rename = "rembrane_binding")]
    binding: String,
}

impl WireMemory {
    fn try_into_record(self) -> Result<Mem0Record, ProviderError> {
        let score_millionths = self
            .score
            .map(|score| {
                if !score.is_finite() || !(0.0..=1.0).contains(&score) {
                    return Err(ProviderError::Rejected(
                        "Mem0 returned an invalid similarity score".to_owned(),
                    ));
                }
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                Ok((score * 1_000_000.0).round() as u32)
            })
            .transpose()?;
        Mem0Record::new(
            self.id,
            MemoryId::new(self.metadata.memory_id),
            self.metadata.version,
            self.metadata.binding,
            score_millionths,
        )
    }
}

fn validate_base_url(value: &str) -> Result<Url, ProviderError> {
    let mut url = Url::parse(value)
        .map_err(|_| ProviderError::InvalidConfiguration("Mem0 base URL is invalid".to_owned()))?;
    let loopback = url
        .host_str()
        .is_some_and(|host| matches!(host, "127.0.0.1" | "::1"));
    if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(ProviderError::InvalidConfiguration(
            "Mem0 base URL must be an HTTPS origin or exact loopback HTTP origin".to_owned(),
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
            "Mem0 API key is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn require_success(response: &Response) -> Result<(), ProviderError> {
    if response.status().is_success() {
        return Ok(());
    }
    Err(
        if matches!(response.status().as_u16(), 400 | 404 | 409 | 413 | 422) {
            ProviderError::Rejected("Mem0 rejected the operation".to_owned())
        } else {
            ProviderError::Unavailable
        },
    )
}

fn decode_json_bytes(response: Response) -> Result<Vec<u8>, ProviderError> {
    if !response.status().is_success() {
        return require_success(&response).map(|()| Vec::new());
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
            "Mem0 returned an invalid response".to_owned(),
        ));
    }
    let mut bytes = Vec::new();
    response
        .take((MAXIMUM_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ProviderError::Unavailable)?;
    if bytes.len() > MAXIMUM_RESPONSE_BYTES {
        return Err(ProviderError::Rejected(
            "Mem0 response exceeded the transport limit".to_owned(),
        ));
    }
    Ok(bytes)
}

pub struct Mem0SemanticProvider<Transport> {
    transport: Transport,
    workspace_lookup_key: hmac::Key,
}

impl Mem0SemanticProvider<HttpMem0Transport> {
    pub fn from_http(
        base_url: &str,
        api_key: String,
        workspace_lookup_secret: Vec<u8>,
    ) -> Result<Self, ProviderError> {
        Self::new(
            HttpMem0Transport::new(base_url, api_key)?,
            workspace_lookup_secret,
        )
    }

    /// Builds the direct Mem0 adapter from a validated profile whose ordered
    /// references are API key followed by workspace-pseudonym secret.
    ///
    /// # Errors
    ///
    /// Returns a provider error unless Mem0 and provider plaintext processing
    /// are explicitly selected, exactly two secrets resolve, and both values
    /// satisfy their transport and pseudonym-key constraints.
    pub fn from_connection<Resolver>(
        connection: &ProviderConnection,
        resolver: &Resolver,
        allow_provider_plaintext: bool,
    ) -> Result<Self, ProviderError>
    where
        Resolver: SecretResolver + ?Sized,
    {
        if connection.kind() != ProviderKind::Mem0
            || connection.endpoint().is_none()
            || connection.credentials().len() != 2
        {
            return Err(ProviderError::InvalidConfiguration(
                "Mem0 requires one endpoint plus API-key and workspace-secret references"
                    .to_owned(),
            ));
        }
        if !allow_provider_plaintext {
            return Err(ProviderError::InvalidConfiguration(
                "Mem0 provider plaintext processing was not explicitly allowed".to_owned(),
            ));
        }
        let mut credentials = resolve_provider_credentials(resolver, connection).map_err(|_| {
            ProviderError::InvalidConfiguration("Mem0 credentials unavailable".to_owned())
        })?;
        let mut workspace_secret = credentials.pop().ok_or_else(|| {
            ProviderError::InvalidConfiguration("Mem0 credentials unavailable".to_owned())
        })?;
        let api_key = credentials.pop().ok_or_else(|| {
            ProviderError::InvalidConfiguration("Mem0 credentials unavailable".to_owned())
        })?;
        let transport = HttpMem0Transport::new_with_secret(
            connection.endpoint().ok_or_else(|| {
                ProviderError::InvalidConfiguration("Mem0 endpoint unavailable".to_owned())
            })?,
            api_key,
        )?;
        Self::new(
            transport,
            std::mem::take(&mut *workspace_secret).into_bytes(),
        )
    }
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
        encode_signature("rembrane_ws_", signature.as_ref())
    }

    fn record_binding(
        &self,
        workspace_id: &WorkspaceId,
        memory_id: &MemoryId,
        version: u64,
    ) -> String {
        let message = record_binding_message(workspace_id, memory_id, version);
        encode_signature(
            "",
            hmac::sign(&self.workspace_lookup_key, &message).as_ref(),
        )
    }

    fn record_is_bound(&self, workspace_id: &WorkspaceId, record: &Mem0Record) -> bool {
        let Some(tag) = decode_signature(&record.canonical_binding) else {
            return false;
        };
        let message = record_binding_message(
            workspace_id,
            &record.canonical_memory_id,
            record.canonical_version,
        );
        hmac::verify(&self.workspace_lookup_key, &message, &tag).is_ok()
    }
}

fn record_binding_message(
    workspace_id: &WorkspaceId,
    memory_id: &MemoryId,
    version: u64,
) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(15 + workspace_id.as_str().len() + memory_id.as_str().len() + 10);
    message.extend_from_slice(b"record-binding\0");
    message.extend_from_slice(workspace_id.as_str().as_bytes());
    message.push(0);
    message.extend_from_slice(memory_id.as_str().as_bytes());
    message.push(0);
    message.extend_from_slice(&version.to_be_bytes());
    message
}

fn encode_signature(prefix: &str, signature: &[u8]) -> String {
    let mut encoded = String::with_capacity(prefix.len() + signature.len() * 2);
    encoded.push_str(prefix);
    for byte in signature {
        use std::fmt::Write;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn decode_signature(encoded: &str) -> Option<[u8; 32]> {
    if encoded.len() != 64 {
        return None;
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = char::from(pair[0]).to_digit(16)?;
        let low = char::from(pair[1]).to_digit(16)?;
        decoded[index] = u8::try_from((high << 4) | low).ok()?;
    }
    Some(decoded)
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
        if existing
            .iter()
            .any(|record| !self.record_is_bound(&projection.workspace_id, record))
        {
            return Err(ProviderError::Rejected(
                "Mem0 returned unbound canonical projection metadata".to_owned(),
            ));
        }
        for record in existing {
            if record.canonical_memory_id == projection.memory_id {
                self.transport.delete(record.provider_id())?;
            }
        }
        let binding = self.record_binding(
            &projection.workspace_id,
            &projection.memory_id,
            projection.version,
        );
        self.transport.add_exact(&user_id, &projection, &binding)
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
            if !self.record_is_bound(&query.workspace_id, &record) {
                return Err(ProviderError::Rejected(
                    "Mem0 returned unbound canonical projection metadata".to_owned(),
                ));
            }
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
        let records = self.transport.list(&user_id)?;
        if records
            .iter()
            .any(|record| !self.record_is_bound(workspace_id, record))
        {
            return Err(ProviderError::Rejected(
                "Mem0 returned unbound canonical projection metadata".to_owned(),
            ));
        }
        for record in records {
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

    use rembrane_config::{ProviderConnection, ProviderKind, ProviderPlacement, SecretReference};
    use rembrane_domain::{MemoryId, MemoryKind, MemoryScope, WorkspaceId};
    use rembrane_provider_sdk::{
        AuthorizedMemoryProjection, ProviderError, SemanticMemoryProvider, SemanticQuery,
        verify_semantic_provider,
    };
    use rembrane_secret_local::{SecretResolutionError, SecretResolver};
    use zeroize::Zeroizing;

    use super::{
        Mem0Record, Mem0SemanticProvider, Mem0Transport, WireCollection, validate_api_key,
        validate_base_url,
    };

    struct PanicResolver;

    impl SecretResolver for PanicResolver {
        fn resolve(
            &self,
            _reference: &SecretReference,
        ) -> Result<Zeroizing<String>, SecretResolutionError> {
            panic!("invalid profile must fail before secret resolution")
        }
    }

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
            canonical_binding: &str,
        ) -> Result<(), ProviderError> {
            self.next_id += 1;
            let record = Mem0Record::new(
                format!("mem0_{}", self.next_id),
                projection.memory_id.clone(),
                projection.version,
                canonical_binding,
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
    fn profile_and_plaintext_policy_fail_before_secret_resolution() {
        let wrong_kind = ProviderConnection::remote(
            ProviderKind::Supermemory,
            "https://memory.example.test",
            vec![
                SecretReference::environment("MEMORY_API_KEY").expect("reference"),
                SecretReference::environment("MEMORY_LOOKUP_SECRET").expect("reference"),
            ],
            ProviderPlacement::External,
        )
        .expect("profile");
        assert!(Mem0SemanticProvider::from_connection(&wrong_kind, &PanicResolver, true).is_err());

        let mem0 = ProviderConnection::remote(
            ProviderKind::Mem0,
            "https://memory.example.test",
            vec![
                SecretReference::environment("MEMORY_API_KEY").expect("reference"),
                SecretReference::environment("MEMORY_LOOKUP_SECRET").expect("reference"),
            ],
            ProviderPlacement::External,
        )
        .expect("profile");
        assert!(Mem0SemanticProvider::from_connection(&mem0, &PanicResolver, false).is_err());
    }

    #[test]
    fn rejects_invalid_records_and_queries() {
        assert!(Mem0Record::new("provider", MemoryId::new("memory"), 0, "", None).is_err());
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

    #[test]
    fn rejects_unbound_provider_metadata_before_read_or_mutation() {
        let workspace_id = WorkspaceId::new("workspace");
        let memory_id = MemoryId::new("memory");
        let mut provider =
            Mem0SemanticProvider::new(FakeMem0::default(), vec![10; 32]).expect("valid secret");
        provider
            .index(AuthorizedMemoryProjection {
                workspace_id: workspace_id.clone(),
                memory_id: memory_id.clone(),
                version: 1,
                scope: MemoryScope::Global,
                kind: MemoryKind::Semantic,
                content: "Call me Hippo".to_owned(),
            })
            .expect("initial projection");
        let user_id = provider.user_id(&workspace_id);
        let record = provider
            .transport
            .records
            .get_mut(&user_id)
            .expect("workspace partition")
            .first_mut()
            .expect("record");
        record.0.canonical_binding.replace_range(0..1, "f");

        assert!(matches!(
            provider.search(&SemanticQuery {
                workspace_id: workspace_id.clone(),
                text: "Hippo".to_owned(),
                maximum_candidates: 10,
            }),
            Err(ProviderError::Rejected(_))
        ));
        assert!(matches!(
            provider.delete(&workspace_id, &memory_id, 1),
            Err(ProviderError::Rejected(_))
        ));
        assert!(matches!(
            provider.index(AuthorizedMemoryProjection {
                workspace_id,
                memory_id,
                version: 2,
                scope: MemoryScope::Global,
                kind: MemoryKind::Semantic,
                content: "Call me Hippo again".to_owned(),
            }),
            Err(ProviderError::Rejected(_))
        ));
        assert_eq!(provider.transport.next_id, 1);
    }

    #[test]
    fn decodes_mem0_result_metadata_and_rejects_invalid_scores() {
        let collection: WireCollection = serde_json::from_str(
            r#"{"results":[{"id":"provider-01","memory":"Call me Hippo","metadata":{"rembrane_memory_id":"memory_01","rembrane_version":2,"rembrane_binding":"0000000000000000000000000000000000000000000000000000000000000000"},"score":0.75}]}"#,
        )
        .expect("wire result should decode");
        let record = collection
            .into_records()
            .pop()
            .expect("record should exist")
            .try_into_record()
            .expect("canonical metadata should validate");
        assert_eq!(record.canonical_memory_id.as_str(), "memory_01");
        assert_eq!(record.canonical_version, 2);
        assert_eq!(record.score_millionths, Some(750_000));

        let collection: WireCollection = serde_json::from_str(
            r#"[{"id":"provider-01","metadata":{"rembrane_memory_id":"memory_01","rembrane_version":2,"rembrane_binding":"0000000000000000000000000000000000000000000000000000000000000000"},"score":1.1}]"#,
        )
        .expect("wire shape should decode");
        assert!(
            collection
                .into_records()
                .into_iter()
                .next()
                .expect("record should exist")
                .try_into_record()
                .is_err()
        );
    }

    #[test]
    fn http_configuration_requires_safe_origin_and_bounded_key() {
        assert!(validate_base_url("https://mem0.example").is_ok());
        assert!(validate_base_url("http://127.0.0.1:8888").is_ok());
        for unsafe_url in [
            "http://mem0.example",
            "http://localhost:8888",
            "https://user:secret@mem0.example",
            "https://mem0.example/path",
            "https://mem0.example?token=secret",
        ] {
            assert!(validate_base_url(unsafe_url).is_err());
        }
        assert!(validate_api_key("test-key-123456").is_ok());
        assert!(validate_api_key("short").is_err());
        assert!(validate_api_key("key\ninjected").is_err());
    }
}

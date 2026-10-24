//! Deployment-selected portable memory provider composition.

use std::time::{SystemTime, UNIX_EPOCH};

use rembrane_config::{ProviderConnection, ProviderKind, SecretReference};
use rembrane_memory_provider_http::HttpMemoryProviderClient;
use rembrane_provider_sdk::{
    CheckpointActivityPayload, CheckpointActivityResult, DeleteMemoryPayload, DeleteMemoryResult,
    ExplainMemoryPayload, ExplainMemoryResult, MemoryProviderClient, MemoryProviderConnection,
    MemoryProviderPolicy, MemoryProviderResponse, ProposeMemoryPayload, ProposeMemoryResult,
    ProviderError, RecordDisclosurePayload, RecordDisclosureResult, RecordEventPayload,
    RecordEventResult, ResolveContextPayload, ResolveContextResult, ResolveQuestionPayload,
    ResolveQuestionResult, SyncPullPayload, SyncPullResult, SyncPushPayload, SyncPushResult,
};
use rembrane_secret_local::{LocalSecretResolver, SecretResolver, resolve_provider_credentials};
use zeroize::Zeroizing;

pub struct ConfiguredMemoryProvider {
    client: Box<dyn MemoryProviderClient>,
    connection: MemoryProviderConnection,
}

/// Deployment-owned HTTP values for portable Memory Provider composition.
///
/// The type intentionally does not implement `Clone`, `Debug`, serialization,
/// or field accessors so bearer credentials are not accidentally duplicated,
/// formatted, or persisted by generic configuration tooling.
pub struct MemoryProviderHttpConfig {
    base_url: String,
    bearer_token: Zeroizing<String>,
    request_prefix: Option<String>,
}

impl MemoryProviderHttpConfig {
    #[must_use]
    pub fn new(base_url: impl Into<String>, bearer_token: impl Into<String>) -> Self {
        Self::new_with_secret(base_url, Zeroizing::new(bearer_token.into()))
    }

    #[must_use]
    pub fn new_with_secret(base_url: impl Into<String>, bearer_token: Zeroizing<String>) -> Self {
        Self {
            base_url: base_url.into(),
            bearer_token,
            request_prefix: None,
        }
    }

    #[must_use]
    pub fn with_request_prefix(mut self, request_prefix: impl Into<String>) -> Self {
        self.request_prefix = Some(request_prefix.into());
        self
    }
}

impl ConfiguredMemoryProvider {
    /// Connects to the selected portable memory provider using
    /// deployment-owned environment variables.
    ///
    /// `REMBRANE_MEMORY_PROVIDER` currently accepts `http`. The selected
    /// provider requires `REMBRANE_MEMORY_PROVIDER_BASE_URL` and
    /// `REMBRANE_MEMORY_PROVIDER_TOKEN` or its reference locator. An optional safe
    /// `REMBRANE_MEMORY_PROVIDER_REQUEST_PREFIX` makes request identities
    /// recognizable without containing tenant or credential material.
    ///
    /// # Errors
    ///
    /// Returns a provider error for missing, unsupported, malformed, or
    /// policy-incompatible configuration and for discovery failures.
    pub fn from_environment(policy: &MemoryProviderPolicy) -> Result<Self, ProviderError> {
        match std::env::var("REMBRANE_MEMORY_PROVIDER")
            .as_deref()
            .unwrap_or("http")
        {
            "http" => {
                let endpoint = required_environment("REMBRANE_MEMORY_PROVIDER_BASE_URL")?;
                let token_reference = configured_token_reference()?;
                let token = LocalSecretResolver
                    .resolve(&token_reference)
                    .map_err(|_| provider_credential_unavailable())?;
                let mut config = MemoryProviderHttpConfig::new_with_secret(endpoint, token);
                if let Ok(prefix) = std::env::var("REMBRANE_MEMORY_PROVIDER_REQUEST_PREFIX") {
                    config = config.with_request_prefix(prefix);
                }
                Self::from_http_config(config, policy)
            }
            _ => Err(ProviderError::InvalidConfiguration(
                "REMBRANE_MEMORY_PROVIDER must be http".to_owned(),
            )),
        }
    }

    /// Connects using values supplied by deployment-owned configuration and
    /// secret-resolution code.
    ///
    /// This lets applications resolve credentials from an OS keychain,
    /// customer vault, cloud secret manager, file descriptor, or another
    /// mechanism without copying secrets into fixed Rembrane environment
    /// variables.
    ///
    /// # Errors
    ///
    /// Returns a provider error for malformed endpoint, token, request prefix,
    /// discovery, or policy negotiation.
    pub fn from_http_config(
        mut config: MemoryProviderHttpConfig,
        policy: &MemoryProviderPolicy,
    ) -> Result<Self, ProviderError> {
        let request_prefix = match config.request_prefix.take() {
            Some(value) => validate_request_prefix(value)?,
            None => default_request_prefix()?,
        };
        let bearer_token = std::mem::take(&mut config.bearer_token);
        let client = HttpMemoryProviderClient::new_with_secret(&config.base_url, bearer_token)?;
        Self::from_client(Box::new(client), policy, request_prefix)
    }

    /// Connects a portable semantic provider from a validated profile through
    /// a deployment-selected secret resolver.
    ///
    /// The negotiated provider policy remains responsible for explicitly
    /// accepting or rejecting the provider's advertised privacy mode.
    ///
    /// # Errors
    ///
    /// Returns a provider error unless the profile selects Mem0 or
    /// Supermemory with one endpoint and one credential reference, resolution
    /// succeeds, and provider discovery satisfies the supplied policy.
    pub fn from_connection<Resolver>(
        connection: &ProviderConnection,
        resolver: &Resolver,
        policy: &MemoryProviderPolicy,
        request_prefix: Option<String>,
    ) -> Result<Self, ProviderError>
    where
        Resolver: SecretResolver + ?Sized,
    {
        if !matches!(
            connection.kind(),
            ProviderKind::Mem0 | ProviderKind::Supermemory
        ) || connection.endpoint().is_none()
            || connection.credentials().len() != 1
        {
            return Err(ProviderError::InvalidConfiguration(
                "portable semantic provider requires one endpoint and one credential reference"
                    .to_owned(),
            ));
        }
        let request_prefix = match request_prefix {
            Some(value) => validate_request_prefix(value)?,
            None => default_request_prefix()?,
        };
        let mut credentials = resolve_provider_credentials(resolver, connection).map_err(|_| {
            ProviderError::InvalidConfiguration(
                "portable semantic provider credential unavailable".to_owned(),
            )
        })?;
        let bearer_token = credentials.pop().ok_or_else(|| {
            ProviderError::InvalidConfiguration(
                "portable semantic provider credential unavailable".to_owned(),
            )
        })?;
        let client = HttpMemoryProviderClient::new_with_secret(
            connection.endpoint().ok_or_else(|| {
                ProviderError::InvalidConfiguration(
                    "portable semantic provider endpoint unavailable".to_owned(),
                )
            })?,
            bearer_token,
        )?;
        Self::from_client(Box::new(client), policy, request_prefix)
    }

    /// Negotiates and installs any transport implementing the portable client
    /// boundary.
    ///
    /// # Errors
    ///
    /// Returns a provider error when discovery fails or the transport's
    /// manifest does not satisfy the supplied policy.
    pub fn from_client(
        client: Box<dyn MemoryProviderClient>,
        policy: &MemoryProviderPolicy,
        request_prefix: String,
    ) -> Result<Self, ProviderError> {
        let connection = client.connect(policy, request_prefix)?;
        Ok(Self { client, connection })
    }

    #[must_use]
    pub fn client(&self) -> &dyn MemoryProviderClient {
        self.client.as_ref()
    }

    #[must_use]
    pub const fn connection(&self) -> &MemoryProviderConnection {
        &self.connection
    }

    pub fn resolve_context(
        &self,
        payload: ResolveContextPayload,
    ) -> Result<MemoryProviderResponse<ResolveContextResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.resolve_context(&request)
    }

    pub fn resolve_question(
        &self,
        payload: ResolveQuestionPayload,
    ) -> Result<MemoryProviderResponse<ResolveQuestionResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.resolve_question(&request)
    }

    pub fn propose_memory(
        &self,
        payload: ProposeMemoryPayload,
    ) -> Result<MemoryProviderResponse<ProposeMemoryResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.propose_memory(&request)
    }

    pub fn record_events(
        &self,
        payload: RecordEventPayload,
    ) -> Result<MemoryProviderResponse<RecordEventResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.record_events(&request)
    }

    pub fn checkpoint_activity(
        &self,
        payload: CheckpointActivityPayload,
    ) -> Result<MemoryProviderResponse<CheckpointActivityResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.checkpoint_activity(&request)
    }

    pub fn record_disclosure(
        &self,
        payload: RecordDisclosurePayload,
    ) -> Result<MemoryProviderResponse<RecordDisclosureResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.record_disclosure(&request)
    }

    pub fn delete_memory(
        &self,
        payload: DeleteMemoryPayload,
    ) -> Result<MemoryProviderResponse<DeleteMemoryResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.delete_memory(&request)
    }

    pub fn explain_memory(
        &self,
        payload: ExplainMemoryPayload,
    ) -> Result<MemoryProviderResponse<ExplainMemoryResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.explain_memory(&request)
    }

    pub fn sync_pull(
        &self,
        payload: SyncPullPayload,
    ) -> Result<MemoryProviderResponse<SyncPullResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.sync_pull(&request)
    }

    pub fn sync_push(
        &self,
        payload: SyncPushPayload,
    ) -> Result<MemoryProviderResponse<SyncPushResult>, ProviderError> {
        let request = self.connection.request(payload)?;
        self.client.sync_push(&request)
    }
}

fn required_environment(name: &str) -> Result<String, ProviderError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ProviderError::InvalidConfiguration(format!("{name} is required")))
}

fn configured_token_reference() -> Result<SecretReference, ProviderError> {
    match std::env::var("REMBRANE_MEMORY_PROVIDER_TOKEN_REFERENCE") {
        Ok(locator) => selected_token_reference(&locator),
        Err(std::env::VarError::NotPresent) => selected_token_reference(""),
        Err(_) => Err(provider_credential_unavailable()),
    }
}

fn selected_token_reference(locator: &str) -> Result<SecretReference, ProviderError> {
    if locator.is_empty() {
        SecretReference::environment("REMBRANE_MEMORY_PROVIDER_TOKEN")
            .map_err(|_| provider_credential_unavailable())
    } else {
        locator
            .parse()
            .map_err(|_| provider_credential_unavailable())
    }
}

fn provider_credential_unavailable() -> ProviderError {
    ProviderError::InvalidConfiguration("memory provider credential unavailable".to_owned())
}

fn validate_request_prefix(value: String) -> Result<String, ProviderError> {
    if !(8..=64).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ProviderError::InvalidConfiguration(
            "REMBRANE_MEMORY_PROVIDER_REQUEST_PREFIX must contain 8 to 64 URL-safe characters"
                .to_owned(),
        ));
    }
    Ok(value)
}

fn default_request_prefix() -> Result<String, ProviderError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProviderError::Unavailable)?
        .as_nanos();
    validate_request_prefix(format!("rembrane-{}-{timestamp}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use rembrane_config::{ProviderConnection, ProviderKind, ProviderPlacement, SecretReference};
    use rembrane_provider_sdk::{
        CURRENT_MEMORY_PROVIDER_PROTOCOL, MemoryProviderCapability, MemoryProviderLimits,
        MemoryProviderPolicy, MemoryProviderPrivacyMode, MemoryProviderTransport,
    };
    use rembrane_secret_local::{SecretResolutionError, SecretResolver};
    use zeroize::Zeroizing;

    use super::{
        ConfiguredMemoryProvider, MemoryProviderHttpConfig, default_request_prefix,
        selected_token_reference, validate_request_prefix,
    };

    struct RejectingResolver;

    impl SecretResolver for RejectingResolver {
        fn resolve(
            &self,
            _reference: &SecretReference,
        ) -> Result<Zeroizing<String>, SecretResolutionError> {
            Err(SecretResolutionError::Unavailable)
        }
    }

    fn minimal_policy() -> MemoryProviderPolicy {
        MemoryProviderPolicy::new(
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            MemoryProviderTransport::Https,
            vec![MemoryProviderCapability::ResolveContext],
            vec![MemoryProviderPrivacyMode::EndToEndEncrypted],
            MemoryProviderLimits {
                maximum_context_items: 1,
                maximum_context_bytes: 1,
                maximum_event_batch_items: 1,
                maximum_sync_batch_items: 1,
            },
        )
        .expect("policy")
    }

    #[test]
    fn validates_explicit_request_prefixes_without_secret_material() {
        assert_eq!(
            validate_request_prefix("coding-agent_01".to_owned()).expect("prefix"),
            "coding-agent_01"
        );
        assert!(validate_request_prefix("short".to_owned()).is_err());
        assert!(validate_request_prefix("tenant/name".to_owned()).is_err());
        assert!(validate_request_prefix("token value".to_owned()).is_err());
        assert!(validate_request_prefix(String::new()).is_err());
    }

    #[test]
    fn generates_safe_bounded_process_request_prefixes() {
        let prefix = default_request_prefix().expect("prefix");
        assert!(prefix.starts_with("rembrane-"));
        assert!((8..=64).contains(&prefix.len()));
        assert!(
            prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        );
    }

    #[test]
    fn memory_provider_token_reference_defaults_and_rejects_inline_values() {
        let default = selected_token_reference("").expect("default environment reference");
        assert_eq!(
            default.environment_variable(),
            Some("REMBRANE_MEMORY_PROVIDER_TOKEN")
        );
        let file = selected_token_reference("file:/run/secrets/memory-provider-token")
            .expect("file reference");
        assert_eq!(file.file_path(), Some("/run/secrets/memory-provider-token"));
        assert!(selected_token_reference("inline-token").is_err());
    }

    #[test]
    fn explicit_http_configuration_validates_before_discovery() {
        let result = ConfiguredMemoryProvider::from_http_config(
            MemoryProviderHttpConfig::new("https://memory.example.com", "synthetic-test-token")
                .with_request_prefix("contains tenant name"),
            &minimal_policy(),
        );
        let error = match result {
            Ok(_) => panic!("unsafe request prefix must fail before network access"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("must contain 8 to 64 URL-safe characters")
        );
    }

    #[test]
    fn explicit_http_configuration_reuses_transport_endpoint_validation() {
        let result = ConfiguredMemoryProvider::from_http_config(
            MemoryProviderHttpConfig::new("http://memory.example.com", "synthetic-test-token")
                .with_request_prefix("safe-client-01"),
            &minimal_policy(),
        );
        let error = match result {
            Ok(_) => panic!("remote plaintext HTTP must fail before discovery"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("HTTPS"));
    }

    #[test]
    fn validates_portable_profile_before_resolving_credential() {
        let graphiti = ProviderConnection::remote(
            ProviderKind::Graphiti,
            "https://graph.example.test",
            vec![SecretReference::environment("GRAPH_TOKEN").expect("reference")],
            ProviderPlacement::External,
        )
        .expect("profile");
        assert!(
            ConfiguredMemoryProvider::from_connection(
                &graphiti,
                &RejectingResolver,
                &minimal_policy(),
                Some("safe-client-01".to_owned()),
            )
            .is_err()
        );

        let mem0 = ProviderConnection::remote(
            ProviderKind::Mem0,
            "https://memory.example.test",
            vec![SecretReference::external("vault", "memory/token").expect("reference")],
            ProviderPlacement::External,
        )
        .expect("profile");
        let error = match ConfiguredMemoryProvider::from_connection(
            &mem0,
            &RejectingResolver,
            &minimal_policy(),
            Some("safe-client-01".to_owned()),
        ) {
            Ok(_) => panic!("resolver failure must remain opaque"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "invalid provider configuration: portable semantic provider credential unavailable"
        );
    }
}

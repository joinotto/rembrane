//! Deployment-selected local or customer-controlled record encryption.

use std::time::{SystemTime, UNIX_EPOCH};

use rembrane_config::{ProviderConnection, ProviderKind, SecretReference};
use rembrane_crypto::{
    CURRENT_KEY_PROVIDER_PROTOCOL, CryptoError, EncryptedPayload, EncryptionContext,
    KeyProviderCipher, KeyProviderPolicy, RecordCipher,
};
use rembrane_crypto_rustcrypto::RustCryptoKeyringCipher;
use rembrane_domain::{KeyRotationReceipt, PrincipalId, WorkspaceId};
use rembrane_key_provider_http::HttpKeyProviderTransport;
use rembrane_secret_local::{LocalSecretResolver, SecretResolver, resolve_provider_credentials};
use zeroize::Zeroizing;

const DEFAULT_ALGORITHM: &str = "xchacha20poly1305-ietf";
const DEFAULT_MINIMUM_PLAINTEXT_BYTES: usize = 262_144;

pub enum ConfiguredRecordCipher {
    Local(RustCryptoKeyringCipher),
    Http(Box<KeyProviderCipher<HttpKeyProviderTransport>>),
}

/// Deployment-owned values for a customer-controlled HTTP key provider.
///
/// This consumed type intentionally omits cloning, debug formatting, and
/// serialization. Its bearer credential is wiped when construction succeeds
/// or fails.
pub struct KeyProviderHttpConfig {
    base_url: String,
    bearer_token: Zeroizing<String>,
    algorithm: String,
    minimum_plaintext_bytes: usize,
    require_historical_keys: bool,
    request_prefix: Option<String>,
}

impl KeyProviderHttpConfig {
    #[must_use]
    pub fn new(base_url: impl Into<String>, bearer_token: impl Into<String>) -> Self {
        Self::new_with_secret(base_url, Zeroizing::new(bearer_token.into()))
    }

    #[must_use]
    pub fn new_with_secret(base_url: impl Into<String>, bearer_token: Zeroizing<String>) -> Self {
        Self {
            base_url: base_url.into(),
            bearer_token,
            algorithm: DEFAULT_ALGORITHM.to_owned(),
            minimum_plaintext_bytes: DEFAULT_MINIMUM_PLAINTEXT_BYTES,
            require_historical_keys: true,
            request_prefix: None,
        }
    }

    #[must_use]
    pub fn with_algorithm(mut self, algorithm: impl Into<String>) -> Self {
        self.algorithm = algorithm.into();
        self
    }

    #[must_use]
    pub const fn with_minimum_plaintext_bytes(mut self, minimum_plaintext_bytes: usize) -> Self {
        self.minimum_plaintext_bytes = minimum_plaintext_bytes;
        self
    }

    #[must_use]
    pub const fn require_historical_keys(mut self, required: bool) -> Self {
        self.require_historical_keys = required;
        self
    }

    #[must_use]
    pub fn with_request_prefix(mut self, request_prefix: impl Into<String>) -> Self {
        self.request_prefix = Some(request_prefix.into());
        self
    }
}

impl ConfiguredRecordCipher {
    /// Loads the selected encryption provider without placing key material in
    /// application configuration.
    ///
    /// Supported values for `REMBRANE_KEY_PROVIDER` are `environment`,
    /// `macos-keychain`, `linux-secret-service`, `windows-dpapi`, and `http`.
    /// The HTTP provider requires `REMBRANE_KEY_PROVIDER_BASE_URL` and
    /// `REMBRANE_KEY_PROVIDER_TOKEN` or its reference locator.
    ///
    /// # Errors
    ///
    /// Returns key-unavailable for missing, malformed, unsupported, or
    /// policy-incompatible provider configuration.
    pub fn from_environment() -> Result<Self, CryptoError> {
        let provider =
            std::env::var("REMBRANE_KEY_PROVIDER").unwrap_or_else(|_| "environment".to_owned());
        match provider.as_str() {
            "environment" | "macos-keychain" | "linux-secret-service" | "windows-dpapi" => {
                RustCryptoKeyringCipher::from_configured_provider().map(Self::Local)
            }
            "http" => Self::http_from_environment(),
            _ => Err(CryptoError::KeyUnavailable),
        }
    }

    fn http_from_environment() -> Result<Self, CryptoError> {
        let endpoint = required_environment("REMBRANE_KEY_PROVIDER_BASE_URL")?;
        let token_reference = configured_token_reference()?;
        let token = LocalSecretResolver
            .resolve(&token_reference)
            .map_err(|_| CryptoError::KeyUnavailable)?;
        let algorithm = std::env::var("REMBRANE_KEY_PROVIDER_ALGORITHM")
            .unwrap_or_else(|_| DEFAULT_ALGORITHM.to_owned());
        if algorithm.trim().is_empty() || algorithm.trim() != algorithm {
            return Err(CryptoError::KeyUnavailable);
        }
        let minimum_plaintext_bytes =
            std::env::var("REMBRANE_KEY_PROVIDER_MINIMUM_PLAINTEXT_BYTES")
                .ok()
                .map_or(Ok(DEFAULT_MINIMUM_PLAINTEXT_BYTES), |value| {
                    value
                        .parse::<usize>()
                        .ok()
                        .filter(|size| *size > 0)
                        .ok_or(CryptoError::KeyUnavailable)
                })?;
        let require_historical_keys =
            match std::env::var("REMBRANE_KEY_PROVIDER_REQUIRE_HISTORICAL_KEYS")
                .as_deref()
                .unwrap_or("true")
            {
                "true" => true,
                "false" => false,
                _ => return Err(CryptoError::KeyUnavailable),
            };
        let request_prefix = std::env::var("REMBRANE_KEY_PROVIDER_REQUEST_PREFIX").ok();
        let config = KeyProviderHttpConfig::new_with_secret(endpoint, token)
            .with_algorithm(algorithm)
            .with_minimum_plaintext_bytes(minimum_plaintext_bytes)
            .require_historical_keys(require_historical_keys);
        let config = match request_prefix {
            Some(value) => config.with_request_prefix(value),
            None => config,
        };
        Self::from_http_config(config)
    }

    /// Connects to a customer-controlled key provider using values resolved by
    /// application-owned configuration and secret-management code.
    ///
    /// # Errors
    ///
    /// Returns key-unavailable when configuration, transport construction,
    /// discovery, or policy negotiation fails.
    pub fn from_http_config(mut config: KeyProviderHttpConfig) -> Result<Self, CryptoError> {
        if config.algorithm.trim().is_empty()
            || config.algorithm.trim() != config.algorithm
            || config.minimum_plaintext_bytes == 0
        {
            return Err(CryptoError::KeyUnavailable);
        }
        let request_prefix = match config.request_prefix.take() {
            Some(value) => value,
            None => default_request_prefix()?,
        };
        let token = std::mem::take(&mut config.bearer_token);
        let transport = HttpKeyProviderTransport::new_with_secret(&config.base_url, token)?;
        let cipher = KeyProviderCipher::connect(
            transport,
            KeyProviderPolicy {
                minimum_protocol_version: CURRENT_KEY_PROVIDER_PROTOCOL,
                required_algorithm: config.algorithm.clone(),
                minimum_plaintext_bytes: config.minimum_plaintext_bytes,
                require_historical_keys: config.require_historical_keys,
                require_rotation: false,
            },
            request_prefix,
        )?;
        Ok(Self::Http(Box::new(cipher)))
    }

    /// Connects to a customer-controlled key provider from a validated
    /// reference-only profile through a deployment-selected resolver.
    ///
    /// # Errors
    ///
    /// Returns key-unavailable unless the profile selects one key-provider
    /// endpoint and one credential reference, resolution succeeds, and
    /// protocol discovery satisfies the requested cryptographic policy.
    pub fn from_connection<Resolver>(
        connection: &ProviderConnection,
        resolver: &Resolver,
        algorithm: String,
        minimum_plaintext_bytes: usize,
        require_historical_keys: bool,
        request_prefix: Option<String>,
    ) -> Result<Self, CryptoError>
    where
        Resolver: SecretResolver + ?Sized,
    {
        if connection.kind() != ProviderKind::KeyProvider
            || connection.endpoint().is_none()
            || connection.credentials().len() != 1
            || algorithm.trim().is_empty()
            || algorithm.trim() != algorithm
            || minimum_plaintext_bytes == 0
        {
            return Err(CryptoError::KeyUnavailable);
        }
        let request_prefix = match request_prefix {
            Some(value) => value,
            None => default_request_prefix()?,
        };
        let mut credentials = resolve_provider_credentials(resolver, connection)
            .map_err(|_| CryptoError::KeyUnavailable)?;
        let bearer_token = credentials.pop().ok_or(CryptoError::KeyUnavailable)?;
        let transport = HttpKeyProviderTransport::new_with_secret(
            connection.endpoint().ok_or(CryptoError::KeyUnavailable)?,
            bearer_token,
        )?;
        let cipher = KeyProviderCipher::connect(
            transport,
            KeyProviderPolicy {
                minimum_protocol_version: CURRENT_KEY_PROVIDER_PROTOCOL,
                required_algorithm: algorithm,
                minimum_plaintext_bytes,
                require_historical_keys,
                require_rotation: false,
            },
            request_prefix,
        )?;
        Ok(Self::Http(Box::new(cipher)))
    }

    /// Requests a shared-workspace key rotation from the configured
    /// customer-controlled provider.
    ///
    /// Local keyrings do not yet implement group-recipient rotation and fail
    /// closed rather than manufacturing a receipt.
    pub fn rotate_workspace_key(
        &self,
        workspace_id: WorkspaceId,
        generation: u64,
        recipient_ids: Vec<PrincipalId>,
    ) -> Result<KeyRotationReceipt, CryptoError> {
        match self {
            Self::Http(cipher) => cipher.rotate(workspace_id, generation, recipient_ids),
            Self::Local(_) => Err(CryptoError::KeyUnavailable),
        }
    }
}

impl RecordCipher for ConfiguredRecordCipher {
    fn seal(
        &self,
        context: &EncryptionContext,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, CryptoError> {
        match self {
            Self::Local(cipher) => cipher.seal(context, plaintext),
            Self::Http(cipher) => cipher.seal(context, plaintext),
        }
    }

    fn open(
        &self,
        context: &EncryptionContext,
        payload: &EncryptedPayload,
    ) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::Local(cipher) => cipher.open(context, payload),
            Self::Http(cipher) => cipher.open(context, payload),
        }
    }
}

fn required_environment(name: &str) -> Result<String, CryptoError> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(CryptoError::KeyUnavailable)
}

fn configured_token_reference() -> Result<SecretReference, CryptoError> {
    match std::env::var("REMBRANE_KEY_PROVIDER_TOKEN_REFERENCE") {
        Ok(locator) => selected_token_reference(&locator),
        Err(std::env::VarError::NotPresent) => selected_token_reference(""),
        Err(_) => Err(CryptoError::KeyUnavailable),
    }
}

fn selected_token_reference(locator: &str) -> Result<SecretReference, CryptoError> {
    if locator.is_empty() {
        SecretReference::environment("REMBRANE_KEY_PROVIDER_TOKEN")
            .map_err(|_| CryptoError::KeyUnavailable)
    } else {
        locator.parse().map_err(|_| CryptoError::KeyUnavailable)
    }
}

fn default_request_prefix() -> Result<String, CryptoError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CryptoError::KeyUnavailable)?
        .as_nanos();
    Ok(format!("rembrane-{}-{timestamp}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use rembrane_config::{ProviderConnection, ProviderKind, ProviderPlacement, SecretReference};
    use rembrane_secret_local::{SecretResolutionError, SecretResolver};
    use zeroize::Zeroizing;

    use super::{
        ConfiguredRecordCipher, DEFAULT_MINIMUM_PLAINTEXT_BYTES, KeyProviderHttpConfig,
        default_request_prefix, selected_token_reference,
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

    #[test]
    fn generated_request_prefix_is_nonempty_and_bounded() {
        let prefix = default_request_prefix().expect("system clock should provide a prefix");
        assert!(prefix.starts_with("rembrane-"));
        assert!(prefix.len() <= 200);
        assert!(
            prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        );
    }

    #[test]
    fn default_plaintext_policy_covers_canonical_records() {
        assert_eq!(DEFAULT_MINIMUM_PLAINTEXT_BYTES, 262_144);
    }

    #[test]
    fn key_provider_token_reference_defaults_and_rejects_inline_values() {
        let default = selected_token_reference("").expect("default environment reference");
        assert_eq!(
            default.environment_variable(),
            Some("REMBRANE_KEY_PROVIDER_TOKEN")
        );
        let file = selected_token_reference("file:/run/secrets/key-provider-token")
            .expect("file reference");
        assert_eq!(file.file_path(), Some("/run/secrets/key-provider-token"));
        assert!(selected_token_reference("inline-token").is_err());
    }

    #[test]
    fn explicit_http_configuration_rejects_invalid_policy_before_discovery() {
        let result = ConfiguredRecordCipher::from_http_config(
            KeyProviderHttpConfig::new("https://keys.example.test", "synthetic-token")
                .with_minimum_plaintext_bytes(0),
        );
        assert!(matches!(
            result,
            Err(rembrane_crypto::CryptoError::KeyUnavailable)
        ));
    }

    #[test]
    fn explicit_http_configuration_reuses_secure_endpoint_validation() {
        let result = ConfiguredRecordCipher::from_http_config(
            KeyProviderHttpConfig::new("http://keys.example.test", "synthetic-token")
                .with_request_prefix("safe-client-01"),
        );
        assert!(matches!(
            result,
            Err(rembrane_crypto::CryptoError::KeyUnavailable)
        ));
    }

    #[test]
    fn reference_profile_is_validated_before_secret_resolution() {
        let wrong_kind = ProviderConnection::remote(
            ProviderKind::Graphiti,
            "https://keys.example.test",
            vec![SecretReference::environment("KEY_PROVIDER_TOKEN").expect("reference")],
            ProviderPlacement::External,
        )
        .expect("profile");
        assert!(
            ConfiguredRecordCipher::from_connection(
                &wrong_kind,
                &PanicResolver,
                "xchacha20poly1305-ietf".to_owned(),
                DEFAULT_MINIMUM_PLAINTEXT_BYTES,
                true,
                Some("safe-client-01".to_owned()),
            )
            .is_err()
        );

        let key_provider = ProviderConnection::remote(
            ProviderKind::KeyProvider,
            "https://keys.example.test",
            vec![SecretReference::environment("KEY_PROVIDER_TOKEN").expect("reference")],
            ProviderPlacement::External,
        )
        .expect("profile");
        assert!(
            ConfiguredRecordCipher::from_connection(
                &key_provider,
                &PanicResolver,
                String::new(),
                DEFAULT_MINIMUM_PLAINTEXT_BYTES,
                true,
                Some("safe-client-01".to_owned()),
            )
            .is_err()
        );
    }
}

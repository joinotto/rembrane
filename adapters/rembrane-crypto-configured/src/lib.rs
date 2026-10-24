//! Deployment-selected local or customer-controlled record encryption.

use std::time::{SystemTime, UNIX_EPOCH};

use rembrane_crypto::{
    CURRENT_KEY_PROVIDER_PROTOCOL, CryptoError, EncryptedPayload, EncryptionContext,
    KeyProviderCipher, KeyProviderPolicy, RecordCipher,
};
use rembrane_crypto_rustcrypto::RustCryptoKeyringCipher;
use rembrane_domain::{KeyRotationReceipt, PrincipalId, WorkspaceId};
use rembrane_key_provider_http::HttpKeyProviderTransport;
use zeroize::Zeroize;

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
    bearer_token: String,
    algorithm: String,
    minimum_plaintext_bytes: usize,
    require_historical_keys: bool,
    request_prefix: Option<String>,
}

impl KeyProviderHttpConfig {
    #[must_use]
    pub fn new(base_url: impl Into<String>, bearer_token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            bearer_token: bearer_token.into(),
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

impl Drop for KeyProviderHttpConfig {
    fn drop(&mut self) {
        self.bearer_token.zeroize();
    }
}

impl ConfiguredRecordCipher {
    /// Loads the selected encryption provider without placing key material in
    /// application configuration.
    ///
    /// Supported values for `REMBRANE_KEY_PROVIDER` are `environment`,
    /// `macos-keychain`, `linux-secret-service`, and `http`. The HTTP provider requires
    /// `REMBRANE_KEY_PROVIDER_BASE_URL` and `REMBRANE_KEY_PROVIDER_TOKEN`.
    ///
    /// # Errors
    ///
    /// Returns key-unavailable for missing, malformed, unsupported, or
    /// policy-incompatible provider configuration.
    pub fn from_environment() -> Result<Self, CryptoError> {
        let provider =
            std::env::var("REMBRANE_KEY_PROVIDER").unwrap_or_else(|_| "environment".to_owned());
        match provider.as_str() {
            "environment" | "macos-keychain" | "linux-secret-service" => {
                RustCryptoKeyringCipher::from_configured_provider().map(Self::Local)
            }
            "http" => Self::http_from_environment(),
            _ => Err(CryptoError::KeyUnavailable),
        }
    }

    fn http_from_environment() -> Result<Self, CryptoError> {
        let endpoint = required_environment("REMBRANE_KEY_PROVIDER_BASE_URL")?;
        let token = required_environment("REMBRANE_KEY_PROVIDER_TOKEN")?;
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
        let config = KeyProviderHttpConfig::new(endpoint, token)
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
        let transport = HttpKeyProviderTransport::new(&config.base_url, token)?;
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

fn default_request_prefix() -> Result<String, CryptoError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CryptoError::KeyUnavailable)?
        .as_nanos();
    Ok(format!("rembrane-{}-{timestamp}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::{
        ConfiguredRecordCipher, DEFAULT_MINIMUM_PLAINTEXT_BYTES, KeyProviderHttpConfig,
        default_request_prefix,
    };

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
}

use std::error::Error;
use std::fmt::{self, Display};

use crate::{EncryptedPayload, EncryptionContext};

pub const CURRENT_KEY_PROVIDER_PROTOCOL: KeyProviderProtocolVersion =
    KeyProviderProtocolVersion::new(0, 1);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct KeyProviderProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl KeyProviderProtocolVersion {
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    #[must_use]
    pub const fn is_compatible_with(self, required: Self) -> bool {
        self.major == required.major && self.minor >= required.minor
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyProviderManifest {
    pub provider_id: String,
    pub protocol_version: KeyProviderProtocolVersion,
    pub algorithms: Vec<String>,
    pub maximum_plaintext_bytes: usize,
    pub supports_historical_keys: bool,
}

impl KeyProviderManifest {
    pub fn validate(&self) -> Result<(), KeyProviderProtocolError> {
        if self.provider_id.len() < 2
            || self.provider_id.len() > 255
            || !self.provider_id.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
            })
        {
            return Err(KeyProviderProtocolError::InvalidManifest);
        }
        if self.algorithms.is_empty()
            || self.algorithms.iter().any(|algorithm| {
                algorithm.trim().is_empty()
                    || algorithm.trim() != algorithm
                    || algorithm.len() > 100
            })
            || self
                .algorithms
                .iter()
                .enumerate()
                .any(|(index, algorithm)| self.algorithms[..index].contains(algorithm))
            || self.maximum_plaintext_bytes == 0
        {
            return Err(KeyProviderProtocolError::InvalidManifest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyProviderPolicy {
    pub minimum_protocol_version: KeyProviderProtocolVersion,
    pub required_algorithm: String,
    pub minimum_plaintext_bytes: usize,
    pub require_historical_keys: bool,
}

impl KeyProviderPolicy {
    pub fn validate(&self, manifest: &KeyProviderManifest) -> Result<(), KeyProviderProtocolError> {
        manifest.validate()?;
        if self.required_algorithm.trim().is_empty() || self.minimum_plaintext_bytes == 0 {
            return Err(KeyProviderProtocolError::InvalidPolicy);
        }
        if !manifest
            .protocol_version
            .is_compatible_with(self.minimum_protocol_version)
        {
            return Err(KeyProviderProtocolError::IncompatibleProtocol);
        }
        if !manifest.algorithms.contains(&self.required_algorithm) {
            return Err(KeyProviderProtocolError::UnsupportedAlgorithm);
        }
        if manifest.maximum_plaintext_bytes < self.minimum_plaintext_bytes {
            return Err(KeyProviderProtocolError::LimitTooSmall);
        }
        if self.require_historical_keys && !manifest.supports_historical_keys {
            return Err(KeyProviderProtocolError::HistoricalKeysRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealRequest {
    request_id: String,
    context: EncryptionContext,
    plaintext: Vec<u8>,
}

impl SealRequest {
    pub fn new(
        request_id: impl Into<String>,
        context: EncryptionContext,
        plaintext: Vec<u8>,
        maximum_plaintext_bytes: usize,
    ) -> Result<Self, KeyProviderProtocolError> {
        let request_id = request_id.into();
        validate_request_id(&request_id)?;
        validate_plaintext_size(plaintext.len(), maximum_plaintext_bytes)?;
        Ok(Self {
            request_id,
            context,
            plaintext,
        })
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub const fn context(&self) -> &EncryptionContext {
        &self.context
    }

    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenRequest {
    request_id: String,
    context: EncryptionContext,
    envelope: EncryptedPayload,
}

impl OpenRequest {
    pub fn new(
        request_id: impl Into<String>,
        context: EncryptionContext,
        envelope: EncryptedPayload,
    ) -> Result<Self, KeyProviderProtocolError> {
        let request_id = request_id.into();
        validate_request_id(&request_id)?;
        Ok(Self {
            request_id,
            context,
            envelope,
        })
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub const fn context(&self) -> &EncryptionContext {
        &self.context
    }

    #[must_use]
    pub const fn envelope(&self) -> &EncryptedPayload {
        &self.envelope
    }

    pub fn validate_plaintext_response(
        &self,
        plaintext: &[u8],
        maximum_plaintext_bytes: usize,
    ) -> Result<(), KeyProviderProtocolError> {
        validate_plaintext_size(plaintext.len(), maximum_plaintext_bytes)
    }
}

fn validate_request_id(request_id: &str) -> Result<(), KeyProviderProtocolError> {
    if request_id.trim().is_empty() || request_id.trim() != request_id || request_id.len() > 255 {
        return Err(KeyProviderProtocolError::InvalidRequest);
    }
    Ok(())
}

fn validate_plaintext_size(
    size: usize,
    maximum_plaintext_bytes: usize,
) -> Result<(), KeyProviderProtocolError> {
    if maximum_plaintext_bytes == 0 || size > maximum_plaintext_bytes {
        return Err(KeyProviderProtocolError::PlaintextTooLarge);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyProviderProtocolError {
    HistoricalKeysRequired,
    IncompatibleProtocol,
    InvalidManifest,
    InvalidPolicy,
    InvalidRequest,
    LimitTooSmall,
    PlaintextTooLarge,
    UnsupportedAlgorithm,
}

impl Display for KeyProviderProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::HistoricalKeysRequired => "key provider must support historical keys",
            Self::IncompatibleProtocol => "key provider protocol is incompatible",
            Self::InvalidManifest => "key provider manifest is invalid",
            Self::InvalidPolicy => "key provider policy is invalid",
            Self::InvalidRequest => "key provider request is invalid",
            Self::LimitTooSmall => "key provider plaintext limit is too small",
            Self::PlaintextTooLarge => "plaintext exceeds the key provider limit",
            Self::UnsupportedAlgorithm => "required encryption algorithm is unsupported",
        })
    }
}

impl Error for KeyProviderProtocolError {}

#[cfg(test)]
mod tests {
    use rembrane_domain::WorkspaceId;

    use super::{
        CURRENT_KEY_PROVIDER_PROTOCOL, KeyProviderManifest, KeyProviderPolicy,
        KeyProviderProtocolError, KeyProviderProtocolVersion, SealRequest,
    };
    use crate::{EncryptionContext, PayloadPurpose};

    fn manifest() -> KeyProviderManifest {
        KeyProviderManifest {
            provider_id: "rembrane.test-key-provider".to_owned(),
            protocol_version: CURRENT_KEY_PROVIDER_PROTOCOL,
            algorithms: vec!["xchacha20poly1305-ietf".to_owned()],
            maximum_plaintext_bytes: 262_144,
            supports_historical_keys: true,
        }
    }

    fn context() -> EncryptionContext {
        EncryptionContext::new(
            WorkspaceId::new("workspace_01"),
            "memory_01",
            1,
            PayloadPurpose::MemoryContent,
        )
        .expect("context should be valid")
    }

    #[test]
    fn negotiates_protocol_algorithm_limits_and_history() {
        let policy = KeyProviderPolicy {
            minimum_protocol_version: CURRENT_KEY_PROVIDER_PROTOCOL,
            required_algorithm: "xchacha20poly1305-ietf".to_owned(),
            minimum_plaintext_bytes: 262_144,
            require_historical_keys: true,
        };
        assert_eq!(policy.validate(&manifest()), Ok(()));

        let mut incompatible = manifest();
        incompatible.protocol_version = KeyProviderProtocolVersion::new(1, 0);
        assert_eq!(
            policy.validate(&incompatible),
            Err(KeyProviderProtocolError::IncompatibleProtocol)
        );
    }

    #[test]
    fn rejects_duplicate_algorithms_and_oversized_plaintext() {
        let mut invalid = manifest();
        invalid.algorithms.push("xchacha20poly1305-ietf".to_owned());
        assert_eq!(
            invalid.validate(),
            Err(KeyProviderProtocolError::InvalidManifest)
        );
        assert_eq!(
            SealRequest::new("request_01", context(), vec![0; 5], 4),
            Err(KeyProviderProtocolError::PlaintextTooLarge)
        );
    }

    #[test]
    fn binds_request_to_the_complete_encryption_context() {
        let request = SealRequest::new("request_01", context(), b"secret".to_vec(), 10)
            .expect("request should be valid");

        assert_eq!(request.context().workspace_id().as_str(), "workspace_01");
        assert_eq!(request.context().record_id(), "memory_01");
        assert_eq!(request.context().record_version(), 1);
        assert_eq!(request.context().purpose(), PayloadPurpose::MemoryContent);
        assert_eq!(request.plaintext(), b"secret");
    }
}

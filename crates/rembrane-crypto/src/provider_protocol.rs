use std::error::Error;
use std::fmt::{self, Display};
use std::sync::atomic::{AtomicU64, Ordering};

use rembrane_domain::{KeyRotationReceipt, MAX_KEY_ROTATION_RECIPIENTS, PrincipalId, WorkspaceId};

use crate::{CryptoError, EncryptedPayload, EncryptionContext, RecordCipher};

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
    pub supports_rotation: bool,
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
    pub require_rotation: bool,
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
        if self.require_rotation && !manifest.supports_rotation {
            return Err(KeyProviderProtocolError::RotationRequired);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotateKeyRequest {
    request_id: String,
    workspace_id: WorkspaceId,
    generation: u64,
    recipient_ids: Vec<PrincipalId>,
}

impl RotateKeyRequest {
    pub fn new(
        request_id: impl Into<String>,
        workspace_id: WorkspaceId,
        generation: u64,
        mut recipient_ids: Vec<PrincipalId>,
    ) -> Result<Self, KeyProviderProtocolError> {
        let request_id = request_id.into();
        validate_request_id(&request_id)?;
        if workspace_id.as_str().is_empty()
            || generation == 0
            || recipient_ids.is_empty()
            || recipient_ids.len() > MAX_KEY_ROTATION_RECIPIENTS
            || recipient_ids
                .iter()
                .any(|recipient| recipient.as_str().is_empty())
        {
            return Err(KeyProviderProtocolError::InvalidRequest);
        }
        recipient_ids.sort();
        if recipient_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(KeyProviderProtocolError::InvalidRequest);
        }
        Ok(Self {
            request_id,
            workspace_id,
            generation,
            recipient_ids,
        })
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn recipient_ids(&self) -> &[PrincipalId] {
        &self.recipient_ids
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
    RotationRequired,
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
            Self::RotationRequired => "key provider must support workspace key rotation",
            Self::UnsupportedAlgorithm => "required encryption algorithm is unsupported",
        })
    }
}

impl Error for KeyProviderProtocolError {}

pub trait KeyProviderTransport {
    fn fetch_manifest(&self) -> Result<KeyProviderManifest, CryptoError>;

    fn seal(&self, request: &SealRequest) -> Result<EncryptedPayload, CryptoError>;

    fn open(&self, request: &OpenRequest) -> Result<Vec<u8>, CryptoError>;

    fn rotate(&self, _request: &RotateKeyRequest) -> Result<KeyRotationReceipt, CryptoError> {
        Err(CryptoError::KeyUnavailable)
    }
}

pub struct KeyProviderCipher<Transport> {
    transport: Transport,
    manifest: KeyProviderManifest,
    required_algorithm: String,
    request_prefix: String,
    next_request: AtomicU64,
}

impl<Transport: KeyProviderTransport> KeyProviderCipher<Transport> {
    pub fn connect(
        transport: Transport,
        policy: KeyProviderPolicy,
        request_prefix: impl Into<String>,
    ) -> Result<Self, CryptoError> {
        let request_prefix = request_prefix.into();
        validate_request_id(&request_prefix).map_err(protocol_error)?;
        if request_prefix.len() > 200 {
            return Err(CryptoError::InvalidEnvelope);
        }
        let manifest = transport.fetch_manifest()?;
        policy.validate(&manifest).map_err(protocol_error)?;
        Ok(Self {
            transport,
            manifest,
            required_algorithm: policy.required_algorithm,
            request_prefix,
            next_request: AtomicU64::new(1),
        })
    }

    #[must_use]
    pub const fn manifest(&self) -> &KeyProviderManifest {
        &self.manifest
    }

    fn request_id(&self, operation: &str) -> Result<String, CryptoError> {
        let mut current = self.next_request.load(Ordering::Relaxed);
        loop {
            let next = current.checked_add(1).ok_or(CryptoError::KeyUnavailable)?;
            match self.next_request.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(format!("{}-{operation}-{current}", self.request_prefix)),
                Err(observed) => current = observed,
            }
        }
    }

    pub fn rotate(
        &self,
        workspace_id: WorkspaceId,
        generation: u64,
        recipient_ids: Vec<PrincipalId>,
    ) -> Result<KeyRotationReceipt, CryptoError> {
        if !self.manifest.supports_rotation {
            return Err(CryptoError::KeyUnavailable);
        }
        let request = RotateKeyRequest::new(
            self.request_id("rotate")?,
            workspace_id,
            generation,
            recipient_ids,
        )
        .map_err(protocol_error)?;
        let receipt = self.transport.rotate(&request)?;
        if receipt.provider_id().as_str() != self.manifest.provider_id
            || receipt.request_id() != request.request_id()
            || receipt.workspace_id() != request.workspace_id()
            || receipt.generation() != request.generation()
            || receipt.recipient_ids() != request.recipient_ids()
        {
            return Err(CryptoError::InvalidEnvelope);
        }
        Ok(receipt)
    }
}

impl<Transport: KeyProviderTransport> RecordCipher for KeyProviderCipher<Transport> {
    fn seal(
        &self,
        context: &EncryptionContext,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, CryptoError> {
        let request = SealRequest::new(
            self.request_id("seal")?,
            context.clone(),
            plaintext.to_vec(),
            self.manifest.maximum_plaintext_bytes,
        )
        .map_err(protocol_error)?;
        let envelope = self.transport.seal(&request)?;
        if envelope.algorithm() != self.required_algorithm
            || !self
                .manifest
                .algorithms
                .iter()
                .any(|algorithm| algorithm == envelope.algorithm())
        {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        Ok(envelope)
    }

    fn open(
        &self,
        context: &EncryptionContext,
        payload: &EncryptedPayload,
    ) -> Result<Vec<u8>, CryptoError> {
        if payload.algorithm() != self.required_algorithm {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        let request = OpenRequest::new(self.request_id("open")?, context.clone(), payload.clone())
            .map_err(protocol_error)?;
        let plaintext = self.transport.open(&request)?;
        request
            .validate_plaintext_response(&plaintext, self.manifest.maximum_plaintext_bytes)
            .map_err(protocol_error)?;
        Ok(plaintext)
    }
}

fn protocol_error(error: KeyProviderProtocolError) -> CryptoError {
    match error {
        KeyProviderProtocolError::UnsupportedAlgorithm => CryptoError::UnsupportedAlgorithm,
        KeyProviderProtocolError::InvalidRequest | KeyProviderProtocolError::PlaintextTooLarge => {
            CryptoError::InvalidEnvelope
        }
        KeyProviderProtocolError::HistoricalKeysRequired
        | KeyProviderProtocolError::IncompatibleProtocol
        | KeyProviderProtocolError::InvalidManifest
        | KeyProviderProtocolError::InvalidPolicy
        | KeyProviderProtocolError::LimitTooSmall
        | KeyProviderProtocolError::RotationRequired => CryptoError::KeyUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use rembrane_domain::{KeyRotationReceipt, PrincipalId, ProviderId, WorkspaceId};

    use super::{
        CURRENT_KEY_PROVIDER_PROTOCOL, KeyProviderCipher, KeyProviderManifest, KeyProviderPolicy,
        KeyProviderProtocolError, KeyProviderProtocolVersion, KeyProviderTransport, OpenRequest,
        RotateKeyRequest, SealRequest,
    };
    use crate::{CryptoError, EncryptedPayload, EncryptionContext, PayloadPurpose, RecordCipher};

    fn manifest() -> KeyProviderManifest {
        KeyProviderManifest {
            provider_id: "rembrane.test-key-provider".to_owned(),
            protocol_version: CURRENT_KEY_PROVIDER_PROTOCOL,
            algorithms: vec!["xchacha20poly1305-ietf".to_owned()],
            maximum_plaintext_bytes: 262_144,
            supports_historical_keys: true,
            supports_rotation: true,
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
            require_rotation: false,
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

    struct FakeTransport {
        manifest: KeyProviderManifest,
        open_response: Vec<u8>,
    }

    impl KeyProviderTransport for FakeTransport {
        fn fetch_manifest(&self) -> Result<KeyProviderManifest, CryptoError> {
            Ok(self.manifest.clone())
        }

        fn seal(&self, request: &SealRequest) -> Result<EncryptedPayload, CryptoError> {
            EncryptedPayload::new(
                request.plaintext().to_vec(),
                "key_v1",
                "xchacha20poly1305-ietf",
                vec![7; 24],
            )
        }

        fn open(&self, request: &OpenRequest) -> Result<Vec<u8>, CryptoError> {
            assert_eq!(request.context().workspace_id().as_str(), "workspace_01");
            Ok(self.open_response.clone())
        }

        fn rotate(&self, request: &RotateKeyRequest) -> Result<KeyRotationReceipt, CryptoError> {
            KeyRotationReceipt::new(
                ProviderId::new(self.manifest.provider_id.clone()),
                request.request_id(),
                request.workspace_id().clone(),
                request.generation(),
                format!("key_v{}", request.generation()),
                request.recipient_ids().to_vec(),
            )
            .map_err(|_| CryptoError::InvalidEnvelope)
        }
    }

    fn connected(open_response: Vec<u8>) -> KeyProviderCipher<FakeTransport> {
        KeyProviderCipher::connect(
            FakeTransport {
                manifest: manifest(),
                open_response,
            },
            KeyProviderPolicy {
                minimum_protocol_version: CURRENT_KEY_PROVIDER_PROTOCOL,
                required_algorithm: "xchacha20poly1305-ietf".to_owned(),
                minimum_plaintext_bytes: 10,
                require_historical_keys: true,
                require_rotation: false,
            },
            "test-client",
        )
        .expect("compatible provider should connect")
    }

    #[test]
    fn provider_cipher_negotiates_then_seals_and_opens() {
        let cipher = connected(b"opened".to_vec());
        let envelope = cipher
            .seal(&context(), b"sealed")
            .expect("bounded plaintext should seal");
        assert_eq!(envelope.key_id(), "key_v1");
        assert_eq!(
            cipher
                .open(&context(), &envelope)
                .expect("provider response should open"),
            b"opened"
        );
    }

    #[test]
    fn provider_cipher_rotates_for_exact_workspace_generation_and_recipients() {
        let cipher = connected(Vec::new());
        let receipt = cipher
            .rotate(
                WorkspaceId::new("workspace_01"),
                2,
                vec![PrincipalId::new("owner"), PrincipalId::new("member")],
            )
            .expect("rotation-capable provider should return a correlated receipt");

        assert_eq!(receipt.provider_id().as_str(), "rembrane.test-key-provider");
        assert_eq!(receipt.generation(), 2);
        assert_eq!(receipt.key_id(), "key_v2");
        assert_eq!(
            receipt.recipient_ids(),
            &[PrincipalId::new("member"), PrincipalId::new("owner")]
        );
    }

    #[test]
    fn provider_cipher_fails_closed_on_limits_and_algorithms() {
        let cipher = connected(vec![0; 262_145]);
        assert_eq!(
            cipher.seal(&context(), &vec![0; 262_145]),
            Err(CryptoError::InvalidEnvelope)
        );
        let foreign = EncryptedPayload::new(vec![1], "key", "foreign", vec![2; 24])
            .expect("envelope should be structurally valid");
        assert_eq!(
            cipher.open(&context(), &foreign),
            Err(CryptoError::UnsupportedAlgorithm)
        );
        let valid = EncryptedPayload::new(vec![1], "key_v1", "xchacha20poly1305-ietf", vec![2; 24])
            .expect("envelope should be valid");
        assert_eq!(
            cipher.open(&context(), &valid),
            Err(CryptoError::InvalidEnvelope)
        );
    }

    #[test]
    fn provider_cipher_rejects_request_namespace_that_cannot_safely_grow() {
        let result = KeyProviderCipher::connect(
            FakeTransport {
                manifest: manifest(),
                open_response: Vec::new(),
            },
            KeyProviderPolicy {
                minimum_protocol_version: CURRENT_KEY_PROVIDER_PROTOCOL,
                required_algorithm: "xchacha20poly1305-ietf".to_owned(),
                minimum_plaintext_bytes: 1,
                require_historical_keys: false,
                require_rotation: false,
            },
            "x".repeat(201),
        );
        assert!(matches!(result, Err(CryptoError::InvalidEnvelope)));
    }

    #[test]
    fn provider_cipher_never_wraps_or_reuses_exhausted_request_ids() {
        let cipher = connected(Vec::new());
        cipher
            .next_request
            .store(u64::MAX - 1, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(
            cipher
                .request_id("seal")
                .expect("last available request id should be issued"),
            format!("test-client-seal-{}", u64::MAX - 1)
        );
        assert_eq!(cipher.request_id("seal"), Err(CryptoError::KeyUnavailable));
        assert_eq!(cipher.request_id("open"), Err(CryptoError::KeyUnavailable));
    }
}

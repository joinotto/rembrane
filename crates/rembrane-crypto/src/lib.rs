//! Narrow cryptographic boundary for canonical encrypted payloads.
//!
//! Concrete algorithm and key-store integrations belong in separate adapters.
//! Callers receive opaque envelopes and never receive workspace key bytes.

use std::error::Error;
use std::fmt::{self, Display};

use rembrane_domain::WorkspaceId;

mod provider_protocol;

pub const MAX_ENCRYPTED_CIPHERTEXT_BYTES: usize = 1_500_000;
pub const MAX_ENCRYPTION_CONTEXT_RECORD_ID_BYTES: usize = 1_024;
pub const MAX_ENCRYPTION_CONTEXT_WORKSPACE_ID_BYTES: usize = 255;
pub const MAX_ENCRYPTION_KEY_ID_BYTES: usize = 2_048;
pub const MAX_ENCRYPTION_ALGORITHM_BYTES: usize = 100;
pub const MAX_ENCRYPTION_NONCE_BYTES: usize = 64;

pub use provider_protocol::{
    CURRENT_KEY_PROVIDER_PROTOCOL, KeyProviderCipher, KeyProviderManifest, KeyProviderPolicy,
    KeyProviderProtocolError, KeyProviderProtocolVersion, KeyProviderTransport,
    MAX_KEY_PROVIDER_ALGORITHMS, MAX_KEY_PROVIDER_PLAINTEXT_BYTES, OpenRequest, RotateKeyRequest,
    SealRequest,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayloadPurpose {
    ActivityCheckpoint,
    CanonicalEvent,
    KnowledgeEdge,
    KnowledgeNode,
    MemoryContent,
    TripEntity,
    BookingResearch,
    ChannelMessage,
}

impl PayloadPurpose {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ActivityCheckpoint => "activity-checkpoint",
            Self::CanonicalEvent => "canonical-event",
            Self::KnowledgeEdge => "knowledge-edge",
            Self::KnowledgeNode => "knowledge-node",
            Self::MemoryContent => "memory-content",
            Self::TripEntity => "trip-entity",
            Self::BookingResearch => "booking-research",
            Self::ChannelMessage => "channel-message",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EncryptionContext {
    workspace_id: WorkspaceId,
    record_id: String,
    record_version: u64,
    purpose: PayloadPurpose,
}

impl fmt::Debug for EncryptionContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptionContext")
            .field("workspace_id", &"[REDACTED]")
            .field("record_id", &"[REDACTED]")
            .field("record_version", &self.record_version)
            .field("purpose", &self.purpose)
            .finish()
    }
}

impl EncryptionContext {
    pub fn new(
        workspace_id: WorkspaceId,
        record_id: impl Into<String>,
        record_version: u64,
        purpose: PayloadPurpose,
    ) -> Result<Self, CryptoError> {
        let record_id = record_id.into();
        if workspace_id.as_str().trim().is_empty()
            || workspace_id.as_str().trim() != workspace_id.as_str()
            || workspace_id.as_str().len() > MAX_ENCRYPTION_CONTEXT_WORKSPACE_ID_BYTES
            || workspace_id.as_str().chars().any(char::is_control)
            || record_id.trim().is_empty()
            || record_id.trim() != record_id
            || record_id.len() > MAX_ENCRYPTION_CONTEXT_RECORD_ID_BYTES
            || record_id.chars().any(char::is_control)
            || record_version == 0
        {
            return Err(CryptoError::InvalidContext);
        }

        Ok(Self {
            workspace_id,
            record_id,
            record_version,
            purpose,
        })
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub fn record_id(&self) -> &str {
        &self.record_id
    }

    #[must_use]
    pub const fn record_version(&self) -> u64 {
        self.record_version
    }

    #[must_use]
    pub const fn purpose(&self) -> PayloadPurpose {
        self.purpose
    }

    /// Stable, length-delimited associated data prevents ciphertext from being
    /// moved between tenants, records, versions, or payload purposes.
    #[must_use]
    pub fn associated_data(&self) -> Vec<u8> {
        let version = self.record_version.to_be_bytes();
        let fields = [
            self.workspace_id.as_str().as_bytes(),
            self.record_id.as_bytes(),
            version.as_slice(),
            self.purpose.label().as_bytes(),
        ];
        let mut encoded = Vec::new();

        for field in fields {
            let length = u64::try_from(field.len()).unwrap_or(u64::MAX);
            encoded.extend_from_slice(&length.to_be_bytes());
            encoded.extend_from_slice(field);
        }

        encoded
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct EncryptedPayload {
    ciphertext: Vec<u8>,
    key_id: String,
    algorithm: String,
    nonce: Vec<u8>,
}

impl fmt::Debug for EncryptedPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedPayload")
            .field("ciphertext_bytes", &self.ciphertext.len())
            .field("key_id", &"[REDACTED]")
            .field("algorithm", &"[REDACTED]")
            .field("nonce_bytes", &self.nonce.len())
            .finish()
    }
}

impl EncryptedPayload {
    pub fn new(
        ciphertext: Vec<u8>,
        key_id: impl Into<String>,
        algorithm: impl Into<String>,
        nonce: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        let key_id = key_id.into();
        let algorithm = algorithm.into();
        if ciphertext.is_empty()
            || ciphertext.len() > MAX_ENCRYPTED_CIPHERTEXT_BYTES
            || key_id.trim().is_empty()
            || key_id.trim() != key_id
            || key_id.len() > MAX_ENCRYPTION_KEY_ID_BYTES
            || key_id.chars().any(char::is_control)
            || algorithm.trim().is_empty()
            || algorithm.trim() != algorithm
            || algorithm.len() > MAX_ENCRYPTION_ALGORITHM_BYTES
            || algorithm.chars().any(char::is_control)
            || !(12..=MAX_ENCRYPTION_NONCE_BYTES).contains(&nonce.len())
        {
            return Err(CryptoError::InvalidEnvelope);
        }

        Ok(Self {
            ciphertext,
            key_id,
            algorithm,
            nonce,
        })
    }

    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    #[must_use]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CryptoError {
    AuthenticationFailed,
    EntropyUnavailable,
    InvalidContext,
    InvalidEnvelope,
    KeyUnavailable,
    UnsupportedAlgorithm,
}

impl Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailed => formatter.write_str("payload authentication failed"),
            Self::EntropyUnavailable => formatter.write_str("secure randomness is unavailable"),
            Self::InvalidContext => formatter.write_str("encryption context is invalid"),
            Self::InvalidEnvelope => formatter.write_str("encrypted payload is invalid"),
            Self::KeyUnavailable => formatter.write_str("encryption key is unavailable"),
            Self::UnsupportedAlgorithm => {
                formatter.write_str("encryption algorithm is unsupported")
            }
        }
    }
}

impl Error for CryptoError {}

pub trait RecordCipher {
    fn seal(
        &self,
        context: &EncryptionContext,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, CryptoError>;

    fn open(
        &self,
        context: &EncryptionContext,
        payload: &EncryptedPayload,
    ) -> Result<Vec<u8>, CryptoError>;
}

#[cfg(test)]
mod tests {
    use super::{
        CryptoError, EncryptedPayload, EncryptionContext, MAX_ENCRYPTED_CIPHERTEXT_BYTES,
        MAX_ENCRYPTION_ALGORITHM_BYTES, MAX_ENCRYPTION_CONTEXT_RECORD_ID_BYTES,
        MAX_ENCRYPTION_CONTEXT_WORKSPACE_ID_BYTES, MAX_ENCRYPTION_KEY_ID_BYTES,
        MAX_ENCRYPTION_NONCE_BYTES, PayloadPurpose,
    };
    use rembrane_domain::WorkspaceId;

    #[test]
    fn associated_data_changes_across_workspace_boundaries() {
        let first = EncryptionContext::new(
            WorkspaceId::new("workspace_01"),
            "memory_01",
            1,
            PayloadPurpose::MemoryContent,
        )
        .expect("valid context");
        let second = EncryptionContext::new(
            WorkspaceId::new("workspace_02"),
            "memory_01",
            1,
            PayloadPurpose::MemoryContent,
        )
        .expect("valid context");

        assert_ne!(first.associated_data(), second.associated_data());
        let debug = format!("{first:?}");
        assert!(!debug.contains("workspace_01"));
        assert!(!debug.contains("memory_01"));
    }

    #[test]
    fn rejects_incomplete_encryption_envelope() {
        let error = EncryptedPayload::new(vec![1], "key_01", "xchacha20poly1305", vec![0; 8])
            .expect_err("short nonce must fail");

        assert_eq!(error, CryptoError::InvalidEnvelope);
    }

    #[test]
    fn rejects_unbounded_or_unsafe_encryption_envelope_metadata() {
        let valid =
            || EncryptedPayload::new(vec![1], "key_01", "xchacha20poly1305-ietf", vec![0; 24]);
        let valid = valid().expect("valid envelope");
        let debug = format!("{valid:?}");
        assert!(!debug.contains("key_01"));
        assert!(!debug.contains("[1]"));
        assert!(!debug.contains("[0, 0"));
        assert_eq!(
            EncryptedPayload::new(
                vec![0; MAX_ENCRYPTED_CIPHERTEXT_BYTES + 1],
                "key_01",
                "xchacha20poly1305-ietf",
                vec![0; 24],
            ),
            Err(CryptoError::InvalidEnvelope)
        );
        assert_eq!(
            EncryptedPayload::new(
                vec![1],
                "k".repeat(MAX_ENCRYPTION_KEY_ID_BYTES + 1),
                "xchacha20poly1305-ietf",
                vec![0; 24],
            ),
            Err(CryptoError::InvalidEnvelope)
        );
        assert_eq!(
            EncryptedPayload::new(
                vec![1],
                "key_01",
                "a".repeat(MAX_ENCRYPTION_ALGORITHM_BYTES + 1),
                vec![0; 24],
            ),
            Err(CryptoError::InvalidEnvelope)
        );
        for nonce_length in [11, MAX_ENCRYPTION_NONCE_BYTES + 1] {
            assert_eq!(
                EncryptedPayload::new(
                    vec![1],
                    "key_01",
                    "xchacha20poly1305-ietf",
                    vec![0; nonce_length],
                ),
                Err(CryptoError::InvalidEnvelope)
            );
        }
        for value in [" key_01", "key_01\n"] {
            assert_eq!(
                EncryptedPayload::new(vec![1], value, "xchacha20poly1305-ietf", vec![0; 24],),
                Err(CryptoError::InvalidEnvelope)
            );
        }
    }

    #[test]
    fn rejects_zero_record_version() {
        let error = EncryptionContext::new(
            WorkspaceId::new("workspace_01"),
            "memory_01",
            0,
            PayloadPurpose::MemoryContent,
        )
        .expect_err("zero version must fail");

        assert_eq!(error, CryptoError::InvalidContext);
    }

    #[test]
    fn rejects_unbounded_or_noncanonical_encryption_context_identifiers() {
        for workspace_id in [
            " workspace_01".to_owned(),
            "workspace_01\n".to_owned(),
            "w".repeat(MAX_ENCRYPTION_CONTEXT_WORKSPACE_ID_BYTES + 1),
        ] {
            assert_eq!(
                EncryptionContext::new(
                    WorkspaceId::new(workspace_id),
                    "memory_01",
                    1,
                    PayloadPurpose::MemoryContent,
                ),
                Err(CryptoError::InvalidContext)
            );
        }
        for record_id in [
            " memory_01".to_owned(),
            "memory_01\n".to_owned(),
            "r".repeat(MAX_ENCRYPTION_CONTEXT_RECORD_ID_BYTES + 1),
        ] {
            assert_eq!(
                EncryptionContext::new(
                    WorkspaceId::new("workspace_01"),
                    record_id,
                    1,
                    PayloadPurpose::MemoryContent,
                ),
                Err(CryptoError::InvalidContext)
            );
        }
    }
}

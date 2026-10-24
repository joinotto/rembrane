//! Experimental portable XChaCha20-Poly1305 record cipher.
//!
//! This adapter provides the record AEAD primitive only. Production use still
//! requires an audited key provider, rotation, recovery, secure device storage,
//! and independent review.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rembrane_crypto::{CryptoError, EncryptedPayload, EncryptionContext, RecordCipher};
#[cfg(target_os = "macos")]
use std::process::Command;
use zeroize::Zeroizing;

const ALGORITHM: &str = "xchacha20poly1305-ietf";
const NONCE_LENGTH: usize = 24;

pub struct RustCryptoRecordCipher {
    key_id: String,
    key: Zeroizing<[u8; 32]>,
}

impl RustCryptoRecordCipher {
    pub fn new(key_id: impl Into<String>, key: [u8; 32]) -> Result<Self, CryptoError> {
        let key_id = key_id.into();
        if key_id.trim().is_empty() {
            return Err(CryptoError::KeyUnavailable);
        }
        Ok(Self {
            key_id,
            key: Zeroizing::new(key),
        })
    }

    pub fn from_environment() -> Result<Self, CryptoError> {
        let key_id =
            std::env::var("REMBRANE_WORKSPACE_KEY_ID").map_err(|_| CryptoError::KeyUnavailable)?;
        let encoded_key = Zeroizing::new(
            std::env::var("REMBRANE_WORKSPACE_KEY_HEX").map_err(|_| CryptoError::KeyUnavailable)?,
        );
        let key = decode_key(&encoded_key)?;
        Self::new(key_id, key)
    }

    /// Resolves a hex-encoded workspace key from the current user's macOS
    /// Keychain. The service and account are lookup metadata, not secrets.
    #[cfg(target_os = "macos")]
    pub fn from_macos_keychain(
        key_id: impl Into<String>,
        service: &str,
        account: &str,
    ) -> Result<Self, CryptoError> {
        if service.trim().is_empty() || account.trim().is_empty() {
            return Err(CryptoError::KeyUnavailable);
        }
        let output = Command::new("/usr/bin/security")
            .args(["find-generic-password", "-s", service, "-a", account, "-w"])
            .output()
            .map_err(|_| CryptoError::KeyUnavailable)?;
        if !output.status.success() {
            return Err(CryptoError::KeyUnavailable);
        }
        let encoded = String::from_utf8(output.stdout).map_err(|_| CryptoError::KeyUnavailable)?;
        let encoded = Zeroizing::new(encoded);
        let key = decode_key(encoded.trim())?;
        Self::new(key_id, key)
    }

    #[cfg(not(target_os = "macos"))]
    pub fn from_macos_keychain(
        _key_id: impl Into<String>,
        _service: &str,
        _account: &str,
    ) -> Result<Self, CryptoError> {
        Err(CryptoError::KeyUnavailable)
    }

    /// Selects the configured local key source without accepting key material
    /// through command-line arguments.
    ///
    /// `environment` is the pre-alpha development mode. `macos-keychain`
    /// resolves the value from the current user's login keychain.
    pub fn from_configured_provider() -> Result<Self, CryptoError> {
        match std::env::var("REMBRANE_KEY_PROVIDER")
            .unwrap_or_else(|_| "environment".to_owned())
            .as_str()
        {
            "environment" => Self::from_environment(),
            "macos-keychain" => {
                let key_id = std::env::var("REMBRANE_WORKSPACE_KEY_ID")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                let service = std::env::var("REMBRANE_KEYCHAIN_SERVICE")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                let account = std::env::var("REMBRANE_KEYCHAIN_ACCOUNT")
                    .map_err(|_| CryptoError::KeyUnavailable)?;
                Self::from_macos_keychain(key_id, &service, &account)
            }
            _ => Err(CryptoError::KeyUnavailable),
        }
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// In-process keyring for staged key rotation.
///
/// New records are sealed with the active key. Existing records are opened
/// only by the key whose opaque identifier is stored in their envelope.
/// Key-provider adapters can construct this keyring after resolving key
/// material from an OS keychain, HSM, or customer-controlled KMS.
pub struct RustCryptoKeyringCipher {
    active: RustCryptoRecordCipher,
    historical: Vec<RustCryptoRecordCipher>,
}

impl RustCryptoKeyringCipher {
    pub fn new(
        active: RustCryptoRecordCipher,
        historical: Vec<RustCryptoRecordCipher>,
    ) -> Result<Self, CryptoError> {
        if historical
            .iter()
            .any(|candidate| candidate.key_id() == active.key_id())
        {
            return Err(CryptoError::KeyUnavailable);
        }
        for (index, candidate) in historical.iter().enumerate() {
            if historical[..index]
                .iter()
                .any(|earlier| earlier.key_id() == candidate.key_id())
            {
                return Err(CryptoError::KeyUnavailable);
            }
        }
        Ok(Self { active, historical })
    }

    #[must_use]
    pub fn active_key_id(&self) -> &str {
        self.active.key_id()
    }

    fn cipher_for_key(&self, key_id: &str) -> Option<&RustCryptoRecordCipher> {
        if self.active.key_id() == key_id {
            return Some(&self.active);
        }
        self.historical
            .iter()
            .find(|candidate| candidate.key_id() == key_id)
    }
}

fn decode_key(encoded: &str) -> Result<[u8; 32], CryptoError> {
    if encoded.len() != 64 || !encoded.is_ascii() {
        return Err(CryptoError::KeyUnavailable);
    }
    let mut key = Zeroizing::new([0_u8; 32]);
    for (index, output) in key.iter_mut().enumerate() {
        let offset = index.saturating_mul(2);
        *output = u8::from_str_radix(&encoded[offset..offset + 2], 16)
            .map_err(|_| CryptoError::KeyUnavailable)?;
    }
    Ok(*key)
}

impl RecordCipher for RustCryptoRecordCipher {
    fn seal(
        &self,
        context: &EncryptionContext,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, CryptoError> {
        let mut nonce = [0_u8; NONCE_LENGTH];
        getrandom::fill(&mut nonce).map_err(|_| CryptoError::EntropyUnavailable)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(self.key.as_ref()));
        let associated_data = context.associated_data();
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        EncryptedPayload::new(ciphertext, self.key_id.clone(), ALGORITHM, nonce.to_vec())
    }

    fn open(
        &self,
        context: &EncryptionContext,
        payload: &EncryptedPayload,
    ) -> Result<Vec<u8>, CryptoError> {
        if payload.algorithm() != ALGORITHM {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        if payload.key_id() != self.key_id {
            return Err(CryptoError::KeyUnavailable);
        }
        let nonce: &[u8; NONCE_LENGTH] = payload
            .nonce()
            .try_into()
            .map_err(|_| CryptoError::InvalidEnvelope)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(self.key.as_ref()));
        let associated_data = context.associated_data();
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: payload.ciphertext(),
                    aad: &associated_data,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

impl RecordCipher for RustCryptoKeyringCipher {
    fn seal(
        &self,
        context: &EncryptionContext,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, CryptoError> {
        self.active.seal(context, plaintext)
    }

    fn open(
        &self,
        context: &EncryptionContext,
        payload: &EncryptedPayload,
    ) -> Result<Vec<u8>, CryptoError> {
        self.cipher_for_key(payload.key_id())
            .ok_or(CryptoError::KeyUnavailable)?
            .open(context, payload)
    }
}

#[cfg(test)]
mod tests {
    use rembrane_crypto::{CryptoError, EncryptionContext, PayloadPurpose, RecordCipher};
    use rembrane_domain::WorkspaceId;

    use super::{RustCryptoKeyringCipher, RustCryptoRecordCipher};

    fn context(workspace: &str) -> EncryptionContext {
        EncryptionContext::new(
            WorkspaceId::new(workspace),
            "memory_01",
            1,
            PayloadPurpose::MemoryContent,
        )
        .expect("context is valid")
    }

    #[test]
    fn round_trips_authenticated_record() {
        let cipher = RustCryptoRecordCipher::new("key_01", [7; 32]).expect("key is valid");
        let encrypted = cipher
            .seal(&context("workspace_01"), b"Call me Hippo")
            .expect("encryption succeeds");
        let plaintext = cipher
            .open(&context("workspace_01"), &encrypted)
            .expect("decryption succeeds");

        assert_eq!(plaintext, b"Call me Hippo");
    }

    #[test]
    fn rejects_cross_workspace_substitution() {
        let cipher = RustCryptoRecordCipher::new("key_01", [7; 32]).expect("key is valid");
        let encrypted = cipher
            .seal(&context("workspace_01"), b"Call me Hippo")
            .expect("encryption succeeds");
        let error = cipher
            .open(&context("workspace_02"), &encrypted)
            .expect_err("different associated data must fail");

        assert_eq!(error, CryptoError::AuthenticationFailed);
    }

    #[test]
    fn rejects_invalid_encoded_key() {
        assert_eq!(super::decode_key("abcd"), Err(CryptoError::KeyUnavailable));
    }

    #[test]
    fn keyring_writes_active_key_and_reads_historical_ciphertext() {
        let old = RustCryptoRecordCipher::new("key_v1", [1; 32]).expect("old key should be valid");
        let old_payload = old
            .seal(&context("workspace_01"), b"historical")
            .expect("old key should seal");
        let keyring = RustCryptoKeyringCipher::new(
            RustCryptoRecordCipher::new("key_v2", [2; 32]).expect("active key should be valid"),
            vec![old],
        )
        .expect("distinct keyring should be valid");

        assert_eq!(
            keyring
                .open(&context("workspace_01"), &old_payload)
                .expect("historical key should remain readable"),
            b"historical"
        );
        let current = keyring
            .seal(&context("workspace_01"), b"current")
            .expect("active key should seal");
        assert_eq!(current.key_id(), "key_v2");
        assert_eq!(keyring.active_key_id(), "key_v2");
    }

    #[test]
    fn keyring_rejects_duplicate_and_unknown_key_ids() {
        let duplicate = RustCryptoKeyringCipher::new(
            RustCryptoRecordCipher::new("key_v2", [2; 32]).expect("active key should be valid"),
            vec![
                RustCryptoRecordCipher::new("key_v2", [3; 32])
                    .expect("historical key should be structurally valid"),
            ],
        );
        assert!(matches!(duplicate, Err(CryptoError::KeyUnavailable)));

        let foreign = RustCryptoRecordCipher::new("foreign", [4; 32])
            .expect("foreign key should be valid")
            .seal(&context("workspace_01"), b"foreign")
            .expect("foreign key should seal");
        let keyring = RustCryptoKeyringCipher::new(
            RustCryptoRecordCipher::new("key_v2", [2; 32]).expect("active key should be valid"),
            Vec::new(),
        )
        .expect("keyring should be valid");
        assert_eq!(
            keyring.open(&context("workspace_01"), &foreign),
            Err(CryptoError::KeyUnavailable)
        );
    }
}

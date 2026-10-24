//! Experimental portable XChaCha20-Poly1305 record cipher.
//!
//! This adapter provides the record AEAD primitive only. Production use still
//! requires an audited key provider, rotation, recovery, secure device storage,
//! and independent review.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rembrane_crypto::{CryptoError, EncryptedPayload, EncryptionContext, RecordCipher};
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

#[cfg(test)]
mod tests {
    use rembrane_crypto::{CryptoError, EncryptionContext, PayloadPurpose, RecordCipher};
    use rembrane_domain::WorkspaceId;

    use super::RustCryptoRecordCipher;

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
}

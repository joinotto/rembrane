//! Reusable trust boundary for embedded and detached-signed provider registries.

mod selection;

use std::error::Error;
use std::fmt::{Display, Formatter};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

pub use selection::{
    ProviderEligibility, ProviderRegistrySelectionError, ProviderSelectionApprovals,
    ProviderSelectionEvidence, ProviderSelectionPolicy, ProviderSelectionReceipt,
    ProviderSelectionTrust,
};

const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryTrust {
    Embedded,
    Ed25519 { public_key_sha256: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedProviderRegistry {
    bytes: Vec<u8>,
    sha256: String,
    trust: RegistryTrust,
}

impl VerifiedProviderRegistry {
    /// Accepts bytes compiled into the trusted application artifact.
    #[must_use]
    pub fn embedded(bytes: impl Into<Vec<u8>>) -> Self {
        let bytes = bytes.into();
        Self {
            sha256: sha256_hex(&bytes),
            bytes,
            trust: RegistryTrust::Embedded,
        }
    }

    /// Verifies exact registry bytes against a detached Ed25519 signature and
    /// canonical `SubjectPublicKeyInfo` PEM trust anchor.
    ///
    /// # Errors
    ///
    /// Returns an opaque verification error for malformed keys, signatures,
    /// or signature mismatch.
    pub fn verify_ed25519(
        bytes: impl Into<Vec<u8>>,
        signature: &[u8],
        public_key_pem: &[u8],
    ) -> Result<Self, RegistryVerificationError> {
        let bytes = bytes.into();
        if signature.len() != 64 {
            return Err(RegistryVerificationError);
        }
        let der = decode_ed25519_public_key(public_key_pem)?;
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            &der[ED25519_SPKI_PREFIX.len()..],
        )
        .verify(&bytes, signature)
        .map_err(|_| RegistryVerificationError)?;
        Ok(Self {
            sha256: sha256_hex(&bytes),
            bytes,
            trust: RegistryTrust::Ed25519 {
                public_key_sha256: sha256_hex(&der),
            },
        })
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    #[must_use]
    pub const fn trust(&self) -> &RegistryTrust {
        &self.trust
    }

    /// Selects one exact provider build under a fail-closed policy.
    ///
    /// # Errors
    ///
    /// Returns an opaque selection error for malformed, stale, ambiguous,
    /// withdrawn, unconformant, or insufficiently approved providers.
    pub fn select(
        &self,
        policy: &ProviderSelectionPolicy<'_>,
    ) -> Result<ProviderSelectionReceipt, ProviderRegistrySelectionError> {
        selection::select(self, policy)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryVerificationError;

impl Display for RegistryVerificationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("provider registry signature verification failed")
    }
}

impl Error for RegistryVerificationError {}

fn decode_ed25519_public_key(public_key_pem: &[u8]) -> Result<Vec<u8>, RegistryVerificationError> {
    let pem = std::str::from_utf8(public_key_pem).map_err(|_| RegistryVerificationError)?;
    let body = pem
        .strip_prefix("-----BEGIN PUBLIC KEY-----\n")
        .and_then(|value| value.strip_suffix("-----END PUBLIC KEY-----\n"))
        .ok_or(RegistryVerificationError)?;
    let encoded = body.lines().collect::<String>();
    let der = BASE64
        .decode(encoded)
        .map_err(|_| RegistryVerificationError)?;
    if der.len() != ED25519_SPKI_PREFIX.len() + 32 || !der.starts_with(ED25519_SPKI_PREFIX) {
        return Err(RegistryVerificationError);
    }
    Ok(der)
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest.as_ref() {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::{ED25519_SPKI_PREFIX, RegistryTrust, VerifiedProviderRegistry};

    fn fixture() -> (Ed25519KeyPair, Vec<u8>) {
        let random = SystemRandom::new();
        let document = Ed25519KeyPair::generate_pkcs8(&random).expect("generate key");
        let key = Ed25519KeyPair::from_pkcs8(document.as_ref()).expect("parse key");
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(key.public_key().as_ref());
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            BASE64.encode(der)
        )
        .into_bytes();
        (key, pem)
    }

    #[test]
    fn verifies_exact_registry_and_records_trust_anchor() {
        let (key, pem) = fixture();
        let registry = br#"{"schemaVersion":1}"#;
        let signature = key.sign(registry);
        let verified = VerifiedProviderRegistry::verify_ed25519(registry, signature.as_ref(), &pem)
            .expect("verified registry");

        assert_eq!(verified.bytes(), registry);
        assert_eq!(verified.sha256().len(), 64);
        assert!(matches!(
            verified.trust(),
            RegistryTrust::Ed25519 { public_key_sha256 }
                if public_key_sha256.len() == 64
        ));
    }

    #[test]
    fn rejects_tampered_registry_and_non_ed25519_key() {
        let (key, pem) = fixture();
        let signature = key.sign(b"original");
        assert!(
            VerifiedProviderRegistry::verify_ed25519(b"tampered", signature.as_ref(), &pem)
                .is_err()
        );
        assert!(
            VerifiedProviderRegistry::verify_ed25519(
                b"original",
                signature.as_ref(),
                b"not a public key",
            )
            .is_err()
        );
    }
}

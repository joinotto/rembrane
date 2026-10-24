//! Authenticated, bounded HTTP transport for customer-controlled key providers.

use std::io::Read;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rembrane_crypto::{
    CryptoError, EncryptedPayload, EncryptionContext, KeyProviderManifest,
    KeyProviderProtocolVersion, KeyProviderTransport, OpenRequest, RotateKeyRequest, SealRequest,
};
use rembrane_domain::{KeyRotationReceipt, PrincipalId, ProviderId, WorkspaceId};
use reqwest::Url;
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAXIMUM_RESPONSE_BYTES: u64 = 1_500_000;
const MAXIMUM_ADVERTISED_PLAINTEXT_BYTES: usize = 1_048_576;

pub struct HttpKeyProviderTransport {
    client: Client,
    manifest_endpoint: Url,
    seal_endpoint: Url,
    open_endpoint: Url,
    rotate_endpoint: Url,
    bearer_token: Zeroizing<String>,
}

impl HttpKeyProviderTransport {
    /// Creates a secret-safe key-provider transport.
    ///
    /// HTTPS is required outside exact loopback hosts. The base URL must be an
    /// origin without credentials, query, fragment, or a non-root path.
    ///
    /// # Errors
    ///
    /// Returns an opaque key-unavailable error when endpoint, credential, or
    /// HTTP-client configuration is invalid.
    pub fn new(base_url: &str, bearer_token: String) -> Result<Self, CryptoError> {
        let bearer_token = Zeroizing::new(bearer_token);
        let base = validate_base_url(base_url)?;
        if bearer_token.is_empty()
            || bearer_token.len() > 8192
            || !bearer_token.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-')
            })
        {
            return Err(CryptoError::KeyUnavailable);
        }
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| CryptoError::KeyUnavailable)?;
        Ok(Self {
            client,
            manifest_endpoint: base
                .join("v0.1/manifest")
                .map_err(|_| CryptoError::KeyUnavailable)?,
            seal_endpoint: base
                .join("v0.1/seal")
                .map_err(|_| CryptoError::KeyUnavailable)?,
            open_endpoint: base
                .join("v0.1/open")
                .map_err(|_| CryptoError::KeyUnavailable)?,
            rotate_endpoint: base
                .join("v0.1/rotate")
                .map_err(|_| CryptoError::KeyUnavailable)?,
            bearer_token,
        })
    }

    fn request(&self, endpoint: Url) -> reqwest::blocking::RequestBuilder {
        self.client
            .post(endpoint)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .bearer_auth(self.bearer_token.as_str())
    }

    fn decode_response<T: for<'de> Deserialize<'de>>(response: Response) -> Result<T, CryptoError> {
        let status = response.status();
        if !status.is_success() {
            return Err(match status.as_u16() {
                401 | 403 => CryptoError::AuthenticationFailed,
                413 | 422 => CryptoError::InvalidEnvelope,
                _ => CryptoError::KeyUnavailable,
            });
        }
        let is_json = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|media_type| media_type.eq_ignore_ascii_case("application/json"))
            });
        if !is_json {
            return Err(CryptoError::InvalidEnvelope);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAXIMUM_RESPONSE_BYTES)
        {
            return Err(CryptoError::InvalidEnvelope);
        }
        let mut body = Vec::new();
        response
            .take(MAXIMUM_RESPONSE_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| CryptoError::KeyUnavailable)?;
        if body.len() as u64 > MAXIMUM_RESPONSE_BYTES {
            return Err(CryptoError::InvalidEnvelope);
        }
        serde_json::from_slice(&body).map_err(|_| CryptoError::InvalidEnvelope)
    }
}

impl KeyProviderTransport for HttpKeyProviderTransport {
    fn fetch_manifest(&self) -> Result<KeyProviderManifest, CryptoError> {
        let response = self
            .client
            .get(self.manifest_endpoint.clone())
            .header(ACCEPT, "application/json")
            .bearer_auth(self.bearer_token.as_str())
            .send()
            .map_err(|_| CryptoError::KeyUnavailable)?;
        let wire: ManifestResponse = Self::decode_response(response)?;
        wire.try_into()
    }

    fn seal(&self, request: &SealRequest) -> Result<EncryptedPayload, CryptoError> {
        let body = SealBody {
            request_id: request.request_id(),
            context: ContextBody::from(request.context()),
            plaintext_base64: BASE64.encode(request.plaintext()),
        };
        let response = self
            .request(self.seal_endpoint.clone())
            .json(&body)
            .send()
            .map_err(|_| CryptoError::KeyUnavailable)?;
        let wire: EnvelopeResponse = Self::decode_response(response)?;
        wire.try_into()
    }

    fn open(&self, request: &OpenRequest) -> Result<Vec<u8>, CryptoError> {
        let body = OpenBody {
            request_id: request.request_id(),
            context: ContextBody::from(request.context()),
            envelope: EnvelopeBody::from(request.envelope()),
        };
        let response = self
            .request(self.open_endpoint.clone())
            .json(&body)
            .send()
            .map_err(|_| CryptoError::KeyUnavailable)?;
        let wire: PlaintextResponse = Self::decode_response(response)?;
        BASE64
            .decode(wire.plaintext_base64)
            .map_err(|_| CryptoError::InvalidEnvelope)
    }

    fn rotate(&self, request: &RotateKeyRequest) -> Result<KeyRotationReceipt, CryptoError> {
        let body = RotateBody {
            request_id: request.request_id(),
            workspace_id: request.workspace_id().as_str(),
            generation: request.generation(),
            recipient_ids: request
                .recipient_ids()
                .iter()
                .map(PrincipalId::as_str)
                .collect(),
        };
        let response = self
            .request(self.rotate_endpoint.clone())
            .json(&body)
            .send()
            .map_err(|_| CryptoError::KeyUnavailable)?;
        let wire: RotationReceiptResponse = Self::decode_response(response)?;
        wire.into_domain()
    }
}

fn validate_base_url(value: &str) -> Result<Url, CryptoError> {
    let mut url = Url::parse(value).map_err(|_| CryptoError::KeyUnavailable)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(CryptoError::KeyUnavailable);
    }
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "::1"));
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(CryptoError::KeyUnavailable);
    }
    url.set_path("/");
    Ok(url)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ManifestResponse {
    provider_id: String,
    protocol_version: String,
    algorithms: Vec<String>,
    maximum_plaintext_bytes: usize,
    #[serde(default)]
    supports_historical_keys: bool,
    #[serde(default)]
    supports_rotation: bool,
}

impl TryFrom<ManifestResponse> for KeyProviderManifest {
    type Error = CryptoError;

    fn try_from(wire: ManifestResponse) -> Result<Self, Self::Error> {
        if wire.protocol_version != "0.1"
            || wire.maximum_plaintext_bytes > MAXIMUM_ADVERTISED_PLAINTEXT_BYTES
        {
            return Err(CryptoError::KeyUnavailable);
        }
        let manifest = Self {
            provider_id: wire.provider_id,
            protocol_version: KeyProviderProtocolVersion::new(0, 1),
            algorithms: wire.algorithms,
            maximum_plaintext_bytes: wire.maximum_plaintext_bytes,
            supports_historical_keys: wire.supports_historical_keys,
            supports_rotation: wire.supports_rotation,
        };
        manifest
            .validate()
            .map_err(|_| CryptoError::KeyUnavailable)?;
        Ok(manifest)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ContextBody<'value> {
    workspace_id: &'value str,
    record_id: &'value str,
    record_version: u64,
    purpose: &'static str,
}

impl<'value> From<&'value EncryptionContext> for ContextBody<'value> {
    fn from(context: &'value EncryptionContext) -> Self {
        Self {
            workspace_id: context.workspace_id().as_str(),
            record_id: context.record_id(),
            record_version: context.record_version(),
            purpose: context.purpose().label(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SealBody<'value> {
    request_id: &'value str,
    context: ContextBody<'value>,
    plaintext_base64: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenBody<'value> {
    request_id: &'value str,
    context: ContextBody<'value>,
    envelope: EnvelopeBody<'value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RotateBody<'value> {
    request_id: &'value str,
    workspace_id: &'value str,
    generation: u64,
    recipient_ids: Vec<&'value str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnvelopeBody<'value> {
    ciphertext_base64: String,
    key_id: &'value str,
    algorithm: &'value str,
    nonce_base64: String,
}

impl<'value> From<&'value EncryptedPayload> for EnvelopeBody<'value> {
    fn from(envelope: &'value EncryptedPayload) -> Self {
        Self {
            ciphertext_base64: BASE64.encode(envelope.ciphertext()),
            key_id: envelope.key_id(),
            algorithm: envelope.algorithm(),
            nonce_base64: BASE64.encode(envelope.nonce()),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct EnvelopeResponse {
    ciphertext_base64: String,
    key_id: String,
    algorithm: String,
    nonce_base64: String,
}

impl TryFrom<EnvelopeResponse> for EncryptedPayload {
    type Error = CryptoError;

    fn try_from(wire: EnvelopeResponse) -> Result<Self, Self::Error> {
        Self::new(
            BASE64
                .decode(wire.ciphertext_base64)
                .map_err(|_| CryptoError::InvalidEnvelope)?,
            wire.key_id,
            wire.algorithm,
            BASE64
                .decode(wire.nonce_base64)
                .map_err(|_| CryptoError::InvalidEnvelope)?,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PlaintextResponse {
    plaintext_base64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RotationReceiptResponse {
    provider_id: String,
    request_id: String,
    workspace_id: String,
    generation: u64,
    key_id: String,
    recipient_ids: Vec<String>,
}

impl RotationReceiptResponse {
    fn into_domain(self) -> Result<KeyRotationReceipt, CryptoError> {
        KeyRotationReceipt::new(
            ProviderId::new(self.provider_id),
            self.request_id,
            WorkspaceId::new(self.workspace_id),
            self.generation,
            self.key_id,
            self.recipient_ids
                .into_iter()
                .map(PrincipalId::new)
                .collect(),
        )
        .map_err(|_| CryptoError::InvalidEnvelope)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EnvelopeResponse, HttpKeyProviderTransport, ManifestResponse, PlaintextResponse,
        RotationReceiptResponse, validate_base_url,
    };
    use rembrane_crypto::{CryptoError, EncryptedPayload, KeyProviderManifest};

    #[test]
    fn accepts_https_and_exact_loopback_origins_only() {
        assert!(
            HttpKeyProviderTransport::new("https://keys.example.test", "opaque-token".to_owned())
                .is_ok()
        );
        assert!(
            HttpKeyProviderTransport::new("http://127.0.0.1:8792", "opaque-token".to_owned())
                .is_ok()
        );
        for invalid in [
            "http://keys.example.test",
            "https://user:secret@keys.example.test",
            "https://keys.example.test/provider",
            "https://keys.example.test?token=secret",
            "https://keys.example.test#fragment",
        ] {
            assert_eq!(validate_base_url(invalid), Err(CryptoError::KeyUnavailable));
        }
    }

    #[test]
    fn rejects_empty_or_header_unsafe_bearer_credentials() {
        assert!(HttpKeyProviderTransport::new("https://keys.example.test", String::new()).is_err());
        assert!(
            HttpKeyProviderTransport::new(
                "https://keys.example.test",
                "token\r\ninjected: value".to_owned()
            )
            .is_err()
        );
        assert!(
            HttpKeyProviderTransport::new(
                "https://keys.example.test",
                "token with spaces".to_owned()
            )
            .is_err()
        );
    }

    #[test]
    fn validates_manifest_protocol_limits_and_shape() {
        let manifest = KeyProviderManifest::try_from(ManifestResponse {
            provider_id: "rembrane.test-key-provider".to_owned(),
            protocol_version: "0.1".to_owned(),
            algorithms: vec!["xchacha20poly1305-ietf".to_owned()],
            maximum_plaintext_bytes: 262_144,
            supports_historical_keys: true,
            supports_rotation: false,
        })
        .expect("manifest should validate");
        assert_eq!(manifest.maximum_plaintext_bytes, 262_144);
        assert!(!manifest.supports_rotation);

        assert_eq!(
            KeyProviderManifest::try_from(ManifestResponse {
                provider_id: "rembrane.test-key-provider".to_owned(),
                protocol_version: "0.2".to_owned(),
                algorithms: vec!["xchacha20poly1305-ietf".to_owned()],
                maximum_plaintext_bytes: 262_144,
                supports_historical_keys: true,
                supports_rotation: false,
            }),
            Err(CryptoError::KeyUnavailable)
        );
    }

    #[test]
    fn decodes_strict_base64_envelopes_and_plaintext() {
        let envelope = EncryptedPayload::try_from(EnvelopeResponse {
            ciphertext_base64: "Y2lwaGVydGV4dA==".to_owned(),
            key_id: "key-v1".to_owned(),
            algorithm: "xchacha20poly1305-ietf".to_owned(),
            nonce_base64: "AAAAAAAAAAAAAAAA".to_owned(),
        })
        .expect("envelope should decode");
        assert_eq!(envelope.ciphertext(), b"ciphertext");

        let plaintext: PlaintextResponse =
            serde_json::from_str(r#"{"plaintextBase64":"cGxhaW50ZXh0"}"#)
                .expect("response should decode");
        assert_eq!(plaintext.plaintext_base64, "cGxhaW50ZXh0");
        assert!(
            serde_json::from_str::<PlaintextResponse>(
                r#"{"plaintextBase64":"cGxhaW50ZXh0","extra":true}"#
            )
            .is_err()
        );
    }

    #[test]
    fn validates_rotation_receipt_shape_and_recipient_uniqueness() {
        let receipt = RotationReceiptResponse {
            provider_id: "rembrane.test-key-provider".to_owned(),
            request_id: "rotate-01".to_owned(),
            workspace_id: "workspace-01".to_owned(),
            generation: 2,
            key_id: "key-v2".to_owned(),
            recipient_ids: vec!["member-b".to_owned(), "member-a".to_owned()],
        }
        .into_domain()
        .expect("receipt should validate");
        assert_eq!(receipt.generation(), 2);
        assert_eq!(receipt.recipient_ids()[0].as_str(), "member-a");

        assert!(
            RotationReceiptResponse {
                provider_id: "rembrane.test-key-provider".to_owned(),
                request_id: "rotate-02".to_owned(),
                workspace_id: "workspace-01".to_owned(),
                generation: 2,
                key_id: "key-v2".to_owned(),
                recipient_ids: vec!["member-a".to_owned(), "member-a".to_owned()],
            }
            .into_domain()
            .is_err()
        );
    }
}

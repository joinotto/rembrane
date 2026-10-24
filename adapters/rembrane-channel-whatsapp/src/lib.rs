//! Authenticated, bounded `WhatsApp` Business webhook ingestion.

use rembrane_application::{
    ApplicationError, ChannelIngressRepository, DurableChannelIngressRepository,
};
use rembrane_contracts::{ChannelKind, VerifiedChannelMessage};
use ring::hmac;
use serde::Deserialize;
use zeroize::Zeroize;

const MAXIMUM_WEBHOOK_BYTES: usize = 3 * 1024 * 1024;
const MAXIMUM_MESSAGES: usize = 100;
const MAXIMUM_IDENTIFIER_BYTES: usize = 256;
const MAXIMUM_TEXT_BYTES: usize = 16_384;
const MAXIMUM_CHALLENGE_BYTES: usize = 512;
const MAXIMUM_VERIFICATION_TOKEN_BYTES: usize = 256;

pub struct WhatsAppWebhookVerifier {
    signature_key: hmac::Key,
    lookup_key: hmac::Key,
}

pub struct WhatsAppSubscriptionVerifier {
    verification_key: hmac::Key,
}

pub struct WhatsAppTextEvent {
    account_lookup_key: String,
    sender_lookup_key: String,
    event_id: String,
    text: String,
    received_at_epoch_seconds: u64,
}

pub struct WhatsAppBindingLookupKeys {
    account_lookup_key: String,
    sender_lookup_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WhatsAppWebhookError {
    InvalidConfiguration,
    InvalidSignature,
    InvalidPayload,
    PayloadTooLarge,
    TooManyMessages,
    StaleEvent,
    Admission(ApplicationError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WhatsAppHttpStatus {
    Ok,
    Accepted,
    BadRequest,
    Unauthorized,
    PayloadTooLarge,
    TooManyRequests,
    ServiceUnavailable,
}

impl WhatsAppWebhookVerifier {
    pub fn new(
        mut app_secret: Vec<u8>,
        mut binding_lookup_secret: Vec<u8>,
    ) -> Result<Self, WhatsAppWebhookError> {
        if app_secret.len() < 32 || binding_lookup_secret.len() < 32 {
            app_secret.zeroize();
            binding_lookup_secret.zeroize();
            return Err(WhatsAppWebhookError::InvalidConfiguration);
        }
        let signature_key = hmac::Key::new(hmac::HMAC_SHA256, &app_secret);
        let lookup_key = hmac::Key::new(hmac::HMAC_SHA256, &binding_lookup_secret);
        app_secret.zeroize();
        binding_lookup_secret.zeroize();
        Ok(Self {
            signature_key,
            lookup_key,
        })
    }

    pub fn verify_and_extract_text(
        &self,
        signature_header: &str,
        payload: &[u8],
    ) -> Result<Vec<WhatsAppTextEvent>, WhatsAppWebhookError> {
        if payload.len() > MAXIMUM_WEBHOOK_BYTES {
            return Err(WhatsAppWebhookError::PayloadTooLarge);
        }
        let signature = decode_signature(signature_header)?;
        hmac::verify(&self.signature_key, payload, &signature)
            .map_err(|_| WhatsAppWebhookError::InvalidSignature)?;
        let webhook: Webhook =
            serde_json::from_slice(payload).map_err(|_| WhatsAppWebhookError::InvalidPayload)?;
        if webhook.object != "whatsapp_business_account" {
            return Err(WhatsAppWebhookError::InvalidPayload);
        }
        let mut events = Vec::new();
        for entry in webhook.entry {
            for change in entry.changes {
                if change.field != "messages" {
                    continue;
                }
                let account = bounded_identifier(&change.value.metadata.phone_number_id)?;
                for message in change.value.messages {
                    if message.kind != "text" {
                        continue;
                    }
                    if events.len() >= MAXIMUM_MESSAGES {
                        return Err(WhatsAppWebhookError::TooManyMessages);
                    }
                    let sender = bounded_identifier(&message.from)?;
                    let event_id = bounded_identifier(&message.id)?;
                    let received_at_epoch_seconds = message
                        .timestamp
                        .parse::<u64>()
                        .ok()
                        .filter(|timestamp| *timestamp > 0)
                        .ok_or(WhatsAppWebhookError::InvalidPayload)?;
                    let text = message
                        .text
                        .ok_or(WhatsAppWebhookError::InvalidPayload)?
                        .body;
                    if text.trim().is_empty() || text.len() > MAXIMUM_TEXT_BYTES {
                        return Err(WhatsAppWebhookError::InvalidPayload);
                    }
                    events.push(WhatsAppTextEvent {
                        account_lookup_key: lookup_fingerprint(
                            &self.lookup_key,
                            b"account",
                            account,
                        ),
                        sender_lookup_key: lookup_fingerprint(&self.lookup_key, b"sender", sender),
                        event_id: event_id.to_owned(),
                        text,
                        received_at_epoch_seconds,
                    });
                }
            }
        }
        Ok(events)
    }

    /// Authenticates a webhook and admits each text event through Rembrane's
    /// atomic sender-binding and replay boundary.
    ///
    /// Duplicate platform deliveries are ignored. Every other admission
    /// failure is fail-closed and returned to the caller for retry handling.
    pub fn ingest_text<R: ChannelIngressRepository>(
        &self,
        repository: &mut R,
        signature_header: &str,
        payload: &[u8],
        now_epoch_seconds: u64,
        maximum_event_age_seconds: u64,
        replay_window_seconds: u64,
        maximum_events: usize,
    ) -> Result<Vec<VerifiedChannelMessage>, WhatsAppWebhookError> {
        let events = self.verify_and_extract_text(signature_header, payload)?;
        let oldest_accepted = now_epoch_seconds.saturating_sub(maximum_event_age_seconds);
        if events
            .iter()
            .any(|event| event.received_at_epoch_seconds() < oldest_accepted)
        {
            return Err(WhatsAppWebhookError::StaleEvent);
        }
        let mut admitted = Vec::with_capacity(events.len());
        for event in events {
            match repository.accept_bound_channel_event(
                ChannelKind::WhatsAppBusiness,
                event.account_lookup_key(),
                event.sender_lookup_key(),
                event.event_id(),
                event.text(),
                event.received_at_epoch_seconds(),
                now_epoch_seconds,
                replay_window_seconds,
                maximum_events,
            ) {
                Ok(message) => admitted.push(message),
                Err(ApplicationError::AlreadyExists) => {}
                Err(error) => return Err(WhatsAppWebhookError::Admission(error)),
            }
        }
        Ok(admitted)
    }

    /// Authenticates a webhook and durably enqueues each text event through
    /// Rembrane's atomic sender-binding, replay, and encrypted-inbox boundary.
    pub fn ingest_text_durable<R: DurableChannelIngressRepository>(
        &self,
        repository: &mut R,
        signature_header: &str,
        payload: &[u8],
        now_epoch_seconds: u64,
        maximum_event_age_seconds: u64,
        replay_window_seconds: u64,
        maximum_events: usize,
    ) -> Result<Vec<VerifiedChannelMessage>, WhatsAppWebhookError> {
        let events = self.verify_and_extract_text(signature_header, payload)?;
        let oldest_accepted = now_epoch_seconds.saturating_sub(maximum_event_age_seconds);
        if events
            .iter()
            .any(|event| event.received_at_epoch_seconds() < oldest_accepted)
        {
            return Err(WhatsAppWebhookError::StaleEvent);
        }
        let mut admitted = Vec::with_capacity(events.len());
        for event in events {
            match repository.accept_bound_channel_event_to_inbox(
                ChannelKind::WhatsAppBusiness,
                event.account_lookup_key(),
                event.sender_lookup_key(),
                event.event_id(),
                event.text(),
                event.received_at_epoch_seconds(),
                now_epoch_seconds,
                replay_window_seconds,
                maximum_events,
            ) {
                Ok(message) => admitted.push(message),
                Err(ApplicationError::AlreadyExists) => {}
                Err(error) => return Err(WhatsAppWebhookError::Admission(error)),
            }
        }
        Ok(admitted)
    }
}

/// Derives the same pseudonymous account and sender keys used by webhook
/// ingestion, without retaining the deployment-owned lookup secret.
///
/// # Errors
///
/// Rejects weak secrets and malformed platform identifiers.
pub fn derive_binding_lookup_keys(
    mut binding_lookup_secret: Vec<u8>,
    account_identifier: &str,
    sender_identifier: &str,
) -> Result<WhatsAppBindingLookupKeys, WhatsAppWebhookError> {
    if binding_lookup_secret.len() < 32 {
        binding_lookup_secret.zeroize();
        return Err(WhatsAppWebhookError::InvalidConfiguration);
    }
    let account_identifier = match bounded_identifier(account_identifier) {
        Ok(identifier) => identifier,
        Err(error) => {
            binding_lookup_secret.zeroize();
            return Err(error);
        }
    };
    let sender_identifier = match bounded_identifier(sender_identifier) {
        Ok(identifier) => identifier,
        Err(error) => {
            binding_lookup_secret.zeroize();
            return Err(error);
        }
    };
    let key = hmac::Key::new(hmac::HMAC_SHA256, &binding_lookup_secret);
    binding_lookup_secret.zeroize();
    Ok(WhatsAppBindingLookupKeys {
        account_lookup_key: lookup_fingerprint(&key, b"account", account_identifier),
        sender_lookup_key: lookup_fingerprint(&key, b"sender", sender_identifier),
    })
}

impl WhatsAppBindingLookupKeys {
    #[must_use]
    pub fn account_lookup_key(&self) -> &str {
        &self.account_lookup_key
    }

    #[must_use]
    pub fn sender_lookup_key(&self) -> &str {
        &self.sender_lookup_key
    }
}

impl WhatsAppSubscriptionVerifier {
    pub fn new(mut verification_token: Vec<u8>) -> Result<Self, WhatsAppWebhookError> {
        if verification_token.len() < 32
            || verification_token.len() > MAXIMUM_VERIFICATION_TOKEN_BYTES
        {
            verification_token.zeroize();
            return Err(WhatsAppWebhookError::InvalidConfiguration);
        }
        let verification_key = hmac::Key::new(hmac::HMAC_SHA256, &verification_token);
        verification_token.zeroize();
        Ok(Self { verification_key })
    }

    pub fn verify_challenge(
        &self,
        mode: &str,
        supplied_token: &[u8],
        challenge: &str,
    ) -> Result<String, WhatsAppWebhookError> {
        if supplied_token.len() < 32 || supplied_token.len() > MAXIMUM_VERIFICATION_TOKEN_BYTES {
            return Err(WhatsAppWebhookError::InvalidSignature);
        }
        let supplied_key = hmac::Key::new(hmac::HMAC_SHA256, supplied_token);
        let comparison_message = b"rembrane.whatsapp.subscription.v1";
        let supplied_proof = hmac::sign(&supplied_key, comparison_message);
        if mode != "subscribe"
            || challenge.is_empty()
            || challenge.len() > MAXIMUM_CHALLENGE_BYTES
            || challenge.bytes().any(|byte| byte.is_ascii_control())
            || hmac::verify(
                &self.verification_key,
                comparison_message,
                supplied_proof.as_ref(),
            )
            .is_err()
        {
            return Err(WhatsAppWebhookError::InvalidSignature);
        }
        Ok(challenge.to_owned())
    }
}

#[must_use]
pub const fn webhook_http_status(
    result: &Result<Vec<VerifiedChannelMessage>, WhatsAppWebhookError>,
) -> WhatsAppHttpStatus {
    match result {
        Ok(_) => WhatsAppHttpStatus::Ok,
        Err(WhatsAppWebhookError::InvalidSignature) => WhatsAppHttpStatus::Unauthorized,
        Err(WhatsAppWebhookError::InvalidPayload | WhatsAppWebhookError::StaleEvent) => {
            WhatsAppHttpStatus::BadRequest
        }
        Err(WhatsAppWebhookError::PayloadTooLarge) => WhatsAppHttpStatus::PayloadTooLarge,
        Err(WhatsAppWebhookError::TooManyMessages) => WhatsAppHttpStatus::TooManyRequests,
        Err(WhatsAppWebhookError::Admission(
            ApplicationError::AccessDenied | ApplicationError::NotFound,
        )) => WhatsAppHttpStatus::Accepted,
        Err(
            WhatsAppWebhookError::InvalidConfiguration
            | WhatsAppWebhookError::Admission(
                ApplicationError::AlreadyExists
                | ApplicationError::SequenceConflict
                | ApplicationError::StorageUnavailable
                | ApplicationError::Validation(_)
                | ApplicationError::VersionConflict,
            ),
        ) => WhatsAppHttpStatus::ServiceUnavailable,
    }
}

impl WhatsAppTextEvent {
    #[must_use]
    pub fn account_lookup_key(&self) -> &str {
        &self.account_lookup_key
    }

    #[must_use]
    pub fn sender_lookup_key(&self) -> &str {
        &self.sender_lookup_key
    }

    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub const fn received_at_epoch_seconds(&self) -> u64 {
        self.received_at_epoch_seconds
    }
}

fn bounded_identifier(value: &str) -> Result<&str, WhatsAppWebhookError> {
    if value.is_empty()
        || value.len() > MAXIMUM_IDENTIFIER_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(WhatsAppWebhookError::InvalidPayload);
    }
    Ok(value)
}

fn decode_signature(header: &str) -> Result<[u8; 32], WhatsAppWebhookError> {
    let encoded = header
        .strip_prefix("sha256=")
        .filter(|value| value.len() == 64)
        .ok_or(WhatsAppWebhookError::InvalidSignature)?;
    let mut signature = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        signature[index] = (decode_hex(pair[0])? << 4) | decode_hex(pair[1])?;
    }
    Ok(signature)
}

fn decode_hex(value: u8) -> Result<u8, WhatsAppWebhookError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(WhatsAppWebhookError::InvalidSignature),
    }
}

fn lookup_fingerprint(key: &hmac::Key, namespace: &[u8], identifier: &str) -> String {
    let mut input = Vec::with_capacity(namespace.len() + 1 + identifier.len());
    input.extend_from_slice(namespace);
    input.push(0);
    input.extend_from_slice(identifier.as_bytes());
    let digest = hmac::sign(key, &input);
    input.zeroize();
    encode_hex(digest.as_ref())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[derive(Deserialize)]
struct Webhook {
    object: String,
    entry: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    changes: Vec<Change>,
}

#[derive(Deserialize)]
struct Change {
    field: String,
    value: Value,
}

#[derive(Deserialize)]
struct Value {
    metadata: Metadata,
    #[serde(default)]
    messages: Vec<Message>,
}

#[derive(Deserialize)]
struct Metadata {
    phone_number_id: String,
}

#[derive(Deserialize)]
struct Message {
    from: String,
    id: String,
    timestamp: String,
    #[serde(rename = "type")]
    kind: String,
    text: Option<Text>,
}

#[derive(Deserialize)]
struct Text {
    body: String,
}

#[cfg(test)]
mod tests {
    use rembrane_application::{ApplicationError, ChannelIngressRepository};
    use rembrane_contracts::{ChannelKind, VerifiedChannelMessage};
    use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};
    use ring::hmac;

    use super::{
        MAXIMUM_WEBHOOK_BYTES, WhatsAppHttpStatus, WhatsAppSubscriptionVerifier,
        WhatsAppWebhookError, WhatsAppWebhookVerifier, derive_binding_lookup_keys, encode_hex,
        webhook_http_status,
    };

    const PAYLOAD: &[u8] = br#"{
      "object":"whatsapp_business_account",
      "entry":[{"changes":[{"field":"messages","value":{
        "metadata":{"phone_number_id":"15550000001"},
        "messages":[{"from":"15550000002","id":"wamid.opaque-event",
          "timestamp":"1700000000","type":"text",
          "text":{"body":"Continue my flight search"}}]
      }}]}]
    }"#;

    fn verifier() -> WhatsAppWebhookVerifier {
        WhatsAppWebhookVerifier::new(vec![7; 32], vec![9; 32])
            .expect("test secrets should be valid")
    }

    fn signature(payload: &[u8]) -> String {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[7; 32]);
        format!("sha256={}", encode_hex(hmac::sign(&key, payload).as_ref()))
    }

    #[test]
    fn verifies_before_extracting_pseudonymous_bound_event() {
        let events = verifier()
            .verify_and_extract_text(&signature(PAYLOAD), PAYLOAD)
            .expect("valid webhook should pass");
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event.event_id(), "wamid.opaque-event");
        assert_eq!(event.text(), "Continue my flight search");
        assert_eq!(event.received_at_epoch_seconds(), 1_700_000_000);
        assert_eq!(event.account_lookup_key().len(), 64);
        assert_eq!(event.sender_lookup_key().len(), 64);
        assert!(!event.account_lookup_key().contains("15550000001"));
        assert!(!event.sender_lookup_key().contains("15550000002"));
    }

    #[test]
    fn rejects_tampering_bad_headers_and_oversized_payloads() {
        let mut tampered = PAYLOAD.to_vec();
        tampered.push(b' ');
        assert!(matches!(
            verifier().verify_and_extract_text(&signature(PAYLOAD), &tampered),
            Err(WhatsAppWebhookError::InvalidSignature)
        ));
        assert!(matches!(
            verifier().verify_and_extract_text("sha256=ABC", PAYLOAD),
            Err(WhatsAppWebhookError::InvalidSignature)
        ));
        let oversized = vec![0; MAXIMUM_WEBHOOK_BYTES + 1];
        assert!(matches!(
            verifier().verify_and_extract_text(&signature(&oversized), &oversized),
            Err(WhatsAppWebhookError::PayloadTooLarge)
        ));
    }

    struct RecordingIngress {
        calls: usize,
        replay: bool,
    }

    impl ChannelIngressRepository for RecordingIngress {
        fn accept_bound_channel_event(
            &mut self,
            channel: ChannelKind,
            _account_lookup_key: &str,
            _sender_lookup_key: &str,
            event_id: &str,
            text: &str,
            received_at_epoch_seconds: u64,
            _now_epoch_seconds: u64,
            _replay_window_seconds: u64,
            _maximum_events: usize,
        ) -> Result<VerifiedChannelMessage, ApplicationError> {
            self.calls += 1;
            if self.replay {
                return Err(ApplicationError::AlreadyExists);
            }
            VerifiedChannelMessage::from_authenticated_transport(
                channel,
                event_id,
                WorkspaceId::new("workspace_01"),
                PrincipalId::new("principal_01"),
                ClientId::new("client_whatsapp_01"),
                text,
                received_at_epoch_seconds,
            )
            .map_err(|_| ApplicationError::Validation("invalid fixture".to_owned()))
        }
    }

    #[test]
    fn signature_precedes_storage_and_duplicate_delivery_is_idempotent() {
        let mut repository = RecordingIngress {
            calls: 0,
            replay: false,
        };
        let verifier = verifier();
        let bad_signature = format!("sha256={}", "0".repeat(64));
        assert!(matches!(
            verifier.ingest_text(
                &mut repository,
                &bad_signature,
                PAYLOAD,
                1_700_000_001,
                300,
                86_400,
                1_000,
            ),
            Err(WhatsAppWebhookError::InvalidSignature)
        ));
        assert_eq!(repository.calls, 0);

        let admitted = verifier
            .ingest_text(
                &mut repository,
                &signature(PAYLOAD),
                PAYLOAD,
                1_700_000_001,
                300,
                86_400,
                1_000,
            )
            .expect("verified event should be admitted");
        assert_eq!(admitted.len(), 1);
        assert_eq!(repository.calls, 1);

        repository.replay = true;
        let duplicate = verifier
            .ingest_text(
                &mut repository,
                &signature(PAYLOAD),
                PAYLOAD,
                1_700_000_002,
                300,
                86_400,
                1_000,
            )
            .expect("duplicate delivery should be idempotent");
        assert!(duplicate.is_empty());
        assert_eq!(repository.calls, 2);
    }

    #[test]
    fn rejects_stale_events_before_storage_at_an_inclusive_boundary() {
        let mut repository = RecordingIngress {
            calls: 0,
            replay: false,
        };
        let verifier = verifier();

        let accepted = verifier
            .ingest_text(
                &mut repository,
                &signature(PAYLOAD),
                PAYLOAD,
                1_700_000_300,
                300,
                86_400,
                1_000,
            )
            .expect("event exactly at maximum age should be accepted");
        assert_eq!(accepted.len(), 1);
        assert_eq!(repository.calls, 1);

        assert!(matches!(
            verifier.ingest_text(
                &mut repository,
                &signature(PAYLOAD),
                PAYLOAD,
                1_700_000_301,
                300,
                86_400,
                1_000,
            ),
            Err(WhatsAppWebhookError::StaleEvent)
        ));
        assert_eq!(repository.calls, 1);
    }

    #[test]
    fn verifies_subscription_challenges_without_exposing_the_token() {
        let token = vec![11; 32];
        let verifier =
            WhatsAppSubscriptionVerifier::new(token.clone()).expect("test token should be valid");
        assert_eq!(
            verifier
                .verify_challenge("subscribe", &token, "opaque-challenge")
                .expect("matching challenge should pass"),
            "opaque-challenge"
        );
        assert!(matches!(
            verifier.verify_challenge("subscribe", &[12; 32], "opaque-challenge"),
            Err(WhatsAppWebhookError::InvalidSignature)
        ));
        assert!(matches!(
            verifier.verify_challenge("unsubscribe", &token, "opaque-challenge"),
            Err(WhatsAppWebhookError::InvalidSignature)
        ));
    }

    #[test]
    fn maps_webhook_results_to_bounded_non_enumerating_http_outcomes() {
        assert_eq!(webhook_http_status(&Ok(Vec::new())), WhatsAppHttpStatus::Ok);
        assert_eq!(
            webhook_http_status(&Err(WhatsAppWebhookError::InvalidSignature)),
            WhatsAppHttpStatus::Unauthorized
        );
        assert_eq!(
            webhook_http_status(&Err(WhatsAppWebhookError::Admission(
                ApplicationError::NotFound
            ))),
            WhatsAppHttpStatus::Accepted
        );
        assert_eq!(
            webhook_http_status(&Err(WhatsAppWebhookError::Admission(
                ApplicationError::StorageUnavailable
            ))),
            WhatsAppHttpStatus::ServiceUnavailable
        );
    }

    #[test]
    fn onboarding_derives_the_same_pseudonyms_as_verified_ingress() {
        let event = verifier()
            .verify_and_extract_text(&signature(PAYLOAD), PAYLOAD)
            .expect("fixture webhook should verify")
            .pop()
            .expect("fixture should contain one event");
        let binding = derive_binding_lookup_keys(vec![9; 32], "15550000001", "15550000002")
            .expect("binding identifiers should be valid");
        assert_eq!(binding.account_lookup_key(), event.account_lookup_key());
        assert_eq!(binding.sender_lookup_key(), event.sender_lookup_key());
    }
}

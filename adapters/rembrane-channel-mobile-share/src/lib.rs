//! Authenticated, bounded ingestion for explicit user-mediated mobile shares.

use rembrane_application::{
    ApplicationError, ChannelIngressRepository, DurableChannelIngressRepository,
};
use rembrane_contracts::{ChannelKind, VerifiedChannelMessage};
use ring::hmac;
use serde::Deserialize;
use zeroize::Zeroize;

const MAXIMUM_ENVELOPE_BYTES: usize = 64 * 1024;
const MAXIMUM_IDENTIFIER_BYTES: usize = 256;
const MAXIMUM_TEXT_BYTES: usize = 16_384;

pub struct MobileShareVerifier {
    signature_key: hmac::Key,
    lookup_key: hmac::Key,
}

pub struct MobileShareBindingLookupKeys {
    account_lookup_key: String,
    device_lookup_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MobileShareError {
    InvalidConfiguration,
    InvalidSignature,
    InvalidPayload,
    PayloadTooLarge,
    StaleEvent,
    Admission(ApplicationError),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MobileShareEnvelope {
    account_id: String,
    device_id: String,
    event_id: String,
    text: String,
    shared_at_epoch_seconds: u64,
}

impl MobileShareVerifier {
    pub fn new(
        mut signing_secret: Vec<u8>,
        mut binding_lookup_secret: Vec<u8>,
    ) -> Result<Self, MobileShareError> {
        if signing_secret.len() < 32 || binding_lookup_secret.len() < 32 {
            signing_secret.zeroize();
            binding_lookup_secret.zeroize();
            return Err(MobileShareError::InvalidConfiguration);
        }
        let signature_key = hmac::Key::new(hmac::HMAC_SHA256, &signing_secret);
        let lookup_key = hmac::Key::new(hmac::HMAC_SHA256, &binding_lookup_secret);
        signing_secret.zeroize();
        binding_lookup_secret.zeroize();
        Ok(Self {
            signature_key,
            lookup_key,
        })
    }

    pub fn ingest<R: ChannelIngressRepository>(
        &self,
        repository: &mut R,
        signature_header: &str,
        payload: &[u8],
        now_epoch_seconds: u64,
        maximum_event_age_seconds: u64,
        replay_window_seconds: u64,
        maximum_events: usize,
    ) -> Result<Option<VerifiedChannelMessage>, MobileShareError> {
        let event = self.verify(
            signature_header,
            payload,
            now_epoch_seconds,
            maximum_event_age_seconds,
        )?;
        match repository.accept_bound_channel_event(
            ChannelKind::MobileShare,
            &event.account_lookup_key,
            &event.sender_lookup_key,
            &event.event_id,
            &event.text,
            event.received_at_epoch_seconds,
            now_epoch_seconds,
            replay_window_seconds,
            maximum_events,
        ) {
            Ok(message) => Ok(Some(message)),
            Err(ApplicationError::AlreadyExists) => Ok(None),
            Err(error) => Err(MobileShareError::Admission(error)),
        }
    }

    pub fn ingest_durable<R: DurableChannelIngressRepository>(
        &self,
        repository: &mut R,
        signature_header: &str,
        payload: &[u8],
        now_epoch_seconds: u64,
        maximum_event_age_seconds: u64,
        replay_window_seconds: u64,
        maximum_events: usize,
    ) -> Result<Option<VerifiedChannelMessage>, MobileShareError> {
        let event = self.verify(
            signature_header,
            payload,
            now_epoch_seconds,
            maximum_event_age_seconds,
        )?;
        match repository.accept_bound_channel_event_to_inbox(
            ChannelKind::MobileShare,
            &event.account_lookup_key,
            &event.sender_lookup_key,
            &event.event_id,
            &event.text,
            event.received_at_epoch_seconds,
            now_epoch_seconds,
            replay_window_seconds,
            maximum_events,
        ) {
            Ok(message) => Ok(Some(message)),
            Err(ApplicationError::AlreadyExists) => Ok(None),
            Err(error) => Err(MobileShareError::Admission(error)),
        }
    }

    fn verify(
        &self,
        signature_header: &str,
        payload: &[u8],
        now_epoch_seconds: u64,
        maximum_event_age_seconds: u64,
    ) -> Result<BoundMobileShare, MobileShareError> {
        if payload.len() > MAXIMUM_ENVELOPE_BYTES {
            return Err(MobileShareError::PayloadTooLarge);
        }
        let signature = decode_signature(signature_header)?;
        hmac::verify(&self.signature_key, payload, &signature)
            .map_err(|_| MobileShareError::InvalidSignature)?;
        let envelope: MobileShareEnvelope =
            serde_json::from_slice(payload).map_err(|_| MobileShareError::InvalidPayload)?;
        let account_id = bounded_identifier(&envelope.account_id)?;
        let device_id = bounded_identifier(&envelope.device_id)?;
        let event_id = bounded_identifier(&envelope.event_id)?;
        if envelope.text.trim().is_empty()
            || envelope.text.len() > MAXIMUM_TEXT_BYTES
            || envelope.shared_at_epoch_seconds == 0
            || envelope.shared_at_epoch_seconds > now_epoch_seconds
        {
            return Err(MobileShareError::InvalidPayload);
        }
        let oldest_accepted = now_epoch_seconds.saturating_sub(maximum_event_age_seconds);
        if envelope.shared_at_epoch_seconds < oldest_accepted {
            return Err(MobileShareError::StaleEvent);
        }
        Ok(BoundMobileShare {
            account_lookup_key: lookup_fingerprint(&self.lookup_key, b"account", account_id),
            sender_lookup_key: lookup_fingerprint(&self.lookup_key, b"device", device_id),
            event_id: event_id.to_owned(),
            text: envelope.text,
            received_at_epoch_seconds: envelope.shared_at_epoch_seconds,
        })
    }
}

/// Derives the pseudonymous identifiers used to enroll a mobile-share device
/// without retaining its raw account or device identifiers.
pub fn derive_binding_lookup_keys(
    mut binding_lookup_secret: Vec<u8>,
    account_identifier: &str,
    device_identifier: &str,
) -> Result<MobileShareBindingLookupKeys, MobileShareError> {
    if binding_lookup_secret.len() < 32 {
        binding_lookup_secret.zeroize();
        return Err(MobileShareError::InvalidConfiguration);
    }
    let account_identifier = match bounded_identifier(account_identifier) {
        Ok(identifier) => identifier,
        Err(error) => {
            binding_lookup_secret.zeroize();
            return Err(error);
        }
    };
    let device_identifier = match bounded_identifier(device_identifier) {
        Ok(identifier) => identifier,
        Err(error) => {
            binding_lookup_secret.zeroize();
            return Err(error);
        }
    };
    let key = hmac::Key::new(hmac::HMAC_SHA256, &binding_lookup_secret);
    binding_lookup_secret.zeroize();
    Ok(MobileShareBindingLookupKeys {
        account_lookup_key: lookup_fingerprint(&key, b"account", account_identifier),
        device_lookup_key: lookup_fingerprint(&key, b"device", device_identifier),
    })
}

impl MobileShareBindingLookupKeys {
    #[must_use]
    pub fn account_lookup_key(&self) -> &str {
        &self.account_lookup_key
    }

    #[must_use]
    pub fn device_lookup_key(&self) -> &str {
        &self.device_lookup_key
    }
}

struct BoundMobileShare {
    account_lookup_key: String,
    sender_lookup_key: String,
    event_id: String,
    text: String,
    received_at_epoch_seconds: u64,
}

fn bounded_identifier(value: &str) -> Result<&str, MobileShareError> {
    if value.is_empty()
        || value.len() > MAXIMUM_IDENTIFIER_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(MobileShareError::InvalidPayload);
    }
    Ok(value)
}

fn lookup_fingerprint(key: &hmac::Key, domain: &[u8], value: &str) -> String {
    let mut input = Vec::with_capacity(domain.len() + value.len() + 1);
    input.extend_from_slice(domain);
    input.push(0);
    input.extend_from_slice(value.as_bytes());
    encode_hex(hmac::sign(key, &input).as_ref())
}

fn decode_signature(header: &str) -> Result<Vec<u8>, MobileShareError> {
    let encoded = header
        .strip_prefix("sha256=")
        .ok_or(MobileShareError::InvalidSignature)?;
    if encoded.len() != 64 {
        return Err(MobileShareError::InvalidSignature);
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = decode_hex_digit(pair[0]).ok_or(MobileShareError::InvalidSignature)?;
            let low = decode_hex_digit(pair[1]).ok_or(MobileShareError::InvalidSignature)?;
            Ok((high << 4) | low)
        })
        .collect()
}

const fn decode_hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use rembrane_application::{ApplicationError, ChannelIngressRepository};
    use rembrane_contracts::{ChannelKind, VerifiedChannelMessage};
    use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};
    use ring::hmac;

    use super::{MobileShareError, MobileShareVerifier, derive_binding_lookup_keys, encode_hex};

    #[derive(Default)]
    struct Repository {
        accepted: bool,
    }

    impl ChannelIngressRepository for Repository {
        fn accept_bound_channel_event(
            &mut self,
            channel: ChannelKind,
            account_lookup_key: &str,
            sender_lookup_key: &str,
            event_id: &str,
            text: &str,
            received_at_epoch_seconds: u64,
            _now_epoch_seconds: u64,
            _replay_window_seconds: u64,
            _maximum_events: usize,
        ) -> Result<VerifiedChannelMessage, ApplicationError> {
            if self.accepted {
                return Err(ApplicationError::AlreadyExists);
            }
            self.accepted = true;
            assert_eq!(channel, ChannelKind::MobileShare);
            assert_eq!(account_lookup_key.len(), 64);
            assert_eq!(sender_lookup_key.len(), 64);
            VerifiedChannelMessage::from_authenticated_transport(
                channel,
                event_id,
                WorkspaceId::new("workspace_01"),
                PrincipalId::new("principal_01"),
                ClientId::new("client_mobile_01"),
                text,
                received_at_epoch_seconds,
            )
            .map_err(|_| ApplicationError::Validation("invalid fixture".to_owned()))
        }
    }

    fn fixture() -> (MobileShareVerifier, Vec<u8>, String) {
        let secret = vec![7; 32];
        let payload = br#"{"account_id":"account_01","device_id":"device_01","event_id":"share_01","text":"Continue this research","shared_at_epoch_seconds":1000}"#.to_vec();
        let key = hmac::Key::new(hmac::HMAC_SHA256, &secret);
        let signature = format!("sha256={}", encode_hex(hmac::sign(&key, &payload).as_ref()));
        (
            MobileShareVerifier::new(secret, vec![9; 32]).expect("valid verifier"),
            payload,
            signature,
        )
    }

    #[test]
    fn authenticates_explicit_share_and_treats_replay_idempotently() {
        let (verifier, payload, signature) = fixture();
        let mut repository = Repository::default();
        let admitted = verifier
            .ingest(&mut repository, &signature, &payload, 1_010, 30, 300, 10)
            .expect("share should verify")
            .expect("first delivery should admit");
        assert_eq!(admitted.text(), "Continue this research");
        assert!(
            verifier
                .ingest(&mut repository, &signature, &payload, 1_010, 30, 300, 10)
                .expect("replay should be idempotent")
                .is_none()
        );
    }

    #[test]
    fn rejects_tampering_future_time_and_stale_events() {
        let (verifier, mut payload, signature) = fixture();
        payload[20] ^= 1;
        assert_eq!(
            verifier
                .ingest(
                    &mut Repository::default(),
                    &signature,
                    &payload,
                    1_010,
                    30,
                    300,
                    10,
                )
                .expect_err("tampering must fail"),
            MobileShareError::InvalidSignature
        );

        let (verifier, payload, signature) = fixture();
        assert_eq!(
            verifier
                .ingest(
                    &mut Repository::default(),
                    &signature,
                    &payload,
                    999,
                    30,
                    300,
                    10,
                )
                .expect_err("future share must fail"),
            MobileShareError::InvalidPayload
        );
        assert_eq!(
            verifier
                .ingest(
                    &mut Repository::default(),
                    &signature,
                    &payload,
                    1_100,
                    30,
                    300,
                    10,
                )
                .expect_err("stale share must fail"),
            MobileShareError::StaleEvent
        );
    }

    #[test]
    fn enrollment_derives_the_same_pseudonyms_as_ingestion() {
        let lookup =
            derive_binding_lookup_keys(vec![9; 32], "account_01", "device_01").expect("valid");
        assert_eq!(lookup.account_lookup_key().len(), 64);
        assert_eq!(lookup.device_lookup_key().len(), 64);
        assert!(!lookup.account_lookup_key().contains("account_01"));
        assert!(!lookup.device_lookup_key().contains("device_01"));
    }
}

//! Authenticated bounded HTTP delivery for trusted bot and agent processors.

use std::io::Read;
use std::time::Duration;

use rembrane_application::{ApplicationError, ChannelMessageProcessor};
use rembrane_contracts::VerifiedChannelMessage;
use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const MAXIMUM_RESPONSE_BYTES: u64 = 4_096;
const MAXIMUM_REQUEST_BYTES: usize = 262_144;
const MAXIMUM_BEARER_BYTES: usize = 8_192;
const PROTOCOL_VERSION: &str = "0.1";
const PROCESSING_TIMEOUT_SECONDS: u64 = 20;

pub struct HttpChannelMessageProcessor {
    client: Client,
    endpoint: Url,
    bearer_token: Zeroizing<String>,
}

impl HttpChannelMessageProcessor {
    /// Creates a strict HTTP processor for one deployment-owned bot endpoint.
    ///
    /// HTTPS is mandatory except on exact loopback hosts. Redirects and
    /// ambient proxy configuration are disabled.
    pub fn new(
        base_url: &str,
        bearer_token: impl Into<Zeroizing<String>>,
    ) -> Result<Self, ApplicationError> {
        let bearer_token = bearer_token.into();
        validate_bearer_token(&bearer_token)?;
        let base_url = validate_base_url(base_url)?;
        let endpoint = base_url
            .join("v1/channel/messages")
            .map_err(|_| invalid_configuration())?;
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(PROCESSING_TIMEOUT_SECONDS))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| invalid_configuration())?;
        Ok(Self {
            client,
            endpoint,
            bearer_token,
        })
    }
}

impl ChannelMessageProcessor for HttpChannelMessageProcessor {
    fn maximum_processing_seconds(&self) -> u64 {
        PROCESSING_TIMEOUT_SECONDS
    }

    fn process_channel_message(
        &mut self,
        message: &VerifiedChannelMessage,
    ) -> Result<(), ApplicationError> {
        let body = DeliveryBody::from(message);
        let encoded = Zeroizing::new(
            serde_json::to_vec(&body).map_err(|_| ApplicationError::StorageUnavailable)?,
        );
        if encoded.len() > MAXIMUM_REQUEST_BYTES {
            return Err(ApplicationError::StorageUnavailable);
        }
        let response = self
            .client
            .post(self.endpoint.clone())
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header("x-rembrane-protocol-version", PROTOCOL_VERSION)
            .header("x-rembrane-channel-event-id", message.event_id())
            .bearer_auth(self.bearer_token.as_str())
            .body(bytes::Bytes::from_owner(encoded))
            .send()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        if !response.status().is_success()
            || !response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(is_json_content_type)
            || response
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|length| length > MAXIMUM_RESPONSE_BYTES)
        {
            return Err(ApplicationError::StorageUnavailable);
        }
        let mut bounded = Zeroizing::new(Vec::new());
        response
            .take(MAXIMUM_RESPONSE_BYTES + 1)
            .read_to_end(&mut bounded)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        if bounded.len() as u64 > MAXIMUM_RESPONSE_BYTES {
            return Err(ApplicationError::StorageUnavailable);
        }
        validate_acknowledgement(bounded.as_slice(), message.event_id())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DeliveryAcknowledgement {
    protocol_version: String,
    event_id: String,
    status: DeliveryStatus,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DeliveryStatus {
    Processed,
    Duplicate,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeliveryBody<'message> {
    protocol_version: &'static str,
    channel: &'static str,
    event_id: &'message str,
    workspace_id: &'message str,
    principal_id: &'message str,
    client_id: &'message str,
    text: &'message str,
    received_at_epoch_seconds: u64,
}

impl<'message> From<&'message VerifiedChannelMessage> for DeliveryBody<'message> {
    fn from(message: &'message VerifiedChannelMessage) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            channel: message.channel().label(),
            event_id: message.event_id(),
            workspace_id: message.workspace_id().as_str(),
            principal_id: message.principal_id().as_str(),
            client_id: message.client_id().as_str(),
            text: message.text(),
            received_at_epoch_seconds: message.received_at_epoch_seconds(),
        }
    }
}

fn validate_base_url(value: &str) -> Result<Url, ApplicationError> {
    let mut url = Url::parse(value).map_err(|_| invalid_configuration())?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(invalid_configuration());
    }
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "::1"));
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(invalid_configuration());
    }
    url.set_path("/");
    Ok(url)
}

fn validate_bearer_token(value: &str) -> Result<(), ApplicationError> {
    if value.is_empty()
        || value.len() > MAXIMUM_BEARER_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'~' | b'+' | b'/' | b'=' | b'-')
        })
    {
        return Err(invalid_configuration());
    }
    Ok(())
}

fn is_json_content_type(value: &str) -> bool {
    value
        .split_once(';')
        .map_or(value, |(media_type, _)| media_type)
        .trim()
        .eq_ignore_ascii_case("application/json")
}

fn validate_acknowledgement(
    encoded: &[u8],
    expected_event_id: &str,
) -> Result<(), ApplicationError> {
    let acknowledgement: DeliveryAcknowledgement =
        serde_json::from_slice(encoded).map_err(|_| ApplicationError::StorageUnavailable)?;
    if acknowledgement.protocol_version != PROTOCOL_VERSION
        || acknowledgement.event_id != expected_event_id
    {
        return Err(ApplicationError::StorageUnavailable);
    }
    match acknowledgement.status {
        DeliveryStatus::Processed | DeliveryStatus::Duplicate => Ok(()),
    }
}

fn invalid_configuration() -> ApplicationError {
    ApplicationError::Validation("channel processor HTTP configuration is invalid".to_owned())
}

#[cfg(test)]
mod tests {
    use rembrane_contracts::{ChannelKind, VerifiedChannelMessage};
    use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};

    use super::{
        DeliveryBody, HttpChannelMessageProcessor, is_json_content_type, validate_acknowledgement,
    };

    #[test]
    fn accepts_https_and_exact_loopback_but_rejects_unsafe_origins() {
        assert!(
            HttpChannelMessageProcessor::new("https://bot.example", "token_01".to_owned()).is_ok()
        );
        assert!(
            HttpChannelMessageProcessor::new("http://127.0.0.1:9000", "token_01".to_owned())
                .is_ok()
        );
        for origin in [
            "http://bot.example",
            "http://localhost:9000",
            "https://user@bot.example",
            "https://bot.example/path",
            "https://bot.example?query=1",
        ] {
            assert!(
                HttpChannelMessageProcessor::new(origin, "token_01".to_owned()).is_err(),
                "{origin} must fail"
            );
        }
    }

    #[test]
    fn wire_body_carries_canonical_identity_and_idempotency_key() {
        let message = VerifiedChannelMessage::from_authenticated_transport(
            ChannelKind::WhatsAppBusiness,
            "wamid.opaque",
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            ClientId::new("client_01"),
            "continue",
            1_000,
        )
        .expect("message should validate");
        let encoded =
            serde_json::to_value(DeliveryBody::from(&message)).expect("wire body should encode");
        assert_eq!(encoded["eventId"], "wamid.opaque");
        assert_eq!(encoded["workspaceId"], "workspace_01");
        assert_eq!(encoded["channel"], "whatsapp-business");
        assert_eq!(encoded["text"], "continue");
    }

    #[test]
    fn wire_body_matches_language_neutral_protocol_fixture() {
        let message = VerifiedChannelMessage::from_authenticated_transport(
            ChannelKind::WhatsAppBusiness,
            "wamid.opaque-example-event",
            WorkspaceId::new("workspace_example"),
            PrincipalId::new("principal_example"),
            ClientId::new("client_whatsapp_example"),
            "Continue my flight research",
            1_792_890_000,
        )
        .expect("protocol fixture should form a valid channel message");
        let encoded =
            serde_json::to_value(DeliveryBody::from(&message)).expect("wire body should encode");
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../spec/examples/channel-processor-message.json"
        ))
        .expect("published processor fixture should be valid JSON");

        assert_eq!(encoded, fixture);
    }

    #[test]
    fn accepts_only_event_bound_json_acknowledgements() {
        let fixture =
            include_bytes!("../../../spec/examples/channel-processor-acknowledgement.json");
        assert!(validate_acknowledgement(fixture, "wamid.opaque-example-event").is_ok());
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("Application/Json; charset=utf-8"));
        assert!(!is_json_content_type("text/html"));

        for invalid in [
            br#"{"protocolVersion":"0.2","eventId":"wamid.opaque-example-event","status":"processed"}"#
                .as_slice(),
            br#"{"protocolVersion":"0.1","eventId":"other-event","status":"processed"}"#.as_slice(),
            br#"{"protocolVersion":"0.1","eventId":"wamid.opaque-example-event","status":"unknown"}"#
                .as_slice(),
            br#"{"protocolVersion":"0.1","eventId":"wamid.opaque-example-event","status":"processed","ignored":true}"#
                .as_slice(),
            b"<html>accepted</html>".as_slice(),
        ] {
            assert!(
                validate_acknowledgement(invalid, "wamid.opaque-example-event").is_err(),
                "unbound or malformed acknowledgement must fail"
            );
        }
    }
}

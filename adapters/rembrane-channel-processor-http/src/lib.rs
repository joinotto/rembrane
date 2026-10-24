//! Authenticated bounded HTTP delivery for trusted bot and agent processors.

use std::io::Read;
use std::time::Duration;

use rembrane_application::{ApplicationError, ChannelMessageProcessor};
use rembrane_contracts::VerifiedChannelMessage;
use reqwest::Url;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use serde::Serialize;
use zeroize::Zeroizing;

const MAXIMUM_RESPONSE_BYTES: u64 = 4_096;
const MAXIMUM_BEARER_BYTES: usize = 8_192;
const PROTOCOL_VERSION: &str = "0.1";

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
    pub fn new(base_url: &str, bearer_token: String) -> Result<Self, ApplicationError> {
        let bearer_token = Zeroizing::new(bearer_token);
        validate_bearer_token(&bearer_token)?;
        let base_url = validate_base_url(base_url)?;
        let endpoint = base_url
            .join("v1/channel/messages")
            .map_err(|_| invalid_configuration())?;
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
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
    fn process_channel_message(
        &mut self,
        message: &VerifiedChannelMessage,
    ) -> Result<(), ApplicationError> {
        let body = DeliveryBody::from(message);
        let encoded =
            serde_json::to_vec(&body).map_err(|_| ApplicationError::StorageUnavailable)?;
        let response = self
            .client
            .post(self.endpoint.clone())
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .header("x-rembrane-protocol-version", PROTOCOL_VERSION)
            .header("x-rembrane-channel-event-id", message.event_id())
            .bearer_auth(self.bearer_token.as_str())
            .body(encoded)
            .send()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        if !response.status().is_success()
            || response
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|length| length > MAXIMUM_RESPONSE_BYTES)
        {
            return Err(ApplicationError::StorageUnavailable);
        }
        let mut bounded = Vec::new();
        response
            .take(MAXIMUM_RESPONSE_BYTES + 1)
            .read_to_end(&mut bounded)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        if bounded.len() as u64 > MAXIMUM_RESPONSE_BYTES {
            return Err(ApplicationError::StorageUnavailable);
        }
        Ok(())
    }
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
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "::1" | "localhost"));
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

fn invalid_configuration() -> ApplicationError {
    ApplicationError::Validation("channel processor HTTP configuration is invalid".to_owned())
}

#[cfg(test)]
mod tests {
    use rembrane_contracts::{ChannelKind, VerifiedChannelMessage};
    use rembrane_domain::{ClientId, PrincipalId, WorkspaceId};

    use super::{DeliveryBody, HttpChannelMessageProcessor};

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
}

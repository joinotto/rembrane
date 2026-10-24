//! Bounded HTTPS implementation of the OAuth introspection transport.

use std::io::Read;
use std::time::Duration;

use rembrane_oauth_introspection::{
    IntrospectionResponse, IntrospectionTransport, IntrospectionTransportError,
};
use reqwest::blocking::Client;
use serde::Deserialize;
use zeroize::Zeroizing;

const MAXIMUM_RESPONSE_BYTES: u64 = 65_536;

pub struct HttpIntrospectionTransport {
    client: Client,
    endpoint: String,
    client_id: String,
    client_secret: Zeroizing<String>,
}

impl HttpIntrospectionTransport {
    /// Creates a bounded RFC 7662 transport.
    ///
    /// # Errors
    ///
    /// Returns an error when the endpoint is not HTTPS, credentials are empty,
    /// or the bounded HTTP client cannot be constructed.
    pub fn new(
        endpoint: String,
        client_id: String,
        client_secret: String,
    ) -> Result<Self, IntrospectionTransportError> {
        if !endpoint.starts_with("https://") || client_id.is_empty() || client_secret.is_empty() {
            return Err(IntrospectionTransportError);
        }
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .build()
            .map_err(|_| IntrospectionTransportError)?;
        Ok(Self {
            client,
            endpoint,
            client_id,
            client_secret: Zeroizing::new(client_secret),
        })
    }
}

impl IntrospectionTransport for HttpIntrospectionTransport {
    fn introspect(
        &self,
        token: &str,
    ) -> Result<IntrospectionResponse, IntrospectionTransportError> {
        let response = self
            .client
            .post(&self.endpoint)
            .basic_auth(&self.client_id, Some(self.client_secret.as_str()))
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[("token", token), ("token_type_hint", "access_token")])
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(|_| IntrospectionTransportError)?;
        if response
            .content_length()
            .is_some_and(|length| length > MAXIMUM_RESPONSE_BYTES)
        {
            return Err(IntrospectionTransportError);
        }
        let mut body = Vec::new();
        response
            .take(MAXIMUM_RESPONSE_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| IntrospectionTransportError)?;
        if body.len() as u64 > MAXIMUM_RESPONSE_BYTES {
            return Err(IntrospectionTransportError);
        }
        let wire: WireResponse =
            serde_json::from_slice(&body).map_err(|_| IntrospectionTransportError)?;
        Ok(IntrospectionResponse {
            active: wire.active,
            issuer: wire.issuer,
            audience: wire.audience.into_vec(),
            subject: wire.subject,
            client_id: wire.client_id,
            workspace_id: wire.workspace_id,
            scope: wire.scope,
            expires_at_epoch_seconds: wire.expires_at_epoch_seconds,
            not_before_epoch_seconds: wire.not_before_epoch_seconds,
        })
    }
}

#[derive(Deserialize)]
struct WireResponse {
    active: bool,
    #[serde(rename = "iss")]
    issuer: Option<String>,
    #[serde(default, rename = "aud")]
    audience: Audience,
    #[serde(rename = "sub")]
    subject: Option<String>,
    client_id: Option<String>,
    workspace_id: Option<String>,
    scope: Option<String>,
    #[serde(rename = "exp")]
    expires_at_epoch_seconds: Option<u64>,
    #[serde(rename = "nbf")]
    not_before_epoch_seconds: Option<u64>,
}

#[derive(Default, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
    #[default]
    Missing,
}

impl Audience {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
            Self::Missing => Vec::new(),
        }
    }
}

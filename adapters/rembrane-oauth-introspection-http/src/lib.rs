//! Bounded HTTPS implementation of the OAuth introspection transport.

use std::io::Read;
use std::time::Duration;

use rembrane_config::RemoteMcpConfig;
use rembrane_oauth_introspection::{
    IntrospectionResponse, IntrospectionTransport, IntrospectionTransportError,
    MAX_REMOTE_AUDIENCE_BYTES, MAX_REMOTE_AUDIENCES, MAXIMUM_SCOPE_BYTES,
};
use rembrane_secret_local::SecretResolver;
use reqwest::Url;
use reqwest::blocking::{Client, Request};
use serde::Deserialize;
use zeroize::Zeroizing;

const MAXIMUM_RESPONSE_BYTES: u64 = 65_536;
const MAXIMUM_CLIENT_ID_BYTES: usize = 255;
const MAXIMUM_CLIENT_SECRET_BYTES: usize = 4_096;
const MAXIMUM_TOKEN_BYTES: usize = 8_192;

pub struct HttpIntrospectionTransport {
    client: Client,
    endpoint: Url,
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
        endpoint: impl AsRef<str>,
        client_id: String,
        client_secret: String,
    ) -> Result<Self, IntrospectionTransportError> {
        Self::new_with_secret(endpoint.as_ref(), client_id, Zeroizing::new(client_secret))
    }

    /// Resolves the client secret referenced by a validated remote MCP profile.
    ///
    /// # Errors
    ///
    /// Returns an opaque error when secret resolution or transport
    /// construction fails.
    pub fn from_config<Resolver>(
        config: &RemoteMcpConfig,
        resolver: &Resolver,
    ) -> Result<Self, IntrospectionTransportError>
    where
        Resolver: SecretResolver + ?Sized,
    {
        let client_secret = resolver
            .resolve(config.introspection_client_secret())
            .map_err(|_| IntrospectionTransportError)?;
        Self::new_with_secret(
            config.introspection_endpoint(),
            config.introspection_client_id().to_owned(),
            client_secret,
        )
    }

    fn new_with_secret(
        endpoint: &str,
        client_id: String,
        client_secret: Zeroizing<String>,
    ) -> Result<Self, IntrospectionTransportError> {
        let endpoint = validate_endpoint(endpoint)?;
        validate_client_id(&client_id)?;
        validate_secret(&client_secret)?;
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .no_proxy()
            .build()
            .map_err(|_| IntrospectionTransportError)?;
        Ok(Self {
            client,
            endpoint,
            client_id,
            client_secret,
        })
    }

    fn build_request(&self, token: &str) -> Result<Request, IntrospectionTransportError> {
        validate_token(token)?;
        let body = introspection_form_body(token)?;
        self.client
            .post(self.endpoint.clone())
            .basic_auth(&self.client_id, Some(self.client_secret.as_str()))
            .header(reqwest::header::ACCEPT, "application/json")
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(bytes::Bytes::from_owner(body))
            .build()
            .map_err(|_| IntrospectionTransportError)
    }
}

fn introspection_form_body(token: &str) -> Result<Zeroizing<Vec<u8>>, IntrospectionTransportError> {
    validate_token(token)?;
    let mut body = Zeroizing::new(Vec::with_capacity(token.len() * 3 + 42));
    body.extend_from_slice(b"token=");
    for byte in token.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'*' | b'-' | b'.' | b'_') {
            body.push(byte);
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            body.push(b'%');
            body.push(HEX[usize::from(byte >> 4)]);
            body.push(HEX[usize::from(byte & 0x0f)]);
        }
    }
    body.extend_from_slice(b"&token_type_hint=access_token");
    if body.len() > MAXIMUM_TOKEN_BYTES * 3 + 42 {
        return Err(IntrospectionTransportError);
    }
    Ok(body)
}

impl IntrospectionTransport for HttpIntrospectionTransport {
    fn introspect(
        &self,
        token: &str,
    ) -> Result<IntrospectionResponse, IntrospectionTransportError> {
        let request = self.build_request(token)?;
        let response = self
            .client
            .execute(request)
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(|_| IntrospectionTransportError)?;
        if !response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(is_json_content_type)
        {
            return Err(IntrospectionTransportError);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAXIMUM_RESPONSE_BYTES)
        {
            return Err(IntrospectionTransportError);
        }
        let mut body = Zeroizing::new(Vec::new());
        response
            .take(MAXIMUM_RESPONSE_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| IntrospectionTransportError)?;
        if body.len() as u64 > MAXIMUM_RESPONSE_BYTES {
            return Err(IntrospectionTransportError);
        }
        decode_response(body.as_slice())
    }
}

fn validate_endpoint(endpoint: &str) -> Result<Url, IntrospectionTransportError> {
    let endpoint = Url::parse(endpoint).map_err(|_| IntrospectionTransportError)?;
    if endpoint.scheme() != "https"
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(IntrospectionTransportError);
    }
    Ok(endpoint)
}

fn is_json_content_type(value: &str) -> bool {
    value
        .split_once(';')
        .map_or(value, |(media_type, _)| media_type)
        .trim()
        .eq_ignore_ascii_case("application/json")
}

fn validate_client_id(client_id: &str) -> Result<(), IntrospectionTransportError> {
    if client_id.is_empty()
        || client_id.len() > MAXIMUM_CLIENT_ID_BYTES
        || !client_id.is_ascii()
        || client_id
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b':')
    {
        return Err(IntrospectionTransportError);
    }
    Ok(())
}

fn validate_secret(secret: &str) -> Result<(), IntrospectionTransportError> {
    if secret.is_empty()
        || secret.len() > MAXIMUM_CLIENT_SECRET_BYTES
        || secret.chars().any(char::is_control)
    {
        return Err(IntrospectionTransportError);
    }
    Ok(())
}

fn validate_token(token: &str) -> Result<(), IntrospectionTransportError> {
    if token.is_empty()
        || token.len() > MAXIMUM_TOKEN_BYTES
        || !token.is_ascii()
        || token
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(IntrospectionTransportError);
    }
    Ok(())
}

fn decode_response(body: &[u8]) -> Result<IntrospectionResponse, IntrospectionTransportError> {
    let wire: WireResponse =
        serde_json::from_slice(body).map_err(|_| IntrospectionTransportError)?;
    let audience = wire.audience.into_vec();
    if audience.len() > MAX_REMOTE_AUDIENCES
        || audience
            .iter()
            .any(|value| value.len() > MAX_REMOTE_AUDIENCE_BYTES)
        || wire
            .scope
            .as_ref()
            .is_some_and(|scope| scope.len() > MAXIMUM_SCOPE_BYTES)
    {
        return Err(IntrospectionTransportError);
    }
    Ok(IntrospectionResponse {
        active: wire.active,
        issuer: wire.issuer,
        audience,
        subject: wire.subject,
        client_id: wire.client_id,
        workspace_id: wire.workspace_id,
        scope: wire.scope,
        expires_at_epoch_seconds: wire.expires_at_epoch_seconds,
        not_before_epoch_seconds: wire.not_before_epoch_seconds,
    })
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

#[cfg(test)]
mod tests {
    use rembrane_config::{RemoteMcpConfig, SecretReference};
    use rembrane_secret_local::{SecretResolutionError, SecretResolver};
    use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
    use zeroize::Zeroizing;

    use super::{
        HttpIntrospectionTransport, MAXIMUM_CLIENT_ID_BYTES, MAXIMUM_CLIENT_SECRET_BYTES,
        MAXIMUM_TOKEN_BYTES, decode_response, introspection_form_body, is_json_content_type,
    };
    use rembrane_oauth_introspection::{
        MAX_REMOTE_AUDIENCE_BYTES, MAX_REMOTE_AUDIENCES, MAXIMUM_SCOPE_BYTES,
    };

    #[test]
    fn rejects_unsafe_endpoints_credentials_and_tokens_before_network_access() {
        for endpoint in [
            "http://identity.example.test/introspect",
            "https://user:secret@identity.example.test/introspect",
            "https://identity.example.test/introspect?client=ambiguous",
            "https://identity.example.test/introspect#fragment",
            "httpsx://identity.example.test/introspect",
        ] {
            assert!(
                HttpIntrospectionTransport::new(
                    endpoint,
                    "rembrane".to_owned(),
                    "client-secret".to_owned(),
                )
                .is_err()
            );
        }
        assert!(
            HttpIntrospectionTransport::new(
                "https://identity.example.test/introspect",
                "bad:id".to_owned(),
                "client-secret".to_owned(),
            )
            .is_err()
        );
        assert!(
            HttpIntrospectionTransport::new(
                "https://identity.example.test/introspect",
                "x".repeat(MAXIMUM_CLIENT_ID_BYTES + 1),
                "client-secret".to_owned(),
            )
            .is_err()
        );
        assert!(
            HttpIntrospectionTransport::new(
                "https://identity.example.test/introspect",
                "rembrane".to_owned(),
                "x".repeat(MAXIMUM_CLIENT_SECRET_BYTES + 1),
            )
            .is_err()
        );

        let transport = HttpIntrospectionTransport::new(
            "https://identity.example.test/introspect",
            "rembrane".to_owned(),
            "client-secret".to_owned(),
        )
        .expect("safe transport");
        for token in ["", "token with spaces", "token\r\ninjected"] {
            assert!(transport.build_request(token).is_err());
        }
        assert!(
            transport
                .build_request(&"x".repeat(MAXIMUM_TOKEN_BYTES + 1))
                .is_err()
        );
    }

    #[test]
    fn accepts_only_json_introspection_media_types() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("Application/JSON; charset=utf-8"));
        for invalid in ["", "text/plain", "application/problem+json", "text/html"] {
            assert!(!is_json_content_type(invalid));
        }
    }

    #[test]
    fn builds_exact_authenticated_rfc7662_request_without_a_socket() {
        let transport = HttpIntrospectionTransport::new(
            "https://identity.example.test/oauth/introspect",
            "rembrane".to_owned(),
            "client-secret".to_owned(),
        )
        .expect("safe transport");
        let request = transport
            .build_request("opaque-access-token")
            .expect("request");

        assert_eq!(request.method(), reqwest::Method::POST);
        assert_eq!(
            request.url().as_str(),
            "https://identity.example.test/oauth/introspect"
        );
        assert_eq!(request.headers()[ACCEPT], "application/json");
        assert_eq!(
            request.headers()[CONTENT_TYPE],
            "application/x-www-form-urlencoded"
        );
        assert_eq!(
            request.headers()[AUTHORIZATION],
            "Basic cmVtYnJhbmU6Y2xpZW50LXNlY3JldA=="
        );
        assert_eq!(
            request
                .body()
                .and_then(reqwest::blocking::Body::as_bytes)
                .expect("form body"),
            b"token=opaque-access-token&token_type_hint=access_token"
        );
    }

    #[test]
    fn introspection_form_encodes_token_delimiters_without_parameter_injection() {
        let body = introspection_form_body("opaque&token=other+/%~")
            .expect("header-safe token should be form encoded");
        assert_eq!(
            body.as_slice(),
            b"token=opaque%26token%3Dother%2B%2F%25%7E&token_type_hint=access_token"
        );
    }

    #[test]
    fn resolves_configured_client_secret_without_a_fixed_environment_name() {
        struct FixtureResolver;

        impl SecretResolver for FixtureResolver {
            fn resolve(
                &self,
                reference: &SecretReference,
            ) -> Result<Zeroizing<String>, SecretResolutionError> {
                assert_eq!(
                    reference.environment_variable(),
                    Some("REMBrane_TEST_OAUTH_SECRET")
                );
                Ok(Zeroizing::new("client-secret".to_owned()))
            }
        }

        let config = RemoteMcpConfig::new(
            "https://memory.example.test/mcp".to_owned(),
            "https://identity.example.test".to_owned(),
            "https://identity.example.test/oauth/introspect".to_owned(),
            "rembrane".to_owned(),
            SecretReference::environment("REMBrane_TEST_OAUTH_SECRET")
                .expect("valid secret reference"),
            vec!["https://agent.example.test".to_owned()],
        )
        .expect("valid remote MCP config");
        let transport = HttpIntrospectionTransport::from_config(&config, &FixtureResolver)
            .expect("resolved transport");
        let request = transport
            .build_request("opaque-access-token")
            .expect("request");

        assert_eq!(
            request.url().as_str(),
            "https://identity.example.test/oauth/introspect"
        );
        assert_eq!(
            request.headers()[AUTHORIZATION],
            "Basic cmVtYnJhbmU6Y2xpZW50LXNlY3JldA=="
        );
    }

    #[test]
    fn decodes_single_and_multiple_audiences_without_inventing_claims() {
        let single = decode_response(
            br#"{"active":true,"iss":"https://identity.example.test","aud":"memory","sub":"principal_01","client_id":"client_01","workspace_id":"workspace_01","scope":"rembrane:context:read","exp":2000,"nbf":1000}"#,
        )
        .expect("single audience response");
        assert_eq!(single.audience, ["memory"]);
        assert_eq!(single.workspace_id.as_deref(), Some("workspace_01"));

        let many = decode_response(br#"{"active":false,"aud":["memory","account"]}"#)
            .expect("multiple audience response");
        assert_eq!(many.audience, ["memory", "account"]);
        assert!(many.subject.is_none());
        assert!(decode_response(br#"{"active":"yes"}"#).is_err());

        let excessive_audiences = serde_json::json!({
            "active": false,
            "aud": vec!["memory"; MAX_REMOTE_AUDIENCES + 1],
        });
        assert!(
            decode_response(&serde_json::to_vec(&excessive_audiences).expect("introspection JSON"))
                .is_err()
        );
        let oversized_audience = serde_json::json!({
            "active": false,
            "aud": ["x".repeat(MAX_REMOTE_AUDIENCE_BYTES + 1)],
        });
        assert!(
            decode_response(&serde_json::to_vec(&oversized_audience).expect("introspection JSON"))
                .is_err()
        );
        let oversized_scope = serde_json::json!({
            "active": false,
            "scope": "x".repeat(MAXIMUM_SCOPE_BYTES + 1),
        });
        assert!(
            decode_response(&serde_json::to_vec(&oversized_scope).expect("introspection JSON"))
                .is_err()
        );
    }
}

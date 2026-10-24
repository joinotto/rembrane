//! Typed deployment configuration without credentials.
//!
//! Secret values are resolved by adapters from environment variables, files,
//! container secrets, or secret managers. They do not belong in this crate's
//! serializable deployment policy.

use rembrane_domain::{ActivityId, EntityId, ReadPermission, ReadScope};
use rembrane_provider_sdk::{CURRENT_PROVIDER_PROTOCOL, Capability, ProviderPolicy};
use std::error::Error;
use std::fmt::{self, Display};
use url::{Position, Url};

pub const MAX_REMOTE_ENDPOINT_BYTES: usize = 2_048;
pub const MAX_REMOTE_CLIENT_ID_BYTES: usize = 255;
pub const MAX_REMOTE_TRUSTED_ORIGINS: usize = 64;
pub const MAX_REMOTE_ORIGIN_BYTES: usize = 2_048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessingMode {
    Hosted,
    CustomerGateway,
    LocalOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderPlacement {
    TrustedBoundary,
    External,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderKind {
    Native,
    Mem0,
    Supermemory,
    Graphiti,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderConnection {
    pub kind: ProviderKind,
    pub endpoint: Option<String>,
    pub credentials: Vec<SecretReference>,
    pub placement: ProviderPlacement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderConnectionError {
    NativeProviderMustBeLocal,
    EmptyEndpoint,
    InsecureRemoteEndpoint,
    CredentialBearingEndpoint,
}

impl Display for ProviderConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativeProviderMustBeLocal => {
                formatter.write_str("native provider must not configure an endpoint or credentials")
            }
            Self::EmptyEndpoint => formatter.write_str("provider endpoint must not be empty"),
            Self::InsecureRemoteEndpoint => {
                formatter.write_str("provider endpoint must use HTTPS or loopback HTTP")
            }
            Self::CredentialBearingEndpoint => formatter
                .write_str("provider endpoint must not contain credentials, query, or fragment"),
        }
    }
}

impl Error for ProviderConnectionError {}

impl ProviderConnection {
    #[must_use]
    pub const fn native() -> Self {
        Self {
            kind: ProviderKind::Native,
            endpoint: None,
            credentials: Vec::new(),
            placement: ProviderPlacement::TrustedBoundary,
        }
    }

    pub fn remote(
        kind: ProviderKind,
        endpoint: impl Into<String>,
        credentials: Vec<SecretReference>,
        placement: ProviderPlacement,
    ) -> Result<Self, ProviderConnectionError> {
        if kind == ProviderKind::Native {
            return Err(ProviderConnectionError::NativeProviderMustBeLocal);
        }
        let endpoint = endpoint.into();
        validate_provider_endpoint(&endpoint)?;
        Ok(Self {
            kind,
            endpoint: Some(endpoint),
            credentials,
            placement,
        })
    }
}

fn validate_provider_endpoint(endpoint: &str) -> Result<(), ProviderConnectionError> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return Err(ProviderConnectionError::EmptyEndpoint);
    }
    if endpoint.contains('@') || endpoint.contains('?') || endpoint.contains('#') {
        return Err(ProviderConnectionError::CredentialBearingEndpoint);
    }
    let Some((scheme, remainder)) = endpoint.split_once("://") else {
        return Err(ProviderConnectionError::InsecureRemoteEndpoint);
    };
    let authority = remainder.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        return Err(ProviderConnectionError::InsecureRemoteEndpoint);
    }
    let secure = scheme == "https";
    let loopback = scheme == "http"
        && (authority == "127.0.0.1"
            || authority.starts_with("127.0.0.1:")
            || authority == "[::1]"
            || authority.starts_with("[::1]:"));
    if !secure && !loopback {
        return Err(ProviderConnectionError::InsecureRemoteEndpoint);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeploymentPolicy {
    pub processing_mode: ProcessingMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SecretReference {
    Environment { variable: String },
    File { path: String },
    External { provider: String, key: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretReferenceError {
    EmptyField,
    InlineValueForbidden,
}

impl Display for SecretReferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField => formatter.write_str("secret reference fields must not be empty"),
            Self::InlineValueForbidden => {
                formatter.write_str("inline secret values are forbidden; use a reference")
            }
        }
    }
}

impl Error for SecretReferenceError {}

impl SecretReference {
    pub fn environment(variable: impl Into<String>) -> Result<Self, SecretReferenceError> {
        let variable = variable.into();
        if variable.trim().is_empty() {
            return Err(SecretReferenceError::EmptyField);
        }
        Ok(Self::Environment { variable })
    }

    pub fn file(path: impl Into<String>) -> Result<Self, SecretReferenceError> {
        let path = path.into();
        if path.trim().is_empty() {
            return Err(SecretReferenceError::EmptyField);
        }
        Ok(Self::File { path })
    }

    pub fn external(
        provider: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<Self, SecretReferenceError> {
        let provider = provider.into();
        let key = key.into();
        if provider.trim().is_empty() || key.trim().is_empty() {
            return Err(SecretReferenceError::EmptyField);
        }
        Ok(Self::External { provider, key })
    }

    pub fn inline(_value: impl Into<String>) -> Result<Self, SecretReferenceError> {
        Err(SecretReferenceError::InlineValueForbidden)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteMcpConfig {
    resource: String,
    resource_authority: String,
    issuer: String,
    introspection_endpoint: String,
    introspection_client_id: String,
    introspection_client_secret: SecretReference,
    trusted_origins: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteMcpConfigError {
    EmptyClientId,
    InvalidClientId,
    InsecureEndpoint,
    CredentialBearingEndpoint,
    InvalidOrigin,
}

impl Display for RemoteMcpConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyClientId => "OAuth introspection client id must not be empty",
            Self::InvalidClientId => {
                "OAuth introspection client id contains unsafe HTTP characters"
            }
            Self::InsecureEndpoint => "remote MCP and OAuth endpoints must use HTTPS",
            Self::CredentialBearingEndpoint => {
                "remote MCP and OAuth endpoints must not contain credentials, query, or fragment"
            }
            Self::InvalidOrigin => {
                "trusted origins must be exact HTTPS origins without wildcard, path, query, or fragment"
            }
        })
    }
}

impl Error for RemoteMcpConfigError {}

impl RemoteMcpConfig {
    /// Creates a complete remote MCP deployment profile.
    ///
    /// # Errors
    ///
    /// Returns an error for plaintext or credential-bearing endpoints, an
    /// empty OAuth client id, or non-exact trusted browser origins.
    pub fn new(
        resource: String,
        issuer: String,
        introspection_endpoint: String,
        introspection_client_id: String,
        introspection_client_secret: SecretReference,
        trusted_origins: Vec<String>,
    ) -> Result<Self, RemoteMcpConfigError> {
        for endpoint in [&resource, &issuer, &introspection_endpoint] {
            validate_remote_https_endpoint(endpoint)?;
        }
        if introspection_client_id.trim().is_empty() {
            return Err(RemoteMcpConfigError::EmptyClientId);
        }
        if introspection_client_id.len() > MAX_REMOTE_CLIENT_ID_BYTES
            || contains_unsafe_http_value_char(&introspection_client_id)
        {
            return Err(RemoteMcpConfigError::InvalidClientId);
        }
        if trusted_origins.len() > MAX_REMOTE_TRUSTED_ORIGINS {
            return Err(RemoteMcpConfigError::InvalidOrigin);
        }
        let mut normalized_origins = Vec::new();
        for origin in trusted_origins {
            validate_exact_https_origin(&origin)?;
            if !normalized_origins.contains(&origin) {
                normalized_origins.push(origin);
            }
        }
        let resource_authority = remote_endpoint_authority(&resource)?;
        Ok(Self {
            resource,
            resource_authority,
            issuer,
            introspection_endpoint,
            introspection_client_id,
            introspection_client_secret,
            trusted_origins: normalized_origins,
        })
    }

    /// Returns the RFC 9728 protected-resource metadata URL derived from the
    /// validated MCP resource URL.
    #[must_use]
    pub fn protected_resource_metadata_url(&self) -> String {
        let remainder = self
            .resource
            .strip_prefix("https://")
            .unwrap_or(&self.resource);
        let (authority, path) = remainder
            .split_once('/')
            .map_or((remainder, ""), |(authority, path)| (authority, path));
        if path.is_empty() {
            format!("https://{authority}/.well-known/oauth-protected-resource")
        } else {
            format!("https://{authority}/.well-known/oauth-protected-resource/{path}")
        }
    }

    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Returns the exact public authority accepted in the HTTP `Host` header.
    ///
    /// This is derived from the validated resource rather than independently
    /// configured, preventing the advertised OAuth resource and DNS-rebinding
    /// allowlist from drifting apart.
    #[must_use]
    pub fn resource_authority(&self) -> &str {
        &self.resource_authority
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    #[must_use]
    pub fn introspection_endpoint(&self) -> &str {
        &self.introspection_endpoint
    }

    #[must_use]
    pub fn introspection_client_id(&self) -> &str {
        &self.introspection_client_id
    }

    #[must_use]
    pub const fn introspection_client_secret(&self) -> &SecretReference {
        &self.introspection_client_secret
    }

    #[must_use]
    pub fn trusted_origins(&self) -> &[String] {
        &self.trusted_origins
    }

    /// Returns the canonical OAuth bearer challenge for this MCP resource.
    #[must_use]
    pub fn bearer_challenge(&self) -> String {
        format!(
            "Bearer resource_metadata=\"{}\"",
            self.protected_resource_metadata_url()
        )
    }
}

fn validate_remote_https_endpoint(endpoint: &str) -> Result<(), RemoteMcpConfigError> {
    if endpoint.len() > MAX_REMOTE_ENDPOINT_BYTES || contains_unsafe_http_value_char(endpoint) {
        return Err(RemoteMcpConfigError::InsecureEndpoint);
    }
    if endpoint.contains('@') || endpoint.contains('?') || endpoint.contains('#') {
        return Err(RemoteMcpConfigError::CredentialBearingEndpoint);
    }
    if endpoint.contains('\\') {
        return Err(RemoteMcpConfigError::InsecureEndpoint);
    }
    let parsed = Url::parse(endpoint).map_err(|_| RemoteMcpConfigError::InsecureEndpoint)?;
    let canonical_endpoint = parsed.as_str();
    let canonical_root_without_slash =
        parsed.path() == "/" && canonical_endpoint.strip_suffix('/') == Some(endpoint);
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || (canonical_endpoint != endpoint && !canonical_root_without_slash)
    {
        return Err(RemoteMcpConfigError::InsecureEndpoint);
    }
    let authority = &parsed[Position::BeforeHost..Position::AfterPort];
    if authority.starts_with('.') || authority.ends_with('.') {
        return Err(RemoteMcpConfigError::InsecureEndpoint);
    }
    Ok(())
}

fn remote_endpoint_authority(endpoint: &str) -> Result<String, RemoteMcpConfigError> {
    let parsed = Url::parse(endpoint).map_err(|_| RemoteMcpConfigError::InsecureEndpoint)?;
    Ok(parsed[Position::BeforeHost..Position::AfterPort].to_owned())
}

fn validate_exact_https_origin(origin: &str) -> Result<(), RemoteMcpConfigError> {
    if origin.len() > MAX_REMOTE_ORIGIN_BYTES
        || origin == "*"
        || origin.ends_with('/')
        || contains_unsafe_http_value_char(origin)
    {
        return Err(RemoteMcpConfigError::InvalidOrigin);
    }
    let parsed = Url::parse(origin).map_err(|_| RemoteMcpConfigError::InvalidOrigin)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.path() != "/"
        || parsed.origin().ascii_serialization() != origin
    {
        return Err(RemoteMcpConfigError::InvalidOrigin);
    }
    Ok(())
}

fn contains_unsafe_http_value_char(value: &str) -> bool {
    !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b'"')
}

impl DeploymentPolicy {
    #[must_use]
    pub fn provider_policy(
        self,
        required_capabilities: Vec<Capability>,
        placement: ProviderPlacement,
    ) -> ProviderPolicy {
        let allow_plaintext_processing = self.processing_mode == ProcessingMode::Hosted
            || placement == ProviderPlacement::TrustedBoundary;

        ProviderPolicy {
            minimum_protocol_version: CURRENT_PROVIDER_PROTOCOL,
            required_capabilities,
            allow_plaintext_processing,
        }
    }
}

pub fn parse_read_scopes(value: &str) -> Result<Vec<ReadScope>, String> {
    let mut scopes = Vec::new();
    for entry in value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let scope = if entry == "global" {
            ReadScope::Global
        } else if let Some(name) = entry.strip_prefix("domain:") {
            nonempty_scope_value(name, entry)?;
            ReadScope::Domain {
                name: name.to_owned(),
            }
        } else if let Some(id) = entry.strip_prefix("entity:") {
            nonempty_scope_value(id, entry)?;
            ReadScope::Entity {
                id: EntityId::new(id),
            }
        } else if let Some(id) = entry.strip_prefix("activity:") {
            nonempty_scope_value(id, entry)?;
            ReadScope::Activity {
                id: ActivityId::new(id),
            }
        } else {
            return Err(format!("invalid read scope {entry}"));
        };
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    if scopes.is_empty() {
        return Err("at least one read scope is required".to_owned());
    }
    Ok(scopes)
}

pub fn parse_read_permissions(value: &str) -> Result<Vec<ReadPermission>, String> {
    let mut permissions = Vec::new();
    for entry in value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let permission = match entry {
            "travel-source-references" => ReadPermission::RevealTravelSourceReferences,
            "travel-sensitive-profile" => ReadPermission::RevealTravelSensitiveProfile,
            _ => return Err(format!("invalid read permission {entry}")),
        };
        if !permissions.contains(&permission) {
            permissions.push(permission);
        }
    }
    Ok(permissions)
}

fn nonempty_scope_value(value: &str, entry: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("read scope {entry} has an empty value"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rembrane_provider_sdk::Capability;

    use super::{
        DeploymentPolicy, MAX_REMOTE_CLIENT_ID_BYTES, MAX_REMOTE_ENDPOINT_BYTES,
        MAX_REMOTE_ORIGIN_BYTES, MAX_REMOTE_TRUSTED_ORIGINS, ProcessingMode, ProviderConnection,
        ProviderConnectionError, ProviderKind, ProviderPlacement, RemoteMcpConfig,
        RemoteMcpConfigError, SecretReference, SecretReferenceError, parse_read_permissions,
        parse_read_scopes,
    };

    #[test]
    fn strict_modes_allow_plaintext_only_inside_trusted_boundary() {
        for processing_mode in [ProcessingMode::CustomerGateway, ProcessingMode::LocalOnly] {
            let deployment = DeploymentPolicy { processing_mode };
            assert!(
                deployment
                    .provider_policy(vec![Capability::Search], ProviderPlacement::TrustedBoundary,)
                    .allow_plaintext_processing
            );
            assert!(
                !deployment
                    .provider_policy(vec![Capability::Search], ProviderPlacement::External,)
                    .allow_plaintext_processing
            );
        }
    }

    #[test]
    fn hosted_mode_discloses_that_provider_plaintext_is_allowed() {
        let deployment = DeploymentPolicy {
            processing_mode: ProcessingMode::Hosted,
        };

        assert!(
            deployment
                .provider_policy(vec![Capability::Search], ProviderPlacement::External,)
                .allow_plaintext_processing
        );
    }

    #[test]
    fn configuration_rejects_inline_secret_values() {
        assert_eq!(
            SecretReference::inline("database-password"),
            Err(SecretReferenceError::InlineValueForbidden)
        );
        assert_eq!(
            SecretReference::environment("REMBRANE_DATABASE_URL"),
            Ok(SecretReference::Environment {
                variable: "REMBRANE_DATABASE_URL".to_owned()
            })
        );
    }

    #[test]
    fn parses_and_deduplicates_connection_read_scopes() {
        let scopes = parse_read_scopes("global,domain:development,entity:project_01,global")
            .expect("scope configuration should parse");

        assert_eq!(scopes.len(), 3);
    }

    #[test]
    fn rejects_wildcards_and_empty_scope_values() {
        assert!(parse_read_scopes("*").is_err());
        assert!(parse_read_scopes("entity:").is_err());
        assert!(parse_read_scopes(" ").is_err());
    }

    #[test]
    fn parses_explicit_sensitive_read_permissions() {
        let permissions = parse_read_permissions(
            "travel-source-references,travel-sensitive-profile,travel-source-references",
        )
        .expect("permission configuration should parse");
        assert_eq!(permissions.len(), 2);
        assert_eq!(
            parse_read_permissions("").expect("empty permissions should be valid"),
            []
        );
        assert!(parse_read_permissions("*").is_err());
        assert!(parse_read_permissions("unknown").is_err());
    }

    #[test]
    fn byo_provider_profiles_keep_credentials_as_references() {
        let profile = ProviderConnection::remote(
            ProviderKind::Mem0,
            "https://memory.example/v1",
            vec![
                SecretReference::environment("MEM0_API_KEY")
                    .expect("secret reference should be valid"),
            ],
            ProviderPlacement::External,
        )
        .expect("secure provider profile should be valid");

        assert_eq!(profile.kind, ProviderKind::Mem0);
        assert_eq!(
            profile.credentials,
            vec![SecretReference::Environment {
                variable: "MEM0_API_KEY".to_owned()
            }]
        );

        let supermemory = ProviderConnection::remote(
            ProviderKind::Supermemory,
            "https://api.supermemory.ai",
            vec![
                SecretReference::environment("SUPERMEMORY_API_KEY")
                    .expect("secret reference should be valid"),
            ],
            ProviderPlacement::External,
        )
        .expect("Supermemory profile should be valid");
        assert_eq!(supermemory.kind, ProviderKind::Supermemory);
    }

    #[test]
    fn provider_profiles_reject_credential_urls_and_remote_http() {
        assert_eq!(
            ProviderConnection::remote(
                ProviderKind::Graphiti,
                "https://user:secret@graph.example",
                Vec::new(),
                ProviderPlacement::External,
            ),
            Err(ProviderConnectionError::CredentialBearingEndpoint)
        );
        assert_eq!(
            ProviderConnection::remote(
                ProviderKind::Mem0,
                "http://memory.example",
                Vec::new(),
                ProviderPlacement::External,
            ),
            Err(ProviderConnectionError::InsecureRemoteEndpoint)
        );
        assert!(
            ProviderConnection::remote(
                ProviderKind::Graphiti,
                "http://127.0.0.1:8000",
                Vec::new(),
                ProviderPlacement::TrustedBoundary,
            )
            .is_ok()
        );
        assert!(
            ProviderConnection::remote(
                ProviderKind::Graphiti,
                "http://localhost:8000",
                Vec::new(),
                ProviderPlacement::TrustedBoundary,
            )
            .is_err()
        );
        assert!(
            ProviderConnection::remote(
                ProviderKind::Graphiti,
                "http://localhost.evil.example",
                Vec::new(),
                ProviderPlacement::TrustedBoundary,
            )
            .is_err()
        );
    }

    #[test]
    fn remote_mcp_profile_requires_https_and_secret_references() {
        let secret = SecretReference::environment("REMBRANE_OAUTH_CLIENT_SECRET")
            .expect("secret reference should be valid");
        let profile = RemoteMcpConfig::new(
            "https://memory.example/mcp".to_owned(),
            "https://identity.example".to_owned(),
            "https://identity.example/oauth/introspect".to_owned(),
            "rembrane-resource-server".to_owned(),
            secret.clone(),
            vec![
                "https://app.example".to_owned(),
                "https://app.example".to_owned(),
            ],
        )
        .expect("complete secure profile should be valid");

        assert_eq!(profile.introspection_client_secret(), &secret);
        assert_eq!(profile.trusted_origins(), ["https://app.example"]);
        assert_eq!(profile.resource_authority(), "memory.example");
        assert_eq!(
            profile.protected_resource_metadata_url(),
            "https://memory.example/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            profile.bearer_challenge(),
            "Bearer resource_metadata=\"https://memory.example/.well-known/oauth-protected-resource/mcp\""
        );
        assert_eq!(
            RemoteMcpConfig::new(
                "http://memory.example/mcp".to_owned(),
                "https://identity.example".to_owned(),
                "https://identity.example/oauth/introspect".to_owned(),
                "client".to_owned(),
                SecretReference::environment("SECRET").expect("reference should be valid"),
                Vec::new(),
            ),
            Err(RemoteMcpConfigError::InsecureEndpoint)
        );
    }

    #[test]
    fn remote_mcp_profile_derives_root_resource_metadata_without_trailing_path() {
        let profile = RemoteMcpConfig::new(
            "https://memory.example".to_owned(),
            "https://identity.example".to_owned(),
            "https://identity.example/oauth/introspect".to_owned(),
            "client".to_owned(),
            SecretReference::environment("SECRET").expect("reference should be valid"),
            Vec::new(),
        )
        .expect("root resource should be valid");

        assert_eq!(
            profile.protected_resource_metadata_url(),
            "https://memory.example/.well-known/oauth-protected-resource"
        );
        assert_eq!(profile.resource_authority(), "memory.example");
    }

    #[test]
    fn remote_mcp_profile_rejects_wildcard_and_credential_bearing_urls() {
        let profile = |resource: &str, origins: Vec<String>| {
            RemoteMcpConfig::new(
                resource.to_owned(),
                "https://identity.example".to_owned(),
                "https://identity.example/oauth/introspect".to_owned(),
                "client".to_owned(),
                SecretReference::environment("SECRET").expect("reference should be valid"),
                origins,
            )
        };
        assert_eq!(
            profile("https://user:secret@memory.example/mcp", Vec::new()),
            Err(RemoteMcpConfigError::CredentialBearingEndpoint)
        );
        assert_eq!(
            profile("https://memory.example/mcp", vec!["*".to_owned()]),
            Err(RemoteMcpConfigError::InvalidOrigin)
        );
        assert_eq!(
            profile(
                "https://memory.example/mcp",
                vec!["https://app.example/path".to_owned()]
            ),
            Err(RemoteMcpConfigError::InvalidOrigin)
        );
        for unsafe_resource in [
            "https://memory.example/mcp\r\nInjected: value",
            "https://memory.example/\"quoted",
            "https://memory example/mcp",
            "https://.example/mcp",
            "https://example./mcp",
        ] {
            assert_eq!(
                profile(unsafe_resource, Vec::new()),
                Err(RemoteMcpConfigError::InsecureEndpoint)
            );
        }
        for unsafe_origin in [
            "https://app.example\r\nInjected: value",
            "https://app.example\"",
            "https://app example",
            "https://äpp.example",
        ] {
            assert_eq!(
                profile("https://memory.example/mcp", vec![unsafe_origin.to_owned()]),
                Err(RemoteMcpConfigError::InvalidOrigin)
            );
        }
        assert_eq!(
            RemoteMcpConfig::new(
                "https://memory.example/mcp".to_owned(),
                "https://identity.example".to_owned(),
                "https://identity.example/oauth/introspect".to_owned(),
                "client\r\nInjected: value".to_owned(),
                SecretReference::environment("SECRET").expect("reference should be valid"),
                Vec::new(),
            ),
            Err(RemoteMcpConfigError::InvalidClientId)
        );
    }

    #[test]
    fn remote_mcp_profile_bounds_and_canonicalizes_deployment_values() {
        let profile = |resource: String, client_id: String, origins: Vec<String>| {
            RemoteMcpConfig::new(
                resource,
                "https://identity.example".to_owned(),
                "https://identity.example/oauth/introspect".to_owned(),
                client_id,
                SecretReference::environment("SECRET").expect("reference should be valid"),
                origins,
            )
        };

        for malformed in [
            "https://memory.example:invalid/mcp".to_owned(),
            "HTTPS://memory.example/mcp".to_owned(),
            "https://MEMORY.example/mcp".to_owned(),
            "https://memory.example:443/mcp".to_owned(),
            format!(
                "https://memory.example/{}",
                "x".repeat(MAX_REMOTE_ENDPOINT_BYTES)
            ),
        ] {
            assert_eq!(
                profile(malformed, "client".to_owned(), Vec::new()),
                Err(RemoteMcpConfigError::InsecureEndpoint)
            );
        }

        assert_eq!(
            profile(
                "https://memory.example/mcp".to_owned(),
                "x".repeat(MAX_REMOTE_CLIENT_ID_BYTES + 1),
                Vec::new(),
            ),
            Err(RemoteMcpConfigError::InvalidClientId)
        );
        assert_eq!(
            profile(
                "https://memory.example/mcp".to_owned(),
                "client".to_owned(),
                vec!["https://app.example".to_owned(); MAX_REMOTE_TRUSTED_ORIGINS + 1],
            ),
            Err(RemoteMcpConfigError::InvalidOrigin)
        );
        assert_eq!(
            profile(
                "https://memory.example/mcp".to_owned(),
                "client".to_owned(),
                vec![format!(
                    "https://{}.example",
                    "x".repeat(MAX_REMOTE_ORIGIN_BYTES)
                )],
            ),
            Err(RemoteMcpConfigError::InvalidOrigin)
        );
        for noncanonical_origin in [
            "https://APP.example",
            "https://app.example:443",
            "https://app.example/",
        ] {
            assert_eq!(
                profile(
                    "https://memory.example/mcp".to_owned(),
                    "client".to_owned(),
                    vec![noncanonical_origin.to_owned()],
                ),
                Err(RemoteMcpConfigError::InvalidOrigin)
            );
        }
    }
}

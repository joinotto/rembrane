//! Typed deployment configuration without credentials.
//!
//! Secret values are resolved by adapters from environment variables, files,
//! container secrets, or secret managers. They do not belong in this crate's
//! serializable deployment policy.

use rembrane_domain::{ActivityId, EntityId, ReadPermission, ReadScope};
use rembrane_provider_sdk::{CURRENT_PROVIDER_PROTOCOL, Capability, ProviderPolicy};
use std::error::Error;
use std::fmt::{self, Display};

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
        && (authority == "localhost"
            || authority.starts_with("localhost:")
            || authority == "127.0.0.1"
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
    pub resource: String,
    pub issuer: String,
    pub introspection_endpoint: String,
    pub introspection_client_id: String,
    pub introspection_client_secret: SecretReference,
    pub trusted_origins: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemoteMcpConfigError {
    EmptyClientId,
    InsecureEndpoint,
    CredentialBearingEndpoint,
    InvalidOrigin,
}

impl Display for RemoteMcpConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyClientId => "OAuth introspection client id must not be empty",
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
        let mut normalized_origins = Vec::new();
        for origin in trusted_origins {
            validate_exact_https_origin(&origin)?;
            if !normalized_origins.contains(&origin) {
                normalized_origins.push(origin);
            }
        }
        Ok(Self {
            resource,
            issuer,
            introspection_endpoint,
            introspection_client_id,
            introspection_client_secret,
            trusted_origins: normalized_origins,
        })
    }
}

fn validate_remote_https_endpoint(endpoint: &str) -> Result<(), RemoteMcpConfigError> {
    if endpoint.contains('@') || endpoint.contains('?') || endpoint.contains('#') {
        return Err(RemoteMcpConfigError::CredentialBearingEndpoint);
    }
    let Some(authority) = endpoint.strip_prefix("https://") else {
        return Err(RemoteMcpConfigError::InsecureEndpoint);
    };
    if authority.is_empty() || authority.starts_with('/') {
        return Err(RemoteMcpConfigError::InsecureEndpoint);
    }
    Ok(())
}

fn validate_exact_https_origin(origin: &str) -> Result<(), RemoteMcpConfigError> {
    if origin == "*" || origin.ends_with('/') {
        return Err(RemoteMcpConfigError::InvalidOrigin);
    }
    let Some(authority) = origin.strip_prefix("https://") else {
        return Err(RemoteMcpConfigError::InvalidOrigin);
    };
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('@')
        || authority.contains('?')
        || authority.contains('#')
    {
        return Err(RemoteMcpConfigError::InvalidOrigin);
    }
    Ok(())
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
        DeploymentPolicy, ProcessingMode, ProviderConnection, ProviderConnectionError,
        ProviderKind, ProviderPlacement, RemoteMcpConfig, RemoteMcpConfigError, SecretReference,
        SecretReferenceError, parse_read_permissions, parse_read_scopes,
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

        assert_eq!(profile.introspection_client_secret, secret);
        assert_eq!(profile.trusted_origins, ["https://app.example"]);
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
    }
}

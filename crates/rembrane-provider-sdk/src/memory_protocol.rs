use crate::{ProviderError, ProviderProtocolVersion};

pub const MEMORY_PROVIDER_DISCOVERY_PATH: &str = "/.well-known/ai-memory";
pub const CURRENT_MEMORY_PROVIDER_PROTOCOL: ProviderProtocolVersion =
    ProviderProtocolVersion::new(0, 1);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MemoryProviderTransport {
    Https,
    Mcp,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MemoryProviderCapability {
    ResolveContext,
    ResolveQuestion,
    RecordEvent,
    ProposeMemory,
    CheckpointActivity,
    RecordDisclosure,
    DeleteMemory,
    ExplainMemory,
    SyncPull,
    SyncPush,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MemoryProviderScope {
    ContextRead,
    QuestionRead,
    EventWrite,
    ProposalWrite,
    CheckpointWrite,
    DisclosureWrite,
    MemoryDelete,
    MemoryExplain,
    SyncRead,
    SyncWrite,
}

impl MemoryProviderScope {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContextRead => "memory:context:read",
            Self::QuestionRead => "memory:question:read",
            Self::EventWrite => "memory:event:write",
            Self::ProposalWrite => "memory:proposal:write",
            Self::CheckpointWrite => "memory:checkpoint:write",
            Self::DisclosureWrite => "memory:disclosure:write",
            Self::MemoryDelete => "memory:memory:delete",
            Self::MemoryExplain => "memory:memory:explain",
            Self::SyncRead => "memory:sync:read",
            Self::SyncWrite => "memory:sync:write",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MemoryProviderHttpMethod {
    Get,
    Post,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MemoryProviderOperation {
    ResolveContext,
    ResolveQuestion,
    RecordEvent,
    ProposeMemory,
    CheckpointActivity,
    RecordDisclosure,
    DeleteMemory,
    ExplainMemory,
    SyncPull,
    SyncPush,
}

impl MemoryProviderOperation {
    #[must_use]
    pub const fn capability(self) -> MemoryProviderCapability {
        match self {
            Self::ResolveContext => MemoryProviderCapability::ResolveContext,
            Self::ResolveQuestion => MemoryProviderCapability::ResolveQuestion,
            Self::RecordEvent => MemoryProviderCapability::RecordEvent,
            Self::ProposeMemory => MemoryProviderCapability::ProposeMemory,
            Self::CheckpointActivity => MemoryProviderCapability::CheckpointActivity,
            Self::RecordDisclosure => MemoryProviderCapability::RecordDisclosure,
            Self::DeleteMemory => MemoryProviderCapability::DeleteMemory,
            Self::ExplainMemory => MemoryProviderCapability::ExplainMemory,
            Self::SyncPull => MemoryProviderCapability::SyncPull,
            Self::SyncPush => MemoryProviderCapability::SyncPush,
        }
    }

    #[must_use]
    pub const fn required_scope(self) -> MemoryProviderScope {
        match self {
            Self::ResolveContext => MemoryProviderScope::ContextRead,
            Self::ResolveQuestion => MemoryProviderScope::QuestionRead,
            Self::RecordEvent => MemoryProviderScope::EventWrite,
            Self::ProposeMemory => MemoryProviderScope::ProposalWrite,
            Self::CheckpointActivity => MemoryProviderScope::CheckpointWrite,
            Self::RecordDisclosure => MemoryProviderScope::DisclosureWrite,
            Self::DeleteMemory => MemoryProviderScope::MemoryDelete,
            Self::ExplainMemory => MemoryProviderScope::MemoryExplain,
            Self::SyncPull => MemoryProviderScope::SyncRead,
            Self::SyncPush => MemoryProviderScope::SyncWrite,
        }
    }

    #[must_use]
    pub const fn http_method(self) -> MemoryProviderHttpMethod {
        match self {
            Self::ExplainMemory | Self::SyncPull => MemoryProviderHttpMethod::Get,
            Self::DeleteMemory => MemoryProviderHttpMethod::Delete,
            Self::ResolveContext
            | Self::ResolveQuestion
            | Self::RecordEvent
            | Self::ProposeMemory
            | Self::CheckpointActivity
            | Self::RecordDisclosure
            | Self::SyncPush => MemoryProviderHttpMethod::Post,
        }
    }

    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::ResolveContext => "/v1/context/resolve",
            Self::ResolveQuestion => "/v1/questions/resolve",
            Self::RecordEvent => "/v1/events",
            Self::ProposeMemory => "/v1/memory/proposals",
            Self::CheckpointActivity => "/v1/activities/{activity_id}/checkpoint",
            Self::RecordDisclosure => "/v1/disclosures/receipt",
            Self::DeleteMemory => "/v1/memories/{memory_id}",
            Self::ExplainMemory => "/v1/memories/{memory_id}/explain",
            Self::SyncPull => "/v1/sync/pull",
            Self::SyncPush => "/v1/sync/push",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryProviderPrivacyMode {
    /// The provider stores and transports opaque end-to-end encrypted data.
    EndToEndEncrypted,
    /// Plaintext processing is confined to the user's trusted deployment.
    TrustedBoundary,
    /// The remote provider may receive plaintext after explicit policy checks.
    ProviderPlaintext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryProviderLimits {
    pub maximum_context_items: usize,
    pub maximum_context_bytes: usize,
    pub maximum_event_batch_items: usize,
    pub maximum_sync_batch_items: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryProviderManifest {
    id: String,
    version: String,
    protocol_version: ProviderProtocolVersion,
    transports: Vec<MemoryProviderTransport>,
    capabilities: Vec<MemoryProviderCapability>,
    privacy_mode: MemoryProviderPrivacyMode,
    supported_domains: Vec<String>,
    limits: MemoryProviderLimits,
}

impl MemoryProviderManifest {
    /// Creates one validated, immutable memory-provider discovery manifest.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for malformed identifiers,
    /// empty or duplicate capability/transport declarations, malformed or
    /// duplicate domains, or zero operation limits.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        version: String,
        protocol_version: ProviderProtocolVersion,
        transports: Vec<MemoryProviderTransport>,
        capabilities: Vec<MemoryProviderCapability>,
        privacy_mode: MemoryProviderPrivacyMode,
        supported_domains: Vec<String>,
        limits: MemoryProviderLimits,
    ) -> Result<Self, ProviderError> {
        validate_identifier("memory provider id", &id)?;
        if version.trim().is_empty()
            || version.len() > 100
            || version
                .bytes()
                .any(|byte| byte.is_ascii_control() || !byte.is_ascii())
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory provider version must contain 1 to 100 safe ASCII characters".to_owned(),
            ));
        }
        validate_unique_nonempty("transport", &transports)?;
        validate_unique_nonempty("capability", &capabilities)?;
        if limits.maximum_context_items == 0
            || limits.maximum_context_bytes == 0
            || limits.maximum_event_batch_items == 0
            || limits.maximum_sync_batch_items == 0
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory provider limits must be greater than zero".to_owned(),
            ));
        }

        let mut domains = Vec::with_capacity(supported_domains.len());
        for domain in supported_domains {
            validate_identifier("supported domain", &domain)?;
            if domains.contains(&domain) {
                return Err(ProviderError::InvalidConfiguration(
                    "supported domains must be unique".to_owned(),
                ));
            }
            domains.push(domain);
        }

        Ok(Self {
            id,
            version,
            protocol_version,
            transports,
            capabilities,
            privacy_mode,
            supported_domains: domains,
            limits,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub const fn protocol_version(&self) -> ProviderProtocolVersion {
        self.protocol_version
    }

    #[must_use]
    pub fn transports(&self) -> &[MemoryProviderTransport] {
        &self.transports
    }

    #[must_use]
    pub fn capabilities(&self) -> &[MemoryProviderCapability] {
        &self.capabilities
    }

    #[must_use]
    pub const fn privacy_mode(&self) -> MemoryProviderPrivacyMode {
        self.privacy_mode
    }

    #[must_use]
    pub fn supported_domains(&self) -> &[String] {
        &self.supported_domains
    }

    #[must_use]
    pub const fn limits(&self) -> MemoryProviderLimits {
        self.limits
    }

    #[must_use]
    pub fn supports(&self, capability: MemoryProviderCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    #[must_use]
    pub const fn is_protocol_compatible(&self, required: ProviderProtocolVersion) -> bool {
        self.protocol_version.is_compatible_with(required)
    }
}

fn validate_unique_nonempty<T>(label: &str, values: &[T]) -> Result<(), ProviderError>
where
    T: Eq,
{
    if values.is_empty() {
        return Err(ProviderError::InvalidConfiguration(format!(
            "memory provider must declare at least one {label}"
        )));
    }
    if values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
    {
        return Err(ProviderError::InvalidConfiguration(format!(
            "memory provider {label}s must be unique"
        )));
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str) -> Result<(), ProviderError> {
    if value.len() < 2
        || value.len() > 255
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return Err(ProviderError::InvalidConfiguration(format!(
            "{label} must match ^[a-z0-9][a-z0-9._-]+$"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CURRENT_MEMORY_PROVIDER_PROTOCOL, MEMORY_PROVIDER_DISCOVERY_PATH, MemoryProviderCapability,
        MemoryProviderHttpMethod, MemoryProviderLimits, MemoryProviderManifest,
        MemoryProviderOperation, MemoryProviderPrivacyMode, MemoryProviderScope,
        MemoryProviderTransport,
    };
    use crate::{ProviderError, ProviderProtocolVersion};

    fn manifest() -> MemoryProviderManifest {
        MemoryProviderManifest::new(
            "rembrane.local".to_owned(),
            "0.1.0".to_owned(),
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            vec![MemoryProviderTransport::Https, MemoryProviderTransport::Mcp],
            vec![
                MemoryProviderCapability::ResolveContext,
                MemoryProviderCapability::ProposeMemory,
                MemoryProviderCapability::CheckpointActivity,
                MemoryProviderCapability::RecordDisclosure,
            ],
            MemoryProviderPrivacyMode::EndToEndEncrypted,
            vec!["personal".to_owned(), "development".to_owned()],
            MemoryProviderLimits {
                maximum_context_items: 50,
                maximum_context_bytes: 131_072,
                maximum_event_batch_items: 100,
                maximum_sync_batch_items: 500,
            },
        )
        .expect("fixture manifest should validate")
    }

    #[test]
    fn advertises_versioned_memory_provider_discovery() {
        let manifest = manifest();

        assert_eq!(MEMORY_PROVIDER_DISCOVERY_PATH, "/.well-known/ai-memory");
        assert_eq!(manifest.id(), "rembrane.local");
        assert!(manifest.is_protocol_compatible(ProviderProtocolVersion::new(0, 1)));
        assert!(!manifest.is_protocol_compatible(ProviderProtocolVersion::new(1, 0)));
        assert!(manifest.supports(MemoryProviderCapability::ResolveContext));
        assert_eq!(
            manifest.privacy_mode(),
            MemoryProviderPrivacyMode::EndToEndEncrypted
        );
        assert_eq!(manifest.supported_domains(), ["personal", "development"]);
    }

    #[test]
    fn rejects_ambiguous_or_unbounded_discovery_manifests() {
        let duplicate_transport = MemoryProviderManifest::new(
            "rembrane.local".to_owned(),
            "0.1.0".to_owned(),
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            vec![
                MemoryProviderTransport::Https,
                MemoryProviderTransport::Https,
            ],
            vec![MemoryProviderCapability::ResolveContext],
            MemoryProviderPrivacyMode::TrustedBoundary,
            Vec::new(),
            MemoryProviderLimits {
                maximum_context_items: 1,
                maximum_context_bytes: 1,
                maximum_event_batch_items: 1,
                maximum_sync_batch_items: 1,
            },
        );
        assert_eq!(
            duplicate_transport,
            Err(ProviderError::InvalidConfiguration(
                "memory provider transports must be unique".to_owned()
            ))
        );

        let invalid_domain = MemoryProviderManifest::new(
            "rembrane.local".to_owned(),
            "0.1.0".to_owned(),
            CURRENT_MEMORY_PROVIDER_PROTOCOL,
            vec![MemoryProviderTransport::Https],
            vec![MemoryProviderCapability::ResolveContext],
            MemoryProviderPrivacyMode::ProviderPlaintext,
            vec!["Travel Plans".to_owned()],
            MemoryProviderLimits {
                maximum_context_items: 1,
                maximum_context_bytes: 0,
                maximum_event_batch_items: 1,
                maximum_sync_batch_items: 1,
            },
        );
        assert!(matches!(
            invalid_domain,
            Err(ProviderError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn every_operation_has_one_capability_scope_and_http_binding() {
        let cases = [
            (
                MemoryProviderOperation::ResolveContext,
                MemoryProviderCapability::ResolveContext,
                MemoryProviderScope::ContextRead,
                MemoryProviderHttpMethod::Post,
                "/v1/context/resolve",
            ),
            (
                MemoryProviderOperation::ResolveQuestion,
                MemoryProviderCapability::ResolveQuestion,
                MemoryProviderScope::QuestionRead,
                MemoryProviderHttpMethod::Post,
                "/v1/questions/resolve",
            ),
            (
                MemoryProviderOperation::RecordEvent,
                MemoryProviderCapability::RecordEvent,
                MemoryProviderScope::EventWrite,
                MemoryProviderHttpMethod::Post,
                "/v1/events",
            ),
            (
                MemoryProviderOperation::ProposeMemory,
                MemoryProviderCapability::ProposeMemory,
                MemoryProviderScope::ProposalWrite,
                MemoryProviderHttpMethod::Post,
                "/v1/memory/proposals",
            ),
            (
                MemoryProviderOperation::CheckpointActivity,
                MemoryProviderCapability::CheckpointActivity,
                MemoryProviderScope::CheckpointWrite,
                MemoryProviderHttpMethod::Post,
                "/v1/activities/{activity_id}/checkpoint",
            ),
            (
                MemoryProviderOperation::RecordDisclosure,
                MemoryProviderCapability::RecordDisclosure,
                MemoryProviderScope::DisclosureWrite,
                MemoryProviderHttpMethod::Post,
                "/v1/disclosures/receipt",
            ),
            (
                MemoryProviderOperation::DeleteMemory,
                MemoryProviderCapability::DeleteMemory,
                MemoryProviderScope::MemoryDelete,
                MemoryProviderHttpMethod::Delete,
                "/v1/memories/{memory_id}",
            ),
            (
                MemoryProviderOperation::ExplainMemory,
                MemoryProviderCapability::ExplainMemory,
                MemoryProviderScope::MemoryExplain,
                MemoryProviderHttpMethod::Get,
                "/v1/memories/{memory_id}/explain",
            ),
            (
                MemoryProviderOperation::SyncPull,
                MemoryProviderCapability::SyncPull,
                MemoryProviderScope::SyncRead,
                MemoryProviderHttpMethod::Get,
                "/v1/sync/pull",
            ),
            (
                MemoryProviderOperation::SyncPush,
                MemoryProviderCapability::SyncPush,
                MemoryProviderScope::SyncWrite,
                MemoryProviderHttpMethod::Post,
                "/v1/sync/push",
            ),
        ];

        for (operation, capability, scope, method, path) in cases {
            assert_eq!(operation.capability(), capability);
            assert_eq!(operation.required_scope(), scope);
            assert_eq!(operation.http_method(), method);
            assert_eq!(operation.path_template(), path);
            assert!(scope.as_str().starts_with("memory:"));
        }
    }
}

use crate::ProviderError;

pub const CURRENT_PROVIDER_PROTOCOL: ProviderProtocolVersion = ProviderProtocolVersion::new(0, 1);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProviderProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProviderProtocolVersion {
    #[must_use]
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    #[must_use]
    pub const fn is_compatible_with(self, required: Self) -> bool {
        self.major == required.major && self.minor >= required.minor
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Capability {
    Index,
    Search,
    Delete,
    WorkspaceFilter,
    VersionedRecords,
    HealthCheck,
    Export,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderLimits {
    pub maximum_batch_items: usize,
    pub maximum_content_bytes: usize,
    pub maximum_candidates: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderManifest {
    pub id: String,
    pub version: String,
    pub protocol_version: ProviderProtocolVersion,
    pub capabilities: Vec<Capability>,
    pub plaintext_processing: bool,
    pub limits: ProviderLimits,
}

impl ProviderManifest {
    #[must_use]
    pub fn missing_capabilities(&self, required: &[Capability]) -> Vec<Capability> {
        required
            .iter()
            .filter(|capability| !self.capabilities.contains(capability))
            .copied()
            .collect()
    }

    #[must_use]
    pub fn supports_all(&self, required: &[Capability]) -> bool {
        self.missing_capabilities(required).is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderPolicy {
    pub minimum_protocol_version: ProviderProtocolVersion,
    pub required_capabilities: Vec<Capability>,
    pub allow_plaintext_processing: bool,
}

impl ProviderPolicy {
    pub fn validate(&self, provider: &ProviderManifest) -> Result<(), ProviderError> {
        if !provider
            .protocol_version
            .is_compatible_with(self.minimum_protocol_version)
        {
            return Err(ProviderError::IncompatibleProtocol {
                required_major: self.minimum_protocol_version.major,
                required_minor: self.minimum_protocol_version.minor,
                offered_major: provider.protocol_version.major,
                offered_minor: provider.protocol_version.minor,
            });
        }
        if provider.limits.maximum_batch_items == 0
            || provider.limits.maximum_content_bytes == 0
            || provider.limits.maximum_candidates == 0
        {
            return Err(ProviderError::InvalidConfiguration(
                "provider limits must be greater than zero".to_owned(),
            ));
        }
        let missing = provider.missing_capabilities(&self.required_capabilities);
        if let Some(capability) = missing.first() {
            return Err(ProviderError::MissingCapability(format!("{capability:?}")));
        }

        if provider.plaintext_processing && !self.allow_plaintext_processing {
            return Err(ProviderError::Rejected(
                "plaintext processing is forbidden by deployment policy".to_owned(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CURRENT_PROVIDER_PROTOCOL, Capability, ProviderLimits, ProviderManifest, ProviderPolicy,
        ProviderProtocolVersion,
    };
    use crate::ProviderError;

    #[test]
    fn reports_missing_security_capability() {
        let provider = ProviderManifest {
            id: "example".to_owned(),
            version: "1.0".to_owned(),
            protocol_version: CURRENT_PROVIDER_PROTOCOL,
            capabilities: vec![Capability::Index, Capability::Search],
            plaintext_processing: true,
            limits: ProviderLimits {
                maximum_batch_items: 100,
                maximum_content_bytes: 262_144,
                maximum_candidates: 100,
            },
        };

        assert_eq!(
            provider.missing_capabilities(&[Capability::Search, Capability::WorkspaceFilter,]),
            vec![Capability::WorkspaceFilter]
        );
        assert!(!provider.supports_all(&[Capability::WorkspaceFilter]));
    }

    #[test]
    fn rejects_provider_missing_deletion_support() {
        let provider = ProviderManifest {
            id: "managed-memory".to_owned(),
            version: "1.0".to_owned(),
            protocol_version: CURRENT_PROVIDER_PROTOCOL,
            capabilities: vec![
                Capability::Index,
                Capability::Search,
                Capability::WorkspaceFilter,
            ],
            plaintext_processing: true,
            limits: ProviderLimits {
                maximum_batch_items: 100,
                maximum_content_bytes: 262_144,
                maximum_candidates: 100,
            },
        };
        let policy = ProviderPolicy {
            minimum_protocol_version: CURRENT_PROVIDER_PROTOCOL,
            required_capabilities: vec![
                Capability::Search,
                Capability::WorkspaceFilter,
                Capability::Delete,
            ],
            allow_plaintext_processing: true,
        };

        assert_eq!(
            policy.validate(&provider),
            Err(ProviderError::MissingCapability("Delete".to_owned()))
        );
    }

    #[test]
    fn rejects_plaintext_provider_in_strict_mode() {
        let provider = ProviderManifest {
            id: "external-memory".to_owned(),
            version: "1.0".to_owned(),
            protocol_version: CURRENT_PROVIDER_PROTOCOL,
            capabilities: vec![Capability::Search],
            plaintext_processing: true,
            limits: ProviderLimits {
                maximum_batch_items: 100,
                maximum_content_bytes: 262_144,
                maximum_candidates: 100,
            },
        };
        let policy = ProviderPolicy {
            minimum_protocol_version: CURRENT_PROVIDER_PROTOCOL,
            required_capabilities: vec![Capability::Search],
            allow_plaintext_processing: false,
        };

        assert_eq!(
            policy.validate(&provider),
            Err(ProviderError::Rejected(
                "plaintext processing is forbidden by deployment policy".to_owned()
            ))
        );
    }

    #[test]
    fn rejects_incompatible_provider_protocol() {
        let provider = ProviderManifest {
            id: "future-provider".to_owned(),
            version: "1.0".to_owned(),
            protocol_version: ProviderProtocolVersion::new(1, 0),
            capabilities: vec![Capability::Search],
            plaintext_processing: false,
            limits: ProviderLimits {
                maximum_batch_items: 100,
                maximum_content_bytes: 262_144,
                maximum_candidates: 100,
            },
        };
        let policy = ProviderPolicy {
            minimum_protocol_version: CURRENT_PROVIDER_PROTOCOL,
            required_capabilities: vec![Capability::Search],
            allow_plaintext_processing: false,
        };

        assert_eq!(
            policy.validate(&provider),
            Err(ProviderError::IncompatibleProtocol {
                required_major: 0,
                required_minor: 1,
                offered_major: 1,
                offered_minor: 0,
            })
        );
    }
}

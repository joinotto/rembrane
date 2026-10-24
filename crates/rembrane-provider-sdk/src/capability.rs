use crate::{CandidateMemory, ProviderError};

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
    GraphTraverse,
    GraphUpsert,
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
    pub fn validate_structure(&self) -> Result<(), ProviderError> {
        if self.id.len() < 2
            || self.id.len() > 255
            || !self.id.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
            })
        {
            return Err(ProviderError::InvalidConfiguration(
                "provider id must match ^[a-z0-9][a-z0-9._-]+$".to_owned(),
            ));
        }
        if self.version.trim().is_empty() || self.version.len() > 100 {
            return Err(ProviderError::InvalidConfiguration(
                "provider version must contain 1 to 100 characters".to_owned(),
            ));
        }
        if self.capabilities.is_empty() {
            return Err(ProviderError::InvalidConfiguration(
                "provider must declare at least one capability".to_owned(),
            ));
        }
        if self
            .capabilities
            .iter()
            .enumerate()
            .any(|(index, capability)| self.capabilities[..index].contains(capability))
        {
            return Err(ProviderError::InvalidConfiguration(
                "provider capabilities must be unique".to_owned(),
            ));
        }
        if self.limits.maximum_batch_items == 0
            || self.limits.maximum_content_bytes == 0
            || self.limits.maximum_candidates == 0
        {
            return Err(ProviderError::InvalidConfiguration(
                "provider limits must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }

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

    pub fn bounded_candidate_limit(&self, requested: usize) -> Result<usize, ProviderError> {
        if requested == 0 || self.limits.maximum_candidates == 0 {
            return Err(ProviderError::InvalidConfiguration(
                "candidate limits must be greater than zero".to_owned(),
            ));
        }
        Ok(requested.min(self.limits.maximum_candidates))
    }

    pub fn validate_candidates(
        &self,
        candidates: &[CandidateMemory],
        requested_limit: usize,
    ) -> Result<(), ProviderError> {
        if candidates.len() > requested_limit || candidates.len() > self.limits.maximum_candidates {
            return Err(ProviderError::Rejected(
                "provider returned more candidates than requested".to_owned(),
            ));
        }
        if candidates
            .iter()
            .any(|candidate| candidate.version == 0 || candidate.score_millionths > 1_000_000)
        {
            return Err(ProviderError::Rejected(
                "provider returned an invalid candidate".to_owned(),
            ));
        }
        Ok(())
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
        provider.validate_structure()?;
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
    use rembrane_domain::MemoryId;

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

    #[test]
    fn bounds_queries_and_rejects_invalid_candidates() {
        let provider = ProviderManifest {
            id: "bounded-provider".to_owned(),
            version: "1.0".to_owned(),
            protocol_version: CURRENT_PROVIDER_PROTOCOL,
            capabilities: vec![Capability::Search],
            plaintext_processing: false,
            limits: ProviderLimits {
                maximum_batch_items: 10,
                maximum_content_bytes: 262_144,
                maximum_candidates: 2,
            },
        };
        assert_eq!(
            provider
                .bounded_candidate_limit(100)
                .expect("limit should be bounded"),
            2
        );
        assert_eq!(
            provider.validate_candidates(
                &[crate::CandidateMemory {
                    memory_id: MemoryId::new("memory"),
                    version: 1,
                    score_millionths: 1_000_001,
                }],
                2,
            ),
            Err(ProviderError::Rejected(
                "provider returned an invalid candidate".to_owned()
            ))
        );
    }

    #[test]
    fn rejects_manifest_structure_that_json_schema_forbids() {
        let malformed = ProviderManifest {
            id: "Invalid Provider".to_owned(),
            version: " ".to_owned(),
            protocol_version: CURRENT_PROVIDER_PROTOCOL,
            capabilities: vec![Capability::Search, Capability::Search],
            plaintext_processing: false,
            limits: ProviderLimits {
                maximum_batch_items: 1,
                maximum_content_bytes: 1,
                maximum_candidates: 1,
            },
        };

        assert_eq!(
            malformed.validate_structure(),
            Err(ProviderError::InvalidConfiguration(
                "provider id must match ^[a-z0-9][a-z0-9._-]+$".to_owned()
            ))
        );

        let duplicate_capabilities = ProviderManifest {
            id: "valid.provider".to_owned(),
            version: "1.0.0".to_owned(),
            ..malformed
        };
        assert_eq!(
            duplicate_capabilities.validate_structure(),
            Err(ProviderError::InvalidConfiguration(
                "provider capabilities must be unique".to_owned()
            ))
        );
    }
}

use crate::ProviderError;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderManifest {
    pub id: String,
    pub version: String,
    pub capabilities: Vec<Capability>,
    pub plaintext_processing: bool,
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
    pub required_capabilities: Vec<Capability>,
    pub allow_plaintext_processing: bool,
}

impl ProviderPolicy {
    pub fn validate(&self, provider: &ProviderManifest) -> Result<(), ProviderError> {
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
    use super::{Capability, ProviderManifest, ProviderPolicy};
    use crate::ProviderError;

    #[test]
    fn reports_missing_security_capability() {
        let provider = ProviderManifest {
            id: "example".to_owned(),
            version: "1.0".to_owned(),
            capabilities: vec![Capability::Index, Capability::Search],
            plaintext_processing: true,
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
            capabilities: vec![
                Capability::Index,
                Capability::Search,
                Capability::WorkspaceFilter,
            ],
            plaintext_processing: true,
        };
        let policy = ProviderPolicy {
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
            capabilities: vec![Capability::Search],
            plaintext_processing: true,
        };
        let policy = ProviderPolicy {
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
}

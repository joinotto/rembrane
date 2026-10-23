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
    pub fn missing_capabilities(
        &self,
        required: &[Capability],
    ) -> Vec<Capability> {
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

#[cfg(test)]
mod tests {
    use super::{Capability, ProviderManifest};

    #[test]
    fn reports_missing_security_capability() {
        let provider = ProviderManifest {
            id: "example".to_owned(),
            version: "1.0".to_owned(),
            capabilities: vec![Capability::Index, Capability::Search],
            plaintext_processing: true,
        };

        assert_eq!(
            provider.missing_capabilities(&[
                Capability::Search,
                Capability::WorkspaceFilter,
            ]),
            vec![Capability::WorkspaceFilter]
        );
        assert!(!provider.supports_all(&[Capability::WorkspaceFilter]));
    }
}

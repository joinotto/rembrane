//! Typed deployment configuration without credentials.
//!
//! Secret values are resolved by adapters from environment variables, files,
//! container secrets, or secret managers. They do not belong in this crate's
//! serializable deployment policy.

use rembrane_provider_sdk::{Capability, ProviderPolicy};

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
pub struct DeploymentPolicy {
    pub processing_mode: ProcessingMode,
}

impl DeploymentPolicy {
    #[must_use]
    pub fn provider_policy(
        self,
        required_capabilities: Vec<Capability>,
        placement: ProviderPlacement,
    ) -> ProviderPolicy {
        let allow_plaintext_processing =
            self.processing_mode == ProcessingMode::Hosted
                || placement == ProviderPlacement::TrustedBoundary;

        ProviderPolicy {
            required_capabilities,
            allow_plaintext_processing,
        }
    }
}

#[cfg(test)]
mod tests {
    use rembrane_provider_sdk::Capability;

    use super::{DeploymentPolicy, ProcessingMode, ProviderPlacement};

    #[test]
    fn strict_modes_allow_plaintext_only_inside_trusted_boundary() {
        for processing_mode in [
            ProcessingMode::CustomerGateway,
            ProcessingMode::LocalOnly,
        ] {
            let deployment = DeploymentPolicy { processing_mode };
            assert!(
                deployment
                    .provider_policy(
                        vec![Capability::Search],
                        ProviderPlacement::TrustedBoundary,
                    )
                    .allow_plaintext_processing
            );
            assert!(
                !deployment
                    .provider_policy(
                        vec![Capability::Search],
                        ProviderPlacement::External,
                    )
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
                .provider_policy(
                    vec![Capability::Search],
                    ProviderPlacement::External,
                )
                .allow_plaintext_processing
        );
    }
}

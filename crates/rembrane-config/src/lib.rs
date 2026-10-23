//! Typed deployment configuration without credentials.
//!
//! Secret values are resolved by adapters from environment variables, files,
//! container secrets, or secret managers. They do not belong in this crate's
//! serializable deployment policy.

use rembrane_provider_sdk::{Capability, ProviderPolicy};
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
            Self::EmptyField => {
                formatter.write_str("secret reference fields must not be empty")
            }
            Self::InlineValueForbidden => formatter.write_str(
                "inline secret values are forbidden; use a reference",
            ),
        }
    }
}

impl Error for SecretReferenceError {}

impl SecretReference {
    pub fn environment(
        variable: impl Into<String>,
    ) -> Result<Self, SecretReferenceError> {
        let variable = variable.into();
        if variable.trim().is_empty() {
            return Err(SecretReferenceError::EmptyField);
        }
        Ok(Self::Environment { variable })
    }

    pub fn file(
        path: impl Into<String>,
    ) -> Result<Self, SecretReferenceError> {
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

    pub fn inline(
        _value: impl Into<String>,
    ) -> Result<Self, SecretReferenceError> {
        Err(SecretReferenceError::InlineValueForbidden)
    }
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

    use super::{
        DeploymentPolicy, ProcessingMode, ProviderPlacement, SecretReference,
        SecretReferenceError,
    };

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
}

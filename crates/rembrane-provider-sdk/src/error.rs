use std::error::Error;
use std::fmt::{self, Display};

#[derive(Clone, Eq, PartialEq)]
pub enum ProviderError {
    IncompatibleProtocol {
        required_major: u16,
        required_minor: u16,
        offered_major: u16,
        offered_minor: u16,
    },
    InvalidConfiguration(String),
    MissingCapability(String),
    Unavailable,
    Rejected(String),
}

impl fmt::Debug for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompatibleProtocol {
                required_major,
                required_minor,
                offered_major,
                offered_minor,
            } => formatter
                .debug_struct("IncompatibleProtocol")
                .field("required_major", required_major)
                .field("required_minor", required_minor)
                .field("offered_major", offered_major)
                .field("offered_minor", offered_minor)
                .finish(),
            Self::InvalidConfiguration(_) => {
                formatter.write_str("InvalidConfiguration(<redacted>)")
            }
            Self::MissingCapability(_) => formatter.write_str("MissingCapability(<redacted>)"),
            Self::Unavailable => formatter.write_str("Unavailable"),
            Self::Rejected(_) => formatter.write_str("Rejected(<redacted>)"),
        }
    }
}

impl Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompatibleProtocol {
                required_major,
                required_minor,
                offered_major,
                offered_minor,
            } => write!(
                formatter,
                "incompatible provider protocol: requires {required_major}.{required_minor}, provider offers {offered_major}.{offered_minor}"
            ),
            Self::InvalidConfiguration(message) => {
                write!(formatter, "invalid provider configuration: {message}")
            }
            Self::MissingCapability(capability) => {
                write!(formatter, "provider is missing capability: {capability}")
            }
            Self::Unavailable => formatter.write_str("provider unavailable"),
            Self::Rejected(message) => {
                write!(formatter, "provider rejected operation: {message}")
            }
        }
    }
}

impl Error for ProviderError {}

#[cfg(test)]
mod tests {
    use super::ProviderError;

    #[test]
    fn debug_output_redacts_arbitrary_provider_error_details() {
        let diagnostic = format!(
            "{:?} {:?} {:?}",
            ProviderError::InvalidConfiguration("private configuration".to_owned()),
            ProviderError::MissingCapability("private capability".to_owned()),
            ProviderError::Rejected("private rejection".to_owned()),
        );

        for private_value in [
            "private configuration",
            "private capability",
            "private rejection",
        ] {
            assert!(!diagnostic.contains(private_value));
        }
        assert!(diagnostic.contains("InvalidConfiguration(<redacted>)"));
        assert!(diagnostic.contains("MissingCapability(<redacted>)"));
        assert!(diagnostic.contains("Rejected(<redacted>)"));
    }
}

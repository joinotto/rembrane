use std::error::Error;
use std::fmt::{self, Display};

#[derive(Clone, Debug, Eq, PartialEq)]
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

use std::error::Error;
use std::fmt::{self, Display};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderError {
    InvalidConfiguration(String),
    MissingCapability(String),
    Unavailable,
    Rejected(String),
}

impl Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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

use std::error::Error;
use std::fmt::{self, Display};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplicationError {
    AccessDenied,
    AlreadyExists,
    NotFound,
    SequenceConflict,
    StorageUnavailable,
    Validation(String),
    VersionConflict,
}

impl Display for ApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessDenied => formatter.write_str("access denied"),
            Self::AlreadyExists => formatter.write_str("record already exists"),
            Self::NotFound => formatter.write_str("record not found"),
            Self::SequenceConflict => formatter.write_str("event sequence conflict"),
            Self::StorageUnavailable => formatter.write_str("storage unavailable"),
            Self::VersionConflict => formatter.write_str("version conflict"),
            Self::Validation(message) => {
                write!(formatter, "validation failed: {message}")
            }
        }
    }
}

impl Error for ApplicationError {}

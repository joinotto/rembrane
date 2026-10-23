use std::error::Error;
use std::fmt::{self, Display};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApplicationError {
    AlreadyExists,
    NotFound,
    StorageUnavailable,
    Validation(String),
}

impl Display for ApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => formatter.write_str("record already exists"),
            Self::NotFound => formatter.write_str("record not found"),
            Self::StorageUnavailable => formatter.write_str("storage unavailable"),
            Self::Validation(message) => {
                write!(formatter, "validation failed: {message}")
            }
        }
    }
}

impl Error for ApplicationError {}

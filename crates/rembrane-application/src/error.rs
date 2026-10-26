use std::error::Error;
use std::fmt::{self, Display};

#[derive(Clone, Eq, PartialEq)]
pub enum ApplicationError {
    AccessDenied,
    AlreadyExists,
    NotFound,
    SequenceConflict,
    StorageUnavailable,
    Validation(String),
    VersionConflict,
}

impl fmt::Debug for ApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AccessDenied => "AccessDenied",
            Self::AlreadyExists => "AlreadyExists",
            Self::NotFound => "NotFound",
            Self::SequenceConflict => "SequenceConflict",
            Self::StorageUnavailable => "StorageUnavailable",
            Self::Validation(_) => "Validation(<redacted>)",
            Self::VersionConflict => "VersionConflict",
        })
    }
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

#[cfg(test)]
mod tests {
    use super::ApplicationError;

    #[test]
    fn validation_debug_redacts_arbitrary_detail() {
        let error = ApplicationError::Validation("private user-controlled detail".to_owned());

        assert_eq!(format!("{error:?}"), "Validation(<redacted>)");
        assert!(!format!("{error:?}").contains("private user-controlled detail"));
    }
}

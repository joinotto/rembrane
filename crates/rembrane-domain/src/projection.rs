use std::error::Error;
use std::fmt::{self, Display};

use crate::{MemoryId, ProjectionJobId, ProviderId, WorkspaceId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionOperation {
    Upsert,
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionStatus {
    Pending,
    Processing,
    Completed,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionJobError {
    InvalidVersion,
    InvalidTransition,
    AttemptOverflow,
}

impl Display for ProjectionJobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidVersion => {
                formatter.write_str("projection version must be greater than zero")
            }
            Self::InvalidTransition => formatter.write_str("invalid projection status transition"),
            Self::AttemptOverflow => formatter.write_str("projection attempt count overflow"),
        }
    }
}

impl Error for ProjectionJobError {}

/// Durable work for updating one derived provider from canonical state.
#[derive(Clone, Eq, PartialEq)]
pub struct ProjectionJob {
    id: ProjectionJobId,
    workspace_id: WorkspaceId,
    memory_id: MemoryId,
    memory_version: u64,
    provider_id: ProviderId,
    operation: ProjectionOperation,
    status: ProjectionStatus,
    attempts: u32,
}

impl fmt::Debug for ProjectionJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectionJob")
            .field("id", &"<redacted>")
            .field("workspace_id", &"<redacted>")
            .field("memory_id", &"<redacted>")
            .field("memory_version", &self.memory_version)
            .field("provider_id", &"<redacted>")
            .field("operation", &self.operation)
            .field("status", &self.status)
            .field("attempts", &self.attempts)
            .finish()
    }
}

impl ProjectionJob {
    pub fn restore(
        id: ProjectionJobId,
        workspace_id: WorkspaceId,
        memory_id: MemoryId,
        memory_version: u64,
        provider_id: ProviderId,
        operation: ProjectionOperation,
        status: ProjectionStatus,
        attempts: u32,
    ) -> Result<Self, ProjectionJobError> {
        if memory_version == 0 {
            return Err(ProjectionJobError::InvalidVersion);
        }
        if status != ProjectionStatus::Pending && attempts == 0 {
            return Err(ProjectionJobError::InvalidTransition);
        }

        Ok(Self {
            id,
            workspace_id,
            memory_id,
            memory_version,
            provider_id,
            operation,
            status,
            attempts,
        })
    }

    pub fn new(
        id: ProjectionJobId,
        workspace_id: WorkspaceId,
        memory_id: MemoryId,
        memory_version: u64,
        provider_id: ProviderId,
        operation: ProjectionOperation,
    ) -> Result<Self, ProjectionJobError> {
        if memory_version == 0 {
            return Err(ProjectionJobError::InvalidVersion);
        }

        Ok(Self {
            id,
            workspace_id,
            memory_id,
            memory_version,
            provider_id,
            operation,
            status: ProjectionStatus::Pending,
            attempts: 0,
        })
    }

    pub fn begin(mut self) -> Result<Self, ProjectionJobError> {
        if self.status != ProjectionStatus::Pending {
            return Err(ProjectionJobError::InvalidTransition);
        }
        self.attempts = self
            .attempts
            .checked_add(1)
            .ok_or(ProjectionJobError::AttemptOverflow)?;
        self.status = ProjectionStatus::Processing;
        Ok(self)
    }

    pub fn retry(mut self) -> Result<Self, ProjectionJobError> {
        if self.status != ProjectionStatus::Processing {
            return Err(ProjectionJobError::InvalidTransition);
        }
        self.status = ProjectionStatus::Pending;
        Ok(self)
    }

    pub fn complete(mut self) -> Result<Self, ProjectionJobError> {
        if self.status != ProjectionStatus::Processing {
            return Err(ProjectionJobError::InvalidTransition);
        }
        self.status = ProjectionStatus::Completed;
        Ok(self)
    }

    pub fn quarantine(mut self) -> Result<Self, ProjectionJobError> {
        if self.status != ProjectionStatus::Processing {
            return Err(ProjectionJobError::InvalidTransition);
        }
        self.status = ProjectionStatus::Quarantined;
        Ok(self)
    }

    #[must_use]
    pub const fn id(&self) -> &ProjectionJobId {
        &self.id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn memory_id(&self) -> &MemoryId {
        &self.memory_id
    }

    #[must_use]
    pub const fn memory_version(&self) -> u64 {
        self.memory_version
    }

    #[must_use]
    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    #[must_use]
    pub const fn operation(&self) -> ProjectionOperation {
        self.operation
    }

    #[must_use]
    pub const fn status(&self) -> ProjectionStatus {
        self.status
    }

    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }
}

#[cfg(test)]
mod tests {
    use super::{ProjectionJob, ProjectionJobError, ProjectionOperation, ProjectionStatus};
    use crate::{MemoryId, ProjectionJobId, ProviderId, WorkspaceId};

    fn job() -> ProjectionJob {
        ProjectionJob::new(
            ProjectionJobId::new("projection_01"),
            WorkspaceId::new("workspace_01"),
            MemoryId::new("memory_01"),
            2,
            ProviderId::new("semantic.primary"),
            ProjectionOperation::Upsert,
        )
        .expect("test projection should be valid")
    }

    #[test]
    fn retry_preserves_attempt_count() {
        let pending = job()
            .begin()
            .expect("pending job should begin")
            .retry()
            .expect("processing job should retry");

        assert_eq!(pending.status(), ProjectionStatus::Pending);
        assert_eq!(pending.attempts(), 1);
    }

    #[test]
    fn cannot_complete_job_that_never_started() {
        assert_eq!(job().complete(), Err(ProjectionJobError::InvalidTransition));
    }

    #[test]
    fn debug_output_redacts_projection_routing() {
        let job = ProjectionJob::new(
            ProjectionJobId::new("private_projection"),
            WorkspaceId::new("private_workspace"),
            MemoryId::new("private_memory"),
            7,
            ProviderId::new("private.provider"),
            ProjectionOperation::Delete,
        )
        .expect("job should validate")
        .begin()
        .expect("job should begin");

        let diagnostic = format!("{job:?}");

        for private_value in [
            "private_projection",
            "private_workspace",
            "private_memory",
            "private.provider",
        ] {
            assert!(!diagnostic.contains(private_value));
        }
        assert!(diagnostic.contains("memory_version: 7"));
        assert!(diagnostic.contains("operation: Delete"));
        assert!(diagnostic.contains("status: Processing"));
        assert!(diagnostic.contains("attempts: 1"));
    }
}

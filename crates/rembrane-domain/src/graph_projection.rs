use std::error::Error;
use std::fmt::{self, Display};

use crate::{
    KnowledgeEdgeId, KnowledgeNodeId, ProjectionJobId, ProjectionOperation, ProjectionStatus,
    ProviderId, WorkspaceId,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GraphProjectionResource {
    Node(KnowledgeNodeId),
    Edge(KnowledgeEdgeId),
}

impl GraphProjectionResource {
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Node(id) => id.as_str(),
            Self::Edge(id) => id.as_str(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphProjectionJobError {
    AttemptOverflow,
    InvalidIdentity,
    InvalidTransition,
    InvalidVersion,
}

impl Display for GraphProjectionJobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AttemptOverflow => "graph projection attempt count overflow",
            Self::InvalidIdentity => "graph projection identity is invalid",
            Self::InvalidTransition => "invalid graph projection status transition",
            Self::InvalidVersion => "graph projection version must be greater than zero",
        })
    }
}

impl Error for GraphProjectionJobError {}

/// Durable work for synchronizing one canonical graph aggregate to one
/// replaceable derived engine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GraphProjectionJob {
    id: ProjectionJobId,
    workspace_id: WorkspaceId,
    resource: GraphProjectionResource,
    resource_version: u64,
    provider_id: ProviderId,
    operation: ProjectionOperation,
    status: ProjectionStatus,
    attempts: u32,
}

impl GraphProjectionJob {
    #[allow(clippy::too_many_arguments)]
    pub fn restore(
        id: ProjectionJobId,
        workspace_id: WorkspaceId,
        resource: GraphProjectionResource,
        resource_version: u64,
        provider_id: ProviderId,
        operation: ProjectionOperation,
        status: ProjectionStatus,
        attempts: u32,
    ) -> Result<Self, GraphProjectionJobError> {
        validate(
            &id,
            &workspace_id,
            &resource,
            resource_version,
            status,
            attempts,
        )?;
        Ok(Self {
            id,
            workspace_id,
            resource,
            resource_version,
            provider_id,
            operation,
            status,
            attempts,
        })
    }

    pub fn new(
        id: ProjectionJobId,
        workspace_id: WorkspaceId,
        resource: GraphProjectionResource,
        resource_version: u64,
        provider_id: ProviderId,
        operation: ProjectionOperation,
    ) -> Result<Self, GraphProjectionJobError> {
        Self::restore(
            id,
            workspace_id,
            resource,
            resource_version,
            provider_id,
            operation,
            ProjectionStatus::Pending,
            0,
        )
    }

    pub fn begin(mut self) -> Result<Self, GraphProjectionJobError> {
        if self.status != ProjectionStatus::Pending {
            return Err(GraphProjectionJobError::InvalidTransition);
        }
        self.attempts = self
            .attempts
            .checked_add(1)
            .ok_or(GraphProjectionJobError::AttemptOverflow)?;
        self.status = ProjectionStatus::Processing;
        Ok(self)
    }

    pub fn retry(mut self) -> Result<Self, GraphProjectionJobError> {
        if self.status != ProjectionStatus::Processing {
            return Err(GraphProjectionJobError::InvalidTransition);
        }
        self.status = ProjectionStatus::Pending;
        Ok(self)
    }

    pub fn complete(mut self) -> Result<Self, GraphProjectionJobError> {
        if self.status != ProjectionStatus::Processing {
            return Err(GraphProjectionJobError::InvalidTransition);
        }
        self.status = ProjectionStatus::Completed;
        Ok(self)
    }

    pub fn quarantine(mut self) -> Result<Self, GraphProjectionJobError> {
        if self.status != ProjectionStatus::Processing {
            return Err(GraphProjectionJobError::InvalidTransition);
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
    pub const fn resource(&self) -> &GraphProjectionResource {
        &self.resource
    }

    #[must_use]
    pub const fn resource_version(&self) -> u64 {
        self.resource_version
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

fn validate(
    id: &ProjectionJobId,
    workspace_id: &WorkspaceId,
    resource: &GraphProjectionResource,
    resource_version: u64,
    status: ProjectionStatus,
    attempts: u32,
) -> Result<(), GraphProjectionJobError> {
    if id.as_str().is_empty() || workspace_id.as_str().is_empty() || resource.id().is_empty() {
        return Err(GraphProjectionJobError::InvalidIdentity);
    }
    if resource_version == 0 {
        return Err(GraphProjectionJobError::InvalidVersion);
    }
    if status != ProjectionStatus::Pending && attempts == 0 {
        return Err(GraphProjectionJobError::InvalidTransition);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        GraphProjectionJob, GraphProjectionJobError, GraphProjectionResource, KnowledgeNodeId,
        ProjectionJobId, ProjectionOperation, ProjectionStatus, ProviderId, WorkspaceId,
    };

    fn job() -> GraphProjectionJob {
        GraphProjectionJob::new(
            ProjectionJobId::new("graph_projection_01"),
            WorkspaceId::new("workspace_01"),
            GraphProjectionResource::Node(KnowledgeNodeId::new("node_01")),
            1,
            ProviderId::new("graph.primary"),
            ProjectionOperation::Upsert,
        )
        .expect("job should be valid")
    }

    #[test]
    fn follows_retry_and_completion_state_machine() {
        let retry = job()
            .begin()
            .expect("job should begin")
            .retry()
            .expect("job should retry");
        assert_eq!(retry.status(), ProjectionStatus::Pending);
        assert_eq!(retry.attempts(), 1);
        assert_eq!(
            job().complete(),
            Err(GraphProjectionJobError::InvalidTransition)
        );
    }
}

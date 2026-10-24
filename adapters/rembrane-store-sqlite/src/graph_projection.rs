use rembrane_application::{ApplicationError, GraphProjectionOutboxRepository};
use rembrane_domain::{
    GraphProjectionJob, GraphProjectionResource, KnowledgeEdgeId, KnowledgeNodeId, ProjectionJobId,
    ProjectionOperation, ProjectionStatus, ProviderId, WorkspaceId,
};
use rusqlite::{OptionalExtension, params};

use crate::{SqliteStore, map_write_error};

impl<C> GraphProjectionOutboxRepository for SqliteStore<C> {
    fn enqueue_graph_projection(
        &mut self,
        job: GraphProjectionJob,
    ) -> Result<(), ApplicationError> {
        let (resource_type, node_id, edge_id) = encode_resource(job.resource());
        self.connection
            .execute(
                "INSERT INTO graph_projection_outbox (
                    id, workspace_id, resource_type, node_id, edge_id,
                    resource_version, provider_id, operation, status, attempts
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    job.id().as_str(),
                    job.workspace_id().as_str(),
                    resource_type,
                    node_id,
                    edge_id,
                    to_i64(job.resource_version())?,
                    job.provider_id().as_str(),
                    encode_operation(job.operation()),
                    encode_status(job.status()),
                    i64::from(job.attempts())
                ],
            )
            .map(|_| ())
            .map_err(map_write_error)
    }

    fn pending_graph_projections(
        &self,
        provider_id: &ProviderId,
        limit: usize,
    ) -> Result<Vec<GraphProjectionJob>, ApplicationError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, workspace_id, resource_type, node_id, edge_id,
                        resource_version, provider_id, operation, status, attempts
                 FROM graph_projection_outbox
                 WHERE provider_id = ?1
                   AND status = 'pending'
                   AND available_at <= CURRENT_TIMESTAMP
                 ORDER BY available_at, id
                 LIMIT ?2",
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let rows = statement
            .query_map(
                params![
                    provider_id.as_str(),
                    i64::try_from(limit).map_err(|_| {
                        ApplicationError::Validation(
                            "graph projection limit exceeds SQLite range".to_owned(),
                        )
                    })?
                ],
                decode_row,
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        rows.map(|row| {
            row.map_err(|_| ApplicationError::StorageUnavailable)
                .and_then(GraphProjectionJob::try_from)
        })
        .collect()
    }

    fn replace_graph_projection(
        &mut self,
        job: GraphProjectionJob,
        expected_status: ProjectionStatus,
        expected_attempts: u32,
    ) -> Result<(), ApplicationError> {
        let (resource_type, node_id, edge_id) = encode_resource(job.resource());
        let changed = self
            .connection
            .execute(
                "UPDATE graph_projection_outbox
                 SET status = ?2,
                     attempts = ?3,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?1
                   AND workspace_id = ?4
                   AND resource_type = ?5
                   AND node_id IS ?6
                   AND edge_id IS ?7
                   AND resource_version = ?8
                   AND provider_id = ?9
                   AND operation = ?10
                   AND status = ?11
                   AND attempts = ?12",
                params![
                    job.id().as_str(),
                    encode_status(job.status()),
                    i64::from(job.attempts()),
                    job.workspace_id().as_str(),
                    resource_type,
                    node_id,
                    edge_id,
                    to_i64(job.resource_version())?,
                    job.provider_id().as_str(),
                    encode_operation(job.operation()),
                    encode_status(expected_status),
                    i64::from(expected_attempts)
                ],
            )
            .map_err(map_write_error)?;
        if changed == 0 {
            return Err(ApplicationError::VersionConflict);
        }
        Ok(())
    }

    fn find_graph_projection(
        &self,
        workspace_id: &WorkspaceId,
        job_id: &ProjectionJobId,
    ) -> Result<Option<GraphProjectionJob>, ApplicationError> {
        self.connection
            .query_row(
                "SELECT id, workspace_id, resource_type, node_id, edge_id,
                        resource_version, provider_id, operation, status, attempts
                 FROM graph_projection_outbox
                 WHERE workspace_id = ?1 AND id = ?2",
                params![workspace_id.as_str(), job_id.as_str()],
                decode_row,
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?
            .map(GraphProjectionJob::try_from)
            .transpose()
    }
}

struct GraphProjectionRow {
    id: String,
    workspace_id: String,
    resource_type: String,
    node_id: Option<String>,
    edge_id: Option<String>,
    resource_version: i64,
    provider_id: String,
    operation: String,
    status: String,
    attempts: i64,
}

impl TryFrom<GraphProjectionRow> for GraphProjectionJob {
    type Error = ApplicationError;

    fn try_from(row: GraphProjectionRow) -> Result<Self, Self::Error> {
        Self::restore(
            ProjectionJobId::new(row.id),
            WorkspaceId::new(row.workspace_id),
            decode_resource(&row.resource_type, row.node_id, row.edge_id)?,
            u64::try_from(row.resource_version)
                .map_err(|_| ApplicationError::StorageUnavailable)?,
            ProviderId::new(row.provider_id),
            decode_operation(&row.operation)?,
            decode_status(&row.status)?,
            u32::try_from(row.attempts).map_err(|_| ApplicationError::StorageUnavailable)?,
        )
        .map_err(|_| ApplicationError::StorageUnavailable)
    }
}

fn decode_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<GraphProjectionRow> {
    Ok(GraphProjectionRow {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        resource_type: row.get(2)?,
        node_id: row.get(3)?,
        edge_id: row.get(4)?,
        resource_version: row.get(5)?,
        provider_id: row.get(6)?,
        operation: row.get(7)?,
        status: row.get(8)?,
        attempts: row.get(9)?,
    })
}

fn encode_resource(
    resource: &GraphProjectionResource,
) -> (&'static str, Option<&str>, Option<&str>) {
    match resource {
        GraphProjectionResource::Node(id) => ("node", Some(id.as_str()), None),
        GraphProjectionResource::Edge(id) => ("edge", None, Some(id.as_str())),
    }
}

fn decode_resource(
    resource_type: &str,
    node_id: Option<String>,
    edge_id: Option<String>,
) -> Result<GraphProjectionResource, ApplicationError> {
    match (resource_type, node_id, edge_id) {
        ("node", Some(id), None) => Ok(GraphProjectionResource::Node(KnowledgeNodeId::new(id))),
        ("edge", None, Some(id)) => Ok(GraphProjectionResource::Edge(KnowledgeEdgeId::new(id))),
        _ => Err(ApplicationError::StorageUnavailable),
    }
}

const fn encode_operation(operation: ProjectionOperation) -> &'static str {
    match operation {
        ProjectionOperation::Upsert => "upsert",
        ProjectionOperation::Delete => "delete",
    }
}

fn decode_operation(operation: &str) -> Result<ProjectionOperation, ApplicationError> {
    match operation {
        "upsert" => Ok(ProjectionOperation::Upsert),
        "delete" => Ok(ProjectionOperation::Delete),
        _ => Err(ApplicationError::StorageUnavailable),
    }
}

const fn encode_status(status: ProjectionStatus) -> &'static str {
    match status {
        ProjectionStatus::Pending => "pending",
        ProjectionStatus::Processing => "processing",
        ProjectionStatus::Completed => "completed",
        ProjectionStatus::Quarantined => "quarantined",
    }
}

fn decode_status(status: &str) -> Result<ProjectionStatus, ApplicationError> {
    match status {
        "pending" => Ok(ProjectionStatus::Pending),
        "processing" => Ok(ProjectionStatus::Processing),
        "completed" => Ok(ProjectionStatus::Completed),
        "quarantined" => Ok(ProjectionStatus::Quarantined),
        _ => Err(ApplicationError::StorageUnavailable),
    }
}

fn to_i64(value: u64) -> Result<i64, ApplicationError> {
    i64::try_from(value).map_err(|_| {
        ApplicationError::Validation("graph projection version exceeds SQLite range".to_owned())
    })
}

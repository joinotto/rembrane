use rembrane_application::{ApplicationError, ProjectionOutboxRepository};
use rembrane_domain::{
    MemoryId, ProjectionJob, ProjectionJobId, ProjectionOperation, ProjectionStatus, ProviderId,
    WorkspaceId,
};
use rusqlite::{OptionalExtension, params};

use crate::{SqliteStore, map_write_error};

impl<C> ProjectionOutboxRepository for SqliteStore<C> {
    fn enqueue_projection(&mut self, job: ProjectionJob) -> Result<(), ApplicationError> {
        let memory_version = to_i64(job.memory_version())?;
        self.connection
            .execute(
                "INSERT INTO projection_outbox (
                    id,
                    workspace_id,
                    memory_id,
                    memory_version,
                    provider_id,
                    operation,
                    status,
                    attempts
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    job.id().as_str(),
                    job.workspace_id().as_str(),
                    job.memory_id().as_str(),
                    memory_version,
                    job.provider_id().as_str(),
                    encode_operation(job.operation()),
                    encode_status(job.status()),
                    i64::from(job.attempts())
                ],
            )
            .map(|_| ())
            .map_err(map_write_error)
    }

    fn pending_projections(
        &self,
        provider_id: &ProviderId,
        limit: usize,
    ) -> Result<Vec<ProjectionJob>, ApplicationError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT
                    id,
                    workspace_id,
                    memory_id,
                    memory_version,
                    provider_id,
                    operation,
                    status,
                    attempts
                 FROM projection_outbox
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
                            "projection limit exceeds SQLite range".to_owned(),
                        )
                    })?
                ],
                decode_projection_row,
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;

        rows.map(|row| {
            row.map_err(|_| ApplicationError::StorageUnavailable)
                .and_then(ProjectionJob::try_from)
        })
        .collect()
    }

    fn replace_projection(
        &mut self,
        job: ProjectionJob,
        expected_status: ProjectionStatus,
        expected_attempts: u32,
    ) -> Result<(), ApplicationError> {
        let changed = self
            .connection
            .execute(
                "UPDATE projection_outbox
                 SET status = ?2,
                     attempts = ?3,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?1
                   AND workspace_id = ?4
                   AND memory_id = ?5
                   AND memory_version = ?6
                   AND provider_id = ?7
                   AND operation = ?8
                   AND status = ?9
                   AND attempts = ?10",
                params![
                    job.id().as_str(),
                    encode_status(job.status()),
                    i64::from(job.attempts()),
                    job.workspace_id().as_str(),
                    job.memory_id().as_str(),
                    to_i64(job.memory_version())?,
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

    fn find_projection(
        &self,
        workspace_id: &WorkspaceId,
        job_id: &ProjectionJobId,
    ) -> Result<Option<ProjectionJob>, ApplicationError> {
        self.connection
            .query_row(
                "SELECT
                    id,
                    workspace_id,
                    memory_id,
                    memory_version,
                    provider_id,
                    operation,
                    status,
                    attempts
                 FROM projection_outbox
                 WHERE workspace_id = ?1 AND id = ?2",
                params![workspace_id.as_str(), job_id.as_str()],
                decode_projection_row,
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?
            .map(ProjectionJob::try_from)
            .transpose()
    }
}

struct ProjectionRow {
    id: String,
    workspace_id: String,
    memory_id: String,
    memory_version: i64,
    provider_id: String,
    operation: String,
    status: String,
    attempts: i64,
}

impl TryFrom<ProjectionRow> for ProjectionJob {
    type Error = ApplicationError;

    fn try_from(row: ProjectionRow) -> Result<Self, Self::Error> {
        Self::restore(
            ProjectionJobId::new(row.id),
            WorkspaceId::new(row.workspace_id),
            MemoryId::new(row.memory_id),
            u64::try_from(row.memory_version).map_err(|_| ApplicationError::StorageUnavailable)?,
            ProviderId::new(row.provider_id),
            decode_operation(&row.operation)?,
            decode_status(&row.status)?,
            u32::try_from(row.attempts).map_err(|_| ApplicationError::StorageUnavailable)?,
        )
        .map_err(|_| ApplicationError::StorageUnavailable)
    }
}

fn decode_projection_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProjectionRow> {
    Ok(ProjectionRow {
        id: row.get(0)?,
        workspace_id: row.get(1)?,
        memory_id: row.get(2)?,
        memory_version: row.get(3)?,
        provider_id: row.get(4)?,
        operation: row.get(5)?,
        status: row.get(6)?,
        attempts: row.get(7)?,
    })
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
    i64::try_from(value)
        .map_err(|_| ApplicationError::Validation("numeric value exceeds SQLite range".to_owned()))
}

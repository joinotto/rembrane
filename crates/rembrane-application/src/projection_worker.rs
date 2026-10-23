use rembrane_domain::{
    MemoryStatus, ProjectionJob, ProjectionOperation, ProjectionStatus,
    ProviderId,
};
use rembrane_provider_sdk::{
    AuthorizedMemoryProjection, Capability, SemanticMemoryProvider,
};

use crate::{
    ApplicationError, MemoryRepository, ProjectionOutboxRepository,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionOutcome {
    NoWork,
    Completed,
    Superseded,
    Retried,
    Quarantined,
}

pub struct ProjectionWorker<'worker, Repository, Provider> {
    repository: &'worker mut Repository,
    provider: &'worker mut Provider,
    provider_id: ProviderId,
    maximum_attempts: u32,
}

impl<'worker, Repository, Provider>
    ProjectionWorker<'worker, Repository, Provider>
where
    Repository: MemoryRepository + ProjectionOutboxRepository,
    Provider: SemanticMemoryProvider,
{
    pub fn new(
        repository: &'worker mut Repository,
        provider: &'worker mut Provider,
        provider_id: ProviderId,
        maximum_attempts: u32,
    ) -> Result<Self, ApplicationError> {
        if maximum_attempts == 0 {
            return Err(ApplicationError::Validation(
                "maximum_attempts must be greater than zero".to_owned(),
            ));
        }
        let manifest = provider.manifest();
        if manifest.id != provider_id.as_str() {
            return Err(ApplicationError::Validation(
                "configured provider id does not match provider manifest"
                    .to_owned(),
            ));
        }
        let required = [
            Capability::Index,
            Capability::Delete,
            Capability::WorkspaceFilter,
            Capability::VersionedRecords,
        ];
        if !manifest.supports_all(&required) {
            return Err(ApplicationError::Validation(
                "provider lacks required projection capabilities".to_owned(),
            ));
        }
        Ok(Self {
            repository,
            provider,
            provider_id,
            maximum_attempts,
        })
    }

    pub fn process_next(
        &mut self,
    ) -> Result<ProjectionOutcome, ApplicationError> {
        let Some(pending) = self
            .repository
            .pending_projections(&self.provider_id, 1)?
            .into_iter()
            .next()
        else {
            return Ok(ProjectionOutcome::NoWork);
        };

        let processing = pending
            .clone()
            .begin()
            .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        self.repository.replace_projection(
            processing.clone(),
            ProjectionStatus::Pending,
            pending.attempts(),
        )?;

        match self.apply(&processing) {
            Ok(
                result
                @ (ProjectionOutcome::Completed
                    | ProjectionOutcome::Superseded),
            ) => {
                let completed = processing
                    .clone()
                    .complete()
                    .map_err(|error| {
                        ApplicationError::Validation(error.to_string())
                    })?;
                self.repository.replace_projection(
                    completed,
                    ProjectionStatus::Processing,
                    processing.attempts(),
                )?;
                Ok(result)
            }
            Ok(other) => Ok(other),
            Err(_) if processing.attempts() >= self.maximum_attempts => {
                let quarantined = processing
                    .clone()
                    .quarantine()
                    .map_err(|error| {
                        ApplicationError::Validation(error.to_string())
                    })?;
                self.repository.replace_projection(
                    quarantined,
                    ProjectionStatus::Processing,
                    processing.attempts(),
                )?;
                Ok(ProjectionOutcome::Quarantined)
            }
            Err(_) => {
                let retry = processing
                    .clone()
                    .retry()
                    .map_err(|error| {
                        ApplicationError::Validation(error.to_string())
                    })?;
                self.repository.replace_projection(
                    retry,
                    ProjectionStatus::Processing,
                    processing.attempts(),
                )?;
                Ok(ProjectionOutcome::Retried)
            }
        }
    }

    fn apply(
        &mut self,
        job: &ProjectionJob,
    ) -> Result<ProjectionOutcome, ApplicationError> {
        match job.operation() {
            ProjectionOperation::Upsert => self.upsert(job),
            ProjectionOperation::Delete => self.delete(job),
        }
    }

    fn upsert(
        &mut self,
        job: &ProjectionJob,
    ) -> Result<ProjectionOutcome, ApplicationError> {
        let Some(memory) = self
            .repository
            .find(job.workspace_id(), job.memory_id())?
        else {
            return Ok(ProjectionOutcome::Superseded);
        };
        if memory.version() != job.memory_version()
            || memory.status() == MemoryStatus::Deleted
        {
            return Ok(ProjectionOutcome::Superseded);
        }

        self.provider
            .index(AuthorizedMemoryProjection {
                workspace_id: memory.workspace_id().clone(),
                memory_id: memory.id().clone(),
                version: memory.version(),
                scope: memory.scope().clone(),
                kind: memory.kind(),
                content: memory.content().to_owned(),
            })
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        Ok(ProjectionOutcome::Completed)
    }

    fn delete(
        &mut self,
        job: &ProjectionJob,
    ) -> Result<ProjectionOutcome, ApplicationError> {
        self.provider
            .delete(
                job.workspace_id(),
                job.memory_id(),
                job.memory_version(),
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        Ok(ProjectionOutcome::Completed)
    }
}

use rembrane_domain::{
    GraphProjectionJob, GraphProjectionResource, ProjectionOperation, ProjectionStatus, ProviderId,
};
use rembrane_provider_sdk::{
    CURRENT_PROVIDER_PROTOCOL, Capability, KnowledgeGraphProvider, ProviderPolicy,
};

use crate::{
    ApplicationError, GraphProjectionOutboxRepository, KnowledgeGraphRepository, ProjectionOutcome,
};

pub struct GraphProjectionWorker<'worker, Repository, Provider> {
    repository: &'worker mut Repository,
    provider: &'worker mut Provider,
    provider_id: ProviderId,
    maximum_attempts: u32,
}

impl<'worker, Repository, Provider> GraphProjectionWorker<'worker, Repository, Provider>
where
    Repository: GraphProjectionOutboxRepository + KnowledgeGraphRepository,
    Provider: KnowledgeGraphProvider,
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
                "configured graph provider id does not match its manifest".to_owned(),
            ));
        }
        ProviderPolicy {
            minimum_protocol_version: CURRENT_PROVIDER_PROTOCOL,
            required_capabilities: vec![
                Capability::GraphUpsert,
                Capability::Delete,
                Capability::WorkspaceFilter,
                Capability::VersionedRecords,
            ],
            allow_plaintext_processing: true,
        }
        .validate(&manifest)
        .map_err(|_| {
            ApplicationError::Validation(
                "provider does not satisfy graph projection requirements".to_owned(),
            )
        })?;
        Ok(Self {
            repository,
            provider,
            provider_id,
            maximum_attempts,
        })
    }

    pub fn process_next(&mut self) -> Result<ProjectionOutcome, ApplicationError> {
        let Some(pending) = self
            .repository
            .pending_graph_projections(&self.provider_id, 1)?
            .into_iter()
            .next()
        else {
            return Ok(ProjectionOutcome::NoWork);
        };
        let processing = pending
            .clone()
            .begin()
            .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        self.repository.replace_graph_projection(
            processing.clone(),
            ProjectionStatus::Pending,
            pending.attempts(),
        )?;

        match self.apply(&processing) {
            Ok(result @ (ProjectionOutcome::Completed | ProjectionOutcome::Superseded)) => {
                let completed = processing
                    .clone()
                    .complete()
                    .map_err(|error| ApplicationError::Validation(error.to_string()))?;
                self.repository.replace_graph_projection(
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
                    .map_err(|error| ApplicationError::Validation(error.to_string()))?;
                self.repository.replace_graph_projection(
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
                    .map_err(|error| ApplicationError::Validation(error.to_string()))?;
                self.repository.replace_graph_projection(
                    retry,
                    ProjectionStatus::Processing,
                    processing.attempts(),
                )?;
                Ok(ProjectionOutcome::Retried)
            }
        }
    }

    fn apply(&mut self, job: &GraphProjectionJob) -> Result<ProjectionOutcome, ApplicationError> {
        match job.operation() {
            ProjectionOperation::Upsert => self.upsert(job),
            ProjectionOperation::Delete => self.delete(job),
        }
    }

    fn upsert(&mut self, job: &GraphProjectionJob) -> Result<ProjectionOutcome, ApplicationError> {
        match job.resource() {
            GraphProjectionResource::Node(node_id) => {
                let Some(node) = self
                    .repository
                    .find_knowledge_node(job.workspace_id(), node_id)?
                else {
                    return Ok(ProjectionOutcome::Superseded);
                };
                if node.version() != job.resource_version() {
                    return Ok(ProjectionOutcome::Superseded);
                }
                self.provider
                    .upsert_node(node)
                    .map_err(|_| ApplicationError::StorageUnavailable)?;
            }
            GraphProjectionResource::Edge(edge_id) => {
                let Some(edge) = self
                    .repository
                    .find_knowledge_edge(job.workspace_id(), edge_id)?
                else {
                    return Ok(ProjectionOutcome::Superseded);
                };
                if edge.version() != job.resource_version() {
                    return Ok(ProjectionOutcome::Superseded);
                }
                self.provider
                    .upsert_edge(edge)
                    .map_err(|_| ApplicationError::StorageUnavailable)?;
            }
        }
        Ok(ProjectionOutcome::Completed)
    }

    fn delete(&mut self, job: &GraphProjectionJob) -> Result<ProjectionOutcome, ApplicationError> {
        match job.resource() {
            GraphProjectionResource::Node(node_id) => {
                self.provider
                    .delete_node(job.workspace_id(), node_id, job.resource_version())
            }
            GraphProjectionResource::Edge(edge_id) => {
                self.provider
                    .delete_edge(job.workspace_id(), edge_id, job.resource_version())
            }
        }
        .map_err(|_| ApplicationError::StorageUnavailable)?;
        Ok(ProjectionOutcome::Completed)
    }
}

//! Volatile reference adapter used by tests, examples, and local prototypes.

use rembrane_application::{
    ApplicationError, CanonicalMutationRepository,
    CheckpointMutationRepository, CheckpointRepository, DisclosureRepository,
    EventRepository, MembershipRepository, MemoryRepository,
    ProjectionOutboxRepository, WorkspaceRepository,
};
use rembrane_domain::{
    ActivityCheckpoint, ActivityId, CanonicalEvent, DisclosureReceipt,
    Membership, MemoryId, MemoryRecord, Principal, PrincipalId, ProjectionJob,
    ProjectionJobId, ProjectionOperation, ProjectionStatus, ProviderId,
    Workspace, WorkspaceId, WorkspaceKind, WorkspaceRole,
};

#[derive(Debug, Default)]
pub struct InMemoryStore {
    principals: Vec<Principal>,
    workspaces: Vec<Workspace>,
    memories: Vec<MemoryRecord>,
    disclosures: Vec<DisclosureReceipt>,
    events: Vec<CanonicalEvent>,
    checkpoints: Vec<ActivityCheckpoint>,
    memberships: Vec<Membership>,
    projections: Vec<ProjectionJob>,
}

impl WorkspaceRepository for InMemoryStore {
    fn initialize_personal_workspace(
        &mut self,
        principal: Principal,
        workspace: Workspace,
        owner_membership: Membership,
    ) -> Result<(), ApplicationError> {
        if workspace.kind() != WorkspaceKind::Personal
            || owner_membership.workspace_id() != workspace.id()
            || owner_membership.principal_id() != principal.id()
            || owner_membership.role() != WorkspaceRole::Owner
            || !owner_membership.is_active()
        {
            return Err(ApplicationError::Validation(
                "personal workspace bootstrap records must agree".to_owned(),
            ));
        }
        if self
            .principals
            .iter()
            .any(|stored| stored.id() == principal.id())
            || self
                .workspaces
                .iter()
                .any(|stored| stored.id() == workspace.id())
            || self.memberships.iter().any(|stored| {
                stored.workspace_id() == workspace.id()
                    && stored.principal_id() == principal.id()
            })
        {
            return Err(ApplicationError::AlreadyExists);
        }

        self.principals.push(principal);
        self.workspaces.push(workspace);
        self.memberships.push(owner_membership);
        Ok(())
    }

    fn find_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Option<Principal>, ApplicationError> {
        Ok(self
            .principals
            .iter()
            .find(|principal| principal.id() == principal_id)
            .cloned())
    }

    fn find_workspace(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<Workspace>, ApplicationError> {
        Ok(self
            .workspaces
            .iter()
            .find(|workspace| workspace.id() == workspace_id)
            .cloned())
    }
}

impl InMemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn disclosure_count(&self) -> usize {
        self.disclosures.len()
    }
}

impl MemoryRepository for InMemoryStore {
    fn find(
        &self,
        workspace_id: &WorkspaceId,
        memory_id: &MemoryId,
    ) -> Result<Option<MemoryRecord>, ApplicationError> {
        Ok(self
            .memories
            .iter()
            .find(|memory| {
                memory.workspace_id() == workspace_id
                    && memory.id() == memory_id
            })
            .cloned())
    }

    fn list_for_subject(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
    ) -> Result<Vec<MemoryRecord>, ApplicationError> {
        Ok(self
            .memories
            .iter()
            .filter(|memory| {
                memory.workspace_id() == workspace_id
                    && memory.subject_id() == subject_id
            })
            .cloned()
            .collect())
    }

}

impl CanonicalMutationRepository for InMemoryStore {
    fn insert_memory_with_event(
        &mut self,
        memory: MemoryRecord,
        event: CanonicalEvent,
        projections: Vec<ProjectionJob>,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        if memory.workspace_id() != event.workspace_id() {
            return Err(ApplicationError::Validation(
                "memory and event workspace must match".to_owned(),
            ));
        }
        if self.memories.iter().any(|stored| {
            stored.workspace_id() == memory.workspace_id()
                && stored.id() == memory.id()
        }) {
            return Err(ApplicationError::AlreadyExists);
        }
        self.validate_event(&event, expected_previous_sequence)?;
        self.validate_projections(&memory, &projections)?;

        self.memories.push(memory);
        self.events.push(event);
        self.projections.extend(projections);
        Ok(())
    }

    fn replace_memory_with_event(
        &mut self,
        memory: MemoryRecord,
        expected_memory_version: u64,
        event: CanonicalEvent,
        projections: Vec<ProjectionJob>,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        if memory.workspace_id() != event.workspace_id() {
            return Err(ApplicationError::Validation(
                "memory and event workspace must match".to_owned(),
            ));
        }

        let position = self
            .memories
            .iter()
            .position(|stored| {
                stored.workspace_id() == memory.workspace_id()
                    && stored.id() == memory.id()
            })
            .ok_or(ApplicationError::NotFound)?;
        let stored = &self.memories[position];
        if stored.version() != expected_memory_version
            || memory.version()
                != expected_memory_version.saturating_add(1)
        {
            return Err(ApplicationError::VersionConflict);
        }
        self.validate_event(&event, expected_previous_sequence)?;
        self.validate_projections(&memory, &projections)?;

        self.memories[position] = memory;
        self.events.push(event);
        self.projections.extend(projections);
        Ok(())
    }
}

impl DisclosureRepository for InMemoryStore {
    fn append(
        &mut self,
        receipt: DisclosureReceipt,
    ) -> Result<(), ApplicationError> {
        let duplicate = self
            .disclosures
            .iter()
            .any(|stored| stored.id == receipt.id);

        if duplicate {
            return Err(ApplicationError::AlreadyExists);
        }

        self.disclosures.push(receipt);
        Ok(())
    }
}

impl ProjectionOutboxRepository for InMemoryStore {
    fn enqueue_projection(
        &mut self,
        job: ProjectionJob,
    ) -> Result<(), ApplicationError> {
        let duplicate = self.projections.iter().any(|stored| {
            stored.id() == job.id()
                || (stored.workspace_id() == job.workspace_id()
                    && stored.memory_id() == job.memory_id()
                    && stored.memory_version() == job.memory_version()
                    && stored.provider_id() == job.provider_id()
                    && stored.operation() == job.operation())
        });
        if duplicate {
            return Err(ApplicationError::AlreadyExists);
        }

        self.projections.push(job);
        Ok(())
    }

    fn pending_projections(
        &self,
        provider_id: &ProviderId,
        limit: usize,
    ) -> Result<Vec<ProjectionJob>, ApplicationError> {
        Ok(self
            .projections
            .iter()
            .filter(|job| {
                job.provider_id() == provider_id
                    && job.status() == ProjectionStatus::Pending
            })
            .take(limit)
            .cloned()
            .collect())
    }

    fn replace_projection(
        &mut self,
        job: ProjectionJob,
        expected_status: ProjectionStatus,
        expected_attempts: u32,
    ) -> Result<(), ApplicationError> {
        let stored = self
            .projections
            .iter_mut()
            .find(|stored| stored.id() == job.id())
            .ok_or(ApplicationError::NotFound)?;

        if stored.status() != expected_status
            || stored.attempts() != expected_attempts
        {
            return Err(ApplicationError::VersionConflict);
        }
        if stored.workspace_id() != job.workspace_id()
            || stored.memory_id() != job.memory_id()
            || stored.memory_version() != job.memory_version()
            || stored.provider_id() != job.provider_id()
            || stored.operation() != job.operation()
        {
            return Err(ApplicationError::Validation(
                "projection identity fields are immutable".to_owned(),
            ));
        }

        *stored = job;
        Ok(())
    }

    fn find_projection(
        &self,
        workspace_id: &WorkspaceId,
        job_id: &ProjectionJobId,
    ) -> Result<Option<ProjectionJob>, ApplicationError> {
        Ok(self
            .projections
            .iter()
            .find(|job| {
                job.workspace_id() == workspace_id && job.id() == job_id
            })
            .cloned())
    }
}

impl MembershipRepository for InMemoryStore {
    fn insert_membership(
        &mut self,
        membership: Membership,
    ) -> Result<(), ApplicationError> {
        let duplicate = self.memberships.iter().any(|stored| {
            stored.workspace_id() == membership.workspace_id()
                && stored.principal_id() == membership.principal_id()
        });
        if duplicate {
            return Err(ApplicationError::AlreadyExists);
        }

        self.memberships.push(membership);
        Ok(())
    }

    fn find_membership(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Option<Membership>, ApplicationError> {
        Ok(self
            .memberships
            .iter()
            .find(|membership| {
                membership.workspace_id() == workspace_id
                    && membership.principal_id() == principal_id
            })
            .cloned())
    }

    fn replace_membership(
        &mut self,
        membership: Membership,
    ) -> Result<(), ApplicationError> {
        let stored = self
            .memberships
            .iter_mut()
            .find(|stored| {
                stored.workspace_id() == membership.workspace_id()
                    && stored.principal_id() == membership.principal_id()
            })
            .ok_or(ApplicationError::NotFound)?;

        *stored = membership;
        Ok(())
    }
}

impl CheckpointRepository for InMemoryStore {
    fn latest_checkpoint(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
        activity_id: &ActivityId,
    ) -> Result<Option<ActivityCheckpoint>, ApplicationError> {
        Ok(self
            .checkpoints
            .iter()
            .filter(|checkpoint| {
                checkpoint.workspace_id() == workspace_id
                    && checkpoint.subject_id() == subject_id
                    && checkpoint.activity_id() == activity_id
            })
            .max_by_key(|checkpoint| checkpoint.version())
            .cloned())
    }

}

impl CheckpointMutationRepository for InMemoryStore {
    fn insert_checkpoint_with_event(
        &mut self,
        checkpoint: ActivityCheckpoint,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        if checkpoint.workspace_id() != event.workspace_id() {
            return Err(ApplicationError::Validation(
                "checkpoint and event workspace must match".to_owned(),
            ));
        }
        if self.checkpoints.iter().any(|stored| {
            stored.workspace_id() == checkpoint.workspace_id()
                && stored.id() == checkpoint.id()
        }) {
            return Err(ApplicationError::AlreadyExists);
        }
        self.validate_event(&event, expected_previous_sequence)?;

        self.checkpoints.push(checkpoint);
        self.events.push(event);
        Ok(())
    }

    fn replace_checkpoint_with_event(
        &mut self,
        checkpoint: ActivityCheckpoint,
        expected_checkpoint_version: u64,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        if checkpoint.workspace_id() != event.workspace_id() {
            return Err(ApplicationError::Validation(
                "checkpoint and event workspace must match".to_owned(),
            ));
        }
        let position = self
            .checkpoints
            .iter()
            .position(|stored| {
                stored.workspace_id() == checkpoint.workspace_id()
                    && stored.id() == checkpoint.id()
            })
            .ok_or(ApplicationError::NotFound)?;
        let stored = &self.checkpoints[position];
        if stored.version() != expected_checkpoint_version
            || checkpoint.version()
                != expected_checkpoint_version.saturating_add(1)
        {
            return Err(ApplicationError::VersionConflict);
        }
        self.validate_event(&event, expected_previous_sequence)?;

        self.checkpoints[position] = checkpoint;
        self.events.push(event);
        Ok(())
    }
}

impl EventRepository for InMemoryStore {
    fn append_event(
        &mut self,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        let current_sequence = self
            .events
            .iter()
            .filter(|stored| stored.workspace_id() == event.workspace_id())
            .map(CanonicalEvent::sequence)
            .max()
            .unwrap_or(0);

        if current_sequence != expected_previous_sequence
            || event.sequence() != expected_previous_sequence.saturating_add(1)
        {
            return Err(ApplicationError::SequenceConflict);
        }

        let duplicate_id = self
            .events
            .iter()
            .any(|stored| stored.id() == event.id());
        if duplicate_id {
            return Err(ApplicationError::AlreadyExists);
        }

        self.events.push(event);
        Ok(())
    }

    fn list_events_since(
        &self,
        workspace_id: &WorkspaceId,
        sequence: u64,
    ) -> Result<Vec<CanonicalEvent>, ApplicationError> {
        let mut events: Vec<_> = self
            .events
            .iter()
            .filter(|event| {
                event.workspace_id() == workspace_id
                    && event.sequence() > sequence
            })
            .cloned()
            .collect();
        events.sort_by_key(CanonicalEvent::sequence);
        Ok(events)
    }
}

impl InMemoryStore {
    fn validate_event(
        &self,
        event: &CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        let current_sequence = self
            .events
            .iter()
            .filter(|stored| stored.workspace_id() == event.workspace_id())
            .map(CanonicalEvent::sequence)
            .max()
            .unwrap_or(0);
        if current_sequence != expected_previous_sequence
            || event.sequence() != expected_previous_sequence.saturating_add(1)
        {
            return Err(ApplicationError::SequenceConflict);
        }
        if self
            .events
            .iter()
            .any(|stored| stored.id() == event.id())
        {
            return Err(ApplicationError::AlreadyExists);
        }
        Ok(())
    }

    fn validate_projections(
        &self,
        memory: &MemoryRecord,
        projections: &[ProjectionJob],
    ) -> Result<(), ApplicationError> {
        let expected_operation = if memory.status()
            == rembrane_domain::MemoryStatus::Deleted
        {
            ProjectionOperation::Delete
        } else {
            ProjectionOperation::Upsert
        };

        for (index, projection) in projections.iter().enumerate() {
            if projection.workspace_id() != memory.workspace_id()
                || projection.memory_id() != memory.id()
                || projection.memory_version() != memory.version()
                || projection.operation() != expected_operation
            {
                return Err(ApplicationError::Validation(
                    "projection does not match canonical memory mutation"
                        .to_owned(),
                ));
            }
            if self.projections.iter().any(|stored| {
                stored.id() == projection.id()
                    || (stored.workspace_id() == projection.workspace_id()
                        && stored.memory_id() == projection.memory_id()
                        && stored.memory_version()
                            == projection.memory_version()
                        && stored.provider_id() == projection.provider_id()
                        && stored.operation() == projection.operation())
            }) {
                return Err(ApplicationError::AlreadyExists);
            }
            if projections[..index].iter().any(|earlier| {
                earlier.id() == projection.id()
                    || (earlier.provider_id() == projection.provider_id()
                        && earlier.operation() == projection.operation())
            }) {
                return Err(ApplicationError::AlreadyExists);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rembrane_application::{
        ApplicationError, CanonicalMutationRepository, EventRepository,
        MemoryRepository,
    };
    use rembrane_domain::{
        CanonicalEvent, EventId, EventPayload, EvidenceId, EvidenceReference,
        EvidenceSource, MemoryId, MemoryRecord, MemoryScope, PrincipalId,
        WorkspaceId,
    };

    use super::InMemoryStore;

    fn preference(
        memory_id: &str,
        workspace_id: &str,
        subject_id: &str,
        content: &str,
    ) -> MemoryRecord {
        MemoryRecord::confirmed_preference(
            MemoryId::new(memory_id),
            WorkspaceId::new(workspace_id),
            PrincipalId::new(subject_id),
            MemoryScope::Global,
            content,
            EvidenceReference::new(
                EvidenceId::new(format!("evidence_{memory_id}")),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("test preference should be valid")
    }

    fn insert(
        store: &mut InMemoryStore,
        memory: MemoryRecord,
        event_id: &str,
    ) -> Result<(), ApplicationError> {
        let event = CanonicalEvent::new(
            EventId::new(event_id),
            memory.workspace_id().clone(),
            memory.subject_id().clone(),
            Some(memory.subject_id().clone()),
            1,
            EventPayload::MemoryCreated {
                memory_id: memory.id().clone(),
                version: memory.version(),
            },
        )
        .expect("test event should be valid");
        store.insert_memory_with_event(memory, event, Vec::new(), 0)
    }

    #[test]
    fn does_not_find_memory_across_workspace_boundary() {
        let mut store = InMemoryStore::new();
        insert(
            &mut store,
            preference(
                "memory_01",
                "workspace_private",
                "principal_01",
                "Call me Hippo",
            ),
            "event_private",
        )
        .expect("insert should succeed");

        let result = store
            .find(
                &WorkspaceId::new("workspace_other"),
                &MemoryId::new("memory_01"),
            )
            .expect("lookup should succeed");

        assert!(result.is_none());
    }

    #[test]
    fn permits_same_memory_id_in_different_workspaces() {
        let mut store = InMemoryStore::new();
        insert(
            &mut store,
            preference(
                "memory_01",
                "workspace_one",
                "principal_01",
                "Preference one",
            ),
            "event_one",
        )
        .expect("first insert should succeed");
        insert(
            &mut store,
            preference(
                "memory_01",
                "workspace_two",
                "principal_02",
                "Preference two",
            ),
            "event_two",
        )
        .expect("second workspace insert should succeed");

        assert_eq!(
            store
                .list_for_subject(
                    &WorkspaceId::new("workspace_one"),
                    &PrincipalId::new("principal_01"),
                )
                .expect("lookup should succeed")
                .len(),
            1
        );
        assert_eq!(
            store
                .list_for_subject(
                    &WorkspaceId::new("workspace_two"),
                    &PrincipalId::new("principal_02"),
                )
                .expect("lookup should succeed")
                .len(),
            1
        );
    }

    #[test]
    fn rejects_duplicate_memory_within_workspace() {
        let mut store = InMemoryStore::new();
        let memory = preference(
            "memory_01",
            "workspace_one",
            "principal_01",
            "Call me Hippo",
        );

        insert(&mut store, memory.clone(), "event_01")
            .expect("first insert should succeed");
        let error = insert(&mut store, memory, "event_02")
            .expect_err("duplicate insert should fail");

        assert_eq!(error, ApplicationError::AlreadyExists);
    }

    #[test]
    fn rejects_stale_revision() {
        let mut store = InMemoryStore::new();
        let original = preference(
            "memory_01",
            "workspace_one",
            "principal_01",
            "Call me Hippo",
        );
        insert(&mut store, original.clone(), "event_01")
            .expect("initial insert should succeed");

        let revised = original
            .revise(
                "Call me Captain Hippo",
                rembrane_domain::EvidenceReference::new(
                    rembrane_domain::EvidenceId::new("evidence_revision"),
                    rembrane_domain::EvidenceSource::UserStatement,
                ),
            )
            .expect("revision should be valid");

        let revision_event = CanonicalEvent::new(
            EventId::new("event_02"),
            WorkspaceId::new("workspace_one"),
            PrincipalId::new("principal_01"),
            Some(PrincipalId::new("principal_01")),
            2,
            EventPayload::MemoryRevised {
                memory_id: MemoryId::new("memory_01"),
                version: 2,
            },
        )
        .expect("test event should be valid");
        let error = store
            .replace_memory_with_event(
                revised,
                2,
                revision_event,
                Vec::new(),
                1,
            )
            .expect_err("stale expected version should fail");

        assert_eq!(error, ApplicationError::VersionConflict);
    }

    fn event(
        id: &str,
        workspace_id: &str,
        sequence: u64,
    ) -> CanonicalEvent {
        CanonicalEvent::new(
            EventId::new(id),
            WorkspaceId::new(workspace_id),
            PrincipalId::new("principal_01"),
            None,
            sequence,
            EventPayload::MemoryCreated {
                memory_id: MemoryId::new("memory_01"),
                version: 1,
            },
        )
        .expect("test event should be valid")
    }

    #[test]
    fn enforces_workspace_event_sequence() {
        let mut store = InMemoryStore::new();
        store
            .append_event(event("event_01", "workspace_01", 1), 0)
            .expect("first event should append");

        let error = store
            .append_event(event("event_03", "workspace_01", 3), 1)
            .expect_err("sequence gap should fail");

        assert_eq!(error, ApplicationError::SequenceConflict);
    }

    #[test]
    fn keeps_event_sequences_independent_between_workspaces() {
        let mut store = InMemoryStore::new();
        store
            .append_event(event("event_one", "workspace_one", 1), 0)
            .expect("first workspace event should append");
        store
            .append_event(event("event_two", "workspace_two", 1), 0)
            .expect("second workspace event should append");

        assert_eq!(
            store
                .list_events_since(&WorkspaceId::new("workspace_one"), 0)
                .expect("event listing should succeed")
                .len(),
            1
        );
    }
}

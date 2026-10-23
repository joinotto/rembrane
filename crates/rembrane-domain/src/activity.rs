use std::error::Error;
use std::fmt::{self, Display};

use crate::{
    ActivityId, CheckpointId, EntityId, PrincipalId, WorkspaceId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointError {
    EmptyGoal,
    EmptySummary,
    EmptyStateFingerprint,
    InvalidVersion,
    VersionOverflow,
}

impl Display for CheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyGoal => formatter.write_str("activity goal must not be empty"),
            Self::EmptySummary => {
                formatter.write_str("activity summary must not be empty")
            }
            Self::EmptyStateFingerprint => {
                formatter.write_str("state fingerprint must not be empty")
            }
            Self::InvalidVersion => {
                formatter.write_str("checkpoint version must be greater than zero")
            }
            Self::VersionOverflow => {
                formatter.write_str("checkpoint version cannot be incremented")
            }
        }
    }
}

impl Error for CheckpointError {}

/// The resumable state of an activity at a meaningful boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivityCheckpoint {
    id: CheckpointId,
    workspace_id: WorkspaceId,
    subject_id: PrincipalId,
    activity_id: ActivityId,
    entity_id: Option<EntityId>,
    goal: String,
    summary: String,
    next_steps: Vec<String>,
    blockers: Vec<String>,
    state_fingerprint: Option<String>,
    version: u64,
}

impl ActivityCheckpoint {
    pub fn restore(
        id: CheckpointId,
        workspace_id: WorkspaceId,
        subject_id: PrincipalId,
        activity_id: ActivityId,
        entity_id: Option<EntityId>,
        goal: impl Into<String>,
        summary: impl Into<String>,
        next_steps: Vec<String>,
        blockers: Vec<String>,
        state_fingerprint: Option<String>,
        version: u64,
    ) -> Result<Self, CheckpointError> {
        let goal = goal.into();
        if goal.trim().is_empty() {
            return Err(CheckpointError::EmptyGoal);
        }

        let summary = summary.into();
        if summary.trim().is_empty() {
            return Err(CheckpointError::EmptySummary);
        }
        if version == 0 {
            return Err(CheckpointError::InvalidVersion);
        }
        validate_state_fingerprint(state_fingerprint.as_deref())?;

        Ok(Self {
            id,
            workspace_id,
            subject_id,
            activity_id,
            entity_id,
            goal,
            summary,
            next_steps,
            blockers,
            state_fingerprint,
            version,
        })
    }

    pub fn new(
        id: CheckpointId,
        workspace_id: WorkspaceId,
        subject_id: PrincipalId,
        activity_id: ActivityId,
        entity_id: Option<EntityId>,
        goal: impl Into<String>,
        summary: impl Into<String>,
        next_steps: Vec<String>,
        blockers: Vec<String>,
    ) -> Result<Self, CheckpointError> {
        let goal = goal.into();
        if goal.trim().is_empty() {
            return Err(CheckpointError::EmptyGoal);
        }

        let summary = summary.into();
        if summary.trim().is_empty() {
            return Err(CheckpointError::EmptySummary);
        }

        Ok(Self {
            id,
            workspace_id,
            subject_id,
            activity_id,
            entity_id,
            goal,
            summary,
            next_steps,
            blockers,
            state_fingerprint: None,
            version: 1,
        })
    }

    pub fn with_state_fingerprint(
        mut self,
        state_fingerprint: impl Into<String>,
    ) -> Result<Self, CheckpointError> {
        let state_fingerprint = state_fingerprint.into();
        validate_state_fingerprint(Some(&state_fingerprint))?;
        self.state_fingerprint = Some(state_fingerprint);
        Ok(self)
    }

    pub fn update(
        mut self,
        summary: impl Into<String>,
        next_steps: Vec<String>,
        blockers: Vec<String>,
    ) -> Result<Self, CheckpointError> {
        let summary = summary.into();
        if summary.trim().is_empty() {
            return Err(CheckpointError::EmptySummary);
        }

        self.version = self
            .version
            .checked_add(1)
            .ok_or(CheckpointError::VersionOverflow)?;
        self.summary = summary;
        self.next_steps = next_steps;
        self.blockers = blockers;
        Ok(self)
    }

    #[must_use]
    pub const fn id(&self) -> &CheckpointId {
        &self.id
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    #[must_use]
    pub const fn subject_id(&self) -> &PrincipalId {
        &self.subject_id
    }

    #[must_use]
    pub const fn activity_id(&self) -> &ActivityId {
        &self.activity_id
    }

    #[must_use]
    pub const fn entity_id(&self) -> Option<&EntityId> {
        self.entity_id.as_ref()
    }

    #[must_use]
    pub fn goal(&self) -> &str {
        &self.goal
    }

    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    #[must_use]
    pub fn next_steps(&self) -> &[String] {
        &self.next_steps
    }

    #[must_use]
    pub fn blockers(&self) -> &[String] {
        &self.blockers
    }

    #[must_use]
    pub fn state_fingerprint(&self) -> Option<&str> {
        self.state_fingerprint.as_deref()
    }

    #[must_use]
    pub fn is_stale_against(&self, current_state_fingerprint: &str) -> bool {
        self.state_fingerprint
            .as_deref()
            .is_some_and(|recorded| recorded != current_state_fingerprint)
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }
}

fn validate_state_fingerprint(
    state_fingerprint: Option<&str>,
) -> Result<(), CheckpointError> {
    if state_fingerprint.is_some_and(|value| value.trim().is_empty()) {
        Err(CheckpointError::EmptyStateFingerprint)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ActivityCheckpoint;
    use crate::{
        ActivityId, CheckpointId, EntityId, PrincipalId, WorkspaceId,
    };

    fn checkpoint() -> ActivityCheckpoint {
        ActivityCheckpoint::new(
            CheckpointId::new("checkpoint_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            ActivityId::new("activity_01"),
            Some(EntityId::new("project_01")),
            "Implement authentication",
            "The callback is implemented and unit tested.",
            vec!["Run integration tests".to_owned()],
            Vec::new(),
        )
        .expect("test checkpoint should be valid")
    }

    #[test]
    fn updates_resumable_state_with_new_version() {
        let updated = checkpoint()
            .update(
                "Integration tests expose a token refresh race.",
                vec!["Fix refresh locking".to_owned()],
                vec!["Need a reproducible concurrency test".to_owned()],
            )
            .expect("checkpoint update should succeed");

        assert_eq!(updated.version(), 2);
        assert_eq!(updated.next_steps()[0], "Fix refresh locking");
    }

    #[test]
    fn detects_external_state_changes() {
        let checkpoint = checkpoint()
            .with_state_fingerprint("git:abc123")
            .expect("fingerprint should be valid");

        assert!(!checkpoint.is_stale_against("git:abc123"));
        assert!(checkpoint.is_stale_against("git:def456"));
    }
}

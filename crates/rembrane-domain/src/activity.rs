use std::error::Error;
use std::fmt::{self, Display};

use crate::{ActivityId, CheckpointId, EntityId, PrincipalId, WorkspaceId};

pub const MAX_CHECKPOINT_PAYLOAD_BYTES: usize = 262_144;
pub const MAX_CHECKPOINT_LIST_ITEMS: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointError {
    EmptyGoal,
    EmptySummary,
    InvalidListItem,
    EmptyStateFingerprint,
    PayloadTooLarge,
    InvalidVersion,
    VersionOverflow,
}

impl Display for CheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyGoal => formatter.write_str("activity goal must not be empty"),
            Self::EmptySummary => formatter.write_str("activity summary must not be empty"),
            Self::InvalidListItem => {
                formatter.write_str(
                    "checkpoint list items must not be empty or contain null characters",
                )
            }
            Self::EmptyStateFingerprint => {
                formatter.write_str("state fingerprint must not be empty")
            }
            Self::PayloadTooLarge => {
                formatter.write_str("checkpoint exceeds the canonical byte limit")
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
#[derive(Clone, Eq, PartialEq)]
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

impl fmt::Debug for ActivityCheckpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivityCheckpoint")
            .field("id", &"<redacted>")
            .field("workspace_id", &"<redacted>")
            .field("subject_id", &"<redacted>")
            .field("activity_id", &"<redacted>")
            .field("entity_id_present", &self.entity_id.is_some())
            .field("goal_bytes", &self.goal.len())
            .field("summary_bytes", &self.summary.len())
            .field("next_step_count", &self.next_steps.len())
            .field("blocker_count", &self.blockers.len())
            .field(
                "state_fingerprint_present",
                &self.state_fingerprint.is_some(),
            )
            .field("version", &self.version)
            .finish()
    }
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
        validate_payload_size(
            &goal,
            &summary,
            &next_steps,
            &blockers,
            state_fingerprint.as_deref(),
        )?;

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
        validate_payload_size(&goal, &summary, &next_steps, &blockers, None)?;

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
        validate_payload_size(
            &self.goal,
            &self.summary,
            &self.next_steps,
            &self.blockers,
            Some(&state_fingerprint),
        )?;
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
        validate_payload_size(
            &self.goal,
            &summary,
            &next_steps,
            &blockers,
            self.state_fingerprint.as_deref(),
        )?;

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

fn validate_state_fingerprint(state_fingerprint: Option<&str>) -> Result<(), CheckpointError> {
    if state_fingerprint.is_some_and(|value| value.trim().is_empty()) {
        Err(CheckpointError::EmptyStateFingerprint)
    } else {
        Ok(())
    }
}

fn validate_payload_size(
    goal: &str,
    summary: &str,
    next_steps: &[String],
    blockers: &[String],
    state_fingerprint: Option<&str>,
) -> Result<(), CheckpointError> {
    if next_steps
        .iter()
        .chain(blockers)
        .any(|item| item.trim().is_empty() || item.contains('\0'))
    {
        return Err(CheckpointError::InvalidListItem);
    }
    let list_items = next_steps
        .len()
        .checked_add(blockers.len())
        .ok_or(CheckpointError::PayloadTooLarge)?;
    if list_items > MAX_CHECKPOINT_LIST_ITEMS {
        return Err(CheckpointError::PayloadTooLarge);
    }
    let mut fields = next_steps
        .iter()
        .chain(blockers)
        .map(String::len)
        .chain([goal.len(), summary.len()])
        .chain(state_fingerprint.map(str::len));
    let total = fields
        .try_fold(0_usize, usize::checked_add)
        .ok_or(CheckpointError::PayloadTooLarge)?;
    if total > MAX_CHECKPOINT_PAYLOAD_BYTES {
        Err(CheckpointError::PayloadTooLarge)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ActivityCheckpoint;
    use crate::{ActivityId, CheckpointId, EntityId, PrincipalId, WorkspaceId};

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

    #[test]
    fn rejects_checkpoint_payload_over_the_canonical_limit() {
        let error = ActivityCheckpoint::new(
            CheckpointId::new("checkpoint_large"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            ActivityId::new("activity_01"),
            None,
            "Goal",
            "x".repeat(super::MAX_CHECKPOINT_PAYLOAD_BYTES),
            vec!["overflow".to_owned()],
            Vec::new(),
        )
        .expect_err("oversized checkpoint should fail");

        assert_eq!(error, super::CheckpointError::PayloadTooLarge);
    }

    #[test]
    fn rejects_unbounded_checkpoint_collections_with_small_items() {
        let error = ActivityCheckpoint::new(
            CheckpointId::new("checkpoint_many_items"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            ActivityId::new("activity_01"),
            None,
            "Goal",
            "Summary",
            vec!["x".to_owned(); super::MAX_CHECKPOINT_LIST_ITEMS + 1],
            Vec::new(),
        )
        .expect_err("unbounded checkpoint collection should fail");

        assert_eq!(error, super::CheckpointError::PayloadTooLarge);
    }

    #[test]
    fn rejects_empty_or_whitespace_checkpoint_list_items() {
        let error = ActivityCheckpoint::new(
            CheckpointId::new("checkpoint_empty_item"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            ActivityId::new("activity_01"),
            None,
            "Goal",
            "Summary",
            vec!["  ".to_owned()],
            Vec::new(),
        )
        .expect_err("empty checkpoint list item should fail");

        assert_eq!(error, super::CheckpointError::InvalidListItem);

        let null_error = checkpoint()
            .update(
                "Summary",
                Vec::new(),
                vec!["blocked\0secret".to_owned()],
            )
            .expect_err("null checkpoint list item should fail");
        assert_eq!(null_error, super::CheckpointError::InvalidListItem);
    }

    #[test]
    fn debug_output_redacts_working_memory_and_identities() {
        let checkpoint = ActivityCheckpoint::new(
            CheckpointId::new("private_checkpoint"),
            WorkspaceId::new("private_workspace"),
            PrincipalId::new("private_subject"),
            ActivityId::new("private_activity"),
            Some(EntityId::new("private_project")),
            "Private implementation goal",
            "Private working-state summary",
            vec!["Private next step".to_owned()],
            vec!["Private blocker".to_owned()],
        )
        .expect("test checkpoint should be valid")
        .with_state_fingerprint("private_state_fingerprint")
        .expect("fingerprint should be valid");

        let diagnostic = format!("{checkpoint:?}");

        for private_value in [
            "private_checkpoint",
            "private_workspace",
            "private_subject",
            "private_activity",
            "private_project",
            "Private implementation goal",
            "Private working-state summary",
            "Private next step",
            "Private blocker",
            "private_state_fingerprint",
        ] {
            assert!(!diagnostic.contains(private_value));
        }
        assert!(diagnostic.contains("goal_bytes: 27"));
        assert!(diagnostic.contains("summary_bytes: 29"));
        assert!(diagnostic.contains("next_step_count: 1"));
        assert!(diagnostic.contains("blocker_count: 1"));
        assert!(diagnostic.contains("state_fingerprint_present: true"));
        assert!(diagnostic.contains("version: 1"));
    }
}

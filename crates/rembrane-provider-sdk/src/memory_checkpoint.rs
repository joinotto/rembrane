use rembrane_domain::{ActivityId, CheckpointId, EntityId, MAX_CHECKPOINT_PAYLOAD_BYTES};

use crate::{MemoryProviderIdempotencyKey, ProviderError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointActivityPayload {
    idempotency_key: MemoryProviderIdempotencyKey,
    activity_id: ActivityId,
    entity_id: Option<EntityId>,
    expected_version: Option<u64>,
    goal: Option<String>,
    summary: String,
    next_steps: Vec<String>,
    blockers: Vec<String>,
    state_fingerprint: Option<String>,
}

impl CheckpointActivityPayload {
    /// Creates a first persisted checkpoint for an activity.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for unsafe identifiers, empty
    /// required text, empty list entries, an empty fingerprint, or a payload
    /// exceeding the canonical checkpoint byte limit.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        idempotency_key: MemoryProviderIdempotencyKey,
        activity_id: ActivityId,
        entity_id: Option<EntityId>,
        goal: impl Into<String>,
        summary: impl Into<String>,
        next_steps: Vec<String>,
        blockers: Vec<String>,
        state_fingerprint: Option<String>,
    ) -> Result<Self, ProviderError> {
        let goal = goal.into();
        let summary = summary.into();
        validate_checkpoint_fields(
            &activity_id,
            entity_id.as_ref(),
            Some(&goal),
            &summary,
            &next_steps,
            &blockers,
            state_fingerprint.as_deref(),
        )?;
        Ok(Self {
            idempotency_key,
            activity_id,
            entity_id,
            expected_version: None,
            goal: Some(goal),
            summary,
            next_steps,
            blockers,
            state_fingerprint,
        })
    }

    /// Creates an optimistic update to an existing checkpoint.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for a zero expected version,
    /// unsafe identifiers, invalid text, or an oversized payload.
    #[allow(clippy::too_many_arguments)]
    pub fn update(
        idempotency_key: MemoryProviderIdempotencyKey,
        activity_id: ActivityId,
        entity_id: Option<EntityId>,
        expected_version: u64,
        summary: impl Into<String>,
        next_steps: Vec<String>,
        blockers: Vec<String>,
        state_fingerprint: Option<String>,
    ) -> Result<Self, ProviderError> {
        if expected_version == 0 {
            return Err(ProviderError::InvalidConfiguration(
                "checkpoint expected version must be greater than zero".to_owned(),
            ));
        }
        let summary = summary.into();
        validate_checkpoint_fields(
            &activity_id,
            entity_id.as_ref(),
            None,
            &summary,
            &next_steps,
            &blockers,
            state_fingerprint.as_deref(),
        )?;
        Ok(Self {
            idempotency_key,
            activity_id,
            entity_id,
            expected_version: Some(expected_version),
            goal: None,
            summary,
            next_steps,
            blockers,
            state_fingerprint,
        })
    }

    #[must_use]
    pub const fn idempotency_key(&self) -> &MemoryProviderIdempotencyKey {
        &self.idempotency_key
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
    pub const fn expected_version(&self) -> Option<u64> {
        self.expected_version
    }

    #[must_use]
    pub fn goal(&self) -> Option<&str> {
        self.goal.as_deref()
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointActivityResult {
    checkpoint_id: CheckpointId,
    version: u64,
}

impl CheckpointActivityResult {
    /// Creates the canonical checkpoint identity returned after persistence.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for an unsafe ID or zero
    /// version.
    pub fn new(checkpoint_id: CheckpointId, version: u64) -> Result<Self, ProviderError> {
        validate_identifier("checkpoint id", checkpoint_id.as_str())?;
        if version == 0 {
            return Err(ProviderError::InvalidConfiguration(
                "checkpoint result version must be greater than zero".to_owned(),
            ));
        }
        Ok(Self {
            checkpoint_id,
            version,
        })
    }

    #[must_use]
    pub const fn checkpoint_id(&self) -> &CheckpointId {
        &self.checkpoint_id
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }
}

fn validate_checkpoint_fields(
    activity_id: &ActivityId,
    entity_id: Option<&EntityId>,
    goal: Option<&str>,
    summary: &str,
    next_steps: &[String],
    blockers: &[String],
    state_fingerprint: Option<&str>,
) -> Result<(), ProviderError> {
    validate_identifier("checkpoint activity id", activity_id.as_str())?;
    if let Some(entity_id) = entity_id {
        validate_identifier("checkpoint entity id", entity_id.as_str())?;
    }
    if goal.is_some_and(|value| value.trim().is_empty() || value.contains('\0'))
        || summary.trim().is_empty()
        || summary.contains('\0')
        || next_steps
            .iter()
            .chain(blockers)
            .any(|value| value.trim().is_empty() || value.contains('\0'))
        || state_fingerprint.is_some_and(|value| value.trim().is_empty() || value.contains('\0'))
    {
        return Err(ProviderError::InvalidConfiguration(
            "checkpoint text fields must be non-empty and contain no null characters".to_owned(),
        ));
    }

    let payload_bytes = goal.map_or(0, str::len)
        + summary.len()
        + next_steps.iter().map(String::len).sum::<usize>()
        + blockers.iter().map(String::len).sum::<usize>()
        + state_fingerprint.map_or(0, str::len);
    if payload_bytes > MAX_CHECKPOINT_PAYLOAD_BYTES {
        return Err(ProviderError::InvalidConfiguration(
            "checkpoint exceeds the canonical payload byte limit".to_owned(),
        ));
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > 255
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ProviderError::InvalidConfiguration(format!(
            "{label} must contain 1 to 255 safe ASCII characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rembrane_domain::{ActivityId, CheckpointId, EntityId, MAX_CHECKPOINT_PAYLOAD_BYTES};

    use super::{CheckpointActivityPayload, CheckpointActivityResult};
    use crate::MemoryProviderIdempotencyKey;

    fn key() -> MemoryProviderIdempotencyKey {
        MemoryProviderIdempotencyKey::new("checkpoint_0123456789abcdef")
            .expect("idempotency key should be valid")
    }

    #[test]
    fn separates_create_and_optimistic_update_checkpoint_shapes() {
        let create = CheckpointActivityPayload::create(
            key(),
            ActivityId::new("activity_01"),
            Some(EntityId::new("project_01")),
            "Ship the remote MCP adapter",
            "Authorization boundaries are complete.",
            vec!["Integrate the SDK transport.".to_owned()],
            vec!["Crates.io is unavailable.".to_owned()],
            Some("git:abc123".to_owned()),
        )
        .expect("create payload should be valid");
        assert_eq!(create.expected_version(), None);
        assert_eq!(create.goal(), Some("Ship the remote MCP adapter"));

        let update = CheckpointActivityPayload::update(
            key(),
            ActivityId::new("activity_01"),
            Some(EntityId::new("project_01")),
            3,
            "Transport integration is in progress.",
            vec!["Run dependency-enabled tests.".to_owned()],
            Vec::new(),
            Some("git:def456".to_owned()),
        )
        .expect("update payload should be valid");
        assert_eq!(update.expected_version(), Some(3));
        assert_eq!(update.goal(), None);

        let result = CheckpointActivityResult::new(CheckpointId::new("checkpoint_01"), 4)
            .expect("result should be valid");
        assert_eq!(result.version(), 4);
    }

    #[test]
    fn rejects_invalid_ids_versions_text_and_oversized_state() {
        assert!(
            CheckpointActivityPayload::create(
                key(),
                ActivityId::new(""),
                None,
                "goal",
                "summary",
                Vec::new(),
                Vec::new(),
                None,
            )
            .is_err()
        );
        assert!(
            CheckpointActivityPayload::update(
                key(),
                ActivityId::new("activity_01"),
                None,
                0,
                "summary",
                Vec::new(),
                Vec::new(),
                None,
            )
            .is_err()
        );
        assert!(
            CheckpointActivityPayload::create(
                key(),
                ActivityId::new("activity_01"),
                None,
                "goal",
                "summary",
                vec![" ".to_owned()],
                Vec::new(),
                None,
            )
            .is_err()
        );
        assert!(
            CheckpointActivityPayload::create(
                key(),
                ActivityId::new("activity_01"),
                None,
                "goal",
                "x".repeat(MAX_CHECKPOINT_PAYLOAD_BYTES),
                vec!["overflow".to_owned()],
                Vec::new(),
                None,
            )
            .is_err()
        );
        assert!(CheckpointActivityResult::new(CheckpointId::new(""), 1).is_err());
        assert!(CheckpointActivityResult::new(CheckpointId::new("checkpoint_01"), 0).is_err());
    }
}

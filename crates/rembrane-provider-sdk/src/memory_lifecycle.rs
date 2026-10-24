use rembrane_domain::{EvidenceReference, MemoryId};

use crate::{MemoryProviderIdempotencyKey, ProviderError};

pub const MAX_DELETE_REASON_BYTES: usize = 4_096;
pub const MAX_EXPLAIN_PURPOSE_BYTES: usize = 4_096;
pub const MAX_EXPLANATION_BYTES: usize = 32_768;
pub const MAX_EXPLANATION_EVIDENCE: usize = 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteMemoryPayload {
    idempotency_key: MemoryProviderIdempotencyKey,
    memory_id: MemoryId,
    expected_version: u64,
    reason: String,
}

impl DeleteMemoryPayload {
    /// Creates an optimistic, idempotent request to tombstone one memory.
    ///
    /// Workspace, subject, actor, and client identity are deliberately absent.
    /// The server must derive them from authenticated connection context and
    /// re-authorize the exact memory before applying the mutation.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for an unsafe memory ID, zero
    /// expected version, or an empty, oversized, or null-containing reason.
    pub fn new(
        idempotency_key: MemoryProviderIdempotencyKey,
        memory_id: MemoryId,
        expected_version: u64,
        reason: impl Into<String>,
    ) -> Result<Self, ProviderError> {
        validate_identifier("deleted memory id", memory_id.as_str())?;
        if expected_version == 0 {
            return Err(ProviderError::InvalidConfiguration(
                "deleted memory expected version must be greater than zero".to_owned(),
            ));
        }
        let reason = reason.into();
        validate_text("memory deletion reason", &reason, MAX_DELETE_REASON_BYTES)?;
        Ok(Self {
            idempotency_key,
            memory_id,
            expected_version,
            reason,
        })
    }

    #[must_use]
    pub const fn idempotency_key(&self) -> &MemoryProviderIdempotencyKey {
        &self.idempotency_key
    }

    #[must_use]
    pub const fn memory_id(&self) -> &MemoryId {
        &self.memory_id
    }

    #[must_use]
    pub const fn expected_version(&self) -> u64 {
        self.expected_version
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeleteMemoryResult {
    memory_id: MemoryId,
    deleted_version: u64,
    tombstone_version: u64,
}

impl DeleteMemoryResult {
    /// Identifies the exact revision deleted and its canonical tombstone.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error unless the tombstone is exactly
    /// the revision following the deleted revision.
    pub fn new(
        memory_id: MemoryId,
        deleted_version: u64,
        tombstone_version: u64,
    ) -> Result<Self, ProviderError> {
        validate_identifier("deleted memory result id", memory_id.as_str())?;
        if deleted_version == 0
            || deleted_version
                .checked_add(1)
                .is_none_or(|next| next != tombstone_version)
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory deletion result must contain consecutive positive revisions".to_owned(),
            ));
        }
        Ok(Self {
            memory_id,
            deleted_version,
            tombstone_version,
        })
    }

    #[must_use]
    pub const fn memory_id(&self) -> &MemoryId {
        &self.memory_id
    }

    #[must_use]
    pub const fn deleted_version(&self) -> u64 {
        self.deleted_version
    }

    #[must_use]
    pub const fn tombstone_version(&self) -> u64 {
        self.tombstone_version
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplainMemoryPayload {
    memory_id: MemoryId,
    version: u64,
    purpose: String,
}

impl ExplainMemoryPayload {
    /// Requests bounded provenance for one exact canonical memory revision.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for an unsafe memory ID, zero
    /// version, or invalid purpose.
    pub fn new(
        memory_id: MemoryId,
        version: u64,
        purpose: impl Into<String>,
    ) -> Result<Self, ProviderError> {
        validate_identifier("explained memory id", memory_id.as_str())?;
        if version == 0 {
            return Err(ProviderError::InvalidConfiguration(
                "explained memory version must be greater than zero".to_owned(),
            ));
        }
        let purpose = purpose.into();
        validate_text(
            "memory explanation purpose",
            &purpose,
            MAX_EXPLAIN_PURPOSE_BYTES,
        )?;
        Ok(Self {
            memory_id,
            version,
            purpose,
        })
    }

    #[must_use]
    pub const fn memory_id(&self) -> &MemoryId {
        &self.memory_id
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplainMemoryResult {
    memory_id: MemoryId,
    version: u64,
    explanation: String,
    evidence: Vec<EvidenceReference>,
}

impl ExplainMemoryResult {
    /// Creates a bounded explanation tied to immutable evidence references.
    ///
    /// The portable result excludes raw source material and provider-internal
    /// reasoning. Authorized clients can use the evidence IDs to request
    /// richer source details through a separate, policy-controlled surface.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for an unsafe memory/evidence
    /// ID, zero version, invalid explanation, missing evidence, duplicates, or
    /// excessive evidence count.
    pub fn new(
        memory_id: MemoryId,
        version: u64,
        explanation: impl Into<String>,
        evidence: Vec<EvidenceReference>,
    ) -> Result<Self, ProviderError> {
        validate_identifier("explanation memory id", memory_id.as_str())?;
        if version == 0 {
            return Err(ProviderError::InvalidConfiguration(
                "explanation memory version must be greater than zero".to_owned(),
            ));
        }
        let explanation = explanation.into();
        validate_text("memory explanation", &explanation, MAX_EXPLANATION_BYTES)?;
        if evidence.is_empty() || evidence.len() > MAX_EXPLANATION_EVIDENCE {
            return Err(ProviderError::InvalidConfiguration(
                "memory explanation evidence must be non-empty and within the item limit"
                    .to_owned(),
            ));
        }
        if evidence.iter().enumerate().any(|(index, reference)| {
            validate_identifier("explanation evidence id", reference.id.as_str()).is_err()
                || evidence[..index]
                    .iter()
                    .any(|previous| previous.id == reference.id)
        }) {
            return Err(ProviderError::InvalidConfiguration(
                "memory explanation evidence IDs must be safe and unique".to_owned(),
            ));
        }
        Ok(Self {
            memory_id,
            version,
            explanation,
            evidence,
        })
    }

    #[must_use]
    pub const fn memory_id(&self) -> &MemoryId {
        &self.memory_id
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub fn explanation(&self) -> &str {
        &self.explanation
    }

    #[must_use]
    pub fn evidence(&self) -> &[EvidenceReference] {
        &self.evidence
    }
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

fn validate_text(label: &str, value: &str, maximum_bytes: usize) -> Result<(), ProviderError> {
    if value.trim().is_empty() || value.len() > maximum_bytes || value.contains('\0') {
        return Err(ProviderError::InvalidConfiguration(format!(
            "{label} must be non-empty, bounded, and contain no null characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rembrane_domain::{EvidenceId, EvidenceReference, EvidenceSource, MemoryId};

    use super::{
        DeleteMemoryPayload, DeleteMemoryResult, ExplainMemoryPayload, ExplainMemoryResult,
        MAX_EXPLANATION_EVIDENCE,
    };
    use crate::MemoryProviderIdempotencyKey;

    fn key() -> MemoryProviderIdempotencyKey {
        MemoryProviderIdempotencyKey::new("delete_0123456789abcdef")
            .expect("idempotency key should be valid")
    }

    fn evidence(id: impl Into<String>) -> EvidenceReference {
        EvidenceReference::new(EvidenceId::new(id), EvidenceSource::UserStatement)
    }

    #[test]
    fn deletes_one_exact_revision_into_the_next_tombstone() {
        let payload = DeleteMemoryPayload::new(
            key(),
            MemoryId::new("memory_01"),
            3,
            "user requested erasure",
        )
        .expect("delete payload should be valid");
        assert_eq!(payload.memory_id().as_str(), "memory_01");
        assert_eq!(payload.expected_version(), 3);

        let result = DeleteMemoryResult::new(MemoryId::new("memory_01"), 3, 4)
            .expect("delete result should be valid");
        assert_eq!(result.deleted_version(), 3);
        assert_eq!(result.tombstone_version(), 4);
    }

    #[test]
    fn rejects_unsafe_or_non_consecutive_deletion_revisions() {
        assert!(DeleteMemoryPayload::new(key(), MemoryId::new(""), 1, "reason").is_err());
        assert!(DeleteMemoryPayload::new(key(), MemoryId::new("memory_01"), 0, "reason").is_err());
        assert!(DeleteMemoryPayload::new(key(), MemoryId::new("memory_01"), 1, " ").is_err());
        assert!(DeleteMemoryResult::new(MemoryId::new("memory_01"), 1, 3).is_err());
        assert!(DeleteMemoryResult::new(MemoryId::new("memory_01"), u64::MAX, 0).is_err());
    }

    #[test]
    fn explains_one_exact_revision_with_bounded_provenance() {
        let payload = ExplainMemoryPayload::new(
            MemoryId::new("memory_01"),
            2,
            "show why this preference is active",
        )
        .expect("explain payload should be valid");
        assert_eq!(payload.version(), 2);

        let result = ExplainMemoryResult::new(
            MemoryId::new("memory_01"),
            2,
            "The user stated this preference directly.",
            vec![evidence("evidence_01")],
        )
        .expect("explanation result should be valid");
        assert_eq!(result.memory_id().as_str(), "memory_01");
        assert_eq!(result.evidence().len(), 1);
    }

    #[test]
    fn rejects_invalid_explanation_identity_text_and_evidence() {
        assert!(ExplainMemoryPayload::new(MemoryId::new(""), 1, "purpose").is_err());
        assert!(ExplainMemoryPayload::new(MemoryId::new("memory_01"), 0, "purpose").is_err());
        assert!(
            ExplainMemoryResult::new(MemoryId::new("memory_01"), 1, "explanation", Vec::new())
                .is_err()
        );
        assert!(
            ExplainMemoryResult::new(
                MemoryId::new("memory_01"),
                1,
                "explanation",
                vec![evidence("evidence_01"), evidence("evidence_01")],
            )
            .is_err()
        );
        assert!(
            ExplainMemoryResult::new(
                MemoryId::new("memory_01"),
                1,
                "explanation",
                (0..=MAX_EXPLANATION_EVIDENCE)
                    .map(|index| evidence(format!("evidence_{index}")))
                    .collect(),
            )
            .is_err()
        );
    }
}

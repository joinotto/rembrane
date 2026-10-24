use rembrane_domain::{EvidenceSource, MAX_MEMORY_CONTENT_BYTES, MemoryId, MemoryKind};

use crate::{MemoryProviderContextSelector, MemoryProviderIdempotencyKey, ProviderError};

pub const MAX_SOURCE_REFERENCE_BYTES: usize = 2_048;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposeMemoryPayload {
    idempotency_key: MemoryProviderIdempotencyKey,
    selector: MemoryProviderContextSelector,
    kind: MemoryKind,
    content: String,
    evidence_source: EvidenceSource,
    source_reference: Option<String>,
    observed_at_epoch_seconds: u64,
}

impl ProposeMemoryPayload {
    /// Creates an evidence-bearing proposed-memory request.
    ///
    /// Proposal payloads never express confirmed status. Confirmation remains
    /// a canonical server-side policy and user-consent transition.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for empty or oversized content,
    /// unsafe source references, zero observation time, or observation times
    /// later than the server-provided current time.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        idempotency_key: MemoryProviderIdempotencyKey,
        selector: MemoryProviderContextSelector,
        kind: MemoryKind,
        content: impl Into<String>,
        evidence_source: EvidenceSource,
        source_reference: Option<String>,
        observed_at_epoch_seconds: u64,
        now_epoch_seconds: u64,
    ) -> Result<Self, ProviderError> {
        let content = content.into();
        if content.trim().is_empty()
            || content.len() > MAX_MEMORY_CONTENT_BYTES
            || content.contains('\0')
        {
            return Err(ProviderError::InvalidConfiguration(
                "proposed memory content must be non-empty, within the canonical byte limit, and contain no null characters".to_owned(),
            ));
        }
        if source_reference.as_ref().is_some_and(|reference| {
            reference.is_empty()
                || reference.len() > MAX_SOURCE_REFERENCE_BYTES
                || reference.contains('\0')
                || reference.chars().any(char::is_control)
        }) {
            return Err(ProviderError::InvalidConfiguration(
                "proposal source reference is empty, oversized, or contains control characters"
                    .to_owned(),
            ));
        }
        if observed_at_epoch_seconds == 0 || observed_at_epoch_seconds > now_epoch_seconds {
            return Err(ProviderError::InvalidConfiguration(
                "proposal observation time must be positive and not in the future".to_owned(),
            ));
        }
        Ok(Self {
            idempotency_key,
            selector,
            kind,
            content,
            evidence_source,
            source_reference,
            observed_at_epoch_seconds,
        })
    }

    #[must_use]
    pub const fn idempotency_key(&self) -> &MemoryProviderIdempotencyKey {
        &self.idempotency_key
    }

    #[must_use]
    pub const fn selector(&self) -> &MemoryProviderContextSelector {
        &self.selector
    }

    #[must_use]
    pub const fn kind(&self) -> MemoryKind {
        self.kind
    }

    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    #[must_use]
    pub const fn evidence_source(&self) -> EvidenceSource {
        self.evidence_source
    }

    #[must_use]
    pub fn source_reference(&self) -> Option<&str> {
        self.source_reference.as_deref()
    }

    #[must_use]
    pub const fn observed_at_epoch_seconds(&self) -> u64 {
        self.observed_at_epoch_seconds
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposeMemoryResult {
    memory_id: MemoryId,
    version: u64,
}

impl ProposeMemoryResult {
    /// Creates the canonical identity returned for a persisted proposal.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for an empty, oversized, unsafe
    /// memory identifier or a zero version.
    pub fn new(memory_id: MemoryId, version: u64) -> Result<Self, ProviderError> {
        if memory_id.as_str().is_empty()
            || memory_id.as_str().len() > 255
            || !memory_id.as_str().is_ascii()
            || memory_id
                .as_str()
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || version == 0
        {
            return Err(ProviderError::InvalidConfiguration(
                "proposal result requires a safe memory id and positive version".to_owned(),
            ));
        }
        Ok(Self { memory_id, version })
    }

    #[must_use]
    pub const fn memory_id(&self) -> &MemoryId {
        &self.memory_id
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }
}

#[cfg(test)]
mod tests {
    use rembrane_domain::{EvidenceSource, MemoryId, MemoryKind};

    use super::{MAX_SOURCE_REFERENCE_BYTES, ProposeMemoryPayload, ProposeMemoryResult};
    use crate::{MemoryProviderContextSelector, MemoryProviderIdempotencyKey};

    #[test]
    fn builds_idempotent_evidence_bearing_proposals_without_confirmed_status() {
        let payload = ProposeMemoryPayload::new(
            MemoryProviderIdempotencyKey::new("proposal_0123456789abcdef")
                .expect("idempotency key should be valid"),
            MemoryProviderContextSelector::domain("personal").expect("selector should be valid"),
            MemoryKind::Preference,
            "The user asked to be called Hippo.",
            EvidenceSource::UserStatement,
            Some("conversation-turn-42".to_owned()),
            1_000,
            1_001,
        )
        .expect("proposal should be valid");

        assert_eq!(payload.kind(), MemoryKind::Preference);
        assert_eq!(payload.evidence_source(), EvidenceSource::UserStatement);
        assert_eq!(payload.selector().scope().specificity(), 1);
        assert_eq!(payload.observed_at_epoch_seconds(), 1_000);

        let result = ProposeMemoryResult::new(MemoryId::new("memory_01"), 1)
            .expect("result should be valid");
        assert_eq!(result.memory_id().as_str(), "memory_01");
        assert_eq!(result.version(), 1);
    }

    #[test]
    fn rejects_invalid_content_reference_time_and_result_identity() {
        let build = |content: String, source_reference: Option<String>, observed_at| {
            ProposeMemoryPayload::new(
                MemoryProviderIdempotencyKey::new("proposal_0123456789abcdef")
                    .expect("idempotency key should be valid"),
                MemoryProviderContextSelector::global(),
                MemoryKind::Observation,
                content,
                EvidenceSource::AgentObservation,
                source_reference,
                observed_at,
                1_000,
            )
        };
        assert!(build(" ".to_owned(), None, 999).is_err());
        assert!(build("content".to_owned(), Some("\n".to_owned()), 999).is_err());
        assert!(
            build(
                "content".to_owned(),
                Some("x".repeat(MAX_SOURCE_REFERENCE_BYTES + 1)),
                999,
            )
            .is_err()
        );
        assert!(build("content".to_owned(), None, 1_001).is_err());
        assert!(ProposeMemoryResult::new(MemoryId::new(""), 1).is_err());
        assert!(ProposeMemoryResult::new(MemoryId::new("memory_01"), 0).is_err());
    }
}

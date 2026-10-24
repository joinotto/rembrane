use rembrane_domain::{ContextPackId, DisclosureId};

use crate::{
    MemoryProviderContextSelector, MemoryProviderDisclosedMemory, MemoryProviderLimits,
    ProviderError,
};

pub const MAX_QUESTION_PURPOSE_BYTES: usize = 4_096;
pub const MAX_QUESTION_BYTES: usize = 32_768;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveQuestionPayload {
    purpose: String,
    question: String,
    selector: MemoryProviderContextSelector,
    maximum_supporting_items: usize,
    maximum_answer_bytes: usize,
}

impl ResolveQuestionPayload {
    /// Creates a bounded question over an explicitly selected memory scope.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for invalid text, zero output
    /// ceilings, or ceilings exceeding provider-negotiated context limits.
    pub fn new(
        purpose: impl Into<String>,
        question: impl Into<String>,
        selector: MemoryProviderContextSelector,
        maximum_supporting_items: usize,
        maximum_answer_bytes: usize,
        provider_limits: MemoryProviderLimits,
    ) -> Result<Self, ProviderError> {
        let purpose = purpose.into();
        validate_text(
            "memory question purpose",
            &purpose,
            MAX_QUESTION_PURPOSE_BYTES,
        )?;
        let question = question.into();
        validate_text("memory question", &question, MAX_QUESTION_BYTES)?;
        if maximum_supporting_items == 0
            || maximum_supporting_items > provider_limits.maximum_context_items
            || maximum_answer_bytes == 0
            || maximum_answer_bytes > provider_limits.maximum_context_bytes
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory question output ceilings must be positive and within negotiated context limits"
                    .to_owned(),
            ));
        }
        Ok(Self {
            purpose,
            question,
            selector,
            maximum_supporting_items,
            maximum_answer_bytes,
        })
    }

    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    #[must_use]
    pub fn question(&self) -> &str {
        &self.question
    }

    #[must_use]
    pub const fn selector(&self) -> &MemoryProviderContextSelector {
        &self.selector
    }

    #[must_use]
    pub const fn maximum_supporting_items(&self) -> usize {
        self.maximum_supporting_items
    }

    #[must_use]
    pub const fn maximum_answer_bytes(&self) -> usize {
        self.maximum_answer_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveQuestionResult {
    answer: String,
    supporting_memories: Vec<MemoryProviderDisclosedMemory>,
    context_pack_id: ContextPackId,
    disclosure_id: DisclosureId,
}

impl ResolveQuestionResult {
    /// Creates an answer grounded in exact disclosed memory revisions.
    ///
    /// The result must be validated against the originating request so a
    /// provider cannot exceed caller-selected answer or evidence ceilings.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for invalid answer text, missing
    /// or duplicate support, output-limit overruns, or unsafe receipt IDs.
    pub fn new(
        answer: impl Into<String>,
        supporting_memories: Vec<MemoryProviderDisclosedMemory>,
        context_pack_id: ContextPackId,
        disclosure_id: DisclosureId,
        request: &ResolveQuestionPayload,
    ) -> Result<Self, ProviderError> {
        let answer = answer.into();
        validate_text(
            "memory question answer",
            &answer,
            request.maximum_answer_bytes,
        )?;
        if supporting_memories.is_empty()
            || supporting_memories.len() > request.maximum_supporting_items
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory question support must be non-empty and within the requested item limit"
                    .to_owned(),
            ));
        }
        if supporting_memories
            .iter()
            .enumerate()
            .any(|(index, memory)| {
                supporting_memories[..index].iter().any(|previous| {
                    previous.memory_id() == memory.memory_id()
                        && previous.version() == memory.version()
                })
            })
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory question supporting revisions must be unique".to_owned(),
            ));
        }
        validate_identifier("question context pack id", context_pack_id.as_str())?;
        validate_identifier("question disclosure id", disclosure_id.as_str())?;
        Ok(Self {
            answer,
            supporting_memories,
            context_pack_id,
            disclosure_id,
        })
    }

    #[must_use]
    pub fn answer(&self) -> &str {
        &self.answer
    }

    #[must_use]
    pub fn supporting_memories(&self) -> &[MemoryProviderDisclosedMemory] {
        &self.supporting_memories
    }

    #[must_use]
    pub const fn context_pack_id(&self) -> &ContextPackId {
        &self.context_pack_id
    }

    #[must_use]
    pub const fn disclosure_id(&self) -> &DisclosureId {
        &self.disclosure_id
    }
}

fn validate_text(label: &str, value: &str, maximum_bytes: usize) -> Result<(), ProviderError> {
    if value.trim().is_empty() || value.len() > maximum_bytes || value.contains('\0') {
        return Err(ProviderError::InvalidConfiguration(format!(
            "{label} must be non-empty, bounded, and contain no null characters"
        )));
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
    use rembrane_domain::{ContextPackId, DisclosureId, MemoryId};

    use super::{ResolveQuestionPayload, ResolveQuestionResult};
    use crate::{
        MemoryProviderContextSelector, MemoryProviderDisclosedMemory, MemoryProviderLimits,
    };

    fn limits() -> MemoryProviderLimits {
        MemoryProviderLimits {
            maximum_context_items: 5,
            maximum_context_bytes: 1_000,
            maximum_event_batch_items: 5,
            maximum_sync_batch_items: 5,
        }
    }

    fn request() -> ResolveQuestionPayload {
        ResolveQuestionPayload::new(
            "continue a coding project",
            "What should the next agent work on?",
            MemoryProviderContextSelector::domain("development").expect("selector should be valid"),
            2,
            500,
            limits(),
        )
        .expect("question request should be valid")
    }

    fn support(id: &str, version: u64) -> MemoryProviderDisclosedMemory {
        MemoryProviderDisclosedMemory::new(MemoryId::new(id), version)
            .expect("supporting revision should be valid")
    }

    #[test]
    fn resolves_a_bounded_question_with_exact_disclosed_support() {
        let request = request();
        let result = ResolveQuestionResult::new(
            "Implement the provider serialization binding next.",
            vec![support("memory_01", 3), support("memory_02", 1)],
            ContextPackId::new("context_pack_01"),
            DisclosureId::new("disclosure_01"),
            &request,
        )
        .expect("question result should be valid");

        assert_eq!(request.maximum_supporting_items(), 2);
        assert_eq!(result.supporting_memories()[0].version(), 3);
        assert_eq!(result.disclosure_id().as_str(), "disclosure_01");
    }

    #[test]
    fn rejects_invalid_questions_and_provider_limit_overruns() {
        assert!(
            ResolveQuestionPayload::new(
                "purpose",
                "question",
                MemoryProviderContextSelector::global(),
                6,
                500,
                limits(),
            )
            .is_err()
        );
        assert!(
            ResolveQuestionPayload::new(
                "purpose",
                "question",
                MemoryProviderContextSelector::global(),
                1,
                1_001,
                limits(),
            )
            .is_err()
        );
        assert!(
            ResolveQuestionPayload::new(
                "purpose",
                " ",
                MemoryProviderContextSelector::global(),
                1,
                500,
                limits(),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_ungrounded_duplicate_or_oversized_answers() {
        let request = request();
        assert!(
            ResolveQuestionResult::new(
                "answer",
                Vec::new(),
                ContextPackId::new("context_pack_01"),
                DisclosureId::new("disclosure_01"),
                &request,
            )
            .is_err()
        );
        assert!(
            ResolveQuestionResult::new(
                "answer",
                vec![support("memory_01", 1), support("memory_01", 1)],
                ContextPackId::new("context_pack_01"),
                DisclosureId::new("disclosure_01"),
                &request,
            )
            .is_err()
        );
        assert!(
            ResolveQuestionResult::new(
                "x".repeat(501),
                vec![support("memory_01", 1)],
                ContextPackId::new("context_pack_01"),
                DisclosureId::new("disclosure_01"),
                &request,
            )
            .is_err()
        );
    }
}

use rembrane_domain::{
    ActivityId, ContextPackId, DisclosureId, EntityId, EvidenceReference, MAX_MEMORY_CONTENT_BYTES,
    MemoryId, MemoryKind, MemoryScope,
};

use crate::{MemoryProviderLimits, ProviderError};

pub const MAX_CONTEXT_PURPOSE_BYTES: usize = 4_096;
pub const MAX_CONTEXT_QUERY_BYTES: usize = 32_768;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryProviderContextSelector {
    Global,
    Domain(String),
    Entity(EntityId),
    Activity(ActivityId),
}

impl MemoryProviderContextSelector {
    /// Creates a domain selector using a portable provider-domain identifier.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for malformed domain names.
    pub fn domain(name: impl Into<String>) -> Result<Self, ProviderError> {
        let name = name.into();
        validate_portable_identifier("context domain", &name)?;
        Ok(Self::Domain(name))
    }

    /// Creates a non-empty bounded entity selector.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for an unsafe entity ID.
    pub fn entity(id: EntityId) -> Result<Self, ProviderError> {
        validate_opaque_identifier("context entity id", id.as_str())?;
        Ok(Self::Entity(id))
    }

    /// Creates a non-empty bounded activity selector.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for an unsafe activity ID.
    pub fn activity(id: ActivityId) -> Result<Self, ProviderError> {
        validate_opaque_identifier("context activity id", id.as_str())?;
        Ok(Self::Activity(id))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveContextPayload {
    purpose: String,
    query: String,
    selector: MemoryProviderContextSelector,
    maximum_items: usize,
    maximum_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryProviderSensitivity {
    Personal,
    Sensitive,
    Restricted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryProviderDisclosureConstraint {
    PurposeBound,
    NoTraining,
    NoRetention,
    ExpiresAt(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryProviderContextItem {
    memory_id: MemoryId,
    version: u64,
    scope: MemoryScope,
    kind: MemoryKind,
    content: String,
    evidence: Vec<EvidenceReference>,
    confidence_millionths: u32,
    valid_from_epoch_seconds: Option<u64>,
    valid_until_epoch_seconds: Option<u64>,
    sensitivity: MemoryProviderSensitivity,
    disclosure_constraints: Vec<MemoryProviderDisclosureConstraint>,
}

impl MemoryProviderContextItem {
    /// Creates one provenance-bearing context item.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for unsafe IDs, zero versions,
    /// empty or oversized content, missing/duplicate evidence, confidence
    /// outside `[0, 1_000_000]`, invalid validity intervals, or duplicate
    /// disclosure constraints.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        memory_id: MemoryId,
        version: u64,
        scope: MemoryScope,
        kind: MemoryKind,
        content: impl Into<String>,
        evidence: Vec<EvidenceReference>,
        confidence_millionths: u32,
        valid_from_epoch_seconds: Option<u64>,
        valid_until_epoch_seconds: Option<u64>,
        sensitivity: MemoryProviderSensitivity,
        disclosure_constraints: Vec<MemoryProviderDisclosureConstraint>,
    ) -> Result<Self, ProviderError> {
        validate_opaque_identifier("context memory id", memory_id.as_str())?;
        let content = content.into();
        validate_bounded_text("context item content", &content, MAX_MEMORY_CONTENT_BYTES)?;
        if version == 0 {
            return Err(ProviderError::InvalidConfiguration(
                "context item version must be greater than zero".to_owned(),
            ));
        }
        if evidence.is_empty()
            || evidence.iter().enumerate().any(|(index, reference)| {
                evidence[..index]
                    .iter()
                    .any(|previous| previous.id == reference.id)
            })
        {
            return Err(ProviderError::InvalidConfiguration(
                "context item evidence must be non-empty and unique".to_owned(),
            ));
        }
        if evidence.iter().any(|reference| {
            validate_opaque_identifier("context evidence id", reference.id.as_str()).is_err()
        }) {
            return Err(ProviderError::InvalidConfiguration(
                "context item evidence contains an unsafe id".to_owned(),
            ));
        }
        if confidence_millionths > 1_000_000 {
            return Err(ProviderError::InvalidConfiguration(
                "context item confidence must not exceed 1,000,000 millionths".to_owned(),
            ));
        }
        if valid_from_epoch_seconds
            .zip(valid_until_epoch_seconds)
            .is_some_and(|(start, end)| start >= end)
        {
            return Err(ProviderError::InvalidConfiguration(
                "context item validity start must precede its end".to_owned(),
            ));
        }
        if disclosure_constraints
            .iter()
            .enumerate()
            .any(|(index, constraint)| disclosure_constraints[..index].contains(constraint))
        {
            return Err(ProviderError::InvalidConfiguration(
                "context item disclosure constraints must be unique".to_owned(),
            ));
        }
        Ok(Self {
            memory_id,
            version,
            scope,
            kind,
            content,
            evidence,
            confidence_millionths,
            valid_from_epoch_seconds,
            valid_until_epoch_seconds,
            sensitivity,
            disclosure_constraints,
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
    pub const fn scope(&self) -> &MemoryScope {
        &self.scope
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
    pub fn evidence(&self) -> &[EvidenceReference] {
        &self.evidence
    }

    #[must_use]
    pub const fn confidence_millionths(&self) -> u32 {
        self.confidence_millionths
    }

    #[must_use]
    pub const fn valid_from_epoch_seconds(&self) -> Option<u64> {
        self.valid_from_epoch_seconds
    }

    #[must_use]
    pub const fn valid_until_epoch_seconds(&self) -> Option<u64> {
        self.valid_until_epoch_seconds
    }

    #[must_use]
    pub const fn sensitivity(&self) -> MemoryProviderSensitivity {
        self.sensitivity
    }

    #[must_use]
    pub fn disclosure_constraints(&self) -> &[MemoryProviderDisclosureConstraint] {
        &self.disclosure_constraints
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveContextResult {
    context_pack_id: ContextPackId,
    disclosure_id: DisclosureId,
    items: Vec<MemoryProviderContextItem>,
}

impl ResolveContextResult {
    /// Creates a response bounded by the exact originating request.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for unsafe response IDs,
    /// duplicate memory IDs, too many items, or excessive disclosed content.
    pub fn new(
        context_pack_id: ContextPackId,
        disclosure_id: DisclosureId,
        items: Vec<MemoryProviderContextItem>,
        request: &ResolveContextPayload,
    ) -> Result<Self, ProviderError> {
        validate_opaque_identifier("context pack id", context_pack_id.as_str())?;
        validate_opaque_identifier("context disclosure id", disclosure_id.as_str())?;
        if items.len() > request.maximum_items {
            return Err(ProviderError::Rejected(
                "context response contains more items than requested".to_owned(),
            ));
        }
        let mut disclosed_bytes = 0_usize;
        for (index, item) in items.iter().enumerate() {
            if items[..index]
                .iter()
                .any(|previous| previous.memory_id == item.memory_id)
            {
                return Err(ProviderError::Rejected(
                    "context response contains duplicate memory ids".to_owned(),
                ));
            }
            disclosed_bytes = disclosed_bytes
                .checked_add(item.content.len())
                .ok_or_else(|| {
                    ProviderError::Rejected(
                        "context response disclosed byte count overflowed".to_owned(),
                    )
                })?;
        }
        if disclosed_bytes > request.maximum_bytes {
            return Err(ProviderError::Rejected(
                "context response contains more bytes than requested".to_owned(),
            ));
        }
        Ok(Self {
            context_pack_id,
            disclosure_id,
            items,
        })
    }

    #[must_use]
    pub const fn context_pack_id(&self) -> &ContextPackId {
        &self.context_pack_id
    }

    #[must_use]
    pub const fn disclosure_id(&self) -> &DisclosureId {
        &self.disclosure_id
    }

    #[must_use]
    pub fn items(&self) -> &[MemoryProviderContextItem] {
        &self.items
    }
}

impl ResolveContextPayload {
    /// Creates a bounded provider-independent context request.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for empty or oversized text,
    /// zero limits, or limits exceeding the provider's advertised maximums.
    pub fn new(
        purpose: impl Into<String>,
        query: impl Into<String>,
        selector: MemoryProviderContextSelector,
        maximum_items: usize,
        maximum_bytes: usize,
        provider_limits: MemoryProviderLimits,
    ) -> Result<Self, ProviderError> {
        let purpose = purpose.into();
        let query = query.into();
        validate_bounded_text("context purpose", &purpose, MAX_CONTEXT_PURPOSE_BYTES)?;
        validate_bounded_text("context query", &query, MAX_CONTEXT_QUERY_BYTES)?;
        if maximum_items == 0
            || maximum_items > provider_limits.maximum_context_items
            || maximum_bytes == 0
            || maximum_bytes > provider_limits.maximum_context_bytes
        {
            return Err(ProviderError::InvalidConfiguration(
                "context request exceeds the provider's advertised limits".to_owned(),
            ));
        }
        Ok(Self {
            purpose,
            query,
            selector,
            maximum_items,
            maximum_bytes,
        })
    }

    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    #[must_use]
    pub fn query(&self) -> &str {
        &self.query
    }

    #[must_use]
    pub const fn selector(&self) -> &MemoryProviderContextSelector {
        &self.selector
    }

    #[must_use]
    pub const fn maximum_items(&self) -> usize {
        self.maximum_items
    }

    #[must_use]
    pub const fn maximum_bytes(&self) -> usize {
        self.maximum_bytes
    }
}

fn validate_bounded_text(label: &str, value: &str, maximum: usize) -> Result<(), ProviderError> {
    if value.trim().is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(ProviderError::InvalidConfiguration(format!(
            "{label} must contain 1 to {maximum} bytes and no null characters"
        )));
    }
    Ok(())
}

fn validate_portable_identifier(label: &str, value: &str) -> Result<(), ProviderError> {
    if value.len() < 2
        || value.len() > 255
        || !value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return Err(ProviderError::InvalidConfiguration(format!(
            "{label} must match ^[a-z0-9][a-z0-9._-]+$"
        )));
    }
    Ok(())
}

fn validate_opaque_identifier(label: &str, value: &str) -> Result<(), ProviderError> {
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
    use rembrane_domain::{
        ActivityId, ContextPackId, DisclosureId, EntityId, EvidenceId, EvidenceReference,
        EvidenceSource, MemoryId, MemoryKind, MemoryScope,
    };

    use super::{
        MAX_CONTEXT_PURPOSE_BYTES, MemoryProviderContextItem, MemoryProviderContextSelector,
        MemoryProviderDisclosureConstraint, MemoryProviderSensitivity, ResolveContextPayload,
        ResolveContextResult,
    };
    use crate::MemoryProviderLimits;

    fn limits() -> MemoryProviderLimits {
        MemoryProviderLimits {
            maximum_context_items: 20,
            maximum_context_bytes: 65_536,
            maximum_event_batch_items: 100,
            maximum_sync_batch_items: 500,
        }
    }

    fn request(maximum_items: usize, maximum_bytes: usize) -> ResolveContextPayload {
        ResolveContextPayload::new(
            "continue the current task",
            "deployment decisions and next steps",
            MemoryProviderContextSelector::Global,
            maximum_items,
            maximum_bytes,
            limits(),
        )
        .expect("request should be valid")
    }

    fn item(memory_id: &str, content: &str) -> MemoryProviderContextItem {
        MemoryProviderContextItem::new(
            MemoryId::new(memory_id),
            3,
            MemoryScope::Entity {
                id: EntityId::new("project_01"),
            },
            MemoryKind::Semantic,
            content,
            vec![EvidenceReference::new(
                EvidenceId::new(format!("evidence_{memory_id}")),
                EvidenceSource::UserStatement,
            )],
            900_000,
            Some(1_000),
            Some(2_000),
            MemoryProviderSensitivity::Personal,
            vec![
                MemoryProviderDisclosureConstraint::PurposeBound,
                MemoryProviderDisclosureConstraint::NoTraining,
            ],
        )
        .expect("context item should be valid")
    }

    #[test]
    fn builds_bounded_global_domain_entity_and_activity_requests() {
        let selectors = [
            MemoryProviderContextSelector::Global,
            MemoryProviderContextSelector::domain("development").expect("domain should be valid"),
            MemoryProviderContextSelector::entity(EntityId::new("project_01"))
                .expect("entity should be valid"),
            MemoryProviderContextSelector::activity(ActivityId::new("activity_01"))
                .expect("activity should be valid"),
        ];

        for selector in selectors {
            let payload = ResolveContextPayload::new(
                "continue the current task",
                "deployment decisions and next steps",
                selector.clone(),
                10,
                16_384,
                limits(),
            )
            .expect("request should be valid");
            assert_eq!(payload.selector(), &selector);
            assert_eq!(payload.maximum_items(), 10);
        }
    }

    #[test]
    fn rejects_unsafe_selectors_text_and_provider_limit_overruns() {
        assert!(MemoryProviderContextSelector::domain("Travel Plans").is_err());
        assert!(MemoryProviderContextSelector::entity(EntityId::new("")).is_err());
        assert!(MemoryProviderContextSelector::activity(ActivityId::new("bad id")).is_err());
        assert!(
            ResolveContextPayload::new(
                " ",
                "query",
                MemoryProviderContextSelector::Global,
                1,
                1,
                limits(),
            )
            .is_err()
        );
        assert!(
            ResolveContextPayload::new(
                "x".repeat(MAX_CONTEXT_PURPOSE_BYTES + 1),
                "query",
                MemoryProviderContextSelector::Global,
                1,
                1,
                limits(),
            )
            .is_err()
        );
        assert!(
            ResolveContextPayload::new(
                "purpose",
                "query",
                MemoryProviderContextSelector::Global,
                21,
                65_537,
                limits(),
            )
            .is_err()
        );
    }

    #[test]
    fn builds_provenance_bearing_bounded_context_results() {
        let result = ResolveContextResult::new(
            ContextPackId::new("context_pack_01"),
            DisclosureId::new("disclosure_01"),
            vec![item("memory_01", "Call the user Hippo.")],
            &request(2, 1_024),
        )
        .expect("context result should be valid");

        assert_eq!(result.context_pack_id().as_str(), "context_pack_01");
        assert_eq!(result.disclosure_id().as_str(), "disclosure_01");
        assert_eq!(result.items()[0].version(), 3);
        assert_eq!(result.items()[0].confidence_millionths(), 900_000);
        assert_eq!(
            result.items()[0].disclosure_constraints(),
            [
                MemoryProviderDisclosureConstraint::PurposeBound,
                MemoryProviderDisclosureConstraint::NoTraining,
            ]
        );
    }

    #[test]
    fn rejects_invalid_items_duplicates_and_response_limit_overruns() {
        assert!(
            MemoryProviderContextItem::new(
                MemoryId::new("memory_01"),
                0,
                MemoryScope::Global,
                MemoryKind::Preference,
                "content",
                Vec::new(),
                1_000_001,
                Some(2_000),
                Some(1_000),
                MemoryProviderSensitivity::Restricted,
                Vec::new(),
            )
            .is_err()
        );

        let duplicate = item("memory_01", "first");
        assert!(
            ResolveContextResult::new(
                ContextPackId::new("context_pack_01"),
                DisclosureId::new("disclosure_01"),
                vec![duplicate.clone(), duplicate],
                &request(2, 1_024),
            )
            .is_err()
        );
        assert!(
            ResolveContextResult::new(
                ContextPackId::new("context_pack_01"),
                DisclosureId::new("disclosure_01"),
                vec![item("memory_01", "12345"), item("memory_02", "67890")],
                &request(2, 9),
            )
            .is_err()
        );
        assert!(
            ResolveContextResult::new(
                ContextPackId::new(""),
                DisclosureId::new("disclosure_01"),
                Vec::new(),
                &request(1, 1),
            )
            .is_err()
        );
    }
}

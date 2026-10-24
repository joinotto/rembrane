use rembrane_domain::{ActivityId, EntityId};

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
    use rembrane_domain::{ActivityId, EntityId};

    use super::{MAX_CONTEXT_PURPOSE_BYTES, MemoryProviderContextSelector, ResolveContextPayload};
    use crate::MemoryProviderLimits;

    fn limits() -> MemoryProviderLimits {
        MemoryProviderLimits {
            maximum_context_items: 20,
            maximum_context_bytes: 65_536,
            maximum_event_batch_items: 100,
            maximum_sync_batch_items: 500,
        }
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
}

use rembrane_domain::{ContextPackId, DisclosureId, MemoryId};

use crate::{MemoryProviderIdempotencyKey, ProviderError};

pub const MAX_DISCLOSURE_PURPOSE_BYTES: usize = 4_096;
pub const MAX_DISCLOSED_MEMORIES: usize = 1_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryProviderDisclosedMemory {
    memory_id: MemoryId,
    version: u64,
}

impl MemoryProviderDisclosedMemory {
    /// Identifies one exact canonical memory revision crossing a trust boundary.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for an unsafe memory ID or zero
    /// version.
    pub fn new(memory_id: MemoryId, version: u64) -> Result<Self, ProviderError> {
        validate_identifier("disclosed memory id", memory_id.as_str())?;
        if version == 0 {
            return Err(ProviderError::InvalidConfiguration(
                "disclosed memory version must be greater than zero".to_owned(),
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordDisclosurePayload {
    idempotency_key: MemoryProviderIdempotencyKey,
    context_pack_id: ContextPackId,
    purpose: String,
    memories: Vec<MemoryProviderDisclosedMemory>,
    disclosed_at_epoch_seconds: u64,
}

impl RecordDisclosurePayload {
    /// Creates a portable append-only disclosure receipt request.
    ///
    /// Workspace, subject, and client identity are deliberately absent and
    /// must be derived from authenticated connection context by the server.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for unsafe IDs, invalid purpose,
    /// duplicate exact revisions, excessive item count, or a zero/future
    /// disclosure time.
    pub fn new(
        idempotency_key: MemoryProviderIdempotencyKey,
        context_pack_id: ContextPackId,
        purpose: impl Into<String>,
        memories: Vec<MemoryProviderDisclosedMemory>,
        disclosed_at_epoch_seconds: u64,
        now_epoch_seconds: u64,
    ) -> Result<Self, ProviderError> {
        validate_identifier("disclosure context pack id", context_pack_id.as_str())?;
        let purpose = purpose.into();
        if purpose.trim().is_empty()
            || purpose.len() > MAX_DISCLOSURE_PURPOSE_BYTES
            || purpose.contains('\0')
        {
            return Err(ProviderError::InvalidConfiguration(
                "disclosure purpose must be non-empty, bounded, and contain no null characters"
                    .to_owned(),
            ));
        }
        if memories.len() > MAX_DISCLOSED_MEMORIES {
            return Err(ProviderError::InvalidConfiguration(
                "disclosure contains too many memory revisions".to_owned(),
            ));
        }
        if memories.iter().enumerate().any(|(index, memory)| {
            memories[..index].iter().any(|previous| {
                previous.memory_id == memory.memory_id && previous.version == memory.version
            })
        }) {
            return Err(ProviderError::InvalidConfiguration(
                "disclosed memory revisions must be unique".to_owned(),
            ));
        }
        if disclosed_at_epoch_seconds == 0 || disclosed_at_epoch_seconds > now_epoch_seconds {
            return Err(ProviderError::InvalidConfiguration(
                "disclosure time must be positive and not in the future".to_owned(),
            ));
        }
        Ok(Self {
            idempotency_key,
            context_pack_id,
            purpose,
            memories,
            disclosed_at_epoch_seconds,
        })
    }

    #[must_use]
    pub const fn idempotency_key(&self) -> &MemoryProviderIdempotencyKey {
        &self.idempotency_key
    }

    #[must_use]
    pub const fn context_pack_id(&self) -> &ContextPackId {
        &self.context_pack_id
    }

    #[must_use]
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    #[must_use]
    pub fn memories(&self) -> &[MemoryProviderDisclosedMemory] {
        &self.memories
    }

    #[must_use]
    pub const fn disclosed_at_epoch_seconds(&self) -> u64 {
        self.disclosed_at_epoch_seconds
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordDisclosureResult {
    disclosure_id: DisclosureId,
}

impl RecordDisclosureResult {
    /// Creates the canonical identity of the appended disclosure receipt.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for an unsafe disclosure ID.
    pub fn new(disclosure_id: DisclosureId) -> Result<Self, ProviderError> {
        validate_identifier("disclosure id", disclosure_id.as_str())?;
        Ok(Self { disclosure_id })
    }

    #[must_use]
    pub const fn disclosure_id(&self) -> &DisclosureId {
        &self.disclosure_id
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

#[cfg(test)]
mod tests {
    use rembrane_domain::{ContextPackId, DisclosureId, MemoryId};

    use super::{
        MAX_DISCLOSED_MEMORIES, MemoryProviderDisclosedMemory, RecordDisclosurePayload,
        RecordDisclosureResult,
    };
    use crate::MemoryProviderIdempotencyKey;

    fn key() -> MemoryProviderIdempotencyKey {
        MemoryProviderIdempotencyKey::new("disclosure_0123456789abcdef")
            .expect("idempotency key should be valid")
    }

    #[test]
    fn records_exact_revisions_without_caller_controlled_identity() {
        let payload = RecordDisclosurePayload::new(
            key(),
            ContextPackId::new("context_pack_01"),
            "continue project work",
            vec![
                MemoryProviderDisclosedMemory::new(MemoryId::new("memory_01"), 3)
                    .expect("revision should be valid"),
                MemoryProviderDisclosedMemory::new(MemoryId::new("memory_02"), 1)
                    .expect("revision should be valid"),
            ],
            1_000,
            1_001,
        )
        .expect("receipt payload should be valid");

        assert_eq!(payload.context_pack_id().as_str(), "context_pack_01");
        assert_eq!(payload.memories()[0].version(), 3);
        assert_eq!(payload.disclosed_at_epoch_seconds(), 1_000);

        let result = RecordDisclosureResult::new(DisclosureId::new("disclosure_01"))
            .expect("result should be valid");
        assert_eq!(result.disclosure_id().as_str(), "disclosure_01");
    }

    #[test]
    fn rejects_invalid_revisions_duplicates_bounds_and_future_time() {
        assert!(MemoryProviderDisclosedMemory::new(MemoryId::new(""), 1).is_err());
        assert!(MemoryProviderDisclosedMemory::new(MemoryId::new("memory_01"), 0).is_err());
        let revision = MemoryProviderDisclosedMemory::new(MemoryId::new("memory_01"), 1)
            .expect("revision should be valid");
        assert!(
            RecordDisclosurePayload::new(
                key(),
                ContextPackId::new("context_pack_01"),
                "purpose",
                vec![revision.clone(), revision],
                1_000,
                1_000,
            )
            .is_err()
        );
        assert!(
            RecordDisclosurePayload::new(
                key(),
                ContextPackId::new("context_pack_01"),
                "purpose",
                (0..=MAX_DISCLOSED_MEMORIES)
                    .map(|index| {
                        MemoryProviderDisclosedMemory::new(
                            MemoryId::new(format!("memory_{index}")),
                            1,
                        )
                        .expect("revision should be valid")
                    })
                    .collect(),
                1_000,
                1_000,
            )
            .is_err()
        );
        assert!(
            RecordDisclosurePayload::new(
                key(),
                ContextPackId::new("context_pack_01"),
                "purpose",
                Vec::new(),
                1_001,
                1_000,
            )
            .is_err()
        );
        assert!(RecordDisclosureResult::new(DisclosureId::new("")).is_err());
    }
}

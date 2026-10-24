use crate::{MemoryProviderIdempotencyKey, MemoryProviderLimits, ProviderError};

pub const MAX_SYNC_CURSOR_BYTES: usize = 512;
pub const MAX_SYNC_RESOURCE_ID_BYTES: usize = 255;
pub const MAX_SYNC_PAYLOAD_BYTES: usize = 262_144;
pub const MAX_SYNC_BATCH_BYTES: usize = 4_194_304;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MemoryProviderSyncCursor(String);

impl MemoryProviderSyncCursor {
    /// Creates an opaque server-issued synchronization cursor.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error unless the cursor contains
    /// 16-512 URL-safe ASCII characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ProviderError> {
        let value = value.into();
        if !(16..=MAX_SYNC_CURSOR_BYTES).contains(&value.len())
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory sync cursor must contain 16 to 512 URL-safe ASCII characters".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryProviderSyncResource {
    Memory,
    Evidence,
    ActivityCheckpoint,
    DisclosureReceipt,
    Entity,
    Event,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryProviderSyncOperation {
    Upsert,
    Delete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncPullPayload {
    cursor: Option<MemoryProviderSyncCursor>,
    maximum_items: usize,
}

impl SyncPullPayload {
    /// Creates a bounded incremental pull request.
    ///
    /// A missing cursor starts from the provider-defined retained beginning.
    /// Cursors are server-issued capabilities and must remain bound to the
    /// authenticated workspace and client connection by the transport layer.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for a zero item limit or a limit
    /// exceeding provider negotiation.
    pub fn new(
        cursor: Option<MemoryProviderSyncCursor>,
        maximum_items: usize,
        provider_limits: MemoryProviderLimits,
    ) -> Result<Self, ProviderError> {
        if maximum_items == 0 || maximum_items > provider_limits.maximum_sync_batch_items {
            return Err(ProviderError::InvalidConfiguration(
                "memory sync pull item limit must be positive and within negotiated limits"
                    .to_owned(),
            ));
        }
        Ok(Self {
            cursor,
            maximum_items,
        })
    }

    #[must_use]
    pub const fn cursor(&self) -> Option<&MemoryProviderSyncCursor> {
        self.cursor.as_ref()
    }

    #[must_use]
    pub const fn maximum_items(&self) -> usize {
        self.maximum_items
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryProviderPulledChange {
    change_id: String,
    sequence: u64,
    resource: MemoryProviderSyncResource,
    resource_id: String,
    version: u64,
    operation: MemoryProviderSyncOperation,
    payload: Option<String>,
    payload_sha256: Option<String>,
}

impl MemoryProviderPulledChange {
    /// Creates one canonical server-ordered synchronization change.
    ///
    /// Upserts carry a bounded representation and its lowercase SHA-256
    /// digest. Deletions carry neither, preventing deleted content from being
    /// replicated accidentally. Payloads may contain ciphertext when the
    /// provider advertises end-to-end-encrypted privacy mode.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for unsafe identities, zero
    /// sequence/version, or payload/digest state inconsistent with operation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        change_id: impl Into<String>,
        sequence: u64,
        resource: MemoryProviderSyncResource,
        resource_id: impl Into<String>,
        version: u64,
        operation: MemoryProviderSyncOperation,
        payload: Option<String>,
        payload_sha256: Option<String>,
    ) -> Result<Self, ProviderError> {
        let change_id = change_id.into();
        validate_identifier("memory sync change id", &change_id)?;
        let resource_id = resource_id.into();
        validate_identifier("memory sync resource id", &resource_id)?;
        if sequence == 0 || version == 0 {
            return Err(ProviderError::InvalidConfiguration(
                "memory sync change sequence and version must be greater than zero".to_owned(),
            ));
        }
        validate_operation_payload(operation, payload.as_deref(), payload_sha256.as_deref())?;
        Ok(Self {
            change_id,
            sequence,
            resource,
            resource_id,
            version,
            operation,
            payload,
            payload_sha256,
        })
    }

    #[must_use]
    pub fn change_id(&self) -> &str {
        &self.change_id
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn resource(&self) -> MemoryProviderSyncResource {
        self.resource
    }

    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub const fn operation(&self) -> MemoryProviderSyncOperation {
        self.operation
    }

    #[must_use]
    pub fn payload(&self) -> Option<&str> {
        self.payload.as_deref()
    }

    #[must_use]
    pub fn payload_sha256(&self) -> Option<&str> {
        self.payload_sha256.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncPullResult {
    changes: Vec<MemoryProviderPulledChange>,
    next_cursor: MemoryProviderSyncCursor,
    has_more: bool,
}

impl SyncPullResult {
    /// Creates a canonical incremental pull page.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for item/byte limit overruns,
    /// duplicate change IDs, non-increasing sequence, or an empty page that
    /// incorrectly claims more immediately available changes.
    pub fn new(
        changes: Vec<MemoryProviderPulledChange>,
        next_cursor: MemoryProviderSyncCursor,
        has_more: bool,
        request: &SyncPullPayload,
    ) -> Result<Self, ProviderError> {
        if changes.len() > request.maximum_items
            || total_payload_bytes(changes.iter().map(|change| change.payload.as_deref()))
                > MAX_SYNC_BATCH_BYTES
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory sync pull result exceeds requested item or canonical byte limits"
                    .to_owned(),
            ));
        }
        if has_more && changes.is_empty() {
            return Err(ProviderError::InvalidConfiguration(
                "memory sync pull cannot claim more changes after an empty page".to_owned(),
            ));
        }
        if changes.iter().enumerate().any(|(index, change)| {
            changes[..index]
                .iter()
                .any(|previous| previous.change_id == change.change_id)
                || index > 0 && changes[index - 1].sequence >= change.sequence
        }) {
            return Err(ProviderError::InvalidConfiguration(
                "memory sync pull change IDs must be unique and sequences strictly increasing"
                    .to_owned(),
            ));
        }
        Ok(Self {
            changes,
            next_cursor,
            has_more,
        })
    }

    #[must_use]
    pub fn changes(&self) -> &[MemoryProviderPulledChange] {
        &self.changes
    }

    #[must_use]
    pub const fn next_cursor(&self) -> &MemoryProviderSyncCursor {
        &self.next_cursor
    }

    #[must_use]
    pub const fn has_more(&self) -> bool {
        self.has_more
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryProviderPushMutation {
    mutation_id: String,
    resource: MemoryProviderSyncResource,
    resource_id: String,
    expected_version: Option<u64>,
    operation: MemoryProviderSyncOperation,
    payload: Option<String>,
    payload_sha256: Option<String>,
}

impl MemoryProviderPushMutation {
    /// Creates one optimistic client mutation without canonical sequence.
    ///
    /// `expected_version = None` represents creation and is valid only for an
    /// upsert. Existing upserts and deletions require a positive exact version.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for unsafe identities, invalid
    /// optimistic version state, or operation/payload mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mutation_id: impl Into<String>,
        resource: MemoryProviderSyncResource,
        resource_id: impl Into<String>,
        expected_version: Option<u64>,
        operation: MemoryProviderSyncOperation,
        payload: Option<String>,
        payload_sha256: Option<String>,
    ) -> Result<Self, ProviderError> {
        let mutation_id = mutation_id.into();
        validate_identifier("memory sync mutation id", &mutation_id)?;
        let resource_id = resource_id.into();
        validate_identifier("memory sync mutation resource id", &resource_id)?;
        if expected_version == Some(0)
            || (operation == MemoryProviderSyncOperation::Delete && expected_version.is_none())
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory sync mutation requires valid optimistic version state".to_owned(),
            ));
        }
        validate_operation_payload(operation, payload.as_deref(), payload_sha256.as_deref())?;
        Ok(Self {
            mutation_id,
            resource,
            resource_id,
            expected_version,
            operation,
            payload,
            payload_sha256,
        })
    }

    #[must_use]
    pub fn mutation_id(&self) -> &str {
        &self.mutation_id
    }

    #[must_use]
    pub const fn resource(&self) -> MemoryProviderSyncResource {
        self.resource
    }

    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    #[must_use]
    pub const fn expected_version(&self) -> Option<u64> {
        self.expected_version
    }

    #[must_use]
    pub const fn operation(&self) -> MemoryProviderSyncOperation {
        self.operation
    }

    #[must_use]
    pub fn payload(&self) -> Option<&str> {
        self.payload.as_deref()
    }

    #[must_use]
    pub fn payload_sha256(&self) -> Option<&str> {
        self.payload_sha256.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncPushPayload {
    idempotency_key: MemoryProviderIdempotencyKey,
    base_cursor: MemoryProviderSyncCursor,
    mutations: Vec<MemoryProviderPushMutation>,
}

impl SyncPushPayload {
    /// Creates an idempotent optimistic synchronization push.
    ///
    /// The base cursor lets the server reject a fork before partially applying
    /// a batch. Atomic application remains a mandatory server responsibility.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for empty/oversized batches,
    /// duplicate mutation IDs, or canonical byte-limit overruns.
    pub fn new(
        idempotency_key: MemoryProviderIdempotencyKey,
        base_cursor: MemoryProviderSyncCursor,
        mutations: Vec<MemoryProviderPushMutation>,
        provider_limits: MemoryProviderLimits,
    ) -> Result<Self, ProviderError> {
        if mutations.is_empty()
            || mutations.len() > provider_limits.maximum_sync_batch_items
            || total_payload_bytes(mutations.iter().map(|mutation| mutation.payload.as_deref()))
                > MAX_SYNC_BATCH_BYTES
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory sync push must be non-empty and within negotiated item and byte limits"
                    .to_owned(),
            ));
        }
        if mutations.iter().enumerate().any(|(index, mutation)| {
            mutations[..index]
                .iter()
                .any(|previous| previous.mutation_id == mutation.mutation_id)
        }) {
            return Err(ProviderError::InvalidConfiguration(
                "memory sync push mutation IDs must be unique".to_owned(),
            ));
        }
        Ok(Self {
            idempotency_key,
            base_cursor,
            mutations,
        })
    }

    #[must_use]
    pub const fn idempotency_key(&self) -> &MemoryProviderIdempotencyKey {
        &self.idempotency_key
    }

    #[must_use]
    pub const fn base_cursor(&self) -> &MemoryProviderSyncCursor {
        &self.base_cursor
    }

    #[must_use]
    pub fn mutations(&self) -> &[MemoryProviderPushMutation] {
        &self.mutations
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryProviderAcceptedMutation {
    mutation_id: String,
    version: u64,
    sequence: u64,
}

impl MemoryProviderAcceptedMutation {
    /// Binds a submitted mutation to its canonical revision and sequence.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error for unsafe identity or zero
    /// canonical version/sequence.
    pub fn new(
        mutation_id: impl Into<String>,
        version: u64,
        sequence: u64,
    ) -> Result<Self, ProviderError> {
        let mutation_id = mutation_id.into();
        validate_identifier("accepted sync mutation id", &mutation_id)?;
        if version == 0 || sequence == 0 {
            return Err(ProviderError::InvalidConfiguration(
                "accepted sync mutation version and sequence must be greater than zero".to_owned(),
            ));
        }
        Ok(Self {
            mutation_id,
            version,
            sequence,
        })
    }

    #[must_use]
    pub fn mutation_id(&self) -> &str {
        &self.mutation_id
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncPushResult {
    accepted: Vec<MemoryProviderAcceptedMutation>,
    next_cursor: MemoryProviderSyncCursor,
}

impl SyncPushResult {
    /// Creates the atomic success result for a complete push batch.
    ///
    /// # Errors
    ///
    /// Returns an invalid-configuration error unless every submitted mutation
    /// appears exactly once, in request order, with strictly increasing
    /// canonical sequence.
    pub fn new(
        accepted: Vec<MemoryProviderAcceptedMutation>,
        next_cursor: MemoryProviderSyncCursor,
        request: &SyncPushPayload,
    ) -> Result<Self, ProviderError> {
        if accepted.len() != request.mutations.len()
            || accepted.iter().enumerate().any(|(index, result)| {
                result.mutation_id != request.mutations[index].mutation_id
                    || index > 0 && accepted[index - 1].sequence >= result.sequence
            })
        {
            return Err(ProviderError::InvalidConfiguration(
                "memory sync push result must exactly match the ordered request with increasing sequences"
                    .to_owned(),
            ));
        }
        Ok(Self {
            accepted,
            next_cursor,
        })
    }

    #[must_use]
    pub fn accepted(&self) -> &[MemoryProviderAcceptedMutation] {
        &self.accepted
    }

    #[must_use]
    pub const fn next_cursor(&self) -> &MemoryProviderSyncCursor {
        &self.next_cursor
    }
}

fn validate_operation_payload(
    operation: MemoryProviderSyncOperation,
    payload: Option<&str>,
    payload_sha256: Option<&str>,
) -> Result<(), ProviderError> {
    match operation {
        MemoryProviderSyncOperation::Upsert => {
            let Some(payload) = payload else {
                return Err(ProviderError::InvalidConfiguration(
                    "memory sync upsert requires a payload".to_owned(),
                ));
            };
            let Some(digest) = payload_sha256 else {
                return Err(ProviderError::InvalidConfiguration(
                    "memory sync upsert requires a payload digest".to_owned(),
                ));
            };
            if payload.is_empty()
                || payload.len() > MAX_SYNC_PAYLOAD_BYTES
                || payload.contains('\0')
            {
                return Err(ProviderError::InvalidConfiguration(
                    "memory sync payload must be non-empty, bounded, and contain no null characters"
                        .to_owned(),
                ));
            }
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(ProviderError::InvalidConfiguration(
                    "memory sync payload digest must be lowercase SHA-256 hex".to_owned(),
                ));
            }
        }
        MemoryProviderSyncOperation::Delete => {
            if payload.is_some() || payload_sha256.is_some() {
                return Err(ProviderError::InvalidConfiguration(
                    "memory sync deletion must not contain payload data or digest".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn total_payload_bytes<'a>(payloads: impl Iterator<Item = Option<&'a str>>) -> usize {
    payloads
        .map(|payload| payload.map_or(0, str::len))
        .try_fold(0usize, usize::checked_add)
        .unwrap_or(usize::MAX)
}

fn validate_identifier(label: &str, value: &str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.len() > MAX_SYNC_RESOURCE_ID_BYTES
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
    use super::{
        MemoryProviderAcceptedMutation, MemoryProviderPulledChange, MemoryProviderPushMutation,
        MemoryProviderSyncCursor, MemoryProviderSyncOperation, MemoryProviderSyncResource,
        SyncPullPayload, SyncPullResult, SyncPushPayload, SyncPushResult,
    };
    use crate::{MemoryProviderIdempotencyKey, MemoryProviderLimits};

    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn limits(maximum_sync_batch_items: usize) -> MemoryProviderLimits {
        MemoryProviderLimits {
            maximum_context_items: 10,
            maximum_context_bytes: 10_000,
            maximum_event_batch_items: 10,
            maximum_sync_batch_items,
        }
    }

    fn cursor(suffix: &str) -> MemoryProviderSyncCursor {
        MemoryProviderSyncCursor::new(format!("cursor_0123456789_{suffix}"))
            .expect("cursor should be valid")
    }

    fn pulled(id: &str, sequence: u64) -> MemoryProviderPulledChange {
        MemoryProviderPulledChange::new(
            id,
            sequence,
            MemoryProviderSyncResource::Memory,
            "memory_01",
            sequence,
            MemoryProviderSyncOperation::Upsert,
            Some(format!("ciphertext-{sequence}")),
            Some(DIGEST.to_owned()),
        )
        .expect("pull change should be valid")
    }

    fn mutation(id: &str, expected_version: Option<u64>) -> MemoryProviderPushMutation {
        MemoryProviderPushMutation::new(
            id,
            MemoryProviderSyncResource::Memory,
            "memory_01",
            expected_version,
            MemoryProviderSyncOperation::Upsert,
            Some("ciphertext".to_owned()),
            Some(DIGEST.to_owned()),
        )
        .expect("push mutation should be valid")
    }

    #[test]
    fn pulls_strictly_ordered_bounded_changes_from_opaque_cursor() {
        let request = SyncPullPayload::new(Some(cursor("start")), 2, limits(2))
            .expect("pull request should be valid");
        let result = SyncPullResult::new(
            vec![pulled("change_01", 4), pulled("change_02", 5)],
            cursor("next"),
            true,
            &request,
        )
        .expect("pull result should be valid");
        assert_eq!(result.changes()[1].sequence(), 5);
        assert!(result.has_more());
    }

    #[test]
    fn rejects_invalid_pull_limits_order_and_payload_state() {
        assert!(SyncPullPayload::new(None, 0, limits(2)).is_err());
        assert!(MemoryProviderSyncCursor::new("short").is_err());
        assert!(
            MemoryProviderPulledChange::new(
                "change_01",
                1,
                MemoryProviderSyncResource::Memory,
                "memory_01",
                1,
                MemoryProviderSyncOperation::Delete,
                Some("deleted plaintext".to_owned()),
                Some(DIGEST.to_owned()),
            )
            .is_err()
        );
        let request =
            SyncPullPayload::new(None, 2, limits(2)).expect("pull request should be valid");
        assert!(
            SyncPullResult::new(
                vec![pulled("change_01", 5), pulled("change_02", 4)],
                cursor("next"),
                false,
                &request,
            )
            .is_err()
        );
        assert!(SyncPullResult::new(Vec::new(), cursor("next"), true, &request).is_err());
    }

    #[test]
    fn pushes_an_atomic_idempotent_optimistic_batch() {
        let request = SyncPushPayload::new(
            MemoryProviderIdempotencyKey::new("syncpush_0123456789")
                .expect("idempotency key should be valid"),
            cursor("base"),
            vec![
                mutation("mutation_01", None),
                mutation("mutation_02", Some(1)),
            ],
            limits(2),
        )
        .expect("push request should be valid");
        let result = SyncPushResult::new(
            vec![
                MemoryProviderAcceptedMutation::new("mutation_01", 1, 8)
                    .expect("accepted mutation should be valid"),
                MemoryProviderAcceptedMutation::new("mutation_02", 2, 9)
                    .expect("accepted mutation should be valid"),
            ],
            cursor("next"),
            &request,
        )
        .expect("push result should be valid");
        assert_eq!(result.accepted()[1].version(), 2);
        assert_eq!(result.next_cursor().as_str(), "cursor_0123456789_next");
    }

    #[test]
    fn rejects_delete_without_version_and_mismatched_push_results() {
        assert!(
            MemoryProviderPushMutation::new(
                "mutation_delete",
                MemoryProviderSyncResource::Memory,
                "memory_01",
                None,
                MemoryProviderSyncOperation::Delete,
                None,
                None,
            )
            .is_err()
        );
        let request = SyncPushPayload::new(
            MemoryProviderIdempotencyKey::new("syncpush_0123456789")
                .expect("idempotency key should be valid"),
            cursor("base"),
            vec![mutation("mutation_01", Some(1))],
            limits(1),
        )
        .expect("push request should be valid");
        assert!(
            SyncPushResult::new(
                vec![
                    MemoryProviderAcceptedMutation::new("wrong_mutation", 2, 8)
                        .expect("accepted mutation should be valid"),
                ],
                cursor("next"),
                &request,
            )
            .is_err()
        );
    }
}

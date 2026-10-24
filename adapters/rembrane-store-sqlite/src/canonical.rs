use rembrane_application::{ApplicationError, CanonicalMutationRepository, EventRepository};
use rembrane_codec::{decode_event, encode_event, encode_memory};
use rembrane_crypto::{EncryptedPayload, EncryptionContext, PayloadPurpose, RecordCipher};
use rembrane_domain::{
    CanonicalEvent, EventPayload, EvidenceSource, MemoryKind, MemoryRecord, MemoryScope,
    MemoryStatus, ProjectionJob, ProjectionOperation, ProjectionStatus, WorkspaceId,
};
use rusqlite::{Transaction, params};

use crate::{SqliteStore, map_write_error};

impl<C: RecordCipher> CanonicalMutationRepository for SqliteStore<C> {
    fn insert_memory_with_event(
        &mut self,
        memory: MemoryRecord,
        event: CanonicalEvent,
        projections: Vec<ProjectionJob>,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        validate_mutation(&memory, &event, &projections)?;
        let encrypted_memory = seal_memory(&self.cipher, &memory)?;
        let encrypted_event = seal_event(&self.cipher, &event)?;

        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        require_event_sequence(
            &transaction,
            event.workspace_id(),
            event.sequence(),
            expected_previous_sequence,
        )?;
        insert_memory(&transaction, &memory, &encrypted_memory)?;
        insert_evidence(&transaction, &memory)?;
        insert_event(&transaction, &event, &encrypted_event)?;
        insert_projections(&transaction, &projections)?;
        transaction.commit().map_err(map_write_error)
    }

    fn replace_memory_with_event(
        &mut self,
        memory: MemoryRecord,
        expected_memory_version: u64,
        event: CanonicalEvent,
        projections: Vec<ProjectionJob>,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        validate_mutation(&memory, &event, &projections)?;
        if memory.version() != expected_memory_version.saturating_add(1) {
            return Err(ApplicationError::VersionConflict);
        }
        let encrypted_memory = seal_memory(&self.cipher, &memory)?;
        let encrypted_event = seal_event(&self.cipher, &event)?;

        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        require_event_sequence(
            &transaction,
            event.workspace_id(),
            event.sequence(),
            expected_previous_sequence,
        )?;
        replace_memory(
            &transaction,
            &memory,
            expected_memory_version,
            &encrypted_memory,
        )?;
        transaction
            .execute(
                "DELETE FROM memory_evidence
                 WHERE workspace_id = ?1 AND memory_id = ?2",
                params![memory.workspace_id().as_str(), memory.id().as_str()],
            )
            .map_err(map_write_error)?;
        insert_evidence(&transaction, &memory)?;
        insert_event(&transaction, &event, &encrypted_event)?;
        insert_projections(&transaction, &projections)?;
        transaction.commit().map_err(map_write_error)
    }
}

impl<C: RecordCipher> EventRepository for SqliteStore<C> {
    fn append_event(
        &mut self,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        let encrypted_event = seal_event(&self.cipher, &event)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        require_event_sequence(
            &transaction,
            event.workspace_id(),
            event.sequence(),
            expected_previous_sequence,
        )?;
        insert_event(&transaction, &event, &encrypted_event)?;
        transaction.commit().map_err(map_write_error)
    }

    fn list_events_since(
        &self,
        workspace_id: &WorkspaceId,
        sequence: u64,
    ) -> Result<Vec<CanonicalEvent>, ApplicationError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT
                    sequence,
                    id,
                    payload_ciphertext,
                    encryption_key_id,
                    encryption_algorithm,
                    encryption_nonce
                 FROM workspace_events
                 WHERE workspace_id = ?1 AND sequence > ?2
                 ORDER BY sequence",
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let rows = statement
            .query_map(params![workspace_id.as_str(), to_i64(sequence)?], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            })
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let mut events = Vec::new();
        for row in rows {
            let (sequence, event_id, ciphertext, key_id, algorithm, nonce) =
                row.map_err(|_| ApplicationError::StorageUnavailable)?;
            let sequence =
                u64::try_from(sequence).map_err(|_| ApplicationError::StorageUnavailable)?;
            let context = EncryptionContext::new(
                workspace_id.clone(),
                &event_id,
                sequence,
                PayloadPurpose::CanonicalEvent,
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
            let payload = EncryptedPayload::new(ciphertext, key_id, algorithm, nonce)
                .map_err(|_| ApplicationError::StorageUnavailable)?;
            let plaintext = self
                .cipher
                .open(&context, &payload)
                .map_err(|_| ApplicationError::StorageUnavailable)?;
            let event =
                decode_event(&plaintext).map_err(|_| ApplicationError::StorageUnavailable)?;
            if event.workspace_id() != workspace_id
                || event.id().as_str() != event_id
                || event.sequence() != sequence
            {
                return Err(ApplicationError::StorageUnavailable);
            }
            events.push(event);
        }
        Ok(events)
    }
}

pub(super) struct SealedRecord {
    pub(super) ciphertext: Vec<u8>,
    pub(super) key_id: String,
    pub(super) algorithm: String,
    pub(super) nonce: Vec<u8>,
}

pub(super) fn seal_memory(
    cipher: &impl RecordCipher,
    memory: &MemoryRecord,
) -> Result<SealedRecord, ApplicationError> {
    let plaintext = encode_memory(memory).map_err(|_| ApplicationError::StorageUnavailable)?;
    let context = EncryptionContext::new(
        memory.workspace_id().clone(),
        memory.id().as_str(),
        memory.version(),
        PayloadPurpose::MemoryContent,
    )
    .map_err(|_| ApplicationError::Validation("invalid memory context".to_owned()))?;
    let encrypted = cipher
        .seal(&context, &plaintext)
        .map_err(|_| ApplicationError::StorageUnavailable)?;
    Ok(SealedRecord {
        ciphertext: encrypted.ciphertext().to_vec(),
        key_id: encrypted.key_id().to_owned(),
        algorithm: encrypted.algorithm().to_owned(),
        nonce: encrypted.nonce().to_vec(),
    })
}

pub(super) fn seal_event(
    cipher: &impl RecordCipher,
    event: &CanonicalEvent,
) -> Result<SealedRecord, ApplicationError> {
    let plaintext = encode_event(event).map_err(|_| ApplicationError::StorageUnavailable)?;
    let context = EncryptionContext::new(
        event.workspace_id().clone(),
        event.id().as_str(),
        event.sequence(),
        PayloadPurpose::CanonicalEvent,
    )
    .map_err(|_| ApplicationError::Validation("invalid event context".to_owned()))?;
    let encrypted = cipher
        .seal(&context, &plaintext)
        .map_err(|_| ApplicationError::StorageUnavailable)?;
    Ok(SealedRecord {
        ciphertext: encrypted.ciphertext().to_vec(),
        key_id: encrypted.key_id().to_owned(),
        algorithm: encrypted.algorithm().to_owned(),
        nonce: encrypted.nonce().to_vec(),
    })
}

pub(super) fn insert_memory(
    transaction: &Transaction<'_>,
    memory: &MemoryRecord,
    encrypted: &SealedRecord,
) -> Result<(), ApplicationError> {
    let (scope_type, scope_value) = encode_scope(memory.scope());
    transaction
        .execute(
            "INSERT INTO memories (
                workspace_id,
                id,
                subject_id,
                scope_type,
                scope_value,
                kind,
                status,
                content_ciphertext,
                encryption_key_id,
                encryption_algorithm,
                encryption_nonce,
                version
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12
            )",
            params![
                memory.workspace_id().as_str(),
                memory.id().as_str(),
                memory.subject_id().as_str(),
                scope_type,
                scope_value,
                encode_memory_kind(memory.kind()),
                encode_memory_status(memory.status()),
                encrypted.ciphertext,
                encrypted.key_id,
                encrypted.algorithm,
                encrypted.nonce,
                to_i64(memory.version())?
            ],
        )
        .map(|_| ())
        .map_err(map_write_error)
}

fn replace_memory(
    transaction: &Transaction<'_>,
    memory: &MemoryRecord,
    expected_version: u64,
    encrypted: &SealedRecord,
) -> Result<(), ApplicationError> {
    let (scope_type, scope_value) = encode_scope(memory.scope());
    let changed = transaction
        .execute(
            "UPDATE memories
             SET subject_id = ?3,
                 scope_type = ?4,
                 scope_value = ?5,
                 kind = ?6,
                 status = ?7,
                 content_ciphertext = ?8,
                 encryption_key_id = ?9,
                 encryption_algorithm = ?10,
                 encryption_nonce = ?11,
                 version = ?12,
                 updated_at = CURRENT_TIMESTAMP
             WHERE workspace_id = ?1 AND id = ?2 AND version = ?13",
            params![
                memory.workspace_id().as_str(),
                memory.id().as_str(),
                memory.subject_id().as_str(),
                scope_type,
                scope_value,
                encode_memory_kind(memory.kind()),
                encode_memory_status(memory.status()),
                encrypted.ciphertext,
                encrypted.key_id,
                encrypted.algorithm,
                encrypted.nonce,
                to_i64(memory.version())?,
                to_i64(expected_version)?
            ],
        )
        .map_err(map_write_error)?;
    if changed == 0 {
        return Err(ApplicationError::VersionConflict);
    }
    Ok(())
}

pub(super) fn insert_evidence(
    transaction: &Transaction<'_>,
    memory: &MemoryRecord,
) -> Result<(), ApplicationError> {
    for (ordinal, evidence) in memory.evidence().iter().enumerate() {
        transaction
            .execute(
                "INSERT INTO memory_evidence (
                    workspace_id,
                    memory_id,
                    ordinal,
                    evidence_id,
                    source_type
                ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    memory.workspace_id().as_str(),
                    memory.id().as_str(),
                    i64::try_from(ordinal).map_err(|_| {
                        ApplicationError::Validation("too many evidence references".to_owned())
                    })?,
                    evidence.id.as_str(),
                    encode_evidence_source(evidence.source)
                ],
            )
            .map_err(map_write_error)?;
    }
    Ok(())
}

pub(super) fn insert_event(
    transaction: &Transaction<'_>,
    event: &CanonicalEvent,
    encrypted: &SealedRecord,
) -> Result<(), ApplicationError> {
    transaction
        .execute(
            "INSERT INTO workspace_events (
                workspace_id,
                sequence,
                id,
                actor_id,
                subject_id,
                event_type,
                payload_ciphertext,
                encryption_key_id,
                encryption_algorithm,
                encryption_nonce
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                event.workspace_id().as_str(),
                to_i64(event.sequence())?,
                event.id().as_str(),
                event.actor_id().as_str(),
                event.subject_id().map(|subject| subject.as_str()),
                event_type(event),
                encrypted.ciphertext,
                encrypted.key_id,
                encrypted.algorithm,
                encrypted.nonce
            ],
        )
        .map(|_| ())
        .map_err(map_write_error)
}

pub(super) fn insert_projections(
    transaction: &Transaction<'_>,
    projections: &[ProjectionJob],
) -> Result<(), ApplicationError> {
    for projection in projections {
        transaction
            .execute(
                "INSERT INTO projection_outbox (
                    id,
                    workspace_id,
                    memory_id,
                    memory_version,
                    provider_id,
                    operation,
                    status,
                    attempts
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    projection.id().as_str(),
                    projection.workspace_id().as_str(),
                    projection.memory_id().as_str(),
                    to_i64(projection.memory_version())?,
                    projection.provider_id().as_str(),
                    encode_projection_operation(projection.operation()),
                    encode_projection_status(projection.status()),
                    i64::from(projection.attempts())
                ],
            )
            .map_err(map_write_error)?;
    }
    Ok(())
}

pub(super) fn require_event_sequence(
    transaction: &Transaction<'_>,
    workspace_id: &WorkspaceId,
    event_sequence: u64,
    expected_previous_sequence: u64,
) -> Result<(), ApplicationError> {
    let current: i64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(sequence), 0)
             FROM workspace_events
             WHERE workspace_id = ?1",
            [workspace_id.as_str()],
            |row| row.get(0),
        )
        .map_err(|_| ApplicationError::StorageUnavailable)?;
    let expected = to_i64(expected_previous_sequence)?;
    if current != expected || event_sequence != expected_previous_sequence.saturating_add(1) {
        return Err(ApplicationError::SequenceConflict);
    }
    Ok(())
}

fn validate_mutation(
    memory: &MemoryRecord,
    event: &CanonicalEvent,
    projections: &[ProjectionJob],
) -> Result<(), ApplicationError> {
    if memory.workspace_id() != event.workspace_id() {
        return Err(ApplicationError::Validation(
            "memory and event workspace must match".to_owned(),
        ));
    }
    if event.subject_id() != Some(memory.subject_id())
        || !event_describes_memory(event.payload(), memory)
    {
        return Err(ApplicationError::Validation(
            "event does not describe canonical memory mutation".to_owned(),
        ));
    }
    let expected_operation = if memory.status() == MemoryStatus::Deleted {
        ProjectionOperation::Delete
    } else {
        ProjectionOperation::Upsert
    };
    if projections.iter().any(|projection| {
        projection.workspace_id() != memory.workspace_id()
            || projection.memory_id() != memory.id()
            || projection.memory_version() != memory.version()
            || projection.operation() != expected_operation
            || projection.status() != ProjectionStatus::Pending
            || projection.attempts() != 0
    }) {
        return Err(ApplicationError::Validation(
            "projection does not match canonical memory mutation".to_owned(),
        ));
    }
    Ok(())
}

fn event_describes_memory(payload: &EventPayload, memory: &MemoryRecord) -> bool {
    let (memory_id, version, compatible_status) = match payload {
        EventPayload::MemoryProposed { memory_id, version } => (
            memory_id,
            version,
            memory.status() == MemoryStatus::Proposed,
        ),
        EventPayload::MemoryConfirmed { memory_id, version }
        | EventPayload::MemoryCreated { memory_id, version }
        | EventPayload::MemoryRevised { memory_id, version } => (
            memory_id,
            version,
            memory.status() == MemoryStatus::Confirmed,
        ),
        EventPayload::MemoryDeleted { memory_id, version } => {
            (memory_id, version, memory.status() == MemoryStatus::Deleted)
        }
        EventPayload::MemorySharedIn {
            target_memory_id,
            target_version,
            ..
        } => (
            target_memory_id,
            target_version,
            memory.status() == MemoryStatus::Confirmed,
        ),
        EventPayload::MemoryShareProposed { .. }
        | EventPayload::MemoryShareApproved { .. }
        | EventPayload::MemoryShareRejected { .. }
        | EventPayload::MemoryShareRevoked { .. }
        | EventPayload::TripCreated { .. }
        | EventPayload::TripRevised { .. }
        | EventPayload::BookingResearchCaptured { .. }
        | EventPayload::ObservationCaptured { .. }
        | EventPayload::ActivityCheckpointed { .. }
        | EventPayload::DisclosureRecorded { .. } => return false,
    };

    compatible_status && memory_id == memory.id() && *version == memory.version()
}

fn encode_scope(scope: &MemoryScope) -> (&'static str, Option<&str>) {
    match scope {
        MemoryScope::Global => ("global", None),
        MemoryScope::Domain { name } => ("domain", Some(name)),
        MemoryScope::Entity { id } => ("entity", Some(id.as_str())),
        MemoryScope::Activity { id } => ("activity", Some(id.as_str())),
    }
}

const fn encode_memory_kind(kind: MemoryKind) -> &'static str {
    match kind {
        MemoryKind::Preference => "preference",
        MemoryKind::Semantic => "semantic",
        MemoryKind::Episodic => "episodic",
        MemoryKind::Procedural => "procedural",
        MemoryKind::Observation => "observation",
        MemoryKind::Working => "working",
    }
}

const fn encode_memory_status(status: MemoryStatus) -> &'static str {
    match status {
        MemoryStatus::Proposed => "proposed",
        MemoryStatus::Confirmed => "confirmed",
        MemoryStatus::Superseded => "superseded",
        MemoryStatus::Deleted => "deleted",
    }
}

const fn encode_evidence_source(source: EvidenceSource) -> &'static str {
    match source {
        EvidenceSource::UserStatement => "user-statement",
        EvidenceSource::AgentObservation => "agent-observation",
        EvidenceSource::ToolResult => "tool-result",
        EvidenceSource::ImportedRecord => "imported-record",
        EvidenceSource::WorkspaceDecision => "workspace-decision",
    }
}

const fn encode_projection_operation(operation: ProjectionOperation) -> &'static str {
    match operation {
        ProjectionOperation::Upsert => "upsert",
        ProjectionOperation::Delete => "delete",
    }
}

const fn encode_projection_status(status: ProjectionStatus) -> &'static str {
    match status {
        ProjectionStatus::Pending => "pending",
        ProjectionStatus::Processing => "processing",
        ProjectionStatus::Completed => "completed",
        ProjectionStatus::Quarantined => "quarantined",
    }
}

fn event_type(event: &CanonicalEvent) -> &'static str {
    match event.payload() {
        rembrane_domain::EventPayload::MemoryProposed { .. } => "memory-proposed",
        rembrane_domain::EventPayload::MemoryConfirmed { .. } => "memory-confirmed",
        rembrane_domain::EventPayload::MemoryCreated { .. } => "memory-created",
        rembrane_domain::EventPayload::MemoryRevised { .. } => "memory-revised",
        rembrane_domain::EventPayload::MemoryDeleted { .. } => "memory-deleted",
        rembrane_domain::EventPayload::MemoryShareProposed { .. } => "memory-share-proposed",
        rembrane_domain::EventPayload::MemoryShareApproved { .. } => "memory-share-approved",
        rembrane_domain::EventPayload::MemoryShareRejected { .. } => "memory-share-rejected",
        rembrane_domain::EventPayload::MemoryShareRevoked { .. } => "memory-share-revoked",
        rembrane_domain::EventPayload::MemorySharedIn { .. } => "memory-shared-in",
        rembrane_domain::EventPayload::TripCreated { .. } => "trip-created",
        rembrane_domain::EventPayload::TripRevised { .. } => "trip-revised",
        rembrane_domain::EventPayload::BookingResearchCaptured { .. } => {
            "booking-research-captured"
        }
        rembrane_domain::EventPayload::ObservationCaptured { .. } => "observation-captured",
        rembrane_domain::EventPayload::ActivityCheckpointed { .. } => "activity-checkpointed",
        rembrane_domain::EventPayload::DisclosureRecorded { .. } => "disclosure-recorded",
    }
}

pub(super) fn to_i64(value: u64) -> Result<i64, ApplicationError> {
    i64::try_from(value)
        .map_err(|_| ApplicationError::Validation("numeric value exceeds SQLite range".to_owned()))
}

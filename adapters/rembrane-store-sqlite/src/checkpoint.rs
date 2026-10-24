use rembrane_application::{ApplicationError, CheckpointMutationRepository, CheckpointRepository};
use rembrane_codec::{decode_checkpoint, encode_checkpoint};
use rembrane_crypto::{EncryptedPayload, EncryptionContext, PayloadPurpose, RecordCipher};
use rembrane_domain::{ActivityCheckpoint, ActivityId, CanonicalEvent, PrincipalId, WorkspaceId};
use rusqlite::{OptionalExtension, Transaction, params};

use crate::canonical::{SealedRecord, insert_event, require_event_sequence, seal_event, to_i64};
use crate::{SqliteStore, map_write_error};

type EncryptedCheckpointRow = (String, i64, Vec<u8>, String, String, Vec<u8>);

impl<C: RecordCipher> CheckpointRepository for SqliteStore<C> {
    fn latest_checkpoint(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
        activity_id: &ActivityId,
    ) -> Result<Option<ActivityCheckpoint>, ApplicationError> {
        let row = self
            .connection
            .query_row(
                "SELECT
                    id,
                    version,
                    checkpoint_ciphertext,
                    encryption_key_id,
                    encryption_algorithm,
                    encryption_nonce
                 FROM activity_checkpoints
                 WHERE workspace_id = ?1
                   AND subject_id = ?2
                   AND activity_id = ?3
                 ORDER BY version DESC
                 LIMIT 1",
                params![
                    workspace_id.as_str(),
                    subject_id.as_str(),
                    activity_id.as_str()
                ],
                encrypted_checkpoint_row,
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?;

        row.map(|row| self.decrypt_checkpoint(workspace_id, subject_id, Some(activity_id), row))
            .transpose()
    }

    fn list_checkpoints_for_subject(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
    ) -> Result<Vec<ActivityCheckpoint>, ApplicationError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT
                    id,
                    version,
                    checkpoint_ciphertext,
                    encryption_key_id,
                    encryption_algorithm,
                    encryption_nonce
                 FROM activity_checkpoints
                 WHERE workspace_id = ?1 AND subject_id = ?2
                 ORDER BY id",
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let rows = statement
            .query_map(
                params![workspace_id.as_str(), subject_id.as_str()],
                encrypted_checkpoint_row,
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let mut checkpoints = Vec::new();
        for row in rows {
            checkpoints.push(self.decrypt_checkpoint(
                workspace_id,
                subject_id,
                None,
                row.map_err(|_| ApplicationError::StorageUnavailable)?,
            )?);
        }
        Ok(checkpoints)
    }
}

impl<C: RecordCipher> SqliteStore<C> {
    fn decrypt_checkpoint(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
        expected_activity_id: Option<&ActivityId>,
        row: EncryptedCheckpointRow,
    ) -> Result<ActivityCheckpoint, ApplicationError> {
        let (checkpoint_id, version, ciphertext, key_id, algorithm, nonce) = row;
        let version = u64::try_from(version).map_err(|_| ApplicationError::StorageUnavailable)?;
        let context = EncryptionContext::new(
            workspace_id.clone(),
            &checkpoint_id,
            version,
            PayloadPurpose::ActivityCheckpoint,
        )
        .map_err(|_| ApplicationError::StorageUnavailable)?;
        let payload = EncryptedPayload::new(ciphertext, key_id, algorithm, nonce)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let plaintext = self
            .cipher
            .open(&context, &payload)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let checkpoint =
            decode_checkpoint(&plaintext).map_err(|_| ApplicationError::StorageUnavailable)?;
        if checkpoint.workspace_id() != workspace_id
            || checkpoint.subject_id() != subject_id
            || checkpoint.id().as_str() != checkpoint_id
            || checkpoint.version() != version
            || expected_activity_id.is_some_and(|expected| checkpoint.activity_id() != expected)
        {
            return Err(ApplicationError::StorageUnavailable);
        }
        Ok(checkpoint)
    }
}

fn encrypted_checkpoint_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EncryptedCheckpointRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

impl<C: RecordCipher> CheckpointMutationRepository for SqliteStore<C> {
    fn insert_checkpoint_with_event(
        &mut self,
        checkpoint: ActivityCheckpoint,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        validate_checkpoint_event(&checkpoint, &event)?;
        let encrypted_checkpoint = seal_checkpoint(&self.cipher, &checkpoint)?;
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
        insert_checkpoint(&transaction, &checkpoint, &encrypted_checkpoint)?;
        insert_event(&transaction, &event, &encrypted_event)?;
        transaction.commit().map_err(map_write_error)
    }

    fn replace_checkpoint_with_event(
        &mut self,
        checkpoint: ActivityCheckpoint,
        expected_checkpoint_version: u64,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        validate_checkpoint_event(&checkpoint, &event)?;
        if checkpoint.version() != expected_checkpoint_version.saturating_add(1) {
            return Err(ApplicationError::VersionConflict);
        }
        let encrypted_checkpoint = seal_checkpoint(&self.cipher, &checkpoint)?;
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
        replace_checkpoint(
            &transaction,
            &checkpoint,
            expected_checkpoint_version,
            &encrypted_checkpoint,
        )?;
        insert_event(&transaction, &event, &encrypted_event)?;
        transaction.commit().map_err(map_write_error)
    }
}

fn seal_checkpoint(
    cipher: &impl RecordCipher,
    checkpoint: &ActivityCheckpoint,
) -> Result<SealedRecord, ApplicationError> {
    let plaintext =
        encode_checkpoint(checkpoint).map_err(|_| ApplicationError::StorageUnavailable)?;
    let context = EncryptionContext::new(
        checkpoint.workspace_id().clone(),
        checkpoint.id().as_str(),
        checkpoint.version(),
        PayloadPurpose::ActivityCheckpoint,
    )
    .map_err(|_| ApplicationError::Validation("invalid checkpoint context".to_owned()))?;
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

fn insert_checkpoint(
    transaction: &Transaction<'_>,
    checkpoint: &ActivityCheckpoint,
    encrypted: &SealedRecord,
) -> Result<(), ApplicationError> {
    transaction
        .execute(
            "INSERT INTO activity_checkpoints (
                workspace_id,
                id,
                subject_id,
                activity_id,
                entity_id,
                checkpoint_ciphertext,
                encryption_key_id,
                encryption_algorithm,
                encryption_nonce,
                version
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                checkpoint.workspace_id().as_str(),
                checkpoint.id().as_str(),
                checkpoint.subject_id().as_str(),
                checkpoint.activity_id().as_str(),
                checkpoint
                    .entity_id()
                    .map(rembrane_domain::EntityId::as_str),
                encrypted.ciphertext,
                encrypted.key_id,
                encrypted.algorithm,
                encrypted.nonce,
                to_i64(checkpoint.version())?
            ],
        )
        .map(|_| ())
        .map_err(map_write_error)
}

fn replace_checkpoint(
    transaction: &Transaction<'_>,
    checkpoint: &ActivityCheckpoint,
    expected_version: u64,
    encrypted: &SealedRecord,
) -> Result<(), ApplicationError> {
    let changed = transaction
        .execute(
            "UPDATE activity_checkpoints
             SET subject_id = ?3,
                 activity_id = ?4,
                 entity_id = ?5,
                 checkpoint_ciphertext = ?6,
                 encryption_key_id = ?7,
                 encryption_algorithm = ?8,
                 encryption_nonce = ?9,
                 version = ?10,
                 updated_at = CURRENT_TIMESTAMP
             WHERE workspace_id = ?1 AND id = ?2 AND version = ?11",
            params![
                checkpoint.workspace_id().as_str(),
                checkpoint.id().as_str(),
                checkpoint.subject_id().as_str(),
                checkpoint.activity_id().as_str(),
                checkpoint
                    .entity_id()
                    .map(rembrane_domain::EntityId::as_str),
                encrypted.ciphertext,
                encrypted.key_id,
                encrypted.algorithm,
                encrypted.nonce,
                to_i64(checkpoint.version())?,
                to_i64(expected_version)?
            ],
        )
        .map_err(map_write_error)?;
    if changed == 0 {
        return Err(ApplicationError::VersionConflict);
    }
    Ok(())
}

fn validate_checkpoint_event(
    checkpoint: &ActivityCheckpoint,
    event: &CanonicalEvent,
) -> Result<(), ApplicationError> {
    if checkpoint.workspace_id() != event.workspace_id()
        || event.subject_id() != Some(checkpoint.subject_id())
    {
        return Err(ApplicationError::Validation(
            "checkpoint and event identity must match".to_owned(),
        ));
    }
    match event.payload() {
        rembrane_domain::EventPayload::ActivityCheckpointed {
            activity_id,
            version,
        } if activity_id == checkpoint.activity_id() && *version == checkpoint.version() => Ok(()),
        _ => Err(ApplicationError::Validation(
            "event does not describe activity checkpoint".to_owned(),
        )),
    }
}

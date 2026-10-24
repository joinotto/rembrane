use rembrane_application::{
    ApplicationError, BookingResearchMutationRepository, BookingResearchRepository,
};
use rembrane_codec::{decode_booking_research, encode_booking_research};
use rembrane_crypto::{EncryptedPayload, EncryptionContext, PayloadPurpose, RecordCipher};
use rembrane_domain::{
    BookingResearch, BookingResearchId, CanonicalEvent, EntityId, EventPayload, WorkspaceId,
};
use rusqlite::{OptionalExtension, Transaction, params};

use crate::canonical::{SealedRecord, insert_event, require_event_sequence, seal_event, to_i64};
use crate::{SqliteStore, map_write_error};

type EncryptedResearchRow = (
    String,
    String,
    String,
    i64,
    Vec<u8>,
    String,
    String,
    Vec<u8>,
);

impl<C: RecordCipher> BookingResearchRepository for SqliteStore<C> {
    fn find_booking_research(
        &self,
        workspace_id: &WorkspaceId,
        research_id: &BookingResearchId,
    ) -> Result<Option<BookingResearch>, ApplicationError> {
        let row = self
            .connection
            .query_row(
                "SELECT
                    id,
                    trip_id,
                    observed_by,
                    version,
                    research_ciphertext,
                    encryption_key_id,
                    encryption_algorithm,
                    encryption_nonce
                 FROM booking_research
                 WHERE workspace_id = ?1 AND id = ?2",
                params![workspace_id.as_str(), research_id.as_str()],
                encrypted_research_row,
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        row.map(|row| self.decrypt_research(workspace_id, Some(research_id), None, row))
            .transpose()
    }

    fn list_booking_research_for_trip(
        &self,
        workspace_id: &WorkspaceId,
        trip_id: &EntityId,
    ) -> Result<Vec<BookingResearch>, ApplicationError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT
                    id,
                    trip_id,
                    observed_by,
                    version,
                    research_ciphertext,
                    encryption_key_id,
                    encryption_algorithm,
                    encryption_nonce
                 FROM booking_research
                 WHERE workspace_id = ?1 AND trip_id = ?2
                 ORDER BY created_at DESC, id",
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let rows = statement
            .query_map(
                params![workspace_id.as_str(), trip_id.as_str()],
                encrypted_research_row,
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let mut research = Vec::new();
        for row in rows {
            research.push(self.decrypt_research(
                workspace_id,
                None,
                Some(trip_id),
                row.map_err(|_| ApplicationError::StorageUnavailable)?,
            )?);
        }
        Ok(research)
    }
}

impl<C: RecordCipher> SqliteStore<C> {
    fn decrypt_research(
        &self,
        workspace_id: &WorkspaceId,
        expected_research_id: Option<&BookingResearchId>,
        expected_trip_id: Option<&EntityId>,
        row: EncryptedResearchRow,
    ) -> Result<BookingResearch, ApplicationError> {
        let (id, trip_id, observed_by, version, ciphertext, key_id, algorithm, nonce) = row;
        let version = u64::try_from(version).map_err(|_| ApplicationError::StorageUnavailable)?;
        let context = EncryptionContext::new(
            workspace_id.clone(),
            &id,
            version,
            PayloadPurpose::BookingResearch,
        )
        .map_err(|_| ApplicationError::StorageUnavailable)?;
        let encrypted = EncryptedPayload::new(ciphertext, key_id, algorithm, nonce)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let plaintext = self
            .cipher
            .open(&context, &encrypted)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let research = decode_booking_research(&plaintext)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        if research.workspace_id() != workspace_id
            || research.id().as_str() != id
            || research.trip_id().as_str() != trip_id
            || research.observed_by().as_str() != observed_by
            || research.version() != version
            || expected_research_id.is_some_and(|expected| research.id() != expected)
            || expected_trip_id.is_some_and(|expected| research.trip_id() != expected)
        {
            return Err(ApplicationError::StorageUnavailable);
        }
        Ok(research)
    }
}

impl<C: RecordCipher> BookingResearchMutationRepository for SqliteStore<C> {
    fn insert_booking_research_with_event(
        &mut self,
        research: BookingResearch,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        validate_research_event(&research, &event)?;
        let encrypted_research = seal_research(&self.cipher, &research)?;
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
        insert_research(&transaction, &research, &encrypted_research)?;
        insert_event(&transaction, &event, &encrypted_event)?;
        transaction.commit().map_err(map_write_error)
    }
}

fn seal_research(
    cipher: &impl RecordCipher,
    research: &BookingResearch,
) -> Result<SealedRecord, ApplicationError> {
    let plaintext =
        encode_booking_research(research).map_err(|_| ApplicationError::StorageUnavailable)?;
    let context = EncryptionContext::new(
        research.workspace_id().clone(),
        research.id().as_str(),
        research.version(),
        PayloadPurpose::BookingResearch,
    )
    .map_err(|_| ApplicationError::Validation("invalid booking research context".to_owned()))?;
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

fn insert_research(
    transaction: &Transaction<'_>,
    research: &BookingResearch,
    encrypted: &SealedRecord,
) -> Result<(), ApplicationError> {
    transaction
        .execute(
            "INSERT INTO booking_research (
                workspace_id,
                id,
                trip_id,
                observed_by,
                research_ciphertext,
                encryption_key_id,
                encryption_algorithm,
                encryption_nonce,
                version
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                research.workspace_id().as_str(),
                research.id().as_str(),
                research.trip_id().as_str(),
                research.observed_by().as_str(),
                encrypted.ciphertext,
                encrypted.key_id,
                encrypted.algorithm,
                encrypted.nonce,
                to_i64(research.version())?
            ],
        )
        .map(|_| ())
        .map_err(map_write_error)
}

fn validate_research_event(
    research: &BookingResearch,
    event: &CanonicalEvent,
) -> Result<(), ApplicationError> {
    let payload_matches = matches!(
        event.payload(),
        EventPayload::BookingResearchCaptured {
            research_id,
            trip_id,
            version,
        } if research_id == research.id()
            && trip_id == research.trip_id()
            && *version == research.version()
    );
    if event.workspace_id() != research.workspace_id()
        || event.subject_id() != Some(research.observed_by())
        || !payload_matches
    {
        return Err(ApplicationError::Validation(
            "event does not describe booking research capture".to_owned(),
        ));
    }
    Ok(())
}

fn encrypted_research_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EncryptedResearchRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

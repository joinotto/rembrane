use rembrane_application::{ApplicationError, TripMutationRepository, TripRepository};
use rembrane_codec::{decode_trip, encode_trip};
use rembrane_crypto::{EncryptedPayload, EncryptionContext, PayloadPurpose, RecordCipher};
use rembrane_domain::{CanonicalEvent, EntityId, EventPayload, PrincipalId, Trip, WorkspaceId};
use rusqlite::{OptionalExtension, Transaction, params};

use crate::canonical::{SealedRecord, insert_event, require_event_sequence, seal_event, to_i64};
use crate::{SqliteStore, is_strict_successor, map_write_error};

type EncryptedTripRow = (String, String, i64, Vec<u8>, String, String, Vec<u8>);

impl<C: RecordCipher> TripRepository for SqliteStore<C> {
    fn find_trip(
        &self,
        workspace_id: &WorkspaceId,
        trip_id: &EntityId,
    ) -> Result<Option<Trip>, ApplicationError> {
        let row = self
            .connection
            .query_row(
                "SELECT
                    id,
                    owner_subject_id,
                    version,
                    trip_ciphertext,
                    encryption_key_id,
                    encryption_algorithm,
                    encryption_nonce
                 FROM trips
                 WHERE workspace_id = ?1 AND id = ?2",
                params![workspace_id.as_str(), trip_id.as_str()],
                encrypted_trip_row,
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?;

        row.map(|row| self.decrypt_trip(workspace_id, Some(trip_id), None, row))
            .transpose()
    }

    fn list_trips_for_owner(
        &self,
        workspace_id: &WorkspaceId,
        owner_subject_id: &PrincipalId,
    ) -> Result<Vec<Trip>, ApplicationError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT
                    id,
                    owner_subject_id,
                    version,
                    trip_ciphertext,
                    encryption_key_id,
                    encryption_algorithm,
                    encryption_nonce
                 FROM trips
                 WHERE workspace_id = ?1 AND owner_subject_id = ?2
                 ORDER BY updated_at DESC, id",
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let rows = statement
            .query_map(
                params![workspace_id.as_str(), owner_subject_id.as_str()],
                encrypted_trip_row,
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let mut trips = Vec::new();
        for row in rows {
            trips.push(self.decrypt_trip(
                workspace_id,
                None,
                Some(owner_subject_id),
                row.map_err(|_| ApplicationError::StorageUnavailable)?,
            )?);
        }
        Ok(trips)
    }
}

impl<C: RecordCipher> SqliteStore<C> {
    fn decrypt_trip(
        &self,
        workspace_id: &WorkspaceId,
        expected_trip_id: Option<&EntityId>,
        expected_owner_subject_id: Option<&PrincipalId>,
        row: EncryptedTripRow,
    ) -> Result<Trip, ApplicationError> {
        let (trip_id, owner_subject_id, version, ciphertext, key_id, algorithm, nonce) = row;
        let version = u64::try_from(version).map_err(|_| ApplicationError::StorageUnavailable)?;
        let context = EncryptionContext::new(
            workspace_id.clone(),
            &trip_id,
            version,
            PayloadPurpose::TripEntity,
        )
        .map_err(|_| ApplicationError::StorageUnavailable)?;
        let payload = EncryptedPayload::new(ciphertext, key_id, algorithm, nonce)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let plaintext = self
            .cipher
            .open(&context, &payload)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let trip = decode_trip(&plaintext).map_err(|_| ApplicationError::StorageUnavailable)?;
        if trip.workspace_id() != workspace_id
            || trip.id().as_str() != trip_id
            || trip.owner_subject_id().as_str() != owner_subject_id
            || trip.version() != version
            || expected_trip_id.is_some_and(|expected| trip.id() != expected)
            || expected_owner_subject_id.is_some_and(|expected| trip.owner_subject_id() != expected)
        {
            return Err(ApplicationError::StorageUnavailable);
        }
        Ok(trip)
    }
}

impl<C: RecordCipher> TripMutationRepository for SqliteStore<C> {
    fn insert_trip_with_event(
        &mut self,
        trip: Trip,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        validate_trip_event(&trip, &event, false)?;
        let encrypted_trip = seal_trip(&self.cipher, &trip)?;
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
        insert_trip(&transaction, &trip, &encrypted_trip)?;
        insert_event(&transaction, &event, &encrypted_event)?;
        transaction.commit().map_err(map_write_error)
    }

    fn replace_trip_with_event(
        &mut self,
        trip: Trip,
        expected_trip_version: u64,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        validate_trip_event(&trip, &event, true)?;
        if !is_strict_successor(expected_trip_version, trip.version()) {
            return Err(ApplicationError::VersionConflict);
        }
        let encrypted_trip = seal_trip(&self.cipher, &trip)?;
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
        replace_trip(&transaction, &trip, expected_trip_version, &encrypted_trip)?;
        insert_event(&transaction, &event, &encrypted_event)?;
        transaction.commit().map_err(map_write_error)
    }
}

fn seal_trip(cipher: &impl RecordCipher, trip: &Trip) -> Result<SealedRecord, ApplicationError> {
    let plaintext = encode_trip(trip).map_err(|_| ApplicationError::StorageUnavailable)?;
    let context = EncryptionContext::new(
        trip.workspace_id().clone(),
        trip.id().as_str(),
        trip.version(),
        PayloadPurpose::TripEntity,
    )
    .map_err(|_| ApplicationError::Validation("invalid trip context".to_owned()))?;
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

fn insert_trip(
    transaction: &Transaction<'_>,
    trip: &Trip,
    encrypted: &SealedRecord,
) -> Result<(), ApplicationError> {
    transaction
        .execute(
            "INSERT INTO trips (
                workspace_id,
                id,
                owner_subject_id,
                trip_ciphertext,
                encryption_key_id,
                encryption_algorithm,
                encryption_nonce,
                version
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                trip.workspace_id().as_str(),
                trip.id().as_str(),
                trip.owner_subject_id().as_str(),
                encrypted.ciphertext,
                encrypted.key_id,
                encrypted.algorithm,
                encrypted.nonce,
                to_i64(trip.version())?
            ],
        )
        .map(|_| ())
        .map_err(map_write_error)
}

fn replace_trip(
    transaction: &Transaction<'_>,
    trip: &Trip,
    expected_version: u64,
    encrypted: &SealedRecord,
) -> Result<(), ApplicationError> {
    let changed = transaction
        .execute(
            "UPDATE trips
             SET trip_ciphertext = ?3,
                 encryption_key_id = ?4,
                 encryption_algorithm = ?5,
                 encryption_nonce = ?6,
                 version = ?7,
                 updated_at = CURRENT_TIMESTAMP
             WHERE workspace_id = ?1
               AND id = ?2
               AND owner_subject_id = ?8
               AND version = ?9",
            params![
                trip.workspace_id().as_str(),
                trip.id().as_str(),
                encrypted.ciphertext,
                encrypted.key_id,
                encrypted.algorithm,
                encrypted.nonce,
                to_i64(trip.version())?,
                trip.owner_subject_id().as_str(),
                to_i64(expected_version)?
            ],
        )
        .map_err(map_write_error)?;
    if changed == 0 {
        return Err(ApplicationError::VersionConflict);
    }
    Ok(())
}

fn validate_trip_event(
    trip: &Trip,
    event: &CanonicalEvent,
    revision: bool,
) -> Result<(), ApplicationError> {
    if trip.workspace_id() != event.workspace_id()
        || event.subject_id() != Some(trip.owner_subject_id())
    {
        return Err(ApplicationError::Validation(
            "trip and event identity must match".to_owned(),
        ));
    }
    let matches_payload = match event.payload() {
        EventPayload::TripCreated { trip_id, version } if !revision => {
            trip_id == trip.id() && *version == trip.version()
        }
        EventPayload::TripRevised { trip_id, version } if revision => {
            trip_id == trip.id() && *version == trip.version()
        }
        _ => false,
    };
    if matches_payload {
        Ok(())
    } else {
        Err(ApplicationError::Validation(
            "event does not describe trip mutation".to_owned(),
        ))
    }
}

fn encrypted_trip_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EncryptedTripRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
    ))
}

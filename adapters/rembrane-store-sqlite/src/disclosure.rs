use rembrane_application::{
    ApplicationError, CheckpointDisclosureRepository, DisclosureRepository,
    TravelDisclosureRepository,
};
use rembrane_domain::{
    CheckpointDisclosureReceipt, DisclosureReceipt, ResearchFreshness, TravelDisclosureReceipt,
};
use rusqlite::{OptionalExtension, params};

use crate::{SqliteStore, map_write_error};

impl<C> DisclosureRepository for SqliteStore<C> {
    fn append(&mut self, receipt: DisclosureReceipt) -> Result<(), ApplicationError> {
        if receipt.purpose.trim().is_empty() {
            return Err(ApplicationError::Validation(
                "disclosure purpose must not be empty".to_owned(),
            ));
        }

        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        transaction
            .execute(
                "INSERT INTO disclosure_receipts (
                    workspace_id,
                    id,
                    context_pack_id,
                    subject_id,
                    client_id,
                    purpose_code
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    receipt.workspace_id.as_str(),
                    receipt.id.as_str(),
                    receipt.context_pack_id.as_str(),
                    receipt.subject_id.as_str(),
                    receipt.client_id.as_str(),
                    receipt.purpose
                ],
            )
            .map_err(map_write_error)?;

        for (ordinal, memory) in receipt.memories.iter().enumerate() {
            let stored_version: Option<i64> = transaction
                .query_row(
                    "SELECT version
                     FROM memories
                     WHERE workspace_id = ?1
                       AND id = ?2
                       AND subject_id = ?3",
                    params![
                        receipt.workspace_id.as_str(),
                        memory.id.as_str(),
                        receipt.subject_id.as_str()
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| ApplicationError::StorageUnavailable)?;
            if stored_version
                != Some(i64::try_from(memory.version).map_err(|_| {
                    ApplicationError::Validation("memory version exceeds SQLite range".to_owned())
                })?)
            {
                return Err(ApplicationError::VersionConflict);
            }

            transaction
                .execute(
                    "INSERT INTO disclosed_memories (
                        workspace_id,
                        disclosure_id,
                        memory_id,
                        memory_version,
                        ordinal
                    ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        receipt.workspace_id.as_str(),
                        receipt.id.as_str(),
                        memory.id.as_str(),
                        i64::try_from(memory.version).map_err(|_| {
                            ApplicationError::Validation(
                                "memory version exceeds SQLite range".to_owned(),
                            )
                        })?,
                        i64::try_from(ordinal).map_err(|_| {
                            ApplicationError::Validation("too many disclosed memories".to_owned())
                        })?
                    ],
                )
                .map_err(map_write_error)?;
        }

        transaction.commit().map_err(map_write_error)
    }
}

impl<C> CheckpointDisclosureRepository for SqliteStore<C> {
    fn append_checkpoint_disclosure(
        &mut self,
        receipt: CheckpointDisclosureReceipt,
    ) -> Result<(), ApplicationError> {
        if receipt.purpose.trim().is_empty() || receipt.checkpoint_version == 0 {
            return Err(ApplicationError::Validation(
                "invalid checkpoint disclosure".to_owned(),
            ));
        }
        let version = i64::try_from(receipt.checkpoint_version).map_err(|_| {
            ApplicationError::Validation("checkpoint version exceeds SQLite range".to_owned())
        })?;
        let stored_version: Option<i64> = self
            .connection
            .query_row(
                "SELECT version
                 FROM activity_checkpoints
                 WHERE workspace_id = ?1
                   AND id = ?2
                   AND subject_id = ?3
                   AND activity_id = ?4",
                params![
                    receipt.workspace_id.as_str(),
                    receipt.checkpoint_id.as_str(),
                    receipt.subject_id.as_str(),
                    receipt.activity_id.as_str()
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        if stored_version != Some(version) {
            return Err(ApplicationError::VersionConflict);
        }

        self.connection
            .execute(
                "INSERT INTO checkpoint_disclosures (
                    workspace_id,
                    id,
                    checkpoint_id,
                    checkpoint_version,
                    activity_id,
                    subject_id,
                    client_id,
                    purpose_code
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    receipt.workspace_id.as_str(),
                    receipt.id.as_str(),
                    receipt.checkpoint_id.as_str(),
                    version,
                    receipt.activity_id.as_str(),
                    receipt.subject_id.as_str(),
                    receipt.client_id.as_str(),
                    receipt.purpose
                ],
            )
            .map(|_| ())
            .map_err(map_write_error)
    }
}

impl<C> TravelDisclosureRepository for SqliteStore<C> {
    #[allow(clippy::too_many_lines)]
    fn append_travel_disclosure(
        &mut self,
        receipt: TravelDisclosureReceipt,
    ) -> Result<(), ApplicationError> {
        if receipt.purpose.trim().is_empty()
            || receipt.trip_version == 0
            || receipt.as_of.trim().is_empty()
            || receipt.research.iter().any(|item| item.version == 0)
        {
            return Err(ApplicationError::Validation(
                "invalid travel disclosure".to_owned(),
            ));
        }
        let trip_version = i64::try_from(receipt.trip_version).map_err(|_| {
            ApplicationError::Validation("trip version exceeds SQLite range".to_owned())
        })?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let stored_trip_version: Option<i64> = transaction
            .query_row(
                "SELECT version
                 FROM trips
                 WHERE workspace_id = ?1
                   AND id = ?2",
                params![receipt.workspace_id.as_str(), receipt.trip_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        if stored_trip_version != Some(trip_version) {
            return Err(ApplicationError::VersionConflict);
        }

        transaction
            .execute(
                "INSERT INTO travel_disclosure_receipts (
                    workspace_id,
                    id,
                    subject_id,
                    client_id,
                    purpose_code,
                    trip_id,
                    trip_version,
                    as_of,
                    source_references_included,
                    sensitive_profile_included
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    receipt.workspace_id.as_str(),
                    receipt.id.as_str(),
                    receipt.subject_id.as_str(),
                    receipt.client_id.as_str(),
                    receipt.purpose,
                    receipt.trip_id.as_str(),
                    trip_version,
                    receipt.as_of,
                    receipt.source_references_included,
                    receipt.sensitive_profile_included
                ],
            )
            .map_err(map_write_error)?;

        for (ordinal, research) in receipt.research.iter().enumerate() {
            let research_version = i64::try_from(research.version).map_err(|_| {
                ApplicationError::Validation(
                    "booking research version exceeds SQLite range".to_owned(),
                )
            })?;
            let stored_research_version: Option<i64> = transaction
                .query_row(
                    "SELECT version
                     FROM booking_research
                     WHERE workspace_id = ?1
                       AND id = ?2
                       AND trip_id = ?3",
                    params![
                        receipt.workspace_id.as_str(),
                        research.id.as_str(),
                        receipt.trip_id.as_str()
                    ],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| ApplicationError::StorageUnavailable)?;
            if stored_research_version != Some(research_version) {
                return Err(ApplicationError::VersionConflict);
            }
            let freshness = match research.freshness {
                ResearchFreshness::Fresh => "fresh",
                ResearchFreshness::Expired => "expired",
            };
            transaction
                .execute(
                    "INSERT INTO disclosed_booking_research (
                        workspace_id,
                        disclosure_id,
                        research_id,
                        research_version,
                        freshness,
                        ordinal
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        receipt.workspace_id.as_str(),
                        receipt.id.as_str(),
                        research.id.as_str(),
                        research_version,
                        freshness,
                        i64::try_from(ordinal).map_err(|_| {
                            ApplicationError::Validation(
                                "too many disclosed booking research records".to_owned(),
                            )
                        })?
                    ],
                )
                .map_err(map_write_error)?;
        }
        transaction.commit().map_err(map_write_error)
    }
}

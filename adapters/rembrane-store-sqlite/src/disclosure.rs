use rembrane_application::{ApplicationError, DisclosureRepository};
use rembrane_domain::DisclosureReceipt;
use rusqlite::{OptionalExtension, params};

use crate::{SqliteStore, map_write_error};

impl<C> DisclosureRepository for SqliteStore<C> {
    fn append(
        &mut self,
        receipt: DisclosureReceipt,
    ) -> Result<(), ApplicationError> {
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
                    ApplicationError::Validation(
                        "memory version exceeds SQLite range".to_owned(),
                    )
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
                            ApplicationError::Validation(
                                "too many disclosed memories".to_owned(),
                            )
                        })?
                    ],
                )
                .map_err(map_write_error)?;
        }

        transaction.commit().map_err(map_write_error)
    }
}

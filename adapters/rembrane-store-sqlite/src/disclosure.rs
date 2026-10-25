use rembrane_application::{
    ApplicationError, CheckpointDisclosureRepository, DisclosureRepository,
    GraphDisclosureRepository, TravelDisclosureRepository,
};
use rembrane_domain::{
    CheckpointDisclosureReceipt, DisclosureReceipt, GraphDisclosureDirection,
    GraphDisclosureReceipt, ResearchFreshness, TravelDisclosureReceipt,
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

impl<C> GraphDisclosureRepository for SqliteStore<C> {
    fn append_graph_disclosure(
        &mut self,
        receipt: GraphDisclosureReceipt,
    ) -> Result<(), ApplicationError> {
        if receipt.purpose.trim().is_empty()
            || receipt.valid_at_epoch_seconds == 0
            || receipt.edges.iter().any(|edge| edge.version == 0)
        {
            return Err(ApplicationError::Validation(
                "invalid graph disclosure".to_owned(),
            ));
        }
        let direction = match receipt.direction {
            GraphDisclosureDirection::Incoming => "incoming",
            GraphDisclosureDirection::Outgoing => "outgoing",
            GraphDisclosureDirection::Both => "both",
        };
        let valid_at = i64::try_from(receipt.valid_at_epoch_seconds).map_err(|_| {
            ApplicationError::Validation(
                "graph disclosure validity time exceeds SQLite range".to_owned(),
            )
        })?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        transaction
            .execute(
                "INSERT INTO graph_disclosure_receipts (
                    workspace_id, id, subject_id, client_id, purpose_code,
                    node_id, direction, valid_at_epoch_seconds
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    receipt.workspace_id.as_str(),
                    receipt.id.as_str(),
                    receipt.subject_id.as_str(),
                    receipt.client_id.as_str(),
                    receipt.purpose,
                    receipt.node_id.as_str(),
                    direction,
                    valid_at
                ],
            )
            .map_err(map_write_error)?;

        for (ordinal, disclosed) in receipt.edges.iter().enumerate() {
            let version = i64::try_from(disclosed.version).map_err(|_| {
                ApplicationError::Validation(
                    "knowledge edge version exceeds SQLite range".to_owned(),
                )
            })?;
            let stored_version: Option<i64> = transaction
                .query_row(
                    "SELECT version FROM knowledge_edges
                     WHERE workspace_id = ?1 AND id = ?2",
                    params![receipt.workspace_id.as_str(), disclosed.id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| ApplicationError::StorageUnavailable)?;
            if stored_version != Some(version) {
                return Err(ApplicationError::VersionConflict);
            }
            transaction
                .execute(
                    "INSERT INTO disclosed_knowledge_edges (
                        workspace_id, disclosure_id, edge_id, edge_version, ordinal
                     ) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        receipt.workspace_id.as_str(),
                        receipt.id.as_str(),
                        disclosed.id.as_str(),
                        version,
                        i64::try_from(ordinal).map_err(|_| {
                            ApplicationError::Validation(
                                "too many disclosed knowledge edges".to_owned(),
                            )
                        })?
                    ],
                )
                .map_err(map_write_error)?;
        }
        transaction.commit().map_err(map_write_error)
    }
}

#[cfg(test)]
mod tests {
    use rembrane_application::{ApplicationError, GraphDisclosureRepository};
    use rembrane_domain::{
        ClientId, DisclosedKnowledgeEdge, DisclosureId, GraphDisclosureDirection,
        GraphDisclosureReceipt, KnowledgeEdgeId, KnowledgeNodeId, PrincipalId, WorkspaceId,
    };
    use rusqlite::params;

    use crate::SqliteStore;

    fn store_with_graph() -> SqliteStore {
        let store = SqliteStore::open_in_memory().expect("store should initialize");
        store
            .connection
            .execute("INSERT INTO principals (id) VALUES ('principal_01')", [])
            .expect("principal should insert");
        store
            .connection
            .execute(
                "INSERT INTO workspaces (id, kind) VALUES ('workspace_01', 'personal')",
                [],
            )
            .expect("workspace should insert");
        for (id, ciphertext) in [("node_project", vec![1_u8]), ("node_rust", vec![2_u8])] {
            store
                .connection
                .execute(
                    "INSERT INTO knowledge_nodes (
                        workspace_id, id, node_ciphertext, encryption_key_id,
                        encryption_algorithm, encryption_nonce, version,
                        valid_from, recorded_at
                     ) VALUES (?1, ?2, ?3, 'key_01', 'xchacha20poly1305',
                               zeroblob(24), 1, 100, 100)",
                    params!["workspace_01", id, ciphertext],
                )
                .expect("node should insert");
        }
        store
            .connection
            .execute(
                "INSERT INTO knowledge_edges (
                    workspace_id, id, source_id, target_id, edge_ciphertext,
                    encryption_key_id, encryption_algorithm, encryption_nonce,
                    version, valid_from, recorded_at
                 ) VALUES (
                    'workspace_01', 'edge_uses', 'node_project', 'node_rust', X'03',
                    'key_01', 'xchacha20poly1305', zeroblob(24), 1, 100, 100
                 )",
                [],
            )
            .expect("edge should insert");
        store
    }

    fn receipt(version: u64) -> GraphDisclosureReceipt {
        GraphDisclosureReceipt {
            id: DisclosureId::new("graph_disclosure_01"),
            workspace_id: WorkspaceId::new("workspace_01"),
            subject_id: PrincipalId::new("principal_01"),
            client_id: ClientId::new("client_01"),
            purpose: "assistant_graph_context".to_owned(),
            node_id: KnowledgeNodeId::new("node_project"),
            direction: GraphDisclosureDirection::Outgoing,
            valid_at_epoch_seconds: 150,
            edges: vec![DisclosedKnowledgeEdge {
                id: KnowledgeEdgeId::new("edge_uses"),
                version,
            }],
        }
    }

    #[test]
    fn persists_exact_graph_disclosure_atomically() {
        let mut store = store_with_graph();
        store
            .append_graph_disclosure(receipt(1))
            .expect("receipt should append");

        let receipt_count: u64 = store
            .connection
            .query_row(
                "SELECT count(*) FROM graph_disclosure_receipts
                 WHERE workspace_id='workspace_01' AND id='graph_disclosure_01'",
                [],
                |row| row.get(0),
            )
            .expect("receipt count should read");
        let edge_count: u64 = store
            .connection
            .query_row(
                "SELECT count(*) FROM disclosed_knowledge_edges
                 WHERE workspace_id='workspace_01'
                   AND disclosure_id='graph_disclosure_01'
                   AND edge_id='edge_uses' AND edge_version=1",
                [],
                |row| row.get(0),
            )
            .expect("edge count should read");
        assert_eq!((receipt_count, edge_count), (1, 1));
    }

    #[test]
    fn stale_edge_revision_rolls_back_receipt() {
        let mut store = store_with_graph();
        assert_eq!(
            store.append_graph_disclosure(receipt(2)),
            Err(ApplicationError::VersionConflict)
        );
        let count: u64 = store
            .connection
            .query_row(
                "SELECT count(*) FROM graph_disclosure_receipts",
                [],
                |row| row.get(0),
            )
            .expect("receipt count should read");
        assert_eq!(count, 0);
    }
}

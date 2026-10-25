use rembrane_application::{
    ApplicationError, CanonicalGraphMutationRepository, KnowledgeDirection,
    KnowledgeGraphMutationRepository, KnowledgeGraphRepository, MAX_KNOWLEDGE_NEIGHBOURS,
};
use rembrane_codec::{
    decode_knowledge_edge, decode_knowledge_node, encode_knowledge_edge, encode_knowledge_node,
};
use rembrane_crypto::{EncryptedPayload, EncryptionContext, PayloadPurpose, RecordCipher};
use rembrane_domain::{
    GraphProjectionJob, GraphProjectionResource, KnowledgeEdge, KnowledgeEdgeId, KnowledgeNode,
    KnowledgeNodeId, ProjectionOperation, ProjectionStatus, WorkspaceId,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::graph_projection::insert_graph_projection;
use crate::{SqliteStore, is_strict_successor, map_write_error};

type EncryptedNodeRow = (String, i64, Vec<u8>, String, String, Vec<u8>);
type EncryptedEdgeRow = (
    String,
    String,
    String,
    Option<String>,
    i64,
    Vec<u8>,
    String,
    String,
    Vec<u8>,
);

impl<C: RecordCipher> KnowledgeGraphRepository for SqliteStore<C> {
    fn find_knowledge_node(
        &self,
        workspace_id: &WorkspaceId,
        node_id: &KnowledgeNodeId,
    ) -> Result<Option<KnowledgeNode>, ApplicationError> {
        let row = self
            .connection
            .query_row(
                "SELECT id, version, node_ciphertext, encryption_key_id,
                        encryption_algorithm, encryption_nonce
                 FROM knowledge_nodes
                 WHERE workspace_id = ?1 AND id = ?2",
                params![workspace_id.as_str(), node_id.as_str()],
                encrypted_node_row,
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        row.map(|row| self.decrypt_node(workspace_id, Some(node_id), row))
            .transpose()
    }

    fn find_knowledge_edge(
        &self,
        workspace_id: &WorkspaceId,
        edge_id: &KnowledgeEdgeId,
    ) -> Result<Option<KnowledgeEdge>, ApplicationError> {
        let row = self
            .connection
            .query_row(
                "SELECT id, source_id, target_id, supersedes_id, version,
                        edge_ciphertext, encryption_key_id,
                        encryption_algorithm, encryption_nonce
                 FROM knowledge_edges
                 WHERE workspace_id = ?1 AND id = ?2",
                params![workspace_id.as_str(), edge_id.as_str()],
                encrypted_edge_row,
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        row.map(|row| self.decrypt_edge(workspace_id, Some(edge_id), row))
            .transpose()
    }

    fn list_neighbour_edges(
        &self,
        workspace_id: &WorkspaceId,
        node_id: &KnowledgeNodeId,
        direction: KnowledgeDirection,
        valid_at_epoch_seconds: u64,
        limit: usize,
    ) -> Result<Vec<KnowledgeEdge>, ApplicationError> {
        if valid_at_epoch_seconds == 0 || limit == 0 || limit > MAX_KNOWLEDGE_NEIGHBOURS {
            return Err(ApplicationError::Validation(
                "knowledge neighbourhood query is outside canonical bounds".to_owned(),
            ));
        }
        if self.find_knowledge_node(workspace_id, node_id)?.is_none() {
            return Err(ApplicationError::NotFound);
        }
        let endpoint_predicate = match direction {
            KnowledgeDirection::Incoming => "target_id = ?2",
            KnowledgeDirection::Outgoing => "source_id = ?2",
            KnowledgeDirection::Both => "(source_id = ?2 OR target_id = ?2)",
        };
        let query = format!(
            "SELECT id, source_id, target_id, supersedes_id, version,
                    edge_ciphertext, encryption_key_id,
                    encryption_algorithm, encryption_nonce
             FROM knowledge_edges
             WHERE workspace_id = ?1
               AND {endpoint_predicate}
               AND valid_from <= ?3
               AND (valid_until IS NULL OR valid_until > ?3)
             ORDER BY valid_from DESC, id
             LIMIT ?4"
        );
        let mut statement = self
            .connection
            .prepare(&query)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let rows = statement
            .query_map(
                params![
                    workspace_id.as_str(),
                    node_id.as_str(),
                    to_i64(valid_at_epoch_seconds)?,
                    i64::try_from(limit).map_err(|_| ApplicationError::StorageUnavailable)?
                ],
                encrypted_edge_row,
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let mut edges = Vec::new();
        for row in rows {
            edges.push(self.decrypt_edge(
                workspace_id,
                None,
                row.map_err(|_| ApplicationError::StorageUnavailable)?,
            )?);
        }
        Ok(edges)
    }
}

impl<C: RecordCipher> KnowledgeGraphMutationRepository for SqliteStore<C> {
    fn insert_knowledge_node(&mut self, node: KnowledgeNode) -> Result<(), ApplicationError> {
        let encrypted = seal_node(&self.cipher, &node)?;
        self.connection
            .execute(
                "INSERT INTO knowledge_nodes (
                    workspace_id, id, node_ciphertext, encryption_key_id,
                    encryption_algorithm, encryption_nonce, version,
                    valid_from, valid_until, recorded_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    node.workspace_id().as_str(),
                    node.id().as_str(),
                    encrypted.ciphertext(),
                    encrypted.key_id(),
                    encrypted.algorithm(),
                    encrypted.nonce(),
                    to_i64(node.version())?,
                    to_i64(node.validity().valid_from_epoch_seconds())?,
                    optional_i64(node.validity().valid_until_epoch_seconds())?,
                    to_i64(node.validity().recorded_at_epoch_seconds())?
                ],
            )
            .map(|_| ())
            .map_err(map_write_error)
    }

    fn replace_knowledge_node(
        &mut self,
        node: KnowledgeNode,
        expected_version: u64,
    ) -> Result<(), ApplicationError> {
        if !is_strict_successor(expected_version, node.version()) {
            return Err(ApplicationError::VersionConflict);
        }
        let encrypted = seal_node(&self.cipher, &node)?;
        let changed = self
            .connection
            .execute(
                "UPDATE knowledge_nodes
                 SET node_ciphertext = ?3,
                     encryption_key_id = ?4,
                     encryption_algorithm = ?5,
                     encryption_nonce = ?6,
                     version = ?7,
                     valid_from = ?8,
                     valid_until = ?9,
                     recorded_at = ?10,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE workspace_id = ?1 AND id = ?2 AND version = ?11",
                params![
                    node.workspace_id().as_str(),
                    node.id().as_str(),
                    encrypted.ciphertext(),
                    encrypted.key_id(),
                    encrypted.algorithm(),
                    encrypted.nonce(),
                    to_i64(node.version())?,
                    to_i64(node.validity().valid_from_epoch_seconds())?,
                    optional_i64(node.validity().valid_until_epoch_seconds())?,
                    to_i64(node.validity().recorded_at_epoch_seconds())?,
                    to_i64(expected_version)?
                ],
            )
            .map_err(map_write_error)?;
        changed_or_conflict(changed)
    }

    fn insert_knowledge_edge(&mut self, edge: KnowledgeEdge) -> Result<(), ApplicationError> {
        self.validate_edge_lineage(&edge, None)?;
        let encrypted = seal_edge(&self.cipher, &edge)?;
        self.connection
            .execute(
                "INSERT INTO knowledge_edges (
                    workspace_id, id, source_id, target_id, supersedes_id,
                    edge_ciphertext, encryption_key_id, encryption_algorithm,
                    encryption_nonce, version, valid_from, valid_until, recorded_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    edge.workspace_id().as_str(),
                    edge.id().as_str(),
                    edge.source_id().as_str(),
                    edge.target_id().as_str(),
                    edge.supersedes().map(KnowledgeEdgeId::as_str),
                    encrypted.ciphertext(),
                    encrypted.key_id(),
                    encrypted.algorithm(),
                    encrypted.nonce(),
                    to_i64(edge.version())?,
                    to_i64(edge.validity().valid_from_epoch_seconds())?,
                    optional_i64(edge.validity().valid_until_epoch_seconds())?,
                    to_i64(edge.validity().recorded_at_epoch_seconds())?
                ],
            )
            .map(|_| ())
            .map_err(map_write_error)
    }

    fn replace_knowledge_edge(
        &mut self,
        edge: KnowledgeEdge,
        expected_version: u64,
    ) -> Result<(), ApplicationError> {
        if !is_strict_successor(expected_version, edge.version()) {
            return Err(ApplicationError::VersionConflict);
        }
        self.validate_edge_lineage(&edge, Some(expected_version))?;
        let encrypted = seal_edge(&self.cipher, &edge)?;
        let changed = self
            .connection
            .execute(
                "UPDATE knowledge_edges
                 SET source_id = ?3,
                     target_id = ?4,
                     supersedes_id = ?5,
                     edge_ciphertext = ?6,
                     encryption_key_id = ?7,
                     encryption_algorithm = ?8,
                     encryption_nonce = ?9,
                     version = ?10,
                     valid_from = ?11,
                     valid_until = ?12,
                     recorded_at = ?13,
                     updated_at = CURRENT_TIMESTAMP
                 WHERE workspace_id = ?1 AND id = ?2 AND version = ?14",
                params![
                    edge.workspace_id().as_str(),
                    edge.id().as_str(),
                    edge.source_id().as_str(),
                    edge.target_id().as_str(),
                    edge.supersedes().map(KnowledgeEdgeId::as_str),
                    encrypted.ciphertext(),
                    encrypted.key_id(),
                    encrypted.algorithm(),
                    encrypted.nonce(),
                    to_i64(edge.version())?,
                    to_i64(edge.validity().valid_from_epoch_seconds())?,
                    optional_i64(edge.validity().valid_until_epoch_seconds())?,
                    to_i64(edge.validity().recorded_at_epoch_seconds())?,
                    to_i64(expected_version)?
                ],
            )
            .map_err(map_write_error)?;
        changed_or_conflict(changed)
    }
}

impl<C: RecordCipher> CanonicalGraphMutationRepository for SqliteStore<C> {
    fn insert_knowledge_node_with_projections(
        &mut self,
        node: KnowledgeNode,
        projections: Vec<GraphProjectionJob>,
    ) -> Result<(), ApplicationError> {
        validate_projection_batch(
            node.workspace_id(),
            &GraphProjectionResource::Node(node.id().clone()),
            node.version(),
            &projections,
        )?;
        let encrypted = seal_node(&self.cipher, &node)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        insert_node(&transaction, &node, &encrypted)?;
        insert_projection_batch(&transaction, &projections)?;
        transaction.commit().map_err(map_write_error)
    }

    fn replace_knowledge_node_with_projections(
        &mut self,
        node: KnowledgeNode,
        expected_version: u64,
        projections: Vec<GraphProjectionJob>,
    ) -> Result<(), ApplicationError> {
        if !is_strict_successor(expected_version, node.version()) {
            return Err(ApplicationError::VersionConflict);
        }
        validate_projection_batch(
            node.workspace_id(),
            &GraphProjectionResource::Node(node.id().clone()),
            node.version(),
            &projections,
        )?;
        let encrypted = seal_node(&self.cipher, &node)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        replace_node(&transaction, &node, expected_version, &encrypted)?;
        insert_projection_batch(&transaction, &projections)?;
        transaction.commit().map_err(map_write_error)
    }

    fn insert_knowledge_edge_with_projections(
        &mut self,
        edge: KnowledgeEdge,
        projections: Vec<GraphProjectionJob>,
    ) -> Result<(), ApplicationError> {
        self.validate_edge_lineage(&edge, None)?;
        validate_projection_batch(
            edge.workspace_id(),
            &GraphProjectionResource::Edge(edge.id().clone()),
            edge.version(),
            &projections,
        )?;
        let encrypted = seal_edge(&self.cipher, &edge)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        insert_edge(&transaction, &edge, &encrypted)?;
        insert_projection_batch(&transaction, &projections)?;
        transaction.commit().map_err(map_write_error)
    }

    fn replace_knowledge_edge_with_projections(
        &mut self,
        edge: KnowledgeEdge,
        expected_version: u64,
        projections: Vec<GraphProjectionJob>,
    ) -> Result<(), ApplicationError> {
        if !is_strict_successor(expected_version, edge.version()) {
            return Err(ApplicationError::VersionConflict);
        }
        self.validate_edge_lineage(&edge, Some(expected_version))?;
        validate_projection_batch(
            edge.workspace_id(),
            &GraphProjectionResource::Edge(edge.id().clone()),
            edge.version(),
            &projections,
        )?;
        let encrypted = seal_edge(&self.cipher, &edge)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        replace_edge(&transaction, &edge, expected_version, &encrypted)?;
        insert_projection_batch(&transaction, &projections)?;
        transaction.commit().map_err(map_write_error)
    }
}

impl<C: RecordCipher> SqliteStore<C> {
    fn decrypt_node(
        &self,
        workspace_id: &WorkspaceId,
        expected_id: Option<&KnowledgeNodeId>,
        row: EncryptedNodeRow,
    ) -> Result<KnowledgeNode, ApplicationError> {
        let (id, version, ciphertext, key_id, algorithm, nonce) = row;
        let version = from_i64(version)?;
        let context = EncryptionContext::new(
            workspace_id.clone(),
            &id,
            version,
            PayloadPurpose::KnowledgeNode,
        )
        .map_err(|_| ApplicationError::StorageUnavailable)?;
        let encrypted = EncryptedPayload::new(ciphertext, key_id, algorithm, nonce)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let plaintext = self
            .cipher
            .open(&context, &encrypted)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let node =
            decode_knowledge_node(&plaintext).map_err(|_| ApplicationError::StorageUnavailable)?;
        if node.workspace_id() != workspace_id
            || node.id().as_str() != id
            || node.version() != version
            || expected_id.is_some_and(|expected| node.id() != expected)
        {
            return Err(ApplicationError::StorageUnavailable);
        }
        Ok(node)
    }

    fn decrypt_edge(
        &self,
        workspace_id: &WorkspaceId,
        expected_id: Option<&KnowledgeEdgeId>,
        row: EncryptedEdgeRow,
    ) -> Result<KnowledgeEdge, ApplicationError> {
        let (
            id,
            source_id,
            target_id,
            supersedes_id,
            version,
            ciphertext,
            key_id,
            algorithm,
            nonce,
        ) = row;
        let version = from_i64(version)?;
        let context = EncryptionContext::new(
            workspace_id.clone(),
            &id,
            version,
            PayloadPurpose::KnowledgeEdge,
        )
        .map_err(|_| ApplicationError::StorageUnavailable)?;
        let encrypted = EncryptedPayload::new(ciphertext, key_id, algorithm, nonce)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let plaintext = self
            .cipher
            .open(&context, &encrypted)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let edge =
            decode_knowledge_edge(&plaintext).map_err(|_| ApplicationError::StorageUnavailable)?;
        if edge.workspace_id() != workspace_id
            || edge.id().as_str() != id
            || edge.source_id().as_str() != source_id
            || edge.target_id().as_str() != target_id
            || edge.supersedes().map(KnowledgeEdgeId::as_str) != supersedes_id.as_deref()
            || edge.version() != version
            || expected_id.is_some_and(|expected| edge.id() != expected)
        {
            return Err(ApplicationError::StorageUnavailable);
        }
        Ok(edge)
    }

    fn validate_edge_lineage(
        &self,
        edge: &KnowledgeEdge,
        expected_version: Option<u64>,
    ) -> Result<(), ApplicationError> {
        if let Some(expected_version) = expected_version {
            let current = self
                .find_knowledge_edge(edge.workspace_id(), edge.id())?
                .ok_or(ApplicationError::NotFound)?;
            if current.version() != expected_version
                || current.source_id() != edge.source_id()
                || current.target_id() != edge.target_id()
                || current.relation() != edge.relation()
            {
                return Err(ApplicationError::VersionConflict);
            }
        }
        if let Some(superseded_id) = edge.supersedes() {
            let superseded = self
                .find_knowledge_edge(edge.workspace_id(), superseded_id)?
                .ok_or_else(|| {
                    ApplicationError::Validation(
                        "superseded knowledge edge must exist in the same workspace".to_owned(),
                    )
                })?;
            if superseded.source_id() != edge.source_id()
                || superseded.target_id() != edge.target_id()
                || superseded.relation() != edge.relation()
            {
                return Err(ApplicationError::Validation(
                    "knowledge edge supersession must preserve endpoints and relation".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

fn seal_node(
    cipher: &impl RecordCipher,
    node: &KnowledgeNode,
) -> Result<EncryptedPayload, ApplicationError> {
    let plaintext =
        encode_knowledge_node(node).map_err(|_| ApplicationError::StorageUnavailable)?;
    seal(
        cipher,
        node.workspace_id(),
        node.id().as_str(),
        node.version(),
        PayloadPurpose::KnowledgeNode,
        &plaintext,
    )
}

fn seal_edge(
    cipher: &impl RecordCipher,
    edge: &KnowledgeEdge,
) -> Result<EncryptedPayload, ApplicationError> {
    let plaintext =
        encode_knowledge_edge(edge).map_err(|_| ApplicationError::StorageUnavailable)?;
    seal(
        cipher,
        edge.workspace_id(),
        edge.id().as_str(),
        edge.version(),
        PayloadPurpose::KnowledgeEdge,
        &plaintext,
    )
}

fn seal(
    cipher: &impl RecordCipher,
    workspace_id: &WorkspaceId,
    id: &str,
    version: u64,
    purpose: PayloadPurpose,
    plaintext: &[u8],
) -> Result<EncryptedPayload, ApplicationError> {
    let context = EncryptionContext::new(workspace_id.clone(), id, version, purpose)
        .map_err(|_| ApplicationError::Validation("invalid knowledge graph context".to_owned()))?;
    cipher
        .seal(&context, plaintext)
        .map_err(|_| ApplicationError::StorageUnavailable)
}

fn validate_projection_batch(
    workspace_id: &WorkspaceId,
    resource: &GraphProjectionResource,
    resource_version: u64,
    projections: &[GraphProjectionJob],
) -> Result<(), ApplicationError> {
    if projections.iter().any(|job| {
        job.workspace_id() != workspace_id
            || job.resource() != resource
            || job.resource_version() != resource_version
            || job.operation() != ProjectionOperation::Upsert
            || job.status() != ProjectionStatus::Pending
            || job.attempts() != 0
    }) {
        return Err(ApplicationError::Validation(
            "graph projection does not describe the canonical mutation".to_owned(),
        ));
    }
    Ok(())
}

fn insert_projection_batch(
    connection: &Connection,
    projections: &[GraphProjectionJob],
) -> Result<(), ApplicationError> {
    for projection in projections {
        insert_graph_projection(connection, projection)?;
    }
    Ok(())
}

fn insert_node(
    connection: &Connection,
    node: &KnowledgeNode,
    encrypted: &EncryptedPayload,
) -> Result<(), ApplicationError> {
    connection
        .execute(
            "INSERT INTO knowledge_nodes (
                workspace_id, id, node_ciphertext, encryption_key_id,
                encryption_algorithm, encryption_nonce, version,
                valid_from, valid_until, recorded_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                node.workspace_id().as_str(),
                node.id().as_str(),
                encrypted.ciphertext(),
                encrypted.key_id(),
                encrypted.algorithm(),
                encrypted.nonce(),
                to_i64(node.version())?,
                to_i64(node.validity().valid_from_epoch_seconds())?,
                optional_i64(node.validity().valid_until_epoch_seconds())?,
                to_i64(node.validity().recorded_at_epoch_seconds())?
            ],
        )
        .map(|_| ())
        .map_err(map_write_error)
}

fn replace_node(
    connection: &Connection,
    node: &KnowledgeNode,
    expected_version: u64,
    encrypted: &EncryptedPayload,
) -> Result<(), ApplicationError> {
    let changed = connection
        .execute(
            "UPDATE knowledge_nodes
             SET node_ciphertext = ?3,
                 encryption_key_id = ?4,
                 encryption_algorithm = ?5,
                 encryption_nonce = ?6,
                 version = ?7,
                 valid_from = ?8,
                 valid_until = ?9,
                 recorded_at = ?10,
                 updated_at = CURRENT_TIMESTAMP
             WHERE workspace_id = ?1 AND id = ?2 AND version = ?11",
            params![
                node.workspace_id().as_str(),
                node.id().as_str(),
                encrypted.ciphertext(),
                encrypted.key_id(),
                encrypted.algorithm(),
                encrypted.nonce(),
                to_i64(node.version())?,
                to_i64(node.validity().valid_from_epoch_seconds())?,
                optional_i64(node.validity().valid_until_epoch_seconds())?,
                to_i64(node.validity().recorded_at_epoch_seconds())?,
                to_i64(expected_version)?
            ],
        )
        .map_err(map_write_error)?;
    changed_or_conflict(changed)
}

fn insert_edge(
    connection: &Connection,
    edge: &KnowledgeEdge,
    encrypted: &EncryptedPayload,
) -> Result<(), ApplicationError> {
    connection
        .execute(
            "INSERT INTO knowledge_edges (
                workspace_id, id, source_id, target_id, supersedes_id,
                edge_ciphertext, encryption_key_id, encryption_algorithm,
                encryption_nonce, version, valid_from, valid_until, recorded_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                edge.workspace_id().as_str(),
                edge.id().as_str(),
                edge.source_id().as_str(),
                edge.target_id().as_str(),
                edge.supersedes().map(KnowledgeEdgeId::as_str),
                encrypted.ciphertext(),
                encrypted.key_id(),
                encrypted.algorithm(),
                encrypted.nonce(),
                to_i64(edge.version())?,
                to_i64(edge.validity().valid_from_epoch_seconds())?,
                optional_i64(edge.validity().valid_until_epoch_seconds())?,
                to_i64(edge.validity().recorded_at_epoch_seconds())?
            ],
        )
        .map(|_| ())
        .map_err(map_write_error)
}

fn replace_edge(
    connection: &Connection,
    edge: &KnowledgeEdge,
    expected_version: u64,
    encrypted: &EncryptedPayload,
) -> Result<(), ApplicationError> {
    let changed = connection
        .execute(
            "UPDATE knowledge_edges
             SET source_id = ?3,
                 target_id = ?4,
                 supersedes_id = ?5,
                 edge_ciphertext = ?6,
                 encryption_key_id = ?7,
                 encryption_algorithm = ?8,
                 encryption_nonce = ?9,
                 version = ?10,
                 valid_from = ?11,
                 valid_until = ?12,
                 recorded_at = ?13,
                 updated_at = CURRENT_TIMESTAMP
             WHERE workspace_id = ?1 AND id = ?2 AND version = ?14",
            params![
                edge.workspace_id().as_str(),
                edge.id().as_str(),
                edge.source_id().as_str(),
                edge.target_id().as_str(),
                edge.supersedes().map(KnowledgeEdgeId::as_str),
                encrypted.ciphertext(),
                encrypted.key_id(),
                encrypted.algorithm(),
                encrypted.nonce(),
                to_i64(edge.version())?,
                to_i64(edge.validity().valid_from_epoch_seconds())?,
                optional_i64(edge.validity().valid_until_epoch_seconds())?,
                to_i64(edge.validity().recorded_at_epoch_seconds())?,
                to_i64(expected_version)?
            ],
        )
        .map_err(map_write_error)?;
    changed_or_conflict(changed)
}

fn encrypted_node_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EncryptedNodeRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
    ))
}

fn encrypted_edge_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EncryptedEdgeRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
    ))
}

fn to_i64(value: u64) -> Result<i64, ApplicationError> {
    i64::try_from(value)
        .map_err(|_| ApplicationError::Validation("integer is too large".to_owned()))
}

fn optional_i64(value: Option<u64>) -> Result<Option<i64>, ApplicationError> {
    value.map(to_i64).transpose()
}

fn from_i64(value: i64) -> Result<u64, ApplicationError> {
    u64::try_from(value).map_err(|_| ApplicationError::StorageUnavailable)
}

fn changed_or_conflict(changed: usize) -> Result<(), ApplicationError> {
    if changed == 0 {
        Err(ApplicationError::VersionConflict)
    } else {
        Ok(())
    }
}

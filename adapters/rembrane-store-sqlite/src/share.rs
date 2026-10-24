use rembrane_application::{ApplicationError, ShareProposalMutationRepository};
use rembrane_crypto::RecordCipher;
use rembrane_domain::{
    CanonicalEvent, EventPayload, MemoryRecord, MemoryShareProposal, MemoryStatus, ProjectionJob,
    ShareProposalStatus,
};
use rusqlite::{OptionalExtension, Transaction, params};

use crate::canonical::{
    insert_event, insert_evidence, insert_memory, insert_projections, require_event_sequence,
    seal_event, seal_memory,
};
use crate::{
    SqliteStore, decrypt_memory_record, encode_memory_scope, encode_share_proposal_status,
    encrypted_memory_row, map_write_error,
};

impl<C: RecordCipher> ShareProposalMutationRepository for SqliteStore<C> {
    fn insert_share_proposal_with_event(
        &mut self,
        proposal: MemoryShareProposal,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        validate_share_proposed_event(&proposal, &event)?;
        let encrypted_event = seal_event(&self.cipher, &event)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        require_exact_source(&transaction, &self.cipher, &proposal)?;
        require_event_sequence(
            &transaction,
            event.workspace_id(),
            event.sequence(),
            expected_previous_sequence,
        )?;
        insert_share_proposal(&transaction, &proposal)?;
        insert_event(&transaction, &event, &encrypted_event)?;
        transaction.commit().map_err(map_write_error)
    }

    fn approve_share_proposal_with_copy(
        &mut self,
        proposal: MemoryShareProposal,
        expected_status: ShareProposalStatus,
        target_memory: MemoryRecord,
        source_event: CanonicalEvent,
        target_event: CanonicalEvent,
        projections: Vec<ProjectionJob>,
        expected_source_sequence: u64,
        expected_target_sequence: u64,
    ) -> Result<(), ApplicationError> {
        if expected_status != ShareProposalStatus::Pending
            || proposal.status() != ShareProposalStatus::Approved
        {
            return Err(ApplicationError::VersionConflict);
        }
        validate_share_approval_events(&proposal, &target_memory, &source_event, &target_event)?;
        validate_projections(&target_memory, &projections)?;

        let encrypted_target = seal_memory(&self.cipher, &target_memory)?;
        let encrypted_source_event = seal_event(&self.cipher, &source_event)?;
        let encrypted_target_event = seal_event(&self.cipher, &target_event)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;

        let source = require_exact_source(&transaction, &self.cipher, &proposal)?;
        validate_shared_copy(&proposal, &source, &target_memory)?;
        require_event_sequence(
            &transaction,
            source_event.workspace_id(),
            source_event.sequence(),
            expected_source_sequence,
        )?;
        require_event_sequence(
            &transaction,
            target_event.workspace_id(),
            target_event.sequence(),
            expected_target_sequence,
        )?;
        replace_share_proposal(&transaction, &proposal, expected_status)?;
        insert_memory(&transaction, &target_memory, &encrypted_target)?;
        insert_evidence(&transaction, &target_memory)?;
        insert_event(&transaction, &source_event, &encrypted_source_event)?;
        insert_event(&transaction, &target_event, &encrypted_target_event)?;
        insert_projections(&transaction, &projections)?;
        transaction.commit().map_err(map_write_error)
    }
}

fn insert_share_proposal(
    transaction: &Transaction<'_>,
    proposal: &MemoryShareProposal,
) -> Result<(), ApplicationError> {
    let (scope_type, scope_value) = encode_memory_scope(proposal.target_scope());
    transaction
        .execute(
            "INSERT INTO memory_share_proposals (
                source_workspace_id, id, source_memory_id,
                source_memory_version, source_subject_id,
                target_workspace_id, target_scope_type, target_scope_value,
                proposed_by, status
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending')",
            params![
                proposal.source_workspace_id().as_str(),
                proposal.id().as_str(),
                proposal.source_memory_id().as_str(),
                proposal.source_memory_version(),
                proposal.source_subject_id().as_str(),
                proposal.target_workspace_id().as_str(),
                scope_type,
                scope_value,
                proposal.proposed_by().as_str()
            ],
        )
        .map(|_| ())
        .map_err(map_write_error)
}

fn replace_share_proposal(
    transaction: &Transaction<'_>,
    proposal: &MemoryShareProposal,
    expected_status: ShareProposalStatus,
) -> Result<(), ApplicationError> {
    let (scope_type, scope_value) = encode_memory_scope(proposal.target_scope());
    let changed = transaction
        .execute(
            "UPDATE memory_share_proposals
             SET status = ?10, updated_at = CURRENT_TIMESTAMP
             WHERE source_workspace_id = ?1 AND id = ?2
               AND source_memory_id = ?3 AND source_memory_version = ?4
               AND source_subject_id = ?5 AND target_workspace_id = ?6
               AND target_scope_type = ?7 AND target_scope_value = ?8
               AND proposed_by = ?9 AND status = ?11",
            params![
                proposal.source_workspace_id().as_str(),
                proposal.id().as_str(),
                proposal.source_memory_id().as_str(),
                proposal.source_memory_version(),
                proposal.source_subject_id().as_str(),
                proposal.target_workspace_id().as_str(),
                scope_type,
                scope_value,
                proposal.proposed_by().as_str(),
                encode_share_proposal_status(proposal.status()),
                encode_share_proposal_status(expected_status)
            ],
        )
        .map_err(map_write_error)?;
    if changed != 1 {
        return Err(ApplicationError::VersionConflict);
    }
    Ok(())
}

fn require_exact_source(
    transaction: &Transaction<'_>,
    cipher: &impl RecordCipher,
    proposal: &MemoryShareProposal,
) -> Result<MemoryRecord, ApplicationError> {
    let encrypted = transaction
        .query_row(
            "SELECT version, content_ciphertext, encryption_key_id,
                    encryption_algorithm, encryption_nonce
             FROM memories
             WHERE workspace_id = ?1 AND id = ?2 AND version = ?3
               AND subject_id = ?4 AND status = 'confirmed'",
            params![
                proposal.source_workspace_id().as_str(),
                proposal.source_memory_id().as_str(),
                proposal.source_memory_version(),
                proposal.source_subject_id().as_str()
            ],
            encrypted_memory_row,
        )
        .optional()
        .map_err(|_| ApplicationError::StorageUnavailable)?;
    let encrypted = encrypted.ok_or(ApplicationError::VersionConflict)?;
    decrypt_memory_record(
        cipher,
        proposal.source_workspace_id(),
        proposal.source_memory_id(),
        encrypted,
    )
}

fn validate_share_proposed_event(
    proposal: &MemoryShareProposal,
    event: &CanonicalEvent,
) -> Result<(), ApplicationError> {
    let valid_payload = matches!(
        event.payload(),
        EventPayload::MemoryShareProposed {
            proposal_id,
            source_memory_id,
            source_version,
            target_workspace_id,
        } if proposal_id == proposal.id()
            && source_memory_id == proposal.source_memory_id()
            && *source_version == proposal.source_memory_version()
            && target_workspace_id == proposal.target_workspace_id()
    );
    if proposal.status() != ShareProposalStatus::Pending
        || event.workspace_id() != proposal.source_workspace_id()
        || event.actor_id() != proposal.proposed_by()
        || event.subject_id() != Some(proposal.source_subject_id())
        || !valid_payload
    {
        return Err(ApplicationError::Validation(
            "event does not describe share proposal creation".to_owned(),
        ));
    }
    Ok(())
}

fn validate_shared_copy(
    proposal: &MemoryShareProposal,
    source: &MemoryRecord,
    target: &MemoryRecord,
) -> Result<(), ApplicationError> {
    let evidence_preserved = target.evidence().len() == source.evidence().len().saturating_add(1)
        && target.evidence().starts_with(source.evidence());
    if target.workspace_id() != proposal.target_workspace_id()
        || target.subject_id() != proposal.source_subject_id()
        || target.scope() != proposal.target_scope()
        || target.kind() != source.kind()
        || target.status() != MemoryStatus::Confirmed
        || target.version() != 1
        || target.content() != source.content()
        || !evidence_preserved
    {
        return Err(ApplicationError::Validation(
            "target memory is not an approved copy of the exact source".to_owned(),
        ));
    }
    Ok(())
}

fn validate_share_approval_events(
    proposal: &MemoryShareProposal,
    target: &MemoryRecord,
    source_event: &CanonicalEvent,
    target_event: &CanonicalEvent,
) -> Result<(), ApplicationError> {
    let source_payload = matches!(
        source_event.payload(),
        EventPayload::MemoryShareApproved {
            proposal_id,
            target_workspace_id,
            target_memory_id,
        } if proposal_id == proposal.id()
            && target_workspace_id == proposal.target_workspace_id()
            && target_memory_id == target.id()
    );
    let target_payload = matches!(
        target_event.payload(),
        EventPayload::MemorySharedIn {
            proposal_id,
            source_workspace_id,
            source_memory_id,
            source_version,
            target_memory_id,
            target_version,
        } if proposal_id == proposal.id()
            && source_workspace_id == proposal.source_workspace_id()
            && source_memory_id == proposal.source_memory_id()
            && *source_version == proposal.source_memory_version()
            && target_memory_id == target.id()
            && *target_version == target.version()
    );
    if source_event.workspace_id() != proposal.source_workspace_id()
        || target_event.workspace_id() != proposal.target_workspace_id()
        || source_event.actor_id() != proposal.source_subject_id()
        || target_event.actor_id() != proposal.source_subject_id()
        || source_event.subject_id() != Some(proposal.source_subject_id())
        || target_event.subject_id() != Some(proposal.source_subject_id())
        || source_event.id() == target_event.id()
        || !source_payload
        || !target_payload
    {
        return Err(ApplicationError::Validation(
            "events do not describe approved memory sharing".to_owned(),
        ));
    }
    Ok(())
}

fn validate_projections(
    target: &MemoryRecord,
    projections: &[ProjectionJob],
) -> Result<(), ApplicationError> {
    if projections.iter().any(|projection| {
        projection.workspace_id() != target.workspace_id()
            || projection.memory_id() != target.id()
            || projection.memory_version() != target.version()
            || projection.status() != rembrane_domain::ProjectionStatus::Pending
            || projection.attempts() != 0
            || projection.operation() != rembrane_domain::ProjectionOperation::Upsert
    }) {
        return Err(ApplicationError::Validation(
            "projection does not match shared target memory".to_owned(),
        ));
    }
    Ok(())
}

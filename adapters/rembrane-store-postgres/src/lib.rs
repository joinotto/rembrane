//! `PostgreSQL` transaction boundary with fail-closed tenant verification.
//!
//! A concrete database driver must create a transaction and transfer ownership
//! of it to [`TenantTransaction::verify`] before executing repository SQL.
//! This crate intentionally contains no connection driver yet.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use rembrane_application::{
    AdministrativeAuditRepository, ApplicationError, CanonicalMutationRepository,
    CheckpointDisclosureRepository, CheckpointMutationRepository, CheckpointRepository,
    DisclosureRepository, EventRepository, InvitationRepository, KeyRotationRepository,
    MAX_ADMINISTRATIVE_AUDIT_PAGE, MAXIMUM_INVITATION_LIST_ITEMS, MemberLifecycleRepository,
    MemberScopeGrantRepository, MembershipRepository, MemoryRepository, ProjectionOutboxRepository,
    RetentionRepository, TripRepository, WorkspaceReadRepository, WorkspaceRepository,
    is_strict_successor,
};
use rembrane_codec::{
    decode_checkpoint, decode_event, decode_memory, decode_trip, encode_checkpoint, encode_event,
    encode_memory,
};
use rembrane_crypto::{EncryptedPayload, EncryptionContext, PayloadPurpose, RecordCipher};
use rembrane_domain::{
    ActivityCheckpoint, ActivityId, AdministrativeAction, AdministrativeAuditEvent,
    AdministrativeAuditEventId, AdministrativeTargetKind, CanonicalEvent,
    CheckpointDisclosureReceipt, DisclosureReceipt, EntityId, EventPayload, EvidenceSource,
    Invitation, InvitationId, InvitationStatus, KeyRotationId, KeyRotationReceipt,
    KeyRotationStatus, LegalHoldId, LegalHoldStatus, MAX_KEY_ROTATION_RECIPIENTS, MemberScopeGrant,
    Membership, MembershipStatus, MemoryId, MemoryKind, MemoryRecord, MemoryScope, MemoryStatus,
    Principal, PrincipalId, ProjectionJob, ProjectionJobId, ProjectionOperation, ProjectionStatus,
    ProviderId, ReadScope, RetentionPeriod, RetentionResource, Trip, Workspace, WorkspaceId,
    WorkspaceKeyRotation, WorkspaceKind, WorkspaceLegalHold, WorkspaceRetentionPolicy,
    WorkspaceRole,
};

pub const SET_TENANT_SQL: &str = "SELECT set_config('rembrane.workspace_id', $1, true);";
pub const READ_TENANT_SQL: &str = "SELECT rembrane.current_workspace_id();";
pub const FIND_WORKSPACE_SQL: &str =
    "SELECT id, kind FROM workspaces WHERE id = $1 ORDER BY id LIMIT 2";
pub const FIND_PRINCIPAL_SQL: &str = "SELECT id FROM principals WHERE id = $1 ORDER BY id LIMIT 2";
pub const FIND_MEMBERSHIP_SQL: &str = "SELECT workspace_id, principal_id, role, status \
    FROM memberships WHERE workspace_id = $1 AND principal_id = $2 \
    ORDER BY workspace_id, principal_id LIMIT 2";
pub const MAX_ACTIVE_MEMBERSHIPS: usize = 10_000;
pub const LIST_ACTIVE_MEMBERSHIPS_SQL: &str = "SELECT workspace_id, principal_id, role, status \
    FROM memberships WHERE workspace_id = $1 AND status = 'active' \
    ORDER BY principal_id LIMIT 10001";
pub const INSERT_MEMBERSHIP_SQL: &str = "INSERT INTO memberships \
    (workspace_id, principal_id, role, status) VALUES ($1, $2, $3, $4)";
pub const REPLACE_MEMBERSHIP_SQL: &str = "UPDATE memberships SET role = $3, status = $4, \
    updated_at = CURRENT_TIMESTAMP WHERE workspace_id = $1 AND principal_id = $2";
pub const FIND_INVITATION_SQL: &str = "SELECT workspace_id, id, invited_principal_id, invited_by, \
    role, status, created_at_epoch_seconds, expires_at_epoch_seconds \
    FROM workspace_invitations WHERE workspace_id = $1 AND id = $2 \
    ORDER BY workspace_id, id LIMIT 2";
pub const LIST_INVITATIONS_SQL: &str = "SELECT workspace_id, id, invited_principal_id, invited_by, \
    role, status, created_at_epoch_seconds, expires_at_epoch_seconds \
    FROM workspace_invitations WHERE workspace_id = $1 \
    ORDER BY created_at_epoch_seconds DESC, id ASC LIMIT $2";
pub const LIST_INVITATIONS_BY_STATUS_SQL: &str = "SELECT workspace_id, id, invited_principal_id, \
    invited_by, role, status, created_at_epoch_seconds, expires_at_epoch_seconds \
    FROM workspace_invitations WHERE workspace_id = $1 AND status = $2 \
    ORDER BY created_at_epoch_seconds DESC, id ASC LIMIT $3";
pub const EXPIRE_PENDING_INVITATION_SQL: &str = "UPDATE workspace_invitations \
    SET status = 'expired', updated_at = CURRENT_TIMESTAMP \
    WHERE workspace_id = $1 AND invited_principal_id = $2 \
    AND status = 'pending' AND expires_at_epoch_seconds <= $3";
pub const INSERT_INVITATION_SQL: &str = "INSERT INTO workspace_invitations \
    (workspace_id, id, invited_principal_id, invited_by, role, status, \
    created_at_epoch_seconds, expires_at_epoch_seconds) \
    VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)";
pub const ACCEPT_INVITATION_SQL: &str = "UPDATE workspace_invitations \
    SET status = 'accepted', updated_at = CURRENT_TIMESTAMP \
    WHERE workspace_id = $1 AND id = $2 AND status = 'pending' \
    AND invited_principal_id = $3 AND role = $4 \
    AND created_at_epoch_seconds = $5 AND expires_at_epoch_seconds = $6";
pub const REPLACE_INVITATION_SQL: &str = "UPDATE workspace_invitations \
    SET status = $6, updated_at = CURRENT_TIMESTAMP \
    WHERE workspace_id = $1 AND id = $2 AND invited_principal_id = $3 \
    AND invited_by = $4 AND role = $5 AND status = $7 \
    AND created_at_epoch_seconds = $8 AND expires_at_epoch_seconds = $9";
pub const INSERT_ADMINISTRATIVE_AUDIT_SQL: &str = "INSERT INTO administrative_audit_events \
    (workspace_id, id, actor_id, action, target_kind, target_id, request_id, \
    occurred_at_epoch_seconds) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
pub const INSERT_PRINCIPAL_SQL: &str = "INSERT INTO principals (id) VALUES ($1)";
pub const INSERT_WORKSPACE_SQL: &str = "INSERT INTO workspaces (id, kind) VALUES ($1, $2)";
pub const FIND_PROVISIONING_PRINCIPAL_SQL: &str =
    "SELECT id FROM principals WHERE id = $1 ORDER BY id LIMIT 2";
pub const LIST_ADMINISTRATIVE_AUDIT_SQL: &str = "SELECT workspace_id, id, actor_id, action, \
    target_kind, target_id, request_id, occurred_at_epoch_seconds \
    FROM administrative_audit_events \
    WHERE workspace_id = $1 AND occurred_at_epoch_seconds > $2 \
    ORDER BY occurred_at_epoch_seconds, id LIMIT $3";
pub const FIND_RETENTION_POLICY_SQL: &str = "SELECT workspace_id, version, \
    COALESCE(user_memory_days, 0) AS user_memory_days, \
    COALESCE(activity_checkpoint_days, 0) AS activity_checkpoint_days, \
    COALESCE(travel_research_days, 0) AS travel_research_days, \
    COALESCE(disclosure_receipt_days, 0) AS disclosure_receipt_days, \
    COALESCE(canonical_event_days, 0) AS canonical_event_days, \
    COALESCE(administrative_audit_days, 0) AS administrative_audit_days \
    FROM workspace_retention_policies WHERE workspace_id = $1 \
    ORDER BY workspace_id LIMIT 2";
pub const INSERT_RETENTION_POLICY_SQL: &str = "INSERT INTO workspace_retention_policies \
    (workspace_id, version, user_memory_days, activity_checkpoint_days, travel_research_days, \
    disclosure_receipt_days, canonical_event_days, administrative_audit_days) \
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
pub const REPLACE_RETENTION_POLICY_SQL: &str = "UPDATE workspace_retention_policies SET \
    version = $2, user_memory_days = $3, activity_checkpoint_days = $4, \
    travel_research_days = $5, disclosure_receipt_days = $6, canonical_event_days = $7, \
    administrative_audit_days = $8 WHERE workspace_id = $1 AND version = $9";
pub const FIND_LEGAL_HOLD_SQL: &str = "SELECT workspace_id, id, placed_by, \
    placed_at_epoch_seconds, status, version, COALESCE(released_by, '') AS released_by, \
    COALESCE(released_at_epoch_seconds, 0) AS released_at_epoch_seconds \
    FROM workspace_legal_holds WHERE workspace_id = $1 AND id = $2 \
    ORDER BY workspace_id, id LIMIT 2";
pub const MAX_ACTIVE_LEGAL_HOLDS: usize = 10_000;
pub const LIST_ACTIVE_LEGAL_HOLDS_SQL: &str = "SELECT workspace_id, id, placed_by, \
    placed_at_epoch_seconds, status, version, COALESCE(released_by, '') AS released_by, \
    COALESCE(released_at_epoch_seconds, 0) AS released_at_epoch_seconds \
    FROM workspace_legal_holds WHERE workspace_id = $1 AND status = 'active' \
    ORDER BY id LIMIT 10001";
pub const INSERT_LEGAL_HOLD_SQL: &str = "INSERT INTO workspace_legal_holds \
    (workspace_id, id, placed_by, placed_at_epoch_seconds, status, version, released_by, \
    released_at_epoch_seconds) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
pub const REPLACE_LEGAL_HOLD_SQL: &str = "UPDATE workspace_legal_holds SET status = $3, \
    version = $4, released_by = $5, released_at_epoch_seconds = $6 \
    WHERE workspace_id = $1 AND id = $2 AND version = $7";
pub const INSERT_MEMBER_SCOPE_GRANT_SQL: &str = "INSERT INTO member_scope_grants \
    (workspace_id, principal_id, scope_type, scope_value) VALUES ($1, $2, $3, $4)";
pub const MAX_MEMBER_SCOPE_GRANTS: usize = 10_000;
pub const LIST_MEMBER_SCOPE_GRANTS_SQL: &str = "SELECT workspace_id, principal_id, \
    scope_type, scope_value FROM member_scope_grants \
    WHERE workspace_id = $1 AND principal_id = $2 \
    ORDER BY scope_type, scope_value LIMIT 10001";
pub const DELETE_MEMBER_SCOPE_GRANT_SQL: &str = "DELETE FROM member_scope_grants \
    WHERE workspace_id = $1 AND principal_id = $2 AND scope_type = $3 AND scope_value = $4";
pub const LATEST_KEY_ROTATION_SQL: &str = "SELECT workspace_id, id, generation, \
    removed_principal_id, requested_by, status, \
    COALESCE(completed_key_id, '') AS completed_key_id, \
    COALESCE(completed_by, '') AS completed_by \
    FROM workspace_key_rotations WHERE workspace_id = $1 \
    ORDER BY generation DESC LIMIT 1";
pub const FIND_KEY_ROTATION_RECEIPT_SQL: &str = "SELECT workspace_id, rotation_id, provider_id, \
    request_id, generation, key_id FROM workspace_key_rotation_receipts \
    WHERE workspace_id = $1 AND rotation_id = $2 \
    ORDER BY workspace_id, rotation_id LIMIT 2";
pub const LIST_KEY_ROTATION_RECIPIENTS_SQL: &str = "SELECT workspace_id, rotation_id, principal_id \
    FROM workspace_key_rotation_recipients \
    WHERE workspace_id = $1 AND rotation_id = $2 \
    ORDER BY principal_id LIMIT 10001";
pub const COMPLETE_KEY_ROTATION_SQL: &str = "UPDATE workspace_key_rotations \
    SET status = 'completed', completed_key_id = $1, completed_by = $2, \
    completed_at = CURRENT_TIMESTAMP WHERE workspace_id = $3 AND id = $4 \
    AND generation = $5 AND status = 'required'";
pub const INSERT_KEY_ROTATION_RECEIPT_SQL: &str = "INSERT INTO workspace_key_rotation_receipts \
    (workspace_id, rotation_id, provider_id, request_id, generation, key_id) \
    VALUES ($1, $2, $3, $4, $5, $6)";
pub const INSERT_KEY_ROTATION_RECIPIENT_SQL: &str = "INSERT INTO workspace_key_rotation_recipients \
    (workspace_id, rotation_id, principal_id) VALUES ($1, $2, $3)";
pub const LOCK_WORKSPACE_FOR_ROTATION_SQL: &str =
    "SELECT id FROM workspaces WHERE id = $1 FOR UPDATE";
pub const NEXT_KEY_ROTATION_GENERATION_SQL: &str = "SELECT COALESCE(MAX(generation), 0) + 1 AS next_generation \
    FROM workspace_key_rotations WHERE workspace_id = $1";
pub const REMOVE_MEMBERSHIP_SQL: &str = "UPDATE memberships \
    SET status = 'removed', updated_at = CURRENT_TIMESTAMP \
    WHERE workspace_id = $1 AND principal_id = $2 AND role = $3 AND status = $4";
pub const DELETE_MEMBER_SCOPE_GRANTS_SQL: &str = "DELETE FROM member_scope_grants \
    WHERE workspace_id = $1 AND principal_id = $2";
pub const INSERT_REQUIRED_KEY_ROTATION_SQL: &str = "INSERT INTO workspace_key_rotations \
    (workspace_id, id, generation, removed_principal_id, requested_by, status) \
    VALUES ($1, $2, $3, $4, $5, 'required')";
pub const FIND_MEMORY_SQL: &str = "SELECT workspace_id, id, subject_id, version, \
    content_ciphertext, encryption_key_id, encryption_algorithm, encryption_nonce \
    FROM memories WHERE workspace_id = $1 AND id = $2 \
    ORDER BY workspace_id, id LIMIT 2";
pub const MAX_SUBJECT_MEMORIES: usize = 10_000;
pub const LIST_SUBJECT_MEMORIES_SQL: &str = "SELECT workspace_id, id, subject_id, version, \
    content_ciphertext, encryption_key_id, encryption_algorithm, encryption_nonce \
    FROM memories WHERE workspace_id = $1 AND subject_id = $2 \
    ORDER BY id LIMIT 10001";
pub const CURRENT_EVENT_SEQUENCE_SQL: &str = "SELECT COALESCE(MAX(sequence), 0) AS current_sequence \
    FROM workspace_events WHERE workspace_id = $1";
pub const INSERT_EVENT_SQL: &str = "INSERT INTO workspace_events \
    (workspace_id, sequence, id, actor_id, subject_id, event_type, payload_ciphertext, \
    encryption_key_id, encryption_algorithm, encryption_nonce) \
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";
pub const MAX_EVENT_STREAM_READ: usize = 10_000;
pub const LIST_EVENTS_SINCE_SQL: &str = "SELECT workspace_id, sequence, id, actor_id, subject_id, \
    event_type, payload_ciphertext, encryption_key_id, encryption_algorithm, encryption_nonce \
    FROM workspace_events WHERE workspace_id = $1 AND sequence > $2 \
    ORDER BY sequence LIMIT 10001";
pub const INSERT_MEMORY_SQL: &str = "INSERT INTO memories \
    (workspace_id, id, subject_id, scope_type, scope_value, kind, status, content_ciphertext, \
    encryption_key_id, encryption_algorithm, encryption_nonce, version) \
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)";
pub const REPLACE_MEMORY_SQL: &str = "UPDATE memories SET subject_id = $3, scope_type = $4, \
    scope_value = $5, kind = $6, status = $7, content_ciphertext = $8, \
    encryption_key_id = $9, encryption_algorithm = $10, encryption_nonce = $11, \
    version = $12, updated_at = CURRENT_TIMESTAMP \
    WHERE workspace_id = $1 AND id = $2 AND version = $13";
pub const DELETE_MEMORY_EVIDENCE_SQL: &str =
    "DELETE FROM memory_evidence WHERE workspace_id = $1 AND memory_id = $2";
pub const INSERT_MEMORY_EVIDENCE_SQL: &str = "INSERT INTO memory_evidence \
    (workspace_id, memory_id, ordinal, evidence_id, source_type) VALUES ($1, $2, $3, $4, $5)";
pub const INSERT_PROJECTION_SQL: &str = "INSERT INTO projection_outbox \
    (id, workspace_id, memory_id, memory_version, provider_id, operation, status, attempts) \
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
pub const MAX_PENDING_PROJECTIONS: usize = 1_000;
pub const LIST_PENDING_PROJECTIONS_SQL: &str = "SELECT id, workspace_id, memory_id, \
    memory_version, provider_id, operation, status, attempts FROM projection_outbox \
    WHERE workspace_id = $1 AND provider_id = $2 AND status = 'pending' \
    AND available_at <= CURRENT_TIMESTAMP ORDER BY available_at, id LIMIT $3";
pub const REPLACE_PROJECTION_SQL: &str = "UPDATE projection_outbox \
    SET status = $2, attempts = $3, updated_at = CURRENT_TIMESTAMP \
    WHERE id = $1 AND workspace_id = $4 AND memory_id = $5 AND memory_version = $6 \
    AND provider_id = $7 AND operation = $8 AND status = $9 AND attempts = $10";
pub const FIND_PROJECTION_SQL: &str = "SELECT id, workspace_id, memory_id, memory_version, \
    provider_id, operation, status, attempts FROM projection_outbox \
    WHERE workspace_id = $1 AND id = $2 ORDER BY workspace_id, id LIMIT 2";
pub const INSERT_DISCLOSURE_SQL: &str = "INSERT INTO disclosure_receipts \
    (workspace_id, id, context_pack_id, subject_id, client_id, purpose_code) \
    VALUES ($1, $2, $3, $4, $5, $6)";
pub const FIND_DISCLOSED_MEMORY_VERSION_SQL: &str = "SELECT workspace_id, id, subject_id, version \
    FROM memories WHERE workspace_id = $1 AND id = $2 AND subject_id = $3 \
    ORDER BY workspace_id, id LIMIT 2";
pub const INSERT_DISCLOSED_MEMORY_SQL: &str = "INSERT INTO disclosed_memories \
    (workspace_id, disclosure_id, memory_id, memory_version, ordinal) \
    VALUES ($1, $2, $3, $4, $5)";
pub const LATEST_CHECKPOINT_SQL: &str = "SELECT workspace_id, id, subject_id, activity_id, version, \
    checkpoint_ciphertext, encryption_key_id, encryption_algorithm, encryption_nonce \
    FROM activity_checkpoints WHERE workspace_id = $1 AND subject_id = $2 AND activity_id = $3 \
    ORDER BY version DESC LIMIT 1";
pub const MAX_SUBJECT_CHECKPOINTS: usize = 10_000;
pub const LIST_SUBJECT_CHECKPOINTS_SQL: &str = "SELECT workspace_id, id, subject_id, activity_id, \
    version, checkpoint_ciphertext, encryption_key_id, encryption_algorithm, encryption_nonce \
    FROM activity_checkpoints WHERE workspace_id = $1 AND subject_id = $2 \
    ORDER BY id LIMIT 10001";
pub const INSERT_CHECKPOINT_SQL: &str = "INSERT INTO activity_checkpoints \
    (workspace_id, id, subject_id, activity_id, entity_id, checkpoint_ciphertext, \
    encryption_key_id, encryption_algorithm, encryption_nonce, version) \
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";
pub const REPLACE_CHECKPOINT_SQL: &str = "UPDATE activity_checkpoints SET subject_id = $3, \
    activity_id = $4, entity_id = $5, checkpoint_ciphertext = $6, encryption_key_id = $7, \
    encryption_algorithm = $8, encryption_nonce = $9, version = $10, \
    updated_at = CURRENT_TIMESTAMP WHERE workspace_id = $1 AND id = $2 AND version = $11";
pub const FIND_DISCLOSED_CHECKPOINT_VERSION_SQL: &str = "SELECT workspace_id, id, subject_id, \
    activity_id, version FROM activity_checkpoints WHERE workspace_id = $1 AND id = $2 \
    AND subject_id = $3 AND activity_id = $4 ORDER BY workspace_id, id LIMIT 2";
pub const INSERT_CHECKPOINT_DISCLOSURE_SQL: &str = "INSERT INTO checkpoint_disclosures \
    (workspace_id, id, checkpoint_id, checkpoint_version, activity_id, subject_id, client_id, \
    purpose_code) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";
pub const FIND_TRIP_SQL: &str = "SELECT workspace_id, id, owner_subject_id, version, \
    trip_ciphertext, encryption_key_id, encryption_algorithm, encryption_nonce FROM trips \
    WHERE workspace_id = $1 AND id = $2 ORDER BY workspace_id, id LIMIT 2";
pub const MAX_OWNER_TRIPS: usize = 10_000;
pub const LIST_OWNER_TRIPS_SQL: &str = "SELECT workspace_id, id, owner_subject_id, version, \
    trip_ciphertext, encryption_key_id, encryption_algorithm, encryption_nonce FROM trips \
    WHERE workspace_id = $1 AND owner_subject_id = $2 \
    ORDER BY updated_at DESC, id LIMIT 10001";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresParameter<'value> {
    Text(&'value str),
    OptionalText(Option<&'value str>),
    I64(i64),
    OptionalI64(Option<i64>),
    Bytes(&'value [u8]),
}

pub trait PostgresRow {
    type Error;

    fn text(&self, column: &str) -> Result<String, Self::Error>;

    fn u64(&self, column: &str) -> Result<u64, Self::Error>;

    fn bytes(&self, column: &str) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresFailureKind {
    UniqueViolation,
    ForeignKeyViolation,
    CheckViolation,
    SerializationFailure,
    Other,
}

/// Driver errors implement this without exposing SQL text, parameter values,
/// credentials, or tenant identifiers through application errors.
pub trait ClassifiedPostgresError {
    fn kind(&self) -> PostgresFailureKind;
}

/// Minimal transaction surface required by the tenant-verifying adapter.
///
/// Implementations must represent a database transaction, not a pooled
/// connection. Dropping or explicitly rolling back the value must release all
/// transaction-local `PostgreSQL` settings before the connection is reused.
pub trait PostgresTransaction {
    type Error;
    type Row;

    fn execute(
        &mut self,
        statement: &str,
        parameters: &[PostgresParameter<'_>],
    ) -> Result<u64, Self::Error>;

    fn query(
        &mut self,
        statement: &str,
        parameters: &[PostgresParameter<'_>],
    ) -> Result<Vec<Self::Row>, Self::Error>;

    fn query_optional_text(
        &mut self,
        statement: &str,
        parameters: &[PostgresParameter<'_>],
    ) -> Result<Option<String>, Self::Error>;

    fn commit(self) -> Result<(), Self::Error>;

    fn rollback(self) -> Result<(), Self::Error>;
}

/// Connection-pool boundary used by repository operations.
///
/// Each call must return a newly begun database transaction. It must not apply
/// tenant identity through connection startup parameters or session-global
/// settings.
pub trait PostgresPool {
    type Error;
    type Transaction: PostgresTransaction<Error = Self::Error>;

    fn begin(&self) -> Result<Self::Transaction, Self::Error>;
}

/// Deliberately separate pool for the narrow control-plane operations that
/// create a workspace's first rows before tenant RLS can authorize them.
///
/// Implementations must use credentials distinct from the ordinary runtime
/// pool. Those credentials may provision principals, workspaces, and initial
/// owner memberships, but must not be exposed to request-serving code.
pub trait PostgresProvisioningPool {
    type Error;
    type Transaction: PostgresTransaction<Error = Self::Error>;

    fn begin_provisioning(&self) -> Result<Self::Transaction, Self::Error>;
}

/// Rollback-on-drop guard for one privileged provisioning transaction.
pub struct ProvisioningTransaction<Transaction: PostgresTransaction> {
    transaction: Option<Transaction>,
}

pub struct PostgresProvisioner<Pool> {
    pool: Pool,
}

pub struct PostgresWorkspaceAdminStore<RuntimePool, ProvisioningPool> {
    runtime: PostgresStore<RuntimePool>,
    provisioner: PostgresProvisioner<ProvisioningPool>,
    workspace_id: WorkspaceId,
}

impl<RuntimePool, ProvisioningPool> PostgresWorkspaceAdminStore<RuntimePool, ProvisioningPool> {
    #[must_use]
    pub const fn new(
        runtime: PostgresStore<RuntimePool>,
        provisioner: PostgresProvisioner<ProvisioningPool>,
        workspace_id: WorkspaceId,
    ) -> Self {
        Self {
            runtime,
            provisioner,
            workspace_id,
        }
    }
}

impl<Pool> PostgresProvisioner<Pool>
where
    Pool: PostgresProvisioningPool,
{
    #[must_use]
    pub const fn new(pool: Pool) -> Self {
        Self { pool }
    }

    pub fn initialize_personal_workspace(
        &self,
        principal: &Principal,
        workspace: &Workspace,
        owner_membership: &Membership,
    ) -> Result<(), PostgresStoreError<Pool::Error>> {
        if !valid_personal_bootstrap(principal, workspace, owner_membership) {
            return Err(PostgresStoreError::InvalidInput);
        }
        let mut transaction =
            ProvisioningTransaction::begin(&self.pool).map_err(PostgresStoreError::Begin)?;
        provisioning_execute_exactly_one(
            &mut transaction,
            INSERT_PRINCIPAL_SQL,
            &[PostgresParameter::Text(principal.id().as_str())],
        )?;
        provisioning_execute_exactly_one(
            &mut transaction,
            INSERT_WORKSPACE_SQL,
            &[
                PostgresParameter::Text(workspace.id().as_str()),
                PostgresParameter::Text("personal"),
            ],
        )?;
        provisioning_execute_exactly_one(
            &mut transaction,
            INSERT_MEMBERSHIP_SQL,
            &[
                PostgresParameter::Text(owner_membership.workspace_id().as_str()),
                PostgresParameter::Text(owner_membership.principal_id().as_str()),
                PostgresParameter::Text("owner"),
                PostgresParameter::Text("active"),
            ],
        )?;
        transaction.commit().map_err(PostgresStoreError::Tenant)
    }

    pub fn initialize_shared_workspace(
        &self,
        workspace: &Workspace,
        owner_membership: &Membership,
    ) -> Result<(), PostgresStoreError<Pool::Error>> {
        if !valid_shared_bootstrap(workspace, owner_membership) {
            return Err(PostgresStoreError::InvalidInput);
        }
        let mut transaction =
            ProvisioningTransaction::begin(&self.pool).map_err(PostgresStoreError::Begin)?;
        let principal_id = transaction
            .query_optional_text(
                FIND_PROVISIONING_PRINCIPAL_SQL,
                &[PostgresParameter::Text(
                    owner_membership.principal_id().as_str(),
                )],
            )
            .map_err(PostgresStoreError::Tenant)?;
        match principal_id {
            Some(id) if id == owner_membership.principal_id().as_str() => {}
            Some(_) => return Err(PostgresStoreError::InvalidRow),
            None => return Err(PostgresStoreError::MissingRow),
        }
        provisioning_execute_exactly_one(
            &mut transaction,
            INSERT_WORKSPACE_SQL,
            &[
                PostgresParameter::Text(workspace.id().as_str()),
                PostgresParameter::Text("shared"),
            ],
        )?;
        provisioning_execute_exactly_one(
            &mut transaction,
            INSERT_MEMBERSHIP_SQL,
            &[
                PostgresParameter::Text(owner_membership.workspace_id().as_str()),
                PostgresParameter::Text(owner_membership.principal_id().as_str()),
                PostgresParameter::Text("owner"),
                PostgresParameter::Text("active"),
            ],
        )?;
        transaction.commit().map_err(PostgresStoreError::Tenant)
    }

    pub fn find_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Option<Principal>, PostgresStoreError<Pool::Error>> {
        let mut transaction =
            ProvisioningTransaction::begin(&self.pool).map_err(PostgresStoreError::Begin)?;
        let returned_id = transaction
            .query_optional_text(
                FIND_PROVISIONING_PRINCIPAL_SQL,
                &[PostgresParameter::Text(principal_id.as_str())],
            )
            .map_err(PostgresStoreError::Tenant)?;
        let principal = match returned_id {
            Some(id) if id == principal_id.as_str() => Some(Principal::new(PrincipalId::new(id))),
            Some(_) => return Err(PostgresStoreError::InvalidRow),
            None => None,
        };
        transaction.commit().map_err(PostgresStoreError::Tenant)?;
        Ok(principal)
    }
}

impl<Transaction: PostgresTransaction> ProvisioningTransaction<Transaction> {
    pub fn begin<Pool>(pool: &Pool) -> Result<Self, Transaction::Error>
    where
        Pool: PostgresProvisioningPool<Error = Transaction::Error, Transaction = Transaction>,
    {
        pool.begin_provisioning().map(|transaction| Self {
            transaction: Some(transaction),
        })
    }

    pub fn execute(
        &mut self,
        statement: &str,
        parameters: &[PostgresParameter<'_>],
    ) -> Result<u64, TenantTransactionError<Transaction::Error>> {
        self.transaction_mut()?
            .execute(statement, parameters)
            .map_err(TenantTransactionError::Driver)
    }

    pub fn query_optional_text(
        &mut self,
        statement: &str,
        parameters: &[PostgresParameter<'_>],
    ) -> Result<Option<String>, TenantTransactionError<Transaction::Error>> {
        self.transaction_mut()?
            .query_optional_text(statement, parameters)
            .map_err(TenantTransactionError::Driver)
    }

    pub fn commit(mut self) -> Result<(), TenantTransactionError<Transaction::Error>> {
        self.take_transaction()?
            .commit()
            .map_err(TenantTransactionError::Driver)
    }

    pub fn rollback(mut self) -> Result<(), TenantTransactionError<Transaction::Error>> {
        self.take_transaction()?
            .rollback()
            .map_err(TenantTransactionError::Driver)
    }

    fn transaction_mut(
        &mut self,
    ) -> Result<&mut Transaction, TenantTransactionError<Transaction::Error>> {
        self.transaction
            .as_mut()
            .ok_or(TenantTransactionError::Closed)
    }

    fn take_transaction(
        &mut self,
    ) -> Result<Transaction, TenantTransactionError<Transaction::Error>> {
        self.transaction
            .take()
            .ok_or(TenantTransactionError::Closed)
    }
}

impl<Transaction: PostgresTransaction> Drop for ProvisioningTransaction<Transaction> {
    fn drop(&mut self) {
        if let Some(transaction) = self.transaction.take() {
            let _ = transaction.rollback();
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum TenantTransactionError<DriverError> {
    Driver(DriverError),
    MissingTenant,
    TenantMismatch,
    Closed,
}

impl<DriverError: Display> Display for TenantTransactionError<DriverError> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Driver(error) => write!(formatter, "PostgreSQL transaction failed: {error}"),
            Self::MissingTenant => {
                formatter.write_str("PostgreSQL tenant context was not established")
            }
            Self::TenantMismatch => formatter
                .write_str("PostgreSQL tenant context did not match the requested workspace"),
            Self::Closed => formatter.write_str("PostgreSQL tenant transaction is closed"),
        }
    }
}

impl<DriverError> Error for TenantTransactionError<DriverError> where DriverError: Error + 'static {}

#[derive(Debug, Eq, PartialEq)]
pub enum PostgresStoreError<DriverError> {
    Begin(DriverError),
    Tenant(TenantTransactionError<DriverError>),
    Row(DriverError),
    InvalidRow,
    InvalidInput,
    InvalidLimit,
    MissingRow,
    VersionConflict,
    UnexpectedCardinality,
}

impl<DriverError: Display> Display for PostgresStoreError<DriverError> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Begin(error) => {
                write!(formatter, "could not begin PostgreSQL transaction: {error}")
            }
            Self::Tenant(error) => Display::fmt(error, formatter),
            Self::Row(error) => write!(formatter, "could not decode PostgreSQL row: {error}"),
            Self::InvalidRow => formatter.write_str("PostgreSQL returned an invalid canonical row"),
            Self::InvalidInput => formatter.write_str("PostgreSQL mutation input is invalid"),
            Self::InvalidLimit => formatter.write_str("PostgreSQL query limit is invalid"),
            Self::MissingRow => formatter.write_str("PostgreSQL row was not found"),
            Self::VersionConflict => formatter.write_str("PostgreSQL row version changed"),
            Self::UnexpectedCardinality => {
                formatter.write_str("PostgreSQL returned unexpected row cardinality")
            }
        }
    }
}

impl<DriverError> Error for PostgresStoreError<DriverError> where DriverError: Error + 'static {}

/// Driver-neutral store root that creates one verified tenant transaction per
/// repository operation.
pub struct PostgresStore<Pool> {
    pool: Pool,
}

/// Application-facing view that pins every repository call to one canonical
/// workspace before a database transaction can begin.
pub struct PostgresTenantStore<'store, Pool> {
    store: &'store PostgresStore<Pool>,
    workspace_id: WorkspaceId,
}

/// Tenant-pinned memory view with explicit access to an operator-selected
/// record cipher. Administrative repository facades never receive this key
/// capability.
pub struct PostgresTenantMemoryStore<'store, 'cipher, Pool, Cipher> {
    store: &'store PostgresStore<Pool>,
    cipher: &'cipher Cipher,
    workspace_id: WorkspaceId,
}

impl<Pool: PostgresPool> PostgresStore<Pool> {
    #[must_use]
    pub const fn new(pool: Pool) -> Self {
        Self { pool }
    }

    #[must_use]
    pub fn for_workspace(&self, workspace_id: WorkspaceId) -> PostgresTenantStore<'_, Pool> {
        PostgresTenantStore {
            store: self,
            workspace_id,
        }
    }

    pub fn begin_tenant(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<TenantTransaction<Pool::Transaction>, PostgresStoreError<Pool::Error>> {
        let transaction = self.pool.begin().map_err(PostgresStoreError::Begin)?;
        TenantTransaction::verify(transaction, workspace_id).map_err(PostgresStoreError::Tenant)
    }

    pub fn find_workspace(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<Workspace>, PostgresStoreError<Pool::Error>>
    where
        <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    {
        let mut transaction = self.begin_tenant(workspace_id.clone())?;
        let rows = transaction
            .query(
                FIND_WORKSPACE_SQL,
                &[PostgresParameter::Text(workspace_id.as_str())],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if rows.len() > 1 {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        let workspace = rows
            .first()
            .map(|row| decode_workspace(row, workspace_id))
            .transpose()?;
        transaction.commit().map_err(PostgresStoreError::Tenant)?;
        Ok(workspace)
    }

    pub fn find_principal(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Option<Principal>, PostgresStoreError<Pool::Error>>
    where
        <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    {
        let mut transaction = self.begin_tenant(workspace_id.clone())?;
        let rows = transaction
            .query(
                FIND_PRINCIPAL_SQL,
                &[PostgresParameter::Text(principal_id.as_str())],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if rows.len() > 1 {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        let principal = rows
            .first()
            .map(|row| decode_principal(row, principal_id))
            .transpose()?;
        transaction.commit().map_err(PostgresStoreError::Tenant)?;
        Ok(principal)
    }

    pub fn find_membership(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Option<Membership>, PostgresStoreError<Pool::Error>>
    where
        <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    {
        let mut transaction = self.begin_tenant(workspace_id.clone())?;
        let rows = transaction
            .query(
                FIND_MEMBERSHIP_SQL,
                &[
                    PostgresParameter::Text(workspace_id.as_str()),
                    PostgresParameter::Text(principal_id.as_str()),
                ],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if rows.len() > 1 {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        let membership = rows
            .first()
            .map(|row| decode_membership(row, workspace_id, principal_id))
            .transpose()?;
        transaction.commit().map_err(PostgresStoreError::Tenant)?;
        Ok(membership)
    }

    pub fn list_active_memberships(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<Membership>, PostgresStoreError<Pool::Error>>
    where
        <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    {
        let mut transaction = self.begin_tenant(workspace_id.clone())?;
        let rows = transaction
            .query(
                LIST_ACTIVE_MEMBERSHIPS_SQL,
                &[PostgresParameter::Text(workspace_id.as_str())],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if rows.len() > MAX_ACTIVE_MEMBERSHIPS {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        let mut principal_ids = BTreeSet::new();
        let memberships = rows
            .iter()
            .map(|row| {
                let principal_id = row.text("principal_id").map_err(PostgresStoreError::Row)?;
                if !principal_ids.insert(principal_id.clone()) {
                    return Err(PostgresStoreError::InvalidRow);
                }
                decode_membership(row, workspace_id, &PrincipalId::new(principal_id))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if memberships.iter().any(|membership| !membership.is_active()) {
            return Err(PostgresStoreError::InvalidRow);
        }
        transaction.commit().map_err(PostgresStoreError::Tenant)?;
        Ok(memberships)
    }

    pub fn insert_membership(
        &self,
        membership: &Membership,
    ) -> Result<(), PostgresStoreError<Pool::Error>> {
        self.write_membership(INSERT_MEMBERSHIP_SQL, membership, false)
    }

    pub fn replace_membership(
        &self,
        membership: &Membership,
    ) -> Result<(), PostgresStoreError<Pool::Error>> {
        self.write_membership(REPLACE_MEMBERSHIP_SQL, membership, true)
    }

    fn write_membership(
        &self,
        statement: &str,
        membership: &Membership,
        missing_is_not_found: bool,
    ) -> Result<(), PostgresStoreError<Pool::Error>> {
        let mut transaction = self.begin_tenant(membership.workspace_id().clone())?;
        let changed = transaction
            .execute(
                statement,
                &[
                    PostgresParameter::Text(membership.workspace_id().as_str()),
                    PostgresParameter::Text(membership.principal_id().as_str()),
                    PostgresParameter::Text(membership_role_name(membership.role())),
                    PostgresParameter::Text(membership_status_name(membership)),
                ],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if changed == 0 && missing_is_not_found {
            return Err(PostgresStoreError::MissingRow);
        }
        if changed != 1 {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        transaction.commit().map_err(PostgresStoreError::Tenant)
    }

    pub fn find_invitation(
        &self,
        workspace_id: &WorkspaceId,
        invitation_id: &InvitationId,
    ) -> Result<Option<Invitation>, PostgresStoreError<Pool::Error>>
    where
        <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    {
        let mut transaction = self.begin_tenant(workspace_id.clone())?;
        let rows = transaction
            .query(
                FIND_INVITATION_SQL,
                &[
                    PostgresParameter::Text(workspace_id.as_str()),
                    PostgresParameter::Text(invitation_id.as_str()),
                ],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if rows.len() > 1 {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        let invitation = rows
            .first()
            .map(|row| decode_invitation(row, workspace_id, Some(invitation_id)))
            .transpose()?;
        transaction.commit().map_err(PostgresStoreError::Tenant)?;
        Ok(invitation)
    }

    pub fn list_invitations(
        &self,
        workspace_id: &WorkspaceId,
        status: Option<InvitationStatus>,
        limit: usize,
    ) -> Result<Vec<Invitation>, PostgresStoreError<Pool::Error>>
    where
        <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    {
        if !(1..=MAXIMUM_INVITATION_LIST_ITEMS).contains(&limit) {
            return Err(PostgresStoreError::InvalidLimit);
        }
        let maximum_rows = limit;
        let mut transaction = self.begin_tenant(workspace_id.clone())?;
        let limit = i64::try_from(limit).map_err(|_| PostgresStoreError::InvalidLimit)?;
        let (statement, parameters) = status.map_or_else(
            || {
                (
                    LIST_INVITATIONS_SQL,
                    vec![
                        PostgresParameter::Text(workspace_id.as_str()),
                        PostgresParameter::I64(limit),
                    ],
                )
            },
            |status| {
                (
                    LIST_INVITATIONS_BY_STATUS_SQL,
                    vec![
                        PostgresParameter::Text(workspace_id.as_str()),
                        PostgresParameter::Text(invitation_status_name(status)),
                        PostgresParameter::I64(limit),
                    ],
                )
            },
        );
        let rows = transaction
            .query(statement, &parameters)
            .map_err(PostgresStoreError::Tenant)?;
        if rows.len() > maximum_rows {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        let invitations = rows
            .iter()
            .map(|row| decode_invitation(row, workspace_id, None))
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().map_err(PostgresStoreError::Tenant)?;
        Ok(invitations)
    }

    pub fn insert_invitation_replacing_expired(
        &self,
        invitation: &Invitation,
        audit_event: &AdministrativeAuditEvent,
    ) -> Result<(), PostgresStoreError<Pool::Error>> {
        if invitation.status() != InvitationStatus::Pending
            || !valid_invitation_audit(
                invitation,
                audit_event,
                AdministrativeAction::InvitationCreated,
            )
        {
            return Err(PostgresStoreError::InvalidInput);
        }
        let created_at = postgres_epoch(invitation.created_at_epoch_seconds())?;
        let expires_at = postgres_epoch(invitation.expires_at_epoch_seconds())?;
        let mut transaction = self.begin_tenant(invitation.workspace_id().clone())?;
        let expired = transaction
            .execute(
                EXPIRE_PENDING_INVITATION_SQL,
                &[
                    PostgresParameter::Text(invitation.workspace_id().as_str()),
                    PostgresParameter::Text(invitation.invited_principal_id().as_str()),
                    PostgresParameter::I64(created_at),
                ],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if expired > 1 {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        insert_administrative_audit(&mut transaction, audit_event)?;
        execute_exactly_one(
            &mut transaction,
            INSERT_INVITATION_SQL,
            &[
                PostgresParameter::Text(invitation.workspace_id().as_str()),
                PostgresParameter::Text(invitation.id().as_str()),
                PostgresParameter::Text(invitation.invited_principal_id().as_str()),
                PostgresParameter::Text(invitation.invited_by().as_str()),
                PostgresParameter::Text(membership_role_name(invitation.role())),
                PostgresParameter::I64(created_at),
                PostgresParameter::I64(expires_at),
            ],
        )?;
        transaction.commit().map_err(PostgresStoreError::Tenant)
    }

    pub fn accept_invitation_with_membership(
        &self,
        invitation: &Invitation,
        membership: &Membership,
        audit_event: &AdministrativeAuditEvent,
    ) -> Result<(), PostgresStoreError<Pool::Error>> {
        if invitation.status() != InvitationStatus::Accepted
            || invitation.workspace_id() != membership.workspace_id()
            || invitation.invited_principal_id() != membership.principal_id()
            || invitation.role() != membership.role()
            || !membership.is_active()
            || !valid_invitation_audit(
                invitation,
                audit_event,
                AdministrativeAction::InvitationAccepted,
            )
            || audit_event.actor_id() != membership.principal_id()
        {
            return Err(PostgresStoreError::InvalidInput);
        }
        let created_at = postgres_epoch(invitation.created_at_epoch_seconds())?;
        let expires_at = postgres_epoch(invitation.expires_at_epoch_seconds())?;
        let mut transaction = self.begin_tenant(invitation.workspace_id().clone())?;
        let changed = transaction
            .execute(
                ACCEPT_INVITATION_SQL,
                &[
                    PostgresParameter::Text(invitation.workspace_id().as_str()),
                    PostgresParameter::Text(invitation.id().as_str()),
                    PostgresParameter::Text(invitation.invited_principal_id().as_str()),
                    PostgresParameter::Text(membership_role_name(invitation.role())),
                    PostgresParameter::I64(created_at),
                    PostgresParameter::I64(expires_at),
                ],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if changed != 1 {
            return Err(PostgresStoreError::VersionConflict);
        }
        execute_exactly_one(
            &mut transaction,
            INSERT_MEMBERSHIP_SQL,
            &[
                PostgresParameter::Text(membership.workspace_id().as_str()),
                PostgresParameter::Text(membership.principal_id().as_str()),
                PostgresParameter::Text(membership_role_name(membership.role())),
                PostgresParameter::Text("active"),
            ],
        )?;
        insert_administrative_audit(&mut transaction, audit_event)?;
        transaction.commit().map_err(PostgresStoreError::Tenant)
    }

    pub fn replace_invitation(
        &self,
        invitation: &Invitation,
        expected_status: InvitationStatus,
        audit_event: &AdministrativeAuditEvent,
    ) -> Result<(), PostgresStoreError<Pool::Error>> {
        if !valid_invitation_audit(
            invitation,
            audit_event,
            AdministrativeAction::InvitationRevoked,
        ) {
            return Err(PostgresStoreError::InvalidInput);
        }
        let created_at = postgres_epoch(invitation.created_at_epoch_seconds())?;
        let expires_at = postgres_epoch(invitation.expires_at_epoch_seconds())?;
        let mut transaction = self.begin_tenant(invitation.workspace_id().clone())?;
        let changed = transaction
            .execute(
                REPLACE_INVITATION_SQL,
                &[
                    PostgresParameter::Text(invitation.workspace_id().as_str()),
                    PostgresParameter::Text(invitation.id().as_str()),
                    PostgresParameter::Text(invitation.invited_principal_id().as_str()),
                    PostgresParameter::Text(invitation.invited_by().as_str()),
                    PostgresParameter::Text(membership_role_name(invitation.role())),
                    PostgresParameter::Text(invitation_status_name(invitation.status())),
                    PostgresParameter::Text(invitation_status_name(expected_status)),
                    PostgresParameter::I64(created_at),
                    PostgresParameter::I64(expires_at),
                ],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if changed != 1 {
            return Err(PostgresStoreError::VersionConflict);
        }
        insert_administrative_audit(&mut transaction, audit_event)?;
        transaction.commit().map_err(PostgresStoreError::Tenant)
    }

    pub fn append_administrative_audit(
        &self,
        event: &AdministrativeAuditEvent,
    ) -> Result<(), PostgresStoreError<Pool::Error>> {
        let mut transaction = self.begin_tenant(event.workspace_id().clone())?;
        insert_administrative_audit(&mut transaction, event)?;
        transaction.commit().map_err(PostgresStoreError::Tenant)
    }

    pub fn list_administrative_audit(
        &self,
        workspace_id: &WorkspaceId,
        after_epoch_seconds: u64,
        limit: usize,
    ) -> Result<Vec<AdministrativeAuditEvent>, PostgresStoreError<Pool::Error>>
    where
        <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    {
        if !(1..=MAX_ADMINISTRATIVE_AUDIT_PAGE).contains(&limit) {
            return Err(PostgresStoreError::InvalidLimit);
        }
        let after = postgres_epoch(after_epoch_seconds)?;
        let maximum_rows = limit;
        let limit = i64::try_from(limit).map_err(|_| PostgresStoreError::InvalidLimit)?;
        let mut transaction = self.begin_tenant(workspace_id.clone())?;
        let rows = transaction
            .query(
                LIST_ADMINISTRATIVE_AUDIT_SQL,
                &[
                    PostgresParameter::Text(workspace_id.as_str()),
                    PostgresParameter::I64(after),
                    PostgresParameter::I64(limit),
                ],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if rows.len() > maximum_rows {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        let mut ids = BTreeSet::new();
        let events = rows
            .iter()
            .map(|row| {
                let event = decode_administrative_audit(row, workspace_id)?;
                if !ids.insert(event.id().as_str().to_owned()) {
                    return Err(PostgresStoreError::InvalidRow);
                }
                Ok(event)
            })
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().map_err(PostgresStoreError::Tenant)?;
        Ok(events)
    }

    pub fn find_retention_policy(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<WorkspaceRetentionPolicy>, PostgresStoreError<Pool::Error>>
    where
        <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    {
        let mut transaction = self.begin_tenant(workspace_id.clone())?;
        let rows = transaction
            .query(
                FIND_RETENTION_POLICY_SQL,
                &[PostgresParameter::Text(workspace_id.as_str())],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if rows.len() > 1 {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        let policy = rows
            .first()
            .map(|row| decode_retention_policy(row, workspace_id))
            .transpose()?;
        transaction.commit().map_err(PostgresStoreError::Tenant)?;
        Ok(policy)
    }

    pub fn replace_retention_policy(
        &self,
        policy: &WorkspaceRetentionPolicy,
        expected_version: Option<u64>,
        audit_event: &AdministrativeAuditEvent,
    ) -> Result<(), PostgresStoreError<Pool::Error>> {
        if !valid_retention_audit(policy, audit_event) {
            return Err(PostgresStoreError::InvalidInput);
        }
        let version = postgres_epoch(policy.version())?;
        let values = retention_policy_parameters(policy);
        let mut transaction = self.begin_tenant(policy.workspace_id().clone())?;
        let changed = match expected_version {
            None if policy.version() == 1 => transaction.execute(
                INSERT_RETENTION_POLICY_SQL,
                &[
                    PostgresParameter::Text(policy.workspace_id().as_str()),
                    PostgresParameter::I64(version),
                    values[0],
                    values[1],
                    values[2],
                    values[3],
                    values[4],
                    values[5],
                ],
            ),
            Some(expected) if is_strict_successor(expected, policy.version()) => {
                let expected = postgres_epoch(expected)?;
                transaction.execute(
                    REPLACE_RETENTION_POLICY_SQL,
                    &[
                        PostgresParameter::Text(policy.workspace_id().as_str()),
                        PostgresParameter::I64(version),
                        values[0],
                        values[1],
                        values[2],
                        values[3],
                        values[4],
                        values[5],
                        PostgresParameter::I64(expected),
                    ],
                )
            }
            None | Some(_) => return Err(PostgresStoreError::VersionConflict),
        }
        .map_err(PostgresStoreError::Tenant)?;
        if changed != 1 {
            return Err(PostgresStoreError::VersionConflict);
        }
        insert_administrative_audit(&mut transaction, audit_event)?;
        transaction.commit().map_err(PostgresStoreError::Tenant)
    }

    pub fn find_legal_hold(
        &self,
        workspace_id: &WorkspaceId,
        hold_id: &LegalHoldId,
    ) -> Result<Option<WorkspaceLegalHold>, PostgresStoreError<Pool::Error>>
    where
        <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    {
        let mut transaction = self.begin_tenant(workspace_id.clone())?;
        let rows = transaction
            .query(
                FIND_LEGAL_HOLD_SQL,
                &[
                    PostgresParameter::Text(workspace_id.as_str()),
                    PostgresParameter::Text(hold_id.as_str()),
                ],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if rows.len() > 1 {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        let hold = rows
            .first()
            .map(|row| decode_legal_hold(row, workspace_id, Some(hold_id)))
            .transpose()?;
        transaction.commit().map_err(PostgresStoreError::Tenant)?;
        Ok(hold)
    }

    pub fn list_active_legal_holds(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<WorkspaceLegalHold>, PostgresStoreError<Pool::Error>>
    where
        <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    {
        let mut transaction = self.begin_tenant(workspace_id.clone())?;
        let rows = transaction
            .query(
                LIST_ACTIVE_LEGAL_HOLDS_SQL,
                &[PostgresParameter::Text(workspace_id.as_str())],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if rows.len() > MAX_ACTIVE_LEGAL_HOLDS {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        let mut ids = BTreeSet::new();
        let holds = rows
            .iter()
            .map(|row| {
                let hold = decode_legal_hold(row, workspace_id, None)?;
                if hold.status() != LegalHoldStatus::Active
                    || !ids.insert(hold.id().as_str().to_owned())
                {
                    return Err(PostgresStoreError::InvalidRow);
                }
                Ok(hold)
            })
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().map_err(PostgresStoreError::Tenant)?;
        Ok(holds)
    }

    pub fn insert_legal_hold(
        &self,
        hold: &WorkspaceLegalHold,
        audit_event: &AdministrativeAuditEvent,
    ) -> Result<(), PostgresStoreError<Pool::Error>> {
        if hold.status() != LegalHoldStatus::Active
            || hold.version() != 1
            || !valid_legal_hold_audit(hold, audit_event, AdministrativeAction::LegalHoldPlaced)
        {
            return Err(PostgresStoreError::InvalidInput);
        }
        let mut transaction = self.begin_tenant(hold.workspace_id().clone())?;
        execute_exactly_one(
            &mut transaction,
            INSERT_LEGAL_HOLD_SQL,
            &legal_hold_parameters(hold)?,
        )?;
        insert_administrative_audit(&mut transaction, audit_event)?;
        transaction.commit().map_err(PostgresStoreError::Tenant)
    }

    pub fn replace_legal_hold(
        &self,
        hold: &WorkspaceLegalHold,
        expected_version: u64,
        audit_event: &AdministrativeAuditEvent,
    ) -> Result<(), PostgresStoreError<Pool::Error>> {
        if !valid_legal_hold_audit(hold, audit_event, AdministrativeAction::LegalHoldReleased) {
            return Err(PostgresStoreError::InvalidInput);
        }
        if !is_strict_successor(expected_version, hold.version()) {
            return Err(PostgresStoreError::VersionConflict);
        }
        let expected_version = postgres_epoch(expected_version)?;
        let parameters = legal_hold_parameters(hold)?;
        let mut transaction = self.begin_tenant(hold.workspace_id().clone())?;
        let changed = transaction
            .execute(
                REPLACE_LEGAL_HOLD_SQL,
                &[
                    parameters[0],
                    parameters[1],
                    parameters[4],
                    parameters[5],
                    parameters[6],
                    parameters[7],
                    PostgresParameter::I64(expected_version),
                ],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if changed != 1 {
            return Err(PostgresStoreError::VersionConflict);
        }
        insert_administrative_audit(&mut transaction, audit_event)?;
        transaction.commit().map_err(PostgresStoreError::Tenant)
    }

    pub fn insert_member_scope_grant(
        &self,
        grant: &MemberScopeGrant,
        audit_event: &AdministrativeAuditEvent,
    ) -> Result<(), PostgresStoreError<Pool::Error>> {
        if !valid_scope_audit(grant, audit_event) {
            return Err(PostgresStoreError::InvalidInput);
        }
        let (scope_type, scope_value) = encode_read_scope(grant.scope());
        let mut transaction = self.begin_tenant(grant.workspace_id().clone())?;
        execute_exactly_one(
            &mut transaction,
            INSERT_MEMBER_SCOPE_GRANT_SQL,
            &[
                PostgresParameter::Text(grant.workspace_id().as_str()),
                PostgresParameter::Text(grant.principal_id().as_str()),
                PostgresParameter::Text(scope_type),
                PostgresParameter::Text(scope_value),
            ],
        )?;
        insert_administrative_audit(&mut transaction, audit_event)?;
        transaction.commit().map_err(PostgresStoreError::Tenant)
    }

    pub fn list_member_scope_grants(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Vec<MemberScopeGrant>, PostgresStoreError<Pool::Error>>
    where
        <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    {
        let mut transaction = self.begin_tenant(workspace_id.clone())?;
        let rows = transaction
            .query(
                LIST_MEMBER_SCOPE_GRANTS_SQL,
                &[
                    PostgresParameter::Text(workspace_id.as_str()),
                    PostgresParameter::Text(principal_id.as_str()),
                ],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if rows.len() > MAX_MEMBER_SCOPE_GRANTS {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        let mut scopes = BTreeSet::new();
        let grants = rows
            .iter()
            .map(|row| {
                let grant = decode_member_scope_grant(row, workspace_id, principal_id)?;
                let encoded = encode_read_scope(grant.scope());
                if !scopes.insert((encoded.0, encoded.1.to_owned())) {
                    return Err(PostgresStoreError::InvalidRow);
                }
                Ok(grant)
            })
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().map_err(PostgresStoreError::Tenant)?;
        Ok(grants)
    }

    pub fn delete_member_scope_grant(
        &self,
        grant: &MemberScopeGrant,
        audit_event: &AdministrativeAuditEvent,
    ) -> Result<(), PostgresStoreError<Pool::Error>> {
        if !valid_scope_audit(grant, audit_event) {
            return Err(PostgresStoreError::InvalidInput);
        }
        let (scope_type, scope_value) = encode_read_scope(grant.scope());
        let mut transaction = self.begin_tenant(grant.workspace_id().clone())?;
        let changed = transaction
            .execute(
                DELETE_MEMBER_SCOPE_GRANT_SQL,
                &[
                    PostgresParameter::Text(grant.workspace_id().as_str()),
                    PostgresParameter::Text(grant.principal_id().as_str()),
                    PostgresParameter::Text(scope_type),
                    PostgresParameter::Text(scope_value),
                ],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if changed == 0 {
            return Err(PostgresStoreError::MissingRow);
        }
        if changed != 1 {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        insert_administrative_audit(&mut transaction, audit_event)?;
        transaction.commit().map_err(PostgresStoreError::Tenant)
    }

    pub fn latest_key_rotation(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<WorkspaceKeyRotation>, PostgresStoreError<Pool::Error>>
    where
        <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    {
        let mut transaction = self.begin_tenant(workspace_id.clone())?;
        let rows = transaction
            .query(
                LATEST_KEY_ROTATION_SQL,
                &[PostgresParameter::Text(workspace_id.as_str())],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if rows.len() > 1 {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        let rotation = rows
            .first()
            .map(|row| decode_key_rotation(row, workspace_id))
            .transpose()?;
        transaction.commit().map_err(PostgresStoreError::Tenant)?;
        Ok(rotation)
    }

    pub fn find_key_rotation_receipt(
        &self,
        workspace_id: &WorkspaceId,
        rotation_id: &KeyRotationId,
    ) -> Result<Option<KeyRotationReceipt>, PostgresStoreError<Pool::Error>>
    where
        <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    {
        let mut transaction = self.begin_tenant(workspace_id.clone())?;
        let header_rows = transaction
            .query(
                FIND_KEY_ROTATION_RECEIPT_SQL,
                &[
                    PostgresParameter::Text(workspace_id.as_str()),
                    PostgresParameter::Text(rotation_id.as_str()),
                ],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if header_rows.len() > 1 {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        let Some(header) = header_rows.first() else {
            transaction.commit().map_err(PostgresStoreError::Tenant)?;
            return Ok(None);
        };
        validate_rotation_receipt_header(header, workspace_id, rotation_id)?;
        let recipient_rows = transaction
            .query(
                LIST_KEY_ROTATION_RECIPIENTS_SQL,
                &[
                    PostgresParameter::Text(workspace_id.as_str()),
                    PostgresParameter::Text(rotation_id.as_str()),
                ],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if recipient_rows.len() > MAX_KEY_ROTATION_RECIPIENTS {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        let mut recipient_ids = Vec::with_capacity(recipient_rows.len());
        for row in &recipient_rows {
            let row_workspace_id = row.text("workspace_id").map_err(PostgresStoreError::Row)?;
            let row_rotation_id = row.text("rotation_id").map_err(PostgresStoreError::Row)?;
            if row_workspace_id != workspace_id.as_str() || row_rotation_id != rotation_id.as_str()
            {
                return Err(PostgresStoreError::InvalidRow);
            }
            recipient_ids.push(PrincipalId::new(
                row.text("principal_id").map_err(PostgresStoreError::Row)?,
            ));
        }
        let receipt = KeyRotationReceipt::new(
            ProviderId::new(
                header
                    .text("provider_id")
                    .map_err(PostgresStoreError::Row)?,
            ),
            header.text("request_id").map_err(PostgresStoreError::Row)?,
            workspace_id.clone(),
            header.u64("generation").map_err(PostgresStoreError::Row)?,
            header.text("key_id").map_err(PostgresStoreError::Row)?,
            recipient_ids,
        )
        .map_err(|_| PostgresStoreError::InvalidRow)?;
        transaction.commit().map_err(PostgresStoreError::Tenant)?;
        Ok(Some(receipt))
    }

    pub fn complete_key_rotation(
        &self,
        rotation: &WorkspaceKeyRotation,
        receipt: &KeyRotationReceipt,
        expected_generation: u64,
        audit_event: &AdministrativeAuditEvent,
    ) -> Result<(), PostgresStoreError<Pool::Error>> {
        if !valid_completed_rotation(rotation, receipt, expected_generation, audit_event) {
            return Err(PostgresStoreError::InvalidInput);
        }
        let completed_key_id = rotation
            .completed_key_id()
            .ok_or(PostgresStoreError::InvalidInput)?;
        let completed_by = rotation
            .completed_by()
            .ok_or(PostgresStoreError::InvalidInput)?;
        let generation = postgres_epoch(expected_generation)?;
        let mut transaction = self.begin_tenant(rotation.workspace_id().clone())?;
        let changed = transaction
            .execute(
                COMPLETE_KEY_ROTATION_SQL,
                &[
                    PostgresParameter::Text(completed_key_id),
                    PostgresParameter::Text(completed_by.as_str()),
                    PostgresParameter::Text(rotation.workspace_id().as_str()),
                    PostgresParameter::Text(rotation.id().as_str()),
                    PostgresParameter::I64(generation),
                ],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if changed != 1 {
            return Err(PostgresStoreError::VersionConflict);
        }
        execute_exactly_one(
            &mut transaction,
            INSERT_KEY_ROTATION_RECEIPT_SQL,
            &[
                PostgresParameter::Text(receipt.workspace_id().as_str()),
                PostgresParameter::Text(rotation.id().as_str()),
                PostgresParameter::Text(receipt.provider_id().as_str()),
                PostgresParameter::Text(receipt.request_id()),
                PostgresParameter::I64(generation),
                PostgresParameter::Text(receipt.key_id()),
            ],
        )?;
        for recipient_id in receipt.recipient_ids() {
            execute_exactly_one(
                &mut transaction,
                INSERT_KEY_ROTATION_RECIPIENT_SQL,
                &[
                    PostgresParameter::Text(receipt.workspace_id().as_str()),
                    PostgresParameter::Text(rotation.id().as_str()),
                    PostgresParameter::Text(recipient_id.as_str()),
                ],
            )?;
        }
        insert_administrative_audit(&mut transaction, audit_event)?;
        transaction.commit().map_err(PostgresStoreError::Tenant)
    }

    pub fn remove_member_and_scope_grants(
        &self,
        membership: &Membership,
        expected_status: MembershipStatus,
        rotation_id: &KeyRotationId,
        requested_by: &PrincipalId,
        audit_events: &[AdministrativeAuditEvent],
    ) -> Result<(), PostgresStoreError<Pool::Error>>
    where
        <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    {
        if membership.status() != MembershipStatus::Removed
            || !valid_member_removal_audits(membership, rotation_id, requested_by, audit_events)
        {
            return Err(PostgresStoreError::InvalidInput);
        }
        let mut transaction = self.begin_tenant(membership.workspace_id().clone())?;
        let lock_rows = transaction
            .query(
                LOCK_WORKSPACE_FOR_ROTATION_SQL,
                &[PostgresParameter::Text(membership.workspace_id().as_str())],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if lock_rows.len() != 1
            || lock_rows[0].text("id").map_err(PostgresStoreError::Row)?
                != membership.workspace_id().as_str()
        {
            return Err(PostgresStoreError::MissingRow);
        }
        let generation_rows = transaction
            .query(
                NEXT_KEY_ROTATION_GENERATION_SQL,
                &[PostgresParameter::Text(membership.workspace_id().as_str())],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if generation_rows.len() != 1 {
            return Err(PostgresStoreError::UnexpectedCardinality);
        }
        let generation = generation_rows[0]
            .u64("next_generation")
            .map_err(PostgresStoreError::Row)?;
        WorkspaceKeyRotation::required(
            rotation_id.clone(),
            membership.workspace_id().clone(),
            generation,
            membership.principal_id().clone(),
            requested_by.clone(),
        )
        .map_err(|_| PostgresStoreError::InvalidInput)?;
        let changed = transaction
            .execute(
                REMOVE_MEMBERSHIP_SQL,
                &[
                    PostgresParameter::Text(membership.workspace_id().as_str()),
                    PostgresParameter::Text(membership.principal_id().as_str()),
                    PostgresParameter::Text(membership_role_name(membership.role())),
                    PostgresParameter::Text(membership_status_label(expected_status)),
                ],
            )
            .map_err(PostgresStoreError::Tenant)?;
        if changed != 1 {
            return Err(PostgresStoreError::VersionConflict);
        }
        transaction
            .execute(
                DELETE_MEMBER_SCOPE_GRANTS_SQL,
                &[
                    PostgresParameter::Text(membership.workspace_id().as_str()),
                    PostgresParameter::Text(membership.principal_id().as_str()),
                ],
            )
            .map_err(PostgresStoreError::Tenant)?;
        for event in audit_events {
            insert_administrative_audit(&mut transaction, event)?;
        }
        execute_exactly_one(
            &mut transaction,
            INSERT_REQUIRED_KEY_ROTATION_SQL,
            &[
                PostgresParameter::Text(membership.workspace_id().as_str()),
                PostgresParameter::Text(rotation_id.as_str()),
                PostgresParameter::I64(postgres_epoch(generation)?),
                PostgresParameter::Text(membership.principal_id().as_str()),
                PostgresParameter::Text(requested_by.as_str()),
            ],
        )?;
        transaction.commit().map_err(PostgresStoreError::Tenant)
    }
}

impl<Pool> MembershipRepository for PostgresStore<Pool>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn insert_membership(&mut self, membership: Membership) -> Result<(), ApplicationError> {
        PostgresStore::insert_membership(self, &membership).map_err(map_application_error)
    }

    fn find_membership(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Option<Membership>, ApplicationError> {
        PostgresStore::find_membership(self, workspace_id, principal_id)
            .map_err(map_application_error)
    }

    fn list_active_memberships(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<Membership>, ApplicationError> {
        PostgresStore::list_active_memberships(self, workspace_id).map_err(map_application_error)
    }

    fn replace_membership(&mut self, membership: Membership) -> Result<(), ApplicationError> {
        PostgresStore::replace_membership(self, &membership).map_err(map_application_error)
    }
}

impl<Pool> InvitationRepository for PostgresStore<Pool>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn insert_invitation_replacing_expired(
        &mut self,
        invitation: Invitation,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        PostgresStore::insert_invitation_replacing_expired(self, &invitation, &audit_event)
            .map_err(map_invitation_application_error)
    }

    fn find_invitation(
        &self,
        workspace_id: &WorkspaceId,
        invitation_id: &InvitationId,
    ) -> Result<Option<Invitation>, ApplicationError> {
        PostgresStore::find_invitation(self, workspace_id, invitation_id)
            .map_err(map_invitation_application_error)
    }

    fn list_invitations(
        &self,
        workspace_id: &WorkspaceId,
        status: Option<InvitationStatus>,
        limit: usize,
    ) -> Result<Vec<Invitation>, ApplicationError> {
        PostgresStore::list_invitations(self, workspace_id, status, limit)
            .map_err(map_invitation_application_error)
    }

    fn accept_invitation_with_membership(
        &mut self,
        invitation: Invitation,
        membership: Membership,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        PostgresStore::accept_invitation_with_membership(
            self,
            &invitation,
            &membership,
            &audit_event,
        )
        .map_err(map_invitation_application_error)
    }

    fn replace_invitation(
        &mut self,
        invitation: Invitation,
        expected_status: InvitationStatus,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        PostgresStore::replace_invitation(self, &invitation, expected_status, &audit_event)
            .map_err(map_invitation_application_error)
    }
}

impl<Pool> AdministrativeAuditRepository for PostgresStore<Pool>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn append_administrative_audit(
        &mut self,
        event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        PostgresStore::append_administrative_audit(self, &event)
            .map_err(map_audit_application_error)
    }

    fn list_administrative_audit(
        &self,
        workspace_id: &WorkspaceId,
        after_epoch_seconds: u64,
        limit: usize,
    ) -> Result<Vec<AdministrativeAuditEvent>, ApplicationError> {
        PostgresStore::list_administrative_audit(self, workspace_id, after_epoch_seconds, limit)
            .map_err(map_audit_application_error)
    }
}

impl<Pool> RetentionRepository for PostgresStore<Pool>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn find_retention_policy(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<WorkspaceRetentionPolicy>, ApplicationError> {
        PostgresStore::find_retention_policy(self, workspace_id)
            .map_err(map_retention_application_error)
    }

    fn replace_retention_policy(
        &mut self,
        policy: WorkspaceRetentionPolicy,
        expected_version: Option<u64>,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        PostgresStore::replace_retention_policy(self, &policy, expected_version, &audit_event)
            .map_err(map_retention_application_error)
    }

    fn find_legal_hold(
        &self,
        workspace_id: &WorkspaceId,
        hold_id: &LegalHoldId,
    ) -> Result<Option<WorkspaceLegalHold>, ApplicationError> {
        PostgresStore::find_legal_hold(self, workspace_id, hold_id)
            .map_err(map_retention_application_error)
    }

    fn list_active_legal_holds(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<WorkspaceLegalHold>, ApplicationError> {
        PostgresStore::list_active_legal_holds(self, workspace_id)
            .map_err(map_retention_application_error)
    }

    fn insert_legal_hold(
        &mut self,
        hold: WorkspaceLegalHold,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        PostgresStore::insert_legal_hold(self, &hold, &audit_event)
            .map_err(map_retention_application_error)
    }

    fn replace_legal_hold(
        &mut self,
        hold: WorkspaceLegalHold,
        expected_version: u64,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        PostgresStore::replace_legal_hold(self, &hold, expected_version, &audit_event)
            .map_err(map_retention_application_error)
    }
}

impl<Pool> MemberScopeGrantRepository for PostgresStore<Pool>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn insert_member_scope_grant(
        &mut self,
        grant: MemberScopeGrant,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        PostgresStore::insert_member_scope_grant(self, &grant, &audit_event)
            .map_err(map_scope_application_error)
    }

    fn list_member_scope_grants(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Vec<MemberScopeGrant>, ApplicationError> {
        PostgresStore::list_member_scope_grants(self, workspace_id, principal_id)
            .map_err(map_scope_application_error)
    }

    fn delete_member_scope_grant(
        &mut self,
        grant: &MemberScopeGrant,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        PostgresStore::delete_member_scope_grant(self, grant, &audit_event)
            .map_err(map_scope_application_error)
    }
}

impl<Pool> KeyRotationRepository for PostgresStore<Pool>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn latest_key_rotation(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<WorkspaceKeyRotation>, ApplicationError> {
        PostgresStore::latest_key_rotation(self, workspace_id)
            .map_err(map_key_rotation_application_error)
    }

    fn find_key_rotation_receipt(
        &self,
        workspace_id: &WorkspaceId,
        rotation_id: &KeyRotationId,
    ) -> Result<Option<KeyRotationReceipt>, ApplicationError> {
        PostgresStore::find_key_rotation_receipt(self, workspace_id, rotation_id)
            .map_err(map_key_rotation_application_error)
    }

    fn complete_key_rotation(
        &mut self,
        rotation: WorkspaceKeyRotation,
        receipt: KeyRotationReceipt,
        expected_generation: u64,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        PostgresStore::complete_key_rotation(
            self,
            &rotation,
            &receipt,
            expected_generation,
            &audit_event,
        )
        .map_err(map_key_rotation_application_error)
    }
}

impl<Pool> MemberLifecycleRepository for PostgresStore<Pool>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn remove_member_and_scope_grants(
        &mut self,
        membership: Membership,
        expected_status: MembershipStatus,
        rotation_id: KeyRotationId,
        requested_by: PrincipalId,
        audit_events: Vec<AdministrativeAuditEvent>,
    ) -> Result<(), ApplicationError> {
        PostgresStore::remove_member_and_scope_grants(
            self,
            &membership,
            expected_status,
            &rotation_id,
            &requested_by,
            &audit_events,
        )
        .map_err(map_key_rotation_application_error)
    }
}

impl<Pool> PostgresTenantStore<'_, Pool> {
    fn require_workspace(&self, workspace_id: &WorkspaceId) -> Result<(), ApplicationError> {
        if workspace_id == &self.workspace_id {
            Ok(())
        } else {
            Err(ApplicationError::AccessDenied)
        }
    }

    #[must_use]
    pub fn with_cipher<'cipher, Cipher>(
        &self,
        cipher: &'cipher Cipher,
    ) -> PostgresTenantMemoryStore<'_, 'cipher, Pool, Cipher> {
        PostgresTenantMemoryStore {
            store: self.store,
            cipher,
            workspace_id: self.workspace_id.clone(),
        }
    }

    pub fn find_retention_policy(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<WorkspaceRetentionPolicy>, ApplicationError>
    where
        Pool: PostgresPool,
        Pool::Error: ClassifiedPostgresError,
        <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    {
        self.require_workspace(workspace_id)?;
        self.store
            .find_retention_policy(workspace_id)
            .map_err(map_application_error)
    }

    pub fn replace_retention_policy(
        &mut self,
        policy: &WorkspaceRetentionPolicy,
        expected_version: Option<u64>,
        audit_event: &AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError>
    where
        Pool: PostgresPool,
        Pool::Error: ClassifiedPostgresError,
    {
        self.require_workspace(policy.workspace_id())?;
        self.require_workspace(audit_event.workspace_id())?;
        self.store
            .replace_retention_policy(policy, expected_version, audit_event)
            .map_err(map_retention_application_error)
    }

    pub fn find_legal_hold(
        &self,
        workspace_id: &WorkspaceId,
        hold_id: &LegalHoldId,
    ) -> Result<Option<WorkspaceLegalHold>, ApplicationError>
    where
        Pool: PostgresPool,
        Pool::Error: ClassifiedPostgresError,
        <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    {
        self.require_workspace(workspace_id)?;
        self.store
            .find_legal_hold(workspace_id, hold_id)
            .map_err(map_application_error)
    }

    pub fn list_active_legal_holds(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<WorkspaceLegalHold>, ApplicationError>
    where
        Pool: PostgresPool,
        Pool::Error: ClassifiedPostgresError,
        <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    {
        self.require_workspace(workspace_id)?;
        self.store
            .list_active_legal_holds(workspace_id)
            .map_err(map_application_error)
    }
}

impl<Pool> AdministrativeAuditRepository for PostgresTenantStore<'_, Pool>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn append_administrative_audit(
        &mut self,
        event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        self.require_workspace(event.workspace_id())?;
        self.store
            .append_administrative_audit(&event)
            .map_err(map_audit_application_error)
    }

    fn list_administrative_audit(
        &self,
        workspace_id: &WorkspaceId,
        after_epoch_seconds: u64,
        limit: usize,
    ) -> Result<Vec<AdministrativeAuditEvent>, ApplicationError> {
        self.require_workspace(workspace_id)?;
        self.store
            .list_administrative_audit(workspace_id, after_epoch_seconds, limit)
            .map_err(map_audit_application_error)
    }
}

impl<Pool> RetentionRepository for PostgresTenantStore<'_, Pool>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn find_retention_policy(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<WorkspaceRetentionPolicy>, ApplicationError> {
        self.require_workspace(workspace_id)?;
        self.store
            .find_retention_policy(workspace_id)
            .map_err(map_retention_application_error)
    }

    fn replace_retention_policy(
        &mut self,
        policy: WorkspaceRetentionPolicy,
        expected_version: Option<u64>,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        self.require_workspace(policy.workspace_id())?;
        self.require_workspace(audit_event.workspace_id())?;
        self.store
            .replace_retention_policy(&policy, expected_version, &audit_event)
            .map_err(map_retention_application_error)
    }

    fn find_legal_hold(
        &self,
        workspace_id: &WorkspaceId,
        hold_id: &LegalHoldId,
    ) -> Result<Option<WorkspaceLegalHold>, ApplicationError> {
        self.require_workspace(workspace_id)?;
        self.store
            .find_legal_hold(workspace_id, hold_id)
            .map_err(map_retention_application_error)
    }

    fn list_active_legal_holds(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<WorkspaceLegalHold>, ApplicationError> {
        self.require_workspace(workspace_id)?;
        self.store
            .list_active_legal_holds(workspace_id)
            .map_err(map_retention_application_error)
    }

    fn insert_legal_hold(
        &mut self,
        hold: WorkspaceLegalHold,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        self.require_workspace(hold.workspace_id())?;
        self.require_workspace(audit_event.workspace_id())?;
        self.store
            .insert_legal_hold(&hold, &audit_event)
            .map_err(map_retention_application_error)
    }

    fn replace_legal_hold(
        &mut self,
        hold: WorkspaceLegalHold,
        expected_version: u64,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        self.require_workspace(hold.workspace_id())?;
        self.require_workspace(audit_event.workspace_id())?;
        self.store
            .replace_legal_hold(&hold, expected_version, &audit_event)
            .map_err(map_retention_application_error)
    }
}

impl<Pool> MemberScopeGrantRepository for PostgresTenantStore<'_, Pool>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn insert_member_scope_grant(
        &mut self,
        grant: MemberScopeGrant,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        self.require_workspace(grant.workspace_id())?;
        self.require_workspace(audit_event.workspace_id())?;
        self.store
            .insert_member_scope_grant(&grant, &audit_event)
            .map_err(map_scope_application_error)
    }

    fn list_member_scope_grants(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Vec<MemberScopeGrant>, ApplicationError> {
        self.require_workspace(workspace_id)?;
        self.store
            .list_member_scope_grants(workspace_id, principal_id)
            .map_err(map_scope_application_error)
    }

    fn delete_member_scope_grant(
        &mut self,
        grant: &MemberScopeGrant,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        self.require_workspace(grant.workspace_id())?;
        self.require_workspace(audit_event.workspace_id())?;
        self.store
            .delete_member_scope_grant(grant, &audit_event)
            .map_err(map_scope_application_error)
    }
}

impl<Pool> KeyRotationRepository for PostgresTenantStore<'_, Pool>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn latest_key_rotation(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<WorkspaceKeyRotation>, ApplicationError> {
        self.require_workspace(workspace_id)?;
        self.store
            .latest_key_rotation(workspace_id)
            .map_err(map_key_rotation_application_error)
    }

    fn find_key_rotation_receipt(
        &self,
        workspace_id: &WorkspaceId,
        rotation_id: &KeyRotationId,
    ) -> Result<Option<KeyRotationReceipt>, ApplicationError> {
        self.require_workspace(workspace_id)?;
        self.store
            .find_key_rotation_receipt(workspace_id, rotation_id)
            .map_err(map_key_rotation_application_error)
    }

    fn complete_key_rotation(
        &mut self,
        rotation: WorkspaceKeyRotation,
        receipt: KeyRotationReceipt,
        expected_generation: u64,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        self.require_workspace(rotation.workspace_id())?;
        self.require_workspace(receipt.workspace_id())?;
        self.require_workspace(audit_event.workspace_id())?;
        self.store
            .complete_key_rotation(&rotation, &receipt, expected_generation, &audit_event)
            .map_err(map_key_rotation_application_error)
    }
}

impl<Pool> MemberLifecycleRepository for PostgresTenantStore<'_, Pool>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn remove_member_and_scope_grants(
        &mut self,
        membership: Membership,
        expected_status: MembershipStatus,
        rotation_id: KeyRotationId,
        requested_by: PrincipalId,
        audit_events: Vec<AdministrativeAuditEvent>,
    ) -> Result<(), ApplicationError> {
        self.require_workspace(membership.workspace_id())?;
        for event in &audit_events {
            self.require_workspace(event.workspace_id())?;
        }
        self.store
            .remove_member_and_scope_grants(
                &membership,
                expected_status,
                &rotation_id,
                &requested_by,
                &audit_events,
            )
            .map_err(map_key_rotation_application_error)
    }
}

impl<Pool> WorkspaceReadRepository for PostgresTenantStore<'_, Pool>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn find_workspace(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<Workspace>, ApplicationError> {
        self.require_workspace(workspace_id)?;
        self.store
            .find_workspace(workspace_id)
            .map_err(map_application_error)
    }
}

impl<Pool> MembershipRepository for PostgresTenantStore<'_, Pool>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn insert_membership(&mut self, membership: Membership) -> Result<(), ApplicationError> {
        self.require_workspace(membership.workspace_id())?;
        self.store
            .insert_membership(&membership)
            .map_err(map_application_error)
    }

    fn find_membership(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Option<Membership>, ApplicationError> {
        self.require_workspace(workspace_id)?;
        self.store
            .find_membership(workspace_id, principal_id)
            .map_err(map_application_error)
    }

    fn list_active_memberships(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<Membership>, ApplicationError> {
        self.require_workspace(workspace_id)?;
        self.store
            .list_active_memberships(workspace_id)
            .map_err(map_application_error)
    }

    fn replace_membership(&mut self, membership: Membership) -> Result<(), ApplicationError> {
        self.require_workspace(membership.workspace_id())?;
        self.store
            .replace_membership(&membership)
            .map_err(map_application_error)
    }
}

impl<Pool> InvitationRepository for PostgresTenantStore<'_, Pool>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn insert_invitation_replacing_expired(
        &mut self,
        invitation: Invitation,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        self.require_workspace(invitation.workspace_id())?;
        self.store
            .insert_invitation_replacing_expired(&invitation, &audit_event)
            .map_err(map_invitation_application_error)
    }

    fn find_invitation(
        &self,
        workspace_id: &WorkspaceId,
        invitation_id: &InvitationId,
    ) -> Result<Option<Invitation>, ApplicationError> {
        self.require_workspace(workspace_id)?;
        self.store
            .find_invitation(workspace_id, invitation_id)
            .map_err(map_invitation_application_error)
    }

    fn list_invitations(
        &self,
        workspace_id: &WorkspaceId,
        status: Option<InvitationStatus>,
        limit: usize,
    ) -> Result<Vec<Invitation>, ApplicationError> {
        self.require_workspace(workspace_id)?;
        self.store
            .list_invitations(workspace_id, status, limit)
            .map_err(map_invitation_application_error)
    }

    fn accept_invitation_with_membership(
        &mut self,
        invitation: Invitation,
        membership: Membership,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        self.require_workspace(invitation.workspace_id())?;
        self.require_workspace(membership.workspace_id())?;
        self.store
            .accept_invitation_with_membership(&invitation, &membership, &audit_event)
            .map_err(map_invitation_application_error)
    }

    fn replace_invitation(
        &mut self,
        invitation: Invitation,
        expected_status: InvitationStatus,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        self.require_workspace(invitation.workspace_id())?;
        self.store
            .replace_invitation(&invitation, expected_status, &audit_event)
            .map_err(map_invitation_application_error)
    }
}

impl<Pool> ProjectionOutboxRepository for PostgresTenantStore<'_, Pool>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn enqueue_projection(&mut self, job: ProjectionJob) -> Result<(), ApplicationError> {
        self.require_workspace(job.workspace_id())?;
        let mut transaction = self
            .store
            .begin_tenant(self.workspace_id.clone())
            .map_err(map_application_error)?;
        insert_projection_jobs(&mut transaction, &[job])?;
        transaction
            .commit()
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)
    }

    fn pending_projections(
        &self,
        provider_id: &ProviderId,
        limit: usize,
    ) -> Result<Vec<ProjectionJob>, ApplicationError> {
        if limit == 0 || limit > MAX_PENDING_PROJECTIONS {
            return Err(ApplicationError::Validation(
                "projection limit must be between 1 and 1000".to_owned(),
            ));
        }
        let mut transaction = self
            .store
            .begin_tenant(self.workspace_id.clone())
            .map_err(map_application_error)?;
        let rows = transaction
            .query(
                LIST_PENDING_PROJECTIONS_SQL,
                &[
                    PostgresParameter::Text(self.workspace_id.as_str()),
                    PostgresParameter::Text(provider_id.as_str()),
                    PostgresParameter::I64(i64::try_from(limit).map_err(|_| {
                        ApplicationError::Validation(
                            "projection limit exceeds PostgreSQL range".to_owned(),
                        )
                    })?),
                ],
            )
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        if rows.len() > limit {
            return Err(ApplicationError::StorageUnavailable);
        }
        let mut ids = BTreeSet::new();
        let projections = rows
            .iter()
            .map(|row| {
                let projection =
                    decode_projection(row, &self.workspace_id, None, Some(provider_id))?;
                if projection.status() != ProjectionStatus::Pending
                    || !ids.insert(projection.id().as_str().to_owned())
                {
                    return Err(PostgresStoreError::InvalidRow);
                }
                Ok(projection)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_application_error)?;
        transaction
            .commit()
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        Ok(projections)
    }

    fn replace_projection(
        &mut self,
        job: ProjectionJob,
        expected_status: ProjectionStatus,
        expected_attempts: u32,
    ) -> Result<(), ApplicationError> {
        self.require_workspace(job.workspace_id())?;
        let mut transaction = self
            .store
            .begin_tenant(self.workspace_id.clone())
            .map_err(map_application_error)?;
        let changed = transaction
            .execute(
                REPLACE_PROJECTION_SQL,
                &[
                    PostgresParameter::Text(job.id().as_str()),
                    PostgresParameter::Text(projection_status_name(job.status())),
                    PostgresParameter::I64(i64::from(job.attempts())),
                    PostgresParameter::Text(job.workspace_id().as_str()),
                    PostgresParameter::Text(job.memory_id().as_str()),
                    PostgresParameter::I64(
                        postgres_epoch::<Pool::Error>(job.memory_version())
                            .map_err(map_application_error)?,
                    ),
                    PostgresParameter::Text(job.provider_id().as_str()),
                    PostgresParameter::Text(projection_operation_name(job.operation())),
                    PostgresParameter::Text(projection_status_name(expected_status)),
                    PostgresParameter::I64(i64::from(expected_attempts)),
                ],
            )
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        if changed != 1 {
            return Err(ApplicationError::VersionConflict);
        }
        transaction
            .commit()
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)
    }

    fn find_projection(
        &self,
        workspace_id: &WorkspaceId,
        job_id: &ProjectionJobId,
    ) -> Result<Option<ProjectionJob>, ApplicationError> {
        self.require_workspace(workspace_id)?;
        let mut transaction = self
            .store
            .begin_tenant(self.workspace_id.clone())
            .map_err(map_application_error)?;
        let rows = transaction
            .query(
                FIND_PROJECTION_SQL,
                &[
                    PostgresParameter::Text(workspace_id.as_str()),
                    PostgresParameter::Text(job_id.as_str()),
                ],
            )
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        if rows.len() > 1 {
            return Err(ApplicationError::StorageUnavailable);
        }
        let projection = rows
            .first()
            .map(|row| decode_projection(row, workspace_id, Some(job_id), None))
            .transpose()
            .map_err(map_application_error)?;
        transaction
            .commit()
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        Ok(projection)
    }
}

impl<Pool, Cipher> MemoryRepository for PostgresTenantMemoryStore<'_, '_, Pool, Cipher>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    Cipher: RecordCipher,
{
    fn find(
        &self,
        workspace_id: &WorkspaceId,
        memory_id: &MemoryId,
    ) -> Result<Option<MemoryRecord>, ApplicationError> {
        if workspace_id != &self.workspace_id {
            return Err(ApplicationError::AccessDenied);
        }
        let mut transaction = self
            .store
            .begin_tenant(workspace_id.clone())
            .map_err(map_application_error)?;
        let rows = transaction
            .query(
                FIND_MEMORY_SQL,
                &[
                    PostgresParameter::Text(workspace_id.as_str()),
                    PostgresParameter::Text(memory_id.as_str()),
                ],
            )
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        if rows.len() > 1 {
            return Err(ApplicationError::StorageUnavailable);
        }
        let memory = rows
            .first()
            .map(|row| decrypt_memory_row(self.cipher, row, workspace_id, memory_id, None))
            .transpose()
            .map_err(map_application_error)?;
        transaction
            .commit()
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        Ok(memory)
    }

    fn list_for_subject(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
    ) -> Result<Vec<MemoryRecord>, ApplicationError> {
        if workspace_id != &self.workspace_id {
            return Err(ApplicationError::AccessDenied);
        }
        let mut transaction = self
            .store
            .begin_tenant(workspace_id.clone())
            .map_err(map_application_error)?;
        let rows = transaction
            .query(
                LIST_SUBJECT_MEMORIES_SQL,
                &[
                    PostgresParameter::Text(workspace_id.as_str()),
                    PostgresParameter::Text(subject_id.as_str()),
                ],
            )
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        if rows.len() > MAX_SUBJECT_MEMORIES {
            return Err(ApplicationError::StorageUnavailable);
        }
        let mut ids = BTreeSet::new();
        let memories = rows
            .iter()
            .map(|row| {
                let id = row.text("id").map_err(PostgresStoreError::Row)?;
                if !ids.insert(id.clone()) {
                    return Err(PostgresStoreError::InvalidRow);
                }
                decrypt_memory_row(
                    self.cipher,
                    row,
                    workspace_id,
                    &MemoryId::new(id),
                    Some(subject_id),
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_application_error)?;
        transaction
            .commit()
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        Ok(memories)
    }
}

impl<Pool, Cipher> ProjectionOutboxRepository for PostgresTenantMemoryStore<'_, '_, Pool, Cipher>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn enqueue_projection(&mut self, job: ProjectionJob) -> Result<(), ApplicationError> {
        let mut tenant = PostgresTenantStore {
            store: self.store,
            workspace_id: self.workspace_id.clone(),
        };
        ProjectionOutboxRepository::enqueue_projection(&mut tenant, job)
    }

    fn pending_projections(
        &self,
        provider_id: &ProviderId,
        limit: usize,
    ) -> Result<Vec<ProjectionJob>, ApplicationError> {
        let tenant = PostgresTenantStore {
            store: self.store,
            workspace_id: self.workspace_id.clone(),
        };
        ProjectionOutboxRepository::pending_projections(&tenant, provider_id, limit)
    }

    fn replace_projection(
        &mut self,
        job: ProjectionJob,
        expected_status: ProjectionStatus,
        expected_attempts: u32,
    ) -> Result<(), ApplicationError> {
        let mut tenant = PostgresTenantStore {
            store: self.store,
            workspace_id: self.workspace_id.clone(),
        };
        ProjectionOutboxRepository::replace_projection(
            &mut tenant,
            job,
            expected_status,
            expected_attempts,
        )
    }

    fn find_projection(
        &self,
        workspace_id: &WorkspaceId,
        job_id: &ProjectionJobId,
    ) -> Result<Option<ProjectionJob>, ApplicationError> {
        let tenant = PostgresTenantStore {
            store: self.store,
            workspace_id: self.workspace_id.clone(),
        };
        ProjectionOutboxRepository::find_projection(&tenant, workspace_id, job_id)
    }
}

impl<Pool, Cipher> DisclosureRepository for PostgresTenantMemoryStore<'_, '_, Pool, Cipher>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
{
    fn append(&mut self, receipt: DisclosureReceipt) -> Result<(), ApplicationError> {
        if receipt.workspace_id != self.workspace_id || receipt.purpose.trim().is_empty() {
            return Err(ApplicationError::Validation(
                "disclosure receipt is invalid".to_owned(),
            ));
        }
        let mut transaction = self
            .store
            .begin_tenant(self.workspace_id.clone())
            .map_err(map_application_error)?;
        execute_exactly_one(
            &mut transaction,
            INSERT_DISCLOSURE_SQL,
            &[
                PostgresParameter::Text(receipt.workspace_id.as_str()),
                PostgresParameter::Text(receipt.id.as_str()),
                PostgresParameter::Text(receipt.context_pack_id.as_str()),
                PostgresParameter::Text(receipt.subject_id.as_str()),
                PostgresParameter::Text(receipt.client_id.as_str()),
                PostgresParameter::Text(&receipt.purpose),
            ],
        )
        .map_err(map_application_error)?;
        for (ordinal, memory) in receipt.memories.iter().enumerate() {
            let rows = transaction
                .query(
                    FIND_DISCLOSED_MEMORY_VERSION_SQL,
                    &[
                        PostgresParameter::Text(receipt.workspace_id.as_str()),
                        PostgresParameter::Text(memory.id.as_str()),
                        PostgresParameter::Text(receipt.subject_id.as_str()),
                    ],
                )
                .map_err(PostgresStoreError::Tenant)
                .map_err(map_application_error)?;
            if rows.len() != 1
                || rows[0]
                    .text("workspace_id")
                    .map_err(PostgresStoreError::Row)
                    .map_err(map_application_error)?
                    != receipt.workspace_id.as_str()
                || rows[0]
                    .text("id")
                    .map_err(PostgresStoreError::Row)
                    .map_err(map_application_error)?
                    != memory.id.as_str()
                || rows[0]
                    .text("subject_id")
                    .map_err(PostgresStoreError::Row)
                    .map_err(map_application_error)?
                    != receipt.subject_id.as_str()
                || rows[0]
                    .u64("version")
                    .map_err(PostgresStoreError::Row)
                    .map_err(map_application_error)?
                    != memory.version
            {
                return Err(ApplicationError::VersionConflict);
            }
            execute_exactly_one(
                &mut transaction,
                INSERT_DISCLOSED_MEMORY_SQL,
                &[
                    PostgresParameter::Text(receipt.workspace_id.as_str()),
                    PostgresParameter::Text(receipt.id.as_str()),
                    PostgresParameter::Text(memory.id.as_str()),
                    PostgresParameter::I64(
                        postgres_epoch::<Pool::Error>(memory.version)
                            .map_err(map_application_error)?,
                    ),
                    PostgresParameter::I64(i64::try_from(ordinal).map_err(|_| {
                        ApplicationError::Validation("too many disclosed memories".to_owned())
                    })?),
                ],
            )
            .map_err(map_application_error)?;
        }
        transaction
            .commit()
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)
    }
}

impl<Pool, Cipher> CheckpointRepository for PostgresTenantMemoryStore<'_, '_, Pool, Cipher>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    Cipher: RecordCipher,
{
    fn latest_checkpoint(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
        activity_id: &ActivityId,
    ) -> Result<Option<ActivityCheckpoint>, ApplicationError> {
        if workspace_id != &self.workspace_id {
            return Err(ApplicationError::AccessDenied);
        }
        let mut transaction = self
            .store
            .begin_tenant(workspace_id.clone())
            .map_err(map_application_error)?;
        let rows = transaction
            .query(
                LATEST_CHECKPOINT_SQL,
                &[
                    PostgresParameter::Text(workspace_id.as_str()),
                    PostgresParameter::Text(subject_id.as_str()),
                    PostgresParameter::Text(activity_id.as_str()),
                ],
            )
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        if rows.len() > 1 {
            return Err(ApplicationError::StorageUnavailable);
        }
        let checkpoint = rows
            .first()
            .map(|row| {
                decrypt_checkpoint_row(
                    self.cipher,
                    row,
                    workspace_id,
                    subject_id,
                    Some(activity_id),
                )
            })
            .transpose()
            .map_err(map_application_error)?;
        transaction
            .commit()
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        Ok(checkpoint)
    }

    fn list_checkpoints_for_subject(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
    ) -> Result<Vec<ActivityCheckpoint>, ApplicationError> {
        if workspace_id != &self.workspace_id {
            return Err(ApplicationError::AccessDenied);
        }
        let mut transaction = self
            .store
            .begin_tenant(workspace_id.clone())
            .map_err(map_application_error)?;
        let rows = transaction
            .query(
                LIST_SUBJECT_CHECKPOINTS_SQL,
                &[
                    PostgresParameter::Text(workspace_id.as_str()),
                    PostgresParameter::Text(subject_id.as_str()),
                ],
            )
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        if rows.len() > MAX_SUBJECT_CHECKPOINTS {
            return Err(ApplicationError::StorageUnavailable);
        }
        let mut ids = BTreeSet::new();
        let checkpoints = rows
            .iter()
            .map(|row| {
                let checkpoint =
                    decrypt_checkpoint_row(self.cipher, row, workspace_id, subject_id, None)?;
                if !ids.insert(checkpoint.id().as_str().to_owned()) {
                    return Err(PostgresStoreError::InvalidRow);
                }
                Ok(checkpoint)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_application_error)?;
        transaction
            .commit()
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        Ok(checkpoints)
    }
}

impl<Pool, Cipher> TripRepository for PostgresTenantMemoryStore<'_, '_, Pool, Cipher>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    Cipher: RecordCipher,
{
    fn find_trip(
        &self,
        workspace_id: &WorkspaceId,
        trip_id: &EntityId,
    ) -> Result<Option<Trip>, ApplicationError> {
        if workspace_id != &self.workspace_id {
            return Err(ApplicationError::AccessDenied);
        }
        let mut transaction = self
            .store
            .begin_tenant(workspace_id.clone())
            .map_err(map_application_error)?;
        let rows = transaction
            .query(
                FIND_TRIP_SQL,
                &[
                    PostgresParameter::Text(workspace_id.as_str()),
                    PostgresParameter::Text(trip_id.as_str()),
                ],
            )
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        if rows.len() > 1 {
            return Err(ApplicationError::StorageUnavailable);
        }
        let trip = rows
            .first()
            .map(|row| decrypt_trip_row(self.cipher, row, workspace_id, Some(trip_id), None))
            .transpose()
            .map_err(map_application_error)?;
        transaction
            .commit()
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        Ok(trip)
    }

    fn list_trips_for_owner(
        &self,
        workspace_id: &WorkspaceId,
        owner_subject_id: &PrincipalId,
    ) -> Result<Vec<Trip>, ApplicationError> {
        if workspace_id != &self.workspace_id {
            return Err(ApplicationError::AccessDenied);
        }
        let mut transaction = self
            .store
            .begin_tenant(workspace_id.clone())
            .map_err(map_application_error)?;
        let rows = transaction
            .query(
                LIST_OWNER_TRIPS_SQL,
                &[
                    PostgresParameter::Text(workspace_id.as_str()),
                    PostgresParameter::Text(owner_subject_id.as_str()),
                ],
            )
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        if rows.len() > MAX_OWNER_TRIPS {
            return Err(ApplicationError::StorageUnavailable);
        }
        let mut ids = BTreeSet::new();
        let trips = rows
            .iter()
            .map(|row| {
                let trip =
                    decrypt_trip_row(self.cipher, row, workspace_id, None, Some(owner_subject_id))?;
                if !ids.insert(trip.id().as_str().to_owned()) {
                    return Err(PostgresStoreError::InvalidRow);
                }
                Ok(trip)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_application_error)?;
        transaction
            .commit()
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        Ok(trips)
    }
}

impl<Pool, Cipher> CheckpointMutationRepository for PostgresTenantMemoryStore<'_, '_, Pool, Cipher>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    Cipher: RecordCipher,
{
    fn insert_checkpoint_with_event(
        &mut self,
        checkpoint: ActivityCheckpoint,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        persist_checkpoint_mutation(self, &checkpoint, None, &event, expected_previous_sequence)
    }

    fn replace_checkpoint_with_event(
        &mut self,
        checkpoint: ActivityCheckpoint,
        expected_checkpoint_version: u64,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        if !is_strict_successor(expected_checkpoint_version, checkpoint.version()) {
            return Err(ApplicationError::VersionConflict);
        }
        persist_checkpoint_mutation(
            self,
            &checkpoint,
            Some(expected_checkpoint_version),
            &event,
            expected_previous_sequence,
        )
    }
}

impl<Pool, Cipher> CheckpointDisclosureRepository
    for PostgresTenantMemoryStore<'_, '_, Pool, Cipher>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    Cipher: RecordCipher,
{
    fn append_checkpoint_disclosure(
        &mut self,
        receipt: CheckpointDisclosureReceipt,
    ) -> Result<(), ApplicationError> {
        if receipt.workspace_id != self.workspace_id {
            return Err(ApplicationError::AccessDenied);
        }
        if receipt.purpose.trim().is_empty() || receipt.checkpoint_version == 0 {
            return Err(ApplicationError::Validation(
                "invalid checkpoint disclosure".to_owned(),
            ));
        }
        let mut transaction = self
            .store
            .begin_tenant(receipt.workspace_id.clone())
            .map_err(map_application_error)?;
        let rows = transaction
            .query(
                FIND_DISCLOSED_CHECKPOINT_VERSION_SQL,
                &[
                    PostgresParameter::Text(receipt.workspace_id.as_str()),
                    PostgresParameter::Text(receipt.checkpoint_id.as_str()),
                    PostgresParameter::Text(receipt.subject_id.as_str()),
                    PostgresParameter::Text(receipt.activity_id.as_str()),
                ],
            )
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
        if rows.len() > 1 {
            return Err(ApplicationError::StorageUnavailable);
        }
        let Some(row) = rows.first() else {
            return Err(ApplicationError::VersionConflict);
        };
        if !checkpoint_disclosure_row_matches(row, &receipt)? {
            return Err(ApplicationError::StorageUnavailable);
        }
        if row
            .u64("version")
            .map_err(PostgresStoreError::Row)
            .map_err(map_application_error)?
            != receipt.checkpoint_version
        {
            return Err(ApplicationError::VersionConflict);
        }
        execute_exactly_one(
            &mut transaction,
            INSERT_CHECKPOINT_DISCLOSURE_SQL,
            &[
                PostgresParameter::Text(receipt.workspace_id.as_str()),
                PostgresParameter::Text(receipt.id.as_str()),
                PostgresParameter::Text(receipt.checkpoint_id.as_str()),
                PostgresParameter::I64(
                    postgres_epoch::<Pool::Error>(receipt.checkpoint_version)
                        .map_err(map_application_error)?,
                ),
                PostgresParameter::Text(receipt.activity_id.as_str()),
                PostgresParameter::Text(receipt.subject_id.as_str()),
                PostgresParameter::Text(receipt.client_id.as_str()),
                PostgresParameter::Text(&receipt.purpose),
            ],
        )
        .map_err(map_application_error)?;
        transaction
            .commit()
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)
    }
}

fn checkpoint_disclosure_row_matches<Row, DriverError>(
    row: &Row,
    receipt: &CheckpointDisclosureReceipt,
) -> Result<bool, ApplicationError>
where
    Row: PostgresRow<Error = DriverError>,
    DriverError: ClassifiedPostgresError,
{
    Ok(row
        .text("workspace_id")
        .map_err(PostgresStoreError::Row)
        .map_err(map_application_error)?
        == receipt.workspace_id.as_str()
        && row
            .text("id")
            .map_err(PostgresStoreError::Row)
            .map_err(map_application_error)?
            == receipt.checkpoint_id.as_str()
        && row
            .text("subject_id")
            .map_err(PostgresStoreError::Row)
            .map_err(map_application_error)?
            == receipt.subject_id.as_str()
        && row
            .text("activity_id")
            .map_err(PostgresStoreError::Row)
            .map_err(map_application_error)?
            == receipt.activity_id.as_str())
}

fn persist_checkpoint_mutation<Pool, Cipher>(
    store: &PostgresTenantMemoryStore<'_, '_, Pool, Cipher>,
    checkpoint: &ActivityCheckpoint,
    expected_checkpoint_version: Option<u64>,
    event: &CanonicalEvent,
    expected_previous_sequence: u64,
) -> Result<(), ApplicationError>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    Cipher: RecordCipher,
{
    validate_checkpoint_event(checkpoint, event)?;
    if checkpoint.workspace_id() != &store.workspace_id {
        return Err(ApplicationError::AccessDenied);
    }
    if !is_strict_successor(expected_previous_sequence, event.sequence()) {
        return Err(ApplicationError::SequenceConflict);
    }
    let checkpoint_plaintext =
        encode_checkpoint(checkpoint).map_err(|_| ApplicationError::StorageUnavailable)?;
    let checkpoint_context = EncryptionContext::new(
        checkpoint.workspace_id().clone(),
        checkpoint.id().as_str(),
        checkpoint.version(),
        PayloadPurpose::ActivityCheckpoint,
    )
    .map_err(|_| ApplicationError::Validation("invalid checkpoint context".to_owned()))?;
    let encrypted_checkpoint = store
        .cipher
        .seal(&checkpoint_context, &checkpoint_plaintext)
        .map_err(|_| ApplicationError::StorageUnavailable)?;
    let event_plaintext = encode_event(event).map_err(|_| ApplicationError::StorageUnavailable)?;
    let event_context = EncryptionContext::new(
        event.workspace_id().clone(),
        event.id().as_str(),
        event.sequence(),
        PayloadPurpose::CanonicalEvent,
    )
    .map_err(|_| ApplicationError::Validation("invalid event context".to_owned()))?;
    let encrypted_event = store
        .cipher
        .seal(&event_context, &event_plaintext)
        .map_err(|_| ApplicationError::StorageUnavailable)?;
    let mut transaction = store
        .store
        .begin_tenant(checkpoint.workspace_id().clone())
        .map_err(map_event_application_error)?;
    require_event_sequence(
        &mut transaction,
        checkpoint.workspace_id(),
        expected_previous_sequence,
    )?;
    write_checkpoint(
        &mut transaction,
        checkpoint,
        expected_checkpoint_version,
        &encrypted_checkpoint,
    )?;
    insert_canonical_event(&mut transaction, event, &encrypted_event)?;
    transaction
        .commit()
        .map_err(PostgresStoreError::Tenant)
        .map_err(map_event_application_error)
}

impl<Pool, Cipher> EventRepository for PostgresTenantMemoryStore<'_, '_, Pool, Cipher>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    Cipher: RecordCipher,
{
    fn append_event(
        &mut self,
        event: CanonicalEvent,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        if event.workspace_id() != &self.workspace_id
            || !is_strict_successor(expected_previous_sequence, event.sequence())
        {
            return Err(ApplicationError::SequenceConflict);
        }
        let plaintext = encode_event(&event).map_err(|_| ApplicationError::StorageUnavailable)?;
        let context = EncryptionContext::new(
            event.workspace_id().clone(),
            event.id().as_str(),
            event.sequence(),
            PayloadPurpose::CanonicalEvent,
        )
        .map_err(|_| ApplicationError::Validation("invalid event context".to_owned()))?;
        let encrypted = self
            .cipher
            .seal(&context, &plaintext)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let mut transaction = self
            .store
            .begin_tenant(event.workspace_id().clone())
            .map_err(map_application_error)?;
        let sequence_rows = transaction
            .query(
                CURRENT_EVENT_SEQUENCE_SQL,
                &[PostgresParameter::Text(event.workspace_id().as_str())],
            )
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_event_application_error)?;
        if sequence_rows.len() != 1
            || sequence_rows[0]
                .u64("current_sequence")
                .map_err(PostgresStoreError::Row)
                .map_err(map_event_application_error)?
                != expected_previous_sequence
        {
            return Err(ApplicationError::SequenceConflict);
        }
        execute_exactly_one(
            &mut transaction,
            INSERT_EVENT_SQL,
            &[
                PostgresParameter::Text(event.workspace_id().as_str()),
                PostgresParameter::I64(
                    postgres_epoch::<Pool::Error>(event.sequence())
                        .map_err(map_event_application_error)?,
                ),
                PostgresParameter::Text(event.id().as_str()),
                PostgresParameter::Text(event.actor_id().as_str()),
                PostgresParameter::OptionalText(event.subject_id().map(PrincipalId::as_str)),
                PostgresParameter::Text(event_type(&event)),
                PostgresParameter::Bytes(encrypted.ciphertext()),
                PostgresParameter::Text(encrypted.key_id()),
                PostgresParameter::Text(encrypted.algorithm()),
                PostgresParameter::Bytes(encrypted.nonce()),
            ],
        )
        .map_err(map_event_application_error)?;
        transaction
            .commit()
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_event_application_error)
    }

    fn list_events_since(
        &self,
        workspace_id: &WorkspaceId,
        sequence: u64,
    ) -> Result<Vec<CanonicalEvent>, ApplicationError> {
        if workspace_id != &self.workspace_id {
            return Err(ApplicationError::AccessDenied);
        }
        let sequence =
            postgres_epoch::<Pool::Error>(sequence).map_err(map_event_application_error)?;
        let mut transaction = self
            .store
            .begin_tenant(workspace_id.clone())
            .map_err(map_event_application_error)?;
        let rows = transaction
            .query(
                LIST_EVENTS_SINCE_SQL,
                &[
                    PostgresParameter::Text(workspace_id.as_str()),
                    PostgresParameter::I64(sequence),
                ],
            )
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_event_application_error)?;
        if rows.len() > MAX_EVENT_STREAM_READ {
            return Err(ApplicationError::StorageUnavailable);
        }
        let mut sequences = BTreeSet::new();
        let events = rows
            .iter()
            .map(|row| {
                let event = decrypt_event_row(self.cipher, row, workspace_id)?;
                if !sequences.insert(event.sequence()) {
                    return Err(PostgresStoreError::InvalidRow);
                }
                Ok(event)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_event_application_error)?;
        transaction
            .commit()
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_event_application_error)?;
        Ok(events)
    }
}

impl<Pool, Cipher> CanonicalMutationRepository for PostgresTenantMemoryStore<'_, '_, Pool, Cipher>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    Cipher: RecordCipher,
{
    fn insert_memory_with_event(
        &mut self,
        memory: MemoryRecord,
        event: CanonicalEvent,
        projections: Vec<ProjectionJob>,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        persist_memory_mutation(
            self,
            &memory,
            None,
            &event,
            &projections,
            expected_previous_sequence,
        )
    }

    fn replace_memory_with_event(
        &mut self,
        memory: MemoryRecord,
        expected_memory_version: u64,
        event: CanonicalEvent,
        projections: Vec<ProjectionJob>,
        expected_previous_sequence: u64,
    ) -> Result<(), ApplicationError> {
        if !is_strict_successor(expected_memory_version, memory.version()) {
            return Err(ApplicationError::VersionConflict);
        }
        persist_memory_mutation(
            self,
            &memory,
            Some(expected_memory_version),
            &event,
            &projections,
            expected_previous_sequence,
        )
    }
}

fn persist_memory_mutation<Pool, Cipher>(
    store: &PostgresTenantMemoryStore<'_, '_, Pool, Cipher>,
    memory: &MemoryRecord,
    expected_memory_version: Option<u64>,
    event: &CanonicalEvent,
    projections: &[ProjectionJob],
    expected_previous_sequence: u64,
) -> Result<(), ApplicationError>
where
    Pool: PostgresPool,
    Pool::Error: ClassifiedPostgresError,
    <Pool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = Pool::Error>,
    Cipher: RecordCipher,
{
    validate_memory_mutation(memory, event, projections)?;
    if memory.workspace_id() != &store.workspace_id
        || !is_strict_successor(expected_previous_sequence, event.sequence())
    {
        return Err(ApplicationError::SequenceConflict);
    }
    let memory_plaintext =
        encode_memory(memory).map_err(|_| ApplicationError::StorageUnavailable)?;
    let memory_context = EncryptionContext::new(
        memory.workspace_id().clone(),
        memory.id().as_str(),
        memory.version(),
        PayloadPurpose::MemoryContent,
    )
    .map_err(|_| ApplicationError::Validation("invalid memory context".to_owned()))?;
    let encrypted_memory = store
        .cipher
        .seal(&memory_context, &memory_plaintext)
        .map_err(|_| ApplicationError::StorageUnavailable)?;
    let event_plaintext = encode_event(event).map_err(|_| ApplicationError::StorageUnavailable)?;
    let event_context = EncryptionContext::new(
        event.workspace_id().clone(),
        event.id().as_str(),
        event.sequence(),
        PayloadPurpose::CanonicalEvent,
    )
    .map_err(|_| ApplicationError::Validation("invalid event context".to_owned()))?;
    let encrypted_event = store
        .cipher
        .seal(&event_context, &event_plaintext)
        .map_err(|_| ApplicationError::StorageUnavailable)?;
    let mut transaction = store
        .store
        .begin_tenant(memory.workspace_id().clone())
        .map_err(map_event_application_error)?;
    require_event_sequence(
        &mut transaction,
        memory.workspace_id(),
        expected_previous_sequence,
    )?;
    write_memory(
        &mut transaction,
        memory,
        expected_memory_version,
        &encrypted_memory,
    )?;
    if expected_memory_version.is_some() {
        transaction
            .execute(
                DELETE_MEMORY_EVIDENCE_SQL,
                &[
                    PostgresParameter::Text(memory.workspace_id().as_str()),
                    PostgresParameter::Text(memory.id().as_str()),
                ],
            )
            .map_err(PostgresStoreError::Tenant)
            .map_err(map_application_error)?;
    }
    insert_memory_evidence(&mut transaction, memory)?;
    insert_canonical_event(&mut transaction, event, &encrypted_event)?;
    insert_projection_jobs(&mut transaction, projections)?;
    transaction
        .commit()
        .map_err(PostgresStoreError::Tenant)
        .map_err(map_event_application_error)
}

impl<RuntimePool, ProvisioningPool> WorkspaceRepository
    for PostgresWorkspaceAdminStore<RuntimePool, ProvisioningPool>
where
    RuntimePool: PostgresPool,
    RuntimePool::Error: ClassifiedPostgresError,
    <RuntimePool::Transaction as PostgresTransaction>::Row: PostgresRow<Error = RuntimePool::Error>,
    ProvisioningPool: PostgresProvisioningPool,
    ProvisioningPool::Error: ClassifiedPostgresError,
{
    fn initialize_personal_workspace(
        &mut self,
        principal: Principal,
        workspace: Workspace,
        owner_membership: Membership,
    ) -> Result<(), ApplicationError> {
        if workspace.id() != &self.workspace_id {
            return Err(ApplicationError::AccessDenied);
        }
        self.provisioner
            .initialize_personal_workspace(&principal, &workspace, &owner_membership)
            .map_err(map_workspace_application_error)
    }

    fn initialize_shared_workspace(
        &mut self,
        workspace: Workspace,
        owner_membership: Membership,
    ) -> Result<(), ApplicationError> {
        if workspace.id() != &self.workspace_id {
            return Err(ApplicationError::AccessDenied);
        }
        self.provisioner
            .initialize_shared_workspace(&workspace, &owner_membership)
            .map_err(map_workspace_application_error)
    }

    fn find_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Option<Principal>, ApplicationError> {
        self.provisioner
            .find_principal(principal_id)
            .map_err(map_workspace_application_error)
    }

    fn find_workspace(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<Workspace>, ApplicationError> {
        if workspace_id != &self.workspace_id {
            return Err(ApplicationError::AccessDenied);
        }
        self.runtime
            .find_workspace(workspace_id)
            .map_err(map_application_error)
    }
}

fn map_application_error<DriverError>(error: PostgresStoreError<DriverError>) -> ApplicationError
where
    DriverError: ClassifiedPostgresError,
{
    match error {
        PostgresStoreError::MissingRow => ApplicationError::NotFound,
        PostgresStoreError::Begin(error)
        | PostgresStoreError::Row(error)
        | PostgresStoreError::Tenant(TenantTransactionError::Driver(error)) => match error.kind() {
            PostgresFailureKind::UniqueViolation => ApplicationError::AlreadyExists,
            PostgresFailureKind::ForeignKeyViolation | PostgresFailureKind::CheckViolation => {
                ApplicationError::Validation(
                    "database constraint rejected the membership".to_owned(),
                )
            }
            PostgresFailureKind::SerializationFailure | PostgresFailureKind::Other => {
                ApplicationError::StorageUnavailable
            }
        },
        PostgresStoreError::Tenant(
            TenantTransactionError::MissingTenant
            | TenantTransactionError::TenantMismatch
            | TenantTransactionError::Closed,
        )
        | PostgresStoreError::InvalidRow
        | PostgresStoreError::InvalidLimit
        | PostgresStoreError::InvalidInput
        | PostgresStoreError::VersionConflict
        | PostgresStoreError::UnexpectedCardinality => ApplicationError::StorageUnavailable,
    }
}

fn map_workspace_application_error<DriverError>(
    error: PostgresStoreError<DriverError>,
) -> ApplicationError
where
    DriverError: ClassifiedPostgresError,
{
    match error {
        PostgresStoreError::InvalidInput => {
            ApplicationError::Validation("invalid workspace bootstrap request".to_owned())
        }
        other => map_application_error(other),
    }
}

fn map_audit_application_error<DriverError>(
    error: PostgresStoreError<DriverError>,
) -> ApplicationError
where
    DriverError: ClassifiedPostgresError,
{
    match error {
        PostgresStoreError::InvalidInput | PostgresStoreError::InvalidLimit => {
            ApplicationError::Validation("invalid administrative audit request".to_owned())
        }
        other => map_application_error(other),
    }
}

fn map_retention_application_error<DriverError>(
    error: PostgresStoreError<DriverError>,
) -> ApplicationError
where
    DriverError: ClassifiedPostgresError,
{
    match error {
        PostgresStoreError::InvalidInput => {
            ApplicationError::Validation("invalid retention persistence request".to_owned())
        }
        PostgresStoreError::VersionConflict => ApplicationError::VersionConflict,
        other => map_application_error(other),
    }
}

fn map_scope_application_error<DriverError>(
    error: PostgresStoreError<DriverError>,
) -> ApplicationError
where
    DriverError: ClassifiedPostgresError,
{
    match error {
        PostgresStoreError::InvalidInput => {
            ApplicationError::Validation("invalid member scope persistence request".to_owned())
        }
        other => map_application_error(other),
    }
}

fn map_key_rotation_application_error<DriverError>(
    error: PostgresStoreError<DriverError>,
) -> ApplicationError
where
    DriverError: ClassifiedPostgresError,
{
    match error {
        PostgresStoreError::InvalidInput => {
            ApplicationError::Validation("invalid key rotation persistence request".to_owned())
        }
        PostgresStoreError::VersionConflict => ApplicationError::VersionConflict,
        other => map_application_error(other),
    }
}

fn map_event_application_error<DriverError>(
    error: PostgresStoreError<DriverError>,
) -> ApplicationError
where
    DriverError: ClassifiedPostgresError,
{
    match error {
        PostgresStoreError::VersionConflict => ApplicationError::SequenceConflict,
        PostgresStoreError::Begin(error)
        | PostgresStoreError::Row(error)
        | PostgresStoreError::Tenant(TenantTransactionError::Driver(error))
            if error.kind() == PostgresFailureKind::SerializationFailure =>
        {
            ApplicationError::SequenceConflict
        }
        other => map_application_error(other),
    }
}

fn map_invitation_application_error<DriverError>(
    error: PostgresStoreError<DriverError>,
) -> ApplicationError
where
    DriverError: ClassifiedPostgresError,
{
    match error {
        PostgresStoreError::InvalidInput | PostgresStoreError::InvalidLimit => {
            ApplicationError::Validation("invalid invitation persistence request".to_owned())
        }
        PostgresStoreError::VersionConflict => ApplicationError::VersionConflict,
        PostgresStoreError::Begin(error)
        | PostgresStoreError::Row(error)
        | PostgresStoreError::Tenant(TenantTransactionError::Driver(error))
            if error.kind() == PostgresFailureKind::ForeignKeyViolation =>
        {
            ApplicationError::NotFound
        }
        other => map_application_error(other),
    }
}

fn postgres_epoch<DriverError>(epoch_seconds: u64) -> Result<i64, PostgresStoreError<DriverError>> {
    i64::try_from(epoch_seconds).map_err(|_| PostgresStoreError::InvalidInput)
}

fn provisioning_execute_exactly_one<Transaction>(
    transaction: &mut ProvisioningTransaction<Transaction>,
    statement: &str,
    parameters: &[PostgresParameter<'_>],
) -> Result<(), PostgresStoreError<Transaction::Error>>
where
    Transaction: PostgresTransaction,
{
    let changed = transaction
        .execute(statement, parameters)
        .map_err(PostgresStoreError::Tenant)?;
    if changed != 1 {
        return Err(PostgresStoreError::UnexpectedCardinality);
    }
    Ok(())
}

fn valid_personal_bootstrap(
    principal: &Principal,
    workspace: &Workspace,
    membership: &Membership,
) -> bool {
    workspace.kind() == WorkspaceKind::Personal
        && membership.workspace_id() == workspace.id()
        && membership.principal_id() == principal.id()
        && membership.role() == WorkspaceRole::Owner
        && membership.is_active()
}

fn valid_shared_bootstrap(workspace: &Workspace, membership: &Membership) -> bool {
    workspace.kind() == WorkspaceKind::Shared
        && membership.workspace_id() == workspace.id()
        && membership.role() == WorkspaceRole::Owner
        && membership.is_active()
}

fn execute_exactly_one<Transaction>(
    transaction: &mut TenantTransaction<Transaction>,
    statement: &str,
    parameters: &[PostgresParameter<'_>],
) -> Result<(), PostgresStoreError<Transaction::Error>>
where
    Transaction: PostgresTransaction,
{
    let changed = transaction
        .execute(statement, parameters)
        .map_err(PostgresStoreError::Tenant)?;
    if changed != 1 {
        return Err(PostgresStoreError::UnexpectedCardinality);
    }
    Ok(())
}

fn insert_administrative_audit<Transaction>(
    transaction: &mut TenantTransaction<Transaction>,
    event: &AdministrativeAuditEvent,
) -> Result<(), PostgresStoreError<Transaction::Error>>
where
    Transaction: PostgresTransaction,
{
    let occurred_at = postgres_epoch(event.occurred_at_epoch_seconds())?;
    execute_exactly_one(
        transaction,
        INSERT_ADMINISTRATIVE_AUDIT_SQL,
        &[
            PostgresParameter::Text(event.workspace_id().as_str()),
            PostgresParameter::Text(event.id().as_str()),
            PostgresParameter::Text(event.actor_id().as_str()),
            PostgresParameter::Text(event.action().label()),
            PostgresParameter::Text(event.target_kind().label()),
            PostgresParameter::Text(event.target_id()),
            PostgresParameter::Text(event.request_id()),
            PostgresParameter::I64(occurred_at),
        ],
    )
}

fn require_event_sequence<Transaction>(
    transaction: &mut TenantTransaction<Transaction>,
    workspace_id: &WorkspaceId,
    expected_previous_sequence: u64,
) -> Result<(), ApplicationError>
where
    Transaction: PostgresTransaction,
    Transaction::Error: ClassifiedPostgresError,
    Transaction::Row: PostgresRow<Error = Transaction::Error>,
{
    let rows = transaction
        .query(
            CURRENT_EVENT_SEQUENCE_SQL,
            &[PostgresParameter::Text(workspace_id.as_str())],
        )
        .map_err(PostgresStoreError::Tenant)
        .map_err(map_event_application_error)?;
    if rows.len() != 1
        || rows[0]
            .u64("current_sequence")
            .map_err(PostgresStoreError::Row)
            .map_err(map_event_application_error)?
            != expected_previous_sequence
    {
        return Err(ApplicationError::SequenceConflict);
    }
    Ok(())
}

fn write_memory<Transaction>(
    transaction: &mut TenantTransaction<Transaction>,
    memory: &MemoryRecord,
    expected_version: Option<u64>,
    encrypted: &EncryptedPayload,
) -> Result<(), ApplicationError>
where
    Transaction: PostgresTransaction,
    Transaction::Error: ClassifiedPostgresError,
{
    let (scope_type, scope_value) = encode_memory_scope(memory.scope());
    let mut parameters = vec![
        PostgresParameter::Text(memory.workspace_id().as_str()),
        PostgresParameter::Text(memory.id().as_str()),
        PostgresParameter::Text(memory.subject_id().as_str()),
        PostgresParameter::Text(scope_type),
        PostgresParameter::OptionalText(scope_value),
        PostgresParameter::Text(memory_kind_name(memory.kind())),
        PostgresParameter::Text(memory_status_name(memory.status())),
        PostgresParameter::Bytes(encrypted.ciphertext()),
        PostgresParameter::Text(encrypted.key_id()),
        PostgresParameter::Text(encrypted.algorithm()),
        PostgresParameter::Bytes(encrypted.nonce()),
        PostgresParameter::I64(
            postgres_epoch::<Transaction::Error>(memory.version())
                .map_err(map_application_error)?,
        ),
    ];
    let statement = if let Some(expected_version) = expected_version {
        parameters.push(PostgresParameter::I64(
            postgres_epoch::<Transaction::Error>(expected_version)
                .map_err(map_application_error)?,
        ));
        REPLACE_MEMORY_SQL
    } else {
        INSERT_MEMORY_SQL
    };
    let changed = transaction
        .execute(statement, &parameters)
        .map_err(PostgresStoreError::Tenant)
        .map_err(map_application_error)?;
    if changed != 1 {
        return Err(if expected_version.is_some() {
            ApplicationError::VersionConflict
        } else {
            ApplicationError::StorageUnavailable
        });
    }
    Ok(())
}

fn write_checkpoint<Transaction>(
    transaction: &mut TenantTransaction<Transaction>,
    checkpoint: &ActivityCheckpoint,
    expected_version: Option<u64>,
    encrypted: &EncryptedPayload,
) -> Result<(), ApplicationError>
where
    Transaction: PostgresTransaction,
    Transaction::Error: ClassifiedPostgresError,
{
    let mut parameters = vec![
        PostgresParameter::Text(checkpoint.workspace_id().as_str()),
        PostgresParameter::Text(checkpoint.id().as_str()),
        PostgresParameter::Text(checkpoint.subject_id().as_str()),
        PostgresParameter::Text(checkpoint.activity_id().as_str()),
        PostgresParameter::OptionalText(checkpoint.entity_id().map(EntityId::as_str)),
        PostgresParameter::Bytes(encrypted.ciphertext()),
        PostgresParameter::Text(encrypted.key_id()),
        PostgresParameter::Text(encrypted.algorithm()),
        PostgresParameter::Bytes(encrypted.nonce()),
        PostgresParameter::I64(
            postgres_epoch::<Transaction::Error>(checkpoint.version())
                .map_err(map_application_error)?,
        ),
    ];
    let statement = if let Some(expected_version) = expected_version {
        parameters.push(PostgresParameter::I64(
            postgres_epoch::<Transaction::Error>(expected_version)
                .map_err(map_application_error)?,
        ));
        REPLACE_CHECKPOINT_SQL
    } else {
        INSERT_CHECKPOINT_SQL
    };
    let changed = transaction
        .execute(statement, &parameters)
        .map_err(PostgresStoreError::Tenant)
        .map_err(map_application_error)?;
    if changed != 1 {
        return Err(if expected_version.is_some() {
            ApplicationError::VersionConflict
        } else {
            ApplicationError::StorageUnavailable
        });
    }
    Ok(())
}

fn insert_memory_evidence<Transaction>(
    transaction: &mut TenantTransaction<Transaction>,
    memory: &MemoryRecord,
) -> Result<(), ApplicationError>
where
    Transaction: PostgresTransaction,
    Transaction::Error: ClassifiedPostgresError,
{
    for (ordinal, evidence) in memory.evidence().iter().enumerate() {
        execute_exactly_one(
            transaction,
            INSERT_MEMORY_EVIDENCE_SQL,
            &[
                PostgresParameter::Text(memory.workspace_id().as_str()),
                PostgresParameter::Text(memory.id().as_str()),
                PostgresParameter::I64(i64::try_from(ordinal).map_err(|_| {
                    ApplicationError::Validation("too many evidence references".to_owned())
                })?),
                PostgresParameter::Text(evidence.id.as_str()),
                PostgresParameter::Text(evidence_source_name(evidence.source)),
            ],
        )
        .map_err(map_application_error)?;
    }
    Ok(())
}

fn insert_canonical_event<Transaction>(
    transaction: &mut TenantTransaction<Transaction>,
    event: &CanonicalEvent,
    encrypted: &EncryptedPayload,
) -> Result<(), ApplicationError>
where
    Transaction: PostgresTransaction,
    Transaction::Error: ClassifiedPostgresError,
{
    execute_exactly_one(
        transaction,
        INSERT_EVENT_SQL,
        &[
            PostgresParameter::Text(event.workspace_id().as_str()),
            PostgresParameter::I64(
                postgres_epoch::<Transaction::Error>(event.sequence())
                    .map_err(map_event_application_error)?,
            ),
            PostgresParameter::Text(event.id().as_str()),
            PostgresParameter::Text(event.actor_id().as_str()),
            PostgresParameter::OptionalText(event.subject_id().map(PrincipalId::as_str)),
            PostgresParameter::Text(event_type(event)),
            PostgresParameter::Bytes(encrypted.ciphertext()),
            PostgresParameter::Text(encrypted.key_id()),
            PostgresParameter::Text(encrypted.algorithm()),
            PostgresParameter::Bytes(encrypted.nonce()),
        ],
    )
    .map_err(map_event_application_error)
}

fn insert_projection_jobs<Transaction>(
    transaction: &mut TenantTransaction<Transaction>,
    projections: &[ProjectionJob],
) -> Result<(), ApplicationError>
where
    Transaction: PostgresTransaction,
    Transaction::Error: ClassifiedPostgresError,
{
    for projection in projections {
        execute_exactly_one(
            transaction,
            INSERT_PROJECTION_SQL,
            &[
                PostgresParameter::Text(projection.id().as_str()),
                PostgresParameter::Text(projection.workspace_id().as_str()),
                PostgresParameter::Text(projection.memory_id().as_str()),
                PostgresParameter::I64(
                    postgres_epoch::<Transaction::Error>(projection.memory_version())
                        .map_err(map_application_error)?,
                ),
                PostgresParameter::Text(projection.provider_id().as_str()),
                PostgresParameter::Text(projection_operation_name(projection.operation())),
                PostgresParameter::Text(projection_status_name(projection.status())),
                PostgresParameter::I64(i64::from(projection.attempts())),
            ],
        )
        .map_err(map_application_error)?;
    }
    Ok(())
}

fn valid_invitation_audit(
    invitation: &Invitation,
    event: &AdministrativeAuditEvent,
    action: AdministrativeAction,
) -> bool {
    event.workspace_id() == invitation.workspace_id()
        && event.action() == action
        && event.target_kind() == AdministrativeTargetKind::Invitation
        && event.target_id() == invitation.id().as_str()
}

fn valid_retention_audit(
    policy: &WorkspaceRetentionPolicy,
    event: &AdministrativeAuditEvent,
) -> bool {
    event.workspace_id() == policy.workspace_id()
        && event.action() == AdministrativeAction::RetentionPolicyChanged
        && event.target_kind() == AdministrativeTargetKind::RetentionPolicy
        && event.target_id() == policy.workspace_id().as_str()
}

fn valid_legal_hold_audit(
    hold: &WorkspaceLegalHold,
    event: &AdministrativeAuditEvent,
    action: AdministrativeAction,
) -> bool {
    event.workspace_id() == hold.workspace_id()
        && event.action() == action
        && event.target_kind() == AdministrativeTargetKind::LegalHold
        && event.target_id() == hold.id().as_str()
}

fn encode_read_scope(scope: &ReadScope) -> (&'static str, &str) {
    match scope {
        ReadScope::Global => ("global", ""),
        ReadScope::Domain { name } => ("domain", name),
        ReadScope::Entity { id } => ("entity", id.as_str()),
        ReadScope::Activity { id } => ("activity", id.as_str()),
    }
}

fn valid_scope_audit(grant: &MemberScopeGrant, event: &AdministrativeAuditEvent) -> bool {
    let (scope_type, scope_value) = encode_read_scope(grant.scope());
    let expected_target = if scope_value.is_empty() {
        format!("{}:{scope_type}", grant.principal_id().as_str())
    } else {
        format!(
            "{}:{scope_type}:{scope_value}",
            grant.principal_id().as_str()
        )
    };
    event.workspace_id() == grant.workspace_id()
        && event.action() == AdministrativeAction::ScopeGrantChanged
        && event.target_kind() == AdministrativeTargetKind::ScopeGrant
        && event.target_id() == expected_target
}

fn valid_completed_rotation(
    rotation: &WorkspaceKeyRotation,
    receipt: &KeyRotationReceipt,
    expected_generation: u64,
    audit_event: &AdministrativeAuditEvent,
) -> bool {
    rotation.status() == KeyRotationStatus::Completed
        && rotation.generation() == expected_generation
        && receipt.workspace_id() == rotation.workspace_id()
        && receipt.generation() == expected_generation
        && receipt.key_id() == rotation.completed_key_id().unwrap_or_default()
        && rotation
            .completed_by()
            .is_some_and(|completed_by| audit_event.actor_id() == completed_by)
        && audit_event.workspace_id() == rotation.workspace_id()
        && audit_event.action() == AdministrativeAction::KeyRotationCompleted
        && audit_event.target_kind() == AdministrativeTargetKind::KeyRotation
        && audit_event.target_id() == rotation.id().as_str()
}

fn valid_member_removal_audits(
    membership: &Membership,
    rotation_id: &KeyRotationId,
    requested_by: &PrincipalId,
    audit_events: &[AdministrativeAuditEvent],
) -> bool {
    if audit_events.len() != 2
        || audit_events[0].id() == audit_events[1].id()
        || audit_events.iter().any(|event| {
            event.workspace_id() != membership.workspace_id()
                || event.actor_id() != requested_by
                || event.request_id() != rotation_id.as_str()
        })
    {
        return false;
    }
    let member = audit_events.iter().any(|event| {
        event.action() == AdministrativeAction::MemberRemoved
            && event.target_kind() == AdministrativeTargetKind::Principal
            && event.target_id() == membership.principal_id().as_str()
    });
    let rotation = audit_events.iter().any(|event| {
        event.action() == AdministrativeAction::KeyRotationRequired
            && event.target_kind() == AdministrativeTargetKind::KeyRotation
            && event.target_id() == rotation_id.as_str()
    });
    member && rotation
}

fn legal_hold_parameters<DriverError>(
    hold: &WorkspaceLegalHold,
) -> Result<[PostgresParameter<'_>; 8], PostgresStoreError<DriverError>> {
    Ok([
        PostgresParameter::Text(hold.workspace_id().as_str()),
        PostgresParameter::Text(hold.id().as_str()),
        PostgresParameter::Text(hold.placed_by().as_str()),
        PostgresParameter::I64(postgres_epoch(hold.placed_at_epoch_seconds())?),
        PostgresParameter::Text(match hold.status() {
            LegalHoldStatus::Active => "active",
            LegalHoldStatus::Released => "released",
        }),
        PostgresParameter::I64(postgres_epoch(hold.version())?),
        PostgresParameter::OptionalText(hold.released_by().map(PrincipalId::as_str)),
        PostgresParameter::OptionalI64(
            hold.released_at_epoch_seconds()
                .map(postgres_epoch)
                .transpose()?,
        ),
    ])
}

fn retention_policy_parameters(
    policy: &WorkspaceRetentionPolicy,
) -> [PostgresParameter<'static>; 6] {
    let period = |resource| policy.period(resource).days_value().map(i64::from);
    [
        PostgresParameter::OptionalI64(period(RetentionResource::UserMemory)),
        PostgresParameter::OptionalI64(period(RetentionResource::ActivityCheckpoint)),
        PostgresParameter::OptionalI64(period(RetentionResource::TravelResearch)),
        PostgresParameter::OptionalI64(period(RetentionResource::DisclosureReceipt)),
        PostgresParameter::OptionalI64(period(RetentionResource::CanonicalEvent)),
        PostgresParameter::OptionalI64(period(RetentionResource::AdministrativeAudit)),
    ]
}

fn decode_administrative_audit<Row, DriverError>(
    row: &Row,
    expected_workspace_id: &WorkspaceId,
) -> Result<AdministrativeAuditEvent, PostgresStoreError<DriverError>>
where
    Row: PostgresRow<Error = DriverError>,
{
    let workspace_id = row.text("workspace_id").map_err(PostgresStoreError::Row)?;
    if workspace_id != expected_workspace_id.as_str() {
        return Err(PostgresStoreError::InvalidRow);
    }
    let action = match row
        .text("action")
        .map_err(PostgresStoreError::Row)?
        .as_str()
    {
        "invitation-created" => AdministrativeAction::InvitationCreated,
        "invitation-accepted" => AdministrativeAction::InvitationAccepted,
        "invitation-revoked" => AdministrativeAction::InvitationRevoked,
        "member-removed" => AdministrativeAction::MemberRemoved,
        "key-rotation-required" => AdministrativeAction::KeyRotationRequired,
        "key-rotation-completed" => AdministrativeAction::KeyRotationCompleted,
        "scope-grant-changed" => AdministrativeAction::ScopeGrantChanged,
        "retention-policy-changed" => AdministrativeAction::RetentionPolicyChanged,
        "legal-hold-placed" => AdministrativeAction::LegalHoldPlaced,
        "legal-hold-released" => AdministrativeAction::LegalHoldReleased,
        "channel-binding-created" => AdministrativeAction::ChannelBindingCreated,
        "channel-binding-revoked" => AdministrativeAction::ChannelBindingRevoked,
        "channel-message-requeued" => AdministrativeAction::ChannelMessageRequeued,
        _ => return Err(PostgresStoreError::InvalidRow),
    };
    let target_kind = match row
        .text("target_kind")
        .map_err(PostgresStoreError::Row)?
        .as_str()
    {
        "invitation" => AdministrativeTargetKind::Invitation,
        "principal" => AdministrativeTargetKind::Principal,
        "key-rotation" => AdministrativeTargetKind::KeyRotation,
        "scope-grant" => AdministrativeTargetKind::ScopeGrant,
        "retention-policy" => AdministrativeTargetKind::RetentionPolicy,
        "legal-hold" => AdministrativeTargetKind::LegalHold,
        "channel-binding" => AdministrativeTargetKind::ChannelBinding,
        "channel-message" => AdministrativeTargetKind::ChannelMessage,
        _ => return Err(PostgresStoreError::InvalidRow),
    };
    AdministrativeAuditEvent::new(
        AdministrativeAuditEventId::new(row.text("id").map_err(PostgresStoreError::Row)?),
        WorkspaceId::new(workspace_id),
        PrincipalId::new(row.text("actor_id").map_err(PostgresStoreError::Row)?),
        action,
        target_kind,
        row.text("target_id").map_err(PostgresStoreError::Row)?,
        row.text("request_id").map_err(PostgresStoreError::Row)?,
        row.u64("occurred_at_epoch_seconds")
            .map_err(PostgresStoreError::Row)?,
    )
    .map_err(|_| PostgresStoreError::InvalidRow)
}

fn decode_retention_policy<Row, DriverError>(
    row: &Row,
    expected_workspace_id: &WorkspaceId,
) -> Result<WorkspaceRetentionPolicy, PostgresStoreError<DriverError>>
where
    Row: PostgresRow<Error = DriverError>,
{
    let workspace_id = row.text("workspace_id").map_err(PostgresStoreError::Row)?;
    if workspace_id != expected_workspace_id.as_str() {
        return Err(PostgresStoreError::InvalidRow);
    }
    WorkspaceRetentionPolicy::new(
        WorkspaceId::new(workspace_id),
        row.u64("version").map_err(PostgresStoreError::Row)?,
        decode_retention_period(row, "user_memory_days")?,
        decode_retention_period(row, "activity_checkpoint_days")?,
        decode_retention_period(row, "travel_research_days")?,
        decode_retention_period(row, "disclosure_receipt_days")?,
        decode_retention_period(row, "canonical_event_days")?,
        decode_retention_period(row, "administrative_audit_days")?,
    )
    .map_err(|_| PostgresStoreError::InvalidRow)
}

fn decode_retention_period<Row, DriverError>(
    row: &Row,
    column: &str,
) -> Result<RetentionPeriod, PostgresStoreError<DriverError>>
where
    Row: PostgresRow<Error = DriverError>,
{
    let days = row.u64(column).map_err(PostgresStoreError::Row)?;
    if days == 0 {
        return Ok(RetentionPeriod::Forever);
    }
    let days = u32::try_from(days).map_err(|_| PostgresStoreError::InvalidRow)?;
    RetentionPeriod::days(days).map_err(|_| PostgresStoreError::InvalidRow)
}

fn decode_legal_hold<Row, DriverError>(
    row: &Row,
    expected_workspace_id: &WorkspaceId,
    expected_hold_id: Option<&LegalHoldId>,
) -> Result<WorkspaceLegalHold, PostgresStoreError<DriverError>>
where
    Row: PostgresRow<Error = DriverError>,
{
    let workspace_id = row.text("workspace_id").map_err(PostgresStoreError::Row)?;
    let hold_id = row.text("id").map_err(PostgresStoreError::Row)?;
    if workspace_id != expected_workspace_id.as_str()
        || expected_hold_id.is_some_and(|expected| hold_id != expected.as_str())
    {
        return Err(PostgresStoreError::InvalidRow);
    }
    let status = match row
        .text("status")
        .map_err(PostgresStoreError::Row)?
        .as_str()
    {
        "active" => LegalHoldStatus::Active,
        "released" => LegalHoldStatus::Released,
        _ => return Err(PostgresStoreError::InvalidRow),
    };
    let released_by = row.text("released_by").map_err(PostgresStoreError::Row)?;
    let released_at = row
        .u64("released_at_epoch_seconds")
        .map_err(PostgresStoreError::Row)?;
    WorkspaceLegalHold::restore(
        LegalHoldId::new(hold_id),
        WorkspaceId::new(workspace_id),
        PrincipalId::new(row.text("placed_by").map_err(PostgresStoreError::Row)?),
        row.u64("placed_at_epoch_seconds")
            .map_err(PostgresStoreError::Row)?,
        status,
        row.u64("version").map_err(PostgresStoreError::Row)?,
        (!released_by.is_empty()).then(|| PrincipalId::new(released_by)),
        (released_at != 0).then_some(released_at),
    )
    .map_err(|_| PostgresStoreError::InvalidRow)
}

fn decode_workspace<Row, DriverError>(
    row: &Row,
    expected_id: &WorkspaceId,
) -> Result<Workspace, PostgresStoreError<DriverError>>
where
    Row: PostgresRow<Error = DriverError>,
{
    let id = row.text("id").map_err(PostgresStoreError::Row)?;
    if id != expected_id.as_str() {
        return Err(PostgresStoreError::InvalidRow);
    }
    match row.text("kind").map_err(PostgresStoreError::Row)?.as_str() {
        "personal" => Ok(Workspace::personal(WorkspaceId::new(id))),
        "shared" => Ok(Workspace::shared(WorkspaceId::new(id))),
        _ => Err(PostgresStoreError::InvalidRow),
    }
}

fn decode_member_scope_grant<Row, DriverError>(
    row: &Row,
    expected_workspace_id: &WorkspaceId,
    expected_principal_id: &PrincipalId,
) -> Result<MemberScopeGrant, PostgresStoreError<DriverError>>
where
    Row: PostgresRow<Error = DriverError>,
{
    let workspace_id = row.text("workspace_id").map_err(PostgresStoreError::Row)?;
    let principal_id = row.text("principal_id").map_err(PostgresStoreError::Row)?;
    if workspace_id != expected_workspace_id.as_str()
        || principal_id != expected_principal_id.as_str()
    {
        return Err(PostgresStoreError::InvalidRow);
    }
    let scope_value = row.text("scope_value").map_err(PostgresStoreError::Row)?;
    let scope = match row
        .text("scope_type")
        .map_err(PostgresStoreError::Row)?
        .as_str()
    {
        "global" if scope_value.is_empty() => ReadScope::Global,
        "domain" if !scope_value.is_empty() => ReadScope::Domain { name: scope_value },
        "entity" if !scope_value.is_empty() => ReadScope::Entity {
            id: EntityId::new(scope_value),
        },
        "activity" if !scope_value.is_empty() => ReadScope::Activity {
            id: ActivityId::new(scope_value),
        },
        _ => return Err(PostgresStoreError::InvalidRow),
    };
    Ok(MemberScopeGrant::new(
        WorkspaceId::new(workspace_id),
        PrincipalId::new(principal_id),
        scope,
    ))
}

fn decrypt_memory_row<Row, Cipher, DriverError>(
    cipher: &Cipher,
    row: &Row,
    expected_workspace_id: &WorkspaceId,
    expected_memory_id: &MemoryId,
    expected_subject_id: Option<&PrincipalId>,
) -> Result<MemoryRecord, PostgresStoreError<DriverError>>
where
    Row: PostgresRow<Error = DriverError>,
    Cipher: RecordCipher,
{
    let workspace_id = row.text("workspace_id").map_err(PostgresStoreError::Row)?;
    let memory_id = row.text("id").map_err(PostgresStoreError::Row)?;
    let subject_id = row.text("subject_id").map_err(PostgresStoreError::Row)?;
    if workspace_id != expected_workspace_id.as_str()
        || memory_id != expected_memory_id.as_str()
        || expected_subject_id.is_some_and(|expected| subject_id != expected.as_str())
    {
        return Err(PostgresStoreError::InvalidRow);
    }
    let version = row.u64("version").map_err(PostgresStoreError::Row)?;
    let context = EncryptionContext::new(
        expected_workspace_id.clone(),
        expected_memory_id.as_str(),
        version,
        PayloadPurpose::MemoryContent,
    )
    .map_err(|_| PostgresStoreError::InvalidRow)?;
    let payload = EncryptedPayload::new(
        row.bytes("content_ciphertext")
            .map_err(PostgresStoreError::Row)?,
        row.text("encryption_key_id")
            .map_err(PostgresStoreError::Row)?,
        row.text("encryption_algorithm")
            .map_err(PostgresStoreError::Row)?,
        row.bytes("encryption_nonce")
            .map_err(PostgresStoreError::Row)?,
    )
    .map_err(|_| PostgresStoreError::InvalidRow)?;
    let plaintext = cipher
        .open(&context, &payload)
        .map_err(|_| PostgresStoreError::InvalidRow)?;
    let memory = decode_memory(&plaintext).map_err(|_| PostgresStoreError::InvalidRow)?;
    if memory.workspace_id() != expected_workspace_id
        || memory.id() != expected_memory_id
        || memory.subject_id().as_str() != subject_id
        || memory.version() != version
    {
        return Err(PostgresStoreError::InvalidRow);
    }
    Ok(memory)
}

fn decrypt_checkpoint_row<Row, Cipher, DriverError>(
    cipher: &Cipher,
    row: &Row,
    expected_workspace_id: &WorkspaceId,
    expected_subject_id: &PrincipalId,
    expected_activity_id: Option<&ActivityId>,
) -> Result<ActivityCheckpoint, PostgresStoreError<DriverError>>
where
    Row: PostgresRow<Error = DriverError>,
    Cipher: RecordCipher,
{
    let workspace_id = row.text("workspace_id").map_err(PostgresStoreError::Row)?;
    let subject_id = row.text("subject_id").map_err(PostgresStoreError::Row)?;
    let activity_id = row.text("activity_id").map_err(PostgresStoreError::Row)?;
    if workspace_id != expected_workspace_id.as_str()
        || subject_id != expected_subject_id.as_str()
        || expected_activity_id.is_some_and(|expected| activity_id != expected.as_str())
    {
        return Err(PostgresStoreError::InvalidRow);
    }
    let checkpoint_id = row.text("id").map_err(PostgresStoreError::Row)?;
    let version = row.u64("version").map_err(PostgresStoreError::Row)?;
    let context = EncryptionContext::new(
        expected_workspace_id.clone(),
        &checkpoint_id,
        version,
        PayloadPurpose::ActivityCheckpoint,
    )
    .map_err(|_| PostgresStoreError::InvalidRow)?;
    let payload = EncryptedPayload::new(
        row.bytes("checkpoint_ciphertext")
            .map_err(PostgresStoreError::Row)?,
        row.text("encryption_key_id")
            .map_err(PostgresStoreError::Row)?,
        row.text("encryption_algorithm")
            .map_err(PostgresStoreError::Row)?,
        row.bytes("encryption_nonce")
            .map_err(PostgresStoreError::Row)?,
    )
    .map_err(|_| PostgresStoreError::InvalidRow)?;
    let plaintext = cipher
        .open(&context, &payload)
        .map_err(|_| PostgresStoreError::InvalidRow)?;
    let checkpoint = decode_checkpoint(&plaintext).map_err(|_| PostgresStoreError::InvalidRow)?;
    if checkpoint.workspace_id() != expected_workspace_id
        || checkpoint.subject_id() != expected_subject_id
        || checkpoint.activity_id().as_str() != activity_id
        || checkpoint.id().as_str() != checkpoint_id
        || checkpoint.version() != version
    {
        return Err(PostgresStoreError::InvalidRow);
    }
    Ok(checkpoint)
}

fn decrypt_trip_row<Row, Cipher, DriverError>(
    cipher: &Cipher,
    row: &Row,
    expected_workspace_id: &WorkspaceId,
    expected_trip_id: Option<&EntityId>,
    expected_owner_subject_id: Option<&PrincipalId>,
) -> Result<Trip, PostgresStoreError<DriverError>>
where
    Row: PostgresRow<Error = DriverError>,
    Cipher: RecordCipher,
{
    let workspace_id = row.text("workspace_id").map_err(PostgresStoreError::Row)?;
    let trip_id = row.text("id").map_err(PostgresStoreError::Row)?;
    let owner_subject_id = row
        .text("owner_subject_id")
        .map_err(PostgresStoreError::Row)?;
    let version = row.u64("version").map_err(PostgresStoreError::Row)?;
    if workspace_id != expected_workspace_id.as_str()
        || expected_trip_id.is_some_and(|expected| expected.as_str() != trip_id)
        || expected_owner_subject_id.is_some_and(|expected| expected.as_str() != owner_subject_id)
    {
        return Err(PostgresStoreError::InvalidRow);
    }
    let context = EncryptionContext::new(
        expected_workspace_id.clone(),
        &trip_id,
        version,
        PayloadPurpose::TripEntity,
    )
    .map_err(|_| PostgresStoreError::InvalidRow)?;
    let encrypted = EncryptedPayload::new(
        row.bytes("trip_ciphertext")
            .map_err(PostgresStoreError::Row)?,
        row.text("encryption_key_id")
            .map_err(PostgresStoreError::Row)?,
        row.text("encryption_algorithm")
            .map_err(PostgresStoreError::Row)?,
        row.bytes("encryption_nonce")
            .map_err(PostgresStoreError::Row)?,
    )
    .map_err(|_| PostgresStoreError::InvalidRow)?;
    let plaintext = cipher
        .open(&context, &encrypted)
        .map_err(|_| PostgresStoreError::InvalidRow)?;
    let trip = decode_trip(&plaintext).map_err(|_| PostgresStoreError::InvalidRow)?;
    if trip.workspace_id() != expected_workspace_id
        || trip.id().as_str() != trip_id
        || trip.owner_subject_id().as_str() != owner_subject_id
        || trip.version() != version
    {
        return Err(PostgresStoreError::InvalidRow);
    }
    Ok(trip)
}

fn decrypt_event_row<Row, Cipher, DriverError>(
    cipher: &Cipher,
    row: &Row,
    expected_workspace_id: &WorkspaceId,
) -> Result<CanonicalEvent, PostgresStoreError<DriverError>>
where
    Row: PostgresRow<Error = DriverError>,
    Cipher: RecordCipher,
{
    let workspace_id = row.text("workspace_id").map_err(PostgresStoreError::Row)?;
    if workspace_id != expected_workspace_id.as_str() {
        return Err(PostgresStoreError::InvalidRow);
    }
    let event_id = row.text("id").map_err(PostgresStoreError::Row)?;
    let sequence = row.u64("sequence").map_err(PostgresStoreError::Row)?;
    let context = EncryptionContext::new(
        expected_workspace_id.clone(),
        &event_id,
        sequence,
        PayloadPurpose::CanonicalEvent,
    )
    .map_err(|_| PostgresStoreError::InvalidRow)?;
    let payload = EncryptedPayload::new(
        row.bytes("payload_ciphertext")
            .map_err(PostgresStoreError::Row)?,
        row.text("encryption_key_id")
            .map_err(PostgresStoreError::Row)?,
        row.text("encryption_algorithm")
            .map_err(PostgresStoreError::Row)?,
        row.bytes("encryption_nonce")
            .map_err(PostgresStoreError::Row)?,
    )
    .map_err(|_| PostgresStoreError::InvalidRow)?;
    let plaintext = cipher
        .open(&context, &payload)
        .map_err(|_| PostgresStoreError::InvalidRow)?;
    let event = decode_event(&plaintext).map_err(|_| PostgresStoreError::InvalidRow)?;
    if event.workspace_id() != expected_workspace_id
        || event.id().as_str() != event_id
        || event.sequence() != sequence
        || event.actor_id().as_str() != row.text("actor_id").map_err(PostgresStoreError::Row)?
        || event.subject_id().map(PrincipalId::as_str)
            != optional_row_text(row, "subject_id")?.as_deref()
        || event_type(&event) != row.text("event_type").map_err(PostgresStoreError::Row)?
    {
        return Err(PostgresStoreError::InvalidRow);
    }
    Ok(event)
}

fn optional_row_text<Row, DriverError>(
    row: &Row,
    column: &str,
) -> Result<Option<String>, PostgresStoreError<DriverError>>
where
    Row: PostgresRow<Error = DriverError>,
{
    let value = row.text(column).map_err(PostgresStoreError::Row)?;
    Ok((!value.is_empty()).then_some(value))
}

const fn event_type(event: &CanonicalEvent) -> &'static str {
    match event.payload() {
        EventPayload::MemoryProposed { .. } => "memory-proposed",
        EventPayload::MemoryConfirmed { .. } => "memory-confirmed",
        EventPayload::MemoryCreated { .. } => "memory-created",
        EventPayload::MemoryRevised { .. } => "memory-revised",
        EventPayload::MemoryDeleted { .. } => "memory-deleted",
        EventPayload::MemoryShareProposed { .. } => "memory-share-proposed",
        EventPayload::MemoryShareApproved { .. } => "memory-share-approved",
        EventPayload::MemoryShareRejected { .. } => "memory-share-rejected",
        EventPayload::MemoryShareRevoked { .. } => "memory-share-revoked",
        EventPayload::MemorySharedIn { .. } => "memory-shared-in",
        EventPayload::ObservationCaptured { .. } => "observation-captured",
        EventPayload::ActivityCheckpointed { .. } => "activity-checkpointed",
        EventPayload::TripCreated { .. } => "trip-created",
        EventPayload::TripRevised { .. } => "trip-revised",
        EventPayload::BookingResearchCaptured { .. } => "booking-research-captured",
        EventPayload::DisclosureRecorded { .. } => "disclosure-recorded",
    }
}

fn validate_memory_mutation(
    memory: &MemoryRecord,
    event: &CanonicalEvent,
    projections: &[ProjectionJob],
) -> Result<(), ApplicationError> {
    if memory.workspace_id() != event.workspace_id()
        || event.subject_id() != Some(memory.subject_id())
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

fn validate_checkpoint_event(
    checkpoint: &ActivityCheckpoint,
    event: &CanonicalEvent,
) -> Result<(), ApplicationError> {
    if checkpoint.workspace_id() != event.workspace_id()
        || event.subject_id() != Some(checkpoint.subject_id())
        || !matches!(
            event.payload(),
            EventPayload::ActivityCheckpointed {
                activity_id,
                version,
            } if activity_id == checkpoint.activity_id() && *version == checkpoint.version()
        )
    {
        return Err(ApplicationError::Validation(
            "event does not describe activity checkpoint".to_owned(),
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
        _ => return false,
    };
    compatible_status && memory_id == memory.id() && *version == memory.version()
}

fn encode_memory_scope(scope: &MemoryScope) -> (&'static str, Option<&str>) {
    match scope {
        MemoryScope::Global => ("global", None),
        MemoryScope::Domain { name } => ("domain", Some(name)),
        MemoryScope::Entity { id } => ("entity", Some(id.as_str())),
        MemoryScope::Activity { id } => ("activity", Some(id.as_str())),
    }
}

const fn memory_kind_name(kind: MemoryKind) -> &'static str {
    match kind {
        MemoryKind::Preference => "preference",
        MemoryKind::Semantic => "semantic",
        MemoryKind::Episodic => "episodic",
        MemoryKind::Procedural => "procedural",
        MemoryKind::Observation => "observation",
        MemoryKind::Working => "working",
    }
}

const fn memory_status_name(status: MemoryStatus) -> &'static str {
    match status {
        MemoryStatus::Proposed => "proposed",
        MemoryStatus::Confirmed => "confirmed",
        MemoryStatus::Superseded => "superseded",
        MemoryStatus::Deleted => "deleted",
    }
}

const fn evidence_source_name(source: EvidenceSource) -> &'static str {
    match source {
        EvidenceSource::UserStatement => "user-statement",
        EvidenceSource::AgentObservation => "agent-observation",
        EvidenceSource::ToolResult => "tool-result",
        EvidenceSource::ImportedRecord => "imported-record",
        EvidenceSource::WorkspaceDecision => "workspace-decision",
    }
}

const fn projection_operation_name(operation: ProjectionOperation) -> &'static str {
    match operation {
        ProjectionOperation::Upsert => "upsert",
        ProjectionOperation::Delete => "delete",
    }
}

const fn projection_status_name(status: ProjectionStatus) -> &'static str {
    match status {
        ProjectionStatus::Pending => "pending",
        ProjectionStatus::Processing => "processing",
        ProjectionStatus::Completed => "completed",
        ProjectionStatus::Quarantined => "quarantined",
    }
}

fn decode_projection<Row, DriverError>(
    row: &Row,
    expected_workspace_id: &WorkspaceId,
    expected_job_id: Option<&ProjectionJobId>,
    expected_provider_id: Option<&ProviderId>,
) -> Result<ProjectionJob, PostgresStoreError<DriverError>>
where
    Row: PostgresRow<Error = DriverError>,
{
    let workspace_id = row.text("workspace_id").map_err(PostgresStoreError::Row)?;
    let job_id = row.text("id").map_err(PostgresStoreError::Row)?;
    let provider_id = row.text("provider_id").map_err(PostgresStoreError::Row)?;
    if workspace_id != expected_workspace_id.as_str()
        || expected_job_id.is_some_and(|expected| job_id != expected.as_str())
        || expected_provider_id.is_some_and(|expected| provider_id != expected.as_str())
    {
        return Err(PostgresStoreError::InvalidRow);
    }
    let operation = match row
        .text("operation")
        .map_err(PostgresStoreError::Row)?
        .as_str()
    {
        "upsert" => ProjectionOperation::Upsert,
        "delete" => ProjectionOperation::Delete,
        _ => return Err(PostgresStoreError::InvalidRow),
    };
    let status = match row
        .text("status")
        .map_err(PostgresStoreError::Row)?
        .as_str()
    {
        "pending" => ProjectionStatus::Pending,
        "processing" => ProjectionStatus::Processing,
        "completed" => ProjectionStatus::Completed,
        "quarantined" => ProjectionStatus::Quarantined,
        _ => return Err(PostgresStoreError::InvalidRow),
    };
    let attempts = u32::try_from(row.u64("attempts").map_err(PostgresStoreError::Row)?)
        .map_err(|_| PostgresStoreError::InvalidRow)?;
    ProjectionJob::restore(
        ProjectionJobId::new(job_id),
        WorkspaceId::new(workspace_id),
        MemoryId::new(row.text("memory_id").map_err(PostgresStoreError::Row)?),
        row.u64("memory_version").map_err(PostgresStoreError::Row)?,
        ProviderId::new(provider_id),
        operation,
        status,
        attempts,
    )
    .map_err(|_| PostgresStoreError::InvalidRow)
}

fn decode_key_rotation<Row, DriverError>(
    row: &Row,
    expected_workspace_id: &WorkspaceId,
) -> Result<WorkspaceKeyRotation, PostgresStoreError<DriverError>>
where
    Row: PostgresRow<Error = DriverError>,
{
    let workspace_id = row.text("workspace_id").map_err(PostgresStoreError::Row)?;
    if workspace_id != expected_workspace_id.as_str() {
        return Err(PostgresStoreError::InvalidRow);
    }
    let status = match row
        .text("status")
        .map_err(PostgresStoreError::Row)?
        .as_str()
    {
        "required" => KeyRotationStatus::Required,
        "completed" => KeyRotationStatus::Completed,
        _ => return Err(PostgresStoreError::InvalidRow),
    };
    let completed_key_id = row
        .text("completed_key_id")
        .map_err(PostgresStoreError::Row)?;
    let completed_by = row.text("completed_by").map_err(PostgresStoreError::Row)?;
    WorkspaceKeyRotation::restore(
        KeyRotationId::new(row.text("id").map_err(PostgresStoreError::Row)?),
        WorkspaceId::new(workspace_id),
        row.u64("generation").map_err(PostgresStoreError::Row)?,
        PrincipalId::new(
            row.text("removed_principal_id")
                .map_err(PostgresStoreError::Row)?,
        ),
        PrincipalId::new(row.text("requested_by").map_err(PostgresStoreError::Row)?),
        status,
        (!completed_key_id.is_empty()).then_some(completed_key_id),
        (!completed_by.is_empty()).then(|| PrincipalId::new(completed_by)),
    )
    .map_err(|_| PostgresStoreError::InvalidRow)
}

fn validate_rotation_receipt_header<Row, DriverError>(
    row: &Row,
    expected_workspace_id: &WorkspaceId,
    expected_rotation_id: &KeyRotationId,
) -> Result<(), PostgresStoreError<DriverError>>
where
    Row: PostgresRow<Error = DriverError>,
{
    let workspace_id = row.text("workspace_id").map_err(PostgresStoreError::Row)?;
    let rotation_id = row.text("rotation_id").map_err(PostgresStoreError::Row)?;
    if workspace_id != expected_workspace_id.as_str()
        || rotation_id != expected_rotation_id.as_str()
    {
        return Err(PostgresStoreError::InvalidRow);
    }
    Ok(())
}

fn decode_principal<Row, DriverError>(
    row: &Row,
    expected_id: &PrincipalId,
) -> Result<Principal, PostgresStoreError<DriverError>>
where
    Row: PostgresRow<Error = DriverError>,
{
    let id = row.text("id").map_err(PostgresStoreError::Row)?;
    if id != expected_id.as_str() {
        return Err(PostgresStoreError::InvalidRow);
    }
    Ok(Principal::new(PrincipalId::new(id)))
}

fn decode_membership<Row, DriverError>(
    row: &Row,
    expected_workspace_id: &WorkspaceId,
    expected_principal_id: &PrincipalId,
) -> Result<Membership, PostgresStoreError<DriverError>>
where
    Row: PostgresRow<Error = DriverError>,
{
    let workspace_id = row.text("workspace_id").map_err(PostgresStoreError::Row)?;
    let principal_id = row.text("principal_id").map_err(PostgresStoreError::Row)?;
    if workspace_id != expected_workspace_id.as_str()
        || principal_id != expected_principal_id.as_str()
    {
        return Err(PostgresStoreError::InvalidRow);
    }
    let role = match row.text("role").map_err(PostgresStoreError::Row)?.as_str() {
        "owner" => WorkspaceRole::Owner,
        "admin" => WorkspaceRole::Admin,
        "member" => WorkspaceRole::Member,
        "viewer" => WorkspaceRole::Viewer,
        _ => return Err(PostgresStoreError::InvalidRow),
    };
    let membership = Membership::new(
        WorkspaceId::new(workspace_id),
        PrincipalId::new(principal_id),
        role,
    );
    match row
        .text("status")
        .map_err(PostgresStoreError::Row)?
        .as_str()
    {
        "active" => Ok(membership),
        "suspended" => Ok(membership.suspend()),
        "removed" => Ok(membership.remove()),
        _ => Err(PostgresStoreError::InvalidRow),
    }
}

fn decode_invitation<Row, DriverError>(
    row: &Row,
    expected_workspace_id: &WorkspaceId,
    expected_invitation_id: Option<&InvitationId>,
) -> Result<Invitation, PostgresStoreError<DriverError>>
where
    Row: PostgresRow<Error = DriverError>,
{
    let workspace_id = row.text("workspace_id").map_err(PostgresStoreError::Row)?;
    let invitation_id = row.text("id").map_err(PostgresStoreError::Row)?;
    if workspace_id != expected_workspace_id.as_str()
        || expected_invitation_id.is_some_and(|expected| invitation_id != expected.as_str())
    {
        return Err(PostgresStoreError::InvalidRow);
    }
    let invited_principal_id = row
        .text("invited_principal_id")
        .map_err(PostgresStoreError::Row)?;
    let invited_by = row.text("invited_by").map_err(PostgresStoreError::Row)?;
    let role = match row.text("role").map_err(PostgresStoreError::Row)?.as_str() {
        "admin" => WorkspaceRole::Admin,
        "member" => WorkspaceRole::Member,
        "viewer" => WorkspaceRole::Viewer,
        _ => return Err(PostgresStoreError::InvalidRow),
    };
    let status = row.text("status").map_err(PostgresStoreError::Row)?;
    let created_at = row
        .u64("created_at_epoch_seconds")
        .map_err(PostgresStoreError::Row)?;
    let expires_at = row
        .u64("expires_at_epoch_seconds")
        .map_err(PostgresStoreError::Row)?;
    let invitation = Invitation::new(
        InvitationId::new(invitation_id),
        WorkspaceId::new(workspace_id),
        PrincipalId::new(invited_principal_id),
        PrincipalId::new(invited_by),
        role,
        created_at,
        expires_at,
    )
    .map_err(|_| PostgresStoreError::InvalidRow)?;
    match status.as_str() {
        "pending" => Ok(invitation),
        "accepted" => invitation
            .accept_at(created_at)
            .map_err(|_| PostgresStoreError::InvalidRow),
        "revoked" => invitation
            .revoke()
            .map_err(|_| PostgresStoreError::InvalidRow),
        "expired" => invitation
            .expire_at(expires_at)
            .map_err(|_| PostgresStoreError::InvalidRow),
        _ => Err(PostgresStoreError::InvalidRow),
    }
}

const fn membership_role_name(role: WorkspaceRole) -> &'static str {
    match role {
        WorkspaceRole::Owner => "owner",
        WorkspaceRole::Admin => "admin",
        WorkspaceRole::Member => "member",
        WorkspaceRole::Viewer => "viewer",
    }
}

const fn invitation_status_name(status: InvitationStatus) -> &'static str {
    match status {
        InvitationStatus::Pending => "pending",
        InvitationStatus::Accepted => "accepted",
        InvitationStatus::Revoked => "revoked",
        InvitationStatus::Expired => "expired",
    }
}

fn membership_status_name(membership: &Membership) -> &'static str {
    membership_status_label(membership.status())
}

const fn membership_status_label(status: MembershipStatus) -> &'static str {
    match status {
        MembershipStatus::Active => "active",
        MembershipStatus::Suspended => "suspended",
        MembershipStatus::Removed => "removed",
    }
}

/// An owned `PostgreSQL` transaction whose RLS workspace has been read back and
/// proven to match the requested tenant.
pub struct TenantTransaction<Transaction: PostgresTransaction> {
    transaction: Option<Transaction>,
    workspace_id: WorkspaceId,
}

impl<Transaction: PostgresTransaction> TenantTransaction<Transaction> {
    /// Establishes transaction-local tenant state with one bound parameter and
    /// verifies the canonical database read-back before returning a queryable
    /// transaction.
    pub fn verify(
        mut transaction: Transaction,
        workspace_id: WorkspaceId,
    ) -> Result<Self, TenantTransactionError<Transaction::Error>> {
        let parameter = PostgresParameter::Text(workspace_id.as_str());
        if let Err(error) = transaction.execute(SET_TENANT_SQL, &[parameter]) {
            let _ = transaction.rollback();
            return Err(TenantTransactionError::Driver(error));
        }
        let tenant = match transaction.query_optional_text(READ_TENANT_SQL, &[]) {
            Ok(tenant) => tenant,
            Err(error) => {
                let _ = transaction.rollback();
                return Err(TenantTransactionError::Driver(error));
            }
        };
        match tenant {
            None => {
                let _ = transaction.rollback();
                Err(TenantTransactionError::MissingTenant)
            }
            Some(tenant) if tenant != workspace_id.as_str() => {
                let _ = transaction.rollback();
                Err(TenantTransactionError::TenantMismatch)
            }
            Some(_) => Ok(Self {
                transaction: Some(transaction),
                workspace_id,
            }),
        }
    }

    #[must_use]
    pub const fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }

    pub fn execute(
        &mut self,
        statement: &str,
        parameters: &[PostgresParameter<'_>],
    ) -> Result<u64, TenantTransactionError<Transaction::Error>> {
        self.revalidate()?;
        self.transaction_mut()?
            .execute(statement, parameters)
            .map_err(TenantTransactionError::Driver)
    }

    pub fn query(
        &mut self,
        statement: &str,
        parameters: &[PostgresParameter<'_>],
    ) -> Result<Vec<Transaction::Row>, TenantTransactionError<Transaction::Error>> {
        self.revalidate()?;
        self.transaction_mut()?
            .query(statement, parameters)
            .map_err(TenantTransactionError::Driver)
    }

    pub fn commit(mut self) -> Result<(), TenantTransactionError<Transaction::Error>> {
        self.take_transaction()?
            .commit()
            .map_err(TenantTransactionError::Driver)
    }

    pub fn rollback(mut self) -> Result<(), TenantTransactionError<Transaction::Error>> {
        self.take_transaction()?
            .rollback()
            .map_err(TenantTransactionError::Driver)
    }

    fn revalidate(&mut self) -> Result<(), TenantTransactionError<Transaction::Error>> {
        let tenant = self
            .transaction_mut()?
            .query_optional_text(READ_TENANT_SQL, &[])
            .map_err(TenantTransactionError::Driver);
        match tenant {
            Ok(Some(tenant)) if tenant == self.workspace_id.as_str() => Ok(()),
            Ok(Some(_)) => {
                self.rollback_open();
                Err(TenantTransactionError::TenantMismatch)
            }
            Ok(None) => {
                self.rollback_open();
                Err(TenantTransactionError::MissingTenant)
            }
            Err(error) => {
                self.rollback_open();
                Err(error)
            }
        }
    }

    fn rollback_open(&mut self) {
        if let Some(transaction) = self.transaction.take() {
            let _ = transaction.rollback();
        }
    }

    fn transaction_mut(
        &mut self,
    ) -> Result<&mut Transaction, TenantTransactionError<Transaction::Error>> {
        self.transaction
            .as_mut()
            .ok_or(TenantTransactionError::Closed)
    }

    fn take_transaction(
        &mut self,
    ) -> Result<Transaction, TenantTransactionError<Transaction::Error>> {
        self.transaction
            .take()
            .ok_or(TenantTransactionError::Closed)
    }
}

impl<Transaction: PostgresTransaction> Drop for TenantTransaction<Transaction> {
    fn drop(&mut self) {
        if let Some(transaction) = self.transaction.take() {
            let _ = transaction.rollback();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};
    use std::rc::Rc;

    use rembrane_application::{
        AdministrativeAuditRepository, ApplicationError, AuthorizeClientCommand,
        AuthorizeClientService, CanonicalMutationRepository, CheckpointDisclosureRepository,
        CheckpointMutationRepository, CheckpointRepository, CheckpointService,
        CreateInvitationCommand, DisclosureRepository, EventRepository, InvitationRepository,
        InvitationService, KeyRotationRepository, MemberLifecycleRepository,
        MemberScopeGrantRepository, MembershipRepository, MemoryRepository,
        ProjectionOutboxRepository, ProjectionOutcome, ProjectionWorker, ResolveContextCommand,
        ResolveContextService, ResumeActivityCommand, RetentionRepository, TripRepository,
        WorkspaceRepository,
    };
    use rembrane_codec::{encode_checkpoint, encode_memory, encode_trip};
    use rembrane_contracts::ResolveContextRequest;
    use rembrane_crypto::{CryptoError, EncryptedPayload, EncryptionContext, RecordCipher};
    use rembrane_domain::{
        ActivityCheckpoint, ActivityId, AdministrativeAction, AdministrativeAuditEvent,
        AdministrativeAuditEventId, AdministrativeTargetKind, CanonicalEvent,
        CheckpointDisclosureReceipt, CheckpointId, ClientId, ContextPackId, DisclosedMemory,
        DisclosureId, DisclosureReceipt, EntityId, EventId, EventPayload, EvidenceId,
        EvidenceReference, EvidenceSource, Invitation, InvitationId, InvitationStatus,
        KeyRotationId, KeyRotationReceipt, KeyRotationStatus, LegalHoldId, LegalHoldStatus,
        MemberScopeGrant, MembershipStatus, MemoryId, MemoryRecord, MemoryScope, Principal,
        PrincipalId, ProjectionJob, ProjectionJobId, ProjectionOperation, ProjectionStatus,
        ProviderId, ReadGrant, ReadScope, RetentionPeriod, RetentionResource, TravelDateWindow,
        Trip, Workspace, WorkspaceId, WorkspaceKeyRotation, WorkspaceRetentionPolicy,
        WorkspaceRole, WritePermission,
    };
    use rembrane_semantic_native::NativeSemanticProvider;

    use super::{
        ACCEPT_INVITATION_SQL, COMPLETE_KEY_ROTATION_SQL, CURRENT_EVENT_SEQUENCE_SQL,
        ClassifiedPostgresError, DELETE_MEMBER_SCOPE_GRANT_SQL, DELETE_MEMBER_SCOPE_GRANTS_SQL,
        EXPIRE_PENDING_INVITATION_SQL, FIND_DISCLOSED_CHECKPOINT_VERSION_SQL,
        FIND_DISCLOSED_MEMORY_VERSION_SQL, FIND_INVITATION_SQL, FIND_KEY_ROTATION_RECEIPT_SQL,
        FIND_LEGAL_HOLD_SQL, FIND_MEMBERSHIP_SQL, FIND_MEMORY_SQL, FIND_PRINCIPAL_SQL,
        FIND_PROJECTION_SQL, FIND_PROVISIONING_PRINCIPAL_SQL, FIND_RETENTION_POLICY_SQL,
        FIND_TRIP_SQL, FIND_WORKSPACE_SQL, INSERT_ADMINISTRATIVE_AUDIT_SQL,
        INSERT_CHECKPOINT_DISCLOSURE_SQL, INSERT_CHECKPOINT_SQL, INSERT_DISCLOSED_MEMORY_SQL,
        INSERT_DISCLOSURE_SQL, INSERT_EVENT_SQL, INSERT_INVITATION_SQL,
        INSERT_KEY_ROTATION_RECEIPT_SQL, INSERT_KEY_ROTATION_RECIPIENT_SQL, INSERT_LEGAL_HOLD_SQL,
        INSERT_MEMBER_SCOPE_GRANT_SQL, INSERT_MEMBERSHIP_SQL, INSERT_MEMORY_EVIDENCE_SQL,
        INSERT_MEMORY_SQL, INSERT_PRINCIPAL_SQL, INSERT_PROJECTION_SQL,
        INSERT_REQUIRED_KEY_ROTATION_SQL, INSERT_RETENTION_POLICY_SQL, INSERT_WORKSPACE_SQL,
        LATEST_CHECKPOINT_SQL, LATEST_KEY_ROTATION_SQL, LIST_ACTIVE_LEGAL_HOLDS_SQL,
        LIST_ACTIVE_MEMBERSHIPS_SQL, LIST_ADMINISTRATIVE_AUDIT_SQL, LIST_EVENTS_SINCE_SQL,
        LIST_INVITATIONS_BY_STATUS_SQL, LIST_MEMBER_SCOPE_GRANTS_SQL, LIST_OWNER_TRIPS_SQL,
        LIST_PENDING_PROJECTIONS_SQL, LIST_SUBJECT_CHECKPOINTS_SQL, LIST_SUBJECT_MEMORIES_SQL,
        LOCK_WORKSPACE_FOR_ROTATION_SQL, MAX_ACTIVE_MEMBERSHIPS, NEXT_KEY_ROTATION_GENERATION_SQL,
        PostgresFailureKind, PostgresParameter, PostgresPool, PostgresProvisioner,
        PostgresProvisioningPool, PostgresRow, PostgresStore, PostgresStoreError,
        PostgresTransaction, PostgresWorkspaceAdminStore, ProvisioningTransaction, READ_TENANT_SQL,
        REMOVE_MEMBERSHIP_SQL, REPLACE_CHECKPOINT_SQL, REPLACE_INVITATION_SQL,
        REPLACE_LEGAL_HOLD_SQL, REPLACE_MEMBERSHIP_SQL, REPLACE_PROJECTION_SQL,
        REPLACE_RETENTION_POLICY_SQL, SET_TENANT_SQL, TenantTransaction, TenantTransactionError,
        map_application_error, map_invitation_application_error,
    };

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Call {
        Execute(String, Vec<String>),
        QueryText(String),
        Query(String, Vec<String>),
        Commit,
        Rollback,
    }

    type TenantRead = Result<Option<String>, &'static str>;
    type TenantReadBatch = VecDeque<TenantRead>;

    impl ClassifiedPostgresError for &'static str {
        fn kind(&self) -> PostgresFailureKind {
            PostgresFailureKind::Other
        }
    }

    struct IdentityCipher;

    impl RecordCipher for IdentityCipher {
        fn seal(
            &self,
            _context: &EncryptionContext,
            plaintext: &[u8],
        ) -> Result<EncryptedPayload, CryptoError> {
            EncryptedPayload::new(plaintext.to_vec(), "key_test", "identity-test", vec![7; 24])
        }

        fn open(
            &self,
            _context: &EncryptionContext,
            payload: &EncryptedPayload,
        ) -> Result<Vec<u8>, CryptoError> {
            Ok(payload.ciphertext().to_vec())
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct FakeRow {
        columns: BTreeMap<&'static str, String>,
        numbers: BTreeMap<&'static str, u64>,
    }

    impl FakeRow {
        fn principal(id: &str) -> Self {
            Self {
                columns: BTreeMap::from([("id", id.to_owned())]),
                numbers: BTreeMap::new(),
            }
        }

        fn workspace(id: &str, kind: &str) -> Self {
            Self {
                columns: BTreeMap::from([("id", id.to_owned()), ("kind", kind.to_owned())]),
                numbers: BTreeMap::new(),
            }
        }

        fn membership(workspace_id: &str, principal_id: &str, role: &str, status: &str) -> Self {
            Self {
                columns: BTreeMap::from([
                    ("workspace_id", workspace_id.to_owned()),
                    ("principal_id", principal_id.to_owned()),
                    ("role", role.to_owned()),
                    ("status", status.to_owned()),
                ]),
                numbers: BTreeMap::new(),
            }
        }

        fn member_scope(
            workspace_id: &str,
            principal_id: &str,
            scope_type: &str,
            scope_value: &str,
        ) -> Self {
            Self {
                columns: BTreeMap::from([
                    ("workspace_id", workspace_id.to_owned()),
                    ("principal_id", principal_id.to_owned()),
                    ("scope_type", scope_type.to_owned()),
                    ("scope_value", scope_value.to_owned()),
                ]),
                numbers: BTreeMap::new(),
            }
        }

        fn key_rotation(
            workspace_id: &str,
            id: &str,
            generation: u64,
            status: &str,
            completed_key_id: &str,
            completed_by: &str,
        ) -> Self {
            Self {
                columns: BTreeMap::from([
                    ("workspace_id", workspace_id.to_owned()),
                    ("id", id.to_owned()),
                    ("removed_principal_id", "principal_removed".to_owned()),
                    ("requested_by", "principal_admin".to_owned()),
                    ("status", status.to_owned()),
                    ("completed_key_id", completed_key_id.to_owned()),
                    ("completed_by", completed_by.to_owned()),
                ]),
                numbers: BTreeMap::from([("generation", generation)]),
            }
        }

        fn next_rotation(workspace_id: &str, generation: u64) -> Self {
            Self {
                columns: BTreeMap::from([("id", workspace_id.to_owned())]),
                numbers: BTreeMap::from([("next_generation", generation)]),
            }
        }

        fn memory(memory: &MemoryRecord) -> Self {
            let encoded = encode_memory(memory).expect("encode memory");
            Self {
                columns: BTreeMap::from([
                    ("workspace_id", memory.workspace_id().as_str().to_owned()),
                    ("id", memory.id().as_str().to_owned()),
                    ("subject_id", memory.subject_id().as_str().to_owned()),
                    (
                        "content_ciphertext",
                        String::from_utf8(encoded).expect("JSON payload"),
                    ),
                    ("encryption_key_id", "key_test".to_owned()),
                    ("encryption_algorithm", "identity-test".to_owned()),
                    ("encryption_nonce", "777777777777777777777777".to_owned()),
                ]),
                numbers: BTreeMap::from([("version", memory.version())]),
            }
        }

        fn checkpoint(checkpoint: &ActivityCheckpoint) -> Self {
            let encoded = encode_checkpoint(checkpoint).expect("encode checkpoint");
            Self {
                columns: BTreeMap::from([
                    (
                        "workspace_id",
                        checkpoint.workspace_id().as_str().to_owned(),
                    ),
                    ("id", checkpoint.id().as_str().to_owned()),
                    ("subject_id", checkpoint.subject_id().as_str().to_owned()),
                    ("activity_id", checkpoint.activity_id().as_str().to_owned()),
                    (
                        "checkpoint_ciphertext",
                        String::from_utf8(encoded).expect("JSON payload"),
                    ),
                    ("encryption_key_id", "key_test".to_owned()),
                    ("encryption_algorithm", "identity-test".to_owned()),
                    ("encryption_nonce", "777777777777777777777777".to_owned()),
                ]),
                numbers: BTreeMap::from([("version", checkpoint.version())]),
            }
        }

        fn trip(trip: &Trip) -> Self {
            let encoded = encode_trip(trip).expect("encode trip");
            Self {
                columns: BTreeMap::from([
                    ("workspace_id", trip.workspace_id().as_str().to_owned()),
                    ("id", trip.id().as_str().to_owned()),
                    (
                        "owner_subject_id",
                        trip.owner_subject_id().as_str().to_owned(),
                    ),
                    (
                        "trip_ciphertext",
                        String::from_utf8(encoded).expect("JSON payload"),
                    ),
                    ("encryption_key_id", "key_test".to_owned()),
                    ("encryption_algorithm", "identity-test".to_owned()),
                    ("encryption_nonce", "777777777777777777777777".to_owned()),
                ]),
                numbers: BTreeMap::from([("version", trip.version())]),
            }
        }

        fn current_event_sequence(sequence: u64) -> Self {
            Self {
                columns: BTreeMap::new(),
                numbers: BTreeMap::from([("current_sequence", sequence)]),
            }
        }

        fn event(event: &CanonicalEvent) -> Self {
            let encoded = rembrane_codec::encode_event(event).expect("encode event");
            Self {
                columns: BTreeMap::from([
                    ("workspace_id", event.workspace_id().as_str().to_owned()),
                    ("id", event.id().as_str().to_owned()),
                    ("actor_id", event.actor_id().as_str().to_owned()),
                    (
                        "subject_id",
                        event
                            .subject_id()
                            .map_or_else(String::new, |id| id.as_str().to_owned()),
                    ),
                    ("event_type", super::event_type(event).to_owned()),
                    (
                        "payload_ciphertext",
                        String::from_utf8(encoded).expect("JSON payload"),
                    ),
                    ("encryption_key_id", "key_test".to_owned()),
                    ("encryption_algorithm", "identity-test".to_owned()),
                    ("encryption_nonce", "777777777777777777777777".to_owned()),
                ]),
                numbers: BTreeMap::from([("sequence", event.sequence())]),
            }
        }

        fn projection(job: &ProjectionJob) -> Self {
            Self {
                columns: BTreeMap::from([
                    ("id", job.id().as_str().to_owned()),
                    ("workspace_id", job.workspace_id().as_str().to_owned()),
                    ("memory_id", job.memory_id().as_str().to_owned()),
                    ("provider_id", job.provider_id().as_str().to_owned()),
                    (
                        "operation",
                        super::projection_operation_name(job.operation()).to_owned(),
                    ),
                    (
                        "status",
                        super::projection_status_name(job.status()).to_owned(),
                    ),
                ]),
                numbers: BTreeMap::from([
                    ("memory_version", job.memory_version()),
                    ("attempts", u64::from(job.attempts())),
                ]),
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn invitation(
            workspace_id: &str,
            id: &str,
            invited_principal_id: &str,
            invited_by: &str,
            role: &str,
            status: &str,
            created_at: u64,
            expires_at: u64,
        ) -> Self {
            Self {
                columns: BTreeMap::from([
                    ("workspace_id", workspace_id.to_owned()),
                    ("id", id.to_owned()),
                    ("invited_principal_id", invited_principal_id.to_owned()),
                    ("invited_by", invited_by.to_owned()),
                    ("role", role.to_owned()),
                    ("status", status.to_owned()),
                ]),
                numbers: BTreeMap::from([
                    ("created_at_epoch_seconds", created_at),
                    ("expires_at_epoch_seconds", expires_at),
                ]),
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn audit(
            workspace_id: &str,
            id: &str,
            actor_id: &str,
            action: &str,
            target_kind: &str,
            target_id: &str,
            request_id: &str,
            occurred_at: u64,
        ) -> Self {
            Self {
                columns: BTreeMap::from([
                    ("workspace_id", workspace_id.to_owned()),
                    ("id", id.to_owned()),
                    ("actor_id", actor_id.to_owned()),
                    ("action", action.to_owned()),
                    ("target_kind", target_kind.to_owned()),
                    ("target_id", target_id.to_owned()),
                    ("request_id", request_id.to_owned()),
                ]),
                numbers: BTreeMap::from([("occurred_at_epoch_seconds", occurred_at)]),
            }
        }

        fn retention_policy(workspace_id: &str, version: u64, audit_days: u64) -> Self {
            Self {
                columns: BTreeMap::from([("workspace_id", workspace_id.to_owned())]),
                numbers: BTreeMap::from([
                    ("version", version),
                    ("user_memory_days", 30),
                    ("activity_checkpoint_days", 7),
                    ("travel_research_days", 14),
                    ("disclosure_receipt_days", 90),
                    ("canonical_event_days", 365),
                    ("administrative_audit_days", audit_days),
                ]),
            }
        }

        #[allow(clippy::too_many_arguments)]
        fn legal_hold(
            workspace_id: &str,
            id: &str,
            placed_by: &str,
            status: &str,
            version: u64,
            released_by: &str,
            placed_at: u64,
            released_at: u64,
        ) -> Self {
            Self {
                columns: BTreeMap::from([
                    ("workspace_id", workspace_id.to_owned()),
                    ("id", id.to_owned()),
                    ("placed_by", placed_by.to_owned()),
                    ("status", status.to_owned()),
                    ("released_by", released_by.to_owned()),
                ]),
                numbers: BTreeMap::from([
                    ("placed_at_epoch_seconds", placed_at),
                    ("version", version),
                    ("released_at_epoch_seconds", released_at),
                ]),
            }
        }
    }

    impl PostgresRow for FakeRow {
        type Error = &'static str;

        fn text(&self, column: &str) -> Result<String, Self::Error> {
            self.columns.get(column).cloned().ok_or("unknown column")
        }

        fn u64(&self, column: &str) -> Result<u64, Self::Error> {
            self.numbers
                .get(column)
                .copied()
                .ok_or("unknown numeric column")
        }

        fn bytes(&self, column: &str) -> Result<Vec<u8>, Self::Error> {
            self.columns
                .get(column)
                .map(|value| value.as_bytes().to_vec())
                .ok_or("unknown bytes column")
        }
    }

    struct FakeTransaction {
        calls: Rc<RefCell<Vec<Call>>>,
        tenants: TenantReadBatch,
        rows: Vec<FakeRow>,
    }

    struct FakePool {
        calls: Rc<RefCell<Vec<Call>>>,
        tenant_batches: RefCell<VecDeque<TenantReadBatch>>,
        row_batches: RefCell<VecDeque<Vec<FakeRow>>>,
    }

    impl PostgresPool for FakePool {
        type Error = &'static str;
        type Transaction = FakeTransaction;

        fn begin(&self) -> Result<Self::Transaction, Self::Error> {
            let tenants = self
                .tenant_batches
                .borrow_mut()
                .pop_front()
                .ok_or("unexpected transaction begin")?;
            let rows = self
                .row_batches
                .borrow_mut()
                .pop_front()
                .ok_or("unexpected row batch")?;
            Ok(FakeTransaction {
                calls: Rc::clone(&self.calls),
                tenants,
                rows,
            })
        }
    }

    impl PostgresTransaction for FakeTransaction {
        type Error = &'static str;
        type Row = FakeRow;

        fn execute(
            &mut self,
            statement: &str,
            parameters: &[PostgresParameter<'_>],
        ) -> Result<u64, Self::Error> {
            self.calls
                .borrow_mut()
                .push(Call::Execute(statement.to_owned(), rendered(parameters)));
            Ok(1)
        }

        fn query(
            &mut self,
            statement: &str,
            parameters: &[PostgresParameter<'_>],
        ) -> Result<Vec<Self::Row>, Self::Error> {
            self.calls
                .borrow_mut()
                .push(Call::Query(statement.to_owned(), rendered(parameters)));
            Ok(self.rows.clone())
        }

        fn query_optional_text(
            &mut self,
            statement: &str,
            _parameters: &[PostgresParameter<'_>],
        ) -> Result<Option<String>, Self::Error> {
            self.calls
                .borrow_mut()
                .push(Call::QueryText(statement.to_owned()));
            self.tenants
                .pop_front()
                .unwrap_or(Err("unexpected tenant read"))
        }

        fn commit(self) -> Result<(), Self::Error> {
            self.calls.borrow_mut().push(Call::Commit);
            Ok(())
        }

        fn rollback(self) -> Result<(), Self::Error> {
            self.calls.borrow_mut().push(Call::Rollback);
            Ok(())
        }
    }

    fn rendered(parameters: &[PostgresParameter<'_>]) -> Vec<String> {
        parameters
            .iter()
            .map(|parameter| match parameter {
                PostgresParameter::Text(value) => format!("text:{value}"),
                PostgresParameter::OptionalText(value) => match value {
                    Some(value) => format!("optional-text:{value}"),
                    None => "optional-text:null".to_owned(),
                },
                PostgresParameter::I64(value) => format!("i64:{value}"),
                PostgresParameter::OptionalI64(value) => match value {
                    Some(value) => format!("optional-i64:{value}"),
                    None => "optional-i64:null".to_owned(),
                },
                PostgresParameter::Bytes(value) => format!("bytes:{}", value.len()),
            })
            .collect()
    }

    fn fake(
        tenants: impl IntoIterator<Item = Result<Option<&'static str>, &'static str>>,
    ) -> (FakeTransaction, Rc<RefCell<Vec<Call>>>) {
        let calls = Rc::new(RefCell::new(Vec::new()));
        (
            FakeTransaction {
                calls: Rc::clone(&calls),
                tenants: tenants
                    .into_iter()
                    .map(|tenant| tenant.map(|value| value.map(str::to_owned)))
                    .collect(),
                rows: vec![FakeRow::workspace("workspace_01", "shared")],
            },
            calls,
        )
    }

    fn checkpoint_event(id: &str, sequence: u64, version: u64) -> CanonicalEvent {
        CanonicalEvent::new(
            EventId::new(id),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            Some(PrincipalId::new("principal_01")),
            sequence,
            EventPayload::ActivityCheckpointed {
                activity_id: ActivityId::new("activity_02"),
                version,
            },
        )
        .expect("checkpoint event")
    }

    #[test]
    fn provisioning_transactions_use_a_separate_pool_and_rollback_on_drop() {
        struct FakeProvisioningPool {
            calls: Rc<RefCell<Vec<Call>>>,
        }

        impl PostgresProvisioningPool for FakeProvisioningPool {
            type Error = &'static str;
            type Transaction = FakeTransaction;

            fn begin_provisioning(&self) -> Result<Self::Transaction, Self::Error> {
                Ok(FakeTransaction {
                    calls: Rc::clone(&self.calls),
                    tenants: VecDeque::new(),
                    rows: Vec::new(),
                })
            }
        }

        let calls = Rc::new(RefCell::new(Vec::new()));
        let pool = FakeProvisioningPool {
            calls: Rc::clone(&calls),
        };
        {
            let mut transaction =
                ProvisioningTransaction::begin(&pool).expect("provisioning transaction");
            transaction
                .execute(
                    "INSERT INTO workspaces (id, kind) VALUES ($1, $2)",
                    &[
                        PostgresParameter::Text("workspace_01"),
                        PostgresParameter::Text("personal"),
                    ],
                )
                .expect("provisioning write");
        }
        assert_eq!(calls.borrow().last(), Some(&Call::Rollback));

        ProvisioningTransaction::begin(&pool)
            .expect("second provisioning transaction")
            .commit()
            .expect("commit");
        assert_eq!(calls.borrow().last(), Some(&Call::Commit));
        assert!(!calls.borrow().iter().any(
            |call| matches!(call, Call::QueryText(statement) if statement == READ_TENANT_SQL)
        ));
    }

    #[test]
    fn provisioner_atomically_bootstraps_personal_and_shared_workspaces() {
        struct FakeProvisioningPool {
            calls: Rc<RefCell<Vec<Call>>>,
            tenant_batches: RefCell<VecDeque<TenantReadBatch>>,
        }

        impl PostgresProvisioningPool for FakeProvisioningPool {
            type Error = &'static str;
            type Transaction = FakeTransaction;

            fn begin_provisioning(&self) -> Result<Self::Transaction, Self::Error> {
                Ok(FakeTransaction {
                    calls: Rc::clone(&self.calls),
                    tenants: self
                        .tenant_batches
                        .borrow_mut()
                        .pop_front()
                        .ok_or("unexpected provisioning begin")?,
                    rows: Vec::new(),
                })
            }
        }

        let calls = Rc::new(RefCell::new(Vec::new()));
        let provisioner = PostgresProvisioner::new(FakeProvisioningPool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::new(),
                    VecDeque::from([Ok(Some("principal_01".to_owned()))]),
                ]
                .into(),
            ),
        });
        let principal = Principal::new(PrincipalId::new("principal_01"));
        let personal = Workspace::personal(WorkspaceId::new("workspace_personal"));
        let personal_owner = rembrane_domain::Membership::new(
            personal.id().clone(),
            principal.id().clone(),
            WorkspaceRole::Owner,
        );
        provisioner
            .initialize_personal_workspace(&principal, &personal, &personal_owner)
            .expect("personal bootstrap");

        let shared = Workspace::shared(WorkspaceId::new("workspace_shared"));
        let shared_owner = rembrane_domain::Membership::new(
            shared.id().clone(),
            principal.id().clone(),
            WorkspaceRole::Owner,
        );
        provisioner
            .initialize_shared_workspace(&shared, &shared_owner)
            .expect("shared bootstrap");

        let calls = calls.borrow();
        for statement in [
            INSERT_PRINCIPAL_SQL,
            INSERT_WORKSPACE_SQL,
            INSERT_MEMBERSHIP_SQL,
        ] {
            assert!(
                calls.iter().any(
                    |call| matches!(call, Call::Execute(executed, _) if executed == statement)
                )
            );
        }
        assert!(calls.iter().any(|call| {
            matches!(
                call,
                Call::QueryText(statement) if statement == FIND_PROVISIONING_PRINCIPAL_SQL
            )
        }));
        assert_eq!(
            calls.iter().filter(|call| **call == Call::Commit).count(),
            2
        );
    }

    #[test]
    fn workspace_admin_store_confines_provisioning_to_its_target_workspace() {
        struct NeverBeginRuntimePool;

        impl PostgresPool for NeverBeginRuntimePool {
            type Error = &'static str;
            type Transaction = FakeTransaction;

            fn begin(&self) -> Result<Self::Transaction, Self::Error> {
                Err("runtime pool must not begin")
            }
        }

        struct PrincipalDirectoryPool {
            calls: Rc<RefCell<Vec<Call>>>,
        }

        impl PostgresProvisioningPool for PrincipalDirectoryPool {
            type Error = &'static str;
            type Transaction = FakeTransaction;

            fn begin_provisioning(&self) -> Result<Self::Transaction, Self::Error> {
                Ok(FakeTransaction {
                    calls: Rc::clone(&self.calls),
                    tenants: VecDeque::from([Ok(Some("principal_01".to_owned()))]),
                    rows: Vec::new(),
                })
            }
        }

        let calls = Rc::new(RefCell::new(Vec::new()));
        let runtime = PostgresStore::new(NeverBeginRuntimePool);
        let provisioner = PostgresProvisioner::new(PrincipalDirectoryPool {
            calls: Rc::clone(&calls),
        });
        let mut admin = PostgresWorkspaceAdminStore::new(
            runtime,
            provisioner,
            WorkspaceId::new("workspace_01"),
        );

        assert_eq!(
            WorkspaceRepository::find_principal(&admin, &PrincipalId::new("principal_01"))
                .expect("principal directory lookup")
                .expect("principal")
                .id()
                .as_str(),
            "principal_01"
        );
        assert_eq!(calls.borrow().last(), Some(&Call::Commit));
        assert_eq!(
            WorkspaceRepository::initialize_shared_workspace(
                &mut admin,
                Workspace::shared(WorkspaceId::new("workspace_other")),
                rembrane_domain::Membership::new(
                    WorkspaceId::new("workspace_other"),
                    PrincipalId::new("principal_01"),
                    WorkspaceRole::Owner,
                ),
            ),
            Err(ApplicationError::AccessDenied)
        );
        assert_eq!(
            WorkspaceRepository::find_workspace(&admin, &WorkspaceId::new("workspace_other"),),
            Err(ApplicationError::AccessDenied)
        );
    }

    #[test]
    fn verifies_bound_tenant_before_allowing_queries_and_commit() {
        let (transaction, calls) = fake([Ok(Some("workspace_01")), Ok(Some("workspace_01"))]);
        let mut verified = TenantTransaction::verify(transaction, WorkspaceId::new("workspace_01"))
            .expect("exact tenant should verify");
        assert_eq!(verified.workspace_id().as_str(), "workspace_01");
        assert_eq!(
            verified
                .query(
                    "SELECT id FROM memories WHERE workspace_id = $1",
                    &[PostgresParameter::Text("workspace_01")],
                )
                .expect("query"),
            vec![FakeRow::workspace("workspace_01", "shared")]
        );
        verified.commit().expect("commit");

        assert_eq!(
            *calls.borrow(),
            [
                Call::Execute(
                    SET_TENANT_SQL.to_owned(),
                    vec!["text:workspace_01".to_owned()]
                ),
                Call::QueryText(READ_TENANT_SQL.to_owned()),
                Call::QueryText(READ_TENANT_SQL.to_owned()),
                Call::Query(
                    "SELECT id FROM memories WHERE workspace_id = $1".to_owned(),
                    vec!["text:workspace_01".to_owned()]
                ),
                Call::Commit,
            ]
        );
    }

    #[test]
    fn missing_or_mismatched_tenant_rolls_back_without_query_access() {
        for (tenant, expected) in [
            (Ok(None), TenantTransactionError::MissingTenant),
            (
                Ok(Some("workspace_other")),
                TenantTransactionError::TenantMismatch,
            ),
        ] {
            let (transaction, calls) = fake([tenant]);
            let result = TenantTransaction::verify(transaction, WorkspaceId::new("workspace_01"));
            assert!(matches!(result, Err(error) if error == expected));
            assert_eq!(calls.borrow().last(), Some(&Call::Rollback));
        }
    }

    #[test]
    fn uncommitted_verified_transaction_rolls_back_on_drop() {
        let (transaction, calls) = fake([Ok(Some("workspace_01"))]);
        let verified = TenantTransaction::verify(transaction, WorkspaceId::new("workspace_01"))
            .expect("exact tenant should verify");
        drop(verified);
        assert_eq!(calls.borrow().last(), Some(&Call::Rollback));
    }

    #[test]
    fn tenant_drift_rolls_back_and_poisoned_transaction_stays_closed() {
        let (transaction, calls) = fake([Ok(Some("workspace_01")), Ok(Some("workspace_other"))]);
        let mut verified = TenantTransaction::verify(transaction, WorkspaceId::new("workspace_01"))
            .expect("initial tenant should verify");

        assert_eq!(
            verified.query("SELECT id FROM memories", &[]),
            Err(TenantTransactionError::TenantMismatch)
        );
        assert_eq!(calls.borrow().last(), Some(&Call::Rollback));
        assert_eq!(
            verified.execute("DELETE FROM memories", &[]),
            Err(TenantTransactionError::Closed)
        );
    }

    #[test]
    fn store_reverifies_each_tenant_when_pool_connections_are_reused() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let pool = FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([Ok(Some("workspace_a".to_owned()))]),
                    VecDeque::from([Ok(Some("workspace_b".to_owned()))]),
                ]
                .into(),
            ),
            row_batches: RefCell::new([Vec::new(), Vec::new()].into()),
        };
        let store = PostgresStore::new(pool);

        store
            .begin_tenant(WorkspaceId::new("workspace_a"))
            .expect("first tenant")
            .commit()
            .expect("first commit");
        store
            .begin_tenant(WorkspaceId::new("workspace_b"))
            .expect("second tenant")
            .commit()
            .expect("second commit");

        assert_eq!(
            calls
                .borrow()
                .iter()
                .filter_map(|call| match call {
                    Call::Execute(statement, parameters) if statement == SET_TENANT_SQL => {
                        parameters.first().cloned()
                    }
                    _ => None,
                })
                .collect::<Vec<_>>(),
            ["text:workspace_a", "text:workspace_b"]
        );
    }

    #[test]
    fn store_distinguishes_begin_failure_from_tenant_failure() {
        struct FailingPool;

        impl PostgresPool for FailingPool {
            type Error = &'static str;
            type Transaction = FakeTransaction;

            fn begin(&self) -> Result<Self::Transaction, Self::Error> {
                Err("pool unavailable")
            }
        }

        assert!(matches!(
            PostgresStore::new(FailingPool).begin_tenant(WorkspaceId::new("workspace_01")),
            Err(PostgresStoreError::Begin("pool unavailable"))
        ));
    }

    #[test]
    fn workspace_lookup_decodes_exact_tenant_and_commits() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [VecDeque::from([
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                ])]
                .into(),
            ),
            row_batches: RefCell::new([vec![FakeRow::workspace("workspace_01", "shared")]].into()),
        });

        let workspace = store
            .find_workspace(&WorkspaceId::new("workspace_01"))
            .expect("workspace lookup")
            .expect("workspace");
        assert_eq!(workspace.id().as_str(), "workspace_01");
        assert_eq!(workspace.kind(), rembrane_domain::WorkspaceKind::Shared);
        assert!(calls.borrow().contains(&Call::Query(
            FIND_WORKSPACE_SQL.to_owned(),
            vec!["text:workspace_01".to_owned()]
        )));
        assert_eq!(calls.borrow().last(), Some(&Call::Commit));
    }

    #[test]
    fn workspace_lookup_rejects_invalid_or_excessive_rows() {
        for rows in [
            vec![FakeRow::workspace("workspace_other", "shared")],
            vec![FakeRow::workspace("workspace_01", "unknown")],
            vec![
                FakeRow::workspace("workspace_01", "shared"),
                FakeRow::workspace("workspace_01", "shared"),
            ],
        ] {
            let calls = Rc::new(RefCell::new(Vec::new()));
            let store = PostgresStore::new(FakePool {
                calls: Rc::clone(&calls),
                tenant_batches: RefCell::new(
                    [VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ])]
                    .into(),
                ),
                row_batches: RefCell::new([rows].into()),
            });

            assert!(
                store
                    .find_workspace(&WorkspaceId::new("workspace_01"))
                    .is_err()
            );
            assert_eq!(calls.borrow().last(), Some(&Call::Rollback));
        }
    }

    #[test]
    fn principal_lookup_is_tenant_verified_and_identity_exact() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [VecDeque::from([
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                ])]
                .into(),
            ),
            row_batches: RefCell::new([vec![FakeRow::principal("principal_01")]].into()),
        });

        let principal = store
            .find_principal(
                &WorkspaceId::new("workspace_01"),
                &rembrane_domain::PrincipalId::new("principal_01"),
            )
            .expect("principal lookup")
            .expect("principal");
        assert_eq!(principal.id().as_str(), "principal_01");
        assert!(calls.borrow().contains(&Call::Query(
            FIND_PRINCIPAL_SQL.to_owned(),
            vec!["text:principal_01".to_owned()]
        )));
        assert_eq!(calls.borrow().last(), Some(&Call::Commit));
    }

    #[test]
    fn principal_lookup_rejects_substitution_and_excessive_rows() {
        for rows in [
            vec![FakeRow::principal("principal_other")],
            vec![
                FakeRow::principal("principal_01"),
                FakeRow::principal("principal_01"),
            ],
        ] {
            let calls = Rc::new(RefCell::new(Vec::new()));
            let store = PostgresStore::new(FakePool {
                calls: Rc::clone(&calls),
                tenant_batches: RefCell::new(
                    [VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ])]
                    .into(),
                ),
                row_batches: RefCell::new([rows].into()),
            });

            assert!(
                store
                    .find_principal(
                        &WorkspaceId::new("workspace_01"),
                        &rembrane_domain::PrincipalId::new("principal_01"),
                    )
                    .is_err()
            );
            assert_eq!(calls.borrow().last(), Some(&Call::Rollback));
        }
    }

    #[test]
    fn membership_lookup_decodes_exact_authorization_state() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [VecDeque::from([
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                ])]
                .into(),
            ),
            row_batches: RefCell::new(
                [vec![FakeRow::membership(
                    "workspace_01",
                    "principal_01",
                    "admin",
                    "suspended",
                )]]
                .into(),
            ),
        });

        let membership = store
            .find_membership(
                &WorkspaceId::new("workspace_01"),
                &rembrane_domain::PrincipalId::new("principal_01"),
            )
            .expect("membership lookup")
            .expect("membership");
        assert_eq!(membership.role(), rembrane_domain::WorkspaceRole::Admin);
        assert_eq!(
            membership.status(),
            rembrane_domain::MembershipStatus::Suspended
        );
        assert!(calls.borrow().contains(&Call::Query(
            FIND_MEMBERSHIP_SQL.to_owned(),
            vec![
                "text:workspace_01".to_owned(),
                "text:principal_01".to_owned()
            ]
        )));
        assert_eq!(calls.borrow().last(), Some(&Call::Commit));
    }

    #[test]
    fn membership_lookup_rejects_mismatched_unknown_or_duplicate_rows() {
        let invalid_rows = [
            vec![FakeRow::membership(
                "workspace_other",
                "principal_01",
                "member",
                "active",
            )],
            vec![FakeRow::membership(
                "workspace_01",
                "principal_other",
                "member",
                "active",
            )],
            vec![FakeRow::membership(
                "workspace_01",
                "principal_01",
                "root",
                "active",
            )],
            vec![FakeRow::membership(
                "workspace_01",
                "principal_01",
                "member",
                "unknown",
            )],
            vec![
                FakeRow::membership("workspace_01", "principal_01", "member", "active"),
                FakeRow::membership("workspace_01", "principal_01", "member", "active"),
            ],
        ];
        for rows in invalid_rows {
            let calls = Rc::new(RefCell::new(Vec::new()));
            let store = PostgresStore::new(FakePool {
                calls: Rc::clone(&calls),
                tenant_batches: RefCell::new(
                    [VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ])]
                    .into(),
                ),
                row_batches: RefCell::new([rows].into()),
            });

            assert!(
                store
                    .find_membership(
                        &WorkspaceId::new("workspace_01"),
                        &rembrane_domain::PrincipalId::new("principal_01"),
                    )
                    .is_err()
            );
            assert_eq!(calls.borrow().last(), Some(&Call::Rollback));
        }
    }

    #[test]
    fn active_membership_listing_is_bounded_ordered_and_tenant_exact() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [VecDeque::from([
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                ])]
                .into(),
            ),
            row_batches: RefCell::new(
                [vec![
                    FakeRow::membership("workspace_01", "admin_01", "admin", "active"),
                    FakeRow::membership("workspace_01", "member_01", "member", "active"),
                ]]
                .into(),
            ),
        });

        let memberships = store
            .list_active_memberships(&WorkspaceId::new("workspace_01"))
            .expect("active memberships");
        assert_eq!(
            memberships
                .iter()
                .map(|membership| membership.principal_id().as_str())
                .collect::<Vec<_>>(),
            ["admin_01", "member_01"]
        );
        assert!(calls.borrow().contains(&Call::Query(
            LIST_ACTIVE_MEMBERSHIPS_SQL.to_owned(),
            vec!["text:workspace_01".to_owned()]
        )));
        assert_eq!(calls.borrow().last(), Some(&Call::Commit));
    }

    #[test]
    fn active_membership_listing_rejects_duplicates_inactive_rows_and_overflow() {
        let duplicate = FakeRow::membership("workspace_01", "member_01", "member", "active");
        let overflow = (0..=MAX_ACTIVE_MEMBERSHIPS)
            .map(|index| {
                FakeRow::membership(
                    "workspace_01",
                    &format!("principal_{index:05}"),
                    "member",
                    "active",
                )
            })
            .collect::<Vec<_>>();
        for rows in [
            vec![duplicate.clone(), duplicate],
            vec![FakeRow::membership(
                "workspace_01",
                "member_01",
                "member",
                "suspended",
            )],
            vec![FakeRow::membership(
                "workspace_other",
                "member_01",
                "member",
                "active",
            )],
            overflow,
        ] {
            let calls = Rc::new(RefCell::new(Vec::new()));
            let store = PostgresStore::new(FakePool {
                calls: Rc::clone(&calls),
                tenant_batches: RefCell::new(
                    [VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ])]
                    .into(),
                ),
                row_batches: RefCell::new([rows].into()),
            });

            assert!(
                store
                    .list_active_memberships(&WorkspaceId::new("workspace_01"))
                    .is_err()
            );
            assert_eq!(calls.borrow().last(), Some(&Call::Rollback));
        }
    }

    #[test]
    fn invitation_lookup_restores_terminal_state_with_exact_identity() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [VecDeque::from([
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                ])]
                .into(),
            ),
            row_batches: RefCell::new(
                [vec![FakeRow::invitation(
                    "workspace_01",
                    "invitation_01",
                    "principal_guest",
                    "principal_admin",
                    "member",
                    "accepted",
                    100,
                    200,
                )]]
                .into(),
            ),
        });

        let invitation = store
            .find_invitation(
                &WorkspaceId::new("workspace_01"),
                &InvitationId::new("invitation_01"),
            )
            .expect("invitation lookup")
            .expect("invitation");
        assert_eq!(invitation.status(), InvitationStatus::Accepted);
        assert_eq!(invitation.created_at_epoch_seconds(), 100);
        assert_eq!(invitation.expires_at_epoch_seconds(), 200);
        assert!(calls.borrow().contains(&Call::Query(
            FIND_INVITATION_SQL.to_owned(),
            vec![
                "text:workspace_01".to_owned(),
                "text:invitation_01".to_owned(),
            ]
        )));
        assert_eq!(calls.borrow().last(), Some(&Call::Commit));
    }

    #[test]
    fn invitation_listing_is_bounded_status_filtered_and_tenant_exact() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [VecDeque::from([
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                ])]
                .into(),
            ),
            row_batches: RefCell::new(
                [vec![
                    FakeRow::invitation(
                        "workspace_01",
                        "invitation_02",
                        "principal_guest_02",
                        "principal_admin",
                        "viewer",
                        "revoked",
                        300,
                        400,
                    ),
                    FakeRow::invitation(
                        "workspace_01",
                        "invitation_01",
                        "principal_guest_01",
                        "principal_admin",
                        "member",
                        "revoked",
                        100,
                        200,
                    ),
                ]]
                .into(),
            ),
        });

        let invitations = store
            .list_invitations(
                &WorkspaceId::new("workspace_01"),
                Some(InvitationStatus::Revoked),
                2,
            )
            .expect("invitation listing");
        assert_eq!(invitations.len(), 2);
        assert!(
            invitations
                .iter()
                .all(|invitation| invitation.status() == InvitationStatus::Revoked)
        );
        assert!(calls.borrow().contains(&Call::Query(
            LIST_INVITATIONS_BY_STATUS_SQL.to_owned(),
            vec![
                "text:workspace_01".to_owned(),
                "text:revoked".to_owned(),
                "i64:2".to_owned(),
            ]
        )));
        assert_eq!(calls.borrow().last(), Some(&Call::Commit));
    }

    #[test]
    fn invitation_reads_reject_invalid_limits_and_uncorrelated_rows() {
        struct NeverBeginPool;

        impl PostgresPool for NeverBeginPool {
            type Error = &'static str;
            type Transaction = FakeTransaction;

            fn begin(&self) -> Result<Self::Transaction, Self::Error> {
                Err("must not begin")
            }
        }

        let store = PostgresStore::new(NeverBeginPool);
        for limit in [0, 101] {
            assert_eq!(
                store.list_invitations(&WorkspaceId::new("workspace_01"), None, limit),
                Err(PostgresStoreError::InvalidLimit)
            );
        }

        for row in [
            FakeRow::invitation(
                "workspace_other",
                "invitation_01",
                "principal_guest",
                "principal_admin",
                "member",
                "pending",
                100,
                200,
            ),
            FakeRow::invitation(
                "workspace_01",
                "invitation_other",
                "principal_guest",
                "principal_admin",
                "member",
                "pending",
                100,
                200,
            ),
            FakeRow::invitation(
                "workspace_01",
                "invitation_01",
                "principal_guest",
                "principal_admin",
                "owner",
                "pending",
                100,
                200,
            ),
        ] {
            let calls = Rc::new(RefCell::new(Vec::new()));
            let store = PostgresStore::new(FakePool {
                calls: Rc::clone(&calls),
                tenant_batches: RefCell::new(
                    [VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ])]
                    .into(),
                ),
                row_batches: RefCell::new([vec![row]].into()),
            });
            assert!(
                store
                    .find_invitation(
                        &WorkspaceId::new("workspace_01"),
                        &InvitationId::new("invitation_01"),
                    )
                    .is_err()
            );
            assert_eq!(calls.borrow().last(), Some(&Call::Rollback));
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn invitation_mutations_commit_lifecycle_membership_and_audit_atomically() {
        fn audit(
            invitation: &Invitation,
            actor: &str,
            action: AdministrativeAction,
            suffix: &str,
        ) -> AdministrativeAuditEvent {
            AdministrativeAuditEvent::new(
                AdministrativeAuditEventId::new(format!("audit_{suffix}")),
                invitation.workspace_id().clone(),
                PrincipalId::new(actor),
                action,
                AdministrativeTargetKind::Invitation,
                invitation.id().as_str(),
                format!("request_{suffix}"),
                150,
            )
            .expect("valid audit")
        }

        let pending = Invitation::new(
            InvitationId::new("invitation_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_guest"),
            PrincipalId::new("principal_admin"),
            WorkspaceRole::Member,
            100,
            200,
        )
        .expect("valid invitation");
        let accepted = pending.clone().accept_at(150).expect("accepted invitation");
        let revoked = pending.clone().revoke().expect("revoked invitation");
        let membership = rembrane_domain::Membership::new(
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_guest"),
            WorkspaceRole::Member,
        );
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new([Vec::new(), Vec::new(), Vec::new()].into()),
        });

        store
            .insert_invitation_replacing_expired(
                &pending,
                &audit(
                    &pending,
                    "principal_admin",
                    AdministrativeAction::InvitationCreated,
                    "created",
                ),
            )
            .expect("insert invitation");
        store
            .accept_invitation_with_membership(
                &accepted,
                &membership,
                &audit(
                    &accepted,
                    "principal_guest",
                    AdministrativeAction::InvitationAccepted,
                    "accepted",
                ),
            )
            .expect("accept invitation");
        store
            .replace_invitation(
                &revoked,
                InvitationStatus::Pending,
                &audit(
                    &revoked,
                    "principal_admin",
                    AdministrativeAction::InvitationRevoked,
                    "revoked",
                ),
            )
            .expect("replace invitation");

        let executed = calls
            .borrow()
            .iter()
            .filter_map(|call| match call {
                Call::Execute(statement, _) => Some(statement.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        for statement in [
            EXPIRE_PENDING_INVITATION_SQL,
            INSERT_INVITATION_SQL,
            ACCEPT_INVITATION_SQL,
            INSERT_MEMBERSHIP_SQL,
            REPLACE_INVITATION_SQL,
        ] {
            assert!(executed.iter().any(|executed| executed == statement));
        }
        assert_eq!(
            executed
                .iter()
                .filter(|statement| statement.as_str() == INSERT_ADMINISTRATIVE_AUDIT_SQL)
                .count(),
            3
        );
        assert_eq!(
            calls
                .borrow()
                .iter()
                .filter(|call| **call == Call::Commit)
                .count(),
            3
        );
    }

    #[test]
    fn invitation_application_port_rejects_mismatched_atomic_acceptance() {
        struct NeverBeginPool;

        impl PostgresPool for NeverBeginPool {
            type Error = &'static str;
            type Transaction = FakeTransaction;

            fn begin(&self) -> Result<Self::Transaction, Self::Error> {
                Err("must not begin")
            }
        }

        let pending = Invitation::new(
            InvitationId::new("invitation_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_guest"),
            PrincipalId::new("principal_admin"),
            WorkspaceRole::Member,
            100,
            200,
        )
        .expect("valid invitation");
        let accepted = pending.accept_at(150).expect("accepted invitation");
        let audit = AdministrativeAuditEvent::new(
            AdministrativeAuditEventId::new("audit_accept"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_guest"),
            AdministrativeAction::InvitationAccepted,
            AdministrativeTargetKind::Invitation,
            "invitation_01",
            "request_accept",
            150,
        )
        .expect("valid audit");
        let mismatched = rembrane_domain::Membership::new(
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_other"),
            WorkspaceRole::Member,
        );
        let mut store = PostgresStore::new(NeverBeginPool);

        assert!(matches!(
            InvitationRepository::accept_invitation_with_membership(
                &mut store, accepted, mismatched, audit,
            ),
            Err(ApplicationError::Validation(_))
        ));
    }

    #[test]
    fn tenant_store_denies_cross_workspace_calls_before_pool_access() {
        struct NeverBeginPool;

        impl PostgresPool for NeverBeginPool {
            type Error = &'static str;
            type Transaction = FakeTransaction;

            fn begin(&self) -> Result<Self::Transaction, Self::Error> {
                Err("must not begin")
            }
        }

        let store = PostgresStore::new(NeverBeginPool);
        let tenant = store.for_workspace(WorkspaceId::new("workspace_01"));
        assert_eq!(
            MembershipRepository::find_membership(
                &tenant,
                &WorkspaceId::new("workspace_other"),
                &PrincipalId::new("principal_01"),
            ),
            Err(ApplicationError::AccessDenied)
        );
        assert_eq!(
            InvitationRepository::list_invitations(
                &tenant,
                &WorkspaceId::new("workspace_other"),
                None,
                10,
            ),
            Err(ApplicationError::AccessDenied)
        );
        assert_eq!(
            AdministrativeAuditRepository::list_administrative_audit(
                &tenant,
                &WorkspaceId::new("workspace_other"),
                0,
                10,
            ),
            Err(ApplicationError::AccessDenied)
        );
        assert_eq!(
            MemberScopeGrantRepository::list_member_scope_grants(
                &tenant,
                &WorkspaceId::new("workspace_other"),
                &PrincipalId::new("principal_01"),
            ),
            Err(ApplicationError::AccessDenied)
        );
        assert_eq!(
            KeyRotationRepository::latest_key_rotation(
                &tenant,
                &WorkspaceId::new("workspace_other"),
            ),
            Err(ApplicationError::AccessDenied)
        );
    }

    #[test]
    fn member_scope_port_atomically_mutates_and_strictly_lists_grants() {
        fn audit(suffix: &str) -> AdministrativeAuditEvent {
            AdministrativeAuditEvent::new(
                AdministrativeAuditEventId::new(format!("audit_{suffix}")),
                WorkspaceId::new("workspace_01"),
                PrincipalId::new("principal_admin"),
                AdministrativeAction::ScopeGrantChanged,
                AdministrativeTargetKind::ScopeGrant,
                "principal_01:domain:travel",
                format!("request_{suffix}"),
                150,
            )
            .expect("scope audit")
        }

        let grant = MemberScopeGrant::new(
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            ReadScope::Domain {
                name: "travel".to_owned(),
            },
        );
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new(
                [
                    Vec::new(),
                    vec![FakeRow::member_scope(
                        "workspace_01",
                        "principal_01",
                        "domain",
                        "travel",
                    )],
                    Vec::new(),
                ]
                .into(),
            ),
        });
        let mut tenant = store.for_workspace(WorkspaceId::new("workspace_01"));

        MemberScopeGrantRepository::insert_member_scope_grant(
            &mut tenant,
            grant.clone(),
            audit("insert"),
        )
        .expect("insert grant");
        assert_eq!(
            MemberScopeGrantRepository::list_member_scope_grants(
                &tenant,
                &WorkspaceId::new("workspace_01"),
                &PrincipalId::new("principal_01"),
            )
            .expect("list grants"),
            vec![grant.clone()]
        );
        MemberScopeGrantRepository::delete_member_scope_grant(&mut tenant, &grant, audit("delete"))
            .expect("delete grant");

        let calls = calls.borrow();
        assert!(calls.iter().any(
            |call| matches!(call, Call::Execute(statement, _) if statement == INSERT_MEMBER_SCOPE_GRANT_SQL)
        ));
        assert!(calls
            .iter()
            .any(|call| matches!(call, Call::Query(statement, _) if statement == LIST_MEMBER_SCOPE_GRANTS_SQL)));
        assert!(calls.iter().any(
            |call| matches!(call, Call::Execute(statement, _) if statement == DELETE_MEMBER_SCOPE_GRANT_SQL)
        ));
        assert_eq!(
            calls
                .iter()
                .filter(|call| matches!(call, Call::Execute(statement, _) if statement == INSERT_ADMINISTRATIVE_AUDIT_SQL))
                .count(),
            2
        );
        assert_eq!(
            calls.iter().filter(|call| **call == Call::Commit).count(),
            3
        );
    }

    #[test]
    fn key_rotation_reads_restore_latest_state_and_absent_receipt() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new(
                [
                    vec![FakeRow::key_rotation(
                        "workspace_01",
                        "rotation_02",
                        2,
                        "completed",
                        "key_02",
                        "principal_admin",
                    )],
                    Vec::new(),
                ]
                .into(),
            ),
        });

        let rotation = store
            .latest_key_rotation(&WorkspaceId::new("workspace_01"))
            .expect("latest rotation")
            .expect("rotation");
        assert_eq!(rotation.id().as_str(), "rotation_02");
        assert_eq!(rotation.generation(), 2);
        assert_eq!(rotation.status(), KeyRotationStatus::Completed);
        assert_eq!(
            store
                .find_key_rotation_receipt(
                    &WorkspaceId::new("workspace_01"),
                    &KeyRotationId::new("rotation_02"),
                )
                .expect("receipt lookup"),
            None
        );
        assert!(calls.borrow().contains(&Call::Query(
            LATEST_KEY_ROTATION_SQL.to_owned(),
            vec!["text:workspace_01".to_owned()]
        )));
        assert!(calls.borrow().contains(&Call::Query(
            FIND_KEY_ROTATION_RECEIPT_SQL.to_owned(),
            vec![
                "text:workspace_01".to_owned(),
                "text:rotation_02".to_owned(),
            ]
        )));
    }

    #[test]
    fn key_rotation_port_atomically_completes_receipt_recipients_and_audit() {
        let rotation = WorkspaceKeyRotation::required(
            KeyRotationId::new("rotation_03"),
            WorkspaceId::new("workspace_01"),
            3,
            PrincipalId::new("principal_removed"),
            PrincipalId::new("principal_admin"),
        )
        .expect("required rotation")
        .complete("key_03", PrincipalId::new("principal_admin"))
        .expect("completed rotation");
        let receipt = KeyRotationReceipt::new(
            ProviderId::new("provider_01"),
            "request-provider-03",
            WorkspaceId::new("workspace_01"),
            3,
            "key_03",
            vec![
                PrincipalId::new("principal_admin"),
                PrincipalId::new("principal_member"),
            ],
        )
        .expect("receipt");
        let audit = AdministrativeAuditEvent::new(
            AdministrativeAuditEventId::new("audit_rotation_03"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_admin"),
            AdministrativeAction::KeyRotationCompleted,
            AdministrativeTargetKind::KeyRotation,
            "rotation_03",
            "request_rotation_03",
            200,
        )
        .expect("audit");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [VecDeque::from([
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                ])]
                .into(),
            ),
            row_batches: RefCell::new([Vec::new()].into()),
        });
        let mut tenant = store.for_workspace(WorkspaceId::new("workspace_01"));

        KeyRotationRepository::complete_key_rotation(&mut tenant, rotation, receipt, 3, audit)
            .expect("complete rotation");

        let calls = calls.borrow();
        assert!(calls.iter().any(
            |call| matches!(call, Call::Execute(statement, _) if statement == COMPLETE_KEY_ROTATION_SQL)
        ));
        assert!(calls.iter().any(
            |call| matches!(call, Call::Execute(statement, _) if statement == INSERT_KEY_ROTATION_RECEIPT_SQL)
        ));
        assert_eq!(
            calls
                .iter()
                .filter(|call| matches!(call, Call::Execute(statement, _) if statement == INSERT_KEY_ROTATION_RECIPIENT_SQL))
                .count(),
            2
        );
        assert!(calls.iter().any(
            |call| matches!(call, Call::Execute(statement, _) if statement == INSERT_ADMINISTRATIVE_AUDIT_SQL)
        ));
        assert_eq!(calls.last(), Some(&Call::Commit));
    }

    #[test]
    fn member_lifecycle_port_removes_scopes_and_requires_rotation_atomically() {
        let removed = rembrane_domain::Membership::new(
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_member"),
            WorkspaceRole::Member,
        )
        .remove();
        let rotation_id = KeyRotationId::new("rotation_04");
        let audit_events = vec![
            AdministrativeAuditEvent::new(
                AdministrativeAuditEventId::new("audit_member_removed"),
                WorkspaceId::new("workspace_01"),
                PrincipalId::new("principal_admin"),
                AdministrativeAction::MemberRemoved,
                AdministrativeTargetKind::Principal,
                "principal_member",
                "rotation_04",
                300,
            )
            .expect("member audit"),
            AdministrativeAuditEvent::new(
                AdministrativeAuditEventId::new("audit_rotation_required"),
                WorkspaceId::new("workspace_01"),
                PrincipalId::new("principal_admin"),
                AdministrativeAction::KeyRotationRequired,
                AdministrativeTargetKind::KeyRotation,
                "rotation_04",
                "rotation_04",
                300,
            )
            .expect("rotation audit"),
        ];
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [VecDeque::from([
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                ])]
                .into(),
            ),
            row_batches: RefCell::new([vec![FakeRow::next_rotation("workspace_01", 4)]].into()),
        });
        let mut tenant = store.for_workspace(WorkspaceId::new("workspace_01"));

        MemberLifecycleRepository::remove_member_and_scope_grants(
            &mut tenant,
            removed,
            MembershipStatus::Active,
            rotation_id,
            PrincipalId::new("principal_admin"),
            audit_events,
        )
        .expect("remove member");

        let calls = calls.borrow();
        assert!(calls.iter().any(
            |call| matches!(call, Call::Query(statement, _) if statement == LOCK_WORKSPACE_FOR_ROTATION_SQL)
        ));
        assert!(calls.iter().any(
            |call| matches!(call, Call::Query(statement, _) if statement == NEXT_KEY_ROTATION_GENERATION_SQL)
        ));
        assert!(calls.iter().any(
            |call| matches!(call, Call::Execute(statement, _) if statement == REMOVE_MEMBERSHIP_SQL)
        ));
        assert!(calls.iter().any(
            |call| matches!(call, Call::Execute(statement, _) if statement == DELETE_MEMBER_SCOPE_GRANTS_SQL)
        ));
        assert!(
            calls
                .iter()
                .any(|call| matches!(call, Call::Execute(statement, parameters)
                if statement == INSERT_REQUIRED_KEY_ROTATION_SQL
                    && parameters.contains(&"i64:4".to_owned())))
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| matches!(call, Call::Execute(statement, _) if statement == INSERT_ADMINISTRATIVE_AUDIT_SQL))
                .count(),
            2
        );
        assert_eq!(calls.last(), Some(&Call::Commit));
    }

    #[test]
    fn tenant_store_authorizes_client_from_composed_postgres_ports() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new(
                [
                    vec![FakeRow::membership(
                        "workspace_01",
                        "principal_member",
                        "member",
                        "active",
                    )],
                    Vec::new(),
                    vec![FakeRow::member_scope(
                        "workspace_01",
                        "principal_member",
                        "entity",
                        "project_01",
                    )],
                ]
                .into(),
            ),
        });
        let tenant = store.for_workspace(WorkspaceId::new("workspace_01"));

        let grants = AuthorizeClientService::new(&tenant)
            .execute(AuthorizeClientCommand {
                client_id: ClientId::new("client_coding_tool"),
                workspace_id: WorkspaceId::new("workspace_01"),
                principal_id: PrincipalId::new("principal_member"),
                requested_read_scopes: vec![
                    ReadScope::Global,
                    ReadScope::Entity {
                        id: EntityId::new("project_01"),
                    },
                ],
                requested_read_permissions: Vec::new(),
                requested_write_permissions: vec![
                    WritePermission::CreateMemory,
                    WritePermission::ProposeMemory,
                    WritePermission::WriteCheckpoint,
                ],
            })
            .expect("authorize tenant client");

        assert_eq!(
            grants.read.scopes,
            vec![ReadScope::Entity {
                id: EntityId::new("project_01"),
            }]
        );
        assert_eq!(
            grants.write.permissions,
            vec![
                WritePermission::ProposeMemory,
                WritePermission::WriteCheckpoint,
            ]
        );
        assert_eq!(
            calls
                .borrow()
                .iter()
                .filter(|call| **call == Call::Commit)
                .count(),
            3
        );
    }

    #[test]
    fn tenant_store_denies_client_while_key_rotation_is_required() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new(
                [
                    vec![FakeRow::membership(
                        "workspace_01",
                        "principal_member",
                        "member",
                        "active",
                    )],
                    vec![FakeRow::key_rotation(
                        "workspace_01",
                        "rotation_required",
                        5,
                        "required",
                        "",
                        "",
                    )],
                ]
                .into(),
            ),
        });
        let tenant = store.for_workspace(WorkspaceId::new("workspace_01"));

        assert_eq!(
            AuthorizeClientService::new(&tenant).execute(AuthorizeClientCommand {
                client_id: ClientId::new("client_coding_tool"),
                workspace_id: WorkspaceId::new("workspace_01"),
                principal_id: PrincipalId::new("principal_member"),
                requested_read_scopes: vec![ReadScope::Global],
                requested_read_permissions: Vec::new(),
                requested_write_permissions: vec![WritePermission::ProposeMemory],
            }),
            Err(ApplicationError::AccessDenied)
        );
        assert!(!calls.borrow().iter().any(
            |call| matches!(call, Call::Query(statement, _) if statement == LIST_MEMBER_SCOPE_GRANTS_SQL)
        ));
    }

    #[test]
    fn tenant_cipher_store_decrypts_exact_and_subject_memory_reads() {
        fn assert_projection_worker_repository<
            Repository: MemoryRepository + ProjectionOutboxRepository,
        >(
            _repository: &Repository,
        ) {
        }

        let expected = MemoryRecord::confirmed_preference(
            MemoryId::new("memory_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            MemoryScope::Global,
            "Call me Hippo",
            EvidenceReference::new(
                EvidenceId::new("evidence_01"),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("memory");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new(
                [
                    vec![FakeRow::memory(&expected)],
                    vec![FakeRow::memory(&expected)],
                ]
                .into(),
            ),
        });
        let tenant = store.for_workspace(WorkspaceId::new("workspace_01"));
        let cipher = IdentityCipher;
        let memories = tenant.with_cipher(&cipher);
        assert_projection_worker_repository(&memories);

        assert_eq!(
            MemoryRepository::find(
                &memories,
                &WorkspaceId::new("workspace_01"),
                &MemoryId::new("memory_01"),
            )
            .expect("find memory"),
            Some(expected.clone())
        );
        assert_eq!(
            MemoryRepository::list_for_subject(
                &memories,
                &WorkspaceId::new("workspace_01"),
                &PrincipalId::new("principal_01"),
            )
            .expect("list memories"),
            vec![expected]
        );
        assert!(calls.borrow().contains(&Call::Query(
            FIND_MEMORY_SQL.to_owned(),
            vec!["text:workspace_01".to_owned(), "text:memory_01".to_owned(),]
        )));
        assert!(calls.borrow().contains(&Call::Query(
            LIST_SUBJECT_MEMORIES_SQL.to_owned(),
            vec![
                "text:workspace_01".to_owned(),
                "text:principal_01".to_owned(),
            ]
        )));
    }

    #[test]
    fn tenant_cipher_store_decrypts_latest_and_subject_checkpoint_reads() {
        let expected = ActivityCheckpoint::new(
            CheckpointId::new("checkpoint_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            ActivityId::new("activity_01"),
            Some(EntityId::new("project_01")),
            "Ship PostgreSQL checkpoint continuity",
            "Encrypted checkpoint reads are implemented.",
            vec!["Add canonical checkpoint mutations".to_owned()],
            Vec::new(),
        )
        .expect("checkpoint");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new(
                [
                    vec![FakeRow::checkpoint(&expected)],
                    vec![FakeRow::checkpoint(&expected)],
                ]
                .into(),
            ),
        });
        let tenant = store.for_workspace(WorkspaceId::new("workspace_01"));
        let cipher = IdentityCipher;
        let memories = tenant.with_cipher(&cipher);

        assert_eq!(
            CheckpointRepository::latest_checkpoint(
                &memories,
                &WorkspaceId::new("workspace_01"),
                &PrincipalId::new("principal_01"),
                &ActivityId::new("activity_01"),
            )
            .expect("latest checkpoint"),
            Some(expected.clone())
        );
        assert_eq!(
            CheckpointRepository::list_checkpoints_for_subject(
                &memories,
                &WorkspaceId::new("workspace_01"),
                &PrincipalId::new("principal_01"),
            )
            .expect("list checkpoints"),
            vec![expected]
        );
        assert!(calls.borrow().contains(&Call::Query(
            LATEST_CHECKPOINT_SQL.to_owned(),
            vec![
                "text:workspace_01".to_owned(),
                "text:principal_01".to_owned(),
                "text:activity_01".to_owned(),
            ]
        )));
        assert!(calls.borrow().contains(&Call::Query(
            LIST_SUBJECT_CHECKPOINTS_SQL.to_owned(),
            vec![
                "text:workspace_01".to_owned(),
                "text:principal_01".to_owned(),
            ]
        )));
    }

    #[test]
    fn tenant_cipher_store_decrypts_exact_and_owner_trip_reads() {
        let expected = Trip::new(
            EntityId::new("trip_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            "Bengaluru to Tokyo",
            "Bengaluru",
            vec!["Tokyo".to_owned()],
            TravelDateWindow::new("2027-03-10", "2027-03-20").expect("date window"),
        )
        .expect("trip");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new(
                [
                    vec![FakeRow::trip(&expected)],
                    vec![FakeRow::trip(&expected)],
                ]
                .into(),
            ),
        });
        let tenant = store.for_workspace(WorkspaceId::new("workspace_01"));
        let cipher = IdentityCipher;
        let memories = tenant.with_cipher(&cipher);

        assert_eq!(
            TripRepository::find_trip(
                &memories,
                &WorkspaceId::new("workspace_01"),
                &EntityId::new("trip_01"),
            )
            .expect("find trip"),
            Some(expected.clone())
        );
        assert_eq!(
            TripRepository::list_trips_for_owner(
                &memories,
                &WorkspaceId::new("workspace_01"),
                &PrincipalId::new("principal_01"),
            )
            .expect("list trips"),
            vec![expected]
        );
        assert!(calls.borrow().contains(&Call::Query(
            FIND_TRIP_SQL.to_owned(),
            vec!["text:workspace_01".to_owned(), "text:trip_01".to_owned()]
        )));
        assert!(calls.borrow().contains(&Call::Query(
            LIST_OWNER_TRIPS_SQL.to_owned(),
            vec![
                "text:workspace_01".to_owned(),
                "text:principal_01".to_owned(),
            ]
        )));
    }

    #[test]
    fn checkpoint_mutations_commit_ciphertext_and_canonical_events_atomically() {
        let checkpoint = ActivityCheckpoint::new(
            CheckpointId::new("checkpoint_02"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            ActivityId::new("activity_02"),
            Some(EntityId::new("project_02")),
            "Continue project work across coding agents",
            "Initial implementation context captured.",
            vec!["Run the integration suite".to_owned()],
            Vec::new(),
        )
        .expect("checkpoint");
        let revised = checkpoint
            .clone()
            .update(
                "Integration suite is passing.",
                vec!["Prepare provider conformance test".to_owned()],
                Vec::new(),
            )
            .expect("revised checkpoint");
        let inserted_event = checkpoint_event("event_checkpoint_01", 1, 1);
        let revised_event = checkpoint_event("event_checkpoint_02", 2, 2);
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new(
                [
                    vec![FakeRow::current_event_sequence(0)],
                    vec![FakeRow::current_event_sequence(1)],
                ]
                .into(),
            ),
        });
        let tenant = store.for_workspace(WorkspaceId::new("workspace_01"));
        let cipher = IdentityCipher;
        let mut memories = tenant.with_cipher(&cipher);

        CheckpointMutationRepository::insert_checkpoint_with_event(
            &mut memories,
            checkpoint,
            inserted_event,
            0,
        )
        .expect("insert checkpoint");
        CheckpointMutationRepository::replace_checkpoint_with_event(
            &mut memories,
            revised,
            1,
            revised_event,
            1,
        )
        .expect("replace checkpoint");

        let calls = calls.borrow();
        for statement in [
            INSERT_CHECKPOINT_SQL,
            REPLACE_CHECKPOINT_SQL,
            INSERT_EVENT_SQL,
        ] {
            assert!(
                calls
                    .iter()
                    .any(|call| matches!(call, Call::Execute(actual, _) if actual == statement)),
                "missing execution for {statement}"
            );
        }
        assert_eq!(
            calls.iter().filter(|call| **call == Call::Commit).count(),
            2
        );
        assert!(calls.iter().any(|call| matches!(
            call,
            Call::Execute(statement, parameters)
                if statement == INSERT_CHECKPOINT_SQL
                    && parameters.contains(&"bytes:24".to_owned())
                    && parameters.contains(&"i64:1".to_owned())
        )));
        assert!(calls.iter().any(|call| matches!(
            call,
            Call::Execute(statement, parameters)
                if statement == REPLACE_CHECKPOINT_SQL
                    && parameters.iter().filter(|value| *value == "i64:1").count() == 1
                    && parameters.contains(&"i64:2".to_owned())
        )));
    }

    #[test]
    fn checkpoint_disclosure_persists_only_the_exact_stored_revision() {
        let checkpoint = ActivityCheckpoint::new(
            CheckpointId::new("checkpoint_03"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            ActivityId::new("activity_03"),
            Some(EntityId::new("project_03")),
            "Resume securely in another coding agent",
            "Current implementation state is ready to hand off.",
            vec!["Continue protocol conformance work".to_owned()],
            Vec::new(),
        )
        .expect("checkpoint");
        let receipt = CheckpointDisclosureReceipt {
            id: DisclosureId::new("disclosure_checkpoint_03"),
            workspace_id: WorkspaceId::new("workspace_01"),
            subject_id: PrincipalId::new("principal_01"),
            client_id: ClientId::new("client_coding_agent"),
            purpose: "resume_development_activity".to_owned(),
            checkpoint_id: CheckpointId::new("checkpoint_03"),
            checkpoint_version: 1,
            activity_id: ActivityId::new("activity_03"),
        };
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [VecDeque::from([
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                ])]
                .into(),
            ),
            row_batches: RefCell::new([vec![FakeRow::checkpoint(&checkpoint)]].into()),
        });
        let tenant = store.for_workspace(WorkspaceId::new("workspace_01"));
        let cipher = IdentityCipher;
        let mut memories = tenant.with_cipher(&cipher);

        CheckpointDisclosureRepository::append_checkpoint_disclosure(&mut memories, receipt)
            .expect("append disclosure");

        let calls = calls.borrow();
        assert!(calls.contains(&Call::Query(
            FIND_DISCLOSED_CHECKPOINT_VERSION_SQL.to_owned(),
            vec![
                "text:workspace_01".to_owned(),
                "text:checkpoint_03".to_owned(),
                "text:principal_01".to_owned(),
                "text:activity_03".to_owned(),
            ]
        )));
        assert!(calls.iter().any(|call| matches!(
            call,
            Call::Execute(statement, parameters)
                if statement == INSERT_CHECKPOINT_DISCLOSURE_SQL
                    && parameters.contains(&"text:disclosure_checkpoint_03".to_owned())
                    && parameters.contains(&"i64:1".to_owned())
                    && parameters.contains(&"text:resume_development_activity".to_owned())
        )));
        assert!(calls.contains(&Call::Commit));
    }

    #[test]
    fn checkpoint_service_resumes_postgres_state_only_after_disclosure_audit() {
        let checkpoint = ActivityCheckpoint::new(
            CheckpointId::new("checkpoint_04"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            ActivityId::new("activity_04"),
            Some(EntityId::new("project_04")),
            "Continue Rembrane with another coding agent",
            "The PostgreSQL working-memory boundary is implemented.",
            vec!["Add live driver integration".to_owned()],
            Vec::new(),
        )
        .expect("checkpoint");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new(
                [
                    vec![FakeRow::checkpoint(&checkpoint)],
                    vec![FakeRow::checkpoint(&checkpoint)],
                ]
                .into(),
            ),
        });
        let tenant = store.for_workspace(WorkspaceId::new("workspace_01"));
        let cipher = IdentityCipher;
        let mut memories = tenant.with_cipher(&cipher);
        let command = ResumeActivityCommand {
            grant: ReadGrant {
                client_id: ClientId::new("client_next_coding_agent"),
                workspace_id: WorkspaceId::new("workspace_01"),
                subject_id: PrincipalId::new("principal_01"),
                scopes: vec![ReadScope::Activity {
                    id: ActivityId::new("activity_04"),
                }],
                permissions: Vec::new(),
            },
            activity_id: ActivityId::new("activity_04"),
            disclosure_id: DisclosureId::new("disclosure_checkpoint_04"),
            purpose: "resume_development_activity".to_owned(),
        };

        let resumed = CheckpointService::new(&mut memories)
            .resume(&command)
            .expect("resume checkpoint")
            .expect("stored checkpoint");

        assert_eq!(resumed, checkpoint);
        let calls = calls.borrow();
        let disclosure_position = calls
            .iter()
            .position(|call| {
                matches!(
                    call,
                    Call::Execute(statement, _) if statement == INSERT_CHECKPOINT_DISCLOSURE_SQL
                )
            })
            .expect("disclosure insert");
        assert!(matches!(
            calls.get(disclosure_position + 1),
            Some(Call::Commit)
        ));
    }

    #[test]
    fn tenant_cipher_store_appends_and_reads_authenticated_events() {
        let event = CanonicalEvent::new(
            EventId::new("event_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            Some(PrincipalId::new("principal_01")),
            1,
            EventPayload::MemoryCreated {
                memory_id: MemoryId::new("memory_01"),
                version: 1,
            },
        )
        .expect("event");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new(
                [
                    vec![FakeRow::current_event_sequence(0)],
                    vec![FakeRow::event(&event)],
                ]
                .into(),
            ),
        });
        let tenant = store.for_workspace(WorkspaceId::new("workspace_01"));
        let cipher = IdentityCipher;
        let mut memories = tenant.with_cipher(&cipher);

        EventRepository::append_event(&mut memories, event.clone(), 0).expect("append event");
        assert_eq!(
            EventRepository::list_events_since(&memories, &WorkspaceId::new("workspace_01"), 0,)
                .expect("list events"),
            vec![event]
        );
        let calls = calls.borrow();
        assert!(calls.contains(&Call::Query(
            CURRENT_EVENT_SEQUENCE_SQL.to_owned(),
            vec!["text:workspace_01".to_owned()]
        )));
        assert!(
            calls
                .iter()
                .any(|call| matches!(call, Call::Execute(statement, parameters)
                if statement == INSERT_EVENT_SQL
                    && parameters.contains(&"bytes:24".to_owned())))
        );
        assert!(calls.contains(&Call::Query(
            LIST_EVENTS_SINCE_SQL.to_owned(),
            vec!["text:workspace_01".to_owned(), "i64:0".to_owned()]
        )));
    }

    #[test]
    fn canonical_memory_insert_commits_ciphertext_event_evidence_and_projection() {
        let memory = MemoryRecord::confirmed_preference(
            MemoryId::new("memory_02"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            MemoryScope::Global,
            "Preferred name is Hippo",
            EvidenceReference::new(
                EvidenceId::new("evidence_02"),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("memory");
        let event = CanonicalEvent::new(
            EventId::new("event_02"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            Some(PrincipalId::new("principal_01")),
            1,
            EventPayload::MemoryCreated {
                memory_id: MemoryId::new("memory_02"),
                version: 1,
            },
        )
        .expect("event");
        let projection = ProjectionJob::new(
            ProjectionJobId::new("projection_02"),
            WorkspaceId::new("workspace_01"),
            MemoryId::new("memory_02"),
            1,
            ProviderId::new("provider_native"),
            ProjectionOperation::Upsert,
        )
        .expect("projection");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [VecDeque::from([
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                ])]
                .into(),
            ),
            row_batches: RefCell::new([vec![FakeRow::current_event_sequence(0)]].into()),
        });
        let tenant = store.for_workspace(WorkspaceId::new("workspace_01"));
        let cipher = IdentityCipher;
        let mut memories = tenant.with_cipher(&cipher);

        CanonicalMutationRepository::insert_memory_with_event(
            &mut memories,
            memory,
            event,
            vec![projection],
            0,
        )
        .expect("canonical insert");

        let calls = calls.borrow();
        for statement in [
            INSERT_MEMORY_SQL,
            INSERT_MEMORY_EVIDENCE_SQL,
            INSERT_EVENT_SQL,
            INSERT_PROJECTION_SQL,
        ] {
            assert!(
                calls
                    .iter()
                    .any(|call| matches!(call, Call::Execute(actual, _) if actual == statement))
            );
        }
        assert_eq!(calls.last(), Some(&Call::Commit));
    }

    #[test]
    fn tenant_projection_outbox_is_workspace_pinned_and_optimistic() {
        let pending = ProjectionJob::new(
            ProjectionJobId::new("projection_03"),
            WorkspaceId::new("workspace_01"),
            MemoryId::new("memory_03"),
            1,
            ProviderId::new("provider_native"),
            ProjectionOperation::Upsert,
        )
        .expect("pending projection");
        let processing = pending.clone().begin().expect("processing projection");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new(
                [
                    Vec::new(),
                    vec![FakeRow::projection(&pending)],
                    Vec::new(),
                    vec![FakeRow::projection(&processing)],
                ]
                .into(),
            ),
        });
        let mut tenant = store.for_workspace(WorkspaceId::new("workspace_01"));

        ProjectionOutboxRepository::enqueue_projection(&mut tenant, pending.clone())
            .expect("enqueue projection");
        assert_eq!(
            ProjectionOutboxRepository::pending_projections(
                &tenant,
                &ProviderId::new("provider_native"),
                10,
            )
            .expect("pending projections"),
            vec![pending]
        );
        ProjectionOutboxRepository::replace_projection(
            &mut tenant,
            processing.clone(),
            ProjectionStatus::Pending,
            0,
        )
        .expect("begin projection");
        assert_eq!(
            ProjectionOutboxRepository::find_projection(
                &tenant,
                &WorkspaceId::new("workspace_01"),
                &ProjectionJobId::new("projection_03"),
            )
            .expect("find projection"),
            Some(processing)
        );

        let calls = calls.borrow();
        assert!(
            calls
                .iter()
                .any(|call| matches!(call, Call::Query(statement, parameters)
                if statement == LIST_PENDING_PROJECTIONS_SQL
                    && parameters.first() == Some(&"text:workspace_01".to_owned())))
        );
        assert!(calls.iter().any(
            |call| matches!(call, Call::Execute(statement, _) if statement == REPLACE_PROJECTION_SQL)
        ));
        assert!(calls.iter().any(
            |call| matches!(call, Call::Query(statement, _) if statement == FIND_PROJECTION_SQL)
        ));
    }

    #[test]
    fn projection_worker_indexes_postgres_memory_and_completes_job() {
        let memory = MemoryRecord::confirmed_preference(
            MemoryId::new("memory_04"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            MemoryScope::Global,
            "Call me Hippo",
            EvidenceReference::new(
                EvidenceId::new("evidence_04"),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("memory");
        let pending = ProjectionJob::new(
            ProjectionJobId::new("projection_04"),
            WorkspaceId::new("workspace_01"),
            MemoryId::new("memory_04"),
            1,
            ProviderId::new("rembrane.native"),
            ProjectionOperation::Upsert,
        )
        .expect("projection");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new(
                [
                    vec![FakeRow::projection(&pending)],
                    Vec::new(),
                    vec![FakeRow::memory(&memory)],
                    Vec::new(),
                ]
                .into(),
            ),
        });
        let tenant = store.for_workspace(WorkspaceId::new("workspace_01"));
        let cipher = IdentityCipher;
        let mut repository = tenant.with_cipher(&cipher);
        let mut provider = NativeSemanticProvider::new();

        let outcome = ProjectionWorker::new(
            &mut repository,
            &mut provider,
            ProviderId::new("rembrane.native"),
            3,
        )
        .expect("worker")
        .process_next()
        .expect("process projection");

        assert_eq!(outcome, ProjectionOutcome::Completed);
        let replacement_calls = calls
            .borrow()
            .iter()
            .filter(|call| matches!(call, Call::Execute(statement, _) if statement == REPLACE_PROJECTION_SQL))
            .count();
        assert_eq!(replacement_calls, 2);
    }

    #[test]
    fn context_capable_store_persists_exact_disclosure_versions() {
        let memory = MemoryRecord::confirmed_preference(
            MemoryId::new("memory_05"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            MemoryScope::Global,
            "Call me Hippo",
            EvidenceReference::new(
                EvidenceId::new("evidence_05"),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("memory");
        let receipt = DisclosureReceipt {
            id: DisclosureId::new("disclosure_05"),
            context_pack_id: ContextPackId::new("context_05"),
            workspace_id: WorkspaceId::new("workspace_01"),
            subject_id: PrincipalId::new("principal_01"),
            client_id: ClientId::new("client_05"),
            purpose: "assistant-personalization".to_owned(),
            memories: vec![DisclosedMemory {
                id: MemoryId::new("memory_05"),
                version: 1,
            }],
        };
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [VecDeque::from([
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                ])]
                .into(),
            ),
            row_batches: RefCell::new([vec![FakeRow::memory(&memory)]].into()),
        });
        let tenant = store.for_workspace(WorkspaceId::new("workspace_01"));
        let cipher = IdentityCipher;
        let mut repository = tenant.with_cipher(&cipher);

        DisclosureRepository::append(&mut repository, receipt).expect("append disclosure");

        let calls = calls.borrow();
        assert!(calls.iter().any(
            |call| matches!(call, Call::Execute(statement, _) if statement == INSERT_DISCLOSURE_SQL)
        ));
        assert!(calls.iter().any(
            |call| matches!(call, Call::Query(statement, _) if statement == FIND_DISCLOSED_MEMORY_VERSION_SQL)
        ));
        assert!(calls.iter().any(
            |call| matches!(call, Call::Execute(statement, _) if statement == INSERT_DISCLOSED_MEMORY_SQL)
        ));
        assert_eq!(calls.last(), Some(&Call::Commit));
    }

    #[test]
    fn resolve_context_reads_and_audits_postgres_memory_end_to_end() {
        let memory = MemoryRecord::confirmed_preference(
            MemoryId::new("memory_06"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_01"),
            MemoryScope::Global,
            "Please call me Hippo",
            EvidenceReference::new(
                EvidenceId::new("evidence_06"),
                EvidenceSource::UserStatement,
            ),
        )
        .expect("memory");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new(
                [
                    vec![FakeRow::memory(&memory)],
                    vec![FakeRow::memory(&memory)],
                ]
                .into(),
            ),
        });
        let tenant = store.for_workspace(WorkspaceId::new("workspace_01"));
        let cipher = IdentityCipher;
        let mut repository = tenant.with_cipher(&cipher);

        let response = ResolveContextService::new(&mut repository)
            .execute(ResolveContextCommand {
                request: ResolveContextRequest {
                    workspace_id: WorkspaceId::new("workspace_01"),
                    principal_id: PrincipalId::new("principal_01"),
                    domain: None,
                    entity_id: None,
                    activity_id: None,
                    purpose: "assistant-personalization".to_owned(),
                    query: "What should I call the user?".to_owned(),
                    maximum_items: 10,
                    maximum_bytes: 65_536,
                },
                grant: ReadGrant {
                    client_id: ClientId::new("client_06"),
                    workspace_id: WorkspaceId::new("workspace_01"),
                    subject_id: PrincipalId::new("principal_01"),
                    scopes: vec![ReadScope::Global],
                    permissions: Vec::new(),
                },
                context_pack_id: ContextPackId::new("context_06"),
                disclosure_id: DisclosureId::new("disclosure_06"),
            })
            .expect("resolve context");

        assert_eq!(response.items, vec![memory]);
        let calls = calls.borrow();
        assert!(calls.iter().any(
            |call| matches!(call, Call::Query(statement, _) if statement == LIST_SUBJECT_MEMORIES_SQL)
        ));
        assert!(calls.iter().any(
            |call| matches!(call, Call::Execute(statement, _) if statement == INSERT_DISCLOSURE_SQL)
        ));
        assert!(calls.iter().any(
            |call| matches!(call, Call::Execute(statement, _) if statement == INSERT_DISCLOSED_MEMORY_SQL)
        ));
    }

    #[test]
    fn tenant_store_appends_and_lists_closed_administrative_audit_rows() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new(
                [
                    Vec::new(),
                    vec![FakeRow::audit(
                        "workspace_01",
                        "audit_01",
                        "principal_admin",
                        "invitation-created",
                        "invitation",
                        "invitation_01",
                        "request_01",
                        150,
                    )],
                ]
                .into(),
            ),
        });
        let mut tenant = store.for_workspace(WorkspaceId::new("workspace_01"));
        let event = AdministrativeAuditEvent::new(
            AdministrativeAuditEventId::new("audit_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_admin"),
            AdministrativeAction::InvitationCreated,
            AdministrativeTargetKind::Invitation,
            "invitation_01",
            "request_01",
            150,
        )
        .expect("audit event");

        AdministrativeAuditRepository::append_administrative_audit(&mut tenant, event)
            .expect("append audit");
        let events = AdministrativeAuditRepository::list_administrative_audit(
            &tenant,
            &WorkspaceId::new("workspace_01"),
            100,
            10,
        )
        .expect("list audit");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action(), AdministrativeAction::InvitationCreated);
        assert!(calls.borrow().contains(&Call::Query(
            LIST_ADMINISTRATIVE_AUDIT_SQL.to_owned(),
            vec![
                "text:workspace_01".to_owned(),
                "i64:100".to_owned(),
                "i64:10".to_owned(),
            ]
        )));
        assert_eq!(
            calls
                .borrow()
                .iter()
                .filter(|call| **call == Call::Commit)
                .count(),
            2
        );
    }

    #[test]
    fn tenant_store_decodes_retention_policy_with_forever_periods() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut row = FakeRow::retention_policy("workspace_01", 3, 365);
        row.numbers.insert("travel_research_days", 0);
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [VecDeque::from([
                    Ok(Some("workspace_01".to_owned())),
                    Ok(Some("workspace_01".to_owned())),
                ])]
                .into(),
            ),
            row_batches: RefCell::new([vec![row]].into()),
        });
        let tenant = store.for_workspace(WorkspaceId::new("workspace_01"));

        let policy = tenant
            .find_retention_policy(&WorkspaceId::new("workspace_01"))
            .expect("retention lookup")
            .expect("retention policy");

        assert_eq!(policy.version(), 3);
        assert_eq!(
            policy.period(RetentionResource::TravelResearch),
            RetentionPeriod::Forever
        );
        assert!(calls.borrow().contains(&Call::Query(
            FIND_RETENTION_POLICY_SQL.to_owned(),
            vec!["text:workspace_01".to_owned()]
        )));
        assert_eq!(calls.borrow().last(), Some(&Call::Commit));
    }

    #[test]
    fn tenant_store_atomically_inserts_and_replaces_retention_policy_with_audit() {
        fn policy(version: u64) -> WorkspaceRetentionPolicy {
            WorkspaceRetentionPolicy::new(
                WorkspaceId::new("workspace_01"),
                version,
                RetentionPeriod::days(30).expect("memory"),
                RetentionPeriod::days(7).expect("checkpoint"),
                RetentionPeriod::Forever,
                RetentionPeriod::days(90).expect("disclosure"),
                RetentionPeriod::days(365).expect("event"),
                RetentionPeriod::days(365).expect("audit"),
            )
            .expect("policy")
        }

        fn audit(suffix: &str) -> AdministrativeAuditEvent {
            AdministrativeAuditEvent::new(
                AdministrativeAuditEventId::new(format!("audit_{suffix}")),
                WorkspaceId::new("workspace_01"),
                PrincipalId::new("principal_admin"),
                AdministrativeAction::RetentionPolicyChanged,
                AdministrativeTargetKind::RetentionPolicy,
                "workspace_01",
                format!("request_{suffix}"),
                150,
            )
            .expect("audit")
        }

        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new([Vec::new(), Vec::new()].into()),
        });
        let mut tenant = store.for_workspace(WorkspaceId::new("workspace_01"));

        tenant
            .replace_retention_policy(&policy(1), None, &audit("create"))
            .expect("insert policy");
        tenant
            .replace_retention_policy(&policy(2), Some(1), &audit("replace"))
            .expect("replace policy");

        let calls = calls.borrow();
        assert!(calls.iter().any(
            |call| matches!(call, Call::Execute(statement, _) if statement == INSERT_RETENTION_POLICY_SQL)
        ));
        assert!(calls.iter().any(
            |call| matches!(call, Call::Execute(statement, _) if statement == REPLACE_RETENTION_POLICY_SQL)
        ));
        assert!(calls.iter().any(|call| {
            matches!(
                call,
                Call::Execute(statement, parameters)
                    if statement == INSERT_RETENTION_POLICY_SQL
                        && parameters.contains(&"optional-i64:null".to_owned())
            )
        }));
        assert_eq!(
            calls.iter().filter(|call| **call == Call::Commit).count(),
            2
        );
    }

    #[test]
    fn tenant_store_restores_exact_and_active_legal_holds() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new(
                [
                    vec![FakeRow::legal_hold(
                        "workspace_01",
                        "hold_released",
                        "principal_admin",
                        "released",
                        2,
                        "principal_admin",
                        100,
                        200,
                    )],
                    vec![FakeRow::legal_hold(
                        "workspace_01",
                        "hold_active",
                        "principal_admin",
                        "active",
                        1,
                        "",
                        300,
                        0,
                    )],
                ]
                .into(),
            ),
        });
        let tenant = store.for_workspace(WorkspaceId::new("workspace_01"));

        let released = tenant
            .find_legal_hold(
                &WorkspaceId::new("workspace_01"),
                &LegalHoldId::new("hold_released"),
            )
            .expect("hold lookup")
            .expect("hold");
        assert_eq!(released.status(), LegalHoldStatus::Released);
        assert_eq!(
            released.released_by().map(PrincipalId::as_str),
            Some("principal_admin")
        );
        let active = tenant
            .list_active_legal_holds(&WorkspaceId::new("workspace_01"))
            .expect("active holds");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].status(), LegalHoldStatus::Active);
        assert!(calls.borrow().contains(&Call::Query(
            FIND_LEGAL_HOLD_SQL.to_owned(),
            vec![
                "text:workspace_01".to_owned(),
                "text:hold_released".to_owned(),
            ]
        )));
        assert!(calls.borrow().contains(&Call::Query(
            LIST_ACTIVE_LEGAL_HOLDS_SQL.to_owned(),
            vec!["text:workspace_01".to_owned()]
        )));
    }

    #[test]
    fn retention_port_atomically_places_and_releases_legal_hold_with_audit() {
        fn audit(action: AdministrativeAction, suffix: &str) -> AdministrativeAuditEvent {
            AdministrativeAuditEvent::new(
                AdministrativeAuditEventId::new(format!("audit_{suffix}")),
                WorkspaceId::new("workspace_01"),
                PrincipalId::new("principal_admin"),
                action,
                AdministrativeTargetKind::LegalHold,
                "hold_01",
                format!("request_{suffix}"),
                150,
            )
            .expect("audit")
        }

        let active = rembrane_domain::WorkspaceLegalHold::active(
            LegalHoldId::new("hold_01"),
            WorkspaceId::new("workspace_01"),
            PrincipalId::new("principal_admin"),
            100,
        )
        .expect("active hold");
        let released = active
            .clone()
            .release(PrincipalId::new("principal_admin"), 200)
            .expect("released hold");
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new([Vec::new(), Vec::new()].into()),
        });
        let mut tenant = store.for_workspace(WorkspaceId::new("workspace_01"));

        RetentionRepository::insert_legal_hold(
            &mut tenant,
            active,
            audit(AdministrativeAction::LegalHoldPlaced, "placed"),
        )
        .expect("place hold");
        RetentionRepository::replace_legal_hold(
            &mut tenant,
            released,
            1,
            audit(AdministrativeAction::LegalHoldReleased, "released"),
        )
        .expect("release hold");

        let calls = calls.borrow();
        assert!(calls.iter().any(
            |call| matches!(call, Call::Execute(statement, _) if statement == INSERT_LEGAL_HOLD_SQL)
        ));
        assert!(calls.iter().any(
            |call| matches!(call, Call::Execute(statement, _) if statement == REPLACE_LEGAL_HOLD_SQL)
        ));
        assert!(calls.iter().any(|call| {
            matches!(
                call,
                Call::Execute(statement, parameters)
                    if statement == INSERT_LEGAL_HOLD_SQL
                        && parameters.contains(&"optional-text:null".to_owned())
                        && parameters.contains(&"optional-i64:null".to_owned())
            )
        }));
        assert_eq!(
            calls.iter().filter(|call| **call == Call::Commit).count(),
            2
        );
    }

    #[test]
    fn tenant_store_runs_invitation_service_without_provisioning_credentials() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new(
                [
                    vec![FakeRow::workspace("workspace_01", "shared")],
                    vec![FakeRow::membership(
                        "workspace_01",
                        "principal_admin",
                        "admin",
                        "active",
                    )],
                    Vec::new(),
                    Vec::new(),
                ]
                .into(),
            ),
        });
        let mut tenant = store.for_workspace(WorkspaceId::new("workspace_01"));

        let invitation = InvitationService::new(&mut tenant)
            .create(CreateInvitationCommand {
                invitation_id: InvitationId::new("invitation_01"),
                workspace_id: WorkspaceId::new("workspace_01"),
                invited_principal_id: PrincipalId::new("principal_guest"),
                invited_by: PrincipalId::new("principal_admin"),
                role: WorkspaceRole::Member,
                request_id: "request_create_01".to_owned(),
                created_at_epoch_seconds: 100,
                expires_at_epoch_seconds: 200,
            })
            .expect("tenant-scoped invitation service");

        assert_eq!(invitation.id().as_str(), "invitation_01");
        assert!(calls.borrow().iter().any(
            |call| matches!(call, Call::Execute(statement, _) if statement == INSERT_INVITATION_SQL)
        ));
        assert_eq!(calls.borrow().last(), Some(&Call::Commit));
    }

    #[test]
    fn membership_mutations_bind_canonical_identity_role_and_status() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let store = PostgresStore::new(FakePool {
            calls: Rc::clone(&calls),
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new([Vec::new(), Vec::new()].into()),
        });
        let membership = rembrane_domain::Membership::new(
            WorkspaceId::new("workspace_01"),
            rembrane_domain::PrincipalId::new("principal_01"),
            rembrane_domain::WorkspaceRole::Member,
        );
        store
            .insert_membership(&membership)
            .expect("membership insert");
        store
            .replace_membership(&membership.suspend())
            .expect("membership replacement");

        let writes = calls
            .borrow()
            .iter()
            .filter_map(|call| match call {
                Call::Execute(statement, parameters)
                    if statement == INSERT_MEMBERSHIP_SQL
                        || statement == REPLACE_MEMBERSHIP_SQL =>
                {
                    Some((statement.clone(), parameters.clone()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            writes,
            [
                (
                    INSERT_MEMBERSHIP_SQL.to_owned(),
                    vec![
                        "text:workspace_01".to_owned(),
                        "text:principal_01".to_owned(),
                        "text:member".to_owned(),
                        "text:active".to_owned(),
                    ],
                ),
                (
                    REPLACE_MEMBERSHIP_SQL.to_owned(),
                    vec![
                        "text:workspace_01".to_owned(),
                        "text:principal_01".to_owned(),
                        "text:member".to_owned(),
                        "text:suspended".to_owned(),
                    ],
                ),
            ]
        );
        assert_eq!(
            calls
                .borrow()
                .iter()
                .filter(|call| **call == Call::Commit)
                .count(),
            2
        );
    }

    #[test]
    fn membership_application_port_is_usable_with_the_driver_boundary() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut store = PostgresStore::new(FakePool {
            calls,
            tenant_batches: RefCell::new(
                [
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                    VecDeque::from([
                        Ok(Some("workspace_01".to_owned())),
                        Ok(Some("workspace_01".to_owned())),
                    ]),
                ]
                .into(),
            ),
            row_batches: RefCell::new(
                [
                    vec![FakeRow::membership(
                        "workspace_01",
                        "principal_01",
                        "member",
                        "active",
                    )],
                    Vec::new(),
                ]
                .into(),
            ),
        });
        let workspace_id = WorkspaceId::new("workspace_01");
        let principal_id = rembrane_domain::PrincipalId::new("principal_01");

        let membership =
            MembershipRepository::find_membership(&store, &workspace_id, &principal_id)
                .expect("application membership lookup")
                .expect("membership");
        MembershipRepository::replace_membership(&mut store, membership)
            .expect("application membership replacement");
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ClassifiedError {
        Unique,
        ForeignKey,
        Check,
        Serialization,
        Other,
    }

    impl ClassifiedPostgresError for ClassifiedError {
        fn kind(&self) -> PostgresFailureKind {
            match self {
                Self::Unique => PostgresFailureKind::UniqueViolation,
                Self::ForeignKey => PostgresFailureKind::ForeignKeyViolation,
                Self::Check => PostgresFailureKind::CheckViolation,
                Self::Serialization => PostgresFailureKind::SerializationFailure,
                Self::Other => PostgresFailureKind::Other,
            }
        }
    }

    #[test]
    fn classified_driver_failures_map_to_opaque_application_errors() {
        assert_eq!(
            map_application_error(PostgresStoreError::Tenant(TenantTransactionError::Driver(
                ClassifiedError::Unique
            ))),
            ApplicationError::AlreadyExists
        );
        for failure in [ClassifiedError::ForeignKey, ClassifiedError::Check] {
            assert!(matches!(
                map_application_error(PostgresStoreError::Tenant(
                    TenantTransactionError::Driver(failure)
                )),
                ApplicationError::Validation(message)
                    if message == "database constraint rejected the membership"
            ));
        }
        for failure in [ClassifiedError::Serialization, ClassifiedError::Other] {
            assert_eq!(
                map_application_error(PostgresStoreError::Tenant(TenantTransactionError::Driver(
                    failure
                ))),
                ApplicationError::StorageUnavailable
            );
        }
        assert_eq!(
            map_application_error::<ClassifiedError>(PostgresStoreError::MissingRow),
            ApplicationError::NotFound
        );
        assert_eq!(
            map_invitation_application_error(PostgresStoreError::Tenant(
                TenantTransactionError::Driver(ClassifiedError::ForeignKey)
            )),
            ApplicationError::NotFound
        );
    }
}

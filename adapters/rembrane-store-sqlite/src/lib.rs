//! Persistent tenant-isolated `SQLite` adapter.

mod booking_research;
mod canonical;
mod channel;
mod checkpoint;
mod disclosure;
mod graph_projection;
mod knowledge_graph;
mod projection;
mod share;
mod trip;

use std::path::Path;

use rembrane_application::{
    AdministrativeAuditRepository, ApplicationError, InvitationRepository, KeyRotationRepository,
    MAX_ADMINISTRATIVE_AUDIT_PAGE, MemberLifecycleRepository, MemberScopeGrantRepository,
    MembershipRepository, MemoryRepository, RetentionPurgePlan, RetentionPurgeRepository,
    RetentionPurgeResult, RetentionRepository, ShareProposalRepository, WorkspaceRepository,
    is_strict_successor,
};
use rembrane_codec::decode_memory;
use rembrane_crypto::{EncryptedPayload, EncryptionContext, PayloadPurpose, RecordCipher};
use rembrane_domain::{
    ActivityId, AdministrativeAction, AdministrativeAuditEvent, AdministrativeAuditEventId,
    AdministrativeTargetKind, EntityId, Invitation, InvitationId, InvitationStatus, KeyRotationId,
    KeyRotationReceipt, KeyRotationStatus, LegalHoldId, LegalHoldStatus, MemberScopeGrant,
    Membership, MembershipStatus, MemoryId, MemoryRecord, MemoryScope, MemoryShareProposal,
    Principal, PrincipalId, ProviderId, ReadScope, RetentionPeriod, RetentionResource,
    ShareProposalId, ShareProposalStatus, Workspace, WorkspaceId, WorkspaceKeyRotation,
    WorkspaceKind, WorkspaceLegalHold, WorkspaceRetentionPolicy, WorkspaceRole,
};
use rusqlite::{Connection, ErrorCode, OptionalExtension, params};

const CANONICAL_SCHEMA: &str = include_str!("../../../migrations/sqlite/0001_canonical_schema.sql");
const CHECKPOINT_DISCLOSURE_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0002_checkpoint_disclosures.sql");
const WORKSPACE_INVITATION_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0003_workspace_invitations.sql");
const MEMBER_SCOPE_GRANT_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0004_member_scope_grants.sql");
const MEMORY_SHARE_PROPOSAL_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0005_memory_share_proposals.sql");
const TRIP_MIGRATION: &str = include_str!("../../../migrations/sqlite/0006_trips.sql");
const BOOKING_RESEARCH_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0007_booking_research.sql");
const TRAVEL_DISCLOSURE_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0008_travel_disclosures.sql");
const TRAVEL_SENSITIVE_DISCLOSURE_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0009_travel_sensitive_disclosures.sql");
const TRAVEL_SENSITIVE_PROFILE_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0010_travel_sensitive_profiles.sql");
const KNOWLEDGE_GRAPH_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0011_knowledge_graph.sql");
const GRAPH_PROJECTION_OUTBOX_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0012_graph_projection_outbox.sql");
const WORKSPACE_KEY_ROTATION_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0013_workspace_key_rotations.sql");
const KEY_ROTATION_RECEIPT_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0014_key_rotation_receipts.sql");
const ADMINISTRATIVE_AUDIT_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0015_administrative_audit.sql");
const RETENTION_AND_LEGAL_HOLDS_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0016_retention_and_legal_holds.sql");
const CHANNEL_EVENT_RECEIPTS_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0017_channel_event_receipts.sql");
const CHANNEL_SENDER_BINDINGS_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0018_channel_sender_bindings.sql");
const CHANNEL_BINDING_LIFECYCLE_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0019_channel_binding_lifecycle.sql");
const CHANNEL_BINDING_AUDIT_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0020_channel_binding_audit.sql");
const ENCRYPTED_CHANNEL_INBOX_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0021_encrypted_channel_inbox.sql");
const CHANNEL_INBOX_RETRY_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0022_channel_inbox_retry.sql");
const CHANNEL_INBOX_LEASE_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0023_channel_inbox_leases.sql");
const CHANNEL_INBOX_LEASE_OWNERSHIP_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0024_channel_inbox_lease_ownership.sql");
const CHANNEL_MESSAGE_AUDIT_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0025_channel_message_audit.sql");
const WORKSPACE_INVITATION_EXPIRY_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0026_workspace_invitation_expiry.sql");
const CURRENT_SCHEMA_VERSION: u32 = 26;
const CANONICAL_TABLES: [&str; 10] = [
    "activity_checkpoints",
    "disclosed_memories",
    "disclosure_receipts",
    "memberships",
    "memories",
    "memory_evidence",
    "principals",
    "projection_outbox",
    "workspace_events",
    "workspaces",
];

pub struct MissingCipher;

pub struct SqliteStore<C = MissingCipher> {
    connection: Connection,
    cipher: C,
}

impl<C> AdministrativeAuditRepository for SqliteStore<C> {
    fn append_administrative_audit(
        &mut self,
        event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        self.connection
            .execute(
                "INSERT INTO administrative_audit_events (
                    workspace_id, id, actor_id, action, target_kind, target_id,
                    request_id, occurred_at_epoch_seconds
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    event.workspace_id().as_str(),
                    event.id().as_str(),
                    event.actor_id().as_str(),
                    event.action().label(),
                    event.target_kind().label(),
                    event.target_id(),
                    event.request_id(),
                    event.occurred_at_epoch_seconds(),
                ],
            )
            .map_err(map_write_error)?;
        Ok(())
    }

    fn list_administrative_audit(
        &self,
        workspace_id: &WorkspaceId,
        after_epoch_seconds: u64,
        limit: usize,
    ) -> Result<Vec<AdministrativeAuditEvent>, ApplicationError> {
        if !(1..=MAX_ADMINISTRATIVE_AUDIT_PAGE).contains(&limit) {
            return Err(ApplicationError::Validation(
                "administrative audit page limit is invalid".to_owned(),
            ));
        }
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, actor_id, action, target_kind, target_id, request_id,
                        occurred_at_epoch_seconds
                 FROM administrative_audit_events
                 WHERE workspace_id = ?1 AND occurred_at_epoch_seconds > ?2
                 ORDER BY occurred_at_epoch_seconds, id
                 LIMIT ?3",
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let rows = statement
            .query_map(
                params![workspace_id.as_str(), after_epoch_seconds, limit as u64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, u64>(6)?,
                    ))
                },
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        rows.map(|row| {
            let (id, actor_id, action, target_kind, target_id, request_id, occurred_at) =
                row.map_err(|_| ApplicationError::StorageUnavailable)?;
            AdministrativeAuditEvent::new(
                AdministrativeAuditEventId::new(id),
                workspace_id.clone(),
                PrincipalId::new(actor_id),
                parse_administrative_action(&action)?,
                parse_administrative_target_kind(&target_kind)?,
                target_id,
                request_id,
                occurred_at,
            )
            .map_err(|_| ApplicationError::StorageUnavailable)
        })
        .collect()
    }
}

impl<C> RetentionRepository for SqliteStore<C> {
    fn find_retention_policy(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<WorkspaceRetentionPolicy>, ApplicationError> {
        self.connection
            .query_row(
                "SELECT version, user_memory_days, activity_checkpoint_days,
                        travel_research_days, disclosure_receipt_days,
                        canonical_event_days, administrative_audit_days
                 FROM workspace_retention_policies WHERE workspace_id = ?1",
                [workspace_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, Option<u32>>(1)?,
                        row.get::<_, Option<u32>>(2)?,
                        row.get::<_, Option<u32>>(3)?,
                        row.get::<_, Option<u32>>(4)?,
                        row.get::<_, Option<u32>>(5)?,
                        row.get::<_, Option<u32>>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?
            .map(
                |(version, memory, checkpoint, travel, disclosure, event, audit)| {
                    WorkspaceRetentionPolicy::new(
                        workspace_id.clone(),
                        version,
                        retention_period(memory)?,
                        retention_period(checkpoint)?,
                        retention_period(travel)?,
                        retention_period(disclosure)?,
                        retention_period(event)?,
                        retention_period(audit)?,
                    )
                    .map_err(|_| ApplicationError::StorageUnavailable)
                },
            )
            .transpose()
    }

    fn replace_retention_policy(
        &mut self,
        policy: WorkspaceRetentionPolicy,
        expected_version: Option<u64>,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        validate_retention_audit(&policy, &audit_event)?;
        let values = [
            policy.period(RetentionResource::UserMemory).days_value(),
            policy
                .period(RetentionResource::ActivityCheckpoint)
                .days_value(),
            policy
                .period(RetentionResource::TravelResearch)
                .days_value(),
            policy
                .period(RetentionResource::DisclosureReceipt)
                .days_value(),
            policy
                .period(RetentionResource::CanonicalEvent)
                .days_value(),
            policy
                .period(RetentionResource::AdministrativeAudit)
                .days_value(),
        ];
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let changed = match expected_version {
            None if policy.version() == 1 => transaction.execute(
                "INSERT INTO workspace_retention_policies VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    policy.workspace_id().as_str(),
                    policy.version(),
                    values[0],
                    values[1],
                    values[2],
                    values[3],
                    values[4],
                    values[5]
                ],
            ),
            Some(expected) if is_strict_successor(expected, policy.version()) => transaction
                .execute(
                    "UPDATE workspace_retention_policies SET version=?2, user_memory_days=?3,
                 activity_checkpoint_days=?4, travel_research_days=?5,
                 disclosure_receipt_days=?6, canonical_event_days=?7,
                 administrative_audit_days=?8 WHERE workspace_id=?1 AND version=?9",
                    params![
                        policy.workspace_id().as_str(),
                        policy.version(),
                        values[0],
                        values[1],
                        values[2],
                        values[3],
                        values[4],
                        values[5],
                        expected
                    ],
                ),
            None | Some(_) => return Err(ApplicationError::VersionConflict),
        }
        .map_err(map_write_error)?;
        if changed != 1 {
            return Err(ApplicationError::VersionConflict);
        }
        insert_administrative_audit(&transaction, &audit_event)?;
        transaction
            .commit()
            .map_err(|_| ApplicationError::StorageUnavailable)
    }

    fn find_legal_hold(
        &self,
        workspace_id: &WorkspaceId,
        hold_id: &LegalHoldId,
    ) -> Result<Option<WorkspaceLegalHold>, ApplicationError> {
        self.connection
            .query_row(
                "SELECT placed_by, placed_at_epoch_seconds, status, version,
                        released_by, released_at_epoch_seconds
                 FROM workspace_legal_holds WHERE workspace_id=?1 AND id=?2",
                params![workspace_id.as_str(), hold_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<u64>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?
            .map(
                |(placed_by, placed_at, status, version, released_by, released_at)| {
                    WorkspaceLegalHold::restore(
                        hold_id.clone(),
                        workspace_id.clone(),
                        PrincipalId::new(placed_by),
                        placed_at,
                        legal_hold_status(&status)?,
                        version,
                        released_by.map(PrincipalId::new),
                        released_at,
                    )
                    .map_err(|_| ApplicationError::StorageUnavailable)
                },
            )
            .transpose()
    }

    fn list_active_legal_holds(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<WorkspaceLegalHold>, ApplicationError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id FROM workspace_legal_holds
             WHERE workspace_id=?1 AND status='active' ORDER BY id",
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let ids = statement
            .query_map([workspace_id.as_str()], |row| row.get::<_, String>(0))
            .map_err(|_| ApplicationError::StorageUnavailable)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        ids.into_iter()
            .map(|id| {
                self.find_legal_hold(workspace_id, &LegalHoldId::new(id))?
                    .ok_or(ApplicationError::StorageUnavailable)
            })
            .collect()
    }

    fn insert_legal_hold(
        &mut self,
        hold: WorkspaceLegalHold,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        validate_legal_hold_audit(&hold, &audit_event, AdministrativeAction::LegalHoldPlaced)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        transaction
            .execute(
                "INSERT INTO workspace_legal_holds VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![
                    hold.workspace_id().as_str(),
                    hold.id().as_str(),
                    hold.placed_by().as_str(),
                    hold.placed_at_epoch_seconds(),
                    legal_hold_status_label(hold.status()),
                    hold.version(),
                    hold.released_by().map(PrincipalId::as_str),
                    hold.released_at_epoch_seconds()
                ],
            )
            .map_err(map_write_error)?;
        insert_administrative_audit(&transaction, &audit_event)?;
        transaction
            .commit()
            .map_err(|_| ApplicationError::StorageUnavailable)
    }

    fn replace_legal_hold(
        &mut self,
        hold: WorkspaceLegalHold,
        expected_version: u64,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        validate_legal_hold_audit(&hold, &audit_event, AdministrativeAction::LegalHoldReleased)?;
        if !is_strict_successor(expected_version, hold.version()) {
            return Err(ApplicationError::VersionConflict);
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let changed = transaction
            .execute(
                "UPDATE workspace_legal_holds SET status=?3, version=?4, released_by=?5,
             released_at_epoch_seconds=?6 WHERE workspace_id=?1 AND id=?2 AND version=?7",
                params![
                    hold.workspace_id().as_str(),
                    hold.id().as_str(),
                    legal_hold_status_label(hold.status()),
                    hold.version(),
                    hold.released_by().map(PrincipalId::as_str),
                    hold.released_at_epoch_seconds(),
                    expected_version
                ],
            )
            .map_err(map_write_error)?;
        if changed != 1 {
            return Err(ApplicationError::VersionConflict);
        }
        insert_administrative_audit(&transaction, &audit_event)?;
        transaction
            .commit()
            .map_err(|_| ApplicationError::StorageUnavailable)
    }
}

impl<C> RetentionPurgeRepository for SqliteStore<C> {
    fn execute_retention_purge(
        &mut self,
        plan: &RetentionPurgePlan,
    ) -> Result<RetentionPurgeResult, ApplicationError> {
        if plan.maximum_items == 0 {
            return Err(ApplicationError::Validation(
                "retention purge limit must be positive".to_owned(),
            ));
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let mut remaining = plan.maximum_items;
        let mut result = RetentionPurgeResult::default();

        if let Some(cutoff) = plan.disclosure_cutoff_epoch_seconds {
            for table in [
                "disclosure_receipts",
                "checkpoint_disclosures",
                "travel_disclosure_receipts",
            ] {
                if remaining == 0 {
                    break;
                }
                let deleted = delete_bounded_by_created_at(
                    &transaction,
                    table,
                    &plan.workspace_id,
                    cutoff,
                    remaining,
                    None,
                )?;
                result.disclosures = result.disclosures.saturating_add(deleted);
                remaining = remaining.saturating_sub(deleted);
            }
        }
        if let Some(cutoff) = plan.travel_cutoff_epoch_seconds {
            let deleted = delete_bounded_by_created_at(
                &transaction,
                "booking_research",
                &plan.workspace_id,
                cutoff,
                remaining,
                Some(
                    "NOT EXISTS (SELECT 1 FROM disclosed_booking_research d \
                     WHERE d.workspace_id=booking_research.workspace_id \
                     AND d.research_id=booking_research.id)",
                ),
            )?;
            result.travel_research = deleted;
            remaining = remaining.saturating_sub(deleted);
        }
        if let Some(cutoff) = plan.checkpoint_cutoff_epoch_seconds {
            let deleted = delete_bounded_by_created_at(
                &transaction,
                "activity_checkpoints",
                &plan.workspace_id,
                cutoff,
                remaining,
                Some(
                    "NOT EXISTS (SELECT 1 FROM checkpoint_disclosures d \
                     WHERE d.workspace_id=activity_checkpoints.workspace_id \
                     AND d.checkpoint_id=activity_checkpoints.id)",
                ),
            )?;
            result.checkpoints = deleted;
            remaining = remaining.saturating_sub(deleted);
        }
        if let Some(cutoff) = plan.memory_cutoff_epoch_seconds {
            let deleted = delete_bounded_by_created_at(
                &transaction,
                "memories",
                &plan.workspace_id,
                cutoff,
                remaining,
                Some(
                    "NOT EXISTS (SELECT 1 FROM disclosed_memories d \
                     WHERE d.workspace_id=memories.workspace_id AND d.memory_id=memories.id) \
                     AND NOT EXISTS (SELECT 1 FROM projection_outbox p \
                     WHERE p.workspace_id=memories.workspace_id AND p.memory_id=memories.id)",
                ),
            )?;
            result.memories = deleted;
            remaining = remaining.saturating_sub(deleted);
        }
        if let Some(cutoff) = plan.event_cutoff_epoch_seconds {
            let deleted = delete_bounded_by_created_at(
                &transaction,
                "workspace_events",
                &plan.workspace_id,
                cutoff,
                remaining,
                None,
            )?;
            result.canonical_events = deleted;
        }

        transaction
            .commit()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        Ok(result)
    }
}

fn delete_bounded_by_created_at(
    connection: &Connection,
    table: &str,
    workspace_id: &WorkspaceId,
    cutoff_epoch_seconds: u64,
    limit: usize,
    additional_predicate: Option<&str>,
) -> Result<usize, ApplicationError> {
    if limit == 0 {
        return Ok(0);
    }
    let allowed_table = matches!(
        table,
        "disclosure_receipts"
            | "checkpoint_disclosures"
            | "travel_disclosure_receipts"
            | "booking_research"
            | "activity_checkpoints"
            | "memories"
            | "workspace_events"
    );
    if !allowed_table {
        return Err(ApplicationError::StorageUnavailable);
    }
    let predicate = additional_predicate.unwrap_or("1=1");
    let statement = format!(
        "DELETE FROM {table} WHERE rowid IN (
            SELECT rowid FROM {table}
            WHERE workspace_id=?1 AND unixepoch(created_at) <= ?2 AND {predicate}
            ORDER BY created_at, rowid LIMIT ?3
        )"
    );
    let cutoff = i64::try_from(cutoff_epoch_seconds).map_err(|_| {
        ApplicationError::Validation("retention cutoff is outside SQLite range".to_owned())
    })?;
    let limit = i64::try_from(limit).map_err(|_| {
        ApplicationError::Validation("retention purge limit is outside SQLite range".to_owned())
    })?;
    connection
        .execute(&statement, params![workspace_id.as_str(), cutoff, limit])
        .map_err(map_write_error)
}

fn retention_period(days: Option<u32>) -> Result<RetentionPeriod, ApplicationError> {
    days.map_or(Ok(RetentionPeriod::Forever), |days| {
        RetentionPeriod::days(days).map_err(|_| ApplicationError::StorageUnavailable)
    })
}

fn legal_hold_status(value: &str) -> Result<LegalHoldStatus, ApplicationError> {
    match value {
        "active" => Ok(LegalHoldStatus::Active),
        "released" => Ok(LegalHoldStatus::Released),
        _ => Err(ApplicationError::StorageUnavailable),
    }
}

const fn legal_hold_status_label(status: LegalHoldStatus) -> &'static str {
    match status {
        LegalHoldStatus::Active => "active",
        LegalHoldStatus::Released => "released",
    }
}

fn parse_administrative_action(value: &str) -> Result<AdministrativeAction, ApplicationError> {
    match value {
        "member-removed" => Ok(AdministrativeAction::MemberRemoved),
        "key-rotation-required" => Ok(AdministrativeAction::KeyRotationRequired),
        "key-rotation-completed" => Ok(AdministrativeAction::KeyRotationCompleted),
        "scope-grant-changed" => Ok(AdministrativeAction::ScopeGrantChanged),
        "retention-policy-changed" => Ok(AdministrativeAction::RetentionPolicyChanged),
        "legal-hold-placed" => Ok(AdministrativeAction::LegalHoldPlaced),
        "legal-hold-released" => Ok(AdministrativeAction::LegalHoldReleased),
        "channel-binding-created" => Ok(AdministrativeAction::ChannelBindingCreated),
        "channel-binding-revoked" => Ok(AdministrativeAction::ChannelBindingRevoked),
        "channel-message-requeued" => Ok(AdministrativeAction::ChannelMessageRequeued),
        _ => Err(ApplicationError::StorageUnavailable),
    }
}

fn parse_administrative_target_kind(
    value: &str,
) -> Result<AdministrativeTargetKind, ApplicationError> {
    match value {
        "principal" => Ok(AdministrativeTargetKind::Principal),
        "key-rotation" => Ok(AdministrativeTargetKind::KeyRotation),
        "scope-grant" => Ok(AdministrativeTargetKind::ScopeGrant),
        "retention-policy" => Ok(AdministrativeTargetKind::RetentionPolicy),
        "legal-hold" => Ok(AdministrativeTargetKind::LegalHold),
        "channel-binding" => Ok(AdministrativeTargetKind::ChannelBinding),
        "channel-message" => Ok(AdministrativeTargetKind::ChannelMessage),
        _ => Err(ApplicationError::StorageUnavailable),
    }
}

impl SqliteStore<MissingCipher> {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ApplicationError> {
        let connection =
            Connection::open(path).map_err(|_| ApplicationError::StorageUnavailable)?;
        Self::initialize(connection)
    }

    pub fn open_in_memory() -> Result<Self, ApplicationError> {
        let connection =
            Connection::open_in_memory().map_err(|_| ApplicationError::StorageUnavailable)?;
        Self::initialize(connection)
    }

    fn initialize(mut connection: Connection) -> Result<Self, ApplicationError> {
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA busy_timeout = 5000;
                 PRAGMA journal_mode = WAL;",
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        migrate(&mut connection)?;
        Ok(Self {
            connection,
            cipher: MissingCipher,
        })
    }
}

#[allow(clippy::too_many_lines)]
fn migrate(connection: &mut Connection) -> Result<(), ApplicationError> {
    let mut version = schema_version(connection)?;
    if version > CURRENT_SCHEMA_VERSION {
        return Err(ApplicationError::StorageUnavailable);
    }
    if version == CURRENT_SCHEMA_VERSION {
        return Ok(());
    }

    if version == 0 && has_user_tables(connection)? {
        verify_legacy_schema(connection)?;
        connection
            .pragma_update(None, "user_version", 1)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 1;
    }

    let transaction = connection
        .transaction()
        .map_err(|_| ApplicationError::StorageUnavailable)?;
    if version == 0 {
        transaction
            .execute_batch(CANONICAL_SCHEMA)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 1;
    }
    if version == 1 {
        transaction
            .execute_batch(CHECKPOINT_DISCLOSURE_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 2;
    }
    if version == 2 {
        transaction
            .execute_batch(WORKSPACE_INVITATION_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 3;
    }
    if version == 3 {
        transaction
            .execute_batch(MEMBER_SCOPE_GRANT_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 4;
    }
    if version == 4 {
        transaction
            .execute_batch(MEMORY_SHARE_PROPOSAL_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 5;
    }
    if version == 5 {
        transaction
            .execute_batch(TRIP_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 6;
    }
    if version == 6 {
        transaction
            .execute_batch(BOOKING_RESEARCH_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 7;
    }
    if version == 7 {
        transaction
            .execute_batch(TRAVEL_DISCLOSURE_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 8;
    }
    if version == 8 {
        transaction
            .execute_batch(TRAVEL_SENSITIVE_DISCLOSURE_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 9;
    }
    if version == 9 {
        transaction
            .execute_batch(TRAVEL_SENSITIVE_PROFILE_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 10;
    }
    if version == 10 {
        transaction
            .execute_batch(KNOWLEDGE_GRAPH_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 11;
    }
    if version == 11 {
        transaction
            .execute_batch(GRAPH_PROJECTION_OUTBOX_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 12;
    }
    if version == 12 {
        transaction
            .execute_batch(WORKSPACE_KEY_ROTATION_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 13;
    }
    if version == 13 {
        transaction
            .execute_batch(KEY_ROTATION_RECEIPT_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 14;
    }
    if version == 14 {
        transaction
            .execute_batch(ADMINISTRATIVE_AUDIT_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 15;
    }
    if version == 15 {
        transaction
            .execute_batch(RETENTION_AND_LEGAL_HOLDS_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 16;
    }
    if version == 16 {
        transaction
            .execute_batch(CHANNEL_EVENT_RECEIPTS_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 17;
    }
    if version == 17 {
        transaction
            .execute_batch(CHANNEL_SENDER_BINDINGS_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 18;
    }
    if version == 18 {
        transaction
            .execute_batch(CHANNEL_BINDING_LIFECYCLE_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 19;
    }
    if version == 19 {
        transaction
            .execute_batch(CHANNEL_BINDING_AUDIT_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 20;
    }
    if version == 20 {
        transaction
            .execute_batch(ENCRYPTED_CHANNEL_INBOX_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 21;
    }
    if version == 21 {
        transaction
            .execute_batch(CHANNEL_INBOX_RETRY_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 22;
    }
    if version == 22 {
        transaction
            .execute_batch(CHANNEL_INBOX_LEASE_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 23;
    }
    if version == 23 {
        transaction
            .execute_batch(CHANNEL_INBOX_LEASE_OWNERSHIP_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 24;
    }
    if version == 24 {
        transaction
            .execute_batch(CHANNEL_MESSAGE_AUDIT_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        version = 25;
    }
    if version == 25 {
        transaction
            .execute_batch(WORKSPACE_INVITATION_EXPIRY_MIGRATION)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
    }
    transaction
        .pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)
        .map_err(|_| ApplicationError::StorageUnavailable)?;
    transaction
        .commit()
        .map_err(|_| ApplicationError::StorageUnavailable)
}

fn schema_version(connection: &Connection) -> Result<u32, ApplicationError> {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| ApplicationError::StorageUnavailable)
}

fn has_user_tables(connection: &Connection) -> Result<bool, ApplicationError> {
    connection
        .query_row(
            "SELECT EXISTS (
                SELECT 1
                FROM sqlite_schema
                WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| ApplicationError::StorageUnavailable)
}

fn verify_legacy_schema(connection: &Connection) -> Result<(), ApplicationError> {
    let mut statement = connection
        .prepare(
            "SELECT name
             FROM sqlite_schema
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )
        .map_err(|_| ApplicationError::StorageUnavailable)?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| ApplicationError::StorageUnavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ApplicationError::StorageUnavailable)?;

    if names == CANONICAL_TABLES {
        Ok(())
    } else {
        Err(ApplicationError::StorageUnavailable)
    }
}

impl<C> SqliteStore<C> {
    #[must_use]
    pub fn with_cipher<D: RecordCipher>(self, cipher: D) -> SqliteStore<D> {
        SqliteStore {
            connection: self.connection,
            cipher,
        }
    }

    pub fn backup_to(&self, destination: impl AsRef<Path>) -> Result<(), ApplicationError> {
        let destination = destination.as_ref();
        if destination.exists() {
            return Err(ApplicationError::AlreadyExists);
        }
        let destination = destination
            .to_str()
            .ok_or(ApplicationError::StorageUnavailable)?;
        self.connection
            .execute("VACUUM INTO ?1", [destination])
            .map_err(map_write_error)?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod migration_tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::Connection;

    use super::{CURRENT_SCHEMA_VERSION, SqliteStore, schema_version};

    fn database_path(test_name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rembrane-{test_name}-{}-{unique}.sqlite",
            std::process::id()
        ))
    }

    #[test]
    fn initializes_and_reopens_the_current_schema() {
        let database = database_path("schema-reopen");
        SqliteStore::open(&database).expect("database should initialize");

        let connection = Connection::open(&database).expect("database should reopen");
        assert_eq!(
            schema_version(&connection).expect("schema version should read"),
            CURRENT_SCHEMA_VERSION
        );
        drop(connection);

        SqliteStore::open(&database).expect("current database should reopen idempotently");
        fs::remove_file(database).expect("temporary database should be removed");
    }

    #[test]
    fn configures_integrity_and_contention_pragmas() {
        let database = database_path("connection-pragmas");
        let store = SqliteStore::open(&database).expect("database should initialize");
        let foreign_keys: u32 = store
            .connection
            .pragma_query_value(None, "foreign_keys", |row| row.get(0))
            .expect("foreign key pragma should read");
        let busy_timeout: u32 = store
            .connection
            .pragma_query_value(None, "busy_timeout", |row| row.get(0))
            .expect("busy timeout pragma should read");
        let journal_mode: String = store
            .connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("journal mode pragma should read");

        assert_eq!(foreign_keys, 1);
        assert_eq!(busy_timeout, 5_000);
        assert_eq!(journal_mode, "wal");
        drop(store);
        fs::remove_file(database).expect("temporary database should be removed");
    }

    #[test]
    fn rejects_a_database_from_a_newer_schema_version() {
        let database = database_path("future-schema");
        let connection = Connection::open(&database).expect("database should open");
        connection
            .pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION + 1)
            .expect("future version should be set");
        drop(connection);

        assert!(SqliteStore::open(&database).is_err());
        fs::remove_file(database).expect("temporary database should be removed");
    }

    #[test]
    fn adopts_the_complete_pre_versioned_schema() {
        let database = database_path("legacy-schema");
        let connection = Connection::open(&database).expect("database should open");
        connection
            .execute_batch(super::CANONICAL_SCHEMA)
            .expect("legacy schema should initialize");
        drop(connection);

        SqliteStore::open(&database).expect("complete legacy schema should be adopted");
        let connection = Connection::open(&database).expect("database should reopen");
        assert_eq!(
            schema_version(&connection).expect("schema version should read"),
            CURRENT_SCHEMA_VERSION
        );
        drop(connection);
        fs::remove_file(database).expect("temporary database should be removed");
    }

    #[test]
    fn upgrades_version_one_through_all_migrations() {
        let database = database_path("schema-v1-upgrade");
        let connection = Connection::open(&database).expect("database should open");
        connection
            .execute_batch(super::CANONICAL_SCHEMA)
            .expect("version one schema should initialize");
        connection
            .pragma_update(None, "user_version", 1)
            .expect("version one should be recorded");
        drop(connection);

        SqliteStore::open(&database).expect("version one should upgrade");
        let connection = Connection::open(&database).expect("database should reopen");
        assert_eq!(
            schema_version(&connection).expect("schema version should read"),
            CURRENT_SCHEMA_VERSION
        );
        let table_exists: bool = connection
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM sqlite_schema
                    WHERE type = 'table'
                      AND name = 'checkpoint_disclosures'
                )",
                [],
                |row| row.get(0),
            )
            .expect("migration table should be inspectable");
        assert!(table_exists);
        let invitations_exist: bool = connection
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM sqlite_schema
                    WHERE type = 'table'
                      AND name = 'workspace_invitations'
                )",
                [],
                |row| row.get(0),
            )
            .expect("invitation migration should be inspectable");
        assert!(invitations_exist);
        let member_scope_grants_exist: bool = connection
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM sqlite_schema
                    WHERE type = 'table'
                      AND name = 'member_scope_grants'
                )",
                [],
                |row| row.get(0),
            )
            .expect("member scope migration should be inspectable");
        assert!(member_scope_grants_exist);
        let share_proposals_exist: bool = connection
            .query_row(
                "SELECT EXISTS (
                    SELECT 1 FROM sqlite_schema
                    WHERE type = 'table'
                      AND name = 'memory_share_proposals'
                )",
                [],
                |row| row.get(0),
            )
            .expect("share proposal migration should be inspectable");
        assert!(share_proposals_exist);
        drop(connection);
        fs::remove_file(database).expect("temporary database should be removed");
    }

    #[test]
    fn rejects_an_unknown_pre_versioned_schema() {
        let database = database_path("unknown-schema");
        let connection = Connection::open(&database).expect("database should open");
        connection
            .execute("CREATE TABLE unrelated (id TEXT PRIMARY KEY) STRICT", [])
            .expect("unknown table should initialize");
        drop(connection);

        assert!(SqliteStore::open(&database).is_err());
        fs::remove_file(database).expect("temporary database should be removed");
    }
}

impl<C: RecordCipher> MemoryRepository for SqliteStore<C> {
    fn find(
        &self,
        workspace_id: &WorkspaceId,
        memory_id: &MemoryId,
    ) -> Result<Option<MemoryRecord>, ApplicationError> {
        let row = self
            .connection
            .query_row(
                "SELECT
                    version,
                    content_ciphertext,
                    encryption_key_id,
                    encryption_algorithm,
                    encryption_nonce
                 FROM memories
                 WHERE workspace_id = ?1 AND id = ?2",
                params![workspace_id.as_str(), memory_id.as_str()],
                encrypted_memory_row,
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?;

        row.map(|encrypted| decrypt_memory_record(&self.cipher, workspace_id, memory_id, encrypted))
            .transpose()
    }

    fn list_for_subject(
        &self,
        workspace_id: &WorkspaceId,
        subject_id: &PrincipalId,
    ) -> Result<Vec<MemoryRecord>, ApplicationError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT
                    id,
                    version,
                    content_ciphertext,
                    encryption_key_id,
                    encryption_algorithm,
                    encryption_nonce
                 FROM memories
                 WHERE workspace_id = ?1 AND subject_id = ?2
                 ORDER BY id",
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let rows = statement
            .query_map(params![workspace_id.as_str(), subject_id.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    EncryptedMemoryRow {
                        version: row.get(1)?,
                        ciphertext: row.get(2)?,
                        key_id: row.get(3)?,
                        algorithm: row.get(4)?,
                        nonce: row.get(5)?,
                    },
                ))
            })
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let mut memories = Vec::new();
        for row in rows {
            let (memory_id, encrypted) = row.map_err(|_| ApplicationError::StorageUnavailable)?;
            let memory_id = MemoryId::new(memory_id);
            let memory = decrypt_memory_record(&self.cipher, workspace_id, &memory_id, encrypted)?;
            if memory.subject_id() != subject_id {
                return Err(ApplicationError::StorageUnavailable);
            }
            memories.push(memory);
        }
        Ok(memories)
    }
}

pub(crate) fn decrypt_memory_record(
    cipher: &impl RecordCipher,
    workspace_id: &WorkspaceId,
    memory_id: &MemoryId,
    encrypted: EncryptedMemoryRow,
) -> Result<MemoryRecord, ApplicationError> {
    let context = EncryptionContext::new(
        workspace_id.clone(),
        memory_id.as_str(),
        encrypted.version,
        PayloadPurpose::MemoryContent,
    )
    .map_err(|_| ApplicationError::StorageUnavailable)?;
    let payload = EncryptedPayload::new(
        encrypted.ciphertext,
        encrypted.key_id,
        encrypted.algorithm,
        encrypted.nonce,
    )
    .map_err(|_| ApplicationError::StorageUnavailable)?;
    let plaintext = cipher
        .open(&context, &payload)
        .map_err(|_| ApplicationError::StorageUnavailable)?;
    let memory = decode_memory(&plaintext).map_err(|_| ApplicationError::StorageUnavailable)?;
    if memory.workspace_id() != workspace_id || memory.id() != memory_id {
        return Err(ApplicationError::StorageUnavailable);
    }
    Ok(memory)
}

pub(crate) struct EncryptedMemoryRow {
    version: u64,
    ciphertext: Vec<u8>,
    key_id: String,
    algorithm: String,
    nonce: Vec<u8>,
}

pub(crate) fn encrypted_memory_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<EncryptedMemoryRow> {
    Ok(EncryptedMemoryRow {
        version: row.get(0)?,
        ciphertext: row.get(1)?,
        key_id: row.get(2)?,
        algorithm: row.get(3)?,
        nonce: row.get(4)?,
    })
}

impl<C> WorkspaceRepository for SqliteStore<C> {
    fn initialize_personal_workspace(
        &mut self,
        principal: Principal,
        workspace: Workspace,
        owner_membership: Membership,
    ) -> Result<(), ApplicationError> {
        validate_personal_bootstrap(&principal, &workspace, &owner_membership)?;

        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        transaction
            .execute(
                "INSERT INTO principals (id) VALUES (?1)",
                [principal.id().as_str()],
            )
            .map_err(map_write_error)?;
        transaction
            .execute(
                "INSERT INTO workspaces (id, kind) VALUES (?1, 'personal')",
                [workspace.id().as_str()],
            )
            .map_err(map_write_error)?;
        transaction
            .execute(
                "INSERT INTO memberships (
                    workspace_id,
                    principal_id,
                    role,
                    status
                ) VALUES (?1, ?2, 'owner', 'active')",
                params![
                    owner_membership.workspace_id().as_str(),
                    owner_membership.principal_id().as_str()
                ],
            )
            .map_err(map_write_error)?;
        transaction
            .commit()
            .map_err(|_| ApplicationError::StorageUnavailable)
    }

    fn initialize_shared_workspace(
        &mut self,
        workspace: Workspace,
        owner_membership: Membership,
    ) -> Result<(), ApplicationError> {
        validate_shared_bootstrap(&workspace, &owner_membership)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let owner_exists: bool = transaction
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM principals WHERE id = ?1)",
                [owner_membership.principal_id().as_str()],
                |row| row.get(0),
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        if !owner_exists {
            return Err(ApplicationError::NotFound);
        }
        transaction
            .execute(
                "INSERT INTO workspaces (id, kind) VALUES (?1, 'shared')",
                [workspace.id().as_str()],
            )
            .map_err(map_write_error)?;
        transaction
            .execute(
                "INSERT INTO memberships (
                    workspace_id, principal_id, role, status
                ) VALUES (?1, ?2, 'owner', 'active')",
                params![
                    owner_membership.workspace_id().as_str(),
                    owner_membership.principal_id().as_str()
                ],
            )
            .map_err(map_write_error)?;
        transaction
            .commit()
            .map_err(|_| ApplicationError::StorageUnavailable)
    }

    fn find_principal(
        &self,
        principal_id: &PrincipalId,
    ) -> Result<Option<Principal>, ApplicationError> {
        self.connection
            .query_row(
                "SELECT id FROM principals WHERE id = ?1",
                [principal_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map(|id| id.map(|value| Principal::new(PrincipalId::new(value))))
            .map_err(|_| ApplicationError::StorageUnavailable)
    }

    fn find_workspace(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<Workspace>, ApplicationError> {
        self.connection
            .query_row(
                "SELECT id, kind FROM workspaces WHERE id = ?1",
                [workspace_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?
            .map(|(id, kind)| decode_workspace(id, &kind))
            .transpose()
    }
}

impl<C> MembershipRepository for SqliteStore<C> {
    fn insert_membership(&mut self, membership: Membership) -> Result<(), ApplicationError> {
        self.connection
            .execute(
                "INSERT INTO memberships (
                    workspace_id,
                    principal_id,
                    role,
                    status
                ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    membership.workspace_id().as_str(),
                    membership.principal_id().as_str(),
                    encode_role(membership.role()),
                    encode_status(membership.status())
                ],
            )
            .map(|_| ())
            .map_err(map_write_error)
    }

    fn find_membership(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Option<Membership>, ApplicationError> {
        self.connection
            .query_row(
                "SELECT role, status
                 FROM memberships
                 WHERE workspace_id = ?1 AND principal_id = ?2",
                params![workspace_id.as_str(), principal_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?
            .map(|(role, status)| {
                decode_membership(workspace_id.clone(), principal_id.clone(), &role, &status)
            })
            .transpose()
    }

    fn list_active_memberships(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<Membership>, ApplicationError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT principal_id, role
                 FROM memberships
                 WHERE workspace_id = ?1 AND status = 'active'
                 ORDER BY principal_id",
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let rows = statement
            .query_map([workspace_id.as_str()], |row| {
                decode_membership(
                    workspace_id.clone(),
                    PrincipalId::new(row.get::<_, String>(0)?),
                    &row.get::<_, String>(1)?,
                    "active",
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)
            })
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| ApplicationError::StorageUnavailable)
    }

    fn replace_membership(&mut self, membership: Membership) -> Result<(), ApplicationError> {
        let changed = self
            .connection
            .execute(
                "UPDATE memberships
                 SET role = ?3, status = ?4, updated_at = CURRENT_TIMESTAMP
                 WHERE workspace_id = ?1 AND principal_id = ?2",
                params![
                    membership.workspace_id().as_str(),
                    membership.principal_id().as_str(),
                    encode_role(membership.role()),
                    encode_status(membership.status())
                ],
            )
            .map_err(map_write_error)?;
        if changed == 0 {
            return Err(ApplicationError::NotFound);
        }
        Ok(())
    }
}

impl<C> InvitationRepository for SqliteStore<C> {
    fn insert_invitation(&mut self, invitation: Invitation) -> Result<(), ApplicationError> {
        self.connection
            .execute(
                "INSERT INTO workspace_invitations (
                    workspace_id, id, invited_principal_id, invited_by, role, status,
                    created_at_epoch_seconds, expires_at_epoch_seconds
                ) VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7)",
                params![
                    invitation.workspace_id().as_str(),
                    invitation.id().as_str(),
                    invitation.invited_principal_id().as_str(),
                    invitation.invited_by().as_str(),
                    encode_role(invitation.role()),
                    invitation.created_at_epoch_seconds(),
                    invitation.expires_at_epoch_seconds()
                ],
            )
            .map(|_| ())
            .map_err(map_write_error)
    }

    fn find_invitation(
        &self,
        workspace_id: &WorkspaceId,
        invitation_id: &InvitationId,
    ) -> Result<Option<Invitation>, ApplicationError> {
        self.connection
            .query_row(
                "SELECT invited_principal_id, invited_by, role, status,
                        created_at_epoch_seconds, expires_at_epoch_seconds
                 FROM workspace_invitations
                 WHERE workspace_id = ?1 AND id = ?2",
                params![workspace_id.as_str(), invitation_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, u64>(4)?,
                        row.get::<_, u64>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?
            .map(|(invited, inviter, role, status, created_at, expires_at)| {
                decode_invitation(
                    invitation_id.clone(),
                    workspace_id.clone(),
                    PrincipalId::new(invited),
                    PrincipalId::new(inviter),
                    &role,
                    &status,
                    created_at,
                    expires_at,
                )
            })
            .transpose()
    }

    fn accept_invitation_with_membership(
        &mut self,
        invitation: Invitation,
        membership: Membership,
    ) -> Result<(), ApplicationError> {
        if invitation.status() != InvitationStatus::Accepted
            || invitation.workspace_id() != membership.workspace_id()
            || invitation.invited_principal_id() != membership.principal_id()
            || invitation.role() != membership.role()
        {
            return Err(ApplicationError::Validation(
                "accepted invitation and membership must agree".to_owned(),
            ));
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let changed = transaction
            .execute(
                "UPDATE workspace_invitations
                 SET status = 'accepted', updated_at = CURRENT_TIMESTAMP
                 WHERE workspace_id = ?1 AND id = ?2 AND status = 'pending'
                   AND invited_principal_id = ?3 AND role = ?4
                   AND created_at_epoch_seconds = ?5
                   AND expires_at_epoch_seconds = ?6",
                params![
                    invitation.workspace_id().as_str(),
                    invitation.id().as_str(),
                    invitation.invited_principal_id().as_str(),
                    encode_role(invitation.role()),
                    invitation.created_at_epoch_seconds(),
                    invitation.expires_at_epoch_seconds()
                ],
            )
            .map_err(map_write_error)?;
        if changed != 1 {
            return Err(ApplicationError::VersionConflict);
        }
        transaction
            .execute(
                "INSERT INTO memberships (
                    workspace_id, principal_id, role, status
                ) VALUES (?1, ?2, ?3, 'active')",
                params![
                    membership.workspace_id().as_str(),
                    membership.principal_id().as_str(),
                    encode_role(membership.role())
                ],
            )
            .map_err(map_write_error)?;
        transaction
            .commit()
            .map_err(|_| ApplicationError::StorageUnavailable)
    }

    fn replace_invitation(
        &mut self,
        invitation: Invitation,
        expected_status: InvitationStatus,
    ) -> Result<(), ApplicationError> {
        let changed = self
            .connection
            .execute(
                "UPDATE workspace_invitations
                 SET status = ?6, updated_at = CURRENT_TIMESTAMP
                 WHERE workspace_id = ?1 AND id = ?2
                   AND invited_principal_id = ?3 AND invited_by = ?4
                   AND role = ?5 AND status = ?7
                   AND created_at_epoch_seconds = ?8
                   AND expires_at_epoch_seconds = ?9",
                params![
                    invitation.workspace_id().as_str(),
                    invitation.id().as_str(),
                    invitation.invited_principal_id().as_str(),
                    invitation.invited_by().as_str(),
                    encode_role(invitation.role()),
                    encode_invitation_status(invitation.status()),
                    encode_invitation_status(expected_status),
                    invitation.created_at_epoch_seconds(),
                    invitation.expires_at_epoch_seconds()
                ],
            )
            .map_err(map_write_error)?;
        if changed != 1 {
            return Err(ApplicationError::VersionConflict);
        }
        Ok(())
    }
}

impl<C> ShareProposalRepository for SqliteStore<C> {
    fn insert_share_proposal(
        &mut self,
        proposal: MemoryShareProposal,
    ) -> Result<(), ApplicationError> {
        let (scope_type, scope_value) = encode_memory_scope(proposal.target_scope());
        self.connection
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

    fn find_share_proposal(
        &self,
        source_workspace_id: &WorkspaceId,
        proposal_id: &ShareProposalId,
    ) -> Result<Option<MemoryShareProposal>, ApplicationError> {
        self.connection
            .query_row(
                "SELECT source_memory_id, source_memory_version,
                        source_subject_id, target_workspace_id,
                        target_scope_type, target_scope_value,
                        proposed_by, status
                 FROM memory_share_proposals
                 WHERE source_workspace_id = ?1 AND id = ?2",
                params![source_workspace_id.as_str(), proposal_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?
            .map(
                |(
                    memory_id,
                    memory_version,
                    subject_id,
                    target_workspace,
                    scope_type,
                    scope_value,
                    proposed_by,
                    status,
                )| {
                    decode_share_proposal(
                        proposal_id.clone(),
                        source_workspace_id.clone(),
                        MemoryId::new(memory_id),
                        memory_version,
                        PrincipalId::new(subject_id),
                        WorkspaceId::new(target_workspace),
                        &scope_type,
                        &scope_value,
                        PrincipalId::new(proposed_by),
                        &status,
                    )
                },
            )
            .transpose()
    }

    fn list_share_proposals_for_source(
        &self,
        source_workspace_id: &WorkspaceId,
        source_subject_id: &PrincipalId,
    ) -> Result<Vec<MemoryShareProposal>, ApplicationError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, source_memory_id, source_memory_version,
                        target_workspace_id, target_scope_type,
                        target_scope_value, proposed_by, status
                 FROM memory_share_proposals
                 WHERE source_workspace_id = ?1 AND source_subject_id = ?2
                 ORDER BY created_at, id",
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let rows = statement
            .query_map(
                params![source_workspace_id.as_str(), source_subject_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let mut proposals = Vec::new();
        for row in rows {
            let (
                id,
                memory_id,
                memory_version,
                target_workspace,
                scope_type,
                scope_value,
                proposed_by,
                status,
            ) = row.map_err(|_| ApplicationError::StorageUnavailable)?;
            proposals.push(decode_share_proposal(
                ShareProposalId::new(id),
                source_workspace_id.clone(),
                MemoryId::new(memory_id),
                memory_version,
                source_subject_id.clone(),
                WorkspaceId::new(target_workspace),
                &scope_type,
                &scope_value,
                PrincipalId::new(proposed_by),
                &status,
            )?);
        }
        Ok(proposals)
    }

    fn replace_share_proposal(
        &mut self,
        proposal: MemoryShareProposal,
        expected_status: ShareProposalStatus,
    ) -> Result<(), ApplicationError> {
        let (scope_type, scope_value) = encode_memory_scope(proposal.target_scope());
        let changed = self
            .connection
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
}

impl<C> MemberScopeGrantRepository for SqliteStore<C> {
    fn insert_member_scope_grant(
        &mut self,
        grant: MemberScopeGrant,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        validate_scope_audit(&grant, &audit_event)?;
        let (scope_type, scope_value) = encode_read_scope(grant.scope());
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        transaction
            .execute(
                "INSERT INTO member_scope_grants (
                    workspace_id, principal_id, scope_type, scope_value
                ) VALUES (?1, ?2, ?3, ?4)",
                params![
                    grant.workspace_id().as_str(),
                    grant.principal_id().as_str(),
                    scope_type,
                    scope_value
                ],
            )
            .map_err(map_write_error)?;
        insert_administrative_audit(&transaction, &audit_event)?;
        transaction
            .commit()
            .map_err(|_| ApplicationError::StorageUnavailable)
    }

    fn list_member_scope_grants(
        &self,
        workspace_id: &WorkspaceId,
        principal_id: &PrincipalId,
    ) -> Result<Vec<MemberScopeGrant>, ApplicationError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT scope_type, scope_value
                 FROM member_scope_grants
                 WHERE workspace_id = ?1 AND principal_id = ?2
                 ORDER BY scope_type, scope_value",
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let rows = statement
            .query_map(
                params![workspace_id.as_str(), principal_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let mut grants = Vec::new();
        for row in rows {
            let (scope_type, scope_value) =
                row.map_err(|_| ApplicationError::StorageUnavailable)?;
            grants.push(MemberScopeGrant::new(
                workspace_id.clone(),
                principal_id.clone(),
                decode_read_scope(&scope_type, &scope_value)?,
            ));
        }
        Ok(grants)
    }

    fn delete_member_scope_grant(
        &mut self,
        grant: &MemberScopeGrant,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        validate_scope_audit(grant, &audit_event)?;
        let (scope_type, scope_value) = encode_read_scope(grant.scope());
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let changed = transaction
            .execute(
                "DELETE FROM member_scope_grants
                 WHERE workspace_id = ?1 AND principal_id = ?2
                   AND scope_type = ?3 AND scope_value = ?4",
                params![
                    grant.workspace_id().as_str(),
                    grant.principal_id().as_str(),
                    scope_type,
                    scope_value
                ],
            )
            .map_err(map_write_error)?;
        if changed != 1 {
            return Err(ApplicationError::NotFound);
        }
        insert_administrative_audit(&transaction, &audit_event)?;
        transaction
            .commit()
            .map_err(|_| ApplicationError::StorageUnavailable)
    }
}

impl<C> MemberLifecycleRepository for SqliteStore<C> {
    fn remove_member_and_scope_grants(
        &mut self,
        membership: Membership,
        expected_status: MembershipStatus,
        rotation_id: KeyRotationId,
        requested_by: PrincipalId,
        audit_events: Vec<AdministrativeAuditEvent>,
    ) -> Result<(), ApplicationError> {
        if membership.status() != MembershipStatus::Removed {
            return Err(ApplicationError::Validation(
                "member lifecycle transition must end in removed status".to_owned(),
            ));
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let generation = transaction
            .query_row(
                "SELECT COALESCE(MAX(generation), 0) + 1
                 FROM workspace_key_rotations
                 WHERE workspace_id = ?1",
                [membership.workspace_id().as_str()],
                |row| row.get::<_, u64>(0),
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        WorkspaceKeyRotation::required(
            rotation_id.clone(),
            membership.workspace_id().clone(),
            generation,
            membership.principal_id().clone(),
            requested_by.clone(),
        )
        .map_err(|error| ApplicationError::Validation(error.to_string()))?;
        if audit_events.len() != 2
            || audit_events.iter().any(|event| {
                event.workspace_id() != membership.workspace_id()
                    || event.actor_id() != &requested_by
            })
        {
            return Err(ApplicationError::Validation(
                "member removal audit evidence is invalid".to_owned(),
            ));
        }
        let changed = transaction
            .execute(
                "UPDATE memberships
                 SET status = 'removed', updated_at = CURRENT_TIMESTAMP
                 WHERE workspace_id = ?1 AND principal_id = ?2
                   AND role = ?3 AND status = ?4",
                params![
                    membership.workspace_id().as_str(),
                    membership.principal_id().as_str(),
                    encode_role(membership.role()),
                    encode_status(expected_status)
                ],
            )
            .map_err(map_write_error)?;
        if changed != 1 {
            return Err(ApplicationError::VersionConflict);
        }
        transaction
            .execute(
                "DELETE FROM member_scope_grants
                 WHERE workspace_id = ?1 AND principal_id = ?2",
                params![
                    membership.workspace_id().as_str(),
                    membership.principal_id().as_str()
                ],
            )
            .map_err(map_write_error)?;
        for audit_event in &audit_events {
            insert_administrative_audit(&transaction, audit_event)?;
        }
        transaction
            .execute(
                "INSERT INTO workspace_key_rotations (
                    workspace_id, id, generation, removed_principal_id,
                    requested_by, status
                 ) VALUES (?1, ?2, ?3, ?4, ?5, 'required')",
                params![
                    membership.workspace_id().as_str(),
                    rotation_id.as_str(),
                    generation,
                    membership.principal_id().as_str(),
                    requested_by.as_str()
                ],
            )
            .map_err(map_write_error)?;
        transaction
            .commit()
            .map_err(|_| ApplicationError::StorageUnavailable)
    }
}

impl<C> KeyRotationRepository for SqliteStore<C> {
    fn latest_key_rotation(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Option<WorkspaceKeyRotation>, ApplicationError> {
        self.connection
            .query_row(
                "SELECT id, generation, removed_principal_id, requested_by,
                        status, completed_key_id, completed_by
                 FROM workspace_key_rotations
                 WHERE workspace_id = ?1
                 ORDER BY generation DESC
                 LIMIT 1",
                [workspace_id.as_str()],
                |row| {
                    let status: String = row.get(4)?;
                    let status = match status.as_str() {
                        "required" => KeyRotationStatus::Required,
                        "completed" => KeyRotationStatus::Completed,
                        _ => return Err(rusqlite::Error::InvalidQuery),
                    };
                    WorkspaceKeyRotation::restore(
                        KeyRotationId::new(row.get::<_, String>(0)?),
                        workspace_id.clone(),
                        row.get(1)?,
                        PrincipalId::new(row.get::<_, String>(2)?),
                        PrincipalId::new(row.get::<_, String>(3)?),
                        status,
                        row.get(5)?,
                        row.get::<_, Option<String>>(6)?.map(PrincipalId::new),
                    )
                    .map_err(|_| rusqlite::Error::InvalidQuery)
                },
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)
    }

    fn find_key_rotation_receipt(
        &self,
        workspace_id: &WorkspaceId,
        rotation_id: &KeyRotationId,
    ) -> Result<Option<KeyRotationReceipt>, ApplicationError> {
        let header = self
            .connection
            .query_row(
                "SELECT provider_id, request_id, generation, key_id
                 FROM workspace_key_rotation_receipts
                 WHERE workspace_id = ?1 AND rotation_id = ?2",
                params![workspace_id.as_str(), rotation_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let Some((provider_id, request_id, generation, key_id)) = header else {
            return Ok(None);
        };
        let mut statement = self
            .connection
            .prepare(
                "SELECT principal_id
                 FROM workspace_key_rotation_recipients
                 WHERE workspace_id = ?1 AND rotation_id = ?2
                 ORDER BY principal_id",
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let recipients = statement
            .query_map(
                params![workspace_id.as_str(), rotation_id.as_str()],
                |row| row.get::<_, String>(0).map(PrincipalId::new),
            )
            .map_err(|_| ApplicationError::StorageUnavailable)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        KeyRotationReceipt::new(
            ProviderId::new(provider_id),
            request_id,
            workspace_id.clone(),
            generation,
            key_id,
            recipients,
        )
        .map(Some)
        .map_err(|_| ApplicationError::StorageUnavailable)
    }

    fn complete_key_rotation(
        &mut self,
        rotation: WorkspaceKeyRotation,
        receipt: KeyRotationReceipt,
        expected_generation: u64,
        audit_event: AdministrativeAuditEvent,
    ) -> Result<(), ApplicationError> {
        if rotation.status() != KeyRotationStatus::Completed
            || rotation.generation() != expected_generation
            || receipt.workspace_id() != rotation.workspace_id()
            || receipt.generation() != expected_generation
            || receipt.key_id() != rotation.completed_key_id().unwrap_or_default()
            || audit_event.workspace_id() != rotation.workspace_id()
            || audit_event.actor_id() != rotation.completed_by().unwrap_or(audit_event.actor_id())
            || audit_event.action() != AdministrativeAction::KeyRotationCompleted
            || audit_event.target_id() != rotation.id().as_str()
        {
            return Err(ApplicationError::Validation(
                "completed rotation must match the expected generation".to_owned(),
            ));
        }
        let completed_key_id = rotation.completed_key_id().ok_or_else(|| {
            ApplicationError::Validation(
                "completed rotation must contain an opaque key identifier".to_owned(),
            )
        })?;
        let completed_by = rotation.completed_by().ok_or_else(|| {
            ApplicationError::Validation(
                "completed rotation must identify the completing principal".to_owned(),
            )
        })?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let changed = transaction
            .execute(
                "UPDATE workspace_key_rotations
                 SET status = 'completed', completed_key_id = ?1,
                     completed_by = ?2, completed_at = CURRENT_TIMESTAMP
                 WHERE workspace_id = ?3 AND id = ?4
                   AND generation = ?5 AND status = 'required'",
                params![
                    completed_key_id,
                    completed_by.as_str(),
                    rotation.workspace_id().as_str(),
                    rotation.id().as_str(),
                    expected_generation
                ],
            )
            .map_err(map_write_error)?;
        if changed != 1 {
            return Err(ApplicationError::VersionConflict);
        }
        transaction
            .execute(
                "INSERT INTO workspace_key_rotation_receipts (
                    workspace_id, rotation_id, provider_id, request_id,
                    generation, key_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    receipt.workspace_id().as_str(),
                    rotation.id().as_str(),
                    receipt.provider_id().as_str(),
                    receipt.request_id(),
                    receipt.generation(),
                    receipt.key_id()
                ],
            )
            .map_err(map_write_error)?;
        for recipient in receipt.recipient_ids() {
            transaction
                .execute(
                    "INSERT INTO workspace_key_rotation_recipients (
                        workspace_id, rotation_id, principal_id
                     ) VALUES (?1, ?2, ?3)",
                    params![
                        receipt.workspace_id().as_str(),
                        rotation.id().as_str(),
                        recipient.as_str()
                    ],
                )
                .map_err(map_write_error)?;
        }
        insert_administrative_audit(&transaction, &audit_event)?;
        transaction
            .commit()
            .map_err(|_| ApplicationError::StorageUnavailable)
    }
}

fn insert_administrative_audit(
    connection: &Connection,
    event: &AdministrativeAuditEvent,
) -> Result<(), ApplicationError> {
    connection
        .execute(
            "INSERT INTO administrative_audit_events (
                workspace_id, id, actor_id, action, target_kind, target_id,
                request_id, occurred_at_epoch_seconds
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                event.workspace_id().as_str(),
                event.id().as_str(),
                event.actor_id().as_str(),
                event.action().label(),
                event.target_kind().label(),
                event.target_id(),
                event.request_id(),
                event.occurred_at_epoch_seconds()
            ],
        )
        .map_err(map_write_error)?;
    Ok(())
}

fn validate_scope_audit(
    grant: &MemberScopeGrant,
    event: &AdministrativeAuditEvent,
) -> Result<(), ApplicationError> {
    let (scope_type, scope_value) = encode_read_scope(grant.scope());
    let expected_target = if scope_value.is_empty() {
        format!("{}:{scope_type}", grant.principal_id().as_str())
    } else {
        format!(
            "{}:{scope_type}:{scope_value}",
            grant.principal_id().as_str()
        )
    };
    if event.workspace_id() != grant.workspace_id()
        || event.action() != AdministrativeAction::ScopeGrantChanged
        || event.target_kind() != AdministrativeTargetKind::ScopeGrant
        || event.target_id() != expected_target
    {
        return Err(ApplicationError::Validation(
            "scope grant audit evidence is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_retention_audit(
    policy: &WorkspaceRetentionPolicy,
    event: &AdministrativeAuditEvent,
) -> Result<(), ApplicationError> {
    if event.workspace_id() != policy.workspace_id()
        || event.action() != AdministrativeAction::RetentionPolicyChanged
        || event.target_kind() != AdministrativeTargetKind::RetentionPolicy
        || event.target_id() != policy.workspace_id().as_str()
    {
        return Err(ApplicationError::Validation(
            "retention policy audit evidence is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_legal_hold_audit(
    hold: &WorkspaceLegalHold,
    event: &AdministrativeAuditEvent,
    action: AdministrativeAction,
) -> Result<(), ApplicationError> {
    if event.workspace_id() != hold.workspace_id()
        || event.action() != action
        || event.target_kind() != AdministrativeTargetKind::LegalHold
        || event.target_id() != hold.id().as_str()
    {
        return Err(ApplicationError::Validation(
            "legal hold audit evidence is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_personal_bootstrap(
    principal: &Principal,
    workspace: &Workspace,
    membership: &Membership,
) -> Result<(), ApplicationError> {
    if workspace.kind() != WorkspaceKind::Personal
        || membership.workspace_id() != workspace.id()
        || membership.principal_id() != principal.id()
        || membership.role() != WorkspaceRole::Owner
        || !membership.is_active()
    {
        return Err(ApplicationError::Validation(
            "personal workspace bootstrap records must agree".to_owned(),
        ));
    }
    Ok(())
}

fn validate_shared_bootstrap(
    workspace: &Workspace,
    membership: &Membership,
) -> Result<(), ApplicationError> {
    if workspace.kind() != WorkspaceKind::Shared
        || membership.workspace_id() != workspace.id()
        || membership.role() != WorkspaceRole::Owner
        || !membership.is_active()
    {
        return Err(ApplicationError::Validation(
            "shared workspace bootstrap records must agree".to_owned(),
        ));
    }
    Ok(())
}

fn decode_invitation(
    invitation_id: InvitationId,
    workspace_id: WorkspaceId,
    invited_principal_id: PrincipalId,
    invited_by: PrincipalId,
    role: &str,
    status: &str,
    created_at_epoch_seconds: u64,
    expires_at_epoch_seconds: u64,
) -> Result<Invitation, ApplicationError> {
    let role = decode_role(role)?;
    let invitation = Invitation::new(
        invitation_id,
        workspace_id,
        invited_principal_id,
        invited_by,
        role,
        created_at_epoch_seconds,
        expires_at_epoch_seconds,
    )
    .map_err(|_| ApplicationError::StorageUnavailable)?;
    match status {
        "pending" => Ok(invitation),
        "accepted" => invitation
            .accept_at(created_at_epoch_seconds)
            .map_err(|_| ApplicationError::StorageUnavailable),
        "revoked" => invitation
            .revoke()
            .map_err(|_| ApplicationError::StorageUnavailable),
        _ => Err(ApplicationError::StorageUnavailable),
    }
}

fn decode_workspace(id: String, kind: &str) -> Result<Workspace, ApplicationError> {
    match kind {
        "personal" => Ok(Workspace::personal(WorkspaceId::new(id))),
        "shared" => Ok(Workspace::shared(WorkspaceId::new(id))),
        _ => Err(ApplicationError::StorageUnavailable),
    }
}

fn decode_membership(
    workspace_id: WorkspaceId,
    principal_id: PrincipalId,
    role: &str,
    status: &str,
) -> Result<Membership, ApplicationError> {
    let role = decode_role(role)?;
    let membership = Membership::new(workspace_id, principal_id, role);
    match status {
        "active" => Ok(membership),
        "suspended" => Ok(membership.suspend()),
        "removed" => Ok(membership.remove()),
        _ => Err(ApplicationError::StorageUnavailable),
    }
}

fn decode_role(role: &str) -> Result<WorkspaceRole, ApplicationError> {
    Ok(match role {
        "owner" => WorkspaceRole::Owner,
        "admin" => WorkspaceRole::Admin,
        "member" => WorkspaceRole::Member,
        "viewer" => WorkspaceRole::Viewer,
        _ => return Err(ApplicationError::StorageUnavailable),
    })
}

fn encode_read_scope(scope: &ReadScope) -> (&'static str, &str) {
    match scope {
        ReadScope::Global => ("global", ""),
        ReadScope::Domain { name } => ("domain", name),
        ReadScope::Entity { id } => ("entity", id.as_str()),
        ReadScope::Activity { id } => ("activity", id.as_str()),
    }
}

fn encode_memory_scope(scope: &MemoryScope) -> (&'static str, &str) {
    match scope {
        MemoryScope::Global => ("global", ""),
        MemoryScope::Domain { name } => ("domain", name),
        MemoryScope::Entity { id } => ("entity", id.as_str()),
        MemoryScope::Activity { id } => ("activity", id.as_str()),
    }
}

fn decode_memory_scope(
    scope_type: &str,
    scope_value: &str,
) -> Result<MemoryScope, ApplicationError> {
    match scope_type {
        "global" if scope_value.is_empty() => Ok(MemoryScope::Global),
        "domain" if !scope_value.is_empty() => Ok(MemoryScope::Domain {
            name: scope_value.to_owned(),
        }),
        "entity" if !scope_value.is_empty() => Ok(MemoryScope::Entity {
            id: EntityId::new(scope_value),
        }),
        "activity" if !scope_value.is_empty() => Ok(MemoryScope::Activity {
            id: ActivityId::new(scope_value),
        }),
        _ => Err(ApplicationError::StorageUnavailable),
    }
}

fn decode_share_proposal(
    id: ShareProposalId,
    source_workspace_id: WorkspaceId,
    source_memory_id: MemoryId,
    source_memory_version: u64,
    source_subject_id: PrincipalId,
    target_workspace_id: WorkspaceId,
    target_scope_type: &str,
    target_scope_value: &str,
    proposed_by: PrincipalId,
    status: &str,
) -> Result<MemoryShareProposal, ApplicationError> {
    let status = match status {
        "pending" => ShareProposalStatus::Pending,
        "approved" => ShareProposalStatus::Approved,
        "rejected" => ShareProposalStatus::Rejected,
        "revoked" => ShareProposalStatus::Revoked,
        _ => return Err(ApplicationError::StorageUnavailable),
    };
    MemoryShareProposal::restore(
        id,
        source_workspace_id,
        source_memory_id,
        source_memory_version,
        source_subject_id,
        target_workspace_id,
        decode_memory_scope(target_scope_type, target_scope_value)?,
        proposed_by,
        status,
    )
    .map_err(|_| ApplicationError::StorageUnavailable)
}

fn decode_read_scope(scope_type: &str, scope_value: &str) -> Result<ReadScope, ApplicationError> {
    match scope_type {
        "global" if scope_value.is_empty() => Ok(ReadScope::Global),
        "domain" if !scope_value.is_empty() => Ok(ReadScope::Domain {
            name: scope_value.to_owned(),
        }),
        "entity" if !scope_value.is_empty() => Ok(ReadScope::Entity {
            id: EntityId::new(scope_value),
        }),
        "activity" if !scope_value.is_empty() => Ok(ReadScope::Activity {
            id: ActivityId::new(scope_value),
        }),
        _ => Err(ApplicationError::StorageUnavailable),
    }
}

const fn encode_role(role: WorkspaceRole) -> &'static str {
    match role {
        WorkspaceRole::Owner => "owner",
        WorkspaceRole::Admin => "admin",
        WorkspaceRole::Member => "member",
        WorkspaceRole::Viewer => "viewer",
    }
}

const fn encode_status(status: MembershipStatus) -> &'static str {
    match status {
        MembershipStatus::Active => "active",
        MembershipStatus::Suspended => "suspended",
        MembershipStatus::Removed => "removed",
    }
}

const fn encode_invitation_status(status: InvitationStatus) -> &'static str {
    match status {
        InvitationStatus::Pending => "pending",
        InvitationStatus::Accepted => "accepted",
        InvitationStatus::Revoked => "revoked",
    }
}

const fn encode_share_proposal_status(status: ShareProposalStatus) -> &'static str {
    match status {
        ShareProposalStatus::Pending => "pending",
        ShareProposalStatus::Approved => "approved",
        ShareProposalStatus::Rejected => "rejected",
        ShareProposalStatus::Revoked => "revoked",
    }
}

fn map_write_error(error: rusqlite::Error) -> ApplicationError {
    match error {
        rusqlite::Error::SqliteFailure(_, Some(message))
            if message == "workspace event sequence conflict" =>
        {
            ApplicationError::SequenceConflict
        }
        rusqlite::Error::SqliteFailure(_, Some(message))
            if message == "share proposal source conflict" =>
        {
            ApplicationError::VersionConflict
        }
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == ErrorCode::ConstraintViolation =>
        {
            match failure.extended_code {
                1_555 | 2_067 => ApplicationError::AlreadyExists,
                _ => ApplicationError::Validation(
                    "database constraint rejected the write".to_owned(),
                ),
            }
        }
        _ => ApplicationError::StorageUnavailable,
    }
}

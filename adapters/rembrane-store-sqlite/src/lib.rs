//! Persistent tenant-isolated SQLite adapter.

mod booking_research;
mod canonical;
mod checkpoint;
mod disclosure;
mod projection;
mod share;
mod trip;

use std::path::Path;

use rembrane_application::{
    ApplicationError, InvitationRepository, MemberLifecycleRepository, MemberScopeGrantRepository,
    MembershipRepository, MemoryRepository, ShareProposalRepository, WorkspaceRepository,
};
use rembrane_codec::decode_memory;
use rembrane_crypto::{EncryptedPayload, EncryptionContext, PayloadPurpose, RecordCipher};
use rembrane_domain::{
    ActivityId, EntityId, Invitation, InvitationId, InvitationStatus, MemberScopeGrant, Membership,
    MembershipStatus, MemoryId, MemoryRecord, MemoryScope, MemoryShareProposal, Principal,
    PrincipalId, ReadScope, ShareProposalId, ShareProposalStatus, Workspace, WorkspaceId,
    WorkspaceKind, WorkspaceRole,
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
const CURRENT_SCHEMA_VERSION: u32 = 10;
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

pub(super) fn decrypt_memory_record(
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

pub(super) struct EncryptedMemoryRow {
    version: u64,
    ciphertext: Vec<u8>,
    key_id: String,
    algorithm: String,
    nonce: Vec<u8>,
}

pub(super) fn encrypted_memory_row(
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
                    workspace_id, id, invited_principal_id, invited_by, role, status
                ) VALUES (?1, ?2, ?3, ?4, ?5, 'pending')",
                params![
                    invitation.workspace_id().as_str(),
                    invitation.id().as_str(),
                    invitation.invited_principal_id().as_str(),
                    invitation.invited_by().as_str(),
                    encode_role(invitation.role())
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
                "SELECT invited_principal_id, invited_by, role, status
                 FROM workspace_invitations
                 WHERE workspace_id = ?1 AND id = ?2",
                params![workspace_id.as_str(), invitation_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?
            .map(|(invited, inviter, role, status)| {
                decode_invitation(
                    invitation_id.clone(),
                    workspace_id.clone(),
                    PrincipalId::new(invited),
                    PrincipalId::new(inviter),
                    &role,
                    &status,
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
                   AND invited_principal_id = ?3 AND role = ?4",
                params![
                    invitation.workspace_id().as_str(),
                    invitation.id().as_str(),
                    invitation.invited_principal_id().as_str(),
                    encode_role(invitation.role())
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
                   AND role = ?5 AND status = ?7",
                params![
                    invitation.workspace_id().as_str(),
                    invitation.id().as_str(),
                    invitation.invited_principal_id().as_str(),
                    invitation.invited_by().as_str(),
                    encode_role(invitation.role()),
                    encode_invitation_status(invitation.status()),
                    encode_invitation_status(expected_status)
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
    ) -> Result<(), ApplicationError> {
        let (scope_type, scope_value) = encode_read_scope(grant.scope());
        self.connection
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
            .map(|_| ())
            .map_err(map_write_error)
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
    ) -> Result<(), ApplicationError> {
        let (scope_type, scope_value) = encode_read_scope(grant.scope());
        let changed = self
            .connection
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
        Ok(())
    }
}

impl<C> MemberLifecycleRepository for SqliteStore<C> {
    fn remove_member_and_scope_grants(
        &mut self,
        membership: Membership,
        expected_status: MembershipStatus,
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
        transaction
            .commit()
            .map_err(|_| ApplicationError::StorageUnavailable)
    }
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
) -> Result<Invitation, ApplicationError> {
    let role = decode_role(role)?;
    let invitation = Invitation::new(
        invitation_id,
        workspace_id,
        invited_principal_id,
        invited_by,
        role,
    )
    .map_err(|_| ApplicationError::StorageUnavailable)?;
    match status {
        "pending" => Ok(invitation),
        "accepted" => invitation
            .accept()
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

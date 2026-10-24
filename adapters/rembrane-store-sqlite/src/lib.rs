//! Persistent tenant-isolated SQLite adapter.

mod canonical;
mod checkpoint;
mod disclosure;
mod projection;

use std::path::Path;

use rembrane_application::{
    ApplicationError, MembershipRepository, MemoryRepository, WorkspaceRepository,
};
use rembrane_codec::decode_memory;
use rembrane_crypto::{EncryptedPayload, EncryptionContext, PayloadPurpose, RecordCipher};
use rembrane_domain::{
    Membership, MembershipStatus, MemoryId, MemoryRecord, Principal, PrincipalId, Workspace,
    WorkspaceId, WorkspaceKind, WorkspaceRole,
};
use rusqlite::{Connection, ErrorCode, OptionalExtension, params};

const CANONICAL_SCHEMA: &str = include_str!("../../../migrations/sqlite/0001_canonical_schema.sql");
const CHECKPOINT_DISCLOSURE_MIGRATION: &str =
    include_str!("../../../migrations/sqlite/0002_checkpoint_disclosures.sql");
const CURRENT_SCHEMA_VERSION: u32 = 2;
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
    fn upgrades_version_one_with_checkpoint_disclosures() {
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

        row.map(|encrypted| self.decrypt_memory(workspace_id, memory_id, encrypted))
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
            let memory = self.decrypt_memory(workspace_id, &memory_id, encrypted)?;
            if memory.subject_id() != subject_id {
                return Err(ApplicationError::StorageUnavailable);
            }
            memories.push(memory);
        }
        Ok(memories)
    }
}

impl<C: RecordCipher> SqliteStore<C> {
    fn decrypt_memory(
        &self,
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
        let plaintext = self
            .cipher
            .open(&context, &payload)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        let memory = decode_memory(&plaintext).map_err(|_| ApplicationError::StorageUnavailable)?;
        if memory.workspace_id() != workspace_id || memory.id() != memory_id {
            return Err(ApplicationError::StorageUnavailable);
        }
        Ok(memory)
    }
}

struct EncryptedMemoryRow {
    version: u64,
    ciphertext: Vec<u8>,
    key_id: String,
    algorithm: String,
    nonce: Vec<u8>,
}

fn encrypted_memory_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EncryptedMemoryRow> {
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
    let role = match role {
        "owner" => WorkspaceRole::Owner,
        "admin" => WorkspaceRole::Admin,
        "member" => WorkspaceRole::Member,
        "viewer" => WorkspaceRole::Viewer,
        _ => return Err(ApplicationError::StorageUnavailable),
    };
    let membership = Membership::new(workspace_id, principal_id, role);
    match status {
        "active" => Ok(membership),
        "suspended" => Ok(membership.suspend()),
        "removed" => Ok(membership.remove()),
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

fn map_write_error(error: rusqlite::Error) -> ApplicationError {
    match error {
        rusqlite::Error::SqliteFailure(_, Some(message))
            if message == "workspace event sequence conflict" =>
        {
            ApplicationError::SequenceConflict
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

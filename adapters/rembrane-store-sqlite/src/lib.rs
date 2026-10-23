//! Persistent tenant-isolated SQLite adapter.

use std::path::Path;

use rembrane_application::{
    ApplicationError, MembershipRepository, WorkspaceRepository,
};
use rembrane_domain::{
    Membership, MembershipStatus, Principal, PrincipalId, Workspace,
    WorkspaceId, WorkspaceKind, WorkspaceRole,
};
use rusqlite::{Connection, ErrorCode, OptionalExtension, params};

const CANONICAL_SCHEMA: &str =
    include_str!("../../../migrations/sqlite/0001_canonical_schema.sql");

pub struct SqliteStore {
    connection: Connection,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ApplicationError> {
        let connection = Connection::open(path)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        Self::initialize(connection)
    }

    pub fn open_in_memory() -> Result<Self, ApplicationError> {
        let connection = Connection::open_in_memory()
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        Self::initialize(connection)
    }

    fn initialize(connection: Connection) -> Result<Self, ApplicationError> {
        connection
            .execute_batch(CANONICAL_SCHEMA)
            .map_err(|_| ApplicationError::StorageUnavailable)?;
        Ok(Self { connection })
    }
}

impl WorkspaceRepository for SqliteStore {
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
                |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                },
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?
            .map(|(id, kind)| decode_workspace(id, &kind))
            .transpose()
    }
}

impl MembershipRepository for SqliteStore {
    fn insert_membership(
        &mut self,
        membership: Membership,
    ) -> Result<(), ApplicationError> {
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
                |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                },
            )
            .optional()
            .map_err(|_| ApplicationError::StorageUnavailable)?
            .map(|(role, status)| {
                decode_membership(
                    workspace_id.clone(),
                    principal_id.clone(),
                    &role,
                    &status,
                )
            })
            .transpose()
    }

    fn replace_membership(
        &mut self,
        membership: Membership,
    ) -> Result<(), ApplicationError> {
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

fn decode_workspace(
    id: String,
    kind: &str,
) -> Result<Workspace, ApplicationError> {
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

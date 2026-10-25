//! `PostgreSQL` transaction boundary with fail-closed tenant verification.
//!
//! A concrete database driver must create a transaction and transfer ownership
//! of it to [`TenantTransaction::verify`] before executing repository SQL.
//! This crate intentionally contains no connection driver yet.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use rembrane_application::{
    ApplicationError, InvitationRepository, MAXIMUM_INVITATION_LIST_ITEMS, MembershipRepository,
};
use rembrane_domain::{
    AdministrativeAction, AdministrativeAuditEvent, AdministrativeTargetKind, Invitation,
    InvitationId, InvitationStatus, Membership, Principal, PrincipalId, Workspace, WorkspaceId,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresParameter<'value> {
    Text(&'value str),
    I64(i64),
    Bytes(&'value [u8]),
}

pub trait PostgresRow {
    type Error;

    fn text(&self, column: &str) -> Result<String, Self::Error>;

    fn u64(&self, column: &str) -> Result<u64, Self::Error>;
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

impl<Pool> PostgresTenantStore<'_, Pool> {
    fn require_workspace(&self, workspace_id: &WorkspaceId) -> Result<(), ApplicationError> {
        if workspace_id == &self.workspace_id {
            Ok(())
        } else {
            Err(ApplicationError::AccessDenied)
        }
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
        other => map_application_error(other),
    }
}

fn postgres_epoch<DriverError>(epoch_seconds: u64) -> Result<i64, PostgresStoreError<DriverError>> {
    i64::try_from(epoch_seconds).map_err(|_| PostgresStoreError::InvalidInput)
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
    match membership.status() {
        rembrane_domain::MembershipStatus::Active => "active",
        rembrane_domain::MembershipStatus::Suspended => "suspended",
        rembrane_domain::MembershipStatus::Removed => "removed",
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

    use rembrane_application::{ApplicationError, InvitationRepository, MembershipRepository};
    use rembrane_domain::{
        AdministrativeAction, AdministrativeAuditEvent, AdministrativeAuditEventId,
        AdministrativeTargetKind, Invitation, InvitationId, InvitationStatus, PrincipalId,
        WorkspaceId, WorkspaceRole,
    };

    use super::{
        ACCEPT_INVITATION_SQL, ClassifiedPostgresError, EXPIRE_PENDING_INVITATION_SQL,
        FIND_INVITATION_SQL, FIND_MEMBERSHIP_SQL, FIND_PRINCIPAL_SQL, FIND_WORKSPACE_SQL,
        INSERT_ADMINISTRATIVE_AUDIT_SQL, INSERT_INVITATION_SQL, INSERT_MEMBERSHIP_SQL,
        LIST_ACTIVE_MEMBERSHIPS_SQL, LIST_INVITATIONS_BY_STATUS_SQL, MAX_ACTIVE_MEMBERSHIPS,
        PostgresFailureKind, PostgresParameter, PostgresPool, PostgresRow, PostgresStore,
        PostgresStoreError, PostgresTransaction, READ_TENANT_SQL, REPLACE_INVITATION_SQL,
        REPLACE_MEMBERSHIP_SQL, SET_TENANT_SQL, TenantTransaction, TenantTransactionError,
        map_application_error,
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
                PostgresParameter::I64(value) => format!("i64:{value}"),
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
    }
}

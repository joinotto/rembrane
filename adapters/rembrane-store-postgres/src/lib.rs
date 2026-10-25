//! `PostgreSQL` transaction boundary with fail-closed tenant verification.
//!
//! A concrete database driver must create a transaction and transfer ownership
//! of it to [`TenantTransaction::verify`] before executing repository SQL.
//! This crate intentionally contains no connection driver yet.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use rembrane_domain::{Membership, PrincipalId, Workspace, WorkspaceId, WorkspaceRole};

pub const SET_TENANT_SQL: &str = "SELECT set_config('rembrane.workspace_id', $1, true);";
pub const READ_TENANT_SQL: &str = "SELECT rembrane.current_workspace_id();";
pub const FIND_WORKSPACE_SQL: &str =
    "SELECT id, kind FROM workspaces WHERE id = $1 ORDER BY id LIMIT 2";
pub const FIND_MEMBERSHIP_SQL: &str = "SELECT workspace_id, principal_id, role, status \
    FROM memberships WHERE workspace_id = $1 AND principal_id = $2 \
    ORDER BY workspace_id, principal_id LIMIT 2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresParameter<'value> {
    Text(&'value str),
    I64(i64),
    Bytes(&'value [u8]),
}

pub trait PostgresRow {
    type Error;

    fn text(&self, column: &str) -> Result<String, Self::Error>;
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

impl<Pool: PostgresPool> PostgresStore<Pool> {
    #[must_use]
    pub const fn new(pool: Pool) -> Self {
        Self { pool }
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

    use rembrane_domain::WorkspaceId;

    use super::{
        FIND_MEMBERSHIP_SQL, FIND_WORKSPACE_SQL, PostgresParameter, PostgresPool, PostgresRow,
        PostgresStore, PostgresStoreError, PostgresTransaction, READ_TENANT_SQL, SET_TENANT_SQL,
        TenantTransaction, TenantTransactionError,
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

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct FakeRow {
        columns: BTreeMap<&'static str, String>,
    }

    impl FakeRow {
        fn workspace(id: &str, kind: &str) -> Self {
            Self {
                columns: BTreeMap::from([("id", id.to_owned()), ("kind", kind.to_owned())]),
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
            }
        }
    }

    impl PostgresRow for FakeRow {
        type Error = &'static str;

        fn text(&self, column: &str) -> Result<String, Self::Error> {
            self.columns.get(column).cloned().ok_or("unknown column")
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
}

# PostgreSQL tenant boundary

`0001_tenant_rls.sql` is applied after the canonical PostgreSQL tables exist.
The application must begin a transaction and run:

```sql
SET LOCAL rembrane.workspace_id = 'workspace_opaque_id';
```

before any tenant query. Missing or empty identity matches no row. The runtime
database role must be non-superuser, must not own tenant tables, and must not
have `BYPASSRLS`; migration ownership belongs to a separate role.

Every ordinary table containing `workspace_id` receives forced read/write RLS.
`workspaces` is isolated by `id`. Private-to-shared proposals are isolated by
their source workspace; cross-workspace approval must use a separately audited
security-definer operation that verifies both memberships instead of weakening
the general table policy.

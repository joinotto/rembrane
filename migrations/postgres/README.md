# PostgreSQL tenant boundary

`0001_canonical_schema.sql` creates the encrypted canonical memory tables with
the same domain constraints, append-only event behavior, and indexes as the
SQLite alpha schema. `0002_tenant_rls.sql` must be applied immediately after
it, before granting access to the runtime role.
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
the general table policy. Principal reads are limited to members visible
through the current workspace's membership rows, so opaque identity records
cannot be enumerated across tenants.

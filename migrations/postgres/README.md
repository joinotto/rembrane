# PostgreSQL tenant boundary

`0001_canonical_schema.sql` creates the encrypted canonical memory tables with
the same domain constraints, append-only event behavior, and indexes as the
SQLite alpha schema. `0002_workspace_administration.sql` adds shared-workspace
invitations and scope grants, key-rotation state, append-only administrative
audit, retention policies, and legal holds.

Apply numbered schema migrations in ascending order, then apply
`9999_tenant_rls.sql` after every schema migration and before granting access
to the runtime role. Keeping RLS last ensures every newly introduced
`workspace_id` table is included by the deny-by-default policy generator.
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

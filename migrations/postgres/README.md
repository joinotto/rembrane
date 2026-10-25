# PostgreSQL tenant boundary

`0001_canonical_schema.sql` creates the encrypted canonical memory tables with
the same domain constraints, append-only event behavior, and indexes as the
SQLite alpha schema. `0002_workspace_administration.sql` adds shared-workspace
invitations and scope grants, key-rotation state, append-only administrative
audit, retention policies, and legal holds. `0003_travel_continuity.sql` adds
encrypted trip and booking research records plus checkpoint and travel
disclosure receipts, including explicit sensitive-data disclosure flags.
`0004_knowledge_graph.sql` adds encrypted temporal nodes and edges plus a
provider-specific projection outbox with partial unique indexes for exact
node and edge idempotency.
`0005_channel_continuity.sql` adds authenticated replay receipts, active-member
sender bindings, and an encrypted leased inbox with monotonic retry,
quarantine, requeue, and delivery transitions.

Apply numbered schema migrations in ascending order, then apply
`9999_tenant_rls.sql` after every schema migration and before granting access
to the runtime role. Keeping RLS last ensures every newly introduced
`workspace_id` table is included by the deny-by-default policy generator.
The application must begin a transaction and execute this as a prepared,
parameter-bound statement:

```sql
SELECT set_config('rembrane.workspace_id', $1, true);
```

The third argument must remain `true`, making the setting local to the current
transaction so a pooled connection cannot leak one workspace into the next.
The adapter must read back `rembrane.current_workspace_id()` and require an
exact match before issuing any tenant query. It must never interpolate a
workspace identifier into `SET`, SQL text, an identifier, or a connection
startup option. Missing, empty, mismatched, or transaction-external identity
matches no row. The runtime database role must be non-superuser, must not own
tenant tables, and must not have `BYPASSRLS`; migration ownership belongs to a
separate role.

The Rust adapter configuration carries the database URL only as a
`SecretReference`. Operators may point it at an environment variable,
protected file, or deployment-provided external secret resolver. The resolved
URL, including any password, must remain short-lived and must never be
serialized, logged, returned by diagnostics, or stored in a provider profile.
The typed connection profile deliberately has no debug representation, so its
secret locator cannot be included accidentally by derived structured logging.
Remote deployments require full TLS verification; plaintext transport is an
explicit trusted-boundary-only mode. Connection pools are bounded to prevent a
tenant or configuration error from exhausting the database.

Every ordinary table containing `workspace_id` receives forced read/write RLS.
`workspaces` is isolated by `id`. Private-to-shared proposals are isolated by
their source workspace; cross-workspace approval must use a separately audited
security-definer operation that verifies both memberships instead of weakening
the general table policy. Principal reads are limited to members visible
through the current workspace's membership rows, so opaque identity records
cannot be enumerated across tenants.

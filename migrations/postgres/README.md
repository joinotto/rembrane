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
`0006_graph_disclosures.sql` adds append-only graph-context disclosure
receipts and exact disclosed edge revisions, constrained to canonical
workspace-scoped graph identities.

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

The Rust tenant transaction now executes the shared
`adapters/rembrane-store-postgres/src/runtime-role.sql` guard before setting
tenant state and before each repository read/write. It accepts only the
`restricted-runtime` marker. Missing, unexpected, or failed proof rolls back
the transaction, and authority drift poisons the transaction for further use.
The guard checks both effective and session roles, rejects membership in
superuser/BYPASSRLS or canonical table-owner roles, requires enabled/forced
RLS and `row_security=on`, and rejects search-path shadowing of protected
relations. Membership rejection is deliberately conservative even where a
role grant cannot currently be inherited or assumed.
The guard also rejects `TRUNCATE` and table/column `REFERENCES` grants on
protected relations because those privileges are not constrained by RLS.
It checks every role reachable through effective or session membership,
including non-inherited membership and effective `PUBLIC` grants. Do not
grant these privileges to request-serving accounts; use a separate migration
identity. Ordinary runtime grants should be limited to the necessary
`SELECT`, `INSERT`, `UPDATE`, and `DELETE` privileges.

The current schema is `public`; protected relations are its tables with
`workspace_id` plus `principals`, `workspaces`, and `memory_share_proposals`.
Protected views, materialized views, and foreign tables are rejected rather
than treated as forced-RLS tables. Use a dedicated database/role for Rembrane.
This guard does not verify the
contents of every policy or protect against a malicious database administrator.
It complements migrations and live isolation testing; it is not a substitute
for either. The live RLS suite exercises allowed roles, owner/BYPASSRLS denial,
unforced policies, temporary-table shadowing, and direct, column, `PUBLIC`,
and non-inherited member table-wide privileges using rollback-only fixtures.
The expanded privilege fixtures have not yet been executed here against a
live database.
The read fixture matrix now seeds all 32 migrated tables in both tested
workspaces and uses one shared query for both scopes and unscoped denial.
It verifies exact counts and visible row identities, including principal
membership, to reject cross-tenant substitution with unchanged cardinality.
Work traces, disclosure receipts, rotation history/recipients, and legal holds
are included. Local inventory and output tests do not execute this query.
The guard's local Rust tests do not prove that its SQL ran against PostgreSQL.
The catalog checks follow PostgreSQL's documented row-security and role
inquiry interfaces:

- [PostgreSQL row security](https://www.postgresql.org/docs/16/ddl-rowsecurity.html)
- [Role and schema inquiry functions](https://www.postgresql.org/docs/16/functions-info.html)
- [Relation catalog attributes](https://www.postgresql.org/docs/16/catalog-pg-class.html)

Workspace bootstrap is a separate control-plane operation because the first
workspace and owner membership do not exist yet and therefore cannot pass the
ordinary forced-RLS policies. Configure a distinct, narrowly held provisioning
pool for that operation. Never reuse its credentials in API, bot, MCP, worker,
or other request-serving processes. The Rust provisioning boundary deliberately
has a different pool trait and rolls back uncommitted transactions on drop.

The Rust adapter configuration carries the database URL only as a
`SecretReference`. Operators may point it at an environment variable,
protected file, or deployment-provided external secret resolver. The resolved
URL, including any password, must remain short-lived and must never be
serialized, logged, returned by diagnostics, or stored in a provider profile.
The typed connection profile deliberately has no debug representation, so its
secret locator cannot be included accidentally by derived structured logging.
The deployment-selected `SecretResolver` resolves it only while constructing
the database adapter. The resolved URL is validated as a bounded `postgres` or
`postgresql` URL with a host, kept in zeroizing memory, and represented by a
non-cloneable, non-debuggable consumed configuration.
Remote deployments require full TLS verification; plaintext transport is an
explicit trusted-boundary-only mode. Connection pools are bounded to prevent a
tenant or configuration error from exhausting the database.
Resolution also requires exactly one matching `sslmode`: `verify-full` for
verified transport or `disable` for the explicit trusted-boundary plaintext
mode. Missing, duplicate, or contradictory URL settings fail before a driver
opens a socket.

Every ordinary table containing `workspace_id` receives forced read/write RLS.
`workspaces` is isolated by `id`. Private-to-shared proposals are isolated by
their source workspace; cross-workspace approval must use a separately audited
security-definer operation that verifies both memberships instead of weakening
the general table policy. Principal reads are limited to members visible
through the current workspace's membership rows, so opaque identity records
cannot be enumerated across tenants.

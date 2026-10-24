#!/bin/sh
set -eu

migration=migrations/postgres/0001_tenant_rls.sql
readme=migrations/postgres/README.md

for invariant in \
    "current_setting('rembrane.workspace_id', true)" \
    'ENABLE ROW LEVEL SECURITY' \
    'FORCE ROW LEVEL SECURITY' \
    'WITH CHECK (workspace_id = rembrane.current_workspace_id())' \
    'WITH CHECK (id = rembrane.current_workspace_id())' \
    'source_workspace_id = rembrane.current_workspace_id()'
do
    rg -F "$invariant" "$migration" >/dev/null || {
        echo "PostgreSQL RLS invariant is missing: $invariant" >&2
        exit 1
    }
done

for operational_invariant in \
    'SET LOCAL rembrane.workspace_id' \
    'must not own tenant tables' \
    'BYPASSRLS' \
    'security-definer'
do
    rg -F "$operational_invariant" "$readme" >/dev/null || {
        echo "PostgreSQL RLS operator invariant is missing: $operational_invariant" >&2
        exit 1
    }
done

echo "PostgreSQL RLS checks passed"

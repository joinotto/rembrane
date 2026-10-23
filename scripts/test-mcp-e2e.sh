#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
rembrane_binary=${REMBRANE_BIN:-"$repository_root/target/debug/rembrane"}
export REMBRANE_MCP_BIN=${REMBRANE_MCP_BIN:-"$repository_root/target/debug/rembrane-mcp"}
test -x "$rembrane_binary"
test -x "$REMBRANE_MCP_BIN"

test_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-mcp-e2e.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT

export REMBRANE_DATABASE="$test_directory/rembrane.sqlite"
export REMBRANE_PRINCIPAL_ID="principal_mcp_e2e"
export REMBRANE_WORKSPACE_ID="workspace_mcp_e2e"
export REMBRANE_CLIENT_ID="client_mcp_e2e"
export REMBRANE_READ_SCOPES="global,entity:project_e2e,activity:activity_e2e"
export REMBRANE_WORKSPACE_KEY_ID="mcp-e2e-key-v1"
export REMBRANE_WORKSPACE_KEY_HEX="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

"$rembrane_binary" init \
    --database "$REMBRANE_DATABASE" \
    --principal "$REMBRANE_PRINCIPAL_ID" \
    --workspace "$REMBRANE_WORKSPACE_ID" >/dev/null

if REMBRANE_READ_SCOPES="*" \
    "$REMBRANE_MCP_BIN" </dev/null >/dev/null 2>&1
then
    echo "MCP unexpectedly accepted wildcard read scope" >&2
    exit 1
fi

node "$repository_root/scripts/test-mcp-e2e.mjs"

disclosure_count=$(
    sqlite3 "$REMBRANE_DATABASE" \
        "SELECT count(*) FROM disclosure_receipts WHERE workspace_id = '$REMBRANE_WORKSPACE_ID';"
)
test "$disclosure_count" = "3"
checkpoint_disclosure_count=$(
    sqlite3 "$REMBRANE_DATABASE" \
        "SELECT count(*) FROM checkpoint_disclosures WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND activity_id = 'activity_e2e';"
)
test "$checkpoint_disclosure_count" = "2"
event_count=$(
    sqlite3 "$REMBRANE_DATABASE" \
        "SELECT count(*) FROM workspace_events WHERE workspace_id = '$REMBRANE_WORKSPACE_ID';"
)
test "$event_count" = "6"
trace_count=$(
    sqlite3 "$REMBRANE_DATABASE" \
        "SELECT count(*) FROM memories WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND kind = 'observation' AND status = 'proposed' AND scope_type = 'activity' AND scope_value = 'activity_e2e';"
)
test "$trace_count" = "1"

echo "MCP end-to-end checks passed"

#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
rembrane_binary=${REMBRANE_BIN:-"$repository_root/target/debug/rembrane"}
export REMBRANE_MCP_BIN=${REMBRANE_MCP_BIN:-"$repository_root/target/debug/rembrane-mcp"}
test -x "$rembrane_binary"
test -x "$REMBRANE_MCP_BIN"

test_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-handoff-e2e.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT

export REMBRANE_DATABASE="$test_directory/rembrane.sqlite"
export REMBRANE_PRINCIPAL_ID="principal_handoff"
export REMBRANE_WORKSPACE_ID="workspace_handoff"
export REMBRANE_READ_SCOPES="global,entity:project_handoff,activity:activity_handoff"
export REMBRANE_WORKSPACE_KEY_ID="handoff-key-v1"
export REMBRANE_WORKSPACE_KEY_HEX="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

"$rembrane_binary" init \
    --database "$REMBRANE_DATABASE" \
    --principal "$REMBRANE_PRINCIPAL_ID" \
    --workspace "$REMBRANE_WORKSPACE_ID" >/dev/null

remember_output=$(
    "$rembrane_binary" remember \
        --database "$REMBRANE_DATABASE" \
        --principal "$REMBRANE_PRINCIPAL_ID" \
        --workspace "$REMBRANE_WORKSPACE_ID" \
        --content "Call me Hippo"
)
export REMBRANE_HANDOFF_MEMORY_ID
REMBRANE_HANDOFF_MEMORY_ID=$(
    printf '%s\n' "$remember_output" | awk '/^Remembered / { print $2 }'
)
test -n "$REMBRANE_HANDOFF_MEMORY_ID"

node "$repository_root/scripts/test-cross-tool-continuity.mjs"

recall_output=$(
    "$rembrane_binary" recall \
        --database "$REMBRANE_DATABASE" \
        --principal "$REMBRANE_PRINCIPAL_ID" \
        --workspace "$REMBRANE_WORKSPACE_ID" \
        --client client_handoff_cli_reader \
        --purpose continue-user-preferences \
        --query "What should I call the user?"
)
printf '%s\n' "$recall_output" | rg -F "Call me Captain Hippo" >/dev/null

test "$(
    sqlite3 "$REMBRANE_DATABASE" \
        "SELECT version FROM memories WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND id = '$REMBRANE_HANDOFF_MEMORY_ID';"
)" = "2"
test "$(
    sqlite3 "$REMBRANE_DATABASE" \
        "SELECT count(*) FROM disclosure_receipts WHERE workspace_id = '$REMBRANE_WORKSPACE_ID';"
)" = "2"
test "$(
    sqlite3 "$REMBRANE_DATABASE" \
        "SELECT count(*) FROM checkpoint_disclosures WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND activity_id = 'activity_handoff';"
)" = "1"
test "$(
    sqlite3 "$REMBRANE_DATABASE" \
        "SELECT client_id FROM checkpoint_disclosures WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND activity_id = 'activity_handoff';"
)" = "client_handoff_reader"

"$rembrane_binary" doctor \
    --database "$REMBRANE_DATABASE" \
    --principal "$REMBRANE_PRINCIPAL_ID" \
    --workspace "$REMBRANE_WORKSPACE_ID" >/dev/null

echo "cross-tool memory continuity checks passed"

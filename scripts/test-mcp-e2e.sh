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
export REMBRANE_WORKSPACE_KEY_ID="mcp-e2e-key-v1"
export REMBRANE_WORKSPACE_KEY_HEX="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

"$rembrane_binary" init \
    --database "$REMBRANE_DATABASE" \
    --principal "$REMBRANE_PRINCIPAL_ID" \
    --workspace "$REMBRANE_WORKSPACE_ID" >/dev/null
"$rembrane_binary" remember \
    --database "$REMBRANE_DATABASE" \
    --principal "$REMBRANE_PRINCIPAL_ID" \
    --workspace "$REMBRANE_WORKSPACE_ID" \
    --content "Call me Hippo" >/dev/null

node "$repository_root/scripts/test-mcp-e2e.mjs"

disclosure_count=$(
    sqlite3 "$REMBRANE_DATABASE" \
        "SELECT count(*) FROM disclosure_receipts WHERE workspace_id = '$REMBRANE_WORKSPACE_ID';"
)
test "$disclosure_count" = "1"

echo "MCP end-to-end checks passed"

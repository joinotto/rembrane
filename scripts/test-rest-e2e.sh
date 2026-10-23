#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
rembrane_binary=${REMBRANE_BIN:-"$repository_root/target/debug/rembrane"}
api_binary=${REMBRANE_API_BIN:-"$repository_root/target/debug/rembrane-api"}
test -x "$rembrane_binary"
test -x "$api_binary"

test_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-rest-e2e.XXXXXX")
database="$test_directory/rembrane.sqlite"
api_stdout="$test_directory/api.stdout"
api_stderr="$test_directory/api.stderr"
api_pid=

cleanup() {
    if test -n "$api_pid"; then
        kill "$api_pid" 2>/dev/null || true
        wait "$api_pid" 2>/dev/null || true
    fi
    rm -rf "$test_directory"
}
trap cleanup EXIT

export REMBRANE_WORKSPACE_KEY_ID="rest-e2e-key-v1"
export REMBRANE_WORKSPACE_KEY_HEX="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
export REMBRANE_DATABASE="$database"
export REMBRANE_PRINCIPAL_ID="principal_rest_e2e"
export REMBRANE_WORKSPACE_ID="workspace_rest_e2e"
export REMBRANE_CLIENT_ID="client_rest_e2e"
export REMBRANE_API_TOKEN="rest-e2e-token"
export REMBRANE_LISTEN="${REMBRANE_TEST_LISTEN:-127.0.0.1:18787}"

"$rembrane_binary" init \
    --database "$database" \
    --principal "$REMBRANE_PRINCIPAL_ID" \
    --workspace "$REMBRANE_WORKSPACE_ID" >/dev/null
"$rembrane_binary" remember \
    --database "$database" \
    --principal "$REMBRANE_PRINCIPAL_ID" \
    --workspace "$REMBRANE_WORKSPACE_ID" \
    --content "Call me Hippo" >/dev/null

"$api_binary" >"$api_stdout" 2>"$api_stderr" &
api_pid=$!

base_url="http://$REMBRANE_LISTEN"
attempt=0
until curl -fsS "$base_url/health" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if test "$attempt" -ge 50; then
        echo "REST server did not become ready" >&2
        sed -n '1,120p' "$api_stderr" >&2
        exit 1
    fi
    sleep 0.1
done

postman collection run \
    "$repository_root/tests/postman/rembrane-local.postman_collection.json" \
    --env-var "baseUrl=$base_url" \
    --env-var "apiToken=$REMBRANE_API_TOKEN" \
    --env-var "workspaceId=$REMBRANE_WORKSPACE_ID" \
    --env-var "principalId=$REMBRANE_PRINCIPAL_ID"

disclosure_count=$(
    sqlite3 "$database" \
        "SELECT count(*) FROM disclosure_receipts WHERE workspace_id = '$REMBRANE_WORKSPACE_ID';"
)
test "$disclosure_count" = "1"

echo "REST end-to-end checks passed"

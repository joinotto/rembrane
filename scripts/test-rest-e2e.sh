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
invited_principal_id="principal_rest_invited"
owner_personal_workspace="workspace_rest_owner_personal"
invited_personal_workspace="workspace_rest_invited_personal"
export REMBRANE_CLIENT_ID="client_rest_e2e"
export REMBRANE_READ_SCOPES="global,domain:travel,entity:project_rest_e2e,entity:trip_missing"
export REMBRANE_API_TOKEN="rest-e2e-token"
export REMBRANE_LISTEN="${REMBRANE_TEST_LISTEN:-127.0.0.1:18787}"

"$rembrane_binary" init \
    --database "$database" \
    --principal "$REMBRANE_PRINCIPAL_ID" \
    --workspace "$owner_personal_workspace" >/dev/null
"$rembrane_binary" init \
    --database "$database" \
    --principal "$invited_principal_id" \
    --workspace "$invited_personal_workspace" >/dev/null
"$rembrane_binary" workspace create-shared \
    --database "$database" \
    --principal "$REMBRANE_PRINCIPAL_ID" \
    --workspace "$REMBRANE_WORKSPACE_ID" >/dev/null
"$rembrane_binary" remember \
    --database "$database" \
    --principal "$REMBRANE_PRINCIPAL_ID" \
    --workspace "$REMBRANE_WORKSPACE_ID" \
    --content "Call me Hippo" >/dev/null
"$rembrane_binary" remember \
    --database "$database" \
    --principal "$REMBRANE_PRINCIPAL_ID" \
    --workspace "$REMBRANE_WORKSPACE_ID" \
    --entity project_rest_e2e \
    --content "Use Rust for the REST project" >/dev/null

if REMBRANE_READ_SCOPES="*" \
    "$api_binary" >/dev/null 2>&1
then
    echo "REST unexpectedly accepted wildcard read scope" >&2
    exit 1
fi

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

scoped_response="$test_directory/scoped-response.json"
scoped_status=$(
    curl -sS \
        -o "$scoped_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/context/resolve" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"workspaceId\":\"$REMBRANE_WORKSPACE_ID\",\"subjectId\":\"$REMBRANE_PRINCIPAL_ID\",\"entityId\":\"project_outside_grant\",\"purpose\":\"continue-project\",\"query\":\"What is next?\",\"maximumItems\":10}"
)
test "$scoped_status" = "403"
test "$(jq -r '.code' "$scoped_response")" = "access_denied"

authorized_scoped_response="$test_directory/authorized-scoped-response.json"
authorized_scoped_status=$(
    curl -sS \
        -o "$authorized_scoped_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/context/resolve" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"workspaceId\":\"$REMBRANE_WORKSPACE_ID\",\"subjectId\":\"$REMBRANE_PRINCIPAL_ID\",\"entityId\":\"project_rest_e2e\",\"purpose\":\"continue-project\",\"query\":\"Which language should the REST project use?\",\"maximumItems\":10}"
)
test "$authorized_scoped_status" = "200"
test "$(
    jq -r '.items[0].content' "$authorized_scoped_response"
)" = "Use Rust for the REST project"

postman collection run \
    "$repository_root/tests/postman/rembrane-local.postman_collection.json" \
    --env-var "baseUrl=$base_url" \
    --env-var "apiToken=$REMBRANE_API_TOKEN" \
    --env-var "workspaceId=$REMBRANE_WORKSPACE_ID" \
    --env-var "principalId=$REMBRANE_PRINCIPAL_ID" \
    --env-var "invitedPrincipalId=$invited_principal_id" \
    --env-var "invitationId=invitation_rest_e2e" \
    --env-var "tripId=trip_missing"

acceptance_invitation_id="invitation_rest_accept"
acceptance_create_response="$test_directory/acceptance-create-response.json"
acceptance_create_status=$(
    curl -sS \
        -o "$acceptance_create_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/workspaces/invitations" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"workspaceId\":\"$REMBRANE_WORKSPACE_ID\",\"invitationId\":\"$acceptance_invitation_id\",\"invitedPrincipalId\":\"$invited_principal_id\",\"role\":\"member\",\"ttlSeconds\":3600,\"requestId\":\"request_invitation_accept_create_rest_e2e\"}"
)
test "$acceptance_create_status" = "201"
test "$(jq -r '.status' "$acceptance_create_response")" = "pending"

kill "$api_pid"
wait "$api_pid" 2>/dev/null || true
api_pid=
export REMBRANE_PRINCIPAL_ID="$invited_principal_id"
export REMBRANE_CLIENT_ID="client_rest_invited"
export REMBRANE_READ_SCOPES="global"
"$api_binary" >"$api_stdout" 2>"$api_stderr" &
api_pid=$!

attempt=0
until curl -fsS "$base_url/health" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if test "$attempt" -ge 50; then
        echo "invitation-only REST server did not become ready" >&2
        sed -n '1,120p' "$api_stderr" >&2
        exit 1
    fi
    sleep 0.1
done

pre_accept_response="$test_directory/pre-accept-response.json"
pre_accept_status=$(
    curl -sS \
        -o "$pre_accept_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/context/resolve" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"workspaceId\":\"$REMBRANE_WORKSPACE_ID\",\"subjectId\":\"$invited_principal_id\",\"purpose\":\"pre-accept isolation proof\",\"query\":\"Must not disclose memory\",\"maximumItems\":1}"
)
test "$pre_accept_status" = "403"
test "$(jq -r '.code' "$pre_accept_response")" = "access_denied"

accept_response="$test_directory/accept-response.json"
accept_status=$(
    curl -sS \
        -o "$accept_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/workspaces/invitations/accept" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"workspaceId\":\"$REMBRANE_WORKSPACE_ID\",\"invitationId\":\"$acceptance_invitation_id\",\"requestId\":\"request_invitation_accept_rest_e2e\"}"
)
test "$accept_status" = "200"
test "$(jq -r '.status' "$accept_response")" = "accepted"
test "$(jq -r '.invitedPrincipalId' "$accept_response")" = "$invited_principal_id"

disclosure_count=$(
    sqlite3 "$database" \
        "SELECT count(*) FROM disclosure_receipts WHERE workspace_id = '$REMBRANE_WORKSPACE_ID';"
)
test "$disclosure_count" = "2"
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM trips WHERE workspace_id = '$REMBRANE_WORKSPACE_ID';"
)" = "1"
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM booking_research WHERE workspace_id = '$REMBRANE_WORKSPACE_ID';"
)" = "1"
test "$(
    sqlite3 "$database" \
        "SELECT status FROM workspace_invitations WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND id = 'invitation_rest_e2e';"
)" = "revoked"
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM administrative_audit_events WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND target_kind = 'invitation';"
)" = "4"
test "$(
    sqlite3 "$database" \
        "SELECT status FROM workspace_invitations WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND id = '$acceptance_invitation_id';"
)" = "accepted"
test "$(
    sqlite3 "$database" \
        "SELECT role || ':' || status FROM memberships WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND principal_id = '$invited_principal_id';"
)" = "member:active"

echo "REST end-to-end checks passed"

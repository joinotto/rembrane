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
export REMBRANE_READ_SCOPES="global,domain:travel,entity:project_rest_e2e,entity:trip_missing,activity:activity_rest_e2e"
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

sqlite3 "$database" <<SQL
PRAGMA foreign_keys = ON;
INSERT INTO knowledge_nodes (
    workspace_id, id, node_ciphertext, encryption_key_id,
    encryption_algorithm, encryption_nonce, version,
    valid_from, valid_until, recorded_at
) VALUES (
    '$REMBRANE_WORKSPACE_ID', 'project_rest_e2e', X'01',
    '$REMBRANE_WORKSPACE_KEY_ID', 'xchacha20poly1305', zeroblob(24),
    1, 1700000000, NULL, 1700000000
);
SQL

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

denied_graph_response="$test_directory/denied-graph-response.json"
denied_graph_status=$(
    curl -sS \
        -o "$denied_graph_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/graph/context/resolve" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"workspaceId\":\"$REMBRANE_WORKSPACE_ID\",\"subjectId\":\"$REMBRANE_PRINCIPAL_ID\",\"nodeId\":\"project_rest_e2e\",\"direction\":\"outgoing\",\"validAtEpochSeconds\":1700000000,\"purpose\":\"continue-project\",\"entityId\":\"project_outside_grant\"}"
)
test "$denied_graph_status" = "403"
test "$(jq -r '.code' "$denied_graph_response")" = "access_denied"

graph_response="$test_directory/graph-response.json"
graph_status=$(
    curl -sS \
        -o "$graph_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/graph/context/resolve" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"workspaceId\":\"$REMBRANE_WORKSPACE_ID\",\"subjectId\":\"$REMBRANE_PRINCIPAL_ID\",\"nodeId\":\"project_rest_e2e\",\"direction\":\"outgoing\",\"validAtEpochSeconds\":1700000000,\"maximumCandidates\":20,\"purpose\":\"continue-project\",\"entityId\":\"project_rest_e2e\"}"
)
test "$graph_status" = "200"
test "$(jq -r '.edges | length' "$graph_response")" = "0"
test -n "$(jq -r '.disclosureId' "$graph_response")"
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM graph_disclosure_receipts WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND node_id = 'project_rest_e2e' AND direction = 'outgoing' AND valid_at_epoch_seconds = 1700000000;"
)" = "1"

postman collection run \
    "$repository_root/tests/postman/rembrane-local.postman_collection.json" \
    --env-var "baseUrl=$base_url" \
    --env-var "apiToken=$REMBRANE_API_TOKEN" \
    --env-var "workspaceId=$REMBRANE_WORKSPACE_ID" \
    --env-var "principalId=$REMBRANE_PRINCIPAL_ID" \
    --env-var "invitedPrincipalId=$invited_principal_id" \
    --env-var "invitationId=invitation_rest_e2e" \
    --env-var "tripId=trip_missing"

denied_checkpoint_response="$test_directory/denied-checkpoint-response.json"
denied_checkpoint_status=$(
    curl -sS \
        -o "$denied_checkpoint_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/activities/activity_outside_grant/checkpoint" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"workspaceId\":\"$REMBRANE_WORKSPACE_ID\",\"subjectId\":\"$REMBRANE_PRINCIPAL_ID\",\"goal\":\"Must not persist\",\"summary\":\"Outside activity grant\",\"expectedPreviousSequence\":7}"
)
test "$denied_checkpoint_status" = "403"
test "$(jq -r '.code' "$denied_checkpoint_response")" = "access_denied"

checkpoint_response="$test_directory/checkpoint-response.json"
checkpoint_status=$(
    curl -sS \
        -o "$checkpoint_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/activities/activity_rest_e2e/checkpoint" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"workspaceId\":\"$REMBRANE_WORKSPACE_ID\",\"subjectId\":\"$REMBRANE_PRINCIPAL_ID\",\"entityId\":\"project_rest_e2e\",\"goal\":\"Ship REST continuity\",\"summary\":\"REST checkpoint creation works.\",\"nextSteps\":[\"Resume from another app\"],\"blockers\":[],\"stateFingerprint\":\"git:rest123\",\"expectedPreviousSequence\":7}"
)
test "$checkpoint_status" = "201"
test "$(jq -r '.version' "$checkpoint_response")" = "1"
test "$(jq -r '.activityId' "$checkpoint_response")" = "activity_rest_e2e"

resume_response="$test_directory/resume-response.json"
resume_status=$(
    curl -sS \
        -o "$resume_response" \
        -w '%{http_code}' \
        "$base_url/v1/activities/activity_rest_e2e/resume?workspaceId=$REMBRANE_WORKSPACE_ID&subjectId=$REMBRANE_PRINCIPAL_ID&purpose=continue-development&stateFingerprint=git%3Arest123" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN"
)
test "$resume_status" = "200"
jq -e \
    '.version == 1
        and .summary == "REST checkpoint creation works."
        and .stale == false
        and .disclosureId' "$resume_response" >/dev/null

updated_checkpoint_response="$test_directory/updated-checkpoint-response.json"
updated_checkpoint_status=$(
    curl -sS \
        -o "$updated_checkpoint_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/activities/activity_rest_e2e/checkpoint" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"workspaceId\":\"$REMBRANE_WORKSPACE_ID\",\"subjectId\":\"$REMBRANE_PRINCIPAL_ID\",\"summary\":\"REST checkpoint update works.\",\"nextSteps\":[\"Run all clients\"],\"blockers\":[],\"stateFingerprint\":\"git:rest456\",\"expectedVersion\":1,\"expectedPreviousSequence\":8}"
)
test "$updated_checkpoint_status" = "200"
test "$(jq -r '.version' "$updated_checkpoint_response")" = "2"

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

pending_list_response="$test_directory/pending-list-response.json"
pending_list_status=$(
    curl -sS \
        -o "$pending_list_response" \
        -w '%{http_code}' \
        "$base_url/v1/workspaces/invitations?workspaceId=$REMBRANE_WORKSPACE_ID&status=pending&limit=1" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN"
)
test "$pending_list_status" = "200"
test "$(jq -r '.workspaceId' "$pending_list_response")" = "$REMBRANE_WORKSPACE_ID"
test "$(jq -r '.invitations | length' "$pending_list_response")" = "1"
test "$(jq -r '.invitations[0].invitationId' "$pending_list_response")" = "$acceptance_invitation_id"
test "$(jq -r '.invitations[0].status' "$pending_list_response")" = "pending"

cross_workspace_list_response="$test_directory/cross-workspace-list-response.json"
cross_workspace_list_status=$(
    curl -sS \
        -o "$cross_workspace_list_response" \
        -w '%{http_code}' \
        "$base_url/v1/workspaces/invitations?workspaceId=workspace_other&limit=1" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN"
)
test "$cross_workspace_list_status" = "403"
test "$(jq -r '.code' "$cross_workspace_list_response")" = "access_denied"

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
        "SELECT count(*) FROM graph_disclosure_receipts WHERE workspace_id = '$REMBRANE_WORKSPACE_ID';"
)" = "2"
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
        "SELECT version FROM activity_checkpoints WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND activity_id = 'activity_rest_e2e';"
)" = "2"
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM checkpoint_disclosures WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND activity_id = 'activity_rest_e2e';"
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

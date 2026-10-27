#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$repository_root/scripts/local-test-environment.sh"
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

discovery_response="$test_directory/discovery-response.json"
discovery_status=$(
    curl -sS \
        -o "$discovery_response" \
        -w '%{http_code}' \
        "$base_url/.well-known/ai-memory"
)
test "$discovery_status" = "200"
jq -e \
    '.provider.id == "local.rembrane"
        and .protocolVersions == ["0.1"]
        and .endpoints.api == "'"$base_url"'/v1"
        and .capabilities.contextResolution == true
        and .capabilities.activityCheckpoint == true
        and .capabilities.disclosureReceipt == true
        and .capabilities.memoryProposal == true
        and .capabilities.imports == ["jsonl"]
        and .capabilities.exports == ["jsonl", "markdown", "graph-json", "encrypted-archive"]
        and .privacy.processingModes == ["local-only"]
        and .privacy.plaintextProcessingLocation == "user-device"' \
    "$discovery_response" >/dev/null

invalid_travel_response="$test_directory/invalid-travel-response.json"
invalid_travel_status=$(
    curl -sS \
        -o "$invalid_travel_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/travel/context/resolve" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"workspaceId\":\"$REMBRANE_WORKSPACE_ID\",\"subjectId\":\"$REMBRANE_PRINCIPAL_ID\",\"tripId\":\"../trip\",\"purpose\":\"continue-trip\",\"asOf\":\"2026-10-25T00:00:00Z\"}"
)
test "$invalid_travel_status" = "400"
test "$(jq -r '.code' "$invalid_travel_response")" = "invalid_request"

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

denied_memory_response="$test_directory/denied-memory-response.json"
denied_memory_status=$(
    curl -sS \
        -o "$denied_memory_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/memories/preferences" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"workspaceId\":\"$REMBRANE_WORKSPACE_ID\",\"subjectId\":\"$REMBRANE_PRINCIPAL_ID\",\"entityId\":\"project_outside_grant\",\"content\":\"Must not persist\",\"expectedPreviousSequence\":9}"
)
test "$denied_memory_status" = "403"
test "$(jq -r '.code' "$denied_memory_response")" = "access_denied"

remember_response="$test_directory/remember-response.json"
remember_status=$(
    curl -sS \
        -o "$remember_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/memories/preferences" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"workspaceId\":\"$REMBRANE_WORKSPACE_ID\",\"subjectId\":\"$REMBRANE_PRINCIPAL_ID\",\"content\":\"Use concise REST responses\",\"expectedPreviousSequence\":9}"
)
test "$remember_status" = "201"
test "$(jq -r '.version' "$remember_response")" = "1"
test "$(jq -r '.status' "$remember_response")" = "confirmed"
rest_memory_id=$(jq -er '.memoryId' "$remember_response")

correction_response="$test_directory/correction-response.json"
correction_status=$(
    curl -sS \
        -o "$correction_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/memories/$rest_memory_id/correction" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"workspaceId\":\"$REMBRANE_WORKSPACE_ID\",\"subjectId\":\"$REMBRANE_PRINCIPAL_ID\",\"replacement\":\"Use concise and direct REST responses\",\"expectedVersion\":1,\"expectedPreviousSequence\":10}"
)
test "$correction_status" = "200"
test "$(jq -r '.version' "$correction_response")" = "2"

deletion_response="$test_directory/deletion-response.json"
deletion_status=$(
    curl -sS \
        -o "$deletion_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/memories/$rest_memory_id/deletion" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"workspaceId\":\"$REMBRANE_WORKSPACE_ID\",\"subjectId\":\"$REMBRANE_PRINCIPAL_ID\",\"reason\":\"Preference withdrawn\",\"expectedVersion\":2,\"expectedPreviousSequence\":11}"
)
test "$deletion_status" = "200"
test "$(jq -r '.version' "$deletion_response")" = "3"
test "$(jq -r '.status' "$deletion_response")" = "deleted"

work_trace_response="$test_directory/work-trace-response.json"
work_trace_status=$(
    curl -sS \
        -o "$work_trace_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/memories/work-traces" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"workspaceId\":\"$REMBRANE_WORKSPACE_ID\",\"subjectId\":\"$REMBRANE_PRINCIPAL_ID\",\"activityId\":\"activity_rest_e2e\",\"entityId\":\"project_rest_e2e\",\"summary\":\"Completed the REST memory lifecycle.\",\"expectedPreviousSequence\":12}"
)
test "$work_trace_status" = "201"
test "$(jq -r '.version' "$work_trace_response")" = "1"
test "$(jq -r '.status' "$work_trace_response")" = "proposed"
rest_trace_id=$(jq -er '.memoryId' "$work_trace_response")

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

unauthenticated_export_response="$test_directory/unauthenticated-export-response.json"
unauthenticated_export_status=$(
    curl -sS \
        -o "$unauthenticated_export_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/exports?workspaceId=$REMBRANE_WORKSPACE_ID&subjectId=$REMBRANE_PRINCIPAL_ID&format=jsonl"
)
test "$unauthenticated_export_status" = "401"
test "$(jq -r '.code' "$unauthenticated_export_response")" = "unauthorized"

cross_workspace_export_response="$test_directory/cross-workspace-export-response.json"
cross_workspace_export_status=$(
    curl -sS \
        -o "$cross_workspace_export_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/exports?workspaceId=workspace_other&subjectId=$REMBRANE_PRINCIPAL_ID&format=jsonl" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN"
)
test "$cross_workspace_export_status" = "403"
test "$(jq -r '.code' "$cross_workspace_export_response")" = "access_denied"

jsonl_export="$test_directory/rest-export.jsonl"
jsonl_export_headers="$test_directory/rest-export-jsonl.headers"
jsonl_export_status=$(
    curl -sS \
        -D "$jsonl_export_headers" \
        -o "$jsonl_export" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/exports?workspaceId=$REMBRANE_WORKSPACE_ID&subjectId=$REMBRANE_PRINCIPAL_ID&format=jsonl" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN"
)
test "$jsonl_export_status" = "200"
rg -i '^content-type: application/x-ndjson\r?$' "$jsonl_export_headers" >/dev/null
rg -i '^cache-control: no-store\r?$' "$jsonl_export_headers" >/dev/null
rg -i '^x-content-type-options: nosniff\r?$' "$jsonl_export_headers" >/dev/null
rg -i '^content-disposition: attachment; filename="rembrane-memories.jsonl"\r?$' \
    "$jsonl_export_headers" >/dev/null
head -n 1 "$jsonl_export" | jq -e \
    '.format == "rembrane-memory-jsonl"
        and .workspaceId == "'"$REMBRANE_WORKSPACE_ID"'"
        and .subjectId == "'"$REMBRANE_PRINCIPAL_ID"'"' >/dev/null

markdown_export="$test_directory/rest-export.md"
markdown_export_status=$(
    curl -sS \
        -o "$markdown_export" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/exports?workspaceId=$REMBRANE_WORKSPACE_ID&subjectId=$REMBRANE_PRINCIPAL_ID&format=markdown" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN"
)
test "$markdown_export_status" = "200"
rg -F '<!-- rembrane-memory-markdown-v1 -->' "$markdown_export" >/dev/null
rg -F "# Rembrane memory export" "$markdown_export" >/dev/null

graph_export="$test_directory/rest-graph-export.json"
graph_export_status=$(
    curl -sS \
        -o "$graph_export" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/exports?workspaceId=$REMBRANE_WORKSPACE_ID&subjectId=$REMBRANE_PRINCIPAL_ID&format=graph-json" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN"
)
test "$graph_export_status" = "200"
jq -e \
    '.format == "rembrane.knowledge-graph"
        and .version == 1
        and .workspace_id == "'"$REMBRANE_WORKSPACE_ID"'"
        and (.nodes | type == "array")
        and (.edges | type == "array")' \
    "$graph_export" >/dev/null

portable_import="$test_directory/portable-import.jsonl"
printf '%s\n' \
    '{"format":"rembrane-memory-jsonl","formatVersion":1,"workspaceId":"workspace_portable_source","subjectId":"principal_portable_source","memoryId":"memory_portable_source","version":1,"scope":{"type":"global"},"kind":"preference","status":"confirmed","content":"Call me Hippo across assistants","evidence":[{"id":"evidence_portable_source","source":"user-statement"}]}' \
    >"$portable_import"
import_sequence=$(
    sqlite3 "$database" \
        "SELECT COALESCE(MAX(sequence), 0) FROM workspace_events WHERE workspace_id = '$REMBRANE_WORKSPACE_ID';"
)
proposals_before=$(
    sqlite3 "$database" \
        "SELECT count(*) FROM memories WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND subject_id = '$REMBRANE_PRINCIPAL_ID' AND kind = 'preference' AND status = 'proposed' AND scope_type = 'global';"
)
imported_evidence_before=$(
    sqlite3 "$database" \
        "SELECT count(*) FROM memory_evidence WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND source_type = 'imported-record';"
)

unauthenticated_import_response="$test_directory/unauthenticated-import-response.json"
unauthenticated_import_status=$(
    curl -sS \
        -o "$unauthenticated_import_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/imports?workspaceId=$REMBRANE_WORKSPACE_ID&subjectId=$REMBRANE_PRINCIPAL_ID&expectedPreviousSequence=$import_sequence" \
        -H "Content-Type: application/x-ndjson" \
        --data-binary "@$portable_import"
)
test "$unauthenticated_import_status" = "401"
test "$(jq -r '.code' "$unauthenticated_import_response")" = "unauthorized"

invalid_import_media_response="$test_directory/invalid-import-media-response.json"
invalid_import_media_status=$(
    curl -sS \
        -o "$invalid_import_media_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/imports?workspaceId=$REMBRANE_WORKSPACE_ID&subjectId=$REMBRANE_PRINCIPAL_ID&expectedPreviousSequence=$import_sequence" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/json" \
        --data-binary "@$portable_import"
)
test "$invalid_import_media_status" = "400"
test "$(jq -r '.code' "$invalid_import_media_response")" = "invalid_request"

invalid_import_response="$test_directory/invalid-import-response.json"
invalid_import_status=$(
    curl -sS \
        -o "$invalid_import_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/imports?workspaceId=$REMBRANE_WORKSPACE_ID&subjectId=$REMBRANE_PRINCIPAL_ID&expectedPreviousSequence=$import_sequence" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/x-ndjson" \
        --data-binary '{"not":"portable-memory"}'
)
test "$invalid_import_status" = "400"
test "$(jq -r '.code' "$invalid_import_response")" = "invalid_request"

cross_workspace_import_response="$test_directory/cross-workspace-import-response.json"
cross_workspace_import_status=$(
    curl -sS \
        -o "$cross_workspace_import_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/imports?workspaceId=workspace_other&subjectId=$REMBRANE_PRINCIPAL_ID&expectedPreviousSequence=$import_sequence" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/x-ndjson" \
        --data-binary "@$portable_import"
)
test "$cross_workspace_import_status" = "403"
test "$(jq -r '.code' "$cross_workspace_import_response")" = "access_denied"

import_response="$test_directory/import-response.json"
import_status=$(
    curl -sS \
        -o "$import_response" \
        -w '%{http_code}' \
        -X POST "$base_url/v1/imports?workspaceId=$REMBRANE_WORKSPACE_ID&subjectId=$REMBRANE_PRINCIPAL_ID&expectedPreviousSequence=$import_sequence" \
        -H "Authorization: Bearer $REMBRANE_API_TOKEN" \
        -H "Content-Type: application/x-ndjson" \
        --data-binary "@$portable_import"
)
test "$import_status" = "201"
test "$(jq -r '.imported' "$import_response")" = "1"
test "$(jq -r '.status' "$import_response")" = "proposed"
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM memories WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND subject_id = '$REMBRANE_PRINCIPAL_ID' AND kind = 'preference' AND status = 'proposed' AND scope_type = 'global';"
)" = "$((proposals_before + 1))"
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM memory_evidence WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND source_type = 'imported-record';"
)" = "$((imported_evidence_before + 1))"
test "$(
    sqlite3 "$database" \
        "SELECT COALESCE(MAX(sequence), 0) FROM workspace_events WHERE workspace_id = '$REMBRANE_WORKSPACE_ID';"
)" = "$((import_sequence + 1))"

kill "$api_pid"
wait "$api_pid" 2>/dev/null || true
api_pid=

cli_resume=$(
    "$rembrane_binary" resume \
        --database "$database" \
        --principal "$REMBRANE_PRINCIPAL_ID" \
        --workspace "$REMBRANE_WORKSPACE_ID" \
        --activity activity_rest_e2e \
        --client client_rest_to_cli_reader \
        --purpose continue-after-api-handoff \
        --state-fingerprint "git:rest456"
)
printf '%s\n' "$cli_resume" | jq -e \
    '.version == 2
        and .entityId == "project_rest_e2e"
        and .summary == "REST checkpoint update works."
        and .nextSteps == ["Run all clients"]
        and .stale == false
        and .disclosureId' >/dev/null

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
)" = "2"
test "$(
    sqlite3 "$database" \
        "SELECT count(*) FROM checkpoint_disclosures WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND activity_id = 'activity_rest_e2e' AND client_id = 'client_rest_to_cli_reader' AND purpose = 'continue-after-api-handoff';"
)" = "1"
test "$(
    sqlite3 "$database" \
        "SELECT version || ':' || status FROM memories WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND id = '$rest_memory_id';"
)" = "3:deleted"
test "$(
    sqlite3 "$database" \
        "SELECT kind || ':' || status || ':' || scope_type || ':' || scope_value FROM memories WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND id = '$rest_trace_id';"
)" = "observation:proposed:activity:activity_rest_e2e"
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

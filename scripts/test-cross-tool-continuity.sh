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

trace_output=$(
    "$rembrane_binary" trace \
        --database "$REMBRANE_DATABASE" \
        --principal "$REMBRANE_PRINCIPAL_ID" \
        --workspace "$REMBRANE_WORKSPACE_ID" \
        --activity activity_handoff \
        --entity project_handoff \
        --summary "Verified encrypted work-trace handoff" \
        --json
)
export REMBRANE_HANDOFF_TRACE_ID
REMBRANE_HANDOFF_TRACE_ID=$(printf '%s\n' "$trace_output" | jq -er '
    select(.schemaVersion == 1 and .status == "proposed" and .version == 1)
    | .memoryId
')

proposed_context=$(
    "$rembrane_binary" recall \
        --database "$REMBRANE_DATABASE" \
        --principal "$REMBRANE_PRINCIPAL_ID" \
        --workspace "$REMBRANE_WORKSPACE_ID" \
        --activity activity_handoff \
        --client client_handoff_proposal_reader \
        --purpose review-trust-boundary \
        --query "Verified encrypted work-trace handoff" \
        --json
)
printf '%s\n' "$proposed_context" | jq -e --arg trace_id "$REMBRANE_HANDOFF_TRACE_ID" '
    .disclosureId and all(.items[]; .memoryId != $trace_id)
    and ((tostring | contains("Verified encrypted work-trace handoff")) | not)
' >/dev/null

assert_confirmation_rejected() {
    confirmation_principal=$1
    confirmation_workspace=$2
    shift 2
    state_before=$(sqlite3 "$REMBRANE_DATABASE" "
        SELECT version || ':' || status || ':' || hex(content_ciphertext)
            FROM memories WHERE id = '$REMBRANE_HANDOFF_TRACE_ID';
        SELECT count(*) FROM workspace_events;
        SELECT count(*) FROM memory_evidence;
    ")
    if "$rembrane_binary" confirm \
        --database "$REMBRANE_DATABASE" \
        --principal "$confirmation_principal" \
        --workspace "$confirmation_workspace" \
        --memory "$REMBRANE_HANDOFF_TRACE_ID" \
        --json "$@" >"$test_directory/confirm-failure.json" \
        2>"$test_directory/confirm-failure.stderr"
    then
        echo "confirmation unexpectedly accepted a denied approval" >&2
        exit 1
    fi
    jq -e '. == {"schemaVersion": 1, "error": {"code": "confirm_failed"}}' \
        "$test_directory/confirm-failure.json" >/dev/null
    test ! -s "$test_directory/confirm-failure.stderr"
    test "$state_before" = "$(sqlite3 "$REMBRANE_DATABASE" "
        SELECT version || ':' || status || ':' || hex(content_ciphertext)
            FROM memories WHERE id = '$REMBRANE_HANDOFF_TRACE_ID';
        SELECT count(*) FROM workspace_events;
        SELECT count(*) FROM memory_evidence;
    ")"
}

assert_confirmation_rejected "$REMBRANE_PRINCIPAL_ID" "$REMBRANE_WORKSPACE_ID" \
    --version 1 --activity activity_handoff
assert_confirmation_rejected "$REMBRANE_PRINCIPAL_ID" "$REMBRANE_WORKSPACE_ID" \
    --version 1 --activity activity_handoff --approve --approve
assert_confirmation_rejected "$REMBRANE_PRINCIPAL_ID" "$REMBRANE_WORKSPACE_ID" \
    --version 1 --approve
assert_confirmation_rejected "$REMBRANE_PRINCIPAL_ID" "$REMBRANE_WORKSPACE_ID" \
    --version 1 --entity project_handoff --approve
assert_confirmation_rejected "$REMBRANE_PRINCIPAL_ID" "$REMBRANE_WORKSPACE_ID" \
    --version 2 --activity activity_handoff --approve
assert_confirmation_rejected principal_other "$REMBRANE_WORKSPACE_ID" \
    --version 1 --activity activity_handoff --approve
assert_confirmation_rejected "$REMBRANE_PRINCIPAL_ID" workspace_other \
    --version 1 --activity activity_handoff --approve
(
    REMBRANE_WORKSPACE_KEY_HEX="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
        assert_confirmation_rejected "$REMBRANE_PRINCIPAL_ID" "$REMBRANE_WORKSPACE_ID" \
            --version 1 --activity activity_handoff --approve
)

confirm_output=$(
    "$rembrane_binary" confirm \
        --database "$REMBRANE_DATABASE" \
        --principal "$REMBRANE_PRINCIPAL_ID" \
        --workspace "$REMBRANE_WORKSPACE_ID" \
        --memory "$REMBRANE_HANDOFF_TRACE_ID" \
        --version 1 \
        --activity activity_handoff \
        --approve \
        --json
)
printf '%s\n' "$confirm_output" | jq -e --arg trace_id "$REMBRANE_HANDOFF_TRACE_ID" '
    . == {
        "schemaVersion": 1,
        "memoryId": $trace_id,
        "version": 2,
        "kind": "observation",
        "status": "confirmed"
    }
' >/dev/null
assert_confirmation_rejected "$REMBRANE_PRINCIPAL_ID" "$REMBRANE_WORKSPACE_ID" \
    --version 1 --activity activity_handoff --approve
assert_confirmation_rejected "$REMBRANE_PRINCIPAL_ID" "$REMBRANE_WORKSPACE_ID" \
    --version 2 --activity activity_handoff --approve

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

resume_output=$(
    "$rembrane_binary" resume \
        --database "$REMBRANE_DATABASE" \
        --principal "$REMBRANE_PRINCIPAL_ID" \
        --workspace "$REMBRANE_WORKSPACE_ID" \
        --activity activity_handoff \
        --client client_handoff_cli_checkpoint_reader \
        --purpose continue-development \
        --state-fingerprint "git:handoff123"
)
printf '%s\n' "$resume_output" | jq -e \
    '.version == 1
        and .entityId == "project_handoff"
        and .summary == "CLI and the first MCP client share encrypted memory."
        and .nextSteps == ["Resume from a fresh agent process"]
        and .stale == false
        and .disclosureId' >/dev/null

test "$(
    sqlite3 "$REMBRANE_DATABASE" \
        "SELECT version FROM memories WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND id = '$REMBRANE_HANDOFF_MEMORY_ID';"
)" = "2"
test "$(
    sqlite3 "$REMBRANE_DATABASE" \
        "SELECT count(*) FROM disclosure_receipts WHERE workspace_id = '$REMBRANE_WORKSPACE_ID';"
)" = "4"
test "$(
    sqlite3 "$REMBRANE_DATABASE" \
        "SELECT count(*) FROM checkpoint_disclosures WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND activity_id = 'activity_handoff';"
)" = "2"
test "$(
    sqlite3 "$REMBRANE_DATABASE" \
        "SELECT group_concat(client_id, ',') FROM (SELECT client_id FROM checkpoint_disclosures WHERE workspace_id = '$REMBRANE_WORKSPACE_ID' AND activity_id = 'activity_handoff' ORDER BY client_id);"
)" = "client_handoff_cli_checkpoint_reader,client_handoff_reader"

test "$(sqlite3 "$REMBRANE_DATABASE" "
    SELECT count(*) FROM memories WHERE id = '$REMBRANE_HANDOFF_TRACE_ID'
        AND version = 2 AND kind = 'observation' AND status = 'confirmed'
        AND scope_type = 'activity' AND scope_value = 'activity_handoff'
        AND instr(content_ciphertext, CAST('work-trace handoff' AS BLOB)) = 0;
")" = "1"
test "$(sqlite3 "$REMBRANE_DATABASE" "
    SELECT group_concat(source_type, ',') FROM (
        SELECT source_type FROM memory_evidence
        WHERE memory_id = '$REMBRANE_HANDOFF_TRACE_ID' ORDER BY ordinal
    );
")" = "agent-observation,user-statement"
test "$(sqlite3 "$REMBRANE_DATABASE" "
    SELECT count(*) FROM disclosed_memories AS memory
    JOIN disclosure_receipts AS receipt
        ON receipt.workspace_id = memory.workspace_id
        AND receipt.id = memory.disclosure_id
    WHERE memory.memory_id = '$REMBRANE_HANDOFF_TRACE_ID'
        AND memory.memory_version = 2
        AND receipt.client_id = 'client_handoff_reader';
")" = "1"

"$rembrane_binary" doctor \
    --database "$REMBRANE_DATABASE" \
    --principal "$REMBRANE_PRINCIPAL_ID" \
    --workspace "$REMBRANE_WORKSPACE_ID" >/dev/null

echo "cross-tool memory continuity checks passed"

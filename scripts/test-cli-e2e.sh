#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
rembrane_binary=${REMBRANE_BIN:-"$repository_root/target/debug/rembrane"}
test -x "$rembrane_binary"

test_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-cli-e2e.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT
database="$test_directory/rembrane.sqlite"

export REMBRANE_WORKSPACE_KEY_ID="e2e-key-v1"
export REMBRANE_WORKSPACE_KEY_HEX="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

"$rembrane_binary" init \
    --database "$database" \
    --principal principal_e2e \
    --workspace workspace_e2e >/dev/null

remember_output=$(
    "$rembrane_binary" remember \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --content "Call me Hippo"
)
memory_id=$(printf '%s\n' "$remember_output" | awk '/^Remembered / { print $2 }')
test -n "$memory_id"

doctor_output=$(
    "$rembrane_binary" doctor \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e
)
printf '%s\n' "$doctor_output" |
    rg -F "Rembrane doctor: ready" >/dev/null
printf '%s\n' "$doctor_output" |
    rg -F "Authenticated encrypted records: 1" >/dev/null

first_recall=$(
    "$rembrane_binary" recall \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --client assistant_e2e \
        --purpose personalize-assistant \
        --query "What should I call the user?"
)
printf '%s\n' "$first_recall" | rg -F "$memory_id: Call me Hippo" >/dev/null

"$rembrane_binary" correct \
    --database "$database" \
    --principal principal_e2e \
    --workspace workspace_e2e \
    --memory "$memory_id" \
    --version 1 \
    --content "Call me Captain Hippo" >/dev/null

second_recall=$(
    "$rembrane_binary" recall \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --client assistant_e2e \
        --purpose personalize-assistant \
        --query "What should I call the user?"
)
printf '%s\n' "$second_recall" |
    rg -F "$memory_id: Call me Captain Hippo" >/dev/null

"$rembrane_binary" forget \
    --database "$database" \
    --principal principal_e2e \
    --workspace workspace_e2e \
    --memory "$memory_id" \
    --version 2 >/dev/null

final_recall=$(
    "$rembrane_binary" recall \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --client assistant_e2e \
        --purpose personalize-assistant \
        --query "What should I call the user?"
)
if printf '%s\n' "$final_recall" | rg -F "Captain Hippo" >/dev/null; then
    echo "deleted memory was disclosed" >&2
    exit 1
fi

event_count=$(
    sqlite3 "$database" \
        "SELECT count(*) FROM workspace_events WHERE workspace_id = 'workspace_e2e';"
)
disclosure_count=$(
    sqlite3 "$database" \
        "SELECT count(*) FROM disclosure_receipts WHERE workspace_id = 'workspace_e2e';"
)
plaintext_count=$(
    sqlite3 "$database" \
        "SELECT count(*) FROM memories WHERE instr(content_ciphertext, CAST('Hippo' AS BLOB)) > 0;"
)
test "$event_count" = "3"
test "$disclosure_count" = "3"
test "$plaintext_count" = "0"

if REMBRANE_WORKSPACE_KEY_HEX="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "$rembrane_binary" recall \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --client assistant_e2e \
        --purpose personalize-assistant \
        --query "What should I call the user?" >/dev/null 2>&1
then
    echo "recall unexpectedly succeeded with the wrong key" >&2
    exit 1
fi

if REMBRANE_WORKSPACE_KEY_HEX="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "$rembrane_binary" doctor \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e >/dev/null 2>&1
then
    echo "doctor unexpectedly succeeded with the wrong key" >&2
    exit 1
fi

echo "CLI end-to-end checks passed"

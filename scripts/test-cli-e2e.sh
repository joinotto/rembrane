#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
rembrane_binary=${REMBRANE_BIN:-"$repository_root/target/debug/rembrane"}
test -x "$rembrane_binary"

test_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-cli-e2e.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT
database="$test_directory/rembrane.sqlite"
backup="$test_directory/rembrane-backup.rembrane"
restored_database="$test_directory/rembrane-restored.sqlite"
invalid_export="$test_directory/rembrane-invalid.rembrane"
invalid_restore="$test_directory/rembrane-invalid.sqlite"
git_repository="$test_directory/project"

export REMBRANE_WORKSPACE_KEY_ID="e2e-key-v1"
export REMBRANE_WORKSPACE_KEY_HEX="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
export REMBRANE_READ_SCOPES="global,domain:development,entity:project_e2e"

"$rembrane_binary" init \
    --database "$database" \
    --principal principal_e2e \
    --workspace workspace_e2e >/dev/null

second_init=$(
    "$rembrane_binary" init \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e
)
printf '%s\n' "$second_init" |
    rg -F "Rembrane is already initialized" >/dev/null

remember_output=$(
    "$rembrane_binary" remember \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --content "Call me Hippo"
)
memory_id=$(printf '%s\n' "$remember_output" | awk '/^Remembered / { print $2 }')
test -n "$memory_id"

"$rembrane_binary" backup \
    --database "$database" \
    --principal principal_e2e \
    --workspace workspace_e2e \
    --output "$backup" >/dev/null

test "$(head -c 16 "$backup")" = "REMBRANE-EXPORT"

cp "$backup" "$invalid_export"
ruby -e '
  path = ARGV.fetch(0)
  data = File.binread(path)
  data[16, 4] = [2].pack("N")
  File.binwrite(path, data)
' "$invalid_export"
if "$rembrane_binary" restore \
    --input "$invalid_export" \
    --database "$invalid_restore" \
    --principal principal_e2e \
    --workspace workspace_e2e >/dev/null 2>&1
then
    echo "restore unexpectedly accepted an unknown export version" >&2
    exit 1
fi
test ! -e "$invalid_restore"

mkdir "$git_repository"
git -C "$git_repository" init --quiet
git -C "$git_repository" config user.name "Rembrane Test"
git -C "$git_repository" config user.email "rembrane@example.invalid"
printf 'initial\n' > "$git_repository/README.md"
git -C "$git_repository" add README.md
git -C "$git_repository" commit --quiet -m "initial"
clean_fingerprint=$(
    "$rembrane_binary" fingerprint-git --repository "$git_repository"
)
printf '%s\n' "$clean_fingerprint" | rg '^git:[0-9a-f]+:clean$' >/dev/null
printf 'changed\n' >> "$git_repository/README.md"
dirty_fingerprint=$(
    "$rembrane_binary" fingerprint-git --repository "$git_repository"
)
printf '%s\n' "$dirty_fingerprint" | rg '^git:[0-9a-f]+:dirty$' >/dev/null
test "$clean_fingerprint" != "$dirty_fingerprint"

codex_config=$(
    "$rembrane_binary" mcp-config \
        --client codex \
        --server-binary "$repository_root/target/debug/rembrane-mcp"
)
printf '%s\n' "$codex_config" |
    rg -F '[mcp_servers.rembrane]' >/dev/null
printf '%s\n' "$codex_config" |
    rg -F 'env_vars = [' >/dev/null
claude_config=$(
    "$rembrane_binary" mcp-config \
        --client claude-code \
        --server-binary "$repository_root/target/debug/rembrane-mcp"
)
printf '%s\n' "$claude_config" | jq -e \
    '.mcpServers.rembrane.env.REMBRANE_WORKSPACE_KEY_HEX
        == "${REMBRANE_WORKSPACE_KEY_HEX}"' >/dev/null

"$rembrane_binary" restore \
    --input "$backup" \
    --database "$restored_database" \
    --principal principal_e2e \
    --workspace workspace_e2e >/dev/null

restored_recall=$(
    "$rembrane_binary" recall \
        --database "$restored_database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --client assistant_e2e \
        --purpose restore-verification \
        --query "What should I call the user?"
)
printf '%s\n' "$restored_recall" |
    rg -F "$memory_id: Call me Hippo" >/dev/null

doctor_output=$(
    "$rembrane_binary" doctor \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --privacy
)
printf '%s\n' "$doctor_output" |
    rg -F "Rembrane doctor: ready" >/dev/null
printf '%s\n' "$doctor_output" |
    rg -F "Authenticated encrypted records: 1" >/dev/null
printf '%s\n' "$doctor_output" |
    rg -F "Processing location: local trusted boundary" >/dev/null
printf '%s\n' "$doctor_output" |
    rg -F "Outbound endpoints: none" >/dev/null
printf '%s\n' "$doctor_output" |
    rg -F \
        "Configured read scopes: global,domain:development,entity:project_e2e" \
        >/dev/null

project_remember_output=$(
    "$rembrane_binary" remember \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --entity project_e2e \
        --content "Use Rust for the Rembrane core"
)
project_memory_id=$(
    printf '%s\n' "$project_remember_output" |
        awk '/^Remembered / { print $2 }'
)
test -n "$project_memory_id"

project_recall=$(
    "$rembrane_binary" recall \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --client coding_agent_e2e \
        --entity project_e2e \
        --purpose continue-project \
        --query "Which language should power the Rembrane core?"
)
printf '%s\n' "$project_recall" |
    rg -F "$project_memory_id: Use Rust for the Rembrane core" >/dev/null

layered_identity_recall=$(
    "$rembrane_binary" recall \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --client coding_agent_e2e \
        --domain development \
        --entity project_e2e \
        --activity implementation_e2e \
        --purpose personalize-project-assistant \
        --query "What should I call the user?"
)
printf '%s\n' "$layered_identity_recall" |
    rg -F "$memory_id: Call me Hippo" >/dev/null

"$rembrane_binary" correct \
    --database "$database" \
    --principal principal_e2e \
    --workspace workspace_e2e \
    --entity project_e2e \
    --memory "$project_memory_id" \
    --version 1 \
    --content "Use Rust and SQLite for the Rembrane core" >/dev/null

corrected_project_recall=$(
    "$rembrane_binary" recall \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --client coding_agent_e2e \
        --entity project_e2e \
        --purpose continue-project \
        --query "Which technology should power the Rembrane core?"
)
printf '%s\n' "$corrected_project_recall" |
    rg -F "$project_memory_id: Use Rust and SQLite for the Rembrane core" \
        >/dev/null

"$rembrane_binary" forget \
    --database "$database" \
    --principal principal_e2e \
    --workspace workspace_e2e \
    --entity project_e2e \
    --memory "$project_memory_id" \
    --version 2 >/dev/null

deleted_project_recall=$(
    "$rembrane_binary" recall \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --client coding_agent_e2e \
        --entity project_e2e \
        --purpose continue-project \
        --query "Which technology should power the Rembrane core?"
)
if printf '%s\n' "$deleted_project_recall" |
    rg -F "Rust and SQLite" >/dev/null
then
    echo "deleted project memory was disclosed" >&2
    exit 1
fi

travel_preference_output=$(
    "$rembrane_binary" remember \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --domain travel \
        --content "Prefer nonstop flights"
)
travel_preference_id=$(
    printf '%s\n' "$travel_preference_output" |
        awk '/^Remembered / { print $2 }'
)
trip_constraint_output=$(
    "$rembrane_binary" remember \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --entity trip_berlin_e2e \
        --content "Berlin trip budget is 2000 EUR"
)
trip_constraint_id=$(
    printf '%s\n' "$trip_constraint_output" |
        awk '/^Remembered / { print $2 }'
)
test -n "$travel_preference_id"
test -n "$trip_constraint_id"

travel_recall=$(
    "$rembrane_binary" recall \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --client travel_assistant_e2e \
        --domain travel \
        --entity trip_berlin_e2e \
        --purpose continue-trip-planning \
        --query "Do I prefer nonstop flights and what is the trip budget?"
)
printf '%s\n' "$travel_recall" |
    rg -F "$travel_preference_id: Prefer nonstop flights" >/dev/null
printf '%s\n' "$travel_recall" |
    rg -F "$trip_constraint_id: Berlin trip budget is 2000 EUR" >/dev/null

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
test "$event_count" = "8"
test "$disclosure_count" = "8"
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

invalid_restore="$test_directory/invalid-restore.sqlite"
if REMBRANE_WORKSPACE_KEY_HEX="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
    "$rembrane_binary" restore \
        --input "$backup" \
        --database "$invalid_restore" \
        --principal principal_e2e \
        --workspace workspace_e2e >/dev/null 2>&1
then
    echo "restore unexpectedly succeeded with the wrong key" >&2
    exit 1
fi
test ! -e "$invalid_restore"

echo "CLI end-to-end checks passed"

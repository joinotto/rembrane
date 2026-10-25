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
printf '%s\n' "$codex_config" |
    rg -F 'REMBRANE_WORKSPACE_KEY_REFERENCE' >/dev/null
if printf '%s\n' "$codex_config" | rg -F 'REMBRANE_WORKSPACE_KEY_HEX' >/dev/null
then
    echo "Codex config unexpectedly requested a raw workspace key" >&2
    exit 1
fi
claude_config=$(
    "$rembrane_binary" mcp-config \
        --client claude-code \
        --server-binary "$repository_root/target/debug/rembrane-mcp"
)
printf '%s\n' "$claude_config" | jq -e \
    '.mcpServers.rembrane.env.REMBRANE_WORKSPACE_KEY_REFERENCE
        == "${REMBRANE_WORKSPACE_KEY_REFERENCE}"
        and (.mcpServers.rembrane.env | has("REMBRANE_WORKSPACE_KEY_HEX") | not)' \
    >/dev/null
gemini_config=$(
    "$rembrane_binary" mcp-config \
        --client gemini-cli \
        --server-binary "$repository_root/target/debug/rembrane-mcp"
)
printf '%s\n' "$gemini_config" | jq -e \
    '.mcpServers.rembrane.command
        and .mcpServers.rembrane.args == []
        and .mcpServers.rembrane.env.REMBRANE_WORKSPACE_KEY_REFERENCE
            == "${REMBRANE_WORKSPACE_KEY_REFERENCE}"
        and (.mcpServers.rembrane.env | has("REMBRANE_WORKSPACE_KEY_HEX") | not)' \
    >/dev/null
zed_config=$(
    "$rembrane_binary" mcp-config \
        --client zed \
        --server-binary "$repository_root/target/debug/rembrane-mcp"
)
printf '%s\n' "$zed_config" | jq -e \
    '.context_servers.rembrane.command
        and .context_servers.rembrane.args == []
        and .context_servers.rembrane.env == {}' \
    >/dev/null
if printf '%s\n' "$zed_config" | rg -F '${' >/dev/null
then
    echo "Zed config unexpectedly relies on unsupported environment interpolation" >&2
    exit 1
fi
cursor_config=$(
    "$rembrane_binary" mcp-config \
        --client cursor \
        --server-binary "$repository_root/target/debug/rembrane-mcp"
)
printf '%s\n' "$cursor_config" | jq -e \
    '.mcpServers.rembrane.type == "stdio"
        and .mcpServers.rembrane.args == []
        and .mcpServers.rembrane.env.REMBRANE_WORKSPACE_KEY_REFERENCE
            == "${env:REMBRANE_WORKSPACE_KEY_REFERENCE}"
        and (.mcpServers.rembrane.env | has("REMBRANE_WORKSPACE_KEY_HEX") | not)' \
    >/dev/null
vscode_config=$(
    "$rembrane_binary" mcp-config \
        --client vscode \
        --server-binary "$repository_root/target/debug/rembrane-mcp"
)
printf '%s\n' "$vscode_config" | jq -e \
    '.servers.rembrane.type == "stdio"
        and .servers.rembrane.args == []
        and .servers.rembrane.env.REMBRANE_WORKSPACE_KEY_REFERENCE
            == "${env:REMBRANE_WORKSPACE_KEY_REFERENCE}"
        and (.servers.rembrane.env | has("REMBRANE_WORKSPACE_KEY_HEX") | not)' \
    >/dev/null
opencode_config=$(
    "$rembrane_binary" mcp-config \
        --client opencode \
        --server-binary "$repository_root/target/debug/rembrane-mcp"
)
printf '%s\n' "$opencode_config" | jq -e \
    '.mcp.rembrane.type == "local"
        and .mcp.rembrane.enabled == true
        and .mcp.rembrane.command
            == ["'"$repository_root"'/target/debug/rembrane-mcp"]
        and .mcp.rembrane.environment.REMBRANE_WORKSPACE_KEY_REFERENCE
            == "{env:REMBRANE_WORKSPACE_KEY_REFERENCE}"
        and (.mcp.rembrane.environment | has("REMBRANE_WORKSPACE_KEY_HEX") | not)' \
    >/dev/null
generic_config=$(
    "$rembrane_binary" mcp-config \
        --client generic \
        --server-binary "$repository_root/target/debug/rembrane-mcp"
)
printf '%s\n' "$generic_config" | jq -e \
    '.schemaVersion == 1
        and .transport == "stdio"
        and (.requiredEnvironment | index("REMBRANE_WORKSPACE_KEY_REFERENCE"))
        and (.requiredEnvironment | index("REMBRANE_WORKSPACE_KEY_HEX") | not)' \
    >/dev/null

provider_registry=$("$rembrane_binary" providers list)
printf '%s\n' "$provider_registry" | jq -e \
    '.schemaVersion == 1
        and (.providers | length >= 1)
        and ([.providers[].id] | index("rembrane.native"))
        and all(.providers[]; has("plaintextProcessing"))
        and all(.providers[]; has("conformance"))' >/dev/null

native_provider_version=$(
    printf '%s\n' "$provider_registry" |
        jq -er '.providers[] | select(.id == "rembrane.native") | .adapterVersion'
)
provider_selection=$(
    "$rembrane_binary" providers check \
        --provider rembrane.native \
        --adapter-version "$native_provider_version" \
        --allow-experimental \
        --allow-provider-plaintext
)
printf '%s\n' "$provider_selection" | jq -e \
    '.schemaVersion == 1
        and (.registryGeneratedAt | fromdateiso8601) <= now
        and (.registrySha256 | test("^[0-9a-f]{64}$"))
        and .registryTrust.mode == "embedded"
        and .provider == "rembrane.native"
        and .eligibility == "experimental-opt-in"
        and .protocolVersion == "0.1"
        and .approvals.experimental == true
        and .approvals.providerPlaintext == true
        and (.evidence.profileSha256 | test("^[0-9a-f]{64}$"))
        and (.evidence.sourceRevision | test("^[0-9a-f]{7,64}$"))' >/dev/null
if "$rembrane_binary" providers check \
    --provider rembrane.native \
    --adapter-version "$native_provider_version" >/dev/null 2>&1
then
    echo "provider selection accepted experimental status without opt-in" >&2
    exit 1
fi
if "$rembrane_binary" providers check \
    --provider rembrane.native \
    --adapter-version "$native_provider_version" \
    --allow-experimental >/dev/null 2>&1
then
    echo "provider selection accepted plaintext processing without opt-in" >&2
    exit 1
fi

openssl genpkey -algorithm Ed25519 \
    -out "$test_directory/registry-private.pem" >/dev/null 2>&1
openssl pkey -in "$test_directory/registry-private.pem" -pubout \
    -out "$test_directory/registry-public.pem" >/dev/null 2>&1
cp "$repository_root/spec/provider-registry.json" "$test_directory/provider-registry.json"
openssl pkeyutl -sign -rawin \
    -inkey "$test_directory/registry-private.pem" \
    -in "$test_directory/provider-registry.json" \
    -out "$test_directory/provider-registry.sig"
external_selection=$(
    "$rembrane_binary" providers check \
        --provider rembrane.native \
        --adapter-version "$native_provider_version" \
        --allow-experimental \
        --allow-provider-plaintext \
        --registry "$test_directory/provider-registry.json" \
        --signature "$test_directory/provider-registry.sig" \
        --public-key "$test_directory/registry-public.pem"
)
printf '%s\n' "$external_selection" | jq -e \
    '.registrySha256 != null
        and .registryTrust.mode == "ed25519"
        and (.registryTrust.publicKeySha256 | test("^[0-9a-f]{64}$"))
        and .provider == "rembrane.native"' >/dev/null
printf '\n' >>"$test_directory/provider-registry.json"
if "$rembrane_binary" providers check \
    --provider rembrane.native \
    --adapter-version "$native_provider_version" \
    --allow-experimental \
    --allow-provider-plaintext \
    --registry "$test_directory/provider-registry.json" \
    --signature "$test_directory/provider-registry.sig" \
    --public-key "$test_directory/registry-public.pem" >/dev/null 2>&1
then
    echo "provider selection accepted a tampered signed registry" >&2
    exit 1
fi

provider_conformance=$(
    "$rembrane_binary" providers test \
        --provider rembrane.native \
        --namespace cli-e2e
)
printf '%s\n' "$provider_conformance" | jq -e \
    '.provider == "rembrane.native"
        and (.profileSha256 | test("^[0-9a-f]{64}$"))
        and .protocolVersion == "0.1"
        and .result == "pass"' >/dev/null
if "$rembrane_binary" providers test \
    --provider community.not-installed \
    --namespace cli-e2e >/dev/null 2>&1
then
    echo "provider test unexpectedly accepted an unavailable adapter" >&2
    exit 1
fi

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

if MEM0_BASE_URL="https://operator:secret@memory.example/v1?token=hidden" \
    "$rembrane_binary" doctor \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --privacy >/dev/null 2>&1
then
    echo "privacy diagnostics accepted credentials in a provider endpoint" >&2
    exit 1
fi
doctor_output=$(
    MEM0_BASE_URL="https://memory.example/v1" \
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
    rg -F -- "- MEM0_BASE_URL: https://memory.example" >/dev/null
if printf '%s\n' "$doctor_output" | rg -F "secret" >/dev/null; then
    echo "privacy diagnostics disclosed endpoint credentials" >&2
    exit 1
fi
if MEM0_BASE_URL="http://memory.example" \
    "$rembrane_binary" doctor \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --privacy >/dev/null 2>&1
then
    echo "privacy diagnostics accepted insecure Mem0 endpoint" >&2
    exit 1
fi
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

trace_output=$(
    "$rembrane_binary" trace \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --activity activity_cli_e2e \
        --entity project_e2e \
        --summary "Completed the CLI memory lifecycle."
)
trace_id=$(printf '%s\n' "$trace_output" | awk '/^Proposed / { print $2 }')
test -n "$trace_id"

"$rembrane_binary" checkpoint \
    --database "$database" \
    --principal principal_e2e \
    --workspace workspace_e2e \
    --activity activity_cli_e2e \
    --goal "Ship CLI handoffs" \
    --summary "Checkpoint creation works." \
    --next-steps "Resume in another tool,Run full tests" \
    --state-fingerprint "git:cli123" >/dev/null

first_resume=$(
    "$rembrane_binary" resume \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --activity activity_cli_e2e \
        --client assistant_cli_e2e \
        --state-fingerprint "git:cli123"
)
printf '%s\n' "$first_resume" | jq -e \
    '.version == 1
        and .summary == "Checkpoint creation works."
        and .nextSteps == ["Resume in another tool", "Run full tests"]
        and .stale == false
        and .disclosureId' >/dev/null

"$rembrane_binary" checkpoint \
    --database "$database" \
    --principal principal_e2e \
    --workspace workspace_e2e \
    --activity activity_cli_e2e \
    --version 1 \
    --summary "Checkpoint update works." \
    --next-steps "Resume from the latest state" \
    --state-fingerprint "git:cli456" >/dev/null

second_resume=$(
    "$rembrane_binary" resume \
        --database "$database" \
        --principal principal_e2e \
        --workspace workspace_e2e \
        --activity activity_cli_e2e \
        --client assistant_cli_e2e \
        --purpose continue-development \
        --state-fingerprint "git:cli123"
)
printf '%s\n' "$second_resume" | jq -e \
    '.version == 2
        and .summary == "Checkpoint update works."
        and .stale == true
        and .disclosureId' >/dev/null

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
checkpoint_disclosure_count=$(
    sqlite3 "$database" \
        "SELECT count(*) FROM checkpoint_disclosures WHERE workspace_id = 'workspace_e2e' AND activity_id = 'activity_cli_e2e';"
)
trace_count=$(
    sqlite3 "$database" \
        "SELECT count(*) FROM memories WHERE workspace_id = 'workspace_e2e' AND id = '$trace_id' AND kind = 'observation' AND status = 'proposed' AND scope_type = 'activity' AND scope_value = 'activity_cli_e2e';"
)
test "$event_count" = "11"
test "$disclosure_count" = "8"
test "$checkpoint_disclosure_count" = "2"
test "$trace_count" = "1"
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

if sqlite3 "$database" \
    "UPDATE workspace_events SET payload_ciphertext = X'00' WHERE workspace_id = 'workspace_e2e' AND sequence = 1;" \
    >/dev/null 2>&1
then
    echo "workspace event immutability trigger accepted an update" >&2
    exit 1
fi
sqlite3 "$database" "DROP TRIGGER workspace_events_are_immutable;"
sqlite3 "$database" \
    "UPDATE workspace_events SET payload_ciphertext = X'00' WHERE workspace_id = 'workspace_e2e' AND sequence = 1;"
if "$rembrane_binary" doctor \
    --database "$database" \
    --principal principal_e2e \
    --workspace workspace_e2e >/dev/null 2>&1
then
    echo "doctor unexpectedly accepted a tampered event" >&2
    exit 1
fi

echo "CLI end-to-end checks passed"

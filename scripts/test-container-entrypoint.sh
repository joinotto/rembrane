#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

invocation_log="$temporary_directory/invocations"
secret_source="$temporary_directory/source-secrets"
secret_runtime="$temporary_directory/runtime-secrets"
mkdir -p "$secret_source"
printf '%s\n' 'staged-secret-value' >"$secret_source/test_secret"
chmod 644 "$secret_source/test_secret"

cat >"$temporary_directory/chown" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$temporary_directory/gosu" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"$REMBRANE_ENTRYPOINT_TEST_LOG"
EOF
chmod 700 "$temporary_directory/chown" "$temporary_directory/gosu"

PATH="$temporary_directory:$PATH" \
REMBRANE_ENTRYPOINT_TEST_LOG="$invocation_log" \
REMBRANE_DATABASE="$temporary_directory/skip/rembrane.db" \
REMBRANE_SKIP_WORKSPACE_INIT=1 \
REMBRANE_SECRET_SOURCE_DIRECTORY="$secret_source" \
REMBRANE_SECRET_RUNTIME_DIRECTORY="$secret_runtime" \
    sh "$repository_root/docker/entrypoint.sh" test-command

test "$(wc -l <"$invocation_log" | tr -d ' ')" -eq 1
test "$(sed -n '1p' "$invocation_log")" = "rembrane test-command"
test "$(sed -n '1p' "$secret_runtime/test_secret")" = "staged-secret-value"
test "$(stat -f '%Lp' "$secret_runtime/test_secret" 2>/dev/null || stat -c '%a' "$secret_runtime/test_secret")" = "400"

: >"$invocation_log"
PATH="$temporary_directory:$PATH" \
REMBRANE_ENTRYPOINT_TEST_LOG="$invocation_log" \
REMBRANE_DATABASE="$temporary_directory/init/rembrane.db" \
REMBRANE_PRINCIPAL_ID=principal_entrypoint_test \
REMBRANE_WORKSPACE_ID=workspace_entrypoint_test \
REMBRANE_SECRET_SOURCE_DIRECTORY="$temporary_directory/no-secrets" \
REMBRANE_SECRET_RUNTIME_DIRECTORY="$temporary_directory/no-runtime-secrets" \
    sh "$repository_root/docker/entrypoint.sh" test-command

test "$(wc -l <"$invocation_log" | tr -d ' ')" -eq 2
test "$(sed -n '1p' "$invocation_log")" = \
    "rembrane rembrane init --database $temporary_directory/init/rembrane.db --principal principal_entrypoint_test --workspace workspace_entrypoint_test"
test "$(sed -n '2p' "$invocation_log")" = "rembrane test-command"

: >"$invocation_log"
rm -rf "$secret_runtime"
PATH="$temporary_directory:$PATH" \
REMBRANE_ENTRYPOINT_TEST_LOG="$invocation_log" \
REMBRANE_SECRET_STAGER="$repository_root/docker/rembrane-stage-secrets" \
REMBRANE_SECRET_SOURCE_DIRECTORY="$secret_source" \
REMBRANE_SECRET_RUNTIME_DIRECTORY="$secret_runtime" \
    sh "$repository_root/sidecars/rembrane-graphiti/docker/entrypoint.sh" test-command

test "$(sed -n '1p' "$invocation_log")" = "rembrane-graphiti test-command"
test "$(sed -n '1p' "$secret_runtime/test_secret")" = "staged-secret-value"
test "$(stat -f '%Lp' "$secret_runtime/test_secret" 2>/dev/null || stat -c '%a' "$secret_runtime/test_secret")" = "400"

ln -s "$secret_source/test_secret" "$secret_source/linked_secret"
if PATH="$temporary_directory:$PATH" \
    REMBRANE_SECRET_SOURCE_DIRECTORY="$secret_source" \
    REMBRANE_SECRET_RUNTIME_DIRECTORY="$temporary_directory/rejected-secrets" \
        "$repository_root/docker/rembrane-stage-secrets" rembrane 2>/dev/null; then
    echo "secret stager accepted a symbolic link" >&2
    exit 1
fi
rm "$secret_source/linked_secret"

if PATH="$temporary_directory:$PATH" \
    REMBRANE_ENTRYPOINT_TEST_LOG="$invocation_log" \
    REMBRANE_DATABASE="$temporary_directory/invalid/rembrane.db" \
    REMBRANE_SKIP_WORKSPACE_INIT=yes \
    REMBRANE_SECRET_SOURCE_DIRECTORY="$temporary_directory/no-secrets" \
    REMBRANE_SECRET_RUNTIME_DIRECTORY="$temporary_directory/no-runtime-secrets" \
        sh "$repository_root/docker/entrypoint.sh" test-command 2>/dev/null; then
    echo "entrypoint accepted an invalid skip-workspace-init value" >&2
    exit 1
fi

echo "container entrypoint checks passed"

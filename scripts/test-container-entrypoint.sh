#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

invocation_log="$temporary_directory/invocations"

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
    sh "$repository_root/docker/entrypoint.sh" test-command

test "$(wc -l <"$invocation_log" | tr -d ' ')" -eq 1
test "$(sed -n '1p' "$invocation_log")" = "rembrane test-command"

: >"$invocation_log"
PATH="$temporary_directory:$PATH" \
REMBRANE_ENTRYPOINT_TEST_LOG="$invocation_log" \
REMBRANE_DATABASE="$temporary_directory/init/rembrane.db" \
REMBRANE_PRINCIPAL_ID=principal_entrypoint_test \
REMBRANE_WORKSPACE_ID=workspace_entrypoint_test \
    sh "$repository_root/docker/entrypoint.sh" test-command

test "$(wc -l <"$invocation_log" | tr -d ' ')" -eq 2
test "$(sed -n '1p' "$invocation_log")" = \
    "rembrane rembrane init --database $temporary_directory/init/rembrane.db --principal principal_entrypoint_test --workspace workspace_entrypoint_test"
test "$(sed -n '2p' "$invocation_log")" = "rembrane test-command"

if PATH="$temporary_directory:$PATH" \
    REMBRANE_ENTRYPOINT_TEST_LOG="$invocation_log" \
    REMBRANE_DATABASE="$temporary_directory/invalid/rembrane.db" \
    REMBRANE_SKIP_WORKSPACE_INIT=yes \
        sh "$repository_root/docker/entrypoint.sh" test-command 2>/dev/null; then
    echo "entrypoint accepted an invalid skip-workspace-init value" >&2
    exit 1
fi

echo "container entrypoint checks passed"

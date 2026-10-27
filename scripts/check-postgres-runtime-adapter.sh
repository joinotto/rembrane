#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

mode=${1:---build}
if [ "$#" -gt 1 ] || { [ "$mode" != "--build" ] && [ "$mode" != "--live" ]; }; then
    echo "usage: check-postgres-runtime-adapter.sh [--build|--live]" >&2
    exit 2
fi
for command in cargo jq; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "PostgreSQL runtime checker requires $command" >&2
        exit 1
    }
done

# Inspect resolved Cargo data, not source/manifest regexes that accept comments,
# dev-only dependencies, disabled features, or arbitrary struct declarations.
metadata=$(cargo metadata --locked --offline --format-version 1 2>/dev/null) || {
    echo "PostgreSQL runtime dependency metadata is unavailable" >&2
    exit 1
}
printf '%s\n' "$metadata" | jq -e '
    . as $metadata
    | [.packages[] | select(.name == "rembrane-store-postgres")] as $adapters
    | ($adapters | length == 1)
      and any(
        $metadata.resolve.nodes[] | select(.id == $adapters[0].id) | .deps[];
        . as $dependency
        | any(.dep_kinds[]; .kind == null and .target == null)
          and any(
            $metadata.packages[];
            .id == $dependency.pkg
            and (.name == "postgres" or .name == "tokio-postgres"
                 or .name == "sqlx" or .name == "diesel")
          )
      )
' >/dev/null 2>&1 || {
    echo "PostgreSQL adapter has no resolved normal runtime database driver" >&2
    exit 1
}

printf '%s\n' "$metadata" | jq -e '
    . as $metadata
    | [.packages[] | select(.name == "rembrane-store-postgres")] as $adapters
    | [
        $metadata.resolve.nodes[]
        | select(.id == $adapters[0].id)
        | .features[]
    ] as $features
    | [
        $adapters[0].targets[]
        | select(
            .name == "postgres_runtime"
            and .kind == ["test"]
            and all(
                (."required-features" // [])[];
                . as $required | ($features | index($required)) != null
            )
        )
    ] | length == 1
' >/dev/null 2>&1 || {
    echo "PostgreSQL adapter has no default-enabled runtime integration target" >&2
    exit 1
}
unset metadata

cargo check --package rembrane-store-postgres --test postgres_runtime --locked --offline \
    >/dev/null 2>&1 || {
    echo "PostgreSQL runtime integration does not compile from the lockfile" >&2
    exit 1
}
if [ "$mode" = "--build" ]; then
    echo "PostgreSQL runtime integration target compiles; live verification is still required"
    exit 0
fi

# The SQL fixtures and live driver suite may mutate only explicitly authorized
# disposable data. Runtime connections must use a distinct restricted login;
# the live suite must verify actual server authority, not trust configuration.
if [ "${REMBRANE_POSTGRES_TEST_CONFIRM:-}" != "disposable-empty-database" ]; then
    echo "Live PostgreSQL runtime tests require disposable database authorization" >&2
    exit 2
fi
test_database=${REMBRANE_POSTGRES_TEST_DATABASE:-}
case "$test_database" in
    rembrane_test_*) ;;
    *) echo "Live PostgreSQL runtime tests require a dedicated test database" >&2; exit 2 ;;
esac
test_suffix=${test_database#rembrane_test_}
case "$test_suffix" in
    ""|*[!a-z0-9_]*) echo "Invalid PostgreSQL runtime test database name" >&2; exit 2 ;;
esac
if [ "${#test_database}" -gt 63 ]; then
    echo "Invalid PostgreSQL runtime test database name" >&2
    exit 2
fi
command -v node >/dev/null 2>&1 || {
    echo "PostgreSQL runtime checker requires node" >&2
    exit 1
}
admin_profile=${REMBRANE_POSTGRES_TEST_SERVICE_FILE:-}
runtime_profile=${REMBRANE_POSTGRES_RUNTIME_URL_FILE:-}
if [ -z "$admin_profile" ] || [ -z "$runtime_profile" ] \
    || [ "$admin_profile" = "$runtime_profile" ]; then
    echo "Live PostgreSQL tests require separate private administrator and runtime configuration" >&2
    exit 2
fi
node scripts/check-postgres-fixture-service.mjs "$admin_profile" || exit 2
node scripts/check-postgres-fixture-service.mjs "$runtime_profile" runtime-url || exit 2

# Capture diagnostics privately: panic/driver messages can contain credentials,
# parameter values, or tenant data. A zero exit status alone is not proof that
# an exact test ran: filtered-out and ignored tests must fail this gate.
umask 077
test_output=$(mktemp "${TMPDIR:-/tmp}/rembrane-postgres-runtime.XXXXXX")
trap 'rm -f "$test_output"' EXIT HUP INT TERM
for test_name in \
    runtime_pool_two_tenant_lifecycle \
    runtime_pool_connection_reset_after_rollback_and_error \
    runtime_pool_rejects_unsafe_authority \
    runtime_pool_atomicity_and_cancellation \
    runtime_pool_redacts_driver_errors
do
    if ! cargo test --package rembrane-store-postgres --test postgres_runtime \
        --locked --offline --color never -- "$test_name" --exact --include-ignored \
        --nocapture --color never \
        >"$test_output" 2>&1; then
        echo "PostgreSQL live runtime test failed: $test_name" >&2
        exit 1
    fi
    # Stable libtest summary, independent of arbitrary test-body output.
    # Keep this as the final nonempty line: an earlier printed fake summary
    # must not hide a later zero-test/ignored/failing summary.
    test_summary=$(LC_ALL=C awk 'NF { last = $0 } END { print last }' "$test_output")
    # Elapsed time and the other filtered tests vary; execution counts do not.
    printf '%s\n' "$test_summary" | LC_ALL=C \
        grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9]+\.[0-9]+s$' || {
            echo "PostgreSQL live runtime test did not execute exactly once: $test_name" >&2
            exit 1
        }
done

echo "PostgreSQL live runtime integration checks passed"

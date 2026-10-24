#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

python_runtime=
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 &&
        "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'
    then
        python_runtime=$candidate
        break
    fi
done
if test -z "$python_runtime"; then
    echo "Python 3.11 or newer is required for the Graphiti HTTP test" >&2
    exit 1
fi
"$python_runtime" -c 'import fastapi, uvicorn' >/dev/null 2>&1 || {
    echo "install sidecars/rembrane-graphiti[dev] before running this test" >&2
    exit 1
}

test_port=${REMBRANE_GRAPHITI_TEST_PORT:-18793}
test_token=${REMBRANE_GRAPHITI_TEST_TOKEN:-graphiti-test-token-00000001}
test_base_url="http://127.0.0.1:$test_port"

REMBRANE_GRAPHITI_ENABLE_IN_MEMORY_TEST_SERVER=1 \
REMBRANE_GRAPHITI_BEARER_TOKEN="$test_token" \
REMBRANE_GRAPHITI_PORT="$test_port" \
PYTHONPATH="$repository_root/sidecars/rembrane-graphiti/src" \
    "$python_runtime" -m rembrane_graphiti.testing &
sidecar_pid=$!
trap 'kill "$sidecar_pid" >/dev/null 2>&1 || true; wait "$sidecar_pid" >/dev/null 2>&1 || true' EXIT

attempt=0
until curl --fail --silent --show-error "$test_base_url/healthz" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if test "$attempt" -ge 30 || ! kill -0 "$sidecar_pid" >/dev/null 2>&1; then
        echo "Graphiti test sidecar did not become ready" >&2
        exit 1
    fi
    sleep 1
done

REMBRANE_RUN_GRAPHITI_SIDECAR_TESTS=1 \
REMBRANE_GRAPHITI_TEST_BASE_URL="$test_base_url" \
REMBRANE_GRAPHITI_TEST_TOKEN="$test_token" \
    cargo test --package rembrane-graph-graphiti-http --test live_sidecar

echo "Graphiti HTTP boundary checks passed"

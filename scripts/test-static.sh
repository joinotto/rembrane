#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "required static-test command is unavailable: $1" >&2
        exit 1
    fi
}

for command in git jq node rg ruby sqlite3; do
    require_command "$command"
done
python_command=python3
if command -v python3.11 >/dev/null 2>&1; then
    python_command=python3.11
fi
require_command "$python_command"

./scripts/check-architecture.sh
./scripts/check-sensitive-files.sh
./scripts/check-protocols.sh
./scripts/test-sqlite-schema.sh
./scripts/test-sqlite-atomicity.sh
node sdks/typescript/test.mjs
node --check sdks/typescript/index.js
PYTHONPATH=sdks/python "$python_command" -m unittest sdks/python/test_rembrane.py
"$python_command" -m py_compile sdks/python/rembrane.py sdks/python/test_rembrane.py
if command -v swiftc >/dev/null 2>&1; then
    ./scripts/test-swift-sdk.sh
fi
./scripts/test-kotlin-sdk.sh

for deployment_file in \
    Dockerfile \
    compose.yaml \
    compose.cloudflare.yaml \
    compose.graphiti.yaml \
    docs/CLOUDFLARE_DEPLOYMENT.md \
    docs/GRAPHITI_SIDECAR.md \
    docker/entrypoint.sh \
    scripts/check-local-alpha.sh \
    scripts/test-graphiti-http-e2e.sh \
    scripts/test-graphiti-sidecar.sh \
    scripts/test-swift-sdk.sh \
    scripts/test-kotlin-sdk.sh \
    scripts/test-core-offline.sh
do
    test -s "$deployment_file" || {
        echo "missing deployment artifact: $deployment_file" >&2
        exit 1
    }
done
sh -n scripts/check-local-alpha.sh
sh -n scripts/test-graphiti-http-e2e.sh
sh -n scripts/test-graphiti-sidecar.sh
sh -n scripts/test-swift-sdk.sh
sh -n scripts/test-kotlin-sdk.sh
sh -n scripts/test-core-offline.sh
rg -q '127\.0\.0\.1:8787:8787' compose.yaml
rg -q 'no-new-privileges:true' compose.yaml
rg -q 'cap_drop:' compose.yaml
rg -q 'CLOUDFLARE_TUNNEL_TOKEN' compose.cloudflare.yaml
rg -q 'http://rembrane:8787' docs/CLOUDFLARE_DEPLOYMENT.md
rg -q 'read_only: true' compose.cloudflare.yaml
rg -q '127\.0\.0\.1:8793:8793' compose.graphiti.yaml
rg -q 'REMBRANE_GRAPHITI_BEARER_TOKEN' compose.graphiti.yaml
rg -q 'rembrane-graph-worker' compose.graphiti.yaml
rg -q 'REMBRANE_GRAPH_PROVIDER_ALLOW_PLAINTEXT: "true"' compose.graphiti.yaml
rg -q 'no-new-privileges:true' compose.graphiti.yaml
rg -q -- '--package rembrane-graph-worker' Dockerfile
rg -q 'USER 10002:10002' sidecars/rembrane-graphiti/Dockerfile
if command -v docker >/dev/null 2>&1; then
    REMBRANE_PRINCIPAL_ID=principal_static \
    REMBRANE_WORKSPACE_ID=workspace_static \
    REMBRANE_CLIENT_ID=client_static \
    REMBRANE_WORKSPACE_KEY_ID=key_static \
    REMBRANE_WORKSPACE_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000000 \
    REMBRANE_API_TOKEN=token_static \
        docker compose config --quiet
    CLOUDFLARE_TUNNEL_TOKEN=static-test-token \
    CLOUDFLARED_IMAGE=cloudflare/cloudflared:latest \
    REMBRANE_PRINCIPAL_ID=principal_static \
    REMBRANE_WORKSPACE_ID=workspace_static \
    REMBRANE_CLIENT_ID=client_static \
    REMBRANE_WORKSPACE_KEY_ID=key_static \
    REMBRANE_WORKSPACE_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000000 \
    REMBRANE_API_TOKEN=token_static \
        docker compose -f compose.yaml -f compose.cloudflare.yaml config --quiet
    REMBRANE_PRINCIPAL_ID=principal_static \
    REMBRANE_WORKSPACE_ID=workspace_static \
    REMBRANE_CLIENT_ID=client_static \
    REMBRANE_WORKSPACE_KEY_ID=key_static \
    REMBRANE_WORKSPACE_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000000 \
    REMBRANE_API_TOKEN=token_static \
    REMBRANE_GRAPHITI_BEARER_TOKEN=graphiti-static-token \
    REMBRANE_GRAPHITI_NEO4J_PASSWORD=graphiti-static-password \
    REMBRANE_GRAPHITI_OPENAI_API_KEY=graphiti-static-model-key \
        docker compose -f compose.yaml -f compose.graphiti.yaml config --quiet
fi

echo "all static Rembrane checks passed"

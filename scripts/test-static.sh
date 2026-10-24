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
./scripts/check-ci-security.sh
./scripts/check-protocols.sh
./scripts/check-postgres-rls.sh
./scripts/verify-provider-registry.sh
./scripts/test-provider-registry-signing.sh
./scripts/test-sqlite-schema.sh
./scripts/test-sqlite-atomicity.sh
node sdks/typescript/test.mjs
node --check sdks/typescript/index.js
PYTHONPATH=sdks/python "$python_command" -m unittest sdks/python/test_rembrane.py
"$python_command" -m py_compile sdks/python/rembrane.py sdks/python/test_rembrane.py
if command -v swiftc >/dev/null 2>&1; then
    ./scripts/test-swift-sdk.sh
fi
if command -v xcrun >/dev/null 2>&1 \
    && xcrun --sdk iphonesimulator --show-sdk-path >/dev/null 2>&1; then
    ./scripts/test-ios-share-extension.sh
    ./scripts/test-ios-imessage-extension.sh
fi
./scripts/test-kotlin-sdk.sh

for deployment_file in \
    Dockerfile \
    compose.yaml \
    compose.cloudflare.yaml \
    compose.graphiti.yaml \
    compose.whatsapp.yaml \
    docs/CLOUDFLARE_DEPLOYMENT.md \
    docs/GRAPHITI_SIDECAR.md \
    docker/entrypoint.sh \
    scripts/check-local-alpha.sh \
    scripts/test-graphiti-http-e2e.sh \
    scripts/test-graphiti-sidecar.sh \
    scripts/test-swift-sdk.sh \
    scripts/test-ios-share-extension.sh \
    scripts/test-ios-imessage-extension.sh \
    scripts/test-kotlin-sdk.sh \
    scripts/check-postgres-rls.sh \
    scripts/check-ci-security.sh \
    scripts/test-postgres-rls.sh \
    scripts/check-production-readiness.sh \
    scripts/verify-provider-registry.sh \
    scripts/sign-provider-registry.sh \
    scripts/verify-provider-registry-signature.sh \
    scripts/test-provider-registry-signing.sh \
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
sh -n scripts/test-ios-share-extension.sh
sh -n scripts/test-ios-imessage-extension.sh
sh -n scripts/test-kotlin-sdk.sh
sh -n scripts/check-postgres-rls.sh
sh -n scripts/check-ci-security.sh
sh -n scripts/test-postgres-rls.sh
sh -n scripts/check-production-readiness.sh
sh -n scripts/verify-provider-registry.sh
sh -n scripts/sign-provider-registry.sh
sh -n scripts/verify-provider-registry-signature.sh
sh -n scripts/test-provider-registry-signing.sh
sh -n scripts/test-core-offline.sh
rg -q '127\.0\.0\.1:8787:8787' compose.yaml
rg -q 'no-new-privileges:true' compose.yaml
rg -q 'cap_drop:' compose.yaml
rg -q 'REMBRANE_WORKSPACE_KEY_REFERENCE: file:/run/secrets/rembrane_workspace_key' \
    compose.yaml
rg -q 'REMBRANE_API_TOKEN_REFERENCE: file:/run/secrets/rembrane_api_token' compose.yaml
if rg -q '^[[:space:]]+(REMBRANE_WORKSPACE_KEY_HEX|REMBRANE_API_TOKEN):' compose.yaml; then
    echo "core Compose must not interpolate raw workspace or API credentials" >&2
    exit 1
fi
test "$(rg -c 'mode: 0400' compose.yaml)" -eq 2
rg -q 'CLOUDFLARE_TUNNEL_TOKEN' compose.cloudflare.yaml
rg -q 'http://rembrane:8787' docs/CLOUDFLARE_DEPLOYMENT.md
rg -q 'read_only: true' compose.cloudflare.yaml
rg -q '127\.0\.0\.1:8793:8793' compose.graphiti.yaml
rg -q 'REMBRANE_GRAPHITI_BEARER_TOKEN_REFERENCE' compose.graphiti.yaml
rg -q 'REMBRANE_GRAPHITI_BEARER_TOKEN_FILE' compose.graphiti.yaml
rg -q 'REMBRANE_GRAPHITI_NEO4J_AUTH_FILE' compose.graphiti.yaml
rg -q 'REMBRANE_GRAPHITI_OPENAI_API_KEY_FILE' compose.graphiti.yaml
rg -q 'file:/run/secrets/rembrane_graphiti_bearer_token' compose.graphiti.yaml
rg -q 'NEO4J_AUTH_FILE: /run/secrets/rembrane_graphiti_neo4j_auth' compose.graphiti.yaml
rg -q 'OPENAI_API_KEY_REFERENCE: file:/run/secrets/rembrane_graphiti_openai_api_key' \
    compose.graphiti.yaml
if rg -q '^[[:space:]]+REMBRANE_GRAPHITI_BEARER_TOKEN:' compose.graphiti.yaml; then
    echo "Graphiti Compose must not interpolate the raw bearer token" >&2
    exit 1
fi
if rg -q '^[[:space:]]+(NEO4J_PASSWORD|OPENAI_API_KEY):' compose.graphiti.yaml; then
    echo "Graphiti Compose must not interpolate raw provider credentials" >&2
    exit 1
fi
test "$(rg -c 'mode: 0400' compose.graphiti.yaml)" -eq 6
rg -q 'rembrane-graph-worker' compose.graphiti.yaml
rg -q 'REMBRANE_GRAPH_PROVIDER_ALLOW_PLAINTEXT: "true"' compose.graphiti.yaml
rg -q 'no-new-privileges:true' compose.graphiti.yaml
rg -q -- '--package rembrane-graph-worker' Dockerfile
rg -q -- '--package rembrane-channel-worker' Dockerfile
rg -q -- '--package rembrane-whatsapp-gateway' Dockerfile
rg -q '127\.0\.0\.1:8790:8790' compose.whatsapp.yaml
rg -q 'REMBRANE_WHATSAPP_APP_SECRET_REFERENCE' compose.whatsapp.yaml
rg -q 'REMBRANE_WHATSAPP_BINDING_LOOKUP_SECRET_REFERENCE' compose.whatsapp.yaml
rg -q 'REMBRANE_WHATSAPP_WEBHOOK_VERIFICATION_TOKEN_REFERENCE' compose.whatsapp.yaml
rg -q 'REMBRANE_CHANNEL_PROCESSOR_URL' compose.whatsapp.yaml
rg -q 'REMBRANE_CHANNEL_PROCESSOR_TOKEN_REFERENCE' compose.whatsapp.yaml
rg -q 'REMBRANE_WHATSAPP_APP_SECRET_FILE' compose.whatsapp.yaml
rg -q 'REMBRANE_WHATSAPP_BINDING_LOOKUP_SECRET_FILE' compose.whatsapp.yaml
rg -q 'REMBRANE_WHATSAPP_WEBHOOK_VERIFICATION_TOKEN_FILE' compose.whatsapp.yaml
rg -q 'REMBRANE_CHANNEL_PROCESSOR_TOKEN_FILE' compose.whatsapp.yaml
if rg -q '^[[:space:]]+(REMBRANE_WHATSAPP_APP_SECRET|REMBRANE_WHATSAPP_BINDING_LOOKUP_SECRET|REMBRANE_WHATSAPP_WEBHOOK_VERIFICATION_TOKEN|REMBRANE_CHANNEL_PROCESSOR_TOKEN):' \
    compose.whatsapp.yaml; then
    echo "WhatsApp Compose must not interpolate raw channel credentials" >&2
    exit 1
fi
rg -q 'REMBRANE_KEY_PROVIDER_TOKEN_REFERENCE' compose.whatsapp.yaml
if rg -q '^[[:space:]]+REMBRANE_WORKSPACE_KEY_HEX:' \
    compose.graphiti.yaml compose.whatsapp.yaml compose.mobile-share.yaml; then
    echo "Compose overlays must not interpolate raw workspace keys" >&2
    exit 1
fi
rg -q 'rembrane-channel-worker' compose.whatsapp.yaml
rg -q '127\.0\.0\.1:8791:8791' compose.mobile-share.yaml
rg -q 'REMBRANE_MOBILE_SHARE_SIGNING_SECRET_REFERENCE' compose.mobile-share.yaml
rg -q 'REMBRANE_MOBILE_SHARE_BINDING_LOOKUP_SECRET_REFERENCE' compose.mobile-share.yaml
rg -q 'REMBRANE_KEY_PROVIDER_TOKEN_REFERENCE' compose.mobile-share.yaml
rg -q 'REMBRANE_API_TOKEN_REFERENCE' compose.yaml
rg -q 'no-new-privileges:true' compose.whatsapp.yaml
rg -q 'USER 10002:10002' sidecars/rembrane-graphiti/Dockerfile
if command -v docker >/dev/null 2>&1; then
    REMBRANE_PRINCIPAL_ID=principal_static \
    REMBRANE_WORKSPACE_ID=workspace_static \
    REMBRANE_CLIENT_ID=client_static \
    REMBRANE_WORKSPACE_KEY_ID=key_static \
    REMBRANE_WORKSPACE_KEY_FILE=/tmp/rembrane-static-workspace-key \
    REMBRANE_API_TOKEN_FILE=/tmp/rembrane-static-api-token \
        docker compose config --quiet
    CLOUDFLARE_TUNNEL_TOKEN=static-test-token \
    CLOUDFLARED_IMAGE=cloudflare/cloudflared:latest \
    REMBRANE_PRINCIPAL_ID=principal_static \
    REMBRANE_WORKSPACE_ID=workspace_static \
    REMBRANE_CLIENT_ID=client_static \
    REMBRANE_WORKSPACE_KEY_ID=key_static \
    REMBRANE_WORKSPACE_KEY_FILE=/tmp/rembrane-static-workspace-key \
    REMBRANE_API_TOKEN_FILE=/tmp/rembrane-static-api-token \
        docker compose -f compose.yaml -f compose.cloudflare.yaml config --quiet
    REMBRANE_PRINCIPAL_ID=principal_static \
    REMBRANE_WORKSPACE_ID=workspace_static \
    REMBRANE_CLIENT_ID=client_static \
    REMBRANE_WORKSPACE_KEY_ID=key_static \
    REMBRANE_WORKSPACE_KEY_FILE=/tmp/rembrane-static-workspace-key \
    REMBRANE_API_TOKEN_FILE=/tmp/rembrane-static-api-token \
    REMBRANE_GRAPHITI_BEARER_TOKEN_FILE=/tmp/rembrane-graphiti-static-token \
    REMBRANE_GRAPHITI_NEO4J_AUTH_FILE=/tmp/rembrane-graphiti-static-neo4j-auth \
    REMBRANE_GRAPHITI_OPENAI_API_KEY_FILE=/tmp/rembrane-graphiti-static-openai-key \
        docker compose -f compose.yaml -f compose.graphiti.yaml config --quiet
    REMBRANE_PRINCIPAL_ID=principal_static \
    REMBRANE_WORKSPACE_ID=workspace_static \
    REMBRANE_CLIENT_ID=client_static \
    REMBRANE_WORKSPACE_KEY_ID=key_static \
    REMBRANE_WORKSPACE_KEY_FILE=/tmp/rembrane-static-workspace-key \
    REMBRANE_API_TOKEN_FILE=/tmp/rembrane-static-api-token \
    REMBRANE_WHATSAPP_APP_SECRET_FILE=/tmp/rembrane-static-whatsapp-app-secret \
    REMBRANE_WHATSAPP_BINDING_LOOKUP_SECRET_FILE=/tmp/rembrane-static-whatsapp-binding-key \
    REMBRANE_WHATSAPP_WEBHOOK_VERIFICATION_TOKEN_FILE=/tmp/rembrane-static-whatsapp-verification-token \
    REMBRANE_CHANNEL_PROCESSOR_URL=https://processor.example \
    REMBRANE_CHANNEL_PROCESSOR_TOKEN_FILE=/tmp/rembrane-static-channel-processor-token \
        docker compose -f compose.yaml -f compose.whatsapp.yaml config --quiet
fi

echo "all static Rembrane checks passed"

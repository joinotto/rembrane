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
sh ./scripts/check-security-review-manifest.sh
sh ./scripts/test-security-review-signing.sh
sh ./scripts/test-security-review-attestation.sh
sh ./scripts/test-customer-kms-evidence.sh
sh ./scripts/test-customer-kms-provider-set.sh
sh ./scripts/test-memory-provider-mixed-version-evidence.sh
sh ./scripts/test-memory-provider-release-evidence.sh
sh ./scripts/test-memory-provider-external-provenance.sh
sh ./scripts/test-package-memory-provider-release-evidence.sh
node ./scripts/test-memory-provider-conformance-secrets.mjs
node ./scripts/test-memory-provider-discovery.mjs
./scripts/test-memory-provider-discovery-jq.sh
./scripts/test-memory-provider-conformance-inputs.sh
./scripts/test-memory-provider-context-result.sh
./scripts/test-memory-provider-sync-result.sh
./scripts/check-protocols.sh
./scripts/test-semantic-provider-compatibility-lock.sh
./scripts/test-memory-provider-compatibility-lock.sh
./scripts/test-key-provider-compatibility-lock.sh
./scripts/check-postgres-rls.sh
./scripts/verify-provider-registry.sh
./scripts/test-provider-registry-validation.sh
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
    scripts/derive-ed25519-public-key.mjs \
    scripts/ed25519-signing.mjs \
    scripts/ed25519-verification.mjs \
    scripts/sign-ed25519-document.mjs \
    scripts/sha256-bounded-file.mjs \
    scripts/verify-security-review-correlation.mjs \
    scripts/customer-kms-evidence.mjs \
    scripts/generate-customer-kms-evidence.mjs \
    scripts/verify-customer-kms-evidence.mjs \
    scripts/verify-customer-kms-provider-set.mjs \
    scripts/verify-security-review-signature.mjs \
    scripts/security-review-evidence.mjs \
    scripts/verify-security-review-bundle.mjs \
    scripts/test-graphiti-http-e2e.sh \
    scripts/test-graphiti-sidecar.sh \
    scripts/test-cross-tool-continuity.sh \
    scripts/test-cross-tool-continuity.mjs \
    scripts/test-swift-sdk.sh \
    scripts/test-ios-share-extension.sh \
    scripts/test-ios-imessage-extension.sh \
    scripts/test-kotlin-sdk.sh \
    scripts/test-memory-provider-compatibility-lock.sh \
    scripts/memory-provider-conformance-secrets.mjs \
    scripts/memory-provider-discovery.jq \
    scripts/test-memory-provider-discovery-jq.sh \
    scripts/test-memory-provider-conformance-inputs.sh \
    scripts/memory-provider-context-result.jq \
    scripts/test-memory-provider-context-result.sh \
    scripts/memory-provider-sync-result.jq \
    scripts/test-memory-provider-sync-result.sh \
    scripts/verify-memory-provider-sync-result.sh \
    scripts/run-memory-provider-conformance.mjs \
    scripts/test-memory-provider-conformance-secrets.mjs \
    scripts/test-memory-provider-mixed-version-evidence.sh \
    scripts/test-memory-provider-release-evidence.sh \
    scripts/test-memory-provider-external-provenance.sh \
    scripts/generate-memory-provider-external-provenance.mjs \
    scripts/memory-provider-external-provenance.mjs \
    scripts/memory-provider-mixed-version-evidence.mjs \
    scripts/read-bounded-regular-file.mjs \
    scripts/test-package-memory-provider-release-evidence.sh \
    scripts/package-memory-provider-release-evidence.mjs \
    scripts/test-key-provider-compatibility-lock.sh \
    scripts/test-semantic-provider-compatibility-lock.sh \
    scripts/verify-semantic-provider-compatibility.mjs \
    scripts/check-postgres-rls.sh \
    scripts/check-ci-security.sh \
    scripts/test-postgres-rls.sh \
    scripts/check-production-readiness.sh \
    scripts/verify-provider-registry.sh \
    scripts/verify-provider-registry.mjs \
    scripts/test-provider-registry-validation.sh \
    scripts/sign-provider-registry.sh \
    scripts/verify-provider-registry-signature.sh \
    scripts/verify-provider-registry-signature.mjs \
    scripts/provider-registry-evidence.mjs \
    scripts/verify-provider-registry-bundle.mjs \
    scripts/verify-provider-registry-bundle.sh \
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
sh -n scripts/test-cross-tool-continuity.sh
sh -n scripts/test-container-entrypoint.sh
sh -n docker/rembrane-stage-secrets
sh -n sidecars/rembrane-graphiti/docker/entrypoint.sh
sh -n scripts/test-swift-sdk.sh
sh -n scripts/test-ios-share-extension.sh
sh -n scripts/test-ios-imessage-extension.sh
sh -n scripts/test-kotlin-sdk.sh
sh -n scripts/test-memory-provider-compatibility-lock.sh
sh -n scripts/test-memory-provider-mixed-version-evidence.sh
sh -n scripts/test-memory-provider-release-evidence.sh
sh -n scripts/test-memory-provider-external-provenance.sh
sh -n scripts/test-package-memory-provider-release-evidence.sh
sh -n scripts/test-key-provider-compatibility-lock.sh
sh -n scripts/test-semantic-provider-compatibility-lock.sh
sh -n scripts/check-postgres-rls.sh
sh -n scripts/check-ci-security.sh
sh -n scripts/test-postgres-rls.sh
sh -n scripts/check-production-readiness.sh
sh -n scripts/verify-provider-registry.sh
sh -n scripts/test-provider-registry-validation.sh
sh -n scripts/sign-provider-registry.sh
sh -n scripts/verify-provider-registry-signature.sh
sh -n scripts/test-provider-registry-signing.sh
sh -n scripts/test-core-offline.sh
rg -q '^# REMBRANE_KEY_PROVIDER=macos-keychain$' .env.example
rg -q '^REMBRANE_KEYCHAIN_SERVICE=$' .env.example
rg -q '^REMBRANE_KEYCHAIN_ACCOUNT=$' .env.example
rg -q '^REMBRANE_KEYCHAIN_HISTORICAL_KEYS=$' .env.example
for variable in \
    MEM0_API_KEY_REFERENCE \
    MEM0_WORKSPACE_LOOKUP_SECRET_REFERENCE \
    SUPERMEMORY_API_KEY_REFERENCE \
    SUPERMEMORY_WORKSPACE_LOOKUP_SECRET_REFERENCE
do
    rg -q "^${variable}=$" .env.example
done
rg -q '127\.0\.0\.1:8787:8787' compose.yaml
rg -q 'no-new-privileges:true' compose.yaml
rg -q 'cap_drop:' compose.yaml
rg -q 'read_only: true' compose.yaml
rg -q '/tmp:size=16m,mode=1777' compose.yaml
rg -q '/run/rembrane-secrets:size=1m,mode=0700' compose.yaml
rg -q 'REMBRANE_WORKSPACE_KEY_REFERENCE: file:/run/rembrane-secrets/rembrane_workspace_key' \
    compose.yaml
rg -q 'REMBRANE_API_TOKEN_REFERENCE: file:/run/rembrane-secrets/rembrane_api_token' compose.yaml
if rg -q '^[[:space:]]+(REMBRANE_WORKSPACE_KEY_HEX|REMBRANE_API_TOKEN):' compose.yaml; then
    echo "core Compose must not interpolate raw workspace or API credentials" >&2
    exit 1
fi
test "$(rg -c 'mode: 0400' compose.yaml)" -eq 2
rg -q -- '--token-file' compose.cloudflare.yaml
rg -q 'CLOUDFLARE_TUNNEL_TOKEN_FILE' compose.cloudflare.yaml
if rg -q -- '(^|[[:space:]])--token([[:space:]]|$)' compose.cloudflare.yaml; then
    echo "Cloudflare Compose must not expose the tunnel token as an argument" >&2
    exit 1
fi
rg -q 'http://rembrane:8787' docs/CLOUDFLARE_DEPLOYMENT.md
rg -q 'read_only: true' compose.cloudflare.yaml
rg -q '127\.0\.0\.1:8793:8793' compose.graphiti.yaml
rg -q 'REMBRANE_GRAPHITI_BEARER_TOKEN_REFERENCE' compose.graphiti.yaml
rg -q 'REMBRANE_GRAPHITI_BEARER_TOKEN_FILE' compose.graphiti.yaml
rg -q 'REMBRANE_GRAPHITI_NEO4J_AUTH_FILE' compose.graphiti.yaml
rg -q 'REMBRANE_GRAPHITI_OPENAI_API_KEY_FILE' compose.graphiti.yaml
rg -q '^REMBRANE_GRAPHITI_BASE_URL=$' .env.example
rg -q '^REMBRANE_GRAPHITI_BEARER_TOKEN=$' .env.example
rg -q '^REMBRANE_GRAPHITI_BEARER_TOKEN_REFERENCE=$' .env.example
rg -q '^REMBRANE_OAUTH_INTROSPECTION_ENDPOINT=$' .env.example
rg -q '^REMBRANE_OAUTH_INTROSPECTION_CLIENT_ID=$' .env.example
rg -q '^REMBRANE_OAUTH_INTROSPECTION_CLIENT_SECRET_REFERENCE=$' .env.example
rg -q '^REMBRANE_MCP_TRUSTED_ORIGINS=$' .env.example
rg -q 'Result<Zeroizing<Vec<u8>>, ProviderError>' adapters/rembrane-semantic-mem0/src/lib.rs
rg -q 'Mem0 returned too many records' adapters/rembrane-semantic-mem0/src/lib.rs
rg -q 'Graphiti sidecar returned too many candidates' \
    adapters/rembrane-graph-graphiti-http/src/lib.rs
rg -q 'memory provider returned too many context items' \
    adapters/rembrane-memory-provider-http/src/lib.rs
rg -q 'memory provider returned too many supporting memories' \
    adapters/rembrane-memory-provider-http/src/lib.rs
rg -q 'memory provider sync pull returned too many changes' \
    adapters/rembrane-memory-provider-http/src/lib.rs
rg -q 'memory provider sync push result count does not match' \
    adapters/rembrane-memory-provider-http/src/lib.rs
rg -q 'Result<Zeroizing<Vec<u8>>, ProviderError>' \
    adapters/rembrane-semantic-supermemory/src/lib.rs
for zeroizing_response_adapter in \
    adapters/rembrane-channel-processor-http/src/lib.rs \
    adapters/rembrane-graph-graphiti-http/src/lib.rs \
    adapters/rembrane-key-provider-http/src/lib.rs \
    adapters/rembrane-memory-provider-http/src/lib.rs \
    adapters/rembrane-oauth-introspection-http/src/lib.rs
do
    if ! rg -q 'Zeroizing::new\(Vec::new\(\)\)' "$zeroizing_response_adapter"; then
        echo "HTTP adapter must zeroize bounded raw response bodies: $zeroizing_response_adapter" >&2
        exit 1
    fi
done
for zeroizing_request_adapter in \
    adapters/rembrane-channel-processor-http/src/lib.rs \
    adapters/rembrane-graph-graphiti-http/src/lib.rs \
    adapters/rembrane-key-provider-http/src/lib.rs \
    adapters/rembrane-memory-provider-http/src/lib.rs \
    adapters/rembrane-oauth-introspection-http/src/lib.rs \
    adapters/rembrane-semantic-mem0/src/lib.rs \
    adapters/rembrane-semantic-supermemory/src/lib.rs
do
    if ! rg -q 'bytes::Bytes::from_owner\((encoded|body)\)' "$zeroizing_request_adapter"; then
        echo "HTTP adapter must preserve zeroizing serialized request ownership: $zeroizing_request_adapter" >&2
        exit 1
    fi
done
if rg -q '\.form\(' adapters/rembrane-oauth-introspection-http/src/lib.rs; then
    echo "OAuth introspection must preserve zeroizing form-body ownership" >&2
    exit 1
fi
rg -q 'wire\.plaintext_base64\.zeroize\(\)' adapters/rembrane-key-provider-http/src/lib.rs
if rg -q 'errors: Vec<serde_json::Value>' adapters/rembrane-semantic-supermemory/src/lib.rs; then
    echo "Supermemory deletion errors must be streamed without arbitrary JSON retention" >&2
    exit 1
fi
if rg -q 'REMBRANE_REMOTE_MCP_URL' apps/rembrane-cli/src/main.rs .env.example; then
    echo "CLI and environment template must use the canonical remote MCP profile" >&2
    exit 1
fi
if rg -q '^(GRAPHITI_BASE_URL|GRAPHITI_CREDENTIALS)=' .env.example; then
    echo "Canonical environment template must use REMBRANE_GRAPHITI_* variables" >&2
    exit 1
fi
rg -q 'file:/run/rembrane-secrets/rembrane_graphiti_bearer_token' compose.graphiti.yaml
rg -q 'NEO4J_AUTH_FILE: /run/secrets/rembrane_graphiti_neo4j_auth' compose.graphiti.yaml
rg -q 'OPENAI_API_KEY_REFERENCE: file:/run/rembrane-secrets/rembrane_graphiti_openai_api_key' \
    compose.graphiti.yaml
rg -q '/run/rembrane-secrets:size=1m,mode=0700' compose.graphiti.yaml
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
if rg -q '^[[:space:]]+REMBRANE_KEY_PROVIDER_TOKEN:' compose.whatsapp.yaml; then
    echo "WhatsApp Compose must not interpolate raw key-provider credentials" >&2
    exit 1
fi
if rg -q '^[[:space:]]+REMBRANE_WORKSPACE_KEY_HEX:' \
    compose.graphiti.yaml compose.whatsapp.yaml compose.mobile-share.yaml; then
    echo "Compose overlays must not interpolate raw workspace keys" >&2
    exit 1
fi
rg -q 'rembrane-channel-worker' compose.whatsapp.yaml
rg -q '127\.0\.0\.1:8791:8791' compose.mobile-share.yaml
rg -q 'REMBRANE_MOBILE_SHARE_SIGNING_SECRET_REFERENCE' compose.mobile-share.yaml
rg -q 'REMBRANE_MOBILE_SHARE_BINDING_LOOKUP_SECRET_REFERENCE' compose.mobile-share.yaml
rg -q 'REMBRANE_MOBILE_SHARE_SIGNING_SECRET_FILE' compose.mobile-share.yaml
rg -q 'REMBRANE_MOBILE_SHARE_BINDING_LOOKUP_SECRET_FILE' compose.mobile-share.yaml
if rg -q '^[[:space:]]+(REMBRANE_MOBILE_SHARE_SIGNING_SECRET|REMBRANE_MOBILE_SHARE_BINDING_LOOKUP_SECRET):' \
    compose.mobile-share.yaml; then
    echo "mobile-share Compose must not interpolate raw gateway credentials" >&2
    exit 1
fi
rg -q 'REMBRANE_KEY_PROVIDER_TOKEN_REFERENCE' compose.mobile-share.yaml
if rg -q '^[[:space:]]+REMBRANE_KEY_PROVIDER_TOKEN:' compose.mobile-share.yaml; then
    echo "mobile-share Compose must not interpolate raw key-provider credentials" >&2
    exit 1
fi
rg -q 'REMBRANE_API_TOKEN_REFERENCE' compose.yaml
rg -q 'no-new-privileges:true' compose.whatsapp.yaml
test "$(rg -c 'read_only: true' compose.whatsapp.yaml)" -eq 2
test "$(rg -c '/tmp:size=16m,mode=1777' compose.whatsapp.yaml)" -eq 2
test "$(rg -c '/run/rembrane-secrets:size=1m,mode=0700' compose.whatsapp.yaml)" -eq 2
test "$(rg -c 'read_only: true' compose.mobile-share.yaml)" -eq 1
test "$(rg -c '/tmp:size=16m,mode=1777' compose.mobile-share.yaml)" -eq 1
test "$(rg -c '/run/rembrane-secrets:size=1m,mode=0700' compose.mobile-share.yaml)" -eq 1
test "$(rg 'REMBRANE_SKIP_WORKSPACE_INIT: \"1\"' \
    compose.whatsapp.yaml compose.mobile-share.yaml | wc -l | tr -d ' ')" -eq 3
rg -q 'ENTRYPOINT \[\"rembrane-graphiti-entrypoint\"\]' \
    sidecars/rembrane-graphiti/Dockerfile
rg -q 'exec gosu rembrane-graphiti' sidecars/rembrane-graphiti/docker/entrypoint.sh
rg -q 'rembrane-stage-secrets' Dockerfile sidecars/rembrane-graphiti/Dockerfile
./scripts/test-container-entrypoint.sh
if command -v docker >/dev/null 2>&1; then
    REMBRANE_PRINCIPAL_ID=principal_static \
    REMBRANE_WORKSPACE_ID=workspace_static \
    REMBRANE_CLIENT_ID=client_static \
    REMBRANE_WORKSPACE_KEY_ID=key_static \
    REMBRANE_WORKSPACE_KEY_FILE=/tmp/rembrane-static-workspace-key \
    REMBRANE_API_TOKEN_FILE=/tmp/rembrane-static-api-token \
        docker compose config --quiet
    CLOUDFLARE_TUNNEL_TOKEN_FILE=/tmp/rembrane-static-cloudflare-token \
    CLOUDFLARED_IMAGE=cloudflare/cloudflared:2026.7.0 \
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
    REMBRANE_PRINCIPAL_ID=principal_static \
    REMBRANE_WORKSPACE_ID=workspace_static \
    REMBRANE_CLIENT_ID=client_static \
    REMBRANE_WORKSPACE_KEY_ID=key_static \
    REMBRANE_WORKSPACE_KEY_FILE=/tmp/rembrane-static-workspace-key \
    REMBRANE_API_TOKEN_FILE=/tmp/rembrane-static-api-token \
    REMBRANE_MOBILE_SHARE_SIGNING_SECRET_FILE=/tmp/rembrane-static-mobile-signing \
    REMBRANE_MOBILE_SHARE_BINDING_LOOKUP_SECRET_FILE=/tmp/rembrane-static-mobile-binding \
        docker compose -f compose.yaml -f compose.mobile-share.yaml config --quiet
fi

echo "all static Rembrane checks passed"

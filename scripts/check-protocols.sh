#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "required protocol checker is unavailable: $1" >&2
        exit 1
    fi
}

for command in jq node ruby rg; do
    require_command "$command"
done

ruby -e 'require "yaml"; YAML.load_file(ARGV.fetch(0))' spec/openapi.yaml
ruby -e 'require "yaml"; YAML.load_file(ARGV.fetch(0))' spec/provider-openapi.yaml
ruby -e 'require "yaml"; YAML.load_file(ARGV.fetch(0))' spec/key-provider-openapi.yaml
jq empty \
    spec/discovery.schema.json \
    spec/memory-provider.schema.json \
    spec/examples/discovery.json \
    spec/examples/memory-provider-discovery.json \
    spec/examples/memory-provider-context-request.json \
    spec/examples/memory-provider-context-response.json \
    spec/examples/memory-provider-proposal-request.json \
    spec/examples/oauth-protected-resource.json \
    spec/examples/provider-manifest.json \
    spec/examples/provider-projection.json \
    spec/examples/provider-search-request.json \
    spec/examples/provider-search-response.json \
    spec/examples/key-provider-manifest.json \
    spec/provider-manifest.schema.json \
    spec/provider-registry.json \
    spec/provider-registry.schema.json \
    spec/oauth-protected-resource.schema.json \
    spec/stdio-connection-manifest.schema.json \
    tests/postman/rembrane-local.postman_collection.json

jq -e '
    ."$defs".protocolVersion.const == "0.1"
    and (."$defs".operation.enum | length == 10)
    and (."$defs".oauthScope.enum | length == 10)
    and (."$defs".errorCode.enum | length == 7)
    and ."$defs".requestEnvelope.additionalProperties == false
    and ."$defs".successEnvelope.additionalProperties == false
    and ."$defs".errorEnvelope.additionalProperties == false
    and ."$defs".resolveContextPayload.additionalProperties == false
    and ."$defs".resolveContextResult.additionalProperties == false
    and ."$defs".resolveQuestionPayload.additionalProperties == false
    and ."$defs".resolveQuestionResult.additionalProperties == false
    and ."$defs".deleteMemoryPayload.additionalProperties == false
    and ."$defs".deleteMemoryResult.additionalProperties == false
    and ."$defs".explainMemoryPayload.additionalProperties == false
    and ."$defs".explainMemoryResult.additionalProperties == false
    and ."$defs".recordEventPayload.additionalProperties == false
    and ."$defs".recordEventResult.additionalProperties == false
    and ."$defs".proposeMemoryPayload.additionalProperties == false
    and ."$defs".checkpointActivityPayload.oneOf[0].additionalProperties == false
    and ."$defs".checkpointActivityPayload.oneOf[1].additionalProperties == false
    and ."$defs".recordDisclosurePayload.additionalProperties == false
    and ."$defs".recordDisclosureResult.additionalProperties == false
' spec/memory-provider.schema.json >/dev/null

jq -e '
    .protocolVersion == "0.1"
    and .privacyMode == "end_to_end_encrypted"
    and (.capabilities | length == 10 and length == (unique | length))
    and (.operations | length == 10)
    and ([.operations[].operation] | length == (unique | length))
    and all(
        .operations[];
        .operation == .capability
        and (.oauthScope | startswith("memory:"))
        and (.pathTemplate | startswith("/v1/"))
    )
' spec/examples/memory-provider-discovery.json >/dev/null

jq -e '
    .protocolVersion == "0.1"
    and .operation == "resolve_context"
    and .payload.selector.scope == "entity"
    and (.payload.maximumItems > 0)
    and (.payload.maximumBytes > 0)
' spec/examples/memory-provider-context-request.json >/dev/null

jq -e '
    .protocolVersion == "0.1"
    and (.result.items | length > 0)
    and all(
        .result.items[];
        (.version > 0)
        and (.confidenceMillionths >= 0 and .confidenceMillionths <= 1000000)
        and (.evidence | length > 0)
    )
' spec/examples/memory-provider-context-response.json >/dev/null

jq -e '
    .protocolVersion == "0.1"
    and .operation == "propose_memory"
    and .payload.selector.scope == "global"
    and .payload.kind == "preference"
    and .payload.evidenceSource == "user_statement"
    and (.payload | has("workspaceId") | not)
    and (.payload | has("subjectId") | not)
    and (.payload | has("confirmed") | not)
' spec/examples/memory-provider-proposal-request.json >/dev/null

jq -e '
    (.resource | startswith("https://"))
    and (.authorization_servers | length > 0)
    and all(.authorization_servers[]; startswith("https://"))
    and (.scopes_supported | length > 0)
    and all(.scopes_supported[]; test("^rembrane:[a-z][a-z0-9:_-]*$"))
    and .bearer_methods_supported == ["header"]
' spec/examples/oauth-protected-resource.json >/dev/null

for remote_mcp_invariant in \
    'Authorization: Bearer <access-token>' \
    'WWW-Authenticate: Bearer resource_metadata=' \
    'Every request is reauthenticated' \
    'Workspace, subject, and client identifiers are derived from verified claims'
do
    if ! rg -F "$remote_mcp_invariant" spec/remote-mcp.md >/dev/null; then
        echo "remote MCP security invariant is missing: $remote_mcp_invariant" >&2
        exit 1
    fi
done
node --check scripts/test-mcp-e2e.mjs
sh -n scripts/test-provider-http.sh
node --check scripts/test-provider-http-runner.mjs
sh -n scripts/test-key-provider-http.sh
node --check scripts/test-key-provider-http-runner.mjs
if [ "${REMBRANE_RUN_LOOPBACK_TESTS:-0}" = "1" ]; then
    node scripts/test-provider-http-runner.mjs
    node scripts/test-key-provider-http-runner.mjs
fi
if REMBRANE_PROVIDER_BASE_URL=http://provider.example \
    REMBRANE_PROVIDER_TOKEN=test-token \
    ./scripts/test-provider-http.sh static-check >/dev/null 2>&1
then
    echo "provider runner unexpectedly accepted remote plaintext HTTP" >&2
    exit 1
fi
if REMBRANE_KEY_PROVIDER_BASE_URL=http://key-provider.example \
    REMBRANE_KEY_PROVIDER_TOKEN=test-token \
    ./scripts/test-key-provider-http.sh static-check >/dev/null 2>&1
then
    echo "key provider runner unexpectedly accepted remote plaintext HTTP" >&2
    exit 1
fi

for provider_route in \
    '/v0.1/manifest:' \
    '/v0.1/projections:' \
    '/v0.1/projections/{workspaceId}/{memoryId}:' \
    '/v0.1/search:'
do
    if ! rg -F "$provider_route" spec/provider-openapi.yaml >/dev/null; then
        echo "provider protocol route is missing: $provider_route" >&2
        exit 1
    fi
done

for key_provider_route in \
    '/v0.1/manifest:' \
    '/v0.1/seal:' \
    '/v0.1/open:'
do
    if ! rg -F "$key_provider_route" spec/key-provider-openapi.yaml >/dev/null; then
        echo "key provider protocol route is missing: $key_provider_route" >&2
        exit 1
    fi
done

jq -e '
    .protocolVersion == "0.1"
    and (.providerId | test("^[a-z0-9][a-z0-9._-]+$"))
    and (.algorithms | type == "array" and length > 0)
    and (.maximumPlaintextBytes | type == "number" and . > 0)
    and (.supportsHistoricalKeys | type == "boolean")
' spec/examples/key-provider-manifest.json >/dev/null

jq -e '
    .schemaVersion == 1
    and (.generatedAt | type == "string" and length > 0)
    and (.providers | type == "array")
    and ([.providers[].id] | length == (unique | length))
    and all(
        .providers[];
        (.id | test("^[a-z0-9][a-z0-9._-]+$"))
        and (.protocolVersions | length > 0)
        and (.deploymentModes | length > 0)
        and (.source.repository | startswith("https://"))
        and (.source.revision | test("^[0-9a-f]{7,64}$"))
        and (
            if .conformance.result == "pass"
            then .conformance.testedAt != null
            else true
            end
        )
    )
' spec/provider-registry.json >/dev/null

if ! rg -F 'include_str!("../../../spec/provider-registry.json")' \
    apps/rembrane-cli/src/main.rs >/dev/null ||
    ! rg -F 'Some("providers") => providers(&arguments[1..])' \
        apps/rembrane-cli/src/main.rs >/dev/null ||
    ! rg -F 'rembrane providers list' apps/rembrane-cli/src/main.rs >/dev/null ||
    ! rg -F 'rembrane providers test' apps/rembrane-cli/src/main.rs >/dev/null
then
    echo "CLI provider registry command is inconsistent with the registry artifact" >&2
    exit 1
fi

implemented_tools=$(
    sed -n 's/^[[:space:]]*name = "\(rembrane_[a-z_]*\)",$/\1/p' \
        apps/rembrane-mcp/src/lib.rs
)
test -n "$implemented_tools"
for tool in $implemented_tools; do
    if ! rg -F "\`$tool\`" spec/mcp.md >/dev/null; then
        echo "implemented MCP tool is undocumented: $tool" >&2
        exit 1
    fi
    if ! rg -F "\"$tool\"" crates/rembrane-contracts/src/lib.rs >/dev/null; then
        echo "implemented MCP tool has no remote OAuth scope mapping: $tool" >&2
        exit 1
    fi
done

if ! rg -F '/context/resolve:' spec/openapi.yaml >/dev/null ||
    ! rg -F '"/.well-known/oauth-protected-resource/mcp"' apps/rembrane-api/src/main.rs >/dev/null ||
    ! rg -F '"/v1/context/resolve"' apps/rembrane-api/src/main.rs >/dev/null ||
    ! rg -F '/travel/trips:' spec/openapi.yaml >/dev/null ||
    ! rg -F '"/v1/travel/trips"' apps/rembrane-api/src/main.rs >/dev/null ||
    ! rg -F '/travel/booking-research:' spec/openapi.yaml >/dev/null ||
    ! rg -F '"/v1/travel/booking-research"' apps/rembrane-api/src/main.rs >/dev/null ||
    ! rg -F '/travel/context/resolve:' spec/openapi.yaml >/dev/null ||
    ! rg -F '"/v1/travel/context/resolve"' apps/rembrane-api/src/main.rs >/dev/null ||
    ! rg -F '/travel/trip-participants:' spec/openapi.yaml >/dev/null ||
    ! rg -F '"/v1/travel/trip-participants"' apps/rembrane-api/src/main.rs >/dev/null ||
    ! rg -F '/travel/trip-constraints:' spec/openapi.yaml >/dev/null ||
    ! rg -F '"/v1/travel/trip-constraints"' apps/rembrane-api/src/main.rs >/dev/null ||
    ! rg -F '/travel/trip-decisions:' spec/openapi.yaml >/dev/null ||
    ! rg -F '"/v1/travel/trip-decisions"' apps/rembrane-api/src/main.rs >/dev/null
then
    echo "REST routes and OpenAPI contract are inconsistent" >&2
    exit 1
fi

echo "protocol checks passed"

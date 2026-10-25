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
ruby -e 'require "yaml"; YAML.load_file(ARGV.fetch(0))' spec/memory-provider-openapi.yaml
ruby -e 'require "yaml"; YAML.load_file(ARGV.fetch(0))' spec/mobile-share-openapi.yaml
jq empty \
    spec/discovery.schema.json \
    spec/channel-processor-message.schema.json \
    spec/channel-processor-acknowledgement.schema.json \
    spec/mcp-client-catalog.schema.json \
    spec/memory-provider-compatibility-lock.json \
    spec/key-provider-compatibility-lock.json \
    spec/memory-provider.schema.json \
    spec/memory-provider-conformance.schema.json \
    spec/memory-provider-conformance-result.schema.json \
    spec/key-provider-conformance-result.schema.json \
    spec/key-provider-conformance.schema.json \
    spec/memory-provider-fixtures.schema.json \
    spec/conformance/memory-provider-core.json \
    spec/conformance/key-provider-core.json \
    spec/conformance/memory-provider-core-fixtures.json \
    spec/examples/discovery.json \
    spec/examples/channel-processor-message.json \
    spec/examples/channel-processor-acknowledgement.json \
    spec/examples/memory-provider-discovery.json \
    spec/examples/memory-provider-context-request.json \
    spec/examples/memory-provider-context-response.json \
    spec/examples/memory-provider-conformance-result.json \
    spec/examples/memory-provider-proposal-request.json \
    spec/examples/memory-provider-sync-push-request.json \
    spec/examples/oauth-protected-resource.json \
    spec/examples/provider-manifest.json \
    spec/examples/provider-projection.json \
    spec/examples/provider-search-request.json \
    spec/examples/provider-search-response.json \
    spec/examples/key-provider-manifest.json \
    spec/examples/key-provider-conformance-result.json \
    spec/examples/mcp-client-catalog.json \
    spec/provider-manifest.schema.json \
    spec/provider-registry.json \
    spec/provider-registry.schema.json \
    spec/oauth-protected-resource.schema.json \
    spec/stdio-connection-manifest.schema.json \
    tests/postman/rembrane-local.postman_collection.json

jq -e '
    .additionalProperties == false
    and .properties.protocolVersion.const == "0.1"
    and (.properties.channel.enum == [
        "whatsapp-business",
        "imessage-extension",
        "mobile-share"
    ])
    and .properties.eventId["x-rembrane-maxUtf8Bytes"] == 256
    and .properties.text["x-rembrane-maxUtf8Bytes"] == 16384
    and .properties.text.pattern == "\\S"
    and ."$defs".opaqueId["x-rembrane-maxUtf8Bytes"] == 255
    and ."$defs".opaqueId.additionalProperties == null
' spec/channel-processor-message.schema.json >/dev/null

jq -e '
    .additionalProperties == false
    and .properties.protocolVersion.const == "0.1"
    and .properties.eventId["x-rembrane-maxUtf8Bytes"] == 256
    and .properties.status.enum == ["processed", "duplicate"]
' spec/channel-processor-acknowledgement.schema.json >/dev/null

jq -e --slurpfile example spec/examples/key-provider-conformance-result.json '
    .additionalProperties == false
    and .properties.profileId.const == "rembrane.key-provider.core"
    and .properties.profileSha256.pattern == "^[0-9a-f]{64}$"
    and .properties.protocolVersion.const == "0.1"
    and .properties.result.const == "pass"
    and .properties.providerVersion.maxLength == 100
    and .properties.cases.minItems == 8
    and .properties.cases.maxItems == 8
    and ($example[0].cases | length) == 8
    and ($example[0].cases | map(.id) | unique | length) == 8
    and all($example[0].cases[]; .result == "pass")
    and $example[0].providerVersion == "0.1.0-test"
    and $example[0].profileId == "rembrane.key-provider.core"
    and ($example[0].profileSha256 | test("^[0-9a-f]{64}$"))
' spec/key-provider-conformance-result.schema.json >/dev/null

jq -e '
    .additionalProperties == false
    and .properties.profileId.const == "rembrane.memory-provider.core"
    and .properties.protocolVersion.const == "0.1"
' spec/memory-provider-conformance.schema.json >/dev/null

jq -e '
    .additionalProperties == false
    and .properties.profileId.const == "rembrane.memory-provider.core"
    and .properties.fixtureId.const == "rembrane.memory-provider.core.lifecycle"
    and .properties.protocolVersion.const == "0.1"
' spec/memory-provider-fixtures.schema.json >/dev/null

jq -e '
    .additionalProperties == false
    and .properties.profileId.const == "rembrane.memory-provider.core"
    and .properties.profileSha256.pattern == "^[0-9a-f]{64}$"
    and .properties.fixtureId.const == "rembrane.memory-provider.core.lifecycle"
    and .properties.fixtureSha256.pattern == "^[0-9a-f]{64}$"
    and .properties.protocolVersion.const == "0.1"
    and .properties.result.const == "pass"
' spec/memory-provider-conformance-result.schema.json >/dev/null

jq -e '
    .profileId == "rembrane.key-provider.core"
    and .protocolVersion == "0.1"
    and (.cases | map(.id)) == [
        "authentication",
        "manifest",
        "roundtrip",
        "context-substitution",
        "unknown-key",
        "plaintext-limit",
        "rotation",
        "repeated-rotation"
    ]
    and all(.cases[]; (.requirement | length) >= 1 and (.requirement | length) <= 500)
' spec/conformance/key-provider-core.json >/dev/null

jq -e '
    .additionalProperties == false
    and .properties.profileId.const == "rembrane.key-provider.core"
    and .properties.protocolVersion.const == "0.1"
    and .properties.cases.minItems == 8
    and .properties.cases.maxItems == 8
' spec/key-provider-conformance.schema.json >/dev/null

jq -e --slurpfile schema spec/channel-processor-acknowledgement.schema.json '
    .protocolVersion == $schema[0].properties.protocolVersion.const
    and (.eventId | test("^\\S+$") and length <= 256)
    and (.status as $status | $schema[0].properties.status.enum | index($status) != null)
    and ((keys | sort) == ($schema[0].required | sort))
' spec/examples/channel-processor-acknowledgement.json >/dev/null

jq -e --slurpfile schema spec/channel-processor-message.schema.json '
    .protocolVersion == $schema[0].properties.protocolVersion.const
    and (.channel as $channel | $schema[0].properties.channel.enum | index($channel) != null)
    and (.eventId | test("^\\S+$") and length <= 256)
    and (.workspaceId | test("^\\S+$") and length <= 255)
    and (.principalId | test("^\\S+$") and length <= 255)
    and (.clientId | test("^\\S+$") and length <= 255)
    and (.text | test("\\S") and length <= 16384)
    and (.receivedAtEpochSeconds | type == "number" and . > 0)
    and ((keys | sort) == ($schema[0].required | sort))
' spec/examples/channel-processor-message.json >/dev/null

ruby -ryaml -e '
document = YAML.load_file(ARGV.fetch(0))
operation = document.fetch("paths").fetch("/graph/context/resolve").fetch("post")
request_schema = operation
  .fetch("requestBody")
  .fetch("content")
  .fetch("application/json")
  .fetch("schema")
response_schema = operation
  .fetch("responses")
  .fetch("200")
  .fetch("content")
  .fetch("application/json")
  .fetch("schema")
abort("graph request schema binding differs") unless request_schema.fetch("$ref") == "#/components/schemas/ResolveGraphContextRequest"
abort("graph response schema binding differs") unless response_schema.fetch("$ref") == "#/components/schemas/ResolveGraphContextResponse"
%w[400 401 403 409].each do |status|
  abort("graph error response #{status} is missing") unless operation.fetch("responses").key?(status)
end
' spec/openapi.yaml

jq -e '
    ([.item[] | select(.request.url == "{{baseUrl}}/v1/graph/context/resolve")] | length == 2)
    and any(
        .item[];
        .name == "Reject graph context outside connection scope"
        and (.request.body.raw | contains("\"entityId\":\"project_outside_grant\""))
        and (.event[].script.exec | any(contains("status(403)")))
    )
    and any(
        .item[];
        .name == "Resolve audited graph context"
        and (.request.body.raw | contains("\"entityId\":\"project_rest_e2e\""))
        and (.event[].script.exec | any(contains("body.disclosureId")))
        and (.event[].script.exec | any(contains("body.edges")))
    )
' tests/postman/rembrane-local.postman_collection.json >/dev/null

jq -e '
    .schemaVersion == 1
    and (.clients | length == 8)
    and ([.clients[].id] | length == (unique | length))
    and all(
        .clients[];
        (.id | test("^[a-z0-9][a-z0-9-]*$"))
        and (.configFormat | IN("toml", "json", "rembrane-stdio-manifest-v1"))
        and (
            .environmentMode
            | IN(
                "inherit-allowlist",
                "placeholder",
                "process-inherited",
                "required-environment"
            )
        )
    )
' spec/examples/mcp-client-catalog.json >/dev/null

node scripts/verify-memory-provider-compatibility.mjs
node scripts/verify-key-provider-compatibility.mjs

jq -e '
    .properties.command.minLength == 1
    and .properties.command.maxLength == 4096
    and .properties.command.pattern == "^[^\\u0000-\\u001F\\u007F]+$"
    and .properties.args.maxItems == 64
    and .properties.args.items.maxLength == 4096
    and .properties.args.items.pattern == "^[^\\u0000-\\u001F\\u007F]*$"
    and .properties.requiredEnvironment.uniqueItems == true
' spec/stdio-connection-manifest.schema.json >/dev/null

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
    and ."$defs".syncPullPayload.additionalProperties == false
    and ."$defs".syncPullResult.additionalProperties == false
    and ."$defs".syncPushPayload.additionalProperties == false
    and ."$defs".syncPushResult.additionalProperties == false
    and ."$defs".pulledSyncChange.oneOf[0].properties.sequence.minimum == 1
    and (."$defs".pushSyncMutation.oneOf[0].properties | has("sequence") | not)
    and (."$defs".pushSyncMutation.oneOf[1].required | index("expectedVersion") != null)
' spec/memory-provider.schema.json >/dev/null

if ! rg -F '/v1/shares:' spec/mobile-share-openapi.yaml >/dev/null ||
    ! rg -F 'X-Rembrane-Signature-256' spec/mobile-share-openapi.yaml >/dev/null ||
    ! rg -F 'additionalProperties: false' spec/mobile-share-openapi.yaml >/dev/null ||
    ! rg -F 'shared_at_epoch_seconds' spec/mobile-share-openapi.yaml >/dev/null
then
    echo "mobile-share protocol is missing strict authenticated envelope invariants" >&2
    exit 1
fi

ruby -rjson -e '
request = JSON.parse(File.read(ARGV.fetch(0)))
required = %w[account_id device_id event_id text shared_at_epoch_seconds]
abort("mobile-share example fields differ") unless request.keys.sort == required.sort
required.first(4).each do |field|
  value = request.fetch(field)
  abort("mobile-share example string is invalid") unless value.is_a?(String) && !value.empty?
end
timestamp = request.fetch("shared_at_epoch_seconds")
abort("mobile-share example time is invalid") unless timestamp.is_a?(Integer) && timestamp.positive?
' spec/examples/mobile-share-request.json

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
    .protocolVersion == "0.1"
    and .operation == "sync_push"
    and (.payload.mutations | length == 2)
    and all(.payload.mutations[]; has("sequence") | not)
    and (.payload | has("workspaceId") | not)
    and (.payload.mutations[0].payloadSha256 | test("^[0-9a-f]{64}$"))
    and (.payload.mutations[1].operation == "delete")
    and (.payload.mutations[1] | has("payload") | not)
' spec/examples/memory-provider-sync-push-request.json >/dev/null

jq -e '
    .protocolVersion == "0.1"
    and (.requiredCapabilities | length == 4 and length == (unique | length))
    and (.cases | length >= 10)
    and ([.cases[].id] | length == (unique | length))
    and any(.cases[]; .expected == "unauthorized")
    and any(.cases[]; .expected == "forbidden")
    and any(.cases[]; .expected == "conflict")
    and any(.cases[]; .expected == "isolated")
    and any(.cases[]; .expected == "idempotent")
    and any(.cases[]; .expected == "ordered")
' spec/conformance/memory-provider-core.json >/dev/null

jq -e '
    .fixtureId == "rembrane.memory-provider.core.lifecycle"
    and .profileId == "rembrane.memory-provider.core"
    and .protocolVersion == "0.1"
    and (.actors.primary.requiredScopes | contains([
        "memory:context:read",
        "memory:proposal:write",
        "memory:memory:delete",
        "memory:sync:read"
    ]))
    and .actors.otherWorkspace.requiredScopes == .actors.primary.requiredScopes
    and .actors.readOnly.requiredScopes == ["memory:context:read"]
    and (.scenario.maximumContextItems > 0)
    and (.scenario.maximumContextBytes > 0)
    and (.scenario.maximumSyncItems > 0)
    and (.scenario | has("workspaceId") | not)
    and (.scenario | has("subjectId") | not)
    and (.scenario | has("token") | not)
' spec/conformance/memory-provider-core-fixtures.json >/dev/null

jq -e --slurpfile profile spec/conformance/memory-provider-core.json '
    .profileId == $profile[0].profileId
    and .protocolVersion == $profile[0].protocolVersion
    and .fixtureId == "rembrane.memory-provider.core.lifecycle"
    and .result == "pass"
    and (.provider.id | test("^[a-z0-9][a-z0-9._-]+$"))
    and (.provider.version | length > 0)
    and ([.cases[].id] == [$profile[0].cases[].id])
    and all(.cases[]; .result == "pass")
' spec/examples/memory-provider-conformance-result.json >/dev/null

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
sh -n scripts/test-memory-provider-http.sh
node --check scripts/test-memory-provider-http-runner.mjs
if [ "${REMBRANE_RUN_LOOPBACK_TESTS:-0}" = "1" ]; then
    node scripts/test-provider-http-runner.mjs
    node scripts/test-key-provider-http-runner.mjs
    node scripts/test-memory-provider-http-runner.mjs
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
if REMBRANE_MEMORY_PROVIDER_BASE_URL=http://memory-provider.example \
    REMBRANE_MEMORY_PROVIDER_PRIMARY_TOKEN=primary-token \
    REMBRANE_MEMORY_PROVIDER_OTHER_TOKEN=other-token \
    REMBRANE_MEMORY_PROVIDER_READONLY_TOKEN=readonly-token \
    ./scripts/test-memory-provider-http.sh static-check >/dev/null 2>&1
then
    echo "memory provider runner unexpectedly accepted remote plaintext HTTP" >&2
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
    '/v0.1/open:' \
    '/v0.1/rotate:'
do
    if ! rg -F "$key_provider_route" spec/key-provider-openapi.yaml >/dev/null; then
        echo "key provider protocol route is missing: $key_provider_route" >&2
        exit 1
    fi
done

for memory_provider_route in \
    '/.well-known/ai-memory:' \
    '/v1/context/resolve:' \
    '/v1/questions/resolve:' \
    '/v1/events:' \
    '/v1/memory/proposals:' \
    '/v1/activities/{activity_id}/checkpoint:' \
    '/v1/disclosures/receipt:' \
    '/v1/memories/{memory_id}:' \
    '/v1/memories/{memory_id}/explain:' \
    '/v1/sync/pull:' \
    '/v1/sync/push:'
do
    if ! rg -F "$memory_provider_route" spec/memory-provider-openapi.yaml >/dev/null; then
        echo "memory provider protocol route is missing: $memory_provider_route" >&2
        exit 1
    fi
done

for memory_provider_scope in \
    'memory:context:read' \
    'memory:question:read' \
    'memory:event:write' \
    'memory:proposal:write' \
    'memory:checkpoint:write' \
    'memory:disclosure:write' \
    'memory:memory:delete' \
    'memory:memory:explain' \
    'memory:sync:read' \
    'memory:sync:write'
do
    if ! rg -F "$memory_provider_scope" spec/memory-provider-openapi.yaml >/dev/null; then
        echo "memory provider OAuth scope is missing: $memory_provider_scope" >&2
        exit 1
    fi
done

if ! rg -F 'principal, client, workspace, and subject' \
    spec/memory-provider-openapi.yaml >/dev/null ||
    ! rg -F 'path memory_id MUST exactly equal payload.memoryId' \
        spec/memory-provider-openapi.yaml >/dev/null ||
    ! rg -F 'path activity_id MUST exactly equal payload.activityId' \
        spec/memory-provider-openapi.yaml >/dev/null
then
    echo "memory provider HTTP identity-binding invariants are missing" >&2
    exit 1
fi

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
    ! rg -F '/workspaces/key-rotation:' spec/openapi.yaml >/dev/null ||
    ! rg -F '"/v1/workspaces/key-rotation"' apps/rembrane-api/src/main.rs >/dev/null ||
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

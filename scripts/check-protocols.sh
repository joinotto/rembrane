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
jq empty \
    spec/discovery.schema.json \
    spec/examples/discovery.json \
    spec/examples/provider-manifest.json \
    spec/examples/provider-projection.json \
    spec/examples/provider-search-request.json \
    spec/examples/provider-search-response.json \
    spec/provider-manifest.schema.json \
    spec/provider-registry.json \
    spec/provider-registry.schema.json \
    spec/stdio-connection-manifest.schema.json \
    tests/postman/rembrane-local.postman_collection.json
node --check scripts/test-mcp-e2e.mjs
sh -n scripts/test-provider-http.sh
node --check scripts/test-provider-http-runner.mjs
if [ "${REMBRANE_RUN_LOOPBACK_TESTS:-0}" = "1" ]; then
    node scripts/test-provider-http-runner.mjs
fi
if REMBRANE_PROVIDER_BASE_URL=http://provider.example \
    REMBRANE_PROVIDER_TOKEN=test-token \
    ./scripts/test-provider-http.sh static-check >/dev/null 2>&1
then
    echo "provider runner unexpectedly accepted remote plaintext HTTP" >&2
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
        apps/rembrane-mcp/src/main.rs
)
test -n "$implemented_tools"
for tool in $implemented_tools; do
    if ! rg -F "\`$tool\`" spec/mcp.md >/dev/null; then
        echo "implemented MCP tool is undocumented: $tool" >&2
        exit 1
    fi
done

if ! rg -F '/context/resolve:' spec/openapi.yaml >/dev/null ||
    ! rg -F '"/v1/context/resolve"' apps/rembrane-api/src/main.rs >/dev/null
then
    echo "REST context route and OpenAPI contract are inconsistent" >&2
    exit 1
fi

echo "protocol checks passed"

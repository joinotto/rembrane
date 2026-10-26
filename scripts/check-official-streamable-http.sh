#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

manifest=apps/rembrane-mcp/Cargo.toml
source_directory=apps/rembrane-mcp/src

for command in cargo jq rg; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "official MCP SDK readiness checker requires $command" >&2
        exit 1
    }
done

metadata=$(cargo metadata --no-deps --format-version 1 --offline) || {
    echo "official MCP SDK dependency metadata is unavailable" >&2
    exit 1
}

printf '%s\n' "$metadata" | jq -e '
    [
        .packages[]
        | select(.name == "rembrane-mcp")
        | .dependencies[]
        | select(
            .name == "rmcp"
            and .req == "=3.7.0"
            and (.features | index("server")) != null
            and (.features | index("transport-streamable-http-server")) != null
        )
    ]
    | length == 1
' >/dev/null || {
    echo "official MCP SDK Streamable HTTP server feature is not enabled" >&2
    exit 1
}

printf '%s\n' "$metadata" | jq -e '
    [
        .packages[]
        | select(.name == "rembrane-mcp")
        | .dependencies[]
        | select(.name == "rembrane-remote-mcp-http")
    ]
    | length == 1
' >/dev/null || {
    echo "MCP application is not connected to the remote authorization adapter" >&2
    exit 1
}

rg -q '^[[:space:]]*let([[:space:]]+mut)?[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*=[[:space:]]*StreamableHttpService::new' \
    "$source_directory" || {
    echo "official MCP SDK Streamable HTTP service is not instantiated" >&2
    exit 1
}

echo "official MCP SDK Streamable HTTP transport is wired"

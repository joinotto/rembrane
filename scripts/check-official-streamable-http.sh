#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

manifest=apps/rembrane-mcp/Cargo.toml
source_directory=apps/rembrane-mcp/src

rg -q 'transport-streamable-http-server' "$manifest" || {
    echo "official MCP SDK Streamable HTTP server feature is not enabled" >&2
    exit 1
}

rg -q 'rembrane-remote-mcp-http' "$manifest" || {
    echo "MCP application is not connected to the remote authorization adapter" >&2
    exit 1
}

rg -q 'StreamableHttpService::new' "$source_directory" || {
    echo "official MCP SDK Streamable HTTP service is not instantiated" >&2
    exit 1
}

echo "official MCP SDK Streamable HTTP transport is wired"

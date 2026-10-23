#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
domain_manifest="$repository_root/crates/rembrane-domain/Cargo.toml"
domain_source="$repository_root/crates/rembrane-domain/src"

if rg -n '^\[dependencies\]' "$domain_manifest" >/dev/null; then
    echo "rembrane-domain must not declare external or workspace dependencies" >&2
    exit 1
fi

forbidden_pattern='(axum|tokio|sqlx|rusqlite|reqwest|rmcp|mem0|graphiti|supermemory|cloudflare|aws_sdk)'
if rg -n "$forbidden_pattern" "$domain_source"; then
    echo "rembrane-domain contains a forbidden infrastructure dependency" >&2
    exit 1
fi

echo "architecture checks passed"

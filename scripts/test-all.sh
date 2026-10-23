#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "required command is unavailable: $1" >&2
        exit 1
    fi
}

for command in cargo rustc rustfmt sqlite3 jq node postman; do
    require_command "$command"
done

rust_version=$(rustc --version | awk '{ print $2 }')
rust_major=$(printf '%s' "$rust_version" | cut -d. -f1)
rust_minor=$(printf '%s' "$rust_version" | cut -d. -f2)
if test "$rust_major" -lt 1 ||
    { test "$rust_major" -eq 1 && test "$rust_minor" -lt 88; }
then
    echo "Rust 1.88 or newer is required; found $rust_version" >&2
    exit 1
fi

./scripts/check-architecture.sh
./scripts/check-sensitive-files.sh
./scripts/check-protocols.sh
./scripts/test-sqlite-schema.sh
./scripts/test-sqlite-atomicity.sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
./scripts/test-cli-e2e.sh
./scripts/test-mcp-e2e.sh
./scripts/test-rest-e2e.sh

echo "all Rembrane checks passed"

#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

manifest=adapters/rembrane-store-postgres/Cargo.toml
source_directory=adapters/rembrane-store-postgres/src

rg -q '^(tokio-postgres|sqlx|diesel|postgres)[[:space:]]*=' "$manifest" || {
    echo "PostgreSQL adapter has no concrete Rust database driver" >&2
    exit 1
}

rg -q 'pub struct [A-Za-z0-9_]*(Postgres|PostgreSql)[A-Za-z0-9_]*(Pool|Repository)' \
    "$source_directory" || {
    echo "PostgreSQL adapter has no public concrete runtime pool or repository" >&2
    exit 1
}

echo "concrete PostgreSQL runtime adapter is wired"

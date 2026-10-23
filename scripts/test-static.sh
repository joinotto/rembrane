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

./scripts/check-architecture.sh
./scripts/check-sensitive-files.sh
./scripts/check-protocols.sh
./scripts/test-sqlite-schema.sh
./scripts/test-sqlite-atomicity.sh

echo "all static Rembrane checks passed"

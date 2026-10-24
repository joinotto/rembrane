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

for deployment_file in \
    Dockerfile \
    compose.yaml \
    docker/entrypoint.sh \
    scripts/check-local-alpha.sh \
    scripts/test-core-offline.sh
do
    test -s "$deployment_file" || {
        echo "missing deployment artifact: $deployment_file" >&2
        exit 1
    }
done
sh -n scripts/check-local-alpha.sh
sh -n scripts/test-core-offline.sh
rg -q '127\.0\.0\.1:8787:8787' compose.yaml
rg -q 'no-new-privileges:true' compose.yaml
rg -q 'cap_drop:' compose.yaml
if command -v docker >/dev/null 2>&1; then
    REMBRANE_PRINCIPAL_ID=principal_static \
    REMBRANE_WORKSPACE_ID=workspace_static \
    REMBRANE_CLIENT_ID=client_static \
    REMBRANE_WORKSPACE_KEY_ID=key_static \
    REMBRANE_WORKSPACE_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000000 \
    REMBRANE_API_TOKEN=token_static \
        docker compose config --quiet
fi

echo "all static Rembrane checks passed"

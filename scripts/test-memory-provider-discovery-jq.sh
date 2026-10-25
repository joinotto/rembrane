#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
validator="$repository_root/scripts/memory-provider-discovery.jq"
fixture="$repository_root/spec/examples/memory-provider-discovery.json"
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-provider-discovery.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT

jq -e --argjson requiredScopes '[]' -f "$validator" "$fixture" >/dev/null

for mutation in \
    '.unexpected = true' \
    '.privacyMode = "encrypted"' \
    '.limits.maximumContextItems = 0' \
    '.operations[0].oauthScope = "memory:sync:read"' \
    '.operations += [.operations[0]]' \
    'del(.operations[0])'
do
    jq "$mutation" "$fixture" >"$test_directory/invalid.json"
    if jq -e --argjson requiredScopes '[]' \
        -f "$validator" "$test_directory/invalid.json" >/dev/null
    then
        echo "jq discovery validator accepted invalid manifest: $mutation" >&2
        exit 1
    fi
done

echo "memory provider jq discovery validation checks passed"

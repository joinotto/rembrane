#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
validator="$repository_root/scripts/memory-provider-context-result.jq"
fixture="$repository_root/spec/examples/memory-provider-context-response.json"
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-context-result.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT

jq '.result' "$fixture" >"$test_directory/result.json"
jq -e -f "$validator" "$test_directory/result.json" >/dev/null

for mutation in \
    '.providerDebug = "secret"' \
    '.items[0].providerDebug = "secret"' \
    '.items[0].scope = {"scope":"global","entityId":"project"}' \
    '.items[0].evidence[0].secret = "leak"' \
    '.items[0].confidenceMillionths = 1000001' \
    '.items[0].disclosureConstraints += [.items[0].disclosureConstraints[0]]'
do
    jq "$mutation" "$test_directory/result.json" >"$test_directory/invalid.json"
    if jq -e -f "$validator" "$test_directory/invalid.json" >/dev/null
    then
        echo "context-result validator accepted invalid projection: $mutation" >&2
        exit 1
    fi
done

echo "memory provider context result validation checks passed"

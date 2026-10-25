#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
validator="$repository_root/scripts/memory-provider-sync-result.jq"
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-sync-result.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT

jq -cn '{
    changes: [{
        changeId: "change_1",
        sequence: 1,
        resource: "memory",
        resourceId: "memory_1",
        version: 1,
        operation: "upsert",
        payload: "remember this",
        payloadSha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }],
    nextCursor: "cursor_0123456789",
    hasMore: false
}' >"$test_directory/result.json"
jq -e -f "$validator" "$test_directory/result.json" >/dev/null

for mutation in \
    '.providerDebug = "secret"' \
    '.changes[0].providerDebug = "secret"' \
    '.changes[0].operation = "delete"' \
    '.changes[0].payloadSha256 = "invalid"' \
    '.changes += [.changes[0]]' \
    '.changes = [] | .hasMore = true'
do
    jq "$mutation" "$test_directory/result.json" >"$test_directory/invalid.json"
    if jq -e -f "$validator" "$test_directory/invalid.json" >/dev/null
    then
        echo "sync-result validator accepted invalid page: $mutation" >&2
        exit 1
    fi
done

echo "memory provider sync result validation checks passed"

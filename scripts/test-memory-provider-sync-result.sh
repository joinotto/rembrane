#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
verifier="$repository_root/scripts/verify-memory-provider-sync-result.sh"
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-sync-result.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT

jq -cn \
    --arg payloadSha256 "$(
        printf '%s' 'remember this' |
            openssl dgst -sha256 |
            sed 's/^.*= //'
    )" \
    '{
    changes: [{
        changeId: "change_1",
        sequence: 1,
        resource: "memory",
        resourceId: "memory_1",
        version: 1,
        operation: "upsert",
        payload: "remember this",
        payloadSha256: $payloadSha256
    }],
    nextCursor: "cursor_0123456789",
    hasMore: false
}' >"$test_directory/result.json"
"$verifier" "$test_directory/result.json" >/dev/null

for mutation in \
    '.providerDebug = "secret"' \
    '.changes[0].providerDebug = "secret"' \
    '.changes[0].operation = "delete"' \
    '.changes[0].payloadSha256 = "invalid"' \
    '.changes[0].payloadSha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
    '.changes += [.changes[0]]' \
    '.changes = [] | .hasMore = true'
do
    jq "$mutation" "$test_directory/result.json" >"$test_directory/invalid.json"
    if "$verifier" "$test_directory/invalid.json" >/dev/null 2>&1
    then
        echo "sync-result validator accepted invalid page: $mutation" >&2
        exit 1
    fi
done

echo "memory provider sync result validation checks passed"

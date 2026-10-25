#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
input=${1:-}
if [ -z "$input" ] || [ ! -f "$input" ] || [ -L "$input" ] || [ ! -r "$input" ]; then
    echo "usage: verify-memory-provider-sync-result.sh REGULAR_RESULT_FILE" >&2
    exit 1
fi
if [ "$(wc -c <"$input")" -gt 4194304 ]; then
    echo "memory provider sync result exceeds the protocol limit" >&2
    exit 1
fi

jq -e -f "$repository_root/scripts/memory-provider-sync-result.jq" \
    "$input" >/dev/null

rows=$(mktemp "${TMPDIR:-/tmp}/rembrane-sync-payloads.XXXXXX")
trap 'rm -f "$rows"' EXIT
jq -r '
    .changes[]
    | select(.operation == "upsert")
    | [(.payload | @base64), .payloadSha256]
    | @tsv
' "$input" >"$rows"

tab=$(printf '\t')
while IFS="$tab" read -r payload_base64 expected_sha256
do
    actual_sha256=$(
        printf '%s' "$payload_base64" |
            openssl base64 -d -A |
            openssl dgst -sha256 |
            sed 's/^.*= //'
    )
    if [ "$actual_sha256" != "$expected_sha256" ]; then
        echo "memory provider sync payload digest mismatch" >&2
        exit 1
    fi
done <"$rows"

echo "memory provider sync result verified"

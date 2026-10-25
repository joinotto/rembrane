#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-provider-provenance.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

cp "$repository_root/spec/examples/memory-provider-conformance-result.json" \
    "$test_root/result.json"
result_sha256=$(openssl dgst -sha256 "$test_root/result.json" | awk '{print $NF}')
jq --arg digest "$result_sha256" '.resultSha256 = $digest' \
    "$repository_root/spec/examples/memory-provider-external-provenance.json" \
    >"$test_root/provenance.json"
openssl genpkey -algorithm Ed25519 -out "$test_root/private.pem" >/dev/null 2>&1
openssl pkey -in "$test_root/private.pem" -pubout \
    -out "$test_root/public.pem" >/dev/null 2>&1
openssl pkeyutl -sign -inkey "$test_root/private.pem" -rawin \
    -in "$test_root/provenance.json" -out "$test_root/provenance.sig"

verify() {
    node "$repository_root/scripts/verify-memory-provider-external-provenance.mjs" \
        "$1" "$2" "$3" "$4"
}
verify "$test_root/provenance.json" "$test_root/result.json" \
    "$test_root/provenance.sig" "$test_root/public.pem" >/dev/null

jq '.sourceRevision = "3333333333333333333333333333333333333333"' \
    "$test_root/provenance.json" >"$test_root/forged.json"
if verify "$test_root/forged.json" "$test_root/result.json" \
    "$test_root/provenance.sig" "$test_root/public.pem" >/dev/null 2>&1
then
    echo "external provenance accepted a forged source revision" >&2
    exit 1
fi

printf ' ' >>"$test_root/result.json"
if verify "$test_root/provenance.json" "$test_root/result.json" \
    "$test_root/provenance.sig" "$test_root/public.pem" >/dev/null 2>&1
then
    echo "external provenance accepted changed result bytes" >&2
    exit 1
fi

echo "external memory-provider provenance checks passed"

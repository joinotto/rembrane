#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-provider-provenance.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

cp "$repository_root/spec/examples/memory-provider-conformance-result.json" \
    "$test_root/result.json"
result_sha256=$(openssl dgst -sha256 "$test_root/result.json" | awk '{print $NF}')
node "$repository_root/scripts/generate-memory-provider-external-provenance.mjs" \
    "$test_root/result.json" \
    independent-provider-maintainer \
    2222222222222222222222222222222222222222 \
    2026-01-15T11:45:00Z \
    >"$test_root/provenance.json"
jq -e --arg digest "$result_sha256" \
    '.resultSha256 == $digest' "$test_root/provenance.json" >/dev/null
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

ln -s "$test_root/provenance.json" "$test_root/provenance-link.json"
if verify "$test_root/provenance-link.json" "$test_root/result.json" \
    "$test_root/provenance.sig" "$test_root/public.pem" >/dev/null 2>&1
then
    echo "external provenance verifier accepted a symbolic input" >&2
    exit 1
fi

if node "$repository_root/scripts/generate-memory-provider-external-provenance.mjs" \
    "$test_root/result.json" \
    independent-provider-maintainer \
    2222222222222222222222222222222222222222 \
    2999-01-01T00:00:00Z >/dev/null 2>&1
then
    echo "external provenance generator accepted a future signing time" >&2
    exit 1
fi

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

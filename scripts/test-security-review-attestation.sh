#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-review-attestation.XXXXXX")

cleanup() {
    rm -rf "$test_root"
}
trap cleanup EXIT HUP INT TERM

fixture="$repository_root/spec/examples/security-review-attestation.json"
verifier="$repository_root/scripts/verify-security-review-attestation.mjs"
node "$verifier" "$fixture" >/dev/null

jq '.reviewer.independent = false' "$fixture" >"$test_root/dependent.json"
if node "$verifier" "$test_root/dependent.json" >/dev/null 2>&1; then
    echo "review attestation accepted a non-independent reviewer" >&2
    exit 1
fi

jq '.findings.unresolved = 1' "$fixture" >"$test_root/unresolved.json"
if node "$verifier" "$test_root/unresolved.json" >/dev/null 2>&1; then
    echo "approved review attestation accepted unresolved findings" >&2
    exit 1
fi

jq '.scope.exclusions = ["authentication"]' "$fixture" >"$test_root/excluded.json"
if node "$verifier" "$test_root/excluded.json" >/dev/null 2>&1; then
    echo "approved review attestation accepted scope exclusions" >&2
    exit 1
fi

jq '.unexpected = true' "$fixture" >"$test_root/unknown.json"
if node "$verifier" "$test_root/unknown.json" >/dev/null 2>&1; then
    echo "review attestation accepted an unknown field" >&2
    exit 1
fi

echo "security review attestation checks passed"

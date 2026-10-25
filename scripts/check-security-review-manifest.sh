#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-security-review.XXXXXX")

cleanup() {
    rm -rf "$test_root"
}
trap cleanup EXIT

node "$repository_root/scripts/generate-security-review-manifest.mjs" \
    --allow-dirty >"$test_root/first.json"
node "$repository_root/scripts/generate-security-review-manifest.mjs" \
    --allow-dirty >"$test_root/second.json"
cmp "$test_root/first.json" "$test_root/second.json"
node "$repository_root/scripts/verify-security-review-manifest.mjs" \
    "$test_root/first.json" >/dev/null

for required in \
    Cargo.lock \
    Dockerfile \
    compose.yaml \
    docs/THREAT_MODEL.md \
    scripts/generate-security-review-manifest.mjs \
    scripts/test-static.sh \
    apps/rembrane-api/src/main.rs \
    crates/rembrane-application/src/lib.rs \
    crates/rembrane-crypto/src/lib.rs \
    migrations/postgres/0001_canonical_schema.sql \
    spec/memory-provider.schema.json
do
    jq -e --arg path "$required" \
        'any(.files[]; .path == $path)' "$test_root/first.json" >/dev/null
done

echo "security review manifest checks passed"

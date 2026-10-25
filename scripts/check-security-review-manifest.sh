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

jq -e '
    def safe_path:
        type == "string"
        and length > 0
        and length <= 4096
        and test("^[A-Za-z0-9._@+/-]+$")
        and (test("(^|/)\\.\\.?(/|$)") | not);
    .schemaVersion == 1
    and (.sourceRevision | test("^[0-9a-f]{40}$"))
    and (.workingTreeDirty | type == "boolean")
    and (.files | length > 0)
    and ([.files[].path] == ([.files[].path] | sort))
    and (([.files[].path] | unique | length) == (.files | length))
    and all(
        .files[];
        (.path | safe_path)
        and (.bytes | type == "number" and . >= 0)
        and (.sha256 | test("^[0-9a-f]{64}$"))
    )
' "$test_root/first.json" >/dev/null

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

#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-semantic-compatibility.XXXXXX")
trap 'rm -rf "$test_root"' EXIT

mkdir -p "$test_root/scripts" "$test_root/spec"
cp "$repository_root/scripts/verify-semantic-provider-compatibility.mjs" "$test_root/scripts/"
cp "$repository_root/spec/semantic-provider-compatibility-lock.json" "$test_root/spec/"
jq -r '.artifacts[].path' "$repository_root/spec/semantic-provider-compatibility-lock.json" |
while IFS= read -r artifact; do
    mkdir -p "$test_root/$(dirname "$artifact")"
    cp "$repository_root/$artifact" "$test_root/$artifact"
done

node "$test_root/scripts/verify-semantic-provider-compatibility.mjs" >/dev/null

printf '\n' >>"$test_root/spec/provider-openapi.yaml"
if node "$test_root/scripts/verify-semantic-provider-compatibility.mjs" >/dev/null 2>&1; then
    echo "semantic compatibility verifier accepted a tampered protocol" >&2
    exit 1
fi

cp "$repository_root/spec/provider-openapi.yaml" "$test_root/spec/provider-openapi.yaml"
jq 'del(.artifacts[-1])' "$repository_root/spec/semantic-provider-compatibility-lock.json" \
    >"$test_root/spec/semantic-provider-compatibility-lock.json"
if node "$test_root/scripts/verify-semantic-provider-compatibility.mjs" >/dev/null 2>&1; then
    echo "semantic compatibility verifier accepted an omitted artifact" >&2
    exit 1
fi

cp "$repository_root/spec/semantic-provider-compatibility-lock.json" \
    "$test_root/spec/semantic-provider-compatibility-lock.json"
jq '.cases = ([.cases[1], .cases[0]] + .cases[2:])' \
    "$repository_root/spec/examples/semantic-provider-conformance-result.json" \
    >"$test_root/spec/examples/semantic-provider-conformance-result.json"
result_hash=$(node -e 'const c=require("node:crypto"),f=require("node:fs");process.stdout.write(c.createHash("sha256").update(f.readFileSync(process.argv[1])).digest("hex"))' "$test_root/spec/examples/semantic-provider-conformance-result.json")
jq --arg hash "$result_hash" '
    .artifacts |= map(if .path == "spec/examples/semantic-provider-conformance-result.json"
        then .sha256 = $hash else . end)
' "$repository_root/spec/semantic-provider-compatibility-lock.json" \
    >"$test_root/spec/semantic-provider-compatibility-lock.json"
if node "$test_root/scripts/verify-semantic-provider-compatibility.mjs" >/dev/null 2>&1; then
    echo "semantic compatibility verifier accepted reordered cases" >&2
    exit 1
fi

echo "semantic provider compatibility tamper test passed"

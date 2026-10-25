#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-memory-compatibility.XXXXXX")

cleanup() {
    rm -rf "$test_root"
}
trap cleanup EXIT

mkdir -p "$test_root/scripts" "$test_root/spec"
cp "$repository_root/scripts/verify-memory-provider-compatibility.mjs" \
    "$test_root/scripts/"
cp "$repository_root/spec/memory-provider-compatibility-lock.json" \
    "$test_root/spec/"

jq -r '.artifacts[].path' \
    "$repository_root/spec/memory-provider-compatibility-lock.json" |
while IFS= read -r artifact; do
    case "$artifact" in
        spec/* | scripts/*) ;;
        *)
            echo "compatibility fixture contains an unsafe path: $artifact" >&2
            exit 1
            ;;
    esac
    mkdir -p "$test_root/$(dirname "$artifact")"
    cp "$repository_root/$artifact" "$test_root/$artifact"
done

node "$test_root/scripts/verify-memory-provider-compatibility.mjs" >/dev/null

printf '\n' >>"$test_root/spec/memory-provider.schema.json"
if node "$test_root/scripts/verify-memory-provider-compatibility.mjs" \
    >"$test_root/tamper.stdout" 2>"$test_root/tamper.stderr"
then
    echo "compatibility verifier accepted a tampered canonical schema" >&2
    exit 1
fi
if ! rg -F \
    "changed without a reviewed compatibility-lock update" \
    "$test_root/tamper.stderr" >/dev/null
then
    echo "compatibility verifier did not report the tampered artifact" >&2
    exit 1
fi

cp "$repository_root/spec/memory-provider.schema.json" \
    "$test_root/spec/memory-provider.schema.json"
jq 'del(.artifacts[-1])' \
    "$repository_root/spec/memory-provider-compatibility-lock.json" \
    >"$test_root/spec/memory-provider-compatibility-lock.json"
if node "$test_root/scripts/verify-memory-provider-compatibility.mjs" \
    >"$test_root/removal.stdout" 2>"$test_root/removal.stderr"
then
    echo "compatibility verifier accepted a lock with a removed artifact" >&2
    exit 1
fi
if ! rg -F \
    "compatibility lock has an unexpected artifact set" \
    "$test_root/removal.stderr" >/dev/null
then
    echo "compatibility verifier did not report the removed artifact" >&2
    exit 1
fi

cp "$repository_root/spec/memory-provider-compatibility-lock.json" \
    "$test_root/spec/memory-provider-compatibility-lock.json"
jq '.profileId = "attacker.rebound-profile"' \
    "$repository_root/spec/examples/memory-provider-conformance-result.json" \
    >"$test_root/spec/examples/memory-provider-conformance-result.json"
rebound_hash=$(
    node -e '
        const {createHash} = require("node:crypto");
        const {readFileSync} = require("node:fs");
        process.stdout.write(
            createHash("sha256").update(readFileSync(process.argv[1])).digest("hex")
        );
    ' "$test_root/spec/examples/memory-provider-conformance-result.json"
)
jq --arg hash "$rebound_hash" '
    .artifacts |= map(
        if .path == "spec/examples/memory-provider-conformance-result.json"
        then .sha256 = $hash
        else .
        end
    )
' "$repository_root/spec/memory-provider-compatibility-lock.json" \
    >"$test_root/spec/memory-provider-compatibility-lock.json"
if node "$test_root/scripts/verify-memory-provider-compatibility.mjs" \
    >"$test_root/rebound.stdout" 2>"$test_root/rebound.stderr"
then
    echo "memory-provider compatibility verifier accepted rebound evidence" >&2
    exit 1
fi
if ! rg -F \
    "result fixture is bound to a different profile" \
    "$test_root/rebound.stderr" >/dev/null
then
    echo "memory-provider compatibility verifier missed rebound evidence" >&2
    exit 1
fi

cp "$repository_root/spec/memory-provider-compatibility-lock.json" \
    "$test_root/spec/memory-provider-compatibility-lock.json"
jq '.cases = ([.cases[1], .cases[0]] + .cases[2:])' \
    "$repository_root/spec/examples/memory-provider-conformance-result.json" \
    >"$test_root/spec/examples/memory-provider-conformance-result.json"
reordered_hash=$(
    node -e '
        const {createHash} = require("node:crypto");
        const {readFileSync} = require("node:fs");
        process.stdout.write(
            createHash("sha256").update(readFileSync(process.argv[1])).digest("hex")
        );
    ' "$test_root/spec/examples/memory-provider-conformance-result.json"
)
jq --arg hash "$reordered_hash" '
    .artifacts |= map(
        if .path == "spec/examples/memory-provider-conformance-result.json"
        then .sha256 = $hash
        else .
        end
    )
' "$repository_root/spec/memory-provider-compatibility-lock.json" \
    >"$test_root/spec/memory-provider-compatibility-lock.json"
if node "$test_root/scripts/verify-memory-provider-compatibility.mjs" \
    >"$test_root/reordered.stdout" 2>"$test_root/reordered.stderr"
then
    echo "memory-provider compatibility verifier accepted reordered cases" >&2
    exit 1
fi
if ! rg -F \
    "result fixture cases differ from the reviewed profile" \
    "$test_root/reordered.stderr" >/dev/null
then
    echo "memory-provider compatibility verifier missed reordered cases" >&2
    exit 1
fi

echo "memory provider compatibility tamper test passed"

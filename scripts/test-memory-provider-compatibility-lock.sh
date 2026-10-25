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
        spec/*) ;;
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

echo "memory provider compatibility tamper test passed"

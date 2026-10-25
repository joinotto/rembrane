#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-key-compatibility.XXXXXX")

cleanup() {
    rm -rf "$test_root"
}
trap cleanup EXIT

mkdir -p "$test_root/scripts" "$test_root/spec"
cp "$repository_root/scripts/verify-key-provider-compatibility.mjs" \
    "$test_root/scripts/"
cp "$repository_root/spec/key-provider-compatibility-lock.json" \
    "$test_root/spec/"

jq -r '.artifacts[].path' \
    "$repository_root/spec/key-provider-compatibility-lock.json" |
while IFS= read -r artifact; do
    case "$artifact" in
        spec/* | scripts/*) ;;
        *)
            echo "key-provider compatibility lock has an unsafe path: $artifact" >&2
            exit 1
            ;;
    esac
    mkdir -p "$test_root/$(dirname "$artifact")"
    cp "$repository_root/$artifact" "$test_root/$artifact"
done

node "$test_root/scripts/verify-key-provider-compatibility.mjs" >/dev/null

printf '\n' >>"$test_root/spec/key-provider-openapi.yaml"
if node "$test_root/scripts/verify-key-provider-compatibility.mjs" \
    >"$test_root/tamper.stdout" 2>"$test_root/tamper.stderr"
then
    echo "key-provider compatibility verifier accepted a tampered protocol" >&2
    exit 1
fi
if ! rg -F \
    "changed without a reviewed compatibility-lock update" \
    "$test_root/tamper.stderr" >/dev/null
then
    echo "key-provider compatibility verifier missed the tampered artifact" >&2
    exit 1
fi

cp "$repository_root/spec/key-provider-openapi.yaml" \
    "$test_root/spec/key-provider-openapi.yaml"
jq 'del(.artifacts[-1])' \
    "$repository_root/spec/key-provider-compatibility-lock.json" \
    >"$test_root/spec/key-provider-compatibility-lock.json"
if node "$test_root/scripts/verify-key-provider-compatibility.mjs" \
    >"$test_root/omission.stdout" 2>"$test_root/omission.stderr"
then
    echo "key-provider compatibility verifier accepted an omitted artifact" >&2
    exit 1
fi
if ! rg -F \
    "exact reviewed key-provider artifact set" \
    "$test_root/omission.stderr" >/dev/null
then
    echo "key-provider compatibility verifier missed artifact omission" >&2
    exit 1
fi

echo "key provider compatibility tamper test passed"

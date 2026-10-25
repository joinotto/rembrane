#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-memory-versions.XXXXXX")

cleanup() {
    rm -rf "$test_root"
}
trap cleanup EXIT HUP INT TERM

profile_sha256=$(openssl dgst -sha256 \
    "$repository_root/spec/conformance/memory-provider-core.json" |
    awk '{print $NF}')
fixture_sha256=$(openssl dgst -sha256 \
    "$repository_root/spec/conformance/memory-provider-core-fixtures.json" |
    awk '{print $NF}')

jq --arg profile "$profile_sha256" --arg fixture "$fixture_sha256" \
    '.profileSha256 = $profile | .fixtureSha256 = $fixture' \
    "$repository_root/spec/examples/memory-provider-mixed-version-evidence.json" \
    >"$test_root/evidence.json"

verify() {
    node "$repository_root/scripts/verify-memory-provider-mixed-version-evidence.mjs" \
        "$1"
}

verify "$test_root/evidence.json" >/dev/null

jq '.runs[0].result = "rejected"' "$test_root/evidence.json" \
    >"$test_root/old-client-rejected.json"
if verify "$test_root/old-client-rejected.json" >/dev/null 2>&1; then
    echo "mixed-version evidence accepted rejected compatible client" >&2
    exit 1
fi

jq '.runs[2].result = "pass"' "$test_root/evidence.json" \
    >"$test_root/major-accepted.json"
if verify "$test_root/major-accepted.json" >/dev/null 2>&1; then
    echo "mixed-version evidence accepted unsupported major" >&2
    exit 1
fi

jq '.runs[1].namespace = .runs[0].namespace' "$test_root/evidence.json" \
    >"$test_root/reused-namespace.json"
if verify "$test_root/reused-namespace.json" >/dev/null 2>&1; then
    echo "mixed-version evidence accepted a reused namespace" >&2
    exit 1
fi

jq '.newestSupportedMinor = "1.0"' "$test_root/evidence.json" \
    >"$test_root/not-mixed.json"
if verify "$test_root/not-mixed.json" >/dev/null 2>&1; then
    echo "mixed-version evidence accepted a single minor version" >&2
    exit 1
fi

jq '.runs[0].unexpected = true' "$test_root/evidence.json" \
    >"$test_root/unknown-field.json"
if verify "$test_root/unknown-field.json" >/dev/null 2>&1; then
    echo "mixed-version evidence accepted an unknown field" >&2
    exit 1
fi

echo "memory-provider mixed-version evidence checks passed"

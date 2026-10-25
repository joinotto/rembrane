#!/bin/sh
set -eu

bundle=${1:?usage: verify-security-review-bundle.sh BUNDLE_DIRECTORY PUBLIC_KEY}
public_key=${2:?usage: verify-security-review-bundle.sh BUNDLE_DIRECTORY PUBLIC_KEY}
repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ ! -d "$bundle" ] || [ -L "$bundle" ]; then
    echo "security review bundle must be a non-symbolic directory" >&2
    exit 1
fi

node -e '
    const { lstatSync, readdirSync } = require("node:fs");
    const { join } = require("node:path");
    const expected = [
        "security-review-attestation.json",
        "security-review-attestation.json.sha256",
        "security-review-attestation.json.sig",
        "security-review-manifest.json",
        "security-review-manifest.json.sha256",
        "security-review-manifest.json.sig",
    ];
    const actual = readdirSync(process.argv[1]).sort();
    if (actual.length !== expected.length ||
        actual.some((name, index) => name !== expected[index])) {
        throw new Error("security review bundle contains unexpected artifacts");
    }
    for (const name of actual) {
        const metadata = lstatSync(join(process.argv[1], name));
        if (!metadata.isFile() || metadata.isSymbolicLink()) {
            throw new Error("security review bundle artifacts must be regular files");
        }
    }
' "$bundle"

for name in \
    security-review-manifest.json \
    security-review-manifest.json.sha256 \
    security-review-manifest.json.sig \
    security-review-attestation.json \
    security-review-attestation.json.sha256 \
    security-review-attestation.json.sig
do
    if [ ! -f "$bundle/$name" ] || [ -L "$bundle/$name" ]; then
        echo "security review bundle artifact is missing or symbolic: $name" >&2
        exit 1
    fi
done

node "$repository_root/scripts/verify-security-review-manifest.mjs" \
    "$bundle/security-review-manifest.json" >/dev/null
node "$repository_root/scripts/verify-security-review-attestation.mjs" \
    "$bundle/security-review-attestation.json" >/dev/null

verify_checksum() {
    file=$1
    checksum=$2
    expected_name=$3
    actual=$(openssl dgst -sha256 "$file" | awk '{print $NF}')
    expected_record=$(printf '%s  %s' "$actual" "$expected_name")
    recorded_bytes=$(wc -c <"$checksum" | tr -d ' ')
    expected_bytes=$((${#expected_record} + 1))
    if [ "$recorded_bytes" -ne "$expected_bytes" ] ||
        [ "$(cat "$checksum")" != "$expected_record" ]
    then
        echo "security review bundle checksum is invalid: $expected_name" >&2
        exit 1
    fi
}

verify_checksum \
    "$bundle/security-review-manifest.json" \
    "$bundle/security-review-manifest.json.sha256" \
    security-review-manifest.json
verify_checksum \
    "$bundle/security-review-attestation.json" \
    "$bundle/security-review-attestation.json.sha256" \
    security-review-attestation.json

manifest_sha256=$(
    openssl dgst -sha256 "$bundle/security-review-manifest.json" |
        awk '{print $NF}'
)
jq -e \
    --arg digest "$manifest_sha256" \
    --arg revision "$(jq -r '.sourceRevision' "$bundle/security-review-manifest.json")" \
    --argjson file_count "$(jq -r '.files | length' "$bundle/security-review-manifest.json")" \
    '.manifestSha256 == $digest
     and .sourceRevision == $revision
     and .scope.manifestFileCount == $file_count' \
    "$bundle/security-review-attestation.json" >/dev/null

sh "$repository_root/scripts/verify-security-review-signature.sh" \
    "$bundle/security-review-manifest.json" \
    "$bundle/security-review-manifest.json.sig" \
    "$public_key" >/dev/null
sh "$repository_root/scripts/verify-security-review-signature.sh" \
    "$bundle/security-review-attestation.json" \
    "$bundle/security-review-attestation.json.sig" \
    "$public_key" >/dev/null

echo "security review bundle verified: $bundle"

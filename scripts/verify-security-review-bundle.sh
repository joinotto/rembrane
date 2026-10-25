#!/bin/sh
set -eu

bundle=${1:?usage: verify-security-review-bundle.sh BUNDLE_DIRECTORY PUBLIC_KEY}
public_key=${2:?usage: verify-security-review-bundle.sh BUNDLE_DIRECTORY PUBLIC_KEY}
repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ ! -d "$bundle" ] || [ -L "$bundle" ]; then
    echo "security review bundle must be a non-symbolic directory" >&2
    exit 1
fi
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
    expected=$(awk 'NR == 1 { print $1 }' "$checksum")
    recorded_name=$(awk 'NR == 1 { print $2 }' "$checksum")
    actual=$(openssl dgst -sha256 "$file" | awk '{print $NF}')
    if [ "$expected" != "$actual" ] || [ "$recorded_name" != "$expected_name" ] ||
        [ "$(wc -l <"$checksum" | tr -d ' ')" != 1 ]
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

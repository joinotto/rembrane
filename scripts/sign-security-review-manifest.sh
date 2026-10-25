#!/bin/sh
set -eu

manifest=${1:?usage: sign-security-review-manifest.sh MANIFEST OUTPUT_DIRECTORY}
output_directory=${2:?usage: sign-security-review-manifest.sh MANIFEST OUTPUT_DIRECTORY}
private_key=${REMBRANE_SECURITY_REVIEW_SIGNING_KEY:-}
repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -z "$private_key" ]; then
    echo "REMBRANE_SECURITY_REVIEW_SIGNING_KEY must name an Ed25519 PEM private key" >&2
    exit 1
fi
if [ ! -f "$private_key" ] || [ -L "$private_key" ]; then
    echo "security review signing key must be a regular non-symbolic file" >&2
    exit 1
fi
private_key_mode=$(
    stat -f '%Lp' "$private_key" 2>/dev/null ||
        stat -c '%a' "$private_key" 2>/dev/null
)
case "$private_key_mode" in
    400 | 600) ;;
    *)
        echo "security review signing key must be owner-only (0400 or 0600)" >&2
        exit 1
        ;;
esac
node "$repository_root/scripts/verify-security-review-manifest.mjs" \
    "$manifest" --verify-repository >/dev/null

umask 077
if [ -e "$output_directory" ] || [ -L "$output_directory" ]; then
    echo "security review output directory must not already exist" >&2
    exit 1
fi
mkdir "$output_directory"
chmod 700 "$output_directory"

cp "$manifest" "$output_directory/security-review-manifest.json"
node "$repository_root/scripts/verify-security-review-manifest.mjs" \
    "$output_directory/security-review-manifest.json" \
    --verify-repository >/dev/null
manifest_sha256=$(
    openssl dgst -sha256 "$output_directory/security-review-manifest.json" |
        awk '{print $NF}'
)
printf '%s  %s\n' "$manifest_sha256" security-review-manifest.json \
    >"$output_directory/security-review-manifest.json.sha256"
openssl pkeyutl -sign -rawin \
    -inkey "$private_key" \
    -in "$output_directory/security-review-manifest.json" \
    -out "$output_directory/security-review-manifest.json.sig"

echo "signed security review artifacts written to: $output_directory"

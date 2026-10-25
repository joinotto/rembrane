#!/bin/sh
set -eu

manifest=${1:?usage: sign-security-review-manifest.sh MANIFEST OUTPUT_DIRECTORY [ATTESTATION]}
output_directory=${2:?usage: sign-security-review-manifest.sh MANIFEST OUTPUT_DIRECTORY [ATTESTATION]}
attestation=${3:-}
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
if [ -n "$attestation" ]; then
    node "$repository_root/scripts/verify-security-review-attestation.mjs" \
        "$attestation" >/dev/null
    node "$repository_root/scripts/verify-security-review-correlation.mjs" \
        "$manifest" "$attestation" >/dev/null
fi

umask 077
if [ -e "$output_directory" ] || [ -L "$output_directory" ]; then
    echo "security review output directory must not already exist" >&2
    exit 1
fi
mkdir "$output_directory"
chmod 700 "$output_directory"
complete=0
verification_public_key=
cleanup() {
    if [ -n "$verification_public_key" ]; then
        rm -f "$verification_public_key"
    fi
    if [ "$complete" != 1 ]; then
        rm -rf "$output_directory"
    fi
}
trap cleanup EXIT HUP INT TERM

cp "$manifest" "$output_directory/security-review-manifest.json"
node "$repository_root/scripts/verify-security-review-manifest.mjs" \
    "$output_directory/security-review-manifest.json" \
    --verify-repository >/dev/null
manifest_sha256=$(
    node "$repository_root/scripts/sha256-bounded-file.mjs" \
        "$output_directory/security-review-manifest.json" 16777216
)
printf '%s  %s\n' "$manifest_sha256" security-review-manifest.json \
    >"$output_directory/security-review-manifest.json.sha256"
node "$repository_root/scripts/sign-ed25519-document.mjs" \
    "$output_directory/security-review-manifest.json" \
    "$private_key" \
    "$output_directory/security-review-manifest.json.sig"

if [ -n "$attestation" ]; then
    cp "$attestation" "$output_directory/security-review-attestation.json"
    node "$repository_root/scripts/verify-security-review-attestation.mjs" \
        "$output_directory/security-review-attestation.json" >/dev/null
    node "$repository_root/scripts/verify-security-review-correlation.mjs" \
        "$output_directory/security-review-manifest.json" \
        "$output_directory/security-review-attestation.json" >/dev/null
    attestation_sha256=$(
        node "$repository_root/scripts/sha256-bounded-file.mjs" \
            "$output_directory/security-review-attestation.json" 65536
    )
    printf '%s  %s\n' "$attestation_sha256" security-review-attestation.json \
        >"$output_directory/security-review-attestation.json.sha256"
    node "$repository_root/scripts/sign-ed25519-document.mjs" \
        "$output_directory/security-review-attestation.json" \
        "$private_key" \
        "$output_directory/security-review-attestation.json.sig"
fi

find "$output_directory" -type f -exec chmod 600 {} +
verification_public_key=$(mktemp "${TMPDIR:-/tmp}/rembrane-review-public.XXXXXX")
chmod 600 "$verification_public_key"
rm -f "$verification_public_key"
node "$repository_root/scripts/derive-ed25519-public-key.mjs" \
    "$private_key" "$verification_public_key"
if [ -n "$attestation" ]; then
    sh "$repository_root/scripts/verify-security-review-bundle.sh" \
        "$output_directory" "$verification_public_key" \
        --verify-repository >/dev/null
else
    sh "$repository_root/scripts/verify-security-review-signature.sh" \
        "$output_directory/security-review-manifest.json" \
        "$output_directory/security-review-manifest.json.sig" \
        "$verification_public_key" >/dev/null
fi

complete=1
echo "signed security review artifacts written to: $output_directory"

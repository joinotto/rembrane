#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-review-signing.XXXXXX")

cleanup() {
    rm -rf "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

openssl genpkey -algorithm Ed25519 \
    -out "$temporary_directory/private.pem" >/dev/null 2>&1
openssl pkey -in "$temporary_directory/private.pem" -pubout \
    -out "$temporary_directory/public.pem" >/dev/null 2>&1

cat >"$temporary_directory/manifest.json" <<'EOF'
{
  "schemaVersion": 1,
  "sourceRevision": "1111111111111111111111111111111111111111",
  "workingTreeDirty": false,
  "files": [
    {
      "path": "SECURITY.md",
      "bytes": 1,
      "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ]
}
EOF

REMBRANE_SECURITY_REVIEW_SIGNING_KEY="$temporary_directory/private.pem" \
    sh "$repository_root/scripts/sign-security-review-manifest.sh" \
    "$temporary_directory/manifest.json" \
    "$temporary_directory/signed" >/dev/null

sh "$repository_root/scripts/verify-security-review-signature.sh" \
    "$temporary_directory/signed/security-review-manifest.json" \
    "$temporary_directory/signed/security-review-manifest.json.sig" \
    "$temporary_directory/public.pem" >/dev/null

cp "$temporary_directory/signed/security-review-manifest.json" \
    "$temporary_directory/tampered.json"
printf '\n' >>"$temporary_directory/tampered.json"
if sh "$repository_root/scripts/verify-security-review-signature.sh" \
    "$temporary_directory/tampered.json" \
    "$temporary_directory/signed/security-review-manifest.json.sig" \
    "$temporary_directory/public.pem" >/dev/null 2>&1
then
    echo "security review signature accepted tampered manifest bytes" >&2
    exit 1
fi

if REMBRANE_SECURITY_REVIEW_SIGNING_KEY="$temporary_directory/private.pem" \
    sh "$repository_root/scripts/sign-security-review-manifest.sh" \
    "$temporary_directory/manifest.json" \
    "$temporary_directory/signed" >/dev/null 2>&1
then
    echo "security review signer overwrote existing evidence" >&2
    exit 1
fi

echo "security review signing test passed"

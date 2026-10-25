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
chmod 600 "$temporary_directory/private.pem"
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

cp "$temporary_directory/private.pem" "$temporary_directory/permissive.pem"
chmod 644 "$temporary_directory/permissive.pem"
if REMBRANE_SECURITY_REVIEW_SIGNING_KEY="$temporary_directory/permissive.pem" \
    sh "$repository_root/scripts/sign-security-review-manifest.sh" \
    "$temporary_directory/manifest.json" \
    "$temporary_directory/permissive-output" >/dev/null 2>&1
then
    echo "security review signer accepted a permissive private key" >&2
    exit 1
fi

jq '.workingTreeDirty = true' "$temporary_directory/manifest.json" \
    >"$temporary_directory/dirty.json"
if REMBRANE_SECURITY_REVIEW_SIGNING_KEY="$temporary_directory/private.pem" \
    sh "$repository_root/scripts/sign-security-review-manifest.sh" \
    "$temporary_directory/dirty.json" \
    "$temporary_directory/dirty-output" >/dev/null 2>&1
then
    echo "security review signer accepted a dirty-worktree manifest" >&2
    exit 1
fi

jq '.files[0].path = "../SECURITY.md"' "$temporary_directory/manifest.json" \
    >"$temporary_directory/unsafe-path.json"
if REMBRANE_SECURITY_REVIEW_SIGNING_KEY="$temporary_directory/private.pem" \
    sh "$repository_root/scripts/sign-security-review-manifest.sh" \
    "$temporary_directory/unsafe-path.json" \
    "$temporary_directory/unsafe-path-output" >/dev/null 2>&1
then
    echo "security review signer accepted an unsafe manifest path" >&2
    exit 1
fi

mkdir "$temporary_directory/real-output"
ln -s "$temporary_directory/real-output" "$temporary_directory/symbolic-output"
if REMBRANE_SECURITY_REVIEW_SIGNING_KEY="$temporary_directory/private.pem" \
    sh "$repository_root/scripts/sign-security-review-manifest.sh" \
    "$temporary_directory/manifest.json" \
    "$temporary_directory/symbolic-output" >/dev/null 2>&1
then
    echo "security review signer accepted a symbolic output directory" >&2
    exit 1
fi

echo "security review signing test passed"

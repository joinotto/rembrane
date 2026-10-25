#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-review-signing.XXXXXX")
review_repository="$temporary_directory/repository"

cleanup() {
    rm -rf "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$review_repository/scripts"
for script in \
    generate-security-review-manifest.mjs \
    verify-security-review-manifest.mjs \
    verify-security-review-attestation.mjs \
    sign-security-review-manifest.sh \
    verify-security-review-signature.sh \
    verify-security-review-bundle.sh
do
    cp "$repository_root/scripts/$script" "$review_repository/scripts/$script"
done
printf '%s\n' '# Security policy fixture' >"$review_repository/SECURITY.md"
git -C "$review_repository" init -q
git -C "$review_repository" config user.name "Rembrane Test"
git -C "$review_repository" config user.email "test@rembrane.invalid"
git -C "$review_repository" add .
git -C "$review_repository" commit -q -m "test fixture"

(
    cd "$review_repository"
    node scripts/generate-security-review-manifest.mjs \
        >"$temporary_directory/manifest.json"
)
node "$review_repository/scripts/verify-security-review-manifest.mjs" \
    "$temporary_directory/manifest.json" --verify-repository >/dev/null
manifest_sha256=$(
    openssl dgst -sha256 "$temporary_directory/manifest.json" |
        awk '{print $NF}'
)
jq -n \
    --arg revision "$(jq -r '.sourceRevision' "$temporary_directory/manifest.json")" \
    --arg digest "$manifest_sha256" \
    --argjson file_count "$(jq -r '.files | length' "$temporary_directory/manifest.json")" \
    '{
        schemaVersion: 1,
        sourceRevision: $revision,
        manifestSha256: $digest,
        reviewedAt: "2026-01-15T12:00:00Z",
        reviewer: {
            id: "independent-reviewer",
            independent: true
        },
        scope: {
            manifestFileCount: $file_count,
            exclusions: []
        },
        findings: {
            critical: 0,
            high: 0,
            moderate: 0,
            low: 0,
            informational: 0,
            unresolved: 0
        },
        disposition: "approved"
    }' >"$temporary_directory/attestation.json"

openssl genpkey -algorithm Ed25519 \
    -out "$temporary_directory/private.pem" >/dev/null 2>&1
chmod 600 "$temporary_directory/private.pem"
openssl pkey -in "$temporary_directory/private.pem" -pubout \
    -out "$temporary_directory/public.pem" >/dev/null 2>&1

REMBRANE_SECURITY_REVIEW_SIGNING_KEY="$temporary_directory/private.pem" \
    sh "$review_repository/scripts/sign-security-review-manifest.sh" \
    "$temporary_directory/manifest.json" \
    "$temporary_directory/signed" \
    "$temporary_directory/attestation.json" >/dev/null

sh "$review_repository/scripts/verify-security-review-bundle.sh" \
    "$temporary_directory/signed" \
    "$temporary_directory/public.pem" >/dev/null

cp "$temporary_directory/signed/security-review-manifest.json" \
    "$temporary_directory/tampered.json"
printf '\n' >>"$temporary_directory/tampered.json"
if sh "$review_repository/scripts/verify-security-review-signature.sh" \
    "$temporary_directory/tampered.json" \
    "$temporary_directory/signed/security-review-manifest.json.sig" \
    "$temporary_directory/public.pem" >/dev/null 2>&1
then
    echo "security review signature accepted tampered manifest bytes" >&2
    exit 1
fi

if REMBRANE_SECURITY_REVIEW_SIGNING_KEY="$temporary_directory/private.pem" \
    sh "$review_repository/scripts/sign-security-review-manifest.sh" \
    "$temporary_directory/manifest.json" \
    "$temporary_directory/signed" >/dev/null 2>&1
then
    echo "security review signer overwrote existing evidence" >&2
    exit 1
fi

cp "$temporary_directory/private.pem" "$temporary_directory/permissive.pem"
chmod 644 "$temporary_directory/permissive.pem"
if REMBRANE_SECURITY_REVIEW_SIGNING_KEY="$temporary_directory/permissive.pem" \
    sh "$review_repository/scripts/sign-security-review-manifest.sh" \
    "$temporary_directory/manifest.json" \
    "$temporary_directory/permissive-output" >/dev/null 2>&1
then
    echo "security review signer accepted a permissive private key" >&2
    exit 1
fi

jq '.workingTreeDirty = true' "$temporary_directory/manifest.json" \
    >"$temporary_directory/dirty.json"
if REMBRANE_SECURITY_REVIEW_SIGNING_KEY="$temporary_directory/private.pem" \
    sh "$review_repository/scripts/sign-security-review-manifest.sh" \
    "$temporary_directory/dirty.json" \
    "$temporary_directory/dirty-output" >/dev/null 2>&1
then
    echo "security review signer accepted a dirty-worktree manifest" >&2
    exit 1
fi

jq '.files[0].path = "../SECURITY.md"' "$temporary_directory/manifest.json" \
    >"$temporary_directory/unsafe-path.json"
if REMBRANE_SECURITY_REVIEW_SIGNING_KEY="$temporary_directory/private.pem" \
    sh "$review_repository/scripts/sign-security-review-manifest.sh" \
    "$temporary_directory/unsafe-path.json" \
    "$temporary_directory/unsafe-path-output" >/dev/null 2>&1
then
    echo "security review signer accepted an unsafe manifest path" >&2
    exit 1
fi

printf '%s\n' '# Changed after review' >"$review_repository/SECURITY.md"
if REMBRANE_SECURITY_REVIEW_SIGNING_KEY="$temporary_directory/private.pem" \
    sh "$review_repository/scripts/sign-security-review-manifest.sh" \
    "$temporary_directory/manifest.json" \
    "$temporary_directory/changed-output" >/dev/null 2>&1
then
    echo "security review signer accepted changed repository bytes" >&2
    exit 1
fi

mkdir "$temporary_directory/real-output"
ln -s "$temporary_directory/real-output" "$temporary_directory/symbolic-output"
if REMBRANE_SECURITY_REVIEW_SIGNING_KEY="$temporary_directory/private.pem" \
    sh "$review_repository/scripts/sign-security-review-manifest.sh" \
    "$temporary_directory/manifest.json" \
    "$temporary_directory/symbolic-output" >/dev/null 2>&1
then
    echo "security review signer accepted a symbolic output directory" >&2
    exit 1
fi

echo "security review signing test passed"

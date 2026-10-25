#!/bin/sh
set -eu

manifest=${1:?usage: sign-security-review-manifest.sh MANIFEST OUTPUT_DIRECTORY}
output_directory=${2:?usage: sign-security-review-manifest.sh MANIFEST OUTPUT_DIRECTORY}
private_key=${REMBRANE_SECURITY_REVIEW_SIGNING_KEY:-}

if [ -z "$private_key" ]; then
    echo "REMBRANE_SECURITY_REVIEW_SIGNING_KEY must name an Ed25519 PEM private key" >&2
    exit 1
fi
if [ ! -f "$private_key" ] || [ -L "$private_key" ]; then
    echo "security review signing key must be a regular non-symbolic file" >&2
    exit 1
fi
if [ ! -f "$manifest" ] || [ -L "$manifest" ]; then
    echo "security review manifest must be a regular non-symbolic file" >&2
    exit 1
fi
jq -e '
    .schemaVersion == 1
    and (.sourceRevision | test("^[0-9a-f]{40}$"))
    and .workingTreeDirty == false
    and (.files | length > 0)
    and ([.files[].path] == ([.files[].path] | sort))
    and (([.files[].path] | unique | length) == (.files | length))
    and all(
        .files[];
        (.path | type == "string" and length > 0)
        and (.bytes | type == "number" and . >= 0)
        and (.sha256 | test("^[0-9a-f]{64}$"))
    )
' "$manifest" >/dev/null

umask 077
mkdir -p "$output_directory"
for artifact in \
    security-review-manifest.json \
    security-review-manifest.json.sha256 \
    security-review-manifest.json.sig
do
    if [ -e "$output_directory/$artifact" ]; then
        echo "refusing to overwrite security review artifact: $artifact" >&2
        exit 1
    fi
done

cp "$manifest" "$output_directory/security-review-manifest.json"
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

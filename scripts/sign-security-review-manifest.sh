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
if [ ! -f "$manifest" ] || [ -L "$manifest" ]; then
    echo "security review manifest must be a regular non-symbolic file" >&2
    exit 1
fi
jq -e '
    def safe_path:
        type == "string"
        and length > 0
        and length <= 4096
        and test("^[A-Za-z0-9._@+/-]+$")
        and (test("(^|/)\\.\\.?(/|$)") | not);
    .schemaVersion == 1
    and (.sourceRevision | test("^[0-9a-f]{40}$"))
    and .workingTreeDirty == false
    and (.files | length > 0)
    and ([.files[].path] == ([.files[].path] | sort))
    and (([.files[].path] | unique | length) == (.files | length))
    and all(
        .files[];
        (.path | safe_path)
        and (.bytes | type == "number" and . >= 0)
        and (.sha256 | test("^[0-9a-f]{64}$"))
    )
' "$manifest" >/dev/null

umask 077
if [ -L "$output_directory" ] ||
    { [ -e "$output_directory" ] && [ ! -d "$output_directory" ]; }
then
    echo "security review output must be a non-symbolic directory" >&2
    exit 1
fi
mkdir -p "$output_directory"
chmod 700 "$output_directory"
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

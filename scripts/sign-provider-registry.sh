#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
registry=${1:-"$repository_root/spec/provider-registry.json"}
output_directory=${2:-"$repository_root/dist/provider-registry"}
private_key=${REMBRANE_REGISTRY_SIGNING_KEY:-}

if [ -z "$private_key" ]; then
    echo "REMBRANE_REGISTRY_SIGNING_KEY must name an Ed25519 PEM private key" >&2
    exit 1
fi

if [ ! -f "$private_key" ] || [ -L "$private_key" ]; then
    echo "provider registry signing key must be a regular non-symbolic file" >&2
    exit 1
fi
private_key_mode=$(
    stat -f '%Lp' "$private_key" 2>/dev/null ||
        stat -c '%a' "$private_key" 2>/dev/null
)
case "$private_key_mode" in
    400 | 600) ;;
    *)
        echo "provider registry signing key must be owner-only (0400 or 0600)" >&2
        exit 1
        ;;
esac
if [ ! -f "$registry" ] || [ -L "$registry" ]; then
    echo "provider registry signing input must be a regular non-symbolic file" >&2
    exit 1
fi

"$repository_root/scripts/verify-provider-registry.sh" "$registry" >/dev/null

umask 077
if [ -e "$output_directory" ] || [ -L "$output_directory" ]; then
    echo "provider registry output directory must not already exist" >&2
    exit 1
fi
mkdir -p "$(dirname -- "$output_directory")"
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

cp "$registry" "$output_directory/provider-registry.json"
"$repository_root/scripts/verify-provider-registry.sh" \
    "$output_directory/provider-registry.json" >/dev/null
registry_sha256=$(
    node "$repository_root/scripts/sha256-bounded-file.mjs" \
        "$output_directory/provider-registry.json" 4194304
)
printf '%s  %s\n' "$registry_sha256" provider-registry.json \
    >"$output_directory/provider-registry.json.sha256"
node "$repository_root/scripts/sign-ed25519-document.mjs" \
    "$output_directory/provider-registry.json" \
    "$private_key" \
    "$output_directory/provider-registry.json.sig"
signature_bytes=$(wc -c <"$output_directory/provider-registry.json.sig" | tr -d ' ')
if [ "$signature_bytes" -ne 64 ]; then
    echo "provider registry signer produced an invalid signature" >&2
    exit 1
fi
chmod 600 "$output_directory"/*

verification_public_key=$(mktemp "${TMPDIR:-/tmp}/rembrane-registry-public.XXXXXX")
chmod 600 "$verification_public_key"
rm -f "$verification_public_key"
node "$repository_root/scripts/derive-ed25519-public-key.mjs" \
    "$private_key" "$verification_public_key"
"$repository_root/scripts/verify-provider-registry-bundle.sh" \
    "$output_directory" "$verification_public_key" >/dev/null

complete=1
echo "signed provider registry artifacts written to: $output_directory"

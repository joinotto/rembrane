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

if [ ! -f "$private_key" ]; then
    echo "provider registry signing key does not exist: $private_key" >&2
    exit 1
fi

"$repository_root/scripts/verify-provider-registry.sh" "$registry" >/dev/null
mkdir -p "$output_directory"

cp "$registry" "$output_directory/provider-registry.json"
openssl dgst -sha256 \
    -out "$output_directory/provider-registry.json.sha256" \
    "$output_directory/provider-registry.json"
openssl pkeyutl -sign -rawin \
    -inkey "$private_key" \
    -in "$output_directory/provider-registry.json" \
    -out "$output_directory/provider-registry.json.sig"

echo "signed provider registry artifacts written to: $output_directory"

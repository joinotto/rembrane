#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

openssl genpkey -algorithm Ed25519 \
    -out "$temporary_directory/private.pem" >/dev/null 2>&1
openssl pkey -in "$temporary_directory/private.pem" -pubout \
    -out "$temporary_directory/public.pem" >/dev/null 2>&1

REMBRANE_REGISTRY_SIGNING_KEY="$temporary_directory/private.pem" \
    "$repository_root/scripts/sign-provider-registry.sh" \
    "$repository_root/spec/provider-registry.json" \
    "$temporary_directory/artifacts" >/dev/null

"$repository_root/scripts/verify-provider-registry-signature.sh" \
    "$temporary_directory/artifacts/provider-registry.json" \
    "$temporary_directory/artifacts/provider-registry.json.sig" \
    "$temporary_directory/public.pem" >/dev/null

ln -s "$temporary_directory/artifacts/provider-registry.json" \
    "$temporary_directory/registry-link.json"
if "$repository_root/scripts/verify-provider-registry-signature.sh" \
    "$temporary_directory/registry-link.json" \
    "$temporary_directory/artifacts/provider-registry.json.sig" \
    "$temporary_directory/public.pem" >/dev/null 2>&1
then
    echo "provider registry signature accepted a symbolic input" >&2
    exit 1
fi

cp "$temporary_directory/artifacts/provider-registry.json" \
    "$temporary_directory/tampered.json"
printf '\n' >>"$temporary_directory/tampered.json"
if "$repository_root/scripts/verify-provider-registry-signature.sh" \
    "$temporary_directory/tampered.json" \
    "$temporary_directory/artifacts/provider-registry.json.sig" \
    "$temporary_directory/public.pem" >/dev/null 2>&1
then
    echo "provider registry signature accepted tampered bytes" >&2
    exit 1
fi

echo "provider registry signing test passed"

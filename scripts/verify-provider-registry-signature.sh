#!/bin/sh
set -eu

registry=${1:?usage: verify-provider-registry-signature.sh REGISTRY SIGNATURE PUBLIC_KEY}
signature=${2:?usage: verify-provider-registry-signature.sh REGISTRY SIGNATURE PUBLIC_KEY}
public_key=${3:?usage: verify-provider-registry-signature.sh REGISTRY SIGNATURE PUBLIC_KEY}

openssl pkeyutl -verify -rawin -pubin \
    -inkey "$public_key" \
    -in "$registry" \
    -sigfile "$signature" >/dev/null

echo "provider registry signature verified: $registry"

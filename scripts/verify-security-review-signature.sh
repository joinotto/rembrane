#!/bin/sh
set -eu

manifest=${1:?usage: verify-security-review-signature.sh MANIFEST SIGNATURE PUBLIC_KEY}
signature=${2:?usage: verify-security-review-signature.sh MANIFEST SIGNATURE PUBLIC_KEY}
public_key=${3:?usage: verify-security-review-signature.sh MANIFEST SIGNATURE PUBLIC_KEY}

for artifact in "$manifest" "$signature" "$public_key"; do
    if [ ! -f "$artifact" ] || [ -L "$artifact" ]; then
        echo "security review verification input must be a regular non-symbolic file" >&2
        exit 1
    fi
done

openssl pkeyutl -verify -rawin -pubin \
    -inkey "$public_key" \
    -in "$manifest" \
    -sigfile "$signature" >/dev/null

echo "security review signature verified: $manifest"

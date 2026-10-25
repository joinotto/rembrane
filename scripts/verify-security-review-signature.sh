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

signature_bytes=$(wc -c <"$signature" | tr -d ' ')
public_key_bytes=$(wc -c <"$public_key" | tr -d ' ')
if [ "$signature_bytes" -ne 64 ]; then
    echo "security review Ed25519 signature must be exactly 64 bytes" >&2
    exit 1
fi
if [ "$public_key_bytes" -eq 0 ] || [ "$public_key_bytes" -gt 16384 ]; then
    echo "security review public key exceeds the bounded size" >&2
    exit 1
fi

openssl pkeyutl -verify -rawin -pubin \
    -inkey "$public_key" \
    -in "$manifest" \
    -sigfile "$signature" >/dev/null

echo "security review signature verified: $manifest"

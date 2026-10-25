#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

openssl genpkey -algorithm Ed25519 \
    -out "$temporary_directory/private.pem" >/dev/null 2>&1
chmod 600 "$temporary_directory/private.pem"
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

"$repository_root/scripts/verify-provider-registry-bundle.sh" \
    "$temporary_directory/artifacts" \
    "$temporary_directory/public.pem" >/dev/null

if "$repository_root/scripts/verify-provider-registry-signature.sh" \
    "$temporary_directory/artifacts/provider-registry.json" \
    "$temporary_directory/artifacts/provider-registry.json.sig" \
    "$temporary_directory/private.pem" >/dev/null 2>&1
then
    echo "provider registry verifier accepted a private trust anchor" >&2
    exit 1
fi

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

if REMBRANE_REGISTRY_SIGNING_KEY="$temporary_directory/private.pem" \
    "$repository_root/scripts/sign-provider-registry.sh" \
    "$repository_root/spec/provider-registry.json" \
    "$temporary_directory/artifacts" >/dev/null 2>&1
then
    echo "provider registry signer overwrote existing evidence" >&2
    exit 1
fi

cp "$temporary_directory/private.pem" "$temporary_directory/permissive.pem"
chmod 644 "$temporary_directory/permissive.pem"
if REMBRANE_REGISTRY_SIGNING_KEY="$temporary_directory/permissive.pem" \
    "$repository_root/scripts/sign-provider-registry.sh" \
    "$repository_root/spec/provider-registry.json" \
    "$temporary_directory/permissive-output" >/dev/null 2>&1
then
    echo "provider registry signer accepted a permissive private key" >&2
    exit 1
fi
test ! -e "$temporary_directory/permissive-output"

cp -R "$temporary_directory/artifacts" "$temporary_directory/bad-checksum"
printf '%s\n' \
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  provider-registry.json' \
    >"$temporary_directory/bad-checksum/provider-registry.json.sha256"
if "$repository_root/scripts/verify-provider-registry-bundle.sh" \
    "$temporary_directory/bad-checksum" \
    "$temporary_directory/public.pem" >/dev/null 2>&1
then
    echo "provider registry bundle accepted a false checksum" >&2
    exit 1
fi

cp -R "$temporary_directory/artifacts" "$temporary_directory/invalid-semantics"
jq '.providers[0].unexpected = true' \
    "$temporary_directory/invalid-semantics/provider-registry.json" \
    >"$temporary_directory/invalid-semantics/provider-registry.next"
mv "$temporary_directory/invalid-semantics/provider-registry.next" \
    "$temporary_directory/invalid-semantics/provider-registry.json"
invalid_sha256=$(
    openssl dgst -sha256 \
        "$temporary_directory/invalid-semantics/provider-registry.json" |
        awk '{print $NF}'
)
printf '%s  %s\n' "$invalid_sha256" provider-registry.json \
    >"$temporary_directory/invalid-semantics/provider-registry.json.sha256"
openssl pkeyutl -sign -rawin \
    -inkey "$temporary_directory/private.pem" \
    -in "$temporary_directory/invalid-semantics/provider-registry.json" \
    -out "$temporary_directory/invalid-semantics/provider-registry.json.sig"
if "$repository_root/scripts/verify-provider-registry-bundle.sh" \
    "$temporary_directory/invalid-semantics" \
    "$temporary_directory/public.pem" >/dev/null 2>&1
then
    echo "provider registry bundle accepted signed invalid semantics" >&2
    exit 1
fi

cp -R "$temporary_directory/artifacts" "$temporary_directory/extra-artifact"
printf '%s\n' 'undeclared' >"$temporary_directory/extra-artifact/notes.txt"
if "$repository_root/scripts/verify-provider-registry-bundle.sh" \
    "$temporary_directory/extra-artifact" \
    "$temporary_directory/public.pem" >/dev/null 2>&1
then
    echo "provider registry bundle accepted an undeclared artifact" >&2
    exit 1
fi

mkdir "$temporary_directory/real-output"
ln -s "$temporary_directory/real-output" "$temporary_directory/symbolic-output"
if REMBRANE_REGISTRY_SIGNING_KEY="$temporary_directory/private.pem" \
    "$repository_root/scripts/sign-provider-registry.sh" \
    "$repository_root/spec/provider-registry.json" \
    "$temporary_directory/symbolic-output" >/dev/null 2>&1
then
    echo "provider registry signer accepted a symbolic output directory" >&2
    exit 1
fi

echo "provider registry signing test passed"

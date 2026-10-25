#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-memory-release.XXXXXX")
evidence_root="$test_root/evidence"

cleanup() {
    rm -rf "$test_root"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$evidence_root"
openssl genpkey -algorithm Ed25519 \
    -out "$test_root/external-private.pem" >/dev/null 2>&1
openssl pkey -in "$test_root/external-private.pem" -pubout \
    -out "$test_root/external-public.pem" >/dev/null 2>&1
cp "$repository_root/spec/memory-provider-compatibility-lock.json" \
    "$evidence_root/compatibility-lock.json"
cp "$repository_root/spec/MEMORY_PROVIDER_0.1_TO_1.0_MIGRATION.md" \
    "$evidence_root/migration.md"

profile_sha256=$(openssl dgst -sha256 \
    "$repository_root/spec/conformance/memory-provider-core.json" |
    awk '{print $NF}')
fixture_sha256=$(openssl dgst -sha256 \
    "$repository_root/spec/conformance/memory-provider-core-fixtures.json" |
    awk '{print $NF}')

jq --arg profile "$profile_sha256" --arg fixture "$fixture_sha256" \
    '.profileSha256 = $profile | .fixtureSha256 = $fixture' \
    "$repository_root/spec/examples/memory-provider-mixed-version-evidence.json" \
    >"$evidence_root/mixed-version.json"
jq --arg profile "$profile_sha256" --arg fixture "$fixture_sha256" \
    '.profileSha256 = $profile
     | .fixtureSha256 = $fixture
     | .provider.id = "rembrane.internal-provider"
     | .provider.version = "0.1.0"
     | .namespace = "release-provider-a"' \
    "$repository_root/spec/examples/memory-provider-conformance-result.json" \
    >"$evidence_root/provider-a.json"
jq --arg profile "$profile_sha256" --arg fixture "$fixture_sha256" \
    '.profileSha256 = $profile
     | .fixtureSha256 = $fixture
     | .provider.id = "example.external-provider"
     | .provider.version = "2.4.1"
     | .namespace = "release-provider-b"' \
    "$repository_root/spec/examples/memory-provider-conformance-result.json" \
    >"$evidence_root/provider-b.json"
provider_b_sha256=$(openssl dgst -sha256 "$evidence_root/provider-b.json" |
    awk '{print $NF}')
jq --arg digest "$provider_b_sha256" \
    '.resultSha256 = $digest' \
    "$repository_root/spec/examples/memory-provider-external-provenance.json" \
    >"$evidence_root/provider-b.provenance.json"
openssl pkeyutl -sign -inkey "$test_root/external-private.pem" -rawin \
    -in "$evidence_root/provider-b.provenance.json" \
    -out "$evidence_root/provider-b.provenance.json.sig"

mixed_sha256=$(openssl dgst -sha256 "$evidence_root/mixed-version.json" |
    awk '{print $NF}')
lock_sha256=$(openssl dgst -sha256 "$evidence_root/compatibility-lock.json" |
    awk '{print $NF}')
migration_sha256=$(openssl dgst -sha256 "$evidence_root/migration.md" |
    awk '{print $NF}')
provider_a_sha256=$(openssl dgst -sha256 "$evidence_root/provider-a.json" |
    awk '{print $NF}')
provenance_sha256=$(openssl dgst -sha256 \
    "$evidence_root/provider-b.provenance.json" | awk '{print $NF}')
signature_sha256=$(openssl dgst -sha256 \
    "$evidence_root/provider-b.provenance.json.sig" | awk '{print $NF}')
public_key_sha256=$(openssl dgst -sha256 "$test_root/external-public.pem" |
    awk '{print $NF}')
jq \
    --arg profile "$profile_sha256" \
    --arg fixture "$fixture_sha256" \
    --arg revision 1111111111111111111111111111111111111111 \
    --arg lock "$lock_sha256" \
    --arg migration "$migration_sha256" \
    --arg mixed "$mixed_sha256" \
    --arg provider_a "$provider_a_sha256" \
    --arg provider_b "$provider_b_sha256" \
    --arg provenance "$provenance_sha256" \
    --arg signature "$signature_sha256" \
    --arg public_key "$public_key_sha256" \
    '.profileSha256 = $profile
     | .fixtureSha256 = $fixture
     | .candidateSourceRevision = $revision
     | .compatibilityLockSha256 = $lock
     | .migrationNotesSha256 = $migration
     | .mixedVersionEvidenceSha256 = $mixed
     | .externalProvenanceSha256 = $provenance
     | .externalProvenanceSignatureSha256 = $signature
     | .externalPublicKeySha256 = $public_key
     | .providers[0].resultSha256 = $provider_a
     | .providers[1].resultSha256 = $provider_b' \
    "$repository_root/spec/examples/memory-provider-release-evidence.json" \
    >"$evidence_root/manifest.json"

verifier="$repository_root/scripts/verify-memory-provider-release-evidence.mjs"
verify() {
    evidence=$1
    option=${2:-}
    if [ -n "$option" ]; then
        node "$verifier" "$evidence" "$test_root/external-public.pem" "$option"
    else
        node "$verifier" "$evidence" "$test_root/external-public.pem"
    fi
}
node "$verifier" "$evidence_root" "$test_root/external-public.pem" >/dev/null

if verify "$evidence_root" --verify-repository >/dev/null 2>&1; then
    echo "release evidence accepted a different repository revision" >&2
    exit 1
fi

cp -R "$evidence_root" "$test_root/no-external"
jq '.providers[1].origin = "in-repository"' \
    "$test_root/no-external/manifest.json" >"$test_root/manifest.next"
mv "$test_root/manifest.next" "$test_root/no-external/manifest.json"
if verify "$test_root/no-external" >/dev/null 2>&1; then
    echo "release evidence accepted no external provider" >&2
    exit 1
fi

cp -R "$evidence_root" "$test_root/reused-provider"
jq '.provider.id = "rembrane.internal-provider"' \
    "$test_root/reused-provider/provider-b.json" >"$test_root/provider.next"
mv "$test_root/provider.next" "$test_root/reused-provider/provider-b.json"
new_digest=$(openssl dgst -sha256 \
    "$test_root/reused-provider/provider-b.json" | awk '{print $NF}')
jq --arg digest "$new_digest" '.providers[1].resultSha256 = $digest' \
    "$test_root/reused-provider/manifest.json" >"$test_root/manifest.next"
mv "$test_root/manifest.next" "$test_root/reused-provider/manifest.json"
if verify "$test_root/reused-provider" >/dev/null 2>&1; then
    echo "release evidence accepted duplicate provider identity" >&2
    exit 1
fi

cp -R "$evidence_root" "$test_root/forged-external"
jq '.provider.version = "forged"' \
    "$test_root/forged-external/provider-b.json" >"$test_root/provider.next"
mv "$test_root/provider.next" "$test_root/forged-external/provider-b.json"
new_digest=$(openssl dgst -sha256 \
    "$test_root/forged-external/provider-b.json" | awk '{print $NF}')
jq --arg digest "$new_digest" '.providers[1].resultSha256 = $digest' \
    "$test_root/forged-external/manifest.json" >"$test_root/manifest.next"
mv "$test_root/manifest.next" "$test_root/forged-external/manifest.json"
if verify "$test_root/forged-external" >/dev/null 2>&1; then
    echo "release evidence accepted a forged external provider result" >&2
    exit 1
fi

cp -R "$evidence_root" "$test_root/reordered"
jq '.cases |= [.[1], .[0], .[2:][]]' \
    "$test_root/reordered/provider-a.json" >"$test_root/provider.next"
mv "$test_root/provider.next" "$test_root/reordered/provider-a.json"
new_digest=$(openssl dgst -sha256 "$test_root/reordered/provider-a.json" |
    awk '{print $NF}')
jq --arg digest "$new_digest" '.providers[0].resultSha256 = $digest' \
    "$test_root/reordered/manifest.json" >"$test_root/manifest.next"
mv "$test_root/manifest.next" "$test_root/reordered/manifest.json"
if verify "$test_root/reordered" >/dev/null 2>&1; then
    echo "release evidence accepted reordered conformance cases" >&2
    exit 1
fi

cp -R "$evidence_root" "$test_root/substituted-lock"
printf ' ' >>"$test_root/substituted-lock/compatibility-lock.json"
new_digest=$(openssl dgst -sha256 \
    "$test_root/substituted-lock/compatibility-lock.json" | awk '{print $NF}')
jq --arg digest "$new_digest" '.compatibilityLockSha256 = $digest' \
    "$test_root/substituted-lock/manifest.json" >"$test_root/manifest.next"
mv "$test_root/manifest.next" "$test_root/substituted-lock/manifest.json"
if verify "$test_root/substituted-lock" >/dev/null 2>&1; then
    echo "release evidence accepted a substituted compatibility lock" >&2
    exit 1
fi

cp -R "$evidence_root" "$test_root/substituted-migration"
printf ' ' >>"$test_root/substituted-migration/migration.md"
new_digest=$(openssl dgst -sha256 \
    "$test_root/substituted-migration/migration.md" | awk '{print $NF}')
jq --arg digest "$new_digest" '.migrationNotesSha256 = $digest' \
    "$test_root/substituted-migration/manifest.json" >"$test_root/manifest.next"
mv "$test_root/manifest.next" "$test_root/substituted-migration/manifest.json"
if verify "$test_root/substituted-migration" >/dev/null 2>&1; then
    echo "release evidence accepted substituted migration notes" >&2
    exit 1
fi

touch "$evidence_root/notes.txt"
if verify "$evidence_root" >/dev/null 2>&1; then
    echo "release evidence accepted an undeclared artifact" >&2
    exit 1
fi

echo "memory-provider release evidence checks passed"

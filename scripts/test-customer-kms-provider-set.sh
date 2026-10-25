#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-kms-provider-set.XXXXXX")

cleanup() {
    rm -rf "$test_root"
}
trap cleanup EXIT HUP INT TERM

create_provider() {
    cloud_provider=$1
    provider_id=$2
    namespace=$3
    directory="$test_root/providers/$cloud_provider"
    mkdir -p "$directory"
    jq \
        --arg provider_id "$provider_id" \
        --arg namespace "$namespace" \
        '.providerId = $provider_id
         | .providerVersion = "0.1.0"
         | .namespace = $namespace' \
        "$repository_root/spec/examples/key-provider-conformance-result.json" \
        >"$directory/conformance-result.json"
    printf '%s\n' '{"policy":"reviewed"}' >"$directory/iam-policy.json"
    printf '{"events":[{"operation":"GenerateDataKey","provider":"%s"}]}\n' \
        "$cloud_provider" >"$directory/cloud-audit.json"
    node "$repository_root/scripts/generate-customer-kms-evidence.mjs" \
        "$cloud_provider" \
        1111111111111111111111111111111111111111 \
        "$directory/conformance-result.json" \
        "$directory/iam-policy.json" \
        "$directory/cloud-audit.json" \
        cloud-security-reviewer \
        2026-01-15T12:00:00Z \
        2026-01-15T11:30:00Z \
        2026-01-15T12:30:00Z \
        >"$directory/evidence.json"
}

create_provider aws-kms example.aws-sidecar aws-disposable-run
create_provider azure-key-vault example.azure-sidecar azure-disposable-run
create_provider google-cloud-kms example.gcp-sidecar gcp-disposable-run

verifier="$repository_root/scripts/verify-customer-kms-provider-set.mjs"
node "$verifier" "$test_root/providers" >/dev/null

cp -R "$test_root/providers" "$test_root/wrong-slot"
jq '.cloudProvider = "aws-kms"' \
    "$test_root/wrong-slot/azure-key-vault/evidence.json" \
    >"$test_root/wrong-slot/azure-key-vault/evidence.next"
mv "$test_root/wrong-slot/azure-key-vault/evidence.next" \
    "$test_root/wrong-slot/azure-key-vault/evidence.json"
if node "$verifier" "$test_root/wrong-slot" >/dev/null 2>&1; then
    echo "customer KMS provider set accepted evidence in the wrong slot" >&2
    exit 1
fi

cp -R "$test_root/providers" "$test_root/reused-namespace"
aws_namespace=$(jq -r '.namespace' \
    "$test_root/reused-namespace/aws-kms/evidence.json")
jq --arg namespace "$aws_namespace" '.namespace = $namespace' \
    "$test_root/reused-namespace/azure-key-vault/evidence.json" \
    >"$test_root/reused-namespace/azure-key-vault/evidence.next"
mv "$test_root/reused-namespace/azure-key-vault/evidence.next" \
    "$test_root/reused-namespace/azure-key-vault/evidence.json"
if node "$verifier" "$test_root/reused-namespace" >/dev/null 2>&1; then
    echo "customer KMS provider set accepted a reused namespace" >&2
    exit 1
fi

cp -R "$test_root/providers" "$test_root/oversized-evidence"
dd if=/dev/zero bs=1024 count=65 2>/dev/null |
    tr '\000' 'x' \
        >"$test_root/oversized-evidence/aws-kms/evidence.json"
if node "$verifier" "$test_root/oversized-evidence" >/dev/null 2>&1; then
    echo "customer KMS provider set accepted oversized evidence" >&2
    exit 1
fi

touch "$test_root/providers/notes.txt"
if node "$verifier" "$test_root/providers" >/dev/null 2>&1; then
    echo "customer KMS provider set accepted an undeclared artifact" >&2
    exit 1
fi

echo "customer KMS provider-set checks passed"

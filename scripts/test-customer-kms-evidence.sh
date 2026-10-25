#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-kms-evidence.XXXXXX")

cleanup() {
    rm -rf "$test_root"
}
trap cleanup EXIT HUP INT TERM

jq '.providerId = "example.aws-kms-sidecar"
    | .providerVersion = "0.1.0"
    | .namespace = "example-disposable-run"' \
    "$repository_root/spec/examples/key-provider-conformance-result.json" \
    >"$test_root/result.json"
printf '%s\n' '{"Version":"2012-10-17","Statement":[]}' >"$test_root/iam-policy.json"

profile_sha256=$(openssl dgst -sha256 \
    "$repository_root/spec/conformance/key-provider-core.json" | awk '{print $NF}')
result_sha256=$(openssl dgst -sha256 "$test_root/result.json" | awk '{print $NF}')
policy_sha256=$(openssl dgst -sha256 "$test_root/iam-policy.json" | awk '{print $NF}')

jq -n \
    --arg profile "$profile_sha256" \
    --arg result "$result_sha256" \
    --arg policy "$policy_sha256" \
    '{
        schemaVersion: 1,
        cloudProvider: "aws-kms",
        providerId: "example.aws-kms-sidecar",
        providerVersion: "0.1.0",
        sidecarSourceRevision: ("1" * 40),
        namespace: "example-disposable-run",
        executedAt: "2026-01-15T12:00:00Z",
        conformanceProfileSha256: $profile,
        conformanceResultSha256: $result,
        iamPolicySha256: $policy,
        cleanup: {
            completedAt: "2026-01-15T12:30:00Z",
            resourcesDeleted: true
        }
    }' >"$test_root/evidence.json"

verify() {
    node "$repository_root/scripts/verify-customer-kms-evidence.mjs" \
        "$1" "$2" "$3"
}

verify "$test_root/evidence.json" "$test_root/result.json" \
    "$test_root/iam-policy.json" >/dev/null

jq '.cleanup.resourcesDeleted = false' "$test_root/evidence.json" \
    >"$test_root/not-cleaned.json"
if verify "$test_root/not-cleaned.json" "$test_root/result.json" \
    "$test_root/iam-policy.json" >/dev/null 2>&1
then
    echo "customer KMS evidence accepted incomplete cleanup" >&2
    exit 1
fi

jq '.cleanup.completedAt = "2026-01-15T11:59:59Z"' "$test_root/evidence.json" \
    >"$test_root/backwards-cleanup.json"
if verify "$test_root/backwards-cleanup.json" "$test_root/result.json" \
    "$test_root/iam-policy.json" >/dev/null 2>&1
then
    echo "customer KMS evidence accepted cleanup before execution" >&2
    exit 1
fi

jq '.namespace = "different-run"' "$test_root/result.json" \
    >"$test_root/wrong-namespace.json"
if verify "$test_root/evidence.json" "$test_root/wrong-namespace.json" \
    "$test_root/iam-policy.json" >/dev/null 2>&1
then
    echo "customer KMS evidence accepted a different namespace" >&2
    exit 1
fi

printf ' ' >>"$test_root/iam-policy.json"
if verify "$test_root/evidence.json" "$test_root/result.json" \
    "$test_root/iam-policy.json" >/dev/null 2>&1
then
    echo "customer KMS evidence accepted a changed IAM policy" >&2
    exit 1
fi

echo "customer KMS evidence checks passed"

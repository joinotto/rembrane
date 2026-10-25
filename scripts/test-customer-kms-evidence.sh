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
printf '%s\n' '{"events":[{"operation":"GenerateDataKey"},{"operation":"Decrypt"}]}' \
    >"$test_root/cloud-audit.json"

profile_sha256=$(openssl dgst -sha256 \
    "$repository_root/spec/conformance/key-provider-core.json" | awk '{print $NF}')
result_sha256=$(openssl dgst -sha256 "$test_root/result.json" | awk '{print $NF}')
policy_sha256=$(openssl dgst -sha256 "$test_root/iam-policy.json" | awk '{print $NF}')
audit_sha256=$(openssl dgst -sha256 "$test_root/cloud-audit.json" | awk '{print $NF}')

node "$repository_root/scripts/generate-customer-kms-evidence.mjs" \
    aws-kms \
    1111111111111111111111111111111111111111 \
    "$test_root/result.json" \
    "$test_root/iam-policy.json" \
    "$test_root/cloud-audit.json" \
    cloud-security-reviewer \
    2026-01-15T12:00:00Z \
    2026-01-15T11:30:00Z \
    2026-01-15T12:30:00Z \
    >"$test_root/evidence.json"

jq -e \
    --arg profile "$profile_sha256" \
    --arg result "$result_sha256" \
    --arg policy "$policy_sha256" \
    --arg audit "$audit_sha256" \
    '.conformanceProfileSha256 == $profile
     and .conformanceResultSha256 == $result
     and .iamPolicySha256 == $policy
     and .cloudAuditEvidenceSha256 == $audit' \
    "$test_root/evidence.json" >/dev/null

verify() {
    node "$repository_root/scripts/verify-customer-kms-evidence.mjs" \
        "$1" "$2" "$3" "$4"
}

verify "$test_root/evidence.json" "$test_root/result.json" \
    "$test_root/iam-policy.json" "$test_root/cloud-audit.json" >/dev/null

if node "$repository_root/scripts/generate-customer-kms-evidence.mjs" \
    aws-kms \
    1111111111111111111111111111111111111111 \
    "$test_root/result.json" \
    "$test_root/iam-policy.json" \
    "$test_root/cloud-audit.json" \
    cloud-security-reviewer \
    not-a-time \
    2026-01-15T11:30:00Z \
    2026-01-15T12:30:00Z >/dev/null 2>&1
then
    echo "customer KMS evidence generator accepted an invalid timestamp" >&2
    exit 1
fi

jq '.cleanup.resourcesDeleted = false' "$test_root/evidence.json" \
    >"$test_root/not-cleaned.json"
if verify "$test_root/not-cleaned.json" "$test_root/result.json" \
    "$test_root/iam-policy.json" "$test_root/cloud-audit.json" >/dev/null 2>&1
then
    echo "customer KMS evidence accepted incomplete cleanup" >&2
    exit 1
fi

jq '.iamPolicyReview.approved = false' "$test_root/evidence.json" \
    >"$test_root/unapproved-policy.json"
if verify "$test_root/unapproved-policy.json" "$test_root/result.json" \
    "$test_root/iam-policy.json" "$test_root/cloud-audit.json" >/dev/null 2>&1
then
    echo "customer KMS evidence accepted an unapproved IAM policy" >&2
    exit 1
fi

jq '.iamPolicyReview.reviewedAt = "2026-01-15T12:31:00Z"' \
    "$test_root/evidence.json" >"$test_root/late-policy-review.json"
if verify "$test_root/late-policy-review.json" "$test_root/result.json" \
    "$test_root/iam-policy.json" "$test_root/cloud-audit.json" >/dev/null 2>&1
then
    echo "customer KMS evidence accepted policy review after cleanup" >&2
    exit 1
fi

jq '.cleanup.completedAt = "2026-01-15T11:59:59Z"' "$test_root/evidence.json" \
    >"$test_root/backwards-cleanup.json"
if verify "$test_root/backwards-cleanup.json" "$test_root/result.json" \
    "$test_root/iam-policy.json" "$test_root/cloud-audit.json" >/dev/null 2>&1
then
    echo "customer KMS evidence accepted cleanup before execution" >&2
    exit 1
fi

jq '.namespace = "different-run"' "$test_root/result.json" \
    >"$test_root/wrong-namespace.json"
if verify "$test_root/evidence.json" "$test_root/wrong-namespace.json" \
    "$test_root/iam-policy.json" "$test_root/cloud-audit.json" >/dev/null 2>&1
then
    echo "customer KMS evidence accepted a different namespace" >&2
    exit 1
fi

printf ' ' >>"$test_root/iam-policy.json"
if verify "$test_root/evidence.json" "$test_root/result.json" \
    "$test_root/iam-policy.json" "$test_root/cloud-audit.json" >/dev/null 2>&1
then
    echo "customer KMS evidence accepted a changed IAM policy" >&2
    exit 1
fi

printf '%s\n' '{"Version":"2012-10-17","Statement":[]}' >"$test_root/iam-policy.json"
printf ' ' >>"$test_root/cloud-audit.json"
if verify "$test_root/evidence.json" "$test_root/result.json" \
    "$test_root/iam-policy.json" \
    "$test_root/cloud-audit.json" >/dev/null 2>&1
then
    echo "customer KMS evidence accepted changed cloud audit bytes" >&2
    exit 1
fi

printf '%s\n' '{"events":[{"accessToken":"redaction-failed"}]}' \
    >"$test_root/sensitive-audit.json"
sensitive_audit_sha256=$(
    openssl dgst -sha256 "$test_root/sensitive-audit.json" | awk '{print $NF}'
)
jq --arg digest "$sensitive_audit_sha256" \
    '.cloudAuditEvidenceSha256 = $digest' "$test_root/evidence.json" \
    >"$test_root/sensitive-evidence.json"
if verify "$test_root/sensitive-evidence.json" "$test_root/result.json" \
    "$test_root/iam-policy.json" \
    "$test_root/sensitive-audit.json" >/dev/null 2>&1
then
    echo "customer KMS evidence accepted a credential-bearing audit export" >&2
    exit 1
fi

echo "customer KMS evidence checks passed"

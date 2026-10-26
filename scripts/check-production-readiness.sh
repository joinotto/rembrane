#!/bin/sh
set -eu

mode=${1:-available}
case "$mode" in
    available|--available|--strict) ;;
    *)
        echo "usage: ./scripts/check-production-readiness.sh [available|--available|--strict] [--json]" >&2
        exit 2
        ;;
esac

output=${2:-text}
case "$output" in
    text|--json) ;;
    *)
        echo "usage: ./scripts/check-production-readiness.sh [available|--available|--strict] [--json]" >&2
        exit 2
        ;;
esac

strict=0
test "$mode" = "--strict" && strict=1

if [ "$output" = "--json" ]; then
    exec 3>&1
    exec 1>&2
fi

./scripts/check-local-alpha.sh --core

missing=
missing_json=
record_missing() {
    label=$1
    missing="${missing}${missing:+, }${label}"
    escaped_label=$(printf '%s' "$label" | sed 's/\\/\\\\/g; s/"/\\"/g')
    missing_json="${missing_json}${missing_json:+,}\"${escaped_label}\""
}

all_suite_ready=1
if ! command -v postman >/dev/null 2>&1; then
    record_missing "Postman CLI"
    all_suite_ready=0
fi
if ! command -v cargo >/dev/null 2>&1; then
    record_missing "Cargo"
    all_suite_ready=0
elif ! cargo metadata --format-version 1 >/dev/null 2>&1; then
    record_missing "Cargo dependency resolution"
    all_suite_ready=0
fi
if ! command -v ruby >/dev/null 2>&1; then
    record_missing "Ruby loopback probe"
    all_suite_ready=0
elif ! ruby -rsocket -e \
    'server = TCPServer.new("127.0.0.1", 0); server.close' \
    >/dev/null 2>&1
then
    record_missing "loopback bind permission"
    all_suite_ready=0
fi
if [ "$all_suite_ready" = "1" ]; then
    ./scripts/test-all.sh
fi

if ! ./scripts/check-official-streamable-http.sh >/dev/null 2>&1; then
    record_missing "official MCP SDK Streamable HTTP transport"
fi

postgres_ready=1
if ! command -v psql >/dev/null 2>&1; then
    record_missing "PostgreSQL client"
    postgres_ready=0
fi
if [ -z "${REMBRANE_POSTGRES_URL:-}" ]; then
    record_missing "REMBRANE_POSTGRES_URL"
    postgres_ready=0
fi
if [ "$postgres_ready" = "1" ]; then
    ./scripts/test-postgres-rls.sh
fi
if ! ./scripts/check-postgres-runtime-adapter.sh >/dev/null 2>&1; then
    record_missing "concrete Rust PostgreSQL runtime adapter"
fi

docker_ready=1
if ! command -v docker >/dev/null 2>&1; then
    record_missing "Docker CLI"
    docker_ready=0
elif ! docker info >/dev/null 2>&1; then
    record_missing "Docker daemon"
    docker_ready=0
fi
if [ "$docker_ready" = "1" ]; then
    REMBRANE_PRINCIPAL_ID=principal_readiness \
    REMBRANE_WORKSPACE_ID=workspace_readiness \
    REMBRANE_CLIENT_ID=client_readiness \
    REMBRANE_WORKSPACE_KEY_ID=key_readiness \
    REMBRANE_WORKSPACE_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000000 \
    REMBRANE_API_TOKEN=token_readiness \
        docker compose config --quiet
    docker build --tag rembrane:readiness .
fi

if [ -n "${REMBRANE_SECURITY_REVIEW_BUNDLE:-}" ] &&
    [ -n "${REMBRANE_SECURITY_REVIEW_PUBLIC_KEY:-}" ]
then
    sh ./scripts/verify-security-review-bundle.sh \
        "$REMBRANE_SECURITY_REVIEW_BUNDLE" \
        "$REMBRANE_SECURITY_REVIEW_PUBLIC_KEY" \
        --verify-repository \
        --require-approval
else
    record_missing "independent security-review bundle"
fi

if [ -n "${REMBRANE_CUSTOMER_KMS_EVIDENCE_DIRECTORY:-}" ]; then
    node ./scripts/verify-customer-kms-provider-set.mjs \
        "$REMBRANE_CUSTOMER_KMS_EVIDENCE_DIRECTORY"
else
    record_missing "AWS/Azure/GCP customer-KMS evidence set"
fi

if [ -n "${REMBRANE_MEMORY_PROVIDER_EVIDENCE_DIRECTORY:-}" ] &&
    [ -n "${REMBRANE_MEMORY_PROVIDER_EXTERNAL_PUBLIC_KEY:-}" ]
then
    node ./scripts/verify-memory-provider-release-evidence.mjs \
        "$REMBRANE_MEMORY_PROVIDER_EVIDENCE_DIRECTORY" \
        "$REMBRANE_MEMORY_PROVIDER_EXTERNAL_PUBLIC_KEY" \
        --verify-repository
else
    record_missing "signed two-provider protocol release evidence set"
fi

if [ -n "$missing" ]; then
    if [ "$output" = "--json" ]; then
        printf '{"schemaVersion":1,"ready":false,"strict":%s,"missing":[%s]}\n' \
            "$([ "$strict" = "1" ] && printf true || printf false)" \
            "$missing_json" >&3
    fi
    if [ "$strict" = "1" ]; then
        if [ "$output" = "text" ]; then
            echo "NOT READY: unavailable required gates: $missing" >&2
        fi
        exit 1
    fi
    if [ "$output" = "text" ]; then
        echo "AVAILABLE GATES PASSED; unavailable gates: $missing"
    fi
else
    if [ "$output" = "--json" ]; then
        printf '{"schemaVersion":1,"ready":true,"strict":%s,"missing":[]}\n' \
            "$([ "$strict" = "1" ] && printf true || printf false)" >&3
    else
        echo "READY: all production-readiness gates passed"
    fi
fi

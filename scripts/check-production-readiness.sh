#!/bin/sh
set -eu

mode=${1:-available}
case "$mode" in
    available|--strict) ;;
    *)
        echo "usage: ./scripts/check-production-readiness.sh [available|--strict]" >&2
        exit 2
        ;;
esac

strict=0
test "$mode" = "--strict" && strict=1

./scripts/check-local-alpha.sh --core

missing=
require_or_skip() {
    label=$1
    available=$2
    if [ "$available" = "1" ]; then
        return 0
    fi
    missing="${missing}${missing:+, }${label}"
    return 1
}

if command -v postman >/dev/null 2>&1 &&
    command -v cargo >/dev/null 2>&1 &&
    command -v ruby >/dev/null 2>&1 &&
    ruby -rsocket -e \
        'server = TCPServer.new("127.0.0.1", 0); server.close' \
        >/dev/null 2>&1 &&
    cargo metadata --format-version 1 >/dev/null 2>&1
then
    ./scripts/test-all.sh
else
    require_or_skip "dependency-enabled Rust/Postman/loopback suite" 0 || true
fi

if command -v psql >/dev/null 2>&1 &&
    [ -n "${REMBRANE_POSTGRES_URL:-}" ]
then
    ./scripts/test-postgres-rls.sh
else
    require_or_skip "live PostgreSQL RLS suite" 0 || true
fi

if command -v docker >/dev/null 2>&1 &&
    docker info >/dev/null 2>&1
then
    REMBRANE_PRINCIPAL_ID=principal_readiness \
    REMBRANE_WORKSPACE_ID=workspace_readiness \
    REMBRANE_CLIENT_ID=client_readiness \
    REMBRANE_WORKSPACE_KEY_ID=key_readiness \
    REMBRANE_WORKSPACE_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000000 \
    REMBRANE_API_TOKEN=token_readiness \
        docker compose config --quiet
    docker build --tag rembrane:readiness .
else
    require_or_skip "container build" 0 || true
fi

if [ -n "${REMBRANE_SECURITY_REVIEW_BUNDLE:-}" ] &&
    [ -n "${REMBRANE_SECURITY_REVIEW_PUBLIC_KEY:-}" ]
then
    sh ./scripts/verify-security-review-bundle.sh \
        "$REMBRANE_SECURITY_REVIEW_BUNDLE" \
        "$REMBRANE_SECURITY_REVIEW_PUBLIC_KEY"
else
    require_or_skip "independent security-review bundle" 0 || true
fi

if [ -n "${REMBRANE_CUSTOMER_KMS_EVIDENCE_DIRECTORY:-}" ]; then
    node ./scripts/verify-customer-kms-provider-set.mjs \
        "$REMBRANE_CUSTOMER_KMS_EVIDENCE_DIRECTORY"
else
    require_or_skip "AWS/Azure/GCP customer-KMS evidence set" 0 || true
fi

if [ -n "${REMBRANE_MEMORY_PROVIDER_EVIDENCE_DIRECTORY:-}" ]; then
    node ./scripts/verify-memory-provider-release-evidence.mjs \
        "$REMBRANE_MEMORY_PROVIDER_EVIDENCE_DIRECTORY"
else
    require_or_skip "two-provider protocol release evidence set" 0 || true
fi

if [ -n "$missing" ]; then
    if [ "$strict" = "1" ]; then
        echo "NOT READY: unavailable required gates: $missing" >&2
        exit 1
    fi
    echo "AVAILABLE GATES PASSED; unavailable gates: $missing"
else
    echo "READY: all production-readiness gates passed"
fi

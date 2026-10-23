#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

mode=${1:-full}
case "$mode" in
    --static)
        ./scripts/test-static.sh
        echo "READY: local-alpha static contract"
        ;;
    full)
        ./scripts/test-all.sh
        echo "READY: local-alpha executable contract"
        ;;
    *)
        echo "usage: ./scripts/check-local-alpha.sh [--static]" >&2
        exit 2
        ;;
esac

#!/bin/sh
set -eu

: "${REMBRANE_DATABASE:?REMBRANE_DATABASE is required}"

database_directory=$(dirname "$REMBRANE_DATABASE")
mkdir -p "$database_directory"
chown rembrane:rembrane "$database_directory"

case "${REMBRANE_SKIP_WORKSPACE_INIT:-0}" in
    0)
        : "${REMBRANE_PRINCIPAL_ID:?REMBRANE_PRINCIPAL_ID is required}"
        : "${REMBRANE_WORKSPACE_ID:?REMBRANE_WORKSPACE_ID is required}"
        gosu rembrane rembrane init \
            --database "$REMBRANE_DATABASE" \
            --principal "$REMBRANE_PRINCIPAL_ID" \
            --workspace "$REMBRANE_WORKSPACE_ID"
        ;;
    1)
        ;;
    *)
        echo "REMBRANE_SKIP_WORKSPACE_INIT must be 0 or 1" >&2
        exit 1
        ;;
esac

exec gosu rembrane "$@"

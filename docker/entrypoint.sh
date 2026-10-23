#!/bin/sh
set -eu

: "${REMBRANE_DATABASE:?REMBRANE_DATABASE is required}"
: "${REMBRANE_PRINCIPAL_ID:?REMBRANE_PRINCIPAL_ID is required}"
: "${REMBRANE_WORKSPACE_ID:?REMBRANE_WORKSPACE_ID is required}"

database_directory=$(dirname "$REMBRANE_DATABASE")
mkdir -p "$database_directory"
chown rembrane:rembrane "$database_directory"

gosu rembrane rembrane init \
    --database "$REMBRANE_DATABASE" \
    --principal "$REMBRANE_PRINCIPAL_ID" \
    --workspace "$REMBRANE_WORKSPACE_ID"

exec gosu rembrane "$@"

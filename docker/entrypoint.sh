#!/bin/sh
set -eu

: "${REMBRANE_DATABASE:?REMBRANE_DATABASE is required}"

secret_source_directory=${REMBRANE_SECRET_SOURCE_DIRECTORY:-/run/secrets}
secret_runtime_directory=${REMBRANE_SECRET_RUNTIME_DIRECTORY:-/run/rembrane-secrets}
case "$secret_source_directory:$secret_runtime_directory" in
    /*:/*)
        ;;
    *)
        echo "secret source and runtime directories must be absolute" >&2
        exit 1
        ;;
esac
if [ "$secret_source_directory" = "$secret_runtime_directory" ]; then
    echo "secret source and runtime directories must be distinct" >&2
    exit 1
fi

if [ -d "$secret_source_directory" ]; then
    mkdir -p "$secret_runtime_directory"
    chown rembrane:rembrane "$secret_runtime_directory"
    chmod 700 "$secret_runtime_directory"
    for source_file in "$secret_source_directory"/*; do
        [ -e "$source_file" ] || continue
        if [ -L "$source_file" ] || [ ! -f "$source_file" ]; then
            echo "mounted secrets must be regular non-symlink files" >&2
            exit 1
        fi
        target_file="$secret_runtime_directory/$(basename "$source_file")"
        cp "$source_file" "$target_file"
        chown rembrane:rembrane "$target_file"
        chmod 400 "$target_file"
    done
fi

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

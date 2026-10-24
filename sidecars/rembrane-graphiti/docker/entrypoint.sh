#!/bin/sh
set -eu

entrypoint_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
secret_stager=${REMBRANE_SECRET_STAGER:-"$entrypoint_directory/rembrane-stage-secrets"}
"$secret_stager" rembrane-graphiti

exec gosu rembrane-graphiti "$@"

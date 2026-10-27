#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

. "$repository_root/scripts/graphiti-python-runtime.sh"
python_runtime=$(rembrane_graphiti_python)

"$python_runtime" -m unittest discover \
    -s sidecars/rembrane-graphiti/tests \
    -v
"$python_runtime" -m compileall -q \
    sidecars/rembrane-graphiti/src \
    sidecars/rembrane-graphiti/tests

echo "Graphiti sidecar core checks passed"

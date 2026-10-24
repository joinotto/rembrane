#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

python_runtime=
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 &&
        "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'
    then
        python_runtime=$candidate
        break
    fi
done

if test -z "$python_runtime"; then
    echo "Python 3.11 or newer is required for the Graphiti sidecar tests" >&2
    exit 1
fi

"$python_runtime" -m unittest discover \
    -s sidecars/rembrane-graphiti/tests \
    -v
"$python_runtime" -m compileall -q \
    sidecars/rembrane-graphiti/src \
    sidecars/rembrane-graphiti/tests

echo "Graphiti sidecar core checks passed"

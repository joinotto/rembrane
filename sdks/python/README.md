# Rembrane Python SDK

Standard-library-only Python client for the authenticated Rembrane REST API.

> Rembrane is pre-alpha. Pin the package version and review protocol changes
> before upgrading.

## Requirements

- Python 3.11 or newer.
- A Rembrane API endpoint over HTTPS, or an explicit loopback HTTP endpoint.
- A scoped bearer token. Keep tokens in a secret manager or protected
  environment rather than source control.

## Basic client

```python
import os

from rembrane import RembraneClient

memory = RembraneClient(
    os.environ["REMBRANE_API_URL"],
    os.environ["REMBRANE_API_TOKEN"],
)

context = memory.resolve_context(
    {
        "workspaceId": "workspace_personal",
        "subjectId": "principal_hippo",
        "purpose": "personalize-assistant",
        "query": "How should I address the user?",
    }
)
```

The client rejects redirects, non-loopback plaintext HTTP, malformed discovery,
oversized responses, and non-JSON API responses.

## Portable export

```python
import os

archive = memory.export_portable_data(
    "workspace_personal",
    "principal_hippo",
    "jsonl",  # "markdown" or "graph-json"
)

descriptor = os.open(
    archive.filename,
    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
    0o600,
)
with os.fdopen(descriptor, "wb") as output:
    output.write(archive.payload)
```

JSONL and Markdown exports are subject-scoped. Graph JSON exports cover the
workspace graph and therefore require an owner or admin. All three are
plaintext. Store them as sensitive files; use encrypted backup for recovery or
opaque transfer.

## Portable import

```python
from pathlib import Path

jsonl = Path("rembrane-memories.jsonl").read_bytes()
result = memory.import_portable_memories(
    "workspace_personal",
    "principal_hippo",
    42,
    jsonl,
)
```

The complete archive is bounded to 64 MiB before transport. The server validates
it atomically and imports records only as reviewable proposals. The expected
previous sequence prevents writing against stale workspace state.

## Test

```text
PYTHONPATH=sdks/python python3.11 -m unittest sdks/python/test_rembrane.py
```

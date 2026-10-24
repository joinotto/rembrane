"""Explicitly gated disposable server used only by cross-language tests."""

from __future__ import annotations

import os

from .app import create_app
from .core import InMemoryGraphStore


def run() -> None:
    if os.environ.get("REMBRANE_GRAPHITI_ENABLE_IN_MEMORY_TEST_SERVER") != "1":
        raise RuntimeError("in-memory Graphiti sidecar is restricted to explicit test runs")

    import uvicorn

    token = os.environ.get("REMBRANE_GRAPHITI_BEARER_TOKEN", "")
    port = int(os.environ.get("REMBRANE_GRAPHITI_PORT", "18793"))
    uvicorn.run(
        create_app(InMemoryGraphStore(), token),
        host="127.0.0.1",
        port=port,
        access_log=False,
        log_level="warning",
    )


if __name__ == "__main__":
    run()

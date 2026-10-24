"""Authenticated FastAPI surface for the Rembrane Graphiti sidecar."""

from __future__ import annotations

import hmac
import json
import os
import stat
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from .core import GraphStore, SidecarError, SidecarService

MAXIMUM_REQUEST_BYTES = 1_048_576
MAXIMUM_TOKEN_BYTES = 8_192
MAXIMUM_SECRET_BYTES = 65_536
_DEFAULT_TOKEN_ENVIRONMENT = "REMBRANE_GRAPHITI_BEARER_TOKEN"
_TOKEN_REFERENCE_ENVIRONMENT = "REMBRANE_GRAPHITI_BEARER_TOKEN_REFERENCE"
_ROUTES = {
    "/v0.1/nodes:upsert": "upsertNode",
    "/v0.1/edges:upsert": "upsertEdge",
    "/v0.1/neighbours:query": "neighbours",
    "/v0.1/nodes:delete": "deleteNode",
    "/v0.1/edges:delete": "deleteEdge",
}


def create_app(store: GraphStore | None = None, bearer_token: str | None = None) -> Any:
    """Builds the sidecar without placing credentials in application state."""

    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    configured_token = (
        bearer_token if bearer_token is not None else _resolve_bearer_token()
    )
    _validate_token(configured_token)

    @asynccontextmanager
    async def lifespan(application: Any) -> AsyncIterator[None]:
        selected_store = store
        if selected_store is None:
            from .graphiti_store import GraphitiGraphStore

            selected_store = await GraphitiGraphStore.from_environment()
        application.state.service = SidecarService(selected_store)
        try:
            yield
        finally:
            close = getattr(selected_store, "close", None)
            if close is not None:
                await close()

    app = FastAPI(
        title="Rembrane Graphiti Sidecar",
        version="0.1.0-alpha.1",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def authenticate(request: Request, call_next: Any) -> Any:
        if request.url.path == "/healthz":
            return await call_next(request)
        authorization = request.headers.get("authorization", "")
        if not authorization.startswith("Bearer ") or "," in authorization:
            return JSONResponse(
                status_code=401,
                content={"error": "unauthorized"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        supplied = authorization[7:]
        if not hmac.compare_digest(supplied.encode(), configured_token.encode()):
            return JSONResponse(
                status_code=401,
                content={"error": "unauthorized"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        return await call_next(request)

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v0.1/manifest")
    async def manifest() -> dict[str, Any]:
        return {
            "providerId": "rembrane.graph.graphiti",
            "providerVersion": "0.1.0-alpha.1",
            "protocolVersion": "0.1",
            "capabilities": [
                "graphUpsert",
                "graphTraverse",
                "delete",
                "workspaceFilter",
                "versionedRecords",
                "healthCheck",
            ],
            "plaintextProcessing": True,
            "limits": {
                "maximumBatchItems": 1,
                "maximumContentBytes": 262_144,
                "maximumCandidates": 100,
            },
        }

    async def dispatch(request: Request, operation: str) -> JSONResponse:
        try:
            envelope = await _read_json(request)
            response = await request.app.state.service.execute(operation, envelope)
            return JSONResponse(content=response)
        except SidecarError as error:
            return JSONResponse(
                status_code=error.status,
                content={"error": error.code},
            )

    for path, operation in _ROUTES.items():
        app.add_api_route(
            path,
            _handler(dispatch, operation),
            methods=["POST"],
            response_class=JSONResponse,
        )

    return app


def _handler(dispatch: Any, operation: str) -> Any:
    async def handle(request: Any) -> Any:
        return await dispatch(request, operation)

    handle.__name__ = f"handle_{operation}"
    return handle


async def _read_json(request: Any) -> dict[str, Any]:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].lower()
    if content_type != "application/json":
        raise SidecarError("invalidRequest", "content type must be application/json", 415)
    advertised = request.headers.get("content-length")
    if advertised is not None:
        try:
            if int(advertised) > MAXIMUM_REQUEST_BYTES:
                raise SidecarError("invalidRequest", "request body is too large", 413)
        except ValueError as error:
            raise SidecarError("invalidRequest", "invalid content length", 400) from error
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAXIMUM_REQUEST_BYTES:
            raise SidecarError("invalidRequest", "request body is too large", 413)
    try:
        decoded = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SidecarError("invalidRequest", "request body is not valid JSON", 400) from error
    if not isinstance(decoded, dict):
        raise SidecarError("invalidRequest", "request body must be an object", 400)
    return decoded


def _validate_token(token: str) -> None:
    if (
        not token
        or len(token.encode()) > MAXIMUM_TOKEN_BYTES
        or any(character.isspace() or ord(character) < 33 or ord(character) > 126 for character in token)
    ):
        raise RuntimeError(
            "REMBRANE_GRAPHITI_BEARER_TOKEN must contain 1-8192 header-safe ASCII bytes"
        )


def _resolve_bearer_token() -> str:
    locator = os.environ.get(_TOKEN_REFERENCE_ENVIRONMENT, "")
    if not locator:
        return _resolve_environment_secret(_DEFAULT_TOKEN_ENVIRONMENT)
    source, separator, target = locator.partition(":")
    if not separator or not target:
        raise RuntimeError("Graphiti bearer credential unavailable")
    if source == "env":
        return _resolve_environment_secret(target)
    if source == "file":
        return _resolve_file_secret(target)
    raise RuntimeError("Graphiti bearer credential unavailable")


def _resolve_environment_secret(variable: str) -> str:
    if (
        len(variable) > 128
        or not variable
        or (not variable[0].isalpha() and variable[0] != "_")
        or any(
            not character.isascii()
            or not (character.isalnum() or character == "_")
            for character in variable
        )
    ):
        raise RuntimeError("Graphiti bearer credential unavailable")
    try:
        value = os.environ[variable]
    except (KeyError, UnicodeError) as error:
        raise RuntimeError("Graphiti bearer credential unavailable") from error
    return _validate_resolved_secret(value)


def _resolve_file_secret(path: str) -> str:
    if (
        len(path.encode()) > 4_096
        or path.strip() != path
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        raise RuntimeError("Graphiti bearer credential unavailable")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > MAXIMUM_SECRET_BYTES
            or metadata.st_mode & 0o077
        ):
            raise RuntimeError("Graphiti bearer credential unavailable")
        value = bytearray()
        while len(value) <= MAXIMUM_SECRET_BYTES:
            chunk = os.read(
                descriptor,
                min(8_192, MAXIMUM_SECRET_BYTES + 1 - len(value)),
            )
            if not chunk:
                break
            value.extend(chunk)
    except (OSError, UnicodeError, ValueError) as error:
        raise RuntimeError("Graphiti bearer credential unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(value) > MAXIMUM_SECRET_BYTES:
        raise RuntimeError("Graphiti bearer credential unavailable")
    if value.endswith(b"\n"):
        value.pop()
        if value.endswith(b"\r"):
            value.pop()
    try:
        decoded = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError("Graphiti bearer credential unavailable") from error
    finally:
        value[:] = b"\0" * len(value)
    return _validate_resolved_secret(decoded)


def _validate_resolved_secret(value: str) -> str:
    if not value or len(value.encode()) > MAXIMUM_SECRET_BYTES or "\0" in value:
        raise RuntimeError("Graphiti bearer credential unavailable")
    return value


def run() -> None:
    """Runs the production sidecar on the configured interface."""

    import uvicorn

    host = os.environ.get("REMBRANE_GRAPHITI_HOST", "127.0.0.1")
    port_text = os.environ.get("REMBRANE_GRAPHITI_PORT", "8793")
    try:
        port = int(port_text)
    except ValueError as error:
        raise RuntimeError("REMBRANE_GRAPHITI_PORT must be an integer") from error
    if not (1 <= port <= 65_535):
        raise RuntimeError("REMBRANE_GRAPHITI_PORT must be between 1 and 65535")
    uvicorn.run(create_app(), host=host, port=port, access_log=False)


if __name__ == "__main__":
    run()

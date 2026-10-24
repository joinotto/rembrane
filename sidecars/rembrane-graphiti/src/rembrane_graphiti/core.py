"""Dependency-free implementation of the Rembrane Graphiti sidecar contract."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any, Protocol

PROTOCOL_VERSION = "0.1"
MAXIMUM_CANDIDATES = 100
_NAMESPACE = re.compile(r"rb_[0-9a-f]{2,252}\Z")
_OPERATIONS = {
    "upsertNode",
    "upsertEdge",
    "neighbours",
    "deleteNode",
    "deleteEdge",
}


class SidecarError(Exception):
    """Portable sidecar rejection mapped to one protocol error code."""

    def __init__(self, code: str, message: str, status: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class NodeRecord:
    physical_id: str
    namespace: str
    canonical_id: str
    kind: str
    label: str
    aliases: tuple[str, ...]
    valid_from: int
    valid_until: int | None
    recorded_at: int
    version: int
    payload_digest: str


@dataclass(frozen=True)
class EdgeRecord:
    physical_id: str
    namespace: str
    canonical_id: str
    source_physical_id: str
    target_physical_id: str
    relation: str
    valid_from: int
    valid_until: int | None
    recorded_at: int
    version: int
    supersedes_canonical_id: str | None
    payload_digest: str


class GraphStore(Protocol):
    async def get_node(self, namespace: str, physical_id: str) -> NodeRecord | None: ...

    async def save_node(self, node: NodeRecord) -> None: ...

    async def delete_node(self, namespace: str, physical_id: str) -> None: ...

    async def get_edge(self, namespace: str, physical_id: str) -> EdgeRecord | None: ...

    async def save_edge(self, edge: EdgeRecord) -> None: ...

    async def delete_edge(self, namespace: str, physical_id: str) -> None: ...

    async def edges_for_node(
        self, namespace: str, physical_node_id: str, maximum_candidates: int
    ) -> list[EdgeRecord]: ...


class InMemoryGraphStore:
    """Disposable conformance store; never selected for production startup."""

    def __init__(self) -> None:
        self.nodes: dict[tuple[str, str], NodeRecord] = {}
        self.edges: dict[tuple[str, str], EdgeRecord] = {}

    async def get_node(self, namespace: str, physical_id: str) -> NodeRecord | None:
        return self.nodes.get((namespace, physical_id))

    async def save_node(self, node: NodeRecord) -> None:
        self.nodes[(node.namespace, node.physical_id)] = node

    async def delete_node(self, namespace: str, physical_id: str) -> None:
        self.nodes.pop((namespace, physical_id), None)
        self.edges = {
            key: edge
            for key, edge in self.edges.items()
            if key[0] != namespace
            or (
                edge.source_physical_id != physical_id
                and edge.target_physical_id != physical_id
            )
        }

    async def get_edge(self, namespace: str, physical_id: str) -> EdgeRecord | None:
        return self.edges.get((namespace, physical_id))

    async def save_edge(self, edge: EdgeRecord) -> None:
        self.edges[(edge.namespace, edge.physical_id)] = edge

    async def delete_edge(self, namespace: str, physical_id: str) -> None:
        self.edges.pop((namespace, physical_id), None)

    async def edges_for_node(
        self, namespace: str, physical_node_id: str, maximum_candidates: int
    ) -> list[EdgeRecord]:
        return [
            edge
            for (edge_namespace, _), edge in self.edges.items()
            if edge_namespace == namespace
            and (
                edge.source_physical_id == physical_node_id
                or edge.target_physical_id == physical_node_id
            )
        ][:maximum_candidates]


class SidecarService:
    def __init__(self, store: GraphStore) -> None:
        self._store = store

    async def execute(self, expected_operation: str, envelope: dict[str, Any]) -> dict[str, Any]:
        request_id, namespace, payload = _validate_envelope(expected_operation, envelope)
        try:
            if expected_operation == "upsertNode":
                result = await self._upsert_node(namespace, envelope, payload)
            elif expected_operation == "upsertEdge":
                result = await self._upsert_edge(namespace, envelope, payload)
            elif expected_operation == "neighbours":
                result = await self._neighbours(namespace, payload)
            elif expected_operation == "deleteNode":
                result = await self._delete_node(namespace, envelope, payload)
            elif expected_operation == "deleteEdge":
                result = await self._delete_edge(namespace, envelope, payload)
            else:
                raise SidecarError("invalidRequest", "unsupported operation")
            return {
                "requestId": request_id,
                "protocolVersion": PROTOCOL_VERSION,
                "result": result,
                "error": None,
            }
        except SidecarError as error:
            return {
                "requestId": request_id,
                "protocolVersion": PROTOCOL_VERSION,
                "result": None,
                "error": error.code,
            }

    async def _upsert_node(
        self, namespace: str, envelope: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, bool]:
        _require_idempotency(envelope)
        canonical_id = _required_text(payload, "nodeId")
        version = _positive_integer(payload, "version")
        validity = _validity(payload)
        label = _required_text(payload, "label")
        kind = _required_text(payload, "kind")
        aliases_value = payload.get("aliases", [])
        if not isinstance(aliases_value, list) or any(
            not isinstance(alias, str) or not alias for alias in aliases_value
        ):
            raise SidecarError("invalidRequest", "aliases must be non-empty strings")
        physical_id = physical_identifier(namespace, "node", canonical_id)
        digest = payload_digest(payload)
        existing = await self._store.get_node(namespace, physical_id)
        _enforce_optimistic_version(existing, version, digest)
        if existing is None or existing.version < version:
            await self._store.save_node(
                NodeRecord(
                    physical_id=physical_id,
                    namespace=namespace,
                    canonical_id=canonical_id,
                    kind=kind,
                    label=label,
                    aliases=tuple(aliases_value),
                    valid_from=validity[0],
                    valid_until=validity[1],
                    recorded_at=validity[2],
                    version=version,
                    payload_digest=digest,
                )
            )
        return {"accepted": True}

    async def _upsert_edge(
        self, namespace: str, envelope: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, bool]:
        _require_idempotency(envelope)
        canonical_id = _required_text(payload, "edgeId")
        source_id = _required_text(payload, "sourceId")
        target_id = _required_text(payload, "targetId")
        if source_id == target_id:
            raise SidecarError("invalidRequest", "edge endpoints must differ")
        version = _positive_integer(payload, "version")
        validity = _validity(payload)
        source_physical = physical_identifier(namespace, "node", source_id)
        target_physical = physical_identifier(namespace, "node", target_id)
        if (
            await self._store.get_node(namespace, source_physical) is None
            or await self._store.get_node(namespace, target_physical) is None
        ):
            raise SidecarError("conflict", "edge endpoints must exist")
        physical_id = physical_identifier(namespace, "edge", canonical_id)
        digest = payload_digest(payload)
        existing = await self._store.get_edge(namespace, physical_id)
        _enforce_optimistic_version(existing, version, digest)
        if existing is None or existing.version < version:
            supersedes = payload.get("supersedesEdgeId")
            if supersedes is not None and (not isinstance(supersedes, str) or not supersedes):
                raise SidecarError("invalidRequest", "invalid supersession identity")
            await self._store.save_edge(
                EdgeRecord(
                    physical_id=physical_id,
                    namespace=namespace,
                    canonical_id=canonical_id,
                    source_physical_id=source_physical,
                    target_physical_id=target_physical,
                    relation=_required_text(payload, "relation"),
                    valid_from=validity[0],
                    valid_until=validity[1],
                    recorded_at=validity[2],
                    version=version,
                    supersedes_canonical_id=supersedes,
                    payload_digest=digest,
                )
            )
        return {"accepted": True}

    async def _neighbours(
        self, namespace: str, payload: dict[str, Any]
    ) -> dict[str, list[dict[str, Any]]]:
        canonical_node_id = _required_text(payload, "nodeId")
        valid_at = _positive_integer(payload, "validAtEpochSeconds")
        limit = _positive_integer(payload, "maximumCandidates")
        if limit > MAXIMUM_CANDIDATES:
            raise SidecarError("invalidRequest", "candidate limit exceeds provider maximum")
        direction = payload.get("direction")
        if direction not in {"incoming", "outgoing", "both"}:
            raise SidecarError("invalidRequest", "invalid graph direction")
        physical_node_id = physical_identifier(namespace, "node", canonical_node_id)
        edges = await self._store.edges_for_node(namespace, physical_node_id, limit)
        candidates = []
        for edge in edges:
            direction_matches = (
                direction == "both"
                or (direction == "incoming" and edge.target_physical_id == physical_node_id)
                or (direction == "outgoing" and edge.source_physical_id == physical_node_id)
            )
            validity_matches = edge.valid_from <= valid_at and (
                edge.valid_until is None or valid_at < edge.valid_until
            )
            if direction_matches and validity_matches:
                candidates.append(
                    {"edgeId": edge.canonical_id, "version": edge.version}
                )
            if len(candidates) == limit:
                break
        return {"candidates": candidates}

    async def _delete_node(
        self, namespace: str, envelope: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, bool]:
        _require_idempotency(envelope)
        canonical_id = _required_text(payload, "nodeId")
        through_version = _positive_integer(payload, "throughVersion")
        physical_id = physical_identifier(namespace, "node", canonical_id)
        existing = await self._store.get_node(namespace, physical_id)
        if existing is not None and existing.version <= through_version:
            await self._store.delete_node(namespace, physical_id)
        return {"accepted": True}

    async def _delete_edge(
        self, namespace: str, envelope: dict[str, Any], payload: dict[str, Any]
    ) -> dict[str, bool]:
        _require_idempotency(envelope)
        canonical_id = _required_text(payload, "edgeId")
        through_version = _positive_integer(payload, "throughVersion")
        physical_id = physical_identifier(namespace, "edge", canonical_id)
        existing = await self._store.get_edge(namespace, physical_id)
        if existing is not None and existing.version <= through_version:
            await self._store.delete_edge(namespace, physical_id)
        return {"accepted": True}


def physical_identifier(namespace: str, kind: str, canonical_id: str) -> str:
    """Produces a deterministic UUID that cannot collide across workspaces."""

    if not _NAMESPACE.fullmatch(namespace) or kind not in {"node", "edge"} or not canonical_id:
        raise SidecarError("invalidRequest", "invalid physical identity input")
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"rembrane:{namespace}:{kind}:{canonical_id}"))


def payload_digest(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate_envelope(
    expected_operation: str, envelope: dict[str, Any]
) -> tuple[str, str, dict[str, Any]]:
    if expected_operation not in _OPERATIONS or not isinstance(envelope, dict):
        raise SidecarError("invalidRequest", "invalid operation envelope")
    request_id = _required_text(envelope, "requestId")
    if not (16 <= len(request_id) <= 128) or not all(
        character.isascii() and (character.isalnum() or character in "-_")
        for character in request_id
    ):
        raise SidecarError("invalidRequest", "invalid request identity")
    if envelope.get("protocolVersion") != PROTOCOL_VERSION:
        raise SidecarError("invalidRequest", "incompatible protocol")
    if envelope.get("operation") != expected_operation:
        raise SidecarError("invalidRequest", "operation does not match endpoint")
    namespace = _required_text(envelope, "namespace")
    if not _NAMESPACE.fullmatch(namespace):
        raise SidecarError("invalidRequest", "invalid workspace namespace")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise SidecarError("invalidRequest", "payload must be an object")
    return request_id, namespace, payload


def _require_idempotency(envelope: dict[str, Any]) -> str:
    key = _required_text(envelope, "idempotencyKey")
    if not (16 <= len(key) <= 255) or not all(
        character.isascii() and (character.isalnum() or character in ".-_")
        for character in key
    ):
        raise SidecarError("invalidRequest", "invalid idempotency key")
    return key


def _validity(payload: dict[str, Any]) -> tuple[int, int | None, int]:
    valid_from = _positive_integer(payload, "validFromEpochSeconds")
    recorded_at = _positive_integer(payload, "recordedAtEpochSeconds")
    valid_until = payload.get("validUntilEpochSeconds")
    if valid_until is not None and (
        isinstance(valid_until, bool)
        or not isinstance(valid_until, int)
        or valid_until <= valid_from
    ):
        raise SidecarError("invalidRequest", "invalid temporal validity")
    return valid_from, valid_until, recorded_at


def _positive_integer(value: dict[str, Any], key: str) -> int:
    candidate = value.get(key)
    if isinstance(candidate, bool) or not isinstance(candidate, int) or candidate <= 0:
        raise SidecarError("invalidRequest", f"{key} must be a positive integer")
    return candidate


def _required_text(value: dict[str, Any], key: str) -> str:
    candidate = value.get(key)
    if not isinstance(candidate, str) or not candidate:
        raise SidecarError("invalidRequest", f"{key} must be non-empty text")
    return candidate


def _enforce_optimistic_version(
    existing: NodeRecord | EdgeRecord | None, version: int, digest: str
) -> None:
    if existing is None:
        return
    if existing.version > version:
        raise SidecarError("conflict", "stale projection version", 409)
    if existing.version == version and existing.payload_digest != digest:
        raise SidecarError("conflict", "projection version content conflict", 409)

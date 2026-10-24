"""Production Graphiti persistence driver for exact Rembrane projections."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from .core import EdgeRecord, NodeRecord, SidecarError
from .secrets import resolve_secret

_NODE_PREFIX = "rembrane-node-v1:"
_EDGE_PREFIX = "rembrane-edge-v1:"


class GraphitiGraphStore:
    """Maps exact canonical records onto Graphiti entity nodes and edges."""

    def __init__(self, graphiti: Any) -> None:
        self._graphiti = graphiti

    @classmethod
    async def from_environment(cls) -> "GraphitiGraphStore":
        from graphiti_core import Graphiti

        uri = _required_environment("NEO4J_URI")
        user = _required_environment("NEO4J_USER")
        password = _database_password(user)
        model_api_key = resolve_secret(
            "OPENAI_API_KEY_REFERENCE",
            "OPENAI_API_KEY",
        )
        with _temporary_environment("OPENAI_API_KEY", model_api_key):
            graphiti = Graphiti(uri, user, password)
        try:
            await graphiti.build_indices_and_constraints()
        except Exception:
            await graphiti.close()
            raise
        return cls(graphiti)

    async def close(self) -> None:
        await self._graphiti.close()

    async def get_node(self, namespace: str, physical_id: str) -> NodeRecord | None:
        from graphiti_core.errors import NodeNotFoundError
        from graphiti_core.nodes import EntityNode

        try:
            node = await EntityNode.get_by_uuid(self._graphiti.driver, physical_id)
        except NodeNotFoundError:
            return None
        if node.group_id != namespace:
            return None
        return _decode_node(node)

    async def save_node(self, node: NodeRecord) -> None:
        from graphiti_core.nodes import EntityNode

        entity = EntityNode(
            uuid=node.physical_id,
            name=node.label,
            group_id=node.namespace,
            summary=_encode_node(node),
        )
        await entity.generate_name_embedding(self._graphiti.embedder)
        await entity.save(self._graphiti.driver)

    async def delete_node(self, namespace: str, physical_id: str) -> None:
        from graphiti_core.errors import NodeNotFoundError
        from graphiti_core.nodes import EntityNode

        for edge in await self._entity_edges(namespace):
            if edge.source_node_uuid == physical_id or edge.target_node_uuid == physical_id:
                await edge.delete(self._graphiti.driver)
        try:
            node = await EntityNode.get_by_uuid(self._graphiti.driver, physical_id)
        except NodeNotFoundError:
            return
        if node.group_id == namespace:
            await node.delete(self._graphiti.driver)

    async def get_edge(self, namespace: str, physical_id: str) -> EdgeRecord | None:
        from graphiti_core.edges import EntityEdge
        from graphiti_core.errors import EdgeNotFoundError

        try:
            edge = await EntityEdge.get_by_uuid(self._graphiti.driver, physical_id)
        except EdgeNotFoundError:
            return None
        if edge.group_id != namespace:
            return None
        return _decode_edge(edge)

    async def save_edge(self, edge: EdgeRecord) -> None:
        from graphiti_core.edges import EntityEdge

        entity = EntityEdge(
            uuid=edge.physical_id,
            group_id=edge.namespace,
            source_node_uuid=edge.source_physical_id,
            target_node_uuid=edge.target_physical_id,
            created_at=_instant(edge.recorded_at),
            name=edge.relation,
            fact=_encode_edge(edge),
            episodes=[],
            valid_at=_instant(edge.valid_from),
            invalid_at=_instant(edge.valid_until) if edge.valid_until is not None else None,
            expired_at=None,
        )
        await entity.generate_embedding(self._graphiti.embedder)
        await entity.save(self._graphiti.driver)

    async def delete_edge(self, namespace: str, physical_id: str) -> None:
        from graphiti_core.edges import EntityEdge
        from graphiti_core.errors import EdgeNotFoundError

        try:
            edge = await EntityEdge.get_by_uuid(self._graphiti.driver, physical_id)
        except EdgeNotFoundError:
            return
        if edge.group_id == namespace:
            await edge.delete(self._graphiti.driver)

    async def edges_for_node(
        self, namespace: str, physical_node_id: str, maximum_candidates: int
    ) -> list[EdgeRecord]:
        matches = []
        for edge in await self._entity_edges(namespace):
            if (
                edge.source_node_uuid == physical_node_id
                or edge.target_node_uuid == physical_node_id
            ):
                matches.append(_decode_edge(edge))
            if len(matches) == maximum_candidates:
                break
        return matches

    async def _entity_edges(self, namespace: str) -> list[Any]:
        from graphiti_core.edges import EntityEdge
        from graphiti_core.errors import GroupsEdgesNotFoundError

        try:
            return await EntityEdge.get_by_group_ids(self._graphiti.driver, [namespace])
        except GroupsEdgesNotFoundError:
            return []


def _encode_node(node: NodeRecord) -> str:
    return _NODE_PREFIX + _encode(
        {
            "canonicalId": node.canonical_id,
            "kind": node.kind,
            "label": node.label,
            "aliases": list(node.aliases),
            "validFrom": node.valid_from,
            "validUntil": node.valid_until,
            "recordedAt": node.recorded_at,
            "version": node.version,
            "payloadDigest": node.payload_digest,
        }
    )


def _decode_node(node: Any) -> NodeRecord:
    data = _decode(node.summary, _NODE_PREFIX)
    return NodeRecord(
        physical_id=node.uuid,
        namespace=node.group_id,
        canonical_id=_text(data, "canonicalId"),
        kind=_text(data, "kind"),
        label=_text(data, "label"),
        aliases=tuple(_text_list(data, "aliases")),
        valid_from=_integer(data, "validFrom"),
        valid_until=_optional_integer(data, "validUntil"),
        recorded_at=_integer(data, "recordedAt"),
        version=_integer(data, "version"),
        payload_digest=_digest(data),
    )


def _encode_edge(edge: EdgeRecord) -> str:
    return _EDGE_PREFIX + _encode(
        {
            "canonicalId": edge.canonical_id,
            "relation": edge.relation,
            "validFrom": edge.valid_from,
            "validUntil": edge.valid_until,
            "recordedAt": edge.recorded_at,
            "version": edge.version,
            "supersedesCanonicalId": edge.supersedes_canonical_id,
            "payloadDigest": edge.payload_digest,
        }
    )


def _decode_edge(edge: Any) -> EdgeRecord:
    data = _decode(edge.fact, _EDGE_PREFIX)
    supersedes = data.get("supersedesCanonicalId")
    if supersedes is not None and not isinstance(supersedes, str):
        raise SidecarError("internal", "stored edge supersession is invalid", 500)
    return EdgeRecord(
        physical_id=edge.uuid,
        namespace=edge.group_id,
        canonical_id=_text(data, "canonicalId"),
        source_physical_id=edge.source_node_uuid,
        target_physical_id=edge.target_node_uuid,
        relation=_text(data, "relation"),
        valid_from=_integer(data, "validFrom"),
        valid_until=_optional_integer(data, "validUntil"),
        recorded_at=_integer(data, "recordedAt"),
        version=_integer(data, "version"),
        supersedes_canonical_id=supersedes,
        payload_digest=_digest(data),
    )


def _encode(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _decode(value: Any, prefix: str) -> dict[str, Any]:
    if not isinstance(value, str) or not value.startswith(prefix):
        raise SidecarError("internal", "stored Graphiti record is not a Rembrane projection", 500)
    try:
        decoded = json.loads(value[len(prefix) :])
    except json.JSONDecodeError as error:
        raise SidecarError("internal", "stored Graphiti projection is malformed", 500) from error
    if not isinstance(decoded, dict):
        raise SidecarError("internal", "stored Graphiti projection is malformed", 500)
    return decoded


def _required_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is required by the Graphiti sidecar")
    return value


def _database_password(user: str) -> str:
    if os.environ.get("NEO4J_AUTH_REFERENCE"):
        authentication = resolve_secret(
            "NEO4J_AUTH_REFERENCE",
            "NEO4J_AUTH",
        )
        configured_user, separator, password = authentication.partition("/")
        if not separator or configured_user != user or not password:
            raise RuntimeError("Graphiti database credential unavailable")
        return password
    return resolve_secret("NEO4J_PASSWORD_REFERENCE", "NEO4J_PASSWORD")


@contextmanager
def _temporary_environment(name: str, value: str) -> Iterator[None]:
    previous = os.environ.get(name)
    os.environ[name] = value
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = previous


def _instant(epoch_seconds: int) -> datetime:
    return datetime.fromtimestamp(epoch_seconds, timezone.utc)


def _text(value: dict[str, Any], key: str) -> str:
    candidate = value.get(key)
    if not isinstance(candidate, str) or not candidate:
        raise SidecarError("internal", f"stored {key} is invalid", 500)
    return candidate


def _text_list(value: dict[str, Any], key: str) -> list[str]:
    candidate = value.get(key)
    if not isinstance(candidate, list) or any(
        not isinstance(item, str) or not item for item in candidate
    ):
        raise SidecarError("internal", f"stored {key} is invalid", 500)
    return candidate


def _integer(value: dict[str, Any], key: str) -> int:
    candidate = value.get(key)
    if isinstance(candidate, bool) or not isinstance(candidate, int) or candidate <= 0:
        raise SidecarError("internal", f"stored {key} is invalid", 500)
    return candidate


def _optional_integer(value: dict[str, Any], key: str) -> int | None:
    candidate = value.get(key)
    if candidate is None:
        return None
    if isinstance(candidate, bool) or not isinstance(candidate, int) or candidate <= 0:
        raise SidecarError("internal", f"stored {key} is invalid", 500)
    return candidate


def _digest(value: dict[str, Any]) -> str:
    candidate = _text(value, "payloadDigest")
    if len(candidate) != 64 or any(character not in "0123456789abcdef" for character in candidate):
        raise SidecarError("internal", "stored payload digest is invalid", 500)
    return candidate

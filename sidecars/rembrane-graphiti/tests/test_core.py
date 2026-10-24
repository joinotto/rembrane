import asyncio
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from rembrane_graphiti.core import InMemoryGraphStore, SidecarService, physical_identifier


def envelope(operation, namespace, payload, request="request_000000000001"):
    return {
        "requestId": request,
        "protocolVersion": "0.1",
        "operation": operation,
        "namespace": namespace,
        "idempotencyKey": "rembrane.projection.0001"
        if operation != "neighbours"
        else None,
        "payload": payload,
    }


def node(node_id, version=1, label=None):
    return {
        "nodeId": node_id,
        "kind": "concept",
        "label": label or node_id,
        "aliases": [],
        "validFromEpochSeconds": 100,
        "validUntilEpochSeconds": None,
        "recordedAtEpochSeconds": 100,
        "version": version,
    }


class SidecarCoreTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.store = InMemoryGraphStore()
        self.service = SidecarService(self.store)
        self.workspace_a = "rb_776f726b73706163652d61"
        self.workspace_b = "rb_776f726b73706163652d62"

    async def upsert_node(self, workspace, node_id, version=1, label=None):
        return await self.service.execute(
            "upsertNode", envelope("upsertNode", workspace, node(node_id, version, label))
        )

    async def test_physical_identity_is_deterministic_and_tenant_scoped(self):
        first = physical_identifier(self.workspace_a, "node", "same-id")
        self.assertEqual(first, physical_identifier(self.workspace_a, "node", "same-id"))
        self.assertNotEqual(
            first, physical_identifier(self.workspace_b, "node", "same-id")
        )

    async def test_rejects_cross_workspace_edge_endpoints(self):
        await self.upsert_node(self.workspace_a, "source")
        await self.upsert_node(self.workspace_b, "target")
        response = await self.service.execute(
            "upsertEdge",
            envelope(
                "upsertEdge",
                self.workspace_a,
                {
                    "edgeId": "edge",
                    "sourceId": "source",
                    "targetId": "target",
                    "relation": "uses",
                    "validFromEpochSeconds": 100,
                    "validUntilEpochSeconds": 200,
                    "recordedAtEpochSeconds": 100,
                    "version": 1,
                    "supersedesEdgeId": None,
                },
            ),
        )
        self.assertEqual(response["error"], "conflict")

    async def test_idempotent_retry_succeeds_but_same_version_conflict_fails(self):
        first = await self.upsert_node(self.workspace_a, "node")
        retry = await self.upsert_node(self.workspace_a, "node")
        conflict = await self.upsert_node(self.workspace_a, "node", label="changed")
        self.assertTrue(first["result"]["accepted"])
        self.assertTrue(retry["result"]["accepted"])
        self.assertEqual(conflict["error"], "conflict")

    async def test_temporal_neighbours_and_version_bounded_delete(self):
        await self.upsert_node(self.workspace_a, "source")
        await self.upsert_node(self.workspace_a, "target")
        await self.service.execute(
            "upsertEdge",
            envelope(
                "upsertEdge",
                self.workspace_a,
                {
                    "edgeId": "edge",
                    "sourceId": "source",
                    "targetId": "target",
                    "relation": "uses",
                    "validFromEpochSeconds": 100,
                    "validUntilEpochSeconds": 200,
                    "recordedAtEpochSeconds": 100,
                    "version": 2,
                    "supersedesEdgeId": None,
                },
            ),
        )
        visible = await self.service.execute(
            "neighbours",
            envelope(
                "neighbours",
                self.workspace_a,
                {
                    "nodeId": "source",
                    "direction": "outgoing",
                    "validAtEpochSeconds": 150,
                    "maximumCandidates": 10,
                },
            ),
        )
        expired = await self.service.execute(
            "neighbours",
            envelope(
                "neighbours",
                self.workspace_a,
                {
                    "nodeId": "source",
                    "direction": "outgoing",
                    "validAtEpochSeconds": 200,
                    "maximumCandidates": 10,
                },
            ),
        )
        self.assertEqual(visible["result"]["candidates"], [{"edgeId": "edge", "version": 2}])
        self.assertEqual(expired["result"]["candidates"], [])

        await self.service.execute(
            "deleteEdge",
            envelope(
                "deleteEdge",
                self.workspace_a,
                {"edgeId": "edge", "throughVersion": 1},
            ),
        )
        still_visible = await self.service.execute(
            "neighbours",
            envelope(
                "neighbours",
                self.workspace_a,
                {
                    "nodeId": "source",
                    "direction": "outgoing",
                    "validAtEpochSeconds": 150,
                    "maximumCandidates": 10,
                },
            ),
        )
        self.assertEqual(len(still_visible["result"]["candidates"]), 1)
        await self.service.execute(
            "deleteEdge",
            envelope(
                "deleteEdge",
                self.workspace_a,
                {"edgeId": "edge", "throughVersion": 2},
            ),
        )
        deleted = await self.service.execute(
            "neighbours",
            envelope(
                "neighbours",
                self.workspace_a,
                {
                    "nodeId": "source",
                    "direction": "outgoing",
                    "validAtEpochSeconds": 150,
                    "maximumCandidates": 10,
                },
            ),
        )
        self.assertEqual(deleted["result"]["candidates"], [])


if __name__ == "__main__":
    unittest.main()

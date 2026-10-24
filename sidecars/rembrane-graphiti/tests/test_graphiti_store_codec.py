import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from rembrane_graphiti.core import EdgeRecord, NodeRecord, SidecarError
from rembrane_graphiti.graphiti_store import (
    _decode_edge,
    _decode_node,
    _encode_edge,
    _encode_node,
)


class GraphitiStoreCodecTests(unittest.TestCase):
    def test_node_metadata_round_trips_without_exposing_it_as_graph_identity(self):
        record = NodeRecord(
            physical_id="physical-node",
            namespace="rb_776f726b7370616365",
            canonical_id="canonical-node",
            kind="project",
            label="Rembrane",
            aliases=("Central Memory",),
            valid_from=100,
            valid_until=None,
            recorded_at=101,
            version=3,
            payload_digest="a" * 64,
        )
        restored = _decode_node(
            SimpleNamespace(
                uuid=record.physical_id,
                group_id=record.namespace,
                summary=_encode_node(record),
            )
        )
        self.assertEqual(restored, record)

    def test_edge_metadata_round_trips_with_graphiti_endpoints(self):
        record = EdgeRecord(
            physical_id="physical-edge",
            namespace="rb_776f726b7370616365",
            canonical_id="canonical-edge",
            source_physical_id="physical-source",
            target_physical_id="physical-target",
            relation="uses",
            valid_from=100,
            valid_until=200,
            recorded_at=101,
            version=2,
            supersedes_canonical_id="older-edge",
            payload_digest="b" * 64,
        )
        restored = _decode_edge(
            SimpleNamespace(
                uuid=record.physical_id,
                group_id=record.namespace,
                source_node_uuid=record.source_physical_id,
                target_node_uuid=record.target_physical_id,
                fact=_encode_edge(record),
            )
        )
        self.assertEqual(restored, record)

    def test_rejects_non_rembrane_records_and_invalid_digests(self):
        with self.assertRaises(SidecarError):
            _decode_node(
                SimpleNamespace(
                    uuid="node",
                    group_id="rb_776f726b7370616365",
                    summary="provider-owned summary",
                )
            )
        record = NodeRecord(
            physical_id="node",
            namespace="rb_776f726b7370616365",
            canonical_id="canonical",
            kind="concept",
            label="label",
            aliases=(),
            valid_from=1,
            valid_until=None,
            recorded_at=1,
            version=1,
            payload_digest="not-a-digest",
        )
        with self.assertRaises(SidecarError):
            _decode_node(
                SimpleNamespace(
                    uuid=record.physical_id,
                    group_id=record.namespace,
                    summary=_encode_node(record),
                )
            )


if __name__ == "__main__":
    unittest.main()

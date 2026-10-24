import asyncio
import os
import sys
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from rembrane_graphiti.graphiti_store import GraphitiGraphStore


class FakeGraphiti:
    constructed = None

    def __init__(self, uri, user, password):
        self.driver = object()
        self.embedder = object()
        self.closed = False
        self.model_api_key = os.environ.get("OPENAI_API_KEY")
        type(self).constructed = (uri, user, password, self.model_api_key)

    async def build_indices_and_constraints(self):
        return None

    async def close(self):
        self.closed = True


class GraphitiStoreEnvironmentTests(unittest.TestCase):
    def test_resolves_credentials_and_removes_transient_model_environment(self):
        graphiti_module = ModuleType("graphiti_core")
        graphiti_module.Graphiti = FakeGraphiti
        with patch.dict(
            sys.modules,
            {"graphiti_core": graphiti_module},
        ), patch.dict(
            os.environ,
            {
                "NEO4J_URI": "bolt://neo4j:7687",
                "NEO4J_USER": "neo4j",
                "NEO4J_PASSWORD_REFERENCE": "env:TEST_NEO4J_PASSWORD",
                "TEST_NEO4J_PASSWORD": "database-secret",
                "OPENAI_API_KEY_REFERENCE": "env:TEST_OPENAI_API_KEY",
                "TEST_OPENAI_API_KEY": "model-secret",
            },
            clear=True,
        ):
            store = asyncio.run(GraphitiGraphStore.from_environment())
            self.assertEqual(
                FakeGraphiti.constructed,
                (
                    "bolt://neo4j:7687",
                    "neo4j",
                    "database-secret",
                    "model-secret",
                ),
            )
            self.assertNotIn("OPENAI_API_KEY", os.environ)
            asyncio.run(store.close())

    def test_restores_preexisting_model_environment_after_construction(self):
        graphiti_module = ModuleType("graphiti_core")
        graphiti_module.Graphiti = FakeGraphiti
        with patch.dict(
            sys.modules,
            {"graphiti_core": graphiti_module},
        ), patch.dict(
            os.environ,
            {
                "NEO4J_URI": "bolt://neo4j:7687",
                "NEO4J_USER": "neo4j",
                "NEO4J_PASSWORD": "database-secret",
                "OPENAI_API_KEY": "existing-model-secret",
                "OPENAI_API_KEY_REFERENCE": "env:SELECTED_MODEL_API_KEY",
                "SELECTED_MODEL_API_KEY": "selected-model-secret",
            },
            clear=True,
        ):
            asyncio.run(GraphitiGraphStore.from_environment())
            self.assertEqual(
                FakeGraphiti.constructed[-1],
                "selected-model-secret",
            )
            self.assertEqual(os.environ["OPENAI_API_KEY"], "existing-model-secret")

    def test_accepts_neo4j_auth_reference_only_for_the_configured_user(self):
        graphiti_module = ModuleType("graphiti_core")
        graphiti_module.Graphiti = FakeGraphiti
        environment = {
            "NEO4J_URI": "bolt://neo4j:7687",
            "NEO4J_USER": "neo4j",
            "NEO4J_AUTH_REFERENCE": "env:TEST_NEO4J_AUTH",
            "TEST_NEO4J_AUTH": "neo4j/database-secret",
            "OPENAI_API_KEY": "model-secret",
        }
        with patch.dict(
            sys.modules,
            {"graphiti_core": graphiti_module},
        ), patch.dict(os.environ, environment, clear=True):
            asyncio.run(GraphitiGraphStore.from_environment())
            self.assertEqual(FakeGraphiti.constructed[2], "database-secret")

        environment["TEST_NEO4J_AUTH"] = "another-user/database-secret"
        with patch.dict(
            sys.modules,
            {"graphiti_core": graphiti_module},
        ), patch.dict(os.environ, environment, clear=True):
            with self.assertRaisesRegex(
                RuntimeError, "^Graphiti database credential unavailable$"
            ):
                asyncio.run(GraphitiGraphStore.from_environment())


if __name__ == "__main__":
    unittest.main()

"""Tests for dependency ranking (lowest reference_load)."""

import unittest

from usmd.domain.usd import USDConfig, UnifiedSystemDomain
from usmd.mutation.dependency_rank import best_node_for_dependency
from usmd.node.node import Node
from usmd.node.state import NodeState


class TestBestNodeForDependency(unittest.TestCase):
    def test_picks_lowest_load(self):
        cfg = USDConfig(name="t")
        usd = UnifiedSystemDomain(cfg, b"\x00" * 32)
        a = Node(address="10.0.0.1", name=1, state=NodeState.ACTIVE)
        a.service_name = "db"
        a.reference_load = 0.9
        b = Node(address="10.0.0.2", name=2, state=NodeState.ACTIVE)
        b.service_name = "db"
        b.reference_load = 0.2
        usd.add_node(a)
        usd.add_node(b)
        best = best_node_for_dependency(usd, "db")
        self.assertIsNotNone(best)
        self.assertEqual(best.name, 2)

    def test_excludes_local(self):
        cfg = USDConfig(name="t")
        usd = UnifiedSystemDomain(cfg, b"\x00" * 32)
        a = Node(address="10.0.0.1", name=1, state=NodeState.ACTIVE)
        a.service_name = "db"
        a.reference_load = 0.1
        usd.add_node(a)
        self.assertIsNone(
            best_node_for_dependency(usd, "db", exclude_name=1)
        )


if __name__ == "__main__":
    unittest.main()

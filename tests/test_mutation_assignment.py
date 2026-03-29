"""Tests for static vs dynamic mutation assignment."""

import unittest

from usmd.domain.usd import USDConfig, UnifiedSystemDomain
from usmd.mutation.assignment import (
    apply_hosting_to_local_node,
    compute_hosting_planes,
    dynamics_claimed_by_reference_peers,
    peer_claimed_dynamic_names,
)
from usmd.mutation.catalog import MutationCatalog
from usmd.mutation.service import Service, ServiceType
from usmd.node.node import Node
from usmd.node.state import NodeState


class TestMutationAssignment(unittest.TestCase):
    def setUp(self) -> None:
        self.cat = MutationCatalog()
        self.cat.register(
            Service(name="web", service_type=ServiceType.STATIC), None
        )
        self.cat.register(
            Service(name="shard_a", service_type=ServiceType.DYNAMIC), None
        )
        self.cat.register(
            Service(name="shard_b", service_type=ServiceType.DYNAMIC), None
        )
        cfg = USDConfig(name="t")
        self.usd = UnifiedSystemDomain(cfg, b"\x00" * 32)

    def test_static_all_assigned_locally(self):
        local = Node(address="10.0.0.1", name=1, state=NodeState.ACTIVE)
        st, _dyn = compute_hosting_planes(self.cat, self.usd, local)
        self.assertEqual(st, ["web"])

    def test_dynamic_skips_reference_peer_claim(self):
        local = Node(address="10.0.0.1", name=1, state=NodeState.ACTIVE)
        local.reference_nodes = [2]
        peer = Node(address="10.0.0.2", name=2, state=NodeState.ACTIVE)
        peer.hosting_dynamic = ["shard_a"]
        self.usd.add_node(local)
        self.usd.add_node(peer)
        _st, dyn = compute_hosting_planes(self.cat, self.usd, local)
        self.assertIn("shard_b", dyn)
        self.assertNotIn("shard_a", dyn)

    def test_peer_legacy_service_name_dynamic(self):
        peer = Node(address="10.0.0.2", name=2, state=NodeState.ACTIVE)
        peer.service_name = "shard_b"
        peer.hosting_dynamic = []
        claimed = peer_claimed_dynamic_names(self.cat, peer)
        self.assertEqual(claimed, {"shard_b"})

    def test_apply_sets_service_name_primary_dynamic(self):
        local = Node(address="10.0.0.1", name=1, state=NodeState.ACTIVE)
        apply_hosting_to_local_node(self.cat, self.usd, local)
        self.assertEqual(local.hosting_static, ["web"])
        self.assertEqual(set(local.hosting_dynamic), {"shard_a", "shard_b"})
        self.assertEqual(local.service_name, "shard_a")

    def test_dynamics_claimed_union(self):
        local = Node(address="10.0.0.1", name=1, state=NodeState.ACTIVE)
        local.reference_nodes = [2, 3]
        p2 = Node(address="10.0.0.2", name=2, state=NodeState.ACTIVE)
        p2.hosting_dynamic = ["shard_a"]
        p3 = Node(address="10.0.0.3", name=3, state=NodeState.ACTIVE)
        p3.hosting_dynamic = ["shard_b"]
        self.usd.add_node(p2)
        self.usd.add_node(p3)
        taken = dynamics_claimed_by_reference_peers(
            self.cat, self.usd, local.reference_nodes
        )
        self.assertEqual(taken, {"shard_a", "shard_b"})
        _st, dyn = compute_hosting_planes(self.cat, self.usd, local)
        self.assertEqual(dyn, [])


if __name__ == "__main__":
    unittest.main()

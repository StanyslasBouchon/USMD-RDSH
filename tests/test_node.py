"""Tests for Node and NodeInfo."""

import unittest

from usmd.node.node import Node, NodeInfo
from usmd.node.state import NodeState


class TestNode(unittest.TestCase):

    def test_default_state_is_pending(self):
        node = Node(address="10.0.0.1", name=1710000000)
        self.assertEqual(node.state, NodeState.PENDING_APPROVAL)

    def test_custom_state(self):
        node = Node(address="10.0.0.1", name=1710000000, state=NodeState.ACTIVE)
        self.assertEqual(node.state, NodeState.ACTIVE)

    def test_set_state(self):
        node = Node(address="10.0.0.1", name=1710000000)
        node.set_state(NodeState.ACTIVE)
        self.assertEqual(node.state, NodeState.ACTIVE)

    def test_is_reachable_pending(self):
        node = Node(address="10.0.0.1", name=1710000000)
        self.assertFalse(node.is_reachable())

    def test_is_reachable_active(self):
        node = Node(address="10.0.0.1", name=1710000000, state=NodeState.ACTIVE)
        self.assertTrue(node.is_reachable())

    def test_is_not_reachable_inactive(self):
        node = Node(address="10.0.0.1", name=1710000000, state=NodeState.INACTIVE)
        self.assertFalse(node.is_reachable())

    def test_add_reference_node(self):
        node = Node(address="10.0.0.1", name=1)
        node.add_reference_node(2)
        self.assertIn(2, node.reference_nodes)

    def test_add_duplicate_reference_node_ignored(self):
        node = Node(address="10.0.0.1", name=1)
        node.add_reference_node(2)
        node.add_reference_node(2)
        self.assertEqual(node.reference_nodes.count(2), 1)

    def test_remove_reference_node(self):
        node = Node(address="10.0.0.1", name=1)
        node.add_reference_node(2)
        node.remove_reference_node(2)
        self.assertNotIn(2, node.reference_nodes)

    def test_remove_nonexistent_reference_node_safe(self):
        node = Node(address="10.0.0.1", name=1)
        # Should not raise
        node.remove_reference_node(9999)

    def test_to_info_fields(self):
        node = Node(address="10.0.0.5", name=1710000000, state=NodeState.ACTIVE,
                    service_name="backend")
        node.add_reference_node(1710000001)
        info = node.to_info()
        self.assertEqual(info.name, 1710000000)
        self.assertEqual(info.state, NodeState.ACTIVE)
        self.assertEqual(info.address, "10.0.0.5")
        self.assertEqual(info.service_name, "backend")
        self.assertIn(1710000001, info.reference_nodes)

    def test_to_info_reference_nodes_copy(self):
        node = Node(address="10.0.0.1", name=1)
        node.add_reference_node(2)
        info = node.to_info()
        # Modifying the info list should not affect the node
        info.reference_nodes.append(999)
        self.assertNotIn(999, node.reference_nodes)

    def test_name_auto_assigned_if_omitted(self):
        import time
        before = int(time.time())
        node = Node(address="10.0.0.1")
        after = int(time.time())
        self.assertGreaterEqual(node.name, before)
        self.assertLessEqual(node.name, after)

    def test_repr_contains_address(self):
        node = Node(address="192.168.1.1", name=1)
        self.assertIn("192.168.1.1", repr(node))

    def test_hosts_service_static_and_dynamic(self):
        node = Node(address="10.0.0.1", name=1, state=NodeState.ACTIVE)
        node.hosting_static = ["s1"]
        node.hosting_dynamic = ["d1"]
        self.assertTrue(node.hosts_service("s1"))
        self.assertTrue(node.hosts_service("d1"))
        self.assertFalse(node.hosts_service("other"))

    def test_iter_hosted_service_names_order(self):
        node = Node(address="10.0.0.1", name=1)
        node.hosting_static = ["a"]
        node.hosting_dynamic = ["b"]
        self.assertEqual(list(node.iter_hosted_service_names()), ["a", "b"])


class TestNodeInfo(unittest.TestCase):

    def test_create(self):
        info = NodeInfo(
            name=1710000000,
            state=NodeState.ACTIVE,
            address="10.0.0.1",
            service_name="frontend",
        )
        self.assertEqual(info.name, 1710000000)
        self.assertEqual(info.service_name, "frontend")

    def test_default_reference_nodes_empty(self):
        info = NodeInfo(name=1, state=NodeState.ACTIVE, address="1.2.3.4")
        self.assertEqual(info.reference_nodes, [])

    def test_default_service_name_none(self):
        info = NodeInfo(name=1, state=NodeState.PENDING_APPROVAL, address="1.2.3.4")
        self.assertIsNone(info.service_name)

    def test_default_hosting_lists_empty(self):
        info = NodeInfo(name=1, state=NodeState.ACTIVE, address="1.2.3.4")
        self.assertEqual(info.hosting_static, [])
        self.assertEqual(info.hosting_dynamic, [])


if __name__ == "__main__":
    unittest.main()

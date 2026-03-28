"""Tests for UnifiedSystemDomain (USD) and EdbParser."""

import unittest

from usmd.domain.edb import EdbEntry, EdbParser
from usmd.domain.usd import USDConfig, UnifiedSystemDomain
from usmd.node.node import Node
from usmd.node.state import NodeState


def _make_usd(name: str = "test-domain") -> UnifiedSystemDomain:
    cfg = USDConfig(name=name, cluster_name="test-cluster")
    return UnifiedSystemDomain(config=cfg, private_key=b"\x00" * 32)


class TestUSDConfig(unittest.TestCase):

    def test_defaults(self):
        cfg = USDConfig(name="prod")
        self.assertEqual(cfg.max_reference_nodes, 5)
        self.assertAlmostEqual(cfg.load_threshold, 0.8)
        self.assertEqual(cfg.ping_tolerance_ms, 200)

    def test_custom_values(self):
        cfg = USDConfig(
            name="staging",
            cluster_name="eu",
            max_reference_nodes=3,
            load_threshold=0.75,
            ping_tolerance_ms=100,
        )
        self.assertEqual(cfg.cluster_name, "eu")
        self.assertEqual(cfg.max_reference_nodes, 3)


class TestUnifiedSystemDomain(unittest.TestCase):

    def setUp(self):
        self.usd = _make_usd()

    def test_config_accessible(self):
        self.assertEqual(self.usd.config.name, "test-domain")

    def test_add_node_ok(self):
        node = Node(address="10.0.0.1", name=1710000001)
        result = self.usd.add_node(node)
        self.assertTrue(result.is_ok())

    def test_add_duplicate_node_fails(self):
        node = Node(address="10.0.0.1", name=1710000001)
        self.usd.add_node(node)
        result = self.usd.add_node(node)
        self.assertTrue(result.is_err())

    def test_get_node_returns_node(self):
        node = Node(address="10.0.0.1", name=1710000001)
        self.usd.add_node(node)
        self.assertIs(self.usd.get_node(1710000001), node)

    def test_get_node_unknown_returns_none(self):
        self.assertIsNone(self.usd.get_node(9999))

    def test_remove_node_ok(self):
        node = Node(address="10.0.0.1", name=1710000001)
        self.usd.add_node(node)
        result = self.usd.remove_node(1710000001)
        self.assertTrue(result.is_ok())
        self.assertIsNone(self.usd.get_node(1710000001))

    def test_remove_node_unknown_fails(self):
        result = self.usd.remove_node(9999)
        self.assertTrue(result.is_err())

    def test_active_nodes_only_active(self):
        n1 = Node(address="10.0.0.1", name=1, state=NodeState.ACTIVE)
        n2 = Node(address="10.0.0.2", name=2, state=NodeState.INACTIVE)
        n3 = Node(address="10.0.0.3", name=3, state=NodeState.ACTIVE)
        for n in (n1, n2, n3):
            self.usd.add_node(n)
        active = self.usd.active_nodes()
        self.assertEqual(len(active), 2)
        self.assertIn(n1, active)
        self.assertIn(n3, active)

    def test_all_node_infos_count(self):
        for i in range(3):
            self.usd.add_node(Node(address=f"10.0.0.{i+1}", name=i + 1))
        infos = self.usd.all_node_infos()
        self.assertEqual(len(infos), 3)

    def test_update_config_newer_version(self):
        new_cfg = USDConfig(name="test-domain", version=2)
        self.usd.update_config(new_cfg)
        self.assertEqual(self.usd.config.version, 2)

    def test_update_config_older_version_ignored(self):
        self.usd.config.version = 5
        old_cfg = USDConfig(name="test-domain", version=3)
        self.usd.update_config(old_cfg)
        self.assertEqual(self.usd.config.version, 5)


class TestEdbParser(unittest.TestCase):

    SAMPLE = "Node1: 10.0.0.1\nNode2: 192.168.1.5\n"

    def test_parse_returns_entries(self):
        entries = EdbParser.parse(self.SAMPLE)
        self.assertEqual(len(entries), 2)

    def test_parse_names_and_addresses(self):
        entries = EdbParser.parse(self.SAMPLE)
        self.assertEqual(entries[0].name, "Node1")
        self.assertEqual(entries[0].address, "10.0.0.1")
        self.assertEqual(entries[1].name, "Node2")
        self.assertEqual(entries[1].address, "192.168.1.5")

    def test_parse_ignores_blank_lines(self):
        content = "\nNode1: 1.2.3.4\n\nNode2: 5.6.7.8\n"
        entries = EdbParser.parse(content)
        self.assertEqual(len(entries), 2)

    def test_parse_ignores_comments(self):
        content = "# this is a comment\nNode1: 10.0.0.1\n"
        entries = EdbParser.parse(content)
        self.assertEqual(len(entries), 1)

    def test_parse_malformed_line_skipped(self):
        content = "Node1: 10.0.0.1\nbadline\n"
        entries = EdbParser.parse(content)
        self.assertEqual(len(entries), 1)

    def test_parse_empty_returns_empty_list(self):
        entries = EdbParser.parse("")
        self.assertEqual(entries, [])

    def test_parse_result_ok_with_entries(self):
        result = EdbParser.parse_result(self.SAMPLE)
        self.assertTrue(result.is_ok())

    def test_parse_result_err_on_empty(self):
        result = EdbParser.parse_result("")
        self.assertTrue(result.is_err())

    def test_edb_entry_dataclass(self):
        entry = EdbEntry(name="MyNode", address="172.16.0.1")
        self.assertEqual(entry.name, "MyNode")
        self.assertEqual(entry.address, "172.16.0.1")


if __name__ == "__main__":
    unittest.main()

"""Tests for NodeRole enumeration."""

import unittest

from usmd.node.role import NodeRole


class TestNodeRole(unittest.TestCase):

    def test_ucd_operator_can_manage_ucd(self):
        self.assertTrue(NodeRole.UCD_OPERATOR.can_manage_ucd())

    def test_usd_operator_can_manage_usd(self):
        self.assertTrue(NodeRole.USD_OPERATOR.can_manage_usd())

    def test_node_operator_can_manage_nodes(self):
        self.assertTrue(NodeRole.NODE_OPERATOR.can_manage_nodes())

    def test_node_executor_can_execute(self):
        self.assertTrue(NodeRole.NODE_EXECUTOR.can_execute())

    def test_roles_are_exclusive(self):
        """Each role only allows its specific permission."""
        self.assertFalse(NodeRole.NODE_EXECUTOR.can_manage_ucd())
        self.assertFalse(NodeRole.NODE_EXECUTOR.can_manage_usd())
        self.assertFalse(NodeRole.NODE_EXECUTOR.can_manage_nodes())

        self.assertFalse(NodeRole.UCD_OPERATOR.can_manage_usd())
        self.assertFalse(NodeRole.UCD_OPERATOR.can_execute())

    def test_ucd_operator_does_not_require_keys(self):
        self.assertFalse(NodeRole.UCD_OPERATOR.requires_ucd_key())
        self.assertFalse(NodeRole.UCD_OPERATOR.requires_usd_key())

    def test_usd_operator_requires_ucd_key_not_usd(self):
        self.assertTrue(NodeRole.USD_OPERATOR.requires_ucd_key())
        self.assertFalse(NodeRole.USD_OPERATOR.requires_usd_key())

    def test_node_operator_requires_both_keys(self):
        self.assertTrue(NodeRole.NODE_OPERATOR.requires_ucd_key())
        self.assertTrue(NodeRole.NODE_OPERATOR.requires_usd_key())

    def test_node_executor_requires_both_keys(self):
        self.assertTrue(NodeRole.NODE_EXECUTOR.requires_ucd_key())
        self.assertTrue(NodeRole.NODE_EXECUTOR.requires_usd_key())

    def test_str_returns_value(self):
        self.assertEqual(str(NodeRole.NODE_EXECUTOR), "node_executor")


if __name__ == "__main__":
    unittest.main()

"""Tests for NodeAccessList (NAL)."""

import unittest

from usmd.node.nal import NodeAccessList
from usmd.node.role import NodeRole


class TestNodeAccessList(unittest.TestCase):

    def setUp(self):
        self.nal = NodeAccessList()
        self.key = b"k" * 32

    def test_grant_and_has_role(self):
        self.nal.grant(self.key, NodeRole.NODE_EXECUTOR)
        self.assertTrue(self.nal.has_role(self.key, NodeRole.NODE_EXECUTOR))

    def test_no_role_returns_false(self):
        self.assertFalse(self.nal.has_role(self.key, NodeRole.UCD_OPERATOR))

    def test_revoke_role(self):
        self.nal.grant(self.key, NodeRole.NODE_EXECUTOR)
        result = self.nal.revoke(self.key, NodeRole.NODE_EXECUTOR)
        self.assertTrue(result.is_ok())
        self.assertFalse(self.nal.has_role(self.key, NodeRole.NODE_EXECUTOR))

    def test_revoke_all_roles(self):
        self.nal.grant(self.key, NodeRole.NODE_EXECUTOR)
        self.nal.grant(self.key, NodeRole.NODE_OPERATOR)
        result = self.nal.revoke(self.key)
        self.assertTrue(result.is_ok())
        self.assertEqual(len(self.nal.get_roles(self.key)), 0)

    def test_revoke_permanent_fails(self):
        self.nal.grant(self.key, NodeRole.UCD_OPERATOR, permanent=True)
        result = self.nal.revoke(self.key)
        self.assertTrue(result.is_err())

    def test_revoke_unknown_key_fails(self):
        result = self.nal.revoke(b"z" * 32)
        self.assertTrue(result.is_err())

    def test_authorize_ok(self):
        self.nal.grant(self.key, NodeRole.NODE_OPERATOR)
        result = self.nal.authorize(self.key, NodeRole.NODE_OPERATOR)
        self.assertTrue(result.is_ok())

    def test_authorize_fails_missing_role(self):
        self.nal.grant(self.key, NodeRole.NODE_EXECUTOR)
        result = self.nal.authorize(self.key, NodeRole.NODE_OPERATOR)
        self.assertTrue(result.is_err())

    def test_is_permanent(self):
        self.nal.grant(self.key, NodeRole.UCD_OPERATOR, permanent=True)
        self.assertTrue(self.nal.is_permanent(self.key))

    def test_not_permanent_by_default(self):
        self.nal.grant(self.key, NodeRole.NODE_EXECUTOR)
        self.assertFalse(self.nal.is_permanent(self.key))

    def test_get_roles_multiple(self):
        self.nal.grant(self.key, NodeRole.NODE_EXECUTOR)
        self.nal.grant(self.key, NodeRole.NODE_OPERATOR)
        roles = self.nal.get_roles(self.key)
        self.assertIn(NodeRole.NODE_EXECUTOR, roles)
        self.assertIn(NodeRole.NODE_OPERATOR, roles)

    def test_len(self):
        self.nal.grant(b"a" * 32, NodeRole.NODE_EXECUTOR)
        self.nal.grant(b"b" * 32, NodeRole.USD_OPERATOR)
        self.assertEqual(len(self.nal), 2)


if __name__ == "__main__":
    unittest.main()

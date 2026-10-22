"""Tests for NodeIdentityTable (NIT)."""

import time
import unittest

from usmd.node.nit import NitEntry, NodeIdentityTable


class TestNodeIdentityTable(unittest.TestCase):

    def setUp(self):
        self.nit = NodeIdentityTable()
        self.key_a = b"a" * 32
        self.key_b = b"b" * 32

    def test_register_and_validate(self):
        self.nit.register("10.0.0.1", self.key_a, ttl=3600)
        result = self.nit.validate("10.0.0.1", self.key_a)
        self.assertTrue(result.is_ok())

    def test_validate_wrong_address(self):
        self.nit.register("10.0.0.1", self.key_a, ttl=3600)
        result = self.nit.validate("10.0.0.2", self.key_a)
        self.assertTrue(result.is_err())

    def test_validate_unknown_key(self):
        result = self.nit.validate("10.0.0.1", self.key_a)
        self.assertTrue(result.is_err())

    def test_get_address(self):
        self.nit.register("192.168.1.5", self.key_a)
        self.assertEqual(self.nit.get_address(self.key_a), "192.168.1.5")

    def test_get_address_unknown_returns_none(self):
        self.assertIsNone(self.nit.get_address(b"x" * 32))

    def test_multiple_keys_same_address(self):
        self.nit.register("10.0.0.1", self.key_a)
        self.nit.register("10.0.0.1", self.key_b)
        keys = self.nit.get_keys_for_address("10.0.0.1")
        self.assertIn(self.key_a, keys)
        self.assertIn(self.key_b, keys)

    def test_remove_entry(self):
        self.nit.register("10.0.0.1", self.key_a)
        self.nit.remove(self.key_a)
        self.assertIsNone(self.nit.get_address(self.key_a))

    def test_expired_entry_fails_validation(self):
        entry = NitEntry(address="10.0.0.1", public_key=self.key_a, ttl=1,
                         registered_at=time.time() - 10)
        self.nit._entries[self.key_a] = entry
        result = self.nit.validate("10.0.0.1", self.key_a)
        self.assertTrue(result.is_err())

    def test_purge_expired(self):
        entry = NitEntry(address="10.0.0.1", public_key=self.key_a, ttl=1,
                         registered_at=time.time() - 10)
        self.nit._entries[self.key_a] = entry
        removed = self.nit.purge_expired()
        self.assertEqual(removed, 1)
        self.assertEqual(len(self.nit), 0)

    def test_len(self):
        self.nit.register("10.0.0.1", self.key_a)
        self.nit.register("10.0.0.2", self.key_b)
        self.assertEqual(len(self.nit), 2)


if __name__ == "__main__":
    unittest.main()

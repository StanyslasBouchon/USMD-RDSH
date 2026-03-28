"""Tests for NodeEndorsementList (NEL)."""

import time
import unittest

from usmd.node.nel import EndorsementPacket, NodeEndorsementList
from usmd.node.role import NodeRole


def _make_packet(
    endorser_key: bytes = b"e" * 32,
    node_pub_key: bytes = b"n" * 32,
    expiration: int | None = None,
) -> EndorsementPacket:
    """Helper: build a dummy EndorsementPacket."""
    if expiration is None:
        expiration = int(time.time()) + 86400
    return EndorsementPacket(
        endorser_key=endorser_key,
        node_name=1710000000,
        node_pub_key=node_pub_key,
        node_session_key=b"s" * 32,
        roles=[NodeRole.NODE_EXECUTOR],
        serial=b"\x00" * 16,
        expiration=expiration,
        signature=b"\xff" * 64,
    )


class TestEndorsementPacket(unittest.TestCase):

    def test_not_expired_future(self):
        p = _make_packet(expiration=int(time.time()) + 9999)
        self.assertFalse(p.is_expired())

    def test_expired_past(self):
        p = _make_packet(expiration=int(time.time()) - 1)
        self.assertTrue(p.is_expired())

    def test_signable_bytes_is_bytes(self):
        p = _make_packet()
        result = p.signable_bytes()
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), 0)

    def test_signable_bytes_contains_endorser_key(self):
        key = b"E" * 32
        p = _make_packet(endorser_key=key)
        self.assertIn(key, p.signable_bytes())

    def test_signable_bytes_excludes_signature(self):
        p = _make_packet()
        # signature is b"\xff" * 64 — should not appear in signable bytes
        self.assertNotIn(p.signature, p.signable_bytes())


class TestNodeEndorsementList(unittest.TestCase):

    def setUp(self):
        self.nel = NodeEndorsementList()
        self.packet = _make_packet()

    def test_initial_empty(self):
        self.assertFalse(self.nel.has_issued_to(b"n" * 32))
        self.assertIsNone(self.nel.get_received())

    def test_add_issued(self):
        self.nel.add_issued(self.packet)
        self.assertTrue(self.nel.has_issued_to(b"n" * 32))

    def test_get_issued_returns_packet(self):
        self.nel.add_issued(self.packet)
        retrieved = self.nel.get_issued(b"n" * 32)
        self.assertIs(retrieved, self.packet)

    def test_get_issued_unknown_returns_none(self):
        self.assertIsNone(self.nel.get_issued(b"x" * 32))

    def test_revoke_issued_ok(self):
        self.nel.add_issued(self.packet)
        result = self.nel.revoke_issued(b"n" * 32)
        self.assertTrue(result.is_ok())
        self.assertFalse(self.nel.has_issued_to(b"n" * 32))

    def test_revoke_issued_unknown_err(self):
        result = self.nel.revoke_issued(b"x" * 32)
        self.assertTrue(result.is_err())

    def test_all_issued(self):
        p1 = _make_packet(node_pub_key=b"a" * 32)
        p2 = _make_packet(node_pub_key=b"b" * 32)
        self.nel.add_issued(p1)
        self.nel.add_issued(p2)
        all_packets = self.nel.all_issued()
        self.assertEqual(len(all_packets), 2)

    def test_set_and_get_received(self):
        self.nel.set_received(self.packet)
        self.assertIs(self.nel.get_received(), self.packet)

    def test_clear_received(self):
        self.nel.set_received(self.packet)
        self.nel.clear_received()
        self.assertIsNone(self.nel.get_received())

    def test_repr(self):
        r = repr(self.nel)
        self.assertIn("NodeEndorsementList", r)


if __name__ == "__main__":
    unittest.main()

"""Tests for EndorsementFactory and EndorsementVerifier."""

import time
import unittest

from usmd.node.nel import EndorsementPacket
from usmd.node.role import NodeRole
from usmd.security.crypto import Ed25519Pair, X25519Pair
from usmd.security.endorsement import EndorsementFactory, EndorsementVerifier


class TestEndorsementFactory(unittest.TestCase):

    def setUp(self):
        self.endorser_priv, self.endorser_pub = Ed25519Pair.generate()
        self.node_priv, self.node_pub = Ed25519Pair.generate()
        self.session_priv, self.session_pub = X25519Pair.generate()
        self.factory = EndorsementFactory(self.endorser_priv, self.endorser_pub)

    def test_issue_returns_endorsement_packet(self):
        packet = self.factory.issue(
            node_name=1710000000,
            node_pub_key=self.node_pub,
            node_session_key=self.session_pub,
            roles=[NodeRole.NODE_EXECUTOR],
        )
        self.assertIsInstance(packet, EndorsementPacket)

    def test_endorser_key_matches(self):
        packet = self.factory.issue(1710000000, self.node_pub, self.session_pub,
                                    [NodeRole.NODE_EXECUTOR])
        self.assertEqual(packet.endorser_key, self.endorser_pub)

    def test_node_pub_key_matches(self):
        packet = self.factory.issue(1710000000, self.node_pub, self.session_pub,
                                    [NodeRole.NODE_EXECUTOR])
        self.assertEqual(packet.node_pub_key, self.node_pub)

    def test_roles_preserved(self):
        roles = [NodeRole.NODE_OPERATOR, NodeRole.NODE_EXECUTOR]
        packet = self.factory.issue(1710000000, self.node_pub, self.session_pub, roles)
        self.assertEqual(packet.roles, roles)

    def test_signature_is_64_bytes(self):
        packet = self.factory.issue(1710000000, self.node_pub, self.session_pub,
                                    [NodeRole.NODE_EXECUTOR])
        self.assertEqual(len(packet.signature), 64)

    def test_serial_is_16_bytes(self):
        packet = self.factory.issue(1710000000, self.node_pub, self.session_pub,
                                    [NodeRole.NODE_EXECUTOR])
        self.assertEqual(len(packet.serial), 16)

    def test_expiration_in_future(self):
        packet = self.factory.issue(1710000000, self.node_pub, self.session_pub,
                                    [NodeRole.NODE_EXECUTOR], ttl_seconds=3600)
        self.assertGreater(packet.expiration, time.time())

    def test_ttl_applied_correctly(self):
        ttl = 7200
        before = int(time.time())
        packet = self.factory.issue(1710000000, self.node_pub, self.session_pub,
                                    [NodeRole.NODE_EXECUTOR], ttl_seconds=ttl)
        after = int(time.time())
        self.assertGreaterEqual(packet.expiration, before + ttl)
        self.assertLessEqual(packet.expiration, after + ttl)


class TestEndorsementVerifier(unittest.TestCase):

    def setUp(self):
        self.endorser_priv, self.endorser_pub = Ed25519Pair.generate()
        self.node_priv, self.node_pub = Ed25519Pair.generate()
        self.session_priv, self.session_pub = X25519Pair.generate()
        self.factory = EndorsementFactory(self.endorser_priv, self.endorser_pub)
        self.verifier = EndorsementVerifier()

    def _issue(self, **kwargs):
        defaults = dict(
            node_name=1710000000,
            node_pub_key=self.node_pub,
            node_session_key=self.session_pub,
            roles=[NodeRole.NODE_EXECUTOR],
        )
        defaults.update(kwargs)
        return self.factory.issue(**defaults)

    def test_verify_valid_packet(self):
        packet = self._issue()
        result = self.verifier.verify(packet)
        self.assertTrue(result.is_ok())

    def test_verify_expired_packet_fails(self):
        packet = self._issue(ttl_seconds=-1)
        result = self.verifier.verify(packet)
        self.assertTrue(result.is_err())

    def test_verify_tampered_signature_fails(self):
        packet = self._issue()
        # Flip a byte in the signature
        bad_sig = bytearray(packet.signature)
        bad_sig[0] ^= 0xFF
        packet.signature = bytes(bad_sig)
        result = self.verifier.verify(packet)
        self.assertTrue(result.is_err())

    def test_verify_with_nel_check_known_endorser(self):
        packet = self._issue()
        result = self.verifier.verify_with_nel_check(packet, endorser_known=True)
        self.assertTrue(result.is_ok())

    def test_verify_with_nel_check_unknown_endorser_fails(self):
        packet = self._issue()
        result = self.verifier.verify_with_nel_check(packet, endorser_known=False)
        self.assertTrue(result.is_err())

    def test_verify_with_nel_check_expired_packet_fails(self):
        packet = self._issue(ttl_seconds=-1)
        result = self.verifier.verify_with_nel_check(packet, endorser_known=True)
        self.assertTrue(result.is_err())


if __name__ == "__main__":
    unittest.main()

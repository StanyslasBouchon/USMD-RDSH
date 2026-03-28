"""Tests for NNDP Here I Am (HIA) packet."""

import unittest

from usmd.nndp.protocol.here_i_am import HereIAmPacket, HiaData, PACKET_SIZE
from usmd.node.state import NodeState
from usmd.security.crypto import Ed25519Pair


class TestHiaData(unittest.TestCase):

    def test_build_correct_ttl(self):
        data = HiaData.build(ttl=60)
        self.assertEqual(data.ttl, 60)

    def test_build_nonce_8_bytes(self):
        data = HiaData.build(ttl=30)
        self.assertEqual(len(data.nonce), 8)

    def test_to_bytes_is_24(self):
        data = HiaData.build(ttl=30)
        self.assertEqual(len(data.to_bytes()), 24)

    def test_from_bytes_roundtrip(self):
        data = HiaData.build(ttl=45)
        raw = data.to_bytes()
        result = HiaData.from_bytes(raw)
        self.assertTrue(result.is_ok())
        parsed = result.unwrap()
        self.assertEqual(parsed.ttl, 45)
        self.assertEqual(parsed.timestamp_ms, data.timestamp_ms)
        self.assertEqual(parsed.nonce, data.nonce)

    def test_from_bytes_too_short_fails(self):
        result = HiaData.from_bytes(b"\x00" * 10)
        self.assertTrue(result.is_err())


class TestHereIAmPacket(unittest.TestCase):

    def setUp(self):
        self.priv, self.pub = Ed25519Pair.generate()

    def test_build_returns_packet(self):
        pkt = HereIAmPacket.build(
            sender_name=1710000000,
            sender_pub_key=self.pub,
            sender_priv_key=self.priv,
            ttl=30,
            state=NodeState.ACTIVE,
        )
        self.assertIsInstance(pkt, HereIAmPacket)

    def test_to_bytes_length(self):
        pkt = HereIAmPacket.build(1710000000, self.pub, self.priv, 30, NodeState.ACTIVE)
        self.assertEqual(len(pkt.to_bytes()), PACKET_SIZE)
        self.assertEqual(PACKET_SIZE, 124)

    def test_verify_and_parse_valid(self):
        pkt = HereIAmPacket.build(0, self.pub, self.priv, 30, NodeState.ACTIVE)
        result = HereIAmPacket.verify_and_parse(pkt.to_bytes(), self.pub)
        self.assertTrue(result.is_ok())

    def test_verify_and_parse_wrong_key_fails(self):
        pkt = HereIAmPacket.build(0, self.pub, self.priv, 30, NodeState.ACTIVE)
        _, other_pub = Ed25519Pair.generate()
        result = HereIAmPacket.verify_and_parse(pkt.to_bytes(), other_pub)
        self.assertTrue(result.is_err())

    def test_verify_and_parse_tampered_fails(self):
        pkt = HereIAmPacket.build(0, self.pub, self.priv, 30, NodeState.ACTIVE)
        raw = bytearray(pkt.to_bytes())
        raw[36] ^= 0xFF  # flip a byte in the HIA data
        result = HereIAmPacket.verify_and_parse(bytes(raw), self.pub)
        self.assertTrue(result.is_err())

    def test_verify_and_parse_too_short_fails(self):
        result = HereIAmPacket.verify_and_parse(b"\x00" * 50, self.pub)
        self.assertTrue(result.is_err())

    def test_parsed_pub_key_matches(self):
        pkt = HereIAmPacket.build(0, self.pub, self.priv, 30, NodeState.ACTIVE)
        parsed = HereIAmPacket.verify_and_parse(pkt.to_bytes(), self.pub).unwrap()
        self.assertEqual(parsed.sender_pub_key, self.pub)

    def test_ttl_preserved_in_packet(self):
        ttl = 120
        pkt = HereIAmPacket.build(0, self.pub, self.priv, ttl, NodeState.ACTIVE)
        parsed = HereIAmPacket.verify_and_parse(pkt.to_bytes(), self.pub).unwrap()
        self.assertEqual(parsed.data.ttl, ttl)


if __name__ == "__main__":
    unittest.main()

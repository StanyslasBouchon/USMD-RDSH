"""Tests for NCP frame serialisation and command IDs."""

import unittest

from usmd.ncp.protocol.frame import NcpCommandId, NcpFrame
from usmd.ncp.protocol.versions import NcpVersion


V1 = NcpVersion(1, 0, 0, 0)


class TestNcpCommandId(unittest.TestCase):

    def test_all_ten_commands_exist(self):
        expected = {
            "GET_STATUS", "CHECK_DISTANCE", "REQUEST_EMERGENCY",
            "REQUEST_HELP", "REQUEST_APPROVAL", "SEND_UCD_PROPERTIES",
            "SEND_USD_PROPERTIES", "SEND_MUTATION_PROPERTIES",
            "INFORM_REFERENCE_NODE", "REQUEST_SNAPSHOT",
        }
        names = {cmd.name for cmd in NcpCommandId}
        self.assertEqual(names, expected)

    def test_get_status_value_zero(self):
        self.assertEqual(NcpCommandId.GET_STATUS.value, 0)

    def test_inform_reference_node_value_eight(self):
        self.assertEqual(NcpCommandId.INFORM_REFERENCE_NODE.value, 8)

    def test_round_trip_from_int(self):
        for i in range(9):
            cmd = NcpCommandId(i)
            self.assertEqual(cmd.value, i)


class TestNcpFrame(unittest.TestCase):

    def test_empty_payload_length(self):
        frame = NcpFrame(V1, NcpCommandId.GET_STATUS, b"")
        self.assertEqual(len(frame.to_bytes()), 9)

    def test_payload_appended(self):
        payload = b"hello world"
        frame = NcpFrame(V1, NcpCommandId.CHECK_DISTANCE, payload)
        raw = frame.to_bytes()
        self.assertEqual(len(raw), 9 + len(payload))

    def test_from_bytes_roundtrip(self):
        frame = NcpFrame(V1, NcpCommandId.REQUEST_APPROVAL, b"test payload")
        raw = frame.to_bytes()
        parsed = NcpFrame.from_bytes(raw)
        self.assertTrue(parsed.is_ok())
        f = parsed.unwrap()
        self.assertEqual(f.command_id, NcpCommandId.REQUEST_APPROVAL)
        self.assertEqual(f.payload, b"test payload")

    def test_from_bytes_version_preserved(self):
        ver = NcpVersion(2, 3, 4, 5)
        frame = NcpFrame(ver, NcpCommandId.GET_STATUS, b"")
        parsed = NcpFrame.from_bytes(frame.to_bytes()).unwrap()
        self.assertEqual(parsed.version.major, 2)
        self.assertEqual(parsed.version.minor, 3)

    def test_from_bytes_too_short_returns_err(self):
        result = NcpFrame.from_bytes(b"\x00\x01\x02")
        self.assertTrue(result.is_err())

    def test_from_bytes_unknown_command_returns_err(self):
        frame = NcpFrame(V1, NcpCommandId.GET_STATUS, b"")
        raw = bytearray(frame.to_bytes())
        raw[4] = 255  # invalid command byte
        result = NcpFrame.from_bytes(bytes(raw))
        self.assertTrue(result.is_err())

    def test_all_commands_roundtrip(self):
        for cmd in NcpCommandId:
            with self.subTest(cmd=cmd):
                frame = NcpFrame(V1, cmd, b"data")
                parsed = NcpFrame.from_bytes(frame.to_bytes())
                self.assertTrue(parsed.is_ok())
                self.assertEqual(parsed.unwrap().command_id, cmd)


class TestNcpVersion(unittest.TestCase):

    def test_to_bytes_length(self):
        ver = NcpVersion(1, 2, 3, 4)
        self.assertEqual(len(ver.to_bytes()), 4)

    def test_from_bytes_roundtrip(self):
        ver = NcpVersion(1, 2, 3, 4)
        raw = ver.to_bytes()
        parsed = NcpVersion.from_bytes(raw)
        self.assertTrue(parsed.is_ok())
        v = parsed.unwrap()
        self.assertEqual(v.major, 1)
        self.assertEqual(v.minor, 2)
        self.assertEqual(v.patch, 3)
        self.assertEqual(v.bugfix, 4)

    def test_is_compatible_same_major(self):
        v1 = NcpVersion(1, 0, 0, 0)
        v2 = NcpVersion(1, 5, 0, 0)
        self.assertTrue(v1.is_compatible_with(v2))

    def test_not_compatible_different_major(self):
        v1 = NcpVersion(1, 0, 0, 0)
        v2 = NcpVersion(2, 0, 0, 0)
        self.assertFalse(v1.is_compatible_with(v2))

    def test_current_returns_version(self):
        ver = NcpVersion.current()
        self.assertIsInstance(ver, NcpVersion)


if __name__ == "__main__":
    unittest.main()

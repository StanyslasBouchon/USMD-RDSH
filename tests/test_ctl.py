"""Tests for the CTL control socket (server + client + snapshot)."""

import asyncio
import json
import os
import sys
import tempfile
import time

import pytest

from usmd.ctl.server import CtlServer
from usmd.ctl.client import _format_uptime, _bar, print_status


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_snapshot() -> dict:
    """Return a minimal but complete status snapshot for testing."""
    return {
        "node": {
            "name": 1710000000,
            "address": "192.168.1.5",
            "state": "active",
            "role": "node_executor",
            "uptime_seconds": 3661.0,
        },
        "usd": {
            "name": "test-domain",
            "cluster_name": "eu",
            "edb_address": None,
            "config_version": 2,
            "node_count": 3,
        },
        "nit": [
            {
                "address": "192.168.1.6",
                "pub_key": "abc123def456789012…",
                "ttl_remaining": 85,
                "expired": False,
            }
        ],
        "nal": [
            {
                "pub_key": "abc123def456789012…",
                "roles": ["node_executor"],
                "permanent": True,
            }
        ],
        "nel": {
            "received": None,
            "issued": [
                {
                    "node_pub_key": "def456abc789012345…",
                    "node_name": 1710000001,
                    "roles": ["node_executor"],
                    "expiration": int(time.time()) + 86400,
                    "expired": False,
                }
            ],
        },
        "resources": {
            "cpu_percent": 0.12,
            "ram_percent": 0.45,
            "disk_percent": 0.20,
            "network_percent": 0.01,
            "reference_load": 0.195,
        },
    }


# ---------------------------------------------------------------------------
# CtlServer unit tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Unix domain sockets not available on Windows",
)
class TestCtlServer:

    @pytest.mark.asyncio
    async def test_start_creates_socket_file(self):
        """start() must create a socket file at the configured path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "usmd_test.sock")
            srv = CtlServer(socket_path=path, snapshot_fn=_make_snapshot)
            await srv.start()
            try:
                assert os.path.exists(path)
            finally:
                srv.close()

    @pytest.mark.asyncio
    async def test_close_removes_socket_file(self):
        """close() must remove the socket file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "usmd_test.sock")
            srv = CtlServer(socket_path=path, snapshot_fn=_make_snapshot)
            await srv.start()
            srv.close()
            assert not os.path.exists(path)

    @pytest.mark.asyncio
    async def test_status_command_returns_snapshot(self):
        """A 'status' request must return the snapshot dict."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "usmd_test.sock")
            srv = CtlServer(socket_path=path, snapshot_fn=_make_snapshot)
            await srv.start()

            try:
                reader, writer = await asyncio.open_unix_connection(path)
                writer.write(b'{"cmd": "status"}\n')
                await writer.drain()
                line = await asyncio.wait_for(reader.readline(), timeout=3.0)
                writer.close()
                data = json.loads(line.decode().strip())
            finally:
                srv.close()

            assert data["node"]["name"] == 1710000000
            assert data["usd"]["name"] == "test-domain"
            assert len(data["nit"]) == 1
            assert len(data["nal"]) == 1
            assert data["nel"]["received"] is None
            assert len(data["nel"]["issued"]) == 1

    @pytest.mark.asyncio
    async def test_unknown_command_returns_error(self):
        """An unknown command must return an error key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "usmd_test.sock")
            srv = CtlServer(socket_path=path, snapshot_fn=_make_snapshot)
            await srv.start()

            try:
                reader, writer = await asyncio.open_unix_connection(path)
                writer.write(b'{"cmd": "reboot"}\n')
                await writer.drain()
                line = await asyncio.wait_for(reader.readline(), timeout=3.0)
                writer.close()
                data = json.loads(line.decode().strip())
            finally:
                srv.close()

            assert "error" in data

    @pytest.mark.asyncio
    async def test_invalid_json_does_not_crash_server(self):
        """Garbage input must be tolerated without crashing the server."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "usmd_test.sock")
            srv = CtlServer(socket_path=path, snapshot_fn=_make_snapshot)
            await srv.start()

            try:
                reader, writer = await asyncio.open_unix_connection(path)
                writer.write(b"not valid json\n")
                await writer.drain()
                # Server should respond with an error (or close gracefully)
                line = await asyncio.wait_for(reader.readline(), timeout=3.0)
                writer.close()
                data = json.loads(line.decode().strip())
                assert "error" in data
            finally:
                srv.close()

    @pytest.mark.asyncio
    async def test_stale_socket_replaced_on_start(self):
        """If a socket file already exists, start() must replace it."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "usmd_test.sock")
            # Create a stale file at the path
            open(path, "w").close()  # noqa: WPS515
            srv = CtlServer(socket_path=path, snapshot_fn=_make_snapshot)
            await srv.start()
            try:
                assert os.path.exists(path)
            finally:
                srv.close()

    @pytest.mark.asyncio
    async def test_multiple_sequential_requests(self):
        """The server must correctly handle several sequential connections."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "usmd_test.sock")
            srv = CtlServer(socket_path=path, snapshot_fn=_make_snapshot)
            await srv.start()

            try:
                for _ in range(3):
                    reader, writer = await asyncio.open_unix_connection(path)
                    writer.write(b'{"cmd": "status"}\n')
                    await writer.drain()
                    line = await asyncio.wait_for(reader.readline(), timeout=3.0)
                    writer.close()
                    data = json.loads(line.decode().strip())
                    assert "node" in data
            finally:
                srv.close()


# ---------------------------------------------------------------------------
# build_status_snapshot integration-style tests
# ---------------------------------------------------------------------------


class TestNodeDaemonSnapshot:

    def _make_daemon(self):
        """Return a NodeDaemon instance without starting any network."""
        from usmd.config import NodeConfig  # noqa: PLC0415
        from usmd.node_daemon import NodeDaemon  # noqa: PLC0415

        cfg = NodeConfig(bootstrap=True, usd_name="snap-domain")
        return NodeDaemon(cfg)

    def test_snapshot_has_all_sections(self):
        daemon = self._make_daemon()
        snap = daemon.build_status_snapshot()
        assert "node" in snap
        assert "usd" in snap
        assert "nit" in snap
        assert "nal" in snap
        assert "nel" in snap
        assert "resources" in snap

    def test_snapshot_node_fields(self):
        daemon = self._make_daemon()
        snap = daemon.build_status_snapshot()
        node = snap["node"]
        assert isinstance(node["name"], int)
        assert isinstance(node["address"], str)
        assert isinstance(node["uptime_seconds"], float)
        assert isinstance(node["state"], str)
        assert isinstance(node["role"], str)

    def test_snapshot_usd_fields(self):
        daemon = self._make_daemon()
        snap = daemon.build_status_snapshot()
        usd = snap["usd"]
        assert usd["name"] == "snap-domain"
        assert isinstance(usd["node_count"], int)

    def test_snapshot_nit_contains_self(self):
        """The daemon registers itself in the NIT on init."""
        daemon = self._make_daemon()
        snap = daemon.build_status_snapshot()
        assert len(snap["nit"]) >= 1

    def test_snapshot_nal_contains_self(self):
        """The daemon grants its own key in the NAL on init."""
        daemon = self._make_daemon()
        snap = daemon.build_status_snapshot()
        assert len(snap["nal"]) >= 1
        assert snap["nal"][0]["permanent"] is True

    def test_snapshot_nel_bootstrap_node(self):
        """A bootstrap node has no received endorsement."""
        daemon = self._make_daemon()
        snap = daemon.build_status_snapshot()
        assert snap["nel"]["received"] is None

    def test_snapshot_resources_keys(self):
        daemon = self._make_daemon()
        snap = daemon.build_status_snapshot()
        res = snap["resources"]
        for key in (
            "cpu_percent",
            "ram_percent",
            "disk_percent",
            "network_percent",
            "reference_load",
        ):
            assert key in res
            assert isinstance(res[key], float)


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------


class TestFormatUptime:
    def test_seconds_only(self):
        assert _format_uptime(45) == "45s"

    def test_minutes_and_seconds(self):
        assert _format_uptime(125) == "2m 5s"

    def test_hours_minutes_seconds(self):
        assert _format_uptime(7384) == "2h 3m 4s"

    def test_zero(self):
        assert _format_uptime(0) == "0s"

    def test_exact_hour(self):
        assert _format_uptime(3600) == "1h 0m 0s"


class TestBar:
    def test_zero_is_empty(self):
        bar = _bar(0.0)
        assert "█" not in bar

    def test_full_is_filled(self):
        bar = _bar(1.0)
        assert "░" not in bar

    def test_half(self):
        bar = _bar(0.5, width=10)
        assert bar.count("█") == 5
        assert bar.count("░") == 5


class TestPrintStatus:
    def test_does_not_raise(self, capsys):
        """print_status must run without errors on a valid snapshot."""
        print_status(_make_snapshot())
        captured = capsys.readouterr()
        assert "USMD-RDSH" in captured.out
        assert "test-domain" in captured.out
        assert "192.168.1.5" in captured.out

    def test_shows_nit_entries(self, capsys):
        print_status(_make_snapshot())
        out = capsys.readouterr().out
        assert "192.168.1.6" in out

    def test_shows_nal_roles(self, capsys):
        print_status(_make_snapshot())
        out = capsys.readouterr().out
        assert "node_executor" in out

    def test_bootstrap_node_shows_no_received(self, capsys):
        snap = _make_snapshot()
        snap["nel"]["received"] = None
        print_status(snap)
        out = capsys.readouterr().out
        assert "bootstrap" in out.lower()


# ---------------------------------------------------------------------------
# CtlServer TCP tests (cross-platform — works on Linux and Windows)
# ---------------------------------------------------------------------------


class TestCtlServerTCP:

    @pytest.mark.asyncio
    async def test_tcp_status_command_returns_snapshot(self):
        """A 'status' request over TCP must return the snapshot dict."""
        srv = CtlServer(
            socket_path="unused.sock", snapshot_fn=_make_snapshot, ctl_port=0
        )
        # Force TCP path regardless of platform
        await srv._start_tcp()

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", srv.actual_port)
            writer.write(b'{"cmd": "status"}\n')
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=3.0)
            writer.close()
            data = json.loads(line.decode().strip())
        finally:
            srv.close()

        assert data["node"]["name"] == 1710000000
        assert data["usd"]["name"] == "test-domain"

    @pytest.mark.asyncio
    async def test_tcp_unknown_command_returns_error(self):
        """An unknown command over TCP must return an error key."""
        srv = CtlServer(
            socket_path="unused.sock", snapshot_fn=_make_snapshot, ctl_port=0
        )
        await srv._start_tcp()

        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", srv.actual_port)
            writer.write(b'{"cmd": "unknown"}\n')
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), timeout=3.0)
            writer.close()
            data = json.loads(line.decode().strip())
        finally:
            srv.close()

        assert "error" in data

    @pytest.mark.asyncio
    async def test_tcp_actual_port_nonzero_after_start(self):
        """actual_port must be updated to the OS-assigned port after start."""
        srv = CtlServer(
            socket_path="unused.sock", snapshot_fn=_make_snapshot, ctl_port=0
        )
        await srv._start_tcp()
        try:
            assert srv.actual_port > 0
        finally:
            srv.close()

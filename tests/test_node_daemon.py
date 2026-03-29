"""Tests for NodeDaemon (orchestrator)."""

import json
import os
import tempfile
import time
from unittest.mock import MagicMock, patch

import pytest

from usmd.config import NodeConfig
from usmd.node.state import NodeState
from usmd.node_daemon import NodeDaemon
from usmd._daemon_helpers import _get_resource_usage, _load_or_generate_keys
from usmd.security.crypto import Ed25519Pair, X25519Pair


# ---------------------------------------------------------------------------
# _load_or_generate_keys tests
# ---------------------------------------------------------------------------

class TestLoadOrGenerateKeys:
    def test_generates_new_keys_when_file_missing(self, tmp_path):
        path = str(tmp_path / "keys.json")
        ed_priv, ed_pub, x_priv, x_pub, node_name = _load_or_generate_keys(path)
        assert len(ed_priv) == 32
        assert len(ed_pub) == 32
        assert len(x_priv) == 32
        assert len(x_pub) == 32
        assert node_name > 0

    def test_saves_keys_to_file(self, tmp_path):
        path = str(tmp_path / "keys.json")
        _load_or_generate_keys(path)
        assert os.path.exists(path)
        with open(path) as fh:
            data = json.load(fh)
        assert "ed25519_priv" in data
        assert "ed25519_pub" in data
        assert "x25519_priv" in data
        assert "x25519_pub" in data
        assert "node_name" in data

    def test_loads_existing_keys(self, tmp_path):
        path = str(tmp_path / "keys.json")
        # First call generates
        ed_priv1, ed_pub1, x_priv1, x_pub1, name1 = _load_or_generate_keys(path)
        # Second call loads
        ed_priv2, ed_pub2, x_priv2, x_pub2, name2 = _load_or_generate_keys(path)
        assert ed_priv1 == ed_priv2
        assert ed_pub1 == ed_pub2
        assert x_priv1 == x_priv2
        assert x_pub1 == x_pub2
        assert name1 == name2

    def test_regenerates_on_invalid_file(self, tmp_path):
        path = str(tmp_path / "keys.json")
        with open(path, "w") as fh:
            fh.write("not json at all {{{")
        ed_priv, ed_pub, x_priv, x_pub, node_name = _load_or_generate_keys(path)
        assert len(ed_priv) == 32

    def test_regenerates_on_missing_fields(self, tmp_path):
        path = str(tmp_path / "keys.json")
        with open(path, "w") as fh:
            json.dump({"ed25519_priv": "deadbeef"}, fh)
        ed_priv, ed_pub, x_priv, x_pub, node_name = _load_or_generate_keys(path)
        assert len(ed_priv) == 32

    def test_keys_file_not_writable(self, tmp_path):
        path = str(tmp_path / "readonly_dir" / "keys.json")
        # Non-existent parent dir — should still return valid keys
        ed_priv, ed_pub, x_priv, x_pub, node_name = _load_or_generate_keys(path)
        assert len(ed_priv) == 32


# ---------------------------------------------------------------------------
# _get_resource_usage tests
# ---------------------------------------------------------------------------

class TestGetResourceUsage:
    def test_returns_resource_usage(self):
        usage = _get_resource_usage()
        assert 0.0 <= usage.ram_percent <= 1.0
        assert 0.0 <= usage.cpu_percent <= 1.0
        assert 0.0 <= usage.disk_percent <= 1.0
        assert 0.0 <= usage.network_percent <= 1.0

    def test_returns_zeros_without_psutil(self):
        import sys  # noqa: PLC0415
        with patch.dict(sys.modules, {"psutil": None}):
            usage = _get_resource_usage()
        # Should return dummy zeros when psutil unavailable
        assert usage.ram_percent == 0.0
        assert usage.cpu_percent == 0.0


# ---------------------------------------------------------------------------
# NodeDaemon init tests
# ---------------------------------------------------------------------------

class TestNodeDaemonInit:
    def test_creates_node(self, tmp_path):
        cfg = NodeConfig(
            bootstrap=True,
            keys_file=str(tmp_path / "keys.json"),
            usd_name="test-domain",
        )
        daemon = NodeDaemon(cfg)
        assert daemon.node is not None
        assert daemon.node.state == NodeState.PENDING_APPROVAL

    def test_creates_usd_with_correct_name(self, tmp_path):
        cfg = NodeConfig(
            bootstrap=True,
            keys_file=str(tmp_path / "keys.json"),
            usd_name="my-usd",
        )
        daemon = NodeDaemon(cfg)
        assert daemon.usd.config.name == "my-usd"

    def test_nit_has_self_entry(self, tmp_path):
        cfg = NodeConfig(
            bootstrap=True,
            keys_file=str(tmp_path / "keys.json"),
        )
        daemon = NodeDaemon(cfg)
        # Our own pub key should be in the NIT
        assert len(daemon.nit) >= 1

    def test_nal_has_self_role(self, tmp_path):
        cfg = NodeConfig(
            bootstrap=True,
            keys_file=str(tmp_path / "keys.json"),
            role="usd_operator",
        )
        daemon = NodeDaemon(cfg)
        assert daemon.nal.has_role(daemon._ed_pub, daemon.cfg.node_role)

    def test_from_config_factory(self, tmp_path):
        cfg = NodeConfig(
            bootstrap=True,
            keys_file=str(tmp_path / "keys.json"),
        )
        daemon = NodeDaemon.from_config(cfg)
        assert isinstance(daemon, NodeDaemon)

    def test_address_auto_detected(self, tmp_path):
        cfg = NodeConfig(
            bootstrap=True,
            keys_file=str(tmp_path / "keys.json"),
            address="auto",
        )
        daemon = NodeDaemon(cfg)
        assert daemon.node.address != "auto"
        assert len(daemon.node.address) > 0

    def test_address_explicit(self, tmp_path):
        cfg = NodeConfig(
            bootstrap=True,
            keys_file=str(tmp_path / "keys.json"),
            address="10.0.0.5",
        )
        daemon = NodeDaemon(cfg)
        assert daemon.node.address == "10.0.0.5"


# ---------------------------------------------------------------------------
# NodeDaemon bootstrap tests
# ---------------------------------------------------------------------------

class TestNodeDaemonBootstrap:
    @pytest.mark.asyncio
    async def test_bootstrap_sets_active(self, tmp_path):
        cfg = NodeConfig(
            bootstrap=True,
            keys_file=str(tmp_path / "keys.json"),
        )
        daemon = NodeDaemon(cfg)
        await daemon._bootstrap()
        assert daemon.node.state == NodeState.ACTIVE

    @pytest.mark.asyncio
    async def test_bootstrap_adds_self_to_usd(self, tmp_path):
        cfg = NodeConfig(
            bootstrap=True,
            keys_file=str(tmp_path / "keys.json"),
        )
        daemon = NodeDaemon(cfg)
        await daemon._bootstrap()
        assert daemon.usd.get_node(daemon.node.name) is not None

    @pytest.mark.asyncio
    async def test_bootstrap_sets_joined_event(self, tmp_path):
        cfg = NodeConfig(
            bootstrap=True,
            keys_file=str(tmp_path / "keys.json"),
        )
        daemon = NodeDaemon(cfg)
        assert not daemon._joined.is_set()
        await daemon._bootstrap()
        assert daemon._joined.is_set()


# ---------------------------------------------------------------------------
# NodeDaemon peer discovery tests
# ---------------------------------------------------------------------------

class TestNodeDaemonPeerDiscovery:
    def test_on_peer_discovered_registers_in_nit(self, tmp_path):
        from usmd.nndp.protocol.here_i_am import HiaData, HereIAmPacket  # noqa: PLC0415
        from usmd.security.crypto import Ed25519Pair  # noqa: PLC0415

        cfg = NodeConfig(
            bootstrap=False,
            keys_file=str(tmp_path / "keys.json"),
        )
        daemon = NodeDaemon(cfg)

        peer_priv, peer_pub = Ed25519Pair.generate()
        pkt = HereIAmPacket.build(
            sender_name=999,
            sender_pub_key=peer_pub,
            sender_priv_key=peer_priv,
            ttl=30,
            state=NodeState.ACTIVE,
        )

        nit_size_before = len(daemon.nit)
        daemon._on_peer_discovered(pkt, "192.168.1.10")
        assert len(daemon.nit) > nit_size_before

    def test_on_peer_discovered_queues_for_join(self, tmp_path):
        from usmd.nndp.protocol.here_i_am import HereIAmPacket  # noqa: PLC0415
        from usmd.security.crypto import Ed25519Pair  # noqa: PLC0415

        cfg = NodeConfig(
            bootstrap=False,
            keys_file=str(tmp_path / "keys.json"),
        )
        daemon = NodeDaemon(cfg)

        peer_priv, peer_pub = Ed25519Pair.generate()
        pkt = HereIAmPacket.build(
            sender_name=999,
            sender_pub_key=peer_pub,
            sender_priv_key=peer_priv,
            ttl=30,
            state=NodeState.ACTIVE,
        )

        daemon._on_peer_discovered(pkt, "192.168.1.10")
        assert len(daemon._pending_peers) == 1

    def test_on_peer_discovered_does_not_queue_after_joined(self, tmp_path):
        from usmd.nndp.protocol.here_i_am import HereIAmPacket  # noqa: PLC0415
        from usmd.security.crypto import Ed25519Pair  # noqa: PLC0415

        cfg = NodeConfig(
            bootstrap=False,
            keys_file=str(tmp_path / "keys.json"),
        )
        daemon = NodeDaemon(cfg)
        daemon._joined.set()  # Mark as already joined

        peer_priv, peer_pub = Ed25519Pair.generate()
        pkt = HereIAmPacket.build(
            sender_name=999,
            sender_pub_key=peer_pub,
            sender_priv_key=peer_priv,
            ttl=30,
            state=NodeState.ACTIVE,
        )

        daemon._on_peer_discovered(pkt, "192.168.1.10")
        assert len(daemon._pending_peers) == 0

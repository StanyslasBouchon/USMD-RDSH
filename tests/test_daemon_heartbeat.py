"""Tests for _daemon_heartbeat._heartbeat_loop."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest

from usmd._daemon_heartbeat import _heartbeat_loop
from usmd.node.node import Node
from usmd.node.nit import NodeIdentityTable
from usmd.node.nrt import NodeReferenceTable
from usmd.node.state import NodeState
from usmd.domain.usd import USDConfig, UnifiedSystemDomain
from usmd.security.crypto import Ed25519Pair


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_daemon(*, active_peer: bool = True, expired_peer: bool = False):
    """Build a minimal mock daemon for heartbeat tests."""
    ed_priv, ed_pub = Ed25519Pair.generate()
    local_node = Node(address="10.0.0.1", name=1, state=NodeState.ACTIVE)

    nit = NodeIdentityTable()
    nit.register("10.0.0.1", ed_pub, ttl=86400)

    nrt = NodeReferenceTable()

    cfg = USDConfig(name="test", cluster_name="", max_reference_nodes=5,
                    load_threshold=0.8, ping_tolerance_ms=200, load_check_interval=30)
    usd = UnifiedSystemDomain(config=cfg, private_key=ed_priv)
    usd.add_node(local_node)

    if active_peer or expired_peer:
        _, peer_pub = Ed25519Pair.generate()
        ttl = 1 if expired_peer else 86400
        nit.register("10.0.0.2", peer_pub, ttl=ttl)
        peer_node = Node(address="10.0.0.2", name=2,
                         state=NodeState.ACTIVE if active_peer else NodeState.INACTIVE_TIMEOUT)
        usd.add_node(peer_node)
        if expired_peer:
            nrt.update("10.0.0.2", 0.5, 10.0)

    daemon = MagicMock()
    daemon.node = local_node
    daemon.nit = nit
    daemon.nrt = nrt
    daemon.usd = usd
    return daemon


# ---------------------------------------------------------------------------
# _heartbeat_loop tests
# ---------------------------------------------------------------------------

class TestHeartbeatLoop:
    @pytest.mark.asyncio
    async def test_updates_reference_load(self):
        """Heartbeat should set reference_load on the local node."""
        daemon = _make_daemon()
        daemon.node.reference_load = 0.0

        async def _run():
            task = asyncio.create_task(_heartbeat_loop(daemon))
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        with patch("usmd._daemon_heartbeat._HEARTBEAT_INTERVAL", 0.01):
            with patch("usmd._daemon_heartbeat._get_resource_usage") as mock_usage:
                mock_ru = MagicMock()
                mock_ru.reference_load.return_value = 0.42
                mock_usage.return_value = mock_ru
                await _run()

        assert daemon.node.reference_load == pytest.approx(0.42)

    @pytest.mark.asyncio
    async def test_marks_expired_peer_inactive(self):
        """An active peer whose NIT entry is expired should become INACTIVE_NNDP_NO_HIA."""
        import time
        daemon = _make_daemon(active_peer=False)  # no peer yet

        _, peer_pub = Ed25519Pair.generate()
        daemon.nit.register("10.0.0.2", peer_pub, ttl=86400)
        peer_node = Node(address="10.0.0.2", name=2, state=NodeState.ACTIVE)
        daemon.usd.add_node(peer_node)

        # Expire the entry we just added (keyed by public_key bytes)
        # TTL=86400, so set registered_at far enough back to be expired
        daemon.nit._entries[peer_pub].registered_at = time.time() - 86401

        async def _run():
            task = asyncio.create_task(_heartbeat_loop(daemon))
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        with patch("usmd._daemon_heartbeat._HEARTBEAT_INTERVAL", 0.01):
            with patch("usmd._daemon_heartbeat._get_resource_usage") as mock_usage:
                mock_ru = MagicMock()
                mock_ru.reference_load.return_value = 0.1
                mock_usage.return_value = mock_ru
                await _run()

        assert peer_node.state == NodeState.INACTIVE_NNDP_NO_HIA

    @pytest.mark.asyncio
    async def test_does_not_mark_self_inactive(self):
        """The local node should never be marked inactive by the heartbeat."""
        import time
        daemon = _make_daemon(active_peer=False)

        # Expire the local node's NIT entry
        local_pub = daemon.node.state  # not the pub key — find it properly
        for entry in daemon.nit._entries.values():
            if entry.address == "10.0.0.1":
                entry.registered_at = time.time() - 86401
                break

        async def _run():
            task = asyncio.create_task(_heartbeat_loop(daemon))
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        with patch("usmd._daemon_heartbeat._HEARTBEAT_INTERVAL", 0.01):
            with patch("usmd._daemon_heartbeat._get_resource_usage") as mock_usage:
                mock_ru = MagicMock()
                mock_ru.reference_load.return_value = 0.1
                mock_usage.return_value = mock_ru
                await _run()

        # local node must remain ACTIVE
        assert daemon.node.state == NodeState.ACTIVE

    @pytest.mark.asyncio
    async def test_purges_expired_nit_entries(self):
        """Expired NIT entries should be purged after marking nodes inactive."""
        import time
        daemon = _make_daemon(active_peer=False)

        _, peer_pub = Ed25519Pair.generate()
        daemon.nit.register("10.0.0.2", peer_pub, ttl=86400)
        peer_node = Node(address="10.0.0.2", name=2, state=NodeState.ACTIVE)
        daemon.usd.add_node(peer_node)

        # Expire the specific entry keyed by public_key
        daemon.nit._entries[peer_pub].registered_at = time.time() - 86401

        async def _run():
            task = asyncio.create_task(_heartbeat_loop(daemon))
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        with patch("usmd._daemon_heartbeat._HEARTBEAT_INTERVAL", 0.01):
            with patch("usmd._daemon_heartbeat._get_resource_usage") as mock_usage:
                mock_ru = MagicMock()
                mock_ru.reference_load.return_value = 0.1
                mock_usage.return_value = mock_ru
                await _run()

        # After purge, only local node's entry should remain
        remaining = list(daemon.nit.iter_all_entries())
        addresses = {e.address for e in remaining}
        assert "10.0.0.2" not in addresses

    @pytest.mark.asyncio
    async def test_handles_exception_gracefully(self):
        """Heartbeat loop should swallow errors and keep running."""
        daemon = _make_daemon()

        call_count = 0

        async def _run():
            nonlocal call_count
            task = asyncio.create_task(_heartbeat_loop(daemon))
            await asyncio.sleep(0.08)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        with patch("usmd._daemon_heartbeat._HEARTBEAT_INTERVAL", 0.01):
            with patch("usmd._daemon_heartbeat._get_resource_usage") as mock_usage:
                def side_effect():
                    nonlocal call_count
                    call_count += 1
                    if call_count == 1:
                        raise RuntimeError("simulated error")
                    ru = MagicMock()
                    ru.reference_load.return_value = 0.0
                    return ru

                mock_usage.side_effect = side_effect
                await _run()

        # Loop survived the first error and continued
        assert call_count >= 2

    @pytest.mark.asyncio
    async def test_nrt_entry_removed_on_expiry(self):
        """NRT entry for the expired peer should be removed."""
        import time
        daemon = _make_daemon(active_peer=False)

        _, peer_pub = Ed25519Pair.generate()
        daemon.nit.register("10.0.0.2", peer_pub, ttl=86400)
        peer_node = Node(address="10.0.0.2", name=2, state=NodeState.ACTIVE)
        daemon.usd.add_node(peer_node)
        daemon.nrt.update("10.0.0.2", 0.5, 10.0)

        # Expire the specific entry keyed by public_key
        daemon.nit._entries[peer_pub].registered_at = time.time() - 86401

        async def _run():
            task = asyncio.create_task(_heartbeat_loop(daemon))
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        with patch("usmd._daemon_heartbeat._HEARTBEAT_INTERVAL", 0.01):
            with patch("usmd._daemon_heartbeat._get_resource_usage") as mock_usage:
                mock_ru = MagicMock()
                mock_ru.reference_load.return_value = 0.0
                mock_usage.return_value = mock_ru
                await _run()

        # The NRT entry should have been removed
        nrt_addresses = {e["address"] for e in daemon.nrt.get_all()}
        assert "10.0.0.2" not in nrt_addresses

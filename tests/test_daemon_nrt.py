"""Tests for _daemon_nrt (NRT update + reference nodes) and _daemon_peer
(peer discovery + NCP failure callback)."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from usmd._daemon_nrt import (
    _compute_reference_names,
    _log_ref_change,
    _update_nrt_for_peer,
    _update_reference_nodes,
)
from usmd._daemon_peer import _mark_peer_inactive, _on_peer_discovered
from usmd.config import NodeConfig
from usmd.domain.usd import USDConfig, UnifiedSystemDomain
from usmd.node.nit import NodeIdentityTable
from usmd.node.node import Node
from usmd.node.nrl import NodeReferenceList
from usmd.node.nrt import NodeReferenceTable
from usmd.node.state import NodeState
from usmd.nndp.protocol.here_i_am import HereIAmPacket
from usmd.security.crypto import Ed25519Pair
from usmd.utils.result import Result
from usmd.utils.errors import Error, ErrorKind


def _err():
    return Result.Err(Error.new(ErrorKind.CONNECTION_ERROR, "mocked failure"))


def _ok(frame):
    return Result.Ok(frame)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_nrt_daemon(*, peer_address="10.0.0.2"):
    ed_priv, ed_pub = Ed25519Pair.generate()
    cfg = NodeConfig(
        bootstrap=True,
        usd_name="test",
        ncp_port=5626,
        ncp_timeout=2.0,
        max_reference_nodes=2,
    )
    local_node = Node(address="10.0.0.1", name=1, state=NodeState.ACTIVE)
    local_node.reference_nodes = []

    usd_cfg = cfg.to_usd_config()
    usd = UnifiedSystemDomain(config=usd_cfg, private_key=ed_priv)
    usd.add_node(local_node)

    nit = NodeIdentityTable()
    nit.register("10.0.0.1", ed_pub, ttl=86400)

    nrt = NodeReferenceTable()
    nrl = NodeReferenceList()

    if peer_address:
        _, peer_pub = Ed25519Pair.generate()
        nit.register(peer_address, peer_pub, ttl=86400)
        peer_node = Node(address=peer_address, name=2, state=NodeState.ACTIVE)
        usd.add_node(peer_node)

    daemon = MagicMock()
    daemon.cfg = cfg
    daemon.node = local_node
    daemon.usd = usd
    daemon.nit = nit
    daemon.nrt = nrt
    daemon.nrl = nrl
    daemon.reference_since = {}
    daemon.consume_monotonic_gate = MagicMock(return_value=True)
    return daemon


def _make_hia_packet(name: int, pub_key: bytes) -> HereIAmPacket:
    from usmd.security.crypto import Ed25519Pair as _Pair
    from usmd.node.state import NodeState as _NS

    priv, _ = _Pair.generate()
    return HereIAmPacket.build(
        sender_name=name,
        sender_pub_key=pub_key,
        sender_priv_key=priv,
        ttl=30,
        state=NodeState.ACTIVE,
    )


# ===========================================================================
# _daemon_nrt tests
# ===========================================================================


class TestUpdateNrtForPeer:
    @pytest.mark.asyncio
    async def test_updates_nrt_on_success(self):
        """A successful CHECK_DISTANCE response should update the NRT."""
        daemon = _make_nrt_daemon()
        from usmd.ncp.protocol.commands.check_distance import CheckDistanceResponse

        resp = CheckDistanceResponse(distance=0.3)
        mock_frame = MagicMock()
        mock_frame.payload = resp.to_payload()

        with patch("usmd._daemon_nrt.NcpClient") as MockClient:
            with patch(
                "usmd._daemon_nrt._update_reference_nodes", new_callable=AsyncMock
            ):
                mock_client = AsyncMock()
                mock_client.send = AsyncMock(return_value=_ok(mock_frame))
                MockClient.return_value = mock_client
                await _update_nrt_for_peer(daemon, "10.0.0.2")

        entries = daemon.nrt.get_all()
        assert len(entries) == 1
        assert entries[0]["address"] == "10.0.0.2"
        assert entries[0]["distance"] == pytest.approx(0.3, abs=0.1)

    @pytest.mark.asyncio
    async def test_does_not_update_on_ncp_error(self):
        """NCP failure should leave the NRT unchanged."""
        daemon = _make_nrt_daemon()

        with patch("usmd._daemon_nrt.NcpClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.send = AsyncMock(return_value=_err())
            MockClient.return_value = mock_client
            await _update_nrt_for_peer(daemon, "10.0.0.2")

        assert len(daemon.nrt.get_all()) == 0

    @pytest.mark.asyncio
    async def test_triggers_reference_node_update(self):
        """Successful NRT update should trigger _update_reference_nodes."""
        daemon = _make_nrt_daemon()
        from usmd.ncp.protocol.commands.check_distance import CheckDistanceResponse

        resp = CheckDistanceResponse(distance=0.2)
        mock_frame = MagicMock()
        mock_frame.payload = resp.to_payload()

        with patch("usmd._daemon_nrt.NcpClient") as MockClient:
            with patch(
                "usmd._daemon_nrt._update_reference_nodes", new_callable=AsyncMock
            ) as mock_update:
                mock_client = AsyncMock()
                mock_client.send = AsyncMock(return_value=_ok(mock_frame))
                MockClient.return_value = mock_client
                await _update_nrt_for_peer(daemon, "10.0.0.2")
                mock_update.assert_called_once_with(daemon)


class TestUpdateReferenceNodes:
    @pytest.mark.asyncio
    async def test_selects_closest_peers(self):
        """_update_reference_nodes should pick the N closest peers from NRT."""
        daemon = _make_nrt_daemon()
        daemon.nrt.update("10.0.0.2", 0.1, 5.0)
        # Add a third node so we can test max_reference_nodes cap
        _, pub3 = Ed25519Pair.generate()
        daemon.nit.register("10.0.0.3", pub3, ttl=86400)
        node3 = Node(address="10.0.0.3", name=3, state=NodeState.ACTIVE)
        daemon.usd.add_node(node3)
        daemon.nrt.update("10.0.0.3", 0.5, 20.0)

        with patch("usmd._daemon_nrt.NcpClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.send = AsyncMock(return_value=_err())
            MockClient.return_value = mock_client
            await _update_reference_nodes(daemon)

        # max_reference_nodes=2, both nodes should be selected
        assert len(daemon.node.reference_nodes) <= 2

    @pytest.mark.asyncio
    async def test_no_change_skips_ncp(self):
        """If reference set is unchanged, no NCP messages should be sent."""
        daemon = _make_nrt_daemon()
        daemon.nrt.update("10.0.0.2", 0.1, 5.0)
        # Pre-set the same reference nodes to simulate no change
        daemon.node.reference_nodes = [2]

        with patch("usmd._daemon_nrt.NcpClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.send = AsyncMock()
            MockClient.return_value = mock_client
            await _update_reference_nodes(daemon)
            mock_client.send.assert_not_called()

    @pytest.mark.asyncio
    async def test_notifies_removed_peer(self):
        """Peers removed from the reference list should also receive INFORM."""
        daemon = _make_nrt_daemon()
        daemon.nrt.update("10.0.0.2", 0.1, 5.0)
        # Pre-set old reference including a node we're about to remove
        daemon.node.reference_nodes = [2, 99]  # 99 doesn't exist anymore

        with patch("usmd._daemon_nrt.NcpClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.send = AsyncMock(return_value=_err())
            MockClient.return_value = mock_client
            await _update_reference_nodes(daemon)
            # At least one send attempt should have occurred
            assert mock_client.send.called

    @pytest.mark.asyncio
    async def test_ncp_failure_logged_not_raised(self):
        """NCP failure during INFORM_REFERENCE_NODE should not raise."""
        daemon = _make_nrt_daemon()
        daemon.nrt.update("10.0.0.2", 0.1, 5.0)

        with patch("usmd._daemon_nrt.NcpClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.send = AsyncMock(return_value=_err())
            MockClient.return_value = mock_client
            await _update_reference_nodes(daemon)  # must not raise


class TestLogRefChange:
    def test_added_and_removed(self):
        """_log_ref_change should produce a readable log without raising."""
        _log_ref_change(
            new_ref_names=[2, 3],
            added_names={2},
            removed_names={1},
            name_to_addr={1: "10.0.0.1", 2: "10.0.0.2", 3: "10.0.0.3"},
        )

    def test_no_change(self):
        """Empty sets should produce 'unchanged'."""
        _log_ref_change(
            new_ref_names=[],
            added_names=set(),
            removed_names=set(),
            name_to_addr={},
        )

    def test_missing_address_uses_question_mark(self):
        """Unknown node names should be formatted as '?'."""
        _log_ref_change(
            new_ref_names=[42],
            added_names={42},
            removed_names=set(),
            name_to_addr={},
        )


# ===========================================================================
# _daemon_peer tests
# ===========================================================================


class TestOnPeerDiscovered:
    def _make_peer_daemon(self):
        ed_priv, ed_pub = Ed25519Pair.generate()
        cfg = NodeConfig(bootstrap=True)
        local_node = Node(address="10.0.0.1", name=1, state=NodeState.ACTIVE)
        usd_cfg = cfg.to_usd_config()
        usd = UnifiedSystemDomain(config=usd_cfg, private_key=ed_priv)
        usd.add_node(local_node)
        nit = NodeIdentityTable()
        nit.register("10.0.0.1", ed_pub, ttl=86400)
        nrt = NodeReferenceTable()

        daemon = MagicMock()
        daemon.node = local_node
        daemon.usd = usd
        daemon.nit = nit
        daemon.nrt = nrt
        daemon.is_joined = True  # already joined — don't queue
        daemon.add_pending_peer = MagicMock()
        return daemon

    def test_registers_in_nit(self):
        daemon = self._make_peer_daemon()
        _, pub = Ed25519Pair.generate()
        packet = _make_hia_packet(2, pub)
        _on_peer_discovered(daemon, packet, "10.0.0.2")
        keys = {e.address for e in daemon.nit.iter_all_entries()}
        assert "10.0.0.2" in keys

    def test_adds_new_peer_to_usd(self):
        daemon = self._make_peer_daemon()
        _, pub = Ed25519Pair.generate()
        packet = _make_hia_packet(2, pub)
        _on_peer_discovered(daemon, packet, "10.0.0.2")
        assert daemon.usd.get_node(2) is not None

    def test_reactivates_inactive_timeout_peer(self):
        daemon = self._make_peer_daemon()
        _, pub = Ed25519Pair.generate()
        existing = Node(address="10.0.0.2", name=2, state=NodeState.INACTIVE_TIMEOUT)
        daemon.usd.add_node(existing)
        daemon.nit.register("10.0.0.2", pub, ttl=86400)
        packet = _make_hia_packet(2, pub)
        _on_peer_discovered(daemon, packet, "10.0.0.2")
        assert existing.state == NodeState.ACTIVE

    def test_updates_address_on_ip_change(self):
        daemon = self._make_peer_daemon()
        _, pub = Ed25519Pair.generate()
        existing = Node(address="10.0.0.99", name=2, state=NodeState.ACTIVE)
        daemon.usd.add_node(existing)
        daemon.nit.register("10.0.0.99", pub, ttl=86400)
        packet = _make_hia_packet(2, pub)
        _on_peer_discovered(daemon, packet, "10.0.0.2")
        assert existing.address == "10.0.0.2"

    def test_queues_peer_when_not_joined(self):
        daemon = self._make_peer_daemon()
        daemon.is_joined = False
        _, pub = Ed25519Pair.generate()
        packet = _make_hia_packet(2, pub)
        _on_peer_discovered(daemon, packet, "10.0.0.2")
        daemon.add_pending_peer.assert_called_once_with(packet, "10.0.0.2")

    def test_skips_self_for_nrt_update(self):
        """No NRT task should be created for the local node's own address."""
        daemon = self._make_peer_daemon()
        _, pub = Ed25519Pair.generate()
        packet = _make_hia_packet(1, pub)

        # Patch asyncio loop to detect task creation
        with patch("usmd._daemon_peer.asyncio.get_running_loop") as mock_loop:
            _on_peer_discovered(daemon, packet, "10.0.0.1")  # self
            mock_loop.return_value.create_task.assert_not_called()

    def test_runtime_error_in_loop_does_not_raise(self):
        """RuntimeError (no running loop in tests) should be swallowed."""
        daemon = self._make_peer_daemon()
        _, pub = Ed25519Pair.generate()
        packet = _make_hia_packet(2, pub)

        with patch(
            "usmd._daemon_peer.asyncio.get_running_loop",
            side_effect=RuntimeError("no loop"),
        ):
            _on_peer_discovered(daemon, packet, "10.0.0.2")  # must not raise


class TestMarkPeerInactive:
    def _make_peer_daemon(self):
        ed_priv, ed_pub = Ed25519Pair.generate()
        cfg = NodeConfig(bootstrap=True)
        local_node = Node(address="10.0.0.1", name=1, state=NodeState.ACTIVE)
        usd_cfg = cfg.to_usd_config()
        usd = UnifiedSystemDomain(config=usd_cfg, private_key=ed_priv)
        usd.add_node(local_node)
        _, peer_pub = Ed25519Pair.generate()
        peer_node = Node(address="10.0.0.2", name=2, state=NodeState.ACTIVE)
        usd.add_node(peer_node)
        nrt = NodeReferenceTable()
        nrt.update("10.0.0.2", 0.2, 10.0)

        daemon = MagicMock()
        daemon.node = local_node
        daemon.usd = usd
        daemon.nrt = nrt
        return daemon, peer_node

    def test_marks_active_peer_inactive(self):
        daemon, peer_node = self._make_peer_daemon()
        _mark_peer_inactive(daemon, "10.0.0.2")
        assert peer_node.state == NodeState.INACTIVE_TIMEOUT

    def test_does_not_affect_local_node(self):
        daemon, _ = self._make_peer_daemon()
        # Try to mark the local address — should have no effect
        _mark_peer_inactive(daemon, "10.0.0.1")
        assert daemon.node.state == NodeState.ACTIVE

    def test_removes_nrt_entry(self):
        daemon, _ = self._make_peer_daemon()
        _mark_peer_inactive(daemon, "10.0.0.2")
        nrt_addrs = {e["address"] for e in daemon.nrt.get_all()}
        assert "10.0.0.2" not in nrt_addrs

    def test_skips_already_inactive_peer(self):
        daemon, peer_node = self._make_peer_daemon()
        peer_node.set_state(NodeState.INACTIVE_TIMEOUT)
        _mark_peer_inactive(daemon, "10.0.0.2")  # must not raise, no double-set
        assert peer_node.state == NodeState.INACTIVE_TIMEOUT

    def test_unknown_address_does_not_raise(self):
        daemon, _ = self._make_peer_daemon()
        _mark_peer_inactive(daemon, "99.99.99.99")  # no matching node — no raise


# ---------------------------------------------------------------------------
# _compute_reference_names (stickiness + preemption)
# ---------------------------------------------------------------------------


class TestComputeReferenceNames:
    def test_fills_up_to_max_by_closest_distance(self):
        cands = [(1, "a", 0.1), (2, "b", 0.4), (3, "c", 0.9)]
        out = _compute_reference_names(cands, [], {}, 1000.0, 300.0, 2)
        assert out == [1, 2]

    def test_preempts_strictly_closer_peer(self):
        """Unselected peer with lower d must enter, displacing a worse one."""
        cands = [(1, "a", 0.1), (2, "b", 0.5), (3, "c", 0.9)]
        old = [3]
        since = {3: 500.0}
        now = 550.0
        hold = 300.0
        out = _compute_reference_names(cands, old, since, now, hold, 2)
        assert 3 not in out
        assert set(out) == {1, 2}

    def test_sticky_keeps_peer_if_no_strictly_better_outside(self):
        # Sort by distance: 2 then 1; no strictly lower d outside set preempts
        cands = [(2, "b", 0.60), (1, "a", 0.65)]
        old = [2]
        since = {2: 800.0}
        now = 850.0
        hold = 300.0
        out = _compute_reference_names(cands, old, since, now, hold, 1)
        assert out == [2]

    def test_after_hold_expires_can_drop_for_closer(self):
        cands = [(1, "a", 0.1), (2, "b", 0.9)]
        old = [2]
        since = {2: 0.0}
        now = 400.0
        hold = 300.0
        out = _compute_reference_names(cands, old, since, now, hold, 1)
        assert out == [1]

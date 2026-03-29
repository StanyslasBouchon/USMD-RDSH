"""Tests for _daemon_join: _bootstrap, _join, _try_join_via, _sync_nqt_from,
_store_endorsement."""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from usmd._daemon_join import (
    _bootstrap,
    _join,
    _store_endorsement,
    _sync_nqt_from,
    _try_join_via,
)
from usmd.config import NodeConfig
from usmd.domain.usd import USDConfig, UnifiedSystemDomain
from usmd.node.nal import NodeAccessList
from usmd.node.nel import NodeEndorsementList
from usmd.node.nit import NodeIdentityTable
from usmd.node.node import Node
from usmd.node.nqt import NodeQuorumTable
from usmd.node.role import NodeRole
from usmd.node.state import NodeState
from usmd.security.crypto import Ed25519Pair
from usmd.security.endorsement import EndorsementFactory
from usmd.utils.result import Ok, Err


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_daemon():
    """Return a minimal mock daemon for join-logic tests."""
    ed_priv, ed_pub = Ed25519Pair.generate()
    cfg = NodeConfig(bootstrap=False, usd_name="test-domain")
    local_node = Node(address="10.0.0.1", name=1, state=NodeState.PENDING_APPROVAL)

    usd_cfg = cfg.to_usd_config()
    usd = UnifiedSystemDomain(config=usd_cfg, private_key=ed_priv)

    nit = NodeIdentityTable()
    nal = NodeAccessList()
    nel = NodeEndorsementList()
    nqt = NodeQuorumTable()

    endorsement_factory = EndorsementFactory(
        endorser_private_key=ed_priv,
        endorser_public_key=ed_pub,
    )

    daemon = MagicMock()
    daemon.cfg = cfg
    daemon.node = local_node
    daemon.usd = usd
    daemon.nit = nit
    daemon.nal = nal
    daemon.nel = nel
    daemon.nqt = nqt
    daemon.ed_pub = ed_pub
    daemon.x_pub = b"\x00" * 32
    daemon.sign_ed25519 = lambda data: Ed25519Pair.sign(ed_priv, data)
    daemon.mark_joined = MagicMock()
    daemon.has_pending_peers = False
    daemon.pop_pending_peer = MagicMock(return_value=None)
    daemon.is_joined = False
    return daemon, ed_priv, ed_pub


def _make_endorsement_payload(ed_priv, ed_pub):
    """Build a minimal endorsement JSON payload."""
    import time as _time
    ef = EndorsementFactory(endorser_private_key=ed_priv, endorser_public_key=ed_pub)
    from usmd.node.role import NodeRole
    packet = ef.issue(
        node_name=1,
        node_pub_key=ed_pub,
        node_session_key=b"\xbb" * 32,
        roles=[NodeRole.EXECUTOR],
        ttl_seconds=3600,
    )
    return json.dumps({
        "endorser_key": ed_pub.hex(),
        "node_name": packet.node_name,
        "node_pub_key": packet.node_pub_key.hex(),
        "node_session_key": packet.node_session_key.hex(),
        "roles": [r.value for r in packet.roles],
        "serial": packet.serial.hex(),
        "expiration": packet.expiration,
        "signature": packet.signature.hex(),
    }).encode()


# ---------------------------------------------------------------------------
# _bootstrap
# ---------------------------------------------------------------------------

class TestBootstrap:
    @pytest.mark.asyncio
    async def test_sets_node_active(self):
        daemon, _, _ = _make_daemon()
        await _bootstrap(daemon)
        assert daemon.node.state == NodeState.ACTIVE

    @pytest.mark.asyncio
    async def test_calls_mark_joined(self):
        daemon, _, _ = _make_daemon()
        await _bootstrap(daemon)
        daemon.mark_joined.assert_called_once()

    @pytest.mark.asyncio
    async def test_adds_self_to_usd(self):
        daemon, _, _ = _make_daemon()
        await _bootstrap(daemon)
        assert daemon.usd.get_node(daemon.node.name) is not None

    @pytest.mark.asyncio
    async def test_bootstrap_already_in_usd_logs_warning(self):
        """Calling _bootstrap when node is already in USD should log, not raise."""
        daemon, _, _ = _make_daemon()
        daemon.usd.add_node(daemon.node)  # pre-register
        await _bootstrap(daemon)  # must not raise
        assert daemon.node.state == NodeState.ACTIVE


# ---------------------------------------------------------------------------
# _join
# ---------------------------------------------------------------------------

class TestJoin:
    @pytest.mark.asyncio
    async def test_join_succeeds_via_pending_peer(self):
        daemon, _, _ = _make_daemon()
        daemon.cfg.join_timeout = 5.0

        # Simulate one pending peer that will approve
        call_count = 0
        def _has_pending():
            nonlocal call_count
            call_count += 1
            return call_count == 1  # True only on first check

        daemon.has_pending_peers = property(lambda s: _has_pending())

        _, ip = (MagicMock(), "10.0.0.2")
        daemon.pop_pending_peer.return_value = (MagicMock(), "10.0.0.2")

        with patch("usmd._daemon_join._try_join_via", new_callable=AsyncMock,
                   return_value=True) as mock_try:
            # patch has_pending_peers as a side-effecting attribute
            type(daemon).has_pending_peers = property(
                lambda s, c=iter([True, False, False]): next(c, False))
            await _join(daemon)
            mock_try.assert_called_once_with(daemon, "10.0.0.2")

    @pytest.mark.asyncio
    async def test_join_timeout_marks_inactive(self):
        daemon, _, _ = _make_daemon()
        daemon.cfg.join_timeout = 0.05  # very short

        # No pending peers ever
        type(daemon).has_pending_peers = property(lambda s: False)

        await _join(daemon)
        assert daemon.node.state == NodeState.INACTIVE_TIMEOUT
        daemon.mark_joined.assert_called_once()


# ---------------------------------------------------------------------------
# _try_join_via
# ---------------------------------------------------------------------------

class TestTryJoinVia:
    @pytest.mark.asyncio
    async def test_returns_false_on_ncp_error(self):
        daemon, _, _ = _make_daemon()
        with patch("usmd._daemon_join.NcpClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.send = AsyncMock(return_value=Err(Exception("conn refused")))
            MockClient.return_value = mock_client
            result = await _try_join_via(daemon, "10.0.0.2")
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_on_empty_payload(self):
        daemon, _, _ = _make_daemon()
        with patch("usmd._daemon_join.NcpClient") as MockClient:
            mock_frame = MagicMock()
            mock_frame.payload = b""
            mock_client = AsyncMock()
            mock_client.send = AsyncMock(return_value=Ok(mock_frame))
            MockClient.return_value = mock_client
            result = await _try_join_via(daemon, "10.0.0.2")
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_when_rejected(self):
        daemon, _, _ = _make_daemon()
        with patch("usmd._daemon_join.NcpClient") as MockClient:
            mock_frame = MagicMock()
            mock_frame.payload = bytes([0x00])  # 0x00 = rejected
            mock_client = AsyncMock()
            mock_client.send = AsyncMock(return_value=Ok(mock_frame))
            MockClient.return_value = mock_client
            result = await _try_join_via(daemon, "10.0.0.2")
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_true_when_approved_no_endorsement(self):
        daemon, _, _ = _make_daemon()
        with patch("usmd._daemon_join.NcpClient") as MockClient:
            with patch("usmd._daemon_join._sync_nqt_from", new_callable=AsyncMock):
                mock_frame = MagicMock()
                mock_frame.payload = bytes([0x01])  # approved, no endorsement
                mock_client = AsyncMock()
                mock_client.send = AsyncMock(return_value=Ok(mock_frame))
                MockClient.return_value = mock_client
                result = await _try_join_via(daemon, "10.0.0.2")
        assert result is True
        assert daemon.node.state == NodeState.ACTIVE

    @pytest.mark.asyncio
    async def test_returns_true_when_approved_with_endorsement(self):
        daemon, ed_priv, ed_pub = _make_daemon()
        endorsement_bytes = _make_endorsement_payload(ed_priv, ed_pub)
        payload = bytes([0x01]) + endorsement_bytes

        with patch("usmd._daemon_join.NcpClient") as MockClient:
            with patch("usmd._daemon_join._sync_nqt_from", new_callable=AsyncMock):
                mock_frame = MagicMock()
                mock_frame.payload = payload
                mock_client = AsyncMock()
                mock_client.send = AsyncMock(return_value=Ok(mock_frame))
                MockClient.return_value = mock_client
                result = await _try_join_via(daemon, "10.0.0.2")
        assert result is True


# ---------------------------------------------------------------------------
# _sync_nqt_from
# ---------------------------------------------------------------------------

class TestSyncNqtFrom:
    @pytest.mark.asyncio
    async def test_ncp_failure_does_not_raise(self):
        daemon, _, _ = _make_daemon()
        with patch("usmd._daemon_join.NcpClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.send = AsyncMock(return_value=Err(Exception("timeout")))
            MockClient.return_value = mock_client
            await _sync_nqt_from(daemon, "10.0.0.2")

    @pytest.mark.asyncio
    async def test_merges_nqt_entries(self):
        from usmd.ncp.protocol.commands.get_nqt import GetNqtResponse
        from usmd.node.nqt import NodeQuorumTable
        daemon, _, ed_pub = _make_daemon()

        nqt_entry = {
            "epoch": 1,
            "address": "10.0.0.2",
            "pub_key_hex": ed_pub.hex(),
            "pub_key": "…",
            "promoted_at": time.time(),
            "promoted_at_str": "",
            "reason": "test",
            "role_name": "node_operator",
        }
        resp = GetNqtResponse(entries=[nqt_entry])

        with patch("usmd._daemon_join.NcpClient") as MockClient:
            mock_frame = MagicMock()
            mock_frame.payload = resp.to_payload()
            mock_client = AsyncMock()
            mock_client.send = AsyncMock(return_value=Ok(mock_frame))
            MockClient.return_value = mock_client
            await _sync_nqt_from(daemon, "10.0.0.2")

        assert len(daemon.nqt) == 1


# ---------------------------------------------------------------------------
# _store_endorsement
# ---------------------------------------------------------------------------

class TestStoreEndorsement:
    def test_valid_endorsement_stored(self):
        daemon, ed_priv, ed_pub = _make_daemon()
        payload = _make_endorsement_payload(ed_priv, ed_pub)
        _store_endorsement(daemon, payload, "10.0.0.2")
        assert daemon.nel.get_received() is not None

    def test_invalid_json_does_not_raise(self):
        daemon, _, _ = _make_daemon()
        _store_endorsement(daemon, b"not json {{", "10.0.0.2")
        assert daemon.nel.get_received() is None

    def test_missing_field_does_not_raise(self):
        daemon, _, _ = _make_daemon()
        _store_endorsement(daemon, json.dumps({"bad": "data"}).encode(), "10.0.0.2")
        assert daemon.nel.get_received() is None

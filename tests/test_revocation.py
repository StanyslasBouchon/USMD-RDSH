"""Tests for the endorsement revocation flows.

Three suites are covered:

1. :class:`TestRevokeEndorsementHandler` — unit tests for the NCP handler
   (``REVOKE_ENDORSEMENT`` command, all three branches).

2. :class:`TestScheduleRejoin` — unit tests for
   :meth:`~usmd.node_daemon.NodeDaemon._schedule_rejoin`.

3. :class:`TestRevokeOnShutdown` — integration-style async tests for
   :func:`~usmd._daemon_run._revoke_endorsements_on_shutdown`, verifying
   that the correct REVOKE_ENDORSEMENT frames are sent to the right peers.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from usmd._daemon_run import _revoke_endorsements_on_shutdown
from usmd.domain.usd import USDConfig, UnifiedSystemDomain
from usmd.mutation.transmutation import ResourceUsage
from usmd.ncp.protocol.commands.revoke_endorsement import (
    RevokeEndorsementRequest,
    RevokeEndorsementResponse,
)
from usmd.ncp.protocol.frame import NcpCommandId, NcpFrame
from usmd.ncp.protocol.versions import NcpVersion
from usmd.ncp.server.handler import HandlerContext, NcpCommandHandler
from usmd.node.nal import NodeAccessList
from usmd.node.nel import EndorsementPacket, NodeEndorsementList
from usmd.node.nit import NodeIdentityTable
from usmd.node.node import Node
from usmd.node.role import NodeRole
from usmd.node.state import NodeState
from usmd.security.crypto import Ed25519Pair
from usmd.security.endorsement import EndorsementFactory
from usmd.utils.errors import Error, ErrorKind
from usmd.utils.result import Result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_packet(endorser_key: bytes, node_pub_key: bytes) -> EndorsementPacket:
    """Build a minimal EndorsementPacket for testing."""
    return EndorsementPacket(
        endorser_key=endorser_key,
        node_name=1710000000,
        node_pub_key=node_pub_key,
        node_session_key=b"s" * 32,
        roles=[NodeRole.NODE_EXECUTOR],
        serial=b"\x00" * 16,
        expiration=9_999_999_999,
        signature=b"\xff" * 64,
    )


def _make_frame(sender_key: bytes) -> NcpFrame:
    """Build a REVOKE_ENDORSEMENT NCP frame for *sender_key*."""
    return NcpFrame(
        version=NcpVersion(1, 0, 0, 0),
        command_id=NcpCommandId.REVOKE_ENDORSEMENT,
        payload=RevokeEndorsementRequest(sender_key).to_payload(),
    )


@pytest.fixture()
def ed_keypair():
    return Ed25519Pair.generate()


@pytest.fixture()
def usd_config():
    return USDConfig(
        name="test-domain",
        cluster_name="",
        max_reference_nodes=5,
        load_threshold=0.8,
        ping_tolerance_ms=200,
        load_check_interval=30,
        emergency_threshold=0.9,
        version=1,
    )


@pytest.fixture()
def handler_ctx(ed_keypair, usd_config):
    priv, pub = ed_keypair
    node = Node(address="127.0.0.1", name=1710000000, state=NodeState.ACTIVE)
    usd = UnifiedSystemDomain(config=usd_config, private_key=priv)
    factory = EndorsementFactory(priv, pub)

    return HandlerContext(
        node=node,
        usd=usd,
        nit=NodeIdentityTable(),
        nal=NodeAccessList(),
        nel=NodeEndorsementList(),
        endorsement_factory=factory,
        resource_getter=lambda: ResourceUsage(0.1, 0.2, 0.05, 0.01),
        ping_tolerance_ms=200,
    )


# ---------------------------------------------------------------------------
# Suite 1 — NCP handler
# ---------------------------------------------------------------------------

class TestRevokeEndorsementHandler:
    """Unit tests for NcpCommandHandler._handle_revoke_endorsement."""

    def test_case1_endorser_shuts_down_clears_received_and_calls_rejoin(
        self, handler_ctx
    ):
        """Case 1: the sender is our endorser — clear received packet + call rejoin_fn."""
        endorser_key = b"E" * 32
        my_pub_key   = b"M" * 32

        packet = _make_packet(endorser_key=endorser_key, node_pub_key=my_pub_key)
        handler_ctx.nel.set_received(packet)

        rejoin_called = []
        handler_ctx.rejoin_fn = lambda: rejoin_called.append(True)

        handler = NcpCommandHandler(handler_ctx)
        response = handler.handle(_make_frame(sender_key=endorser_key))

        assert response.command_id == NcpCommandId.REVOKE_ENDORSEMENT
        assert handler_ctx.nel.get_received() is None, (
            "Le paquet reçu doit être effacé après la révocation de l'endosseur."
        )
        assert rejoin_called, "rejoin_fn doit être appelé après la révocation de l'endosseur."

    def test_case1_rejoin_fn_none_does_not_raise(self, handler_ctx):
        """Case 1 with rejoin_fn=None must not raise (graceful degradation)."""
        endorser_key = b"E" * 32
        packet = _make_packet(endorser_key=endorser_key, node_pub_key=b"M" * 32)
        handler_ctx.nel.set_received(packet)
        handler_ctx.rejoin_fn = None  # explicitly unset

        handler = NcpCommandHandler(handler_ctx)
        # Must not raise
        response = handler.handle(_make_frame(sender_key=endorser_key))
        assert response.command_id == NcpCommandId.REVOKE_ENDORSEMENT

    def test_case2_endorsed_node_shuts_down_removes_from_nel(self, handler_ctx):
        """Case 2: the sender was endorsed by us — remove it from NEL._issued."""
        endorsed_key = b"N" * 32
        packet = _make_packet(endorser_key=b"E" * 32, node_pub_key=endorsed_key)
        handler_ctx.nel.add_issued(packet)

        assert handler_ctx.nel.has_issued_to(endorsed_key)

        handler = NcpCommandHandler(handler_ctx)
        response = handler.handle(_make_frame(sender_key=endorsed_key))

        assert response.command_id == NcpCommandId.REVOKE_ENDORSEMENT
        assert not handler_ctx.nel.has_issued_to(endorsed_key), (
            "L'entrée doit être retirée de NEL._issued après la révocation."
        )

    def test_no_relationship_permanently_excludes_sender(self, handler_ctx):
        """If neither relationship exists, the sender is permanently excluded."""
        unknown_key = b"X" * 32

        handler = NcpCommandHandler(handler_ctx)
        response = handler.handle(_make_frame(sender_key=unknown_key))

        assert response.command_id == NcpCommandId.REVOKE_ENDORSEMENT
        assert handler_ctx.nit.is_excluded(unknown_key), (
            "Un nœud sans relation d'endossement doit être exclu de façon permanente."
        )

    def test_malformed_payload_returns_empty_response(self, handler_ctx):
        """A frame with a truncated payload must not crash the handler."""
        frame = NcpFrame(
            version=NcpVersion(1, 0, 0, 0),
            command_id=NcpCommandId.REVOKE_ENDORSEMENT,
            payload=b"\x00\x01",  # too short (needs 32 bytes)
        )
        handler = NcpCommandHandler(handler_ctx)
        response = handler.handle(frame)
        assert response.command_id == NcpCommandId.REVOKE_ENDORSEMENT
        assert response.payload == b""

    def test_case1_and_case2_are_mutually_exclusive(self, handler_ctx):
        """A key matching case 1 must not be treated as case 2 (no double action)."""
        shared_key = b"K" * 32

        # Set both: shared_key is simultaneously our endorser key AND an issued key.
        # In practice this should not happen, but the handler must pick case 1 first.
        issued_packet = _make_packet(endorser_key=b"E" * 32, node_pub_key=shared_key)
        received_packet = _make_packet(endorser_key=shared_key, node_pub_key=b"M" * 32)
        handler_ctx.nel.add_issued(issued_packet)
        handler_ctx.nel.set_received(received_packet)

        rejoin_called = []
        handler_ctx.rejoin_fn = lambda: rejoin_called.append(True)

        handler = NcpCommandHandler(handler_ctx)
        handler.handle(_make_frame(sender_key=shared_key))

        # Case 1 takes priority — received packet cleared, rejoin triggered.
        assert handler_ctx.nel.get_received() is None
        assert rejoin_called
        # Case 2 side-effect should NOT have fired (issued packet still present).
        assert handler_ctx.nel.has_issued_to(shared_key)


# ---------------------------------------------------------------------------
# Suite 2 — NodeDaemon._schedule_rejoin
# ---------------------------------------------------------------------------

class TestScheduleRejoin:
    """Unit tests for NodeDaemon._schedule_rejoin."""

    def test_sets_state_to_pending_approval(self):
        """_schedule_rejoin must change the node's state to PENDING_APPROVAL."""
        from usmd.config import NodeConfig
        from usmd.node_daemon import NodeDaemon

        cfg = NodeConfig(bootstrap=True, usd_name="test-domain")
        daemon = NodeDaemon(cfg)
        daemon.node.set_state(NodeState.ACTIVE)

        # Patch create_task to avoid needing a running loop
        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.create_task = MagicMock()
            daemon._schedule_rejoin()

        assert daemon.node.state == NodeState.PENDING_APPROVAL

    def test_schedules_join_task_on_running_loop(self):
        """_schedule_rejoin must call loop.create_task with a _join coroutine."""
        from usmd.config import NodeConfig
        from usmd.node_daemon import NodeDaemon

        cfg = NodeConfig(bootstrap=True, usd_name="test-domain")
        daemon = NodeDaemon(cfg)

        created = []
        mock_loop = MagicMock()
        mock_loop.create_task = lambda coro, **kw: created.append((coro, kw))

        with patch("asyncio.get_event_loop", return_value=mock_loop):
            daemon._schedule_rejoin()

        assert len(created) == 1
        _, kw = created[0]
        assert kw.get("name") == "rejoin-after-revocation"

    def test_no_error_when_no_event_loop(self):
        """_schedule_rejoin must not raise even when there is no running loop."""
        from usmd.config import NodeConfig
        from usmd.node_daemon import NodeDaemon

        cfg = NodeConfig(bootstrap=True, usd_name="test-domain")
        daemon = NodeDaemon(cfg)

        with patch("asyncio.get_event_loop", side_effect=RuntimeError("no loop")):
            # Must not propagate the RuntimeError
            daemon._schedule_rejoin()

        # State is still changed even if the task could not be scheduled
        assert daemon.node.state == NodeState.PENDING_APPROVAL

    def test_rejoin_fn_is_wired_in_handler_context(self):
        """HandlerContext.rejoin_fn must point to NodeDaemon._schedule_rejoin.

        Note: bound-method identity (``is``) is False in CPython because
        each attribute access creates a fresh wrapper object.  We compare
        with ``==`` which delegates to ``__eq__`` on the underlying
        (function, instance) pair.
        """
        from usmd.config import NodeConfig
        from usmd.node_daemon import NodeDaemon

        cfg = NodeConfig(bootstrap=True, usd_name="test-domain")
        daemon = NodeDaemon(cfg)

        assert daemon._handler.ctx.rejoin_fn is not None, (
            "rejoin_fn ne doit pas être None après l'initialisation."
        )
        assert daemon._handler.ctx.rejoin_fn == daemon._schedule_rejoin, (
            "rejoin_fn doit pointer vers _schedule_rejoin."
        )


# ---------------------------------------------------------------------------
# Suite 3 — _revoke_endorsements_on_shutdown (async)
# ---------------------------------------------------------------------------

def _make_ok_response() -> Result:
    frame = NcpFrame(
        version=NcpVersion(1, 0, 0, 0),
        command_id=NcpCommandId.REVOKE_ENDORSEMENT,
        payload=RevokeEndorsementResponse().to_payload(),
    )
    return Result.Ok(frame)


def _make_err_response() -> Result:
    return Result.Err(Error.new(ErrorKind.CONNECTION_ERROR, "unreachable"))


@pytest.fixture()
def mock_daemon():
    """Minimal NodeDaemon-like mock for _revoke_endorsements_on_shutdown."""
    daemon = MagicMock()
    daemon.ed_pub = b"O" * 32  # "our" pub key
    daemon.cfg.ncp_port = 5626
    daemon.cfg.ncp_timeout = 5.0
    return daemon


class TestRevokeOnShutdown:
    """Async integration-style tests for _revoke_endorsements_on_shutdown."""

    @pytest.mark.asyncio
    async def test_notifies_each_endorsed_node(self, mock_daemon):
        """Each endorsed node whose address is in the NIT must receive a frame."""
        endorsed_key_a = b"A" * 32
        endorsed_key_b = b"B" * 32
        endorser_key   = b"E" * 32

        packet_a = _make_packet(endorser_key=endorser_key, node_pub_key=endorsed_key_a)
        packet_b = _make_packet(endorser_key=endorser_key, node_pub_key=endorsed_key_b)

        mock_daemon.nel.all_issued.return_value = [packet_a, packet_b]
        mock_daemon.nel.get_received.return_value = None

        mock_daemon.nit.get_address.side_effect = lambda key: {
            endorsed_key_a: "10.0.0.2",
            endorsed_key_b: "10.0.0.3",
        }.get(key)

        sent_to: list[str] = []

        async def fake_send(command_id, payload):
            return _make_ok_response()

        with patch("usmd._daemon_run.NcpClient") as MockClient:
            instance = AsyncMock()
            instance.send = fake_send
            MockClient.side_effect = lambda address, **kw: (
                sent_to.append(address) or instance
            )
            await _revoke_endorsements_on_shutdown(mock_daemon)

        assert set(sent_to) == {"10.0.0.2", "10.0.0.3"}, (
            "Les deux nœuds endossés doivent recevoir une notification."
        )

    @pytest.mark.asyncio
    async def test_notifies_endorser_when_received_packet_present(self, mock_daemon):
        """If we have a received endorsement, our endorser must be notified."""
        endorser_key = b"E" * 32
        received_pkt = _make_packet(endorser_key=endorser_key, node_pub_key=b"O" * 32)

        mock_daemon.nel.all_issued.return_value = []
        mock_daemon.nel.get_received.return_value = received_pkt
        mock_daemon.nit.get_address.return_value = "10.0.0.1"

        sent_to: list[str] = []

        async def fake_send(command_id, payload):
            return _make_ok_response()

        with patch("usmd._daemon_run.NcpClient") as MockClient:
            instance = AsyncMock()
            instance.send = fake_send
            MockClient.side_effect = lambda address, **kw: (
                sent_to.append(address) or instance
            )
            await _revoke_endorsements_on_shutdown(mock_daemon)

        assert sent_to == ["10.0.0.1"], (
            "L'endosseur doit être notifié lorsque le nœud quitte le réseau."
        )

    @pytest.mark.asyncio
    async def test_skips_endorsed_node_with_no_nit_address(self, mock_daemon):
        """An endorsed node with no NIT entry must be silently skipped."""
        endorsed_key = b"N" * 32
        packet = _make_packet(endorser_key=b"E" * 32, node_pub_key=endorsed_key)

        mock_daemon.nel.all_issued.return_value = [packet]
        mock_daemon.nel.get_received.return_value = None
        mock_daemon.nit.get_address.return_value = None  # address unknown

        with patch("usmd._daemon_run.NcpClient") as MockClient:
            await _revoke_endorsements_on_shutdown(mock_daemon)

        MockClient.assert_not_called()

    @pytest.mark.asyncio
    async def test_skips_endorser_with_no_nit_address(self, mock_daemon):
        """An endorser with no NIT entry must be silently skipped."""
        received_pkt = _make_packet(endorser_key=b"E" * 32, node_pub_key=b"O" * 32)

        mock_daemon.nel.all_issued.return_value = []
        mock_daemon.nel.get_received.return_value = received_pkt
        mock_daemon.nit.get_address.return_value = None  # address unknown

        with patch("usmd._daemon_run.NcpClient") as MockClient:
            await _revoke_endorsements_on_shutdown(mock_daemon)

        MockClient.assert_not_called()

    @pytest.mark.asyncio
    async def test_continues_after_connection_failure(self, mock_daemon):
        """A failed send to one node must not abort the rest of the notifications."""
        key_a = b"A" * 32
        key_b = b"B" * 32

        mock_daemon.nel.all_issued.return_value = [
            _make_packet(b"E" * 32, key_a),
            _make_packet(b"E" * 32, key_b),
        ]
        mock_daemon.nel.get_received.return_value = None
        mock_daemon.nit.get_address.side_effect = lambda k: {
            key_a: "10.0.0.2",
            key_b: "10.0.0.3",
        }.get(k)

        call_count = 0

        async def fake_send(command_id, payload):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _make_err_response()  # first send fails
            return _make_ok_response()

        with patch("usmd._daemon_run.NcpClient") as MockClient:
            instance = AsyncMock()
            instance.send = fake_send
            MockClient.return_value = instance
            await _revoke_endorsements_on_shutdown(mock_daemon)

        assert call_count == 2, (
            "L'échec du premier envoi ne doit pas empêcher la notification du second nœud."
        )

    @pytest.mark.asyncio
    async def test_no_calls_when_nel_empty(self, mock_daemon):
        """Nothing must be sent if the NEL has no issued packets and no received packet."""
        mock_daemon.nel.all_issued.return_value = []
        mock_daemon.nel.get_received.return_value = None

        with patch("usmd._daemon_run.NcpClient") as MockClient:
            await _revoke_endorsements_on_shutdown(mock_daemon)

        MockClient.assert_not_called()

    @pytest.mark.asyncio
    async def test_payload_contains_own_pub_key(self, mock_daemon):
        """The REVOKE_ENDORSEMENT payload must carry the departing node's own pub key."""
        endorsed_key = b"N" * 32
        packet = _make_packet(endorser_key=b"E" * 32, node_pub_key=endorsed_key)

        mock_daemon.nel.all_issued.return_value = [packet]
        mock_daemon.nel.get_received.return_value = None
        mock_daemon.nit.get_address.return_value = "10.0.0.2"

        captured_payloads: list[bytes] = []

        async def fake_send(command_id, payload):
            captured_payloads.append(payload)
            return _make_ok_response()

        with patch("usmd._daemon_run.NcpClient") as MockClient:
            instance = AsyncMock()
            instance.send = fake_send
            MockClient.return_value = instance
            await _revoke_endorsements_on_shutdown(mock_daemon)

        assert len(captured_payloads) == 1
        parsed = RevokeEndorsementRequest.from_payload(captured_payloads[0]).unwrap()
        assert parsed.sender_pub_key == mock_daemon.ed_pub, (
            "Le payload doit contenir la clé publique du nœud partant."
        )

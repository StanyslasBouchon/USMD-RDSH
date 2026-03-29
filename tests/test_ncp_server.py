"""Tests for the NCP TCP server and command handler."""

import asyncio
import time
from unittest.mock import MagicMock, patch

import pytest

from usmd.domain.usd import USDConfig, UnifiedSystemDomain
from usmd.mutation.transmutation import ResourceUsage
from usmd.ncp.protocol.commands.check_distance import CheckDistanceRequest
from usmd.ncp.protocol.commands.get_status import GetStatusResponse
from usmd.ncp.protocol.commands.inform_reference_node import InformReferenceNodeRequest
from usmd.ncp.protocol.commands.request_approval import (
    RequestApprovalRequest,
    RequestApprovalResponse,
)
from usmd.ncp.protocol.commands.request_emergency import (
    RequestEmergencyRequest,
    RequestEmergencyResponse,
)
from usmd.ncp.protocol.commands.request_help import RequestHelpRequest
from usmd.ncp.protocol.commands.send_mutation_properties import (
    MutationSummary,
    SendMutationPropertiesRequest,
)
from usmd.ncp.protocol.commands.send_ucd_properties import SendUcdPropertiesRequest
from usmd.ncp.protocol.commands.send_usd_properties import SendUsdPropertiesRequest
from usmd.ncp.protocol.frame import NcpCommandId, NcpFrame
from usmd.ncp.protocol.versions import NcpVersion
from usmd.ncp.server.handler import HandlerContext, NcpCommandHandler
from usmd.ncp.server.tcp import NcpServer
from usmd.node.nal import NodeAccessList
from usmd.node.nel import NodeEndorsementList
from usmd.node.nit import NodeIdentityTable
from usmd.node.node import Node
from usmd.node.role import NodeRole
from usmd.node.state import NodeState
from usmd.security.crypto import Ed25519Pair
from usmd.security.endorsement import EndorsementFactory


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

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

    ctx = HandlerContext(
        node=node,
        usd=usd,
        nit=NodeIdentityTable(),
        nal=NodeAccessList(),
        nel=NodeEndorsementList(),
        endorsement_factory=factory,
        resource_getter=lambda: ResourceUsage(0.1, 0.2, 0.05, 0.01),
        ping_tolerance_ms=200,
    )
    return ctx


@pytest.fixture()
def handler(handler_ctx):
    return NcpCommandHandler(handler_ctx)


def _make_frame(command_id: NcpCommandId, payload: bytes = b"") -> NcpFrame:
    return NcpFrame(
        version=NcpVersion(1, 0, 0, 0),
        command_id=command_id,
        payload=payload,
    )


# ---------------------------------------------------------------------------
# NcpCommandHandler tests
# ---------------------------------------------------------------------------

class TestNcpCommandHandler:
    def test_get_status_returns_node_info(self, handler):
        frame = _make_frame(NcpCommandId.GET_STATUS)
        response = handler.handle(frame)
        assert response.command_id == NcpCommandId.GET_STATUS
        result = GetStatusResponse.from_payload(response.payload)
        assert result.is_ok()
        status = result.unwrap().status
        assert status.state == NodeState.ACTIVE
        assert 0.0 <= status.ram_percent <= 1.0

    def test_check_distance_returns_score(self, handler):
        sent_ms = int(time.time() * 1000) - 50  # 50 ms ago
        req = CheckDistanceRequest(sent_at_ms=sent_ms)
        frame = _make_frame(NcpCommandId.CHECK_DISTANCE, req.to_payload())
        response = handler.handle(frame)
        assert response.command_id == NcpCommandId.CHECK_DISTANCE
        import struct  # noqa: PLC0415
        (d,) = struct.unpack_from("!d", response.payload)
        assert 0.0 <= d <= 5.0

    def test_request_emergency_can_help_when_healthy(self, handler):
        req = RequestEmergencyRequest(already_notified=[])
        frame = _make_frame(NcpCommandId.REQUEST_EMERGENCY, req.to_payload())
        response = handler.handle(frame)
        result = RequestEmergencyResponse.from_payload(response.payload)
        assert result.is_ok()
        # Node is healthy (load ~0.2) and active → can help
        assert result.unwrap().can_help is True

    def test_request_emergency_cannot_help_when_overloaded(self, handler_ctx, ed_keypair):
        priv, pub = ed_keypair
        # Overloaded context
        handler_ctx.resource_getter = lambda: ResourceUsage(0.95, 0.95, 0.95, 0.95)
        h = NcpCommandHandler(handler_ctx)
        req = RequestEmergencyRequest(already_notified=[])
        frame = _make_frame(NcpCommandId.REQUEST_EMERGENCY, req.to_payload())
        response = h.handle(frame)
        result = RequestEmergencyResponse.from_payload(response.payload)
        assert result.is_ok()
        assert result.unwrap().can_help is False

    def test_request_help_can_help_when_healthy(self, handler):
        req = RequestHelpRequest(already_notified=[])
        frame = _make_frame(NcpCommandId.REQUEST_HELP, req.to_payload())
        response = handler.handle(frame)
        assert response.command_id == NcpCommandId.REQUEST_HELP
        assert len(response.payload) >= 1
        assert response.payload[0] == 0x01  # can_help = True

    def test_request_approval_approves_new_node(self, handler):
        new_priv, new_pub = Ed25519Pair.generate()
        from usmd.security.crypto import X25519Pair  # noqa: PLC0415
        _, x_pub = X25519Pair.generate()
        import os  # noqa: PLC0415
        nonce = os.urandom(16)
        node_name = int(time.time())

        req = RequestApprovalRequest(
            node_name=node_name,
            ed25519_pub=new_pub,
            x25519_pub=x_pub,
            nonce=nonce,
            signature=b"",
        )
        req.signature = Ed25519Pair.sign(new_priv, req.signable_bytes())

        frame = _make_frame(NcpCommandId.REQUEST_APPROVAL, req.to_payload())
        response = handler.handle(frame)
        assert response.command_id == NcpCommandId.REQUEST_APPROVAL
        assert len(response.payload) >= 1
        assert response.payload[0] == 0x01  # approved

    def test_request_approval_rejects_bad_signature(self, handler):
        _, new_pub = Ed25519Pair.generate()
        from usmd.security.crypto import X25519Pair  # noqa: PLC0415
        _, x_pub = X25519Pair.generate()
        import os  # noqa: PLC0415
        req = RequestApprovalRequest(
            node_name=int(time.time()),
            ed25519_pub=new_pub,
            x25519_pub=x_pub,
            nonce=os.urandom(16),
            signature=b"\x00" * 64,  # invalid signature
        )
        frame = _make_frame(NcpCommandId.REQUEST_APPROVAL, req.to_payload())
        response = handler.handle(frame)
        assert response.payload[0] == 0x00  # rejected

    def test_request_approval_rejects_inactive_node(self, handler_ctx):
        handler_ctx.node.set_state(NodeState.INACTIVE_TIMEOUT)
        h = NcpCommandHandler(handler_ctx)
        new_priv, new_pub = Ed25519Pair.generate()
        from usmd.security.crypto import X25519Pair  # noqa: PLC0415
        _, x_pub = X25519Pair.generate()
        import os  # noqa: PLC0415
        req = RequestApprovalRequest(
            node_name=int(time.time()),
            ed25519_pub=new_pub,
            x25519_pub=x_pub,
            nonce=os.urandom(16),
            signature=b"",
        )
        req.signature = Ed25519Pair.sign(new_priv, req.signable_bytes())
        frame = _make_frame(NcpCommandId.REQUEST_APPROVAL, req.to_payload())
        response = h.handle(frame)
        assert response.payload[0] == 0x00  # rejected — node not reachable

    def test_send_usd_properties_updates_config(self, handler, usd_config):
        new_cfg = USDConfig(
            name=usd_config.name,
            cluster_name="eu",
            max_reference_nodes=3,
            load_threshold=0.7,
            ping_tolerance_ms=100,
            load_check_interval=15,
            emergency_threshold=0.85,
            version=9999,
        )
        req = SendUsdPropertiesRequest.from_usd_config(new_cfg)
        frame = _make_frame(NcpCommandId.SEND_USD_PROPERTIES, req.to_payload())
        response = handler.handle(frame)
        assert response.command_id == NcpCommandId.SEND_USD_PROPERTIES
        assert handler.ctx.usd.config.version == 9999

    def test_send_usd_properties_ignores_older_version(self, handler):
        old_cfg = USDConfig(name="test-domain", version=0)
        req = SendUsdPropertiesRequest.from_usd_config(old_cfg)
        frame = _make_frame(NcpCommandId.SEND_USD_PROPERTIES, req.to_payload())
        handler.handle(frame)
        # Version should remain unchanged (config has version=1 from fixture)
        assert handler.ctx.usd.config.version == 1

    def test_send_ucd_properties_returns_empty(self, handler):
        req = SendUcdPropertiesRequest(version=100, properties={"k": "v"})
        frame = _make_frame(NcpCommandId.SEND_UCD_PROPERTIES, req.to_payload())
        response = handler.handle(frame)
        assert response.command_id == NcpCommandId.SEND_UCD_PROPERTIES
        assert response.payload == b""

    def test_send_mutation_properties_returns_empty(self, handler):
        req = SendMutationPropertiesRequest(
            services=[MutationSummary("web", 1000)]
        )
        frame = _make_frame(NcpCommandId.SEND_MUTATION_PROPERTIES, req.to_payload())
        response = handler.handle(frame)
        assert response.command_id == NcpCommandId.SEND_MUTATION_PROPERTIES
        assert response.payload == b""

    def test_inform_reference_node_returns_empty(self, handler):
        req = InformReferenceNodeRequest(
            sender_name=1,
            sender_address="10.0.0.1",
            reference_names=[100, 200, 300],
        )
        frame = _make_frame(NcpCommandId.INFORM_REFERENCE_NODE, req.to_payload())
        response = handler.handle(frame)
        assert response.command_id == NcpCommandId.INFORM_REFERENCE_NODE
        assert response.payload == b""

    def test_unknown_command_returns_empty(self, handler):
        frame = NcpFrame(
            version=NcpVersion(1, 0, 0, 0),
            command_id=NcpCommandId.GET_STATUS,
            payload=b"",
        )
        # Patch the dispatch dict to simulate an unknown command
        frame.command_id = 99  # type: ignore[assignment]
        response = handler.handle(frame)
        assert response.payload == b""


# ---------------------------------------------------------------------------
# NcpServer tests
# ---------------------------------------------------------------------------

class TestNcpServer:
    def test_init(self, handler):
        server = NcpServer(handler, port=5626, timeout=5.0)
        assert server._port == 5626
        assert server._timeout == 5.0

    def test_close_before_start_does_not_raise(self, handler):
        server = NcpServer(handler, port=5626)
        server.close()  # Should not raise

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        __import__("sys").platform == "win32",
        reason=(
            "Binding arbitrary high ports requires elevated privileges on Windows "
            "(Winsock error 10013). The server start/close logic is tested by "
            "test_handles_get_status_over_tcp on all platforms."
        ),
    )
    async def test_start_binds_port(self, handler):
        import random  # noqa: PLC0415
        port = random.randint(40000, 50000)
        server = NcpServer(handler, port=port)
        try:
            await server.start()
            assert server._server is not None
        finally:
            server.close()

    @pytest.mark.asyncio
    async def test_handles_get_status_over_tcp(self, handler):
        """End-to-end: connect, send GET_STATUS, receive response."""
        import random  # noqa: PLC0415
        port = random.randint(40000, 50000)
        server = NcpServer(handler, port=port, timeout=3.0)
        await server.start()

        try:
            request = NcpFrame(
                version=NcpVersion(1, 0, 0, 0),
                command_id=NcpCommandId.GET_STATUS,
                payload=b"",
            ).to_bytes()

            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(request)
            await writer.drain()

            # Read response header (9 bytes)
            import struct  # noqa: PLC0415
            header = await asyncio.wait_for(reader.readexactly(9), timeout=3.0)
            (_, _, payload_len) = struct.unpack_from("!4sBL", header)
            payload = await asyncio.wait_for(
                reader.readexactly(payload_len), timeout=3.0
            ) if payload_len > 0 else b""

            writer.close()
            await writer.wait_closed()

            response = NcpFrame.from_bytes(header + payload).unwrap()
            assert response.command_id == NcpCommandId.GET_STATUS
        finally:
            server.close()

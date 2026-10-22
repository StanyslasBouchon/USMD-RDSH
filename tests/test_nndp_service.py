"""Tests for the NndpService (NNDP UDP broadcaster + listener)."""

import asyncio
import sys
from unittest.mock import MagicMock, patch

import pytest

from usmd.nndp.lib import (
    NndpOptions,
    NndpService,
    _NndpListenerProtocol,
    _get_interface_broadcasts,
)
from usmd.nndp.protocol.here_i_am import HereIAmPacket, PACKET_SIZE
from usmd.node.state import NodeState
from usmd.security.crypto import Ed25519Pair


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def keypair():
    priv, pub = Ed25519Pair.generate()
    return priv, pub


@pytest.fixture()
def nndp_service(keypair):
    priv, pub = keypair
    return NndpService(
        node_name=1710000000,
        pub_key=pub,
        priv_key=priv,
        ttl=30,
        state_getter=lambda: NodeState.ACTIVE,
        on_peer_discovered=lambda pkt, ip: None,
    )


# ---------------------------------------------------------------------------
# _NndpListenerProtocol unit tests
# ---------------------------------------------------------------------------


class TestNndpListenerProtocol:
    def _make_valid_packet(self, priv, pub):
        pkt = HereIAmPacket.build(
            sender_name=1710000001,
            sender_pub_key=pub,
            sender_priv_key=priv,
            ttl=30,
            state=NodeState.ACTIVE,
        )
        return pkt.to_bytes()

    def test_valid_packet_triggers_callback(self):
        priv, pub = Ed25519Pair.generate()
        own_priv, own_pub = Ed25519Pair.generate()  # different key = not self
        discovered = []
        protocol = _NndpListenerProtocol(
            own_pub_key=own_pub,
            on_packet=lambda pkt, ip: discovered.append((pkt, ip)),
        )
        raw = self._make_valid_packet(priv, pub)
        protocol.datagram_received(raw, ("192.168.1.5", 5222))
        assert len(discovered) == 1
        assert discovered[0][1] == "192.168.1.5"

    def test_own_packet_ignored(self):
        priv, pub = Ed25519Pair.generate()
        discovered = []
        protocol = _NndpListenerProtocol(
            own_pub_key=pub,  # same key as sender
            on_packet=lambda pkt, ip: discovered.append((pkt, ip)),
        )
        raw = self._make_valid_packet(priv, pub)
        protocol.datagram_received(raw, ("192.168.1.5", 5222))
        assert len(discovered) == 0

    def test_too_short_packet_ignored(self):
        discovered = []
        own_priv, own_pub = Ed25519Pair.generate()
        protocol = _NndpListenerProtocol(
            own_pub_key=own_pub,
            on_packet=lambda pkt, ip: discovered.append((pkt, ip)),
        )
        protocol.datagram_received(b"\x00" * 10, ("10.0.0.1", 5222))
        assert len(discovered) == 0

    def test_tampered_signature_ignored(self):
        priv, pub = Ed25519Pair.generate()
        own_priv, own_pub = Ed25519Pair.generate()
        discovered = []
        protocol = _NndpListenerProtocol(
            own_pub_key=own_pub,
            on_packet=lambda pkt, ip: discovered.append((pkt, ip)),
        )
        raw = bytearray(self._make_valid_packet(priv, pub))
        raw[-1] ^= 0xFF  # corrupt last byte of signature
        protocol.datagram_received(bytes(raw), ("10.0.0.1", 5222))
        assert len(discovered) == 0

    def test_connection_made_does_not_raise(self):
        own_priv, own_pub = Ed25519Pair.generate()
        protocol = _NndpListenerProtocol(
            own_pub_key=own_pub, on_packet=lambda p, i: None
        )
        protocol.connection_made(MagicMock())  # Should not raise

    def test_error_received_does_not_raise(self):
        own_priv, own_pub = Ed25519Pair.generate()
        protocol = _NndpListenerProtocol(
            own_pub_key=own_pub, on_packet=lambda p, i: None
        )
        protocol.error_received(OSError("test"))  # Should not raise

    def test_connection_lost_does_not_raise(self):
        own_priv, own_pub = Ed25519Pair.generate()
        protocol = _NndpListenerProtocol(
            own_pub_key=own_pub, on_packet=lambda p, i: None
        )
        protocol.connection_lost(None)
        protocol.connection_lost(OSError("closed"))


# ---------------------------------------------------------------------------
# NndpService unit tests
# ---------------------------------------------------------------------------


class TestNndpService:
    def test_init_stores_config(self, nndp_service, keypair):
        priv, pub = keypair
        assert nndp_service.node_name == 1710000000
        assert nndp_service.ttl == 30
        assert nndp_service._pub_key == pub
        assert nndp_service._listen_port == 5221
        assert nndp_service._send_port == 5222
        assert nndp_service._broadcast_address == "auto"

    def test_custom_ports(self, keypair):
        priv, pub = keypair
        svc = NndpService(
            node_name=1,
            pub_key=pub,
            priv_key=priv,
            ttl=10,
            state_getter=lambda: NodeState.ACTIVE,
            on_peer_discovered=lambda p, i: None,
            options=NndpOptions(
                listen_port=9221,
                send_port=9222,
                broadcast_address="10.255.255.255",
            ),
        )
        assert svc._listen_port == 9221
        assert svc._send_port == 9222
        assert svc._broadcast_address == "10.255.255.255"

    @pytest.mark.asyncio
    async def test_broadcast_loop_sends_and_cancels(self, nndp_service):
        """broadcast_loop should send at least one packet then stop when cancelled."""
        sent_packets = []

        class MockSock:
            def setsockopt(self, *a, **kw):
                pass

            def bind(self, *a, **kw):
                pass

            def sendto(self, data, addr):
                sent_packets.append((data, addr))

            def close(self):
                pass

        with patch("usmd.nndp.lib.socket.socket", return_value=MockSock()):
            task = asyncio.create_task(nndp_service.broadcast_loop())
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        assert len(sent_packets) >= 1
        data, addr = sent_packets[0]
        assert len(data) == PACKET_SIZE
        assert addr[1] == 5221  # destination port

    @pytest.mark.asyncio
    async def test_broadcast_loop_sends_on_multiple_interfaces(self, keypair):
        """broadcast_loop should send one HIA per interface when in auto mode."""
        priv, pub = keypair
        svc = NndpService(
            node_name=1710000000,
            pub_key=pub,
            priv_key=priv,
            ttl=30,
            state_getter=lambda: NodeState.ACTIVE,
            on_peer_discovered=lambda pkt, ip: None,
            options=NndpOptions(broadcast_address="auto"),
        )
        sent_addrs = []

        class MockSock:
            def setsockopt(self, *a, **kw):
                pass

            def bind(self, *a, **kw):
                pass

            def sendto(self, data, addr):
                sent_addrs.append(addr[0])

            def close(self):
                pass

        two_iface_broadcasts = ["192.168.1.255", "10.0.0.255"]
        with patch("usmd.nndp.lib.socket.socket", return_value=MockSock()):
            with patch(
                "usmd.nndp.lib._get_interface_broadcasts",
                return_value=two_iface_broadcasts,
            ):
                task = asyncio.create_task(svc.broadcast_loop())
                await asyncio.sleep(0.05)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        # Both broadcast addresses must have been used
        assert "192.168.1.255" in sent_addrs
        assert "10.0.0.255" in sent_addrs

    @pytest.mark.asyncio
    async def test_broadcast_loop_skips_failed_interface(self, keypair):
        """An OSError on one interface must not stop the others."""
        priv, pub = keypair
        svc = NndpService(
            node_name=1710000000,
            pub_key=pub,
            priv_key=priv,
            ttl=30,
            state_getter=lambda: NodeState.ACTIVE,
            on_peer_discovered=lambda pkt, ip: None,
        )
        sent_addrs = []

        class MockSockWithError:
            def setsockopt(self, *a, **kw):
                pass

            def bind(self, *a, **kw):
                pass

            def sendto(self, data, addr):
                if addr[0] == "192.168.1.255":
                    raise OSError("network unreachable")
                sent_addrs.append(addr[0])

            def close(self):
                pass

        with patch("usmd.nndp.lib.socket.socket", return_value=MockSockWithError()):
            with patch(
                "usmd.nndp.lib._get_interface_broadcasts",
                return_value=["192.168.1.255", "10.0.0.255"],
            ):
                task = asyncio.create_task(svc.broadcast_loop())
                await asyncio.sleep(0.05)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        # The second interface must still have received the packet
        assert "10.0.0.255" in sent_addrs


# ---------------------------------------------------------------------------
# _get_interface_broadcasts unit tests
# ---------------------------------------------------------------------------


class TestGetInterfaceBroadcasts:
    def test_explicit_address_returned_directly(self):
        """A non-auto address bypasses interface enumeration."""
        assert _get_interface_broadcasts("10.255.255.255") == ["10.255.255.255"]
        assert _get_interface_broadcasts("192.168.0.255") == ["192.168.0.255"]
        assert _get_interface_broadcasts("255.255.255.255") == ["255.255.255.255"]

    def test_auto_returns_nonempty_list(self):
        """Auto mode always returns at least one address."""
        result = _get_interface_broadcasts("auto")
        assert isinstance(result, list)
        assert len(result) >= 1
        for addr in result:
            assert isinstance(addr, str)

    def test_auto_fallback_when_psutil_missing(self):
        """Without psutil, falls back to 255.255.255.255."""
        with patch.dict(sys.modules, {"psutil": None}):
            result = _get_interface_broadcasts("auto")
        assert result == ["255.255.255.255"]

    def test_auto_fallback_on_empty_interfaces(self):
        """When psutil reports no IPv4 broadcast addresses, fall back."""
        mock_psutil = MagicMock()
        mock_psutil.net_if_addrs.return_value = {}
        with patch.dict(sys.modules, {"psutil": mock_psutil}):
            result = _get_interface_broadcasts("auto")
        assert result == ["255.255.255.255"]

    def test_auto_collects_all_interface_broadcasts(self):
        """Each interface broadcast address is included in the result."""
        import socket as _socket  # noqa: PLC0415

        mock_addr_1 = MagicMock()
        mock_addr_1.family = _socket.AF_INET
        mock_addr_1.broadcast = "192.168.1.255"
        mock_addr_2 = MagicMock()
        mock_addr_2.family = _socket.AF_INET
        mock_addr_2.broadcast = "10.0.0.255"
        mock_addr_ipv6 = MagicMock()
        mock_addr_ipv6.family = _socket.AF_INET6  # must be ignored
        mock_addr_ipv6.broadcast = None

        mock_psutil = MagicMock()
        mock_psutil.net_if_addrs.return_value = {
            "eth0": [mock_addr_1, mock_addr_ipv6],
            "eth1": [mock_addr_2],
        }
        with patch.dict(sys.modules, {"psutil": mock_psutil}):
            result = _get_interface_broadcasts("auto")

        assert "192.168.1.255" in result
        assert "10.0.0.255" in result
        assert len(result) == 2  # IPv6 entry excluded

    def test_auto_ignores_none_broadcast(self):
        """Interface addresses with broadcast=None (e.g. loopback) are skipped."""
        import socket as _socket  # noqa: PLC0415

        mock_lo = MagicMock()
        mock_lo.family = _socket.AF_INET
        mock_lo.broadcast = None  # loopback has no broadcast
        mock_eth = MagicMock()
        mock_eth.family = _socket.AF_INET
        mock_eth.broadcast = "172.16.0.255"

        mock_psutil = MagicMock()
        mock_psutil.net_if_addrs.return_value = {
            "lo": [mock_lo],
            "eth0": [mock_eth],
        }
        with patch.dict(sys.modules, {"psutil": mock_psutil}):
            result = _get_interface_broadcasts("auto")

        assert result == ["172.16.0.255"]

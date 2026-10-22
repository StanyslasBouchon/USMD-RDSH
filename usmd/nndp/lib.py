"""NNDP service — UDP broadcaster and listener for USMD-RDSH.

Broadcasts a signed Here-I-Am (HIA) packet every TTL seconds on **every**
active network interface (source port 5222, destination port 5221).
When ``broadcast_address`` is ``"auto"`` (the default) the service enumerates
all IPv4 interfaces at each cycle and sends a directed broadcast per interface
(e.g. ``192.168.1.255``).  If ``psutil`` is not installed it falls back to the
limited broadcast ``255.255.255.255``.  A specific address can always be forced
by passing it explicitly.

Listens on UDP port 5221 for incoming HIA packets on all interfaces.  For every
valid, cryptographically-verified packet a caller-supplied callback is invoked
so the daemon can initiate the NCP join handshake.

Examples:
    >>> from usmd.nndp.lib import NndpService
    >>> from usmd.node.state import NodeState
    >>> from usmd.security.crypto import Ed25519Pair
    >>> priv, pub = Ed25519Pair.generate()
    >>> svc = NndpService(
    ...     node_name=1710000000,
    ...     pub_key=pub,
    ...     priv_key=priv,
    ...     ttl=30,
    ...     state_getter=lambda: NodeState.ACTIVE,
    ...     on_peer_discovered=lambda pkt, ip: None,
    ... )
"""

import asyncio
import logging
import socket
from dataclasses import dataclass
from typing import Callable, Optional

from ..node.state import NodeState
from ..nndp.protocol.here_i_am import HereIAmPacket, PACKET_SIZE

# Offset into a raw HIA packet where the sender's Ed25519 public key starts.
_PUB_KEY_OFFSET = 4   # 4 bytes NNDP version prefix
_PUB_KEY_SIZE = 32

_FALLBACK_BROADCAST = "255.255.255.255"


@dataclass
class NndpOptions:
    """Network-level options for :class:`NndpService`.

    Attributes:
        listen_port: UDP port to listen on.
        send_port: UDP source port for outbound broadcasts.
        broadcast_address: ``"auto"`` to enumerate interfaces, or a specific
            broadcast IP such as ``"192.168.1.255"``.

    Examples:
        >>> opts = NndpOptions()
        >>> opts.listen_port
        5221
    """

    listen_port: int = 5221
    send_port: int = 5222
    broadcast_address: str = "auto"


def _get_interface_broadcasts(fallback: str) -> list[str]:
    """Return the list of IPv4 broadcast addresses to use for NNDP.

    When *fallback* is a specific IP address it is returned as-is (single
    element list), which lets operators pin broadcasts to a particular subnet.

    When *fallback* is ``"auto"`` the function enumerates every active IPv4
    interface via ``psutil`` (optional dependency) and collects their directed
    broadcast addresses.  If ``psutil`` is unavailable, or if enumeration
    yields no usable address, ``["255.255.255.255"]`` is returned as a
    safe fallback.

    Args:
        fallback: Either ``"auto"`` or an explicit broadcast IP such as
            ``"192.168.1.255"`` or ``"255.255.255.255"``.

    Returns:
        list[str]: One or more broadcast addresses to send HIA packets to.

    Examples:
        >>> addrs = _get_interface_broadcasts("10.255.255.255")
        >>> addrs
        ['10.255.255.255']
        >>> isinstance(_get_interface_broadcasts("auto"), list)
        True
    """
    if fallback != "auto":
        return [fallback]

    try:
        import psutil

        broadcasts: list[str] = []
        for iface_addrs in psutil.net_if_addrs().values():
            for addr in iface_addrs:
                if addr.family == socket.AF_INET and addr.broadcast:
                    broadcasts.append(addr.broadcast)
        if broadcasts:
            return broadcasts
    except ImportError:
        pass

    return [_FALLBACK_BROADCAST]


class _NndpListenerProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protocol that receives and validates incoming HIA packets."""

    def __init__(
        self,
        own_pub_key: bytes,
        on_packet: Callable[[HereIAmPacket, str], None],
    ) -> None:
        self._own_pub_key = own_pub_key
        self._on_packet = on_packet

    def connection_made(self, transport: asyncio.BaseTransport) -> None:  # noqa: D102
        pass  # transport stored by asyncio internally

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:  # noqa: D102
        ip, _ = addr

        if len(data) < PACKET_SIZE:
            return

        pub_key = data[_PUB_KEY_OFFSET: _PUB_KEY_OFFSET + _PUB_KEY_SIZE]

        # Ignore our own broadcasts
        if pub_key == self._own_pub_key:
            return

        result = HereIAmPacket.verify_and_parse(data, pub_key)
        if result.is_err():
            logging.debug(
                "[\x1b[38;5;51mUSMD\x1b[0m] NNDP invalid HIA from %s: %s",
                ip,
                result.unwrap_err(),
            )
            return

        packet = result.unwrap()
        logging.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] NNDP HIA from %s key=%s",
            ip,
            pub_key.hex()[:16] + "…",
        )
        self._on_packet(packet, ip)

    def error_received(self, exc: Exception) -> None:  # noqa: D102
        logging.warning(
            "[\x1b[38;5;51mUSMD\x1b[0m] NNDP listener error: %s", exc
        )

    def connection_lost(self, exc: Optional[Exception]) -> None:  # noqa: D102
        if exc:
            logging.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] NNDP listener connection lost: %s", exc
            )


class NndpService:
    """NNDP broadcaster and listener for a running USMD-RDSH node.

    Starts two concurrent asyncio tasks:
    - **Listener**: binds UDP port ``listen_port``, calls ``on_peer_discovered``
      for each valid inbound HIA packet that does not come from this node.
    - **Broadcaster**: sends a signed HIA packet to the broadcast address every
      ``ttl`` seconds.

    Attributes:
        node_name: UNIX-timestamp identity of this node.
        ttl: Liveness interval in seconds (also the broadcast period).

    Examples:
        >>> svc = NndpService.__new__(NndpService)
        >>> isinstance(svc, NndpService)
        True
    """

    def __init__(
        self,
        node_name: int,
        pub_key: bytes,
        priv_key: bytes,
        ttl: int,
        state_getter: Callable[[], NodeState],
        on_peer_discovered: Callable[[HereIAmPacket, str], None],
        options: NndpOptions | None = None,
    ) -> None:
        """Initialise the NNDP service.

        Args:
            node_name: UNIX-timestamp name of this node.
            pub_key: Ed25519 public key (32 bytes).
            priv_key: Ed25519 private key (32 bytes).
            ttl: Broadcast interval in seconds.
            state_getter: Callable returning the current NodeState.
            on_peer_discovered: Called with (packet, sender_ip) on valid HIA.
            options: Network-level options (ports, broadcast address).
                     Defaults to :class:`NndpOptions` with stock values.
        """
        _opts = options or NndpOptions()
        self.node_name = node_name
        self.ttl = ttl
        self._pub_key = pub_key
        self._priv_key = priv_key
        self._state_getter = state_getter
        self._on_peer_discovered = on_peer_discovered
        self._listen_port = _opts.listen_port
        self._send_port = _opts.send_port
        self._broadcast_address = _opts.broadcast_address

    # ------------------------------------------------------------------
    # Listener
    # ------------------------------------------------------------------

    async def start_listener(self) -> asyncio.DatagramTransport:
        """Bind the UDP listener and start receiving HIA packets.

        Returns:
            asyncio.DatagramTransport: The underlying transport (for cleanup).
        """
        loop = asyncio.get_running_loop()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            # SO_REUSEPORT lets multiple processes bind the same port; not on Windows
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)  # type: ignore[attr-defined]
        except AttributeError:
            pass
        sock.bind(("", self._listen_port))

        transport, _ = await loop.create_datagram_endpoint(
            lambda: _NndpListenerProtocol(self._pub_key, self._on_peer_discovered),
            sock=sock,
        )

        logging.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] NNDP listener bound on UDP :%d",
            self._listen_port,
        )
        return transport  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Broadcaster
    # ------------------------------------------------------------------

    async def broadcast_loop(self) -> None:
        """Broadcast a signed HIA packet every TTL seconds on all interfaces.

        On each cycle, :func:`_get_interface_broadcasts` is called to obtain
        the current list of broadcast addresses so that newly-added interfaces
        are picked up without a restart.  One HIA packet is sent per address.

        This coroutine should be started as an asyncio Task. It stops only
        when cancelled.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.bind(("", self._send_port))
        except OSError as exc:
            logging.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] NNDP could not bind send port %d: %s",
                self._send_port,
                exc,
            )
            sock.bind(("", 0))

        logging.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] NNDP broadcaster started "
            "(ttl=%ds, broadcast=%s, port=%d)",
            self.ttl,
            self._broadcast_address,
            self._listen_port,
        )

        try:
            while True:
                state = self._state_getter()
                pkt = HereIAmPacket.build(
                    sender_name=self.node_name,
                    sender_pub_key=self._pub_key,
                    sender_priv_key=self._priv_key,
                    ttl=self.ttl,
                    state=state,
                )
                raw = pkt.to_bytes()

                targets = _get_interface_broadcasts(self._broadcast_address)
                for bcast in targets:
                    try:
                        await asyncio.get_running_loop().run_in_executor(
                            None,
                            lambda r=raw, b=bcast: sock.sendto(
                                r, (b, self._listen_port)
                            ),
                        )
                        logging.debug(
                            "[\x1b[38;5;51mUSMD\x1b[0m] NNDP HIA → %s:%d "
                            "(%d bytes, state=%s)",
                            bcast,
                            self._listen_port,
                            len(raw),
                            self._state_getter().value,
                        )
                    except Exception as exc:  # pylint: disable=broad-except
                        logging.debug(
                            "[\x1b[38;5;51mUSMD\x1b[0m] NNDP send error: %s", exc
                        )
                await asyncio.sleep(self.ttl)
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # pylint: disable=broad-except
            logging.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] NNDP broadcast loop error: %s", exc
            )
            await asyncio.sleep(self.ttl)

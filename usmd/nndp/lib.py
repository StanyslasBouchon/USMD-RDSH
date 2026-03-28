"""NNDP service — UDP broadcaster and listener for USMD-RDSH.

Broadcasts a signed Here-I-Am (HIA) packet every TTL seconds on the
broadcast address (source port 5222, destination port 5221).

Listens on UDP port 5221 for incoming HIA packets. For every valid,
cryptographically-verified packet a caller-supplied callback is invoked
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
from typing import Callable, Optional

from ..node.state import NodeState
from ..nndp.protocol.here_i_am import HereIAmPacket, PACKET_SIZE

# Offset into a raw HIA packet where the sender's Ed25519 public key starts.
_PUB_KEY_OFFSET = 4   # 4 bytes NNDP version prefix
_PUB_KEY_SIZE = 32


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


class NndpService:  # pylint: disable=too-many-instance-attributes
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

    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        node_name: int,
        pub_key: bytes,
        priv_key: bytes,
        ttl: int,
        state_getter: Callable[[], NodeState],
        on_peer_discovered: Callable[[HereIAmPacket, str], None],
        listen_port: int = 5221,
        send_port: int = 5222,
        broadcast_address: str = "255.255.255.255",
    ) -> None:
        """Initialise the NNDP service.

        Args:
            node_name: UNIX-timestamp name of this node.
            pub_key: Ed25519 public key (32 bytes).
            priv_key: Ed25519 private key (32 bytes).
            ttl: Broadcast interval in seconds.
            state_getter: Callable returning the current NodeState.
            on_peer_discovered: Called with (packet, sender_ip) on valid HIA.
            listen_port: UDP port to listen on. Default: 5221.
            send_port: UDP source port for broadcasts. Default: 5222.
            broadcast_address: Broadcast destination IP. Default: 255.255.255.255.
        """
        self.node_name = node_name
        self.ttl = ttl
        self._pub_key = pub_key
        self._priv_key = priv_key
        self._state_getter = state_getter
        self._on_peer_discovered = on_peer_discovered
        self._listen_port = listen_port
        self._send_port = send_port
        self._broadcast_address = broadcast_address

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
        """Broadcast a signed HIA packet every TTL seconds (runs forever).

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
            "(ttl=%ds → %s:%d)",
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
                try:
                    await asyncio.get_running_loop().run_in_executor(
                        None,
                        lambda r=raw: sock.sendto(
                            r, (self._broadcast_address, self._listen_port)
                        ),
                    )
                    logging.debug(
                        "[\x1b[38;5;51mUSMD\x1b[0m] NNDP HIA sent (%d bytes, "
                        "state=%s)",
                        len(raw),
                        state.value,
                    )
                except OSError as exc:
                    logging.warning(
                        "[\x1b[38;5;51mUSMD\x1b[0m] NNDP broadcast error: %s", exc
                    )
                await asyncio.sleep(self.ttl)
        except asyncio.CancelledError:
            logging.debug("[\x1b[38;5;51mUSMD\x1b[0m] NNDP broadcast loop cancelled")
        finally:
            sock.close()

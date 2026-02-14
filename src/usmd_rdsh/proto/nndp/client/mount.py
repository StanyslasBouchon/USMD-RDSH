"""UDP service for sending Here I Am packets periodically via broadcast.

This module provides a UDP service that sends Here I Am packets every 15 seconds
via broadcast to announce the node's presence on the network.
"""

import asyncio
import logging
import socket
import threading
import time
from typing import Awaitable, Callable, Optional, Union

from usmd_rdsh.proto.base.bitvec import Msb
from usmd_rdsh.proto.base.encoder import FrameEncoder
from usmd_rdsh.proto.nndp.base.env import VERSION, HereIAmData
from usmd_rdsh.proto.nndp.client.packets.here_i_am import HereIAmPacket
from usmd_rdsh.security.ed25519 import Ed25519KeyPair, unb64u
from usmd_rdsh.utils.errors import Error, ErrorKind
from usmd_rdsh.utils.result import Result

PayloadProvider = Union[Callable[[], HereIAmData], Callable[[], Awaitable[HereIAmData]]]


class MountService:
    """UDP service for periodically sending Here I Am packets via broadcast.

    This service creates a UDP socket configured for broadcast and sends Here I Am
    packets every 15 seconds to announce the node's presence on the network.
    The service runs in a separate thread and can be started and stopped as needed.

    Attributes:
        send_port (int): The UDP port for sending broadcast packets
        receive_port (int): The UDP port for receiving packets
        interval (float): Interval between packet sends in seconds (default: 15.0)
        socket (Optional[socket.socket]): The UDP socket instance
        thread (Optional[threading.Thread]): The service thread
        running (bool): Flag indicating if the service is running

    Examples:
        >>> service = MountService(8080, 8081)
        >>> service.start()
        >>> # Service is now sending packets every 15 seconds
        >>> service.stop()
    """

    def __init__(
        self,
        payload_provider: PayloadProvider,
        send_port: int,
        receive_port: int,
        ed25519_keypair: Ed25519KeyPair,
        interval: float = 15.0,
    ) -> None:
        """Initialize the mount service.

        Args:
            payload_provider: The provider for the payload for the Here I Am packet
            send_port: The UDP port for sending broadcast packets
            receive_port: The UDP port for receiving packets (socket will bind to this)
            ed25519_keypair: The Ed25519 key pair for the node
            interval: Interval between packet sends in seconds (default: 15.0)

        Examples:
            >>> service = MountService(
            ...     lambda: HereIAmData(
            ...         version=VERSION,
            ...         node_id="my-node",
            ...         next_hia_pkt_time=int((time.time() + 15.0) * 1000),
            ...         state=NodeState.ACTIVE,
            ...     ),
            ...     8080,
            ...     8081,
            ...     Ed25519KeyPair.generate(),
            ... )
        """
        self.payload_provider = payload_provider
        self.send_port = send_port
        self.receive_port = receive_port
        self.ed25519_keypair = ed25519_keypair
        self.interval = interval
        self.socket: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.running = False
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the UDP broadcast service.

        Creates a UDP socket configured for broadcast and starts a background
        thread that sends Here I Am packets at the configured interval.

        Examples:
            >>> service = MountService(8080, 8081)
            >>> service.start()
            >>> # Service is now running
        """
        with self._lock:
            if self.running:
                logging.warning("[NNDP] MountService is already running")
                return

            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                self.socket.bind(("", self.receive_port))
                self.running = True
                self.thread = threading.Thread(
                    target=asyncio.run, args=(self._run(),), daemon=True
                )
                self.thread.start()
                logging.info(
                    "[NNDP] MountService started: sending Here I Am packets via broadcast "
                    "to port %d, receiving on port %d, every %.1f seconds",
                    self.send_port,
                    self.receive_port,
                    self.interval,
                )
            except (OSError, RuntimeError) as e:
                logging.error("[NNDP] Failed to start MountService: %s", e)
                self.running = False
                if self.socket:
                    self.socket.close()
                    self.socket = None

    def stop(self) -> None:
        """Stop the UDP service.

        Stops the background thread and closes the UDP socket.

        Examples:
            >>> service.start()
            >>> # ... do work ...
            >>> service.stop()
        """
        with self._lock:
            if not self.running:
                return

            self.running = False
            if self.socket:
                try:
                    self.socket.close()
                except OSError as e:
                    logging.error("[NNDP] Error closing socket: %s", e)
                finally:
                    self.socket = None

            if self.thread:
                self.thread.join(timeout=5.0)
                self.thread = None

            logging.info("[NNDP] MountService stopped")

    async def _run(self) -> None:
        """Main service loop running in background thread.

        Continuously sends Here I Am packets at the configured interval
        until the service is stopped.
        """
        while self.running:
            try:
                result = await self._send_packet()
                if result.is_err():
                    error = result.unwrap_err()
                    logging.error(
                        "[NNDP] Failed to send Here I Am packet: %s", error.message
                    )
            except (OSError, RuntimeError) as e:
                logging.error("[NNDP] Error in MountService loop: %s", e)

            # Sleep for the interval, checking running flag periodically
            sleep_time = 0.1
            elapsed = 0.0
            while elapsed < self.interval and self.running:
                time.sleep(sleep_time)
                elapsed += sleep_time

    async def _send_packet(self) -> Result[None, Error]:
        """Encode and send a Here I Am packet via UDP broadcast.

        Creates a Here I Am packet, encodes it using FrameEncoder, converts
        it to bytes, and sends it via UDP broadcast to all nodes on the network.

        Returns:
            Result[None, Error]: Ok(None) if packet was sent successfully,
                               Err(Error) if encoding or sending failed

        Examples:
            >>> service = MountService(8080, 8081)
            >>> service.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            >>> service.socket.bind(("", 8081))
            >>> result = service._send_packet()
            >>> if result.is_ok():
            ...     print("Packet sent successfully")
        """
        if not self.socket:
            return Result.Err(
                Error.new(ErrorKind.PROTOCOL_ERROR, "UDP socket is not initialized")
            )

        data = await self._get_payload()

        # Create and encode the packet
        packet = HereIAmPacket(data)
        encode_result = packet.encode()
        if encode_result.is_err():
            return Result.Err(encode_result.unwrap_err())

        # Encode the frame
        frame_encoder = FrameEncoder[Msb](version=VERSION)
        frame_result = frame_encoder.encode(packet)
        if frame_result.is_err():
            return Result.Err(frame_result.unwrap_err())

        # Convert BitVec to bytes
        bitvec = frame_result.unwrap()
        packet_bytes = bitvec.to_bytes()

        # Sign the packet
        signed_packet = bytes(self.ed25519_keypair.sk.sign(packet_bytes))
        pub_key_bytes = unb64u(self.ed25519_keypair.pub32_b64u)
        full_packet = pub_key_bytes + signed_packet

        # Send via UDP broadcast
        try:
            broadcast_address = "255.255.255.255"
            self.socket.sendto(full_packet, (broadcast_address, self.send_port))
            logging.debug(
                "[NNDP] Sent Here I Am packet (%d bytes) via broadcast to port %d",
                len(full_packet),
                self.send_port,
            )
            return Result.Ok(None)
        except OSError as e:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"Failed to send UDP packet: {str(e)}",
                )
            )

    async def _get_payload(self) -> HereIAmData:
        """Get the payload for the Here I Am packet.

        Returns:
            HereIAmData: The payload for the Here I Am packet
        """
        res = self.payload_provider()
        if asyncio.iscoroutinefunction(self.payload_provider):
            res = await self.payload_provider()
        return res

"""QUIC service for sending NCP packets periodically.

This module provides a QUIC service that sends NCP (Network Control Protocol)
packets every 15 seconds to announce the node's presence on the network.
Uses TLS 1.3 on QUIC; the client trusts node.crt from ~/.usmd.
"""

import asyncio
import logging
import os
import threading
from typing import Awaitable, Callable, Optional, Union

from aioquic.asyncio import connect
from aioquic.quic.configuration import QuicConfiguration
from usmd_rdsh.proto.base.bitvec import Msb
from usmd_rdsh.proto.base.encoder import FrameEncoder
from usmd_rdsh.proto.base.env import NNDP_VERSION
from usmd_rdsh.proto.nndp.base.env import HereIAmData
from usmd_rdsh.proto.nndp.client.packets.here_i_am import HereIAmPacket
from usmd_rdsh.utils.errors import Error, ErrorKind
from usmd_rdsh.utils.result import Result

PayloadProvider = Union[Callable[[], HereIAmData], Callable[[], Awaitable[HereIAmData]]]


class MountService:
    """QUIC service for periodically sending NCP packets.

    This service creates QUIC connections and sends NCP packets every 15 seconds
    to announce the node's presence on the network. Uses TLS 1.3 on QUIC; trusts
    node.crt from ~/.usmd to verify the server. It runs in a separate thread and
    can be started and stopped as needed.

    Attributes:
        port (int): The QUIC port for both sending and receiving packets
        host (str): The target host to connect to (default: "0.0.0.0" for broadcast)
        interval (float): Interval between packet sends in seconds (default: 15.0)
        connection (Optional[QuicConnection]): The QUIC connection instance
        thread (Optional[threading.Thread]): The service thread
        running (bool): Flag indicating if the service is running

    Examples:
        >>> service = MountService(lambda: HereIAmData(...), 8080)
        >>> service.start()
        >>> # Service is now sending packets every 15 seconds
        >>> service.stop()
    """

    def __init__(
        self,
        payload_provider: PayloadProvider,
        port: int,
        host: str = "0.0.0.0",
        interval: float = 15.0,
    ) -> None:
        """Initialize the mount service.

        Args:
            payload_provider: The provider for the payload for the NCP packet
            port: The QUIC port for both sending and receiving packets
            host: The target host to connect to (default: "0.0.0.0")
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
            ... )
        """
        self.payload_provider = payload_provider
        self.port = port
        self.host = host
        self.interval = interval
        self.connection: Optional[object] = None
        self.thread: Optional[threading.Thread] = None
        self.running = False
        self._lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def start(self) -> None:
        """Start the QUIC service.

        Creates a QUIC connection and starts a background thread that sends
        NCP packets at the configured interval.

        Examples:
            >>> service = MountService(lambda: HereIAmData(...), 8080)
            >>> service.start()
            >>> # Service is now running
        """
        with self._lock:
            if self.running:
                logging.warning("[NCP] MountService is already running")
                return

            try:
                # TLS 1.3 on QUIC: trust node.crt from ~/.usmd
                cert_dir = os.path.expanduser("~/.usmd")
                cert_file = os.path.join(cert_dir, "node.crt")

                configuration = QuicConfiguration(is_client=True)
                configuration.load_verify_locations(cafile=cert_file)
                configuration.server_name = self.host or "localhost"
                configuration.idle_timeout = 60.0

                # Create event loop for QUIC client
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)

                self.running = True
                self.thread = threading.Thread(
                    target=self._run, args=(configuration,), daemon=True
                )
                self.thread.start()
                logging.info(
                    "[NCP] MountService started: sending NCP packets via QUIC "
                    "to %s:%d, every %.1f seconds",
                    self.host,
                    self.port,
                    self.interval,
                )
            except (OSError, RuntimeError) as e:
                logging.error("[NCP] Failed to start MountService: %s", e)
                self.running = False
                if self._loop:
                    self._loop.close()
                    self._loop = None

    def stop(self) -> None:
        """Stop the QUIC service.

        Stops the background thread and closes the QUIC connection.

        Examples:
            >>> service.start()
            >>> # ... do work ...
            >>> service.stop()
        """
        with self._lock:
            if not self.running:
                return

            self.running = False
            if self._loop:
                self._loop.call_soon_threadsafe(self._loop.stop)
                if self.connection:
                    self._loop.call_soon_threadsafe(self.connection.close)

            if self.thread:
                self.thread.join(timeout=5.0)
                self.thread = None

            if self._loop:
                self._loop.close()
                self._loop = None

            logging.info("[NCP] MountService stopped")

    def _run(self, configuration: QuicConfiguration) -> None:
        """Main service loop running in background thread.

        Establishes QUIC connection and continuously sends NCP packets at the
        configured interval until the service is stopped.
        """
        asyncio.set_event_loop(self._loop)

        async def run_client():
            try:
                # Connect to QUIC server
                self.connection, protocol = await connect(
                    self.host,
                    self.port,
                    configuration=configuration,
                )

                while self.running:
                    try:
                        result = await self._send_packet(protocol)
                        if result.is_err():
                            error = result.unwrap_err()
                            logging.error(
                                "[NCP] Failed to send NCP packet: %s", error.message
                            )
                    except (OSError, RuntimeError) as e:
                        logging.error("[NCP] Error in MountService loop: %s", e)

                    # Sleep for the interval, checking running flag periodically
                    sleep_time = 0.1
                    elapsed = 0.0
                    while elapsed < self.interval and self.running:
                        await asyncio.sleep(sleep_time)
                        elapsed += sleep_time
            except (OSError, RuntimeError) as e:
                if self.running:
                    logging.error("[NCP] Failed to connect: %s", e)

        try:
            self._loop.run_until_complete(run_client())
        except (OSError, RuntimeError) as e:
            if self.running:
                logging.error("[NCP] Error in MountService loop: %s", e)

    async def _send_packet(self, _protocol) -> Result[None, Error]:
        """Encode and send an NCP packet via QUIC.

        Creates an NCP packet, encodes it using FrameEncoder, converts
        it to bytes, and sends it via QUIC stream.

        Args:
            protocol: The QUIC protocol instance

        Returns:
            Result[None, Error]: Ok(None) if packet was sent successfully,
                               Err(Error) if encoding or sending failed

        Examples:
            >>> service = MountService(lambda: HereIAmData(...), 8080)
            >>> result = await service._send_packet(protocol)
            >>> if result.is_ok():
            ...     print("Packet sent successfully")
        """
        if not self.connection:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR, "QUIC connection is not initialized"
                )
            )

        data = await self._get_payload()

        # Create and encode the packet
        packet = HereIAmPacket(data)
        encode_result = packet.encode()
        if encode_result.is_err():
            return Result.Err(encode_result.unwrap_err())

        # Encode the frame
        frame_encoder = FrameEncoder[Msb](version=NNDP_VERSION)
        frame_result = frame_encoder.encode(packet)
        if frame_result.is_err():
            return Result.Err(frame_result.unwrap_err())

        # Convert BitVec to bytes
        bitvec = frame_result.unwrap()
        packet_bytes = bitvec.to_bytes()

        # Send via QUIC stream (TLS 1.3 encrypted)
        try:
            stream_id = self.connection.get_next_available_stream_id()
            self.connection.send_stream_data(stream_id, packet_bytes, end_stream=True)
            logging.debug(
                "[NCP] Sent NCP packet (%d bytes) via QUIC stream %d to %s:%d",
                len(packet_bytes),
                stream_id,
                self.host,
                self.port,
            )
            return Result.Ok(None)
        except (OSError, RuntimeError) as e:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"Failed to send QUIC packet: {str(e)}",
                )
            )

    async def _get_payload(self) -> HereIAmData:
        """Get the payload for the NCP packet.

        Returns:
            HereIAmData: The payload for the NCP packet
        """
        res = self.payload_provider()
        if asyncio.iscoroutinefunction(self.payload_provider):
            res = await self.payload_provider()
        return res

"""QUIC service for receiving and decoding NCP packets.

This module provides a QUIC service that listens for NCP (Network Control Protocol)
packets on a specified port, decodes them, and publishes events when packets are received.
The service uses TLS 1.3 on QUIC with node.crt and node.key from ~/.usmd.
"""

import asyncio
import logging
import os
import threading
from typing import Optional

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived
from usmd_rdsh.proto.base.bitvec import BitVec, Msb
from usmd_rdsh.proto.base.decoder import BitDecoder, Frame, FrameDecoder
from usmd_rdsh.proto.nndp.server.packets.here_i_am import HereIAmDecoder
from usmd_rdsh.utils.errors import Error, ErrorKind
from usmd_rdsh.utils.result import Result


class NCPProtocol(QuicConnectionProtocol):
    """QUIC protocol handler for NCP packets.

    This class handles individual QUIC connections and processes incoming
    stream data as NCP packets.
    """

    def __init__(self, *args, decode_callback, **kwargs):
        """Initialize the NCP protocol handler.

        Args:
            *args: Arguments passed to QuicConnectionProtocol
            decode_callback: Callback function to decode packets
            **kwargs: Keyword arguments passed to QuicConnectionProtocol
        """
        super().__init__(*args, **kwargs)
        self._decode_callback = decode_callback

    def quic_event_received(self, event: QuicEvent) -> None:
        """Handle QUIC events.

        Args:
            event: The QUIC event to handle
        """
        if isinstance(event, StreamDataReceived):
            # Decode the packet from stream data
            # Get peer address from the connection (use default if not available)
            peer_addr = getattr(self._quic, "_remote_addr", None)
            if peer_addr:
                addr = (peer_addr[0], peer_addr[1])
            else:
                addr = ("0.0.0.0", 0)
            self._decode_callback(event.data, addr)


class MountService:
    """QUIC service for receiving and decoding NCP packets.

    This service creates a QUIC server that listens for NCP packets on a
    specified port. It accepts incoming QUIC connections and decodes packets
    from stream data. Uses TLS 1.3 on QUIC with node.crt and node.key from
    ~/.usmd (same as Ed25519Certificate.generate output).
    It runs in a separate thread and can be started and stopped as needed.

    Attributes:
        port (int): The QUIC port for listening for connections
        server (Optional[asyncio.Server]): The QUIC server instance
        thread (Optional[threading.Thread]): The service thread
        running (bool): Flag indicating if the service is running

    Examples:
        >>> service = MountService(8080)
        >>> service.start()
        >>> # Service is now listening for QUIC connections
        >>> service.stop()
    """

    def __init__(self, port: int) -> None:
        """Initialize the mount service.

        Args:
            port: The QUIC port to listen on for incoming connections

        Examples:
            >>> service = MountService(8080)
        """
        self.port = port
        self.server: Optional[asyncio.Server] = None
        self.thread: Optional[threading.Thread] = None
        self.running = False
        self._lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def start(self) -> None:
        """Start the QUIC receive service.

        Creates a QUIC server, binds it to the port, and starts a
        background thread that accepts connections and decodes packets.

        Examples:
            >>> service = MountService(8080)
            >>> service.start()
            >>> # Service is now running and accepting QUIC connections
        """
        with self._lock:
            if self.running:
                logging.warning("[NCP] MountService is already running")
                return

            try:
                # TLS 1.3 on QUIC: load cert and key from ~/.usmd
                cert_dir = os.path.expanduser("~/.usmd")
                cert_file = os.path.join(cert_dir, "node.crt")
                key_file = os.path.join(cert_dir, "node.key")

                configuration = QuicConfiguration(is_client=False)
                configuration.load_cert_chain(cert_file, key_file)
                configuration.idle_timeout = 60.0

                # Create event loop for QUIC server
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)

                # Start QUIC server
                self.running = True
                self.thread = threading.Thread(
                    target=self._run, args=(configuration,), daemon=True
                )
                self.thread.start()
                logging.info(
                    "[NCP] MountService started: listening on QUIC port %d",
                    self.port,
                )
            except (OSError, RuntimeError) as e:
                logging.error("[NCP] Failed to start MountService: %s", e)
                self.running = False
                if self._loop:
                    self._loop.close()
                    self._loop = None

    def stop(self) -> None:
        """Stop the QUIC service.

        Stops the background thread and closes the QUIC server.

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
                if self.server:
                    self._loop.call_soon_threadsafe(self.server.close)

            if self.thread:
                self.thread.join(timeout=5.0)
                self.thread = None

            if self._loop:
                self._loop.close()
                self._loop = None

            logging.info("[NCP] MountService stopped")

    def _run(self, configuration: QuicConfiguration) -> None:
        """Main service loop running in background thread.

        Starts the QUIC server and handles incoming connections.
        """
        asyncio.set_event_loop(self._loop)

        async def create_protocol(*args, **kwargs):
            return NCPProtocol(*args, decode_callback=self._decode_packet, **kwargs)

        async def run_server():
            self.server = await serve(
                "0.0.0.0",
                self.port,
                configuration=configuration,
                create_protocol=create_protocol,
            )
            while self.running:
                await asyncio.sleep(0.1)

        try:
            self._loop.run_until_complete(run_server())
        except (OSError, RuntimeError) as e:
            if self.running:
                logging.error("[NCP] Error in MountService loop: %s", e)

    def _decode_packet(
        self, packet_bytes: bytes, addr: tuple[str, int]
    ) -> Result[None, Error]:
        """Decode an NCP packet from bytes.

        Converts bytes to BitVec, decodes the frame structure, and then decodes
        the NCP packet data. No encryption/decryption is performed as this is
        unencrypted QUIC.

        Args:
            packet_bytes: The raw QUIC stream data bytes to decode
            addr: The address of the sender

        Returns:
            Result[None, Error]: Ok(None) if packet was decoded successfully,
                               Err(Error) if decoding failed

        Examples:
            >>> service = MountService(8080)
            >>> result = service._decode_packet(b'\\x01\\x00\\x01...', ("127.0.0.1", 8080))
            >>> if result.is_ok():
            ...     print("Packet decoded successfully")
        """
        try:
            # Convert bytes to BitVec with MSB ordering (same as client)
            bitvec = BitVec.from_bytes(packet_bytes, Msb)

            # Create bit decoder
            bit_decoder = BitDecoder[Msb](bitvec)

            # Decode the frame structure
            frame_decoder = FrameDecoder[Msb](bit_decoder)
            frame_result = frame_decoder.decode()
            if frame_result.is_err():
                return Result.Err(frame_result.unwrap_err())

            frame: Frame[Msb] = frame_result.unwrap()

            # Check if this is a HIA packet (event ID 0x0001)
            if frame.event != 0x0001:
                return Result.Err(
                    Error.new(
                        ErrorKind.PROTOCOL_ERROR,
                        f"Unexpected event ID: {frame.event:#06x}",
                    )
                )

            # Create a new decoder from the frame data for HIA decoding
            data_decoder = BitDecoder[Msb](frame.data)
            here_i_am_decoder = HereIAmDecoder(data_decoder)
            # TLS encrypts transport; pub_key for app-level auth is not used here
            decode_result = here_i_am_decoder.decode(b"", addr[0], frame=frame)
            if decode_result.is_err():
                return Result.Err(decode_result.unwrap_err())

            logging.debug(
                "[NCP] Successfully decoded NCP packet (version=%d, event=%d, "
                "data_size=%d)",
                frame.version,
                frame.event,
                frame.data_size,
            )

            return Result.Ok(None)
        except (OSError, RuntimeError, ValueError) as e:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"Failed to decode packet: {str(e)}",
                )
            )

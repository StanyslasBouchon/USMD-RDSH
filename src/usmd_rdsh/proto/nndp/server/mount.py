"""UDP service for receiving and decoding Here I Am packets.

This module provides a UDP service that listens for Here I Am packets on a
specified port, decodes them, and publishes events when packets are received.
"""

import logging
import socket
import threading
from typing import Optional

from usmd_rdsh.proto.base.bitvec import BitVec, Msb
from usmd_rdsh.proto.base.decoder import BitDecoder, Frame, FrameDecoder
from usmd_rdsh.proto.nndp.server.packets.here_i_am import HereIAmDecoder
from usmd_rdsh.security.ed25519 import Ed25519KeyPair
from usmd_rdsh.utils.errors import Error, ErrorKind
from usmd_rdsh.utils.result import Result


class MountService:
    """UDP service for receiving and decoding Here I Am packets.

    This service creates a UDP socket that listens for Here I Am packets on a
    specified port. It decodes incoming packets and publishes events when valid
    packets are received from a specific source port. The service runs in a
    separate thread and can be started and stopped as needed.

    Attributes:
        receive_port (int): The UDP port for receiving packets (socket will bind to this)
        source_port (int): The expected source port for incoming packets
        socket (Optional[socket.socket]): The UDP socket instance
        thread (Optional[threading.Thread]): The service thread
        running (bool): Flag indicating if the service is running

    Examples:
        >>> service = MountService(8080, 8081)
        >>> service.start()
        >>> # Service is now listening for packets
        >>> service.stop()
    """

    def __init__(self, receive_port: int, source_port: int) -> None:
        """Initialize the mount service.

        Args:
            receive_port: The UDP port to listen on (inverse of client send_port)
            source_port: The expected source port for incoming packets
                        (inverse of client receive_port)

        Examples:
            >>> service = MountService(8080, 8081)
        """
        self.receive_port = receive_port
        self.source_port = source_port
        self.socket: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.running = False
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the UDP receive service.

        Creates a UDP socket, binds it to the receive port, and starts a
        background thread that listens for and decodes incoming packets.

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
                self.socket.bind(("", self.receive_port))
                self.running = True
                self.thread = threading.Thread(target=self._run, daemon=True)
                self.thread.start()
                logging.info(
                    "[NNDP] MountService started: listening on port %d for packets "
                    "from source port %d",
                    self.receive_port,
                    self.source_port,
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

    def _run(self) -> None:
        """Main service loop running in background thread.

        Continuously listens for incoming UDP packets, validates the source port,
        and decodes valid Here I Am packets.
        """
        if not self.socket:
            return

        while self.running:
            try:
                # Receive packet with timeout to allow checking running flag
                self.socket.settimeout(1.0)
                try:
                    data, addr = self.socket.recvfrom(65507)  # Max UDP size
                    _, source_port = addr

                    # Check if packet comes from expected source port
                    if source_port != self.source_port:
                        logging.debug(
                            "[NNDP] Received packet from unexpected source port %d "
                            "(expected %d), ignoring",
                            source_port,
                            self.source_port,
                        )
                        continue

                    # Decode the packet
                    result = self._decode_packet(data)
                    if result.is_err():
                        error = result.unwrap_err()
                        logging.warning(
                            "[NNDP] Failed to decode Here I Am packet: %s",
                            error.message,
                        )
                except socket.timeout:
                    # Timeout is expected, continue loop to check running flag
                    continue
            except (OSError, RuntimeError) as e:
                if self.running:
                    logging.error("[NNDP] Error in MountService loop: %s", e)

    def _decode_packet(self, packet_bytes: bytes) -> Result[None, Error]:
        """Decode a Here I Am packet from bytes.

        Converts bytes to BitVec, decodes the frame structure, and then decodes
        the Here I Am packet data.

        Args:
            packet_bytes: The raw UDP packet bytes to decode

        Returns:
            Result[None, Error]: Ok(None) if packet was decoded successfully,
                               Err(Error) if decoding failed

        Examples:
            >>> service = MountService(8080, 8081)
            >>> service.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            >>> result = service._decode_packet(b'\\x01\\x00\\x01...')
            >>> if result.is_ok():
            ...     print("Packet decoded successfully")
        """
        try:
            pub_key = packet_bytes[:32]
            signed_packet = packet_bytes[32:]

            verify_result = Ed25519KeyPair.verify(pub_key, signed_packet)
            if verify_result.is_err():
                return Result.Err(verify_result.unwrap_err())

            # Convert bytes to BitVec with MSB ordering (same as client)
            bitvec = BitVec.from_bytes(verify_result.unwrap(), Msb)

            # Create bit decoder
            bit_decoder = BitDecoder[Msb](bitvec)

            # Decode the frame structure
            frame_decoder = FrameDecoder[Msb](bit_decoder)
            frame_result = frame_decoder.decode()
            if frame_result.is_err():
                return Result.Err(frame_result.unwrap_err())

            frame: Frame[Msb] = frame_result.unwrap()

            # Check if this is a Here I Am packet (event ID 0x0001)
            if frame.event != 0x0001:
                return Result.Err(
                    Error.new(
                        ErrorKind.PROTOCOL_ERROR,
                        f"Unexpected event ID: {frame.event:#06x}",
                    )
                )

            # Create a new decoder from the frame data for Here I Am decoding
            data_decoder = BitDecoder[Msb](frame.data)
            here_i_am_decoder = HereIAmDecoder(data_decoder)
            decode_result = here_i_am_decoder.decode(frame)
            if decode_result.is_err():
                return Result.Err(decode_result.unwrap_err())

            logging.debug(
                "[NNDP] Successfully decoded Here I Am packet (version=%d, event=%d, "
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

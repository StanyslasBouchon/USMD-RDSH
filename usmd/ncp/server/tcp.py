"""NCP TCP server for USMD-RDSH.

Listens on TCP port 5626 (configurable). For each incoming connection it:
1. Reads the 9-byte NCP header.
2. Reads the payload (length encoded in the header).
3. Dispatches to NcpCommandHandler.handle().
4. Writes the response frame.
5. Closes the connection.

Examples:
    >>> handler = object()  # placeholder NcpCommandHandler
    >>> server = NcpServer(handler, port=5626, timeout=5.0)
    >>> isinstance(server, NcpServer)
    True
"""

import asyncio
import logging
import struct
from typing import Optional

from ..protocol.frame import NcpFrame
from .handler import NcpCommandHandler

logger = logging.getLogger(__name__)

_HEADER_SIZE = 9  # 4 version + 1 command + 4 payload-length
_PAYLOAD_LEN_OFFSET = 5  # offset inside the header where uint32 payload-length sits
_MAX_PAYLOAD = 1 << 20  # 1 MiB safety cap


class NcpServer:
    """Asyncio TCP server that accepts NCP connections.

    One NcpCommandHandler instance is shared across all connections so that
    all handlers see the same node state.

    Attributes:
        port: TCP port to listen on. Default: 5626.
        timeout: Per-read timeout in seconds. Default: 5.0.

    Examples:
        >>> srv = NcpServer.__new__(NcpServer)
        >>> isinstance(srv, NcpServer)
        True
    """

    def __init__(
        self,
        handler: NcpCommandHandler,
        host: str = "0.0.0.0",
        port: int = 5626,
        timeout: float = 5.0,
    ) -> None:
        """Initialise the server.

        Args:
            handler: Command handler instance.
            host: Interface to bind. Default: all interfaces.
            port: TCP port. Default: 5626.
            timeout: Per-connection read timeout. Default: 5.0 s.
        """
        self._handler = handler
        self._host = host
        self._port = port
        self._timeout = timeout
        self._server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        """Bind the TCP socket and start accepting connections."""
        self._server = await asyncio.start_server(
            self._handle_connection,
            host=self._host,
            port=self._port,
        )
        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP server listening on TCP %s:%d",
            self._host,
            self._port,
        )

    def close(self) -> None:
        """Stop accepting new connections."""
        if self._server is not None:
            self._server.close()
            logger.info("[\x1b[38;5;51mUSMD\x1b[0m] NCP server closed")

    async def serve_forever(self) -> None:
        """Run the server until cancelled."""
        if self._server is None:
            await self.start()
        async with self._server:
            await self._server.serve_forever()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername", ("?", 0))
        ip, port = peer[0], peer[1]
        logger.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP connection from %s:%d",
            ip,
            port,
        )

        try:
            frame_result = await self._read_frame(reader, ip)
            if frame_result is None:
                return

            response = self._handler.handle(frame_result)
            writer.write(response.to_bytes())
            await writer.drain()

        except (ConnectionResetError, BrokenPipeError) as exc:
            logger.debug(
                "[\x1b[38;5;51mUSMD\x1b[0m] NCP connection from %s:%d lost: %s",
                ip,
                port,
                exc,
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def _read_frame(
        self,
        reader: asyncio.StreamReader,
        peer_ip: str,
    ) -> Optional[NcpFrame]:
        """Read a complete NCP frame from the stream."""
        # Step 1: header
        try:
            header = await asyncio.wait_for(
                reader.readexactly(_HEADER_SIZE),
                timeout=self._timeout,
            )
        except asyncio.IncompleteReadError:
            logger.debug(
                "[\x1b[38;5;51mUSMD\x1b[0m] NCP %s closed before header", peer_ip
            )
            return None
        except asyncio.TimeoutError:
            logger.debug("[\x1b[38;5;51mUSMD\x1b[0m] NCP %s header timeout", peer_ip)
            return None

        # Extract payload length
        (payload_len,) = struct.unpack_from("!L", header, _PAYLOAD_LEN_OFFSET)
        if payload_len > _MAX_PAYLOAD:
            logger.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] NCP %s payload too large: %d bytes",
                peer_ip,
                payload_len,
            )
            return None

        # Step 2: payload
        if payload_len > 0:
            try:
                payload = await asyncio.wait_for(
                    reader.readexactly(payload_len),
                    timeout=self._timeout,
                )
            except (asyncio.IncompleteReadError, asyncio.TimeoutError) as exc:
                logger.debug(
                    "[\x1b[38;5;51mUSMD\x1b[0m] NCP %s payload read failed: %s",
                    peer_ip,
                    exc,
                )
                return None
        else:
            payload = b""

        # Step 3: parse
        frame_result = NcpFrame.from_bytes(header + payload)
        if frame_result.is_err():
            logger.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] NCP %s bad frame: %s",
                peer_ip,
                frame_result.unwrap_err(),
            )
            return None

        frame = frame_result.unwrap()
        logger.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP ← %s cmd=%s payload=%d bytes",
            peer_ip,
            frame.command_id.name,
            len(frame.payload),
        )
        return frame

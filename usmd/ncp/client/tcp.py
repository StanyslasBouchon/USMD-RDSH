"""NCP TCP client for USMD-RDSH.

Opens a short-lived TCP connection to a remote node, sends one NCP frame,
reads the response frame, then closes the connection.

Examples:
    >>> client = NcpClient("10.0.0.5", port=5626, timeout=5.0)
    >>> # result = await client.send(NcpCommandId.GET_STATUS, b"")
"""

import asyncio
import logging
import struct
from typing import Optional

from ..protocol.frame import (
    NCP_LOG_ARROW_IN,
    NCP_LOG_ARROW_OUT,
    NcpCommandId,
    NcpFrame,
    format_ncp_cmd_for_log,
)
from ..protocol.versions import NcpVersion
from ...utils.errors import Error, ErrorKind
from ...utils.io import close_stream_writer
from ...utils.result import Result

# Current NCP version this node speaks
_VERSION = NcpVersion(1, 0, 0, 0)

# Header: 4 bytes version + 1 byte command + 4 bytes payload length
_HEADER_SIZE = 9
_PAYLOAD_LEN_OFFSET = 5  # offset of the uint32 payload length inside the header


class NcpClient:
    """Async TCP client that sends a single NCP command and reads the response.

    Each call to :meth:`send` opens a fresh TCP connection, transmits the
    request frame, reads the response frame, then closes the connection.
    This keeps the implementation stateless and avoids connection reuse bugs.

    Attributes:
        address: IPv4/IPv6 address of the remote node.
        port: TCP port of the remote NCP server. Default: 5626.
        timeout: Per-operation timeout in seconds. Default: 5.0.

    Examples:
        >>> c = NcpClient("127.0.0.1", port=5626, timeout=3.0)
        >>> c.address
        '127.0.0.1'
    """

    def __init__(
        self,
        address: str,
        port: int = 5626,
        timeout: float = 5.0,
    ) -> None:
        """Initialise the client.

        Args:
            address: IP address of the remote NCP server.
            port: TCP port. Defaults to the spec-defined 5626.
            timeout: Seconds to wait for connection and each read. Default: 5.
        """
        self.address = address
        self.port = port
        self.timeout = timeout

    async def send(
        self,
        command_id: NcpCommandId,
        payload: bytes,
    ) -> Result[NcpFrame, Error]:
        """Send one NCP frame and return the response frame.

        Args:
            command_id: The command to send.
            payload: Raw payload bytes for the command.

        Returns:
            Result[NcpFrame, Error]: Parsed response frame or connection/parse error.

        Example:
            >>> c = NcpClient.__new__(NcpClient)
            >>> isinstance(c, NcpClient)
            True
        """
        request_frame = NcpFrame(
            version=_VERSION,
            command_id=command_id,
            payload=payload,
        )
        raw_request = request_frame.to_bytes()

        logging.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] NCP %s %s:%d cmd=%s payload=%d bytes",
            NCP_LOG_ARROW_OUT,
            self.address,
            self.port,
            format_ncp_cmd_for_log(command_id),
            len(payload),
        )

        reader: Optional[asyncio.StreamReader] = None
        writer: Optional[asyncio.StreamWriter] = None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.address, self.port),
                timeout=self.timeout,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            return Result.Err(
                Error.new(
                    ErrorKind.CONNECTION_ERROR,
                    f"NCP connect to {self.address}:{self.port} failed: {exc}",
                )
            )

        try:
            # Send request
            writer.write(raw_request)
            await writer.drain()

            # Read response header (exactly 9 bytes)
            try:
                header_bytes = await asyncio.wait_for(
                    reader.readexactly(_HEADER_SIZE),
                    timeout=self.timeout,
                )
            except (asyncio.IncompleteReadError, asyncio.TimeoutError) as exc:
                return Result.Err(
                    Error.new(
                        ErrorKind.CONNECTION_ERROR,
                        f"NCP read header from {self.address} failed: {exc}",
                    )
                )

            # Extract payload length from header
            (payload_len,) = struct.unpack_from(
                "!L", header_bytes, _PAYLOAD_LEN_OFFSET
            )

            # Read response payload
            if payload_len > 0:
                try:
                    payload_bytes = await asyncio.wait_for(
                        reader.readexactly(payload_len),
                        timeout=self.timeout,
                    )
                except (asyncio.IncompleteReadError, asyncio.TimeoutError) as exc:
                    return Result.Err(
                        Error.new(
                            ErrorKind.CONNECTION_ERROR,
                            f"NCP read payload from {self.address} failed: {exc}",
                        )
                    )
            else:
                payload_bytes = b""

            response_result = NcpFrame.from_bytes(header_bytes + payload_bytes)
            if response_result.is_ok():
                logging.debug(
                    "[\x1b[38;5;51mUSMD\x1b[0m] NCP %s %s cmd=%s payload=%d bytes",
                    NCP_LOG_ARROW_IN,
                    self.address,
                    format_ncp_cmd_for_log(response_result.unwrap().command_id),
                    len(payload_bytes),
                )
            return response_result

        finally:
            if writer is not None:
                await close_stream_writer(writer)

"""Control socket server for USMD-RDSH node introspection.

On **Linux / macOS** a Unix-domain socket is created at *socket_path*.
On **Windows** a TCP server is started on ``127.0.0.1:ctl_port`` instead
(Unix-domain sockets require a third-party driver on Windows).

Protocol (newline-delimited JSON):
    Request  → {"cmd": "status"}
    Response ← {<full status snapshot>}

Examples:
    >>> srv = CtlServer.__new__(CtlServer)
    >>> isinstance(srv, CtlServer)
    True
"""

import asyncio
import json
import logging
import os
import sys
from typing import Callable, Optional

from ..utils.io import close_writer

logger = logging.getLogger(__name__)


class CtlServer:  # pylint: disable=too-few-public-methods
    """Asyncio control server that serves node status snapshots on demand.

    On Linux/macOS a Unix-domain socket is used.  On Windows a TCP loopback
    server is used on the configured *ctl_port* instead.

    The server accepts a single JSON command per connection and immediately
    responds with the result of *snapshot_fn*, then closes the connection.

    Attributes:
        socket_path: Filesystem path of the Unix-domain socket (Linux only).
        ctl_port: TCP port used on Windows (0 = OS assigns a free port).

    Examples:
        >>> srv = CtlServer.__new__(CtlServer)
        >>> isinstance(srv, CtlServer)
        True
    """

    def __init__(
        self,
        socket_path: str,
        snapshot_fn: Callable[[], dict],
        ctl_port: int = 0,
    ) -> None:
        """Initialise the control server.

        Args:
            socket_path: Path at which the Unix socket will be created
                (ignored on Windows).
            snapshot_fn: Zero-argument callable that returns the status dict.
            ctl_port: TCP port for the loopback server on Windows.
                0 = let the OS pick a free port.
        """
        self.socket_path = socket_path
        self.ctl_port = ctl_port
        self._snapshot_fn = snapshot_fn
        self._server: Optional[asyncio.AbstractServer] = None
        # Actual TCP port chosen by the OS (updated after start on Windows)
        self.actual_port: int = ctl_port

    async def start(self) -> None:
        """Bind the server and start accepting clients.

        On Linux/macOS: creates parent directories if necessary, removes any
        stale socket file, then listens on the Unix-domain socket (mode 0o666).
        On Windows: starts a TCP loopback server on 127.0.0.1:ctl_port.

        Raises:
            OSError: If the socket / TCP server cannot be created.
        """
        if sys.platform == "win32":
            await self._start_tcp()
        else:
            await self._start_unix()

    async def _start_unix(self) -> None:
        """Start a Unix-domain socket server (Linux / macOS)."""
        # Remove stale socket from a previous crash
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass

        parent = os.path.dirname(self.socket_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

        self._server = await asyncio.start_unix_server(
            self._handle_client,
            path=self.socket_path,
        )
        # Allow any local user to query (status is read-only)
        os.chmod(self.socket_path, 0o666)

        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] CTL socket ready: %s",
            self.socket_path,
        )

    async def _start_tcp(self) -> None:
        """Start a TCP loopback server (Windows)."""
        self._server = await asyncio.start_server(
            self._handle_client,
            host="127.0.0.1",
            port=self.ctl_port,
        )
        # Retrieve the actual port chosen by the OS (when ctl_port == 0)
        socks = self._server.sockets
        if socks:
            self.actual_port = socks[0].getsockname()[1]

        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] CTL TCP ready: 127.0.0.1:%d",
            self.actual_port,
        )

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single control connection."""
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=5.0)
            try:
                request = json.loads(line.decode().strip())
            except json.JSONDecodeError:
                response: dict = {"error": "Invalid JSON request"}
            else:
                cmd = request.get("cmd", "")
                if cmd == "status":
                    response = self._snapshot_fn()
                else:
                    response = {"error": f"Unknown command: {cmd!r}"}

            writer.write((json.dumps(response) + "\n").encode())
            await writer.drain()

        except (asyncio.TimeoutError, OSError):
            pass
        finally:
            close_writer(writer)

    def close(self) -> None:
        """Close the server and (on Linux) remove the socket file."""
        if self._server is not None:
            self._server.close()
        if sys.platform != "win32":
            try:
                os.unlink(self.socket_path)
            except FileNotFoundError:
                pass

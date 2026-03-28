"""Control socket server for USMD-RDSH node introspection.

Listens on a Unix-domain socket and answers JSON status requests from
the CLI or any local tool, without requiring network exposure.

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
from typing import Callable

logger = logging.getLogger(__name__)


class CtlServer:  # pylint: disable=too-few-public-methods
    """Asyncio Unix-socket server that serves node status snapshots on demand.

    The server accepts a single JSON command per connection and immediately
    responds with the result of *snapshot_fn*, then closes the connection.

    Attributes:
        socket_path: Filesystem path of the Unix-domain socket.

    Examples:
        >>> srv = CtlServer.__new__(CtlServer)
        >>> isinstance(srv, CtlServer)
        True
    """

    def __init__(
        self,
        socket_path: str,
        snapshot_fn: Callable[[], dict],
    ) -> None:
        """Initialise the control server.

        Args:
            socket_path: Path at which the Unix socket will be created.
            snapshot_fn: Zero-argument callable that returns the status dict.
        """
        self.socket_path = socket_path
        self._snapshot_fn = snapshot_fn
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        """Bind the Unix socket and start accepting clients.

        Creates parent directories if necessary and removes any stale socket
        file left over from a previous run.  The socket is made world-readable
        (mode 0o666) so any local user can query the running daemon.

        Raises:
            NotImplementedError: On Windows, where Unix sockets are unavailable.
        """
        if sys.platform == "win32":
            raise NotImplementedError(
                "Le socket CTL Unix n'est pas disponible sur Windows. "
                "Déployez le nœud sur Linux."
            )

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
            try:
                writer.close()
            except OSError:
                pass

    def close(self) -> None:
        """Close the server and remove the socket file."""
        if self._server is not None:
            self._server.close()
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass

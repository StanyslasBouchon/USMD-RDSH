"""USMD-RDSH web dashboard server.

Runs a Django ASGI application via uvicorn inside the existing asyncio event
loop.  HTTPS is enabled by default: if ssl_cert / ssl_key paths are provided
in the config, those certificates are used; otherwise a self-signed certificate
is generated at startup (requires openssl on PATH).

If neither a valid certificate nor openssl is available, the server falls back
to plain HTTP.

Usage::

    server = WebServer(cfg, snapshot_fn, nit)
    # In NodeDaemon.run():
    web_task = asyncio.create_task(server.start(), name="web-server")
    # In NodeDaemon finally:
    server.close()

Examples:
    >>> srv = WebServer.__new__(WebServer)
    >>> isinstance(srv, WebServer)
    True
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

from .settings import configure as _configure_django
from .state import WebState, set_state

if TYPE_CHECKING:
    from ..config import NodeConfig
    from ..domain.usd import UnifiedSystemDomain
    from ..node.nit import NodeIdentityTable

logger = logging.getLogger(__name__)


class _Win32ProactorResetFilter(
    logging.Filter
):
    """Suppress harmless WinError 10054 from the asyncio proactor on Windows.

    When a browser closes a connection abruptly, the proactor transport logs a
    ConnectionResetError at ERROR level. This filter drops those records by
    inspecting the attached exception, not just the message text.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if record.exc_info:
            exc = record.exc_info[1]
            if isinstance(exc, ConnectionResetError):
                return False
        return True


class WebServer:
    """Asyncio-compatible web server wrapping Django + uvicorn.

    Attributes:
        cfg: NodeConfig (``cfg.web.host``, ``cfg.web.port``, credentials, etc.).

    Examples:
        >>> srv = WebServer.__new__(WebServer)
        >>> isinstance(srv, WebServer)
        True
    """

    def __init__(
        self,
        cfg: "NodeConfig",
        snapshot_fn: Callable[[], dict],
        nit: "NodeIdentityTable",
        usd: "UnifiedSystemDomain",
        on_ncp_failure: Optional[Callable[[str], None]] = None,
    ) -> None:
        """Initialise the web server.

        Args:
            cfg: Node configuration (web_* fields).
            snapshot_fn: Returns the local node's status snapshot dict.
            nit: Live NodeIdentityTable for peer discovery.
            usd: Live UnifiedSystemDomain used to check node states before polling.
            on_ncp_failure: Optional callback invoked with a peer's address when
                an outgoing NCP REQUEST_SNAPSHOT to that peer fails.
        """
        self._cfg = cfg
        self._snapshot_fn = snapshot_fn
        self._nit = nit
        self._usd = usd
        self._on_ncp_failure = on_ncp_failure
        self._uvicorn_server: Optional[object] = None
        self._cleanup: contextlib.ExitStack = contextlib.ExitStack()
        self._mutation_apply_fn: Optional[Callable[..., object]] = None

    # ------------------------------------------------------------------
    # SSL / TLS helpers
    # ------------------------------------------------------------------

    def _resolve_ssl(self) -> tuple[Optional[str], Optional[str]]:
        """Return (cert_path, key_path) or (None, None) for plain HTTP.

        Priority:
        1. Explicit paths in config (must both exist).
        2. Auto-generate self-signed cert via openssl.
        3. Fall back to HTTP (None, None).
        """
        cert = self._cfg.web.ssl_cert
        key = self._cfg.web.ssl_key

        if cert and key and Path(cert).is_file() and Path(key).is_file():
            logger.info("[\x1b[38;5;51mUSMD\x1b[0m] Web: using TLS cert %s", cert)
            return cert, key

        # Try to generate a self-signed cert
        try:
            tmp = self._cleanup.enter_context(
                tempfile.TemporaryDirectory(prefix="usmd_tls_")
            )
            cert_path = os.path.join(tmp, "cert.pem")
            key_path = os.path.join(tmp, "key.pem")
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-keyout",
                    key_path,
                    "-out",
                    cert_path,
                    "-days",
                    "3650",
                    "-nodes",
                    "-subj",
                    "/CN=usmd-dashboard/O=USMD-RDSH",
                ],
                check=True,
                capture_output=True,
            )
            logger.info(
                "[\x1b[38;5;51mUSMD\x1b[0m] Web: self-signed TLS cert generated"
            )
            return cert_path, key_path
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] Web: openssl not found — "
                "starting without TLS (HTTP only)"
            )
            self._cleanup.close()
            self._cleanup = contextlib.ExitStack()
            return None, None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Configure Django, set shared state, and run uvicorn.

        This coroutine blocks until the server is shut down (via close()).

        Raises:
            ImportError: If uvicorn or Django are not installed.
        """
        try:
            import uvicorn
        except ImportError as exc:
            raise ImportError(
                "uvicorn is required for the web dashboard: pip install uvicorn"
            ) from exc

        # 1. Configure Django settings
        _configure_django(
            username=self._cfg.web.username,
            password=self._cfg.web.password,
            secret_key=secrets.token_hex(32),
        )

        # 2. Initialise Django
        import django

        if not django.conf.settings.configured:
            pass  # Already done above
        try:
            django.setup()
        except RuntimeError:
            pass  # setup() called more than once — safe to ignore

        # 3. Register shared web state
        set_state(
            WebState(
                snapshot_fn=self._snapshot_fn,
                nit=self._nit,
                usd=self._usd,
                ncp_port=self._cfg.ncp_port,
                cfg=self._cfg,
                on_ncp_failure=self._on_ncp_failure,
                mutation_apply_fn=self._mutation_apply_fn,
            )
        )

        # 4. Resolve TLS — subprocess.run() is blocking; run it in a thread
        loop = asyncio.get_running_loop()
        cert, key = await loop.run_in_executor(None, self._resolve_ssl)

        # 5. Build ASGI app
        from django.core.asgi import (
            get_asgi_application,
           )
        app = get_asgi_application()
        config = uvicorn.Config(
            app=app,
            host=self._cfg.web.host,
            port=self._cfg.web.port,
            ssl_certfile=cert,
            ssl_keyfile=key,
            log_level="warning",
        )

        # Recent uvicorn wraps ``serve()`` with ``capture_signals()`` which calls
        # ``signal.signal(SIGINT, handle_exit)``: Ctrl+C no longer reaches
        # ``KeyboardInterrupt`` or the parent ``daemon.run()`` task.
        # Older versions use ``install_signal_handlers``.
        class _EmbeddedUvicornServer(uvicorn.Server):
            @contextlib.contextmanager
            def capture_signals(self):  # type: ignore[override]
                """Do not register uvicorn SIGINT/SIGTERM handlers (parent owns signals)."""
                yield

            def install_signal_handlers(self) -> None:
                """No-op: parent daemon must receive SIGINT, not uvicorn."""

        self._uvicorn_server = _EmbeddedUvicornServer(config)

        await self._uvicorn_server.serve()

    def set_mutation_apply_fn(self, fn: Optional[Callable[..., object]]) -> None:
        """Register async callback for dashboard mutation publish (usd_operator)."""
        self._mutation_apply_fn = fn

    def close(self) -> None:
        """Signal the uvicorn server to stop."""
        srv = self._uvicorn_server
        if srv is not None:
            setattr(srv, "should_exit", True)

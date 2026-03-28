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

import logging
import os
import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from ..config import NodeConfig
    from ..node.nit import NodeIdentityTable

logger = logging.getLogger(__name__)


class WebServer:  # pylint: disable=too-few-public-methods
    """Asyncio-compatible web server wrapping Django + uvicorn.

    Attributes:
        cfg: NodeConfig containing web_host, web_port, credentials, etc.

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
    ) -> None:
        """Initialise the web server.

        Args:
            cfg: Node configuration (web_* fields).
            snapshot_fn: Returns the local node's status snapshot dict.
            nit: Live NodeIdentityTable for peer discovery.
        """
        self._cfg = cfg
        self._snapshot_fn = snapshot_fn
        self._nit = nit
        self._uvicorn_server: Optional[object] = None
        self._tmp_cert_dir: Optional[tempfile.TemporaryDirectory] = None  # type: ignore[type-arg]

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
        cert = self._cfg.web_ssl_cert
        key = self._cfg.web_ssl_key

        if cert and key and Path(cert).is_file() and Path(key).is_file():
            logger.info(
                "[\x1b[38;5;51mUSMD\x1b[0m] Web: using TLS cert %s", cert
            )
            return cert, key

        # Try to generate a self-signed cert
        try:
            self._tmp_cert_dir = tempfile.TemporaryDirectory(  # pylint: disable=consider-using-with
                prefix="usmd_tls_"
            )
            tmp = self._tmp_cert_dir.name
            cert_path = os.path.join(tmp, "cert.pem")
            key_path = os.path.join(tmp, "key.pem")
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", key_path, "-out", cert_path,
                    "-days", "3650", "-nodes",
                    "-subj", "/CN=usmd-dashboard/O=USMD-RDSH",
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
            if self._tmp_cert_dir:
                self._tmp_cert_dir.cleanup()
                self._tmp_cert_dir = None
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
            import uvicorn  # pylint: disable=import-outside-toplevel
        except ImportError as exc:
            raise ImportError(
                "uvicorn is required for the web dashboard: pip install uvicorn"
            ) from exc

        # 1. Configure Django settings
        from .settings import configure  # pylint: disable=import-outside-toplevel
        configure(
            username=self._cfg.web_username,
            password=self._cfg.web_password,
            secret_key=secrets.token_hex(32),
        )

        # 2. Initialise Django
        import django  # pylint: disable=import-outside-toplevel
        if not django.conf.settings.configured:
            pass  # Already done above
        try:
            django.setup()
        except RuntimeError:
            pass  # setup() called more than once — safe to ignore

        # 3. Register shared web state
        from .state import WebState, set_state  # pylint: disable=import-outside-toplevel
        set_state(
            WebState(
                snapshot_fn=self._snapshot_fn,
                nit=self._nit,
                ncp_port=self._cfg.ncp_port,
                cfg=self._cfg,
            )
        )

        # 4. Resolve TLS
        cert, key = self._resolve_ssl()
        scheme = "https" if cert else "http"

        # 5. Build ASGI app
        from django.core.asgi import get_asgi_application  # pylint: disable=import-outside-toplevel
        asgi_app = get_asgi_application()

        # 6. Start uvicorn
        config = uvicorn.Config(
            app=asgi_app,
            host=self._cfg.web_host,
            port=self._cfg.web_port,
            ssl_certfile=cert,
            ssl_keyfile=key,
            log_level="warning",
            access_log=False,
            loop="none",  # Use the running asyncio loop
        )
        self._uvicorn_server = uvicorn.Server(config)

        logger.info(
            "[\x1b[38;5;51mUSMD\x1b[0m] Web dashboard: "
            "%s://%s:%d  (user: %s)",
            scheme,
            self._cfg.web_host if self._cfg.web_host != "0.0.0.0" else "localhost",
            self._cfg.web_port,
            self._cfg.web_username,
        )

        await self._uvicorn_server.serve()

    def close(self) -> None:
        """Signal uvicorn to stop gracefully."""
        if self._uvicorn_server is not None:
            self._uvicorn_server.should_exit = True  # type: ignore[attr-defined]
        if self._tmp_cert_dir is not None:
            try:
                self._tmp_cert_dir.cleanup()
            except OSError:
                pass
            self._tmp_cert_dir = None

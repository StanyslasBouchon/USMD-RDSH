"""The web interface: a dashboard page, the token API, and a web console.

    GET  /                       the single-page dashboard (static/index.html)
    *    /api/v1/...             nan_actions' token API: every action, as JSON
    POST /web/cli                one console line, run as the token's holder
    GET  /web/summary            everything the dashboard draws, in one call

Everything but the page itself needs ``Authorization: Bearer <token>``, minted
at the console with ``execute api-token create``. The console line endpoint is
what makes the web interface able to change everything the console can: it
runs the same shell, with the same configuration tree and the same permission
checks, under the token's own permissions.

Turned on and off by ``config system web-interface`` / ``set status``; the
transport is ``nan_actions.api.http_server.ApiHttpServer`` with its limits,
extended only to serve one HTML page.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import ssl
from dataclasses import dataclass, field
from http import HTTPStatus
from importlib import resources
from typing import TYPE_CHECKING, Any, Mapping
from urllib.parse import urlsplit

from nan_actions import ActionActor, action_is_available
from nan_actions.access import reset_current_action_actor, set_current_action_actor
from nan_actions.api import ApiBindings
from nan_actions.api.dispatcher import ApiDispatcher
from nan_actions.api.http_server import ApiHttpServer
from nan_actions.api.ports import StaticApiSwitch
from nan_actions.api.response import ApiResponse
from nan_actions.api.token import ApiToken
from nan_runtime.log import set_log_sink, reset_log_sink, strip_level_prefix

from usmd_rdsh.cli.confirm import reset_web_confirmation, web_confirmation
from usmd_rdsh.cli.permissions import READ, WRITE
from usmd_rdsh.cli.runtime import RUNTIME

if TYPE_CHECKING:  # pragma: no cover
    from usmd_rdsh.cli.shell import ShellFactory
    from usmd_rdsh.cli.views.system import WebInterfaceConfig

log = logging.getLogger("usmd_rdsh.web")

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


@dataclass(frozen=True, slots=True)
class PageResponse:
    """A non-JSON answer: the dashboard page."""

    status: int
    payload: bytes
    content_type: str
    headers: dict[str, str] = field(default_factory=dict)

    def json_bytes(self) -> bytes:
        """What ``ApiHttpServer`` writes, whatever the type."""
        return self.payload


class _Transport(ApiHttpServer):
    """``ApiHttpServer``, writing the content type the response carries."""

    @staticmethod
    async def _write(writer: asyncio.StreamWriter, response: Any) -> None:
        payload = response.json_bytes()
        try:
            reason = HTTPStatus(response.status).phrase
        except ValueError:
            reason = "Status"
        content_type = getattr(response, "content_type", "application/json")
        head = [
            f"HTTP/1.1 {response.status} {reason}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(payload)}",
            "Connection: close",
            "Cache-Control: no-store",
            "X-Content-Type-Options: nosniff",
            "X-Frame-Options: DENY",
            "Referrer-Policy: no-referrer",
        ]
        head.extend(f"{name}: {value}" for name, value in response.headers.items())
        writer.write(("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + payload)
        await writer.drain()


class _TokenAuthenticator:
    """Binds the token API to the node's token store."""

    async def authenticate(self, token: ApiToken) -> ActionActor | None:
        """The actor a token acts as."""
        return RUNTIME.tokens.actor_for(token)


class WebRouter:
    """Routes one request to the page, the token API or the web console."""

    def __init__(self, shells: "ShellFactory", refresh: int = 5) -> None:
        self._api = ApiDispatcher()
        self._shells = shells
        self.refresh = refresh

    async def handle(  # pylint: disable=too-many-arguments
        self,
        method: str,
        path: str,
        headers: Mapping[str, str],
        body: bytes = b"",
        *,
        client: str | None = None,
    ) -> Any:
        """The answer to one request."""
        route = urlsplit(path).path
        if route.startswith(self._api.prefix):
            return await self._api.handle(method, path, headers, body, client=client)
        if route in ("/", "/index.html") and method == "GET":
            return self._page()
        if route.startswith("/web/"):
            actor = await self._actor(headers)
            if isinstance(actor, ApiResponse):
                return actor
            if route == "/web/summary" and method == "GET":
                return await self._summary(actor)
            if route == "/web/cli" and method == "POST":
                return await self._cli(actor, body)
        return ApiResponse.error(404, "not_found", "Nothing is served here.")

    def _page(self) -> PageResponse:
        html = (
            resources.files("usmd_rdsh.web")
            .joinpath("static/index.html")
            .read_text(encoding="utf-8")
            .replace("{{REFRESH}}", str(self.refresh))
        )
        return PageResponse(
            200,
            html.encode("utf-8"),
            "text/html; charset=utf-8",
            {"Content-Security-Policy": "default-src 'self'; style-src 'self' "
             "'unsafe-inline'; script-src 'self' 'unsafe-inline'"},
        )

    @staticmethod
    async def _actor(headers: Mapping[str, str]) -> ActionActor | ApiResponse:
        lowered = {k.lower(): v for k, v in headers.items()}
        scheme, _, value = lowered.get("authorization", "").partition(" ")
        token = ApiToken.parse(value) if scheme.lower() == "bearer" else None
        actor = RUNTIME.tokens.actor_for(token) if token else None
        if actor is None:
            return ApiResponse.error(401, "invalid_token", "Unknown, revoked or missing token.")
        if not action_is_available([READ], actor):
            return ApiResponse.error(403, "missing_permissions", f"'{READ}' is required.")
        return actor

    async def _summary(self, actor: ActionActor) -> ApiResponse:
        # Imported here: the action modules import the runtime, which this
        # module is imported beside; at call time everything is loaded.
        from usmd_rdsh.cli.actions import (  # pylint: disable=import-outside-toplevel
            nndp,
            show_logging,
            show_system,
            tables,
            web,
        )

        context = set_current_action_actor(actor)
        try:
            logs = await show_logging.show_logging(
                show_logging.ShowLoggingInput(last=200)
            )
            summary = {
                "node": await show_system.show_node(),
                "load": await show_system.show_load(),
                "nndp": await nndp.show_nndp(),
                "neighbors": nndp.neighbor_rows(),
                "nit": tables.nit_rows(),
                "web": await web.show_web_interface(),
                "logs": [{k: v for k, v in r.items() if k != "line"} for r in logs],
                "can_write": action_is_available([WRITE], actor),
                "user": actor.username,
            }
        finally:
            reset_current_action_actor(context)
        return ApiResponse(200, summary)

    async def _cli(self, actor: ActionActor, body: bytes) -> ApiResponse:
        try:
            request = json.loads(body or b"{}")
            line = str(request.get("line", ""))
            confirmed = request.get("confirm") is True
        except (json.JSONDecodeError, AttributeError):
            return ApiResponse.error(400, "bad_request", 'Send {"line": "<command>"}.')
        if "\n" in line or len(line) > 4096:
            return ApiResponse.error(400, "bad_request", "One line, at most 4096 characters.")
        if line.strip().split()[:1] in (["exit"], ["quit"]):
            return ApiResponse(200, {"output": [], "prompt": self._shells.prompt(actor)})

        lines: list[str] = []
        sink = set_log_sink(lambda text: lines.append(_ANSI.sub("", strip_level_prefix(text))))
        answer, confirmation = web_confirmation(confirmed)
        try:
            await self._shells.shell_for(actor).execute_line(line)
        finally:
            reset_web_confirmation(confirmation)
            reset_log_sink(sink)
        log.info("[WEB] %s ran '%s'", actor.username, line)
        return ApiResponse(200, {
            "output": lines,
            "prompt": self._shells.prompt(actor),
            "needs_confirm": answer.asked and not confirmed,
        })


class WebServer:
    """Starts, stops and reconfigures the web interface."""

    def __init__(self, shells: "ShellFactory") -> None:
        self._router = WebRouter(shells)
        self._switch = StaticApiSwitch(False)
        self._server: _Transport | None = None
        self._address: tuple[str, int] | None = None
        self._tls = False
        self._lock = asyncio.Lock()
        ApiBindings.bind(switch=self._switch, authenticator=_TokenAuthenticator())

    @property
    def listening(self) -> bool:
        """Whether a socket is bound."""
        return self._server is not None and self._server.listening

    @property
    def url(self) -> str | None:
        """Where the interface answers."""
        if self._address is None:
            return None
        host, port = self._address
        return f"{'https' if self._tls else 'http'}://{host}:{port}/"

    @property
    def served(self) -> int:
        """Requests answered since the interface was last started."""
        return self._server.served if self._server else 0

    @property
    def rejected(self) -> int:
        """Requests refused by the transport (malformed, too large...)."""
        return self._server.rejected if self._server else 0

    async def reconfigure(self, config: "WebInterfaceConfig") -> None:
        """Apply a committed ``system web-interface``: stop, then start if enabled."""
        async with self._lock:
            self._router.refresh = config.refresh_interval
            await self._stop()
            self._switch.enabled = config.status
            if not config.status:
                log.info("[WEB] Web interface disabled")
                return
            context = None
            if config.tls_certificate:
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(config.tls_certificate, config.tls_private_key)
            server = _Transport(
                self._router,  # type: ignore[arg-type]
                config.listen_address,
                config.port,
                ssl_context=context,
            )
            self._address = await server.start()
            self._server = server
            self._tls = context is not None
            log.warning("[WEB] Web interface listening on %s", self.url)

    async def _stop(self) -> None:
        server, self._server = self._server, None
        self._address = None
        if server is not None:
            await server.stop()

    async def stop(self) -> None:
        """Stop serving, at shutdown."""
        async with self._lock:
            self._switch.enabled = False
            await self._stop()

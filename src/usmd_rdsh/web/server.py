"""The web interface: a dashboard page, the token API, and a web console.

    GET  /                       the single-page dashboard (static/index.html)
    GET  /static/capture.js      its Capture tab (packet list, field tree, bytes)
    *    /api/v1/...             nan_actions' token API: every action, as JSON
    POST /web/cli                one console line, run as the token's holder
                                 (a line ending in ``?`` lists what may follow)
    POST /web/complete           Tab: candidates for the text before the cursor
    GET  /web/summary            everything the dashboard draws, in one call
    GET  /web/config/text        ``which`` = running | startup | full: the
                                 configuration as the console shows it
    POST /web/service-files      keep an uploaded file of a service on the
                                 authority; GET reads one a service names
    GET  /web/shows              every ``show`` of the console and its inputs;
                                 POST runs one (web/shows.py)
    GET  /web/capture            captured frames after ``since`` matching ``filter``;
                                 ``wait`` seconds of long poll for new ones
    GET  /web/capture/<n>        one frame: its field tree and its bytes
    GET  /web/capture/fields     field names a filter may use
    POST /web/capture/clear      empty the capture buffer

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
from urllib.parse import parse_qs, urlsplit

from nan_actions import ActionActor, action_is_available
from nan_actions.access import reset_current_action_actor, set_current_action_actor
from nan_actions.api import ApiBindings
from nan_actions.api.dispatcher import ApiDispatcher
from nan_actions.api.http_server import ApiHttpServer
from nan_actions.api.ports import StaticApiSwitch
from nan_actions.api.response import ApiResponse
from nan_actions.api.token import ApiToken
from nan_runtime.log import set_log_sink, reset_log_sink, strip_level_prefix

from nan_actions.views.errors import ViewError

from usmd_rdsh.cli.confirm import reset_web_confirmation, web_confirmation
from usmd_rdsh.web import config_forms, service_files, shows
from usmd_rdsh.cli.permissions import READ, WRITE
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.node.capture import CAPTURE, FilterError, compile_filter, field_names

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
        self.username = ""
        self.password = ""

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
        if route == "/static/capture.js" and method == "GET":
            script = resources.files("usmd_rdsh.web").joinpath("static/capture.js").read_bytes()
            return PageResponse(200, script, "text/javascript; charset=utf-8")
        if route == "/web/login" and method == "POST":
            return self._login(body, client)
        if route == "/web/login" and method == "GET":
            return ApiResponse(200, {"password_login": bool(self.username)})
        if route.startswith("/web/"):
            actor = await self._actor(headers)
            if isinstance(actor, ApiResponse):
                return actor
            if route == "/web/summary" and method == "GET":
                return await self._summary(actor)
            if route == "/web/cli" and method == "POST":
                return await self._cli(actor, body)
            if route == "/web/complete" and method == "POST":
                return self._complete(actor, body)
            if route == "/web/config" and method == "GET":
                return ApiResponse(200, {**config_forms.schema(actor),
                                         "can_write": action_is_available([WRITE], actor)})
            if route == "/web/config" and method == "POST":
                return await self._config(actor, body)
            if route == "/web/config/text" and method == "GET":
                return await self._config_text(actor, urlsplit(path).query)
            if route == "/web/service-files":
                return self._service_files(actor, method, body, urlsplit(path).query)
            if route == "/web/shows":
                return await self._shows(actor, method, body)
            if route.startswith("/web/capture"):
                return await self._capture(actor, method, route, urlsplit(path).query)
        return ApiResponse.error(404, "not_found", "Nothing is served here.")

    @staticmethod
    async def _capture(actor: ActionActor, method: str, route: str, query: str) -> ApiResponse:
        """The packet list (long poll), one dissected frame, the fields, clearing."""
        params = {k: v[-1] for k, v in parse_qs(query).items()}
        if route == "/web/capture" and method == "GET":
            try:
                flt = compile_filter(params.get("filter"))
                since = max(0, int(params.get("since", 0)))
                wait = min(20.0, max(0.0, float(params.get("wait", 0))))
                limit = min(20000, max(1, int(params.get("limit", 2000))))
            except FilterError as exc:
                return ApiResponse.error(422, "invalid_filter", str(exc))
            except ValueError:
                return ApiResponse.error(400, "bad_request", "since, wait and limit are numbers.")
            await CAPTURE.wait(since, wait)
            return ApiResponse(200, {
                "packets": [p.row() for p in CAPTURE.packets(since=since, flt=flt, last=limit)],
                "last": CAPTURE.last_number,
                "held": CAPTURE.held(),
                "capacity": CAPTURE.capacity,
                "enabled": CAPTURE.enabled,
                "protocols": sorted(CAPTURE.protocols),
                "started": CAPTURE.started,
            })
        if route == "/web/capture/fields" and method == "GET":
            return ApiResponse(200, {"fields": [{"name": n, "label": l}
                                                for n, l in field_names()]})
        if route == "/web/capture/clear" and method == "POST":
            if not action_is_available([WRITE], actor):
                return ApiResponse.error(403, "missing_permissions", f"'{WRITE}' is required.")
            log.info("[WEB] %s cleared the capture buffer", actor.username)
            return ApiResponse(200, {"cleared": CAPTURE.clear()})
        number = route.removeprefix("/web/capture/")
        if method == "GET" and number.isdigit():
            packet = CAPTURE.get(int(number))
            if packet is None:
                return ApiResponse.error(404, "not_found", "Frame no longer in the buffer.")
            return ApiResponse(200, packet.detail())
        return ApiResponse.error(404, "not_found", "Nothing is served here.")

    def _login(self, body: bytes, client: str | None) -> ApiResponse:
        """Username and password of ``system web-interface`` -> a session token."""
        import hmac  # pylint: disable=import-outside-toplevel

        try:
            request = json.loads(body or b"{}")
            username, password = str(request["username"]), str(request["password"])
        except (ValueError, KeyError, TypeError):
            return ApiResponse.error(400, "bad_request", 'Send {"username": .., "password": ..}.')
        allowed = bool(self.username) and hmac.compare_digest(username, self.username) and \
            hmac.compare_digest(password, self.password)
        if not allowed:
            log.warning("[WEB] Failed login for '%s' from %s", username, client)
            return ApiResponse.error(401, "invalid_credentials", "Wrong username or password.")
        token = RUNTIME.tokens.mint_session(username)
        log.info("[WEB] %s logged in from %s", username, client)
        return ApiResponse(200, {"token": token.plaintext})

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
            catalog,
            domain,
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
                "load": show_system.load_view(),
                "nndp": await nndp.show_nndp(),
                "neighbors": nndp.neighbor_rows(),
                "nearest": nndp.nearest_rows(),
                "nit": tables.nit_rows(),
                "table": tables.node_table_rows(),
                "references": (await tables.show_references())["rows"],
                "master": await catalog.show_usd_master(),
                "mutation": await catalog.show_mutation_status(),
                "catalog": catalog.catalog_rows(),
                "sp": await domain.show_sp(),
                "sessions": await domain.show_sp_sessions(),
                "events": (await show_system.show_node_events())[-50:],
                "web": await web.show_web_interface(),
                "logs": [{k: v for k, v in r.items() if k != "line"} for r in logs],
                "can_write": action_is_available([WRITE], actor),
                "user": actor.username,
            }
        finally:
            reset_current_action_actor(context)
        return ApiResponse(200, summary)

    @staticmethod
    async def _config_text(actor: ActionActor, query: str) -> ApiResponse:
        """``show running-config``, ``show startup-config`` or ``show configuration``."""
        from usmd_rdsh.cli.actions import configuration  # pylint: disable=import-outside-toplevel

        shows = {
            "running": configuration.show_running_config,
            "startup": configuration.show_startup_config,
            "full": configuration.show_configuration,
        }
        which = parse_qs(query).get("which", ["running"])[-1]
        if which not in shows:
            return ApiResponse.error(400, "bad_request", "which is running, startup or full.")
        context = set_current_action_actor(actor)
        try:
            result = await shows[which]()
        finally:
            reset_current_action_actor(context)
        return ApiResponse(200, {"which": which, "text": result["text"],
                                 "path": result.get("path")})

    @staticmethod
    def _service_files(actor: ActionActor, method: str, body: bytes, query: str) -> ApiResponse:
        """POST: keep an uploaded file on the authority; GET: read one a service names."""
        try:
            if method == "GET":
                params = {k: v[-1] for k, v in parse_qs(query).items()}
                return ApiResponse(200, service_files.read(params.get("service", ""),
                                                           params.get("path", "")))
            if method != "POST":
                return ApiResponse.error(404, "not_found", "Nothing is served here.")
            if not action_is_available([WRITE], actor):
                return ApiResponse.error(403, "missing_permissions", f"'{WRITE}' is required.")
            try:
                request = json.loads(body or b"{}")
                if not isinstance(request, dict):
                    raise ValueError
            except ValueError:
                return ApiResponse.error(400, "bad_request", "Send a JSON object.")
            saved = service_files.save(request)
        except service_files.UploadError as exc:
            return ApiResponse.error(422, "invalid_input", str(exc))
        log.info("[WEB] %s uploaded %s (%d bytes)", actor.username, saved["path"], saved["size"])
        return ApiResponse(200, saved)

    @staticmethod
    async def _shows(actor: ActionActor, method: str, body: bytes) -> ApiResponse:
        """GET: the ``show`` commands; POST: run one of them."""
        if method == "GET":
            return ApiResponse(200, {"shows": shows.catalog(actor)})
        if method != "POST":
            return ApiResponse.error(404, "not_found", "Nothing is served here.")
        try:
            request = json.loads(body or b"{}")
            cli, args = str(request["cli"]), request.get("args") or {}
            if not isinstance(args, dict):
                raise TypeError
        except (ValueError, KeyError, TypeError, AttributeError):
            return ApiResponse.error(400, "bad_request", 'Send {"cli": "show ...", "args": {}}.')
        try:
            return ApiResponse(200, await shows.run(actor, cli, args))
        except shows.ShowError as exc:
            return ApiResponse.error(exc.status, "refused", str(exc))

    @staticmethod
    async def _config(actor: ActionActor, body: bytes) -> ApiResponse:
        if not action_is_available([WRITE], actor):
            return ApiResponse.error(403, "missing_permissions", f"'{WRITE}' is required.")
        try:
            request = json.loads(body or b"{}")
            if not isinstance(request, dict):
                raise ValueError
        except ValueError:
            return ApiResponse.error(400, "bad_request", "Send a JSON object.")
        try:
            result = await config_forms.apply(actor, request)
        except ViewError as exc:
            return ApiResponse.error(422, "invalid_input", exc.message)
        log.info("[WEB] %s changed '%s'%s: %s", actor.username, request.get("path"),
                 f" [{request.get('key')}]" if request.get("key") else "",
                 "committed" if result["ok"] else "refused")
        return ApiResponse(200 if result["ok"] else 422, result)

    def _complete(self, actor: ActionActor, body: bytes) -> ApiResponse:
        """Tab in the web console: what may follow the text before the cursor."""
        try:
            text = str(json.loads(body or b"{}").get("text", ""))
        except (json.JSONDecodeError, AttributeError):
            return ApiResponse.error(400, "bad_request", 'Send {"text": "<line>"}.')
        if "\n" in text or len(text) > 4096:
            return ApiResponse.error(400, "bad_request", "One line, at most 4096 characters.")
        return ApiResponse(200, {"candidates": self._shells.shell_for(actor).completions(text)})

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


def self_signed_certificate(address: str) -> tuple[str, str]:
    """A self-signed certificate in the state directory, made once [usmd.example.yaml]."""
    import datetime  # pylint: disable=import-outside-toplevel
    import ipaddress  # pylint: disable=import-outside-toplevel

    from cryptography import x509  # pylint: disable=import-outside-toplevel
    from cryptography.hazmat.primitives import hashes, serialization  # pylint: disable=import-outside-toplevel
    from cryptography.hazmat.primitives.asymmetric import ec  # pylint: disable=import-outside-toplevel
    from cryptography.x509.oid import NameOID  # pylint: disable=import-outside-toplevel

    from usmd_rdsh.cli.store import state_directory  # pylint: disable=import-outside-toplevel

    state = state_directory()
    cert_path, key_path = state.path("web-cert.pem"), state.path("web-key.pem")
    if cert_path.exists() and key_path.exists():
        return str(cert_path), str(key_path)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "usmd-rdsh")])
    now = datetime.datetime.now(datetime.timezone.utc)
    alt = [x509.DNSName("localhost")]
    try:
        alt.append(x509.IPAddress(ipaddress.ip_address(address)))
    except ValueError:
        pass
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .sign(key, hashes.SHA256()))
    state.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                        serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()), "web-key.pem", mode=0o600)
    state.write_bytes(cert.public_bytes(serialization.Encoding.PEM), "web-cert.pem")
    log.warning("[WEB] Generated a self-signed certificate: %s", cert_path)
    return str(cert_path), str(key_path)


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
            self._router.username, self._router.password = config.username, config.password
            await self._stop()
            self._switch.enabled = config.status
            if not config.status:
                log.info("[WEB] Web interface disabled")
                return
            context = None
            mode = str(getattr(config, "tls_mode", "off"))
            certificate, key = config.tls_certificate, config.tls_private_key
            if mode == "self-signed":
                certificate, key = self_signed_certificate(config.listen_address)
            if mode in ("self-signed", "files") or certificate:
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(certificate, key)
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

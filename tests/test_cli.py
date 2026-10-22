"""Console, configuration tree, logging and web interface of the management plane."""

import asyncio
import json
import logging

import pytest
from nan_actions.views import ConfigDocument

from usmd_rdsh.cli.logbuffer import LogBuffer, Severity
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.shell import ShellFactory
from usmd_rdsh.cli.store import ConfigStore, TokenStore
from usmd_rdsh.web.server import WebRouter


@pytest.fixture(name="factory")
def _factory(tmp_path, monkeypatch):
    monkeypatch.setenv("USMD_STATE_DIR", str(tmp_path))
    RUNTIME.config_store = ConfigStore()
    RUNTIME.tokens = TokenStore()
    RUNTIME.document = ConfigDocument()
    RUNTIME.node = None
    RUNTIME.web = None
    return ShellFactory()


def _run(factory, *lines):
    """Run console lines; return everything they printed."""
    printed = []
    from nan_runtime.log import reset_log_sink, set_log_sink  # pylint: disable=import-outside-toplevel

    async def go():
        shell = factory.console()
        token = set_log_sink(printed.append)
        try:
            for line in lines:
                await shell.execute_line(line)
        finally:
            reset_log_sink(token)

    asyncio.run(go())
    return "\n".join(printed)


def test_logbuffer_formats_like_ios():
    buffer = LogBuffer(capacity=16)
    logger = logging.getLogger("usmd_rdsh.test.logbuffer")
    logger.propagate = False
    buffer.attach(logger)
    logger.warning("[NCP] Peer 10.0.0.1 is busy")
    message = buffer.messages()[-1]
    assert message.facility == "NCP"
    assert message.severity is Severity.WARNINGS
    assert "%NCP-4-PEER_BUSY: Peer 10.0.0.1 is busy" in message.render()


def test_logbuffer_keeps_only_buffered_level():
    buffer = LogBuffer(capacity=16)
    buffer.buffered_level = Severity.WARNINGS
    logger = logging.getLogger("usmd_rdsh.test.level")
    logger.propagate = False
    buffer.attach(logger)
    logger.info("dropped")
    logger.error("kept")
    assert [m.text for m in buffer.messages()] == ["kept"]


def test_configuration_is_committed_saved_and_shown(factory):
    out = _run(
        factory,
        "config usd", "set name 01JAB7R9F2W5H1N3S8D0Q4K6ME", "set ping-tolerance 500", "end",
        "show running-config",
    )
    assert "Committed 1 node(s)." in out
    assert "set ping-tolerance 500" in out
    saved = json.loads(RUNTIME.config_store.path.read_text(encoding="utf-8"))
    assert saved["singletons"]["usd"]["name"] == "01JAB7R9F2W5H1N3S8D0Q4K6ME"


def test_incoherent_usd_is_refused_inside_the_node(factory):
    out = _run(factory, "config usd", "set solicited-nodes 9", "end")
    assert "cannot exceed reference-nodes" in out
    assert RUNTIME.document.fields(("usd",)) == {}


def test_show_logging_and_usd_parameters(factory):
    out = _run(factory, "show logging", "show usd parameters")
    assert "Syslog logging: enabled" in out
    assert "0x0013  sp-mtu                 1412" in out
    assert "0x0014  voters" in out
    assert "0x0011" not in out


def test_service_catalogue_checks_areas(factory):
    out = _run(
        factory,
        "config service-area", "edit front", "set id 1", "set prefix 10.80.0.0",
        "set prefix-length 16", "next", "edit back", "set id 2", "set prefix 10.80.4.0",
        "next", "end",
    )
    assert "overlap" in out
    out = _run(
        factory,
        "abort",
        "config service-area", "edit front", "set id 1", "set prefix 10.80.0.0",
        "set prefix-length 16", "next", "end",
        "config service", "edit web", "set id A1", "set area front",
        "set vip 10.90.0.1", "set dependencies db", "next", "end",
        "show running-config",
    )
    assert 'edit "web"' in out and "set id 0a1" in out


def test_service_id_reserved_values_are_refused(factory):
    out = _run(factory, "config service", "edit x", "set id fff", "set area a", "next")
    assert "reserved" in out


def test_observed_state_cannot_be_declared(factory):
    out = _run(factory, "execute node state state=inactive-timeout")
    assert "origin O" in out
    assert "Traceback" not in out


def _router(factory):
    return WebRouter(factory)


def test_web_requires_a_token(factory):
    response = asyncio.run(_router(factory).handle("GET", "/web/summary", {}))
    assert response.status == 401


def test_web_console_respects_the_token_profile(factory):
    monitor = RUNTIME.tokens.mint("mon", "monitor").plaintext
    admin = RUNTIME.tokens.mint("adm", "admin").plaintext
    router = _router(factory)

    async def cli(token, line, confirm=False):
        body = json.dumps({"line": line, "confirm": confirm}).encode()
        return await router.handle(
            "POST", "/web/cli", {"Authorization": f"Bearer {token}"}, body
        )

    refused = asyncio.run(cli(monitor, "config system global"))
    assert "no such configuration node" in refused.body["output"][0]

    async def admin_session():
        await cli(admin, "config system global")
        await cli(admin, "set hostname web-node")
        return await cli(admin, "end")

    committed = asyncio.run(admin_session())
    assert committed.body["prompt"] == "web-node#"

    erase = asyncio.run(cli(admin, "write erase"))
    assert erase.body["needs_confirm"] is True
    assert RUNTIME.hostname() == "web-node"
    asyncio.run(cli(admin, "write erase", confirm=True))
    assert RUNTIME.hostname() == "usmd"


def test_web_forms_cover_every_node_and_commit(factory):
    from nan_actions.views import views  # pylint: disable=import-outside-toplevel

    admin = RUNTIME.tokens.mint("adm", "admin").plaintext
    monitor = RUNTIME.tokens.mint("mon", "monitor").plaintext
    router = _router(factory)
    auth = {"Authorization": f"Bearer {admin}"}

    async def post(body, headers=auth):
        return await router.handle("POST", "/web/config", headers, json.dumps(body).encode())

    schema = asyncio.run(router.handle("GET", "/web/config", auth)).body
    assert {n["path"] for n in schema["nodes"]} == {n.cli_path for n in views.nodes()}

    ok = asyncio.run(post({"path": "usd", "values": {"name": "01JAB7R9F2W5H1N3S8D0Q4K6ME",
                                                      "voters": 3}}))
    assert ok.status == 200, ok.body
    assert RUNTIME.config("usd").voters == 3

    bad = asyncio.run(post({"path": "usd", "values": {"solicited_nodes": 50}}))
    assert bad.status == 422 and "reference-nodes" in bad.body["error"]

    row = asyncio.run(post({"path": "service", "key": "web",
                            "values": {"id": "0a1", "area": "front",
                                       "dependencies": ["db", "cache"]}}))
    assert row.status == 200, row.body
    assert RUNTIME.config("service")["web"].dependencies == ["db", "cache"]
    gone = asyncio.run(post({"path": "service", "key": "web", "delete": True}))
    assert gone.status == 200 and RUNTIME.config("service") == {}

    refused = asyncio.run(post({"path": "usd", "values": {"name": "x"}},
                               {"Authorization": f"Bearer {monitor}"}))
    assert refused.status == 403


def test_authority_commit_signs_and_others_refuse(factory, tmp_path):
    from nan_runtime.state import StateDirectory  # pylint: disable=import-outside-toplevel

    from usmd_rdsh.cli import bridge  # pylint: disable=import-outside-toplevel
    from usmd_rdsh.node.node import Node  # pylint: disable=import-outside-toplevel

    plain = Node(StateDirectory(tmp_path / "plain"))
    RUNTIME.node = plain
    out = _run(factory, "config usd", "set name 01JAB7R9F2W5H1N3S8D0Q4K6ME", "end")
    assert "does not hold the USC key" in out
    assert plain.signed.usd is None

    authority = Node(StateDirectory(tmp_path / "authority"))
    authority.authority.generate("usc")
    authority.authority.generate("usd")
    authority.on_signed_change = bridge.reflect
    RUNTIME.node = authority

    async def go():
        shell = factory.console()
        for line in ("config service-area", "edit front", "set id 1", "set prefix 10.80.0.0",
                     "set prefix-length 16", "next", "end",
                     "config service", "edit web", "set id 0a1", "set area front",
                     "set vip 10.80.0.10", "next", "end",
                     "config mutation", "edit frontal", "set services web", "next", "end",
                     "config usd", "set name 01JAB7R9F2W5H1N3S8D0Q4K6ME", "set sp-port 9993",
                     "end"):
            await shell.execute_line(line)

    asyncio.run(go())
    usd = authority.signed.usd
    assert usd is not None and usd.usdn == "01JAB7R9F2W5H1N3S8D0Q4K6ME"
    usd.verify(authority.authority.usc.public)
    assert [e.vip for e in usd.catalog] == ["10.80.0.10"]
    assert usd.parameters[0x0010] == 9993
    assert authority.signed.mutation_services("frontal") == ["web"]
    version = usd.version
    out = _run(factory, "show service catalog", "show usd parameters")
    assert "0a1" in out and "9993" in out
    # A commit that changes nothing signs nothing.
    _run(factory, "config usd", "set sp-port 9993", "end")
    assert authority.signed.usd.version == version


def test_web_serves_the_page(factory):
    response = asyncio.run(_router(factory).handle("GET", "/", {}))
    assert response.status == 200
    assert b"{{REFRESH}}" not in response.payload

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


def test_data_id_commands(factory):
    """[ARCH-03 11.6]: decode, PostgreSQL generator, no instance without a node."""
    out = _run(factory, "show data-id id=00b20003-0192-8d3a-8000-000004000001",
               "show data-id postgresql", "show data-id id=not-a-uuid",
               "execute data-id generate service=web")
    assert "0b2.0003" in out and " UTC" in out
    assert "FUNCTION usmd_id()" in out
    assert "not a USMD-RDSH data identifier" in out
    assert "node is not running" in out
    assert "Traceback" not in out


def test_question_mark_lists_what_may_follow(factory):
    """'?' as on IOS: bare, after a word, inside a word; actions included."""
    root = _run(factory, "?")
    assert "execute" in root and "show" in root and "config" in root
    after_show = _run(factory, "show ?")
    assert "logging" in after_show and "data-id" in after_show and "protocol" in after_show
    assert after_show.count("  |") == 1  # both trees offer the pipe: listed once
    assert "transmute" in _run(factory, "execute node tr?")
    assert "level=" in _run(factory, "show logging ?")
    assert "<cr>" in _run(factory, "show version ?")
    assert "<cr>" not in _run(factory, "show data-id ?")  # id= is required
    assert "Unrecognized command" in _run(factory, "frobnicate?")
    assert "Traceback" not in root + after_show


def test_completion_lends_the_operator_only_while_completing(factory):
    from nan_actions import access  # pylint: disable=import-outside-toplevel

    before = access._actor_fallback  # pylint: disable=protected-access
    values = [c["value"] for c in factory.console().completions("execute node ")]
    assert "transmute" in values
    assert access._actor_fallback is before  # pylint: disable=protected-access


def test_web_completion_follows_the_token_profile(factory):
    monitor = RUNTIME.tokens.mint("mon", "monitor").plaintext
    admin = RUNTIME.tokens.mint("adm", "admin").plaintext
    router = _router(factory)

    def complete(token, text):
        body = json.dumps({"text": text}).encode()
        response = asyncio.run(router.handle(
            "POST", "/web/complete", {"Authorization": f"Bearer {token}"}, body))
        return [c["value"] for c in response.body["candidates"]]

    assert "execute" in complete(admin, "") and "logging" in complete(admin, "show ")
    assert "transmute" in complete(admin, "execute node ")
    assert "transmute" not in complete(monitor, "execute node ")
    unauthenticated = asyncio.run(router.handle("POST", "/web/complete", {}, b"{}"))
    assert unauthenticated.status == 401


def test_local_console_keys(factory, monkeypatch):
    """Tab and '?' at the local prompt: the operator's completer, and a '?'
    that prints the candidates and keeps the line (inside quotes: a character)."""
    from types import SimpleNamespace  # pylint: disable=import-outside-toplevel

    from prompt_toolkit.buffer import Buffer  # pylint: disable=import-outside-toplevel
    from prompt_toolkit.completion import CompleteEvent  # pylint: disable=import-outside-toplevel
    from prompt_toolkit.document import Document  # pylint: disable=import-outside-toplevel

    from usmd_rdsh.cli import shell as shell_module  # pylint: disable=import-outside-toplevel

    shell = factory.console()
    completer = shell_module._OperatorCompleter(  # pylint: disable=protected-access
        shell._registry, shell._views, shell._actor_factory)  # pylint: disable=protected-access
    found = [c.text for c in completer.get_completions(Document("execute node tr"), CompleteEvent())]
    assert found == ["transmute"]

    monkeypatch.setattr(shell_module, "run_in_terminal", lambda job: job())
    bindings = shell_module._key_bindings(shell).get_bindings_for_keys(("?",))  # pylint: disable=protected-access
    question = bindings[-1].handler  # prompt_toolkit runs the last match

    def press(text):
        buffer = Buffer(document=Document(text))
        printed = []
        monkeypatch.setattr("builtins.print", lambda *a, **k: printed.append(" ".join(map(str, a))))
        out = _run_key(question, buffer)
        return buffer.text, printed, out

    def _run_key(handler, buffer):
        lines = []
        from nan_runtime.log import reset_log_sink, set_log_sink  # pylint: disable=import-outside-toplevel
        token = set_log_sink(lines.append)
        try:
            handler(SimpleNamespace(app=SimpleNamespace(current_buffer=buffer)))
        finally:
            reset_log_sink(token)
        return "\n".join(lines)

    text, echoed, out = press("show ")
    assert text == "show " and echoed[0].endswith("show ?") and "logging" in out
    text, _, out = press('set banner "why')
    assert text == 'set banner "why?' and out == ""

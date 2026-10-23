"""The console of a running node through its Unix socket (``sudo usmd``)."""

import asyncio
import os
import threading

import pytest
from nan_actions.views import ConfigDocument

from usmd_rdsh.cli import control
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.shell import ShellFactory
from usmd_rdsh.cli.store import ConfigStore, TokenStore


@pytest.fixture(name="factory")
def _factory(tmp_path, monkeypatch):
    monkeypatch.setenv("USMD_STATE_DIR", str(tmp_path))
    RUNTIME.config_store = ConfigStore()
    RUNTIME.tokens = TokenStore()
    RUNTIME.document = ConfigDocument()
    RUNTIME.node = None
    RUNTIME.web = None
    return ShellFactory()


def test_answers_lines_prompts_completion_and_confirmation(factory):
    shell = factory.console()

    async def go():
        ask = control.ControlServer._answer  # pylint: disable=protected-access
        entered = await ask(shell, {"line": "config system global"})
        await ask(shell, {"line": "set hostname node1"})
        committed = await ask(shell, {"line": "end"})
        listed = await ask(shell, {"line": "show ?"})
        completed = await ask(shell, {"complete": "show n"})
        refused = await ask(shell, {"line": "write erase"})
        kept = RUNTIME.hostname()
        erased = await ask(shell, {"line": "write erase", "confirm": True})
        left = await ask(shell, {"line": "exit"})
        return entered, committed, listed, completed, refused, kept, erased, left

    entered, committed, listed, completed, refused, kept, erased, left = asyncio.run(go())
    assert entered["prompt"].endswith("(config-global)#")
    assert committed["prompt"] == "node1#"
    assert any("running-config" in line for line in listed["output"])
    assert "node" in [c["value"] for c in completed["candidates"]]
    assert refused["needs_confirm"] and kept == "node1"
    assert not erased["needs_confirm"] and RUNTIME.hostname() == "usmd"
    assert left["exit"] is True


def test_socket_path_follows_the_service_then_the_state(tmp_path, monkeypatch):
    monkeypatch.setenv(control.SOCKET_ENV_VAR, str(tmp_path / "x.sock"))
    assert control.socket_path() == tmp_path / "x.sock"
    monkeypatch.delenv(control.SOCKET_ENV_VAR)
    monkeypatch.setenv("USMD_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(control, "SERVICE_RUN_DIR", tmp_path / "absent")
    assert control.socket_path() == tmp_path / "usmd.sock"


@pytest.mark.skipif(not control.available(), reason="Unix sockets (Linux nodes)")
def test_usmd_attaches_to_the_running_node(factory, tmp_path, capsys):
    path = tmp_path / "usmd.sock"
    server = control.ControlServer(factory, path)
    loop = asyncio.new_event_loop()
    started = threading.Event()

    def serve():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(server.start())
        started.set()
        loop.run_forever()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    started.wait(5)
    try:
        assert oct(os.stat(path).st_mode & 0o777) == "0o660"
        control.run_lines(path, ["config system global", "set hostname node1", "end",
                                 "show running-config"], yes=False)
        assert "set hostname node1" in capsys.readouterr().out
        control.run_lines(path, ["write erase"], yes=False)
        assert "Not confirmed" in capsys.readouterr().out and RUNTIME.hostname() == "node1"
        control.run_lines(path, ["write erase"], yes=True)
        assert RUNTIME.hostname() == "usmd"
    finally:
        asyncio.run_coroutine_threadsafe(server.stop(), loop).result(5)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(5)
    assert not path.exists()

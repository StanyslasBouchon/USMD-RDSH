"""The console of a running node, from another process (``sudo usmd``).

A node started as a service has no terminal. It listens on a Unix socket::

    $USMD_CONTROL_SOCKET, or /run/usmd/usmd.sock (systemd's RuntimeDirectory),
    or <state>/usmd.sock

with mode 0660: root and the members of the node's group may connect, nobody
else. Each connection gets a console shell of its own, with the local
console's rights, so ``usmd`` typed on the machine opens the console of the
node that runs there instead of starting a second node beside it.

The exchange is one JSON object per line, as the web console's:

    -> {"line": "show node", "confirm": false}
    <- {"output": [...], "prompt": "node1#", "needs_confirm": false, "exit": false}
    -> {"complete": "show n"}
    <- {"candidates": [{"value": ..., "display": ..., "description": ...}]}
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import socket
import stat
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

from nan_runtime.log import reset_log_sink, set_log_sink, strip_level_prefix

from usmd_rdsh.cli.confirm import reset_web_confirmation, web_confirmation
from usmd_rdsh.cli.store import state_directory

if TYPE_CHECKING:  # pragma: no cover
    from usmd_rdsh.cli.shell import ShellFactory

log = logging.getLogger("usmd_rdsh.cli")

SOCKET_ENV_VAR = "USMD_CONTROL_SOCKET"
#: Set by the installed ``usmd`` command: attach to the service, never start a node.
ATTACH_ONLY_ENV_VAR = "USMD_ATTACH_ONLY"
SERVICE_RUN_DIR = Path("/run/usmd")
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_NOT_CONFIRMED = "Not confirmed: nothing was done."
MAX_LINE = 1 << 20


def socket_path() -> Path:
    """Where the node listens, and where ``usmd`` looks for it."""
    configured = os.getenv(SOCKET_ENV_VAR)
    if configured:
        return Path(configured)
    if SERVICE_RUN_DIR.is_dir():
        return SERVICE_RUN_DIR / "usmd.sock"
    return state_directory().path("usmd.sock")


def available() -> bool:
    """Unix sockets: not on Windows."""
    return hasattr(socket, "AF_UNIX") and sys.platform != "win32"


class ControlServer:
    """The node's side: one console shell per connection."""

    def __init__(self, factory: "ShellFactory", path: Path | None = None) -> None:
        self._factory = factory
        self.path = path or socket_path()
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        """Listen; a socket left by a node that died is replaced."""
        if not available():
            return
        if self.path.exists() and not _answers(self.path):
            self.path.unlink()
        try:
            self._server = await asyncio.start_unix_server(self._serve, path=str(self.path),
                                                           limit=MAX_LINE)
        except OSError as exc:
            log.error("[CLI] Console socket %s not opened: %s", self.path, exc)
            return
        os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
        log.info("[CLI] Console of this node: 'usmd' (socket %s)", self.path)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            try:
                self.path.unlink()
            except OSError:
                pass

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        shell = self._factory.console()
        try:
            while True:
                raw = await reader.readline()
                if not raw:
                    break
                try:
                    request = json.loads(raw)
                    if not isinstance(request, dict):
                        raise ValueError
                except ValueError:
                    answer: dict[str, Any] = {"error": "one JSON object per line"}
                else:
                    answer = await self._answer(shell, request)
                writer.write(json.dumps(answer).encode() + b"\n")
                await writer.drain()
                if answer.get("exit"):
                    break
        except (ConnectionError, asyncio.IncompleteReadError, ValueError):
            pass
        finally:
            writer.close()

    @staticmethod
    async def _answer(shell, request: dict) -> dict[str, Any]:
        if "complete" in request:
            return {"candidates": await shell.completions_async(str(request["complete"]))}
        return await run_line(shell, str(request.get("line", "")), request.get("confirm") is True)


async def run_line(shell, line: str, confirm: bool) -> dict[str, Any]:
    """One line with its output captured; a confirmation is answered by *confirm*.

    Shared by this socket and Operate [ARCH 12.5]: the same exchange either way."""
    lines: list[str] = []
    sink = set_log_sink(lambda text: lines.append(_ANSI.sub("", strip_level_prefix(text))))
    answer, confirmation = web_confirmation(confirm)
    try:
        leave = bool(await shell.execute_line(line))
    finally:
        reset_web_confirmation(confirmation)
        reset_log_sink(sink)
    return {"output": lines, "prompt": shell.prompt(), "exit": leave,
            "needs_confirm": answer.asked and not confirm}


def _answers(path: Path) -> bool:
    """Whether a node listens on *path*."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(1.0)
            probe.connect(str(path))
        return True
    except OSError:
        return False


class ControlClient:
    """``usmd``'s side, synchronous: it only waits for the node."""

    def __init__(self, path: Path) -> None:
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(str(path))
        self._file = self._sock.makefile("rwb")

    def request(self, message: dict) -> dict:
        self._file.write(json.dumps(message).encode() + b"\n")
        self._file.flush()
        raw = self._file.readline()
        if not raw:
            raise ConnectionError("the node closed the console")
        return json.loads(raw)

    def close(self) -> None:
        self._file.close()
        self._sock.close()


def running_node() -> Path | None:
    """The socket of the node running on this machine, if one answers."""
    if not available():
        return None
    path = socket_path()
    if not path.exists():
        return None
    if not os.access(path, os.R_OK | os.W_OK):
        raise SystemExit(f"A node runs here but {path} is not yours: use 'sudo usmd', "
                         "or join the node's group ('usermod -aG usmd $USER').")
    return path if _answers(path) else None


#: What the node prints when a command asking for confirmation was not confirmed.
_CANCELLED = (_NOT_CONFIRMED, "Operation cancelled.")


def _print(answer: dict) -> None:
    for text in answer.get("output", []):
        print(text)


def _run(client: ControlClient, line: str, ask) -> dict:
    """One line; a confirmation asked by the node is asked here, then resent.

    The node answers the first attempt with its question and its refusal: the
    question is shown, the refusal is not. Confirmed, the line runs again and
    the node asks its question again: shown once is enough.
    """
    answer = client.request({"line": line})
    if not answer.get("needs_confirm"):
        _print(answer)
        return answer
    question = [text for text in answer.get("output", []) if text not in _CANCELLED]
    for text in question:
        print(text)
    if not ask():
        print(_NOT_CONFIRMED)
        return answer
    answer = client.request({"line": line, "confirm": True})
    for text in answer.get("output", []):
        if text not in question:
            print(text)
    return answer


def _lines(typed: str) -> list[str]:
    """A paste of several lines is several commands, as on the local console."""
    return typed.splitlines() or [""]


def run_lines(path: Path, lines: list[str], *, yes: bool) -> None:
    """``usmd -c LINE``: the lines, in one console session, then exit."""
    client = ControlClient(path)
    try:
        for line in lines:
            if _run(client, line, lambda: yes).get("exit"):
                break
    finally:
        client.close()


def attach(path: Path) -> None:
    """``usmd``: the interactive console of the running node."""
    # pylint: disable=import-outside-toplevel
    from prompt_toolkit import PromptSession
    from prompt_toolkit.application import run_in_terminal
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.key_binding import KeyBindings

    client = ControlClient(path)
    prompt = client.request({"line": ""}).get("prompt", "#")

    class Remote(Completer):
        def get_completions(self, document, complete_event):
            typed = document.text_before_cursor
            word = typed.split(" ")[-1] if typed and not typed.endswith(" ") else ""
            for c in client.request({"complete": typed}).get("candidates", []):
                yield Completion(c["value"], start_position=-len(word),
                                 display=c.get("display"), display_meta=c.get("description"))

    keys = KeyBindings()

    @keys.add("?")
    def _(event) -> None:
        buffer = event.app.current_buffer
        typed = buffer.document.text_before_cursor
        if typed.count('"') % 2:
            buffer.insert_text("?")
            return
        answer = client.request({"line": typed + "?"})
        run_in_terminal(lambda: (print(prompt + typed + "?"), _print(answer)))

    def ask() -> bool:
        try:
            return PromptSession().prompt("Proceed? [y/N] ").strip().lower() in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    session: PromptSession[str] = PromptSession(completer=Remote(), key_bindings=keys,
                                                complete_while_typing=False)
    print(f"Connected to the node running on this machine ({path}). 'exit' to leave.")
    try:
        while True:
            try:
                typed = session.prompt(prompt)
            except KeyboardInterrupt:
                continue
            except EOFError:
                break
            leave = False
            for number, line in enumerate(_lines(typed)):
                if number:
                    print(prompt + line)  # each pasted line, as if typed at its prompt
                answer = _run(client, line, ask)
                prompt = answer.get("prompt", prompt)
                if answer.get("exit"):
                    leave = True
                    break
            if leave:
                break
    except ConnectionError as exc:
        print(f"% {exc}")
    finally:
        client.close()

"""Building the console: registry, view sessions, prompts, banner.

One command registry and one configuration document serve every operator; each
operator (the local console, each web token) gets a shell of their own, so a
``config`` block opened in the browser does not move the console's prompt.
"""

from __future__ import annotations

import inspect
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Awaitable, Callable, Iterator

from nan_actions import ActionActor, access, registry as action_registry
from nan_actions.access import (
    reset_current_action_actor,
    set_actor_fallback,
    set_current_action_actor,
)
from nan_actions.cli.completer import ShellCompleter
from nan_actions.cli.continuation import CONTINUATION_PROMPT, QuotedContinuation
from nan_actions.cli.history import as_history
from nan_actions.cli.registry import Registry
from nan_actions.cli.shell import Shell
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import CompleteEvent, Completion
from prompt_toolkit.document import Document
from prompt_toolkit.application import in_terminal, run_in_terminal
from prompt_toolkit.key_binding import KeyBindings, merge_key_bindings
from nan_actions.errors import SdkError
from nan_actions.ports import set_confirm_prompt
from nan_actions.abbrev import AmbiguousToken
from nan_actions.views import SHOW_FULL, SHOW_UNENCRYPTED, ViewSession, is_view_line, views
from nan_runtime.log import LogLevel, emit, log

from usmd_rdsh.cli import views as _views  # noqa: F401  # pylint: disable=unused-import
from usmd_rdsh.cli.confirm import UsmdConfirmPrompt
from usmd_rdsh.cli.permissions import VOCABULARY, console_actor
from usmd_rdsh.cli.bridge import after_commit
from usmd_rdsh.cli.runtime import RUNTIME

_ACTIONS_DIR = Path(__file__).parent / "actions"


class _Refusing:
    """A command whose ``SdkError`` is one line, not a traceback.

    ``Shell`` reports every exception of a command as a fault, which is right
    for a bug and wrong for "that state cannot be declared". Everything else is
    delegated, so completion, pipes and help see the command unchanged.
    """

    def __init__(self, command: Any) -> None:
        self._command = command

    def __getattr__(self, name: str) -> Any:
        return getattr(self._command, name)

    async def execute(self, args: dict[str, str]) -> None:
        """Run the command; a refusal is printed."""
        try:
            result = self._command.execute(args)
            if inspect.isawaitable(result):
                await result
        except SdkError as exc:
            log(exc.message or str(exc), LogLevel.ERROR)


@contextmanager
def _operator(actor: ActionActor) -> Iterator[None]:
    """The completer asks :func:`resolve_fallback_actor` who is at the prompt.

    USMD-RDSH declares no process-wide fallback: the web server shares the
    process, and a request without an actor must stay anonymous rather than
    inherit the console's rights. The shell's own operator is lent for the
    duration of one synchronous completion instead.
    """
    previous = access._actor_fallback  # pylint: disable=protected-access
    set_actor_fallback(lambda: actor)
    try:
        yield
    finally:
        set_actor_fallback(previous)


class _OperatorCompleter(ShellCompleter):
    """Tab and ``?`` as the shell's operator sees them, actions included."""

    def __init__(self, registry, views, actor_factory: Callable[[], ActionActor],
                 shell: "UsmdShell | None" = None) -> None:
        super().__init__(registry, views=views)
        self._actor_factory = actor_factory
        self._shell = shell

    def get_completions(self, document: Document, complete_event: CompleteEvent):
        from usmd_rdsh.cli import operate  # pylint: disable=import-outside-toplevel

        actor = self._actor_factory()
        text = document.text_before_cursor
        with _operator(actor):
            offered = operate.offered(actor)
            fleet = operate.completions(text, lambda rest: super(  # pylint: disable=super-with-arguments
                _OperatorCompleter, self).get_completions(Document(rest, len(rest)),
                                                          complete_event)) if offered else None
            found = fleet if fleet is not None else list(
                super().get_completions(document, complete_event))
            if offered and " " not in text.lstrip():
                found += list(operate.root_completions(text.lstrip()))
        yield from found

    async def get_completions_async(self, document: Document, complete_event: CompleteEvent):
        if self._shell is not None and self._shell.remote is not None:
            # Another node's console: its own candidates [ARCH 12.5].
            typed = document.text_before_cursor
            word = typed.split(" ")[-1] if typed and not typed.endswith(" ") else ""
            for c in await self._shell.remote.completions(typed):
                yield Completion(c["value"], start_position=-len(word),
                                 display=c.get("display"), display_meta=c.get("description"))
            return
        # Synchronous on purpose: an await would let another request run while
        # the operator is lent (see _operator).
        for completion in self.get_completions(document, complete_event):
            yield completion


def _key_bindings(shell: "UsmdShell") -> KeyBindings:
    """The SDK's Tab, Escape and Enter; ``?`` prints the candidates above the
    prompt and leaves the line as typed, as IOS does. Inside a quoted value
    ``?`` is just a character."""
    own = KeyBindings()

    @own.add("?")
    def _(event) -> None:
        buffer = event.app.current_buffer
        typed = buffer.document.text_before_cursor
        if typed.count('"') % 2:
            buffer.insert_text("?")
            return
        if shell.remote is not None:
            async def remote_help() -> None:
                async with in_terminal():
                    print(shell.prompt() + typed + "?")
                    await shell.execute_line(typed + "?")

            event.app.create_background_task(remote_help())
            return
        run_in_terminal(lambda: (print(shell.prompt() + typed + "?"), shell._answer(typed)))  # pylint: disable=protected-access

    return merge_key_bindings([ShellCompleter.build_key_bindings(), own])


class UsmdShell(Shell):
    """``nan_actions`` shell reporting host refusals as one line.

    ``show <configuration node>`` prints the node's values in force, defaults
    included, as IOS does: the view engine's own ``show`` (what differs from
    the defaults, FortiOS style) stays available as ``show running-config``.

    A line ending in ``?`` lists what may be typed there, as on IOS:
    ``?``, ``show ?`` (the next words), ``sh?`` (the words starting so). It is
    answered by the shell, so the web console and ``usmd -c`` get it too.
    """

    #: Another node's console (or several), while ``node`` / ``on`` holds it [ARCH 12.5].
    remote: Any = None

    async def execute_line(self, line: str) -> bool:  # type: ignore[override]
        from usmd_rdsh.cli import operate  # pylint: disable=import-outside-toplevel

        if self.remote is not None:
            await operate.remote_line(self, line)
            return False
        if self._is_question(line):  # 'on all show ?' is answered here, not by the nodes
            self._answer(line.rstrip()[:-1])
            return False
        if line.strip().split()[:1] in (["node"], ["on"]) and not (
                self._views is not None and self._views.active):
            await operate.enter(self, line, self._actor_factory())
            return False
        return await super().execute_line(self._full_show(line))

    @staticmethod
    def _is_question(line: str) -> bool:
        stripped = line.rstrip()
        return stripped.endswith("?") and stripped.count('"') % 2 == 0 \
            and not stripped.startswith("help")

    def prompt(self) -> str:
        if self.remote is not None:
            return self.remote.prompt(RUNTIME.hostname())
        return super().prompt()

    async def completions_async(self, text: str) -> list[dict[str, str]]:
        """Tab: the remote console's candidates while one holds this shell."""
        if self.remote is not None:
            return await self.remote.completions(text)
        return self.completions(text)

    def completions(self, text: str) -> list[dict[str, str]]:  # type: ignore[override]
        # The shell's own completer, so 'node' and 'on' are offered here too.
        actor = self._actor_factory()
        completer = _OperatorCompleter(self._registry, self._views, self._actor_factory, self)
        token = set_current_action_actor(actor)
        try:
            found = [{"value": c.text, "display": c.display_text,
                      "description": c.display_meta_text, "start": str(c.start_position)}
                     for c in completer.get_completions(Document(text, len(text)),
                                                        CompleteEvent())]
        except AmbiguousToken:
            found = []
        finally:
            reset_current_action_actor(token)
        # Both trees answer some lines (`show protocol ` offers `|` twice).
        unique: dict[str, dict[str, str]] = {}
        for candidate in found:
            unique.setdefault(candidate["value"], candidate)
        return list(unique.values())

    def _answer(self, text: str) -> None:
        """What may follow *text*: one candidate per line with its description."""
        candidates = self.completions(text)
        if not candidates:
            stripped = text.strip()
            if stripped and self._complete_command(stripped):
                emit("  <cr>")
            else:
                log(f"% Unrecognized command: {stripped or '?'}", LogLevel.ERROR)
            return
        width = max(len(c["display"]) for c in candidates)
        for candidate in candidates:
            emit(f"  {candidate['display'].ljust(width)}  {candidate['description']}".rstrip())
        required = any(c["description"].startswith("(required)") for c in candidates)
        if text.endswith(" ") and not required and self._complete_command(text.strip()):
            emit("  <cr>")

    def _complete_command(self, line: str) -> bool:
        """Whether *line* could be run as it stands."""
        if line.split()[:1] in (["node"], ["on"]):
            from usmd_rdsh.cli import operate  # pylint: disable=import-outside-toplevel

            return operate.is_complete(line, self._complete_command)
        try:
            expanded = self._expand_verb(line)
        except AmbiguousToken:
            return False
        if self._views is not None and is_view_line(self._views.registry, expanded):
            return True
        with _operator(self._actor_factory()):
            path = self._registry.resolve_path(expanded.split(), actor=self._actor_factory())
        return bool(path) and self._registry.get(*path, actor=self._actor_factory(),
                                                 visible_only=True) is not None

    async def run(self) -> None:
        """The prompt loop of :class:`Shell`, with the operator's completer."""
        session: PromptSession[str] = PromptSession(
            history=as_history(self._history),
            completer=_OperatorCompleter(self._registry, self._views, self._actor_factory, self),
            complete_while_typing=False,
            key_bindings=_key_bindings(self),
        )
        self._session = session
        if self._on_ready is not None:
            await self._on_ready()
        pending: str | None = None
        while True:
            try:
                raw: str = await session.prompt_async(
                    CONTINUATION_PROMPT if pending is not None else self.prompt())
            except KeyboardInterrupt:
                if pending is not None:
                    pending = None
                    continue
                break
            except EOFError:
                break
            lines = raw.split("\n")
            if pending is not None:
                lines[0] = QuotedContinuation.join(pending, lines[0])
            commands, pending = QuotedContinuation.group(lines)
            for single_line in commands:
                if await self.execute_line(single_line):
                    return

    def _full_show(self, line: str) -> str:
        stripped = line.strip()
        if not stripped or "|" in stripped:
            return line
        try:
            expanded = self._expand_verb(stripped)
        except AmbiguousToken:
            return line
        words = expanded.split()
        if words[0] != "show" or (len(words) > 1 and words[1] in (SHOW_FULL, SHOW_UNENCRYPTED)):
            return line
        views = self._views
        if views is None:
            return line
        if len(words) == 1:
            # Bare 'show' inside a node: that node in full; at the root: the delta.
            return "show " + SHOW_FULL if views.active else line
        if is_view_line(views.registry, expanded):
            return "show " + SHOW_FULL + " " + " ".join(words[1:])
        return line

    async def _execute(self, cmd, args, line, *, capture):  # type: ignore[override]
        return await super()._execute(_Refusing(cmd), args, line, capture=capture)


class ShellFactory:
    """Makes the shells of the console and of each web token."""

    def __init__(self) -> None:
        action_registry.set_vocabulary(VOCABULARY)
        set_confirm_prompt(UsmdConfirmPrompt())
        self.registry = Registry()
        self.registry.autodiscover(
            actions_path=_ACTIONS_DIR, actions_package="usmd_rdsh.cli.actions"
        )
        self._web: dict[str, tuple[UsmdShell, ViewSession]] = {}

    def _session(self, actor: ActionActor) -> ViewSession:
        return ViewSession(
            views,
            RUNTIME.document,
            on_commit=after_commit,
            actor_factory=lambda: actor,
            reveal_permissions=None,
        )

    def _shell(
        self,
        actor: ActionActor,
        session: ViewSession,
        on_ready: Callable[[], Awaitable[None]] | None = None,
    ) -> UsmdShell:
        return UsmdShell(
            self.registry,
            prompt=lambda: f"{RUNTIME.hostname()}#",
            actor_factory=lambda: actor,
            views=session,
            view_prompt=lambda labels: f"{RUNTIME.hostname()}(config-{labels[-1]})#",
            on_ready=on_ready,
        )

    def console(self, on_ready: Callable[[], Awaitable[None]] | None = None) -> UsmdShell:
        """The local console's shell."""
        actor = console_actor()
        return self._shell(actor, self._session(actor), on_ready)

    def shell_for(self, actor: ActionActor) -> UsmdShell:
        """The shell of one web token, kept across requests."""
        key = actor.user_id or ""
        if key not in self._web:
            session = self._session(actor)
            self._web[key] = (self._shell(actor, session), session)
        return self._web[key][0]

    def operator_shell(self, actor: ActionActor) -> UsmdShell:
        """A shell lent to an elected operator of another node [ARCH 12.5]."""
        return self._shell(actor, self._session(actor))

    def prompt(self, actor: ActionActor) -> str:
        """The prompt a web token's next line is typed at."""
        return self.shell_for(actor).prompt()


def banner() -> None:
    """What the console prints before its first prompt."""
    text = RUNTIME.config("system global").banner
    node_id = RUNTIME.node.node_id if RUNTIME.node else "?"
    emit("")
    if text:
        emit(text)
    emit(f"USMD-RDSH node {node_id}")
    emit("Type 'help' or '?' for commands, 'config <node>' to configure, 'exit' to quit.")
    emit("")

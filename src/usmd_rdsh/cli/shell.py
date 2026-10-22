"""Building the console: registry, view sessions, prompts, banner.

One command registry and one configuration document serve every operator; each
operator (the local console, each web token) gets a shell of their own, so a
``config`` block opened in the browser does not move the console's prompt.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any, Awaitable, Callable

from nan_actions import ActionActor, registry as action_registry
from nan_actions.cli.registry import Registry
from nan_actions.cli.shell import Shell
from nan_actions.errors import SdkError
from nan_actions.ports import set_confirm_prompt
from nan_actions.views import ViewSession, views
from nan_runtime.log import LogLevel, emit, log

from usmd_rdsh.cli import views as _views  # noqa: F401  # pylint: disable=unused-import
from usmd_rdsh.cli.confirm import UsmdConfirmPrompt
from usmd_rdsh.cli.permissions import VOCABULARY, console_actor
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


class UsmdShell(Shell):
    """``nan_actions`` shell reporting host refusals as one line."""

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
            on_commit=RUNTIME.config_store.save,
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

    def prompt(self, actor: ActionActor) -> str:
        """The prompt a web token's next line is typed at."""
        return self.shell_for(actor).prompt()


def banner() -> None:
    """What the console prints before its first prompt."""
    text = RUNTIME.config("system global").banner
    node_id = RUNTIME.core.properties.node_id if RUNTIME.core else "?"
    emit("")
    if text:
        emit(text)
    emit(f"USMD-RDSH node {node_id}")
    emit("Type 'help' or '?' for commands, 'config <node>' to configure, 'exit' to quit.")
    emit("")

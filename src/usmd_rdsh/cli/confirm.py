"""Confirmation of the commands declaring ``cli_confirm`` (``write erase``...).

``nan_actions`` binds one prompt for the whole process, and this process has two
kinds of operator:

    - the console, asked on the terminal - asynchronously, so the web interface
      keeps answering while the question waits;
    - a web console line, which cannot be asked anything mid-request: the
      browser sends ``"confirm": true`` with the line, after the first attempt
      came back with ``needs_confirm``.
"""

from __future__ import annotations

import contextvars
from dataclasses import dataclass

from nan_runtime.log import LogLevel, log
from prompt_toolkit import PromptSession


@dataclass(slots=True)
class WebConfirmation:
    """What one web request answered in advance, and whether it was asked."""

    confirmed: bool
    asked: bool = False


_web: contextvars.ContextVar[WebConfirmation | None] = contextvars.ContextVar(
    "usmd_web_confirmation", default=None
)


def web_confirmation(confirmed: bool) -> tuple[WebConfirmation, contextvars.Token]:
    """Install the answer of the current web request; reset with the token."""
    answer = WebConfirmation(confirmed=confirmed)
    return answer, _web.set(answer)


def reset_web_confirmation(token: contextvars.Token) -> None:
    """Undo :func:`web_confirmation`."""
    _web.reset(token)


class UsmdConfirmPrompt:
    """Asks the console, or answers from the web request."""

    async def ask(self, message: str) -> bool:
        """Show *message*; True when the operator confirmed."""
        web = _web.get()
        log(message, LogLevel.WARNING)
        if web is not None:
            web.asked = True
            if not web.confirmed:
                log("Not confirmed: nothing was done.", LogLevel.ERROR)
            return web.confirmed
        try:
            answer = await PromptSession().prompt_async("Proceed? [y/N] ")
        except (EOFError, KeyboardInterrupt):
            return False
        except Exception:  # pylint: disable=broad-except
            # No terminal at all (``usmd -c``, a service): nobody to ask is a no.
            log("No terminal to confirm on: nothing was done.", LogLevel.ERROR)
            return False
        return answer.strip().lower() in ("y", "yes")

"""The running node, as the management plane sees it.

One object, set up by ``main`` before the console or the web interface starts,
and read by every action and every configuration node. Holding it here rather
than passing it down is what lets an ``@action`` handler stay a plain function
of its input model, which is what makes it callable from both the console and
the HTTP API.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from nan_actions.views import ConfigDocument, ViewError, views
from pydantic import BaseModel

from usmd_rdsh.cli.logbuffer import LogBuffer
from usmd_rdsh.cli.store import ConfigStore, TokenStore

if TYPE_CHECKING:  # pragma: no cover
    from usmd_rdsh.self.core import Core
    from usmd_rdsh.web.server import WebServer

log = logging.getLogger("usmd_rdsh.cli")


@dataclass
class Runtime:  # pylint: disable=too-many-instance-attributes
    """Everything a command may need to read or change."""

    config_store: ConfigStore = field(default_factory=ConfigStore)
    tokens: TokenStore = field(default_factory=TokenStore)
    logbuffer: LogBuffer = field(default_factory=LogBuffer)
    document: ConfigDocument = field(default_factory=ConfigDocument)
    core: "Core | None" = None
    web: "WebServer | None" = None
    started_at: float = field(default_factory=time.time)

    # -- configuration -----------------------------------------------------

    def config(self, path: str) -> Any:
        """The committed, validated configuration of the node at *path*.

        A singleton yields its model, defaults included; a table yields
        ``{key: model}``.
        """
        node = views.get(tuple(path.split()))
        if node is None:
            raise KeyError(f"no configuration node '{path}'")
        if node.table:
            return {
                key: node.fields.validate(stored)
                for key, stored in self.document.rows(node.path).items()
            }
        return node.fields.validate(self.document.fields(node.path))

    async def apply_all(self) -> None:
        """Push the whole committed document into the node, at startup.

        A node whose saved values no longer validate (a field was tightened
        since they were written) keeps its defaults and is reported, rather
        than stopping the node from starting.
        """
        applied = []
        for node in views.nodes():
            try:
                if node.table:
                    value: Any = {
                        key: node.fields.validate(stored)
                        for key, stored in self.document.rows(node.path).items()
                    }
                else:
                    value = node.fields.validate(self.document.fields(node.path))
            except ViewError as exc:
                log.error("[CONFIG] Saved '%s' is invalid, defaults used: %s",
                          node.cli_path, exc.message)
                value = {} if node.table else node.model()
            await node.node.apply(value)
            applied.append(node)
        for node in applied:
            await node.node.settle()

    # -- identity ----------------------------------------------------------

    def hostname(self) -> str:
        """The configured hostname, or one derived from the node id."""
        configured: BaseModel = self.config("system global")
        name = getattr(configured, "hostname", "")
        if name:
            return name
        if self.core is not None:
            return f"usmd-{self.core.properties.node_id[-6:].lower()}"
        return "usmd"

    def uptime(self) -> float:
        """Seconds since the management plane started."""
        return time.time() - self.started_at


#: The one runtime of this process. ``main`` fills in ``core`` and ``web``.
RUNTIME = Runtime()


def format_duration(seconds: float) -> str:
    """``3 days, 4 hours, 5 minutes`` the way ``show version`` says uptime."""
    seconds = int(seconds)
    parts = []
    for unit, size in (("week", 604800), ("day", 86400), ("hour", 3600), ("minute", 60)):
        count, seconds = divmod(seconds, size)
        if count:
            parts.append(f"{count} {unit}{'s' if count > 1 else ''}")
    return ", ".join(parts) or f"{seconds} seconds"

"""Shared state between the NodeDaemon and the Django web views.

Because Django settings are configured before the app is imported, and
views run in the same process as the daemon, we use a module-level
singleton to pass live data (snapshot function, NIT reference, config)
without going through a database or IPC.

Examples:
    >>> from usmd.web.state import WebState, set_state, get_state
    >>> # In node_daemon.py:
    >>> # set_state(WebState(snapshot_fn=..., nit=..., ncp_port=5626, cfg=cfg))
    >>> # In views.py:
    >>> # state = get_state()
    >>> # snapshot = state.snapshot_fn()
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from ..config import NodeConfig
    from ..node.nit import NodeIdentityTable


@dataclass
class WebState:
    """All data the web views need from the running daemon.

    Attributes:
        snapshot_fn: Zero-arg callable returning the local node's status dict.
        nit: Live NodeIdentityTable (read-only from views).
        ncp_port: NCP TCP port used to query remote nodes.
        cfg: Full node configuration (contains web_username, web_password, etc.).
    """

    snapshot_fn: Callable[[], dict]
    nit: "NodeIdentityTable"
    ncp_port: int
    cfg: "NodeConfig"


_STATE: Optional[WebState] = None


def set_state(state: WebState) -> None:
    """Register the shared state. Called once by NodeDaemon before starting."""
    global _STATE  # pylint: disable=global-statement
    _STATE = state


def get_state() -> WebState:
    """Return the shared state. Raises RuntimeError if not yet initialised."""
    if _STATE is None:
        raise RuntimeError(
            "WebState has not been initialised — "
            "call usmd.web.state.set_state() before serving requests."
        )
    return _STATE

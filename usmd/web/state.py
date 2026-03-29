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
from typing import TYPE_CHECKING, Awaitable, Callable, Optional

if TYPE_CHECKING:
    from ..config import NodeConfig
    from ..domain.usd import UnifiedSystemDomain
    from ..node.nit import NodeIdentityTable


@dataclass
class WebState:
    """All data the web views need from the running daemon.

    Attributes:
        snapshot_fn: Zero-arg callable returning the local node's status dict.
        nit: Live NodeIdentityTable (read-only from views).
        ncp_port: NCP TCP port used to query remote nodes.
        cfg: Full node configuration (e.g. ``cfg.web.username`` / ``cfg.web.password``).
        usd: Live UnifiedSystemDomain used to check per-node state before NCP polling.
        on_ncp_failure: Optional callback invoked with the peer's address when an
            outgoing NCP request fails (connection refused, timeout, etc.).
        mutation_apply_fn: Optional async (service_name, yaml, apply_locally) →
            (success, message) for the mutation dashboard.
    """

    snapshot_fn: Callable[[], dict]
    nit: "NodeIdentityTable"
    ncp_port: int
    cfg: "NodeConfig"
    usd: "UnifiedSystemDomain"
    on_ncp_failure: Optional[Callable[[str], None]] = None
    mutation_apply_fn: Optional[
        Callable[[str, str, bool], Awaitable[tuple[bool, str]]]
    ] = None


class _StateHolder:
    """Module-level singleton container.

    Using a class attribute instead of a module-level variable means the write
    in :func:`set_state` is visible to all importers of this module.

    Attributes:
        web_state: The active :class:`WebState`, or ``None`` before initialisation.
    """

    web_state: Optional["WebState"] = None


_STATE = _StateHolder()


def get_state() -> Optional["WebState"]:
    """Return the active :class:`WebState`, or ``None`` before initialisation.

    Returns:
        Optional[WebState]: The shared state, or None.
    """
    return _STATE.web_state


def set_state(state: "WebState") -> None:
    """Store the daemon's live state so the web views can access it.

    Args:
        state: Initialised :class:`WebState` from the running daemon.
    """
    _STATE.web_state = state

"""Internal module — heartbeat loop for NodeDaemon.

Provides :func:`_heartbeat_loop`, which periodically:

- Reads resource metrics and updates ``daemon.node.reference_load``.
- Marks USD nodes whose NIT entry has expired as ``INACTIVE_TIMEOUT``.
- Purges expired NIT entries.

This module is private to the USMD-RDSH daemon subsystem.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from ._daemon_helpers import _HEARTBEAT_INTERVAL, _get_resource_usage
from ._daemon_mutation_hosting import refresh_mutation_hosting
from .mutation.dependency_rank import best_node_for_dependency
from .node.state import NodeState

if TYPE_CHECKING:
    from .node_daemon import NodeDaemon

logger = logging.getLogger(__name__)

# ANSI: red heart marker on every heartbeat line; load colour by USD thresholds.
_RED_HEART = "\x1b[31m\u2665\x1b[0m"
_LOAD_GREEN = "\x1b[32m"
_LOAD_YELLOW = "\x1b[33m"
_LOAD_RED = "\x1b[31m"
_ANSI_RESET = "\x1b[0m"


def _format_reference_load_for_log(
    load: float,
    load_threshold: float,
    emergency_threshold: float,
) -> str:
    """Format reference load with a colour from USD config (normal / weakened / emergency).

    - Below ``load_threshold``: green.
    - From ``load_threshold`` up to (but not including) ``emergency_threshold``: yellow.
    - At or above ``emergency_threshold``: red.

    Values are clamped to ``[0, 1]``.
    """
    load_c = max(0.0, min(1.0, load))
    lt = max(0.0, min(1.0, load_threshold))
    et = max(0.0, min(1.0, emergency_threshold))
    if load_c >= et:
        color = _LOAD_RED
    elif load_c >= lt:
        color = _LOAD_YELLOW
    else:
        color = _LOAD_GREEN
    return f"{color}{load_c:.1%}{_ANSI_RESET}"


async def _heartbeat_loop(daemon: "NodeDaemon") -> None:
    """Periodically update resource load and purge stale NIT entries.

    Runs until the enclosing asyncio task is cancelled.

    Args:
        daemon: The running :class:`NodeDaemon` instance.
    """
    while True:
        try:
            usage = _get_resource_usage()
            daemon.node.reference_load = usage.reference_load()

            # Mark USD nodes as INACTIVE_TIMEOUT when their NIT entry expires.
            # The NIT TTL acts as the liveness signal: no HIA → no refresh → expired.
            expired_addresses = {
                entry.address
                for entry in daemon.nit.iter_all_entries()
                if entry.is_expired()
            }
            for peer_node in daemon.usd.nodes.values():
                if (
                    peer_node.address in expired_addresses
                    and peer_node.address != daemon.node.address
                    and peer_node.state.is_active()
                ):
                    peer_node.set_state(NodeState.INACTIVE_NNDP_NO_HIA)
                    daemon.nrt.remove(peer_node.address)
                    logger.info(
                        "[\x1b[38;5;51mUSMD\x1b[0m] Node %d (%s) → "
                        "INACTIVE_NNDP_NO_HIA (NIT entry expired — no HIA received)",
                        peer_node.name,
                        peer_node.address,
                    )

            purged = daemon.nit.purge_expired()
            if purged:
                logger.debug(
                    "[\x1b[38;5;51mUSMD\x1b[0m] NIT purged %d expired entries",
                    purged,
                )

            await refresh_mutation_hosting(daemon, poll_peers=True, force_peer_poll=False)

            cfg = daemon.usd.config
            load_str = _format_reference_load_for_log(
                daemon.node.reference_load,
                cfg.load_threshold,
                cfg.emergency_threshold,
            )
            logger.debug(
                "[\x1b[38;5;51mUSMD\x1b[0m] %s Heartbeat: state=%s load=%s nit=%d",
                _RED_HEART,
                daemon.node.state.value,
                load_str,
                len(daemon.nit),
            )

            iv = float(daemon.usd.config.dependency_check_interval)
            if iv > 0 and daemon.consume_monotonic_gate("dependency_check", iv):
                for hsvc in daemon.node.iter_hosted_service_names():
                    svc = daemon.usd.mutation_catalog.get(hsvc)
                    if svc and svc.dependencies:
                        for dep in svc.dependencies:
                            best = best_node_for_dependency(
                                daemon.usd,
                                dep,
                                exclude_name=daemon.node.name,
                            )
                            if best is not None:
                                logger.debug(
                                    "[\x1b[38;5;51mUSMD\x1b[0m] "
                                    "dependency %s → best node %d (load=%.3f)",
                                    dep,
                                    best.name,
                                    best.reference_load,
                                )
        except Exception as exc:
            logger.warning(
                "[\x1b[38;5;51mUSMD\x1b[0m] %s Heartbeat error: %s",
                _RED_HEART,
                exc,
            )
        await asyncio.sleep(_HEARTBEAT_INTERVAL)

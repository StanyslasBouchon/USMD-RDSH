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
from .node.state import NodeState

if TYPE_CHECKING:
    from .node_daemon import NodeDaemon

logger = logging.getLogger(__name__)


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
                        "[\x1b[38;5;51mUSMD\x1b[0m] Nœud %d (%s) → "
                        "INACTIVE_NNDP_NO_HIA (entrée NIT expirée — aucun HIA reçu)",
                        peer_node.name,
                        peer_node.address,
                    )

            purged = daemon.nit.purge_expired()
            if purged:
                logger.debug(
                    "[\x1b[38;5;51mUSMD\x1b[0m] NIT purged %d expired entries",
                    purged,
                )

            load_str = f"{daemon.node.reference_load:.1%}"
            logger.debug(
                "[\x1b[38;5;51mUSMD\x1b[0m] Heartbeat: state=%s load=%s nit=%d",
                daemon.node.state.value,
                load_str,
                len(daemon.nit),
            )
        except Exception as exc:
            logger.warning("[\x1b[38;5;51mUSMD\x1b[0m] Heartbeat error: %s", exc)
        await asyncio.sleep(_HEARTBEAT_INTERVAL)

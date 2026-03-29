"""Daemon peer-discovery and NCP-failure helpers.

- :func:`_on_peer_discovered` — NNDP HIA callback: registers the peer in NIT
  and USD, reactivates inactive nodes, queues pending-join entries.
- :func:`_mark_peer_inactive` — NCP failure callback: marks all active USD
  nodes at the given address as INACTIVE_TIMEOUT and removes their NRT entry.

Both functions only access *public* attributes and methods of the daemon.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from ._daemon_nrt import _update_nrt_for_peer
from .node.node import Node
from .node.state import NodeState
from .nndp.protocol.here_i_am import HereIAmPacket

if TYPE_CHECKING:
    from .node_daemon import NodeDaemon

logger = logging.getLogger(__name__)


def _on_peer_discovered(daemon: "NodeDaemon", packet: HereIAmPacket, ip: str) -> None:
    """Called by the NNDP listener when a valid HIA packet arrives.

    Registers the peer in the NIT (refreshing its TTL), then either updates
    the existing USD node entry or creates a new one.  If the daemon has not
    yet joined the network, the peer is queued via :meth:`NodeDaemon.add_pending_peer`.

    Args:
        daemon: The running :class:`NodeDaemon` instance.
        packet: Decoded HIA packet from the peer.
        ip: Source IP address of the packet.
    """
    daemon.nit.register(ip, packet.sender_pub_key, ttl=int(packet.data.ttl) * 3)
    logger.info(
        "[\x1b[38;5;51mUSMD\x1b[0m] Peer discovered: %s key=%s",
        ip,
        packet.sender_pub_key.hex()[:16] + "…",
    )

    peer_node = daemon.usd.get_node(packet.sender_name)
    if peer_node is not None:
        if peer_node.address != ip:
            peer_node.address = ip
        if peer_node.state == NodeState.INACTIVE_TIMEOUT:
            peer_node.set_state(NodeState.ACTIVE)
            logger.info(
                "[\x1b[38;5;51mUSMD\x1b[0m] Nœud %d (%s) → ACTIVE (HIA)",
                packet.sender_name,
                ip,
            )
    else:
        daemon.usd.add_node(
            Node(address=ip, name=packet.sender_name, state=NodeState.ACTIVE)
        )

    if not daemon.is_joined:
        daemon.add_pending_peer(packet, ip)

    if ip != daemon.node.address:
        try:
            asyncio.get_running_loop().create_task(
                _update_nrt_for_peer(daemon, ip),
                name=f"nrt-update-{ip}",
            )
        except RuntimeError:
            pass  # No running loop (unit-test context)


def _mark_peer_inactive(daemon: "NodeDaemon", address: str) -> None:
    """Mark all active USD nodes at *address* as INACTIVE_TIMEOUT.

    Called whenever an outgoing NCP request to *address* fails.  The local
    node is never affected.  The peer's NRT entry is also removed.

    Args:
        daemon: The running :class:`NodeDaemon` instance.
        address: IP address of the unresponsive peer.
    """
    for peer_node in daemon.usd.nodes.values():
        if (
            peer_node.address == address
            and peer_node.address != daemon.node.address
            and peer_node.state.is_active()
        ):
            peer_node.set_state(NodeState.INACTIVE_TIMEOUT)
            logger.info(
                "[\x1b[38;5;51mUSMD\x1b[0m] Nœud %d (%s) → INACTIVE_TIMEOUT "
                "(échec requête NCP sortante)",
                peer_node.name,
                address,
            )
    daemon.nrt.remove(address)

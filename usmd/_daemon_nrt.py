"""Internal module — NRT update and reference node selection for NodeDaemon.

Provides two async helpers:

- :func:`_update_nrt_for_peer` — sends a CHECK_DISTANCE NCP request to one
  peer, measures the round-trip ping, and updates the local NRT.
- :func:`_update_reference_nodes` — recomputes the set of reference nodes
  from the NRT and broadcasts ``INFORM_REFERENCE_NODE`` to affected peers.

This module is private to the USMD-RDSH daemon subsystem.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from .ncp.client.tcp import NcpClient
from .ncp.protocol.commands.check_distance import (
    CheckDistanceRequest,
    CheckDistanceResponse,
)
from .ncp.protocol.commands.inform_reference_node import InformReferenceNodeRequest
from .ncp.protocol.frame import NcpCommandId

if TYPE_CHECKING:
    from .node_daemon import NodeDaemon

logger = logging.getLogger(__name__)


async def _update_nrt_for_peer(daemon: "NodeDaemon", address: str) -> None:
    """Send CHECK_DISTANCE to *address* and record the result in the NRT.

    Args:
        daemon: The running :class:`NodeDaemon` instance.
        address: IP address of the peer to measure.
    """
    sent_at = time.time()
    req = CheckDistanceRequest(sent_at_ms=int(sent_at * 1000))
    client = NcpClient(
        address=address,
        port=daemon.cfg.ncp_port,
        timeout=daemon.cfg.ncp_timeout,
    )
    result = await client.send(NcpCommandId.CHECK_DISTANCE, req.to_payload())
    if result.is_err():
        logger.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] NRT: CHECK_DISTANCE to %s failed: %s",
            address,
            result.unwrap_err(),
        )
        return
    ping_ms = (time.time() - sent_at) * 1000.0
    parsed  = CheckDistanceResponse.from_payload(result.unwrap().payload)
    if parsed.is_ok():
        daemon.nrt.update(address, parsed.unwrap().distance, ping_ms)
        logger.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] NRT: %s → d=%.4f ping=%.1fms",
            address,
            parsed.unwrap().distance,
            ping_ms,
        )
        # Recompute reference node selection after every NRT change.
        await _update_reference_nodes(daemon)


def _log_ref_change(
    new_ref_names: list[int],
    added_names: set[int],
    removed_names: set[int],
    name_to_addr: dict[int, str],
) -> None:
    """Emit an INFO log describing what changed in the reference node selection."""
    def fmt(names: set[int]) -> str:
        return ", ".join(f"#{n} ({name_to_addr.get(n, '?')})" for n in names)

    parts = []
    if added_names:
        parts.append(f"+[{fmt(added_names)}]")
    if removed_names:
        parts.append(f"-[{fmt(removed_names)}]")
    logger.info(
        "[\x1b[38;5;51mUSMD\x1b[0m] Nœuds de référence → %s  (%s)",
        [f"#{n}" for n in new_ref_names] or "aucun",
        "  ".join(parts) if parts else "inchangé",
    )


async def _update_reference_nodes(
    daemon: "NodeDaemon",
) -> None:
    """Recompute reference nodes from the NRT and notify affected peers via NCP.

    Selects the ``cfg.max_reference_nodes`` closest peers from the NRT
    (sorted by distance d).  If the selection changed since the last call,
    the new names are stored in ``daemon.node.reference_nodes`` and each
    affected peer receives an ``INFORM_REFERENCE_NODE`` message.

    Peers removed from the list also receive the updated (shorter) list so
    they can drop this node from their own NRL.

    Args:
        daemon: The running :class:`NodeDaemon` instance.
    """
    max_refs: int = daemon.cfg.max_reference_nodes

    # Build address → node-name map from USD (skip ourselves)
    addr_to_name: dict[str, int] = {}
    for peer in daemon.usd.nodes.values():
        if (
            peer.address != daemon.node.address
            and peer.address not in addr_to_name
        ):
            addr_to_name[peer.address] = peer.name

    # Pick the top-N NRT entries (already sorted by distance asc)
    new_ref_names:     list[int] = []
    new_ref_addresses: list[str] = []
    for entry in daemon.nrt.get_all():
        if len(new_ref_names) >= max_refs:
            break
        name = addr_to_name.get(entry["address"])
        if name is not None:
            new_ref_names.append(name)
            new_ref_addresses.append(entry["address"])

    old_ref_set = set(daemon.node.reference_nodes)
    new_ref_set = set(new_ref_names)

    if old_ref_set == new_ref_set:
        return  # Nothing changed — no NCP messages needed

    daemon.node.reference_nodes = new_ref_names

    added_names   = new_ref_set - old_ref_set
    removed_names = old_ref_set - new_ref_set
    name_to_addr: dict[int, str] = {
        n.name: n.address for n in daemon.usd.nodes.values()
    }
    _log_ref_change(new_ref_names, added_names, removed_names, name_to_addr)

    # Determine all addresses to notify (new + removed references)
    notify_addresses: set[str] = set(new_ref_addresses)
    for peer in daemon.usd.nodes.values():
        if peer.name in removed_names:
            notify_addresses.add(peer.address)

    req = InformReferenceNodeRequest(
        sender_name=daemon.node.name,
        sender_address=daemon.node.address,
        reference_names=new_ref_names,
    )
    payload = req.to_payload()

    for addr in notify_addresses:
        if addr == daemon.node.address:
            continue
        client = NcpClient(
            address=addr,
            port=daemon.cfg.ncp_port,
            timeout=daemon.cfg.ncp_timeout,
        )
        result = await client.send(NcpCommandId.INFORM_REFERENCE_NODE, payload)
        if result.is_err():
            logger.debug(
                "[\x1b[38;5;51mUSMD\x1b[0m] INFORM_REFERENCE_NODE → %s échoué: %s",
                addr,
                result.unwrap_err(),
            )
        else:
            logger.info(
                "[\x1b[38;5;51mUSMD\x1b[0m] INFORM_REFERENCE_NODE → %s  "
                "(refs: %s)",
                addr,
                [f"#{n}" for n in new_ref_names],
            )

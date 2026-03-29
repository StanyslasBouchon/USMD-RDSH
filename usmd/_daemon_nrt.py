"""Internal module — NRT update and reference node selection for NodeDaemon.

Provides two async helpers:

- :func:`_update_nrt_for_peer` — sends a CHECK_DISTANCE NCP request to one
  peer, measures the round-trip ping, and updates the local NRT.
- :func:`_update_reference_nodes` — recomputes the set of reference nodes
  from the NRT and broadcasts ``INFORM_REFERENCE_NODE`` to affected peers.

Selection policy (see :func:`_compute_reference_names`):

- Up to ``cfg.max_reference_nodes`` peers, preferring lowest distance *d*.
- Peers already selected stay in the set for ``cfg.reference_hold_seconds``
  (default 5 minutes), unless a **not**-selected peer has a **strictly**
  lower distance (preemption): then the worse current peer is replaced.
- After preemption stabilises, any remaining slots are filled with the
  closest peers not yet selected.

This module is private to the USMD-RDSH daemon subsystem.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Callable

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


def _usd_addr_to_peer_name(daemon: "NodeDaemon") -> dict[str, int]:
    """Map each remote peer address to its USD node name (first name wins)."""
    addr_to_name: dict[str, int] = {}
    for peer in daemon.usd.nodes.values():
        if peer.address == daemon.node.address or peer.address in addr_to_name:
            continue
        addr_to_name[peer.address] = peer.name
    return addr_to_name


# ---------------------------------------------------------------------------
# Selection helpers (keep each function well under the branch limit)
# ---------------------------------------------------------------------------


def _collect_sticky(
    old_names: list[int],
    by_name_dist: dict[int, float],
    since: dict[int, float],
    now: float,
    hold: float,
) -> list[int]:
    """Return old reference names that are still inside the hold window.

    Args:
        old_names: Previous reference node names.
        by_name_dist: Mapping of node name → current distance (from NRT).
        since: Mapping of node name → monotonic time it entered the set.
        now: Current monotonic time.
        hold: ``reference_hold_seconds`` grace period.

    Returns:
        Deduplicated list of names still within the hold window.
    """
    seen: set[int] = set()
    result: list[int] = []
    for n in old_names:
        if n not in by_name_dist or n in seen:
            continue
        seen.add(n)
        if now - since.get(n, 0.0) < hold:
            result.append(n)
    return result


def _run_preemption(
    result: list[int],
    result_set: set[int],
    candidates: list[tuple[int, str, float]],
    max_k: int,
    dist_fn: Callable[[int], float],
) -> None:
    """Iteratively replace the worst current peer if a better candidate exists.

    Modifies *result* and *result_set* in place.

    Args:
        result: Current selection (mutable).
        result_set: Fast-lookup mirror of *result* (mutable).
        candidates: ``(name, address, distance)`` sorted by distance asc.
        max_k: Maximum number of reference nodes.
        dist_fn: Callable that returns the distance for a node name.
    """
    changed = True
    while changed:
        changed = False
        for n, _addr, d in candidates:
            if n in result_set:
                continue
            if len(result) < max_k:
                result.append(n)
                result_set.add(n)
                changed = True
                continue
            worst_n = max(result, key=dist_fn)
            if d < dist_fn(worst_n):
                result.remove(worst_n)
                result_set.remove(worst_n)
                result.append(n)
                result_set.add(n)
                changed = True


def _compute_reference_names(
    candidates: list[tuple[int, str, float]],
    old_names: list[int],
    since: dict[int, float],
    now: float,
    hold: float,
    max_k: int,
) -> list[int]:
    """Pick reference peer names from NRT-ordered candidates.

    Args:
        candidates: ``(node_name, address, distance)`` sorted by distance
            ascending (same order as :meth:`NodeReferenceTable.get_all`).
        old_names: Previous ``reference_nodes`` name list.
        since: ``node_name → monotonic time`` when that name entered the set.
        now: Current monotonic time.
        hold: ``reference_hold_seconds`` — keep peers unless preempted.
        max_k: ``max_reference_nodes``.

    Returns:
        New reference node names, sorted by ascending distance.

    Examples:
        >>> _compute_reference_names([], [], {}, 0.0, 300.0, 5)
        []
        >>> _compute_reference_names([], [], {}, 0.0, 300.0, 0)
        []
    """
    if max_k <= 0:
        return []

    by_name_dist: dict[int, float] = {n: d for n, _, d in candidates}
    if not by_name_dist:
        return []

    def dist(n: int) -> float:
        return by_name_dist[n]

    must_keep = _collect_sticky(old_names, by_name_dist, since, now, hold)
    must_keep.sort(key=dist)
    result: list[int] = list(must_keep)
    while len(result) > max_k:
        result.remove(max(result, key=dist))
    result_set = set(result)

    _run_preemption(result, result_set, candidates, max_k, dist)

    for n, _addr, _d in candidates:
        if len(result) >= max_k:
            break
        if n not in result_set:
            result.append(n)
            result_set.add(n)

    return sorted(result, key=dist)


# ---------------------------------------------------------------------------
# NRT peer update
# ---------------------------------------------------------------------------


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
    parsed = CheckDistanceResponse.from_payload(result.unwrap().payload)
    if parsed.is_ok():
        daemon.nrt.update(address, parsed.unwrap().distance, ping_ms)
        logger.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] NRT: %s → d=%.4f ping=%.1fms",
            address,
            parsed.unwrap().distance,
            ping_ms,
        )
        await _update_reference_nodes(daemon)


# ---------------------------------------------------------------------------
# Reference node update helpers
# ---------------------------------------------------------------------------


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


def _build_nrt_candidates(
    daemon: "NodeDaemon",
) -> list[tuple[int, str, float]]:
    """Build ``(node_name, address, distance)`` candidates from NRT + USD.

    Entries for this node's own address are excluded.

    Args:
        daemon: The running :class:`NodeDaemon` instance.

    Returns:
        List of ``(name, address, distance)`` sorted by distance ascending.
    """
    addr_to_name = _usd_addr_to_peer_name(daemon)
    candidates: list[tuple[int, str, float]] = []
    for entry in daemon.nrt.get_all():
        name = addr_to_name.get(entry["address"])
        if name is not None:
            candidates.append((name, entry["address"], entry["distance"]))
    return candidates


async def _send_inform_reference_node(
    daemon: "NodeDaemon",
    addresses: set[str],
    new_ref_names: list[int],
) -> None:
    """Send INFORM_REFERENCE_NODE to each address in *addresses*.

    Best-effort: failures are logged at DEBUG level and never raised.

    Args:
        daemon: The running :class:`NodeDaemon` instance.
        addresses: Set of IP addresses to notify.
        new_ref_names: Updated reference node name list to broadcast.
    """
    req = InformReferenceNodeRequest(
        sender_name=daemon.node.name,
        sender_address=daemon.node.address,
        reference_names=new_ref_names,
    )
    payload = req.to_payload()
    for addr in addresses:
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
                "[\x1b[38;5;51mUSMD\x1b[0m] INFORM_REFERENCE_NODE → %s (refs: %s)",
                addr,
                [f"#{n}" for n in new_ref_names],
            )


async def _update_reference_nodes(
    daemon: "NodeDaemon",
) -> None:
    """Recompute reference nodes from the NRT and notify affected peers via NCP.

    Uses :func:`_compute_reference_names` for sticky selection, then stores
    ``daemon.node.reference_nodes`` and sends ``INFORM_REFERENCE_NODE`` to
    new references and to peers that were just removed from the list.

    Args:
        daemon: The running :class:`NodeDaemon` instance.
    """
    candidates = _build_nrt_candidates(daemon)
    now = time.monotonic()
    old_names = list(daemon.node.reference_nodes)

    new_ref_names = _compute_reference_names(
        candidates,
        old_names,
        daemon.reference_since,
        now,
        daemon.cfg.reference_hold_seconds,
        daemon.cfg.max_reference_nodes,
    )

    old_ref_set = set(old_names)
    new_ref_set = set(new_ref_names)

    if old_ref_set == new_ref_set:
        return

    for n in new_ref_names:
        if n not in old_ref_set:
            daemon.reference_since[n] = now
    for n in old_names:
        if n not in new_ref_set:
            daemon.reference_since.pop(n, None)

    daemon.node.reference_nodes = new_ref_names

    added_names = new_ref_set - old_ref_set
    removed_names = old_ref_set - new_ref_set
    name_to_addr: dict[int, str] = {
        p.name: p.address for p in daemon.usd.nodes.values()
    }
    _log_ref_change(new_ref_names, added_names, removed_names, name_to_addr)

    name_set = set(name_to_addr)
    new_ref_addrs = {name_to_addr[n] for n in new_ref_names if n in name_set}
    removed_addrs = {name_to_addr[n] for n in removed_names if n in name_set}
    await _send_inform_reference_node(
        daemon, new_ref_addrs | removed_addrs, new_ref_names)

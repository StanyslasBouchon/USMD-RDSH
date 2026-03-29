"""Collect and normalise node snapshots for the web dashboard (NCP + cache)."""

from __future__ import annotations

import asyncio
import copy
import logging
import time
from typing import Iterable

from ..ncp.client.tcp import NcpClient
from ..ncp.protocol.commands.request_snapshot import (
    RequestSnapshotRequest,
    RequestSnapshotResponse,
)
from ..ncp.protocol.frame import NcpCommandId
from .state import get_state

logger = logging.getLogger(__name__)

_SNAPSHOT_CACHE: dict[str, tuple[dict, float]] = {}  # address → (data, ts)
_CACHE_TTL = 8.0  # seconds before re-querying

_STATE_REASONS: dict[str, str] = {
    "inactive": "Inactive",
    "inactive_timeout": "NCP timeout exceeded",
    "inactive_nndp_no_here_i_am": "No HIA received",
    "inactive_mutating": "Mutating",
    "inactive_emergency": "Emergency",
    "inactive_emergency_out_of_resources": "Insufficient resources",
    "inactive_emergency_dependency_inactive": "Inactive dependency",
    "inactive_emergency_health_check_failed": "Health check failed",
    "inactive_emergency_update_failed": "Update failed",
    "excluded_invalid_nit": "Invalid NIT (excluded)",
    "excluded_invalid_endorsement": "Invalid endorsement (excluded)",
    "excluded_unverifiable_endorsement": "Unverifiable endorsement (excluded)",
    "excluded_invalid_revocation": "Invalid revocation (excluded)",
    "excluded_invalid_endorsement_revocation": "Invalid endorsement revocation (excluded)",
}


def _get_state_reason(state_value: str) -> str:
    """Return a human-readable label for a NodeState value."""
    return _STATE_REASONS.get(state_value, "")


def _ensure_mutation_fields(snap: dict) -> None:
    """Older snapshots may omit mutation catalogue / execution fields."""
    snap.setdefault("mutations", [])
    snap.setdefault("service_execution_log", [])


def _normalize_nrt_rows(snap: dict, usd_nodes: Iterable | None = None) -> None:
    """Ensure each NRT row exposes ``node_name`` for templates / JSON clients.

    - Rows are **shallow-copied** into a new list so we never mutate lists that
      may still be referenced from the snapshot cache.
    - If the key ``node_name`` is **absent** (older daemons), it is derived from
      the USD of the node hosting the dashboard (best effort).
    - If the key is present with value ``None`` (JSON ``null``), it is **left
      unchanged**: that is the source node's truth and must not be replaced
      from local USD (otherwise the NRT "reference" column would lie).
    """
    nrt = snap.get("nrt")
    if not nrt:
        return
    addr_to_name: dict[str, int] = {}
    if usd_nodes is not None:
        for n in usd_nodes:
            a = getattr(n, "address", None)
            if a and a not in addr_to_name:
                addr_to_name[a] = n.name
    out: list = []
    for row in nrt:
        if not isinstance(row, dict):
            out.append(row)
            continue
        r = dict(row)
        if "node_name" not in r:
            addr = r.get("address")
            r["node_name"] = addr_to_name.get(addr) if addr else None
        out.append(r)
    snap["nrt"] = out


def invalidate_snapshot_cache(address: str) -> None:
    """Remove any cached snapshot for *address* (e.g. after a node goes inactive)."""
    _SNAPSHOT_CACHE.pop(address, None)


def _build_inactive_stub(address: str, usd_node) -> dict:
    """Build a minimal snapshot dict for a node known to be inactive.

    Avoids any NCP poll while still surfacing the node on the dashboard.
    """
    state_val = usd_node.state.value
    return {
        "is_local": False,
        "node": {
            "address": address,
            "name": usd_node.name,
            "state": state_val,
            "state_reason": _get_state_reason(state_val),
            "role": "unknown",
            "uptime_seconds": 0,
        },
        "resources": {
            "cpu_percent": 0.0,
            "ram_percent": 0.0,
            "disk_percent": 0.0,
            "network_percent": 0.0,
            "reference_load": 0.0,
        },
        "usd": {},
        "nit": [],
        "nal": [],
        "nel": [],
        "nrt": [],
        "nrl": [],
        "reference_nodes": [],
        "quorum": {"elected_roles": [], "promotions": []},
        "mutations": [],
        "service_execution_log": [],
    }


async def _fetch_remote_snapshot(address: str, ncp_port: int) -> dict | None:
    """Fetch a snapshot from a remote node via NCP REQUEST_SNAPSHOT."""
    now = time.time()
    cached, ts = _SNAPSHOT_CACHE.get(address, ({}, 0.0))
    if cached and now - ts < _CACHE_TTL:
        # Deep copy: views must never mutate the cached object
        # (otherwise NRT / normalization would "stick" across requests and TTL).
        return copy.deepcopy(cached)

    client = NcpClient(address=address, port=ncp_port, timeout=3.0)
    result = await client.send(
        NcpCommandId.REQUEST_SNAPSHOT,
        RequestSnapshotRequest().to_payload(),
    )
    if result.is_err():
        logger.debug("REQUEST_SNAPSHOT to %s failed: %s", address, result.unwrap_err())
        invalidate_snapshot_cache(address)
        # Do not call on_ncp_failure here: the web server must not change the
        # daemon's internal state (NRT or USD) on dashboard polling failure.
        # The daemon manages peer lifecycle itself (NNDP heartbeat,
        # _mark_peer_inactive). Calling on_ncp_failure from here caused two
        # regressions:
        #   1. nrt.remove(address) → NRT entry cleared → "Ref. node" column
        #      flickering until the next successful CHECK_DISTANCE.
        #   2. peer marked INACTIVE_TIMEOUT → resolve_node_snapshot returned
        #      an empty stub → NRL table always empty on the dashboard.
        return None

    resp = RequestSnapshotResponse.from_payload(result.unwrap().payload)
    if resp.is_err():
        return None

    data = resp.unwrap().snapshot
    _SNAPSHOT_CACHE[address] = (data, now)
    return copy.deepcopy(data)


async def collect_all_nodes() -> list[dict]:
    """Collect snapshots from the local node + all peers.

    Inactive nodes (state != ACTIVE in the USD) are included as lightweight
    stub entries without any NCP poll.  Only nodes whose USD state is active
    (or whose state is unknown, e.g. not yet registered in the USD) are queried
    via NCP REQUEST_SNAPSHOT.
    """
    state = get_state()

    local_snap = state.snapshot_fn()
    local_snap["is_local"] = True
    nodes = [local_snap]

    local_addr = local_snap.get("node", {}).get("address", "")

    addr_to_usd_node = {
        n.address: n
        for n in state.usd.nodes.values()
        if n.address != local_addr
    }

    nit_addrs = {
        entry.address
        for entry in state.nit.iter_all_entries()
        if entry.address != local_addr
    }
    all_remote_addrs = nit_addrs | set(addr_to_usd_node.keys())

    active_addrs: list[str] = []
    for addr in all_remote_addrs:
        usd_node = addr_to_usd_node.get(addr)
        if usd_node is not None and not usd_node.state.is_active():
            nodes.append(_build_inactive_stub(addr, usd_node))
        else:
            active_addrs.append(addr)

    tasks = [_fetch_remote_snapshot(addr, state.ncp_port) for addr in active_addrs]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for addr, snap in zip(active_addrs, results):
        if isinstance(snap, dict) and snap:
            snap["is_local"] = False
            nodes.append(snap)

    usd_node_list = list(state.usd.nodes.values())
    for node_snap in nodes:
        node_info = node_snap.get("node")
        if isinstance(node_info, dict):
            node_info.setdefault(
                "state_reason", _get_state_reason(node_info.get("state", ""))
            )
        _normalize_nrt_rows(node_snap, usd_node_list)
        _ensure_mutation_fields(node_snap)

    return nodes


def extract_promotions(nodes: list[dict]) -> list[dict]:
    """Aggregate and deduplicate quorum promotions from all node snapshots.

    Args:
        nodes: List of node snapshot dicts (each may contain ``quorum.promotions``).

    Returns:
        list[dict]: Deduplicated promotions sorted newest first.
    """
    seen: set[tuple] = set()
    all_promotions: list[dict] = []
    for snap in nodes:
        for promo in snap.get("quorum", {}).get("promotions", []):
            key = (promo.get("epoch"), promo.get("address"))
            if key not in seen:
                seen.add(key)
                all_promotions.append(promo)
    all_promotions.sort(key=lambda p: p.get("promoted_at", 0.0), reverse=True)
    return all_promotions


async def resolve_node_snapshot(address: str) -> tuple[dict | None, str | None]:
    """Load the status snapshot for *address* (local shortcut, stub, or NCP).

    Returns:
        ``(snapshot, None)`` on success, or ``(None, error_message)`` if the
        active remote peer is unreachable.
    """
    state = get_state()
    local_addr = state.snapshot_fn().get("node", {}).get("address", "")
    if address in (local_addr, "local"):
        snap = state.snapshot_fn()
        snap["is_local"] = True
    else:
        usd_node = next(
            (n for n in state.usd.nodes.values() if n.address == address),
            None,
        )
        if usd_node is not None and not usd_node.state.is_active():
            snap = _build_inactive_stub(address, usd_node)
        else:
            snap = await _fetch_remote_snapshot(address, state.ncp_port)
            if not snap:
                return None, f"Node {address} unreachable."
            snap["is_local"] = False
            node_info = snap.get("node")
            if isinstance(node_info, dict):
                node_info.setdefault(
                    "state_reason", _get_state_reason(node_info.get("state", ""))
                )

    _normalize_nrt_rows(snap, list(state.usd.nodes.values()))
    return snap, None

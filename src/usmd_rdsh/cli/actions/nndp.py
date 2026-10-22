"""``show nndp``, ``show nndp neighbors``, ``show nndp services``,
``clear nndp neighbors``, ``execute nndp restart`` [NNDP-01]."""

from __future__ import annotations

from nan_actions import action
from pydantic import BaseModel

from usmd_rdsh.cli.permissions import READ, WRITE
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.actions.overview import with_reason
from usmd_rdsh.cli.text import fields, printer, table
from usmd_rdsh.node import addresses
from usmd_rdsh.node.states import State
from usmd_rdsh.node.wire import now_ms


@action(cli="show nndp", description="NNDP status, ports and counters", permissions=[READ],
        cli_output=printer(lambda r: fields([
            ("NNDP", f"{'enabled' if r['enabled'] else 'disabled'}, "
                     f"{'running' if r['running'] else 'stopped'}"),
            ("Ports", f"HIA from UDP {r['source_port']} to UDP {r['destination_port']}, "
                      "broadcast and unicast to reference nodes"),
            ("HIA interval", f"{r['hia_interval']} s (inactive after {2 * r['hia_interval']} s)"),
            ("Freshness window", f"{r['freshness_window']} s"),
            ("HIA sent / accepted / rejected", f"{r['sent']} / {r['received']} / {r['rejected']}"),
            ("Last rejection", r["last_rejection"] or "-"),
            ("Neighbours", r["neighbors"]),
            ("Nearest-service entries", r["vector_entries"]),
        ])))
async def show_nndp() -> dict:
    """NNDP status, ports and counters."""
    node = RUNTIME.node
    service = node.nndp if node else None
    settings = node.settings if node else None
    return {
        "enabled": bool(settings and settings.nndp_enabled),
        "running": bool(service and service.running),
        "source_port": settings.nndp_source_port if settings else 5221,
        "destination_port": settings.nndp_destination_port if settings else 5222,
        "hia_interval": settings.hia_interval if settings else 15,
        "freshness_window": settings.nndp_freshness_s if settings else 30,
        "sent": service.sent if service else 0,
        "received": service.received if service else 0,
        "rejected": service.rejected if service else 0,
        "last_rejection": service.last_rejection if service else "",
        "neighbors": len(service.neighbors) if service else 0,
        "vector_entries": sum(len(r) for r in service.services.entries.values()) if service else 0,
    }


class NeighborRow(BaseModel):
    node_id: str
    address: str
    state: str
    hosted: str
    last_seen: int
    hold: int
    status: str


def neighbor_rows() -> list[dict]:
    """Every (key, address) heard; shared with the web interface."""
    node = RUNTIME.node
    if node is None or node.nndp is None:
        return []
    now = now_ms()
    rows = []
    for n in sorted(node.nndp.neighbors.values(), key=lambda x: x.node_id):
        try:
            state = State(n.state).name
        except ValueError:
            state = f"0x{n.state:04X}"
        rows.append({
            "node_id": n.node_id,
            "address": n.address,
            "state": state,
            "state_code": f"0x{n.state:04X}",
            "hosted": " ".join(addresses.to_text(a) for a in n.hosted),
            "last_seen": int((now - n.received_at) / 1000),
            "hold": max(0, int((n.deadline - now) / 1000)),
            "status": "inactive (0x3400)" if n.inactive else "up",
        })
    return rows


@action(cli="show nndp neighbors", description="Nodes heard by NNDP", permissions=[READ],
        rows=NeighborRow,
        cli_output=printer(with_reason(lambda rows: table(rows, [
            ("node_id", "Node ID"), ("address", "Address"), ("state", "Declared state"),
            ("hosted", "Hosted"), ("last_seen", "Seen(s)"), ("hold", "Hold(s)"),
            ("status", "Status"),
        ]) + f"\n\nTotal neighbours: {len(rows)}")))
async def show_nndp_neighbors() -> list[dict]:
    """Nodes heard by NNDP, and the time left before 0x3400 [NNDP 6.3]."""
    return neighbor_rows()


class NearestRow(BaseModel):
    service: str
    instance: str
    distance: int
    hops: int
    learned_from: str
    expires: int


def nearest_rows() -> list[dict]:
    node = RUNTIME.node
    if node is None or node.nndp is None:
        return []
    catalog = node.signed.catalog()
    now = now_ms()
    names = {e.key: e.record.node_id for e in node.tables.nodes.entries.values()}
    rows = []
    for service, entries in sorted(node.nndp.services.entries.items()):
        for e in entries:
            rows.append({
                "service": catalog[service].name if service in catalog else f"{service:03x}",
                "instance": addresses.to_text(e.address),
                "distance": e.distance,
                "hops": e.hops,
                "learned_from": "local" if e.learned_from is None
                else names.get(e.learned_from, e.learned_from.hex()[:12]),
                "expires": -1 if e.expires is None else max(0, int((e.expires - now) / 1000)),
            })
    return rows


@action(cli="show nndp services", description="Nearest services table [NNDP 6.5]",
        permissions=[READ], rows=NearestRow,
        cli_output=printer(with_reason(lambda rows: table(rows, [
            ("service", "Service"), ("instance", "Instance"), ("distance", "D (permille)"),
            ("hops", "Hops"), ("learned_from", "Learned from"), ("expires", "Expires(s)"),
        ]))))
async def show_nndp_services() -> list[dict]:
    """K instances per service of our areas, with distance and hops."""
    return nearest_rows()


@action(cli="clear nndp neighbors", description="Forget every neighbour heard by NNDP",
        permissions=[WRITE])
async def clear_nndp_neighbors() -> dict:
    """Forget neighbours; they reappear at their next HIA."""
    node = RUNTIME.node
    count = len(node.nndp.neighbors) if node and node.nndp else 0
    if node and node.nndp:
        node.nndp.neighbors.clear()
    return {"cleared": count}


@action(cli="execute nndp restart", description="Restart NNDP", permissions=[WRITE])
async def execute_nndp_restart() -> dict:
    """Close and reopen the NNDP sockets."""
    node = RUNTIME.node
    if node is not None:
        await node.restart_nndp()
    return {"running": bool(node and node.nndp and node.nndp.running)}

"""``show nndp``, ``show nndp neighbors``, ``clear nndp neighbors``, ``execute nndp restart``."""

from __future__ import annotations

import time

from nan_actions import action
from pydantic import BaseModel

from usmd_rdsh.cli.permissions import READ, WRITE
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.text import fields, printer, table


class NeighborRow(BaseModel):
    """One NNDP neighbour."""

    node_id: str
    address: str
    state: str
    state_code: str
    last_seen: int
    expires_in: int
    status: str


@action(cli="show nndp", description="NNDP status, ports and counters", permissions=[READ],
        cli_output=printer(lambda r: fields([
            ("NNDP", f"{'enabled' if r['enabled'] else 'disabled'}, "
                     f"{'running' if r['running'] else 'stopped'}"),
            ("Ports", f"HIA sent to UDP {r['client_port']}, from UDP {r['server_port']}"),
            ("HIA interval", f"{r['hia_interval']} s"),
            ("Inactivity delay", f"{2 * r['hia_interval']} s (2 x I)"),
            ("Freshness window", f"{r['freshness_window']} s"),
            ("HIA sent / received", f"{r['hia_sent']} / {r['hia_received']}"),
            ("Neighbours", r["neighbors"]),
        ])))
async def show_nndp() -> dict:
    """NNDP status, ports and counters."""
    core = RUNTIME.core
    config = RUNTIME.config("protocol nndp")
    return {
        "enabled": config.status,
        "running": bool(core and core.is_running()),
        "client_port": config.client_port,
        "server_port": config.server_port,
        "hia_interval": config.hia_interval,
        "freshness_window": config.freshness_window,
        "hia_sent": core.hia_sent if core else 0,
        "hia_received": core.hia_received if core else 0,
        "neighbors": len(core.neighbors) if core else 0,
    }


def neighbor_rows() -> list[dict]:
    """Every neighbour heard from; shared with the web interface."""
    core = RUNTIME.core
    if core is None:
        return []
    now = time.time()
    rows = []
    for node_id, (hia, seen) in sorted(core.neighbors.items()):
        deadline = hia.next_hia_pkt_time / 1000 + core.hia_tolerance
        rows.append({
            "node_id": node_id,
            "address": hia.ip,
            "state": hia.state.name,
            "state_code": f"0x{hia.state.value:04X}",
            "last_seen": int(now - seen),
            "expires_in": int(deadline - now),
            # [ARCH 5.5] 0x3400: no HIA within the announced time.
            "status": "up" if now <= deadline else "timeout (0x3400)",
        })
    return rows


@action(cli="show nndp neighbors", description="Nodes heard by NNDP", permissions=[READ],
        rows=NeighborRow,
        cli_output=printer(lambda rows: table(rows, [
            ("node_id", "Node ID"), ("address", "Address"), ("state", "Declared state"),
            ("last_seen", "Seen(s)"), ("expires_in", "Hold(s)"), ("status", "Status"),
        ]) + f"\n\nTotal neighbours: {len(rows)}"))
async def show_nndp_neighbors() -> list[dict]:
    """Nodes heard by NNDP, with the time left before they are considered gone."""
    return neighbor_rows()


@action(cli="clear nndp neighbors", description="Forget every neighbour heard by NNDP",
        permissions=[WRITE])
async def clear_nndp_neighbors() -> dict:
    """Forget every neighbour; they reappear at their next HIA."""
    core = RUNTIME.core
    count = len(core.neighbors) if core else 0
    if core is not None:
        core.neighbors.clear()
    return {"cleared": count}


@action(cli="execute nndp restart", description="Restart the NNDP client and server",
        permissions=[WRITE])
async def execute_nndp_restart() -> dict:
    """Restart the NNDP services."""
    core = RUNTIME.core
    if core is None:
        return {"restarted": False}
    core.stop()
    if core.nndp_enabled:
        core.start()
    return {"restarted": core.nndp_enabled, "running": core.is_running()}

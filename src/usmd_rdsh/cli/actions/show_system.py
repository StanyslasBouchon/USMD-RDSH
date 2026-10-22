"""``show version``, ``show clock``, ``show node``, ``show node states``, ``show load``."""

from __future__ import annotations

import asyncio
import platform
import socket
import sys
import time
from datetime import datetime
from importlib import metadata

import psutil
from nan_actions import action

from usmd_rdsh.cli.permissions import READ
from usmd_rdsh.cli.runtime import RUNTIME, format_duration
from usmd_rdsh.cli.text import fields, printer, table
from usmd_rdsh.proto.base.env import NNDP_VERSION, PROTO_MAGIC
from usmd_rdsh.utils.node_state import NodeState


def _version() -> str:
    try:
        return metadata.version("USMD-RDSH")
    except metadata.PackageNotFoundError:
        return "0.0.0"


@action(cli="show version", description="Software, platform and uptime", permissions=[READ],
        cli_output=printer(lambda r: (
            f"USMD-RDSH Software, Version {r['version']}\n"
            f"Frame magic 0x{r['magic']:04X}, NNDP version {r['nndp_version']}\n\n"
            f"{r['hostname']} uptime is {r['uptime']}\n"
            f"Node ID {r['node_id']}\n"
            f"Running on {r['platform']}, Python {r['python']}\n"
            f"{r['cpus']} CPU(s), {r['memory_mb']} MB of memory\n"
            f"Configuration file is {r['config_file']}"
        )))
async def show_version() -> dict:
    """Software, platform and uptime."""
    return {
        "version": _version(),
        "magic": PROTO_MAGIC,
        "nndp_version": NNDP_VERSION,
        "hostname": RUNTIME.hostname(),
        "uptime": format_duration(RUNTIME.uptime()),
        "node_id": RUNTIME.core.properties.node_id if RUNTIME.core else None,
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python": sys.version.split()[0],
        "cpus": psutil.cpu_count(),
        "memory_mb": psutil.virtual_memory().total // (1024 * 1024),
        "config_file": str(RUNTIME.config_store.path),
    }


@action(cli="show clock", description="Local time (all protocols need it within 30 s)",
        permissions=[READ], cli_output=printer(lambda r: r["display"]))
async def show_clock() -> dict:
    """Local time."""
    now = datetime.now().astimezone()
    return {
        "time": now.isoformat(timespec="milliseconds"),
        "display": "*" + now.strftime("%H:%M:%S.") + f"{now.microsecond // 1000:03d} "
        + now.strftime("%Z %a %b %d %Y"),
    }


def _state_label(state: NodeState) -> str:
    return f"{state.name} (0x{state.value:04X})"


def _local_ip() -> str:
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "unknown"


@action(cli="show node", description="Identity, declared state and keys of this node",
        permissions=[READ], cli_output=printer(lambda r: fields([
            ("Hostname", r["hostname"]),
            ("Node ID", r["node_id"]),
            ("State", r["state"]),
            ("Role", r["role"]),
            ("Address", r["address"]),
            ("USD", r["usd"] or "(not configured)"),
            ("USC", r["usc"] or "(not configured)"),
            ("Ed25519 public key", r["ed25519_public_key"]),
            ("NNDP", r["nndp"]),
            ("Neighbours", r["neighbors"]),
            ("Uptime", r["uptime"]),
        ])))
async def show_node() -> dict:
    """Identity, declared state and keys of this node."""
    core = RUNTIME.core
    bootstrap = RUNTIME.config("system bootstrap")
    return {
        "hostname": RUNTIME.hostname(),
        "node_id": core.properties.node_id if core else None,
        "state": _state_label(core.state) if core else None,
        "state_code": f"0x{core.state.value:04X}" if core else None,
        "role": str(bootstrap.role),
        "address": _local_ip(),
        "usd": RUNTIME.config("usd").name,
        "usc": RUNTIME.config("usc").name,
        "ed25519_public_key": core.properties.self_ed25519_keypair.pub32_b64u if core else None,
        "nndp": ("running" if core and core.is_running() else "stopped") if core else None,
        "neighbors": len(core.neighbors) if core else 0,
        "uptime": format_duration(RUNTIME.uptime()),
    }


#: [ARCH 5.5]: D = declared by the node, O = observed by a peer.
_ORIGIN = {
    NodeState.INACTIVE_TIMEOUT: "O",
    NodeState.INACTIVE_NNDP_HERE_I_AM_TIMEOUT: "O",
}


def state_origin(state: NodeState) -> str:
    """D or O, per the registry of [ARCH] section 5.5."""
    if state.value >= 0x4000:
        return "O"
    return _ORIGIN.get(state, "D")


@action(cli="show node states", description="Node state registry [ARCH 5.5]",
        permissions=[READ], cli_output=printer(lambda rows: table(
            rows, [("code", "Code"), ("name", "State"), ("origin", "Origin"),
                   ("current", "")])))
async def show_node_states() -> list[dict]:
    """Node state registry."""
    current = RUNTIME.core.state if RUNTIME.core else None
    return [
        {
            "code": f"0x{state.value:04X}",
            "name": state.name,
            "origin": state_origin(state),
            "current": "<- current" if state is current else "",
        }
        for state in NodeState
    ]


def _network_per_mille() -> int:
    """Observed throughput over the nominal speed of the busiest interface."""
    before = psutil.net_io_counters(pernic=True)
    stats = psutil.net_if_stats()
    time.sleep(0.2)
    after = psutil.net_io_counters(pernic=True)
    best = 0
    for nic, counters in after.items():
        speed = stats.get(nic).speed if stats.get(nic) else 0
        if not speed or nic not in before:
            continue
        delta = (counters.bytes_sent + counters.bytes_recv
                 - before[nic].bytes_sent - before[nic].bytes_recv)
        bits_per_s = delta * 8 / 0.2
        best = max(best, int(bits_per_s / (speed * 1_000_000) * 1000))
    return min(best, 1000)


def measure_load() -> dict:
    """The four rates of [ARCH 6.1], per mille, and the reference load."""
    rates = {
        "memory": int(psutil.virtual_memory().percent * 10),
        "cpu": int(psutil.cpu_percent(interval=0.2) * 10),
        "disk": int(psutil.disk_usage("/").percent * 10),
        "network": _network_per_mille(),
    }
    usd = RUNTIME.config("usd")
    reference = max(rates.values())
    status = "normal"
    if reference >= usd.emergency_threshold:
        status = "emergency"
    elif reference >= usd.weakened_threshold:
        status = "weakened"
    return {
        **rates,
        "reference": reference,
        "weakened_threshold": usd.weakened_threshold,
        "emergency_threshold": usd.emergency_threshold,
        "status": status,
    }


@action(cli="show load", description="Resource rates and reference load [ARCH 6.1]",
        permissions=[READ], cli_output=printer(lambda r: fields([
            ("Memory", f"{r['memory']} permille"),
            ("CPU", f"{r['cpu']} permille"),
            ("Disk", f"{r['disk']} permille"),
            ("Network", f"{r['network']} permille"),
            ("Reference load", f"{r['reference']} permille"),
            ("Thresholds", f"weakened {r['weakened_threshold']}, "
                           f"emergency {r['emergency_threshold']}"),
            ("Status", r["status"]),
        ])))
async def show_load() -> dict:
    """Instantaneous measure; the protocol smooths over the last three samples."""
    return await asyncio.to_thread(measure_load)

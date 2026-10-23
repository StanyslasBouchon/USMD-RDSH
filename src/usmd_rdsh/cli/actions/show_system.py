"""``show version``, ``show clock``, ``show node``, ``show node states``,
``show node events``, ``show load``."""

from __future__ import annotations

import platform
import sys
from datetime import datetime
from importlib import metadata

import psutil
from nan_actions import action

from usmd_rdsh.cli.permissions import READ
from usmd_rdsh.cli.runtime import RUNTIME, format_duration
from usmd_rdsh.cli.text import fields, printer, table
from usmd_rdsh.node.crypto import b64u
from usmd_rdsh.node.signed import parameter
from usmd_rdsh.node.states import LABELS, State
from usmd_rdsh.node.wire import MAGIC, VERSION


def _version() -> str:
    """Four components major.feature.security.fix [ARCH 10.2]."""
    try:
        text = metadata.version("USMD-RDSH")
    except metadata.PackageNotFoundError:
        text = "0.0.0.0"
    parts = (text.split(".") + ["0", "0", "0", "0"])[:4]
    return ".".join(parts)


@action(cli="show version", description="Software, platform and uptime", permissions=[READ],
        cli_output=printer(lambda r: (
            f"USMD-RDSH Software, Version {r['version']}\n"
            f"Frame magic 0x{r['magic']:04X}, protocol version {r['protocol_version']} "
            f"(NNDP-01, NCP-02, SP-01, ARCH-02)\n\n"
            f"{r['hostname']} uptime is {r['uptime']}\n"
            f"Node ID {r['node_id']}\n"
            f"Running on {r['platform']}, Python {r['python']}\n"
            f"{r['cpus']} CPU(s), {r['memory_mb']} MB of memory\n"
            f"Configuration file is {r['config_file']}"
        )))
async def show_version() -> dict:
    """Software, platform and uptime."""
    node = RUNTIME.node
    return {
        "version": _version(),
        "magic": MAGIC,
        "protocol_version": VERSION,
        "hostname": RUNTIME.hostname(),
        "uptime": format_duration(RUNTIME.uptime()),
        "node_id": node.node_id if node else None,
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python": sys.version.split()[0],
        "cpus": psutil.cpu_count(),
        "memory_mb": psutil.virtual_memory().total // (1024 * 1024),
        "config_file": str(RUNTIME.config_store.path),
    }


@action(cli="show clock", description="Local time (protocols require it within 30 s)",
        permissions=[READ], cli_output=printer(lambda r: r["display"]))
async def show_clock() -> dict:
    """Local time."""
    now = datetime.now().astimezone()
    return {
        "time": now.isoformat(timespec="milliseconds"),
        "display": "*" + now.strftime("%H:%M:%S.") + f"{now.microsecond // 1000:03d} "
        + now.strftime("%Z %a %b %d %Y"),
    }


def state_text(state: State) -> str:
    return f"{state.name} (0x{state.value:04X})"


def _named(r: dict, which: str) -> str:
    """``dho (01JAB7...)``: the signed label, then the identifier [NCP-03 6.8]."""
    if not r[which]:
        return "(not configured)"
    return f"{r[which + '_label']} ({r[which]})" if r[which + "_label"] else r[which]


@action(cli="show node", description="Identity, state, keys and roles of this node",
        permissions=[READ], cli_output=printer(lambda r: fields([
            ("Hostname", r["hostname"]),
            ("Node ID", r["node_id"]),
            ("State", r["state"]),
            ("Admitted", "yes" if r["admitted"] else "no"),
            ("Endorser", r["endorser"] or "-"),
            ("Role", r["role"]),
            ("Address", r["address"]),
            ("Mutation", r["mutation"] or "(none)"),
            ("Hosted services", ", ".join(r["hosted"]) or "(none)"),
            ("SP addresses", ", ".join(r["sp_addresses"]) or "(none)"),
            ("Reference nodes", ", ".join(r["references"]) or "(none)"),
            ("USD", _named(r, "usd")),
            ("USC", _named(r, "usc")),
            ("Ed25519 public key", r["ed25519_public_key"]),
            ("X25519 public key", r["x25519_public_key"]),
            ("Creation token", r["token"]),
            ("Uptime", r["uptime"]),
        ])))
async def show_node() -> dict:
    """Identity, declared state and keys of this node."""
    node = RUNTIME.node
    if node is None:
        return {"hostname": RUNTIME.hostname(), "node_id": None}
    from usmd_rdsh.node import addresses  # pylint: disable=import-outside-toplevel

    catalog = node.signed.catalog()
    token = node.token
    return {
        "hostname": RUNTIME.hostname(),
        "node_id": node.node_id,
        "state": state_text(node.state),
        "state_code": f"0x{node.state.value:04X}",
        "admitted": node.admitted,
        "endorser": b64u(node.endorser) if node.endorser else None,
        "role": node.settings.role.name.lower().replace("_", "-"),
        "address": node.settings.address,
        "mutation": node.mutation,
        "hosted": sorted(catalog[s].name for s in node.hosted if s in catalog),
        "sp_addresses": [addresses.to_text(addresses.pack(s, m))
                         for s, m in sorted(node.management.items())],
        "references": list(node.references),
        "usd": node.signed.usd.usdn if node.signed.usd else "",
        "usc": node.signed.usc.uscn if node.signed.usc else "",
        "usd_label": node.signed.usd.label if node.signed.usd else "",
        "usc_label": node.signed.usc.label if node.signed.usc else "",
        "ed25519_public_key": b64u(node.key),
        "x25519_public_key": b64u(node.identity.x25519_public),
        "token": ("none" if token is None else
                  f"{'founder, ' if token.founder else ''}expires "
                  f"{datetime.fromtimestamp(token.expires / 1000):%Y-%m-%d %H:%M}"),
        "uptime": format_duration(RUNTIME.uptime()),
    }


@action(cli="show node states", description="Node state registry [ARCH 5.5]",
        permissions=[READ], cli_output=printer(lambda rows: table(
            rows, [("code", "Code"), ("name", "State"), ("origin", "Origin"),
                   ("label", "Meaning"), ("current", "")])))
async def show_node_states() -> list[dict]:
    """Node state registry."""
    current = RUNTIME.node.state if RUNTIME.node else None
    return [
        {
            "code": f"0x{state.value:04X}",
            "name": state.name,
            "origin": "O" if state.observed else "D",
            "label": LABELS[state],
            "current": "<- current" if state is current else "",
        }
        for state in State
    ]


@action(cli="show node events", description="What the node did lately (procedures)",
        permissions=[READ], cli_output=printer(lambda rows: "\n".join(r["event"] for r in rows)))
async def show_node_events() -> list[dict]:
    """The node's recent procedure events."""
    return [{"event": e} for e in (RUNTIME.node.events if RUNTIME.node else [])]


def load_view() -> dict:
    """The monitor's smoothed rates and the node's judgement [ARCH 6.1, 7.1]."""
    node = RUNTIME.node
    monitor = node.load if node else None
    sample = monitor.smoothed() if monitor else None
    usd = node.signed.usd if node else None
    weak, urgent = parameter(usd, 0x0004) or 800, parameter(usd, 0x0005) or 950
    reference = sample.reference if sample else 0
    status = "emergency" if reference >= urgent else "weakened" if reference >= weak else "normal"
    return {
        "memory": sample.memory if sample else 0,
        "cpu": sample.cpu if sample else 0,
        "disk": sample.disk if sample else 0,
        "network": sample.network if sample else 0,
        "reference": reference,
        "samples": [int(r) for r in (monitor.references if monitor else [])],
        "weakened_threshold": weak,
        "emergency_threshold": urgent,
        "status": status,
    }


@action(cli="show load", description="Resource rates and reference load [ARCH 6.1]",
        permissions=[READ], cli_output=printer(lambda r: fields([
            ("Memory", f"{r['memory']} permille"),
            ("CPU", f"{r['cpu']} permille"),
            ("Disk", f"{r['disk']} permille"),
            ("Network", f"{r['network']} permille"),
            ("Reference load", f"{r['reference']} permille (last samples {r['samples']})"),
            ("Thresholds", f"weakened {r['weakened_threshold']}, "
                           f"emergency {r['emergency_threshold']}"),
            ("Status", r["status"]),
        ])))
async def show_load() -> dict:
    """Smoothed over the last three samples, taken every 0x0007 seconds."""
    return load_view()

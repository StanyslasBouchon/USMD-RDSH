"""IOS-style overviews: ``show tables``, ``show protocols``, ``show interfaces``,
``show ip route``, ``show processes``, ``show users``, ``show tech-support``.

Also :func:`empty_reason`: why a table is empty on this node, printed under
an empty table instead of leaving the operator with headers and nothing else.
"""

from __future__ import annotations

import time

import psutil
from nan_actions import action
from nan_runtime.log import emit

from usmd_rdsh.cli.permissions import READ
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.text import fields, printer, table
from usmd_rdsh.node.signed import parameter
from usmd_rdsh.node.states import State


def empty_reason() -> str:
    """One line saying why the node's tables are still empty, or ""."""
    node = RUNTIME.node
    if node is None:
        return "The node is not running (console started with -c)."
    if not node._tasks:  # pylint: disable=protected-access
        return "The node's protocols are not started (console started with -c)."
    if node.state == State.APPROVAL_REQUIRED:
        if node.token is None:
            return ("Not admitted yet and no creation token: 'execute node token install "
                    "token=<...>' (or 'config system bootstrap'), then 'execute node admission'.")
        return "Not admitted yet: waiting for an admitted node ('show node events')."
    if node.nndp is None or not node.nndp.running:
        failure = next((e for e in reversed(node.events) if "NNDP" in e), "")
        return "NNDP is not running" + (f": {failure}" if failure else ".")
    return ""


def with_reason(render):
    """Wrap a table renderer: an empty table says why."""

    def output(rows) -> str:
        text = render(rows)
        if not rows:
            reason = empty_reason()
            if reason:
                text += f"\n% {reason}"
        return text

    return output


@action(cli="show tables", description="Every table of the node and its size", permissions=[READ],
        cli_output=printer(with_reason(lambda rows: table(rows, [
            ("table", "Table"), ("entries", "Entries"), ("command", "Show with"),
            ("reference", "Draft")]))))
async def show_tables() -> list[dict]:
    """The node's tables, with the command that shows each one."""
    node = RUNTIME.node
    if node is None:
        return []
    nndp, sp, raft = node.nndp, node.sp, node.raft
    rows = [
        ("NIT", sum(len(e.addresses) for e in node.tables.nit.entries.values()),
         "show nit", "ARCH 4.3"),
        ("NAL", len(node.tables.nal.roles), "show nal", "ARCH 4.3"),
        ("NEL", len(node.tables.nel), "show nel", "NCP 7.1"),
        ("Node table", len(node.tables.nodes.entries), "show node-table", "NCP 7.8"),
        ("Exclusions", len(node.tables.exclusions.by_key), "show exclusions", "ARCH 5.5"),
        ("Reference nodes", len(node.references), "show references", "ARCH 6.3"),
        ("NNDP neighbours", len(nndp.neighbors) if nndp else 0, "show nndp neighbors",
         "NNDP 6.2"),
        ("Nearest services", sum(len(r) for r in nndp.services.entries.values()) if nndp else 0,
         "show nndp services", "NNDP 6.5"),
        ("SP addresses", sum(len(e.record.sp_addresses) for e in node.tables.nodes.entries.values()),
         "show sp addresses", "SP 4.3"),
        ("SP sessions", len(sp.sessions) if sp else 0, "show sp sessions", "SP 7"),
        ("SP flows", len(sp.flows.flows) if sp else 0, "show sp flows", "SP 6.3"),
        ("Master assignments", len(raft.state.assignments) if raft else 0,
         "show usd assignments", "ARCH 12"),
        ("Service catalogue", len(node.signed.catalog()), "show service catalog", "ARCH 11.1"),
        ("Mutations", len(node.signed.mutations), "show mutation status", "ARCH 8"),
        ("Log buffer", len(RUNTIME.logbuffer.messages()), "show logging", "-"),
    ]
    return [{"table": t, "entries": n, "command": c, "reference": r} for t, n, c, r in rows]


@action(cli="show protocols", description="NNDP, NCP, SP and Raft at a glance", permissions=[READ],
        cli_output=printer(lambda rows: table(rows, [
            ("protocol", "Protocol"), ("status", "Status"), ("port", "Port"),
            ("detail", "Detail")])))
async def show_protocols() -> list[dict]:
    node = RUNTIME.node
    if node is None:
        return []
    nndp, sp, raft, ncp = node.nndp, node.sp, node.raft, node.ncp
    sp_port = parameter(node.signed.usd, 0x0010)
    return [
        {"protocol": "NNDP", "status": "running" if nndp and nndp.running else "down",
         "port": f"{node.settings.nndp_source_port}->{node.settings.nndp_destination_port}",
         "detail": f"{len(nndp.neighbors) if nndp else 0} neighbours, HIA every "
                   f"{node.settings.hia_interval}s"},
        {"protocol": "NCP", "status": "listening" if ncp and ncp._transport else "down",  # pylint: disable=protected-access
         "port": str(node.settings.ncp_port),
         "detail": ", ".join(f"{k} {v}" for k, v in (ncp.stats.items() if ncp else []))},
        {"protocol": "SP", "status": "running" if sp else
         ("no port (USD 0x0010)" if sp_port is None else "down"),
         "port": str(sp_port or "-"),
         "detail": f"{len(sp.sessions)} sessions, interface {node.tun.kind}" if sp and node.tun
         else ""},
        {"protocol": "Raft", "status": raft.role if raft and raft.is_voter else "not a voter",
         "port": "(NCP)", "detail": f"term {raft.term}, master {raft.leader or '?'}" if raft else ""},
    ]


@action(cli="show interfaces", description="Network interfaces and the SP interface",
        permissions=[READ], cli_output=printer(lambda rows: table(rows, [
            ("interface", "Interface"), ("status", "Status"), ("addresses", "IPv4"),
            ("mtu", "MTU"), ("speed", "Speed (Mb/s)")])))
async def show_interfaces() -> list[dict]:
    stats = psutil.net_if_stats()
    rows = []
    for name, addrs in sorted(psutil.net_if_addrs().items()):
        link = stats.get(name)
        rows.append({
            "interface": name,
            "status": "up" if link and link.isup else "down",
            "addresses": " ".join(a.address for a in addrs if a.family.name == "AF_INET"),
            "mtu": link.mtu if link else "",
            "speed": link.speed if link else "",
        })
    node = RUNTIME.node
    if node is not None and node.tun is not None and node.tun.kind != "memory":
        rows.append({"interface": f"usmd-sp ({node.tun.kind})", "status": "up",
                     "addresses": " ".join(node.sp_vips()),
                     "mtu": parameter(node.signed.usd, 0x0013), "speed": ""})
    elif node is not None:
        # No system interface: say why, rather than leave the services' VIPs unexplained.
        rows.append({"interface": "usmd-sp", "status": "down",
                     "addresses": node.sp_problem() or "simulated in memory",
                     "mtu": "", "speed": ""})
    return rows


@action(cli="show ip route", description="Routes of the SP interface [SP-01 5.1]",
        permissions=[READ], cli_output=printer(lambda rows: table(rows, [
            ("prefix", "Prefix"), ("interface", "Interface"), ("source", "Source")])
            + ("" if rows else "\n% No SP route: this node hosts no mutation with a service area.")))
async def show_ip_route() -> list[dict]:
    node = RUNTIME.node
    if node is None:
        return []
    return [{"prefix": r, "interface": "usmd-sp",
             "source": "group addresses" if r.startswith("239.") else "service area"}
            for r in node.sp_routes()]


@action(cli="show processes", description="Service sequences run by this node [ARCH 8]",
        permissions=[READ], cli_output=printer(lambda rows: table(rows, [
            ("service", "Service"), ("sequence", "Sequence"), ("result", "Result"),
            ("duration", "Duration (s)")])
            + ("" if rows else "\n% No service sequence has run on this node yet.")))
async def show_processes() -> list[dict]:
    node = RUNTIME.node
    if node is None:
        return []
    return [{"service": s, "sequence": q, "result": "ok" if r.ok else "FAILED",
             "duration": round(r.duration, 1)} for (s, q), r in node.runner.last.items()]


@action(cli="show users", description="Who can reach the management plane", permissions=[READ],
        cli_output=printer(lambda rows: table(rows, [
            ("user", "User"), ("kind", "Access"), ("profile", "Profile"),
            ("last_seen", "Last seen")])))
async def show_users() -> list[dict]:
    rows = [{"user": "console", "kind": "local console", "profile": "all",
             "last_seen": "now"}]
    for token in RUNTIME.tokens.all():
        seen = RUNTIME.tokens.last_used.get(token.key_id)
        rows.append({"user": token.name, "kind": f"web/API token {token.key_id}",
                     "profile": token.profile,
                     "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(seen))
                     if seen else "never"})
    return rows


_TECH_SUPPORT = (
    "show version", "show clock", "show node", "show protocols", "show tables", "show load",
    "show references", "show node-table", "show nit", "show nal", "show nel", "show exclusions",
    "show nndp", "show nndp neighbors", "show nndp services", "show ncp statistics",
    "show usd parameters", "show usd master", "show service catalog", "show mutation status",
    "show sp", "show sp sessions", "show sp addresses", "show interfaces", "show ip route",
    "show processes", "show node events", "show running-config", "show logging",
)


@action(cli="show tech-support", description="Every show command, one after another",
        permissions=[READ], cli_output=lambda result: None)
async def show_tech_support() -> dict:
    """What support asks for first: the output of every ``show``."""
    from nan_actions import registry  # pylint: disable=import-outside-toplevel

    for line in _TECH_SUPPORT:
        emit(f"\n------------------ {line} ------------------\n")
        definition = registry.get_by_cli_path(*line.split())
        if definition is None:
            continue
        schema = definition.input_schema
        result = await (definition.handler(schema()) if schema else definition.handler())
        if definition.cli_output is not None:
            definition.cli_output(result)
        else:
            emit(fields(list(result.items())) if isinstance(result, dict) else str(result))
    return {"sections": len(_TECH_SUPPORT)}

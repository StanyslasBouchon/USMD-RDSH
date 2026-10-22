"""Trust tables [ARCH-02 4.3]: ``show nit``, ``show nal``, ``show nel``,
``show node-table``, ``show exclusions``, ``show references``, ``clear exclusions``."""

from __future__ import annotations

import time

from nan_actions import action
from pydantic import BaseModel, Field

from usmd_rdsh.cli.permissions import READ, WRITE
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.actions.overview import with_reason
from usmd_rdsh.cli.text import printer, table
from usmd_rdsh.node import addresses
from usmd_rdsh.node.crypto import b64u, unb64u
from usmd_rdsh.node.ncp.codec import Role
from usmd_rdsh.node.states import State
from usmd_rdsh.node.wire import now_ms


def _short(key: str) -> str:
    return key if len(key) <= 16 else f"{key[:8]}...{key[-6:]}"


def _when(ms: int | None) -> str:
    return "-" if not ms else time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ms / 1000))


def _roles(roles) -> str:
    return ", ".join(Role(r).name.lower().replace("_", "-") for r in sorted(roles) if r in (1, 2, 3, 4))


class NitRow(BaseModel):
    node_id: str
    address: str
    public_key: str
    ttl: str


def nit_rows() -> list[dict]:
    node = RUNTIME.node
    if node is None:
        return []
    now = now_ms()
    rows = []
    for entry in node.tables.nit.entries.values():
        for address, expiry in entry.addresses.items():
            rows.append({
                "node_id": entry.node_id or "?",
                "address": address,
                "public_key": b64u(entry.ed25519),
                "ttl": "node table" if expiry == 0 else f"{max(0, (expiry - now) // 1000)}s",
            })
    return sorted(rows, key=lambda r: r["node_id"])


@action(cli="show nit", description="Node Identity Table", permissions=[READ], rows=NitRow,
        cli_output=printer(with_reason(lambda rows: table(
            [{**r, "public_key": _short(r["public_key"])} for r in rows],
            [("node_id", "Node ID"), ("address", "Address"), ("public_key", "Ed25519 key"),
             ("ttl", "TTL")]) + f"\n\nTotal entries: {len(rows)}")))
async def show_nit() -> list[dict]:
    """Key, identifier, address and validity; a key may have several addresses."""
    return nit_rows()


class NalRow(BaseModel):
    public_key: str
    node_id: str
    roles: str
    anchor: bool


@action(cli="show nal", description="Node Access List", permissions=[READ], rows=NalRow,
        cli_output=printer(with_reason(lambda rows: table(
            [{**r, "public_key": _short(r["public_key"]), "anchor": "anchor" if r["anchor"] else ""}
             for r in rows],
            [("public_key", "Ed25519 key"), ("node_id", "Node"), ("roles", "Roles"),
             ("anchor", "")]) + f"\n\nTotal entries: {len(rows)}")))
async def show_nal() -> list[dict]:
    """Key and roles; trust anchors are permanent [ARCH 4.4]."""
    node = RUNTIME.node
    if node is None:
        return []
    out = []
    for key, roles in node.tables.nal.roles.items():
        entry = node.tables.nodes.get(key)
        out.append({"public_key": b64u(key), "node_id": entry.record.node_id if entry else "",
                    "roles": _roles(roles), "anchor": key in node.tables.nal.anchors})
    return out


class NelRow(BaseModel):
    node_id: str
    serial: str
    expiration: str
    roles: str


@action(cli="show nel", description="Endorsement packets issued by this node [NCP 7.1]",
        permissions=[READ], rows=NelRow,
        cli_output=printer(with_reason(lambda rows: table(rows, [
            ("node_id", "Endorsed node"), ("serial", "Serial"), ("expiration", "Expires"),
            ("roles", "Roles")]) + f"\n\nTotal entries: {len(rows)}")))
async def show_nel() -> list[dict]:
    node = RUNTIME.node
    return [{"node_id": p.node_id, "serial": p.serial.hex(), "expiration": _when(p.expiration),
             "roles": _roles(p.roles)} for p in (node.tables.nel if node else [])]


class TableRow(BaseModel):
    node_id: str
    address: str
    declared: str
    observed: str
    mutation: str
    references: str
    sp_addresses: str
    voter: bool
    load: str
    record_date: str


def node_table_rows() -> list[dict]:
    node = RUNTIME.node
    if node is None:
        return []
    rows = []
    for e in node.tables.nodes.sorted():
        try:
            declared = State(e.record.state).name
        except ValueError:
            declared = f"0x{e.record.state:04X}"
        observed = node.observed.get(e.key)
        excluded = node.tables.exclusions.by_key.get(e.key)
        rows.append({
            "node_id": e.record.node_id + (" (self)" if e.key == node.key else ""),
            "address": e.record.address,
            "declared": declared,
            "observed": (excluded.state.name if excluded else observed.name if observed else ""),
            "mutation": e.record.mutation,
            "references": " ".join(e.record.reference_nodes),
            "sp_addresses": " ".join(addresses.to_text(a) for a in e.record.sp_addresses),
            "voter": e.record.voter,
            "load": "" if e.record.node_id not in node.loads
            else f"{node.loads[e.record.node_id]}",
            "record_date": _when(e.record.date),
        })
    return rows


@action(cli="show node-table", description="The USD's node table [NCP 7.8, 7.9]",
        permissions=[READ], rows=TableRow,
        cli_output=printer(with_reason(lambda rows: table(rows, [
            ("node_id", "Node ID"), ("address", "Address"), ("declared", "Declared"),
            ("observed", "Observed"), ("mutation", "Mutation"), ("sp_addresses", "SP addresses"),
            ("voter", "Voter"), ("load", "Load"), ("record_date", "Record date")])
        + f"\n\nTotal nodes: {len(rows)}")))
async def show_node_table() -> list[dict]:
    """Every node of the USD: its latest signed record and what we observe."""
    return node_table_rows()


@action(cli="show exclusions", description="Keys excluded locally (family 0x4000)",
        permissions=[READ], cli_output=printer(lambda rows: table(rows, [
            ("public_key", "Ed25519 key"), ("state", "State"), ("since", "Since"),
            ("until", "Until")])))
async def show_exclusions() -> list[dict]:
    node = RUNTIME.node
    if node is None:
        return []
    return [{"public_key": b64u(k), "state": f"{v.state.name} (0x{v.state.value:04X})",
             "since": _when(v.since), "until": "permanent" if v.until is None else _when(v.until)}
            for k, v in node.tables.exclusions.by_key.items()]


class ClearExclusion(BaseModel):
    public_key: str = Field("", description="Key to readmit (base64url); empty for all")


@action(cli="clear exclusions", description="Lift local exclusions", permissions=[WRITE],
        cli_confirm="Lift exclusion(s)? {public_key}")
async def clear_exclusions(data: ClearExclusion) -> dict:
    node = RUNTIME.node
    if node is None:
        return {"cleared": 0}
    if data.public_key:
        removed = node.tables.exclusions.by_key.pop(unb64u(data.public_key), None)
        return {"cleared": int(removed is not None)}
    count = len(node.tables.exclusions.by_key)
    node.tables.exclusions.by_key.clear()
    return {"cleared": count}


@action(cli="show references", description="Reference nodes and distances [ARCH 6]",
        permissions=[READ], cli_output=printer(with_reason(lambda r: table(r["rows"], [
            ("node_id", "Node ID"), ("distance", "Distance d"), ("rtt", "RTT(ms)"),
            ("reference", "Our reference"), ("references_us", "References us")]))))
async def show_references() -> dict:
    """d = p + c + t/T + n for every measured node; NNR closest are references."""
    node = RUNTIME.node
    if node is None:
        return {"rows": []}
    rows = []
    for node_id in sorted(set(node.distances) | set(node.references)):
        key = node.node_key(node_id)
        rtt = node.rtt.get(key) if key else None
        rows.append({
            "node_id": node_id,
            "distance": round(node.distances[node_id], 3) if node_id in node.distances else "-",
            "rtt": round(rtt, 1) if rtt is not None else "-",
            "reference": "yes" if node_id in node.references else "",
            "references_us": "yes" if node.node_id in node.referenced_by.get(node_id, []) else "",
        })
    return {"rows": rows, "references": node.references}

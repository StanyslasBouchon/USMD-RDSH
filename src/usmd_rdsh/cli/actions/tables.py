"""``show nit``, ``show nal``, ``show nel``, ``show unl``: the trust tables [ARCH 4.3]."""

from __future__ import annotations

import base64
import time

from nan_actions import action
from pydantic import BaseModel

from usmd_rdsh.cli.permissions import READ
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.text import printer, table


def _b64u(raw: bytes | str) -> str:
    if isinstance(raw, str):
        return raw
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _short(key: str) -> str:
    return key if len(key) <= 16 else f"{key[:8]}...{key[-6:]}"


class NitRow(BaseModel):
    """One NIT entry."""

    node_id: str
    address: str
    public_key: str
    ttl: int


def nit_rows() -> list[dict]:
    """The NIT; shared with the web interface."""
    if RUNTIME.core is None:
        return []
    now_ms = time.time() * 1000
    return [
        {
            "node_id": entry.node_id,
            "address": entry.node_ip,
            "public_key": _b64u(entry.ed25519_pub32),
            # The stored TTL is an absolute deadline in ms; shown as seconds left.
            "ttl": max(0, int((entry.ttl - now_ms) / 1000)),
        }
        for entry in RUNTIME.core.tables.nit
    ]


@action(cli="show nit", description="Node Identity Table", permissions=[READ], rows=NitRow,
        cli_output=printer(lambda rows: table(
            [{**r, "public_key": _short(r["public_key"])} for r in rows],
            [("node_id", "Node ID"), ("address", "Address"),
             ("public_key", "Ed25519 key"), ("ttl", "TTL(s)")],
        ) + f"\n\nTotal entries: {len(rows)}"))
async def show_nit() -> list[dict]:
    """Node Identity Table: key, identifier, address, time to live."""
    return nit_rows()


class NalRow(BaseModel):
    """One NAL entry."""

    public_key: str
    roles: str


@action(cli="show nal", description="Node Access List", permissions=[READ], rows=NalRow,
        cli_output=printer(lambda rows: table(
            rows, [("public_key", "Ed25519 key"), ("roles", "Roles")],
        ) + f"\n\nTotal entries: {len(rows)}"))
async def show_nal() -> list[dict]:
    """Node Access List: key and roles."""
    if RUNTIME.core is None:
        return []
    return [
        {
            "public_key": entry.ed25519_pub_key_32,
            "roles": ", ".join(role.value.lower().replace("_", "-") for role in entry.roles),
        }
        for entry in RUNTIME.core.tables.nal
    ]


class NelRow(BaseModel):
    """One endorsement packet."""

    serial: str
    expiration: str
    roles: str
    authority: str


@action(cli="show nel", description="Node Endorsement List", permissions=[READ], rows=NelRow,
        cli_output=printer(lambda rows: table(
            [{**r, "authority": _short(r["authority"])} for r in rows],
            [("serial", "Serial"), ("expiration", "Expires"), ("roles", "Roles"),
             ("authority", "Endorser key")],
        ) + f"\n\nTotal entries: {len(rows)}"))
async def show_nel() -> list[dict]:
    """Endorsement packets issued by this node."""
    if RUNTIME.core is None:
        return []
    return [
        {
            "serial": packet.serial,
            "expiration": time.strftime("%Y-%m-%d %H:%M:%S",
                                        time.localtime(packet.expiration / 1000)),
            "roles": ", ".join(role.value.lower().replace("_", "-") for role in packet.roles),
            "authority": packet.authoritative_node_ed25519_pub_key_32,
        }
        for packet in RUNTIME.core.tables.nel
    ]


class UnlRow(BaseModel):
    """One node of the USD node table."""

    node_id: str
    state: str
    services: str
    references: str
    usage_reference: float


@action(cli="show unl", description="USD node table (neighbours, services, load)",
        permissions=[READ], rows=UnlRow,
        cli_output=printer(lambda rows: table(
            rows, [("node_id", "Node ID"), ("state", "State"), ("services", "Services"),
                   ("references", "Reference nodes"), ("usage_reference", "Load")],
        ) + f"\n\nTotal entries: {len(rows)}"))
async def show_unl() -> list[dict]:
    """The node table of the USD, as far as this node knows it."""
    if RUNTIME.core is None:
        return []
    return [
        {
            "node_id": n.node_id,
            "state": n.state.name,
            "services": ", ".join(n.hosted_services),
            "references": ", ".join(n.node_references),
            "usage_reference": n.usage_reference,
        }
        for n in RUNTIME.core.tables.unl
    ]

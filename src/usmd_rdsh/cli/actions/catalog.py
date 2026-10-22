"""``show service catalog``, ``show service-area addresses``, ``show usd master``
[ARCH-02 sections 11 and 12]."""

from __future__ import annotations

import ipaddress

from nan_actions import action
from pydantic import BaseModel

from usmd_rdsh.cli.permissions import READ
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.text import fields, printer, table


class CatalogRow(BaseModel):
    """One catalogue entry, with what is wrong with it."""

    id: str
    name: str
    area: str
    type: str
    vip: str
    group: str
    sp_address: str
    problems: str


def catalog_rows() -> list[dict]:
    """The catalogue, checked against the areas and the dependencies."""
    areas = RUNTIME.config("service-area")
    services = RUNTIME.config("service")
    rows = []
    for service in sorted(services.values(), key=lambda s: s.id):
        problems = []
        area = areas.get(service.area)
        if area is None:
            problems.append(f"unknown area '{service.area}'")
        elif service.vip and ipaddress.IPv4Address(service.vip) not in area.network():
            problems.append(f"VIP outside {area.network()}")
        if not service.vip:
            problems.append("no VIP")
        for dependency in service.dependencies:
            other = services.get(dependency)
            if other is None:
                problems.append(f"dependency '{dependency}' not in catalogue")
            elif other.area != service.area:
                # [ARCH-02 8.4]: areas are isolated, a dependency must share it.
                problems.append(f"dependency '{dependency}' in another area")
        rows.append({
            "id": service.id,
            "name": service.name,
            "area": service.area,
            "type": str(service.type),
            "vip": service.vip,
            "group": service.group,
            "sp_address": f"{service.id}.0000",
            "problems": "; ".join(problems) or "ok",
        })
    return rows


@action(cli="show service catalog", description="Service catalogue, checked [ARCH-02 11.1]",
        permissions=[READ], rows=CatalogRow,
        cli_output=printer(lambda rows: table(rows, [
            ("id", "Id"), ("name", "Service"), ("area", "Area"), ("type", "Type"),
            ("vip", "VIP"), ("group", "Group"), ("problems", "Check")])
            + f"\n\nTotal services: {len(rows)}"))
async def show_service_catalog() -> list[dict]:
    """The services of the USD catalogue and the result of their checks."""
    return catalog_rows()


class AreaRow(BaseModel):
    """One service area."""

    id: int
    name: str
    prefix: str
    addresses: int
    services: int


@action(cli="show service-area summary", description="Service areas and their use",
        permissions=[READ], rows=AreaRow,
        cli_output=printer(lambda rows: table(rows, [
            ("id", "Id"), ("name", "Area"), ("prefix", "Prefix"),
            ("addresses", "Addresses"), ("services", "Services")])))
async def show_service_area_summary() -> list[dict]:
    """Every area, its prefix (all addresses usable) and how many services use it."""
    services = RUNTIME.config("service").values()
    return [
        {
            "id": area.id,
            "name": area.name,
            "prefix": str(area.network()),
            "addresses": area.network().num_addresses,
            "services": sum(1 for s in services if s.area == area.name),
        }
        for area in sorted(RUNTIME.config("service-area").values(), key=lambda a: a.id)
    ]


@action(cli="show usd master", description="USD master and Raft voters [ARCH-02 12]",
        permissions=[READ], cli_output=printer(lambda r: fields([
            ("Master", r["leader"] or "unknown (no election seen)"),
            ("Term", r["term"] if r["term"] is not None else "-"),
            ("Quorum", r["quorum"] if r["quorum"] is not None else "-"),
            ("Voters (Nv)", r["voters"]),
            ("Voter removal delay", f"{r['voter_removal_delay']} s"),
            ("Founder node", "yes" if r["founder"] else "no"),
            ("Raft timers", f"heartbeat {r['raft_heartbeat']} s, "
                            f"election {r['raft_election']} s"),
        ])))
async def show_usd_master() -> dict:
    """What this node knows of the USD master; Raft itself is not implemented yet."""
    usd = RUNTIME.config("usd")
    ncp = RUNTIME.config("protocol ncp")
    raft = getattr(RUNTIME.core, "raft", None)
    return {
        "leader": getattr(raft, "leader_ed25519_pub_key_32", None),
        "term": getattr(raft, "term", None),
        "quorum": getattr(raft, "quorum", None),
        "voters": usd.voters,
        "voter_removal_delay": usd.voter_removal_delay,
        "founder": RUNTIME.config("system bootstrap").founder,
        "raft_heartbeat": ncp.raft_heartbeat,
        "raft_election": f"{ncp.raft_election_min}-{ncp.raft_election_max}",
    }

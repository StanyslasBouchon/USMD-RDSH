"""``show service catalog``, ``show service instances``, ``show service-area summary``,
``show usd master``, ``show mutation status`` [ARCH-02 8, 11, 12]."""

from __future__ import annotations

import ipaddress

from nan_actions import action
from pydantic import BaseModel

from usmd_rdsh.cli.permissions import READ
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.text import fields, printer, table
from usmd_rdsh.node.ncp.codec import OPERATOR_ROLES
from usmd_rdsh.node.signed import parameter


class CatalogRow(BaseModel):
    id: str
    name: str
    area: str
    vip: str
    group: str
    vip_address: str
    instances: int
    hosted_here: bool
    problems: str


def catalog_rows() -> list[dict]:
    """The catalogue in force, checked against the areas and the service files."""
    node = RUNTIME.node
    if node is None or node.signed.usd is None:
        return []
    usd = node.signed.usd
    areas = {a.area_id: a for a in usd.areas}
    networks = node.signed.areas()
    names = {e.name for e in usd.catalog}
    dependencies: dict[str, list[str]] = {}
    for mutation in node.signed.mutations:
        for spec in node.mutation_specs(mutation):
            dependencies[spec.name] = spec.dependencies
    instances: dict[int, int] = {}
    for entry in node.tables.nodes.entries.values():
        for address in entry.record.sp_addresses:
            if (address >> 16) & 0xFFF in [e.service_id for e in usd.catalog]:
                pass
        for name in node.signed.mutation_services(entry.record.mutation):
            svc = node.signed.service_by_name(name)
            if svc is not None:
                instances[svc.service_id] = instances.get(svc.service_id, 0) + 1
    rows = []
    for e in sorted(usd.catalog, key=lambda x: x.service_id):
        problems = []
        if e.area_id not in areas:
            problems.append("unknown area")
        elif ipaddress.IPv4Address(e.vip) not in networks[e.area_id]:
            problems.append("VIP outside its area")
        for dependency in dependencies.get(e.name, []):
            other = node.signed.service_by_name(dependency)
            if dependency not in names or other is None:
                problems.append(f"dependency '{dependency}' not in catalogue")
            elif other.area_id != e.area_id:
                problems.append(f"dependency '{dependency}' in another area [ARCH 8.4]")
        rows.append({
            "id": f"{e.service_id:03x}", "name": e.name,
            "area": areas[e.area_id].name if e.area_id in areas else str(e.area_id),
            "vip": e.vip, "group": "" if e.group == "0.0.0.0" else e.group,
            "vip_address": f"{e.service_id:03x}.0000",
            "instances": instances.get(e.service_id, 0),
            "hosted_here": e.service_id in node.hosted,
            "problems": "; ".join(problems) or "ok",
        })
    return rows


@action(cli="show service catalog", description="Service catalogue in force [ARCH-02 11.1]",
        permissions=[READ], rows=CatalogRow,
        cli_output=printer(lambda rows: table(rows, [
            ("id", "Id"), ("name", "Service"), ("area", "Area"), ("vip", "VIP"),
            ("group", "Group"), ("instances", "Instances"), ("problems", "Check")])
            + f"\n\nTotal services: {len(rows)}"))
async def show_service_catalog() -> list[dict]:
    return catalog_rows()


class InstanceRow(BaseModel):
    service: str
    sp_address: str
    node_id: str
    node_address: str
    state: str
    mutation: str
    nearest: str


def instance_rows() -> list[dict]:
    """Every instance of the USD, from the node table: the nodes whose mutation
    runs the service, with their SP address and state.

    The node table reaches every node; the table of nearest services does not
    (NNDP-01 6.5 keeps only the services of the node's own areas), so this is
    where a node without a mutation sees who hosts what.
    """
    node = RUNTIME.node
    if node is None or node.signed.usd is None:
        return []
    from usmd_rdsh.node import addresses  # pylint: disable=import-outside-toplevel
    from usmd_rdsh.node.states import State  # pylint: disable=import-outside-toplevel

    best = node.nndp.services._bests() if node.nndp else {}  # pylint: disable=protected-access
    rows = []
    for e in node.tables.nodes.sorted():
        record = e.record
        if not record.mutation:
            continue
        held = {addresses.service_of(a): a for a in record.sp_addresses}
        try:
            state = State(record.state).name
        except ValueError:
            state = f"0x{record.state:04X}"
        for name in node.signed.mutation_services(record.mutation):
            svc = node.signed.service_by_name(name)
            if svc is None:
                continue
            address = held.get(svc.service_id)
            rows.append({
                "service": name,
                "sp_address": addresses.to_text(address) if address is not None else "(no id)",
                "node_id": record.node_id + (" (self)" if e.key == node.key else ""),
                "node_address": record.address,
                "state": state,
                "mutation": record.mutation,
                "nearest": "yes" if address is not None and best.get(svc.service_id) == address
                else "",
            })
    return sorted(rows, key=lambda r: (r["service"], r["sp_address"]))


@action(cli="show service instances",
        description="Who runs each service in the USD, from the node table [ARCH 8, 11.3]",
        permissions=[READ], rows=InstanceRow,
        cli_output=printer(lambda rows: table(rows, [
            ("service", "Service"), ("sp_address", "SP address"), ("node_id", "Node ID"),
            ("node_address", "Address"), ("state", "State"), ("mutation", "Mutation"),
            ("nearest", "Nearest")])
            + "\n\nNearest: the instance this node's SP would choose (NNDP, own areas only)."))
async def show_service_instances() -> list[dict]:
    return instance_rows()


@action(cli="show service-area summary", description="Service areas in force [ARCH-02 11.2]",
        permissions=[READ], cli_output=printer(lambda rows: table(rows, [
            ("id", "Id"), ("name", "Area"), ("prefix", "Prefix"), ("addresses", "Addresses"),
            ("services", "Services"), ("member", "This node")])))
async def show_service_area_summary() -> list[dict]:
    node = RUNTIME.node
    if node is None or node.signed.usd is None:
        return []
    mine = node.my_areas()
    networks = node.signed.areas()
    return [{"id": a.area_id, "name": a.name, "prefix": str(networks[a.area_id]),
             "addresses": networks[a.area_id].num_addresses,
             "services": sum(1 for e in node.signed.usd.catalog if e.area_id == a.area_id),
             "member": "yes" if a.area_id in mine else ""}
            for a in sorted(node.signed.usd.areas, key=lambda x: x.area_id)]


@action(cli="show usd master", description="USD master and Raft voters [ARCH-02 12]",
        permissions=[READ], cli_output=printer(lambda r: fields([
            ("Master", r["leader"] or "unknown"),
            ("This node", r["role"]),
            ("Term", r["term"]),
            ("Commit / last index", f"{r['commit']} / {r['last']}"),
            ("Voters", ", ".join(r["voters"]) or "-"),
            ("Voters wanted (Nv)", r["nv"]),
            ("Voter removal delay", f"{r['removal']} s"),
            ("Assignments", r["assignments"]),
        ])))
async def show_usd_master() -> dict:
    node = RUNTIME.node
    raft = node.raft if node else None
    usd = node.signed.usd if node else None
    return {
        "leader": raft.leader if raft else None,
        "role": raft.role if raft and raft.is_voter else "not a voter",
        "term": raft.term if raft else 0,
        "commit": raft.commit_index if raft else 0,
        "last": raft.last_index if raft else 0,
        "voters": sorted(raft.voters) if raft else node.known_voters if node else [],
        "nv": parameter(usd, 0x0014),
        "removal": parameter(usd, 0x0015),
        "assignments": len(raft.state.assignments) if raft else 0,
    }


@action(cli="show usd operators", description="Operators elected by the master [ARCH-02 12.4]",
        permissions=[READ], cli_output=printer(lambda rows: table(rows, [
            ("role", "Role"), ("node_id", "Node"), ("state", "State"),
            ("this_node", "This node")])))
async def show_usd_operators() -> list[dict]:
    """Every node is an executor; the operator roles are elected among the
    nodes whose creation token authorises them."""
    node = RUNTIME.node
    if node is None:
        return []
    rows = []
    for role in OPERATOR_ROLES:
        holders = sorted(node.operators.get(int(role), set()))
        for node_id in holders or [None]:
            key = node.node_key(node_id) if node_id else None
            state = (node.state if node_id == node.node_id
                     else node.peer_state(key) if key else None)
            rows.append({"role": role.name.lower().replace("_", "-"),
                         "node_id": node_id or "(none elected)",
                         "state": state.name if state is not None else "-",
                         "this_node": "yes" if node_id == node.node_id else ""})
    return rows


@action(cli="show usd assignments", description="SP addresses assigned by the master",
        permissions=[READ], cli_output=printer(lambda rows: table(rows, [
            ("address", "SP address"), ("node_id", "Node")])))
async def show_usd_assignments() -> list[dict]:
    node = RUNTIME.node
    raft = node.raft if node else None
    if raft is None:
        return []
    return [{"address": f"{s:03x}.{m:04x}", "node_id": a.node_id}
            for (s, m), a in sorted(raft.state.assignments.items())]


@action(cli="show mutation status", description="Hosted mutation, health and history",
        permissions=[READ], cli_output=printer(lambda r: fields([
            ("Mutation", r["mutation"] or "(none)"),
            ("Version in force", r["version"]),
            ("Instances in the USD", r["instances"]),
            ("Bounds", r["bounds"]),
            ("Health failures in a row", r["health_failures"]),
            ("Last runs", "\n" + "\n".join(r["runs"]) if r["runs"] else "-"),
            ("Transmutations", "\n" + "\n".join(r["history"]) if r["history"] else "-"),
        ])))
async def show_mutation_status() -> dict:
    node = RUNTIME.node
    if node is None:
        return {"mutation": "", "version": "", "instances": 0, "bounds": "", "runs": [],
                "history": [], "health_failures": 0}
    props = node.signed.mutations.get(node.mutation)
    return {
        "mutation": node.mutation,
        "version": props.version if props else "",
        "instances": node.instance_count(node.mutation) if node.mutation else 0,
        "bounds": f"{props.min_instances}..{props.max_instances or 'unbounded'}" if props else "",
        "health_failures": node.delegation.health_failures,
        "runs": [f"  {svc} {seq}: {'ok' if r.ok else 'FAILED'} ({r.duration:.1f}s)"
                 for (svc, seq), r in node.runner.last.items()],
        "history": [f"  {t['at']} {t['from'] or '-'} -> {t['to'] or '-'} "
                    f"{'ok' if t['ok'] else 'failed'} {t['seconds']}s {t['reason']}"
                    for t in node.transmutations],
    }

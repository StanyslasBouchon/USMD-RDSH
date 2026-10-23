"""Protocol and USD views of what is in force:
``show usd parameters``, ``show ncp [commands|errors|statistics]``,
``show sp [sessions|flows|addresses|statistics]``, ``execute node state``."""

from __future__ import annotations

import logging
import time

from nan_actions import action
from nan_actions.errors import SdkError
from pydantic import BaseModel, Field, field_validator

from usmd_rdsh.cli.permissions import READ, WRITE
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.text import fields, printer, table
from usmd_rdsh.node import addresses
from usmd_rdsh.node.ncp.codec import Command, ErrorCode
from usmd_rdsh.node.signed import USD_PARAMETERS, parameter
from usmd_rdsh.node.states import State
from usmd_rdsh.node.wire import Writer


class ParameterRow(BaseModel):
    code: str
    name: str
    value: str
    default: str
    range: str


@action(cli="show usd parameters", description="USD parameters in force [ARCH-02 9.2]",
        permissions=[READ], rows=ParameterRow,
        cli_output=printer(lambda rows: table(rows, [
            ("code", "Code"), ("name", "Parameter"), ("value", "Value"),
            ("default", "Default"), ("range", "Range")])))
async def show_usd_parameters() -> list[dict]:
    """The signed values, or the defaults for an absent code."""
    usd = RUNTIME.node.signed.usd if RUNTIME.node else None
    rows = []
    for code, (name, default, low, high) in USD_PARAMETERS.items():
        value = parameter(usd, code)
        rows.append({"code": f"0x{code:04X}", "name": name.replace("_", "-"),
                     "value": "" if value is None else str(value),
                     "default": "" if default is None else str(default),
                     "range": f"{low}..{high}"})
    return rows


@action(cli="show ncp", description="NCP transport parameters in force", permissions=[READ],
        cli_output=printer(lambda r: fields(
            [(k.replace("_", " ").capitalize(), v) for k, v in r.items()])))
async def show_ncp() -> dict:
    return RUNTIME.config("protocol ncp").model_dump()


@action(cli="show ncp commands", description="NCP command registry [NCP-02 6.1]",
        permissions=[READ], cli_output=printer(lambda rows: table(
            rows, [("code", "Event"), ("name", "Command")])))
async def show_ncp_commands() -> list[dict]:
    return [{"code": f"0x{c.value:04X}", "name": c.name.capitalize()} for c in Command]


@action(cli="show ncp errors", description="NCP error codes [NCP-02 9]", permissions=[READ],
        cli_output=printer(lambda rows: table(rows, [("code", "Code"), ("name", "Meaning")])))
async def show_ncp_errors() -> list[dict]:
    return [{"code": f"0x{e.value:04X}", "name": e.name.lower().replace("_", " ")}
            for e in ErrorCode]


@action(cli="show ncp statistics", description="NCP transport counters", permissions=[READ],
        cli_output=printer(lambda r: fields([(k.capitalize(), v) for k, v in r.items()])))
async def show_ncp_statistics() -> dict:
    node = RUNTIME.node
    stats = dict(node.ncp.stats) if node and node.ncp else {}
    stats["port"] = node.settings.ncp_port if node else 9992
    return stats


@action(cli="show sp", description="SP parameters and interface", permissions=[READ],
        cli_output=printer(lambda r: fields(
            [(k.replace("_", " ").capitalize(), v) for k, v in r.items()])))
async def show_sp() -> dict:
    node = RUNTIME.node
    usd = node.signed.usd if node else None
    port = parameter(usd, 0x0010)
    return {
        "status": "running" if node and node.sp else
        ("no SP port configured (0x0010)" if port is None else "stopped"),
        "udp_port": port or "-",
        "interface": node.tun.kind if node and node.tun else "-",
        "problem": (node.sp_problem() if node else "") or "-",
        "mtu": parameter(usd, 0x0013),
        "instances_per_service": parameter(usd, 0x000A),
        "vips": ", ".join(node.sp_vips()) if node else "",
        "routes": ", ".join(node.sp_routes()) if node else "",
        "groups": ", ".join(node.sp_groups()) if node else "",
        **RUNTIME.config("protocol sp").model_dump(),
    }


@action(cli="show sp sessions", description="SP sessions [SP-01 7]", permissions=[READ],
        cli_output=printer(lambda rows: table(rows, [
            ("index", "Index"), ("peer", "Peer"), ("address", "Address"), ("role", "Role"),
            ("age", "Age(s)"), ("sent", "Frames sent"), ("received", "Highest rx")])))
async def show_sp_sessions() -> list[dict]:
    node = RUNTIME.node
    if node is None or node.sp is None:
        return []
    now = time.monotonic()
    names = {e.key: e.record.node_id for e in node.tables.nodes.entries.values()}
    return [{"index": f"{i:08x}", "peer": names.get(s.peer, s.peer.hex()[:12]),
             "address": s.peer_address, "role": "initiator" if s.keys.initiator else "responder",
             "age": int(now - s.established), "sent": s.send_counter,
             "received": s.window.highest} for i, s in node.sp.sessions.items()]


@action(cli="show sp flows", description="SP flow table [SP-01 6.3]", permissions=[READ],
        cli_output=printer(lambda rows: table(rows, [
            ("flow", "Flow"), ("instance", "Instance"), ("direction", "Dir"),
            ("idle", "Idle(s)")])))
async def show_sp_flows() -> list[dict]:
    node = RUNTIME.node
    if node is None or node.sp is None:
        return []
    now = time.monotonic()
    return [{"flow": f"{k[0]} {k[1]}:{k[2]} -> {k[3]}:{k[4]}",
             "instance": addresses.to_text(f.peer_address),
             "direction": "out" if f.outbound else "in",
             "idle": int(now - f.last_activity)} for k, f in node.sp.flows.flows.items()]


@action(cli="clear sp flows", description="Forget every SP flow (next packets reselect)",
        permissions=[WRITE])
async def clear_sp_flows() -> dict:
    node = RUNTIME.node
    count = len(node.sp.flows.flows) if node and node.sp else 0
    if node and node.sp:
        node.sp.flows.flows.clear()
    return {"cleared": count}


@action(cli="show sp addresses", description="SP address table [SP-01 4.3]",
        permissions=[READ], cli_output=printer(lambda rows: table(rows, [
            ("address", "SP address"), ("service", "Service"), ("node_id", "Node")])))
async def show_sp_addresses() -> list[dict]:
    node = RUNTIME.node
    if node is None:
        return []
    catalog = node.signed.catalog()
    rows = []
    for e in node.tables.nodes.sorted():
        for address in e.record.sp_addresses:
            service = addresses.service_of(address)
            rows.append({"address": addresses.to_text(address),
                         "service": catalog[service].name if service in catalog else "?",
                         "node_id": e.record.node_id})
    return rows


@action(cli="show sp statistics", description="SP counters", permissions=[READ],
        cli_output=printer(lambda r: fields([(k.replace("_", " ").capitalize(), v)
                                             for k, v in r.items()])))
async def show_sp_statistics() -> dict:
    node = RUNTIME.node
    return dict(node.sp.stats) if node and node.sp else {}


class DeclaredState(BaseModel):
    """A state this node may declare about itself."""

    state: str = Field(description="active, inactive, inactive-emergency ... or a 0x code")

    @field_validator("state")
    @classmethod
    def _declarable(cls, text: str) -> str:
        # Checked here, before the confirmation is asked, not in the handler.
        state = parse_state(text)
        if not state.declarable:
            raise ValueError(f"{state.name} is attributed by peers (origin O); "
                             "a node must not declare it")
        return state.name


def parse_state(text: str) -> State:
    """``active``, ``ACTIVE`` or ``0x2000``."""
    cleaned = text.strip().upper().replace("-", "_")
    try:
        if cleaned.startswith("0X"):
            return State(int(cleaned, 16))
        return State[cleaned]
    except (KeyError, ValueError) as exc:
        raise ValueError(f"unknown state '{text}'; see 'show node states'") from exc


@action(cli="execute node state", permissions=[WRITE],
        description="Declare this node's state and tell the reference nodes [NCP 6.6]",
        cli_confirm="Declare state {state} on this node?")
async def execute_node_state(data: DeclaredState) -> dict:
    node = RUNTIME.node
    if node is None:
        raise SdkError("the node is not running")
    state = State[data.state]
    previous = node.state
    if state in (State.APPROVAL_REQUIRED, State.SYNCHRONISING) or not node.admitted:
        raise SdkError("admission states follow the admission procedure, not the operator "
                       "[ARCH 5.3, 5.4]")
    try:
        node.set_state(state, reason="operator")
    except ValueError as exc:
        raise SdkError(str(exc)) from exc
    node.publish_record()
    body = Writer().u16(int(state)).bytes()
    for ref in node.references:
        await node._quiet(node.call(ref, Command.DECLARE_STATE, body))  # pylint: disable=protected-access
    logging.warning("[NODE] State changed from %s to %s by the operator",
                    previous.name, state.name)
    return {"previous": previous.name, "state": state.name, "code": f"0x{state.value:04X}"}

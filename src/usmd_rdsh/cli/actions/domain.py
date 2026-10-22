"""``show usd parameters``, ``show ncp``, ``show ncp errors``, ``show sp``,
``execute node state``."""

from __future__ import annotations

import logging

from nan_actions import action
from nan_actions.errors import SdkError
from pydantic import BaseModel, Field, field_validator

from usmd_rdsh.cli.actions.show_system import state_origin
from usmd_rdsh.cli.permissions import READ, WRITE
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.text import fields, printer, table
from usmd_rdsh.cli.views.domain import USD_PARAMETER_CODES, UsdConfig
from usmd_rdsh.utils.node_state import NodeState


class ParameterRow(BaseModel):
    """One USD parameter."""

    code: str
    name: str
    value: str
    default: str
    unit: str


@action(cli="show usd parameters", description="USD parameters with their codes [ARCH 9.2]",
        permissions=[READ], rows=ParameterRow,
        cli_output=printer(lambda rows: table(rows, [
            ("code", "Code"), ("name", "Parameter"), ("value", "Value"),
            ("default", "Default"), ("unit", "Unit")])))
async def show_usd_parameters() -> list[dict]:
    """USD parameters with their registry codes, values and defaults."""
    usd = RUNTIME.config("usd")
    rows = []
    for name, code in USD_PARAMETER_CODES.items():
        info = UsdConfig.model_fields[name]
        value = getattr(usd, name)
        rows.append({
            "code": f"0x{code:04X}",
            "name": name.replace("_", "-"),
            "value": "" if value in (None, "") else str(value),
            "default": "" if info.default in (None, "") else str(info.default),
            "unit": (info.description or "").split(" ", 1)[-1],
        })
    return rows


#: [NCP] section 9.
NCP_ERRORS = {
    0x0001: "Command not authorised (role, or no reference relation)",
    0x0002: "Timestamp outside the freshness window",
    0x0003: "Malformed body or invalid parameter",
    0x0004: "Recipient busy, retry later",
    0x0005: "Unknown key or (address, key) association",
    0x0006: "Obsolete object version or invalid authority signature",
    0x0007: "Creation token missing, invalid, expired or not bound to the sender",
    0x0008: "Node identifier already used in the USD by another key",
    0x0009: "Invalid node record, or record address differs from source",
    0x000A: "Command reserved to voters",
    0x000B: "Service identifier unknown or outside the requester's areas",
}

#: [NCP-02] section 6.1: the twenty commands.
NCP_COMMANDS = {
    0x0001: "Get_status", 0x0002: "Check_distance_to_node", 0x0003: "Request_emergency",
    0x0004: "Request_help", 0x0005: "Request_approval", 0x0006: "Send_usc_properties",
    0x0007: "Send_usd_properties", 0x0008: "Send_mutation_properties",
    0x0009: "Inform_reference_node", 0x000A: "Endorsement_check_required",
    0x000B: "Verify_endorsement", 0x000C: "Notify_end_of_service",
    0x000D: "Request_revocation", 0x000E: "Confirm_delegation", 0x000F: "Declare_state",
    0x0010: "Send_node_table", 0x0011: "Request_management_id",
    0x0012: "Raft_request_vote", 0x0013: "Raft_append_entries",
    0x0014: "Raft_install_snapshot",
}


@action(cli="show ncp", description="NCP parameters", permissions=[READ],
        cli_output=printer(lambda r: fields(
            [(k.replace("_", " ").capitalize(), v) for k, v in r.items()])))
async def show_ncp() -> dict:
    """NCP parameters in force."""
    return RUNTIME.config("protocol ncp").model_dump()


@action(cli="show ncp commands", description="NCP command registry [NCP-02 6.1]",
        permissions=[READ], cli_output=printer(lambda rows: table(
            rows, [("code", "Event"), ("name", "Command")])))
async def show_ncp_commands() -> list[dict]:
    """NCP command codes."""
    return [{"code": f"0x{c:04X}", "name": n} for c, n in NCP_COMMANDS.items()]


@action(cli="show ncp errors", description="NCP error codes [NCP-02 9]", permissions=[READ],
        cli_output=printer(lambda rows: table(
            rows, [("code", "Code"), ("meaning", "Meaning")])))
async def show_ncp_errors() -> list[dict]:
    """NCP error codes."""
    return [{"code": f"0x{c:04X}", "meaning": m} for c, m in NCP_ERRORS.items()]


@action(cli="show sp", description="SP parameters (USD and local)", permissions=[READ],
        cli_output=printer(lambda r: fields(
            [(k.replace("_", " ").capitalize(), v) for k, v in r.items()])))
async def show_sp() -> dict:
    """SP parameters: the USD-wide ones and the local ones."""
    usd = RUNTIME.config("usd")
    return {
        "udp_port": usd.sp_port or "(not configured)",
        "service_areas": len(RUNTIME.config("service-area")),
        "catalogue_services": len(RUNTIME.config("service")),
        "mtu": usd.sp_mtu,
        "instances_per_service": usd.instances_per_service,
        **RUNTIME.config("protocol sp").model_dump(),
    }


class DeclaredState(BaseModel):
    """A state this node may declare about itself."""

    state: str = Field(description="active, inactive, synchronising ... or a 0x code")

    @field_validator("state")
    @classmethod
    def _declarable(cls, text: str) -> str:
        # Checked here, before the confirmation is asked, not in the handler.
        state = parse_state(text)
        if state_origin(state) != "D":
            raise ValueError(
                f"{state.name} is attributed by peers (origin O); a node must not declare it"
            )
        return state.name


def parse_state(text: str) -> NodeState:
    """``active``, ``ACTIVE`` or ``0x2000`` -> NodeState.ACTIVE."""
    cleaned = text.strip().upper().replace("-", "_")
    try:
        if cleaned.startswith("0X"):
            return NodeState(int(cleaned, 16))
        return NodeState[cleaned]
    except (KeyError, ValueError) as exc:
        raise ValueError(f"unknown state '{text}'; see 'show node states'") from exc


@action(cli="execute node state", permissions=[WRITE],
        description="Declare this node's state (origin D only) [ARCH 5.5]",
        cli_confirm="Declare state {state} on this node?")
async def execute_node_state(data: DeclaredState) -> dict:
    """Declare this node's own state."""
    state = NodeState[data.state]
    if RUNTIME.core is None:
        raise SdkError("the node core is not running")
    previous = RUNTIME.core.state
    RUNTIME.core.state = state
    logging.warning("[NODE] State changed from %s to %s by the operator",
                    previous.name, state.name)
    return {"previous": previous.name, "state": state.name, "code": f"0x{state.value:04X}"}

"""Operator procedures [ARCH-02 5, 6, 7, 8, 11; NCP-02 7]:

    execute node admission            run the bootstrap/admission now
    execute node token install        install a creation token
    execute node transmute            change mutation (administrator decision)
    execute node retire               end of service, revocation, delegation
    execute node help | emergency     ask the reference nodes to take over
    execute distance measure          measure distances, reselect references
    execute table reconcile           full Send_node_table with a reference node
    execute properties push           send the signed objects to the references
    execute management-id request     ask the USD master for management ids
    show authority                    keys this node holds as authority / USD operator
    execute authority keygen          create the USC or USD key pair here
    execute authority token create    mint a creation token for a node key
"""

from __future__ import annotations

from enum import StrEnum

from nan_actions import action
from nan_actions.api.permissions import ApiPermission
from nan_actions.errors import SdkError
from pydantic import BaseModel, Field

from usmd_rdsh.cli.permissions import READ, WRITE
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.cli.text import fields, printer
from usmd_rdsh.node.crypto import b64u, unb64u
from usmd_rdsh.node.ncp.codec import Role
from usmd_rdsh.node.states import State


def _node():
    if RUNTIME.node is None:
        raise SdkError("the node is not running")
    return RUNTIME.node


@action(cli="execute node admission", description="Look for an admitted node now [ARCH 5.2]",
        permissions=[WRITE])
async def execute_node_admission() -> dict:
    node = _node()
    if node.token is None:
        raise SdkError("no creation token: 'config system bootstrap' / 'set creation-token'")
    if node.state != State.APPROVAL_REQUIRED:
        return {"state": node.state.name, "message": "already admitted"}
    for key, address, x25519 in node.candidates():
        if key and x25519 and await node.request_approval(key, address, x25519):
            return {"state": node.state.name, "endorser": address}
    return {"state": node.state.name, "message": "no admitted node answered"}


class TokenInput(BaseModel):
    token: str = Field(description="Creation token (base64url) from the USD operator")


@action(cli="execute node token install", description="Install a creation token [NCP 7.7]",
        permissions=[WRITE])
async def execute_node_token_install(data: TokenInput) -> dict:
    node = _node()
    try:
        token = node.install_token(data.token)
    except ValueError as exc:
        raise SdkError(str(exc)) from exc
    RUNTIME.document.set_field(("system", "bootstrap"), "creation_token", data.token)
    await RUNTIME.config_store.save(RUNTIME.document)
    return {"founder": token.founder, "roles": token.roles, "expires": token.expires}


class TransmuteInput(BaseModel):
    mutation: str = Field("", description="Mutation to host; empty to host none")


@action(cli="execute node transmute", description="Change mutation [ARCH 8.1]",
        permissions=[WRITE], cli_confirm="Transmute this node to '{mutation}'?")
async def execute_node_transmute(data: TransmuteInput) -> dict:
    node = _node()
    if data.mutation and data.mutation not in node.signed.mutations:
        raise SdkError(f"no mutation '{data.mutation}' in force")
    try:
        ok = await node.transmute(data.mutation, reason="administrator")
    except ValueError as exc:
        raise SdkError(str(exc)) from exc
    return {"ok": ok, "state": node.state.name, "mutation": node.mutation}


@action(cli="execute node retire", description="Leave the USD [ARCH 5.7, NCP 7.5]",
        permissions=[WRITE], cli_confirm="Retire this node from the USD?")
async def execute_node_retire() -> dict:
    node = _node()
    await node.retire()
    return {"state": node.state.name}


@action(cli="execute node help", description="Ask the reference nodes for help [ARCH 7.2]",
        permissions=[WRITE])
async def execute_node_help() -> dict:
    node = _node()
    if not node.mutation:
        raise SdkError("this node hosts no mutation")
    return {"favourable": await node.request_help()}


class EmergencyReason(StrEnum):
    RESOURCES = "resources"
    DEPENDENCIES = "dependencies"
    HEALTH_CHECK = "health-check"
    UPDATE = "update"


_REASONS = {EmergencyReason.RESOURCES: State.INACTIVE_EMERGENCY_RESOURCES,
            EmergencyReason.DEPENDENCIES: State.INACTIVE_EMERGENCY_DEPENDENCIES,
            EmergencyReason.HEALTH_CHECK: State.INACTIVE_EMERGENCY_HEALTH_CHECK,
            EmergencyReason.UPDATE: State.INACTIVE_EMERGENCY_UPDATE}


class EmergencyInput(BaseModel):
    reason: EmergencyReason = Field(description="resources, dependencies, health-check, update")


@action(cli="execute node emergency", description="Emergency delegation [ARCH 7.3, 7.4]",
        permissions=[WRITE], cli_confirm="Hand over every service ({reason}) and stop them?")
async def execute_node_emergency(data: EmergencyInput) -> dict:
    node = _node()
    state = _REASONS[data.reason]
    try:
        node.set_state(state, reason="operator emergency")
    except ValueError as exc:
        raise SdkError(str(exc)) from exc
    node.publish_record()
    await node.emergency(state)
    return {"state": node.state.name}


@action(cli="execute distance measure", description="Measure distances now [ARCH 6.4]",
        permissions=[WRITE])
async def execute_distance_measure() -> dict:
    node = _node()
    await node.measure_distances()
    return {"references": node.references, "distances": node.distances}


@action(cli="execute table reconcile", description="Full node-table exchange [NCP 7.9]",
        permissions=[WRITE])
async def execute_table_reconcile() -> dict:
    node = _node()
    if not node.references:
        raise SdkError("no reference node to reconcile with")
    import random  # pylint: disable=import-outside-toplevel

    target = random.choice(node.references)
    await node.send_table(target, node.tables.nodes.sorted(), mode=0x00)
    return {"with": target, "entries": len(node.tables.nodes.entries)}


@action(cli="execute properties push", description="Send the signed objects to references",
        permissions=[WRITE])
async def execute_properties_push() -> dict:
    node = _node()
    await node.push_properties()
    return {"to": node.references}


@action(cli="execute management-id request", description="Ask the master [NCP 6.15]",
        permissions=[WRITE])
async def execute_management_id_request() -> dict:
    node = _node()
    await node.request_management_ids()
    return {"management": {f"{s:03x}": f"{m:04x}" for s, m in node.management.items()}}


# -- authority ---------------------------------------------------------------


@action(cli="show authority", description="Authority keys held by this node [ARCH 3.3]",
        permissions=[READ], cli_output=printer(lambda r: fields([
            ("USC key (authority)", r["usc"] or "not held"),
            ("USD key (operator)", r["usd"] or "not held"),
            ("Trusted USC key", r["trusted_usc"] or "-"),
            ("Trusted USD key", r["trusted_usd"] or "-"),
        ])))
async def show_authority() -> dict:
    node = _node()
    return {"usc": b64u(node.authority.usc.public) if node.authority.usc else "",
            "usd": b64u(node.authority.usd.public) if node.authority.usd else "",
            "trusted_usc": b64u(node.usc_key) if node.usc_key else "",
            "trusted_usd": b64u(node.usd_key) if node.usd_key else ""}


class KeyKind(StrEnum):
    USC = "usc"
    USD = "usd"


class KeygenInput(BaseModel):
    which: KeyKind = Field(description="usc (authority) or usd (domain operator)")


@action(cli="execute authority keygen", description="Create the USC or USD key pair here",
        permissions=[ApiPermission.MANAGE],
        cli_confirm="Make this node hold the {which} private key? Keep it offline [ARCH 12].")
async def execute_authority_keygen(data: KeygenInput) -> dict:
    node = _node()
    try:
        key = node.authority.generate(str(data.which))
    except ValueError as exc:
        raise SdkError(str(exc)) from exc
    node.apply_anchors()
    return {"which": str(data.which), "public_key": b64u(key.public)}


class RoleName(StrEnum):
    USC_OPERATOR = "usc-operator"
    USD_OPERATOR = "usd-operator"
    NODE_OPERATOR = "node-operator"
    NODE_EXECUTOR = "node-executor"


class TokenCreate(BaseModel):
    node_key: str = Field(description="The node's Ed25519 public key (base64url)")
    usdn: str = Field("", description="USDN (default: the USD in force)")
    roles: list[RoleName] = Field([RoleName.NODE_EXECUTOR], description="Authorised roles")
    validity_hours: int = Field(24, ge=1, le=168, description="At most 7 days")
    founder: bool = Field(False, description="First node of the USD [NCP 7.7]")
    second_founder: bool = Field(False, description="Allow another founder token (one SHOULD exist)")


@action(cli="execute authority token create", description="Mint a creation token [NCP 7.7]",
        permissions=[ApiPermission.MANAGE],
        cli_output=printer(lambda r: (
            f"Creation token for {r['node_key']} ({', '.join(r['roles'])}"
            f"{', founder' if r['founder'] else ''}), valid {r['hours']} h:\n\n    {r['token']}\n\n"
            "Give it to the node: 'execute node token install token=<...>' or "
            "'config system bootstrap' / 'set creation-token'.")))
async def execute_authority_token_create(data: TokenCreate) -> dict:
    node = _node()
    usdn = data.usdn or (node.signed.usd.usdn if node.signed.usd else "")
    if not usdn:
        raise SdkError("no USDN given and no USD in force")
    roles = [Role[str(r).upper().replace("-", "_")] for r in data.roles]
    try:
        token = node.authority.mint_token(usdn.upper(), unb64u(data.node_key), roles,
                                          validity_ms=data.validity_hours * 3_600_000,
                                          founder=data.founder,
                                          allow_second_founder=data.second_founder)
    except ValueError as exc:
        raise SdkError(str(exc)) from exc
    return {"node_key": data.node_key, "roles": [str(r) for r in data.roles],
            "founder": data.founder, "hours": data.validity_hours,
            "token": b64u(token.encode())}

"""Security procedures [ARCH-02 3.3, 4.2, 14; NCP-02 10]:

    execute nal revoke                revoke a compromised key and exclude it for good
    execute node rekey                new key pairs for this node
    execute properties export         write the signed objects in force to a file
    execute properties import         inject signed objects from a file (offline authority)
"""

from __future__ import annotations

import json
from pathlib import Path

from nan_actions import action
from nan_actions.api.permissions import ApiPermission
from nan_actions.errors import SdkError
from pydantic import BaseModel, Field

from usmd_rdsh.cli.permissions import READ, WRITE
from usmd_rdsh.cli.runtime import RUNTIME
from usmd_rdsh.node.authority import export_signed, import_signed
from usmd_rdsh.node.crypto import b64u, unb64u
from usmd_rdsh.node.states import State


def _node():
    if RUNTIME.node is None:
        raise SdkError("the node is not running")
    return RUNTIME.node


class RevokeInput(BaseModel):
    public_key: str = Field(description="Ed25519 public key of the node (base64url)")


@action(cli="execute nal revoke",
        description="Revoke a compromised node's roles and exclude it [ARCH 14]",
        permissions=[WRITE],
        cli_confirm="Revoke every role of {public_key} and exclude it permanently?")
async def execute_nal_revoke(data: RevokeInput) -> dict:
    """[ARCH 14] a compromised node: its roles go and it is never admitted again here.

    The key is also removed from ``config trust nal``, or the next commit of
    that table would grant it again.
    """
    node = _node()
    try:
        key = unb64u(data.public_key)
    except ValueError as exc:
        raise SdkError(f"not a base64url key: {exc}") from exc
    if len(key) != 32:
        raise SdkError("an Ed25519 public key is 32 bytes (base64url)")
    if key == node.key:
        raise SdkError("this is this node's own key: use 'execute node rekey' [ARCH 4.2]")
    if key in (node.usc_key, node.usd_key):
        raise SdkError("this is a USC or USD trust anchor: change 'config system trust-anchor'")
    node.tables.nal.anchors.discard(key)
    node.tables.nal.revoke(key)
    node.tables.exclusions.exclude(key, State.EXCLUDED_INVALID_ENDORSEMENT)
    removed = RUNTIME.document.delete_row(("trust", "nal"), data.public_key)
    if removed:
        await RUNTIME.config_store.save(RUNTIME.document)
    node.event(f"Key {data.public_key} revoked and excluded by the administrator")
    return {"public_key": data.public_key, "excluded": "permanent",
            "removed_from_config": bool(removed)}


@action(cli="execute node rekey", description="Replace this node's key pairs [ARCH 4.2, NCP 10]",
        permissions=[ApiPermission.MANAGE],
        cli_confirm="Replace this node's Ed25519 and X25519 key pairs? "
                    "A new creation token will be needed.")
async def execute_node_rekey() -> dict:
    node = _node()
    try:
        await node.rekey()
    except ValueError as exc:
        raise SdkError(str(exc)) from exc
    return {"ed25519": b64u(node.key), "x25519": b64u(node.identity.x25519_public),
            "node_id": node.node_id}


class FileInput(BaseModel):
    file: str = Field(description="Path of the JSON file")


@action(cli="execute properties export",
        description="Write the signed objects in force to a file [ARCH 3.3]",
        permissions=[READ])
async def execute_properties_export(data: FileInput) -> dict:
    node = _node()
    exported = export_signed(node.signed)
    path = Path(data.file).expanduser()
    try:
        path.write_text(json.dumps(exported, indent=2) + "\n", encoding="utf-8")
    except OSError as exc:
        raise SdkError(f"cannot write {path}: {exc}") from exc
    return {"file": str(path), "usc": exported["usc"] is not None,
            "usd": exported["usd"] is not None, "mutations": len(exported["mutations"])}


@action(cli="execute properties import",
        description="Inject signed objects from a file (offline authority) [ARCH 3.3, 14]",
        permissions=[ApiPermission.MANAGE])
async def execute_properties_import(data: FileInput) -> dict:
    """Signatures and versions are checked by the injection, as for NCP [ARCH 9.3]."""
    node = _node()
    path = Path(data.file).expanduser()
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        usc, usd, mutations = import_signed(document)
        applied = node.inject(usc, usd, mutations)
    except OSError as exc:
        raise SdkError(f"cannot read {path}: {exc}") from exc
    except ValueError as exc:  # JSON, decoding, signature, validity
        raise SdkError(f"refused: {exc}") from exc
    return {"file": str(path), "applied": applied or ["nothing newer than what is in force"]}

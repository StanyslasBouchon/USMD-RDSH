"""Who this node is: its ULID and its two key pairs [ARCH-02 4.1, 4.2].

Kept in ``identity.json`` in the state directory, readable by the owner only.
The private keys never leave the node [ARCH 4.2]: nothing in the management
plane prints or sends them.

A prototype node (``node.properties`` + ``node.key``) keeps its identifier and
Ed25519 key; it gains the X25519 pair it never had.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import ulid
from nan_runtime.state import StateDirectory

from usmd_rdsh.node.crypto import AgreementKey, SigningKey, b64u, unb64u
from usmd_rdsh.node.wire import is_ulid

_FILE = "identity.json"


@dataclass
class Identity:
    """The node's identifier and keys."""

    node_id: str
    signing: SigningKey
    agreement: AgreementKey

    @property
    def ed25519_public(self) -> bytes:
        return self.signing.public

    @property
    def x25519_public(self) -> bytes:
        return self.agreement.public

    def regenerate_id(self) -> None:
        """A new ULID, after error 0x0008 (identifier already used) [ARCH 4.1]."""
        self.node_id = ulid.new().str

    def to_json(self) -> dict:
        return {
            "node_id": self.node_id,
            "ed25519_seed": b64u(self.signing.seed),
            "x25519_private": b64u(self.agreement.private),
        }

    @classmethod
    def from_json(cls, data: dict) -> "Identity":
        node_id = str(data["node_id"])
        if not is_ulid(node_id):
            raise ValueError(f"stored node id '{node_id}' is not a ULID")
        return cls(
            node_id=node_id,
            signing=SigningKey(unb64u(data["ed25519_seed"])),
            agreement=AgreementKey(unb64u(data["x25519_private"])),
        )


def _prototype(state: StateDirectory) -> tuple[str, SigningKey] | None:
    """The identifier and key of a prototype node, if this directory has one."""
    properties = state.path("node.properties")
    key_file = state.path("node.key")
    if not properties.exists() or not key_file.exists():
        return None
    try:
        # pylint: disable=import-outside-toplevel
        from usmd_rdsh.security.ed25519 import Ed25519Certificate

        node_id = properties.read_text(encoding="utf-8").splitlines()[0].strip()
        pair = Ed25519Certificate.load(str(state.root))
        return node_id, SigningKey(unb64u(pair.seed32_b64u))
    except (OSError, ValueError, IndexError):
        return None


def load_identity(state: StateDirectory, filename: str | None = None) -> Identity:
    """Load the identity, migrating or creating it on first use.

    *filename* is ``keys_file`` of ``usmd.yaml`` (default ``identity.json``).
    """
    name = filename or _FILE
    stored = state.read_json(name, default=None)
    if stored:
        return Identity.from_json(stored)
    migrated = _prototype(state)
    if migrated and is_ulid(migrated[0]):
        identity = Identity(migrated[0], migrated[1], AgreementKey.generate())
        save_identity(state, identity, name)
        return identity
    else:
        identity = Identity(ulid.new().str, SigningKey.generate(), AgreementKey.generate())
    save_identity(state, identity, name)
    return identity


def save_identity(state: StateDirectory, identity: Identity, filename: str | None = None) -> Path:
    """Write the identity, owner-only."""
    path = state.write_json(identity.to_json(), filename or _FILE, mode=0o600)
    if os.name != "nt":
        os.chmod(path, 0o600)
    return path

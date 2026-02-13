from dataclasses import dataclass

from usmd_rdsh.sys.nal import Role


@dataclass
class NodeEndorsementPacket:
    """Node endorsement packet class."""

    serial: str
    expiration: int
    ed25519_signature: str
    roles: list[Role]
    x25519_session_key: str
    authoritative_node_pubkey: str

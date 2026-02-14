from dataclasses import dataclass


@dataclass
class NodeIdentity:
    """Node identity class."""

    ed25519_pub32: bytes
    id: str
    ip: str
    ttl: int = 300

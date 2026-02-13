from dataclasses import dataclass


@dataclass
class NodeIdentity:
    """Node identity class."""

    pubkey: str
    ip: str
    ttl: int

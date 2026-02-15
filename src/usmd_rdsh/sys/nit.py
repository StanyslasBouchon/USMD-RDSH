"""Node identity representation.

This module defines a dataclass for a node's identity: Ed25519 public key,
identifier, IP address, and time-to-live.
"""

from dataclasses import dataclass


@dataclass
class NodeIdentity:
    """Node identity with public key, ID, IP, and TTL.

    Attributes:
        ed25519_pub32: Raw 32-byte Ed25519 public key.
        node_id: Node identifier.
        node_ip: IP address (e.g. "192.168.1.1" or "::1").
        ttl: Time-to-live in seconds (default: 300).

    Example:
        >>> from usmd_rdsh.sys.nit import NodeIdentity
        >>> pub = b"\\x00" * 32  # placeholder
        >>> ni = NodeIdentity(ed25519_pub32=pub, node_id="node-1", node_ip="10.0.0.1", ttl=60)
        >>> ni.node_id
        'node-1'
        >>> ni.ttl
        60
    """

    ed25519_pub32: bytes
    node_id: str
    node_ip: str
    ttl: int = 300

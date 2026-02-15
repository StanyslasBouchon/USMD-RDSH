"""Node endorsement packet representation.

This module defines a dataclass for a node endorsement packet, including
serial, expiration, signature, roles, session key, and authoritative node.
"""

from dataclasses import dataclass

from usmd_rdsh.sys.nal import Role


@dataclass
class NodeEndorsementPacket:
    """Packet endorsing a node with signature, roles, and authoritative node public key.

    Attributes:
        serial: Packet serial identifier.
        expiration: Expiration timestamp (e.g. Unix epoch milliseconds).
        ed25519_signature: Base64URL-encoded Ed25519 signature.
        roles: Roles endorsed by this packet.
        authoritative_node_ed25519_pub_key_32: Base64URL-encoded 32-byte Ed25519 public key.

    Example:
        >>> from usmd_rdsh.sys.nel import NodeEndorsementPacket
        >>> from usmd_rdsh.sys.nal import Role
        >>> pkt = NodeEndorsementPacket(
        ...     serial="EP-001",
        ...     expiration=1735689600000,
        ...     ed25519_signature="sig...",
        ...     roles=[Role.NODE_OPERATOR],
        ...     authoritative_node_ed25519_pub_key_32="pub...",
        ... )
        >>> pkt.serial
        'EP-001'
        >>> Role.NODE_OPERATOR in pkt.roles
        True
    """

    serial: str
    expiration: int
    ed25519_signature: str
    roles: list[Role]
    authoritative_node_ed25519_pub_key_32: str

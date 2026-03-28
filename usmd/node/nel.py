"""Node Endorsement List (NEL) for USMD-RDSH.

The NEL tracks endorsement packets that a node has issued to joining peers
(as endorser) and the endorsement packet it received when it joined (as
endorsed node).

When an endorser node shuts down, it must notify all endorsed nodes so
they can re-initiate the join process. If a revocation request is received
from a node that never issued an endorsement to the receiver, the sender is
permanently excluded.

Examples:
    >>> nel = NodeEndorsementList()
    >>> packet = EndorsementPacket(
    ...     endorser_key=b"e"*32,
    ...     node_name=1710000000,
    ...     node_pub_key=b"n"*32,
    ...     node_session_key=b"s"*32,
    ...     roles=[NodeRole.NODE_EXECUTOR],
    ...     serial=b"\\x00"*16,
    ...     expiration=9999999999,
    ...     signature=b"\\xff"*64,
    ... )
    >>> nel.add_issued(packet)
    >>> nel.has_issued_to(b"n"*32)
    True
"""

import logging
import time
from dataclasses import dataclass
from typing import Optional

from ..utils.errors import Error, ErrorKind
from ..utils.result import Result
from .role import NodeRole


@dataclass
class EndorsementPacket:  # pylint: disable=too-many-instance-attributes
    """An endorsement packet issued by an existing node to a new joining node.

    This packet is the proof-of-identity that new nodes present to unknown
    peers when challenged with an ECR (Endorsement Check Required).

    Attributes:
        endorser_key: Ed25519 public key of the endorsing node.
        node_name: UNIX timestamp name of the endorsed node.
        node_pub_key: Ed25519 public key of the endorsed node.
        node_session_key: X25519 session key of the endorsed node.
        roles: Roles granted to the endorsed node.
        serial: 16-byte unique identifier for this packet.
        expiration: UNIX timestamp after which this packet is no longer valid.
        signature: Ed25519 signature over all other fields, by the endorser.

    Examples:
        >>> packet = EndorsementPacket(
        ...     endorser_key=b"e"*32, node_name=1710000000,
        ...     node_pub_key=b"n"*32, node_session_key=b"s"*32,
        ...     roles=[NodeRole.NODE_EXECUTOR], serial=b"\\x00"*16,
        ...     expiration=9999999999, signature=b"\\xff"*64,
        ... )
        >>> packet.is_expired()
        False
    """

    endorser_key: bytes
    node_name: int
    node_pub_key: bytes
    node_session_key: bytes
    roles: list[NodeRole]
    serial: bytes
    expiration: int
    signature: bytes

    def is_expired(self) -> bool:
        """Return True if this endorsement has passed its expiration timestamp.

        Example:
            >>> import time
            >>> p = EndorsementPacket(b"e"*32, 0, b"n"*32, b"s"*32,
            ...     [], b"\\x00"*16, int(time.time()) - 1, b"\\xff"*64)
            >>> p.is_expired()
            True
        """
        return time.time() > self.expiration

    def signable_bytes(self) -> bytes:
        """Return the canonical byte representation signed by the endorser.

        This covers all fields except the signature itself. Used for
        Ed25519 verification.

        Returns:
            bytes: Concatenated field bytes.

        Example:
            >>> packet = EndorsementPacket(b"e"*32, 1710000000, b"n"*32,
            ...     b"s"*32, [NodeRole.NODE_EXECUTOR], b"\\x00"*16,
            ...     9999999999, b"\\xff"*64)
            >>> isinstance(packet.signable_bytes(), bytes)
            True
        """
        roles_bytes = b"".join(r.value.encode() for r in self.roles)
        return (
            self.endorser_key
            + self.node_name.to_bytes(8, "big")
            + self.node_pub_key
            + self.node_session_key
            + roles_bytes
            + self.serial
            + self.expiration.to_bytes(8, "big")
        )


class NodeEndorsementList:
    """Manages the endorsement packets issued and received by a node.

    Two separate ledgers are maintained:
        - ``_issued``: Packets this node has issued to others (as endorser).
        - ``_received``: The single packet this node received when it joined.

    Attributes:
        _issued: Mapping of endorsed node's public key → EndorsementPacket.
        _received: The EndorsementPacket this node received (or None).

    Examples:
        >>> nel = NodeEndorsementList()
        >>> # (Assuming a valid packet exists)
        >>> nel.has_issued_to(b"n" * 32)
        False
    """

    def __init__(self) -> None:
        self._issued: dict[bytes, EndorsementPacket] = {}
        self._received: Optional[EndorsementPacket] = None

    # ------------------------------------------------------------------
    # Issued packets (endorser side)
    # ------------------------------------------------------------------

    def add_issued(self, packet: EndorsementPacket) -> None:
        """Record an endorsement packet issued to a new node.

        Args:
            packet: The EndorsementPacket issued by this node.

        Example:
            >>> nel = NodeEndorsementList()
            >>> # nel.add_issued(packet)
        """
        self._issued[packet.node_pub_key] = packet
        logging.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] NEL issued to %s (serial=%s)",
            packet.node_pub_key.hex()[:16] + "…",
            packet.serial.hex(),
        )

    def revoke_issued(self, node_pub_key: bytes) -> Result[EndorsementPacket, Error]:
        """Remove and return an issued endorsement packet.

        Called when this node is shutting down and must notify its endorsed peers,
        or when an endorsed peer re-joins under a new identity.

        Args:
            node_pub_key: Public key of the endorsed node.

        Returns:
            Result[EndorsementPacket, Error]: The revoked packet or an error.

        Example:
            >>> nel = NodeEndorsementList()
            >>> nel.revoke_issued(b"n" * 32).is_err()
            True
        """
        packet = self._issued.pop(node_pub_key, None)
        if packet is None:
            return Result.Err(
                Error.new(
                    ErrorKind.INVALID_REVOCATION_REQUEST,
                    f"No issued endorsement for key {node_pub_key.hex()[:16]}…",
                )
            )
        return Result.Ok(packet)

    def has_issued_to(self, node_pub_key: bytes) -> bool:
        """Return True if this node has an active issued packet for a given key.

        Args:
            node_pub_key: Public key of the target node.

        Example:
            >>> nel = NodeEndorsementList()
            >>> nel.has_issued_to(b"n" * 32)
            False
        """
        return node_pub_key in self._issued

    def get_issued(self, node_pub_key: bytes) -> Optional[EndorsementPacket]:
        """Return the issued packet for a node, or None.

        Args:
            node_pub_key: Public key of the endorsed node.

        Example:
            >>> nel = NodeEndorsementList()
            >>> nel.get_issued(b"n" * 32) is None
            True
        """
        return self._issued.get(node_pub_key)

    def all_issued(self) -> list[EndorsementPacket]:
        """Return all active issued endorsement packets.

        Returns:
            list[EndorsementPacket]: All packets issued by this node.
        """
        return list(self._issued.values())

    # ------------------------------------------------------------------
    # Received packet (endorsed side)
    # ------------------------------------------------------------------

    def set_received(self, packet: EndorsementPacket) -> None:
        """Store the endorsement packet received when this node joined.

        Args:
            packet: The endorsement packet received from the endorser.

        Example:
            >>> nel = NodeEndorsementList()
            >>> # nel.set_received(packet)
        """
        self._received = packet
        logging.debug(
            "[\x1b[38;5;51mUSMD\x1b[0m] NEL received from %s",
            packet.endorser_key.hex()[:16] + "…",
        )

    def get_received(self) -> Optional[EndorsementPacket]:
        """Return the endorsement packet this node received, or None.

        Example:
            >>> nel = NodeEndorsementList()
            >>> nel.get_received() is None
            True
        """
        return self._received

    def clear_received(self) -> None:
        """Remove the received endorsement packet (e.g. after re-joining).

        Example:
            >>> nel = NodeEndorsementList()
            >>> nel.clear_received()
        """
        self._received = None

    def __repr__(self) -> str:
        return (
            f"NodeEndorsementList(issued={len(self._issued)}, "
            f"received={'yes' if self._received else 'no'})"
        )

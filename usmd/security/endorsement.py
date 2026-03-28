"""Endorsement process for USMD-RDSH node joining.

When a new node wishes to join an USD, it follows this sequence:

1. The node generates its Ed25519 and X25519 key pairs.
2. It sends a signed join request (name + keys + nonce) to an existing node.
3. The existing node validates the request and returns an **EndorsementPacket**
   signed with its own Ed25519 private key.
4. The new node stores the packet. When challenged (ECR), it presents it.

The endorsement system provides the foundation for the Node Identity Table (NIT)
and is used to detect and exclude rogue nodes.

Examples:
    >>> from usmd.security.crypto import Ed25519Pair
    >>> endorser_priv, endorser_pub = Ed25519Pair.generate()
    >>> node_priv, node_pub = Ed25519Pair.generate()
    >>> session_priv, session_pub = X25519Pair.generate()
    >>>
    >>> factory = EndorsementFactory(
    ...     endorser_private_key=endorser_priv,
    ...     endorser_public_key=endorser_pub,
    ... )
    >>> packet = factory.issue(
    ...     node_name=1710000000,
    ...     node_pub_key=node_pub,
    ...     node_session_key=session_pub,
    ...     roles=[NodeRole.NODE_EXECUTOR],
    ...     ttl_seconds=86400,
    ... )
    >>> verifier = EndorsementVerifier()
    >>> verifier.verify(packet).is_ok()
    True
"""

import os
import time

from ..node.nel import EndorsementPacket
from ..node.role import NodeRole
from ..security.crypto import Ed25519Pair
from ..utils.errors import Error, ErrorKind
from ..utils.result import Result


class EndorsementFactory:  # pylint: disable=too-few-public-methods
    """Creates signed EndorsementPackets on behalf of an endorsing node.

    Attributes:
        endorser_private_key: Ed25519 private key of the endorser.
        endorser_public_key: Ed25519 public key of the endorser.

    Examples:
        >>> priv, pub = Ed25519Pair.generate()
        >>> factory = EndorsementFactory(priv, pub)
    """

    def __init__(self, endorser_private_key: bytes, endorser_public_key: bytes) -> None:
        """Initialise with the endorser's key pair.

        Args:
            endorser_private_key: 32-byte Ed25519 private key of this node.
            endorser_public_key: 32-byte Ed25519 public key of this node.
        """
        self._priv = endorser_private_key
        self._pub = endorser_public_key

    def issue(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self,
        node_name: int,
        node_pub_key: bytes,
        node_session_key: bytes,
        roles: list[NodeRole],
        ttl_seconds: int = 86400,
    ) -> EndorsementPacket:
        """Create and sign a new EndorsementPacket.

        Args:
            node_name: UNIX-timestamp name of the joining node.
            node_pub_key: Ed25519 public key of the joining node.
            node_session_key: X25519 session key of the joining node.
            roles: List of roles granted to the new node.
            ttl_seconds: How long (seconds) this endorsement is valid. Default: 86 400 (24 h).

        Returns:
            EndorsementPacket: Signed endorsement for the new node.

        Example:
            >>> priv, pub = Ed25519Pair.generate()
            >>> factory = EndorsementFactory(priv, pub)
            >>> _, node_pub = Ed25519Pair.generate()
            >>> _, session_pub = X25519Pair.generate()
            >>> packet = factory.issue(1710000000, node_pub, session_pub,
            ...                        [NodeRole.NODE_EXECUTOR])
            >>> packet.endorser_key == pub
            True
        """
        serial = os.urandom(16)
        expiration = int(time.time()) + ttl_seconds

        # Build unsigned packet to compute signable bytes
        packet = EndorsementPacket(
            endorser_key=self._pub,
            node_name=node_name,
            node_pub_key=node_pub_key,
            node_session_key=node_session_key,
            roles=roles,
            serial=serial,
            expiration=expiration,
            signature=b"",  # placeholder
        )

        signature = Ed25519Pair.sign(self._priv, packet.signable_bytes())
        packet.signature = signature
        return packet


class EndorsementVerifier:
    """Verifies the authenticity and validity of an EndorsementPacket.

    Examples:
        >>> verifier = EndorsementVerifier()
        >>> # verifier.verify(packet).is_ok()
    """

    def verify(self, packet: EndorsementPacket) -> Result[None, Error]:
        """Verify the signature and expiry of an EndorsementPacket.

        Checks:
        1. The packet has not expired.
        2. The Ed25519 signature (from the endorser) is valid over the
           canonical signable bytes.

        Args:
            packet: The EndorsementPacket to verify.

        Returns:
            Result[None, Error]: Ok(None) if valid, Err otherwise.

        Examples:
            >>> priv, pub = Ed25519Pair.generate()
            >>> factory = EndorsementFactory(priv, pub)
            >>> _, node_pub = Ed25519Pair.generate()
            >>> _, session_pub = X25519Pair.generate()
            >>> packet = factory.issue(1710000000, node_pub, session_pub,
            ...                        [NodeRole.NODE_EXECUTOR])
            >>> EndorsementVerifier().verify(packet).is_ok()
            True
        """
        if packet.is_expired():
            return Result.Err(
                Error.new(
                    ErrorKind.UNVERIFIABLE_ENDORSEMENT,
                    f"Endorsement packet expired at {packet.expiration}",
                )
            )

        return Ed25519Pair.verify(
            packet.endorser_key,
            packet.signable_bytes(),
            packet.signature,
        )

    def verify_with_nel_check(
        self,
        packet: EndorsementPacket,
        endorser_known: bool,
    ) -> Result[None, Error]:
        """Verify a packet and additionally check whether the endorser is known.

        If the endorser is not in the local NIT/NEL and cannot be reached for
        confirmation, the endorsed node is temporarily excluded.

        Args:
            packet: The packet to verify.
            endorser_known: True if the endorser is known in the local NIT.

        Returns:
            Result[None, Error]: Ok(None) if all checks pass, Err otherwise.

        Examples:
            >>> priv, pub = Ed25519Pair.generate()
            >>> factory = EndorsementFactory(priv, pub)
            >>> _, node_pub = Ed25519Pair.generate()
            >>> _, session_pub = X25519Pair.generate()
            >>> packet = factory.issue(1710000000, node_pub, session_pub,
            ...                        [NodeRole.NODE_EXECUTOR])
            >>> EndorsementVerifier().verify_with_nel_check(packet, endorser_known=True).is_ok()
            True
            >>> EndorsementVerifier().verify_with_nel_check(packet, endorser_known=False).is_err()
            True
        """
        sig_result = self.verify(packet)
        if sig_result.is_err():
            return sig_result

        if not endorser_known:
            return Result.Err(
                Error.new(
                    ErrorKind.ENDORSER_NOT_FOUND,
                    f"Endorser {packet.endorser_key.hex()[:16]}… not in local NIT",
                )
            )

        return Result.Ok(None)

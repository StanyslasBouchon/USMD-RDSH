"""NCP Command 13 — Revoke_endorsement.

Sent by a node that is shutting down to notify its endorsement peers of its
departure. Two complementary flows are handled by a single command:

  - **Endorser shutting down**: sends REVOKE_ENDORSEMENT to every node it
    endorsed (those tracked in its ``NEL._issued`` list). Each notified node
    must clear its received endorsement packet and restart the join process.

  - **Endorsed node shutting down**: sends REVOKE_ENDORSEMENT to its own
    endorser (the key recorded in its ``NEL._received`` packet). The endorser
    must remove the sender from its ``NEL._issued`` list.

Security rule
~~~~~~~~~~~~~
If a REVOKE_ENDORSEMENT arrives but the sender has no valid endorsement
relationship with the receiver (i.e. neither case applies), the receiver
permanently excludes the sender from its NIT and ignores the request.

Request payload::

    [sender_pub_key : 32 bytes]   Ed25519 public key of the departing node.

Response payload::

    (empty — acknowledgement only)

Examples:
    >>> req = RevokeEndorsementRequest(sender_pub_key=b"k" * 32)
    >>> payload = req.to_payload()
    >>> len(payload)
    32
    >>> parsed = RevokeEndorsementRequest.from_payload(payload).unwrap()
    >>> parsed.sender_pub_key == b"k" * 32
    True
    >>> RevokeEndorsementResponse().to_payload()
    b''
"""

from ....utils.errors import Error, ErrorKind
from ....utils.result import Result

_PUB_KEY_SIZE = 32  # Ed25519 public key is always 32 bytes


class RevokeEndorsementRequest:
    """NCP command 13 request — departing node announces its revocation.

    Attributes:
        sender_pub_key: Ed25519 public key of the shutting-down node (32 bytes).

    Examples:
        >>> req = RevokeEndorsementRequest(sender_pub_key=b"s" * 32)
        >>> len(req.to_payload())
        32
        >>> req.sender_pub_key == b"s" * 32
        True
    """

    def __init__(self, sender_pub_key: bytes) -> None:
        """Initialise the request.

        Args:
            sender_pub_key: Ed25519 public key of the departing node (32 bytes).
        """
        self.sender_pub_key = sender_pub_key

    def to_payload(self) -> bytes:
        """Serialise the request as raw bytes.

        Returns:
            bytes: The 32-byte Ed25519 public key of the departing node.

        Example:
            >>> req = RevokeEndorsementRequest(b"k" * 32)
            >>> req.to_payload() == b"k" * 32
            True
        """
        return self.sender_pub_key

    @staticmethod
    def from_payload(payload: bytes) -> "Result[RevokeEndorsementRequest, Error]":
        """Deserialise a Revoke_endorsement request.

        Args:
            payload: Raw bytes from the network (must be at least 32 bytes).

        Returns:
            Result[RevokeEndorsementRequest, Error]: Ok with parsed request, or Err.

        Examples:
            >>> req = RevokeEndorsementRequest(b"k" * 32)
            >>> RevokeEndorsementRequest.from_payload(req.to_payload()).is_ok()
            True
            >>> RevokeEndorsementRequest.from_payload(b"short").is_err()
            True
        """
        if len(payload) < _PUB_KEY_SIZE:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"RevokeEndorsementRequest too short: {len(payload)} bytes, "
                    f"expected {_PUB_KEY_SIZE}",
                )
            )
        return Result.Ok(
            RevokeEndorsementRequest(sender_pub_key=payload[:_PUB_KEY_SIZE])
        )


class RevokeEndorsementResponse:
    """NCP command 13 response — acknowledgement (empty payload).

    Examples:
        >>> resp = RevokeEndorsementResponse()
        >>> resp.to_payload()
        b''
        >>> RevokeEndorsementResponse.from_payload(b"ignored").is_ok()
        True
    """

    def to_payload(self) -> bytes:
        """Serialise as an empty byte string.

        Returns:
            bytes: Always ``b""``.

        Example:
            >>> RevokeEndorsementResponse().to_payload()
            b''
        """
        return b""

    @staticmethod
    def from_payload(_payload: bytes) -> "Result[RevokeEndorsementResponse, Error]":
        """Deserialise a Revoke_endorsement response (always succeeds).

        Args:
            _payload: Ignored — the response carries no data.

        Returns:
            Result[RevokeEndorsementResponse, Error]: Always Ok.

        Examples:
            >>> RevokeEndorsementResponse.from_payload(b"").is_ok()
            True
        """
        return Result.Ok(RevokeEndorsementResponse())

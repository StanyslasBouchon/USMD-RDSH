"""NCP Command 4 — Request_approval.

Sent by a new node to any existing node to request admission into the USD.
The request carries the new node's name, its Ed25519 public key, its X25519
session key, and a nonce. The whole request is signed with the new node's
Ed25519 private key.

Request payload: JSON object with name, ed25519_pub (hex), x25519_pub (hex),
                 nonce (hex), signature (hex).
Response payload: 1 byte — 0x01 if approved, 0x00 if rejected.
                  On approval, the endorsement packet is appended as JSON.

Examples:
    >>> req = RequestApprovalRequest(
    ...     node_name=1710000000,
    ...     ed25519_pub=b"e"*32,
    ...     x25519_pub=b"x"*32,
    ...     nonce=b"n"*16,
    ...     signature=b"s"*64,
    ... )
    >>> payload = req.to_payload()
    >>> parsed = RequestApprovalRequest.from_payload(payload).unwrap()
    >>> parsed.node_name
    1710000000
"""

import json
from dataclasses import dataclass

from ....utils.errors import Error, ErrorKind
from ....utils.result import Result


@dataclass
class RequestApprovalRequest:
    """NCP command 4 request — join request from a new node.

    Attributes:
        node_name: UNIX-timestamp name chosen by the joining node.
        ed25519_pub: Ed25519 public key of the joining node (32 bytes).
        x25519_pub: X25519 session public key (32 bytes).
        nonce: 16-byte random nonce for freshness.
        signature: Ed25519 signature over all other fields (64 bytes).

    Examples:
        >>> req = RequestApprovalRequest(1710000000, b"e"*32, b"x"*32,
        ...                              b"n"*16, b"s"*64)
        >>> RequestApprovalRequest.from_payload(req.to_payload()).unwrap().node_name
        1710000000
    """

    node_name: int
    ed25519_pub: bytes
    x25519_pub: bytes
    nonce: bytes
    signature: bytes

    def to_payload(self) -> bytes:
        """Serialise to JSON bytes.

        Returns:
            bytes: UTF-8 encoded JSON.
        """
        doc = {
            "name": self.node_name,
            "ed25519_pub": self.ed25519_pub.hex(),
            "x25519_pub": self.x25519_pub.hex(),
            "nonce": self.nonce.hex(),
            "signature": self.signature.hex(),
        }
        return json.dumps(doc).encode("utf-8")

    def signable_bytes(self) -> bytes:
        """Return the canonical bytes that should be signed by the new node.

        Covers all fields except the signature.

        Returns:
            bytes: Concatenation of name + ed25519_pub + x25519_pub + nonce.
        """
        return (
            self.node_name.to_bytes(8, "big")
            + self.ed25519_pub
            + self.x25519_pub
            + self.nonce
        )

    @staticmethod
    def from_payload(payload: bytes) -> Result["RequestApprovalRequest", Error]:
        """Deserialise from JSON bytes.

        Args:
            payload: UTF-8 JSON bytes.

        Returns:
            Result[RequestApprovalRequest, Error]: Ok or Err.

        Example:
            >>> req = RequestApprovalRequest(1710000000, b"e"*32, b"x"*32,
            ...                              b"n"*16, b"s"*64)
            >>> RequestApprovalRequest.from_payload(req.to_payload()).is_ok()
            True
        """
        try:
            doc = json.loads(payload.decode("utf-8"))
            return Result.Ok(
                RequestApprovalRequest(
                    node_name=int(doc["name"]),
                    ed25519_pub=bytes.fromhex(doc["ed25519_pub"]),
                    x25519_pub=bytes.fromhex(doc["x25519_pub"]),
                    nonce=bytes.fromhex(doc["nonce"]),
                    signature=bytes.fromhex(doc["signature"]),
                )
            )
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR, f"RequestApproval parse error: {exc}"
                )
            )


@dataclass
class RequestApprovalResponse:
    """NCP command 4 response — approval or rejection.

    Attributes:
        approved: True if the node is approved.

    Examples:
        >>> resp = RequestApprovalResponse(approved=True)
        >>> RequestApprovalResponse.from_payload(resp.to_payload()).unwrap().approved
        True
    """

    approved: bool

    def to_payload(self) -> bytes:
        """Serialise to 1 byte.

        Returns:
            bytes: b'\\x01' if approved, b'\\x00' otherwise.
        """
        return bytes([0x01 if self.approved else 0x00])

    @staticmethod
    def from_payload(payload: bytes) -> Result["RequestApprovalResponse", Error]:
        """Deserialise from 1 byte.

        Args:
            payload: 1 byte.

        Example:
            >>> RequestApprovalResponse.from_payload(b'\\x01').unwrap().approved
            True
        """
        if len(payload) < 1:
            return Result.Err(
                Error.new(ErrorKind.PROTOCOL_ERROR, "RequestApproval response is empty")
            )
        return Result.Ok(RequestApprovalResponse(approved=bool(payload[0])))

"""NCP Command 11 — Announce_promotion (quorum election result).

Broadcast by the winner of a quorum election to notify all peers that it
has been promoted to NODE_OPERATOR.  Receiving nodes update their local NAL
to grant the operator role to the announced public key.

Request payload layout:
    [epoch: uint32 big-endian (4 bytes)]
    [pub_key: 32 bytes Ed25519 public key]
    [address: UTF-8 string (remaining bytes)]

Response payload: empty (acknowledgement only).

Examples:
    >>> key = b'k' * 32
    >>> req = AnnouncePromotionRequest(epoch=1, pub_key=key, address="10.0.0.2")
    >>> payload = req.to_payload()
    >>> parsed = AnnouncePromotionRequest.from_payload(payload).unwrap()
    >>> parsed.address
    '10.0.0.2'
    >>> parsed.pub_key == key
    True
"""

import struct

from ....utils.errors import Error, ErrorKind
from ....utils.result import Result

_EPOCH_SIZE = 4    # uint32 big-endian
_PUBKEY_SIZE = 32  # Ed25519 public key length in bytes
_HEADER_SIZE = _EPOCH_SIZE + _PUBKEY_SIZE  # 36 bytes


class AnnouncePromotionRequest:
    """NCP command 11 request — winner announces its new operator role.

    Attributes:
        epoch: Election epoch the promotion belongs to.
        pub_key: Ed25519 public key of the promoted node (32 bytes).
        address: IP address of the promoted node.

    Examples:
        >>> key = b'\\x00' * 32
        >>> req = AnnouncePromotionRequest(epoch=2, pub_key=key, address="1.2.3.4")
        >>> req.to_payload()[:4] == b'\\x00\\x00\\x00\\x02'
        True
    """

    def __init__(self, epoch: int, pub_key: bytes, address: str) -> None:
        self.epoch = epoch
        self.pub_key = pub_key
        self.address = address

    def to_payload(self) -> bytes:
        """Serialise the announcement.

        Returns:
            bytes: 4-byte epoch + 32-byte pub_key + UTF-8 address.
        """
        return (
            struct.pack("!I", self.epoch)
            + self.pub_key
            + self.address.encode("utf-8")
        )

    @staticmethod
    def from_payload(payload: bytes) -> "Result[AnnouncePromotionRequest, Error]":
        """Deserialise an Announce_promotion request.

        Args:
            payload: Raw bytes from the network.

        Returns:
            Result[AnnouncePromotionRequest, Error]: Ok or Err.

        Examples:
            >>> key = b'x' * 32
            >>> req = AnnouncePromotionRequest(epoch=1, pub_key=key, address="5.5.5.5")
            >>> AnnouncePromotionRequest.from_payload(req.to_payload()).is_ok()
            True
        """
        if len(payload) < _HEADER_SIZE:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"AnnouncePromotionRequest too short: {len(payload)} bytes",
                )
            )
        epoch = struct.unpack("!I", payload[:_EPOCH_SIZE])[0]
        pub_key = payload[_EPOCH_SIZE:_HEADER_SIZE]
        try:
            address = payload[_HEADER_SIZE:].decode("utf-8")
        except UnicodeDecodeError as exc:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"AnnouncePromotionRequest address decode: {exc}",
                )
            )
        return Result.Ok(AnnouncePromotionRequest(epoch=epoch, pub_key=pub_key, address=address))


class AnnouncePromotionResponse:
    """NCP command 11 response — empty acknowledgement.

    Examples:
        >>> resp = AnnouncePromotionResponse()
        >>> resp.to_payload()
        b''
    """

    def to_payload(self) -> bytes:
        """Serialise the response (always empty).

        Returns:
            bytes: Empty bytes.
        """
        return b""

    @staticmethod
    def from_payload(_payload: bytes) -> "Result[AnnouncePromotionResponse, Error]":
        """Deserialise an Announce_promotion response.

        Args:
            _payload: Ignored (expected empty).

        Returns:
            Result[AnnouncePromotionResponse, Error]: Always Ok.
        """
        return Result.Ok(AnnouncePromotionResponse())

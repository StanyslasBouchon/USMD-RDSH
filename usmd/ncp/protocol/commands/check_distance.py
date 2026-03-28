"""NCP Command 1 — Check_distance_to_node.

The requesting node sends the timestamp (ms) at which it sent the request.
The receiving node replies with its computed distance score d.

Request payload: 8-byte big-endian UNIX timestamp in milliseconds.
Response payload: 8-byte IEEE 754 double (big-endian) representing d.

This command may only be sent to reference nodes.

Examples:
    >>> import time
    >>> req = CheckDistanceRequest(sent_at_ms=int(time.time() * 1000))
    >>> payload = req.to_payload()
    >>> parsed = CheckDistanceRequest.from_payload(payload).unwrap()
    >>> parsed.sent_at_ms == req.sent_at_ms
    True

    >>> resp = CheckDistanceResponse(distance=1.25)
    >>> CheckDistanceResponse.from_payload(resp.to_payload()).unwrap().distance
    1.25
"""

import struct
from dataclasses import dataclass

from ....utils.errors import Error, ErrorKind
from ....utils.result import Result


@dataclass
class CheckDistanceRequest:
    """NCP command 1 request — carries the sender's transmission timestamp.

    Attributes:
        sent_at_ms: UNIX timestamp in milliseconds at time of sending.

    Examples:
        >>> req = CheckDistanceRequest(sent_at_ms=1710000000000)
        >>> len(req.to_payload())
        8
    """

    sent_at_ms: int

    def to_payload(self) -> bytes:
        """Serialise to 8-byte big-endian integer.

        Returns:
            bytes: 8 bytes.

        Example:
            >>> CheckDistanceRequest(1710000000000).to_payload()
            b'\\x00\\x00\\x01\\x8e...'
        """
        return struct.pack("!Q", self.sent_at_ms)

    @staticmethod
    def from_payload(payload: bytes) -> Result["CheckDistanceRequest", Error]:
        """Deserialise a Check_distance request payload.

        Args:
            payload: Exactly 8 bytes.

        Returns:
            Result[CheckDistanceRequest, Error]: Ok with parsed request, or Err.

        Example:
            >>> req = CheckDistanceRequest(1710000000000)
            >>> CheckDistanceRequest.from_payload(req.to_payload()).is_ok()
            True
        """
        if len(payload) < 8:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"CheckDistance request needs 8 bytes, got {len(payload)}",
                )
            )
        (ts,) = struct.unpack_from("!Q", payload)
        return Result.Ok(CheckDistanceRequest(sent_at_ms=ts))


@dataclass
class CheckDistanceResponse:
    """NCP command 1 response — carries the computed distance score.

    Attributes:
        distance: The distance d ∈ [0, 5] computed by the receiver.

    Examples:
        >>> resp = CheckDistanceResponse(distance=2.5)
        >>> len(resp.to_payload())
        8
    """

    distance: float

    def to_payload(self) -> bytes:
        """Serialise the distance as an 8-byte IEEE 754 double.

        Returns:
            bytes: 8 bytes big-endian double.

        Example:
            >>> CheckDistanceResponse(1.5).to_payload()
            b'?\\xf8...'
        """
        return struct.pack("!d", self.distance)

    @staticmethod
    def from_payload(payload: bytes) -> Result["CheckDistanceResponse", Error]:
        """Deserialise a Check_distance response payload.

        Args:
            payload: Exactly 8 bytes.

        Returns:
            Result[CheckDistanceResponse, Error]: Ok with distance, or Err.

        Example:
            >>> resp = CheckDistanceResponse(3.14)
            >>> CheckDistanceResponse.from_payload(resp.to_payload()).unwrap().distance
            3.14
        """
        if len(payload) < 8:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"CheckDistance response needs 8 bytes, got {len(payload)}",
                )
            )
        (d,) = struct.unpack_from("!d", payload)
        return Result.Ok(CheckDistanceResponse(distance=d))

"""NCP Command 2 — Request_emergency.

Sent by a weakened node to its reference nodes to signal that it needs help.
The request includes the list of peers to which the emergency has already been
forwarded, preventing loops.

Only reference nodes may receive this command.

Request payload: JSON list of node names (ints) already notified.
Response payload: 1 byte — 0x01 if the peer can help, 0x00 otherwise.

Examples:
    >>> req = RequestEmergencyRequest(already_notified=[1710000001, 1710000002])
    >>> payload = req.to_payload()
    >>> parsed = RequestEmergencyRequest.from_payload(payload).unwrap()
    >>> parsed.already_notified
    [1710000001, 1710000002]

    >>> resp = RequestEmergencyResponse(can_help=True)
    >>> RequestEmergencyResponse.from_payload(resp.to_payload()).unwrap().can_help
    True
"""

import json
from dataclasses import dataclass, field

from ....utils.errors import Error, ErrorKind
from ....utils.result import Result


@dataclass
class RequestEmergencyRequest:
    """NCP command 2 request — signals a failure and lists already-notified nodes.

    Attributes:
        already_notified: List of node names (UNIX timestamps) that have already
                          received this emergency request (anti-loop mechanism).

    Examples:
        >>> req = RequestEmergencyRequest(already_notified=[100, 200])
        >>> RequestEmergencyRequest.from_payload(req.to_payload()).unwrap().already_notified
        [100, 200]
    """

    already_notified: list[int] = field(default_factory=list)

    def to_payload(self) -> bytes:
        """Serialise to JSON bytes.

        Returns:
            bytes: UTF-8 JSON array of node names.

        Example:
            >>> RequestEmergencyRequest([1, 2]).to_payload()
            b'[1, 2]'
        """
        return json.dumps(self.already_notified).encode("utf-8")

    @staticmethod
    def from_payload(payload: bytes) -> Result["RequestEmergencyRequest", Error]:
        """Deserialise from JSON bytes.

        Args:
            payload: UTF-8 JSON array.

        Returns:
            Result[RequestEmergencyRequest, Error]: Ok with parsed request, or Err.

        Example:
            >>> req = RequestEmergencyRequest([5, 10])
            >>> RequestEmergencyRequest.from_payload(req.to_payload()).is_ok()
            True
        """
        try:
            data = json.loads(payload.decode("utf-8"))
            return Result.Ok(RequestEmergencyRequest(already_notified=list(data)))
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR, f"RequestEmergency parse error: {exc}"
                )
            )


@dataclass
class RequestEmergencyResponse:
    """NCP command 2 response — indicates whether this node can take over.

    Attributes:
        can_help: True if this node is available to accept the failing node's service.

    Examples:
        >>> resp = RequestEmergencyResponse(can_help=True)
        >>> RequestEmergencyResponse.from_payload(resp.to_payload()).unwrap().can_help
        True
    """

    can_help: bool

    def to_payload(self) -> bytes:
        """Serialise to 1 byte.

        Returns:
            bytes: b'\\x01' if can help, b'\\x00' otherwise.
        """
        return bytes([0x01 if self.can_help else 0x00])

    @staticmethod
    def from_payload(payload: bytes) -> Result["RequestEmergencyResponse", Error]:
        """Deserialise from 1 byte.

        Args:
            payload: 1 byte.

        Returns:
            Result[RequestEmergencyResponse, Error]: Ok with parsed response, or Err.

        Example:
            >>> RequestEmergencyResponse.from_payload(b'\\x01').unwrap().can_help
            True
        """
        if len(payload) < 1:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR, "RequestEmergency response is empty"
                )
            )
        return Result.Ok(RequestEmergencyResponse(can_help=payload[0] == 0x01))

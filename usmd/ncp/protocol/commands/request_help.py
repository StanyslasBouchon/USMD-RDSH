"""NCP Command 3 — Request_help.

Propagated by nodes that received a Request_emergency. They forward the
request to their own reference nodes (excluding those already in the
``already_notified`` list of the original emergency).

Only reference nodes may receive this command.

Request payload: JSON list of node names already notified.
Response payload: 1 byte — 0x01 if help is available, 0x00 otherwise.

Examples:
    >>> req = RequestHelpRequest(already_notified=[1710000001])
    >>> resp = RequestHelpResponse(can_help=False)
    >>> RequestHelpResponse.from_payload(resp.to_payload()).unwrap().can_help
    False
"""

import json
from dataclasses import dataclass, field

from ....utils.errors import Error, ErrorKind
from ....utils.result import Result


@dataclass
class RequestHelpRequest:
    """NCP command 3 request — secondary propagation of an emergency.

    Attributes:
        already_notified: Node names already involved in this emergency cascade.

    Examples:
        >>> req = RequestHelpRequest(already_notified=[1, 2, 3])
        >>> RequestHelpRequest.from_payload(req.to_payload()).unwrap().already_notified
        [1, 2, 3]
    """

    already_notified: list[int] = field(default_factory=list)

    def to_payload(self) -> bytes:
        """Serialise to JSON bytes."""
        return json.dumps(self.already_notified).encode("utf-8")

    @staticmethod
    def from_payload(payload: bytes) -> Result["RequestHelpRequest", Error]:
        """Deserialise from JSON bytes.

        Args:
            payload: UTF-8 JSON array of node names.

        Returns:
            Result[RequestHelpRequest, Error]: Ok or Err.

        Example:
            >>> req = RequestHelpRequest([7, 8])
            >>> RequestHelpRequest.from_payload(req.to_payload()).is_ok()
            True
        """
        try:
            data = json.loads(payload.decode("utf-8"))
            return Result.Ok(RequestHelpRequest(already_notified=list(data)))
        except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
            return Result.Err(
                Error.new(ErrorKind.PROTOCOL_ERROR, f"RequestHelp parse error: {exc}")
            )


@dataclass
class RequestHelpResponse:
    """NCP command 3 response — whether this node can take over.

    Attributes:
        can_help: True if this node is willing and able to help.

    Examples:
        >>> resp = RequestHelpResponse(can_help=True)
        >>> RequestHelpResponse.from_payload(resp.to_payload()).unwrap().can_help
        True
    """

    can_help: bool

    def to_payload(self) -> bytes:
        """Serialise to 1 byte."""
        return bytes([0x01 if self.can_help else 0x00])

    @staticmethod
    def from_payload(payload: bytes) -> Result["RequestHelpResponse", Error]:
        """Deserialise from 1 byte.

        Example:
            >>> RequestHelpResponse.from_payload(b'\\x00').unwrap().can_help
            False
        """
        if len(payload) < 1:
            return Result.Err(
                Error.new(ErrorKind.PROTOCOL_ERROR, "RequestHelp response is empty")
            )
        return Result.Ok(RequestHelpResponse(can_help=payload[0] == 0x01))

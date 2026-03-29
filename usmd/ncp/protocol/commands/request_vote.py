"""NCP Command 10 — Request_vote (quorum election).

Sent by a candidate node to solicit a vote from its peers during a quorum
election.  Used when no active operator is detected in the USD.

Request payload layout:
    [epoch: uint32 big-endian (4 bytes)]
    [candidate_address: UTF-8 string (remaining bytes)]

Response payload:
    [vote: uint8] — 0x01 = YES, 0x00 = NO

Examples:
    >>> req = RequestVoteRequest(epoch=1, candidate_address="192.168.1.1")
    >>> payload = req.to_payload()
    >>> parsed = RequestVoteRequest.from_payload(payload).unwrap()
    >>> parsed.epoch
    1
    >>> parsed.candidate_address
    '192.168.1.1'
"""

import struct

from ....utils.errors import Error, ErrorKind
from ....utils.result import Result

_EPOCH_SIZE = 4  # uint32 big-endian


class RequestVoteRequest:
    """NCP command 10 request — candidate proposes itself for election.

    Attributes:
        epoch: Election epoch counter (prevents stale votes from older rounds).
        candidate_address: IP address of the candidate node.

    Examples:
        >>> req = RequestVoteRequest(epoch=3, candidate_address="10.0.0.1")
        >>> req.to_payload()[:4] == b'\\x00\\x00\\x00\\x03'
        True
    """

    def __init__(self, epoch: int, candidate_address: str) -> None:
        self.epoch = epoch
        self.candidate_address = candidate_address

    def to_payload(self) -> bytes:
        """Serialise the request.

        Returns:
            bytes: 4-byte epoch + UTF-8 address.
        """
        return struct.pack("!I", self.epoch) + self.candidate_address.encode("utf-8")

    @staticmethod
    def from_payload(payload: bytes) -> "Result[RequestVoteRequest, Error]":
        """Deserialise a Request_vote request.

        Args:
            payload: Raw bytes from the network.

        Returns:
            Result[RequestVoteRequest, Error]: Ok with parsed request or Err.

        Examples:
            >>> req = RequestVoteRequest(epoch=1, candidate_address="1.2.3.4")
            >>> RequestVoteRequest.from_payload(req.to_payload()).is_ok()
            True
        """
        if len(payload) < _EPOCH_SIZE:
            return Result.Err(
                Error.new(
                    ErrorKind.PROTOCOL_ERROR,
                    f"RequestVoteRequest too short: {len(payload)} bytes",
                )
            )
        epoch = struct.unpack("!I", payload[:_EPOCH_SIZE])[0]
        try:
            address = payload[_EPOCH_SIZE:].decode("utf-8")
        except UnicodeDecodeError as exc:
            return Result.Err(
                Error.new(ErrorKind.PROTOCOL_ERROR, f"RequestVoteRequest address decode: {exc}")
            )
        return Result.Ok(RequestVoteRequest(epoch=epoch, candidate_address=address))


class RequestVoteResponse:
    """NCP command 10 response — peer's vote (YES or NO).

    Attributes:
        granted: True if the peer votes YES for the candidate.

    Examples:
        >>> resp = RequestVoteResponse(granted=True)
        >>> resp.to_payload()
        b'\\x01'
        >>> RequestVoteResponse.from_payload(b'\\x00').unwrap().granted
        False
    """

    def __init__(self, granted: bool) -> None:
        self.granted = granted

    def to_payload(self) -> bytes:
        """Serialise the vote to a single byte.

        Returns:
            bytes: b'\\x01' for YES, b'\\x00' for NO.
        """
        return b"\x01" if self.granted else b"\x00"

    @staticmethod
    def from_payload(payload: bytes) -> "Result[RequestVoteResponse, Error]":
        """Deserialise a Request_vote response.

        Args:
            payload: Expected to be a single byte.

        Returns:
            Result[RequestVoteResponse, Error]: Ok with parsed response or Err.

        Examples:
            >>> RequestVoteResponse.from_payload(b'\\x01').unwrap().granted
            True
        """
        if len(payload) < 1:
            return Result.Err(
                Error.new(ErrorKind.PROTOCOL_ERROR, "RequestVoteResponse: empty payload")
            )
        return Result.Ok(RequestVoteResponse(granted=payload[0] == 0x01))
